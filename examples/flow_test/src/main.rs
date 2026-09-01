use clap::{ArgAction, Parser, ValueEnum};
use iris_datatypes::{PktCount, TlsHandshake, ConnRecord};
use iris_datatypes::conn_fts::InterArrivals;
use lazy_static::lazy_static;
use serde::Serialize;

use iris_core::{
    config::{default_config, load_config, FlowMode},
    filter::flow_drop::{install_drop_flow, install_split_flow, uninstall_flow},
    multicore::{ChannelDispatcher, ChannelMode, SharedWorkerThreadSpawner},
    port::PortId,
    CoreId,
    FiveTuple,
    Runtime,
};

use iris_core::dpdk::{rte_flow, rte_flow_action_handle};
use iris_compiler::{callback, input_files, iris_end_macros};

use std::{
    collections::{HashMap, HashSet, BTreeSet, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, RwLock},
};

mod model;

use flow_features::conn_features::{ConnFeatures, ConnInvariants};
use flow_features::tls_features::TlsFeatures;

#[derive(Clone, Copy)]
struct FlowPtr(*mut rte_flow);
unsafe impl Send for FlowPtr {}
unsafe impl Sync for FlowPtr {}

#[derive(Clone, Copy)]
struct HandlePtr(*mut rte_flow_action_handle);
unsafe impl Send for HandlePtr {}
unsafe impl Sync for HandlePtr {}

#[derive(Clone)]
struct FlowEntry {
    tuple: FiveTuple,
    ports: Vec<PortId>,
    flow_ptrs: Vec<FlowPtr>,
    handle_ptrs: Vec<HandlePtr>,
}

lazy_static! {
    static ref PORT_IDS: RwLock<Option<Vec<PortId>>> = RwLock::new(None);
    static ref TARGET_FLOWS: Mutex<HashSet<FiveTuple>> = Mutex::new(HashSet::new());
    static ref FLOW_QUEUE: Mutex<VecDeque<FlowEntry>> = Mutex::new(VecDeque::new());
}

// Dispatching
static FLOW_DISPATCHER: OnceLock<Arc<ChannelDispatcher<FlowEvent>>> = OnceLock::new();
static MODE: RwLock<FlowMode> = RwLock::new(FlowMode::Standard);
static SPLIT_QUEUES: RwLock<Option<HashMap<CoreId, u16>>> = RwLock::new(None);

static NUM_FLOWS: OnceLock<usize> = OnceLock::new();
static USE_MODEL: OnceLock<bool> = OnceLock::new();

#[derive(Clone, Serialize)]
enum FlowEvent {
    /// Minimal payload to keep cloning cheap
    TlsSeen { tuple: FiveTuple, rx_core: CoreId },
}

// ===== CLI =====
#[derive(Copy, Clone, Debug, ValueEnum)]
enum ChannelModeArg {
    PerCore,
    Shared,
}


#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, value_parser, value_name = "FILE")]
    config: Option<PathBuf>,

    #[clap(
        short,
        long,
        value_parser,
        value_name = "FILE",
        default_value = "ports.jsonl"
    )]
    outfile: PathBuf,

    #[clap(long, value_name = "SIZE", default_value = "32768")]
    flow_channel_size: usize,

    #[clap(
        long,
        value_delimiter = ',',
        value_name = "CORES",
        default_value = "40"
    )]
    worker_cores: Vec<u32>,

    #[clap(long, value_name = "SIZE", default_value = "16")]
    batch_size: usize,

    #[clap(long, value_enum, default_value = "per-core")]
    channel_mode: ChannelModeArg,

    #[clap(long, value_parser, value_name = "PATH")]
    flush_channels: Option<PathBuf>,

    #[clap(long, action = ArgAction::SetTrue)]
    show_stats: bool,

    #[clap(long, action = ArgAction::SetTrue)]
    show_args: bool,

    #[clap(long, value_parser, value_name = "FILE")]
    model: Option<PathBuf>,

    #[clap(long, value_name = "COUNT", default_value = "100")]
    num_flows: usize,
}



// ===== Helpers =====

/// Uninstall a single flow entry's rules. Does not touch TARGET_FLOWS.
fn uninstall_entry(entry: &FlowEntry) {
    let raw_ptrs: Vec<*mut rte_flow> = entry.flow_ptrs.iter().map(|fp| fp.0).collect();
    let raw_handles: Vec<*mut rte_flow_action_handle> =
        entry.handle_ptrs.iter().map(|hp| hp.0).collect();
    if let Err(e) = uninstall_flow(entry.ports.clone(), raw_ptrs, raw_handles) {
        eprintln!("Failed to uninstall flow: {:?}", e);
    }
}

// ===== Filters =====

// Fire on TLS connections
#[callback("tls,level=InL4Conn")]
#[allow(unused_variables)]
fn tls_cb(
    five_tuple: &FiveTuple,
    rx_core: &CoreId,
    pkts: &PktCount,
    conn: &ConnRecord,
    iat: &InterArrivals,
    tls: &TlsHandshake,
) -> bool {
    if pkts.total() != 20 {
        return true;
    }

    let is_elephant = if *USE_MODEL.get().unwrap_or(&false) {
        let conn_hash = conn.five_tuple.conn_hash();
        let first_seen_ts = conn.first_seen_wall
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let inv = ConnInvariants::from_conn(conn, conn_hash, first_seen_ts);

        match (
            ConnFeatures::from_conn_at(conn, iat, 20, &inv),
            TlsFeatures::from_tls(tls),
        ) {
            (Some(conn_features), Some(tls_features)) => {
                model::predict(&conn_features, &tls_features)
                    .map(|proba| proba >= 0.5)
                    .unwrap_or(false)
            }
            _ => false,
        }
    } else {
        true
    };

    if is_elephant {
        let tuple = five_tuple.clone();
        if let Some(dispatcher) = FLOW_DISPATCHER.get() {
            let _ = dispatcher.dispatch(
                FlowEvent::TlsSeen {
                    tuple,
                    rx_core: *rx_core,
                },
                Some(rx_core), // preserve affinity when in PerCore mode
            );
        }
    }

    true
}


// ===== Main =====

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    // Parse CLI args
    let args = Args::parse();
    if args.show_args {
        println!("{args:#?}");
    }

    NUM_FLOWS.set(args.num_flows).unwrap();

    // Load the LightGBM model before starting the runtime, if one was provided.
    // With no model, every qualifying TLS flow is admitted (admit-all mode).
    let use_model = match &args.model {
        Some(path) => {
            model::load_model(path.to_str().expect("Invalid model path"));
            true
        }
        None => {
            println!("No model provided; running in admit-all mode.");
            false
        }
    };
    USE_MODEL.set(use_model).unwrap();

    let config = if let Some(path) = args.config.clone() {
        load_config(path)
    } else {
        default_config()
    };

    // Build ChannelMode
    let rx_cores = config.get_all_rx_core_ids();
    let channel_mode = match args.channel_mode {
        ChannelModeArg::PerCore => ChannelMode::PerCore(rx_cores),
        ChannelModeArg::Shared => ChannelMode::Shared,
    };

    let flow_mode = config.online.as_ref().map_or(FlowMode::Standard, |o| o.flow_mode);
    *MODE.write().unwrap() = flow_mode;

    // Initialize split queues if needed
    if flow_mode == FlowMode::Split {
        // Layout per port (no sink): q0=receive  q1=split    q2=receive  q3=split    ...
        let mut split_queues: HashMap<CoreId, u16> = HashMap::new();
        if let Some(online) = &config.online {
            for port_map in &online.ports {
                for (i, core) in port_map
                    .cores
                    .iter()
                    .copied()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .enumerate()
                {
                    split_queues.insert(
                        CoreId(core),
                        (i as u16) * 2 + 1,
                    );
                }
            }
        }

        *SPLIT_QUEUES.write().unwrap() = Some(split_queues);
    }

    // Create and publish the dispatcher
    let flow_dispatcher = Arc::new(ChannelDispatcher::new(
        channel_mode.clone(),
        args.flow_channel_size,
        "flow_dispatcher".to_string(),
    ));
    FLOW_DISPATCHER
        .set(flow_dispatcher.clone())
        .map_err(|_| "Failed to set FLOW dispatcher")
        .unwrap();

    // Map provided worker cores
    let worker_core_ids: Vec<CoreId> = args.worker_cores.iter().map(|&c| CoreId(c)).collect();

    // Spawn workers and attach the handler
    let worker_handle = SharedWorkerThreadSpawner::new()
        .set_cores(worker_core_ids)
        .set_batch_size(args.batch_size)
        .add_dispatcher(flow_dispatcher.clone(), |event: FlowEvent| {
            match event {
                FlowEvent::TlsSeen { tuple, rx_core } => {
                    let mode = *MODE.read().unwrap();
                    if mode == FlowMode::Standard {
                        return;
                    }

                    let num_flows = *NUM_FLOWS.get().unwrap();

                    // num_flows == 0 means install nothing.
                    if num_flows == 0 {
                        return;
                    }

                    // Deduplicate
                    if TARGET_FLOWS.lock().unwrap().contains(&tuple) {
                        return;
                    }

                    let split_queue = if mode == FlowMode::Split {
                        let queues = SPLIT_QUEUES.read().unwrap();
                        match queues.as_ref().and_then(|m| m.get(&rx_core)).copied() {
                            Some(q) => Some(q),
                            None => {
                                eprintln!("No split queue mapped for core {rx_core:?}");
                                return;
                            }
                        }
                    } else {
                        None
                    };

                    // Install, if we have ports
                    let maybe_ports = PORT_IDS.read().unwrap().clone();
                    if let Some(ports) = maybe_ports {
                        // FIFO eviction
                        let evicted = {
                            let mut queue = FLOW_QUEUE.lock().unwrap();
                            if queue.len() >= num_flows {
                                queue.pop_front()
                            } else {
                                None
                            }
                        };
                        if let Some(old) = evicted {
                            uninstall_entry(&old);
                            TARGET_FLOWS.lock().unwrap().remove(&old.tuple);
                        }

                        let result = match mode {
                            FlowMode::Drop => install_drop_flow(ports.clone(), &tuple),
                            FlowMode::Split => install_split_flow(ports.clone(), &tuple, split_queue.unwrap()),
                            FlowMode::Standard => return,
                        };

                        match result {
                            Ok((raw_flows, raw_handles)) => {
                                let entry = FlowEntry {
                                    tuple: tuple.clone(),
                                    ports: ports.clone(),
                                    flow_ptrs: raw_flows.into_iter().map(FlowPtr).collect(),
                                    handle_ptrs: raw_handles.into_iter().map(HandlePtr).collect(),
                                };
                                TARGET_FLOWS.lock().unwrap().insert(tuple.clone());
                                FLOW_QUEUE.lock().unwrap().push_back(entry);
                            }
                            Err(e) => eprintln!("install flow failed: {e:?}"),
                        }
                    } else {
                        eprintln!("PORT_IDS is None when trying to install flow!");
                    }
                }
            }
        })
        .run();

    // Build runtime
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config.clone(), filter).unwrap();

    // Extract and store PortIds
    if let Some(online) = &config.online {
        let port_ids: Vec<PortId> = online
            .ports
            .iter()
            .map(|port| {
                println!("Device: {}", port.device);
                PortId::new_from_device(port.device.clone())
            })
            .collect();

        for pid in &port_ids {
            println!("Port ID: {:?}", pid);
        }

        *PORT_IDS.write().unwrap() = Some(port_ids);
    }

    // Run packet processing
    runtime.run();

    // Graceful shutdown
    let final_stats = worker_handle.shutdown(args.flush_channels.as_ref());

    if args.show_stats {
        if let Some(flow_stats) = final_stats.get(0) {
            println!("=== FLOW Stats ===");
            println!("{flow_stats}");
        }
    }
}