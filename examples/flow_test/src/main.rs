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
    collections::{HashMap, BTreeSet, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::{Duration, Instant},
};

mod model;

use flow_features::conn_features::ConnFeatures;
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
    expires_at: Instant,
}

lazy_static! {
    static ref PORT_IDS: RwLock<Option<Vec<PortId>>> = RwLock::new(None);
    static ref TARGET_FLOWS: Mutex<HashMap<FiveTuple, Instant>> = Mutex::new(HashMap::new());
    static ref FLOW_QUEUE: Mutex<VecDeque<FlowEntry>> = Mutex::new(VecDeque::new());
}

// Dispatching
static FLOW_DISPATCHER: OnceLock<Arc<ChannelDispatcher<FlowEvent>>> = OnceLock::new();
static MODE: RwLock<FlowMode> = RwLock::new(FlowMode::Standard);
static SPLIT_QUEUES: RwLock<Option<HashMap<CoreId, u16>>> = RwLock::new(None);

static TIMEOUT_SECS: OnceLock<u64> = OnceLock::new();
static NUM_FLOWS: OnceLock<usize> = OnceLock::new();

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
    model: PathBuf,

    #[clap(long, value_name = "SECS", default_value = "10")]
    timeout_secs: u64,

    #[clap(long, value_name = "COUNT", default_value = "100")]
    num_flows: usize,
}



// ===== Helpers =====

/// Expire and uninstall any rules whose deadlines have passed.
fn expire_flows_now() {
    let mut queue = FLOW_QUEUE.lock().unwrap();
    let now = Instant::now();

    while let Some(entry) = queue.front() {
        if entry.expires_at > now {
            break;
        }
        // pop first (to drop the borrow) then uninstall
        let expired = queue.pop_front().unwrap();
        let raw_ptrs: Vec<*mut rte_flow> = expired.flow_ptrs.iter().map(|fp| fp.0).collect();
        let raw_handles: Vec<*mut rte_flow_action_handle> =
            expired.handle_ptrs.iter().map(|hp| hp.0).collect();
        if let Err(e) = uninstall_flow(expired.ports.clone(), raw_ptrs, raw_handles) {
            eprintln!("Failed to uninstall flow: {:?}", e);
        }
        // Optionally also remove from TARGET_FLOWS when it expires:
        TARGET_FLOWS.lock().unwrap().remove(&expired.tuple);
    }
}

// ===== Filters =====

// Fire on TLS connections
#[callback("tls,level=InL4Conn")]
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

    let is_elephant = match (
        ConnFeatures::from_conn(conn, iat),
        TlsFeatures::from_tls(tls),
    ) {
        (Some(conn_features), Some(tls_features)) => {
            model::predict(&conn_features, &tls_features)
                .map(|proba| proba >= 0.5)
                .unwrap_or(false)
        }
        _ => false,
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

    TIMEOUT_SECS.set(args.timeout_secs).unwrap();
    NUM_FLOWS.set(args.num_flows).unwrap();

    // Load the LightGBM model before starting the runtime.
    model::load_model(args.model.to_str().expect("Invalid model path"));

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
            // Lightweight periodic maintenance
            expire_flows_now();

            match event {
                FlowEvent::TlsSeen { tuple, rx_core } => {
                    let mode = *MODE.read().unwrap();
                    if mode == FlowMode::Standard {
                        return;
                    }

                    let num_flows = *NUM_FLOWS.get().unwrap();

                    // Respect num_flows cap first
                    if num_flows == 0 {
                        return;
                    }

                    // Deduplicate and cap
                    {
                        let mut targets = TARGET_FLOWS.lock().unwrap();
                        if targets.contains_key(&tuple) || targets.len() >= num_flows {
                            return;
                        }
                        // Record when we installed the drop rule for this tuple
                        targets.insert(tuple.clone(), Instant::now());
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
                                    expires_at: Instant::now()
                                        + Duration::from_secs(*TIMEOUT_SECS.get().unwrap()),
                                };
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