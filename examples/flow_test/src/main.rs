use clap::{ArgAction, Parser, ValueEnum};
use iris_datatypes::PktCount;
use lazy_static::lazy_static;
use serde::Serialize;

use iris_core::{
    CoreId, FiveTuple, Runtime,
    config::{default_config, load_config},
    filter::flow_drop::{install_drop_flow, uninstall_drop_flow},
    multicore::{ChannelDispatcher, ChannelMode, SharedWorkerThreadSpawner},
    port::PortId,
};

use iris_compiler::{callback, input_files, iris_end_macros};
use iris_core::dpdk::rte_flow;

use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
struct FlowPtr(*mut rte_flow);
unsafe impl Send for FlowPtr {}
unsafe impl Sync for FlowPtr {}

#[derive(Clone)]
struct FlowEntry {
    tuple: FiveTuple,
    ports: Vec<PortId>,
    flow_ptrs: Vec<FlowPtr>,
    expires_at: Instant,
}

lazy_static! {
    static ref PORT_IDS: RwLock<Option<Vec<PortId>>> = RwLock::new(None);
    static ref TARGET_FLOWS: Mutex<HashMap<FiveTuple, Instant>> = Mutex::new(HashMap::new());
    static ref FLOW_QUEUE: Mutex<VecDeque<FlowEntry>> = Mutex::new(VecDeque::new());
}

// Dispatching
static FLOW_DISPATCHER: OnceLock<Arc<ChannelDispatcher<FlowEvent>>> = OnceLock::new();

#[derive(Clone, Serialize)]
enum FlowEvent {
    /// Minimal payload to keep cloning cheap
    TlsSeen { tuple: FiveTuple, rx_core: CoreId },
}

const TIMEOUT_SECS: u64 = 10;
const NUM_FLOWS: usize = 100;
const GRACE_PERIOD: u64 = 5;

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
        if let Err(e) = uninstall_drop_flow(expired.ports.clone(), raw_ptrs) {
            eprintln!("Failed to uninstall drop flow: {:?}", e);
        }
        // Optionally also remove from TARGET_FLOWS when it expires:
        TARGET_FLOWS.lock().unwrap().remove(&expired.tuple);
    }
}

// ===== Filters =====

// Try for all TCP
#[callback("tcp,level=InL4Conn")]
fn tls_cb(five_tuple: &FiveTuple, rx_core: &CoreId, pkts: &PktCount) -> bool {
    if pkts.total() < 10 {
        return true;
    }

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
                FlowEvent::TlsSeen { tuple, .. } => {
                    // Respect NUM_FLOWS cap first
                    if NUM_FLOWS == 0 {
                        return;
                    }

                    // Deduplicate and cap
                    {
                        let mut targets = TARGET_FLOWS.lock().unwrap();
                        if targets.contains_key(&tuple) || targets.len() >= NUM_FLOWS {
                            return;
                        }
                        // Record when we installed the drop rule for this tuple
                        targets.insert(tuple.clone(), Instant::now());
                    }

                    // Install, if we have ports
                    let maybe_ports = PORT_IDS.read().unwrap().clone();
                    if let Some(ports) = maybe_ports {
                        match install_drop_flow(ports.clone(), &tuple) {
                            Ok(raw_flows) => {
                                let entry = FlowEntry {
                                    tuple: tuple.clone(),
                                    ports: ports.clone(),
                                    flow_ptrs: raw_flows.into_iter().map(FlowPtr).collect(),
                                    expires_at: Instant::now() + Duration::from_secs(TIMEOUT_SECS),
                                };
                                FLOW_QUEUE.lock().unwrap().push_back(entry);
                            }
                            Err(e) => eprintln!("Failed to install drop flow: {:?}", e),
                        }
                    } else {
                        eprintln!("PORT_IDS is None when trying to install drop flow!");
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
