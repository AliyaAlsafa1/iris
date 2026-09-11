use clap::{ArgAction, Parser, ValueEnum};
use iris_datatypes::conn_fts::InterArrivals;
use iris_datatypes::{ConnRecord, PktCount, TlsHandshake};
use lazy_static::lazy_static;
use serde::Serialize;

use iris_core::{
    CoreId, FiveTuple, L4Pdu, Runtime,
    config::{FlowMode, default_config, load_config},
    filter::flow_drop::{
        DISCARDED_BYTES, DISCARDED_PACKETS, SplitQueueMap, install_drop_flow, install_split_flow,
        query_resident_flow, uninstall_flow,
    },
    multicore::{ChannelDispatcher, ChannelMode, SharedWorkerThreadSpawner},
    port::PortId,
    protocols::packet::tcp::TCP_PROTOCOL,
    protocols::packet::udp::UDP_PROTOCOL,
    subscription::Tracked,
};

use iris_compiler::{callback, datatype, datatype_fn, input_files, iris_end_macros};
use iris_core::dpdk::{rte_flow, rte_flow_action_handle};

use std::{
    collections::{HashSet, VecDeque},
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
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

static TCP_BYTES: AtomicUsize = AtomicUsize::new(0);
static UDP_BYTES: AtomicUsize = AtomicUsize::new(0);
static TLS_BYTES: AtomicUsize = AtomicUsize::new(0);

// Dispatching
static FLOW_DISPATCHER: OnceLock<Arc<ChannelDispatcher<FlowEvent>>> = OnceLock::new();
static MODE: RwLock<FlowMode> = RwLock::new(FlowMode::Standard);
static SPLIT_QUEUES: RwLock<Option<SplitQueueMap>> = RwLock::new(None);

static NUM_FLOWS: OnceLock<usize> = OnceLock::new();
static USE_MODEL: OnceLock<bool> = OnceLock::new();

static OFFLOAD_ENABLED: [AtomicBool; 4] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];
static OFFLOAD_AFTER_PKTS: OnceLock<usize> = OnceLock::new();

static DISPATCHED: [AtomicUsize; 4] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];
static INSTALLED_BY_KIND: [AtomicUsize; 4] = [
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
    AtomicUsize::new(0),
];

#[inline]
fn offload_enabled(kind: FlowKind) -> bool {
    OFFLOAD_ENABLED[kind.idx()].load(Ordering::Relaxed)
}

#[inline]
fn offload_after_pkts() -> usize {
    *OFFLOAD_AFTER_PKTS.get().unwrap_or(&20)
}

#[inline]
fn offer_for_offload(kind: FlowKind, five_tuple: &FiveTuple, rx_core: &CoreId, total_pkts: usize) {
    if total_pkts != offload_after_pkts() || !offload_enabled(kind) {
        return;
    }
    if let Some(dispatcher) = FLOW_DISPATCHER.get() {
        let _ = dispatcher.dispatch(
            FlowEvent::FlowSeen {
                tuple: *five_tuple,
                rx_core: *rx_core,
                kind,
            },
            Some(rx_core),
        );
        DISPATCHED[kind.idx()].fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, ValueEnum)]
enum FlowKind {
    Tls,
    Ssh,
    Quic,
    MaybeQuic,
}

impl FlowKind {
    fn label(self) -> &'static str {
        match self {
            FlowKind::Tls => "tls",
            FlowKind::Ssh => "ssh",
            FlowKind::Quic => "quic",
            FlowKind::MaybeQuic => "maybe_quic",
        }
    }

    fn all() -> [FlowKind; 4] {
        [
            FlowKind::Tls,
            FlowKind::Ssh,
            FlowKind::Quic,
            FlowKind::MaybeQuic,
        ]
    }

    const fn idx(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Serialize)]
enum FlowEvent {
    /// Minimal payload to keep cloning cheap
    FlowSeen {
        tuple: FiveTuple,
        rx_core: CoreId,
        kind: FlowKind,
    },
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

    #[clap(
        long,
        value_enum,
        value_delimiter = ',',
        value_name = "KINDS",
        default_value = "tls,ssh,quic,maybe-quic"
    )]
    offload_protos: Vec<FlowKind>,

    #[clap(long, value_name = "COUNT", default_value = "20")]
    offload_after_pkts: usize,
}

const MODEL_FEATURE_PKTS: usize = 20;

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

// ===== TCP/UDP byte counting =====

/// Per-connection on-wire byte count, split by transport protocol. Accumulated into the
/// global `TCP_BYTES`/`UDP_BYTES` totals at `L4Terminated`. This runs independently of the
/// TLS flow-handling path above; it counts every TCP/UDP frame's full `mbuf.data_len()`,
/// headers included, regardless of whether the connection was ever admitted or installed.
///
/// Each frame is also fed to the per-core transport meter in iris_core so the monitor can
/// print live per-second TCP/UDP throughput; that path is lock-free (thread-local).
#[datatype]
struct TransportBytes {
    tcp_bytes: usize,
    udp_bytes: usize,
}

impl TransportBytes {
    #[datatype_fn("TransportBytes,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) {
        let len = pdu.mbuf.data_len();
        match pdu.ctxt.proto {
            TCP_PROTOCOL => {
                self.tcp_bytes += len;
                iris_core::lcore::transport_meter::add_tcp(len);
            }
            UDP_PROTOCOL => {
                self.udp_bytes += len;
                iris_core::lcore::transport_meter::add_udp(len);
            }
            _ => {}
        }
    }
}

impl Tracked for TransportBytes {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            tcp_bytes: 0,
            udp_bytes: 0,
        }
    }

    fn clear(&mut self) {
        self.tcp_bytes = 0;
        self.udp_bytes = 0;
    }
}

#[callback("tcp or udp,level=L4Terminated")]
fn record_transport_bytes(bytes: &TransportBytes) {
    TCP_BYTES.fetch_add(bytes.tcp_bytes, Ordering::Relaxed);
    UDP_BYTES.fetch_add(bytes.udp_bytes, Ordering::Relaxed);
}

#[datatype]
struct TlsWireBytes {
    bytes: usize,
}

impl TlsWireBytes {
    #[datatype_fn("TlsWireBytes,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) {
        self.bytes += pdu.mbuf.data_len();
    }
}

impl Tracked for TlsWireBytes {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { bytes: 0 }
    }

    fn clear(&mut self) {
        self.bytes = 0;
    }
}

#[callback("tls,level=L4Terminated")]
fn record_tls_bytes(bytes: &TlsWireBytes) {
    if *MODE.read().unwrap() == FlowMode::Standard {
        TLS_BYTES.fetch_add(bytes.bytes, Ordering::Relaxed);
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
    if pkts.total() != offload_after_pkts() {
        return true;
    }

    let is_elephant = if *USE_MODEL.get().unwrap_or(&false) {
        let conn_hash = conn.five_tuple.conn_hash();
        let first_seen_ts = conn
            .first_seen_wall
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let inv = ConnInvariants::from_conn(conn, conn_hash, first_seen_ts);

        match (
            ConnFeatures::from_conn_at(conn, iat, MODEL_FEATURE_PKTS as u64, &inv),
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
        offer_for_offload(FlowKind::Tls, five_tuple, rx_core, pkts.total());
    }

    true
}

#[callback("ssh,level=InL4Conn")]
fn ssh_cb(five_tuple: &FiveTuple, rx_core: &CoreId, pkts: &PktCount) -> bool {
    offer_for_offload(FlowKind::Ssh, five_tuple, rx_core, pkts.total());
    true
}

#[callback("quic,level=InL4Conn")]
fn quic_cb(five_tuple: &FiveTuple, rx_core: &CoreId, pkts: &PktCount) -> bool {
    offer_for_offload(FlowKind::Quic, five_tuple, rx_core, pkts.total());
    true
}

#[callback("MaybeQuic,level=InL4Conn")]
fn maybe_quic_cb(five_tuple: &FiveTuple, rx_core: &CoreId, pkts: &PktCount) -> bool {
    offer_for_offload(FlowKind::MaybeQuic, five_tuple, rx_core, pkts.total());
    true
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    // Without this every log::error! in iris-core is discarded, including the PCIe monitor's
    // "disabled" and "needs root" diagnostics — which is the only way to find out why a monitor
    // produced no samples. Controlled by RUST_LOG, so it stays silent unless asked.
    env_logger::init();

    // Parse CLI args
    let args = Args::parse();
    if args.show_args {
        println!("{args:#?}");
    }

    NUM_FLOWS.set(args.num_flows).unwrap();

    for kind in &args.offload_protos {
        OFFLOAD_ENABLED[kind.idx()].store(true, Ordering::Relaxed);
    }
    OFFLOAD_AFTER_PKTS.set(args.offload_after_pkts).unwrap();
    println!(
        "offloading: [{}] at {} packets",
        FlowKind::all()
            .iter()
            .filter(|k| offload_enabled(**k))
            .map(|k| k.label())
            .collect::<Vec<_>>()
            .join(", "),
        args.offload_after_pkts,
    );

    if offload_enabled(FlowKind::MaybeQuic)
        && args.offload_after_pkts <= iris_datatypes::MAYBE_QUIC_WINDOW
    {
        eprintln!(
            "warning: --offload-after-pkts {} does not exceed the MaybeQuic evidence window ({} \
             payload-bearing packets); connections carrying any non-payload packets will accept \
             too late to be offered, so the maybe_quic arm will under-report.",
            args.offload_after_pkts,
            iris_datatypes::MAYBE_QUIC_WINDOW,
        );
    }

    let use_model = match &args.model {
        Some(path) => {
            // The model's features are snapshotted at a fixed packet count, so moving the
            // threshold would feed it features from the wrong point in the connection. That is a
            // silent correctness bug, not a tuning choice.
            assert_eq!(
                args.offload_after_pkts, MODEL_FEATURE_PKTS,
                "--model requires --offload-after-pkts {MODEL_FEATURE_PKTS} (the packet count the \
                 model's features were trained at); got {}",
                args.offload_after_pkts,
            );
            model::load_model(path.to_str().expect("Invalid model path"));
            true
        }
        None => {
            println!("No model provided; running in admit-all mode.");
            false
        }
    };
    USE_MODEL.set(use_model).unwrap();
    if use_model {
        println!(
            "note: the elephant model gates the tls arm only; ssh/quic/maybe_quic admit all \
             matched connections at the threshold."
        );
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

    let flow_mode = config
        .online
        .as_ref()
        .map_or(FlowMode::Standard, |o| o.flow_mode);
    *MODE.write().unwrap() = flow_mode;
    println!(
        "resolved flow_mode = {:?} (online section present: {})",
        flow_mode,
        config.online.is_some()
    );

    // Initialize split queues if needed. Both trim paths use the same queue
    // layout; they differ only in whether the NIC DMAs the payload segment.
    if flow_mode.uses_split_queues() {
        // Queue ids are per port, so the map yields one id per port for a
        // given core: a rule goes onto every port, and a queue id taken from
        // one port means nothing on another.
        if let Some(online) = &config.online {
            *SPLIT_QUEUES.write().unwrap() = Some(SplitQueueMap::from_config(online));
        }
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

    if worker_core_ids.len() > 1 {
        eprintln!(
            "warning: {} worker cores supplied, but the flow handler runs \
             serially; extra cores provide no additional throughput.",
            worker_core_ids.len()
        );
    }

    // Spawn workers and attach the handler
    let worker_handle = SharedWorkerThreadSpawner::new()
        .set_cores(worker_core_ids)
        .set_batch_size(args.batch_size)
        .measure_utilization(true)
        .add_dispatcher(flow_dispatcher.clone(), |event: FlowEvent| {
            match event {
                FlowEvent::FlowSeen {
                    tuple,
                    rx_core,
                    kind,
                } => {
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

                    // One split queue id per port, in the same order as PORT_IDS.
                    let split_queues = if mode.uses_split_queues() {
                        let map = SPLIT_QUEUES.read().unwrap();
                        match map.as_ref().and_then(|m| m.queues_for(rx_core)) {
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
                            FlowMode::Split | FlowMode::TrimNativeDpdk => install_split_flow(
                                ports.clone(),
                                &tuple,
                                split_queues.as_ref().unwrap(),
                            ),
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
                                INSTALLED_BY_KIND[kind.idx()].fetch_add(1, Ordering::Relaxed);
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

    // Offline there is no monitor, so this is the only report of where the RX cores' cycles
    // went; online the same figures go to cycle_budget.csv every interval.
    println!("{}", iris_core::lcore::datapath_budget::current());

    // Read after shutdown so the last batch is included; the monitor's own line, printed
    // earlier, shows the same pools live.
    for p in iris_core::multicore::worker_budget::pools() {
        let w = p.budget;
        let tsc_hz = unsafe { iris_core::rte_get_tsc_hz() };
        println!(
            "Rule-install workers ({}): {:.4} cores busy over {} thread(s), {:.2}% mean \
             utilization, {} offloads handled, {:.0} offloads/s sustainable at one core",
            p.label,
            w.cores_busy(tsc_hz),
            w.threads,
            100.0 * w.busy_fraction(tsc_hz),
            w.items,
            w.sustainable_item_rate(),
        );
    }

    // Discard totals are accumulated at eviction time (each evicted rule's
    // indirect counter is queried in uninstall_flow). Flows still resident at
    // exit were never evicted, so their counters have not been read yet. Query
    // them here (WITHOUT destroying the rules — mass rte_flow_destroy at
    // shutdown faults in the PMD) so the totals include the resident set too.
    {
        let queue = FLOW_QUEUE.lock().unwrap();
        for entry in queue.iter() {
            let raw_ptrs: Vec<*mut rte_flow> = entry.flow_ptrs.iter().map(|fp| fp.0).collect();
            let raw_handles: Vec<*mut rte_flow_action_handle> =
                entry.handle_ptrs.iter().map(|hp| hp.0).collect();
            if let Err(e) = query_resident_flow(&entry.ports, &raw_ptrs, &raw_handles) {
                eprintln!("resident flow query failed: {e:?}");
            }
        }
    }

    let discarded_packets = DISCARDED_PACKETS.load(std::sync::atomic::Ordering::Relaxed);
    let discarded_bytes = DISCARDED_BYTES.load(std::sync::atomic::Ordering::Relaxed);
    println!("{discarded_packets} packets and {discarded_bytes} bytes discarded");

    println!("=== Offload by protocol ===");
    println!(
        "{:<12}{:>12}{:>12}{:>10}",
        "kind", "dispatched", "installed", "enabled"
    );
    for kind in FlowKind::all() {
        println!(
            "{:<12}{:>12}{:>12}{:>10}",
            kind.label(),
            DISPATCHED[kind.idx()].load(Ordering::Relaxed),
            INSTALLED_BY_KIND[kind.idx()].load(Ordering::Relaxed),
            offload_enabled(kind),
        );
    }

    if *MODE.read().unwrap() == FlowMode::Standard {
        let tls_bytes = TLS_BYTES.load(Ordering::Relaxed);
        println!("TLS on-wire bytes seen (Standard mode): {tls_bytes} bytes");
    }

    if args.show_stats {
        if let Some(flow_stats) = final_stats.get(0) {
            println!("=== FLOW Stats ===");
            println!("{flow_stats}");
        }
    }
}
