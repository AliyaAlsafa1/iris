//! Drop-mechanism comparison app. Per-connection byte counting into a large
//! cache-bound array (the expensive downstream work a real flow monitor does),
//! with the connection *tail* shed after `--drop-after` packets by one of three
//! mechanisms, selected at runtime via `--drop-mode`:
//!
//!   none      no drop — count every packet (the full-monitoring baseline).
//!   software  software flow table: at the threshold, install a Drop rule
//!             (`sw_flow`) inline. Tail packets are dropped at RX, before the
//!             pipeline, and skip the byte counting. Requires the runtime flow
//!             table (this app sets `IRIS_SW_FLOW=1` itself) and reads its
//!             sizing from `[flow_table]` (capacity/ways) — override with
//!             `--capacity`/`--ways`.
//!   hardware  NIC rte_flow: at the threshold, the RX callback *dispatches* the
//!             flow to a worker thread (off the datapath), which installs a
//!             5-tuple DROP rule in hardware (`install_drop_flow`), deduped and
//!             capped at `--num-flows`, expired after `--hw-rule-secs`. Tail
//!             packets are then dropped in the NIC and never reach the CPU.
//!             Needs `dyn_hardware_assist = true` in the config so the mlx5 flow
//!             engine is configured. This mirrors examples/flow_test.
//!   filter    in-pipeline drop before the callback: after the head, the
//!             callback returns `false` to unsubscribe the connection, so the
//!             pipeline stops delivering its tail to the callback (verified:
//!             ~1 invocation/connection vs every packet for baseline). The tail
//!             is still tracked by conntrack — it drops later than software,
//!             which sheds the tail at RX before conntrack.
//!
//! All modes use one plain per-packet `InL4Conn` callback (no streaming-filter
//! gate — a callback gated on a `StreamingFilter` does not fire in this build;
//! the callback `false`-return / unsubscribe path does work).
//!
//! Knobs (CLI, with env fallback for NPF compatibility):
//!   --drop-mode   none|software|hardware|filter          (default none)
//!   --drop-after  keep this many packets, then drop the tail (env IRIS_DROP_AFTER, default 1)
//!   --stats-size  counter slots, rounded up to a power of two (env IRIS_STATS_SIZE, default 2^24)
//!   --capacity --ways   software flow-table sizing (override config [flow_table])
//!   --worker-cores --num-flows --hw-rule-secs --flow-channel-size   hardware arm

use clap::{ArgEnum, Parser};
use iris_compiler::*;
use iris_core::dpdk::{rte_flow, rte_flow_action_handle};
use iris_core::filter::flow_drop::{install_drop_flow, uninstall_flow};
use iris_core::filter::sw_flow::{self, FlowAction};
use iris_core::multicore::{ChannelDispatcher, ChannelMode, SharedWorkerThreadSpawner};
use iris_core::port::PortId;
use iris_core::{config::load_config, CoreId, FiveTuple, L4Pdu, Runtime};
use iris_datatypes::PktCount;
use lazy_static::lazy_static;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

static STATS: OnceLock<Vec<AtomicU64>> = OnceLock::new();
static MASK: OnceLock<usize> = OnceLock::new();
static DROP_AFTER: OnceLock<u64> = OnceLock::new();
static DROP_MODE: OnceLock<DropMode> = OnceLock::new();
static PORT_IDS: OnceLock<Vec<PortId>> = OnceLock::new();
static DROPPED_CONNS: AtomicUsize = AtomicUsize::new(0);
static CB_CALLS: AtomicUsize = AtomicUsize::new(0);

// --- hardware arm: off-datapath rte_flow install (flow_test pattern) ---
static FLOW_DISPATCHER: OnceLock<Arc<ChannelDispatcher<FlowEvent>>> = OnceLock::new();
static NUM_FLOWS: OnceLock<usize> = OnceLock::new();
static HW_RULE_SECS: OnceLock<u64> = OnceLock::new();

/// Raw rte_flow pointers are not Send; wrap them so the worker can own them.
#[derive(Clone, Copy)]
struct FlowPtr(*mut rte_flow);
unsafe impl Send for FlowPtr {}
unsafe impl Sync for FlowPtr {}
#[derive(Clone, Copy)]
struct HandlePtr(*mut rte_flow_action_handle);
unsafe impl Send for HandlePtr {}
unsafe impl Sync for HandlePtr {}

/// An installed HW rule set (both directions of a connection), tracked for
/// expiry and FIFO eviction.
struct FlowEntry {
    tuple: FiveTuple,
    ports: Vec<PortId>,
    flow_ptrs: Vec<FlowPtr>,
    handle_ptrs: Vec<HandlePtr>,
    expires_at: Instant,
}

lazy_static! {
    /// Tuples already offloaded to HW (dedup + cap).
    static ref TARGET_FLOWS: Mutex<HashMap<FiveTuple, Instant>> = Mutex::new(HashMap::new());
    /// Installed rules awaiting expiry.
    static ref FLOW_QUEUE: Mutex<VecDeque<FlowEntry>> = Mutex::new(VecDeque::new());
}

/// Event sent from the RX datapath to the install worker.
#[derive(Clone, Serialize)]
enum FlowEvent {
    DropFlow { tuple: FiveTuple, rx_core: CoreId },
}

#[derive(ArgEnum, Copy, Clone, Debug, PartialEq, Eq)]
enum DropMode {
    None,
    Software,
    Hardware,
    Filter,
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn stats() -> &'static Vec<AtomicU64> {
    STATS.get().expect("stats() used before init_stats()")
}

fn init_stats(size: usize) {
    let n = size.next_power_of_two();
    let _ = MASK.set(n - 1);
    let _ = STATS.set((0..n).map(|_| AtomicU64::new(0)).collect());
}

fn drop_after() -> u64 {
    *DROP_AFTER.get().unwrap_or(&1)
}

fn drop_mode() -> DropMode {
    *DROP_MODE.get().unwrap_or(&DropMode::None)
}

#[inline]
fn slot(ft: &FiveTuple) -> usize {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ft.hash(&mut h);
    (h.finish() as usize) & *MASK.get().unwrap()
}

fn reverse(ft: &FiveTuple) -> FiveTuple {
    FiveTuple {
        orig: ft.resp,
        resp: ft.orig,
        proto: ft.proto,
    }
}

/// Uninstall one entry's HW rules and free its dedup slot.
fn uninstall_entry(entry: FlowEntry) {
    let flows: Vec<*mut rte_flow> = entry.flow_ptrs.iter().map(|p| p.0).collect();
    let handles: Vec<*mut rte_flow_action_handle> =
        entry.handle_ptrs.iter().map(|p| p.0).collect();
    if let Err(e) = uninstall_flow(entry.ports.clone(), flows, handles) {
        log::warn!("Failed to uninstall HW flow: {e:?}");
    }
    TARGET_FLOWS.lock().unwrap().remove(&entry.tuple);
}

/// Uninstall any HW rules whose lifetime has elapsed (called from the worker).
fn expire_flows_now() {
    let now = Instant::now();
    loop {
        let expired = {
            let mut queue = FLOW_QUEUE.lock().unwrap();
            match queue.front() {
                Some(e) if e.expires_at <= now => queue.pop_front(),
                _ => None,
            }
        };
        match expired {
            Some(entry) => uninstall_entry(entry),
            None => break,
        }
    }
}

/// Evict the oldest installed rule (FIFO). Returns false if nothing to evict.
fn evict_oldest() -> bool {
    let oldest = FLOW_QUEUE.lock().unwrap().pop_front();
    match oldest {
        Some(entry) => {
            uninstall_entry(entry);
            true
        }
        None => false,
    }
}

/// Worker-side handler: install a HW DROP rule for both directions of `tuple`,
/// deduped and capped at `--num-flows` with FIFO eviction. Runs on a dedicated
/// worker core, off the RX datapath.
fn install_hw_drop(tuple: &FiveTuple) {
    expire_flows_now();

    // Dedup: already offloaded.
    if TARGET_FLOWS.lock().unwrap().contains_key(tuple) {
        return;
    }

    // FIFO eviction: if at capacity, evict oldest rules to make room.
    let cap = *NUM_FLOWS.get().unwrap_or(&0);
    if cap != 0 {
        while TARGET_FLOWS.lock().unwrap().len() >= cap {
            if !evict_oldest() {
                break;
            }
        }
    }

    // Reserve the slot before installing so a concurrent worker can't double-fill.
    TARGET_FLOWS.lock().unwrap().insert(*tuple, Instant::now());

    let ports = match PORT_IDS.get() {
        Some(p) => p,
        None => {
            log::warn!("hardware mode but no port ids resolved");
            return;
        }
    };

    let rev = reverse(tuple);
    let mut flow_ptrs = Vec::new();
    let mut handle_ptrs = Vec::new();
    for t in [tuple, &rev] {
        match install_drop_flow(ports.clone(), t) {
            Ok((flows, handles)) => {
                flow_ptrs.extend(flows.into_iter().map(FlowPtr));
                handle_ptrs.extend(handles.into_iter().map(HandlePtr));
            }
            Err(e) => log::warn!("HW drop rule install failed for {t:?}: {e:?}"),
        }
    }
    if !flow_ptrs.is_empty() {
        FLOW_QUEUE.lock().unwrap().push_back(FlowEntry {
            tuple: *tuple,
            ports: ports.clone(),
            flow_ptrs,
            handle_ptrs,
            expires_at: Instant::now() + Duration::from_secs(*HW_RULE_SECS.get().unwrap_or(&60)),
        });
        DROPPED_CONNS.fetch_add(1, Ordering::Relaxed);
    } else {
        // Install failed entirely — roll back the reserved dedup slot.
        TARGET_FLOWS.lock().unwrap().remove(tuple);
    }
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,

    /// Which drop mechanism to exercise.
    #[clap(long, arg_enum, default_value = "none")]
    drop_mode: DropMode,

    /// Keep this many packets of a connection, then drop the tail.
    #[clap(long)]
    drop_after: Option<u64>,

    /// Counter-array slot count (rounded up to a power of two).
    #[clap(long)]
    stats_size: Option<usize>,

    /// Software flow-table capacity (overrides config [flow_table].capacity).
    #[clap(long)]
    capacity: Option<usize>,

    /// Software flow-table set-associativity (overrides config [flow_table].ways).
    #[clap(long)]
    ways: Option<usize>,

    /// Cores for the hardware-arm install worker (comma-separated).
    #[clap(long, value_delimiter = ',', default_value = "3")]
    worker_cores: Vec<u32>,

    /// Max number of connections to offload to HW (0 = unbounded).
    #[clap(long, default_value = "0")]
    num_flows: usize,

    /// Lifetime of an installed HW rule before it is uninstalled.
    #[clap(long, default_value = "60")]
    hw_rule_secs: u64,

    /// Dispatcher channel size for the hardware arm.
    #[clap(long, default_value = "32768")]
    flow_channel_size: usize,
}

/// Per-packet connection callback. Counts this packet's bytes against its
/// connection (the expensive, cache-bound downstream work), then sheds the tail
/// once the connection reaches `drop_after` packets per `--drop-mode` (see the
/// module docs).
#[callback("(ipv4 or ipv6) and (tcp or udp),level=InL4Conn")]
fn count(five_tuple: &FiveTuple, core_id: &CoreId, pkts: &PktCount, pdu: &L4Pdu) -> bool {
    CB_CALLS.fetch_add(1, Ordering::Relaxed);
    let n = pkts.total() as u64;
    let mode = drop_mode();

    let s = stats();
    s[slot(five_tuple)].fetch_add(pdu.length() as u64, Ordering::Relaxed);

    // At the threshold, arrange the upstream (RX / NIC) drop for the tail.
    if n == drop_after() {
        match mode {
            DropMode::Software => {
                sw_flow::install(*core_id, *five_tuple, FlowAction::Drop);
                sw_flow::install(*core_id, reverse(five_tuple), FlowAction::Drop);
                DROPPED_CONNS.fetch_add(1, Ordering::Relaxed);
            }
            DropMode::Hardware => {
                // Off-datapath: dispatch to the install worker (flow_test pattern).
                if let Some(d) = FLOW_DISPATCHER.get() {
                    let _ = d.dispatch(
                        FlowEvent::DropFlow {
                            tuple: *five_tuple,
                            rx_core: *core_id,
                        },
                        Some(core_id),
                    );
                }
            }
            DropMode::Filter | DropMode::None => {}
        }
    }

    // filter mode: unsubscribe this connection once past the head, so the
    // pipeline stops delivering its tail to this callback (drop before callback).
    if mode == DropMode::Filter && n >= drop_after() {
        if n == drop_after() {
            DROPPED_CONNS.fetch_add(1, Ordering::Relaxed);
        }
        return false;
    }
    true
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();

    let mode = args.drop_mode;
    let _ = DROP_MODE.set(mode);
    // The software flow table is enabled once, lazily, at rx-core start; setting
    // the env here (before the runtime runs) makes --drop-mode fully drive it.
    std::env::set_var(
        "IRIS_SW_FLOW",
        if mode == DropMode::Software { "1" } else { "0" },
    );

    let after = args.drop_after.unwrap_or_else(|| env_usize("IRIS_DROP_AFTER", 1) as u64);
    let _ = DROP_AFTER.set(after);
    let size = args.stats_size.unwrap_or_else(|| env_usize("IRIS_STATS_SIZE", 1 << 24));
    init_stats(size);

    let mut config = load_config(&args.config);
    if let Some(c) = args.capacity {
        config.flow_table.capacity = c;
    }
    if let Some(w) = args.ways {
        config.flow_table.ways = w;
    }

    // Hardware arm: stand up the off-datapath install worker before the runtime.
    let mut worker_handle = None;
    if mode == DropMode::Hardware {
        let _ = NUM_FLOWS.set(args.num_flows);
        let _ = HW_RULE_SECS.set(args.hw_rule_secs);
        let rx_cores = config.get_all_rx_core_ids();
        let dispatcher = Arc::new(ChannelDispatcher::new(
            ChannelMode::PerCore(rx_cores),
            args.flow_channel_size,
            "flow_dispatcher".to_string(),
        ));
        FLOW_DISPATCHER
            .set(dispatcher.clone())
            .map_err(|_| "Failed to set FLOW dispatcher")
            .unwrap();
        let worker_core_ids: Vec<CoreId> = args.worker_cores.iter().map(|&c| CoreId(c)).collect();
        worker_handle = Some(
            SharedWorkerThreadSpawner::new()
                .set_cores(worker_core_ids)
                .set_batch_size(16)
                .add_dispatcher(dispatcher, |event: FlowEvent| match event {
                    FlowEvent::DropFlow { tuple, .. } => install_hw_drop(&tuple),
                })
                .run(),
        );
    }

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config.clone(), filter).unwrap();

    // Resolve port ids for hardware drop (must be after EAL init / port probe).
    if mode == DropMode::Hardware {
        if let Some(online) = &config.online {
            let port_ids: Vec<PortId> = online
                .ports
                .iter()
                .map(|p| PortId::new_from_device(p.device.clone()))
                .collect();
            let _ = PORT_IDS.set(port_ids);
        }
    }

    runtime.run();

    if let Some(h) = worker_handle {
        h.shutdown(None);
    }

    let total: u64 = stats().iter().map(|c| c.load(Ordering::Relaxed)).sum();
    println!("Drop mode: {:?}", mode);
    println!("Counter slots: {}", stats().len());
    println!("Drop after: {} pkts", drop_after());
    println!("Dropped {} connections", DROPPED_CONNS.load(Ordering::Relaxed));
    println!("Callback invocations: {}", CB_CALLS.load(Ordering::Relaxed));
    println!("Total bytes counted: {}", total);

    // Datapath per-received-packet cost (rte_rdtsc, non-empty bursts only).
    let (dp_cycles, dp_pkts) = iris_core::stats::datapath_busy();
    let cpp = if dp_pkts > 0 { dp_cycles as f64 / dp_pkts as f64 } else { 0.0 };
    println!("Datapath busy cycles: {dp_cycles}");
    println!("Datapath received pkts: {dp_pkts}");
    println!("Datapath cycles/pkt: {cpp:.2}");
}
