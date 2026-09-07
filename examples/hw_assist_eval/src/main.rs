//! A/B harness for measuring the CPU cycles that `dyn_hardware_assist` frees up.
//!
//! # What is being tested
//!
//! Iris already discards ciphertext packets in software: once a TLS connection's `Actions` bitmask
//! empties at the handshake/ciphertext boundary, `ConnTracker::process` returns early. But by then
//! the packet has crossed PCIe, consumed an RX descriptor, been DMA'd into an mbuf, been
//! RSS-hashed to a core, been parsed to a five-tuple and taken one connection-table lookup.
//! `dyn_hardware_assist` installs a per-connection NIC drop rule so the packet never arrives at
//! all. **That residual per-packet cost is the entire quantity under test.**
//!
//! # Why the obvious metric is wrong
//!
//! The natural thing to report is cycles per received packet. It is misleading here: shedding
//! removes the *cheapest* packets (a parse plus one hot hash hit) from the denominator while
//! leaving handshakes, reassembly and L7 parsing in it, so per-packet cost can stay flat or rise
//! even when total cycles fall. This app instead reports
//!
//!   1. cycles per **ingress** packet/byte — the denominator is `rx_phy_*`, what the NIC saw
//!      before any rule dropped anything, so it is fixed across arms and load-normalised; and
//!   2. the per-core cycle **budget**, whose `poll_idle` bucket is the pool of cycles actually
//!      available to application logic in a busy-poll datapath.
//!
//! # Arms (`--arm` is a free-text label; `--drop-mode` selects the mechanism)
//!
//! The control arm is **not** `dyn_hardware_assist = false`. That flag also changes the NIC flow
//! engine (a group-0 -> group-1 jump plus an explicit catch-all RSS rule replace the default RSS
//! path), which would confound the comparison. Run instead:
//!
//!   * **A, control** — `dyn_hardware_assist = true`, `--drop-mode none`: same NIC configuration,
//!     no drop rules.
//!   * **B, treatment** — `dyn_hardware_assist = true`, `--drop-mode hardware`.
//!
//! `B - A` is the hypothesis test.
//!
//! # Keeping the arms comparable
//!
//! The application work is a calibrated spin of `--app-cycles`, run from a callback on the `tls`
//! session, which fires **once per TLS connection at the ciphertext transition** (`L7EndHdrs`).
//! That is deliberate: a per-packet callback would stop firing for packets the NIC dropped, so the
//! treatment arm would simply do less work and the comparison would measure nothing. Because the
//! trigger is the handshake, not the tail, both arms perform identical application work — and the
//! report prints `tls_callbacks` so that invariant can be *checked* rather than assumed. If the
//! arms' callback counts differ by more than sampling noise, the runs are not comparable.
//!
//! The report also charges the mechanism for its own overhead: `rte_flow_create` cycles, install
//! count and failures, and the NIC-side drop counters read back from the rules' indirect COUNT
//! actions. Net freed cycles = datapath cycles saved - control-plane cycles spent. Rule install
//! cost scales with *connection arrival rate*, not byte rate, so at high connection churn this
//! term can exceed the saving; that is a real result, not a measurement artefact.

use clap::{ArgEnum, Parser};
use iris_compiler::*;
use iris_core::config::load_config;
use iris_core::dpdk::{rte_flow, rte_flow_action_handle};
use iris_core::filter::flow_drop::{
    install_drop_flow, query_resident_flow, rule_control_cost, uninstall_flow, DISCARDED_BYTES,
    DISCARDED_PACKETS,
};
use iris_core::multicore::{ChannelDispatcher, ChannelMode, SharedWorkerThreadSpawner};
use iris_core::port::{ingress_counters, IngressCounters, PortId};
use iris_core::{CoreId, FiveTuple, Runtime};
use iris_datatypes::TlsHandshake;
use lazy_static::lazy_static;
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

// ---------------------------------------------------------------------------
// Run configuration, resolved once in main() and read from the datapath.
// ---------------------------------------------------------------------------

static DROP_MODE: OnceLock<DropMode> = OnceLock::new();
static APP_CYCLES: OnceLock<u64> = OnceLock::new();
static PORT_IDS: OnceLock<Vec<PortId>> = OnceLock::new();
static FLOW_DISPATCHER: OnceLock<Arc<ChannelDispatcher<FlowEvent>>> = OnceLock::new();
static MAX_RULES: OnceLock<usize> = OnceLock::new();
static TABLE_FULL_POLICY: OnceLock<TableFullPolicy> = OnceLock::new();

/// Once per TLS connection at the ciphertext transition. The arm-equivalence check: this must
/// match across arms, otherwise they did not do the same work.
static TLS_CALLBACKS: AtomicU64 = AtomicU64::new(0);
/// Cycles actually burned by the synthetic application workload.
static APP_CYCLES_BURNED: AtomicU64 = AtomicU64::new(0);
/// Connections for which a drop was arranged (dispatched, for the hardware arm).
static SHED_CONNS: AtomicU64 = AtomicU64::new(0);
/// Offload requests refused because the rule table was already at `--max-rules`.
static OFFLOAD_REFUSED: AtomicU64 = AtomicU64::new(0);
/// Rules evicted to make room, under `--table-full-policy evict`.
static RULE_EVICTIONS: AtomicU64 = AtomicU64::new(0);

#[derive(ArgEnum, Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum DropMode {
    /// Control: do the application work, arrange no drop.
    None,
    /// Shed the tail in the NIC via a per-connection `rte_flow` DROP rule.
    Hardware,
}

/// What to do when the rule table is already at `--max-rules`.
#[derive(ArgEnum, Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum TableFullPolicy {
    /// Decline the offload and count it in `offload_refused`. The rule set is then whichever
    /// connections happened to arrive first, which are disproportionately long-lived — a biased
    /// sample, but a stable one.
    Refuse,
    /// Evict the least recently *added* rule (FIFO) and install the new one. Bounds the table the
    /// same way, but keeps it tracking current traffic rather than freezing on the first arrivals.
    Evict,
}

// ---------------------------------------------------------------------------
// Hardware arm: rte_flow install, off the datapath.
// ---------------------------------------------------------------------------

/// Raw `rte_flow` pointers are not `Send`; the worker owns them after install.
#[derive(Clone, Copy)]
struct FlowPtr(*mut rte_flow);
unsafe impl Send for FlowPtr {}
unsafe impl Sync for FlowPtr {}

#[derive(Clone, Copy)]
struct HandlePtr(*mut rte_flow_action_handle);
unsafe impl Send for HandlePtr {}
unsafe impl Sync for HandlePtr {}

/// One installed rule set, retained so its COUNT handles can be read back — on eviction, or at
/// shutdown for whatever is still resident.
struct FlowEntry {
    tuple: FiveTuple,
    ports: Vec<PortId>,
    flow_ptrs: Vec<FlowPtr>,
    handle_ptrs: Vec<HandlePtr>,
}

/// The offloaded rule set: dedup membership and FIFO order, under one lock.
///
/// One mutex rather than two, because the two facts have to agree. With more than one
/// `--worker-cores` thread, separate locks would let two workers both observe a full table and
/// both evict, or both pass the dedup check for the same tuple and both install — the second
/// leaking a NIC rule that nothing subsequently uninstalls or counts.
#[derive(Default)]
struct RuleTable {
    /// Tuples with a rule installed *or an install in flight*. Installs are counted so that
    /// `--max-rules` bounds what the NIC holds, not merely what has finished installing.
    resident: HashSet<FiveTuple>,
    /// Installed rule sets in install order, so the front is the least recently added.
    fifo: VecDeque<FlowEntry>,
}

lazy_static! {
    static ref RULES: Mutex<RuleTable> = Mutex::new(RuleTable::default());
}

/// Sent from the RX datapath to the install worker. `rte_flow_create` takes far too long to run
/// inline on a poll loop, so the datapath only enqueues.
#[derive(Clone, Serialize)]
enum FlowEvent {
    DropFlow { tuple: FiveTuple },
}

/// Worker-side install. Deduped, and bounded at `--max-rules` so a run cannot silently become a
/// rule-table capacity experiment. `--table-full-policy` decides what happens at the bound.
fn install_hw_drop(tuple: &FiveTuple) {
    let ports = match PORT_IDS.get() {
        Some(p) => p,
        None => {
            log::warn!("hardware arm selected but no port ids resolved");
            return;
        }
    };

    let cap = *MAX_RULES.get().unwrap_or(&0);
    let policy = *TABLE_FULL_POLICY.get().unwrap_or(&TableFullPolicy::Refuse);

    // Decide and reserve under the lock; do no rte_flow work while holding it. A create or a
    // destroy is on the order of 12 us, and every other worker would serialise behind it.
    let victim = {
        let mut table = RULES.lock().unwrap();
        if table.resident.contains(tuple) {
            return;
        }

        let mut victim = None;
        if cap != 0 && table.resident.len() >= cap {
            match policy {
                TableFullPolicy::Refuse => {
                    OFFLOAD_REFUSED.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                TableFullPolicy::Evict => match table.fifo.pop_front() {
                    // Release the victim's reservation along with its rule, so that tuple can be
                    // offered again later.
                    Some(old) => {
                        table.resident.remove(&old.tuple);
                        victim = Some(old);
                    }
                    // Nothing installed yet to evict: every resident tuple is an install still in
                    // flight. Refuse rather than let the table exceed the cap.
                    None => {
                        OFFLOAD_REFUSED.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                },
            }
        }

        // Reserve before installing so a concurrent worker cannot double-install.
        table.resident.insert(*tuple);
        victim
    };

    // Evict before installing rather than after: against a real table limit the install would
    // otherwise fail with the victim still resident. `uninstall_flow` queries each COUNT handle
    // before destroying it, so an evicted rule's drops stay in the ground-truth totals and its
    // teardown is charged to `destroy_cycles`.
    if let Some(old) = victim {
        let flows: Vec<*mut rte_flow> = old.flow_ptrs.iter().map(|p| p.0).collect();
        let handles: Vec<*mut rte_flow_action_handle> =
            old.handle_ptrs.iter().map(|p| p.0).collect();
        if let Err(e) = uninstall_flow(old.ports.clone(), flows, handles) {
            log::warn!("failed to evict HW flow {:?}: {e:?}", old.tuple);
        }
        RULE_EVICTIONS.fetch_add(1, Ordering::Relaxed);
    }

    // `install_drop_flow` installs both directions and attaches an indirect COUNT action to each
    // rule, which is how the report proves the rules actually matched traffic.
    match install_drop_flow(ports.clone(), tuple) {
        Ok((flows, handles)) => {
            RULES.lock().unwrap().fifo.push_back(FlowEntry {
                tuple: *tuple,
                ports: ports.clone(),
                flow_ptrs: flows.into_iter().map(FlowPtr).collect(),
                handle_ptrs: handles.into_iter().map(HandlePtr).collect(),
            });
        }
        Err(e) => {
            log::warn!("HW drop rule install failed for {tuple:?}: {e:?}");
            RULES.lock().unwrap().resident.remove(tuple);
        }
    }
}

/// Read every still-resident rule's COUNT handle, then tear the rules down. Both paths accumulate
/// into `DISCARDED_PACKETS`/`DISCARDED_BYTES`, giving the NIC-side ground truth for how much
/// traffic was shed.
fn drain_rules(uninstall: bool) {
    let entries: Vec<FlowEntry> = {
        let mut table = RULES.lock().unwrap();
        table.resident.clear();
        table.fifo.drain(..).collect()
    };
    for entry in entries {
        let flows: Vec<*mut rte_flow> = entry.flow_ptrs.iter().map(|p| p.0).collect();
        let handles: Vec<*mut rte_flow_action_handle> =
            entry.handle_ptrs.iter().map(|p| p.0).collect();
        if uninstall {
            if let Err(e) = uninstall_flow(entry.ports.clone(), flows, handles) {
                log::warn!("failed to uninstall HW flow: {e:?}");
            }
        } else if let Err(e) = query_resident_flow(&entry.ports, &flows, &handles) {
            log::warn!("failed to query resident HW flow: {e:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// The synthetic application workload.
// ---------------------------------------------------------------------------

/// Burn approximately `target` TSC cycles.
///
/// This stands in for application logic so the freed-cycle headroom can be swept against a known
/// application cost. It is bounded by `rte_rdtsc` rather than by an iteration count so that the
/// cost is expressed in the same units as the cycle budget and does not drift with CPU frequency
/// or microarchitecture. `black_box` keeps the arithmetic from being optimised away.
///
/// Returns the cycles actually consumed, which overshoots `target` by up to one loop iteration.
#[inline(never)]
fn burn_cycles(target: u64) -> u64 {
    if target == 0 {
        return 0;
    }
    let start = unsafe { iris_core::rte_rdtsc() };
    let mut acc: u64 = start;
    loop {
        // A few rounds of cheap arithmetic between clock reads, so the loop is not purely
        // rdtsc-bound and looks more like real work to the core's execution ports.
        for _ in 0..8 {
            acc = acc
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            std::hint::black_box(acc);
        }
        let elapsed = unsafe { iris_core::rte_rdtsc() }.wrapping_sub(start);
        if elapsed >= target {
            return elapsed;
        }
    }
}

// ---------------------------------------------------------------------------
// The datapath callback.
// ---------------------------------------------------------------------------

/// Fires once per TLS connection, at the point the session turns to ciphertext.
///
/// The `tls` session datatype resolves to `L7EndHdrs`, which is exactly the transition
/// `dyn_hardware_assist` is meant to exploit: everything after it is opaque, so there is nothing
/// left for the CPU to learn from the connection's remaining packets.
///
/// Order matters: the application work runs *before* the drop is arranged, so it is charged to the
/// datapath in every arm identically.
#[callback("tls")]
fn on_ciphertext(tls: &TlsHandshake, five_tuple: &FiveTuple, core_id: &CoreId) {
    TLS_CALLBACKS.fetch_add(1, Ordering::Relaxed);

    // Touch the handshake so the parse cannot be optimised away, and so the workload has a
    // plausible input. This is the data a real analysis application would consume.
    std::hint::black_box(tls.sni().len());

    let burned = burn_cycles(*APP_CYCLES.get().unwrap_or(&0));
    APP_CYCLES_BURNED.fetch_add(burned, Ordering::Relaxed);

    match DROP_MODE.get().copied().unwrap_or(DropMode::None) {
        DropMode::None => {}
        DropMode::Hardware => {
            // Never install inline: `rte_flow_create` is orders of magnitude slower than a poll
            // iteration and would stall the RX core.
            if let Some(d) = FLOW_DISPATCHER.get() {
                if d.dispatch(FlowEvent::DropFlow { tuple: *five_tuple }, Some(core_id))
                    .is_ok()
                {
                    SHED_CONNS.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CycleBudgetReport {
    /// Cycle buckets, attributed over the sampled iterations only (see `sample_stride`). Sum to
    /// `sampled_wall`.
    poll_busy: u64,
    poll_idle: u64,
    pipeline: u64,
    maint: u64,
    sampled_wall: u64,
    sampled_iters: u64,
    /// One in every this many loop iterations was attributed. 1 = exact.
    sample_stride: u64,
    /// Share of the run's cycles covered by the sample.
    sampled_share: f64,
    /// Exact counters, not sampled.
    wall: u64,
    bursts: u64,
    idle_polls: u64,
    recv_pkts: u64,
    rx_cores: u64,
    /// `poll_idle` scaled up to the whole run: the estimated absolute size of the freed-cycle pool.
    est_poll_idle_cycles: f64,
    /// Share of RX-core cycles spent polling an empty queue. **The headline**: the pool of cycles
    /// available to application logic. Should rise in the treatment arm.
    idle_fraction: f64,
    /// Share spent on packet work (`poll_busy + pipeline + maint`).
    busy_fraction: f64,
    /// `idle_fraction` expressed as whole cores.
    cores_idle: f64,
    /// Floor on how much of an idle cycle is really reclaimable: an empty burst still reads a
    /// completion-queue entry.
    cycles_per_idle_poll: f64,
    /// Must be ~0. Non-zero means the poll loop has an unbracketed path and this budget is wrong.
    residual_fraction: f64,
    /// Measurement overhead as a share of `wall`. Must be far below the A/B effect size, or the
    /// result is not credible.
    instrumentation_fraction: f64,
    cycles_per_rdtsc_read: f64,
    /// Per-read cost measured on the RX cores and already subtracted from each bucket, so the
    /// correction is auditable rather than implicit.
    rdtsc_cost_subtracted: u64,
}

#[derive(Serialize)]
struct NormalisedMetrics {
    /// **M1, the primary metric.** Datapath cycles per packet the NIC *saw*. Load-normalised, so
    /// it is comparable across paired runs on non-stationary live traffic, and it falls when the
    /// NIC sheds traffic (unlike cycles per *received* packet).
    cycles_per_ingress_pkt: f64,
    cycles_per_ingress_byte: f64,
    /// Included for contrast only. This is the metric that can move the wrong way; do not report
    /// it as the result.
    cycles_per_received_pkt: f64,
    /// Fraction of ingress packets that never reached software.
    shed_fraction_pkts: f64,
    /// False when the PMD does not expose `rx_phy_*`, in which case the ingress-normalised
    /// numbers above are meaningless and the run must be discarded.
    ingress_normalisation_valid: bool,
}

#[derive(Serialize)]
struct ControlPlaneCost {
    /// Cycles inside `rte_flow_create`. Charged against the mechanism.
    install_cycles: u64,
    installs: u64,
    install_failures: u64,
    destroy_cycles: u64,
    destroys: u64,
    mean_install_cycles: f64,
    /// Rules the app declined to install because `--max-rules` was reached.
    offload_refused: u64,
    /// Rules evicted to make room under `--table-full-policy evict`. Their drops are still in
    /// `ground_truth.discarded_packets` and their teardown in `destroy_cycles`, so eviction churn
    /// is charged to the mechanism rather than hidden.
    evictions: u64,
    /// Install cycles as a share of one RX core's `wall`. If this approaches the datapath saving,
    /// the mechanism does not pay for itself at this connection arrival rate.
    install_cycles_vs_core_wall: f64,
}

#[derive(Serialize)]
struct GroundTruth {
    /// Packets/bytes the NIC's drop rules actually matched, read from the rules' indirect COUNT
    /// actions. Zero here with a non-zero `shed_conns` means the experiment measured nothing.
    discarded_packets: u64,
    discarded_bytes: u64,
    /// `phy - good - phy_discard`, summed over ports. Should be ~0; a large value means packets
    /// went somewhere unaccounted for and the reconciliation failed.
    ingress_reconciliation_gap: i64,
}

#[derive(Serialize)]
struct Report {
    arm: String,
    drop_mode: DropMode,
    app_cycles_requested: u64,
    max_rules: usize,
    table_full_policy: TableFullPolicy,
    config_path: String,
    /// Arm-equivalence check: must match across arms.
    tls_callbacks: u64,
    app_cycles_burned: u64,
    shed_conns: u64,
    budget: CycleBudgetReport,
    normalised: NormalisedMetrics,
    control_plane: ControlPlaneCost,
    ground_truth: GroundTruth,
    ingress: Vec<IngressCounters>,
    tsc_hz: u64,
}

// ---------------------------------------------------------------------------

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

    /// Which shedding mechanism to exercise. `none` is the control arm.
    #[clap(long, arg_enum, default_value = "none")]
    drop_mode: DropMode,

    /// Free-text arm label recorded in the report (e.g. "A", "B").
    #[clap(long, default_value = "unlabelled")]
    arm: String,

    /// Synthetic application work per TLS connection, in TSC cycles. Sweep this to trade the
    /// freed-cycle headroom against a known application cost.
    #[clap(long, default_value = "0")]
    app_cycles: u64,

    /// Cap on concurrently installed NIC rules (0 = unbounded). Bounds the run so it does not
    /// silently turn into a rule-table capacity test.
    #[clap(long, default_value = "0")]
    max_rules: usize,

    /// What to do once `--max-rules` is reached: `refuse` the offload, or `evict` the least
    /// recently added rule to make room.
    ///
    /// Defaults to `refuse`, which is what earlier runs did — switching the default would silently
    /// change what `--max-rules N` means and break comparison with reports already collected.
    #[clap(long, arg_enum, default_value = "refuse")]
    table_full_policy: TableFullPolicy,

    /// Cores for the off-datapath rule-install worker (comma-separated). Must not overlap the RX
    /// cores in the config.
    #[clap(long, value_delimiter = ',', default_value = "17")]
    worker_cores: Vec<u32>,

    /// Dispatcher channel depth for install requests.
    #[clap(long, default_value = "32768")]
    flow_channel_size: usize,

    /// Leave the NIC rules installed at shutdown (they are read for counters either way). The
    /// port stop flushes them regardless; this only affects whether they are explicitly destroyed,
    /// and so whether `destroy_cycles` is measured.
    #[clap(long)]
    keep_rules: bool,

    /// Write the run report here as JSON. Everything downstream should read this rather than
    /// scraping stdout.
    #[clap(long, parse(from_os_str), value_name = "FILE")]
    report: Option<PathBuf>,
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();

    let _ = DROP_MODE.set(args.drop_mode);
    let _ = APP_CYCLES.set(args.app_cycles);
    let _ = MAX_RULES.set(args.max_rules);
    let _ = TABLE_FULL_POLICY.set(args.table_full_policy);

    let mut config = load_config(&args.config);

    // Neither arm uses the software flow table, so leave it unallocated: the runtime allocates it
    // iff `config.flow_table` is Some, and a table nothing installs into would charge both arms a
    // per-packet lookup for nothing.
    config.flow_table = None;

    // Stand the install worker up before the runtime, so no dispatch can be dropped on the floor
    // during the first bursts.
    let mut worker_handle = None;
    if args.drop_mode == DropMode::Hardware {
        let rx_cores = config.get_all_rx_core_ids();
        if let Some(overlap) = args
            .worker_cores
            .iter()
            .find(|c| rx_cores.contains(&CoreId(**c)))
        {
            // Sharing a core would let install work steal cycles from the datapath being measured.
            panic!(
                "worker core {} is also an RX core; pick a core outside {:?}",
                overlap, rx_cores
            );
        }
        let dispatcher = Arc::new(ChannelDispatcher::new(
            ChannelMode::PerCore(rx_cores),
            args.flow_channel_size,
            "flow_dispatcher".to_string(),
        ));
        FLOW_DISPATCHER
            .set(dispatcher.clone())
            .map_err(|_| "failed to set flow dispatcher")
            .unwrap();
        worker_handle = Some(
            SharedWorkerThreadSpawner::new()
                .set_cores(args.worker_cores.iter().map(|&c| CoreId(c)).collect())
                .set_batch_size(16)
                .add_dispatcher(dispatcher, |event: FlowEvent| match event {
                    FlowEvent::DropFlow { tuple } => install_hw_drop(&tuple),
                })
                .run(),
        );
    }

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config.clone(), filter).unwrap();

    // Port ids are only resolvable after EAL init and port probe.
    let port_ids: Vec<PortId> = config
        .online
        .as_ref()
        .map(|online| {
            online
                .ports
                .iter()
                .map(|p| PortId::new_from_device(p.device.clone()))
                .collect()
        })
        .unwrap_or_default();
    let _ = PORT_IDS.set(port_ids.clone());

    // Calibrate the instrumentation's own cost before the run, on an idle core, so the report can
    // state what fraction of the budget is measurement overhead.
    let cycles_per_rdtsc_read = iris_core::stats::measure_rdtsc_overhead(100_000);
    let tsc_hz = unsafe { iris_core::rte_get_tsc_hz() };

    // Everything that touches the NIC has to happen in the pre-stop hook, i.e. after the RX cores
    // have exited but before the ports are stopped. `stop_ports` calls `rte_flow_flush` and
    // `rte_eth_dev_stop`, which free every rule and indirect COUNT handle installed during the
    // run; doing this work after `run` returns queried freed handles and died with SIGBUS, so the
    // hardware arm could never write a report. The order within the hook matters too: the install
    // worker must be joined first, or it keeps calling `rte_flow_create` on a port about to stop.
    let mut ingress: Vec<IngressCounters> = Vec::new();
    {
        let mut worker_handle = worker_handle;
        let mut pre_stop = || {
            if let Some(h) = worker_handle.take() {
                h.shutdown(None);
            }

            // Read the NIC-side ground truth while the rules are still resident.
            drain_rules(!args.keep_rules);

            ingress = port_ids
                .iter()
                .filter_map(|pid| match ingress_counters(*pid) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        log::warn!("could not read ingress counters for port {pid}: {e:?}");
                        None
                    }
                })
                .collect();
        };
        runtime.run_with_pre_stop(&mut pre_stop);
    }

    let report = build_report(&args, &ingress, cycles_per_rdtsc_read, tsc_hz);
    print_summary(&report);

    if let Some(path) = &args.report {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json + "\n") {
                    log::error!("failed to write report to {}: {e}", path.display());
                }
            }
            Err(e) => log::error!("failed to serialise report: {e}"),
        }
    }
}

fn build_report(
    args: &Args,
    ingress: &[IngressCounters],
    cycles_per_rdtsc_read: f64,
    tsc_hz: u64,
) -> Report {
    let b = iris_core::stats::datapath_budget();
    let (install_cycles, installs, install_failures, destroy_cycles, destroys) =
        rule_control_cost();

    let phy_pkts: u64 = ingress.iter().map(|c| c.phy_packets).sum();
    let phy_bytes: u64 = ingress.iter().map(|c| c.phy_bytes).sum();
    let good_pkts: u64 = ingress.iter().map(|c| c.good_packets).sum();
    let phy_discard: u64 = ingress.iter().map(|c| c.phy_discard_packets).sum();
    // Every port must expose rx_phy_* for the ingress-normalised metric to mean anything.
    let phy_ok = !ingress.is_empty() && ingress.iter().all(|c| c.phy_available);

    // Only packet work belongs in the numerator: idle polling is by definition not packet cost.
    //
    // The bucket totals cover the sampled iterations only, so scale the sampled *fraction* up by
    // the exact `wall` to get the run's total work cycles. Dividing raw sampled cycles by total
    // ingress packets would understate the cost by the sampling stride.
    let work_cycles = b.busy_fraction() * b.wall as f64;
    let per_core_wall = if b.cores > 0 { b.wall / b.cores } else { 0 };

    Report {
        arm: args.arm.clone(),
        drop_mode: args.drop_mode,
        app_cycles_requested: args.app_cycles,
        max_rules: args.max_rules,
        table_full_policy: args.table_full_policy,
        config_path: args.config.display().to_string(),
        tls_callbacks: TLS_CALLBACKS.load(Ordering::Relaxed),
        app_cycles_burned: APP_CYCLES_BURNED.load(Ordering::Relaxed),
        shed_conns: SHED_CONNS.load(Ordering::Relaxed),
        budget: CycleBudgetReport {
            poll_busy: b.poll_busy,
            poll_idle: b.poll_idle,
            pipeline: b.pipeline,
            maint: b.maint,
            sampled_wall: b.sampled_wall,
            sampled_iters: b.sampled_iters,
            sample_stride: b.sample_stride,
            sampled_share: b.sampled_share(),
            wall: b.wall,
            bursts: b.bursts,
            idle_polls: b.idle_polls,
            recv_pkts: b.recv_pkts,
            rx_cores: b.cores,
            est_poll_idle_cycles: b.est_poll_idle_cycles(),
            idle_fraction: b.idle_fraction(),
            busy_fraction: b.busy_fraction(),
            cores_idle: b.cores_idle(),
            cycles_per_idle_poll: b.cycles_per_idle_poll(),
            residual_fraction: b.residual_fraction(),
            instrumentation_fraction: b.instrumentation_fraction(cycles_per_rdtsc_read),
            cycles_per_rdtsc_read,
            rdtsc_cost_subtracted: b.rdtsc_cost,
        },
        normalised: NormalisedMetrics {
            cycles_per_ingress_pkt: fdiv(work_cycles, phy_pkts as f64),
            cycles_per_ingress_byte: fdiv(work_cycles, phy_bytes as f64),
            cycles_per_received_pkt: fdiv(work_cycles, b.recv_pkts as f64),
            shed_fraction_pkts: if phy_pkts > 0 {
                1.0 - (good_pkts as f64 / phy_pkts as f64)
            } else {
                0.0
            },
            ingress_normalisation_valid: phy_ok,
        },
        control_plane: ControlPlaneCost {
            install_cycles,
            installs,
            install_failures,
            destroy_cycles,
            destroys,
            mean_install_cycles: div(install_cycles, installs),
            offload_refused: OFFLOAD_REFUSED.load(Ordering::Relaxed),
            evictions: RULE_EVICTIONS.load(Ordering::Relaxed),
            install_cycles_vs_core_wall: div(install_cycles, per_core_wall),
        },
        ground_truth: GroundTruth {
            discarded_packets: DISCARDED_PACKETS.load(Ordering::Relaxed),
            discarded_bytes: DISCARDED_BYTES.load(Ordering::Relaxed),
            ingress_reconciliation_gap: phy_pkts as i64 - good_pkts as i64 - phy_discard as i64,
        },
        ingress: ingress.to_vec(),
        tsc_hz,
    }
}

fn div(num: u64, den: u64) -> f64 {
    fdiv(num as f64, den as f64)
}

fn fdiv(num: f64, den: f64) -> f64 {
    if den == 0.0 {
        0.0
    } else {
        num / den
    }
}

fn print_summary(r: &Report) {
    println!(
        "\n=== hw_assist_eval: arm {} ({:?}) ===",
        r.arm, r.drop_mode
    );
    println!(
        "TLS callbacks:            {}  (must match across arms)",
        r.tls_callbacks
    );
    println!(
        "App cycles:               {} requested/conn, {} burned total",
        r.app_cycles_requested, r.app_cycles_burned
    );
    println!("Connections shed:         {}", r.shed_conns);
    println!(
        "NIC discarded:            {} pkts, {} bytes",
        r.ground_truth.discarded_packets, r.ground_truth.discarded_bytes
    );
    println!("--- cycle budget ({} RX cores) ---", r.budget.rx_cores);
    println!(
        "  poll_idle:              {:>7.3}%   <- freed-cycle pool ({:.2} cores)",
        100.0 * r.budget.idle_fraction,
        r.budget.cores_idle
    );
    println!(
        "  poll_busy:              {:>7.3}%",
        100.0 * div(r.budget.poll_busy, r.budget.sampled_wall)
    );
    println!(
        "  pipeline:               {:>7.3}%",
        100.0 * div(r.budget.pipeline, r.budget.sampled_wall)
    );
    println!(
        "  maint:                  {:>7.3}%",
        100.0 * div(r.budget.maint, r.budget.sampled_wall)
    );
    println!(
        "  residual:               {:>7.4}%  (must be ~0)",
        100.0 * r.budget.residual_fraction
    );
    println!(
        "  instrumentation:        {:>7.4}%  ({:.1} cyc/rdtsc)",
        100.0 * r.budget.instrumentation_fraction,
        r.budget.cycles_per_rdtsc_read
    );
    println!(
        "  sampling:               1 in {} iters, {} sampled, {:.2}% of cycles covered",
        r.budget.sample_stride,
        r.budget.sampled_iters,
        100.0 * r.budget.sampled_share
    );
    println!(
        "  rdtsc cost subtracted:  {} cyc/span (removes the idle-poll inflation bias)",
        r.budget.rdtsc_cost_subtracted
    );
    println!("--- normalised ---");
    println!(
        "  cycles/ingress pkt:     {:>10.2}   <- PRIMARY{}",
        r.normalised.cycles_per_ingress_pkt,
        if r.normalised.ingress_normalisation_valid {
            ""
        } else {
            "  [INVALID: no rx_phy_* from this PMD]"
        }
    );
    println!(
        "  cycles/ingress byte:    {:>10.4}",
        r.normalised.cycles_per_ingress_byte
    );
    println!(
        "  cycles/received pkt:    {:>10.2}   (for contrast; can move the wrong way)",
        r.normalised.cycles_per_received_pkt
    );
    println!(
        "  shed fraction:          {:>9.3}%",
        100.0 * r.normalised.shed_fraction_pkts
    );
    println!("--- control-plane cost (charged against the mechanism) ---");
    println!(
        "  installs:               {} ({} failed, {} refused), mean {:.0} cycles",
        r.control_plane.installs,
        r.control_plane.install_failures,
        r.control_plane.offload_refused,
        r.control_plane.mean_install_cycles
    );
    println!(
        "  install cycles:         {} ({:.4}% of one RX core)",
        r.control_plane.install_cycles,
        100.0 * r.control_plane.install_cycles_vs_core_wall
    );
    println!(
        "  table {:?} at max_rules {}: {} evicted, {} destroy cycles over {} destroys",
        r.table_full_policy,
        r.max_rules,
        r.control_plane.evictions,
        r.control_plane.destroy_cycles,
        r.control_plane.destroys
    );
    println!(
        "  ingress reconciliation gap: {} pkts (should be ~0)",
        r.ground_truth.ingress_reconciliation_gap
    );
}
