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
    install_drop_flow, query_resident_flow, rule_control_cost, uninstall_flow, RuleControlCost,
    DISCARDED_BYTES, DISCARDED_PACKETS,
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

// Cycle buckets for the rule-management core, measured on the worker thread itself. These cover
// the part of the install path that lives in this binary; the PMD calls underneath are timed in
// `iris_core::filter::flow_drop`, and the loop around it in `iris_core::stats::WorkerBudget`.
// Together the three layers account for the worker core's whole busy time, and the report checks
// that they reconcile rather than assuming they do.
//
// Unlike the RX budget these are exact, not sampled: the unit of work is an `rte_flow_create` of
// order 12 us, against which an `rte_rdtsc` is under 0.1%. Sampling exists on the datapath because
// there an empty poll is only a few reads long.
/// The install path's cycle buckets.
///
/// Grouped in one struct rather than left as free statics only for readability; sharing a cache
/// line was tried as a way to cut the attribution's own cost and measurably did not help, so
/// nothing here depends on their layout.
struct InstallBuckets {
    /// Handler entry up to the first lock attempt: three `OnceLock` reads and the `RULES` deref.
    /// Nominally a few dozen cycles, and more in practice, since a parked core takes them cold.
    preamble: AtomicU64,
    /// Waiting for the `RULES` mutex. The lock is deliberately never held across an `rte_flow`
    /// call, so with one worker core this is pure uncontended-acquire cost; with several it is the
    /// figure that says whether more worker cores buy install throughput or just contention.
    lock_wait: AtomicU64,
    /// Under the lock, on the dedup set and the FIFO.
    table: AtomicU64,
    /// Inside `install_drop_flow`: every PMD call for one rule set, plus the pattern and action
    /// marshalling around them. Timed as a whole span so that subtracting the individually timed
    /// PMD calls leaves the glue as a residual — nothing can hide in a span never opened.
    install_span: AtomicU64,
    /// Inside `uninstall_flow` on the eviction path. Excludes the shutdown drain, which runs on
    /// the main thread and is not a steady-state cost.
    evict_span: AtomicU64,
}

static INSTALL_BUCKETS: InstallBuckets = InstallBuckets {
    preamble: AtomicU64::new(0),
    lock_wait: AtomicU64::new(0),
    table: AtomicU64::new(0),
    install_span: AtomicU64::new(0),
    evict_span: AtomicU64::new(0),
};
/// Offload requests for a tuple already resident or already installing. These reach the worker,
/// take the lock and return, so they cost utilisation while installing nothing.
static DEDUP_HITS: AtomicU64 = AtomicU64::new(0);
/// Offload requests the datapath could not enqueue because the worker's channel was full.
///
/// Distinct from `OFFLOAD_REFUSED`, which is the rule table hitting `--max-rules`. This one means
/// the *worker* could not keep up, and without it a saturated worker is indistinguishable from a
/// low connection arrival rate.
static DISPATCH_FAILURES: AtomicU64 = AtomicU64::new(0);

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

/// What the reservation step decided. Split out from [`install_hw_drop`] so the work done under
/// the lock has exactly one exit, and the caller can therefore close its cycle bucket on every
/// path — an early `return` from inside the critical section would drop those cycles into the
/// residual instead.
enum Reservation {
    /// Already resident, or an install for it is already in flight.
    Duplicate,
    /// The table is at `--max-rules` and the policy is to decline.
    Refused,
    /// Reserved; install, evicting `victim` first if there is one.
    Proceed { victim: Option<FlowEntry> },
}

/// Decide and reserve, doing no `rte_flow` work: the caller holds the lock across this and a
/// create or destroy is on the order of 12 us, which every other worker would serialise behind.
fn reserve(
    table: &mut RuleTable,
    tuple: &FiveTuple,
    cap: usize,
    policy: TableFullPolicy,
) -> Reservation {
    if table.resident.contains(tuple) {
        return Reservation::Duplicate;
    }

    let mut victim = None;
    if cap != 0 && table.resident.len() >= cap {
        match policy {
            TableFullPolicy::Refuse => return Reservation::Refused,
            TableFullPolicy::Evict => match table.fifo.pop_front() {
                // Release the victim's reservation along with its rule, so that tuple can be
                // offered again later.
                Some(old) => {
                    table.resident.remove(&old.tuple);
                    victim = Some(old);
                }
                // Nothing installed yet to evict: every resident tuple is an install still in
                // flight. Refuse rather than let the table exceed the cap.
                None => return Reservation::Refused,
            },
        }
    }

    // Reserve before installing so a concurrent worker cannot double-install.
    table.resident.insert(*tuple);
    Reservation::Proceed { victim }
}

/// Worker-side install. Deduped, and bounded at `--max-rules` so a run cannot silently become a
/// rule-table capacity experiment. `--table-full-policy` decides what happens at the bound.
///
/// Runs on the rule-management core, and every cycle of it is attributed: the buckets here plus
/// the PMD counters in `iris_core::filter::flow_drop` should account for
/// `WorkerBudget::handler`, which is measured independently from inside the worker loop.
fn install_hw_drop(tuple: &FiveTuple) {
    let t_entry = unsafe { iris_core::rte_rdtsc() };

    let ports = match PORT_IDS.get() {
        Some(p) => p,
        None => {
            log::warn!("hardware arm selected but no port ids resolved");
            return;
        }
    };

    let cap = *MAX_RULES.get().unwrap_or(&0);
    let policy = *TABLE_FULL_POLICY.get().unwrap_or(&TableFullPolicy::Refuse);

    let reservation = {
        let t_enter = unsafe { iris_core::rte_rdtsc() };
        let mut table = RULES.lock().unwrap();
        let t_locked = unsafe { iris_core::rte_rdtsc() };
        let reservation = reserve(&mut table, tuple, cap, policy);
        drop(table);
        let t_done = unsafe { iris_core::rte_rdtsc() };

        // All three updates after the last read, so that no bucket absorbs another's write.
        INSTALL_BUCKETS
            .preamble
            .fetch_add(t_enter.wrapping_sub(t_entry), Ordering::Relaxed);
        INSTALL_BUCKETS
            .lock_wait
            .fetch_add(t_locked.wrapping_sub(t_enter), Ordering::Relaxed);
        INSTALL_BUCKETS
            .table
            .fetch_add(t_done.wrapping_sub(t_locked), Ordering::Relaxed);
        reservation
    };

    let victim = match reservation {
        Reservation::Duplicate => {
            DEDUP_HITS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        Reservation::Refused => {
            OFFLOAD_REFUSED.fetch_add(1, Ordering::Relaxed);
            return;
        }
        Reservation::Proceed { victim } => victim,
    };

    // Evict before installing rather than after: against a real table limit the install would
    // otherwise fail with the victim still resident. `uninstall_flow` queries each COUNT handle
    // before destroying it, so an evicted rule's drops stay in the ground-truth totals and its
    // teardown is charged to `destroy_cycles`.
    if let Some(old) = victim {
        let flows: Vec<*mut rte_flow> = old.flow_ptrs.iter().map(|p| p.0).collect();
        let handles: Vec<*mut rte_flow_action_handle> =
            old.handle_ptrs.iter().map(|p| p.0).collect();

        let start = unsafe { iris_core::rte_rdtsc() };
        let evicted = uninstall_flow(old.ports.clone(), flows, handles);
        INSTALL_BUCKETS.evict_span.fetch_add(
            unsafe { iris_core::rte_rdtsc() }.wrapping_sub(start),
            Ordering::Relaxed,
        );

        if let Err(e) = evicted {
            log::warn!("failed to evict HW flow {:?}: {e:?}", old.tuple);
        }
        RULE_EVICTIONS.fetch_add(1, Ordering::Relaxed);
    }

    // `install_drop_flow` installs both directions and attaches an indirect COUNT action to each
    // rule, which is how the report proves the rules actually matched traffic.
    let start = unsafe { iris_core::rte_rdtsc() };
    let installed = install_drop_flow(ports.clone(), tuple);
    INSTALL_BUCKETS.install_span.fetch_add(
        unsafe { iris_core::rte_rdtsc() }.wrapping_sub(start),
        Ordering::Relaxed,
    );

    let t_enter = unsafe { iris_core::rte_rdtsc() };
    let mut table = RULES.lock().unwrap();
    let t_locked = unsafe { iris_core::rte_rdtsc() };
    match installed {
        Ok((flows, handles)) => {
            table.fifo.push_back(FlowEntry {
                tuple: *tuple,
                ports: ports.clone(),
                flow_ptrs: flows.into_iter().map(FlowPtr).collect(),
                handle_ptrs: handles.into_iter().map(HandlePtr).collect(),
            });
        }
        Err(e) => {
            log::warn!("HW drop rule install failed for {tuple:?}: {e:?}");
            table.resident.remove(tuple);
        }
    }
    drop(table);
    let t_done = unsafe { iris_core::rte_rdtsc() };

    INSTALL_BUCKETS
        .lock_wait
        .fetch_add(t_locked.wrapping_sub(t_enter), Ordering::Relaxed);
    INSTALL_BUCKETS
        .table
        .fetch_add(t_done.wrapping_sub(t_locked), Ordering::Relaxed);
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
                // A failure here is the worker's queue being full, i.e. the rule-management core
                // not keeping up. Counted rather than swallowed: otherwise a saturated worker
                // looks identical to a low connection arrival rate.
                match d.dispatch(FlowEvent::DropFlow { tuple: *five_tuple }, Some(core_id)) {
                    Ok(()) => {
                        SHED_CONNS.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        DISPATCH_FAILURES.fetch_add(1, Ordering::Relaxed);
                    }
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

/// What the rule-management core cost, as opposed to what its PMD calls cost.
///
/// [`ControlPlaneCost`] charges the mechanism for the cycles inside `rte_flow_create`. This charges
/// it for the **core**: every cycle the install worker was on-CPU, whether that was in a PMD call,
/// waiting for the rule-table lock, or taking events off its queue. The two differ by a lot, and
/// the difference is not overhead that can be waved away — a core the offload occupies is a core
/// the application does not get, no matter which instruction it was executing.
///
/// Note that only `busy_fraction` and `cores_busy` measure utilisation. The cycle buckets are
/// `rte_rdtsc` spans, which keep counting while the thread is parked; see
/// [`iris_core::stats::WorkerBudget`] for why measuring this needs two clocks.
#[derive(Serialize)]
struct RuleManagementReport {
    /// Worker threads instrumented, i.e. the width of `--worker-cores`.
    cores: u64,
    /// On-CPU seconds summed over the worker threads, from `CLOCK_THREAD_CPUTIME_ID`.
    cpu_seconds: f64,
    /// **The headline.** Mean share of one worker core consumed over the run.
    busy_fraction: f64,
    /// Utilisation expressed as whole cores. Subtract from `budget.cores_idle` for the net
    /// freed-core figure; `tools/paired_ab.py` does that across the arms, which is the only place
    /// it can be done, since one run cannot see the other arm.
    cores_busy: f64,
    /// Offload requests per second sustainable at 100% of one core.
    ///
    /// Requests, not rules: one request installs a rule per direction per port, and may instead
    /// dedup or be refused. Requests are the unit to compare against a TLS connection arrival
    /// rate, which is the crossover the README predicts as the binding constraint. Independent of
    /// this run's offered load, unlike a utilisation fraction.
    sustainable_offload_rate: f64,

    /// Cycles spanned by the worker loop, and the buckets it splits into.
    wall_cycles: u64,
    /// In `Select::select()` with nothing to do — parked, or spinning before it parks.
    blocked_cycles: u64,
    /// Taking events off the channel and assembling a batch.
    dispatch_cycles: u64,
    /// Inside `install_hw_drop`, the indirect call to it included.
    handler_cycles: u64,
    /// The dispatcher's per-batch counter updates. Three cold atomics on a core that parks
    /// between batches, which is why they are not folded into `handler_cycles`.
    bookkeeping_cycles: u64,
    /// Share of `blocked_cycles` that was actually on-CPU. Near 0 means the worker gives the core
    /// back between installs and `busy_fraction` is the whole cost; near 1 means the "idle" worker
    /// is burning a core and `blocked_cycles` should be read as cost, not slack.
    spin_fraction: f64,
    /// Must be ~0. Non-zero means the worker loop has a path the instrumentation does not bracket.
    loop_residual_fraction: f64,

    /// Offload requests the worker handled. The denominator for the per-request means, and the
    /// unit `sustainable_offload_rate` is expressed in.
    offload_requests: u64,
    /// Handler entry to the first lock attempt. Larger than its instruction count suggests, since
    /// a parked core takes these accesses cold.
    preamble_cycles: u64,
    /// Waiting for the `RULES` mutex. With one worker core this is uncontended-acquire cost; with
    /// several it is the figure that says whether more worker cores buy install throughput.
    lock_wait_cycles: u64,
    /// Under the lock, on the dedup set and the FIFO.
    table_cycles: u64,
    /// The whole `install_drop_flow` span, PMD calls included.
    install_span_cycles: u64,
    /// The whole `uninstall_flow` span on the eviction path.
    evict_span_cycles: u64,
    /// Per-PMD-entry-point cycles attributable to the worker, snapshotted when it stopped so the
    /// shutdown drain's queries and destroys stay out. Those are teardown, not a steady-state
    /// per-install cost, and their size depends only on how many rules happened to be resident.
    pmd: RuleControlCost,
    /// `install_span - (flow_create + handle_create)`: pattern building, action marshalling and
    /// the `Vec`s around them. A residual rather than a bucket, so nothing can hide in a span the
    /// instrumentation forgot to open. Signed, since two independent reads can cross at low counts.
    install_glue_cycles: i64,
    /// Share of `handler_cycles` that no bucket above covers.
    ///
    /// What lives in this region is per-call overhead outside every span: the boxed-closure
    /// dispatch, the batch iteration, the bucket updates themselves, and the handler's own
    /// prologue and epilogue. It has not been attributed more finely than that. Packing the
    /// buckets onto one cache line was tried on the theory that their read-modify-writes dominated
    /// and made no difference, so the cause is not established — treat it as cold-core per-call
    /// cost, and expect it to shrink as a share once the install rate keeps the core warm.
    ///
    /// It is also the cross-check between the two instrumentation layers: `handler_cycles` is
    /// timed independently inside the worker loop, so a jump here means a span stopped being
    /// bracketed. Note that it does **not** put the headline at risk — `busy_fraction` comes from
    /// the CPU clock, not from these buckets, so incomplete attribution cannot understate the cost.
    handler_unbracketed_fraction: f64,
    /// What `control_plane.install_cycles` was missing: on-CPU cycles over `rte_flow_create`
    /// cycles. The factor by which charging the mechanism for its creates alone understates it.
    understatement_vs_install_cycles: f64,

    /// Offload requests for a tuple already resident. They cost utilisation and install nothing.
    dedup_hits: u64,
    /// Offloads lost because the worker's queue was full — the worker, not the rule table, being
    /// the bottleneck. Non-zero means `shed_conns` undercounts what the policy asked for.
    dispatch_failures: u64,
    /// Involuntary context switches on the worker cores. Should be ~0 under `isolcpus`; a large
    /// value means something else was scheduled there and `busy_fraction` describes this thread
    /// rather than the core.
    nonvoluntary_ctxt_switches: u64,
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
    rule_management: RuleManagementReport,
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
    //
    // Stood up in **both** arms, not just the hardware one. Nothing dispatches to it in the
    // control arm, so it parks immediately and should report ~0 utilisation — which is worth
    // measuring rather than assuming, and which keeps the two arms holding the same number of
    // cores so "cores consumed" can be compared directly instead of across different machines.
    let worker_handle = {
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
        SharedWorkerThreadSpawner::new()
            .set_cores(args.worker_cores.iter().map(|&c| CoreId(c)).collect())
            .set_batch_size(16)
            .measure_utilisation(true)
            .add_dispatcher(dispatcher, |event: FlowEvent| match event {
                FlowEvent::DropFlow { tuple } => install_hw_drop(&tuple),
            })
            .run()
    };

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
    // PMD control-plane cost as of the moment the worker stopped. Snapshotted here rather than
    // read at the end so the shutdown drain's queries and destroys stay out of it: that work runs
    // on the main thread, scales with how many rules happened to still be resident, and is not a
    // cost the mechanism pays per install.
    let mut worker_pmd = RuleControlCost::default();
    {
        let mut worker_handle = Some(worker_handle);
        let mut pre_stop = || {
            if let Some(h) = worker_handle.take() {
                h.shutdown(None);
            }
            worker_pmd = rule_control_cost();

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

    let report = build_report(&args, &ingress, &worker_pmd, cycles_per_rdtsc_read, tsc_hz);
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
    worker_pmd: &RuleControlCost,
    cycles_per_rdtsc_read: f64,
    tsc_hz: u64,
) -> Report {
    let b = iris_core::stats::datapath_budget();
    // Read at the end, not in the pre-stop hook: `shutdown` joins the worker threads, and each
    // publishes its budget as it leaves the loop.
    let w = iris_core::stats::worker_budget();
    // The whole-run PMD cost, teardown included. `worker_pmd` is the steady-state subset.
    let cp = rule_control_cost();

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
            install_cycles: cp.install_cycles,
            installs: cp.installs,
            install_failures: cp.install_failures,
            destroy_cycles: cp.destroy_cycles,
            destroys: cp.destroys,
            mean_install_cycles: div(cp.install_cycles, cp.installs),
            offload_refused: OFFLOAD_REFUSED.load(Ordering::Relaxed),
            evictions: RULE_EVICTIONS.load(Ordering::Relaxed),
            install_cycles_vs_core_wall: div(cp.install_cycles, per_core_wall),
        },
        rule_management: build_rule_management_report(&w, worker_pmd, tsc_hz),
        ground_truth: GroundTruth {
            discarded_packets: DISCARDED_PACKETS.load(Ordering::Relaxed),
            discarded_bytes: DISCARDED_BYTES.load(Ordering::Relaxed),
            ingress_reconciliation_gap: phy_pkts as i64 - good_pkts as i64 - phy_discard as i64,
        },
        ingress: ingress.to_vec(),
        tsc_hz,
    }
}

/// Assemble the rule-management core's accounting from the three layers that measure it: the
/// worker loop's budget, this binary's install-path buckets, and the PMD counters beneath them.
///
/// The two residuals are the reason for the layering. `handler_unbracketed_fraction` checks the
/// install-path buckets against `handler`, which the worker loop timed independently, and
/// `install_glue_cycles` checks the PMD counters against the span that contains them. A span
/// nobody remembered to open shows up as a number in one of the two rather than as a quietly low
/// cost.
fn build_rule_management_report(
    w: &iris_core::stats::WorkerBudget,
    pmd: &RuleControlCost,
    tsc_hz: u64,
) -> RuleManagementReport {
    let preamble = INSTALL_BUCKETS.preamble.load(Ordering::Relaxed);
    let lock_wait = INSTALL_BUCKETS.lock_wait.load(Ordering::Relaxed);
    let table = INSTALL_BUCKETS.table.load(Ordering::Relaxed);
    let install_span = INSTALL_BUCKETS.install_span.load(Ordering::Relaxed);
    let evict_span = INSTALL_BUCKETS.evict_span.load(Ordering::Relaxed);
    let accounted = preamble + lock_wait + table + install_span + evict_span;

    RuleManagementReport {
        cores: w.threads,
        cpu_seconds: w.cpu_ns as f64 / 1e9,
        busy_fraction: w.busy_fraction(tsc_hz),
        cores_busy: w.cores_busy(tsc_hz),
        sustainable_offload_rate: w.sustainable_item_rate(),
        wall_cycles: w.wall,
        blocked_cycles: w.blocked,
        dispatch_cycles: w.dispatch,
        handler_cycles: w.handler,
        bookkeeping_cycles: w.bookkeeping,
        spin_fraction: w.spin_fraction(tsc_hz),
        loop_residual_fraction: w.residual_fraction(),
        offload_requests: w.items,
        preamble_cycles: preamble,
        lock_wait_cycles: lock_wait,
        table_cycles: table,
        install_span_cycles: install_span,
        evict_span_cycles: evict_span,
        install_glue_cycles: install_span as i64
            - pmd.install_cycles as i64
            - pmd.handle_create_cycles as i64,
        handler_unbracketed_fraction: fdiv(w.handler as f64 - accounted as f64, w.handler as f64),
        understatement_vs_install_cycles: fdiv(w.cpu_cycles(tsc_hz), pmd.install_cycles as f64),
        pmd: *pmd,
        dedup_hits: DEDUP_HITS.load(Ordering::Relaxed),
        dispatch_failures: DISPATCH_FAILURES.load(Ordering::Relaxed),
        nonvoluntary_ctxt_switches: w.nonvoluntary_ctxt_switches,
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
    print_rule_management_summary(&r.rule_management);
}

fn per_request(cycles: u64, requests: u64) -> String {
    if requests == 0 {
        "-".to_string()
    } else {
        format!("{:.0}", cycles as f64 / requests as f64)
    }
}

/// The rule-management core, printed as utilisation first and attribution second — that is the
/// order in which the numbers are trustworthy, since the buckets cannot distinguish a parked
/// thread from a spinning one and the CPU clock can.
fn print_rule_management_summary(m: &RuleManagementReport) {
    println!("--- rule-management core ({} core(s)) ---", m.cores);
    println!(
        "  utilisation:            {:>9.4}%  <- PRIMARY ({:.4} cores, {:.3} CPU-sec)",
        100.0 * m.busy_fraction,
        m.cores_busy,
        m.cpu_seconds
    );
    println!(
        "  sustainable offload:    {:>10.0} req/s at 100% of one core",
        m.sustainable_offload_rate
    );
    if m.pmd.installs > 0 {
        println!(
            "  vs install_cycles:      {:>10.2}x  <- factor by which rte_flow_create alone understates it",
            m.understatement_vs_install_cycles
        );
    } else {
        println!("  vs install_cycles:            n/a  (no rules were installed)");
    }
    println!(
        "  busy time went to ({} offload requests):",
        m.offload_requests
    );
    println!(
        "    handler:              {:>12} cyc ({} per request)",
        m.handler_cycles,
        per_request(m.handler_cycles, m.offload_requests)
    );
    println!(
        "      flow_create:        {:>12} cyc over {} rules",
        m.pmd.install_cycles, m.pmd.installs
    );
    println!(
        "      handle_create:      {:>12} cyc over {} handles  <- was never counted before",
        m.pmd.handle_create_cycles, m.pmd.handle_creates
    );
    println!(
        "      query/destroy:      {:>12} cyc ({} queries, {} destroys, {} handle destroys)",
        m.pmd.query_cycles + m.pmd.destroy_cycles + m.pmd.handle_destroy_cycles,
        m.pmd.queries,
        m.pmd.destroys,
        m.pmd.handle_destroys
    );
    println!(
        "      install glue:       {:>12} cyc (pattern/action marshalling, by residual)",
        m.install_glue_cycles
    );
    println!(
        "      preamble:           {:>12} cyc ({} per request, cold on a parked core)",
        m.preamble_cycles,
        per_request(m.preamble_cycles, m.offload_requests)
    );
    println!(
        "      lock wait:          {:>12} cyc ({} per request)",
        m.lock_wait_cycles,
        per_request(m.lock_wait_cycles, m.offload_requests)
    );
    println!(
        "      rule table:         {:>12} cyc ({} per request)",
        m.table_cycles,
        per_request(m.table_cycles, m.offload_requests)
    );
    println!(
        "    bookkeeping:          {:>12} cyc ({} per request, 3 cold atomics)",
        m.bookkeeping_cycles,
        per_request(m.bookkeeping_cycles, m.offload_requests)
    );
    println!("    dispatch:             {:>12} cyc", m.dispatch_cycles);
    println!(
        "    blocked:              {:>12} cyc ({:.2}% of it spinning, not parked)",
        m.blocked_cycles,
        100.0 * m.spin_fraction
    );
    println!(
        "  loop residual:          {:>10.6}   (must be ~0)",
        m.loop_residual_fraction
    );
    println!(
        "  unbracketed:            {:>9.4}%  of handler (per-call overhead; not in the headline)",
        100.0 * m.handler_unbracketed_fraction
    );
    println!(
        "  saturation:             {} dedup hits, {} dispatch failures (queue full), {} involuntary ctx switches",
        m.dedup_hits, m.dispatch_failures, m.nonvoluntary_ctxt_switches
    );
}
