//! Time accounting for the off-datapath worker cores.
//!
//! [`DatapathBudget`](super::DatapathBudget) measures where a *fully utilised* core's cycles went.
//! The RX loop runs to completion, so its utilisation is pinned at 100% and the only thing that
//! varies is the split between real work and empty polls. A worker thread parks when its queue is
//! empty, so the first question here is a different one: how much of the core did it use at all?
//!
//! Answering that needs two clocks, because neither one alone can.
//!
//! * `cpu_ns` comes from `CLOCK_THREAD_CPUTIME_ID`, which advances only while the thread is
//!   on-CPU. **This is the utilisation figure.** The TSC cannot produce it: crossbeam's `Select`
//!   spins before it parks, and `rte_rdtsc` counts through both the spin and the sleep, so it
//!   cannot tell one from the other.
//! * the cycle buckets are `rte_rdtsc` spans that partition `wall`. Parked time lands in
//!   `blocked`, so they do **not** measure utilisation — they say where the busy time went.
//!
//! `cpu_ns` sizes the cost, the buckets attribute it, and reconciling the two
//! ([`WorkerBudget::spin_fraction`]) is itself the check that the thread parks rather than
//! spinning a core away.
//!
//! # Why this needs no sampling
//!
//! `DatapathBudget` attributes one iteration in `budget_sample_stride` because an empty
//! `rte_eth_rx_burst` is ~100 cycles and an `rte_rdtsc` is ~24 of them: measuring exactly would
//! inflate the idle bucket, which is the very quantity under test. The unit of work here is an
//! `rte_flow_create`, on the order of 12 us, so one read is under 0.1% of it. Attribution is
//! therefore exact, and no `rdtsc_cost` is subtracted — at these span lengths that correction
//! would be fitting noise.

use crate::dpdk;
use cpu_time::ThreadTime;
use std::sync::atomic::{AtomicU64, Ordering};

/// Where an off-datapath worker thread's time went, summed across worker threads.
///
/// The three cycle buckets are disjoint and sum to `wall` by construction, which is what
/// [`Self::residual_fraction`] checks. `cpu_ns` is measured on a different clock and is *not* part
/// of that sum — see the module docs for why both are needed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WorkerBudget {
    /// On-CPU nanoseconds from `CLOCK_THREAD_CPUTIME_ID`. **The headline**: this is the only field
    /// that measures utilisation, because it is the only one that stops while the thread is parked.
    pub cpu_ns: u64,
    /// Exact cycles between entering and leaving the worker loop.
    pub wall: u64,
    /// Cycles inside `Select::select()` — queue empty, waiting for work. Spans both crossbeam's
    /// pre-park spin (on-CPU) and the park itself (not), which is exactly why this bucket cannot
    /// stand in for idleness.
    pub blocked: u64,
    /// Cycles taking messages off the channel and assembling a batch.
    pub dispatch: u64,
    /// Cycles inside the handler itself, the indirect call to it included.
    pub handler: u64,
    /// The dispatcher's per-batch counter updates, which bracket the handler calls.
    ///
    /// Its own bucket rather than part of `handler` because on a worker that parks between items
    /// these are three cold atomic read-modify-writes, not the handful of cycles they look like:
    /// left inside `handler` they would inflate the apparent per-item cost of the actual work.
    pub bookkeeping: u64,
    /// Batches the handler was invoked for.
    pub batches: u64,
    /// Items handled.
    pub items: u64,
    /// Worker threads that contributed. `wall` is a sum across them, so per-core figures need it
    /// as a divisor.
    pub threads: u64,
    /// Context switches over the run, read from `/proc/thread-self/status`.
    ///
    /// On a properly isolated core the nonvoluntary count should be ~0. A large one means the
    /// scheduler put something else on the core, in which case `cpu_ns` still measures this
    /// thread honestly but no longer describes what the core as a whole was doing.
    pub voluntary_ctxt_switches: u64,
    pub nonvoluntary_ctxt_switches: u64,
    /// `rte_rdtsc()` calls the instrumentation made, for the same overhead bound
    /// `DatapathBudget` reports.
    pub rdtsc_reads: u64,
}

impl WorkerBudget {
    /// `cpu_ns` converted to cycles at the TSC frequency, so it can be compared with the buckets.
    /// The TSC is invariant, so this conversion survives frequency scaling.
    pub fn cpu_cycles(&self, tsc_hz: u64) -> f64 {
        self.cpu_ns as f64 * tsc_hz as f64 / 1e9
    }

    /// **The headline metric.** Mean share of one worker core actually consumed.
    pub fn busy_fraction(&self, tsc_hz: u64) -> f64 {
        fraction(self.cpu_cycles(tsc_hz), self.wall as f64)
    }

    /// Utilisation as whole cores. Directly comparable with `DatapathBudget::cores_idle`, and the
    /// term to subtract from it for a net figure.
    pub fn cores_busy(&self, tsc_hz: u64) -> f64 {
        self.busy_fraction(tsc_hz) * self.threads as f64
    }

    /// Items per second the worker could sustain at 100% of one core.
    ///
    /// This is the capacity ceiling of the mechanism, and unlike a utilisation fraction it does
    /// not depend on the offered load of the run that measured it — so it can be compared directly
    /// against a connection arrival rate to find where the offload stops keeping up.
    pub fn sustainable_item_rate(&self) -> f64 {
        fraction(self.items as f64 * 1e9, self.cpu_ns as f64)
    }

    /// Mean handler cycles per item. The per-install cost that generalises to other install rates.
    pub fn cycles_per_item(&self) -> f64 {
        fraction(self.handler as f64, self.items as f64)
    }

    /// Share of `wall` spent in the handler. Note this is a share of *wall*, not of busy time: a
    /// worker that is 2% utilised and spends all of it installing rules reports ~0.02 here.
    pub fn handler_fraction(&self) -> f64 {
        fraction(self.handler as f64, self.wall as f64)
    }

    /// How far the buckets miss `wall`, as a fraction of it. Should be ~0; a non-zero value means
    /// the loop has a path this does not bracket and the attribution cannot be trusted.
    pub fn residual_fraction(&self) -> f64 {
        let accounted = self.blocked + self.dispatch + self.handler + self.bookkeeping;
        fraction(self.wall.saturating_sub(accounted) as f64, self.wall as f64)
    }

    /// Share of `blocked` that was actually on-CPU, i.e. crossbeam spinning rather than sleeping.
    ///
    /// Derived by subtracting the busy buckets from the on-CPU total, so it is the one figure that
    /// crosses the two clocks. Near 0 means the worker really does give the core back between
    /// items and `busy_fraction` is the whole cost. Near 1 means the "idle" worker is burning a
    /// core, and `blocked` should be read as work, not slack.
    ///
    /// Clamped to [0, 1]: the two clocks are independent, so at very low utilisation rounding can
    /// push the difference slightly outside it.
    pub fn spin_fraction(&self, tsc_hz: u64) -> f64 {
        let busy = self.handler as f64 + self.dispatch as f64 + self.bookkeeping as f64;
        let on_cpu_while_blocked = self.cpu_cycles(tsc_hz) - busy;
        fraction(on_cpu_while_blocked, self.blocked as f64).clamp(0.0, 1.0)
    }
}

fn fraction(num: f64, den: f64) -> f64 {
    if den <= 0.0 {
        0.0
    } else {
        num / den
    }
}

/// Per-thread accumulator for a worker loop.
///
/// Timestamps are chained: each `end_*` call closes one bucket and opens the next, so the buckets
/// sum to the loop's span the same way `DatapathBudget`'s do. The calls must therefore follow the
/// loop's actual control flow — a path that skips one leaves a gap, which is what
/// [`WorkerBudget::residual_fraction`] is for.
pub struct WorkerProbe {
    budget: WorkerBudget,
    cpu_start: ThreadTime,
    ctxt_start: (u64, u64),
    wall_start: u64,
    cursor: u64,
}

impl WorkerProbe {
    /// Start both clocks. Call from inside the worker thread, after it has been pinned — the CPU
    /// clock is per-thread, so it cannot be started anywhere else.
    pub fn start() -> Self {
        let now = unsafe { dpdk::rte_rdtsc() };
        Self {
            budget: WorkerBudget {
                threads: 1,
                rdtsc_reads: 1,
                ..Default::default()
            },
            cpu_start: ThreadTime::now(),
            ctxt_start: read_ctxt_switches(),
            wall_start: now,
            cursor: now,
        }
    }

    /// Close the open span and open the next, returning its length.
    fn split(&mut self) -> u64 {
        let now = unsafe { dpdk::rte_rdtsc() };
        self.budget.rdtsc_reads += 1;
        let span = now.wrapping_sub(self.cursor);
        self.cursor = now;
        span
    }

    pub fn end_blocked(&mut self) {
        self.budget.blocked += self.split();
    }

    pub fn end_dispatch(&mut self) {
        self.budget.dispatch += self.split();
    }

    pub fn end_handler(&mut self, items: u64) {
        self.budget.handler += self.split();
        self.budget.batches += 1;
        self.budget.items += items;
    }

    pub fn end_bookkeeping(&mut self) {
        self.budget.bookkeeping += self.split();
    }

    /// Close the run and publish into the process-wide totals.
    pub fn finish(mut self) {
        let end = unsafe { dpdk::rte_rdtsc() };
        self.budget.rdtsc_reads += 1;
        self.budget.wall = end.wrapping_sub(self.wall_start);
        self.budget.cpu_ns = self.cpu_start.elapsed().as_nanos() as u64;

        let (vol, nonvol) = read_ctxt_switches();
        self.budget.voluntary_ctxt_switches = vol.saturating_sub(self.ctxt_start.0);
        self.budget.nonvoluntary_ctxt_switches = nonvol.saturating_sub(self.ctxt_start.1);

        publish_worker_thread(&self.budget);
    }
}

/// `(voluntary, nonvoluntary)` context switches for the calling thread.
///
/// Read from `/proc/thread-self`, which the kernel resolves to the calling thread, so this needs
/// no `gettid` and no extra crate feature. Returns zeroes if the file is unreadable; the counts are
/// a diagnostic, so failing to read them should not take the rest of the budget down with it.
fn read_ctxt_switches() -> (u64, u64) {
    let Ok(status) = std::fs::read_to_string("/proc/thread-self/status") else {
        return (0, 0);
    };
    let mut vol = 0;
    let mut nonvol = 0;
    for line in status.lines() {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let parsed = val.trim().parse().unwrap_or(0);
        match key {
            "voluntary_ctxt_switches" => vol = parsed,
            "nonvoluntary_ctxt_switches" => nonvol = parsed,
            _ => {}
        }
    }
    (vol, nonvol)
}

static W_CPU_NS: AtomicU64 = AtomicU64::new(0);
static W_WALL: AtomicU64 = AtomicU64::new(0);
static W_BLOCKED: AtomicU64 = AtomicU64::new(0);
static W_DISPATCH: AtomicU64 = AtomicU64::new(0);
static W_HANDLER: AtomicU64 = AtomicU64::new(0);
static W_BOOKKEEPING: AtomicU64 = AtomicU64::new(0);
static W_BATCHES: AtomicU64 = AtomicU64::new(0);
static W_ITEMS: AtomicU64 = AtomicU64::new(0);
static W_THREADS: AtomicU64 = AtomicU64::new(0);
static W_VOL_CTXT: AtomicU64 = AtomicU64::new(0);
static W_NONVOL_CTXT: AtomicU64 = AtomicU64::new(0);
static W_RDTSC_READS: AtomicU64 = AtomicU64::new(0);

/// Add one finished worker thread's budget to the process-wide totals.
///
/// Published once, at thread exit, rather than incrementally as `publish_datapath_delta` is: the
/// datapath's budget has to be readable mid-run so the monitor can log a duty cycle against each
/// interval's load, whereas a worker core's utilisation is a whole-run figure.
pub fn publish_worker_thread(b: &WorkerBudget) {
    W_CPU_NS.fetch_add(b.cpu_ns, Ordering::Relaxed);
    W_WALL.fetch_add(b.wall, Ordering::Relaxed);
    W_BLOCKED.fetch_add(b.blocked, Ordering::Relaxed);
    W_DISPATCH.fetch_add(b.dispatch, Ordering::Relaxed);
    W_HANDLER.fetch_add(b.handler, Ordering::Relaxed);
    W_BOOKKEEPING.fetch_add(b.bookkeeping, Ordering::Relaxed);
    W_BATCHES.fetch_add(b.batches, Ordering::Relaxed);
    W_ITEMS.fetch_add(b.items, Ordering::Relaxed);
    W_THREADS.fetch_add(b.threads, Ordering::Relaxed);
    W_VOL_CTXT.fetch_add(b.voluntary_ctxt_switches, Ordering::Relaxed);
    W_NONVOL_CTXT.fetch_add(b.nonvoluntary_ctxt_switches, Ordering::Relaxed);
    W_RDTSC_READS.fetch_add(b.rdtsc_reads, Ordering::Relaxed);
}

/// Worker time summed over every worker thread that has exited its loop.
///
/// Read after the workers are joined. `threads` is 0 if nothing was instrumented, which is the
/// signal that the run had no worker cores rather than fully idle ones.
pub fn worker_budget() -> WorkerBudget {
    WorkerBudget {
        cpu_ns: W_CPU_NS.load(Ordering::Relaxed),
        wall: W_WALL.load(Ordering::Relaxed),
        blocked: W_BLOCKED.load(Ordering::Relaxed),
        dispatch: W_DISPATCH.load(Ordering::Relaxed),
        handler: W_HANDLER.load(Ordering::Relaxed),
        bookkeeping: W_BOOKKEEPING.load(Ordering::Relaxed),
        batches: W_BATCHES.load(Ordering::Relaxed),
        items: W_ITEMS.load(Ordering::Relaxed),
        threads: W_THREADS.load(Ordering::Relaxed),
        voluntary_ctxt_switches: W_VOL_CTXT.load(Ordering::Relaxed),
        nonvoluntary_ctxt_switches: W_NONVOL_CTXT.load(Ordering::Relaxed),
        rdtsc_reads: W_RDTSC_READS.load(Ordering::Relaxed),
    }
}
