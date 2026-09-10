//! Cycle accounting for the RX datapath.
//!
//! Every TSC tick on an RX lcore is attributed to (1) polling a queue that
//! returned packets, (2) polling an empty queue, (3) the per-mbuf pipeline, and
//! (4) timer-wheel maintenance.
//! The split between those buckets should vary with load and application.
//! Changes in `poll_idle` provide rough estimates of cycles available to the application.
//!
//! Cycle measurement is sampled to avoid interfering too much with the data path
//! (an `rte_rdtsc` costs ~24 cycles against a ~100-cycle empty poll).
//! One iteration in `[online] budget_sample_stride` is attributed.
//! The cheap counters stay exact on every one.
//!
//! Each RX core publishes into these globals periodically from its poll loop rather than only at
//! exit, so the monitor can log a duty cycle beside each interval's ingress rate.

use std::sync::atomic::{AtomicU64, Ordering};

/// Where every TSC tick on the RX lcores went, summed across cores.
///
/// A run-to-completion busy-poll loop is always 100% utilized, so what varies is the split
/// between work and spinning on an empty queue; `poll_idle` is roughly the pool available to
/// application logic. The buckets are disjoint and sum to `sampled_wall`. Divide by
/// `sampled_wall` for a duty cycle, or by ingress packets for a load-independent per-packet cost.
///
/// Two things would bias it if left alone. Bracketing every iteration adds a read per empty poll,
/// so attribution runs on one iteration in `sample_stride` while the cheap counters stay exact.
/// And each span absorbs the latency of the read that closes it, which is a larger share of an
/// empty poll than of real work -- so `rdtsc_cost` is calibrated per core and subtracted from
/// every span and from `sampled_wall`. Fractions are taken within the sample, where they are
/// unbiased; `wall` supplies the absolute scale.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DatapathBudget {
    /// Sampled cycles in `rte_eth_rx_burst` calls that returned at least one packet.
    pub poll_busy: u64,
    /// Sampled cycles in `rte_eth_rx_burst` calls that returned nothing — the spare-capacity pool.
    ///
    /// Note these cycles are not 100% recoverable as application cycles: an empty burst still
    /// reads a completion-queue entry. See [`Self::cycles_per_idle_poll`] for that floor.
    pub poll_idle: u64,
    /// Sampled cycles in the per-mbuf pipeline: packet filter, conntrack, reassembly, L7 parse,
    /// callbacks.
    pub pipeline: u64,
    /// Sampled cycles in `ConnTracker::check_inactive` (timer-wheel maintenance).
    pub maint: u64,
    /// Total cycles spanned by the sampled iterations. The four buckets above sum to this by
    /// construction, which is what [`Self::residual_fraction`] checks.
    pub sampled_wall: u64,
    /// Loop iterations that were sampled.
    pub sampled_iters: u64,
    /// Exact total cycles between entering and leaving the poll loop, across all cores.
    pub wall: u64,
    /// Exact count of bursts that returned at least one packet.
    pub bursts: u64,
    /// Exact count of bursts that returned nothing.
    pub idle_polls: u64,
    /// Exact count of packets handed to the pipeline.
    pub recv_pkts: u64,
    /// Number of RX cores that contributed to this budget. `wall` is a sum across cores, so
    /// per-core duty cycles need this as a divisor.
    pub cores: u64,
    /// `rte_rdtsc()` calls the instrumentation itself made. Multiply by the calibrated per-read
    /// cost to bound how much of `wall` is measurement overhead.
    pub rdtsc_reads: u64,
    /// One in every `sample_stride` loop iterations was attributed. 1 means exact; 0 means cycle
    /// attribution was disabled, in which case the four buckets are empty but the exact counters
    /// above are still valid.
    pub sample_stride: u64,
    /// Calibrated cost of one `rte_rdtsc()` read, in cycles, measured on the RX core itself.
    ///
    /// Already subtracted from every bucket: within a sampled iteration each span absorbs the
    /// latency of the read that closes it, and because an empty poll is the cheapest event
    /// `poll_idle` would otherwise be inflated most — biasing the freed-cycle metric in favour of
    /// the hypothesis. Reported so the correction is auditable.
    pub rdtsc_cost: u64,
}

impl DatapathBudget {
    /// Fraction of the RX cores' cycles spent polling an empty queue — the share of the machine
    /// that ingress shedding has freed up. Rises when the NIC drops more traffic.
    pub fn idle_fraction(&self) -> f64 {
        self.fraction(self.poll_idle)
    }

    /// Fraction of the RX cores' cycles spent doing packet work (`poll_busy + pipeline + maint`).
    pub fn busy_fraction(&self) -> f64 {
        self.fraction(self.poll_busy + self.pipeline + self.maint)
    }

    /// The three busy buckets individually, over the same denominator as the fractions above.
    pub fn poll_busy_fraction(&self) -> f64 {
        self.fraction(self.poll_busy)
    }

    pub fn pipeline_fraction(&self) -> f64 {
        self.fraction(self.pipeline)
    }

    pub fn maint_fraction(&self) -> f64 {
        self.fraction(self.maint)
    }

    /// The freed-cycle pool expressed as whole cores.
    pub fn cores_idle(&self) -> f64 {
        self.idle_fraction() * self.cores as f64
    }

    /// Estimated total idle-poll cycles across the whole run, scaling the sample up by `wall`.
    pub fn est_poll_idle_cycles(&self) -> f64 {
        self.idle_fraction() * self.wall as f64
    }

    /// Mean cycles per empty poll — the floor below which idle cycles cannot be reclaimed, since
    /// an empty burst still reads a completion-queue entry.
    ///
    /// Computed within the sample: sampled idle cycles over the idle polls those samples covered,
    /// estimated as `idle_polls / sample_stride`.
    pub fn cycles_per_idle_poll(&self) -> f64 {
        let sampled_idle_polls = self.idle_polls as f64 / self.sample_stride.max(1) as f64;
        if sampled_idle_polls <= 0.0 {
            0.0
        } else {
            self.poll_idle as f64 / sampled_idle_polls
        }
    }

    /// How far the four buckets miss `sampled_wall`, as a fraction of it. Should be ~0; a non-zero
    /// value means a sampled iteration had an unbracketed path and the budget cannot be trusted.
    pub fn residual_fraction(&self) -> f64 {
        let accounted = self.poll_busy + self.poll_idle + self.pipeline + self.maint;
        ratio(
            self.sampled_wall.saturating_sub(accounted),
            self.sampled_wall,
        )
    }

    /// Share of `wall` consumed by the instrumentation's own `rte_rdtsc()` calls, given the
    /// calibrated per-read cost from [`measure_rdtsc_overhead`].
    ///
    /// This has to be small relative to the effect under study for the measurement to mean
    /// anything — it is not a footnote, it is a validity check. Sampling is what keeps it small.
    pub fn instrumentation_fraction(&self, cycles_per_read: f64) -> f64 {
        if self.wall == 0 {
            0.0
        } else {
            (self.rdtsc_reads as f64 * cycles_per_read) / self.wall as f64
        }
    }

    /// Share of the run's iterations that were attributed. Small values mean the fractions above
    /// carry sampling error; the sample count is `sampled_iters`.
    pub fn sampled_share(&self) -> f64 {
        ratio(self.sampled_wall, self.wall)
    }

    fn fraction(&self, part: u64) -> f64 {
        ratio(part, self.sampled_wall)
    }
}

fn ratio(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

static DP_POLL_BUSY: AtomicU64 = AtomicU64::new(0);
static DP_POLL_IDLE: AtomicU64 = AtomicU64::new(0);
static DP_PIPELINE: AtomicU64 = AtomicU64::new(0);
static DP_MAINT: AtomicU64 = AtomicU64::new(0);
static DP_WALL: AtomicU64 = AtomicU64::new(0);
static DP_BURSTS: AtomicU64 = AtomicU64::new(0);
static DP_IDLE_POLLS: AtomicU64 = AtomicU64::new(0);
static DP_CORES: AtomicU64 = AtomicU64::new(0);
static DP_RDTSC_READS: AtomicU64 = AtomicU64::new(0);
static DP_SAMPLED_WALL: AtomicU64 = AtomicU64::new(0);
static DP_SAMPLED_ITERS: AtomicU64 = AtomicU64::new(0);
static DP_SAMPLE_STRIDE: AtomicU64 = AtomicU64::new(1);
static DP_RDTSC_COST: AtomicU64 = AtomicU64::new(0);

/// Publish one RX core's cycle budget.
///
/// `running` is the core's cumulative budget; `published` is what was last pushed to the globals.
/// Only the difference is added, so this can be called periodically from the poll loop — which is
/// what lets the monitor log a duty cycle alongside each interval's ingress rate. `published` is
/// updated in place.
///
/// This does not touch `cores`. Because it is called repeatedly per core, counting here would
/// count publish events; [`set_datapath_cores`] declares the core count once at startup instead.
pub fn publish_datapath_delta(running: &DatapathBudget, published: &mut DatapathBudget) {
    macro_rules! push {
        ($atomic:ident, $field:ident) => {{
            let delta = running.$field.saturating_sub(published.$field);
            if delta != 0 {
                $atomic.fetch_add(delta, Ordering::Relaxed);
            }
        }};
    }
    push!(DP_POLL_BUSY, poll_busy);
    push!(DP_POLL_IDLE, poll_idle);
    push!(DP_PIPELINE, pipeline);
    push!(DP_MAINT, maint);
    push!(DP_WALL, wall);
    push!(DP_BURSTS, bursts);
    push!(DP_IDLE_POLLS, idle_polls);
    push!(DP_RDTSC_READS, rdtsc_reads);
    push!(DP_SAMPLED_WALL, sampled_wall);
    push!(DP_SAMPLED_ITERS, sampled_iters);
    // Stored unconditionally, including zero: `sample_stride == 0` means attribution is disabled
    // and `rdtsc_cost == 0` follows from it, so suppressing zeroes here would report a run with no
    // attribution as if it had been sampled exactly.
    DP_SAMPLE_STRIDE.store(running.sample_stride, Ordering::Relaxed);
    DP_RDTSC_COST.store(running.rdtsc_cost, Ordering::Relaxed);

    // See `crate::stats::add_datapath_busy`; "busy" there means non-empty bursts.
    // Scale by `sample_stride`, because `recv_pkts` are exact but cycles are sampled.
    let work = (running.poll_busy + running.pipeline + running.maint)
        .saturating_sub(published.poll_busy + published.pipeline + published.maint)
        .saturating_mul(running.sample_stride.max(1));
    let pkts = running.recv_pkts.saturating_sub(published.recv_pkts);
    crate::stats::add_datapath_busy(work, pkts);

    *published = *running;
}

/// Declare how many RX cores contribute to the budget.
/// Set once at startup.
pub fn set_datapath_cores(n: u64) {
    DP_CORES.store(n, Ordering::Relaxed);
}

/// The cycle budget summed over every RX core, including cores still running: each publishes
/// periodically from its poll loop, not only at exit.
pub fn datapath_budget() -> DatapathBudget {
    DatapathBudget {
        poll_busy: DP_POLL_BUSY.load(Ordering::Relaxed),
        poll_idle: DP_POLL_IDLE.load(Ordering::Relaxed),
        pipeline: DP_PIPELINE.load(Ordering::Relaxed),
        maint: DP_MAINT.load(Ordering::Relaxed),
        wall: DP_WALL.load(Ordering::Relaxed),
        bursts: DP_BURSTS.load(Ordering::Relaxed),
        idle_polls: DP_IDLE_POLLS.load(Ordering::Relaxed),
        recv_pkts: crate::stats::DP_BUSY_PKTS.load(Ordering::Relaxed),
        cores: DP_CORES.load(Ordering::Relaxed),
        rdtsc_reads: DP_RDTSC_READS.load(Ordering::Relaxed),
        sampled_wall: DP_SAMPLED_WALL.load(Ordering::Relaxed),
        sampled_iters: DP_SAMPLED_ITERS.load(Ordering::Relaxed),
        sample_stride: DP_SAMPLE_STRIDE.load(Ordering::Relaxed),
        rdtsc_cost: DP_RDTSC_COST.load(Ordering::Relaxed),
    }
}

/// Measured cost of one `rte_rdtsc()` pair, in cycles.
///
/// The budget above adds three `rte_rdtsc()` reads per loop iteration. On an idle-heavy loop an
/// iteration may itself only be a few hundred cycles, so this overhead has to be reported rather
/// than assumed negligible: if it is not far smaller than the effect being measured, the
/// measurement is not credible. Call after EAL init and record the value alongside the budget.
pub fn measure_rdtsc_overhead(iters: u64) -> f64 {
    if iters == 0 {
        return 0.0;
    }
    // Sum the deltas rather than timing the whole loop, so the result includes the pair's own
    // latency the same way the instrumented loop pays for it.
    let mut total: u64 = 0;
    for _ in 0..iters {
        let a = unsafe { crate::dpdk::rte_rdtsc() };
        let b = unsafe { crate::dpdk::rte_rdtsc() };
        total += b.wrapping_sub(a);
    }
    total as f64 / iters as f64
}
