use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "prometheus")]
mod prometheus;

/// Datapath busy cycles (rte_rdtsc) and received packets, summed across RX cores.
/// Only non-empty rx_bursts are counted, so idle poll-spin is excluded — this is
/// the actual per-packet processing cost, unlike `perf`'s cycles (which include
/// the poll-mode spin and so are ~constant regardless of load).
pub static DP_BUSY_CYCLES: AtomicU64 = AtomicU64::new(0);
pub static DP_BUSY_PKTS: AtomicU64 = AtomicU64::new(0);

/// Add this core's accumulated datapath busy cycles and received packet count.
pub fn add_datapath_busy(cycles: u64, pkts: u64) {
    DP_BUSY_CYCLES.fetch_add(cycles, Ordering::Relaxed);
    DP_BUSY_PKTS.fetch_add(pkts, Ordering::Relaxed);
}

/// Total datapath busy cycles (rte_rdtsc) and received packets across RX cores.
pub fn datapath_busy() -> (u64, u64) {
    (
        DP_BUSY_CYCLES.load(Ordering::Relaxed),
        DP_BUSY_PKTS.load(Ordering::Relaxed),
    )
}

/// A full accounting of every TSC tick spent on the RX lcores, summed across cores.
///
/// `DP_BUSY_CYCLES` above answers "what did a received packet cost?". That is the wrong question
/// for evaluating an ingress-shedding mechanism such as `dyn_hardware_assist`: shedding removes the
/// *cheapest* packets (a parse plus one hot hash hit) from the denominator while leaving handshakes
/// and reassembly in it, so per-packet cost can stay flat or rise even as total cycles fall.
///
/// This budget answers "where did the core's time go?" instead. In a run-to-completion busy-poll
/// loop the CPU is always 100% utilised, so the quantity that actually varies is the *split*
/// between doing work and spinning on an empty queue. `poll_idle` is therefore the headline: it is
/// the pool of cycles available to application logic. The buckets are disjoint and, by
/// construction, sum to `sampled_wall`.
///
/// Cycles are only comparable across runs once normalised — divide by `sampled_wall` for a duty
/// cycle, or by ingress packets/bytes from `rte_eth_xstats` (i.e. what the NIC *saw*, before flow
/// rules dropped anything) for a load-independent per-packet cost.
///
/// # Measuring this without biasing it
///
/// Two distinct problems, and both had to be solved, because `poll_idle` is both the headline
/// number and the most fragile one — an empty `rte_eth_rx_burst` is only on the order of a hundred
/// cycles, while an `rte_rdtsc()` read is a couple of dozen.
///
/// 1. **Perturbation.** Bracketing every iteration would add a read per empty poll, materially
///    slowing the very path being measured. So attribution runs on a sampled subset of iterations
///    (`sample_stride`), while the cheap counters (`wall`, `bursts`, `idle_polls`, `recv_pkts`)
///    stay exact. `sample_stride = 1` recovers exact attribution, which is right offline and is
///    how to confirm sampling has not skewed a result.
///
/// 2. **Bias.** Sampling alone does *not* fix the accounting: inside a sampled iteration every
///    span still absorbs the latency of the read that closes it, and since idle polls are the
///    cheapest events they are inflated most in relative terms. Left uncorrected, that inflates
///    `poll_idle` in proportion to the idle-poll count — which is exactly what differs between the
///    arms of an ingress-shedding experiment, so the error would push *in favour of* the
///    hypothesis. Hence `rdtsc_cost` is calibrated per core and subtracted from every span, and
///    the same total from `sampled_wall` so the buckets still close.
///
/// Fractions are computed within the sample, where they are unbiased; `wall` supplies the absolute
/// scale. `instrumentation_fraction` and `residual_fraction` are the two validity checks.
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
    /// One in every `sample_stride` loop iterations was attributed. 1 means exact.
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
        ratio(self.sampled_wall.saturating_sub(accounted), self.sampled_wall)
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
/// Callers must invoke [`claim_datapath_core`] exactly once, when the core's loop exits, so that
/// `cores` counts cores rather than publish events.
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
    if running.sample_stride != 0 {
        DP_SAMPLE_STRIDE.store(running.sample_stride, Ordering::Relaxed);
    }
    if running.rdtsc_cost != 0 {
        DP_RDTSC_COST.store(running.rdtsc_cost, Ordering::Relaxed);
    }

    // Keep the legacy pair in step so existing consumers (e.g. examples/flow_stats) keep working:
    // "busy" there means non-empty bursts, i.e. poll_busy + pipeline + maint.
    let work = (running.poll_busy + running.pipeline + running.maint)
        .saturating_sub(published.poll_busy + published.pipeline + published.maint);
    let pkts = running.recv_pkts.saturating_sub(published.recv_pkts);
    add_datapath_busy(work, pkts);

    *published = *running;
}

/// Declare how many RX cores contribute to the budget.
///
/// Set once at startup rather than counted as cores exit, so that `wall` can be turned into a
/// per-core duty cycle *during* the run — the periodic monitor log needs it, and cores only exit
/// at shutdown.
pub fn set_datapath_cores(n: u64) {
    DP_CORES.store(n, Ordering::Relaxed);
}

/// The cycle budget summed over every RX core that has finished its poll loop.
pub fn datapath_budget() -> DatapathBudget {
    DatapathBudget {
        poll_busy: DP_POLL_BUSY.load(Ordering::Relaxed),
        poll_idle: DP_POLL_IDLE.load(Ordering::Relaxed),
        pipeline: DP_PIPELINE.load(Ordering::Relaxed),
        maint: DP_MAINT.load(Ordering::Relaxed),
        wall: DP_WALL.load(Ordering::Relaxed),
        bursts: DP_BURSTS.load(Ordering::Relaxed),
        idle_polls: DP_IDLE_POLLS.load(Ordering::Relaxed),
        recv_pkts: DP_BUSY_PKTS.load(Ordering::Relaxed),
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

#[cfg(feature = "prometheus")]
pub use prometheus::*;

thread_local! {
    pub(crate) static IGNORED_BY_PACKET_FILTER_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static IGNORED_BY_PACKET_FILTER_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static DROPPED_MIDDLE_OF_CONNECTION_TCP_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static DROPPED_MIDDLE_OF_CONNECTION_TCP_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TOTAL_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TOTAL_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TCP_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TCP_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static UDP_PKT: Cell<u64> = const { Cell::new(0) };
    pub(crate) static UDP_BYTE: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TCP_NEW_CONNECTIONS: Cell<u64> = const { Cell::new(0) };
    pub(crate) static UDP_NEW_CONNECTIONS: Cell<u64> = const { Cell::new(0) };
    pub(crate) static IDLE_CYCLES: Cell<u64> = const { Cell::new(0) };
    pub(crate) static TOTAL_CYCLES: Cell<u64> = const { Cell::new(0) };

    #[cfg(feature = "prometheus")]
    pub(crate) static PROMETHEUS: std::cell::OnceCell<prometheus::PerCorePrometheusStats> = const { std::cell::OnceCell::new() };
}

pub(crate) trait StatExt: Sized {
    fn inc(&'static self) {
        self.inc_by(1);
    }
    fn inc_by(&'static self, val: u64);
}

impl StatExt for std::thread::LocalKey<Cell<u64>> {
    fn inc_by(&'static self, val: u64) {
        self.set(self.get() + val);
    }
}
