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

/// Packets delivered by `rx_burst`, separated by the type of queue they came
/// from. Incremented ONCE PER BURST (by the burst length), not per packet, so
/// the datapath cost is one relaxed atomic add per poll.
///
/// Why this is needed: mlx5 charges RX misses to the port, and DPDK only keeps
/// per-queue xstats for the first RTE_ETHDEV_QUEUE_STAT_CNTRS (16) queues --
/// fewer than the 2*ncores queues split mode creates, so rx_qN_packets cannot
/// see the whole port. These two totals cover EVERY queue, so the port-level
/// miss count can be attributed to the Receive side or the Split side:
///
///   split arrivals   = DISCARDED_PACKETS (the rte_flow indirect counters)
///   receive arrivals = rx_phy_packets - DISCARDED_PACKETS
///   drop rate/side   = 1 - delivered/arrivals
pub static RECEIVE_Q_PKTS: AtomicU64 = AtomicU64::new(0);
pub static SPLIT_Q_PKTS: AtomicU64 = AtomicU64::new(0);

/// Delivered packet totals as (receive_queues, split_queues).
pub fn queue_delivered() -> (u64, u64) {
    (
        RECEIVE_Q_PKTS.load(Ordering::Relaxed),
        SPLIT_Q_PKTS.load(Ordering::Relaxed),
    )
}

/// The SPLIT-queue subset of DP_BUSY_CYCLES / DP_BUSY_PKTS. DP_BUSY_* stay the
/// all-queue aggregate (flow_stats reads them), so the Receive-queue figures are
/// simply aggregate minus split.
///
/// This is the number that decides whether buffer split costs per-packet CPU:
/// compare cycles/pkt on Split queues against cycles/pkt on Receive queues in
/// the same run, same cores, same pipeline.
pub static DP_SPLIT_CYCLES: AtomicU64 = AtomicU64::new(0);
pub static DP_SPLIT_PKTS: AtomicU64 = AtomicU64::new(0);

/// Add this core's accumulated busy cycles/packets for SPLIT queues only.
pub fn add_datapath_busy_split(cycles: u64, pkts: u64) {
    DP_SPLIT_CYCLES.fetch_add(cycles, Ordering::Relaxed);
    DP_SPLIT_PKTS.fetch_add(pkts, Ordering::Relaxed);
}

/// Split-queue busy cycles and packets across RX cores.
pub fn datapath_busy_split() -> (u64, u64) {
    (
        DP_SPLIT_CYCLES.load(Ordering::Relaxed),
        DP_SPLIT_PKTS.load(Ordering::Relaxed),
    )
}

/// The rest of the RX core's time, so the budget closes.
///
/// DP_IDLE_CYCLES: time inside a queue block whose rx_burst returned nothing
/// (poll-spin on an empty queue).
/// DP_GAP_CYCLES: time OUTSIDE the per-queue blocks -- i.e. `check_inactive`
/// (the conntrack timerwheel) plus outer-loop overhead. This was previously
/// unmeasured: `add_datapath_busy` only ever saw non-empty bursts.
///
/// busy(receive) + busy(split) + idle + gap == total rx_loop wall time, so the
/// four can be read as percentages without knowing the TSC frequency.
pub static DP_IDLE_CYCLES: AtomicU64 = AtomicU64::new(0);
pub static DP_GAP_CYCLES: AtomicU64 = AtomicU64::new(0);

/// Add this core's idle-poll and out-of-block cycles.
pub fn add_datapath_overhead(idle: u64, gap: u64) {
    DP_IDLE_CYCLES.fetch_add(idle, Ordering::Relaxed);
    DP_GAP_CYCLES.fetch_add(gap, Ordering::Relaxed);
}

/// (idle_cycles, gap_cycles) across RX cores.
pub fn datapath_overhead() -> (u64, u64) {
    (
        DP_IDLE_CYCLES.load(Ordering::Relaxed),
        DP_GAP_CYCLES.load(Ordering::Relaxed),
    )
}

/// Total datapath busy cycles (rte_rdtsc) and received packets across RX cores.
pub fn datapath_busy() -> (u64, u64) {
    (
        DP_BUSY_CYCLES.load(Ordering::Relaxed),
        DP_BUSY_PKTS.load(Ordering::Relaxed),
    )
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
