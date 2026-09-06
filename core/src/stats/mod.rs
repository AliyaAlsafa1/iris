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
