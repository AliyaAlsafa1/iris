use super::CoreId;
use crate::config::{ConnTrackConfig, FlowTableConfig};
use crate::conntrack::{ConnTracker, TrackerConfig};
use crate::dpdk;
use crate::filter::sw_flow::{FlowAction, FlowTable};
use crate::memory::mbuf::Mbuf;
use crate::port::{RxQueue, RxQueueType};
use crate::stats::{
    StatExt, IDLE_CYCLES, IGNORED_BY_PACKET_FILTER_BYTE, IGNORED_BY_PACKET_FILTER_PKT, TOTAL_BYTE,
    TOTAL_CYCLES, TOTAL_PKT,
};
use crate::subscription::*;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use itertools::Itertools;

/// A RxCore polls from `rxqueues` and reduces the stream of packets into
/// a stream of higher-level network events to be processed by the user.
pub(crate) struct RxCore<S>
where
    S: Subscribable,
{
    pub(crate) id: CoreId,
    pub(crate) rxqueues: Vec<RxQueue>,
    pub(crate) conntrack: ConnTrackConfig,
    pub(crate) flow_table: FlowTableConfig,
    #[cfg(feature = "prometheus")]
    pub(crate) is_prometheus_enabled: bool,
    pub(crate) subscription: Arc<Subscription<S>>,
    pub(crate) is_running: Arc<AtomicBool>,
}

impl<S> RxCore<S>
where
    S: Subscribable,
{
    pub(crate) fn new(
        core_id: CoreId,
        rxqueues: Vec<RxQueue>,
        conntrack: ConnTrackConfig,
        flow_table: FlowTableConfig,
        #[cfg(feature = "prometheus")] is_prometheus_enabled: bool,
        subscription: Arc<Subscription<S>>,
        is_running: Arc<AtomicBool>,
    ) -> Self {
        RxCore {
            id: core_id,
            rxqueues,
            conntrack,
            flow_table,
            #[cfg(feature = "prometheus")]
            is_prometheus_enabled,
            subscription,
            is_running,
        }
    }

    pub(crate) fn rx_burst(&self, rxqueue: &RxQueue, rx_burst_size: u16) -> Vec<Mbuf> {
        let mut ptrs = Vec::with_capacity(rx_burst_size as usize);
        let nb_rx = unsafe {
            dpdk::rte_eth_rx_burst(
                rxqueue.pid.raw(),
                rxqueue.qid.raw(),
                ptrs.as_mut_ptr(),
                rx_burst_size,
            )
        };
        unsafe {
            ptrs.set_len(nb_rx as usize);
            ptrs.into_iter()
                .map(Mbuf::new_unchecked)
                .collect::<Vec<Mbuf>>()
        }
    }

    pub(crate) fn rx_loop(&self) {
        // TODO: need check to enforce that each core only has same queue types
        if self.rxqueues[0].ty == RxQueueType::Sink {
            self.rx_sink();
        } else {
            self.rx_process();
        }
    }

    fn rx_process(&self) {
        log::info!(
            "Launched RX on core {}, polling {}",
            self.id,
            self.rxqueues.iter().format(", "),
        );

        let mut nb_pkts = 0;
        let mut nb_bytes = 0;

        let config = TrackerConfig::from(&self.conntrack);
        let registry = S::Tracked::parsers();
        log::debug!("{:#?}", registry);
        let mut conn_table = ConnTracker::<S::Tracked>::new(config, registry, self.id);

        // Per-core (sharded) software flow table, mirroring NIC rte_flow rules.
        // Rules arrive via `inbox` from the control-plane API and are drained
        // right after each rx_burst. Preallocated (2 rules per connection, both
        // directions) so it never resizes mid-run within the connection cap.
        // Disabled (IRIS_SW_FLOW=0) => no preallocation, no lookup/drain.
        let sw_flow_on = crate::filter::sw_flow::enabled();
        let mut flow_table = if sw_flow_on {
            FlowTable::with_capacity_ways(self.flow_table.capacity, self.flow_table.ways)
        } else {
            FlowTable::new()
        };
        let inbox = crate::filter::sw_flow::register_core(self.id);

        let mut now = Instant::now();

        // rte_rdtsc-based per-packet cost: accumulate cycles only for non-empty
        // bursts (idle poll-spin excluded), divided by received packets.
        let mut busy_cycles: u64 = 0;
        let mut busy_pkts: u64 = 0;

        while self.is_running.load(Ordering::Relaxed) {
            for rxqueue in self.rxqueues.iter() {
                let t_start = unsafe { dpdk::rte_rdtsc() };
                let mbufs: Vec<Mbuf> = self.rx_burst(rxqueue, 32);
                let n_recv = mbufs.len();
                if mbufs.is_empty() {
                    IDLE_CYCLES.inc();
                }

                // Apply any pending flow rules pushed by the control plane.
                if sw_flow_on {
                    while let Ok(cmd) = inbox.try_recv() {
                        flow_table.apply(cmd);
                    }
                }

                TOTAL_CYCLES.inc();
                if TOTAL_CYCLES.get() & 1023 == 512 {
                    now = Instant::now();
                }
                #[cfg(feature = "prometheus")]
                if TOTAL_CYCLES.get() & 1023 == 0 && self.is_prometheus_enabled {
                    crate::stats::update_thread_local_stats(self.id);
                }

                for mbuf in mbufs.into_iter() {
                    // Consult the flow table first, just as the NIC would apply
                    // rte_flow rules before the packet reaches the pipeline.
                    if sw_flow_on {
                        if let Some(action) = flow_table.lookup(&mbuf) {
                            match action {
                                FlowAction::Drop => continue,
                                FlowAction::Queue(_) => {} // no SW steering; fall through
                            }
                        }
                    }

                    // log::debug!("{:#?}", mbuf);
                    // log::debug!("Mark: {}", mbuf.mark());
                    // log::debug!("RSS Hash: 0x{:x}", mbuf.rss_hash());
                    // log::debug!(
                    //     "Queue ID: {}, Port ID: {}, Core ID: {}",
                    //     rxqueue.qid,
                    //     rxqueue.pid,
                    //     self.id,
                    // );
                    nb_pkts += 1;
                    nb_bytes += mbuf.data_len() as u64;

                    TOTAL_PKT.inc();
                    TOTAL_BYTE.inc_by(mbuf.data_len() as u64);

                    let cont = self.subscription.filter_packet(&mbuf, &self.id);
                    if cont {
                        self.subscription.process_packet(mbuf, &mut conn_table);
                    } else {
                        IGNORED_BY_PACKET_FILTER_PKT.inc();
                        IGNORED_BY_PACKET_FILTER_BYTE.inc_by(mbuf.data_len() as u64);
                    }
                }

                // Charge this burst's cycles to per-packet cost (skip idle polls).
                if n_recv > 0 {
                    busy_cycles += unsafe { dpdk::rte_rdtsc() } - t_start;
                    busy_pkts += n_recv as u64;
                }
            }
            conn_table.check_inactive(&self.subscription, now);
        }

        crate::stats::add_datapath_busy(busy_cycles, busy_pkts);

        // // Deliver remaining data in table from unfinished connections
        conn_table.drain(&self.subscription);

        log::info!(
            "Core {} total recv from {}: {} pkts, {} bytes",
            self.id,
            self.rxqueues.iter().format(", "),
            nb_pkts,
            nb_bytes
        );
    }

    fn rx_sink(&self) {
        log::info!(
            "Launched SINK on core {}, polling {}",
            self.id,
            self.rxqueues.iter().format(", "),
        );

        // Per-queue counters so a sink core polling multiple steered queues
        // (e.g. TLS on one queue, QUIC on another) reports each separately.
        let mut per_queue: Vec<(u64, u64)> = vec![(0, 0); self.rxqueues.len()];

        while self.is_running.load(Ordering::Relaxed) {
            for (i, rxqueue) in self.rxqueues.iter().enumerate() {
                let mbufs: Vec<Mbuf> = self.rx_burst(rxqueue, 32);
                for mbuf in mbufs.into_iter() {
                    per_queue[i].0 += 1;
                    per_queue[i].1 += mbuf.data_len() as u64;
                }
            }
        }

        for (i, rxqueue) in self.rxqueues.iter().enumerate() {
            let (nb_pkts, nb_bytes) = per_queue[i];
            log::info!(
                "Sink Core {} queue {}: {} pkts, {} bytes",
                self.id,
                rxqueue,
                nb_pkts,
                nb_bytes
            );
        }
    }
}
