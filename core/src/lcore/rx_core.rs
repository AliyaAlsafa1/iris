use super::CoreId;
use crate::config::{ConnTrackConfig, FlowTableConfig};
use crate::conntrack::{ConnTracker, TrackerConfig};
use crate::dpdk;
use crate::filter::sw_flow::{FlowAction, FlowTable};
use crate::lcore::datapath_budget::{
    measure_rdtsc_overhead, publish_datapath_delta, DatapathBudget,
};
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

/// Number of mbufs requested per `rte_eth_rx_burst` call, and the unit in which datapath
/// maintenance is amortised.
const RX_BURST_SIZE: u16 = 32;

/// A RxCore polls from `rxqueues` and reduces the stream of packets into
/// a stream of higher-level network events to be processed by the user.
pub(crate) struct RxCore<S>
where
    S: Subscribable,
{
    pub(crate) id: CoreId,
    pub(crate) rxqueues: Vec<RxQueue>,
    pub(crate) conntrack: ConnTrackConfig,
    pub(crate) flow_table: Option<FlowTableConfig>,
    /// Attribute cycles on one in every this many loop iterations. See
    /// `config::OnlineConfig::budget_sample_stride`.
    pub(crate) budget_sample_stride: u64,
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
        flow_table: Option<FlowTableConfig>,
        budget_sample_stride: u64,
        #[cfg(feature = "prometheus")] is_prometheus_enabled: bool,
        subscription: Arc<Subscription<S>>,
        is_running: Arc<AtomicBool>,
    ) -> Self {
        RxCore {
            id: core_id,
            rxqueues,
            conntrack,
            flow_table,
            budget_sample_stride,
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
        // Allocated only when the config provides a [flow_table] section;
        // otherwise `flow_table` is None and the datapath allocates nothing and
        // skips the lookup/drain entirely. Rules arrive via `inbox` from the
        // control-plane API and are drained right after each rx_burst.
        let mut flow_table = self
            .flow_table
            .as_ref()
            .map(|c| FlowTable::with_capacity_ways(c.capacity, c.ways));
        let inbox = crate::filter::sw_flow::register_core(self.id);

        let mut now = Instant::now();

        // Cycle budget for this lcore. See `DatapathBudget`.
        // Timestamps within a sampled iteration are chained.
        // Each span has one read's cost subtracted to avoid skewing short spans.
        let attribute_cycles = self.budget_sample_stride != 0;
        let sample_stride = self.budget_sample_stride.max(1);
        let rdtsc_cost = if attribute_cycles {
            measure_rdtsc_overhead(4096).round() as u64
        } else {
            0
        };
        let mut budget = DatapathBudget {
            // The configured value so a report can tell
            // "attribution off" (0) from "attribution exact" (1).
            sample_stride: self.budget_sample_stride,
            rdtsc_cost,
            ..Default::default()
        };
        let loop_start = unsafe { dpdk::rte_rdtsc() };
        let mut rdtsc_reads: u64 = 1;
        // Last snapshot pushed to the global atomics. The budget is published incrementally.
        let mut published = DatapathBudget::default();
        // Note: countdown rather than `iter % stride` to avoid u64 division.
        let mut countdown: u64 = 1;

        while self.is_running.load(Ordering::Relaxed) {
            // Sample decision for this iteration.
            // Taken once so every bucket within it is either attributed or not.
            countdown -= 1;
            let due = countdown == 0;
            if due {
                countdown = sample_stride;
            }
            // Let the countdown keep cycling even with attribution off, so it cannot underflow.
            let sampled = due && attribute_cycles;
            let mut t_cursor = if sampled {
                rdtsc_reads += 1;
                unsafe { dpdk::rte_rdtsc() }
            } else {
                0
            };
            let iter_start = t_cursor;
            // Spans closed within this iteration, i.e. how many read latencies its own span
            // absorbed, so the same correction can be taken off `sampled_wall`.
            let mut spans_closed: u64 = 0;

            for rxqueue in self.rxqueues.iter() {
                let mbufs: Vec<Mbuf> = self.rx_burst(rxqueue, RX_BURST_SIZE);
                let n_recv = mbufs.len();

                if sampled {
                    // Close poll bucket
                    let t_after_poll = unsafe { dpdk::rte_rdtsc() };
                    rdtsc_reads += 1;
                    spans_closed += 1;
                    let poll_span = t_after_poll
                        .wrapping_sub(t_cursor)
                        .saturating_sub(rdtsc_cost);
                    t_cursor = t_after_poll;
                    if n_recv == 0 {
                        budget.poll_idle += poll_span;
                    } else {
                        budget.poll_busy += poll_span;
                    }
                }
                if n_recv == 0 {
                    // exact counters
                    budget.idle_polls += 1;
                    IDLE_CYCLES.inc();
                } else {
                    budget.bursts += 1;
                    budget.recv_pkts += n_recv as u64;
                }

                // Apply any pending flow rules pushed by the control plane.
                if let Some(ft) = flow_table.as_mut() {
                    while let Ok(cmd) = inbox.try_recv() {
                        ft.apply(cmd);
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
                    if let Some(ft) = flow_table.as_mut() {
                        if let Some(action) = ft.lookup(&mbuf) {
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

                if sampled && n_recv > 0 {
                    // Close the pipeline bucket, if applicable.
                    let t_after_pipeline = unsafe { dpdk::rte_rdtsc() };
                    rdtsc_reads += 1;
                    spans_closed += 1;
                    budget.pipeline += t_after_pipeline
                        .wrapping_sub(t_cursor)
                        .saturating_sub(rdtsc_cost);
                    t_cursor = t_after_pipeline;
                }
            }
            // Run every iteration, so the `maint` bucket below measures the whole cost. Note this
            // means its cost per delivered packet rises as the core goes idle.
            conn_table.check_inactive(&self.subscription, now);

            if sampled {
                // Close the maintenance bucket (timer-wheel expiry).
                let t_after_maint = unsafe { dpdk::rte_rdtsc() };
                rdtsc_reads += 1;
                spans_closed += 1;
                budget.maint += t_after_maint
                    .wrapping_sub(t_cursor)
                    .saturating_sub(rdtsc_cost);
                // Same total correction, so the buckets still sum to `sampled_wall`.
                budget.sampled_wall += t_after_maint
                    .wrapping_sub(iter_start)
                    .saturating_sub(spans_closed * rdtsc_cost);
                budget.sampled_iters += 1;

                // Publish the delta periodically so the monitor can log cycles beside each
                // interval's ingress rate. Only on sampled iterations.
                if budget.sampled_iters & 1023 == 0 {
                    budget.wall = t_after_maint.wrapping_sub(loop_start);
                    budget.rdtsc_reads = rdtsc_reads;
                    publish_datapath_delta(&budget, &mut published);
                }
            }
        }

        budget.wall = unsafe { dpdk::rte_rdtsc() }.wrapping_sub(loop_start);
        budget.rdtsc_reads = rdtsc_reads + 1;
        // Final flush of the not-yet-published remainder.
        publish_datapath_delta(&budget, &mut published);

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
                let mbufs: Vec<Mbuf> = self.rx_burst(rxqueue, RX_BURST_SIZE);
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
