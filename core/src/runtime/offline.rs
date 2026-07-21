use crate::config::{ConnTrackConfig, FlowTableConfig, OfflineConfig};
use crate::conntrack::{ConnTracker, TrackerConfig};
use crate::dpdk;
use crate::filter::sw_flow::{FlowAction, FlowTable};
use crate::lcore::{CoreId, SocketId};
use crate::memory::mbuf::Mbuf;
use crate::memory::mempool::Mempool;
use crate::subscription::*;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::Arc;

use cpu_time::ProcessTime;
use pcap::Capture;

pub(crate) struct OfflineRuntime<S>
where
    S: Subscribable,
{
    pub(crate) mempool_name: String,
    pub(crate) subscription: Arc<Subscription<S>>,
    pub(crate) options: OfflineOptions,
    id: CoreId,
}

impl<S> OfflineRuntime<S>
where
    S: Subscribable,
{
    pub(crate) fn new(
        options: OfflineOptions,
        mempools: &BTreeMap<SocketId, Mempool>,
        subscription: Arc<Subscription<S>>,
    ) -> Self {
        let core_id = CoreId(unsafe { dpdk::rte_lcore_id() } as u32);
        let mempool_name = mempools
            .get(&core_id.socket_id())
            .expect("Get offline mempool")
            .name()
            .to_string();
        OfflineRuntime {
            mempool_name,
            subscription,
            options,
            id: core_id,
        }
    }

    pub(crate) fn run(&self) {
        log::info!(
            "Launched offline analysis. Processing pcap: {}",
            self.options.offline.pcap,
        );

        let mut nb_pkts = 0;
        let mut nb_bytes = 0;
        // Total frames the datapath touched (incl. those dropped by the flow
        // table) — the correct denominator for per-packet perf metrics.
        let mut nb_frames = 0u64;

        let config = TrackerConfig::from(&self.options.conntrack);
        let registry = S::Tracked::parsers();
        log::debug!("{:#?}", registry);
        let mut stream_table = ConnTracker::<S::Tracked>::new(config, registry, self.id);

        // Software flow table, mirroring NIC rte_flow rules (single core here).
        // Rules arrive via `inbox` from the control-plane API. Allocated only
        // when the config provides a [flow_table] section; otherwise None and
        // the loop allocates nothing and skips the lookup/drain — a zero-
        // overhead baseline.
        let mut flow_table = self
            .options
            .flow_table
            .as_ref()
            .map(|c| FlowTable::with_capacity_ways(c.capacity, c.ways));
        let inbox = crate::filter::sw_flow::register_core(self.id);

        let mempool_raw = self.get_mempool_raw();
        let pcap = self.options.offline.pcap.as_str();
        let mut cap = Capture::from_file(pcap).expect("Error opening pcap. Aborting.");
        let start = ProcessTime::try_now().expect("Getting process time failed");
        while let Ok(frame) = cap.next() {
            if frame.header.len as usize > self.options.offline.mtu {
                continue;
            }
            let mbuf = Mbuf::from_bytes(frame.data, mempool_raw)
                .expect("Unable to allocate mbuf. Try increasing mempool size.");
            nb_frames += 1;

            if let Some(ft) = flow_table.as_mut() {
                // Apply any pending flow rules pushed by the control plane.
                while let Ok(cmd) = inbox.try_recv() {
                    ft.apply(cmd);
                }

                // Consult the flow table first, as a NIC would apply rte_flow.
                if let Some(action) = ft.lookup(&mbuf) {
                    match action {
                        FlowAction::Drop => continue,
                        FlowAction::Queue(_) => {} // no SW steering; fall through
                    }
                }
            }

            nb_pkts += 1;
            nb_bytes += mbuf.data_len() as u64;

            /* Apply the packet filter to get actions */
            let cont = self.subscription.filter_packet(&mbuf, &self.id);
            if cont {
                self.subscription.process_packet(mbuf, &mut stream_table);
            }
        }

        // // Deliver remaining data in table
        stream_table.drain(&self.subscription);
        let cpu_time = start.elapsed();
        println!("Frames read: {}", nb_frames);
        println!("Processed: {} pkts, {} bytes", nb_pkts, nb_bytes);
        println!("CPU time: {:?}ms", cpu_time.as_millis());
        println!("Flow table entries: {}", flow_table.as_ref().map_or(0, |t| t.len()));
        println!("Evictions: {}", flow_table.as_ref().map_or(0, |t| t.evictions()));
    }

    pub(crate) fn get_mempool_raw(&self) -> *mut dpdk::rte_mempool {
        let cname = CString::new(self.mempool_name.clone()).expect("Invalid CString conversion");
        unsafe { dpdk::rte_mempool_lookup(cname.as_ptr()) }
    }
}

/// Read-only runtime options for the offline core
#[derive(Debug)]
pub(crate) struct OfflineOptions {
    pub(crate) offline: OfflineConfig,
    pub(crate) conntrack: ConnTrackConfig,
    pub(crate) flow_table: Option<FlowTableConfig>,
}
