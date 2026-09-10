#[allow(dead_code)]
mod info;
pub(crate) mod statistics;

use crate::config::{FlowMode, PortMap};
use crate::dpdk;
use crate::lcore::{CoreId, SocketId};
use crate::memory::mempool::{Mempool, SplitMempool};

use self::info::PortInfo;

use std::cmp;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::ffi::CString;
use std::fmt;
use std::mem;
use std::ptr;

use anyhow::{bail, Context, Result};

pub(crate) const SYMMETRIC_RSS_KEY: [u8; 52] = [
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A,
];
const RSS_RETA_SIZE: usize = 512;

#[derive(Debug, Copy, Clone, Hash, Ord, Eq, PartialEq, PartialOrd)]
pub struct PortId(pub u16);

impl PortId {
    pub fn new_from_device(device: String) -> PortId {
        let mut port_id: u16 = 0;
        let _device = device.clone();
        // The registered ethdev name is the bare PCI address; EAL strips any
        // devargs (e.g. "0000:51:00.0,txq_mem_algn=0") after probe. Look the
        // port up by the address alone so devargs in the config still work.
        let dev_addr = device.split(',').next().unwrap_or(&device).to_owned();
        let ret = unsafe {
            let dev_name = CString::new(dev_addr).unwrap();
            dpdk::rte_eth_dev_get_port_by_name(dev_name.as_ptr(), &mut port_id)
        };
        if ret != 0 {
            panic!(
                "Failed to find device by name {} (Avail. devices: {})",
                _device,
                Self::get_avail_device_names()
            );
        }

        if { unsafe { dpdk::rte_eth_dev_is_valid_port(port_id) } } == 0 {
            panic!("ERROR: Invalid port ID {}.", port_id);
        }
        PortId(port_id)
    }

    pub(crate) fn socket_id(&self) -> SocketId {
        unsafe { SocketId(dpdk::rte_eth_dev_socket_id(self.raw()) as u32) }
    }

    /// For DPDK functions
    pub fn raw(&self) -> u16 {
        self.0
    }

    /// Error helper
    fn get_avail_device_names() -> String {
        let port_count = unsafe { dpdk::rte_eth_dev_count_avail() };
        let mut avail_devices = String::new();
        for id in 0..port_count {
            let mut name = [0i8; dpdk::RTE_ETH_NAME_MAX_LEN as usize];
            let ret = unsafe {
                dpdk::rte_eth_dev_get_name_by_port(
                    id,
                    name.as_mut_ptr() as *mut std::os::raw::c_char,
                )
            };
            if ret == 0 {
                let name = unsafe {
                    std::ffi::CStr::from_ptr(name.as_ptr() as *const std::os::raw::c_char)
                };
                avail_devices.push_str(&format!("{:?}, ", name));
            } else {
                avail_devices.push_str(&format!("(Unknown: {} (err: {}), ", id, ret));
            }
        }
        avail_devices
    }
}

impl fmt::Display for PortId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/* --------------------------------------------------------------------------------- */

#[derive(Debug)]
pub(crate) struct Port {
    /// Port ID
    pub(crate) id: PortId,

    /// Device PCI ID
    pub(crate) device: String,

    /// Mapping of receive queues to cores
    pub(crate) queue_map: BTreeMap<RxQueue, CoreId>,

    /// Redirection table mapping RSS bucket IDs to RxQueueIds
    pub(crate) reta: [RxQueueId; RSS_RETA_SIZE],
}

impl Port {
    pub(crate) fn new(port_map: &PortMap, flow_mode: FlowMode) -> Port {
        let port_id = PortId::new_from_device(port_map.device.clone());

        let mut queue_map: BTreeMap<RxQueue, CoreId> = BTreeMap::new();
        let mut rx_core_ids = port_map.cores.to_vec();
        rx_core_ids.sort_unstable();
        rx_core_ids.dedup();

        // NICE-TO-HAVE: error handling
        // - Display warning if cores do not match port socket
        // - Display warning and handle duplicate cores per port and across ports
        // Queue ids are assigned in allocation order from 0. Sinks are
        // allocated before the Receive queues below, so when any sink is
        // configured it takes qid 0 (additional sinks take 1, 2, ...). That
        // ordering is what lets RSS sampling work: the RETA (further down) is
        // default-initialized to RxQueueId(0), and `nb_buckets` (from the first
        // sink) controls how many buckets get overwritten with Receive queues.
        // With the default nb_buckets == RSS_RETA_SIZE every bucket maps to a
        // Receive queue, so NO RSS traffic reaches a sink — sinks then receive
        // only flow-steered packets (the measurement case). Only an explicit
        // nb_buckets < RSS_RETA_SIZE leaves leftover buckets at the qid-0
        // default, sampling that fraction of RSS traffic into the first sink.
        let mut q: u16 = 0;
        let nb_buckets = if let Some(first_sink) = port_map.sinks.first() {
            for sink in &port_map.sinks {
                queue_map.insert(
                    RxQueue::new(port_id, RxQueueId(q), RxQueueType::Sink),
                    CoreId(sink.core),
                );
                q += 1;
            }
            first_sink.nb_buckets
        } else {
            RSS_RETA_SIZE
        };

        for core_id in rx_core_ids.iter() {
            queue_map.insert(
                RxQueue::new(port_id, RxQueueId(q), RxQueueType::Receive),
                CoreId(*core_id),
            );
            q += 1;
            if flow_mode.uses_split_queues() {
                let ty = match flow_mode {
                    FlowMode::TrimNativeDpdk => RxQueueType::TrimNativeDpdk,
                    _ => RxQueueType::Split,
                };
                queue_map.insert(RxQueue::new(port_id, RxQueueId(q), ty), CoreId(*core_id));
                q += 1;
            }
        }

        if nb_buckets < rx_core_ids.len() {
            log::error!("Requested number of RX redirection table buckets ({}) less than number of RX queues ({}).", nb_buckets, rx_core_ids.len());
            panic!();
        }
        if nb_buckets > RSS_RETA_SIZE {
            log::error!("Requested number of RX redirection table buckets ({}) greater than redirection table capacity ({}).", nb_buckets, RSS_RETA_SIZE);
            panic!();
        }

        if nb_buckets % rx_core_ids.len() != 0 {
            log::warn!("Requested number of RX redirection table buckets ({}) not a multiple of number of RX queues ({}). May result in poor load balancing.", nb_buckets, rx_core_ids.len());
        }

        // Set RSS redirection table
        let mut reta = [RxQueueId(0); RSS_RETA_SIZE];
        let rx_queues: Vec<RxQueueId> = queue_map
            .keys()
            .filter(|rxq| rxq.ty == RxQueueType::Receive)
            .map(|rxq| rxq.qid)
            .collect();
        for i in 0..nb_buckets {
            reta[i] = rx_queues[i % rx_queues.len()];
        }

        log::debug!("{:?}", reta);

        Port {
            id: port_id,
            device: port_map.device.clone(),
            queue_map,
            reta,
        }
    }

    /// Configure port and setup RX queues.
    pub(crate) fn init(
        &self,
        standard_mempools: &mut BTreeMap<SocketId, Mempool>,
        split_mempools: &mut BTreeMap<SocketId, SplitMempool>,
        nb_rxd: usize,
        mtu: usize,
        promiscuous: bool,
    ) -> Result<()> {
        self.configure(promiscuous, mtu)?;

        let standard_mempool = standard_mempools.get_mut(&self.id.socket_id()).unwrap();
        // Absent unless some port runs split queues; see `Runtime::new`.
        let split_mempool = split_mempools.get_mut(&self.id.socket_id());
        self.setup_queues(standard_mempool, split_mempool, nb_rxd)?;

        // Startup-only: the queue layout actually handed to
        // rte_eth_dev_configure. rte_flow validates a QUEUE action's index
        // against this count, so a rule rejected with "queue index out of
        // range" is checked against the number printed here.
        let layout: Vec<String> = self
            .queue_map
            .iter()
            .map(|(rxq, core)| format!("q{}{}=core{}", rxq.qid, rxq.ty, core.raw()))
            .collect();
        println!(
            "Port {} configured {} rx queues: {}",
            self.id.raw(),
            self.queue_map.len(),
            layout.join(" ")
        );
        self.display_info();
        Ok(())
    }

    /// Whether any of this port's queues draws from a [`SplitMempool`], and so whether the port
    /// needs one on its socket.
    ///
    /// Both buffer-split queue types do: `TrimNativeDpdk` still takes its header segment from the
    /// split pool, it only declines a mempool for the payload segment.
    pub(crate) fn needs_split_mempool(&self) -> bool {
        self.queue_map
            .keys()
            .any(|rxq| matches!(rxq.ty, RxQueueType::Split | RxQueueType::TrimNativeDpdk))
    }

    /// Start port
    pub(crate) fn start(&self) {
        let ret = unsafe { dpdk::rte_eth_dev_start(self.id.raw()) };
        if ret != 0 {
            panic!("Failed to start Port {}", self.id);
        }
        log::info!("Port {} ({}) started.", self.id, self.device);

        self.disable_flow_ctrl();
        self.configure_rss_reta();
    }

    /// Flush flow rules and stop port
    pub(crate) fn stop(&self) {
        log::info!("Flushing hardware flow rules on Port {}...", self.id);
        let mut error: dpdk::rte_flow_error = unsafe { mem::zeroed() };
        let ret = unsafe { dpdk::rte_flow_flush(self.id.raw(), &mut error) };
        if ret != 0 {
            log::error!("Failed to flush hardware rules from Port {}.", self.id);
        }
        let ret = unsafe { dpdk::rte_eth_dev_stop(self.id.raw()) };
        if ret != 0 {
            log::error!("Failed to stop Port {}.", self.id);
        } else {
            log::info!("Port {} ({}) stopped.", self.id, self.device);
        }
    }

    /// Close and free all port resources
    pub(crate) fn close(&self) {
        let ret = unsafe { dpdk::rte_eth_dev_close(self.id.raw()) };
        if ret != 0 {
            log::error!("Failed to close Port {}.", self.id);
        } else {
            log::info!("Port {} ({}) closed.", self.id, self.device);
        }
    }

    /// Display port information
    #[allow(dead_code)]
    pub(crate) fn display_info(&self) {
        let info = PortInfo::collect(self.id);
        match info {
            Ok(info) => info.display(),
            Err(error) => log::error!("{}", error),
        }
    }

    /// Resets physical counters.
    /// Does not reset counters for packets or byte delivered to cores.
    #[allow(dead_code)]
    pub(crate) fn reset_stats(&self) {
        unsafe { dpdk::rte_eth_xstats_reset(self.id.raw()) };
    }

    /// Disables Ethernet flow control on port
    fn disable_flow_ctrl(&self) {
        log::info!("Disabling Ethernet flow control on Port {}...", self.id);
        let prev_mode = {
            let mut fc_conf: dpdk::rte_eth_fc_conf = unsafe { mem::zeroed() };
            let ret = unsafe { dpdk::rte_eth_dev_flow_ctrl_get(self.id.raw(), &mut fc_conf) };
            if ret != 0 {
                log::warn!("Unable to retrieve current flow control status.");
            }
            fc_conf.mode
        };

        // reset flow control config, set to disabled
        let mut fc_conf: dpdk::rte_eth_fc_conf = unsafe { mem::zeroed() };
        fc_conf.mode = dpdk::rte_eth_fc_mode_RTE_FC_NONE;
        let ret = unsafe { dpdk::rte_eth_dev_flow_ctrl_set(self.id.raw(), &mut fc_conf) };
        if ret != 0 {
            log::warn!("Failure disabling flow control.");
        } else if prev_mode == fc_conf.mode {
            log::info!("Ethernet flow control disabled (unchanged).");
        } else {
            log::info!("Ethernet flow control disabled.");
        }
    }

    /// Sets RSS redirection table to full RSS_RETA_SIZE entries
    fn configure_rss_reta(&self) {
        log::info!("Configuring RSS redirection table...");
        const GROUP_SIZE: usize = dpdk::RTE_RETA_GROUP_SIZE as usize;
        let capacity = RSS_RETA_SIZE / GROUP_SIZE;
        let mut reta_conf: Vec<dpdk::rte_eth_rss_reta_entry64> = Vec::with_capacity(capacity);

        for i in 0..capacity {
            let mut reta_entry64: dpdk::rte_eth_rss_reta_entry64 = unsafe { mem::zeroed() };
            reta_entry64.mask = u64::MAX;
            let start = i * GROUP_SIZE;
            let end = (i + 1) * GROUP_SIZE;
            let entry64 = self.reta[start..end]
                .iter()
                .map(|q| q.raw())
                .collect::<Vec<_>>();

            //reta_slice.copy_from_slice(&self.reta[start..end]);
            reta_entry64.reta = entry64.try_into().unwrap();
            reta_conf.push(reta_entry64);
        }

        let ret = unsafe {
            dpdk::rte_eth_dev_rss_reta_update(
                self.id.raw(),
                reta_conf.as_mut_ptr(),
                RSS_RETA_SIZE as u16,
            )
        };
        if ret != 0 {
            if ret == -95 {
                log::warn!("Setting RSS redirection table is not supported for Port {}. Without a symmetrical key and more than one core, you will experience problems matching connections.", self.id);
            } else {
                panic!("Failed to set RSS redirection table for Port {}.", self.id);
            }
        } else {
            log::info!("Configured RSS redirection table.");
        }
    }

    fn configure(&self, promiscuous: bool, mtu: usize) -> Result<()> {
        let mut port_conf: dpdk::rte_eth_conf = unsafe { mem::zeroed() };

        let mut dev_info: dpdk::rte_eth_dev_info = unsafe { std::mem::zeroed() };
        // Safety: foreign function.
        unsafe { dpdk::rte_eth_dev_info_get(self.id.raw(), &mut dev_info) };

        // turn on RSS
        if dev_info.flow_type_rss_offloads != 0 {
            port_conf.rxmode.mq_mode = dpdk::rte_eth_rx_mq_mode_ETH_MQ_RX_RSS;
            if ![40, 52].contains(&dev_info.hash_key_size) {
                panic!("Unexpected hash key size {}", dev_info.hash_key_size);
            }
            port_conf.rx_adv_conf.rss_conf.rss_key = SYMMETRIC_RSS_KEY.as_ptr() as *mut u8;
            port_conf.rx_adv_conf.rss_conf.rss_key_len = dev_info.hash_key_size;
            // The cast is redundant on DPDK >= 23.11, where dpdk::ETH_RSS_* are u64
            // consts, but required on older versions where bindgen widths differ.
            #[allow(clippy::unnecessary_cast)]
            {
                port_conf.rx_adv_conf.rss_conf.rss_hf =
                    (dpdk::ETH_RSS_IP | dpdk::ETH_RSS_TCP | dpdk::ETH_RSS_UDP) as u64
                        & dev_info.flow_type_rss_offloads;
            }
        }

        // In newer DPDKs setting only mtu with `dpdk::rte_eth_dev_set_mtu` is enough
        #[cfg(not(dpdk_ge_2311))]
        {
            let max_rx_pkt_len = mtu_to_max_frame_len(mtu as u32);
            port_conf.rxmode.max_rx_pkt_len = cmp::max(dpdk::RTE_ETHER_MAX_LEN, max_rx_pkt_len);
        }

        // turns on VLAN stripping if supported
        if dev_info.rx_offload_capa & dpdk::DEV_RX_OFFLOAD_VLAN_STRIP as u64 != 0 {
            port_conf.rxmode.offloads |= dpdk::DEV_RX_OFFLOAD_VLAN_STRIP as u64;
        }

        // turns on buffer split if supported and actually used
        if self.needs_split_mempool()
            && dev_info.rx_offload_capa & dpdk::RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT as u64 != 0
        {
            port_conf.rxmode.offloads |= dpdk::RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT as u64;
            port_conf.rxmode.offloads |= dpdk::RTE_ETH_RX_OFFLOAD_SCATTER as u64;
        }

        if self
            .queue_map
            .keys()
            .any(|rxq| rxq.ty == RxQueueType::TrimNativeDpdk)
            && !selective_rx_supported(&dev_info)
        {
            bail!(
                "Port {} does not support selective Rx (rx_seg_capa.selective_rx); \
                 flow_mode = \"trim-native-dpdk\" is unavailable, use \"split\" instead",
                self.id
            );
        }

        {
            let nb_queues = self.queue_map.len() as u16;
            let ret = unsafe {
                dpdk::rte_eth_dev_configure(self.id.raw(), nb_queues, 0, &port_conf as *const _)
            };
            if ret < 0 {
                bail!("Failed to configure Port {}", self.id);
            }
        }

        // enables or disables promiscuous mode
        if promiscuous {
            let ret = unsafe { dpdk::rte_eth_promiscuous_enable(self.id.raw()) };
            if ret < 0 {
                bail!("Failure enabling promiscuous mode on Port {}", self.id);
            }
        } else {
            let ret = unsafe { dpdk::rte_eth_promiscuous_disable(self.id.raw()) };
            if ret < 0 {
                bail!("Failure disabling promiscuous mode on Port {}", self.id);
            }
        }

        // set MTU to max(1500, requested_mtu)
        let mut set_mtu = cmp::max(dpdk::RTE_ETHER_MTU, mtu as u32);
        if set_mtu > dev_info.max_mtu as u32 {
            set_mtu = dev_info.max_mtu as u32;
            log::warn!("MTU is too big for device that only supports {}", set_mtu);
        }
        if set_mtu < dev_info.min_mtu as u32 {
            set_mtu = dev_info.min_mtu as u32;
            log::warn!("MTU is too small for device that only supports {}", set_mtu);
        }
        let ret = unsafe { dpdk::rte_eth_dev_set_mtu(self.id.raw(), set_mtu as u16) };
        if ret < 0 {
            if ret == -95 {
                log::warn!("Setting MTU is not supported")
            } else {
                bail!(
                    "Failure setting Port {} MTU to {}: Error {}",
                    self.id,
                    set_mtu,
                    ret
                );
            }
        } else {
            log::debug!("Requested MTU: {}, Set MTU: {}", mtu, set_mtu);
            log::debug!("Maximum RX frame size: {}", mtu_to_frame_len(set_mtu));
        }
        Ok(())
    }

    /// `split_mempool` is `None` when no port uses split queues, in which case neither split arm
    /// below can be reached — `needs_split_mempool` decides both.
    fn setup_queues(
        &self,
        standard_mempool: &mut Mempool,
        mut split_mempool: Option<&mut SplitMempool>,
        nb_rxd: usize,
    ) -> Result<()> {
        for rxqueue in self.queue_map.keys() {
            match rxqueue.ty {
                RxQueueType::Split => {
                    let pool = split_mempool.as_deref_mut().with_context(|| {
                        format!("Port {} has a split queue but no split mempool", self.id)
                    })?;
                    self.setup_split_queue(rxqueue, pool, nb_rxd, false)?
                }
                RxQueueType::TrimNativeDpdk => {
                    let pool = split_mempool.as_deref_mut().with_context(|| {
                        format!("Port {} has a trim queue but no split mempool", self.id)
                    })?;
                    self.setup_split_queue(rxqueue, pool, nb_rxd, true)?
                }
                _ => self.setup_standard_queue(rxqueue, standard_mempool, nb_rxd)?,
            };
        }

        Ok(())
    }

    /// First `hdr_len` bytes to the header mempool, payload to the second
    /// segment. With `discard_payload` that segment gets no mempool, so the NIC
    /// drops the payload instead of DMA-ing it (selective Rx).
    fn setup_split_queue(
        &self,
        rxqueue: &RxQueue,
        split_mempool: &mut SplitMempool,
        nb_rxd: usize,
        discard_payload: bool,
    ) -> Result<()> {
        let mut rx_segs: [dpdk::rte_eth_rxseg; 2] = unsafe { mem::zeroed() };

        rx_segs[0].split.length = split_mempool.hdr_len;
        rx_segs[0].split.mp = split_mempool.header.raw_mut();

        rx_segs[1].split.length = 0;
        rx_segs[1].split.mp = if discard_payload {
            ptr::null_mut()
        } else {
            split_mempool.remainder.raw_mut() as *mut _
        };

        let mut rxq_conf: dpdk::rte_eth_rxconf = unsafe { mem::zeroed() };
        rxq_conf.offloads =
            dpdk::RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT as u64 | dpdk::RTE_ETH_RX_OFFLOAD_SCATTER as u64;
        rxq_conf.rx_nseg = 2;
        rxq_conf.rx_seg = rx_segs.as_mut_ptr();

        let ret = unsafe {
            dpdk::rte_eth_rx_queue_setup(
                self.id.raw(),
                rxqueue.qid.raw(),
                nb_rxd as u16,
                self.id.socket_id().raw(),
                &rxq_conf,
                ptr::null_mut(),
            )
        };

        if ret < 0 {
            bail!("Failed to setup split RX queue {}: error {}", rxqueue, ret);
        }

        Ok(())
    }

    fn setup_standard_queue(
        &self,
        rxqueue: &RxQueue,
        standard_mempool: &mut Mempool,
        nb_rxd: usize,
    ) -> Result<()> {
        let ret = unsafe {
            dpdk::rte_eth_rx_queue_setup(
                self.id.raw(),
                rxqueue.qid.raw(),
                nb_rxd as u16,
                self.id.socket_id().raw(),
                ptr::null(),
                standard_mempool.raw_mut(),
            )
        };

        if ret < 0 {
            bail!("Failed to setup standard RX queue {}", rxqueue);
        }

        Ok(())
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        log::info!("Dropping Port {} ({}).", self.id, self.device);
        self.close();
    }
}

/// Whether the device accepts an Rx segment with no mempool (selective Rx).
/// The capability bit only exists from DPDK 26.07.
#[cfg(dpdk_ge_2607)]
fn selective_rx_supported(dev_info: &dpdk::rte_eth_dev_info) -> bool {
    dev_info.rx_seg_capa.selective_rx() != 0
}

#[cfg(not(dpdk_ge_2607))]
fn selective_rx_supported(_dev_info: &dpdk::rte_eth_dev_info) -> bool {
    false
}

fn mtu_to_frame_len(mtu: u32) -> u32 {
    mtu + dpdk::RTE_ETHER_HDR_LEN + dpdk::RTE_ETHER_CRC_LEN
}

/// Some DPDK drivers require sufficient space in the RX buffer to accomodate 2 VLAN tags
/// for QinQ frames, so set sufficient overhead to accomodate this.
pub(crate) fn mtu_to_max_frame_len(mtu: u32) -> u32 {
    const VLAN_HDR_LEN: u32 = 4;
    mtu + dpdk::RTE_ETHER_HDR_LEN + dpdk::RTE_ETHER_CRC_LEN + 2 * VLAN_HDR_LEN
}

/* --------------------------------------------------------------------------------- */

#[derive(Debug, Copy, Clone, Hash, Ord, Eq, PartialEq, PartialOrd)]
pub(crate) enum RxQueueType {
    /// Packets forwarded to processing pipeline
    Receive,
    /// Throwaway
    Sink,
    /// Packets backed by buffer segmentation
    Split,
    /// Packets backed by buffer segmentation whose payload segment is discarded
    /// by the NIC (selective Rx). Same trim as `Split`, done in hardware.
    TrimNativeDpdk,
}

impl fmt::Display for RxQueueType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RxQueueType::Receive => write!(f, "r"),
            RxQueueType::Split => write!(f, "x"),
            RxQueueType::TrimNativeDpdk => write!(f, "t"),
            RxQueueType::Sink => write!(f, "s"),
        }
    }
}

#[derive(Debug, Copy, Clone, Hash, Ord, Eq, PartialEq, PartialOrd)]
pub(crate) struct RxQueueId(pub(crate) u16);

impl RxQueueId {
    /// For DPDK functions
    pub(crate) fn raw(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for RxQueueId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Copy, Clone, Hash, Ord, Eq, PartialEq, PartialOrd)]
pub(crate) struct RxQueue {
    pub(crate) pid: PortId,
    pub(crate) qid: RxQueueId,
    pub(crate) ty: RxQueueType,
}

impl RxQueue {
    pub(crate) fn new(pid: PortId, qid: RxQueueId, ty: RxQueueType) -> Self {
        RxQueue { pid, qid, ty }
    }
}

impl fmt::Display for RxQueue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "p{}q{}{}", self.pid, self.qid, self.ty)
    }
}
