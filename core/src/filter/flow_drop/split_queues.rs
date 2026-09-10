//! Per-port split-queue lookup for per-flow QUEUE rules.
//!
//! Split queue ids are **per port**: `Port::new` numbers each port's queues
//! from 0 (sinks first, then `receive, split` for each core in sorted order).
//! A queue id derived from one port's core list therefore means something
//! different on another port -- and when the other port has fewer cores it
//! does not exist at all, which `rte_flow_create` reports as
//! "queue index out of range". That is why a split-mode run works with one
//! port and fails with two of unequal core counts.
//!
//! A per-flow rule is installed on *every* port (either direction of a flow
//! can arrive on either port of a tap), so each rule needs one queue id per
//! port. This map supplies that vector: the exact split queue of the core that
//! saw the flow on that core's own port, and a same-index split queue
//! (wrapped to the port's core count) on every other port -- RSS on the other
//! port would not have chosen the same core anyway, so no affinity is lost
//! that split mode had to begin with.

use std::collections::{BTreeSet, HashMap};

use crate::config::OnlineConfig;
use crate::CoreId;

/// Maps the RX core that saw a flow to one split queue id per port.
#[derive(Debug, Clone, Default)]
pub struct SplitQueueMap {
    /// Split queue ids per port, in config port order, each in core order.
    port_queues: Vec<Vec<u16>>,

    /// Core -> (port index, index of the core within that port's core list).
    core_loc: HashMap<CoreId, (usize, usize)>,
}

impl SplitQueueMap {
    /// Build the map from the online config. The queue layout mirrors
    /// `Port::new`: sink queues occupy qids `[0, sinks.len())`, then each core
    /// in sorted order takes a Receive qid followed by a Split qid.
    pub fn from_config(online: &OnlineConfig) -> Self {
        let mut port_queues = Vec::with_capacity(online.ports.len());
        let mut core_loc = HashMap::new();

        for (port_idx, port_map) in online.ports.iter().enumerate() {
            let base = port_map.sinks.len() as u16;
            let cores: BTreeSet<u32> = port_map.cores.iter().copied().collect();
            let mut queues = Vec::with_capacity(cores.len());
            for (core_idx, core) in cores.into_iter().enumerate() {
                queues.push(base + (core_idx as u16) * 2 + 1);
                core_loc.insert(CoreId(core), (port_idx, core_idx));
            }
            port_queues.push(queues);
        }

        SplitQueueMap {
            port_queues,
            core_loc,
        }
    }

    /// One split queue id per port, in config port order -- the same order as
    /// the `PortId` vector handed to `install_split_flow`.
    ///
    /// Returns `None` if `core` polls no port, or if some port has no cores
    /// (and hence no split queue to steer that port's copy of the rule to).
    pub fn queues_for(&self, core: CoreId) -> Option<Vec<u16>> {
        let &(flow_port, core_idx) = self.core_loc.get(&core)?;

        let mut queues = Vec::with_capacity(self.port_queues.len());
        for (port_idx, port) in self.port_queues.iter().enumerate() {
            if port.is_empty() {
                return None;
            }
            let idx = if port_idx == flow_port {
                core_idx
            } else {
                core_idx % port.len()
            };
            queues.push(port[idx]);
        }
        Some(queues)
    }
}
