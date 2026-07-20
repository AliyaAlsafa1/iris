//! Software flow table: an `rte_flow`-style match-action lookup in software.
//!
//! Maps a [`FiveTuple`] to an action so packets can be matched against
//! installed rules the way a NIC matches `rte_flow` rules — but on the CPU.
//! One table is owned per RX core (sharded, no locking) and consulted right
//! after `rx_burst`, so matched packets are handled before any parsing or
//! conntrack — the software analog of the NIC acting at ingress.
//!
//! The table is a **bounded, set-associative cache** — a software model of a
//! hardware flow table. It is backed by flat arrays (structure-of-arrays) so a
//! lookup touches a single contiguous set of `ways` slots (~one cache line),
//! and it hashes with a fast non-cryptographic hash (FxHash) rather than the
//! std default SipHash. When a set is full, the least-recently-accessed way in
//! that set is evicted (per-set LRU). Eviction is correctness-free: an evicted
//! rule simply means those packets fall through to the normal pipeline.

use crate::conntrack::pdu::L4Context;
use crate::memory::mbuf::Mbuf;
use crate::{CoreId, FiveTuple};
use crossbeam::channel::{unbounded, Receiver, Sender};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::RwLock;

/// Action to apply to packets matching a rule (subset of `rte_flow` actions).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowAction {
    Drop,
    Queue(u16),
}

/// Bounded, set-associative software flow table keyed on 5-tuples.
///
/// Slots are laid out as `n_sets` sets of `ways` slots each, in
/// structure-of-arrays form (`fp`/`key`/`act`/`age`). A 5-tuple maps to one set
/// via its hash; within that set, lookups compare a `u64` fingerprint (fast
/// reject) then the full key (no false matches). Eviction is per-set LRU.
pub struct FlowTable {
    /// `n_sets - 1`; `n_sets` is a power of two so indexing is a mask.
    mask: usize,
    /// Associativity (slots per set). `1` = direct-mapped.
    ways: usize,
    /// Fingerprint per slot; `0` marks an empty slot (real fingerprints are
    /// forced odd, so never `0`).
    fp: Vec<u64>,
    /// Authoritative key per slot (exact compare — no false drops).
    key: Vec<FiveTuple>,
    /// Action per slot.
    act: Vec<FlowAction>,
    /// Recency tick per slot (larger = more recently accessed).
    age: Vec<u64>,
    /// Monotonic access counter feeding `age`.
    tick: u64,
    /// Number of live rules.
    entries: usize,
    /// Number of LRU evictions (a stat for experiments).
    evictions: u64,
}

/// Placeholder key for empty slots — never compared (gated by `fp == 0`).
#[inline]
fn placeholder_tuple() -> FiveTuple {
    let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
    FiveTuple {
        orig: a,
        resp: a,
        proto: 0,
    }
}

impl FlowTable {
    /// A minimal 1-slot table, used only on the disabled datapath (never hit).
    pub fn new() -> Self {
        Self::with_capacity_ways(1, 1)
    }

    /// Builds a table holding up to ~`capacity` rules with associativity
    /// `ways`. The set count is rounded to a power of two, so the true capacity
    /// is `next_pow2(capacity / ways) * ways`.
    pub fn with_capacity_ways(capacity: usize, ways: usize) -> Self {
        let ways = ways.max(1);
        let n_sets = (capacity / ways).max(1).next_power_of_two();
        let slots = n_sets * ways;
        FlowTable {
            mask: n_sets - 1,
            ways,
            fp: vec![0u64; slots],
            key: vec![placeholder_tuple(); slots],
            act: vec![FlowAction::Drop; slots],
            age: vec![0u64; slots],
            tick: 0,
            entries: 0,
            evictions: 0,
        }
    }

    /// First slot index of the set a hash maps to.
    #[inline]
    fn set_base(&self, h: u64) -> usize {
        (h as usize & self.mask) * self.ways
    }

    /// Install a rule (updates in place if the key is already present; else
    /// fills an empty way, or evicts the least-recently-accessed way in the set).
    pub fn insert(&mut self, tuple: FiveTuple, action: FlowAction) {
        let h = fxhash(&tuple);
        let fp = h | 1;
        let base = self.set_base(h);
        self.tick += 1;
        let tick = self.tick;

        let mut empty: Option<usize> = None;
        let mut lru = base;
        let mut lru_age = u64::MAX;
        for i in base..base + self.ways {
            if self.fp[i] == 0 {
                if empty.is_none() {
                    empty = Some(i);
                }
                continue;
            }
            if self.fp[i] == fp && self.key[i] == tuple {
                self.act[i] = action;
                self.age[i] = tick;
                return;
            }
            if self.age[i] < lru_age {
                lru_age = self.age[i];
                lru = i;
            }
        }

        let slot = match empty {
            Some(i) => {
                self.entries += 1;
                i
            }
            None => {
                self.evictions += 1;
                lru
            }
        };
        self.fp[slot] = fp;
        self.key[slot] = tuple;
        self.act[slot] = action;
        self.age[slot] = tick;
    }

    /// Look up the action for a 5-tuple, bumping its recency on a hit.
    pub fn get(&mut self, tuple: &FiveTuple) -> Option<FlowAction> {
        let h = fxhash(tuple);
        let fp = h | 1;
        let base = self.set_base(h);
        for i in base..base + self.ways {
            if self.fp[i] == fp && &self.key[i] == tuple {
                self.tick += 1;
                self.age[i] = self.tick;
                return Some(self.act[i]);
            }
        }
        None
    }

    /// Match a raw packet by its 5-tuple. Returns the action to apply, or
    /// `None` if it doesn't match a rule (or isn't TCP/UDP). Hot path.
    pub fn lookup(&mut self, mbuf: &Mbuf) -> Option<FlowAction> {
        let ctxt = L4Context::new(mbuf).ok()?;
        self.get(&FiveTuple::from_ctxt(&ctxt))
    }

    /// Uninstall a rule.
    pub fn remove(&mut self, tuple: &FiveTuple) {
        let h = fxhash(tuple);
        let fp = h | 1;
        let base = self.set_base(h);
        for i in base..base + self.ways {
            if self.fp[i] == fp && &self.key[i] == tuple {
                self.fp[i] = 0;
                self.entries -= 1;
                return;
            }
        }
    }

    /// Apply a control-plane command drained from this core's inbox.
    pub fn apply(&mut self, cmd: FlowCommand) {
        match cmd {
            FlowCommand::Install(tuple, action) => self.insert(tuple, action),
            FlowCommand::Uninstall(tuple) => self.remove(&tuple),
        }
    }

    /// Number of live rules.
    pub fn len(&self) -> usize {
        self.entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }

    /// Total number of LRU evictions since construction.
    pub fn evictions(&self) -> u64 {
        self.evictions
    }
}

/// FxHash of a 5-tuple (fast, non-cryptographic; reuses `FiveTuple`'s `Hash`).
#[inline]
fn fxhash(tuple: &FiveTuple) -> u64 {
    let mut h = FxHasher::default();
    tuple.hash(&mut h);
    h.finish()
}

/// The "FxHash" algorithm used by rustc — much faster than SipHash for small
/// fixed-size keys, at the cost of DoS resistance (not needed for a trusted
/// flow table).
#[derive(Default)]
struct FxHasher {
    hash: u64,
}

const FX_SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

impl FxHasher {
    #[inline]
    fn add(&mut self, i: u64) {
        self.hash = (self.hash.rotate_left(5) ^ i).wrapping_mul(FX_SEED);
    }
}

impl Hasher for FxHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut b = bytes;
        while b.len() >= 8 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&b[..8]);
            self.add(u64::from_le_bytes(buf));
            b = &b[8..];
        }
        if b.len() >= 4 {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&b[..4]);
            self.add(u32::from_le_bytes(buf) as u64);
            b = &b[4..];
        }
        for &x in b {
            self.add(x as u64);
        }
    }
    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u16(&mut self, i: u16) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.add(i as u64);
    }
    #[inline]
    fn write_u64(&mut self, i: u64) {
        self.add(i);
    }
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.add(i as u64);
    }
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
}

/// A control-plane request to modify a core's flow table.
#[derive(Clone, Copy, Debug)]
pub enum FlowCommand {
    Install(FiveTuple, FlowAction),
    Uninstall(FiveTuple),
}

lazy_static! {
    /// Registry of per-core install inboxes. Written only by the control plane
    /// (core registration and rule pushes) — never touched on the datapath,
    /// where each core drains its own lock-free `Receiver`.
    static ref INBOXES: RwLock<HashMap<CoreId, Sender<FlowCommand>>> =
        RwLock::new(HashMap::new());

    /// Global on/off switch, read once from the `IRIS_SW_FLOW` env var
    /// (default on; `0`/`false` disables). When disabled, installs are no-ops
    /// and the datapath skips the lookup/drain entirely — a zero-overhead
    /// baseline for measuring the software flow table's cost.
    static ref ENABLED: bool = std::env::var("IRIS_SW_FLOW")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
}

/// Whether the software flow table is enabled (see `IRIS_SW_FLOW`). Read this
/// once per RX loop, not per packet.
#[inline]
pub fn enabled() -> bool {
    *ENABLED
}

/// Registers an inbox for `core` and returns the `Receiver` it drains at the
/// top of its RX loop, right after `rx_burst`. Called once per RX core.
pub(crate) fn register_core(core: CoreId) -> Receiver<FlowCommand> {
    let (tx, rx) = unbounded();
    INBOXES.write().unwrap().insert(core, tx);
    rx
}

/// Pushes a command to one core's table. Returns `false` if disabled or if
/// that core has no registered inbox.
fn push(core: CoreId, cmd: FlowCommand) -> bool {
    if !enabled() {
        return false;
    }
    match INBOXES.read().unwrap().get(&core) {
        Some(tx) => tx.send(cmd).is_ok(),
        None => false,
    }
}

/// Pushes a command to every registered core (rte_flow-on-port semantics: all
/// queues honor the rule regardless of which one RSS steers the flow to).
fn push_all(cmd: FlowCommand) {
    if !enabled() {
        return;
    }
    for tx in INBOXES.read().unwrap().values() {
        let _ = tx.send(cmd);
    }
}

/// Control-plane API: install a rule on a specific core's table.
pub fn install(core: CoreId, tuple: FiveTuple, action: FlowAction) -> bool {
    push(core, FlowCommand::Install(tuple, action))
}

/// Control-plane API: remove a rule from a specific core's table.
pub fn uninstall(core: CoreId, tuple: FiveTuple) -> bool {
    push(core, FlowCommand::Uninstall(tuple))
}

/// Control-plane API: install a rule on every core.
pub fn install_all(tuple: FiveTuple, action: FlowAction) {
    push_all(FlowCommand::Install(tuple, action));
}

/// Control-plane API: remove a rule from every core.
pub fn uninstall_all(tuple: FiveTuple) {
    push_all(FlowCommand::Uninstall(tuple));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(port: u16) -> FiveTuple {
        let orig = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port);
        let resp = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443);
        FiveTuple {
            orig,
            resp,
            proto: 6,
        }
    }

    #[test]
    fn insert_get_remove() {
        // Single fully-associative set of 4 ways.
        let mut ft = FlowTable::with_capacity_ways(4, 4);
        assert!(ft.is_empty());
        ft.insert(tuple(1), FlowAction::Drop);
        assert_eq!(ft.len(), 1);
        assert_eq!(ft.get(&tuple(1)), Some(FlowAction::Drop));
        assert_eq!(ft.get(&tuple(999)), None);
        ft.remove(&tuple(1));
        assert!(ft.is_empty());
        assert_eq!(ft.get(&tuple(1)), None);
        assert_eq!(ft.evictions(), 0);
    }

    #[test]
    fn per_set_lru_eviction() {
        // n_sets = 4/4 = 1, so every key lands in the same set of 4 ways.
        let mut ft = FlowTable::with_capacity_ways(4, 4);
        for p in 1..=4 {
            ft.insert(tuple(p), FlowAction::Drop);
        }
        assert_eq!(ft.len(), 4);

        // Touch tuple(1) so it becomes most-recently-used; tuple(2) is now LRU.
        assert_eq!(ft.get(&tuple(1)), Some(FlowAction::Drop));

        // Inserting a 5th key into the full set evicts the LRU way (tuple 2).
        ft.insert(tuple(5), FlowAction::Drop);
        assert_eq!(ft.len(), 4);
        assert_eq!(ft.evictions(), 1);
        assert_eq!(ft.get(&tuple(2)), None, "LRU entry should be evicted");
        for p in [1, 3, 4, 5] {
            assert_eq!(ft.get(&tuple(p)), Some(FlowAction::Drop), "port {p} kept");
        }
    }

    #[test]
    fn update_in_place_no_eviction() {
        let mut ft = FlowTable::with_capacity_ways(4, 4);
        for p in 1..=4 {
            ft.insert(tuple(p), FlowAction::Drop);
        }
        // Re-installing an existing key updates in place, never evicts.
        ft.insert(tuple(2), FlowAction::Queue(7));
        assert_eq!(ft.len(), 4);
        assert_eq!(ft.evictions(), 0);
        assert_eq!(ft.get(&tuple(2)), Some(FlowAction::Queue(7)));
    }

    #[test]
    fn direct_mapped_evicts_on_collision() {
        // ways = 1: a set holds a single slot, so a colliding key evicts.
        let mut ft = FlowTable::with_capacity_ways(1, 1); // 1 set, 1 way
        ft.insert(tuple(1), FlowAction::Drop);
        ft.insert(tuple(2), FlowAction::Drop); // same (only) set -> evicts tuple(1)
        assert_eq!(ft.len(), 1);
        assert_eq!(ft.evictions(), 1);
        assert_eq!(ft.get(&tuple(2)), Some(FlowAction::Drop));
    }
}
