//! Exact memory accounting for the DPDK mbuf pools.
//!
//! The mbuf pools are the largest single allocation Iris makes, so "how much memory does Iris
//! need?" is mostly a question about them. This module answers it with figures read back from the
//! pools themselves rather than computed from the config, because the two disagree in a way that
//! matters: [`Mempool::new`](super::mempool::Mempool) floors the data room at
//! `RTE_MBUF_DEFAULT_BUF_SIZE`, so a pool created for a 64-byte split header is exactly as large as
//! one created for a 1500-byte MTU.
//!
//! Pools are discovered with `rte_mempool_walk` rather than by reconstructing
//! `mempool_{prefix}_{socket}` names. Enumerating cannot silently miss a pool some other part of
//! the system created, nor report one that was never allocated — both of which a hardcoded name
//! list does.

use crate::dpdk;
use lazy_static::lazy_static;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::sync::Mutex;

/// What one `rte_mempool` costs, and how much of it is in use.
///
/// `allocated_bytes` is the figure that matters for "could we afford a smaller pool": it is the
/// hugepage memory the pool actually holds. `in_use` against `size` is the figure that says whether
/// that allocation was ever justified.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct MempoolStats {
    pub name: String,
    pub socket_id: i32,
    /// Objects requested at creation, i.e. `[mempool] capacity`.
    pub size: u32,
    /// Objects actually populated. Short of `size` means the pool could not be fully backed.
    pub populated_size: u32,
    /// Per-object bytes, including the mempool's own per-object header and trailer. For the
    /// standard pool at a 1500-byte MTU this is 128 (`rte_mbuf`) + 2176 (data room) plus overhead.
    pub obj_bytes: u32,
    /// Bytes the pool holds, summed over its `nb_mem_chunks` memory chunks. Exact, and generally
    /// above `obj_bytes * size` because DPDK will not let an object straddle a page.
    ///
    /// That gap is not a rounding footnote — it can be most of the allocation. Under `--no-huge`
    /// the page size is 4 KiB, so a 2368-byte mbuf gets a whole page to itself and the pool costs
    /// 4096 bytes per object, 1.73x its nominal size. Measure this; do not compute it from
    /// `capacity` and the MTU.
    pub allocated_bytes: u64,
    pub nb_mem_chunks: u32,
    /// Per-lcore cache size. Cached objects count as in-use even while idle, so a large cache
    /// across many cores raises the floor on `in_use` independently of offered load.
    pub cache_size: u32,
    /// Objects currently available.
    pub avail: u32,
    /// Objects currently held: RX descriptor rings, in-flight bursts, and anything retained for
    /// reassembly. Only the last of these varies with what the NIC chose to drop.
    pub in_use: u32,
}

impl MempoolStats {
    /// Fraction of the pool currently in use. This is what a smaller `capacity` would have to
    /// accommodate — but see [`MempoolHighWater`]: a periodic sample can miss the peak.
    pub fn utilisation(&self) -> f64 {
        let total = self.avail as u64 + self.in_use as u64;
        if total == 0 {
            0.0
        } else {
            self.in_use as f64 / total as f64
        }
    }

    /// Bytes currently in use, i.e. `in_use` objects at `obj_bytes` each.
    pub fn in_use_bytes(&self) -> u64 {
        self.in_use as u64 * self.obj_bytes as u64
    }
}

/// Hugepage bytes the mbuf pools hold in total. The headline "what Iris costs in memory" figure.
pub fn total_allocated_bytes(stats: &[MempoolStats]) -> u64 {
    stats.iter().map(|s| s.allocated_bytes).sum()
}

/// Sum the memory-chunk lengths of one pool.
///
/// # Safety
/// `mp` must be a live mempool. The chunk list is only mutated when a pool is populated or freed,
/// neither of which happens after startup, so reading it from the monitor thread is sound.
unsafe fn allocated_bytes(mp: *const dpdk::rte_mempool) -> u64 {
    let mut total: u64 = 0;
    let mut hdr = (*mp).mem_list.stqh_first;
    while !hdr.is_null() {
        total += (*hdr).len as u64;
        hdr = (*hdr).next.stqe_next;
    }
    total
}

/// # Safety
/// `mp` must be a live mempool.
unsafe fn stats_from_raw(mp: *mut dpdk::rte_mempool) -> MempoolStats {
    let raw = &*mp;
    MempoolStats {
        name: CStr::from_ptr(raw.name.as_ptr())
            .to_string_lossy()
            .into_owned(),
        socket_id: raw.socket_id,
        size: raw.size,
        populated_size: raw.populated_size,
        obj_bytes: raw.header_size + raw.elt_size + raw.trailer_size,
        allocated_bytes: allocated_bytes(mp),
        nb_mem_chunks: raw.nb_mem_chunks,
        cache_size: raw.cache_size,
        avail: dpdk::rte_mempool_avail_count(mp) as u32,
        in_use: dpdk::rte_mempool_in_use_count(mp) as u32,
    }
}

unsafe extern "C" fn collect_one(mp: *mut dpdk::rte_mempool, arg: *mut std::os::raw::c_void) {
    if mp.is_null() || arg.is_null() {
        return;
    }
    let out = &mut *(arg as *mut Vec<MempoolStats>);
    out.push(stats_from_raw(mp));
}

/// Read accounting for every live mempool, in name order.
///
/// Off-datapath only: this walks a global list and reads per-lcore caches, so it is far too
/// expensive for the RX loop. The monitor thread is the intended caller.
pub fn all_mempool_stats() -> Vec<MempoolStats> {
    let mut out: Vec<MempoolStats> = Vec::new();
    unsafe {
        dpdk::rte_mempool_walk(
            Some(collect_one),
            &mut out as *mut Vec<MempoolStats> as *mut std::os::raw::c_void,
        );
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Read accounting for one pool by name, or `None` if no such pool exists.
pub fn mempool_stats(name: &str) -> Option<MempoolStats> {
    let cname = CString::new(name).ok()?;
    let mp = unsafe { dpdk::rte_mempool_lookup(cname.as_ptr()) };
    if mp.is_null() {
        return None;
    }
    Some(unsafe { stats_from_raw(mp) })
}

/// Peak and mean occupancy of one pool, accumulated across the run.
///
/// Occupancy is a **gauge, not a counter**, so the delta-publish pattern the cycle budget uses
/// ([`crate::stats::publish_datapath_delta`]) does not apply — there is nothing to sum. What sizing
/// a pool actually needs is the maximum ever reached, which only a periodic sampler can observe;
/// the mean is carried alongside to show how far the peak sits above typical load. A peak close to
/// the mean means the pool is steadily occupied; a peak far above it means a burst set the
/// requirement, and `samples` says how much confidence to place in having caught it.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct MempoolHighWater {
    pub name: String,
    /// Largest `in_use` observed. The minimum viable `capacity` must exceed this.
    pub peak_in_use: u32,
    /// `peak_in_use` in bytes.
    pub peak_in_use_bytes: u64,
    /// Peak as a fraction of the pool's `size`. A small value is the whole finding: the pool is
    /// oversized by its reciprocal.
    pub peak_utilisation: f64,
    /// Mean `in_use` over the samples taken.
    pub mean_in_use: f64,
    /// Samples the peak and mean were computed from. A handful of samples cannot be trusted to
    /// have caught the peak.
    pub samples: u64,
}

#[derive(Default)]
struct Accum {
    peak: u32,
    sum: u128,
    samples: u64,
    size: u32,
    obj_bytes: u32,
}

lazy_static! {
    static ref HIGH_WATER: Mutex<BTreeMap<String, Accum>> = Mutex::new(BTreeMap::new());
}

/// Fold one sample of every live pool into the running peak and mean.
///
/// Call periodically from the monitor. The sampling interval bounds how short a burst can be and
/// still be seen, so a coarse `[online.monitor.log] interval` understates the peak.
pub fn sample_mempool_high_water() {
    let stats = all_mempool_stats();
    let mut table = HIGH_WATER.lock().unwrap();
    for s in stats {
        let acc = table.entry(s.name).or_default();
        acc.peak = acc.peak.max(s.in_use);
        acc.sum += s.in_use as u128;
        acc.samples += 1;
        acc.size = s.size;
        acc.obj_bytes = s.obj_bytes;
    }
}

/// The accumulated peak and mean for every pool sampled so far.
pub fn mempool_high_water() -> Vec<MempoolHighWater> {
    let table = HIGH_WATER.lock().unwrap();
    table
        .iter()
        .map(|(name, acc)| MempoolHighWater {
            name: name.clone(),
            peak_in_use: acc.peak,
            peak_in_use_bytes: acc.peak as u64 * acc.obj_bytes as u64,
            peak_utilisation: if acc.size == 0 {
                0.0
            } else {
                acc.peak as f64 / acc.size as f64
            },
            mean_in_use: if acc.samples == 0 {
                0.0
            } else {
                acc.sum as f64 / acc.samples as f64
            },
            samples: acc.samples,
        })
        .collect()
}
