//! Per-core on-wire TCP/UDP byte accounting with a lock-free hot path.
//!
//! Each worker thread accumulates into its own cache-line-isolated counter
//! (registered once into a global registry on first use). The monitor sums the
//! registry ~once a second to derive per-second throughput. The hot path is a
//! single relaxed store to a thread-owned atomic — no shared line, no lock.

use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// One worker's counters, cache-line aligned to avoid false sharing when the
/// monitor reads adjacent cores' counters.
#[repr(align(64))]
pub struct CoreCounters {
    tcp: AtomicU64,
    udp: AtomicU64,
}

impl CoreCounters {
    fn new() -> Self {
        Self {
            tcp: AtomicU64::new(0),
            udp: AtomicU64::new(0),
        }
    }
}

/// Registry of every worker thread's counters. Written once per thread (first
/// packet), read by the monitor. The Mutex is never touched on the hot path.
static REGISTRY: OnceLock<Mutex<Vec<Arc<CoreCounters>>>> = OnceLock::new();

fn registry() -> &'static Mutex<Vec<Arc<CoreCounters>>> {
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

thread_local! {
    /// Cached raw pointer to this thread's counters (valid after first touch).
    static LOCAL: Cell<Option<*const CoreCounters>> = const { Cell::new(None) };
    /// Keeps this thread's Arc alive for the thread's lifetime.
    static LOCAL_KEEPALIVE: RefCell<Option<Arc<CoreCounters>>> =
        const { RefCell::new(None) };
}

#[inline]
fn with_local<R>(f: impl FnOnce(&CoreCounters) -> R) -> R {
    LOCAL.with(|slot| {
        let ptr = match slot.get() {
            Some(p) => p,
            None => {
                let counters = Arc::new(CoreCounters::new());
                let raw: *const CoreCounters = Arc::as_ptr(&counters);
                registry().lock().unwrap().push(counters.clone());
                LOCAL_KEEPALIVE.with(|k| *k.borrow_mut() = Some(counters));
                slot.set(Some(raw));
                raw
            }
        };
        // Safety: the Arc is kept alive by LOCAL_KEEPALIVE (this thread) and by
        // the registry, so the pointer remains valid for the thread's lifetime.
        f(unsafe { &*ptr })
    })
}

/// Hot path: add `len` bytes to this core's TCP counter.
/// Single-writer (this thread) + monitor-only reader => the load/store RMW is
/// race-free without a locked atomic add.
#[inline]
pub fn add_tcp(len: usize) {
    with_local(|c| {
        c.tcp.store(
            c.tcp.load(Ordering::Relaxed) + len as u64,
            Ordering::Relaxed,
        );
    });
}

/// Hot path: add `len` bytes to this core's UDP counter.
#[inline]
pub fn add_udp(len: usize) {
    with_local(|c| {
        c.udp.store(
            c.udp.load(Ordering::Relaxed) + len as u64,
            Ordering::Relaxed,
        );
    });
}

/// Sum every registered core's counters. Returns (tcp_bytes, udp_bytes).
pub fn totals() -> (u64, u64) {
    let reg = registry().lock().unwrap();
    let mut tcp = 0u64;
    let mut udp = 0u64;
    for c in reg.iter() {
        tcp += c.tcp.load(Ordering::Relaxed);
        udp += c.udp.load(Ordering::Relaxed);
    }
    (tcp, udp)
}
