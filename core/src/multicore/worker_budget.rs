//! Utilization accounting for the worker pools.
//!
//! A worker parks when its queue is empty, so unlike an RX core its utilization is a real number.
//! Measuring it needs `cpu_ns` from `CLOCK_THREAD_CPUTIME_ID` over a `wall` span from
//! `rte_rdtsc`: the TSC alone counts through crossbeam's pre-park spin and the sleep alike, so by
//! the TSC an idle worker looks fully occupied. Their ratio is the whole report -- a worker that
//! spins instead of parking needs no separate diagnostic, since the spinning is on-CPU time and
//! drives `busy_fraction` towards 1.
//!
//! Each pool registers its counters at spawn and its threads refresh them per batch, the way
//! [`transport_meter`](crate::lcore::transport_meter) does, so the monitor can read a live figure
//! per pool rather than one process-wide total that only fills in as threads exit.

use crate::dpdk;
use cpu_time::ThreadTime;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// One worker thread's live counters, cache-line isolated so a thread's own updates do not
/// contend with its neighbours' or with the monitor's reads.
#[repr(align(64))]
#[derive(Default)]
struct ThreadCounters {
    cpu_ns: AtomicU64,
    wall: AtomicU64,
    items: AtomicU64,
    nonvoluntary_ctxt_switches: AtomicU64,
}

/// One pool's counters: a fixed slot per worker thread, allocated when the pool is spawned.
pub(crate) struct PoolShared {
    label: String,
    /// Threads that reached their loop. Slots are allocated up front, so this is what says how
    /// many of them are contributing.
    started: AtomicU64,
    slots: Vec<ThreadCounters>,
}

impl PoolShared {
    fn snapshot(&self) -> WorkerBudget {
        let mut b = WorkerBudget {
            threads: self.started.load(Ordering::Relaxed),
            ..Default::default()
        };
        for s in &self.slots {
            b.cpu_ns += s.cpu_ns.load(Ordering::Relaxed);
            b.wall += s.wall.load(Ordering::Relaxed);
            b.items += s.items.load(Ordering::Relaxed);
            b.nonvoluntary_ctxt_switches += s.nonvoluntary_ctxt_switches.load(Ordering::Relaxed);
        }
        b
    }
}

static REGISTRY: OnceLock<Mutex<Vec<Arc<PoolShared>>>> = OnceLock::new();

fn registry() -> &'static Mutex<Vec<Arc<PoolShared>>> {
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

/// Register a pool of `threads` workers under `label`, returning the counters its threads write.
pub(crate) fn register(label: String, threads: usize) -> Arc<PoolShared> {
    let shared = Arc::new(PoolShared {
        label,
        started: AtomicU64::new(0),
        slots: (0..threads).map(|_| ThreadCounters::default()).collect(),
    });
    registry().lock().unwrap().push(Arc::clone(&shared));
    shared
}

/// Every registered pool's current budget. Empty if no pool enabled `measure_utilization`.
pub fn pools() -> Vec<PoolBudget> {
    registry()
        .lock()
        .unwrap()
        .iter()
        .map(|p| PoolBudget {
            label: p.label.clone(),
            budget: p.snapshot(),
        })
        .collect()
}

/// One pool's budget, labelled by the cores it was given.
pub struct PoolBudget {
    pub label: String,
    pub budget: WorkerBudget,
}

/// How much of a worker core a pool used, summed across its threads.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WorkerBudget {
    /// On-CPU nanoseconds. The only field that measures utilization, being the only one that
    /// stops while the thread is parked.
    pub cpu_ns: u64,
    /// Cycles since each thread entered its loop, summed across threads.
    pub wall: u64,
    pub items: u64,
    pub threads: u64,
    /// From `/proc/thread-self/status`, and only updated when a thread exits. Should be ~0 under
    /// `isolcpus`; a large value means `cpu_ns` still describes the thread honestly but no longer
    /// describes the core.
    pub nonvoluntary_ctxt_switches: u64,
}

impl WorkerBudget {
    /// `cpu_ns` in cycles, so it can be divided by `wall`. The TSC is invariant, so this
    /// survives frequency scaling.
    pub fn cpu_cycles(&self, tsc_hz: u64) -> f64 {
        self.cpu_ns as f64 * tsc_hz as f64 / 1e9
    }

    /// The headline: mean share of one worker core consumed.
    pub fn busy_fraction(&self, tsc_hz: u64) -> f64 {
        fraction(self.cpu_cycles(tsc_hz), self.wall as f64)
    }

    /// Utilization as whole cores, so it can be differenced against
    /// [`DatapathBudget::cores_idle`](crate::lcore::datapath_budget::DatapathBudget::cores_idle).
    pub fn cores_busy(&self, tsc_hz: u64) -> f64 {
        self.busy_fraction(tsc_hz) * self.threads as f64
    }

    /// Items per second sustainable at 100% of one core. Independent of the offered load of the
    /// run that measured it, so it can be compared against an arrival rate directly.
    pub fn sustainable_item_rate(&self) -> f64 {
        fraction(self.items as f64 * 1e9, self.cpu_ns as f64)
    }
}

fn fraction(num: f64, den: f64) -> f64 {
    if den <= 0.0 {
        0.0
    } else {
        num / den
    }
}

/// One worker thread's accumulator, refreshing its pool slot as it goes.
///
/// Both clocks run from [`Self::start`] to the [`Drop`], so nothing inside the loop needs to be
/// bracketed; the loop only reports how much work it handled. The `Drop` refresh is what makes a
/// panicking handler still record -- it unwinds past any explicit call.
pub(crate) struct WorkerProbe {
    shared: Arc<PoolShared>,
    index: usize,
    cpu_start: ThreadTime,
    nonvol_start: u64,
    wall_start: u64,
    items: u64,
}

impl WorkerProbe {
    /// Start both clocks and claim slot `index`. Call from inside the worker thread, after it has
    /// been pinned -- the CPU clock is per-thread, so it cannot be started anywhere else.
    pub(crate) fn start(shared: Arc<PoolShared>, index: usize) -> Self {
        shared.started.fetch_add(1, Ordering::Relaxed);
        Self {
            shared,
            index,
            cpu_start: ThreadTime::now(),
            nonvol_start: read_nonvoluntary_ctxt_switches(),
            wall_start: unsafe { dpdk::rte_rdtsc() },
            items: 0,
        }
    }

    /// Count work handled and refresh the pool's slot.
    ///
    /// Called once per batch. `ThreadTime::now` is a vDSO `clock_gettime`, negligible against a
    /// batch of real handler work, and it is what lets the monitor report a live figure.
    pub(crate) fn record_items(&mut self, items: u64) {
        self.items += items;
        self.refresh();
    }

    fn refresh(&self) {
        let slot = &self.shared.slots[self.index];
        let wall = unsafe { dpdk::rte_rdtsc() }.wrapping_sub(self.wall_start);
        slot.cpu_ns.store(
            self.cpu_start.elapsed().as_nanos() as u64,
            Ordering::Relaxed,
        );
        slot.wall.store(wall, Ordering::Relaxed);
        slot.items.store(self.items, Ordering::Relaxed);
    }
}

impl Drop for WorkerProbe {
    fn drop(&mut self) {
        self.refresh();
        // Only here: reading /proc per batch would cost far more than the loop it measures.
        self.shared.slots[self.index]
            .nonvoluntary_ctxt_switches
            .store(
                read_nonvoluntary_ctxt_switches().saturating_sub(self.nonvol_start),
                Ordering::Relaxed,
            );
    }
}

/// Involuntary context switches for the calling thread. `/proc/thread-self` needs no `gettid`.
/// Returns 0 if unreadable -- a diagnostic should not take the budget down with it.
fn read_nonvoluntary_ctxt_switches() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/thread-self/status") else {
        return 0;
    };
    status
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| *key == "nonvoluntary_ctxt_switches")
        .and_then(|(_, val)| val.trim().parse().ok())
        .unwrap_or(0)
}
