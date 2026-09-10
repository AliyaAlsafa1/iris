//! Statistics tracking for subscription processing.
//!
//! This module provides thread-safe statistics tracking allowing monitoring of subscription dispatch, processing, and completion states.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Thread-safe statistics tracker for the various stages of subscription processing.
/// All counters use atomic operations for thread safety.
#[derive(Default)]
pub struct SubscriptionStats {
    /// Number of messages dispatched to processing queues.
    pub dispatched: AtomicU64,

    /// Number of messages dropped due to queue overflow or errors.
    pub dropped: AtomicU64,

    /// Number of messages that have completed processing.
    /// Wrapped in `Arc` for thread sharing.
    pub processed: Arc<AtomicU64>,

    /// Number of messages currently being processed.
    /// Wrapped in `Arc` for thread sharing.
    pub actively_processing: Arc<AtomicU64>,

    /// Number of messages saved to disk (not processed).
    /// Wrapped in `Arc` for thread sharing.
    pub flushed: Arc<AtomicU64>,
}

impl SubscriptionStats {
    /// Creates a new instance with all counters initialized to zero.
    pub fn new() -> Self {
        Self {
            dispatched: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            processed: Arc::new(AtomicU64::new(0)),
            actively_processing: Arc::new(AtomicU64::new(0)),
            flushed: Arc::new(AtomicU64::new(0)),
        }
    }

    /// This creates a new `SubscriptionStats` instance with identical atomic counters.
    pub fn snapshot(&self) -> SubscriptionStats {
        SubscriptionStats {
            dispatched: AtomicU64::new(self.get_dispatched()),
            dropped: AtomicU64::new(self.get_dropped()),
            processed: Arc::new(AtomicU64::new(self.get_processed())),
            actively_processing: Arc::new(AtomicU64::new(self.get_actively_processing())),
            flushed: Arc::new(AtomicU64::new(self.get_flushed())),
        }
    }

    /// Returns the current number of dispatched messages.
    pub fn get_dispatched(&self) -> u64 {
        self.dispatched.load(Ordering::Relaxed)
    }

    /// Returns the current number of dropped messages.
    pub fn get_dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Returns the current number of processed messages.
    pub fn get_processed(&self) -> u64 {
        self.processed.load(Ordering::Relaxed)
    }

    /// Returns the current number of messages actively being processed.
    pub fn get_actively_processing(&self) -> u64 {
        self.actively_processing.load(Ordering::Relaxed)
    }

    /// Mark `count` messages as being processed until the returned guard is dropped.
    ///
    /// A guard rather than a bare `fetch_add`/`fetch_sub` pair around the handler calls, because
    /// the decrement has to survive a panicking handler. `wait_for_completion` blocks until this
    /// counter reaches zero, so a single lost decrement does not merely skew a statistic — it
    /// wedges shutdown forever, and in an application that writes its results from a shutdown
    /// hook that means one panicking message costs the whole run.
    pub fn begin_processing(&self, count: u64) -> InFlight {
        self.actively_processing.fetch_add(count, Ordering::Relaxed);
        InFlight {
            counter: Arc::clone(&self.actively_processing),
            count,
        }
    }

    /// Returns the current number of messages flushed to disk.
    pub fn get_flushed(&self) -> u64 {
        self.flushed.load(Ordering::Relaxed)
    }
}

/// Outstanding work registered by [`SubscriptionStats::begin_processing`], released on drop.
///
/// Normally just let it fall out of scope; drop it explicitly only if the decrement has to land
/// at a particular point.
#[must_use = "actively_processing is only decremented when the guard drops, so it must be held \
              for as long as the batch is being processed"]
pub struct InFlight {
    counter: Arc<AtomicU64>,
    count: u64,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.counter.fetch_sub(self.count, Ordering::Relaxed);
    }
}

/// Prints current statistics to stdout.
impl fmt::Display for SubscriptionStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Processed: {}\nDropped: {}\nFlushed (to disk): {}",
            self.get_processed(),
            self.get_dropped(),
            self.get_flushed(),
        )
    }
}
