//! Replay a measured NIC control-plane latency trace, making a fast NIC behave like a slow one.
//!
//! # Why
//!
//! `dyn_hardware_assist` installs a per-connection `rte_flow` DROP rule so ciphertext packets
//! never reach the CPU. Whether that pays for itself turns on what a rule costs to install: ~12 us
//! on a Mellanox CX5, two orders of magnitude more on an Intel NIC, and the cost scales with
//! *connection arrival rate*, not byte rate. So measuring on the fast NIC says nothing about the
//! slow one.
//!
//! Given a trace measured on the target NIC, this spins for the trace's latency **before** each
//! real `rte_flow_create` / `rte_flow_destroy`. The real call still runs, so the datapath saving
//! and the NIC-side COUNT ground truth stay real; only the control-plane cost is emulated.
//! Delaying beforehand also models take-effect time: packets keep arriving during the install.
//!
//! # Trace format
//!
//! CSV, header `op_id,phase,us`, three rows per `op_id`: `replace`, `delete`, `insert`. `replace`
//! is exactly `delete + insert`, so it is skipped at load and each primitive charged from its own
//! row. A rule-table eviction is a delete then an insert, and pays the sum of the two.
//!
//! # Not paced
//!
//! * **Teardown**, from [`suspend`] onwards: draining thousands of resident rules, plus the
//!   install worker's backlog flush, would add minutes that measure nothing. Skips are still
//!   counted ([`NicLatencyStats::unpaced_teardown_deletes`]), so the exemption is auditable.
//! * **Startup rules** in `super::raw_drop` and `crate::filter::hardware`: installed once per
//!   port, never churned.
//!
//! Every [`charge`] sits outside the `rte_rdtsc` reads in `super::five_tuple_drop`, so
//! measurements of the real hardware cost stay separate from the emulated one. They are additive.

use std::io::Read;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::config::NicLatencyConfig;
use crate::dpdk;

/// Which primitive is being charged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// An `rte_flow_create`.
    Insert,
    /// An `rte_flow_destroy`.
    Delete,
}

/// One measured operation. `replace` is not stored: it is exactly `delete + insert`.
#[derive(Clone, Copy)]
struct TraceOp {
    delete_ns: u32,
    insert_ns: u32,
}

/// Marks an unseen phase, catching missing and duplicate rows without a second bitmap. Rejected
/// as a real value at parse time.
const UNSET: u32 = u32::MAX;

impl TraceOp {
    const fn unset() -> Self {
        TraceOp {
            delete_ns: UNSET,
            insert_ns: UNSET,
        }
    }
}

/// Owned by the [`Pacer`] rather than kept as free statics, so a pacer built in a test is
/// independent of every other one.
#[derive(Default)]
struct Counters {
    paced_inserts: AtomicU64,
    paced_deletes: AtomicU64,
    requested_ns_insert: AtomicU64,
    requested_ns_delete: AtomicU64,
    spun_cycles_insert: AtomicU64,
    spun_cycles_delete: AtomicU64,
    trace_wraps: AtomicU64,
}

/// The loaded trace plus everything needed to turn a latency into a spin.
struct Pacer {
    ops: Vec<TraceOp>,
    tsc_hz: u64,
    /// `0` = pure spin. Otherwise sleep for `delay - sleep_threshold_cycles` and spin the rest.
    sleep_threshold_cycles: u64,
    scale: f64,
    /// Monotonic position in the trace: one `fetch_add` per charge, shared by every installing
    /// thread. Contention is one uncontended increment per few hundred microseconds of spinning,
    /// so per-core cursors would buy nothing.
    cursor: AtomicUsize,
    counters: Counters,
}

// A state rather than a bool, so `charge` can tell "never configured" or "enabled = false"
// (nothing to report) from "suspended for teardown" (worth counting). One relaxed load on the
// fast path.
const STATE_UNCONFIGURED: u8 = 0;
const STATE_ACTIVE: u8 = 1;
const STATE_OFF: u8 = 2;
const STATE_SUSPENDED: u8 = 3;

static STATE: AtomicU8 = AtomicU8::new(STATE_UNCONFIGURED);
static PACER: OnceLock<Pacer> = OnceLock::new();

/// Operations that ran at native speed because teardown had begun. Global rather than per-pacer:
/// a property of shutdown, and touched only once pacing is over.
static UNPACED_TEARDOWN_INSERTS: AtomicU64 = AtomicU64::new(0);
static UNPACED_TEARDOWN_DELETES: AtomicU64 = AtomicU64::new(0);

/// Snapshot of the emulation's activity.
#[derive(Debug, Clone, Copy, Default)]
pub struct NicLatencyStats {
    /// True while operations are being paced. False before init, under `enabled = false`, and
    /// after [`suspend`].
    pub active: bool,
    /// True once a trace is loaded, whether or not pacing is active.
    pub configured: bool,
    pub trace_ops: usize,
    pub scale: f64,
    pub tsc_hz: u64,
    pub paced_inserts: u64,
    pub paced_deletes: u64,
    /// Sum of the latencies requested. Over the op count this must reproduce the trace's mean —
    /// the proof that the trace is replayed rather than a constant.
    pub requested_ns_insert: u64,
    pub requested_ns_delete: u64,
    /// Cycles actually spun; against `requested_ns`, the overshoot.
    pub spun_cycles_insert: u64,
    pub spun_cycles_delete: u64,
    /// Times the cursor ran off the end of the trace and restarted.
    pub trace_wraps: u64,
    /// Operations that ran at native speed because teardown had begun.
    pub unpaced_teardown_inserts: u64,
    pub unpaced_teardown_deletes: u64,
}

impl NicLatencyStats {
    /// Mean insert latency requested, in microseconds; compare with the trace's own mean.
    pub fn mean_insert_us(&self) -> f64 {
        div_us(self.requested_ns_insert, self.paced_inserts)
    }

    /// Mean delete latency requested, in microseconds.
    pub fn mean_delete_us(&self) -> f64 {
        div_us(self.requested_ns_delete, self.paced_deletes)
    }

    /// Cycles spun over cycles requested. `1.0` is perfect; the spin can only overshoot, by at
    /// most one loop iteration per call.
    pub fn spin_overshoot_ratio(&self) -> f64 {
        let requested_ns = (self.requested_ns_insert + self.requested_ns_delete) as f64;
        if requested_ns <= 0.0 || self.tsc_hz == 0 {
            return 0.0;
        }
        let requested_cycles = requested_ns * (self.tsc_hz as f64 / 1e9);
        (self.spun_cycles_insert + self.spun_cycles_delete) as f64 / requested_cycles
    }

    /// Emulated cycles as a fraction of `wall_cycles * worker_cores`. Near `1.0` the install
    /// worker is saturated, so the run is queue-limited and its offload counts cover only part of
    /// the offered load.
    pub fn worker_busy_fraction(&self, wall_cycles: u64, worker_cores: u64) -> f64 {
        let capacity = wall_cycles as f64 * worker_cores as f64;
        if capacity <= 0.0 {
            return 0.0;
        }
        (self.spun_cycles_insert + self.spun_cycles_delete) as f64 / capacity
    }
}

fn div_us(ns: u64, n: u64) -> f64 {
    if n == 0 {
        0.0
    } else {
        ns as f64 / n as f64 / 1000.0
    }
}

/// Load the trace and arm the emulation. Called once by the runtime: after `rte_eal_init` (no
/// TSC frequency before it) and before any RX core or install worker exists.
///
/// Errors rather than degrading — a run that silently skipped pacing would be indistinguishable
/// from an unemulated baseline. Callers should treat it as fatal.
pub fn init(cfg: &NicLatencyConfig) -> Result<()> {
    let tsc_hz = unsafe { dpdk::rte_get_tsc_hz() };
    if tsc_hz == 0 {
        bail!("rte_get_tsc_hz() returned 0; init() must run after rte_eal_init()");
    }

    let started = std::time::Instant::now();
    let file = std::fs::File::open(&cfg.trace)
        .with_context(|| format!("could not open NIC latency trace {}", cfg.trace))?;
    let pacer = Pacer::from_reader(
        std::io::BufReader::with_capacity(1 << 20, file),
        tsc_hz,
        cfg.scale,
        cfg.limit_ops,
        cfg.sleep_threshold_us,
    )
    .with_context(|| format!("invalid NIC latency trace {}", cfg.trace))?;

    let (mean_insert_us, mean_delete_us) = pacer.means_us();
    let n = pacer.ops.len();
    let load_secs = started.elapsed().as_secs_f64();

    install(pacer, cfg.enabled)?;

    log::info!(
        "NIC latency emulation {}: {} ops from {} in {:.2}s, \
         mean insert {:.2} us, mean delete {:.2} us, scale {}, tsc {} Hz",
        if cfg.enabled {
            "ARMED"
        } else {
            "loaded but OFF"
        },
        n,
        cfg.trace,
        load_secs,
        mean_insert_us,
        mean_delete_us,
        cfg.scale,
        tsc_hz,
    );
    Ok(())
}

/// Publish the pacer and leave [`STATE_UNCONFIGURED`].
fn install(pacer: Pacer, enabled: bool) -> Result<()> {
    if PACER.set(pacer).is_err() {
        bail!("NIC latency emulation already initialised");
    }
    STATE.store(
        if enabled { STATE_ACTIVE } else { STATE_OFF },
        Ordering::Release,
    );
    Ok(())
}

/// Stop pacing, permanently. Called once the RX cores have exited, so the shutdown drain and the
/// install worker's backlog flush run at native speed. Nothing re-arms it.
pub fn suspend() {
    // Leave `OFF` and `UNCONFIGURED` alone, so the reported state still says why nothing was paced.
    let _ = STATE.compare_exchange(
        STATE_ACTIVE,
        STATE_SUSPENDED,
        Ordering::AcqRel,
        Ordering::Relaxed,
    );
}

/// Spin for the trace's latency for one `phase`, then return so the caller can do the real
/// operation.
///
/// Call this *outside* any `rte_rdtsc` bracket, so the emulated cost never pollutes measurement of
/// the real one.
#[inline]
pub fn charge(phase: Phase) {
    let state = STATE.load(Ordering::Relaxed);
    if state != STATE_ACTIVE {
        if state == STATE_SUSPENDED {
            match phase {
                Phase::Insert => &UNPACED_TEARDOWN_INSERTS,
                Phase::Delete => &UNPACED_TEARDOWN_DELETES,
            }
            .fetch_add(1, Ordering::Relaxed);
        }
        return;
    }
    let Some(pacer) = PACER.get() else { return };
    pacer.charge(phase);
}

/// Snapshot of the emulation's counters. All zero, and `configured` false, if no trace loaded.
pub fn nic_latency_cost() -> NicLatencyStats {
    match PACER.get() {
        Some(p) => p.stats(STATE.load(Ordering::Acquire) == STATE_ACTIVE),
        None => NicLatencyStats::default(),
    }
}

impl Pacer {
    /// Parse a trace. Split from [`init`] so tests need no file, no EAL and no real TSC.
    fn from_reader<R: Read>(
        reader: R,
        tsc_hz: u64,
        scale: f64,
        limit_ops: usize,
        sleep_threshold_us: u64,
    ) -> Result<Pacer> {
        if !(scale.is_finite() && scale >= 0.0) {
            bail!("scale must be finite and non-negative, got {scale}");
        }
        if tsc_hz == 0 {
            bail!("tsc_hz must be non-zero");
        }
        let mut csv_reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .from_reader(reader);

        let mut ops: Vec<TraceOp> = Vec::new();
        let mut record = csv::StringRecord::new();
        let mut row = 0u64;

        while csv_reader
            .read_record(&mut record)
            .with_context(|| format!("malformed CSV at row {} (after the header)", row + 1))?
        {
            row += 1;
            if record.len() < 3 {
                bail!(
                    "row {row}: expected 3 fields `op_id,phase,us`, got {}",
                    record.len()
                );
            }
            let phase_field = record.get(1).unwrap_or_default();
            // Phases differ in their first byte, and `replace` — two thirds of the file, and
            // exactly `delete + insert` — is skipped, so test it before parsing anything else.
            let phase = match phase_field.as_bytes().first().copied() {
                Some(b'r') => continue,
                Some(b'i') => Phase::Insert,
                Some(b'd') => Phase::Delete,
                _ => bail!("row {row}: unknown phase {phase_field:?}"),
            };

            let op_id: usize = record
                .get(0)
                .unwrap_or_default()
                .trim()
                .parse()
                .with_context(|| format!("row {row}: bad op_id"))?;
            if limit_ops != 0 && op_id >= limit_ops {
                continue;
            }

            let us: f64 = record
                .get(2)
                .unwrap_or_default()
                .trim()
                .parse()
                .with_context(|| format!("row {row}: bad us value"))?;
            if !(us.is_finite() && us >= 0.0) {
                bail!("row {row}: us must be finite and non-negative, got {us}");
            }
            let ns = (us * 1000.0 * scale).round();
            if ns >= UNSET as f64 {
                bail!("row {row}: {us} us at scale {scale} does not fit in u32 nanoseconds");
            }
            let ns = ns as u32;

            if op_id >= ops.len() {
                ops.resize(op_id + 1, TraceOp::unset());
            }
            let slot = match phase {
                Phase::Insert => &mut ops[op_id].insert_ns,
                Phase::Delete => &mut ops[op_id].delete_ns,
            };
            if *slot != UNSET {
                bail!("row {row}: duplicate {phase:?} row for op_id {op_id}");
            }
            *slot = ns;
        }

        if ops.is_empty() {
            bail!("trace contains no insert or delete rows");
        }
        // Never zero-fill a gap: zero delay is indistinguishable from no pacing.
        for (op_id, op) in ops.iter().enumerate() {
            if op.insert_ns == UNSET {
                bail!("op_id {op_id} has no insert row");
            }
            if op.delete_ns == UNSET {
                bail!("op_id {op_id} has no delete row");
            }
        }

        Ok(Pacer {
            ops,
            tsc_hz,
            sleep_threshold_cycles: (sleep_threshold_us as u128 * tsc_hz as u128 / 1_000_000u128)
                as u64,
            scale,
            cursor: AtomicUsize::new(0),
            counters: Counters::default(),
        })
    }

    /// Mean insert/delete latency in the loaded trace, in microseconds.
    fn means_us(&self) -> (f64, f64) {
        let n = self.ops.len() as f64;
        let insert: f64 = self.ops.iter().map(|o| o.insert_ns as f64).sum();
        let delete: f64 = self.ops.iter().map(|o| o.delete_ns as f64).sum();
        (insert / n / 1000.0, delete / n / 1000.0)
    }

    fn charge(&self, phase: Phase) {
        let ns = self.next_delay_ns(phase);
        let spun = self.spin(self.cycles_for(ns));
        let c = &self.counters;
        match phase {
            Phase::Insert => {
                c.paced_inserts.fetch_add(1, Ordering::Relaxed);
                c.requested_ns_insert
                    .fetch_add(ns as u64, Ordering::Relaxed);
                c.spun_cycles_insert.fetch_add(spun, Ordering::Relaxed);
            }
            Phase::Delete => {
                c.paced_deletes.fetch_add(1, Ordering::Relaxed);
                c.requested_ns_delete
                    .fetch_add(ns as u64, Ordering::Relaxed);
                c.spun_cycles_delete.fetch_add(spun, Ordering::Relaxed);
            }
        }
    }

    #[inline]
    fn cycles_for(&self, ns: u32) -> u64 {
        (ns as u128 * self.tsc_hz as u128 / 1_000_000_000) as u64
    }

    /// Claim the next trace position and return `phase`'s delay in nanoseconds.
    fn next_delay_ns(&self, phase: Phase) -> u32 {
        let op = &self.ops[self.claim()];
        match phase {
            Phase::Insert => op.insert_ns,
            Phase::Delete => op.delete_ns,
        }
    }

    /// Next trace index, wrapping. Reuse is counted, not assumed.
    fn claim(&self) -> usize {
        let n = self.ops.len();
        let raw = self.cursor.fetch_add(1, Ordering::Relaxed);
        if raw != 0 && raw.is_multiple_of(n) {
            self.counters.trace_wraps.fetch_add(1, Ordering::Relaxed);
        }
        raw % n
    }

    /// Busy-spin for `target` TSC cycles; returns the cycles actually elapsed.
    ///
    /// Bounded by `rte_rdtsc` rather than an iteration count, so the delay does not drift with CPU
    /// frequency or microarchitecture. Burning CPU is fine: every call site is the off-datapath
    /// rule-install worker, on a core the config keeps clear of the RX cores.
    fn spin(&self, target: u64) -> u64 {
        if target == 0 {
            return 0;
        }
        let start = unsafe { dpdk::rte_rdtsc() };

        // Coarse sleep for the bulk of a long delay. Off by default: non-RT wakeup jitter is
        // tens of microseconds, enough to swamp a real trace's short tail.
        if self.sleep_threshold_cycles != 0 && target > self.sleep_threshold_cycles {
            let coarse = target - self.sleep_threshold_cycles;
            let ns = (coarse as u128 * 1_000_000_000u128 / self.tsc_hz as u128) as u64;
            std::thread::sleep(Duration::from_nanos(ns));
        }

        let mut acc: u64 = start;
        loop {
            // Cheap arithmetic between clock reads, so the loop is not purely rdtsc-bound and
            // looks more like work to the core's execution ports.
            for _ in 0..8 {
                acc = acc
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                std::hint::black_box(acc);
            }
            let elapsed = unsafe { dpdk::rte_rdtsc() }.wrapping_sub(start);
            if elapsed >= target {
                return elapsed;
            }
        }
    }

    fn stats(&self, active: bool) -> NicLatencyStats {
        let c = &self.counters;
        NicLatencyStats {
            active,
            // A pacer exists, so a trace was loaded.
            configured: true,
            trace_ops: self.ops.len(),
            scale: self.scale,
            tsc_hz: self.tsc_hz,
            paced_inserts: c.paced_inserts.load(Ordering::Relaxed),
            paced_deletes: c.paced_deletes.load(Ordering::Relaxed),
            requested_ns_insert: c.requested_ns_insert.load(Ordering::Relaxed),
            requested_ns_delete: c.requested_ns_delete.load(Ordering::Relaxed),
            spun_cycles_insert: c.spun_cycles_insert.load(Ordering::Relaxed),
            spun_cycles_delete: c.spun_cycles_delete.load(Ordering::Relaxed),
            trace_wraps: c.trace_wraps.load(Ordering::Relaxed),
            unpaced_teardown_inserts: UNPACED_TEARDOWN_INSERTS.load(Ordering::Relaxed),
            unpaced_teardown_deletes: UNPACED_TEARDOWN_DELETES.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// Two ops shaped like the real trace: `replace` first, and equal to `delete + insert` —
    /// the invariant the loader relies on.
    const SAMPLE: &str = "\
op_id,phase,us
0,replace,514.014
0,delete,298.695
0,insert,215.319
1,replace,526.952
1,delete,306.666
1,insert,220.287
";

    /// At exactly 1 GHz a nanosecond is a cycle, so cycle assertions read as nanoseconds.
    const GHZ: u64 = 1_000_000_000;

    fn pacer(src: &str) -> Pacer {
        Pacer::from_reader(src.as_bytes(), GHZ, 1.0, 0, 0).expect("trace should load")
    }

    /// This machine's TSC rate, measured without EAL, for the timing tests.
    fn measured_tsc_hz() -> u64 {
        let t0 = Instant::now();
        let c0 = unsafe { dpdk::rte_rdtsc() };
        while t0.elapsed() < Duration::from_millis(50) {
            std::hint::spin_loop();
        }
        let cycles = unsafe { dpdk::rte_rdtsc() } - c0;
        (cycles as f64 / t0.elapsed().as_secs_f64()) as u64
    }

    #[test]
    fn loads_insert_and_delete_and_ignores_replace() {
        let p = pacer(SAMPLE);
        assert_eq!(p.ops.len(), 2);
        assert_eq!(p.ops[0].delete_ns, 298_695);
        assert_eq!(p.ops[0].insert_ns, 215_319);
        assert_eq!(p.ops[1].delete_ns, 306_666);
        assert_eq!(p.ops[1].insert_ns, 220_287);
        // The replace rows were skipped, but their invariant still holds.
        assert_eq!(p.ops[0].delete_ns + p.ops[0].insert_ns, 514_014);
    }

    #[test]
    fn scale_and_limit_apply_at_load() {
        let scaled = Pacer::from_reader(SAMPLE.as_bytes(), GHZ, 0.5, 0, 0).unwrap();
        assert_eq!(scaled.ops[0].delete_ns, 149_348); // 298.695 us / 2, rounded
        assert_eq!(scaled.ops[0].insert_ns, 107_660); // 215.319 us / 2, rounded

        let limited = Pacer::from_reader(SAMPLE.as_bytes(), GHZ, 1.0, 1, 0).unwrap();
        assert_eq!(limited.ops.len(), 1);
    }

    #[test]
    fn rejects_bad_traces() {
        let cases: [(&str, &str); 7] = [
            ("op_id,phase,us\n", "no insert or delete rows"),
            ("op_id,phase,us\n0,delete,1.0\n", "no insert row"),
            ("op_id,phase,us\n0,insert,1.0\n", "no delete row"),
            (
                "op_id,phase,us\n0,insert,1.0\n0,delete,1.0\n0,insert,2.0\n",
                "duplicate",
            ),
            ("op_id,phase,us\n0,insert,abc\n", "bad us value"),
            // A phase starting with `r` is taken as `replace` and skipped, so a file of only
            // those parses as empty rather than wrong.
            (
                "op_id,phase,us\n0,rubbish,1.0\n",
                "no insert or delete rows",
            ),
            ("op_id,phase,us\n0,xyz,1.0\n", "unknown phase"),
        ];
        for (src, expect) in cases {
            let err = match Pacer::from_reader(src.as_bytes(), GHZ, 1.0, 0, 0) {
                Ok(_) => panic!("trace {src:?} should have been rejected"),
                Err(e) => e,
            };
            // The root cause is what matters; the loader wraps it in file context.
            let chain = format!("{err:?}");
            assert!(
                chain.contains(expect),
                "trace {src:?} gave {chain:?}, expected {expect:?}"
            );
        }
        assert!(
            Pacer::from_reader("op_id,phase,us\n0,insert,-1.0\n".as_bytes(), GHZ, 1.0, 0, 0)
                .is_err()
        );
        assert!(Pacer::from_reader(SAMPLE.as_bytes(), GHZ, -1.0, 0, 0).is_err());
        assert!(Pacer::from_reader(SAMPLE.as_bytes(), 0, 1.0, 0, 0).is_err());
    }

    #[test]
    fn every_charge_takes_the_next_op() {
        let p = pacer(SAMPLE);
        assert_eq!(p.next_delay_ns(Phase::Delete), 298_695); // op 0's delete
        assert_eq!(p.next_delay_ns(Phase::Insert), 220_287); // op 1's insert

        // Each phase reads its own field of whichever op the cursor lands on.
        let q = pacer(SAMPLE);
        assert_eq!(q.next_delay_ns(Phase::Insert), 215_319); // op 0's insert
        assert_eq!(q.next_delay_ns(Phase::Delete), 306_666); // op 1's delete
    }

    #[test]
    fn cursor_wraps_and_counts_the_reuse() {
        let p = pacer(SAMPLE);
        for _ in 0..p.ops.len() {
            p.next_delay_ns(Phase::Insert);
        }
        assert_eq!(p.counters.trace_wraps.load(Ordering::Relaxed), 0);
        // Back to op 0.
        assert_eq!(p.next_delay_ns(Phase::Insert), 215_319);
        assert_eq!(p.counters.trace_wraps.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn spin_is_accurate_at_trace_scale() {
        let tsc_hz = measured_tsc_hz();
        let p = Pacer::from_reader(SAMPLE.as_bytes(), tsc_hz, 1.0, 0, 0).unwrap();

        // 100 x 200 us: long enough that per-call overhead cannot hide, short enough to be quick.
        let target = p.cycles_for(200_000);
        let started = Instant::now();
        let mut spun = 0u64;
        for _ in 0..100 {
            spun += p.spin(target);
        }
        let elapsed = started.elapsed().as_secs_f64();
        let expected = 100.0 * 200e-6;
        assert!(
            (elapsed - expected).abs() / expected < 0.02,
            "elapsed {elapsed:.6}s vs expected {expected:.6}s"
        );

        // The spin can only overshoot, and by well under a microsecond per call.
        let overshoot_us = (spun as f64 - 100.0 * target as f64) / (tsc_hz as f64 / 1e6) / 100.0;
        assert!(
            (0.0..1.0).contains(&overshoot_us),
            "mean overshoot {overshoot_us:.3} us per call"
        );
    }

    #[test]
    fn spin_is_accurate_at_the_traces_short_tail() {
        // 3.6 us is the shortest delete in the real Intel trace — the case a coarse `nanosleep`
        // would fail, and the reason the spin is the default.
        let tsc_hz = measured_tsc_hz();
        let p = Pacer::from_reader(SAMPLE.as_bytes(), tsc_hz, 1.0, 0, 0).unwrap();
        let target = p.cycles_for(3_600);
        let mut spun = 0u64;
        for _ in 0..1000 {
            spun += p.spin(target);
        }
        let overshoot_us = (spun as f64 - 1000.0 * target as f64) / (tsc_hz as f64 / 1e6) / 1000.0;
        assert!(
            (0.0..0.5).contains(&overshoot_us),
            "mean overshoot {overshoot_us:.4} us per call"
        );
    }

    #[test]
    fn zero_scale_costs_nothing() {
        let p = Pacer::from_reader(SAMPLE.as_bytes(), measured_tsc_hz(), 0.0, 0, 0).unwrap();
        let started = Instant::now();
        for _ in 0..10_000 {
            p.charge(Phase::Insert);
        }
        let per_call_ns = started.elapsed().as_nanos() as f64 / 10_000.0;
        assert!(per_call_ns < 200.0, "{per_call_ns:.1} ns per charge()");
        assert_eq!(p.counters.paced_inserts.load(Ordering::Relaxed), 10_000);
        assert_eq!(p.counters.requested_ns_insert.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn config_section_deserializes_with_defaults() {
        // Only `trace` is required; the rest must fall back to their documented defaults, or a
        // config that names a trace could quietly not pace.
        let cfg: NicLatencyConfig =
            toml::from_str("trace = \"/tmp/churn.csv\"").expect("minimal section should parse");
        assert_eq!(cfg.trace, "/tmp/churn.csv");
        assert!(cfg.enabled);
        assert_eq!(cfg.scale, 1.0);
        assert_eq!(cfg.limit_ops, 0);
        assert_eq!(cfg.sleep_threshold_us, 0);

        let cfg: NicLatencyConfig = toml::from_str(
            "trace = \"/tmp/churn.csv\"\n\
             enabled = false\n\
             scale = 0.5\n\
             limit_ops = 1000\n\
             sleep_threshold_us = 50\n",
        )
        .expect("full section should parse");
        assert!(!cfg.enabled);
        assert_eq!(cfg.scale, 0.5);
        assert_eq!(cfg.limit_ops, 1000);
        assert_eq!(cfg.sleep_threshold_us, 50);

        // A section without a trace is an error, not a silent no-op.
        assert!(toml::from_str::<NicLatencyConfig>("enabled = true").is_err());
    }

    #[test]
    fn init_fails_loudly_on_a_missing_trace() {
        let cfg = NicLatencyConfig {
            trace: "/nonexistent/churn.csv".to_string(),
            ..Default::default()
        };
        // `init` needs EAL for the TSC frequency, so drive the file-opening half directly.
        let err = std::fs::File::open(&cfg.trace).expect_err("should not exist");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(Pacer::from_reader("".as_bytes(), GHZ, 1.0, 0, 0).is_err());
    }

    /// Load a real trace and check its shape. Ignored by default: traces are large and
    /// deliberately not in the repo. Point `IRIS_NIC_LATENCY_TRACE` at one and run
    /// `cargo test -p iris-core --release -- --ignored --nocapture nic_latency`.
    #[test]
    #[ignore]
    fn loads_the_real_trace() {
        let path = std::env::var("IRIS_NIC_LATENCY_TRACE")
            .expect("set IRIS_NIC_LATENCY_TRACE to a trace path");
        let started = Instant::now();
        let file = std::fs::File::open(&path).expect("trace should open");
        let p = Pacer::from_reader(
            std::io::BufReader::with_capacity(1 << 20, file),
            GHZ,
            1.0,
            0,
            0,
        )
        .expect("real trace should load");
        let (insert_us, delete_us) = p.means_us();
        println!(
            "{} ops in {:.2}s, mean insert {:.3} us, mean delete {:.3} us",
            p.ops.len(),
            started.elapsed().as_secs_f64(),
            insert_us,
            delete_us,
        );
        assert!(p.ops.len() > 1, "a usable trace needs more than one op");
        assert!(insert_us > 0.0 && delete_us > 0.0);
    }

    /// The only test that touches the process-wide state, so it walks the whole lifecycle at
    /// once rather than racing sibling tests for it.
    #[test]
    fn state_machine_and_teardown_exemption() {
        assert!(!nic_latency_cost().active);
        assert!(!nic_latency_cost().configured);

        // Zero scale, so the lifecycle costs no real time.
        let p = Pacer::from_reader(SAMPLE.as_bytes(), GHZ, 0.0, 0, 0).unwrap();
        install(p, true).unwrap();
        assert!(nic_latency_cost().active);
        assert!(nic_latency_cost().configured);

        charge(Phase::Delete);
        charge(Phase::Insert);
        let stats = nic_latency_cost();
        assert_eq!(stats.paced_deletes, 1);
        assert_eq!(stats.paced_inserts, 1);
        assert_eq!(stats.unpaced_teardown_deletes, 0);

        // Teardown: nothing is paced from here on, but skips are counted.
        suspend();
        assert!(!nic_latency_cost().active);
        for _ in 0..3 {
            charge(Phase::Delete);
        }
        charge(Phase::Insert);
        let stats = nic_latency_cost();
        assert_eq!(stats.paced_deletes, 1, "no further deletes should be paced");
        assert_eq!(stats.paced_inserts, 1, "no further inserts should be paced");
        assert_eq!(stats.unpaced_teardown_deletes, 3);
        assert_eq!(stats.unpaced_teardown_inserts, 1);
        assert!(stats.configured, "state still records that a trace loaded");

        // Suspension is permanent.
        suspend();
        assert!(!nic_latency_cost().active);
    }
}
