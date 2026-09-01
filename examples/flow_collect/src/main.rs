// examples/flow_collect/src/main.rs
use clap::Parser;
use iris_core::{config::load_config, CoreId, Runtime, L4Pdu};
use iris_datatypes::{TlsHandshake, ConnRecord};
use iris_datatypes::conn_fts::InterArrivals;
use iris_compiler::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use flow_features::conn_features::{ConnFeatures, ConnInvariants};
use flow_features::tls_features::TlsFeatures;

mod csv_output;
mod schema;
mod builders;

use csv_output::{FinalLabel, Snapshot, TraceRecord};

/// Snapshot depths: buffer a stream-1 prefix row ONLY when the live packet count
/// crosses one of these exact depths. Previously this was every packet from 1 to
/// 200 (SNAPSHOT_STEP=1, SNAPSHOT_MAX=200), which wrote ~613GB per capture of
/// which ~87% was never read: classifier.py trains on 5,10,20,40,80 and needs
/// depth 1 for the global elephant threshold. Restricting to the depths actually
/// consumed cuts stream 1 to ~78GB with no downstream change (to_parquet.py's
/// discover_depths just finds fewer files).
///
/// This list is the ONLY bound on stream 1: the per-flow cursor (next_depth_i)
/// saturates at its length, so the deepest entry is implicitly the old
/// SNAPSHOT_MAX. Stream 2, when enabled, is UNCAPPED and runs to termination.
///
/// MUST stay sorted ascending, and MUST include 1: classifier.py's
/// train_threshold() reads depth_1.parquet to define the elephant cutoff over the
/// complete flow population (every flow has >=1 packet, exactly one row each).
/// Add depths here if you want to sweep more; there is no cost to depths you
/// don't collect other than not having them.
const SNAPSHOT_DEPTHS: &[u64] = &[1, 5, 10, 20, 40, 80];
/// Stream-2 trace flush granularity (one record per packet -> flush a bit larger).
const TRACE_BATCH_N: usize = 64;
const WRITER_CORES: &[u32] = &[24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46];
/// Whether stream 2 (the per-packet A_i(t) trace) is collected at all. Set once in
/// main() from --trace before the runtime starts, then read-only for the process
/// lifetime, so the per-packet load is an uncontended relaxed read of a cache-hot
/// line -- negligible next to the work it gates.
///
/// WHY this is a flag: the trace exists solely so bandwidth_sim.py can integrate
/// Z(O) = sum A_i(b) - A_i(a) over residency intervals, and the sim runs against
/// the TEST capture only. classifier.py trains from the depth shards alone and
/// never opens the trace. So the train capture writes ~400GB of per-packet records
/// that nothing reads -- across a 1G CIFS link, twice (once written, once read by
/// to_parquet.py). Disabling stream 2 on the train run removes that entirely.
static TRACE_ENABLED: AtomicBool = AtomicBool::new(true);
#[inline(always)]
fn trace_enabled() -> bool {
    TRACE_ENABLED.load(Ordering::Relaxed)
}
// ===== CLI =====
#[derive(Parser, Debug)]
struct Args {
    /// Path to the runtime config TOML (e.g. configs/online-train.toml).
    #[clap(short, long, value_parser, value_name = "FILE",
           default_value = "./configs/online.toml")]
    config: PathBuf,
    /// Collect stream 2, the per-packet cumulative-bytes trace (A_i(t)).
    ///
    /// Needed ONLY by bandwidth_sim.py, which runs on the test capture. The train
    /// capture feeds classifier.py, which reads the depth shards only -- so run
    /// train with --no-trace and test with --trace.
    ///
    /// Defaults ON so an unflagged run stays backward-compatible with the old
    /// always-collect behavior. Pass --trace=false to disable (the = form is
    /// required: `--trace false` misparses and leaves the trace ON).
    #[clap(long, action = clap::ArgAction::Set, default_value_t = true,
           num_args = 0..=1, default_missing_value = "true")]
    trace: bool,
    /// Output root for all shards and stats. Takes precedence over the FLOW_OUT_DIR
    /// env var, which takes precedence over the built-in default (/mnt/netdata/).
    ///
    /// Prefer this flag over FLOW_OUT_DIR: it travels as an argument, so it survives
    /// wrappers that reset the environment (e.g. `sudo env ...`), whereas the env var
    /// is silently dropped by them and the collector falls back to the default.
    #[clap(long, value_parser, value_name = "DIR")]
    out_dir: Option<PathBuf>,
    /// Print parsed args and exit-adjacent debug info.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    show_args: bool,
}
/// Wall-clock arrival time (microseconds since UNIX_EPOCH) of the latest packet,
/// on the same monotonic-derived clock as the composite key: take the flow's
/// monotonic first-packet epoch-micros and add the Instant-delta between the first
/// and latest packet (Instants have no epoch on their own). Keeps stream 1 and
/// stream 2 sharing one clock, now anchored so timestamps never step backward
/// under NTP correction.
#[inline]
fn packet_wall_ts_us(conn: &ConnRecord) -> u64 {
    let delta_us = (conn.last_seen_ts - conn.first_seen_ts).as_micros() as u64;
    conn.first_seen_epoch_micros() + delta_us
}
/// Streaming callback: appends a stream-2 trace record (conn_hash, first_seen_ts, snapshot_ts,
/// cumulative payload bytes) for EVERY packet when --trace is on, and BUFFERS
/// stream-1 (conn, tls) snapshots at the depths in SNAPSHOT_DEPTHS. On termination
/// the final_* label is known, so it is backfilled once and every buffered snapshot
/// is flushed as a complete conn+tls+final row. One instance is scoped per
/// connection by Iris, so `snapshots` IS the per-flow buffer.
#[callback("tls,level=InL4Conn")]
#[derive(Debug)]
struct PrefixSweep {
    /// Buffered stream-1 snapshots (conn features + shared TLS handle).
    /// At most SNAPSHOT_DEPTHS.len() entries.
    snapshots: Vec<Snapshot>,
    /// Index into SNAPSHOT_DEPTHS of the next depth to emit. Monotone, so the
    /// per-packet check is a single compare against SNAPSHOT_DEPTHS[next_depth_i]
    /// rather than a scan -- line-rate safe. Saturating at SNAPSHOT_DEPTHS.len()
    /// is what caps stream 1; there is no separate max constant.
    next_depth_i: usize,
    /// TLS handshake features, computed once and reused (immutable post-handshake).
    tls: Option<std::sync::Arc<TlsFeatures>>,
    /// Per-connection invariant features, computed once on first packet.
    inv: Option<ConnInvariants>,
    /// Buffered stream-2 trace records, flushed in batches. Stays empty (and never
    /// allocates) when --no-trace.
    trace_batch: Vec<TraceRecord>,
    /// (conn_hash, first_seen_ts) cached once, so the trace path works before inv/tls are set.
    /// Single source of truth for the composite key shared by both streams.
    key: Option<(u64, u64)>,
}
impl StreamingCallback for PrefixSweep {
    fn new(_first_pkt: &L4Pdu) -> PrefixSweep {
        PrefixSweep {
            snapshots: Vec::with_capacity(SNAPSHOT_DEPTHS.len()),
            next_depth_i: 0,
            tls: None,
            inv: None,
            // Don't reserve the trace batch when stream 2 is off: this allocation
            // happens once per CONNECTION, so at connection rates it is worth
            // skipping rather than holding TRACE_BATCH_N slots that never fill.
            trace_batch: if trace_enabled() {
                Vec::with_capacity(TRACE_BATCH_N)
            } else {
                Vec::new()
            },
            key: None,
        }
    }
    fn clear(&mut self) {
        self.snapshots = Vec::with_capacity(0);
        self.trace_batch = Vec::with_capacity(0);
    }
}
impl PrefixSweep {
    /// Compute-or-return the cached composite key (conn_hash, first_seen_ts).
    /// Both are stable for the connection's life, so this is computed once and
    /// reused by both streams (line-rate safe).
    #[inline]
    fn conn_key(&mut self, conn: &ConnRecord) -> (u64, u64) {
        *self.key.get_or_insert_with(|| {
            (conn.five_tuple.conn_hash(), conn.first_seen_epoch_micros())
        })
    }
    #[callback_fn("PrefixSweep,level=InL4Conn")]
    fn on_packet(&mut self, conn: &ConnRecord, iat: &InterArrivals, tls: &TlsHandshake, core_id: &CoreId) -> bool {
        let total = conn.total_pkts();
        // --- Stream 2: per-packet byte/time trace (UNCAPPED, --trace only) --
        // When enabled, ALWAYS append, BEFORE the TLS gate below, for EVERY packet
        // of the ENTIRE connection -- no depth cap. A_i(t) must be complete to
        // termination so the sim can integrate Z(O) = sum A_i(b) - A_i(a) over the
        // full residency, including the long tails of elephant flows that run well
        // past stream 1's deepest snapshot. Includes pre-handshake packets, ACKs,
        // and flows that never present a ClientHello/ServerHello.
        if trace_enabled() {
            let (conn_hash, first_seen_ts) = self.conn_key(conn);
            self.trace_batch.push(TraceRecord {
                conn_hash,
                first_seen_ts,
                snapshot_ts: packet_wall_ts_us(conn),
                cumulative_bytes: conn.total_payload_bytes(),
            });
            if self.trace_batch.len() >= TRACE_BATCH_N {
                csv_output::write_trace_batch(
                    std::mem::replace(&mut self.trace_batch, Vec::with_capacity(TRACE_BATCH_N)),
                    core_id,
                );
            }
        }
        // --- Stream 1: buffer full feature snapshots (gated on TLS presence) -
        if self.tls.is_none() {
            self.tls = TlsFeatures::from_tls(tls).map(std::sync::Arc::new);
        }
        // If the handshake yielded no features it never will (immutable), so
        // stream 1 has nothing further to buffer for this flow. We still stay
        // subscribed to termination: on_terminate must run to flush any already
        // buffered snapshots (and, under --trace, trailing trace records). Under
        // --no-trace this flow simply idles until L4Terminated.
        let Some(tls_features) = self.tls.as_ref() else {
            return true;
        };
        // Fast path: every depth already emitted -- this flow is past the deepest
        // entry in SNAPSHOT_DEPTHS. Stream 1 has nothing left to buffer, but we
        // stay subscribed so on_terminate flushes the buffered snapshots with their
        // final label. (Under --trace the same subscription also keeps stream 2's
        // per-packet trace flowing to termination.)
        if self.next_depth_i >= SNAPSHOT_DEPTHS.len() {
            return true;
        }
        // Fast path: haven't reached the next depth of interest yet. This is the
        // common case now that depths are sparse -- one compare, no work.
        if total < SNAPSHOT_DEPTHS[self.next_depth_i] {
            return true;
        }
        let tls_arc = std::sync::Arc::clone(tls_features);
        let (conn_hash, first_seen_ts) = self.conn_key(conn);
        let inv = self.inv.get_or_insert_with(|| {
            ConnInvariants::from_conn(conn, conn_hash, first_seen_ts)
        });
        // Emit every not-yet-emitted depth at or below `total`. The while loop (vs
        // a single emit) covers BATCHED delivery: total can jump by more than one
        // between callbacks and could skip past several depths at once. Advancing
        // next_depth_i past any depth <= total keeps each depth emitted at most
        // once, matching the old last_emitted semantics.
        while self.next_depth_i < SNAPSHOT_DEPTHS.len()
            && SNAPSHOT_DEPTHS[self.next_depth_i] <= total
        {
            let bucket = SNAPSHOT_DEPTHS[self.next_depth_i];
            if let Some(cf) = ConnFeatures::from_conn_at(conn, iat, bucket, inv) {
                self.snapshots.push(Snapshot {
                    conn: cf,
                    tls: std::sync::Arc::clone(&tls_arc),
                });
            }
            self.next_depth_i += 1;
        }
        // Stay subscribed to termination unconditionally. on_terminate is where the
        // final label is backfilled into the buffered stream-1 snapshots and they
        // are flushed as complete rows -- unsubscribing before then would truncate
        // the flow and drop everything buffered here. (Under --trace this also keeps
        // stream 2's per-packet trace flowing to the end, which it requires anyway.)
        true
    }
    #[callback_fn("PrefixSweep,level=L4Terminated")]
    fn on_terminate(&mut self, conn: &ConnRecord, core_id: &CoreId) -> bool {
        // Flush trailing stream-2 trace records unconditionally (independent of
        // TLS state -- a flow with buffered trace rows but no TLS features must
        // still have them written). Empty under --no-trace, so this is a no-op.
        if !self.trace_batch.is_empty() {
            csv_output::write_trace_batch(
                std::mem::take(&mut self.trace_batch),
                core_id,
            );
        }
        // Backfill the now-known final label into every buffered stream-1 snapshot
        // and flush them as complete conn+tls+final rows.
        if !self.snapshots.is_empty() {
            let label = FinalLabel {
                final_total_payload_bytes: conn.total_payload_bytes(),
                final_duration_ms: conn.duration().as_millis() as u64,
                final_total_pkts: conn.total_pkts(),
            };
            csv_output::write_flow_batch(
                std::mem::take(&mut self.snapshots),
                label,
                core_id,
            );
        }
        true
    }
}
#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    // Parse CLI args (config path selectable per train/test run).
    let args = Args::parse();
    if args.show_args {
        println!("{args:#?}");
    }
    let config_path = args.config.to_str().expect("Invalid config path");
    println!("Loading config from {config_path}");
    // Publish the trace decision BEFORE any writer or runtime thread exists, so
    // every subsequent read (all on the packet path) sees the final value and no
    // synchronization beyond Relaxed is needed.
    TRACE_ENABLED.store(args.trace, Ordering::Relaxed);
    // Surface the collection plan up front: the depths collected here are the ONLY
    // depths available to classifier.py / bandwidth_sim.py downstream.
    println!("Stream-1 snapshot depths: {SNAPSHOT_DEPTHS:?}");
    println!(
        "Stream-2 per-packet trace: {}",
        if args.trace {
            "ENABLED (bandwidth_sim.py can run against this capture)"
        } else {
            "DISABLED (--no-trace; classifier.py only -- bandwidth_sim.py CANNOT run against this capture)"
        }
    );
    debug_assert!(
        !SNAPSHOT_DEPTHS.is_empty(),
        "SNAPSHOT_DEPTHS must not be empty"
    );
    debug_assert!(
        SNAPSHOT_DEPTHS.windows(2).all(|w| w[0] < w[1]),
        "SNAPSHOT_DEPTHS must be strictly ascending"
    );
    debug_assert!(
        SNAPSHOT_DEPTHS.first() == Some(&1),
        "SNAPSHOT_DEPTHS must include depth 1 (classifier.py's global elephant threshold)"
    );
    // Resolve the output root BEFORE init_writer, so the writer banner and every
    // sink path reflect it. Precedence: --out-dir > FLOW_OUT_DIR > default. This
    // must happen before any out_dir() read (init_writer is the first), since that
    // value is cached on first read.
    if let Some(dir) = args.out_dir.as_ref() {
        let s = dir.to_str().expect("--out-dir is not valid UTF-8");
        csv_output::set_out_dir(s);
    }
    let config = load_config(config_path);
    let writer_handles = csv_output::init_writer(
        WRITER_CORES.iter().map(|&c| CoreId(c)).collect(),
        args.trace,
    );
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    csv_output::shutdown_writer(writer_handles);
    csv_output::print_stats();
}