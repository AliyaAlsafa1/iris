// examples/flow_collect/src/csv_output.rs
//
// Output sink. Rewritten to emit per-core **Parquet** shards instead of
// zstd-framed CSV. The sharding, dispatch, and per-flow buffering model are
// unchanged; only the on-disk encoding changed:
//
//   depth_{N}_core_{i}.parquet          (stream 1, one file per (depth, core))
//   flow_features_tls_trace_{i}.parquet  (stream 2, one file per core)
//
// Why Parquet is structurally different from the old CSV path, and what that
// forces here:
//
//   * CSV was row-streamed: csv::Writer::serialize() wrote one row immediately,
//     inside a zstd frame that finalized on Drop. Parquet is columnar and
//     block-structured -- rows are accumulated into an in-memory column buffer
//     and emitted as compressed row groups. There is no "append one row to a
//     .parquet on disk" primitive.
//   * Because stream 2 is UNCAPPED (per packet, to termination), we must NOT
//     hold the whole file in memory. Each dispatched batch is turned into an
//     Arrow RecordBatch and handed to ArrowWriter::write(); the writer flushes
//     row groups as they fill, keeping memory bounded regardless of flow length.
//   * The Parquet footer (schema + row-group index) is written ONLY by an
//     explicit close(). Unlike the old AutoFinishEncoder, dropping an
//     ArrowWriter does NOT produce a valid file. shutdown_writer() therefore
//     closes every open writer; a writer left unclosed yields a truncated,
//     unreadable shard. Nothing downstream may read a shard before shutdown
//     returns.
//
// The column contract now lives in the Parquet footer schema (built in
// `schema.rs`), so the old one-line *_header.txt files and write_header_files()
// are gone: to_parquet.py reads column names from the Parquet metadata itself.
// serde Serialize is no longer used for output; fields are copied into typed
// Arrow builders in declaration order (the same order that used to keep the CSV
// columns aligned with TLS_CONN_HEADER).

use flow_features::conn_features::ConnFeatures;
use flow_features::tls_features::TlsFeatures;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex, OnceLock};

use arrow::array::{ArrayRef, RecordBatch};
use arrow::datatypes::Schema;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::{WriterProperties, WriterVersion};

use iris_core::CoreId;
use iris_core::multicore::{ChannelDispatcher, ChannelMode, DedicatedWorkerThreadSpawner, DedicatedWorkerHandle};

use crate::builders::{FlowColumns, TraceColumns};

const CHANNEL_CAP: usize = 1 << 18;

/// Target row-group size (in rows) for the ArrowWriter. The writer buffers rows
/// and cuts a compressed row group once this many have accumulated, so this is
/// the knob that bounds writer memory on the UNCAPPED stream-2 trace: at most
/// ~this many TraceRecords per core are held before a group is flushed to disk.
/// 128Ki rows of the narrow (4 x u64) trace schema is a few MB per core in
/// flight -- far below the old WRITE_BUF_CAP-era footprint -- while staying large
/// enough that zstd sees long runs of the repetitive decimal-free integer
/// columns and dictionary/RLE encoding does its job.
const MAX_ROW_GROUP_ROWS: usize = 1 << 17;

/// zstd compression level for the Parquet column chunks. Kept at 3, matching the
/// old CSV-frame level: 1-3 sustains well over 1GB/s/core, so the 23 writer cores
/// stay far ahead of the capture. Parquet's per-column dictionary + RLE encoding
/// applied BEFORE zstd typically beats the old row-oriented CSV+zstd on this data
/// (the trace's four integer columns compress especially well column-wise), so
/// on-disk size holds or improves. That still matters because /mnt/netdata is
/// CIFS over a 1G link: every byte written crosses the wire, and every byte is
/// read back across it by to_parquet.py. DuckDB's read_parquet and pandas'
/// read_parquet replace the old read_csv; nothing else downstream changes except
/// the glob (*.parquet) and that column names now come from the file schema.
const ZSTD_LEVEL: i32 = 3;

/// File extension for the shards. Both streams are now Parquet.
const SHARD_EXT: &str = "parquet";

// Output root. Configurable via the --out-dir CLI arg (preferred) or the
// FLOW_OUT_DIR env var so the train and test captures can be written to separate
// trees without recompiling. Resolved once at first use and cached; a trailing '/'
// is ensured.
const DEFAULT_OUT_DIR: &str = "/mnt/netdata/";
const OUT_DIR_ENV: &str = "FLOW_OUT_DIR";
static OUT_DIR_CELL: OnceLock<String> = OnceLock::new();

/// Explicitly set the output root (from the --out-dir CLI arg). Must be called
/// BEFORE the first out_dir() read (i.e. before init_writer), since the value is
/// cached on first read. A trailing '/' is ensured. Takes precedence over
/// FLOW_OUT_DIR and the built-in default. If out_dir() has already been read, this
/// is a no-op (the earlier value wins) -- so always call it first.
///
/// Prefer this over FLOW_OUT_DIR: it travels as a CLI argument, so it survives
/// wrappers that reset the environment (e.g. `sudo env ...`), whereas the env var is
/// silently dropped by them and the collector falls back to the default.
pub fn set_out_dir(dir: &str) {
    let mut d = dir.to_string();
    if !d.ends_with('/') {
        d.push('/');
    }
    let _ = OUT_DIR_CELL.set(d);
}

/// Output root (always ends in '/'). All outputs -- the per-(depth,core) shards,
/// the per-core trace shards, and the stats file -- live here.
/// Precedence: set_out_dir() (--out-dir) > FLOW_OUT_DIR env var > DEFAULT_OUT_DIR.
fn out_dir() -> &'static str {
    OUT_DIR_CELL.get_or_init(|| {
        let mut d = std::env::var(OUT_DIR_ENV).unwrap_or_else(|_| DEFAULT_OUT_DIR.to_string());
        if !d.ends_with('/') {
            d.push('/');
        }
        d
    })
}

// Stream-1 per-(depth,core) shard basename: depth_{N}_core_{i}.parquet (under out_dir())
const DEPTH_PREFIX: &str = "depth_";
// Stream-2 per-core trace basename: flow_features_tls_trace_{i}.parquet (under out_dir())
const TRACE_PREFIX: &str = "flow_features_tls_trace_";
// Writer-dispatcher stats are also persisted here (under out_dir()).
const STATS_FILE: &str = "writer_stats.txt";

/// A Parquet sink over a plain File. `arrow`'s ArrowWriter buffers rows and cuts
/// zstd-compressed row groups at MAX_ROW_GROUP_ROWS; the footer is written by an
/// explicit close() (NOT on Drop), so every one of these must be closed at
/// shutdown or its shard is truncated and unreadable.
type ParquetSink = ArrowWriter<File>;

/// Shared WriterProperties for every shard: zstd(level), capped row-group size,
/// and Parquet v2 pages (better encodings for the integer-heavy columns here).
fn writer_props() -> WriterProperties {
    WriterProperties::builder()
        .set_compression(Compression::ZSTD(
            ZstdLevel::try_new(ZSTD_LEVEL).expect("valid zstd level"),
        ))
        .set_max_row_group_size(MAX_ROW_GROUP_ROWS)
        .set_writer_version(WriterVersion::PARQUET_2_0)
        .build()
}

/// Build a Parquet writer at `path` for the given schema.
fn parquet_writer(path: &str, schema: Arc<Schema>) -> ParquetSink {
    let file = File::create(path)
        .unwrap_or_else(|e| panic!("could not create shard {path}: {e}"));
    ArrowWriter::try_new(file, schema, Some(writer_props()))
        .unwrap_or_else(|e| panic!("could not init parquet writer for {path}: {e}"))
}

/// Final per-connection outcome, backfilled at termination and written as the
/// LAST columns of a stream-1 row so the on-disk column order matches the old
/// (CONN, TLS, FINAL) contract. No longer serde-serialized -- the fields are
/// appended to the stream-1 Arrow builders after the conn and tls blocks.
#[derive(Clone, Debug, Serialize)]
pub struct FinalLabel {
    pub final_total_payload_bytes: u64,
    pub final_duration_ms: u64,
    pub final_total_pkts: u64,
}

/// One buffered stream-1 snapshot: conn features (carrying pkt_snapshot = depth)
/// + a shared handle to the flow's TLS features. Final label applied at flush.
#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub conn: ConnFeatures,
    pub tls: Arc<TlsFeatures>,
}

/// One stream-2 trace record: cumulative payload bytes for a flow at the
/// wall-clock arrival time of a single packet. Emitted every packet when --trace.
#[derive(Clone, Debug, Serialize)]
pub struct TraceRecord {
    pub conn_hash: u64,         // full-tuple u64 hash (1st half of the composite connection key)
    pub first_seen_ts: u64,     // connection first-seen wall clock, us (2nd half of the key)
    pub snapshot_ts: u64,       // microseconds since UNIX_EPOCH (per-packet arrival)
    pub cumulative_bytes: u64,  // running orig+resp payload bytes through this packet
}

#[derive(Clone, Serialize)]
pub enum WriteEvent {
    /// A terminated flow's buffered stream-1 snapshots plus its final label. Each
    /// snapshot is routed to its depth file (by conn.pkt_snapshot) and written
    /// conn + tls + final so columns align with the schema.
    FlowBatch { snaps: Vec<Snapshot>, label: FinalLabel },
    /// Stream-2 per-packet trace records (per-core, no depth split). Never
    /// dispatched under --no-trace.
    TraceBatch { rows: Vec<TraceRecord> },
}

/// Per-writer-thread sinks. `depth_writers` is created lazily per depth so we
/// only open files for depths this core actually observes; the core index is
/// fixed per thread, so no file is ever written by more than one thread (the A1
/// zero-contention property).
struct Sinks {
    core_idx: usize,
    depth_writers: HashMap<u64, ParquetSink>,
    /// None under --no-trace: the per-core trace shard is never created, so the
    /// output dir carries no empty trace files to confuse to_parquet.py's glob.
    trace: Option<ParquetSink>,
}

impl Sinks {
    /// Get (creating if needed) the stream-1 writer for `depth` on this core.
    fn depth_writer(&mut self, depth: u64) -> &mut ParquetSink {
        let core_idx = self.core_idx;
        self.depth_writers.entry(depth).or_insert_with(|| {
            let path = format!("{}{DEPTH_PREFIX}{depth}_core_{core_idx}.{SHARD_EXT}", out_dir());
            parquet_writer(&path, crate::schema::flow_schema())
        })
    }

    /// Close every open writer on this core, writing each Parquet footer. Called
    /// once, from the worker thread's Drop path via close_all(). Idempotent-safe:
    /// the maps are drained so a second call is a no-op.
    fn close_all(&mut self) {
        for (depth, w) in self.depth_writers.drain() {
            if let Err(e) = w.close() {
                eprintln!("warning: failed closing depth {depth} shard on core {}: {e}", self.core_idx);
            }
        }
        if let Some(w) = self.trace.take() {
            if let Err(e) = w.close() {
                eprintln!("warning: failed closing trace shard on core {}: {e}", self.core_idx);
            }
        }
    }
}

struct WriterPool {
    dispatchers: Vec<Arc<ChannelDispatcher<WriteEvent>>>,
    /// One handle per core to the Sinks it owns, so shutdown can close writers
    /// (write footers) after the channels drain. Kept behind the same Mutex the
    /// handler locks, so close happens strictly after the last handled event.
    sinks: Vec<Arc<Mutex<Sinks>>>,
    n: usize,
}

static POOL: OnceLock<WriterPool> = OnceLock::new();

/// Spin up one writer thread per core. `trace` mirrors main()'s --trace: when
/// false, no per-core trace shard is opened and TraceBatch events are never sent.
pub fn init_writer(worker_cores: Vec<CoreId>, trace: bool) -> Vec<DedicatedWorkerHandle<WriteEvent>> {
    // Output root resolved here (from --out-dir, FLOW_OUT_DIR, or the default),
    // assumed to already exist on disk.
    println!(
        "Writing output to {} (parquet, zstd level {ZSTD_LEVEL}, row-group {MAX_ROW_GROUP_ROWS} rows, shards *.{SHARD_EXT}, trace {})",
        out_dir(),
        if trace { "on" } else { "off" }
    );
    let mut dispatchers = Vec::with_capacity(worker_cores.len());
    let mut sinks_vec = Vec::with_capacity(worker_cores.len());
    let mut handles = Vec::with_capacity(worker_cores.len());
    for (i, core) in worker_cores.iter().enumerate() {
        let dispatcher = Arc::new(ChannelDispatcher::new(
            ChannelMode::Shared,
            CHANNEL_CAP,
            format!("flow_writer_{i}"),
        ));
        let sinks = Arc::new(Mutex::new(Sinks {
            core_idx: i,
            depth_writers: HashMap::new(),
            trace: if trace {
                Some(parquet_writer(
                    &format!("{}{TRACE_PREFIX}{i}.{SHARD_EXT}", out_dir()),
                    crate::schema::trace_schema(),
                ))
            } else {
                None
            },
        }));
        let handler_sinks = sinks.clone();
        let handle = DedicatedWorkerThreadSpawner::new()
            .set_cores(vec![*core])
            .set_dispatcher(dispatcher.clone())
            .set_handler(move |event: WriteEvent| {
                let mut s = handler_sinks.lock().unwrap();
                match event {
                    WriteEvent::FlowBatch { snaps, label } => {
                        // Group this terminated flow's snapshots by depth, then
                        // write each depth's rows as one RecordBatch into that
                        // depth's shard. A flow contributes at most one row per
                        // depth, so these batches are tiny; the ArrowWriter
                        // coalesces them into full row groups across many flows.
                        let mut by_depth: HashMap<u64, Vec<&Snapshot>> = HashMap::new();
                        for snap in &snaps {
                            by_depth.entry(snap.conn.pkt_snapshot).or_default().push(snap);
                        }
                        for (depth, group) in by_depth {
                            let batch = FlowColumns::build(&group, &label);
                            if let Err(e) = s.depth_writer(depth).write(&batch) {
                                eprintln!("warning: failed writing depth {depth} batch: {e}");
                            }
                        }
                    }
                    WriteEvent::TraceBatch { rows } => {
                        // Unreachable under --no-trace (the packet path never
                        // builds a TraceBatch), but drop rather than panic if a
                        // stray event ever arrives -- losing trace rows on a run
                        // that asked for no trace is not an error worth aborting a
                        // multi-hour capture over.
                        if let Some(w) = s.trace.as_mut() {
                            let batch = TraceColumns::build(&rows);
                            if let Err(e) = w.write(&batch) {
                                eprintln!("warning: failed writing trace batch: {e}");
                            }
                        }
                    }
                }
            })
            .run();
        dispatchers.push(dispatcher);
        sinks_vec.push(sinks);
        handles.push(handle);
    }
    let n = dispatchers.len();
    POOL.set(WriterPool { dispatchers, sinks: sinks_vec, n }).ok();
    handles
}

pub fn shutdown_writer(handles: Vec<DedicatedWorkerHandle<WriteEvent>>) {
    if let Some(pool) = POOL.get() {
        for d in &pool.dispatchers {
            d.close_channels();
        }
    }
    // Drain the worker threads first: after each handle's shutdown returns, that
    // thread has processed its last event and will touch its Sinks no more.
    for h in handles {
        let _ = h.shutdown(None);
    }
    // Now write every Parquet footer. This is REQUIRED and has no CSV analogue:
    // the old AutoFinishEncoder finalized on Drop, but ArrowWriter does not --
    // dropping it would leave every shard truncated and unreadable. We close here,
    // after the threads are joined, so no handler can be mid-write. Nothing
    // downstream may read a shard until this returns.
    if let Some(pool) = POOL.get() {
        for sinks in &pool.sinks {
            sinks.lock().unwrap().close_all();
        }
    }
}

/// Print writer-dispatcher stats to stdout AND persist them to
/// {out_dir()}/writer_stats.txt so they survive after the console scrolls.
pub fn print_stats() {
    if let Some(pool) = POOL.get() {
        // Build the full report once, then emit to both stdout and the file.
        let mut report = String::new();
        report.push_str("=== Writer Dispatcher Stats ===\n");
        for (i, d) in pool.dispatchers.iter().enumerate() {
            report.push_str(&format!("[writer {i}]\n"));
            report.push_str(&format!("{}\n", d.stats()));
        }
        print!("{report}");
        let path = format!("{}{STATS_FILE}", out_dir());
        match File::create(&path) {
            Ok(f) => {
                let mut w = BufWriter::new(f);
                if let Err(e) = w.write_all(report.as_bytes()) {
                    eprintln!("warning: failed writing stats to {path}: {e}");
                } else {
                    println!("Wrote writer stats to {path}");
                }
            }
            Err(e) => eprintln!("warning: could not create stats file {path}: {e}"),
        }
    }
}

/// Flush a terminated flow's buffered stream-1 snapshots with its final label.
pub fn write_flow_batch(snaps: Vec<Snapshot>, label: FinalLabel, core: &CoreId) {
    if snaps.is_empty() {
        return;
    }
    if let Some(pool) = POOL.get() {
        let idx = core.raw() as usize % pool.n;
        let _ = pool.dispatchers[idx].dispatch(
            WriteEvent::FlowBatch { snaps, label },
            None,
        );
    }
}

/// Append a batch of stream-2 per-packet trace records. Callers gate on
/// trace_enabled(), so this is never reached under --no-trace.
pub fn write_trace_batch(rows: Vec<TraceRecord>, core: &CoreId) {
    if rows.is_empty() {
        return;
    }
    if let Some(pool) = POOL.get() {
        let idx = core.raw() as usize % pool.n;
        let _ = pool.dispatchers[idx].dispatch(
            WriteEvent::TraceBatch { rows },
            None,
        );
    }
}