// Single-stream writer: one per-core shard of label rows. This is the flow_collect
// writer with the depth split and the trace stream removed -- there is exactly one
// kind of row here (the per-flow label), so a core writes to exactly one file.
use crate::headers::LABELS_HEADER;
use csv::Writer;
use serde::Serialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex, OnceLock};
use iris_core::CoreId;
use iris_core::multicore::{ChannelDispatcher, ChannelMode, DedicatedWorkerThreadSpawner, DedicatedWorkerHandle};

const WRITE_BUF_CAP: usize = 1 << 20;
const CHANNEL_CAP: usize = 1 << 18;

/// zstd compression level for the on-disk shards. Level 3 sustains well over
/// 1GB/s/core, far ahead of the label row rate (one short row per flow), and the
/// text is highly repetitive decimal, so it compresses hard. Matters because
/// /mnt/netdata is CIFS over a 1G link: every byte written crosses the wire and is
/// read back across it. DuckDB / pandas read_csv both decompress .zst transparently.
const ZSTD_LEVEL: i32 = 3;

/// File extension for the shards (zstd-framed CSV).
const SHARD_EXT: &str = "csv.zst";

// Output root, configurable via the --out-dir CLI arg (preferred) or FLOW_OUT_DIR so
// runs can target separate trees without recompiling. Resolved once at first use and
// cached. A trailing '/' is ensured.
const DEFAULT_OUT_DIR: &str = "/mnt/netdata/";
const OUT_DIR_ENV: &str = "FLOW_OUT_DIR";
static OUT_DIR_CELL: OnceLock<String> = OnceLock::new();

/// Explicitly set the output root (from the --out-dir CLI arg). Must be called
/// BEFORE the first out_dir() read (i.e. before init_writer), since the value is
/// cached on first read. Takes precedence over FLOW_OUT_DIR and the default. No-op if
/// out_dir() has already been read -- so always call it first. Prefer this over
/// FLOW_OUT_DIR: it travels as a CLI arg and survives `sudo env`-style wrappers that
/// reset the environment.
pub fn set_out_dir(dir: &str) {
    let mut d = dir.to_string();
    if !d.ends_with('/') {
        d.push('/');
    }
    let _ = OUT_DIR_CELL.set(d);
}

/// Output root (always ends in '/'). All outputs -- the per-core label shards, the
/// header file, and the stats file -- live here. Precedence: set_out_dir() (--out-dir)
/// > FLOW_OUT_DIR env var > DEFAULT_OUT_DIR.
fn out_dir() -> &'static str {
    OUT_DIR_CELL.get_or_init(|| {
        let mut d = std::env::var(OUT_DIR_ENV).unwrap_or_else(|_| DEFAULT_OUT_DIR.to_string());
        if !d.ends_with('/') {
            d.push('/');
        }
        d
    })
}

// Per-core label shard basename: labels_core_{i}.csv.zst (under out_dir()).
const LABEL_PREFIX: &str = "labels_core_";
// Writer-dispatcher stats are also persisted here (under out_dir()).
const STATS_FILE: &str = "writer_stats.txt";
// One-line header file (column-name row, no data) that downstream readers use to
// name the columns of the headerless shards. Kept UNCOMPRESSED -- it's one line.
const LABEL_HEADER_FILE: &str = "labels_header.txt";

/// A zstd-compressing CSV sink. `auto_finish()` hands back a writer that emits the
/// zstd frame epilogue on Drop, so shards are valid archives without an explicit
/// finish() at shutdown -- the csv::Writer owns the encoder and is dropped when
/// Sinks is dropped.
type ZstdCsv = Writer<zstd::stream::AutoFinishEncoder<'static, BufWriter<File>>>;

/// Build a headerless, zstd-framed CSV writer at `path`.
fn zstd_csv_writer(path: &str) -> ZstdCsv {
    let file = File::create(path)
        .unwrap_or_else(|e| panic!("could not create shard {path}: {e}"));
    let buf = BufWriter::with_capacity(WRITE_BUF_CAP, file);
    let enc = zstd::stream::Encoder::new(buf, ZSTD_LEVEL)
        .unwrap_or_else(|e| panic!("could not init zstd encoder for {path}: {e}"))
        .auto_finish();
    csv::WriterBuilder::new().has_headers(false).from_writer(enc)
}

/// One per-flow label row: identifying key (conn_hash, first_seen_ts) + final
/// outcome. Field order MUST match LABELS_HEADER in headers.rs, since the shards
/// are written headerless and serde emits fields in declaration order.
#[derive(Clone, Debug, Serialize)]
pub struct LabelRecord {
    pub conn_hash: u64,                  // full-tuple u64 hash (1st half of the composite key)
    pub first_seen_ts: u64,              // connection first-seen wall clock, us (2nd half of the key)
    pub final_total_payload_bytes: u64,  // orig+resp payload bytes over the whole flow
    pub final_duration_ms: u64,          // first-to-last packet span (ms)
    pub final_total_pkts: u64,           // total packets over the whole flow
}

#[derive(Clone, Serialize)]
pub enum WriteEvent {
    /// A batch of terminated-flow label rows for one writer core.
    LabelBatch { rows: Vec<LabelRecord> },
}

/// Per-writer-thread sink: a single label shard. The core index is fixed per
/// thread, so no file is ever written by more than one thread (zero-contention).
struct Sinks {
    labels: ZstdCsv,
}

struct WriterPool {
    dispatchers: Vec<Arc<ChannelDispatcher<WriteEvent>>>,
    n: usize,
}

static POOL: OnceLock<WriterPool> = OnceLock::new();

/// Spin up one writer thread per core, each owning a single label shard.
pub fn init_writer(worker_cores: Vec<CoreId>) -> Vec<DedicatedWorkerHandle<WriteEvent>> {
    println!(
        "Writing output to {} (zstd level {ZSTD_LEVEL}, shards {LABEL_PREFIX}*.{SHARD_EXT})",
        out_dir(),
    );
    let mut dispatchers = Vec::with_capacity(worker_cores.len());
    let mut handles = Vec::with_capacity(worker_cores.len());
    for (i, core) in worker_cores.iter().enumerate() {
        let dispatcher = Arc::new(ChannelDispatcher::new(
            ChannelMode::Shared,
            CHANNEL_CAP,
            format!("flow_writer_{i}"),
        ));
        let sinks = Arc::new(Mutex::new(Sinks {
            labels: zstd_csv_writer(&format!("{}{LABEL_PREFIX}{i}.{SHARD_EXT}", out_dir())),
        }));
        let handle = DedicatedWorkerThreadSpawner::new()
            .set_cores(vec![*core])
            .set_dispatcher(dispatcher.clone())
            .set_handler(move |event: WriteEvent| {
                let mut s = sinks.lock().unwrap();
                match event {
                    WriteEvent::LabelBatch { rows } => {
                        for rec in &rows {
                            s.labels.serialize(rec).unwrap();
                        }
                    }
                }
            })
            .run();
        dispatchers.push(dispatcher);
        handles.push(handle);
    }
    let n = dispatchers.len();
    POOL.set(WriterPool { dispatchers, n }).ok();
    handles
}

pub fn shutdown_writer(handles: Vec<DedicatedWorkerHandle<WriteEvent>>) {
    if let Some(pool) = POOL.get() {
        for d in &pool.dispatchers {
            d.close_channels();
        }
    }
    // Each handle's shutdown drops that thread's Sinks, which drops the
    // csv::Writer -> AutoFinishEncoder, flushing the CSV buffer and writing the
    // zstd frame epilogue. Shards are only valid archives after this completes.
    for h in handles {
        let _ = h.shutdown(None);
    }
}

/// Print writer-dispatcher stats to stdout AND persist them to
/// {out_dir()}/writer_stats.txt so they survive after the console scrolls.
pub fn print_stats() {
    if let Some(pool) = POOL.get() {
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

/// Append a batch of per-flow label rows. Routed to a writer core by core id, so a
/// given core's rows always land in the same shard.
pub fn write_label_batch(rows: Vec<LabelRecord>, core: &CoreId) {
    if rows.is_empty() {
        return;
    }
    if let Some(pool) = POOL.get() {
        let idx = core.raw() as usize % pool.n;
        let _ = pool.dispatchers[idx].dispatch(
            WriteEvent::LabelBatch { rows },
            None,
        );
    }
}

/// Write the one-line header file naming the columns of the headerless shards.
/// LABELS_HEADER already ends in '\n' (see headers.rs), so the file is exactly the
/// column-name row and nothing else.
pub fn write_header_files() {
    let path = format!("{}{LABEL_HEADER_FILE}", out_dir());
    match File::create(&path) {
        Ok(f) => {
            let mut w = BufWriter::new(f);
            if let Err(e) = w.write_all(LABELS_HEADER.as_bytes()) {
                eprintln!("warning: failed writing header file {path}: {e}");
            } else if let Err(e) = w.flush() {
                eprintln!("warning: failed flushing header file {path}: {e}");
            } else {
                println!("Wrote header file {path}");
            }
        }
        Err(e) => eprintln!("warning: could not create header file {path}: {e}"),
    }
}