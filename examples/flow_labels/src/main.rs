// Minimal per-flow label collector. For EVERY terminated connection it emits a
// single row identifying the flow (conn_hash, first_seen_ts) plus its final
// outcome (total payload bytes, duration, total packets). No snapshots, no TLS
// features, no per-packet trace -- this is the smallest useful sibling of
// flow_collect, producing only the label columns.
//
// The composite key (conn_hash, first_seen_ts) matches flow_collect exactly, so
// these rows join 1:1 against that example's depth shards / trace if you ever run
// both against the same capture.
use clap::Parser;
use iris_core::{config::load_config, CoreId, Runtime, L4Pdu};
use iris_datatypes::{TlsHandshake, ConnRecord, connection::clock};
use iris_datatypes::conn_fts::InterArrivals;
use iris_compiler::*;
use std::path::PathBuf;
mod csv_output;
mod headers;
use csv_output::LabelRecord;
/// Flush granularity: buffer this many label rows per flow before handing them to
/// a writer core. In practice a flow emits exactly one row at termination, so this
/// only ever batches across the (rare) case of the same callback instance being
/// reused; kept for symmetry with flow_collect's batched writes.
const LABEL_BATCH_N: usize = 64;
const WRITER_CORES: &[u32] = &[24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46];
// ===== CLI =====
#[derive(Parser, Debug)]
struct Args {
    /// Path to the runtime config TOML (e.g. configs/online.toml).
    #[clap(short, long, value_parser, value_name = "FILE",
           default_value = "./configs/online.toml")]
    config: PathBuf,
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
/// Streaming callback scoped per connection by Iris. It does no per-packet work:
/// the InL4Conn callback exists only to register the subscription (the macro
/// requires an InL4Conn handler to bind this struct as the callback type), and it
/// simply stays subscribed. All real work happens at L4Terminated, where the
/// final outcome is read straight off `conn`. `batch` holds the one row until the
/// terminal flush, matching the shape flow_collect hands to the writer.
#[callback("tls,level=InL4Conn")]
#[derive(Debug)]
struct LabelSweep {
    /// Buffered label rows, flushed at termination. Normally holds exactly one.
    batch: Vec<LabelRecord>,
}
impl StreamingCallback for LabelSweep {
    fn new(_first_pkt: &L4Pdu) -> LabelSweep {
        LabelSweep {
            batch: Vec::with_capacity(1),
        }
    }
    fn clear(&mut self) {
        self.batch = Vec::with_capacity(0);
    }
}
impl LabelSweep {
    /// Per-packet callback. Does nothing but stay subscribed: this example needs
    /// no prefix snapshots, so there is no work to do until termination. It exists
    /// because the callback macro requires an InL4Conn handler to bind LabelSweep
    /// as the callback type (an L4Terminated handler alone leaves the struct
    /// unbound). Signature matches flow_collect's InL4Conn callback; the args are
    /// unused here.
    #[callback_fn("LabelSweep,level=InL4Conn")]
    fn on_packet(&mut self, _conn: &ConnRecord, _iat: &InterArrivals, _tls: &TlsHandshake, _core_id: &CoreId) -> bool {
        // Stay subscribed to termination; nothing to collect per packet.
        true
    }
    /// Terminal callback: build the one label row for this flow and flush it.
    ///
    /// conn_hash and first_seen_ts are the identifying key; the final_* fields are
    /// the outcome. Everything is read from `conn`, so no per-packet state is kept.
    #[callback_fn("LabelSweep,level=L4Terminated")]
    fn on_terminate(&mut self, conn: &ConnRecord, core_id: &CoreId) -> bool {
        let first_seen_ts = conn.first_seen_epoch_micros();
        self.batch.push(LabelRecord {
            conn_hash: conn.five_tuple.conn_hash(),
            first_seen_ts,
            final_total_payload_bytes: conn.total_payload_bytes(),
            final_duration_ms: conn.duration().as_millis() as u64,
            final_total_pkts: conn.total_pkts(),
        });
        // One row per flow, so this flushes immediately; the >= keeps it correct if
        // a callback instance is ever reused for multiple terminations.
        if self.batch.len() >= LABEL_BATCH_N || !self.batch.is_empty() {
            csv_output::write_label_batch(
                std::mem::take(&mut self.batch),
                core_id,
            );
        }
        true
    }
}
#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    let _ = clock();
    let args = Args::parse();
    if args.show_args {
        println!("{args:#?}");
    }
    let config_path = args.config.to_str().expect("Invalid config path");
    println!("Loading config from {config_path}");
    // Resolve the output root BEFORE init_writer. Precedence: --out-dir >
    // FLOW_OUT_DIR > default. Must happen before any out_dir() read (init_writer is
    // the first), since it caches on first read.
    if let Some(dir) = args.out_dir.as_ref() {
        let s = dir.to_str().expect("--out-dir is not valid UTF-8");
        csv_output::set_out_dir(s);
    }
    let config = load_config(config_path);
    let writer_handles = csv_output::init_writer(
        WRITER_CORES.iter().map(|&c| CoreId(c)).collect(),
    );
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    csv_output::shutdown_writer(writer_handles);
    csv_output::print_stats();
    csv_output::write_header_files();
}