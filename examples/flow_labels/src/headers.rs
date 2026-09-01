// Column contract for the label shards. The shards are written headerless; this
// one-line string is emitted to labels_header.txt so downstream readers can name
// the columns, and a change here propagates automatically.
//
// Field order MUST match csv_output::LabelRecord (serde serializes struct fields
// in declaration order).
use const_format::concatcp;

/// Final per-flow outcome columns.
pub const FINAL_HEADER: &str =
    "final_total_payload_bytes,final_duration_ms,final_total_pkts";

/// Full label row: identifying key + final outcome, newline-terminated.
pub const LABELS_HEADER: &str = concatcp!("conn_hash,first_seen_ts,", FINAL_HEADER, "\n");