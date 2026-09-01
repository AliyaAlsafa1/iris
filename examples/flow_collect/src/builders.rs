// examples/flow_collect/src/csv_output/builders.rs
//
// Row->column conversion. This is the code that used to be a single
// csv::Writer::serialize((&conn, &tls, &label)) call and is now explicit,
// because Arrow has no serde-style struct flattening: every field must be pushed
// into a typed column builder by hand, in the SAME order as schema.rs (and thus
// the same order the old CSV columns appeared). Add/reorder a field in
// flow_features and you must mirror it in BOTH this file and schema.rs.
//
// Each `build` produces one Arrow RecordBatch from a slice of rows. The
// ArrowWriter coalesces successive batches into row groups, so it is fine (and
// expected) for these batches to be small -- a terminated flow contributes only
// a handful of stream-1 rows, and a trace batch is TRACE_BATCH_N packets.

use std::sync::Arc;
use arrow::array::{
    ArrayRef, Float64Array, RecordBatch, UInt16Array, UInt32Array, UInt64Array, UInt8Array,
};

use crate::schema;
use crate::csv_output::{FinalLabel, Snapshot, TraceRecord};

pub struct FlowColumns;

impl FlowColumns {
    /// Build one RecordBatch from a group of snapshots that all share a depth
    /// (they are written into the same depth shard) plus the flow's final label,
    /// which is identical for every snapshot of the flow and so is broadcast to
    /// every row here.
    pub fn build(snaps: &[&Snapshot], label: &FinalLabel) -> RecordBatch {
        let n = snaps.len();

        // Small helpers to collect a column by mapping over the snapshots. The
        // closures read one field; the order of the `col!` invocations below is
        // the column order and MUST match schema::flow_schema().
        macro_rules! col_u8 {
            ($e:expr) => {{
                let a: UInt8Array = snaps.iter().map(|s| Some($e(&s.conn, &s.tls))).collect();
                Arc::new(a) as ArrayRef
            }};
        }
        macro_rules! col_u16 {
            ($e:expr) => {{
                let a: UInt16Array = snaps.iter().map(|s| Some($e(&s.conn, &s.tls))).collect();
                Arc::new(a) as ArrayRef
            }};
        }
        macro_rules! col_u32 {
            ($e:expr) => {{
                let a: UInt32Array = snaps.iter().map(|s| Some($e(&s.conn, &s.tls))).collect();
                Arc::new(a) as ArrayRef
            }};
        }
        macro_rules! col_u64 {
            ($e:expr) => {{
                let a: UInt64Array = snaps.iter().map(|s| Some($e(&s.conn, &s.tls))).collect();
                Arc::new(a) as ArrayRef
            }};
        }
        macro_rules! col_f64 {
            ($e:expr) => {{
                let a: Float64Array = snaps.iter().map(|s| Some($e(&s.conn, &s.tls))).collect();
                Arc::new(a) as ArrayRef
            }};
        }

        // Type aliases so the closures below name the arg types once.
        type C = flow_features::conn_features::ConnFeatures;
        type T = flow_features::tls_features::TlsFeatures;

        let columns: Vec<ArrayRef> = vec![
            // ---- ConnFeatures ----
            col_u64!(|c: &C, _t: &T| c.conn_hash),
            col_u64!(|c: &C, _t: &T| c.first_seen_ts),
            col_u64!(|c: &C, _t: &T| c.snapshot_ts),
            col_u64!(|c: &C, _t: &T| c.pkt_snapshot),
            col_u64!(|c: &C, _t: &T| c.src_ip_subn),
            col_u64!(|c: &C, _t: &T| c.dst_ip_subn),
            col_u16!(|c: &C, _t: &T| c.src_port),
            col_u16!(|c: &C, _t: &T| c.dst_port),
            col_u64!(|c: &C, _t: &T| c.protocol as u64), // usize -> u64
            col_u64!(|c: &C, _t: &T| c.duration_ms),
            col_u64!(|c: &C, _t: &T| c.max_inactivity_ms),
            col_u64!(|c: &C, _t: &T| c.time_to_second_pkt_ms),
            col_u8!(|c: &C, _t: &T| c.hist_syn),
            col_u8!(|c: &C, _t: &T| c.hist_synack),
            col_u8!(|c: &C, _t: &T| c.hist_ack),
            col_u8!(|c: &C, _t: &T| c.hist_data),
            col_u8!(|c: &C, _t: &T| c.hist_fin),
            col_u8!(|c: &C, _t: &T| c.hist_rst),
            col_u8!(|c: &C, _t: &T| c.hist_syn_r),
            col_u8!(|c: &C, _t: &T| c.hist_synack_r),
            col_u8!(|c: &C, _t: &T| c.hist_ack_r),
            col_u8!(|c: &C, _t: &T| c.hist_data_r),
            col_u8!(|c: &C, _t: &T| c.hist_fin_r),
            col_u8!(|c: &C, _t: &T| c.hist_rst_r),
            col_u64!(|c: &C, _t: &T| c.orig_nb_pkts),
            col_u64!(|c: &C, _t: &T| c.orig_nb_malformed_pkts),
            col_u64!(|c: &C, _t: &T| c.orig_nb_late_start_pkts),
            col_u64!(|c: &C, _t: &T| c.orig_nb_pkt_bytes),
            col_u64!(|c: &C, _t: &T| c.orig_nb_payload_bytes),
            col_u64!(|c: &C, _t: &T| c.orig_max_simult_gaps),
            col_u64!(|c: &C, _t: &T| c.orig_content_gaps),
            col_u64!(|c: &C, _t: &T| c.orig_missed_bytes),
            col_f64!(|c: &C, _t: &T| c.orig_mean_pkts_to_fill),
            col_u64!(|c: &C, _t: &T| c.resp_nb_pkts),
            col_u64!(|c: &C, _t: &T| c.resp_nb_malformed_pkts),
            col_u64!(|c: &C, _t: &T| c.resp_nb_late_start_pkts),
            col_u64!(|c: &C, _t: &T| c.resp_nb_pkt_bytes),
            col_u64!(|c: &C, _t: &T| c.resp_nb_payload_bytes),
            col_u64!(|c: &C, _t: &T| c.resp_max_simult_gaps),
            col_u64!(|c: &C, _t: &T| c.resp_content_gaps),
            col_u64!(|c: &C, _t: &T| c.resp_missed_bytes),
            col_f64!(|c: &C, _t: &T| c.resp_mean_pkts_to_fill),
            col_f64!(|c: &C, _t: &T| c.orig_iat_mean),
            col_u64!(|c: &C, _t: &T| c.orig_iat_min),
            col_u64!(|c: &C, _t: &T| c.orig_iat_max),
            col_f64!(|c: &C, _t: &T| c.orig_iat_std),
            col_f64!(|c: &C, _t: &T| c.resp_iat_mean),
            col_u64!(|c: &C, _t: &T| c.resp_iat_min),
            col_u64!(|c: &C, _t: &T| c.resp_iat_max),
            col_f64!(|c: &C, _t: &T| c.resp_iat_std),
            // ---- TlsFeatures ----
            col_u8!(|_c: &C, t: &T| t.has_client_hello),
            col_u16!(|_c: &C, t: &T| t.client_version),
            col_u16!(|_c: &C, t: &T| t.client_num_supported_groups),
            col_u16!(|_c: &C, t: &T| t.client_num_sig_algs),
            col_u16!(|_c: &C, t: &T| t.client_num_alpn_protocols),
            col_u16!(|_c: &C, t: &T| t.client_num_key_shares),
            col_u16!(|_c: &C, t: &T| t.client_num_supported_vers),
            col_u8!(|_c: &C, t: &T| t.client_has_sni),
            col_u64!(|_c: &C, t: &T| t.client_sni_hash),
            col_u16!(|_c: &C, t: &T| t.client_sni_len),
            col_u8!(|_c: &C, t: &T| t.client_has_session_id),
            col_u8!(|_c: &C, t: &T| t.client_session_id_len),
            col_u8!(|_c: &C, t: &T| t.client_has_compression),
            col_u8!(|_c: &C, t: &T| t.client_has_alpn),
            col_u8!(|_c: &C, t: &T| t.client_has_key_share),
            col_u8!(|_c: &C, t: &T| t.client_has_supported_vers),
            col_u8!(|_c: &C, t: &T| t.has_server_hello),
            col_u16!(|_c: &C, t: &T| t.server_version),
            col_u16!(|_c: &C, t: &T| t.server_cipher_suite),
            col_u8!(|_c: &C, t: &T| t.server_compression_alg),
            col_u8!(|_c: &C, t: &T| t.server_has_alpn),
            col_u8!(|_c: &C, t: &T| t.server_has_key_share),
            col_u8!(|_c: &C, t: &T| t.server_has_selected_vers),
            col_u16!(|_c: &C, t: &T| t.num_server_certs),
            col_u16!(|_c: &C, t: &T| t.num_client_certs),
            col_u32!(|_c: &C, t: &T| t.server_cert0_len),
            col_u32!(|_c: &C, t: &T| t.server_cert1_len),
            col_u8!(|_c: &C, t: &T| t.has_server_kex),
            col_u8!(|_c: &C, t: &T| t.has_client_kex),
            col_u8!(|_c: &C, t: &T| t.kex_type),
        ];

        // ---- FinalLabel (broadcast: same value on every row of this flow) ----
        let mut columns = columns;
        columns.push(Arc::new(UInt64Array::from(vec![label.final_total_payload_bytes; n])) as ArrayRef);
        columns.push(Arc::new(UInt64Array::from(vec![label.final_duration_ms; n])) as ArrayRef);
        columns.push(Arc::new(UInt64Array::from(vec![label.final_total_pkts; n])) as ArrayRef);

        RecordBatch::try_new(schema::flow_schema(), columns)
            .expect("flow columns must match flow_schema (check field order/count)")
    }
}

pub struct TraceColumns;

impl TraceColumns {
    /// Build one RecordBatch from a batch of per-packet trace records.
    pub fn build(rows: &[TraceRecord]) -> RecordBatch {
        let conn_hash: UInt64Array = rows.iter().map(|r| Some(r.conn_hash)).collect();
        let first_seen_ts: UInt64Array = rows.iter().map(|r| Some(r.first_seen_ts)).collect();
        let snapshot_ts: UInt64Array = rows.iter().map(|r| Some(r.snapshot_ts)).collect();
        let cumulative_bytes: UInt64Array = rows.iter().map(|r| Some(r.cumulative_bytes)).collect();

        let columns: Vec<ArrayRef> = vec![
            Arc::new(conn_hash),
            Arc::new(first_seen_ts),
            Arc::new(snapshot_ts),
            Arc::new(cumulative_bytes),
        ];

        RecordBatch::try_new(schema::trace_schema(), columns)
            .expect("trace columns must match trace_schema")
    }
}