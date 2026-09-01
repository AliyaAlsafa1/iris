// examples/flow_collect/src/csv_output/schema.rs
//
// Arrow schemas for the two Parquet shard types. These schemas ARE the column
// contract that the old *_header.txt files used to carry: they are embedded in
// every Parquet footer, so to_parquet.py reads column names and types straight
// from the file metadata instead of a sidecar header.
//
// Field ORDER is load-bearing and must match the struct declaration order in
// flow_features (ConnFeatures, then TlsFeatures, then FinalLabel) -- this is the
// same ordering the old serde CSV path relied on to keep columns aligned with
// TLS_CONN_HEADER. If you add/reorder a field in conn_features.rs or
// tls_features.rs, mirror it here AND in builders.rs, or the shard will be
// mislabeled.
//
// Type mapping notes:
//   * Rust u8/u16/u32/u64 -> Arrow UInt8/UInt16/UInt32/UInt64.
//   * `protocol: usize` has no Arrow analogue; it holds tiny IP proto numbers
//     (6, 17), so it maps to UInt64. Downstream reads it as an unsigned 64-bit
//     integer (was a bare decimal in CSV, so no semantic change).
//   * f64 -> Float64.
// All columns are non-nullable: every row always carries every field (the
// feature extractors substitute 0/0.0 rather than emitting nulls).

use std::sync::Arc;
use arrow::datatypes::{DataType, Field, Schema};

fn f(name: &str, dt: DataType) -> Field {
    // Non-nullable: the collector never emits a null cell.
    Field::new(name, dt, false)
}

/// Schema for the stream-1 depth shards: ConnFeatures ++ TlsFeatures ++ FinalLabel,
/// in that exact order.
pub fn flow_schema() -> Arc<Schema> {
    use DataType::*;
    let fields = vec![
        // ---- ConnFeatures (46) ----
        f("conn_hash", UInt64),
        f("first_seen_ts", UInt64),
        f("snapshot_ts", UInt64),
        f("pkt_snapshot", UInt64),
        f("src_ip_subn", UInt64),
        f("dst_ip_subn", UInt64),
        f("src_port", UInt16),
        f("dst_port", UInt16),
        f("protocol", UInt64), // usize -> UInt64
        f("duration_ms", UInt64),
        f("max_inactivity_ms", UInt64),
        f("time_to_second_pkt_ms", UInt64),
        f("hist_syn", UInt8),
        f("hist_synack", UInt8),
        f("hist_ack", UInt8),
        f("hist_data", UInt8),
        f("hist_fin", UInt8),
        f("hist_rst", UInt8),
        f("hist_syn_r", UInt8),
        f("hist_synack_r", UInt8),
        f("hist_ack_r", UInt8),
        f("hist_data_r", UInt8),
        f("hist_fin_r", UInt8),
        f("hist_rst_r", UInt8),
        f("orig_nb_pkts", UInt64),
        f("orig_nb_malformed_pkts", UInt64),
        f("orig_nb_late_start_pkts", UInt64),
        f("orig_nb_pkt_bytes", UInt64),
        f("orig_nb_payload_bytes", UInt64),
        f("orig_max_simult_gaps", UInt64),
        f("orig_content_gaps", UInt64),
        f("orig_missed_bytes", UInt64),
        f("orig_mean_pkts_to_fill", Float64),
        f("resp_nb_pkts", UInt64),
        f("resp_nb_malformed_pkts", UInt64),
        f("resp_nb_late_start_pkts", UInt64),
        f("resp_nb_pkt_bytes", UInt64),
        f("resp_nb_payload_bytes", UInt64),
        f("resp_max_simult_gaps", UInt64),
        f("resp_content_gaps", UInt64),
        f("resp_missed_bytes", UInt64),
        f("resp_mean_pkts_to_fill", Float64),
        f("orig_iat_mean", Float64),
        f("orig_iat_min", UInt64),
        f("orig_iat_max", UInt64),
        f("orig_iat_std", Float64),
        f("resp_iat_mean", Float64),
        f("resp_iat_min", UInt64),
        f("resp_iat_max", UInt64),
        f("resp_iat_std", Float64),
        // ---- TlsFeatures (33) ----
        f("has_client_hello", UInt8),
        f("client_version", UInt16),
        f("client_num_supported_groups", UInt16),
        f("client_num_sig_algs", UInt16),
        f("client_num_alpn_protocols", UInt16),
        f("client_num_key_shares", UInt16),
        f("client_num_supported_vers", UInt16),
        f("client_has_sni", UInt8),
        f("client_sni_hash", UInt64),
        f("client_sni_len", UInt16),
        f("client_has_session_id", UInt8),
        f("client_session_id_len", UInt8),
        f("client_has_compression", UInt8),
        f("client_has_alpn", UInt8),
        f("client_has_key_share", UInt8),
        f("client_has_supported_vers", UInt8),
        f("has_server_hello", UInt8),
        f("server_version", UInt16),
        f("server_cipher_suite", UInt16),
        f("server_compression_alg", UInt8),
        f("server_has_alpn", UInt8),
        f("server_has_key_share", UInt8),
        f("server_has_selected_vers", UInt8),
        f("num_server_certs", UInt16),
        f("num_client_certs", UInt16),
        f("server_cert0_len", UInt32),
        f("server_cert1_len", UInt32),
        f("has_server_kex", UInt8),
        f("has_client_kex", UInt8),
        f("kex_type", UInt8),
        // ---- FinalLabel (3) ----
        f("final_total_payload_bytes", UInt64),
        f("final_duration_ms", UInt64),
        f("final_total_pkts", UInt64),
    ];
    Arc::new(Schema::new(fields))
}

/// Schema for the stream-2 per-core trace shards: the four TraceRecord columns.
pub fn trace_schema() -> Arc<Schema> {
    use DataType::*;
    Arc::new(Schema::new(vec![
        f("conn_hash", UInt64),
        f("first_seen_ts", UInt64),
        f("snapshot_ts", UInt64),
        f("cumulative_bytes", UInt64),
    ]))
}