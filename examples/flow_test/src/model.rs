use lightgbm3::Booster;
use std::sync::OnceLock;

use flow_features::conn_features::ConnFeatures;
use flow_features::tls_features::TlsFeatures;

pub struct SendSyncBooster(Booster);
unsafe impl Send for SendSyncBooster {}
unsafe impl Sync for SendSyncBooster {}

static BOOSTER: OnceLock<SendSyncBooster> = OnceLock::new();

pub fn load_model(path: &str) {
    let booster = Booster::from_file(path).expect("Failed to load elephant flow model");
    BOOSTER.set(SendSyncBooster(booster)).ok();
}

pub fn predict(f: &ConnFeatures, t: &TlsFeatures) -> Option<f64> {
    let booster = &BOOSTER.get()?.0;

    let features: Vec<f64> = vec![
        // --- ConnFeatures ---
        f.src_ip_oct0                 as f64,
        f.src_ip_oct1                 as f64,
        f.src_ip_oct2                 as f64,
        f.src_ip_oct3                 as f64,
        f.src_ip_oct4                 as f64,
        f.src_ip_oct5                 as f64,
        f.dst_ip_oct0                 as f64,
        f.dst_ip_oct1                 as f64,
        f.dst_ip_oct2                 as f64,
        f.dst_ip_oct3                 as f64,
        f.dst_ip_oct4                 as f64,
        f.dst_ip_oct5                 as f64,
        f.src_port                    as f64,
        f.dst_port                    as f64,
        f.protocol                    as f64,
        f.duration_ms                 as f64,
        f.max_inactivity_ms           as f64,
        f.time_to_second_pkt_ms       as f64,
        f.hist_syn                    as f64,
        f.hist_synack                 as f64,
        f.hist_ack                    as f64,
        f.hist_data                   as f64,
        f.hist_fin                    as f64,
        f.hist_rst                    as f64,
        f.hist_syn_r                  as f64,
        f.hist_synack_r               as f64,
        f.hist_ack_r                  as f64,
        f.hist_data_r                 as f64,
        f.hist_fin_r                  as f64,
        f.hist_rst_r                  as f64,
        f.orig_nb_pkts                as f64,
        f.orig_nb_malformed_pkts      as f64,
        f.orig_nb_late_start_pkts     as f64,
        f.orig_nb_pkt_bytes           as f64,
        f.orig_nb_payload_bytes       as f64,
        f.orig_max_simult_gaps        as f64,
        f.orig_content_gaps           as f64,
        f.orig_missed_bytes           as f64,
        f.orig_mean_pkts_to_fill,
        f.orig_median_pkts_to_fill    as f64,
        f.resp_nb_pkts                as f64,
        f.resp_nb_malformed_pkts      as f64,
        f.resp_nb_late_start_pkts     as f64,
        f.resp_nb_pkt_bytes           as f64,
        f.resp_nb_payload_bytes       as f64,
        f.resp_max_simult_gaps        as f64,
        f.resp_content_gaps           as f64,
        f.resp_missed_bytes           as f64,
        f.resp_mean_pkts_to_fill,
        f.resp_median_pkts_to_fill    as f64,
        f.orig_iat_mean,
        f.orig_iat_median,
        f.orig_iat_min                as f64,
        f.orig_iat_max                as f64,
        f.orig_iat_std,
        f.resp_iat_mean,
        f.resp_iat_median,
        f.resp_iat_min                as f64,
        f.resp_iat_max                as f64,
        f.resp_iat_std,

        // --- TlsFeatures ---
        t.has_client_hello            as f64,
        t.client_version              as f64,
        t.client_num_supported_groups as f64,
        t.client_num_sig_algs         as f64,
        t.client_num_alpn_protocols   as f64,
        t.client_num_key_shares       as f64,
        t.client_num_supported_vers   as f64,
        t.client_has_sni              as f64,
        t.client_sni_hash             as f64,
        t.client_sni_len              as f64,
        t.client_has_session_id       as f64,
        t.client_session_id_len       as f64,
        t.client_has_compression      as f64,
        t.client_has_alpn             as f64,
        t.client_has_key_share        as f64,
        t.client_has_supported_vers   as f64,
        t.has_server_hello            as f64,
        t.server_version              as f64,
        t.server_cipher_suite         as f64,
        t.server_compression_alg      as f64,
        t.server_has_alpn             as f64,
        t.server_has_key_share        as f64,
        t.server_has_selected_vers    as f64,
        t.num_server_certs            as f64,
        t.num_client_certs            as f64,
        t.server_cert0_len            as f64,
        t.server_cert1_len            as f64,
        t.has_server_kex              as f64,
        t.has_client_kex              as f64,
        t.kex_type                    as f64,
    ];

    let n_features = features.len() as i32;

    match booster.predict_with_params(&features, n_features, true, "num_threads=1") {
        Ok(result) => Some(result[0]),
        Err(e) => {
            println!("[ELEPHANT ERROR] predict failed: {:?}", e);
            None
        }
    }
}