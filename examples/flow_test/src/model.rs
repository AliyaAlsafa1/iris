use lightgbm3::Booster;
use std::sync::OnceLock;

use crate::conn_features::ConnFeatures;

pub struct SendSyncBooster(Booster);
unsafe impl Send for SendSyncBooster {}
unsafe impl Sync for SendSyncBooster {}

static BOOSTER: OnceLock<SendSyncBooster> = OnceLock::new();

pub fn load_model(path: &str) {
    let booster = Booster::from_file(path).expect("Failed to load elephant flow model");
    BOOSTER.set(SendSyncBooster(booster)).ok();
}

pub fn predict(f: &ConnFeatures) -> Option<f64> {
    let booster = &BOOSTER.get()?.0;

    let features: Vec<f64> = vec![
        f.src_ip_subn                 as f64,
        f.dst_ip_subn                 as f64,
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
        f.resp_iat_std
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