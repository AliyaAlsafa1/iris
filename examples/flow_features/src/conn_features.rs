use iris_datatypes::{ConnRecord, connection::N_PACKETS};
use iris_datatypes::connection::{HIST_SYN, HIST_SYNACK, HIST_ACK, HIST_DATA, HIST_FIN, HIST_RST};
use iris_datatypes::conn_fts::InterArrivals;
use serde::Serialize;
use std::time::SystemTime;
use crate::hash_utils::hash_ip;

fn ip_to_prefix(ip: &std::net::IpAddr) -> u64 {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            let prefix = u32::from_be_bytes([octets[0], octets[1], octets[2], 0]);
            prefix as u64
        }
        std::net::IpAddr::V6(ipv6) => {
            let octets = ipv6.octets();
            let mut prefix_bytes = [0u8; 8];
            prefix_bytes[2..8].copy_from_slice(&octets[..6]);
            u64::from_be_bytes(prefix_bytes)
        }
    }
}

fn iat_stats(iats_us: &[u128]) -> (f64, f64, u64, u64, f64) {
    let n = iats_us.len();
    if n == 0 {
        return (0.0, 0.0, 0, 0, 0.0);
    }

    let min = *iats_us.iter().min().unwrap();
    let max = *iats_us.iter().max().unwrap();

    let mean = iats_us.iter().map(|&v| v as f64).sum::<f64>() / n as f64;

    let variance = iats_us
        .iter()
        .map(|&v| { let d = v as f64 - mean; d * d })
        .sum::<f64>()
        / n as f64;
    let std_dev = variance.sqrt();

    let mut sorted = iats_us.to_vec();
    sorted.sort_unstable();
    let median = if n % 2 == 1 {
        sorted[n / 2] as f64
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) as f64 / 2.0
    };

    (mean, median, min as u64, max as u64, std_dev)
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnFeatures {
    pub first_seen_ts: u64,              // Timestamp
    pub src_ip_hash: u64,                // hash of source IP address
    pub dst_ip_hash: u64,                // hash of destination IP address
    pub src_ip_subn: u64,                // source IP address, masked to /24 (IPv4) or /48 (IPv6)
    pub dst_ip_subn: u64,                // destination IP address, masked to /24 (IPv4) or /48 (IPv6)
    pub src_port: u16,                   // source port
    pub dst_port: u16,                   // destination port
    pub protocol: usize,                 // IP protocol number (6=TCP, 17=UDP)

    pub duration_ms: u64,                // elapsed time between first and Nth packet (ms)
    pub max_inactivity_ms: u64,          // maximum time between any two consecutive packets up to Nth (ms)
    pub time_to_second_pkt_ms: u64,      // elapsed time between first and second packet (ms)

    pub hist_syn:      u8,               // originator sent a pure SYN
    pub hist_synack:   u8,               // originator sent a pure SYNACK
    pub hist_ack:      u8,               // originator sent a pure ACK (no payload)
    pub hist_data:     u8,               // originator sent a segment with non-zero payload
    pub hist_fin:      u8,               // originator sent a FIN
    pub hist_rst:      u8,               // originator sent a RST
    pub hist_syn_r:    u8,               // responder sent a pure SYN
    pub hist_synack_r: u8,               // responder sent a pure SYNACK
    pub hist_ack_r:    u8,               // responder sent a pure ACK (no payload)
    pub hist_data_r:   u8,               // responder sent a segment with non-zero payload
    pub hist_fin_r:    u8,               // responder sent a FIN
    pub hist_rst_r:    u8,               // responder sent a RST

    pub orig_nb_pkts:             u64,   // originator packets seen in first N packets
    pub orig_nb_malformed_pkts:   u64,   // originator malformed packets in first N packets
    pub orig_nb_late_start_pkts:  u64,   // originator late start packets in first N packets (TCP only)
    pub orig_nb_pkt_bytes:        u64,   // originator total packet bytes in first N packets (includes headers)
    pub orig_nb_payload_bytes:    u64,   // originator payload bytes in first N packets (excludes malformed)
    pub orig_max_simult_gaps:     u64,   // originator max simultaneous TCP sequence gaps in first N packets
    pub orig_content_gaps:        u64,   // originator TCP sequence gaps remaining at Nth packet
    pub orig_missed_bytes:        u64,   // originator bytes missing in sequence gaps at Nth packet
    pub orig_mean_pkts_to_fill:   f64,   // originator mean packet arrivals to fill a sequence gap (0.0 if no gaps)
    pub orig_median_pkts_to_fill: u64,   // originator median packet arrivals to fill a sequence gap (0 if no gaps)

    pub resp_nb_pkts:             u64,   // responder packets seen in first N packets
    pub resp_nb_malformed_pkts:   u64,   // responder malformed packets in first N packets
    pub resp_nb_late_start_pkts:  u64,   // responder late start packets in first N packets (TCP only)
    pub resp_nb_pkt_bytes:        u64,   // responder total packet bytes in first N packets (includes headers)
    pub resp_nb_payload_bytes:    u64,   // responder payload bytes in first N packets (excludes malformed)
    pub resp_max_simult_gaps:     u64,   // responder max simultaneous TCP sequence gaps in first N packets
    pub resp_content_gaps:        u64,   // responder TCP sequence gaps remaining at Nth packet
    pub resp_missed_bytes:        u64,   // responder bytes missing in sequence gaps at Nth packet
    pub resp_mean_pkts_to_fill:   f64,   // responder mean packet arrivals to fill a sequence gap (0.0 if no gaps)
    pub resp_median_pkts_to_fill: u64,   // responder median packet arrivals to fill a sequence gap (0 if no gaps)

    pub orig_iat_mean:    f64,           // originator mean inter-arrival time in first N packets (us)
    pub orig_iat_median:  f64,           // originator median inter-arrival time in first N packets (us)
    pub orig_iat_min:     u64,           // originator minimum inter-arrival time in first N packets (us)
    pub orig_iat_max:     u64,           // originator maximum inter-arrival time in first N packets (us)
    pub orig_iat_std:     f64,           // originator inter-arrival time std deviation in first N packets (us)

    pub resp_iat_mean:    f64,           // responder mean inter-arrival time in first N packets (us)
    pub resp_iat_median:  f64,           // responder median inter-arrival time in first N packets (us)
    pub resp_iat_min:     u64,           // responder minimum inter-arrival time in first N packets (us)
    pub resp_iat_max:     u64,           // responder maximum inter-arrival time in first N packets (us)
    pub resp_iat_std:     f64,           // responder inter-arrival time std deviation in first N packets (us)

    pub final_total_payload_bytes: u64,  // total payload bytes across full connection (both directions)
    pub final_duration_ms: u64,          // elapsed time between first and last packet of full connection (ms)
    pub final_total_pkts: u64,           // total packets across full connection (both directions)
}

impl ConnFeatures {
    pub fn from_conn(conn: &ConnRecord, iat: &InterArrivals) -> Option<Self> {
        if (conn.total_pkts() as usize) < N_PACKETS {
            return None;
        }

        let orig    = conn.prefix_orig.as_ref()?;
        let resp    = conn.prefix_resp.as_ref()?;
        let history = conn.prefix_history.as_ref()?;

        // Truncate InterArrivals to N_PACKETS-1 to match the prefix window.
        let max_iats = N_PACKETS - 1;
        let orig_iats_us: Vec<u128> = iat.interarrivals_ctos.iter().take(max_iats).map(|d| d.as_micros()).collect();
        let resp_iats_us: Vec<u128> = iat.interarrivals_stoc.iter().take(max_iats).map(|d| d.as_micros()).collect();

        let (orig_iat_mean, orig_iat_median, orig_iat_min, orig_iat_max, orig_iat_std) = iat_stats(&orig_iats_us);
        let (resp_iat_mean, resp_iat_median, resp_iat_min, resp_iat_max, resp_iat_std) = iat_stats(&resp_iats_us);

        Some(Self {
            first_seen_ts: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64,
            src_ip_hash: hash_ip(conn.five_tuple.orig.ip()),
            dst_ip_hash: hash_ip(conn.five_tuple.resp.ip()),
            src_ip_subn: ip_to_prefix(&conn.five_tuple.orig.ip()),
            dst_ip_subn: ip_to_prefix(&conn.five_tuple.resp.ip()),
            src_port: conn.five_tuple.orig.port(),
            dst_port: conn.five_tuple.resp.port(),
            protocol: conn.five_tuple.proto,

            duration_ms:           conn.prefix_duration?.as_millis() as u64,
            max_inactivity_ms:     conn.prefix_max_inactivity?.as_millis() as u64,
            time_to_second_pkt_ms: conn.prefix_time_to_second_pkt?.as_millis() as u64,

            hist_syn:      history.contains(&HIST_SYN)             as u8,
            hist_synack:   history.contains(&HIST_SYNACK)          as u8,
            hist_ack:      history.contains(&HIST_ACK)             as u8,
            hist_data:     history.contains(&HIST_DATA)            as u8,
            hist_fin:      history.contains(&HIST_FIN)             as u8,
            hist_rst:      history.contains(&HIST_RST)             as u8,
            hist_syn_r:    history.contains(&(HIST_SYN    ^ 0x20)) as u8,
            hist_synack_r: history.contains(&(HIST_SYNACK ^ 0x20)) as u8,
            hist_ack_r:    history.contains(&(HIST_ACK    ^ 0x20)) as u8,
            hist_data_r:   history.contains(&(HIST_DATA   ^ 0x20)) as u8,
            hist_fin_r:    history.contains(&(HIST_FIN    ^ 0x20)) as u8,
            hist_rst_r:    history.contains(&(HIST_RST    ^ 0x20)) as u8,

            orig_nb_pkts:             orig.nb_pkts,
            orig_nb_malformed_pkts:   orig.nb_malformed_pkts,
            orig_nb_late_start_pkts:  orig.nb_late_start_pkts,
            orig_nb_pkt_bytes:        orig.nb_pkt_bytes,
            orig_nb_payload_bytes:    orig.nb_payload_bytes,
            orig_max_simult_gaps:     orig.max_simult_gaps,
            orig_content_gaps:        orig.content_gaps(),
            orig_missed_bytes:        orig.missed_bytes(),
            orig_mean_pkts_to_fill:   orig.mean_pkts_to_fill().unwrap_or(0.0),
            orig_median_pkts_to_fill: orig.median_pkts_to_fill().unwrap_or(0),

            resp_nb_pkts:             resp.nb_pkts,
            resp_nb_malformed_pkts:   resp.nb_malformed_pkts,
            resp_nb_late_start_pkts:  resp.nb_late_start_pkts,
            resp_nb_pkt_bytes:        resp.nb_pkt_bytes,
            resp_nb_payload_bytes:    resp.nb_payload_bytes,
            resp_max_simult_gaps:     resp.max_simult_gaps,
            resp_content_gaps:        resp.content_gaps(),
            resp_missed_bytes:        resp.missed_bytes(),
            resp_mean_pkts_to_fill:   resp.mean_pkts_to_fill().unwrap_or(0.0),
            resp_median_pkts_to_fill: resp.median_pkts_to_fill().unwrap_or(0),

            orig_iat_mean,
            orig_iat_median,
            orig_iat_min,
            orig_iat_max,
            orig_iat_std,

            resp_iat_mean,
            resp_iat_median,
            resp_iat_min,
            resp_iat_max,
            resp_iat_std,

            final_total_payload_bytes: conn.orig.nb_payload_bytes + conn.resp.nb_payload_bytes,
            final_duration_ms: conn.duration().as_millis() as u64,
            final_total_pkts: conn.total_pkts(),
        })
    }
}