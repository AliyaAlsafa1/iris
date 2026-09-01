use iris_datatypes::ConnRecord;
use iris_datatypes::connection::{HIST_SYN, HIST_SYNACK, HIST_ACK, HIST_DATA, HIST_FIN, HIST_RST};
use iris_datatypes::conn_fts::InterArrivals;
use serde::Serialize;
use std::time::SystemTime;

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

#[derive(Clone, Debug)]
pub struct ConnInvariants {
    pub conn_hash: u64,
    pub first_seen_ts: u64,
    pub src_ip_subn: u64,
    pub dst_ip_subn: u64,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: usize,
}

impl ConnInvariants {
    pub fn from_conn(conn: &ConnRecord, conn_hash: u64, first_seen_ts: u64) -> Self {
        Self {
            conn_hash,
            first_seen_ts,
            src_ip_subn: ip_to_prefix(&conn.five_tuple.orig.ip()),
            dst_ip_subn: ip_to_prefix(&conn.five_tuple.resp.ip()),
            src_port: conn.five_tuple.orig.port(),
            dst_port: conn.five_tuple.resp.port(),
            protocol: conn.five_tuple.proto,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnFeatures {
    pub conn_hash: u64,                  // full-tuple u64 hash; pair with first_seen_ts for the connection key

    pub first_seen_ts: u64,              // first time this flow was observed (stable across snapshots); 2nd key column
    pub snapshot_ts: u64,                // time this particular snapshot row was emitted
    pub pkt_snapshot: u64,               // total packets observed when this row was emitted
    
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

    pub resp_nb_pkts:             u64,   // responder packets seen in first N packets
    pub resp_nb_malformed_pkts:   u64,   // responder malformed packets in first N packets
    pub resp_nb_late_start_pkts:  u64,   // responder late start packets in first N packets (TCP only)
    pub resp_nb_pkt_bytes:        u64,   // responder total packet bytes in first N packets (includes headers)
    pub resp_nb_payload_bytes:    u64,   // responder payload bytes in first N packets (excludes malformed)
    pub resp_max_simult_gaps:     u64,   // responder max simultaneous TCP sequence gaps in first N packets
    pub resp_content_gaps:        u64,   // responder TCP sequence gaps remaining at Nth packet
    pub resp_missed_bytes:        u64,   // responder bytes missing in sequence gaps at Nth packet
    pub resp_mean_pkts_to_fill:   f64,   // responder mean packet arrivals to fill a sequence gap (0.0 if no gaps)

    pub orig_iat_mean:    f64,           // originator mean inter-arrival time in first N packets (us)
    pub orig_iat_min:     u64,           // originator minimum inter-arrival time in first N packets (us)
    pub orig_iat_max:     u64,           // originator maximum inter-arrival time in first N packets (us)
    pub orig_iat_std:     f64,           // originator inter-arrival time std deviation in first N packets (us)

    pub resp_iat_mean:    f64,           // responder mean inter-arrival time in first N packets (us)
    pub resp_iat_min:     u64,           // responder minimum inter-arrival time in first N packets (us)
    pub resp_iat_max:     u64,           // responder maximum inter-arrival time in first N packets (us)
    pub resp_iat_std:     f64,           // responder inter-arrival time std deviation in first N packets (us)
}

impl ConnFeatures {
    pub fn from_conn_at(conn: &ConnRecord, iat: &InterArrivals, pkt_count: u64, inv: &ConnInvariants) -> Option<Self> {
        if pkt_count == 0 {
            return None;
        }

        let (orig_iat_mean, orig_iat_min, orig_iat_max, orig_iat_std) =
            iat.stats_ctos.summary();
        let (resp_iat_mean, resp_iat_min, resp_iat_max, resp_iat_std) =
            iat.stats_stoc.summary();

        // Read LIVE connection state directly (pre-snapshot connection.rs has no prefix_* fields).
        let orig = &conn.orig;
        let resp = &conn.resp;

        let (mut hist_syn, mut hist_synack, mut hist_ack, mut hist_data, mut hist_fin, mut hist_rst) =
            (0u8, 0u8, 0u8, 0u8, 0u8, 0u8);
        let (mut hist_syn_r, mut hist_synack_r, mut hist_ack_r, mut hist_data_r, mut hist_fin_r, mut hist_rst_r) =
            (0u8, 0u8, 0u8, 0u8, 0u8, 0u8);
        for &b in &conn.history {
            match b {
                x if x == HIST_SYN            => hist_syn = 1,
                x if x == HIST_SYNACK         => hist_synack = 1,
                x if x == HIST_ACK            => hist_ack = 1,
                x if x == HIST_DATA           => hist_data = 1,
                x if x == HIST_FIN            => hist_fin = 1,
                x if x == HIST_RST            => hist_rst = 1,
                x if x == HIST_SYN    ^ 0x20  => hist_syn_r = 1,
                x if x == HIST_SYNACK ^ 0x20  => hist_synack_r = 1,
                x if x == HIST_ACK    ^ 0x20  => hist_ack_r = 1,
                x if x == HIST_DATA   ^ 0x20  => hist_data_r = 1,
                x if x == HIST_FIN    ^ 0x20  => hist_fin_r = 1,
                x if x == HIST_RST    ^ 0x20  => hist_rst_r = 1,
                _ => {}
            }
        }

        Some(Self {
            conn_hash: inv.conn_hash,
            first_seen_ts: inv.first_seen_ts,
            snapshot_ts: (conn.first_seen_wall + (conn.last_seen_ts - conn.first_seen_ts))
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64,
            pkt_snapshot: pkt_count,
            src_ip_subn: inv.src_ip_subn,
            dst_ip_subn: inv.dst_ip_subn,
            src_port: inv.src_port,
            dst_port: inv.dst_port,
            protocol: inv.protocol,

            duration_ms:           conn.duration().as_millis() as u64,
            max_inactivity_ms:     conn.max_inactivity.as_millis() as u64,
            time_to_second_pkt_ms: conn.time_to_second_packet().as_millis() as u64,

            hist_syn,
            hist_synack,
            hist_ack,
            hist_data,
            hist_fin,
            hist_rst,
            hist_syn_r,
            hist_synack_r,
            hist_ack_r,
            hist_data_r,
            hist_fin_r,
            hist_rst_r,

            orig_nb_pkts:             orig.nb_pkts,
            orig_nb_malformed_pkts:   orig.nb_malformed_pkts,
            orig_nb_late_start_pkts:  orig.nb_late_start_pkts,
            orig_nb_pkt_bytes:        orig.nb_pkt_bytes,
            orig_nb_payload_bytes:    orig.nb_payload_bytes,
            orig_max_simult_gaps:     orig.max_simult_gaps,
            orig_content_gaps:        orig.content_gaps(),
            orig_missed_bytes:        orig.missed_bytes(),
            orig_mean_pkts_to_fill:   orig.mean_pkts_to_fill().unwrap_or(0.0),

            resp_nb_pkts:             resp.nb_pkts,
            resp_nb_malformed_pkts:   resp.nb_malformed_pkts,
            resp_nb_late_start_pkts:  resp.nb_late_start_pkts,
            resp_nb_pkt_bytes:        resp.nb_pkt_bytes,
            resp_nb_payload_bytes:    resp.nb_payload_bytes,
            resp_max_simult_gaps:     resp.max_simult_gaps,
            resp_content_gaps:        resp.content_gaps(),
            resp_missed_bytes:        resp.missed_bytes(),
            resp_mean_pkts_to_fill:   resp.mean_pkts_to_fill().unwrap_or(0.0),

            orig_iat_mean,
            orig_iat_min,
            orig_iat_max,
            orig_iat_std,

            resp_iat_mean,
            resp_iat_min,
            resp_iat_max,
            resp_iat_std,
        })
    }
}