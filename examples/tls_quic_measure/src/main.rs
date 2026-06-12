//! Software oracle for the raw TLS/QUIC drop rules.
//!
//! Runs the same byte tests the hardware FDIR rules use, but in software and on
//! every packet, so we can compare three quantities in a single run (no FDIR
//! "one queue per packet" limit, no doff/FV-profile constraints):
//!
//!   1. total traffic
//!   2. addressable TLS+QUIC (ground-truth ceiling)
//!   3. what the hardware rules would actually match
//!
//! Works online or offline depending on the loaded config — the framework
//! handles ingestion; this app only classifies.

use clap::Parser;
use iris_compiler::*;
use iris_core::{config::load_config, L4Pdu, Runtime};
use lazy_static::lazy_static;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,
}

/// Counter categories. One global atomic per entry, indexed by these constants.
mod cat {
    pub const TOTAL: usize = 0;
    pub const TCP: usize = 1;
    pub const UDP: usize = 2;
    pub const TCP443: usize = 3;
    pub const UDP443: usize = 4;
    pub const TLS_RECORD: usize = 5; // any TLS record start (0x14-0x17, 0x03)
    pub const TLS_APPDATA: usize = 6; // AppData start (0x17 0x03), any doff, ihl=5/v6
    pub const TLS_HW: usize = 7; // HW rule: above AND TCP doff == 8
    pub const QUIC_SHORT: usize = 8; // UDP, (b0 & 0xc0) == 0x40
    pub const QUIC_LONG: usize = 9; // UDP, (b0 & 0xc0) == 0xc0
    pub const QUIC_HW: usize = 10; // HW rule: ihl=5/v6, UDP, short header
    pub const N: usize = 11;

    pub const LABELS: [&str; N] = [
        "total",
        "tcp",
        "udp",
        "tcp:443",
        "udp:443",
        "tls_record",
        "tls_appdata",
        "tls_hw(doff=8)",
        "quic_short",
        "quic_long",
        "quic_hw",
    ];
}

lazy_static! {
    /// Global per-category packet counters.
    static ref COUNTS: [AtomicU64; cat::N] = std::array::from_fn(|_| AtomicU64::new(0));
    /// Total bytes seen (not a category — kept separately).
    static ref TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);
}

#[inline]
fn bump(i: usize) {
    COUNTS[i].fetch_add(1, Ordering::Relaxed);
}

/// Classify one L2 frame, mirroring the raw-rule byte tests in
/// `core/src/filter/flow_drop/raw_drop.rs`, incrementing the relevant counters.
fn classify(data: &[u8]) {
    bump(cat::TOTAL);
    TOTAL_BYTES.fetch_add(data.len() as u64, Ordering::Relaxed);

    let b = |i: usize| data.get(i).copied();

    if data.len() < 14 {
        return;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut off = 14usize;
    if ethertype == 0x8100 {
        // single 802.1Q VLAN tag
        match (b(16), b(17)) {
            (Some(hi), Some(lo)) => {
                ethertype = u16::from_be_bytes([hi, lo]);
                off = 18;
            }
            _ => return,
        }
    }

    // L3: L4 protocol, L4 offset, and whether the IP header matches the rule's
    // pinned form (IPv4 IHL=5, or IPv6).
    let (proto, l4, ihl_ok) = match ethertype {
        0x0800 => {
            let ihl = match b(off) {
                Some(v) => (v & 0x0f) as usize,
                None => return,
            };
            let proto = match b(off + 9) {
                Some(v) => v,
                None => return,
            };
            (proto, off + ihl * 4, ihl == 5)
        }
        0x86dd => match b(off + 6) {
            Some(proto) => (proto, off + 40, true),
            None => return,
        },
        _ => return,
    };

    let port = |o: usize| match (b(o), b(o + 1)) {
        (Some(hi), Some(lo)) => Some(u16::from_be_bytes([hi, lo])),
        _ => None,
    };

    match proto {
        6 => {
            bump(cat::TCP);
            if matches!(port(l4), Some(443)) || matches!(port(l4 + 2), Some(443)) {
                bump(cat::TCP443);
            }
            let doff = match b(l4 + 12) {
                Some(v) => (v >> 4) as usize,
                None => return,
            };
            let pstart = l4 + doff * 4;
            // TLS record at the actual payload start (any doff).
            if let (Some(t), Some(0x03)) = (b(pstart), b(pstart + 1)) {
                if (0x14..=0x17).contains(&t) {
                    bump(cat::TLS_RECORD);
                    if t == 0x17 && ihl_ok {
                        bump(cat::TLS_APPDATA);
                    }
                }
            }
            // HW rule: pinned doff=8 -> record header expected at l4 + 32.
            if ihl_ok && doff == 8 {
                if let (Some(0x17), Some(0x03)) = (b(l4 + 32), b(l4 + 33)) {
                    bump(cat::TLS_HW);
                }
            }
        }
        17 => {
            bump(cat::UDP);
            if matches!(port(l4), Some(443)) || matches!(port(l4 + 2), Some(443)) {
                bump(cat::UDP443);
            }
            if let Some(b0) = b(l4 + 8) {
                match b0 & 0xc0 {
                    0x40 => {
                        bump(cat::QUIC_SHORT);
                        if ihl_ok {
                            bump(cat::QUIC_HW); // HW QUIC rule (no port constraint)
                        }
                    }
                    0xc0 => bump(cat::QUIC_LONG),
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn report() {
    let g = |i: usize| COUNTS[i].load(Ordering::Relaxed);
    let total = g(cat::TOTAL);
    let pct = |n: u64| if total == 0 { 0.0 } else { 100.0 * n as f64 / total as f64 };

    println!("\n==================== SW classifier (oracle) ====================");
    println!("total bytes: {}", TOTAL_BYTES.load(Ordering::Relaxed));
    for i in 0..cat::N {
        println!("  {:<16}: {:>12}  ({:.2}%)", cat::LABELS[i], g(i), pct(g(i)));
    }

    // Derived comparison: total vs addressable TLS+QUIC vs HW-rule match.
    let hw_match = g(cat::TLS_HW) + g(cat::QUIC_HW);
    let addr_proto = g(cat::TLS_APPDATA) + g(cat::QUIC_SHORT) + g(cat::QUIC_LONG);
    let addr_port = g(cat::TCP443) + g(cat::UDP443);
    println!("----------------------------------------------------------------");
    println!("[1] total traffic         : {}", total);
    println!(
        "[2] addressable TLS+QUIC  : {} (by protocol) | {} (by port 443)",
        addr_proto, addr_port
    );
    println!("[3] HW rules would match  : {}  ({:.2}% of total)", hw_match, pct(hw_match));
    if addr_proto > 0 {
        println!(
            "    HW / addressable      : {:.1}% (proto) | {:.1}% (port)",
            100.0 * hw_match as f64 / addr_proto as f64,
            if addr_port > 0 {
                100.0 * hw_match as f64 / addr_port as f64
            } else {
                0.0
            }
        );
    }
    println!("================================================================\n");
}

#[callback("ipv4 or ipv6,level=InL4Conn")]
fn classify_packet(pdu: &L4Pdu) -> bool {
    classify(pdu.mbuf_ref().data());
    true
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    report();
}
