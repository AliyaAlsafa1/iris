//! Prints how much of each packet actually reached software, to check trimming.
//!
//! `steer` installs a per-flow QUEUE rule onto the core's split queue (split
//! queues are never fed by RSS), `pkt_size` then reports what arrived.
//!
//! `delivered` is what the NIC handed us; `on_wire` comes from the IP header,
//! which survives trimming. Under `split` and `trim-native-dpdk` both read
//! 64 / 1514 — they differ only in whether the payload crossed PCIe, which the
//! mbuf can't show. Compare NIC `rx_bytes_phy` between runs for that.

use clap::Parser;
use iris_compiler::*;
use iris_core::{
    config::load_config,
    filter::flow_drop::{install_split_flow, SplitQueueMap},
    port::PortId,
    CoreId, FiveTuple, L4Pdu, Runtime,
};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};

static PACKETS: AtomicU64 = AtomicU64::new(0);
static DELIVERED: AtomicU64 = AtomicU64::new(0);
static ON_WIRE: AtomicU64 = AtomicU64::new(0);
static TRIMMED_PKTS: AtomicU64 = AtomicU64::new(0);
static PRINTED: AtomicUsize = AtomicUsize::new(0);
static STEERED_OK: AtomicUsize = AtomicUsize::new(0);
static STEERED_ERR: AtomicUsize = AtomicUsize::new(0);

static PORT_IDS: RwLock<Option<Vec<PortId>>> = RwLock::new(None);
static SPLIT_QUEUES: RwLock<Option<SplitQueueMap>> = RwLock::new(None);
static SEEN: Mutex<Option<HashSet<FiveTuple>>> = Mutex::new(None);

static PRINT_FIRST: OnceLock<usize> = OnceLock::new();
static MAX_FLOWS: OnceLock<usize> = OnceLock::new();

fn print_first() -> usize {
    *PRINT_FIRST.get().unwrap_or(&20)
}

fn max_flows() -> usize {
    *MAX_FLOWS.get().unwrap_or(&64)
}

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

    /// Print per-packet sizes for the first N packets, then only aggregate.
    #[clap(long, default_value = "20")]
    print_first: usize,

    /// Cap on how many flows get a steering rule.
    #[clap(long, default_value = "64")]
    max_flows: usize,
}

/// Steer each new flow to its core's split queue. Rules are flushed when the
/// port stops, so nothing is uninstalled here.
#[callback("(ipv4 or ipv6) and (tcp or udp),level=L4FirstPacket")]
fn steer(five_tuple: &FiveTuple, core_id: &CoreId) {
    let mut guard = SEEN.lock().unwrap();
    let seen = guard.get_or_insert_with(HashSet::new);
    if seen.len() >= max_flows() || !seen.insert(*five_tuple) {
        return;
    }
    drop(guard);

    // One split queue id per port, in the same order as PORT_IDS: queue ids
    // are per port, so the id for this core's port does not carry over.
    let queues = match SPLIT_QUEUES
        .read()
        .unwrap()
        .as_ref()
        .and_then(|m| m.queues_for(*core_id))
    {
        Some(q) => q,
        None => {
            eprintln!("no split queue mapped for {core_id:?}");
            STEERED_ERR.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    let ports = match PORT_IDS.read().unwrap().clone() {
        Some(p) => p,
        None => return,
    };

    match install_split_flow(ports, five_tuple, &queues) {
        Ok(_) => {
            let n = STEERED_OK.fetch_add(1, Ordering::Relaxed) + 1;
            if n <= 8 {
                println!("steered flow {n} -> queues {queues:?} (core {core_id:?})");
            }
        }
        Err(e) => {
            eprintln!("install_split_flow failed: {e:?}");
            STEERED_ERR.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[callback("(ipv4 or ipv6) and (tcp or udp),level=InL4Conn")]
fn pkt_size(pdu: &L4Pdu) -> bool {
    let delivered = pdu.mbuf_ref().data_len();
    let on_wire = pdu.offset() + pdu.length();
    let trimmed = on_wire.saturating_sub(delivered);

    PACKETS.fetch_add(1, Ordering::Relaxed);
    DELIVERED.fetch_add(delivered as u64, Ordering::Relaxed);
    ON_WIRE.fetch_add(on_wire as u64, Ordering::Relaxed);
    if trimmed > 0 {
        TRIMMED_PKTS.fetch_add(1, Ordering::Relaxed);
    }

    // fetch_update so the Nth print is exact with several RX cores racing.
    let n = print_first();
    if n > 0
        && PRINTED
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |p| {
                (p < n).then_some(p + 1)
            })
            .is_ok()
    {
        println!("delivered={delivered:>5} B  on_wire={on_wire:>5} B  trimmed={trimmed:>5} B");
    }

    true
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let _ = PRINT_FIRST.set(args.print_first);
    let _ = MAX_FLOWS.set(args.max_flows);
    let config = load_config(&args.config);

    // Queue layout per port: sink qids first, then q(2i)=receive q(2i+1)=split
    // per core. Queue ids are per port, so this map is keyed by core AND port.
    if let Some(online) = &config.online {
        let map = SplitQueueMap::from_config(online);
        println!("split queue map: {map:?}");
        *SPLIT_QUEUES.write().unwrap() = Some(map);
    }

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config.clone(), filter).unwrap();

    if let Some(online) = &config.online {
        let port_ids: Vec<PortId> = online
            .ports
            .iter()
            .map(|p| PortId::new_from_device(p.device.clone()))
            .collect();
        println!("ports: {port_ids:?}");
        *PORT_IDS.write().unwrap() = Some(port_ids);
    }

    runtime.run();

    let pkts = PACKETS.load(Ordering::Relaxed);
    let delivered = DELIVERED.load(Ordering::Relaxed);
    let on_wire = ON_WIRE.load(Ordering::Relaxed);
    let trimmed_pkts = TRIMMED_PKTS.load(Ordering::Relaxed);
    let trimmed = on_wire.saturating_sub(delivered);

    println!("\n--- trim check ---");
    println!(
        "flows steered     : {} (errors: {})",
        STEERED_OK.load(Ordering::Relaxed),
        STEERED_ERR.load(Ordering::Relaxed)
    );
    println!("packets seen      : {pkts}");
    if pkts == 0 {
        println!("No packets reached the callback.");
        return;
    }
    println!(
        "packets trimmed   : {trimmed_pkts} ({:.1}%)",
        100.0 * trimmed_pkts as f64 / pkts as f64
    );
    println!(
        "delivered to SW   : {delivered} B ({:.1} B/pkt)",
        delivered as f64 / pkts as f64
    );
    println!(
        "on-wire (IP hdr)  : {on_wire} B ({:.1} B/pkt)",
        on_wire as f64 / pkts as f64
    );
    println!(
        "trimmed away      : {trimmed} B ({:.1}% of on-wire)",
        100.0 * trimmed as f64 / on_wire.max(1) as f64
    );
    if trimmed == 0 {
        println!("\nNothing trimmed: flow_mode leaves packets whole, or no traffic matched.");
    }
}
