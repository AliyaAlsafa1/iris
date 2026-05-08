// src/bin/flow_preinstall.rs
use clap::Parser;
use lazy_static::lazy_static;

use iris_core::{
    config::{default_config, load_config},
    filter::flow_drop::{install_drop_flow, uninstall_flow},
    port::PortId,
    rte_flow,
//    CoreId,
    FiveTuple,
    Runtime,
};
use iris_datatypes::TlsHandshake;
use iris_compiler::{callback, input_files, iris_end_macros};

use rand::Rng;
use std::{
    collections::{HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Mutex, RwLock},
    thread,
};

// ---------- CLI ----------
#[derive(Parser, Debug)]
struct Args {
    /// Retina config
    #[clap(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// How many flows to pre-install (exact-match drop rules)
    #[clap(long, default_value = "1000")]
    num_flows: usize,

    /// Milliseconds to wait after starting the runtime before installing flows
    /// (gives ports time to be fully up)
    #[clap(long, default_value = "500")]
    warmup_ms: u64,

    /// If set, we will uninstall all installed rules on exit (Ctrl-C)
    #[clap(long)]
    uninstall_on_exit: bool,
}

// ---------- globals (same style as your test) ----------
#[derive(Clone, Copy)]
struct FlowPtr(*mut rte_flow);
unsafe impl Send for FlowPtr {}
unsafe impl Sync for FlowPtr {}

#[derive(Clone)]
struct FlowEntry {
    tuple: FiveTuple,
    ports: Vec<PortId>,
    flow_ptrs: Vec<FlowPtr>,
}

lazy_static! {
    static ref PORT_IDS: RwLock<Option<Vec<PortId>>> = RwLock::new(None);
    static ref INSTALLED: Mutex<Vec<FlowEntry>> = Mutex::new(Vec::new());
    static ref TARGET_SET: Mutex<HashSet<FiveTuple>> = Mutex::new(HashSet::new());
}

// ---------- helpers ----------
fn random_ipv4(a: u8, b: u8) -> Ipv4Addr {
    // Use 10.a.b.x to avoid overlapping pktgen ranges like 192.168.x.x
    let mut rng = rand::thread_rng();
    Ipv4Addr::new(10, a, b, rng.gen_range(2..=250))
}

fn mk_tuple(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, sport: u16, dport: u16) -> FiveTuple {
    FiveTuple {
        orig: SocketAddr::new(IpAddr::V4(src), sport),
        resp: SocketAddr::new(IpAddr::V4(dst), dport),
        proto: proto as usize, // 6=tcp, 17=udp
    }
}

// Not used
#[callback("tls")]
fn tls_cb(_tls: &TlsHandshake) {}

// ---------- main ----------
#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    let args = Args::parse();

    // 1) Load config
    let config = if let Some(p) = args.config.clone() {
        load_config(p)
    } else {
        default_config()
    };

    // 2) Initialize EAL/runtime *first*
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config.clone(), filter).unwrap();

    // 3) Now that EAL is initialized, resolve PortIds
    if let Some(online) = &config.online {
        let port_ids: Vec<PortId> = online
            .ports
            .iter()
            .map(|p| {
                println!("Device: {}", p.device);
                PortId::new_from_device(p.device.clone())
            })
            .collect();

        for pid in &port_ids {
            println!("Port ID: {:?}", pid);
        }
        *PORT_IDS.write().unwrap() = Some(port_ids);
    } else {
        eprintln!("No online ports in config; exiting.");
        return;
    }

    // 4) Spawn the installer thread
    let num_flows = args.num_flows;
    let warmup_ms = args.warmup_ms;
    let uninstall_on_exit = args.uninstall_on_exit;

    let installer = std::thread::spawn(move || {
        use std::time::Duration;

        // Give ports time to come up
        std::thread::sleep(Duration::from_millis(warmup_ms));

        // Grab PortIds and only use the first (PortId(0)) for flow install
        let ports = {
            let guard = PORT_IDS.read().unwrap();
            let all = guard.as_ref().cloned().expect("PORT_IDS not set");

            if all.is_empty() {
                panic!("No ports available in PORT_IDS");
            }

            // Only install on the first port to avoid "port not started" errors
            vec![all[0].clone()]
        };

        let mut rng = rand::thread_rng();
        let mut installed = 0usize;

        for i in 0..num_flows {
            let src = random_ipv4((i % 200) as u8, ((i / 200) % 200) as u8);
            let dst = random_ipv4(((i + 37) % 200) as u8, (((i + 37) / 200) % 200) as u8);
            let tcp = rng.gen_bool(0.5);
            let proto = if tcp { 6u8 } else { 17u8 };
            let sport = 10000 + (i as u16 % 50000);
            let dport = 20000 + (i as u16 % 45535);
            let tuple = mk_tuple(src, dst, proto, sport, dport);

            match install_drop_flow(ports.clone(), &tuple) {
                Ok(raws) => {
                    TARGET_SET.lock().unwrap().insert(tuple.clone());
                    INSTALLED.lock().unwrap().push(FlowEntry {
                        tuple,
                        ports: ports.clone(),
                        flow_ptrs: raws.into_iter().map(FlowPtr).collect(),
                    });
                    installed += 1;
                    if installed % 10000 == 0 || installed == num_flows {
                       // eprintln!("[loss_test] installed {} / {} flows", installed, num_flows);
                    }
                }
                Err(e) => eprintln!("[loss_test] install failed at {}: {:?}", i, e),
            }
        }

        eprintln!(
            "[loss_test] DONE: installed {} flows across {} port(s).",
            installed,
            ports.len()
        );

        // Note: uninstall is handled after runtime.run() in main when uninstall_on_exit is true
        if uninstall_on_exit {
            eprintln!(
                "[loss_test] uninstall_on_exit is set; flows will be removed after runtime finishes."
            );
        }
    });

    // 5) Run the runtime on the main thread (blocks for online.duration)
    runtime.run();

    // 6) Uninstall all flows on exit if requested
    if args.uninstall_on_exit {
        eprintln!(
            "[loss_test] uninstall_on_exit set — uninstalling {} flows...",
            INSTALLED.lock().unwrap().len()
        );
        let mut inst = INSTALLED.lock().unwrap();
        for entry in inst.drain(..) {
            let raw_ptrs: Vec<*mut rte_flow> =
                entry.flow_ptrs.iter().map(|fp| fp.0).collect();
            if let Err(e) = uninstall_flow(entry.ports.clone(), raw_ptrs) {
                eprintln!("[loss_test] uninstall error: {:?}", e);
            }
        }
        eprintln!("[loss_test] uninstall complete.");
    }

    let _ = installer.join();
}