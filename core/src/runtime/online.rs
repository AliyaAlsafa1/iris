use crate::config::{ConnTrackConfig, FlowTableConfig, OnlineConfig, RuntimeConfig};
use crate::dpdk;
use crate::filter::flow_drop::RawAction;
use crate::filter::Filter;
use crate::lcore::monitor::Monitor;
use crate::lcore::rx_core::RxCore;
use crate::lcore::{CoreId, SocketId};
use crate::memory::mempool::{Mempool, SplitMempool};
use crate::port::*;
use crate::runtime::SPLIT_HDR_SIZE;
use crate::subscription::*;

use std::collections::BTreeMap;
use std::os::raw::{c_uint, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub(crate) struct OnlineRuntime<S>
where
    S: Subscribable,
{
    ports: BTreeMap<PortId, Port>,
    rx_cores: BTreeMap<CoreId, RxCore<S>>,
    monitor: Option<Monitor>,
    filter: Filter,
    options: OnlineOptions,
}

impl<S> OnlineRuntime<S>
where
    S: Subscribable,
{
    pub(crate) fn new(
        config: &RuntimeConfig,
        options: OnlineOptions,
        standard_mempools: &mut BTreeMap<SocketId, Mempool>,
        split_mempools: &mut BTreeMap<SocketId, SplitMempool>,
        hw_filter_str: String,
        subscription: Arc<Subscription<S>>,
    ) -> Self {
        let hw_filter = Filter::new(&hw_filter_str, &[]).expect("Failed to parse collapsed filter");
        // Set up signal handler
        let is_running = Arc::new(AtomicBool::new(true));
        let r = Arc::clone(&is_running);
        ctrlc::set_handler(move || {
            r.store(false, Ordering::Relaxed);
        })
        .expect("Error setting Ctrl-C handler");

        log::info!("Initializing Ports...");
        let mut ports: BTreeMap<PortId, Port> = BTreeMap::new();
        for port_map in options.online.ports.iter() {
            let port = Port::new(port_map, options.online.flow_mode);
            let socket_id = port.id.socket_id();
            let mtu = if let Some(online) = &config.online {
                online.mtu
            } else {
                Mempool::default_mtu()
            };
            standard_mempools.entry(socket_id).or_insert_with(|| {
                Mempool::new(&config.mempool, socket_id, mtu, "standard")
                    .expect("Unable to initialize standard mempool")
            });
            split_mempools.entry(socket_id).or_insert_with(|| {
                SplitMempool::new(&config.mempool, socket_id, SPLIT_HDR_SIZE, mtu)
                    .expect("Unable to initialize split mempool")
            });
            port.init(
                standard_mempools,
                split_mempools,
                options.online.nb_rxd,
                options.online.mtu,
                options.online.promiscuous,
            )
            .expect("Failed to initialize port.");
            ports.insert(port.id, port);
        }

        log::info!("Initializing RX Cores...");
        let mut rx_cores: BTreeMap<CoreId, RxCore<S>> = BTreeMap::new();
        let mut core_map: BTreeMap<CoreId, Vec<RxQueue>> = BTreeMap::new();
        for port in ports.values() {
            for (rxqueue, core_id) in port.queue_map.iter() {
                core_map.entry(*core_id).or_default().push(*rxqueue);
            }
        }
        for (core_id, rxqueues) in core_map.into_iter() {
            let rx_core = RxCore::new(
                core_id,
                rxqueues,
                options.conntrack.clone(),
                options.flow_table.clone(),
                options.online.budget_sample_stride,
                #[cfg(feature = "prometheus")]
                options.online.prometheus.is_some(),
                Arc::clone(&subscription),
                Arc::clone(&is_running),
            );
            rx_cores.insert(core_id, rx_core);
        }

        let monitor = Some(Monitor::new(config, &ports, Arc::clone(&is_running)));

        OnlineRuntime {
            ports,
            rx_cores,
            monitor,
            filter: hw_filter,
            options,
        }
    }

    pub(crate) fn run(&mut self) {
        self.start_ports();

        // Declare the cycle-budget denominator up front. Sink cores are excluded: they run
        // `rx_sink`, which does no pipeline work and publishes no budget. Setting this before
        // launch (rather than counting cores as they exit) is what lets the monitor report a
        // per-core duty cycle while the run is still going.
        let budget_cores = self
            .rx_cores
            .values()
            .filter(|rx_core| rx_core.rxqueues.first().map(|q| q.ty) != Some(RxQueueType::Sink))
            .count();
        crate::stats::set_datapath_cores(budget_cores as u64);

        log::info!("Launching RX cores...");
        for core_id in self.rx_cores.keys() {
            let role = unsafe { dpdk::rte_eal_lcore_role(core_id.raw()) };
            if role != dpdk::rte_lcore_role_t_ROLE_RTE {
                log::error!("Attempted to launch non-DPDK core");
                panic!();
            }

            let arg = &self.rx_cores as *const _ as *mut c_void;
            let ret = unsafe {
                dpdk::rte_eal_remote_launch(Some(launch_rx::<S>), arg, core_id.raw() as c_uint)
            };
            if ret != 0 {
                log::error!("RX Core {} busy, launch failed.", core_id);
                panic!();
            }
        }

        // run main thread
        self.run_main();
        unsafe { dpdk::rte_eal_mp_wait_lcore() };

        log::info!("Exiting loop...");
        self.stop_ports();
    }

    fn run_main(&mut self) {
        let id = unsafe { dpdk::rte_lcore_id() };
        log::info!("Running main on Core {}", id);
        let start = Instant::now();
        let tokio_runtime = tokio::runtime::Builder::new_current_thread() // Use a current-thread runtime
            .enable_all() // Enables all necessary features (I/O, time, etc.)
            .build()
            .expect("Failed to create Tokio runtime");
        let mut monitor = self.monitor.take().unwrap();
        tokio_runtime.block_on(async move {
            let jh1 = tokio::spawn(async move {
                monitor.run().await;
            });
            #[cfg(feature = "prometheus")]
            if let Some(prometheus) = self.options.online.prometheus {
                use hyper::service::service_fn;
                use hyper_util::rt::TokioIo;
                use tokio::net::TcpListener;
                tokio::spawn(async move {
                    let listener = TcpListener::bind((prometheus.ip, prometheus.port))
                        .await
                        .expect("failed to run prometheus server");
                    loop {
                        let Ok((socket, _)) = listener.accept().await else {
                            eprintln!("Prometheus server accept failed");
                            break;
                        };
                        let socket = TokioIo::new(socket);
                        tokio::spawn(async move {
                            if let Err(e) = hyper::server::conn::http1::Builder::new()
                                .serve_connection(socket, service_fn(crate::stats::serve_req))
                                .await
                            {
                                eprintln!("Prometheus server error: {}", e);
                            }
                        });
                    }
                });
            }
            jh1.await.unwrap();
        });
        println!("Main done. Ran for {:?}", start.elapsed());
    }

    fn start_ports(&self) {
        log::info!("Starting ports...");
        let measure = self.options.online.measure_raw_drop;
        for port in self.ports.values() {
            port.start();

            // In measurement mode the raw rules steer matches to dedicated sink
            // queues (counted by the sink core) instead of dropping in hardware.
            // With two sinks, TLS steers to the first and QUIC to the second so
            // each protocol is counted separately.
            let (tls_action, quic_action) = if measure {
                let sink_qids: Vec<u16> = port
                    .queue_map
                    .keys()
                    .filter(|rxq| rxq.ty == RxQueueType::Sink)
                    .map(|rxq| rxq.qid.raw())
                    .collect();
                match sink_qids.as_slice() {
                    [] => {
                        log::warn!(
                            "measure_raw_drop set but no sink queue on port {}; falling back to hardware drop. Add [[online.ports.sinks]] to count matches.",
                            port.id
                        );
                        (RawAction::Drop, RawAction::Drop)
                    }
                    [only] => {
                        log::warn!(
                            "measure_raw_drop on port {}: only one sink queue ({}); TLS and QUIC both steer to it (counts combined). Add a second sink for per-protocol granularity.",
                            port.id,
                            only
                        );
                        (RawAction::Steer(*only), RawAction::Steer(*only))
                    }
                    [tls_q, quic_q, ..] => {
                        log::info!(
                            "Raw drop MEASURE mode on port {}: TLS -> sink queue {}, QUIC -> sink queue {}",
                            port.id,
                            tls_q,
                            quic_q
                        );
                        (RawAction::Steer(*tls_q), RawAction::Steer(*quic_q))
                    }
                }
            } else {
                (RawAction::Drop, RawAction::Drop)
            };

            if self.options.online.dyn_hardware_assist {
                log::info!("Applying dynamic hardware filters...");
                self.filter
                    .set_dynamic_hardware_filters(port)
                    .unwrap_or_else(|e| {
                        panic!(
                            "Dynamic hardware filter install failed on Port {}: {}",
                            port.id, e
                        )
                    });
            } else if self.options.online.hardware_assist {
                log::info!("Applying hardware filters...");
                let res = self.filter.set_hardware_filter(port);
                if let Err(error) = res {
                    log::warn!("Failed to apply some patterns, passing all traffic through Port {}. Reason: {}", port.id, error);
                };
            } else {
                log::info!("No hardware assist configured for port {}, passing all traffic through device.", port.id);
            }

            if self.options.online.drop_tls_raw {
                log::info!(
                    "Installing TLS Application-Data raw rule on port {}",
                    port.id
                );
                if let Err(e) =
                    crate::filter::flow_drop::install_tls_appdata_drop(port.id, tls_action)
                {
                    log::warn!(
                        "TLS Application-Data raw rule install failed on port {}: {:?}",
                        port.id,
                        e
                    );
                }
            }
            if self.options.online.drop_quic_raw {
                log::info!("Installing QUIC short-header raw rule on port {}", port.id);
                if let Err(e) =
                    crate::filter::flow_drop::install_quic_short_drop(port.id, quic_action)
                {
                    log::warn!(
                        "QUIC short-header raw rule install failed on port {}: {:?}",
                        port.id,
                        e
                    );
                }
            }
        }
    }

    fn stop_ports(&self) {
        log::info!("Stopping ports...");
        for port in self.ports.values() {
            port.stop();
        }
    }
}

/// Read-only runtime options for the offline core
#[derive(Debug)]
pub(crate) struct OnlineOptions {
    pub(crate) online: OnlineConfig,
    pub(crate) conntrack: ConnTrackConfig,
    pub(crate) flow_table: Option<FlowTableConfig>,
}

extern "C" fn launch_rx<S>(arg: *mut c_void) -> i32
where
    S: Subscribable,
{
    // enforce that workers cores cannot mutate runtime
    // NICE-TO-HAVE: make this *const and use Mutex for interior mutability
    let rx_cores = arg as *const BTreeMap<CoreId, RxCore<S>>;
    let rx_cores = unsafe { &*rx_cores };

    let core_id = CoreId(unsafe { dpdk::rte_lcore_id() } as u32);
    let rx_core = rx_cores.get(&core_id).expect("Invalid Core");

    // TODO: if the hardware takes care of the whole packet filter, we can skip the packet filter.
    rx_core.rx_loop();
    0
}
