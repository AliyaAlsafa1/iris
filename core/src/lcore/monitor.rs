use crate::config::RuntimeConfig;
use crate::dpdk;
use crate::lcore::datapath_budget::{self, DatapathBudget};
use crate::lcore::pcie_meter::PcieMeter;
use crate::port::{statistics::PortStats, Port, PortId, RxQueue, RxQueueType};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use chrono::Local;
use csv::Writer;
use serde::Serialize;

/// Preamble + Start Frame Delimiter
const PSFD_SIZE: u64 = 8;
/// Interpacket Gap
const IPG_SIZE: u64 = 12;
/// Frame Checksum
const FCS_SIZE: u64 = 4;

/// A Monitor monitors throughput when running online, displays live statistics
#[derive(Debug)]
pub(crate) struct Monitor {
    duration: Option<Duration>,
    display: Option<Display>,
    logger: Option<Logger>,
    ports: BTreeMap<PortId, Vec<RxQueue>>,
    is_running: Arc<AtomicBool>,
    prev_tcp_bytes: u64,
    prev_udp_bytes: u64,
    /// PCIe root-port bandwidth, sampled by a `pcm-iio` child process.
    pcie: Option<PcieMeter>,
}

impl Monitor {
    pub(crate) fn new(
        config: &RuntimeConfig,
        ports: &BTreeMap<PortId, Port>,
        is_running: Arc<AtomicBool>,
    ) -> Self {
        let date = Local::now();
        let online_cfg = config
            .online
            .as_ref()
            .expect("Not configured for online runtime");

        let duration = online_cfg.duration.map(Duration::from_secs);

        let display = (|| {
            if let Some(monitor_cfg) = &online_cfg.monitor {
                if let Some(display_cfg) = &monitor_cfg.display {
                    return Some(Display {
                        throughput: display_cfg.throughput,
                        pcie: display_cfg.pcie,
                        keywords: display_cfg.port_stats.clone(),
                    });
                }
            }
            None
        })();

        let logger = (|| {
            if let Some(monitor_cfg) = &online_cfg.monitor {
                if let Some(log_cfg) = &monitor_cfg.log {
                    let path = Path::new(&log_cfg.directory)
                        .join(date.format("%Y-%m-%dT%H:%M:%S").to_string());
                    fs::create_dir_all(&path).expect("create log directory");
                    log::info!("Logging to {:?}", path);

                    let toml = toml::to_string(&config).expect("serialize config");
                    let mut config_file =
                        fs::File::create(path.join("config.toml")).expect("create config log");
                    config_file.write_all(toml.as_bytes()).expect("log config");

                    let mut port_wtrs = hashmap! {};
                    for port_id in ports.keys() {
                        let fname = path.join(format!("port{}.csv", port_id));
                        let wtr = Writer::from_path(&fname).expect("create portstat log");
                        port_wtrs.insert(*port_id, wtr);
                    }
                    let budget_wtr = Writer::from_path(path.join("cycle_budget.csv"))
                        .expect("create cycle budget log");
                    return Some(Logger {
                        interval: Duration::from_millis(log_cfg.interval),
                        path,
                        port_wtrs,
                        keywords: log_cfg.port_stats.clone(),
                        budget_wtr,
                        last_budget: Default::default(),
                        last_ingress_pkts: 0,
                        last_ingress_bytes: 0,
                        warned_no_phy: false,
                    });
                }
            }
            None
        })();

        // PCIe monitoring is optional and best-effort: if `pcm-iio` will not run
        // (not installed, not root), log and carry on without it. The root port to
        // follow is derived from the ports' PCI addresses.
        let port_devices: Vec<String> = online_cfg
            .ports
            .iter()
            .map(|port| port.device.clone())
            .collect();
        let pcie = display
            .as_ref()
            .filter(|display| display.pcie)
            .and_then(|_| {
                PcieMeter::spawn(
                    &port_devices,
                    logger.as_ref().map(|logger| logger.path.as_path()),
                )
            });

        let mut monitor_ports: BTreeMap<PortId, Vec<RxQueue>> = BTreeMap::new();
        for (port_id, port) in ports.iter() {
            monitor_ports.insert(*port_id, port.queue_map.keys().cloned().collect());
        }

        Monitor {
            duration,
            display,
            logger,
            ports: monitor_ports,
            is_running,
            prev_tcp_bytes: 0,
            prev_udp_bytes: 0,
            pcie,
        }
    }

    pub(crate) async fn run(&mut self) {
        if let Some(logger) = &mut self.logger {
            logger.init_port_wtrs().expect("port logger init");
            logger.init_budget_wtr().expect("cycle budget logger init");
        }
        // ts of run start
        let start_ts = Instant::now();
        // initial data capture
        let mut init_rx = AggRxStats::default();
        // ts of initial data capture
        let mut init_ts = start_ts;

        let mut prev_rx = init_rx;
        let mut prev_ts = init_ts;
        let mut init = true;
        let mut display_ticker = tokio::time::interval(Duration::from_millis(1000));

        let mut logger_ticker = self
            .logger
            .as_ref()
            .map(|logger| tokio::time::interval(logger.interval));
        // Add a small delay to allow workers to start polling for packets
        tokio::time::sleep(Duration::from_millis(1000)).await;
        while self.is_running.load(Ordering::Relaxed) {
            if let Some(duration) = self.duration {
                if start_ts.elapsed() >= duration {
                    self.is_running.store(false, Ordering::Relaxed);
                }
            }

            if self.display.is_some() {
                display_ticker.tick().await;
                let curr_ts = Instant::now();
                let delta = curr_ts - prev_ts;

                // Snapshot what we need off `display`, then release the borrow so
                // we can mutate self.prev_* below without a borrow conflict.
                let (show_throughput, keywords) = {
                    let display = self.display.as_ref().unwrap();
                    (display.throughput, display.keywords.clone())
                };

                match AggRxStats::collect(&self.ports, &keywords) {
                    Ok(curr_rx) => {
                        #[cfg(feature = "prometheus")]
                        curr_rx.update_prometheus_stats();
                        let nms = delta.as_millis() as f64;
                        if init {
                            init_rx = curr_rx;
                            init_ts = curr_ts;
                            init = false;
                        }
                        if show_throughput {
                            let elapsed_ts = curr_ts - start_ts;
                            println!("----------------------------------------------");
                            println!("Current time: {}", pretty_print_duration(elapsed_ts));
                            // Takes &self.ports (and &self.display); no self mutation here.
                            self.display.as_ref().unwrap().mempool_usage(&self.ports);
                            AggRxStats::display_rates(curr_rx, prev_rx, nms);
                            AggRxStats::display_dropped(curr_rx, init_rx);
                        }
                        prev_rx = curr_rx;
                        prev_ts = curr_ts;

                        // Per-second on-wire TCP/UDP acquired (live, per-core summed).
                        if show_throughput {
                            let (tcp, udp) = crate::lcore::transport_meter::totals();
                            let d_tcp = tcp.saturating_sub(self.prev_tcp_bytes);
                            let d_udp = udp.saturating_sub(self.prev_udp_bytes);
                            self.prev_tcp_bytes = tcp;
                            self.prev_udp_bytes = udp;
                            let secs = nms / 1000.0;
                            if secs > 0.0 {
                                let tcp_bps = (d_tcp as f64) * 8.0 / secs;
                                let udp_bps = (d_udp as f64) * 8.0 / secs;
                                println!(
                                    "Transport: TCP {} / UDP {} / total {}",
                                    pretty_print_unit(tcp_bps, "bps"),
                                    pretty_print_unit(udp_bps, "bps"),
                                    pretty_print_unit(tcp_bps + udp_bps, "bps"),
                                );
                            }
                        }

                        // Per-second PCIe inbound bandwidth for the NIC's root port.
                        if show_throughput {
                            self.display_pcie();
                        }
                    }
                    Err(error) => {
                        log::error!("Monitor display error: {}", error);
                    }
                }
            }

            if let Some(logger) = &mut self.logger {
                logger_ticker.as_mut().unwrap().tick().await;
                match logger.log_stats(init_ts.elapsed()) {
                    Ok(_) => (),
                    Err(error) => log::error!("Monitor log error: {}", error),
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(1000)).await;
        println!("----------------------------------------------");
        let tputs = Throughputs::new(prev_rx, init_rx, (prev_ts - init_ts).as_millis() as f64);
        println!("{}", tputs);

        // Final cumulative on-wire transport totals.
        let (tcp_total, udp_total) = crate::lcore::transport_meter::totals();
        println!(
            "Transport (cumulative on-wire): TCP {} / UDP {} / total {}",
            pretty_print_unit(tcp_total as f64, "B"),
            pretty_print_unit(udp_total as f64, "B"),
            pretty_print_unit((tcp_total + udp_total) as f64, "B"),
        );

        // Final cumulative PCIe inbound totals, per monitored root port.
        if let Some(pcie) = &mut self.pcie {
            for stats in pcie.stats() {
                println!(
                    "PCIe {} (cumulative inbound): write {} bytes / read {} bytes",
                    stats.label, stats.total_write_bytes, stats.total_read_bytes,
                );
            }
        }

        if let Some(logger) = &self.logger {
            let json_fname = logger.path.join("throughputs.json");
            tputs.dump_json(json_fname).expect("Unable to dump to json");
        }
    }

    /// Display the latest PCIe inbound bandwidth sample for each monitored root
    /// port, if PCIe monitoring is on.
    ///
    /// `pcm-iio` samples on its own second, which drifts against this tick, so a tick
    /// may find no new sample; say so rather than reprinting a stale count as if it
    /// covered the last second.
    fn display_pcie(&mut self) {
        let pcie = match &mut self.pcie {
            Some(pcie) => pcie,
            None => return,
        };
        for stats in pcie.stats() {
            match stats.sample {
                Some(sample) => println!(
                    "PCIe {}: in-write {} bytes / in-read {} bytes",
                    stats.label, sample.write_bytes, sample.read_bytes,
                ),
                None if stats.started => println!("PCIe {}: no new sample", stats.label),
                None => println!("PCIe {}: waiting for first sample", stats.label),
            }
        }
    }
}

#[derive(Debug)]
struct Display {
    throughput: bool,
    pcie: bool,
    keywords: Vec<String>,
}

impl Display {
    /// Display mempool usage
    fn mempool_usage(&self, ports: &BTreeMap<PortId, Vec<RxQueue>>) {
        let sockets: BTreeSet<_> = ports.keys().map(|id| id.socket_id()).collect();

        for socket in sockets {
            for prefix in ["standard", "split_header", "split_remainder"] {
                let name = format!("mempool_{}_{}", prefix, socket);
                let cname = CString::new(name.clone()).expect("Invalid CString conversion");
                let mempool_raw = unsafe { dpdk::rte_mempool_lookup(cname.as_ptr()) };
                // The split pools are only allocated when a port runs split queues, so under a
                // non-split flow mode this lookup returns null. Skip rather than hand null to
                // `rte_mempool_avail_count`, which dereferences it.
                if mempool_raw.is_null() {
                    continue;
                }
                let avail_cnt = unsafe { dpdk::rte_mempool_avail_count(mempool_raw) };
                let inuse_cnt = unsafe { dpdk::rte_mempool_in_use_count(mempool_raw) };

                println!(
                    "{} avail: {}, in use: {} ({:.3}%)",
                    name,
                    avail_cnt,
                    inuse_cnt,
                    100.0 * inuse_cnt as f64 / (inuse_cnt + avail_cnt) as f64
                );
            }
        }
    }
}

#[derive(Debug)]
struct Logger {
    interval: Duration,
    path: PathBuf,
    port_wtrs: HashMap<PortId, Writer<std::fs::File>>,
    keywords: Vec<String>,
    /// Per-interval datapath cycle budget, one row per logger tick.
    budget_wtr: Writer<std::fs::File>,
    /// Previous tick's cumulative budget, so each row can be a delta.
    last_budget: DatapathBudget,
    last_ingress_pkts: u64,
    last_ingress_bytes: u64,
    /// Whether the "no rx_phy_*" warning has been issued; once is enough.
    warned_no_phy: bool,
}

impl Logger {
    /// Initialize port statistic CSV writers. Must occur after ports have been started.
    fn init_port_wtrs(&mut self) -> Result<()> {
        for (port_id, wtr) in self.port_wtrs.iter_mut() {
            let port_stats = PortStats::collect(*port_id)?;
            wtr.write_field("ts")?;
            for label in port_stats.stats.keys() {
                if self.keywords.iter().any(|k| label.contains(k)) {
                    wtr.write_field(label)?;
                }
            }
            wtr.write_field("mempool_avail_cnt")?;
            wtr.write_field("mempool_inuse_cnt")?;
            wtr.write_record(None::<&[u8]>)?;
            wtr.flush()?;
        }
        Ok(())
    }

    /// Logs per-port statistics and mempool statistics (per-socket statistics).
    fn log_stats(&mut self, elapsed: Duration) -> Result<()> {
        // Offered load for the cycle budget, taken from the same collect as the port rows so the
        // two describe the same instant. `ok` goes false if any port failed, in which case the
        // budget row is skipped rather than written with a short denominator.
        let (mut phy_pkts, mut phy_bytes, mut ok) = (0u64, 0u64, true);
        let mut missing_phy = false;

        for (port_id, wtr) in self.port_wtrs.iter_mut() {
            let port_stats = PortStats::collect(*port_id);
            match port_stats {
                Ok(port_stats) => {
                    // Read outside the keyword filter: these are the budget's denominator, and a
                    // `[online.monitor.log] port_stats` list that omits them must not delete it.
                    // Not every PMD exposes rx_phy_* (ICE does not), so fall back to rx_good_*,
                    // which undercounts whatever the NIC dropped before software saw it.
                    let get = |k: &str| port_stats.stats.get(k).copied();
                    match (get("rx_phy_packets"), get("rx_phy_bytes")) {
                        (Some(pkts), Some(bytes)) => {
                            phy_pkts += pkts;
                            phy_bytes += bytes;
                        }
                        _ => {
                            missing_phy = true;
                            phy_pkts += get("rx_good_packets").unwrap_or(0);
                            phy_bytes += get("rx_good_bytes").unwrap_or(0);
                        }
                    }

                    wtr.write_field(elapsed.as_millis().to_string())?;
                    for label in port_stats.stats.keys() {
                        if self.keywords.iter().any(|k| label.contains(k)) {
                            if let Some(value) = port_stats.stats.get(label) {
                                wtr.write_field(value.to_string())?;
                            } else {
                                wtr.write_field("-")?;
                            }
                        }
                    }
                }
                Err(error) => {
                    log::error!("{}", error);
                    ok = false;
                }
            }
            let name = format!("mempool_standard_{}", port_id.socket_id());
            let cname = CString::new(name).expect("Invalid CString conversion");
            let mempool_raw = unsafe { dpdk::rte_mempool_lookup(cname.as_ptr()) };
            // The standard pool always exists, unlike the split pools; guarded anyway so a
            // missing one logs zeros instead of dereferencing null.
            let (avail_cnt, inuse_cnt) = if mempool_raw.is_null() {
                (0, 0)
            } else {
                unsafe {
                    (
                        dpdk::rte_mempool_avail_count(mempool_raw),
                        dpdk::rte_mempool_in_use_count(mempool_raw),
                    )
                }
            };
            wtr.write_field(avail_cnt.to_string())?;
            wtr.write_field(inuse_cnt.to_string())?;
            wtr.write_record(None::<&[u8]>)?;
        }
        for wtr in self.port_wtrs.values_mut() {
            wtr.flush()?;
        }

        if missing_phy && !self.warned_no_phy {
            self.warned_no_phy = true;
            log::warn!(
                "a port exposes no rx_phy_* counters, so cycle_budget.csv's ingress_pkts and \
                 ingress_bytes fall back to rx_good_*, which excludes anything the NIC dropped \
                 before software saw it"
            );
        }
        if ok {
            self.log_cycle_budget(elapsed, phy_pkts, phy_bytes)?;
        }
        Ok(())
    }

    /// Write the header for `cycle_budget.csv`.
    ///
    /// Every column except `ts_ms`, `rx_cores_cnt`, `rdtsc_cost_cycles` and the two fractions is
    /// a delta over the logging interval, the same way `pcie.csv`'s `ib_write_bytes` is a
    /// per-second count rather than a running total.
    fn init_budget_wtr(&mut self) -> Result<()> {
        for field in [
            "ts_ms",
            // The four attributed buckets. Disjoint, and they sum to sampled_wall_cycles.
            "poll_busy_cycles",
            "poll_idle_cycles",
            "pipeline_cycles",
            "maint_cycles",
            // Span the buckets were attributed over, and the exact span of the interval. Take
            // fractions against the former and scale by the latter for absolute cycles.
            "sampled_wall_cycles",
            "wall_cycles",
            // Exact counters: never sampled.
            "bursts_cnt",
            "idle_polls_cnt",
            "recv_pkts",
            // Offered load, from rx_phy_* where the PMD provides it.
            "ingress_pkts",
            "ingress_bytes",
            // Constant across the run, recorded per row so a CSV is self-describing.
            "rx_cores_cnt",
            // Per-read rte_rdtsc cost subtracted from each closed span. Zero means attribution
            // is off (budget_sample_stride = 0), which is why a run of zeroed cycle columns is
            // not necessarily a broken file.
            "rdtsc_cost_cycles",
            "idle_fraction",
            "busy_fraction",
            "cycles_per_ingress_pkt",
        ] {
            self.budget_wtr.write_field(field)?;
        }
        self.budget_wtr.write_record(None::<&[u8]>)?;
        self.budget_wtr.flush()?;
        Ok(())
    }

    /// Write one interval's cycle budget, differenced against the previous tick.
    fn log_cycle_budget(&mut self, elapsed: Duration, phy_pkts: u64, phy_bytes: u64) -> Result<()> {
        let now = datapath_budget::current();
        let prev = self.last_budget;
        let diff = |cur: u64, old: u64| cur.saturating_sub(old);

        let d_poll_busy = diff(now.poll_busy, prev.poll_busy);
        let d_poll_idle = diff(now.poll_idle, prev.poll_idle);
        let d_pipeline = diff(now.pipeline, prev.pipeline);
        let d_maint = diff(now.maint, prev.maint);
        let d_sampled_wall = diff(now.sampled_wall, prev.sampled_wall);
        let d_wall = diff(now.wall, prev.wall);
        let d_ingress_pkts = diff(phy_pkts, self.last_ingress_pkts);
        let d_ingress_bytes = diff(phy_bytes, self.last_ingress_bytes);

        // Fractions come from the sample, where they are unbiased; absolute cycles are the
        // fraction scaled by the exact interval span.
        let frac = |part: u64| {
            if d_sampled_wall == 0 {
                0.0
            } else {
                part as f64 / d_sampled_wall as f64
            }
        };
        let busy_fraction = frac(d_poll_busy + d_pipeline + d_maint);
        let work = busy_fraction * d_wall as f64;
        let cycles_per_ingress_pkt = if d_ingress_pkts == 0 {
            0.0
        } else {
            work / d_ingress_pkts as f64
        };

        let row = [
            elapsed.as_millis().to_string(),
            d_poll_busy.to_string(),
            d_poll_idle.to_string(),
            d_pipeline.to_string(),
            d_maint.to_string(),
            d_sampled_wall.to_string(),
            d_wall.to_string(),
            diff(now.bursts, prev.bursts).to_string(),
            diff(now.idle_polls, prev.idle_polls).to_string(),
            diff(now.recv_pkts, prev.recv_pkts).to_string(),
            d_ingress_pkts.to_string(),
            d_ingress_bytes.to_string(),
            now.cores.to_string(),
            now.rdtsc_cost.to_string(),
            format!("{:.6}", frac(d_poll_idle)),
            format!("{:.6}", busy_fraction),
            format!("{:.3}", cycles_per_ingress_pkt),
        ];
        for field in row {
            self.budget_wtr.write_field(field)?;
        }
        self.budget_wtr.write_record(None::<&[u8]>)?;
        self.budget_wtr.flush()?;

        self.last_budget = now;
        self.last_ingress_pkts = phy_pkts;
        self.last_ingress_bytes = phy_bytes;
        Ok(())
    }
}

/// Aggregate RX port statistics at time of collection
#[derive(Debug, Default, Clone, Copy)]
struct AggRxStats {
    ingress_bits: u64,
    ingress_pkts: u64,
    good_bits: u64,
    good_pkts: u64,
    process_bits: u64,
    process_pkts: u64,
    hw_dropped_pkts: u64,
    sw_dropped_pkts: u64,
}

impl AggRxStats {
    /// Collect aggregate statistics, display keyword statistics if `keywords` is not `None`
    fn collect(ports: &BTreeMap<PortId, Vec<RxQueue>>, keywords: &[String]) -> Result<Self> {
        let mut ingress_bytes = 0;
        let mut ingress_pkts = 0;
        let mut good_bytes = 0;
        let mut good_pkts = 0;
        let mut process_bytes = 0;
        let mut process_pkts = 0;
        let mut hw_dropped_pkts = 0;
        let mut sw_dropped_pkts = 0;
        for (port_id, rx_queues) in ports.iter() {
            // All sink queues on this port (TLS/QUIC measure sinks, sampling
            // sink, etc.). Their traffic is excluded from the "reached workers"
            // stat below.
            let sink_qids: Vec<u16> = rx_queues
                .iter()
                .filter(|queue| queue.ty == RxQueueType::Sink)
                .map(|queue| queue.qid.raw())
                .collect();

            match PortStats::collect(*port_id) {
                Ok(port_stats) => {
                    // Ingress (reached NIC)
                    ingress_bytes += match port_stats.stats.get("rx_phy_bytes") {
                        Some(v) => *v,
                        None => {
                            log::warn!("Failed retrieving ingress_bytes, device does not support precise PHY count");
                            0
                        }
                    };
                    ingress_pkts += match port_stats.stats.get("rx_phy_packets") {
                        Some(v) => *v,
                        None => {
                            log::warn!("Failed retrieving ingress_pkts, device does not support precise PHY count");
                            0
                        }
                    };

                    // Good (reached software)
                    let good_bytes_temp = match port_stats.stats.get("rx_good_bytes") {
                        Some(v) => *v,
                        None => {
                            log::warn!("Failed retrieving good_bytes, device does not support precise PHY count");
                            0
                        }
                    };
                    let good_pkts_temp = match port_stats.stats.get("rx_good_packets") {
                        Some(v) => *v,
                        None => {
                            log::warn!("Failed retrieving good_pkts, device does not support precise PHY count");
                            0
                        }
                    };
                    good_bytes += good_bytes_temp;
                    good_pkts += good_pkts_temp;

                    // Process (reached workers) = good minus traffic steered to
                    // every sink queue. Per-queue byte/packet xstats are not
                    // exposed by all PMDs (e.g. ICE); when missing, fall back to
                    // the good total rather than failing the whole display.
                    let mut sink_bytes = 0;
                    let mut sink_pkts = 0;
                    for sink in &sink_qids {
                        match port_stats.stats.get(&format!("rx_q{}_bytes", sink)) {
                            Some(v) => sink_bytes += *v,
                            None => log::debug!(
                                "No per-queue byte xstat for sink queue {}; not excluded from process stats",
                                sink
                            ),
                        }
                        if let Some(v) = port_stats.stats.get(&format!("rx_q{}_packets", sink)) {
                            sink_pkts += *v;
                        }
                    }
                    process_bytes += good_bytes_temp.saturating_sub(sink_bytes);
                    process_pkts += good_pkts_temp.saturating_sub(sink_pkts);

                    // dropped
                    hw_dropped_pkts += match port_stats.stats.get("rx_phy_discard_packets") {
                        Some(v) => *v,
                        None => {
                            log::warn!("Failed retrieving hw_dropped_pkts, device does not support precise packet dropped counter (no hardware drop will be accounted for).");
                            0
                        }
                    };
                    sw_dropped_pkts += match port_stats.stats.get("rx_missed_errors") {
                        Some(v) => *v,
                        None => bail!("Failed retrieving sw_dropped_pkts"),
                    };

                    port_stats.display(keywords);
                }
                Err(error) => bail!(error),
            }
        }
        Ok(AggRxStats {
            ingress_bits: (ingress_bytes + (PSFD_SIZE + IPG_SIZE) * ingress_pkts) * 8,
            ingress_pkts,
            good_bits: (good_bytes + (PSFD_SIZE + IPG_SIZE + FCS_SIZE) * good_pkts) * 8,
            good_pkts,
            process_bits: (process_bytes + (PSFD_SIZE + IPG_SIZE + FCS_SIZE) * process_pkts) * 8,
            process_pkts,
            hw_dropped_pkts,
            sw_dropped_pkts,
        })
    }

    /// Display live bits per second and packets per second between `curr_rx` and `prev_rx`
    fn display_rates(curr_rx: AggRxStats, prev_rx: AggRxStats, nms: f64) {
        println!(
            "Ingress: {} / {}",
            pretty_print_unit(
                (curr_rx.ingress_bits - prev_rx.ingress_bits) as f64 / nms * 1000.0,
                "bps",
            ),
            pretty_print_unit(
                (curr_rx.ingress_pkts - prev_rx.ingress_pkts) as f64 / nms * 1000.0,
                "pps",
            ),
        );
        println!(
            "Good:    {} / {}",
            pretty_print_unit(
                (curr_rx.good_bits - prev_rx.good_bits) as f64 / nms * 1000.0,
                "bps",
            ),
            pretty_print_unit(
                (curr_rx.good_pkts - prev_rx.good_pkts) as f64 / nms * 1000.0,
                "pps",
            ),
        );
        println!(
            "Process: {} / {}",
            pretty_print_unit(
                (curr_rx.process_bits - prev_rx.process_bits) as f64 / nms * 1000.0,
                "bps",
            ),
            pretty_print_unit(
                (curr_rx.process_pkts - prev_rx.process_pkts) as f64 / nms * 1000.0,
                "pps",
            ),
        );
        println!(
            "Drop: {} ({}%)",
            pretty_print_unit(
                (curr_rx.dropped_pkts() - prev_rx.dropped_pkts()) as f64 / nms * 1000.0,
                "pps",
            ),
            100.0
                * ((curr_rx.dropped_pkts() - prev_rx.dropped_pkts()) as f64
                    / (curr_rx.ingress_pkts - prev_rx.ingress_pkts) as f64)
        );
    }

    fn display_dropped(curr_rx: AggRxStats, init_rx: AggRxStats) {
        println!(
            "HW Dropped: {} ({}%)",
            pretty_print_unit(
                (curr_rx.hw_dropped_pkts - init_rx.hw_dropped_pkts) as f64,
                "pkt",
            ),
            100.0
                * ((curr_rx.hw_dropped_pkts - init_rx.hw_dropped_pkts) as f64
                    / (curr_rx.ingress_pkts - init_rx.ingress_pkts) as f64)
        );
        println!(
            "SW Dropped: {} ({}%)",
            pretty_print_unit(
                (curr_rx.sw_dropped_pkts - init_rx.sw_dropped_pkts) as f64,
                "pkt",
            ),
            100.0
                * ((curr_rx.sw_dropped_pkts - init_rx.sw_dropped_pkts) as f64
                    / (curr_rx.ingress_pkts - init_rx.ingress_pkts) as f64)
        );
        println!(
            "Total Dropped: {} ({}%)",
            pretty_print_unit(
                (curr_rx.dropped_pkts() - init_rx.dropped_pkts()) as f64,
                "pkt",
            ),
            100.0
                * ((curr_rx.dropped_pkts() - init_rx.dropped_pkts()) as f64
                    / (curr_rx.ingress_pkts - init_rx.ingress_pkts) as f64)
        );
        println!(
            "Total Packets: {}",
            pretty_print_unit((curr_rx.ingress_pkts - init_rx.ingress_pkts) as f64, "pkt",),
        );
    }

    fn dropped_pkts(&self) -> u64 {
        self.hw_dropped_pkts + self.sw_dropped_pkts
    }

    #[cfg(feature = "prometheus")]
    fn update_prometheus_stats(&self) {
        use crate::stats::DPDK_STATS;
        DPDK_STATS
            .ingress_pkts
            .inc_by(self.ingress_pkts - DPDK_STATS.ingress_pkts.get());
        DPDK_STATS
            .ingress_bits
            .inc_by(self.ingress_bits - DPDK_STATS.ingress_bits.get());
        DPDK_STATS
            .good_pkts
            .inc_by(self.good_pkts - DPDK_STATS.good_pkts.get());
        DPDK_STATS
            .good_bits
            .inc_by(self.good_bits - DPDK_STATS.good_bits.get());
        DPDK_STATS
            .process_pkts
            .inc_by(self.process_pkts - DPDK_STATS.process_pkts.get());
        DPDK_STATS
            .process_bits
            .inc_by(self.process_bits - DPDK_STATS.process_bits.get());
        DPDK_STATS
            .hw_dropped_pkts
            .inc_by(self.hw_dropped_pkts - DPDK_STATS.hw_dropped_pkts.get());
        DPDK_STATS
            .sw_dropped_pkts
            .inc_by(self.sw_dropped_pkts - DPDK_STATS.sw_dropped_pkts.get());
    }
}

#[derive(Debug, Serialize)]
struct Throughputs {
    avg_ingress_bps: f64,
    avg_ingress_pps: f64,
    avg_good_bps: f64,
    avg_good_pps: f64,
    avg_process_bps: f64,
    avg_process_pps: f64,
    hw_dropped_pkts: u64,
    sw_dropped_pkts: u64,
    tot_dropped_pkts: u64,
    percent_dropped: f64,
}

impl Throughputs {
    /// Compute average rates over elapsed time
    fn new(curr_rx: AggRxStats, init_rx: AggRxStats, ems: f64) -> Self {
        Throughputs {
            avg_ingress_bps: (curr_rx.ingress_bits - init_rx.ingress_bits) as f64 / ems * 1000.0,
            avg_ingress_pps: (curr_rx.ingress_pkts - init_rx.ingress_pkts) as f64 / ems * 1000.0,
            avg_good_bps: (curr_rx.good_bits - init_rx.good_bits) as f64 / ems * 1000.0,
            avg_good_pps: (curr_rx.good_pkts - init_rx.good_pkts) as f64 / ems * 1000.0,
            avg_process_bps: (curr_rx.process_bits - init_rx.process_bits) as f64 / ems * 1000.0,
            avg_process_pps: (curr_rx.process_pkts - init_rx.process_pkts) as f64 / ems * 1000.0,
            hw_dropped_pkts: (curr_rx.hw_dropped_pkts - init_rx.hw_dropped_pkts),
            sw_dropped_pkts: (curr_rx.sw_dropped_pkts - init_rx.sw_dropped_pkts),
            tot_dropped_pkts: (curr_rx.dropped_pkts() - init_rx.dropped_pkts()),
            percent_dropped: 100.0
                * ((curr_rx.dropped_pkts() - init_rx.dropped_pkts()) as f64
                    / (curr_rx.ingress_pkts - init_rx.ingress_pkts) as f64),
        }
    }

    fn dump_json(&self, path: PathBuf) -> Result<()> {
        let file = std::fs::File::create(path)?;
        serde_json::to_writer(&file, self)?;
        Ok(())
    }
}

impl fmt::Display for Throughputs {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "AVERAGE Ingress: {} / {} / {}",
            pretty_print_unit(self.avg_ingress_bps, "bps"),
            pretty_print_unit(self.avg_ingress_pps, "pps"),
            format_args!("{} bps", self.avg_process_bps)
        )?;
        writeln!(
            f,
            "AVERAGE Good:    {} / {} / {}",
            pretty_print_unit(self.avg_good_bps, "bps"),
            pretty_print_unit(self.avg_good_pps, "pps"),
            format_args!("{} bps", self.avg_process_bps)
        )?;
        writeln!(
            f,
            "AVERAGE Process: {} / {} / {}",
            pretty_print_unit(self.avg_process_bps, "bps"),
            pretty_print_unit(self.avg_process_pps, "pps"),
            format_args!("{} bps", self.avg_process_bps)
        )?;
        writeln!(
            f,
            "DROPPED: {} ({}%)",
            pretty_print_unit(self.tot_dropped_pkts as f64, "pkt"),
            self.percent_dropped,
        )?;
        Ok(())
    }
}

fn pretty_print_unit(mut value: f64, unit: &str) -> String {
    let kilo_coef = 1000.;
    let mut unit_prefix = "";
    if value > kilo_coef {
        value /= kilo_coef;
        unit_prefix = "k";
        if value > kilo_coef {
            value /= kilo_coef;
            unit_prefix = "M";
            if value > kilo_coef {
                value /= kilo_coef;
                unit_prefix = "G";
            }
        }
    }
    format!("{value:.4} {unit_prefix}{unit}")
}

fn pretty_print_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let days = total_seconds / 86_400;
    let hours = (total_seconds % 86_400) / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    let seconds = total_seconds % 60;

    if days == 0 {
        if hours == 0 {
            if minutes == 0 {
                format!("{seconds}s")
            } else {
                format!("{minutes}m {seconds}s")
            }
        } else {
            format!("{hours}h {minutes}m {seconds}s")
        }
    } else {
        format!("{days}d {hours}h {minutes}m {seconds}s")
    }
}
