//! Iris runtime.
//!
//! The runtime initializes the DPDK environment abstraction layer, creates memory pools, launches
//! the packet processing cores, and manages logging and display output.

mod offline;
mod online;
use self::offline::*;
use self::online::*;

use crate::config::*;
use crate::dpdk;
use crate::filter::FilterFactory;
use crate::lcore::SocketId;
use crate::memory::mempool::{Mempool, SplitMempool};
use crate::subscription::*;

use std::collections::BTreeMap;
use std::ffi::CString;
use std::sync::Arc;

use anyhow::{bail, Result};

pub(crate) const SPLIT_HDR_SIZE: u16 = 64;

/// The Iris runtime.
///
/// The runtime initializes the DPDK environment abstraction layer, creates memory pools, launches
/// the packet processing cores, and manages logging and display output.
pub struct Runtime<S>
where
    S: Subscribable,
{
    #[allow(dead_code)]
    standard_mempools: BTreeMap<SocketId, Mempool>,
    #[allow(dead_code)]
    split_mempools: BTreeMap<SocketId, SplitMempool>,
    online: Option<OnlineRuntime<S>>,
    pub(crate) offline: Option<OfflineRuntime<S>>, // Public for testing only
    #[cfg(feature = "timing")]
    subscription: Arc<Subscription<S>>,
}

impl<S> Runtime<S>
where
    S: Subscribable,
{
    /// Creates a new runtime from the `config` settings, filter, and callback.
    ///
    /// # Remarks
    ///
    /// The `factory` parameter is a macro-generated function pointer based on the user-defined
    /// filter string, and must take the value "`filter`". `cb` is the name of the user-defined
    /// callback function.
    ///
    /// # Example
    ///
    /// let mut runtime = Runtime::new(config, filter, callback)?;
    pub fn new(config: RuntimeConfig, factory: fn() -> FilterFactory<S::Tracked>) -> Result<Self> {
        let factory = factory();
        let filter_str = factory.hw_filter_str.clone();
        let subscription = Arc::new(Subscription::new(factory));

        println!("Initializing Iris runtime...");
        log::info!("Initializing EAL...");
        dpdk::load_drivers();
        {
            let eal_params = config.get_eal_params();
            let eal_params_len = eal_params.len() as i32;

            let args: Vec<CString> = eal_params
                .into_iter()
                .map(|arg| CString::new(arg).unwrap())
                .collect();
            let ptrs: Vec<*mut u8> = args.iter().map(|s| s.as_ptr() as *mut u8).collect();

            let ret = unsafe { dpdk::rte_eal_init(eal_params_len, ptrs.as_ptr() as *mut _) };
            if ret < 0 {
                bail!("Failure initializing EAL");
            }
        }

        log::info!("Initializing Mempools...");
        let mut standard_mempools: BTreeMap<SocketId, Mempool> = BTreeMap::new();
        let mut split_mempools: BTreeMap<SocketId, SplitMempool> = BTreeMap::new();
        let socket_ids = config.get_all_socket_ids();
        let mtu = if let Some(online) = &config.online {
            online.mtu
        } else if let Some(offline) = &config.offline {
            offline.mtu
        } else {
            Mempool::default_mtu()
        };
        for socket_id in socket_ids {
            log::debug!("Socket ID: {}", socket_id);
            standard_mempools.insert(
                socket_id,
                Mempool::new(&config.mempool, socket_id, mtu, "standard")?,
            );
            split_mempools.insert(
                socket_id,
                SplitMempool::new(&config.mempool, socket_id, SPLIT_HDR_SIZE, mtu)?,
            );
        }

        // Enable the software flow table iff the config provides a [flow_table]
        // section; otherwise no table is allocated and installs are no-ops.
        crate::filter::sw_flow::set_enabled(config.flow_table.is_some());

        let online = config.online.as_ref().map(|cfg| {
            log::info!("Initializing Online Runtime...");
            let online_opts = OnlineOptions {
                online: cfg.clone(),
                conntrack: config.conntrack.clone(),
                flow_table: config.flow_table.clone(),
            };
            OnlineRuntime::new(
                &config,
                online_opts,
                &mut standard_mempools,
                &mut split_mempools,
                filter_str.clone(),
                Arc::clone(&subscription),
            )
        });

        let offline = config.offline.as_ref().map(|cfg| {
            log::info!("Initializing Offline Analysis...");
            let offline_opts = OfflineOptions {
                offline: cfg.clone(),
                conntrack: config.conntrack.clone(),
                flow_table: config.flow_table.clone(),
            };
            OfflineRuntime::new(offline_opts, &standard_mempools, Arc::clone(&subscription))
        });

        log::info!("Runtime ready.");
        Ok(Runtime {
            standard_mempools,
            split_mempools,
            online,
            offline,
            #[cfg(feature = "timing")]
            subscription,
        })
    }

    /// Run Iris for the duration specified in the configuration or until `ctrl-c` to terminate.
    ///
    /// # Example
    ///
    /// runtime.run();
    pub fn run(&mut self) {
        self.run_hooked(None);
    }

    /// Like [`Runtime::run`], but invokes `pre_stop` after the RX cores have exited and before the
    /// ports are stopped.
    ///
    /// Stopping a port flushes its hardware flow rules and calls `rte_eth_dev_stop`, which frees
    /// every `rte_flow` and indirect action handle the port owns. An application that installed
    /// rules and wants to read their counters back, or that runs a worker still issuing
    /// `rte_flow_create`, must therefore finish that work *before* the stop — after `run` returns
    /// the handles are already dangling and touching them is a use-after-free. This hook is that
    /// window.
    ///
    /// Offline mode has no ports to stop, so the hook simply runs after the replay finishes.
    ///
    /// # Example
    ///
    /// runtime.run_with_pre_stop(|| read_back_flow_counters());
    pub fn run_with_pre_stop(&mut self, mut pre_stop: impl FnMut()) {
        self.run_hooked(Some(&mut pre_stop));
    }

    fn run_hooked(&mut self, pre_stop: Option<&mut dyn FnMut()>) {
        if let Some(online) = &mut self.online {
            online.run(pre_stop);
        } else if let Some(offline) = &self.offline {
            offline.run();
            if let Some(pre_stop) = pre_stop {
                pre_stop();
            }
        } else {
            log::error!("No runtime");
        }
        #[cfg(feature = "timing")]
        {
            self.subscription.timers.display_stats();
            self.subscription.timers.dump_stats();
        }
        log::info!("Done.");
    }
}
