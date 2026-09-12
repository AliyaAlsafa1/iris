//! Utilities for managing and monitoring Iris cores.

pub mod datapath_budget;
pub mod dram_meter;
pub(crate) mod monitor;
pub mod pcie_meter;
// pub(crate) mod ring;
pub(crate) mod rx_core;
pub mod transport_meter;

use crate::dpdk;

use std::fmt;
use std::os::unix::process::CommandExt;
use std::process::Command;

use serde::{Deserialize, Serialize};

/* --------------------------------------------------------------------------------- */

/// Arrange for `cmd`'s child to be killed when this process dies.
///
/// The meters kill their child from `Drop`, which covers a clean exit and an
/// unwinding panic but not a process that dies without running destructors --
/// SIGKILL, a fatal signal, a second Ctrl-C. An orphaned `pcm-*` is reparented
/// to init and keeps sampling for as long as the machine is up, and until DPDK
/// duplicated its uverbs FD with `F_DUPFD_CLOEXEC` such a child also held the
/// NIC's device memory hostage.
///
/// Two things to know about the parent-death signal. It fires when the spawning
/// *thread* exits, not the process, so this is only correct from a thread that
/// lives as long as the run -- both callers spawn from the main thread. And the
/// kernel clears it across an exec of a set-user-ID binary, so a setuid `pcm-*`
/// still relies on the `Drop` path.
pub(crate) fn die_with_parent(cmd: &mut Command) {
    let parent = nix::unistd::getpid();
    // SAFETY: the closure runs between fork and exec, where only
    // async-signal-safe calls are allowed. prctl(2), getppid(2) and _exit(2)
    // all are; nothing here allocates or takes a lock.
    unsafe {
        cmd.pre_exec(move || {
            nix::sys::prctl::set_pdeathsig(Some(nix::sys::signal::Signal::SIGTERM))?;
            // Close the race: if the parent died between the fork and the call
            // above, the signal has already been missed and this child would
            // outlive it anyway.
            if nix::unistd::getppid() != parent {
                std::process::exit(0);
            }
            Ok(())
        });
    }
}

#[derive(Debug, Copy, Clone, Hash, Ord, Eq, PartialEq, PartialOrd)]
pub(crate) struct SocketId(pub(crate) u32);

impl SocketId {
    // For DPDK functions
    pub(crate) fn raw(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for SocketId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/* --------------------------------------------------------------------------------- */

/// An identifier for a core running Iris (sink, monitoring, or RX).
#[derive(Debug, Copy, Clone, Hash, Ord, Eq, PartialEq, PartialOrd, Deserialize, Serialize)]
pub struct CoreId(pub u32);

impl CoreId {
    pub(crate) fn socket_id(&self) -> SocketId {
        unsafe { SocketId(dpdk::rte_lcore_to_socket_id(self.0)) }
    }

    /// The core ID as u32, primarily for DPDK functions
    pub fn raw(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for CoreId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
