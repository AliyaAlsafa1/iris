//! PCIe inbound-bandwidth meter driven by Intel PCM (`pcm-iio`).
//!
//! Spawns `pcm-iio 1 -csv` as a child process and follows its CSV stream on a
//! background thread, keeping the most recent sample for each monitored PCIe
//! root port. `pcm-iio` samples once a second, so each sample is the exact
//! number of bytes that crossed the root port in the last second; the monitor
//! prints those counts alongside the on-wire ingress rate, so PCIe-side traffic
//! can be compared directly against what the NIC reports having received.
//!
//! Which root port to follow is derived from the PCI addresses already in
//! `[[online.ports]]` (see [`PcieTarget::derive`]), so no extra topology has to
//! be spelled out in the config.
//!
//! This is instrumentation only: if `pcm-iio` is missing or cannot open the
//! MSRs (it needs root), we log once and the run continues without PCIe stats.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use csv::Writer;

/// Column indices used when the CSV header cannot be interpreted.
/// `Socket0,IIO Stack 2 - PCIe2,Part0 (...),<IB write>,<IB read>,...`
const DEFAULT_WRITE_COL: usize = 3;
const DEFAULT_READ_COL: usize = 4;

/// Where PCI topology is read from. Overridden by the tests.
const SYSFS: &str = "/sys";

/// Intel PCM's IIO tool, resolved on `PATH`.
const PCM_IIO: &str = "pcm-iio";

/// `pcm-iio` sampling interval, in seconds. One second, so every sample is
/// directly a per-second byte count.
const INTERVAL: &str = "1";

/// The `pcm-iio` row a device's traffic shows up in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcieTarget {
    /// CPU package the root port hangs off.
    pub socket: u32,
    /// IIO stack index within the socket (`IIO Stack <n>` in `pcm-iio` output).
    pub stack: u32,
    /// Root port within the stack (`Part<n>` in `pcm-iio` output).
    pub part: u32,
    /// What this target was derived from, for display.
    pub device: String,
}

impl PcieTarget {
    /// Derive the (socket, stack, part) of the root port above a PCI device.
    ///
    /// PCM numbers IIO stacks per socket in root-bus order, and numbers parts by
    /// the device number of the root port within the stack, so all three fall out
    /// of sysfs:
    ///
    /// ```text
    /// /sys/bus/pci/devices/0000:3b:00.0
    ///   -> /sys/devices/pci0000:3a/0000:3a:00.0/0000:3b:00.0
    ///           root complex ^        ^ root port
    /// ```
    ///
    /// Socket 0 owns root buses 00, 17, 3a, 5d on a two-socket Xeon Scalable box,
    /// so bus 3a is its third stack (`IIO Stack 2`), and root port `3a:00.0` is
    /// device 0, i.e. `Part0`.
    pub fn derive(device: &str) -> Result<Self> {
        Self::derive_in(Path::new(SYSFS), device)
    }

    fn derive_in(sysfs: &Path, device: &str) -> Result<Self> {
        let link = sysfs.join("bus/pci/devices").join(device);
        let path = fs::canonicalize(&link)
            .with_context(|| format!("no PCI device {} in {}", device, link.display()))?;

        // .../pci0000:3a/0000:3a:00.0/[...]/0000:3b:00.0
        let names: Vec<String> = path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let root_idx = names
            .iter()
            .position(|name| name.starts_with("pci") && name.contains(':'))
            .ok_or_else(|| anyhow!("no PCI root complex in {}", path.display()))?;
        let (domain, bus) = parse_root_complex(&names[root_idx])?;

        // The root port is the device directly below the root complex; PCM counts
        // traffic there, however deep the NIC itself sits behind it.
        let root_port = names
            .get(root_idx + 1)
            .ok_or_else(|| anyhow!("no root port above {}", device))?;
        let part = root_port_device_number(root_port)?;

        let socket = socket_of_device(&path)?;
        let stack = stack_index(sysfs, socket, domain, bus)?;

        Ok(PcieTarget {
            socket,
            stack,
            part,
            device: device.to_owned(),
        })
    }

    fn label(&self) -> String {
        format!(
            "{} (Socket{} IIO Stack {} Part{})",
            self.device, self.socket, self.stack, self.part
        )
    }

    /// Does this `pcm-iio` CSV row describe this target?
    fn matches(&self, fields: &[&str]) -> bool {
        fields.len() >= 5
            && fields[0] == format!("Socket{}", self.socket)
            && matches_stack(fields[1], self.stack)
            && matches_part(fields[2], self.part)
    }
}

/// `"pci0000:3a"` -> (domain 0x0000, bus 0x3a).
fn parse_root_complex(name: &str) -> Result<(u32, u32)> {
    let rest = name
        .strip_prefix("pci")
        .ok_or_else(|| anyhow!("not a root complex: {}", name))?;
    let (domain, bus) = rest
        .split_once(':')
        .ok_or_else(|| anyhow!("not a root complex: {}", name))?;
    Ok((
        u32::from_str_radix(domain, 16)?,
        u32::from_str_radix(bus, 16)?,
    ))
}

/// `"0000:3a:00.0"` -> device number 0x00, which is the `Part` index.
fn root_port_device_number(bdf: &str) -> Result<u32> {
    let (_, device_function) = bdf
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("not a PCI address: {}", bdf))?;
    let (device, _) = device_function
        .split_once('.')
        .ok_or_else(|| anyhow!("not a PCI address: {}", bdf))?;
    Ok(u32::from_str_radix(device, 16)?)
}

/// CPU package a PCI device is attached to, by BDF.
pub(crate) fn socket_of_pci_device(device: &str) -> Result<u32> {
    socket_of_pci_device_in(Path::new(SYSFS), device)
}

/// [`socket_of_pci_device`] against an arbitrary sysfs root, for the tests.
pub(crate) fn socket_of_pci_device_in(sysfs: &Path, device: &str) -> Result<u32> {
    let link = sysfs.join("bus/pci/devices").join(device);
    let path = fs::canonicalize(&link)
        .with_context(|| format!("no PCI device {} in {}", device, link.display()))?;
    socket_of_device(&path)
}

/// CPU package of a PCI device, via the package of its local CPUs. Falls back to
/// the NUMA node, which is the same number unless sub-NUMA clustering is on.
fn socket_of_device(device_path: &Path) -> Result<u32> {
    let sysfs = sysfs_root(device_path)?;
    if let Some(cpu) =
        read_trimmed(&device_path.join("local_cpulist")).and_then(|list| first_cpu(&list))
    {
        let package = sysfs
            .join("devices/system/cpu")
            .join(format!("cpu{}", cpu))
            .join("topology/physical_package_id");
        if let Some(id) = read_trimmed(&package).and_then(|id| id.parse::<u32>().ok()) {
            return Ok(id);
        }
    }
    match read_trimmed(&device_path.join("numa_node")).and_then(|id| id.parse::<i32>().ok()) {
        Some(node) if node >= 0 => Ok(node as u32),
        _ => bail!("cannot determine socket of {}", device_path.display()),
    }
}

/// Recover the sysfs mount point from a `.../devices/pci0000:3a/...` path.
fn sysfs_root(device_path: &Path) -> Result<PathBuf> {
    let mut path = device_path;
    while let Some(parent) = path.parent() {
        if path.file_name().is_some_and(|name| name == "devices") {
            return Ok(parent.to_path_buf());
        }
        path = parent;
    }
    bail!("no sysfs root above {}", device_path.display())
}

/// Position of this root bus among the root buses of its socket, ascending,
/// which is how PCM numbers IIO stacks.
fn stack_index(sysfs: &Path, socket: u32, domain: u32, bus: u32) -> Result<u32> {
    let devices = sysfs.join("devices");
    let mut buses: Vec<(u32, u32)> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();

    for entry in fs::read_dir(&devices)
        .with_context(|| format!("cannot list {}", devices.display()))?
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        let (root_domain, root_bus) = match parse_root_complex(&name) {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };
        match socket_of_root_complex(&entry.path()) {
            Some(root_socket) if root_socket == socket => buses.push((root_domain, root_bus)),
            Some(_) => (),
            // A root complex whose socket we cannot read would shift every index
            // after it, so say so rather than silently mis-numbering.
            None => unresolved.push(name),
        }
    }

    if !unresolved.is_empty() {
        log::warn!(
            "PCIe topology: no socket for root complex(es) {}; derived stack index may be off",
            unresolved.join(", ")
        );
    }

    buses.sort_unstable();
    buses
        .iter()
        .position(|entry| *entry == (domain, bus))
        .map(|index| index as u32)
        .ok_or_else(|| {
            anyhow!(
                "root bus {:04x}:{:02x} not found on socket {}",
                domain,
                bus,
                socket
            )
        })
}

/// Socket of a root complex, taken from the first child device that reports one.
fn socket_of_root_complex(path: &Path) -> Option<u32> {
    let children = fs::read_dir(path).ok()?;
    for child in children.flatten() {
        if !child.file_name().to_string_lossy().contains(':') {
            continue;
        }
        if let Ok(socket) = socket_of_device(&child.path()) {
            return Some(socket);
        }
    }
    None
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|contents| contents.trim().to_owned())
}

/// First CPU of a `local_cpulist` such as `"0-17,36-53"`.
fn first_cpu(list: &str) -> Option<u32> {
    list.split(',')
        .next()?
        .split('-')
        .next()?
        .trim()
        .parse()
        .ok()
}

/// One `pcm-iio` sample for one root port: the bytes it moved in one second.
#[derive(Debug, Clone, Copy)]
pub struct PcieSample {
    /// Monotonic sample counter; unchanged between reads means no new sample.
    pub seq: u64,
    /// Inbound (device -> host) write bytes, exactly as `pcm-iio` counted them.
    pub write_bytes: u64,
    /// Inbound (host <- device) read bytes, exactly as `pcm-iio` counted them.
    pub read_bytes: u64,
}

/// What the monitor prints for one target on a display tick.
#[derive(Debug, Clone)]
pub struct PcieStats {
    pub label: String,
    /// Latest sample, if one has arrived since the previously displayed one.
    pub sample: Option<PcieSample>,
    /// `true` once at least one sample has ever arrived for this target.
    pub started: bool,
    pub total_write_bytes: u64,
    pub total_read_bytes: u64,
}

#[derive(Debug, Default)]
struct Shared {
    seq: AtomicU64,
    write_bytes: AtomicU64,
    read_bytes: AtomicU64,
    total_write_bytes: AtomicU64,
    total_read_bytes: AtomicU64,
}

#[derive(Debug)]
struct TargetState {
    target: PcieTarget,
    label: String,
    shared: Shared,
}

/// Handle to the `pcm-iio` child and its reader thread. Dropping it kills the
/// child, which in turn ends the reader thread.
#[derive(Debug)]
pub struct PcieMeter {
    targets: Arc<Vec<TargetState>>,
    /// Sequence number last handed out per target, to spot stale samples.
    displayed: Vec<u64>,
    child: Child,
}

impl PcieMeter {
    /// Derive the root port of every monitored device, then spawn `pcm-iio` and
    /// start following its output. Returns `None` if no target could be derived
    /// or the process could not be started (not installed, not permitted, ...).
    ///
    /// `port_devices` are the PCI addresses from `[[online.ports]]`: one root port is
    /// followed per port.
    ///
    /// If `log_dir` is given, every sample is also appended to `pcie.csv` there.
    pub fn spawn(port_devices: &[String], log_dir: Option<&Path>) -> Option<Self> {
        let targets = resolve_targets(port_devices);
        if targets.is_empty() {
            log::error!("PCIe monitor disabled: no root port to follow");
            return None;
        }
        for target in &targets {
            log::info!("PCIe monitor: following {}", target.label());
        }

        let mut cmd = Command::new(PCM_IIO);
        cmd.arg(INTERVAL)
            .arg("-csv")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null());
        crate::lcore::die_with_parent(&mut cmd);

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(error) => {
                log::error!(
                    "PCIe monitor disabled: failed to spawn `{}`: {}",
                    PCM_IIO,
                    error
                );
                return None;
            }
        };

        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                log::error!("PCIe monitor disabled: no stdout from `{}`", PCM_IIO);
                let _ = child.kill();
                return None;
            }
        };

        let wtr = log_dir.and_then(|dir| open_log(&dir.join("pcie.csv")));

        let states: Vec<TargetState> = targets
            .into_iter()
            .map(|target| TargetState {
                label: target.label(),
                target,
                shared: Shared::default(),
            })
            .collect();
        let displayed = vec![0; states.len()];
        let states = Arc::new(states);

        let reader_states = Arc::clone(&states);
        thread::Builder::new()
            .name("pcie-meter".to_owned())
            .spawn(move || {
                read_loop(BufReader::new(stdout), &reader_states, wtr);
            })
            .ok()?;

        log::info!("PCIe monitor: `{} {} -csv`", PCM_IIO, INTERVAL);

        Some(PcieMeter {
            targets: states,
            displayed,
            child,
        })
    }

    /// Per-target stats since the last call. `sample` is `None` when `pcm-iio`
    /// has produced nothing new for that target, so a stale rate is never
    /// reprinted as if it were current.
    pub fn stats(&mut self) -> Vec<PcieStats> {
        let mut stats = Vec::with_capacity(self.targets.len());
        for (index, state) in self.targets.iter().enumerate() {
            let seq = state.shared.seq.load(Ordering::Acquire);
            let fresh = seq != 0 && seq != self.displayed[index];
            if fresh {
                self.displayed[index] = seq;
            }
            stats.push(PcieStats {
                label: state.label.clone(),
                sample: fresh.then(|| PcieSample {
                    seq,
                    write_bytes: state.shared.write_bytes.load(Ordering::Relaxed),
                    read_bytes: state.shared.read_bytes.load(Ordering::Relaxed),
                }),
                started: seq != 0,
                total_write_bytes: state.shared.total_write_bytes.load(Ordering::Relaxed),
                total_read_bytes: state.shared.total_read_bytes.load(Ordering::Relaxed),
            });
        }
        stats
    }
}

impl Drop for PcieMeter {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One target per configured port, derived from its PCI address.
fn resolve_targets(port_devices: &[String]) -> Vec<PcieTarget> {
    port_devices
        .iter()
        .filter_map(|device| match PcieTarget::derive(device) {
            Ok(target) => Some(target),
            Err(error) => {
                log::error!(
                    "PCIe monitor: cannot locate root port of {}: {:#}",
                    device,
                    error
                );
                None
            }
        })
        .collect()
}

fn open_log(path: &Path) -> Option<Writer<fs::File>> {
    let mut wtr = match Writer::from_path(path) {
        Ok(wtr) => wtr,
        Err(error) => {
            log::error!("PCIe log disabled: {}", error);
            return None;
        }
    };
    let header = [
        "ts_ms",
        "device",
        "socket",
        "stack",
        "part",
        "ib_write_bytes",
        "ib_read_bytes",
    ];
    match wtr
        .write_record(header)
        .and_then(|_| wtr.flush().map_err(Into::into))
    {
        Ok(_) => Some(wtr),
        Err(error) => {
            log::error!("PCIe log disabled: {}", error);
            None
        }
    }
}

fn read_loop<R: BufRead>(reader: R, targets: &[TargetState], mut wtr: Option<Writer<fs::File>>) {
    let mut write_col = DEFAULT_WRITE_COL;
    let mut read_col = DEFAULT_READ_COL;
    let mut logged_header = false;
    let mut logged_row = vec![false; targets.len()];

    let start = Instant::now();

    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                log::error!("PCIe monitor read error: {}", error);
                break;
            }
        };

        // Interval boundary: `pcm-iio` reprints the column header each round.
        if line.starts_with("Socket,Name") {
            if let Some((w, r)) = header_columns(&line) {
                write_col = w;
                read_col = r;
            }
            if !logged_header {
                log::info!(
                    "PCIe header: {} (using columns {} write / {} read)",
                    line.trim(),
                    write_col,
                    read_col
                );
                logged_header = true;
            }
            continue;
        }

        let fields: Vec<&str> = line.trim().split(',').map(|field| field.trim()).collect();
        for (index, state) in targets.iter().enumerate() {
            if !state.target.matches(&fields) {
                continue;
            }
            if !logged_row[index] {
                log::info!("PCIe row for {}: {}", state.label, line.trim());
                logged_row[index] = true;
            }

            let write_bytes = fields
                .get(write_col)
                .and_then(|f| parse_bytes(f))
                .unwrap_or(0);
            let read_bytes = fields
                .get(read_col)
                .and_then(|f| parse_bytes(f))
                .unwrap_or(0);

            let shared = &state.shared;
            shared.write_bytes.store(write_bytes, Ordering::Relaxed);
            shared.read_bytes.store(read_bytes, Ordering::Relaxed);
            shared
                .total_write_bytes
                .fetch_add(write_bytes, Ordering::Relaxed);
            shared
                .total_read_bytes
                .fetch_add(read_bytes, Ordering::Relaxed);
            // Publish last: a non-zero seq means every field above is readable.
            shared.seq.fetch_add(1, Ordering::Release);

            if let Some(wtr) = wtr.as_mut() {
                let record = [
                    start.elapsed().as_millis().to_string(),
                    state.target.device.clone(),
                    state.target.socket.to_string(),
                    state.target.stack.to_string(),
                    state.target.part.to_string(),
                    write_bytes.to_string(),
                    read_bytes.to_string(),
                ];
                if let Err(error) = wtr
                    .write_record(record)
                    .and_then(|_| wtr.flush().map_err(Into::into))
                {
                    log::error!("PCIe log write error: {}", error);
                }
            }
        }
    }

    for state in targets.iter() {
        if state.shared.seq.load(Ordering::Relaxed) == 0 {
            log::error!(
                "PCIe monitor produced no samples for {}. `pcm-iio` needs root; run it by \
                 hand to check the derived socket/stack/part against its output.",
                state.label
            );
        }
    }
}

/// Locate the inbound write / read columns from the CSV header, if it names them.
fn header_columns(header: &str) -> Option<(usize, usize)> {
    let mut write = None;
    let mut read = None;
    for (idx, field) in header.split(',').enumerate() {
        let field = field.trim().to_ascii_lowercase();
        if write.is_none() && field.contains("write") {
            write = Some(idx);
        } else if read.is_none() && field.contains("read") {
            read = Some(idx);
        }
    }
    match (write, read) {
        (Some(w), Some(r)) => Some((w, r)),
        _ => None,
    }
}

/// `"IIO Stack 2 - PCIe2"` matches stack 2 (but not stack 20).
fn matches_stack(field: &str, stack: u32) -> bool {
    let mut tokens = field.split_whitespace();
    while let Some(token) = tokens.next() {
        if token.eq_ignore_ascii_case("stack") {
            return tokens.next().and_then(|n| n.parse::<u32>().ok()) == Some(stack);
        }
    }
    false
}

/// `"Part0 (1st x16/x8/x4)"` matches part 0 (but not part 01).
fn matches_part(field: &str, part: u32) -> bool {
    field.split_whitespace().next() == Some(format!("Part{}", part).as_str())
}

/// Byte count from one CSV cell. `pcm-iio` prints plain integers in CSV mode
/// (scaled units are the `-human-readable` format), but tolerate a float or an
/// empty cell rather than dropping the sample.
fn parse_bytes(field: &str) -> Option<u64> {
    if field.is_empty() {
        return Some(0);
    }
    match field.parse::<u64>() {
        Ok(bytes) => Some(bytes),
        Err(_) => field.parse::<f64>().ok().map(|value| value as u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::symlink;

    /// A two-socket Xeon Scalable topology: root buses 00/17/3a/5d on socket 0,
    /// 80/85/ae/d7 on socket 1, with a NIC at 0000:3b:00.0 behind root port
    /// 0000:3a:00.0 and another at 0000:d8:00.0 behind 0000:d7:00.0.
    fn fake_sysfs() -> PathBuf {
        let root = std::env::temp_dir().join(format!("iris-pcie-sysfs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        for (cpu, package) in [(0u32, 0u32), (18, 1)] {
            let topology = root.join(format!("devices/system/cpu/cpu{}/topology", cpu));
            fs::create_dir_all(&topology).unwrap();
            fs::write(
                topology.join("physical_package_id"),
                format!("{}\n", package),
            )
            .unwrap();
        }

        // (root bus, socket, cpulist, endpoint below the root port)
        let complexes = [
            (0x00, "0-17", None),
            (0x17, "0-17", None),
            (0x3a, "0-17", Some("0000:3b:00.0")),
            (0x5d, "0-17", None),
            (0x80, "18-35", None),
            (0x85, "18-35", None),
            (0xae, "18-35", None),
            (0xd7, "18-35", Some("0000:d8:00.0")),
        ];
        for (bus, cpulist, endpoint) in complexes {
            let root_port = format!("0000:{:02x}:00.0", bus);
            let port_path = root
                .join(format!("devices/pci0000:{:02x}", bus))
                .join(&root_port);
            fs::create_dir_all(&port_path).unwrap();
            fs::write(port_path.join("local_cpulist"), format!("{}\n", cpulist)).unwrap();

            let leaf = match endpoint {
                Some(endpoint) => {
                    let leaf = port_path.join(endpoint);
                    fs::create_dir_all(&leaf).unwrap();
                    fs::write(leaf.join("local_cpulist"), format!("{}\n", cpulist)).unwrap();
                    (endpoint.to_owned(), leaf)
                }
                None => (root_port.clone(), port_path.clone()),
            };

            let links = root.join("bus/pci/devices");
            fs::create_dir_all(&links).unwrap();
            let _ = symlink(&leaf.1, links.join(&leaf.0));
        }
        root
    }

    #[test]
    fn derives_target_from_pci_address() {
        let sysfs = fake_sysfs();

        let nic = PcieTarget::derive_in(&sysfs, "0000:3b:00.0").unwrap();
        assert_eq!((nic.socket, nic.stack, nic.part), (0, 2, 0));

        let other = PcieTarget::derive_in(&sysfs, "0000:d8:00.0").unwrap();
        assert_eq!((other.socket, other.stack, other.part), (1, 3, 0));

        assert!(PcieTarget::derive_in(&sysfs, "0000:99:00.0").is_err());
        fs::remove_dir_all(&sysfs).unwrap();
    }

    #[test]
    fn matches_derived_row() {
        let target = PcieTarget {
            socket: 0,
            stack: 2,
            part: 0,
            device: "0000:3b:00.0".to_owned(),
        };
        let row = "Socket0,IIO Stack 2 - PCIe2,Part0 (1st x16/x8/x4),9821,147,0";
        let fields: Vec<&str> = row.split(',').collect();
        assert!(target.matches(&fields));

        let other = "Socket0,IIO Stack 20 - PCIe2,Part0 (1st x16/x8/x4),9821,147,0";
        assert!(!target.matches(&other.split(',').collect::<Vec<_>>()));
    }

    #[test]
    fn parses_pci_addresses() {
        assert_eq!(parse_root_complex("pci0000:3a").unwrap(), (0, 0x3a));
        assert!(parse_root_complex("system").is_err());
        assert_eq!(root_port_device_number("0000:3a:02.0").unwrap(), 2);
        assert_eq!(first_cpu("0-17,36-53").unwrap(), 0);
    }

    #[test]
    fn parses_byte_counts() {
        assert_eq!(parse_bytes("10485760"), Some(10485760));
        assert_eq!(parse_bytes(""), Some(0));
        assert_eq!(parse_bytes("1024.0"), Some(1024));
        assert_eq!(parse_bytes("n/a"), None);
    }

    #[test]
    fn header_columns_by_name() {
        let header = "Socket,Name,Part,IB write,IB read,CPU read,CPU write";
        assert_eq!(header_columns(header), Some((3, 4)));
    }
}
