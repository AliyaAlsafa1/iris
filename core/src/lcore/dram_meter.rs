//! DRAM bandwidth meter driven by Intel PCM (`pcm-memory`).
//!
//! Spawns `pcm-memory 1 -csv` as a child process and follows its CSV stream on a
//! background thread, keeping the most recent read/write sample for each socket a
//! monitored port is attached to. `pcm-memory` samples once a second, so each
//! sample covers the last second; the monitor prints those counts alongside the
//! PCIe inbound figures, so DRAM traffic can be compared directly against what
//! the NIC DMA'd into the host.
//!
//! Same shape as [`super::pcie_meter`] deliberately: subprocess scraper, one
//! reader thread, atomics published behind a release `seq`, its own CSV, and
//! every failure path logging and carrying on rather than panicking.
//!
//! # These are bytes derived from a printed rate
//!
//! PCM computes `MB/s` as `CAS count x 64 / 1e6 / seconds`, so converting back
//! recovers the underlying byte count -- but only to the precision `pcm-memory`
//! prints, which at 100Gbps-class rates is coarse. This is a converted rate, not
//! a counter read, and the CSV column comment says so.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use csv::Writer;

use super::pcie_meter::socket_of_pci_device;

/// Intel PCM's memory tool, resolved on `PATH`.
const PCM_MEMORY: &str = "pcm-memory";

/// `pcm-memory` sampling interval, in seconds. One second, so every sample is
/// directly a per-second byte count.
const INTERVAL: &str = "1";

/// Seconds each sample covers, matching [`INTERVAL`].
const INTERVAL_SECS: f64 = 1.0;

/// `Date` and `Time` lead every data row before the first socket's columns.
const DEFAULT_LEAD_COLS: usize = 2;

/// Columns `pcm-memory -nc` prints per socket: read, write, and their total.
/// Only used if the header cannot be interpreted at all.
const DEFAULT_COLS_PER_SOCKET: usize = 3;

/// One socket's read/write column positions in the `pcm-memory` CSV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketColumns {
    socket: u32,
    read_col: usize,
    write_col: usize,
}

/// A socket whose DRAM traffic is being followed, and the ports that put it there.
#[derive(Debug, Clone)]
pub struct DramTarget {
    pub socket: u32,
    /// PCI addresses of the monitored ports on this socket. More than one is normal.
    pub devices: Vec<String>,
}

impl DramTarget {
    fn label(&self) -> String {
        format!("socket{}", self.socket)
    }
}

/// One interval's DRAM traffic for one socket.
#[derive(Debug, Clone, Copy)]
pub struct DramSample {
    /// Bytes read from DRAM in the last interval, converted from `pcm-memory`'s MB/s.
    pub read_bytes: u64,
    /// Bytes written to DRAM in the last interval, converted from `pcm-memory`'s MB/s.
    pub write_bytes: u64,
}

/// What the monitor prints for one socket on a display tick.
#[derive(Debug, Clone)]
pub struct DramStats {
    pub label: String,
    /// Latest sample, if one has arrived since the previously displayed one.
    pub sample: Option<DramSample>,
    /// `true` once at least one sample has ever arrived for this socket.
    pub started: bool,
    pub total_read_bytes: u64,
    pub total_write_bytes: u64,
}

#[derive(Debug, Default)]
struct Shared {
    seq: AtomicU64,
    read_bytes: AtomicU64,
    write_bytes: AtomicU64,
    total_read_bytes: AtomicU64,
    total_write_bytes: AtomicU64,
}

#[derive(Debug)]
struct TargetState {
    target: DramTarget,
    label: String,
    shared: Shared,
}

/// Handle to the `pcm-memory` child and its reader thread. Dropping it kills the
/// child, which in turn ends the reader thread.
#[derive(Debug)]
pub struct DramMeter {
    targets: Arc<Vec<TargetState>>,
    /// Sequence number last handed out per target, to spot stale samples.
    displayed: Vec<u64>,
    child: Child,
}

impl DramMeter {
    /// Resolve the socket of every monitored device, then spawn `pcm-memory` and
    /// start following its output. Returns `None` if no socket could be resolved
    /// or the process could not be started (not installed, not permitted, ...).
    ///
    /// `port_devices` are the PCI addresses from `[[online.ports]]`. Ports sharing a
    /// socket collapse into one target, since DRAM traffic is per socket, not per port.
    ///
    /// If `log_dir` is given, every sample is also appended to `dram.csv` there.
    pub fn spawn(port_devices: &[String], log_dir: Option<&Path>) -> Option<Self> {
        let targets = resolve_targets(port_devices);
        if targets.is_empty() {
            log::error!("DRAM monitor disabled: no socket to follow");
            return None;
        }
        for target in &targets {
            log::info!(
                "DRAM monitor: following {} ({})",
                target.label(),
                target.devices.join(", ")
            );
        }

        let mut cmd = Command::new(PCM_MEMORY);
        // -nc drops the per-channel columns, leaving the per-socket groups this parses.
        // -silent suppresses the banner so only header and data reach stdout.
        // -f forces a flush per sample: stdout is a pipe here, so without it libc
        // block-buffers and samples arrive in 4 KiB clumps minutes apart.
        cmd.arg(INTERVAL)
            .arg("-csv")
            .arg("-nc")
            .arg("-silent")
            .arg("-f")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null());

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(error) => {
                log::error!(
                    "DRAM monitor disabled: failed to spawn `{}`: {}",
                    PCM_MEMORY,
                    error
                );
                return None;
            }
        };

        let stdout = match child.stdout.take() {
            Some(stdout) => stdout,
            None => {
                log::error!("DRAM monitor disabled: no stdout from `{}`", PCM_MEMORY);
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        };

        let wtr = log_dir.and_then(|dir| open_log(&dir.join("dram.csv")));

        let states: Arc<Vec<TargetState>> = Arc::new(
            targets
                .into_iter()
                .map(|target| TargetState {
                    label: target.label(),
                    target,
                    shared: Shared::default(),
                })
                .collect(),
        );
        let displayed = vec![0; states.len()];

        let reader_states = Arc::clone(&states);
        thread::Builder::new()
            .name("dram-meter".to_owned())
            .spawn(move || {
                read_loop(BufReader::new(stdout), &reader_states, wtr);
            })
            .ok()?;

        log::info!("DRAM monitor: `{} {} -csv -nc`", PCM_MEMORY, INTERVAL);
        Some(DramMeter {
            targets: states,
            displayed,
            child,
        })
    }

    /// Latest sample per socket, or `None` for a socket with nothing new since the
    /// previous call.
    pub fn stats(&mut self) -> Vec<DramStats> {
        let mut stats = Vec::with_capacity(self.targets.len());
        for (index, state) in self.targets.iter().enumerate() {
            let seq = state.shared.seq.load(Ordering::Acquire);
            let fresh = seq != 0 && seq != self.displayed[index];
            if fresh {
                self.displayed[index] = seq;
            }
            stats.push(DramStats {
                label: state.label.clone(),
                sample: fresh.then(|| DramSample {
                    read_bytes: state.shared.read_bytes.load(Ordering::Relaxed),
                    write_bytes: state.shared.write_bytes.load(Ordering::Relaxed),
                }),
                started: seq != 0,
                total_read_bytes: state.shared.total_read_bytes.load(Ordering::Relaxed),
                total_write_bytes: state.shared.total_write_bytes.load(Ordering::Relaxed),
            });
        }
        stats
    }
}

impl Drop for DramMeter {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One target per socket that hosts at least one monitored port.
fn resolve_targets(port_devices: &[String]) -> Vec<DramTarget> {
    let mut by_socket: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for device in port_devices {
        match socket_of_pci_device(device) {
            Ok(socket) => by_socket.entry(socket).or_default().push(device.clone()),
            Err(error) => {
                log::error!(
                    "DRAM monitor: cannot resolve socket of {}: {:#}",
                    device,
                    error
                )
            }
        }
    }
    by_socket
        .into_iter()
        .map(|(socket, devices)| DramTarget { socket, devices })
        .collect()
}

fn open_log(path: &Path) -> Option<Writer<fs::File>> {
    let mut wtr = match Writer::from_path(path) {
        Ok(wtr) => wtr,
        Err(error) => {
            log::error!("DRAM log disabled: {}", error);
            return None;
        }
    };
    let header = [
        // Relative to this reader thread's start, as in pcie.csv, so the two are joinable
        // with each other. The monitor's own clock is not available here.
        "ts_ms",
        "socket",
        // Monitored ports on this socket, ';'-separated. A socket's traffic is not
        // attributable to one of them.
        "devices",
        // Bytes over the last interval, converted from pcm-memory's MB/s -- a derived
        // count, not a counter read. See the module docs.
        "dram_read_bytes",
        "dram_write_bytes",
    ];
    match wtr
        .write_record(header)
        .and_then(|_| wtr.flush().map_err(Into::into))
    {
        Ok(_) => Some(wtr),
        Err(error) => {
            log::error!("DRAM log disabled: {}", error);
            None
        }
    }
}

fn read_loop<R: BufRead>(reader: R, targets: &[TargetState], mut wtr: Option<Writer<fs::File>>) {
    let mut columns: Vec<SocketColumns> = Vec::new();
    let mut logged_header = false;
    let mut prev_line = String::new();

    let start = Instant::now();

    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                log::error!("DRAM monitor read error: {}", error);
                break;
            }
        };

        // `pcm-memory`'s header is two lines: a group row naming SKT<n>/System, then a
        // metric row starting `Date,Time`. Resolving on the second means the first is
        // still in hand, which is where the socket numbers are.
        if line.starts_with("Date,Time") {
            columns = header_columns(&prev_line, &line);
            let guessed = columns.is_empty();
            if guessed {
                columns = fallback_columns(targets);
            }
            // Once only: pcm-memory may reprint its header every interval.
            if !logged_header {
                logged_header = true;
                if guessed {
                    log::warn!(
                        "DRAM monitor: could not read pcm-memory's header ({} | {}); guessing {} \
                         lead columns and {} per socket. Check `pcm-memory 1 -csv -nc` by hand.",
                        prev_line.trim(),
                        line.trim(),
                        DEFAULT_LEAD_COLS,
                        DEFAULT_COLS_PER_SOCKET
                    );
                } else {
                    log::info!("DRAM header: {} (resolved {:?})", line.trim(), columns);
                }
            }
            prev_line = line;
            continue;
        }

        if columns.is_empty() {
            prev_line = line;
            continue;
        }

        let fields: Vec<&str> = line.trim().split(',').map(|field| field.trim()).collect();
        for state in targets.iter() {
            let cols = match columns.iter().find(|c| c.socket == state.target.socket) {
                Some(cols) => cols,
                None => continue,
            };
            let read_bytes = fields
                .get(cols.read_col)
                .and_then(|f| parse_mb_per_s(f))
                .map(mb_per_s_to_bytes);
            let write_bytes = fields
                .get(cols.write_col)
                .and_then(|f| parse_mb_per_s(f))
                .map(mb_per_s_to_bytes);
            let (read_bytes, write_bytes) = match (read_bytes, write_bytes) {
                (Some(r), Some(w)) => (r, w),
                _ => continue,
            };

            let shared = &state.shared;
            shared.read_bytes.store(read_bytes, Ordering::Relaxed);
            shared.write_bytes.store(write_bytes, Ordering::Relaxed);
            shared
                .total_read_bytes
                .fetch_add(read_bytes, Ordering::Relaxed);
            shared
                .total_write_bytes
                .fetch_add(write_bytes, Ordering::Relaxed);
            // Publish last: a non-zero seq means every field above is readable.
            shared.seq.fetch_add(1, Ordering::Release);

            if let Some(wtr) = wtr.as_mut() {
                let record = [
                    start.elapsed().as_millis().to_string(),
                    state.target.socket.to_string(),
                    state.target.devices.join(";"),
                    read_bytes.to_string(),
                    write_bytes.to_string(),
                ];
                if let Err(error) = wtr
                    .write_record(record)
                    .and_then(|_| wtr.flush().map_err(Into::into))
                {
                    log::error!("DRAM log write error: {}", error);
                }
            }
        }
        prev_line = line;
    }

    for state in targets.iter() {
        if state.shared.seq.load(Ordering::Relaxed) == 0 {
            log::error!(
                "DRAM monitor produced no samples for {}. `pcm-memory` needs root; run \
                 `pcm-memory 1 -csv -nc` by hand and check that it prints a SKT{} column group.",
                state.label,
                state.target.socket
            );
        }
    }
}

/// Resolve each socket's read/write columns from `pcm-memory`'s two header lines.
///
/// `groups` names the column groups (`SKT0`, `System`, ...), `metrics` names each column
/// (`Mem Read (MB/s)`, ...). Columns are found by name rather than position, so a change
/// in how many metrics PCM prints per socket does not silently shift the reading.
///
/// Only `SKT<n>` groups yield targets. That is what excludes the trailing `System` group,
/// whose metrics are the bare words `Read`/`Write` and would otherwise match.
fn header_columns(groups: &str, metrics: &str) -> Vec<SocketColumns> {
    let group_fields: Vec<&str> = groups.split(',').map(|f| f.trim()).collect();
    let mut found: BTreeMap<u32, (Option<usize>, Option<usize>)> = BTreeMap::new();

    for (idx, metric) in metrics.split(',').map(|f| f.trim()).enumerate() {
        let socket = match group_fields.get(idx).and_then(|g| parse_socket_group(g)) {
            Some(socket) => socket,
            None => continue,
        };
        let metric = metric.to_ascii_lowercase();
        let entry = found.entry(socket).or_insert((None, None));
        if metric.contains("read") {
            entry.0.get_or_insert(idx);
        } else if metric.contains("write") {
            entry.1.get_or_insert(idx);
        }
        // Anything else in the group -- the per-socket `Memory (MB/s)` total -- is ignored.
    }

    found
        .into_iter()
        .filter_map(|(socket, (read_col, write_col))| {
            Some(SocketColumns {
                socket,
                read_col: read_col?,
                write_col: write_col?,
            })
        })
        .collect()
}

/// Socket number of a `SKT<n>` column-group label, tolerating a space after the prefix.
fn parse_socket_group(field: &str) -> Option<u32> {
    let rest = field
        .strip_prefix("SKT")
        .or_else(|| field.strip_prefix("skt"))?;
    rest.trim().parse().ok()
}

/// Positional guess, used only when the header could not be interpreted at all.
fn fallback_columns(targets: &[TargetState]) -> Vec<SocketColumns> {
    targets
        .iter()
        .map(|state| {
            let base = DEFAULT_LEAD_COLS + DEFAULT_COLS_PER_SOCKET * state.target.socket as usize;
            SocketColumns {
                socket: state.target.socket,
                read_col: base,
                write_col: base + 1,
            }
        })
        .collect()
}

/// MB/s from one CSV cell. Empty means zero; anything unparseable means "no sample".
fn parse_mb_per_s(field: &str) -> Option<f64> {
    let field = field.trim();
    if field.is_empty() {
        return Some(0.0);
    }
    field.parse::<f64>().ok()
}

/// Bytes moved over one [`INTERVAL`], from `pcm-memory`'s MB/s.
fn mb_per_s_to_bytes(mb: f64) -> u64 {
    if !mb.is_finite() || mb <= 0.0 {
        return 0;
    }
    (mb * 1e6 * INTERVAL_SECS).round() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two header lines `pcm-memory -nc -csv` prints on a two-socket host.
    const GROUPS: &str = ",,SKT0,SKT0,SKT0,SKT1,SKT1,SKT1,System,System,System";
    const METRICS: &str = "Date,Time,Mem Read (MB/s),Mem Write (MB/s),Memory (MB/s),\
                           Mem Read (MB/s),Mem Write (MB/s),Memory (MB/s),Read,Write,Memory";

    #[test]
    fn header_columns_by_name() {
        assert_eq!(
            header_columns(GROUPS, METRICS),
            vec![
                SocketColumns {
                    socket: 0,
                    read_col: 2,
                    write_col: 3
                },
                SocketColumns {
                    socket: 1,
                    read_col: 5,
                    write_col: 6
                },
            ]
        );
    }

    #[test]
    fn header_columns_follow_names_not_positions() {
        // Write before Read within the group: the indices must follow the names.
        let metrics = "Date,Time,Mem Write (MB/s),Mem Read (MB/s),Memory (MB/s)";
        let groups = ",,SKT0,SKT0,SKT0";
        assert_eq!(
            header_columns(groups, metrics),
            vec![SocketColumns {
                socket: 0,
                read_col: 3,
                write_col: 2
            }]
        );
    }

    #[test]
    fn header_columns_ignore_system_group() {
        // The System group's metrics are the bare words Read/Write, so a global
        // first-hit scan would match them. Grouping by socket is what excludes them.
        for cols in header_columns(GROUPS, METRICS) {
            assert!(cols.read_col < 8, "picked up a System column: {:?}", cols);
            assert!(cols.write_col < 8, "picked up a System column: {:?}", cols);
        }
    }

    #[test]
    fn header_columns_ignore_socket_total() {
        // `Memory (MB/s)` is the socket's read+write total and must not be read as either.
        let cols = header_columns(GROUPS, METRICS);
        assert!(cols.iter().all(|c| c.read_col != 4 && c.write_col != 4));
    }

    #[test]
    fn header_columns_tolerate_spaced_socket_token() {
        let groups = ",,SKT 0,SKT 0";
        let metrics = "Date,Time,Mem Read (MB/s),Mem Write (MB/s)";
        assert_eq!(
            header_columns(groups, metrics),
            vec![SocketColumns {
                socket: 0,
                read_col: 2,
                write_col: 3
            }]
        );
    }

    #[test]
    fn header_columns_reject_unreadable_header() {
        assert!(header_columns("nothing,useful", "Date,Time,junk").is_empty());
    }

    #[test]
    fn parses_mb_per_s() {
        assert_eq!(parse_mb_per_s("11234.56"), Some(11234.56));
        assert_eq!(parse_mb_per_s("0"), Some(0.0));
        assert_eq!(parse_mb_per_s(" 12 "), Some(12.0));
        assert_eq!(parse_mb_per_s(""), Some(0.0));
        assert_eq!(parse_mb_per_s("n/a"), None);
    }

    #[test]
    fn converts_mb_per_s_to_bytes() {
        assert_eq!(mb_per_s_to_bytes(11234.56), 11_234_560_000);
        assert_eq!(mb_per_s_to_bytes(0.0), 0);
        // A negative rate is not a quantity; PCM should never print one.
        assert_eq!(mb_per_s_to_bytes(-1.0), 0);
    }
}
