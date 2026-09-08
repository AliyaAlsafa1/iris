#!/usr/bin/env python3
"""Sample memory-system counters alongside an Iris run, per socket, per interval.

Collects the three independent vantage points on the same flow of bytes:

  NIC    `rx_phy_bytes`, from the eval's own report — what arrived at the port.
  PCIe   uncore IIO inbound bandwidth — what the NIC actually DMA'd into the host.
  DRAM   uncore IMC CAS read/write — what reached memory.

plus Intel RDT's per-core-group view:

  MBM    `mbm_total_bytes` / `mbm_local_bytes` — DRAM traffic originated by the RX *cores*.
  CMT    `llc_occupancy` — how much LLC the RX cores are holding.

## Why these particular counters

The ratios between them are the results, not the raw numbers:

  `iio_inbound / rx_phy_bytes`   ~1 plus descriptor overhead. A sanity check: if this is far from
                                 1, the wrong IIO stack is being read and everything else is wrong.

  `imc_bytes - sum(MBM)`         **IO-originated DRAM traffic.** On Skylake-SP, MBM attributes only
                                 core-originated traffic to an RMID; DDIO writes from the IIO are
                                 attributed to no RMID at all. That apparent gap in the hardware is
                                 what makes the decomposition possible — it separates "the
                                 application's memory traffic" from "the packets' memory traffic",
                                 which is the question being asked.

  `io_dram / iio_inbound`        The share of DMA'd packet data that reaches DRAM rather than being
                                 absorbed and overwritten in LLC. This is the DDIO question,
                                 answered without touching DDIO — and it decides whether a DDIO way
                                 sweep is worth running at all.

## What this deliberately does not do

Nothing here runs in the Iris process. Programming per-socket uncore PMUs via `perf_event_open`
in-process is a large amount of fragile code for no benefit, and resctrl supports CPU-based
monitoring groups, which suits pinned `isolcpus` RX cores exactly and needs no thread enumeration
inside Iris. So the datapath is untouched and there is no perturbation to correct for — unlike the
cycle budget, which needs a sampling stride and rdtsc debiasing.

## The two real measurement hazards

1. **This sampler must not run on an RX core.** It would steal datapath cycles and, worse, pollute
   that core's own CMT/LLC occupancy figure — corrupting the very metric it is collecting.
   `--sampler-core` is mandatory and is checked against the config's RX cores.

2. **Uncore counters are socket-wide.** IMC CAS counts the OS, this sampler, and anything else on
   the box, not just Iris. Run `--baseline` with Iris stopped to measure that floor, and subtract
   it. A floor that is a large fraction of the signal means the effect is not resolvable.

Usage
-----
    # once, after scripts/mem_setup.sh, to confirm the counters read and parse
    sudo tools/mem_sample.py --config configs/online-cx5-eval.toml --sampler-core 14 --worker-cores 13 --selftest

    # the DRAM noise floor, with Iris NOT running
    sudo tools/mem_sample.py --config configs/online-cx5-eval.toml --sampler-core 14 \
        --baseline --duration 30 --out baseline.csv

    # alongside a run (tools/paired_ab.py does this for you)
    sudo tools/mem_sample.py --config configs/online-cx5-eval.toml --sampler-core 14 \
        --duration 120 --out mem_sample.csv

Only the standard library is required.
"""

import argparse
import collections
import csv
import json
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import tomllib
from pathlib import Path

PMU_DIR = Path("/sys/bus/event_source/devices")
RESCTRL = Path("/sys/fs/resctrl")
CPU_DIR = Path("/sys/devices/system/cpu")
BYTES_PER_CAS = 64  # a CAS command moves one cache line

# Byte units perf may report a counter in. When a row carries one of these, perf has ALREADY
# applied the event's sysfs `.scale`, so the value must be converted from that unit and the scale
# must not be applied a second time.
#
# Getting this wrong is silent and enormous rather than marginal: uncore_imc/cas_count_read/ has
# scale 6.103515625e-5 with unit MiB, so treating perf's already-scaled MiB figure as a raw CAS
# count and multiplying by 64 understates DRAM traffic by 1048576/64 = 16384x. It looks like a
# nearly idle memory system instead of a busy one, which is exactly how it was first noticed.
UNIT_BYTES = {"B": 1, "Bytes": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30}


def value_to_bytes(value: float, unit, bytes_per_count: float) -> float:
    """Convert one perf counter value to bytes.

    `unit` comes from perf's own JSON row, which is why `-j` is used in preference to `-x,`: the
    output states whether it has already scaled the counter, so this does not have to be assumed
    from the perf version or the kernel.
    """
    u = (unit or "").strip()
    if u in UNIT_BYTES:
        return value * UNIT_BYTES[u]
    # No unit: the value is a raw event count, so apply the per-event byte size ourselves.
    return value * bytes_per_count


# --------------------------------------------------------------------------- topology


def cpu_socket(cpu: int) -> int:
    p = CPU_DIR / f"cpu{cpu}" / "topology" / "physical_package_id"
    return int(p.read_text().strip())


PCI_VENDORS = {"0x15b3": "Mellanox", "0x8086": "Intel", "0x14e4": "Broadcom"}

# Whether a PMD exposes rx_phy_* — the N1 denominator, and all-or-nothing across ports, so one
# port without it invalidates the ingress normalisation for the whole run.
PHY_COUNTER_BY_VENDOR = {"0x15b3": True, "0x8086": False}


def device_identity(pci_addr: str):
    """Vendor, driver and whether this NIC is expected to expose `rx_phy_*`.

    Reported because the answer changes what N1 means, and it is a property of the card rather
    than of the harness: mlx5 provides `rx_phy_*`, ICE does not. Guessing it from the config's
    filename is how a mixed-vendor assumption survives onto a machine where it is false.
    """
    base = Path("/sys/bus/pci/devices") / pci_addr

    def read(name):
        try:
            return (base / name).read_text().strip()
        except OSError:
            return None

    vendor = read("vendor")
    driver = None
    try:
        driver = (base / "driver").resolve().name
    except OSError:
        pass
    return {
        "vendor_id": vendor,
        "vendor": PCI_VENDORS.get(vendor, vendor or "unknown"),
        "device_id": read("device"),
        "driver": driver or "(unbound)",
        # None means "cannot tell from the vendor alone" — check the smoke run's ingress[] array.
        "phy_counters": PHY_COUNTER_BY_VENDOR.get(vendor),
    }


def llc_geometry():
    """LLC size and way count for one socket, or None if it cannot be determined.

    Needed to interpret N3: an occupancy figure means nothing without knowing the cache it is a
    fraction of, and the per-way size is what a future CAT or DDIO sweep moves in units of.
    """
    size_raw = None
    try:
        size_raw = Path(
            "/sys/devices/system/cpu/cpu0/cache/index3/size").read_text().strip()
    except OSError:
        return None
    mult = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}
    size = None
    if size_raw and size_raw[-1].upper() in mult:
        try:
            size = int(size_raw[:-1]) * mult[size_raw[-1].upper()]
        except ValueError:
            return None
    if size is None:
        return None

    ways = None
    # resctrl's cbm_mask is authoritative for how many ways CAT can actually address; fall back to
    # the cache's own associativity when resctrl is not mounted.
    try:
        ways = bin(int((RESCTRL / "info" / "L3" / "cbm_mask").read_text().strip(), 16)).count("1")
    except (OSError, ValueError):
        try:
            ways = int(Path("/sys/devices/system/cpu/cpu0/cache/index3/"
                            "ways_of_associativity").read_text().strip())
        except (OSError, ValueError):
            return None
    if not ways:
        return None
    return {"size_bytes": size, "ways": ways, "bytes_per_way": size // ways}


def device_numa_node(pci_addr: str):
    """The NUMA node a PCI device is attached to, or None if the platform does not say."""
    try:
        node = int((Path("/sys/bus/pci/devices") / pci_addr / "numa_node").read_text().strip())
    except (OSError, ValueError):
        return None
    return None if node < 0 else node


def check_numa_locality(layout):
    """Reasons the core allocation makes the memory measurement unsound.

    This is a hard gate rather than a warning, because cross-socket polling does not merely add
    noise to N2 — it misattributes it. The decomposition per socket S is

        io_dram[S] = imc_bytes[S] - mbm_total[group S]

    and it assumes socket S's cores are what drive socket S's memory controllers. A core on socket
    0 polling a NIC whose queues and mbufs live on socket 1 generates traffic that appears in
    `mbm_total[group 0]` but in `imc[1]`. So io_dram[0] subtracts traffic that never crossed IMC 0
    and comes out too low (clamped at zero, which hides it), while io_dram[1] credits those remote
    reads to DDIO. Neither mbm_total nor mbm_local repairs this, because no group's local counter
    captures another socket's cores hitting this socket's memory.

    Note the ports themselves are what fix the reference: DPDK sets up each port's RX queues and
    takes its mbufs from the mempool on the *port's* socket, so it is the port's NUMA node the
    cores must match, not merely each other.
    """
    problems = []
    for port in layout["ports"]:
        dev = port["device"]
        node = device_numa_node(dev)
        sockets = {}
        for c in port["cores"]:
            sockets.setdefault(cpu_socket(c), []).append(c)
        if len(sockets) > 1:
            problems.append(
                f"port {dev}: RX cores span sockets "
                + ", ".join(f"{s}:{cs}" for s, cs in sorted(sockets.items()))
                + " — its queues and mbufs live on one socket, so the cores on the other read "
                  "them across UPI"
            )
        if node is not None:
            remote = sorted(c for c in port["cores"] if cpu_socket(c) != node)
            if remote:
                problems.append(
                    f"port {dev} is on NUMA node {node}, but cores {remote} are not — "
                    "every packet header they touch crosses UPI, and that traffic is attributed "
                    "to the wrong socket's memory controllers"
                )
    return problems


def suggest_allocation(layout, reserve=()):
    """A NUMA-local core allocation for the configured ports, as TOML.

    Keeps each port's core count but draws the cores from the port's own NUMA node, skipping
    `main_core` and preferring the lowest-numbered physical cores. Hyperthread siblings are
    avoided: two RX cores sharing a physical core contend for the same L1/L2 and halve the
    per-core throughput the evaluation is trying to measure.
    """
    # `reserve` keeps cores that are already spoken for — the memory sampler and the rte_flow
    # install worker — out of the RX lists. Omitting them produced a suggestion that silently made
    # the sampler core an RX core, which the gates would then reject.
    used = set(reserve)
    if layout["main_core"] is not None:
        used.add(layout["main_core"])
    by_node = {}
    for cpu_path in sorted(CPU_DIR.glob("cpu[0-9]*"), key=lambda p: int(p.name[3:])):
        cpu = int(cpu_path.name[3:])
        try:
            node = cpu_socket(cpu)
            siblings = (cpu_path / "topology" / "thread_siblings_list").read_text().strip()
        except OSError:
            continue
        # Keep only the first thread of each physical core.
        if parse_cpu_list(siblings) and min(parse_cpu_list(siblings)) != cpu:
            continue
        by_node.setdefault(node, []).append(cpu)

    # Ports sharing a NUMA node compete for its cores, so allocate the most demanding first and
    # report any shortfall explicitly: when two NICs sit on one node, a NUMA-local allocation
    # bounds the *total* core count, and the fix is fewer cores per port rather than cores on the
    # far socket.
    per_node_demand = {}
    for port in layout["ports"]:
        node = device_numa_node(port["device"])
        per_node_demand.setdefault(node, 0)
        per_node_demand[node] += len(port["cores"])

    lines, warnings = [], []
    for node, demand in sorted(per_node_demand.items(), key=lambda kv: (kv[0] is None, kv[0])):
        supply = len([c for c in by_node.get(node, []) if c not in used])
        if demand > supply:
            sharers = [p["device"] for p in layout["ports"]
                       if device_numa_node(p["device"]) == node]
            warnings.append(
                f"NUMA node {node} has {supply} usable physical cores (excluding main_core and "
                f"hyperthread siblings) but {len(sharers)} port(s) on it ask for {demand} "
                f"in total: {', '.join(sharers)}.\n"
                f"    A NUMA-local allocation is therefore only possible with fewer cores per "
                f"port — roughly {supply // max(1, len(sharers))} each. Spilling the remainder "
                f"onto the other socket is what the gate rejects, because it misattributes N2.\n"
                f"    Reducing the core count is a real change to the experiment: it lowers the "
                f"per-arm throughput ceiling, so cycle results are not comparable across the "
                f"change either."
            )

    for port in layout["ports"]:
        node = device_numa_node(port["device"])
        want = len(port["cores"])
        pool = [c for c in by_node.get(node, []) if c not in used]
        take = pool[:want]
        used.update(take)
        note = ("" if len(take) == want
                else f"   # SHORT: {len(take)} of {want} requested; see the note above")
        lines.append(f"[[online.ports]]\ndevice = \"{port['device']}\"   # NUMA node {node}\n"
                     f"cores = {take}{note}")
    out = "\n\n".join(lines)
    if warnings:
        out += "\n\n" + "\n\n".join(f"NOTE: {w}" for w in warnings)
    return out


def device_root_bus(pci_addr: str) -> str:
    """The PCI root bus a device sits under, e.g. '0000:3a' for '0000:3b:00.0'.

    Resolved by following the sysfs symlink up to the `pci0000:xx` root complex, rather than by
    assuming the device's own bus number, since an endpoint always sits behind at least one bridge.
    """
    real = (Path("/sys/bus/pci/devices") / pci_addr).resolve()
    for part in real.parts:
        if part.startswith("pci0000:"):
            return part[len("pci"):]
    raise RuntimeError(f"could not find a PCI root complex for {pci_addr} (resolved to {real})")


def iio_stacks() -> dict:
    """Map (root_bus) -> (pmu_index, die). Read from each IIO PMU's `dieN` attributes.

    Stack numbering is not stable across platforms, so this is resolved at runtime rather than
    hardcoded: `uncore_iio_2/die0` naming the CX-5's root bus on this host is a fact about this
    host.
    """
    out = {}
    for pmu in sorted(PMU_DIR.glob("uncore_iio_[0-9]*")):
        idx = int(pmu.name.rsplit("_", 1)[1])
        for die_file in sorted(pmu.glob("die*")):
            bus = die_file.read_text().strip()
            if bus:
                out[bus] = (idx, int(die_file.name[len("die"):]))
    return out


def iio_scale(pmu_index: int) -> float:
    """Bytes per **raw count** of a `bw_in_portN` event, from the PMU's sysfs attributes.

    Only used when perf reports the counter with no unit, i.e. unscaled; see [`value_to_bytes`].
    On this host the scale is 3.814697266e-6 with unit MiB, giving 4 bytes per count.
    """
    base = PMU_DIR / f"uncore_iio_free_running_{pmu_index}" / "events"
    try:
        scale = float((base / "bw_in_port0.scale").read_text().strip())
        unit = (base / "bw_in_port0.unit").read_text().strip()
    except OSError:
        return 4.0  # documented default for this counter family
    return scale * UNIT_BYTES.get(unit, 1 << 20)


# --------------------------------------------------------------------------- config


def load_layout(config_path: Path):
    """Extract the RX cores and NIC devices the run will use, grouped by socket."""
    with config_path.open("rb") as fh:
        cfg = tomllib.load(fh)
    online = cfg.get("online")
    if not online:
        raise SystemExit(f"{config_path} has no [online] section; nothing to sample")

    ports = []
    all_rx_cores = set()
    for pm in online.get("ports", []):
        cores = sorted(set(pm.get("cores", [])))
        sinks = [s.get("core") for s in ([pm["sink"]] if "sink" in pm else pm.get("sinks", []))]
        all_rx_cores.update(cores)
        ports.append({
            "device": pm["device"],
            "cores": cores,
            "sink_cores": [c for c in sinks if c is not None],
        })

    by_socket = {}
    for p in ports:
        for c in p["cores"]:
            by_socket.setdefault(cpu_socket(c), set()).add(c)

    return {
        "ports": ports,
        "rx_cores": sorted(all_rx_cores),
        "cores_by_socket": {s: sorted(cs) for s, cs in sorted(by_socket.items())},
        "main_core": cfg.get("main_core"),
    }


# --------------------------------------------------------------------------- resctrl


class ResctrlGroups:
    """One CPU-based monitoring group per socket, over that socket's RX cores.

    CPU-based rather than task-based: the RX lcores are pinned (and expected to be `isolcpus`), so
    a CPU set identifies them exactly and needs no cooperation from the Iris process. Task-based
    groups would need thread ids, which change every run.
    """

    def __init__(self, cores_by_socket, prefix="iris"):
        self.cores_by_socket = cores_by_socket
        self.prefix = prefix
        self.groups = {}
        self.created = []

    def __enter__(self):
        if not (RESCTRL / "info").is_dir():
            raise SystemExit(
                "resctrl is not mounted. Run: sudo scripts/mem_setup.sh"
            )
        if not (RESCTRL / "info" / "L3_MON").is_dir():
            raise SystemExit(
                "resctrl has no L3_MON: this CPU exposes no LLC/bandwidth monitoring, so N2 and "
                "N3 cannot be measured on this host"
            )
        mon_root = RESCTRL / "mon_groups"
        for socket, cores in self.cores_by_socket.items():
            path = mon_root / f"{self.prefix}_s{socket}"
            if not path.is_dir():
                path.mkdir()
                self.created.append(path)
            # Assigning CPUs moves them out of whatever group held them; on __exit__ removing the
            # directory returns them to the default group.
            (path / "cpus_list").write_text(",".join(str(c) for c in cores))
            readback = (path / "cpus_list").read_text().strip()
            self.groups[socket] = {"path": path, "cores": cores, "cpus_list": readback}
        return self

    def __exit__(self, *exc):
        for path in reversed(self.created):
            try:
                path.rmdir()
            except OSError as e:
                print(f"warning: could not remove {path}: {e}", file=sys.stderr)
        return False

    def verify(self):
        """Confirm each group holds exactly the cores it was given.

        A hard gate, not a warning: a group that silently holds the wrong CPUs reports a plausible
        LLC occupancy for the wrong thing.
        """
        problems = []
        for socket, g in self.groups.items():
            got = parse_cpu_list(g["cpus_list"])
            want = set(g["cores"])
            if got != want:
                problems.append(
                    f"socket {socket}: resctrl group holds {sorted(got)}, expected {sorted(want)}"
                )
        return problems

    def read(self):
        """Read every group's monitoring files. Returns {(group, domain, field): value}.

        `group` is the socket number for an RX-core group, or the string "root" for the default
        group — which holds every CPU *not* moved into one of ours: the main lcore, the install
        worker, the sampler, kernel threads and any other process.

        Reading root is what makes the IO decomposition honest. `imc - mbm(RX cores)` attributes
        all of that other core traffic to DDIO, because it is core-originated but not originated
        by a *monitored* core. Subtracting root as well leaves only traffic that no core caused.
        """
        out = {}
        sources = list(self.groups.items()) + [("root", {"path": RESCTRL})]
        for key, g in sources:
            mon_data = g["path"] / "mon_data"
            for dom in sorted(mon_data.glob("mon_L3_*")):
                domain = int(dom.name.rsplit("_", 1)[1])
                for field in ("llc_occupancy", "mbm_total_bytes", "mbm_local_bytes"):
                    try:
                        raw = (dom / field).read_text().strip()
                    except OSError:
                        continue
                    # "Unavailable" appears when no RMID is assigned yet.
                    out[(key, domain, field)] = int(raw) if raw.isdigit() else None
        return out


def parse_cpu_list(text: str) -> set:
    """Parse a sysfs cpu list like '1-4,9,13-15'."""
    cpus = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            cpus.update(range(int(lo), int(hi) + 1))
        else:
            cpus.add(int(part))
    return cpus


# --------------------------------------------------------------------------- perf


def build_events(layout):
    """The perf event list, plus how to interpret each one.

    Returns (event_specs, perf_event_args). Each spec says which socket and which quantity an
    event name maps to, so the JSON rows can be attributed without relying on field order.
    """
    stacks = iio_stacks()
    specs = []

    # DRAM traffic, per socket. `--per-socket` aggregates the six channel units for us.
    for name in ("cas_count_read", "cas_count_write"):
        specs.append({
            "event": f"uncore_imc/{name}/",
            "kind": f"imc_{name}",
            "socket": None,          # resolved from the row's own socket field
            "bytes_per_count": BYTES_PER_CAS,
        })

    # PCIe inbound bytes, for the stack each configured NIC actually sits on. All four ports of
    # the stack are summed: on this host the NIC is the only endpoint on its stack, so the sum is
    # the NIC's DMA and nothing else.
    for port in layout["ports"]:
        bus = device_root_bus(port["device"])
        if bus not in stacks:
            print(f"warning: no IIO stack found for {port['device']} (root bus {bus}); "
                  "PCIe columns will be blank for it", file=sys.stderr)
            continue
        idx, die = stacks[bus]
        scale = iio_scale(idx)
        for p in range(4):
            specs.append({
                "event": f"uncore_iio_free_running_{idx}/bw_in_port{p}/",
                "kind": f"iio_in::{port['device']}",
                "socket": die,
                "bytes_per_count": scale,
            })

    args = []
    for ev in dict.fromkeys(s["event"] for s in specs):  # dedupe, preserve order
        args += ["-e", ev]
    return specs, args


PERF_INTERVAL_KEYS = ("interval", "counter-value", "event", "socket", "unit", "event-runtime")


def parse_perf_json_line(line: str):
    """Parse one line of `perf stat -j -I` output.

    perf's JSON is self-describing, which is why it is used here in preference to `-x,`: the CSV
    field order has changed between perf releases and a misparse would silently shift every
    column. Unknown keys are ignored; a line that is not JSON at all is skipped.
    """
    line = line.strip()
    if not line or not line.startswith("{"):
        return None
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        return None
    if "counter-value" not in row and "value" not in row:
        return None
    raw = row.get("counter-value", row.get("value"))
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None  # "<not counted>" / "<not supported>"
    socket = row.get("socket") or row.get("cpu") or ""
    m = re.search(r"S(\d+)", str(socket))
    return {
        "interval": float(row.get("interval", row.get("time", 0.0)) or 0.0),
        "event": (row.get("event") or "").strip(),
        "socket": int(m.group(1)) if m else None,
        "value": value,
        # Whether perf already applied the event's sysfs `.scale`, and in what unit. See
        # `value_to_bytes`: this is the whole reason `-j` is preferred over `-x,`.
        "unit": row.get("unit"),
    }


def check_events_exist(event_args):
    """Reasons perf will not be able to count these events, checked against sysfs.

    A pre-flight check because the failure mode otherwise is a silent hang: perf writes its
    complaint to stderr and produces no interval rows, and a reader waiting on stdout waits
    forever. Better to name the missing PMU up front.
    """
    problems = []
    for i in range(0, len(event_args), 2):
        ev = event_args[i + 1]
        pmu = ev.split("/", 1)[0]

        # A bare `uncore_imc` is not a directory: the instances are uncore_imc_0..N and perf
        # treats the unsuffixed name as a wildcard across them. Resolve either spelling, or this
        # check rejects the very events it is meant to validate.
        candidates = [PMU_DIR / pmu] if (PMU_DIR / pmu).is_dir() else sorted(
            p for p in PMU_DIR.glob(f"{pmu}_[0-9]*") if p.is_dir()
        )
        if not candidates:
            problems.append(f"{ev}: no PMU matching {pmu!r} or {pmu}_N under {PMU_DIR}")
            continue

        name = ev.split("/")[1] if "/" in ev else ""
        if not name:
            continue
        # Present on any instance is enough; perf will expand the wildcard to those that have it.
        # Only conclude "missing" when at least one instance publishes a populated events/ dir,
        # since some kernels expose events as aliases rather than files.
        saw_populated = False
        for inst in candidates:
            events_dir = inst / "events"
            if events_dir.is_dir() and any(events_dir.iterdir()):
                saw_populated = True
                if (events_dir / name).exists():
                    break
        else:
            if saw_populated:
                problems.append(
                    f"{ev}: {pmu} exists ({len(candidates)} instance(s)) but none publishes an "
                    f"event named {name!r}"
                )
    return problems


class PerfSampler:
    """Runs `perf stat` as a child and hands back its interval rows.

    Lines are drained by a reader thread onto a queue rather than read inline. Two reasons, both
    of which produced hangs when this was a plain `for line in proc.stdout`:

    * stderr used to be a second pipe that was only read at shutdown. perf writes one warning per
      event per interval in some configurations, and once that 64 KiB pipe filled, perf blocked
      writing while this process blocked reading stdout — a deadlock with no output at all. stderr
      is now merged into stdout, and the JSON parser already skips non-JSON lines, so perf's own
      diagnostics are captured instead of discarded.
    * a blocking read has no timeout, so perf failing to start (a missing PMU, paranoid still
      restricting) meant waiting forever. The queue lets the caller apply a deadline.
    """

    def __init__(self, specs, event_args, interval_ms, sampler_core):
        self.specs = specs
        self.event_args = event_args
        self.cmd = [
            "perf", "stat",
            "-j",                       # self-describing output; see parse_perf_json_line
            "-a", "--per-socket",
            "-I", str(interval_ms),
            *event_args,
        ]
        # Pin perf itself off the RX cores. `-a` makes it count system-wide regardless of where
        # its own thread runs, so this only keeps its bookkeeping off the datapath.
        self.cmd = ["taskset", "-c", str(sampler_core)] + self.cmd
        self.proc = None
        self.lines = queue.Queue()
        # Bounded: perf can emit a warning per event per interval, and a two-hour run would
        # otherwise accumulate them all in memory for the sake of an error path that prints 40.
        self.diagnostics = collections.deque(maxlen=2000)
        self._reader = None

    def start(self):
        if shutil.which("perf") is None:
            raise SystemExit("perf not found on PATH")
        self.proc = subprocess.Popen(
            self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )

        def drain(stream, q):
            try:
                for line in stream:
                    q.put(line)
            finally:
                q.put(None)  # sentinel: the child closed its output

        self._reader = threading.Thread(target=drain, args=(self.proc.stdout, self.lines),
                                        daemon=True)
        self._reader.start()
        return self

    def rows(self, deadline=None, first_row_timeout=15.0):
        """Yield parsed rows, giving up rather than blocking forever.

        `first_row_timeout` bounds the wait for perf's *first* interval; after that the deadline
        governs. Raises SystemExit with perf's own output when nothing parseable ever arrives,
        which is the case that used to hang.
        """
        seen_any = False
        started = time.time()
        while True:
            if deadline and time.time() >= deadline:
                return
            budget = first_row_timeout if not seen_any else 5.0
            if not seen_any and (time.time() - started) >= first_row_timeout:
                self._fail_no_output(first_row_timeout)
            try:
                line = self.lines.get(timeout=min(budget, 1.0))
            except queue.Empty:
                # The child may have died without closing cleanly; notice rather than spin.
                if self.proc.poll() is not None and self.lines.empty():
                    if not seen_any:
                        self._fail_no_output(time.time() - started)
                    return
                continue
            if line is None:
                if not seen_any:
                    self._fail_no_output(time.time() - started)
                return
            parsed = parse_perf_json_line(line)
            if parsed:
                seen_any = True
                yield parsed
            elif line.strip():
                # perf's warnings and errors land here now that stderr is merged.
                self.diagnostics.append(line.rstrip())

    def _fail_no_output(self, waited):
        self.stop()
        # deque has no slicing, and this runs on the error path where a TypeError would replace
        # the diagnostic it is trying to print.
        detail = "\n  ".join(list(self.diagnostics)[-40:]) or "(perf produced no output at all)"
        raise SystemExit(
            f"perf produced no parseable interval rows in {waited:.0f}s. Its output was:\n"
            f"  {detail}\n\n"
            "Common causes: scripts/mem_setup.sh has not been run (perf_event_paranoid must be "
            "-1, or run as root); this kernel's perf does not support `-j` with `-I`; or one of "
            "the requested uncore PMUs does not exist on this host. Run with --show-topology to "
            "see which PMUs were resolved."
        )

    def stop(self):
        """Stop perf and return whatever it wrote that was not interval data."""
        if not self.proc:
            return ""
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGINT)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        # Collect anything the reader thread still has buffered.
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                line = self.lines.get_nowait()
            except queue.Empty:
                break
            if line is None:
                break
            if line.strip() and not parse_perf_json_line(line):
                self.diagnostics.append(line.rstrip())
        return "\n".join(self.diagnostics)


# --------------------------------------------------------------------------- aggregation


def classify(event: str, specs_by_event):
    return specs_by_event.get(event.strip(), [])


def aggregate_interval(rows, specs_by_event, port_devices):
    """Fold one interval's perf rows into per-socket byte totals."""
    agg = {}

    def bump(socket, key, delta):
        agg.setdefault(socket, {}).setdefault(key, 0.0)
        agg[socket][key] += delta

    for r in rows:
        for spec in classify(r["event"], specs_by_event):
            socket = r["socket"] if r["socket"] is not None else spec["socket"]
            if socket is None:
                continue
            kind = spec["kind"]
            scaled = value_to_bytes(r["value"], r.get("unit"),
                                    spec["bytes_per_count"])
            if kind.startswith("imc_"):
                bump(socket, kind, scaled)
                bump(socket, "imc_bytes", scaled)
            elif kind.startswith("iio_in::"):
                dev = kind.split("::", 1)[1]
                # Only credit the die the device actually sits on; the same PMU index exists on
                # both sockets and the other one is a different, unrelated stack.
                if spec["socket"] is not None and socket != spec["socket"]:
                    continue
                bump(socket, f"iio_in_bytes::{dev}", scaled)
                bump(socket, "iio_in_bytes", scaled)
    for socket in agg:
        for dev in port_devices:
            agg[socket].setdefault(f"iio_in_bytes::{dev}", 0.0)
    return agg


# --------------------------------------------------------------------------- output


def csv_fields(port_devices):
    return [
        "unix_ms",
        "elapsed_s",
        "socket",
        # DRAM, from the memory controllers. Socket-wide: includes the OS and this sampler, which
        # is why --baseline exists.
        "imc_read_bytes",
        "imc_write_bytes",
        "imc_bytes",
        # PCIe inbound, i.e. NIC DMA into the host, summed over the stack's ports.
        "iio_in_bytes",
        *[f"iio_in_bytes::{d}" for d in port_devices],
        # RDT: core-originated DRAM traffic and LLC occupancy for this socket's RX cores.
        "mbm_total_bytes",
        "mbm_local_bytes",
        # RX-core traffic to the other socket's memory. ~0 under a NUMA-local allocation.
        "mbm_remote_bytes",
        # Every other CPU on the box: main lcore, install worker, sampler, kernel, other procs.
        # Subtracted alongside the RX cores so it is not misattributed to DDIO.
        "mbm_other_local_bytes",
        "llc_occupancy_bytes",
        # The decomposition. IO-originated = everything the memory controller saw that the cores
        # did not originate; on Skylake-SP that is DDIO/IIO traffic, which carries no RMID.
        "core_dram_bytes",
        "io_dram_bytes",
        "io_dram_fraction",
        # 1 when MBM claimed more local traffic than the IMC saw, i.e. the counters disagree.
        "io_dram_clamped",
    ]


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--config", type=Path, required=True,
                    help="the Iris config the run will use; RX cores and NICs are read from it")
    ap.add_argument("--sampler-core", type=int, required=True,
                    help="CPU to pin this sampler to. Must not be an RX core (checked): sharing "
                         "one would steal datapath cycles and pollute that core's LLC occupancy.")
    ap.add_argument("--worker-cores", default="",
                    help="comma-separated cores the eval's rte_flow install worker uses, so this "
                         "sampler can refuse to share one with it")
    ap.add_argument("--interval", type=int, default=1000, help="sample period in ms")
    ap.add_argument("--duration", type=float, default=None,
                    help="stop after this many seconds (default: until SIGINT/SIGTERM)")
    ap.add_argument("--out", type=Path, default=Path("mem_sample.csv"))
    ap.add_argument("--baseline", action="store_true",
                    help="label this run as the Iris-stopped DRAM noise floor. Does not change "
                         "what is measured, only what the output claims to be.")
    ap.add_argument("--selftest", action="store_true",
                    help="sample a few intervals, then report exactly which counters were seen "
                         "and whether they advanced. Run this once after scripts/mem_setup.sh.")
    ap.add_argument("--show-topology", action="store_true",
                    help="print the core/NUMA/IIO layout for this host and a NUMA-local core "
                         "allocation for the configured ports, then exit. Changes nothing.")
    ap.add_argument("--startup-timeout", type=float, default=15.0,
                    help="give up if perf has produced no parseable interval row within this "
                         "many seconds, printing what it did output (default: 15)")
    ap.add_argument("--allow-cross-numa", action="store_true",
                    help="proceed even though a port's RX cores are not on the port's NUMA node. "
                         "Only for deliberately measuring the cross-socket case: it misattributes "
                         "N2 between sockets rather than merely adding noise.")
    args = ap.parse_args()

    layout = load_layout(args.config)
    port_devices = [p["device"] for p in layout["ports"]]

    # Hazard 1: never share a core with the datapath.
    if args.sampler_core in layout["rx_cores"]:
        raise SystemExit(
            f"--sampler-core {args.sampler_core} is an RX core in {args.config} "
            f"(RX cores: {layout['rx_cores']}). Sampling from a measured core steals its cycles "
            "and pollutes its LLC occupancy; pick a core outside that set."
        )
    worker = {int(c) for c in args.worker_cores.split(",") if c.strip()}
    if args.sampler_core in worker:
        raise SystemExit(f"--sampler-core {args.sampler_core} is also an install-worker core")

    print(f"config          {args.config}")
    print(f"RX cores        {layout['rx_cores']}")
    print(f"cores by socket {layout['cores_by_socket']}")
    print(f"sampler core    {args.sampler_core} (socket {cpu_socket(args.sampler_core)})")
    stacks = iio_stacks()
    for p in layout["ports"]:
        bus = device_root_bus(p["device"])
        loc = stacks.get(bus)
        node = device_numa_node(p["device"])
        core_sockets = sorted({cpu_socket(c) for c in p["cores"]})
        ident = device_identity(p["device"])
        print(f"port {p['device']}  {ident['vendor']} "
              f"({ident['device_id']}, driver {ident['driver']}), NUMA node {node}")
        print(f"    root bus {bus} -> "
              + (f"uncore_iio_{loc[0]} die{loc[1]}, {iio_scale(loc[0]):.1f} B/count"
                 if loc else "NO IIO STACK FOUND"))
        print(f"    {len(p['cores'])} RX cores on socket(s) {core_sockets}")
        phy = ident["phy_counters"]
        print("    rx_phy_* (the ingress denominator): "
              + ("expected" if phy is True else
                 "NOT exposed by this PMD — M1 is invalid for the whole run (it sums every "
                 "port into one denominator), and N1 is skipped for this socket only"
                 if phy is False else
                 "unknown for this vendor; check ingress[] in a smoke run"))

    llc = llc_geometry()
    if llc:
        print(f"LLC             {llc['size_bytes'] / (1 << 20):.2f} MiB per socket, "
              f"{llc['ways']} ways, {llc['bytes_per_way'] / (1 << 10):.0f} KiB per way")

    # Cross-NUMA polling misattributes N2 between sockets, so this is a gate, not a note.
    numa_problems = check_numa_locality(layout)
    if numa_problems or args.show_topology:
        print()
        for p in numa_problems:
            print(f"  NUMA: {p}")
        if numa_problems:
            print("\nA NUMA-local allocation for this host:\n")
            reserve = {args.sampler_core} | worker
            print("    " + suggest_allocation(layout, reserve).replace("\n", "\n    "))
            print(f"\n  (keeping cores {sorted(reserve)} free for the sampler and install "
                  "worker)")
    if args.show_topology:
        return
    if numa_problems and not args.allow_cross_numa:
        raise SystemExit(
            "\nRefusing to sample: the core allocation makes N2 unsound (see above). Fix the "
            "config's `cores` lists, or pass --allow-cross-numa to measure the cross-socket case "
            "deliberately."
        )

    specs, event_args = build_events(layout)
    specs_by_event = {}
    for s in specs:
        specs_by_event.setdefault(s["event"], []).append(s)

    # Name a missing PMU here rather than letting it become a wait for output that never comes.
    event_problems = check_events_exist(event_args)
    if event_problems:
        print("\nRequested events that this host cannot count:", file=sys.stderr)
        for p in event_problems:
            print(f"  {p}", file=sys.stderr)
        raise SystemExit(
            "\nThe uncore PMUs differ between platforms. Re-run with --show-topology to see what "
            "was resolved, and check `perf list | grep uncore` for what this host offers."
        )

    n_intervals = 3 if args.selftest else None
    interval_ms = 200 if args.selftest else args.interval

    with ResctrlGroups(layout["cores_by_socket"]) as groups:
        problems = groups.verify()
        if problems:
            raise SystemExit("resctrl group setup is wrong:\n  " + "\n  ".join(problems))
        print(f"resctrl groups  " + ", ".join(
            f"s{s}: {g['cpus_list']}" for s, g in groups.groups.items()))

        sampler = PerfSampler(specs, event_args, interval_ms, args.sampler_core).start()
        print(f"perf            {' '.join(sampler.cmd)}\n")

        started = time.time()
        # MBM counters are cumulative per RMID, so bandwidth is a delta; occupancy is a gauge.
        prev_rdt = groups.read()
        seen_events, advanced, written = set(), set(), 0
        # Per-socket byte totals, so the selftest can report observed *rates*. An order-of-
        # magnitude error in counter scaling is invisible in a pass/fail check but obvious in
        # GB/s — a busy datapath does not move 0.6 MB/s of DRAM traffic.
        totals = collections.defaultdict(lambda: {"imc": 0.0, "pcie": 0.0, "core": 0.0})

        # No SIGINT handler. An earlier version installed one that only set a flag, and checked
        # that flag solely on an interval boundary — so when perf emitted nothing the flag was
        # never read and Ctrl-C did nothing at all. Letting KeyboardInterrupt propagate is both
        # simpler and correct: the `with` blocks below and above still run their cleanup, removing
        # the resctrl monitoring groups and stopping perf. SIGTERM keeps its default too, so
        # `pkill` works. `paired_ab.py` stops the sampler with SIGINT and relies on this.
        deadline = (started + args.duration) if args.duration else None

        with args.out.open("w", newline="") as fh:
            wtr = csv.DictWriter(fh, fieldnames=csv_fields(port_devices),
                                 extrasaction="ignore")
            wtr.writeheader()

            batch, cur_interval, intervals_done = [], None, 0
            for row in sampler.rows(deadline=deadline,
                                    first_row_timeout=args.startup_timeout):
                seen_events.add(row["event"].strip())
                if row["value"] > 0:
                    advanced.add(row["event"].strip())

                # perf emits all events for one interval together; a change of interval stamp
                # closes the previous one.
                if cur_interval is None:
                    cur_interval = row["interval"]
                if row["interval"] != cur_interval:
                    rdt = groups.read()
                    agg = aggregate_interval(batch, specs_by_event, port_devices)
                    now_ms = int(time.time() * 1000)
                    for socket, vals in sorted(agg.items()):
                        rec = {
                            "unix_ms": now_ms,
                            "elapsed_s": round(time.time() - started, 3),
                            "socket": socket,
                            "imc_read_bytes": int(vals.get("imc_cas_count_read", 0)),
                            "imc_write_bytes": int(vals.get("imc_cas_count_write", 0)),
                            "imc_bytes": int(vals.get("imc_bytes", 0)),
                            "iio_in_bytes": int(vals.get("iio_in_bytes", 0)),
                        }
                        for d in port_devices:
                            rec[f"iio_in_bytes::{d}"] = int(vals.get(f"iio_in_bytes::{d}", 0))

                        # RDT deltas keyed by (group, field), restricted to the L3 domain that
                        # matches this socket.
                        #
                        # `mbm_local_bytes`, not `mbm_total_bytes`, is what may be subtracted from
                        # imc_bytes: total includes traffic those cores sent to the *other*
                        # socket's memory, which never crossed this socket's controllers.
                        # Subtracting it over-subtracts and inflates the IO share.
                        d = {}
                        occ = 0
                        for (grp, dom, field), v in rdt.items():
                            if v is None or dom != socket:
                                continue
                            if field == "llc_occupancy":
                                if grp == socket:      # RX cores' own occupancy only
                                    occ += v
                                continue
                            p = prev_rdt.get((grp, dom, field))
                            if p is None:
                                continue
                            delta = max(0, v - p)      # counter wrap or RMID reassignment
                            d[(grp, field)] = d.get((grp, field), 0) + delta

                        rx_local = d.get((socket, "mbm_local_bytes"), 0)
                        rx_total = d.get((socket, "mbm_total_bytes"), 0)
                        other_local = d.get(("root", "mbm_local_bytes"), 0)

                        rec["mbm_local_bytes"] = rx_local
                        rec["mbm_total_bytes"] = rx_total
                        # RX-core traffic that went to the other socket's memory. Should be ~0
                        # under a NUMA-local allocation; a large value means the gate was bypassed
                        # and this socket's decomposition cannot be trusted.
                        rec["mbm_remote_bytes"] = max(0, rx_total - rx_local)
                        rec["mbm_other_local_bytes"] = other_local
                        rec["llc_occupancy_bytes"] = occ

                        # The headline decomposition. Core-originated is the RX cores plus every
                        # other CPU on the box; whatever the memory controller saw beyond that had
                        # no core behind it, which on this microarchitecture means DDIO/IIO.
                        core = rx_local + other_local
                        raw_io = rec["imc_bytes"] - core
                        io = max(0, raw_io)
                        # A negative value means MBM claimed more local traffic than the IMC saw:
                        # the two counters disagree and the split is not trustworthy. Clamping
                        # silently would hide that, so record it.
                        rec["io_dram_clamped"] = 1 if raw_io < 0 else 0
                        rec["core_dram_bytes"] = core
                        rec["io_dram_bytes"] = io
                        rec["io_dram_fraction"] = (
                            round(io / rec["imc_bytes"], 6) if rec["imc_bytes"] else 0.0
                        )
                        wtr.writerow(rec)
                        written += 1
                        totals[socket]["imc"] += rec["imc_bytes"]
                        totals[socket]["pcie"] += rec["iio_in_bytes"]
                        totals[socket]["core"] += core
                    fh.flush()

                    prev_rdt = rdt
                    batch, cur_interval = [], row["interval"]
                    intervals_done += 1
                    if n_intervals and intervals_done >= n_intervals:
                        break
                    if deadline and time.time() >= deadline:
                        break
                batch.append(row)

        err = sampler.stop()

    if args.selftest:
        print("=== selftest ===")
        # The pass criterion is per PMU, not per event. A NIC occupies ONE port of its 4-port IIO
        # stack, so `bw_in_port1..3` on that stack read zero with no device attached — requiring
        # every port to advance can never be satisfied and reports a healthy host as broken.
        # (Summing all four is still right: adding zeros costs nothing and avoids having to
        # discover which port the card sits on.) IMC events, by contrast, must each advance:
        # they are stack-independent and any zero there is a real failure.
        by_pmu = {}
        for ev in sorted(specs_by_event):
            by_pmu.setdefault(ev.split("/", 1)[0], []).append(ev)

        failures = []
        for pmu, evs in sorted(by_pmu.items()):
            is_iio = "iio" in pmu
            live = [e for e in evs if e in advanced]
            for ev in evs:
                state = ("advanced" if ev in advanced
                         else "zero" if ev in seen_events
                         else "NOT SEEN")
                suffix = ""
                if is_iio and state == "zero":
                    suffix = "   (no device on this stack port — expected)"
                print(f"  {ev:<48} {state}{suffix}")
            if is_iio:
                if not live:
                    failures.append(
                        f"{pmu}: no port advanced. Either no packets are arriving on the NIC on "
                        f"this stack, or the stack was misidentified — check --show-topology."
                    )
                else:
                    print(f"  -> {pmu}: {len(live)} of {len(evs)} ports carrying traffic, "
                          "which is what a single card in one slot looks like")
            else:
                for ev in evs:
                    if ev not in advanced:
                        failures.append(f"{ev}: did not advance")
        print(f"  rows written: {written}")

        # Rates, not just liveness. Scaling errors pass a pass/fail check and are obvious here.
        elapsed = max(time.time() - started, 1e-9)
        if totals:
            print("\n  observed rates (sanity-check these against the offered load):")
            for socket, t in sorted(totals.items()):
                print(f"    socket {socket}: DRAM {t['imc'] / elapsed / 1e9:6.2f} GB/s, "
                      f"PCIe in {t['pcie'] / elapsed / 1e9:6.2f} GB/s, "
                      f"core-originated {t['core'] / elapsed / 1e9:6.2f} GB/s")
            print("    A busy datapath moves GB/s, not MB/s. Rates orders of magnitude below the "
                  "offered\n    load mean a counter is being scaled wrongly, not that memory is "
                  "idle.")

        if failures:
            print("\nselftest FAILED:", file=sys.stderr)
            for f in failures:
                print(f"  {f}", file=sys.stderr)
            if err.strip():
                print("\nperf's own output:\n" + err[-4000:], file=sys.stderr)
            else:
                print("\n(perf reported no errors, so the events were accepted; the counters "
                      "simply read zero)", file=sys.stderr)
            print("\nCommon causes: perf_event_paranoid not -1 (run scripts/mem_setup.sh); the "
                  "event name differs on this kernel; or no traffic is arriving on the port.",
                  file=sys.stderr)
            sys.exit(1)
        print("\nDRAM counters advanced and every IIO stack is carrying traffic. Ready.")
    else:
        label = "baseline (Iris stopped)" if args.baseline else "run"
        print(f"wrote {written} rows to {args.out} ({label})")
        if err.strip() and written == 0:
            print(err[-2000:], file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
