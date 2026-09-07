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
    sudo tools/mem_sample.py --config configs/online-cx5-eval.toml --sampler-core 35 --selftest

    # the DRAM noise floor, with Iris NOT running
    sudo tools/mem_sample.py --config configs/online-cx5-eval.toml --sampler-core 35 \
        --baseline --duration 30 --out baseline.csv

    # alongside a run (tools/paired_ab.py does this for you)
    sudo tools/mem_sample.py --config configs/online-cx5-eval.toml --sampler-core 35 \
        --duration 120 --out mem_sample.csv

Only the standard library is required.
"""

import argparse
import csv
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import tomllib
from pathlib import Path

PMU_DIR = Path("/sys/bus/event_source/devices")
RESCTRL = Path("/sys/fs/resctrl")
CPU_DIR = Path("/sys/devices/system/cpu")
BYTES_PER_CAS = 64  # a CAS command moves one cache line


# --------------------------------------------------------------------------- topology


def cpu_socket(cpu: int) -> int:
    p = CPU_DIR / f"cpu{cpu}" / "topology" / "physical_package_id"
    return int(p.read_text().strip())


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
    """Bytes per unit of a `bw_in_portN` count, from the PMU's own scale/unit attributes.

    On this host the scale is 3.814697266e-6 with unit MiB, i.e. 4 bytes per count. Read rather
    than hardcoded, because getting this wrong scales every PCIe number silently.
    """
    base = PMU_DIR / f"uncore_iio_free_running_{pmu_index}" / "events"
    try:
        scale = float((base / "bw_in_port0.scale").read_text().strip())
        unit = (base / "bw_in_port0.unit").read_text().strip()
    except OSError:
        return 4.0  # documented default for this counter family
    mult = {"MiB": 1 << 20, "KiB": 1 << 10, "Bytes": 1, "B": 1}.get(unit, 1 << 20)
    return scale * mult


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
        """Read every group's monitoring files. Returns {(socket, domain, field): value}."""
        out = {}
        for socket, g in self.groups.items():
            for dom in sorted((g["path"] / "mon_data").glob("mon_L3_*")):
                domain = int(dom.name.rsplit("_", 1)[1])
                for field in ("llc_occupancy", "mbm_total_bytes", "mbm_local_bytes"):
                    try:
                        raw = (dom / field).read_text().strip()
                    except OSError:
                        continue
                    # "Unavailable" appears when no RMID is assigned yet.
                    out[(socket, domain, field)] = int(raw) if raw.isdigit() else None
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
            "scale": BYTES_PER_CAS,
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
                "scale": scale,
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
    }


class PerfSampler:
    """Runs `perf stat` as a child and reads its interval rows off stdout."""

    def __init__(self, specs, event_args, interval_ms, sampler_core):
        self.specs = specs
        self.by_event = {}
        for s in specs:
            self.by_event.setdefault(s["event"], []).append(s)
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

    def start(self):
        if shutil.which("perf") is None:
            raise SystemExit("perf not found on PATH")
        self.proc = subprocess.Popen(
            self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        return self

    def rows(self):
        """Yield parsed rows as perf emits them."""
        assert self.proc and self.proc.stdout
        for line in self.proc.stdout:
            parsed = parse_perf_json_line(line)
            if parsed:
                yield parsed

    def stop(self):
        if not self.proc:
            return ""
        self.proc.send_signal(signal.SIGINT)
        try:
            _, err = self.proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            _, err = self.proc.communicate()
        return err or ""


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
            scaled = r["value"] * spec["scale"]
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
        "llc_occupancy_bytes",
        # The decomposition. IO-originated = everything the memory controller saw that the cores
        # did not originate; on Skylake-SP that is DDIO/IIO traffic, which carries no RMID.
        "core_dram_bytes",
        "io_dram_bytes",
        "io_dram_fraction",
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
        print(f"port {p['device']}  root bus {bus} -> "
              + (f"uncore_iio_{loc[0]} die{loc[1]}, {iio_scale(loc[0]):.1f} B/count"
                 if loc else "NO IIO STACK FOUND"))

    specs, event_args = build_events(layout)
    specs_by_event = {}
    for s in specs:
        specs_by_event.setdefault(s["event"], []).append(s)

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

        stop = {"now": False}
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.update(now=True))

        with args.out.open("w", newline="") as fh:
            wtr = csv.DictWriter(fh, fieldnames=csv_fields(port_devices),
                                 extrasaction="ignore")
            wtr.writeheader()

            batch, cur_interval, intervals_done = [], None, 0
            for row in sampler.rows():
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

                        # RDT deltas for this socket's group, summed over its L3 domains.
                        mbm_total = mbm_local = 0
                        occ = 0
                        for (s, dom, field), v in rdt.items():
                            if s != socket or v is None:
                                continue
                            p = prev_rdt.get((s, dom, field))
                            if field == "llc_occupancy":
                                occ += v
                            elif p is not None:
                                d = v - p
                                if d < 0:
                                    d = 0  # counter wrap or RMID reassignment
                                if field == "mbm_total_bytes":
                                    mbm_total += d
                                else:
                                    mbm_local += d
                        rec["mbm_total_bytes"] = mbm_total
                        rec["mbm_local_bytes"] = mbm_local
                        rec["llc_occupancy_bytes"] = occ

                        # The headline decomposition.
                        core = mbm_total
                        io = max(0, rec["imc_bytes"] - core)
                        rec["core_dram_bytes"] = core
                        rec["io_dram_bytes"] = io
                        rec["io_dram_fraction"] = (
                            round(io / rec["imc_bytes"], 6) if rec["imc_bytes"] else 0.0
                        )
                        wtr.writerow(rec)
                        written += 1
                    fh.flush()

                    prev_rdt = rdt
                    batch, cur_interval = [], row["interval"]
                    intervals_done += 1
                    if n_intervals and intervals_done >= n_intervals:
                        break
                    if args.duration and (time.time() - started) >= args.duration:
                        break
                    if stop["now"]:
                        break
                batch.append(row)

        err = sampler.stop()

    if args.selftest:
        print("=== selftest ===")
        wanted = sorted(specs_by_event)
        ok = True
        for ev in wanted:
            state = ("advanced" if ev in advanced
                     else "SEEN BUT ZERO" if ev in seen_events
                     else "NOT SEEN")
            print(f"  {ev:<48} {state}")
            if ev not in advanced:
                ok = False
        print(f"  rows written: {written}")
        if not ok:
            print("\nSome counters did not advance. Raw perf stderr follows so the cause is "
                  "visible rather than guessed:\n", file=sys.stderr)
            print(err[-4000:], file=sys.stderr)
            print("Common causes: perf_event_paranoid not -1 (run scripts/mem_setup.sh); the "
                  "event name differs on this kernel; or nothing is generating traffic, which is "
                  "expected for iio_in when no packets are arriving.", file=sys.stderr)
            sys.exit(1)
        print("\nAll counters advanced and parsed. Ready.")
    else:
        label = "baseline (Iris stopped)" if args.baseline else "run"
        print(f"wrote {written} rows to {args.out} ({label})")
        if err.strip() and written == 0:
            print(err[-2000:], file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
