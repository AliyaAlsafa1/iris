#!/usr/bin/env python3
"""Find the smallest `[mempool] capacity` each arm can run on without losing packets.

Answers "if `dyn_hardware_assist` means fewer packets in flight, can we afford a smaller mbuf
pool — and how much memory does that free for application data structures?"

## Read this before reading the numbers

Most of the headroom this finds is **not** an effect of the mechanism. In-use mbufs are dominated
by the pre-filled RX descriptor rings, `nb_rxd x queues x ports`, which are populated at port setup
regardless of what the NIC later drops and are therefore identical in both arms. The arm-sensitive
term is only the mbufs retained for TCP reassembly.

So expect two findings, and keep them apart:

  * a large **right-sizing** win available to both arms, from `capacity` being set far above what
    the datapath ever holds; and
  * a smaller **A/B delta** on top of it, which is the part attributable to hardware shedding.

`--report-both` (the default) prints them separately for exactly this reason.

## Method

Per arm: exponentially bracket downward from the config's capacity to find a failing value, then
binary-search the boundary. A capacity is "viable" for a run iff

  * `memory.mbuf_allocation_errors == 0` — the PMD never wanted an mbuf and found none, and
  * `memory.missed_errors` does not exceed the baseline run's by more than `--missed-tolerance`,
    since a starved pool shows up as no-descriptor drops before it shows up as allocation failures,
    and
  * the run is otherwise valid by the same gates `paired_ab.py` applies.

Each trial is a full run of `--duration` seconds, so a bisection over a 4M starting capacity is
roughly `log2(4e6 / 1e4)` ~ 9 trials per arm. Budget accordingly.

## Caveat on live traffic

Viability is measured against whatever load happened to arrive during that trial. A capacity that
survived a quiet minute can fail in a busy one, so the result is a lower bound, not a guarantee.
`--repeat` re-tests the winning capacity to reduce the chance of a fluke, and the report records
the offered load of every trial so a suspiciously quiet winner is visible rather than hidden.

Usage
-----
    tools/mempool_bisect.py --arms A,B --duration 60 --out-dir results/mempool1

Only the standard library is required.
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

# Reuse the arm definitions so the two harnesses cannot drift apart on what "arm B" means.
from paired_ab import ARMS, check_run  # noqa: E402

GIB = 1 << 30


def parse_args():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--arms", default="A,B", help="comma-separated arms to bisect (default: A,B)")
    p.add_argument(
        "--prefix",
        default="standard",
        help="which mempool prefix to shrink (default: standard). The split pools only exist "
        "under flow_mode = 'split'.",
    )
    p.add_argument(
        "--duration",
        type=int,
        default=None,
        help="override [online] duration for each trial, in seconds. Shorter trials make the "
        "bisection cheaper but less likely to see a burst that starves the pool.",
    )
    p.add_argument("--app-cycles", type=int, default=0)
    p.add_argument("--worker-cores", default="9")
    p.add_argument(
        "--floor",
        type=int,
        default=8192,
        help="never test a capacity below this (default: 8192). Below the RX ring total the port "
        "cannot even be set up, and the failure is uninformative.",
    )
    p.add_argument(
        "--tolerance",
        type=float,
        default=0.05,
        help="stop bisecting once the bracket is within this relative width (default: 0.05)",
    )
    p.add_argument(
        "--missed-tolerance",
        type=int,
        default=0,
        help="allow this many more rx_missed_errors than the baseline run before calling a "
        "capacity unviable (default: 0)",
    )
    p.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="re-test the winning capacity this many extra times (default: 1)",
    )
    p.add_argument("--out-dir", type=Path, default=Path("results/mempool_bisect"))
    p.add_argument("--settle", type=float, default=5.0)
    p.add_argument("--dry-run", action="store_true", help="print the trial plan, run nothing")
    p.add_argument("--quiet", action="store_true", help="capture run output instead of streaming")
    return p.parse_args()


# --------------------------------------------------------------------------- config rewriting


def base_capacity(config_path: Path, prefix: str) -> int:
    """The capacity the config starts from, honouring an existing override for `prefix`."""
    with config_path.open("rb") as fh:
        cfg = tomllib.load(fh)
    mempool = cfg.get("mempool", {})
    return int(mempool.get("capacity_overrides", {}).get(prefix, mempool.get("capacity", 65536)))


def write_variant(config_path: Path, out_path: Path, prefix: str, capacity: int, duration):
    """Write a copy of `config_path` with `prefix`'s capacity overridden.

    Done by appending a `[mempool.capacity_overrides]` table rather than by editing the existing
    `[mempool]` block: TOML tables may be declared in any order, and appending cannot corrupt
    whatever else the config has in that section.

    A `duration` override is appended the same way only if requested — `[online]` already exists in
    any config this tool is useful on, and re-declaring a table is a TOML error, so the duration is
    instead rewritten in place.
    """
    text = config_path.read_text()

    if duration is not None:
        lines = []
        in_online = False
        replaced = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                # Leaving [online] without having seen a duration: add one.
                if in_online and not replaced:
                    lines.append(f"duration = {duration}")
                    replaced = True
                in_online = stripped == "[online]"
            elif in_online and stripped.startswith("duration"):
                line = f"duration = {duration}"
                replaced = True
            lines.append(line)
        if in_online and not replaced:
            lines.append(f"duration = {duration}")
        text = "\n".join(lines) + "\n"

    if "[mempool.capacity_overrides]" in text:
        raise SystemExit(
            f"{config_path} already declares [mempool.capacity_overrides]; remove it so this "
            "tool can set the capacity it is bisecting"
        )
    text += f"\n[mempool.capacity_overrides]\n{prefix} = {capacity}\n"
    out_path.write_text(text)


# --------------------------------------------------------------------------- running


def run_trial(arm, capacity, index, args):
    """One run at one capacity. Returns the parsed report, or None if the run itself failed."""
    spec = ARMS[arm]
    config_src = REPO_ROOT / spec["config"]
    config_dst = args.out_dir / f"config_{arm}_{capacity}_{index:02d}.toml"
    report_path = args.out_dir / f"report_{arm}_{capacity}_{index:02d}.json"

    write_variant(config_src, config_dst, args.prefix, capacity, args.duration)

    cmd = [
        str(REPO_ROOT / "scripts" / "run_eval.sh"),
        str(config_dst),
        "--arm", f"{arm}-cap{capacity}",
        "--drop-mode", spec["drop_mode"],
        "--app-cycles", str(args.app_cycles),
        "--worker-cores", args.worker_cores,
        "--report", str(report_path),
    ]
    print(f"[{time.strftime('%H:%M:%S')}] arm {arm} capacity {capacity:,}: {' '.join(cmd)}",
          flush=True)
    if args.dry_run:
        return None

    if args.quiet:
        proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
        if proc.returncode != 0:
            print(f"  !! exit {proc.returncode}\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}",
                  file=sys.stderr)
            return None
    else:
        proc = subprocess.run(cmd, cwd=REPO_ROOT)
        if proc.returncode != 0:
            print(f"  !! exit {proc.returncode} (output above)", file=sys.stderr)
            return None
    if not report_path.exists():
        print(f"  !! no report written to {report_path}", file=sys.stderr)
        return None

    report = json.loads(report_path.read_text())
    report["_arm"] = arm
    report["_capacity"] = capacity

    # Keep the monitor's mempool.csv beside the report; it carries the per-interval occupancy the
    # single end-of-run snapshot cannot show.
    log_root = REPO_ROOT / "log"
    if log_root.is_dir():
        stamps = sorted((d for d in log_root.iterdir() if d.is_dir()),
                        key=lambda d: d.stat().st_mtime)
        if stamps and (stamps[-1] / "mempool.csv").exists():
            shutil.copy(stamps[-1] / "mempool.csv",
                        args.out_dir / f"mempool_{arm}_{capacity}_{index:02d}.csv")

    time.sleep(args.settle)
    return report


def viability(report, baseline_missed, args):
    """Return (viable, reasons). A capacity is viable only if nothing was starved."""
    reasons = list(check_run(report))
    mem = report["memory"]
    if mem["mbuf_allocation_errors"] > 0:
        reasons.append(f"{mem['mbuf_allocation_errors']} mbuf allocation errors")
    excess = mem["missed_errors"] - baseline_missed
    if excess > args.missed_tolerance:
        reasons.append(
            f"{excess} more no-descriptor drops than baseline ({mem['missed_errors']} vs "
            f"{baseline_missed})"
        )
    return (not reasons), reasons


def offered_bytes(report):
    return sum(p["phy_bytes"] for p in report["ingress"])


# --------------------------------------------------------------------------- bisection


def bisect_arm(arm, args, trials):
    """Bisect one arm. Appends every trial to `trials`; returns a result dict."""
    start = base_capacity(REPO_ROOT / ARMS[arm]["config"], args.prefix)
    print(f"\n=== arm {arm}: bisecting {args.prefix} capacity down from {start:,} ===")

    index = 0

    def trial(cap, baseline_missed):
        nonlocal index
        index += 1
        report = run_trial(arm, cap, index, args)
        if report is None:
            return None, ["run failed"]
        ok, reasons = viability(report, baseline_missed, args)
        trials.append({
            "arm": arm,
            "capacity": cap,
            "viable": ok,
            "reasons": reasons,
            "mbuf_allocation_errors": report["memory"]["mbuf_allocation_errors"],
            "missed_errors": report["memory"]["missed_errors"],
            "peak_in_use_bytes": report["memory"]["total_peak_in_use_bytes"],
            "allocated_bytes": report["memory"]["total_allocated_bytes"],
            "offered_bytes": offered_bytes(report),
        })
        print(f"  -> capacity {cap:,}: {'VIABLE' if ok else 'FAILED'}"
              + ("" if ok else f" ({'; '.join(reasons)})"))
        return report, reasons

    # The starting capacity establishes the no-descriptor-drop baseline. Live traffic produces
    # some missed_errors regardless of pool size, so "any missed_errors" would fail every trial.
    baseline, reasons = trial(start, baseline_missed=0)
    if baseline is None:
        return {"arm": arm, "error": f"baseline run at {start} failed: {'; '.join(reasons)}"}
    baseline_missed = baseline["memory"]["missed_errors"]
    peak_in_use = baseline["memory"]["total_peak_in_use_bytes"]
    print(f"  baseline: {baseline_missed} no-descriptor drops, "
          f"peak {peak_in_use / GIB:.2f} GiB in use")

    # Halve until something fails, so the search has a bracket. `lo` stays unviable, `hi` viable.
    hi, lo = start, None
    cap = start
    while cap // 2 >= args.floor:
        cap //= 2
        report, _ = trial(cap, baseline_missed)
        if report is None:
            lo = cap  # treat a failed run as unviable rather than aborting the bisection
            break
        ok, _ = viability(report, baseline_missed, args)
        if ok:
            hi = cap
        else:
            lo = cap
            break

    if lo is None:
        print(f"  never failed down to the floor {args.floor:,}; that is the answer's lower bound")
        minimum = hi
    else:
        # Binary-search the boundary between `lo` (unviable) and `hi` (viable).
        while (hi - lo) / hi > args.tolerance:
            mid = (lo + hi) // 2
            if mid <= lo or mid >= hi:
                break
            report, _ = trial(mid, baseline_missed)
            if report is None:
                lo = mid
                continue
            ok, _ = viability(report, baseline_missed, args)
            if ok:
                hi = mid
            else:
                lo = mid
        minimum = hi

    # Confirm the winner, since a single trial only saw one minute of traffic.
    confirmations = []
    for _ in range(args.repeat):
        report, reasons = trial(minimum, baseline_missed)
        confirmations.append(report is not None and viability(report, baseline_missed, args)[0])

    return {
        "arm": arm,
        "start_capacity": start,
        "min_viable_capacity": minimum,
        "confirmed": all(confirmations) if confirmations else None,
        "baseline_missed_errors": baseline_missed,
        "baseline_peak_in_use_bytes": peak_in_use,
        "reduction_factor": start / minimum if minimum else None,
    }


# --------------------------------------------------------------------------- reporting


def summarise(results, trials, args):
    print("\n=========================== mempool bisection ===========================")
    for r in results:
        if "error" in r:
            print(f"arm {r['arm']}: {r['error']}")
            continue
        # Bytes are taken from a trial at the winning capacity, so they reflect what DPDK actually
        # reserved rather than capacity x obj_bytes, which understates it (page padding).
        won = [t for t in trials
               if t["arm"] == r["arm"] and t["capacity"] == r["min_viable_capacity"]]
        alloc = won[0]["allocated_bytes"] if won else 0
        start_alloc = next((t["allocated_bytes"] for t in trials
                            if t["arm"] == r["arm"] and t["capacity"] == r["start_capacity"]), 0)
        print(f"arm {r['arm']}:")
        print(f"  capacity  {r['start_capacity']:>12,} -> {r['min_viable_capacity']:>12,} "
              f"({r['reduction_factor']:.1f}x smaller)")
        print(f"  allocated {start_alloc / GIB:>9.2f} GiB -> {alloc / GIB:>9.2f} GiB "
              f"(frees {(start_alloc - alloc) / GIB:.2f} GiB)")
        print(f"  peak in use at baseline: {r['baseline_peak_in_use_bytes'] / GIB:.2f} GiB")
        if r["confirmed"] is False:
            print("  !! the winning capacity failed on re-test; treat it as optimistic")

    ok = [r for r in results if "error" not in r]
    if len(ok) == 2:
        a, b = ok
        print("\n--- separating the two findings ---")
        # Right-sizing: available to both arms, so attribute the smaller of the two reductions to
        # config rather than to the mechanism.
        shared = min(a["min_viable_capacity"], b["min_viable_capacity"])
        print(f"  right-sizing (both arms):  {a['start_capacity']:,} -> {shared:,} mbufs")
        delta = a["min_viable_capacity"] - b["min_viable_capacity"]
        print(f"  A/B delta (the mechanism): {delta:+,} mbufs "
              f"({'B needs fewer' if delta > 0 else 'no saving'})")
        if delta <= 0:
            print("  ^ no mempool saving attributable to hardware shedding. Expected if the RX "
                  "rings dominate the peak; report it as the result.")

    out = args.out_dir / "bisect.json"
    out.write_text(json.dumps({"results": results, "trials": trials}, indent=2) + "\n")
    print(f"\nwrote {out}")


def main():
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    for arm in arms:
        if arm not in ARMS:
            raise SystemExit(f"unknown arm {arm!r}; known arms: {', '.join(ARMS)}")

    trials, results = [], []
    for arm in arms:
        results.append(bisect_arm(arm, args, trials))
    if not args.dry_run:
        summarise(results, trials, args)


if __name__ == "__main__":
    main()
