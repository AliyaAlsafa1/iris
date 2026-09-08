#!/usr/bin/env python3
"""Paired A/B runner and analysis for the dyn_hardware_assist cycle-budget evaluation.

Runs the arms in an alternating A,B,A,B,... sequence, collects each run's JSON report, and reports:

  M1  cycles per *ingress* packet, with a paired test over the A/B pairs. Ingress-normalised, so
      it is comparable even though the two runs in a pair never see identical live traffic.
  M2  the per-core cycle budget, whose poll_idle bucket is the freed-cycle pool.
  M3  a per-arm regression of duty cycle on offered load, fitted from the per-second rows in each
      run's cycle_budget.csv. The slope gap is the effect size and, unlike M1, it does not assume
      the two arms saw comparable load at all.

With --mem-sample, the memory-side metrics are collected from the same runs and reported alongside:

  N1  DRAM bytes per *ingress* byte, per socket, with the same paired test. Ingress-normalised for
      the same reason M1 is.
  N2  that traffic split into core-originated (RDT MBM) and IO-originated (IMC minus MBM), plus
      PCIe inbound bytes. Answers whether packet writes or the application dominate memory usage.
  N3  the RX cores' LLC occupancy (RDT CMT).

Why from the same runs rather than separate ones: freed cycles and freed memory bandwidth are two
views of the same shed traffic, so measuring them together lets a single run state both at a given
offered load. The cycle instrumentation issues no memory reference of its own — `rte_rdtsc` is a
register read — but that is checked rather than assumed, by running with `budget_sample_stride = 0`
and confirming N1 does not move.

Why alternating rather than one run per arm: campus traffic is non-stationary on a minutes
timescale, so back-to-back runs of the same arm differ. Alternating makes the arm assignment
roughly orthogonal to the drift, and pairing lets the analysis difference it out.

Usage
-----
    tools/paired_ab.py --pairs 10 --app-cycles 100000 --out-dir results/run1

Add --dry-run to print the commands without executing anything.

Only the standard library is required; the paired test is an exact sign test, so scipy is not
needed. Pass --plot to also write the M3 regression figure, which does need matplotlib.
"""

import argparse
import csv
import json
import math
import shutil
import signal
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Arms. `config` is relative to REPO_ROOT; `drop_mode` selects the mechanism.
#
# Note A is dyn_hardware_assist=true with no rules installed, NOT dyn_hardware_assist=false.
# Using the latter as the baseline would fold the flow-engine reconfiguration into the measured
# effect, since that flag reconfigures the NIC flow engine whether or not any rule drops a packet.
ARMS = {
    "A": dict(config="configs/online-cx5-eval.toml", drop_mode="none",
              label="control (assist configured, no rules)"),
    "B": dict(config="configs/online-cx5-eval.toml", drop_mode="hardware",
              label="treatment (NIC per-connection drop)"),
}


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pairs", type=int, default=10,
                   help="number of A/B pairs to run (default: 10)")
    p.add_argument("--arms", default="A,B",
                   help="comma-separated arms to alternate through (default: A,B)")
    p.add_argument("--app-cycles", type=int, default=0,
                   help="synthetic application work per TLS connection, in TSC cycles")
    p.add_argument("--max-rules", type=int, default=0,
                   help="cap on concurrently installed NIC rules (0 = unbounded)")
    p.add_argument("--table-full-policy", choices=("refuse", "evict"), default="refuse",
                   help="at --max-rules: refuse further offloads, or evict the least recently "
                        "added rule (FIFO) to make room (default: refuse)")
    p.add_argument("--worker-cores", default="13",
                   help="cores for the rte_flow install worker (default: 13 — NUMA-local to "
                        "the node-0 CX-5 and outside the RX set in configs/online-cx5-eval.toml. "
                        "hw_assist_eval panics if this overlaps an RX core.)")
    p.add_argument("--out-dir", type=Path, default=Path("results/paired_ab"),
                   help="where to write reports, the tidy CSV and the summary")
    p.add_argument("--settle", type=float, default=5.0,
                   help="seconds to wait between runs so the NIC and rule table quiesce")
    p.add_argument("--load-tolerance", type=float, default=0.10,
                   help="discard a pair whose two runs differ in ingress bytes by more than this "
                        "fraction (default: 0.10)")
    p.add_argument("--mem-sample", action="store_true",
                   help="collect memory counters (uncore IMC/IIO, RDT MBM/CMT) alongside each "
                        "run via tools/mem_sample.py, and report N1-N3. Needs "
                        "scripts/mem_setup.sh to have been run.")
    p.add_argument("--sampler-core", type=int, default=None,
                   help="core to pin the memory sampler to. Required with --mem-sample, and "
                        "must not be an RX core or a --worker-cores core: sampling from a "
                        "measured core steals its cycles and pollutes its LLC occupancy.")
    p.add_argument("--clamp-tolerance", type=float, default=0.05,
                   help="reject a socket's memory data when more than this fraction of its "
                        "io_dram was clamped away because MBM momentarily exceeded IMC "
                        "(default: 0.05). Occasional clamping is sampling skew and cancels; a "
                        "large share means the counters genuinely disagree.")
    p.add_argument("--allow-cross-numa", action="store_true",
                   help="proceed even though a port's RX cores are not on the port's NUMA node. "
                        "Only for deliberately measuring the cross-socket case.")
    p.add_argument("--mem-baseline", type=Path, default=None,
                   help="a mem_sample.py --baseline CSV, measured with Iris stopped. Its DRAM "
                        "rate is subtracted from N1, since uncore counters are socket-wide and "
                        "include the OS and the sampler itself.")
    p.add_argument("--plot", action="store_true", help="write the M3 regression plot (matplotlib)")
    p.add_argument("--dry-run", action="store_true", help="print commands, run nothing")
    p.add_argument("--quiet", action="store_true",
                   help="capture each run's output instead of streaming it to the terminal, and "
                        "print only the tail on failure. Useful for long unattended batches; the "
                        "default streams so a run's progress is visible.")
    p.add_argument("--analyze-only", action="store_true",
                   help="skip the runs and re-analyze reports already in --out-dir")
    return p.parse_args()


# --------------------------------------------------------------------------- running


def start_mem_sampler(arm, index, args):
    """Launch tools/mem_sample.py for the duration of one run.

    Started before the run rather than after so the first intervals are covered, and given no
    --duration: it is stopped by SIGINT when the run returns, which is what bounds it. That way a
    run that ends early does not leave a sampler running into the next one.
    """
    if not args.mem_sample:
        return None, None
    out = args.out_dir / f"mem_sample_{arm}_{index:03d}.csv"
    cmd = [
        "sudo", str(REPO_ROOT / "tools" / "mem_sample.py"),
        "--config", ARMS[arm]["config"],
        "--sampler-core", str(args.sampler_core),
        "--worker-cores", args.worker_cores,
        "--out", str(out),
    ]
    if args.dry_run:
        print(f"    (would start: {' '.join(cmd)})")
        return None, out
    proc = subprocess.Popen(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    return proc, out


def stop_mem_sampler(proc, out):
    """SIGINT the sampler and wait for it to flush its CSV."""
    if proc is None:
        return
    try:
        proc.send_signal(signal.SIGINT)
        stdout, _ = proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, _ = proc.communicate()
    if proc.returncode not in (0, -2, 130) or not (out and out.exists()):
        print(f"  !! memory sampler failed (exit {proc.returncode}); "
              f"N1-N3 will be missing for this run", file=sys.stderr)
        if stdout:
            print(stdout[-2000:], file=sys.stderr)


def run_one(arm, index, args):
    """Run one arm once. Returns the parsed report dict, or None on failure."""
    spec = ARMS[arm]
    report_path = args.out_dir / f"report_{arm}_{index:03d}.json"
    cmd = [
        str(REPO_ROOT / "scripts" / "run_eval.sh"),
        spec["config"],
        "--arm", arm,
        "--drop-mode", spec["drop_mode"],
        "--app-cycles", str(args.app_cycles),
        "--max-rules", str(args.max_rules),
        "--table-full-policy", args.table_full_policy,
        "--worker-cores", args.worker_cores,
        "--report", str(report_path),
    ]

    print(f"[{time.strftime('%H:%M:%S')}] arm {arm} run {index}: {' '.join(cmd)}", flush=True)
    if args.dry_run:
        start_mem_sampler(arm, index, args)
        return None

    mem_proc, mem_out = start_mem_sampler(arm, index, args)

    # Stream by default: a run is `duration` seconds long and captured output means a silent
    # terminal for all of it, with no way to tell a healthy run from a hang. Inheriting the
    # terminal rather than piping also keeps DPDK's own C-buffered output line-prompt, which a
    # pipe would hold back in 4 KB blocks.
    #
    # `finally`, not a stop at each exit: a sampler left running past its run would keep a resctrl
    # monitoring group holding the RX cores, and the next run would then measure through it.
    try:
        if args.quiet:
            proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
            if proc.returncode != 0:
                print(f"  !! exit {proc.returncode}\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}",
                      file=sys.stderr)
                return None
        else:
            proc = subprocess.run(cmd, cwd=REPO_ROOT)
            if proc.returncode != 0:
                # No tail to reprint: the run's output already went to the terminal above.
                print(f"  !! exit {proc.returncode} (output above)", file=sys.stderr)
                return None
        if not report_path.exists():
            print(f"  !! no report written to {report_path}", file=sys.stderr)
            return None
    finally:
        stop_mem_sampler(mem_proc, mem_out)

    report = json.loads(report_path.read_text())

    # The monitor writes cycle_budget.csv into a fresh timestamped directory per run. Move the
    # newest one next to the report so the M3 regression can find it, and so a later run cannot
    # overwrite the association.
    log_root = REPO_ROOT / "log"
    if log_root.is_dir():
        stamps = sorted((d for d in log_root.iterdir() if d.is_dir()),
                        key=lambda d: d.stat().st_mtime)
        if stamps:
            src = stamps[-1] / "cycle_budget.csv"
            if src.exists():
                shutil.copy(src, args.out_dir / f"budget_{arm}_{index:03d}.csv")

    report["_arm"] = arm
    report["_index"] = index
    return report


# --------------------------------------------------------------------------- validity


# Prefix marking the one gate that is fatal to M1 but not necessarily to the per-socket N1.
PHY_GATE = "no-rx-phy"

# Prefix marking problems that invalidate the core/IO decomposition (N2) but NOT N1. N1 is
# imc_bytes over rx_phy_bytes and involves no RDT counter, so an MBM/IMC disagreement cannot
# touch it. Excluding such a run outright would discard the headline metric to protect a
# secondary one.
DECOMP_GATE = "decomposition"


def phy_only_failures(problems):
    """True when the only thing wrong with a run is the machine-wide rx_phy_* gate.

    Such a run is unusable for M1, whose denominator sums every port's phy_bytes, but its memory
    metrics are still sound on any socket whose own ports report the counters.
    """
    return bool(problems) and all(p.startswith(PHY_GATE) for p in problems)


def check_run(report):
    """Return a list of reasons this run must not be used. Empty means usable.

    These are hard validity gates, not warnings: each one, if ignored, produces a number that
    looks plausible and is wrong.
    """
    problems = []
    b = report["budget"]
    n = report["normalised"]

    if not n["ingress_normalisation_valid"]:
        # Tagged so the memory analysis can tell this apart from the other gates. M1 sums every
        # port's phy_bytes into one denominator, so a single port without the counters spoils it
        # — but N1 is computed per socket, and a socket whose own ports all report phy_* is still
        # sound. See `phy_only_failures`.
        problems.append(PHY_GATE + ": PMD exposed no rx_phy_* counters, so M1 is meaningless")
    if abs(b["residual_fraction"]) > 1e-3:
        problems.append(f"cycle budget does not close (residual {b['residual_fraction']:.2%})")
    if b["instrumentation_fraction"] > 0.02:
        problems.append(f"instrumentation is {b['instrumentation_fraction']:.2%} of wall")
    if b["rx_cores"] == 0:
        problems.append("no RX cores reported a budget")
    # Sampled cycle attribution needs enough samples for the fractions to be stable. A few
    # thousand sampled iterations is plenty; a handful is not.
    if b.get("sampled_iters", 0) < 1000:
        problems.append(f"only {b.get('sampled_iters', 0)} sampled iterations: "
                        "cycle fractions are too noisy")
    if report["drop_mode"] == "hardware":
        if report["ground_truth"]["discarded_packets"] == 0:
            problems.append("treatment arm shed nothing: NIC COUNT handles read zero")
        if report["control_plane"]["install_failures"] > 0:
            problems.append(f"{report['control_plane']['install_failures']} rule installs failed")
    return problems


def check_pair(a, b, tolerance):
    """Reasons this pair must be discarded."""
    problems = []

    # Arm equivalence: the app-work callback fires once per TLS connection at the ciphertext
    # transition, so it must fire a comparable number of times in both arms. If it does not, the
    # arms did different amounts of work and the cycle comparison is meaningless.
    ca, cb = a["tls_callbacks"], b["tls_callbacks"]
    if ca == 0 or cb == 0:
        problems.append("a run saw no TLS connections")
    else:
        skew = abs(ca - cb) / max(ca, cb)
        if skew > 0.25:
            problems.append(f"TLS callback counts differ by {skew:.0%} ({ca} vs {cb}): "
                            "the arms did not do the same work")

    ia = sum(p["phy_bytes"] for p in a["ingress"])
    ib = sum(p["phy_bytes"] for p in b["ingress"])
    if ia == 0 or ib == 0:
        problems.append("a run saw no ingress traffic")
    else:
        drift = abs(ia - ib) / max(ia, ib)
        if drift > tolerance:
            problems.append(f"offered load drifted {drift:.0%} between the arms")
    return problems


# --------------------------------------------------------------------------- analysis


def sign_test(diffs):
    """Two-sided exact sign test. Returns (n_effective, n_negative, p).

    Used instead of a paired t-test because a handful of pairs on live traffic gives no basis for
    assuming normal differences, and instead of Wilcoxon to avoid a scipy dependency. It is the
    conservative choice: it only uses the direction of each pair.
    """
    nz = [d for d in diffs if d != 0]
    n = len(nz)
    if n == 0:
        return 0, 0, 1.0
    k = sum(1 for d in nz if d < 0)
    # Two-sided: P(X <= min(k, n-k)) * 2 under Binomial(n, 0.5).
    m = min(k, n - k)
    tail = sum(math.comb(n, i) for i in range(m + 1)) / (2 ** n)
    return n, k, min(1.0, 2 * tail)


def linfit(xs, ys):
    """Ordinary least squares. Returns (slope, intercept, r2, n)."""
    n = len(xs)
    if n < 3:
        return None
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return None
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    slope = sxy / sxx
    intercept = my - slope * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    r2 = 1 - ss_res / ss_tot if ss_tot > 0 else float("nan")
    return slope, intercept, r2, n


def load_budget_rows(out_dir, arm):
    """Per-interval (offered load Gbps, busy fraction) points for one arm, across its runs.

    Intervals with no ingress are skipped: they carry no load information and would anchor the
    regression at the origin.
    """
    points = []
    for path in sorted(out_dir.glob(f"budget_{arm}_*.csv")):
        with path.open() as fh:
            for row in csv.DictReader(fh):
                try:
                    # d_wall is the exact interval span; busy_fraction is already computed
                    # against d_sampled_wall by the monitor, so no rescaling is needed here.
                    d_wall = float(row["d_wall"])
                    d_bytes = float(row["d_ingress_bytes"])
                    busy = float(row["busy_fraction"])
                    cores = float(row["rx_cores"]) or 1.0
                except (KeyError, ValueError):
                    continue
                if d_wall <= 0 or d_bytes <= 0:
                    continue
                # Convert the interval's ingress bytes to Gbps using the interval's own duration,
                # derived from wall cycles per core rather than the nominal log interval.
                # (Cycles are TSC ticks; tsc_hz comes from the report, applied by the caller.)
                points.append((d_bytes, busy, d_wall / cores))
    return points


# --------------------------------------------------------------------------- memory (N1-N3)


MEM_SUM_FIELDS = ("imc_bytes", "imc_read_bytes", "imc_write_bytes", "iio_in_bytes",
                  "mbm_total_bytes", "mbm_local_bytes", "mbm_remote_bytes",
                  "mbm_other_local_bytes", "core_dram_bytes", "io_dram_bytes",
                  "io_dram_clamped", "io_dram_deficit_bytes")

# Occupancies, not deltas: these belong nowhere near MEM_SUM_FIELDS. Adding a gauge across
# intervals produces a number that grows with run length and means nothing at all.
MEM_GAUGE_FIELDS = ("llc_occupancy_bytes", "llc_occupancy_all_bytes", "llc_ddio_bytes",
                    "llc_ddio_fraction")


def load_mem_totals(out_dir, arm, index):
    """Totals per socket for one run's mem_sample CSV, plus mean LLC occupancy.

    Byte columns are per-interval deltas, so they sum. The `llc_*` columns are gauges, so they are
    averaged instead — summing an occupancy would be meaningless.

    A gauge whose column is missing or blank throughout gives a mean of None rather than 0.0, which
    is what a mem_sample CSV written before the `llc_ddio_*` columns existed, or written on a host
    whose LLC size could not be read, looks like. `llc_occupancy_bytes_mean` keeps its old 0.0
    because `check_mem_run` gates on it.
    """
    path = out_dir / f"mem_sample_{arm}_{index:03d}.csv"
    if not path.exists():
        return None
    totals = defaultdict(lambda: defaultdict(float))
    gauges = defaultdict(lambda: defaultdict(list))
    intervals = defaultdict(int)
    with path.open() as fh:
        for row in csv.DictReader(fh):
            try:
                socket = int(row["socket"])
            except (KeyError, ValueError):
                continue
            for f in MEM_SUM_FIELDS:
                try:
                    totals[socket][f] += float(row.get(f) or 0.0)
                except ValueError:
                    pass
            for f in MEM_GAUGE_FIELDS:
                raw = row.get(f)
                if raw is None or not str(raw).strip():
                    continue
                try:
                    gauges[socket][f].append(float(raw))
                except ValueError:
                    pass
            intervals[socket] += 1
    out = {}
    for socket, vals in totals.items():
        d = dict(vals)
        # Undo the per-interval clamp: summing clamped values keeps every positive excursion and
        # discards every negative one, so the total overstates IO traffic by exactly the deficit.
        d["io_dram_bytes"] = max(0.0, d.get("io_dram_bytes", 0.0)
                                 - d.get("io_dram_deficit_bytes", 0.0))
        d["intervals"] = intervals[socket]
        for f in MEM_GAUGE_FIELDS:
            seen = gauges[socket][f]
            d[f"{f}_mean"] = statistics.fmean(seen) if seen else None
        d["llc_occupancy_bytes_mean"] = d["llc_occupancy_bytes_mean"] or 0.0
        out[socket] = d
    return out or None


def ingress_by_socket(report):
    """Ingress bytes/packets summed per socket, using the report's own socket_id field.

    Positional pairing with the config's port list would be fragile — DPDK port ids follow probe
    order, not config order — which is why `IngressCounters` carries `socket_id`.
    """
    out = defaultdict(lambda: {"phy_bytes": 0, "phy_packets": 0, "good_bytes": 0,
                               "phy_available": True})
    for p in report["ingress"]:
        s = p.get("socket_id")
        if s is None:
            continue
        out[s]["phy_bytes"] += p["phy_bytes"]
        out[s]["phy_packets"] += p["phy_packets"]
        out[s]["good_bytes"] += p["good_bytes"]
        out[s]["phy_available"] &= bool(p.get("phy_available", False))
    return dict(out)


def check_mem_run(report, mem, clamp_tolerance=0.05):
    """Hard validity gates for the memory side, in the spirit of `check_run`.

    Each of these, if ignored, yields a number that looks plausible and is wrong.
    """
    problems = []
    if not mem:
        return ["no mem_sample CSV for this run"]
    ing = ingress_by_socket(report)

    # A zero ingress denominator is the one failure that used to pass silently: every /phy column
    # renders as 0.000 and N1 reports "no complete pairs", which reads like a pairing problem
    # rather than the missing input it is. Two distinct causes, so name both.
    if not ing:
        problems.append(
            "the report's ingress[] carries no socket_id, so ingress cannot be attributed per "
            "socket. This means the binary predates that field — rebuild with scripts/build.sh"
        )
    else:
        for socket in sorted(mem):
            phy = ing.get(socket, {}).get("phy_bytes", 0)
            if not phy:
                problems.append(
                    f"socket {socket}: rx_phy_bytes is 0, so there is no N1 denominator — "
                    "either no traffic reached the ports on this socket during the run, or the "
                    "PMD exposed no counters (check ingress[] in the report)"
                )

    for socket, vals in sorted(mem.items()):
        if vals["intervals"] < 10:
            problems.append(f"socket {socket}: only {vals['intervals']} sampled intervals")
        if vals["imc_bytes"] <= 0:
            problems.append(f"socket {socket}: IMC counters never advanced — perf could not read "
                            "the memory controllers")
        # The PCIe/NIC cross-check. If the IIO stack were misidentified this ratio goes wild, and
        # every other memory number for that socket is then attributed to the wrong device.
        phy = ing.get(socket, {}).get("phy_bytes", 0)
        if phy > 0 and vals["iio_in_bytes"] > 0:
            ratio = vals["iio_in_bytes"] / phy
            if not 0.5 <= ratio <= 3.0:
                problems.append(
                    f"socket {socket}: PCIe inbound / rx_phy_bytes = {ratio:.2f}, outside [0.5, 3]"
                    " — likely the wrong IIO stack, so its byte attribution cannot be trusted"
                )
        # io_dram clamping: MBM briefly exceeded IMC on some intervals. Occasional clamping is
        # expected — the two counters are not read atomically, so a burst can land inside one
        # sampling window and outside the other, and the error cancels across intervals. What
        # matters is not how often it happened but how much was discarded, since clamping keeps
        # positive excursions and drops negative ones, biasing io_dram upward. Gate on the
        # magnitude; `io_dram_bytes` below is already net of it.
        clamped_n = int(vals.get("io_dram_clamped", 0))
        deficit = vals.get("io_dram_deficit_bytes", 0.0)
        gross_io = vals.get("io_dram_bytes", 0.0) + deficit
        if clamped_n and not deficit:
            # Pre-dates the deficit column, so the bias cannot be sized or corrected.
            problems.append(
                f"{DECOMP_GATE}: socket {socket}: io_dram clamped on {clamped_n} of "
                f"{vals['intervals']} "
                "intervals and this CSV predates io_dram_deficit_bytes, so the upward bias in "
                "IO% cannot be measured or removed — re-collect to size it"
            )
        elif gross_io > 0 and deficit / gross_io > clamp_tolerance:
            problems.append(
                f"{DECOMP_GATE}: socket {socket}: {100 * deficit / gross_io:.1f}% of io_dram "
                "was clamped away "
                f"(on {clamped_n} of {vals['intervals']} intervals) — MBM and IMC disagree by "
                "too much for the core/IO split to be trustworthy"
            )
        # RX cores reaching the other socket's memory. Should be ~0 with a NUMA-local config.
        if vals.get("mbm_total_bytes", 0) > 0:
            remote_share = vals.get("mbm_remote_bytes", 0) / vals["mbm_total_bytes"]
            if remote_share > 0.05:
                problems.append(
                    f"socket {socket}: {100 * remote_share:.0f}% of RX-core memory traffic went "
                    "to the other socket, so this socket's core/IO split is mixed across domains"
                )
        if vals["llc_occupancy_bytes_mean"] <= 0:
            problems.append(f"socket {socket}: LLC occupancy read zero — the resctrl monitoring "
                            "group held no RX cores, so N3 is invalid")
    return problems


def load_mem_baseline(path):
    """Mean per-socket DRAM bytes per interval from a --baseline CSV, for subtraction."""
    if not path or not Path(path).exists():
        return {}
    per_socket = defaultdict(list)
    with Path(path).open() as fh:
        for row in csv.DictReader(fh):
            try:
                per_socket[int(row["socket"])].append(float(row["imc_bytes"]))
            except (KeyError, ValueError):
                continue
    return {s: statistics.fmean(v) for s, v in per_socket.items() if v}


def analyze_memory(usable, args):
    """N1-N3: DRAM per ingress byte, the core/IO decomposition, and LLC occupancy."""
    mem_by_run = {}
    for r, _ in usable:
        mem = load_mem_totals(args.out_dir, r["_arm"], r["_index"])
        problems = check_mem_run(r, mem, args.clamp_tolerance)
        mem_by_run[(r["_arm"], r["_index"])] = (mem, problems)

    def fatal(problems):
        return [x for x in problems if not x.startswith(DECOMP_GATE)]

    have = [k for k, (m, p) in mem_by_run.items() if m and not fatal(p)]
    print("\n" + "=" * 78)
    print("N1-N3  MEMORY SYSTEM")
    print("=" * 78)
    if not have:
        print("no usable memory samples. Reasons per run:")
        for (arm, idx), (_, problems) in sorted(mem_by_run.items()):
            print(f"  arm {arm} run {idx}: {'; '.join(fatal(problems)) or 'ok'}")
        return
    for (arm, idx), (_, problems) in sorted(mem_by_run.items()):
        hard = fatal(problems)
        if hard:
            print(f"  REJECT memory for arm {arm} run {idx}: {'; '.join(hard)}")
        # Decomposition-only problems leave N1 intact, so the run is still used; the core/IO
        # split from it is what should be discounted.
        for soft in (x for x in problems if x.startswith(DECOMP_GATE)):
            print(f"  WARN  arm {arm} run {idx}: {soft[len(DECOMP_GATE) + 2:]}")
            print("        N1 is unaffected (it uses no RDT counter); treat IO% and core/phy "
                  "from this run with caution.")

    baseline = load_mem_baseline(args.mem_baseline)
    if baseline:
        print(f"\nDRAM baseline (Iris stopped), per interval: "
              + ", ".join(f"socket {s}: {v / 1e6:.1f} MB" for s, v in sorted(baseline.items())))
        print("  subtracted from N1 below, since uncore counters are socket-wide.")
    else:
        print("\nNo --mem-baseline given: N1 includes whatever else the box was doing. "
              "Measure it with `mem_sample.py --baseline` and pass it in.")

    # ---- N2 decomposition, per arm per socket ----
    print("\n--- N2  where the memory traffic comes from (means over usable runs) ---")
    print(f"{'arm':<4}{'sock':>5}{'n':>3}{'DRAM/phy':>10}{'rd/phy':>8}{'wr/phy':>8}"
          f"{'PCIe/phy':>10}{'wr-PCIe':>9}{'IO%':>7}{'core/phy':>10}{'LLC MiB':>9}"
          f"{'DDIO MiB':>10}{'DRAM GB':>10}")
    per_arm_socket = defaultdict(list)
    for (arm, idx) in have:
        mem, _ = mem_by_run[(arm, idx)]
        for socket, vals in mem.items():
            per_arm_socket[(arm, socket)].append((vals, idx))
    for (arm, socket) in sorted(per_arm_socket):
        entries = per_arm_socket[(arm, socket)]
        def mean(f):
            return statistics.fmean(v[f] for v, _ in entries)
        # A gauge is None for a run whose sampler did not record it; those runs drop out of the
        # mean rather than being read as zero, and a column no run recorded stays absent.
        def gauge_mean(f):
            seen = [v[f] for v, _ in entries if v.get(f) is not None]
            return statistics.fmean(seen) if seen else None
        report_by_idx = {r["_index"]: r for r, _ in usable if r["_arm"] == arm}
        phys = [ingress_by_socket(report_by_idx[i]).get(socket, {}).get("phy_bytes", 0)
                for _, i in entries]
        phy_mean = statistics.fmean(phys) if phys else 0
        imc, core, io = mean("imc_bytes"), mean("core_dram_bytes"), mean("io_dram_bytes")
        pcie = mean("iio_in_bytes")
        # Per-ingress-byte columns are the only ones comparable *across* arms: the absolute GB
        # figures scale with whatever load happened to arrive, and the two arms need not have
        # the same number of surviving runs (see `n`), so their raw totals are not commensurate.
        def per_phy(v):
            return v / phy_mean if phy_mean else 0.0
        rd, wr = mean("imc_read_bytes"), mean("imc_write_bytes")
        # wr/phy minus PCIe/phy is the write traffic NOT explained by DMA'd payload being
        # evicted once. It is what separates "we are writing packet bodies" from "we are writing
        # something else we never read": payload writes track DMA, per-packet metadata and
        # application writes do not. Expect a small, arm-stable offset.
        excess = per_phy(wr) - per_phy(pcie)
        ddio = gauge_mean("llc_ddio_bytes_mean")
        ddio_col = f"{'-':>10}" if ddio is None else f"{ddio / (1 << 20):>10.2f}"
        print(f"{arm:<4}{socket:>5}{len(entries):>3}{per_phy(imc):>10.3f}"
              f"{per_phy(rd):>8.3f}{per_phy(wr):>8.3f}{per_phy(pcie):>10.2f}"
              f"{excess:>+9.3f}{100 * (io / imc if imc else 0):>6.1f}%"
              f"{per_phy(core):>10.3f}"
              f"{mean('llc_occupancy_bytes_mean') / (1 << 20):>9.2f}{ddio_col}"
              f"{imc / 1e9:>10.2f}")
    print("  core = RDT MBM mbm_local, RX cores PLUS every other CPU (resctrl root group), so")
    print("  other processes are not misattributed. IO = IMC minus that: traffic the memory")
    print("  controller saw with no core behind it, i.e. DDIO/IIO, which carries no RMID here.")
    print("  IO% answers 'do packet writes or the application dominate memory usage' — note its")
    print("  denominator is imc_bytes, not ingress, so it is a composition share and barely moves")
    print("  between arms even when the /phy columns do. The effect lives in the /phy columns.")
    print("  DRAM GB is load-dependent and NOT comparable across arms; the /phy columns are.")
    print("  PCIe/phy should sit near 1: far from it means the wrong IIO stack was read.")
    print("  wr-PCIe is write traffic beyond DMA'd payload evicted once — per-packet metadata and")
    print("  application writes. A small, arm-stable value means the writes really are payload.")
    print("  LLC MiB is CMT occupancy for the RX cores only. DDIO MiB is the same gap read through")
    print("  CMT: LLC size minus occupancy summed over every RMID (RX groups plus resctrl root),")
    print("  i.e. cache lines no core brought in, which here means packet DMA. It is the direct")
    print("  form of 'do packets evict the connection table', where IO% only says where bytes go.")
    print("  It over-counts when the LLC is not full (invalid lines carry no RMID either), reads")
    print("  high for a few seconds after group creation while resctrl drains recycled RMIDs, and")
    print("  is instantaneous state — a burst between two samples leaves no trace. '-' means the")
    print("  sampler did not record it: an older CSV, or a host whose LLC size could not be read.")

    # ---- N1 paired ----
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    if len(arms) < 2:
        return
    a_arm, b_arm = arms[0], arms[1]
    sockets = sorted({s for (_, s) in per_arm_socket})
    for socket in sockets:
        pairs = []
        for r, _ in usable:
            if r["_arm"] != a_arm:
                continue
            idx = r["_index"]
            if (a_arm, idx) not in have or (b_arm, idx) not in have:
                continue
            a_mem = mem_by_run[(a_arm, idx)][0].get(socket)
            b_mem = mem_by_run[(b_arm, idx)][0].get(socket)
            b_rep = next((x for x, _ in usable
                          if x["_arm"] == b_arm and x["_index"] == idx), None)
            if not (a_mem and b_mem and b_rep):
                continue
            a_phy = ingress_by_socket(r).get(socket, {})
            b_phy = ingress_by_socket(b_rep).get(socket, {})
            if not (a_phy.get("phy_bytes") and b_phy.get("phy_bytes")):
                continue
            # N1 is ingress-normalised for exactly the reason M1 is: the numerator falls when the
            # NIC sheds and the denominator does not, so paired runs on drifting traffic stay
            # comparable. Per *received* byte would be the trap, and is not reported.
            floor_a = baseline.get(socket, 0.0) * a_mem["intervals"]
            floor_b = baseline.get(socket, 0.0) * b_mem["intervals"]
            va = max(0.0, a_mem["imc_bytes"] - floor_a) / a_phy["phy_bytes"]
            vb = max(0.0, b_mem["imc_bytes"] - floor_b) / b_phy["phy_bytes"]
            if not a_phy.get("phy_available") or not b_phy.get("phy_available"):
                continue  # no valid ingress denominator on this socket
            pairs.append((idx, va, vb))

        print(f"\n--- N1  DRAM bytes per ingress byte, socket {socket} "
              f"({a_arm} vs {b_arm}) ---")
        if not pairs:
            print("  no complete pairs with a valid ingress denominator on this socket.")
            continue
        print(f"{'pair':>5}{a_arm:>12}{b_arm:>12}{'change':>10}")
        diffs, rels = [], []
        for idx, va, vb in pairs:
            d = vb - va
            diffs.append(d)
            rels.append(d / va if va else 0.0)
            print(f"{idx:>5}{va:>12.3f}{vb:>12.3f}{100 * (d / va if va else 0):>9.1f}%")
        n, k, p = sign_test(diffs)
        mean_rel = statistics.fmean(rels)
        print(f"  mean change: {100 * mean_rel:+.2f}%   "
              f"sign test n={n}, {k} favour {b_arm}, p={p:.4f}")
        if p >= 0.05:
            print("  -> NOT significant at 0.05; report that rather than the point estimate.")
        elif mean_rel < 0:
            print(f"  -> {b_arm} moves significantly fewer DRAM bytes per ingress byte.")
        else:
            print(f"  -> {b_arm} moves significantly MORE DRAM bytes per ingress byte, "
                  "contradicting the hypothesis.")


def analyze(reports, args):
    usable, rejected = [], []
    for r in reports:
        problems = check_run(r)
        (rejected if problems else usable).append((r, problems))

    print("\n" + "=" * 78)
    print("RUN VALIDITY")
    print("=" * 78)
    print(f"usable runs: {len(usable)}   rejected: {len(rejected)}")
    for r, problems in rejected:
        print(f"  REJECT arm {r['_arm']} run {r['_index']}:")
        for p in problems:
            print(f"    - {p}")

    by_arm = {}
    for r, _ in usable:
        by_arm.setdefault(r["_arm"], []).append(r)

    # ---- per-arm summary (M2) ----
    print("\n" + "=" * 78)
    print("M2  PER-CORE CYCLE BUDGET (means over usable runs)")
    print("=" * 78)
    hdr = f"{'arm':<4}{'n':>3}  {'idle%':>8}{'poll_busy%':>11}{'pipeline%':>10}{'maint%':>8}" \
          f"{'cores_idle':>11}{'cyc/idle poll':>14}"
    print(hdr)
    for arm in sorted(by_arm):
        rs = by_arm[arm]
        def m(fn):
            return statistics.fmean(fn(r) for r in rs)
        # Bucket fractions are taken against sampled_wall, which is what they sum to.
        def sw(r):
            return max(r["budget"].get("sampled_wall") or r["budget"]["wall"], 1)
        print(f"{arm:<4}{len(rs):>3}  "
              f"{100*m(lambda r: r['budget']['idle_fraction']):>7.3f}%"
              f"{100*m(lambda r: r['budget']['poll_busy']/sw(r)):>10.3f}%"
              f"{100*m(lambda r: r['budget']['pipeline']/sw(r)):>9.3f}%"
              f"{100*m(lambda r: r['budget']['maint']/sw(r)):>7.3f}%"
              f"{m(lambda r: r['budget']['cores_idle']):>11.3f}"
              f"{m(lambda r: r['budget']['cycles_per_idle_poll']):>14.1f}")

    # ---- paired M1 ----
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    if len(arms) >= 2:
        a_arm, b_arm = arms[0], arms[1]
        pairs, discarded = [], []
        a_runs = {r["_index"]: r for r in by_arm.get(a_arm, [])}
        b_runs = {r["_index"]: r for r in by_arm.get(b_arm, [])}
        for idx in sorted(set(a_runs) & set(b_runs)):
            a, b = a_runs[idx], b_runs[idx]
            problems = check_pair(a, b, args.load_tolerance)
            (discarded if problems else pairs).append((idx, a, b, problems))

        print("\n" + "=" * 78)
        print(f"M1  CYCLES PER INGRESS PACKET  ({a_arm} vs {b_arm})")
        print("=" * 78)
        print(f"complete pairs: {len(pairs) + len(discarded)}   "
              f"used: {len(pairs)}   discarded: {len(discarded)}")
        for idx, _, _, problems in discarded:
            print(f"  DISCARD pair {idx}: {'; '.join(problems)}")

        if pairs:
            print(f"\n{'pair':>5}{a_arm:>14}{b_arm:>14}{'delta':>12}{'change':>10}"
                  f"{'shed%':>9}")
            diffs, rels = [], []
            for idx, a, b, _ in pairs:
                va = a["normalised"]["cycles_per_ingress_pkt"]
                vb = b["normalised"]["cycles_per_ingress_pkt"]
                d = vb - va
                diffs.append(d)
                rels.append(d / va if va else 0.0)
                print(f"{idx:>5}{va:>14.2f}{vb:>14.2f}{d:>12.2f}"
                      f"{100*(d/va if va else 0):>9.1f}%"
                      f"{100*b['normalised']['shed_fraction_pkts']:>8.1f}%")

            n, k, p = sign_test(diffs)
            mean_rel = statistics.fmean(rels)
            print(f"\nmean change in cycles/ingress pkt: {100*mean_rel:+.2f}%")
            if len(rels) > 1:
                print(f"stdev across pairs:                {100*statistics.stdev(rels):.2f}%")
            print(f"exact sign test: n={n}, {k} pairs favour {b_arm}, p={p:.4f}")
            if p >= 0.05:
                print("  -> NOT significant at 0.05. On this evidence the hypothesis is not "
                      "supported; report that rather than the point estimate.")
            elif mean_rel < 0:
                print(f"  -> {b_arm} spends significantly fewer cycles per ingress packet.")
            else:
                print(f"  -> {b_arm} spends significantly MORE cycles per ingress packet, "
                      "contradicting the hypothesis.")

            # Control-plane debit: what the mechanism cost to operate.
            b_cp = [b["control_plane"] for _, _, b, _ in pairs]
            inst = statistics.fmean(c["install_cycles_vs_core_wall"] for c in b_cp)
            print(f"\ncontrol-plane debit in {b_arm}: rule installs cost "
                  f"{100*inst:.4f}% of one RX core "
                  f"({statistics.fmean(c['installs'] for c in b_cp):.0f} installs, "
                  f"mean {statistics.fmean(c['mean_install_cycles'] for c in b_cp):.0f} cyc)")
            refused = statistics.fmean(c["offload_refused"] for c in b_cp)
            if refused > 0:
                print(f"  {refused:.0f} offloads refused (--max-rules reached): the shed fraction "
                      "is capacity-limited, not policy-limited")

    # ---- M3 regression ----
    print("\n" + "=" * 78)
    print("M3  DUTY CYCLE vs OFFERED LOAD (per-interval, per arm)")
    print("=" * 78)
    fits = {}
    for arm in sorted(by_arm):
        tsc_hz = statistics.fmean(r["tsc_hz"] for r in by_arm[arm]) or 1.0
        pts = load_budget_rows(args.out_dir, arm)
        if not pts:
            print(f"  arm {arm}: no per-interval rows found "
                  f"(was [online.monitor.log] enabled?)")
            continue
        xs, ys = [], []
        for d_bytes, busy, wall_per_core in pts:
            secs = wall_per_core / tsc_hz
            if secs <= 0:
                continue
            xs.append(d_bytes * 8 / secs / 1e9)  # Gbps
            ys.append(busy)
        fit = linfit(xs, ys)
        if not fit:
            print(f"  arm {arm}: too few usable intervals ({len(xs)})")
            continue
        slope, intercept, r2, n = fit
        fits[arm] = (slope, intercept, r2, n, xs, ys)
        print(f"  arm {arm}: busy_fraction = {intercept:.4f} + {slope:.6f} * Gbps   "
              f"(r2={r2:.3f}, n={n} intervals)")

    if len(fits) >= 2:
        arms_fitted = sorted(fits)
        base = arms_fitted[0]
        print(f"\n  slope = marginal core-fraction per Gbps of offered load. "
              f"Lower is better.")
        for arm in arms_fitted[1:]:
            s0, s1 = fits[base][0], fits[arm][0]
            if s0:
                print(f"  {arm} vs {base}: slope {s1:.6f} vs {s0:.6f} "
                      f"({100*(s1-s0)/s0:+.1f}%)")
        print("  This is the load-robust comparison: it does not assume the arms saw "
              "similar traffic.")

    if args.plot and fits:
        write_plot(fits, args.out_dir)

    if args.mem_sample:
        # Include runs rejected *only* by the machine-wide rx_phy_* gate. N1 is per socket and
        # checks each socket's own ports, so a config mixing a PMD that exposes rx_phy_* with one
        # that does not still yields a sound N1 on the former's socket — whereas M1, which sums
        # all ports into one denominator, correctly rejects the run.
        mem_usable = usable + [(r, p) for r, p in rejected if phy_only_failures(p)]
        if len(mem_usable) > len(usable):
            print(f"\n(memory analysis additionally uses {len(mem_usable) - len(usable)} run(s) "
                  f"rejected only by the machine-wide rx_phy_* gate; N1 is per socket and will "
                  f"skip whichever socket lacks the counters)")
        analyze_memory(mem_usable, args)

    write_tidy_csv([r for r, _ in usable], args.out_dir, args)


def write_plot(fits, out_dir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\n(--plot requested but matplotlib is not installed; skipping)")
        return
    fig, ax = plt.subplots(figsize=(7, 5))
    for arm, (slope, intercept, r2, n, xs, ys) in sorted(fits.items()):
        ax.scatter(xs, ys, s=8, alpha=0.35, label=f"{arm} ({ARMS[arm]['drop_mode']})")
        if xs:
            lo, hi = min(xs), max(xs)
            ax.plot([lo, hi], [intercept + slope * lo, intercept + slope * hi], linewidth=2)
    ax.set_xlabel("offered load (Gbps, NIC ingress)")
    ax.set_ylabel("RX-core busy fraction")
    ax.set_title("Datapath duty cycle vs offered load")
    ax.legend()
    ax.grid(alpha=0.3)
    path = out_dir / "duty_vs_load.png"
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    print(f"\nwrote {path}")


def write_tidy_mem_csv(reports, out_dir, args):
    """One row per (run, socket): the memory metrics, which are socket-scoped.

    Kept separate from runs.csv rather than widened into it, because flattening a per-socket
    quantity into a per-run row means either picking one socket or inventing a total, and on a
    config whose RX cores straddle both sockets neither is defensible.
    """
    rows = []
    for r in reports:
        mem = load_mem_totals(out_dir, r["_arm"], r["_index"])
        if not mem:
            continue
        ing = ingress_by_socket(r)
        for socket, vals in sorted(mem.items()):
            phy_bytes = ing.get(socket, {}).get("phy_bytes", 0)
            phy_pkts = ing.get(socket, {}).get("phy_packets", 0)

            def blank_or_int(f, vals=vals):
                return "" if vals[f] is None else int(vals[f])

            rows.append({
                "arm": r["_arm"], "index": r["_index"], "socket": socket,
                "intervals": vals["intervals"],
                "imc_bytes": int(vals["imc_bytes"]),
                "imc_read_bytes": int(vals["imc_read_bytes"]),
                "imc_write_bytes": int(vals["imc_write_bytes"]),
                "core_dram_bytes": int(vals["core_dram_bytes"]),
                "io_dram_bytes": int(vals["io_dram_bytes"]),
                "io_dram_fraction": (vals["io_dram_bytes"] / vals["imc_bytes"]
                                     if vals["imc_bytes"] else 0.0),
                "iio_in_bytes": int(vals["iio_in_bytes"]),
                "mbm_total_bytes": int(vals["mbm_total_bytes"]),
                "mbm_local_bytes": int(vals["mbm_local_bytes"]),
                "llc_occupancy_bytes_mean": int(vals["llc_occupancy_bytes_mean"]),
                # Blank, not 0, when the sampler never recorded it: zero here would read as
                # "packets held no LLC", which is a stronger claim than the CSV can support.
                "llc_occupancy_all_bytes_mean": blank_or_int("llc_occupancy_all_bytes_mean"),
                "llc_ddio_bytes_mean": blank_or_int("llc_ddio_bytes_mean"),
                "llc_ddio_fraction_mean": ("" if vals["llc_ddio_fraction_mean"] is None
                                           else round(vals["llc_ddio_fraction_mean"], 6)),
                "ingress_phy_bytes": phy_bytes,
                "ingress_phy_packets": phy_pkts,
                # N1 and its PCIe cross-check, precomputed so the CSV is usable as-is.
                "dram_bytes_per_ingress_byte": (vals["imc_bytes"] / phy_bytes
                                                if phy_bytes else 0.0),
                "pcie_bytes_per_ingress_byte": (vals["iio_in_bytes"] / phy_bytes
                                                if phy_bytes else 0.0),
                "phy_available": ing.get(socket, {}).get("phy_available", False),
            })
    if not rows:
        return
    path = out_dir / "runs_memory.csv"
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {path}")


def write_tidy_csv(reports, out_dir, args=None):
    """One row per run, for downstream analysis in whatever tool you prefer."""
    if not reports:
        return
    path = out_dir / "runs.csv"
    # Memory columns are per socket, so they cannot be flattened into a one-row-per-run table
    # without picking a socket. Emit a companion tidy file keyed by (run, socket) instead.
    if args is not None and args.mem_sample:
        write_tidy_mem_csv(reports, out_dir, args)
    fields = [
        "arm", "index", "drop_mode", "app_cycles_requested", "tls_callbacks", "shed_conns",
        "idle_fraction", "busy_fraction", "cores_idle", "residual_fraction",
        "instrumentation_fraction", "cycles_per_ingress_pkt", "cycles_per_ingress_byte",
        "cycles_per_received_pkt", "shed_fraction_pkts", "ingress_phy_pkts", "ingress_phy_bytes",
        "ingress_good_pkts", "discarded_packets", "installs", "install_failures",
        "mean_install_cycles", "install_cycles_vs_core_wall", "rx_cores", "tsc_hz",
        "sample_stride", "sampled_iters", "est_poll_idle_cycles",
    ]
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in reports:
            b, n, c, g = r["budget"], r["normalised"], r["control_plane"], r["ground_truth"]
            w.writerow({
                "arm": r["_arm"], "index": r["_index"], "drop_mode": r["drop_mode"],
                "app_cycles_requested": r["app_cycles_requested"],
                "tls_callbacks": r["tls_callbacks"], "shed_conns": r["shed_conns"],
                "idle_fraction": b["idle_fraction"], "busy_fraction": b["busy_fraction"],
                "cores_idle": b["cores_idle"], "residual_fraction": b["residual_fraction"],
                "instrumentation_fraction": b["instrumentation_fraction"],
                "cycles_per_ingress_pkt": n["cycles_per_ingress_pkt"],
                "cycles_per_ingress_byte": n["cycles_per_ingress_byte"],
                "cycles_per_received_pkt": n["cycles_per_received_pkt"],
                "shed_fraction_pkts": n["shed_fraction_pkts"],
                "ingress_phy_pkts": sum(p["phy_packets"] for p in r["ingress"]),
                "ingress_phy_bytes": sum(p["phy_bytes"] for p in r["ingress"]),
                "ingress_good_pkts": sum(p["good_packets"] for p in r["ingress"]),
                "discarded_packets": g["discarded_packets"],
                "installs": c["installs"], "install_failures": c["install_failures"],
                "mean_install_cycles": c["mean_install_cycles"],
                "install_cycles_vs_core_wall": c["install_cycles_vs_core_wall"],
                "rx_cores": b["rx_cores"], "tsc_hz": r["tsc_hz"],
                "sample_stride": b.get("sample_stride", 1),
                "sampled_iters": b.get("sampled_iters", 0),
                "est_poll_idle_cycles": b.get("est_poll_idle_cycles", 0.0),
            })
    print(f"wrote {path}")


def main():
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    for arm in arms:
        if arm not in ARMS:
            sys.exit(f"unknown arm {arm!r}; known arms: {', '.join(ARMS)}")

    if args.mem_sample and not args.analyze_only:
        if args.sampler_core is None:
            sys.exit("--mem-sample needs --sampler-core. Pick a core outside the config's RX "
                     "cores and outside --worker-cores: sampling from a measured core steals "
                     "its cycles and pollutes its LLC occupancy.")
        # Fail before the first run rather than after it, so a whole batch is not wasted.
        # mem_sample.py re-checks this, but only once it is actually launched — too late to save
        # a ten-pair batch, and never at all under --dry-run.
        worker = {int(c) for c in args.worker_cores.split(",") if c.strip()}
        if args.sampler_core in worker:
            sys.exit(f"--sampler-core {args.sampler_core} is also an install-worker core")
        if not (REPO_ROOT / "tools" / "mem_sample.py").exists():
            sys.exit("tools/mem_sample.py is missing")
        # Reuse mem_sample's config parser rather than re-implementing it, so the two tools cannot
        # disagree about which cores the run will use.
        sys.path.insert(0, str(REPO_ROOT / "tools"))
        import mem_sample
        for arm in arms:
            layout = mem_sample.load_layout(REPO_ROOT / ARMS[arm]["config"])
            if args.sampler_core in layout["rx_cores"]:
                sys.exit(
                    f"--sampler-core {args.sampler_core} is an RX core in "
                    f"{ARMS[arm]['config']} (RX cores: {layout['rx_cores']}). Sampling from a "
                    "measured core steals its cycles and pollutes its LLC occupancy."
                )
            # Cross-socket polling misattributes N2 between sockets rather than adding noise to
            # it, so refuse the batch here instead of discovering it once per run.
            numa = mem_sample.check_numa_locality(layout)
            if numa and not args.allow_cross_numa:
                print(f"{ARMS[arm]['config']}: core allocation makes N2 unsound:", file=sys.stderr)
                for p in numa:
                    print(f"  {p}", file=sys.stderr)
                print("\nA NUMA-local allocation for this host:\n", file=sys.stderr)
                reserve = {args.sampler_core} | worker
                print(mem_sample.suggest_allocation(layout, reserve), file=sys.stderr)
                sys.exit("\nFix the config's `cores` lists, or pass --allow-cross-numa.")

    if args.analyze_only:
        reports = []
        for path in sorted(args.out_dir.glob("report_*.json")):
            r = json.loads(path.read_text())
            _, arm, idx = path.stem.split("_")
            r["_arm"], r["_index"] = arm, int(idx)
            reports.append(r)
        if not reports:
            sys.exit(f"no report_*.json in {args.out_dir}")
        analyze(reports, args)
        return

    for arm in arms:
        print(f"arm {arm}: {ARMS[arm]['label']}")
    print(f"{args.pairs} pairs, app_cycles={args.app_cycles}, out={args.out_dir}\n")

    reports = []
    for i in range(1, args.pairs + 1):
        for arm in arms:
            r = run_one(arm, i, args)
            if r:
                reports.append(r)
            if not args.dry_run and args.settle:
                time.sleep(args.settle)

    if args.dry_run:
        return
    if not reports:
        sys.exit("no runs produced a report")
    analyze(reports, args)


if __name__ == "__main__":
    main()
