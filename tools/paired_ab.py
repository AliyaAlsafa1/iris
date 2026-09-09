#!/usr/bin/env python3
"""Paired A/B runner and analysis for the dyn_hardware_assist cycle-budget evaluation.

Runs the arms in an alternating A,B,A,B,... sequence, collects each run's JSON report, and reports:

  M1  cycles per *ingress* packet, with a paired test over the A/B pairs. Ingress-normalised, so
      it is comparable even though the two runs in a pair never see identical live traffic.
  M2  the per-core cycle budget, whose poll_idle bucket is the freed-cycle pool.
  M3  a per-arm regression of duty cycle on offered load, fitted from the per-second rows in each
      run's cycle_budget.csv. The slope gap is the effect size and, unlike M1, it does not assume
      the two arms saw comparable load at all.

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
import statistics
import subprocess
import sys
import time
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
    p.add_argument("--worker-cores", default="9",
                   help="cores for the rte_flow install worker (default: 9, NUMA-local to the CX-5)")
    p.add_argument("--out-dir", type=Path, default=Path("results/paired_ab"),
                   help="where to write reports, the tidy CSV and the summary")
    p.add_argument("--settle", type=float, default=5.0,
                   help="seconds to wait between runs so the NIC and rule table quiesce")
    p.add_argument("--load-tolerance", type=float, default=0.10,
                   help="discard a pair whose two runs differ in ingress bytes by more than this "
                        "fraction (default: 0.10)")
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
        return None

    # Stream by default: a run is `duration` seconds long and captured output means a silent
    # terminal for all of it, with no way to tell a healthy run from a hang. Inheriting the
    # terminal rather than piping also keeps DPDK's own C-buffered output line-prompt, which a
    # pipe would hold back in 4 KB blocks.
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


def check_run(report):
    """Return a list of reasons this run must not be used. Empty means usable.

    These are hard validity gates, not warnings: each one, if ignored, produces a number that
    looks plausible and is wrong.
    """
    problems = []
    b = report["budget"]
    n = report["normalised"]

    if not n["ingress_normalisation_valid"]:
        problems.append("PMD exposed no rx_phy_* counters, so M1 is meaningless")
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
    # The rule-management core's own accounting. Absent from reports written before it existed,
    # in which case there is nothing to gate on and the run is judged on the rest.
    rm = report.get("rule_management")
    if rm:
        if abs(rm.get("loop_residual_fraction", 0.0)) > 1e-3:
            problems.append(f"worker loop budget does not close "
                            f"(residual {rm['loop_residual_fraction']:.2%})")
        # A worker that spun instead of parking was consuming a core the whole run, so
        # `busy_fraction` is not the cost and the utilisation figure cannot be read as one.
        if rm.get("spin_fraction", 0.0) > 0.5:
            problems.append(f"worker spun for {rm['spin_fraction']:.0%} of its idle time rather "
                            "than parking: utilisation is not interpretable")
    if report["drop_mode"] == "hardware":
        if report["ground_truth"]["discarded_packets"] == 0:
            problems.append("treatment arm shed nothing: NIC COUNT handles read zero")
        if report["control_plane"]["install_failures"] > 0:
            problems.append(f"{report['control_plane']['install_failures']} rule installs failed")
        if rm and rm.get("dispatch_failures", 0) > 0:
            # The datapath asked for offloads the worker could not take. Whatever the cycle
            # numbers say, this run measured a worker-limited shed fraction, not the policy's.
            problems.append(f"{rm['dispatch_failures']} offloads dropped by a full worker queue: "
                            "the shed fraction is worker-limited")
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

    # ---- per-arm rule-management core ----
    if any(r.get("rule_management") for rs in by_arm.values() for r in rs):
        print("\n" + "=" * 78)
        print("M5  RULE-MANAGEMENT CORE (means over usable runs)")
        print("=" * 78)
        print(f"{'arm':<4}{'n':>3}  {'util%':>9}{'cores':>8}{'req/s cap':>12}"
              f"{'cyc/req':>10}{'unbrack%':>10}{'spin%':>8}")
        for arm in sorted(by_arm):
            rs = [r for r in by_arm[arm] if r.get("rule_management")]
            if not rs:
                continue
            def rm(fn, rs=rs):
                return statistics.fmean(fn(r["rule_management"]) for r in rs)
            reqs = rm(lambda m: m.get("offload_requests", 0))
            print(f"{arm:<4}{len(rs):>3}  "
                  f"{100*rm(lambda m: m['busy_fraction']):>8.4f}%"
                  f"{rm(lambda m: m['cores_busy']):>8.4f}"
                  f"{rm(lambda m: m['sustainable_offload_rate']):>12.0f}"
                  f"{(rm(lambda m: m['handler_cycles']) / reqs if reqs else 0):>10.0f}"
                  f"{100*rm(lambda m: m.get('handler_unbracketed_fraction', 0)):>9.2f}%"
                  f"{100*rm(lambda m: m['spin_fraction']):>7.2f}%")
        print("  util% is from CLOCK_THREAD_CPUTIME_ID, the only clock here that stops while the "
              "worker is parked.")
        print("  req/s cap is offload requests sustainable at 100% of one core: compare it "
              "against the TLS connection arrival rate.")

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

            # Net cores freed: the datapath credit minus the rule-management debit.
            #
            # Paired and differenced on both terms. Differencing the debit as well as the credit
            # matters because the control arm also stands a worker up (parked, so its utilisation
            # is the floor rather than zero), and subtracting that floor keeps the comparison
            # about installing rules rather than about owning a thread.
            #
            # Only computable here: a single run cannot see the other arm. The full accounting is
            # also only as good as its narrowest term — `cores_idle` is a *pool* of freed cycles,
            # not cycles an application can certainly use, so read this as an upper bound on the
            # benefit and a lower bound on nothing.
            rm_pairs = [(a, b) for _, a, b, _ in pairs
                        if a.get("rule_management") and b.get("rule_management")]
            if rm_pairs:
                credits = [b["budget"]["cores_idle"] - a["budget"]["cores_idle"]
                           for a, b in rm_pairs]
                debits = [b["rule_management"]["cores_busy"] - a["rule_management"]["cores_busy"]
                          for a, b in rm_pairs]
                credit, debit = statistics.fmean(credits), statistics.fmean(debits)
                nets = [c - d for c, d in zip(credits, debits)]
                net = statistics.fmean(nets)
                print(f"\nnet cores freed by {b_arm} over {a_arm} (n={len(rm_pairs)}):")
                print(f"  datapath credit:        {credit:+.4f} cores (idle-poll pool)")
                print(f"  rule-management debit:  {-debit:+.4f} cores (worker utilisation)")
                print(f"  net:                    {net:+.4f} cores")
                if len(nets) >= 2:
                    # sign_test counts negatives, which is "favours B" for a cycle delta but
                    # "costs cores" here, so the positive count is the one to report.
                    n_st, k_neg, p_st = sign_test(nets)
                    print(f"  sign test: n={n_st}, {n_st - k_neg} pairs net-positive, "
                          f"p={p_st:.4f}")
                if net <= 0:
                    print("  -> the mechanism does not pay for itself at this connection arrival "
                          "rate. That is a result, not a failed run.")
                elif debit > 0.1 * credit:
                    print(f"  -> the debit is {100*debit/credit:.0f}% of the credit; it is not a "
                          "rounding term and must be reported alongside the saving.")

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

    write_tidy_csv([r for r, _ in usable], args.out_dir)


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


def prefixed(section, prefix, keys):
    """Flatten `keys` out of a report section into `prefix`-named columns.

    Missing sections and missing keys both yield blanks rather than zeros, so a report written
    before the section existed produces readable rows instead of numbers that look measured.
    """
    section = section or {}
    return {f"{prefix}{k}": section.get(k, "") for k in keys}


def rule_management_columns(rm):
    """Flatten the rule-management section for the tidy CSV.

    Every column is blank when the section is absent, so reports written before the worker core was
    instrumented still produce readable rows rather than zeros that look like measurements.
    """
    fields = {
        "rm_cores": "cores",
        "rm_cpu_seconds": "cpu_seconds",
        "rm_busy_fraction": "busy_fraction",
        "rm_cores_busy": "cores_busy",
        "rm_sustainable_offload_rate": "sustainable_offload_rate",
        "rm_offload_requests": "offload_requests",
        "rm_handler_cycles": "handler_cycles",
        "rm_bookkeeping_cycles": "bookkeeping_cycles",
        "rm_lock_wait_cycles": "lock_wait_cycles",
        "rm_table_cycles": "table_cycles",
        "rm_install_span_cycles": "install_span_cycles",
        "rm_evict_span_cycles": "evict_span_cycles",
        "rm_install_glue_cycles": "install_glue_cycles",
        "rm_understatement_vs_install_cycles": "understatement_vs_install_cycles",
        "rm_spin_fraction": "spin_fraction",
        "rm_loop_residual_fraction": "loop_residual_fraction",
        "rm_handler_unbracketed_fraction": "handler_unbracketed_fraction",
        "rm_dedup_hits": "dedup_hits",
        "rm_dispatch_failures": "dispatch_failures",
        "rm_nonvoluntary_ctxt_switches": "nonvoluntary_ctxt_switches",
    }
    rm = rm or {}
    out = {col: rm.get(key, "") for col, key in fields.items()}
    pmd = rm.get("pmd") or {}
    out["rm_pmd_install_cycles"] = pmd.get("install_cycles", "")
    out["rm_pmd_handle_create_cycles"] = pmd.get("handle_create_cycles", "")
    return out


def write_tidy_csv(reports, out_dir):
    """One row per run, for downstream analysis in whatever tool you prefer."""
    if not reports:
        return
    path = out_dir / "runs.csv"
    fields = [
        "arm", "index", "drop_mode", "app_cycles_requested", "tls_callbacks", "shed_conns",
        "idle_fraction", "busy_fraction", "cores_idle", "residual_fraction",
        "instrumentation_fraction", "cycles_per_ingress_pkt", "cycles_per_ingress_byte",
        "cycles_per_received_pkt", "shed_fraction_pkts", "ingress_phy_pkts", "ingress_phy_bytes",
        "ingress_good_pkts", "discarded_packets", "installs", "install_failures",
        "mean_install_cycles", "install_cycles_vs_core_wall", "rx_cores", "tsc_hz",
        "sample_stride", "sampled_iters", "est_poll_idle_cycles",
        # Rule-management core. Blank for runs written before it was instrumented.
        "rm_cores", "rm_cpu_seconds", "rm_busy_fraction", "rm_cores_busy",
        "rm_sustainable_offload_rate", "rm_offload_requests", "rm_handler_cycles",
        "rm_bookkeeping_cycles", "rm_lock_wait_cycles", "rm_table_cycles",
        "rm_install_span_cycles", "rm_evict_span_cycles", "rm_install_glue_cycles",
        "rm_pmd_install_cycles", "rm_pmd_handle_create_cycles",
        "rm_understatement_vs_install_cycles", "rm_spin_fraction",
        "rm_loop_residual_fraction", "rm_handler_unbracketed_fraction",
        "rm_dedup_hits", "rm_dispatch_failures", "rm_nonvoluntary_ctxt_switches",
        # Control-plane host memory. Blank for runs written before it was measured.
        "cpm_resident_rules", "cpm_peak_resident_rules", "cpm_shadow_table_bytes",
        "cpm_dedup_set_bytes", "cpm_fifo_bytes", "cpm_entry_vec_bytes", "cpm_allocations",
        "cpm_bytes_per_rule", "cpm_dispatch_channel_bytes", "cpm_dispatch_channel_slots",
        "cpm_total_bytes", "cpm_fixed_share",
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
                **rule_management_columns(r.get("rule_management")),
                **prefixed(r.get("control_plane_memory"), "cpm_", (
                    "resident_rules", "peak_resident_rules", "shadow_table_bytes",
                    "dedup_set_bytes", "fifo_bytes", "entry_vec_bytes", "allocations",
                    "bytes_per_rule", "dispatch_channel_bytes", "dispatch_channel_slots",
                    "total_bytes", "fixed_share",
                )),
            })
    print(f"wrote {path}")


def main():
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    for arm in arms:
        if arm not in ARMS:
            sys.exit(f"unknown arm {arm!r}; known arms: {', '.join(ARMS)}")

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
