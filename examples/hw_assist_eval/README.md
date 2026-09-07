# Measuring the CPU cycles `dyn_hardware_assist` frees up

For the memory-side evaluation — DRAM traffic, LLC occupancy and mbuf pool footprint, collected
from these same runs — see [README-memory.md](README-memory.md).

## The claim under test

With `dyn_hardware_assist`, fewer packets are pulled off the NIC, so the system spends fewer CPU
cycles on packet ingress and connection-table lookups, freeing cycles for application logic.

The quantity is narrower than it first appears. Iris **already** discards ciphertext packets in
software: once a TLS connection's `Actions` bitmask empties at the handshake/ciphertext boundary,
`ConnTracker::process` returns early ([`core/src/conntrack/mod.rs`](../../core/src/conntrack/mod.rs)).
By then the packet has crossed PCIe, consumed an RX descriptor, been DMA'd into an mbuf, been
RSS-hashed to a core, been parsed to a five-tuple and taken one hash-table lookup. **That residual
per-packet cost is the whole effect.** It may be small: ciphertext tail packets are the cheapest
packets Iris handles.

## Why measuring this is awkward

The RX loop is a run-to-completion busy-poll, so CPU utilisation is pinned at 100% in every arm and
`perf stat`'s `cycles` is a constant. Cycles have to be attributed from inside the loop.

And the obvious metric misleads. Cycles per *received* packet — what the previous instrumentation
reported — removes the cheapest packets from the denominator while leaving handshakes, reassembly
and L7 parsing in it. It can stay flat or rise while total cycles fall. **Do not report it as the
result.** This harness reports it only for contrast.

## What is measured instead

| | metric | where |
|---|---|---|
| **M1** | cycles per **ingress** packet/byte — denominator is `rx_phy_*`, what the NIC saw before any rule dropped anything | `normalised.cycles_per_ingress_pkt` |
| **M2** | per-core cycle budget: `poll_busy` / `poll_idle` / `pipeline` / `maint`. `poll_idle` is the freed-cycle pool | `budget.*` |
| **M3** | duty cycle regressed on offered load, per arm; the slope gap is the effect size | `cycle_budget.csv`, fitted by `tools/paired_ab.py` |
| **M4** | max zero-loss throughput at fixed `--app-cycles` | `tests/functionality/zero_loss/zlt.py` |

M1 is the headline because it is load-normalised: the numerator falls when the NIC sheds traffic
and the denominator does not, so paired runs on non-stationary live traffic remain comparable.
M3 is the fallback that does not even assume the arms saw similar load.

### Sampling, and why

Bracketing every loop iteration costs one `rte_rdtsc` per empty poll. An empty `rte_eth_rx_burst`
is on the order of a hundred cycles, so at ~24 cycles a read that is close to a tenth of the idle
bucket — and the inflation scales with the idle-poll count, which is *exactly* what differs between
the arms. Measuring exactly would bias the headline metric in favour of the hypothesis.

So cycle attribution is sampled: one in every `[online] budget_sample_stride` iterations (default
64) is fully bracketed, while the packet/burst/idle-poll counters stay exact. Fractions are computed
within the sample, where they are unbiased; the exact `wall` supplies absolute scale. Set
`budget_sample_stride = 1` to measure exactly — appropriate offline, and the way to confirm sampling
has not skewed a result. Every report prints `instrumentation_fraction`; if it is not far below the
A/B effect, the result is not credible, and `tools/paired_ab.py` rejects such runs outright.

## Arms

The control arm is **not** `dyn_hardware_assist = false`. That flag also reconfigures the NIC flow
engine (a group-0 → group-1 jump plus an explicit catch-all RSS rule replace the default RSS path),
independent of any packets being dropped, which would confound the comparison.

| arm | config | `--drop-mode` | what it isolates |
|---|---|---|---|
| **A** control | `online-cx5-eval.toml` | `none` | assist configured, no rules installed |
| **B** treatment | `online-cx5-eval.toml` | `hardware` | per-connection NIC drop |

`B − A` is the hypothesis test. Both arms load the same config, so the flow-engine
reconfiguration `dyn_hardware_assist` performs is common to both and cannot leak into the
difference; the only thing that varies is whether drop rules get installed.

## Keeping the arms comparable

The synthetic application workload (`--app-cycles`, a `rte_rdtsc`-bounded spin) runs from a callback
on the `tls` session, which fires **once per TLS connection at the ciphertext transition**
(`L7EndHdrs`). This is the crux of the design: a per-packet callback would stop firing for packets
the NIC dropped, so the treatment arm would simply do *less work*, and the comparison would measure
nothing at all. Because the trigger is the handshake rather than the tail, both arms perform
identical application work.

The report prints `tls_callbacks` so this can be **checked** rather than assumed;
`tools/paired_ab.py` discards any pair whose counts differ by more than 25%.

Note this is stricter than [`examples/flow_test`](../flow_test), which triggers on any TCP
connection reaching 10 packets rather than on the actual ciphertext transition.

## Honest accounting

The report charges the mechanism for its own overhead:

* `control_plane.install_cycles` — measured inside `rte_flow_create`, plus install count and
  failures. **This cost scales with connection arrival rate, not byte rate**, so at high connection
  churn it can exceed the datapath cycles saved. `install_cycles_vs_core_wall` expresses it as a
  fraction of one RX core.
* `ground_truth.discarded_packets` — read back from each rule's indirect `RTE_FLOW_ACTION_TYPE_COUNT`
  handle. If this is zero in arm B, the experiment measured nothing, regardless of what the cycle
  numbers say.
* `ground_truth.ingress_reconciliation_gap` — `phy − good − phy_discard`, which should be ~0.

The install worker runs on its own core (`--worker-cores`), outside the RX set; the app panics if
they overlap, since sharing would let install work steal cycles from the datapath being measured.

## Running it

Build:

```bash
scripts/build.sh
```

An offline run first, as a harness check rather than an effect measurement — offline replay has no
ports, so `--drop-mode hardware` resolves no port ids and installs nothing. What this confirms is
that the app runs, the `tls` callback fires, and the cycle budget reconciles
(`residual_fraction` ≈ 0):

```bash
scripts/run_eval.sh configs/offline.toml --arm off-A --drop-mode none --app-cycles 100000 --report /tmp/off_A.json
```

Two runs of that command should report **identical** `tls_callbacks`, since offline replay is
deterministic; if they do not, the app-work trigger is not stable and nothing downstream is
meaningful. The A/B effect itself can only be measured online, where a rule can actually drop a
packet.

Then a short online smoke test, to confirm the rules actually fire and to find out which mlx5 xstat
flow-rule drops land in:

```bash
sudo scripts/run_eval.sh configs/online-cx5-eval.toml --arm smoke --drop-mode hardware --worker-cores 13 --report /tmp/smoke.json
```

Then the paired protocol:

```bash
tools/paired_ab.py --pairs 10 --app-cycles 100000 --worker-cores 13 --out-dir results/run1 --plot
```

Add `--dry-run` to see the commands first, or `--analyze-only` to re-analyze existing reports.

## Before trusting any of it

* `isolcpus` for the RX cores and the worker core; pin the CPU frequency
  (`cpupower frequency-set`); disable C-states and turbo. TSC is invariant, so cycle *counts* stay
  valid under frequency change — but the *work* a cycle buys does not, and M4 is wall-clock.
* Confirm `residual_fraction` ≈ 0. A non-zero value means a sampled iteration had an unbracketed
  path and the budget is wrong.
* Confirm `ingress_normalisation_valid`. Without `rx_phy_*` from the PMD (ICE does not expose it)
  M1 is meaningless. This is one reason the evaluation targets the ConnectX-5.
* Idle-poll cycles are **not** 100% reclaimable as application cycles: an empty burst still reads a
  completion-queue entry. `cycles_per_idle_poll` is that floor.

## Where the hypothesis may fail

These are findings, not excuses.

1. **Install rate is the likely binding constraint.** `rte_flow_create` on mlx5 runs at order
   10³–10⁴ rules/sec; campus TLS connection arrival rates can exceed that. That
   [`examples/flow_test`](../flow_test) carries a LightGBM "elephant flow" model to *select* which
   connections to offload is strong evidence this was already hit in practice. The honest result is
   likely a curve of net freed cycles against offload selectivity, with a crossover. `--max-rules`
   bounds a run; `offload_refused` reports when the cap bit.
2. **The tail packets are already the cheapest ones.** If ciphertext is 60% of packets but 15% of
   datapath cycles, 15% is the ceiling, and install overhead eats into it.
3. **Live-traffic variance may exceed the effect.** M3 is the mitigation. If the slopes are
   indistinguishable across ten pairs, that is the result — report it.
