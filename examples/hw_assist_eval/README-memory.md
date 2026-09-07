# Measuring the memory `dyn_hardware_assist` frees up

Companion to [README.md](README.md), which measures CPU cycles. Same arms, same paired protocol,
same harness — a different resource.

## The claim under test

With `dyn_hardware_assist`, ciphertext tail packets never arrive. So they never cross PCIe, never
occupy an mbuf, never get write-allocated into LLC by DDIO, and never generate the DRAM traffic
that follows. The memory system should see proportionally less work.

**This should be a stronger effect than the cycle one, and for a structural reason.** The cycle
README's caveat #2 is that ciphertext tails are *already the cheapest packets Iris handles* — a
parse plus one hot hash hit — which bounds the cycle saving to their share of datapath cycles. But
a 1500-byte ciphertext packet costs exactly the same DMA, the same mbuf and the same cache
footprint as a 1500-byte handshake packet. The cycle effect scales with the **packet** share of the
cheapest packets; the memory effect scales with the **byte** share of the largest ones. If
ciphertext is 60% of packets it is likely 80%+ of bytes.

## Why measuring this is awkward

Three counters see the same bytes at three different points, and none of them alone answers the
question:

| vantage | counter | what it sees |
|---|---|---|
| NIC | `rx_phy_bytes` | what arrived at the port, before any rule matched |
| PCIe | `uncore_iio_free_running_*/bw_in_port*/` | what the NIC actually DMA'd into the host |
| DRAM | `uncore_imc/cas_count_{read,write}/` | what reached memory |

The problem is that **uncore counters are socket-wide**. They count the OS, the sampler, and
anything else on the box. And they cannot distinguish the application's memory traffic from the
packets' — which is the actual question.

Intel RDT resolves this, via what looks at first like a hardware limitation. On Skylake-SP, MBM
attributes only *core-originated* traffic to an RMID; DDIO writes from the IIO carry no RMID at
all. So the gap between the two is the measurement:

```
io_dram_bytes = imc_bytes - sum(mbm_total_bytes)
```

That is the packets' DRAM traffic, separated from the application's, on hardware that provides no
counter for it directly.

## What is measured

| | metric | where |
|---|---|---|
| **N1** | DRAM bytes per **ingress** byte, per socket — denominator is `rx_phy_bytes` | `runs_memory.csv`, paired by `tools/paired_ab.py` |
| **N2** | that traffic split into core-originated (RDT MBM) and IO-originated (IMC − MBM), plus PCIe inbound | the N2 table |
| **N3** | the RX cores' LLC occupancy (RDT CMT) | `llc_occupancy_bytes` |
| **N4** | mbuf pool footprint, peak occupancy, and minimum viable capacity per arm | report `memory`, `tools/mempool_bisect.py` |

**N1 is the headline, for exactly the reason M1 is**: the numerator falls when the NIC sheds traffic
and the denominator does not, so paired runs on non-stationary campus traffic stay comparable.

### The M1 trap recurs verbatim

**DRAM bytes per *received* byte is the wrong metric.** It removes MTU-sized packets — which are
cheap in DRAM-bytes-per-byte, being one sequential DMA — from the denominator while leaving
handshake parsing, reassembly and conn-table churn in it. It can stay flat or rise while total DRAM
traffic falls. It is not reported.

### The ratio worth reading first

```
io_dram_bytes / iio_inbound_bytes
```

This is the share of DMA'd packet data that reaches DRAM rather than being absorbed and overwritten
in LLC. **It answers the DDIO question without touching DDIO** — and it decides whether a DDIO way
sweep is worth running at all. If it is already small, DDIO is absorbing the packet writes and
there is little DRAM traffic for the mechanism to remove.

`iio_inbound_bytes / rx_phy_bytes` should sit near 1. Far from it means the wrong IIO stack is being
read, and every other memory number for that socket is attributed to the wrong device. It is a hard
gate, not a footnote.

## Arms

**Unchanged from the cycle harness, and for the same reason.** Arm A is `dyn_hardware_assist = true`
with `--drop-mode none`, not `dyn_hardware_assist = false`: that flag reconfigures the NIC flow
engine (a group-0 → group-1 jump plus an explicit catch-all RSS rule) whether or not any packet is
dropped, and that reconfiguration plausibly has its own memory footprint. It must be common to both
arms.

## Keeping the measurement honest

### The cycle instrumentation is left running, and that is checked

Cycles and memory come from the same runs. The cycle instrumentation issues no memory reference of
its own — `rte_rdtsc` is a register read, and the per-core `DatapathBudget` is 112 bytes of
L1-resident state — but this is *checked*, not argued. Set `budget_sample_stride = 0` to disable
cycle attribution outright and confirm N1 does not move. This is the memory analogue of
`instrumentation_fraction`. Measure at strides {0, 64, 1}; flat N1 across all three settles it.

### The two hazards that are real

Neither is the cycle counters.

1. **The sampler must not run on an RX core.** It would steal datapath cycles and, worse, pollute
   that core's own CMT occupancy — corrupting the very metric it collects. `--sampler-core` is
   mandatory and checked against the config's RX cores and `--worker-cores`, in `paired_ab.py`
   before the first run rather than only in the sampler once launched.

2. **The socket-wide noise floor must be subtracted.** Run `mem_sample.py --baseline` with Iris
   stopped and pass it as `--mem-baseline`. This matters directionally: removing a constant floor
   from both arms makes the proportional effect *larger*, so omitting it understates the result. A
   floor that is a large fraction of the signal means the effect is not resolvable, and that is the
   finding.

### Per-socket attribution, not machine-wide

Uncore IMC and IIO counters are socket-scoped, so everything is attributed per socket and each
socket is normalised by the ingress of the ports on it — never as one machine-wide figure, which
would mix memory domains.

**The core lists in `configs/online-cx5-eval.toml` are specific to one host and do not transfer.**
They were written for a 2×18-core box; on a machine with a different core count per socket the same
list lands the cores somewhere else entirely. `tools/mem_sample.py --show-topology` prints the
actual layout for the host it runs on, and both it and `paired_ab.py` refuse to sample a
cross-socket allocation rather than reporting a misattributed N2 — see the gate's rationale in
`check_numa_locality`. `mbm_local_bytes` against `mbm_total_bytes` quantifies any residual
cross-socket share.

Two host-dependent facts to establish before trusting N1, rather than assuming:

* **Whether every port exposes `rx_phy_*`.** It is the N1 denominator, and
  `ingress_normalisation_valid` is all-or-nothing across ports: one PMD that lacks it invalidates
  the figure for the whole run. mlx5 provides it; ICE does not, so a mixed
  Mellanox/E810 config is normalisable only on the Mellanox side, whereas an all-Mellanox config
  is credible on every socket. Check the per-port `ingress[]` array in a smoke run.
* **Whether both NICs are on the same NUMA node.** If they are, a NUMA-local allocation needs every
  RX core for both ports drawn from that one node, which bounds the total core count — and the
  right fix is fewer cores per port, not cores on the far socket.

## Running it

```bash
scripts/build.sh
```

Enable the kernel interfaces (root, machine-wide, reversible — `--check` first, `--undo` after):

```bash
sudo scripts/mem_setup.sh
```

Confirm the counters read and parse before spending a session on them:

```bash
sudo tools/mem_sample.py --config configs/online-cx5-eval.toml --sampler-core 35 --selftest
```

Measure the DRAM noise floor with Iris **not** running:

```bash
sudo tools/mem_sample.py --config configs/online-cx5-eval.toml --sampler-core 35 --baseline --duration 30 --out results/baseline.csv
```

Then the paired protocol, which now reports M1–M3 and N1–N3 from the same runs:

```bash
tools/paired_ab.py --pairs 10 --app-cycles 100000 --worker-cores 9 --mem-sample --sampler-core 35 --mem-baseline results/baseline.csv --out-dir results/mem1 --plot
```

And the pool sizing question separately:

```bash
tools/mempool_bisect.py --arms A,B --duration 60 --out-dir results/mempool1
```

## Before trusting any of it

Everything in the cycle README's corresponding section still applies (`isolcpus`, pinned frequency,
C-states and turbo off). In addition:

* `--selftest` must show every counter advancing. A counter that is "SEEN BUT ZERO" is not a
  rounding problem, it is a misconfiguration.
* `PCIe/phy` must sit near 1, per socket.
* The baseline must be small relative to the signal.
* LLC occupancy must be non-zero, or the resctrl group did not hold the RX cores.

## Where the hypothesis may fail

Findings, not excuses.

1. **The conn table may already be thrashing LLC, making DDIO pollution second-order.**
   `max_connections = 10_000_000` against 24.75 MiB of LLC per socket (11 ways × 2304 KiB): at a
   few hundred bytes an entry, only order 10⁵ entries can ever be resident. If the conn table
   misses LLC regardless of what DDIO does, freeing DDIO ways buys nothing. This is the most likely
   null result, and N3's occupancy figure detects it directly.
2. **DDIO may already be absorbing the packet writes.** If a ciphertext packet is DMA'd into LLC,
   its header read, and the line overwritten before eviction, it never reaches DRAM — so there was
   no DRAM traffic to remove and N1 shows little. `io_dram / iio_inbound` measures this, and is
   worth reading before anything else.
3. **The mempool saving is mostly arm-independent.** In-use mbufs are dominated by the pre-filled
   RX rings (`nb_rxd` × queues × ports ≈ 393K mbufs), which are populated at port setup regardless
   of what the NIC later drops and are therefore identical in both arms. The arm-sensitive term is
   only the mbufs held for reassembly. Expect a large right-sizing win available to *both* arms and
   a smaller A/B delta on top; `mempool_bisect.py` reports them separately so the config win is not
   misattributed to the mechanism.
4. **The rule table is itself a memory cost.** `ControlPlaneCost` charges `rte_flow_create` cycles,
   but NIC rules also consume device and host memory, and that cost scales with connection arrival
   rate. If the pool saving is 100 MB and the rule table costs comparably, the mechanism does not
   pay for itself.
5. **Live-traffic variance may exceed the effect**, as with M3. If the paired sign test is not
   significant across ten pairs, that is the result — report it.
