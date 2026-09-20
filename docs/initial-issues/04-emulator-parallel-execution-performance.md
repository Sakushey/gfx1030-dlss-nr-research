# Improve host emulator parallel execution performance

> Draft for supervisor review. Do not open automatically.

**Title:** Improve host emulator parallel execution performance

**Suggested labels:** `host-only`, `performance`, `emulator`, `python`, `good-first-task`

**Evidence level:** `HOST_VALIDATED`. Host-only; no GPU, no ROCm, no C++ toolchain
required.

---

## Context

The host emulator and the model comparisons around it are the inner loop of most
host-side work in this project. When they are slow, they are slow for everything: every
semantic question, every coverage check, and every differential comparison waits on
them. Faster host tooling makes the whole host side of the project more thorough.

Two things are known about the current behavior and should shape any work here:

1. **Long runs have been killed by unbounded accumulator growth.** In earlier work,
   three accumulators grew without bound over a long run and terminated it: a
   cross-case registry, two within-case accumulators (the dominant factor), and a
   workgroup-path accumulator. The practical lesson is that **resident memory must be
   checked as part of any performance change** — a faster run that also leaks is not an
   improvement, and a run that dies silently is worse than a slow one. Heartbeat-style
   RSS sampling is the way to see this, rather than reading a log tail.
2. **A performance change must not change results.** The emulator's value is that its
   output is inspectable and comparable. An optimization that alters the per-instruction
   record stream has broken the tool, even if it is faster.

This is a good entry point for a contributor who wants to work on the host side: it
needs no GPU, and its correctness criterion (output unchanged, compared per record) is
easy to state and easy to check.

## What is needed

- **Measure first.** Produce a profile of the emulator on a representative workload,
  with the measurement method published alongside the result, so that a later change
  can be evaluated against it. A profile without a stated method is not reusable.
- **Establish a benchmark** that reports a rate along with its measurement conditions
  (input size, what is being measured, and how the run is bounded). The benchmark must
  be host-only and deterministic enough to compare across runs.
- **Make a bounded optimization.** Concrete candidates worth evaluating, roughly in
  order of likely payoff and low risk:
  - a **decode cache**, so that decoding a form repeated many times is done once;
  - a **tighter record path**, so that the recorder's bookkeeping — which runs per
    instruction and dominates the inner loop — costs less;
  - eliminating an obvious re-computation in the hot path;
  - reducing per-instruction object churn, which is a common Python cost and is
    especially visible in a per-instruction recorder.
- **Consider parallelism only on measured evidence.** If concurrency is explored,
  raise it only on a measured throughput gain with demonstrated resident-memory
  headroom — never merely because CPU cores sit idle. Idle cores are not evidence that
  parallelism will help, and added concurrency makes the memory-growth problem worse.
- **Keep the recorder's semantics identical.** Whatever changes, the record stream for a
  given input must be the same, value for value.

Out of scope: anything that changes what the emulator computes. This is a performance
task, not a semantics task.

## What a good resolution looks like

- A reproducible profile of the current behavior, with the method stated.
- A benchmark that a third party can run to reproduce the numbers.
- One or more bounded optimizations, each justified by the profile rather than by
  intuition.
- **Evidence that output is unchanged, compared per record** — with the comparison
  count reported. A matching aggregate total is explicitly not acceptable evidence
  here, because two different record streams can produce the same total.
- Resident memory reported before and after, over a run long enough to expose growth.

## Acceptance criteria

- [ ] A profile exists for a representative workload, and the measurement method is
      documented well enough to reproduce it.
- [ ] A host-only benchmark exists and reports a rate together with its measurement
      conditions (input, bounds, method).
- [ ] Each optimization is traceable to something the profile showed, with the
      reasoning stated.
- [ ] Output equivalence is demonstrated by **per-record** comparison, with the
      number of records compared stated; zero comparisons is not a pass.
- [ ] The equivalence check is demonstrated able to fail — for example by comparing
      runs that are known to differ, or by a deliberate perturbation — so that a
      "matching" verdict means something.
- [ ] Resident memory (RSS) is reported before and after over a long run, and any
      growth is either absent or explicitly explained.
- [ ] `python -m unittest discover -s tests/host -t tests/host` still passes from the repository root.
- [ ] If concurrency was added, the concurrency level is justified by a measured
      throughput gain with memory headroom, not by idle CPUs.
- [ ] No host result is presented as bearing on physical device behavior.

## Related

- [Contribution areas](../contribution-areas.md) — the "Python emulator performance"
  area.
- [Architecture](../architecture.md) — the recorder and why the per-record stream is
  the correctness criterion.
- [Evidence and reproducibility](../evidence-and-reproducibility.md) — why matching
  counts are not equivalence, and why a verifier must be tested against a known-bad
  case.
