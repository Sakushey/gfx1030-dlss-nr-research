# Contribution Areas

This page lists where help is useful, with concrete example tasks. It is split into
work that needs **no GPU** (proof-ladder rungs 1–2, host-side) and work that
**requires a `gfx1030` device** (rungs 3 and above).

**Start with the host side.** The great majority of useful work here is host-only:
it is reproducible, it cannot damage anything, it needs no scarce physical run, and it
is where the project's current bottleneck actually lives. Physical experiments are
bounded and authorization-gated; they are not a good first contribution.

Before contributing, read [evidence and reproducibility](evidence-and-reproducibility.md)
and the [glossary](glossary.md). The labels and the rules there are not optional
style — they are the project's method.

Draft tasks that correspond to specific known gaps are in `docs/initial-issues/`
(these are drafts for the maintainer to open; do not open them yourself).

---

## No GPU required (rungs 1–2)

### RDNA2 / GFX10 ISA

Instruction forms, encodings, and semantics for RDNA2.

- Extend decode coverage to instruction forms present in the workload but not yet
  decoded; report coverage as a **population** (how many forms, which) rather than as
  a percentage.
- Write focused semantic tests for a single instruction family against the
  independent oracle, each with a negative control that must fail.
- Document the operand-encoding rules for a family, including the cases that made it
  ambiguous.
- Audit an existing semantic model for a form that is decoded but only partially
  handled, and state explicitly which sub-cases are unhandled.

### AMDGPU backend / code objects

The container and layout layer: code objects, fatbins, sections, and their metadata.

- Extend the container census (`tools/p16g_census.py`, `tools/p16g_msgpack.py`) to
  report properties a reviewer can predict and check.
- Add a static check for a structural invariant of a code object, and demonstrate the
  check rejecting a deliberately malformed artifact.
- Characterize a section or metadata field that the current tooling ignores, and
  document what a consumer can and cannot infer from it.
- Improve the identity/fingerprint coverage of an artifact class so that "is this the
  same artifact" has a definite answer.

### ROCm / HIP runtime

Runtime behavior as observed from the host.

- Extend the ABI fingerprints (`src/bridge/abi_6_4_fingerprint.cpp`,
  `src/bridge/abi_7_1_fingerprint.cpp`) to cover entry points the bridge does not yet
  identify, and record what differs between generations.
- Expand the mock backend (`src/bridge/mock_hip6.cpp`) so that a bridge code path
  currently only exercisable on hardware becomes exercisable host-side.
- Add a host-side test that a fail-closed path really fails closed — drive the bridge
  with a backend that is absent, unidentifiable, and present-but-wrong, and assert the
  refusals.
- Document the runtime identity question: what "the runtime" means here, and why the
  generation matters (ROCm 6.4 enumerates `gfx1030` in this environment; 7.1 does not).

### EXEC / VCC / wave32

The wave-level execution model: the `EXEC` mask, `VCC`, and 32-lane waves.

- Write targeted host cases for `EXEC`-mask behavior under branching, including the
  cases where a naive implementation is wrong, each with a negative control.
- Audit `VCC` usage and carry behavior across the instruction forms the workload
  executes.
- Determine and document which behaviors are **wave32-specific** versus shared with
  wave64, and label the untested cases as untested.
- Check lane-inactive behavior for a family of operations: what happens to a lane whose
  `EXEC` bit is zero, and whether the model implements it.

### Synchronization / waitcnt

Counter waits, barriers, and their placement relative to the operations they cover.

- Extend the barrier oracles (`src/harness/barrier_oracle_src_a..d.cpp`) with a fifth
  independent formulation of a barrier hypothesis, so there are five sources that can
  disagree.
- Add a static analysis that flags a `waitcnt` site whose placement does not cover the
  memory operations it appears intended to cover.
- Model barrier arrival and release semantics in the host models and test them against
  a case with a known-correct expected outcome.
- Write up the synchronization model with an explicit list of what is modeled and what
  is assumed.

### Compiler / binary translation

The decode/rebuild path and translation between representations.

- Strengthen the rebuild path (`src/isa/p14d_rebuild.py`) so a rebuilt artifact can be
  checked against a predicted property rather than inspected by eye.
- Add a differential test between the decoded form and the original encoding that
  compares **per instruction**, and reports the comparison count.
- Extend the memory-model gate (`src/isa/p16h_global_gate.py`) with an additional
  constraint and a known-bad artifact it must reject.
- Document the translation's assumptions and, explicitly, its known-unsound corners.

### Python emulator performance

The host emulator is the inner loop of most host-side work. See draft issue 04.

- Profile the emulator on a representative workload and publish a profile with the
  measurement method, so the result is reproducible.
- Implement a bounded optimization (a decode cache, a tighter record path, avoiding an
  obvious re-computation) and show it changes nothing about the output — compared
  per record, not in aggregate.
- Improve the recorder's memory behavior; long runs have historically been killed by
  unbounded accumulator growth, so check resident memory as part of any change.
- Add a benchmark that reports a rate and its measurement conditions, so a later change
  can be evaluated against it.

### Reproducibility / CI

Keeping results trustworthy and re-runnable.

- Add host-only tests in `tests/host/` (stdlib `unittest`); extend the import check
  (all published modules import cleanly) on a clean checkout.
- Add a guard test (`tools/p16k_guard_test.py`-style) for a check that currently has no
  negative control, and demonstrate it failing against a known-bad input.
- Add a check that a frozen artifact has not changed since it was frozen, and test the
  check by perturbing the artifact.
- Build a small, self-contained deterministic fixture so a host test does not depend on
  a large local artifact to run.
- Verify the repository contains no credential, personal path, or third-party binary,
  and turn that verification into a check rather than a promise.

### Documentation

- Expand the [glossary](glossary.md) where a term is defined but under-explained, with
  a concrete example.
- Document one component's interface from its actual code, stating what is guaranteed
  and what is merely current behavior.
- Write a worked example that a newcomer can follow from a clean checkout to a passing
  host check.
- Audit the documentation for claims that overstate their evidence level, and correct
  the label rather than the prose.

---

## Requires `gfx1030` (rungs 3+)

Physical work is **bounded, one-shot, and authorization-gated**. Read
[hardware testing policy](hardware-testing-policy.md) and
[current state](current-state.md) first. In particular: never modify watchdog/TDR
settings, never change clocks/voltages/power limits/firmware/BIOS/registry/drivers,
never add automatic retries, and always preserve raw output.

The current live problem — a correctly parameterized one-workgroup translation reaches
the runtime but does not complete before the watchdog recovers the engine — is the
focus. See draft issues 01 and 03.

### Physical kernel debugging

- Localize the non-completion of the one-workgroup case by adding a **bounded
  checkpoint** to an existing harness, so that partial progress becomes observable,
  then run it once under authorization.
- Characterize the post-watchdog synchronization behavior: what a synchronization call
  returns after a recovery, and why that return value must not be read as kernel
  output (draft issue 03).
- Compare the preflight-observed environment with the environment the run actually
  used, and report any divergence.
- Add a preflight check that would catch a known prior mismatch class before a run
  rather than after.
- Establish a baseline for a single bounded case that a later change can be compared
  against, with the raw output preserved.

### RDNA2 / GFX10 ISA (device-side)

- Confirm a host-modeled instruction behavior against the device with a minimal,
  bounded probe, and label the result `PHYSICAL_DIAGNOSTIC` unless it is a completed
  workgroup.
- Determine empirically which forms the device actually executes in the bounded case,
  and compare that set with the modeled set.

### ROCm / HIP runtime (device-side)

- Extend the entry probes (`src/harness/p14_entry_probe_host.cpp`,
  `src/harness/p14d10_entry_probe_host.cpp`) to characterize an additional aspect of
  the entry contract, using the mock backend first so the probe logic is known-good
  before it costs a physical run.
- Record the runtime identity that actually loads at run time and compare it with the
  fingerprint's expectation.

### Synchronization / waitcnt (device-side)

- Test a single barrier hypothesis on the device with the bounded barrier oracle, one
  case per authorization, and record the raw result.
- Distinguish, for one observed case, whether a stall is synchronization-related or
  liveness-related, and state the evidence for the distinction.

### Physical kernel debugging across devices

- Reproduce a bounded case on a second Navi21/`gfx1030` device and report the
  difference (draft issue 08).
- Validate the host-only setup on a second machine to confirm the environment
  documentation is accurate for someone who is not the original researcher (draft
  issue 07).

### D3D12 / HIP interop

Not yet demonstrated, and not reachable before the earlier rungs. What is useful now
is preparation, host-side:

- Map the interoperability requirements — what would have to be shared, synchronized,
  and presented — and write it up as a requirements document rather than an
  implementation (draft issue 06).
- Identify which parts of the requirement can be validated host-side before any device
  work is attempted.

### Compiler / binary translation (device-side)

- Verify that a rebuilt artifact is accepted by the device under the same bounded
  procedure used for the original, and report the comparison per instruction where
  that is observable.

---

## How to propose something not listed here

Open a discussion describing the task, which rung it targets, what evidence level you
expect to reach, and what would make you conclude it failed. A task with a stated
failure condition is much easier to accept than one without.
