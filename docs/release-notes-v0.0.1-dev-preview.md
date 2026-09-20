# Development Preview 0.0.1 — gfx1030 Neural-Rendering Research

> **DRAFT — this release has NOT been created yet.** This document is a draft of
> release notes for a release that does not exist. No tag has been created, no
> release has been published, and nothing described here has been shipped. It is
> written so that a future release, if one is made, has a considered description
> ready. Suggested future tag: **`v0.0.1-dev-preview`**.

**Project:** DLSS Neural Rendering on AMD RDNA2 (gfx1030) — Experimental Compatibility
Research

**Suggested tag:** `v0.0.1-dev-preview`

**Suggested release type:** pre-release / development preview

**Status of the work described:** active research. See
[current state](current-state.md) for the accurate, current picture — in particular,
nothing here constitutes a compatibility claim or a working result.

---

## About this preview

This is an independent, unofficial research project. It is **not affiliated with,
endorsed by, or supported by** NVIDIA, AMD, Rockstar Games, Take-Two Interactive, or
any referenced third-party mod or project.

A development preview is being considered for the **host-side research tooling**: the
emulator, the independent oracle, the HIP interoperability tooling, the bounded
harnesses, and the analysis utilities. The purpose of publishing it at this stage is
to make the methodology and the tooling available for review and reuse while the
physical problem is still unsolved — not to announce a result.

Nothing in this preview is a statement that any workload runs on `gfx1030`. There is
no end-to-end result to announce. See "What is explicitly not in this preview" below.

## What is in this preview

### Host instruction emulator

A host-side emulator for the `gfx1030` instruction forms the studied workload actually
executes, with explicit semantic models for LDS and the DS (data share) unit, a
workgroup model, and a recorder that emits **per-instruction records** rather than only
aggregate results. The per-instruction record stream is what makes results comparable
item by item instead of by total. See `src/emulator/`.

### Independent scalar ISA oracle

An independently written scalar reference implementation of the same ISA semantics,
deliberately not sharing code or control flow with the emulator. Its purpose is to be
able to disagree with the emulator; an oracle that restates the emulator validates
nothing. See `src/oracle/isa_oracle_scalar.py` and
[architecture](architecture.md) for why the separation is load-bearing.

### HIP bridge tooling

Tooling for studying the HIP runtime boundary on this platform: ABI fingerprints for
two runtime generations, a forwarding shim, runtime identity handling, a **fail-closed**
backend load, a **fatbin identity gate**, and a mock backend so bridge logic can be
exercised host-side without a GPU. See `src/bridge/`.

### Bounded physical harnesses

Small harness programs that carry a single parameterized case to the runtime and stop —
no loops, no retries, no escalation. These are the mechanism by which the project does
physical experiments in a bounded way. See `src/harness/`. Harnesses that embed a code
object require the researcher to generate that artifact locally; see below.

### Analysis utilities

Host-side tools for determinism and differential comparison, frozen-artifact checking,
guard testing, environment readiness, census and population reporting, static artifact
inspection, and job bookkeeping. See `tools/`. Several of these exist specifically to
keep other checks honest — a guard-testing tool, for instance, exists to verify that
the project's checks are able to fail.

### Bounded test program

A single bounded GPU experiment, run through one documented entry point:
`powershell -ExecutionPolicy Bypass -File scripts\run_test.ps1`. It performs a device
preflight, compiles a small soft-WMMA test program for `gfx1030`, and runs one tiny
tile. It is not a benchmark and not a stress test. See
[build and setup](build-and-setup.md).

### Documentation

The documentation set accompanying the preview: project overview, current state,
architecture, build and setup, evidence and reproducibility, contribution areas,
glossary, and drafted issue descriptions.

## What is explicitly NOT in this preview

- **No proprietary artifacts of any kind.** No code objects, no fatbins, no vendor
  binaries, no vendor SDK content, no game data, no mod payloads, no assets. Where a
  harness needs a code object, the researcher generates it locally from their own
  legitimately obtained installation. This is deliberate and permanent.
- **No game frame, and no end-to-end result.** No DLSS-NR frame has been produced,
  presented, or measured.
- **No D3D12/HIP interoperability.** Not demonstrated; the requirements are an open
  question, not an implementation.
- **No performance or gameplay data.** Performance and gameplay are not applicable at
  the current stage. Nothing here should be read as a benchmark.
- **No multi-workgroup, full-dispatch, or complete-job result.**
- **No driver, firmware, or system modification of any kind.** The project does not
  change clocks, voltages, power limits, firmware, BIOS, registry, or drivers, and does
  not modify watchdog/TDR settings.
- **No compatibility claim.** Compatibility with any game, mod, or workload is not
  asserted, implied, or predicted.

## Known limitations

**The physical liveness failure is the principal known limitation and is unresolved.**

- A correctly parameterized **one-workgroup** `gfx1030` translation reaches the
  physical HIP runtime and is accepted at launch, but **does not complete** before the
  Windows GPU watchdog recovers the engine. That is a rung-3 attempt that has not
  passed.
- Host-side descriptor, argument, address-layout, barrier, and `waitcnt` checks pass
  on the modeled path, so simple host-configuration mistakes in those areas are no
  longer the leading explanations. These checks do not rule out hardware-specific
  synchronization, initialization, scheduling, or model-fidelity defects.
- A bounded midpoint checkpoint diagnostic also triggered watchdog recovery, narrowing
  the first physical failure to the **first ~55.6% of modeled one-workgroup
  execution**. No exact failing instruction or mechanism has been established.
- After a watchdog recovery, a host-side synchronization call can return without
  reporting an error. That return value is **not** kernel output and must not be read as
  success.
- The **T32 host model is experimental** and is not a qualification of anything.
- Host-side coverage tracks the instruction forms the studied workload actually
  executes. It is not whole-ISA coverage, and a coverage gap is not a correctness
  result.
- The host tooling is research-grade: interfaces may change, error reporting is uneven,
  and the import arrangement (one flat namespace across `src/*` directories) is
  convenient for the researcher rather than idiomatic for a library.
- The physical path targets **AMD ROCm 6.4** on Windows because that is the runtime
  generation that enumerates `gfx1030` in this environment; ROCm 7.1 does not enumerate
  this device here.

Full detail: [current state](current-state.md).

## Hardware safety statement

Every physical experiment in this project is **bounded and one-shot**, with no
automatic retries, no watchdog/TDR modification, and no clock/voltage/power/firmware/
BIOS/registry/driver changes. Raw evidence is preserved as produced. Physical tests are
run only when explicitly authorized. See
[hardware testing policy](hardware-testing-policy.md).

**If you run the bounded GPU experiment yourself:** do not modify watchdog or TDR
settings, do not change clocks, voltages, power limits, firmware, BIOS, registry, or
drivers, and preserve the complete output. If it does not pass, report the output
rather than tuning the system.

## Feedback requested

The most useful feedback at this stage, roughly in order:

1. **On the physical liveness problem.** Any independent perspective on why a
   correctly parameterized one-workgroup kernel would be accepted at launch but fail
   to complete, given the host-side areas already eliminated. See
   [issue #2](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/2).
2. **On post-watchdog synchronization semantics.** What a HIP synchronization call
   actually reports after a watchdog recovery, and how to interpret it correctly. See
   [issue #4](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/4).
3. **On the instruction forms actually executed.** Independent review of the
   dynamically executed `gfx1030` forms and their semantics, especially `EXEC`/`VCC`
   masking, LDS/DS, and `waitcnt` placement. See
   [issue #3](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/3).
4. **On the methodology.** Whether the proof ladder, the evidence labels, and the
   verifier rules described in [evidence and reproducibility](evidence-and-reproducibility.md)
   are sound — and where they are gameable.
5. **On reproducibility.** Whether the host-only setup works on a machine that is not
   the original researcher's. See
   [issue #8](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/8).
6. **On hardware generality.** Whether a bounded case behaves the same on a second
   Navi21/`gfx1030` device. See
   [issue #9](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/9).
7. **On host emulator performance**, if the emulator is the bottleneck for your own
   work. See [issue #5](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/5).

Contributions are welcome — including host-only work, which needs no GPU. See
[contribution areas](contribution-areas.md).

## A note on reading this preview

The tooling in this preview is more developed than the results, and that asymmetry is
intentional: the methodology is the contribution at this stage. If you take one thing
from the preview, the intended thing is the discipline of separating host evidence from
physical evidence, and of requiring a check to be demonstrated able to fail. The
project's own history contains several occasions where that discipline caught a
"clean" result that meant nothing.
