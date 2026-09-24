# Project Overview

**DLSS Neural Rendering on AMD RDNA2 (gfx1030) — Experimental Compatibility Research**

This is an independent, unofficial research project. It is **not affiliated with,
endorsed by, or supported by** NVIDIA, AMD, Rockstar Games, Take-Two Interactive, or
any referenced third-party mod or project. No logos or vendor marks are used, and no
proprietary asset is redistributed. See `NOTICE` and `THIRD_PARTY_NOTICES.md` at the
repository root for the full statement.

## What this project is

A research effort investigating whether DLSS Neural Rendering (DLSS-NR) workloads can
be **translated, validated, and executed** on AMD RDNA2 / Navi21-class `gfx1030`
hardware (for example an RX 6950 XT), which is not a platform those workloads were
built for.

The work is organized around a **proof ladder** (see
[evidence and reproducibility](evidence-and-reproducibility.md) and the
[glossary](glossary.md)). Each rung is a strictly stronger claim than the one below
it, and **passing one rung never implies the next**. The ladder is:

1. Host static correctness
2. Host dynamic / independent oracle
3. One-workgroup physical
4. Multi-workgroup
5. Authentic full dispatch
6. Complete neural job
7. D3D12/HIP interop
8. Presented frame
9. Temporal stability
10. Sustained gameplay
11. Performance

**Current position — Phase 16BK:** host-connected graph execution is the primary
validation path. One source-built decoder-transition operation has narrow gfx1030
validation. M0 authentic execution is not established, G8 cold output is blocked,
G4 remains five-way ambiguous, and 91 of 94 graph entries remain placeholders.
Candidate-F is historical and frozen. No complete neural-network run, cold output,
game frame, or temporal sequence has been demonstrated. The recorded physical
launch allowance is 5 authorized, 5 spent, and 0 remaining; another project-local
GPU launch requires a new authorization. For details see [current state](current-state.md).

## What this project is not

- **Not a mod, crack, or piracy tool.** It does not patch, bundle, decrypt, or
  redistribute any third-party game, mod, or proprietary binary.
- **Not a redistributor of proprietary assets.** No game data, no vendor library, no
  vendor SDK binary, and no mod payload is included. Where a code object or similar
  artifact is needed for an experiment, the researcher generates it locally from
  their own legally obtained installation; the repository ships tooling and
  documentation, not the artifact.
- **Not a driver, firmware, or system modification.** The project does not change
  clocks, voltages, power limits, firmware, BIOS, registry, or drivers, and it does
  not modify watchdog/TDR settings. See the hardware safety policy in
  [current state](current-state.md) and [hardware testing policy](hardware-testing-policy.md).
- **Not a performance project.** Performance and gameplay are not applicable at the
  current stage; nothing here should be read as a benchmark or a compatibility claim.

## The four original contributions

### 1. Host instruction emulator

A host-side emulator for the `gfx1030` instruction forms that the traced workload
actually executes, together with explicit semantic models for LDS and the DS (data
share) unit. It runs on the CPU, needs no GPU, and produces per-instruction records
rather than only aggregate results. See `src/emulator/` — `emu.py`, `p14d_kd.py`,
`p14d_dec.py`, `p14d8_core.py`, `p14d11_emu.py`, `p14e_emu.py`, `p14e_emu_g.py`,
`p14e_lds_audit.py`, `wg_emu.py`, `p16k_recorder.py`, and the `p14eh*` reporting
modules, with `disasm_lib.py` for decode support.

### 2. Independent scalar ISA oracle

A separate, scalar reference implementation of the same ISA semantics, written so
that it does **not** share code or control flow with the emulator. Its purpose is to
be an *independent* check: an oracle that restates the emulator validates nothing.
See `src/oracle/isa_oracle_scalar.py` (with `emulator_base__emu.py` as the host-side
base it is deliberately kept apart from) and the explanation in
[architecture](architecture.md).

### 3. HIP interop tooling

A bridge layer for studying the HIP runtime boundary on this platform: ABI
fingerprints for two runtime generations, a forwarding shim, identity and
fail-closed backend loading, a fatbin identity gate, and a mock backend used for
host-side exercises that must not touch a GPU. See `src/bridge/` —
`amdhip64_7.cpp`, `mock_hip6.cpp`, `registry_ident.cpp`/`.h`, `abi_6_4_fingerprint.cpp`,
`abi_7_1_fingerprint.cpp`, `hip_bridge_smoke.cpp`, `hip_bridge_reg_smoke.cpp`,
`bridge_config.h`, `exports.def`, `kernel_policy_map.h`, plus helpers in
`src/bridge/tools/`.

### 4. Bounded physical harnesses

Small, explicitly bounded host programs that bring a single, parameterized workload
to the physical runtime and stop — no loops, no retries, no escalation. See
`src/harness/` — `p14_entry_probe_host.cpp`, the `p14ei_*_host.cpp` family,
`p14d10_entry_probe_host.cpp`, the `barrier_oracle_src_*.cpp` family, `probe_hidden.cpp`,
`probe_priv.cpp`, `p16j_pattern*.h`/`.cpp`, `p16j_sha256.h`, and the accompanying
`*.ps1` build scripts.

Supporting material: host-side analysis utilities in `tools/`, the two GPU-touching
programs in `tests/` (`soft_wmma_test.cpp`, `soft_wmma_bench.cpp`), and the two entry
scripts in `scripts/`.

## Who this is for

- **GPU/ISA researchers** interested in RDNA2 (`gfx1030`) instruction semantics,
  code objects, and the practical gap between host-validated semantics and physical
  execution.
- **Compiler and binary-translation engineers** who want a worked example of an
  independent oracle and a decode/rebuild path with explicit gates.
- **ROCm/HIP practitioners** interested in the runtime boundary on Windows with
  ROCm 6.4, and in bounded diagnostic methodology when a kernel does not complete.
- **Reproducibility-minded contributors** who want host-only tasks that need no GPU at
  all. See [contribution areas](contribution-areas.md).

## Where to go next

| I want to… | Read |
| --- | --- |
| Understand the current status and limits | [current-state.md](current-state.md) |
| Understand how the pieces fit together | [architecture.md](architecture.md) |
| Build it and run the checks | [build-and-setup.md](build-and-setup.md) |
| Understand what counts as evidence here | [evidence-and-reproducibility.md](evidence-and-reproducibility.md) |
| Find something to work on | [contribution-areas.md](contribution-areas.md) |
| Look up a term | [glossary.md](glossary.md) |
| See what a first tagged release would contain | [release-notes-v0.0.1-dev-preview.md](release-notes-v0.0.1-dev-preview.md) |

An independently written proof model is available in
[proof-model.md](proof-model.md); the hardware safety policy in
[hardware-testing-policy.md](hardware-testing-policy.md); the reverse-engineering
scope in [reverse-engineering-boundaries.md](reverse-engineering-boundaries.md);
and provenance records in [PROVENANCE.md](PROVENANCE.md).
