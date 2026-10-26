# @Bottiee RX 6750 XT / gfx1031 Windows MSVC matrix — 2026-09-28

This note records a sanitized external-toolchain A/B supplied by repeat contributor
[@Bottiee](https://github.com/Bottiee). The raw transcripts are intentionally not
committed because they contain local-machine filesystem paths. This document is a
derived public evidence record; the raw transcript hashes are recorded below so the
source material can be distinguished unambiguously without publishing it.

## Scope and classification

This packet compares two Windows MSVC environments on the same RX 6750 XT /
`gfx1031` machine with the same ROCm/HIP 6.4 bounded target-aware runner.

It establishes:

- **host/toolchain A/B evidence:** MSVC 19.29 permits the current ROCm 6.4 direct-Clang
  invocation to compile; MSVC 19.51 hits the known HIP/`<cmath>` overload collision;
- **supplemental `EXTERNAL_PHYSICAL_SAME_TARGET` evidence** for the already-qualified
  bounded soft-WMMA primitive under the MSVC 19.29 environment;
- **no physical evidence at all** for the MSVC 19.51 environment, because compilation
  fails before the executable is produced or launched.

It does **not** establish full-network portability, SOURCE_CANONICAL qualification,
gfx1030 evidence, stress stability, or general binary portability.

## Raw transcript identity

| Transcript | SHA-256 | Public handling |
|---|---|---|
| VS2019 result | `9f0d1ac85dabbcd9f3f6bd4c63d9ef945656048135eab507ee85b8dcca6b5cfd` | raw file withheld; sanitized facts below |
| newer-MSVC result | `c137e0d62c1b839dc9bccbc171b04f86a9ceae7cfce77702db835e4f2b9cb111` | raw file withheld; sanitized facts below |

The transcripts do not include `git rev-parse HEAD`. Their working-directory label
matches the target-aware smoke branch name, but that is not enough to prove an exact
repository commit. Therefore this record does not invent a commit identity.

## Common device/runtime facts

Both transcripts report:

- GPU: AMD Radeon RX 6750 XT
- natural HIP architecture: `gfx1031`
- warp size: 32
- VRAM: 11.98 GiB
- shared memory per block: 64 KiB
- runner compiler: ROCm 6.4 bundled clang `20.0.0git`
- LLVM source revision:
  `33ab2c2f7838239f1e2e5c06432bbb8d887e8cb2`
- requested compile target: `gfx1031`

The later standalone `clang++.exe --version` output in both transcripts reports a
separate system LLVM 23.1.2 installation. That is ambient host inventory, **not** the
compiler printed and used by the target-aware runner.

## Matrix result

| Selected MSVC environment | Result | Classification |
|---|---|---|
| VS2019 / MSVC `19.29.30156` (toolset `14.29.30133`) | single-target gfx1031 compile succeeds; bounded tile executes and passes exactly | host positive + supplemental `EXTERNAL_PHYSICAL_SAME_TARGET` |
| newer VS / MSVC `19.51.36260` (toolset `14.51.36231`) | compile fails in ROCm 6.4 HIP headers with host/device overload collisions; no physical execution | host/toolchain negative only |

### MSVC 19.29 positive path

The runner emits one bundle:

`hipv4-amdgcn-amd-amdhsa--gfx1031`

Executable SHA-256:

`12A8D11A24EE1FA91FC33A15F365C946710D6716D4712DEB67634B5B35ECABB7`

The bounded GPU check reports:

- one 32-thread block / one 16x16x16 FP16→FP32 tile;
- `max abs error = 0.00e+00`;
- untouched sentinel elements: `0`;
- all outputs finite: `yes`;
- `Result: PASS`.

No stress test was run.

### MSVC 19.51 negative path

Compilation fails before physical execution. The first failure family is the known
ROCm 6.4 HIP wrapper collision with newer MSVC `<cmath>` declarations, including
`isgreater`, `isgreaterequal`, `isless`, `islessequal`,
`islessgreater`, and `isunordered`.

The runner terminates with:

`Compilation failed before physical execution.`

This must remain classified as a **host compiler/toolchain failure**, not a gfx1031
kernel or GPU failure.

The trailing `cl /Bv` command reports compiler identity and then prints
`D8003: missing source filename`; that diagnostic is expected from invoking the
compiler only to query version information and is not the HIP compile failure.

## Consequences for #41

This A/B turns the generalized Windows compiler preflight into a concrete,
falsifiable requirement:

1. print the selected MSVC/compiler/SDK identity before the HIP build;
2. run the same direct-Clang preflight shape used by the real runner;
3. classify the MSVC-19.51 `<cmath>` collision separately from target compilation,
   wrapper/path quoting, and GPU execution;
4. stop before dispatch on host-toolchain failure;
5. do not patch installed ROCm headers automatically;
6. preserve a positive path for the known-good MSVC-19.29 environment or use a
   compiler/toolchain carrying the upstream HIP-wrapper fix.

Issue #41 should remain open until that generalized preflight and its synthetic
positive/negative controls are implemented. The A/B question itself is now answered
for this machine.

## Consequences for #26

The MSVC-19.29 run adds an independent supplemental reproduction of the already
qualified bounded gfx1031 soft-WMMA primitive, with a new executable hash. It does
not promote the portability lane to a neural/full-frame claim.

No new physical retry is needed from this result. The next gfx1031 neural/operator
packet should still wait for an exact intentionally published SOURCE_CANONICAL base,
then compile a fresh gfx1031 object from that exact source.
