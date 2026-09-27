# Phase 16BO / A8C8 public state-repair note

Date: 2026-09-27

## Why this note exists

A public coordination update previously stated that Phase 16BO/A8C6 had already
produced a complete project-owned gfx1030 core frame, a GTA V Enhanced capture,
offline replay and two matched presented neural frames.

The later maintainer report of record reconciled that public text against the
canonical local tree and found the claimed successor implementation/evidence was
not present. The public text had been written while the local campaign was still
running and did not describe a later completed state.

This public note corrects the coordination boundary without publishing private
campaign receipts, proprietary assets, model weights, machine-local paths or raw
captures.

## Current boundary

The latest report of record states, in substance:

```text
Phase                              16BO
native core placeholder execution  89 / 94 nodes (25 families)
native REAL-certified families     4 / 30
project-owned gfx1030 source frame  not established
GTA capture                        not established
GTA neural frame presentation      not established
warm/consecutive rendering         not established
```

The host temporal contract and game-integration safety tooling are useful, but
they are host-side preparation rather than evidence that rendering occurred.

## What changes in the engineering plan

Do not spend another convergence campaign turning unresolved native layout
hypotheses into certifications merely to make the historical native registry
green.

Keep the native/recovered backend intact and fail-closed, and build a separate
`SOURCE_CANONICAL_BACKEND` tracked in #76.

That backend:
- uses authenticated user-owned model bytes without redistributing them;
- implements the recovered logical network in project-owned canonical layouts;
- has a CPU reference independent from the HIP implementation;
- uses simple, bounded, explicit source kernels first;
- synchronizes explicitly;
- treats latency as irrelevant until correctness exists;
- uses separate evidence labels so source success cannot masquerade as native
  NVIDIA-kernel/layout parity.

## Physical boundary

No device execution is authorized merely by this documentation correction.

The source backend must first pass:
1. exact schedule/weight-map/reference checks;
2. primitive semantic mutants;
3. two materially different complete host source frames;
4. a new live source-backend gate;
5. gfx1030 object/compiler/source identity checks.

A later fresh bounded physical campaign should proceed from source primitives to
a small complete source frame before target-resolution or GTA work.

## Optimization boundary

Performance, reuse, asynchronous execution, reduced geometry, zero-copy,
frame generation, multipass and runtime migration remain research backlog.
They are not prerequisites for the first faithful source frame and must not be
used to obscure the missing correctness milestone.

## Historical preservation

The older A8C6 coordination document is retained with a superseded warning.
This correction does not delete historical research or retroactively alter
private evidence records. It only prevents stale public prose from being used as
current proof.
