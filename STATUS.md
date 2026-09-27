# Status

Authoritative public coordination state of the project. If this file disagrees
with another high-level public status document, this file wins.

Last reviewed: 2026-09-27

---

## One-line summary

**Phase 16BO remains in progress. The earlier public A8C6 first-frame/GTA
success claims are superseded and must not be used as current evidence.**

The latest maintainer report of record reconciles the local tree against the
public coordination surface and finds that the public success claims did not
have the corresponding local implementation/receipts. The latest measured local
state reported:

```text
host test suite                 845 tests, green
native core placeholders       89 / 94 nodes, 25 families
native REAL-certified families 4 / 30
project-owned gfx1030 frame     NOT REACHED
GTA capture                     NOT REACHED
GTA neural presentation        NOT REACHED
warm/consecutive rendering      NOT REACHED
```

This correction is about claim scope, not about erasing historical research.

## Backend split

The project now distinguishes two independent tracks.

### NATIVE_RECOVERED_BACKEND

The historical translated/native-layout recovery track remains fail-closed where
evidence is absent. It may remain `NOT_READY` without blocking the practical
rendering experiment.

Do not:
- promote hypotheses to REAL/native certification;
- invent native activation/token layouts;
- weaken certificate gates;
- treat source-backend success as native-kernel parity.

### SOURCE_CANONICAL_BACKEND

The immediate P0 engineering path is tracked in
[#76](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/76).

It is a separately labeled, project-controlled implementation of the recovered
logical 71-block network semantics:
- authenticated user-owned model weights;
- canonical row-major project activation layouts;
- independent CPU reference;
- correctness-first HIP source kernels compiled explicitly for gfx1030;
- explicit E4/F16/F32 publication semantics;
- explicit transitions, window attention, ViT and head;
- no dependency on unresolved NVIDIA-native register/token/4x4 activation layout.

The first valid physical claim from this track is
`FIRST_PROJECT_OWNED_GFX1030_SOURCE_FRAME = PASS`, and only after a complete
small source frame agrees against the CPU reference.

## What is actually established

Current high-confidence local/project facts suitable for coordination include:
- the host/native graph is substantially mapped and traversable;
- authenticated model/container work remains valuable;
- the latest report records 89/94 native core nodes still using placeholder
  execution and 4/30 native REAL-certified families;
- `TemporalStateContractV1` exists and is host-tested;
- GTA FrameIdentity/motion/lockstep/late-result/device-health host tooling exists;
- the historical physical harness is fail-closed;
- no current public claim may state that this project already produced a
  complete project-owned gfx1030 neural frame or GTA neural presentation.

## Immediate work

1. **Build/qualify SOURCE_CANONICAL_BACKEND (#76).**
   Start with the CPU reference, logical tensor map, exact schedule and semantic
   mutants; then two different complete host source frames.
2. Build a new live source-backend gate. Every row must be measured; no literal
   verdict rows.
3. Compile source HIP objects explicitly for gfx1030 and inspect compiler/source/
   object identity.
4. Only after the source gate passes, use a fresh bounded physical campaign:
   primitives → small complete source frame → target-resolution source frame.
5. Only then arm actual GTA capture/pattern transport and process two distinct
   cold frames.
6. Reuse the existing temporal host contract only after cold source frames are
   real; warm/consecutive rendering comes later.
7. Keep optimization/reuse/async/zero-copy/runtime-migration experiments out of
   the critical path until the faithful source path exists.

## Publication/reproducibility boundary

The public repository must never invent receipts, hashes or source files to
retroactively support the superseded A8C6 coordination claims.

Publication work should:
- preserve historical artifacts;
- publish only provenance/privacy/license-clean source;
- mark private/proprietary inputs as user-supplied rather than redistribute them;
- distinguish source-backend evidence from native-recovered evidence.

See:
- [A8C8 state-repair note](docs/phase16bo-a8c8-state-repair.md)
- [SOURCE_CANONICAL_BACKEND #76](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/76)
- [state/source publication reconciliation #70](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/70)
- [evidence publication #68](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/68)

## Explicit non-claims

The project does **not** currently claim:
- complete native recovered execution;
- a project-owned complete gfx1030 neural frame;
- GTA V Enhanced neural capture/replay/presentation;
- warm temporal device correctness;
- consecutive neural gameplay;
- playable or real-time performance;
- direct zero-copy D3D12/HIP qualification;
- `hipMallocAsync` safety;
- frame generation or multipass qualification;
- HDR qualification.
