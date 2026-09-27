# Status

Authoritative current state of the project. If this file disagrees with another
high-level status document, this file wins.

Last reviewed: 2026-09-27

---

## One-line summary

**Phase 16BO / A8C6 has crossed the first-frame boundary.** The canonical
project state records a successful authentic host core frame, a successful
project-owned gfx1030 core frame, a real GTA V Enhanced source capture,
captured-frame offline neural replay, a successful presentation-path pattern,
and two different matched GTA neural-frame presentations.

This is a correctness milestone, **not** a temporal-stability, sustained-gameplay,
or performance claim.

See [docs/phase16bo-a8c6-state.md](docs/phase16bo-a8c6-state.md) for the current
campaign summary and evidence/publication boundary.

## Evidence/publication boundary

The canonical maintainer/operator state is ahead of the old public development
preview. Raw private receipts, proprietary-input-derived artifacts, machine-local
identities and game captures are not automatically publishable.

This repository therefore distinguishes:
- the **canonical project state** used for development coordination;
- the subset of evidence that is sanitized and publicly reproducible here.

Do not invent missing public hashes/receipts to make the publication surface look
complete.

## Current ladder position

```
 1. Host static correctness ................. demonstrated
 2. Host dynamic / independent oracle ....... demonstrated
 3. Representative physical qualification ... demonstrated for A8C6 selected package
 4. Multi-workgroup / connected execution ... demonstrated in the A8C6 core path
 5. Authentic full core dispatch ............ demonstrated
 6. Complete neural core job ................ demonstrated
 7. D3D12↔HIP correctness transport ......... demonstrated via staged transport
     direct/zero-copy interop ................ NOT qualified
 8. Presented neural frame .................. demonstrated on two distinct GTA frames
 9. Warm temporal stability ................. not qualified
10. Sustained gameplay ...................... not qualified
11. Performance ............................. intentionally not qualified
```

A8C6 used correctness-first staging. CPU staging between D3D12 and HIP is a valid
correctness transport; it does not constitute a zero-copy shared-resource claim.

## Core semantic/execution state

The canonical A8C6 state records:

- REAL implementation certificates are on the actual production resolution path;
- unadmitted production REAL keys fail closed;
- semantic resolution and execution certification are separate states;
- graph weights are **73/73 applied**;
- the final C512 projection/skip view is the authenticated 263,168-byte
  `block30.layer3.layer` record;
- C1024 scale-first semantics are active;
- ViT QKV uses an exact graph-visible record view/packing rather than the complete
  coarse `t_w_31` aggregate;
- decoder skips use authenticated transition outputs 4/8/14/22;
- core-required TensorSpecs and addition semantics are closed;
- core-required REAL bodies are certified;
- **core placeholder nodes = 0**;
- an authentic connected host core frame completes;
- the conservative execution plan and no-reuse memory plan cover the core;
- selected gfx1030 objects pass identity, VGPR/SGPR and required wave-size admission.

## Physical/game campaign state

Canonical A8C6 result:

| Rung | Result |
| --- | --- |
| START 0 — environment sentinel | PASS |
| START 1 — optional mean microprobe | not required unless separately recorded |
| START 2 — representative neural families | PASS |
| START 3 — complete standalone gfx1030 core frame | PASS |
| START 3 — different cold input A/B control | PASS |
| START 4 — GTA source capture + pattern path | PASS |
| START 5 — captured-frame offline neural replay | PASS |
| START 6 — matched GTA neural frame N | PASS |
| START 7 — second different matched GTA neural frame M | PASS |

The N/M pair establishes that the successful path is not merely a stale, constant or
hard-coded single-frame result. It does **not** establish warm temporal behavior.

## Historical blockers that are no longer current

### Old J3 watchdog localization

The earlier Candidate-F/J3 watchdog diagnostics remain historical evidence, but they
are no longer the project's current blocker. They must not be used to describe the
present project state as "stuck at one-workgroup liveness."

### Old graph-weight identity gap

Earlier stages represented graph weights with invalid/default extents and lacked a
complete graph→container identity map. That state is superseded:

```
A8C5: 73/73 factually resolved, 72/73 applied
A8C6: 73/73 applied
```

### Mean as node-count blocker

`mean` is classified as a Rec.709 luminance-mean reduction with a 32-bit float
output store. Milestone membership is dependency/control-flow based: an auxiliary
leaf does not block the authenticated neural core merely because an older execution
table counted it as node 94.

## Explicit non-claims

The project does **not** yet claim:

- warm temporal/history correctness;
- temporal stability over sustained play;
- sustained gameplay qualification;
- playable performance;
- optimized E4M3/packed/fused execution;
- `hipMallocAsync` safety on gfx103x;
- zero-copy/shared-resource D3D12/HIP qualification;
- DirectML as the project's implementation;
- frame generation or multipass qualification.

## Immediate next work

1. Sanitize and publish the A8C6 proof package where lawful and useful.
2. Preserve an independently reproducible project-owned source/core route.
3. Qualify warm temporal/history behavior.
4. Revisit direct D3D12/HIP zero-copy only as an optimization/engineering path.
5. Pursue independent RDNA2 reproduction.
6. Only after correctness/temporal work, optimize performance.

Live coordination is in the GitHub Issues tab. Post-faithful optimization issues may
now be investigated without reclassifying their external benchmarks as local evidence.
