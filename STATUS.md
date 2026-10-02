# Status

Authoritative public **coordination** state of the project. If this file
disagrees with another high-level public status document, this file wins for
current milestone wording. Public reproducibility may lag the maintainer-local
report; #70/#68 track that publication boundary.

Last reviewed: 2026-10-02

---

## One-line summary

**Phase 16BO / A8C11 remains in progress. SOURCE_CANONICAL host/device proof
stands; a scoped standalone module-resolved canonical launch certificate now
passes; authentic GTA Story Mode was reached with the isolated capture hook
operating, but the first Story-mode readback failed and §23 cancelled the GTA
master before any frame capture.**

No GTA frame has been captured or presented. Pattern paints are not captures.

## Latest maintainer-local measured boundary

```text
phase                              16BO / A8C11
native/recovered backend           NOT_READY
SOURCE_CANONICAL gate              ARMED 25/25, 186 comparisons
Host A / Host B                    71/71 blocks each
mutation discriminability          27/27 required mutants REJECTED
independent audit                  27/27 attacks reached + REJECTED
gfx1030 device fixture 320         PASS
gfx1030 device fixture 512         PASS
standalone launch certificate      PASS, 2/33 canonical symbols
canonical launch route             MODULE_RESOLVED_LAUNCH_V1
registered-static canonical path   FAIL rc=98, unchanged
authentic GTA Story Mode           YES
isolated capture hook in-game      YES
menu pattern paints                3079 verified
armed-window reconcile             784 / 784 / 784
Story first pattern claim          PAT_REFUSED_COPY_FAILED
post-refusal state                 presents frozen -> ERR_GFX_STATE
specific Map HRESULT               NOT CAPTURED
GTA CaptureArm                     NEVER ARMED
GTA frame captured                 NO
presented neural frame             NO
consecutive frames                 0
Master A                           CLOSED, 6/6 exhausted
Master B                           CANCELLED_SECTION23, 2/4 consumed, 2 VOID
```

## Backend / launch split

### NATIVE_RECOVERED_BACKEND

The historical translated/native-layout recovery track remains fail-closed and
`NOT_READY`. SOURCE_CANONICAL success must never be relabeled as native
NVIDIA-kernel/layout parity.

### SOURCE_CANONICAL_BACKEND

The source-canonical correctness baseline remains:

- two complete 71-block host fixtures;
- ARMED 25/25 live source gate;
- 27/27 mutation discrimination;
- 27/27 independent attack rejection;
- complete gfx1030 320 + 512 device fixtures.

### A8C11 launch certificate

A8C11 proves a narrower additional fact:

- ordinary registered-kernel resolution works;
- the canonical gfx1030 inner image loads and resolves through the module API;
- two canonical symbols execute end-to-end through
  `MODULE_RESOLVED_LAUNCH_V1`;
- the registered-static canonical path still returns rc=98.

Certificate headline `REGISTERED_GFX1030_LAUNCH_A8C11 = PASS` therefore means
the directive's allowed module-resolved compatibility-dispatch route is
certified at its exact standalone-host / 2-of-33 scope. It does **not** mean
the original registered-static path is repaired. That secondary defect is #80.

## Current P0 — #82

Active blocker:
[#82](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/82).

The first Story-mode pattern claim completed its fence wait and then failed at
`Map(readback)`. The capture subsystem correctly failed closed:

```text
Map(readback) failure
    -> PAT_REFUSED_COPY_FAILED
    -> HaltPattern
    -> presents frozen
    -> ERR_GFX_STATE
    -> §23
    -> Master B CANCELLED
```

The current queue-state-desynchronization idea is **UNMEASURED**. The specific
HRESULT was not captured because the current diagnostic field is hardcoded to
zero. Host work must first capture the real HRESULT/device-removal reason and
mechanically bind queue, backbuffer, resource, fence and generation identity.

## GTA boundary actually reached

A8C11 did reach authentic Story Mode in a true no-background-neural
configuration:

- quarantine stayed 5/5;
- only the isolated capture DLL was injected;
- hook initialization succeeded;
- presents advanced in-game;
- menu pattern path produced 3079 verified paints;
- the armed menu interval reconciled exactly 784/784/784.

For navigation, the opaque pattern was deliberately disarmed and re-armed only
after Story Mode was live. Mouse input worked; synthesized Enter did not.

This establishes game entry and capture-hook/pattern operation. It does **not**
establish a capture. `CaptureArm` never armed and Q5 is
`NOT_ATTEMPTED_BLOCKED_BY_23`.

## Hard-stop / authorization boundary

Master A:
- 6/6 starts consumed;
- certificate complete;
- CLOSED.

Master B:
- START17 + START17R consumed 2/4;
- §23 fired on the Story readback/ERR_GFX_STATE condition;
- master CANCELLED;
- remaining 2 starts VOID.

There is **no current physical/GTA authorization**. No existing master/start id
may be reopened or routed around. Any future device/GTA start requires a fresh
operator ask and a new master.

Readable OS channels in the A8C11 GTA campaign showed no bugcheck/TDR/display
fault, WER, GTA crash, minidump or LiveKernelReports file. WHEA remains
CANNOT_SEE because the channel is absent. §23 is presence-based on the in-game
condition class; clean OS channels do not invalidate the cancellation.

## Immediate work

1. **#82:** host-only analysis/instrumentation of the Story `Map(readback)`
   failure; capture the real HRESULT/device-removal reason and queue/resource/
   fence/backbuffer identities.
2. Add bounded synthetic controls for stale queue/backbuffer generation and
   resource retirement where possible.
3. Preserve fail-closed pattern refusal and the measured menu-first navigation
   protocol.
4. **#80:** continue registered-static rc=98 investigation separately; do not
   block #82 on repairing a path the standalone certificate did not require.
5. **#70:** publish the actual maintained A8C11 source/integration state safely.
6. **#68:** publish the lawful sanitized A8C11 evidence subset.
7. Only after a fresh operator authorization/new master: ask one narrow physical
   question about surviving the first Story readback and reaching an authentic
   nonempty capture.
8. Two cold captured/presented GTA frames must precede #66 warm qualification.
9. Keep performance/reuse/async/zero-copy outside the critical path.

## Publication / reproducibility boundary

Never publish or reconstruct:

- proprietary model weights/private tensors;
- vendor runtime binaries or proprietary code objects;
- game binaries/assets/raw private captures;
- personal/machine paths;
- credentials/provider configuration;
- raw session prompts;
- unsanitized crash/system dumps;
- invented receipts/hashes.

Historical A8C6/A8C8/A8C10 records remain historical records.

Manifest-tracked live surfaces such as ROADMAP/current-state/project-overview
must be regenerated/reconciled through #70 rather than hand-edited with invented
manifest identities.

## Explicit non-claims

The project does **not** currently claim:

- complete native recovered execution;
- native NVIDIA-kernel/layout parity;
- repaired registered-static canonical launch;
- certification of all 33 canonical symbols;
- a GTA neural capture or presented neural frame;
- warm temporal device correctness;
- consecutive neural gameplay;
- sustained gameplay;
- playable or real-time performance;
- direct zero-copy D3D12/HIP qualification;
- `hipMallocAsync` safety;
- frame generation/multipass qualification;
- HDR qualification.

## Live trackers

- [#82 — P0 Story-mode readback/capture blocker](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/82)
- [#80 — registered-static rc=98 defect](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/80)
- [#70 — publish maintained A8C11 implementation/current state](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/70)
- [#68 — publish sanitized A8C11 evidence](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/68)
- [#66 — temporal host contract / warm qualification](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/66)
- [#57 — external research registry](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/57)
- [#29 — independent whole-job/launch-contract cross-validation](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/29)
