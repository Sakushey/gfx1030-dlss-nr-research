# Status

Last coordination refresh: 2026-10-04

> **Measured report of record: finalized Phase 16BO / A8C14.**
> **Active continuation: A8C15 (authority/plan, not evidence).**
> Active first-frame P0: [#84](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/84).

## One-line summary

SOURCE_CANONICAL host/device-fixture proof and the scoped module-resolved gfx1030
launch certificate remain standing; a later A8C13 campaign also established an
authentic GTA 1920×1080 **source capture**. The first authentic **GTA-derived gfx1030
neural device frame is not yet earned**: A8C14 closed with the genuine Frame-C host
reference incomplete, its freeze incomplete and zero new physical starts.

## Authority split

Use three distinct layers:

1. standing measured history — SOURCE_CANONICAL host/device evidence plus A8C13 capture;
2. finalized measured report — **A8C14**;
3. active execution authority — **A8C15**, which names future work but does not make it PASS.

The broad private CURRENT_STATE record contains older carried Phase-16BL-era package
and budget blocks. Those historical rows do not override later A8C13/A8C14 evidence.

## Current measured state

| Subject | State |
| --- | --- |
| phase | **16BO** |
| finalized stage/report | **A8C14** |
| active continuation | **A8C15** |
| SOURCE_CANONICAL Host A/B | **71/71 + 71/71** |
| source gate | **ARMED 25/25**, 186 comparisons |
| mutation / independent attack controls | **27/27 + 27/27 rejected** |
| gfx1030 device fixtures | **320 PASS + 512 PASS** |
| module-resolved launch certificate | standing PASS at exact scope |
| registered-static launch | historical **rc=98**, non-prerequisite; #80 closed |
| authentic GTA 1920×1080 source capture | **PASS** (standing A8C13 fact) |
| A8C14 reproducible capture build | **PROVEN** |
| Frame-C artifact/routing/input/head binding | **PASS** |
| PresentOwned SOURCE/DESTINATION repair | **D1–D5 REPAIRED**, control PASS |
| sidecar/journal namespace | **REPAIRED**, mutation-proven |
| genuine Frame-C host reference | **INCOMPLETE — Section 7 = 2/7** |
| Class-B recheck | **FAIL by design** — real C plan absent |
| bounded-f16 repair | host control PASS 20/20; **LIVE_UNTESTED** |
| A8C14 freeze V1 | **INCOMPLETE**, 8/9 pending rebuild |
| A8C14 physical starts | **0** |
| authentic captured-frame gfx1030 device NR | **NOT RUN / NOT EARNED** |
| device head / NR.png | **absent / absent** |
| warm temporal / consecutive frames | not reached |
| performance/playability | not qualified |

## A8C14 host attempt result

A8C14 landed the reproducible-build, Frame-C writer/routing, captured-input/head,
PresentOwned, sidecar-namespace, state-aware-control, bounded-f16 and freeze-tooling
repairs, but earned no new device/game neural rung.

The four genuine C-host attempts were:

1. WinError 5 on atomic promotion of the ~849 MB QKV artifact;
2. the same rename failure at **96.85%** (2,142,208 / 2,211,840 rows), with holder unmeasured;
3. MemoryError from eager f16 argument construction; repaired/proven host-side;
4. external background-shell reaper before reaching the repaired path.

Attempt 4 therefore did not test the repair. Preserve the completed C checkpoint and
journals; do not throw them away for a cosmetically fresh run.

## Current P0 — #84

The required host order is:

~~~text
retire attempt-4 stale liveness honestly
→ measure rename holders / harden bounded atomic promotion
→ verify 2,211,840-row C checkpoint + exact argv
→ durable attempt 5
→ SOURCE_HOST_FRAME_C + STAGE_BOUNDARIES_C + HEAD_A8C10_C
→ genuine full-A
→ genuine expected-C
→ real start2_plan_C
→ Class-B + 1920 valid/padded structural falsifiers
→ final battery incl. 243 regression
→ complete A8C15 V2 freeze
→ fresh live device preflight
~~~

No earlier result is reopened to bypass this order.

## A8C15 physical boundary

A8C15 points to the existing immutable Master D:
**maximum 4, used 0, remaining 4**. This is not a new or multiplied budget.

D1 may spawn only after the final A8C15 freeze is COMPLETE and a fresh live preflight
binds the exact C plan, expected outputs, source/features, model/weights, runtime,
gfx1030 objects and result destinations.

Only a successful, fully received D1 may earn
GTA_GAME_DERIVED_SOURCE_NR_FRAME_A8C15 = PASS and the preserved
SOURCE.png / NR.png / DIFF.png result set.

D2 is optional and can only follow that preserved device result: one frozen-frame
diagnostic presentation in GTA with independent observation.

No unchanged retry. Any device removal/hang/reset, UINT64_MAX completion, Kernel
141/117, new WHEA, LiveKernelReport, bugcheck or unsafe guard corruption stops all
A8C15 physical work pending operator review. Plain hipMalloc remains required.

## Same-target structural falsifier

The active directive carries a non-authoritative Praschke cross-check:

~~~text
valid frame      1920 x 1080
padded/pre       1920 x 1152
import grid      8 x 1152
pre grid         240 x 144
post grid        240 x 135
export grid      8 x 1080
~~~

Only the valid-vs-padded invariant is portable. External launch counts, arena layout,
offsets and constants are not local authority. The real C plan must fail closed if
it swaps the 1080 valid and 1152 padded roles.

## Closed historical blockers

- **#82** — A8C11 Story Map(readback) blocker: historically real, superseded by the later authentic capture.
- **#80** — registered-static rc=98: historically real, explicitly non-prerequisite for A8C15.

Closing them does not invent a root cause; their historical evidence stays intact.

## Public documentation warning

The public repository is currently **mid-reconciliation**. README and STATUS are the
narrow live coordination surfaces.

These manifest-tracked pages still contain superseded A8C6 success language and must
be regenerated from canonical provenance under
[#70](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/70), not hand-edited
around the publication manifest:

- ROADMAP.md
- docs/current-state.md
- docs/project-overview.md
- docs/contribution-areas.md
- docs/hardware-testing-policy.md
- affected glossary/evidence pages
- CHANGELOG.md
- CITATION.cff

The A8C8 repair note already records why the old A8C6 “two matched GTA neural frames”
coordination story is not current proof. The A8C6 document remains a historical,
superseded snapshot.

Until #70 finishes canonical regeneration, use **README + STATUS + live issues** as
the current public coordination layer.

## Explicit non-claims

The project does **not yet claim**:

- an authentic GTA-derived gfx1030 neural device frame;
- NR.png from such a device result;
- visible frozen neural presentation inside GTA;
- realtime/native per-frame NR;
- consecutive frames or temporal correctness;
- shipping bridge completeness;
- NVIDIA-exact GTA fidelity;
- performance/playability.

## Live trackers

- [#84 — P0 Frame-C host truth/freeze → first GTA-derived device frame](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/84)
- [#70 — canonical/public current-state reconciliation](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/70)
- [#68 — sanitized current evidence publication](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/68)
- [#66 — temporal/history contract; physical warm work downstream](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/66)
- [#57 — external research registry](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/57)
- [#79 — protected-main owner-review governance](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/79)
- [#27 — fork-friendly CI/provenance split](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/27)
- [#42 — final squash-author identity/privacy](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/42)
