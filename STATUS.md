# Status

Authoritative public **coordination** state of the project. If this file
disagrees with another high-level public status document, this file wins for
current milestone wording. Public reproducibility may lag the maintainer-local
report; #70/#68 track that publication boundary.

Last reviewed: 2026-10-01

---

## One-line summary

**Phase 16BO / A8C10 remains in progress. SOURCE_CANONICAL now passes two
complete host fixtures and two complete physical gfx1030 device fixtures; the
GTA/shipping path is blocked by `hipLaunchKernel` error 98, and no GTA neural
frame has been captured or presented.**

The earlier A8C6 first-frame/GTA claims remain superseded. A8C10 does not restore
them: its physical successes are explicitly **device fixtures, not GTA frames**.

## Latest maintainer-local measured boundary

```text
phase                              16BO / A8C10
native/recovered backend           NOT_READY
SOURCE_CANONICAL gate              ARMED 25/25, 186 comparisons
Host A / Host B                    71/71 blocks each
mutation discriminability          27/27 required mutants REJECTED
independent audit                  27/27 attacks reached + REJECTED
gfx1030 device fixture 320         PASS
gfx1030 device fixture 512         PASS (682/682 receipts; 1,006 comparisons)
GTA capture                        NOT REACHED
GTA neural presentation            NOT REACHED
consecutive frames                 0
shipping-path hipLaunchKernel      error 98 on every measured START9/10 attempt
physical masters                   3/3 CANCELLED_SECTION36
```

A8C10 also closes the A8C9 block-31 operand-domain defect and adds six explicit
operand-domain rows to the source gate.

## Backend split

### NATIVE_RECOVERED_BACKEND

The historical translated/native-layout recovery track remains fail-closed and
is still `NOT_READY`. SOURCE_CANONICAL success must never be relabeled as
native NVIDIA-kernel/layout parity.

### SOURCE_CANONICAL_BACKEND

The source-canonical correctness path has crossed the host and standalone-device
milestones:

- two materially different host frames complete all 71 logical blocks;
- the live source gate is ARMED 25/25;
- semantic mutants and independent attacks are all rejected at their required
  observers;
- two complete gfx1030 device fixtures pass.

The current proof ceiling is therefore **SOURCE_GFX1030_DEVICE_FIXTURE**, not
`PRESENTED_FRAME`.

Publication of the maintained implementation/evidence is tracked in #70/#68.
Until that lands, these are maintainer-local coordination facts rather than a
claim that every result is already independently reproducible from current
`main`.

## Current P0 — #80

The active blocker is
[#80](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/80).

The shipping bridge/game path has not observed a successful
`hipLaunchKernel`:

- START9: 2,879 / 2,879 attempts returned 98;
- START10: 2,719 / 2,719 attempts returned 98;
- kernel registration / host-function matching is measured healthy;
- other instrumented HIP APIs return success;
- `hipModule*` code-object load state is **CANNOT_SEE** because it is not yet
  instrumented.

Error 98 is `hipErrorInvalidDeviceFunction`. Before another GTA neural
campaign, the module/code-object/function path must be made observable and at
least one relevant bounded shipping-bridge launch must succeed.

## GTA / hard-stop boundary

Three A8C10 GTA starts on 2026-10-01 fired the project's §36 hard-stop rule.
Every corresponding master authorization is permanently cancelled. A future
physical campaign requires a **fresh operator ask and a new master id**.

The current crash attribution remains intentionally incomplete:

- the old default-deny launch door is excluded after its host-side fix;
- START10 excludes capture-hook interaction because no injection occurred;
- the measured launch-98 -> unfinished-job -> timeout/FAULT chain remains a
  candidate;
- a chronic same-bucket Kernel_141 host/driver pattern predating the campaign
  remains another candidate.

§36 fires on presence, not on proven causation.

## Temporal boundary

The temporal host contract remains useful, but physical warm/consecutive
qualification is barred until #80 produces **two correctly paired and presented
cold GTA SOURCE_CANONICAL frames**. See #66.

## Immediate work

1. **#80:** instrument `hipModule*` / code-object loading and isolate error 98.
2. Prove at least one relevant bounded shipping-bridge kernel launch succeeds
   before another neural GTA attempt.
3. Continue host-side Kernel_141 attribution without weakening §36.
4. **#70:** publish the actual maintained A8C10 source/integration state safely.
5. **#68:** publish the largest lawful sanitized gate/mutation/audit/device-fixture
   evidence subset.
6. Only after a fresh operator authorization: arm capture at the menu before
   Story Mode, then attempt the first cold GTA SOURCE_CANONICAL frame.
7. Require a second materially different cold GTA frame before #66 warm work.
8. Keep optimization/reuse/async/zero-copy outside the critical path.

## Publication / reproducibility boundary

Never publish or reconstruct:

- proprietary model weights/private tensors;
- vendor runtime binaries or extracted proprietary code objects;
- game binaries/assets/raw private captures;
- personal/machine paths;
- credentials/provider config;
- raw session prompts;
- unsanitized crash dumps;
- invented receipts/hashes.

Historical A8C6/A8C8 records remain preserved as historical records.

## Explicit non-claims

The project does **not** currently claim:

- complete native recovered execution;
- native NVIDIA-kernel/layout parity;
- a GTA V Enhanced neural capture or presented frame;
- warm temporal device correctness;
- consecutive neural gameplay;
- sustained gameplay;
- playable or real-time performance;
- direct zero-copy D3D12/HIP qualification;
- `hipMallocAsync` safety;
- frame generation or multipass qualification;
- HDR qualification.

## Live trackers

- [#80 — P0 runtime/GTA launch blocker](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/80)
- [#70 — publish maintained A8C10 implementation/current state](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/70)
- [#68 — publish sanitized A8C10 evidence](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/68)
- [#66 — temporal host contract / warm qualification](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/66)
- [#57 — external research registry](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/57)
- [#29 — independent whole-job/launch-contract cross-validation](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/29)
