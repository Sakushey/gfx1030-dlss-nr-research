# Phase 16BO / A8C6 public coordination snapshot — superseded

> **SUPERSEDED PUBLIC COORDINATION SNAPSHOT**
>
> This page is retained for provenance because it records what the public
> coordination surface claimed on 2026-09-27. A later maintainer/local
> reconciliation did **not** find the corresponding implementation and receipts
> and therefore does not support the physical/GTA success claims below.
>
> Do not use this page as current project state. See
> [STATUS.md](../STATUS.md) and
> [the A8C8 state-repair note](phase16bo-a8c8-state-repair.md).
>
> The historical text below is intentionally preserved rather than silently
> rewritten.

Last synchronized: 2026-09-27

This page records the **current canonical project state after the successful A8C6 frame campaign**.

## Evidence/publication boundary

The private/canonical campaign state is ahead of the previously published development preview. This public repository does **not** redistribute proprietary model bytes, vendor runtimes, game assets, or private raw captures.

Accordingly, distinguish:

- **canonical project state** — the current maintainer/operator state used to direct development;
- **publicly reproducible evidence** — only what has been sanitized and published in this repository.

A8C6 is treated as successful for project coordination. Public raw receipts, frame captures, proprietary-input-derived artifacts, and machine-local identities remain outside the repository unless they can be published safely and lawfully. No missing public artifact should be silently replaced with an invented hash or synthetic receipt.

## Phase

```
PHASE = 16BO
STAGE = A8C6 COMPLETE
```

Do not create 16BP merely because the A8C6 campaign crossed the first-frame boundary.

## What changed

A8C6 completed the transition from host-only convergence to a correctness-first physical/game path.

The canonical state now records:

- REAL implementation admission is load-bearing on the production executor path;
- production execution refuses unadmitted REAL keys;
- the semantic/execution lifecycle distinguishes resolved-but-uncertified from unresolved;
- the 73rd graph weight is applied from the authenticated `block30.layer3.layer` view;
- graph weights are 73/73 applied, with no synthetic weight standing in for an authentic graph weight;
- the C1024 scale-first contract is active;
- ViT QKV uses an exact graph-visible record view rather than the entire coarse `t_w_31` aggregate;
- the current vendor-graph falsification lane is closed against the locally established graph;
- decoder skips use authenticated transition outputs 4/8/14/22 and are consumed 22/14/8/4;
- core TensorSpecs/addition semantics are sufficient for the authenticated core;
- `mean` is classified by dependency/control flow rather than mechanically blocking the core merely because it is a leaf node;
- core-required REAL bodies are certified;
- core execution contains zero placeholder nodes;
- an authentic connected host core frame completes;
- the conservative source execution plan and memory plan cover the core;
- selected gfx1030 objects pass identity/register/wave-size admission;
- the independent adversarial closeout passes.

## Physical campaign state

The successful A8C6 campaign is treated as having completed the following rungs:

```
START 0  environment sentinel                         PASS
START 1  optional mean microprobe                     not required unless separately recorded
START 2  representative family qualification          PASS
START 3  complete standalone gfx1030 core frame       PASS
         cold input A                                 PASS
         cold input B                                 PASS
START 4  GTA source capture + deterministic pattern   PASS
START 5  captured-frame offline neural replay         PASS
START 6  first matched GTA neural frame N             PASS
START 7  second independent matched GTA frame M       PASS
```

The two successful game-frame milestones are distinct-frame checks, not a warm temporal qualification.

## Highest canonical milestone

```
FIRST_PROJECT_OWNED_AUTHENTIC_GFX1030_CORE_FRAME = PASS
GTA_CAPTURE = PASS
CAPTURED_GTA_FRAME_OFFLINE_NEURAL = PASS
GTA_PATTERN_PATH = PASS
GTA_FRAME_N_MATCHED_NEURAL_PRESENTATION = PASS
GTA_FRAME_M_MATCHED_NEURAL_PRESENTATION = PASS
```

This is **not** a sustained-gameplay, temporal-stability, or performance claim.

## What remains deliberately unclaimed

- warm temporal sequence correctness;
- temporal stability across sustained gameplay;
- performance/playability;
- reduced-resolution or approximate profiles;
- multipass;
- frame generation;
- zero-copy D3D12/HIP sharing;
- `hipMallocAsync` qualification on gfx103x;
- TheRock migration;
- DirectML as the project's execution backend;
- optimized native E4M3/packed/fused paths.

The successful A8C6 path was correctness-first. Latency and FPS were intentionally irrelevant.

## Historical progression worth preserving

### Weight identity

Earlier host stages had graph weights represented with bogus/default extents and no complete graph→container identity.

That blocker is now historical:

```
old state:  graph weights unresolved / bogus default extents
A8C5:       73/73 factually resolved, 72/73 applied
A8C6:       73/73 applied
```

The final applied view is:

```
t_w_conv_res_views
→ block30.layer3.layer
→ [0, 263168)

262144 B = 512 x 512 E4M3
1024 B   = 512 x FP16 skip
```

The corresponding `t_w_30` remainder is 1,705,024 bytes. The previously circulated 1,704,024 value remains a negative control, not a valid state value.

### C1024 / ViT

The local answer was established by project evidence, not by importing an external implementation.

External projects were deliberately used as falsifiers because they disagreed:

- current OpenDLSS-NR / MLX-DLSS-style reconstruction evidence placed FP32 scale/auxiliary data before the QKV matrix;
- lmxxf carried an alternative ordering during its investigation;
- other independent source work converged on the exact 3,145,856-byte record extent.

That disagreement was useful precisely because it forced the project to derive:
- exact matrix start;
- scale/auxiliary location;
- logical orientation;
- Q/K/V ordering;
- packing;
- consumer addressing

from local evidence.

### Mean

`mean` is a Rec.709 luminance-mean reduction with a 32-bit float output store. A8C6 does not keep it falsely classified as an unresolved one-byte neural activation.

Milestone membership is dependency-based:
- a core ancestor blocks the core;
- an auxiliary/live-game leaf does not become a fake core blocker merely to preserve an old node count.

## Next phase of work — still Phase 16BO

The first-frame boundary is crossed. The next work should be evidence-driven and separated into:

1. publish the current lawful A8C6 source subset and integrate approved frozen contributor work (#70);
2. publish/sanitize the A8C6 evidence package where lawful (#68);
3. independent reproduction on another RDNA2 device where useful;
4. warm temporal/history qualification (#66);
5. direct D3D12/HIP zero-copy qualification as an optimization, not a correctness prerequisite;
6. sustained gameplay;
7. only then performance work such as E4M3 splicing, packed FP16/dot2add, wave-owned fusion, reduced-resolution or async profiles.

See the live GitHub issues for the current split.
