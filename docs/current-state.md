# Current State

**Phase 16BO / A8C6 complete.**

This page describes the current canonical project state after the successful A8C6
correctness-first frame campaign. If a sentence here could be read as a stronger
claim than the evidence supports, use the narrower reading.

The canonical/private campaign state is ahead of the old development-preview
publication. Raw private receipts, proprietary-input-derived artifacts, machine-local
identities and captures are not automatically public. The repository must never
invent or synthesize a public receipt to fill that publication gap.

See [phase16bo-a8c6-state.md](phase16bo-a8c6-state.md).

## Current status table

| Area | Status | Current interpretation |
| --- | --- | --- |
| gfx1030 ISA / code-object research | active | Maintained selected objects pass current identity/register/wave-size admission; experimental/historical objects remain separately scoped |
| Host semantic emulator / oracles | mature experimental | Used as authenticated host/reference layer with negative controls |
| REAL implementation admission | closed for core | Production resolution is certificate-gated; missing admission refuses |
| Graph weights | **73/73 applied** | No synthetic graph weight substitutes for an authentic core weight |
| C1024 / ViT | active and closed for current core | Scale-first contract active; exact QKV view/packing used |
| Decoder skips | authenticated | Transition outputs 4/8/14/22, consumed 22/14/8/4 |
| Core placeholders | **0** | Core-required execution uses certified REAL bodies |
| Authentic host core frame | **PASS** | Connected source/reference frame completes |
| Representative gfx1030 families | **PASS** | A8C6 START 2 |
| Complete standalone gfx1030 core frame | **PASS** | A8C6 START 3 with two different cold inputs |
| GTA source capture | **PASS** | Immediate owned source capture and frame identity |
| Captured-frame offline neural replay | **PASS** | A8C6 START 5 |
| Presented GTA neural frame | **PASS** | A8C6 START 6 |
| Second different matched GTA frame | **PASS** | A8C6 START 7 stale/hard-code control |
| Warm temporal correctness | not qualified | next major correctness milestone |
| Sustained gameplay | not qualified | later |
| Performance/playability | not qualified | deliberately deferred |
| Direct zero-copy D3D12/HIP | not qualified | correctness path used explicit CPU staging |
| gfx103x `hipMallocAsync` | not qualified | plain allocation remains first-line policy |

## What the successful A8C6 path established

### 1. State model and REAL admission

The project no longer overloads “unresolved” to mean every kind of missing
execution state.

The current model distinguishes semantic resolution from execution certification:

```
semantic_state:
    UNRESOLVED | RESOLVED

execution_state:
    UNCERTIFIED | CERTIFIED_REAL | NONE_BY_DESIGN | REFUSED
```

A semantically resolved family is not relabelled unresolved merely because its REAL
certificate has not been generated yet.

For the successful core path:
- required semantics are resolved;
- required REAL bodies are certified;
- production execution does not silently fall back to an unadmitted raw body;
- post-registration body replacement is a refusal condition.

Python closure introspection is not treated as a security boundary. The required
property is structural: the production executor cannot select the raw adapter without
authenticated resolution.

### 2. Weight identity

An earlier project state had an incomplete graph→container mapping and invalid/default
weight extents. That state is historical.

The progression is:

```
early state: graph weight identity incomplete
A8C5:       73/73 factually resolved, 72/73 applied
A8C6:       73/73 applied
```

The final graph-visible C512 view is:

```
t_w_conv_res_views
→ block30.layer3.layer
→ [0, 263168)

262144 B  = 512 x 512 E4M3 matrix
1024 B    = 512 x FP16 skip
```

After extracting that record, the correct remaining `t_w_30` extent is
**1,705,024 bytes**.

The old **1,704,024** value is retained only as a known-bad control.

Historical model manifests remain historical. The active maintained model state is
not permitted to mutate a closed predecessor-stage manifest.

### 3. C1024 / ViT QKV

The current core uses an exact graph-visible QKV record/view rather than binding
`vit_qkv` to the full coarse `t_w_31` aggregate.

External projects were deliberately useful because they disagreed on ordering:
that disagreement was treated as a falsifier, not as an answer.

Local evidence established:
- scale/auxiliary region;
- matrix start;
- logical orientation;
- Q/K/V ordering;
- packing;
- consumer addressing.

The exact record extent under the current contract is 3,145,856 bytes.

### 4. Vendor-graph falsification

The graph was challenged against independent contemporary reconstructions before
spending a full-network physical start.

Important questions included:
- E4M3 publication before GEMM;
- raw-vs-published residual splits;
- C32 publication topology;
- block30 raw-pool boundary;
- C512 / ViT FFN publication;
- dedicated ViT attention arithmetic;
- decoder-transition skip identity.

Local evidence remained authoritative.

### 5. Mean is no longer a fake core blocker

The `mean` node is classified as a Rec.709 luminance-mean reduction with a 32-bit
float output store.

Milestone membership is based on dependency and side-effect analysis.

A leaf with no effect on the frame-producing core does not block
`NEURAL_CORE_EXECUTION_READY` merely because an old node table counted it among all
jobs. It remains tracked where required for game/live integration.

### 6. Boundary types and milestone-specific readiness

The project now keeps separate gates for:

```
NEURAL_CORE_SEMANTICS_READY
NEURAL_CORE_HOST_READY
NEURAL_CORE_DEVICE_READY
LIVE_GAME_INPUT_READY
GAME_COMPOSITION_READY
```

This prevents a game-boundary uncertainty from blocking an internal source-backend
test and also prevents a project-owned source API type from being mislabeled as an
authenticated vendor/game boundary type.

Formal historical M0 remains governed by its original project definition rather than
being edited to fit a desired result.

## Physical campaign result

The successful A8C6 campaign used bounded, serialized GPU work.

### START 0 — environment sentinel

PASS.

The purpose was to prove the actual under-load environment:
- pinned runtime identity;
- expected gfx1030 adapter;
- tiny allocation/H2D/D2H;
- one tiny known-clean completion kernel;
- guards/sentinels;
- device health;
- WHEA baseline.

This start was intentionally allowed before full semantic closure because it did not
exercise the neural graph.

### START 2 — representative family qualification

PASS.

The selected set covered materially different maintained GPU implementations rather
than running all 94 graph nodes independently.

Where wave32 semantics were required, actual object metadata had to satisfy the
wave-size contract; `gfx1030` alone was not treated as proof of wave size.

### START 3 — complete standalone core frame

PASS.

Execution policy:
- one HIP stream;
- plain `hipMalloc`;
- separate allocations;
- no activation reuse;
- node-by-node launch;
- explicit synchronization;
- no HIP graph;
- no async memory pool.

Two different deterministic cold inputs completed in one healthy session.

That A/B control establishes:
- not stale output;
- not constant output;
- not a single hard-coded frame.

It does **not** establish warm temporal behavior.

### START 4 — GTA capture and presentation-pattern path

PASS.

The game source was copied to owned D3D12 memory immediately. The path did not rely on
later access to a transient/aliased game resource.

Frame identity is non-null and mismatches refuse.

### START 5 — captured-frame offline replay

PASS.

The exact captured source was replayed through:
- canonical staging;
- authenticated feature construction;
- HIP core;
- readback;
- authenticated output/composition.

This separated game-input semantics from live presentation/injection.

### START 6 — first matched GTA neural frame

PASS.

The correctness-first transport was:

```
D3D12 source N
→ CPU
→ HIP
→ CPU
→ D3D12 result
```

Latency was irrelevant. The result remained tied to the exact source FrameIdentity.

### START 7 — second independent matched GTA frame

PASS.

A materially different game frame M was captured and processed independently.

The N/M pair requires:
- distinct source identities;
- distinct feature identities;
- result N belongs to N;
- result M belongs to M;
- cross-frame substitution refuses.

This rules out the most basic stale/cached/hard-coded success explanation.

## What is not established

### Warm temporal behavior

The successful A8C6 campaign is deliberately a cold/correctness campaign.

It does not establish:
- history-valid multi-frame state;
- motion/reprojection correctness across sustained frames;
- scene-change behavior;
- temporal stability;
- cadence/reuse strategies.

### Performance

External same-target work has shown much faster translated execution and several
cross-target projects report additional kernel optimizations.

None of those numbers is a project performance claim.

The first project-owned frame did not need to be fast.

### Direct D3D12/HIP zero-copy

The successful path used CPU staging.

Direct shared-resource/fence interop remains an optional later engineering path. It
must not be retroactively described as required for the first-frame result.

### Async allocation

Same-target external evidence remains sufficient to keep
`hipMallocAsync` disallowed by default for gfx103x physical qualification until it
is independently proven safe.

## Historical watchdog work

The Candidate-F/J3 watchdog-localization track remains part of project history and
must not be erased.

But it is no longer the live statement of where the project is stuck.

The successful A8C6 selected package and source-level network path supersede that
historical blocker for current development.

## Current engineering priorities

1. Sanitize/publish the A8C6 evidence package without exposing proprietary inputs or
   private machine details.
2. Qualify authentic warm temporal/history execution.
3. Preserve exact FrameIdentity through longer sequences.
4. Test sustained gameplay/resource lifetime.
5. Independently reproduce the successful path on another RDNA2 device where useful.
6. Qualify direct/zero-copy interoperability only if it improves engineering value.
7. Begin performance optimization only with exact faithful controls retained.

## Safety rules remain unchanged

A successful campaign does not relax the hardware policy.

Still prohibited without a new explicit authorization:
- blind retries;
- TDR/watchdog changes;
- clocks/voltage/power changes;
- runtime/driver switching as a convenience;
- forced process kills;
- forced GPU reset;
- automatic stress loops.

Every future physical result remains scoped to the exact runtime/device/object/path
that earned it.
