# Contribution Areas

This page lists where help is useful **after the Phase 16BO / A8C6 first-frame
milestone**.

Before contributing, read:
- [current state](current-state.md);
- [A8C6 state](phase16bo-a8c6-state.md);
- [evidence and reproducibility](evidence-and-reproducibility.md);
- [hardware testing policy](hardware-testing-policy.md).

The project has crossed the first cold-frame/presentation boundary. That changes the
highest-value work: the priority is no longer proving that *some* gfx1030 kernel can
finish. It is now preserving the faithful core, independently reproducing it, closing
warm temporal behavior, hardening game/resource lifetime, and only then optimizing.

## High-value host-only work

### Independent semantic audit

Useful targets:
- compare current publication boundaries against independent MIT/Apache references;
- audit raw-vs-E4M3 paths into every GEMM;
- audit residual paths separately from GEMM inputs;
- test block30 raw-pool vs published-pool behavior;
- audit C512/ViT FFN publication;
- audit vendor-specific ViT attention arithmetic;
- maintain bit-distinguishing negative controls.

External projects are falsifiers. Local evidence remains authority.

### REAL certificate / registry integrity

Even though the current core is admitted, this remains a high-value regression area.

Add adversarial controls for:
- post-registration body swap;
- missing-admission production lookup;
- stale declared dependency;
- same-extent wrong shape;
- wrong weight view;
- zero/partial write;
- immutable-weight mutation.

A host verifier that has never rejected a known-bad case is not evidence.

### TensorSpec / graph authority

Keep the active logical tensor model generated from one canonical semantic source.

Useful contributions:
- prove an alias/view identity explicitly;
- add a same-byte-extent/wrong-logical-shape negative;
- audit project source API types separately from vendor/game boundary types;
- improve graph-digest dependency precision;
- add boundary documentation for core vs live-game tensors.

### Model-layout / weight provenance

Do not publish proprietary weight bytes.

Useful work:
- validate graph-visible record extents and subranges;
- independently derive Q/K/V order and packing;
- compare model-version structure using public metadata;
- add checks that historical manifests are immutable and active manifests are
  generation-bound.

### ISA / code-object safety

Current device work depends on object identity and wave-size correctness.

Useful work:
- extend VGPR/SGPR/static admission checks;
- audit wave32 assumptions;
- add deliberately wrong-wave metadata fixtures;
- audit scratch/LDS bounds;
- verify no selected implementation relies on inter-workgroup spin protocols;
- extend fail-closed handling for unsupported instructions.

### Reproducibility / publication

The current canonical state is ahead of the old public proof package.

High-value tasks:
- sanitize A8C6 receipts without leaking private machine paths or proprietary data;
- publish reproducible host fixtures for the exact semantic properties;
- bind public claims to source/object/runtime identities where publishable;
- make current-state generation reject stale publication inputs;
- keep predecessor evidence byte-exact.

## Physical work requiring explicit authorization

A successful A8C6 run does **not** create permanent authorization for arbitrary GPU
work.

Every future physical run remains bounded, serialized and evidence-producing.

### Independent RDNA2 reproduction

High value:
- reproduce the selected source/core path on another gfx1030 device;
- reproduce relevant source-built primitives on gfx1031/gfx1032;
- record exact runtime/device/object identity;
- keep architecture/SKU evidence separate.

Do not run a gfx1030 binary on gfx1031/32. Recompile for the target.

### Warm temporal/history qualification

This is the next major correctness frontier.

Useful experiments:
- reset frame vs history-valid frame;
- exact history-buffer identity;
- motion/reprojection sign/scale/space;
- scene-cut/reset behavior;
- stale-history rejection;
- two-frame then longer bounded sequences;
- frame identity carried through every result.

A cold two-frame A/B success is **not** temporal qualification.

### Game resource lifetime

The first-frame work established the importance of immediate source ownership.

Useful work:
- prove capture occurs before transient/aliased resources can be reused;
- verify every captured resource stays alive through GPU completion;
- add deliberate stale-resource negative controls;
- audit depth/stencil vs colour resource classification;
- preserve source/result FrameIdentity.

### D3D12/HIP direct interop

The correctness milestone already works with CPU staging.

Direct shared-resource/fence interop is therefore optional engineering work, not a
proof prerequisite.

Useful targets:
- same-adapter identity;
- shared allocation lifetime;
- fence/semaphore ordering;
- process-lifetime memory plateau;
- fallback to staging when unsupported.

### Sustained gameplay

After warm temporal correctness:
- repeated frame identity;
- memory plateau;
- no device loss;
- no WHEA/DRED anomalies;
- no stale/cached output;
- no resource aliasing regression.

## Performance work — now reachable, still evidence-bound

Performance was intentionally irrelevant until the first-frame boundary.

Candidate lanes now include:
- Praschke-style E4M3 representation splicing;
- source-level wave/window fusion;
- packed FP16 / dot2add;
- vectorized packing;
- reduced-resolution profiles;
- one-frame-late async execution;
- direct zero-copy transport;
- allocation/reuse optimization.

Rules:
1. keep a faithful synchronous control;
2. make every optimization independently toggleable;
3. verify exactness before timing;
4. benchmark ABBA or equivalent;
5. report actual gfx1030 measurements;
6. never transfer gfx11/gfx12 speedups as gfx1030 expectations.

## What remains prohibited

- automatic retries after device failure;
- TDR/watchdog modification;
- clocks/voltage/power changes;
- forced GPU reset;
- runtime/driver switching for convenience;
- online/anti-cheat-protected game testing;
- proprietary weight/runtime redistribution;
- rewriting historical evidence to match current source.

## How to propose new work

Open an issue or discussion with:
- target milestone;
- evidence level;
- exact subject/source identity;
- success condition;
- failure condition;
- whether GPU access is required;
- licensing/provenance constraints.

A bounded task with a falsifier is much easier to review than an open-ended
“optimization” or “compatibility” change.
