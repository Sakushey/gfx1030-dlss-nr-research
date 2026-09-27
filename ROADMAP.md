# Roadmap

Milestones map onto the proof ladder in
[docs/proof-model.md](docs/proof-model.md). A milestone is complete only when its
claim is established with meaningful positive and negative controls.

Current canonical position: **first matched GTA neural frames achieved in Phase 16BO / A8C6; temporal/sustained/performance work remains.**

| Milestone | Rung | State |
| --- | --- | --- |
| **M0** Host semantic / reference closure | 1–2 | core closure achieved; historical broader M0 clauses remain governed by their own definitions |
| **M1** Physical one-workgroup completion | 3 | **complete / superseded by stronger A8C6 physical results** |
| **M2** Representative family qualification | 3 | **complete for the A8C6 selected package** |
| **M3** Multi-workgroup / authentic core dispatch | 4–5 | **complete for the A8C6 cold core** |
| **M4** Complete neural core job | 6 | **complete for the authenticated cold core** |
| **M5** D3D12/HIP correctness transport | 7 | **complete via explicit CPU staging; zero-copy direct interop not qualified** |
| **M6** First presented neural-rendered frame | 8 | **complete — two different matched GTA frames in A8C6** |
| **M7** Temporal multi-frame stability | 9 | next major correctness milestone |
| **M8** Sustained gameplay | 10 | not qualified |
| **M9** Performance optimization | 11 | now reachable, but still downstream of temporal correctness |

See [docs/phase16bo-a8c6-state.md](docs/phase16bo-a8c6-state.md) for the A8C6 state
summary and the distinction between canonical state and public evidence publication.

---

## M0 — Host semantic / reference closure

The core now has the semantic/execution state needed for the successful A8C6 path:

- 73/73 graph weights applied;
- C1024 active;
- exact ViT QKV record/view/packing established;
- decoder-transition skips authenticated;
- core TensorSpecs/addition semantics sufficient;
- core REAL bodies certified;
- zero core placeholder nodes;
- authentic connected host core frame completes.

Formal historical M0 remains whatever the project's older definition actually
requires. Do not edit that definition retroactively simply to make a label green.

## M1 — Physical one-workgroup completion

This milestone is no longer the current blocker. The A8C6 campaign progressed beyond
a single bounded workgroup to representative-family qualification and a complete
standalone core frame.

The old Candidate-F/J3 watchdog-localization track remains historical evidence, not
the live critical path.

## M2 — Representative family qualification

A8C6 START 2 qualified the materially distinct maintained GPU body families selected
for the campaign under object/register/wave-size admission.

This does not imply that every historical or experimental object is qualified.

## M3 — Multi-workgroup / authentic core dispatch

The complete A8C6 source/core path executed under the conservative policy:

- one HIP stream;
- plain allocation;
- separate allocations;
- no activation reuse;
- node-by-node launch;
- explicit synchronization;
- no HIP graph;
- no async pool.

## M4 — Complete neural core job

A8C6 START 3 completed the standalone project-owned gfx1030 core for two materially
different deterministic cold inputs.

The A/B control is important: it demonstrates that the successful result was not
merely a constant, stale or hard-coded frame.

Warm temporal/history behavior is a different milestone.

## M5 — D3D12/HIP transport

The first correctness path deliberately did **not** require zero-copy interoperability.

The successful architecture is:

```
D3D12 owned source
→ CPU staging
→ HIP core
→ CPU readback
→ D3D12 result
```

This is enough for the first-frame correctness milestone. Shared-resource/fence
zero-copy remains a separate optimization/engineering qualification.

## M6 — First presented neural-rendered frame

A8C6 crossed this milestone twice:

- frame **N**: captured source and matching neural presentation;
- frame **M**: a second different source and matching neural presentation.

The second frame is a stale/cached/hard-coded negative control. It is not a warm
temporal sequence.

## M7 — Warm temporal correctness

**Next major correctness milestone.**

Done means a real multi-frame sequence demonstrates:

- correct carried history/state identity;
- correct motion/reprojection inputs where required;
- scene/reset semantics;
- no frame-ID cross-association;
- no stale history reuse;
- stable output over a meaningful sequence;
- explicit reset vs history-valid controls.

Do not use multipass wrapper feedback as a substitute for the network's authentic
temporal contract.

## M8 — Sustained gameplay

Done means the correctness path survives sustained interaction without:

- device loss;
- WHEA/DRED anomalies;
- frame/resource identity drift;
- stale output;
- uncontrolled memory growth;
- resource-lifetime errors.

A slow correctness path can reach M8; FPS is not itself the milestone.

## M9 — Performance

Only now does optimization become legitimate project work.

Candidate families include:

- Praschke-style native E4M3 representation splicing;
- wave/window fusion;
- packed FP16 / dot2add candidates;
- reduced-resolution or approximate profiles;
- async one-frame-late execution;
- zero-copy D3D12/HIP;
- allocation/memory reuse;
- persistent/fused kernels.

Every optimization must preserve an exact/faithful control and remain independently
toggleable and benchmarkable. Cross-target speedups never transfer automatically to
gfx1030.

---

## Non-goals

- Redistributing proprietary model weights, game assets, vendor runtimes, or private captures.
- Modifying clocks, voltage, power limits, firmware, BIOS, registry, drivers, watchdog or TDR.
- Using online/anti-cheat-protected game modes for integration testing.
- Turning external benchmark numbers into local performance claims.
- Rewriting historical evidence to make the current state look cleaner.
