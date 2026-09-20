# Roadmap

Milestones map one-to-one onto the proof ladder in
[docs/proof-model.md](docs/proof-model.md). A milestone is complete only
when its rung is established **with a negative control that fails
correctly**.

Current position: **between M0 and M1.**

| Milestone | Rung | State |
| --- | --- | --- |
| **M0** Host semantic / reference closure | 1–2 | partial — substantial coverage, not closed |
| **M1** Physical one-workgroup completion | 3 | **in progress — current blocker** |
| **M2** Representative variant / T32 physical qualification | 3 | not started |
| **M3** Multi-workgroup / authentic dispatch | 4–5 | not started |
| **M4** Complete neural job | 6 | not started |
| **M5** D3D12 / HIP interop | 7 | not started |
| **M6** First presented neural-rendered frame | 8 | not started |
| **M7** Temporal multi-frame stability | 9 | not started |
| **M8** Sustained gameplay | 10 | not started |
| **M9** Performance optimization | 11 | not started |

---

## M0 — Host semantic / reference closure

**Done means:** every instruction form the workload actually executes is
covered by the emulator, and the independent oracle agrees with the
emulator on a per-record basis — with at least one negative control that
demonstrably fails when the emulator is perturbed.

**Why it is not closed:** coverage is measured, not assumed, and the
dynamically executed instruction set is still being enumerated. A form
that is never executed does not need coverage; a form that is executed
but unclassified is a live risk.

## M1 — Physical one-workgroup completion

**Done means:** a single workgroup on gfx1030 runs to completion, the
result is read back from device memory, and the value is checked against a
host-computed expectation. No watchdog reset occurs.

**Why it is blocked:** the kernel launches but does not complete before
the watchdog recovers the engine. Host-side descriptor, argument,
address-layout, barrier, and waitcnt checks pass on the modeled path, so
simple host-configuration mistakes in those areas are no longer the
leading explanation. That does not rule out hardware-specific
synchronization or model-fidelity defects.

The latest checkpoint diagnostic (B2) also recovered through the
watchdog, narrowing the first physical failure to the first 3,547 modeled
per-wave steps — about 25.9% of the full J3 dispatch. This is a
localization result, not a root cause.

**Approach:** bounded checkpoint diagnostics. Each experiment answers one
question, is authorized explicitly, and produces raw evidence that is
preserved.

## M2 — Representative variant / T32 physical qualification

**Done means:** at least one additional workload variant and the T32 model
reach rung 3 under the same discipline.

## M3 — Multi-workgroup / authentic dispatch

**Done means:** the geometry the real workload uses runs, not a synthetic
one-workgroup stand-in. This is where synchronization hypotheses that a
single workgroup cannot exercise get tested.

## M4 — Complete neural job

**Done means:** a whole neural job executes, with buffer dependencies
resolved, and produces numbers comparable to a reference.

## M5 — D3D12 / HIP interop

**Done means:** the interop requirements are mapped *and demonstrated* —
device selection, shared resources, and synchronization across the
D3D12/HIP boundary.

## M6 — First presented neural-rendered frame

**Done means:** a frame produced by the neural path is presented. This is
the first milestone anyone outside the project would recognize as
"it works".

## M7–M9

Temporal stability across frames, sustained interaction, and performance
work. Nothing here should be discussed as reachable until M6 lands.

---

## Non-goals

- Redistributing any proprietary artifact, game asset, or runtime binary.
- Modifying clocks, voltage, power limits, firmware, BIOS, registry, or
  drivers to make an experiment "work".
- Disabling or extending the GPU watchdog.
- Anti-cheat circumvention in any form.
