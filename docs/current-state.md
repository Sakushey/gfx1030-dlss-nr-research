# Current State

**Status: active research.** This page describes where the project actually stands.
It is written to be read as a limits statement first and a progress statement second.
If a sentence here could be read as a stronger claim than the evidence supports, treat
the weaker reading as the intended one.

Nothing in this project constitutes a compatibility claim, a performance claim, or a
statement that any particular game, mod, or workload works on `gfx1030`.

## Status table

| Area | Status | Evidence level | Notes |
| --- | --- | --- | --- |
| `gfx1030` ISA / code-object research | Active development | `HOST_STATIC` | Decode, rebuild, and memory-model gates exist; coverage tracks the traced workload, not the whole ISA. |
| Host semantic emulator / oracles | Advanced experimental | `HOST_VALIDATED`, `HOST_INDEPENDENT_ORACLE` | Per-instruction records and an independently written scalar oracle; validated against each other on bounded cases. |
| J3 host oracle | Available | `HOST_INDEPENDENT_ORACLE` | Runs host-only; no GPU needed. |
| J3 physical execution | Kernel launches; liveness failure under investigation | `PHYSICAL_DIAGNOSTIC` | Reaches the physical HIP runtime; does not complete before the watchdog recovers the engine. |
| T32 host model | Experimental | `HOST_STATIC` | An experimental host-side model; not qualified, not a basis for a physical claim. |
| Complete neural job | Not qualified | `PROPOSED` | No complete neural job has been assembled and validated. |
| D3D12/HIP interop | Not demonstrated | `PROPOSED` | Requirements are mapped only at the level of an open question; see [issue #7](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/7). |
| Presented frame | Not demonstrated | `PROPOSED` | No frame has been produced, let alone presented. |
| Performance / gameplay | Not applicable yet | — | Out of scope until far later rungs; no numbers should be inferred from anything here. |

Evidence levels are defined in
[evidence and reproducibility](evidence-and-reproducibility.md) and
[glossary](glossary.md). A claim is classified at the **highest level actually
established**, not the highest level attempted.

## The current physical problem

This is the project's live blocker and the focus of current work.

### What happens

A correctly parameterized one-workgroup translation of the workload reaches the
physical HIP runtime. It **launches** — the runtime accepts the dispatch — but the
kernel does not complete. The Windows GPU watchdog eventually fires and recovers the
engine. After that recovery, the synchronization call on the host side returns
without an error, and that return value is **not** kernel output and **not** evidence
of success.

### What has been narrowed

Host-side validation has ruled out a large class of simple host-configuration
mistakes. The following have been checked on the modeled path and are not, at this
point, the leading explanation:

- **Descriptor layout** — argument/descriptor placement and packing have been
  validated against the expected entry contract.
- **Barrier placement** — barrier sites and their ordering relative to the analyzed
  control flow have been validated.
- **`waitcnt` placement** — counter-wait placement relative to the memory operations
  it is meant to cover has been validated.
- **Argument layout** — kernarg layout has been validated against the expected ABI
  shape for this code object.
- **Address layout** — the address-space layout of the buffers the workload touches
  has been validated.

The remaining problem is therefore being treated as **physical kernel liveness**.
These host-side checks do not prove that every hardware-specific synchronization,
initialization, scheduling, or model-fidelity hypothesis is impossible.

A midpoint post-barrier diagnostic has now also triggered watchdog recovery. That
narrows the first physical failure to the **first ~55.6% of the modeled
one-workgroup execution**. It is a localization result, not a root-cause result.

### How the problem is being approached

Work focuses on **bounded checkpoint diagnostics** rather than blind retries:

- One bounded physical experiment per authorization; no automatic retries.
- Checkpoints placed so that partial progress is observable rather than only a final
  result.
- Raw evidence preserved as produced; driver-reset output is recorded but never
  treated as kernel output.
- Each diagnostic is designed to be able to fail, and is tested against a known-bad
  case before its "clean" result is believed. See
  [evidence and reproducibility](evidence-and-reproducibility.md).

Live tasks that bear on this problem include
[physical liveness #2](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/2),
[independent ISA review #3](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/3),
and [ROCm post-watchdog semantics #4](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/4).

## Hardware safety policy

The physical path is deliberately constrained. In summary:

- **Bounded, one-shot physical experiments.** No loops intended to grind toward
  success, and no automatic retries.
- **No watchdog/TDR modification.** Tests must never be run with modified watchdog or
  TDR settings.
- **No clock, voltage, or power tricks.** No firmware, BIOS, registry, or driver
  changes.
- **Preflight first.** A physical run is preceded by checks that the environment is
  what it is expected to be.
- **Preserve raw evidence.** Outputs are kept as produced.
- **Driver-reset output is not kernel output.** A recovery message is a report about
  the host, not about the kernel.
- **Host evidence is not physical qualification.** A host-valid result says nothing
  about the device.
- **Physical tests only when explicitly authorized.** The physical path is not
  something to "just try".

The full policy, including what a contributor may and may not do, is in
[hardware testing policy](hardware-testing-policy.md).

## Host-valid does not mean hardware-valid

This distinction is the single most important thing to take away from this page.

A host-side result — whether from the emulator or from the independent oracle — is a
statement about a **model** of `gfx1030` semantics as encoded in host software. It is
not a statement about silicon. Between the two stand at least:

- **The model's fidelity.** The emulator implements the instruction forms the traced
  workload executes. Unsupported or untraced forms are a coverage gap, and a coverage
  gap is not a correctness result.
- **The entry contract.** How arguments, descriptors, and addresses are presented to
  the device at launch is a separate question from what the instructions mean.
- **The runtime.** The HIP runtime's handling of the dispatch, and its behavior after
  an abnormal condition, is a separate question again — see
  [issue #4](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/4).
- **The device.** Scheduling, wave occupancy, memory-system behavior, and interaction
  with the watchdog are properties of the hardware and the platform, not of the
  model.
- **Liveness.** Even a semantically perfect description of what the kernel should
  compute does not establish that the kernel actually runs to completion. That is
  precisely the gap this project is currently sitting in.

Consequently the project maintains the strict separation in the proof ladder:
rungs 1–2 are host rungs, and reaching them says nothing about rung 3. Any
documentation, issue, or commit message in this repository that appears to blur that
line should be treated as a bug in the documentation, not as a stronger claim.

## What is explicitly not claimed

- No end-to-end DLSS-NR game frame has been demonstrated.
- No D3D12/HIP interoperability has been demonstrated.
- No temporal stability, no sustained gameplay, and no performance result exists.
- The T32 host model is experimental and is not a qualification of anything.
- The physical path reaches the runtime but has not completed a single workgroup.
