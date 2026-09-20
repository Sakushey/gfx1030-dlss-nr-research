# Glossary

Definitions as used **in this project**. Where a term has a broader industry meaning,
the entry describes the sense used here, and notes the distinction where it matters.

---

### ABI forwarding

Intercepting a runtime's exported entry points and passing calls through to the real
implementation, so that the calls can be observed and characterized without altering
the runtime's behavior. In this project, `src/bridge/amdhip64_7.cpp` with
`src/bridge/exports.def` provides this for the HIP runtime boundary.

Forwarding is *observation*, not modification. The distinction matters: a forwarding
shim that changes behavior is no longer a shim, and results obtained through it would
describe the shim rather than the runtime.

See also: *fail-closed*.

---

### Barrier

A synchronization point at which participating work-items (or workgroups) wait until
all have arrived before any proceeds. Correctness depends not only on the barrier
existing but on **placement** — specifically, on whether the barrier's position
relative to the operations it is meant to order actually orders them.

In this project, barrier hypotheses are tested against several independently written
formulations (`src/harness/barrier_oracle_src_a.cpp` … `..._d.cpp`) so that a
disagreement is possible. See also: *s_barrier*, *waitcnt*, *workgroup*.

---

### Code object

A compiled, device-targeted binary for a specific architecture (here, `gfx1030`),
together with the metadata needed to load and launch it. It is the thing the runtime
consumes.

This repository **does not redistribute code objects.** Where a harness needs one, the
researcher generates it locally from their own legitimately obtained installation.
That is both a legal boundary and a methodological one: an identity gate can only mean
something if the artifact's provenance is known.

See also: *fatbin*, *kernarg*, *descriptor*.

---

### Descriptor

A structured record describing something the runtime or device needs — for example how
a resource is laid out, or how a kernel is to be launched. Descriptor **layout** (the
order, packing, alignment, and size of its fields) is a common and quiet source of
failure: a descriptor that is semantically right but laid out differently from what
the consumer expects fails in ways that do not look like a layout problem.

In this project, descriptor layout has been validated host-side and is not currently
the leading explanation for the physical liveness problem. See
[current state](current-state.md).

---

### Dispatch

The act of submitting a kernel to the device for execution, with a specified grid of
workgroups. "Authentic full dispatch" (proof-ladder rung 5) means the dispatch the
real workload would issue, as opposed to a reduced or hand-parameterized one.

In this project, a *bounded one-workgroup* dispatch is not an authentic full dispatch.
The distinction is one of the reasons the ladder separates rung 3 from rung 5.

---

### DLSS-NR

DLSS Neural Rendering — the neural-rendering component of the DLSS family of
techniques, which performs image reconstruction/rendering work using learned models.
It is the workload family this project studies: specifically, whether such workloads
can be translated, validated, and executed on `gfx1030`.

This project does not redistribute it, does not include its assets, and makes no claim
that it runs. Stating the goal precisely: the project investigates **compatibility and
execution feasibility** on a platform the workload was not built for.

---

### DS (data share)

The data-share unit: the hardware path handling data movement and operations between a
work-item and the LDS (and related shared-memory operations). In this project, DS and
LDS semantics get their **own model** rather than being folded into core execution,
because they are among the operations most likely to be silently wrong.

See also: *LDS*.

---

### Entry contract

The set of expectations the runtime and device have about a kernel at launch: how
arguments are presented, where descriptors live, what sizes and alignments are
required, what the kernel may assume is initialized. It is a *contract* because
violating it does not necessarily produce a clear error — it can produce a launch that
is accepted and then behaves inexplicably.

The entry contract is distinct from instruction semantics: knowing what the
instructions mean does not tell you how to present the kernel correctly. Entry probes
(`src/harness/p14_entry_probe_host.cpp`, `src/harness/p14d10_entry_probe_host.cpp`)
exist to characterize it.

---

### Evidence label

A classification applied to every claim, fixed at the **highest level actually
established** rather than the level attempted. The labels are `PROPOSED`,
`HOST_STATIC`, `HOST_VALIDATED`, `HOST_INDEPENDENT_ORACLE`, `PHYSICAL_DIAGNOSTIC`,
`PHYSICAL_ONE_WORKGROUP`, `PHYSICAL_MULTI_WORKGROUP`, `COMPLETE_JOB`, `INTEROP`,
`PRESENTED_FRAME`, `TEMPORAL`, `PERFORMANCE`.

Two properties are easy to get wrong: a label is a **ceiling**, not a target; and a
label is **scoped to the artefact it was earned on** — carrying a verdict from one
harness to a different harness is a new, unsupported claim.

Full definitions: [evidence and reproducibility](evidence-and-reproducibility.md).

---

### EXEC mask

The per-lane execution mask that determines which lanes of a wave are active for an
instruction. A lane with its `EXEC` bit clear does not execute, and — critically —
what happens to that lane (its result register, its memory access, its participation in
a reduction or a shared-memory operation) is part of the semantics, not an
implementation detail.

Many plausible-looking host models handle the common case and get the masked-lane
cases wrong. In this project, `EXEC` behavior gets targeted cases with negative
controls. See *negative control*.

---

### Fail-closed

A design property: when a precondition cannot be verified — a backend cannot be
loaded, an identity cannot be established, a gate cannot reach a verdict — the
operation **refuses** rather than proceeding in an uncertain state.

The alternative, fail-open, converts a detectable problem into a confusing downstream
symptom: an identity mismatch becomes an inexplicable wrong result, and a partially
initialized component is presented as a working one. In this project the backend load
and the fatbin identity gate are both fail-closed.

Note the general hazard: a *harness* can be fail-open even when its components are
fail-closed. A run that reports "ended" may have ended because every case faulted;
always read the per-case fault list, not just the summary verdict.

---

### Fatbin

A container bundling device code for one or more target architectures, from which the
runtime selects the appropriate code object. Because a fatbin can hold multiple
targets, "which code object actually ran" is not self-evident from the fatbin — it has
to be established.

This project applies a **fatbin identity gate** (`src/bridge/bridge_config.h`,
`src/bridge/kernel_policy_map.h`): the artifact must match the identity the bridge
expects, or it is refused. See *fail-closed*, *code object*.

---

### gfx1030

The AMD GPU ISA/target identifier for the `gfx10.3` generation — RDNA2 / Navi21-class
hardware, including the RX 6950 XT. It is the target of this project's physical path.

In this environment, `gfx1030` is enumerated by **ROCm 6.4** and is not enumerated by
ROCm 7.1. That fact determines which runtime the physical path targets, and it is why
the runtime identity is recorded rather than assumed.

See also: *Navi21*, *RDNA2*, *code object*.

---

### Host-valid vs. hardware-valid

**Host-valid:** a result obtained from a host-side *model* of the semantics — the
emulator or the oracle. It is a statement about software.

**Hardware-valid:** a result obtained from the physical device and describing the
physical device. It is a statement about silicon and platform.

These are different kinds of statement, and neither implies the other. Between them
stand at least: the model's fidelity (and its coverage gaps), the entry contract, the
runtime's behavior, hardware scheduling and memory-system behavior, and **liveness** —
whether the kernel actually runs to completion at all.

A host-valid result is not partial credit toward hardware validity. This is the single
most important distinction in this project; see [current state](current-state.md).

---

### Kernarg

The kernel argument buffer: the block of argument values passed to a kernel at launch.
Its **layout** (order, offsets, alignment, padding, and where pointer-versus-value
arguments sit) is part of the entry contract, and a mismatch is a classic
"launched but behaved inexplicably" failure.

Kernarg layout for the studied code object has been validated host-side in this
project; see `tools/p16g_kernarg.py`.

---

### LDS

Local Data Share — the per-workgroup scratchpad memory shared among the work-items of
a workgroup (in CUDA terms, roughly "shared memory"). It is explicitly modeled in this
project (`src/emulator/p14d_kd.py`, `src/emulator/p14e_emu.py`,
`src/emulator/p14e_emu_g.py`) and audited separately
(`src/emulator/p14e_lds_audit.py`), because LDS semantics are a high-risk area for
silent error.

See also: *DS (data share)*, *workgroup*.

---

### Navi21

The AMD GPU die family (RDNA2) to which the `gfx1030` target belongs — the RX 6000
series desktop parts. Used here as a hardware family name; it is not a claim that all
Navi21 parts behave identically, which is precisely why a second-device check is a
worthwhile task (see `docs/initial-issues/08-second-navi21-gfx1030-device.md`).

See also: *gfx1030*, *RDNA2*.

---

### Negative control

An input that the check under test **must reject**. Running a check against a
negative control is how you demonstrate the check can fail at all.

A check with no negative control is indistinguishable from a check that always passes,
and a check that always passes provides no information — yet it reads as reassuring.
The symmetric requirement is that a check must also **accept a known-good case**: a
check computed in the wrong space will reject the control too, and that reads as
*strict*, which is the wrong lesson.

Related hazards worth knowing: a check whose "expected" values come from the same code
path as the values under test cannot fail; and a deliberately introduced defect used as
a negative control stops working once the underlying defect is repaired, so negative
controls need periodic re-verification rather than one-time setup.

Full discussion: [evidence and reproducibility](evidence-and-reproducibility.md).

---

### Oracle

An independent implementation used as a reference against which another implementation
is checked.

In this project the oracle is `src/oracle/isa_oracle_scalar.py`, a scalar reference for
the ISA semantics. Its defining property is **independence**: it does not share code or
control flow with the emulator. If it did, a mistake common to both would be invisible
to the comparison, and the check would degenerate into "does the emulator agree with
itself" — which always succeeds and validates nothing.

The corollary is that the oracle is itself a suspect. When the two disagree, the
disagreement is investigated on its merits; the reference model can be the wrong one.

See also: *host-valid vs. hardware-valid*, *negative control*.

---

### RDNA2

The AMD GPU microarchitecture family (also referred to as `gfx10.3` in the ISA target
naming) that includes the `gfx1030` target. Its relevant properties for this project
include its wave size and its shared-memory and synchronization model, both of which
differ from other AMD generations and from other vendors' designs.

See also: *gfx1030*, *Navi21*, *wave32*.

---

### s_barrier

The instruction that implements a workgroup-level barrier. Its semantics include
**arrival and release** behavior for all work-items of the workgroup, and its
correctness in a program depends on its placement relative to the operations it orders.

See also: *barrier*, *waitcnt*, *workgroup*.

---

### SCC

The scalar condition code — a single-bit status flag in the scalar (uniform) execution
path, set by scalar operations and used by scalar branches. Distinct from `VCC`, which
is the vector condition code used on the per-lane path. Confusing the two is a
realistic source of host-model error, so both get explicit coverage.

See also: *VCC*, *EXEC mask*.

---

### VCC

The vector condition code — a per-lane mask register used for per-lane comparison
results and carry/borrow on the vector path. Because it is per-lane, its behavior
interacts with the `EXEC` mask: a masked-off lane's contribution to `VCC` is part of
the semantics, not an afterthought.

See also: *SCC*, *EXEC mask*, *wave32*.

---

### waitcnt

The instruction class that stalls execution until specified counter classes reach a
given value — the mechanism by which a program orders memory operations against their
consumers without a barrier. Correct use depends on **placement**: a wait that does not
cover the operations it appears to cover is a real and easily-missed defect.

In this project, `waitcnt` placement has been validated host-side and is not currently
the leading explanation for the physical liveness problem. See
[current state](current-state.md).

See also: *barrier*, *s_barrier*.

---

### Watchdog / TDR

The Windows GPU watchdog (Timeout Detection and Recovery, TDR): a platform mechanism
that detects a GPU operation that has not completed within a timeout and **recovers the
engine** — resetting it so the system remains usable.

Two consequences matter here:

1. The watchdog firing means the operation did **not** complete. Recovery is not
   success; it is the platform's response to a hang.
2. After recovery, a host-side synchronization call may return *without reporting an
   error*. That return value is a property of the runtime's post-recovery behavior, not
   kernel output, and it must never be recorded as though the kernel had succeeded.

This project **never** modifies watchdog or TDR settings. Tests must never be run with
modified watchdog/TDR configuration — doing so would remove the safety mechanism and
would also invalidate the interpretation of any result.

See also: *dispatch*, *host-valid vs. hardware-valid*.

---

### Wave32

The 32-lane wavefront mode used on RDNA2 for the relevant shader stages. A "wave" is
the unit of lanes executing in lockstep; its size determines how many lanes share an
`EXEC` mask and `VCC` register file, and therefore how masking and per-lane state
behave.

Wave size is a place where knowledge from a different AMD generation (wave64) or a
different vendor does not transfer cleanly. Behaviors that are wave32-specific are
labelled as such in this project rather than being assumed to generalize.

See also: *EXEC mask*, *VCC*, *RDNA2*.

---

### Workgroup

A group of work-items that executes together and may share LDS and synchronize with a
barrier. The workgroup is the unit the proof ladder uses for its physical rungs:
"one-workgroup physical" (rung 3) means a single workgroup completed on the device,
and "multi-workgroup" (rung 4) means more than one did.

The current physical problem is a **one-workgroup** case that does not complete. That
is why the project is at rung 3 rather than further up; see
[current state](current-state.md).

See also: *dispatch*, *LDS*, *s_barrier*, *rung*.

---

### Rung

One step of the eleven-step proof ladder (host static correctness; host dynamic /
independent oracle; one-workgroup physical; multi-workgroup; authentic full dispatch;
complete neural job; D3D12/HIP interop; presented frame; temporal stability; sustained
gameplay; performance).

The defining rule: **passing one rung never implies the next.** The ladder exists to
prevent the most natural error in this kind of work — letting a strong result at one
level quietly become a claim at a higher level.

Full ladder: [current state](current-state.md) and
[evidence and reproducibility](evidence-and-reproducibility.md).
