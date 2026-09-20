# The proof model

The single most important idea in this project: **passing one rung of the
ladder never implies the next.** Every claim is labelled with the highest
rung it has actually reached, and no document, issue, or pull request is
allowed to promote a claim by implication.

## The ladder

| # | Rung | Established by | Needs GPU? |
| --- | --- | --- | --- |
| 1 | Host static correctness | deterministic analysis of the artifact | no |
| 2 | Host dynamic / independent oracle | execution under the host model, cross-checked by a separately written oracle | no |
| 3 | One-workgroup physical | one bounded dispatch on gfx1030 running to completion | yes |
| 4 | Multi-workgroup | the same, with more than one workgroup | yes |
| 5 | Authentic full dispatch | the geometry the real workload uses | yes |
| 6 | Complete neural job | an entire neural job, dependencies resolved | yes |
| 7 | D3D12 / HIP interop | demonstrated interop across the graphics/compute boundary | yes |
| 8 | Presented frame | a frame produced by the neural path and presented | yes |
| 9 | Temporal stability | stability across many frames | yes |
| 10 | Sustained gameplay | interaction over time | yes |
| 11 | Performance | measured, meaningful throughput | yes |

## Why the gaps matter

Each gap is a place where a real project can silently fool itself.

**Rung 2 → 3.** A host model that terminates does not mean the hardware
kernel terminates. The host model implements *a* semantics; the hardware
implements the architecture. Agreement bounds your understanding of the
artifact, not the hardware's behaviour.

**Rung 3 → 4.** One workgroup exercises almost none of the synchronization
surface. A single workgroup can pass while every multi-workgroup barrier
interaction is wrong.

**Rung 6 → 7.** Interop adds a second runtime, a second memory domain, and
a second scheduler. Nothing about rung 6 constrains it.

**Rung 7 → 8.** Producing correct compute output is not presenting a
frame. Presentation adds timing, residency, and the graphics pipeline.

**Rung 8 → 9.** One frame can be right by luck or by a race that has not
lost yet.

## Evidence labels

Every claim is tagged with exactly one label at the highest level actually
established:

| Label | Meaning |
| --- | --- |
| `PROPOSED` | a hypothesis, with no execution behind it |
| `HOST_STATIC` | deterministic analysis of an artifact, no execution |
| `HOST_VALIDATED` | executed under the host model and observed to match an expectation |
| `HOST_INDEPENDENT_ORACLE` | as above, and cross-checked by a separately written oracle |
| `PHYSICAL_DIAGNOSTIC` | a bounded physical run produced diagnostic output |
| `PHYSICAL_ONE_WORKGROUP` | one bounded physical dispatch ran to completion with a checked result |
| `PHYSICAL_MULTI_WORKGROUP` | as above, multiple workgroups |
| `COMPLETE_JOB` | a complete neural job executed |
| `INTEROP` | D3D12/HIP interoperability demonstrated |
| `PRESENTED_FRAME` | a neural-produced frame was presented |
| `TEMPORAL` | stability demonstrated across frames |
| `PERFORMANCE` | measured throughput reported |

`HOST_VALIDATED` and `PHYSICAL_ONE_WORKGROUP` are not adjacent. The gap
between them is the entire difficulty of the project.

## Rules that keep the model honest

1. **Label at the level actually established.** Aspiration is not
   evidence.
2. **Never let a summary promote a claim.** Careful wording in a summary
   does not license a stronger claim elsewhere.
3. **A matching aggregate is not equivalence.** Identical totals can hide
   different values. Compare per-record values.
4. **A tool reporting success is not proof the output is right.** Read the
   artifact back and check a property you can predict.
5. **A verifier that cannot fail is vacuous.** Test every check against a
   known-bad input, and against the known-good case.
6. **A negative control is part of the result.** "It passed" is
   meaningless without "and it fails when it should."
7. **Name the artifact.** Results attach to a content hash, not a
   filename.

## Negative controls

A negative control is an input you *know* must be rejected, included so
that a pass means something.

Without one, a check can be measuring nothing:

- a comparison over an empty record set reports a perfect match;
- a verifier pointed at the wrong file still returns success;
- a check evaluated in the wrong address space rejects the control *and*
  the known-good case, and so reads as strict when it is simply broken;
- an independent reference model that shares a defect with the thing it
  checks will agree with it on every input.

Every non-trivial check in this project should come with a control that
fails correctly. If it cannot, say so explicitly rather than implying
coverage that does not exist.
