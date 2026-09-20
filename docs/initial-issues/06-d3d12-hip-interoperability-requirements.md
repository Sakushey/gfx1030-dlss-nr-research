# Map D3D12/HIP interoperability requirements

> Draft for supervisor review. Do not open automatically.

**Title:** Map D3D12/HIP interoperability requirements

**Suggested labels:** `host-only`, `research`, `interop`, `documentation`,
`requirements`

**Evidence level:** `PROPOSED`. This issue produces a requirements analysis, not a
demonstration. Interoperability itself is **not demonstrated** and is not expected to
be demonstrated by this issue.

---

## Context

Proof-ladder rung 7 is D3D12/HIP interoperability. It is not demonstrated, and the
project has been careful not to imply otherwise. It is also far above the current
position — the project has not yet completed a single workgroup physically (rung 3) —
so there is no possibility of implementing it now.

What *is* useful now, and what this issue asks for, is to **map the requirements**. The
value of a requirements map at this stage is that it constrains the earlier rungs: it
tells the project what properties the earlier work must preserve to leave interop
reachable later. Requirements discovered late are requirements that were violated
early.

The likely shape of the requirement space (to be confirmed or corrected, not assumed):

- **Shared memory.** What memory must be visible to both a D3D12 device and the HIP
  runtime — resources, heaps, or buffers — and what properties (placement, alignment,
  tiling, caching) they must have for both to use them.
- **Synchronization across API boundaries.** How work submitted through one API is
  ordered against work submitted through the other, and what the ordering guarantees
  actually are. Fences, shared handles, and queue semantics all live here.
- **Resource lifetime and ownership.** Which API owns a resource, when ownership
  transfers, and what happens on error paths.
- **Format and layout agreement.** Whether the two sides agree on element formats,
  layouts, and coordinate conventions, and where a silent disagreement would be
  invisible.
- **Device selection.** Which device each API selects, and what happens when they do
  not select the same one — a classic source of "it works until it doesn't".
- **Failure behavior.** What each API reports when the other side misbehaves, and
  whether that reporting is usable for diagnosis.

The last two are where this project's existing hard-won lessons apply directly: a
resource identity mismatch that surfaces as an unrelated downstream symptom, and a
return value that reports success when the operation did not complete.

## What is needed

A **requirements document**, not an implementation. Specifically:

- An inventory of what would have to be shared between the two APIs, with the
  properties each side demands of it.
- The synchronization model: what must be ordered, what mechanism would order it, and
  what guarantee that mechanism provides.
- The points where the two sides could **silently disagree** — formats, layouts,
  identity, device selection — and how each disagreement would manifest. A silent
  disagreement is the dangerous kind, and identifying them in advance is most of the
  value of this exercise.
- **Which parts can be validated host-side** before any device work, and which
  genuinely require a device. Anything that can be moved host-side should be, because
  physical experiments are scarce and bounded.
- **Which earlier-rung properties must be preserved** for interop to remain reachable —
  the constraints this analysis places back on current work.
- Explicit non-goals: this issue does not implement interop, does not demonstrate it,
  and does not claim it.

## What a good resolution looks like

- A requirements document that a future implementer could act on, with each requirement
  stated so that it is either satisfied or not — not as a general consideration.
- A separate list of **host-side-validatable** requirements, each with how it would be
  validated without a device.
- A list of **silent-disagreement risks**, each with the symptom it would produce, so
  that a future investigator encountering that symptom has a lead.
- An explicit statement of what remains unknown and why, rather than a plausible
  filling-in of the gaps.
- No code and no demonstration; the deliverable is the analysis.

## Acceptance criteria

- [ ] The document distinguishes clearly between **established** facts about the two
      APIs and **open questions**; no open question is presented as an answer.
- [ ] Each requirement is stated as something that can be satisfied or not, rather than
      as a general area of concern.
- [ ] The synchronization model is described concretely: what is ordered, by what
      mechanism, with what guarantee.
- [ ] At least three **silent-disagreement risks** are identified, each with the
      symptom it would produce if violated.
- [ ] A host-side-validatable subset is identified, with a validation approach for each
      item in it.
- [ ] Constraints on earlier work are stated explicitly — what current work must not do
      in order to keep interop reachable.
- [ ] The document states plainly that interop is **not demonstrated**, and does not
      present the map as progress up the ladder.
- [ ] No GPU was used; the write-up contains no physical claim.

## Related

- `05-complete-neural-job-buffer-dependency-graph.md` — supplies the buffer/dependency
  structure this requirements map depends on.
- [Current state](../current-state.md) — the accurate status, including that interop is
  not demonstrated.
- [Glossary](../glossary.md) — fail-closed, host-valid vs. hardware-valid, rung,
  watchdog/TDR.
- [Evidence and reproducibility](../evidence-and-reproducibility.md) — why a reported
  success is not proof, applied here to cross-API synchronization.
