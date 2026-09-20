# Independent review of dynamically executed gfx1030 instruction forms

> Draft for supervisor review. Do not open automatically.

**Title:** Independent review of dynamically executed gfx1030 instruction forms

**Suggested labels:** `isa`, `rdna2`, `review`, `host-only`, `correctness`

**Evidence level:** targets `HOST_VALIDATED` / `HOST_INDEPENDENT_ORACLE`. This is a
host-only task; it produces no physical claim and does not require a GPU.

---

## Context

The host emulator implements the `gfx1030` instruction forms the studied workload
**actually executes**. That set is narrower than the full ISA — deliberately so — but
it also means the emulator's coverage is exactly the set of forms that matter, and an
error in any of them propagates into every host result derived from it. Because the
host results are what the project uses to reason about the physical problem, a silent
semantic error here is expensive: it can cause the project to eliminate a *correct*
hypothesis (descriptor layout, barrier placement, `waitcnt` placement, argument layout,
address layout) and search in the wrong place.

The emulator and the oracle were written independently for exactly this reason, and
they have been compared. But two mutually independent host implementations can still
share a **misunderstanding** of the ISA — if both were written from the same
misreading of the same documentation, they will agree and both be wrong.

This issue asks for review by someone who did not write either.

The areas of highest risk, based on where the semantics are subtle rather than merely
numerous:

- **`EXEC`-masked lane behavior** — what happens to a lane whose `EXEC` bit is clear:
  its result register, its memory access, its contribution to `VCC`, its participation
  in LDS/DS operations. The common case is easy and the masked cases are where models
  go wrong.
- **`VCC` carry/borrow semantics** across the instruction forms in use, and their
  interaction with masking.
- **`SCC` on the scalar path**, and keeping it distinct from `VCC`.
- **LDS / DS operations**, including bank behavior where it is architecturally
  observable, and the ordering guarantees the model assumes.
- **`waitcnt` semantics**: which counter classes a given form covers, and what a
  counter reaching its target actually guarantees.
- **Wave32-specific behavior** — cases where a model informed by a different AMD
  generation (wave64) or another vendor's design would be wrong.

## What is needed

An independent read of the instruction forms in the executed set, focused on
**semantics** rather than encoding, and focused on the cases where a plausible
implementation is wrong.

Useful inputs, which the reporter can supply on request:

- The decoded instruction-form population for the studied workload (which forms are
  executed, and how often).
- The emulator's semantic model for those forms (`src/emulator/`) and the independent
  scalar oracle (`src/oracle/isa_oracle_scalar.py`).
- The existing differential comparison and its per-record results (`tools/p16j_differential.py`),
  including the comparison counts.

What is specifically requested:

- **A disagreement with a stated reason.** "I believe this form behaves differently
  for masked lanes, because …" is far more useful than general commentary.
- **Identification of shared-assumption risk**: places where the emulator and the
  oracle could both be wrong in the same way, since those are invisible to a
  differential comparison.
- **Coverage gaps stated as gaps**: forms present in the workload but only partially
  modeled, or modeled with an assumption that is not documented.
- **A negative case**, where you can produce an input on which the current model gives
  a result you believe is wrong.

## What a good resolution looks like

- Each reviewed form is recorded as **confirmed**, **disputed with a reason**, or
  **unresolved**, with the reasoning attached.
- Any dispute is turned into a focused host test with a **negative control** — an input
  the check must reject — so that the fix is demonstrably a fix and not a change in
  output.
- Shared-assumption risks are recorded even when they cannot be resolved, so a future
  reader knows which agreements are weak.
- Any resulting change is verified by **per-record** comparison, not by aggregate
  agreement: a matching total is not evidence of equivalence.

## Acceptance criteria

- [ ] The set of instruction forms reviewed is stated explicitly, and it matches the
      population the workload actually executes.
- [ ] Each form reviewed carries a verdict of confirmed / disputed / unresolved, with
      reasoning.
- [ ] At least one form has been examined specifically for `EXEC`-masked-lane behavior,
      with the masked cases considered separately from the common case.
- [ ] Any disagreement is expressed as an input with a predicted-vs-actual result, not
      as prose only.
- [ ] Any resulting check is demonstrated against a **known-bad** case and shown to
      **accept a known-good** case.
- [ ] Comparisons are per-record and report the number of comparisons made; a result
      with zero comparisons is not accepted as a pass.
- [ ] The review states whether a GPU was used (it should not have been) and keeps any
      host claim labelled as host evidence.

## Related

- `01-candidate-f-physical-j3-non-completion.md` — the physical problem this review
  helps reason about.
- [Architecture](../architecture.md) — why the oracle is kept independent of the
  emulator.
- [Evidence and reproducibility](../evidence-and-reproducibility.md) — negative
  controls, per-record comparison, and why a matching count is not equivalence.
- [Glossary](../glossary.md) — `EXEC mask`, `VCC`, `SCC`, `LDS`, `DS`, `wave32`,
  `waitcnt`.
