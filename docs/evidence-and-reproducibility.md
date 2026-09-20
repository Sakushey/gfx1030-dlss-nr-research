# Evidence and Reproducibility

This page defines what counts as evidence in this project, how claims are labelled,
and the methodological rules that keep the labels honest. The rules exist because
this project's central difficulty is not producing output — it is knowing whether
output means anything.

Terms are defined in the [glossary](glossary.md). The status of each area is in
[current state](current-state.md).

## The proof ladder

Claims are organized on a ladder of eleven rungs. **Passing one rung never implies
the next.**

| Rung | Claim |
| --- | --- |
| 1 | Host static correctness |
| 2 | Host dynamic / independent oracle |
| 3 | One-workgroup physical |
| 4 | Multi-workgroup |
| 5 | Authentic full dispatch |
| 6 | Complete neural job |
| 7 | D3D12/HIP interop |
| 8 | Presented frame |
| 9 | Temporal stability |
| 10 | Sustained gameplay |
| 11 | Performance |

Rungs 1–2 are **host** rungs; rungs 3 and above are **physical**. The boundary
between rung 2 and rung 3 is the project's most important seam. Work on rung 2 says
nothing about rung 3.

## Evidence labels

Every claim is classified at the **highest level actually established** — never the
highest level attempted, and never the level the author hopes for.

| Label | Meaning |
| --- | --- |
| `PROPOSED` | Stated as an intention, hypothesis, or design. No validation has been performed. |
| `HOST_STATIC` | A host-side static property has been checked: decoding, layout, structure, a gate's verdict on an artifact. |
| `HOST_VALIDATED` | A host-side model has been executed and its behavior checked against an expectation. |
| `HOST_INDEPENDENT_ORACLE` | A host-side result has been checked against an independently written implementation, and the comparison is meaningful (per-record, and the checker has been shown able to fail). |
| `PHYSICAL_DIAGNOSTIC` | Something was observed on the physical device, but it is diagnostic rather than a completed result — for example an entry point reached, or a launch accepted. |
| `PHYSICAL_ONE_WORKGROUP` | One workgroup completed on the physical device. |
| `PHYSICAL_MULTI_WORKGROUP` | More than one workgroup completed on the physical device. |
| `COMPLETE_JOB` | A complete neural job completed. |
| `INTEROP` | D3D12/HIP interoperability demonstrated. |
| `PRESENTED_FRAME` | A frame was presented. |
| `TEMPORAL` | Temporal stability demonstrated across frames/time. |
| `PERFORMANCE` | A performance claim, measured. |

Two rules on using labels:

- **A label is a ceiling, not a floor to aspire to.** If the evidence supports
  `HOST_VALIDATED`, the claim is `HOST_VALIDATED` even if the work was aimed at
  `PHYSICAL_ONE_WORKGROUP`.
- **A label is scoped to the artefact it was earned on.** A verdict about one harness
  is a verdict about *that* harness. Carrying it over to a sibling harness that was
  written later, or changed since, is not a smaller claim — it is a different and
  unsupported one. Re-earn it on the artefact you are actually talking about.

## What counts as evidence

Evidence is something a third party could inspect and reach the same conclusion from.
Concretely:

- **Raw output, preserved as produced.** A log, a record stream, a captured result.
  Not a summary of it, and not a description of it.
- **The artifact the claim is about.** If the claim is "this code object has property
  P", the artifact must be available and its identity recorded (a hash, a fingerprint,
  a size) so that a later reader can tell whether it is the same artifact.
- **A stated comparison.** "A matches B" is evidence only with B identified, the
  comparison performed per item, and the count of comparisons reported.
- **A check that can fail.** A check that has been shown to reject a known-bad input.

What is **not** evidence:

- An exit code on its own.
- A tool's self-reported success message.
- An aggregate total that matches another aggregate total.
- A result whose producing artifact cannot be identified.
- A host result presented as if it bore on physical behavior.
- Output produced after a driver reset, treated as kernel output.

## Raw-evidence preservation

Physical experiments are scarce and sometimes destructive to the session. Therefore:

- **Preserve the raw output as produced.** Do not reformat, trim, or "clean up" the
  original; derived views are additional files, not replacements.
- **Record the identity of inputs.** A result is only meaningful alongside the
  identity of the artifacts that produced it. Where an artifact is frozen, freezing
  must mean something: a frozen artifact that silently changes invalidates every
  result derived from it, which is why the frozen-artifact checks exist
  (`tools/p16j_frozen_check.py`, `tools/c_freeze.py`).
- **Distinguish the report from the thing reported.** In particular, a driver-recovery
  or watchdog message is a statement about the *host and the platform*. It is not
  kernel output, and it must never be recorded as if the kernel had produced it. The
  fact that a synchronization call returns without an error after a recovery is a
  property of the runtime's post-recovery behavior, not a success.
- **Bounded runs, preserved rather than repeated.** Because retries are not automatic,
  the first capture matters. Keep it.

## Matching aggregate counts are not equivalence

This is the most frequently violated rule in practice, and it is worth stating
bluntly:

> Two runs producing the **same total** is not evidence that they produced the **same
> values**.

A total is a lossy projection. Consider a workload whose result is a histogram, a sum,
a checksum over a set, or a count of operations. Two different executions can arrive
at the same total through different per-item values: a value that went up by one and
another that went down by one cancel in the total; a mis-attributed value can land in
the right bucket for the wrong reason; a set can be permuted.

**The rule:** compare **per-record values, not totals.** The per-instruction record
stream produced by the recorder exists precisely so that this comparison is possible.
Where a total is all that is available, say so, and label the claim accordingly — an
aggregate match is a weak signal, not an equivalence.

This is why the tools distinguish determinism checking (`p16j_determinism.py`) from
differential comparison (`p16j_differential.py`): one asks "did this run repeat
itself", the other asks "do these two implementations agree item by item".

## A tool reporting success is not proof its output is right

A tool that exits zero, prints "OK", or writes a file has told you that it ran. It has
**not** told you that what it produced is correct, or even that it produced anything
meaningful.

The failure modes are mundane and repeatedly observed:

- The tool ran, but on the **wrong input** — an old artifact, a different file, a
  stale path.
- The tool ran and compared **zero items**, and reported zero mismatches. Zero
  mismatches out of zero comparisons is not a pass.
- The tool's success condition was **satisfied vacuously** — the constraint it checked
  was not actually exercised.
- The tool reported a result computed in the **wrong address space**, or in the wrong
  units, or against the wrong baseline.

**The rule:** read the artifact back, and check a property you can predict in advance.
Not "is the file non-empty" but "does this value equal the value I can compute
independently". A hash over a deterministic pattern is useful here for exactly this
reason: it was computed before the run, so it cannot be rationalized afterwards.

Corollary for reviewers: when a report says "clean", ask **how many comparisons** were
made and **which file** was loaded. Those two numbers settle most vacuous passes.

## A verifier must be tested against a known-bad case

A verifier has two independent jobs, and both must be demonstrated:

1. **It can fail.** Feed it something it must reject, and confirm it rejects it. A
   check that has never rejected anything is indistinguishable from a check that
   always passes.
2. **It accepts the known-good case.** Feed it the thing you are confident is right,
   and confirm it passes. A check computed in the wrong space, or against the wrong
   reference, will reject the control too — and that reads as *strict*, which is
   exactly the wrong lesson to take from it.

Both halves matter because the two failure modes are asymmetric in how they feel. A
check that always passes feels reassuring. A check that rejects everything feels
rigorous. A useful check is neither, and the only way to know which one you have is
to try it on inputs whose verdict you already know.

Two further traps that fall out of this:

- **The verifier must not check the specification that defines it.** If a check's
  "expected" values are generated by the same code path that produced the values under
  test, the check cannot fail. If the check is a rule written into a document, beware
  of the check tripping over text in the rule that created it.
- **The independent reference is itself a suspect.** An oracle built to be independent
  can still be wrong. When the emulator and the oracle disagree, investigate the
  disagreement on its merits — do not resolve it by assuming the oracle is right. In
  this project's history, a disagreement was traced to the *reference model*, not to
  the emulator, which is the outcome the separation is designed to make findable.
- **A mutation table goes stale.** A deliberately-introduced defect used to prove a
  check can fail stops proving anything once the underlying defect is repaired — it
  then rejects nothing, and its "FAIL" verdict becomes noise that gates nothing.
  Re-verify the negative controls periodically, not once.

## Reproducibility checklist

For a claim to be reproducible by someone else, the record must let them:

- [ ] Identify the artifacts involved (identity recorded, e.g. a hash).
- [ ] Re-run the same bounded procedure with the same inputs.
- [ ] See the raw output, not a summary of it.
- [ ] See the comparison performed per record, with the comparison count stated.
- [ ] See the check demonstrated against a known-bad case.
- [ ] Know which runtime generation was in play, for any physical result.
- [ ] Tell host evidence from physical evidence without relying on prose tone.

If a record cannot support all of these, its claim should be labelled at the highest
level it *can* support — which is often lower than the level the work was aimed at.

## See also

- [Architecture](architecture.md) — where the guards, gates, and the independent
  oracle live.
- [Current state](current-state.md) — the live status, including the physical
  liveness problem.
- [Glossary](glossary.md) — definitions of oracle, negative control, rung, evidence
  label, host-valid vs hardware-valid.
- [Hardware testing policy](hardware-testing-policy.md) — the physical-side rules.
