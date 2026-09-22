# Post-review validation findings

This document records what this project **re-measured for itself** after two
rounds of external technical review of the gfx1030 translation work. It is
written for a reader of the public repository who wants to know which
qualification claims survived independent scrutiny and which did not.

It is deliberately **not** a copy of either review. The reviews themselves are
not republished: they name local absolute paths, they carry an auditor's own
file references, and republishing them would publish a third party's document
rather than this project's findings. What follows is this project's synthesis
of its own measurements, in its own words.

Two external reviews were received on 2026-09-20 as plain text, with no source
package, no archive and no auditor-supplied hashes. Both were therefore treated
as **sets of claims to be reproduced**, never as evidence. Every finding below
reached the status "verified" only by re-measuring it from this project's own
artefacts.

## 1. How a finding was accepted

A review claim was machine-recorded with the local source the reviewer named,
and then re-measured. Each claim carries one of four outcomes:

| Outcome | Meaning |
|---|---|
| `VERIFIED` | this project re-measured it from its own artefacts and got the same reading |
| `PARTIALLY_VERIFIED` | what reproduced agrees; whatever did not is carried forward as a stated residue rather than folded into the agreement |
| `CORRECTED` | the claim as written is inaccurate, and the accurately measured version is recorded beside it |
| `NOT_REPRODUCED` | this project ran the check the claim describes and the effect the claim describes did not occur |

Censuses, as measured:

- First review: 11 claims — **10 reproduced, 1 corrected, 0 not reproduced**.
  All six instrument-defect claims reproduced.
- Follow-up review: 52 claims — **47 `VERIFIED`, 3 `PARTIALLY_VERIFIED`,
  2 `CORRECTED`**.

Two claims were corrected rather than accepted, and both corrections matter
more than the reproductions:

1. A claim that a decision record contradicted itself was **not** supported.
   The record and its companion artefact agree. The real defect is a
   **collapsed field**: one value carries technical readiness, while the
   operator's stop order is recorded somewhere else entirely — a separate
   field, in a separate record. A reader who consults the decision field on its
   own therefore reads "authorised to launch". The concern was real; the named
   mechanism was not.
2. A claim about a stale status table cell was directionally right but two
   phases out of date — an instance of the drift being reported, not a
   weakness in the finding.

A review claim that this project could not reproduce is recorded as such and is
never silently dropped.

## 2. Occurrence-aware diagnostics

The first review's sharpest instrument finding was that diagnostic logic keyed
a conclusion to an **instruction address** rather than to an **execution of
that address**. An instruction that executes twice — once before a diagnostic
cut and once after it — was reported as excluded on the strength of its first
execution alone.

This reproduced. The repair is the project's, and it is structural: no claim is
keyed on a program counter alone; every event is keyed on
`(program counter, dynamic occurrence index)`.

The negative control for the occurrence engine asks it for an address that does
not occur in the trace at all. It must return **zero** occurrences rather than
falling back to a site-wide default. Measured: `0` occurrences returned, `0`
expected, control `detected = true`.

Two facts the reviews did not report, found while re-measuring:

- The number `3547` denoted **two different records in two different
  conventions**: the ordinal of one barrier, and the progress value of the cut
  record one step later. The measured relation
  `per_wave_steps[w] == n_records_in_wave[w] - 1` holds for all eight waves.
  The consequence is that a surviving interval's upper bound sat one record
  below the cut it named, so the interval *as written* still contained the
  barrier that prose claimed to exclude. The exclusion came from the prose, not
  from the arithmetic.
- The instruction replaced at one cut is a **cache-invalidate operation**, not
  an ordinary instruction. Replacing it with termination therefore also removed
  a cache-maintenance operation, which no prior report had stated. Separately,
  the instruction replaced at the other cut is a **conditional branch**. That
  run therefore does more than leave one instruction untested: it executes a
  program in which the control-flow decision has been deleted outright.

## 3. Fail-closed qualification

The follow-up review's highest-priority finding was that the physical-readiness
generator **demonstrably failed open**. This reproduced exactly, by injecting
conditions entirely in memory while the real gates ran unmodified:

| Injected condition | Gate behaviour observed |
|---|---|
| Diagnostic digest replaced with a non-hash string | gate stayed `PASS` |
| A prefix-equivalence verdict forced to `FAIL` | gate stayed `PASS` |
| A detail map removed while summary counts were retained | gate stayed `PASS` |
| Two dependent probe results therefore absent | both gates stayed `PASS` |
| Process enumeration returned failure and empty output | three gates stayed `PASS` |

**The aggregate verdict stayed green under every injection.** The mechanisms
were mundane and reproducible: a gate testing whether a stored digest string is
non-empty rather than rehashing the artefact; a gate that was a literal `PASS`
assignment; a gate accepting the vacuous truth of `all(...)` over an empty
collection; gates that *displayed* new-probe results without *requiring* them;
and a process check that ignored a command's return code, so a failed
enumeration read as "no processes running".

The repair is not "add more gates". It is that the aggregate verdict must be a
**predicate over validated, complete evidence**, where missing, malformed,
stale or contradictory evidence yields `FAIL` or `UNKNOWN`.

The measurement that says the repair has teeth is a **mutation suite**, not a
gate count:

- **43 mutations** applied at the evidence layer, in memory, against **22
  gates** running unmodified.
- **43 of 43 effective**; **0 ineffective**.
- **22 of 22 gates** have at least one effective mutant.
- **Every mutation reaches a non-green aggregate verdict.**
- A **known-good control** — no mutation at all — reproduces the green
  baseline. A harness that flagged it would be measuring itself.

The rule adopted from this is explicit: *robust green requires zero gates
without an effective mutant.* A gate nobody can make fail is not a gate.

## 4. Coverage denominators

The follow-up review observed that a clean hazard verdict depended on
insufficient and unknown edge counts, so clause findings could not reach the
verdict at all. That reproduced: forcing **every** clause to a forbidden
verdict left the aggregate result unchanged.

Two changes follow, and both are about **denominators**, not about adding
checks.

First, a verdict must state what it is a verdict *over*. The hazard analysis is
now bound to one named experiment and its actual executed prefix — **1,622
records** — rather than to a different experiment's longer interval that
happened to be a superset. The superset made the earlier result conservative
but unbound: the ledger could not be stated against the right denominator.

Second, coverage is a first-class output. Every mandatory hazard category must
reconcile `analysed + proven_not_applicable == total`, and an incomplete
category is `UNKNOWN`, not silence. Measured on the selected prefix:

| Component | Denominator | Result |
|---|---|---|
| Executed instruction forms | 68 distinct | 0 unsupported |
| Producer / non-producer records | 1,253 / 369 (= 1,622) | sum reconciles |
| Register dependency edges | 28,690 | 0 insufficient; 8 by counting rule |
| Clauses in the prefix | 26 | 26 structurally valid, 0 invalid |
| Clause and wait controls | 19 | 19 correct, 0 failing |
| Mandatory coverage categories | 22 | 0 incomplete |
| Cache-maintenance instructions | 1 | 0 unresolved, 1 with a recorded residual |

Two of these deserve a caveat rather than a clean read.

The **edge count is not comparable across revisions**. The earlier figure of
871 was that revision's count over a different interval under a narrower edge
definition. Reporting 28,690 for the selected prefix is not an improvement in
coverage; it is a different measurement against a different denominator.
Comparing the two numbers would be a category error.

The **cache-maintenance residual is recorded, not absorbed**. The invalidate
retires before the dependent load's data return by same-type in-order
completion, but whether the load's cache lookup can precede the invalidate's
effect is not stated by the ISA. The component therefore passes with a named
residual rather than passing silently.

An important ceiling applies to the whole section. The prefix is
record-identical across all eight waves on every compared field — program
counter, operands, lane masks, LDS and memory counters, barrier field. That is
equivalence **of the model trace**. It says the eight waves do not differ in
this model. It is **not** a statement that the model matches the hardware, and
it is not reported as one.

## 5. Liveness is not causal origin

The follow-up review found that the interval logic excluded every pre-cut event
as a possible site of the original defect. The same file elsewhere stated
correctly that termination provides no semantic correctness coverage. Both
positions cannot hold at once.

The repair separates **four hypotheses about a record** that were previously
one:

| Hypothesis | Question | Updated by a successful cut? |
|---|---|---|
| Non-completion observation site | where does forward progress first fail? | **yes** — constrained to after the cut |
| State corruption origin | where may incorrect state originate? | **no** |
| Memory / synchronisation invalidity onset | where may ordering or visibility break? | **no** |
| Diagnostic perturbation boundary | where does the diagnostic diverge? | **defined at the cut** |

The second and third rows are the point. A shortened run can stop before a
defect becomes harmful **without the defect being absent**. Suppose an early
instruction computes an address incorrectly and the hang only appears later,
when something dereferences that address. Stopping the run before the
dereference lets it terminate, and says nothing at all about whether the
address was right. Prefix termination is therefore not behaviour-neutral after
the cut: shortening execution removes contention, outstanding work and
timing-dependent state.

An executable regression models exactly this — corruption at one event,
diagnostic termination later, manifestation later still. Under the model, the
observation site is constrained to after the cut while the corruption origin
remains unconstrained. The old behaviour fails that regression.

## 6. State typing

The follow-up review found the authoritative state record internally
inconsistent: an expected-output artefact declared not produced while the file
existed on disk with a recomputable digest; a clean hazard status beside a
blocker saying the hazard audit was blocked by specification uncertainty; a
stale blocker about mock and real builds not being separated; a historical
readiness value occupying the current readiness field; and a last-outcome
reference pointing at a readiness card rather than an attempt outcome record.

All of it reproduced. The repair is to **type** the evidence rather than to
hand-correct the output, and to enforce cross-field invariants. The chain the
state must distinguish is:

> artefact exists → identity verified → accepted for this experiment → physically validated

Several distinct facts had been collapsed into single fields. In particular,
one corrected claim is worth restating precisely: establishing that an expected
output **exists and has a stable identity** is not the same as establishing
that it is an **independent correctness oracle**. Identity is verified;
independence is separate and, at the time of writing, unestablished.

Ten semantic invariants now run against the state, with **10 negative controls,
10 detected**, and a **known-good control accepted** — so the validator has
teeth and is not merely rejecting everything.

## 7. Attempt accounting

The follow-up review found that an unspent budget was **hardcoded into a gate**
and that the named accounting artefact was displayed but never read. It also
found that transient conditions — process cleanliness, arming state, remaining
budget — were categorised as static properties of the source tree, which they
are not.

Both reproduced. The repair moves transient checks into immediate prelaunch
verification, and derives budget from an **append-only, crash-surviving ledger**
with a hash chain:

- Events: reserve, prelaunch pass, launch started, process returned, crash
  classification, final outcome.
- **Consumption is recorded before the launch**, so a launch that later crashes
  still consumes budget. Reserved-but-never-launched does **not**.
- Measured: chain **intact** across 5 records; for the named experiment,
  `0` consumed, `1` remaining, `hardcoded_budget = false`.
- **No retry entitlement arises from regenerating a report.**

A gate that recognises absence of a process by matching three name substrings
cannot establish absence of an unrelated GPU workload, and absence of a game
process does not prove that persistent configuration is unarmed. Both were
confirmed by measurement: common unrelated processes are not matched at all.
The replacement reads the arming configuration and reports `UNKNOWN` when it
cannot — a failed observation must not read as a negative observation.

## 8. Hazard-audit methodology

The follow-up review accepted the edge analysis as reproducible but observed
that the broader claim exceeded the checker's coverage. Its specific
methodological criticisms all reproduced and each has a corresponding change:

| Criticism | Change |
|---|---|
| Only wave 0's prefix was loaded | wave equivalence is now **measured** rather than assumed, so the collapse is proven |
| Unrecognised producers were skipped, not recorded | every form is classified; unsupported count is an output |
| Register tracking was not lane-sensitive | every vector-register edge carries the trace's lane mask |
| Store visibility and cross-wave synchronisation unaddressed | stores and barriers analysed as separate categories |
| Overwriting the tracked writer could drop an outstanding producer | an outstanding set is kept, with a disposition for all 363 asynchronous producers |
| Wait parsing returned one counter from a combined wait | every counter in every operand is parsed; the selected prefix is measured to contain zero combined-operand waits |

Two of the criticisms could not be closed, only bounded, and are recorded that
way rather than as passes:

- **General write-after-write / write-after-read safety is not established.**
  The analysis records the ISA's only software-visible ordering mechanisms —
  the four counters, clauses and barriers — and classifies non-memory register
  hazards as hardware-resolved. That last step is an **argument from absence**,
  not a guarantee. The ceiling is stated, and the question is classified as
  open and exercised, with no reliance on it for a green verdict.
- **Clause legality is now checked against the target ISA**, and the earlier
  checker was wrong in two specific, reproducible ways: it grouped global loads
  and global stores together without enforcing the clause restriction against
  mixing them, and it placed an instruction in its permitted set that the ISA
  opcode table classifies in a different family entirely. Both are now rejected.

The direction of the fix is the same one that runs through every section above:
a checker must **reject the known-bad** and **accept the known-good**. The
clause controls are therefore stated as pairs. Four known-good programs
(two global loads; two shared-memory loads; two scratch stores; a global load
with a wait) must be accepted. Known-bad programs (scalar ALU inside a clause;
a branch inside a clause; the misclassified instruction inside a shared-memory
clause) must be rejected. Measured: 19 controls, 19 correct.

## 9. What this does not establish

Recorded plainly, because the value of the above depends on it:

- **No physical result improved.** The most recent recorded physical outcome
  remains a device timeout, and the host work described here has not superseded
  it. None of the findings above establishes a cause for that timeout, and none
  is a defect in the translated candidate binary — they are defects in the
  **instruments** used to reason about it.
- **A green aggregate still measures the gate implementation** as much as it
  measures readiness. That was the follow-up review's closing observation and
  it remains true even after the mutation suite: the suite shows every gate can
  fail, not that the evidence is complete.
- **No executable inference is demonstrated.** Captured host calls with the
  execution gate off establish requested dispatch order and geometry. They do
  not establish tensor production, synchronisation, network output or image
  correctness.
- **Oracle independence is unestablished**, per section 6.
- **Two reviews are two samples.** A claim that both reviews happened to miss
  is not thereby verified, and the mutation suite in section 3 covers the gates
  this project wrote, not the questions it failed to ask.

## 10. Frozen source records

Neither review document is republished, and both are retained unedited so that
what was claimed at the time remains auditable — including the claims this
project corrected. They are evidence about what was believed, and rewriting
them would destroy that evidence. Where a correction was needed in a
historical project record, it was written as a **separate correction record
against the state at the time the claim was made**, not by editing the record.

Digests of the retained originals, and the verification status of this
document, are recorded in `POST_ASTRA_SOURCE_PROVENANCE.json` alongside this
file.
