# SESSION REPORT — fixture (positive control, Phase 16AW)

> **THIS IS A TEST FIXTURE, NOT A PROJECT REPORT.** It is the KNOWN-GOOD case
> for the Phase-16AW status consistency verifier (revision 3). A checker that
> rejects the case you know is right is not strict, it is broken. This document
> is authored by hand, independently of the verifier's own vocabulary tables, so
> that agreement here is evidence about the verifier rather than a restatement
> of its spec.

**Phase:** 16AW — test fixture for the successor status consistency verifier.
**GPU work:** none. The fixture is a text document; nothing is launched.
**Physical batch:** 5 authorised / 4 spent / **1 remaining**.
**Slot 5:** `HOLD`.
**Publication status:** `PUBLICATION_SYNC_PENDING`.

---

## 1. Operator block

<!-- P16AW_OPERATOR_BLOCK_BEGIN -->
phase = 16AW
candidate_f = J3_TDR_CORRECT_INPUT
candidate_f_cause = UNKNOWN
candidate_f_defect = VOPD_SEQUENTIALIZATION_SEMANTIC_DEFECT
slot5_decision = HOLD
slot5 = NOT_RUN
physical_completion_ever = YES
astra4 = CLAIMS_EXTRACTED
native_liveness = RETIRED_UNSOUND
authentic_job_dag = NOT_READY
capture_only_authorization = VALID
status_verifier = REPAIRED
shipping_bridge = BLOCKED
translation_differential = PARTIAL
gta_capture = UNUSED
publication_status = PUBLICATION_SYNC_PENDING
public_branch = publication-sync/post-astra3-native-16au-20260921
first_frame_contract = 520 / 535
<!-- P16AW_OPERATOR_BLOCK_END -->

## 2. Narrative

Candidate F was launched once under canonical input and was reclaimed by the OS
watchdog. It has not completed, and no numerical result about it exists.

A project-owned control kernel completed on this device in about 0.5 ms. That is
not evidence about Candidate F.

The canonical J3 attempt has not gone untested: it was launched under canonical
input and reclaimed by the watchdog.

Slot 5 remains on hold. The decision record is unchanged, and the retired
24 / 26 gate score is no longer physical authority this phase.

Candidate F's cause is not established: the cause of the Slot-4 watchdog reset
remains unknown, and the 21,198.8 ms timeout's origin is still unexplained.

What 16AW did establish is a defect in the emitted translation. One source
`v_dual` pair at 0xCB8DC is emitted as two adjacent plain VALU instructions in
X-then-Y order, so the second op reads the new value, and 11 of 11 calibrated
control sites reached the observer. That is a measurement of one emitted
instruction stream and of nothing else; it is not a measurement of any executed
result, and it is not evidence about why the kernel was reclaimed.

Astra #4 is preserved and its claims extracted, and it is not fully
dispositioned: 8 of the 16 claims remain open.

The retired 16AT native liveness PASS is unsound. The finite-bound classifier
that produced it discharged all 33 back edges by widening a compare-mnemonic
regex, which changed the match vocabulary rather than proving a recurrence, and
no replacement result exists on disk. The 16AT phrase `native liveness PASS` is
named here, not asserted.

The first-frame contract is 520 / 535.

Publication status is PUBLICATION_SYNC_PENDING. The drift check is a read-only
report and no push was performed this phase.

## 3. What this fixture does NOT say

It does not claim Candidate F completed, it does not claim Slot 5 passed, and it
does not claim the native liveness proofs are discharged. It also does not claim
that the demonstrated VOPD defect is the cause of the watchdog reset: the cause
field stays UNKNOWN and the defect is a separate, narrower measurement.
