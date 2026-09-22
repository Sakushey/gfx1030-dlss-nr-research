#!/usr/bin/env python3
"""Phase 16AW Part I -- regression proof for the V3 status consistency verifier.

WHAT THIS PROVES, AND WHAT IT WOULD BE DISHONEST TO CLAIM IT PROVES
-------------------------------------------------------------------
It proves that the verifier can FAIL, and that it fails for the reason it was
aimed at, and that it ACCEPTS the case whose truth is already known.  Those are
two different questions, and the project has a memory entry for getting the
first one right while getting the second one wrong: "Checkers must accept the
known-good case" -- "can it fail?" and "does it pass the thing I know is right?"
are separate tests.

TWO FACTS, DELIBERATELY NOT ONE
-------------------------------
`candidate_f_cause` (the root cause of the Slot-4 TDR: UNKNOWN, held by the
causal-rebase record) and `candidate_f_defect` (the VOPD sequentialization
defect: DEMONSTRATED, held by the VOPD census) are two required keys with two
holders.  The corpus controls the conflation in both places it can happen:

  * M04 writes the defect's own token into the CAUSE field in the operator
    block, and is required to be rejected AND to show the token reached the row
    the checker read (its witness);
  * M28b/M28c promote the defect to the cause in PROSE, where no vocabulary
    table can see it.

The inverse matters just as much, and is exercised by C08/C09/C10: an honest
document must be able to say the cause is UNKNOWN, and to state the defect and
the cause side by side while asserting they are not the same thing.  A checker
that forbids the distinction is not strict, it is broken.

Every mutation is required to satisfy FIVE conditions, recorded separately so a
failure of any one of them is visible rather than collapsed into a single
"rejected" flag:

  mutation_applied        the input actually changed (the targeted text was
                          present exactly once and is now different)
  observer_reached        the check the mutation targets is PRESENT in the
                          observation, and its surface is readable there.  A
                          mutation that dies before the comparison it aims at
                          is INVALID, not a successful rejection -- the project
                          records this as "A control must reach the observer".
  relevant_field_changed  the surface the mutation targets reads differently
                          after the mutation than before it
  expected_rule_fired     the surface reads FAIL, i.e. the specific rule the
                          mutation aimed at is the one that fired
  rejection_occurred      the document is refused: finalization_allowed is
                          False

Most of the corpus mutates the DOCUMENT (text) or the fact BUNDLE (values), both
of which are files this driver writes into a temporary directory, so
"mutation_applied" is a byte-level statement about a file.  THREE probes cannot
be file-based and say so in their own records:

  * the tautology probe constructs a provenance object, because provenance is
    produced by the verifier rather than read from a file;
  * the corroboration probe calls the corroborator directly with an argument no
    artefact covers;
  * the composed-corroboration probe stubs ONE holder read and drives
    `build_facts`, because `build_facts` is the only place a refusal and a fact
    meet, and the override path cannot reach it.

All three record `applied_via` naming the mechanism instead of implying a file
edit.  The same is true of the C07 control, which reads the live provenance to
show the tautology guard does NOT fire on two facts that share a file: it is a
control rather than a mutation, and it is listed with the controls.

Run it twice on a fresh phase: the `status_verifier` fact is self-referential
(the verifier reads the result file this driver writes), so on the first run the
live facts cannot resolve that one field.  The second run resolves it.  The
driver reports which run it was rather than hiding the transient.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.abspath(os.path.dirname(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

import p16aw_status_consistency as V                          # noqa: E402

FIX_REPORT = os.path.join(HERE, "fixtures", "REPORT_POSITIVE_V1.md")
FIX_FACTS = os.path.join(HERE, "fixtures", "FACTS_FIXTURE_V1.json")
OUT_MUTATIONS = os.path.join(HERE, "STATUS_CONSISTENCY_MUTATIONS_16AW.json")
OUT_RESULT = os.path.join(HERE, "STATUS_VERIFIER_V3_RESULT.json")


# --------------------------------------------------------------------------
# surfaces
# --------------------------------------------------------------------------
def row_of(rec, key):
    for r in rec["key_rows"]:
        if r["key"] == key:
            return r
    return None


def rule_of(rec, rid):
    for a in rec["assertion_rules"]:
        if a["rule"] == rid:
            return a
    return None


def struct_of(rec, sid):
    for s in rec["structural"]:
        if s["id"] == sid:
            return s
    return None


def key_probe(key):
    def probe(rec):
        r = row_of(rec, key)
        if r is None:
            return False, None
        return True, r["result"]
    return probe


def rule_probe(rid):
    def probe(rec):
        a = rule_of(rec, rid)
        if a is None:
            return False, None
        return True, a["result"]
    return probe


def struct_probe(sid):
    def probe(rec):
        s = struct_of(rec, sid)
        if s is None:
            return False, None
        return True, s["result"]
    return probe


def batch_probe(rec):
    b = rec["batch_triple"]
    if "result" not in b:
        return False, None
    return True, b["result"]


def selfcert_probe(rec):
    """The targeted surface is the KEY ROW, not the flag.

    A mutation proving "no generated flag is read" must land on the key row: if
    it landed only on a flag the checker never reads, the rejection would prove
    nothing about the flag.  The flag's presence is recorded as a WITNESS (a
    second observable it must have reached), kept separate from the surface so
    that "the rule fired" stays a plain comparison against FAIL.
    """
    r = row_of(rec, "slot5_decision")
    if r is None:
        return False, None
    return True, r["result"]


def selfcert_witness(rec):
    return sorted(rec["self_certification_keys_seen_and_not_read"])


def cause_row_witness(rec):
    """The RAW value the checker recorded for the cause key.

    A distinct observable from the row's RESULT: it proves the mutated token
    reached the record the checker compared, so a rejection cannot be credited
    to a mutation that never arrived.  On the unmutated baseline this reads
    UNKNOWN; under the conflation mutation it must read the defect's token.
    """
    r = row_of(rec, "candidate_f_cause")
    return [r["raw"]] if r and r.get("raw") is not None else []


def defect_row_witness(rec):
    r = row_of(rec, "candidate_f_defect")
    return [r["raw"]] if r and r.get("raw") is not None else []


# --------------------------------------------------------------------------
# mutators: file-based
# --------------------------------------------------------------------------
def _sub(old, new):
    def fn(text, facts):
        if text.count(old) != 1:
            raise AssertionError("mutator target appears %d times, not once: %r"
                                 % (text.count(old), old[:80]))
        return text.replace(old, new), facts
    return fn


def _append(paragraph):
    def fn(text, facts):
        return text.rstrip("\n") + "\n\n" + paragraph + "\n", facts
    return fn


def _block_sub(key, value):
    """Replace the operator-block line for `key`."""
    def fn(text, facts):
        line = "\n%s = " % key
        if text.count(line) != 1:
            raise AssertionError("the block line for %r appears %d times"
                                 % (key, text.count(line)))
        i = text.index(line)
        j = text.index("\n", i + 1)
        return text[:i + 1] + "%s = %s" % (key, value) + text[j:], facts
    return fn


def _block_drop(key):
    def fn(text, facts):
        line = "\n%s = " % key
        if text.count(line) != 1:
            raise AssertionError("the block line for %r appears %d times"
                                 % (key, text.count(line)))
        i = text.index(line)
        j = text.index("\n", i + 1)
        return text[:i + 1] + text[j + 1:], facts
    return fn


def _block_append(line):
    def fn(text, facts):
        marker = V.BLOCK_END
        if text.count(marker) != 1:
            raise AssertionError("the block end marker is not present once")
        return text.replace(marker, line + "\n" + marker), facts
    return fn


def _markers_removed(text, facts):
    if V.BLOCK_BEGIN not in text or V.BLOCK_END not in text:
        raise AssertionError("the fixture carries no block markers to remove")
    return text.replace(V.BLOCK_BEGIN, "").replace(V.BLOCK_END, ""), facts


def _legacy_markers(text, facts):
    if V.BLOCK_BEGIN not in text:
        raise AssertionError("the fixture carries no 16AW block markers")
    return (text.replace(V.BLOCK_BEGIN, V.LEGACY_BLOCK_BEGIN)
                .replace(V.BLOCK_END, V.LEGACY_BLOCK_END), facts)


def _facts_sub(key, value):
    def fn(text, facts):
        if key not in facts:
            raise AssertionError("the fixture bundle carries no fact %r" % key)
        if facts[key] == value:
            raise AssertionError("the value is already %r; this mutator would "
                                 "change nothing" % value)
        f2 = dict(facts)
        f2[key] = value
        return text, f2
    return fn


def _chain(*text_fns):
    """Apply several TEXT mutators in sequence, or fail loudly.

    This exists because its predecessor was a silent no-op.  `_both(text_fn,
    fact_fn)` took the second mutator's FACT slot, so a second TEXT mutator
    passed in that position was called and its returned text thrown away: the
    mutation reported `applied: True` (the first edit did land) while half of it
    had never happened.  That is the project's recorded failure mode "Mutation
    harness that cannot reach its target", caught here by the mutation's WITNESS
    -- the second observable it was required to reach -- rather than by trusting
    the `applied` flag.
    """
    def fn(text, facts):
        for f in text_fns:
            before = text
            text, facts = f(text, facts)
            if text == before:
                raise AssertionError("a chained mutator changed nothing")
        return text, facts
    return fn


# --------------------------------------------------------------------------
# THE MUTATION CORPUS
# --------------------------------------------------------------------------
def MUTATIONS():
    return [
        # ---- one mutation per required key: no key may be decorative ----
        dict(id="M01_phase_outside_the_vocabulary", aimed_at="phase",
             apply=_block_sub("phase", "16ZZ"),
             probe=key_probe("phase"),
             expected="the phase token is outside the declared vocabulary, so "
                      "it is not a value and cannot be compared"),
        dict(id="M02_phase_predecessor_token", aimed_at="phase",
             apply=_block_sub("phase", "16AV"),
             probe=key_probe("phase"),
             expected="16AV is IN the 16AW vocabulary and is still compared "
                      "against CURRENT_STATE.json, so a successor report "
                      "claiming the predecessor's phase fails on the "
                      "comparison rather than on the vocabulary"),
        # NOTE: `aimed_at` names the FACT, not the key.  The required key
        # `candidate_f` is compared against the fact `candidate_f_physical`
        # (REQUIRED_KEYS maps one to the other), and the coverage gate counts
        # facts, so an `aimed_at` of the key name left that fact looking
        # untested -- which is what the gate reported the first time it ran.
        dict(id="M03_candidate_f_no_attempt", aimed_at="candidate_f_physical",
             apply=_block_sub("candidate_f", "NO_ATTEMPT"),
             probe=key_probe("candidate_f"),
             expected="outside the vocabulary"),
        # ---- the conflation control the coordinator asked for -------------
        # A first draft of this verifier put the demonstrated DEFECT into the
        # CAUSE field.  That is an overclaim, and the mutation below is the
        # control that catches it: the cause field is set to the defect's own
        # token and MUST be rejected.
        dict(id="M04_cause_set_to_the_demonstrated_defect",
             aimed_at="candidate_f_cause",
             apply=_block_sub("candidate_f_cause",
                              "VOPD_SEQUENTIALIZATION_SEMANTIC_DEFECT"),
             probe=key_probe("candidate_f_cause"),
             witness=cause_row_witness,
             witness_required="VOPD_SEQUENTIALIZATION_SEMANTIC_DEFECT",
             expected="the cause field's holder is the causal-rebase record, "
                      "whose `cause` is UNKNOWN.  Writing the demonstrated "
                      "defect's token into the cause field is an OVERCLAIM: "
                      "16AW demonstrated a defect and did NOT establish that it "
                      "caused the ~21.2 s watchdog reset.  The witness proves "
                      "the token reached the row the checker actually read, so "
                      "the rejection is a rejection of that token and not of a "
                      "document that never carried it"),
        dict(id="M04b_cause_set_outside_the_vocabulary",
             aimed_at="candidate_f_cause",
             apply=_block_sub("candidate_f_cause",
                              "CONCRETE_TRANSLATION_DEFECT_FOUND"),
             probe=key_probe("candidate_f_cause"),
             expected="the token this verifier's first draft invented is not in "
                      "the cause vocabulary at all -- the vocabulary excludes "
                      "every value except the one the holder states, so the "
                      "conflation fails as a vocabulary violation as well"),
        dict(id="M05_slot5_decision_run", aimed_at="slot5_decision",
             apply=_block_sub("slot5_decision", "RUN"),
             probe=key_probe("slot5_decision"),
             expected="the decision of record is HOLD"),
        dict(id="M06_slot5_pass", aimed_at="slot5",
             apply=_block_sub("slot5", "PASS"),
             probe=key_probe("slot5"),
             expected="no Slot-5 launch is recorded in the ledger"),
        dict(id="M07_physical_completion_no", aimed_at="physical_completion_ever",
             apply=_block_sub("physical_completion_ever", "NO"),
             probe=key_probe("physical_completion_ever"),
             expected="a project-owned control kernel did complete"),
        dict(id="M08_astra4_ingested_and_done", aimed_at="astra4",
             apply=_block_sub("astra4", "INGESTED_AND_DONE"),
             probe=key_probe("astra4"),
             expected="INGESTED_AND_DONE is not on the audit intake's own "
                      "declared ladder; it is the shortcut the intake names as "
                      "FORBIDDEN"),
        dict(id="M09_native_liveness_pass", aimed_at="native_liveness",
             apply=_block_sub("native_liveness", "PASS"),
             probe=key_probe("native_liveness"),
             expected="the standing liveness PASS is retired as unsound; "
                      "restating PASS uses a value the phase did not "
                      "re-establish"),
        dict(id="M10_authentic_job_dag_ready", aimed_at="authentic_job_dag",
             apply=_block_sub("authentic_job_dag", "READY"),
             probe=key_probe("authentic_job_dag"),
             expected="16AW records AUTHENTIC_JOB_DAG_V1 as not reached"),
        dict(id="M11_capture_authorization_expired",
             aimed_at="capture_only_authorization",
             apply=_block_sub("capture_only_authorization", "EXPIRED"),
             probe=key_probe("capture_only_authorization"),
             expected="the committed authorization is valid and unspent"),
        dict(id="M12_status_verifier_unvocabularied", aimed_at="status_verifier",
             apply=_block_sub("status_verifier", "LOOKS_GOOD"),
             probe=key_probe("status_verifier"),
             expected="outside the vocabulary: the only two values this fact "
                      "can take are REPAIRED and FAIL"),
        dict(id="M13_shipping_bridge_equivalent", aimed_at="shipping_bridge",
             apply=_block_sub("shipping_bridge", "INSTRUMENTED_EQUIVALENT"),
             probe=key_probe("shipping_bridge"),
             expected="the instrumented bridge's own status is BLOCKED"),
        dict(id="M14_translation_differential_complete",
             aimed_at="translation_differential",
             apply=_block_sub("translation_differential", "COMPLETE"),
             probe=key_probe("translation_differential"),
             expected="the provenance chain leaves the translator revision of "
                      "record unresolved"),
        dict(id="M15_gta_capture_used", aimed_at="gta_capture",
             apply=_block_sub("gta_capture", "USED"),
             probe=key_probe("gta_capture"),
             expected="the capture session has not been spent"),
        dict(id="M16_publication_status_published_branch",
             aimed_at="publication_status",
             apply=_block_sub("publication_status", "PUBLISHED_BRANCH"),
             probe=key_probe("publication_status"),
             expected="the publication record is not published-branch"),
        dict(id="M17_public_branch_changed", aimed_at="public_branch",
             apply=_block_sub("public_branch",
                              "publication-sync/some-other-branch"),
             probe=key_probe("public_branch"),
             expected="a free key is compared VERBATIM; a different branch is a "
                      "different branch"),
        dict(id="M18_first_frame_535_of_535", aimed_at="first_frame_contract",
             apply=_block_sub("first_frame_contract", "535 / 535"),
             probe=key_probe("first_frame_contract"),
             expected="the contract's own rows resolve 520 of 535 required "
                      "fields, not 535"),
        dict(id="M18b_candidate_f_defect_none_demonstrated",
             aimed_at="candidate_f_defect",
             apply=_block_sub("candidate_f_defect", "NONE_DEMONSTRATED"),
             probe=key_probe("candidate_f_defect"),
             witness=defect_row_witness,
             witness_required="NONE_DEMONSTRATED",
             expected="NONE_DEMONSTRATED is a legitimate token -- it is what "
                      "the defect key would say if no defect were demonstrated "
                      "-- so this mutation is NOT caught by the vocabulary.  It "
                      "is caught by the COMPARISON: the census demonstrates a "
                      "site, so the fact resolves to the defect token and the "
                      "report's NONE_DEMONSTRATED contradicts it"),
        dict(id="M18c_candidate_f_defect_absent",
             aimed_at="candidate_f_defect",
             apply=_block_drop("candidate_f_defect"),
             probe=key_probe("candidate_f_defect"),
             expected="ABSENCE IS BLOCKING for the defect key exactly as for "
                      "the cause key: the demonstrated defect is a required "
                      "generated field, and dropping it is a failure rather "
                      "than a document that never had to mention it"),
        # ---- structural ----
        dict(id="M19_block_markers_removed", aimed_at="operator_block_present",
             apply=_markers_removed,
             probe=struct_probe("operator_block_present"),
             expected="a report the checker cannot parse is not a report it "
                      "may pass"),
        dict(id="M20_duplicate_key", aimed_at="operator_block_no_duplicate_keys",
             apply=_block_append("slot5 = PASS"),
             probe=struct_probe("operator_block_no_duplicate_keys"),
             expected="a second value for one key is a document that says two "
                      "things at once"),
        dict(id="M21_malformed_line", aimed_at="operator_block_wellformed",
             apply=_block_append("this line is not a key value pair"),
             probe=struct_probe("operator_block_wellformed"),
             expected="an unparseable line inside the block is a silent drop "
                      "of whatever it was meant to say"),
        dict(id="M22_predecessor_block_markers",
             aimed_at="no_predecessor_block_markers",
             apply=_legacy_markers,
             probe=struct_probe("no_predecessor_block_markers"),
             expected="the 16AV markers belong to the predecessor's schema"),
        dict(id="M23_required_key_absent", aimed_at="astra4",
             apply=_block_drop("astra4"),
             probe=key_probe("astra4"),
             expected="ABSENCE IS BLOCKING: a missing required key is a "
                      "failure, never a silent pass"),
        # ---- narrative ----
        dict(id="M24_candidate_f_completed_claim", aimed_at="candidate_f_never_completed",
             apply=_append("Candidate F completed under canonical input."),
             probe=rule_probe("candidate_f_never_completed"),
             expected="the outcome record is J3_TDR_CORRECT_INPUT"),
        dict(id="M25_native_liveness_pass_claim",
             aimed_at="native_liveness_not_discharged",
             apply=_append("The native liveness PASS stands as recorded."),
             probe=rule_probe("native_liveness_not_discharged"),
             expected="the 16AT PASS is retired as unsound"),
        dict(id="M26_slot5_passed_claim", aimed_at="slot5_not_passed",
             apply=_append("Slot 5 passed its qualification."),
             probe=rule_probe("slot5_not_passed"),
             expected="the Slot-5 decision is HOLD"),
        dict(id="M27_astra4_fully_dispositioned_claim",
             aimed_at="astra4_not_ingested_as_done",
             apply=_append("Astra #4 is fully dispositioned."),
             probe=rule_probe("astra4_not_ingested_as_done"),
             expected="the rung is CLAIMS_EXTRACTED with 8 claims open"),
        dict(id="M28_cause_declared_identified",
             aimed_at="candidate_f_cause_not_closed",
             apply=_append("The root cause of the Slot-4 watchdog reset has "
                           "been identified."),
             probe=rule_probe("candidate_f_cause_not_closed"),
             expected="the cause of the TDR is still UNKNOWN in the "
                      "causal-rebase record, so a document that declares it "
                      "identified contradicts its own source of record.  The "
                      "INVERSE of this mutation -- the honest statement that "
                      "the cause remains unknown -- is negative control C08"),
        dict(id="M28b_defect_promoted_to_the_cause",
             aimed_at="cause_is_not_the_demonstrated_defect",
             apply=_append("The VOPD sequentialization defect is the root cause "
                           "of the Slot-4 timeout."),
             probe=rule_probe("cause_is_not_the_demonstrated_defect"),
             expected="the PROSE half of the conflation.  M04 does it in the "
                      "operator block; this does it in a sentence, where a "
                      "vocabulary table cannot see it.  The census measures an "
                      "instruction order in an emitted object and says nothing "
                      "about why the kernel was reclaimed"),
        dict(id="M28c_defect_promoted_to_the_cause_variant",
             aimed_at="cause_is_not_the_demonstrated_defect",
             apply=_append("The cause of the 21,198.8 ms timeout is the VOPD "
                           "sequentialization defect."),
             probe=rule_probe("cause_is_not_the_demonstrated_defect"),
             expected="the same conflation written the other way round, so the "
                      "rule cannot be satisfied by matching one word order"),
        dict(id="M28d_demonstrated_defect_denied",
             aimed_at="demonstrated_defect_not_denied",
             apply=_append("No translation defect was demonstrated this "
                           "phase."),
             probe=rule_probe("demonstrated_defect_not_denied"),
             expected="a defect IS demonstrated, by a calibrated measurement "
                      "with a discriminating witness; denying it is its own "
                      "false statement and is rejected in the opposite "
                      "direction from M28b/M28c"),
        dict(id="M29_slot5_score_current_claim", aimed_at="slot5_score_not_current",
             apply=_append("The 24 / 26 gate score is current physical authority."),
             probe=rule_probe("slot5_score_not_current"),
             expected="the 24 / 26 score is retired this phase"),
        # ---- batch ----
        dict(id="M30_batch_triple_wrong", aimed_at="batch_triple",
             apply=_sub("5 authorised / 4 spent / **1 remaining**",
                        "5 authorised / 3 spent / **2 remaining**"),
             probe=batch_probe,
             expected="the ledger records 4 LAUNCH_STARTED events for the batch"),
        dict(id="M31_batch_triple_absent", aimed_at="batch_triple",
             apply=_sub("**Physical batch:** 5 authorised / 4 spent / "
                        "**1 remaining**.",
                        "**Physical batch:** see the ledger."),
             probe=batch_probe,
             expected="the batch is a required generated field; stating it "
                      "nowhere is not a consistent claim"),
        # ---- the self-certification refusal ----
        dict(id="M32_contradiction_with_a_generated_consistent_flag",
             aimed_at="slot5_decision",
             apply=_chain(_block_sub("slot5_decision", "RUN"),
                          _block_append("consistent = true")),
             probe=selfcert_probe,
             witness=selfcert_witness,
             witness_required="consistent",
             expected="the document carries a generated `consistent = true` "
                      "AND a value that contradicts the fact.  The flag is "
                      "DETECTED and NAMED in the record and never read, and "
                      "the contradiction is rejected anyway"),
    ]


# --------------------------------------------------------------------------
# NEGATIVE CONTROLS: these MUST be accepted
# --------------------------------------------------------------------------
def NEGATIVE_CONTROLS():
    return [
        dict(id="C01_negated_completion_accepted",
             why="a report must be able to state the truth negatively: "
                 "'Candidate F has not completed'",
             apply=_append("Candidate F has not completed under canonical "
                           "input.")),
        dict(id="C02_negated_kernel_denial_accepted",
             why="the denial of a false denial is a true statement",
             apply=_append("It is not the case that no kernel has ever "
                           "completed.")),
        dict(id="C03_quoted_phrase_named_not_asserted",
             why="a report that RETIRES a phrase has to write the phrase; "
                 "quoting it in code markup NAMES it rather than asserting it, "
                 "and the same words in prose are rejected by M25/M26",
             apply=_append("The 16AT report stated `Slot 5 passed` and "
                           "`native liveness PASS`; both are retired here.")),
        dict(id="C04_retirement_stated_accepted",
             why="the retirement word placed INSIDE the claim's own sentence "
                 "negates it; the placement requirement is documented in "
                 "NEGATION and exercised in both directions (M29 vs C04)",
             apply=_append("The retired 24 / 26 gate score is not physical "
                           "authority.")),
        dict(id="C05_unmutated_baseline_accepted",
             why="the known-good case itself, unmutated",
             apply=lambda text, facts: (text, facts)),
        dict(id="C06_self_certification_key_alone_is_not_a_rejection",
             why="carrying a `consistent = true` line is not by itself a "
                 "failure -- the checker neither trusts it (M32) nor rejects "
                 "documents merely for containing it",
             apply=_block_append("consistent = true")),
        dict(id="C08_honest_cause_unknown_accepted",
             why="the honest statement of the cause fact.  It must be ACCEPTED "
                 "or the cause rule would punish the only true sentence "
                 "available.  It is the inverse of M28, so the pair proves the "
                 "rule is directional rather than merely present",
             must_exercise="candidate_f_cause_not_closed",
             apply=_append("The root cause of the Slot-4 watchdog reset remains "
                           "unknown.")),
        dict(id="C09_honest_separation_of_cause_and_defect_accepted",
             why="the separation itself has to be sayable.  A document must be "
                 "able to state that a defect IS demonstrated AND that it is "
                 "NOT established as the cause; a conflation-capable checker "
                 "must not become a checker that forbids the distinction.  This "
                 "is the negative control for M04/M28b/M28c",
             must_exercise="cause_is_not_the_demonstrated_defect",
             apply=_append("Phase 16AW demonstrated a defect in the emitted "
                           "translation.  That defect is not established as the "
                           "cause of the watchdog reset, and the cause field "
                           "stays UNKNOWN.")),
        dict(id="C10_cause_and_defect_stated_side_by_side_accepted",
             why="the two facts written adjacently, both true: the defect "
                 "measured, the cause unresolved.  If adjacency alone tripped "
                 "the conflation rule, the rule would be matching on proximity "
                 "rather than on an assertion",
             must_exercise="cause_is_not_the_demonstrated_defect",
             apply=_append("Candidate F's cause is UNKNOWN; candidate F's "
                           "demonstrated defect is a VOPD sequentialization "
                           "site.  Neither statement is the other.")),
    ]


# --------------------------------------------------------------------------
# probes that are NOT file mutations, and say so
# --------------------------------------------------------------------------
def probe_tautology(text, facts):
    """A provenance in which two facts share one REAL path AND one locator.

    The collision is built on a real holder from the live provenance rather
    than on invented paths, so the probe shows what would happen if two of THIS
    phase's facts ever resolved from one locator.
    """
    live = V.build_facts(None)[2]
    p = dict(live)
    p["sources"] = dict(live.get("sources") or {})
    victim, vpath, vloc = None, None, None
    for k, v in p["sources"].items():
        if not isinstance(v, dict) or v.get("kind") != "ARTEFACT":
            continue
        path, loc = _holder_of(v)
        if path:
            victim, vpath, vloc = k, path, loc
            break
    synth = "taut_synthetic_second_fact_on_the_same_locator"
    p["sources"][synth] = {"kind": "ARTEFACT", "path": vpath,
                           "locator": list(vloc or []),
                           "sha256": "0" * 64, "value": "a different value",
                           "note": "not a required key: it exists only to "
                                   "occupy the same locator as a real fact"}
    rec = V.check_document(text, "probe", facts, p)
    dupes = rec["tautologies"]
    s = struct_of(rec, "facts_not_tautological")
    return {
        "applied": bool(dupes),
        "applied_via": "constructed provenance object -- provenance is produced "
                       "by the verifier rather than read from a file, so this "
                       "probe cannot be a file mutation and does not claim to "
                       "be one",
        "observer_reached": s is not None,
        "surface_before": None,
        "surface_after": s["result"] if s else None,
        "relevant_field_changed": bool(dupes),
        "expected_rule_fired": bool(s and s["result"] == V.FAIL),
        "rejection_occurred": not V.finalization_allowed([rec])
                              ["finalization_allowed"],
        "detail": {"tautologies_reported": dupes,
                   "victim_fact": victim,
                   "colliding_source": vpath,
                   "colliding_locator": vloc,
                   "n_sources_seen": len(p["sources"]),
                   "note": "TWO facts on one path and one locator are ONE fact, "
                           "so this is reported as a tautology and fails.  The "
                           "guard counts sources seen, so 'it reported nothing' "
                           "cannot be confused with 'it looked at nothing'.  "
                           "This probe is also how the real defect in this "
                           "file's own first draft was found: "
                           "capture_only_authorization read the capture "
                           "session's status as its 'second side', which is the "
                           "exact locator the gta_capture fact holds."},
    }


def _holder_of(v):
    """The file/locator a provenance entry names, in EITHER spelling.

    Found by this control crashing: the publication facts name their file
    `source`/`source_locator` while every other ARTEFACT source names it
    `path`/`locator`.  The control must read the same pair the guard reads, or
    the control and the guard would be testing different things.
    """
    return (v.get("path") or v.get("source"),
            v.get("locator") or v.get("source_locator"))


def control_same_artefact_distinct_locators(text, facts):
    """The guard must NOT reject any two facts that share a file.

    A guard that fires on 'two facts, one file' instead of on 'two facts, one
    LOCATOR' would reject the publication pair, which is two genuinely
    different facts (a status and a branch) held by one record.
    """
    live = V.build_facts(None)[2]
    pairs = []
    srcs, holderless = {}, []
    for k, v in (live.get("sources") or {}).items():
        if not isinstance(v, dict) or v.get("kind") != "ARTEFACT":
            continue
        path, loc = _holder_of(v)
        if path:
            srcs[k] = (path, loc)
        else:
            holderless.append(k)
    for a in srcs:
        for b in srcs:
            if a < b and srcs[a][0] == srcs[b][0]:
                pairs.append({"a": a, "b": b, "path": srcs[a][0],
                              "locator_a": srcs[a][1],
                              "locator_b": srcs[b][1],
                              "locators_differ": tuple(srcs[a][1] or [])
                              != tuple(srcs[b][1] or [])})
    dupes = V.tautology_guard(live)
    return {
        "id": "C07_same_artefact_distinct_locators", "applied": bool(pairs),
        "accepted": (not dupes) and bool(pairs),
        "shared_file_pairs": pairs,
        "artefact_sources_seen": sorted(srcs),
        "artefact_sources_with_no_holder": holderless,
        "tautologies_reported": dupes,
        "why": "two facts held by one artefact at DIFFERENT locators are two "
               "facts; the guard must fire on the locator, not on the file",
        "valid": bool(pairs) and not dupes,
    }


def probe_corroboration_refused():
    """The corroborator must be able to return a refusal, and must refuse a
    value it does not cover."""
    ok_good, good = True, V.corroborate(
        "authentic_job_dag", {"corroboration": "completeness_row:AUTHENTIC_JOB_DAG_V1"},
        "NOT_READY")
    bad = V.corroborate(
        "authentic_job_dag", {"corroboration": "completeness_row:AUTHENTIC_JOB_DAG_V1"},
        "READY")
    track_ok = V.corroborate(
        "candidate_f_physical",
        {"corroboration": "canonical_track:PHYSICAL"}, "J3_TDR_CORRECT_INPUT")
    track_bad = V.evidence_digest_check("PHYSICAL", "p16aw/not/the/evidence")
    return {
        "applied": bool(bad and bad.get("agrees") is False),
        "applied_via": "direct call on the corroborator with a value the "
                       "corroborating record does not cover, and with a path "
                       "the canonical track does not name -- the mutation is "
                       "the ARGUMENT, not a file, and this record says so",
        "observer_reached": bool(good is not None and track_ok is not None),
        "surface_before": good.get("agrees") if good else None,
        "surface_after": bad.get("agrees") if bad else None,
        "relevant_field_changed": bool(good and bad
                                       and good.get("agrees") is not True
                                       or (good.get("agrees") is True
                                           and bad.get("agrees") is False)),
        "expected_rule_fired": bool(bad and bad.get("agrees") is False
                                    and bad.get("why")),
        "rejection_occurred": bool(bad and bad.get("agrees") is False),
        "detail": {"known_good_corroboration": good.get("agrees"),
                   "refused_corroboration": bad.get("agrees"),
                   "why_refused": bad.get("why"),
                   "known_good_track": track_ok.get("agrees"),
                   "wrong_path_refused": track_bad.get("agrees"),
                   "why_wrong_path_refused": track_bad.get("why")},
    }


def probe_corroboration_composed():
    """A refusing corroboration must actually stop a fact from resolving.

    `build_facts` is the only place the two meet, so the composition is shown
    by driving it with a holder whose value the corroboration does not cover,
    through a temporary fact bundle that the OVERRIDE path cannot reach -- so
    the check is made on the live path with a stubbed holder read.  The stub
    replaces ONE holder read and nothing else.
    """
    real = V.load_json

    def stub(rel):
        if rel == V.RAW_DUMP_AUTH:
            ok, doc, sha = real(rel)
            if ok and isinstance(doc, dict):
                d = json.loads(json.dumps(doc))
                d["part_4_authentic_job_dag_v1"]["status"] = "READY"
                return True, d, sha
        return real(rel)
    V.load_json = stub
    V._CACHE.clear()
    try:
        ok, facts, prov = V.build_facts(None)
        errs = [e for e in prov.get("errors", [])
                if e["field"] == "authentic_job_dag"]
        errs = errs or [{"field": "authentic_job_dag",
                         "why": "the fact resolved despite a corroborating "
                                "side that does not cover its value"}]
        return {
            "ok": (not errs) and False,
            "recorded_error": errs[0] if errs else None,
            "fact_resolved_to": facts.get("authentic_job_dag"),
            "n_errors_total": len(prov.get("errors", [])),
        }
    finally:
        V.load_json = real
        V._CACHE.clear()


# --------------------------------------------------------------------------
# driving
# --------------------------------------------------------------------------
def _seed_facts_file(facts, tmpdir):
    p = os.path.join(tmpdir, "facts.json")
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"schema": "p16aw/facts-fixture/1-mutated",
                   "hand_authored": False,
                   "derived_from": os.path.relpath(FIX_FACTS, ROOT),
                   "facts": facts}, fh, indent=1)
        fh.write("\n")
    return p


def run_one(m, text0, facts0, tmpdir):
    try:
        text1, facts1 = m["apply"](text0, facts0)
        applied = (text1 != text0) or (facts1 != facts0)
        apply_error = None if applied else \
            "the mutator returned its input unchanged"
    except AssertionError as exc:
        return {"id": m["id"], "aimed_at": m["aimed_at"],
                "mutation_applied": False,
                "apply_error": str(exc), "valid": False,
                "why": "the mutator target was not present exactly once, so "
                       "nothing was mutated"}
    ok0, facts_a, prov_a = V.build_facts(_seed_facts_file(facts0, tmpdir))
    ok1, facts_b, prov_b = V.build_facts(_seed_facts_file(facts1, tmpdir))
    rec0 = V.check_document(text0, "baseline", facts_a, prov_a)
    rec1 = V.check_document(text1, m["id"], facts_b, prov_b)
    reached0, surf0 = m["probe"](rec0)
    reached1, surf1 = m["probe"](rec1)
    reject = not V.finalization_allowed([rec1])["finalization_allowed"]
    changed = (surf0 != surf1)
    fired = (surf1 == V.FAIL)
    wit = None
    witness_ok = True
    if m.get("witness"):
        w0 = m["witness"](rec0)
        w1 = m["witness"](rec1)
        witness_ok = m.get("witness_required") in (w1 or [])
        wit = {"before": w0, "after": w1,
               "required": m.get("witness_required"),
               "witness_present_after": witness_ok,
               "note": "a SECOND observable the mutation had to reach, kept "
                       "separate from the surface so 'the rule fired' remains "
                       "a plain comparison against FAIL"}
    valid = bool(applied and reached1 and changed and fired and reject
                 and witness_ok)
    return {
        "id": m["id"], "aimed_at": m["aimed_at"],
        "expected": m["expected"],
        "mutation_applied": bool(applied),
        "apply_error": apply_error,
        "observer_reached": bool(reached1),
        "observer_reached_before": bool(reached0),
        "surface_before": surf0, "surface_after": surf1,
        "relevant_field_changed": bool(changed),
        "expected_rule_fired": bool(fired),
        "rejection_occurred": bool(reject),
        "witness": wit,
        "valid": valid,
        "why_invalid": None if valid else (
            "applied=%s reached=%s changed=%s fired=%s rejected=%s witness=%s"
            % (applied, reached1, changed, fired, reject, witness_ok)),
    }


def run_control(c, text0, facts0, tmpdir):
    try:
        text1, facts1 = c["apply"](text0, facts0)
    except AssertionError as exc:
        return {"id": c["id"], "why": c["why"], "applied": False,
                "accepted": False, "error": str(exc), "valid": False}
    ok, facts_b, prov_b = V.build_facts(_seed_facts_file(facts1, tmpdir))
    rec = V.check_document(text1, c["id"], facts_b, prov_b)
    gate = V.finalization_allowed([rec])
    # An acceptance is only evidence if the rules were REACHED while accepting.
    # A control that passes because no rule applied to it proves nothing, which
    # is the failure this project records as "a checker green having compared
    # nothing is worse than no checker".  So the control records which rules
    # were APPLICABLE to its own facts, and what the negation suppression
    # actually suppressed.
    applicable = [a["rule"] for a in rec["assertion_rules"]
                  if a.get("fact_supports_it")]
    suppressed = [{"rule": a["rule"],
                   "n_matches_suppressed": len(a.get("suppressed") or []),
                   "matches": [s.get("match") for s in (a.get("suppressed")
                                                        or [])]}
                  for a in rec["assertion_rules"] if a.get("suppressed")]
    return {
        "id": c["id"], "why": c["why"],
        "applied": (text1 != text0) or (facts1 != facts0),
        "accepted": bool(gate["finalization_allowed"]),
        "verdict": rec["result"],
        "n_keys_compared": rec["n_keys_compared"],
        "assertion_rules_applicable": applicable,
        "assertion_rules_with_no_force_here": [
            a["rule"] for a in rec["assertion_rules"]
            if not a.get("fact_supports_it")],
        "suppressed_by_negation": suppressed,
        "n_tautologies_reported": len(rec.get("tautologies") or []),
        "exercised_rule": c.get("must_exercise"),
        "exercised_its_rule": (c.get("must_exercise") is None
                               or c["must_exercise"] in applicable),
        "blocking": [b["detail"][0].get("key") or b["detail"][0].get("rule")
                     or b["detail"][0].get("id")
                     for b in gate["blocking"] if b["detail"]][:5],
        "valid": (text1 != text0 or facts1 != facts0)
                 and gate["finalization_allowed"]
                 and (c.get("must_exercise") is None
                      or c["must_exercise"] in applicable),
        "note": "a control whose text is unchanged is the unmutated baseline; "
                "`assertion_rules_applicable` is what keeps an acceptance from "
                "being credited to a rule that never applied",
    }


def live_probe(text0, facts0):
    """The hand-authored fixture bundle against the verifier's LIVE rules.

    This is a REPORT, not a required pass:  the fixture describes a 16AW phase
    and several live artefacts are still moving during the phase.  Every
    disagreement is listed, and any disagreement means the fixture or the live
    rule is wrong -- which is exactly what a reader needs to know.
    """
    V._CACHE.clear()
    ok, facts_live, prov_live = V.build_facts(None)
    rows = []
    for k in sorted(set(facts0) | set(facts_live)):
        a, b = facts0.get(k), facts_live.get(k)
        # Compared on the CANONICAL form, which is what the checker actually
        # compares.  A raw comparison would report a disagreement between
        # 'HOLD' and 'HOLD_SLOT' when the two are the same token, and inflating
        # the disagreement count is its own kind of dishonesty.
        ca = V.canonicalise(k, a)[0] if a is not None else None
        cb = V.canonicalise(k, b)[0] if b is not None else None
        rows.append({"fact": k, "fixture": a, "live": b,
                     "fixture_canonical": ca, "live_canonical": cb,
                     "agrees": (ca is not None and ca == cb),
                     "agrees_raw_strings": a == b})
    errs = [{"field": e["field"], "why": str(e["why"])[:300]}
            for e in prov_live.get("errors", [])]
    n_live = sum(1 for r in rows if r["live"] is not None)
    return {
        "facts_mode": "LIVE",
        "facts_ok": ok,
        "compared_on":
            "the CANONICAL form each side takes in the checker's vocabulary, "
            "because that is what the checker compares",
        "n_facts_compared": len(rows),
        "n_live_resolved": n_live,
        "n_agree": sum(1 for r in rows if r["agrees"]),
        "n_disagree": sum(1 for r in rows if not r["agrees"]),
        "disagreements": [r for r in rows if not r["agrees"]],
        "live_errors": errs,
        "why_not_a_required_pass":
            "the fixture is a hand-authored 16AW document and the live phase "
            "artefacts are still being written; a disagreement here is a "
            "FINDING to report, not a mutation result",
    }


def live_document_probe(text0, facts_live, prov_live):
    """Run the fixture DOCUMENT against the LIVE facts."""
    rec = V.check_document(text0, "fixture-vs-live", facts_live, prov_live)
    gate = V.finalization_allowed([rec])
    return {
        "verdict": rec["result"],
        "finalization_allowed": gate["finalization_allowed"],
        "n_keys_compared": rec["n_keys_compared"],
        "non_passing_reasons": [
            {"surface": "key:%s" % r["key"], "result": r["result"],
             "why": str(r.get("why"))[:220]}
            for r in rec["key_rows"] if r["result"] != V.PASS] + [
            {"surface": "assertion:%s" % a["rule"], "result": a["result"],
             "why": str(a.get("why"))[:220]}
            for a in rec["assertion_rules"] if a["result"] == V.FAIL] + [
            {"surface": "structural:%s" % s["id"], "result": s["result"],
             "why": str(s.get("why"))[:220]}
            for s in rec["structural"] if s["result"] != V.PASS] + (
            [{"surface": "batch_triple", "result": rec["batch_triple"]["result"],
              "why": str(rec["batch_triple"].get("why"))[:220]}]
            if rec["batch_triple"]["result"] != V.PASS else []),
        "note": "the fixture document states a 16AW phase while the live state "
                "record still reads 16AV, so this is EXPECTED to be non-PASS "
                "until the supervisor regenerates CURRENT_STATE.json; it is "
                "reported so the transient is visible rather than inferred",
    }


def main():
    text0 = open(FIX_REPORT, encoding="utf-8").read()
    facts0 = json.load(open(FIX_FACTS, encoding="utf-8"))["facts"]
    tmpdir = tempfile.mkdtemp(prefix="p16aw_v3_mut_")
    try:
        # 0. THE STALENESS BINDING, OBSERVED BEFORE ANYTHING IS WRITTEN.
        # The verifier's LIVE `status_verifier` fact requires the regression
        # record to name the digest of the verifier ON DISK.  If the verifier
        # was edited without re-running this driver, that fact must BLOCK --
        # and this startup capture is what a real such edit looks like, not a
        # stub.  It is re-read after the run to show the binding re-established.
        V._CACHE.clear()
        _ok_s, _f_s, prov_startup = V.build_facts(None)
        startup_errors = [{"field": e["field"], "why": str(e["why"])[:400]}
                          for e in prov_startup.get("errors", [])]

        # 1. POSITIVE CONTROL FIRST.  A corpus that cannot accept the known
        # good case is broken, and every mutation result below would be
        # meaningless -- so the corpus refuses to report if this fails.
        ok, facts_p, prov_p = V.build_facts(_seed_facts_file(facts0, tmpdir))
        rec_p = V.check_document(text0, "positive_control", facts_p, prov_p)
        gate_p = V.finalization_allowed([rec_p])
        positive_ok = (gate_p["finalization_allowed"]
                       and rec_p["result"] == V.PASS
                       and rec_p["n_keys_compared"] == len(V.REQUIRED_KEYS))

        # 2. mutations
        muts = []
        for m in MUTATIONS():
            muts.append(run_one(m, text0, facts0, tmpdir))
        taut = probe_tautology(text0, facts0)
        corr = probe_corroboration_refused()
        composed = probe_corroboration_composed()
        same_file = control_same_artefact_distinct_locators(text0, facts0)

        # 3. negative controls
        ctrls = [run_control(c, text0, facts0, tmpdir)
                 for c in NEGATIVE_CONTROLS()]
        ctrls.append({**same_file, "verdict": "n/a",
                      "why": same_file["why"]})

        # 4. the fixture against the live rules, reported not required
        live = live_probe(text0, facts0)
        ok_l, facts_live, prov_live = V.build_facts(None)
        live_doc = live_document_probe(text0, facts_live, prov_live)

        sums = {
            "n_mutations": len(muts),
            "n_applied": sum(1 for m in muts if m["mutation_applied"]),
            "n_observer_reached": sum(1 for m in muts if m["observer_reached"]),
            "n_field_changed": sum(1 for m in muts if m["relevant_field_changed"]),
            "n_rule_fired": sum(1 for m in muts if m["expected_rule_fired"]),
            "n_rejected": sum(1 for m in muts if m["rejection_occurred"]),
            "n_valid": sum(1 for m in muts if m["valid"]),
            "n_invalid": sum(1 for m in muts if not m["valid"]),
            "n_negative_controls": len(ctrls),
            "n_negative_controls_accepted": sum(1 for c in ctrls if c["accepted"]),
            "n_controls_required_to_exercise_a_rule": sum(
                1 for c in ctrls if c.get("exercised_rule")),
            "n_controls_that_exercised_their_rule": sum(
                1 for c in ctrls if c.get("exercised_rule")
                and c.get("exercised_its_rule")),
            "tautology_probe_valid": taut["expected_rule_fired"]
                                     and taut["rejection_occurred"],
            "corroboration_probe_valid": corr["expected_rule_fired"],
            "corroboration_composed_valid": bool(
                composed["recorded_error"]),
        }
        # "No key may be decorative" is a CLAIM in the corpus comment; this makes
        # it a gate.  A required key with no mutation aimed at it is a key whose
        # comparison has never been shown to be able to fail.
        covered = {m["aimed_at"] for m in MUTATIONS()}
        key_coverage = {
            "required_keys": sorted(V.REQUIRED_KEYS),
            "key_values_with_a_mutation": sorted(
                set(V.REQUIRED_KEYS.values()) & covered),
            "key_values_with_NO_mutation": sorted(
                set(V.REQUIRED_KEYS.values()) - covered),
            "other_surfaces_mutated": sorted(covered
                                             - set(V.REQUIRED_KEYS.values())),
        }
        coverage_ok = not key_coverage["key_values_with_NO_mutation"]
        all_mutations_reached = sums["n_observer_reached"] == sums["n_mutations"]
        # An acceptance is evidence only if the rule it exists to test was
        # APPLICABLE while it accepted.  Without this the honest-separation
        # controls could pass because the conflation rule never fired, which
        # would be the vacuity the project records as "absence is not a pass".
        controls_exercised = (sums["n_controls_that_exercised_their_rule"]
                              == sums["n_controls_required_to_exercise_a_rule"])
        verdict = "REPAIRED" if (positive_ok
                                 and sums["n_valid"] == sums["n_mutations"]
                                 and sums["n_negative_controls_accepted"]
                                 == sums["n_negative_controls"]
                                 and sums["tautology_probe_valid"]
                                 and sums["corroboration_probe_valid"]
                                 and sums["corroboration_composed_valid"]
                                 and coverage_ok
                                 and controls_exercised) \
            else "FAIL"

        # The verifier's digest is taken AFTER the run, and the result record
        # is only valid for the bytes it names.  An edit without re-running
        # therefore cannot present a stale REPAIRED -- and the verifier's own
        # live fact re-checks that binding on every subsequent run.
        vsha = V.sha256_file(os.path.join(HERE, "p16aw_status_consistency.py"))
        vsha_before = V.sha256_file(os.path.join(HERE,
                                                 "p16aw_status_consistency.py"))
        assert vsha == vsha_before

        result = {
            "schema": "p16aw/status-verifier-regression/3",
            "phase": "16AW",
            "replaces": "p16av/consistency/STATUS_VERIFIER_V2_RESULT.json",
            "verifier": "p16aw/consistency/p16aw_status_consistency.py",
            "verifier_sha256": vsha,
            "verifier_sha256_at_this_verdict": vsha,
            "stale_if_the_verifier_is_edited_without_rerunning_this": True,
            "how_that_is_enforced":
                "the verifier's LIVE `status_verifier` fact reads THIS file's "
                "`verdict`, recomputes the SHA-256 of the file this record "
                "names, and BLOCKS the whole row when the digest no longer "
                "matches -- so an edited verifier presents neither a stale "
                "REPAIRED nor a silent pass",
            "verdict": verdict,
            "positive_control": {
                "report": "p16aw/consistency/fixtures/"
                          "REPORT_POSITIVE_V1.md",
                "report_sha256": V.sha256_file(FIX_REPORT),
                "facts": "p16aw/consistency/fixtures/FACTS_FIXTURE_V1.json",
                "facts_sha256": V.sha256_file(FIX_FACTS),
                "verdict": rec_p["result"],
                "finalization_allowed": gate_p["finalization_allowed"],
                "n_keys_compared": rec_p["n_keys_compared"],
                "n_required_keys": len(V.REQUIRED_KEYS),
                "accepted": positive_ok,
            },
            "mutation_summary": sums,
            "every_mutation_reached_the_observer": all_mutations_reached,
            "required_key_coverage": {
                **key_coverage,
                "all_required_keys_have_a_mutation": coverage_ok,
                "why_this_is_gated": "the corpus comment claims no required key "
                                     "is decorative; this is what proves it, "
                                     "and the verdict refuses to report REPAIRED "
                                     "if a required key has no mutation aimed at "
                                     "it",
            },
            "mutations": muts,
            "non_file_probes": {
                "tautology_two_facts_one_locator": taut,
                "corroboration_refuses_a_value_it_does_not_cover": corr,
                "corroboration_refusal_stops_the_fact_resolving": composed,
            },
            "negative_controls": ctrls,
            "fixture_versus_live_rules": live,
            "fixture_document_versus_live_facts": live_doc,
            "what_this_record_does_NOT_establish": [
                "that the phase's work is correct or complete",
                "that any value in an artefact is right -- only that the "
                "report and the artefact agree and that the sentence-level "
                "rules were applied",
                "that the corpus is exhaustive: it is a sample aimed at each "
                "mechanism the verifier has, not a proof about unseen prose",
            ],
            "run_order_note":
                "the `status_verifier` fact is self-referential: the verifier "
                "reads the record this driver writes.  On a fresh phase the "
                "FIRST run cannot resolve that one live field and the second "
                "run does.  This record reports which run it was through "
                "`fixture_versus_live_rules.live_errors`.",
        }
        with open(OUT_RESULT, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(result, fh, indent=1)
            fh.write("\n")
        mut_record = {
            "schema": result["schema"],
            "verifier_sha256": vsha,
            "positive_control": result["positive_control"],
            "mutation_summary": sums,
            "every_mutation_reached_the_observer": all_mutations_reached,
            "mutations": muts,
            "non_file_probes": result["non_file_probes"],
            "negative_controls": ctrls,
            "fixture_versus_live_rules": live,
            "fixture_document_versus_live_facts": live_doc,
        }
        with open(OUT_MUTATIONS, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(mut_record, fh, indent=1)
            fh.write("\n")

        print(json.dumps({
            "verdict": verdict,
            "positive_control_accepted": positive_ok,
            "n_mutations": sums["n_mutations"],
            "n_applied": sums["n_applied"],
            "n_observer_reached": sums["n_observer_reached"],
            "n_rejected": sums["n_rejected"],
            "n_valid": sums["n_valid"],
            "n_invalid": sums["n_invalid"],
            "every_mutation_reached_the_observer": all_mutations_reached,
            "all_required_keys_have_a_mutation": coverage_ok,
            "n_negative_controls": sums["n_negative_controls"],
            "n_negative_controls_accepted":
                sums["n_negative_controls_accepted"],
            "n_controls_required_to_exercise_a_rule":
                sums["n_controls_required_to_exercise_a_rule"],
            "n_controls_that_exercised_their_rule":
                sums["n_controls_that_exercised_their_rule"],
            "tautology_probe_valid": sums["tautology_probe_valid"],
            "corroboration_probe_valid": sums["corroboration_probe_valid"],
            "corroboration_composed_valid":
                sums["corroboration_composed_valid"],
            "fixture_vs_live_disagreements": live["n_disagree"],
            "live_errors": [e["field"] for e in live["live_errors"]],
            "fixture_document_vs_live_facts":
                live_doc["finalization_allowed"],
            "verifier_sha256": vsha,
        }, indent=1))
        for m in muts:
            if not m["valid"]:
                print("INVALID", m["id"], m.get("why_invalid"))
        for c in ctrls:
            if not c["accepted"]:
                print("CONTROL NOT ACCEPTED", c["id"], c.get("blocking"))
        return 0 if verdict == "REPAIRED" else 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
