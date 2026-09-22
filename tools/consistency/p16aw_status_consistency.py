#!/usr/bin/env python3
"""Phase 16AW Part I -- status consistency verifier, revision 3 (V3).

WHY THIS FILE EXISTS (AND WHY IT IS A VERSIONED SUCCESSOR)
----------------------------------------------------------
`p16av/consistency/p16av_status_consistency.py` is the Phase-16AV verifier
of record.  It is preserved unmodified.  It CANNOT serve Phase 16AW, and the
reason is structural rather than cosmetic:

  * its VOCAB declares `"phase": [("16AV", [r"^16AV$"])]`, so a Phase-16AW
    report states a token outside its declared vocabulary;
  * its PHASE_FACT_SOURCES point at 16AV-only artefacts
    (`p16av/bridge/INSTRUMENTED_BRIDGE_STATUS.json`,
    `p16av/candidate_f/CANDIDATE_F_TRANSLATION_DIFFERENTIAL_V1.json`,
    `p16av/state/GTA_CAPTURE_SESSION.json`,
    `p16av/publication/PUBLICATION_16AV.json`,
    `p16av/consistency/STATUS_VERIFIER_V2_RESULT.json`);
  * and, measured while porting, one of its live fact sources has since been
    RETIRED BY THE PROJECT ITSELF: 16AW's provenance chain records
    `p16av/candidate_f/CANDIDATE_F_TRANSLATION_DIFFERENTIAL_V1.json` as
    `SUPERSEDED_WRONG_PARENT`.  Reading a current fact off an artefact the
    project has retired is exactly the defect this project already records as
    "a verdict is scoped to the artefact it read".

The project's established pattern is that a phase which changes the schema
produces a versioned successor rather than editing the frozen predecessor:
`p16af/consistency/p16af_status_consistency.py` is preserved beside 16AV's
as `KNOWN_BROKEN_BASELINE_NOT_USED`.  16AV's checker is preserved byte-exact
beside this one as the Phase-16AV verifier of record, and this file is its
16AW successor.  The predecessor's own vacuity was measured, not asserted:
`p16av/consistency/OLD_VERIFIER_FALSE_NEGATIVE_16AV.json`.

WHAT IS INHERITED UNCHANGED (the mechanisms that made 16AV work)
----------------------------------------------------------------
1.  A report the checker cannot parse is NOT a report it may pass.  The report
    must carry a delimited OPERATOR BLOCK of `key = value` lines
    (`<!-- P16AW_OPERATOR_BLOCK_BEGIN -->` ... `_END_ -->`).
2.  Absence is BLOCKING.  A missing key, an unreadable fact source, a locator
    that does not resolve, a value outside the declared vocabulary, and a fact
    that resolves only from an artefact the project has retired are all
    failures.  There is no path on which "the checker observed nothing" is
    green.
3.  Two independent sides.  Facts come from primary artefacts; statements come
    from the report.  No comparison is derived from one source, and the checker
    ASSERTS that property: two facts sharing one source path AND one locator
    are reported as a tautology and fail the run.
4.  Directional narrative rules with negation suppression, so a true denial
    ("Candidate F has not completed") is accepted and the opposite claim is
    not.
5.  No generated `consistent` flag is ever read.  Consistency is recomputed
    from the facts.  The mutation corpus proves this by supplying
    `consistent: true` together with a contradiction and requiring rejection.

WHAT IS DELIBERATELY EXTENDED FOR 16AW, AND WHY
-----------------------------------------------
E1. `phase` accepts 16AW AND 16AV.  The report is a 16AW report; the token is
    still COMPARED against CURRENT_STATE.json, so accepting two tokens widens
    nothing -- it only lets a report be truthful during the window in which
    CURRENT_STATE.json still carries 16AV.  A report that states 16AW while
    CURRENT_STATE says 16AV FAILS, which is the correct, blocking outcome.

E2. `astra4` gains the ladder rungs.  Phase 16AW established a state that the
    16AV vocabulary could not name.  The 16AV table held only NOT_RECEIVED and
    INGESTED, so a 16AW report would have to claim either "no audit arrived"
    (false) or "the audit is ingested" (the exact shortcut
    `p16aw/audit/ASTRA4_INTAKE.json` names as FORBIDDEN).  The rungs are
    taken from the intake's OWN declared ladder
    (`status_ladder.vocabulary`), not invented here.  The 16AV token INGESTED
    is retained so the older vocabulary still parses.

E3. `native_liveness` gains RETIRED_UNSOUND and the 16AV rule is RETIRED, not
    ported.  16AV derived PASS from `p16at/native/liveness/MACHINE_CFG.json`
    by the rule "every back edge is a natural loop back edge".  16AW's own
    claim ledger records (A4-F09, disposition OPEN) that the classifier which
    produced those counts discharged all 33 back edges "by widening a
    compare-mnemonic regex, which changes the match vocabulary rather than
    proving a recurrence".  Porting the 16AV rule would carry an unsound PASS
    forward inside a verifier whose whole purpose is to stop stale claims from
    reaching a report.  Carrying a FAIL forward would assert a measurement
    nothing on disk supports.  The gate therefore requires the report to state
    what is actually established: the 16AT PASS is retired as unsound and no
    replacement result exists on disk.

E4. `slot5_decision` is no longer read as a bare artefact field.  It is
    resolved from the decision record AND required to be corroborated by 16AW's
    own record that no successor decision was built.  If a successor decision
    row ever reads COMPLETE, the fact BLOCKS rather than continuing to report
    the old decision -- the "verdict is scoped to the artefact it read" rule
    applied to a schema that moved.

E5. `candidate_f_cause` and `candidate_f_defect` are TWO facts, deliberately,
    and the FIRST DRAFT OF THIS FILE GOT IT WRONG: it resolved the cause from
    the VOPD measurement, so 16AW's DEMONSTRATED DEFECT became the CAUSE of the
    Slot-4 watchdog reset.  That is an overclaim of exactly the kind this
    project records as "a verdict is scoped to the artefact it read": the
    census measures an instruction order in an emitted object and says nothing
    about why a kernel was reclaimed 21,198.8 ms later.

      * `candidate_f_cause` is READ from the causal-rebase record's `cause`
        field, which is UNKNOWN, and is permitted only while that record still
        declares the value durable and unchanged.  Its vocabulary admits
        UNKNOWN and nothing else, so the defect's token cannot be written into
        it even by a report that wants to.
      * `candidate_f_defect` is DERIVED: the local VOPD measurement with its
        calibrated controls on one side, and the emitted Candidate-F lowering
        MEASURED out of the disassembly on the other.  It is the only fact
        permitted to read VOPD_SEQUENTIALIZATION_SEMANTIC_DEFECT.

    Each is corroborated by the inbound audit's OWN template field --
    `Candidate-F root cause` and `Candidate-F demonstrated defect`, which the
    audit keeps separate in its section-155 template.  The conflation is
    therefore rejected twice over: as a vocabulary violation, and by the
    narrative rule `cause_is_not_the_demonstrated_defect`.  The inverse is a
    rule too (`demonstrated_defect_not_denied`): a document may not deny a
    defect this phase measured.

E6. `first_frame_contract` is DERIVED.  "520 / 535" is recomputed from the
    frozen contract's own rows (the numerator is the number of required fields
    whose resolution state is not UNRESOLVED) and required to agree with the
    string the authorisation record states.  An undeclared resolution state
    BLOCKS rather than being counted either way.

E7. Every fact records its PROVENANCE -- source, locator, digest, value, the
    rule that produced it, its corroborating side and its evidence CEILING --
    so a reader can see which file each value came from and what the value does
    NOT support.

E8. The pure-string fact source is gone.  Every fact source named here exists
    on disk and is hashed by this checker, and the two 16AW artefacts that are
    relevant but hold no required key are hashed and listed as CONTEXT with the
    reason they are not fact holders -- so "we considered it" is auditable.

A NOTE ON WHAT THIS CHECKER DOES NOT DO
---------------------------------------
It does not certify that the phase's work is correct, complete, or wise.  It
certifies that the report's generated status fields agree with the artefacts
that hold them, that no narrative sentence contradicts a measured fact, and
that no fact was resolved by reading the document it is checking.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

PASS = "PASS"
FAIL = "FAIL"
BLOCKED = "BLOCKED"

BLOCK_BEGIN = "<!-- P16AW_OPERATOR_BLOCK_BEGIN -->"
BLOCK_END = "<!-- P16AW_OPERATOR_BLOCK_END -->"

#: The predecessor's markers.  A 16AW report must not carry them; they are
#: detected so the failure names the actual defect instead of "no block found".
LEGACY_BLOCK_BEGIN = "<!-- P16AV_OPERATOR_BLOCK_BEGIN -->"
LEGACY_BLOCK_END = "<!-- P16AV_OPERATOR_BLOCK_END -->"


# --------------------------------------------------------------------------
# ARTEFACTS.  Every path below is a real file, hashed by this checker.
# --------------------------------------------------------------------------
CURRENT_STATE = "CURRENT_STATE.json"
CANONICAL_TRACKS = "p16aw/state/CANONICAL_TRACKS_16AW.json"
COMPLETENESS = "p16aw/P16AW_COMPLETENESS.json"
ASTRA4_INTAKE = "p16aw/audit/ASTRA4_INTAKE.json"
ASTRA4_CLAIMS = "p16aw/audit/ASTRA4_CLAIMS.json"
AUDIT_REGISTER = "p16aw/audit/AUDIT_REGISTER.json"
ASTRA4_AUDIT_BODY = "p16aw/audit/ASTRA_AUDIT4_2026-09-21.md"
CANDIDATE_F_CAUSAL_REBASE = "p16au/candidate_f/CANDIDATE_F_CAUSAL_REBASE.json"
VOPD_CENSUS = "p16aw/vopd/VOPD_DEPENDENCY_CENSUS_16AW.json"
VOPD_CROSS_CENSUS = "p16aw/vopd/VOPD_CROSS_KERNEL_CENSUS_16AW.json"
CANDIDATE_F_DISASM = "p16aw/vopd/CANDIDATE_F_full.dis"
PROVENANCE_CHAIN = "p16aw/provenance/CANDIDATE_F_PROVENANCE_CHAIN_V2.json"
SOURCE_REGISTER = "p16aw/sources/SOURCE_GROUNDING_REGISTER.json"
SOURCE_REFRESH = "p16aw/sources/SOURCE_REFRESH_16AW.json"
RAW_DUMP_ARGSPEC = "p16aw/raw_dump/RAW_DUMP_ARGSPEC_16AW.json"
STATUS_VERIFIER_RESULT = "p16aw/consistency/STATUS_VERIFIER_V3_RESULT.json"

SLOT4_OUTCOME = "p16aq/slot4/launch/SLOT4_OUTCOME_16AQ.json"
SLOT5_DECISION = "p16at/slot5/SLOT5_FINAL_DECISION.json"
SLOT_A_FREEZE = "p16ap/slot_a/SLOT_A_RAW_EVIDENCE_FREEZE.json"
FIRST_FRAME_CONTRACT = "p16an/contracts/FIRST_FRAME_REQUIRED_FIELDS.json"
RAW_DUMP_AUTH = "p16au/state/RAW_DUMP_AUTHORIZATION_AND_CAPTURE.json"
GTA_CAPTURE = "p16av/state/GTA_CAPTURE_SESSION.json"
BRIDGE_STATUS = "p16av/bridge/INSTRUMENTED_BRIDGE_STATUS.json"
CANDIDATE_F_DIFFERENTIAL_16AV = \
    "p16av/candidate_f/CANDIDATE_F_TRANSLATION_DIFFERENTIAL_V1.json"
PUBLICATION_16AW = "p16aw/publication/PUBLICATION_16AW.json"
PUBLICATION_16AV = "p16av/publication/PUBLICATION_16AV.json"

#: The replacement recurrence prover's result artefact.  It does not exist
#: yet; its ABSENCE is load-bearing (see native_liveness_fact), which is why it
#: is declared here rather than probed by a bare try/except.
LOOP_RESULT = "p16aw/liveness/LOOP_RECURRENCE_RESULT.json"

#: The live batch is DERIVED from the authorization ledger, never read from a
#: generated summary -- a different artefact from every other fact, so the
#: batch comparison has two independent sides.  The digest is RECORDED so the
#: derivation can be refused when the ledger is no longer the pinned one; 16AV
#: declared this constant and never compared it (see the port notes).
BATCH_LEDGER = "p16ao/authorization/state/gen-000015/LEDGER.jsonl"
BATCH_LEDGER_SHA_RECORDED = \
    "29f8f4add5d840539c2050d3a77f3a5859100f2fb33c01fd3cfa99b7180e223c"
BATCH_ID = "P16AO_GENERIC_BATCH"
SLOT5_EXPERIMENT_ID = "NATIVE_K_DEC_UPSAMPLE_V1_SYNTHETIC"

#: 16AW artefacts that are RELEVANT to this phase's status but hold no required
#: key.  They are hashed and listed so a reader can see they were considered
#: and can see the reason each was NOT turned into a comparison.  Using any of
#: them as a fact holder would widen a verdict past the artefact it was
#: measured on (the RAW_DUMP argument table is scoped to argument LOCATION, not
#: to capture validity; the source refresh is scoped to remote HEAD identity,
#: not to any project claim).
CONTEXT_ARTEFACTS = [
    {"path": RAW_DUMP_ARGSPEC,
     "why_not_a_fact_holder":
         "its subject is where each explicit host argument's BYTES live and "
         "which 2 of 15 identities the legacy capture reads wrongly -- it "
         "makes no statement about any required status field"},
    {"path": SOURCE_REGISTER,
     "why_not_a_fact_holder":
         "its subject is source identity and refresh policy; it is the "
         "register the refresh is measured against, not a status field"},
    {"path": SOURCE_REFRESH,
     "why_not_a_fact_holder":
         "its subject is remote HEAD identity for 11 sources; SAME means the "
         "source did not move and explicitly is not a claim promotion"},
    {"path": VOPD_CROSS_CENSUS,
     "why_not_a_fact_holder":
         "its subject is the SOURCE tree's hazard multiplicity across 68 "
         "kernels; it states in its own row that it does not establish which "
         "sites the translator mis-lowered"},
    {"path": ASTRA4_CLAIMS,
     "why_not_a_fact_holder":
         "it is read as a fact holder for native_liveness (claim A4-F09) and "
         "for the astra4 ladder; it is listed here as well because its "
         "remaining rows are CLAIMS TO REPRODUCE and are never read as facts"},
]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


_CACHE = {}


def _abs(rel):
    return rel if os.path.isabs(rel) else os.path.join(ROOT, rel)


def load_json(rel):
    p = _abs(rel)
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return True, json.load(fh), sha256_file(p)
    except Exception as exc:                                   # noqa: BLE001
        return False, "could not read %s: %s" % (rel, exc), None


def load_json_cached(rel):
    if rel not in _CACHE:
        _CACHE[rel] = load_json(rel)
    return _CACHE[rel]


def load_text(rel):
    p = _abs(rel)
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return True, fh.read(), sha256_file(p)
    except Exception as exc:                                   # noqa: BLE001
        return False, "could not read %s: %s" % (rel, exc), None


def dig(obj, locator):
    cur = obj
    for k in locator:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def completeness_row(name):
    """-> (row_or_None, error_or_None, sha_or_None)"""
    ok, doc, sha = load_json_cached(COMPLETENESS)
    if not ok:
        return None, doc, None
    for r in doc.get("rows") or []:
        if r.get("row") == name:
            return r, None, sha
    return None, ("the 16AW completeness register carries no row named %r"
                  % name), sha


def canonical_track(name):
    """-> (track_or_None, error_or_None, sha_or_None)"""
    ok, doc, sha = load_json_cached(CANONICAL_TRACKS)
    if not ok:
        return None, doc, None
    for t in doc.get("tracks") or []:
        if t.get("track") == name:
            return t, None, sha
    return None, ("the 16AW canonical track summary carries no track named %r"
                  % name), sha


def evidence_digest_check(track_name, expected_path):
    """Corroborate a fact against a 16AW canonical track's evidence pointer.

    The digest is RECOMPUTED HERE from the bytes on disk and compared to the
    value the track declares.  The track's own number is therefore checked
    against a measurement, not trusted -- otherwise this would be one fact read
    twice from one file.
    """
    t, err, sha = canonical_track(track_name)
    if err:
        return {"agrees": False, "why": err}
    rec = {"track": track_name,
           "track_source": CANONICAL_TRACKS,
           "track_source_sha256": sha,
           "corroboration_source": CANONICAL_TRACKS,
           "corroboration_source_sha256": sha,
           "corroboration_locator": ["tracks[track==%s]" % track_name,
                                     "evidence_sha256_recomputed"],
           "evidence_artifact_named_by_the_track": t.get("evidence_artifact"),
           "evidence_state": t.get("evidence_state"),
           "how_compared": "the digest is recomputed by this checker from the "
                           "bytes on disk and compared to the value the track "
                           "declares; the track's number is not trusted"}
    if t.get("evidence_state") != "PRESENT":
        return {**rec, "agrees": False,
                "why": "the track records its evidence as %r, not PRESENT"
                       % t.get("evidence_state")}
    if t.get("evidence_artifact") != expected_path:
        return {**rec, "agrees": False,
                "why": "the %s track names %r as its evidence; this fact is "
                       "resolved from %r"
                       % (track_name, t.get("evidence_artifact"), expected_path)}
    p = _abs(expected_path)
    if not os.path.exists(p):
        return {**rec, "agrees": False,
                "why": "the evidence the track names is not on disk"}
    actual = sha256_file(p)
    declared = t.get("evidence_sha256_recomputed")
    rec["sha256_recomputed_here"] = actual
    rec["sha256_declared_by_the_track"] = declared
    if declared is None:
        return {**rec, "agrees": False,
                "why": "the track declares no digest for its evidence, so the "
                       "pointer cannot be checked"}
    if declared != actual:
        return {**rec, "agrees": False,
                "why": "the track records %s for its evidence; the bytes on "
                       "disk hash to %s" % (declared, actual)}
    rec["agrees"] = True
    return rec


# --------------------------------------------------------------------------
# FACT SOURCES.  One artefact per fact, resolved by an explicit locator.
# `source is None` means the fact is DERIVED by a rule in RULE_FACTS.
# --------------------------------------------------------------------------
FACT_SOURCES = {
    "phase": {
        "source": CURRENT_STATE,
        "locator": ["phase"],
        "why": "the phase the machine-readable state record is in",
        "evidence_ceiling": "the phase token of the state record; it says "
                            "nothing about what the phase achieved",
        "no_corroboration_because":
            "the phase token's only holder is the state record itself; every "
            "other file that states it is written by the phase about itself, "
            "so an 'independent side' would be a second reading of one "
            "self-declaration.  Declared rather than faked.",
    },
    "physical_completion_ever": {
        "source": None,
        "locator": None,
        "why": "physical completion is a RULE over the frozen attempt evidence, "
               "cross-checked against the generated record's own claim",
    },
    "candidate_f_physical": {
        "source": SLOT4_OUTCOME,
        "locator": ["outcome"],
        "why": "the Slot-4 attempt's own outcome record",
        "evidence_ceiling": "the outcome of one attempt under canonical input",
        "corroboration": "canonical_track:PHYSICAL",
    },
    "candidate_f_cause": {
        "source": None,
        "locator": None,
        "why": "DERIVED: the causal-rebase record's own value, guarded, and "
               "corroborated by the inbound audit's own root-cause field",
        "evidence_ceiling":
            "the root cause OF THE SLOT-4 TDR.  It is NOT the demonstrated "
            "defect and must never be read from one: a defect that exists is "
            "not a defect that caused anything.",
    },
    "candidate_f_defect": {
        "source": None,
        "locator": None,
        "why": "DERIVED: the local VOPD measurement on one side, the emitted "
               "Candidate-F lowering measured out of the disassembly on the "
               "other, corroborated by the inbound audit's own defect field.",
    },
    "slot5_decision": {
        "source": None,
        "locator": None,
        "why": "DERIVED: the decision record's verdict, corroborated by 16AW's "
               "own record that no successor decision was built",
    },
    "first_frame_contract": {
        "source": None,
        "locator": None,
        "why": "DERIVED: recomputed from the frozen contract's own rows and "
               "required to agree with the string the authorisation states",
    },
    "authentic_job_dag": {
        "source": RAW_DUMP_AUTH,
        "locator": ["part_4_authentic_job_dag_v1", "status"],
        "why": "the authorisation record's own DAG row",
        "evidence_ceiling": "whether an authentic job DAG exists; not the "
                            "validity of any DAG that might later exist",
        "corroboration": "completeness_row:AUTHENTIC_JOB_DAG_V1",
    },
    "capture_only_authorization": {
        "source": None,
        "locator": None,
        "why": "DERIVED: the committed authorization's verdict AND the capture "
               "session's own state -- an authorization that has been spent is "
               "no longer an unspent authorization",
    },
    "astra4": {
        "source": None,
        "locator": None,
        "why": "DERIVED: the intake's declared ladder rung on one side, the "
               "audit register's own AUDIT4 status on the other, plus the "
               "preserved body's digest recomputed from the bytes on disk",
    },
    "native_liveness": {
        "source": None,
        "locator": None,
        "why": "DERIVED: the 16AV rule is retired as unsound by this phase's "
               "own ledger; the replacement result artefact is required to "
               "exist before any PASS may be stated again",
    },
    "status_verifier": {
        "source": STATUS_VERIFIER_RESULT,
        "locator": ["verdict"],
        "why": "this verifier's own regression verdict",
        "evidence_ceiling": "the regression verdict of THIS file as it was when "
                            "the regression ran; the binding is enforced by the "
                            "digest corroboration below",
        "corroboration": "verifier_self_digest",
    },
    "shipping_bridge": {
        # Deliberately NOT SHIPPING_BRIDGE_EQUIVALENCE.json.  That file's
        # verdict is scoped to static export/import equivalence and says so in
        # its own `verdict_scope`; reading "the bridge is ready" off it would
        # widen a verdict past the artefact it was measured on.  16AV made the
        # same choice and 16AW did not retire it.
        "source": BRIDGE_STATUS,
        "locator": ["verdict"],
        "why": "the instrumented-bridge status, whose subject IS deployment "
               "readiness",
        "evidence_ceiling": "readiness of the instrumented bridge; never "
                            "behavioural equivalence of the shipping backend",
        "corroboration": "completeness_row:bridge_real_backend_equivalence",
    },
    "translation_differential": {
        "source": None,
        "locator": None,
        "why": "DERIVED: the Candidate-F provenance chain's own completeness, "
               "with the 16AV differential's RETIREMENT required to be on "
               "record before the chain's numbers are used",
    },
    "gta_capture": {
        "source": GTA_CAPTURE,
        "locator": ["status"],
        "why": "the capture-only session's own outcome row",
        "evidence_ceiling": "whether the capture session was spent; not "
                            "whether any frame was captured",
        # NO corroboration of its own, and the reason is recorded rather than
        # the gate being relabelled.  This fact was gated on 16AW's
        # `capture_cold_frame` completeness row -- the SAME row, at the SAME
        # locator, that gates `capture_only_authorization`.  The tautology guard
        # reported exactly that as soon as the C07 control stopped crashing on a
        # provenance-shape bug, so one of the two readers had to go: a gate is a
        # property of the CONDITION, both facts are compared against it
        # independently, and a gate that blocks blocks the whole document
        # whichever fact carries it.
        "gate": "none of its own: whether the capture condition was reached is "
                "gated by the capture_only_authorization fact, which reads that "
                "row; reading it here as well would make one locator the holder "
                "of two facts",
    },
    "publication_status": {
        "source": PUBLICATION_16AW,
        "locator": ["verdict"],
        "fallback": (PUBLICATION_16AV, ["verdict"]),
        "why": "the publication record for this phase if it exists, otherwise "
               "the last MEASURED publication state",
        "evidence_ceiling": "the last measured publication state of record; a "
                            "16AW record, once filed, takes over automatically "
                            "and is verified by the same digest rule",
        "fallback_guard": "completeness_row:publication_push",
    },
    "public_branch": {
        "source": PUBLICATION_16AW,
        "locator": ["branch"],
        "fallback": (PUBLICATION_16AV, ["branch"]),
        "why": "the publication branch actually used",
        "evidence_ceiling": "the branch named by the publication record this "
                            "fact resolved from; not a claim about the remote",
    },
}


def _track_corroboration(spec, value):
    return evidence_digest_check(spec.split(":", 1)[1],
                                 _EXPECTED_EVIDENCE_PATH[spec])


#: expected evidence path per canonical track, filled at import time from the
#: fact sources so the two cannot drift apart.
_EXPECTED_EVIDENCE_PATH = {
    "canonical_track:PHYSICAL": SLOT4_OUTCOME,
}

_COMPLETENESS_AGREEMENT = {
    # completeness row -> (status the row must read, token it corroborates|None,
    #                      reason)
    #
    # `None` for the token means this row corroborates a STATE rather than a
    # value: the row's status is the phase's own statement that a condition was
    # not reached, and the fact's value comes from its own holder.  This is the
    # distinction between a GATE and a SECOND READING, and it is the reason
    # `capture_only_authorization` no longer reads the capture session directly:
    # reading it there as well as in the `gta_capture` fact made one locator the
    # holder of two facts, which the tautology guard correctly reported.
    "AUTHENTIC_JOB_DAG_V1": (
        "CONDITION_NOT_REACHED", "NOT_READY",
        "16AW records AUTHENTIC_JOB_DAG_V1 as CONDITION_NOT_REACHED, which is "
        "its own statement that no DAG exists"),
    "bridge_real_backend_equivalence": (
        "OPEN", "BLOCKED",
        "16AW records bridge_real_backend_equivalence as OPEN, which is its "
        "own statement that equivalence is not established"),
    "capture_cold_frame": (
        "CONDITION_NOT_REACHED", "VALID",
        "16AW records capture_cold_frame as CONDITION_NOT_REACHED, which is "
        "its own statement that the capture never happened -- and an unspent "
        "authorization is a VALID one.  This row is read by ONE fact: it was "
        "briefly read by the capture-session fact as well, and the tautology "
        "guard reported the collision (control C07); the second reader was "
        "removed rather than the value relabelled"),
    "Slot5_final_decision": (
        "CONDITION_NOT_REACHED", None,
        "16AW records Slot5_final_decision as CONDITION_NOT_REACHED, which is "
        "its own statement that no successor Slot-5 decision was built; if it "
        "ever moves, the decision of record must be re-read from whatever "
        "superseded it"),
    "Slot5_physical": (
        "CONDITION_NOT_REACHED", None,
        "16AW records Slot5_physical as CONDITION_NOT_REACHED, which is its "
        "own statement that no Slot-5 launch occurred"),
    "publication_push": (
        "OPEN", None,
        "16AW records publication_push as OPEN, which is its own statement "
        "that this phase pushed nothing; a COMPLETE row would mean a 16AW "
        "publication record exists and must be read instead of the fallback"),
}


def _completeness_corroboration(spec, value):
    name = spec.split(":", 1)[1]
    row, err, sha = completeness_row(name)
    rec = {"completeness_row": name,
           "corroboration_source": COMPLETENESS,
           "corroboration_source_sha256": sha,
           "corroboration_locator": ["rows[row==%s]" % name, "status"],
           "completeness_source": COMPLETENESS}
    if err:
        return {**rec, "agrees": False, "why": err}
    expect_status, expect_token, why = _COMPLETENESS_AGREEMENT[name]
    rec["row_status"] = row.get("status")
    rec["row_evidence"] = row.get("evidence")
    rec["expected_row_status"] = expect_status
    rec["token_the_row_corroborates"] = expect_token
    rec["why"] = why
    if expect_token is not None and value != expect_token:
        return {**rec, "agrees": False,
                "why": "the fact resolved to %r; this row's corroboration is "
                       "declared only for %r" % (value, expect_token)}
    if row.get("status") != expect_status:
        return {**rec, "agrees": False,
                "why": "the row reads %r, not %r -- the phase's own record has "
                       "moved and this fact must be re-resolved from whatever "
                       "superseded it" % (row.get("status"), expect_status)}
    rec["agrees"] = True
    return rec


def _verifier_self_digest_corroboration(spec, value):
    """The regression verdict must be bound to the verifier ON DISK."""
    ok, doc, sha = load_json_cached(STATUS_VERIFIER_RESULT)
    if not ok:
        return {"agrees": False, "why": doc}
    rec = {"how_compared": "the verifier file named by the result record is "
                           "hashed here and compared to the digest the result "
                           "record claims for it",
           "result_source": STATUS_VERIFIER_RESULT,
           "result_source_sha256": sha,
           "corroboration_source": STATUS_VERIFIER_RESULT,
           "corroboration_source_sha256": sha,
           "corroboration_locator": ["verifier_sha256"],
           "declared_verifier": doc.get("verifier"),
           "declared_verifier_sha256": doc.get("verifier_sha256")}
    named = doc.get("verifier")
    if not named:
        return {**rec, "agrees": False,
                "why": "the result record names no verifier, so the verdict "
                       "cannot be bound to one"}
    p = _abs(named)
    if not os.path.exists(p):
        return {**rec, "agrees": False,
                "why": "the verifier the result record names is not on disk"}
    actual = sha256_file(p)
    rec["verifier_sha256_recomputed_here"] = actual
    if actual != doc.get("verifier_sha256"):
        return {**rec, "agrees": False,
                "why": "the result record claims %s for %s; the bytes on disk "
                       "hash to %s -- the verifier was edited without "
                       "re-running the regression, so its REPAIRED claim is "
                       "stale" % (doc.get("verifier_sha256"), named, actual)}
    rec["agrees"] = True
    return rec


AUDIT_ROOT_CAUSE_LABEL = "Candidate-F root cause"
AUDIT_DEFECT_LABEL = "Candidate-F demonstrated defect"


def audit_template_field(label):
    """Read one `LABEL =` field out of the PRESERVED inbound audit body.

    The audit is a document the project preserved byte-exact and whose digest
    both 16AW records claim.  Reading a field out of it is a different act from
    reading a claim out of it: this is an independent RECORD that states the
    same two things the project's own records state, so it can corroborate them
    -- and it can disagree with them, which is the point.

    The digest is re-verified here, so the corroboration is against the
    preserved body and not against whatever file happens to sit at that path.
    """
    ok, text, sha = load_text(ASTRA4_AUDIT_BODY)
    if not ok:
        return None, None, sha, text
    ok_r, reg, _sha_r = load_json_cached(AUDIT_REGISTER)
    declared = dig(reg, ["audits", "AUDIT4", "whole_file_sha256"]) if ok_r \
        else None
    if declared is None:
        return None, None, sha, ("the audit register declares no digest for the "
                                 "preserved body, so this corroboration cannot "
                                 "be tied to the preserved bytes")
    if declared != sha:
        return None, None, sha, ("the body on disk is NOT the preserved body: "
                                 "the register records %s, the bytes hash to %s"
                                 % (declared, sha))
    pat = re.compile(r"^%s\s*=\s*$" % re.escape(label).replace(r"\ ", r"\s+"),
                     re.I)
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if pat.match(line.strip()):
            for j in range(i + 1, min(i + 6, len(lines))):
                v = lines[j].strip()
                if v:
                    return v, {"label_line": i + 1, "value_line": j + 1,
                               "lines": "%d-%d" % (i + 1, j + 1)}, sha, None
            return None, None, sha, ("the audit's %r field has no value line"
                                     % label)
    return None, None, sha, ("the preserved audit carries no %r field; a field "
                             "that is not there cannot corroborate anything"
                             % label)


def _audit_template_corroboration(spec, value):
    label = spec.split(":", 1)[1]
    val, loc, sha, err = audit_template_field(label)
    rec = {"label": label,
           "corroboration_source": ASTRA4_AUDIT_BODY,
           "corroboration_source_sha256": sha,
           "corroboration_locator": [loc["lines"]] if loc else [label],
           "audit_line_locator": loc,
           "how_compared": "the field is read out of the preserved audit body, "
                           "whose digest is re-verified against the audit "
                           "register, and compared to the value this fact "
                           "resolved independently"}
    if err:
        return {**rec, "agrees": False, "why": err}
    rec["audit_template_value"] = val
    if val != value:
        return {**rec, "agrees": False,
                "why": "the inbound audit states this field as %r; this phase's "
                       "own record resolves it to %r.  TWO RECORDS DISAGREE on "
                       "a field both of them state, and the disagreement is "
                       "not resolved by preferring either side" % (val, value)}
    rec["agrees"] = True
    return rec


_CORROBORATORS = {
    "verifier_self_digest": _verifier_self_digest_corroboration,
}


def corroborate(field, spec, value):
    spec_key = spec.get("corroboration")
    if not spec_key:
        return None
    if spec_key.startswith("canonical_track:"):
        return _track_corroboration(spec_key, value)
    if spec_key.startswith("completeness_row:"):
        return _completeness_corroboration(spec_key, value)
    if spec_key.startswith("audit_template:"):
        return _audit_template_corroboration(spec_key, value)
    fn = _CORROBORATORS.get(spec_key)
    if fn is None:
        return {"agrees": False,
                "why": "the corroborator %r named by the fact source does not "
                       "exist; an unrun corroboration is not an agreement"
                       % spec_key}
    return fn(spec_key, value)


# --------------------------------------------------------------------------
# VOCABULARY.  Declared, auditable, and the matched rule is recorded.
# --------------------------------------------------------------------------
VOCAB = {
    # E1: two tokens, one comparison against CURRENT_STATE.json.
    "phase": [("16AW", [r"^16AW$"]), ("16AV", [r"^16AV$"])],
    "candidate_f_physical": [
        ("J3_TDR_CORRECT_INPUT", [r"^J3_TDR_CORRECT_INPUT$", r"^TDR$"]),
    ],
    # The CAUSE of the Slot-4 TDR.  ONE token.  The demonstrated defect has its
    # own key and its own token, and neither value is legal here.
    "candidate_f_cause": [
        ("UNKNOWN", [r"^UNKNOWN$"]),
    ],
    # The DEMONSTRATED defect.  The token is the inbound audit's own name for
    # it (`VOPD_SEQUENTIALIZATION_SEMANTIC_DEFECT`, audit line 3777), not a
    # name invented here.  A report must state this separately from the cause.
    "candidate_f_defect": [
        ("VOPD_SEQUENTIALIZATION_SEMANTIC_DEFECT",
         [r"^VOPD_SEQUENTIALIZATION_SEMANTIC_DEFECT$"]),
        ("NONE_DEMONSTRATED", [r"^NONE_DEMONSTRATED$"]),
    ],
    "slot5_decision": [
        ("HOLD", [r"^HOLD$", r"^HOLD_SLOT$"]),
        ("RUN", [r"^RUN$", r"^RUN_CURRENT$", r"^RUN_K_DEC_UPSAMPLE$"]),
        ("MODIFY", [r"^MODIFY$", r"^MODIFY_AND_REQUALIFY$"]),
        ("RESELECT", [r"^RESELECT$", r"^RESELECT_OPERATOR$"]),
        ("ROADMAP_PIVOT", [r"^ROADMAP_PIVOT$"]),
    ],
    "slot5": [
        ("NOT_RUN", [r"^NOT_RUN$"]),
        ("PASS", [r"^PASS$"]),
        ("NUMERIC_FAIL", [r"^NUMERIC_FAIL$"]),
        ("TDR", [r"^TDR$"]),
        # 16AV's `_fill_derived` could produce this token and its VOCAB had no
        # rule for it, so a recorded Slot-5 launch resolved the FACT to a value
        # with no vocabulary and BLOCKED the whole row.  Fail-closed, but the
        # vocabulary was incomplete: the derivation's own output had to be
        # nameable.  Added here with the derivation that produces it.
        ("LAUNCHED_RECORDED", [r"^LAUNCHED_RECORDED$"]),
    ],
    "physical_completion_ever": [
        ("YES", [r"^YES$", r"^true$", r"^hipSuccess$"]),
        ("NO", [r"^NO$", r"^false$"]),
    ],
    # E2: the intake's own ladder, plus the 16AV token so the older vocabulary
    # still parses.  NOT_RECEIVED is retained: it is the state a report must be
    # able to state when no audit arrived.
    "astra4": [
        ("NOT_RECEIVED", [r"^NOT_RECEIVED$"]),
        ("INGESTED", [r"^INGESTED$"]),
        ("RECEIVED", [r"^RECEIVED$"]),
        ("PRESERVED", [r"^PRESERVED$"]),
        ("CLAIMS_EXTRACTED", [r"^CLAIMS_EXTRACTED$"]),
        ("REPRODUCTION_IN_PROGRESS", [r"^REPRODUCTION_IN_PROGRESS$"]),
        ("PARTIALLY_DISPOSITIONED", [r"^PARTIALLY_DISPOSITIONED$"]),
        ("FULLY_DISPOSITIONED", [r"^FULLY_DISPOSITIONED$"]),
    ],
    "authentic_job_dag": [
        ("READY", [r"^READY$"]),
        ("NOT_READY", [r"^NOT_READY$"]),
    ],
    "capture_only_authorization": [
        ("VALID", [r"^VALID$", r"^AUTHORIZATION_VALID_AND_UNSPENT$"]),
        ("INVALID", [r"^INVALID$"]),
        ("EXPIRED", [r"^EXPIRED$"]),
    ],
    "status_verifier": [
        ("REPAIRED", [r"^REPAIRED$"]),
        ("FAIL", [r"^FAIL$"]),
    ],
    "shipping_bridge": [
        ("INSTRUMENTED_EQUIVALENT", [r"^INSTRUMENTED_EQUIVALENT$"]),
        ("BLOCKED", [r"^BLOCKED$"]),
    ],
    "translation_differential": [
        ("COMPLETE", [r"^COMPLETE$"]),
        ("PARTIAL", [r"^PARTIAL$"]),
        ("BLOCKED", [r"^BLOCKED$"]),
    ],
    "gta_capture": [
        ("USED", [r"^USED$"]),
        ("UNUSED", [r"^UNUSED$"]),
        ("FAILED", [r"^FAILED$"]),
        ("BLOCKED", [r"^BLOCKED$"]),
    ],
    "publication_status": [
        ("PUBLISHED_BRANCH", [r"^PUBLISHED_BRANCH$"]),
        ("PUBLICATION_SYNC_PENDING", [r"^PUBLICATION_SYNC_PENDING$"]),
        ("PUBLICATION_SYNC_BLOCKED", [r"^PUBLICATION_SYNC_BLOCKED$"]),
        ("PUBLICATION_SYNC_NONE", [r"^PUBLICATION_SYNC_NONE$"]),
    ],
    "first_frame_contract": [
        # canonicalised to "<n> / 535" -- the denominator is fixed by the
        # frozen contract, so only the numerator can move.
        ("520", [r"^520$", r"^520\s*/\s*535$"]),
        ("535", [r"^535$", r"^535\s*/\s*535$"]),
    ],
    # E3: the retired 16AV rule's tokens are kept (a report must be able to
    # report a PASS again once a sound result exists) and the state this phase
    # actually established is nameable.
    "native_liveness": [
        ("RETIRED_UNSOUND", [r"^RETIRED_UNSOUND$"]),
        ("PASS", [r"^PASS$"]),
        ("FAIL", [r"^FAIL$"]),
        ("STOP", [r"^STOP$"]),
        ("NOT_ESTABLISHED", [r"^NOT_ESTABLISHED$"]),
    ],
}

#: key -> fact it is compared against
REQUIRED_KEYS = {
    "phase": "phase",
    "candidate_f": "candidate_f_physical",
    # E9: the cause and the demonstrated defect are TWO keys, because they are
    # two facts with two holders.  16AW established the defect and did NOT
    # establish the cause; a schema with one key would force a report to pick
    # one of them for the other, which is the conflation this phase had to
    # avoid.  The vocabulary of each key EXCLUDES the other's token, so the
    # conflation fails as a vocabulary violation even before the prose rules.
    "candidate_f_cause": "candidate_f_cause",
    "candidate_f_defect": "candidate_f_defect",
    "slot5_decision": "slot5_decision",
    "slot5": "slot5",
    "physical_completion_ever": "physical_completion_ever",
    "astra4": "astra4",
    "native_liveness": "native_liveness",
    "authentic_job_dag": "authentic_job_dag",
    "capture_only_authorization": "capture_only_authorization",
    "status_verifier": "status_verifier",
    "shipping_bridge": "shipping_bridge",
    "translation_differential": "translation_differential",
    "gta_capture": "gta_capture",
    "publication_status": "publication_status",
    "public_branch": "public_branch",
    "first_frame_contract": "first_frame_contract",
}

#: keys whose value is a free string compared for exact equality, not a token
FREE_KEYS = {"public_branch"}

#: Fields the report may carry for its own completeness with no single
#: generated source; declared so a reader can see they were considered.
UNCOMPARED_KEYS = [
    "batch", "roadmap", "current_state", "supervisor_handover", "process_hygiene",
    "new_public_commits", "remote_push", "draft_pr", "executed_closure",
    "reference_executor_closure", "reference_offline_job", "hybrid_offline_job",
    "astra4_claims_open", "vopd_defect_sites", "publication_drift_check",
]

#: Key names that would let a document certify itself.  They are DETECTED and
#: NAMED but never read; the corpus proves the refusal by requiring a
#: contradictory document carrying them to be rejected anyway.
SELF_CERTIFICATION_KEYS = [
    "consistent", "status_consistent", "all_consistent", "self_consistent",
    "finalization_allowed", "verdict", "verifier_verdict", "confidence",
]

NEGATION = re.compile(
    r"\b(?:not|never|no|nor|neither|without|did\s+not|does\s+not|do\s+not|"
    r"cannot|can\s+not|has\s+not|have\s+not|was\s+not|were\s+not|is\s+not|"
    r"remains?|remained|"
    # Added for 16AW: a document must be able to DESCRIBE a retirement or a
    # withdrawal and still be telling the truth about it.  Without these the
    # new liveness rule would reject the only honest sentence available, which
    # is the failure this project records as "a checker must accept the
    # known-good case".  Both directions are exercised in the corpus.
    r"retire[sd]?|retiring|retired|withdrawn|withdrew|superseded|reopened|"
    r"no\s+longer|unsound|unproven|not\s+established)\b", re.I)

#: One span of a SINGLE CLAUSE, for the narrative rules' match windows.
#:
#: `[^.\n]` was the first draft of these windows, and the corpus found two
#: defects in it -- one in each direction:
#:   * a DECIMAL POINT ended the window, so "The cause of the 21,198.8 ms
#:     timeout is the VOPD sequentialization defect" slipped past a rule
#:     written to catch exactly that sentence (mutation M28c).  A point
#:     BETWEEN DIGITS is part of a number, not the end of a statement.
#:   * a SEMICOLON did not end it, so two separate TRUE statements joined by
#:     "; " could be matched as one false one: negative control C10,
#:     "Candidate F's cause is UNKNOWN; candidate F's demonstrated defect is a
#:     VOPD sequentialization site."  The rule rejected a true sentence, which
#:     is the failure this project records as "a checker must accept the
#:     known-good case" -- a checker is not strict for refusing it.
#: A clause therefore ends at a full stop, a semicolon or a newline.
CLAUSE = r"(?:[^.;\n]|\.(?=\d))"

#: The same span, bounded: `CLAUSE` repeated at most N times, lazily.  Used to
#: keep every narrative window inside one clause rather than `[^.\n]{0,N}?`,
#: which does neither of the two things above correctly.
def _win(n):
    return CLAUSE + "{0,%d}?" % n


def _assertion_rules():
    """Directional narrative rules.  Each fires ONLY when the fact supports it."""
    return [
        {
            "id": "candidate_f_never_completed",
            "fact_read": "candidate_f_physical",
            "fires_when": lambda f: f.get("candidate_f_physical") ==
                                    "J3_TDR_CORRECT_INPUT",
            "forbidden": [
                r"\bCandidate\s*F\b" + _win(60) + r"\b(?:completed|passed|succeeded)\b",
            ],
            "why": "the outcome record is J3_TDR_CORRECT_INPUT; a sentence "
                   "claiming Candidate F completed contradicts it",
        },
        {
            "id": "canonical_j3_not_untested",
            "fact_read": "candidate_f_physical",
            "fires_when": lambda f: f.get("candidate_f_physical") ==
                                    "J3_TDR_CORRECT_INPUT",
            "forbidden": [
                r"\bcanonical\s+J3\b" + _win(40) + r"\buntested\b",
                r"\bJ3\b" + _win(40) + r"\bhas\s+not\s+been\s+tested\b",
            ],
            "why": "Slot 4 launched J3 under canonical input; calling it "
                   "untested contradicts the attempt record",
        },
        {
            "id": "kernel_completion_ever",
            "fact_read": "physical_completion_ever",
            "fires_when": lambda f: f.get("physical_completion_ever") == "YES",
            "forbidden": [
                r"\bno\s+kernel\s+has\s+(?:ever\s+)?completed\b",
                r"\bno\s+physical\s+kernel\s+has\s+(?:ever\s+)?complet",
                r"\bphysical\s+completion\s+ever\s*[:=]\s*(?:NO|false)\b",
            ],
            "why": "a project-owned kernel completed in 0.5 ms; denying it "
                   "contradicts the Slot-A freeze",
        },
        {
            "id": "slot5_not_passed",
            "fact_read": "slot5_decision",
            "fires_when": lambda f: f.get("slot5_decision") == "HOLD",
            "forbidden": [
                r"\bSlot[\s-]*5\b" + _win(40) + r"\b(?:PASS|PASSED)\b",
            ],
            "why": "the Slot-5 decision is HOLD; a PASS claim contradicts it",
        },
        {
            "id": "slot5_score_not_current",
            "fact_read": "slot5_decision",
            "fires_when": lambda f: f.get("slot5_decision") == "HOLD",
            "forbidden": [
                r"\b24\s*/\s*26\b",
                r"\bslot5_gates_passed\b",
            ],
            "why": "the 24 / 26 gate score is retired as physical authority "
                   "this phase; restating it as a current qualification "
                   "contradicts the retirement",
        },
        {
            "id": "native_liveness_not_discharged",
            "fact_read": "native_liveness",
            "fires_when": lambda f: f.get("native_liveness") ==
                                    "RETIRED_UNSOUND",
            "forbidden": [
                r"\bnative\s+liveness\b" + _win(60) + r""
                r"\b(?:PASS|proved|proven|discharged|sound)\b",
                r"\ball\s+(?:\d+\s+)?(?:machine\s+)?loops\b" + _win(40) + r""
                r"\b(?:discharged|proved|proven|sound)\b",
                r"\bno\s+unmatched\s+back\s+edge\s+remains\b",
                r"\b24\s+of\s+33\b" + _win(30) + r"\b(?:unmatched|resolved|"
                r"discharged)\b",
            ],
            "why": "16AW's own ledger records the finite-bound classifier that "
                   "produced the standing PASS as unsound and the finding as "
                   "OPEN; claiming the loops are discharged contradicts it",
        },
        {
            "id": "candidate_f_cause_not_closed",
            "fact_read": "candidate_f_cause",
            "fires_when": lambda f: f.get("candidate_f_cause") == "UNKNOWN",
            "forbidden": [
                # 45 clauses, not 30: "The root cause of the Slot-4 watchdog
                # reset has been identified." puts 39 characters between the
                # cause and the verb, and mutation M28 found that a 30-clause
                # window let that exact claim through.  The window stays inside
                # ONE clause, so widening it does not reach a second claim.
                r"\b(?:root\s+cause|cause)\b" + _win(45) + r"\b(?:IDENTIFIED|"
                r"FOUND|ESTABLISHED)\b",
            ],
            "why": "the cause of the Slot-4 TDR is UNKNOWN; claiming it is "
                   "identified contradicts the causal-rebase record and the "
                   "inbound audit's own root-cause field",
        },
        {
            # THE CONFLATION CATCHER.  This rule exists because the first draft
            # of this verifier made exactly the mistake it catches: it read the
            # demonstrated DEFECT into the CAUSE field.
            "id": "cause_is_not_the_demonstrated_defect",
            "fact_read": "candidate_f_cause + candidate_f_defect",
            "fires_when": lambda f: (f.get("candidate_f_cause") == "UNKNOWN"
                                     and f.get("candidate_f_defect") ==
                                     "VOPD_SEQUENTIALIZATION_SEMANTIC_"
                                     "DEFECT"),
            "forbidden": [
                r"\bdefect\b" + _win(60) + r"\b(?:caused|explains|is\s+the\s+"
                r"(?:root\s+)?cause|was\s+the\s+(?:root\s+)?cause)\b",
                r"\bcause\b" + _win(50) + r"\b(?:is|was)\b" + _win(30) + r""
                r"\b(?:VOPD|sequentializ)",
                r"\b(?:VOPD|sequentializ\w*)\b" + _win(45) + r"\b(?:caused|"
                r"explains|is\s+the\s+(?:root\s+)?cause)\b",
                r"\b(?:the\s+)?defect\s+is\s+(?:the|why)\b",
            ],
            "why": "the cause is UNKNOWN and a defect is demonstrated.  These "
                   "are two facts about two things: the census measures an "
                   "instruction order in an emitted object and says nothing "
                   "about why a kernel was reclaimed ~21 s later.  Any sentence "
                   "that promotes the defect into the cause contradicts the "
                   "causal-rebase record and the audit's own separation of the "
                   "two fields.",
        },
        {
            "id": "demonstrated_defect_not_denied",
            "fact_read": "candidate_f_defect",
            "fires_when": lambda f: f.get("candidate_f_defect") ==
                                    "VOPD_SEQUENTIALIZATION_SEMANTIC_DEFECT",
            "forbidden": [
                r"\bno\s+(?:translation\s+|VOPD\s+)?defect\b" + _win(30) + r""
                r"\b(?:was\s+)?(?:found|demonstrated|exists|reproduced)\b",
                r"\bno\s+(?:translation\s+|VOPD\s+)?defect\s+(?:was\s+)?"
                r"(?:found|demonstrated)\b",
            ],
            "why": "a defect is demonstrated by a calibrated measurement at "
                   "0xCB8DC with a discriminating witness; denying it "
                   "contradicts the VOPD census",
        },
        {
            "id": "astra4_not_ingested_as_done",
            "fact_read": "astra4",
            "fires_when": lambda f: f.get("astra4") not in
                                    ("FULLY_DISPOSITIONED", None),
            "forbidden": [
                r"\bINGESTED_AND_DONE\b",
                r"\bAstra\s*#?\s*4\b" + _win(50) + r"\b(?:fully\s+)?(?:"
                r"dispositioned|reproduced|closed)\b",
            ],
            "why": "the intake's own ladder forbids the shortcut "
                   "'ASTRA4 = INGESTED_AND_DONE merely because the report was "
                   "archived'; the rung is CLAIMS_EXTRACTED",
        },
        {
            "id": "translation_differential_not_complete",
            "fact_read": "translation_differential",
            "fires_when": lambda f: f.get("translation_differential") not in
                                    ("COMPLETE", None),
            "forbidden": [
                r"\bsame[- ]source\s+differential\b" + _win(40) + r"\bCOMPLETE\b",
                r"\btranslation\s+differential\b" + _win(30) + r"\b(?:is\s+)?"
                r"COMPLETE\b",
            ],
            "why": "the provenance chain leaves the translator revision and "
                   "configuration UNRESOLVED; a COMPLETE differential claim "
                   "contradicts it",
        },
    ]


#: The brief's own batch triple, anywhere in the narrative.
BATCH_TRIPLE = re.compile(
    r"\b(\d{1,3})\s*(?:authorised|authorized)\s*/\s*(\d{1,3})\s*spent\s*/"
    r"\s*\**(\d{1,3})\**\s*remaining", re.I)


# --------------------------------------------------------------------------
# DERIVED FACTS
# --------------------------------------------------------------------------
def derive_batch_from_ledger(ledger_rel=BATCH_LEDGER):
    """The batch is DERIVED from the ledger, never read from a summary.

    The ledger is also REQUIRED to be the one whose digest was recorded.  A
    derivation from a ledger that has moved is not a derivation from the pinned
    artefact, and 16AV declared the recorded digest without ever comparing it.
    """
    p = _abs(ledger_rel)
    if not os.path.exists(p):
        return False, "ledger absent: %s" % ledger_rel, None
    starts, n_records = set(), 0
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                n_records += 1
                if (rec.get("event") == "LAUNCH_STARTED"
                        and rec.get("batch_id") == BATCH_ID):
                    starts.add(rec.get("sequence"))
    except Exception as exc:                                   # noqa: BLE001
        return False, "ledger unreadable: %s" % exc, None
    actual_sha = sha256_file(p)
    if actual_sha != BATCH_LEDGER_SHA_RECORDED:
        return False, ("the ledger has changed since its digest was recorded: "
                       "recorded %s, on disk %s -- the batch derivation is no "
                       "longer from the pinned artefact and must be re-pinned "
                       "before it can be used as current truth"
                       % (BATCH_LEDGER_SHA_RECORDED, actual_sha)), None
    authorised = 5
    spent = len(starts)
    return True, {
        "authorised": authorised,
        "spent": spent,
        "remaining": authorised - spent,
        "n_records": n_records,
        "launch_started_sequences": sorted(x for x in starts if x is not None),
        "source": ledger_rel,
        "source_sha256": actual_sha,
        "source_locator": ["records[event==LAUNCH_STARTED and batch_id==%s]"
                           % BATCH_ID, "sequence"],
        "pinned_sha256": BATCH_LEDGER_SHA_RECORDED,
        "derivation": "spent = |{sequence : event == LAUNCH_STARTED and "
                      "batch_id == %s}|, counted from the ledger" % BATCH_ID,
    }, None


def _slot5_experiment_ids():
    p = _abs(BATCH_LEDGER)
    if not os.path.exists(p):
        return []
    out = []
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec.get("event") == "LAUNCH_STARTED":
                    out.append(rec.get("experiment_id"))
    except Exception:                                          # noqa: BLE001
        return []
    return out


def physical_completion_fact():
    """Derive physical completion by RULE from the frozen Slot-A evidence.

    The rule: the project-owned control completed iff the attempt produced a
    frozen output artefact AND a captured stdout, both with digests, AND the
    freeze was taken before any expectation change (so it cannot be a post-hoc
    artefact).  A SECOND, independent side is then read from the generated
    state record and required to agree -- if the two disagree the fact is
    unresolvable rather than whichever one was read first.
    """
    ok, fr, sha = load_json(SLOT_A_FREEZE)
    if not ok:
        return False, {"error": fr}
    items = fr.get("items") or {}
    out = items.get("physical_output") or {}
    so = items.get("stdout") or {}
    frozen_first = bool(fr.get("frozen_before_any_expectation_change"))
    rule_side = bool(out.get("exists") and out.get("sha256")
                     and so.get("exists") and frozen_first)
    ok2, cs, cs_sha = load_json(CURRENT_STATE)
    gen_side = None
    if ok2:
        gen_side = dig(cs, ["carried_forward_from_16aq", "carried_verbatim",
                            "physical_completion_ever_observed"])
        if gen_side is None:
            gen_side = dig(cs, ["carried_forward_from_16aq",
                                "physical_completion_ever_observed"])
    if gen_side is None:
        return False, {"error": "the generated record carries no "
                                "physical_completion_ever to cross-check"}
    verdict = "YES" if rule_side else "NO"
    gen_verdict = "YES" if gen_side is True or gen_side == "YES" else "NO"
    if verdict != gen_verdict:
        return False, {"error": "TWO INDEPENDENT SIDES DISAGREE: the frozen "
                                "Slot-A evidence says %s, the generated record "
                                "says %s" % (verdict, gen_verdict)}
    return True, {
        "value": verdict,
        "rule": "YES iff physical_output.exists AND physical_output.sha256 AND "
                "stdout.exists AND frozen_before_any_expectation_change",
        "rule_side_inputs": {
            "physical_output_exists": out.get("exists"),
            "physical_output_sha256": out.get("sha256"),
            "stdout_exists": so.get("exists"),
            "frozen_before_any_expectation_change": frozen_first,
        },
        "second_side": {"source": CURRENT_STATE,
                        "source_locator":
                            ["carried_forward_from_16aq", "carried_verbatim",
                             "physical_completion_ever_observed"],
                        "resolved_as": "carried_forward_from_16aq."
                                       "carried_verbatim."
                                       "physical_completion_ever_observed",
                        "source_sha256": cs_sha,
                        "value": gen_side},
        "sides_agree": True,
        "source": SLOT_A_FREEZE,
        "source_sha256": sha,
        "source_locator": ["items.physical_output", "items.stdout",
                           "frozen_before_any_expectation_change"],
        "evidence_ceiling": "that a project-owned control kernel completed "
                            "once; never that Candidate F completed",
    }


def _plain_forms(x, y):
    """Map a v_dual pair to the plain-VALU spellings a non-VOPD target needs."""
    out = []
    for s in (x, y):
        m = re.match(r"^v_dual_([A-Za-z0-9_]+)\s+(.*)$", str(s).strip())
        if not m:
            return None
        out.append((m.group(1), re.sub(r"\s+", " ", m.group(2).strip())))
    return out


def emitted_lowering_for(x, y):
    """MEASURE the emitted Candidate-F lowering of a source v_dual pair.

    gfx1030 has no VOPD, so a source pair MUST be emitted as two plain VALU
    instructions.  The question a translation defect turns on is the ORDER they
    are emitted in, and whether the pair survives fused anywhere.  Both are
    measured from the emitted disassembly rather than read from a summary.
    """
    forms = _plain_forms(x, y)
    if forms is None:
        return {"error": "the source pair is not a v_dual pair: %r" % [x, y]}
    ok, text, sha = load_text(CANDIDATE_F_DISASM)
    if not ok:
        return {"error": text}
    (bx, ox), (by, oy) = forms
    rx = re.compile(r"^v_%s(?:_e32|_e64)?\s+%s$" % (re.escape(bx),
                                                    re.escape(ox)))
    ry = re.compile(r"^v_%s(?:_e32|_e64)?\s+%s$" % (re.escape(by),
                                                    re.escape(oy)))
    # One pass over the instruction stream.  Adjacency is decided by LINE
    # INDEX, so the scan is linear: a nested scan over every X match times
    # every Y match would be quadratic on a 212k-line object and would time out
    # before it ever reached the comparison it is meant to make.
    per_line = {}
    fused_lines = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        body = line.split("//", 1)[0].strip()
        if not body:
            continue
        tags = set()
        if rx.match(body):
            tags.add("X")
        if ry.match(body):
            tags.add("Y")
        if tags:
            per_line[i] = {"tags": sorted(tags), "instruction": body,
                           "address": _addr_of(line)}
        if "v_dual_" in body:
            fused_lines.append({"line_index": i, "instruction": body})
    n_x = sum(1 for v in per_line.values() if "X" in v["tags"])
    n_y = sum(1 for v in per_line.values() if "Y" in v["tags"])
    if not n_x or not n_y:
        return {"error": "the emitted disassembly contains no plain form of the "
                         "pair (%d X matches, %d Y matches) for %r"
                         % (n_x, n_y, [x, y])}
    adjacent = []
    for i, v in sorted(per_line.items()):
        if "X" not in v["tags"]:
            continue
        nxt = per_line.get(i + 1)
        if nxt and "Y" in nxt["tags"]:
            adjacent.append({"X_line_index": i,
                             "Y_line_index": i + 1,
                             "X_instruction": v["instruction"],
                             "Y_instruction": nxt["instruction"],
                             "X_address": v["address"],
                             "Y_address": nxt["address"]})
    # The pair MUST NOT also survive fused anywhere: a fused form would mean
    # the emitter did not have to sequentialise it at all.
    fused_of_the_pair = [f for f in fused_lines
                         if ("v_dual_%s" % bx) in f["instruction"]
                         and ("v_dual_%s" % by) in f["instruction"]]
    return {
        "disassembly": CANDIDATE_F_DISASM,
        "disassembly_sha256": sha,
        "n_lines": len(lines),
        "n_lines_with_the_pair": len(per_line),
        "source_pair": [x, y],
        "plain_X_matches_total": n_x,
        "plain_Y_matches_total": n_y,
        "adjacent_X_then_Y_pairs_total": len(adjacent),
        "adjacent_X_then_Y_pairs": adjacent[:25],
        "sequential_X_then_Y": bool(adjacent),
        "v_dual_lines_total": len(fused_lines),
        "v_dual_lines_of_this_pair": fused_of_the_pair[:5],
        "fused_form_present": bool(fused_of_the_pair),
        "fused_form_anywhere_present": bool(fused_lines),
        "rule": "the pair is one v_dual instruction in the source and MUST be "
                "two plain VALU instructions in a gfx1030 emission; X is the "
                "writer of a register Y reads, so an X-then-Y emission makes Y "
                "read the NEW value",
        "evidence_ceiling": "the EMITTED INSTRUCTION STREAM of this object, "
                            "measured from its disassembly; it is not a "
                            "measurement of any executed result",
    }


def _addr_of(line):
    """Recover the address a disassembler prints after a `//` marker."""
    m = re.search(r"//\s*([0-9A-Fa-f]{6,16})\s*:?", line)
    return "0x" + m.group(1).lstrip("0") if m else None


def candidate_f_cause_fact():
    """The CAUSE of the Slot-4 TDR -- and nothing else.

    CORRECTED WHILE PORTING, ON AN EXPLICIT SCOPING INSTRUCTION.  The first
    draft of this verifier resolved `candidate_f_cause` from the VOPD
    measurement, so that Phase 16AW's demonstrated translation defect became
    the CAUSE of the Slot-4 watchdog reset.  That is an overclaim of exactly the
    kind this project records as "a verdict is scoped to the artefact it read":
    the census measures an INSTRUCTION-ORDER defect in an emitted object; it
    says nothing about why a kernel was reclaimed 21,198.8 ms later.

    The two are separate facts with separate holders:
      * the CAUSE is the causal-rebase record's `cause` field, still UNKNOWN,
        and the inbound audit's own `Candidate-F root cause` field;
      * the DEFECT is a measurement, and lives in its own fact
        (`candidate_f_defect`) with its own vocab token.
    Nothing in this checker lets one feed the other.
    """
    ok, reb, sha = load_json_cached(CANDIDATE_F_CAUSAL_REBASE)
    if not ok:
        return False, {"error": reb}
    cause = dig(reb, ["cause"])
    if cause is None:
        return False, {"error": "the causal-rebase record carries no cause"}
    if dig(reb, ["cause_changed"]) is not False:
        return False, {"error": "the causal-rebase record no longer declares "
                                "cause_changed == false; the durable value has "
                                "moved and this fact must be re-read from "
                                "whatever superseded it"}
    if dig(reb, ["cause_is_still_the_durable_value"]) is not True:
        return False, {"error": "the causal-rebase record no longer declares "
                                "its cause the durable value"}
    corr = _audit_template_corroboration(
        "audit_template:" + AUDIT_ROOT_CAUSE_LABEL, cause)
    if not corr.get("agrees"):
        return False, {"error": "the inbound audit does not corroborate this "
                                "cause: " + str(corr.get("why"))}
    return True, {
        "value": cause,
        "rule": "the causal-rebase record's `cause` field, permitted only while "
                "that record still declares the value durable and unchanged, "
                "and REQUIRED to equal the inbound audit's own root-cause field",
        "source": CANDIDATE_F_CAUSAL_REBASE,
        "source_sha256": sha,
        "source_locator": ["cause"],
        "same_artefact_guards": {
            "cause_changed": dig(reb, ["cause_changed"]),
            "cause_is_still_the_durable_value":
                dig(reb, ["cause_is_still_the_durable_value"]),
            "what_changed_is_the_hypothesis_landscape_NOT_the_cause":
                dig(reb, ["what_changed_is_the_hypothesis_landscape_NOT_the_"
                          "cause"]),
            "why_this_matters": "these are read from the SAME artefact and the "
                                "SAME read as the value, so they are a guard on "
                                "it rather than a second side pretending to be "
                                "independent",
        },
        "corroboration": corr,
        "scope_warning": "this is the root cause of the Slot-4 TDR, NOT the "
                         "demonstrated translation defect.  16AW established "
                         "that a concrete defect EXISTS and did not establish "
                         "that it caused the reset; the two facts are held "
                         "separately and must not be substituted for one "
                         "another.",
        "evidence_ceiling":
            "the cause of the Slot-4 TDR is UNKNOWN.  This says nothing about "
            "whether a defect exists, and the demonstrated defect says nothing "
            "about this.",
    }


def candidate_f_defect_fact():
    """A CONCRETE translation defect, DEMONSTRATED -- not a cause.

    SIDE A -- the local measurement: a source site the operand model itself
    classes as a cross-dependent hazard, with a discriminating witness (the
    atomic and sequential evaluations differ) and with the model's own controls
    all passing, so the model's discriminating power is calibrated rather than
    assumed.
    SIDE B -- the emitted lowering, measured out of the Candidate-F
    disassembly rather than read off any ledger.
    CORROBORATION -- the inbound audit's own `Candidate-F demonstrated defect`
    field, which is an independent record of the same claim and which must
    AGREE; a disagreement BLOCKS rather than being resolved by preferring
    either side.

    A claim ledger asserting the defect is never a side of this comparison, and
    the value is never permitted to enter the `candidate_f_cause` fact.
    """
    ok, cen, cen_sha = load_json_cached(VOPD_CENSUS)
    if not ok:
        return False, {"error": cen}
    site = cen.get("demonstrated_site")
    if not isinstance(site, dict):
        return False, {"error": "the VOPD census carries no demonstrated_site"}
    fields = ("addr", "x", "y", "discriminating", "atomic",
              "sequential_left_then_right", "preceding_instruction")
    missing = [k for k in fields if site.get(k) is None]
    if missing:
        return False, {"error": "the demonstrated site lacks %r" % missing}
    cls = None
    for h in cen.get("hazard_sites") or []:
        if h.get("addr") == site["addr"]:
            cls = h.get("class")
            break
    if cls is None:
        return False, {"error": "the demonstrated site %s does not appear in "
                                "the census's own hazard_sites" % site["addr"]}
    ctl = cen.get("controls") or {}
    rh = cen.get("rules_honoured") or {}
    premise = {
        "n_controls": ctl.get("n"),
        "n_controls_passed": ctl.get("n_passed"),
        "controls_are_rows_with_reached_observer": all(
            r.get("reached_observer") for r in (ctl.get("rows") or [])),
        "printed_order_not_assumed_semantic":
            rh.get("printed_order_not_assumed_semantic"),
        "fail_closed_rule": rh.get("fail_closed"),
    }
    if not ctl.get("n") or ctl.get("n") != ctl.get("n_passed"):
        return False, {"error": "the operand model's controls are not all "
                                "passing, so its discriminating power is not "
                                "declared: %r" % premise}
    if not premise["controls_are_rows_with_reached_observer"]:
        return False, {"error": "a control row did not reach the observer, so "
                                "the model's calibration is unproven: %r"
                                % premise}
    if rh.get("printed_order_not_assumed_semantic") is not True:
        return False, {"error": "the census does not declare that printed "
                                "order was not assumed to be semantic order; "
                                "the premise this rule rests on is undeclared: "
                                "%r" % premise}
    if cls != "HAZARD_LEFT_BEFORE_RIGHT":
        return False, {"error": "the demonstrated site is classed %r; this "
                                "rule is stated only for "
                                "HAZARD_LEFT_BEFORE_RIGHT" % cls}
    discriminating = (site["discriminating"] is True
                      and site["atomic"] != site["sequential_left_then_right"])
    if not discriminating:
        return False, {"error": "the census's own witness for site %s is not "
                                "discriminating, so it establishes no defect"
                                % site["addr"]}
    emitted = emitted_lowering_for(site["x"], site["y"])
    if emitted.get("error"):
        return False, {"error": emitted["error"]}
    found = bool(emitted["sequential_X_then_Y"]
                 and not emitted["fused_form_present"])
    value = "VOPD_SEQUENTIALIZATION_SEMANTIC_DEFECT" if found \
        else "NONE_DEMONSTRATED"
    corr = _audit_template_corroboration(
        "audit_template:" + AUDIT_DEFECT_LABEL, value)
    if not corr.get("agrees"):
        return False, {"error": "the inbound audit does not corroborate this "
                                "demonstrated defect: " + str(corr.get("why"))}
    return True, {
        "value": value,
        "rule": "VOPD_SEQUENTIALIZATION_SEMANTIC_DEFECT iff the census's own "
                "demonstrated site is a discriminating "
                "HAZARD_LEFT_BEFORE_RIGHT witness under a CALIBRATED operand "
                "model AND the emitted disassembly contains the pair as two "
                "ADJACENT plain instructions in X-then-Y order AND the pair "
                "does not survive fused anywhere, AND the inbound audit's own "
                "demonstrated-defect field states the same thing",
        "side_a_source": VOPD_CENSUS,
        "side_a_source_sha256": cen_sha,
        "side_a_locator": ["demonstrated_site"] +
                          ["hazard_sites[addr==%s]" % site["addr"]],
        "side_a": {
            "addr": site["addr"],
            "x": site["x"],
            "y": site["y"],
            "class": cls,
            "preceding_instruction": site["preceding_instruction"],
            "stimulus": site.get("stimulus"),
            "atomic_result": site["atomic"],
            "sequential_left_then_right_result":
                site["sequential_left_then_right"],
            "n_vopd_pairs_in_the_symbol": cen.get("n_vopd_pairs"),
            "n_hazard_sites": cen.get("n_hazard_sites_total"),
            "calibrated_premise": premise,
        },
        "side_b_source": CANDIDATE_F_DISASM,
        "side_b_source_sha256": emitted["disassembly_sha256"],
        "side_b_locator": ["the instruction stream of %s, measured at the "
                           "adjacent X/Y line indices it reports"
                           % CANDIDATE_F_DISASM],
        "side_b": emitted,
        "corroboration": corr,
        "scope_warning": "this is a DEMONSTRATED DEFECT, not a cause.  It must "
                         "not be read as, substituted for, or promoted into the "
                         "`candidate_f_cause` fact, whose value is UNKNOWN and "
                         "whose holder is a different artefact.",
        "evidence_ceiling":
            "that ONE cross-dependent source pair is emitted in the order "
            "that takes the sequential result.  It does NOT establish that "
            "this is why the physical attempt was reclaimed, that any other "
            "site is mis-lowered, or that the emitted order is the ONLY "
            "difference between the two objects.  16AW's own register leaves "
            "VOPD_123_site_semantics OPEN, so no per-site comparison across "
            "the 123 pairs or the 11 hazard sites exists.",
    }


def astra4_fact():
    """DERIVED from two 16AW artefacts plus the preserved body's own bytes.

    SIDE A: the intake's declared ladder and its current rung.
    SIDE B: the audit register's one-token status for the same audit.
    DIGEST: the preserved body must hash to the digest BOTH records claim for
    it -- a preservation record whose digest does not match the bytes on disk
    is not a preservation.
    """
    ok_i, intake, sha_i = load_json_cached(ASTRA4_INTAKE)
    ok_r, reg, sha_r = load_json_cached(AUDIT_REGISTER)
    if not ok_i:
        return False, {"error": "the 16AW Astra-4 intake record: %s" % intake}
    if not ok_r:
        return False, {"error": "the audit register: %s" % reg}
    ladder = dig(intake, ["status_ladder", "vocabulary"])
    state = dig(intake, ["status_ladder", "state_now"])
    if not isinstance(ladder, list) or not ladder:
        return False, {"error": "the intake declares no status ladder"}
    if state is None:
        return False, {"error": "the intake declares no state_now"}
    if state not in ladder:
        return False, {"error": "the intake's state_now %r is not on its own "
                                "declared ladder %r" % (state, ladder)}
    reg_status = dig(reg, ["audits", "AUDIT4", "status"])
    if reg_status is None:
        return False, {"error": "the audit register carries no AUDIT4.status"}
    reg_pres = dig(reg, ["audits", "AUDIT4", "preservation_path"])
    reg_sha = dig(reg, ["audits", "AUDIT4", "whole_file_sha256"])
    in_pres = dig(intake, ["preserved", "path"])
    in_sha = dig(intake, ["preserved", "sha256"])
    # The register folds the first two rungs into one token.  The equivalence is
    # DECLARED here, pair-wise and exact, rather than approximated by a fuzzy
    # match -- an undeclared token is a BLOCKING failure, not a guess.
    register_aliases = {
        "PRESERVED": "PRESERVED",
        "PRESERVED_AND_CLAIMS_EXTRACTED": "CLAIMS_EXTRACTED",
        "CLAIMS_EXTRACTED": "CLAIMS_EXTRACTED",
        "REPRODUCTION_IN_PROGRESS": "REPRODUCTION_IN_PROGRESS",
        "PARTIALLY_DISPOSITIONED": "PARTIALLY_DISPOSITIONED",
        "FULLY_DISPOSITIONED": "FULLY_DISPOSITIONED",
    }
    mapped = register_aliases.get(reg_status)
    if mapped is None:
        return False, {"error": "the audit register's AUDIT4 status %r has no "
                                "declared equivalence to a ladder rung; the "
                                "vocabulary moved and the fact cannot be "
                                "resolved by guessing" % reg_status}
    if mapped != state:
        return False, {"error": "TWO SIDES DISAGREE: the intake's ladder rung "
                                "is %r, the register's status %r normalises to "
                                "%r" % (state, reg_status, mapped)}
    if not in_pres or not reg_pres:
        return False, {"error": "a preservation path is missing from one of "
                                "the two records"}
    if in_pres != reg_pres:
        return False, {"error": "the two records name DIFFERENT preserved "
                                "bodies (%r vs %r)" % (in_pres, reg_pres)}
    if not in_sha or not reg_sha:
        return False, {"error": "a preservation digest is missing from one of "
                                "the two records"}
    if in_sha != reg_sha:
        return False, {"error": "the two records state DIFFERENT digests for "
                                "the preserved body"}
    if not os.path.exists(_abs(in_pres)):
        return False, {"error": "the preserved body %s is not on disk" % in_pres}
    actual = sha256_file(_abs(in_pres))
    if actual != in_sha:
        return False, {"error": "the preserved body on disk hashes to %s; both "
                                "records claim %s" % (actual, in_sha)}
    return True, {
        "value": state,
        "rule": "the value is the intake's declared ladder rung, and it is "
                "REQUIRED to equal the rung the audit register's status "
                "normalises to, and the preserved body on disk is REQUIRED to "
                "hash to the digest both records claim",
        "side_a_source": ASTRA4_INTAKE,
        "side_a_source_sha256": sha_i,
        "side_a_locator": ["status_ladder", "state_now"],
        "side_a": {"state_now": state, "ladder": ladder,
                   "why_not_higher": dig(intake,
                                         ["status_ladder", "why_not_higher"]),
                   "forbidden": dig(intake, ["status_ladder", "forbidden"])},
        "side_b_source": AUDIT_REGISTER,
        "side_b_source_sha256": sha_r,
        "side_b_locator": ["audits", "AUDIT4", "status"],
        "side_b": {"status": reg_status, "declared_alias": mapped},
        "digest_side": {"preserved_body": in_pres,
                        "digest_claimed_by_both": in_sha,
                        "digest_recomputed_here": actual,
                        "agrees": True},
        "digest_side_note": "the preserved body's digest is recomputed from the "
                            "bytes on disk rather than taken from either "
                            "record",
        "evidence_ceiling":
            "how far the inbound audit has been PROCESSED.  It is not a "
            "statement that any claim in it is true, and the intake says so "
            "itself: intake never implies verification.",
    }


def native_liveness_fact():
    """The 16AV rule is RETIRED, on the phase's own measured record.

    16AV derived PASS from `p16at/native/liveness/MACHINE_CFG.json` by the
    rule "every back edge is a natural loop back edge".  16AW's claim ledger
    records the classifier that produced those counts as unsound and the
    finding as OPEN.  This rule therefore does NOT read that artefact as
    current truth.  A PASS may only be stated again when the replacement
    prover's result artefact exists; while it does not, the honest value is the
    retirement, and the inputs that would be needed to say more are named.
    """
    rows = {}
    for name in ("machine_loop_recurrence_proofs",
                 "machine_loop_negative_cases",
                 "transitive_spin_analysis"):
        row, err, _sha = completeness_row(name)
        if err:
            return False, {"error": err}
        rows[name] = {"status": row.get("status"),
                      "evidence": row.get("evidence"),
                      "note": row.get("note")}
    ok_c, claims, claims_sha = load_json_cached(ASTRA4_CLAIMS)
    if not ok_c:
        return False, {"error": "the Astra-4 claim ledger: %s" % claims}
    claim = None
    for c in claims.get("claims") or []:
        if c.get("id") == "A4-F09":
            claim = c
            break
    if claim is None:
        return False, {"error": "the claim ledger carries no A4-F09; the "
                                "disposition that retires the 16AV rule is "
                                "required to be on record, not assumed"}
    disposition = claim.get("disposition")
    if disposition is None:
        return False, {"error": "A4-F09 carries no disposition"}
    result_present = os.path.exists(_abs(LOOP_RESULT))
    if result_present:
        ok_l, loop, loop_sha = load_json(LOOP_RESULT)
        if not ok_l:
            return False, {"error": "the replacement loop-proof result: %s"
                                    % loop}
        v = dig(loop, ["verdict"])
        if v not in ("PASS", "FAIL"):
            return False, {"error": "the replacement loop-proof result carries "
                                    "verdict %r, which is not PASS or FAIL" % v}
        return True, {
            "value": v,
            "rule": "read from the replacement prover's result artefact, which "
                    "exists",
            "source": LOOP_RESULT, "source_sha256": loop_sha,
            "source_locator": ["verdict"],
            "retired_16av_rule": RETIRED_16AV_LIVENESS_RULE,
            "retirement_disposition": {"claim": "A4-F09",
                                       "disposition": disposition},
            "evidence_ceiling": "the replacement prover's own verdict",
        }
    if disposition != "OPEN":
        return False, {"error": "A4-F09 is dispositioned %r and no replacement "
                                "result artefact exists at %s; the fact is "
                                "UNRESOLVABLE rather than either the retired "
                                "PASS or an invented verdict"
                                % (disposition, LOOP_RESULT)}
    return True, {
        "value": "RETIRED_UNSOUND",
        "rule": "RETIRED_UNSOUND while the claim that retires the 16AV "
                "classifier is dispositioned OPEN and the replacement prover's "
                "result artefact does not exist",
        "source": ASTRA4_CLAIMS,
        "source_sha256": claims_sha,
        "source_locator": ["claims[id==A4-F09]", "disposition"],
        "retired_16av_rule": RETIRED_16AV_LIVENESS_RULE,
        "retirement_disposition": {"claim": "A4-F09",
                                   "subject": claim.get("subject"),
                                   "disposition": disposition,
                                   "acceptance_criterion":
                                       claim.get("acceptance_criterion")},
        "replacement_work_rows": rows,
        "replacement_result_artefact": LOOP_RESULT,
        "replacement_result_present": False,
        "why_not_PASS": "a PASS would restate the retired classifier's "
                        "conclusion; no measurement in this phase supports it",
        "why_not_FAIL": "a FAIL would assert that the loops are unsound, which "
                        "is not what is recorded -- what is recorded is that "
                        "the PROOF was unsound",
        "evidence_ceiling":
            "the standing 16AT liveness PASS is retired and not re-established. "
            "It asserts nothing about the loops themselves.",
    }


RETIRED_16AV_LIVENESS_RULE = {
    "the_retired_rule": "PASS iff n_natural_loop_back_edges == "
                        "n_branch_instructions AND "
                        "n_conditional_branches_with_UNKNOWN_scc_producer == 0 "
                        "AND n_edges_that_are_backward_but_not_natural == 0",
    "artefact_it_read": "p16at/native/liveness/MACHINE_CFG.json",
    "why_retired": "the classifier that produced those counts discharged all 33 "
                   "back edges by widening a compare-mnemonic regex, which "
                   "changes the match vocabulary rather than proving a "
                   "recurrence; 16AW records this as A4-F09, OPEN",
    "not_deleted": True,
}


def first_frame_contract_fact():
    """DERIVED: recompute the numerator from the frozen contract's own rows.

    16AV read the STRING "520 / 535" out of the authorisation record.  A string
    cannot be checked.  The contract carries one row per required field and a
    resolution state per row, so the numerator is recomputable: it is the
    number of required fields whose resolution state is not UNRESOLVED.  An
    UNDECLARED resolution state BLOCKS rather than being counted either way.
    """
    ok, contract, sha = load_json_cached(FIRST_FRAME_CONTRACT)
    if not ok:
        return False, {"error": contract}
    rows = contract.get("required_fields")
    if not isinstance(rows, list) or not rows:
        return False, {"error": "the frozen contract carries no required_fields"}
    n_required = contract.get("n_required_fields")
    if n_required != len(rows):
        return False, {"error": "the contract states n_required_fields=%r but "
                                "carries %d rows"
                                % (n_required, len(rows))}
    declared_states = {"ALREADY_CARRIED_BY_CONTRACT", "RESOLVED_BY_REBASE",
                       "UNRESOLVED"}
    seen = {}
    for r in rows:
        s = r.get("resolution_state")
        if s not in declared_states:
            return False, {"error": "the contract row for %r carries "
                                    "resolution_state %r, which this rule does "
                                    "not declare; the vocabulary moved"
                                    % (r.get("field_path"), s)}
        seen[s] = seen.get(s, 0) + 1
    resolved = sum(v for k, v in seen.items() if k != "UNRESOLVED")
    value = "%d / %d" % (resolved, len(rows))
    ok2, auth, sha2 = load_json_cached(RAW_DUMP_AUTH)
    if not ok2:
        return False, {"error": auth}
    stated = dig(auth, ["part_3_first_frame_contract", "value"])
    if stated is None:
        return False, {"error": "the authorisation record carries no "
                                "first-frame contract row"}
    a, _ = canonicalise("first_frame_contract", stated)
    b, _ = canonicalise("first_frame_contract", value)
    if a is None:
        return False, {"error": "the authorisation record's stated contract "
                                "value %r is outside the vocabulary" % stated}
    if a != b:
        return False, {"error": "TWO INDEPENDENT SIDES DISAGREE: recomputing "
                                "from the contract's rows gives %r, the "
                                "authorisation record states %r"
                                % (value, stated)}
    return True, {
        "value": value,
        "rule": "numerator = |{required field : resolution_state != "
                "UNRESOLVED}|, denominator = n_required_fields; the "
                "authorisation record's stated string is REQUIRED to agree",
        "side_a_source": FIRST_FRAME_CONTRACT,
        "side_a_source_sha256": sha,
        "side_a_locator": ["required_fields[].resolution_state"],
        "side_a": {"n_required_fields": n_required,
                   "state_histogram": seen,
                   "numerator": resolved},
        "side_b_source": RAW_DUMP_AUTH,
        "side_b_source_sha256": sha2,
        "side_b_locator": ["part_3_first_frame_contract", "value"],
        "side_b": {"stated": stated, "canonical": a},
        "sides_agree": True,
        "evidence_ceiling": "how many required fields have a stated resolution; "
                            "NOT that the resolved values are correct",
    }


def translation_differential_fact():
    """DERIVED from the provenance chain, with the 16AV source's RETIREMENT
    required to be on record.

    16AV's fact source for this key
    (`p16av/candidate_f/CANDIDATE_F_TRANSLATION_DIFFERENTIAL_V1.json`) is
    tagged `SUPERSEDED_WRONG_PARENT` by this phase's provenance chain.  Read as
    current truth it would carry a verdict computed against the wrong parent.
    The chain is therefore read instead, and the supersession itself is a
    REQUIRED input: if the chain stops recording it, the fact BLOCKS rather
    than silently reverting to the retired file.
    """
    ok, chain, sha = load_json_cached(PROVENANCE_CHAIN)
    if not ok:
        return False, {"error": chain}
    superseded = chain.get("superseded_wrong_parent_artifacts") or []
    entry = None
    for s in superseded:
        if s.get("path") == CANDIDATE_F_DIFFERENTIAL_16AV:
            entry = s
            break
    if entry is None:
        return False, {"error": "the provenance chain does not record %s as "
                                "SUPERSEDED_WRONG_PARENT; the 16AV fact source "
                                "is retired by the project's own record and "
                                "this checker will not read it as current "
                                "truth" % CANDIDATE_F_DIFFERENTIAL_16AV}
    retired_path = _abs(CANDIDATE_F_DIFFERENTIAL_16AV)
    if not os.path.exists(retired_path):
        return False, {"error": "the superseded artefact %s is not on disk; the "
                                "supersession record cannot be checked"
                                % CANDIDATE_F_DIFFERENTIAL_16AV}
    retired_sha = sha256_file(retired_path)
    if entry.get("sha256") != retired_sha:
        return False, {"error": "the supersession record names sha256 %s for "
                                "%s; the bytes on disk hash to %s"
                                % (entry.get("sha256"),
                                   CANDIDATE_F_DIFFERENTIAL_16AV, retired_sha)}
    comp = chain.get("completeness") or {}
    n_measured = comp.get("links_with_a_measured_sha")
    n_unresolved = comp.get("links_recorded_unresolved")
    translator = dig(chain, ["5_translator"]) or {}
    revision = translator.get("revision_of_record")
    if n_measured is None or n_unresolved is None or revision is None:
        return False, {"error": "the provenance chain lacks the completeness "
                                "fields this rule reads"}
    ceiling_reduced = any(
        s.get("evidence_ceiling_after_supersession")
        for s in superseded)
    if n_measured == 0:
        value = "BLOCKED"
    elif n_unresolved > 0 or revision == "UNRESOLVED" or ceiling_reduced:
        value = "PARTIAL"
    else:
        value = "COMPLETE"
    return True, {
        "value": value,
        "rule": "BLOCKED if no link has a measured digest; PARTIAL if any link "
                "is recorded unresolved OR the translator revision of record is "
                "UNRESOLVED OR any superseded artefact carries a reduced "
                "evidence ceiling; COMPLETE only if none of those hold",
        "source": PROVENANCE_CHAIN,
        "source_sha256": sha,
        "source_locator": ["completeness", "5_translator.revision_of_record",
                           "superseded_wrong_parent_artifacts"],
        "inputs": {"links_with_a_measured_sha": n_measured,
                   "links_recorded_unresolved": n_unresolved,
                   "translator_revision_of_record": revision,
                   "evidence_ceiling_reduced_somewhere": ceiling_reduced},
        "retired_16av_fact_source": {
            "path": CANDIDATE_F_DIFFERENTIAL_16AV,
            "sha256_recomputed_here": retired_sha,
            "sha256_in_the_supersession_record": entry.get("sha256"),
            "disposition": entry.get("disposition"),
            "evidence_ceiling_after_supersession":
                entry.get("evidence_ceiling_after_supersession"),
            "read_as_current_truth": False,
        },
        "evidence_ceiling":
            "how far the candidate-F provenance chain has been MEASURED.  It "
            "does not establish that the differential's values are right.",
    }


def capture_only_authorization_fact():
    """DERIVED: the committed verdict, GATED on the session's spent state.

    CORRECTED WHILE PORTING.  The first version of this rule read the capture
    session's `status` as a second side -- the same artefact and the same
    locator that the `gta_capture` fact holds.  The tautology guard reported it:
    one locator was the holder of two facts, so the "second side" was a second
    reading of `gta_capture`, not independent evidence, and the run failed.  The
    reader was not relabelled; it was REMOVED.  The gate is now 16AW's own
    completeness row (a different artefact, a different locator), which is the
    same state as seen from the phase's record and which moves when the
    authorization is spent.

    A gate is not a second side: it cannot make two facts agree, it can only
    BLOCK one.  That is why this fact states the distinction explicitly rather
    than carrying a `side_b` that a reader would wrongly read as independence.
    """
    ok, auth, sha = load_json_cached(RAW_DUMP_AUTH)
    if not ok:
        return False, {"error": auth}
    verdict = dig(auth, ["part_1_authorization_verified_from_committed_state",
                         "verdict"])
    if verdict is None:
        return False, {"error": "the authorisation record carries no committed "
                                "verification verdict"}
    vtok, _ = canonicalise("capture_only_authorization", verdict)
    if vtok is None:
        return False, {"error": "the committed verdict %r is outside the "
                                "vocabulary" % verdict}
    corr = _completeness_corroboration(
        "completeness_row:capture_cold_frame", vtok)
    if not corr.get("agrees"):
        return False, {"error": "the authorization's unspent state is not "
                                "corroborated by 16AW's own record: "
                                + str(corr.get("why"))}
    return True, {
        "value": vtok,
        "rule": "the committed verdict, permitted only while 16AW's own record "
                "still has the capture frame as CONDITION_NOT_REACHED -- an "
                "authorization that has been spent is not an unspent "
                "authorization",
        "source": RAW_DUMP_AUTH, "source_sha256": sha,
        "source_locator": ["part_1_authorization_verified_from_committed_state",
                           "verdict"],
        "gate_not_a_second_side":
            "the spent/unspent gate is 16AW's completeness row, NOT the "
            "capture session's own status: the session status is already the "
            "holder of the `gta_capture` fact, and reading it here too would "
            "make one locator the holder of two facts",
        "corroboration": corr,
        "evidence_ceiling": "the authorization is valid and unspent; it is not "
                            "a statement that a capture is authorised now",
    }


def slot5_decision_fact():
    """DERIVED: the decision record, guarded by the absence of a successor."""
    ok, dec, sha = load_json_cached(SLOT5_DECISION)
    if not ok:
        return False, {"error": dec}
    verdict = dig(dec, ["verdict"])
    if verdict is None:
        return False, {"error": "the Slot-5 decision record carries no verdict"}
    corr = _completeness_corroboration(
        "completeness_row:Slot5_final_decision", None)
    if not corr.get("agrees"):
        return False, {"error": "16AW's own record does not corroborate this "
                                "decision as the current one: " + str(
                                    corr.get("why"))}
    return True, {
        "value": verdict,
        "rule": "the decision record's verdict, permitted only while 16AW "
                "records Slot5_final_decision as CONDITION_NOT_REACHED -- a "
                "successor decision would move that row and BLOCK this fact "
                "rather than let the old decision keep reporting",
        "source": SLOT5_DECISION, "source_sha256": sha,
        "source_locator": ["verdict"],
        "corroboration": corr,
        "evidence_ceiling": "the last decision of record; not a statement that "
                            "the decision was correct",
    }


def publication_fact(field):
    """The publication facts, with the fallback's use made explicit.

    When no 16AW publication record has been filed, the last MEASURED state is
    used and the fallback is REQUIRED to be consistent with 16AW's own record
    that no push happened this phase.
    """
    spec = FACT_SOURCES[field]
    if os.path.exists(_abs(PUBLICATION_16AW)):
        spec = {**spec, "source": PUBLICATION_16AW,
                "locator": spec["locator"], "fallback": None}
    ok, doc, sha = load_json(spec["source"])
    val = dig(doc, spec["locator"]) if ok else None
    if val is None and spec.get("fallback"):
        fb = spec["fallback"]
        ok, doc, sha = load_json(fb[0])
        val = dig(doc, fb[1]) if ok else None
        if val is not None:
            used_fallback = True
        else:
            return False, {"error": "neither %s nor its fallback %s yielded %r"
                                    % (spec["source"], fb[0], spec["locator"])}
    else:
        used_fallback = False
    if not ok:
        return False, {"error": doc}
    if val is None:
        return False, {"error": "locator %r did not resolve in %s"
                                % (spec["locator"], spec["source"])}
    # Only ONE of the two publication facts is corroborated, and the other is
    # not.  Both are held by the same record with different locators, and both
    # would be gated by the same completeness row -- which is one locator
    # serving two facts, and the tautology guard reports it.  Rather than
    # relabel the second reading, the redundant gate is dropped: the currency
    # of the publication record is a property of the RECORD, the two facts are
    # compared against it independently, and a gate that blocks blocks the
    # whole document whichever fact carries it.  `public_branch` therefore
    # resolves without a gate of its own, and says so.
    if field != "publication_status":
        return True, {
            "value": val,
            "source": spec["source"],
            "source_sha256": sha,
            "source_locator": spec["locator"],
            "used_fallback": used_fallback,
            "fallback_source": spec["fallback"][0] if used_fallback else None,
            "gate": "none of its own: the currency of this record is gated by "
                    "the publication_status fact, which shares the record and "
                    "therefore blocks the document if it blocks",
            "evidence_ceiling":
                "the branch named by the publication record this fact "
                "resolved from; not a claim about the remote",
        }
    corr = _completeness_corroboration("completeness_row:publication_push",
                                       None)
    if not corr.get("agrees"):
        return False, {"error": "16AW's own record does not corroborate this "
                                "publication state: " + str(corr.get("why"))}
    if used_fallback and corr.get("row_status") == "COMPLETE":
        return False, {"error": "16AW records publication_push as COMPLETE but "
                                "no 16AW publication record is on disk; the "
                                "fact must be read from the record the push "
                                "produced, not from the previous phase's"}
    return True, {
        "value": val,
        "source": spec["source"],
        "source_sha256": sha,
        "source_locator": spec["locator"],
        "used_fallback": used_fallback,
        "fallback_source": spec["fallback"][0] if used_fallback else None,
        "corroboration": corr,
        "evidence_ceiling":
            "the last MEASURED publication state of record.  When the fallback "
            "is used this is NOT a fresh measurement for this phase, and the "
            "field says so rather than implying currency.",
    }


#: field -> (function, human description of what it derives)
RULE_FACTS = {
    "physical_completion_ever": physical_completion_fact,
    "candidate_f_cause": candidate_f_cause_fact,
    "candidate_f_defect": candidate_f_defect_fact,
    "astra4": astra4_fact,
    "native_liveness": native_liveness_fact,
    "first_frame_contract": first_frame_contract_fact,
    "translation_differential": translation_differential_fact,
    "capture_only_authorization": capture_only_authorization_fact,
    "slot5_decision": slot5_decision_fact,
}


def _fill_derived(facts, prov):
    """Facts that are DERIVED rather than read from a single field."""
    ok, batch, err = derive_batch_from_ledger()
    if ok:
        prov["batch"] = {"kind": "DERIVED_LEDGER", **batch}
    else:
        prov["batch"] = {"kind": "DERIVED_LEDGER",
                         "source": BATCH_LEDGER, "error": err}
    ids = _slot5_experiment_ids()
    derived_slot5 = ("NOT_RUN" if SLOT5_EXPERIMENT_ID not in ids
                     else "LAUNCHED_RECORDED")
    row, row_err, row_sha = completeness_row("Slot5_physical")
    # `batch` and `slot5` both derive from the SAME ledger, and they are two
    # facts rather than one because they PROJECT different fields through
    # different predicates.  Their locators say so, so the tautology guard can
    # tell the difference between this and two readings of one thing.
    prov["slot5_derivation"] = {
        "kind": "DERIVED_LEDGER",
        "rule": "Slot-5 is NOT_RUN unless a LAUNCH_STARTED record names %r"
                % SLOT5_EXPERIMENT_ID,
        "source": BATCH_LEDGER,
        "source_locator": ["records[event==LAUNCH_STARTED]", "experiment_id"],
        "observed_launch_started_experiment_ids": ids,
        "derived_value": derived_slot5,
        "overridden_by_fixture": "slot5" in facts,
        "corroboration": None if row_err else {
            "row": "Slot5_physical", "status": row.get("status"),
            "note": row.get("note"),
            "agrees": (row.get("status") == "CONDITION_NOT_REACHED")
                      == (derived_slot5 == "NOT_RUN"),
            "corroboration_source": COMPLETENESS,
            "corroboration_source_sha256": row_sha,
            "corroboration_locator": ["rows[row==Slot5_physical]", "status"],
        },
    }
    facts.setdefault("slot5", derived_slot5)


def build_facts(facts_file=None):
    """Resolve every fact from its artefact.  Returns (ok, facts, provenance)."""
    facts, prov, errors = {}, {}, []
    all_fields = list(FACT_SOURCES.keys())
    if facts_file:
        ok, doc, sha = load_json(facts_file)
        if not ok:
            return False, {}, {"error": doc}
        facts = dict(doc.get("facts", {}))
        prov = {"mode": "OVERRIDE_FILE", "path": facts_file, "sha256": sha,
                "note": "regression/mutation mode: facts supplied by a fixture "
                        "bundle, so the checker's LOGIC is exercised "
                        "independently of whether this phase's artefacts exist"}
        _fill_derived(facts, prov)
        return True, facts, prov

    prov = {"mode": "LIVE", "sources": {}, "rules_retired": {
        "native_liveness": RETIRED_16AV_LIVENESS_RULE,
        "translation_differential_fact_source":
            CANDIDATE_F_DIFFERENTIAL_16AV,
        "batch_ledger_digest_now_compared": True,
    }}
    for field, spec in FACT_SOURCES.items():
        if spec["source"] is None:
            fn = RULE_FACTS.get(field)
            if fn is None:
                errors.append({"field": field,
                               "why": "no holder and no rule: the fact source "
                                      "map is inconsistent"})
                continue
            ok, payload = fn()
            if not ok:
                errors.append({"field": field, "why": payload["error"]})
                continue
            facts[field] = payload["value"]
            prov["sources"][field] = {"kind": "DERIVED_RULE", **payload}
            continue
        if field in ("publication_status", "public_branch"):
            ok, payload = publication_fact(field)
            if not ok:
                errors.append({"field": field, "why": payload["error"]})
                continue
            facts[field] = payload["value"]
            prov["sources"][field] = {"kind": "ARTEFACT", **payload}
            continue
        spec = dict(spec)
        ok, doc, sha = load_json(spec["source"])
        val = dig(doc, spec["locator"]) if ok else None
        if val is None:
            fb = spec.get("fallback")
            if fb:
                ok2, doc2, sha2 = load_json(fb[0])
                v2 = dig(doc2, fb[1]) if ok2 else None
                if v2 is not None:
                    ok, doc, sha, val = ok2, doc2, sha2, v2
                    spec = {"source": fb[0], "locator": fb[1],
                            "why": spec.get("why")}
        if not ok:
            errors.append({"field": field, "why": doc})
            continue
        if val is None:
            errors.append({"field": field,
                           "why": "locator %r did not resolve in %s"
                                  % (spec["locator"], spec["source"])})
            continue
        corr = corroborate(field, spec, val)
        rec = {"kind": "ARTEFACT", "path": spec["source"],
               "locator": spec["locator"], "sha256": sha, "value": val,
               "why": spec.get("why"),
               "evidence_ceiling": spec.get("evidence_ceiling")}
        if spec.get("no_corroboration_because"):
            rec["no_corroboration_because"] = spec["no_corroboration_because"]
        if corr is not None:
            rec["corroboration"] = corr
            if not corr.get("agrees"):
                errors.append({"field": field,
                               "why": "the corroborating side did not agree: "
                                      + str(corr.get("why"))})
                prov["sources"][field] = rec
                continue
        facts[field] = val
        prov["sources"][field] = rec
    _fill_derived(facts, prov)
    return (not errors), facts, {**prov, "errors": errors}


# --------------------------------------------------------------------------
# NORMALISATION, PARSING, SCANNING
# --------------------------------------------------------------------------
def canonicalise(field, raw):
    if raw is None:
        return None, "no value"
    s = str(raw).strip().strip("`*").strip()
    if not s:
        return None, "empty after stripping markup"
    if field in FREE_KEYS:
        return s, "verbatim (free key)"
    if field == "first_frame_contract":
        m = re.match(r"^(\d+)\s*/\s*(\d+)$", s)
        if m:
            return m.group(1), "matched 'N / 535' form"
    table = VOCAB.get(field)
    if table is None:
        return s, "verbatim (no vocabulary table)"
    for token, pats in table:
        for pat in [r"^%s$" % re.escape(token)] + list(pats):
            if re.search(pat, s, re.I):
                return token, "matched %r" % pat
    return None, ("no vocabulary rule matched %r -- an unrecognised value is "
                  "not a value" % s)


def parse_operator_block(body):
    """Extract `key = value` pairs from the delimited block."""
    i = body.find(BLOCK_BEGIN)
    j = body.find(BLOCK_END)
    rec = {"begin_found": i != -1, "end_found": j != -1, "pairs": {},
           "duplicates": [], "malformed": [],
           "legacy_block_found": (LEGACY_BLOCK_BEGIN in body
                                  or LEGACY_BLOCK_END in body)}
    if i == -1 or j == -1 or j < i:
        return rec
    block = body[i + len(BLOCK_BEGIN):j]
    rec["block_text"] = block
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(.*?)\s*$", line)
        if not m:
            rec["malformed"].append(line)
            continue
        key, val = m.group(1), m.group(2)
        if key in rec["pairs"]:
            rec["duplicates"].append(key)
            continue
        rec["pairs"][key] = val
    return rec


def quoted_spans(body):
    """Ranges that NAME a phrase rather than ASSERT it.

    A report that describes a defect has to be able to write the defect's own
    wording.  The exemption is deliberately NARROW: only inline code spans
    (backticked, on one line) and fenced code blocks.  Plain prose is never
    exempt, so the control that puts the same sentence in prose must still be
    rejected -- and that pair is exercised in the mutation corpus.
    """
    spans = []
    for m in re.finditer(r"```.*?```", body, re.S):
        spans.append((m.start(), m.end()))
    for line in re.finditer(r"[^\n]*", body):
        t = line.group(0)
        for m in re.finditer(r"`[^`\n]+`", t):
            spans.append((line.start() + m.start(), line.start() + m.end()))
    return spans


def _prefix_zone(body, start, max_chars=320):
    """The span a negation word may sit in and still negate the match.

    The zone runs back to the previous SENTENCE boundary, not to the start of
    the LINE.  A line-limited zone makes the checker's behaviour depend on where
    the author happened to wrap a line: the known-good sentence "the retired
    24 / 26 gate score is no longer physical authority", wrapped after
    "retired", was rejected by a line-limited zone, and the same sentence
    unwrapped was accepted.  A checker whose verdict depends on wrapping is not
    measuring meaning.

    The zone is bounded and stops at a sentence terminator, so a negation in a
    PREVIOUS sentence cannot suppress an assertion in this one.
    """
    if start <= 0:
        return ""
    win = body[max(0, start - max_chars):start]
    cuts = [m.end() for m in re.finditer(r"(?:[.!?])\s", win)]
    if cuts:
        win = win[cuts[-1]:]
    return win


def scan_assertions(body, facts):
    """Directional narrative scan with negation and quotation suppression."""
    out = []
    quotes = quoted_spans(body)
    for rule in _assertion_rules():
        try:
            fires = bool(rule["fires_when"](facts))
        except Exception:                                      # noqa: BLE001
            fires = False
        rec = {"rule": rule["id"], "fact_read": rule["fact_read"],
               "fact_supports_it": fires,
               "why": rule["why"], "hits": [], "suppressed": [],
               "result": PASS}
        if not fires:
            rec["result"] = "NOT_APPLICABLE"
            out.append(rec)
            continue
        for pat in rule["forbidden"]:
            for m in re.finditer(pat, body, re.I):
                line_start = body.rfind("\n", 0, m.start()) + 1
                line_end = body.find("\n", m.end())
                if line_end == -1:
                    line_end = len(body)
                prefix = _prefix_zone(body, m.start())
                # Negation suppression has TWO zones, and both are needed:
                #   * the sentence before the match -- "It is not true that no
                #     kernel has completed";
                #   * INSIDE the match, between the subject and the verb --
                #     "Candidate F has not completed".
                # The first word of the match is excluded from the inner zone,
                # because a leading "no" there is part of the assertion
                # ("No kernel has completed"), not a negation of it.
                words = m.group(0).split()
                inner = " ".join(words[1:-1]) if len(words) > 2 else ""
                if NEGATION.search(prefix) or NEGATION.search(inner):
                    rec["suppressed"].append(
                        {"match": m.group(0)[:120],
                         "prefix_tail": prefix[-90:],
                         "inner": inner,
                         "reason": "NEGATED"})
                    continue
                if any(a <= m.start() and m.end() <= b for a, b in quotes):
                    rec["suppressed"].append(
                        {"match": m.group(0)[:120],
                         "reason": "QUOTED -- the phrase is NAMED inside code "
                                   "markup, not asserted in prose"})
                    continue
                rec["hits"].append({"match": m.group(0)[:160],
                                    "pattern": pat,
                                    "line": body[line_start:line_end]
                                            .strip()[:200]})
        rec["result"] = FAIL if rec["hits"] else PASS
        out.append(rec)
    return out


def check_batch_triple(body, facts, prov):
    """Every `N authorised / M spent / K remaining` in the document must agree."""
    rec = {"rule": "batch_triple", "hits": [], "result": PASS}
    b = prov.get("batch") or {}
    if "authorised" not in b:
        rec["result"] = BLOCKED
        rec["why"] = "the ledger derivation failed: %s" % b.get("error")
        return rec
    want = (b["authorised"], b["spent"], b["remaining"])
    rec["expected"] = want
    rec["derivation"] = b.get("derivation")
    rec["ledger"] = b.get("source")
    rec["ledger_sha256"] = b.get("source_sha256")
    for m in BATCH_TRIPLE.finditer(body):
        got = tuple(int(x) for x in m.groups())
        ok = got == want
        rec["hits"].append({"found": list(got), "expected": list(want), "ok": ok})
        if not ok:
            rec["result"] = FAIL
    if not rec["hits"]:
        rec["result"] = FAIL
        rec["why"] = ("the document states no batch triple anywhere; the batch "
                      "is a required generated field and its absence is not a "
                      "consistent claim")
    return rec


def check_operator_block(parsed, facts, prov):
    rows = []
    keys = parsed["pairs"]
    for key, fact_key in REQUIRED_KEYS.items():
        raw = keys.get(key)
        fact_val = facts.get(fact_key)
        row = {"key": key, "raw": raw, "fact": fact_val,
               "fact_source": (prov.get("sources", {}).get(fact_key)
                               or {"kind": "UNRESOLVED_NO_PROVENANCE"}),
               "evidence_ceiling": (prov.get("sources", {})
                                    .get(fact_key, {})
                                    .get("evidence_ceiling"))}
        if raw is None:
            row.update(result=FAIL,
                       why="the operator block does not state this required key")
            rows.append(row)
            continue
        if fact_val is None:
            row.update(result=BLOCKED,
                       why="the fact for this key could not be resolved, so no "
                           "comparison is possible")
            rows.append(row)
            continue
        tok, rule = canonicalise(key, raw)
        ftok, frule = canonicalise(key, fact_val)
        row["canonical"] = tok
        row["canonical_rule"] = rule
        row["fact_canonical"] = ftok
        if tok is None:
            row.update(result=FAIL, why=rule)
        elif ftok is None:
            row.update(result=BLOCKED,
                       why="the FACT value %r has no vocabulary rule: %s"
                           % (fact_val, frule))
        elif tok != ftok:
            row.update(result=FAIL,
                       why="the report says %r (%s) but the fact is %r (%s)"
                           % (tok, rule, ftok, frule))
        else:
            row.update(result=PASS,
                       why="report and fact agree on %r" % tok)
        rows.append(row)
    return rows


def tautology_guard(prov):
    """One source path AND one locator is one fact, however many times it is
    labelled.

    Extended from 16AV: the CORROBORATING locators are included, so a fact
    cannot be corroborated by re-reading the very locator another fact was
    resolved from.  Without this the corroboration mechanism would itself be a
    place to hide a tautology.
    Extended again while writing the C07 control, which CRASHED on this: the
    publication facts are the one pair of ARTEFACT sources that name their file
    `source`/`source_locator` instead of `path`/`locator`, and the guard was
    reading only `path`/`locator` -- so the pair escaped the tautology check
    entirely.  The two facts and their two DIFFERENT locators happen to be
    legitimate, which is exactly why this was worth fixing rather than
    relabelling: a guard that cannot see a pair cannot clear it either, and the
    same shape would have hidden a real collision.  Either spelling is accepted
    on BOTH sides of the comparison, so the spelling cannot be chosen to escape.
    """
    seen, dupes = {}, []
    def note(owner, role, path, locator):
        if not path:
            return
        sig = (path, tuple(locator or []))
        if sig in seen:
            dupes.append({"a": seen[sig], "b": "%s (%s)" % (owner, role),
                          "source": path, "locator": list(locator or [])})
        else:
            seen[sig] = "%s (%s)" % (owner, role)
    named = dict(prov.get("sources") or {})
    # The two ledger derivations live beside the per-field sources, not inside
    # them: they are phase-level facts with their own projections.
    for extra in ("batch", "slot5_derivation"):
        if isinstance(prov.get(extra), dict):
            named[extra] = prov[extra]

    for k, v in named.items():
        if not isinstance(v, dict):
            continue
        if v.get("kind") == "ARTEFACT":
            note(k, "holder", v.get("path") or v.get("source"),
                 v.get("locator") or v.get("source_locator"))
        # A corroboration's own locator counts.  Without this the corroboration
        # mechanism would be a place to hide a tautology: the standard
        # corroborators read an artefact and a locator like anything else.
        corr = v.get("corroboration")
        if isinstance(corr, dict):
            note(k, "corroboration", corr.get("corroboration_source"),
                 corr.get("corroboration_locator"))
        if v.get("corroboration_source"):
            note(k, "corroboration_source", v.get("corroboration_source"),
                 v.get("corroboration_locator"))
        if v.get("side_a_source"):
            note(k, "side_a", v.get("side_a_source"), v.get("side_a_locator"))
        if v.get("side_b_source"):
            note(k, "side_b", v.get("side_b_source"), v.get("side_b_locator"))
        if v.get("source") and v.get("kind") in ("DERIVED_RULE",
                                                 "DERIVED_LEDGER"):
            note(k, "derived_source", v.get("source"),
                 v.get("source_locator"))
        second = v.get("second_side")
        if isinstance(second, dict) and second.get("source"):
            note(k, "second_side", second.get("source"),
                 second.get("source_locator"))
    return dupes


def check_document(body, document_name, facts, prov):
    parsed = parse_operator_block(body)
    rows = check_operator_block(parsed, facts, prov)
    assertions = scan_assertions(body, facts)
    batch = check_batch_triple(body, facts, prov)
    dupes = tautology_guard(prov)

    self_cert = {k: parsed["pairs"][k] for k in SELF_CERTIFICATION_KEYS
                 if k in parsed["pairs"]}

    structural = []
    if not parsed["begin_found"] or not parsed["end_found"]:
        structural.append({"id": "operator_block_present", "result": FAIL,
                           "legacy_block_found": parsed["legacy_block_found"],
                           "why": "the report carries no delimited operator "
                                  "block; a report the checker cannot parse is "
                                  "not a report it may pass"})
    else:
        structural.append({"id": "operator_block_present", "result": PASS,
                           "legacy_block_found": parsed["legacy_block_found"]})
    structural.append({
        "id": "no_predecessor_block_markers",
        "result": FAIL if parsed["legacy_block_found"] else PASS,
        "why": "the 16AV block markers belong to the 16AV verifier's schema; a "
               "16AW report carrying them is stated in the wrong schema"
               if parsed["legacy_block_found"] else None})
    structural.append({
        "id": "operator_block_wellformed",
        "result": FAIL if parsed["malformed"] else PASS,
        "malformed": parsed["malformed"][:10]})
    structural.append({
        "id": "operator_block_no_duplicate_keys",
        "result": FAIL if parsed["duplicates"] else PASS,
        "duplicates": parsed["duplicates"]})
    structural.append({
        "id": "facts_not_tautological",
        "result": FAIL if dupes else PASS,
        "duplicates": dupes,
        "why": "two facts resolved from one artefact and one locator are one "
               "fact, not two; the guard covers corroborating locators too"})

    n_comparisons = sum(1 for r in rows if r["result"] in (PASS, FAIL))
    n_required = len(REQUIRED_KEYS)
    structural.append({
        "id": "every_required_key_compared",
        "result": PASS if n_comparisons >= n_required else FAIL,
        "n_comparisons": n_comparisons,
        "n_required_keys": n_required,
        "why": "a checker that compared fewer keys than the schema requires has "
               "certified less than it claims"})

    worst = PASS
    for r in [x["result"] for x in rows] + \
             [a["result"] for a in assertions
              if a["result"] != "NOT_APPLICABLE"] + \
             [batch["result"]] + \
             [s["result"] for s in structural]:
        if r == FAIL:
            worst = FAIL
            break
        if r == BLOCKED and worst == PASS:
            worst = BLOCKED

    return {
        "document": document_name,
        "document_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "operator_block": {"pairs": parsed["pairs"],
                           "n_pairs": len(parsed["pairs"]),
                           "malformed": parsed["malformed"],
                           "duplicates": parsed["duplicates"],
                           "legacy_block_found": parsed["legacy_block_found"]},
        "self_certification_keys_seen_and_not_read": self_cert,
        "key_rows": rows,
        "n_keys_compared": n_comparisons,
        "n_required_keys": n_required,
        "assertion_rules": assertions,
        "batch_triple": batch,
        "structural": structural,
        "tautologies": dupes,
        "uncompared_keys_declared": UNCOMPARED_KEYS,
        "result": worst,
        "result_note": ("BLOCKED means a fact could not be resolved; it is "
                        "scored as strongly as FAIL for finalization, because "
                        "an unresolvable comparison is not an agreement"),
    }


def finalization_allowed(recs, min_comparisons=None):
    if min_comparisons is None:
        min_comparisons = len(REQUIRED_KEYS)
    blocking = []
    for r in recs:
        if r["result"] not in (FAIL, BLOCKED):
            continue
        detail = [x for x in r["key_rows"] if x["result"] == r["result"]]
        detail += [a for a in r["assertion_rules"]
                   if a["result"] == r["result"]]
        detail += [s for s in r["structural"] if s["result"] == r["result"]]
        if r["batch_triple"]["result"] == r["result"]:
            detail.append(r["batch_triple"])
        blocking.append({"document": r["document"], "kind": r["result"],
                         "detail": detail})
    total_cmp = sum(r["n_keys_compared"] for r in recs)
    return {
        "finalization_allowed": (not blocking) and total_cmp >= min_comparisons,
        "rule": "a phase may not finalize while any required field is missing, "
                "any value is outside its vocabulary, any stated value "
                "contradicts the artefact that holds it, any narrative sentence "
                "contradicts a measured fact, any fact source is unreadable or "
                "retired, or any fact was corroborated by re-reading the "
                "locator another fact came from.  Absence is BLOCKING: an empty "
                "observation is not a passing observation.",
        "n_blocking": len(blocking),
        "blocking": blocking,
        "n_comparisons_total": total_cmp,
        "min_comparisons_required": min_comparisons,
        "zero_comparison_guard_fired": total_cmp < min_comparisons,
    }


def context_artefacts():
    out = []
    for spec in CONTEXT_ARTEFACTS:
        p = _abs(spec["path"])
        rec = dict(spec)
        rec["exists"] = os.path.exists(p)
        rec["sha256"] = sha256_file(p) if rec["exists"] else None
        out.append(rec)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default="SESSION_REPORT.md")
    ap.add_argument("--facts-file", default=None,
                    help="regression/mutation mode: a fixture fact bundle")
    ap.add_argument("--json-out", default=None)
    args = ap.parse_args(argv)

    p = args.report if os.path.isabs(args.report) else os.path.join(ROOT,
                                                                    args.report)
    if not os.path.exists(p):
        out = {"verdict": BLOCKED, "why": "report not found: %s" % args.report}
        print(json.dumps(out, indent=1))
        return 2
    body = open(p, encoding="utf-8", errors="replace").read()

    ok, facts, prov = build_facts(args.facts_file)
    rec = check_document(body, os.path.basename(p), facts, prov)
    gate = finalization_allowed([rec])
    out = {
        "schema": "p16aw/status-consistency/3",
        "phase": "16AW",
        "replaces": "p16av/consistency/p16av_status_consistency.py",
        "report": args.report,
        "facts_mode": prov.get("mode"),
        "facts_provenance": prov,
        "facts_ok": ok,
        "context_artefacts": context_artefacts(),
        "record": rec,
        "gate": gate,
        "verdict": rec["result"],
        "finalization_allowed": gate["finalization_allowed"],
    }
    out["verifier_sha256"] = sha256_file(os.path.abspath(__file__))
    if args.json_out:
        op = args.json_out if os.path.isabs(args.json_out) \
            else os.path.join(ROOT, args.json_out)
        os.makedirs(os.path.dirname(op), exist_ok=True)
        with open(op, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(out, fh, indent=1)
            fh.write("\n")
    print(json.dumps({"verdict": out["verdict"],
                      "finalization_allowed": out["finalization_allowed"],
                      "n_keys_compared": rec["n_keys_compared"],
                      "n_required_keys": rec["n_required_keys"],
                      "n_blocking": gate["n_blocking"],
                      "facts_ok": ok,
                      "facts_mode": prov.get("mode")}, indent=1))
    return 0 if out["finalization_allowed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
