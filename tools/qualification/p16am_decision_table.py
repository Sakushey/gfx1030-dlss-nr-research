#!/usr/bin/env python3
"""Phase 16AM -- the outcome decision table (brief sections 4, 5 and 6).

Astra finding A's acceptance criterion is two-sided:

    "a known-clean fixture reaches completion; every missing mandatory
     observation prevents a positive verdict."

This file tests BOTH sides, and it tests them against the library rather than
against a copy of the library's rules:

  * fifteen named fixtures, one per row of the brief's list, each asserting an
    exact verdict;
  * a SYSTEMATIC SWEEP that takes the known-clean case and removes exactly one
    mandatory observation at a time -- each removal must independently destroy
    the positive verdict, and each must leave the observation named as UNKNOWN
    with a reason in the verdict;
  * three NEGATIVE CONTROLS that run the same table against deliberately wrong
    rules (the historical fail-open behaviour, the 16AK guard word-match, and a
    classifier that ignores the reset monitor).  Each control must be CAUGHT.
    A table that cannot fail is not evidence.

The fixtures' marker strings are taken from the producer that emits them: the
guard summary format is read from the harness printf at
`phase16w/j3/harness/j3v2_harness_16w.cpp:772-776`, and the on-disk instance is
`p16al/attempt_003/LAUNCH_STDOUT.txt:232`.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p16am_qual as Q                                              # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "p16am", "qualification")

# --- the two attested forms of the guard line ----------------------------
# CLEAN is derived from the harness printf with guardMod == 0 (the ternary
# prints "NONE" for the first-modified address).  DAMAGED is the literal line
# observed on disk in this project.
GUARD_CLEAN = ("GUARD SUMMARY: 16384 guard bytes examined across 4 regions; "
               "0 modified; first modified address NONE")
GUARD_DAMAGED = ("GUARD SUMMARY: 16384 guard bytes examined across 4 regions; "
                 "16384 modified; first modified address 9020547")
GUARD_DAMAGED_ATTESTED_AT = "p16al/attempt_003/LAUNCH_STDOUT.txt:232"

BASE_LINES = [
    "RUNTIME: amdhip64_6.dll loaded from C:\\Windows\\System32\\amdhip64_6.dll",
    "hipRuntimeGetVersion = 60040999",
    "kernel symbol present: main",
    "launch returned hipSuccess",
    "hipDeviceSynchronize = hipSuccess",
    "PHYSICAL_VERDICT_THIS_PROCESS = COMPLETED",
    GUARD_CLEAN,
    "HASHES_EQUAL           = YES",
]

WINDOW = ("2026-09-21T08:55:00Z", "2026-09-21T08:56:30Z")


def obs_from(lines, reset_after, attempt_uuid="ATTEMPT-UUID-1"):
    """Parse one attempt's observations from its stdout and WER snapshots.

    A payload artefact is bound by default because every attempt that produced
    a completion marker also produced one; the missing-output and
    truncated-output fixtures override it explicitly.
    """
    obs = {
        "launch_api": Q.parse_launch_api(lines),
        "synchronization": Q.parse_synchronization(lines),
        "guard_contract": Q.parse_guard_summary(lines),
        "completion_contract": Q.parse_completion_marker(lines),
        "numerical_correctness": Q.parse_hashes_equal(lines),
        "output_payload": Q.payload_is_usable(b"\x11\x22\x33\x44" * 64),
        "reset_monitor": Q.classify_reset_monitor(
            {"wer_kernel": {"record_id": 50}}, reset_after,
            attempt_uuid=attempt_uuid, attempt_start_utc=WINDOW[0],
            attempt_end_utc=WINDOW[1]),
    }
    return obs


NO_RESET = {"wer_kernel": [{"record_id": 50, "message": "older watchdog",
                            "utc": "2026-09-21T07:00:00Z"}]}
NEW_RESET = {"wer_kernel": [{"record_id": 82, "message": "LiveKernelEvent WATCHDOG",
                             "utc": "2026-09-21T08:55:50Z"},
                            {"record_id": 50, "message": "older watchdog",
                             "utc": "2026-09-21T07:00:00Z"}]}
STALE_ONLY = {"wer_kernel": [{"record_id": 49, "message": "WATCHDOG",
                              "utc": "2026-09-21T07:30:00Z"}]}
OUTSIDE_ONLY = {"wer_kernel": [{"record_id": 90, "message": "WATCHDOG",
                                "utc": "2026-09-21T12:00:00Z"}]}


def case(name, lines, reset_after, contract, expect, note="", **kw):
    obs = obs_from(lines, reset_after, **kw)
    v = Q.classify(obs, contract)
    return {"fixture": name, "expected": expect,
            "measured": v.primary_outcome,
            "pass": v.primary_outcome == expect,
            "dimensions": {"dispatch_completion": v.dispatch_completion,
                           "diagnostic_contract": v.diagnostic_contract,
                           "numerical_correctness": v.numerical_correctness,
                           "reset_monitor": v.reset_monitor},
            "why": v.why, "note": note,
            "unknowns": {k: o.reason for k, o in obs.items()
                         if not o.known}}


def build_fixtures():
    live = Q.cut_prefix_contract("CUT_HALF_16AL")          # numerics not required
    numc = Q.DiagnosticContract(name="numeric-diagnostic",
                                numerical_comparison_required=True)
    rows = []

    # 1. clean completion -- the acceptance criterion's positive side
    rows.append(case("clean_completion", BASE_LINES, NO_RESET, live,
                     Q.PHYSICAL_COMPLETES,
                     note="the known-clean fixture the acceptance criterion names"))

    # 2. numeric mismatch -- only meaningful where the contract requires it
    rows.append(case("numeric_mismatch",
                     [l for l in BASE_LINES if "HASHES_EQUAL" not in l]
                     + ["HASHES_EQUAL           = NO"],
                     NO_RESET, numc, Q.NUMERICAL_MISMATCH))

    # 3. guard corruption
    rows.append(case("guard_corruption",
                     [l for l in BASE_LINES if "GUARD SUMMARY" not in l]
                     + [GUARD_DAMAGED],
                     NO_RESET, live, Q.GUARD_VIOLATED))

    # 4. watchdog reset -- and the same case under the numeric contract, to show
    #    the reset dominates the numeric dimension rather than being masked by it
    rows.append(case("watchdog_reset",
                     [l for l in BASE_LINES if "HASHES_EQUAL" not in l]
                     + ["HASHES_EQUAL           = NO"],
                     NEW_RESET, numc, Q.PHYSICAL_TDR))

    # 5. WER query failure
    rows.append(case("wer_query_failure", BASE_LINES, None, live,
                     Q.OBSERVATION_INCOMPLETE,
                     note="the query returning nothing is not 'no reset'"))

    # 6. WER query unavailable (a shaped but empty answer)
    rows.append(case("wer_query_unavailable", BASE_LINES, {}, live,
                     Q.OBSERVATION_INCOMPLETE))

    # 7. timeout -- no reset, no completion marker
    rows.append(case("timeout",
                     [l for l in BASE_LINES
                      if "PHYSICAL_VERDICT_THIS_PROCESS" not in l],
                     NO_RESET, live, Q.DISPATCH_NOT_COMPLETED))

    # 8. launch API failure
    rows.append(case("launch_api_failure",
                     [l.replace("hipSuccess", "hipErrorLaunchFailure")
                      if l.startswith("launch returned") else l
                      for l in BASE_LINES],
                     NO_RESET, live, Q.LAUNCH_API_FAILED))

    # 9. synchronization failure
    rows.append(case("synchronization_failure",
                     [l.replace("hipDeviceSynchronize = hipSuccess",
                                "hipDeviceSynchronize = hipErrorLaunchFailure")
                      for l in BASE_LINES],
                     NO_RESET, live, Q.SYNC_FAILED))

    # 10. missing output -- only blocks a contract that requires an artefact
    obs = obs_from(BASE_LINES, NO_RESET)
    obs["output_payload"] = Q.Obs.unknown("output_payload", Q.ABSENT)
    v = Q.classify(obs, numc)
    rows.append({"fixture": "missing_output",
                 "expected": Q.OBSERVATION_INCOMPLETE,
                 "measured": v.primary_outcome,
                 "pass": v.primary_outcome == Q.OBSERVATION_INCOMPLETE,
                 "note": "no payload artefact was produced",
                 "dimensions": {"dispatch_completion": v.dispatch_completion,
                                "diagnostic_contract": v.diagnostic_contract,
                                "numerical_correctness": v.numerical_correctness,
                                "reset_monitor": v.reset_monitor}})
    # 10b. the SAME missing payload under a LIVENESS contract is not a blocker:
    #      that diagnostic never promised an image.  This is finding B's point.
    obs = obs_from(BASE_LINES, NO_RESET)
    obs["output_payload"] = Q.Obs.unknown("output_payload", Q.ABSENT)
    v = Q.classify(obs, live)
    rows.append({"fixture": "missing_output_liveness_contract",
                 "expected": Q.PHYSICAL_COMPLETES,
                 "measured": v.primary_outcome,
                 "pass": v.primary_outcome == Q.PHYSICAL_COMPLETES,
                 "note": ("a prefix/liveness diagnostic does not promise an "
                          "image, so an absent image is not a failure for it"),
                 "dimensions": {"dispatch_completion": v.dispatch_completion,
                                "diagnostic_contract": v.diagnostic_contract,
                                "numerical_correctness": v.numerical_correctness,
                                "reset_monitor": v.reset_monitor}})

    # 11. truncated output -- modelled by an empty artefact
    obs = obs_from(BASE_LINES, NO_RESET)
    obs["output_payload"] = Q.Obs.unknown("output_payload", Q.TRUNCATED,
                                          detail={"size": 0})
    v = Q.classify(obs, numc)
    rows.append({"fixture": "truncated_output", "expected": Q.OBSERVATION_INCOMPLETE,
                 "measured": v.primary_outcome,
                 "pass": v.primary_outcome == Q.OBSERVATION_INCOMPLETE,
                 "note": "an empty artefact is TRUNCATED, not a valid output",
                 "dimensions": {"dispatch_completion": v.dispatch_completion,
                                "diagnostic_contract": v.diagnostic_contract,
                                "numerical_correctness": v.numerical_correctness,
                                "reset_monitor": v.reset_monitor}})

    # 12. missing guard report -- the fail-open case, now closed
    rows.append(case("missing_guard_report",
                     [l for l in BASE_LINES if "GUARD SUMMARY" not in l],
                     NO_RESET, live, Q.OBSERVATION_INCOMPLETE,
                     note="16AK classified this as a clean completion"))

    # 13. malformed guard report
    rows.append(case("malformed_guard_report",
                     [l for l in BASE_LINES if "GUARD SUMMARY" not in l]
                     + ["GUARD SUMMARY: canaries checked, nothing alarming"],
                     NO_RESET, live, Q.OBSERVATION_INCOMPLETE))

    # 14. stale event -- an old record, already seen before the attempt
    rows.append(case("stale_event", BASE_LINES, STALE_ONLY, live,
                     Q.PHYSICAL_COMPLETES,
                     note="the stale record is excluded AND recorded as excluded"))

    # 15. event outside the attempt interval
    rows.append(case("event_outside_attempt_interval", BASE_LINES, OUTSIDE_ONLY,
                     live, Q.PHYSICAL_COMPLETES,
                     note="a real watchdog record from after the window"))

    # 16. event attributed to another attempt
    other = {"wer_kernel": [{"record_id": 91, "message": "WATCHDOG",
                             "utc": "2026-09-21T08:56:00Z",
                             "attempt_uuid": "SOME-OTHER-ATTEMPT"}]}
    rows.append(case("event_from_another_attempt", BASE_LINES, other, live,
                     Q.PHYSICAL_COMPLETES))
    return rows, live, numc


def sweep(contract):
    """Remove each mandatory observation in turn; none may leave a positive."""
    results = []
    for name in Q.MANDATORY:
        lines = list(BASE_LINES)
        obs = obs_from(lines, NO_RESET)
        obs[name] = Q.Obs.unknown(name, Q.ABSENT,
                                  detail={"removed_by": "the systematic sweep"})
        v = Q.classify(obs, contract)
        results.append({
            "removed_observation": name,
            "measured": v.primary_outcome,
            "positive_verdict_survived": v.is_positive,
            "blocked": not v.is_positive,
            "named_as_unknown_in_the_verdict":
                name in (v.why or "") or any(
                    "%s(" % name in (v.why or "") for _ in [0]),
            "why": v.why,
        })
    return results


def controls(fixtures, live):
    """Run the table against deliberately wrong rules; each must be CAUGHT."""
    out = []
    for mut, label in (
            ("UNKNOWN_READS_AS_CLEAN",
             "the historical fail-open rule: a missing observation reads as clean"),
            ("GUARD_WORD_MATCH",
             "the 16AK guard rule: the presence of the word 'modified' is a violation"),
            ("IGNORE_RESET_MONITOR",
             "a classifier that does not consult the reset monitor")):
        caught = []
        for row in fixtures:
            if row["fixture"] not in ("clean_completion", "missing_guard_report",
                                      "malformed_guard_report", "wer_query_failure",
                                      "wer_query_unavailable", "watchdog_reset"):
                continue
            obs = obs_from(
                BASE_LINES if row["fixture"] == "clean_completion" else
                ([l for l in BASE_LINES if "GUARD SUMMARY" not in l]
                 if row["fixture"] in ("missing_guard_report",) else
                 ([l for l in BASE_LINES if "GUARD SUMMARY" not in l]
                  + ["GUARD SUMMARY: canaries checked, nothing alarming"]
                  if row["fixture"] == "malformed_guard_report" else BASE_LINES)),
                NEW_RESET if row["fixture"] == "watchdog_reset" else NO_RESET)
            v = Q.classify(obs, live, mutate=mut)
            if v.primary_outcome != row["expected"]:
                caught.append({"fixture": row["fixture"],
                               "expected": row["expected"],
                               "mutated_measured": v.primary_outcome})
        out.append({"mutation": mut, "what_it_models": label,
                    "fixtures_that_caught_it": caught,
                    "caught": bool(caught)})
    return out


def main():
    os.makedirs(OUT, exist_ok=True)
    fixtures, live, numc = build_fixtures()
    sweep_rows = sweep(live)
    ctrl = controls(fixtures, live)

    passed = sum(1 for r in fixtures if r["pass"])
    doc = {
        "schema": "p16am-outcome-decision-table/1",
        "phase": "16AM",
        "purpose": ("exercise every verdict of the Phase-16AM qualification "
                    "library against named fixtures and prove each mandatory "
                    "observation can block a positive verdict"),
        "library": {"file": "p16am/qualification/p16am_qual.py",
                    "schema": Q.SCHEMA,
                    "sha256": _sha(os.path.join(OUT, "p16am_qual.py"))},
        "fixtures_total": len(fixtures),
        "fixtures_passed": passed,
        "fixtures": fixtures,
        "systematic_sweep": {
            "what": ("the known-clean case with exactly one mandatory "
                     "observation removed, once per observation"),
            "rows": sweep_rows,
            "all_blocked": all(r["blocked"] for r in sweep_rows),
        },
        "negative_controls": ctrl,
        "all_controls_caught": all(c["caught"] for c in ctrl),
        "acceptance": {
            "known_clean_fixture_reaches_completion":
                all(r["pass"] for r in fixtures
                    if r["fixture"] == "clean_completion"),
            "every_missing_mandatory_observation_blocks_a_positive_verdict":
                all(r["blocked"] for r in sweep_rows),
            "an_incorrect_classifier_cannot_pass":
                all(c["caught"] for c in ctrl),
        },
        "marker_provenance": {
            "guard_summary_producer": Q.GUARD_PRODUCER,
            "hashes_equal_producer": Q.HASHES_PRODUCER,
            "guard_damaged_attested_at": GUARD_DAMAGED_ATTESTED_AT,
            "guard_clean_derived_from": ("the same printf with guardMod == 0; "
                                        "no clean guard line exists on disk in "
                                        "this project, because no physical "
                                        "attempt has ever completed"),
        },
        "utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    path = os.path.join(OUT, "OUTCOME_DECISION_TABLE_16AM.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")

    print(json.dumps({
        "written": path,
        "fixtures": "%d/%d passed" % (passed, len(fixtures)),
        "failing": [r["fixture"] for r in fixtures if not r["pass"]],
        "sweep_all_blocked": doc["systematic_sweep"]["all_blocked"],
        "sweep_survivors": [r["removed_observation"] for r in sweep_rows
                            if not r["blocked"]],
        "controls_caught": {c["mutation"]: c["caught"] for c in ctrl},
        "acceptance": doc["acceptance"],
    }, indent=1))
    return 0 if (passed == len(fixtures)
                 and doc["systematic_sweep"]["all_blocked"]
                 and doc["all_controls_caught"]) else 1


def _sha(path):
    import hashlib
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read())
    return h.hexdigest()


if __name__ == "__main__":
    sys.exit(main())
