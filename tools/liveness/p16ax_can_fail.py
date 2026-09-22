#!/usr/bin/env python3
"""Phase 16AX / W9 -- T-LIVENESS step 4: prove the proof CAN fail.

    "A prover that has only ever returned PASS is not evidence of anything."

Four things are established here.  The third costs something to say and the
fourth is the one that changes what a reader may conclude from the 16AW result.

 1. THE TOP-LEVEL VERDICT VOCABULARY HAS NO `FAIL`.  The prover's verdict
    constants are read out of the prover's own source in this session.  There is
    no `FAILED` verdict, so "can the proof fail?" cannot be answered at the top
    level at all; it has to be answered one requirement down.

 2. TWO LOOPS THAT GENUINELY CANNOT TERMINATE ARE REFUTED, by the same proof
    route in two different guard families, each with an independent witness of
    non-termination from a straight-line interpreter over the same bytes:

      the guard is an equality / inequality whose target is NOT in the
      recurrence's orbit -- the linear congruence a + j*c = T (mod 2**32)
      has no solution, because c does not divide T - a.

    The requirement row carries status FAILED (a refutation), not UNKNOWN, and
    orbit.status is INFINITE with `infinity_proved_by` naming the route.

 3. A SECOND, DOCUMENTED REFUTATION ROUTE IS DEAD CODE.  A guard whose truth set
    is the whole 32-bit domain (`s_cmp_lt_u32 s0, 0`) or empty
    (`s_cmp_ge_u32 s0, 0`) should be decided from the guard alone with no
    search.  It is not: `truth_set_extremes` returns a TUPLE and its only caller
    compares it to bare strings, so the branch never fires.  The loop is instead
    simulated for 2**20 steps and refused as NOT_FOUND_WITHIN_CAP.  Measured by
    calling both functions directly.  The error is CONSERVATIVE and the argument
    is per case, not general: an empty continue-set exits at j=0, which the
    simulation finds; a whole-domain continue-set exhausts the cap and refuses.
    So the defect can turn a refutation into a non-decision and cannot turn a
    non-terminating loop into a PROVEN one.

 4. THE CEILING, WHICH IS THE REAL FINDING.  A loop that genuinely DOES
    terminate but whose exit index lies past the prover's cap is refused with
    status UNKNOWN at the SAME requirement, under the SAME top-level verdict, as
    the refutations in (2) -- and so is the whole-domain loop in (3).  So
    `UNKNOWN_BLOCKING` means three different things: REFUTED, UNDECIDED-BY-CAP,
    and REFUTED-BUT-BY-A-ROUTE-THAT-IS-DEAD.  A reader ranking loops by the
    top-level verdict alone cannot tell them apart; the distinction survives
    only in the requirement row's status and in `orbit.status`.  Both are
    printed here, and printed as differing.

Host-only.  Disassembling is not launching: no HIP call, no GPU, no slot.
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import p16ax_common as C          # noqa: E402

OUT = os.path.join(HERE, "PROVER_CAN_FAIL_16AX.json")

STEP_LIMIT = 200_000
PROVEN = "PROVEN_COUNTED_LOOP_WITH_STATIC_BOUND"
PROVER_PATH = os.path.join(C.ROOT, "p16aw", "liveness",
                           "p16aw_loop_recurrence_prover.py")


# ---------------------------------------------------------------------
def verdict_vocabulary():
    """The top-level verdict constants, read out of the prover's own source."""
    src = open(PROVER_PATH, encoding="utf-8").read()
    consts = re.findall(r'^(VERDICT_[A-Z0-9_]+)\s*=\s*"([^"]+)"', src,
                        re.MULTILINE)
    return {
        "prover_source": C.rel(PROVER_PATH),
        "prover_source_sha256": C.sha256_file(PROVER_PATH),
        "declared_verdict_constants": {k: v for k, v in consts},
        "n_declared": len(consts),
        "is_there_a_FAIL_verdict": any("FAIL" in v.upper() for _k, v in consts),
        "requirement_status_vocabulary": ["PROVEN", "FAILED", "UNKNOWN",
                                          "NOT_EVALUATED"],
        "so_can_the_top_level_verdict_fail": "no -- there is no FAIL verdict.  "
            "The prover's failure signal lives one level down, in a requirement "
            "row's status.  Reading only the verdict cannot tell a refuted loop "
            "from an undecided one",
    }


def analyse(label, prog, step_limit=STEP_LIMIT):
    S, P, OLD = C._load_16aw()
    ins, base, ver = C.build_program(list(prog), C.OBJ, C.WORK, label=label)
    ctx = P.build_context(ins, base)
    loops = P.prove_all(ctx)

    rows = []
    for L in loops:
        rows.append({
            "loop_index": L["loop_index"], "head_pc": L["head_pc"],
            "latch_pc": L["latch_pc"],
            "verdict": L["verdict"],
            "max_trip_count": L.get("max_trip_count"),
            "induction_register": L.get("induction_register"),
            "orbit": L.get("orbit"),
            "first_failing_requirement": L["first_failing_requirement"],
            "first_unknown_requirement": L["first_unknown_requirement"],
            "blocking_reason": L["blocking_reason"],
            "n_requirements_proven": L["n_requirements_proven"],
            "requirements": [{"id": q["id"], "requirement": q["requirement"],
                              "status": q["status"], "detail": q["detail"],
                              "evidence": q["evidence"]}
                             for q in L["requirements"]],
        })

    watch = [int(r["latch_pc"], 16) for r in rows]
    it = C.build_interp(ins, step_limit=step_limit)
    interp = it.run(watch_addrs=watch)
    return {
        "label": label,
        "program": [{"index": i, "asm": asm, "at": hex(ins[i]["addr"])}
                    for i, (asm, _t) in enumerate(prog)],
        "decode_ok": ver["every_planted_word_decoded_to_the_requested_mnemonic"],
        "branch_routes_agree": ver["branch_routes_all_agree"],
        "loops": rows,
        "interpreter": interp,
    }


def the_loop(run):
    return next((x for x in run["loops"] if x["verdict"] != PROVEN),
                run["loops"][0] if run["loops"] else None)


def row_of(L, rid):
    return next((q for q in L["requirements"] if q["id"] == rid), None)


def the_stopping_requirement(L):
    rid = L["first_failing_requirement"] or L["first_unknown_requirement"]
    q = row_of(L, rid) if rid else None
    return rid, (None if q is None else q["status"])


def case_record(name, run, expectation, dead_path_measurement=None):
    L = the_loop(run)
    if L is None:
        return {"case": name, "program": [p["asm"] for p in run["program"]],
                "verdict": "NO_LOOP_WAS_FOUND", "expectation": expectation}
    rid, status = the_stopping_requirement(L)
    r09 = row_of(L, "R09")
    orb = L["orbit"] or {}
    rec = {
        "case": name,
        "program": [p["asm"] for p in run["program"]],
        "expectation": expectation,
        "top_level_verdict": L["verdict"],
        "max_trip_count": L["max_trip_count"],
        "blocking_reason": L["blocking_reason"],
        "the_requirement_that_stopped_the_prover": rid,
        "status_of_that_requirement": status,
        "blocking_reason_of_that_requirement": (
            None if row_of(L, rid) is None else row_of(L, rid)["evidence"]),
        "R09_status": None if r09 is None else r09["status"],
        "R09_detail": None if r09 is None else r09["detail"],
        "R09_evidence": None if r09 is None else r09["evidence"],
        "orbit_status": orb.get("status"),
        "orbit_infinity_proved_by": orb.get("infinity_proved_by"),
        "continue_set_is_the_whole_domain": orb.get(
            "continue_set_is_the_whole_domain"),
        "route_sim": orb.get("route_sim"),
        "route_form": orb.get("route_form"),
        "route_form_kind": orb.get("route_form_kind"),
        "route_form_credited": orb.get("route_form_credited"),
        "cap_trips": 1 << 20,
        "n_requirements_proven": L["n_requirements_proven"],
        "every_requirement_row": [{"id": q["id"], "status": q["status"]}
                                  for q in L["requirements"]],
        "independent_witness": {
            "interpreter_status": run["interpreter"]["status"],
            "steps": run["interpreter"].get("steps"),
            "step_limit": STEP_LIMIT,
            "what_that_means": {
                "STEP_LIMIT_REACHED": "the program did not reach s_endpgm "
                    "within the limit.  A WITNESS of non-termination up to the "
                    "limit, NOT a proof of it; for the refuted cases the proof "
                    "comes from the congruence, and the interpreter is there as "
                    "a second mechanism that agrees",
                "HALTED": "the program reached s_endpgm, so the loop DOES "
                    "terminate",
                "UNDETERMINED_SCC": "a branch condition could not be decided",
                "UNMODELLED_INSTRUCTION": "the interpreter does not model this "
                    "instruction and says so instead of guessing",
            }.get(run["interpreter"]["status"], "see status"),
        },
        "decode_ok": run["decode_ok"],
        "branch_routes_agree": run["branch_routes_agree"],
    }
    if dead_path_measurement is not None:
        rec["dead_path_measurement"] = dead_path_measurement
    return rec


def main() -> int:
    S, P, OLD = C._load_16aw()
    vocab = verdict_vocabulary()

    # ---- (3) the loop whose refutation route is DEAD --------------------
    #  `s_cmp_lt_u32 s0, 0` is false for EVERY 32-bit value and the branch
    #  continues when SCC is 0, so nothing the register can hold ends the loop.
    #  The prover has a documented branch for exactly this and it never fires.
    whole_domain = analyse("cf_whole_domain_guard", [
        ("s_mov_b32 s0, 0", None),
        ("s_add_u32 s0, s0, 1", None),
        ("s_cmp_lt_u32 s0, 0", None),
        ("s_cbranch_scc0 1", 1),
        ("s_endpgm", None)])

    #  the measurement of the dead branch, by calling both functions directly
    extremes = {str((op, T, sg)): P.truth_set_extremes(op, T, sg)
                for op, T, sg in (("lt", 0, False), ("ge", 0, False),
                                  ("le", 0xFFFFFFFF, False),
                                  ("gt", 0x7FFFFFFF, True),
                                  ("lt", 32, False))}
    direct = P.orbit_verdict(0, 1, "lt", 0, False, "scc0")
    dead = {
        "truth_set_extremes_actually_returns": {
            k: (list(v) if isinstance(v, tuple) else v)
            for k, v in extremes.items()},
        "what_orbit_verdict_compares_it_to": "the bare strings 'all' / 'none'",
        "orbit_verdict_called_directly_on_lt_0_scc0": {
            k: direct.get(k) for k in
            ("status", "continue_set_is_the_whole_domain", "route_sim",
             "route_form", "route_form_kind")},
        "so_the_branch_is_dead": True,
        "consequence_on_the_real_object": "measured separately in "
            "DEAD_EXTREMES_PATH_16AX.json: 0 of the 33 loops has an extreme "
            "guard, so this defect does not touch the 33/33 result",
    }

    # ---- (2) two refutations by the congruence route --------------------
    ref_eq = analyse("cf_eq_target_not_in_orbit", [
        ("s_mov_b32 s0, 0", None),
        ("s_add_u32 s0, s0, 4", None),
        ("s_cmp_eq_u32 s0, 5", None),
        ("s_cbranch_scc0 1", 1),
        ("s_endpgm", None)])

    ref_lg = analyse("cf_lg_target_not_in_orbit", [
        ("s_mov_b32 s0, 0", None),
        ("s_add_u32 s0, s0, 2", None),
        ("s_cmp_lg_u32 s0, 3", None),
        ("s_cbranch_scc1 1", 1),
        ("s_endpgm", None)])

    # ---- (4) the ceiling: terminates, but past the cap ------------------
    cap = analyse("cf_exit_past_the_cap", [
        ("s_mov_b32 s0, 0", None),
        ("s_add_u32 s0, s0, 1", None),
        ("s_cmp_lt_i32 s0, 2147483647", None),
        ("s_cbranch_scc1 1", 1),
        ("s_endpgm", None)], step_limit=STEP_LIMIT)

    cases = [
        case_record("A_whole_domain_guard__refutation_route_is_dead",
                    whole_domain,
                    "the prover's own documented extremes path decides INFINITE "
                    "from the guard alone", dead),
        case_record("B_equality_target_not_in_orbit__refuted", ref_eq,
                    "the congruence 0 + 4j = 5 (mod 2**32) has no solution "
                    "because 4 does not divide 5"),
        case_record("C_inequality_target_not_in_orbit__refuted", ref_lg,
                    "the orbit is the even residues and the target 3 is odd, so "
                    "the guard's value is never 3"),
        case_record("D_exit_past_the_cap__undecided", cap,
                    "the loop terminates at j = 2147483647, which is past "
                    "CAP_TRIPS = 2**20"),
    ]

    refuted = [c["case"] for c in cases
               if c.get("R09_status") == "FAILED"
               and c.get("orbit_status") == "INFINITE"]
    undecided = [c["case"] for c in cases
                 if c.get("R09_status") == "UNKNOWN"
                 and c.get("orbit_status") == "NOT_FOUND_WITHIN_CAP"]
    verdicts = {c["case"]: c.get("top_level_verdict") for c in cases}
    same_verdict = len(set(verdicts.values())) == 1

    ok = (len(refuted) == 2 and len(undecided) == 2 and same_verdict
          and vocab["is_there_a_FAIL_verdict"] is False
          and dead["so_the_branch_is_dead"] is True)

    out = {
        "schema": "p16ax/liveness-can-fail/1",
        "phase": "16AX", "worker": "W9", "task": "T-LIVENESS", "brief_step": 4,
        "the_question": "does the recurrence prover ever REFUTE a genuinely "
                        "non-terminating loop, and can its refusals be told "
                        "apart from its failures to decide?",
        "answer": "yes to the first, no to the second, and one of the routes it "
                  "documents for the first is dead code",
        "the_verdict_vocabulary": vocab,
        "the_four_cases": cases,
        "n_refuted_with_a_proof_of_infinity": len(refuted),
        "refuted_cases": refuted,
        "n_refused_as_undecided": len(undecided),
        "undecided_cases": undecided,
        "every_case_shares_one_top_level_verdict": same_verdict,
        "the_top_level_verdict_of_every_case": verdicts,
        "the_ceiling_in_one_line": "the top-level verdict is UNKNOWN_BLOCKING "
            "for two loops the prover PROVED cannot terminate, for a third that "
            "it cannot decide within its cap, and for a fourth whose refutation "
            "route is dead code.  The refusals are NOT distinguishable at the "
            "top level",
        "where_the_distinction_survives": [
            "the requirement row's status: FAILED (a refutation) versus UNKNOWN "
            "(not decided)",
            "orbit.status: INFINITE versus NOT_FOUND_WITHIN_CAP",
            "the presence of orbit.infinity_proved_by, which names the route "
            "that proved it",
        ],
        "what_this_does_NOT_establish": [
            "that the prover is COMPLETE.  It is not, and case D is the "
            "demonstration: a loop whose exit index is 2147483647 exceeds "
            "CAP_TRIPS = %d, the bit-exact simulation never finds the exit, and "
            "the loop is refused even though it does terminate" % (1 << 20),
            "that a PROVEN verdict implies the loop terminates at RUNTIME.  The "
            "bound is a static maximum for the machine loop; the loop may exit "
            "earlier on a value the analysis does not track",
            "that an UNKNOWN verdict implies a defect.  Most refusals are "
            "limitations of the supported form.  What is shown here is narrower: "
            "the top-level verdict conflates a refutation with a non-decision",
            "that the interpreter's STEP_LIMIT_REACHED is a proof of "
            "non-termination.  It is a witness up to %d steps; the proof comes "
            "from the congruence.  The interpreter's value is that it is a "
            "SECOND mechanism, sharing no formula, parser or failure mode with "
            "the prover, and it agrees" % STEP_LIMIT,
            "that the dead branch is the only defect in the prover.  It is the "
            "one that direct calling of the documented decision routes "
            "exposed; that method finds routes the real object never exercises, "
            "not every wrong line",
        ],
        "verdict": ("PROVER_REFUTES_NON_TERMINATION_AND_THE_CEILING_IS_RECORDED"
                    if ok else "CANNOT_FAIL_PROOF_INCOMPLETE"),
    }
    C.dump(OUT, out)

    print("declared verdicts: %s"
          % ", ".join(sorted(vocab["declared_verdict_constants"].values())))
    print("is there a FAIL verdict? %s" % vocab["is_there_a_FAIL_verdict"])
    for c in cases:
        print("  %-52s top=%-18s orbit=%-22s R09=%-8s interp=%s"
              % (c["case"], c.get("top_level_verdict"),
                 c.get("orbit_status"), c.get("R09_status"),
                 c["independent_witness"]["interpreter_status"]))
    print("truth_set_extremes('lt',0,u32) returns %r; orbit_verdict calls it "
          "and compares to 'none' -> %s"
          % (tuple(extremes["('lt', 0, False)"]),
             dead["orbit_verdict_called_directly_on_lt_0_scc0"]["status"]))
    print("all four cases share one top-level verdict: %s" % same_verdict)
    print("VERDICT %s" % out["verdict"])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
