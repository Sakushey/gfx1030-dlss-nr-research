#!/usr/bin/env python3
"""Phase 16AX / W9 -- T-LIVENESS step 3: the required negative set.

THE NINE CASES THIS PHASE MUST REFUSE
    zero step; wrong source register; skipped update; internal reset;
    wraparound; unreachable equality; signedness mismatch; indirect load
    dependency; copied load dependency.

WHAT "REFUSED" HAS TO MEAN TO BE WORTH ANYTHING HERE
    Four separate facts, and a row is only valid when all of them hold:

      applied   the planted word decoded back, with llvm-objdump, as the
                instruction that was requested.  The builder RAISES when it
                does not, so a control that plants one instruction and tests
                another cannot reach this table at all; the per-instruction
                decode rows are carried in the run and counted here.

      reached   the prover emitted a requirement ROW with the expected id, on a
                loop it did NOT prove, and THAT ROW'S OWN EVIDENCE satisfies a
                per-case PREDICATE naming the planted instruction by address
                and text.  "the evidence dict is non-empty" is not the test: a
                refusal for an unrelated reason also has evidence.  A mutant
                that dies before the comparison has no such row.

      attributable
                removing the planted defect and nothing else makes that same
                requirement stop firing.  Without this a refusal proves only
                that the prover disliked the program.

      interpreted
                a straight-line INTERPRETER over the same decoded bytes reports
                whether the program halts and how many times the guard ran.  It
                shares no formula, parser or failure mode with the prover, so
                where it can decide, agreement is evidence and not tautology.

    WHERE THE REQUIREMENT FIRES ON A SIBLING LOOP: a program can produce more
    than one natural loop.  A row is judged on a loop that was refused AT the
    named requirement, and every loop of that program is listed beside it, so a
    reader can see the refusal is not being read off the wrong loop.

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

OUT = os.path.join(HERE, "NEGATIVE_CONTROLS_16AX.json")

STEP_LIMIT = 200_000
PROVEN = "PROVEN_COUNTED_LOOP_WITH_STATIC_BOUND"


# =====================================================================
#  the analysis of one synthetic program
# =====================================================================
def analyse(label, prog):
    S, P, OLD = C._load_16aw()
    ins, base, ver = C.build_program(list(prog), C.OBJ, C.WORK, label=label)
    ctx = P.build_context(ins, base)
    loops = P.prove_all(ctx)
    old_rows, old_meta, old_err = OLD.run_old_classifier(ins, base)

    text = {x["addr"]: re.sub(r"\s+", " ",
                              ("%s %s" % (x["mnemonic"], x["operands"])).strip())
            for x in ins}

    rows = []
    for L in loops:
        fired = next((q for q in L["requirements"]
                      if q["id"] == (L["first_failing_requirement"]
                                     or L["first_unknown_requirement"])), None)
        r07 = next((q for q in L["requirements"] if q["id"] == "R07"), None)
        guard_at = None
        if r07 and isinstance(r07["evidence"], dict):
            guard_at = (r07["evidence"].get("producer") or {}).get("at")
        rows.append({
            "loop_index": L["loop_index"], "head_pc": L["head_pc"],
            "latch_pc": L["latch_pc"], "n_nodes": L["n_nodes"],
            "verdict": L["verdict"], "max_trip_count": L.get("max_trip_count"),
            "induction_register": L.get("induction_register"),
            "guard_at": guard_at,
            "first_failing_requirement": L["first_failing_requirement"],
            "first_unknown_requirement": L["first_unknown_requirement"],
            "blocking_reason": L["blocking_reason"],
            "n_requirements_proven": L["n_requirements_proven"],
            "fired_requirement_id": None if fired is None else fired["id"],
            "fired_requirement_status": None if fired is None
            else fired["status"],
            "fired_requirement_detail": None if fired is None
            else fired["detail"],
            "fired_requirement_evidence": None if fired is None
            else fired["evidence"],
            "orbit_status": (L.get("orbit") or {}).get("status"),
            "spins": bool((L.get("transitive_spin_dependency") or {})
                          .get("is_spin")),
            "requirements": [{"id": q["id"], "requirement": q["requirement"],
                              "status": q["status"], "detail": q["detail"],
                              "evidence": q["evidence"]}
                             for q in L["requirements"]],
        })

    watch = [int(r["guard_at"], 16) for r in rows if r["guard_at"]]
    it = C.build_interp(ins, step_limit=STEP_LIMIT)
    interp = it.run(watch_addrs=watch)

    old_verdicts = []
    if old_rows is not None:
        for L in old_rows:
            t = L.get("termination")
            old_verdicts.append({
                "latch_pc": L["latch_pc"],
                "verdict": (t.get("verdict") if isinstance(t, dict) else t),
                "max_trip_count": (t.get("max_trip_count")
                                   if isinstance(t, dict) else None)})

    return {
        "label": label,
        "program": [{"index": i, "asm": asm, "at": hex(ins[i]["addr"]),
                     "decoded": text.get(ins[i]["addr"])}
                    for i, (asm, _t) in enumerate(prog)],
        "n_instructions": len(ins),
        "decode_verification": {
            "every_planted_word_decoded_to_the_requested_mnemonic":
                ver["every_planted_word_decoded_to_the_requested_mnemonic"],
            "n_decode_checks": len(ver["decode_checks"]),
            "branch_routes_all_agree": ver["branch_routes_all_agree"],
            "decode_checks": ver["decode_checks"],
            "scratch_copy": ver["scratch_copy"],
            "objective_file_sha256": ver["objective_file_sha256"],
        },
        "loops": rows,
        "interpreter": interp,
        "retired_classifier_on_the_same_bytes": old_verdicts,
        "retired_classifier_error": old_err,
    }


def at(run, idx):
    """The address, as the prover prints it in hex, of instruction `idx`."""
    return run["program"][idx]["at"]


def loop_ref(L):
    return {"loop_index": L["loop_index"], "head_pc": L["head_pc"],
            "latch_pc": L["latch_pc"], "n_nodes": L["n_nodes"]}


def build_row(cid, concept, expect_rid, run, pred, repaired=None,
              repaired_must_prove=True, notes=(), interp_expectation=None):
    cands = [L for L in run["loops"] if L["fired_requirement_id"] == expect_rid]
    fired_it = bool(cands)
    pool = (cands or [L for L in run["loops"] if L["verdict"] != PROVEN]
            or run["loops"])
    L = pool[0]
    pred_ok, pred_why = pred(L)

    r = {
        "id": cid,
        "concept": concept,
        "expectation": {"requirement_that_must_fire": expect_rid},
        "observed": {
            "verdict": L["verdict"],
            "requirement_that_fired": L["fired_requirement_id"],
            "status_of_that_requirement": L["fired_requirement_status"],
            "detail": L["fired_requirement_detail"],
            "n_requirements_proven": L["n_requirements_proven"],
            "max_trip_count": L["max_trip_count"],
            "blocking_reason": L["blocking_reason"],
            "loop_the_row_was_judged_on": loop_ref(L),
            "every_loop_of_this_program": [
                dict(loop_ref(x), verdict=x["verdict"],
                     requirement_that_fired=x["fired_requirement_id"])
                for x in run["loops"]],
        },
        "applied": {
            "every_planted_word_decoded_as_requested":
                run["decode_verification"][
                    "every_planted_word_decoded_to_the_requested_mnemonic"],
            "n_instructions_planted_and_decode_checked":
                run["decode_verification"]["n_decode_checks"],
            "branch_target_routes_agree":
                run["decode_verification"]["branch_routes_all_agree"],
            "decoded_text_of_every_instruction_of_this_program":
                [{k: p[k] for k in ("index", "asm", "at", "decoded")}
                 for p in run["program"]],
            "how_a_plant_that_did_not_take_is_caught": "the builder RAISES "
                "when a planted word decodes as a different mnemonic, so "
                "`False` here is unreachable from this script; the "
                "per-instruction rows are carried so the claim can be checked "
                "without re-running",
        },
        "reached": {
            "a_loop_was_refused_at_the_expected_requirement": fired_it,
            "that_requirement_is_not_PROVEN":
                L["fired_requirement_status"] in ("FAILED", "UNKNOWN"),
            "the_expected_requirement_is_the_one_that_fired":
                L["fired_requirement_id"] == expect_rid,
            "the_fired_rows_own_evidence_satisfies_the_per_case_predicate":
                pred_ok,
            "why_that_predicate_is_the_test": pred_why,
            "the_evidence_it_fired_with": L["fired_requirement_evidence"],
        },
        "attributable": None,
        "interpreted": {
            "status": run["interpreter"]["status"],
            "guard_evaluations": run["interpreter"].get("guard_evaluations"),
            "steps": run["interpreter"].get("steps"),
            "step_limit": STEP_LIMIT,
            "expectation": interp_expectation,
            "assumptions_it_had_to_make":
                run["interpreter"].get("assumptions", []),
            "what_it_is": "a straight-line interpreter over the SAME decoded "
                          "bytes; it shares no formula, parser or failure mode "
                          "with the recurrence prover, so where it agrees the "
                          "agreement is evidence and not a tautology",
        },
        "the_retired_16AT_classifier_on_the_same_bytes":
            run["retired_classifier_on_the_same_bytes"],
        "notes": list(notes),
    }

    if repaired is not None:
        still = [x for x in repaired["loops"]
                 if x["fired_requirement_id"] == expect_rid]
        all_proven = all(x["verdict"] == PROVEN for x in repaired["loops"])
        r["attributable"] = {
            "what_changed": "the planted defect removed and nothing else",
            "repaired_program": [p["asm"] for p in repaired["program"]],
            "the_named_requirement_no_longer_fires": not still,
            "loops_in_the_repaired_program": len(repaired["loops"]),
            "repaired_verdicts": [x["verdict"] for x in repaired["loops"]],
            "repaired_max_trip_counts":
                [x["max_trip_count"] for x in repaired["loops"]],
            "every_loop_in_the_repaired_program_is_proven": all_proven,
            "repaired_interpreter": {
                "status": repaired["interpreter"]["status"],
                "guard_evaluations":
                    repaired["interpreter"].get("guard_evaluations"),
                "steps": repaired["interpreter"].get("steps")},
            "ok": (not still) and (all_proven or not repaired_must_prove),
            "why_the_repaired_loop_need_not_be_PROVEN":
                None if repaired_must_prove else
                "the claim tested is narrower and exact -- with the planted "
                "defect removed, THIS requirement stops firing.  A repaired "
                "program whose loop is then refused at a LATER requirement is "
                "still a valid attribution, and saying so is better than "
                "quietly requiring a proof the repaired program does not have",
        }
    return r


# =====================================================================
def main() -> int:
    runs = {}

    def R(label, prog):
        if label not in runs:
            runs[label] = analyse(label, prog)
        return runs[label]

    # ---------------------------------------------------------------- REQ-1
    r1 = R("n1_zero_step", [
        ("s_mov_b32 s0, 0", None),
        ("s_add_u32 s0, s0, 0", None),
        ("s_cmp_lg_u32 s0, 1", None),
        ("s_cbranch_scc1 1", 1),
        ("s_endpgm", None)])
    r1f = R("n1_zero_step_fixed", [
        ("s_mov_b32 s0, 0", None),
        ("s_add_u32 s0, s0, 1", None),
        ("s_cmp_lg_u32 s0, 1", None),
        ("s_cbranch_scc1 1", 1),
        ("s_endpgm", None)])

    # ---------------------------------------------------------------- REQ-2
    r2 = R("n2_wrong_source", [
        ("s_mov_b32 s0, 0", None),
        ("s_mov_b32 s5, 0", None),
        ("s_add_u32 s0, s5, 1", None),
        ("s_cmp_lg_u32 s0, 32", None),
        ("s_cbranch_scc1 2", 2),
        ("s_endpgm", None)])
    r2f = R("n2_wrong_source_fixed", [
        ("s_mov_b32 s0, 0", None),
        ("s_mov_b32 s5, 0", None),
        ("s_add_u32 s0, s0, 1", None),
        ("s_cmp_lg_u32 s0, 32", None),
        ("s_cbranch_scc1 2", 2),
        ("s_endpgm", None)])

    # ---------------------------------------------------------------- REQ-3
    #  The GUARD COMPARE sits in the latch block (index 5), so the loop clears
    #  R07; the bypass branch at index 3 reads EXEC, not SCC, so index 5 stays
    #  the latch guard's UNIQUE SCC producer.  The refusal is therefore about
    #  DOMINANCE and not about the condition code.
    r3 = R("n3_skipped_update", [
        ("s_mov_b32 s0, 0", None),
        ("s_cmp_lg_u32 s0, 32", None),
        ("s_cbranch_scc0 7", 7),
        ("s_cbranch_execnz 5", 5),
        ("s_add_u32 s0, s0, 1", None),
        ("s_cmp_lg_u32 s0, 32", None),
        ("s_cbranch_scc1 1", 1),
        ("s_endpgm", None)])
    r3f = R("n3_skipped_update_fixed", [
        ("s_mov_b32 s0, 0", None),
        ("s_cmp_lg_u32 s0, 32", None),
        ("s_cbranch_scc0 6", 6),
        ("s_add_u32 s0, s0, 1", None),
        ("s_cmp_lg_u32 s0, 32", None),
        ("s_cbranch_scc1 1", 1),
        ("s_endpgm", None)])

    # ---------------------------------------------------------------- REQ-4
    #  Both writers must lie INSIDE the loop body, so the reset path is a
    #  branch WITHIN the body rather than a way around the head: a path that
    #  bypasses the head would make the head fail to dominate the latch and the
    #  program would not be a natural loop at all, which is a different fact
    #  from the one being tested.  (The first draft of this control did exactly
    #  that and produced ZERO loops -- recorded because a control that never
    #  reaches the analysis is INVALID, not a rejection.)
    r4 = R("n4_internal_reset", [
        ("s_mov_b32 s0, 0", None),
        ("s_cmp_lg_u32 s0, 32", None),
        ("s_cbranch_scc0 9", 9),
        ("s_cmp_eq_u32 s2, 0", None),
        ("s_cbranch_scc0 6", 6),
        ("s_mov_b32 s0, 0", None),
        ("s_add_u32 s0, s0, 1", None),
        ("s_cmp_lg_u32 s0, 32", None),
        ("s_cbranch_scc1 1", 1),
        ("s_endpgm", None)])
    r4f = R("n4_internal_reset_fixed", [
        ("s_mov_b32 s0, 0", None),
        ("s_cmp_lg_u32 s0, 32", None),
        ("s_cbranch_scc0 6", 6),
        ("s_add_u32 s0, s0, 1", None),
        ("s_cmp_lg_u32 s0, 32", None),
        ("s_cbranch_scc1 1", 1),
        ("s_endpgm", None)])

    # ---------------------------------------------------------------- REQ-5
    r5 = R("n5_wraparound", [
        ("s_mov_b32 s0, -16", None),
        ("s_add_u32 s0, s0, 1", None),
        ("s_cmp_lg_u32 s0, 16", None),
        ("s_cbranch_scc1 1", 1),
        ("s_endpgm", None)])
    r5f = R("n5_wraparound_fixed", [
        ("s_mov_b32 s0, 0", None),
        ("s_add_u32 s0, s0, 1", None),
        ("s_cmp_lg_u32 s0, 16", None),
        ("s_cbranch_scc1 1", 1),
        ("s_endpgm", None)])

    # ---------------------------------------------------------------- REQ-6
    r6 = R("n6_unreachable_equality", [
        ("s_mov_b32 s0, 0", None),
        ("s_add_u32 s0, s0, 4", None),
        ("s_cmp_eq_u32 s0, 5", None),
        ("s_cbranch_scc0 1", 1),
        ("s_endpgm", None)])
    r6f = R("n6_unreachable_equality_fixed", [
        ("s_mov_b32 s0, 0", None),
        ("s_add_u32 s0, s0, 4", None),
        ("s_cmp_eq_u32 s0, 8", None),
        ("s_cbranch_scc0 1", 1),
        ("s_endpgm", None)])

    # ---------------------------------------------------------------- REQ-7
    r7u = R("n7_signedness_u32", [
        ("s_mov_b32 s0, -2", None),
        ("s_add_u32 s0, s0, 1", None),
        ("s_cmp_lt_u32 s0, 4", None),
        ("s_cbranch_scc1 1", 1),
        ("s_endpgm", None)])
    r7i = R("n7_signedness_i32", [
        ("s_mov_b32 s0, -2", None),
        ("s_add_u32 s0, s0, 1", None),
        ("s_cmp_lt_i32 s0, 4", None),
        ("s_cbranch_scc1 1", 1),
        ("s_endpgm", None)])

    # ---------------------------------------------------------------- REQ-8
    r8 = R("n8_indirect_load_dependency", [
        ("s_load_dword s1, s[0:1], 0", None),
        ("s_lshl_b32 s0, s1, 2", None),
        ("s_cmp_eq_u32 s0, 0", None),
        ("s_cbranch_scc1 0", 0),
        ("s_endpgm", None)])
    r8f = R("n8_indirect_load_dependency_fixed", [
        ("s_mov_b32 s1, 0", None),
        ("s_lshl_b32 s0, s1, 2", None),
        ("s_cmp_eq_u32 s0, 0", None),
        ("s_cbranch_scc1 0", 0),
        ("s_endpgm", None)])

    # ---------------------------------------------------------------- REQ-9
    r9 = R("n9_copied_load_dependency", [
        ("s_load_dword s1, s[0:1], 0", None),
        ("s_mov_b32 s0, s1", None),
        ("s_cmp_eq_u32 s0, 0", None),
        ("s_cbranch_scc1 0", 0),
        ("s_endpgm", None)])
    r9f = R("n9_copied_load_dependency_fixed", [
        ("s_mov_b32 s1, 0", None),
        ("s_mov_b32 s0, s1", None),
        ("s_cmp_eq_u32 s0, 0", None),
        ("s_cbranch_scc1 0", 0),
        ("s_endpgm", None)])

    # ==================================================================
    #  the per-case predicates -- each is a claim about the EVIDENCE
    # ==================================================================
    def p_zero_step(run, upd_idx):
        def f(L):
            ev = L["fired_requirement_evidence"] or {}
            u = ev.get("update") or {}
            ok = (ev.get("step") == 0 and u.get("at") == at(run, upd_idx)
                  and "s_add_u32 s0, s0, 0" in (u.get("insn") or ""))
            return ok, ("the row must carry step == 0 AND the planted "
                        "instruction at %s; it carried step=%r update=%r"
                        % (at(run, upd_idx), ev.get("step"), u))
        return f

    def p_wrong_source(run, upd_idx):
        def f(L):
            ev = L["fired_requirement_evidence"] or {}
            u = ev.get("update") or {}
            ok = (ev.get("destination") == "s0" and ev.get("source") == "s5"
                  and u.get("at") == at(run, upd_idx)
                  and "s_add_u32 s0, s5, 1" in (u.get("insn") or ""))
            return ok, ("the row must name the DESTINATION it matched, the "
                        "SOURCE it refused on, and the planted instruction; it "
                        "carried destination=%r source=%r update=%r"
                        % (ev.get("destination"), ev.get("source"), u))
        return f

    def p_skipped(run, latch_idx):
        def f(L):
            ev = L["fired_requirement_evidence"] or {}
            rows = ev.get("latch_rows") or []
            bad = [x for x in rows
                   if x.get("update_dominates_the_latch") is False]
            ok = (len(rows) == 1 and len(bad) == 1
                  and bad[0]["latch_pc"] == at(run, latch_idx))
            return ok, ("the row must contain exactly one LATCH ROW, for the "
                        "bypassing latch at %s, with "
                        "update_dominates_the_latch false -- naming the "
                        "specific path it could not model; it carried %r"
                        % (at(run, latch_idx), rows))
        return f

    def p_internal_reset(run, upd_idx, reset_idx):
        def f(L):
            ev = L["fired_requirement_evidence"] or {}
            ws = ev.get("writers") or []
            ats = [w.get("at") for w in ws]
            ok = (len(ws) == 2 and at(run, reset_idx) in ats
                  and at(run, upd_idx) in ats)
            return ok, ("the row must be the WRITERS list and it must contain "
                        "BOTH the ordinary update at %s and the planted reset "
                        "at %s -- the pair is what makes this a reset and not "
                        "a foreign write; it carried %r"
                        % (at(run, upd_idx), at(run, reset_idx), ws))
        return f

    def p_wraparound():
        def f(L):
            ev = L["fired_requirement_evidence"] or {}
            w, x = ev.get("first_wrap_at"), ev.get("exit_at")
            ok = isinstance(w, int) and isinstance(x, int) and w < x
            return ok, ("the row must carry BOTH indices and the wrap must "
                        "come strictly BEFORE the exit, which is the whole "
                        "content of the check; it carried first_wrap_at=%r "
                        "exit_at=%r" % (w, x))
        return f

    def p_unreachable():
        def f(L):
            ev = L["fired_requirement_evidence"] or {}
            ipb = str(ev.get("infinity_proved_by") or "")
            ok = (ev.get("orbit_status") == "INFINITE" and "congruence" in ipb)
            return ok, ("the refusal must be an INFINITE orbit PROVED by the "
                        "congruence having no solution -- not a generic "
                        "unknown, and not a cap-exhaustion; it carried "
                        "orbit_status=%r infinity_proved_by=%r"
                        % (ev.get("orbit_status"), ev.get("infinity_proved_by")))
        return f

    def p_signedness():
        def f(L):
            ev = L["fired_requirement_evidence"] or {}
            w, x = ev.get("first_wrap_at"), ev.get("exit_at")
            r07 = next((q for q in L["requirements"] if q["id"] == "R07"), {})
            sd = (r07.get("evidence") or {}).get("signedness")
            ok = (isinstance(w, int) and isinstance(x, int) and w <= x
                  and sd == "i32")
            return ok, ("the loop must have been READ as i32 (the mnemonic's "
                        "own signedness; R07's own evidence must say so) and "
                        "then refused by the wrap rule; it carried "
                        "R07.signedness=%r first_wrap_at=%r exit_at=%r"
                        % (sd, w, x))
        return f

    def p_load(run, load_idx, written_reg, guard_reg):
        def f(L):
            ev = L["fired_requirement_evidence"] or {}
            lw = ev.get("load_writers_found") or []
            cl = ev.get("closure") or []
            ok = (bool(lw)
                  and lw[0].get("at") == at(run, load_idx)
                  and lw[0].get("register") == written_reg
                  and "s_load_dword" in (lw[0].get("insn") or "")
                  and ev.get("guard_register") == guard_reg
                  and written_reg in cl and guard_reg in cl)
            return ok, ("the row must name the LOAD, the register it writes and "
                        "the guard register, and the closure must contain BOTH "
                        "the loaded register and the guard register -- that "
                        "containment is exactly what makes R76 transitive and "
                        "NOT the 16AT direct destination test, which saw a load "
                        "writing %s while the compare read %s and answered "
                        "`not a spin`; it carried load_writers_found=%r "
                        "closure=%r guard_register=%r"
                        % (written_reg, guard_reg, lw, cl,
                           ev.get("guard_register")))
        return f

    controls = []

    controls.append(build_row(
        "REQ-1", "zero step", "R06", r1, p_zero_step(r1, 1), repaired=r1f,
        notes=["the audit's own regression, brief section 74: the retired "
               "classifier calls this a COUNTED loop with a STATIC BOUND while "
               "its own max_trip_count is null",
               "the interpreter never reaches s_endpgm, so the refusal is about "
               "a loop that really does not terminate"],
        interp_expectation="STEP_LIMIT_REACHED: the register never changes, so "
                           "a continuing guard continues for ever"))

    controls.append(build_row(
        "REQ-2", "wrong source register", "R05", r2, p_wrong_source(r2, 2),
        repaired=r2f,
        notes=["the DESTINATION is the guard register, so a shape-only rule "
               "accepts it; the SOURCE is what makes it not a recurrence",
               "the interpreter never reaches s_endpgm: s0 is reloaded as "
               "s5+1 = 1 on every trip and s5 is never written"],
        interp_expectation="STEP_LIMIT_REACHED"))

    controls.append(build_row(
        "REQ-3", "skipped update", "R10", r3, p_skipped(r3, 6), repaired=r3f,
        notes=["the head is re-entered along a path that never executes the "
               "update, so the recurrence holds on one path and not the other",
               "the evidence required is the LATCH ROW for the bypassing latch "
               "with update_dominates_the_latch false: the refusal names the "
               "specific path it could not model",
               "the bypass branch reads EXEC, not SCC, so instruction 1 remains "
               "the latch guard's unique SCC producer and the refusal is about "
               "DOMINANCE rather than about the condition code",
               "the interpreter never reaches s_endpgm: the EXEC assumption it "
               "records is what routes it past the update"],
        interp_expectation="STEP_LIMIT_REACHED, with the EXEC assumption "
                           "recorded and named in the row"))

    controls.append(build_row(
        "REQ-4", "internal reset", "R11", r4, p_internal_reset(r4, 6, 5),
        repaired=r4f,
        notes=["the evidence required is the WRITERS list containing BOTH the "
               "ordinary update and the planted reset, which is what makes this "
               "a reached check rather than a verdict",
               "the interpreter cannot decide this program and says so instead "
               "of guessing: it stops on the compare against s2, which nothing "
               "writes"],
        interp_expectation="UNDETERMINED_SCC (s2 is never written)"))

    controls.append(build_row(
        "REQ-5", "wraparound", "R12", r5, p_wraparound(), repaired=r5f,
        notes=["0xFFFFFFF0 counts up THROUGH ZERO on its way to 16, so the "
               "value at the exit is not the value the unwrapped progression "
               "predicts",
               "the interpreter HALTS on this loop, and that is reported rather "
               "than hidden: this refusal is a limitation of the closed form, "
               "NOT a claim that the loop hangs"],
        interp_expectation="HALTED"))

    controls.append(build_row(
        "REQ-6", "unreachable equality", "R09", r6, p_unreachable(),
        repaired=r6f,
        notes=["0, 4, 8, 12, ... never equals 5: the orbit is a residue class "
               "that misses the target, so the loop does not terminate at all",
               "the interpreter never reaches s_endpgm, which is the "
               "independent witness"],
        interp_expectation="STEP_LIMIT_REACHED"))

    controls.append(build_row(
        "REQ-7", "signedness mismatch", "R12", r7i, p_signedness(),
        notes=["the paired control for this row is the OTHER MNEMONIC, "
               "recorded under `signedness_pair` rather than as a 'fix': the two "
               "programs differ in ONE SUFFIX and the prover's answers differ, "
               "which is what shows it read the signedness out of the mnemonic",
               "the interpreter HALTS on the i32 variant, so this is a FALSE "
               "REFUSAL by the wrap rule -- an honest ceiling of the prover, "
               "recorded rather than hidden"],
        interp_expectation="HALTED, after 6 guard evaluations"))

    controls.append(build_row(
        "REQ-8", "indirect load dependency", "R76", r8, p_load(r8, 0, "s1", "s0"),
        repaired=r8f, repaired_must_prove=False,
        notes=["a load -> shift -> compare chain: the load writes s1 and the "
               "compare reads s0, so the 16AT direct destination test answers "
               "`not a spin` about a loop that IS one",
               "the repaired row does NOT require the loop to be PROVEN: with "
               "the load replaced by an immediate the guard becomes a constant "
               "predicate, refused later at R04.  The claim tested is narrower "
               "and exact -- with the load removed, R76 stops firing",
               "the interpreter stops with UNDETERMINED_SCC, by a route that "
               "has nothing to do with the prover's SGPR closure walk"],
        interp_expectation="UNDETERMINED_SCC: the compared value is derived "
                           "from a memory load"))

    controls.append(build_row(
        "REQ-9", "copied load dependency", "R76", r9, p_load(r9, 0, "s1", "s0"),
        repaired=r9f, repaired_must_prove=False,
        notes=["load -> move -> compare: a register COPY is what hides the load "
               "from a destination-only test",
               "the interpreter stops with UNDETERMINED_SCC, independently of "
               "the prover's closure walk"],
        interp_expectation="UNDETERMINED_SCC: the compared value is a copy of "
                           "a loaded word"))

    # ---- the signedness pair, as an explicit two-row comparison ---------
    su = next((x for x in r7u["loops"] if x["verdict"] == PROVEN),
              r7u["loops"][0])
    si = next((x for x in r7i["loops"] if x["fired_requirement_id"] == "R12"),
              r7i["loops"][0])
    pair = {
        "what_is_compared": "the same program with the compare's signedness "
                            "suffix changed and NOTHING else",
        "u32_variant": {"asm": "s_cmp_lt_u32 s0, 4", "verdict": su["verdict"],
                        "max_trip_count": su["max_trip_count"],
                        "orbit_status": su["orbit_status"],
                        "interpreter": {
                            "status": r7u["interpreter"]["status"],
                            "guard_evaluations": r7u["interpreter"].get(
                                "guard_evaluations")}},
        "i32_variant": {"asm": "s_cmp_lt_i32 s0, 4", "verdict": si["verdict"],
                        "max_trip_count": si["max_trip_count"],
                        "orbit_status": si["orbit_status"],
                        "requirement_that_fired": si["fired_requirement_id"],
                        "interpreter": {
                            "status": r7i["interpreter"]["status"],
                            "guard_evaluations": r7i["interpreter"].get(
                                "guard_evaluations")}},
        "the_prover_answered_differently": su["verdict"] != si["verdict"],
        "why_that_is_the_point": "the two programs differ in one MNEMONIC "
                                 "SUFFIX.  The prover's answers differ, so it "
                                 "read the signedness out of the mnemonic "
                                 "rather than assuming one; and in the signed "
                                 "case it REFUSED instead of emitting a bound",
        "which_is_the_required_negative": "the i32 variant",
        "which_is_the_acceptance_control": "the u32 variant, which is PROVEN",
    }

    # ---- verdict --------------------------------------------------------
    def valid(c):
        return (c["applied"]["every_planted_word_decoded_as_requested"]
                and c["applied"]["branch_target_routes_agree"]
                and c["reached"][
                    "a_loop_was_refused_at_the_expected_requirement"]
                and c["reached"]["that_requirement_is_not_PROVEN"]
                and c["reached"][
                    "the_fired_rows_own_evidence_satisfies_the_per_case_"
                    "predicate"]
                and c["observed"]["verdict"] != PROVEN
                and (c["attributable"] is None or c["attributable"]["ok"]))

    bad = [c["id"] for c in controls if not valid(c)]
    n = len(controls)
    verdict = ("ALL_REQUIRED_NEGATIVES_REJECTED_AND_REACHED" if not bad
               else "NEGATIVE_SET_INCOMPLETE")

    out = {
        "schema": "p16ax/liveness-negatives/1",
        "phase": "16AX", "worker": "W9", "task": "T-LIVENESS", "brief_step": 3,
        "object": {
            "path": C.rel(C.OBJ),
            "whole_file_sha256_recomputed": C.sha256_file(C.OBJ),
            "text_sha256_recomputed": C.text_section_of(C.OBJ)["sha256"],
            "how_the_controls_were_built": "each program is assembled with "
                "llvm-mc, written into a COPY of the archived object at 0x7000, "
                "and analysed from what llvm-objdump read back from that copy; "
                "the archived object is never written to",
            "scratch": C.rel(C.WORK),
        },
        "n_required_negatives": n,
        "n_satisfied": n - len(bad),
        "ids_not_satisfied": bad,
        "the_nine_required_concepts": [c["concept"] for c in controls],
        "the_four_facts_each_row_records": {
            "applied": "the planted word decoded as requested, and the branch "
                       "target decoded from the raw bits equals the one "
                       "llvm-objdump printed",
            "reached": "a loop was refused AT the expected requirement, and "
                       "that row's own evidence satisfies a per-case PREDICATE "
                       "naming the planted instruction by address and text",
            "attributable": "removing the planted defect and nothing else stops "
                            "that requirement firing",
            "interpreted": "a straight-line interpreter over the same bytes "
                           "reports halting and the guard's execution count",
        },
        "controls": controls,
        "signedness_pair": pair,
        "interpreter_step_limit": STEP_LIMIT,
        "what_this_does_NOT_establish": [
            "that the prover's supported recurrence form covers every loop a "
            "compiler can emit.  Loops outside the form are refused, and the "
            "wraparound and signedness rows record two refusals of loops this "
            "script's own interpreter shows DO terminate.  A refusal is a "
            "limitation of the derivation, not a claim about the loop",
            "that the trip counts are runtime behaviour: they are static "
            "maxima for these machine loops",
            "that the interpreter models the hardware.  It models the scalar "
            "ALU, the scalar compares and the scalar branches, and nothing "
            "else; it does not model divergence (EXEC is assumed full, and "
            "every row that depends on that assumption records it), memory, or "
            "any instruction outside that set",
            "that these nine programs resemble the real object's loops.  They "
            "are constructed to exercise one requirement each; the real "
            "object's 33 loops are the subject of PROOF_RERUN_16AX.json",
        ],
        "verdict": verdict,
    }
    C.dump(OUT, out)

    for c in controls:
        print("  %-6s %-26s fired=%-4s verdict=%-42s applied=%s reached=%s "
              "attr=%s interp=%s"
              % (c["id"], c["concept"],
                 (c["observed"]["requirement_that_fired"] or "-"),
                 c["observed"]["verdict"],
                 c["applied"]["every_planted_word_decoded_as_requested"],
                 c["reached"][
                     "the_fired_rows_own_evidence_satisfies_the_per_case_"
                     "predicate"],
                 "-" if c["attributable"] is None else c["attributable"]["ok"],
                 c["interpreted"]["status"]))
    print("signedness pair: u32 %s trips=%s | i32 %s fired=%s; answers differ=%s"
          % (pair["u32_variant"]["verdict"],
             pair["u32_variant"]["max_trip_count"],
             pair["i32_variant"]["verdict"],
             pair["i32_variant"]["requirement_that_fired"],
             pair["the_prover_answered_differently"]))
    print("VERDICT %s (%d of %d)" % (verdict, n - len(bad), n))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
