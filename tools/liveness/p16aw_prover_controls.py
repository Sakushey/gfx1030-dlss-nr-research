#!/usr/bin/env python3
"""Phase 16AW -- controls for the replacement recurrence prover.

Brief PART X, sections 74, 75, 76, 77.

THE FAIRNESS RULE, AND THE OTHER ONE
    Two rules from this project's own history are wired into every row here.

      A checker must be able to FAIL.  Each negative control is a program on
      which the prover must return UNKNOWN_BLOCKING, and the row records WHICH
      requirement refused it -- a rejection that names no requirement is
      indistinguishable from a crash.

      A checker must ACCEPT the known-good case.  A run that refuses everything
      reads as strict and certifies nothing, so the positive controls are as
      load-bearing as the negatives, and one of them is the real archived
      object rather than a synthetic program.

    And a control must REACH what it judges: every negative row records the
    requirement that fired, the instruction it examined, and the old
    classifier's answer on the same input, so a reader can see that the two
    classifiers disagree ABOUT THE SAME BYTES.

WHAT "REACHED" MEANS HERE
    For a synthetic program, `reached` is not a claim: it is the requirement
    row the prover actually emitted, quoted from the proof itself.  The program
    text is verified by decode (see p16aw_synthetic), so the bytes the prover
    reasoned about are the bytes llvm-objdump read back.

Host-only.  Disassembling is not launching: no HIP call, no GPU, no slot.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(ROOT, "p16aw", "liveness")
WORK = os.path.join(OUT, "_work")

sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "p16at", "native"))
import p16at_machine_cfg as M            # noqa: E402
import p16aw_loop_recurrence_prover as P  # noqa: E402
import p16aw_old_classifier as OLD        # noqa: E402
import p16aw_synthetic as S               # noqa: E402

CO = M.CO
TEXT_SHA256_EXPECTED = \
    "ec11c135cf9a548cfd2e263757723a178b74bb148496be35bd47b2a95a85312e"

#: the audit's regression program, brief section 74, verbatim.  `loop:` is the
#: SECOND instruction (the s_mov_b32 is the preheader), and the branch's operand
#: is patched to that address by the builder.
AUDIT_REGRESSION = [
    ("s_mov_b32 s0, 0", None),
    ("s_add_u32 s0, s0, 0", None),          # the update advances by ZERO
    ("s_cmp_lg_u32 s0, 1", None),
    ("s_cbranch_scc1 loop", "head"),
    ("s_endpgm", None),
]


def resolve(prog):
    """prog: [(asm, target)].  A target is

        None      no branch
        "head"    the SECOND instruction (the usual layout: a preheader first)
        "exit"    the last instruction
        int       that instruction index, for shapes with more than one latch

    The ADDRESSES are computed by the builder from the encoded lengths of the
    instructions themselves; this function only names the targets, so a program
    containing a two-word instruction cannot silently shift every address.
    """
    n = len(prog)
    by_name = {"head": 1, "exit": n - 1}
    return [(asm, by_name[t] if isinstance(t, str) else t)
            for asm, t in prog]


def run_one(label, prog, obj=CO):
    """Assemble, verify by decode, prove, and summarise both classifiers."""
    ins, symbol_base, verification = S.build_program(
        resolve(prog), obj, WORK, label=label)
    ctx = P.build_context(ins, symbol_base)
    rows = P.prove_all(ctx)
    old_rows, old_meta, old_err = OLD.run_old_classifier(ins, symbol_base)
    old_summary = None if old_rows is None else OLD.summary_of(old_rows)
    #: the guard register, for the direct-vs-transitive comparison.  The prover
    #: records it on every path, not only on the proven one, so a spin can be
    #: compared against the direct test even though the prover refused it.
    guard_reg = None
    for r in rows:
        if r.get("induction_register"):
            guard_reg = r["induction_register"]
            break
    direct = (S.direct_load_test(ins, guard_reg) if guard_reg else
              (False, None))
    return {
        "label": label,
        "program": [{"at": c["at"], "asm": c["requested"], "bytes": c["bytes"],
                     "target_index": t, "decoded_as": c["decoded"]}
                    for c, (_a, t) in zip(verification["decode_checks"],
                                          resolve(prog))],
        "n_instructions": len(ins),
        "decode_verification": verification,
        "n_loops_found": len(rows),
        "loop_outcomes": [
            {"head_pc": r["head_pc"], "latch_pc": r["latch_pc"],
             "n_nodes": r["n_nodes"], "verdict": r["verdict"],
             "first_failing_requirement": r["first_failing_requirement"],
             "first_unknown_requirement": r["first_unknown_requirement"],
             "blocking_reason": r["blocking_reason"],
             "n_requirements_proven": r["n_requirements_proven"],
                 "max_trip_count": r.get("max_trip_count"),
                 "orbit_status": (r.get("orbit") or {}).get("status"),
                 "orbit_route_sim": (r.get("orbit") or {}).get("route_sim"),
                 "orbit_route_form": (r.get("orbit") or {}).get("route_form"),
                 "orbit_route_form_credited":
                     (r.get("orbit") or {}).get("route_form_credited"),
                 "the_requirement_that_fired": next(
                 ({"id": q["id"], "requirement": q["requirement"],
                   "status": q["status"], "detail": q["detail"],
                   "evidence": q["evidence"]}
                  for q in r["requirements"]
                  if q["id"] == (r["first_failing_requirement"]
                                 or r["first_unknown_requirement"])), None),
             "transitive_spin_dependency": r.get(
                 "transitive_spin_dependency")}
            for r in rows],
        "retired_classifier": {
            "slice_meta": old_meta, "error": old_err,
            "summary": old_summary,
            "per_loop": None if old_rows is None else [
                {"head_pc": L["head_pc"], "latch_pc": L["latch_pc"],
                 "termination": L.get("termination")} for L in old_rows],
        },
        "direct_load_test_16AT": {
            "guard_register": guard_reg,
            "says_spin": direct[0], "the_load_it_saw": direct[1],
            "what_it_does": "asks whether a LOAD's DESTINATION is the compared "
                            "register; reproduced line for line from "
                            "p16at/native/p16at_liveness_final.py",
        },
    }


def build_controls():
    controls = []

    def add(cid, kind, title, prog, expect_verdict, expect_requirement,
            why, obj=CO):
        row = run_one(cid, prog, obj=obj)
        row["id"] = cid
        row["kind"] = kind
        row["title"] = title
        row["why_this_control_exists"] = why
        row["expectation"] = {"verdict": expect_verdict,
                              "requirement_that_must_fire": expect_requirement}
        outcomes = row["loop_outcomes"]
        failed_reqs = {o["the_requirement_that_fired"]["id"]
                       for o in outcomes
                       if o["the_requirement_that_fired"]}
        verdicts = {o["verdict"] for o in outcomes}
        rejected_loops = [o for o in outcomes
                          if o["verdict"] != P.VERDICT_PROVEN]
        if kind == "positive":
            row["observed"] = {
                "verdicts": sorted(verdicts),
                "accepted": (verdicts == {P.VERDICT_PROVEN}),
            }
            row["changed"] = row["observed"]["accepted"]
        else:
            row["observed"] = {
                "verdicts": sorted(verdicts),
                "requirements_that_fired": sorted(failed_reqs),
                "rejected": bool(rejected_loops),
                "the_expected_requirement_fired":
                    expect_requirement in failed_reqs,
                "which_loops_were_rejected": [
                    {"latch_pc": o["latch_pc"],
                     "requirement": (o["the_requirement_that_fired"] or {}
                                     ).get("id"),
                     "detail": (o["the_requirement_that_fired"] or {}
                                ).get("detail")}
                    for o in rejected_loops],
                "why_changed_is_the_requirement_and_not_merely_the_verdict":
                    "a program can hold more than one loop, and a control whose "
                    "expected requirement fired on the rejected loop has "
                    "reached the comparison it names even when a sibling loop "
                    "proves out; requiring every loop in the program to be "
                    "rejected would make the row pass for the wrong reason",
            }
            #: CHANGED is per-requirement, not per-program: the row is valid
            #: only when the requirement it names is the one that fired.
            row["changed"] = row["observed"][
                "the_expected_requirement_fired"]
        row["applied"] = row["decode_verification"][
            "every_planted_word_decoded_to_the_requested_mnemonic"]
        if kind == "positive":
            #: REACHED for a positive control: the prover ran over the verified
            #: bytes and produced rows with max_trip_count set.  `accepted` is
            #: not enough -- a program that parsed to zero loops would also have
            #: no refusal in it.
            row["reached"] = bool(outcomes) and all(
                o["max_trip_count"] is not None for o in outcomes)
        else:
            #: REACHED for a negative control: the named requirement has a row
            #: in the proof table for a loop that was refused, and that row's
            #: detail names the instruction examined.  A mutant that died
            #: before the comparison has no such row.
            row["reached"] = any(
                o["the_requirement_that_fired"]
                and o["the_requirement_that_fired"]["id"] == expect_requirement
                and o["the_requirement_that_fired"]["evidence"] is not None
                and o["verdict"] != P.VERDICT_PROVEN
                for o in outcomes)
        row["valid"] = bool(row["applied"] and row["changed"] and
                            row["reached"])
        old_verdicts = ([] if row["retired_classifier"]["per_loop"] is None
                        else [x["termination"].get("verdict")
                              if isinstance(x["termination"], dict)
                              else x["termination"]
                              for x in row["retired_classifier"]["per_loop"]])
        old_bounds = ([] if row["retired_classifier"]["per_loop"] is None
                      else [x["termination"].get("max_trip_count")
                            if isinstance(x["termination"], dict) else None
                            for x in row["retired_classifier"]["per_loop"]])
        #: TWO DIFFERENT QUESTIONS, deliberately kept apart:
        #:   - did the retired classifier CERTIFY a counted loop that the
        #:     replacement REFUSES?  That is the defect this phase is about, and
        #:     a refusal by both (N9, N10) is not one.
        #:   - did the two emit different verdict strings at all?
        row["the_two_classifiers_disagree"] = any(
            (v == "COUNTED_LOOP_WITH_STATIC_BOUND") !=
            (o["verdict"] == P.VERDICT_PROVEN)
            for v, o in zip(old_verdicts, outcomes)) or \
            (len(old_verdicts) != len(outcomes))
        row["the_retired_certified_a_counted_loop_the_prover_refused"] = \
            any(v == "COUNTED_LOOP_WITH_STATIC_BOUND"
                and o["verdict"] != P.VERDICT_PROVEN
                for v, o in zip(old_verdicts, outcomes))
        row["the_verdict_strings_differ"] = bool(
            len(old_verdicts) != len(outcomes)
            or any(v != n for v, n in zip(
                old_verdicts,
                [("COUNTED_LOOP_WITH_STATIC_BOUND"
                  if o["verdict"] == P.VERDICT_PROVEN else o["verdict"])
                 for o in outcomes])))
        row["retired_classifier"]["verdicts"] = old_verdicts
        row["retired_classifier"]["max_trip_counts"] = old_bounds
        controls.append(row)
        print("  %-4s %-9s loops=%d verdicts=%s  old=%s  valid=%s"
              % (cid, kind, row["n_loops_found"],
                 ",".join(sorted(verdicts)) or "-",
                 ",".join(str(v) for v in old_verdicts) or "-",
                 row["valid"]))
        return row

    # ---------------- positives: a prover that refuses everything is not
    # ---------------- qualified, so these must be ACCEPTED.
    add("P1", "positive",
        "the canonical counted loop: compare-not-equal against 32, advance by 4",
        [("s_mov_b32 s0, 0", None),
         ("s_add_u32 s0, s0, 4", None),
         ("s_cmp_lg_u32 s0, 32", None),
         ("s_cbranch_scc1 0", "head"),
         ("s_endpgm", None)],
        P.VERDICT_PROVEN, None,
        "the shape the 16AT object actually contains 32 times; if the prover "
        "will not accept this it has rejected the kernel it is meant to clear")

    add("P2", "positive",
        "an ORDERED unsigned comparison: continue while x < 10, step 1",
        [("s_mov_b32 s0, 0", None),
         ("s_add_u32 s0, s0, 1", None),
         ("s_cmp_lt_u32 s0, 10", None),
         ("s_cbranch_scc1 0", "head"),
         ("s_endpgm", None)],
        P.VERDICT_PROVEN, None,
        "the equality family is decided by a congruence; the ordered family is "
        "decided by a monotone threshold, and the prover must handle both")

    add("P3", "positive",
        "equality with the OPPOSITE branch polarity: scc0 on eq, step 3, T 15",
        [("s_mov_b32 s0, 0", None),
         ("s_add_u32 s0, s0, 3", None),
         ("s_cmp_eq_u32 s0, 15", None),
         ("s_cbranch_scc0 0", "head"),
         ("s_endpgm", None)],
        P.VERDICT_PROVEN, None,
        "s_cbranch_scc0 inverts the continue-set: here the loop continues while "
        "the value is NOT 15, and stops when it is. A prover that assumed scc1 "
        "would report the inverse bound")

    add("P4", "positive",
        "a SIGNED ordered comparison: continue while x < 3 as i32",
        [("s_mov_b32 s0, 0", None),
         ("s_add_u32 s0, s0, 1", None),
         ("s_cmp_lt_i32 s0, 3", None),
         ("s_cbranch_scc1 0", "head"),
         ("s_endpgm", None)],
        P.VERDICT_PROVEN, None,
        "the signedness of the predicate must be read from the mnemonic, not "
        "guessed; the same bytes with _u32 would be a different loop")

    add("P5", "positive",
        "a DECREMENT with the predicate that matches it: step -1, exit at 0",
        [("s_mov_b32 s0, 8", None),
         ("s_sub_u32 s0, s0, 1", None),
         ("s_cmp_lg_u32 s0, 0", None),
         ("s_cbranch_scc1 0", "head"),
         ("s_endpgm", None)],
        P.VERDICT_PROVEN, None,
        "a decrement is a legitimate recurrence; a prover that only accepts "
        "increments would refuse it and be wrong")

    add("P6", "positive",
        "a reset AFTER the loop: it must NOT be read as a reset inside it",
        [("s_mov_b32 s0, 0", None),
         ("s_add_u32 s0, s0, 4", None),
         ("s_cmp_lg_u32 s0, 32", None),
         ("s_cbranch_scc1 0", "head"),
         ("s_mov_b32 s0, 0", None),
         ("s_endpgm", None)],
        P.VERDICT_PROVEN, None,
        "the clean-up write sits on the exit path, outside the loop body; a "
        "reset check that scans the address range instead of the loop would "
        "reject this valid loop")

    add("P8", "positive",
        "a COUNTDOWN with an ordered predicate: continue while x > 0, step -1",
        [("s_mov_b32 s0, 5", None),
         ("s_sub_u32 s0, s0, 1", None),
         ("s_cmp_gt_u32 s0, 0", None),
         ("s_cbranch_scc1 1", "head"),
         ("s_endpgm", None)],
        P.VERDICT_PROVEN, None,
        "a decreasing orbit against an ordered predicate is as ordinary a loop "
        "as an increasing one; a closed form that only handles a positive step "
        "would refuse this, and N7 is the row that shows the refusal is still "
        "correct when the predicate does not match the direction")

    # ---------------- negatives: brief section 75, one row per named case.
    add("N1", "negative",
        "THE AUDIT'S REGRESSION: a loop whose update advances by ZERO",
        AUDIT_REGRESSION, P.VERDICT_UNKNOWN, "R06",
        "brief section 74: s_add_u32 s0, s0, 0 leaves the compared register "
        "fixed for ever. The retired classifier calls it a counted loop with a "
        "static bound and max_trip_count None.")

    add("N2", "negative",
        "the update's SOURCE is a different register",
        [("s_mov_b32 s0, 0", None),
         ("s_mov_b32 s5, 0", None),
         ("s_add_u32 s0, s5, 1", None),
         ("s_cmp_lg_u32 s0, 32", None),
         ("s_cbranch_scc1 0", "head"),
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R05",
        "the destination matches the guard register, so a shape-only match "
        "accepts it -- but s0 is reloaded as s5+1 every trip and s5 is never "
        "written, so the loop never changes its compared value")

    add("N3", "negative",
        "the update is SKIPPED on one of the two latch paths",
        [("s_mov_b32 s0, 0", None),
         ("s_cbranch_execnz 5", 5),             # head: bypasses the update
         ("s_add_u32 s0, s0, 1", None),         # the update, on path A only
         ("s_cmp_lg_u32 s0, 32", None),         # the guard of path A
         ("s_cbranch_scc1 1", 1),               # latch A -> head
         ("s_cmp_lg_u32 s0, 32", None),         # the guard of path B
         ("s_cbranch_scc1 1", 1),               # latch B -> head, no update
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R10",
        "the head is re-entered from latch B without executing the update, so "
        "the recurrence holds on one path and not the other; a prover that "
        "checks only that an advance exists SOMEWHERE in the body accepts it. "
        "The bypass branch reads EXEC, not SCC, so the latch's guard stays the "
        "unique SCC producer and the refusal is about dominance, not about the "
        "condition code")

    add("N4", "negative",
        "a RESET of the induction register inside the loop",
        [("s_mov_b32 s0, 0", None),
         ("s_cmp_eq_u32 s2, 0", None),
         ("s_cbranch_scc0 5", 5),               # head: one of the two paths
         ("s_add_u32 s0, s0, 1", None),         # the update
         ("s_branch 6", 6),                     # path A -> the guard
         ("s_mov_b32 s0, 0", None),             # THE RESET, inside the loop
         ("s_cmp_lg_u32 s0, 32", None),         # the guard, in the latch block
         ("s_cbranch_scc1 2", 2),               # latch -> head
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R11",
        "on the path through the reset the register is zeroed, so the recurrence "
        "has two writers and no single orbit; this is the case that the retired "
        "classifier cannot see at all, because it asks only whether an advance "
        "with the right destination EXISTS")

    add("N5", "negative",
        "the value WRAPS before it can reach the compared value",
        [("s_mov_b32 s0, -16", None),
         ("s_add_u32 s0, s0, 1", None),
         ("s_cmp_lg_u32 s0, 16", None),
         ("s_cbranch_scc1 0", "head"),
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R12",
        "starting at 0xFFFFFFF0 the 32-bit value wraps through zero on the way "
        "to 16; the unwrapped progression, and therefore the bound derived "
        "from it, is wrong")

    add("N6", "negative",
        "the compared value is UNREACHABLE by the recurrence (step 4, target 5)",
        [("s_mov_b32 s0, 0", None),
         ("s_add_u32 s0, s0, 4", None),
         ("s_cmp_eq_u32 s0, 5", None),
         ("s_cbranch_scc0 0", "head"),
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R09",
        "4, 8, 12, ... never equals 5, so the loop does not terminate at all; "
        "the retired classifier reports a bound of 2")

    add("N7", "negative",
        "a DECREMENT with the predicate of an increment",
        [("s_mov_b32 s0, 0", None),
         ("s_sub_u32 s0, s0, 1", None),
         ("s_cmp_gt_u32 s0, 32", None),
         ("s_cbranch_scc1 0", "head"),
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R09",
        "counting down from 0, the first value above 32 is 4 294 967 263 "
        "iterations away; the retired classifier reports a bound of 32")

    add("N8u", "negative",
        "an UNSIGNED compare that no value can fail: x >= 0",
        [("s_mov_b32 s0, 0", None),
         ("s_add_u32 s0, s0, 1", None),
         ("s_cmp_ge_u32 s0, 0", None),
         ("s_cbranch_scc1 0", "head"),
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R09",
        "for an unsigned word, x >= 0 is true for every x, so the continue-set "
        "is the whole domain and the loop never ends")

    add("N8i", "negative",
        "the SAME bytes with a SIGNED compare: x >= 0 as i32",
        [("s_mov_b32 s0, 0", None),
         ("s_add_u32 s0, s0, 1", None),
         ("s_cmp_ge_i32 s0, 0", None),
         ("s_cbranch_scc1 0", "head"),
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R09",
        "signed, the orbit leaves the continue-set at 2**31 - 1 trips, far "
        "beyond the supported cap; the retired classifier cannot tell this "
        "program from N8u -- same verdict, same bound -- although one never "
        "ends and the other ends")

    add("N9", "negative",
        "a SPIN through a copy: load -> move -> compare -> branch",
        [("s_load_dword s1, s[0:1], 0", None),   # the HEAD: the load is in the loop
         ("s_mov_b32 s0, s1", None),
         ("s_cmp_eq_u32 s0, 0", None),
         ("s_cbranch_scc1 0", 0),
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R76",
        "brief section 76. The 16AT direct test asks whether the LOAD's "
        "destination is the compared register; here the load writes s1 and the "
        "compare reads s0, so the direct test answers 'not a spin' about a loop "
        "that is one")

    add("N10", "negative",
        "a SPIN through ARITHMETIC: load -> shift -> compare -> branch",
        [("s_load_dword s1, s[0:1], 0", None),
         ("s_lshl_b32 s0, s1, 2", None),
         ("s_cmp_eq_u32 s0, 0", None),
         ("s_cbranch_scc1 0", 0),
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R76",
        "the transformed value is a second load -> arithmetic -> compare chain "
        "that the direct destination test cannot see; the closure walk has to "
        "follow the operand, not the destination")

    add("N11", "negative",
        "a DATA-DEPENDENT entry value: the initial definition is a LOAD",
        [("s_load_dword s0, s[0:1], 0", None),
         ("s_add_u32 s0, s0, 1", None),
         ("s_cmp_lg_u32 s0, 32", None),
         ("s_cbranch_scc1 1", 1),
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R76",
        "the recurrence itself is a textbook counter, but it starts wherever "
        "memory says, so no static bound exists; the entry value is a loaded "
        "word rather than a constant")

    add("N12", "negative",
        "a DATA-DEPENDENT entry value that is a register, not a constant",
        [("s_mov_b32 s0, s7", None),
         ("s_add_u32 s0, s0, 1", None),
         ("s_cmp_lg_u32 s0, 32", None),
         ("s_cbranch_scc1 1", 1),
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R02",
        "the entry value is copied from an unwritten register; the trip count "
        "is whatever that register holds, and no immediate can be resolved")

    add("N13", "negative",
        "the initial definition is a COPY of the register, not an immediate",
        [("s_mov_b32 s0, 0", None),
         ("s_mov_b32 s0, s0", None),            # a self-copy, preheader
         ("s_add_u32 s0, s0, 4", None),         # head + update in one block
         ("s_cmp_lg_u32 s0, 32", None),
         ("s_cbranch_scc1 2", 2),
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R02",
        "the unique reaching definition of s0 is a move whose source is not an "
        "immediate, so the entry value is whatever the register happened to "
        "hold; the retired classifier sees the advance and calls the loop "
        "counted with a static bound")

    add("N14", "negative",
        "a DIRECT spin: the load writes the compared register itself",
        [("s_load_dword s0, s[0:1], 0", None),
         ("s_cmp_lg_u32 s0, 0", None),
         ("s_cbranch_scc1 0", 0),
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R76",
        "this is the case the 16AT direct test DOES catch, and the row is here "
        "so that the transitive analysis can be seen to be a superset of it "
        "rather than a different answer: the direct test says spin, the "
        "transitive analysis says spin, and the two agree on the program where "
        "they can both see the load")

    add("N15", "negative",
        "the guard's register is never written inside the loop at all",
        [("s_mov_b32 s1, 0", None),
         ("s_cmp_lg_u32 s0, 32", None),         # head: compares a register that
         ("s_cbranch_scc1 1", 1),               # nothing in the loop writes
         ("s_endpgm", None)],
        P.VERDICT_UNKNOWN, "R11",
        "the retired classifier's own vocabulary calls this "
        "GUARD_HAS_NO_IN_LOOP_ADVANCE; the replacement refuses it at the same "
        "fact, with zero writers instead of two")

    return controls


def main() -> int:
    obj_sha = hashlib.sha256(open(CO, "rb").read()).hexdigest()
    text_sha, text_size, text_off = _text_section_sha(CO)
    print("object        %s" % os.path.relpath(CO, ROOT))
    print("object sha256 %s" % obj_sha)
    print(".text  sha256 %s (size %d, offset %#x)"
          % (text_sha, text_size, text_off))
    print(".text sha256 is the brief's           %s"
          % (text_sha == TEXT_SHA256_EXPECTED))

    controls = build_controls()

    #: the real object as a positive control: the prover must accept the
    #: kernel it is meant to clear, not only hand-made programs.
    from p16aw_prove_slot5 import prove_slot5
    real = prove_slot5(CO)
    controls.append({
        "id": "P7", "kind": "positive",
        "title": "the archived Slot-5 object itself",
        "why_this_control_exists": "a prover that accepts synthetic programs "
                                   "and refuses the real one has a form that "
                                   "does not occur in practice; this row is "
                                   "the fairness rule applied to the artefact "
                                   "under test",
        "expectation": {"verdict": P.VERDICT_PROVEN,
                        "requirement_that_must_fire": None},
        "applied": True,
        "reached": True,
        "changed": real["verdict"] == "ALL_LOOPS_PROVEN_WITH_A_FINITE_BOUND",
        "observed": {"verdicts": [r["verdict"] for r in real["loops"]],
                     "n_loops": real["n_loops"],
                     "trip_counts": sorted({r.get("max_trip_count")
                                            for r in real["loops"]})},
        "valid": real["verdict"] == "ALL_LOOPS_PROVEN_WITH_A_FINITE_BOUND",
        "the_two_classifiers_disagree": False,
        "detail": {"artifact": "MACHINE_LOOP_RECURRENCE_PROOFS_16AW.json",
                   "verdict": real["verdict"], "n_loops": real["n_loops"]},
    })
    print("  P7   positive  loops=%d verdicts=%s  valid=%s"
          % (real["n_loops"], real["verdict"], controls[-1]["valid"]))

    n_pos = len([c for c in controls if c["kind"] == "positive"])
    n_neg = len([c for c in controls if c["kind"] == "negative"])
    pos_ok = [c["id"] for c in controls
              if c["kind"] == "positive" and c["valid"]]
    pos_bad = [c["id"] for c in controls
               if c["kind"] == "positive" and not c["valid"]]
    neg_ok = [c["id"] for c in controls
              if c["kind"] == "negative" and c["valid"]]
    neg_bad = [c["id"] for c in controls
               if c["kind"] == "negative" and not c["valid"]]
    n_disagree = len([c for c in controls
                      if c.get("the_two_classifiers_disagree")])
    n_certified_then_refused = len([
        c for c in controls
        if c.get("the_retired_certified_a_counted_loop_the_prover_refused")])
    n_strings_differ = len([c for c in controls
                            if c.get("the_verdict_strings_differ")])

    verdict = ("PASS" if not pos_bad and not neg_bad else "STOP")
    out = {
        "schema": "p16aw/loop-prover-controls/1",
        "phase": "16AW",
        "brief_sections": [74, 75, 76],
        "object": {"path": os.path.relpath(CO, ROOT).replace("\\", "/"),
                   "sha256": obj_sha,
                   "text_section_sha256": text_sha,
                   "text_section_size": text_size,
                   "text_section_file_offset": text_off},
        "verdict": verdict,
        "counts": {
            "n_controls": len(controls),
            "n_positive": n_pos, "n_negative": n_neg,
            "n_positive_accepted": len(pos_ok),
            "n_positive_not_accepted": len(pos_bad),
            "n_negative_rejected_at_the_named_requirement": len(neg_ok),
            "n_negative_not_rejected_as_expected": len(neg_bad),
            "n_controls_whose_planted_word_did_not_decode_as_requested":
                len([c for c in controls
                     if not c.get("applied", True)]),
            "n_controls_on_which_the_retired_classifier_and_the_prover_"
            "disagree": n_disagree,
            "n_controls_where_the_retired_classifier_CERTIFIED_a_counted_loop"
            "_that_the_prover_REFUSES": n_certified_then_refused,
            "n_controls_where_the_two_emit_different_verdict_strings":
                n_strings_differ,
            "how_to_read_the_two_numbers_above": "they answer different "
                "questions. `certified then refused` counts the controls where "
                "the retired classifier wrote COUNTED_LOOP_WITH_STATIC_BOUND "
                "and the replacement refused the loop -- the defect this phase "
                "is about. `different verdict strings` also counts the rows "
                "where BOTH refuse but for different reasons (N9, N10: "
                "GUARD_HAS_NO_IN_LOOP_ADVANCE against "
                "SPIN_OR_EXTERNAL_PROGRESS_DEPENDENCY), which is not a defect "
                "in the retired classifier's sense of the word.",
            "n_requirements_in_the_prover": len(P.REQUIREMENTS),
            "n_requirements_from_brief_section_72": len(
                P.SECTION_72_REQUIREMENTS),
        },
        "positive_controls_not_accepted": pos_bad,
        "negative_controls_not_rejected_as_expected": neg_bad,
        "controls": controls,
        "the_retired_classifier": {
            "slice": OLD.extract_slice()[1],
            "exactly_what_it_did": "scanned the loop body for "
                "`s_(add|addk|sub)_{i32,u32} Rd, Rs, imm` whose DESTINATION was "
                "the register the guard compares, without reading Rs, without "
                "requiring imm != 0, and without any dominance, reset, wrap or "
                "reachability check; if it found one it wrote the verdict "
                "COUNTED_LOOP_WITH_STATIC_BOUND",
            "the_two_defects_measured_here": [
                "a zero step still counts as an advance, so the verdict is "
                "COUNTED_LOOP_WITH_STATIC_BOUND while max_trip_count is None",
                "the SOURCE operand is never read, so an update that reloads "
                "the guard register from another register counts as a counter",
            ],
        },
        "what_this_does_not_establish": [
            "that the prover's supported form covers every loop a compiler can "
            "emit -- loops outside the form are refused, and a refusal is not a "
            "proof that such a loop fails to terminate",
            "that the trip counts are the kernel's runtime behaviour: they are "
            "static maxima for the machine loops of this object, and the "
            "16AS/16AT memory-bounds work is the argument that no loop can "
            "leave its buffer",
            "anything about the device: no kernel was launched",
        ],
    }
    with open(os.path.join(OUT, "LOOP_PROVER_CONTROLS_16AW.json"), "w",
              encoding="utf-8") as f:
        json.dump(out, f, indent=1)

    print()
    print("controls compared           %d (positive %d, negative %d)"
          % (len(controls), n_pos, n_neg))
    print("positive accepted           %d of %d  %s" % (len(pos_ok), n_pos,
                                                       pos_bad or ""))
    print("negative rejected as named  %d of %d  %s" % (len(neg_ok), n_neg,
                                                       neg_bad or ""))
    print("planted words not verified  %d"
          % out["counts"]["n_controls_whose_planted_word_did_not_decode_as_"
                         "requested"])
    print("classifiers disagree on     %d controls (%d of them: the retired "
          "classifier certified a counted loop the prover refuses; %d rows "
          "differ in the verdict string at all)"
          % (n_disagree, n_certified_then_refused, n_strings_differ))
    print("verdict                     %s" % verdict)
    return 0 if verdict == "PASS" else 1


def _text_section_sha(co):
    """One route, one fact: the section layout comes from the same ELF parser
    the Slot-5 report uses, so the two artefacts cannot disagree about which
    bytes they hashed.  (`llvm-objdump -h` on this object does not print the
    file offset at all.)"""
    from p16aw_prove_slot5 import text_section
    sec, err, _meta = text_section(co)
    if sec is None:
        raise RuntimeError("could not read the .text section: %s" % err)
    return sec["sha256"], sec["size"], sec["offset"]


if __name__ == "__main__":
    sys.exit(main())
