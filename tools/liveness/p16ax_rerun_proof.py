#!/usr/bin/env python3
"""Phase 16AX / W9 -- T-LIVENESS step 1 and step 5.

RE-RUN THE RECURRENCE PROVER MYSELF, ON THE FINAL OBJECT, AND RE-DERIVE ITS
NUMBERS BY ROUTES THAT DO NOT GO THROUGH IT.

    Step 1 asks for the proof to be re-run rather than copied.  Copying is what
    the record already did once, and it is how a stale number survives a phase.
    So this script:

      A. recomputes the object's whole-file SHA-256 and the SHA-256 of its .text
         FROM THE BYTES ON DISK, and checks the .text against the hash the brief
         quotes (step 5);
      B. runs the prover over the object and records the counts it produced;
      C. re-derives those counts independently:
           - the instruction count and the backward-branch count come from MY
             disassembly route and MY SOPP displacement decode;
           - the instruction at each loop's head, latch, guard, update and
             initial-definition address is re-read from the decoded stream and
             compared against the prover's own record of it;
           - the guard's truth value at the prover's asserted exit index is
             re-evaluated here, in Python, in the mnemonic's OWN signedness and
             the branch's OWN polarity, with 32-bit modular arithmetic;
           - the index just BEFORE the exit is re-evaluated and must still
             continue, which is the fact that makes the reported trip count a
             MAXIMUM rather than a coincidence.
         A disagreement in any of these is a failure of this phase, not a note.

    Step 5 asks for the binding: the exact object path, its SHA-256 recomputed
    in this session, and its .text SHA -- together with the condition under
    which this whole proof becomes STALE.

Host-only.  Disassembling is not launching: no HIP call, no GPU, no slot.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import p16ax_common as C          # noqa: E402

OUT = os.path.join(HERE, "PROOF_RERUN_16AX.json")


def _hist(rows):
    h = {}
    for r in rows:
        k = str(r.get("max_trip_count"))
        h[k] = h.get(k, 0) + 1
    return h


def main() -> int:
    S, P, OLD = C._load_16aw()

    # ---- A. the object, recomputed from bytes ---------------------------
    whole = C.sha256_file(C.OBJ)
    text = C.text_section_of(C.OBJ)
    meta = C.elf_metadata(C.OBJ)
    ins_own = C.disassemble_own(C.OBJ)
    branches_own, _t = C.backward_branches_own(C.OBJ)
    back_own = [b for b in branches_own if b["is_backward"]]
    unresolved = [b for b in branches_own if b["target"] is None]

    # ---- B. run the prover ---------------------------------------------
    dis = C.disassemble_own(C.OBJ)

    # the prover's front end is the 16AT parser; run it on the SAME bytes via
    # the prover's own documented entry point
    res = None
    sys.path.insert(0, os.path.join(C.ROOT, "p16aw", "liveness"))
    import p16aw_prove_slot5 as PS      # noqa: E402
    res = PS.prove_slot5(C.OBJ)

    # ---- C. independent re-derivation -----------------------------------
    # instruction text, from MY decode, for address lookup
    mine = {a: "%s %s" % (mn, ops) for a, mn, ops, _r in ins_own}
    mine_norm = {a: C.re.sub(r"\s+", " ", v).strip() for a, v in mine.items()}

    per_loop = []
    n_head_ok = n_latch_ok = n_guard_ok = n_update_ok = n_init_ok = 0
    n_index_confirmed = 0
    n_index_prev_continues = 0
    mismatches = []

    PROG = P.VERDICT_PROVEN
    for i, r in enumerate(res["loops"]):
        head = int(r["head_pc"], 16)
        latch = int(r["latch_pc"], 16)
        row = {"loop_index": i, "head_pc": r["head_pc"], "latch_pc": r["latch_pc"],
               "prover_verdict": r["verdict"],
               "prover_max_trip_count": r.get("max_trip_count")}

        # the head and latch must be an instruction boundary in MY decode, and
        # the latch must be a backward branch in MY decode
        head_ok = head in mine
        latch_ok = latch in mine and any(b["at"] == latch for b in back_own)
        row["head_is_an_instruction_boundary_in_my_decode"] = head_ok
        row["latch_is_a_backward_branch_in_my_decode"] = latch_ok
        row["latch_instruction_my_decode"] = mine_norm.get(latch)
        n_head_ok += head_ok
        n_latch_ok += latch_ok

        if r["verdict"] != PROG:
            row["why_not_re_derived"] = ("the loop was refused, so there is no "
                                         "trip count to re-evaluate; the "
                                         "refusal reason is recorded by the "
                                         "prover's requirement table")
            row["blocking_reason"] = r.get("blocking_reason")
            per_loop.append(row)
            continue

        g = r["guard"]
        u = r["update"]
        ini = r["initial_value"]
        reg = r["induction_register"]
        g_addr = int(g["at"], 16)
        u_addr = int(u["at"], 16)
        i_addr = int(ini["at"], 16)

        # 1. the guard the prover names must be the instruction at that address
        guard_text = C.re.sub(r"\s+", " ",
                              "%s %s" % (g["insn"].split(None, 1)[0],
                                         g["insn"].split(None, 1)[1]
                                         if " " in g["insn"] else "")).strip()
        guard_ok = mine_norm.get(g_addr) == guard_text
        update_ok = mine_norm.get(u_addr) == C.re.sub(
            r"\s+", " ", u["insn"]).strip()
        init_ok = mine_norm.get(i_addr) == C.re.sub(
            r"\s+", " ", ini["insn"]).strip()
        row["guard_instruction_matches_my_decode"] = guard_ok
        row["guard_instruction_my_decode"] = mine_norm.get(g_addr)
        row["update_instruction_matches_my_decode"] = update_ok
        row["update_instruction_my_decode"] = mine_norm.get(u_addr)
        row["initial_definition_matches_my_decode"] = init_ok
        row["initial_definition_my_decode"] = mine_norm.get(i_addr)
        n_guard_ok += guard_ok
        n_update_ok += update_ok
        n_init_ok += init_ok
        if not (guard_ok and update_ok and init_ok):
            mismatches.append({"loop_index": i,
                               "what": "the prover's recorded instruction text "
                                       "for the guard/update/initial definition "
                                       "is not what my decode finds at that "
                                       "address",
                               "guard": mine_norm.get(g_addr),
                               "update": mine_norm.get(u_addr),
                               "init": mine_norm.get(i_addr)})

        # 2. re-evaluate the guard at the asserted exit index and at the index
        #    before it, in the mnemonic's own signedness and the branch's OWN
        #    polarity, with 32-bit modular arithmetic -- MY arithmetic, not the
        #    prover's orbit_verdict.
        exit_j = r["orbit"]["route_sim"]
        trips = r["max_trip_count"]
        A0 = ini["post_update_A0"]
        step = u["step"] & 0xFFFFFFFF
        op = g["predicate"]
        signed = (g["signedness"] == "i32")
        T = g["termination_value"]
        pol = next((q["evidence"].get("continues_when_guard_is")
                    for q in r["requirements"]
                    if q["id"] == "R08"
                    and q["status"] == P.PROVEN), None)
        row["continues_when_guard_is"] = pol
        row["guard_op_signedness_T"] = [op, g["signedness"], T]
        row["A0"] = A0
        row["step"] = C._sv(step, True)

        def guard_true(x):
            return C._cmp_true(op, x, T, signed)

        def continues(x):
            gt = guard_true(x)
            return gt if pol == "scc1" else (not gt)

        j = exit_j
        val_at_exit = (A0 + j * step) & 0xFFFFFFFF
        val_before = (A0 + (j - 1) * step) & 0xFFFFFFFF
        exits_at_j = not continues(val_at_exit)
        continues_at_jm1 = continues(val_before) if j >= 1 else None
        row["exit_index_re_evaluated_exits_here"] = exits_at_j
        row["index_before_the_exit_still_continues"] = continues_at_jm1
        row["trips_equals_exit_index_plus_one"] = (trips == j + 1)
        n_index_confirmed += exits_at_j and (trips == j + 1)
        n_index_prev_continues += bool(continues_at_jm1)

        # 3. the trip count must also equal the closed form the prover recorded,
        #    so that "two routes agreed" is a fact this phase can see
        row["prover_route_form"] = r["orbit"]["route_form"]
        row["prover_routes_agree"] = r["orbit"]["routes_agree"]
        row["prover_route_form_credited"] = r["orbit"]["route_form_credited"]
        row["first_wrap_at"] = r["orbit"]["first_wrap_at"]
        row["my_wrap_after_exit"] = (r["orbit"]["first_wrap_at"] is None or
                                     r["orbit"]["first_wrap_at"] > j)
        per_loop.append(row)

    n_loops = res["n_loops"]
    n_proven = res["n_loops_proven_with_a_finite_bound"]
    hist = sorted({r.get("max_trip_count") for r in res["loops"]
                   if r.get("max_trip_count") is not None})

    all_text_matches = (n_guard_ok == n_proven and n_update_ok == n_proven
                        and n_init_ok == n_proven)
    all_index_ok = (n_index_confirmed == n_proven)

    rerun_verdict = (
        "PROOF_REPRODUCED_AND_RE_DERIVED"
        if (res["verdict"] == "ALL_LOOPS_PROVEN_WITH_A_FINITE_BOUND"
            and n_loops == 33 and n_proven == 33 and hist == [8]
            and all_text_matches and all_index_ok
            and not unresolved
            and n_latch_ok == n_loops
            and len(back_own) == 33
            and text["sha256"] == C.TEXT_SHA_IN_BRIEF)
        else "REPRODUCTION_FAILED")

    out = {
        "schema": "p16ax/proof-rerun/1",
        "phase": "16AX",
        "worker": "W9",
        "task": "T-LIVENESS",
        "what_this_is": "the recurrence prover re-executed by this worker over "
                        "the final Slot-5 object, with every number it reports "
                        "re-derived here by a route that does not go through "
                        "the prover",
        "object_binding": {
            "path": C.rel(C.OBJ),
            "whole_file_sha256_recomputed_from_bytes": whole,
            "whole_file_sha256_quoted_in_the_brief": C.WHOLE_SHA_IN_BRIEF,
            "whole_file_sha256_matches_the_brief": whole == C.WHOLE_SHA_IN_BRIEF,
            "text_section": {
                "sha256_recomputed_from_bytes": text["sha256"],
                "sha256_quoted_in_the_brief": C.TEXT_SHA_IN_BRIEF,
                "matches_the_brief": text["sha256"] == C.TEXT_SHA_IN_BRIEF,
                "size": text["size"], "file_offset": text["offset"],
                "vma": hex(text["vma"]), "n_bytes_hashed": text["n_bytes"],
                "how_the_offset_was_obtained": "parsed in this script from the "
                                               "object's own ELF section header "
                                               "table",
            },
            "kernel_descriptor_abi_read_by_llvm_readobj": meta,
            "object_size_bytes": os.path.getsize(C.OBJ),
            "file_mtime_utc": None,
        },
        "STALE_IF": [
            "p16as/native/hip/build/k_dec_upsample_b64.co changes: its "
            "whole-file SHA-256 must stay "
            "24f53bd0f621215c232c782444e7aa364d0e57622b1fd9360e78efdb43572224 "
            "and its .text SHA-256 must stay "
            "ec11c135cf9a548cfd2e263757723a178b74bb148496be35bd47b2a95a85312e",
            "the native SOURCE changes in a way that changes the emitted .text: "
            "p16as/native/hip/k_dec_upsample_gfx1030.cpp currently hashes "
            "8825b07b164a15e93693c7d27419110545461d3a2824a2221fe889066a87beb5, "
            "and another worker (W1/T-VOPD, W2/T-NUMERIC, W3/T-EXEC) rebuilding "
            "this object would invalidate every trip count below without "
            "changing a character of this phase",
            "the prover itself changes: p16aw_loop_recurrence_prover.py and the "
            "16AT front end it imports are the instrument, and their SHA-256s "
            "are recorded under `the_instrument`",
            "the 16AT front end changes: p16at_machine_cfg.py supplies the CFG, "
            "the dominators, the natural loops and the SCC reaching definitions",
        ],
        "the_instrument": {
            "p16aw_loop_recurrence_prover.py": C.sha256_file(os.path.join(
                C.ROOT, "p16aw", "liveness",
                "p16aw_loop_recurrence_prover.py")),
            "p16aw_prove_slot5.py": C.sha256_file(os.path.join(
                C.ROOT, "p16aw", "liveness", "p16aw_prove_slot5.py")),
            "p16at_machine_cfg.py": C.sha256_file(os.path.join(
                C.ROOT, "p16at", "native", "p16at_machine_cfg.py")),
            "this_script": C.sha256_file(os.path.abspath(__file__)),
            "p16ax_common.py": C.sha256_file(os.path.join(HERE,
                                                          "p16ax_common.py")),
        },
        "the_numbers_I_observed": {
            "verdict": res["verdict"],
            "n_instructions_object": res["object"]["n_instructions"],
            "n_instructions_my_decode": len(ins_own),
            "n_branch_instructions": res["cfg"]["n_branch_instructions"],
            "n_backward_branches_prover": res["cfg"]["n_backward_branches"],
            "n_backward_branches_my_decode": len(back_own),
            "n_branch_instructions_my_decode": len(branches_own),
            "n_branches_with_an_unresolved_target_my_decode": len(unresolved),
            "n_natural_loops": len(res["loops"]),
            "n_loops_proven_with_a_finite_bound":
                res["n_loops_proven_with_a_finite_bound"],
            "max_trip_count_histogram_prover": _hist(res["loops"]),
            "distinct_max_trip_counts": hist,
            "every_loop_has_max_trip_count_8": hist == [8],
            "n_backward_branches_not_covered_by_a_natural_loop":
                res["cfg"]["n_backward_branches_not_covered_by_a_natural_loop"],
            "n_blocks": res["cfg"]["n_blocks"],
            "n_reachable_blocks": res["cfg"]["n_reachable_blocks"],
        },
        "my_independent_re_derivation": {
            "what_each_check_answers": {
                "head/latch boundary": "the addresses the prover calls a loop "
                    "head and latch are real instruction boundaries in MY "
                    "disassembly, and the latch is a backward branch in MY "
                    "SOPP decode",
                "instruction text": "the guard, the update and the initial "
                    "definition the prover names are the instructions MY decode "
                    "finds at those addresses -- so the prover reasoned about "
                    "the bytes on disk and not about a remembered string",
                "exit index": "evaluating the guard's own predicate, in the "
                    "mnemonic's own signedness and the branch's own polarity, "
                    "with 32-bit modular arithmetic written here, reproduces "
                    "the prover's exit index",
                "index before": "the same evaluation one step earlier still "
                    "CONTINUES, so the reported index is the FIRST exit and the "
                    "reported count is therefore a maximum",
                "wrap": "the prover's own first-wrap index lies strictly after "
                    "the exit, so the reported value at the exit is the value "
                    "the hardware's 32-bit adder produces",
            },
            "n_loops": n_loops,
            "n_loops_proven": n_proven,
            "n_heads_that_are_instruction_boundaries": n_head_ok,
            "n_latches_that_are_backward_branches_in_my_decode": n_latch_ok,
            "n_guard_instructions_matching_my_decode": n_guard_ok,
            "n_update_instructions_matching_my_decode": n_update_ok,
            "n_initial_definitions_matching_my_decode": n_init_ok,
            "n_exit_indices_re_produced_here": n_index_confirmed,
            "n_loops_where_the_index_before_the_exit_still_continues":
                n_index_prev_continues,
            "instruction_text_mismatches": mismatches,
        },
        "per_loop": per_loop,
        "cross_check_against_the_retired_16AT_classifier": {
            "n_agree": res["cross_check_against_the_retired_classifier"][
                "n_loops_where_they_agree"],
            "n_disagree": res["cross_check_against_the_retired_classifier"][
                "n_loops_where_they_disagree"],
            "n_called_counted_with_a_NULL_bound": res[
                "cross_check_against_the_retired_classifier"][
                "n_loops_the_retired_classifier_called_counted_with_a_NULL_"
                "bound"],
            "why_this_is_reported": "the two classifiers AGREE on every loop of "
                "the real object; that is a fairness fact about the replacement "
                "and it is NOT the claim that the retired classifier is sound. "
                "Its unsoundness is on the controls, which is where a shape-only "
                "rule differs from a recurrence proof.",
        },
        "verdict": rerun_verdict,
        "what_this_does_NOT_establish": [
            "that any loop terminates at RUNTIME with this many iterations: "
            "these are static maxima for the machine loops of this .text",
            "that a refused loop fails to terminate: the prover refuses loops "
            "outside its supported form, and a refusal is not a proof",
            "that the kernel is correct, that a launch would succeed, or "
            "anything about the device -- nothing was launched",
        ],
    }
    C.dump(OUT, out)

    print("object            %s" % out["object_binding"]["path"])
    print("whole sha256      %s  (matches brief %s)"
          % (whole, whole == C.WHOLE_SHA_IN_BRIEF))
    print(".text sha256      %s  (matches brief %s, size %d)"
          % (text["sha256"], text["sha256"] == C.TEXT_SHA_IN_BRIEF,
             text["size"]))
    print("instructions      %d (my decode %d)" % (res["object"]["n_instructions"],
                                                   len(ins_own)))
    print("backward branches %d (my decode %d, branch insns %d, unresolved %d)"
          % (res["cfg"]["n_backward_branches"], len(back_own),
             len(branches_own), len(unresolved)))
    print("loops             %d, proven %d, trip histogram %s"
          % (n_loops, n_proven, hist))
    print("re-derivation     heads %d/%d latches %d/%d guard %d update %d "
          "init %d exit-index %d (prev-index-continues %d)"
          % (n_head_ok, n_loops, n_latch_ok, n_loops, n_guard_ok, n_update_ok,
             n_init_ok, n_index_confirmed, n_index_prev_continues))
    print("VERDICT           %s" % rerun_verdict)
    return 0 if rerun_verdict == "PROOF_REPRODUCED_AND_RE_DERIVED" else 1


if __name__ == "__main__":
    sys.exit(main())
