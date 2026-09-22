#!/usr/bin/env python3
"""Phase 16AW -- reproduce the audit's unsoundness finding against the OLD code.

Brief PART X, section 74.

WHAT THIS SCRIPT IS
    A claim about code is reproduced by RUNNING THAT CODE.  `p16aw_old_classifier`
    slices the finite-bound classifier out of
    `p16at/native/p16at_machine_cfg.py` by byte marker, hashes the slice, and
    exec()s it; this script does three things with it and nothing else:

      1  states EXACTLY how the finite bound is assigned, quoting the two
         decisive lines as they are found in the slice's own bytes -- the quote
         is extracted, never retyped;
      2  VALIDATES THE HARNESS on the known-good case: re-running the retired
         classifier over the archived Slot-5 object must reproduce the numbers
         already published in the 16AT evidence.  A harness that cannot
         reproduce the case that was accepted cannot be trusted to reproduce the
         case that is refused, and this project has shipped a "reproduction"
         that was really a paraphrase;
      3  runs the audit's regression (brief section 74) and measures whether the
         retired classifier assigns a finite bound, and a PASS, to a loop that
         cannot terminate.

THE AUDIT'S CLAIM, IN ONE LINE
    the verdict is chosen from the SHAPE of an instruction (an immediate
    add/sub whose DESTINATION is the register the guard compares); the step is
    read only to compute a bound, never to choose the verdict, so a zero step
    yields COUNTED_LOOP_WITH_STATIC_BOUND with max_trip_count None.

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

sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "p16at", "native"))
import p16aw_old_classifier as OLD            # noqa: E402
import p16aw_prover_controls as C             # noqa: E402
import p16aw_loop_recurrence_prover as P      # noqa: E402

#: the archived 16AT evidence the harness is validated against
MACHINE_CFG_JSON = os.path.join(ROOT, "p16at", "native", "liveness",
                                "MACHINE_CFG.json")

#: the downstream gate that consumes the verdict.  Both expressions are pulled
#: out of the file's own bytes below; these literals only locate them.
GATE_FILE = os.path.join(ROOT, "p16at", "native",
                         "p16at_loop_mapping.py")
GATE_VERDICT_RE = (r"^(\s*unknown_term = \[m for m in mapped\n(?:.*\n){0,3}?"
                   r".*COUNTED_LOOP_WITH_STATIC_BOUND\"\])$")
GATE_ACCEPT_RE = (r'^(\s*"every_machine_loop_is_a_counted_loop_with_a_static_'
                  r'bound":\n\s*len\(unknown_term\) == 0,)$')


def quote(path, pattern, label):
    """One or more lines of `path`, located by `pattern` and returned verbatim.

    If the pattern is not found the caller FAILS rather than quoting from
    memory: a quote that is not in the file is not evidence about the file.
    """
    text = open(path, encoding="utf-8").read()
    m = re.search(pattern, text, re.M)
    if not m:
        return None, {"label": label, "found": False,
                      "file": os.path.relpath(path, ROOT).replace("\\", "/"),
                      "pattern": pattern}
    line_no = text[:m.start(1)].count("\n") + 1
    body = m.group(1)
    return {"label": label, "found": True,
            "file": os.path.relpath(path, ROOT).replace("\\", "/"),
            "file_sha256": hashlib.sha256(
                open(path, "rb").read()).hexdigest(),
            "first_line_1_indexed": line_no,
            "n_lines": body.count("\n") + 1,
            "text": body}, None


def main() -> int:
    out = {"schema": "p16aw/unsoundness-reproduction/1",
           "phase": "16AW", "brief_sections": [71, 74],
           "question": "does the retired finite-bound classifier assign a "
                       "finite bound, and a PASS, to a loop that cannot "
                       "terminate?"}

    # ---- 1. exactly how the bound is assigned ---------------------------
    _, meta = OLD.extract_slice()
    slice_text = open(OLD.OLD_SOURCE, encoding="utf-8").read().split("\n")[
        meta["first_line_1_indexed"] - 1:meta["last_line_1_indexed"]]
    joined = "\n".join(slice_text)
    verdict_q, e1 = quote(OLD.OLD_SOURCE,
                          r"^(\s*\"verdict\": \(\"COUNTED_LOOP_WITH_STATIC_BOUND\""
                          r".*\n.*)$", "the line that CHOOSES the verdict")
    bound_q, e2 = quote(OLD.OLD_SOURCE,
                        r"^(\s*\"max_trip_count\": \(None.*\n.*)$",
                        "the line that COMPUTES the bound")
    step_q, e3 = quote(OLD.OLD_SOURCE,
                       r"^(\s*mm = re\.match\(r\"\^s_\(\?:add\|addk\|sub\)_\("
                       r"\?:i32\|u32\)\\s\+\(\\w\+\),.*\n.*\n.*\n.*)$",
                       "the pattern that decides what counts as an advance")
    #: the DESTINATION-only match: the source operand is matched by `\w+` and
    #: then DISCARDED, so nothing ever reads it.
    dest_only = bool(re.search(r"s_\(\?:add\|addk\|sub\)_\("
                               r"\?:i32\|u32\)\\s\+\(\\w\+\),\\s\*\\w\+,", joined))
    out["1_how_the_finite_bound_is_currently_assigned"] = {
        "the_retired_slice": meta,
        "quoted_lines": [q for q in (step_q, verdict_q, bound_q) if q],
        "quote_failures": [e for e in (e1, e2, e3) if e],
        "read_off_the_quotes": {
            "the_verdict_is_chosen_by": "whether `steps` is NON-EMPTY. `steps` "
                "is every instruction in the loop's blocks matching "
                "`s_(add|addk|sub)_(i32|u32) Rd, <anything>, <imm>` with "
                "Rd == the register the guard compares. Nothing else is "
                "consulted: not the step's value, not the source operand, not "
                "the direction of the step, not the guard's polarity, not the "
                "signedness, not the entry value, not reachability, not the "
                "modular wrap.",
            "the_step_is_read_only_to_compute_the_bound": "`max_trip_count` "
                "becomes None exactly when `steps[0][\"step\"] == 0`, and the "
                "VERDICT is not changed by that -- so the verdict and the bound "
                "can contradict each other inside one row",
            "the_source_operand_is_never_read": (
                "the regex captures the DESTINATION and discards the source "
                "(the operand pattern for the source is `\\w+` with no capture "
                "group); confirmed against the slice bytes: %s" % dest_only),
            "the_bound_is_computed_from": "the guard's compared immediate "
                "(`imm`), divided by the absolute value of the step -- not "
                "from the register's entry value, so the entry value never "
                "enters the bound",
            "which_advance_is_used": "`steps[0]`, the first one in block order, "
                "so with several writers the choice is arbitrary",
        },
    }

    # ---- 2. validate the harness on the known-good case -----------------
    obj = json.load(open(MACHINE_CFG_JSON, encoding="utf-8"))
    arch_loops = obj["loops"]
    arch_verdicts = [L["termination"]["verdict"] for L in arch_loops]
    arch_bounds = [L["termination"]["max_trip_count"] for L in arch_loops]
    import p16at_machine_cfg as M
    dis = M.disassemble(M.OBJDUMP_64, M.CO)
    ins, symbol_base = M.parse_disassembly(dis)
    rerun_rows, rerun_meta, rerun_err = OLD.run_old_classifier(ins, symbol_base)
    rerun_verdicts = ([] if rerun_rows is None else
                      [L["termination"]["verdict"] for L in rerun_rows])
    rerun_bounds = ([] if rerun_rows is None else
                    [L["termination"]["max_trip_count"] for L in rerun_rows])
    rerun_keys = ([] if rerun_rows is None else
                  [(L["termination"].get("induction_register"),
                    L["termination"].get("guard"),
                    L["termination"].get("bound")) for L in rerun_rows])
    arch_keys = [(L["termination"].get("induction_register"),
                  L["termination"].get("guard"),
                  L["termination"].get("bound")) for L in arch_loops]
    harness_ok = (rerun_rows is not None
                  and rerun_verdicts == arch_verdicts
                  and rerun_bounds == arch_bounds
                  and rerun_keys == arch_keys)
    out["2_harness_validation_on_the_known_good_case"] = {
        "why": "the regression below is only evidence if the same harness "
               "reproduces the case that was ACCEPTED. A harness that fails "
               "both sides of a question has measured nothing.",
        "archived_evidence": {
            "file": os.path.relpath(MACHINE_CFG_JSON, ROOT).replace("\\", "/"),
            "object": obj["object"],
            "n_loops": len(arch_loops),
            "n_counted_with_static_bound":
                len([v for v in arch_verdicts
                     if v == "COUNTED_LOOP_WITH_STATIC_BOUND"]),
            "max_trip_count_values": sorted(set(arch_bounds)),
        },
        "re_run_of_the_extracted_slice_over_the_same_object": {
            "slice_meta": rerun_meta, "error": rerun_err,
            "n_loops": len(rerun_rows or []),
            "verdicts": rerun_verdicts[:3] + (["..."] if
                                              len(rerun_verdicts) > 3 else []),
            "max_trip_count_values": sorted(set(rerun_bounds)),
        },
        "verdicts_identical": rerun_verdicts == arch_verdicts,
        "bounds_identical": rerun_bounds == arch_bounds,
        "guard_and_register_and_bound_identical": rerun_keys == arch_keys,
        "harness_validated": harness_ok,
        "n_loops_compared": len(arch_loops),
    }

    # ---- 3. the audit's regression --------------------------------------
    row = C.run_one("AUDIT_ZERO_STEP", C.AUDIT_REGRESSION)
    old_rows = row["retired_classifier"]["per_loop"] or []
    audit = old_rows[0] if old_rows else None
    term = (audit or {}).get("termination")
    retired_verdict = term.get("verdict") if isinstance(term, dict) else term
    retired_bound = (term or {}).get("max_trip_count") if \
        isinstance(term, dict) else None
    new_outcomes = row["loop_outcomes"]
    new_verdict = new_outcomes[0]["verdict"] if new_outcomes else "NO_LOOP_FOUND"
    fired = (new_outcomes[0]["the_requirement_that_fired"] or {}) if \
        new_outcomes else {}

    #: the downstream gate, quoted from its own file, evaluated on the audit's
    #: rows exactly as that file evaluates it: rows whose verdict is not
    #: COUNTED_LOOP_WITH_STATIC_BOUND
    gate_q, gate_e = quote(GATE_FILE, GATE_VERDICT_RE, "the gate's row filter")
    acc_q, acc_e = quote(GATE_FILE, GATE_ACCEPT_RE, "the gate's acceptance key")
    unknown_term = [L for L in old_rows
                    if (L.get("termination") or {}).get("verdict")
                    != "COUNTED_LOOP_WITH_STATIC_BOUND"]
    gate_value = (len(unknown_term) == 0)
    out["3_the_audit_regression"] = {
        "program_as_given_in_the_brief": [
            {"at": c["at"], "asm": c["requested"], "bytes": c["bytes"],
             "decoded_as": c["decoded"]}
            for c in row["decode_verification"]["decode_checks"]],
        "text_verified_by_decode": row["decode_verification"][
            "every_planted_word_decoded_to_the_requested_mnemonic"],
        "the_retired_classifier_says": {
            "verdict": retired_verdict,
            "max_trip_count": retired_bound,
            "induction_register": (term or {}).get("induction_register")
            if isinstance(term, dict) else None,
            "guard": (term or {}).get("guard") if isinstance(term, dict)
            else None,
            "advances_it_counted": (term or {}).get("advances")
            if isinstance(term, dict) else None,
        },
        "the_replacement_prover_says": {
            "verdict": new_verdict,
            "requirement_that_fired": fired.get("id"),
            "detail": fired.get("detail"),
        },
        "the_downstream_gate": {
            "why_it_is_here": "the audit's finding is not that a bound is "
                              "missing; it is that a missing bound PASSES. The "
                              "gate that consumes the verdict is quoted from "
                              "its own bytes and evaluated on these rows.",
            "row_filter_quote": gate_q, "acceptance_key_quote": acc_q,
            "quote_failures": [e for e in (gate_e, acc_e) if e],
            "rows_not_counted": len(unknown_term),
            "the_acceptance_key_evaluates_to": gate_value,
            "what_that_means": "a loop with max_trip_count None is NOT in the "
                               "rows the gate filters out, so the gate reports "
                               "`every machine loop is a counted loop with a "
                               "static bound` = True for a loop that has no "
                               "bound at all",
        },
        "audit_claim_reproduced": (retired_verdict
                                   == "COUNTED_LOOP_WITH_STATIC_BOUND"
                                   and retired_bound is None
                                   and gate_value is True
                                   and new_verdict != P.VERDICT_PROVEN),
        "no_max_trip_count_None_case_may_yield_PASS": {
            "measured_here": "the retired classifier yields PASS with None",
            "enforced_in_the_replacement": "the replacement prover never "
                "emits a verdict without a proven bound: it either proves "
                "R13 with a two-route-confirmed count, or returns UNKNOWN_BLOCKING",
            "n_loops_with_a_verdict_and_a_null_bound_in_the_replacement":
                len([r for r in P.prove_all(P.build_context(ins, symbol_base))
                     if r.get("max_trip_count") is None
                     and r["verdict"] == P.VERDICT_PROVEN]),
        },
    }

    # ---- 4. the other measured defects, from the controls ----------------
    controls_path = os.path.join(OUT, "LOOP_PROVER_CONTROLS_16AW.json")
    controls = json.load(open(controls_path, encoding="utf-8"))
    table = []
    for c in controls["controls"]:
        if c["id"] == "P7":
            continue
        old_bounds = c["retired_classifier"]["max_trip_counts"] or []
        old_verdicts = c["retired_classifier"]["verdicts"] or []
        if not old_verdicts:
            continue
        table.append({
            "control": c["id"], "kind": c["kind"], "title": c["title"],
            "retired_verdicts": old_verdicts,
            "retired_bounds": old_bounds,
            "replacement_verdicts": c["observed"]["verdicts"],
            "replacement_bound_or_refusal": (
                [o["max_trip_count"] for o in c["loop_outcomes"]]
                if c["kind"] == "positive" else
                [o["the_requirement_that_fired"]["id"]
                 for o in c["loop_outcomes"] if o["the_requirement_that_fired"]]),
            "the_two_disagree": c["the_two_classifiers_disagree"],
        })
    out["4_the_other_measured_defects"] = {
        "how_to_read_this": "every row is a program whose bytes were verified "
                            "by decode; the retired classifier's answer and the "
                            "replacement's are both on the same bytes",
        "n_rows": len(table),
        "n_rows_where_they_disagree": len([t for t in table
                                           if t["the_two_disagree"]]),
        "rows": table,
        "the_defects_visible_in_this_table": [
            "the bound comes from the guard's immediate, so an entry value "
            "carried in a register (N12, N13) gets a bound that the loop does "
            "not have",
            "the step's DIRECTION is ignored, so a countdown against an "
            "increment's predicate gets a bound of about 2**32 (N7)",
            "reachability is not checked, so a target the orbit never reaches "
            "gets a small bound (N6)",
            "the modular wrap is not modelled, so a wrapping orbit gets a bound "
            "smaller than the true count (N5)",
            "the guard's polarity and signedness are not read, so `x >= 0` "
            "unsigned and signed get the same answer of 0 although one never "
            "exits at all (N8u, N8i)",
            "the SOURCE operand is never read, so a loop that reloads the "
            "guard register from a dead register is certified as a counter "
            "(N2)",
        ],
    }
    out["verdict"] = ("UNSOUNDNESS_REPRODUCED"
                      if out["3_the_audit_regression"]["audit_claim_reproduced"]
                      and harness_ok else "NOT_REPRODUCED")
    out["what_remains_open"] = [
        "the reproduction is of the classifier as it stands in this tree; if "
        "that file is edited the slice hash recorded above changes and this "
        "reproduction must be re-run rather than cited",
        "no GPU, no kernel, no clock: this is a statement about a classifier "
        "and about a static analysis of an object file",
    ]
    with open(os.path.join(OUT, "UNSOUNDNESS_REPRODUCTION_16AW.json"), "w",
              encoding="utf-8") as f:
        json.dump(out, f, indent=1)

    print("slice                    lines %d-%d sha256 %s"
          % (meta["first_line_1_indexed"], meta["last_line_1_indexed"],
             meta["slice_sha256"][:16]))
    print("harness validation       the retired slice re-run over the archived "
          "object")
    print("  loops compared         %d" % len(arch_loops))
    print("  verdicts identical     %s" % (rerun_verdicts == arch_verdicts))
    print("  bounds identical       %s" % (rerun_bounds == arch_bounds))
    print("  harness validated      %s" % harness_ok)
    print("the audit's regression")
    print("  retired verdict        %s   bound %s"
          % (retired_verdict, retired_bound))
    print("  replacement verdict    %s   requirement %s"
          % (new_verdict, fired.get("id")))
    print("  gate rows not counted  %d   acceptance key evaluates to %s"
          % (len(unknown_term), gate_value))
    print("  audit claim reproduced %s"
          % out["3_the_audit_regression"]["audit_claim_reproduced"])
    print("other defects measured   %d rows, %d disagreements"
          % (out["4_the_other_measured_defects"]["n_rows"],
             out["4_the_other_measured_defects"]["n_rows_where_they_disagree"]))
    print("VERDICT                  %s" % out["verdict"])
    return 0 if out["verdict"] == "UNSOUNDNESS_REPRODUCED" else 1


if __name__ == "__main__":
    sys.exit(main())
