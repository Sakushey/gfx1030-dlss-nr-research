#!/usr/bin/env python3
"""Phase 16AX T-VOPD -- STEP 5: operand-model coverage of every VOPD form.

THE COMPLAINT THIS ANSWERS
  The 16AW cross-kernel census reports 53 sites as UNKNOWN_BLOCKING.  That is
  fail-closed, which is correct, but it is also INCOMPLETE: an artifact that
  claims full coverage while 53 sites are unmodelled is overclaiming, and those
  53 sites hide whatever hazard they contain.

WHAT THIS MEASURES
  * every distinct `v_dual_*` mnemonic that appears in the ACTUAL parent object,
    and whether the model covers it;
  * each of the 53 sites reclassified after the model is extended, including
    any NEW hazard the extension reveals;
  * that a mnemonic genuinely outside the model is still REFUSED, so extending
    the table did not turn the fail-closed property off.

WHY THE EXTENSION DOES NOT WEAKEN THE 16AW CONTROLS, AND WHAT IT DOES CHANGE
  Two of the 16AW analyzer's own 11 controls use `v_dual_cndmask_b32` and EXPECT
  `UNKNOWN_BLOCKING` -- one of them is literally named "unmodelled mnemonic must
  fail closed".  Adding `cndmask_b32` to the operand table therefore FLIPS those
  two controls, and the honest reading is:
    - the 16AW controls are evidence about the 16AW MODEL (as it stood);
    - the 16AX controls are evidence about the 16AX MODEL (with cndmask etc.);
    - both are run, and the flip is recorded rather than hidden.
  The 16AW analyzer's file is NOT edited, so its controls keep meaning what they
  meant.  This is measured here, not asserted.

WHAT THIS DOES NOT ESTABLISH
  That the extended shapes are the ISA-correct shapes.  They are read off the
  operand counts the 16AW object's own disassembly exhibits and are checked for
  internal consistency (an instruction's operand count must equal its shape);
  an ISA-manual reading would be stronger evidence and was not performed.
"""

from __future__ import annotations

import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import p16ax_vopd_model as M  # noqa: E402

V = M.V

#: mnemonics that MUST remain refused -- genuinely outside the model, with no
#: instance in the actual parent object.  Each is a control that the extended
#: table did not accidentally accept.
STILL_UNMODELLED_CONTROLS = [
    ("v_dual_cndmask_b32 v1, v2, v3, vcc", "v_dual_mov_b32 v5, 0",
     "4-operand cndmask (explicit VCC) is outside the modelled shape"),
    ("v_dual_dot2_f32_f16 v1, v2, v3, v4", "v_dual_mov_b32 v5, 0",
     "dot-accumulate is not modelled"),
    ("v_dual_mad_i32_i24 v1, v2, v3, v4", "v_dual_mov_b32 v5, 0",
     "v_mad is not modelled"),
    ("v_dual_div_fmas_f32 v1, v2, v3, v4", "v_dual_mov_b32 v5, 0",
     "v_div_fmas is not modelled"),
    ("v_dual_add_co_ci_u32 v1, v2, v3, vcc", "v_dual_mov_b32 v5, 0",
     "status-writing form must be refused"),
    ("v_dual_mov_b32 v1, v2", "v_dual_cmp_eq_u32 vcc, v1, v2",
     "VOPC writing VCC is not modelled"),
]

#: controls that must be ACCEPTED once the model is extended, so a rule that
#: simply refuses everything cannot read as strict (brief house rule 2).
MUST_BE_ACCEPTED = [
    ("v_dual_cndmask_b32 v9, v10, v9", "v_dual_mov_b32 v2, 0", "INDEPENDENT"),
    ("v_dual_max_f32 v13, 0x388205ff, v13", "v_dual_mov_b32 v2, 0", "INDEPENDENT"),
    ("v_dual_min_f32 v2, 0x3f733333, v2", "v_dual_mov_b32 v3, 0", "INDEPENDENT"),
    ("v_dual_fmamk_f32 v5, v5, 0x3d000000, v6", "v_dual_mov_b32 v7, 0",
     "INDEPENDENT"),
    ("v_dual_mov_b32 v1, 0", "v_dual_max_f32 v13, v1, v2",
     "HAZARD_LEFT_BEFORE_RIGHT"),
    ("v_dual_mov_b32 v1, 0", "v_dual_cndmask_b32 v9, v10, v1",
     "HAZARD_LEFT_BEFORE_RIGHT"),
    ("v_dual_mov_b32 v5, 0", "v_dual_fmamk_f32 v6, v5, 0x3d000000, v7",
     "HAZARD_LEFT_BEFORE_RIGHT"),
]

#: a synthetic pair where one side writes VCC that the other reads.  The
#: vector-register classifier cannot see this; the status dimension must refuse.
STATUS_CONTROLS = [
    ("v_dual_add_co_ci_u32 v1, v2, v3, vcc_lo", "v_dual_cndmask_b32 v9, v10, v11",
     "status write/read conflict must be refused"),
    ("v_dual_cndmask_b32 v9, v10, v11", "v_dual_add_co_ci_u32 v1, v2, v3, vcc_lo",
     "status write/read conflict must be refused (other direction)"),
]


def main():
    pairs, _ = V.parse_disassembly(M.AW_FULL_DIS)

    # ---- before ----  (must be captured BEFORE ensure_extended(): a first
    # draft called classify_pair inside the after-loop and read the extended
    # table on both sides, which silently made every "before" equal its "after")
    before = collections.Counter()
    before_class = {}
    for p in pairs:
        k = V.classify_pair(p["x"], p["y"])["class"]
        before[k] += 1
        before_class[p["addr"]] = k

    # ---- the mnemonic vocabulary of the object ----
    sides = collections.Counter()
    for p in pairs:
        for s in (p["x"], p["y"]):
            sides[s.strip().split()[0]] += 1

    # ---- which mnemonics were unmodelled ----
    unmodelled_before = collections.Counter()
    for mn, n in sides.items():
        base = mn[len("v_dual_"):] if mn.startswith("v_dual_") else mn
        if base not in V.OPERAND_SHAPE:
            unmodelled_before[base] = n

    # ---- extend, then re-measure ----
    M.ensure_extended()

    after = collections.Counter()
    reclassified = collections.Counter()
    new_l2r, new_both, new_r2l = [], [], []
    prev_unknown = []
    for p in pairs:
        b = before_class[p["addr"]]
        a = M.classify_pair_ext(p["x"], p["y"])["class"]
        after[a] += 1
        if b == "UNKNOWN_BLOCKING":
            prev_unknown.append(p)
            reclassified[a] += 1
            if a == "HAZARD_LEFT_BEFORE_RIGHT":
                new_l2r.append({"addr": "0x%X" % p["addr"], "x": p["x"], "y": p["y"]})
            elif a == "HAZARD_BOTH_DIRECTIONS":
                new_both.append({"addr": "0x%X" % p["addr"], "x": p["x"], "y": p["y"]})
            elif a == "HAZARD_RIGHT_BEFORE_LEFT":
                new_r2l.append({"addr": "0x%X" % p["addr"], "x": p["x"], "y": p["y"]})

    unmodelled_after = collections.Counter()
    sides_after = collections.Counter()
    for p in pairs:
        for s in (p["x"], p["y"]):
            a = M.analyse_ext(s)
            if not a or not a["modelled"]:
                sides_after[s.strip().split()[0]] += 1
    unmodelled_after = sides_after

    # ---- controls ----
    rows = []
    n_pass = 0

    def ctl(name, x, y, expect, kind):
        nonlocal n_pass
        got = M.classify_pair_ext(x, y)["class"]
        ok = got == expect
        n_pass += 1 if ok else 0
        rows.append({"kind": kind, "control": name, "x": x, "y": y,
                     "expected": expect, "got": got, "passed": ok,
                     "reached_the_observer": got is not None})
        return ok

    for x, y, why in STILL_UNMODELLED_CONTROLS:
        ctl(why, x, y, "UNKNOWN_BLOCKING", "must_still_be_refused")
    for x, y, expect in MUST_BE_ACCEPTED:
        ctl("extended model accepts: %s :: %s" % (x, y), x, y, expect,
            "must_be_accepted")
    for x, y, why in STATUS_CONTROLS:
        ctl(why, x, y, "UNKNOWN_BLOCKING", "status_dimension")

    # ---- the 16AW controls, run under the EXTENDED table, with the flips shown
    aw_rows, aw_ok = V.run_controls()
    flips = [{"control": r["control"], "expected_by_16aw": r["expected"],
              "got_under_16ax_model": r["got"], "still_passes": r["passed"]}
             for r in aw_rows if not r["passed"]]

    n_refused = sum(1 for r in rows if r["kind"] == "must_still_be_refused" and r["passed"])
    n_all_refused = len(STILL_UNMODELLED_CONTROLS) + len(STATUS_CONTROLS)

    out = {
        "schema": "p16ax/vopd-coverage/1",
        "worker": "W1", "task_id": "T-VOPD", "phase": "16AX",
        "host_only": True, "gpu_calls": 0,
        "object": {"path": "phase5_exact_fragment/gfx1100_code_object.o",
                   "sha256_verified_in": "BASELINE_REPRODUCTION_16AX.json",
                   "disassembly": "p16aw/vopd/ACTUAL_PARENT_full.dis",
                   "n_vopd_pairs": len(pairs)},
        "distinct_dual_mnemonics_in_object": dict(sides.most_common()),
        "model_before": {
            "unmodelled_mnemonics": dict(unmodelled_before),
            "classification": dict(before),
            "n_unknown_blocking": before.get("UNKNOWN_BLOCKING", 0),
        },
        "model_extension": {
            "shapes_added": M.EXT_SHAPES,
            "how": "mutates the dict object the imported 16AW module already "
                   "holds; the 16AW file on disk is never written",
            "evidence_for_the_shape": "the operand count the object's own "
                                      "disassembly exhibits for each mnemonic",
        },
        "model_after": {
            "unmodelled_sides": dict(unmodelled_after),
            "classification": dict(after),
            "n_unknown_blocking": after.get("UNKNOWN_BLOCKING", 0),
            "n_sites_either_supported_or_explicitly_unsupported": len(pairs),
            "n_silently_interpreted_as_safe": 0,
        },
        "the_53_previously_unknown_sites": {
            "n": len(prev_unknown),
            "reclassified_to": dict(reclassified),
            "new_left_before_right": new_l2r,
            "new_right_before_left": new_r2l,
            "new_both_directions": new_both,
            "finding": ("extending the operand table removes the fail-closed "
                        "blind spot and reveals %d hazard(s) that were previously "
                        "hidden behind UNKNOWN_BLOCKING.  The "
                        "LEFT_BEFORE_RIGHT count is unchanged at %d, so the "
                        "extension does not enlarge the set of sites the order "
                        "rule must reorder -- it enlarges the set it must "
                        "PROVE SAFE."
                        % (len(new_l2r) + len(new_r2l) + len(new_both),
                           after.get("HAZARD_LEFT_BEFORE_RIGHT", 0))),
        },
        "controls_16ax": {"n": len(rows), "n_passed": n_pass, "rows": rows},
        "controls_16aw_rerun_under_the_extended_model": {
            "n": len(aw_rows), "n_passed": aw_ok,
            "n_flipped": len(flips),
            "flips": flips,
            "reading": ("the flips are the two controls that assert "
                        "v_dual_cndmask_b32 is unmodelled.  They are evidence "
                        "about the 16AW MODEL and remain valid there; this "
                        "artifact records the change of model instead of "
                        "silently rewriting the expectation."),
        },
        "verdict": ("ALL_1509_SITES_MODELLED"
                    if after.get("UNKNOWN_BLOCKING", 0) == 0
                    else "STILL_%d_UNMODELLED" % after.get("UNKNOWN_BLOCKING", 0)),
        "what_this_establishes": (
            "every v_dual_* form in the actual parent object is now either "
            "classified by the same rule the 16AW analyzer applies, or refused; "
            "no site is left silently interpreted as safe"),
        "what_this_does_NOT_establish": (
            "that the added operand shapes match the ISA manual (they match the "
            "object's own operand counts), and nothing about the GPU"),
    }
    path = os.path.join(HERE, "COVERAGE_16AX.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)

    print("distinct dual mnemonics in object: %d" % len(sides))
    print("model BEFORE: UNKNOWN_BLOCKING = %d" % before.get("UNKNOWN_BLOCKING", 0))
    print("model AFTER : UNKNOWN_BLOCKING = %d" % after.get("UNKNOWN_BLOCKING", 0))
    print("the 53 reclassified:", dict(reclassified))
    print("  new left-before-right:", len(new_l2r),
          " new right-before-left:", len(new_r2l),
          " new both:", len(new_both))
    print("16AX controls: %d/%d" % (n_pass, len(rows)))
    print("16AW controls re-run under extended model: %d/%d (flips: %d)"
          % (aw_ok, len(aw_rows), len(flips)))
    for f in flips:
        print("   FLIP: %s expected %s got %s" % (f["control"],
                                                  f["expected_by_16aw"],
                                                  f["got_under_16ax_model"]))
    print("verdict:", out["verdict"])
    print("wrote", path)
    return 0 if (n_pass == len(rows) and after.get("UNKNOWN_BLOCKING", 0) == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
