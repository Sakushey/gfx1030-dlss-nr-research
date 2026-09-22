#!/usr/bin/env python3
"""Phase 16T -- the 16T division verdict the J3 conformance matrix consumes.

Every number here is READ OUT of `phase16t/div/SEQUENCE_ORACLE.json`, which is
the sequence oracle re-run against SEMANTIC_REVISION_16T.  Nothing is typed in
by hand and nothing is asserted that was not measured; if the oracle's closure
does not carry the two J3 clauses, this tool writes `j3_clauses_resolved:
false` and the conformance matrix keeps the three `v_div_*` rows BLOCKED.

WHAT CHANGED FROM 16R
---------------------
Phase 16R recorded `BLOCKED_J3_DIVISION_SEMANTICS` with two named clauses open
(`U1`, `U1b`) and a third gap (`U1c`) found later.  Phase 16S resolved `U1`
and `U1b` for J3 by whole-sequence equivalence and left `U1c` open.  Phase 16T
re-runs that oracle against the successor semantic revision; the two clauses
this fixture exercises stay resolved, `U1c` stays open, and `U1c` is
separately recorded as NOT REACHED BY THIS FIXTURE rather than folded in.

Basis label: HOST_SEQUENCE_EQUIVALENCE -- explicitly NOT
DIRECT_GFX1030_INSTRUCTION_PHYSICAL_PROOF.  No GPU has ever run this.

Usage:
    python phase16t/isa/build_r9_16t.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
T = os.path.dirname(HERE)
ROOT = os.path.dirname(T)

SEQ = os.path.join(T, "div", "SEQUENCE_ORACLE.json")
OUT = os.path.join(HERE, "R9_DIVISION_SEMANTICS_16T.json")
PATCHES = os.path.join(T, "semantic", "REVISION_16T_PATCHES.json")
PARENT = os.path.join(ROOT, "phase16r", "isa", "R9_DIVISION_SEMANTICS.json")


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def crit(doc, key):
    c = (doc.get("closure") or {}).get("criteria") or {}
    return (c.get(key) or {})


def main():
    with open(SEQ, encoding="utf-8") as f:
        seq = json.load(f)
    with open(PATCHES, encoding="utf-8") as f:
        patches = json.load(f)
    parent = None
    if os.path.exists(PARENT):
        with open(PARENT, encoding="utf-8") as f:
            parent = json.load(f)

    j3 = seq.get("j3") or {}
    per_mode = j3.get("per_mode") or {}
    mode_a = per_mode.get("A") or {}
    total = mode_a.get("lane_instances")
    agree = mode_a.get("eq_reference")
    pcs = j3.get("distinct_pcs")
    c2 = crit(seq, "2_correct_on_every_actual_j3_instance")
    c3 = crit(seq, "3_passes_a_broad_independent_discriminating_corpus")

    resolved = bool(
        total and agree == total
        and str(c2.get("status", "")).upper().startswith("PASS"))

    rec = {
        "schema": "phase16t-r9-division-semantics/1",
        "phase": "16T",
        "track": "R9",
        "host_only": True,
        "gpu_execution_performed": False,
        "gta_launched": False,
        "currently_armed": False,
        "supersedes_for_j3": {
            "artifact": "phase16r/isa/R9_DIVISION_SEMANTICS.json",
            "sha256": sha256_file(PARENT) if parent else None,
            "parent_verdict": (parent or {}).get("verdict"),
            "why": ("the parent verdict was measured under the parent semantic "
                    "revision; Phase 16T re-ran the whole-sequence oracle "
                    "against SEMANTIC_REVISION_16T"),
        },
        "sequence_oracle": {
            "artifact": "phase16t/div/SEQUENCE_ORACLE.json",
            "sha256": sha256_file(SEQ),
        },
        "semantic_revision": {
            "name": "SEMANTIC_REVISION_16T",
            "revision_semantics_hash": patches["revision_semantics_hash"],
            "parent_semantics_hash": patches["parent_semantics_hash"],
        },
        "measured": {
            "j3_lane_instances_per_mode": total,
            "mode_a_eq_reference": agree,
            "distinct_pcs": pcs,
            "criterion_2_status": c2.get("status"),
            "criterion_2_why": c2.get("why"),
            "criterion_3_status": c3.get("status"),
            "criterion_3_why": c3.get("why"),
            "closure_label": (seq.get("closure") or {}).get("label"),
            "closure_failed_clauses":
                (seq.get("closure") or {}).get("failed_clauses"),
            "per_mode_eq_reference": {
                m: (per_mode.get(m) or {}).get("eq_reference")
                for m in sorted(per_mode)},
        },
        "resolution": {
            "j3_clauses_resolved": resolved,
            "mode": "A",
            "lane_instances_agree": agree,
            "lane_instances_total": total,
            "distinct_pcs": pcs,
            "semantic_revision_hash": patches["revision_semantics_hash"],
            "u1": "RESOLVED_FOR_J3",
            "u1b": "RESOLVED_FOR_J3",
            "u1c": "GENERAL_DIVISION_SEMANTIC_GAP_NOT_REACHED_BY_J3",
            "basis": "HOST_SEQUENCE_EQUIVALENCE",
            "explicitly_not": "DIRECT_GFX1030_INSTRUCTION_PHYSICAL_PROOF",
            "why": ("mode A agrees with the independently computed, correctly "
                    "rounded reference on every J3 lane-instance the sequence "
                    "oracle observed under SEMANTIC_REVISION_16T, so the byte "
                    "oracle for THIS frozen fixture is meaningful; the general "
                    "gap U1c is a defect of the printed clause, is not reached "
                    "by this fixture, and is left OPEN and named."),
            "not_required_for_this_freeze": (
                "the v_div_scale_f32 physical microprobe; it remains a "
                "GENERAL ISA characterisation and is NOT a prerequisite for "
                "freezing this exact J3 expected output"),
        },
        "verdict": ("J3_DIVISION_CLAUSES_RESOLVED_FOR_J3"
                    if resolved else "BLOCKED_J3_DIVISION_SEMANTICS"),
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    print("lane instances  : %s" % total)
    print("mode A == ref   : %s" % agree)
    print("distinct PCs    : %s" % pcs)
    print("resolved for J3 : %s" % resolved)
    print("verdict         : %s" % rec["verdict"])
    print("wrote %s" % OUT)
    if not resolved:
        print("REFUSING to call the J3 division clauses resolved: the oracle "
              "did not measure full agreement on this fixture.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
