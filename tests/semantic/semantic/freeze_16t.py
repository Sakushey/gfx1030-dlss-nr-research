#!/usr/bin/env python3
"""Phase 16T -- create SEMANTIC_FREEZE_16T, the successor semantic revision.

RULES THIS TOOL ENFORCES
------------------------
* The Phase 16O freeze is NOT renamed, edited or replaced.  Its artifact and
  the live source tree it hashes are both left exactly as they were; this tool
  only READS them.
* The successor's identity is the hash over the 13 frozen source paths with
  the two edited modules taken from the revision tree and the other 11 from
  the live tree -- the same identity `a_run_rev.py` builds, so a revision
  result and this freeze name the same bytes.
* The freeze REFUSES unless every required gate artefact exists and carries
  the value it must.  A missing gate is not a pass.
* The freeze is called `SEMANTIC_FREEZE_16T`, not FINAL.  Nothing in this
  phase may call the semantic set final: no physical execution has happened.

Usage:
    python phase16t/semantic/freeze_16t.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
T = os.path.dirname(HERE)
ROOT = os.path.dirname(T)
REV = os.path.join(HERE, "revision_16t")

PARENT_FREEZE = os.path.join(ROOT, "phase16o_final",
                             "C_SEMANTIC_FREEZE_FINAL.json")
OUT = os.path.join(HERE, "SEMANTIC_FREEZE_16T.json")
PATCHES = os.path.join(HERE, "REVISION_16T_PATCHES.json")

CAND = "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co"
CAND_SHA = "47b5d1d11041b034ac30eebac090ee922f415d8f08a0111e69641d7e0557524b"

#: gate artefact -> (predicate description, predicate)
GATES = {
    "phase16t/isa/MUTATION_CONTROLS_16T.json":
        ("every known-bad mutation of a repaired handler is rejected and both "
         "non-detecting controls are inert",
         lambda d: d.get("verdict") == "PASS"
         and d["n_detecting_rejected"] == d["n_detecting"]
         and d["n_nondetecting_inert"] == d["n_nondetecting_controls"]),
    "phase16t/isa/J3_INSTRUCTION_CONFORMANCE_16T.json":
        ("J3_INSTRUCTION_SEMANTICS_BLOCKED == 0",
         lambda d: d.get("J3_INSTRUCTION_SEMANTICS_BLOCKED") == 0),
    "phase16t/j3/R7_MEMORY_FIXED_POINT_16T.json":
        ("the six memory-fixed-point criteria the brief names all pass under "
         "the new semantics (a companion evaluated on named fields; the R7 "
         "run's own summary verdict and its stale candidate list are carried "
         "verbatim inside it)",
         lambda d: d.get("verdict") == "PASS" and d.get("n_failures") == 0),
    "phase16t/j3/J3_V2_EXPECTED_OUTPUT.json":
        ("a frozen expected output exists and is FROZEN",
         lambda d: d.get("status") == "FROZEN"),
    "phase16t/isa/R9_DIVISION_SEMANTICS_16T.json":
        ("the J3 division clauses are resolved for this fixture",
         lambda d: d["resolution"]["j3_clauses_resolved"] is True),
    "phase16t/div/SEQUENCE_ORACLE.json":
        ("the sequence oracle criterion 2 passes",
         lambda d: str(((d.get("closure") or {}).get("criteria") or {})
                       .get("2_correct_on_every_actual_j3_instance", {})
                       .get("status", "")).upper().startswith("PASS")),
}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    with open(PARENT_FREEZE, encoding="utf-8") as f:
        parent = json.load(f)
    with open(PATCHES, encoding="utf-8") as f:
        patches = json.load(f)

    # -- the parent freeze must still be literally true on disk ------------
    live = parent["semantics_sources"]
    drift = []
    for rel, want in live.items():
        p = os.path.join(ROOT, rel.replace("/", os.sep))
        got = sha256_file(p) if os.path.exists(p) else None
        if got != want:
            drift.append({"source": rel, "frozen": want, "now": got})
    if drift:
        print("STOP: the LIVE tree no longer matches the parent freeze.")
        print(json.dumps(drift, indent=1))
        print("The 16T revision must be built as a separate source tree; the "
              "live tree must keep hashing to the parent.")
        return 2
    print("parent freeze : %s  (live tree still matches all %d sources)"
          % (parent["semantics_hash"][:16], len(live)))

    # -- every gate ---------------------------------------------------------
    gates = {}
    bad = []
    for rel, (why, pred) in GATES.items():
        p = os.path.join(ROOT, rel.replace("/", os.sep))
        if not os.path.exists(p):
            gates[rel] = {"why": why, "status": "MISSING"}
            bad.append("%s MISSING" % rel)
            print("   MISSING  %s" % rel)
            continue
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        ok = bool(pred(d))
        gates[rel] = {"why": why, "status": "PASS" if ok else "FAIL",
                      "sha256": sha256_file(p)}
        print("   %-7s %s" % ("PASS" if ok else "FAIL", rel))
        if not ok:
            bad.append("%s FAIL" % rel)
    if bad:
        print("\nREFUSING to freeze: %s" % "; ".join(bad))
        return 3

    # -- identity -----------------------------------------------------------
    sources = {}
    for rel in sorted(live):
        base = os.path.basename(rel)
        revp = os.path.join(REV, base)
        if os.path.exists(revp) and base in ("emu.py", "p14d8_core.py"):
            sources[rel] = {"sha256": sha256_file(revp),
                            "from": "phase16t/semantic/revision_16t/" + base}
        else:
            sources[rel] = {"sha256": sha256_file(
                os.path.join(ROOT, rel.replace("/", os.sep))),
                "from": rel}

    h = hashlib.sha256()
    for rel in sorted(live):
        h.update(rel.encode())
        h.update(b"\0")
        h.update(sources[rel]["sha256"].encode())
        h.update(b"\n")
    rev_hash = h.hexdigest()
    if rev_hash != patches["revision_semantics_hash"]:
        print("STOP: the identity recomputed here (%s) is not the revision "
              "tree's recorded identity (%s)"
              % (rev_hash, patches["revision_semantics_hash"]))
        return 4
    print("\nrevision hash : %s  (matches the revision tree's own record)"
          % rev_hash)

    cand = os.path.join(ROOT, CAND)
    if sha256_file(cand) != CAND_SHA:
        print("STOP: Candidate F is not the frozen candidate")
        return 5

    rec = {
        "schema": "phase16t-semantic-freeze/1", "phase": "16T",
        "name": "SEMANTIC_FREEZE_16T",
        "why_not_final": ("no physical execution has occurred; the Phase 16T "
                          "brief forbids calling the semantic set FINAL "
                          "before the physical gates pass"),
        "host_only": True, "gpu_execution_performed": False,
        "gta_launched": False, "currently_armed": False,
        "parent": {"artifact": "phase16o_final/C_SEMANTIC_FREEZE_FINAL.json",
                   "semantics_hash": parent["semantics_hash"],
                   "still_true_on_disk": True},
        "semantics_hash": rev_hash,
        "revision_name": "SEMANTIC_REVISION_16T",
        "revision_tree": "phase16t/semantic/revision_16t",
        "n_sources": len(sources),
        "semantics_sources": sources,
        "candidate_co": CAND, "candidate_sha256": CAND_SHA,
        "candidate_changed": False,
        "is_candidate_g": False,
        "edits": patches["edits"],
        "n_edits": patches["n_edits"],
        "gates": gates,
        "oracle_hashes": {
            "phase16s/isa/ISA_ORACLE_16.json":
                sha256_file(os.path.join(ROOT, "phase16s", "isa",
                                         "ISA_ORACLE_16.json")),
            "phase16t/isa/ISA_ORACLE_16T.json":
                sha256_file(os.path.join(T, "isa", "ISA_ORACLE_16T.json")),
            "phase16t/isa/MUTATION_CONTROLS_16T.json":
                gates["phase16t/isa/MUTATION_CONTROLS_16T.json"]["sha256"],
        },
        "j3_conformance_hash":
            gates["phase16t/isa/J3_INSTRUCTION_CONFORMANCE_16T.json"]["sha256"],
        "memory_fixed_point_revalidation_hash":
            gates["phase16t/j3/R7_MEMORY_FIXED_POINT_16T.json"]["sha256"],
        "memory_fixed_point_run_hash":
            sha256_file(os.path.join(T, "j3", "out",
                                     "R7_MEMORY_FIXED_POINT.json")),
        "load_bearing_hash":
            sha256_file(os.path.join(T, "j3", "LOAD_BEARING_16T.json")),
        "expected_output_hash":
            gates["phase16t/j3/J3_V2_EXPECTED_OUTPUT.json"]["sha256"],
        "five_swin_matrix_hash": None,
        "five_swin_matrix_status":
            "MEASURED SEPARATELY; see phase16t/swin/FINAL_SWIN_MATRIX_16T.json "
            "when present.  A missing SWIN matrix does not gate the J3 freeze "
            "and is NOT recorded as a pass here.",
        "verify_command":
            "python phase16t/semantic/freeze_16t.py --verify",
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    print("wrote %s" % OUT)
    print("sha256 %s" % sha256_file(OUT))
    print("candidate %s (byte-unchanged)" % CAND_SHA[:16])
    return 0


def verify():
    """`--verify`: recompute every hash in the freeze from disk, live."""
    if not os.path.exists(OUT):
        print("no freeze at %s" % OUT)
        return 2
    with open(OUT, encoding="utf-8") as f:
        rec = json.load(f)
    problems = []
    for rel, info in rec["semantics_sources"].items():
        p = os.path.join(ROOT, info["from"].replace("/", os.sep))
        if not os.path.exists(p):
            problems.append("missing %s" % info["from"])
            continue
        got = sha256_file(p)
        if got != info["sha256"]:
            problems.append("%s: frozen %s now %s"
                            % (info["from"], info["sha256"][:16], got[:16]))
    for rel, info in rec["gates"].items():
        p = os.path.join(ROOT, rel.replace("/", os.sep))
        if info.get("sha256") and sha256_file(p) != info["sha256"]:
            problems.append("gate moved: %s" % rel)
    if sha256_file(os.path.join(ROOT, CAND)) != rec["candidate_sha256"]:
        problems.append("Candidate F moved")
    print("verified %d sources, %d gates" % (len(rec["semantics_sources"]),
                                             len(rec["gates"])))
    print("semantics hash %s" % rec["semantics_hash"])
    if problems:
        print("VERDICT: SEMANTIC_FREEZE_16T_MUTATED")
        for p in problems:
            print("   %s" % p)
        return 1
    print("VERDICT: SEMANTIC_FREEZE_16T_INTACT")
    return 0


if __name__ == "__main__":
    if "--verify" in sys.argv[1:]:
        sys.exit(verify())
    sys.exit(main())
