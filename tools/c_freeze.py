#!/usr/bin/env python3
"""Phase 16O Track C -- SEMANTIC_FREEZE_FINAL.

Pins every source file whose behaviour can change a dispatch result.  The
hash is computed, not declared, and it is the value every downstream
artefact (SWIN matrix, J3-V2 expected output, dependency slice) binds to.

A change to any pinned file invalidates every dependent artefact
automatically, because the execution cache key and every artefact record
carry this hash.

    python c_freeze.py            # write SEMANTIC_FREEZE_FINAL.json
    python c_freeze.py --verify   # re-hash and compare with what is on disk
"""
from __future__ import annotations
import argparse, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "phase16k_pretest", "k3_arena"))
sys.path.insert(0, os.path.join(ROOT, "phase16j_pre_gta", "tools"))
for p in ("phase16i_closure/tools", "phase16h_pcrel_fix/tools",
          "phase16e_candidate_e/tools", "phase14e_static/tools",
          "phase14eh_tools", "phase14e_forensics/tools",
          "phase14d11_static/tools", "phase14d_static/tools",
          "phase8_static/tools", "phase14d8_static/tools"):
    sys.path.insert(0, os.path.join(ROOT, p))
import p16j_execcache as EC                       # noqa: E402

OUT = os.path.join(HERE, "C_SEMANTIC_FREEZE_FINAL.json")
CAND = "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co"


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def build():
    h = hashlib.sha256()
    srcs = {}
    for rel in sorted(EC.SEMANTICS_SOURCES):
        p = os.path.join(ROOT, rel)
        d = sha(p) if os.path.exists(p) else None
        srcs[rel] = d
        h.update(rel.encode()); h.update(b"\0")
        h.update((d or "<absent>").encode()); h.update(b"\n")
    return h.hexdigest(), srcs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true")
    a = ap.parse_args()
    sem, srcs = build()
    cand = sha(os.path.join(ROOT, CAND))
    if a.verify:
        old = json.load(open(OUT, encoding="utf-8"))
        ok = old["semantics_hash"] == sem and old["candidate_sha256"] == cand
        n = 0
        for rel, d in old["semantics_sources"].items():
            n += 1
            if srcs.get(rel) != d:
                print("MUTATED %s" % rel); ok = False
        print("verified %d sources; semantics hash %s" % (n, sem[:16]))
        print("VERDICT: %s" % ("NO_FROZEN_ARTEFACT_MUTATED" if ok
                               else "MUTATION_DETECTED"))
        return 0 if ok else 1
    doc = {"schema": "phase16o-semantic-freeze-final/1", "phase": "16O",
           "track": "C", "host_only": True,
           "gpu_execution_performed": False, "gta_launched": False,
           "currently_armed": False,
           "purpose": "the authoritative semantic revision; a change to any "
                      "source below invalidates every dependent artefact",
           "supersedes": "phase16n_semantic_freeze/n6_freeze/"
                         "SEMANTIC_FREEZE.json (SEMANTIC_FREEZE_DIAGNOSTIC_16N)",
           "semantics_hash": sem, "semantics_sources": srcs,
           "candidate_co": CAND, "candidate_sha256": cand,
           "n_sources": len(srcs),
           "changes_since_16N": {
               "phase8_static/tools/emu.py":
                   "Core._mem_byte real-entry test is dict.__contains__; "
                   "f32/f32_bits saturate on overflow instead of raising",
               "phase14d8_static/tools/p14d8_core.py":
                   "Core8.op_v_sqrt_f32 guards its domain",
               "phase16j_pre_gta/tools/p16j_input.py":
                   "regions_for declares synthetic regions only at the "
                   "authentic POINTER fields"},
           }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    print("semantics_hash = %s" % sem)
    print("candidate      = %s" % cand)
    print("wrote %s" % OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
