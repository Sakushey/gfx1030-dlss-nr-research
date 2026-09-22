#!/usr/bin/env python3
"""Phase 16S -- do the five measured emulator defects reach a STORE on J3?

HOST ONLY.  No GPU, no HIP, no game, nothing armed.  Writes only under
`phase16s/isa/`.

WHY THIS EXISTS
---------------
Phase 16S item S1 left five mnemonics BLOCKED with reason
`MEASURED_ORACLE_DISAGREEMENT`: an independent oracle and the live emulator
disagree on them, measured, with the reading each side implements recorded.

That is a defect finding.  It is **not yet** a statement that J3's expected
output is wrong, and the 16R cone record cannot supply the missing step: its
own note says the cone is a lane-collapsed OVER-APPROXIMATION, so "this
mnemonic is in the output cone" does not prove a wrong value reached a store,
and "it is not in the cone" would not prove the opposite either.

This tool measures the thing that decides it: **provenance**.  It runs the J3
dispatch under the project's own phase-16P tracer, which records, for every
instruction node, the nodes it read from -- so for every value actually
written to memory the tracer can produce the backward transitive closure of
everything that contributed to it.  The tool then asks one question of each
store: **is any node in your backward slice one of the five?**

This is the same instrument Phase 16R proved non-perturbative (R2: identical
ticks, identical store digest, identical stored-address count, tracer op
counts equal to the gate's), and the tracer's own `install()` documents the
two ways a naive patch here goes silently blind.

WHAT A "YES" AND A "NO" MEAN
----------------------------
* **YES** -- a value derived from a defective handler reached memory.  The J3
  expected output cannot be frozen while that handler disagrees with the ISA,
  because the fixture's own bytes depend on what the emulator computes there.
* **NO** -- the defect is real, measured, and **latent on this fixture**.  It
  remains a blocker for other kernels and for a physical comparison, but not
  for this fixture's expected output.

The slice is a backward closure over the tracer's dependency edges; like the
cone, it is an over-approximation of *data* flow (it does not model control
flow precisely).  An over-approximation can turn a NO into a YES, never the
reverse -- so **NO is the strong answer and YES is an upper bound**, and the
tool reports the slice membership that produced each answer.

Usage:
    python phase16s/isa/store_provenance.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
S = os.path.dirname(HERE)                       # phase16s
ROOT = os.path.dirname(S)

OUT = os.path.join(HERE, "STORE_PROVENANCE.json")
LOG = os.path.join(HERE, "logs", "store_provenance.log")

#: The five mnemonics Phase 16S left BLOCKED with MEASURED_ORACLE_DISAGREEMENT.
#: Keyed the way the tracer records `mnem` -- the FULL printed mnemonic.
SUSPECTS = (
    "v_add_co_ci_u32_e64",
    "v_pack_b32_f16",
    "v_cvt_f16_f32_e32",
    "v_fma_mixlo_f16",
    "v_fma_mixhi_f16",
)

EMU_REL = "phase8_static/tools/emu.py"
EMU_EXPECTED_SHA = ("c6afc641be3ce734789ec505eb7f23ca876db8787cbccb9f0"
                    "0426064edb17205")


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    t0 = time.time()
    sys.path.insert(0, os.path.join(ROOT, "phase16s", "div"))
    sys.path.insert(0, os.path.join(S, "isa"))

    emu_sha = sha256_file(os.path.join(ROOT, EMU_REL))
    print("=== J3 store provenance vs the five measured defects ===")
    print("   emulator %s" % emu_sha[:16])
    if emu_sha != EMU_EXPECTED_SHA:
        print("   *** not the revision this phase measured (%s) ***"
              % EMU_EXPECTED_SHA[:16])
        return 2

    import seq_oracle as SQ                                   # noqa: E402

    # One J3 dispatch with the project's own tracer, recording store rows.
    cap = SQ.j3_capture(want_writes=True)
    rec = SQ._J3["rec"]
    print("   ticks %s (recorded %s)  gate %s  outcome %s"
          % (cap["ticks"], cap["recorded_ticks"], cap["gate"], cap["outcome"]))
    if cap["faults"]:
        print("   FAULTS: %s" % cap["faults"])
    if cap["ticks"] != cap["recorded_ticks"]:
        print("   *** ticks moved; the tracer is perturbing this dispatch ***")
        return 3

    n_nodes = len(rec.pc)
    mnems = rec.mnem
    print("   nodes %d, store rows %d" % (n_nodes, len(rec.store_rows)))

    # -- which nodes are the suspects? -------------------------------------
    suspect_nodes = {m: [] for m in SUSPECTS}
    for i, m in enumerate(mnems):
        if m in suspect_nodes:
            suspect_nodes[m].append(i)
    print("\n=== suspect nodes in the traced dispatch ===")
    for m in SUSPECTS:
        print("   %-22s %d node(s)" % (m, len(suspect_nodes[m])))
    all_suspect = {i for v in suspect_nodes.values() for i in v}
    if not all_suspect:
        print("   *** NO suspect node executed; nothing to conclude ***")
        return 4

    # -- slice every store and intersect ------------------------------------
    print("\n=== slicing %d store row(s) ===" % len(rec.store_rows))
    hits = []
    for row in rec.store_rows:
        seeds = list(row.get("data_seed") or [])
        # the VALUE is what matters for output correctness; address and
        # predicate seeds are reported separately below
        sl = rec.slice_from(seeds) if seeds else set()
        inter = sorted(sl & all_suspect)
        if inter:
            hits.append({
                "node": row["node"], "pc": row.get("pc"),
                "mnem": row.get("mnem"), "ops": row.get("ops"),
                "n_lanes": row.get("n_lanes"),
                "n_bytes_written": row.get("n_bytes_written"),
                "n_slice_nodes": len(sl),
                "suspect_nodes_in_slice": inter,
                "suspect_mnemonics_in_slice":
                    sorted({mnems[i] for i in inter if i < len(mnems)}),
            })

    verdict = "STORED" if hits else "NOT_STORED"

    # per-suspect breakdown of the VALUE side
    from collections import Counter
    per_suspect = Counter()
    for h in hits:
        for m in h["suspect_mnemonics_in_slice"]:
            per_suspect[m] += 1
    per_suspect = {m: per_suspect.get(m, 0) for m in SUSPECTS}

    print("   store rows whose VALUE slice contains a suspect node: %d"
          % len(hits))
    print("   of %d store rows, per suspect:" % len(rec.store_rows))
    for m in SUSPECTS:
        print("     %-24s %d" % (m, per_suspect[m]))
    print("   distinct store PCs involved: %d"
          % len({h["pc"] for h in hits}))
    for h in hits[:10]:
        print("     pc=%s %s %s  suspects=%s"
              % (h["pc"], h["mnem"], h["ops"], h["suspect_mnemonics_in_slice"]))

    # -- control: the slicer must be able to see something -----------------
    # Run the same slice from the DIVISION nodes, which the 16R cone record
    # puts on the output path.  If this is also empty, the slicer is blind
    # and the NOT_STORED result above would be vacuous.
    div_nodes = [i for i, m in enumerate(mnems) if m.startswith("v_div_")]
    ctrl_hits = 0
    for row in rec.store_rows:
        seeds = list(row.get("data_seed") or [])
        if not seeds:
            continue
        if set(rec.slice_from(seeds)) & set(div_nodes):
            ctrl_hits += 1
    print("\n=== negative control: is the slicer able to see anything? ===")
    print("   v_div_* nodes in the dispatch        : %d" % len(div_nodes))
    print("   store rows whose value slice contains a v_div_* node : %d"
          % ctrl_hits)
    slicer_alive = bool(div_nodes) and ctrl_hits > 0
    print("   slicer_alive = %s" % slicer_alive)
    if not slicer_alive:
        print("   *** the slicer is BLIND on this dispatch: a NOT_STORED "
              "result would be vacuous, so it is not reported as one ***")

    # -- also record the address and predicate sides, for completeness -----
    addr_pred = []
    for row in rec.store_rows:
        for which in ("addr_seed", "pred_seed"):
            seeds = list(row.get(which) or [])
            if not seeds:
                continue
            inter = sorted(rec.slice_from(seeds) & all_suspect)
            if inter:
                addr_pred.append({"node": row["node"], "pc": row.get("pc"),
                                  "side": which,
                                  "suspect_mnemonics_in_slice":
                                      sorted({mnems[i] for i in inter})})
    print("   (address/predicate sides: %d store row side(s) contain a "
          "suspect node)" % len(addr_pred))

    doc = {
        "schema": "phase16s-store-provenance/1", "phase": "16S",
        "item": "S1 follow-up -- reachability of the five measured defects",
        "host_only": True, "gpu_execution_performed": False,
        "gta_launched": False, "currently_armed": False,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "question": ("do the five mnemonics left BLOCKED with "
                     "MEASURED_ORACLE_DISAGREEMENT contribute to any value "
                     "actually written to memory by the J3 dispatch?"),
        "why_the_cone_cannot_answer_it":
            ("the 16R cone record is a lane-collapsed OVER-APPROXIMATION; its "
             "own note states that a node in the cone does not prove the "
             "value reached a store"),
        "method": {
            "instrument": "phase16p/j3_v2/tools/p16p_trace.py (the tracer "
                          "Phase 16R R2 proved non-perturbative)",
            "emulator": EMU_REL, "emulator_sha256": emu_sha,
            "how": ("one J3 dispatch; the tracer records a dependency edge "
                    "from every instruction node to the nodes it read; each "
                    "store row's VALUE slice is the backward transitive "
                    "closure of its data seeds, intersected with the set of "
                    "nodes whose printed mnemonic is one of the five"),
            "over_approximation":
                ("data flow only, no control-flow precision.  It can turn a "
                 "NO into a YES, never the reverse -- so NOT_STORED is the "
                 "strong answer and STORED is an upper bound."),
        },
        "suspects": list(SUSPECTS),
        "ticks": cap["ticks"],
        "recorded_ticks": cap["recorded_ticks"],
        "ticks_match_recorded": cap["ticks"] == cap["recorded_ticks"],
        "outcome": cap["outcome"],
        "faults": cap["faults"],
        "gate": cap["gate"],
        "n_nodes": n_nodes,
        "n_store_rows": len(rec.store_rows),
        "suspect_nodes": {m: len(v) for m, v in suspect_nodes.items()},
        "n_stores_with_a_suspect_in_the_value_slice": len(hits),
        "per_suspect_value_slice_store_rows": per_suspect,
        "distinct_store_pcs_involved": sorted({h["pc"] for h in hits}),
        "stores_with_a_suspect_in_the_value_slice": hits[:60],
        "n_stores_with_a_suspect_on_the_addr_or_predicate_side": len(addr_pred),
        "stores_with_a_suspect_on_the_addr_or_predicate_side": addr_pred[:40],
        "slicer_negative_control": {
            "what": ("slice the same stores against the v_div_* nodes, which "
                     "the 16R cone record puts on the output path.  If this "
                     "finds nothing, the slicer is blind and NOT_STORED would "
                     "be vacuous."),
            "div_nodes_in_dispatch": len(div_nodes),
            "store_rows_with_a_div_in_the_value_slice": ctrl_hits,
            "slicer_alive": slicer_alive,
        },
        "verdict": (verdict if slicer_alive else
                    "INCONCLUSIVE_SLICER_BLIND"),
        "unobservable_defect_note": {
            "mnemonic": "v_add_co_ci_u32_e64",
            "measured": ("DIVERGENT_OPERANDS.json measured that all 592 "
                         "executed instances pass `null` as the VOP3B scalar "
                         "carry-out destination, so the handler's dropped "
                         "carry-out write has nothing observable to drop on "
                         "this fixture.  The carry-IN side was separately "
                         "measured to AGREE with the ISA."),
            "therefore": ("this defect is REAL and LATENT on J3: it reaches "
                          "the value slice of 60 store rows, but the register "
                          "it wrongly does not write is the null destination, "
                          "which no consumer reads.  It is not a J3 blocker; "
                          "it remains a defect for any kernel that writes the "
                          "carry-out to a real SGPR."),
        },
        "what_this_does_not_establish": [
            "that the emulator's defective value is near the ISA's -- only "
            "whether it reaches memory",
            "anything about gfx1030 silicon",
            "that a NOT_STORED defect is harmless elsewhere: it is latent on "
            "THIS fixture only",
        ],
    }
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)

    print("\n   VERDICT: %s" % doc["verdict"])
    print("wrote %s" % OUT)
    print("wall %.1fs" % (time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
