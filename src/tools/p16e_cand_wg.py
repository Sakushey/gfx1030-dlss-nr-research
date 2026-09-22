#!/usr/bin/env python3
"""Phase 16E — candidate-E workgroup emulation (host-only).

Runs the CANDIDATE module (masked swin bodies + gsf 16384) under the
measured gfx1030 DS model (u32 EA, alloc 16,384 = served span of the
raised request) for chosen authentic cells, via the 14EH 8-wave
workgroup driver (barrier epochs, per-wave states).

Usage: python p16e_cand_wg.py <variant_tag> <cell> [--cand|--ref]
Emits out/candwg_<tag>_<cell>.json. No GPU execution.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_ROOT = os.path.abspath(os.path.join(HERE, ".."))
ROOT = os.path.abspath(os.path.join(OUT_ROOT, ".."))
for p in ("phase14e_static/tools", "phase14eh_tools", "phase14eg_tools",
          "phase14e_forensics/tools"):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)
sys.path.insert(0, HERE)

import p16e_lib  # noqa: E402
import p16e_rec  # noqa: E402
import p14eh  # noqa: E402

PE = p14eh.PE
P11 = p14eh.P11
OUTD = os.path.join(HERE, "..", "out")
os.makedirs(OUTD, exist_ok=True)


def run_wg(tag, cell, which="cand"):
    sym = dict((t, s) for s, t in p16e_lib.SWIN_VARIANTS)[tag]
    if which == "cand":
        dis_path = os.path.join(OUT_ROOT, "disasm",
                                "candidate_e_gfx1030_disasm.txt")
        co_path = os.path.join(OUT_ROOT, "gfx1030_dlssnr_candidate_e.co")
    else:
        dis_path = p16e_lib.ENT_DIS
        co_path = p16e_lib.ENT_CO
    c = p16e_rec.CELLS[cell]
    prog, _r, _i = PE.slice_program(dis_path, sym)
    dw = P11.dw16(co_path, sym)
    fields = p16e_rec.fields_for(c)
    p16eh = p14eh
    # swap the core class INSIDE p14eh (scratch + d16 + fp-modifier
    # support from E16Core); restored after the run
    prev_hw = p14eh.HWCore
    p14eh.HWCore = p16e_rec.E16Core
    p14eh.HWCore.oob_sem = "u32"
    p14eh.HWCore.alloc = 16384
    p14eh.HWCore.lds_img = 0x10000
    res = p16eh.run_workgroup_hw(
        prog, dw, "%s_%s_%s" % (which, tag, cell), c["grid"], (256, 1, 1),
        fields, text_path=co_path, wave_count=8, oob_sem="u32",
        alloc=16384, wgid=c["wgid"])
    # per-wave DS event resolution under the candidate rules
    summary = {
        "which": which, "tag": tag, "cell": cell,
        "grid": list(c["grid"]), "wgid": list(c["wgid"]),
        "fields": {k: v for k, v in c.items() if k != "wgid"},
        "outcome": str(res["outcome"]), "ticks": res["ticks"],
        "epochs": len(res["barrier_epochs"]),
        "diverged": res["diverged"],
        "per_wave": [{k: v for k, v in w.items() if k != "core"}
                     for w in res["per_wave"]],
    }
    p14eh.HWCore = prev_hw
    with open(os.path.join(OUTD, "candwg_%s_%s_%s.json" % (which, tag, cell)),
              "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=1)
    return summary


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "swin32f"
    cell = sys.argv[2] if len(sys.argv) > 2 else "A"
    which = sys.argv[3] if len(sys.argv) > 3 else "cand"
    t0 = time.time()
    s = run_wg(tag, cell, which)
    s["_secs"] = round(time.time() - t0, 1)
    print(json.dumps({k: s[k] for k in
                      ("which", "tag", "cell", "outcome", "ticks", "epochs",
                       "diverged", "_secs")}))


if __name__ == "__main__":
    main()
