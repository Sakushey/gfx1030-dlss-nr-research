#!/usr/bin/env python3
"""Phase 16E — fixed-point iteration bookkeeping (host-only).

Adds newly-reached OOB DS sites (found by emulating the candidate) to
the patch plan. Input: out/oob_fold_sites.json
    { tag: [ {"text": "<candidate disasm row>", "imm": <int>}, ... ] }
Sites are located in the REFERENCE disasm by normalized text, mapped to
bundle .s lines, appended to patch_sites.json as form-B fold records,
and oob_fold_sites.json carries the imm per mapped site.
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
import p16e_lib  # noqa: E402

PATCH = os.path.join(OUT_ROOT, "patch_sites.json")
FOLD_IN = os.path.join(OUT_ROOT, "out", "oob_fold_sites.json")
FOLD_OUT = os.path.join(OUT_ROOT, "out", "oob_fold_sites.json")

VREG = re.compile(r"^v(\d+)$")


def main():
    if not os.path.exists(FOLD_IN):
        print("no oob_fold_sites.json; nothing to do")
        return
    fold_in = json.load(open(FOLD_IN, encoding="utf-8"))
    patch = json.load(open(PATCH, encoding="utf-8"))
    lines = open(p16e_lib.ENT_S, encoding="utf-8",
                 errors="replace").read().splitlines()
    dis = p16e_lib.parse_disasm(p16e_lib.ENT_DIS)
    sym_of = dict((t, s) for s, t in p16e_lib.SWIN_VARIANTS)
    added = 0
    fold_out_all = {}
    for tag, items in fold_in.items():
        sym = sym_of[tag]
        rows = dis.get(sym, [])
        byaddr = {a: t for a, t in rows}
        res_items = []
        for it in items:
            addr = int(it["site"], 16)
            t = byaddr.get(addr)
            if t is None:
                raise SystemExit("no ref disasm row for %s %s"
                                 % (tag, it["site"]))
            av_m = re.search(r"v(\d+)", t)
            mp = p16e_lib.site_to_s_lines(lines, sym, rows, [addr])
            if not mp.get(addr):
                raise SystemExit("no .s map for %s %s" % (tag, it["site"]))
            rec = {"site": hex(addr), "n_events": 0, "raw_min": 0,
                   "raw_max": 0x4000, "waves": [], "mnem": [t.split()[0]],
                   "needs_alloc_16384": False, "disasm": t,
                   "s_lines": [{"no": mp[addr][0][0], "text": mp[addr][0][1]}],
                   "addr_vgpr": int(av_m.group(1)) if av_m else None,
                   "fold": True}
            if not any(x["site"] == rec["site"]
                       for x in patch.get(tag, [])):
                patch.setdefault(tag, []).append(rec)
                added += 1
            res_items.append({"site": hex(addr), "imm": it["imm"]})
        if res_items:
            fold_out_all[tag] = res_items
    with open(FOLD_OUT, "w", encoding="utf-8") as f:
        json.dump(fold_out_all, f, indent=1)
    with open(PATCH, "w", encoding="utf-8") as f:
        json.dump(patch, f, indent=1)
    print("added fold sites:", added)


if __name__ == "__main__":
    main()
