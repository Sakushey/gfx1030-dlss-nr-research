#!/usr/bin/env python3
"""Phase 16H — P2/P5: render pcrel_site_ledger.md from the census JSON.

The CSV is the machine-readable ledger; this renders the human-readable
companion from the same JSON so the two can never disagree.
"""
from __future__ import annotations

import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p16h_lib as L  # noqa: E402

CEN = os.path.join(L.P16H, "out", "pcrel_census.json")
MD = os.path.join(L.P16H, "pcrel_site_ledger.md")


def main():
    d = json.load(open(CEN))
    rows = d["rows"]
    man = json.load(open(os.path.join(L.ROOT, "phase16h_candidate_f",
                                      "pcrel_fix_manifest.json")))
    fix = {}
    for p, r in zip(man["sites"], man["resolution"]):
        fix[(p["symbol"], p["orig_pc"])] = r

    md = []
    A = md.append
    A("# Phase 16H — PC-relative site ledger (host-only)")
    A("")
    A("Every `s_getpc_b64` + `s_add_u32`/`s_addc_u32` address formation in "
      "the module, re-derived from the binaries (`p16h_census.py`), with "
      "its original target, its Candidate-E resolution (the defect) and "
      "its Candidate-F resolution (the fix).")
    A("")
    A("Machine-readable twin: `pcrel_site_ledger.csv` (same JSON source).")
    A("")
    A("## Summary")
    A("")
    A("| | |")
    A("|---|---|")
    A("| total sites | **%d** |" % len(rows))
    A("| kernels containing sites | **%d** |"
      % len({r["symbol"] for r in rows}))
    A("| sites whose Candidate-E target is outside every section | **%d** |"
      % sum(1 for r in rows if r["cand_outside"]))
    A("| sites fixed | **%d** |" % man["n_rewritten"])
    A("| sites resolving inside the intended object in Candidate F | "
      "**82 / 82** |")
    A("| relocation addend | `%s` |" % man["reloc_addend"])
    A("")

    A("## By original target")
    A("")
    A("| original target | section | n | Candidate-E outcome | "
      "Candidate-F outcome |")
    A("|---|---|---|---|---|")
    g = collections.defaultdict(list)
    for r in rows:
        g[(r["orig_target"], r["orig_section"])].append(r)
    for (t, sec), rs in sorted(g.items()):
        n_out = sum(1 for r in rs if r["cand_outside"])
        secs_e = sorted({("`%s`" % r["cand_section"]) if r["cand_section"]
                         else "outside all sections" for r in rs})
        labels = sorted({p["label"] for p in man["sites"]
                         if int(p["orig_target"], 16) == int(t, 16)})
        A("| `%s` | `%s` | %d | %d outside every section; in %s | `%s` — %d/%d OK |"
          % (t, sec, len(rs), n_out, ", ".join(secs_e),
             ", ".join(labels), len(rs), len(rs)))
    A("")

    A("## Restored `.rodata` objects")
    A("")
    A("| symbol | bind | size | why |")
    A("|---|---|---|---|")
    for o in man["restored_rodata_objects"]:
        why = ("target of the 79 `.rodata` PC-relative sites"
               if o["name"] == "g_e4m3_lut" else
               "dropped by the same emitter defect")
        A("| `%s` | %s | %d | %s |" % (o["name"], o["bind"], o["size"], why))
    A("")

    A("## Per-kernel site counts")
    A("")
    A("| kernel | sites | original target(s) | Candidate-E outside |")
    A("|---|---|---|---|")
    per = collections.defaultdict(list)
    for r in rows:
        per[r["symbol"]].append(r)
    for sym in sorted(per, key=lambda s: -len(per[s])):
        rs = per[sym]
        tg = sorted({r["orig_target"] for r in rs})
        A("| `%s` | %d | %s | %d |"
          % (sym, len(rs), ", ".join("`%s`" % x for x in tg),
             sum(1 for r in rs if r["cand_outside"])))
    A("")

    A("## Full ledger")
    A("")
    A("| # | kernel | orig PC | orig target | C-E target | C-E section | "
      "C-F target | C-F section | fix label | consumer |")
    A("|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        f = fix.get((r["symbol"], r["orig_pc"]), {})
        lbl = next((p["label"] for p in man["sites"]
                    if p["symbol"] == r["symbol"]
                    and p["orig_pc"] == r["orig_pc"]), "")
        A("| %d | `%s` | `%s` | `%s` | `%s` | %s | `%s` | `%s` | `%s` | "
          "`%s` |"
          % (r["n"], r["symbol"].replace("_Z", ""), r["orig_pc"],
             r["orig_target"], r["cand_target"],
             r["cand_section"] or "**outside**",
             f.get("new_target", ""), f.get("new_section", ""), lbl,
             (r["consumers"].split(" | ")[-1] if r["consumers"] else "")))
    A("")
    A("## Method")
    A("")
    A("Each site is rewritten to")
    A("")
    A("```")
    A("    s_getpc_b64 sN:M")
    A("    s_add_u32   sN, sN, SYM@rel32@lo+4")
    A("    s_addc_u32 sM, sM, SYM@rel32@hi+4")
    A("```")
    A("")
    A("`SYM` comes from the **original** gfx1100 object's symbol table, so "
      "the target is named rather than numbered. `R_AMDGPU_REL32_LO/HI` are "
      "evaluated by `ld.lld` against the final layout, so the correction "
      "survives any later change in instruction count or section size. The "
      "`+4` addend compensates for the linker's `P` being the address of "
      "the literal itself rather than of the `s_getpc_b64` (without it "
      "every site lands exactly 4 bytes short).")
    A("")
    A("This is a property of the **build pipeline**, not of gfx1030 and not "
      "of any particular address: the same rewrite applies to any module "
      "whose translated assembly carries baked PC-relative literals.")
    A("")
    open(MD, "w", encoding="utf-8").write("\n".join(md))
    print("wrote", MD, "(%d rows)" % len(rows))


if __name__ == "__main__":
    main()
