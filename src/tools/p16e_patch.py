#!/usr/bin/env python3
"""Phase 16E — candidate-E patch planner & builder (host-only).

Stage 1 (plan): from the per-variant DS-event census (rec_*.csv +
phase16d auth cells + phase14eh ent events) derive the mask-site set:
  - sites with any recorded raw EA >= 0x4000   -> need the &0x3FFF mask
  - sites with max raw in [0x3E00, 0x4000)     -> alloc-raise only (no mask)
Maps each site address to its bundle .s line via content matching and
emits phase16e_candidate_e/patch_sites.json (per variant).

Stage 2 (apply): textual .s edits —
  a) insert 'v_and_b32_e32 v<N>, 0x3fff, v<N>' immediately before the
     mapped .s line of each masked site (merged for adjacent DS twins
     sharing the same address vgpr with no intervening write);
  b) set group_segment_fixed_size -> 16384 for swin variants whose
     request < 16384 (both the per-function .amdhsa_* directive and the
     .amdgpu_metadata YAML entry);
then llvm-mc assemble + ld.lld -shared -> candidate .co (never touching
the entry-fixed reference).
"""
from __future__ import annotations

import csv
import glob
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_ROOT = os.path.abspath(os.path.join(HERE, ".."))
ROOT = os.path.abspath(os.path.join(OUT_ROOT, ".."))
sys.path.insert(0, HERE)
import p16e_lib  # noqa: E402

LLVM_MC = r"<ROCM_ROOT>\7.1\bin\llvm-mc.exe"
LD_LLD = r"<ROCM_ROOT>\7.1\bin\ld.lld.exe"

GSF_NEW = 16384

# per-variant event sources
EVT = {
    "swin32f": [],   # filled below (phase16d auth_*.csv + 14EH events_all)
    "swin64f": [],
    "swin128f": [],
    "swin256f": [],
    "swin32t": [],
}
for tag in EVT:
    EVT[tag] += sorted(glob.glob(os.path.join(
        ROOT, "phase16e_candidate_e", "out", "rec_%s_*.csv" % tag)))
EVT["swin32f"] += sorted(glob.glob(os.path.join(
    ROOT, "phase16d_authentic_capture", "out", "auth_*.csv")))
# 14EH dims-64 ent events (extra geometry for 32f)
EVT["swin32f"].append(os.path.join(ROOT, "phase14eh_tools", "out",
                                   "events_all.csv"))


def ds_addr_reg(text):
    """vaddr vgpr of a DS instruction per p14eh ds_form convention."""
    ops = re.sub(r"\s*//.*", "", text).strip()
    toks = re.split(r"\s+", ops)[1:] if " " in ops else []
    vtoks = [t for t in toks if re.match(r"^v(\d+|\[\d+:\d+\])", t)]
    if not vtoks:
        return None
    # stores print addr first, loads print dst first (AMD objdump style)
    is_store = "write" in ops or "store" in ops.split()[0]
    a = vtoks[0] if is_store else vtoks[-1]
    m = re.match(r"^v(\d+)", a)
    return int(m.group(1)) if m else None


def load_events():
    """site_hex -> (n, max_raw, min_raw, [waves], [cells], mnems)."""
    agg = {}
    for tag, paths in EVT.items():
        for p in paths:
            if not os.path.exists(p):
                continue
            with open(p, encoding="utf-8", errors="replace") as f:
                rd = csv.DictReader(f)
                if not rd.fieldnames or "raw" not in rd.fieldnames:
                    continue
                for r in rd:
                    if "which" in rd.fieldnames and r.get("which", "ent") != "ent":
                        continue
                    try:
                        raw = int(r["raw"])
                    except (ValueError, TypeError):
                        continue
                    site = r.get("site", "").lower()
                    if not site.startswith("0x"):
                        site = "0x%x" % int(site, 0) if site else ""
                    if not site:
                        continue
                    a = agg.setdefault(site, {"n": 0, "mn": 0, "mx": 0,
                                              "waves": set(), "tags": set(),
                                              "mnems": set()})
                    a["n"] += 1
                    a["mn"] = min(a["mn"], raw)
                    a["mx"] = max(a["mx"], raw)
                    a["waves"].add(r.get("wave", ""))
                    a["tags"].add(tag)
                    a["mnems"].add(r.get("mnem", ""))
    return agg


def site_plan(agg):
    """Classify aggregated sites: mask (>=0x4000) / alloc-only / none."""
    mask = {}
    alloc = {}
    for s, a in agg.items():
        if a["mx"] >= 0x4000:
            mask[s] = a
        elif a["mx"] >= 0x3E00:
            alloc[s] = a
    return mask, alloc


def masked_top(agg):
    """Per site: does any event land in [0x3E00,0x4000) AFTER &0x3FFF?
    Such sites make the 16,384-B segment necessary (not just convenient)."""
    out = {}
    for tag, paths in EVT.items():
        for p in paths:
            if not os.path.exists(p):
                continue
            with open(p, encoding="utf-8", errors="replace") as f:
                rd = csv.DictReader(f)
                if not rd.fieldnames or "raw" not in rd.fieldnames:
                    continue
                for r in rd:
                    try:
                        raw = int(r["raw"])
                    except (ValueError, TypeError):
                        continue
                    site = r.get("site", "").lower()
                    if not site.startswith("0x"):
                        site = "0x%x" % int(site, 0) if site else ""
                    if not site or (raw & 0x3FFF) < 0x3E00:
                        continue
                    a = out.setdefault(site, {"n": 0, "mx_masked": 0,
                                              "tags": set()})
                    a["n"] += 1
                    a["mx_masked"] = max(a["mx_masked"], raw & 0x3FFF)
                    a["tags"].add(tag)
    return out


def map_to_s(mask_sites, sym):
    lines = open(p16e_lib.ENT_S, encoding="utf-8").read().splitlines()
    dis = p16e_lib.parse_disasm(p16e_lib.ENT_DIS)
    if sym not in dis:
        return {}
    want = sorted({int(s, 16) for s in mask_sites})
    return p16e_lib.site_to_s_lines(lines, sym, dis[sym], want)


def main_plan():
    agg = load_events()
    mask, alloc = site_plan(agg)
    mt = masked_top(agg)
    print("aggregate sites:", len(agg), "| mask-needed:", len(mask),
          "| alloc-only-raw:", len(alloc), "| masked-top-band sites:",
          len(mt))
    lines = open(p16e_lib.ENT_S, encoding="utf-8").read().splitlines()
    dis = p16e_lib.parse_disasm(p16e_lib.ENT_DIS)
    plan = {}
    for sym, tag in p16e_lib.SWIN_VARIANTS:
        m2 = {s: a for s, a in mask.items() if tag in a["tags"]}
        mp = p16e_lib.site_to_s_lines(lines, sym, dis.get(sym, []),
                                      sorted({int(s, 16) for s in m2}))
        recs = []
        for s, a in sorted(m2.items(), key=lambda kv: int(kv[0], 16)):
            row = next((t for (ad, t) in dis.get(sym, [])
                        if ad == int(s, 16)), "")
            tband = mt.get(s)
            recs.append({"site": s, "n_events": a["n"],
                         "raw_min": a["mn"], "raw_max": a["mx"],
                         "waves": sorted(a["waves"]),
                         "mnem": sorted(a["mnems"]),
                         "needs_alloc_16384":
                             bool(tband) and tag in tband["tags"],
                         "disasm": row,
                         "s_lines": [{"no": ln, "text": t}
                                     for (ln, t) in mp.get(int(s, 16), [])],
                         "addr_vgpr": ds_addr_reg(row)})
        plan[tag] = recs
    with open(os.path.join(OUT_ROOT, "patch_sites.json"), "w",
              encoding="utf-8") as f:
        json.dump(plan, f, indent=1)
    for tag in plan:
        na = sum(1 for r in plan[tag] if r["needs_alloc_16384"])
        print(tag, len(plan[tag]), "mask sites |",
              na, "need alloc 16384")
    return plan


if __name__ == "__main__":
    main_plan()
