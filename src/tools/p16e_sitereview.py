#!/usr/bin/env python3
"""Phase 16E — per-site static review for candidate-E mask sites.

For every planned mask site (patch_sites.json) produce:
  - instruction text + context rows
  - addr vgpr; its producer (last prior write covering it)
  - dead-after-use: no read of the addr vgpr between the DS site and the
    next write to it (scan forward up to 24 rows / next barrier)
  - twin DS rows (consecutive ds_ rows sharing the addr vgpr, no
    intervening write)
  - barrier row distance before/after
Emits phase16e_candidate_e/site_review.json.
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

PAIR_RE = re.compile(r"v\[(\d+):(\d+)\]")


def text_of(row):
    return re.sub(r"\s*//.*", "", row).strip()


def operands(row):
    toks = re.split(r"\s+", text_of(row))
    out = toks[1:] if len(toks) > 1 else []
    return [t.rstrip(",") for t in out]


def dst_range(row):
    """(lo, hi) vgpr range written by the row, or None."""
    ops = operands(row)
    if not ops:
        return None
    m = PAIR_RE.match(ops[0])
    if m:
        return (int(m.group(1)), int(m.group(2)))
    mm = re.match(r"^v(\d+)", ops[0])
    if mm:
        return (int(mm.group(1)), int(mm.group(1)))
    return None


def reads_cover(row, av):
    """does any operand (other than a dst token) read vgpr av?"""
    ops = operands(row)
    if not ops:
        return False
    d = dst_range(row)
    for p in ops[1:]:
        m = PAIR_RE.match(p)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if lo <= av <= hi:
                return True
        else:
            mm = re.match(r"^v(\d+)$", p)
            if mm and int(mm.group(1)) == av:
                return True
    return False


def review(tag):
    sites = json.load(open(os.path.join(OUT_ROOT, "patch_sites.json"),
                           encoding="utf-8"))[tag]
    sym = dict((t, s) for s, t in p16e_lib.SWIN_VARIANTS)[tag]
    rows = p16e_lib.parse_disasm(p16e_lib.ENT_DIS).get(sym, [])
    out = []
    for st in sites:
        addr = int(st["site"], 16)
        i = next(k for k, (a, _t) in enumerate(rows) if a == addr)
        text = rows[i][1]
        av = st.get("addr_vgpr")
        # producer: last prior row whose dst range covers av
        pd = None
        for j in range(i - 1, max(-1, i - 48), -1):
            d = dst_range(rows[j][1])
            if d and av is not None and d[0] <= av <= d[1]:
                pd = j
                break
        # dead-after-use scan (24 rows or next barrier)
        # DS loads whose data destination covers the address vgpr overwrite
        # it with LOAD DATA: later reads of the vgpr see that data, not the
        # (masked) address, so they cannot be corrupted by the mask.
        site_dst = dst_range(text)
        self_overwrite = bool(
            site_dst and av is not None and site_dst[0] <= av <= site_dst[1]
            and re.match(r"^\s*ds_", text) and "read" in text)
        live_row = nxt_write = None
        if self_overwrite:
            # vgpr becomes load data; first subsequent write is the only
            # event that matters (none between site and next write => ok)
            for j in range(i + 1, min(len(rows), i + 24)):
                if rows[j][1].startswith("s_barrier"):
                    break
                d = dst_range(rows[j][1])
                if d and av is not None and d[0] <= av <= d[1]:
                    nxt_write = j
                    break
        else:
            for j in range(i + 1, min(len(rows), i + 24)):
                if rows[j][1].startswith("s_barrier"):
                    break
                d = dst_range(rows[j][1])
                if d and av is not None and d[0] <= av <= d[1]:
                    nxt_write = j
                    break
                if av is not None and reads_cover(rows[j][1], av):
                    # reads of av by another ds_ instruction before any
                    # write = twin/cluster member (same normalization);
                    # ALU reads would be the dangerous case
                    if not text_of(rows[j][1]).startswith("ds_"):
                        live_row = j
                        break
        # twins: consecutive ds rows after i, before a write of av
        twins = []
        for j in range(i + 1, min(len(rows), i + 8)):
            if rows[j][1].startswith("s_barrier"):
                break
            if not text_of(rows[j][1]).startswith("ds_"):
                break
            if av is not None:
                d = dst_range(rows[j][1])
                if d and d[0] <= av <= d[1]:
                    break
            twins.append({"addr": rows[j][0], "text": rows[j][1]})
        bd_before = bd_after = None
        for j in range(i - 1, max(-1, i - 4000), -1):
            if rows[j][1].startswith("s_barrier"):
                bd_before = i - j
                break
        for j in range(i + 1, min(len(rows), i + 4000)):
            if rows[j][1].startswith("s_barrier"):
                bd_after = j - i
                break
        out.append({
            "site": st["site"], "addr_vgpr": av,
            "n_events": st["n_events"], "raw_max": st["raw_max"],
            "needs_alloc": st["needs_alloc_16384"],
            "mnem": st["mnem"], "text": text,
            "producer_row": pd,
            "producer_text": rows[pd][1] if pd is not None else None,
            "self_overwrite_load": self_overwrite,
            "live_after_use": live_row is not None,
            "first_read_after": live_row,
            "next_write_row": nxt_write,
            "twins": twins,
            "barrier_rows_before": bd_before,
            "barrier_rows_after": bd_after,
            "ctx_before": [rows[j][1] for j in range(i - 5, i)],
        })
    return out


def main():
    res = {}
    for tag in ("swin32t", "swin32f", "swin64f", "swin128f", "swin256f"):
        pj = os.path.join(OUT_ROOT, "patch_sites.json")
        if not os.path.exists(pj):
            continue
        sites = json.load(open(pj, encoding="utf-8")).get(tag, [])
        if sites:
            res[tag] = review(tag)
    with open(os.path.join(OUT_ROOT, "site_review.json"), "w",
              encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    for tag, rr in res.items():
        live = sum(1 for r in rr if r["live_after_use"])
        print("%s %2d sites | live-after-use: %d" % (tag, len(rr), live))


if __name__ == "__main__":
    main()
