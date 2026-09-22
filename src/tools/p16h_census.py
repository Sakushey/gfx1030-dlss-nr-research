#!/usr/bin/env python3
"""Phase 16H — P2: complete module-wide PC-relative census.

Re-derives every `s_getpc_b64`-based address formation from the final
binaries themselves (original gfx1100 translation source and Candidate E),
never from a hard-coded list.

Emits:
    out/pcrel_census.json
    pcrel_site_ledger.csv
    pcrel_site_ledger.md
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p16h_lib as L  # noqa: E402

OUT = L.ensure_out()
ROOT = L.ROOT

LAUNCH_CENSUS = os.path.join(ROOT, "phase16_authentic_kernel_census.csv")
LAUNCH_DB = os.path.join(ROOT, "phase16_authentic_launch_db.csv")


def authentic_kernels():
    """mangled -> dict from the authentic GTA capture."""
    out = {}
    with open(LAUNCH_CENSUS, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            out[r["mangled"]] = r
    return out


def demangle(n):
    return n


def consumer_of(insns, i):
    """The memory operation(s) that consume the base produced at site i.

    Walk forward from the s_addc_u32 looking for the first instruction that
    reads the produced SGPR pair in a memory operand.
    """
    if i + 3 >= len(insns):
        return []
    site = L.find_sites(insns)[0] if False else None
    dst = L.GETPC_RE.match(insns[i][1]).group(1)
    m = re.match(r"^s\[(\d+):(\d+)\]$", dst)
    lo_r, hi_r = (int(m.group(1)), int(m.group(2))) if m else (None, None)
    pair = "s[%d:%d]" % (lo_r, hi_r) if lo_r is not None else dst
    single = "s%d" % lo_r if lo_r is not None else dst
    hits = []
    for k in range(i + 1, min(i + 90, len(insns))):
        t = insns[k][1]
        if re.search(r"\bs_(getpc|add_u32|addc_u32|mov_b32|mov_b64)\b",
                     t.split(None, 1)[0]) and k > i + 3:
            break
        if pair in t or re.search(r"\b%s\b" % re.escape(single), t):
            if re.match(r"^(global|flat|scratch|buffer|ds|s_|image)", t):
                hits.append((insns[k][0], t))
                if len(hits) >= 4:
                    break
    return hits


def access_kind(text):
    m = re.match(r"^(global|flat|scratch|buffer|ds|s_\w+|image)\w*", text)
    kind = m.group(0) if m else "?"
    w = None
    for pat, name in ((r"_ushort|_u16", "u16"), (r"_ubyte|_u8", "u8"),
                      (r"dwordx4|_b128", "128"), (r"dwordx3|_b96", "96"),
                      (r"dwordx2|_b64|_u64", "64"), (r"dword|_b32|_u32", "32"),
                      (r"dwordx2|_b64", "64")):
        if re.search(pat, text):
            w = name
            break
    return kind, w


def main():
    o_order, o_bodies, _ = L.parse_disasm(L.ORIG_DIS)
    c_order, c_bodies, _ = L.parse_disasm(L.CAND_DIS)
    eo = L.Elf(L.ORIG_O)
    ec = L.Elf(L.CAND_CO)
    auth = authentic_kernels()

    # section map summary
    secmap = dict(
        orig={s["sname"]: dict(addr=s["addr"], size=s["size"])
              for s in eo.loadable()},
        cand={s["sname"]: dict(addr=s["addr"], size=s["size"])
              for s in ec.loadable()})

    common = [n for n, _ in o_order if n in c_bodies]
    only_o = [n for n, _ in o_order if n not in c_bodies]
    only_c = [n for n, _ in c_order if n not in o_bodies]

    rows = []
    idx = 0
    for sym, _ in o_order:
        if sym not in c_bodies:
            continue
        so = L.find_sites(o_bodies[sym])
        sc = L.find_sites(c_bodies[sym])
        assert len(so) == len(sc), (sym, len(so), len(sc))
        for a, b in zip(so, sc):
            idx += 1
            os_ = eo.owner(a["target"]) if a["complete"] else None
            cs_ = ec.owner(b["target"]) if b["complete"] else None
            # find the site index inside the instruction list for the consumer
            ii = next((k for k, (ad, t, _b) in enumerate(o_bodies[sym])
                       if ad == a["pc"]), None)
            cons = consumer_of(c_bodies[sym],
                               next((k for k, (ad, t, _b)
                                     in enumerate(c_bodies[sym])
                                     if ad == b["pc"]), 0))
            kinds = sorted({access_kind(t)[0] for _ad, t in cons})
            widths = sorted({access_kind(t)[1] for _ad, t in cons
                             if access_kind(t)[1]})
            au = auth.get(sym)
            rows.append(dict(
                n=idx, symbol=sym,
                orig_pc="0x%08X" % a["pc"], cand_pc="0x%08X" % b["pc"],
                dst=a["dst"],
                seq="%s ; %s ; %s" % (a["text"], a["lo_text"], a["hi_text"]),
                lo=a["lo"], hi=a["hi"], delta=a["delta"],
                orig_target="0x%016X" % a["target"],
                orig_section=(os_["sname"] if os_ else None),
                orig_sec_off=("%d" % (a["target"] - os_["addr"]) if os_ else ""),
                cand_target="0x%016X" % b["target"],
                cand_section=(cs_["sname"] if cs_ else None),
                cand_outside=(cs_ is None),
                authentic_launched=(au["launched"] if au else "no"),
                authentic_launches=(au["total_launches"] if au else "0"),
                consumers=" | ".join(t for _ad, t in cons),
                access_kinds=",".join(kinds), access_widths=",".join(widths),
                cand_delta_same=(a["delta"] == b["delta"]),
            ))

    # group by original target
    by_target = {}
    for r in rows:
        by_target.setdefault(r["orig_target"], []).append(r)

    print("symbols: orig=%d cand=%d common=%d only_orig=%s only_cand=%s"
          % (len(o_order), len(c_order), len(common), only_o, only_c))
    print("total sites: %d" % len(rows))
    print("sites by original target:")
    for t, rs in sorted(by_target.items()):
        secs_ = {r["orig_section"] for r in rs}
        print("   %s  n=%-3d  sec=%s  kernels=%s"
              % (t, len(rs), ",".join(str(x) for x in secs_),
                 ",".join(sorted({r["symbol"] for r in rs}))[:110]))
    nout = sum(1 for r in rows if r["cand_outside"])
    print("candidate targets outside every section: %d / %d" % (nout, len(rows)))
    print("kernels with sites: %d" % len({r["symbol"] for r in rows}))

    json.dump(dict(secmap=secmap, n_sites=len(rows),
                   orig_sections=[s["sname"] for s in eo.loadable()],
                   cand_sections=[s["sname"] for s in ec.loadable()],
                   by_target={k: len(v) for k, v in by_target.items()},
                   rows=rows),
              open(os.path.join(OUT, "pcrel_census.json"), "w"), indent=1)

    cols = list(rows[0].keys())
    with open(os.path.join(ROOT, "phase16h_pcrel_fix", "pcrel_site_ledger.csv"),
              "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    print("wrote pcrel_site_ledger.csv")


if __name__ == "__main__":
    main()
