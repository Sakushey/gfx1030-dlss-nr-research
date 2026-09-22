#!/usr/bin/env python3
"""T-XREF: discover the VOPD 64-bit field layout empirically.

Inputs are PRIMARY, NEUTRAL evidence only:
  * llvm-objdump text  (an independent decoder, not this project's model)
  * the raw symbol bytes are read by the sibling probe

Method: for every `v_dual_*` record, build V = w0 | (w1<<32).  For a given
architectural operand (e.g. "vdst of the X slot"), find every (offset,width)
bitfield of V that equals the operand's numeric value in EVERY record where
that operand is a plain VGPR.  A field that is consistent across all 1509
samples is the field.
"""
import os
import re
import sys
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DISDIR = os.path.join(ROOT, "p16aw", "vopd")
DISS = ["ACTUAL_PARENT_sym.dis", "ACTUAL_PARENT_full.dis", "CANDIDATE_F_full.dis"]

VRE = re.compile(r"^v(\d+)$")
SRE = re.compile(r"^s(\d+)$")


def parse_dis(path):
    recs = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "v_dual_" not in line or "//" not in line:
                continue
            body, tail = line.rstrip("\n").rsplit("//", 1)
            tail = tail.strip()
            if ":" not in tail:
                continue
            a, w = tail.split(":", 1)
            try:
                addr = int(a.strip(), 16)
                words = [int(t, 16) for t in w.split()]
            except ValueError:
                continue
            if len(words) < 2:
                continue
            body = body.strip()
            if " :: " not in body:
                continue
            xs, ys = body.split(" :: ", 1)
            recs.append({
                "file": os.path.basename(path),
                "addr": addr,
                "V": words[0] | (words[1] << 32),
                "words": words,
                "x": xs.strip(),
                "y": ys.strip(),
            })
    return recs


def split_side(text):
    parts = text.split(None, 1)
    mn = parts[0]
    ops = [o.strip() for o in parts[1].split(",")] if len(parts) > 1 else []
    return mn, ops


def vnum(tok):
    m = VRE.match(tok.strip())
    return int(m.group(1)) if m else None


def snum(tok):
    m = SRE.match(tok.strip())
    return int(m.group(1)) if m else None


def prep(rec):
    mx, ox = split_side(rec["x"])
    my, oy = split_side(rec["y"])
    rec["mx"], rec["ox"] = mx, ox
    rec["my"], rec["oy"] = my, oy
    return rec


def discover(recs, getter, label, wlist=(4, 5, 6, 7, 8, 9, 10, 11, 12), topn=4):
    pairs = []
    for r in recs:
        v = getter(r)
        if v is not None:
            pairs.append((r["V"], v))
    n = len(pairs)
    hits = []
    for w in wlist:
        for off in range(0, 65 - w):
            if all(((V >> off) & ((1 << w) - 1)) == v for V, v in pairs):
                hits.append((off, w))
    print("%-28s n=%4d  consistent fields: %s" % (label, n, hits if hits else "NONE"))
    if not hits:
        best = []
        for w in wlist:
            for off in range(0, 65 - w):
                good = sum(1 for V, v in pairs if ((V >> off) & ((1 << w) - 1)) == v)
                best.append((good, off, w))
        best.sort(reverse=True)
        for good, off, w in best[:topn]:
            print("      best: off=%2d w=%2d  %d/%d  (%.1f%%)" %
                  (off, w, good, n, 100.0 * good / max(n, 1)))
    return hits


def main():
    allrecs = []
    for name in DISS:
        p = os.path.join(DISDIR, name)
        if not os.path.exists(p):
            print("MISSING:", p)
            continue
        rs = [prep(r) for r in parse_dis(p)]
        print("%-32s v_dual records: %d" % (name, len(rs)))
        allrecs.extend(rs)
    print("TOTAL v_dual records:", len(allrecs))
    print()

    # distinct opcode pairs
    pairs = collections.Counter((r["mx"], r["my"]) for r in allrecs)
    print("distinct (X mnemonic, Y mnemonic) pairs:", len(pairs))
    for (a, b), c in pairs.most_common(30):
        print("   %5d  %s :: %s" % (c, a, b))
    print()

    print("=== field discovery ===")
    discover(allrecs, lambda r: vnum(r["ox"][0]) if r["ox"] else None, "vdstX = X.operand[0]")
    discover(allrecs, lambda r: vnum(r["oy"][0]) if r["oy"] else None, "vdstY = Y.operand[0]")
    discover(allrecs, lambda r: vnum(r["ox"][1]) if len(r["ox"]) > 1 else None, "X.operand[1]")
    discover(allrecs, lambda r: vnum(r["oy"][1]) if len(r["oy"]) > 1 else None, "Y.operand[1]")
    discover(allrecs, lambda r: vnum(r["ox"][-1]) if len(r["ox"]) > 1 else None, "X.operand[-1]")
    discover(allrecs, lambda r: vnum(r["oy"][-1]) if len(r["oy"]) > 1 else None, "Y.operand[-1]")

    print()
    print("=== sample records (first 25) ===")
    for r in allrecs[:25]:
        print("  0x%06X  V=%016X  %s :: %s" % (r["addr"], r["V"], r["x"], r["y"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
