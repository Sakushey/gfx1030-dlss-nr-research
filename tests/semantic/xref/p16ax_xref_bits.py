#!/usr/bin/env python3
"""T-XREF: bit-level discovery of the VOPD layout.

For an architectural operand bit i, build a bitset signature over all records
where that operand is a plain VGPR.  Do the same for every bit position p of
the 64-bit instruction word V.  Where the two signatures are identical, bit i
of the operand IS bit p of V.  This finds fields even when they are not
byte-aligned or are interleaved.
"""
import os
import re
import sys
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DISDIR = os.path.join(ROOT, "p16aw", "vopd")
DISS = ["ACTUAL_PARENT_sym.dis", "ACTUAL_PARENT_full.dis"]

VRE = re.compile(r"^v(\d+)$")
SRE = re.compile(r"^s(\d+)$")
IRE = re.compile(r"^(0x[0-9a-fA-F]+|-?\d+)$")


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
            recs.append({"addr": addr,
                         "V": words[0] | (words[1] << 32),
                         "words": words,
                         "x": xs.strip(), "y": ys.strip()})
    return recs


def split_side(t):
    p = t.split(None, 1)
    return p[0], ([o.strip() for o in p[1].split(",")] if len(p) > 1 else [])


def operand_kind(tok):
    tok = tok.strip()
    if VRE.match(tok):
        return ("v", int(VRE.match(tok).group(1)))
    if SRE.match(tok):
        return ("s", int(SRE.match(tok).group(1)))
    if IRE.match(tok):
        try:
            return ("i", int(tok, 0))
        except ValueError:
            return ("i", None)
    return ("other", None)


def load():
    recs = []
    for name in DISS:
        p = os.path.join(DISDIR, name)
        if os.path.exists(p):
            recs.extend(parse_dis(p))
    for r in recs:
        r["mx"], r["ox"] = split_side(r["x"])
        r["my"], r["oy"] = split_side(r["y"])
    return recs


def bitset_for(recs, fn):
    """fn(r) -> 0/1, or None to exclude the record."""
    keep = [(i, fn(r)) for i, r in enumerate(recs)]
    s = 0
    n = 0
    for i, v in keep:
        if v is None:
            return None
        if v:
            s |= (1 << i)
        n += 1
    return s


def match_operand_bits(recs, getval, label, nb):
    """getval(r) -> int value (plain VGPR number) or None."""
    sub = [r for r in recs if getval(r) is not None]
    if len(sub) < 20:
        print("%-24s : too few records (%d)" % (label, len(sub)))
        return {}
    print("%-24s : n=%d  distinct values=%d" %
          (label, len(sub), len(set(getval(r) for r in sub))))

    # V bit signatures over the same subset (same indices)
    vsig = {}
    for p in range(64):
        s = 0
        for i, r in enumerate(sub):
            if (r["V"] >> p) & 1:
                s |= (1 << i)
        vsig[p] = s

    mapping = {}
    for i in range(nb):
        osig = 0
        for j, r in enumerate(sub):
            if (getval(r) >> i) & 1:
                osig |= (1 << j)
        hits = [p for p in range(64) if vsig[p] == osig]
        mapping[i] = hits
        print("    operand bit %d -> V bit positions %s" % (i, hits))
    return mapping


def main():
    recs = load()
    print("records:", len(recs))
    print()

    allv = lambda r: (len(r["ox"]) >= 1 and len(r["oy"]) >= 1)
    recs = [r for r in recs if allv(r)]

    def gx(i):
        def f(r):
            if len(r["ox"]) <= i:
                return None
            k, v = operand_kind(r["ox"][i])
            return v if k == "v" else None
        return f

    def gy(i):
        def f(r):
            if len(r["oy"]) <= i:
                return None
            k, v = operand_kind(r["oy"][i])
            return v if k == "v" else None
        return f

    for label, g, nb in [("vdstX (X.op[0])", gx(0), 8),
                         ("vdstY (Y.op[0])", gy(0), 8),
                         ("src0X (X.op[1])", gx(1), 8),
                         ("src0Y (Y.op[1])", gy(1), 8),
                         ("vsrc1Y (Y.op[-1])", lambda r: gy(-1)(r) if len(r["oy"]) >= 3 else None, 8),
                         ]:
        match_operand_bits(recs, g, label, nb)
        print()


if __name__ == "__main__":
    sys.exit(main())
