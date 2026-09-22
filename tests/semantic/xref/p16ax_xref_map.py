#!/usr/bin/env python3
"""T-XREF: complete reverse bit-map of the VOPD 64-bit encoding.

For every bit position p of the instruction word V, find every architectural
signal whose per-record signature is identical to bit p.  Signals considered:
operand value bits, mnemonic one-hots, and literal-marker flags.
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


def parse_dis(path):
    out = []
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
            out.append({"addr": addr, "V": words[0] | (words[1] << 32),
                        "nwords": len(words), "x": xs.strip(), "y": ys.strip()})
    return out


def split_side(t):
    p = t.split(None, 1)
    return p[0], ([o.strip() for o in p[1].split(",")] if len(p) > 1 else [])


def kov(tok):
    tok = tok.strip()
    m = VRE.match(tok)
    if m:
        return ("v", int(m.group(1)))
    m = SRE.match(tok)
    if m:
        return ("s", int(m.group(1)))
    return ("other", None)


def F(V, hi, lo):
    return (V >> lo) & ((1 << (hi - lo + 1)) - 1)


def main():
    recs = []
    for n in DISS:
        p = os.path.join(DISDIR, n)
        if os.path.exists(p):
            recs.extend(parse_dis(p))
    for r in recs:
        r["mx"], r["ox"] = split_side(r["x"])
        r["my"], r["oy"] = split_side(r["y"])
    N = len(recs)
    print("records:", N)

    # ---- candidate signals -------------------------------------------------
    sigs = {}   # name -> int bitset over records

    def add_sig(name, fn):
        s = 0
        for i, r in enumerate(recs):
            if fn(r):
                s |= (1 << i)
        sigs[name] = s

    def opn(side, idx):
        def f(r):
            ops = r[side]
            if len(ops) <= idx:
                return None
            k, v = kov(ops[idx])
            return v if k in ("v", "s") else None
        return f

    names = [("X", "ox"), ("Y", "oy")]
    for tag, side in names:
        for i in range(4):
            for b in range(9):
                def mk(f=opn(side, i), b=b):
                    def g(r):
                        v = f(r)
                        return None if v is None else (v >> b) & 1
                    return g
                add_sig("%s.op%d[%d]" % (tag, i, b), mk())

    # mnemonic one-hots
    for tag, key in (("X", "mx"), ("Y", "my")):
        for mn in sorted(set(r[key] for r in recs)):
            add_sig("%s.mn=%s" % (tag, mn), lambda r, k=key, m=mn: r[k] == m)

    # literal / nwords flags
    add_sig("has_literal", lambda r: r["nwords"] > 2)

    # ---- V bit signatures ---------------------------------------------------
    vsig = []
    for p in range(64):
        s = 0
        for i, r in enumerate(recs):
            if (r["V"] >> p) & 1:
                s |= (1 << i)
        vsig.append(s)

    # constant-bit detection
    print()
    print("=== reverse map (V bit -> signals with identical signature) ===")
    free = []
    for p in range(64):
        s = vsig[p]
        if s == 0:
            print("  V[%2d] = always 0" % p)
            continue
        if s == (1 << N) - 1:
            print("  V[%2d] = always 1" % p)
            continue
        hits = [nm for nm, ss in sigs.items() if ss == s]
        hits = [h for h in hits if "mn=" not in h] or hits
        if hits:
            print("  V[%2d] -> %s" % (p, ", ".join(sorted(hits)[:6])))
        else:
            free.append(p)
            print("  V[%2d] -> (no match)  popcount=%d" % (p, bin(s).count("1")))
    print()
    print("unmatched V bits:", free)

    # ---- opcode field hunt --------------------------------------------------
    print()
    print("=== X-half [31:17] vs X mnemonic ===")
    for hi, lo in [(24, 17), (31, 25), (23, 17), (31, 24), (22, 17), (21, 17)]:
        m = collections.defaultdict(collections.Counter)
        for r in recs:
            m[r["mx"]][F(r["V"], hi, lo)] += 1
        print(" field[%d:%d]:" % (hi, lo))
        for mn in sorted(m):
            print("     %-24s %s" % (mn, sorted(m[mn].items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
