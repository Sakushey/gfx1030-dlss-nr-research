#!/usr/bin/env python3
"""T-XREF: identify the VOPD opcode fields and check they induce functions."""
import os
import re
import sys
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DISDIR = os.path.join(ROOT, "p16aw", "vopd")
DISS = ["ACTUAL_PARENT_sym.dis", "ACTUAL_PARENT_full.dis"]


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
            out.append({"V": words[0] | (words[1] << 32),
                        "mx": xs.strip().split()[0], "my": ys.strip().split()[0]})
    return out


def F(V, hi, lo):
    return (V >> lo) & ((1 << (hi - lo + 1)) - 1)


def is_function(recs, bits, key, val):
    m = {}
    for r in recs:
        k = tuple((r["V"] >> b) & 1 for b in bits)
        v = r[key]
        if k in m and m[k] != v:
            return False, (k, m[k], v)
        m[k] = v
    return True, len(m)


def main():
    recs = []
    for n in DISS:
        p = os.path.join(DISDIR, n)
        if os.path.exists(p):
            recs.extend(parse_dis(p))
    print("records:", len(recs))

    for label, bits in [
        ("V[25:17] 9b", list(range(17, 26))),
        ("V[25:22] 4b", list(range(22, 26))),
        ("V[21:17] 5b", list(range(17, 22))),
        ("V[24:17] 8b", list(range(17, 25))),
        ("V[25:18] 8b", list(range(18, 26))),
    ]:
        okx, ix = is_function(recs, bits, "mx", None)
        oky, iy = is_function(recs, bits, "my", None)
        both = {}
        conflict = None
        for r in recs:
            k = tuple((r["V"] >> b) & 1 for b in bits)
            p = (r["mx"], r["my"])
            if k in both and both[k] != p:
                conflict = (k, both[k], p)
                break
            both[k] = p
        print("%-14s mx:func=%s(%s) my:func=%s(%s) pair:func=%s(n=%d) %s"
              % (label, okx, ix if okx else "n/a", oky, iy if oky else "n/a",
                 conflict is None, len(both),
                 "" if conflict is None else "CONFLICT %s" % (conflict,)))

    print()
    # opcode tables for the winning split
    print("=== opcode tables ===")
    for name, bits, key in [("OP_X = V[25:22]", range(22, 26), "mx"),
                            ("OP_Y = V[21:17]", range(17, 22), "my")]:
        m = collections.defaultdict(collections.Counter)
        for r in recs:
            m[tuple((r["V"] >> b) & 1 for b in bits)][r[key]] += 1
        print(name)
        for k in sorted(m, key=lambda t: sum(bit << i for i, bit in enumerate(t))):
            val = sum(bit << i for i, bit in enumerate(k))
            print("   %2d (0b%s) -> %s" % (val, "".join(str(b) for b in reversed(k)),
                                           sorted(m[k].items())))

    # constant high bits
    print()
    for p in range(26, 32):
        c = collections.Counter((r["V"] >> p) & 1 for r in recs)
        print("  V[%d] counts=%s" % (p, dict(c)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
