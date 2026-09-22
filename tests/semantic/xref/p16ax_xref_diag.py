#!/usr/bin/env python3
"""T-XREF diagnostic: resolve the vdstY-bit0 anomaly and the unassigned fields."""
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
            recs.append({"addr": addr, "V": words[0] | (words[1] << 32),
                         "words": words, "x": xs.strip(), "y": ys.strip()})
    return recs


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
    print("total records:", len(recs))

    # How often is V bit 48 / bit 40 set?
    for b in (8, 40, 48, 24, 16):
        c = sum(1 for r in recs if (r["V"] >> b) & 1)
        print("  V[%2d] set in %5d / %d" % (b, c, len(recs)))
    print()

    # H1: is (vdstY & 1) == ((vdstX + 1) & 1) ?
    h1_bad = h1_tot = 0
    examples = []
    for r in recs:
        if not r["ox"] or not r["oy"]:
            continue
        kx, vx = kov(r["ox"][0])
        ky, vy = kov(r["oy"][0])
        if kx != "v" or ky != "v":
            continue
        h1_tot += 1
        if (vy & 1) != ((vx + 1) & 1):
            h1_bad += 1
            if len(examples) < 5:
                examples.append((hex(r["addr"]), r["x"], r["y"]))
    print("H1 (vdstY&1 == (vdstX+1)&1):  %d violations / %d" % (h1_bad, h1_tot))
    for e in examples:
        print("     ", e)
    print()

    # Is field[55:49] == vdstY>>1 ?
    bad = tot = 0
    for r in recs:
        if not r["oy"]:
            continue
        ky, vy = kov(r["oy"][0])
        if ky != "v":
            continue
        tot += 1
        if F(r["V"], 55, 49) != (vy >> 1):
            bad += 1
            if bad <= 5:
                print("     f55:49 mismatch", hex(r["addr"]), r["y"],
                      "field=%d want=%d" % (F(r["V"], 55, 49), vy >> 1))
    print("field[55:49] == vdstY>>1 :  %d violations / %d" % (bad, tot))
    print()

    # Is vdstY exactly reconstructible?
    bad = tot = 0
    for r in recs:
        if not r["oy"] or not r["ox"]:
            continue
        kx, vx = kov(r["ox"][0])
        ky, vy = kov(r["oy"][0])
        if kx != "v" or ky != "v":
            continue
        tot += 1
        guess = (F(r["V"], 55, 49) << 1) | ((vx + 1) & 1)
        if guess != vy:
            bad += 1
            if bad <= 5:
                print("     recon mismatch", hex(r["addr"]), r["x"], "::", r["y"],
                      "guess=%d want=%d" % (guess, vy))
    print("vdstY == (f[55:49]<<1) | ((vdstX+1)&1) :  %d violations / %d" % (bad, tot))
    print()

    # vsrc1Y: which field?
    for (hi, lo) in [(48, 41), (47, 40)]:
        bad = tot = 0
        for r in recs:
            if len(r["oy"]) < 3:
                continue
            k, v = kov(r["oy"][-1])
            if k != "v":
                continue
            tot += 1
            if F(r["V"], hi, lo) != v:
                bad += 1
        print("vsrc1Y == field[%d:%d] : %d violations / %d" % (hi, lo, bad, tot))
    print()

    # what does V[40] look like vs src0Y 9th bit
    print("V[40] value counts:", collections.Counter((r["V"] >> 40) & 1 for r in recs))

    # free-field census: for each unidentified bit, how many distinct values
    print()
    print("field value distributions for unidentified ranges:")
    for (hi, lo, name) in [(24, 17, "f24:17"), (31, 25, "f31:25"),
                           (40, 40, "f40"), (48, 48, "f48")]:
        c = collections.Counter(F(r["V"], hi, lo) for r in recs)
        print("  %-8s distinct=%3d  top=%s" % (name, len(c), c.most_common(6)))

    # correlate f31:25 with X mnemonic
    print()
    m = collections.defaultdict(set)
    for r in recs:
        m[r["mx"]].add(F(r["V"], 31, 25))
        m["Y:" + r["my"]].add(F(r["V"], 48, 48))
    for k in sorted(m)[:40]:
        print("   %-30s -> %s" % (k, sorted(m[k])[:8]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
