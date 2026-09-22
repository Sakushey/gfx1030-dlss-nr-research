#!/usr/bin/env python3
"""T-XREF: independent VOPD decoder for gfx11 `v_dual_*` encodings.

Derived from the raw symbol bytes plus the AMD VOP2 source-operand coding,
and cross-validated against llvm-objdump's own text on every record in the
tree (an independent decoder).  No other worker's model is consulted.

Bit layout established by exhaustive bit-signature matching over 1632 records
(see p16ax_xref_bits.py / p16ax_xref_map.py / p16ax_xref_optest.py):

  low 32 bits  (first printed dword)
    [8:0]    SRC0_X    9-bit standard VOP source operand
    [16:9]   VSRC1_X   8-bit, v0..v255 only
    [21:17]  OP_Y      5-bit
    [25:22]  OP_X      4-bit
    [31:26]  constant 0b110010  (VOPD format marker)
  high 32 bits (second printed dword)
    [40:32]  SRC0_Y    9-bit standard VOP source operand
    [48:41]  VSRC1_Y   8-bit, v0..v255 only
    [55:49]  VDST_Y[7:1]  (7 bits -- see CAVEAT below)
    [63:56]  VDST_X    8-bit

CAVEAT (measured, not assumed): VDST_Y bit 0 has NO bit position anywhere in
the 64-bit encoding -- exhaustive bit-signature search over all 64 positions
finds nothing.  Over all 1632 records it equals (~VDST_X & 1), i.e.
VDST_Y = (field[55:49] << 1) | ((VDST_X + 1) & 1), with 0 violations.  This
relation is EMPIRICAL: it is not derivable from the ISA material available in
this tree.  It is flagged as a modelling ceiling in XREF_ORACLE_RESULT.json.
"""
import os
import re
import sys
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DISDIR = os.path.join(ROOT, "p16aw", "vopd")

# ---------------------------------------------------------------- opcodes ---
OP_X = {0: "fmac_f32", 1: "fmaak_f32", 2: "fmamk_f32", 3: "mul_f32",
        4: "add_f32", 5: "sub_f32", 8: "mov_b32", 9: "cndmask_b32",
        10: "max_f32", 11: "min_f32"}
OP_Y = dict(OP_X)
OP_Y.update({16: "add_nc_u32", 17: "lshlrev_b32", 18: "and_b32"})

# number of explicit source operands printed by llvm-objdump, per mnemonic
NARGS = {"mov_b32": 1, "cndmask_b32": 2, "lshlrev_b32": 2, "and_b32": 2,
         "add_nc_u32": 2, "add_f32": 2, "sub_f32": 2, "mul_f32": 2,
         "max_f32": 2, "min_f32": 2, "fmac_f32": 2, "fmaak_f32": 3,
         "fmamk_f32": 3}

FLOAT_CONST = {240: "0.5", 241: "-0.5", 242: "1.0", 243: "-1.0",
               244: "2.0", 245: "-2.0", 246: "4.0", 247: "-4.0",
               248: "0.15915494"}


def src0(code):
    """Decode a 9-bit VOP SRC0 field."""
    if 0 <= code <= 127:
        return ("s", code)
    if 128 <= code <= 192:
        return ("i", code - 128)
    if 193 <= code <= 208:
        return ("i", -(code - 192))
    if code in FLOAT_CONST:
        return ("f", FLOAT_CONST[code])
    if code == 254:
        return ("exec", 0)
    if code == 255:
        return ("lit", 0)
    if 256 <= code <= 511:
        return ("v", code - 256)
    return ("?", code)


def vsrc1(code):
    """8-bit VSRC1 field: always a VGPR index (v0..v255)."""
    return ("v", code)


def decode(V, literal=None):
    """Decode a 64-bit VOPD word into its two sub-instructions."""
    opx = (V >> 22) & 0xF
    opy = (V >> 17) & 0x1F
    vdstx = (V >> 56) & 0xFF
    fy = (V >> 49) & 0x7F
    vdsty = (fy << 1) | ((vdstx + 1) & 1)
    sx = src0(V & 0x1FF)
    sy = src0((V >> 32) & 0x1FF)
    vx = vsrc1((V >> 9) & 0xFF)
    vy = vsrc1((V >> 41) & 0xFF)
    return {
        "marker": (V >> 26) & 0x3F,
        "literal": literal,
        "x": {"op": OP_X.get(opx), "opc": opx, "vdst": vdstx,
              "src0": sx, "src0_code": V & 0x1FF, "vsrc1": vx},
        "y": {"op": OP_Y.get(opy), "opc": opy, "vdst": vdsty,
              "src0": sy, "src0_code": (V >> 32) & 0x1FF, "vsrc1": vy},
    }


def fmt(tok, literal):
    k, v = tok
    if k == "v":
        return "v%d" % v
    if k == "s":
        return "s%d" % v
    if k == "i":
        return "%d" % v
    if k == "f":
        return v
    if k == "lit":
        return "0x%x" % literal if literal is not None else "LITERAL?"
    if k == "exec":
        return "exec_lo"
    return "?%r" % (v,)


def render(side, literal):
    """Render one sub-instruction the way llvm-objdump does."""
    op = side["op"]
    if op is None:
        return None
    args = ["v%d" % side["vdst"]]
    n = NARGS[op]
    if op in ("fmaak_f32", "fmamk_f32"):
        # v_fmaak_f32 vdst, src0, src1, imm   (imm is the trailing literal)
        # v_fmamk_f32 vdst, src0, imm,  src1
        s0 = fmt(side["src0"], literal)
        s1 = fmt(side["vsrc1"], literal)
        if op == "fmaak_f32":
            args += [s0, s1, "0x%x" % literal]
        else:
            args += [s0, "0x%x" % literal, s1]
    else:
        if n >= 1:
            args.append(fmt(side["src0"], literal))
        if n >= 2:
            args.append(fmt(side["vsrc1"], literal))
    return "v_dual_%s %s" % (op, ", ".join(args))


# ------------------------------------------------------------- validation ---
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
                        "nwords": len(words),
                        "literal": words[2] if len(words) > 2 else None,
                        "x": " ".join(xs.split()), "y": " ".join(ys.split())})
    return out


def main():
    recs = []
    for name in ("ACTUAL_PARENT_sym.dis", "ACTUAL_PARENT_full.dis",
                 "CANDIDATE_F_full.dis"):
        p = os.path.join(DISDIR, name)
        if os.path.exists(p):
            recs.extend(parse_dis(p))
    print("records:", len(recs))

    n_ok = 0
    mism = []
    nword_hist = collections.Counter(r["nwords"] for r in recs)
    for r in recs:
        d = decode(r["V"], r["literal"])
        if d["marker"] != 0b110010:
            mism.append((r, "BAD_MARKER", d["marker"]))
            continue
        rx = render(d["x"], r["literal"])
        ry = render(d["y"], r["literal"])
        if rx == r["x"] and ry == r["y"]:
            n_ok += 1
        else:
            mism.append((r, rx, ry))
    print("nwords histogram:", dict(nword_hist))
    print("exact round-trip matches: %d / %d" % (n_ok, len(recs)))
    print("mismatches: %d" % len(mism))
    show = collections.Counter()
    for r, a, b in mism:
        show[(r["x"], a)] += 1
    for (want, got), c in show.most_common(15):
        print("   x%3d  want[%s]  got[%s]" % (c, want, got))
    print()
    for r, a, b in mism[:12]:
        print("  0x%06X  X want: %s" % (r["addr"], r["x"]))
        print("            X got : %s" % (a,))
        print("            Y want: %s" % (r["y"],))
        print("            Y got : %s" % (b,))
    return 0


if __name__ == "__main__":
    sys.exit(main())
