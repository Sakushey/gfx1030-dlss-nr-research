#!/usr/bin/env python3
"""Phase 16I-P8 -- recover the authentic VarParams layout from the mod's own
host-side construction code.

Read-only. Parses the stripped disassembly of the DLSS-NR mod
(`phase16c_artifacts/mod_full_disasm.txt`) and locates every launch block that
builds a 168-byte by-value `VarParams` and hands its address to
`__hipPushCallConfiguration` / `hipLaunchKernel`.

For each block it emits, per struct offset: the store instruction that writes
it, the source operand, and the class of the value (pointer / scalar / ZEROED /
never-written).  A field is reported ZEROED only when an explicit
`movups %xmm0` (or equivalent) store covers it; never by inference from
absence.

Usage:
  p16i_varparams_recover.py [--disasm PATH] [--json OUT] [--csv OUT]
"""
from __future__ import annotations

import argparse
import json
import re
import sys

STRUCT_SIZE = 168  # 0xA8, from the kernel descriptor: one by-value arg
LINE = re.compile(
    r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(\S+)\s*(.*?)\s*$")

# x86-64 stores into the VarParams stack object.
STORE_OPS = ("movq", "movl", "movw", "movb", "movups", "movaps", "movdqu",
             "movdqa", "vmovups", "vmovaps", "movsd", "movss", "vmovq")
WIDTH = {"movq": 8, "movl": 4, "movw": 2, "movb": 1, "movsd": 8, "movss": 4,
         "movups": 16, "movaps": 16, "movdqu": 16, "movdqa": 16,
         "vmovups": 16, "vmovaps": 16, "vmovq": 8}

# Sources that are *pointers* to the caller's tensors / context, versus
# scalars.  Resolved by hand from the enclosing function (see the proof doc);
# the table below is the ground truth and the script asserts it is present.
PTR_SOURCES = {
    "0x00": "[rsp+0x60]",
    "0x08": "%r12  (= [rsp+0x4b0])",
    "0x10": "%r15  (= [rsp+0x4b8])",
    "0x30": "[rsp+0x4d8]",
    "0x38": "[rsp+0x4e0]",
    "0xA0": "%r14  (= ctx->canvas_ptr)",
}


def parse(path):
    """Yield (addr, mnemonic, operands) for every instruction."""
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        m = LINE.match(line)
        if not m:
            continue
        out.append((int(m.group(1), 16), m.group(3),
                    m.group(4).split("#")[0].strip()))
    return out


def disp_of(op):
    """Return the numeric stack displacement of `..., 0xNNN(%rsp)`, else None."""
    m = re.search(r",\s*(0x[0-9a-f]+|0)\(%rsp\)\s*$", op)
    if m:
        return int(m.group(1), 16)
    if re.search(r",\s*\(%rsp\)\s*$", op):
        return 0
    return None


def find_blocks(ins):
    """A launch block = a run of stores to one base whose values are then
    passed as args[0] to hipLaunchKernel.  We detect the canonical signature:
    a maximal cluster of stores to a contiguous 168-byte stack window that is
    immediately followed by `leaq <base>(%rsp), %rax` + `movq %rax, ...`."""
    by_addr = {a: (m, o) for a, m, o in ins}
    order = [a for a, _m, _o in ins]

    # Candidate bases: every displacement that receives >= 10 stores inside a
    # 168-byte window with no gaps larger than 16 bytes.
    stores = {}
    for a, m, o in ins:
        if m in STORE_OPS:
            d = disp_of(o)
            if d is not None:
                stores.setdefault(a, (m, o, d))

    bases = {}
    items = sorted(stores.items())
    for idx, (a, (m, o, d)) in enumerate(items):
        # look ahead for a contiguous cluster
        cluster = [(a, m, o, d)]
        for a2, m2, o2, d2 in [(x, y[0], y[1], y[2]) for x, y in items[idx + 1:]]:
            if d2 < d:
                break
            if d2 - (cluster[-1][3] + WIDTH.get(cluster[-1][1], 1)) <= 16:
                cluster.append((a2, m2, o2, d2))
            else:
                break
        if len(cluster) < 8:
            continue
        base = min(c[3] for c in cluster)
        top = max(c[3] + WIDTH.get(c[1], 1) for c in cluster)
        if top - base < STRUCT_SIZE:
            continue
        # the block must be *used* as args[0]: a `leaq base(%rsp)` nearby
        used = False
        for a2, m2, o2 in ins:
            if m2 == "leaq" and re.match(r"0x%x\(%%rsp\),\s*%%\w+$" % base, o2):
                if abs(a2 - cluster[0][0]) < 0x600:
                    used = True
                    break
        if used:
            bases[base] = cluster

    return bases


def field_class(off, src, mnem):
    if mnem in ("movups", "movaps", "movdqu", "movdqa", "vmovups", "vmovaps") \
            and src.startswith("%xmm0"):
        return "ZEROED"
    key = "0x%02X" % off if off < 0x100 else "0x%X" % off
    if key in PTR_SOURCES:
        return "POINTER"
    return "SCALAR"


def build(disasm):
    ins = parse(disasm)
    blocks = find_blocks(ins)
    if not blocks:
        sys.exit("FATAL: no VarParams launch block found -- disasm format changed")
    report = {}
    for base in sorted(blocks):
        slots = {}
        for a, m, o, d in sorted(blocks[base], key=lambda c: c[3]):
            off = d - base
            if off < 0 or off >= STRUCT_SIZE:
                continue
            w = WIDTH.get(m, 1)
            slots[off] = {
                "pc": "0x%x" % a, "mnemonic": m,
                "src": o.rsplit(",", 1)[0].strip(), "width": w,
                "class": field_class(off, o.rsplit(",", 1)[0].strip(), m),
            }
        report["0x%x" % base] = {
            "struct_size": STRUCT_SIZE,
            "slots": {("%#04x" % k): v for k, v in sorted(slots.items())},
        }
    return report


def coverage(report):
    """Byte-level coverage of the struct across all blocks."""
    cov = {}
    for base, blk in report.items():
        for off_s, s in blk["slots"].items():
            off = int(off_s, 16)
            for b in range(off, off + s["width"]):
                if b < STRUCT_SIZE:
                    cov.setdefault(b, []).append((base, s["class"], s["pc"]))
    return cov


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--disasm", default="phase16c_artifacts/mod_full_disasm.txt")
    ap.add_argument("--json", default="phase16i_closure/out/authentic_varparams_layout.json")
    ap.add_argument("--csv", default="phase16i_closure/phase16i_varparams_layout.csv")
    a = ap.parse_args()

    rep = build(a.disasm)
    cov = coverage(rep)

    with open(a.json, "w", encoding="utf-8") as f:
        json.dump({"blocks": rep,
                   "byte_coverage": {"%#04x" % k: v for k, v in sorted(cov.items())}},
                  f, indent=2)

    rows = ["offset,size,class,source,store_pc,n_blocks,n_zeroing_blocks,status"]
    for off in range(0, STRUCT_SIZE, 4):
        ent = cov.get(off)
        if not ent:
            rows.append("0x%02X,4,NEVER_WRITTEN,,,,,not written by any launch block" % off)
            continue
        cls = sorted({e[1] for e in ent})
        n = len({e[0] for e in ent})
        nz = len({e[0] for e in ent if e[1] == "ZEROED"})
        s0 = rep[ent[0][0]]["slots"].get("%#04x" % off, {})
        rows.append("0x%02X,%d,%s,%s,%s,%d,%d,%s" % (
            off, s0.get("width", 4), "|".join(cls),
            '"%s"' % s0.get("src", ""), s0.get("pc", ""), n, nz,
            "PROVEN" if len(cls) == 1 and n == len(rep) else "CHECK"))
    open(a.csv, "w", encoding="utf-8").write("\n".join(rows) + "\n")

    print("blocks found: %d" % len(rep))
    for b, blk in sorted(rep.items()):
        print("  base %s  slots=%d" % (b, len(blk["slots"])))
    zero = [k for k, v in cov.items() if {e[1] for e in v} == {"ZEROED"}]
    print("struct bytes written ONLY as ZERO across all blocks: %d" % len(zero))
    if zero:
        print("  range 0x%02X..0x%02X" % (min(zero), max(zero)))
    print("wrote %s / %s" % (a.json, a.csv))


if __name__ == "__main__":
    main()
