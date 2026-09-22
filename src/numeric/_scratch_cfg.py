#!/usr/bin/env python3
"""scratch: structural CFG analysis of the 16AS code object disassembly."""
import re
import sys
import collections

PATH = r"<PROJECT_ROOT>\p16aw\numeric\_disasm_gfx1030.txt"

INS = re.compile(r"^\s+([a-z][a-z0-9_.]*)\s*(.*?)\s*//\s*([0-9A-Fa-f]+):\s*([0-9A-Fa-f ]+?)\s*(?:<[^>]*>)?\s*$")
SYM = re.compile(r"^([0-9A-Fa-f]+)\s+<([^>]+)>:")

prog = []          # (addr, op, text, raw)
for line in open(PATH, encoding="utf-8", errors="replace"):
    m = INS.match(line)
    if m:
        prog.append((int(m.group(3), 16), m.group(1), m.group(2).strip(),
                     m.group(4).strip()))
    else:
        m = SYM.match(line)
        if m:
            print("SYMBOL %s at %s" % (m.group(2), m.group(1)))

print("parsed %d instructions" % len(prog))
addr2idx = {a: i for i, (a, _, _, _) in enumerate(prog)}

BRANCH = {"s_cbranch_scc0", "s_cbranch_scc1", "s_cbranch_execz",
          "s_cbranch_execnz", "s_cbranch_vccz", "s_cbranch_vccnz",
          "s_cbranch_cdbgsys", "s_branch"}
END = {"s_endpgm", "s_setpc_b64", "s_swappc_b64"}

# decode branch targets
edges = {}
for i, (a, op, txt, raw) in enumerate(prog):
    if op in BRANCH:
        tgt = None
        m = re.search(r"<[^>]*\+0x([0-9A-Fa-f]+)>", txt)
        if m:
            tgt = None  # relative inside; recompute from encoding below
        # encoding: last field is the signed 16-bit offset in dwords
        enc = int(raw.split()[0], 16)
        off = enc & 0xFFFF
        if off & 0x8000:
            off -= 0x10000
        tgt = a + 4 + 4 * off
        edges[a] = tgt
        print("  branch %s @%x -> %x" % (op, a, tgt if tgt else -1))

# back edges => natural loops
back = {a: t for a, t in edges.items() if t is not None and t <= a}
print("\nback edges: %d" % len(back))
for a, t in sorted(back.items()):
    body = [x for x in prog if t <= x[0] <= a]
    c = collections.Counter(x[1] for x in body)
    print("  loop header %x .. %x  (%d instructions in body)"
          % (t, a, len(body)))
    for k in ("v_fma_mix_f32", "v_mul_f32_e32", "v_fma_f32",
              "v_cvt_f16_f32_e32", "v_cvt_f32_ubyte0_e32",
              "v_cvt_f32_f16_e32", "v_add_f32_e32", "v_fma_mixlo_f16",
              "global_load_dword", "global_load_ushort", "global_load_byte",
              "v_add_f16_e32", "s_waitcnt"):
        if c.get(k):
            print("      %-24s %d" % (k, c[k]))

# whole-kernel census and, for each arithmetic op, the containing loop
print("\nper-op location map (loop membership):")
loop_ranges = sorted((t, a) for a, t in back.items())
def which_loops(addr):
    return [("%x..%x" % (t, a)) for t, a in loop_ranges if t <= addr <= a]

for op in ("v_fma_mix_f32", "v_mul_f32_e32", "v_fma_f32", "v_cvt_f16_f32_e32",
           "v_cvt_f32_f16_e32", "v_add_f32_e32", "v_fma_mixlo_f16",
           "v_add_f16_e32"):
    locs = [(a, which_loops(a)) for a, o, _, _ in prog if o == op]
    c = collections.Counter(tuple(l) for _, l in locs)
    print("  %-20s n=%3d  %s" % (op, len(locs),
          dict((("+".join(k) if k else "straight-line"), v)
               for k, v in c.items())))
