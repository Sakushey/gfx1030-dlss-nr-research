"""Phase 8A/8B/8I static analysis of the original gfx1100 k_conv_splitk.

Q1: locate every kernarg-field load (base s[0:1]) and prove which field the
    harness modeled as split_count drives the main work loop.
Q2: prove (original side) that field == 0 skips the WMMA site and all
    dangerous work on the no-work CFG.
Q3/8I: recover launch-geometry constraints visible in the code (reads of
    dispatch/global ids, workgroup size limits, hidden args).

HOST-ONLY analysis; no HIP, no GPU.
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from disasm_lib import parse_orig_disasm, VCCZ

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "phase8_static", "out")
os.makedirs(OUT, exist_ok=True)

rows = parse_orig_disasm(os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_disassembly.txt"))
# keep only this kernel's section (0x69000..0x6B3FF), sorted
func_base = 0x69000
rows = [r for r in rows if func_base <= r["address"] <= 0x6B3FF]
rows.sort(key=lambda r: r["address"])
print("physical sites:", len(rows))

def addr_of(row): return row["address"]

rows = [r for r in rows if 0x69000 <= r["address"] <= 0x6B3FF]
print("physical sites:", len(rows))

by_addr = {}
for r in rows:
    by_addr.setdefault(r["address"], []).append(r)

with open(os.path.join(OUT, "8a1_kernarg_field_loads.txt"), "w") as f:
    f.write("=== All scalar loads whose base is s[0:1] (kernarg segment base) ===\n")
    for r in rows:
        ops = r["operands"]
        if r["mnemonic"].startswith("s_load") and ("s[0:1]" in ops or ", s0," in ops or ", s0 " in ops):
            f.write(f"0x{r['address']:06X}  {r['text']}\n")

with open(os.path.join(OUT, "8a2_s18_uses.txt"), "w") as f:
    f.write("=== Every reference to s18 (first load target = kernarg+0x28) ===\n")
    for r in rows:
        if "s18" in r["text"] and not r["mnemonic"].startswith("s_load"):
            f.write(f"0x{r['address']:06X}  {r['text']}\n")

with open(os.path.join(OUT, "8a3_all_branches.txt"), "w") as f:
    f.write("=== All control-flow instructions (target via comment suffix, "
            "cross-checked with displacement math) ===\n")
    for r in rows:
        m = r["mnemonic"]
        if m.startswith("s_branch") or m.startswith("s_cbranch") or m in ("s_endpgm", "s_trap"):
            # displacement = first whitespace-separated operand, decimal
            tgt = None
            first = r["operands"].split()[0] if r["operands"] else ""
            if first.lstrip("-").isdigit():
                disp = int(first)
                if disp >= 0x8000:
                    disp -= 0x10000
                tgt = r["address"] + 4 + disp * 4
            resolved = r["rel_off"]
            resolved_abs = func_base + resolved if resolved is not None else None
            agree = "" if tgt is None or resolved_abs is None or tgt == resolved_abs else "  <-- MISMATCH"
            f.write(f"0x{r['address']:06X}  {r['text']:<70} disp_tgt={('0x%06X' % tgt) if tgt is not None else '-':>10}"
                    f"  sym_tgt={('0x%06X' % resolved_abs) if resolved_abs is not None else '-':>10}{agree}\n")

def window(lo, hi, tag):
    with open(os.path.join(OUT, f"8a4_window_{tag}.txt"), "w") as f:
        f.write(f"=== instruction window {lo:#x}..{hi:#x} ===\n")
        for r in rows:
            if lo <= r["address"] <= hi:
                f.write(f"0x{r['address']:06X}  {r['text']}\n")

window(0x69000, 0x691C0, "entry_through_loop_eq")
window(0x6AFD4 - 8, 0x6B3FF, "post_work_to_end")
window(0x69C80 - 16, 0x69CB0 + 16, "wmma_site")

# s_load offsets from s[0:1]: collect distinct offsets
import re
offpat = re.compile(r"0x([0-9a-f]+)\s*$")
seen = {}
for r in rows:
    if r["mnemonic"].startswith("s_load") and "s[0:1]" in r["operands"]:
        mm = offpat.search(r["operands"])
        if mm:
            off = int(mm.group(1), 16)
            seen.setdefault(off, []).append((r["address"], r["mnemonic"], r["operands"]))
with open(os.path.join(OUT, "8a5_kernarg_offsets.json"), "w") as f:
    json.dump({hex(k): [f"0x{a:06X} {m} {o}" for a, m, o in v] for k, v in sorted(seen.items())},
              f, indent=1)

print("kernarg offsets read (hex):", sorted(hex(k) for k in seen))
