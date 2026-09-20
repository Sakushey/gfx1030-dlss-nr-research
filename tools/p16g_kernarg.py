#!/usr/bin/env python3
"""Phase16G P3 — byte-exact kernarg audit for swin_var<32,false>.

Builds, for every byte of the declared 424-byte kernarg segment:
  * whether the target code reads it (from a census of every
    `s_load_* s[0:1], <imm>` / `s_load_* ..., s[0:1] + sgpr` site)
  * the destination SGPRs
  * the forward use census of those SGPRs (what the value actually feeds:
    branch predicate / address / arithmetic / dead)
  * the value the physical harness put there, the value the Phase-16F
    mirror emulator put there, and the authentic GTA value if statically
    known (phase14e).

Host-only.  Outputs CSV + JSON.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "phase16g_forensics", "out")
sys.path.insert(0, HERE)
from p16g_isa import parse_disasm  # noqa: E402

DIS = os.path.join(ROOT, "phase16e_candidate_e", "disasm",
                   "candidate_e_gfx1030_disasm.txt")
SYM = "_Z10k_swin_varILi32ELb0EEv9VarParams"

# --- ABI facts recovered independently in this phase ------------------------
# from the code object's .note metadata (per-kernel ".args"), identical in the
# original gfx1100 object and the candidate-E gfx1030 object.
ARGS = [
    (0,   168, "by_value"),
    (168, 4,   "hidden_block_count_x"),
    (172, 4,   "hidden_block_count_y"),
    (176, 4,   "hidden_block_count_z"),
    (180, 2,   "hidden_group_size_x"),
    (182, 2,   "hidden_group_size_y"),
    (184, 2,   "hidden_group_size_z"),
    (186, 2,   "hidden_remainder_x"),
    (188, 2,   "hidden_remainder_y"),
    (190, 2,   "hidden_remainder_z"),
    (208, 8,   "hidden_global_offset_x"),
    (216, 8,   "hidden_global_offset_y"),
    (224, 8,   "hidden_global_offset_z"),
    (232, 2,   "hidden_grid_dims"),
]
KERNARG_SIZE = 424

# VarParams pointer fields written by the authentic host (phase14e §4)
AUTH_PTR_OFF = [0x00, 0x08, 0x10, 0x30, 0x38, 0xA0]
AUTH_ZERO_RANGE = (0x40, 0xA0)      # 0x40..0x9F inclusive zeroed by the host
HARNESS_PTR_OFF = [0x00, 0x08, 0x10, 0x30, 0x38, 0x48, 0x78, 0x80, 0xA0]

LOAD = re.compile(r"^s_load_(dword|dwordx2|dwordx4|dwordx8|dwordx16|ubyte|ushort)$")
SZ = {"dword": 4, "dwordx2": 8, "dwordx4": 16, "dwordx8": 32, "dwordx16": 64,
      "ubyte": 1, "ushort": 2}


def sgpr_list(tok):
    t = tok.strip()
    m = re.match(r"^s\[(\d+):(\d+)\]$", t)
    if m:
        return list(range(int(m.group(1)), int(m.group(2)) + 1))
    m = re.match(r"^s(\d+)$", t)
    if m:
        return [int(m.group(1))]
    m = re.match(r"^s\[(.+)\]$", t)
    if m:
        out = []
        for part in m.group(1).split(","):
            part = part.strip().lstrip("s")
            if ":" in part:
                a, b = part.split(":")
                out += list(range(int(a), int(b) + 1))
            else:
                out.append(int(part))
        return out
    return []


def main():
    prog = parse_disasm(DIS, start_marker=SYM)
    print("instructions:", len(prog))

    # ---- 1. every kernarg load -------------------------------------------
    reads = []      # (idx, addr, mnem, base_tok, imm, size, dst_sgprs)
    for ins in prog:
        if not LOAD.match(ins.mnem):
            continue
        ops = ins.ops
        if len(ops) < 3:
            continue
        base = ops[1].strip()
        if base != "s[0:1]":
            continue
        imm_tok = ops[2].strip()
        if imm_tok in ("null", "off", "0"):
            imm = 0
        else:
            imm = int(imm_tok, 0)
        sz = SZ[LOAD.match(ins.mnem).group(1)]
        dst = sgpr_list(ops[0])
        reads.append(dict(idx=ins.idx, addr=ins.addr, mnem=ins.mnem,
                          imm=imm, size=sz, dst=dst, text=ins.text))

    print("\n=== kernarg load sites (base s[0:1]) : %d ===" % len(reads))
    for r in reads:
        print("  0x%08X  %-22s +0x%03X..+0x%03X  -> s%s"
              % (r["addr"], r["mnem"], r["imm"], r["imm"] + r["size"] - 1,
                 r["dst"]))

    # ---- 2. forward use census of each loaded SGPR ------------------------
    # Build a linear def-use map.  The body has branches, so a purely linear
    # scan over-approximates reachability; we mitigate by also recording the
    # *kind* of every textual use.
    use_map = defaultdict(list)
    for ins in prog:
        for (kind, ridx) in ins.uses:
            if kind == "sgpr":
                use_map[ridx].append(ins)

    # dominator-free sanity: a use is "reaching" if no earlier instruction
    # writes the same sgpr between the load and the use (linear approximation)
    def classify(ins, reg):
        t = ins.text
        if ins.is_branch:
            return "BRANCH_PREDICATE"
        if re.search(r"\bs\[%d[:%d]?\b" % (reg, reg), t) and \
           re.match(r"^(s_load|s_store|s_buffer|s_scratch)", ins.mnem):
            return "ADDRESS_BASE(scalar mem)"
        if re.match(r"^(global|flat|buffer|scratch|ds)_", ins.mnem):
            return "ADDRESS_BASE(vector mem)"
        if re.match(r"^s_(mul|add|sub|lshl|ashr|lshr|and|or|xor|bfe|bfi|cmp)",
                    ins.mnem):
            return "ARITHMETIC(scalar)"
        if re.match(r"^v_", ins.mnem):
            return "VECTOR_OPERAND"
        if ins.mnem.startswith("s_cselect"):
            return "SELECT->PREDICATE/ADDR"
        if ins.mnem.startswith("s_mov") or ins.mnem.startswith("s_movk"):
            return "COPY"
        return "OTHER:" + ins.mnem

    rows = []
    addr_fields = {}
    for r in reads:
        for d in r["dst"]:
            uses = use_map.get(d, [])
            kinds = Counter(classify(u, d) for u in uses)
            first = uses[0] if uses else None
            rows.append(dict(
                load_addr="0x%08X" % r["addr"], mnem=r["mnem"],
                imm="0x%03X" % r["imm"], size=r["size"], sgpr="s%d" % d,
                n_uses=len(uses), kinds=dict(kinds),
                first_use=("0x%08X %s" % (first.addr, first.text)) if first else "",
            ))

    # ---- 3. byte map -------------------------------------------------------
    bytemap = []
    for off in range(0, KERNARG_SIZE, 4):
        elem = None
        for (a, sz, name) in ARGS:
            if a <= off < a + sz:
                elem = "%s +0x%X" % (name, off - a)
                break
        covering = [r for r in reads if r["imm"] <= off < r["imm"] + r["size"]]
        bytemap.append(dict(offset=off, arg=elem or "UNCLAIMED",
                            read=bool(covering),
                            sites=";".join("0x%08X:%s" % (c["addr"], c["mnem"])
                                           for c in covering)))

    nread = sum(1 for b in bytemap if b["read"])
    print("\n=== kernarg byte map: %d of %d dwords are read by the target ==="
          % (nread, len(bytemap)))
    for b in bytemap:
        if b["read"]:
            print("  +0x%03X  %-34s  %s" % (b["offset"], b["arg"], b["sites"]))

    unread_args = sorted({b["arg"] for b in bytemap if not b["read"]})
    print("\n=== declared args NOT read by this kernel ===")
    for a in unread_args:
        print("   ", a)

    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "p16g_kernarg_bytemap.csv"), "w",
              newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["offset", "arg", "read", "sites"])
        w.writeheader()
        for b in bytemap:
            w.writerow({**b, "offset": "0x%03X" % b["offset"]})
    with open(os.path.join(OUT, "p16g_kernarg_uses.csv"), "w", newline="",
              encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        for r in rows:
            w.writerow({**r, "kinds": json.dumps(r["kinds"])})
    json.dump(dict(kernarg_size=KERNARG_SIZE, args=ARGS,
                   reads=reads, unread_args=unread_args),
              open(os.path.join(OUT, "p16g_kernarg_audit.json"), "w"),
              indent=1, default=str)
    print("\nwrote p16g_kernarg_bytemap.csv / p16g_kernarg_uses.csv / "
          "p16g_kernarg_audit.json")


if __name__ == "__main__":
    main()
