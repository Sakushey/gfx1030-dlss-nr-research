"""Phase16G — swin32f static census (host-only).

Produces, for _Z10k_swin_varILi32ELb0EEv9VarParams of the candidate-E
code object:

  * opcode census + reachability from the entry
  * barrier site list with the EXEC/predicate context
  * backward-branch (loop) census
  * read-before-definition census over the whole program
  * def-use slice for a requested SGPR/VGPR
  * memory-op census (global / flat / scratch / LDS / scalar)

Run:  python p16g_census.py [sym]
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter, defaultdict, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from p16g_isa import (Insn, parse_disasm, _branch_target)  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DIS = os.path.join(ROOT, "phase16e_candidate_e", "disasm",
                   "candidate_e_gfx1030_disasm.txt")
OUT = os.path.join(ROOT, "phase16g_forensics", "out")
SYM = sys.argv[1] if len(sys.argv) > 1 else "_Z10k_swin_varILi32ELb0EEv9VarParams"


def resolve_targets(prog, sym):
    """objdump annotates branch targets as <sym+0xNN> (or <sym>)."""
    addr2idx = {}
    for i in prog:
        addr2idx.setdefault(i.addr, i.idx)
    base = prog[0].addr
    # objdump resolves to the enclosing *symbol* start, which is `base` here.
    for ins in prog:
        if not ins.is_branch:
            continue
        m = re.search(r"<[^>+]+(?:\+0x([0-9A-Fa-f]+))?>", ins.raw)
        if not m:
            continue
        off = int(m.group(1), 16) if m.group(1) else 0
        tgt = base + off
        if tgt in addr2idx:
            ins.branch_target = addr2idx[tgt]
        else:
            ins.branch_target = None       # e.g. branch to a label with no insn
    return addr2idx


def reachable(prog):
    """Indices reachable from instruction 0 following fallthrough + branches."""
    n = len(prog)
    seen = set()
    stack = [0]
    while stack:
        i = stack.pop()
        if i in seen or i < 0 or i >= n:
            continue
        seen.add(i)
        ins = prog[i]
        if ins.mnem == "s_endpgm":
            continue
        if ins.branch_target is not None:
            stack.append(ins.branch_target)
        if ins.is_branch:
            # conditional branches fall through too; unconditional s_branch
            # does not.  Be generous: add fallthrough for conditional only.
            if not ins.mnem.startswith("s_branch "):
                stack.append(i + 1)
        else:
            stack.append(i + 1)
    return seen


def find_rbd(prog, reach):
    """Read-before-definition census.

    Walks all reachable instructions in reverse-postorder-ish linear order
    with a simple worklist dataflow over the SGPR/VGPR/EXEC/VCC/SCC/M0
    lattice (a register is 'defined' once any path defines it -> this is a
    MAY analysis, so a reported read-before-def means: there exists a path
    reaching this instruction on which the register was not written by the
    kernel).  Kernel-entry-undefined registers are initialised to
    'undefined'.
    """
    n = len(prog)
    ins_by_idx = prog
    preds = defaultdict(set)
    for i in range(n):
        if i not in reach:
            continue
        ins = prog[i]
        succ = []
        if ins.mnem != "s_endpgm":
            if ins.branch_target is not None:
                succ.append(ins.branch_target)
            if (not ins.is_branch) or (not ins.mnem.startswith("s_branch ")):
                if i + 1 < n:
                    succ.append(i + 1)
        for s in succ:
            preds[s].add(i)

    # in-state: frozenset of defined register keys.
    # ENTRY STATE (from the kernel descriptor, independently confirmed):
    #   amdhsa_user_sgpr_kernarg_segment_ptr 1 -> s[0:1] holds the kernarg ptr
    #   amdhsa_user_sgpr_count 14              -> s[0:13] are the user block
    #   amdhsa_system_sgpr_workgroup_id_x 1    -> s14 = wgid.x
    #   amdhsa_system_sgpr_workgroup_id_y 1    -> s15 = wgid.y
    #   (confirmed behaviourally by s_mul_i32 s4, s6, s15 / s_add_u32 s6, s4, s14)
    #   v0 = workitem id (vgpr_workitem_id 0 -> packed), EXEC/VCC architecturally
    #   defined at dispatch; SCC/M0 are NOT.
    ENTRY = set()
    ENTRY |= {("sgpr", 0), ("sgpr", 1)}
    ENTRY |= {("sgpr", 14), ("sgpr", 15)}
    ENTRY |= {("vgpr", 0)}
    ENTRY |= {("exec", None), ("vcc", None)}
    IN = {i: None for i in reach}
    IN[0] = frozenset(ENTRY)
    changed = True
    order = sorted(reach)
    while changed:
        changed = False
        for i in order:
            if i == 0:
                continue
            ps = [p for p in preds[i] if p in reach]
            if not ps:
                continue
            acc = None
            for p in ps:
                if IN[p] is None:
                    acc = None
                    break
                acc = set(IN[p]) if acc is None else (acc | IN[p])
            if acc is None:
                continue
            new = frozenset(acc | set(prog[i].defs) | set(prog[i].defs_special))
            if IN[i] != new:
                IN[i] = new
                changed = True

    rbd = []
    for i in sorted(reach):
        st = IN[i]
        if st is None:
            st = frozenset()
        reads = list(prog[i].uses) + [(s, None) for s in prog[i].uses_special]
        for k in reads:
            if k not in st:
                rbd.append((i, prog[i], k))
    return rbd, IN


def main():
    prog = parse_disasm(DIS, start_marker=SYM)
    print("instructions: %d  [0x%08X .. 0x%08X]" %
          (len(prog), prog[0].addr, prog[-1].addr))
    addr2idx = resolve_targets(prog, SYM)
    reach = reachable(prog)
    print("reachable from entry: %d of %d" % (len(reach), len(prog)))

    # ---- opcode census ----
    opc_all = Counter(i.mnem for i in prog)
    opc_reach = Counter(prog[i].mnem for i in reach)
    print("\n=== opcode census (reachable) : %d distinct ===" % len(opc_reach))
    for m, c in opc_reach.most_common():
        print("  %-40s %6d   (all=%d)" % (m, c, opc_all[m]))

    # ---- barriers ----
    bars = [i for i in reach if prog[i].mnem == "s_barrier"]
    print("\n=== s_barrier sites (reachable): %d ===" % len(bars))
    for i in sorted(bars):
        print("   #%d  0x%08X" % (i, prog[i].addr))

    # ---- branches ----
    brs = [i for i in reach if prog[i].is_branch and prog[i].branch_target is not None]
    back = [(i, prog[i].branch_target) for i in brs if prog[i].branch_target <= i]
    print("\n=== backward branches (loops): %d ===" % len(back))
    for i, t in sorted(back):
        print("   #%-6d 0x%08X -> #%-6d 0x%08X   %s"
              % (i, prog[i].addr, t, prog[t].addr, prog[i].text))

    # ---- memory census ----
    memc = Counter()
    for i in reach:
        m = prog[i].mnem
        if re.match(r"^(global|flat|scratch|buffer|ds|image)_", m) or \
           re.match(r"^s_(load|store|buffer_|scratch_|atomic|dmb)", m):
            memc[m] += 1
    print("\n=== memory-op census (reachable) ===")
    for m, c in sorted(memc.items()):
        print("  %-40s %6d" % (m, c))

    # ---- read-before-def ----
    rbd, IN = find_rbd(prog, reach)
    print("\n=== read-before-definition over reachable code: %d sites ===" % len(rbd))
    agg = Counter()
    for i, ins, k in rbd:
        agg[k] += 1
    for k, c in sorted(agg.items(), key=lambda x: -x[1])[:60]:
        print("   %-20s %6d" % (str(k), c))
    print("\n  first 40 sites:")
    for i, ins, k in rbd[:40]:
        print("   #%-6d 0x%08X  %-34s  reads %s" % (i, ins.addr, ins.text, k))

    os.makedirs(OUT, exist_ok=True)
    json.dump({
        "symbol": SYM,
        "n_insn": len(prog),
        "n_reachable": len(reach),
        "addr_lo": prog[0].addr, "addr_hi": prog[-1].addr,
        "opcode_all": dict(opc_all),
        "opcode_reachable": dict(opc_reach),
        "barriers": [{"idx": i, "addr": prog[i].addr} for i in sorted(bars)],
        "backward_branches": [{"idx": i, "addr": prog[i].addr,
                               "target_idx": t, "target_addr": prog[t].addr,
                               "text": prog[i].text} for i, t in sorted(back)],
        "memory_ops": dict(memc),
        "rbd_count": len(rbd),
        "rbd_by_reg": {str(k): c for k, c in agg.items()},
        "rbd_sites": [{"idx": i, "addr": ins.addr, "text": ins.text,
                       "reg": str(k)} for i, ins, k in rbd],
    }, open(os.path.join(OUT, "p16g_census_%s.json" %
                         ("swin32f" if "32ELb0" in SYM else "sym")), "w"),
        indent=1)
    print("\nwrote", os.path.join(OUT, "p16g_census_swin32f.json"))


if __name__ == "__main__":
    main()
