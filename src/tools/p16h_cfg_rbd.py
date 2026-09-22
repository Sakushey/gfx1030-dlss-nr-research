#!/usr/bin/env python3
"""Phase 16H — P11: label-based CFG + read-before-definition proof.

Host-only.  No GPU execution.

THE DEFECT THIS CLOSES

Phase 16G's read-before-definition census left **51 residual sites**
(24 `s63`/`s64` + ~27 VGPR) and recorded them as "believed to be
artefacts of the CFG, but that is a belief, not a proof".

The belief was right; the stated cause was wrong.  The cause is not that
"objdump's `<sym+0xNN>` annotation fails to reproduce the 82 backward
edges".  It is that **every branch instruction was silently dropped**:

    p16g_isa.LINE_RE = r"^\\s*(?P<text>.+?)\\s+//\\s+(?P<addr>[0-9A-Fa-f]{8,16}):"
                       r"\\s+(?P<bytes>[0-9A-Fa-f ]+)\\s*$"

objdump renders a branch as

    \ts_branch 17    // 00000000BAD4: BF820011 <_Z10k_swin_var...+0x11c>

and the trailing ` <sym+off>` annotation is not in the byte class, so the
`\\s*$` anchor fails and the line is skipped.  Measured over the SWIN32f
body: **582 of 17,478 instruction lines are rejected, and all 582 are
branches.**  The census therefore ran on a *branch-free, pure-fallthrough*
graph: no loop back-edges and no conditional-branch joins, so no
definition inside a loop body could ever reach its use.

WHAT THIS TOOL DOES

1. Parses the disassembly with a corrected regex, keeping the branches.
2. Resolves each branch target from the **instruction's own relative
   immediate** (`s_branch N` -> pc + 4 + N*4), which is the encoding
   itself and needs no symbol annotation.
3. Cross-checks that graph against the **label-based CFG** built from the
   assembly's own `.L...` labels -- the brief's "label-based CFG" -- by
   comparing the branch sequence and the loop structure.
4. Re-runs the Phase-16G read-before-definition dataflow, unchanged, over
   the corrected graph, with the same entry state.
5. Classifies every residual site.
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "..",
                                "phase16g_forensics", "tools"))
import p16h_lib as L  # noqa: E402

import p16g_isa  # noqa: E402
from p16g_isa import Insn, _fill_defuse  # noqa: E402

SYM = "_Z10k_swin_varILi32ELb0EEv9VarParams"

# Corrected: the ` <sym+off>` annotation objdump appends to branches is
# optional and must not defeat the line match.
LINE_RE_FIXED = re.compile(
    r"^\s*(?P<text>.+?)\s*//\s*(?P<addr>[0-9A-Fa-f]{8,16}):\s+"
    r"(?P<bytes>[0-9A-Fa-f ]+?)\s*(?:<[^>]*>)?\s*$")
LABEL_RE = p16g_isa.LABEL_RE

BRANCH_MNEM = re.compile(r"^(s_branch|s_cbranch_\w+|s_setpc_b64|"
                         r"s_swappc_b64|s_call_b64)\b")

# --------------------------------------------------------------------------
# two more parser defects, both in the direction of *manufacturing* reads
# --------------------------------------------------------------------------
# (a) SCC.  p16g_isa defines SETS_SCC but never uses it; SCC is only marked
#     defined when it appears as an explicit textual destination, so every
#     `s_cmp_*` (which writes SCC implicitly) marks nothing.  Positive list,
#     which can only ADD residual sites, never hide one.
SCC_SETTERS = re.compile(
    r"^s_(cmp_\w+|bitcmp[01]_b\d+|"
    r"add_i32|sub_i32|addc_u32|subb_u32|mul_i32|mul_hi_[ui]32|absdiff_i32|"
    r"and_b\d+|or_b\d+|xor_b\d+|nand_b\d+|nor_b\d+|xnor_b\d+|"
    r"and_not1_b\d+|or_not1_b\d+|lshl_b\d+|lshr_b\d+|ashr_i\d+|"
    r"not_b\d+|brev_b\d+|ff1_i32_b\d+|flbit_i32_b?\d*|"
    r"bcnt[01]_i32_b\d+|bitset[01]_b\d+|quadmask_b\d+|"
    r"bfm_b\d+|bfe_[ui]\d+|min_[iuf]\d+|max_[iuf]\d+|"
    r"sext_i32_i\d+|cvt_\w+)")

# (b) VOP3 carry-out.  `v_add_co_u32 v98, s63, 0x800, v5` has its carry-out
#     SGPR in operand 1; the parser calls it a use and never a def, so s63
#     and s64 are permanently "undefined" and every `v_add_co_ci_u32 ... s63`
#     that consumes them is reported.
VOP3_SDST = re.compile(r"^v_(add|sub)_co(_ci)?_u32|^v_(addc|subb)_co_u32")


def fix_parser(ins):
    """Repair the two manufactured-read defects on one Insn."""
    if SCC_SETTERS.match(ins.mnem):
        if "scc" not in ins.defs_special:
            ins.defs_special.append("scc")
    if VOP3_SDST.match(ins.mnem) and len(ins.ops) >= 2:
        sdst = ins.ops[1].strip()
        if sdst == "null":
            pass
        elif re.match(r"^s\d+$", sdst):
            k = ("sgpr", int(sdst[1:]))
            if k not in ins.defs:
                ins.defs.append(k)
            ins.uses = [u for u in ins.uses if u != k]
    return ins


def parse_body_fixed(path, sym):
    """Parse a body keeping branches; return (insns, rejected)."""
    lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    s = None
    for i, l in enumerate(lines):
        m = LABEL_RE.match(l)
        if m and sym in m.group("name"):
            s = i + 1
            break
    if s is None:
        raise SystemExit("symbol not found")
    e = len(lines)
    for i in range(s, len(lines)):
        if LABEL_RE.match(lines[i]):
            e = i
            break
    out, rejected, idx = [], [], 0
    for i in range(s, e):
        line = lines[i]
        if LABEL_RE.match(line) or "//" not in line:
            continue
        m = LINE_RE_FIXED.match(line)
        if not m:
            rejected.append(line.strip())
            continue
        addr = int(m.group("addr"), 16)
        ins = Insn(idx, addr, m.group("text"), m.group("bytes").strip(), line)
        _fill_defuse(ins)
        fix_parser(ins)
        out.append(ins)
        idx += 1
    return out, rejected


def rel_target(ins):
    """Target address from the branch's own encoded displacement.

    SOPP encodes a signed 16-bit dword displacement from PC+4:
    `s_branch` = 0xBF82_0000 | imm16, `s_cbranch_*` = 0xBF8x_0000 | imm16.

    The displacement is read from the RAW ENCODING, not from objdump's
    operand text: objdump prints it as an *unsigned* 16-bit number
    (`s_cbranch_execz 65471` is really 0xFFBF = -65), so parsing the text
    silently turns every backward edge into a bogus forward one.
    """
    if not BRANCH_MNEM.match(ins.mnem):
        return None
    hx = ins.bytes_hex.split()
    imm = None
    if hx:
        try:
            word = int(hx[0], 16)
            imm = word & 0xFFFF
        except ValueError:
            imm = None
    if imm is None:
        m = re.search(r"(-?\d+)\s*$", ins.text)
        if not m:
            return None
        imm = int(m.group(1)) & 0xFFFF
    if imm >= 0x8000:
        imm -= 0x10000
    return (ins.addr + 4 + imm * 4) & 0xFFFFFFFFFFFF


def build_cfg(prog):
    """Successor lists over instruction indices, using real branch edges."""
    by_addr = {}
    for ins in prog:
        by_addr.setdefault(ins.addr, ins.idx)
    n = len(prog)
    succ = [[] for _ in range(n)]
    unresolved = []
    for ins in prog:
        i = ins.idx
        if ins.mnem == "s_endpgm":
            continue
        t = rel_target(ins)
        if t is not None:
            j = by_addr.get(t)
            if j is None:
                unresolved.append((ins.addr, t, ins.text))
            else:
                ins.branch_target = j
                succ[i].append(j)
            if ins.mnem.startswith("s_cbranch"):
                succ[i].append(i + 1)
        else:
            succ[i].append(i + 1)
    return succ, by_addr, unresolved


def reachable(succ):
    n = len(succ)
    seen, stack = set(), [0]
    while stack:
        i = stack.pop()
        if i in seen or i < 0 or i >= n:
            continue
        seen.add(i)
        for t in succ[i]:
            stack.append(t)
    return seen


def find_rbd(prog, succ, reach, entry):
    """MAY read-before-definition dataflow over the corrected CFG.

    Phase 16G's version required every predecessor to be initialised
    before a node could be computed (`if IN[p] is None: acc = None;
    break`).  On a cyclic graph that never terminates properly: a loop
    body's back-edge predecessor stays `None` forever, so the body is
    never visited and no definition inside a loop can reach its use.
    That is the second half of why the 51 sites survived.

    This is the standard may-analysis fixpoint instead: the lattice is
    sets of defined registers, bottom is the empty set, and

        IN[i] = (union over preds p of OUT[p])   ,  OUT[p] = IN[p] | defs[p]

    with the kernel-entry state folded into IN[0].
    """
    preds = defaultdict(set)
    for i in sorted(reach):
        for s in succ[i]:
            if s in reach:
                preds[s].add(i)

    def out_of(p):
        # `defs_special` holds bare names ("exec", "vcc", "scc") while a
        # read of a special register is keyed as the pair ("exec", None).
        # Phase 16G mixed the two: definitions went in as bare strings and
        # lookups were made with tuples, so EVERY special-register read was
        # reported unconditionally.  Normalise to the pair form.
        return (set(IN[p]) | set(prog[p].defs)
                | {(s, None) for s in prog[p].defs_special})

    IN = {i: frozenset() for i in reach}
    IN[0] = frozenset(entry)
    changed, it = True, 0
    while changed and it < 500:
        changed, it = False, it + 1
        for i in sorted(reach):
            acc = set()
            for p in preds[i]:
                acc |= out_of(p)
            if i == 0:
                acc |= set(entry)
            new = frozenset(acc)
            if new != IN[i]:
                IN[i] = new
                changed = True

    rbd = []
    for i in sorted(reach):
        st = IN[i]
        for k in list(prog[i].uses) + [(s, None)
                                       for s in prog[i].uses_special]:
            if k not in st:
                rbd.append((i, prog[i], k))
    return rbd, IN, it


ENTRY = ({("sgpr", 0), ("sgpr", 1), ("sgpr", 14), ("sgpr", 15),
          ("vgpr", 0), ("exec", None), ("vcc", None)})


# --------------------------------------------------------------------------
# label-based CFG, straight from the assembly's `.L...` labels
# --------------------------------------------------------------------------
NONINSN = re.compile(
    r"^\s*\.(size|type|p2align|section|globl|protected|amdgcn|amdhsa|"
    r"end_amdhsa|set|Lfunc|text|rodata|weak|local|private|amdgpu)")
ASM_LABEL = re.compile(r"^(\.L[A-Za-z0-9_]+):")


def asm_cfg(asm_path, sym):
    """Branch sequence + loop structure from the `.L...` labels."""
    lines = open(asm_path, encoding="utf-8", errors="replace").read().split("\n")
    s = e = None
    for i, l in enumerate(lines):
        if l.strip() == sym + ":":
            s = i
        if l.startswith(".Lfunc_end_" + sym + ":"):
            e = i
            break
    labels, order, cur = {}, [], 0
    for i in range(s + 1, e):
        raw = lines[i]
        st = raw.strip()
        m = ASM_LABEL.match(st)
        if m:
            labels[m.group(1)] = cur
            continue
        if not st or st.startswith("//") or NONINSN.match(raw):
            continue
        order.append(st)
        cur += 1
    brs, back = [], []
    for i, st in enumerate(order):
        m = re.match(r"^(s_branch|s_cbranch_\w+|s_setpc_b64|s_swappc_b64|"
                     r"s_call_b64)\b\s*(\.L[A-Za-z0-9_]+)?", st)
        if not m:
            continue
        tgt = labels.get(m.group(2)) if m.group(2) else None
        brs.append((m.group(1), tgt))
        if tgt is not None and tgt <= i:
            back.append((i, tgt, m.group(1)))
    return {"n_insn": cur, "n_labels": len(labels),
            "branches": brs, "backward": back}


def main():
    OUT = os.path.join(L.P16H, "out")
    os.makedirs(OUT, exist_ok=True)

    targets = {
        "candidate_F": (
            os.path.join(L.ROOT, "phase16h_candidate_f", "disasm",
                         "candidate_f_gfx1030_disasm.txt"),
            os.path.join(L.ROOT, "phase16h_candidate_f", "source",
                         "gfx1030_dlssnr_candidate_f.s")),
        "candidate_E": (
            os.path.join(L.ROOT, "phase16e_candidate_e", "disasm",
                         "candidate_e_gfx1030_disasm.txt"),
            os.path.join(L.ROOT, "phase16e_candidate_e",
                         "gfx1030_dlssnr_candidate_e.s")),
    }

    print("=" * 74)
    print("P11 — label-based CFG + read-before-definition (host-only)")
    print("=" * 74)

    res = {}
    for tag, (dis, asm) in targets.items():
        print("\n=== %s ===" % tag)
        prog, rejected = parse_body_fixed(dis, SYM)
        rej_mn = Counter(r.split(None, 1)[0] for r in rejected)
        print("  disassembly: %d instructions kept, %d rejected"
              % (len(prog), len(rejected)))
        print("  rejected mnemonics: %s" % dict(rej_mn))

        # what the OLD parser saw
        old = p16g_isa.parse_disasm(dis, start_marker=SYM)
        print("  p16g_isa.LINE_RE saw: %d instructions (branch-free)"
              % len(old))

        succ, by_addr, unresolved = build_cfg(prog)
        reach = reachable(succ)
        n_branch = sum(1 for i in prog if BRANCH_MNEM.match(i.mnem))
        back = [(i.idx, i.branch_target, i.mnem) for i in prog
                if BRANCH_MNEM.match(i.mnem) and i.branch_target is not None
                and i.branch_target <= i.idx]
        print("  branches kept: %d ; unresolved targets: %d"
              % (n_branch, len(unresolved)))
        print("  reachable: %d of %d" % (len(reach), len(prog)))
        print("  backward branches: %d ; loop headers: %d"
              % (len(back), len({t for _i, t, _m in back})))

        a = asm_cfg(asm, SYM)
        print("  [label-based .s CFG] instructions=%d labels=%d branches=%d "
              "backward=%d" % (a["n_insn"], a["n_labels"], len(a["branches"]),
                               len(a["backward"])))
        asm_seq = [b[0] for b in a["branches"]]
        dis_seq = [i.mnem for i in prog if BRANCH_MNEM.match(i.mnem)]
        print("  branch mnemonic sequence identical (asm vs disasm): %s"
              % (asm_seq == dis_seq))
        if asm_seq != dis_seq:
            for k, (x, y) in enumerate(zip(asm_seq, dis_seq)):
                if x != y:
                    print("     first divergence at %d: asm=%s disasm=%s"
                          % (k, x, y))
                    break

        rbd, IN, it = find_rbd(prog, succ, reach, ENTRY)
        print("  dataflow fixpoint iterations: %d" % it)
        print("  RESIDUAL read-before-def sites: %d" % len(rbd))

        kinds = Counter()
        sites = []
        for i, ins, k in rbd:
            kind, idx = k
            cls = "other"
            # VOP3 carry-out destination printed as a bare `sN` operand?
            if kind == "sgpr" and idx is not None and idx >= 63:
                cls = "sdst_carry_out"
            elif kind in ("exec", "vcc"):
                cls = "special_" + kind
            elif kind == "sgpr":
                cls = "sgpr"
            elif kind == "vgpr":
                cls = "vgpr"
            kinds[cls] += 1
            sites.append({"idx": i, "addr": "0x%08X" % ins.addr,
                          "mnem": ins.mnem, "text": ins.text,
                          "reg": "%s%s" % (kind, "" if idx is None
                                           else str(idx)),
                          "class": cls})
        print("  by class: %s" % dict(kinds))
        res[tag] = {"n_insn": len(prog), "n_rejected": len(rejected),
                    "rejected_mnemonics": dict(rej_mn),
                    "n_branches": n_branch,
                    "n_unresolved_targets": len(unresolved),
                    "n_reachable": len(reach),
                    "n_backward": len(back),
                    "n_loop_headers": len({t for _i, t, _m in back}),
                    "asm_n_insn": a["n_insn"], "asm_n_labels": a["n_labels"],
                    "asm_n_branches": len(a["branches"]),
                    "asm_n_backward": len(a["backward"]),
                    "branch_seq_identical": asm_seq == dis_seq,
                    "n_rbd": len(rbd), "rbd_by_class": dict(kinds),
                    "rbd_sites": sites}

    # ---- the 51: are they gone? -------------------------------------
    print("\n" + "=" * 74)
    print("the Phase-16G residual 51")
    print("=" * 74)
    e = res["candidate_E"]
    print("  Phase-16G reported: 51 residual sites "
          "(24 s63/s64 + ~27 VGPR)")
    print("  now, with branches kept: %d residual sites" % e["n_rbd"])
    print("  by class: %s" % e["rbd_by_class"])
    print("  s63/s64 sdst sites now: %d"
          % e["rbd_by_class"].get("sdst_carry_out", 0))
    print("  VGPR sites now: %d" % e["rbd_by_class"].get("vgpr", 0))

    json.dump(res, open(os.path.join(OUT, "p11_cfg_rbd.json"), "w"), indent=1)
    print("\nwrote", os.path.join(OUT, "p11_cfg_rbd.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
