"""CFG-aware SGPR read-before-def analysis for AMDGCN entry contracts.

Input: llvm-mc-style per-kernel assembly (.s) of the translated gfx1030
module (labels + plain instruction rows, no address column).

Method:
  - parse every instruction row into (mnemonic, operand list, pc index)
  - decode SGPR/state register tokens from operand text
  - classify each instruction's writes (SGPR dwords + state) and reads
  - build the CFG from branch targets
  - available-definitions dataflow from entry (meet = intersection, no
    kills), flag every SGPR dword read at a program point where it is not
    definitely defined on all paths -> "may read entry state" row with
    first-read / first-def program counters.

Host-only, read-only.
"""
from __future__ import annotations

import os
import re

# ---------------------------------------------------------------------------
# tokenising
# ---------------------------------------------------------------------------
SGPR_RE = re.compile(r"\bs(\d+)\b")
SGPR_PAIR_RE = re.compile(r"\bs\[(\d+):(\d+)\]")
STATE_NAMES = {"vcc", "vcc_lo", "vcc_hi", "exec", "exec_lo", "exec_hi",
               "m0", "scc", "flat_scratch", "flat_scratch_lo",
               "flat_scratch_hi", "tba", "tma", "tba_lo", "tma_lo"}


def reg_tokens(op):
    """Return (sgpr dword set, state set) referenced by one operand text."""
    sgprs = set()
    state = set()
    for m in SGPR_PAIR_RE.finditer(op):
        a, b = int(m.group(1)), int(m.group(2))
        sgprs.update(range(a, b + 1))
    for m in SGPR_RE.finditer(op):
        # guard: 'scc', 's8' handled by SGPR_RE? 'scc' has no digits -> no.
        if m.group(1) != "":
            sgprs.add(int(m.group(1)))
    for name in STATE_NAMES:
        for m in re.finditer(r"\b" + name + r"\b", op):
            state.add(name)
    return sgprs, state


def ops_split(operands):
    """Split operand text on commas; handles dual-issue rows."""
    return [o.strip() for o in operands.split(",")] if operands else []


# mnemonic -> kind.  kind: "dst" (dest-first), "reads" (no dest),
# "vopc" (dest first; sgpr dest on e64 / vcc on e32)
def mnemonic_kind(mnem):
    m = mnem.lower()
    if m.startswith("s_"):
        if any(m.startswith(p) for p in (
                "s_cmp", "s_cbranch", "s_branch", "s_swappc", "s_waitcnt",
                "s_nop", "s_clause", "s_code_end", "s_delay_alu", "s_trap",
                "s_endpgm", "s_sendmsg", "s_sethalt", "s_sleep", "s_setprio",
                "s_ttrace", "s_yield", "s_setreg", "s_memtime",
                "s_memrealtime", "s_inst_prefetch", "s_dcache", "s_icache",
                "s_gl0", "s_gl1", "s_scratch", "s_store")):
            return "reads"
        return "dst"
    if m.startswith("v_"):
        if m.startswith(("v_cmp", "v_cmpx")):
            return "vopc"
        if m.startswith("v_readfirstlane") or m.startswith("v_readlane"):
            return "dst"          # dst may be an SGPR
        return "dst"
    if m.startswith(("ds_read", "ds_bpermute", "ds_swizzle", "ds_ordered")):
        return "dst"
    if m.startswith(("global_load", "flat_load", "scratch_load", "buffer_load",
                     "image_load", "tbuffer_load", "global_atomic",
                     "flat_atomic", "buffer_atomic", "image_atomic")):
        # atomics without _rtn have no dest; with _rtn a dest
        return "dst" if m.endswith("_rtn") else "reads"
    if m.startswith(("global_store", "flat_store", "scratch_store",
                     "buffer_store", "image_store", "buffer_gl0",
                     "buffer_gl1", "ds_write", "ds_add", "ds_sub",
                     "ds_and", "ds_or", "ds_xor", "ds_min", "ds_max",
                     "ds_cmp", "ds_wrap", "ds_inc", "ds_dec", "ds_gws",
                     "exp", "s_sendmsg")):
        return "reads"
    if m.startswith(("global_", "flat_", "scratch_", "buffer_", "image_",
                     "ds_")):
        return "dst"
    return "reads"


def classify_row(mnem, operands):
    """Return (def_sgprs, use_sgprs, def_state, use_state)."""
    kind = mnemonic_kind(mnem)
    parts = []
    if "::" in operands:                       # v_dual / s_dual rows
        parts = [p.strip() for p in operands.split("::")]
    else:
        parts = [operands]
    def_s = set()
    use_s = set()
    def_st = set()
    use_st = set()
    for part in parts:
        ops = ops_split(part)
        if not ops:
            continue
        if kind == "reads":
            for op in ops:
                s, st = reg_tokens(op)
                use_s |= s
                use_st |= st
            continue
        # dest-first
        d = ops[0]
        ds, dst = reg_tokens(d)
        if kind == "vopc":
            # e64 with sgpr dest or e32 with vcc dest
            if ds:
                def_s |= ds
            else:
                def_st |= dst
                if mnem.startswith("v_cmpx"):
                    use_st.add("exec")
                    def_st.add("exec")
        else:
            def_s |= ds
            def_st |= dst
        for op in ops[1:]:
            s, st = reg_tokens(op)
            use_s |= s
            use_st |= st
        if mnem.startswith("v_cmpx"):
            use_st.add("exec")
    return def_s, use_s, def_st, use_st


# ---------------------------------------------------------------------------
# CFG
# ---------------------------------------------------------------------------
BRANCH_RE = re.compile(r"\b(?:s_cbranch(?:_scc0|_scc1|_vccz|_vccnz|_execz|"
                       r"_execnz|_scc)?|s_branch)\b")
LABEL_RE = re.compile(r"^([.A-Za-z_$][\w.$]*):\s*$")
TEXT_RE = re.compile(r"^\s*([A-Za-z_][\w.]*)(?:\s+(.*?))?\s*$")


def parse_asm_text(text):
    """Rows: list of dicts {kind: label|instr, name/mnem, ops, pc}."""
    rows = []
    pc = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(".") or line.startswith("//"):
            if line and not line.startswith(".") and not line.startswith("//"):
                pass
            continue
        if "//" in line:
            line = line.split("//", 1)[0].strip()
        if not line:
            continue
        lm = LABEL_RE.match(line)
        if lm:
            rows.append({"kind": "label", "name": lm.group(1), "pc": pc})
            continue
        tm = TEXT_RE.match(line)
        if tm:
            mnem, ops = tm.group(1), tm.group(2) or ""
            rows.append({"kind": "instr", "mnem": mnem, "ops": ops, "pc": pc})
            pc += 1
            continue
        # unknown text (e.g. directives without dot) -> ignore
    return rows


def build_blocks(rows):
    """Split rows into basic blocks; map label name -> block idx."""
    instr_idxs = [i for i, r in enumerate(rows) if r["kind"] == "instr"]
    blocks = []
    label_of_instr = {}
    cur = None
    for i, r in enumerate(rows):
        if r["kind"] == "label":
            cur = len(blocks)
            blocks.append({"start": i, "rows": [], "label": r["name"],
                           "term": None, "preds": [], "targets": []})
            label_of_instr[i] = cur
    # map instruction index -> containing block
    # (labels begin blocks; an instruction between labels belongs to the
    # block whose label precedes it)
    in_block = [None] * len(rows)
    blk = None
    for i, r in enumerate(rows):
        if r["kind"] == "label":
            blk = label_of_instr[i]
        in_block[i] = blk
    return blocks, in_block


def analyze_kernel(rows):
    """CFG + available-defs pass. Returns list of flagged rows:
    dict(sgpr, pc, first_read_pc, first_write_pc, mnem, ops) and per-sgpr
    first-def/first-read statistics."""
    # order instruction rows; build per-label map
    instrs = [r for r in rows if r["kind"] == "instr"]
    n = len(instrs)
    idx_of = {}
    for i, r in enumerate(rows):
        if r["kind"] == "label":
            idx_of[r["name"]] = r["pc"]
        elif r["kind"] == "instr":
            idx_of.setdefault(r["pc"], r["pc"])
    # blocks over instruction indices (0..n-1)
    # label pc -> instr ordinal
    label_ord = {}
    ord_pc = [r["pc"] for r in instrs]
    pc_ord = {pc: k for k, pc in enumerate(ord_pc)}
    for r in rows:
        if r["kind"] == "label" and r["name"] in pc_ord:
            label_ord[r["name"]] = pc_ord[r["name"]]
    # block boundaries: instruction ordinals that are branch targets or
    # follow a terminator
    term_mnems = {"s_branch", "s_cbranch_scc0", "s_cbranch_scc1",
                  "s_cbranch_vccz", "s_cbranch_vccnz", "s_cbranch_execz",
                  "s_cbranch_execnz", "s_endpgm", "s_trap"}
    is_target = [False] * n
    succ = [[] for _ in range(n)]        # instruction-level succs
    for k, ins in enumerate(instrs):
        mnem, ops = ins["mnem"], ins["ops"]
        tgt = None
        if mnem in term_mnems and mnem != "s_endpgm" and mnem != "s_trap":
            for op in ops_split(ops):
                if op.startswith(".L") or op.startswith("L"):
                    tgt = op
            if tgt is not None and tgt in label_ord:
                is_target[label_ord[tgt]] = True
        if mnem == "s_branch":
            if tgt in label_ord:
                succ[k].append(label_ord[tgt])
        elif mnem.startswith("s_cbranch"):
            if k + 1 < n:
                succ[k].append(k + 1)
            if tgt in label_ord:
                succ[k].append(label_ord[tgt])
        # else fallthrough implicit: succ[k].append(k+1) handled below
    # a new BB starts at instruction k if k==0 or k is a branch target or
    # k-1 is a terminator (except fallthrough into next block)
    starts = [False] * n
    for k in range(n):
        if k == 0 or is_target[k]:
            starts[k] = True
    for k in range(n - 1):
        if instrs[k]["mnem"] in term_mnems and \
                instrs[k]["mnem"] not in ("s_cbranch_scc0", "s_cbranch_scc1",
                                          "s_cbranch_vccz", "s_cbranch_vccnz",
                                          "s_cbranch_execz",
                                          "s_cbranch_execnz"):
            starts[k + 1] = True
        elif instrs[k]["mnem"] not in ("s_branch",) and \
                instrs[k]["mnem"].startswith("s_cbranch") and \
                k + 1 < n:
            starts[k + 1] = True  # after any conditional terminator a bb starts
    bb_of = [0] * n
    cur = 0
    for k in range(n):
        if starts[k]:
            cur = k
        bb_of[k] = cur
    bb_leaders = sorted(set(bb_of))
    bb_idx = {lead: i for i, lead in enumerate(bb_leaders)}
    nb = len(bb_leaders)
    bbs = [[] for _ in range(nb)]
    for k in range(n):
        bbs[bb_idx[bb_of[k]]].append(k)
    # successors per bb
    bb_succ = [[] for _ in range(nb)]
    for i, lead in enumerate(bb_leaders):
        last = bbs[i][-1]
        mnem = instrs[last]["mnem"]
        if mnem == "s_branch":
            for s in succ[last]:
                bb_succ[i].append(bb_idx[bb_of[s]])
        elif mnem.startswith("s_cbranch"):
            for s in succ[last]:
                if s < n and (s in bb_leaders or s == last + 1 or
                              bb_of[s] != lead):
                    t = bb_idx[bb_of[s]]
                    if t not in bb_succ[i]:
                        bb_succ[i].append(t)
        else:
            if last + 1 < n:
                bb_succ[i].append(bb_idx[bb_of[last + 1]])
    # compute class per instruction row once
    rows_info = []       # per instr ordinal: def/use
    for ins in instrs:
        d, u, dst, ust = classify_row(ins["mnem"], ins["ops"])
        rows_info.append((d, u, dst, ust))
    # available-defs dataflow over SGPR dwords 0..127
    FULL = (1 << 128) - 1
    avail_in = [FULL] * nb
    entry = bb_idx[bb_of[0]]
    avail_in[entry] = 0
    # worklist
    changed = True
    out = [FULL] * nb
    preds = [[] for _ in range(nb)]
    for i in range(nb):
        for s in bb_succ[i]:
            preds[s].append(i)
    while changed:
        changed = False
        for i in range(nb):
            if i == entry:
                acc = 0
            else:
                acc = FULL
                for p in preds[i]:
                    acc &= out[p]
                if not preds[i]:
                    acc = avail_in[i] if avail_in[i] != FULL else FULL
            avail_in[i] = acc
            # forward within bb
            cur_av = acc
            for k in bbs[i]:
                d, u, dst, ust = rows_info[k]
                cur_av |= _defmask(d)
            if out[i] != cur_av:
                out[i] = cur_av
                changed = True
    # flag reads where reg not defined on all paths
    flags = []
    first_read = {}
    first_write = {}
    cur_av = 0
    cur_ord = 0
    # walk blocks in leader order recomputing avail at each instruction
    entry_av = 0
    av_at = {}
    for i in range(nb):
        pass
    # simple re-walk using final avail_in
    for i in range(nb):
        av = avail_in[i]
        for k in bbs[i]:
            d, u, dst, ust = rows_info[k]
            for sg in sorted(u):
                if not (av >> sg) & 1:
                    if sg not in first_read:
                        first_read[sg] = k
                    flags.append({"sgpr": sg, "pc": instrs[k]["pc"],
                                  "mnem": instrs[k]["mnem"],
                                  "ops": instrs[k]["ops"],
                                  "at": k})
            av |= _defmask(d)
            for sg in sorted(d):
                if sg not in first_write:
                    first_write[sg] = k
    return flags, first_read, first_write, instrs


def _defmask(d_set):
    m = 0
    for sg in d_set:
        if 0 <= sg < 128:
            m |= 1 << sg
    return m


def load_s(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


if __name__ == "__main__":
    import sys
    path = sys.argv[1]
    rows = parse_asm_text(load_s(path))
    flags, fr, fw, instrs = analyze_kernel(rows)
    print(f"kernel {os.path.basename(path)}: {len(instrs)} instructions, "
          f"{len(flags)} flagged sgpr reads before definite def")
    by_reg = {}
    for f in flags:
        by_reg.setdefault(f["sgpr"], []).append(f)
    for sg in sorted(by_reg):
        fl = by_reg[sg]
        fwpc = instrs[fw[sg]]["pc"] if sg in fw else None
        frpc = instrs[fr[sg]]["pc"] if sg in fr else None
        print(f"  s{sg:3d}: first_read@{frpc} first_write@{fwpc} "
              f"({len(fl)} reads) first: {fl[0]['mnem']} {fl[0]['ops']}")
