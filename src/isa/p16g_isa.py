"""Phase16G — host-only ISA parser / def-use census for a GFX10 kernel body.

Parses the llvm-objdump text output of the candidate-E code object
(``... // 0000000AB200: BFA10003`` form) into instructions and provides:

  * operand extraction (sgpr / vgpr / exec / vcc / m0 / literals)
  * implicit-operand awareness for the ISA state that is NOT a textual
    operand (EXEC, VCC, SCC, flat_scratch, mode, ...)
  * def/use sets per instruction (an approximation good enough for a
    read-before-definition census and a backward slice)
  * basic-block construction from branch targets

No third-party dependencies.
"""
from __future__ import annotations

import re
import sys
from collections import OrderedDict

LINE_RE = re.compile(
    r"^\s*(?P<text>.+?)\s+//\s+(?P<addr>[0-9A-Fa-f]{8,16}):\s+(?P<bytes>[0-9A-Fa-f ]+)\s*$")
LABEL_RE = re.compile(r"^(?P<addr>[0-9A-Fa-f]{8,16})\s+<(?P<name>.+)>:\s*$")

# ---- registers -------------------------------------------------------------

SGPR_SINGLE = re.compile(r"^s(\d+)$")
SGPR_RANGE = re.compile(r"^s\[(\d+):(\d+)\]$")
SGPR_LIST = re.compile(r"^s\[(\d+)(?::(\d+))?(\s*,\s*s?(\d+)(?::(\d+))?)*\]$")
VGPR_SINGLE = re.compile(r"^v(\d+)$")
VGPR_RANGE = re.compile(r"^v\[(\d+):(\d+)\]$")
LITERAL = re.compile(r"^-?(0x[0-9A-Fa-f]+|\d+)$")
IMM_OPERAND = re.compile(r"^(0x[0-9A-Fa-f]+|-?\d+)$")

SPECIAL = {
    "exec_lo": ["exec"], "exec_hi": ["exec"], "exec": ["exec"],
    "vcc_lo": ["vcc"], "vcc_hi": ["vcc"], "vcc": ["vcc"],
    "scc": ["scc"], "m0": ["m0"],
    "flat_scratch_lo": ["flat_scratch"], "flat_scratch_hi": ["flat_scratch"],
    "xnack_mask_lo": ["xnack"], "xnack_mask_hi": ["xnack"],
    "ttmp0": ["ttmp"], "ttmp1": ["ttmp"], "ttmp2": ["ttmp"], "ttmp3": ["ttmp"],
}


def split_operands(text: str) -> list[str]:
    """Split the operand list of an instruction on top-level commas."""
    out, depth, cur = [], 0, []
    for ch in text:
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def _expand_sgpr_bracket(body: str) -> list[int]:
    """AMDGPU register syntax.

    `s[4:7]` is an INCLUSIVE RANGE -> [4,5,6,7].
    `s[0,1]` / `v[19,20]` is a LIST -> [0,1].
    Getting this wrong silently hides definitions of the middle registers
    of a wide load (e.g. only s24 and s27 defined for `s[24:27]`), which
    shows up as spurious read-before-definition reports.
    """
    regs: list[int] = []
    for part in body.split(","):
        part = part.strip().lstrip("sv")
        if ":" in part:
            a, b = part.split(":")
            a, b = int(a), int(b)
            lo, hi = (a, b) if a <= b else (b, a)
            regs.extend(range(lo, hi + 1))
        elif part:
            regs.append(int(part))
    return regs


def parse_regs(op: str):
    """Return (kind, indices) for a textual register operand."""
    o = op.strip()
    if o in SPECIAL:
        return [(SPECIAL[o][0], None)]
    if SGPR_SINGLE.match(o):
        return [("sgpr", [int(SGPR_SINGLE.match(o).group(1))])]
    if SGPR_RANGE.match(o):
        m = SGPR_RANGE.match(o)
        a, b = int(m.group(1)), int(m.group(2))
        lo, hi = (a, b) if a <= b else (b, a)
        return [("sgpr", list(range(lo, hi + 1)))]
    if o.startswith("s[") and o.endswith("]"):
        return [("sgpr", _expand_sgpr_bracket(o[2:-1]))]
    if VGPR_SINGLE.match(o):
        return [("vgpr", [int(VGPR_SINGLE.match(o).group(1))])]
    if VGPR_RANGE.match(o):
        m = VGPR_RANGE.match(o)
        a, b = int(m.group(1)), int(m.group(2))
        lo, hi = (a, b) if a <= b else (b, a)
        return [("vgpr", list(range(lo, hi + 1)))]
    if o.startswith("v[") and o.endswith("]"):
        return [("vgpr", _expand_sgpr_bracket(o[2:-1]))]
    return []


# ---- instruction classes ---------------------------------------------------

# mnemonics whose FIRST textual operand is a destination that is written.
_SCALAR_WRITE = re.compile(
    r"^s_(mov|movk|add|addc|sub|subb|mul|mul_hi|and|or|xor|not|lshl|ashr|"
    r"bfe|bfi|bfm|cselect|cmov|cvt|sext|pack|abs|min|max|minmax|addk|mulk|"
    r"andn2|orn2|bfm|ff1|flbit|ffbh|brev|quadmask|movrel|setpc|getpc|"
    r"atomic|cmpswap|load|store|buffer|scratch|flat|dword|memtime|"
    r"waitcnt|sendmsg|sleep|setreg|sethalt|trap|s_barrier)\b")
_SCALAR_MEM = re.compile(r"^s_(load|store|buffer_load|buffer_store|scratch_load|scratch_store|atomic|dmb|memtime|waitcnt)")

# instructions that read a base register in a memory operand
_MEM_TEXTLIKE = re.compile(
    r"^(global|flat|scratch|buffer|ds|s_|buffer_atomic|global_atomic|flat_atomic)")

# Mnemonics that define SCC
SETS_SCC = re.compile(
    r"^s_(cmp|cmpx|add|addc|sub|subb|mul|and|or|xor|lshl|ashr|lshr|"
    r"bfe|bfm|bfi|sext|bitcmp|ff1|flbit|brev|quadmask|not|abs|min|max|"
    r"cselect|andn2|orn2|pack|atomic|sethalt|sleep)\b")
# s_add/s_sub etc. only set SCC when the _u32/_i32 suffix form is used
_SET_SCC_SUFFIX = re.compile(r"^s_(add|sub|addc|subb|mul|and|or|xor|lshl|ashr|lshr|not|min|max|abs|cvt)")

IMPLICIT_READS = {
    # instructions that read ISA state that is not a textual operand
    "s_cbranch_execz": ["exec"],
    "s_cbranch_execz": ["exec"],
    "s_cbranch_execnz": ["exec"],
    "s_cbranch_vccz": ["vcc"],
    "s_cbranch_vccnz": ["vcc"],
    "s_cbranch_scc0": ["scc"],
    "s_cbranch_scc1": ["scc"],
    "s_and_saveexec_b32": ["exec"], "s_and_saveexec_b64": ["exec"],
    "s_or_saveexec_b32": ["exec"], "s_or_saveexec_b64": ["exec"],
    "s_xor_saveexec_b32": ["exec"], "s_xor_saveexec_b64": ["exec"],
    "s_nand_saveexec_b32": ["exec"], "s_nand_saveexec_b64": ["exec"],
    "s_nor_saveexec_b32": ["exec"], "s_nor_saveexec_b64": ["exec"],
    "s_xnor_saveexec_b32": ["exec"], "s_xnor_saveexec_b64": ["exec"],
    "s_mov_b64": [],
    "v_cndmask_b32": ["vcc"], "v_cndmask_b32_e32": ["vcc"],
    "v_cndmask_b32_e64": [],
    "v_addc_co_u32": ["vcc"], "v_subb_co_u32": ["vcc"],
    "v_add_co_u32": ["vcc"], "v_sub_co_u32": ["vcc"],
    "v_cmp_*": ["exec"],
    "s_barrier": [],
    "s_endpgm": [],
}
# any v_cmp* with an explicit sNN destination writes VCC or an SGPR
VOPC_SDST = re.compile(r"^v_cmp\w*_e64\b|^v_cmp\w*_s\b")

# msgs: operands that are *destinations* even though they appear late
DEST_LATE = re.compile(r"^(buffer_load|global_load|flat_load|scratch_load|ds_read|"
                       r"s_load|s_buffer_load|s_scratch_load)")
# atoms return via vdst (first operand) but also write nothing else special


class Insn:
    __slots__ = ("idx", "addr", "text", "mnem", "ops", "nbytes", "bytes_hex",
                 "uses", "defs", "defs_special", "uses_special", "branch_target",
                 "is_branch", "is_call", "raw")

    def __init__(self, idx, addr, text, bytes_hex, raw):
        self.idx = idx
        self.addr = addr
        self.bytes_hex = bytes_hex
        self.nbytes = len(bytes_hex.split())
        self.raw = raw
        t = text.strip()
        self.text = t
        parts = t.split(None, 1)
        self.mnem = parts[0]
        self.ops = split_operands(parts[1]) if len(parts) > 1 else []
        self.uses = []
        self.defs = []
        self.defs_special = []
        self.uses_special = []
        self.branch_target = None
        self.is_branch = self.mnem.startswith(("s_branch", "s_cbranch",
                                               "s_setpc", "s_swappc",
                                               "s_call", "s_trap"))
        self.is_call = self.mnem.startswith(("s_swappc", "s_call"))

    def __repr__(self):
        return "0x%08X: %s" % (self.addr, self.text)


def _regs_from_operand(op):
    """Yield (kind, idx) pairs for every register-like token in one operand."""
    for kind, idxs in parse_regs(op):
        if idxs is None:
            yield (kind, None)
        else:
            for i in idxs:
                yield (kind, i)


def parse_disasm(path, start_marker=None, end_marker=None):
    """Parse the disasm file into an ordered list of Insn.

    If start_marker is given, only the body of the symbol whose label line
    contains start_marker is returned.
    """
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().split("\n")
    i = 0
    if start_marker is not None:
        while i < len(lines):
            m = LABEL_RE.match(lines[i])
            if m and start_marker in m.group("name"):
                i += 1
                break
            i += 1
    idx = 0
    while i < len(lines):
        line = lines[i]
        i += 1
        m = LABEL_RE.match(line)
        if m:
            if end_marker is not None and end_marker in m.group("name"):
                break
            if start_marker is not None and idx > 0:
                break          # next symbol reached -> end of this body
            continue
        m = LINE_RE.match(line)
        if not m:
            if start_marker is not None and (line.startswith("Disassembly")
                                             or (line.startswith("0000") and ">:" in line)):
                break
            continue
        addr = int(m.group("addr"), 16)
        raw = m.group("bytes").strip()
        ins = Insn(idx, addr, m.group("text"), raw, line)
        _fill_defuse(ins)
        out.append(ins)
        idx += 1
    return out


def _branch_target(ins, by_addr):
    # llvm-objdump prints the resolved target for s_branch / s_cbranch
    m = re.search(r"<(?P<name>[^>+]+)(?:\+0x(?P<off>[0-9A-Fa-f]+))?>", ins.raw)
    if m and ins.is_branch:
        return m.group("name"), (int(m.group("off"), 16) if m.group("off") else 0)
    return None


def _fill_defuse(ins: Insn):
    """Populate ins.uses / ins.defs (registers) and the special-register sets.

    Conservative approximation: an operand is a DESTINATION only in the
    positions the ISA defines as destinations.  Anything unrecognised is
    treated as a use (safe direction for a read-before-def census: it can
    only add uses, never hide one).
    """
    mn = ins.mnem
    ops = ins.ops

    # --- special registers that are implicitly read -----------------------
    for key in ("s_cbranch_execz", "s_cbranch_execnz"):
        if mn == key:
            ins.uses_special.append("exec")
    if mn in ("s_cbranch_vccz", "s_cbranch_vccnz", "s_cbranch_vccnz"):
        ins.uses_special.append("vcc")
    if mn in ("s_cbranch_scc0", "s_cbranch_scc1"):
        ins.uses_special.append("scc")
    if mn.startswith("s_cbranch_vcc"):
        ins.uses_special.append("vcc")
    if mn.startswith("s_cbranch_scc"):
        ins.uses_special.append("scc")
    if mn.startswith("s_cbranch_exec"):
        ins.uses_special.append("exec")
    if mn.startswith("v_cmpx_"):
        # CMPX predicates the comparison with the old EXEC mask and writes
        # the resulting mask back to EXEC.  Omitting either edge hides the
        # control dependency from def/use and liveness analyses.
        ins.uses_special.append("exec")
        ins.defs_special.append("exec")
    if mn in ("v_cndmask_b32", "v_cndmask_b32_e32"):
        if len(ops) > 2:
            ins.uses_special.append("vcc")
    if mn.startswith("v_addc_co_u32") or mn.startswith("v_subb_co_u32"):
        ins.uses_special.append("vcc")
    if mn.startswith("v_add_co_u32") or mn.startswith("v_sub_co_u32"):
        pass
    if mn.startswith("s_and_saveexec") or mn.startswith("s_or_saveexec") \
       or mn.startswith("s_xor_saveexec") or mn.startswith("s_nand_saveexec") \
       or mn.startswith("s_nor_saveexec") or mn.startswith("s_xnor_saveexec"):
        ins.uses_special.append("exec")
        ins.defs_special.append("exec")
    if mn in ("s_mov_b32", "s_mov_b64") and ops and ops[0] in ("exec_lo", "exec_hi", "exec"):
        ins.defs_special.append("exec")
        ins.uses_special.append("exec") if False else None
    if mn.startswith("s_") and ops and ops[0] in ("exec_lo", "exec_hi", "exec"):
        ins.defs_special.append("exec")
    if mn.startswith("s_") and ops and ops[0] in ("vcc_lo", "vcc_hi", "vcc"):
        ins.defs_special.append("vcc")
    if ops and ops[0] == "scc":
        ins.defs_special.append("scc")
    if mn.startswith("s_") and ops and ops[0] == "m0":
        ins.defs_special.append("m0")

    # --- explicit operand scan -------------------------------------------
    # scalar: op0 is a destination for the scalar ALU / scalar memory forms
    scalar_dst_positions = set()
    if mn.startswith("s_"):
        if _SCALAR_MEM.match(mn):
            # s_load_dword s4, s[0:1], off  -> op0 dst, op1 sbase use
            if ops and ops[0].startswith("s"):
                scalar_dst_positions.add(0)
        elif mn.startswith(("s_cbranch", "s_branch", "s_setpc", "s_swappc",
                            "s_endpgm", "s_barrier", "s_waitcnt", "s_sleep",
                            "s_nop", "s_sethalt", "s_trap", "s_dcache",
                            "s_icache", "s_dmb", "s_wait_idle", "s_setkill",
                            "s_set_gpr_idx", "s_rfe", "s_sendmsg",
                            "s_ttracedata", "s_atc", "s_memtime", "s_memrealtime",
                            "s_clause", "s_code_end", "s_inst_prefetch")):
            pass
        else:
            # s_mov_b32 s12, exec_lo / s_add_i32 s4, s6, s15 ...
            if ops and (ops[0].startswith("s") or ops[0] in ("exec_lo", "exec_hi")
                        or ops[0] == "scc" or ops[0] == "m0"):
                scalar_dst_positions.add(0)

    # vector: op0 is a destination for VALU/VOP/VINTRP; for DS reads the
    # destination is also op0 (ds_read_b32 v1, v0).  For global_load the
    # destination is op0 too.  Stores have no destination.
    vector_dst_positions = set()
    if mn.startswith(("v_", "ds_", "global_", "flat_", "scratch_", "buffer_",
                      "image_", "exp")):
        if not mn.startswith(("ds_write", "global_store", "flat_store",
                              "scratch_store", "buffer_store", "global_atomic",
                              "flat_atomic", "buffer_atomic", "ds_add",
                              "ds_sub", "ds_inc", "ds_dec", "ds_min", "ds_max",
                              "ds_and", "ds_or", "ds_xor", "ds_mskor",
                              "ds_cmpst", "ds_wrxchg", "s_")):
            if ops:
                is_store_like = ("store" in mn) or ("_write" in mn)
                if not is_store_like:
                    vector_dst_positions.add(0)
            # v_cmp with explicit sdst in e64 form: last operand is dst SGPR
            if VOPC_SDST.match(mn) and len(ops) >= 3 and ops[-1].startswith("s"):
                scalar_dst_positions.add(len(ops) - 1)
            # v_cmp_*_e32 (VOPC) writes VCC implicitly -> not a textual dst
            if mn.startswith("v_cmp") and mn.endswith("_e32"):
                ins.defs_special.append("vcc")

    for pos, op in enumerate(ops):
        o = op.strip()
        if not o:
            continue
        # strip memory-operand decorations but keep the registers
        is_dst = (pos in scalar_dst_positions) or (pos in vector_dst_positions)
        for kind, ridx in _regs_from_operand(o):
            if kind in ("exec", "vcc", "scc", "m0", "flat_scratch", "xnack", "ttmp"):
                if is_dst and kind not in ("flat_scratch",):
                    if kind not in ins.defs_special:
                        ins.defs_special.append(kind)
                else:
                    if kind not in ins.uses_special:
                        ins.uses_special.append(kind)
                continue
            entry = (kind, ridx)
            if is_dst:
                if entry not in ins.defs:
                    ins.defs.append(entry)
            else:
                if entry not in ins.uses:
                    ins.uses.append(entry)
        # a destination register is never also a use on the same instruction
        # for these forms (no read-modify-write in scalar ALU)
    ins.uses = [u for u in ins.uses if u not in ins.defs]


def build_blocks(prog):
    """Split into basic blocks keyed by start index; return (blocks, addr2idx)."""
    addr2idx = {i.addr: i.idx for i in prog}
    bounds = {0}
    for i, ins in enumerate(prog):
        if ins.is_branch:
            bounds.add(i + 1)
            t = _branch_target(ins, addr2idx)
            if t:
                name, off = t
                # resolve to the label position: labels are not in `prog`,
                # so scan forward for the first insn whose address >= target
                pass
    return addr2idx
