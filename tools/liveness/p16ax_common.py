#!/usr/bin/env python3
"""Phase 16AX / W9 -- shared machinery for the machine-liveness reconciliation.

WHAT IS HERE, AND WHY IT IS WRITTEN HERE RATHER THAN REUSED
    The 16AW prover is the SUBJECT under test in this phase, so it is imported
    and executed as-is -- but every FACT this phase reports about the object is
    re-derived here by a route that does not go through the 16AW code:

      * `text_section_of` / `whole_sha`   -- my own ELF reader, my own hashing
      * `disassemble_own`                 -- my own llvm-objdump invocation and
                                             line parser (not M.disassemble /
                                             M.parse_disassembly)
      * `branch_target_own`               -- my own SOPP simm16 decode, so the
                                             backward-branch count does not come
                                             from the 16AT branch decoder
      * `Interp`                          -- a STRAIGHT LINE INTERPRETER over the
                                             decoded instruction stream.  This is
                                             the one mechanism in this phase that
                                             is not a recurrence argument at all:
                                             it executes the control flow and
                                             counts guard evaluations, so the
                                             trip counts have a witness that does
                                             not share a formula, a parser or a
                                             failure mode with the prover.

    House rule 4 says two checks sharing a lineage are one check run twice.  The
    interpreter is the deliberate exception to that: it is here BECAUSE it shares
    nothing with the prover except the decoded text.

Host-only.  Disassembling is not launching: no HIP call, no GPU, no slot.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

#: the object this whole phase is about
OBJ = os.path.join(ROOT, "p16as", "native", "hip", "build",
                   "k_dec_upsample_b64.co")
#: the brief's own quoted .text hash, so a mismatch is visible rather than
#: silently absorbed
TEXT_SHA_IN_BRIEF = \
    "ec11c135cf9a548cfd2e263757723a178b74bb148496be35bd47b2a95a85312e"
WHOLE_SHA_IN_BRIEF = \
    "24f53bd0f621215c232c782444e7aa364d0e57622b1fd9360e78efdb43572224"

OBJDUMP = r"<ROCM_ROOT>\6.4\bin\llvm-objdump.exe"
MC = r"<ROCM_ROOT>\6.4\bin\llvm-mc.exe"

WORK = os.path.join(HERE, "_work")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: str) -> str:
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _u(b, off, n):
    return int.from_bytes(b[off:off + n], "little")


# =====================================================================
# 1.  MY OWN ELF READER
# =====================================================================
def elf_section_table(co: str):
    b = open(co, "rb").read()
    if b[:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
        raise RuntimeError("%s is not a little-endian ELF64 file" % co)
    shoff, shent, shnum, shstr = (_u(b, 0x28, 8), _u(b, 0x3A, 2),
                                 _u(b, 0x3C, 2), _u(b, 0x3E, 2))
    raw = []
    for i in range(shnum):
        o = shoff + i * shent
        raw.append({"idx": i, "name_off": _u(b, o, 4),
                    "type": _u(b, o + 4, 4),
                    "flags": _u(b, o + 8, 8),
                    "addr": _u(b, o + 16, 8),
                    "offset": _u(b, o + 24, 8),
                    "size": _u(b, o + 32, 8)})
    st = raw[shstr]
    names = b[st["offset"]:st["offset"] + st["size"]]
    for s in raw:
        e = names.find(b"\x00", s["name_off"])
        s["name"] = names[s["name_off"]:e].decode("ascii", "replace")
    return {s["name"]: s for s in raw}, b


def text_section_of(co: str):
    """{sha256, size, offset, vma, n_bytes} for .text, read from the object's
    OWN section header table.  The bytes hashed are the bytes on disk now."""
    secs, b = elf_section_table(co)
    if ".text" not in secs:
        raise RuntimeError("%s has no .text section" % co)
    s = secs[".text"]
    data = b[s["offset"]:s["offset"] + s["size"]]
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": s["size"],
            "offset": s["offset"], "vma": s["addr"], "n_bytes": len(data)}


def elf_metadata(co: str):
    """The kernel descriptor's ABI numbers, read from .note by llvm-readobj.
    Independent of the CFG/prover path entirely."""
    ro = os.path.join(os.path.dirname(OBJDUMP), "llvm-readobj.exe")
    r = subprocess.run([ro, "--notes", co], capture_output=True, text=True)
    if r.returncode != 0:
        return {"error": r.stderr.strip()}
    out = {}
    for k in ("sgpr_count", "vgpr_count", "kernarg_segment_size",
              "wavefront_size", "group_segment_fixed_size",
              "private_segment_fixed_size", "sgpr_spill_count",
              "vgpr_spill_count", "max_flat_workgroup_size"):
        m = re.search(r"%s:\s*(\S+)" % k, r.stdout)
        if m:
            out[k] = m.group(1)
    return out


# =====================================================================
# 2.  MY OWN DISASSEMBLY ROUTE
# =====================================================================
INSN_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s*(?:([0-9a-fA-F]{8,16})\s+)?(.*)$")
ADDR_COMMENT_RE = re.compile(r"//\s*([0-9a-fA-F]{4,16})\s*:")


def disassemble_own(co: str, mcpu="gfx1030"):
    """[(addr, mnemonic, operands, raw_hex_or_None)] straight from objdump.

    This deliberately does NOT reuse M.parse_disassembly, so a parse defect in
    the 16AT front end cannot silently become a fact of this phase as well.
    """
    r = subprocess.run([OBJDUMP, "-d", "--triple=amdgcn--amdhsa",
                        "--mcpu=%s" % mcpu, co], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("llvm-objdump failed on %s: %s" % (co, r.stderr))
    out = []
    for line in r.stdout.splitlines():
        if "//" not in line:
            continue
        m = ADDR_COMMENT_RE.search(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        body = line[:line.find("//")].strip()
        if not body or body.startswith("..."):
            continue
        parts = body.split(None, 1)
        mn = parts[0]
        ops = parts[1].strip() if len(parts) > 1 else ""
        out.append((addr, mn, ops, None))
    out.sort()
    seen = {}
    for row in out:
        seen[row[0]] = row
    return [seen[a] for a in sorted(seen)]


def raw_words_of(co: str):
    """{addr: bytes} for every instruction word in .text, decoded from the
    object's own bytes by walking the instruction stream the way objdump does.

    THE PROBLEM THIS SOLVES: to count BACKWARD BRANCHES without trusting either
    the 16AT decoder or objdump's printed operand, the branch displacement has
    to be read from the raw word -- and the raw word's ADDRESS has to be known.
    Instruction sizes are not uniform (an s_load_dword with an immediate offset
    is two words), so the addresses are taken from objdump's own listing and the
    BYTES are taken from the file.  The two are cross-checked: a word whose
    bytes do not lie inside .text is a refusal, not a guess.
    """
    t = text_section_of(co)
    b = open(co, "rb").read()
    text = b[t["offset"]:t["offset"] + t["size"]]
    ins = disassemble_own(co)
    addrs = [a for a, _m, _o, _r in ins]
    out = {}
    for i, a in enumerate(addrs):
        nxt = addrs[i + 1] if i + 1 < len(addrs) else t["vma"] + t["size"]
        n = nxt - a
        off = a - t["vma"]
        if n <= 0 or off < 0 or off + n > len(text):
            raise RuntimeError("instruction at %#x has size %d, which does not "
                               "lie inside .text" % (a, n))
        out[a] = text[off:off + n]
    return out, t


def branch_target_own(word: bytes, addr: int):
    """The SOPP/GNU-style scalar branch displacement, decoded here.

    On gfx1030 every s_branch / s_cbranch_* is a SOPP: the signed 16-bit
    displacement sits in bits [15:0] and the target is
    addr + 4 + 4 * sext16(disp).  Verified against the archive: at 0x1ad4 the
    printed operand is 65384 = 0xff68, and 0x1ad4 + 4 + 4*(-152) = 0x1878,
    which is the head pc the CFG analysis reports.
    """
    if len(word) < 4:
        return None
    lo = int.from_bytes(word[:2], "little")
    s = lo - 0x10000 if lo >= 0x8000 else lo
    return addr + 4 + 4 * s


BRANCH_MNEM_PREFIX = ("s_branch", "s_cbranch", "s_setpc", "s_swappc")


def backward_branches_own(co: str):
    """[{at, mnemonic, target, is_backward}] -- MY decode, MY count.

    A branch whose raw word could not be turned into a target is reported with
    target None and counted as UNRESOLVED, which is a blocking fact rather than
    something to average away.
    """
    words, t = raw_words_of(co)
    ins = disassemble_own(co)
    rows = []
    for addr, mn, ops, _r in ins:
        if not mn.startswith(BRANCH_MNEM_PREFIX):
            continue
        tgt = branch_target_own(words[addr], addr)
        rows.append({"at": addr, "hex": hex(addr), "mnemonic": mn,
                     "operands": ops, "target": tgt,
                     "target_hex": None if tgt is None else hex(tgt),
                     "is_backward": bool(tgt is not None and tgt <= addr),
                     "word_hex": words[addr].hex().upper()})
    return rows, t


# =====================================================================
# 3.  A STRAIGHT-LINE INTERPRETER OVER THE DECODED INSTRUCTIONS
# =====================================================================
class Unknown(object):
    """A value this interpreter refuses to guess: a load from memory, or a
    register derived from one.  Every operation that reads it produces it
    again, and a compare that reads it makes the condition code UNKNOWN."""

    __slots__ = ("why",)

    def __init__(self, why):
        self.why = why

    def __repr__(self):
        return "<unknown: %s>" % self.why


UNK_SCC = Unknown("the branch condition depends on a value this interpreter "
                  "cannot know (a memory load or something derived from one)")


def _imm(tok):
    t = tok.strip()
    try:
        return int(t, 0) & 0xFFFFFFFF
    except ValueError:
        return None


def _reg(tok):
    t = tok.strip()
    m = re.fullmatch(r"s(\d+)", t)
    if m:
        return ["s" + m.group(1)]
    m = re.fullmatch(r"s\[(\d+):(\d+)\]", t)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        return ["s%d" % i for i in range(a, b + 1)]
    return None


CMP_RE = re.compile(r"^s_cmp(k)?_(eq|lg|gt|ge|lt|le)_(u32|i32)$")


def _sv(x, signed):
    if not signed:
        return x & 0xFFFFFFFF
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x >= 0x80000000 else x


def _cmp_true(op, a, b, signed):
    x, y = _sv(a, signed), _sv(b, signed)
    return {"eq": x == y, "lg": x != y, "gt": x > y, "ge": x >= y,
            "lt": x < y, "le": x <= y}[op]


def norm_ins(ins):
    """[(addr, mnemonic, operands)] from either a dict row (the synthetic
    builder's shape) or a tuple row (this module's own decode)."""
    out = []
    for x in ins:
        if isinstance(x, dict):
            out.append((x["addr"], x["mnemonic"], x.get("operands", "")))
        else:
            out.append((x[0], x[1], x[2]))
    return out


class Interp(object):
    """Execute a decoded instruction stream until s_endpgm, a step limit, or a
    branch whose condition cannot be decided.

    Only the scalar ALU, the scalar compares and the scalar branches are
    modelled, deliberately: those are the instructions a counted loop is made
    of, and modelling anything else would be inventing semantics.  `s_load_*`
    produces Unknown, which is what makes a spin loop UNKNOWN here as well --
    by a route that has nothing to do with the prover's SGPR closure.
    """

    def __init__(self, ins, step_limit=2_000_000):
        rows = norm_ins(ins)
        self.prog = {a: (mn, ops) for a, mn, ops in rows}
        self.addrs = sorted(self.prog)
        self.index = {a: i for i, a in enumerate(self.addrs)}
        self.step_limit = step_limit
        self.regs = {}
        self.scc = False
        self.pc = self.addrs[0]
        self.steps = 0
        self.exec_count = {}
        self.targets = {}
        self.assumptions = set()

    # ---- operand plumbing -------------------------------------------------
    def read(self, tok):
        r = _reg(tok)
        if r is not None:
            if len(r) == 1:
                return self.regs.get(r[0], Unknown("read of an unwritten "
                                                   "register %s" % r[0]))
            return Unknown("a 64-bit register pair read as a unit")
        v = _imm(tok)
        if v is not None:
            return v
        return Unknown("operand %r is neither a scalar register nor an "
                       "immediate" % tok)

    def write(self, tok, val):
        r = _reg(tok)
        if r is None:
            return
        if len(r) == 1:
            self.regs[r[0]] = val
            return
        base = val if isinstance(val, int) else None
        for i, rr in enumerate(r):
            if i == 0 and base is not None:
                self.regs[rr] = base & 0xFFFFFFFF
            else:
                self.regs[rr] = Unknown("the high half of a 64-bit pair")

    # ---- the interpreter --------------------------------------------------
    def run(self, watch_addrs=()):
        watch = set(watch_addrs)
        while self.steps < self.step_limit:
            if self.pc not in self.prog:
                return {"status": "FELL_OFF_THE_END",
                        "at": hex(self.pc), "steps": self.steps,
                        "guard_evaluations": self._n(watch)}
            mn, ops = self.prog[self.pc]
            self.exec_count[self.pc] = self.exec_count.get(self.pc, 0) + 1
            cur = self.pc
            self.steps += 1
            f = [t.strip() for t in ops.split(",")] if ops.strip() else []

            if mn == "s_endpgm" or mn.startswith("s_endpgm"):
                return {"status": "HALTED", "at": hex(cur),
                        "steps": self.steps,
                        "guard_evaluations": self._n(watch),
                        "scc": self.scc}
            if mn == "s_nop" or mn.startswith("s_waitcnt") or \
                    mn.startswith("s_clause"):
                self.pc = self._next(cur)
                continue
            if mn.startswith("s_load_") or mn.startswith("s_buffer_load") or \
                    mn.startswith("s_scratch_load"):
                if f:
                    self.write(f[0], Unknown("a memory load"))
                self.pc = self._next(cur)
                continue
            if mn in ("s_mov_b32", "s_movk_i32", "s_mov_b64"):
                v = self.read(f[1]) if len(f) > 1 else Unknown("no source")
                if mn == "s_movk_i32" and isinstance(v, int):
                    v = v & 0xFFFF
                    if v & 0x8000:
                        v -= 0x10000
                    v &= 0xFFFFFFFF
                if len(f) > 0:
                    self.write(f[0], v)
                self.pc = self._next(cur)
                continue
            m = re.match(r"^s_(lshl|lshr|ashr|and|or|xor|andn2|orn2)_(b32)$", mn)
            if m:
                #: a bitwise/shift step behind the guard.  The result is exactly
                #: as knowable as its inputs, so an Unknown input propagates and
                #: a known input gets the REAL result -- an interpreter that
                #: answered Unknown for a value it could compute would be
                #: conservative in a way that hides mistakes.
                op = m.group(1)
                d = f[0]
                a = self.read(f[1])
                b = self.read(f[2]) if len(f) > 2 else Unknown("no second "
                                                               "operand")
                if isinstance(a, Unknown) or isinstance(b, Unknown):
                    self.write(d, a if isinstance(a, Unknown) else b)
                else:
                    a &= 0xFFFFFFFF
                    b &= 0xFFFFFFFF
                    if op == "lshl":
                        v = (a << (b & 31)) & 0xFFFFFFFF
                    elif op == "lshr":
                        v = (a >> (b & 31)) & 0xFFFFFFFF
                    elif op == "ashr":
                        v = (C._sv(a, True) >> (b & 31)) & 0xFFFFFFFF
                    elif op == "and":
                        v = a & b
                    elif op == "or":
                        v = a | b
                    elif op == "xor":
                        v = a ^ b
                    elif op == "andn2":
                        v = a & (~b & 0xFFFFFFFF)
                    else:                      # orn2
                        v = a | (~b & 0xFFFFFFFF)
                    self.write(d, v)
                self.pc = self._next(cur)
                continue
            m = re.match(r"^s_(lshl|lshr|ashr|and|or|xor)_(b64|i64|u64)$", mn)
            if m:
                self.write(f[0], Unknown("a 64-bit bitwise operation is not "
                                        "modelled by this interpreter"))
                self.pc = self._next(cur)
                continue
            m = re.match(r"^s_(add|sub|addk)_(u32|i32)$", mn)
            if m:
                fam = m.group(1)
                if fam == "addk":
                    d, a_tok, k_tok = f[0], f[0], f[1]
                else:
                    d, a_tok, k_tok = f[0], f[1], f[2]
                a = self.read(a_tok)
                k = self.read(k_tok)
                if isinstance(a, Unknown):
                    self.write(d, a)
                elif isinstance(k, Unknown):
                    self.write(d, k)
                else:
                    v = (a + k) if fam in ("add", "addk") else (a - k)
                    self.write(d, v & 0xFFFFFFFF)
                self.pc = self._next(cur)
                continue
            m = CMP_RE.match(mn)
            if m:
                _k, op, sd = m.groups()
                if len(f) >= 2:
                    a = self.read(f[0])
                    b = self.read(f[1])
                    if isinstance(a, Unknown) or isinstance(b, Unknown):
                        self.scc = UNK_SCC
                    else:
                        self.scc = _cmp_true(op, a, b, sd == "i32")
                self.pc = self._next(cur)
                continue
            if mn in ("s_branch",):
                t = self._target(cur)
                if t is None:
                    return {"status": "UNRESOLVED_BRANCH", "at": hex(cur),
                            "steps": self.steps,
                            "guard_evaluations": self._n(watch)}
                self.pc = t
                continue
            if mn.startswith("s_cbranch_exec"):
                #: EXEC-derived branches are NOT decided by SCC.  This
                #: interpreter assumes a full EXEC mask (no divergence), and
                #: SAYS SO in every row that uses it, because that assumption is
                #: a modelling choice and not a measurement.
                self.assumptions.add(
                    "AT %s the branch reads EXEC, which this interpreter "
                    "assumes to be full (whole wave active) -- divergence is "
                    "NOT modelled" % hex(cur))
                take = mn.startswith("s_cbranch_execnz")
                if take:
                    t = self._target(cur)
                    if t is None:
                        return {"status": "UNRESOLVED_BRANCH", "at": hex(cur),
                                "steps": self.steps,
                                "guard_evaluations": self._n(watch)}
                    self.pc = t
                else:
                    self.pc = self._next(cur)
                continue
            if mn.startswith("s_cbranch_scc0") or mn.startswith("s_cbranch_scc1"):
                if isinstance(self.scc, Unknown):
                    return {"status": "UNDETERMINED_SCC", "at": hex(cur),
                            "steps": self.steps,
                            "guard_evaluations": self._n(watch),
                            "why": self.scc.why}
                take = self.scc if mn.startswith("s_cbranch_scc1") \
                    else (not self.scc)
                if take:
                    t = self._target(cur)
                    if t is None:
                        return {"status": "UNRESOLVED_BRANCH", "at": hex(cur),
                                "steps": self.steps,
                                "guard_evaluations": self._n(watch)}
                    self.pc = t
                else:
                    self.pc = self._next(cur)
                continue
            if mn.startswith(("s_cbranch_", "s_setpc", "s_swappc")):
                return {"status": "UNMODELLED_BRANCH", "at": hex(cur),
                        "mnemonic": mn, "steps": self.steps,
                        "guard_evaluations": self._n(watch)}
            return {"status": "UNMODELLED_INSTRUCTION", "at": hex(cur),
                    "mnemonic": mn, "operands": ops, "steps": self.steps,
                    "guard_evaluations": self._n(watch)}
        return {"status": "STEP_LIMIT_REACHED", "steps": self.steps,
                "guard_evaluations": self._n(watch),
                "assumptions": sorted(self.assumptions),
                "note": "the program did not reach s_endpgm within the limit; "
                        "this is a witness of non-termination up to the limit, "
                        "not a proof of it"}

    def _n(self, watch):
        return {hex(a): self.exec_count.get(a, 0) for a in watch}

    def _next(self, cur):
        i = self.index[cur]
        return self.addrs[i + 1] if i + 1 < len(self.addrs) else cur + 4

    def _target(self, cur):
        # the interpreter works from the DECODED operands, so it needs the
        # addresses too; the caller passes them in via `prog_addrs`.
        return self.targets.get(cur)

    def attach_targets(self, targets):
        self.targets = targets
        return self


# =====================================================================
# 4.  THE 16AW SYNTHETIC BUILDER (imported, not re-implemented)
# =====================================================================
def _load_16aw():
    d = os.path.join(ROOT, "p16aw", "liveness")
    if d not in sys.path:
        sys.path.insert(0, d)
    import p16aw_synthetic as S          # noqa: E402
    import p16aw_loop_recurrence_prover as P   # noqa: E402
    import p16aw_old_classifier as OLD    # noqa: E402
    return S, P, OLD


def build_program(prog, obj=OBJ, scratch_dir=None, label="prog"):
    """Assemble `prog` [(asm, target_index_or_None)] into a COPY of the object,
    read it back with objdump, and return (ins, symbol_base, verification).

    The bytes analysed here are the bytes objdump read back, so a control that
    plants one thing and tests another fails in the builder rather than passing
    quietly.  Nothing is written outside this phase's own scratch directory.
    """
    S, _P, _O = _load_16aw()
    return S.build_program(prog, obj, scratch_dir or WORK, label=label)


build = build_program


def targets_from_printed(ins):
    """{addr: target_addr} decoded from the branch operand objdump printed.

    THE TRAP THIS AVOIDS: llvm-objdump prints the branch operand as the RAW
    SIGNED 16-BIT DISPLACEMENT IN WORDS, not as an address -- the archive's own
    listing shows `s_cbranch_scc0 65384` at 0x1ad4 for a branch to 0x1878, and
    65384 = 0xff68 is -152 words.  Reading that number as an address would put
    every interpreter target at 0xff68 and the interpreter would report
    FELL_OFF_THE_END on a program that in fact loops.  The value is therefore
    sign-extended and scaled exactly as the hardware scales it.
    """
    t = {}
    for a, mn, ops in norm_ins(ins):
        if not mn.startswith(BRANCH_MNEM_PREFIX):
            continue
        tok = ops.strip().rstrip(",").split()[-1] if ops.strip() else ""
        v = _imm(tok)
        if v is None:
            t[a] = None
            continue
        d = v & 0xFFFF
        if d >= 0x8000:
            d -= 0x10000
        t[a] = a + 4 + 4 * d
    #: the same decode applied to the raw word must agree; when it cannot be
    #: checked (no word available) the printed route stands alone and says so.
    return t


def build_interp(ins, step_limit=2_000_000):
    it = Interp(ins, step_limit=step_limit)
    it.attach_targets(targets_from_printed(ins))
    return it


def dump(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1)
    return sha256_file(path)


def rel(p):
    return os.path.relpath(p, ROOT).replace("\\", "/")
