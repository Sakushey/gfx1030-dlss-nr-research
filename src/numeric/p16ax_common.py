#!/usr/bin/env python3
"""Phase 16AX -- shared harness for the T-NUMERIC worker (k_dec_upsample).

Host-only.  No HIP call, no GPU, no launch, no slot.

WHAT THIS MODULE PROVIDES

  sha256_file(path) / sha256_bytes(b)
      Every digest this worker writes is recomputed from the bytes on disk in
      this session.  Nothing is inherited, padded or re-serialised.

  disassemble(path)
      Runs the ROCm 6.4 `llvm-objdump` over a file and parses
      (address, text) out of the `// <16 hex digits>: <encoding>` comment
      column.  The caller is responsible for disassembling a COPY -- project
      memory records that `llvm-objcopy` without an explicit output rewrote a
      frozen code object in place, so nothing here ever points a tool at the
      frozen artefact.

  isa_census(insns) / loops(insns)
      An opcode census and a back-edge scan, so a claim about what the object
      emits is a reading of the object rather than a restatement of a record.

  resolve_fold_chains(insns, lo, hi)
      The NF-1 instrument: inside a region, find every
      `v_cvt_f32_f16_e32` whose destination is then read by a
      `v_add_f32_e32`, whose destination is then read by
      `v_cvt_f16_f32_e32`.  That three-instruction sequence is
      uplift -> f32 add -> round back, i.e. TWO roundings at one chunk
      boundary.  Chains are resolved by REGISTER NAME, not by instruction
      adjacency, so an independent reordering by the compiler cannot hide one.

  Report(x)
      A check recorder that FAILS any check whose compared count is zero.
      A checker that goes green having compared nothing is worse than no
      checker (house rule 3).

Independence note: the reference modules are loaded from the frozen 16AW
directory BY PATH with an identity assertion (`load_by_path`).  This module
implements no arithmetic of its own beyond exact integer/rational reasoning on
binary formats; nothing here re-uses A's or B's accumulator helper.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import struct
import subprocess
from fractions import Fraction as Q

ROOT = r"<PROJECT_ROOT>"
ROCm = r"<ROCM_ROOT>\6.4"
OBJDUMP = os.path.join(ROCm, "bin", "llvm-objdump.exe")
READOBJ = os.path.join(ROCm, "bin", "llvm-readobj.exe")
CLANGXX = os.path.join(ROCm, "bin", "clang++.exe")
BUNDLER = os.path.join(ROCm, "bin", "clang-offload-bundler.exe")

P16AW_NUMERIC = os.path.join(ROOT, "p16aw", "numeric")
P16AR_REF = os.path.join(ROOT, "p16ar", "reference")

A_16AW = os.path.join(P16AW_NUMERIC, "k_dec_upsample_A_rn32.py")
B_16AW = os.path.join(P16AW_NUMERIC, "k_dec_upsample_B_independent.py")
A_16AR = os.path.join(ROOT, "p16ar", "native", "cpu_reference",
                      "k_dec_upsample_A.py")
B_16AR = os.path.join(ROOT, "p16ar", "native", "cpu_reference",
                      "k_dec_upsample_B.py")
FROZEN_CO = os.path.join(ROOT, "p16as", "native", "hip", "build",
                         "k_dec_upsample_b64.co")
NATIVE_SRC = os.path.join(ROOT, "p16as", "native", "hip",
                          "k_dec_upsample_gfx1030.cpp")
NATIVE_HDR = os.path.join(ROOT, "p16as", "native", "hip",
                          "k_dec_upsample_fp8.h")
UPSTREAM_REF = os.path.join(ROOT, "p16as", "_fetch", "upstream",
                            "Development", "native_c64_reference.py")
UPSTREAM_C32 = os.path.join(ROOT, "p16as", "_fetch", "upstream",
                            "Development", "native_c32_reference.py")
PINNING_16AR = os.path.join(P16AR_REF, "NUMERIC_PRECISION_PINNING_16AR.json")

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(HERE, "_work")

MATRIX_ROWS, MATRIX_COLS = 512, 1024
CHUNK, PARTITION = 32, 256


# ---------------------------------------------------------------------------
# digests -- always from bytes
# ---------------------------------------------------------------------------
def sha256_file(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def file_record(p: str) -> dict:
    return {"path": os.path.relpath(p, ROOT).replace("\\", "/"),
            "bytes": os.path.getsize(p), "sha256": sha256_file(p)}


# ---------------------------------------------------------------------------
# module loading, with an identity assertion (16L's silent-wrong-module defect)
# ---------------------------------------------------------------------------
def load_by_path(name: str, path: str):
    """Import `path` as module `name` and ASSERT the loaded file IS `path`."""
    want = os.path.normcase(os.path.abspath(path))
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    got = os.path.normcase(os.path.abspath(mod.__file__))
    if got != want:
        raise AssertionError("loaded %s, wanted %s" % (got, want))
    return mod


# ---------------------------------------------------------------------------
# disassembly
# ---------------------------------------------------------------------------
def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def disassemble(path: str):
    """-> (instructions, raw_stdout, raw_stderr, returncode)

    `instructions` is a list of dicts {addr:int, text:str, encoding:str}.  The
    address and encoding are read from llvm-objdump's comment column, so an
    instruction is never located by line number.
    """
    r = run([OBJDUMP, "-d", "--arch-name=amdgcn", "--mcpu=gfx1030", path])
    insns = []
    #: symbol bases, from the `0000000000001800 <kd_dec_upsample>:` label lines.
    #: A branch's target is printed as `<sym+0xoffset>` in the comment column;
    #: resolving it here means the disassembler's own address arithmetic is
    #: used rather than a re-derivation of the encoded displacement.
    bases = {}
    for line in (r.stdout or "").splitlines():
        s = line.strip()
        if s.endswith(":") and "<" in s and s.split()[0].endswith(":"):
            head = s.split()[0][:-1]
            try:
                bases[s[s.index("<") + 1:s.index(">")]] = int(head, 16)
            except ValueError:
                pass
    for line in (r.stdout or "").splitlines():
        if "//" not in line:
            continue
        left, right = line.split("//", 1)
        right = right.strip()
        if ":" not in right:
            continue
        a_hex, enc = right.split(":", 1)
        a_hex, enc = a_hex.strip(), enc.strip()
        # llvm-objdump prints the address as a 48-bit zero-padded hex literal
        # (12 digits) inside the comment column; accept any width rather than
        # binding the parser to one tool version's padding.
        if not a_hex or len(a_hex) > 16:
            continue
        try:
            addr = int(a_hex, 16)
        except ValueError:
            continue
        text = left.strip()
        if not text:
            continue
        tgt = None
        if "<" in enc and ">" in enc:
            sym = enc[enc.index("<") + 1:enc.index(">")]
            if "+" in sym:
                name, off = sym.split("+", 1)
                try:
                    tgt = bases.get(name, 0) + int(off, 16)
                except ValueError:
                    tgt = None
            else:
                tgt = bases.get(sym)
        insns.append({"addr": addr, "text": text, "encoding": enc,
                      "branch_target": tgt})
    return insns, (r.stdout or ""), (r.stderr or ""), r.returncode


def symbol_ranges(path: str):
    """-> {symbol_name: (addr, size)} read from `llvm-objdump -t`."""
    r = run([OBJDUMP, "-t", path])
    out = {}
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].endswith(":"):
            try:
                addr = int(parts[0][:-1], 16)
            except ValueError:
                continue
            name = parts[-1]
            size = None
            for p in parts:
                if p.startswith("000000000000") and len(p) == 16:
                    try:
                        size = int(p, 16)
                    except ValueError:
                        pass
            out[name] = (addr, size)
    return out


def opcode_of(text: str) -> str:
    """The mnemonic, modifier-free (llvm prints `v_fma_mix_f32 v1, ...`)."""
    return text.split()[0] if text.split() else ""


def census(insns):
    c = {}
    for i in insns:
        op = opcode_of(i["text"])
        c[op] = c.get(op, 0) + 1
    return c


def _signed16(v: int) -> int:
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def back_edges(insns, use_unsigned=False, from_displacement=False):
    """Branches whose target is BELOW them (a back edge).

    The target comes from the disassembler's own `<sym+offset>` rendering.
    `use_unsigned=True` re-reads the same encoded 16-bit displacement as
    UNSIGNED, which is the CONTROL that shows the sign handling is
    load-bearing: read that way, every back edge becomes a forward one.
    """
    out = []
    by_addr = {i["addr"]: n for n, i in enumerate(insns)}
    for n, i in enumerate(insns):
        op = opcode_of(i["text"])
        if not (op.startswith("s_branch") or op.startswith("s_cbranch")):
            continue
        tgt = None
        if not from_displacement:
            tgt = i["branch_target"]
        if tgt is None:
            toks = i["text"].split()
            if len(toks) >= 2 and toks[1].lstrip("-").isdigit():
                disp = int(toks[1])
                disp = (disp & 0xFFFF) if use_unsigned else _signed16(disp)
                tgt = i["addr"] + 4 + disp * 4
        if tgt is None:
            continue
        if tgt < i["addr"]:
            out.append({"from": i["addr"], "to": tgt,
                        "from_index": n, "to_index": by_addr.get(tgt),
                        "text": i["text"]})
    return out


# ---------------------------------------------------------------------------
# NF-1's instrument: uplift -> f32 add -> round back, resolved by register
# ---------------------------------------------------------------------------
def _operands(text: str):
    """(dest, [srcs], {mods}) for a VOP-style instruction, text-level."""
    if " " not in text:
        return None, [], {}
    head, rest = text.split(" ", 1)
    parts = [p.strip() for p in rest.split(",")]
    if len(parts) < 2:
        return None, [], {}
    dest = parts[0]
    srcs, mods = [], {}
    for p in parts[1:]:
        if ":" in p and "[" in p and not p.startswith("0x"):
            mods.setdefault("sel", []).append(p)
        elif p.startswith("op_sel") or p.startswith("op_sel_hi"):
            mods.setdefault("op_sel", []).append(p)
        else:
            srcs.append(p)
    return dest, srcs, mods


def prim_mask(text: str):
    return None


def resolve_fold_chains(insns, lo: int, hi: int, window: int = 24,
                        wrong_src_control: bool = False):
    """Find uplift -> f32 add -> round-back chains inside [lo, hi].

    A chain is: `v_cvt_f32_f16_e32` (uplift the binary16 running sum to
    binary32), then a `v_add_f32_e32` that READS the uplifted register as an
    addend, then a `v_cvt_f16_f32_e32` that READS the add's destination --
    i.e. rounds the sum back to binary16.  TWO roundings at one chunk
    boundary, against the fold's other shape (`v_add_f16_e32`), which rounds
    once.

    Resolution is by REGISTER NAME within a bounded window, not by adjacency,
    because the compiler interleaves four independent chains.  The first
    matching add and the first matching round-back after it are taken.

    `wrong_src_control=True` substitutes an impossible register as the thing
    the round-back must read, so a chain search that resolves NOTHING proves
    the register test is load-bearing rather than incidental.
    """
    win = [i for i in insns if lo <= i["addr"] <= hi]
    ups, adds, downs = [], [], []
    for wi, i in enumerate(win):
        op = opcode_of(i["text"])
        if op == "v_cvt_f32_f16_e32":
            ups.append((wi, i))
        elif op == "v_add_f32_e32":
            adds.append((wi, i))
        elif op == "v_cvt_f16_f32_e32":
            downs.append((wi, i))

    def ops_of(idx):
        return [p.strip() for p in
                win[idx]["text"].split(" ", 1)[1].split(",")]

    chains = []
    resolved_with_a_wrong_target = 0
    for ui, u in ups:
        ud, _us, _ = _operands(u["text"])
        if ud is None:
            continue
        add_at = add_dst = None
        for j in range(ui + 1, min(ui + 1 + window, len(win))):
            if opcode_of(win[j]["text"]) != "v_add_f32_e32":
                continue
            o = ops_of(j)
            if ud in o[1:]:                      # the uplifted value is a src
                add_at, add_dst = win[j]["addr"], o[0]
                break
        if add_at is None:
            continue
        back = None
        for j in range(ui + 1, min(ui + 1 + window, len(win))):
            if win[j]["addr"] <= add_at:
                continue
            if opcode_of(win[j]["text"]) != "v_cvt_f16_f32_e32":
                continue
            o = ops_of(j)
            want = "__never_a_register__" if wrong_src_control else add_dst
            if len(o) >= 2 and o[1] == want:
                back = (win[j]["addr"], o)
                break
        if back:
            chains.append({
                "uplift": "0x%x" % u["addr"],
                "f32_add": "0x%x" % add_at,
                "rounds_back": "0x%x" % back[0],
                "registers": {"uplifted": ud, "sum": add_dst,
                              "rounded_into": back[1][0]},
            })
        elif wrong_src_control:
            resolved_with_a_wrong_target += 1
    seen, uniq = set(), []
    for c in chains:
        key = (c["uplift"], c["f32_add"], c["rounds_back"])
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    return {
        "window": {"from": "0x%x" % lo, "to": "0x%x" % hi,
                   "instructions": len(win)},
        "n_in_window": len(win),
        "n_cvt_f32_f16_e32": len(ups),
        "n_v_add_f32_e32": len(adds),
        "n_cvt_f16_f32_e32": len(downs),
        "n_chains": len(uniq),
        "chains": uniq,
        "n_resolved_with_a_wrong_target": resolved_with_a_wrong_target,
    }


def add16_in(insns, lo: int, hi: int):
    return [i for i in insns
            if opcode_of(i["text"]) == "v_add_f16_e32" and lo <= i["addr"] <= hi]


def add_f32_with_zero_src(insns, lo: int, hi: int):
    """`v_add_f32_e32 vX, 0, vX` -- the add-zero moves that seed the fold."""
    out = []
    for i in insns:
        if not (lo <= i["addr"] <= hi):
            continue
        if opcode_of(i["text"]) != "v_add_f32_e32":
            continue
        d, s, _ = _operands(i["text"])
        if len(s) >= 2 and s[0] in ("0", "0.0") and s[1] == d:
            out.append(i)
    return out


# ---------------------------------------------------------------------------
# exact binary-format arithmetic, computed here (no reference module involved)
#
# These are the INSTRUMENT for the standing regression: an independent
# implementation of RN32 and RN16 on exact Fractions, written as a
# significand-quantum division, and cross-checked below against the host's own
# struct conversions on the pairs where the host route is admissible.
# ---------------------------------------------------------------------------
def floor_log2_exact(x: Q) -> int:
    a = Q(x)
    e = a.numerator.bit_length() - a.denominator.bit_length()
    if a < Q(2) ** e:
        e -= 1
    while a >= Q(2) ** (e + 1):
        e += 1
    while a < Q(2) ** e:
        e -= 1
    return e


def _round_half_even_div(a: Q, quantum: Q) -> int:
    s = a / quantum
    f = s.numerator // s.denominator
    r = s - f
    if r > Q(1, 2) or (r == Q(1, 2) and (f & 1)):
        f += 1
    return f


def rn_exact(x: Q, p: int, e_min: int, e_max: int):
    """Round the exact rational x to an IEEE-style binary format.

    p significand bits, minimum normal exponent e_min, maximum exponent e_max.
    Returns an exact Fraction, or float('inf')/float('-inf') on overflow.
    """
    x = Q(x)
    if x == 0:
        return Q(0)
    neg = x < 0
    a = -x if neg else x
    e = floor_log2_exact(a)
    if e > e_max:
        return float("-inf") if neg else float("inf")
    quantum = Q(2) ** ((e_min - p + 1) if e < e_min else (e - p + 1))
    q = _round_half_even_div(a, quantum)
    val = Q(q) * quantum
    if val >= Q(2) ** (e_max + 1):
        return float("-inf") if neg else float("inf")
    if val == 0:
        return Q(0)
    return -val if neg else val


def rn32(x: Q):
    return rn_exact(x, 24, -126, 127)


def rn16(x: Q):
    return rn_exact(x, 11, -14, 15)


def host_rn32_or_none(x: Q):
    """A SECOND mechanism: exact -> float64 -> C's float64->float32.

    Valid only where the exact rational is itself a binary64 value, else the
    first conversion is not lossless and this route cannot speak.  Returns
    None there rather than a number.
    """
    x = Q(x)
    if x == 0:
        return Q(0)
    a = abs(x)
    e = floor_log2_exact(a)
    if e > 1023 or e < -1074:
        return None
    d = a.denominator
    if d != 1 and (d & (d - 1)):
        return None
    if a.numerator.bit_length() - (d.bit_length() - 1) > 53:
        return None
    v = float(x)
    b = struct.unpack("<f", struct.pack("<f", v))[0]
    if b != b or b in (float("inf"), float("-inf")):
        return None
    return Q(b)


def host_rn16_or_none(x: Q):
    """As above, for binary16.  Returns ('value', Fraction) or ('inf', sign)
    or None."""
    x = Q(x)
    a = abs(x)
    if a != 0:
        e = floor_log2_exact(a)
        if e > 1023 or e < -1074:
            return None
        d = a.denominator
        if d != 1 and (d & (d - 1)):
            return None
        if a.numerator.bit_length() - (d.bit_length() - 1) > 53:
            return None
    v = float(x)
    try:
        return ("value", Q(struct.unpack("<e", struct.pack("<e", v))[0]))
    except OverflowError:
        return ("inf", 1 if v > 0 else -1)


def f16_bits_to_float(b: int) -> float:
    return struct.unpack("<e", struct.pack("<H", b))[0]


def float_to_f16_bits(v: float) -> int:
    return struct.unpack("<H", struct.pack("<e", v))[0]


def is_binary16_value(x) -> bool:
    """Independent of the rounding routes: does this exact rational fit f16?"""
    x = Q(x)
    if x == 0:
        return True
    e = floor_log2_exact(abs(x))
    if e < -14 or e > 15:
        return False
    return (abs(x) * Q(2) ** (10 - e)).denominator == 1


def as_exact(v):
    """A recorded value (float / Fraction / inf string) -> a comparable tag."""
    if isinstance(v, tuple):
        return v
    if isinstance(v, float):
        if v != v:
            return ("nan",)
        if v == float("inf"):
            return ("inf", 1)
        if v == float("-inf"):
            return ("inf", -1)
    return Q(v)


# ---------------------------------------------------------------------------
# check recorder
# ---------------------------------------------------------------------------
class Report:
    def __init__(self, title: str):
        self.title = title
        self.rows = []
        print("=" * 74)
        print(title)
        print("=" * 74)

    def row(self, check, ok, n_compared, detail=None):
        if n_compared == 0:
            ok = False
            detail = dict(detail or {})
            detail["why_failed"] = "COMPARED_NOTHING"
        self.rows.append({"check": check, "ok": bool(ok),
                          "n_compared": int(n_compared),
                          "detail": detail})
        print("  %-4s n=%-8d %s" % ("OK" if ok else "FAIL", n_compared, check))
        if not ok:
            print("       %s" % repr(detail)[:500])
        return bool(ok)

    @property
    def n_ok(self):
        return sum(1 for r in self.rows if r["ok"])

    def verdict(self, good, bad):
        v = good if (self.rows and self.n_ok == len(self.rows)) else bad
        print("  -> %s (%d/%d checks ok)" % (v, self.n_ok, len(self.rows)))
        return v
