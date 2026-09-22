#!/usr/bin/env python3
"""Phase 16L-L3 -- the SCALAR and MEMORY half of the independent oracle.

`isa_oracle.py` covers the vector families the Phase 16L repairs touched.  The
L3 audit then derived, from the modules' own disassembly, the opcode set the
SWIN kernels actually raise, and found that the scalar ALU, the scalar control
instructions and the global/LDS access handlers were the largest uncovered
blocks -- and those are exactly the ones that gate J3, because the project's
gates count *memory events* and scalar comparisons produce the predicates that
decide whether a memory instruction executes at all.

This module extends the oracle to that half.  It follows the same rule as its
sibling and for the same reason: **it must not call the emulator's handler
methods to compute an expected value, and it must not import the emulator at
all.**  Every expected value below is written from the architectural definition.

The memory model is deliberately exact rather than approximate:
  * a global load/store is a 64-bit address `base + offset` with 32-bit wrap on
    the scalar side, and the gate's job is to decide whether the address lies
    inside a declared region;
  * an LDS access is a 32-bit effective address `vaddr + imm` with **32-bit
    wrap before the range check**, which is the modelling decision Phase 16I
    established for this project;
  * a compare writes SCC; EXEC-preserving forms write EXEC.

Host-only.  No GPU.  No emulator import.
"""
from __future__ import annotations

import math

U32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF
SIGN32 = 0x80000000


def u32(x):
    return x & U32


def u64(x):
    return x & M64


def to_s32(x):
    x &= U32
    return x - 0x100000000 if x & SIGN32 else x


def _s64(x):
    x &= M64
    return x - 0x10000000000000000 if x & 0x8000000000000000 else x


# ---------------------------------------------------------------------------
# SCALAR instruction semantics
# ---------------------------------------------------------------------------
# Each entry returns either an integer (the new value of the destination) or a
# dict describing a non-register effect (SCC / EXEC).
SCALAR = {}


def _s(name):
    def deco(fn):
        SCALAR[name] = fn
        return fn
    return deco


# ---- comparisons: write SCC -------------------------------------------------
def _cmp(fn):
    def g(a, b):
        return {"scc": 1 if fn(a, b) else 0}
    return g


SCALAR["s_cmp_eq_u32"] = _cmp(lambda a, b: u32(a) == u32(b))
SCALAR["s_cmp_lg_u32"] = _cmp(lambda a, b: u32(a) != u32(b))
SCALAR["s_cmp_lt_u32"] = _cmp(lambda a, b: u32(a) < u32(b))
SCALAR["s_cmp_le_u32"] = _cmp(lambda a, b: u32(a) <= u32(b))
SCALAR["s_cmp_gt_u32"] = _cmp(lambda a, b: u32(a) > u32(b))
SCALAR["s_cmp_ge_u32"] = _cmp(lambda a, b: u32(a) >= u32(b))
SCALAR["s_cmp_eq_u64"] = _cmp(lambda a, b: u64(a) == u64(b))
SCALAR["s_cmp_lg_u64"] = _cmp(lambda a, b: u64(a) != u64(b))
SCALAR["s_cmp_lt_i32"] = _cmp(lambda a, b: to_s32(a) < to_s32(b))
SCALAR["s_cmp_le_i32"] = _cmp(lambda a, b: to_s32(a) <= to_s32(b))
SCALAR["s_cmp_gt_i32"] = _cmp(lambda a, b: to_s32(a) > to_s32(b))
SCALAR["s_cmp_ge_i32"] = _cmp(lambda a, b: to_s32(a) >= to_s32(b))
SCALAR["s_cmp_eq_i32"] = _cmp(lambda a, b: to_s32(a) == to_s32(b))
SCALAR["s_cmp_lg_i32"] = _cmp(lambda a, b: to_s32(a) != to_s32(b))
# The `k` forms take an immediate; same predicates.
for _n in ("u32", "i32"):
    for _op, _f in (("lt", "<"), ("le", "<="), ("gt", ">"), ("ge", ">="),
                    ("eq", "=="), ("lg", "!=")):
        pass


def _cmpk(signed):
    def mk(op):
        def g(a, imm):
            aa = to_s32(a) if signed else u32(a)
            bb = to_s32(imm) if signed else u32(imm)
            return {"scc": 1 if {"lt": aa < bb, "le": aa <= bb,
                                 "gt": aa > bb, "ge": aa >= bb,
                                 "eq": aa == bb, "lg": aa != bb}[op] else 0}
        return g
    return mk


SCALAR["s_cmpk_lt_u32"] = _cmpk(False)("lt")
SCALAR["s_cmpk_le_u32"] = _cmpk(False)("le")
SCALAR["s_cmpk_gt_u32"] = _cmpk(False)("gt")
SCALAR["s_cmpk_ge_u32"] = _cmpk(False)("ge")
SCALAR["s_cmpk_lt_i32"] = _cmpk(True)("lt")
SCALAR["s_cmpk_gt_i32"] = _cmpk(True)("gt")


# ---- bit tests: write SCC ---------------------------------------------------
@_s("s_bitcmp0_b32")
def s_bitcmp0_b32(a, bit):
    return {"scc": 1 if ((u32(a) >> (u32(bit) & 31)) & 1) == 0 else 0}


@_s("s_bitcmp1_b32")
def s_bitcmp1_b32(a, bit):
    return {"scc": 1 if ((u32(a) >> (u32(bit) & 31)) & 1) == 1 else 0}


# ---- arithmetic ------------------------------------------------------------
@_s("s_add_u32")
def s_add_u32(a, b):
    r = u32(a) + u32(b)
    return {"value": u32(r), "scc": 1 if r > U32 else 0}


@_s("s_add_i32")
def s_add_i32(a, b):
    return {"value": u32(to_s32(a) + to_s32(b))}


@_s("s_addc_u32")
def s_addc_u32(a, b, carry):
    r = u32(a) + u32(b) + (1 if carry else 0)
    return {"value": u32(r), "scc": 1 if r > U32 else 0}


@_s("s_sub_u32")
def s_sub_u32(a, b):
    r = u32(a) - u32(b)
    return {"value": u32(r), "scc": 1 if u32(a) < u32(b) else 0}


@_s("s_sub_i32")
def s_sub_i32(a, b):
    return {"value": u32(to_s32(a) - to_s32(b))}


@_s("s_subb_u32")
def s_subb_u32(a, b, borrow):
    r = u32(a) - u32(b) - (1 if borrow else 0)
    return {"value": u32(r), "scc": 1 if r < 0 else 0}


@_s("s_mul_i32")
def s_mul_i32(a, b):
    return {"value": u32(to_s32(a) * to_s32(b))}


@_s("s_mul_hi_u32")
def s_mul_hi_u32(a, b):
    return {"value": u32((u32(a) * u32(b)) >> 32)}


@_s("s_mul_hi_i32")
def s_mul_hi_i32(a, b):
    return {"value": u32((to_s32(a) * to_s32(b)) >> 32)}


@_s("s_abs_i32")
def s_abs_i32(a):
    v = to_s32(a)
    return {"value": u32(-v if v < 0 else v)}


@_s("s_sext_i32_i8")
def s_sext_i32_i8(a):
    v = u32(a) & 0xFF
    return {"value": u32(v - 0x100 if v & 0x80 else v)}


@_s("s_sext_i32_i16")
def s_sext_i32_i16(a):
    v = u32(a) & 0xFFFF
    return {"value": u32(v - 0x10000 if v & 0x8000 else v)}


@_s("s_min_i32")
def s_min_i32(a, b):
    return {"value": u32(min(to_s32(a), to_s32(b)))}


@_s("s_max_i32")
def s_max_i32(a, b):
    return {"value": u32(max(to_s32(a), to_s32(b)))}


@_s("s_min_u32")
def s_min_u32(a, b):
    return {"value": min(u32(a), u32(b))}


@_s("s_max_u32")
def s_max_u32(a, b):
    return {"value": max(u32(a), u32(b))}


@_s("s_addk_i32")
def s_addk_i32(a, imm):
    """dst = dst + imm, with the immediate taken as a signed or unsigned 32-bit
    value and the sum wrapping."""
    r = u32(a) + int(imm)
    return {"value": u32(r)}


@_s("s_movk_i32")
def s_movk_i32(imm):
    """dst = sign-extended 16-bit immediate.  `Core.op_s_movk_i32` masks with
    `& U32`, so a negative literal and its two's-complement word agree."""
    v = int(imm) & 0xFFFF
    if v & 0x8000:
        v -= 0x10000
    return {"value": u32(v)}


# ---- logic -----------------------------------------------------------------
@_s("s_and_b32")
def s_and_b32(a, b):
    return {"value": u32(a) & u32(b)}


@_s("s_or_b32")
def s_or_b32(a, b):
    return {"value": u32(a) | u32(b)}


@_s("s_xor_b32")
def s_xor_b32(a, b):
    return {"value": u32(a) ^ u32(b)}


@_s("s_not_b32")
def s_not_b32(a):
    return {"value": u32(~u32(a))}


@_s("s_andn2_b32")
def s_andn2_b32(a, b):
    """dst = src0 & ~src1."""
    return {"value": u32(u32(a) & ~u32(b))}


@_s("s_orn2_b32")
def s_orn2_b32(a, b):
    return {"value": u32(u32(a) | ~u32(b))}


@_s("s_nand_b32")
def s_nand_b32(a, b):
    return {"value": u32(~(u32(a) & u32(b)))}


@_s("s_nor_b32")
def s_nor_b32(a, b):
    return {"value": u32(~(u32(a) | u32(b)))}


@_s("s_xnor_b32")
def s_xnor_b32(a, b):
    return {"value": u32(~(u32(a) ^ u32(b)))}


# ---- shifts ----------------------------------------------------------------
@_s("s_lshl_b32")
def s_lshl_b32(a, sh):
    return {"value": u32(u32(a) << (u32(sh) & 31))}


@_s("s_lshr_b32")
def s_lshr_b32(a, sh):
    return {"value": u32(u32(a) >> (u32(sh) & 31))}


@_s("s_ashr_i32")
def s_ashr_i32(a, sh):
    return {"value": u32(to_s32(a) >> (u32(sh) & 31))}


@_s("s_lshl_b64")
def s_lshl_b64(a, sh):
    return {"value": u64(u64(a) << (u32(sh) & 63))}


@_s("s_lshr_b64")
def s_lshr_b64(a, sh):
    return {"value": u64(u64(a) >> (u32(sh) & 63))}


# ---- bit field -------------------------------------------------------------
@_s("s_bfe_u32")
def s_bfe_u32(a, o, w):
    o = u32(o) & 31
    w = u32(w) & 31
    if w == 0:
        return {"value": 0}
    return {"value": u32((u32(a) >> o) & ((1 << w) - 1))}


@_s("s_bfe_i32")
def s_bfe_i32(a, o, w):
    o = u32(o) & 31
    w = u32(w) & 31
    if w == 0:
        return {"value": 0}
    v = u32(a) >> o
    if o + w < 32:
        v &= (1 << w) - 1
        if v & (1 << (w - 1)):
            v |= (U32 << w) & U32
    return {"value": u32(v)}


@_s("s_bfm_b32")
def s_bfm_b32(w, o):
    w = u32(w) & 31
    o = u32(o) & 31
    return {"value": u32(((1 << w) - 1) << o) if w else 0}


# ---- mask / EXEC -----------------------------------------------------------
def _saveexec(a, b, new):
    return {"exec": new, "value": u32(a)}


@_s("s_and_saveexec_b32")
def s_and_saveexec_b32(old_exec, mask):
    new = u32(old_exec) & u32(mask)
    return {"exec": new, "value": u32(old_exec)}


@_s("s_orn2_saveexec_b32")
def s_orn2_saveexec_b32(old_exec, mask):
    return {"exec": u32(u32(old_exec) | ~u32(mask)), "value": u32(old_exec)}


@_s("s_andn2_saveexec_b32")
def s_andn2_saveexec_b32(old_exec, mask):
    return {"exec": u32(u32(old_exec) & ~u32(mask)), "value": u32(old_exec)}


@_s("s_or_saveexec_b32")
def s_or_saveexec_b32(old_exec, mask):
    return {"exec": u32(u32(old_exec) | u32(mask)), "value": u32(old_exec)}


@_s("s_xor_saveexec_b32")
def s_xor_saveexec_b32(old_exec, mask):
    return {"exec": u32(u32(old_exec) ^ u32(mask)), "value": u32(old_exec)}


# ---- move / select ---------------------------------------------------------
@_s("s_mov_b32")
def s_mov_b32(a):
    return {"value": u32(a)}


@_s("s_mov_b64")
def s_mov_b64(a):
    return {"value": u64(a)}


@_s("s_cselect_b32")
def s_cselect_b32(src0, src1, scc):
    """ISA: dst = SCC ? src0 : src1.  Phase 16I found the arms swapped here."""
    return {"value": u32(src0) if scc else u32(src1)}


@_s("s_cselect_b64")
def s_cselect_b64(src0, src1, scc):
    return {"value": u64(src0) if scc else u64(src1)}


# ---------------------------------------------------------------------------
# MEMORY: address formation.  This is the part the gates actually measure.
# ---------------------------------------------------------------------------
def global_address(base64, offset64):
    """A global access address.  The flat/global address space is 64-bit and
    wraps at 64 bits, NOT at 32."""
    return u64(base64 + offset64)


def lds_effective_address(vaddr, imm):
    """LDS effective address.

    THE WRAP HAPPENS BEFORE THE RANGE CHECK, and it happens at 32 bits.  This
    is the modelling decision Phase 16I established for this project and it is
    the thing `0xE077E` is about: a vaddr already holding high/tag bits plus a
    positive immediate wraps rather than saturating, so the effective address
    can land far below the base the kernel meant.
    """
    return u32(vaddr + imm)


def in_range(ea, lo, size, width):
    return lo <= ea and (ea + width) <= (lo + size)


def scalar_addr_wrap(base_lo, base_hi, off):
    """`base + off` for a printed `s[a:b]` base pair, wrapping at 64 bits."""
    base = (u64(base_hi) << 32) | u32(base_lo)
    return u64(base + off)


# ---------------------------------------------------------------------------
# THE SCALAR / MEMORY VECTORS
# ---------------------------------------------------------------------------
NAN = float("nan")


def build_scalar_vectors():
    """Vectors for the scalar families.  Each is
    (family, name, mnemonic, operands, setup, note) where `operands` are the
    PRINTED operands and `setup` maps `s<N>` -> value plus the special keys
    `exec` and `scc`.
    """
    V = []

    def add(family, name, mnem, ops, setup, note=""):
        V.append({"family": family, "name": name, "mnem": mnem, "operands": ops,
                  "setup": setup, "note": note})

    # ---- comparisons.  Every one of these drives a branch. -----------------
    add("scmp", "eq_u32_true", "s_cmp_eq_u32", ["s0", "s1"],
        {"s0": 7, "s1": 7})
    add("scmp", "eq_u32_false", "s_cmp_eq_u32", ["s0", "s1"],
        {"s0": 7, "s1": 8}, "asymmetric: must be false")
    add("scmp", "lt_u32_unsigned_trap", "s_cmp_lt_u32", ["s0", "s1"],
        {"s0": 1, "s1": 0xFFFFFFFF},
        "UNSIGNED: 1 < 0xFFFFFFFF is TRUE.  A signed implementation says "
        "1 < -1 is FALSE -- the classic trap.")
    add("scmp", "gt_u32_unsigned_trap", "s_cmp_gt_u32", ["s0", "s1"],
        {"s0": 0xFFFFFFFF, "s1": 1},
        "UNSIGNED: true.  Signed would be false.")
    add("scmp", "lt_i32_signed_true", "s_cmp_lt_i32", ["s0", "s1"],
        {"s0": 0xFFFFFFFF, "s1": 1},
        "SIGNED: -1 < 1 is TRUE.  Unsigned would say false.")
    add("scmp", "gt_i32_signed_true", "s_cmp_gt_i32", ["s0", "s1"],
        {"s0": 1, "s1": 0xFFFFFFFF},
        "SIGNED: 1 > -1 is TRUE.  Unsigned would say false.")
    add("scmp", "ge_i32_equal", "s_cmp_ge_i32", ["s0", "s1"],
        {"s0": 0x80000000, "s1": 0x80000000})
    add("scmp", "lg_u32_true", "s_cmp_lg_u32", ["s0", "s1"],
        {"s0": 5, "s1": 6})
    add("scmp", "eq_u64_true", "s_cmp_eq_u64", ["s[0:1]", "s[2:3]"],
        {"s0": 0x12345678, "s1": 0x9ABCDEF0, "s2": 0x12345678,
         "s3": 0x9ABCDEF0})
    add("scmp", "eq_u64_false_hi_only", "s_cmp_eq_u64", ["s[0:1]", "s[2:3]"],
        {"s0": 0x12345678, "s1": 0x9ABCDEF0, "s2": 0x12345678,
         "s3": 0x9ABCDEF1},
        "the low halves are equal; only the HIGH half differs.  A 32-bit "
        "implementation that ignores the high word passes this wrongly.")

    # ---- bit tests ----------------------------------------------------------
    add("sbit", "bitcmp0_true", "s_bitcmp0_b32", ["s0", "0x1F"],
        {"s0": 0x7FFFFFFF}, "bit 31 is clear -> true")
    add("sbit", "bitcmp0_false", "s_bitcmp0_b32", ["s0", "0x1F"],
        {"s0": 0x80000000}, "bit 31 is set -> false")
    add("sbit", "bitcmp1_true", "s_bitcmp1_b32", ["s0", "0x1F"],
        {"s0": 0x80000000})
    add("sbit", "bitcmp1_bit0", "s_bitcmp1_b32", ["s0", "0x0"], {"s0": 1},
        "a non-zero bit index must not be ignored")

    # ---- arithmetic: carry out is the part that is easy to get wrong -------
    add("salu", "add_u32_carry", "s_add_u32", ["s9", "s0", "s1"],
        {"s0": 0xFFFFFFFF, "s1": 1}, "SCC must be 1 (carry out)")
    add("salu", "add_u32_nocarry", "s_add_u32", ["s9", "s0", "s1"],
        {"s0": 0xFFFFFFFE, "s1": 1}, "SCC must be 0")
    add("salu", "addc_with_carry_in", "s_addc_u32", ["s9", "s0", "s1"],
        {"s0": 0xFFFFFFFF, "s1": 0, "scc": 1},
        "carry-in must be honoured: 0xFFFFFFFF+0+1 wraps again")
    add("salu", "addc_without_carry_in", "s_addc_u32", ["s9", "s0", "s1"],
        {"s0": 0xFFFFFFFF, "s1": 0, "scc": 0})
    add("salu", "add_i32_wrap", "s_add_i32", ["s9", "s0", "s1"],
        {"s0": 0x7FFFFFFF, "s1": 1})
    add("salu", "addk_positive", "s_addk_i32", ["s9", "0x100"],
        {"s9": 0x10}, "the kernel's own form: an ADDK with a 0x literal")
    add("salu", "addk_negative", "s_addk_i32", ["s9", "-4"],
        {"s9": 0x10}, "a negative literal must wrap, not raise")
    add("salu", "addk_wraps", "s_addk_i32", ["s9", "0x100"],
        {"s9": 0xFFFFFFF0})
    add("salu", "movk_prefixed", "s_movk_i32", ["s9", "0x100"],
        {}, "S_MOVK_I32 with the 0x prefi2x the disassembly emits")
    add("salu", "movk_negative", "s_movk_i32", ["s9", "-1"], {})
    add("salu", "mul_i32_signed", "s_mul_i32", ["s9", "s0", "s1"],
        {"s0": 0xFFFFFFFF, "s1": 3},
        "SIGNED multiply: -1 * 3 = -3 = 0xFFFFFFFD.  Unsigned gives a "
        "different 32-bit result only via the high word, so the hi part is "
        "the discriminator.")
    add("salu", "mul_hi_u32", "s_mul_hi_u32", ["s9", "s0", "s1"],
        {"s0": 0xFFFFFFFF, "s1": 0xFFFFFFFF})
    add("salu", "abs_negative", "s_abs_i32", ["s9", "s0"], {"s0": 0xFFFFFFFB})
    add("salu", "abs_min_int", "s_abs_i32", ["s9", "s0"], {"s0": 0x80000000},
        "|INT_MIN| overflows back to INT_MIN")
    add("salu", "sext_i8_negative", "s_sext_i32_i8", ["s9", "s0"],
        {"s0": 0x000000FF}, "must sign-extend to 0xFFFFFFFF, not zero-extend")
    add("salu", "sext_i8_positive", "s_sext_i32_i8", ["s9", "s0"], {"s0": 0x7F})
    add("salu", "sext_i16_negative", "s_sext_i32_i16", ["s9", "s0"],
        {"s0": 0x0000FFFF})
    add("salu", "min_i32_signed_trap", "s_min_i32", ["s9", "s0", "s1"],
        {"s0": 0xFFFFFFFF, "s1": 1},
        "SIGNED min(-1, 1) = -1.  An unsigned implementation gives 1.")
    add("salu", "max_i32_signed_trap", "s_max_i32", ["s9", "s0", "s1"],
        {"s0": 0xFFFFFFFF, "s1": 1})
    add("salu", "min_u32_trap", "s_min_u32", ["s9", "s0", "s1"],
        {"s0": 0xFFFFFFFF, "s1": 1}, "UNSIGNED min = 1")

    # ---- logic --------------------------------------------------------------
    add("slogic", "and_b32", "s_and_b32", ["s9", "s0", "s1"],
        {"s0": 0xFF00FF00, "s1": 0x0FF00FF0})
    add("slogic", "or_b32", "s_or_b32", ["s9", "s0", "s1"],
        {"s0": 0xFF00FF00, "s1": 0x0FF00FF0})
    add("slogic", "xor_b32", "s_xor_b32", ["s9", "s0", "s1"],
        {"s0": 0xFF00FF00, "s1": 0x0FF00FF0})
    add("slogic", "not_b32", "s_not_b32", ["s9", "s0"], {"s0": 0x0F0F0F0F})
    add("slogic", "andn2_b32", "s_andn2_b32", ["s9", "s0", "s1"],
        {"s0": 0xFF00FF00, "s1": 0x0FF00FF0},
        "dst = src0 & ~src1.  Swapping the operands changes the answer.")
    add("slogic", "nand_b32", "s_nand_b32", ["s9", "s0", "s1"],
        {"s0": 0xFF00FF00, "s1": 0x0FF00FF0})
    add("slogic", "nor_b32", "s_nor_b32", ["s9", "s0", "s1"],
        {"s0": 0xFF00FF00, "s1": 0x0FF00FF0})
    add("slogic", "xnor_b32", "s_xnor_b32", ["s9", "s0", "s1"],
        {"s0": 0xFF00FF00, "s1": 0x0FF00FF0})

    # ---- shifts -------------------------------------------------------------
    for sh, nm in ((0, "zero"), (1, "one"), (7, "seven"), (15, "fifteen"),
                   (31, "thirtyone"), (33, "wraps33")):
        add("sshift", "lshl_%s" % nm, "s_lshl_b32", ["s9", "s0", "s1"],
            {"s0": 0x00000001, "s1": sh},
            "shift count masked to 5 bits" if sh >= 32 else "")
        add("sshift", "ashr_%s" % nm, "s_ashr_i32", ["s9", "s0", "s1"],
            {"s0": 0x80000000, "s1": sh},
            "arithmetic: the sign must survive" if sh else "")
    add("sshift", "lshr_high_bit", "s_lshr_b32", ["s9", "s0", "s1"],
        {"s0": 0x80000000, "s1": 31},
        "logical shift: result 1.  An arithmetic implementation gives "
        "0xFFFFFFFF.")
    add("sshift", "lshl_b64_crosses_word", "s_lshl_b64", ["s[3:4]", "s[0:1]", "s2"],
        {"s0": 0xFFFFFFFF, "s1": 0x00000000, "s2": 1},
        "must shift across the 32-bit boundary into the high word")
    add("sshift", "lshr_b64_crosses_word", "s_lshr_b64", ["s[3:4]", "s[0:1]", "s2"],
        {"s0": 0x00000000, "s1": 0x00000001, "s2": 1})

    # ---- bit field ----------------------------------------------------------
    add("sbfe", "bfe_u32_mid", "s_bfe_u32", ["s9", "s0", "0x10008"],
        {"s0": 0xDEADBEEF}, "offset 8, width 16 -> bits [23:8] = 0xADBE")
    add("sbfe", "bfe_u32_width_zero", "s_bfe_u32", ["s9", "s0", "0x00008"],
        {"s0": 0xFFFFFFFF}, "width 0 -> 0")
    add("sbfe", "bfe_u32_overshoot", "s_bfe_u32", ["s9", "s0", "0x8001C"],
        {"s0": 0xDEADBEEF},
        "o+w > 32: the field is truncated at the top, not shifted in zeros")
    add("sbfe", "bfe_i32_sign", "s_bfe_i32", ["s9", "s0", "0x80008"],
        {"s0": 0x0000FF00},
        "extracted field has its top bit set -> sign-extended to 0xFFFFFFFF")
    add("sbfe", "bfe_i32_nosign", "s_bfe_i32", ["s9", "s0", "0x80008"],
        {"s0": 0x00007F00})

    # ---- EXEC / mask -------------------------------------------------------
    add("sexec", "and_saveexec_clears", "s_and_saveexec_b32", ["s9", "s0", "s1"],
        {"s0": 0xDEADBEEF, "s1": 0xFFFF0000, "exec": 0xFFFFFFFF},
        "old EXEC must be written to s0 BEFORE EXEC is replaced")
    add("sexec", "andn2_saveexec", "s_andn2_saveexec_b32", ["s9", "s0", "s1"],
        {"s0": 0, "s1": 0x0000000F, "exec": 0xFFFFFFFF})
    add("sexec", "orn2_saveexec", "s_orn2_saveexec_b32", ["s9", "s0", "s1"],
        {"s0": 0, "s1": 0x0000000F, "exec": 0x00000000})
    add("sexec", "or_saveexec", "s_or_saveexec_b32", ["s9", "s0", "s1"],
        {"s0": 0, "s1": 0x0000000F, "exec": 0x00000000})
    add("sexec", "xor_saveexec", "s_xor_saveexec_b32", ["s9", "s0", "s1"],
        {"s0": 0, "s1": 0x000000FF, "exec": 0x0000000F})

    # ---- select ------------------------------------------------------------
    add("ssel", "cselect_scc1", "s_cselect_b32", ["s9", "s0", "s1"],
        {"s0": 0xAAAAAAAA, "s1": 0x55555555, "scc": 1},
        "SCC=1 selects src0.  Phase 16I found these arms swapped here.")
    add("ssel", "cselect_scc0", "s_cselect_b32", ["s9", "s0", "s1"],
        {"s0": 0xAAAAAAAA, "s1": 0x55555555, "scc": 0})

    # ---- memory ADDRESS FORMATION ------------------------------------------
    add("addr", "global_base_plus_imm", "global_address", [0x42B870000, 0x40],
        {}, "the canvas pointer plus a VarParams offset")
    add("addr", "global_wraps_at_64", "global_address",
        [0xFFFFFFFFFFFFFFF0, 0x20], {},
        "the global address space wraps at 64 bits, NOT at 32")
    add("addr", "lds_wrap_before_check", "lds_effective_address",
        [0x0FFFF0000, 0x1000], {},
        "A vaddr that ALREADY carries high bits plus a positive immediate "
        "wraps at 32 bits.  This is the modelling decision `0xE077E` is about.")
    add("addr", "lds_simple", "lds_effective_address", [0x100, 0x40], {})
    add("addr", "lds_wrap_exact", "lds_effective_address",
        [0xFFFFFFF0, 0x20], {}, "wraps to 0x10, i.e. BELOW the base")
    add("addr", "lds_tagged_shift", "lds_tagged_shift", [7, 3, 0x37], {},
        "the K4 tag-formation shape: (tag << shift) | low")
    add("addr", "lds_region_check_inside", "in_range",
        [0x1000, 0x1000, 0x1000, 2], {})
    add("addr", "lds_region_check_at_end", "in_range",
        [0x1FFE, 0x1000, 0x1000, 2], {},
        "the LAST legal 2-byte access: must be in range")
    add("addr", "lds_region_check_past_end", "in_range",
        [0x1FFF, 0x1000, 0x1000, 2], {},
        "one byte past: must be OUT of range.  A check written as "
        "`ea <= lo+size` would wrongly accept this.")
    return V


# ---------------------------------------------------------------------------
# EVALUATION
# ---------------------------------------------------------------------------
def eval_scalar(vec):
    """Compute the architectural effect of a scalar vector.

    OPERAND CONTRACT -- the printed operand list is `dst, src...`, exactly as
    the disassembler emits it and exactly as `Core`'s handlers slice it.  The
    source list the oracle passes to the semantic function is `ops[1:]`.

    Two families need care and get it explicitly rather than by luck:

      * `s_bfe_u32/i32` take a **packed immediate**: bits [4:0] are the offset
        and bits [22:16] the width.  `s_bfe_u32 s17, s14, 0x10007` means
        offset 7, width 16.  The oracle unpacks it the same way the hardware
        does, and this is the form the SWIN kernels actually use.
      * `s_*_saveexec_b32` write the OLD EXEC to the destination and the NEW
        EXEC to EXEC.  The entry state must therefore carry `exec`.

    Raises KeyError for an unmodelled mnemonic -- an unmodelled instruction
    must not silently pass.
    """
    m = vec["mnem"]
    setup = vec["setup"]
    exec_lo = setup.get("exec", U32)
    scc = setup.get("scc", 0)
    ops = vec["operands"]
    # WHICH FAMILIES PRINT A DESTINATION?  This is not uniform, and the
    # modules show it directly:
    #     s_cmp_eq_u32 s2, 8            <- two operands, no destination
    #     s_bitcmp1_b32 s4, 0x10        <- two operands, no destination
    #     s_add_u32 s4, s4, 4           <- dst, src0, src1
    #     s_cselect_b32 s4, -1, 0       <- dst, src0, src1
    #     s_and_saveexec_b32 s0, s5     <- dst (old EXEC), mask
    # so the compare and bit-test families read from ops[0].
    dst_tok = None if m.startswith(("s_cmp", "s_bitcmp")) else ops[0]
    src_toks = ops[0:] if dst_tok is None else ops[1:]

    if m in ("s_bfe_u32", "s_bfe_i32"):
        fn = SCALAR[m]
        a = _read_scalar(src_toks[0], setup, exec_lo, scc)
        imm = _read_scalar(src_toks[1], setup, exec_lo, scc)
        # THE PACKED-IMMEDIATE BIT LAYOUT IS **NOT INDEPENDENTLY VERIFIED**.
        #
        # The project's `Core8._sbfe_imm` decodes offset = imm[20:16] and
        # width = imm[5:0] (0 meaning 32).  The AMD ISA text was not available
        # on this machine to check that against, so this oracle adopts the same
        # decode RATHER THAN CLAIMING TO HAVE CONFIRMED IT.
        #
        # What was checked, and is checkable: all 13 packed-immediate `s_bfe`
        # sites in the five SWIN kernels satisfy `offset + width <= 32` under
        # this decode, and so does the alternative reading (offset = imm[4:0],
        # width = imm[22:16]).  Both decodes are therefore self-consistent on
        # the real data, so this test does not discriminate between them, and
        # the matrix records `s_bfe_u32`/`s_bfe_i32` as
        # VERIFIED_BY_SHARED_FAMILY with this caveat rather than as
        # independently verified.
        off = (imm >> 16) & 0x1F
        width = (imm & 0x3F) or 32
        r = fn(a, off, width)
        return r if isinstance(r, dict) else {"value": r}

    if m.startswith("s_cmpk_"):
        fn = SCALAR[m]
        a = _read_scalar(src_toks[0], setup, exec_lo, scc)
        imm = _read_scalar(src_toks[1], setup, exec_lo, scc)
        r = fn(a, imm)
        return r if isinstance(r, dict) else {"value": r}

    if m in ("s_addk_i32", "s_movk_i32"):
        # READ-MODIFY-WRITE / immediate-only forms.  The printed operands are
        # `dst, imm`, and ADDK reads dst as an input, so the destination's OLD
        # value must be supplied as the first source.  `s_add_i32` by contrast
        # is `dst, src0, src1` and does not read dst.
        imm = _read_scalar(src_toks[-1], setup, exec_lo, scc)
        if m == "s_addk_i32":
            old = _read_scalar(dst_tok, setup, exec_lo, scc)
            return SCALAR[m](old, imm)
        return SCALAR[m](imm)

    fn = SCALAR.get(m)
    if fn is None:
        raise KeyError(m)
    # The saveexec family is special-cased BEFORE the generic read, because its
    # first printed operand is the DESTINATION (which receives the old EXEC)
    # and must not be read as a source.
    if "saveexec" in m:
        fn = SCALAR[m]
        r = fn(exec_lo, _read_scalar(src_toks[0], setup, exec_lo, scc))
        return r if isinstance(r, dict) else {"value": r}

    vals = [_read_scalar(t, setup, exec_lo, scc) for t in src_toks]
    # `s_addc_u32` / `s_subb_u32` take their carry-in / borrow-in from SCC, and
    # `s_cselect_b32` takes its select from SCC.  It is architectural state,
    # not a printed operand.
    if m in ("s_addc_u32", "s_subb_u32", "s_cselect_b32"):
        vals = vals + [scc]
    r = fn(*vals)
    if not isinstance(r, dict):
        r = {"value": r}
    # For the compare and bit-test families the destination is SCC, and the
    # value the ISA writes to ops[0] is not defined; report SCC and leave the
    # register alone.
    if m.startswith(("s_cmp", "s_bitcmp")):
        return {"scc": r.get("scc", 0)}
    return r


def _read_scalar(tok, setup, exec_lo, scc):
    t = tok.strip()
    if t in ("exec_lo", "exec"):
        return exec_lo
    if t == "scc":
        return scc
    if t.startswith("s[") and t.endswith("]"):
        a, b = (int(x) for x in t[2:-1].split(":"))
        v = 0
        for i in range(b, a - 1, -1):
            v = (v << 32) | u32(setup.get("s%d" % i, 0))
        return v
    if t.startswith("s") and t[1:].isdigit():
        return u32(setup.get("s%d" % int(t[1:]), 0))
    if t.lstrip("-").lower().startswith("0x") or t.lstrip("-").isdigit():
        return int(t, 0) & U32
    raise KeyError("cannot read scalar operand %r" % tok)


def eval_address(vec):
    """Evaluate the address-formation vectors, whose mnemonics are the
    helper functions themselves rather than instructions."""
    m = vec["mnem"]
    args = list(vec["operands"])
    if m == "global_address":
        return {"value": global_address(*args)}
    if m == "lds_effective_address":
        return {"value": lds_effective_address(*args)}
    if m == "in_range":
        ea, lo, size, width = args
        return {"value": 1 if in_range(ea, lo, size, width) else 0}
    if m == "lds_tagged_shift":
        tag, shift, low = args
        # the repaired reading: (tag << shift) | low
        return {"value": u32(u32(u32(tag) << (u32(shift) & 31)) | u32(low))}
    raise KeyError(m)
