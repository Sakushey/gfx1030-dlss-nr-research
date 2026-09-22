#!/usr/bin/env python3
"""Phase 16L-L2 -- an INDEPENDENT semantic oracle for the gfx1030 ISA subset
the SWIN kernels use.

WHAT THIS FILE IS FOR

Phase 16K found that the project's host emulator -- the instrument that produced
every dynamic gate number -- contains ISA-semantic defects on the critical path
of the very kernel the physical J3 test targets.  The emulator therefore may not
certify its own repair.  This module is the second opinion.

THE RULE THIS FILE ENFORCES ON ITSELF

    It must not call the emulator's handler methods to compute an expected value.

It does not import the emulator at all.  Every expected value here is computed
from the architectural definition of the instruction, written out longhand, with
integer arithmetic (and IEEE-754 `struct`/`math` where a float is genuinely
involved).  `verify_against_oracle.py` then runs the emulator and the oracle on
the same (instruction, entry state) pairs and compares -- which is a comparison,
not a shared implementation.

OPERAND CONVENTIONS (AMD GCN/RDNA, LLVM AMDGPU disassembly)

  VOP2        dst, src0, src1
  VOP1        dst, src0
  VOP3        dst, src0, src1, src2        (dst printed first, always)
  VOP3P       dst, src0, src1, src2
  VOPC        dst, src0, src1              (dst is vcc_lo / vcc_hi / sN)
  VOPCX       src0, src1                   (NO destination: the result is EXEC)

The VOPCX convention is the crux of defect 1: an assembler for gfx1030 prints
`v_cmpx_neq_f32_e32 0, v5` as **two** operands, and the `0` is src0 -- the
hardware's boolean-false literal, which the scalar field encodes as SGPR 0
(`bool_zero`) -- not a destination slot.  The Candidate F module contains that
exact line at 0x000B5124.  The emulator's `len(ops) < 3` fallback read `ops[1]`
for BOTH operands, so every short `v_cmpx_*` was evaluated as `fn(src0, src0)`.

SCALAR-OPERAND DECODING IN _e32 FORMS

When a VOP2/VOP1/VOPC e32 instruction takes a scalar operand whose value is
0-64 or 128-192, the field encodes an SGPR rather than a VGPR.  The canonical
translation (and the one the project's disassembly uses) is

    nop_field 0..63     -> s<nop_field>
    nop_field 64..127   -> v<nop_field - 64>
    nop_field 128..192  -> s<nop_field - 128>
    nop_field 193..255  -> v<nop_field - 193>   (not exercised here)

This module implements that decoding so a test can deliberately place a value in
an SGPR and require the emulator to read it from the SGPR -- a case that fails
loudly if register-class decoding is wrong.

Host-only.  No GPU.  No emulator import.
"""
from __future__ import annotations

import math
import struct

U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF
SIGN32 = 0x80000000


# ---------------------------------------------------------------------------
# scalar helpers -- written out rather than imported
# ---------------------------------------------------------------------------
def u32(x):
    return x & U32


def to_s32(x):
    x = x & U32
    return x - 0x100000000 if x & SIGN32 else x


def to_s16(x):
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def to_s8(x):
    x &= 0xFF
    return x - 0x100 if x & 0x80 else x


def f32_bits(v):
    """Emulate the hardware's f32 rounding of a Python double."""
    return struct.unpack("<I", struct.pack("<f", v))[0]


def bits_f32(b):
    return struct.unpack("<f", struct.pack("<I", b & U32))[0]


def f16_bits_to_f32(b):
    """IEEE binary16 -> Python float, exact (every f16 is an f32)."""
    b &= 0xFFFF
    s = (b >> 15) & 1
    e = (b >> 10) & 0x1F
    m = b & 0x3FF
    if e == 0:
        v = m * 2.0 ** -24
    elif e == 31:
        if m == 0:
            v = math.inf
        else:
            return math.nan
    else:
        v = (1.0 + m / 1024.0) * 2.0 ** (e - 15)
    return -v if s else v


def f32_to_f16_bits(v):
    """f32 value -> nearest f16 bit pattern (round-to-nearest-even on ties).

    Written from the format definition; used only where a test actually needs
    an f16 result.
    """
    b = f32_bits(v)
    s = (b >> 31) & 1
    e = (b >> 23) & 0xFF
    m = b & 0x7FFFFF
    if e == 0xFF:
        return (s << 15) | 0x7C00 | (0x200 if m else 0)
    if e == 0 and m == 0:
        return s << 15
    # unbiased exponent of the f32
    exp = (e if e else 1) - 127
    if exp > 15:
        return (s << 15) | 0x7C00                      # overflow -> inf
    if exp < -25:
        return s << 15                                 # underflow -> zero
    # normalise the significand to [1,2)
    sig = (m | 0x800000) << 1  # 25 bits, leading 1 in bit 24
    if e == 0:
        while not (sig & (1 << 24)):
            sig <<= 1
            exp -= 1
    shift = 24 - 10  # keep 11 significand bits for f16 (1 implicit + 10)
    if shift > 0:
        low = sig & ((1 << shift) - 1)
        half = 1 << (shift - 1)
        sig >>= shift
        if low > half or (low == half and (sig & 1)):
            sig += 1
            if sig & (1 << 11):
                sig >>= 1
                exp += 1
    if exp < -14:
        return s << 15
    if exp > 15:
        return (s << 15) | 0x7C00
    if exp == -14 and not (sig & (1 << 10)):
        pass
    if exp == -14 and (sig >> 10) == 1:
        return (s << 15) | ((sig & 0x3FF))
    return (s << 15) | ((exp + 15) << 10) | (sig & 0x3FF)


def s32_wrap(v):
    v &= U32
    return v - 0x100000000 if v & SIGN32 else v


def u64(x):
    return x & U64


# ---------------------------------------------------------------------------
# operand decoding
# ---------------------------------------------------------------------------
class OperandError(Exception):
    pass


def decode_operand(tok, *, regs, sgprs, lane, fp=False, fp16=False):
    """Decode ONE printed operand token to the value the hardware would read.

    `fp=True` decodes VGPR/SGPR contents as f32 VALUES (this is the whole point
    of defect 2).  `fp16=True` decodes the low 16 bits as an f16 and returns the
    f32 value -- the comparison ops operate on the decoded value.
    """
    tok = tok.strip()
    if tok.startswith("|") and tok.endswith("|"):
        return abs(decode_operand(tok[1:-1], regs=regs, sgprs=sgprs, lane=lane,
                                  fp=fp, fp16=fp16))
    if tok.startswith("-v"):
        return (-decode_operand(tok[1:], regs=regs, sgprs=sgprs, lane=lane,
                                fp=fp, fp16=fp16)) & U32
    if tok.startswith("v") and tok[1:].isdigit():
        raw = regs[lane][int(tok[1:])] & U32
    elif tok.startswith("s") and tok[1:].isdigit():
        raw = sgprs[int(tok[1:])] & U32
    elif tok in ("vcc_lo", "vcc"):
        raw = sgprs["vcc_lo"] & U32
    elif tok in ("exec_lo", "exec"):
        raw = sgprs["exec_lo"] & U32
    elif tok == "scc":
        raw = sgprs["scc"] & 1
    elif tok in ("null", "off"):
        raw = 0
    elif tok.lower().startswith("0x") or tok.lower().startswith("-0x"):
        raw = int(tok, 16) & U32
    elif tok.lstrip("-").isdigit():
        raw = int(tok) & U32
    else:
        # float literal text such as 2.0 / -0.5
        try:
            return float(tok)
        except ValueError:
            raise OperandError("cannot decode operand %r" % tok)
    if fp16:
        return f16_bits_to_f32(raw & 0xFFFF)
    if fp:
        return bits_f32(raw)
    return raw


class LaneState:
    """Minimal architectural state: 256 VGPRs per lane, 128 SGPRs, EXEC/VCC."""

    def __init__(self, lanes=32, vgprs=256, sgprs=128):
        self.lanes = lanes
        self.regs = [[0] * vgprs for _ in range(lanes)]
        self.sgprs = [0] * sgprs
        self.exec_lo = (1 << lanes) - 1
        self.vcc_lo = 0
        self.scc = 0

    def sdict(self):
        d = {"vcc_lo": self.vcc_lo, "exec_lo": self.exec_lo, "scc": self.scc}
        for i, v in enumerate(self.sgprs):
            d[i] = v
        return _SgprView(self)


class _SgprView:
    def __init__(self, st):
        self._st = st

    def __getitem__(self, k):
        if k == "vcc_lo":
            return self._st.vcc_lo
        if k == "exec_lo":
            return self._st.exec_lo
        if k == "scc":
            return self._st.scc
        return self._st.sgprs[int(k)]


# ---------------------------------------------------------------------------
# THE INSTRUCTION TABLE
# ---------------------------------------------------------------------------
# Each entry: name -> (kind, operand_arity, function)
#   kind: "vop1" | "vop2" | "vop3" | "vopc" | "vopcx"
#   arity counts OPERANDS ONLY, excluding the destination.
# The function is called as fn(vals) where vals is the list of decoded source
# values, and returns either an integer (raw u32 result), a float (the result
# VALUE, which the caller must round to f32), or a bool (comparison predicate).
# ---------------------------------------------------------------------------

def _shift_amount(x, width=32):
    """The hardware masks the shift count; it does not saturate."""
    return x & (width - 1)


def _lshl(a, b):
    return u32(u32(a) << _shift_amount(u32(b)))


def _lshr(a, b):
    return u32(u32(a) >> _shift_amount(u32(b)))


def _ashr(a, b):
    return u32(to_s32(a) >> _shift_amount(u32(b)))


TABLE = {}

# operand index (0-based, into the SOURCE list) -> how to decode it
#   "int"  -> raw u32                "sint" -> SIGNED integer value
#   "f16"  -> raw low half, decoded to an f32 value
#   "f32"  -> forced f32 value (overrides a family default)
SRC_DECODE = {
    "v_cvt_f32_u32": {0: "int"},
    "v_cvt_f32_i32": {0: "int"},
    "v_cvt_f32_ubyte0": {0: "int"},
    "v_cvt_f32_f16": {0: "f16"},
    # The exponent is a SIGNED integer: reading it as raw bits turns -3 into
    # 0xFFFFFFFD and the scale factor into nonsense.
    "v_ldexp_f32": {1: "sint"},
    "v_frexp_exp_i32_f32": {0: "f32"},
}


def _reg(kind, arity):
    def deco(fn):
        TABLE[fn.__name__] = (kind, arity, fn)
        return fn
    return deco


# ---- integer ternary / shift-ternary (VOP3) -------------------------------
@_reg("vop3", 3)
def v_lshl_add_u32(a, b, c):
    """dst = (src0 << src1) + src2.

    src0 is the VALUE BEING SHIFTED; src1 is the shift AMOUNT.  Recorded
    asymmetry case: src0=8, src1=3, src2=56  ->  (8<<3)+56 = 120.
    A swapped implementation computes (3<<8)+56 = 824.
    """
    return u32(_lshl(a, b) + u32(c))


@_reg("vop3", 3)
def v_lshl_or_b32(a, b, c):
    """dst = (src0 << src1) | src2."""
    return u32(_lshl(a, b) | u32(c))


@_reg("vop3", 3)
def v_add_lshl_u32(a, b, c):
    """dst = (src0 + src1) << src2."""
    return u32(u32(u32(a) + u32(b)) << _shift_amount(u32(c)))


@_reg("vop3", 3)
def v_and_or_b32(a, b, c):
    return u32((u32(a) & u32(b)) | u32(c))


@_reg("vop3", 3)
def v_or3_b32(a, b, c):
    return u32(u32(a) | u32(b) | u32(c))


@_reg("vop3", 3)
def v_add3_u32(a, b, c):
    return u32(u32(a) + u32(b) + u32(c))


@_reg("vop3", 3)
def v_bfe_u32(a, o, w):
    o = u32(o) & 31
    w = u32(w) & 31
    if w == 0:
        return 0
    if o + w < 32:
        return u32((u32(a) >> o) & ((1 << w) - 1))
    return u32(u32(a) >> o)


@_reg("vop3", 3)
def v_bfe_i32(a, o, w):
    o = u32(o) & 31
    w = u32(w) & 31
    if w == 0:
        return 0
    if o + w < 32:
        v = u32(a) >> o
        v &= (1 << w) - 1
        if v & (1 << (w - 1)):
            v |= (U32 << w) & U32
        return u32(v)
    return u32(to_s32(a) >> o)


@_reg("vop3", 3)
def v_bfi_b32(a, b, c):
    """dst = (src0 & src1) | (~src0 & src2)."""
    a, b, c = u32(a), u32(b), u32(c)
    return u32((a & b) | (~a & c))


@_reg("vop3", 3)
def v_perm_b32(a, b, c):
    """Byte permute.  Independent model of the 4 selectors in src2.

    Selector encoding, per byte position i of src2:
        0..3   -> byte i of src0
        4..7   -> byte (i-4) of src1
        8      -> 0x00        9 -> 0xFF
        10     -> 0x80       11 -> 0x7F
        12..15 -> replicated-sign bytes of src0/src1
    """
    a, b, c = u32(a), u32(b), u32(c)
    out = 0
    for i in range(4):
        sel = (c >> (8 * i)) & 0xFF
        if sel < 4:
            byte = (a >> (8 * sel)) & 0xFF
        elif sel < 8:
            byte = (b >> (8 * (sel - 4))) & 0xFF
        elif sel == 8:
            byte = 0x00
        elif sel == 9:
            byte = 0xFF
        elif sel == 10:
            byte = 0x80
        elif sel == 11:
            byte = 0x7F
        elif sel == 12:
            byte = 0xFF if (a & 0x80000000) else 0x00
        elif sel == 13:
            byte = 0xFF if (a & 0x8000) else 0x00
        elif sel == 14:
            byte = 0xFF if (b & 0x80000000) else 0x00
        else:
            byte = 0xFF if (b & 0x8000) else 0x00
        out |= byte << (8 * i)
    return u32(out)


# ---- VOP2 shift/reverse-shift ---------------------------------------------
@_reg("vop2", 2)
def v_lshlrev_b32(a, b):
    """dst = src1 << src0  (the REV form reverses the operand roles)."""
    return u32(u32(b) << _shift_amount(u32(a)))


@_reg("vop2", 2)
def v_lshrrev_b32(a, b):
    return u32(u32(b) >> _shift_amount(u32(a)))


@_reg("vop2", 2)
def v_ashrrev_i32(a, b):
    return u32(to_s32(b) >> _shift_amount(u32(a)))


@_reg("vop2", 2)
def v_add_nc_u32(a, b):
    return u32(u32(a) + u32(b))


@_reg("vop2", 2)
def v_sub_nc_u32(a, b):
    return u32(u32(a) - u32(b))


@_reg("vop2", 2)
def v_subrev_nc_u32(a, b):
    return u32(u32(b) - u32(a))


@_reg("vop2", 2)
def v_and_b32(a, b):
    return u32(a) & u32(b)


@_reg("vop2", 2)
def v_or_b32(a, b):
    return u32(a) | u32(b)


@_reg("vop2", 2)
def v_xor_b32(a, b):
    return u32(a) ^ u32(b)


@_reg("vop2", 2)
def v_min_i32(a, b):
    return u32(to_s32(a) if to_s32(a) < to_s32(b) else to_s32(b))


@_reg("vop2", 2)
def v_max_i32(a, b):
    return u32(to_s32(a) if to_s32(a) > to_s32(b) else to_s32(b))


@_reg("vop2", 2)
def v_min_u32(a, b):
    return u32(a) if u32(a) < u32(b) else u32(b)


@_reg("vop2", 2)
def v_max_u32(a, b):
    return u32(a) if u32(a) > u32(b) else u32(b)


@_reg("vop2", 2)
def v_min_f32(a, b):
    return _fmin(a, b)


@_reg("vop2", 2)
def v_max_f32(a, b):
    return _fmax(a, b)


@_reg("vop2", 2)
def v_add_f32(a, b):
    return a + b


@_reg("vop2", 2)
def v_sub_f32(a, b):
    return a - b


@_reg("vop2", 2)
def v_mul_f32(a, b):
    return a * b


@_reg("vop2", 2)
def v_mul_legacy_f32(a, b):
    return a * b


@_reg("vop2", 2)
def v_mac_f32(a, b):
    """dst = src0*src1 + dst  -- but the dst is the third input, so the caller
    passes (src0, src1, dst) via the vop2_dst3 hook below."""
    raise OperandError("v_mac_f32 needs the destination; use MAC_OPS")


# FMA/FMAMK/... take three SOURCES (dst, s0, s1, s2 printed).
for _n, _f in {
    "v_fma_f32": lambda a, b, c: a * b + c,
    "v_fmamk_f32": lambda a, b, c: a * b + bits_f32(c),
    "v_fmaak_f32": lambda a, b, c: a * bits_f32(b) + c,
    "v_madak_f32": lambda a, b, c: a * b + bits_f32(c),
    "v_madmk_f32": lambda a, b, c: a * bits_f32(b) + c,
}.items():
    TABLE[_n] = ("vop3", 3, _f)

# MAC/FMAC read the DESTINATION as a third input: `dst, src0, src1`.
MAC_OPS = {
    "v_mac_f32": lambda a, b, d: a * b + d,
    "v_fmac_f32": lambda a, b, d: a * b + d,
}
for _n, _f in MAC_OPS.items():
    TABLE[_n] = ("vop2", 2, _f)

# v_dot2c_f32_f16 is a VOP3P whose destination is also an accumulator, and
# whose source encoding (op_sel / neg modifiers) this oracle does not model.
# It is deliberately NOT in the table: an unmodelled instruction must raise
# rather than silently return a plausible number.  Phase 16K established that
# it is control-neutral on the analysed path.


def _fmin(a, b):
    if math.isnan(a):
        return b
    if math.isnan(b):
        return a
    if a == 0.0 and b == 0.0:
        return -0.0 if (math.copysign(1, a) < 0 or math.copysign(1, b) < 0) else 0.0
    return a if a < b else b


def _fmax(a, b):
    if math.isnan(a):
        return b
    if math.isnan(b):
        return a
    if a == 0.0 and b == 0.0:
        return 0.0 if (math.copysign(1, a) > 0 or math.copysign(1, b) > 0) else -0.0
    return a if a > b else b


# ---- VOP1 conversions ------------------------------------------------------
@_reg("vop1", 1)
def v_cvt_f32_i32(a):
    return float(to_s32(a))


@_reg("vop1", 1)
def v_cvt_f32_u32(a):
    return float(u32(a))


@_reg("vop1", 1)
def v_cvt_i32_f32(a):
    if math.isnan(a) or math.isinf(a):
        return 0
    if a >= 2.0 ** 31:
        return 0x7FFFFFFF
    if a <= -(2.0 ** 31):
        return 0x80000000
    return u32(int(math.trunc(a)))


@_reg("vop1", 1)
def v_cvt_u32_f32(a):
    if math.isnan(a) or a <= 0:
        return 0
    if a >= 2.0 ** 32:
        return U32
    return u32(int(math.trunc(a)))


@_reg("vop1", 1)
def v_cvt_f32_f16(a):
    # The source was declared kind "f16" in SRC_DECODE, so `a` has ALREADY
    # been decoded to an f32 value by the operand reader.  Decoding it a
    # second time was the first draft's bug and it raised TypeError here.
    return a


@_reg("vop1", 1)
def v_cvt_f16_f32(a):
    return f32_to_f16_bits(a)


@_reg("vop1", 1)
def v_cvt_f32_ubyte0(a):
    return float(u32(a) & 0xFF)


@_reg("vop1", 1)
def v_floor_f32(a):
    if math.isnan(a) or math.isinf(a):
        return a
    return float(math.floor(a))


@_reg("vop1", 1)
def v_ceil_f32(a):
    if math.isnan(a) or math.isinf(a):
        return a
    return float(math.ceil(a))


@_reg("vop1", 1)
def v_trunc_f32(a):
    if math.isnan(a) or math.isinf(a):
        return a
    return float(math.trunc(a))


@_reg("vop1", 1)
def v_rndne_f32(a):
    """Round to nearest, ties to EVEN -- the hardware rule, not Python's."""
    if math.isnan(a) or math.isinf(a):
        return a
    f = math.floor(a)
    diff = a - f
    if diff > 0.5:
        return float(f + 1)
    if diff < 0.5:
        return float(f)
    # exact tie: pick the even neighbour
    return float(f if f % 2 == 0 else f + 1)


@_reg("vop1", 1)
def v_rcp_f32(a):
    if math.isnan(a):
        return a
    if a == 0.0:
        return math.copysign(math.inf, a)
    if math.isinf(a):
        return math.copysign(0.0, a)
    return 1.0 / a


@_reg("vop1", 1)
def v_rsq_f32(a):
    if a < 0 or math.isnan(a):
        return math.nan
    if a == 0.0:
        return math.inf
    return 1.0 / math.sqrt(a)


@_reg("vop1", 1)
def v_sqrt_f32(a):
    if math.isnan(a) or a < 0:
        return math.nan
    return math.sqrt(a)


@_reg("vop1", 1)
def v_log_f32(a):
    """f32 natural log.  log(0) = -inf, x<0 or NaN -> NaN."""
    if math.isnan(a):
        return math.nan
    if a < 0:
        return math.nan
    if a == 0.0:
        return -math.inf
    if math.isinf(a):
        return math.inf
    return math.log(a)


@_reg("vop1", 1)
def v_exp_f32(a):
    if math.isnan(a):
        return math.nan
    try:
        return math.exp(a)
    except OverflowError:
        return math.inf


@_reg("vop2", 2)
def v_ldexp_f32(a, b):
    """dst = src0 * 2^src1, with src1 an INTEGER register."""
    if math.isnan(a):
        return math.nan
    n = to_s32(b)
    if math.isinf(a) or a == 0.0:
        return a
    if n > 1000:
        return math.copysign(math.inf, a)
    if n < -1000:
        return math.copysign(0.0, a)
    try:
        return math.ldexp(a, n)
    except OverflowError:
        return math.copysign(math.inf, a)


@_reg("vop1", 1)
def v_frexp_mant_f32(a):
    if math.isnan(a) or math.isinf(a) or a == 0.0:
        return a
    m, _ = math.frexp(a)
    return m


@_reg("vop1", 1)
def v_frexp_exp_i32_f32(a):
    if math.isnan(a) or math.isinf(a) or a == 0.0:
        return 0
    _, e = math.frexp(a)
    return u32(e)


# ---- comparisons -----------------------------------------------------------
# The predicate functions take two decoded operands and return a bool.
# INT predicates take raw u32; FP predicates take f32 VALUES (fp) or f16
# VALUES (fp16, already decoded to f32 by the caller's decode).
_INT_PREDS = {
    "eq": lambda a, b: u32(a) == u32(b),
    "ne": lambda a, b: u32(a) != u32(b),
    "lt": lambda a, b: u32(a) < u32(b),
    "le": lambda a, b: u32(a) <= u32(b),
    "gt": lambda a, b: u32(a) > u32(b),
    "ge": lambda a, b: u32(a) >= u32(b),
}
_SIGNED_PREDS = {
    "eq": lambda a, b: to_s32(a) == to_s32(b),
    "ne": lambda a, b: to_s32(a) != to_s32(b),
    "lt": lambda a, b: to_s32(a) < to_s32(b),
    "le": lambda a, b: to_s32(a) <= to_s32(b),
    "gt": lambda a, b: to_s32(a) > to_s32(b),
    "ge": lambda a, b: to_s32(a) >= to_s32(b),
}
# For floats, "n<cond>" is the NEGATION of the ordered test, and is TRUE when
# either operand is NaN.  This is why `ngt` must be `not (a > b)` and cannot be
# written as `a <= b`.
_FP_PREDS = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: not (a == b),
    "lt": lambda a, b: a < b,
    "le": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
    "ge": lambda a, b: a >= b,
    "nlt": lambda a, b: not (a < b),
    "nle": lambda a, b: not (a <= b),
    "ngt": lambda a, b: not (a > b),
    "nge": lambda a, b: not (a >= b),
    "o": lambda a, b: not (math.isnan(a) or math.isnan(b)),
    "u": lambda a, b: math.isnan(a) or math.isnan(b),
    "lg": lambda a, b: not (a == b),
    # `neq` is the ISA's own spelling for the unordered not-equal, and it is
    # what the encoder's `v_cmpx_neq_f32_e32 0, v5` uses.  It must be NaN-TRUE,
    # like `lg`, and unlike a plain `a != b` on a NaN operand pair that a
    # language-level comparison might short-circuit.
    "neq": lambda a, b: not (a == b),
}


def compare_predicate(mnem, a, b):
    """mnem is a full `v_cmp_*` / `v_cmpx_*` name WITHOUT the _e32/_e64 suffix."""
    core = mnem.replace("v_cmpx_", "").replace("v_cmp_", "")
    cond, _, width = core.rpartition("_")
    if not cond:
        raise OperandError("cannot parse compare %r" % mnem)
    if width in ("f32", "f64", "f16"):
        if cond not in _FP_PREDS:
            raise OperandError("no fp predicate %r (%s)" % (cond, mnem))
        return _FP_PREDS[cond](a, b)
    if width in ("i32", "i16", "i8"):
        tbl = _SIGNED_PREDS if width == "i32" else None
        if tbl is None:
            conv = to_s16 if width == "i16" else to_s8
            if cond not in _SIGNED_PREDS:
                raise OperandError("no pred %r" % cond)
            f = _SIGNED_PREDS[cond]
            return f(conv(a), conv(b))
        if cond not in tbl:
            raise OperandError("no pred %r" % cond)
        return tbl[cond](a, b)
    if width in ("u32", "u16", "u8"):
        conv = {"u32": u32, "u16": lambda x: x & 0xFFFF,
                "u8": lambda x: x & 0xFF}[width]
        if cond not in _INT_PREDS:
            raise OperandError("no pred %r" % cond)
        f = _INT_PREDS[cond]
        return f(conv(a), conv(b))
    raise OperandError("unknown compare width in %r" % mnem)


# ---------------------------------------------------------------------------
# EXECUTING ONE INSTRUCTION
# ---------------------------------------------------------------------------
def execute(mnem, ops, st, dst_token=None):
    """Execute one vector instruction against LaneState `st`.

    Returns a dict describing the architectural effect, so a caller can compare
    it against the emulator field by field rather than only on a summary.

    Only the families this oracle covers are accepted; anything else raises
    KeyError, which is deliberate -- an unknown instruction must not silently
    produce a "pass".
    """
    is_cmp = mnem.startswith("v_cmp_")
    is_cmpx = mnem.startswith("v_cmpx_")

    # ---- operand arity -------------------------------------------------
    # Compares are handled here rather than through TABLE, because their
    # predicate set is open-ended.
    if is_cmp or is_cmpx:
        arity = 2
    else:
        kind_arity = TABLE.get(mnem)
        if kind_arity is None:
            raise KeyError(mnem)
        kind, arity, fn = kind_arity

    # ---- operand layout -------------------------------------------------
    # THE DISASSEMBLER PRINTS A DESTINATION FOR `v_cmpx_*` TOO, and that is
    # not a quirk to be normalised away -- it is the fact the whole repair
    # turns on.  In the Candidate F module the line is
    #
    #     v_cmpx_neq_f32_e32 0, v5
    #
    # so the source operand this kernel compares against v5 sits at INDEX 1,
    # NOT index 0.  For `v_cmpx_*` the destination is architecturally EXEC and
    # is not written by the instruction, but the printed slot is still there.
    #
    # A driver that inserts one and a driver that does not would disagree
    # about which operand is src0; requiring the printed layout here makes
    # that disagreement impossible instead of silent.
    if is_cmpx:
        # VOPCX prints NO destination: ops[0] and ops[1] are src0 and src1.
        dst = None
        srcs = ops[0:arity]
    elif is_cmp or dst_token is not None:
        dst = ops[0]
        srcs = ops[1:1 + arity]
    elif len(ops) > arity:
        # The caller supplied the printed destination itself.
        dst = ops[0]
        srcs = ops[1:1 + arity]
    else:
        # The vector list carries SOURCES ONLY for vop1/vop2/vop3; the
        # destination is a separate field, so the caller hands `dst_token`
        # explicitly and `ops` holds sources.
        dst = dst_token
        srcs = ops[:arity]
    if len(srcs) != arity:
        raise OperandError(
            "mnemonic %s arity %d but got %d source operands from %r"
            % (mnem, arity, len(srcs), ops))

    fp = mnem.endswith("_f32") or mnem.endswith("_f16") or mnem.endswith("_f64")
    fp16 = mnem.endswith("_f16")

    eff = {"exec_lo": st.exec_lo, "vcc_lo": st.vcc_lo, "vregs": {}}

    if is_cmp or is_cmpx:
        # NOTE: no special-casing of immediate operands.  `_f32` compares and
        # `_f32` arithmetic BOTH treat an integer literal as raw f32 bits, so
        # one rule covers every vector here -- including the `0` in the
        # encoder's own `v_cmpx_neq_f32_e32 0, v5`.
        mask = 0
        for lane in range(st.lanes):
            if not ((st.exec_lo >> lane) & 1):
                continue
            a = decode_operand(srcs[0], regs=st.regs, sgprs=st.sdict(),
                               lane=lane, fp=fp, fp16=fp16)
            b = decode_operand(srcs[1], regs=st.regs, sgprs=st.sdict(),
                               lane=lane, fp=fp, fp16=fp16)
            if compare_predicate(mnem, a, b):
                mask |= 1 << lane
        if is_cmpx:
            st.exec_lo = mask
            eff["exec_lo"] = mask
        else:
            if dst in ("vcc_lo", "vcc", "vcc_hi"):
                st.vcc_lo = mask
                eff["vcc_lo"] = mask
            else:
                raise OperandError("oracle covers vcc-destination compares only")
        return eff

    if kind not in ("vop1", "vop2", "vop3"):
        raise OperandError("kind %r" % kind)

    for lane in range(st.lanes):
        if not ((st.exec_lo >> lane) & 1):
            continue
        kinds = SRC_DECODE.get(mnem, {})
        vals = []
        for si, t in enumerate(srcs):
            k = kinds.get(si)
            if k == "int":
                vals.append(decode_operand(t, regs=st.regs, sgprs=st.sdict(),
                                           lane=lane, fp=False))
            elif k == "sint":
                vals.append(to_s32(decode_operand(t, regs=st.regs,
                                                  sgprs=st.sdict(),
                                                  lane=lane, fp=False)))
            elif k == "f16":
                vals.append(decode_operand(t, regs=st.regs, sgprs=st.sdict(),
                                           lane=lane, fp16=True))
            else:
                vals.append(decode_operand(t, regs=st.regs, sgprs=st.sdict(),
                                           lane=lane, fp=fp, fp16=fp16))
        if mnem in MAC_OPS:
            # ONLY v_mac_/v_fmac_ accumulate into the destination.  v_fma_f32
            # takes three printed sources (`dst = src0*src1 + src2`) and does
            # not read its destination -- the first draft of this oracle had
            # that wrong, and the ISA definition corrected it.
            vals.append(decode_operand(dst, regs=st.regs, sgprs=st.sdict(),
                                       lane=lane, fp=fp, fp16=fp16))
        if mnem in MAC_OPS:
            # MAC/FMAC read the destination register as a third INPUT.
            vals.append(decode_operand(dst, regs=st.regs, sgprs=st.sdict(),
                                       lane=lane, fp=fp, fp16=fp16))
        r = fn(*vals)
        if isinstance(r, bool):
            r = 1 if r else 0
        if isinstance(r, float):
            if mnem.endswith("_f16") and kind != "vop1":
                n = st.regs[lane][int(dst_token[1:])]
                st.regs[lane][int(dst_token[1:])] = (n & 0xFFFF0000) | \
                    (f32_to_f16_bits(r) & 0xFFFF)
            else:
                st.regs[lane][int(dst_token[1:])] = f32_bits(r)
        else:
            if mnem in ("v_cvt_f16_f32", "v_cvt_f32_f16"):
                n = st.regs[lane][int(dst_token[1:])]
                st.regs[lane][int(dst_token[1:])] = (n & 0xFFFF0000) | (r & 0xFFFF)
            else:
                st.regs[lane][int(dst_token[1:])] = u32(r)
        eff["vregs"][lane] = st.regs[lane][int(dst_token[1:])]
    return eff


def _is_hex(tok):
    t = tok.strip().lower()
    return t.startswith("0x") or t.startswith("-0x")


# ---------------------------------------------------------------------------
# THE CONFORMANCE TEST VECTORS
# ---------------------------------------------------------------------------
# Every vector is (name, mnemonic, [operands excluding dst], dst_token,
#                 setup, expected).  `setup` names a state-construction recipe.
# Everything here is checked by hand against the ISA text in
# ISA_SEMANTICS.md; the oracle's own arithmetic is what produces the value.
# ---------------------------------------------------------------------------

NAN = float("nan")
INF = float("inf")


def _hex(v):
    return "0x%08X" % u32(v)


def build_vectors():
    """Return the full vector list.  Each entry is a dict.

    LAYOUT CONTRACT -- `srcs` is the operand list WITHOUT a destination for
    vop1/vop2/vop3 (the destination is the separate `dst` field), and WITH the
    printed destination in slot 0 for vopc/vopcx, because the disassembler
    prints one for those too.  `execute()` therefore always receives the exact
    operand list the disassembler would print, index for index.
    """
    V = []

    def add(family, name, mnem, srcs, dst, setup, note=""):
        V.append({"family": family, "name": name, "mnem": mnem,
                  "srcs": srcs, "dst": dst, "setup": setup, "note": note})

    # =====================================================================
    # FAMILY 1 -- v_lshl_add_u32  (defect D)
    # =====================================================================
    # THE recorded asymmetric case.  src0=8 (the value), src1=3 (the shift),
    # src2=56.  ISA 120.  A swapped implementation yields 824.
    add("lshl_add", "asymmetric_8_3_56", "v_lshl_add_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 8, "v2": 3, "v3": 56},
        "the recorded case: ISA (8<<3)+56 = 120; swapped (3<<8)+56 = 824")
    add("lshl_add", "shift_zero", "v_lshl_add_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 0xDEADBEEF, "v2": 0, "v3": 7},
        "shift amount 0 must return src0+src2 unchanged")
    add("lshl_add", "shift_one", "v_lshl_add_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 1, "v2": 1, "v3": 1})
    add("lshl_add", "shift_seven", "v_lshl_add_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 1, "v2": 7, "v3": 0})
    add("lshl_add", "shift_fifteen", "v_lshl_add_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 1, "v2": 15, "v3": 0})
    add("lshl_add", "shift_thirtyone", "v_lshl_add_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 1, "v2": 31, "v3": 0})
    add("lshl_add", "shift_wraps_mod32", "v_lshl_add_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 1, "v2": 33, "v3": 0},
        "shift amount is masked to 5 bits: 33 -> 1")
    add("lshl_add", "sign_bit_value", "v_lshl_add_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 0x80000000, "v2": 1, "v3": 0},
        "left shift out of the top is dropped")
    add("lshl_add", "all_ones", "v_lshl_add_u32",
        ["v1", "v2", "v3"], "v0", {"v1": U32, "v2": 0, "v3": 0})
    add("lshl_add", "carry_out", "v_lshl_add_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 0x7FFFFFFF, "v2": 1, "v3": 1},
        "result wraps to 0xFFFFFFFF, no carry flag exists")
    # The encoder's own shape: pack the 3-bit mantissa.  src0 = mantissa,
    # src1 = 3, src2 = 56.  Distinguishes the operand order in situ.
    add("lshl_add", "encoder_pack_shape", "v_lshl_add_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 5, "v2": 3, "v3": 56},
        "the E4M3 pack site's shape: (5<<3)+56 = 96 vs swapped (3<<5)+56 = 152")

    # =====================================================================
    # FAMILY 2 -- v_lshl_or_b32  (defect E; the LDS tag former)
    # =====================================================================
    add("lshl_or", "asymmetric_8_3_56", "v_lshl_or_b32",
        ["v1", "v2", "v3"], "v0", {"v1": 8, "v2": 3, "v3": 56},
        "ISA (8<<3)|56 = 120; swapped (3<<8)|56 = 824 -- same numbers as "
        "the lshl_add case so the two families cannot be confused")
    add("lshl_or", "tag_formation_shape", "v_lshl_or_b32",
        ["v1", "v2", "v3"], "v0", {"v1": 0x1234, "v2": 7, "v3": 0x9A},
        "the shape the disassembly shows: v_lshl_or_b32 v3, v40, 7, v37")
    add("lshl_or", "shift_zero", "v_lshl_or_b32",
        ["v1", "v2", "v3"], "v0", {"v1": 0x0F0F0F0F, "v2": 0,
                                   "v3": 0xF0F0F0F0})
    add("lshl_or", "shift_thirtyone", "v_lshl_or_b32",
        ["v1", "v2", "v3"], "v0", {"v1": 1, "v2": 31, "v3": 1})
    add("lshl_or", "all_ones_shift_zero", "v_lshl_or_b32",
        ["v1", "v2", "v3"], "v0", {"v1": U32, "v2": 0, "v3": 0})
    add("lshl_or", "or_bits_disjoint", "v_lshl_or_b32",
        ["v1", "v2", "v3"], "v0", {"v1": 0x1, "v2": 16, "v3": 0xFFFF},
        "high bits come only from the shift, low from src2")

    # =====================================================================
    # FAMILY 3 -- v_cmpx_* two-operand / e32   (defect A)
    # =====================================================================
    # LAYOUT: for `v_cmpx_*` the disassembler prints `src0, src1` -- there is
    # no destination to print, because the destination is EXEC and is written
    # implicitly.  `srcs` therefore holds EXACTLY the two sources, and the
    # literal `0` in the encoder's own site is src0, not a destination slot:
    #     v_cmpx_neq_f32_e32 0, v5      ->  src0 = 0 (immediate), src1 = v5
    # A test for that shape is expressed as boolean_literal_zero below, not by
    # putting a placeholder register in the operand list.
    # Every cmpx vector asserts the RESULTING EXEC MASK, which is the whole
    # architectural effect of the instruction.
    add("cmpx", "neq_f32_immediate_unequal", "v_cmpx_neq_f32",
        ["`bool_zero`", "v1"], None, {"v1_f32": 1.0},
        "the J3 encoder's own shape: src0=0, src1=1.0 -> all lanes TRUE. "
        "A self-comparison implementation yields EXEC=0.")
    add("cmpx", "neq_f32_immediate_equal", "v_cmpx_neq_f32",
        ["`bool_zero`", "v1"], None, {"v1_f32": 0.0},
        "src0 == src1 -> all lanes FALSE")
    add("cmpx", "neq_f32_nan", "v_cmpx_neq_f32",
        ["`bool_zero`", "v1"], None, {"v1_f32": NAN},
        "NaN != 0 is TRUE")
    add("cmpx", "neq_bool_zero_literal_true", "v_cmpx_neq_f32",
        ["`bool_zero`", "v1"], None, {"v1_f32": 1.0},
        "THE ENCODER'S EXACT SHAPE, written the way the disassembler prints it: "
        "`v_cmpx_neq_f32_e32 0, v5`.  The first operand is the hardware's "
        "boolean-false literal, which the scalar field encodes as SGPR 0 "
        "(also called `bool_zero`); it is NOT a destination slot.  ISA: TRUE "
        "for every lane, EXEC=0xFFFFFFFF.")
    add("cmpx", "gt_f32_true", "v_cmpx_gt_f32",
        ["v1", "v2"], None, {"v1_f32": 2.0, "v2_f32": 1.0})
    add("cmpx", "gt_f32_false", "v_cmpx_gt_f32",
        ["v1", "v2"], None, {"v1_f32": 1.0, "v2_f32": 2.0},
        "self-comparison would wrongly give TRUE")
    add("cmpx", "lt_f32_false", "v_cmpx_lt_f32",
        ["v1", "v2"], None, {"v1_f32": 2.0, "v2_f32": 1.0},
        "self-comparison would wrongly give FALSE")
    add("cmpx", "lt_f32_true", "v_cmpx_lt_f32",
        ["v1", "v2"], None, {"v1_f32": 1.0, "v2_f32": 2.0})
    add("cmpx", "ngt_f32_gt", "v_cmpx_ngt_f32",
        ["v1", "v2"], None, {"v1_f32": 2.0, "v2_f32": 1.0},
        "the predicate v_cmp_ngt_f32 was entirely absent (defect C)")
    add("cmpx", "ngt_f32_le", "v_cmpx_ngt_f32",
        ["v1", "v2"], None, {"v1_f32": 1.0, "v2_f32": 2.0})
    add("cmpx", "ngt_f32_eq", "v_cmpx_ngt_f32",
        ["v1", "v2"], None, {"v1_f32": 1.0, "v2_f32": 1.0})
    add("cmpx", "ngt_f32_nan", "v_cmpx_ngt_f32",
        ["v1", "v2"], None, {"v1_f32": NAN, "v2_f32": 1.0},
        "not(gt) is TRUE when either operand is NaN -- the entry the "
        "emulator lacked, on the encoder's critical path")
    add("cmpx", "nlt_f32_eq", "v_cmpx_nlt_f32",
        ["v1", "v2"], None, {"v1_f32": 1.0, "v2_f32": 1.0})
    add("cmpx", "nge_f32_lt", "v_cmpx_nge_f32",
        ["v1", "v2"], None, {"v1_f32": 1.0, "v2_f32": 2.0})
    add("cmpx", "o_f32_nan", "v_cmpx_o_f32",
        ["v1", "v2"], None, {"v1_f32": NAN, "v2_f32": 1.0},
        "ordered: FALSE when either is NaN")
    add("cmpx", "u_f32_nan", "v_cmpx_u_f32",
        ["v1", "v2"], None, {"v1_f32": NAN, "v2_f32": 1.0},
        "unordered: TRUE when either is NaN")
    add("cmpx", "eq_f32_negzero", "v_cmpx_eq_f32",
        ["v1", "v2"], None, {"v1_f32": 0.0, "v2_f32": -0.0},
        "+0 == -0 in IEEE-754")
    add("cmpx", "eq_f32_inf", "v_cmpx_eq_f32",
        ["v1", "v2"], None, {"v1_f32": INF, "v2_f32": INF})
    add("cmpx", "lt_f16_scalar", "v_cmpx_lt_f16",
        ["v1", "v2"], None, {"v1_f16": 0x3C00, "v2_f16": 0x4000},
        "f16 comparison decodes halves: 1.0 < 2.0 -> TRUE")
    add("cmpx", "eq_i32_signed_neg", "v_cmpx_eq_i32",
        ["v1", "v2"], None, {"v1": 0xFFFFFFFF, "v2": 0xFFFFFFFF},
        "the integer path must keep working after the fp path is repaired")
    add("cmpx", "gt_u32_unsigned", "v_cmpx_gt_u32",
        ["v1", "v2"], None, {"v1": 0xFFFFFFFF, "v2": 1},
        "unsigned: 0xFFFFFFFF > 1 is TRUE.  As signed it would be FALSE.")
    add("cmpx", "gt_i32_signed_negative", "v_cmpx_gt_i32",
        ["v1", "v2"], None, {"v1": 1, "v2": 0xFFFFFFFF},
        "signed: 1 > -1 is TRUE.  As unsigned it would be FALSE.")

    # =====================================================================
    # FAMILY 4 -- _vfp register operand decoding   (defect B)
    # =====================================================================
    add("vfp", "mul_two_registers", "v_mul_f32",
        ["v1", "v2"], "v0", {"v1_f32": 3.0, "v2_f32": 4.0},
        "raw-bit transport gives a nonsense value here")
    add("vfp", "mul_by_immediate", "v_mul_f32",
        ["v1", "0x40000000"], "v0", {"v1_f32": 3.0},
        "2.0 as an immediate; the immediate path already worked")
    add("vfp", "add_negative", "v_add_f32",
        ["v1", "v2"], "v0", {"v1_f32": 1.5, "v2_f32": -0.25})
    add("vfp", "sub_sign", "v_sub_f32",
        ["v1", "v2"], "v0", {"v1_f32": 0.25, "v2_f32": 1.0},
        "must be negative; a bit-pattern subtraction would not be")
    add("vfp", "mul_zero", "v_mul_f32",
        ["v1", "v2"], "v0", {"v1_f32": 0.0, "v2_f32": 5.0})
    add("vfp", "mul_negzero", "v_mul_f32",
        ["v1", "v2"], "v0", {"v1_f32": -0.0, "v2_f32": 5.0},
        "sign of zero survives")
    add("vfp", "mul_inf_zero", "v_mul_f32",
        ["v1", "v2"], "v0", {"v1_f32": INF, "v2_f32": 0.0},
        "inf*0 is NaN")
    add("vfp", "add_inf_neg_inf", "v_add_f32",
        ["v1", "v2"], "v0", {"v1_f32": INF, "v2_f32": -INF},
        "inf + -inf is NaN")
    add("vfp", "add_nan", "v_add_f32",
        ["v1", "v2"], "v0", {"v1_f32": NAN, "v2_f32": 1.0})
    add("vfp", "add_denormal", "v_add_f32",
        ["v1", "v2"], "v0", {"v1_f32": bits_f32(1), "v2_f32": 0.0},
        "smallest positive subnormal f32")
    add("vfp", "fma_three_registers", "v_fma_f32",
        ["v1", "v2", "v3"], "v0", {"v1_f32": 2.0, "v2_f32": 3.0,
                                   "v3_f32": 4.0},
        "the classic case the K6 report measured as 11/13 disagreeing")
    add("vfp", "fma_negative", "v_fma_f32",
        ["v1", "v2", "v3"], "v0", {"v1_f32": -2.0, "v2_f32": 3.0,
                                   "v3_f32": 4.0})
    add("vfp", "min_ignores_nan", "v_min_f32",
        ["v1", "v2"], "v0", {"v1_f32": NAN, "v2_f32": 1.0},
        "fmin returns the non-NaN operand")
    add("vfp", "max_negzero", "v_max_f32",
        ["v1", "v2"], "v0", {"v1_f32": -0.0, "v2_f32": 0.0})
    add("vfp", "rcp_zero", "v_rcp_f32",
        ["v1"], "v0", {"v1_f32": 0.0},
        "1/0 is +inf, not a Python ZeroDivisionError")
    add("vfp", "rcp_negzero", "v_rcp_f32",
        ["v1"], "v0", {"v1_f32": -0.0})
    add("vfp", "sqrt_negative", "v_sqrt_f32",
        ["v1"], "v0", {"v1_f32": -1.0},
        "sqrt(-1) is NaN")
    add("vfp", "log_zero", "v_log_f32",
        ["v1"], "v0", {"v1_f32": 0.0},
        "log(0) = -inf; the encoder depends on this, not on an exception")
    add("vfp", "log_negative", "v_log_f32",
        ["v1"], "v0", {"v1_f32": -1.0})
    add("vfp", "log_one", "v_log_f32",
        ["v1"], "v0", {"v1_f32": 1.0})
    add("vfp", "floor_negative", "v_floor_f32",
        ["v1"], "v0", {"v1_f32": -1.5},
        "floor(-1.5) is -2.0; truncation would give -1.0")
    add("vfp", "floor_exact", "v_floor_f32",
        ["v1"], "v0", {"v1_f32": 3.0})
    add("vfp", "rndne_tie_down", "v_rndne_f32",
        ["v1"], "v0", {"v1_f32": 0.5},
        "round-to-nearest-EVEN: 0.5 -> 0.0.  Python's round() agrees but "
        "round-half-away would not.")
    add("vfp", "rndne_tie_up", "v_rndne_f32",
        ["v1"], "v0", {"v1_f32": 1.5},
        "1.5 -> 2.0 (2 is even)")
    add("vfp", "rndne_tie_two_five", "v_rndne_f32",
        ["v1"], "v0", {"v1_f32": 2.5},
        "2.5 -> 2.0 (2 is even, 3 is not)")
    add("vfp", "rndne_not_tie", "v_rndne_f32",
        ["v1"], "v0", {"v1_f32": 2.6})
    add("vfp", "ldexp_up", "v_ldexp_f32",
        ["v1", "v2"], "v0", {"v1_f32": 1.5, "v2": 3},
        "1.5 * 2^3 = 12.0")
    add("vfp", "ldexp_down", "v_ldexp_f32",
        ["v1", "v2"], "v0", {"v1_f32": 1.5, "v2": -3},
        "1.5 * 2^-3 = 0.1875")
    add("vfp", "ldexp_zero_exp", "v_ldexp_f32",
        ["v1", "v2"], "v0", {"v1_f32": 7.25, "v2": 0})
    add("vfp", "cvt_f32_u32", "v_cvt_f32_u32",
        ["v1"], "v0", {"v1": 0xFFFFFFFF},
        "unsigned 4294967295.0, not -1.0")
    add("vfp", "cvt_f32_i32", "v_cvt_f32_i32",
        ["v1"], "v0", {"v1": 0xFFFFFFFF},
        "signed -1.0 -- the same bits, the opposite answer")
    add("vfp", "cvt_i32_f32_negative", "v_cvt_i32_f32",
        ["v1"], "v0", {"v1_f32": -3.75},
        "truncation toward zero -> -3")
    add("vfp", "cvt_i32_f32_large", "v_cvt_i32_f32",
        ["v1"], "v0", {"v1_f32": 3.0e9},
        "saturates to 0x7FFFFFFF")
    add("vfp", "cvt_u32_f32_negative", "v_cvt_u32_f32",
        ["v1"], "v0", {"v1_f32": -1.0},
        "clamps to 0")
    add("vfp", "cvt_f32_ubyte0", "v_cvt_f32_ubyte0",
        ["v1"], "v0", {"v1": 0x000000FF})
    add("vfp", "cvt_f32_f16_subnormal", "v_cvt_f32_f16",
        ["v1"], "v0", {"v1_f16": 0x0001},
        "smallest f16 subnormal, exactly representable in f32")

    # =====================================================================
    # FAMILY 5 -- adjacent handlers on the same critical path
    # =====================================================================
    add("adjacent", "lshlrev_asymmetric", "v_lshlrev_b32",
        ["v1", "v2"], "v0", {"v1": 3, "v2": 8},
        "REV form: dst = src1 << src0 = 8<<3 = 64.  Getting lshl and lshlrev "
        "the same way round is the classic way to be wrong twice.")
    add("adjacent", "lshrrev_asymmetric", "v_lshrrev_b32",
        ["v1", "v2"], "v0", {"v1": 3, "v2": 0x40},
        "dst = src1 >> src0 = 0x40>>3 = 8")
    add("adjacent", "ashrrev_negative", "v_ashrrev_i32",
        ["v1", "v2"], "v0", {"v1": 4, "v2": 0xFFFFFF00},
        "arithmetic shift of a negative value keeps the sign")
    add("adjacent", "add_nc_u32_wrap", "v_add_nc_u32",
        ["v1", "v2"], "v0", {"v1": 0xFFFFFFFF, "v2": 2})
    add("adjacent", "sub_nc_u32_negative", "v_sub_nc_u32",
        ["v1", "v2"], "v0", {"v1": 1, "v2": 3},
        "1-3 wraps to 0xFFFFFFFE")
    add("adjacent", "subrev_nc_u32", "v_subrev_nc_u32",
        ["v1", "v2"], "v0", {"v1": 3, "v2": 1},
        "3-1 in the reversed form = src1-src0")
    add("adjacent", "and_or_b32", "v_and_or_b32",
        ["v1", "v2", "v3"], "v0", {"v1": 0xFF00FF00, "v2": 0x0FF00FF0,
                                   "v3": 0x0000000F})
    add("adjacent", "or3_b32", "v_or3_b32",
        ["v1", "v2", "v3"], "v0", {"v1": 0x1, "v2": 0x2, "v3": 0x4})
    add("adjacent", "add3_u32_carry", "v_add3_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 0xFFFFFFFF, "v2": 1, "v3": 1})
    add("adjacent", "bfe_u32_extract", "v_bfe_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 0xDEADBEEF, "v2": 8, "v3": 8})
    add("adjacent", "bfe_u32_width_zero", "v_bfe_u32",
        ["v1", "v2", "v3"], "v0", {"v1": 0xDEADBEEF, "v2": 8, "v3": 0},
        "width 0 yields 0")
    add("adjacent", "bfe_i32_sign_extend", "v_bfe_i32",
        ["v1", "v2", "v3"], "v0", {"v1": 0x0000FFFF, "v2": 0, "v3": 8},
        "the extracted field's top bit set -> sign-extended")
    add("adjacent", "bfi_b32", "v_bfi_b32",
        ["v1", "v2", "v3"], "v0", {"v1": 0x0000FFFF, "v2": 0xAAAAAAAA,
                                   "v3": 0x55555555})
    add("adjacent", "min_i32_signed", "v_min_i32",
        ["v1", "v2"], "v0", {"v1": 0xFFFFFFFF, "v2": 1},
        "signed min(-1, 1) = -1; an unsigned implementation gives 1")
    add("adjacent", "max_u32_unsigned", "v_max_u32",
        ["v1", "v2"], "v0", {"v1": 0xFFFFFFFF, "v2": 1})
    add("adjacent", "perm_b32_selector_mix", "v_perm_b32",
        ["v1", "v2", "v3"], "v0", {"v1": 0x04030201, "v2": 0x08070605,
                                   "v3": 0x00010203},
        "selectors 0,1,2,3 pull src0 bytes in order")
    add("adjacent", "perm_b32_constants", "v_perm_b32",
        ["v1", "v2", "v3"], "v0", {"v1": 0, "v2": 0, "v3": 0x08090A0B},
        "selectors 8,9,10,11 produce 0x00,0xFF,0x80,0x7F")

    # =====================================================================
    # FAMILY 6 -- v_cmp_* (VOPC, with a vcc destination) -- sanity that the
    # repair to the shared operand path did not disturb the 3-operand form
    # =====================================================================
    add("vopc", "gt_f32_true", "v_cmp_gt_f32",
        ["vcc_lo", "v1", "v2"], "vcc_lo", {"v1_f32": 2.0, "v2_f32": 1.0})
    add("vopc", "gt_f32_false", "v_cmp_gt_f32",
        ["vcc_lo", "v1", "v2"], "vcc_lo", {"v1_f32": 1.0, "v2_f32": 2.0})
    add("vopc", "eq_u32", "v_cmp_eq_u32",
        ["vcc_lo", "v1", "v2"], "vcc_lo", {"v1": 7, "v2": 7})
    add("vopc", "neq_f32_nan", "v_cmp_neq_f32",
        ["vcc_lo", "v1", "v2"], "vcc_lo", {"v1_f32": NAN, "v2_f32": 1.0})
    add("vopc", "ngt_f32_nan", "v_cmp_ngt_f32",
        ["vcc_lo", "v1", "v2"], "vcc_lo", {"v1_f32": NAN, "v2_f32": 1.0})

    return V


# ---------------------------------------------------------------------------
# STATE CONSTRUCTION
# ---------------------------------------------------------------------------
def make_state(setup, lanes=32, exec_mask=None):
    """Build a LaneState from a vector's `setup` dict.

    Keys ending in `_f32` place the f32 ENCODING of that value; `_f16` place the
    raw half in the low 16 bits; plain integer keys are written directly.
    Lane 0 gets the value and all other lanes get a DIFFERENT value, so a
    vector cannot pass by accident if the implementation only handles lane 0.
    """
    st = LaneState(lanes=lanes)
    for i in range(lanes):
        st.regs[i][0] = 0xDEADBEEF  # dst pre-loaded with junk
        st.regs[i][1] = 0x11111111
        st.regs[i][2] = 0x22222222
        st.regs[i][3] = 0x33333333
    for i in range(128):
        st.sgprs[i] = 0x44444444
    for k, v in setup.items():
        if k.endswith("_f32"):
            idx = int(k[1:-4])
            for i in range(lanes):
                st.regs[i][idx] = f32_bits(v if i == 0 else _perturb(v, i))
        elif k.endswith("_f16"):
            idx = int(k[1:-4])
            for i in range(lanes):
                st.regs[i][idx] = (v & 0xFFFF) if i == 0 else \
                    ((v + i) & 0xFFFF)
        else:
            idx = int(k[1:])
            for i in range(lanes):
                st.regs[i][idx] = u32(v) if i == 0 else u32(v + i)
    if exec_mask is not None:
        st.exec_lo = exec_mask
    return st


def _perturb(v, i):
    """A different value for lanes != 0, so per-lane bugs cannot hide."""
    try:
        if isinstance(v, float):
            if math.isnan(v) or math.isinf(v):
                return v
            return v + i
    except TypeError:
        pass
    return v


def all_ones(lanes=32):
    return (1 << lanes) - 1
