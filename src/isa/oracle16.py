#!/usr/bin/env python3
"""phase16s/isa/oracle16.py -- INDEPENDENT reference model (Phase 16S item S1).

WHAT THIS IS
------------
A from-scratch implementation of the sixteen J3 mnemonics that Phase 16R/R11
reported as `J3_INSTRUCTION_SEMANTICS_BLOCKED` with reason
`NO_INDEPENDENT_ORACLE_VECTOR_FOR_THIS_MNEMONIC`:

    s_mov_b64                     v_lshlrev_b16
    v_add_co_u32                  v_lshrrev_b16
    v_add_co_ci_u32_e64           v_min_u32_e32
    v_cmp_gt_i32_e64              v_mul_lo_u16
    v_cmp_gt_u32_e64              v_mul_u32_u24_e32
    v_cmp_lt_i32_e64              v_pack_b32_f16
    v_cvt_f16_f32_e32             v_sub_nc_u16
    v_fma_mixlo_f16
    v_fma_mixhi_f16

INDEPENDENCE
------------
This module imports NOTHING.  No emulator module, no in-tree oracle, no
`struct`, no `math`.  Every value here is integer arithmetic written longhand
from the architectural definitions in `phase16r/isa/ref/rdna2_isa.txt`
(sha256 46fdab001a4de548375ba1147213afaf14e86524a5ce137720e1f640d1108950).

In particular the FP16 results are produced by hand-written IEEE-754
round-to-nearest-even over Python integers (`_round_to_f16`, `f16_fma`), not
by Python's native float arithmetic, which is not an acceptable sole source of
an expected binary16 result.

Its input is raw 32-bit register contents and the printed operand tokens; its
output is the expected architectural result.  It has never been run against
the emulator, and the emulator's output is never an input to it.

READING THE ISA TEXT
--------------------
Where the document is silent, the choice made here is labelled `DECLARED` in a
docstring and mirrored in the artifact's OPEN SEMANTICS list.  No silent
reading is presented as fact.  Where the document contradicts itself the
contradiction is recorded instead of resolved by preference.
"""

U32 = 0xFFFFFFFF
U64 = 0xFFFFFFFFFFFFFFFF
M16 = 0xFFFF
M24 = 0xFFFFFF

#: Negative control A (see the artifact's `negative_controls`): when a name is
#: in here the corresponding oracle drops a mask on purpose, so the comparison
#: MUST start failing.  A control that cannot be made to fail proves nothing.
BREAK = set()


def s32(x):
    """Bit pattern -> signed 32-bit value, written out rather than inferred.

    The signed compares must convert explicitly; `0x80000000 < 0x00000001`
    is the whole point of the vector that carries this trap.
    """
    x &= U32
    return x - 0x100000000 if (x & 0x80000000) else x


# ---------------------------------------------------------------------------
# 1. s_mov_b64 -- ISA rdna2_isa.txt:5781-5785 (opcode 4, SOP1)
# ---------------------------------------------------------------------------
def s_mov_b64(src64):
    """S_MOV_B64  D.u64 = S0.u64.

    The document prints the block as

        3       S_MOV_B32
                                 Move data to an SGPR.
        4       S_MOV_B64
                                      D.u = S0.u.
        5       S_CMOV_B32       Move data to an SGPR.
        6       S_CMOV_B64            D.u64 = S0.u64.

    because the two-column page was extracted in column order.  Read as pairs,
    S_MOV_B64 is opcode 4 and the expression belonging to it is the 64-bit one:
    `D.u64 = S0.u64`.  The 32-bit `D.u = S0.u.` belongs to S_MOV_B32 (opcode 3)
    and the `D.u64 = S0.u64.` printed under S_CMOV_B64 is the CMOV body.
    """
    return src64 & U64


# ---------------------------------------------------------------------------
# 2. v_add_co_u32 / v_add_co_ci_u32
# ---------------------------------------------------------------------------
def v_add_co_u32(a, b):
    """V_ADD_CO_U32 -- rdna2_isa.txt:10190-10195 (VOP3B)

        D.u32 = S0.u32 + S1.u32;
        VCC = S0.u + S1.u >= 0x100000000ULL ? 1 : 0.

    Returns (dst_u32, carry_bit).
    """
    a &= U32
    b &= U32
    t = a + b
    return (t & U32, 1 if t >= 0x100000000 else 0)


def v_add_co_ci_u32(a, b, cin):
    """V_ADD_CO_CI_U32 -- rdna2_isa.txt:7275-7284 (VOP2 opcode 40)

        D.u32 = S0.u32 + S1.u32 + VCC;
        VCC = S0.u32 + S1.u32 + VCC >= 0x100000000ULL ? 1 : 0.

    `cin` is the carry-in BIT for this lane.  In the VOP3 form the document
    says the carry-in "comes from the SGPR-pair at S2.u" (line 7281); the
    printed J3 sites pass either `vcc_lo` (bit `lane` of VCC) or an `sN`
    (bit `lane` of that SGPR).  Both are modelled as "the lane's bit of the
    named register".  Returns (dst_u32, carry_bit).
    """
    a &= U32
    b &= U32
    cin &= 1
    t = a + b + cin
    return (t & U32, 1 if t >= 0x100000000 else 0)


def lane_bit(reg32, lane):
    """The carry-in/carry-out bit for one lane of a 32-bit mask register."""
    return (reg32 >> lane) & 1


def mask_from_lanes(bits, exec_mask):
    """Assemble a lane mask: bit i set where EXEC[i] and bits[i].

    EXEC masking is architectural (`3.3 EXECute Mask`, the per-lane write is
    qualified by EXEC).  DECLARED: the value the register takes in lanes where
    EXEC is clear is not stated by the document for these mask writes; the
    reading used here is "those bits are written 0".  The alternative reading
    ("inactive lanes keep their previous bit") is recorded as an alternate
    reading on the EXEC-masked vectors, so the measurement says which one the
    emulator implements instead of the oracle assuming it.
    """
    out = 0
    for i in range(32):
        if (exec_mask >> i) & 1:
            if (bits >> i) & 1:
                out |= 1 << i
    return out & U32


# ---------------------------------------------------------------------------
# 3. the integer compares -- rdna2_isa.txt:8682-8707 (VOPC, VOP3 form)
# ---------------------------------------------------------------------------
# The document prints the opcode column and the description column separately
# and one line apart; read as a block, opcodes 128..135 (I32) and 192..199
# (U32) carry exactly
#     128 V_CMP_F_I32    D[threadId] = 0.
#     129 V_CMP_LT_I32   D[threadId] = (S0 < S1).
#     130 V_CMP_EQ_I32   D[threadId] = (S0 == S1).
#     131 V_CMP_LE_I32   D[threadId] = (S0 <= S1).
#     132 V_CMP_GT_I32   D[threadId] = (S0 > S1).
#     133 V_CMP_NE_I32   D[threadId] = (S0 <> S1).
#     134 V_CMP_GE_I32   D[threadId] = (S0 >= S1).
#     135 V_CMP_T_I32    D[threadId] = 1.
#     196 V_CMP_GT_U32   D[threadId] = (S0 > S1).      (line 8967)
# `// D = VCC in VOPC encoding.` -- the e64 form writes the named SGPR instead.
def v_cmp_gt_i32(a, b):
    return 1 if s32(a) > s32(b) else 0


def v_cmp_gt_u32(a, b):
    return 1 if (a & U32) > (b & U32) else 0


def v_cmp_lt_i32(a, b):
    return 1 if s32(a) < s32(b) else 0


# ---------------------------------------------------------------------------
# 4. 16-bit integer ALU
# ---------------------------------------------------------------------------
def v_lshlrev_b16(a, b):
    """V_LSHLREV_B16 -- rdna2_isa.txt:10224-10226 (VOP3A opcode 788)

        D.u[15:0] = S1.u[15:0] << S0.u[3:0].

    REVERSED: the shift count is the FIRST source, the shifted value is the
    second.  Only the low 4 bits of the count are used (`S0.u[3:0]`).
    """
    if "lshlrev_b16" in BREAK:
        return ((a & M16) << (b & 15)) & M16     # deliberate control: swapped
    return ((b & M16) << (a & 15)) & M16


def v_lshrrev_b16(a, b):
    """V_LSHRREV_B16 -- rdna2_isa.txt:10150-10151 (VOP3A opcode 775)

        D.u16 = S0.u16 * S1.u16.
                             Logical shift right, count is in the first
                             operand.

    THE DOCUMENT'S EXPRESSION LINE FOR THIS MNEMONIC IS WRONG: it prints a
    MULTIPLY.  The caption on the next line is the shift-right caption, and the
    sibling V_ASHRREV_I16 (:10153) prints `D.u[15:0] = S1.u[15:0] >> S0.u[3:0]`
    and the sibling V_LSHLREV_B16 (:10226) prints
    `D.u[15:0] = S1.u[15:0] << S0.u[3:0]`.  The reading used here is the one
    the two siblings and the caption agree on:

        D.u[15:0] = S1.u[15:0] >> S0.u[3:0].
    """
    return ((b & M16) >> (a & 15)) & M16


def v_min_u32(a, b):
    """V_MIN_U32 -- rdna2_isa.txt:7224-7226 (VOP2 opcode 19)

        D.u32 = (S0.u32 < S1.u32 ? S0.u32 : S1.u32).

    The comparison is UNSIGNED.  (rdna2_isa.txt:9635 gives the three-input
    V_MIN3_U32 as V_MIN_U32(V_MIN_U32(S0.u,S1.u),S2.u) over the same
    unsigned predicate.)
    """
    a &= U32
    b &= U32
    return a if a < b else b


def v_mul_lo_u16(a, b):
    """V_MUL_LO_U16 -- rdna2_isa.txt:10147

        "Multiply two unsigned shorts."

    D.u16 = S0.u16 * S1.u16, low 16 bits (the destination is 16 bits wide, so
    the product is truncated to 16).
    """
    if "mul_lo_u16" in BREAK:
        return (a & U32) * (b & U32)        # deliberate control: mask dropped
    return ((a & M16) * (b & M16)) & M16


def v_mul_u32_u24(a, b):
    """V_MUL_U32_U24 -- rdna2_isa.txt:7129-7139 (VOP2 opcode 11)

        D.u32 = S0.u24 * S1.u24.

    Only the LOW 24 BITS of each source take part; the 48-bit product is
    truncated to the 32-bit destination.
    """
    return ((a & M24) * (b & M24)) & U32


def v_sub_nc_u16(a, b):
    """V_SUB_NC_U16 -- rdna2_isa.txt:10139-10145 (VOP3A opcode 772)

    The block prints BOTH expressions:

        772     V_SUB_NC_U16         D.u16 = S0.u16 + S1.u16.

                        Subtract the second unsigned short from the first. ...

                                       D.u16 = S0.u16 - S1.u16.

    The caption says subtract and the mnemonic says SUB; the `+` on the first
    line is the copy of V_ADD_NC_U16's body that sits immediately above it
    (:10134) and belongs to that opcode.  The reading used here is the
    subtraction.  (V_ADD_NC_U16's own text at :10134 prints
    `D.u64 = signext(S1.u64) >> S0.u[5:0].`, which is V_ASHRREV_I32's body --
    the whole block's expression lines are offset by one entry.  Recorded, not
    resolved by preference.)

    DECLARED: "Supports saturation (unsigned 16-bit integer domain)" -- the
    CLAMP modifier.  No vector sets CLAMP, so the unclamped reading (mod 2^16,
    i.e. borrow wraps) is used.
    """
    return ((a & M16) - (b & M16)) & M16


def v_pack_b32_f16(a, b):
    """V_PACK_B32_F16 -- rdna2_isa.txt:10207-10210 (VOP3A opcode 785)

        D[31:16].f16 = S1.f16;
        D[15:0].f16  = S0.f16.

    The SECOND source goes to the HIGH half and the FIRST source to the LOW
    half.  It is a bit-copy of the low 16 bits of each source; no conversion
    is performed.
    """
    return ((b & M16) << 16) | (a & M16)


# ---------------------------------------------------------------------------
# 5. FP16: decode / round / fused multiply-add, all in integer arithmetic
# ---------------------------------------------------------------------------
def _f32_parts(bits):
    """(kind, sign, significand, exp2) with value = (-1)^sign * sig * 2^exp2."""
    bits &= U32
    sign = (bits >> 31) & 1
    e = (bits >> 23) & 0xFF
    m = bits & 0x7FFFFF
    if e == 0xFF:
        return ("nan" if m else "inf", sign, m, 0)
    if e == 0:
        return ("zero" if m == 0 else "num", sign, m, -149)
    return ("num", sign, 0x800000 + m, e - 150)


def _f16_parts(bits):
    """(kind, sign, significand, exp2) with value = (-1)^sign * sig * 2^exp2."""
    bits &= M16
    sign = (bits >> 15) & 1
    e = (bits >> 10) & 0x1F
    m = bits & 0x3FF
    if e == 0x1F:
        return ("nan" if m else "inf", sign, m, 0)
    if e == 0:
        return ("zero" if m == 0 else "num", sign, m, -24)
    return ("num", sign, 1024 + m, e - 25)


def _round_to_f16(sign, sig, exp2):
    """Round the exact positive value `sig * 2**exp2` to binary16, RNE.

    Hand-written, integer only.  `sig` is a positive Python int (arbitrary
    precision, so the exact product of two 11-bit significands and the exact
    alignment shift are both representable with no loss).  Ties go to the
    candidate with an even significand LSB, which is round-to-nearest-even.
    Overflow past the largest finite (65504) produces an infinity, including
    the exact tie at 65520 where the even candidate is infinity.
    """
    if sig <= 0:
        raise ValueError("sig must be positive")
    ub = (sig.bit_length() - 1) + exp2          # floor(log2(value))
    q = ub - 10 if ub >= -14 else -24           # result quantum exponent
    k = q - exp2
    if k <= 0:
        r = sig << (-k)
    else:
        r = sig >> k
        rem = sig & ((1 << k) - 1)
        half = 1 << (k - 1)
        if rem > half or (rem == half and (r & 1)):
            r += 1
    if ub >= -14:
        if r == 2048:                           # rounded up into the next binade
            ub += 1
            r = 1024
        if ub > 15:
            return (sign << 15) | 0x7C00        # overflow -> infinity
        return (sign << 15) | ((ub + 15) << 10) | (r - 1024)
    if r == 1024:                               # rounded up to the smallest normal
        return (sign << 15) | (1 << 10)
    return (sign << 15) | r


#: DECLARED: the quiet NaN this oracle produces for a NaN input.
#: The ISA text for V_CVT_F16_F32 (:7571-7577) says nothing about NaN: it gives
#: `D.f16 = flt32_to_flt16(S0.f)` and states accuracy and denormal behaviour
#: only.  NaN payload/sign propagation is therefore an OPEN question, and this
#: constant is the declared reading (IEEE 754 default quiet NaN, sign cleared).
#: The alternative readings -- 0xFE00 (sign preserved) and a payload-preserving
#: conversion -- are recorded on the NaN vectors so the measurement reports
#: which one the emulator's handler produces rather than assuming it.
QNAN_F16 = 0x7E00


def f16_from_f32(bits32):
    """V_CVT_F16_F32 -- rdna2_isa.txt:7571-7577 (VOP1 opcode 10)

        Convert from a single-precision float to an FP16 float. 0.5ULP
        accuracy, supports input modifiers and creates FP16 denormals when
        appropriate.
        D.f16 = flt32_to_flt16(S0.f).

    Round-to-nearest-even, subnormals created (the text says so explicitly),
    overflow to infinity.  Only the low 16 bits of the destination carry the
    result; how bits [31:16] of the destination are affected is NOT stated by
    the document and the declared reading is zero-extension (see
    `cvt_dst`).
    """
    kind, sign, sig, exp2 = _f32_parts(bits32)
    if kind == "nan":
        return QNAN_F16
    if kind == "inf":
        return (sign << 15) | 0x7C00
    if kind == "zero":
        return sign << 15
    return _round_to_f16(sign, sig, exp2)


def cvt_f16_dst(bits32, dst_old, extend="zero"):
    """The 32-bit destination of V_CVT_F16_F32.

    DECLARED (OPEN): the document says `D.f16 = ...`, a 16-bit destination.
    It does not say what happens to D[31:16].  Two readings are admissible:
    zero-extension (`D.u32 = f16`) and preservation of the old D[31:16].
    `extend="zero"` is the declared reading, `extend="preserve"` the
    alternative; both are computed so the measurement can say which was
    implemented.
    """
    r = f16_from_f32(bits32)
    if extend == "preserve":
        return (dst_old & 0xFFFF0000) | r
    return r


def f16_fma(a, b, c):
    """V_FMA_MIXLO_F16 / V_FMA_MIXHI_F16 -- rdna2_isa.txt:9355-9374

    33      V_FMA_MIXLO_F16
                 Fused-multiply-add of FP16 values with MIX encoding, result
                 stored in low 16 bits of destination. ...
                      D.f[15:0] = S0.f * S1.f + S2.f.
    34      V_FMA_MIXHI_F16
                 ... result stored in HIGH 16 bits of destination. ...
                      D.f[31:16] = S0.f * S1.f + S2.f.

    FUSED: one rounding, exactly as the word says.  The product is exact in
    arbitrary-precision integers here (11x11 significand bits), the addend is
    aligned exactly, and the single rounding to binary16 happens once at the
    end -- so a vector that separates a fused reading from a
    multiply-round-then-add reading is available (see `fma_double_rounding`).

    NaN/Inf: the ISA text gives the arithmetic expression only.  DECLARED
    readings, all recorded as OPEN: NaN input -> QNAN_F16; Inf*0 -> QNAN_F16;
    Inf + (-Inf) -> QNAN_F16; the sign of an exact zero sum is +0 unless both
    addends are -0.
    """
    ka, sa, siga, ea = _f16_parts(a)
    kb, sb, sigb, eb = _f16_parts(b)
    kc, sc, sigc, ec = _f16_parts(c)
    if ka == "nan" or kb == "nan" or kc == "nan":
        return QNAN_F16
    if (ka == "inf" and kb == "zero") or (ka == "zero" and kb == "inf"):
        return QNAN_F16                      # 0 * Inf, IEEE 754 invalid
    psign = sa ^ sb
    if ka == "inf" or kb == "inf":
        if kc == "inf" and sc != psign:
            return QNAN_F16                  # Inf + (-Inf)
        return (psign << 15) | 0x7C00
    if kc == "inf":
        return (sc << 15) | 0x7C00
    psig, pexp = (siga * sigb, ea + eb) if (ka != "zero" and kb != "zero") else (0, 0)
    csig, cexp = (sigc, ec) if kc != "zero" else (0, 0)
    if psig == 0 and csig == 0:
        # IEEE 754: the sum of two zeros is +0 unless both are -0.
        both_neg = (psign == 1 and kc == "zero" and sc == 1)
        return (0x8000 if both_neg else 0x0000)
    exps = [e for (s, e) in ((psig, pexp), (csig, cexp)) if s]
    e = min(exps)
    n = 0
    if psig:
        n += (psig << (pexp - e)) if psign == 0 else -(psig << (pexp - e))
    if csig:
        n += (csig << (cexp - e)) if sc == 0 else -(csig << (cexp - e))
    if n == 0:
        return 0x0000                        # exact cancellation -> +0, RNE
    return _round_to_f16(1 if n < 0 else 0, abs(n), e)


def f16_mul(a, b):
    """Exact f16 multiply with ONE rounding to f16 (for the fused-vs-double
    comparison only; it is an alternate reading, never used as an expectation
    for the FMA mnemonics)."""
    ka, sa, siga, ea = _f16_parts(a)
    kb, sb, sigb, eb = _f16_parts(b)
    if ka == "nan" or kb == "nan":
        return QNAN_F16
    if (ka == "inf" and kb == "zero") or (ka == "zero" and kb == "inf"):
        return QNAN_F16
    psign = sa ^ sb
    if ka == "inf" or kb == "inf":
        return (psign << 15) | 0x7C00
    if ka == "zero" or kb == "zero":
        return psign << 15
    return _round_to_f16(psign, siga * sigb, ea + eb)


def f16_add(a, b):
    """Exact f16 add with ONE rounding to f16 (alternate reading only)."""
    ka, sa, siga, ea = _f16_parts(a)
    kb, sb, sigb, eb = _f16_parts(b)
    if ka == "nan" or kb == "nan":
        return QNAN_F16
    if ka == "inf" and kb == "inf":
        return QNAN_F16 if sa != sb else ((sa << 15) | 0x7C00)
    if ka == "inf":
        return (sa << 15) | 0x7C00
    if kb == "inf":
        return (sb << 15) | 0x7C00
    if ka == "zero" and kb == "zero":
        return (0x8000 if (sa == 1 and sb == 1) else 0x0000)
    if ka == "zero":
        return b & M16                      # the addend alone (its own bits)
    if kb == "zero":
        return a & M16                      # the augend alone (its own bits)
    e = min(ea, eb)
    n = (siga << (ea - e)) * (1 if sa == 0 else -1) \
        + (sigb << (eb - e)) * (1 if sb == 0 else -1)
    if n == 0:
        return 0x0000
    return _round_to_f16(1 if n < 0 else 0, abs(n), e)


def fma_double_rounding(a, b, c):
    """The rejected reading: round(round(a*b) + c), i.e. two roundings.

    Present only so a vector can be shown to separate it from the fused
    reading; it is NOT the expectation for any vector.
    """
    return f16_add(f16_mul(a, b), c)


# ---------------------------------------------------------------------------
# 6. destination composition for the 16-bit-result instructions
# ---------------------------------------------------------------------------
def dst16_lo(dst_old, r16, extend="preserve"):
    """Destination of a `D.u[15:0] = ...` instruction.

    DECLARED (OPEN): the document prints the result into bits [15:0] of a
    32-bit VGPR and does not say what bits [31:16] become.  V_MAD_U16
    (:10244-10248) states the convention for itself explicitly -- "Result is
    written to 16 LSBs of destination VGPR and hi 16 bits are preserved" --
    which is where the declared reading of "preserved" comes from; it is an
    inference from a sibling instruction, not a statement about these ones.
    `extend="zero"` is the alternative reading.
    """
    if extend == "zero":
        return r16 & U32
    return ((dst_old & 0xFFFF0000) | (r16 & M16)) & U32


def dst16_hi(dst_old, r16, extend="preserve"):
    """Destination of a `D.f[31:16] = ...` instruction (V_FMA_MIXHI_F16)."""
    if extend == "zero":
        return (r16 & M16) << 16
    return ((dst_old & 0x0000FFFF) | ((r16 & M16) << 16)) & U32
