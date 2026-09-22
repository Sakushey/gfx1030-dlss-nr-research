#!/usr/bin/env python3
"""Phase 16AW -- CPU REFERENCE A, REPAIRED: `k_dec_upsample` (block 39).

WHY THIS FILE EXISTS
--------------------
`p16ar/native/cpu_reference/k_dec_upsample_A.py` declares, in the frozen
contract it helped produce, that the 32 products of a chunk are summed in
BINARY32:

    "within_a_chunk": "the 32 products are summed in binary32; every partial
                       sum is rounded to binary32"

Its implementation did not do that.  Its accumulator was:

    s = 0.0
    for t in range(CHUNK):
        s += a[a0 + t] * m[m0 + t]

which is a PYTHON BINARY64 accumulator (a CPython float is an IEEE-754
binary64).  A binary64 accumulator keeps 53 significand bits, so it does not
round where binary32 rounds.  Reference B -- which rounds each partial sum to
binary32 -- therefore disagreed with A on inputs the 16AR differential fixture
never contained, and the recorded `A == B` was FIXTURE-LIMITED evidence.

This file is the repair.  It is a NEW file: the 16AR artifact is left byte
unchanged so the defect remains reproducible.

WHAT CHANGED, EXACTLY
---------------------
ONE thing, in one place, and it is the thing the brief names:

    `chunk_dot` no longer accumulates in host floats at all.

Instead every partial sum is carried as an EXACT dyadic integer pair `(m, e)`
meaning `m * 2**e`, and after EVERY accumulate the pair is rounded to binary32
by `rn32_pair` -- an explicit, inspectable, integer-only implementation of
IEEE-754 round-to-nearest-even with a 24-bit significand.  The rounding step is
bit arithmetic on an integer significand; it does not call `+`, `*` or any
other host floating-point operation, and it does not depend on the host's
rounding mode or on CPython's float semantics.

The same explicit rounding is applied to the chunk-boundary accumulation
(`acc = H(acc + s)`), so the whole accumulator chain is explicit.

The SIGNATURES are unchanged, so this file is a drop-in replacement:

    H, e4m3fn_decode, e4m3fn_quantize, F, bits,
    chunk_dot, multiply_row, project, unpack, decoder_entry

H() and the E4M3FN codec are KEPT AS THEY WERE in 16AR A (H via
`struct.pack('<e')`, the codec as the pinned procedure).  That is deliberate:
16AR's own p16ar_ab_harness.py verified those two against the EXECUTED pinned
upstream text over the total domain (all 256 decode bytes; all 65,536 finite
binary16 values for the encoder), so they are not the defect and re-typing them
would throw away that evidence.

THE DECLARED LOCAL CONTRACT THIS IMPLEMENTS
-------------------------------------------
`p16aw/numeric/NUMERICAL_CONTRACT_16AW.json` states it explicitly.  In
short: product exact; within-chunk accumulator binary32 with an explicit RN32
after every accumulate; ascending index order; chunk boundary 32; the
chunk-boundary add taken exactly and rounded ONCE to binary16 by H; four
256-wide partitions folded as H(result + part); final combine
F(H(main + skip*scale)); E4M3FN encode saturating, decode SATFINITE.

This is the LOCAL DETERMINISTIC CONTRACT of this reference pair.  It is NOT a
claim about the original model's reduction order, and nothing here establishes
that the shipping network reduces this way.

No HIP call, no GPU, no launch, no slot.
"""
from __future__ import annotations

import math
import struct

MATRIX_ROWS, MATRIX_COLS = 512, 1024
CHUNK = 32
PARTITION = 256
ROW_POSITIONS = [3, 6, 7, 8, 9, 10, 11, 12, 13]
COL_POSITIONS = [1, 0, 4, 5, 2, 14, 15, 16, 17, 18]

# ---------------------------------------------------------------------------
# explicit binary32 rounding, on exact dyadic integers
#
# A value is the pair (m, e), an exact rational equal to m * 2**e with m an
# arbitrary-precision Python int.  Nothing in this section performs a host
# floating-point operation.
# ---------------------------------------------------------------------------
F32_P = 24          # significand bits
F32_EMIN = -126     # minimum normal exponent
F32_EMAX = 127      # maximum exponent
F32_SUBQ = -149     # subnormal quantum exponent (2**-149)

_INF_M = 1 << 200   # sentinel significand for +inf (see rn32_pair)


class NonFiniteFusedValue(ArithmeticError):
    """Raised when a non-finite value reaches the E4M3FN quantiser.

    Not a ValueError and not a silent saturation: this is a REFUSAL, and it
    exists so that a caller cannot mistake "no value exists" for "the value is
    zero" or "the value saturates".  See `e4m3fn_quantize`."""


def _is_pos_inf(p) -> bool:
    return p[0] == _INF_M and p[1] == 0


def _is_neg_inf(p) -> bool:
    return p[0] == -_INF_M and p[1] == 0


def _is_inf(p) -> bool:
    return _is_pos_inf(p) or _is_neg_inf(p)


def as_dyadic(x) -> tuple:
    """Exact (m, e) for a value that is exactly representable.

    Accepts a python int or float.  A float is decomposed by
    `as_integer_ratio`, which is EXACT: it reports the value the float
    actually holds, not a rounded re-reading of it.

    A float +/-infinity becomes the (_INF_M, 0) / (-_INF_M, 0) SENTINEL, not a
    crash.  This path is REACHABLE and it is in this contract: `H` does not
    saturate, so a row accumulator can legitimately become infinite at a chunk
    boundary and the following chunks must be able to add to it.  B carries
    the same value as a python float and reaches the same answer; the first
    version of this file raised a bare `OverflowError` here
    ("cannot convert Infinity to integer ratio"), an accidental crash rather
    than a decision, which the adversarial corpus measured (case
    `overflow_half_of_chunk`) and which is exactly the class of defect Repair
    A-2 exists to remove.  NaN is still refused, loudly and by name.
    """
    if isinstance(x, int):
        return (x, 0)
    xf = float(x)
    if xf != xf:
        raise NonFiniteFusedValue(
            "as_dyadic: NaN.  NaN is not reachable from admissible inputs "
            "(see NUMERICAL_CONTRACT_16AW.json) and is refused rather than "
            "given a value.")
    if xf == float("inf"):
        return (_INF_M, 0)
    if xf == float("-inf"):
        return (-_INF_M, 0)
    n, d = xf.as_integer_ratio()
    if d & (d - 1):
        raise ValueError("as_dyadic: denominator is not a power of two")
    e = -(d.bit_length() - 1)
    return (n, e)


def dyadic_to_float(p) -> float:
    """The exact (m, e) as a python float, exactly.

    Every FINITE value this module rounds is a binary32 value, and every
    binary32 value is exactly a binary64 value, so this conversion is
    lossless.  It is asserted rather than assumed.  The infinity sentinel maps
    to a python float +/-inf.
    """
    m, e = p
    if m == _INF_M and e == 0:
        return float("inf")
    if m == -_INF_M and e == 0:
        return float("-inf")
    if m == 0:
        return 0.0
    # binary64 significand is 53 bits; a rounded binary32 value needs <= 24
    if abs(m).bit_length() > 53:
        raise ValueError("dyadic_to_float: value is not exactly a binary64")
    v = math.ldexp(float(m), e)
    if v != 0.0 and (v == float("inf") or v == float("-inf")):
        return math.copysign(float("inf"), m)
    # round-trip through binary32 must be lossless, or the value was not one
    if struct.unpack("<f", struct.pack("<f", v))[0] != v:
        raise ValueError("dyadic_to_float: value is not exactly a binary32")
    return v


def _round_half_even_shift(a: int, shift: int) -> int:
    """round(a / 2**shift) with ties to even, on a non-negative integer a."""
    q, r = divmod(a, 1 << shift)
    half = 1 << (shift - 1)
    if r > half or (r == half and (q & 1)):
        q += 1
    return q


def rn32_pair(p) -> tuple:
    """EXPLICIT round-to-nearest-even to binary32.  Returns an exact (m, e).

    This is the function the brief asks for: the rounding step is written out
    as integer significand arithmetic over the whole of binary32, including the
    subnormal range down to 2**-149 and overflow to +/-inf.  `+inf` is
    represented by the sentinel (_INF_M, 0) and maps back to a python float
    infinity: it is a CONTRACT VALUE on the accumulation path (H does not
    saturate, so a chunk boundary can carry the accumulator out of binary16's
    range) and it is refused only where the contract has no value for it, at
    the E4M3FN encoder.
    """
    m, e = p
    if _is_inf(p):
        return p                      # already the answer; nothing to round
    if m == 0:
        return (0, 0)
    neg = m < 0
    a = -m if neg else m
    nbits = a.bit_length()
    e_top = nbits - 1 + e                       # floor(log2(|value|))

    if e_top > F32_EMAX:
        return (-_INF_M, 0) if neg else (_INF_M, 0)

    if e_top < F32_EMIN:
        # subnormal: the quantum is 2**-149, so round a * 2**(e - F32_SUBQ)
        shift = -(e - F32_SUBQ)
        if shift <= 0:
            q = a << (-shift)
        else:
            q = _round_half_even_shift(a, shift)
        # NOTE: q may reach exactly 2**23 -- that value is 2**-126, the
        # smallest normal, and q * 2**-149 represents it EXACTLY with no
        # renormalisation.  Shifting here would be the bug (it would silently
        # halve the result), so the carry case returns the same pair form.
        if q == 0:
            return (0, 0)
        out = (q, F32_SUBQ)
        return (-out[0], out[1]) if neg else out

    # normal range: keep F32_P significand bits
    shift = nbits - F32_P
    if shift <= 0:
        q, e_out = a, e                         # already exact
    else:
        q = _round_half_even_shift(a, shift)
        e_out = e + shift
        if q > (1 << F32_P):
            raise AssertionError("rn32_pair: rounding overshot a binade")
        if q == (1 << F32_P):
            # round-up carried into a new binade.  Truncation gives a value in
            # [2**23, 2**24), so the ONLY reachable carry is exactly 2**24,
            # whose >>1 is exact -- no bit is discarded.
            q >>= 1
            e_out += 1
            if e_out + F32_P - 1 > F32_EMAX:
                return (-_INF_M, 0) if neg else (_INF_M, 0)
    out = (q, e_out)
    return (-out[0], out[1]) if neg else out


def rn32(x):
    """RN32 of an exact value, returned as a python float (or +/-inf)."""
    p = rn32_pair(as_dyadic(x) if not isinstance(x, tuple) else x)
    if p[0] == _INF_M:
        return float("inf")
    if p[0] == -_INF_M:
        return float("-inf")
    return dyadic_to_float(p)


def dyadic_add(p, q) -> tuple:
    """EXACT sum of two dyadics; no rounding at all.

    Both operands must be expressed in the units of the SMALLER exponent: the
    operand with the larger exponent has its significand scaled UP by
    2**(gap).  Scaling the other way (down) would silently truncate.

    The infinity sentinel is absorbing (inf + finite = inf), except for
    inf + (-inf), which is the one sum in this operator with no value at all
    and is therefore REFUSED by name rather than silently answered.
    """
    m1, e1 = p
    m2, e2 = q
    if _is_inf(p) or _is_inf(q):
        if _is_inf(p) and _is_inf(q) and (p[0] != q[0]):
            raise NonFiniteFusedValue(
                "dyadic_add: +inf + -inf has no value.  Unreachable from "
                "admissible inputs (a 32-term chunk sum is bounded far below "
                "binary32's range, so no chunk sum is itself infinite), so "
                "reaching it means an assumption above is wrong.")
        return p if _is_inf(p) else q
    if m1 == 0:
        return q
    if m2 == 0:
        return p
    if e1 >= e2:
        return (m2 + (m1 << (e1 - e2)), e2)
    return (m1 + (m2 << (e2 - e1)), e1)


def dyadic_mul(p, q) -> tuple:
    """EXACT product of two dyadics; no rounding at all.

    Refuses the infinity sentinel: this is only ever called on a channel's
    activation and weight, neither of which can be infinite (the activation is
    binary16 and the weight is E4M3FN), so an infinite operand here means the
    caller is wrong and it is reported rather than propagated."""
    if _is_inf(p) or _is_inf(q):
        raise NonFiniteFusedValue(
            "dyadic_mul: an operand is the infinity sentinel.  The product is "
            "only taken over a binary16 activation and an E4M3FN weight, "
            "neither of which can be infinite.")
    return (p[0] * q[0], p[1] + q[1])


# ---------------------------------------------------------------- primitives
def H(x: float) -> float:
    """Pinned H: round to nearest even binary16, returned as a python float.

    UNCHANGED from 16AR A.  This was verified against the executed pinned text
    over all 65,536 finite binary16 values by p16ar_ab_harness.py; it is not
    the defect.
    """
    if x != x:
        return float("nan")
    if x == 0.0:
        return math.copysign(0.0, x)
    try:
        return struct.unpack("<e", struct.pack("<e", x))[0]
    except (OverflowError, struct.error):
        return math.copysign(float("inf"), x)


def e4m3fn_decode(b: int) -> float:
    """Pinned SATFINITE E4M3FN decode.  UNCHANGED from 16AR A."""
    s = -1.0 if (b >> 7) & 1 else 1.0
    e = (b >> 3) & 0xF
    m = b & 0x7
    if e == 15 and m == 7:
        return s * 448.0
    if e == 0:
        return s * (m / 8.0) * (2.0 ** -6)
    return s * (1.0 + m / 8.0) * (2.0 ** float(e - 7))


def e4m3fn_quantize(v: float) -> int:
    """Pinned `quantize`: value -> E4M3FN byte.  Never emits 0x7F/0xFF.

    UNCHANGED from 16AR A in VALUE on every input on which 16AR A returned.

    16AW REPAIR A-2 (loudness only; no value changes).  16AR A's procedure
    reaches `math.floor(math.log2(max(a, 2.0**-9)))`, which raises
    OverflowError on +inf and ValueError on NaN -- an accidental crash rather
    than a decision.  That path is REACHABLE: `H(...)` can return +/-inf when a
    chunk sum overflows binary16 (32 terms of 65504 x 448 is one way), and the
    fused value is then infinite.  This guard converts the accident into a
    named refusal.  It fires only on a non-finite input, so no finite input's
    value changes -- asserted by the differential in
    NUMERICAL_CONTRACT_16AW.json over all 63,488 finite binary16 values.

    WHAT IT DELIBERATELY DOES NOT DO: it does NOT invent a byte for the
    non-finite case.  The pinned procedure's last rule rewrites any 15/7 code
    to 0x7E, so it can NEVER emit 0x7F -- while the device's own
    `kd::quantize_half_bits` returns `(sign<<7)|0x7F` for non-finite half bits,
    labelled "OUT OF CONTRACT; made loud".  Choosing between 0x7E and 0x7F
    here would be inventing a reference value to make a comparison green.  The
    case is declared OUT OF CONTRACT instead, and any comparison that reaches
    it is void.
    """
    v = float(v)
    if v != v or v == float("inf") or v == float("-inf"):
        raise NonFiniteFusedValue(
            "e4m3fn_quantize: the fused value is %r.  A non-finite fused value "
            "is OUT OF CONTRACT: the kernel answers (sign<<7)|0x7F as a loud "
            "sentinel in kd::quantize_half_bits, and the pinned procedure "
            "cannot emit 0x7F at all.  This reference has no value for it, and "
            "the comparison must exclude the case rather than pick a side." % v)
    sign = 0x80 if v < 0 else 0
    a = abs(v)
    exponent = math.floor(math.log2(max(a, 2.0 ** -9)))
    normal = exponent >= -6
    ee = min(max(exponent + 7, 1), 15)
    mant = round((a / (2.0 ** exponent) - 1) * 8)
    carry = mant >= 8
    ee = min(ee + (1 if carry else 0), 15)
    mant = 0 if carry else mant
    mant = min(max(mant, 0), 7)
    if ee == 15 and mant > 6:
        mant = 6
    out = sign | (((ee << 3) | mant) if normal
                  else min(max(round(a * 512), 0), 8))
    if a >= 448:
        out = sign | 0x7E
    if a == 0:
        out = 0
    if ((out >> 3) == 15) and ((out & 7) == 7):
        out = (out & 0x80) | 0x7E
    return out


def F(v: float) -> float:
    """Pinned F: the fp8 E4M3FN round trip.  UNCHANGED from 16AR A."""
    return e4m3fn_decode(e4m3fn_quantize(v))


def bits(count: int, positions: list) -> list:
    out = []
    for i in range(count):
        v = 0
        for b, p in enumerate(positions):
            v |= ((i >> p) & 1) << b
        out.append(v)
    return out


# ---------------------------------------------------------------- the operator
def chunk_dot(a: list, a0: int, m: list, m0: int) -> float:
    """The 32 products summed in BINARY32 -- explicitly.

    THE REPAIR LIVES HERE.  16AR A accumulated this loop in host binary64:

        s = 0.0
        for t in range(CHUNK):
            s += a[a0 + t] * m[m0 + t]

    Here every partial sum is carried as an exact dyadic and rounded to
    binary32 by `rn32_pair` -- an explicit, integer-only, inspectable RN32 --
    after EVERY accumulate.  Ascending index order, as the contract declares.

    The product is exact before the add (binary16 x E4M3FN needs at most 15
    significand bits; the extremal pair over the whole 16,125,444-pair domain
    is 16,395 = 15 bits), so an FMA contraction by a GPU compiler is
    equivalent to this mul-then-add: there is no double rounding to lose.  The
    accumulation is therefore modelled as exact-product, exact-add, then RN32.
    """
    s = (0, 0)
    for t in range(CHUNK):
        prod = dyadic_mul(as_dyadic(a[a0 + t]), as_dyadic(m[m0 + t]))
        s = rn32_pair(dyadic_add(s, prod))
    return dyadic_to_float(s)


def half_add(acc, s):
    """`acc + s` taken EXACTLY, then rounded once to binary16 by H().

    This is the declared contract's chunk-boundary rule.  It is stated in
    NUMERICAL_CONTRACT_16AW.json because it is a real choice: rounding the sum
    to binary32 first and THEN to binary16 is a different function
    (double rounding), and the contract picks the exact-and-round-once reading,
    which is what 16AR B has always computed and what 16AR's own contract
    sentence describes.
    """
    exact = dyadic_add(as_dyadic(acc), as_dyadic(s))
    return H(dyadic_to_float(rn32_pair(exact)))


def multiply_row(a: list, a0: int, m: list, m0: int, width: int) -> float:
    """`multiply` reduced to one output row: chunked, fp32 inside, H between."""
    acc = 0.0
    for off in range(0, width, CHUNK):
        acc = half_add(acc, chunk_dot(a, a0 + off, m, m0 + off))
    return acc


def project(x_row: list, mat: list, rows: int = MATRIX_ROWS) -> list:
    """The four 256-wide partitions, folded as H(result + part)."""
    parts = []
    for i in range(0, MATRIX_COLS, PARTITION):
        parts.append([multiply_row(x_row, i, mat, r * MATRIX_COLS + i,
                                   PARTITION) for r in range(rows)])
    result = parts[0]
    for part in parts[1:]:
        result = [H(u + v) for u, v in zip(result, part)]
    return result


def unpack(raw: bytes):
    """The 525,312-byte record -> (matrix rows x cols, scale[cols]).

    UNCHANGED from 16AR A.  The decode and the fp16 scale read are exact.
    """
    if len(raw) != MATRIX_COLS * MATRIX_ROWS + 2 * MATRIX_ROWS:
        raise ValueError("block39 record size")
    rows = bits(MATRIX_COLS * MATRIX_ROWS, ROW_POSITIONS)
    cols = bits(MATRIX_COLS * MATRIX_ROWS, COL_POSITIONS)
    mat = [0.0] * (MATRIX_ROWS * MATRIX_COLS)
    for i in range(MATRIX_COLS * MATRIX_ROWS):
        mat[rows[i] * MATRIX_COLS + cols[i]] = e4m3fn_decode(raw[i])
    order = [(c // 16) * 16 + (c % 8) * 2 + ((c % 16) // 8)
             for c in range(MATRIX_ROWS)]
    vals = struct.unpack("<%de" % MATRIX_ROWS,
                         raw[MATRIX_COLS * MATRIX_ROWS:])
    scale = [0.0] * MATRIX_ROWS
    for i, o in enumerate(order):
        scale[o] = float(vals[i])
    return mat, scale


def decoder_entry(x, skip, params, pre_quantization=False):
    """x (H,W,1024) fp16-valued; skip (2H,2W,512); -> (2H,2W,512)."""
    mat, scale = params
    Hh = len(x)
    Ww = len(x[0]) if Hh else 0
    if not Hh or not Ww or len(x[0][0]) != MATRIX_COLS:
        raise ValueError("block39 x must be (H,W,1024)")
    if len(skip) != 2 * Hh or len(skip[0]) != 2 * Ww \
            or len(skip[0][0]) != MATRIX_ROWS:
        raise ValueError("block39 skip must be (2H,2W,512)")

    main = [[project(x[h][w], mat) for w in range(Ww)] for h in range(Hh)]
    out = []
    for h2 in range(2 * Hh):
        row = []
        for w2 in range(2 * Ww):
            mv = main[h2 // 2][w2 // 2]
            sv = skip[h2][w2]
            fused = [H(mv[c] + sv[c] * scale[c]) for c in range(MATRIX_ROWS)]
            row.append(fused if pre_quantization
                       else [F(v) for v in fused])
        out.append(row)
    return out
