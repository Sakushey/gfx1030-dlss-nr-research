#!/usr/bin/env python3
"""Phase 16AW -- CPU REFERENCE B, REPAIRED: `k_dec_upsample` (block 39).

WHY THIS FILE EXISTS
--------------------
`p16ar/native/cpu_reference/k_dec_upsample_B.py` is the independently
structured exact-rational oracle.  It is CORRECT on the defect the audit found:
it really does round every partial sum to binary32 (`s = _f32(s + ...)`), and
it is the reason the audit's cancellation counterexample is visible at all.

It has a DIFFERENT, independently measured defect, found while building the
16AW adversarial corpus (brief section 34, the "saturation" case):

    B.H(32 * 65504 * 448)               -> ValueError
    B.H(2 * 65504)                      -> ValueError
    B.H(70000)                          -> ValueError
    B._f32(Q(10) ** 40)                 -> ValueError
    ValueError: Invalid literal for Fraction: 'inf'

`round_binary` handles overflow by returning `Q("inf")` -- a Fraction built
from the STRING "inf".  CPython's `fractions.Fraction` rejects that literal, so
the construction raises instead of returning a value.  Reference A returns
`inf` for the same inputs.  The trigger is admissible and reachable inside this
operator: a chunk can hold 32 terms of |activation| <= 65504 (the largest
finite binary16) times |weight| <= 448 (the largest finite E4M3FN), so a chunk
sum can exceed 65504 and `H` is then asked to round an overflowing value.

B could not evaluate the saturation cases of the required corpus, so B needed
changing, and this file is that change.

WHAT CHANGED, EXACTLY
---------------------
THREE changes, all in the same subject -- overflow -- plus the exception type
that names the result.  Nothing else.

    (1) overflow now returns a python float +/-inf instead of `Q("inf")`:
            if e > e_max:  return _NEG_INF if neg else _POS_INF
        (2 occurrences: the initial `e > e_max` test and the carry-up test.)
    (2) `round_binary` now passes a float +/-inf straight through, so an
        already-overflowed accumulator can be re-rounded on the next chunk
        (`multiply_row` does `acc = H(acc + chunk_dot(...))`, and once `acc`
        is inf the next `H` sees a float).
    (3) `e4m3fn_encode` REFUSES a non-finite value with `NonFiniteFusedValue`
        instead of silently taking the >= 448 saturation branch.  This is a
        deliberate refusal, not a value: the device's `kd::quantize_half_bits`
        answers `(sign<<7)|0x7F` for non-finite half bits ("OUT OF CONTRACT;
        made loud"), and the pinned procedure cannot emit 0x7F at all, so
        publishing 0x7E here would be a silent disagreement with the kernel on
        a case where no reference value exists.  A refuses the same input with
        the same reasoning, so the two references agree on the case by AGREEING
        TO REFUSE IT.

Note what is NOT changed: the exact-rational mechanism, `_round_half_even`,
`_floor_log2`, the binary16/binary32 parameters, the E4M3FN encoder's
nearest-representable search, the decoder, `chunk_dot`'s per-step `_f32`, and
every shape constant.  B still computes the same function on every input it
could already compute -- the diff is confined to a path that previously raised.
This is asserted, not asserted-by-hope: the 16AW harness re-runs B_16AR against
B_independent over a differential corpus and requires value-for-value identity
on every case where B_16AR returns rather than raises, and it counts those
cases out loud.

INDEPENDENCE (brief section 33) -- THIS FILE IMPORTS NOTHING FROM A
------------------------------------------------------------------
B_independent.py imports `fractions` and `struct` and NOTHING else.  In
particular it does NOT import `k_dec_upsample_A_rn32` or `k_dec_upsample_A`,
and it does not use A's accumulator helper, A's FP8 decode helper, or A's
conversion pipeline.  The functions that would have destroyed independence, by
name, are:

    k_dec_upsample_A_rn32.rn32_pair      A's explicit binary32 rounding
    k_dec_upsample_A_rn32.rn32           A's float-returning wrapper
    k_dec_upsample_A_rn32.dyadic_add     A's exact add
    k_dec_upsample_A_rn32.dyadic_mul     A's exact multiply
    k_dec_upsample_A_rn32.half_add       A's chunk-boundary rule
    k_dec_upsample_A_rn32.e4m3fn_decode  A's SATFINITE decode
    k_dec_upsample_A_rn32.e4m3fn_quantize / .F   A's conversion pipeline
    k_dec_upsample_A_rn32.H              A's struct.pack('<e') half rounding

B rounds by a different mechanism (exact rational divided by an exact quantum,
integer round-half-to-even) and encodes E4M3FN by a different mechanism
(nearest-representable search over the format's ordered value set).  The 16AW
harness verifies this by AST inspection AND by a control: it builds a variant
of this file that DOES import A's `rn32` and requires the independence check to
reject it.

THE DECLARED LOCAL CONTRACT
---------------------------
Same as `k_dec_upsample_A_rn32.py`: `p16aw/numeric/NUMERICAL_CONTRACT_16AW.json`.
This is the LOCAL DETERMINISTIC CONTRACT of this reference pair, not a claim
about the original model's reduction semantics.

No HIP call, no GPU, no launch, no slot.
"""
from __future__ import annotations

from fractions import Fraction as Q

MATRIX_ROWS, MATRIX_COLS = 512, 1024
CHUNK = 32
PARTITION = 256
ROW_POSITIONS = [3, 6, 7, 8, 9, 10, 11, 12, 13]
COL_POSITIONS = [1, 0, 4, 5, 2, 14, 15, 16, 17, 18]

F = Q  # shorthand

#: 16AW FIX (1): overflow is a python float, not a Fraction built from "inf".
#: `Fraction("inf")` raises; `float("inf")` is the value A returns and the
#: value IEEE-754 names.  These are the only non-Fraction values B can produce.
_POS_INF = float("inf")
_NEG_INF = float("-inf")


class NonFiniteFusedValue(ArithmeticError):
    """Raised when a non-finite value reaches the E4M3FN encoder.

    A REFUSAL, not a value: see `e4m3fn_encode`.  Named identically to A's so
    that a caller catching one catches the other."""


# ==========================================================================
# explicit IEEE-754 rounding, on exact rationals
# ==========================================================================
def _round_half_even(x: Q) -> int:
    """Nearest integer to x, ties to even.  Exact; x is a Fraction."""
    neg = x < 0
    a = -x if neg else x
    n, d = a.numerator, a.denominator
    q, r = divmod(n, d)
    twice = 2 * r
    if twice > d or (twice == d and (q & 1)):
        q += 1
    return -q if neg else q


def _floor_log2(x: Q) -> int:
    """Exact floor(log2(x)) for x > 0."""
    e = x.numerator.bit_length() - x.denominator.bit_length()
    if x < Q(2) ** e:
        e -= 1
    while x >= Q(2) ** (e + 1):
        e += 1
    while x < Q(2) ** e:
        e -= 1
    return e


def round_binary(p: int, e_min: int, e_max: int, x: Q) -> Q:
    """Round the exact rational x to the nearest value of an IEEE-style
    binary format with p significand bits, minimum normal exponent e_min and
    maximum exponent e_max.  Returns an exact Fraction, or a python float
    +/-inf when the value is not representable (16AW fix (1)/(2))."""
    if x != x:
        raise ValueError("binary round of NaN")
    # 16AW FIX (2): an already-overflowed value re-enters here as a float.
    # B_16AR raised AttributeError on this path (`inf.numerator`); the value is
    # already the correct answer, so it passes through unchanged.
    if isinstance(x, float) and (x == _POS_INF or x == _NEG_INF):
        return x
    if x == 0:
        return Q(0)
    neg = x < 0
    a = -x if neg else x
    e = _floor_log2(a)
    if e < e_min:
        # subnormal: quantum 2^(e_min - p + 1)
        quantum = Q(2) ** (e_min - p + 1)
        q = _round_half_even(a / quantum)
        val = q * quantum
        if val >= Q(2) ** e_min:            # carried up into the normal range
            return -val if neg else val
        if q == 0:
            return Q(0)
        return -val if neg else val
    if e > e_max:
        # 16AW FIX (1): was `Q("inf")`, which Fraction cannot construct.
        return _NEG_INF if neg else _POS_INF
    quantum = Q(2) ** (e - p + 1)
    q = _round_half_even(a / quantum)
    if q >= Q(2) ** p:
        q >>= 1
        e += 1
        if e > e_max:
            # 16AW FIX (1): as above.
            return _NEG_INF if neg else _POS_INF
    val = q * Q(2) ** (e - p + 1)
    return -val if neg else val


def H(x: Q) -> Q:
    """binary16 round-to-nearest-even, on the exact value."""
    return round_binary(11, -14, 15, x)


def _f32(x: Q) -> Q:
    """binary32 round-to-nearest-even, on the exact value."""
    return round_binary(24, -126, 127, x)


# ==========================================================================
# E4M3FN, built from the format rather than from the pinned procedure
# ==========================================================================
#: the 128 non-negative finite E4M3FN magnitudes, as exact rationals
_MAG = []
for _b in range(128):
    _e = (_b >> 3) & 0xF
    _m = _b & 0x7
    if _e == 15 and _m == 7:
        continue                            # 0x7F is the NaN code; SATFINITE
    _MAG.append((_b, (Q(_m, 8) * Q(2) ** -6) if _e == 0
                 else (Q(1) + Q(_m, 8)) * Q(2) ** (_e - 7)))
_MAG.sort(key=lambda t: t[1])
_MAX_FINITE = Q(448)


def e4m3fn_decode(b: int) -> Q:
    """Exact decode.  SATFINITE: 0x7F/0xFF are +/-448, not NaN."""
    s = -1 if (b >> 7) & 1 else 1
    e = (b >> 3) & 0xF
    m = b & 0x7
    if e == 15 and m == 7:
        return Q(s * 448)
    if e == 0:
        return Q(s) * Q(m, 8) * Q(2) ** -6
    return Q(s) * (Q(1) + Q(m, 8)) * Q(2) ** (e - 7)


def e4m3fn_encode(a: Q) -> int:
    """Nearest-representable search with ties-to-even, saturating at 448.

    A DIFFERENT ALGORITHM from A's: A follows the pinned arithmetic
    procedure; B searches the format's own ordered value set.

    A FINITE value >= 448 saturates to 0x7E.  A NON-FINITE value is REFUSED
    (16AW repair B-2): it is not silently saturated to 0x7E, because the device
    answers `(sign<<7)|0x7F` for that case and the pinned procedure cannot emit
    0x7F at all.  Publishing 0x7E here would be a silent disagreement with the
    kernel on a case where the truth is that no reference value exists.  A's
    `e4m3fn_quantize` refuses the same input with the same reasoning, so the
    two references agree on the case by AGREEING TO REFUSE IT.
    """
    if isinstance(a, float) and (a != a or a == _POS_INF or a == _NEG_INF):
        raise NonFiniteFusedValue(
            "e4m3fn_encode: the fused value is %r.  OUT OF CONTRACT -- the "
            "kernel answers (sign<<7)|0x7F as a loud sentinel and no reference "
            "value exists." % a)
    neg = a < 0
    a = -a if neg else a
    if a >= _MAX_FINITE:
        return 0x7E | (0x80 if neg else 0)
    if a == 0:
        return 0
    best = None
    for b, v in _MAG:
        d = abs(v - a)
        if best is None or d < best[0] or (d == best[0] and (b & 1) == 0
                                           and (best[1] & 1)):
            best = (d, b)
    return best[1] | (0x80 if neg else 0)


def F(x: Q) -> Q:
    """The fp8 round trip."""
    return e4m3fn_decode(e4m3fn_encode(x))


# ==========================================================================
# the operator, in exact rational arithmetic
# ==========================================================================
def bits(count: int, positions: list) -> list:
    out = []
    for i in range(count):
        v = 0
        for b, p in enumerate(positions):
            v |= ((i >> p) & 1) << b
        out.append(v)
    return out


def unpack(raw: bytes):
    rows = bits(MATRIX_COLS * MATRIX_ROWS, ROW_POSITIONS)
    cols = bits(MATRIX_COLS * MATRIX_ROWS, COL_POSITIONS)
    mat = [Q(0)] * (MATRIX_ROWS * MATRIX_COLS)
    for i in range(MATRIX_COLS * MATRIX_ROWS):
        mat[rows[i] * MATRIX_COLS + cols[i]] = e4m3fn_decode(raw[i])
    order = [(c // 16) * 16 + (c % 8) * 2 + ((c % 16) // 8)
             for c in range(MATRIX_ROWS)]
    import struct as _s
    vals = _s.unpack("<%de" % MATRIX_ROWS, raw[MATRIX_COLS * MATRIX_ROWS:])
    scale = [Q(0)] * MATRIX_ROWS
    for i, o in enumerate(order):
        # fp16 -> exact rational, via the bit pattern, not via float()
        half = _s.unpack("<H", _s.pack("<e", float(vals[i])))[0]
        scale[o] = _half_to_exact(half)
    return mat, scale


def _half_to_exact(h: int) -> Q:
    s = -1 if (h >> 15) & 1 else 1
    e = (h >> 10) & 0x1F
    m = h & 0x3FF
    if e == 0:
        return Q(s) * Q(m, 1024) * Q(2) ** -14
    if e == 31:
        return Q(s) * Q(m, 1024) if m else _POS_INF
    return Q(s) * (Q(1) + Q(m, 1024)) * Q(2) ** (e - 15)


def _exact_to_half(x: Q) -> int:
    """Independent encoder for binary16, used only to round-trip inputs."""
    if x == 0:
        return 0
    neg = x < 0
    a = -x if neg else x
    e = _floor_log2(a)
    if e < -14:
        q = _round_half_even(a / (Q(2) ** -24))
        if q >= 1024:
            return (0x8000 if neg else 0) | 0x0400
        return (0x8000 if neg else 0) | q
    quantum = Q(2) ** (e - 10)
    q = _round_half_even(a / quantum)
    if q >= 2048:
        q >>= 1
        e += 1
    if e > 15:
        return (0x8000 if neg else 0) | 0x7C00
    return (0x8000 if neg else 0) | ((e + 15) << 10) | (q - 1024)


def chunk_dot(a: list, a0: int, m: list, m0: int) -> Q:
    """The pinned `@` of a 32-wide chunk: fp32 accumulation, so EVERY partial
    sum is rounded to binary32.  B models that explicitly."""
    s = Q(0)
    for t in range(CHUNK):
        s = _f32(s + a[a0 + t] * m[m0 + t])
    return s


def multiply_row(a: list, a0: int, m: list, m0: int, width: int) -> Q:
    acc = Q(0)
    for off in range(0, width, CHUNK):
        acc = H(acc + chunk_dot(a, a0 + off, m, m0 + off))
    return acc


def project(x_row: list, mat: list, rows: int = MATRIX_ROWS) -> list:
    parts = []
    for i in range(0, MATRIX_COLS, PARTITION):
        parts.append([multiply_row(x_row, i, mat, r * MATRIX_COLS + i,
                                   PARTITION) for r in range(rows)])
    result = parts[0]
    for part in parts[1:]:
        result = [H(u + v) for u, v in zip(result, part)]
    return result


def decoder_entry(x, skip, params, pre_quantization=False):
    mat, scale = params
    Hh = len(x)
    Ww = len(x[0]) if Hh else 0
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
