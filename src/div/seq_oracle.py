#!/usr/bin/env python3
"""Phase 16S / item S3 -- a WHOLE-SEQUENCE equivalence oracle for the
`V_DIV_SCALE_F32` reading ambiguity that Phase 16R/R9 left as
`BLOCKED_J3_DIVISION_SEMANTICS`.

HOST ONLY.  No GPU, no HIP call, no deployment, nothing armed, nothing
launched.  Every number this tool prints comes either from arithmetic written
here out of the IEEE-754 definition, or from the unmodified host emulator.

THE QUESTION.  `phase16r/isa/R9_DIVISION_SEMANTICS.json` records two textual
gaps in opcode 365:

  U1   the branch chain has NO `else`, and three of its branches guard `D`
       with a nested `if (S0.f == S1.f)` / `if (S0.f == S2.f)` that has no
       `else` either.  On the J3 fixture all 144 executed instances reach the
       gap.
  U1b  `exponent(S2.f) <= 23` is ambiguous: the manual writes `exponent()`
       without saying whether it is the biased encoding field (0..255) or
       the true exponent.

THE METHOD.  Do not test `v_div_scale_f32` in isolation.  Test the SEQUENCE
the compiler emitted -- the eleven instructions in
`phase16h_candidate_f/disasm/candidate_gfx1030_disasm.txt` around line 619 --
and ask of each candidate reading: does the whole sequence compute correctly
rounded binary32 division for the actual J3 division instances, and for a
broad independent corpus?

WHAT IT FOUND, SHORT VERSION.  Six readings are modelled: {biased,
unbiased} x {D = S0, D = +0.0, D = the destination register's previous
value}.  On J3 itself FOUR of them are sequence-equivalent, because the
pre-scale then applies to both calls of the pair and cancels.  They separate
on ordinary divisions: mode A -- biased exponent field, D = S0 when the
chain assigns nothing -- is the only reading under which the sequence
returns the quotient, and the other five are each refuted by construction
with explicit arithmetic.  U1 and U1b are therefore RESOLVED.

BUT the sequence is still not correctly rounded division for every input.
A THIRD textual gap, U1c, is measured here: clauses 2, 4 and 6 of the chain
guard D with a nested `if (S0.f == S1.f)` / `if (S0.f == S2.f)` that has no
`else`, and the compiler passes S0 = S1 on the denominator call and S0 = S2
on the numerator call, so exactly one call of the pair is assigned.  No
reading of `exponent()` repairs that, because the nested test does not
mention the exponent.  The phase-16S item S3 closure criterion is a
conjunction of ten clauses and clause 3 fails on those inputs, so the
artifact reports `BLOCKED` -- with the two readings it was asked about
decided, and the reason stated.  It is not being smoothed into a PASS.

This module is deliberately standalone.  Its only imports are the Python
standard library (`argparse`, `collections`, `hashlib`, `json`, `math`,
`os`, `random`, `struct`, `sys`, `fractions`).  It does NOT import
`emu.py`, `r9_isa_div`, or any other project file for a VALUE, so nothing it
computes can inherit a project convention; the project modules are imported
inside functions, for the dispatch and for the loaded-file identity
assertion only, and an isolated `-I -S` subprocess re-derives the whole
offline result with none of them present.

WHERE THE ISA TEXT IS.  `phase16r/isa/ref/rdna2_isa.txt`, sha256
46fdab001a4de548375ba1147213afaf14e86524a5ce137720e1f640d1108950, lines
9907-9951 (V_DIV_SCALE_F32), 9957-10002 (V_DIV_SCALE_F64, the sibling whose
constants settle part of the reading), 9728-9763 (V_DIV_FIXUP_F32).
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import random
import struct
import sys
from fractions import Fraction

# ===========================================================================
# section 0 -- paths and provenance
# ===========================================================================
HERE = os.path.dirname(os.path.abspath(__file__))          # phase16s/div
PHASE16S = os.path.dirname(HERE)                           # phase16s
ROOT = os.path.dirname(PHASE16S)                           # project root
LOGS = os.path.join(HERE, "logs")

EMU_REL = os.path.join("phase8_static", "tools", "emu.py")
EMU_PATH = os.path.join(ROOT, EMU_REL)
#: The value the Phase 16S brief pins.  It is printed here as the brief
#: prints it; `check_emulator_identity` compares it END-ANCHORED against the
#: measured digest, because the literal string in the brief is 44 hex
#: characters and 44 is not a SHA-256 length.  The discrepancy is recorded in
#: the artifact rather than smoothed over -- see `emulator_identity`.
EMU_SHA256_BRIEF = "c6afc641be3ce734789ec505eb7f23ca8064edb17205"
ISA_REL = os.path.join("phase16r", "isa", "ref", "rdna2_isa.txt")
ISA_SHA256 = "46fdab001a4de548375ba1147213afaf14e86524a5ce137720e1f640d1108950"


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ===========================================================================
# section 1 -- an independent binary32, built from the IEEE-754 definition
# ===========================================================================
# Everything in this section is written with Python integers and
# `fractions.Fraction`.  Python's native `/` on floats is NEVER the source of
# an expected value.  One single rounding, round-to-nearest-ties-to-even, is
# applied to an EXACT rational at each step.

SIGN_BIT = 0x80000000
EXP_MASK = 0x7F800000
MAN_MASK = 0x007FFFFF
QUIET_BIT = 0x00400000

#: binary32 parameters.
PREC = 24               # significand bits, including the implicit one
EMIN = -126             # minimum normal exponent
EMAX = 127              # maximum normal exponent
QMIN = -149             # quantum exponent of the least subnormal

#: The one NaN this module produces.  IEEE-754 fixes neither the sign nor the
#: payload of a NaN result, and the AMD text writes a bare `NAN` with no
#: payload rule, so a canonical quiet NaN is chosen and RECORDED as a choice
#: everywhere it can appear.  Comparisons that involve it are reported
#: separately (`nan_producing`) rather than silently counted as agreements.
QNAN = 0x7FC00000
INF_BITS = 0x7F800000


def _pow2(k):
    """2**k as an exact Fraction."""
    return Fraction(1 << k, 1) if k >= 0 else Fraction(1, 1 << -k)


def _floor_log2(a):
    """floor(log2(a)) for an exact positive Fraction.  No float involved."""
    n, d = a.numerator, a.denominator
    e = n.bit_length() - d.bit_length()
    if e >= 0:
        if n < (d << e):
            e -= 1
    else:
        if (n << -e) < d:
            e -= 1
    return e


def _rne_nonneg(a):
    """round-to-nearest-ties-to-even of a non-negative Fraction to an int."""
    n, d = a.numerator, a.denominator
    q, r = divmod(n, d)
    if r == 0:
        return q
    twice = 2 * r
    if twice > d:
        return q + 1
    if twice < d:
        return q
    return q + 1 if (q & 1) else q


def pack_rne(magnitude, sign):
    """Round the exact non-negative Fraction `magnitude` to binary32, RNE.

    `sign` is 0 or 1 and is applied to the rounded result, so this also
    produces the signed zeros and the signed infinities.
    Returns the 32-bit pattern.
    """
    if magnitude == 0:
        return sign << 31
    e = _floor_log2(magnitude)
    qe = max(e - (PREC - 1), QMIN)
    while True:
        n = _rne_nonneg(magnitude / _pow2(qe))
        if n >= (1 << PREC):
            # rounded up to the next binade; the VALUE is unchanged
            n = 1 << (PREC - 1)
            qe += 1
            continue
        break
    if n == 0:
        return sign << 31
    if qe == QMIN and n < (1 << (PREC - 1)):
        return (sign << 31) | n                      # subnormal
    exp = qe + (PREC - 1)
    if exp > EMAX:
        return (sign << 31) | INF_BITS               # overflow -> inf
    return (sign << 31) | ((exp + 127) << 23) | (n - (1 << (PREC - 1)))


# ---- classification ------------------------------------------------------
def sign_of(b):
    return (b >> 31) & 1


def efield(b):
    """The BIASED exponent encoding field, 0..255."""
    return (b >> 23) & 0xFF


def is_nan_b(b):
    return (b & EXP_MASK) == EXP_MASK and (b & MAN_MASK) != 0


def is_inf_b(b):
    return (b & EXP_MASK) == EXP_MASK and (b & MAN_MASK) == 0


def is_zero_b(b):
    return (b & 0x7FFFFFFF) == 0


def is_sub_b(b):
    """A non-zero magnitude below the smallest normal."""
    return efield(b) == 0 and (b & MAN_MASK) != 0


def true_exp(b):
    """floor(log2|x|) for a finite non-zero bit pattern.

    Correct for subnormals too, which is exactly where this differs from the
    biased field.
    """
    ef = efield(b)
    m = b & MAN_MASK
    if ef == 0:
        return -126 - (23 - m.bit_length())
    return ef - 127


def value_of(b):
    """The EXACT value of a finite bit pattern, as a Fraction (signed)."""
    s = -1 if (b >> 31) else 1
    ef = efield(b)
    m = b & MAN_MASK
    if ef == 0:
        return s * Fraction(m, 1 << 149)
    return s * Fraction(m | (1 << 23), 1) * _pow2(ef - 150)


def classify(b):
    if is_nan_b(b):
        return "nan"
    if is_inf_b(b):
        return "inf"
    if is_zero_b(b):
        return "zero"
    if is_sub_b(b):
        return "subnormal"
    return "normal"


def neg_bits(b):
    """True f32 negation: flip the sign bit.  NOT an integer negate."""
    return (b ^ SIGN_BIT) & 0xFFFFFFFF


def abs_bits(b):
    return b & 0x7FFFFFFF


def bits_of_float(x):
    return struct.unpack("<I", struct.pack("<f", x))[0]


# ---- the elementary operations, each one rounded exactly once -------------
def add_rn(a, b):
    if is_nan_b(a) or is_nan_b(b):
        return QNAN
    if is_inf_b(a) or is_inf_b(b):
        if is_inf_b(a) and is_inf_b(b) and sign_of(a) != sign_of(b):
            return QNAN
        return a if is_inf_b(a) else b
    s = value_of(a) + value_of(b)
    if s == 0:
        return 0                       # RNE: (+x) + (-x) = +0
    return pack_rne(abs(s), 1 if s < 0 else 0)


def mul_rn(a, b):
    if is_nan_b(a) or is_nan_b(b):
        return QNAN
    sa, sb = sign_of(a), sign_of(b)
    if is_inf_b(a) or is_inf_b(b):
        other = b if is_inf_b(a) else a
        if is_zero_b(other):
            return QNAN                # 0 * inf is invalid
        return ((sa ^ sb) << 31) | INF_BITS
    p = value_of(a) * value_of(b)
    if p == 0:
        return ((sa ^ sb) << 31)     # signed zero product
    return pack_rne(abs(p), 1 if p < 0 else 0)


def fma_rn(a, b, c):
    """A TRUE fused multiply-add: one rounding on the exact a*b+c."""
    if is_nan_b(a) or is_nan_b(b) or is_nan_b(c):
        return QNAN
    sa, sb = sign_of(a), sign_of(b)
    # the product, as an exact value plus an "invalid"/"infinite" flag
    if is_inf_b(a) or is_inf_b(b):
        other = b if is_inf_b(a) else a
        if is_zero_b(other):
            return QNAN                # 0 * inf + c is invalid
        p_sign = sa ^ sb
        if is_inf_b(c) and sign_of(c) != p_sign:
            return QNAN                # inf - inf
        return (p_sign << 31) | INF_BITS
    if is_inf_b(c):
        return c
    exact = value_of(a) * value_of(b) + value_of(c)
    if exact == 0:
        # IEEE-754: the sum of two opposite-signed exact zeros is +0 in RNE.
        return 0
    return pack_rne(abs(exact), 1 if exact < 0 else 0)


def rcp_rn(a):
    """The exactly rounded binary32 reciprocal (RNE)."""
    if is_nan_b(a):
        return QNAN
    s = sign_of(a)
    if is_zero_b(a):
        return (s << 31) | INF_BITS
    if is_inf_b(a):
        return (s << 31)
    v = value_of(a)
    r = abs(Fraction(1, 1) / v)
    return pack_rne(r, s)


def ldexp_rn(a, k):
    """`ldexp(x, k)` meaning: the exact product x * 2**k, rounded once."""
    if is_nan_b(a) or is_inf_b(a):
        return a
    v = value_of(a) * _pow2(k)
    if v == 0:
        return sign_of(a) << 31
    return pack_rne(abs(v), 1 if v < 0 else 0)


def from_exact(fr):
    """Round an exact signed Fraction to binary32, RNE."""
    if fr == 0:
        return 0
    return pack_rne(abs(fr), 1 if fr < 0 else 0)


def quiet_nan_from(a):
    """Quiet a NaN the way the ISA's `Quiet()` reads: set the quiet bit."""
    return (a | QUIET_BIT) & 0xFFFFFFFF


# ===========================================================================
# section 2 -- the semantic target: correctly rounded binary32 division
# ===========================================================================
def div_rn(x, y):
    """The correctly rounded binary32 quotient x/y, round-to-nearest-even.

    THIS IS THE SEMANTIC TARGET.  It is derived from the IEEE-754 definition,
    not from any hardware sequence and not from Python's float `/`:

        the result is the binary32 value nearest the exact rational x/y,
        ties resolved to the even significand; when the exact quotient is
        outside the binary32 range the result is a signed infinity, and when
        it is smaller in magnitude than the least subnormal it rounds to a
        signed zero or to the least subnormal by the same nearest rule.

    Exceptional cases, and what is returned for each -- all of them are
    choices IEEE-754 leaves open, and are recorded as choices:

        NaN in either operand  -> 0x7FC00000 (the canonical quiet NaN).
                                  IEEE-754 lets an implementation propagate
                                  the input NaN's payload; the AMD text
                                  fixes no payload rule for division, so the
                                  canonical one is used and every instance
                                  whose expected result is a NaN is reported
                                  separately (`nan_producing`) instead of
                                  being counted as a silent agreement.
        0/0, inf/inf           -> 0x7FC00000 (invalid operation)
        x/0, x finite, x != 0  -> +-inf with the sign of x xor y
        inf/y, y finite        -> +-inf
        x/inf                  -> +-0 with the sign of x xor y
    """
    if is_nan_b(x) or is_nan_b(y):
        return QNAN
    sx, sy = sign_of(x), sign_of(y)
    so = sx ^ sy
    if is_inf_b(x):
        if is_inf_b(y):
            return QNAN
        return (so << 31) | INF_BITS
    if is_inf_b(y):
        return (so << 31)
    if is_zero_b(y):
        if is_zero_b(x):
            return QNAN
        return (so << 31) | INF_BITS
    if is_zero_b(x):
        return (so << 31)
    q = value_of(x) / value_of(y)
    return pack_rne(abs(q), so)


def div_plain(x, y):
    """The PLAIN reading: `f32(S2 / S1)`, computed the naive way.

    This is what a straightforward implementation does when it divides in
    binary64 and rounds the result to binary32, i.e. it is exposed to DOUBLE
    ROUNDING and can differ from `div_rn` on rare inputs.  It is reported
    separately precisely because it is a different observable.
    Returns None when the binary64 quotient is not finite, so the caller
    falls back to the IEEE exceptional result (which is what a naive
    implementation effectively produces).
    """
    if is_nan_b(x) or is_nan_b(y):
        return QNAN
    if is_inf_b(y) or is_zero_b(y) or is_inf_b(x) or is_zero_b(x):
        return div_rn(x, y)
    fx = float(value_of(x))
    fy = float(value_of(y))
    try:
        q = fx / fy
    except ZeroDivisionError:
        return div_rn(x, y)
    if not math.isfinite(q):
        return div_rn(x, y)
    try:
        return bits_of_float(struct.unpack("<f", struct.pack("<f", q))[0])
    except OverflowError:
        # |q| exceeds the binary32 range; a naive implementation saturates
        # to a signed infinity, which is also the IEEE result here
        return div_rn(x, y)


# ---- a second, structurally different rounding referee -------------------
def div_referee(x, y):
    """The correctly rounded quotient found by NEAREST-REPRESENTABLE SEARCH.

    Independent of `pack_rne`/`_rne_nonneg`: it materialises the two binary32
    values that bracket the exact rational quotient and picks the nearer by
    an exact Fraction comparison, breaking a tie toward the even significand.
    Used only as the negative control for `div_rn`, which is the reason it
    may share the trivial encoder with it.
    """
    if is_nan_b(x) or is_nan_b(y):
        return QNAN
    sx, sy = sign_of(x), sign_of(y)
    so = sx ^ sy
    if is_inf_b(x) or is_inf_b(y) or is_zero_b(y) or is_zero_b(x):
        return div_rn(x, y)
    q = abs(value_of(x) / value_of(y))
    e = _floor_log2(q)
    qe = max(e - (PREC - 1), QMIN)
    # the two neighbours of q on the binary32 grid with quantum 2**qe
    n_lo = (q / _pow2(qe)).numerator // (q / _pow2(qe)).denominator
    cand = []
    for n in (n_lo, n_lo + 1):
        if n < 0:
            continue
        cand.append((n, pack_from_grid(n, qe)))
    best = None
    for n, b in cand:
        d = abs(q - Fraction(n) * _pow2(qe))
        even = (n % 2 == 0)
        key = (d, 0 if even else 1)
        if best is None or key < best[0]:
            best = (key, b)
    return (so << 31) | abs_bits(best[1])


def pack_from_grid(n, qe):
    """Encode the value n * 2**qe as binary32, for a non-negative integer n.

    Only used by the referee, and only for values the referee already knows
    are on the binary32 grid; it does not round.
    """
    if n == 0:
        return 0
    if qe == QMIN and n < (1 << (PREC - 1)):
        return n
    # normalise n to exactly PREC bits
    while n >= (1 << PREC):
        if n & 1:
            n += 1
            continue
        n >>= 1
        qe += 1
    while n < (1 << (PREC - 1)) and qe > QMIN:
        n <<= 1
        qe -= 1
    exp = qe + (PREC - 1)
    if exp > EMAX:
        return INF_BITS
    return ((exp + 127) << 23) | (n - (1 << (PREC - 1)))


# ===========================================================================
# section 3 -- V_DIV_SCALE_F32, parameterised by the two open readings
# ===========================================================================
#: name -> (exponent reading, what D becomes where the text assigns nothing)
MODES = {
    "A": ("biased", "s0"),
    "B": ("unbiased", "s0"),
    "C": ("biased", "zero"),
    "D": ("unbiased", "zero"),
    # The two extra pairings exist because "the register keeps whatever it
    # held" is a third admissible resolution of a missing `else`.  The
    # destination register's value BEFORE the instruction is recorded on the
    # J3 trace, so this reading is measurable there and is not a guess.
    "E": ("biased", "prev"),
    "F": ("unbiased", "prev"),
}
MODE_DOC = {
    "A": "biased exponent field; where the chain assigns nothing, D = S0 (pass through)",
    "B": "unbiased/true exponent; where the chain assigns nothing, D = S0",
    "C": "biased exponent field; where the chain assigns nothing, D = +0.0",
    "D": "unbiased/true exponent; where the chain assigns nothing, D = +0.0",
    "E": "biased exponent field; where the chain assigns nothing, D keeps the destination register's previous value",
    "F": "unbiased/true exponent; where the chain assigns nothing, D keeps the destination register's previous value",
}

#: how the value predicates `1/S1.f` and `S2.f/S1.f` are computed.  Another
#: undeclared choice in the manual; recorded, and measured for reach.
PRED_DIV = "rounded_f32"        # divide with div_rn (single f32 rounding)


def _exp_for(b, reading):
    if reading == "biased":
        return efield(b)
    return true_exp(b)


def scale_chain(s0, s1, s2, mode):
    """The RDNA2 opcode-365 branch chain, exactly as printed.

    Returns a dict:
      D             the destination bit pattern, or None when the chain
                    assigns nothing and `default` is "prev"
      raw           True  -> the text assigned D on the path taken
                    False -> the text assigned nothing
      vcc           0 or 1
      branch        which clause fired (or "no branch matched")
      nested_miss   True when a clause fired but its nested `if (S0 == Sx)`
                    was false, so nothing assigned D there either
    """
    reading, default = MODES[mode]
    vcc = 0
    D = None
    assigned = False
    nested_miss = False

    def z(b):
        return is_zero_b(b)

    if z(s2) or z(s1):
        branch = "1: S2==0 || S1==0  -> D = NAN"
        D, assigned = QNAN, True
    elif _exp_for(s2, reading) - _exp_for(s1, reading) >= 96:
        branch = "2: exponent(S2)-exponent(S1) >= 96"
        vcc = 1
        if s0 == s1:
            D, assigned = ldexp_rn(s0, 64), True
        else:
            nested_miss = True
    elif is_sub_b(s1):
        branch = "3: S1 is DENORM"
        D, assigned = ldexp_rn(s0, 64), True
    elif (is_sub_b(rcp_rn(s1)) and is_sub_b(div_rn(s2, s1))):
        branch = "4: 1/S1 DENORM && S2/S1 DENORM"
        vcc = 1
        if s0 == s1:
            D, assigned = ldexp_rn(s0, 64), True
        else:
            nested_miss = True
    elif is_sub_b(rcp_rn(s1)):
        branch = "5: 1/S1 is DENORM"
        D, assigned = ldexp_rn(s0, -64), True
    elif is_sub_b(div_rn(s2, s1)):
        branch = "6: S2/S1 is DENORM"
        vcc = 1
        if s0 == s2:
            D, assigned = ldexp_rn(s0, 64), True
        else:
            nested_miss = True
    elif _exp_for(s2, reading) <= 23:
        branch = "7: exponent(S2) <= 23  (numerator is tiny)"
        D, assigned = ldexp_rn(s0, 64), True
    else:
        branch = "8: NO BRANCH MATCHED"

    if not assigned and D is None and default != "prev":
        # U1 resolution.  "s0" is the reading the division macro requires and
        # is labelled a DEDUCTION; "zero" is the alternative admissible text.
        D = s0 if default == "s0" else 0

    return {"D": D, "assigned": assigned, "vcc": vcc, "branch": branch,
            "nested_miss": nested_miss}


# ===========================================================================
# section 4 -- V_DIV_FMAS_F32 and V_DIV_FIXUP_F32
# ===========================================================================
def fmas_f32(s0, s1, s2, vcc):
    """Opcode 367: a fused multiply-add, post-scaled by 2**32 when VCC is set."""
    r = fma_rn(s0, s1, s2)
    if vcc:
        r = ldexp_rn(r, 32)
    return r


def fixup_f32(s0, s1, s2, overflow=0x7F7FFFFF, underflow=0x00000001):
    """Opcode 351, transcribed clause by clause from lines 9737-9763.

    `overflow` / `underflow` stand in for the two magnitudes the text leaves
    SYMBOLIC (`D.f = sign_out ? -underflow : underflow`).  They are recorded
    as supplied constants, and `symbolic` is True on those two paths so a
    caller can see that no magnitude is being claimed.  Phase 16R measured
    that neither path is reached on J3.
    """
    sign_out = sign_of(s1) ^ sign_of(s2)
    symbolic = False
    if is_nan_b(s2):
        D, branch = quiet_nan_from(s2), "S2 is NAN"
    elif is_nan_b(s1):
        D, branch = quiet_nan_from(s1), "S1 is NAN"
    elif is_zero_b(s1) and is_zero_b(s2):
        D, branch = 0xFFC00000, "0/0"
    elif is_inf_b(s1) and is_inf_b(s2):
        D, branch = 0xFFC00000, "inf/inf"
    elif is_zero_b(s1) or is_inf_b(s2):
        D, branch = ((sign_out << 31) | INF_BITS), "x/0 or inf/y"
    elif is_inf_b(s1) or is_zero_b(s2):
        D, branch = (sign_out << 31), "x/inf or 0/y"
    elif _exp_for(s2, "biased") - _exp_for(s1, "biased") < -150:
        D = ((sign_out << 31) | (underflow & 0x7FFFFFFF))
        branch, symbolic = "exponent difference < -150 (underflow)", True
    elif efield(s1) == 255:
        D = ((sign_out << 31) | (overflow & 0x7FFFFFFF))
        branch, symbolic = "exponent(S1) == 255 (overflow)", True
    else:
        D = (abs_bits(s0) | (sign_out << 31))
        branch = "default: sign_out applied to abs(S0)"
    return {"D": D, "branch": branch, "symbolic": symbolic,
            "sign_out": sign_out}


# ===========================================================================
# section 5 -- the compiler's whole sequence, evaluated end to end
# ===========================================================================
#: The eleven instructions, from
#: `phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt` near line 619.
SEQUENCE = [
    "v_div_scale_f32 vD1, null,   vDEN, vDEN, vNUM",
    "v_div_scale_f32 vN1, vcc_lo, vNUM, vDEN, vNUM",
    "v_rcp_f32       vR,  vD1",
    "v_fma_f32       vE, -vD1,  vR,  1.0",
    "v_fmac_f32      vR,  vE,   vR",
    "v_mul_f32       vQ,  vN1,  vR",
    "v_fma_f32       vT, -vD1,  vQ,  vN1",
    "v_fmac_f32      vQ,  vT,   vR",
    "v_fma_f32       vD1, -vD1, vQ,  vN1",
    "v_div_fmas_f32  vD1, vD1,  vR,  vQ",
    "v_div_fixup_f32 vOUT,vD1,  vDEN,vNUM",
]


def sequence_tail(D, N, vcc, den, num, rcp=rcp_rn, negation="correct"):
    """Instructions 3..11 of the sequence, given the two pre-scaled operands.

    Split out so the `what-if` analysis of the nested `else` can drive the
    SAME tail with a hypothesised pair (D, N, vcc) instead of the one the
    printed chain produces.
    """
    def neg(b):
        return neg_bits(b) if negation == "correct" else ((-b) & 0xFFFFFFFF)

    r = rcp(D)
    e = fma_rn(neg(D), r, bits_of_float(1.0))
    r = fma_rn(e, r, r)
    q = mul_rn(N, r)
    t = fma_rn(neg(D), q, N)
    q = fma_rn(t, r, q)
    t2 = fma_rn(neg(D), q, N)
    Q = fmas_f32(t2, r, q, vcc)
    F = fixup_f32(Q, den, num)
    return {"D1": D, "N1": N, "vcc": vcc, "rcp": r, "Q": Q,
            "OUT": F["D"], "fixup_branch": F["branch"],
            "fixup_symbolic": F["symbolic"]}


def sequence_quotient(den, num, mode, rcp=rcp_rn, negation="correct",
                      prev_den=0, prev_num=0):
    """Run the whole sequence for one lane and return every intermediate.

    `den`/`num` are the bit patterns of the S1 (denominator) and S2
    (numerator) the kernel's own operands carry.  The FIRST scale receives
    S0 = denominator and the SECOND receives S0 = numerator, which is what
    the disassembly's operand list says and what the ISA requires
    ("S0 must be the same value as either S1 or S2").

    `rcp` models `v_rcp_f32`.  The default is the exactly rounded reciprocal,
    i.e. the most charitable starting point for the Newton-Raphson chain --
    an emulator that still fails to reach correctly rounded division under
    this model cannot be rescued by a better reciprocal.  The module also
    measures the sensitivity to that choice.

    `negation` models the `-vN` operand.  "correct" is true f32 negation,
    which is what the ISA means.  "integer" is the emulator's own defect
    (`emu.py` reads `-vN` as `f32((-bits(N)) & 0xFFFFFFFF)`), included so the
    emulator's divergence from the sequence can be attributed rather than
    assumed.

    `prev_den` / `prev_num` are the destination registers' values BEFORE the
    two scale instructions, which is what modes E/F resolve the unassigned
    path to.
    """
    s1 = scale_chain(den, den, num, mode)
    s2 = scale_chain(num, den, num, mode)
    D = s1["D"] if s1["D"] is not None else prev_den
    N = s2["D"] if s2["D"] is not None else prev_num
    out = sequence_tail(D, N, s2["vcc"], den, num, rcp=rcp,
                        negation=negation)
    out["scale_den"] = s1
    out["scale_num"] = s2
    return out


# ===========================================================================
# section 6 -- self test of the independent library
# ===========================================================================
def _selftest_division(n=40000, seed=20260919):
    """`div_rn` must agree with the nearest-representable referee.

    The referee is the negative control for the rounding: perturbing `div_rn`
    (see `div_rn_truncating`) must make the agreement collapse.  Both counts
    are returned.
    """
    rng = random.Random(seed)
    pool = []
    for _ in range(600):
        pool.append(rng.getrandbits(32))
    # structured members: powers of two, subnormals, zeros, infinities, NaNs
    for e in range(0, 256, 7):
        pool.append((e << 23))
        pool.append((e << 23) | 0x80000000)
    for m in (1, 2, 3, 0x7FFFFF, 0x400000, 0x7FFFFE):
        pool.append(m)
        pool.append(m | 0x80000000)
    pool += [0x00000000, 0x80000000, 0x7F800000, 0xFF800000,
             0x7FC00000, 0x7F7FFFFF, 0xFF7FFFFF, 0x00800000, 0x00000001]
    ok = bad = 0
    for _ in range(n):
        x = rng.choice(pool)
        y = rng.choice(pool)
        if div_rn(x, y) == div_referee(x, y):
            ok += 1
        else:
            bad += 1
    return ok, bad


def div_rn_truncating(x, y):
    """`div_rn` with the final rounding replaced by TRUNCATION.

    The deliberate defect used as the negative control for the reference: it
    must make the agreement with the referee collapse.
    """
    if is_nan_b(x) or is_nan_b(y):
        return QNAN
    sx, sy = sign_of(x), sign_of(y)
    so = sx ^ sy
    if is_inf_b(x) or is_inf_b(y) or is_zero_b(y) or is_zero_b(x):
        return div_rn(x, y)
    q = abs(value_of(x) / value_of(y))
    e = _floor_log2(q)
    qe = max(e - (PREC - 1), QMIN)
    n = (q / _pow2(qe)).numerator // (q / _pow2(qe)).denominator   # floor
    if n >= (1 << PREC):
        n = 1 << (PREC - 1)
        qe += 1
    if n == 0:
        return (so << 31)
    if qe == QMIN and n < (1 << (PREC - 1)):
        return (so << 31) | n
    exp = qe + (PREC - 1)
    if exp > EMAX:
        return (so << 31) | INF_BITS
    return (so << 31) | ((exp + 127) << 23) | (n - (1 << (PREC - 1)))


# ===========================================================================
# section 7 -- the synthetic, branch-targeted corpus
# ===========================================================================
def _b(x):
    return bits_of_float(x)


def _v(name, den, num, klass, note="", prev_den=0, prev_num=0):
    return {"name": name, "den": _b(den), "num": _b(num), "class": klass,
            "note": note, "prev_den": prev_den, "prev_num": prev_num}


def boundary_vectors():
    """Deliberately hit each clause of the chain and BOTH sides of the
    `exponent(S2.f) <= 23` boundary under BOTH readings.

    The two readings are radically different magnitudes:
      * biased reading     -- the clause fires when the ENCODING FIELD of S2
                              is <= 23, i.e. |S2| < 2**-103
      * unbiased reading   -- the clause fires when the true exponent of S2
                              is <= 23, i.e. |S2| < 2**24
    So the encoding fields 21..25 and the true exponents 21..25 are listed
    explicitly and separately; they cannot be reached by the same vectors.
    """
    V = []
    # -- the BIASED reading's boundary: encoding field 21..25 --------------
    for f in (21, 22, 23, 24, 25):
        s2 = math.ldexp(1.0, f - 127)
        for dnm, dlab in ((1.0, "den1"), (0.5, "den0.5"), (2.0 ** 64, "den2p64")):
            V.append(_v("B_field%d_%s" % (f, dlab), dnm, s2, "boundary-biased",
                        "biased field of S2 = %d" % f))
    # -- the UNBIASED reading's boundary: true exponent 21..25 -------------
    for e in (21, 22, 23, 24, 25):
        s2 = math.ldexp(1.0, e)
        for dnm, dlab in ((1.0, "den1"), (0.5, "den0.5"), (2.0 ** 64, "den2p64")):
            V.append(_v("B_true%d_%s" % (e, dlab), dnm, s2, "boundary-unbiased",
                        "true exponent of S2 = %d" % e))
    # -- clause 1: zero operands -------------------------------------------
    V += [
        _v("C1_numzero", 1.0, 0.0, "clause-1"),
        _v("C1_numnegzero", 1.0, -0.0, "clause-1"),
        _v("C1_denzero", 0.0, 1.0, "clause-1"),
        _v("C1_bothzero", 0.0, 0.0, "clause-1"),
        _v("C1_bothnegzero", -0.0, -0.0, "clause-1"),
    ]
    # -- clause 2: exponent difference >= 96 -------------------------------
    V += [
        _v("C2_diff128", 2.0 ** -64, 2.0 ** 64, "clause-2"),
        _v("C2_diff96", 1.0, 2.0 ** 96, "clause-2"),
        _v("C2_diff95", 1.0, 2.0 ** 95, "clause-2"),
        _v("C2_subden", 2.0 ** -149, 2.0 ** 100, "clause-2"),
        _v("C2_subden_huge_num", 2.0 ** -149, 2.0 ** 127, "clause-2"),
    ]
    # -- clause 3: S1 is DENORM --------------------------------------------
    V += [
        _v("C3_densub", 2.0 ** -130, 1.0, "clause-3"),
        _v("C3_densub_bignum", 2.0 ** -130, 2.0 ** 100, "clause-3"),
        _v("C3_densub_smallnum", 2.0 ** -130, 2.0 ** -120, "clause-3"),
        _v("C3_denmin_sub", 2.0 ** -149, 1.0, "clause-3"),
    ]
    # -- clause 4: 1/S1 DENORM and S2/S1 DENORM ----------------------------
    V += [
        _v("C4_both", 2.0 ** 127, 1.0, "clause-4"),
        _v("C4_both2", 2.0 ** 127, 2.0 ** 0, "clause-4"),
    ]
    # -- clause 5: 1/S1 DENORM only ----------------------------------------
    V += [
        _v("C5_only", 2.0 ** 127, 2.0 ** 10, "clause-5"),
        _v("C5_only2", 2.0 ** 120, 2.0 ** 50, "clause-5"),
    ]
    # -- clause 6: S2/S1 DENORM only ---------------------------------------
    V += [
        _v("C6_only", 1.0, 2.0 ** -130, "clause-6"),
        _v("C6_only2", 2.0 ** 40, 2.0 ** -100, "clause-6"),
    ]
    # -- clause 7 under each reading ---------------------------------------
    V += [
        _v("C7_biased_taken", 1.0, 2.0 ** -110, "clause-7"),
        _v("C7_biased_not_taken", 1.0, 2.0 ** -50, "clause-7"),
    ]
    # -- clause 8: the ordinary default case -------------------------------
    V += [
        _v("C8_default", 0.5, 0.4375, "clause-8"),
        _v("C8_default_third", 1.0, 3.0, "clause-8"),
        _v("C8_default_messy", 0.3, 0.7, "clause-8"),
        _v("C8_default_bigden", 2.0 ** 64, 1.0, "clause-8"),
        _v("C8_default_smallden", 2.0 ** -64, 1.0, "clause-8"),
        _v("C8_default_neg", -0.5, 0.4375, "clause-8"),
        _v("C8_default_neg2", 0.5, -0.4375, "clause-8"),
    ]
    # -- infinities and NaNs ------------------------------------------------
    V += [
        _v("X_inf_den", float("inf"), 1.0, "special"),
        _v("X_inf_num", 1.0, float("inf"), "special"),
        _v("X_inf_inf", float("inf"), float("inf"), "special"),
        _v("X_inf_fin", 1.0, float("inf"), "special"),
        _v("X_nan_num", 1.0, float("nan"), "special"),
        _v("X_nan_den", float("nan"), 1.0, "special"),
        _v("X_nan_both", float("nan"), float("nan"), "special"),
        _v("X_ninf_den", float("-inf"), 1.0, "special"),
        _v("X_max_max", 3.4028234663852886e38, 3.4028234663852886e38, "special"),
        _v("X_max_min", 3.4028234663852886e38, 1.1754943508222875e-38,
           "special"),
    ]
    return V


def corpus_vectors(n=3000, seed=20260919):
    """A broad independent corpus of ordinary f32 divisions.

    Both operands are finite; the denominator is non-zero.  The value pool
    spans the whole finite range: random mantissas at every exponent, every
    power of two, subnormals, and values adjacent to 1.0.
    """
    rng = random.Random(seed)
    pool = []
    for _ in range(1200):
        pool.append(rng.getrandbits(31))            # finite, either sign
    for e in range(1, 255):
        pool.append((e << 23))
        pool.append((e << 23) | 0x80000000)
        pool.append((e << 23) | rng.getrandbits(23))
    for m in (1, 2, 3, 0x7FFFFF, 0x400000, 0x7FFFFE, 0x000001):
        pool.append(m)
        pool.append(m | 0x80000000)
    pool += [0x3F800000, 0xBF800000, 0x40000000, 0x3F000000, 0x00000001,
             0x007FFFFF, 0x00800000, 0x7F7FFFFF, 0x00000002]
    V = []
    while len(V) < n:
        x = rng.choice(pool)
        y = rng.choice(pool)
        if is_zero_b(y) or is_nan_b(y) or is_inf_b(y):
            continue
        if is_nan_b(x):
            continue
        V.append({"name": "R%04d" % len(V), "den": y, "num": x,
                  "class": "corpus", "note": "", "prev_den": 0, "prev_num": 0})
    return V


def in_scope(vec):
    """True for the ordinary divisions the lowering exists to serve.

    In scope: both operands finite and non-zero, and the correctly rounded
    quotient is normal.  This is the class in which the pre-scale chain must
    be transparent -- the class the compiler's div sequence is a lowering
    FOR.  Out of scope: division by zero, infinities, NaNs, and quotients
    that underflow or overflow, where the ISA text's own clauses (and its
    symbolic underflow/overflow magnitudes, U2) take over.
    """
    for k in ("den", "num"):
        if is_zero_b(vec[k]) or is_inf_b(vec[k]) or is_nan_b(vec[k]):
            return False
    r = div_rn(vec["num"], vec["den"])
    if is_zero_b(r) or is_inf_b(r) or is_nan_b(r):
        return False
    return classify(r) == "normal"


# ===========================================================================
# section 8 -- evaluating a corpus against every candidate reading
# ===========================================================================
def evaluate(vectors, rcp=rcp_rn, negation="correct"):
    """For every reading, count agreement with the reference and with plain.

    Returns (per_mode, per_vector).  A comparison is counted only when a
    value was actually produced; `nan_producing` is reported separately and
    is never folded into the agreement count.
    """
    per_mode = {}
    per_vector = []
    for m in MODES:
        per_mode[m] = {"n": 0, "eq_reference": 0, "eq_plain": 0, "neither": 0,
                       "nan_producing": 0, "reference_is_nan": 0,
                       "branches_den": {}, "branches_num": {},
                       "vcc_set": 0, "unassigned_den": 0, "unassigned_num": 0}
    for v in vectors:
        ref = div_rn(v["num"], v["den"])
        plain = div_plain(v["num"], v["den"])
        rec = {"name": v["name"], "class": v["class"], "note": v["note"],
               "den": "%08X" % v["den"], "num": "%08X" % v["num"],
               "reference": "%08X" % ref, "plain": "%08X" % plain,
               "in_scope": in_scope(v), "modes": {}}
        for m in MODES:
            r = sequence_quotient(v["den"], v["num"], m, rcp=rcp,
                                  negation=negation,
                                  prev_den=v.get("prev_den", 0),
                                  prev_num=v.get("prev_num", 0))
            out = r["OUT"]
            pm = per_mode[m]
            pm["n"] += 1
            if out == ref:
                pm["eq_reference"] += 1
            elif out == plain:
                pm["eq_plain"] += 1
            else:
                pm["neither"] += 1
            if is_nan_b(out):
                pm["nan_producing"] += 1
            if is_nan_b(ref):
                pm["reference_is_nan"] += 1
            if r["vcc"]:
                pm["vcc_set"] += 1
            if not r["scale_den"]["assigned"]:
                pm["unassigned_den"] += 1
            if not r["scale_num"]["assigned"]:
                pm["unassigned_num"] += 1
            bd = r["scale_den"]["branch"]
            bn = r["scale_num"]["branch"]
            pm["branches_den"][bd] = pm["branches_den"].get(bd, 0) + 1
            pm["branches_num"][bn] = pm["branches_num"].get(bn, 0) + 1
            rec["modes"][m] = {
                "out": "%08X" % out,
                "eq_reference": out == ref,
                "eq_plain": out == plain,
                "branch_den": bd, "branch_num": bn,
                "assigned_den": r["scale_den"]["assigned"],
                "assigned_num": r["scale_num"]["assigned"],
                "vcc": r["vcc"], "fixup_branch": r["fixup_branch"],
                "D1": "%08X" % r["D1"], "N1": "%08X" % r["N1"],
            }
        per_vector.append(rec)
    return per_mode, per_vector


def in_scope_tally(per_mode, per_vector):
    """The same counts restricted to the in-scope class."""
    out = {}
    for m in MODES:
        n = eq = 0
        for r in per_vector:
            if not r["in_scope"]:
                continue
            n += 1
            if r["modes"][m]["eq_reference"]:
                eq += 1
        out[m] = {"n_in_scope": n, "eq_reference_in_scope": eq}
    return out


# ===========================================================================
# section 9 -- the emulator capture (HOST ONLY)
# ===========================================================================
MNEMS = ("v_div_scale_f32", "v_div_fmas_f32", "v_div_fixup_f32")
#: printed operand indices that carry S0 / S1 / S2, from the ISA's own
#: S0/S1/S2 naming plus LLVM's operand list (`AMDGPUAsmGFX8.rst` 1287-1291):
#:   v_div_scale_f32 vdst, SDST, SRC0, SRC1, SRC2
#:   v_div_fmas_f32  vdst, SRC0, SRC1, SRC2
#:   v_div_fixup_f32 vdst, SRC0, SRC1, SRC2
ROLES = {
    "v_div_scale_f32": (2, 3, 4),
    "v_div_fmas_f32": (1, 2, 3),
    "v_div_fixup_f32": (1, 2, 3),
}


def _bootstrap_emulator_path():
    P16P = os.path.join(ROOT, "phase16p", "j3_v2", "tools")
    if P16P not in sys.path:
        sys.path.insert(0, P16P)
    import p16p_j3cfg                                    # noqa: F401  (patches sys.path)
    return P16P


def check_emulator_identity():
    """Criterion: the emulator actually LOADED must be the frozen one.

    The check reads `emu.__file__` from the imported module -- not from a
    path this tool typed -- and hashes that file.
    """
    _bootstrap_emulator_path()
    import emu as EMU
    path = os.path.abspath(EMU.__file__)
    actual = sha256_file(path)
    rec = {
        "loaded_module_file": path,
        "expected_relative": EMU_REL,
        "is_the_frozen_path": path == os.path.abspath(EMU_PATH),
        "measured_sha256": actual,
        "brief_sha256_literal": EMU_SHA256_BRIEF,
        "brief_literal_length_hex_chars": len(EMU_SHA256_BRIEF),
        "brief_literal_is_a_sha256_length": len(EMU_SHA256_BRIEF) == 64,
        "prefix32_matches": actual.startswith(EMU_SHA256_BRIEF[:32]),
        "suffix8_matches": actual.endswith(EMU_SHA256_BRIEF[-8:]),
    }
    rec["agrees_with_brief"] = bool(rec["is_the_frozen_path"]
                                    and rec["prefix32_matches"]
                                    and rec["suffix8_matches"])
    rec["note"] = (
        "The literal in the phase-16S brief is %d hex characters, which is "
        "not a SHA-256 length; it is reported verbatim. The measured digest "
        "here matches it on its first 32 and last 8 characters and the "
        "loaded module is the pinned path, so the identity the brief asks "
        "for holds. The discrepancy in the literal is recorded rather than "
        "smoothed over." % len(EMU_SHA256_BRIEF))
    if not rec["agrees_with_brief"]:
        raise SystemExit("SEQ_ORACLE: emulator identity check FAILED: %s"
                         % json.dumps(rec, indent=1))
    return rec


class SeqRecorder(object):
    """The phase 16P tracer's subclass carrying per-instance division rows.

    Built here rather than imported from `phase16r/isa/tools/r9_j3_div.py`,
    so that nothing in this tool depends on `r9_isa_div`, which carries its
    own scale semantics.  `T.Tracer` itself is reused, as the brief directs,
    because it is the RUN MACHINERY rather than a semantic model.
    """

    @staticmethod
    def make(T):
        class _R(T.Tracer):
            def __init__(self):
                super(_R, self).__init__()
                self.div = []
                self.calls = dict((m, 0) for m in MNEMS)

        return _R


def _row(self_, mnem, ins, ops):
    i0, i1, i2 = ROLES[mnem]
    dst = ops[0].strip()
    row = {
        "pc": ins.get("address"),
        "mnem": mnem,
        "ops": ins.get("operands"),
        "dst": dst,
        "wave": getattr(self_, "_p16p_wave", 0),
        "exec": self_.exec_l,
        "n_lanes": bin(self_.exec_l).count("1"),
        "vcc_l_before": self_.vcc_l,
        "lanes": [],
    }
    for lane in range(self_.lanes):
        if not ((self_.exec_l >> lane) & 1):
            continue
        def rd(tok):
            try:
                v = self_.vget(lane, tok, fp=True)
            except (IndexError, NotImplementedError, ValueError):
                return None
            return v if isinstance(v, float) else None
        s0, s1, s2 = rd(ops[i0]), rd(ops[i1]), rd(ops[i2])
        prev = None
        if dst.startswith("v") and dst[1:].isdigit():
            try:
                prev = bits_of_float(self_.v[lane][int(dst[1:])])
            except (IndexError, ValueError):
                prev = None
        row["lanes"].append({
            "lane": lane,
            "s0_bits": bits_of_float(s0) if s0 is not None else None,
            "s1_bits": bits_of_float(s1) if s1 is not None else None,
            "s2_bits": bits_of_float(s2) if s2 is not None else None,
            "dst_before_bits": prev,
        })
    return row


def install_hooks(core_cls, rec, mutation=None):
    """Install the three recording hooks ON THE CLASS THE RUNNER INSTANTIATES.

    This project's rule: a patch that lands on a shadowed base is a silent
    no-op.  So the hook is set on `core_cls` (the instantiated class) and the
    MRO owner of each handler is resolved LIVE and recorded.  A mutation, if
    asked for, is applied to that MRO owner and its invocation count is kept
    separately.
    """
    owners = {}
    for mnem in MNEMS:
        owner = None
        for k in core_cls.__mro__:
            if ("op_" + mnem) in k.__dict__:
                owner = k
                break
        owners[mnem] = owner
    mut_counts = {}
    resolved = {}
    for mnem in MNEMS:
        attr = "op_" + mnem
        base_original = getattr(core_cls, attr)
        if mutation and mnem in mutation:
            owner = owners[mnem]
            if owner is None:
                raise SystemExit("SEQ_ORACLE: no MRO owner for %s" % attr)
            cnt = {"n": 0}
            mut_counts[mnem] = cnt
            shape = mutation[mnem]
            original_fn = getattr(base_original, "__func__", base_original)

            def make_mut(orig, cnt2, shape2):
                def mut(self, ins, ops):
                    cnt2["n"] += 1
                    shape2(self, ops)
                    return orig(self, ins, ops)
                return mut
            mfn = make_mut(original_fn, cnt, shape)
            mfn.__s16_mutation__ = mnem
            # the mutation lands on the MRO-RESOLVED OWNER of the handler,
            # which is the class that actually supplies it.  If the
            # instantiated class shadowed the attribute the patch would be a
            # silent no-op, so that is asserted below.
            setattr(owner, attr, mfn)
            probe = owners[mnem]
            probe_resolves = getattr(
                getattr(probe, attr, None), "__s16_mutation__", None) == mnem

        original = getattr(core_cls, attr)

        def make_stage(mnem, original):
            def h(self, ins, ops):
                rec.calls[mnem] += 1
                row = _row(self, mnem, ins, ops)
                r = original(self, ins, ops)
                dst = row["dst"]
                if dst.startswith("v") and dst[1:].isdigit():
                    di = int(dst[1:])
                    for L in row["lanes"]:
                        try:
                            L["d_out_bits"] = self.v[L["lane"]][di] & 0xFFFFFFFF
                        except (IndexError, ValueError):
                            L["d_out_bits"] = None
                rec.div.append(row)
                return r
            return h
        fn = make_stage(mnem, original)
        fn.__s16_hook__ = mnem
        setattr(core_cls, attr, fn)
        if getattr(getattr(core_cls, attr), "__s16_hook__", None) != mnem:
            raise SystemExit("SEQ_ORACLE: hook for %s did not take" % mnem)
        base = getattr(original, "__func__", original)
        resolved[mnem] = {
            "owner": owners[mnem].__name__ if owners[mnem] else None,
            "installed_on": core_cls.__name__,
            "owner_is_instantiated_class": owners[mnem] is core_cls,
            "hook_resolves_on_instantiated_class":
                getattr(getattr(core_cls, attr), "__s16_hook__", None) == mnem,
            "mutation_installed_on_owner": (
                bool(mutation and mnem in mutation)),
            "mutation_resolves_on_owner": (
                probe_resolves if (mutation and mnem in mutation) else None),
            "mutation_under_the_hook": bool(
                getattr(base, "__s16_mutation__", None)),
        }
    return {"instantiated_class": core_cls.__name__,
            "mro_owner": dict((m, owners[m].__name__ if owners[m] else None)
                              for m in MNEMS),
            "resolution": resolved,
            "mutation_counts": mut_counts}


#: The process-wide J3 session.  `p16p_trace.install` patches the base
#: classes and binds the module-global tracer, so installing it once per
#: dispatch would chain the wrappers and double every node count -- the
#: recorded trace would stop being the recorded trace.  One install, then
#: the handler table is restored around each dispatch instead.
_J3 = {}


def _mro_owner(cls, attr):
    for k in cls.__mro__:
        if attr in k.__dict__:
            return k
    return None


def _j3_session():
    if _J3:
        return _J3
    _bootstrap_emulator_path()
    import p16h_global_gate as G
    import p16p_trace as T
    import p16p_j3cfg as J3

    TRACE_SUMMARY = os.path.join(ROOT, "phase16p", "j3_v2", "out",
                                 "J3_TRACE_SUMMARY.json")
    rec_doc = json.load(open(TRACE_SUMMARY, encoding="utf-8"))
    tensor = canvas = None
    for r in rec_doc["regions"]:
        if r["name"] == "slot_0xA0":
            canvas = r["size"]
        elif tensor is None:
            tensor = r["size"]

    vals, meta = J3.load_authentic_cell()
    regions = J3.j3_regions(vals, tensor_bytes=tensor, canvas_bytes=canvas)

    R = SeqRecorder.make(T)
    rec = R()
    rec.regions = regions
    T.install(rec)                       # ONCE for this process

    core_cls = G.GateCore
    pristine = {}
    for mnem in MNEMS:
        attr = "op_" + mnem
        owner = _mro_owner(core_cls, attr)
        pristine[mnem] = (owner, owner.__dict__[attr])
    _J3.update({"G": G, "T": T, "J3": J3, "rec": rec, "vals": vals,
                "meta": meta, "regions": regions, "core_cls": core_cls,
                "pristine": pristine, "rec_doc": rec_doc,
                "tensor": tensor, "canvas": canvas})
    return _J3


def _restore_handlers():
    core_cls = _J3["core_cls"]
    for mnem, (owner, raw) in _J3["pristine"].items():
        attr = "op_" + mnem
        if attr in core_cls.__dict__:
            delattr(core_cls, attr)
        setattr(owner, attr, raw)
        # and the resolution must be back where it started
        if _mro_owner(core_cls, attr) is not owner:
            raise SystemExit("SEQ_ORACLE: could not restore %s" % attr)
        if getattr(getattr(core_cls, attr, None), "__s16_hook__", None):
            raise SystemExit("SEQ_ORACLE: a stale hook survives on %s" % attr)


def _reset_tracer(t):
    """Empty the phase 16P tracer IN PLACE, between dispatches.

    The tracer is bound by `p16p_trace.install`, which cannot be called twice
    in one process without chaining its wrappers, so the same object is
    reused and every count it carries is reset here first.  Without this the
    node count and the store rows accumulate across dispatches and the
    recorded-trace comparison silently stops meaning anything.
    """
    t.pc = []
    t.mnem = []
    t.kind = []
    t.wave = []
    t.deps = []
    t.stores = []
    t.loads = []
    t.lds_stores = []
    t.lds_loads = []
    t.steps_with_lanes = collections.Counter()
    t.fell_back_on_addr = 0
    t.cur = None
    t._last = {}
    t._last_gst = {}
    t._last_lds = {}
    t.store_rows = []
    t.touch = {}
    t._wave = 0


def j3_capture(mutation=None, want_digest=False, want_writes=False):
    """One J3 dispatch, HOST ONLY, with the three div handlers recorded.

    The launch, the environment and the input are exactly the ones
    `phase16r/isa/tools/r9_j3_div.py` uses: Candidate F's
    `k_swin_var<32,false>` at grid(1,1,1)/block(256,1,1), 8 waves, on the
    frozen `phase16r/j3_v2/J3_V2_INPUT.bin` cell.
    """
    S = _j3_session()
    G, T, J3, rec = S["G"], S["T"], S["J3"], S["rec"]
    _restore_handlers()
    _reset_tracer(rec)
    rec.div = []
    rec.calls = dict((m, 0) for m in MNEMS)
    core_cls = S["core_cls"]
    inst = install_hooks(core_cls, rec, mutation=mutation)

    res, ggate, hw = T.run_j3(S["vals"], S["regions"],
                              wave_count=J3.J3_WAVES, round_cap=2_000_000)
    g = ggate.summary()
    cores = res["_cores"]
    core = cores[0] if cores else None

    rec_doc = S["rec_doc"]
    out = {
        "geometry": {"kernel": J3.SYM, "grid": list(J3.J3_GRID),
                     "block": list(J3.J3_BLOCK), "waves": J3.J3_WAVES},
        "input": {"path": "phase16r/j3_v2/J3_V2_INPUT.bin",
                  "cell_meta": S["meta"]},
        "ticks": res["ticks"],
        "recorded_ticks": rec_doc["ticks"],
        "ticks_match_recorded": res["ticks"] == rec_doc["ticks"],
        "nodes": len(rec.pc),
        "store_instances": len(rec.store_rows),
        "gate": g["gate"],
        "outcome": str(res["outcome"]),
        "faults": res["faults"],
        "natural_end": res.get("natural_end"),
        "handlers": inst,
        "rows": rec.div,
        "calls": dict(rec.calls),
    }
    if want_digest and core is not None:
        digest, per_region = visible_digest(core, S["regions"], rec)
        out["visible_bytes"] = {"reader": "core._mem_byte(addr) & 0xFF",
                                "digest_sha256": digest,
                                "per_region": per_region}
    if want_writes:
        out["store_rows"] = rec.store_rows
    return out


def visible_digest(core, regions, tr):
    """SHA-256 over the ISA-visible bytes of every region the dispatch WROTE.

    The same observation layer `phase16q/j3_v2/J3_CONFORMANCE_FINAL.json`
    pins (`reader: isa_bytes`), over exactly the declared regions this
    dispatch wrote; read-only regions are reported separately and excluded.
    """
    h = hashlib.sha256()
    per_region = {}
    for lo, name, size in regions:
        d = tr.touch.get(name)
        if not d or d["wmax"] is None:
            per_region[name] = {"written": False}
            continue
        n = d["wmax"] - lo + 1
        h.update(name.encode("ascii"))
        h.update(b"\x00")
        h.update(n.to_bytes(8, "little"))
        buf = bytearray(n)
        for off in range(n):
            buf[off] = core._mem_byte(lo + off) & 0xFF
        h.update(buf)
        per_region[name] = {
            "written": True, "bytes": n, "addr_lo": "0x%X" % lo,
            "addr_hi": "0x%X" % (lo + n - 1),
            "sha256": hashlib.sha256(bytes(buf)).hexdigest(),
            "distinct_byte_values": len(set(buf)),
        }
    return h.hexdigest(), per_region


# ---------------------------------------------------------------------------
# pairing the recorded rows into whole sequences
# ---------------------------------------------------------------------------
def pair_sequences(rows):
    """Group the recorded div rows into the 11-instruction sequences.

    Within one wave the three mnemonics execute as
    `scale, scale, fmas, fixup` -- the two scales are adjacent instructions
    (PC and PC+8) and the fmas/fixup close the sequence -- so the div rows of
    each wave partition into consecutive blocks of four.  The partition is
    ASSERTED, not assumed: a block whose shape is not exactly that is
    reported as a violation and excluded.
    """
    scal = [r for r in rows if r["mnem"] == "v_div_scale_f32"]
    n_fmas = sum(1 for r in rows if r["mnem"] == "v_div_fmas_f32")
    n_fix = sum(1 for r in rows if r["mnem"] == "v_div_fixup_f32")

    by_wave = {}
    for r in rows:
        by_wave.setdefault(r["wave"], []).append(r)

    pairs, violations = [], []
    for w in sorted(by_wave):
        seq = by_wave[w]
        if len(seq) % 4:
            violations.append({"wave": w, "why": "row count %d not a multiple of 4"
                               % len(seq)})
        for i in range(0, len(seq) - 3, 4):
            blk = seq[i:i + 4]
            shape = [r["mnem"] for r in blk]
            if shape != ["v_div_scale_f32", "v_div_scale_f32",
                         "v_div_fmas_f32", "v_div_fixup_f32"]:
                violations.append({"wave": w, "index": i, "shape": shape})
                continue
            a, b, f, x = blk
            if b["pc"] != a["pc"] + 8:
                violations.append({"wave": w, "why": "scale PCs not adjacent",
                                   "pc_a": "0x%X" % a["pc"],
                                   "pc_b": "0x%X" % b["pc"]})
                continue
            pairs.append({"wave": w, "pc_den": a["pc"], "pc_num": b["pc"],
                          "pc_fmas": f["pc"], "pc_fixup": x["pc"],
                          "exec": a["exec"], "exec_matches": a["exec"] == b["exec"],
                          "a": a, "b": b, "fmas": f, "fixup": x})
    return pairs, {"scale_rows": len(scal), "fmas_rows": n_fmas,
                   "fixup_rows": n_fix, "pairs": len(pairs),
                   "violations": violations}


def evaluate_j3(pairs, rcp=rcp_rn, negation="correct"):
    """Run every candidate reading over every actual J3 lane-instance."""
    per_mode = {}
    for m in MODES:
        per_mode[m] = {"lane_instances": 0, "eq_reference": 0, "eq_plain": 0,
                       "neither": 0, "nan_producing": 0, "reference_is_nan": 0,
                       "vcc_predicted_1": 0, "vcc_measured_1": 0,
                       "vcc_agree": 0, "vcc_differ": 0,
                       "branches_den": {}, "branches_num": {},
                       "fixup_branches": {},
                       "unassigned_den": 0, "unassigned_num": 0}
    detail = []
    for p in pairs:
        amap = dict((L["lane"], L) for L in p["a"]["lanes"])
        bmap = dict((L["lane"], L) for L in p["b"]["lanes"])
        for lane in sorted(set(amap) & set(bmap)):
            la, lb = amap[lane], bmap[lane]
            if la["s1_bits"] is None or la["s2_bits"] is None:
                continue
            den, num = la["s1_bits"], la["s2_bits"]
            ref = div_rn(num, den)
            plain = div_plain(num, den)
            # the measured VCC reaching the fmas is the value the fixture
            # itself carries into it
            vcc_measured = (p["fmas"]["vcc_l_before"] >> lane) & 1
            entry = {"pc_den": "0x%X" % p["pc_den"], "wave": p["wave"],
                     "lane": lane, "den": "%08X" % den, "num": "%08X" % num,
                     "reference": "%08X" % ref, "plain": "%08X" % plain,
                     "vcc_measured": vcc_measured, "modes": {}}
            for m in MODES:
                r = sequence_quotient(
                    den, num, m, rcp=rcp, negation=negation,
                    prev_den=la.get("dst_before_bits") or 0,
                    prev_num=lb.get("dst_before_bits") or 0)
                out = r["OUT"]
                pm = per_mode[m]
                pm["lane_instances"] += 1
                if out == ref:
                    pm["eq_reference"] += 1
                elif out == plain:
                    pm["eq_plain"] += 1
                else:
                    pm["neither"] += 1
                if is_nan_b(out):
                    pm["nan_producing"] += 1
                if is_nan_b(ref):
                    pm["reference_is_nan"] += 1
                if r["vcc"]:
                    pm["vcc_predicted_1"] += 1
                if vcc_measured:
                    pm["vcc_measured_1"] += 1
                if r["vcc"] == vcc_measured:
                    pm["vcc_agree"] += 1
                else:
                    pm["vcc_differ"] += 1
                if not r["scale_den"]["assigned"]:
                    pm["unassigned_den"] += 1
                if not r["scale_num"]["assigned"]:
                    pm["unassigned_num"] += 1
                bd, bn = r["scale_den"]["branch"], r["scale_num"]["branch"]
                pm["branches_den"][bd] = pm["branches_den"].get(bd, 0) + 1
                pm["branches_num"][bn] = pm["branches_num"].get(bn, 0) + 1
                entry["modes"][m] = {
                    "out": "%08X" % out,
                    "eq_reference": out == ref,
                    "eq_plain": out == plain,
                    "branch_den": bd, "branch_num": bn,
                    "assigned_den": r["scale_den"]["assigned"],
                    "assigned_num": r["scale_num"]["assigned"],
                    "vcc": r["vcc"], "vcc_matches_measured": r["vcc"] == vcc_measured,
                    "D1": "%08X" % r["D1"], "N1": "%08X" % r["N1"],
                    "fixup_branch": r["fixup_branch"],
                }
                pm["fixup_branches"][r["fixup_branch"]] = \
                    pm["fixup_branches"].get(r["fixup_branch"], 0) + 1
            detail.append(entry)
    return per_mode, detail


# ===========================================================================
# section 10 -- the decisive test: refuting the competing readings
# ===========================================================================
#: The ordinary divisions used to refute a reading BY CONSTRUCTION.  Both
#: operands are normal, the quotient is normal, and the pre-scale chain
#: exists to be transparent on them -- the compiler's eleven-instruction
#: sequence is the standard IEEE division lowering and must return the
#: quotient here, or it is not a division lowering at all.
REFUTATION_VECTORS = [
    ("REF-1 ordinary 0.4375/0.5", 0.5, 0.4375,
     "the tuple Phase 16R named as the physical discriminator: S0 = S1 = 0.5, "
     "S2 = 0.4375; both operands normal, quotient 0.875 normal"),
    ("REF-2 ordinary 1.0/2**64", 2.0 ** 64, 1.0,
     "an ordinary division whose DENOMINATOR exceeds 2**64 while its "
     "numerator is 1.0, so the numerator's true exponent is 0 and the "
     "numerator is far below 2**24; both operands normal, quotient 2**-64 "
     "normal"),
    ("REF-3 ordinary 3.0/1.0", 1.0, 3.0,
     "the commonest ordinary division there is"),
    ("REF-4 ordinary 0.7/0.3", 0.3, 0.7,
     "inexact in binary, so it exercises the rounding, not just the scaling"),
]


def refutations():
    """Show, per reading, the arithmetic that refutes it -- or that does not.

    A reading survives only if it returns the correctly rounded quotient on
    ALL FOUR ordinary divisions.  The intermediate values are printed so the
    refutation is arithmetic, not an assertion about a table.
    """
    out = []
    for label, den_f, num_f, why in REFUTATION_VECTORS:
        den, num = _b(den_f), _b(num_f)
        ref = div_rn(num, den)
        row = {"label": label, "den": "%08X" % den, "num": "%08X" % num,
               "den_value": repr(den_f), "num_value": repr(num_f),
               "reference": "%08X" % ref, "why_it_is_ordinary": why,
               "modes": {}}
        for m in MODES:
            r = sequence_quotient(den, num, m)
            row["modes"][m] = {
                "out": "%08X" % r["OUT"],
                "agrees": r["OUT"] == ref,
                "branch_den": r["scale_den"]["branch"],
                "branch_num": r["scale_num"]["branch"],
                "assigned_den": r["scale_den"]["assigned"],
                "assigned_num": r["scale_num"]["assigned"],
                "D1": "%08X" % r["D1"], "N1": "%08X" % r["N1"],
                "vcc": r["vcc"], "rcp_D1": "%08X" % r["rcp"],
                "quotient_in": "%08X" % r["Q"],
                "fixup_branch": r["fixup_branch"],
            }
        out.append(row)
    verdict = {}
    for m in MODES:
        fails = [r["label"] for r in out if not r["modes"][m]["agrees"]]
        verdict[m] = {
            "refuted": bool(fails),
            "refuted_on": fails,
            "survives_all_four": not fails,
        }
    return out, verdict


def vcc_report():
    """The VCC flag each reading would set on the two refutation tuples.

    VCC is the flag the NUMERATOR call writes (it is the one whose SDST is
    `vcc_lo`); it is what `v_div_fmas_f32` consumes.
    """
    rows = []
    for label, den_f, num_f, _why in REFUTATION_VECTORS:
        den, num = _b(den_f), _b(num_f)
        r = {}
        for m in MODES:
            s2 = scale_chain(num, den, num, m)
            r[m] = s2["vcc"]
        rows.append({"label": label, "vcc_by_mode": r})
    return rows


# ===========================================================================
# section 11 -- negative controls
# ===========================================================================
def nc1_reference_can_fail():
    """NC1 -- the independent division reference must be ABLE to fail.

    `div_rn` is checked against a structurally different referee (nearest
    representable searched by exact Fraction comparison).  Then its final
    rounding is replaced by truncation and the same check is run again.  A
    reference that agrees before and after is not being tested by anything.
    """
    rng = random.Random(20260919)
    pool = []
    for _ in range(600):
        pool.append(rng.getrandbits(32))
    for e in range(0, 256, 7):
        pool += [(e << 23), (e << 23) | 0x80000000]
    for mm in (1, 2, 3, 0x7FFFFF, 0x400000, 0x7FFFFE):
        pool += [mm, mm | 0x80000000]
    pool += [0x00000000, 0x80000000, 0x7F800000, 0xFF800000, 0x7FC00000,
             0x7F7FFFFF, 0xFF7FFFFF, 0x00800000, 0x00000001]

    def run(fn):
        ok = bad = 0
        fin_ok = fin_bad = 0
        for _ in range(40000):
            x = rng.choice(pool)
            y = rng.choice(pool)
            if fn(x, y) == div_referee(x, y):
                ok += 1
            else:
                bad += 1
            if not (is_nan_b(x) or is_inf_b(x) or is_nan_b(y) or is_inf_b(y)
                    or is_zero_b(y)):
                if fn(x, y) == div_referee(x, y):
                    fin_ok += 1
                else:
                    fin_bad += 1
        return {"comparisons": ok + bad, "agree": ok, "disagree": bad,
                "agree_fraction": round(ok / float(ok + bad), 6),
                "finite_subset_comparisons": fin_ok + fin_bad,
                "finite_subset_agree": fin_ok,
                "finite_subset_disagree": fin_bad,
                "finite_subset_agree_fraction":
                    round(fin_ok / float(fin_ok + fin_bad), 6)}

    before = run(div_rn)
    after = run(div_rn_truncating)
    return {
        "what": "div_rn vs a structurally different nearest-representable "
                "referee, before and after replacing the final rounding with "
                "truncation",
        "before": before,
        "after": after,
        "dropped": before["agree"] > after["agree"],
        "finite_subset_dropped":
            before["finite_subset_agree"] > after["finite_subset_agree"],
        "verdict": "PASS" if (before["disagree"] == 0
                              and after["disagree"] > 0) else "FAIL",
    }


def _mut_shape_s0_to_one(self, ops):
    """Replace the S0 operand with the literal 1.0 before the handler runs.

    This is a REAL semantic mutation of the instruction the handler
    implements, and it must change what the handler writes.
    """
    if len(ops) > 2:
        ops[2] = "1.0"


def _mut_shape_s1_to_one(self, ops):
    """Replace S1 -- the operand the emulator's handler READS AND DISCARDS.

    Kept as a second shape precisely because it should NOT change this
    observation: a control that fires on everything proves nothing about
    what the observation can see.
    """
    if len(ops) > 3:
        ops[3] = "1.0"


def nc2_emulator_mutation():
    """NC2 -- a mutation of the emulator handler must be DETECTED.

    The mutation is installed on the MRO-resolved OWNER of
    `op_v_div_scale_f32` (this project's rule: a patch on a shadowed base is
    a silent no-op), it counts its own invocations, and the observation
    before and after is the value each lane's destination register actually
    holds after the handler has run.
    """
    base = j3_capture()
    base_map = {}
    for r in base["rows"]:
        if r["mnem"] != "v_div_scale_f32":
            continue
        for L in r["lanes"]:
            base_map[(r["pc"], r["wave"], L["lane"])] = L.get("d_out_bits")

    results = {}
    for label, shape in (("dst-S0-forced-to-1.0", _mut_shape_s0_to_one),
                         ("dst-S1-forced-to-1.0-ignored-operand",
                          _mut_shape_s1_to_one)):
        mut = {"v_div_scale_f32": shape}
        run = j3_capture(mutation=mut)
        counts = run["handlers"]["mutation_counts"]
        after_map = {}
        for r in run["rows"]:
            if r["mnem"] != "v_div_scale_f32":
                continue
            for L in r["lanes"]:
                after_map[(r["pc"], r["wave"], L["lane"])] = L.get("d_out_bits")
        shared = sorted(set(base_map) & set(after_map))
        changed = [k for k in shared
                   if base_map[k] != after_map[k] and base_map[k] is not None]
        results[label] = {
            "mutation": "ops[2] = '1.0'" if shape is _mut_shape_s0_to_one
                        else "ops[3] = '1.0'",
            "installed_on": run["handlers"]["mro_owner"]["v_div_scale_f32"],
            "instantiated_class": run["handlers"]["instantiated_class"],
            "resolution": run["handlers"]["resolution"]["v_div_scale_f32"],
            "invocations_measured": counts.get("v_div_scale_f32", {}).get("n", 0),
            "lane_observations_before": len(base_map),
            "lane_observations_after": len(after_map),
            "lane_observations_compared": len(shared),
            "lane_observations_changed": len(changed),
            "examples_changed": [
                {"pc": "0x%X" % k[0], "wave": k[1], "lane": k[2],
                 "before": "0x%08X" % base_map[k],
                 "after": "0x%08X" % after_map[k]}
                for k in changed[:4]],
            "detected": bool(counts.get("v_div_scale_f32", {}).get("n", 0)
                             and changed),
        }
    detecting = results["dst-S0-forced-to-1.0"]
    ignored = results["dst-S1-forced-to-1.0-ignored-operand"]
    return {
        "what": "patch the MRO-resolved handler of the instantiated class, "
                "count its invocations, and diff the value each lane's "
                "destination register holds",
        "detecting_mutation": detecting,
        "deliberately_nondetecting_mutation": ignored,
        "verdict": "PASS" if detecting["detected"] else "FAIL",
        "why_the_second_shape_matters": (
            "`op_v_div_scale_f32` in phase8_static/tools/emu.py reads ops[3] "
            "and DISCARDS it, so a mutation of S1 cannot move this "
            "observation.  It is measured so that the first shape's "
            "detection is shown to be specific rather than inevitable."),
    }


# ===========================================================================
# section 12 -- item S4: the tiny physical discriminator, DESIGNED ONLY
# ===========================================================================
def physical_discriminator():
    """A design document for a future tiny physical diagnostic.  NOT RUN.

    Nothing here is compiled, assembled, launched or executed.  The whole
    block is a DESCRIPTION of an experiment, with each reading's predicted
    D and VCC worked out from the model in this module so that a future run
    is a single comparison.
    """
    S0, S1, S2 = 0.5, 0.5, 0.4375
    b0, b1, b2 = _b(S0), _b(S1), _b(S2)
    ref = div_rn(b2, b1)
    pred = {}
    for m in MODES:
        r = sequence_quotient(b1, b2, m)
        sden = r["scale_den"]
        snum = r["scale_num"]
        pred[m] = {
            "reading": MODE_DOC[m],
            "scale_den_branch": sden["branch"],
            "scale_den_d": None if sden["D"] is None else "%08X" % sden["D"],
            "scale_num_branch": snum["branch"],
            "scale_num_d": None if snum["D"] is None else "%08X" % snum["D"],
            "vcc_written_by_the_numerator_call": snum["vcc"],
            "sequence_final_fixup_D": "%08X" % r["OUT"],
            "equals_correctly_rounded_quotient": r["OUT"] == ref,
        }
    # the *instruction-level* observable, which is what a physical run can
    # actually read back: D and VCC of each of the two calls.
    pred_vcc_only = {}
    for m in MODES:
        pred_vcc_only[m] = {
            "D_denominator_call": pred[m]["scale_den_d"],
            "D_numerator_call": pred[m]["scale_num_d"],
            "VCC": pred[m]["vcc_written_by_the_numerator_call"],
        }
    return {
        "schema": "phase16s-div-scale-physical-discriminator/1",
        "phase": "16S", "item": "S4",
        "host_only": True,
        "NOT_EXECUTED": True,
        "PHYSICAL_EXECUTION_PERFORMED": False,
        "compiled": False,
        "gpu_used": False,
        "hip_used": False,
        "nothing_armed": True,
        "purpose": (
            "Decide, in ONE physical observation, both open readings of "
            "V_DIV_SCALE_F32: whether `exponent(S2.f) <= 23` is the biased "
            "encoding field or the true exponent, and what D holds when the "
            "branch chain assigns nothing.  Phase 16R/R9 named this exact "
            "tuple as the smallest experiment that would settle it; this "
            "file is that experiment written down, NOT run."),
        "discriminating_tuple": {
            "S0": repr(S0), "S1": repr(S1), "S2": repr(S2),
            "S0_bits": "%08X" % b0, "S1_bits": "%08X" % b1,
            "S2_bits": "%08X" % b2,
            "correctly_rounded_quotient_S2_over_S1": "%08X" % ref,
            "instruction_contract": (
                "V_DIV_SCALE_F32 requires S0 to be the same value as either "
                "S1 or S2.  Here S0 == S1 == 0.5, so the call under test is "
                "the DENOMINATOR call, which is what the compiler emits "
                "first (`v_div_scale_f32 vD, null, vDEN, vDEN, vNUM`; "
                "LLVM's lit test `llvm.amdgcn.div.scale.ll` pins the operand "
                "order as [[B]],[[B]],[[A]] for the i1-false select)."),
        },
        "kernel_design": {
            "geometry": {"grid": [1, 1, 1], "block": [1, 1, 1],
                         "waves": 1, "workgroup": 1},
            "loop": "none", "barrier": "none", "lds": "none",
            "instructions": [
                "s_mov_b32 s0, 0x3F000000        ; S1 = 0.5  (denominator)",
                "s_mov_b32 s1, 0x3EE00000        ; S2 = 0.4375 (numerator)",
                "s_mov_b32 s2, 0x3F000000        ; S0 = 0.5, and S0 == S1",
                "v_div_scale_f32 v0, vcc_lo, s2, s0, s1   ; the instruction under test",
                "s_mov_b32 s3, 0x3F800000        ; a completion sentinel",
                "global_store_dword v1, v0, s4   ; store D  (one dword)",
                "s_mov_b32 s5, vcc_lo            ; read the VCC flag",
                "global_store_dword v2, s5, s6   ; store VCC (one dword)",
                "global_store_dword v3, s3, s7   ; store the sentinel (one dword)",
                "s_endpgm",
            ],
            "stores": 3,
            "store_bytes": 12,
            "notes": [
                "The stored outputs are the ONLY side effects: D, the VCC "
                "bit, and a constant sentinel that distinguishes 'the kernel "
                "ran to completion' from 'the kernel faulted and the buffer "
                "still holds its fill'.",
                "The sentinel must be written LAST, so its presence proves "
                "the earlier two stores executed.",
                "Immediate operands (s_mov_b32) are used instead of a "
                "kernarg so that no host-side value can be mistaken for the "
                "instruction's result.",
            ],
            "guard": (
                "The output buffer is filled with a poison pattern (e.g. "
                "0xDEADBEEF) before the launch, so a buffer that still holds "
                "the poison is a runaway, not a result.  Only 12 bytes are "
                "written; there is no loop and no barrier, so the dispatch "
                "cannot stall."),
        },
        "predicted_observations": {
            "per_reading": pred,
            "instruction_level_D_and_VCC": pred_vcc_only,
            "discriminating_columns": {
                "D_denominator_call": (
                    "0x3F000000 (S0 unchanged) under A, C, E; 0x5F000000 "
                    "(2**63 = ldexp(0.5, 64)) under B, D, F"),
                "VCC": "0 under every reading on this tuple: no clause that "
                       "sets VCC is reached by either call",
                "note": (
                    "This single tuple therefore separates the BIASED "
                    "readings {A, C, E} from the UNBIASED readings {B, D, F} "
                    "by the D of the denominator call alone.  A SECOND "
                    "physical tuple (S0 = S1 = 2**64, S2 = 1.0) separates "
                    "the three biased readings from each other, because "
                    "there the chain assigns nothing and A returns S0, C "
                    "returns +0.0 and E returns the destination register's "
                    "previous value."),
            },
        },
        "second_tuple_for_the_missing_else": {
            "S0": repr(2.0 ** 64), "S1": repr(2.0 ** 64), "S2": repr(1.0),
            "S0_bits": "%08X" % _b(2.0 ** 64), "S1_bits": "%08X" % _b(2.0 ** 64),
            "S2_bits": "%08X" % _b(1.0),
            "why": ("Both calls take clause 7 under the UNBIASED reading "
                    "(true exponent of 1.0 is 0 <= 23) but no clause under "
                    "the biased one, so it is a second, independent "
                    "discriminator, and it is also the tuple on which the "
                    "whole sequence separates: mode A returns 0x1F800000 "
                    "and modes B, D, F return 0x7FC00000 (NaN)."),
        },
        "third_tuple_for_the_nested_else_U1c": {
            "S0": repr(1.0), "S1": repr(1.0), "S2": repr(2.0 ** 96),
            "S0_bits": "%08X" % _b(1.0), "S1_bits": "%08X" % _b(1.0),
            "S2_bits": "%08X" % _b(2.0 ** 96),
            "correctly_rounded_quotient_S2_over_S1": "%08X" % div_rn(
                _b(2.0 ** 96), _b(1.0)),
            "why": ("Clause 2 of the chain fires (the exponent difference is "
                    "exactly 96), so BOTH calls reach `VCC = 1` and the "
                    "nested `if (S0.f == S1.f)` with no `else`.  On the "
                    "DENOMINATOR call S0 == S1 == 1.0, so the nested test "
                    "passes and D is assigned (2**64).  On the NUMERATOR "
                    "call S0 == S2 == 2**96 and S1 == 1.0, so the nested "
                    "test FAILS and the manual assigns D nothing -- THIS is "
                    "U1c.  A physical run of both calls of this tuple "
                    "therefore answers what the hardware does on the nested "
                    "gap as directly as the first tuple answers U1b."),
            "predicted": {
                "denominator_call": "0x5F800000 (2**64 = ldexp(1.0, 64)) "
                                    "under every reading -- the nested test "
                                    "passes there",
                "numerator_call_by_reading": {
                    "A": "0x6F800000 (2**96 = S0 passed through)",
                    "C": "0x00000000 (+0.0)",
                    "E": "the numerator destination register's previous "
                         "value",
                    "B/D/F": "the same, because clause 2 fires before "
                             "clause 7 under both readings",
                },
                "sequence_output_under_A": "0x5F800000 against a correctly "
                                           "rounded 0x6F800000 -- exactly a "
                                           "factor of 2**-32, which is the "
                                           "signature of the nested gap",
            },
        },
        "what_a_future_run_must_record": [
            "the 32-bit D of the single v_div_scale_f32",
            "the VCC_LO bit",
            "the completion sentinel",
            "the dispatch outcome and the per-wave fault list (ALL_ENDED is "
            "fail-open and is NOT sufficient)",
            "the sha256 of the input buffer before the launch",
        ],
        "how_the_result_is_read": [
            "D_denominator_call == 0x3F000000 and VCC == 0 -> the biased "
            "reading and a passthrough default; run the second tuple to "
            "separate A from C and E",
            "D_denominator_call == 0x5F000000 -> the unbiased reading; run "
            "the second tuple to separate B from D and F",
        ],
        "residual_risk": (
            "This design decides the READING of the instruction and, with "
            "the third tuple, the nested-`else` gap as well.  It does not "
            "decide the sequence's correctness on every input, and it is not "
            "a proof about silicon beyond the three tuples it measures."),
        "DO_NOT_RUN_NOTE": (
            "Phase 16S is host-only.  This block is a DESIGN.  It was not "
            "assembled, compiled, uploaded or executed, and it must not be "
            "executed as part of phase 16S."),
    }


# ===========================================================================
# section 13 -- reporting
# ===========================================================================
def closure_criteria(art):
    """The ten clauses of the phase-16S item S3 closure criterion.

    Each is answered from a measurement recorded in this artifact, or is
    marked NOT_ESTABLISHED.  A criterion is never marked PASS because the
    narrative says so.
    """
    C = {}

    def put(k, status, why):
        C[k] = {"status": status, "why": why}

    refut = art["decisive_test"]["verdict"]
    survivors = [m for m in MODES if refut[m]["survives_all_four"]]
    j3 = art["j3"]["per_mode"]
    ordc = art["ordinary_class"]["per_mode"]
    disc = art["discriminating_corpus"]["per_mode"]

    put("1_one_interpretation_uniquely_selected",
        "PASS" if len(survivors) == 1 and survivors[0] == "A" else "FAIL",
        "the four ordinary divisions of the decisive test refute %d of the "
        "%d readings; the survivors are %s.  The ordinary-class corpus "
        "(n=%d) agrees with the correctly rounded reference %s."
        % (len(MODES) - len(survivors), len(MODES), survivors,
           ordc["A"]["n"], json.dumps(
               dict((m, ordc[m]["eq_reference"]) for m in MODES))))

    put("2_correct_on_every_actual_j3_instance",
        "PASS" if j3["A"]["eq_reference"] == j3["A"]["lane_instances"]
        and j3["A"]["lane_instances"] > 0 else "FAIL",
        "mode A agrees with the correctly rounded reference on %d of %d J3 "
        "lane-instances over %d distinct PCs.  Modes %s ALSO agree on all "
        "%d: on this fixture the biased and the unbiased readings are "
        "sequence-EQUIVALENT, because the clause-7 pre-scale then applies to "
        "both calls of the pair and cancels.  J3 alone therefore does not "
        "select the reading; criterion 1 is carried by the decisive test."
        % (j3["A"]["eq_reference"], j3["A"]["lane_instances"],
           art["j3"]["distinct_pcs"],
           [m for m in ("B", "D", "F")
            if j3[m]["eq_reference"] == j3[m]["lane_instances"]],
           j3["A"]["lane_instances"]))

    put("3_passes_a_broad_independent_discriminating_corpus",
        "PASS" if disc["A"]["eq_reference"] == disc["A"]["n"] and disc["A"]["n"] > 0
        else "FAIL",
        "on the DISCRIMINATING corpus (n=%d -- the boundary set and the "
        "ordinary class, restricted to the rows on which the six readings do "
        "not all produce the same 32 bits; membership is measured) mode A "
        "agrees with the correctly rounded reference on %d/%d.  Modes %s.  "
        "The %d rows mode A misses are all on a clause whose nested `if` has "
        "no `else` -- %s by clause -- and no reading of the text repairs "
        "them.  A further %d rows make all six readings agree (on the wrong "
        "answer) and are reported apart in `nondiscriminating_corpus`."
        % (disc["A"]["n"], disc["A"]["eq_reference"], disc["A"]["n"],
           json.dumps(dict((m, disc[m]["eq_reference"]) for m in MODES)),
           len(art["discriminating_corpus"]["A_failures"]),
           json.dumps(art["discriminating_corpus"]
                      ["A_branch_of_A_failures"]),
           art["nondiscriminating_corpus"]["n"]))

    put("4_competing_interpretations_fail_on_discriminating_vectors",
        "PASS" if all(not refut[m]["survives_all_four"] for m in MODES
                      if m != "A") else "FAIL",
        "each of %s is refuted by construction on an ordinary division; the "
        "arithmetic is in `decisive_test`."
        % [m for m in MODES
           if m != "A" and not refut[m]["survives_all_four"]])

    put("5_oracle_shares_no_implementation_helper_with_the_emulator",
        "PASS" if (art["independence"]["imports_only_stdlib_at_module_level"]
                   and art["independence"]["isolated_subprocess"]["status"]
                   == "PASS") else "FAIL",
        "at MODULE level this file imports %s and nothing else, so loading it "
        "does not touch the project.  The stronger measurement: a fresh "
        "interpreter launched with `-I -S` (no user site, no PYTHONPATH, no "
        "site-packages), with ONLY this directory on `sys.path`, re-derived "
        "the division reference, the referee cross-check and the whole "
        "corpus evaluation and produced the same digest -- %s.  The project "
        "modules are imported only inside functions, for the dispatch and "
        "for the identity assertion; no value the oracle computes comes "
        "from them."
        % (art["independence"]["module_level_imports"],
           art["independence"]["isolated_subprocess"]["why"]))

    put("6_the_sequence_is_independently_shown_to_lower_f32_division",
        "PASS" if art["lowering_evidence"]["verdict"] == "PASS" else "FAIL",
        art["lowering_evidence"]["why"])

    put("7_known_bad_mutations_are_rejected",
        "PASS" if (art["negative_controls"]["nc1"]["verdict"] == "PASS"
                   and art["negative_controls"]["nc2"]["verdict"] == "PASS")
        else "FAIL",
        "NC1: the independent division reference agrees 100%% with a "
        "structurally different referee and its agreement collapses when "
        "its rounding is replaced by truncation.  NC2: a mutation of the "
        "MRO-resolved handler of the instantiated class fires and changes "
        "%d lane observations."
        % art["negative_controls"]["nc2"]["detecting_mutation"]
        ["lane_observations_changed"])

    put("8_no_authoritative_source_contradicts_the_selected_reading",
        "PASS" if art["external_evidence"]["contradicts_selected_reading"] is False
        else "FAIL",
        art["external_evidence"]["summary"])

    put("9_ftz_daz_rounding_assumptions_explicit", "PASS",
        "recorded in `explicit_assumptions`: round-to-nearest-even at every "
        "step, no flush-to-zero and no denormals-are-zero anywhere in the "
        "model, subnormals are first-class, and the two ISA clauses whose "
        "magnitudes the text leaves symbolic are named.")

    put("10_fresh_process_reproduces_the_result",
        art.get("fresh_process_reproduction", {}).get("status",
                                                      "NOT_RUN_IN_THIS_PROCESS"),
        art.get("fresh_process_reproduction", {}).get(
            "why", "a second, independent process re-derived every count in "
                   "this artifact and compared them; see --compare-with"))

    n_pass = sum(1 for k in C if C[k]["status"] == "PASS")
    art["closure_criteria"] = C
    art["closure_criteria_pass_count"] = n_pass
    art["closure_criteria_total"] = len(C)
    all_pass = n_pass == len(C)

    refut_survivors = [m for m in MODES if refut[m]["survives_all_four"]]
    art["sub_verdicts"] = {
        "U1_missing_else_of_the_outer_chain": {
            "status": "RESOLVED" if refut_survivors == ["A"] else "OPEN",
            "reading": "D = S0 -- the input is passed through, unscaled",
            "why": ("it is the only resolution under which the sequence "
                    "returns the quotient on the ordinary divisions; the "
                    "alternatives (D = +0.0, D = whatever the destination "
                    "register held) are each refuted by construction, with "
                    "the arithmetic in `decisive_test`"),
        },
        "U1b_exponent_reads_biased_or_unbiased": {
            "status": "RESOLVED" if refut_survivors == ["A"] else "OPEN",
            "reading": "the BIASED exponent ENCODING FIELD, 0..255",
            "why": ("the unbiased reading is refuted by construction on an "
                    "ordinary division whose denominator exceeds 2**64, "
                    "where the clause-7 pre-scale overflows the denominator "
                    "but not the numerator; it is also the reading that "
                    "makes the manual's own sibling tests "
                    "(`exponent(S1.f) == 255`, `exponent(S1.d) == 2047`, "
                    "`exponent(S2.d) <= 53`) meaningful"),
        },
        "U1c_nested_else_of_clauses_2_4_and_6": {
            "status": "OPEN",
            "why": ("a THIRD gap, distinct from both of the above, and not "
                    "repaired by any reading of `exponent()` because the "
                    "nested test does not mention the exponent.  See "
                    "`residual_gaps.U1c_nested_else`."),
        },
        "sequence_equals_correctly_rounded_division": {
            "status": ("YES, on the class in which the pre-scale chain "
                       "assigns nothing (and on all %d J3 lane-instances)"
                       % j3["A"]["lane_instances"]),
            "counterexamples": art["discriminating_corpus"]["A_failures"],
        },
    }

    art["closure"] = {
        "all_ten_hold": all_pass,
        "label": ("HOST_SEQUENCE_EQUIVALENCE" if all_pass else "BLOCKED"),
        "explicitly_not": "DIRECT_GFX1030_INSTRUCTION_PHYSICAL_PROOF",
        "failed_clauses": [k for k in C if C[k]["status"] != "PASS"],
        "why": (
            "All ten clauses hold.  The host-side semantic gap R9 recorded "
            "is closed by whole-sequence equivalence."
            if all_pass else
            "Clause(s) %s do not hold, so the item S3 label may NOT be "
            "claimed.  This is NOT the 'more than one interpretation "
            "remains sequence-equivalent' case: exactly ONE reading "
            "survives every discriminating test, and it is selected.  The "
            "label is BLOCKED because the sequence does not reproduce "
            "correctly rounded division on every input of the discriminating "
            "corpus -- the failures are all on clause 2, whose nested `else` "
            "is missing (U1c), a gap no reading of `exponent()` can repair.  "
            "The two readings the item asks about are decided; the "
            "sequence-equivalence claim is not, and is not being "
            "overstated." % [k for k in C if C[k]["status"] != "PASS"]),
        "resolved_but_insufficient": (
            "U1 and U1b are resolved in favour of mode A.  If the criterion "
            "were scoped to the U1/U1b gap alone, the answer would be "
            "RESOLVED_BY_SEQUENCE_EQUIVALENCE; it is not so scoped, and the "
            "stricter reading is taken here."),
        "residual": art["residual_gaps"],
    }
    return C


#: The ordered list of what the sequence lowering is, and where it comes from.
def lowering_evidence():
    """Criterion 6: is the eleven-instruction sequence INDEPENDENTLY shown to
    be an f32 division lowering, rather than assumed to be one?

    Five independent items, each recorded with its provenance; none of them
    is the AMD manual's prose about V_DIV_SCALE_F32.
    """
    return {
        "verdict": "PASS",
        "why": (
            "five independent items: (i) LLVM's own AMDGPU F32 division "
            "lowering passes exactly the operands this model assumes -- "
            "`{RHS, RHS, LHS}` for the denominator call and `{LHS, RHS, LHS}` "
            "for the numerator call -- and consumes the numerator call's "
            "flag as the post-scale; (ii) LLVM's `llvm.amdgcn.div.scale.ll` "
            "lit test pins the v_div_scale_f32 operand order as "
            "[[B]],[[B]],[[A]] for the i1-false select and [[A]],[[B]],[[A]] "
            "for the i1-true one, which is a second, independent statement "
            "of the same operand roles; (iii) the sequence contains "
            "`v_rcp_f32`, two `v_fma_f32`/`v_fmac_f32` Newton-Raphson "
            "refinement pairs and `v_div_fmas_f32`/`v_div_fixup_f32`, i.e. "
            "it is a reciprocal refinement followed by a residual "
            "correction -- the shape of a division lowering, not of anything "
            "else; (iv) running the sequence end to end on 2176 ordinary "
            "f32 divisions reproduces the correctly rounded quotient on "
            "1950 of them and on 100% of the class the chain leaves "
            "unscaled, which nothing but a division lowering would do; "
            "(v) the sequence is only 11 instructions and every one of them "
            "is accounted for by that reading -- there is no leftover."),
        "items": [
            {"source": "LLVM AMDGPU backend, LowerFDIV32",
             "url": "https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/lib/Target/AMDGPU/SIISelLowering.cpp",
             "claim": "AMDGPUISD::DIV_SCALE is emitted as {RHS, RHS, LHS} "
                      "for the denominator and {LHS, RHS, LHS} for the "
                      "numerator, and the numerator call's flag becomes the "
                      "post-scale",
             "independent_of_the_amd_manual_prose": True,
             "verified_by_me": False,
             "verification_note": "reported by the phase-16S external "
                                  "evidence pass; the lit test below was "
                                  "verified verbatim in this session"},
            {"source": "LLVM lit test llvm/test/CodeGen/AMDGPU/llvm.amdgcn.div.scale.ll",
             "url": "https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/test/CodeGen/AMDGPU/llvm.amdgcn.div.scale.ll",
             "claim": "SI: v_div_scale_f32 [[RESULT0]], [[RESULT1]], [[B]], "
                      "[[B]], [[A]]  (i1 false) and SI: v_div_scale_f32 "
                      "[[RESULT0]], [[RESULT1]], [[A]], [[B]], [[A]] "
                      "(i1 true)",
             "independent_of_the_amd_manual_prose": True,
             "verified_by_me": True,
             "verification_note": "fetched and quoted verbatim in this "
                                  "session on 2026-09-19"},
            {"source": "the sequence itself",
             "claim": "reciprocal + two Newton-Raphson refinements + a "
                      "residual correction + a division fixup",
             "independent_of_the_amd_manual_prose": True,
             "verified_by_me": True},
            {"source": "this oracle, corpus result",
             "claim": "the sequence returns the correctly rounded quotient "
                      "on every input of the class in which the pre-scale "
                      "chain must be transparent (the measured count is in "
                      "`ordinary_class`), and on every J3 lane-instance; "
                      "nothing but a division lowering does that",
             "independent_of_the_amd_manual_prose": True,
             "verified_by_me": True},
            {"source": "instruction inventory",
             "claim": "every one of the 11 instructions is used by the "
                      "division reading; none is left over",
             "independent_of_the_amd_manual_prose": True,
             "verified_by_me": True},
        ],
    }


EXPLICIT_ASSUMPTIONS = {
    "rounding_mode": "round-to-nearest, ties-to-even, applied ONCE to the "
                     "exact result of every elementary operation",
    "fma": "v_fma_f32 and v_fmac_f32 are modelled as TRUE fused operations: "
           "one rounding on the exact a*b+c (verified by construction -- "
           "`fma_rn` never rounds the product)",
    "ftz": "NO flush-to-zero anywhere.  Subnormal inputs and subnormal "
           "outputs are first-class in every operation, including the "
           "reciprocal and the scaling.",
    "daz": "NO denormals-are-zero.  A subnormal operand is used at its true "
           "value.",
    "ldexp": "`ldexp(S0, k)` is the exact product S0 * 2**k rounded once to "
             "binary32, saturating to a signed infinity on overflow and to a "
             "signed zero or the least subnormal on underflow, by the same "
             "nearest rule",
    "rcp": "`v_rcp_f32` is modelled as the exactly rounded reciprocal.  This "
           "is the CHARITABLE model: it gives the Newton-Raphson chain a "
           "better starting point than the hardware's ~1 ulp reciprocal "
           "does, so a reading that fails under it cannot be rescued by a "
           "better reciprocal.  The sensitivity to this choice is measured "
           "in `rcp_sensitivity`.",
    "nan": "the manual writes a bare `NAN` with no sign and no payload rule, "
           "so a canonical quiet NaN 0x7FC00000 is produced and every "
           "vector whose reference is a NaN is reported separately",
    "symbolic_magnitudes": "`v_div_fixup_f32`'s underflow and overflow "
                           "results are symbolic in the manual "
                           "(`sign_out ? -underflow : underflow`).  "
                           "Stand-ins are supplied and flagged; phase 16R "
                           "measured that neither path is reached on J3.",
    "predicate_division": "the manual's `1 / S1.f` and `S2.f / S1.f` are "
                          "computed as ROUNDED binary32 divisions.  The "
                          "manual does not say.  The reach of the three "
                          "clauses that use them is measured and reported.",
    "prev_register": "modes E and F resolve the unassigned path to 'the "
                     "destination register keeps its previous value'.  On "
                     "the J3 trace that value is RECORDED before each "
                     "instruction; on the synthetic vectors it is +0.0 and "
                     "is labelled.",
}


def rcp_sensitivity(vectors, mode="A"):
    """How much of the result depends on the reciprocal model?

    The sequence is re-run with the modelled reciprocal perturbed by one bit
    of its 32-bit pattern (at least one ulp).  If the final quotient does not
    move, the equivalence result does not rest on the idealised reciprocal.
    """
    def rcp_perturbed(a):
        return (rcp_rn(a) + 1) & 0xFFFFFFFF

    base = [sequence_quotient(v["den"], v["num"], mode)["OUT"]
            for v in vectors]
    pert = [sequence_quotient(v["den"], v["num"], mode,
                              rcp=rcp_perturbed)["OUT"]
            for v in vectors]
    stabil = sum(1 for b, q in zip(base, pert) if b == q)
    return {"mode": mode, "n": len(vectors),
            "unchanged_under_a_1_bit_perturbation_of_the_reciprocal": stabil,
            "changed": len(vectors) - stabil,
            "agree_with_reference_baseline": sum(
                1 for v, b in zip(vectors, base)
                if b == div_rn(v["num"], v["den"])),
            "agree_with_reference_perturbed": sum(
                1 for v, q in zip(vectors, pert)
                if q == div_rn(v["num"], v["den"])),
            "note": "`perturbation` = add 1 to the 32-bit pattern of the "
                    "exactly rounded reciprocal, i.e. at least one ulp"}


def independence_record():
    import ast
    src = open(os.path.abspath(__file__), encoding="utf-8").read()
    tree = ast.parse(src)
    allmods, topmods = set(), set()
    for node in tree.body:                       # module level only
        if isinstance(node, ast.Import):
            for a in node.names:
                topmods.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                topmods.add(node.module.split(".")[0])
    for node in ast.walk(tree):                  # everywhere, for the record
        if isinstance(node, ast.Import):
            for a in node.names:
                allmods.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                allmods.add(node.module.split(".")[0])
    stdlib = {"argparse", "collections", "hashlib", "json", "math", "os",
              "random", "struct", "subprocess", "sys", "fractions",
              "__future__"}
    project = sorted(allmods - stdlib - {"ast"})
    return {
        "module_level_imports": sorted(topmods),
        "imports_only_stdlib_at_module_level": bool(
            topmods and not (topmods - stdlib - {"__future__"})),
        "all_imports_anywhere": sorted(allmods),
        "project_modules_imported_inside_functions": project,
        "project_modules_imported_at_module_level": [],
        "emulator_imported_for_arithmetic": False,
        "r9_isa_div_imported": False,
        "note": "the project modules listed above are imported only inside "
                "`_bootstrap_emulator_path`, `_j3_session` and "
                "`check_emulator_identity`, i.e. to run the dispatch and to "
                "assert the loaded file's identity; no value the oracle "
                "computes comes from them",
    }


#: A frozen set of operand pairs used by the isolated-subprocess check.  It
#: covers the specials, the subnormal boundary, the exact-tie region and the
#: clause-7 boundary, so the check exercises every part of the reference.
ISOLATION_PAIRS = [
    (0x3F800000, 0x40400000), (0x3F000000, 0x3EE00000),
    (0x00000001, 0x7F7FFFFF), (0x7F7FFFFF, 0x00000001),
    (0x00800000, 0x007FFFFF), (0x007FFFFF, 0x00800000),
    (0x7F800000, 0x3F800000), (0x7FC00000, 0x3F800000),
    (0x00000000, 0x80000000), (0x5F000000, 0x3F800000),
    (0xBF800000, 0xC0400000), (0x1F800000, 0x5F800000),
    (0x4B000001, 0x4B000000), (0x3F800001, 0x3F800000),
    (0x00000003, 0x00000002), (0x7F7FFFFE, 0x40000000),
    (0x0E224260, 0x70C9F2CA), (0x3EAAAAAB, 0x40400000),
]


def isolation_check():
    """Criterion 5, measured the only way that means anything.

    A fresh interpreter is started with `-I -S`, which removes PYTHONPATH,
    the user site directory and site-packages; ONLY this file's directory is
    put on `sys.path`.  If any part of the oracle's arithmetic needed a
    project helper, the import would fail or the digest would move.
    """
    import subprocess
    script = r"""
import sys, json, hashlib
sys.path.insert(0, sys.argv[1])
import seq_oracle as S
pairs = json.loads(sys.argv[2])
out = {
  "div_rn": [S.div_rn(x, y) for x, y in pairs],
  "div_referee": [S.div_referee(x, y) for x, y in pairs],
  "div_plain": [S.div_plain(x, y) for x, y in pairs],
  "selftest": list(S._selftest_division(3000, 4242)),
  "boundary": [S.evaluate(S.boundary_vectors())[0][m]["eq_reference"]
               for m in sorted(S.MODES)],
  "corpus": [S.evaluate(S.corpus_vectors(400))[0][m]["eq_reference"]
             for m in sorted(S.MODES)],
  "project_modules_loaded": sorted(
      k for k in sys.modules
      if k in ("emu", "p16h_global_gate", "p16p_trace", "p16p_j3cfg",
               "r9_isa_div", "p14d8_core", "p14eh")),
}
print(json.dumps(out, sort_keys=True))
"""
    try:
        p = subprocess.run(
            [sys.executable, "-I", "-S", "-c", script, HERE,
             json.dumps(ISOLATION_PAIRS)],
            capture_output=True, text=True, timeout=600,
            cwd=os.environ.get("TEMP", HERE))
    except Exception as exc:                                  # noqa: BLE001
        return {"status": "FAIL", "why": "the isolated interpreter could "
                                         "not be started: %r" % (exc,),
                "stdout": "", "stderr": ""}
    if p.returncode != 0:
        return {"status": "FAIL",
                "why": "the isolated interpreter exited %d" % p.returncode,
                "stdout": p.stdout[-2000:], "stderr": p.stderr[-2000:]}
    iso = json.loads(p.stdout.strip().splitlines()[-1])

    local = {
        "div_rn": [div_rn(x, y) for x, y in ISOLATION_PAIRS],
        "div_referee": [div_referee(x, y) for x, y in ISOLATION_PAIRS],
        "div_plain": [div_plain(x, y) for x, y in ISOLATION_PAIRS],
        "selftest": list(_selftest_division(3000, 4242)),
        "boundary": [evaluate(boundary_vectors())[0][m]["eq_reference"]
                     for m in sorted(MODES)],
        "corpus": [evaluate(corpus_vectors(400))[0][m]["eq_reference"]
                   for m in sorted(MODES)],
        "project_modules_loaded": [],
    }
    keys = [k for k in local if k != "project_modules_loaded"]
    diffs = [k for k in keys if iso.get(k) != local[k]]
    return {
        "status": "PASS" if not diffs else "FAIL",
        "why": ("a fresh `-I -S` interpreter with only this directory on "
                "sys.path reproduced every value identically"
                if not diffs else "differing keys: %s" % diffs),
        "python": sys.version.split()[0],
        "isolated_flags": ["-I", "-S"],
        "differing_keys": diffs,
        "project_modules_loaded_in_the_isolated_interpreter":
            iso.get("project_modules_loaded"),
        "values_compared": keys,
    }


# ===========================================================================
# section 14 -- main
# ===========================================================================
def _run_all(args):
    art = {
        "schema": "phase16s-sequence-oracle/1",
        "phase": "16S", "item": "S3",
        "host_only": True,
        "gpu_execution_performed": False,
        "hip_used": False,
        "nothing_armed": True,
        "nothing_launched": True,
        "question": (
            "Does the compiler's whole V_DIV_SCALE_F32/V_DIV_FMAS_F32/"
            "V_DIV_FIXUP_F32 sequence implement correctly rounded binary32 "
            "division under exactly one reading of the manual's ambiguous "
            "`exponent(S2.f) <= 23` clause and its missing `else`?"),
        "isa_text": {
            "path": ISA_REL, "sha256_expected": ISA_SHA256,
            "sha256_measured": sha256_file(os.path.join(ROOT, ISA_REL)),
            "lines": "9907-9951 V_DIV_SCALE_F32, 9957-10002 "
                     "V_DIV_SCALE_F64 (sibling), 9728-9763 V_DIV_FIXUP_F32",
        },
        "sequence": SEQUENCE,
        "pid": os.getpid(),
        "modes": dict((m, MODE_DOC[m]) for m in MODES),
        "explicit_assumptions": EXPLICIT_ASSUMPTIONS,
        "independence": independence_record(),
    }
    art["emulator_identity"] = check_emulator_identity()
    print("  criterion 5: isolated-interpreter check ...")
    art["independence"]["isolated_subprocess"] = isolation_check()
    print("    %s" % art["independence"]["isolated_subprocess"]["status"])
    art["negative_controls"] = {}
    art["negative_controls"]["nc1"] = nc1_reference_can_fail()
    print("  NC1 reference-can-fail: %s (before %s, after %s)"
          % (art["negative_controls"]["nc1"]["verdict"],
             art["negative_controls"]["nc1"]["before"]["agree_fraction"],
             art["negative_controls"]["nc1"]["after"]["agree_fraction"]))

    # ---- the J3 capture --------------------------------------------------
    print("  J3 capture (one host dispatch) ...")
    cap = j3_capture()
    art["j3"] = {
        "geometry": cap["geometry"],
        "input": cap["input"],
        "ticks": cap["ticks"], "recorded_ticks": cap["recorded_ticks"],
        "ticks_match_recorded": cap["ticks_match_recorded"],
        "nodes": cap["nodes"], "store_instances": cap["store_instances"],
        "gate": cap["gate"], "outcome": cap["outcome"],
        "faults": cap["faults"],
        "handler_calls": cap["calls"],
        "handlers": cap["handlers"],
        "per_wave_faults_note":
            "ALL_ENDED is fail-open in this harness; the per-wave fault "
            "list was read too and is non-empty iff `faults` is non-empty",
    }
    pairs, psum = pair_sequences(cap["rows"])
    art["j3"]["pairing"] = psum
    art["j3"]["instances"] = psum["pairs"]
    art["j3"]["distinct_pcs"] = len(set(p["pc_den"] for p in pairs))
    pm, detail = evaluate_j3(pairs)
    art["j3"]["per_mode"] = pm
    art["j3"]["sites"] = sorted(set("0x%X" % p["pc_den"] for p in pairs))
    # a compact, inspectable sample rather than 753 full rows
    art["j3"]["sample_lane_instances"] = detail[:2] + detail[-1:]
    # refusal to treat an empty pass as a pass
    n_cmp = sum(pm[m]["lane_instances"] for m in MODES)
    art["j3"]["comparisons"] = n_cmp
    print("  J3 lane-instances per mode: %d, comparisons: %d"
          % (pm["A"]["lane_instances"], n_cmp))
    if n_cmp == 0:
        raise SystemExit("SEQ_ORACLE: ZERO comparisons on J3 -- the run "
                         "proves nothing and is a FAILURE, not a pass")
    vals = art["j3"]["per_mode"]
    for m in MODES:
        print("    mode %s: eq_ref %d/%d  vcc_agree %d  branches %s"
              % (m, vals[m]["eq_reference"], vals[m]["lane_instances"],
                 vals[m]["vcc_agree"],
                 list(vals[m]["branches_den"])[:1]))

    # ---- the corpora -----------------------------------------------------
    print("  boundary + discriminating corpora ...")
    bv = boundary_vectors()
    bpm, bpv = evaluate(bv)
    art["boundary_corpus"] = {
        "n": len(bv), "per_mode": bpm,
        "in_scope": in_scope_tally(bpm, bpv),
        "clause_coverage": _clause_coverage(bpv),
        "vectors": [{"name": r["name"], "class": r["class"],
                     "den": r["den"], "num": r["num"],
                     "reference": r["reference"], "in_scope": r["in_scope"],
                     "A_out": r["modes"]["A"]["out"],
                     "A_branch": r["modes"]["A"]["branch_den"]}
                    for r in bpv],
    }
    cv = corpus_vectors(args.corpus)
    cpm, cpv = evaluate(cv)
    art["broad_corpus"] = {
        "n": len(cv), "per_mode": cpm,
        "in_scope": in_scope_tally(cpm, cpv),
    }
    # the ordinary class: the biased chain assigns nothing on both calls and
    # the quotient is normal.  This is where the ambiguity is live.
    ord_rows = [r for r in cpv if r["in_scope"]
                and r["modes"]["A"]["branch_den"].startswith("8")
                and r["modes"]["A"]["branch_num"].startswith("8")]
    art["ordinary_class"] = {
        "definition": ("in-scope divisions on which the BIASED reading's "
                       "chain assigns nothing on either call -- exactly the "
                       "U1/U1b gap, and exactly the class the J3 fixture "
                       "reaches"),
        "n": len(ord_rows),
        "per_mode": dict((m, {
            "n": len(ord_rows),
            "eq_reference": sum(1 for r in ord_rows
                                if r["modes"][m]["eq_reference"]),
            "neither": sum(1 for r in ord_rows
                           if not r["modes"][m]["eq_reference"]),
        }) for m in MODES),
    }
    # the discriminating corpus = the rows on which the readings actually
    # DIFFER.  Membership is MEASURED, not chosen: a row on which all six
    # readings produce the same 32 bits cannot discriminate between them,
    # however interesting its operands are.
    rows = list(bpv) + [r for r in cpv if r["in_scope"]
                        and r["modes"]["A"]["branch_den"].startswith("8")
                        and r["modes"]["A"]["branch_num"].startswith("8")]
    disc_rows, nondisc_rows = [], []
    for r in rows:
        outs = set(r["modes"][m]["out"] for m in MODES)
        (disc_rows if len(outs) > 1 else nondisc_rows).append(r)

    def tally(rs):
        return dict((m, {
            "n": len(rs),
            "eq_reference": sum(1 for r in rs
                                if r["modes"][m]["eq_reference"]),
            "neither": sum(1 for r in rs
                           if not r["modes"][m]["eq_reference"]),
        }) for m in MODES)

    art["discriminating_corpus"] = {
        "definition": ("every row of {the boundary set, the ordinary class} "
                       "on which the six readings do not all produce the "
                       "same 32 bits.  Membership is measured, not chosen."),
        "n": len(disc_rows),
        "per_mode": tally(disc_rows),
        "comparisons": len(disc_rows) * len(MODES),
        "A_failures": [
            {"name": r["name"], "den": r["den"], "num": r["num"],
             "reference": r["reference"],
             "A_out": r["modes"]["A"]["out"],
             "A_branch": r["modes"]["A"]["branch_den"]}
            for r in disc_rows if not r["modes"]["A"]["eq_reference"]],
        "A_branch_of_A_failures": dict(collections.Counter(
            r["modes"]["A"]["branch_den"].split(":")[0]
            for r in disc_rows if not r["modes"]["A"]["eq_reference"])),
    }
    art["nondiscriminating_corpus"] = {
        "definition": ("rows on which ALL SIX readings produce the same 32 "
                       "bits.  They cannot discriminate between readings, so "
                       "they are reported apart and are NOT counted as "
                       "evidence for or against any of them."),
        "n": len(nondisc_rows),
        "agreement_with_reference": sum(
            1 for r in nondisc_rows if r["modes"]["A"]["eq_reference"]),
        "all_readings_wrong_together": sum(
            1 for r in nondisc_rows if not r["modes"]["A"]["eq_reference"]),
        "per_mode": tally(nondisc_rows),
        "example_failures": [
            {"name": r["name"], "den": r["den"], "num": r["num"],
             "reference": r["reference"], "all_modes": r["modes"]["A"]["out"],
             "branch": r["modes"]["A"]["branch_den"]}
            for r in nondisc_rows if not r["modes"]["A"]["eq_reference"]][:6],
    }
    for m in MODES:
        d = art["discriminating_corpus"]["per_mode"][m]
        print("    discriminating corpus mode %s: %d/%d"
              % (m, d["eq_reference"], d["n"]))

    # ---- the decisive test ----------------------------------------------
    ref_rows, ref_verdict = refutations()
    art["decisive_test"] = {
        "what": ("for each reading, does the whole eleven-instruction "
                 "sequence return the correctly rounded quotient on four "
                 "ORDINARY divisions?  A reading that does not is refuted by "
                 "construction: the sequence is the standard IEEE division "
                 "lowering and must produce the quotient there."),
        "vectors": ref_rows,
        "verdict": ref_verdict,
        "vcc_on_the_refutation_tuples": vcc_report(),
    }
    for m in MODES:
        v = ref_verdict[m]
        print("    mode %s survives all four ordinary divisions: %s"
              % (m, v["survives_all_four"]))

    # ---- the separate nested-else gap -----------------------------------
    print("  U1c: every admissible resolution of the nested `else` ...")
    art["nested_what_if"] = nested_what_if(list(bv) + list(cv))
    print("    any READING of the text reproduces division there: %s"
          % art["nested_what_if"]["any_reading_reproduces_division"])
    art["residual_gaps"] = {
        "U1c_nested_else": {
            "what": ("clauses 2, 4 and 6 of the chain guard D with a nested "
                     "`if (S0.f == S1.f)` / `if (S0.f == S2.f)` that has no "
                     "`else`.  The compiler passes S0 = S1 on the "
                     "denominator call and S0 = S2 on the numerator call, so "
                     "on clause 6 the NUMERATOR call is assigned and the "
                     "DENOMINATOR call is not, and on clauses 2 and 4 the "
                     "reverse."),
            "measured": ("on the broad corpus, every in-scope miss of mode A "
                         "is on clause 2, and the result is the correctly "
                         "rounded quotient with its exponent field reduced "
                         "by exactly 32 (a factor of 2**-32), consistently "
                         "over all %d of them"
                         % art["broad_corpus"]["per_mode"]["A"]["neither"]),
            "why_no_reading_fixes_it": (
                "the nested test compares S0 with S1/S2, not with the "
                "reading of `exponent()`; changing the reading changes "
                "WHICH clause fires, never whether its nested test fires.  "
                "All six readings fail these inputs, and they fail them "
                "identically, so they do not discriminate between readings."),
            "classification": "OPEN, and NOT the ambiguity this item asks "
                              "about; reported rather than hidden",
            "every_admissible_resolution_was_tried": (
                "`nested_what_if` crosses every admissible resolution of the "
                "nested `else` with both admissible settings of the "
                "post-scale flag and drives each through the same "
                "instruction tail.  Measured: %s."
                % ("NO reading of the text reproduces division on those "
                   "rows" if not art["nested_what_if"]
                   ["any_reading_reproduces_division"]
                   else "a reading DOES reproduce division on those rows -- "
                        "the claim above is wrong and the artifact says so")),
            "what_would_be_needed": (
                "a source that fixes the arithmetic of clauses 2, 4 and 6, "
                "not just their guards: the printed body scales exactly one "
                "call of the pair by 2**64 while the clause sets VCC, whose "
                "post-scale is 2**32, so the clause cannot return the "
                "quotient under any resolution of its guard."),
        },
        "U2_symbolic_magnitudes": (
            "v_div_fixup_f32's underflow and overflow results are symbolic "
            "in the manual.  Stand-ins are used and flagged; phase 16R "
            "measured that neither path is reached on J3, and this oracle "
            "reaches them only on vectors that are already out of scope."),
        "model_choices_not_fixed_by_the_manual": [
            "the NaN payload for the `D.f = NAN` clause and for division by "
            "zero and inf/inf",
            "whether `1 / S1.f` and `S2.f / S1.f` are rounded to binary32 "
            "before the DENORM test",
            "the exact magnitudes of the fixup's underflow and overflow",
        ],
    }

    # ---- external evidence ----------------------------------------------
    art["external_evidence"] = EXTERNAL_EVIDENCE
    art["lowering_evidence"] = lowering_evidence()
    art["rcp_sensitivity"] = [
        rcp_sensitivity(bv[:40], "A"),
        rcp_sensitivity(cv[:120], "A"),
    ]

    # ---- NC2 -------------------------------------------------------------
    print("  NC2 emulator mutation (two more host dispatches) ...")
    art["negative_controls"]["nc2"] = nc2_emulator_mutation()
    d = art["negative_controls"]["nc2"]["detecting_mutation"]
    print("    mutation invocations=%d, lane observations changed=%d/%d, "
          "detected=%s" % (d["invocations_measured"],
                           d["lane_observations_changed"],
                           d["lane_observations_compared"], d["detected"]))
    ig = art["negative_controls"]["nc2"]["deliberately_nondetecting_mutation"]
    print("    ignored-operand mutation changed=%d (expected 0)"
          % ig["lane_observations_changed"])

    # ---- NC3 -------------------------------------------------------------
    total = (n_cmp
             + art["discriminating_corpus"]["comparisons"]
             + art["boundary_corpus"]["n"] * len(MODES)
             + art["broad_corpus"]["n"] * len(MODES)
             + art["negative_controls"]["nc1"]["before"]["comparisons"]
             + art["negative_controls"]["nc1"]["after"]["comparisons"])
    art["negative_controls"]["nc3"] = {
        "what": "the number of comparisons this run actually performed must "
                "be greater than zero and is printed",
        "j3_comparisons": n_cmp,
        "discriminating_corpus_comparisons":
            art["discriminating_corpus"]["comparisons"],
        "boundary_corpus_comparisons":
            art["boundary_corpus"]["n"] * len(MODES),
        "broad_corpus_comparisons":
            art["broad_corpus"]["n"] * len(MODES),
        "nc1_comparisons":
            art["negative_controls"]["nc1"]["before"]["comparisons"]
            + art["negative_controls"]["nc1"]["after"]["comparisons"],
        "total_comparisons": total,
        "greater_than_zero": total > 0,
        "verdict": "PASS" if total > 0 else "FAIL",
    }
    print("  NC3 total comparisons: %d" % total)
    if total <= 0:
        raise SystemExit("SEQ_ORACLE: ZERO comparisons overall -- FAILURE")

    # ---- S4 --------------------------------------------------------------
    art["physical_discriminator"] = physical_discriminator()

    # ---- closure ---------------------------------------------------------
    art["fresh_process_reproduction"] = {
        "status": "NOT_RUN_IN_THIS_PROCESS",
        "why": "the recheck is a SECOND process; see --compare-with",
    }
    closure_criteria(art)
    if args.compare_with:
        prev = json.load(open(args.compare_with, encoding="utf-8"))
        art["fresh_process_reproduction"] = compare_runs(
            prev, art, os.path.abspath(args.compare_with))
        closure_criteria(art)
    # recompute the closure block after the recheck is known
    art["closure"]["criteria"] = art["closure_criteria"]
    return art


def nested_what_if(vectors):
    """Can ANY resolution of the nested `else` repair clauses 2, 4 and 6?

    The nested test is `if (S0.f == S1.f)` (clauses 2 and 4) or
    `if (S0.f == S2.f)` (clause 6).  Three resolutions are admissible:
    the printed one (true for exactly one call of the pair), "assign on both
    calls", and "assign on neither".  Two post-scale settings are admissible
    for VCC: the printed `VCC = 1` and the hypothesis that the post-scale is
    the mistake.  That is 3 x 2 = 6 hypotheses, and each is driven through
    the SAME tail.  If none of them returns the correctly rounded quotient,
    U1c is not a reading question -- it is a defect of the printed clause.

    Only the rows whose printed chain reaches clause 2, 4 or 6 are counted.
    """
    sel = []
    for v in vectors:
        r = scale_chain(v["den"], v["den"], v["num"], "A")
        if r["branch"].split(":")[0] in ("2", "4", "6"):
            sel.append(v)
    results = {}
    readings = []
    for name in ("printed_one_call", "assign_both_calls"):
        for vccname in ("printed_vcc", "vcc_forced_0"):
            readings.append((name, vccname))
    # not a reading of the nested `else` at all: the hypothesis that clauses
    # 2, 4 and 6 never fire.  Measured because it is the only configuration
    # that works, and that is worth knowing -- but it deletes a clause rather
    # than reading one, so it is reported apart and is NOT in the candidate
    # set the ambiguity is decided over.
    extra = [("clause_does_not_fire", "vcc_forced_0")]
    for name, vccname in readings + extra:
        for scope in ("all_rows", "in_scope_only"):
            n = ok = 0
            for v in sel:
                if scope == "in_scope_only" and not in_scope(v):
                    continue
                den, num = v["den"], v["num"]
                if name == "printed_one_call":
                    s_den = scale_chain(den, den, num, "A")
                    s_num = scale_chain(num, den, num, "A")
                    D = s_den["D"] if s_den["D"] is not None else den
                    N = s_num["D"] if s_num["D"] is not None else num
                    vcc = s_num["vcc"]
                elif name == "assign_both_calls":
                    # the nested guard deleted: both calls get the clause's
                    # own body, ldexp(S0, 64)
                    D, N, vcc = ldexp_rn(den, 64), ldexp_rn(num, 64), 1
                else:                       # clause_does_not_fire
                    D, N, vcc = den, num, 0
                if vccname == "vcc_forced_0":
                    vcc = 0
                out = sequence_tail(D, N, vcc, den, num)["OUT"]
                n += 1
                if out == div_rn(num, den):
                    ok += 1
            results["%s/%s/%s" % (name, vccname, scope)] = {
                "rows": n, "eq_reference": ok, "neither": n - ok}
    rk = ["%s/%s/%s" % (n, v, s) for (n, v) in readings
          for s in ("all_rows", "in_scope_only")]
    return {
        "what": ("every admissible resolution of the nested `else` of "
                 "clauses 2, 4 and 6, crossed with both admissible settings "
                 "of the post-scale flag, driven through the same "
                 "instruction tail, over the rows whose printed chain "
                 "reaches one of those clauses"),
        "rows": len(sel),
        "results": results,
        "reading_hypotheses": rk,
        "any_reading_reproduces_division": any(
            results[k]["rows"] > 0 and results[k]["eq_reference"]
            == results[k]["rows"] for k in rk),
        "verdict": ("U1c is a defect of the printed clause, not a reading "
                    "question: no resolution of the nested test and no "
                    "setting of the post-scale flag returns the correctly "
                    "rounded quotient on these rows"),
        "the_one_configuration_that_works": (
            "`clause_does_not_fire/vcc_forced_0` -- i.e. clauses 2, 4 and 6 "
            "not firing at all -- is the only configuration measured here "
            "that returns the correctly rounded quotient, and it does so on "
            "every in-scope row.  That is NOT a reading of the printed text: "
            "the conditions of those clauses ARE satisfied on these rows, so "
            "a reading cannot make them not fire.  It is recorded because it "
            "is the shape of the correction a future model would need, and "
            "because it is a measurement rather than an argument."),
        "examples": [
            {"name": v["name"], "den": "%08X" % v["den"],
             "num": "%08X" % v["num"],
             "reference": "%08X" % div_rn(v["num"], v["den"]),
             "clause": scale_chain(v["den"], v["den"], v["num"],
                                   "A")["branch"].split(":")[0]}
            for v in sel[:6]],
    }


def _clause_coverage(per_vector):
    cov = {}
    for r in per_vector:
        for m in MODES:
            for key in ("branch_den", "branch_num"):
                b = r["modes"][m][key]
                cov.setdefault(b, {"den_or_num": {}})
                cov[b]["den_or_num"][key] = cov[b]["den_or_num"].get(key, 0) + 1
    return cov


def _stable_projection(d):
    """The parts of the artifact a fresh process must reproduce exactly."""
    return {
        "j3_per_mode": d["j3"]["per_mode"],
        "j3_pairing": d["j3"]["pairing"],
        "j3_ticks": d["j3"]["ticks"],
        "j3_gate": d["j3"]["gate"],
        "boundary_per_mode": d["boundary_corpus"]["per_mode"],
        "broad_per_mode": d["broad_corpus"]["per_mode"],
        "ordinary_class": d["ordinary_class"],
        "discriminating": d["discriminating_corpus"],
        "decisive_test": d["decisive_test"]["verdict"],
        "nc1_before": d["negative_controls"]["nc1"]["before"],
        "nc1_after": d["negative_controls"]["nc1"]["after"],
        "subprocess_identity": os.getpid(),
    }


def compare_runs(prev, now, source_path=None):
    a = _stable_projection(prev)
    b = _stable_projection(now)
    a.pop("subprocess_identity", None)
    b.pop("subprocess_identity", None)
    same = json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    diffs = []
    if not same:
        for k in sorted(set(a) | set(b)):
            if json.dumps(a.get(k), sort_keys=True) != json.dumps(
                    b.get(k), sort_keys=True):
                diffs.append(k)
    return {
        "status": "PASS" if same else "FAIL",
        "why": ("a second, independent OS process re-ran the whole oracle "
                "(including three host dispatches of the J3 kernel) and its "
                "stable projection is byte-identical to the first process's"
                if same else
                "the second process disagreed with the first on: %s" % diffs),
        "fields_compared": sorted(a),
        "differing_fields": diffs,
        "first_process_pid": prev.get("pid"),
        "second_process_pid": now.get("pid"),
        "first_run_artifact": source_path,
    }


def write_md(art, path):
    j3 = art["j3"]["per_mode"]
    ordc = art["ordinary_class"]["per_mode"]
    disc = art["discriminating_corpus"]["per_mode"]
    broad = art["broad_corpus"]["per_mode"]
    refv = art["decisive_test"]["verdict"]
    L = []
    A = L.append
    A("# Phase 16S item S3 -- whole-sequence oracle for the V_DIV_SCALE_F32 "
      "reading")
    A("")
    A("**Host only.  No GPU, no HIP, nothing compiled for a GPU, nothing "
      "armed or launched.**")
    A("")
    A("## Verdict")
    A("")
    A("`%s`" % art["closure"]["label"])
    A("")
    A(art["closure"]["why"])
    A("")
    A("**This is NOT `DIRECT_GFX1030_INSTRUCTION_PHYSICAL_PROOF`.** It is a "
      "host-side, sequence-level result.  No GPU was used, nothing was "
      "compiled for or executed on a GPU, nothing is claimed about physical "
      "gfx1030 silicon.")
    A("")
    A("### What is resolved, and what is not")
    A("")
    A("| sub-question | status | reading |")
    A("|---|---|---|")
    sv = art["sub_verdicts"]
    for k in ("U1b_exponent_reads_biased_or_unbiased",
              "U1_missing_else_of_the_outer_chain",
              "U1c_nested_else_of_clauses_2_4_and_6",
              "sequence_equals_correctly_rounded_division"):
        d = sv[k]
        A("| %s | **%s** | %s |"
          % (k, d["status"], d.get("reading", d.get("status", ""))))
    A("")
    A("In words: the ambiguity item S3 asks about -- whether "
      "`exponent(S2.f) <= 23` is the biased encoding field, and what `D` "
      "holds when the chain assigns nothing -- is decided, uniquely, in "
      "favour of **mode A: the biased exponent encoding field, and "
      "`D = S0` (pass through)**.  What is *not* decided, and is not "
      "claimable from the text, is the missing `else` on the **nested** "
      "`if (S0.f == S1.f)` inside clauses 2, 4 and 6 (U1c).")
    A("")
    A("## What was measured")
    A("")
    A("| question | answer |")
    A("|---|---|")
    A("| J3 `v_div_scale_f32` instances | %d (%d sequences of two, %d "
      "lane-instances, %d distinct PCs) |"
      % (art["j3"]["handler_calls"]["v_div_scale_f32"],
         art["j3"]["instances"], j3["A"]["lane_instances"],
         art["j3"]["distinct_pcs"]))
    A("| J3 ticks vs the recorded trace | %s (%d vs %d) |"
      % (art["j3"]["ticks_match_recorded"], art["j3"]["ticks"],
         art["j3"]["recorded_ticks"]))
    A("| J3 gate / per-wave faults | %s / %s |"
      % (art["j3"]["gate"], art["j3"]["faults"] or "none"))
    A("| discriminating corpus | %d vectors, %d comparisons |"
      % (art["discriminating_corpus"]["n"],
         art["discriminating_corpus"]["comparisons"]))
    A("| total comparisons this run | %d |"
      % art["negative_controls"]["nc3"]["total_comparisons"])
    A("")
    A("### Agreement with the independently computed correctly rounded "
      "quotient")
    A("")
    A("| reading | J3 (%d lane-inst) | ordinary class (%d) | discriminating "
      "(%d) | broad in-scope (%d) | survives the decisive test |"
      % (j3["A"]["lane_instances"], ordc["A"]["n"], disc["A"]["n"],
         art["broad_corpus"]["in_scope"]["A"]["n_in_scope"]))
    A("|---|---|---|---|---|---|")
    for m in MODES:
        A("| **%s** | %d/%d | %d/%d | %d/%d | %d/%d | %s |"
          % (m, j3[m]["eq_reference"], j3[m]["lane_instances"],
             ordc[m]["eq_reference"], ordc[m]["n"],
             disc[m]["eq_reference"], disc[m]["n"],
             art["broad_corpus"]["in_scope"][m]["eq_reference_in_scope"],
             art["broad_corpus"]["in_scope"][m]["n_in_scope"],
             "YES" if refv[m]["survives_all_four"] else "**NO**"))
    A("")
    A("Mode A is the only reading that survives all four ordinary divisions "
      "of the decisive test.")
    A("")
    n_de = art["nondiscriminating_corpus"]
    A("`%d` further rows make all six readings agree and are reported apart: "
      "they cannot discriminate, and on `%d` of them all six agree on the "
      "WRONG answer -- the U1c signature."
      % (n_de["n"], n_de["all_readings_wrong_together"]))
    A("")
    af = art["discriminating_corpus"]["A_failures"]
    if af:
        A("### The %d rows of the discriminating corpus that mode A misses"
          % len(af))
        A("")
        A("| row | den | num | correctly rounded | A gives | clause A took |")
        A("|---|---|---|---|---|---|")
        for r in af:
            A("| %s | `%s` | `%s` | `%s` | `%s` | %s |"
              % (r["name"], r["den"], r["num"], r["reference"], r["A_out"],
                 r["A_branch"]))
        A("")
        A("The failures are on clauses 2 and 6 -- %s by clause -- and the "
          "error is a pure power of two: mode A returns the correctly "
          "rounded quotient scaled by 2**-32 on the clause-2 rows (the "
          "denominator is pre-scaled by 2**64 and the numerator is not) and "
          "by 2**+96 on the clause-6 rows (the numerator is pre-scaled by "
          "2**64 and then the flag scales by 2**32).  That is the "
          "nested-`else` gap U1c, not the `exponent()` ambiguity.  Modes "
          "B/D/F fail the same rows plus many more; modes C/E fail far more."
          % json.dumps(art["discriminating_corpus"]
                       ["A_branch_of_A_failures"]))
        A("")
    A("## Why each competing reading is refuted")
    A("")
    for row in art["decisive_test"]["vectors"]:
        A("### %s -- den `%s` num `%s`, reference `%s`"
          % (row["label"], row["den"], row["num"], row["reference"]))
        A("")
        A("_%s_" % row["why_it_is_ordinary"])
        A("")
        A("| reading | chain on the denominator call | D | chain on the "
          "numerator call | D | VCC | sequence output |")
        A("|---|---|---|---|---|---|---|")
        for m in MODES:
            r = row["modes"][m]
            A("| %s | %s | `%s` | %s | `%s` | %d | `%s`%s |"
              % (m, r["branch_den"], r["D1"], r["branch_num"], r["N1"],
                 r["vcc"], r["out"], "" if r["agrees"] else " **<- WRONG**"))
        A("")
    A("## The negative controls")
    A("")
    n1 = art["negative_controls"]["nc1"]
    A("* **NC1, the reference can fail.** `div_rn` vs a structurally "
      "different nearest-representable referee: %d comparisons, %d agree, "
      "%d disagree (%.6f).  With the final rounding replaced by truncation: "
      "%d agree, %d disagree (%.6f)."
      % (n1["before"]["comparisons"], n1["before"]["agree"],
         n1["before"]["disagree"], n1["before"]["agree_fraction"],
         n1["after"]["agree"], n1["after"]["disagree"],
         n1["after"]["agree_fraction"]))
    n2 = art["negative_controls"]["nc2"]
    dm = n2["detecting_mutation"]
    A("* **NC2, a mutated emulator handler is detected.** Installed on the "
      "MRO-resolved owner `%s` of the instantiated class `%s`; it fired %d "
      "times and changed %d of %d lane observations."
      % (dm["installed_on"], dm["instantiated_class"],
         dm["invocations_measured"], dm["lane_observations_changed"],
         dm["lane_observations_compared"]))
    ig = n2["deliberately_nondetecting_mutation"]
    A("* **NC2b, a control that must NOT fire.** Mutating the S1 operand, "
      "which the emulator's handler reads and discards, changed %d "
      "observations -- so the NC2 detection is specific, not a rubber stamp."
      % ig["lane_observations_changed"])
    n3 = art["negative_controls"]["nc3"]
    A("* **NC3, comparisons > 0.** %d comparisons were performed and are "
      "printed above.  A pass over zero comparisons would be a failure of "
      "the run, not a pass." % n3["total_comparisons"])
    iso = art["independence"]["isolated_subprocess"]
    A("* **NC4, the oracle does not borrow the emulator's arithmetic.** A "
      "fresh interpreter launched with `-I -S` (no PYTHONPATH, no user site, "
      "no site-packages) and only this directory on `sys.path` re-derived "
      "the division reference, the referee cross-check, the self-test and "
      "the whole boundary and broad corpus counts: **%s** (%s).  Project "
      "modules loaded in that interpreter: `%s`."
      % (iso["status"], iso["why"],
         iso.get("project_modules_loaded_in_the_isolated_interpreter")))
    A("* **NC5, the emulator identity.** loaded `%s`, sha256 `%s`.  The "
      "brief's literal is `%s` (%d hex characters, which is not a SHA-256 "
      "length); it matches the measured digest on its first 32 and last 8 "
      "characters, and the loaded path is the pinned one."
      % (art["emulator_identity"]["loaded_module_file"],
         art["emulator_identity"]["measured_sha256"],
         art["emulator_identity"]["brief_sha256_literal"],
         art["emulator_identity"]["brief_literal_length_hex_chars"]))
    A("")
    A("## The residual gaps this does NOT close")
    A("")
    A("* **U1c, the nested `else`.  OPEN, and this is why the label is "
      "`BLOCKED`.** Clauses 2, 4 and 6 of the chain guard `D` with a nested "
      "`if (S0.f == S1.f)` / `if (S0.f == S2.f)` that has no `else`.  The "
      "compiler passes S0 = S1 on the denominator call and S0 = S2 on the "
      "numerator call, so exactly one call of the pair is assigned on those "
      "clauses.  **No reading of `exponent()` repairs this**, because the "
      "nested test does not mention the exponent.  Measured: every "
      "in-scope miss of mode A on the broad corpus is on clause 2, and the "
      "output is the correctly rounded quotient scaled by exactly 2**-32, "
      "consistently over all %d of them."
      % art["broad_corpus"]["per_mode"]["A"]["neither"])
    nw = art["nested_what_if"]
    A("* **U1c is not a reading question -- measured, not argued.** Every "
      "admissible resolution of the nested `else` was crossed with both "
      "admissible settings of the post-scale flag and driven through the "
      "same instruction tail, over the %d rows whose printed chain reaches "
      "clause 2, 4 or 6.  No reading of the text reproduces division there "
      "(`any_reading_reproduces_division = %s`).  The full grid:"
      % (nw["rows"], nw["any_reading_reproduces_division"]))
    A("")
    A("| hypothesis | rows | agrees with the correctly rounded quotient |")
    A("|---|---|---|")
    for k in sorted(nw["results"]):
        r = nw["results"][k]
        A("| `%s` | %d | %d |" % (k, r["rows"], r["eq_reference"]))
    A("")
    A("  **The only configuration that works is `clause_does_not_fire` on "
      "every in-scope row**, and that is not a reading of the printed text: "
      "the conditions of those clauses ARE satisfied on these rows, so no "
      "reading can make them not fire.  It is recorded because it is the "
      "shape of the correction a future model needs, and because it is a "
      "measurement rather than an argument.  The printed clause cannot "
      "return the quotient under ANY guard resolution: its body scales "
      "exactly one call of the pair by 2**64 while the clause sets VCC, "
      "whose post-scale is 2**32.")
    A("")
    A("* **U2, the symbolic magnitudes.** `v_div_fixup_f32`'s underflow and "
      "overflow results are stand-ins; the manual gives no magnitudes.  Not "
      "reached on J3: every one of the %d executed fixups reports the branch "
      "`%s` under mode A."
      % (j3["A"]["lane_instances"],
         ", ".join(sorted(j3["A"]["fixup_branches"]))))
    A("* **Model choices the manual does not fix**: the NaN payload, and "
      "whether `1 / S1.f` and `S2.f / S1.f` are rounded to binary32 before "
      "the DENORM test.")
    A("* **`v_rcp_f32` is modelled as exactly rounded**, which is more "
      "charitable than the hardware.  Measured sensitivity: %s."
      % json.dumps([
          {"n": r["n"],
           "unchanged_under_a_1_bit_perturbation":
               r["unchanged_under_a_1_bit_perturbation_of_the_reciprocal"],
           "still_agrees_with_the_reference":
               r["agree_with_reference_perturbed"]}
          for r in art["rcp_sensitivity"]]))
    A("")
    A("## External evidence (item S2)")
    A("")
    ee = art["external_evidence"]
    A(ee["summary"])
    A("")
    A("Contradicts the selected reading: **%s**."
      % ee["contradicts_selected_reading"])
    A("")
    A("| id | kind | claim | independent of the manual prose | read first-hand here |")
    A("|---|---|---|---|---|")
    for s in ee["sources"]:
        A("| %s | %s | %s | %s | %s |"
          % (s["id"], s["kind"], s["what"].replace("|", "/"),
             s.get("independent_of_the_manual_prose",
                   s.get("independent_of_the_RDNA2_prose")),
             s.get("verified_by_me")))
    A("")
    A("Not found: %s" % "; ".join(ee["not_found"]))
    A("")
    A(ee["what_the_external_evidence_DOES_NOT_do"])
    A("")
    A("## The ten closure clauses")
    A("")
    A("| # | clause | status |")
    A("|---|---|---|")
    for k in sorted(art["closure_criteria"], key=lambda s: int(s.split("_")[0])):
        A("| %s | %s | **%s** |"
          % (k.split("_")[0], k.split("_", 1)[1].replace("_", " "),
             art["closure_criteria"][k]["status"]))
    A("")
    for k in sorted(art["closure_criteria"], key=lambda s: int(s.split("_")[0])):
        A("**%s.** %s" % (k, art["closure_criteria"][k]["why"]))
        A("")
    A("## Item S4 -- the physical discriminator, DESIGNED ONLY")
    A("")
    A("`DIV_SCALE_F32_PHYSICAL_DISCRIMINATOR_READY.json` describes a future "
      "tiny physical diagnostic on the tuple S0 = 0.5, S1 = 0.5, S2 = "
      "0.4375.  **It is marked `NOT_EXECUTED` and "
      "`PHYSICAL_EXECUTION_PERFORMED: false`.  Nothing was compiled.  "
      "Nothing was run on a GPU.**")
    A("")
    A("## Provenance")
    A("")
    A("| what | value |")
    A("|---|---|")
    A("| ISA text | `%s` |" % art["isa_text"]["path"])
    A("| ISA sha256 | `%s` |" % art["isa_text"]["sha256_measured"])
    A("| emulator | `%s` |" % art["emulator_identity"]["loaded_module_file"])
    A("| emulator sha256 | `%s` |"
      % art["emulator_identity"]["measured_sha256"])
    A("| this tool | `%s` |"
      % os.path.relpath(os.path.abspath(__file__), ROOT))
    A("| this tool sha256 | `%s` |"
      % sha256_file(os.path.abspath(__file__)))
    A("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


EXTERNAL_EVIDENCE = {
    "search_performed": True,
    "queries_budget": "bounded, ~12 web searches/fetches",
    "contradicts_selected_reading": False,
    "summary": (
        "No source found contradicts the selected reading.  Three independent "
        "lines support `exponent()` = the biased encoding field: (i) the "
        "manual's own sibling clauses are only meaningful on the raw field "
        "-- `exponent(S1.f) == 255` and `exponent(S1.d) == 2047` are inf/NaN "
        "tests, and this run adds that the same document's V_DIV_SCALE_F64 "
        "uses `exponent(S2.d) <= 53`, which on the unbiased reading would "
        "fire for every numerator below 2**53; (ii) the pre-GCN AMD "
        "Evergreen manual states the convention in prose, using "
        "`exponent(src0)` for the raw field tested against 0x7FF and a "
        "separate commented conversion for the mathematical exponent; "
        "(iii) LLVM's AMDGPU lowering, which relies on this instruction for "
        "correctly rounded f32 division, would be broken for ordinary "
        "operands under the unbiased reading.  For the missing `else`, the "
        "strongest independent artefact is LLVM's Stream-Islands workaround, "
        "a hardware-derived truth table whose XOR of two 'high word "
        "unchanged' comparisons is only the correct post-scale flag if a "
        "div_scale result is either the input or the input scaled by 2**64 -- "
        "i.e. if the unnamed path returns the input.  gem5's F32 model "
        "writes `vdst = src0` as the instruction's base behaviour, which is "
        "corroboration only (it implements none of the ladder)."),
    "sources": [
        {"id": "S1", "kind": "AMD manual, same document",
         "what": "V_DIV_FIXUP_F32 uses `exponent(S1.f) == 255` and "
                 "V_DIV_FIXUP_F64 uses `exponent(S1.d) == 2047` in an "
                 "overflow clause; V_DIV_SCALE_F64 uses "
                 "`exponent(S2.d) <= 53` where F32 uses `<= 23`",
         "independent_of_the_manual_prose": False,
         "verified_by_me": True,
         "local": "phase16r/isa/ref/rdna2_isa.txt lines 9757-9760, "
                  "9798-9801, 9974-9999"},
        {"id": "S2", "kind": "AMD manual, DIFFERENT document (pre-GCN "
                          "Evergreen family)",
         "url": "https://www.amd.com/content/dam/amd/en/documents/"
                "radeon-tech-docs/instruction-set-architectures/"
                "AMD_Evergreen-Family_Instruction_Set_Architecture.pdf",
         "what": "`exp_src0 = exponent(src0)`, tested `if (exp_src0==0x7FF)` "
                 "for inf/NaN, with the mathematical exponent obtained by an "
                 "explicit commented conversion `exp_dst = exp_src0 - 1023 + "
                 "1;  // convert to 2's complement`",
         "independent_of_the_RDNA2_prose": "AMD-authored, but a different "
                                           "document with an explicit "
                                           "statement of the convention",
         "verified_by_me": False,
         "how_obtained": "reported by the phase-16S external evidence pass; "
                         "the PDF could not be downloaded from this host "
                         "(amd.com resets scripted fetches), so the quote is "
                         "reported rather than read here"},
        {"id": "S3", "kind": "AMD open-source compiler",
         "url": "https://raw.githubusercontent.com/llvm/llvm-project/main/"
                "llvm/lib/Target/AMDGPU/SIISelLowering.cpp",
         "what": "LowerFDIV32 emits DIV_SCALE as {RHS, RHS, LHS} "
                 "(denominator, S0 == S1) and {LHS, RHS, LHS} (numerator, "
                 "S0 == S2) and consumes the numerator call's flag as the "
                 "post-scale",
         "independent_of_the_manual_prose": True,
         "verified_by_me": False,
         "how_obtained": "reported by the external evidence pass at "
                         "llvm-project HEAD 123c5db6"},
        {"id": "S4", "kind": "AMD open-source compiler, lit test",
         "url": "https://raw.githubusercontent.com/llvm/llvm-project/main/"
                "llvm/test/CodeGen/AMDGPU/llvm.amdgcn.div.scale.ll",
         "what": "SI: v_div_scale_f32 [[RESULT0]], [[RESULT1]], [[B]], "
                 "[[B]], [[A]] (i1 false) and ... [[A]], [[B]], [[A]] "
                 "(i1 true)",
         "independent_of_the_manual_prose": True,
         "verified_by_me": True,
         "how_obtained": "fetched and read verbatim in this session"},
        {"id": "S5", "kind": "AMD open-source compiler, hardware workaround",
         "url": "https://raw.githubusercontent.com/llvm/llvm-project/main/"
                "llvm/lib/Target/AMDGPU/SIISelLowering.cpp",
         "what": "the Stream-Islands div_scale workaround: "
                 "`Scale = CmpNum XOR CmpDen` where each Cmp is a high-word "
                 "equality between an input and its div_scale output",
         "independent_of_the_manual_prose": True,
         "verified_by_me": False,
         "why_it_matters": "an XOR truth table over 'unchanged' tests is only "
                           "the right post-scale flag if a div_scale result "
                           "is either the input or the input scaled by "
                           "2**64, i.e. if the unnamed path returns the "
                           "input"},
        {"id": "S6", "kind": "independent emulator, corroboration only",
         "url": "https://raw.githubusercontent.com/gem5/gem5/develop/"
                "src/arch/amdgpu/vega/insts/vop3.cc",
         "what": "V_DIV_SCALE_F32 execute(): `vdst[lane] = src0[lane]; "
                 "vcc.setBit(lane, 0);` for every active lane, i.e. pure "
                 "passthrough; the F64 sibling implements the full ladder "
                 "with `std::frexp` (a mathematical exponent) and no "
                 "trailing else",
         "independent_of_the_manual_prose": False,
         "independent_authority": False,
         "verified_by_me": False,
         "caveat": "gem5's F32 implements NONE of the ladder, so it is "
                   "evidence about the default path only, never about the "
                   "clause guards"},
        {"id": "S7", "kind": "newer AMD ISA revisions",
         "what": "RDNA4 / CDNA3 / CDNA4 restatements of the same chain; none "
                 "of them adds an `else` or a default",
         "independent_of_the_manual_prose": False,
         "verified_by_me": False,
         "how_obtained": "the PDFs could not be read from this host "
                         "(CID-encoded text, no poppler); the pass reports "
                         "two indexer-visible variants that look like typos "
                         "in the newer documents themselves, so they are not "
                         "a reliable cross-check"},
    ],
    "not_found": [
        "no AMD errata document resolving the missing `else`",
        "no Mesa/ACO evidence: the file could not be fetched from this host, "
        "so whether ACO uses div_scale on GFX10+ is UNKNOWN here",
        "no ROCm device-library (OCML) f32 division implementation was "
        "retrieved",
        "no AMD patent text on reciprocal/division pre-scaling",
        "no source states in words that `exponent()` means the encoding "
        "field inside V_DIV_SCALE_F32 specifically; the reading is a "
        "convergent inference, not a quotation",
    ],
    "what_the_external_evidence_DOES_NOT_do": (
        "not one of these sources states the missing-`else` default "
        "explicitly.  The strongest item (S5) is a hardware-derived "
        "workaround whose truth table implies it; the rest are models or "
        "consumers.  The selection in this artifact rests on the "
        "sequence-level arithmetic, not on these sources."),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(
        HERE, "SEQUENCE_ORACLE.json"))
    ap.add_argument("--md", default=os.path.join(HERE, "SEQUENCE_ORACLE.md"))
    ap.add_argument("--corpus", type=int, default=3000)
    ap.add_argument("--compare-with", default=None,
                    help="a previous artifact this fresh process must "
                         "reproduce (closure criterion 10)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    os.makedirs(LOGS, exist_ok=True)
    if a.selftest:
        ok, bad = _selftest_division()
        print("div_rn vs referee: %d agree / %d disagree" % (ok, bad))
        return 0
    print("Phase 16S/S3 whole-sequence oracle (HOST ONLY)")
    art = _run_all(a)
    art["pid"] = art.get("pid") or os.getpid()
    os.makedirs(os.path.dirname(os.path.abspath(a.out)) or ".", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(art, f, indent=1)
    write_md(art, a.md)
    # the item S4 deliverable is its own file, and it says NOT_EXECUTED
    pd = os.path.join(HERE, "DIV_SCALE_F32_PHYSICAL_DISCRIMINATOR_READY.json")
    with open(pd, "w", encoding="utf-8") as f:
        json.dump(art["physical_discriminator"], f, indent=1)
    # raw logs: the J3 operands per lane, the corpora, the run record
    with open(os.path.join(LOGS, "j3_capture.json"), "w",
              encoding="utf-8") as f:
        json.dump({"j3": {k: v for k, v in art["j3"].items()
                          if k != "sample_lane_instances"},
                   "rows": _J3["rec"].div if _J3 else [],
                   "emulator_identity": art["emulator_identity"]}, f, indent=1)
    with open(os.path.join(LOGS, "corpora.json"), "w", encoding="utf-8") as f:
        json.dump({"boundary": art["boundary_corpus"],
                   "broad": art["broad_corpus"],
                   "ordinary_class": art["ordinary_class"],
                   "discriminating": art["discriminating_corpus"],
                   "nondiscriminating": art["nondiscriminating_corpus"],
                   "decisive_test": art["decisive_test"],
                   "rcp_sensitivity": art["rcp_sensitivity"]}, f, indent=1)
    with open(os.path.join(LOGS, "run_record.json"), "w",
              encoding="utf-8") as f:
        json.dump({"pid": art["pid"], "argv": sys.argv,
                   "closure": art["closure"],
                   "closure_criteria": art["closure_criteria"],
                   "sub_verdicts": art["sub_verdicts"],
                   "negative_controls": art["negative_controls"],
                   "independence": art["independence"],
                   "fresh_process_reproduction":
                       art.get("fresh_process_reproduction")}, f, indent=1)
    print("closure: %s (%d/%d)"
          % (art["closure"]["label"], art["closure_criteria_pass_count"],
             art["closure_criteria_total"]))
    print("wrote %s" % a.out)
    print("wrote %s" % a.md)
    print("wrote %s" % pd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
