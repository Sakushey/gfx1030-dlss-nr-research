#!/usr/bin/env python3
"""Phase 16AW -- shared harness for the k_dec_upsample CPU-oracle repair.

Host-only.  No HIP call, no GPU, no launch, no slot.

WHAT THIS MODULE PROVIDES, AND WHY EACH PIECE EXISTS

  load_by_path(name, path)
      Imports a module and ASSERTS the identity of what was loaded.  Phase 16L
      had a verifier report 97/97 agreement against a module it believed was
      the frozen copy while `import emu` had silently picked up a different
      file on sys.path.  Every load here re-checks `__file__`.

  rn32_third_route(x)
      binary32 round-to-nearest-even on an exact Fraction, computed by a THIRD
      algorithm: find the binade, form the exact neighbours on either side of
      the value inside that binade, and take the nearer (ties to even).  It is
      not A's algorithm (integer significand shift) and not B's (integer
      division by an exact quantum).  Two implementations that share a
      specification are independent only if they share no mechanism, so a third
      reading is worth having when the first two are the things under test.

  rn32_host_crosscheck(x)
      A FOURTH reading, on a restricted domain: let CPython/C convert an exact
      binary64 to binary32 with `struct.pack('<f', ...)`.  Valid only where the
      exact value is a binary64 value with a 53-bit significand and no
      under/overflow, because there the first conversion is lossless and the
      whole operation is a single correctly-rounded binary64 -> binary32 step.
      Outside that domain it is NOT a cross-check and this function says so
      rather than returning a number.

  floor_log2_exact(x) / neighbours(x)
      exact helpers for the above.

  Case builders for the adversarial corpus (brief section 34).  A case is a
  (chunk index, list of (activation_fp16_value, E4M3FN_byte) pairs) and it is
  materialised into a 1024-wide activation row and a 1024-wide weight row
  through the SAME public entry points the operator has always exposed
  (`project` with rows=1), so the corpus exercises real code paths.

  Report(x) -- a tiny check recorder that PRINTS THE COUNT of what it compared,
  because a check that compared nothing must not be able to read as a pass.
"""
from __future__ import annotations

import importlib.util
import math
import os
import struct
from fractions import Fraction as Q

ROOT = r"<PROJECT_ROOT>"
P16AR = os.path.join(ROOT, "p16ar")
P16AW_NUMERIC = os.path.join(ROOT, "p16aw", "numeric")

A_16AR = os.path.join(P16AR, "native", "cpu_reference",
                      "k_dec_upsample_A.py")
B_16AR = os.path.join(P16AR, "native", "cpu_reference",
                      "k_dec_upsample_B.py")
CONTRACT_16AR = os.path.join(P16AR, "native", "cpu_reference",
                             "NUMERICAL_CONTRACT_16AR.json")
PINNING_16AR = os.path.join(P16AR, "reference",
                            "NUMERIC_PRECISION_PINNING_16AR.json")
FIXTURE_16AR = os.path.join(P16AR, "reference",
                            "DIFFERENTIAL_PRECISION_FIXTURE_16AR.bin")

A_REPAIRED = os.path.join(P16AW_NUMERIC, "k_dec_upsample_A_rn32.py")
B_INDEPENDENT = os.path.join(P16AW_NUMERIC,
                             "k_dec_upsample_B_independent.py")

MATRIX_ROWS, MATRIX_COLS = 512, 1024
CHUNK, PARTITION = 32, 256
F32_P, F32_EMIN, F32_EMAX, F32_SUBQ = 24, -126, 127, -149


def load_by_path(name: str, path: str):
    """Import `path` as module `name` and ASSERT the loaded file is `path`."""
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
# third-route binary32 rounding, on exact rationals
# ---------------------------------------------------------------------------
def floor_log2_exact(x: Q) -> int:
    """Exact floor(log2(x)) for x > 0 (a Fraction or a positive int)."""
    a = Q(x)
    e = a.numerator.bit_length() - a.denominator.bit_length()
    if a < Q(2) ** e:
        e -= 1
    while a >= Q(2) ** (e + 1):
        e += 1
    while a < Q(2) ** e:
        e -= 1
    return e


def rn32_third_route(x: Q):
    """Nearest binary32 to the exact rational x, as an exact Fraction.

    Algorithm: locate the binade, take the exact value's neighbours in that
    binade, and choose the nearer -- ties to the neighbour whose significand
    integer is EVEN.  Returns float('inf') / float('-inf') on overflow (no
    admissible k_dec_upsample value reaches that, but it must not be silent).
    """
    x = Q(x)
    if x == 0:
        return Q(0)
    neg = x < 0
    a = -x if neg else x
    e = floor_log2_exact(a)
    if e > F32_EMAX:
        return float("-inf") if neg else float("inf")
    quantum = Q(2) ** (F32_SUBQ if e < F32_EMIN else (e - (F32_P - 1)))
    s = a / quantum                      # exact rational position on the grid
    f = s.numerator // s.denominator     # floor
    if Q(f) == s:
        lo = hi = f
        val = Q(f) * quantum
    else:
        lo, hi = f, f + 1
        vlo, vhi = Q(lo) * quantum, Q(hi) * quantum
        dlo, dhi = a - vlo, vhi - a
        if dlo < dhi:
            val = vlo
        elif dhi < dlo:
            val = vhi
        else:
            val = vlo if (lo & 1) == 0 else vhi     # ties to even
    return -val if neg else val


def rn32_host_crosscheck(x: Q):
    """A fourth reading, or None where this route is not valid.

    Valid only when the exact rational is itself a binary64 value (<= 53
    significand bits) with an exponent inside binary64's range, so that the
    conversion to binary64 is lossless and the single remaining step is the
    correctly-rounded binary64 -> binary32 conversion performed by C.
    """
    x = Q(x)
    if x == 0:
        return Q(0)
    a = abs(x)
    e = floor_log2_exact(a)
    if e > 1023 or e < -1074:
        return None
    # significand bits needed = (e - trailing_zero_exponent) + 1
    n = a.numerator
    d = a.denominator
    if d != 1 and (d & (d - 1)):
        return None
    tz = (d.bit_length() - 1)
    need = n.bit_length() - tz     # number of significant bits in a
    if need > 53:
        return None
    v = float(x)
    if math.isinf(v):
        return None
    try:
        b = struct.unpack("<f", struct.pack("<f", v))[0]
    except OverflowError:
        return None
    if math.isinf(b):
        return None
    return Q(b)


# ---------------------------------------------------------------------------
# corpus case construction (brief section 34)
# ---------------------------------------------------------------------------
def e4_byte_for(value: float) -> int:
    """The E4M3FN byte that decodes to `value` (exact inverse of the decode)."""
    for b in range(256):
        if float(_e4_decode(b)) == value:
            return b
    raise ValueError("no E4M3FN byte decodes to %r" % value)


def _e4_decode(b: int) -> Q:
    s = -1 if (b >> 7) & 1 else 1
    e = (b >> 3) & 0xF
    m = b & 0x7
    if e == 15 and m == 7:
        return Q(s * 448)
    if e == 0:
        return Q(s) * Q(m, 8) * Q(2) ** -6
    return Q(s) * (Q(1) + Q(m, 8)) * Q(2) ** (e - 7)


def materialise(chunk: int, pairs, width: int = MATRIX_COLS):
    """(pairs at `chunk`) -> (x_row, mat_row) for a single partition row.

    `pairs` is a list of (activation, e4m3fn_byte) for positions 0..31 of the
    chunk.  Positions not given are (0.0, 0x00).  Activation and weight
    pointers are zero outside the named chunk, so the case isolates ONE chunk
    and the answer is readable by hand.
    """
    x_row = [0.0] * width
    mat_row = [0.0] * width
    base = chunk * CHUNK
    for t, (act, byte) in enumerate(pairs):
        x_row[base + t] = float(act)
        mat_row[base + t] = float(_e4_decode(byte))
    return x_row, mat_row


# ---------------------------------------------------------------------------
# comparing values across the two oracles' value types
#
# A speaks python floats; B speaks exact Fractions, and after the 16AW repair B
# can also produce a python float +/-inf.  `Q(float('inf'))` raises, so a naive
# `Q(a) == b` would CRASH on exactly the saturation cases this phase exists to
# test -- which would look like a failure of the test rather than of the
# comparison.  `exact()` puts all three shapes on one scale.
# ---------------------------------------------------------------------------
def exact(v):
    if isinstance(v, tuple):
        return v                     # already a ('inf', sign) / ('nan',) tag
    if isinstance(v, float):
        if v != v:
            return ("nan",)
        if v == float("inf"):
            return ("inf", 1)
        if v == float("-inf"):
            return ("inf", -1)
    return Q(v)


def same(a, b) -> bool:
    return exact(a) == exact(b)


def is_fraction_module(mod) -> bool:
    """True if `mod`'s E4M3FN decoder speaks Fractions rather than floats."""
    return isinstance(mod.e4m3fn_decode(0x38), Q)


def case_rows(mod, pairs, chunk: int = 0, width: int = MATRIX_COLS):
    """(activation row, weight row) built in the MODULE's own value types.

    The weight row is decoded through the module's OWN `e4m3fn_decode`, so the
    corpus never hands B a float where B expects an exact rational: feeding one
    oracle the other's value type would test the adapter, not the arithmetic.
    """
    xrow = [0.0] * width
    byterow = [0] * width
    base = chunk * CHUNK
    for t, (act, b) in enumerate(pairs):
        xrow[base + t] = float(act)
        byterow[base + t] = b
    if is_fraction_module(mod):
        return [Q(v) for v in xrow], [mod.e4m3fn_decode(b) for b in byterow]
    return xrow, [float(mod.e4m3fn_decode(b)) for b in byterow]


def packed_exact(v) -> str:
    """A short exact label for a value: '0.001953125' style, or 'inf'/'0'."""
    e = exact(v)
    if e == ("nan",):
        return "nan"
    if isinstance(e, tuple):
        return "inf" if e[1] > 0 else "-inf"
    if e == 0:
        return "0"
    return ("%s" % float(e)) if abs(e) < Q(2) ** 60 and abs(e) > Q(2) ** -60 \
        else repr(e)


# ---------------------------------------------------------------------------
# check recorder
# ---------------------------------------------------------------------------
class Report:
    """Collects checks and PRINTS THE COUNT of what each one compared."""

    def __init__(self, title: str):
        self.title = title
        self.rows = []
        print("=" * 74)
        print(title)
        print("=" * 74)

    def row(self, check, ok, n_compared, detail=None):
        if n_compared == 0:
            # a check that compared nothing cannot be a pass
            ok = False
            detail = dict(detail or {})
            detail["why_failed"] = "COMPARED_NOTHING"
        self.rows.append({"check": check, "ok": bool(ok),
                          "n_compared": int(n_compared),
                          "detail": detail})
        print("  %-4s n=%-7d %s" % ("OK" if ok else "FAIL", n_compared, check))
        if not ok:
            print("       %s" % repr(detail)[:400])
        return bool(ok)

    @property
    def n_ok(self):
        return sum(1 for r in self.rows if r["ok"])

    def verdict(self, good, bad):
        v = good if self.n_ok == len(self.rows) else bad
        print("  -> %s (%d/%d checks ok)" % (v, self.n_ok, len(self.rows)))
        return v
