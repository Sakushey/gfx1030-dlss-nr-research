#!/usr/bin/env python3
"""Phase 16R / R9 -- an INDEPENDENT bit-level reference for AMD RDNA2's
three f32 division-sequence instructions.

HOST ONLY.  No GPU, no HIP call, no game launch, nothing armed.

INDEPENDENCE.  This module imports `math` and `struct` and nothing else.
It does not import the emulator, the oracle, or any other file in this
project, so nothing it computes can inherit an emulator convention.  Its
semantics are transcribed from the published AMD instruction-set
architecture text quoted verbatim in TRANSSCRIPT below.

WHERE THE TEXT COMES FROM.  `V_DIV_SCALE_F32` (opcode 365),
`V_DIV_FMAS_F32` (opcode 367) and `V_DIV_FIXUP_F32` (opcode 351) are
quoted from:

  "RDNA 2" Instruction Set Architecture, AMD, section 12.12
  (VOP3A & VOP3B Instructions), pages 173-176 of 283.
  Retrieved 2026-09-19 through the Internet Archive from
    https://www.amd.com/content/dam/amd/en/documents/radeon-tech-docs/
    instruction-set-architectures/rdna2-shader-instruction-set-architecture.pdf
  local copy: phase16r/isa/ref/rdna2_isa_wayback.pdf
              phase16r/isa/ref/rdna2_isa.txt   (pdftotext -layout)

  The AMD host serves that URL with a connection reset from this machine;
  the Internet Archive copy is byte-identical in size (4,430,368 B) to the
  two independent mirror URLs tried, and its page count (291) matches the
  document's own footer ("283 of 283" after front matter).

Corroboration of the OPERAND LIST (an independent second source, not a
re-statement of the first): LLVM's `AMDGPUAsmGFX8.rst` gives

    v_div_scale_f32  vdst, vcc, src0, src1, src2
    v_div_fmas_f32   vdst, src0, src1, src2
    v_div_fixup_f32  vdst, src0, src1, src2

  which is the same operand count and order the ISA text implies
  (S0/S1/S2 plus, for V_DIV_SCALE_F32 only, a VCC destination).
  local copy: phase16r/isa/ref/llvm_asm_gfx8.rst lines 1287-1291.

DECLARED UNCERTAINTY.  Two places in the ISA text are not decisive, and
this module does NOT silently pick a reading for either.  Each is returned
in the result dict as an explicit flag so a caller can decide whether the
fixture under test reaches it:

  U1  `V_DIV_SCALE_F32`'s branch chain has NO `else` clause and its nested
      `if (S0.f == S1.f) ... D.f = ... end if` has no `else` either.  The
      text therefore leaves D unassigned (a) when no branch matches and
      (b) when a branch matches but its nested equality test is false.
      `branch_assigned` reports which happened.  `mode="passthrough"`
      resolves the gap to D = S0 (the reading the division macro requires);
      `mode="isa_text"` leaves it unresolved and returns the sentinel.
  U2  `V_DIV_FIXUP_F32`'s underflow and overflow results are symbolic in
      the ISA text (`D.f = sign_out ? -underflow : underflow`); the
      magnitudes are not given.  `fixup_f32` reports `unspecified=True`
      for those two branches and returns a value supplied by the caller.

  A third, separate note: the ISA text writes the third `V_DIV_SCALE_F32`
  branch's nested test as `S0.f == S1.f`, while the phase-16R web summary
  of the same document wrote `S0.f == S2.f`.  The PDF text is used here.
"""

from __future__ import annotations

import math
import struct

U32 = 0xFFFFFFFF

#: Returned as D by the `mode="isa_text"` reading where the ISA text
#: assigns nothing.  Chosen so it cannot be mistaken for a computed value.
UNASSIGNED = "ISA_TEXT_ASSIGNS_NO_VALUE"

#: The emulator's stated arithmetic-NaN convention (phase8_static/tools/
#: emu.py, QNAN_F32).  Used here because the ISA text writes `NAN` without
#: fixing a sign or payload; the choice is recorded, not inherited.
QNAN_F32 = 0x7FC00000

SIGN_BIT = 0x80000000
EXP_MASK = 0x7F800000
MAN_MASK = 0x007FFFFF
QUIET_BIT = 0x00400000

#: `overflow` / `underflow` stand-ins for the fixup's symbolic results (U2).
#: MAX_FLOAT and the smallest denormal: the two magnitudes the F32 encoding
#: can express at those extremes.  NOT claimed to be what the hardware uses.
OVERFLOW_F32 = 0x7F7FFFFF
UNDERFLOW_F32 = 0x00000001


# ---------------------------------------------------------------------------
# binary32 primitives (stdlib only)
# ---------------------------------------------------------------------------
def f32(x):
    """Round a Python float to binary32, saturating at +-inf."""
    try:
        return struct.unpack("<f", struct.pack("<f", x))[0]
    except OverflowError:
        return float("inf") if x > 0 else float("-inf")


def bits(x):
    """binary32 bit pattern of a value."""
    return struct.unpack("<I", struct.pack("<f", f32(x)))[0]


def value(b):
    """The binary32 value of a bit pattern."""
    return struct.unpack("<f", struct.pack("<I", b & U32))[0]


def exp_of(x, mode="biased"):
    """The exponent of a value.

    `mode="biased"` returns the ENCODING FIELD (0..255), the usual meaning of
    "biased exponent", with 0 for zero and for denormals and 255 for
    infinities and NaNs.

    `mode="unbiased"` returns floor(log2|x|) -- the true exponent, so 0.5 -> -1
    and a denormal 2**-140 -> -140.

    The ISA text writes `exponent()` without saying which.  For the
    DIFFERENCE `exponent(S2.f) - exponent(S1.f)` the two agree whenever both
    operands are normal (both shift by 127) and disagree when one is a
    denormal.  For the comparison `exponent(S2.f) <= 23` they disagree always.
    Both are therefore propagated as a parameter, and R9 measures which
    readings J3 reaches rather than choosing one.
    """
    if mode == "unbiased":
        if x == 0.0:
            return -32768                      # not reached: 0 is caught first
        return math.frexp(abs(x))[1] - 1
    return (bits(x) >> 23) & 0xFF


def sign_of(x):
    """1 if the sign bit is set, else 0.  Distinguishes -0.0 from +0.0."""
    return (bits(x) >> 31) & 1


def is_nan(x):
    return isinstance(x, float) and math.isnan(x)


def is_inf(x):
    return isinstance(x, float) and math.isinf(x)


def is_zero(x):
    return x == 0.0


def is_denorm(x):
    """A non-zero magnitude below the smallest normal (2**-126)."""
    if x == 0.0 or is_nan(x) or is_inf(x):
        return False
    return abs(x) < 2.0 ** -126


def quiet(x):
    """Quiet a NaN the way the ISA's `Quiet()` does: set the quiet bit."""
    return value(bits(x) | QUIET_BIT)


def ldexp32(x, k):
    """ldexp rounded to binary32.

    `math.ldexp` is exact in f64 and then rounded once to f32, which is what
    an architectural `ldexp` on an f32 operand means.  An out-of-range
    result saturates to a signed infinity rather than raising.
    """
    try:
        return f32(math.ldexp(x, k))
    except OverflowError:
        return float("inf") if x > 0 else float("-inf")


# ---------------------------------------------------------------------------
# V_DIV_SCALE_F32 -- RDNA2 opcode 365
# ---------------------------------------------------------------------------
def scale_f32(s0, s1, s2, mode="passthrough", exp_mode="biased"):
    """V_DIV_SCALE_F32.

    S0 = input to scale (either denominator or numerator)
    S1 = denominator, S2 = numerator, and S0 must equal S1 or S2.

    Returns a dict:
      D            the destination VALUE (or UNASSIGNED under mode="isa_text")
      vcc          0 or 1 -- the post-scaling flag V_DIV_FMAS_F32 consumes
      branch       the ISA branch that fired, by name
      branch_assigned  True when the ISA text assigns D on that branch
    """
    vcc = 0
    D = UNASSIGNED
    assigned = False
    branch = None

    if s2 == 0.0 or s1 == 0.0:
        branch = "S2==0 or S1==0 -> NAN"
        D = value(QNAN_F32)
        assigned = True
    elif exp_of(s2, exp_mode) - exp_of(s1, exp_mode) >= 96:
        branch = "exp(S2)-exp(S1) >= 96"
        vcc = 1
        if s0 == s1:
            D = ldexp32(s0, 64)
            assigned = True
    elif is_denorm(s1):
        branch = "S1 is DENORM"
        D = ldexp32(s0, 64)
        assigned = True
    elif is_denorm(1.0 / s1) and is_denorm(s2 / s1):
        branch = "1/S1 DENORM and S2/S1 DENORM"
        vcc = 1
        if s0 == s1:
            D = ldexp32(s0, 64)
            assigned = True
    elif is_denorm(1.0 / s1):
        branch = "1/S1 is DENORM"
        D = ldexp32(s0, -64)
        assigned = True
    elif is_denorm(s2 / s1):
        branch = "S2/S1 is DENORM"
        vcc = 1
        if s0 == s2:
            D = ldexp32(s0, 64)
            assigned = True
    elif exp_of(s2, exp_mode) <= 23:
        branch = "exp(S2) <= 23"
        D = ldexp32(s0, 64)
        assigned = True
    else:
        branch = "no branch matched"
        assigned = False

    if not assigned and mode == "passthrough":
        # U1 resolution (a): the reading the division macro requires.
        D = f32(s0)

    return {"D": D, "vcc": vcc, "branch": branch,
            "branch_assigned": assigned}


# ---------------------------------------------------------------------------
# V_DIV_FMAS_F32 -- RDNA2 opcode 367
# ---------------------------------------------------------------------------
def fmas_f32(s0, s1, s2, vcc):
    """V_DIV_FMAS_F32: an FMA whose result is scaled by 2**32 when VCC is set."""
    r = s0 * s1 + s2
    if vcc:
        r = 2.0 ** 32 * r
    return f32(r)


# ---------------------------------------------------------------------------
# V_DIV_FIXUP_F32 -- RDNA2 opcode 351
# ---------------------------------------------------------------------------
def fixup_f32(s0, s1, s2, overflow=OVERFLOW_F32, underflow=UNDERFLOW_F32):
    """V_DIV_FIXUP_F32.

    S0 = Quotient, S1 = Denominator, S2 = Numerator.

    Returns a dict:
      D            the destination value
      branch       the ISA branch that fired, by name
      unspecified  True when the ISA text leaves the result symbolic (U2)
    """
    sign_out = sign_of(s1) ^ sign_of(s2)
    unspec = False

    if is_nan(s2):
        D, branch = quiet(s2), "S2 is NAN"
    elif is_nan(s1):
        D, branch = quiet(s1), "S1 is NAN"
    elif s1 == 0.0 and s2 == 0.0:
        D, branch = value(0xFFC00000), "0/0"
    elif is_inf(s1) and is_inf(s2):
        D, branch = value(0xFFC00000), "inf/inf"
    elif s1 == 0.0 or is_inf(s2):
        D = float("-inf") if sign_out else float("inf")
        branch = "x/0 or inf/y"
    elif is_inf(s1) or s2 == 0.0:
        D = -0.0 if sign_out else 0.0
        branch = "x/inf or 0/y"
    elif exp_of(s2, "biased") - exp_of(s1, "biased") < -150:
        u = value(underflow)
        D = -u if sign_out else u
        branch = "exponent difference < -150 (underflow)"
        unspec = True
    elif exp_of(s1, "biased") == 255:
        o = value(overflow)
        D = -o if sign_out else o
        branch = "exp(S1) == 255 (overflow)"
        unspec = True
    else:
        a = abs(s0)
        D = -a if sign_out else a
        branch = "default: sign_out applied to abs(S0)"

    return {"D": f32(D), "branch": branch, "unspecified": unspec,
            "sign_out": sign_out}


# ---------------------------------------------------------------------------
# what the EMULATOR does, restated here so the two can be diffed in one place
# ---------------------------------------------------------------------------
def emulator_scale_f32(s0, s1, s2):
    """`Core.op_v_div_scale_f32`, phase8_static/tools/emu.py:1708-1716.

    It reads ops[2] and ops[3] with fp=True, writes `f32_bits(f32(a))`, and
    zeroes vcc_l when the printed SDST is vcc_lo.  `a` is ops[2], i.e. the
    instruction's SRC0 = the ISA's S0.  S1 and S2 are read and discarded;
    every scaling branch and the NAN branch are absent.
    """
    return {"D": f32(s0), "vcc": 0}


def emulator_fmas_f32(s0, s1, s2):
    """`Core.op_v_div_fmas_f32`: `lambda a, b, c: f32(a * b + c)`.

    No VCC term at all -- the 2**32 post-scale is absent.
    """
    return f32(s0 * s1 + s2)


def emulator_fixup_f32(s0, s1, s2):
    """`Core.op_v_div_fixup_f32`: `lambda a, b, c: a`.

    Returns S0 untouched: no sign_out, no abs, none of the special cases.
    """
    return f32(s0)


if __name__ == "__main__":                                  # pragma: no cover
    print("RDNA2 V_DIV_SCALE_F32 / V_DIV_FMAS_F32 / V_DIV_FIXUP_F32 reference")
    print("scale(1.0, 1.0, 3.0)   =", scale_f32(1.0, 1.0, 3.0))
    print("fmas(2.0, 3.0, 1.0, 0) =", fmas_f32(2.0, 3.0, 1.0, 0))
    print("fmas(2.0, 3.0, 1.0, 1) =", fmas_f32(2.0, 3.0, 1.0, 1))
    print("fixup(1.5, 3.0, 4.0)   =", fixup_f32(1.5, 3.0, 4.0))
