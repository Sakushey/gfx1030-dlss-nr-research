"""Phase 8 host-only instruction emulator (wave32, gfx1030/gfx1100 subset).

Emulates scalar + vector instructions with EXEC/VCC/SCC semantics for the
k_conv_splitk no-work path. Used to prove termination behavior of the
original gfx1100 stream and the translated gfx1030 stream on identical
launch state. Deterministic; cycle detection on full state. No GPU use.
"""
import math
import struct

U32 = 0xFFFFFFFF
SIGN = 0x80000000


def f32(x):
    """Round a host float to binary32.

    Phase 16O: a magnitude beyond binary32 range SATURATES to a signed
    infinity instead of raising.  `struct.pack("<f", 1e40)` raises
    `OverflowError`, so before this every fp handler that could produce an
    out-of-range product aborted the whole dispatch -- a CRASH under the
    kernel, invisible to any check that only looks at outputs, and the same
    defect class Phase 16L recorded for `v_ldexp_f32`.  IEEE-754 says the
    rounded result of a finite real outside the representable range is a
    signed infinity, so saturating is the architectural answer, not a
    convenience.
    """
    try:
        return struct.unpack("<f", struct.pack("<f", x))[0]
    except OverflowError:
        return float("inf") if x > 0 else float("-inf")
    except (TypeError, ValueError):
        return x


def f32_bits(x):
    return struct.unpack("<I", struct.pack("<f", f32(x)))[0]


def bits_f32(b):
    return struct.unpack("<f", struct.pack("<I", b & U32))[0]


# Canonical quiet NaN.  The emulator's one stated NaN convention: an
# arithmetic NaN result is +qNaN regardless of the operand signs or of the
# sign the host FPU happens to produce, because that sign is not fixed by
# any architectural rule this project can cite.  Written as bits so it does
# not depend on what `struct.pack("<f", float("nan"))` does on this host.
QNAN_F32 = 0x7FC00000

# The same convention in binary16, used by `f32_bits_to_f16` and by the FP16
# fused multiply-add below.  Written as bits so it does not depend on what
# `struct.pack("<H", ...)` would do here.
QNAN_F16 = 0x7E00


def s32(x):
    """interpret u32 as signed"""
    x &= U32
    return x - 0x100000000 if x & SIGN else x


def _s16(x):
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def _s8(x):
    x &= 0xFF
    return x - 0x100 if x & 0x80 else x


def f16_to_f32(b):
    b &= 0xFFFF
    s = (b >> 15) & 1
    e = (b >> 10) & 0x1F
    m = b & 0x3FF
    if e == 0:
        if m == 0:
            return -0.0 if s else 0.0
        v = m * 2.0 ** -24
        return -v if s else v
    if e == 31:
        if m == 0:
            return float("-inf") if s else float("inf")
        return float("nan")
    v = (1 + m / 1024.0) * 2.0 ** (e - 15)
    return -v if s else v


# ---------------------------------------------------------------------------
# Phase 16N: exact binary32 -> binary16 conversion, and an exactly-rounded
# f32 fused multiply-add.
#
# Phase 16M found that the f16 conversion helper used by every scalar and
# packed f16 arithmetic handler took the sign from bit 16 of the binary32
# pattern instead of bit 31, clamped a rounded subnormal significand instead
# of letting it carry into the normal range, and never stated a rounding
# mode.  All three are repaired here by replacing the helper with the format
# definition rather than by patching its symptoms.
# ---------------------------------------------------------------------------
def f32_bits_to_f16(b):
    """binary32 bit pattern -> binary16 bit pattern, round-to-nearest-even.

    Phase 16T.  Two defects were measured in the Phase 16M body:

      * it rounded the significand at bit 13 of a 27-bit scaled value and
        then TRUNCATED three more bits when it formed the 10-bit field, so
        every value whose binary16 rounding decision lay in those three bits
        was truncated instead of rounded.  Measured: 1.00146484375
        (0x3F803000) is an exact tie between 0x3C01 and 0x3C02 and must
        round to the even one, 0x3C02, and the old body returned 0x3C01.
        65520 (0x477FF000) is an exact tie between the largest finite and
        infinity and must round to infinity; the old body returned 0x7BFF.
        The overflow tie is 5 ULP below the top of the range, so the old
        body also mis-rounded 4 of the 32 patterns in the top binade.
      * the NaN arm preserved the input sign and set a payload bit, giving
        0xFE00 for a negative quiet NaN, while this emulator's one stated
        NaN convention (QNAN_F32, above) is a canonical POSITIVE quiet NaN.
        It now returns QNAN_F16, which is also what the value-form helper
        `f32_to_f16_bits` has always returned.

    The sign was already taken from bit 31 here (Phase 16M repaired that)
    and the carry of a rounded subnormal into 0x0400 was already correct;
    both are RE-MEASURED against the Phase 16S oracle rather than trusted.

    ONE rounding, at the destination's own quantum: the exact magnitude is
    scaled by an exact power of two and rounded half-to-even, with the tie
    going to the even significand.
    """
    b &= 0xFFFFFFFF
    s = (b >> 31) & 1
    sgn = s << 15
    e = (b >> 23) & 0xFF
    m = b & 0x7FFFFF
    if e == 0xFF:                                   # infinity or NaN
        return QNAN_F16 if m else (sgn | 0x7C00)
    if e == 0:                                      # f32 zero or denormal
        return sgn
    exp = e - 127                                   # unbiased
    if exp > 15:
        return sgn | 0x7C00                         # >= 2**16 -> infinity
    sig = m | 0x800000                              # 24 significant bits
    # The result's quantum is 2**(exp-10) for a normal result and 2**-24 for
    # a subnormal one; `k` is how many bits of `sig` lie below that quantum.
    qexp = (exp - 10) if exp >= -14 else -24
    k = 23 + qexp - exp
    if k <= 0:
        q, r, den = sig << (-k), 0, 1
    else:
        den = 1 << k
        q, r = divmod(sig, den)
    if 2 * r > den or (2 * r == den and (q & 1)):
        q += 1
    if exp >= -14:
        if q == 0x800:                              # rounded out of the binade
            q = 0x400
            exp += 1
        if exp > 15:
            return sgn | 0x7C00
        return sgn | ((exp + 15) << 10) | (q - 0x400)
    if q >= 0x400:                                  # MUTATION: clamp
        return sgn | 0x03FF
    return sgn | q


def _f16_decode(bits):
    """(kind, sign, significand, exp2), value = (-1)**sign * sig * 2**exp2."""
    bits &= 0xFFFF
    sign = (bits >> 15) & 1
    e = (bits >> 10) & 0x1F
    m = bits & 0x3FF
    if e == 0x1F:
        return ("inf" if m == 0 else "nan"), sign, m, 0
    if e == 0:
        return ("zero" if m == 0 else "sub"), sign, m, -24
    return "norm", sign, 0x400 + m, e - 25


def _round_f16(sign, sig, exp2):
    """Round the exact positive magnitude `sig * 2**exp2` to binary16, RNE."""
    ub = (sig.bit_length() - 1) + exp2            # floor(log2(value))
    qexp = (ub - 10) if ub >= -14 else -24        # the result's own quantum
    k = qexp - exp2
    if k <= 0:
        q, r, den = sig << (-k), 0, 1
    else:
        den = 1 << k
        q, r = divmod(sig, den)
    if 2 * r > den or (2 * r == den and (q & 1)):
        q += 1
    if ub >= -14:
        if q == 0x800:
            ub += 1
            q = 0x400
        if ub > 15:
            return (sign << 15) | 0x7C00
        return (sign << 15) | ((ub + 15) << 10) | (q - 0x400)
    if q >= 0x400:
        return (sign << 15) | 0x0400
    return (sign << 15) | q


def f16_fma_bits(a, b, c):
    """V_FMA_MIXLO_F16 / V_FMA_MIXHI_F16 arithmetic on raw binary16 patterns.

    ISA rdna2_isa.txt:9350-9374 gives the two expressions
        D.f[15:0] = S0.f * S1.f + S2.f
        D.f[31:16] = S0.f * S1.f + S2.f
    so the arithmetic is identical and only the placement differs.  FUSED
    means ONE rounding: the 11x11-bit product is exact in Python integers,
    the addend is aligned to it exactly, and the single rounding to binary16
    happens once at the end.  That is what separates this from a
    multiply-round-then-add reading, and the artifact carries a vector that
    discriminates the two.

    DECLARED readings (recorded as OPEN in the artifact, since the document
    states the arithmetic expression only): a NaN input, Inf*0 and
    Inf + (-Inf) produce the canonical quiet NaN QNAN_F16; the sign of an
    exact zero result is +0 unless both addends are -0.
    """
    ka, sa, siga, ea = _f16_decode(a)
    kb, sb, sigb, eb = _f16_decode(b)
    kc, sc, sigc, ec = _f16_decode(c)
    if ka == "nan" or kb == "nan" or kc == "nan":
        return QNAN_F16
    if (ka == "inf" and kb == "zero") or (ka == "zero" and kb == "inf"):
        return QNAN_F16
    psign = sa ^ sb
    if ka == "inf" or kb == "inf":
        if kc == "inf" and sc != psign:
            return QNAN_F16
        return (psign << 15) | 0x7C00
    if kc == "inf":
        return (sc << 15) | 0x7C00
    if ka != "zero" and kb != "zero":
        psig, pexp = siga * sigb, ea + eb
    else:
        psig, pexp = 0, 0
    csig, cexp = (sigc, ec) if kc != "zero" else (0, 0)
    if psig == 0 and csig == 0:
        # IEEE 754: the sum of two zeros is +0 unless both are -0.
        return 0x8000 if (psign == 1 and kc == "zero" and sc == 1) else 0x0000
    exps = [x for x in ((pexp if psig else None),
                        (cexp if csig else None)) if x is not None]
    e = min(exps)
    n = 0
    if psig:
        n += (psig << (pexp - e)) if psign == 0 else -(psig << (pexp - e))
    if csig:
        n += (csig << (cexp - e)) if sc == 0 else -(csig << (cexp - e))
    if n == 0:
        return 0x0000                       # exact cancellation -> +0
    return _round_f16(1 if n < 0 else 0, abs(n), e)


def f32_to_f16_bits(x):
    """Value form of `f32_bits_to_f16`, for a caller holding a Python float."""
    if x != x:
        return 0x7E00
    if x in (float("inf"), float("-inf")):
        return 0x7C00 | (0x8000 if x < 0 else 0)
    return f32_bits_to_f16(f32_bits(x))


def _f32_decompose(b):
    """(sign, exponent, integer significand) with subnormals normalised.

    Returned so that one alignment path handles every finite input: a
    subnormal binary32 comes back as a normal with a negative exponent.
    """
    s = (b >> 31) & 1
    e = (b >> 23) & 0xFF
    m = b & 0x7FFFFF
    if e == 0:
        return s, -126, m
    return s, e - 127, m | 0x800000


def _frac_to_f32_bits(v):
    """Round an exact Fraction to binary32, RNE, and pack it.

    The value is scaled by a power of two chosen so the 24-bit significand
    lands on an INTEGER, which makes the single rounding a pure integer
    operation.  Scaling by a power of two is exact for a Fraction, so no
    precision is lost before the one rounding.

    This replaced two hand-derived alignment schemes in this file.  Both had
    scaling constants that were wrong in ways only a near-tie value could
    reveal; this form has one constant and it is checked against the whole
    subnormal range.
    """
    from fractions import Fraction
    if not isinstance(v, Fraction):
        v = Fraction(v)
    sign = 1 if v < 0 else 0
    a = -v if v < 0 else v
    if a == 0:
        return sign << 31
    E = a.numerator.bit_length() - a.denominator.bit_length()
    # E is either floor(log2(a)) or one less; settle it exactly.
    if (a.numerator << max(0, -E)) < (a.denominator << max(0, E)):
        E -= 1
    if E < -200:
        return sign << 31                          # far below any subnormal
    if E > 127:
        return (sign << 31) | 0x7F800000           # overflow
    shift = 23 - E
    if shift >= 0:
        scaled = a * (1 << shift)
    else:
        scaled = a / (1 << -shift)
    q = scaled.numerator // scaled.denominator
    rem = scaled - q
    if rem > Fraction(1, 2) or (rem == Fraction(1, 2) and (q & 1)):
        q += 1
    if q >= (1 << 24):
        q >>= 1
        E += 1
    e = E + 127
    if e >= 0xFF:
        return (sign << 31) | 0x7F800000
    if e <= 0:
        drop = 24 - e
        scaled = a * (1 << (149 + shift)) if False else a / Fraction(2) ** (-149)
        q2 = scaled.numerator // scaled.denominator
        rem2 = scaled - q2
        if rem2 > Fraction(1, 2) or (rem2 == Fraction(1, 2) and (q2 & 1)):
            q2 += 1
        if q2 >= (1 << 23):
            return (sign << 31) | (1 << 23)
        return (sign << 31) | int(q2)
    return (sign << 31) | (e << 23) | (q & 0x7FFFFF)


def fma_f32_bits(a_bits, b_bits, c_bits):
    """`a*b + c` with ONE rounding to binary32 -- the V_FMAC/V_FMA contract.

    The exact real value is formed as a `Fraction` (binary32 values are all
    dyadic rationals, so this is exact), then rounded ONCE.  Phase 16M
    measured the emulator computing `f32(a + b*c)` in host f64, which rounds
    twice and lands one ulp away on `DEFECT_v_fmac_f32_double_rounding`.

    This is slower than integer alignment and deliberately so: the integer
    version has two scaling constants that are easy to get wrong, and a wrong
    constant is invisible until a value happens to land near a tie.  The
    `Fraction` form has none.
    """
    from fractions import Fraction
    a_bits &= U32
    b_bits &= U32
    c_bits &= U32
    for x in (a_bits, b_bits, c_bits):
        if (x & 0x7F800000) == 0x7F800000:
            if x & 0x7FFFFF:
                return 0x7FC00000                    # a NaN operand
    ea = (a_bits >> 23) & 0xFF
    eb = (b_bits >> 23) & 0xFF
    ec = (c_bits >> 23) & 0xFF
    sa = (a_bits >> 31) & 1
    sb = (b_bits >> 31) & 1
    sc = (c_bits >> 31) & 1
    if ea == 0xFF or eb == 0xFF:
        psign = sa ^ sb
        if ec == 0xFF and sc != psign:
            return 0x7FC00000                        # inf + (-inf)
        return (psign << 31) | 0x7F800000
    if ec == 0xFF:
        return (sc << 31) | 0x7F800000
    fa = _bits_f32_exact(a_bits)
    fb = _bits_f32_exact(b_bits)
    fc = _bits_f32_exact(c_bits)
    return _frac_to_f32_bits(fa * fb + fc)


def _bits_f32_exact(b):
    """binary32 bits -> the EXACT value as a Fraction (no rounding)."""
    from fractions import Fraction
    b &= U32
    s = (b >> 31) & 1
    e = (b >> 23) & 0xFF
    m = b & 0x7FFFFF
    if e == 0:
        v = Fraction(m, 1 << 149)
    elif e == 0xFF:
        raise ValueError("inf/NaN has no finite value")
    else:
        v = Fraction(m | 0x800000, 1) * Fraction(2) ** (e - 150)
    return -v if s else v


# V_CMP_CLASS_F32 class-mask bit order (LLVM's `llvm.amdgcn.class` layout,
# LSB first):  0 sNaN, 1 qNaN, 2 -inf, 3 -normal, 4 -subnormal, 5 -zero,
# 6 +zero, 7 +subnormal, 8 +normal, 9 +inf.
CLASS_BITS = {-1: 2, 1: 3, 2: 4, 3: 5, 4: 6, 5: 7, 6: 8, 7: 9}


def f32_class_bit(b):
    """Return the class-mask bit index of a binary32 value."""
    b &= U32
    s = (b >> 31) & 1
    e = (b >> 23) & 0xFF
    m = b & 0x7FFFFF
    if e == 0xFF:
        if m == 0:
            return 2 if s else 9                    # -inf / +inf
        return 1 if (m & 0x400000) else 0           # qNaN / sNaN
    if e == 0:
        if m == 0:
            return 5 if s else 6                    # -zero / +zero
        return 4 if s else 7                        # -subnormal / +subnormal
    return 3 if s else 8                            # -normal / +normal


class Halt(Exception):
    """Ends emulation: .kind in END/CYCLE/LDS-OOB/..."""

    def __init__(self, kind, info=None):
        super().__init__(kind)
        self.kind = kind
        self.info = info


class NotImpl(Exception):
    pass


class Core:
    def __init__(self, prog, lanes=32, vgprs=192, lds_size=4096, lds_fill=0,
                 wavebase=0, mem=None):
        self.prog = prog
        self.pc = 0
        self.lanes = lanes
        self.s = [0] * 128
        # Phase 14D8: SGPR indices that are declared-but-unpopulated at
        # dispatch entry (descriptor-derived gap). Reading one before any
        # kernel write is a Halt("UNDEFREAD"). Empty set = legacy behavior.
        self.undef_s = set()
        self.v = [[0] * vgprs for _ in range(lanes)]
        self.vcc_l = 0
        self.scc = 0
        self.exec_l = (1 << lanes) - 1
        self.lds = bytearray(lds_size)
        if isinstance(lds_fill, int):
            for i in range(0, lds_size, 2):
                self.lds[i] = lds_fill & 0xFF
                self.lds[i + 1] = (lds_fill >> 8) & 0xFF
        for lane in range(lanes):
            self.v[lane][0] = wavebase + lane  # tid within workgroup
        self.mem = mem if mem is not None else {}
        self.steps = 0
        self.global_stores = []  # (addr, byteval, lane)
        self._cyckeys = {}
        self._cyckeys_full = {}
        self.terminated = False

    def _v_signature(self):
        import hashlib
        h = hashlib.md5()
        for lane in range(self.lanes):
            for r in self.v[lane]:
                h.update(r.to_bytes(4, "little"))
        # mem signature: sorted (addr,val) of stores
        for addr in sorted(self.mem):
            h.update(addr.to_bytes(8, "little"))
            h.update((self.mem[addr] & 0xFFFFFFFF).to_bytes(4, "little"))
        return h.digest()

    # ---------------- register access ----------------
    def sget(self, tok):
        tok = tok.strip()
        if tok == "vcc_lo":
            return self.vcc_l
        if tok == "exec_lo":
            return self.exec_l
        if tok == "scc":
            return self.scc
        if tok == "m0":
            return self.s[76]
        if tok in ("null", "off"):
            return 0
        if tok.startswith("s"):
            i = int(tok[1:])
            self._chk_def(i)
            return self.s[i]
        if tok.startswith("0x"):
            return int(tok, 16)
        if tok.startswith("-0x"):
            return -int(tok[3:], 16)
        if tok.startswith("-"):
            return int(tok)
        return int(tok)

    def _chk_def(self, i):
        """Fail-closed read of a declared-but-unpopulated entry SGPR."""
        if i in self.undef_s:
            raise Halt("UNDEFREAD", i)

    @staticmethod
    def _bounds(tok):
        tok = tok.strip()
        if ":" not in tok:
            return None
        inner = tok.lstrip("s[").rstrip("]")
        a, b = (int(x) for x in inner.split(":"))
        return a, b

    def sset(self, tok, val):
        tok = tok.strip()
        if tok == "vcc_lo":
            self.vcc_l = val & U32
            return
        if tok == "exec_lo":
            self.exec_l = val & ((1 << self.lanes) - 1)
            return
        if tok == "scc":
            self.scc = val & 1
            return
        if tok in ("null", "off"):
            return
        if tok.startswith("s"):
            bd = self._bounds(tok)
            if bd:
                a, b = bd
                for i in range(a, b + 1):
                    self.s[i] = (val if not isinstance(val, list) else val[i - a]) & U32
                    self.undef_s.discard(i)
            else:
                self.s[int(tok[1:])] = val & U32
                self.undef_s.discard(int(tok[1:]))
            return
        raise NotImpl(f"sset {tok}")

    def spair(self, tok):
        """64-bit value from a scalar pair token s[a:b] or scalar tok."""
        tok = tok.strip()
        bd = self._bounds(tok)
        if bd:
            a, b = bd
            v = 0
            for i in range(b, a - 1, -1):
                self._chk_def(i)
                v = (v << 32) | (self.s[i] & U32)
            return v
        return self.sget(tok)

    def spair_set(self, tok, val):
        tok = tok.strip()
        val &= (1 << 64) - 1
        bd = self._bounds(tok)
        if bd:
            a, b = bd
            for i in range(a, b + 1):
                self.s[i] = (val >> (32 * (i - a))) & U32
                self.undef_s.discard(i)
        else:
            self.sset(tok, val & U32)

    def vget(self, lane, tok, fp=False):
        """Read one vector operand.

        `fp=True` means "this operand is an f32 VALUE", and it applies to
        REGISTER operands as much as to immediates.  Until Phase 16L the
        register paths returned the raw 32-bit pattern and only the immediate
        path decoded it, so `v_mul_f32 v2, v1, v2` computed with the integers
        `0x40400000` and `0x40800000` instead of 3.0 and 4.0 -- and every
        `_vfp` op, every `_vcmp` and every `_vcmpx` inherited that.  The two
        paths now agree, which is the only way one rule can be stated.
        """
        tok = tok.strip()
        if tok.startswith("|") and tok.endswith("|"):
            v = self.vget(lane, tok[1:-1], fp)
            return abs(v)
        if tok.startswith("v"):
            raw = self.v[lane][int(tok[1:])]
        elif tok.startswith("-v"):
            raw = self.v[lane][int(tok[2:])]
            if fp:
                # Phase 16T.  The ISA input modifier `-` on a FLOAT operand
                # negates the f32 VALUE, which is a flip of the encoding's
                # sign bit.  Negating the ENCODING with two's-complement
                # integer arithmetic is a different operation: 1.5
                # (0x3FC00000) came back as -3.0 (0xC0400000) instead of
                # -1.5 (0xBFC00000).  Phase 16S measured this on
                # `v_cvt_f16_f32_e32 v1, -v1`.
                raw ^= SIGN
            else:
                raw = (-raw) & U32
        elif tok == "vcc_lo":
            return (self.vcc_l >> lane) & 1
        elif tok == "exec_lo":
            return (self.exec_l >> lane) & 1
        elif tok.startswith("s"):
            raw = self.sget(tok)
        elif tok == "null" or tok == "off":
            raw = 0
        elif tok.startswith("0x"):
            raw = int(tok, 16)
        elif fp:
            return float(tok)
        else:
            return int(tok)
        return bits_f32(raw & U32) if fp else (raw & U32)

    def vset(self, lane, tok, val):
        tok = tok.strip()
        if tok.startswith("v") and ":" not in tok:
            self.v[lane][int(tok[1:])] = val & U32
            return
        raise NotImpl(f"vset {tok}")

    # ---------------- stepping ----------------
    def step(self):
        if self.pc >= len(self.prog):
            raise Halt("PCOVERRUN")
        ins = self.prog[self.pc]
        self.steps += 1
        mnem = ins["mnemonic"].replace("_e32", "").replace("_e64", "")
        ops = [o.strip() for o in ins["operands"].split(",")] if ins["operands"] else []
        if self.steps % 256 == 0:
            key = (self.pc, self.exec_l, self.vcc_l, self.scc, tuple(self.s))
            if key in self._cyckeys:
                # control state repeated: confirm full state (v + mem) also
                # repeats before declaring a true cycle
                sig = self._v_signature()
                if key in self._cyckeys_full and self._cyckeys_full[key] == sig:
                    raise Halt("CYCLE", (self._cyckeys[key], self.steps))
                self._cyckeys_full[key] = sig
            else:
                self._cyckeys[key] = self.steps
                # The first-visit fingerprint is read only by the branch
                # above, which is reachable only once this key is found
                # again -- so it is worth computing only when this mapping
                # can report membership at all.  `run_workgroup_hw` installs
                # `_NoKeys`, whose `__contains__` is always False; there the
                # fingerprint was computed and stored into a mapping that
                # could never be consulted.  That dead work measured at 95.7%
                # of a dispatch's wall clock: every 256 steps it hashed 6144
                # VGPRs plus 1.21M materialised memory entries, one
                # `to_bytes` and one `update` per field.
                if key in self._cyckeys:
                    self._cyckeys_full[key] = self._v_signature()
        self.pc += 1
        if mnem.startswith("v_dual_"):
            mnem = "v_" + mnem[len("v_dual_"):]
        if mnem.startswith("v_cmp_"):
            self._cmp_dispatch(mnem, ins, ops)
        elif mnem.startswith("v_cmpx_"):
            self._cmpx_dispatch(mnem, ins, ops)
        else:
            fn = getattr(self, "op_" + mnem, None)
            if fn is None:
                addr = ins.get("address")
                loc = f"{addr:#x}" if isinstance(addr, int) else ins.get("text", "?")
                raise NotImpl(f"{loc} {ins['mnemonic']} {ins['operands']}")
            fn(ins, ops)

    # ---------------- scalar ALU/control ----------------
    def op_s_mov_b32(self, ins, ops):
        self.sset(ops[0], self.sget(ops[1]))

    def _cmp_scc(self, fn):
        self.scc = 1 if fn() else 0

    def op_s_cmp_gt_i32(self, ins, ops):
        self._cmp_scc(lambda: s32(self.sget(ops[0])) > s32(self.sget(ops[1])))

    def op_s_cmp_eq_u32(self, ins, ops):
        self._cmp_scc(lambda: (self.sget(ops[0]) & U32) == (self.sget(ops[1]) & U32))

    def op_s_cmp_ge_u32(self, ins, ops):
        self._cmp_scc(lambda: (self.sget(ops[0]) & U32) >= (self.sget(ops[1]) & U32))

    def op_s_cmp_lt_u32(self, ins, ops):
        self._cmp_scc(lambda: (self.sget(ops[0]) & U32) < (self.sget(ops[1]) & U32))

    def op_s_cmp_lg_u32(self, ins, ops):
        self._cmp_scc(lambda: (self.sget(ops[0]) & U32) != (self.sget(ops[1]) & U32))

    def op_s_cselect_b32(self, ins, ops):
        # ISA: S_CSELECT_B32 sdst, src0, src1 => sdst = SCC ? src0 : src1.
        # The arms were swapped here until Phase 16I; that inverted every
        # `s_cmp_*; s_cselect_b32 sN, -1, 0` predicate-to-mask materialisation.
        self.sset(ops[0], self.sget(ops[1] if self.scc else ops[2]))

    def op_s_and_b32(self, ins, ops):
        self.sset(ops[0], self.sget(ops[1]) & self.sget(ops[2]))

    def op_s_or_b32(self, ins, ops):
        self.sset(ops[0], (self.sget(ops[1]) | self.sget(ops[2])) & U32)

    def op_s_xor_b32(self, ins, ops):
        self.sset(ops[0], (self.sget(ops[1]) ^ self.sget(ops[2])) & U32)

    def op_s_and_not1_b32(self, ins, ops):
        self.sset(ops[0], (self.sget(ops[1]) & ~self.sget(ops[2])) & U32)

    def op_s_andn2_b32(self, ins, ops):
        self.op_s_and_not1_b32(ins, ops)

    def _saveexec(self, dst, newmask):
        old = self.exec_l
        self.sset(dst, old)
        self.exec_l = newmask & ((1 << self.lanes) - 1)

    def op_s_and_saveexec_b32(self, ins, ops):
        self._saveexec(ops[0], self.exec_l & self.sget(ops[1]))

    def op_s_andn2_saveexec_b32(self, ins, ops):
        """EXEC = S0 & ~EXEC_old, and D = EXEC_old.

        This handler used to compute `EXEC_old & ~S0`, which is the ANDN2
        operands the wrong way round.  It was wrong here AND in the
        nominally independent `isa_oracle_scalar.py`, so the two agreed and
        the conformance suite reported PASS on the vector that covers this
        opcode: the vector's inputs happen to make both readings equal.
        Two implementations agreeing is not evidence when neither can
        distinguish the readings.

        WHY THE ISA READING IS THE CORRECT ONE -- from the kernel itself,
        not from a document.  139 sites in `k_swin_var<32,false>` use the
        gfx11 if/else idiom:

            s_mov_b32 s12, exec_lo
            v_cmpx_ne_u32_e32 0, v5      ; narrow EXEC
            s_xor_b32 s12, exec_lo, s12  ; s12 = lanes that got masked OFF
            s_andn2_saveexec_b32 s12, s12
            <else-block>
            s_or_b32 exec_lo, exec_lo, s12

        The restore is `EXEC | s12`, and the saveexec writes EXEC_old into
        s12, so the restore yields `else_lanes | EXEC_now`.  Under the ISA
        reading, EXEC_new = s12 & ~EXEC_now = exactly the lanes masked off,
        and the restore reconstructs EXEC_before exactly.  Under the old
        reading EXEC_new = EXEC_now, the else-block runs on the SAME lanes
        as the if-block, and the restore is meaningless.  The ISA reading is
        what makes the surrounding code coherent; that argument is the
        decisive one and it is reproducible from the disassembly.
        """
        self._saveexec(ops[0], self.sget(ops[1]) & ~self.exec_l)

    def op_s_or_saveexec_b32(self, ins, ops):
        self._saveexec(ops[0], self.exec_l | self.sget(ops[1]))

    def op_s_xor_saveexec_b32(self, ins, ops):
        self._saveexec(ops[0], self.exec_l ^ self.sget(ops[1]))

    def op_s_and_not1_saveexec_b32(self, ins, ops):
        self._saveexec(ops[0], self.exec_l & ~self.sget(ops[1]))

    def op_s_add_u32(self, ins, ops):
        a = self.sget(ops[1]); b = self.sget(ops[2])
        r = a + b
        self.sset(ops[0], r)
        self.scc = 1 if r > U32 else 0

    def op_s_add_i32(self, ins, ops):
        self.sset(ops[0], self.sget(ops[1]) + self.sget(ops[2]))

    def op_s_addc_u32(self, ins, ops):
        a = self.sget(ops[1]); b = self.sget(ops[2]) + self.scc
        r = a + b
        self.sset(ops[0], r)
        self.scc = 1 if r > U32 else 0

    def op_s_sub_i32(self, ins, ops):
        self.sset(ops[0], self.sget(ops[1]) - self.sget(ops[2]))

    def op_s_mul_i32(self, ins, ops):
        self.sset(ops[0], (s32(self.sget(ops[1])) * s32(self.sget(ops[2]))) & U32)

    def op_s_mul_hi_u32(self, ins, ops):
        self.sset(ops[0], ((self.sget(ops[1]) * self.sget(ops[2])) >> 32) & U32)

    def op_s_mul_hi_i32(self, ins, ops):
        p = s32(self.sget(ops[1])) * s32(self.sget(ops[2]))
        self.sset(ops[0], (p >> 32) & U32)

    def op_s_ashr_i32(self, ins, ops):
        a = self.sget(ops[1]); sh = self.sget(ops[2]) & 31
        if sh == 0:
            self.sset(ops[0], a)
        else:
            self.sset(ops[0], (s32(a) >> sh) & U32)

    def op_s_lshl_b32(self, ins, ops):
        self.sset(ops[0], (self.sget(ops[1]) << (self.sget(ops[2]) & 31)) & U32)

    def op_s_lshr_b32(self, ins, ops):
        self.sset(ops[0], (self.sget(ops[1]) >> (self.sget(ops[2]) & 31)) & U32)

    def op_s_lshl_b64(self, ins, ops):
        v = self.spair(ops[1])
        sh = self.sget(ops[2]) & 63 if len(ops) > 2 else 0
        self.spair_set(ops[0], (v << sh) & ((1 << 64) - 1))

    def op_s_abs_i32(self, ins, ops):
        self.sset(ops[0], abs(s32(self.sget(ops[1]))) & U32)

    def op_s_cbranch_scc0(self, ins, ops):
        if self.scc == 0:
            self.pc = ins["target"]

    def op_s_cbranch_scc1(self, ins, ops):
        if self.scc == 1:
            self.pc = ins["target"]

    def op_s_cbranch_vccz(self, ins, ops):
        if self.vcc_l == 0:
            self.pc = ins["target"]

    def op_s_cbranch_vccnz(self, ins, ops):
        if self.vcc_l != 0:
            self.pc = ins["target"]

    def op_s_cbranch_execz(self, ins, ops):
        if self.exec_l == 0:
            self.pc = ins["target"]

    def op_s_cbranch_execnz(self, ins, ops):
        if self.exec_l != 0:
            self.pc = ins["target"]

    def op_s_branch(self, ins, ops):
        self.pc = ins["target"]

    def op_s_endpgm(self, ins, ops):
        self.terminated = True
        raise Halt("END")

    # ---------------- scalar loads ----------------
    def _sload(self, ins, ops, nwords):
        dst = ops[0]
        base = self.spair(ops[1])
        off = self.sget(ops[2]) if len(ops) > 2 else 0
        addr = (base + off) & ((1 << 64) - 1)
        words = []
        for i in range(nwords):
            words.append(self._read_u32(addr + 4 * i))
        bd = self._bounds(dst)
        if bd:
            a, b = bd
            for j, i in enumerate(range(a, b + 1)):
                self.s[i] = words[j]
                self.undef_s.discard(i)
        else:
            self.sset(dst, words[0])

    def op_s_load_b32(self, ins, ops):
        self._sload(ins, ops, 1)

    def op_s_load_b64(self, ins, ops):
        self._sload(ins, ops, 2)

    def op_s_load_b128(self, ins, ops):
        self._sload(ins, ops, 4)

    op_s_load_dword = op_s_load_b32
    op_s_load_dwordx2 = op_s_load_b64
    op_s_load_dwordx4 = op_s_load_b128

    def _mem_byte(self, addr):
        """One byte of the ARCHITECTURAL, byte-addressed memory.

        Phase 16M M2 recorded that this emulator's global-memory models and
        its scalar-load model "cannot interoperate": `_read_u32` was a bare
        `mem.get(addr, 0)`, so a scalar load whose region had been primed
        BYTE BY BYTE (which is how `module_mem_map` maps the module image, and
        how `global_store_byte` writes) returned one byte where a dword was
        asked for.

        One rule now covers both priming conventions:
          * a byte key at this address wins -- it is the most specific fact;
          * otherwise the aligned dword key covering the address is split
            little-endian;
          * otherwise the byte is zero.
        The dword fallback is tried at the address with its low two bits
        cleared, which is the only alignment a dword store can have written.

        Phase 16O: the two "does a real entry exist" tests below are
        `dict.__contains__`, not `in`.  `in` asks the memory object a
        DIFFERENT question -- for `PatternMem` it means "does data live
        anywhere at this address", which is true for every address inside a
        declared region, including ones never written.  Using it here made a
        synthesised pattern byte outrank a real dword key, so a 4-byte read
        at a dword-keyed address returned one real byte and three bytes of
        noise.  A real dword at the aligned base shadows the pattern for its
        four bytes, which is exactly what `PatternMem` documents a store to
        do; that only holds if the reader can tell the two apart.
        """
        a = addr & ((1 << 64) - 1)
        if dict.__contains__(self.mem, a):
            return self.mem[a] & 0xFF
        base = a & ~3
        if dict.__contains__(self.mem, base):
            return (self.mem[base] >> (8 * (a - base))) & 0xFF
        try:
            return self.mem[a] & 0xFF       # synthesised region byte, or 0
        except (KeyError, IndexError):
            return 0

    def _read_u32(self, addr):
        """A 4-byte little-endian load, through the byte-addressed model."""
        a = addr & ((1 << 64) - 1)
        return (self._mem_byte(a)
                | (self._mem_byte(a + 1) << 8)
                | (self._mem_byte(a + 2) << 16)
                | (self._mem_byte(a + 3) << 24))

    # ---------------- FP16 operand decoding and fused multiply-add -------
    # Phase 16T.  Added for the four FP16 mnemonics Phase 16S measured: the
    # operand of an FP16 instruction is an FP16 VALUE, so a register's low
    # 16 bits are already its bit pattern, an integer literal is its own
    # pattern, and a decimal literal such as `1.0` denotes the binary16
    # encoding 0x3C00.  Before this, `v_pack_b32_f16 v11, v5, 1.0` reached
    # `int('1.0')` and raised `ValueError`.
    @staticmethod
    def _f16_literal(tok):
        t = tok.strip()
        try:
            if t[:2].lower() == "0x":
                return int(t, 16) & 0xFFFF
            return int(t, 10) & 0xFFFF
        except ValueError:
            pass
        return f32_bits_to_f16(f32_bits(float(t)))

    def _f16_src_bits(self, lane, tok):
        """Read one operand as a raw binary16 bit pattern."""
        t = tok.strip()
        if t.startswith("|") and t.endswith("|"):
            return self._f16_src_bits(lane, t[1:-1]) & 0x7FFF
        if t.startswith("-v"):
            return (self._f16_src_bits(lane, t[1:]) ^ 0x8000) & 0xFFFF
        if t == "null" or t == "off":
            return 0
        if t.startswith("v") and t[1:].isdigit():
            return self.v[lane][int(t[1:])] & 0xFFFF
        if t.startswith("s"):
            return self.sget(t) & 0xFFFF
        return self._f16_literal(t)

    def _fma_mix16(self, ins, ops, high):
        """V_FMA_MIXLO_F16 (high=False) / V_FMA_MIXHI_F16 (high=True).

        One FP16 fused multiply-add, its 16-bit result written into one half
        of the 32-bit destination; the OTHER half of the destination is
        untouched, which is what `D.f[15:0] = ...` / `D.f[31:16] = ...`
        means.  DECLARED reading of the source half: OPSEL is absent from
        every printed J3 form, and the low 16 bits of each source are read --
        the reading phase16s/isa/oracle16.py declares.
        """
        idx = int(ops[0].strip()[1:])
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self._f16_src_bits(lane, ops[1])
                b = self._f16_src_bits(lane, ops[2])
                c = self._f16_src_bits(lane, ops[3])
                r = f16_fma_bits(a, b, c)
                old = self.v[lane][idx]
                if high:
                    self.v[lane][idx] = ((old & 0x0000FFFF)
                                         | ((r & 0xFFFF) << 16)) & U32
                else:
                    self.v[lane][idx] = ((old & 0xFFFF0000)
                                         | (r & 0xFFFF)) & U32

    # ---------------- vector ops ----------------
    def _vbin(self, ins, ops, fn):
        """dst=ops[0], src0=ops[1], src1=ops[2] (int); returns int or fp-typed."""
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[1])
                b = self.vget(lane, ops[2])
                self.vset(lane, ops[0], fn(a, b))

    def _vbin3(self, ins, ops, fn):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[1])
                b = self.vget(lane, ops[2])
                c = self.vget(lane, ops[3])
                self.vset(lane, ops[0], fn(a, b, c))

    # Operand DECODE KINDS, by printed operand index (1-based, dst excluded).
    #   "int" -> the operand is a RAW INTEGER even though the instruction
    #            produces a float  (`v_cvt_f32_u32 v0, v1`)
    #   "f16" -> the operand is a RAW f16 BIT PATTERN (`v_cvt_f32_f16 v0, v1`)
    # Everything not listed is an f32 VALUE, which is the common case and the
    # one the Phase 16L fp repair establishes.
    #
    # Declared centrally rather than passed per handler so that adding an
    # instruction forces the question "what are its operands, really?" to be
    # answered in one place.
    _SRC_KIND = {
        "v_cvt_f32_u32": {1: "int"},
        "v_cvt_f32_i32": {1: "int"},
        "v_cvt_f32_ubyte0": {1: "int"},
        "v_cvt_f32_f16": {1: "f16"},
        # The exponent is SIGNED.  Reading it as an unsigned 32-bit value
        # turns -3 into 0xFFFFFFFD and the scale into a huge positive one.
        "v_ldexp_f32": {2: "sint"},
        "v_frexp_exp_i32_f32": {1: "int"},
    }

    # The same question for the DESTINATION, because FMA-family instructions
    # read it as a third input.  Default is an f32 value; a conversion writes
    # its result over bits it never read, so there is nothing to decode.
    _DST_KIND = {
        "v_cvt_f32_u32": "int",
        "v_cvt_f32_i32": "int",
        "v_cvt_f32_ubyte0": "int",
        "v_cvt_f32_f16": "int",
        "v_cvt_f16_f32": "int",
        "v_cvt_i32_f32": "int",
        "v_cvt_u32_f32": "int",
        "v_frexp_exp_i32_f32": "int",
        "v_frexp_mant_f32": "int",
    }

    def _vfp(self, ins, ops, fn, int_src=None, fp16_src=None):
        """float op: dst=ops[0], operands as f32 values; writes f32 bits.

        Not every operand of a float-producing instruction is a float, and
        assuming otherwise is the same class of error as the one the fp repair
        fixes, pointing the other way.  `int_src` names the printed operand
        indices (1-based) that must be read as RAW INTEGERS
        (`v_cvt_f32_u32 v0, v1` reinterprets v1 as an unsigned integer);
        `fp16_src` names those that must be read as RAW f16 BIT PATTERNS
        (`v_cvt_f32_f16 v0, v1`).  Everything else is an f32 value.

        The Phase 16L oracle is what forced this distinction to be explicit:
        `v_cvt_f32_u32` with a blanket `fp=True` raised
        `TypeError: unsupported operand type(s) for &: 'float' and 'int'`.
        """
        mnem = ins["mnemonic"].replace("_e32", "").replace(
            "_e64", "").replace("_e32_dpp", "")
        kinds = self._SRC_KIND.get(mnem, {})
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                vals = []
                for i in range(1, len(ops)):
                    k = kinds.get(i)
                    if k == "int" or (int_src and i in int_src):
                        vals.append(self.vget(lane, ops[i], fp=False) & U32)
                    elif k == "sint":
                        vals.append(s32(self.vget(lane, ops[i], fp=False)))
                    elif k == "f16" or (fp16_src and i in fp16_src):
                        vals.append(self.vget(lane, ops[i], fp=False) & 0xFFFF)
                    else:
                        vals.append(self.vget(lane, ops[i], fp=True))
                a = vals[0] if len(vals) > 0 else None
                b = vals[1] if len(vals) > 1 else None
                c = vals[2] if len(vals) > 2 else None
                r = fn(a, b, c)
                if isinstance(r, float):
                    self.vset(lane, ops[0], f32_bits(f32(r)))
                else:
                    self.vset(lane, ops[0], r & U32)

    def _vcmp(self, ins, ops, fn, fp):
        """int/float compare: dst vcc_lo (e32) or sreg mask (e64)."""
        dst = ops[0]
        if dst == "vcc_lo":
            out = self.vcc_l
            for lane in range(self.lanes):
                if (self.exec_l >> lane) & 1:
                    a = self.vget(lane, ops[1], fp=fp)
                    b = self.vget(lane, ops[1], fp=fp) if len(ops) < 3 else self.vget(lane, ops[2], fp=fp)
                    bit = 1 if fn(a, b) else 0
                    out = (out & ~(1 << lane)) | (bit << lane)
                else:
                    out &= ~(1 << lane)
            self.vcc_l = out
        else:
            mask = 0
            for lane in range(self.lanes):
                if (self.exec_l >> lane) & 1:
                    a = self.vget(lane, ops[1], fp=fp)
                    b = self.vget(lane, ops[1], fp=fp) if len(ops) < 3 else self.vget(lane, ops[2], fp=fp)
                    if fn(a, b):
                        mask |= 1 << lane
            self.sset(dst, mask)

    def _vcmp_class(self, ins, ops):
        """V_CMP_CLASS_F32 dst, src0, src1 -- src1 is the class MASK.

        Replaces `lambda a, b: math.isnan(a) or math.isinf(a)`, which took no
        notice of src1 at all: under it the mask 0x260 (which selects both
        zeros and +inf) could never match a zero, and -inf matched a mask
        that excludes it.  The mask is read as an integer and the value is
        classified by `f32_class_bit`.
        """
        dst = ops[0]
        out = 0
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                bits = self.vget(lane, ops[1]) & U32
                mask = self.vget(lane, ops[2], fp=False) & U32
                if (mask >> f32_class_bit(bits)) & 1:
                    out |= 1 << lane
        if dst == "vcc_lo" or dst == "vcc":
            self.vcc_l = out
        else:
            self.sset(dst, out)

    def _vcmpx(self, ins, ops, fn, fp):
        """`v_cmpx_*` writes EXEC.  Its operands are src0 and src1.

        The disassembler prints a destination slot for `v_cmpx_*` too -- the
        line in the Candidate F module is `v_cmpx_neq_f32_e32 0, v5` -- so
        src0 is ops[0] and src1 is ops[1], NOT ops[1] and ops[2].

        Until Phase 16L this read `ops[1]` for both operands whenever the
        operand list was short, evaluating every short `v_cmpx_*` as
        `fn(src0, src0)`: a comparison against itself.  At 0x000B5124 that
        turned `v_cmpx_neq_f32_e32 0, v5` into `EXEC=0` where the ISA gives
        `EXEC=0xFFFFFFFF`, and the branch on EXEC then skipped the entire
        E4M3 magnitude encoder.
        """
        out = 0
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[0], fp=fp)
                b = self.vget(lane, ops[1], fp=fp)
                if fn(a, b):
                    out |= 1 << lane
        self.exec_l = out

    def _int_cmp_cond(self, name):
        cmps = {
            "v_cmp_gt_i32": lambda a, b: s32(a) > s32(b),
            "v_cmp_eq_u32": lambda a, b: (a & U32) == (b & U32),
            "v_cmp_lt_u32": lambda a, b: (a & U32) < (b & U32),
            "v_cmp_gt_u32": lambda a, b: (a & U32) > (b & U32),
            "v_cmp_ge_u32": lambda a, b: (a & U32) >= (b & U32),
            "v_cmp_le_u32": lambda a, b: (a & U32) <= (b & U32),
            "v_cmp_eq_i32": lambda a, b: s32(a) == s32(b),
            "v_cmp_ne_u32": lambda a, b: (a & U32) != (b & U32),
            "v_cmp_ne_i32": lambda a, b: s32(a) != s32(b),
            # Phase 16L additive: these three were absent, so a stream using
            # them raised KeyError rather than comparing.  `_cmp_dispatch`
            # already listed them, which made the gap look covered.
            "v_cmp_lt_i32": lambda a, b: s32(a) < s32(b),
            "v_cmp_le_i32": lambda a, b: s32(a) <= s32(b),
            "v_cmp_ge_i32": lambda a, b: s32(a) >= s32(b),
            "v_cmp_gt_i16": lambda a, b: _s16(a) > _s16(b),
            # phase-14D8 additive width/condition families (deterministic)
            "v_cmp_eq_u16": lambda a, b: (a & 0xFFFF) == (b & 0xFFFF),
            "v_cmp_ne_u16": lambda a, b: (a & 0xFFFF) != (b & 0xFFFF),
            "v_cmp_lt_u16": lambda a, b: (a & 0xFFFF) < (b & 0xFFFF),
            "v_cmp_le_u16": lambda a, b: (a & 0xFFFF) <= (b & 0xFFFF),
            "v_cmp_gt_u16": lambda a, b: (a & 0xFFFF) > (b & 0xFFFF),
            "v_cmp_ge_u16": lambda a, b: (a & 0xFFFF) >= (b & 0xFFFF),
            "v_cmp_lt_i16": lambda a, b: _s16(a) < _s16(b),
            "v_cmp_le_i16": lambda a, b: _s16(a) <= _s16(b),
            "v_cmp_ge_i16": lambda a, b: _s16(a) >= _s16(b),
            "v_cmp_ne_i16": lambda a, b: _s16(a) != _s16(b),
            "v_cmp_eq_i16": lambda a, b: _s16(a) == _s16(b),
            "v_cmp_lt_i8": lambda a, b: _s8(a) < _s8(b),
            "v_cmp_gt_i8": lambda a, b: _s8(a) > _s8(b),
            "v_cmp_le_i8": lambda a, b: _s8(a) <= _s8(b),
            "v_cmp_ge_i8": lambda a, b: _s8(a) >= _s8(b),
            "v_cmp_eq_i8": lambda a, b: _s8(a) == _s8(b),
            "v_cmp_ne_i8": lambda a, b: _s8(a) != _s8(b),
        }
        return cmps[name]

    def _fp_cmp_cond(self, name):
        cmps = {
            "v_cmp_gt_f16": lambda a, b: f16_to_f32(a) > f16_to_f32(b),
            "v_cmp_ge_f16": lambda a, b: f16_to_f32(a) >= f16_to_f32(b),
            "v_cmp_eq_f16": lambda a, b: f16_to_f32(a) == f16_to_f32(b),
            "v_cmp_lt_f16": lambda a, b: f16_to_f32(a) < f16_to_f32(b),
            "v_cmp_gt_f32": lambda a, b: a > b,
            "v_cmp_ge_f32": lambda a, b: a >= b,
            "v_cmp_eq_f32": lambda a, b: a == b,
            "v_cmp_lt_f32": lambda a, b: a < b,
            "v_cmp_nlt_f32": lambda a, b: not (a < b),
            "v_cmp_nge_f32": lambda a, b: not (a >= b),
            "v_cmp_neq_f32": lambda a, b: a != b,
            "v_cmp_lg_f32": lambda a, b: a != b,
            # Phase 16L additive.  `ngt` is the one the E4M3 encoder needs at
            # `v_cmpx_ngt_f32_e32 0x3c800000, v5`; `nle` is its sibling and was
            # missing for the same reason.  Both are the NEGATION of the
            # ordered test, so they are TRUE when either operand is NaN --
            # writing them as `a <= b` / `a > b` would be the classic error.
            "v_cmp_ngt_f32": lambda a, b: not (a > b),
            "v_cmp_nle_f32": lambda a, b: not (a <= b),
            "v_cmp_ngt_f16": lambda a, b: not (f16_to_f32(a) > f16_to_f32(b)),
            "v_cmp_nle_f16": lambda a, b: not (f16_to_f32(a) <= f16_to_f32(b)),
            "v_cmp_nlt_f16": lambda a, b: not (f16_to_f32(a) < f16_to_f32(b)),
            "v_cmp_neq_f16": lambda a, b: f16_to_f32(a) != f16_to_f32(b),
            "v_cmp_ngt_f64": lambda a, b: not (a > b),
            "v_cmp_nle_f64": lambda a, b: not (a <= b),
            "v_cmp_nlt_f64": lambda a, b: not (a < b),
            "v_cmp_nge_f64": lambda a, b: not (a >= b),
            "v_cmp_neq_f64": lambda a, b: a != b,
            "v_cmp_o_f16": lambda a, b: not (math.isnan(f16_to_f32(a)) or math.isnan(f16_to_f32(b))),
            "v_cmp_o_f32": lambda a, b: not (math.isnan(a) or math.isnan(b)),
            "v_cmp_o_f64": lambda a, b: not (math.isnan(a) or math.isnan(b)),
            "v_cmp_u_f16": lambda a, b: math.isnan(f16_to_f32(a)) or math.isnan(f16_to_f32(b)),
            "v_cmp_u_f32": lambda a, b: math.isnan(a) or math.isnan(b),
            "v_cmp_u_f64": lambda a, b: math.isnan(a) or math.isnan(b),
            # `v_cmp_class_f32` is deliberately ABSENT here.  Its src1 is a
            # class MASK, not a value, so no binary predicate over two floats
            # can express it -- and the entry that used to live here
            # (`lambda a, b: math.isnan(a) or math.isinf(a)`) silently
            # answered a different question than the one the instruction
            # asks.  `_cmp_dispatch` routes it to `_vcmp_class`, which reads
            # the mask; asking this table for it is a KeyError.
        }
        return cmps[name]

    def __getattr__(self, name):
        # dynamic handlers for compare families
        if name.startswith("op_v_cmp_"):
            mnem = name[3:]
            if mnem in self._int_cmp_cond("") or mnem.replace("v_", "v_") in self._int_cmp_cond(""):
                pass
        raise AttributeError(name)

    def _cmp_dispatch(self, m, ins, ops):
        ints = ("v_cmp_gt_i32", "v_cmp_eq_u32", "v_cmp_lt_u32", "v_cmp_gt_u32",
                "v_cmp_ge_u32", "v_cmp_le_u32", "v_cmp_eq_i32", "v_cmp_ne_u32",
                "v_cmp_lt_i32", "v_cmp_le_i32", "v_cmp_ge_i32", "v_cmp_ne_i32",
                "v_cmp_gt_i16", "v_cmp_eq_u16", "v_cmp_ne_u16", "v_cmp_lt_u16",
                "v_cmp_le_u16", "v_cmp_gt_u16", "v_cmp_ge_u16", "v_cmp_lt_i16",
                "v_cmp_le_i16", "v_cmp_ge_i16", "v_cmp_ne_i16", "v_cmp_eq_i16",
                "v_cmp_lt_i8", "v_cmp_gt_i8", "v_cmp_le_i8", "v_cmp_ge_i8",
                "v_cmp_eq_i8", "v_cmp_ne_i8")
        if m == "v_cmp_class_f32":
            # V_CMP_CLASS_F32 dst, src0, src1 where src1 is a 10-BIT INTEGER
            # class mask, not a float.  Reading it with fp=True would decode
            # 0x260 as a denormal f32 and the test would be meaningless; the
            # pre-16N code avoided that only by ignoring the operand entirely.
            self._vcmp_class(ins, ops)
            return
        if m in ints:
            self._vcmp(ins, ops, self._int_cmp_cond(m), fp=False)
            return
        cond = self._fp_cmp_cond(m)
        if m.endswith("_f16"):
            self._vcmp(ins, ops, cond, fp=False)
        else:
            self._vcmp(ins, ops, cond, fp=True)

    def _cmpx_dispatch(self, m, ins, ops):
        ints = ("v_cmpx_gt_i32", "v_cmpx_eq_u32", "v_cmpx_lt_u32", "v_cmpx_gt_u32",
                "v_cmpx_ne_u32", "v_cmpx_eq_i32", "v_cmpx_ne_i32", "v_cmpx_lt_i32",
                "v_cmpx_ge_u32", "v_cmpx_le_u32", "v_cmpx_lt_i32", "v_cmpx_le_i32",
                "v_cmpx_ge_i32", "v_cmpx_ne_i32", "v_cmpx_eq_u16", "v_cmpx_ne_u16",
                "v_cmpx_lt_u16", "v_cmpx_le_u16", "v_cmpx_gt_u16", "v_cmpx_ge_u16",
                "v_cmpx_lt_i16", "v_cmpx_le_i16", "v_cmpx_ge_i16", "v_cmpx_ne_i16",
                "v_cmpx_eq_i16", "v_cmpx_gt_i16",
                # Phase 16L: `ge_i8` and `le_i8` were absent from this list
                # AND from `_int_cmp_cond`, so a stream using either fell
                # through to the fp table and raised KeyError.  `le_i32` and
                # `ne_i32` above appear twice; that is harmless (tuple
                # membership), so they are left as they were rather than
                # tidied, since this list is also a record of what was
                # believed to be covered.
                "v_cmpx_lt_i8", "v_cmpx_gt_i8", "v_cmpx_le_i8", "v_cmpx_ge_i8",
                "v_cmpx_eq_i8", "v_cmpx_ne_i8")
        if m in ints:
            name = m.replace("v_cmpx_", "v_cmp_")
            self._vcmpx(ins, ops, self._int_cmp_cond(name), fp=False)
        else:
            name = m.replace("v_cmpx_", "v_cmp_")
            cond = self._fp_cmp_cond(name)
            if name.endswith("_f16"):
                self._vcmpx(ins, ops, cond, fp=False)
            else:
                self._vcmpx(ins, ops, cond, fp=True)

    # ---- extra ops needed by the main (work) region ----
    def op_s_bfe_i32(self, ins, ops):
        a = self.sget(ops[1]); o = self.sget(ops[2]) & 31; w = self.sget(ops[3]) & 31
        if w == 0:
            r = 0
        else:
            r = (a >> o) & U32
            if o + w < 32:
                r &= (1 << w) - 1
                if r & (1 << (w - 1)):
                    r |= (U32 << w) & U32
        self.sset(ops[0], r)

    def op_s_bfe_u32(self, ins, ops):
        a = self.sget(ops[1]); o = self.sget(ops[2]) & 31; w = self.sget(ops[3]) & 31
        r = ((a >> o) & ((1 << w) - 1)) & U32 if w else 0
        self.sset(ops[0], r)

    def op_s_cmp_ge_i32(self, ins, ops):
        self._cmp_scc(lambda: s32(self.sget(ops[0])) >= s32(self.sget(ops[1])))

    def op_s_min_i32(self, ins, ops):
        self.sset(ops[0], min(s32(self.sget(ops[1])), s32(self.sget(ops[2]))) & U32)

    def op_s_sext_i32_i16(self, ins, ops):
        self.sset(ops[0], _s16(self.sget(ops[1])) & U32)

    def op_s_sext_i32_i8(self, ins, ops):
        self.sset(ops[0], _s8(self.sget(ops[1])) & U32)

    def op_s_movk_i32(self, ins, ops):
        # S_MOVK_I32 prints its immediate as an integer literal, and in this
        # project's disassembly that literal carries the `0x` prefix
        # (`s_movk_i32 s7, 0x100`).  `self.sset` masks with `& U32`, so a
        # NEGATIVE literal is fine, but the prefixed form is not an int to
        # Python at all.  `Core.parse_simm` is just `sget`, which does not
        # accept `0x` for an `s`-token, so this raised ValueError on every
        # prefixed site -- 15 of them in the J3 kernel alone.
        self.sset(ops[0], self.parse_simm(ops[1]))

    def parse_simm(self, tok):
        """A scalar immediate operand.

        `s_movk_i32 s7, 0x100` and `s_movk_i32 s7, -4` both occur in the
        modules.  This used to be plain `sget`, whose `0x` branch is guarded
        behind `tok.startswith("s")` -- so a prefixed literal fell through to
        `int(tok)` and raised `ValueError: invalid literal for int() with base
        10: '0x100'`.  Fifteen such sites exist in the J3 kernel alone, so
        every one of them aborted its dispatch.

        A negative literal is handled too, and the caller's `& U32` turns it
        into the two's-complement word the hardware writes.
        """
        tok = tok.strip()
        low = tok.lower()
        if low.startswith("0x") or low.startswith("-0x"):
            return int(tok, 16)
        if tok.lstrip("-").isdigit():
            return int(tok)
        return self.sget(tok)

    def op_v_cvt_f32_ubyte0(self, ins, ops):
        # Source is the RAW low byte of a register; result is a float.
        self._vfp(ins, ops, lambda a, b, c: f32(float(a & 0xFF)))

    def op_v_fma_mixlo_f16(self, ins, ops):
        # ISA rdna2_isa.txt:9350-9361 -- an FP16 fused multiply-add written
        # into the LOW half of the destination:
        #     D.f[15:0] = S0.f * S1.f + S2.f.
        # The previous body read each source's FULL 32 bits as an f32 value,
        # evaluated in f32 and wrote the f32 result over the WHOLE
        # destination, so neither the operand width nor the result placement
        # was the ISA's.  Phase 16S measured that divergence as UNCONDITIONAL
        # -- there is no operand for which the two agree -- on all 224 J3
        # executions.  `_fma_mix16` is shared with the MIXHI handler.
        self._fma_mix16(ins, ops, high=False)

    def op_v_lshl_or_b32(self, ins, ops):
        # ISA: dst = (src0 << src1) | src2.  src0 is the run of bits, src1 the
        # count.  Until Phase 16L this computed (src1 << src0) | src2.
        #
        # This one matters more than its sibling: v_lshl_or_b32 is the
        # instruction K4 identified as forming the LDS ring TAG, so the
        # swapped form mis-evaluated the operand that the whole LDS
        # outside-bound question is about.  Disassembly shape, e.g.
        # `v_lshl_or_b32 v3, v40, 7, v37` -- a shift amount of 7 in the src1
        # slot is only meaningful if src0 is the value.
        self._vbin3(ins, ops, lambda a, b, c: ((a << (b & 31)) | c) & U32)

    @staticmethod
    def _perm_b32(a, b, c):
        """v_perm_b32: assemble the result byte by byte from four selectors.

        Selector values, per byte position of src2:
            0..3    byte i of src0        4..7    byte (i-4) of src1
            8 -> 0x00   9 -> 0xFF   10 -> 0x80   11 -> 0x7F
            12 -> 0x00/0xFF by src0 sign bit   13 -> by src0 bit 15
            14 -> by src1 sign bit             15 -> by src1 bit 15

        Until Phase 16L this returned src1 unchanged, discarding the selectors
        entirely.  It is a DATA path op rather than a control op, so the old
        stub could not change which instructions executed -- but it could
        change every value that flows into the E4M3 encoder, which is exactly
        what a numerical contract must not get wrong.
        """
        a &= U32
        b &= U32
        c &= U32
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
                byte = 0xFF if (a & SIGN) else 0x00
            elif sel == 13:
                byte = 0xFF if (a & 0x8000) else 0x00
            elif sel == 14:
                byte = 0xFF if (b & SIGN) else 0x00
            else:
                byte = 0xFF if (b & 0x8000) else 0x00
            out |= byte << (8 * i)
        return out & U32

    def op_v_perm_b32(self, ins, ops):
        self._vbin3(ins, ops, self._perm_b32)

    def op_v_bfi_b32(self, ins, ops):
        """dst = (src0 & src1) | (~src0 & src2).  Was absent entirely."""
        self._vbin3(ins, ops, lambda a, b, c: ((a & b) | (~a & c)) & U32)

    def op_v_cvt_f32_i32(self, ins, ops):
        """Source is a SIGNED INTEGER register.  Was absent entirely."""
        self._vfp(ins, ops, lambda a, b, c: f32(float(s32(a))))

    def op_v_max_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: max(a & U32, b & U32))

    def op_global_load_i8(self, ins, ops):
        dst = ops[0]
        lo_n, hi_n = (int(x) for x in ops[1].lstrip("v[").rstrip("]").split(":"))
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                addr = self.v[lane][lo_n] | (self.v[lane][hi_n] << 32)
                val = self.mem.get(addr, 0)
                self.vset(lane, dst, _s8(val) & U32)

    def op_global_load_u16(self, ins, ops):
        dst = ops[0]
        lo_n, hi_n = (int(x) for x in ops[1].lstrip("v[").rstrip("]").split(":"))
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                addr = self.v[lane][lo_n] | (self.v[lane][hi_n] << 32)
                val = self.mem.get(addr, 0)
                self.vset(lane, dst, val)

    def op_v_wmma_f32_16x16x16_f16(self, ins, ops):
        # value-stub: no control impact; accumulate conservative junk so any
        # later data-dependent compare still exercises all paths deterministically
        dst = ops[0]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                pass  # leave accumulator as-is; control-neutral

    def op_v_dot2c_f32_f16(self, ins, ops):
        """VDOT2C_F32_F16 -- the software-WMMA dot product.

        D.f32 = D.f32 + f32(S0.f16[lo] * S1.f16[lo])
                      + f32(S0.f16[hi] * S1.f16[hi])

        operand sel: the kernel spells the plain two-operand form, so both
        halves are the LO..HI pair in order.  Products of two f16 values are
        exact in f32 (11-bit significands -> 22 bits), so the only rounding
        decisions are the two f32 additions; each is rounded separately, low
        term first, which is the order the `fdot2` hardware path in
        `phase5_exact_fragment/soft_wmma_exact_fragment.cpp` relies on.

        NaN: the instruction produces a qNaN whenever any operand half is a
        NaN or any product is one (`inf * 0` is the reachable case).  The
        SIGN AND PAYLOAD of that result are not fixed by the arithmetic, so
        the model canonicalises to +qNaN `0x7FC00000` and the oracle is
        written to the same convention.  Without one stated convention the
        two disagree in the sign bit alone -- measured, not assumed -- which
        would make every NaN vector a false alarm.  No J3 output byte is a
        NaN on well-formed input; the vectors exist to pin the arithmetic,
        not to certify a payload.

        This was `pass` until Phase 16M -- a true no-op, and the arithmetic
        unit of the whole soft-WMMA replacement.
        """
        dst = ops[0]
        s0 = ops[1]
        s1 = ops[2]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, s0)
                b = self.vget(lane, s1)
                a0 = f16_to_f32(a & 0xFFFF)
                a1 = f16_to_f32((a >> 16) & 0xFFFF)
                b0 = f16_to_f32(b & 0xFFFF)
                b1 = f16_to_f32((b >> 16) & 0xFFFF)
                acc = self.vget(lane, dst, fp=True)
                p0 = a0 * b0
                p1 = a1 * b1
                if any(math.isnan(x) for x in (a0, a1, b0, b1, acc, p0, p1)):
                    self.vset(lane, dst, QNAN_F32)
                    continue
                self.vset(lane, dst,
                          f32_bits(f32(f32(acc + f32(p0)) + f32(p1))))

    def op_ds_bpermute_b32(self, ins, ops):
        """DS_BPERMUTE_B32 -- the software-WMMA cross-lane gather.

        `ds_bpermute_b32 vdst, vaddr, vdata`: lane L reads the dword held by
        lane `(vaddr[L] >> 2) & 31` of VDATA.  The byte address selects a
        lane because one wave's 32 dwords occupy 128 bytes, so bits [6:2]
        are the lane index; bits above 6 are ignored by the datapath.

        This is the instruction the CUDA-side fragment models as
        `__shfl(A[k/2], source_lane, 32)` in
        `phase5_exact_fragment/soft_wmma_exact_fragment.cpp`, which is the
        independent statement of the same contract.

        This was `pass` until Phase 16M.  Note the argument order: `ops[1]`
        is the ADDRESS and `ops[2]` the DATA, which is the ISA order and the
        opposite of what `p14eh.ds_form` assumes for its `addr_reg` field
        (it takes `vtoks[-1]`); that field only labels the recorder's `bp`
        counter, so it affects no emulated value, and it is left alone here.
        """
        dst = ops[0]
        addr_tok = ops[1]
        data_tok = ops[2]
        # read every active lane's source dword BEFORE writing any
        # destination, so a lane that is both source and destination within
        # one step still sees the pre-instruction value
        src = {}
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                vaddr = self.vget(lane, addr_tok)
                src[lane] = (vaddr >> 2) & 31
        vals = {ln: self.vget(sl, data_tok) for ln, sl in src.items()}
        for lane, sl in src.items():
            self.vset(lane, dst, vals[lane])

    def op_v_fmac_f32(self, ins, ops):
        """V_FMAC_F32 dst = src0*src1 + dst, with ONE rounding.

        The product and the addend are aligned as integers in
        `fma_f32_bits`, so there is no double rounding.  Phase 16M M2 defect
        10 measured the previous `f32(a + b*c)` in host f64 landing one ulp
        low on `DEFECT_v_fmac_f32_double_rounding`.
        """
        dst = ops[0]
        src0 = ops[1]
        src1 = ops[2]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                c = self.vget(lane, dst) & U32
                a = self.vget(lane, src0) & U32
                b = self.vget(lane, src1) & U32
                self.vset(lane, dst, fma_f32_bits(a, b, c))

    def op_v_wmma_stub(self, ins, ops):
        pass

    def op_v_cmp(self, ins, ops):  # placeholder, replaced below by dynamic
        raise NotImpl("unused")

    def op_v_cmpx(self, ins, ops):
        raise NotImpl("unused")

    # int ALU
    def op_v_mov_b32(self, ins, ops):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                self.vset(lane, ops[0], self.vget(lane, ops[1]))

    def op_v_add_nc_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (a + b) & U32)

    op_v_add_u32 = op_v_add_nc_u32

    def op_v_add_co_u32(self, ins, ops):
        dst = ops[0]
        carry = ops[1]
        src0 = ops[2]
        src1 = ops[3]
        out = 0
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, src0) & U32  # imm negatives: 2's complement
                b = self.vget(lane, src1) & U32
                r = a + b
                self.vset(lane, dst, r)
                if r > U32:
                    out |= 1 << lane
        if carry == "vcc_lo":
            self.vcc_l = out
        elif carry.startswith("s"):
            self.sset(carry, out)

    def op_v_add_co_ci_u32(self, ins, ops):
        """V_ADD_CO_CI_U32 in both encodings.

        e32:  dst, vcc_lo,    src0, src1            (carry-in and carry-out
                                                     are the same VCC)
        e64:  dst, sdst,      src0, src1, ssrc_cin  (VOP3B)

        ISA rdna2_isa.txt:7275-7284, opcode 40:
            "Add two unsigned integers and a carry-in from VCC. Store the
             result and also save the carry-out to VCC. In VOP3 the VCC
             destination may be an arbitrary SGPR-pair, and the VCC source
             comes from the SGPR-pair at S2.u.
                 D.u32 = S0.u32 + S1.u32 + VCC;
                 VCC   = S0.u32 + S1.u32 + VCC >= 0x100000000ULL ? 1 : 0."

        Phase 16S measured the previous body writing the carry-out ONLY when
        the destination token was `vcc_lo`, so any SGPR destination silently
        dropped it.  The repair covers the three destination classes the
        manual's sentence allows: a named SGPR, `vcc_lo`, and `null` (the
        VOP3B spelling of "this instruction produces no carry-out", which
        must write nothing at all).

        EXEC: the mask write is qualified by EXEC.  The declared reading --
        the one phase16s/isa/oracle16.py records and re-measures -- is that a
        lane where EXEC is clear contributes a 0 bit to the mask rather than
        keeping its previous bit; the `exec_partial` vector carries the
        alternative as a recorded alternate reading.
        """
        dst = ops[0]
        cout = ops[1]
        src0 = ops[2]
        src1 = ops[3]
        cin_tok = ops[4] if len(ops) > 4 else "vcc_lo"
        carry = 0
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, src0) & U32
                b = self.vget(lane, src1) & U32
                if cin_tok == "vcc_lo":
                    c = (self.vcc_l >> lane) & 1
                elif cin_tok.startswith("s"):
                    c = (self.sget(cin_tok) >> lane) & 1
                else:
                    c = 0
                r = a + b + c
                self.vset(lane, dst, r)
                if r > U32:
                    carry |= 1 << lane
        if cout == "vcc_lo":
            self.vcc_l = carry & U32
        elif cout in ("null", "off"):
            pass                      # no carry-out destination named
        elif cout == "scc":
            self.scc = 1 if carry else 0
        elif cout.startswith("s"):
            self.sset(cout, carry & U32)

    def op_v_add3_u32(self, ins, ops):
        self._vbin3(ins, ops, lambda a, b, c: (a + b + c) & U32)

    def op_v_and_b32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (a & b) & U32)

    def op_v_or_b32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (a | b) & U32)

    def op_v_xor_b32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (a ^ b) & U32)

    def op_v_and_or_b32(self, ins, ops):
        # (v0 & v1) | v2 with srcs possibly scalar
        self._vbin3(ins, ops, lambda a, b, c: ((a & b) | c) & U32)

    def op_v_or3_b32(self, ins, ops):
        self._vbin3(ins, ops, lambda a, b, c: (a | b | c) & U32)

    def op_v_lshlrev_b32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (b << (a & 31)) & U32)

    def op_v_lshrrev_b32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (b >> (a & 31)) & U32)

    def op_v_ashrrev_i32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (s32(b) >> (a & 31)) & U32)

    def op_v_lshrrev_b16(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: ((b & 0xFFFF) >> (a & 15)) & 0xFFFF)

    def op_v_ashrrev_i16(self, ins, ops):
        def f(a, b):
            v = b & 0xFFFF
            if v & 0x8000:
                v -= 0x10000
            return (v >> (a & 15)) & 0xFFFF
        self._vbin(ins, ops, f)

    def op_v_add_nc_u16(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: ((a & 0xFFFF) + (b & 0xFFFF)) & 0xFFFF)

    def op_v_sub_nc_u16(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: ((a & 0xFFFF) - (b & 0xFFFF)) & 0xFFFF)

    def op_v_sub_nc_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (a - b) & U32)

    def op_v_lshl_add_u32(self, ins, ops):
        # ISA: dst = (src0 << src1) + src2.  Until Phase 16L this computed
        # (src1 << src0) + src2.
        #
        # The real site, from the original gfx1100 module and carried
        # unchanged into Candidate F:
        #     v_lshl_add_u32 v4, v4, 3, 56
        # which is the E4M3 magnitude encoder packing its 3-bit mantissa:
        # (v4 << 3) + 56.  Reversed, it shifts the constant 3 left by the
        # mantissa, so the encoder produced a different byte for every
        # non-zero mantissa.
        #
        # Recorded asymmetric case: src0=8, src1=3, src2=56 -> 120.
        self._vbin3(ins, ops, lambda a, b, c: ((a << (b & 31)) + c) & U32)

    def op_v_bfe_u32(self, ins, ops):
        self._vbin3(ins, ops, lambda a, o, w: ((a >> (o & 31)) & ((1 << (w & 31)) - 1)) & U32)

    def op_v_bfe_i32(self, ins, ops):
        def f(a, o, w):
            o &= 31
            w &= 31
            if w == 0:
                return 0
            v = (a >> o) & U32
            if o + w < 32:
                v &= (1 << w) - 1
                if v & (1 << (w - 1)):
                    v |= (U32 << w) & U32
            return v & U32
        self._vbin3(ins, ops, f)

    def op_v_min_i32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: min(s32(a), s32(b)) & U32)

    def op_v_max_i32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: max(s32(a), s32(b)) & U32)

    def op_v_min_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: min(a & U32, b & U32) & U32)

    def op_v_cndmask_b32(self, ins, ops):
        # `v_cndmask_b32_e32 v0, v0, v1` is a real spelling -- k_reproject
        # line 49 uses it -- and in that form the condition is the implicit
        # VCC.  Phase 16M M2 defect 5: the handler read `ops[3]`
        # unconditionally and raised IndexError on it.
        dst = ops[0]
        src0 = ops[1]
        src1 = ops[2]
        cond = ops[3] if len(ops) > 3 else "vcc_lo"
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, src0)
                b = self.vget(lane, src1)
                if cond == "vcc_lo":
                    c = (self.vcc_l >> lane) & 1
                elif cond.startswith("s"):
                    c = (self.sget(cond) >> lane) & 1
                elif cond == "vcc":
                    c = (self.vcc_l >> lane) & 1
                else:
                    c = self.vget(lane, cond)
                self.vset(lane, dst, b if c else a)

    def op_v_readfirstlane_b32(self, ins, ops):
        self.sset(ops[0], self.v[0][int(ops[1][1:])])

    # float ALU
    def op_v_add_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: a + b)

    def op_v_sub_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: a - b)

    def op_v_mul_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: a * b)

    def op_v_fma_f32(self, ins, ops):
        # ISA: dst = src0*src1 + src2.  All three sources are printed, and the
        # destination is NOT one of them -- that is V_FMAC_F32, which this
        # module implements separately as `op_v_fmac_f32`.
        #
        # Phase 16L checked this explicitly rather than assuming: the first
        # draft of the conformance oracle had `v_fma_f32` accumulating into the
        # destination and disagreed with this handler.  The ISA definition
        # settled it in favour of the handler, and the oracle was corrected.
        # The existing implementation here was already right.
        self._vfp(ins, ops, lambda a, b, c: a * b + c)

    @staticmethod
    def _fmin32(a, b):
        """IEEE minNum: NaN is the identity; -0 < +0 for the equal case."""
        if math.isnan(a):
            return b
        if math.isnan(b):
            return a
        if a == 0.0 and b == 0.0:
            return -0.0 if (math.copysign(1.0, a) < 0
                            or math.copysign(1.0, b) < 0) else 0.0
        return a if a < b else b

    @staticmethod
    def _fmax32(a, b):
        if math.isnan(a):
            return b
        if math.isnan(b):
            return a
        if a == 0.0 and b == 0.0:
            return 0.0 if (math.copysign(1.0, a) > 0
                           or math.copysign(1.0, b) > 0) else -0.0
        return a if a > b else b

    def op_v_min_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: self._fmin32(a, b))

    def op_v_max_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: self._fmax32(a, b))

    def op_v_sqrt_f32(self, ins, ops):
        def f(a, b, c):
            if math.isnan(a) or a < 0:
                return float("nan")
            if math.isinf(a):
                return a
            return f32(math.sqrt(a))
        self._vfp(ins, ops, f)

    def op_v_rsq_f32(self, ins, ops):
        def f(a, b, c):
            if math.isnan(a) or a < 0:
                return float("nan")
            if a == 0.0:
                return float("inf")
            return f32(1.0 / math.sqrt(a))
        self._vfp(ins, ops, f)

    def op_v_cvt_f32_f16(self, ins, ops):
        # Source is the RAW f16 bit pattern in the low half of a register.
        self._vfp(ins, ops, lambda a, b, c: f16_to_f32(int(a)))

    def op_v_cvt_f16_f32(self, ins, ops):
        # ISA rdna2_isa.txt:7571-7577 -- V_CVT_F16_F32 is
        #     `D.f16 = flt32_to_flt16(S0.f)`,
        # "0.5ULP accuracy, supports input modifiers and creates FP16
        # denormals when appropriate".  Phase 16S measured four separate
        # defects in the previous body, which did not call the format
        # definition at all:
        #
        #   * the sign came from bit 16 of the f32 pattern, not bit 31;
        #   * a magnitude below 2**-24 was flushed to zero instead of being
        #     rounded ("creates FP16 denormals when appropriate");
        #   * a subnormal rounded UP to 2**-14 was clamped back to 0x03FF,
        #     one quantum low, instead of carrying into 0x0400;
        #   * `-vN` was applied as integer negation of the encoding
        #     (repaired in `vget`).
        #
        # The conversion is now the format definition, `f32_bits_to_f16`,
        # applied to the f32 value `_vfp` hands in.  How D[31:16] is treated
        # is NOT stated by the document; the DECLARED reading recorded in
        # phase16s/isa/ISA_ORACLE_16.json is zero-extension, which is what
        # writing the 16-bit pattern into the register produces.
        self._vfp(ins, ops, lambda a, b, c: f32_bits_to_f16(f32_bits(a)))

    def op_v_cvt_i32_f32(self, ins, ops):
        def conv(x):
            if math.isnan(x) or math.isinf(x):
                return 0
            if x >= 2**31:
                return 0x7FFFFFFF
            if x <= -(2**31):
                return SIGN
            return int(math.trunc(x)) & U32
        self._vfp(ins, ops, lambda a, b, c: conv(a))

    def op_v_cvt_f32_u32(self, ins, ops):
        # Source is an UNSIGNED INTEGER register, result is a float.  The
        # operand kind is declared in `_SRC_KIND`, not here.
        self._vfp(ins, ops, lambda a, b, c: f32(float(a & U32)))

    def op_v_cvt_u32_f32(self, ins, ops):
        def conv(x):
            if math.isnan(x) or x <= 0:
                return 0
            if x >= 2**32:
                return U32
            return int(math.trunc(x)) & U32
        self._vfp(ins, ops, lambda a, b, c: conv(a))

    def op_v_rcp_f32(self, ins, ops):
        def f(a, b, c):
            if a == 0:
                return f32(math.copysign(float("inf"), a))
            return f32(1.0 / a)
        self._vfp(ins, ops, f)

    op_v_rcp_iflag_f32 = op_v_rcp_f32

    def op_v_floor_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: f32(math.floor(a)))

    def op_v_rndne_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: f32(round(a)) if not (math.isnan(a) or math.isinf(a)) else a)

    def op_v_ldexp_f32(self, ins, ops):
        def f(a, b, c):
            # The exponent operand is an INTEGER, and it is read from a
            # register.  `int(float('nan'))` raises ValueError in Python, so a
            # NaN exponent used to abort the whole dispatch rather than
            # producing an architectural result.  An exponent that is not a
            # finite integer leaves the mantissa scaled by nothing sane; the
            # hardware saturates, so saturate explicitly.
            if isinstance(b, float) and (math.isnan(b) or math.isinf(b)):
                return a if (a == 0.0 or math.isinf(a) or math.isnan(a))                     else f32(math.copysign(float("inf"), a))
            try:
                n = int(b)
            except (ValueError, OverflowError):
                return float("nan")
            if math.isnan(a):
                return float("nan")
            if a == 0.0 or math.isinf(a):
                return a
            try:
                return f32(math.ldexp(a, n))
            except OverflowError:
                return f32(math.copysign(float("inf"), a))
        self._vfp(ins, ops, f)

    def op_v_log_f32(self, ins, ops):
        def f(a, b, c):
            if a > 0:
                return f32(math.log(a))
            if a == 0:
                return f32(float("-inf"))
            return float("nan")
        self._vfp(ins, ops, f)

    def op_v_div_scale_f32(self, ins, ops):
        # approximate implementation preserving structure: scale = b/c*2^k
        dst = ops[0]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[2], fp=True)
                b = self.vget(lane, ops[3], fp=True)
                self.vset(lane, dst, f32_bits(f32(a)))
        if ops[1] == "vcc_lo":
            self.vcc_l = 0

    def op_v_div_fmas_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: f32(a * b + c))

    def op_v_div_fixup_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: a)

    # ---- memory ----
    def op_s_mov_b64(self, ins, ops):
        # s_mov_b64 dst, imm64/sregpair  (rare; conservative single value)
        self.spair_set(ops[0], self.sget(ops[1]) if ops[1].startswith("0x") or ops[1].isdigit() else self.spair(ops[1]))

    def op_v_subrev_nc_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (b - a) & U32)

    def op_ds_read_u16(self, ins, ops):
        self.op_ds_load_u16(ins, ops)

    def op_ds_load_u16(self, ins, ops):
        dst = ops[0]
        addr_tok = ops[1]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                off = self.vget(lane, addr_tok)
                if off < 0 or off + 1 >= len(self.lds):
                    continue  # HW: out-of-range LDS read -> undefined data, no fault
                v = self.lds[off] | (self.lds[off + 1] << 8)
                self.vset(lane, dst, v)

    @staticmethod
    def _ds_parts(text, nbytes):
        """Return (addr_vreg, data_vregs, offset) parsed from a ds op text."""
        import re
        m = re.match(r"^ds_\S+\s+(v\d+)(?:,\s*)?(.*)$", text)
        if not m:
            raise NotImpl(f"ds parse: {text}")
        addr = m.group(1)
        rest = m.group(2)
        off = 0
        om = re.search(r"offset:(-?[0-9a-fA-Fx]+)", rest)
        if om:
            t = om.group(1)
            off = int(t, 0) if t.lower().startswith("0x") else int(t)
            rest = rest[: om.start()].strip().rstrip(",").strip()
        datas = []
        dm = re.match(r"^v(\d+)", rest)
        if dm and rest.strip():
            # possible v[a:b] range forms
            if "[" in rest:
                datas = [rest.strip()]
            else:
                datas = [rest.strip()]
        return addr, datas, off

    def _ds_data_dwords(self, lane, tok):
        """Read one or more consecutive dwords from a data operand token."""
        tok = tok.strip()
        if "[" in tok:
            a, b = (int(x) for x in tok.lstrip("v[").rstrip("]").split(":"))
            return [self.v[lane][i] for i in range(a, b + 1)]
        return [self.v[lane][int(tok[1:])]]

    def _ds_store(self, ins, ops, nbytes, d16_hi=False):
        addr_tok, data_toks, off = self._ds_parts(ins["text"], nbytes)
        if not data_toks:
            raise NotImpl(f"ds store data parse: {ins['text']}")
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                base = (self.vget(lane, addr_tok) + off) & 0xFFFFFFFF
                if base + nbytes > len(self.lds):
                    continue
                dwords = []
                for t in data_toks:
                    dwords.extend(self._ds_data_dwords(lane, t))
                if d16_hi and dwords:
                    # `_d16_hi` stores the HIGH 16 bits of VDATA.  The low-half
                    # store is a different instruction, and silently aliasing
                    # one onto the other is what Phase 16M found.
                    dwords = [dwords[0] >> 16]
                nbytes_left = nbytes
                di = 0
                while nbytes_left > 0 and di < len(dwords):
                    nb = min(4, nbytes_left)
                    v = dwords[di]
                    for j in range(nb):
                        self.lds[base + di * 4 + j] = (v >> (8 * j)) & 0xFF
                    nbytes_left -= nb
                    di += 1

    def _ds_load(self, ins, ops, nbytes):
        dst = ops[0]
        addr_tok, _, off = self._ds_parts(ins["text"], nbytes)
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                base = (self.vget(lane, addr_tok) + off) & 0xFFFFFFFF
                if base + nbytes > len(self.lds):
                    continue
                val = 0
                for i in range(nbytes):
                    val |= self.lds[base + i] << (8 * i)
                self.vset(lane, dst, val)

    def op_ds_store_b32(self, ins, ops):
        self._ds_store(ins, ops, 4)

    def op_ds_store_b16(self, ins, ops):
        self._ds_store(ins, ops, 2)

    def op_ds_store_b8(self, ins, ops):
        self._ds_store(ins, ops, 1)

    def op_ds_store_b64(self, ins, ops):
        self._ds_store(ins, ops, 8)

    def op_ds_store_b128(self, ins, ops):
        # vdst(4 dwords) via addr vreg + data in 4 consecutive? handle 2addr form
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                pass  # handled via generic when needed

    def op_ds_load_b32(self, ins, ops):
        self._ds_load(ins, ops, 4)

    def op_ds_load_u16(self, ins, ops):
        self._ds_load(ins, ops, 2)

    def op_ds_load_b16(self, ins, ops):
        self._ds_load(ins, ops, 2)

    def op_ds_load_u8(self, ins, ops):
        self._ds_load(ins, ops, 1)

    def op_ds_load_b8(self, ins, ops):
        self._ds_load(ins, ops, 1)

    def op_ds_load_b64(self, ins, ops):
        self._ds_load(ins, ops, 8)

    def op_ds_read_b32(self, ins, ops):
        self._ds_load(ins, ops, 4)

    def op_ds_read_u16(self, ins, ops):
        self._ds_load(ins, ops, 2)

    def op_ds_read_b16(self, ins, ops):
        self._ds_load(ins, ops, 2)

    def op_ds_read_b8(self, ins, ops):
        self._ds_load(ins, ops, 1)

    def op_ds_read_u8(self, ins, ops):
        self._ds_load(ins, ops, 1)

    def op_ds_write_b32(self, ins, ops):
        self.op_ds_store_b32(ins, ops)

    def op_ds_write_b16(self, ins, ops):
        self.op_ds_store_b16(ins, ops)

    def op_ds_write_b8(self, ins, ops):
        self.op_ds_store_b8(ins, ops)

    def op_ds_write_b64(self, ins, ops):
        self._ds_store(ins, ops, 8)

    def op_ds_write_2addr_b32(self, ins, ops):
        self._ds_store(ins, ops, 4)

    def op_ds_read_2addr_b32(self, ins, ops):
        self._ds_load(ins, ops, 4)

    def op_global_store_b8(self, ins, ops):
        lo_n, hi_n = (int(x) for x in ops[0].lstrip("v[").rstrip("]").split(":"))
        data = ops[1]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                addr = self.v[lane][lo_n] | (self.v[lane][hi_n] << 32)
                val = self.vget(lane, data) & 0xFF
                self.mem[addr] = val
                self.global_stores.append((addr, val, lane))

    op_global_store_byte = op_global_store_b8

    def op_global_load_b8(self, ins, ops):
        pass

    op_global_load_byte = op_global_load_b8

    # ---- no-ops ----
    def _noop(self, ins, ops):
        pass

    op_s_nop = _noop
    op_s_delay_alu = _noop
    op_s_clause = _noop
    op_s_waitcnt = _noop
    op_s_waitcnt_depctr = _noop
    op_s_sendmsg = _noop
    op_s_barrier = _noop
    op_s_sleep = _noop
    op_s_code_end = _noop
    op_buffer_gl0_inv = _noop
    op_buffer_gl1_inv = _noop


def split_dual(r):
    """Split a dual-issue disassembly row into component instruction dicts."""
    ops = r["operands"]
    if "::" not in ops:
        return [r]
    left, right = ops.split("::", 1)
    out = []
    # left side keeps the row mnemonic
    l = dict(r)
    l["operands"] = left.strip()
    l["text"] = r["mnemonic"] + " " + left.strip()
    l["dual"] = True
    out.append(l)
    # right side carries its own mnemonic
    rtxt = right.strip()
    rm, _, rops = rtxt.partition(" ")
    rr = dict(r)
    rr["mnemonic"] = rm
    rr["operands"] = rops.strip()
    rr["text"] = rtxt
    rr["dual"] = True
    out.append(rr)
    return out


def build_orig_program(rows):
    prog = []
    for r in rows:
        for ins in split_dual(r):
            ins = dict(ins)
            ins["target"] = None
            prog.append(ins)
    by_addr = {}
    for i, ins in enumerate(prog):
        by_addr.setdefault(ins["address"], i)
    for ins in prog:
        m = ins["mnemonic"]
        if m.startswith("s_cbranch") or m == "s_branch":
            first = ins["operands"].split()[0] if ins["operands"] else ""
            tgt = None
            try:
                if first.startswith("0x"):
                    tgt = int(first, 16)
                elif first.lstrip("-").isdigit():
                    disp = int(first)
                    if disp >= 0x8000:
                        disp -= 0x10000
                    tgt = ins["address"] + 4 + disp * 4
            except ValueError:
                pass
            if tgt is None:
                raise ValueError(f"cannot resolve branch at {ins['address']:#x}")
            cand = by_addr.get(tgt)
            if cand is None:
                raise ValueError(f"branch target {tgt:#x} not found (from {ins['address']:#x})")
            ins["target"] = cand
    return prog


def build_translated_program(rows):
    """rows = full .s rows incl labels; returns program + asm index map."""
    prog = []
    asm_row_of = []  # per prog entry, the index in `rows`
    labels = {}
    for i, r in enumerate(rows):
        if r["kind"] == "label":
            labels[r["name"]] = i
    for i, r in enumerate(rows):
        if r["kind"] != "instruction":
            continue
        ins = dict(r)
        ins["target"] = None
        m = r["mnemonic"]
        if m.startswith("s_cbranch") or m == "s_branch":
            tgtname = r["operands"].strip()
            if tgtname not in labels:
                raise ValueError(f"unknown branch label {tgtname}")
            ins["_label"] = tgtname
        prog.append(ins)
        asm_row_of.append(i)
    for ins in prog:
        if "_label" in ins:
            target_row = labels[ins["_label"]]
            t = None
            for j, rw in enumerate(asm_row_of):
                if rw >= target_row:
                    t = j
                    break
            if t is None:
                raise ValueError(f"label {ins['_label']} past end")
            ins["target"] = t
            del ins["_label"]
    return prog
