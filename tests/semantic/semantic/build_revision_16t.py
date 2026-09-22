#!/usr/bin/env python3
"""Phase 16T -- build SEMANTIC_REVISION_16T.

NEVER EDITS THE OLD FREEZE IN PLACE
-----------------------------------
The Phase 16O freeze (`phase16o_final/C_SEMANTIC_FREEZE_FINAL.json`,
`semantics_hash 76a8ddbc…`) is immutable evidence.  Phase 16R and 16S both
re-verified it *against the live tree*, so the live tree must keep hashing to
it.  This tool therefore does NOT touch the live sources.

It builds a **successor source tree** at
`phase16t/semantic/revision_16t/`, which is this project's own established
mechanism for a semantic revision (`phase16o_final/a_regression/tools/
a_build_revs.py`: "So each revision here is a real SOURCE TREE.  A runner
prepends exactly one …").  A runner loads the revision's copies explicitly by
file path, before anything else can import them, so every transitive
`import emu` resolves to the revision's copy while everything else comes from
the live tree.  The revision's identity is then the hash over the 13 frozen
source paths with those copies substituted -- see `rev_identity()`.

WHAT IT REPAIRS
---------------
The five measured Phase 16S emulator/ISA disagreements, and nothing else:

  A  emu.py :: Core.op_v_cvt_f16_f32       (e32, J3: 1016 execs)
  B  emu.py :: f32_bits_to_f16             (the shared format definition A
                                            now uses; its own rounding arm
                                            truncated the f16 quantum)
  C  emu.py :: Core.vget, the `-vN` arm    (the input modifier A's measured
                                            vector `v_cvt_f16_f32 v1, -v1`
                                            exercised)
  D  p14d8_core.py :: Core8.op_v_pack_b32_f16   (J3: 256 execs)
  E  emu.py :: Core.op_v_fma_mixlo_f16 and
     p14d8_core.py :: Core8.op_v_fma_mixhi_f16  (J3: 224 + 32 execs)
  F  emu.py :: Core.op_v_add_co_ci_u32      (J3: 592 execs, LATENT there)

Every edit is a `(file, find, replace)` triple applied with an exact-count
assertion, so the diff recorded in `REVISION_16T_PATCHES.json` is the diff
that was applied, not a description of it.

Candidate F is NOT touched.  This is a host semantic-model correction; it is
NOT Candidate G.

Usage:
    python phase16t/semantic/build_revision_16t.py            # build
    python phase16t/semantic/build_revision_16t.py --check    # verify only
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
T = os.path.dirname(HERE)
ROOT = os.path.dirname(T)
REV = os.path.join(HERE, "revision_16t")

FREEZE = "phase16o_final/C_SEMANTIC_FREEZE_FINAL.json"

#: module basename -> live path.  The revision tree needs a copy of every
#: module the revision loader registers, because the loader reads them BY
#: FILE PATH out of the tree.
TREE_MODULES = {
    "emu": "phase8_static/tools/emu.py",
    "p14d8_core": "phase14d8_static/tools/p14d8_core.py",
    "p14e_emu": "phase14e_static/tools/p14e_emu.py",
    "p14eh": "phase14eh_tools/p14eh.py",
    "p16e_rec": "phase16e_candidate_e/tools/p16e_rec.py",
    "p16h_scratch_probe": "phase16h_pcrel_fix/tools/p16h_scratch_probe.py",
    "p16j_scratch_isa": "phase16j_pre_gta/tools/p16j_scratch_isa.py",
    "p16j_input": "phase16j_pre_gta/tools/p16j_input.py",
}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# The edits
# ---------------------------------------------------------------------------

# --- C ---------------------------------------------------------------------
# The input modifier.  Applies to EVERY float consumer, not just the one
# measured, because the rule is a property of the encoding.
VGET_OLD = '''        elif tok.startswith("-v"):
            raw = (-self.v[lane][int(tok[2:])]) & U32
'''

VGET_NEW = '''        elif tok.startswith("-v"):
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
'''

# --- B ---------------------------------------------------------------------
F32TOF16_OLD = '''def f32_bits_to_f16(b):
    b &= 0xFFFFFFFF
    s = (b >> 31) & 1
    sgn = s << 15
    e = (b >> 23) & 0xFF
    m = b & 0x7FFFFF
    if e == 0xFF:                                   # infinity or NaN
        return sgn | 0x7C00 | (0x200 if m else 0)
    if e == 0:                                      # f32 zero or denormal
        return sgn
    exp = e - 127                                   # unbiased
    if exp > 15:
        return sgn | 0x7C00                         # >= 2**16 -> infinity
    # 27-bit integer significand: the 24 significant bits with three guard
    # bits below them.  Dividing by 2**10 leaves a quotient on the binary16
    # significand scale -- q = 0x400 is 1.0 at this exponent, so the 10-bit
    # field is `q - 0x400` and `q == 0x800` is the carry out of it.
    sig = (m | 0x800000) << 3
    if exp >= -14:
        # `q` is the significand on the binary16 scale: q == 0x400 is 1.0 at
        # this exponent, so the 10-bit field is `q - 0x400` and q == 0x800
        # is the carry out of the field.
        q, r = divmod(sig, 1 << 13)
        if r > 0x1000 or (r == 0x1000 and (q & 1)):
            q += 1
        if exp == 15 and (q >> 3) >= 0x800:          # rounds up to 2**16
            return sgn | 0x7C00
        if q >> 3 == 0x800:
            q >>= 1
            exp += 1
        if exp > 15:
            return sgn | 0x7C00
        return sgn | ((exp + 15) << 10) | ((q >> 3) & 0x3FF)
    # subnormal: the value is sig * 2**(exp-26), and reaching the binary16
    # grid 2**-24 from there is a right shift by (2 - exp) bits.
    shift = 2 - exp
    if shift > 45:
        return sgn
    q, r = divmod(sig, 1 << shift)
    half = 1 << (shift - 1)
    if r > half or (r == half and (q & 1)):
        q += 1
    return sgn | (q & 0xFFFF)                       # may be exactly 0x400
'''

F32TOF16_NEW = '''def f32_bits_to_f16(b):
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
    if q >= 0x400:                                  # up into the smallest normal
        return sgn | 0x0400
    return sgn | q
'''

# --- B support: the canonical binary16 quiet NaN ---------------------------
QNAN_OLD = '''QNAN_F32 = 0x7FC00000
'''
QNAN_NEW = '''QNAN_F32 = 0x7FC00000

# The same convention in binary16, used by `f32_bits_to_f16` and by the FP16
# fused multiply-add below.  Written as bits so it does not depend on what
# `struct.pack("<H", ...)` would do here.
QNAN_F16 = 0x7E00
'''

# --- A ---------------------------------------------------------------------
CVT_OLD = '''    def op_v_cvt_f16_f32(self, ins, ops):
        # not needed on path; approximate f32->f16 via round to 11-bit mantissa
        def conv(x):
            if math.isnan(x):
                return 0x7E00
            if math.isinf(x):
                return 0x7C00 | (0x8000 if x < 0 else 0)
            if x == 0.0:
                return 0x8000 if math.copysign(1, x) < 0 else 0
            import struct as _st
            b = _st.unpack("<I", _st.pack("<f", f32(x)))[0]
            s = (b >> 16) & 1
            e = ((b >> 23) & 0xFF) - 127
            if e > 15:
                return 0x7C00 | (s << 15)
            if e < -24:
                return s << 15
            if e < -14:
                frac = int(round(abs(x) / 2.0 ** -24))
                return (s << 15) | min(frac, 0x3FF)
            q = abs(x) / 2.0 ** e
            mnt = int(round((q - 1.0) * 1024.0))
            if mnt == 1024:
                e += 1
                mnt = 0
            if e > 15:
                return 0x7C00 | (s << 15)
            return (s << 15) | ((e + 15) << 10) | mnt
        self._vfp(ins, ops, lambda a, b, c: conv(a))
'''

CVT_NEW = '''    def op_v_cvt_f16_f32(self, ins, ops):
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
'''

# --- E (lo) ----------------------------------------------------------------
MIXLO_OLD = '''    def op_v_fma_mixlo_f16(self, ins, ops):
        # f16-lane fma; approximate as f32 arithmetic on halves (control-safe)
        self._vfp(ins, ops, lambda a, b, c: f32(a * b + c))
'''

MIXLO_NEW = '''    def op_v_fma_mixlo_f16(self, ins, ops):
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
'''

# --- F ---------------------------------------------------------------------
ADDCI_OLD = '''    def op_v_add_co_ci_u32(self, ins, ops):
        # e32: dst, vcc, src0, src1 (carry-in vcc). e64: dst, null/scc, ssrc0, vsrc1, sreg-carry
        dst = ops[0]
        cout = ops[1]
        src0 = ops[2]
        src1 = ops[3]
        cin_tok = ops[4] if len(ops) > 4 else "vcc_lo"
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
                if cout == "vcc_lo":
                    self.vcc_l = (self.vcc_l & ~(1 << lane)) | ((1 if r > U32 else 0) << lane)
'''

ADDCI_NEW = '''    def op_v_add_co_ci_u32(self, ins, ops):
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
'''

# --- the new shared FP16 machinery ----------------------------------------
HELPERS_ANCHOR = '''    # ---------------- vector ops ----------------
    def _vbin(self, ins, ops, fn):
'''

HELPERS_NEW = '''    # ---------------- FP16 operand decoding and fused multiply-add -------
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
'''

# --- the FP16 fused multiply-add, module level ----------------------------
FMA_ANCHOR = '''def f32_to_f16_bits(x):
'''
FMA_NEW = '''def _f16_decode(bits):
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
'''

# --- D ---------------------------------------------------------------------
PACK_OLD = '''    def op_v_pack_b32_f16(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: ((a & 0xFFFF) << 16) | (b & 0xFFFF))
'''

PACK_NEW = '''    def op_v_pack_b32_f16(self, ins, ops):
        # ISA rdna2_isa.txt:10207-10210:
        #     D[31:16].f16 = S1.f16;   D[15:0].f16 = S0.f16.
        # The FIRST source goes to the LOW half and the SECOND to the HIGH
        # half.  Phase 16S measured the previous body as
        # `((src0 & 0xFFFF) << 16) | (src1 & 0xFFFF)` -- the two operands
        # EXCHANGED -- on the J3 shape `v_pack_b32_f16 v17, v17, v20`.
        #
        # Both operands are FP16 values, so they are read through
        # `_f16_src_bits`; the old body read them with the integer decoder,
        # which raised `ValueError: invalid literal for int() with base 10:
        # '1.0'` on the J3 form `v_pack_b32_f16 v11, v5, 1.0`.
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                lo = self._f16_src_bits(lane, ops[1])
                hi = self._f16_src_bits(lane, ops[2])
                self.vset(lane, ops[0],
                          (((hi & 0xFFFF) << 16) | (lo & 0xFFFF)) & emu_mod.U32)
'''

MIXHI_OLD = '''    def op_v_fma_mixhi_f16(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: emu_mod.f32(a * b + c))
'''

MIXHI_NEW = '''    def op_v_fma_mixhi_f16(self, ins, ops):
        # ISA rdna2_isa.txt:9367-9374 -- the same FP16 fused multiply-add as
        # MIXLO, written into the HIGH half of the destination:
        #     D.f[31:16] = S0.f * S1.f + S2.f.
        # The previous body read each source's full 32 bits as an f32 and
        # wrote the f32 result over the whole destination -- the same
        # reading as the MIXLO body, with no HIGH-half placement at all.
        # Phase 16S measured that divergence as UNCONDITIONAL on all 32 J3
        # executions.  `_fma_mix16` is shared with the MIXLO handler.
        self._fma_mix16(ins, ops, high=True)
'''


EDITS = [
    ("phase8_static/tools/emu.py", "C_vget_input_modifier_negation",
     VGET_OLD, VGET_NEW,
     "The ISA input modifier `-` negates a float VALUE (sign-bit flip of the "
     "encoding), not the encoding as an integer."),
    ("phase8_static/tools/emu.py", "B_shared_f32_to_f16_definition",
     F32TOF16_OLD, F32TOF16_NEW,
     "The shared binary32->binary16 definition rounded at bit 13 of a 27-bit "
     "scaled significand and then truncated the f16 quantum, and its NaN arm "
     "was sign-preserving where this emulator's stated convention is a "
     "canonical positive quiet NaN."),
    ("phase8_static/tools/emu.py", "B_canonical_f16_qnan",
     QNAN_OLD, QNAN_NEW,
     "Declare the canonical binary16 quiet NaN beside the binary32 one."),
    ("phase8_static/tools/emu.py", "A_op_v_cvt_f16_f32",
     CVT_OLD, CVT_NEW,
     "v_cvt_f16_f32 hand-rolled its own converter with the sign taken from "
     "bit 16, a subnormal flush below 2**-24 and a subnormal clamp at the "
     "top of the range, instead of calling the format definition."),
    ("phase8_static/tools/emu.py", "E_op_v_fma_mixlo_f16",
     MIXLO_OLD, MIXLO_NEW,
     "v_fma_mixlo_f16 computed f32 arithmetic over the whole register "
     "instead of an FP16 fused multiply-add into the low half."),
    ("phase8_static/tools/emu.py", "F_op_v_add_co_ci_u32",
     ADDCI_OLD, ADDCI_NEW,
     "v_add_co_ci_u32 wrote the carry-out only when the destination token "
     "was `vcc_lo`, dropping it for every named SGPR destination."),
    ("phase8_static/tools/emu.py", "E_shared_fp16_machinery",
     HELPERS_ANCHOR, HELPERS_NEW,
     "Add the shared FP16 operand decoder and the shared MIX fused "
     "multiply-add used by both MIX mnemonics."),
    ("phase8_static/tools/emu.py", "E_f16_fused_multiply_add",
     FMA_ANCHOR, FMA_NEW,
     "Add the binary16 fused multiply-add with ONE rounding."),
    ("phase14d8_static/tools/p14d8_core.py", "D_op_v_pack_b32_f16",
     PACK_OLD, PACK_NEW,
     "v_pack_b32_f16 put src0 in the HIGH half and src1 in the LOW half -- "
     "the operands exchanged -- and read its FP16 operands with the integer "
     "decoder, which raised on the J3 form's float literal."),
    ("phase14d8_static/tools/p14d8_core.py", "E_op_v_fma_mixhi_f16",
     MIXHI_OLD, MIXHI_NEW,
     "v_fma_mixhi_f16 computed f32 arithmetic over the whole register "
     "instead of an FP16 fused multiply-add into the high half."),
]


def build(check_only=False):
    freeze_path = os.path.join(ROOT, FREEZE.replace("/", os.sep))
    with open(freeze_path, encoding="utf-8") as f:
        freeze = json.load(f)
    parent_hash = freeze["semantics_hash"]
    live = freeze["semantics_sources"]

    # -- the live tree must still hash to the parent freeze ----------------
    print("parent freeze : %s" % parent_hash)
    live_measured = {rel: sha256_file(os.path.join(ROOT, rel.replace(
        "/", os.sep))) for rel in live}
    drift = [r for r in live if live_measured[r] != live[r]]
    if drift:
        print("STOP: the live tree no longer matches the parent freeze: %r"
              % drift)
        return 2
    print("live tree     : matches the parent freeze on all %d sources"
          % len(live))

    if check_only:
        if not os.path.isdir(REV):
            print("STOP: %s does not exist" % REV)
            return 3
        ok = True
        for rel, name, old, new, why in EDITS:
            base = os.path.basename(rel)
            p = os.path.join(REV, base)
            if not os.path.exists(p):
                print("  MISSING  %s" % base)
                ok = False
                continue
            txt = open(p, encoding="utf-8").read()
            here = ("NEW_PRESENT" if txt.count(new) == 1 else
                    "NEW_ABSENT" if txt.count(new) == 0 else
                    "NEW_%d" % txt.count(new))
            print("  %-24s %-26s %s" % (base, name, here))
            ok = ok and here == "NEW_PRESENT"
        return 0 if ok else 1

    os.makedirs(REV, exist_ok=True)
    copied = {}
    for mod, rel in sorted(TREE_MODULES.items()):
        src = os.path.join(ROOT, rel.replace("/", os.sep))
        dst = os.path.join(REV, mod + ".py")
        shutil.copyfile(src, dst)
        copied[mod] = {"live_rel": rel, "live_sha256": sha256_file(src)}
    print("copied %d modules into %s" % (len(copied), os.path.relpath(REV, ROOT)))

    applied = []
    for rel, name, old, new, why in EDITS:
        base = os.path.basename(rel)
        p = os.path.join(REV, base)
        # Read with universal newlines so the find-text, which is written with
        # LF, matches whatever the live file uses; write the replacement back
        # with the file's own convention so the revision differs from the live
        # file ONLY in the edited spans.
        with open(p, "r", encoding="utf-8", newline=None) as fh:
            txt = fh.read()
        nl = "\r\n" if open(p, "rb").read(65536).count(b"\r\n") else "\n"
        n = txt.count(old)
        if n != 1:
            print("STOP: edit %s: the find-text occurs %d times in %s "
                  "(exactly 1 required)" % (name, n, base))
            return 4
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(txt.replace(old, new).replace("\n", nl))
        applied.append({
            "edit": name, "file": base, "live_rel": rel,
            "rationale": why,
            "find_lines": old.count("\n"),
            "replace_lines": new.count("\n"),
            "find_sha256": hashlib.sha256(old.encode()).hexdigest(),
            "replace_sha256": hashlib.sha256(new.encode()).hexdigest(),
        })
        print("  applied %-30s %s" % (name, base))

    # -- the revision identity --------------------------------------------
    rev_hashes = {}
    for mod, info in copied.items():
        rev_hashes[info["live_rel"]] = sha256_file(os.path.join(REV,
                                                                mod + ".py"))
    h = hashlib.sha256()
    for rel in sorted(live):
        base = os.path.basename(rel)
        if base in ("%s.py" % m for m in TREE_MODULES):
            mod = os.path.splitext(base)[0]
            p = os.path.join(REV, base)
            hh = sha256_file(p)
        else:
            p = os.path.join(ROOT, rel.replace("/", os.sep))
            hh = sha256_file(p)
        h.update(rel.encode())
        h.update(b"\0")
        h.update(hh.encode())
        h.update(b"\n")
    rev_hash = h.hexdigest()

    rec = {
        "schema": "phase16t-semantic-revision/1",
        "phase": "16T",
        "revision": "SEMANTIC_REVISION_16T",
        "host_only": True,
        "gpu_execution_performed": False,
        "gta_launched": False,
        "currently_armed": False,
        "why_a_successor_tree_and_not_an_edit":
            "Phase 16R and 16S both re-verified the Phase 16O freeze AGAINST "
            "THE LIVE TREE, so the live tree must keep hashing to 76a8ddbc. "
            "Editing it in place would destroy the frozen evidence. A "
            "revision source tree loaded explicitly by file path is this "
            "project's own established mechanism (phase16o_final/"
            "a_regression/tools/a_build_revs.py).",
        "parent_semantics_hash": parent_hash,
        "parent_freeze": FREEZE,
        "revision_semantics_hash": rev_hash,
        "revision_tree": os.path.relpath(REV, ROOT).replace("\\", "/"),
        "candidate_co": "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co",
        "candidate_sha256":
            sha256_file(os.path.join(
                ROOT, "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co")),
        "candidate_unchanged": True,
        "is_candidate_g": False,
        "n_edits": len(applied),
        "edits": applied,
        "revision_tree_file_sha256": rev_hashes,
        "live_tree_sha256": live_measured,
        "n_sources": len(live),
    }
    out = os.path.join(HERE, "REVISION_16T_PATCHES.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)
    print("\nrevision tree  : %s" % rec["revision_tree"])
    print("revision hash  : %s" % rev_hash)
    print("candidate      : %s (unchanged)" % rec["candidate_sha256"][:16])
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(build(check_only="--check" in sys.argv[1:]))
