#!/usr/bin/env python3
"""Phase 16R / R9 -- the vector suite and mutation test for the independent
RDNA2 division reference.

HOST ONLY.  No GPU, no HIP call, no game launch, nothing armed.

WHY THIS FILE IS SEPARATE FROM THE REFERENCE.  A suite whose expectations are
computed by the code under test is not a test.  Every expectation below is a
LITERAL bit pattern derived BY HAND from the AMD pseudocode (quoted in
`r9_isa_div.py`), and the reference is checked against those literals.  Where
the ISA text leaves a clause undetermined the vector says so in its own record
(`u1` / `u2`) and the expectation is checked only for the reading named.

AND THE SUITE MUST BE ABLE TO FAIL.  Each target carries mutants: deliberate
misreadings of one clause of the ISA text.  A mutant is only evidence if it
(a) actually runs, (b) changes at least one vector's observation, and (c) is
therefore rejected.  A mutant that nothing detects is reported as
NOT_DETECTED, which is a FAILURE of this suite, not a pass.

  exit 0  every expectation reproduced AND every mutant detected
  exit 1  otherwise, with the offending vector or mutant named
"""
from __future__ import annotations

import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import r9_isa_div as R                                      # noqa: E402

B = R.bits          # value -> bits
V = R.value         # bits -> value

NAN = "IS_NAN"


def _nan_pred(x):
    return isinstance(x, float) and math.isnan(x)


#: Bit patterns the ISA text FIXES, so they are asserted exactly rather than
#: treated as "some NaN".  0xffc0_0000 is written out in the V_DIV_FIXUP_F32
#: pseudocode for 0/0 and inf/inf; 0x7fc00000 is Quiet(0x7fc00000).
ISA_FIXED_NANS = (0xFFC00000, 0x7FC00000)


def _nan_is_platform_defined(x):
    """True when the NaN comes from an arithmetic the ISA does not pin down
    (inf + -inf, 0 * inf).  Those are reported as the sentinel IS_NAN, because
    the payload is the host's, not the architecture's."""
    return B(x) not in ISA_FIXED_NANS


# ---------------------------------------------------------------------------
# vectors.  Each: (id, category, inputs..., expectation, note)
#   expectation for scale:  (D_bits | NAN | R.UNASSIGNED, vcc)
#   `alt` gives the expectation under the OTHER reading of `exponent()`,
#   and is checked when it is present.
# ---------------------------------------------------------------------------

SCALE = [
 ("S-J3-form", "actual-j3-operand", 0.5, 0.5, 0.4375,
  (B(0.5), 0),
  "the executed form on the J3 trace: no branch matches, so the ISA text "
  "assigns nothing (U1); the passthrough reading gives D = S0",
  (B(2.0 ** 63), 0)),
 ("S-zero-num", "zero", 1.0, 1.0, 0.0, (0x7FC00000, 0), "S2 == 0 -> NAN"),
 ("S-zero-den", "zero", 1.0, 0.0, 1.0, (0x7FC00000, 0), "S1 == 0 -> NAN"),
 ("S-negzero-num", "zero", 1.0, 1.0, -0.0, (0x7FC00000, 0),
  "-0.0 compares == 0.0"),
 ("S-bigdiff-s0isS1", "boundary-exponent", 1.0, 1.0, 2.0 ** 96,
  (B(2.0 ** 64), 1), "diff == 96 exactly >= 96, S0 == S1 -> ldexp(S0,64)"),
 ("S-bigdiff-s0isS2", "boundary-exponent", 2.0 ** 96, 1.0, 2.0 ** 96,
  (B(2.0 ** 96), 1, False),
  "diff >= 96 but S0 == S2, so the guarded branch leaves D unassigned (U1); "
  "the passthrough reading gives D = S0 and the third element asserts "
  "branch_assigned is False"),
 ("S-denom-denorm", "subnormal", 2.0 ** -140, 2.0 ** -140, 2.0 ** -40,
  (B(2.0 ** -76), 0), "S1 denormal -> ldexp(S0, 64)",
  (B(2.0 ** -76), 1)),
 ("S-recip-denorm-both", "subnormal", 2.0 ** 127, 2.0 ** 127, 2.0 ** -1,
  (0x7F800000, 1), "1/S1 and S2/S1 both denormal -> ldexp(S0,64) OVERFLOWS to "
  "+inf; this is the branch that saturates"),
 ("S-recip-denorm", "subnormal", 2.0 ** 127, 2.0 ** 127, 2.0 ** 120,
  (B(2.0 ** 63), 0), "1/S1 denormal -> ldexp(S0, -64)"),
 ("S-ratio-denorm", "subnormal", 2.0 ** -140, 2.0 ** -10, 2.0 ** -140,
  (B(2.0 ** -76), 1), "S2/S1 denormal -> ldexp(S0,64)"),
 ("S-recip-normal-edge", "boundary-exponent", 2.0 ** 126, 2.0 ** 126,
  2.0 ** 120, (B(2.0 ** 126), 0, False),
  "1/S1 == 2**-126 is NOT denormal, so the chain falls through (U1)"),
 ("S-unbiased-23", "reading-discriminator", 1.0, 1.0, 1.0,
  (B(1.0), 0, False),
  "unbiased exponent(S2) is 0 <= 23 -> the 'Numerator is tiny' branch; "
  "biased exponent is 127 -> no branch.  THE ONE CONDITION WHERE THE TWO "
  "READINGS OF `exponent()` DISAGREE ON NORMAL OPERANDS.",
  (B(2.0 ** 64), 0)),
 ("S-unbiased-23-edge", "reading-discriminator", 1.0, 1.0, 2.0 ** 23,
  (B(1.0), 0, False), "unbiased exponent == 23 exactly -> branch taken",
  (B(2.0 ** 64), 0)),
 ("S-unbiased-24-edge", "reading-discriminator", 1.0, 1.0, 2.0 ** 24,
  (B(1.0), 0, False), "unbiased exponent == 24 -> branch NOT taken; both "
  "readings agree here"),
 ("S-signs-neg", "sign", -1.0, -1.0, -3.0, (B(-1.0), 0),
  "no branch; passthrough keeps the sign"),
 ("S-inf-num", "infinity", 1.0, 1.0, float("inf"), (B(2.0 ** 64), 1),
  "exp(+inf) == 255 -> diff 128 -> guarded branch, S0 == S1"),
 ("S-inf-den", "infinity", 1.0, float("inf"), 1.0, (B(1.0), 0, False),
  "exp(inf) - exp(1.0) = 128 >= 96 but S0 != S1 -> unassigned (U1)"),
 ("S-nan-num", "nan", 1.0, 1.0, V(0x7FC00000), (B(2.0 ** 64), 1),
  "V_DIV_SCALE_F32 has NO NaN case: a NaN numerator takes the exponent branch"),
 ("S-ldexp-exact", "rounding-sensitive", 1.5, 1.5, 2.0 ** 96,
  (B(1.5 * 2.0 ** 64), 1), "ldexp by 64 of a 2-bit significand is exact"),
]

FMAS = [
 ("F-vcc0", "normal", 2.0, 3.0, 1.0, 0, B(7.0)),
 ("F-vcc1", "normal", 2.0, 3.0, 1.0, 1, B(7.0 * 2 ** 32)),
 ("F-fused", "rounding-sensitive", 1.0 + 2.0 ** -23, 1.0 + 2.0 ** -23,
  -(1.0 + 2.0 ** -22), 0, B(2.0 ** -46)),
 ("F-fused-vcc1", "rounding-sensitive", 1.0 + 2.0 ** -23,
  1.0 + 2.0 ** -23, -(1.0 + 2.0 ** -22), 1, B(2.0 ** -14)),
 ("F-signed-zero", "sign", -0.0, 1.0, -0.0, 0, 0x80000000),
 ("F-zero-sum", "zero", 0.0, 1.0, 0.0, 1, B(0.0)),
 ("F-vcc1-subnormal", "subnormal", 2.0 ** -140, 1.0, 0.0, 1,
  B(2.0 ** -108)),
 ("F-vcc0-subnormal", "subnormal", 2.0 ** -140, 1.0, 0.0, 0,
  B(2.0 ** -140)),
 ("F-inf", "infinity", float("inf"), 1.0, 0.0, 0, B(float("inf"))),
 ("F-inf-minus-inf", "nan", float("inf"), 1.0, float("-inf"), 0, NAN),
 ("F-zero-times-inf", "nan", 0.0, float("inf"), 1.0, 0, NAN),
 ("F-overflow-vcc1", "boundary-exponent", 2.0 ** 100, 2.0 ** 100,
  -2.0 ** 100, 1, B(float("inf"))),
]

FIXUP = [
 ("X-default-pos", "normal", 0.875, 0.5, 0.4375, B(0.875)),
 ("X-default-signout", "sign", 0.875, -0.5, 0.4375, B(-0.875)),
 ("X-J3-form", "actual-j3-operand", V(0xC91814CC), 0.5, 0.4375,
  0x491814CC),
 ("X-abs-of-neg-s0", "sign", -0.875, 0.5, 0.4375, B(0.875)),
 ("X-negzero-s0", "sign", -0.0, 1.0, 1.0, B(0.0)),
 ("X-negzero-signout", "sign", 0.0, -1.0, 0.0, 0x80000000),
 ("X-0-div-0", "zero", 1.0, 0.0, 0.0, 0xFFC00000),
 ("X-inf-div-inf", "infinity", 1.0, float("inf"), float("inf"),
  0xFFC00000),
 ("X-x-div-0", "zero", 1.0, 0.0, 1.0, B(float("inf"))),
 ("X-neg-x-div-0", "sign", 1.0, -0.0, 1.0, B(float("-inf"))),
 ("X-inf-div-y", "infinity", 1.0, 1.0, float("-inf"), B(float("-inf"))),
 ("X-x-div-inf", "infinity", 1.0, float("inf"), 1.0, B(0.0)),
 ("X-zero-div-y", "zero", 1.0, 1.0, 0.0, B(0.0)),
 ("X-nan-num", "nan", 1.0, 1.0, V(0x7FC00000), 0x7FC00000),
 ("X-nan-den", "nan", 1.0, V(0x7FC00000), 1.0, 0x7FC00000),
 ("X-subnormal-s0", "subnormal", 2.0 ** -140, 1.0, 1.0,
  B(2.0 ** -140)),
 ("X-denorm-both", "subnormal", 0.875, 2.0 ** -140, 2.0 ** -140,
  B(0.875)),
 ("X-underflow-u2", "boundary-exponent", 0.875, 2.0 ** 100, 2.0 ** -140,
  0x00000001),
]


# ---------------------------------------------------------------------------
# mutants -- one deliberate misreading of one clause of the ISA text
# ---------------------------------------------------------------------------
def _mk_scale_mutants():
    def m_drop_guard(s0, s1, s2, mode="passthrough", exp_mode="biased"):
        """Misreading: treat the guarded branches as unconditional."""
        r = R.scale_f32(s0, s1, s2, mode="isa_text", exp_mode=exp_mode)
        if r["branch"] in ("exp(S2)-exp(S1) >= 96", "S2/S1 is DENORM",
                           "1/S1 DENORM and S2/S1 DENORM") and not \
                r["branch_assigned"]:
            return {"D": R.ldexp32(s0, 64), "vcc": r["vcc"],
                    "branch": r["branch"], "branch_assigned": True}
        return r

    def m_drop_vcc(s0, s1, s2, mode="passthrough", exp_mode="biased"):
        """Misreading: the derivative VCC flag is never set."""
        r = dict(R.scale_f32(s0, s1, s2, mode=mode, exp_mode=exp_mode))
        r["vcc"] = 0
        return r

    def m_threshold64(s0, s1, s2, mode="passthrough", exp_mode="biased"):
        """Misreading: the overflow guard is 64, not 96."""
        vcc = 0
        if s2 == 0.0 or s1 == 0.0:
            return {"D": V(0x7FC00000), "vcc": 0, "branch": "S2==0 or S1==0",
                    "branch_assigned": True}
        if R.exp_of(s2, exp_mode) - R.exp_of(s1, exp_mode) >= 64:
            vcc = 1
            if s0 == s1:
                return {"D": R.ldexp32(s0, 64), "vcc": 1,
                        "branch": ">=64", "branch_assigned": True}
        return R.scale_f32(s0, s1, s2, mode=mode, exp_mode=exp_mode)

    def m_scale_down(s0, s1, s2, mode="passthrough", exp_mode="biased"):
        """Misreading: the denominator branch scales by -64."""
        r = R.scale_f32(s0, s1, s2, mode="isa_text", exp_mode=exp_mode)
        if r["branch"] == "S1 is DENORM":
            r = dict(r)
            r["D"] = R.ldexp32(s0, -64)
            r["branch_assigned"] = True
        return r

    def m_no_u1(s0, s1, s2, mode="passthrough", exp_mode="biased"):
        """Misreading: the unassigned branch yields 0.0 rather than S0."""
        r = R.scale_f32(s0, s1, s2, mode="isa_text", exp_mode=exp_mode)
        if not r["branch_assigned"]:
            r = dict(r)
            r["D"] = 0.0
        return r

    return [("scale/drop-branch-guard", m_drop_guard),
            ("scale/vcc-never-set", m_drop_vcc),
            ("scale/overflow-threshold-96->64", m_threshold64),
            ("scale/denorm-scale-by-minus-64", m_scale_down),
            ("scale/u1-resolved-to-zero", m_no_u1)]


def _mk_fmas_mutants():
    def m_no_postscale(s0, s1, s2, vcc):
        """Misreading: the conditional 2**32 post-scale is dropped."""
        return R.f32(s0 * s1 + s2)

    def m_scale_after(s0, s1, s2, vcc):
        """Misreading: 2**32 multiplies only the product, not the sum."""
        r = R.f32(s0 * s1) * (2.0 ** 32 if vcc else 1.0) + s2
        return R.f32(r)

    def m_unfused(s0, s1, s2, vcc):
        """Misreading: the multiply is rounded before the add."""
        p = R.f32(R.f32(s0 * s1) + s2)
        return R.f32(p * 2.0 ** 32) if vcc else p

    return [("fmas/no-post-scale", m_no_postscale),
            ("fmas/post-scale-inside-product", m_scale_after),
            ("fmas/unfused", m_unfused)]


def _mk_fixup_mutants():
    def m_no_signout(s0, s1, s2, overflow=R.OVERFLOW_F32,
                     underflow=R.UNDERFLOW_F32):
        """Misreading: the sign_out XOR is dropped (always positive)."""
        v = R.value(R.bits(s1) ^ R.bits(s2))
        return R.fixup_f32(abs(s0), abs(s1), abs(s2), overflow, underflow)

    def m_verbatim_s0(s0, s1, s2, overflow=R.OVERFLOW_F32,
                      underflow=R.UNDERFLOW_F32):
        """Misreading: the default branch returns S0 untouched (what the
        emulator does)."""
        r = R.fixup_f32(s0, s1, s2, overflow, underflow)
        if r["branch"].startswith("default"):
            r = dict(r)
            r["D"] = R.f32(s0)
        return r

    def m_swap_operands(s0, s1, s2, overflow=R.OVERFLOW_F32,
                        underflow=R.UNDERFLOW_F32):
        """Misreading: S1 and S2 are the numerator and denominator."""
        return R.fixup_f32(s0, s2, s1, overflow, underflow)

    def m_threshold_150(s0, s1, s2, overflow=R.OVERFLOW_F32,
                        underflow=R.UNDERFLOW_F32):
        """Misreading: the underflow guard is < -126, not < -150."""
        if R.exp_of(s2) - R.exp_of(s1) < -126 and not (
                s1 == 0.0 or s2 == 0.0 or R.is_inf(s1) or R.is_inf(s2)):
            return {"D": R.f32(R.value(underflow)),
                    "branch": "<-126", "unspecified": True,
                    "sign_out": R.sign_of(s1) ^ R.sign_of(s2)}
        return R.fixup_f32(s0, s1, s2, overflow, underflow)

    return [("fixup/drop-sign-out", m_no_signout),
            ("fixup/default-returns-S0", m_verbatim_s0),
            ("fixup/S1-S2-swapped", m_swap_operands),
            ("fixup/underflow-threshold--150->-126", m_threshold_150)]


# ---------------------------------------------------------------------------
def _obs_scale(fn, s0, s1, s2, exp_mode):
    r = fn(s0, s1, s2, mode="passthrough", exp_mode=exp_mode)
    d = r["D"]
    db = (d if d == R.UNASSIGNED else
          (NAN if (_nan_pred(d) and _nan_is_platform_defined(d)) else B(d)))
    return (db, r["vcc"], bool(r["branch_assigned"]))


def _obs_fmas(fn, s0, s1, s2, vcc):
    d = fn(s0, s1, s2, vcc)
    return NAN if (_nan_pred(d) and _nan_is_platform_defined(d)) else B(d)


def _obs_fixup(fn, s0, s1, s2):
    d = fn(s0, s1, s2)["D"]
    return NAN if (_nan_pred(d) and _nan_is_platform_defined(d)) else B(d)


def _is_nan_bits(x):
    return isinstance(x, int) and (x & 0x7FFFFFFF) > 0x7F800000


def _match(obs, exp):
    """Compare one observation against one hand-derived expectation.

    `NAN` accepts any NaN bit pattern, because for inf + -inf and 0 * inf the
    ISA text pins down neither the payload nor the sign of the result.  Where
    the text DOES write the pattern out (0xffc0_0000 for 0/0 and inf/inf), the
    expectation is the literal and a different NaN fails.
    """
    if exp == NAN:
        return obs == NAN or _is_nan_bits(obs)
    if isinstance(exp, tuple):
        if (obs[0], obs[1]) != (exp[0], exp[1]):
            return False
        return True if len(exp) < 3 else (obs[2] == exp[2])
    return obs == exp


def main():
    out = {"schema": "phase16r-r9-vectors/1", "phase": "16R", "track": "R9",
           "host_only": True, "gpu_execution_performed": False,
           "arms": {}}
    failures = []
    total_cmp = 0

    # ---- ARM 1: the reference against hand-derived literals ---------------
    for name, vectors, obs, exp_key in (
            ("v_div_scale_f32", SCALE, _obs_scale, None),
            ("v_div_fmas_f32", FMAS, _obs_fmas, None),
            ("v_div_fixup_f32", FIXUP, _obs_fixup, None)):
        arm = {"n_vectors": 0, "comparisons": 0, "failures": [],
               "n_reading_discriminating": 0}
        for vec in vectors:
            vid, cat = vec[0], vec[1]
            if name == "v_div_scale_f32":
                _, _, s0, s1, s2, exp = vec[:6]
                alt = vec[7] if len(vec) > 7 else None
                for em, e in (("biased", exp), ("unbiased", alt)):
                    if e is None:
                        continue
                    arm["n_vectors"] += 1
                    got = obs(R.scale_f32, s0, s1, s2, em)
                    arm["comparisons"] += 1
                    total_cmp += 1
                    if not _match(got, e):
                        arm["failures"].append(
                            {"vector": vid, "category": cat, "exp_mode": em,
                             "expected": list(e) if isinstance(e, tuple) else e,
                             "got": list(got)})
                if alt is not None and alt != exp:
                    arm["n_reading_discriminating"] += 1
            elif name == "v_div_fmas_f32":
                _, _, s0, s1, s2, vcc, exp = vec[:7]
                arm["n_vectors"] += 1
                got = obs(R.fmas_f32, s0, s1, s2, vcc)
                arm["comparisons"] += 1
                total_cmp += 1
                if not _match(got, exp):
                    arm["failures"].append({"vector": vid, "category": cat,
                                            "expected": exp, "got": got})
            else:
                _, _, s0, s1, s2, exp = vec[:6]
                arm["n_vectors"] += 1
                got = obs(R.fixup_f32, s0, s1, s2)
                arm["comparisons"] += 1
                total_cmp += 1
                if not _match(got, exp):
                    arm["failures"].append({"vector": vid, "category": cat,
                                            "expected": exp, "got": got})
        arm["verdict"] = "PASS" if not arm["failures"] else "FAIL"
        if arm["failures"]:
            failures.append("reference-vs-hand-derived:" + name)
        out["arms"][name] = arm

    # categorise coverage, so a suite that is all one category is visible
    cats = {}
    for nm, vs in (("scale", SCALE), ("fmas", FMAS), ("fixup", FIXUP)):
        for v in vs:
            cats[v[1]] = cats.get(v[1], 0) + 1
    out["categories"] = cats
    out["total_comparisons_arm1"] = total_cmp
    if total_cmp == 0:
        raise SystemExit("R9 VECTORS: zero comparisons -- not a test")

    # ---- ARM 2: the mutants must be detected ------------------------------
    mut = {"n_mutants": 0, "detected": 0, "not_detected": [],
           "detail": {}, "calls": {}}
    groups = (("v_div_scale_f32", _mk_scale_mutants()),
              ("v_div_fmas_f32", _mk_fmas_mutants()),
              ("v_div_fixup_f32", _mk_fixup_mutants()))
    for name, mutants in groups:
        for mname, raw in mutants:
            ncall = {"n": 0}

            if name == "v_div_scale_f32":
                def fn(s0, s1, s2, mode="passthrough", exp_mode="biased",
                       _r=raw, _c=ncall):
                    _c["n"] += 1
                    return _r(s0, s1, s2, mode=mode, exp_mode=exp_mode)

                def ref(s0, s1, s2, mode="passthrough", exp_mode="biased"):
                    return R.scale_f32(s0, s1, s2, mode=mode,
                                       exp_mode=exp_mode)
                vecs = [(v[2], v[3], v[4], v[5],
                         v[7] if len(v) > 7 else v[5]) for v in SCALE]
                diff_ids = []
                for (s0, s1, s2, e_b, e_u) in vecs:
                    for em, e in (("biased", e_b), ("unbiased", e_u)):
                        a = _obs_scale(ref, s0, s1, s2, em)
                        b = _obs_scale(fn, s0, s1, s2, em)
                        if a[:2] != b[:2]:
                            diff_ids.append("%s/%s" % (em, a))
            elif name == "v_div_fmas_f32":
                def fn(s0, s1, s2, vcc, _r=raw, _c=ncall):
                    _c["n"] += 1
                    return _r(s0, s1, s2, vcc)

                def ref(s0, s1, s2, vcc):
                    return R.fmas_f32(s0, s1, s2, vcc)
                diff_ids = []
                for v in FMAS:
                    a = _obs_fmas(ref, v[2], v[3], v[4], v[5])
                    b = _obs_fmas(fn, v[2], v[3], v[4], v[5])
                    if a != b:
                        diff_ids.append("%s:%s->%s" % (v[0], a, b))
            else:
                def fn(s0, s1, s2, _r=raw, _c=ncall):
                    _c["n"] += 1
                    return _r(s0, s1, s2)

                def ref(s0, s1, s2):
                    return R.fixup_f32(s0, s1, s2)
                diff_ids = []
                for v in FIXUP:
                    a = _obs_fixup(ref, v[2], v[3], v[4])
                    b = _obs_fixup(fn, v[2], v[3], v[4])
                    if a != b:
                        diff_ids.append("%s:%s->%s" % (v[0], a, b))

            mut["n_mutants"] += 1
            mut["calls"][mname] = ncall["n"]
            det = bool(diff_ids) and ncall["n"] > 0
            if det:
                mut["detected"] += 1
            else:
                mut["not_detected"].append(mname)
                failures.append("mutant-not-detected:" + mname)
            mut["detail"][mname] = {
                "target": name, "invocations": ncall["n"],
                "vectors_whose_observation_changed": len(diff_ids),
                "examples": diff_ids[:4],
                "detected": det,
            }
    mut["verdict"] = "PASS" if not mut["not_detected"] else "FAIL"
    out["mutants"] = mut

    # ---- ARM 3: what the EMULATOR does on the same vectors ----------------
    emu = {}
    for name, vectors in (("v_div_scale_f32", SCALE),
                          ("v_div_fmas_f32", FMAS),
                          ("v_div_fixup_f32", FIXUP)):
        agree = differ = 0
        ex = []
        for v in vectors:
            if name == "v_div_scale_f32":
                s0, s1, s2 = v[2], v[3], v[4]
                e = R.emulator_scale_f32(s0, s1, s2)
                g = R.scale_f32(s0, s1, s2, mode="passthrough",
                                exp_mode="biased")
                same = (B(e["D"]) == B(g["D"]) and e["vcc"] == g["vcc"])
            elif name == "v_div_fmas_f32":
                s0, s1, s2, vcc = v[2], v[3], v[4], v[5]
                same = (B(R.emulator_fmas_f32(s0, s1, s2))
                        == B(R.fmas_f32(s0, s1, s2, vcc)))
            else:
                s0, s1, s2 = v[2], v[3], v[4]
                same = (B(R.emulator_fixup_f32(s0, s1, s2))
                        == B(R.fixup_f32(s0, s1, s2)["D"]))
            if same:
                agree += 1
            else:
                differ += 1
                if len(ex) < 8:
                    ex.append(v[0])
        emu[name] = {"vectors": agree + differ, "emulator_agrees": agree,
                     "emulator_differs": differ, "examples_differ": ex}
    out["emulator_vs_isa"] = emu

    out["verdict"] = "PASS" if not failures else "FAIL"
    out["failures"] = failures
    p = os.path.join(os.path.dirname(HERE), "logs", "r9_vectors.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print("R9 VECTORS: comparisons=%d mutants=%d detected=%d not_detected=%d"
          % (total_cmp, mut["n_mutants"], mut["detected"],
             len(mut["not_detected"])))
    for n, a in out["arms"].items():
        print("  %-18s vectors=%-4d failures=%d %s"
              % (n, a["n_vectors"], len(a["failures"]), a["verdict"]))
    print("categories: %s" % out["categories"])
    print("emulator vs ISA: %s"
          % {k: "%d/%d differ" % (v["emulator_differs"], v["vectors"])
             for k, v in emu.items()})
    print("mutants: %s"
          % {k: ("DETECTED %d vectors" % v["vectors_whose_observation_changed"]
                 if v["detected"] else "NOT_DETECTED")
             for k, v in mut["detail"].items()})
    print("VERDICT %s" % out["verdict"])
    print("wrote %s" % p)
    return 0 if out["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
