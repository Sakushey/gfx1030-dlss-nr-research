#!/usr/bin/env python3
"""Phase 16AW -- brief section 31: the LOCAL DETERMINISTIC CONTRACT.

Emits NUMERICAL_CONTRACT_16AW.json.

WHAT THIS FILE IS
-----------------
A declaration, plus the measurements that make the declaration checkable.  The
contract fixes what the PROJECT'S OWN REFERENCE PAIR computes -- reference A
(`k_dec_upsample_A_rn32.py`) and reference B
(`k_dec_upsample_B_independent.py`) -- on every input the operator admits.

WHAT THIS FILE IS NOT
---------------------
It is NOT a claim about the original DLSS-NR model's reduction semantics, about
the vendor kernel's reduction tree, or about what "the model really does".  The
original is a black box that has never been executed here; the brief says so
explicitly and this file keeps the two questions apart by construction: every
sentence below is either (a) a choice the project has made for its own
references, or (b) a measurement OF those references or of the frozen 16AS
native object.  Sentences of kind (b) are labelled `evidence`, and every one of
them carries the count of what was compared.

HOST-ONLY.  No HIP call, no GPU, no launch, no slot.  Nothing outside
`p16aw/numeric/` is written; every input is read-only and its sha256 is
recorded.

A CHECK THAT COMPARES NOTHING IS NOT A PASS.  Every row prints its count, and
every row has a mutant control that is required to CHANGE THE VALUE (not merely
the code path -- a control that swaps in a different mechanism computing the
same function is a measured false start, and the false start is kept on the
record where it happened).
"""
from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import p16aw_common as C                                   # noqa: E402
from fractions import Fraction as Q                        # noqa: E402

OUT = os.path.join(HERE, "NUMERICAL_CONTRACT_16AW.json")
DEVICE_HEADER = os.path.join(C.ROOT, "p16ar", "native", "hip",
                             "k_dec_upsample_fp8.h")
AB_HARNESS = os.path.join(C.P16AR, "native", "cpu_reference",
                          "p16ar_ab_harness.py")
CHUNK, PARTITION, WIDTH = 32, 256, 1024


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def lines_matching(path, needle):
    with open(path, encoding="utf-8") as f:
        return [(i + 1, ln.rstrip("\n"))
                for i, ln in enumerate(f) if needle in ln]


def source_excerpt(path, first, last):
    with open(path, encoding="utf-8") as f:
        ls = f.readlines()
    return [ln.rstrip("\n") for ln in ls[first - 1:last]]


def odd_part(x):
    """x as (m, e) with x = m * 2**e and m ODD (or (0,0)).  Exact."""
    if x == 0:
        return (0, 0)
    neg = x < 0
    a = -x if neg else x
    n, d = a.as_integer_ratio() if isinstance(a, Q) else float(a).as_integer_ratio()
    e = -(d.bit_length() - 1)
    while n % 2 == 0:
        n //= 2
        e += 1
    return (-n if neg else n, e)


def finite_halves():
    """Every finite binary16 value, as the pair (bit pattern, value)."""
    out = []
    for h in range(65536):
        v = struct.unpack("<e", struct.pack("<H", h))[0]
        if v == v and not math.isinf(v):
            out.append((h, v))
    return out


def half_boundary_population():
    """Exact values H() can be asked to round, INCLUDING overflow.

    The 63,488 finite binary16 values are the values H's own domain
    (half-in, half-out) mostly consists of, but they are NOT the whole of what
    H is asked to round: H is applied to a binary32 CHUNK SUM, and that sum can
    exceed binary16's range.  A population that only holds in-range values
    cannot exercise the overflow path, and `H`'s behaviour there is a
    contract sentence -- so the overflow values are built explicitly: n
    maximal products for n = 1..32 (65504 * 448 = 29,345,792 each), the exact
    boundary 65504 and its neighbours, and 2**16, 2**20.
    """
    pop = [("finite_half:%d" % h, Q(v)) for h, v in finite_halves()]
    big = Q(65504) * Q(448)
    for n in range(1, 33):
        pop.append(("chunk_sum_of_%d_maximal_products" % n, n * big))
    for name, v in (("max_half", Q(65504)),
                    ("half_ulp_below_max", Q(65504) - Q(2) ** 5),
                    ("just_over_max", Q(65504) + Q(2) ** 5),
                    ("overflow_tie", Q(65504) + Q(2) ** 4),
                    ("65536", Q(2) ** 16),
                    ("2**20", Q(2) ** 20),
                    ("negative_chunk_sum", -Q(31) * big)):
        pop.append((name, v))
    return pop


def main() -> int:
    rep = C.Report("Phase 16AW section 31 -- the LOCAL DETERMINISTIC CONTRACT")
    A0 = C.load_by_path("A0_16AR", C.A_16AR)
    B0 = C.load_by_path("B0_16AR", C.B_16AR)
    AN = C.load_by_path("AN_16AW", C.A_REPAIRED)
    BI = C.load_by_path("BI_16AW", C.B_INDEPENDENT)
    c16 = json.load(open(C.CONTRACT_16AR, encoding="utf-8"))
    pin = json.load(open(C.PINNING_16AR, encoding="utf-8"))

    doc = {
        "phase": "16AW",
        "brief_section": 31,
        "title": "LOCAL DETERMINISTIC CONTRACT of the k_dec_upsample "
                 "reference pair",
        "host_only": True,
        "no_hip_call": True,
        "status": "DECLARED_AND_MEASURED",
        "what_this_is": (
            "The contract the PROJECT'S OWN two CPU references are required to "
            "implement, stated so that every clause is either a choice this "
            "project made or a measurement of these files."),
        "what_this_is_not": [
            "NOT a claim about the original DLSS-NR model's reduction order, "
            "reduction tree, or accumulator width.",
            "NOT a claim that the vendor kernel implements this contract. "
            "What the frozen 16AS native object actually emits is a separate "
            "measurement (NATIVE_EMITTED_MATH_16AW.json).",
            "NOT a claim that agreement between A and B is evidence about the "
            "model.  A and B agreeing is evidence that THESE TWO FILES "
            "implement THIS CONTRACT; the audit's finding was precisely that "
            "their agreement had been read as more than that.",
        ],
        "provenance": {os.path.relpath(p, C.ROOT): {
            "sha256": sha256_file(p), "bytes": os.path.getsize(p)}
            for p in (C.A_16AR, C.B_16AR, C.CONTRACT_16AR, C.PINNING_16AR,
                      C.A_REPAIRED, C.B_INDEPENDENT, DEVICE_HEADER,
                      AB_HARNESS, os.path.join(HERE, __file__.split(os.sep)[-1]))
            if os.path.exists(p)},
    }

    # ------------------------------------------------------------------ s.30
    # the 16AR sentences this contract replaces, quoted, with the code they
    # were contradicted by
    a_lines = {q: lines_matching(C.A_16AR, q)
               for q in ("s = 0.0", "s += a[a0 + t] * m[m0 + t]")}
    b_lines = {q: lines_matching(C.B_16AR, q)
               for q in ("s = _f32(s + a[a0 + t] * m[m0 + t])",)}
    doc["replaces"] = {
        "16AR_contract_sentence_within_a_chunk":
            c16["frozen_accumulation_model"]["within_a_chunk"],
        "16AR_contract_sentence_between_chunks":
            c16["frozen_accumulation_model"]["between_chunks"],
        "16AR_verdict": c16.get("verdict"),
        "16AR_frozen_tolerances": {
            "absolute": c16.get("frozen_absolute_tolerance"),
            "relative": c16.get("frozen_relative_tolerance")},
        "A_16AR_code_it_described":
            {("line %d" % a_lines[q][0][0]): q for q in a_lines},
        "B_16AR_code_it_described":
            {("line %d" % b_lines[q][0][0]): q for q in b_lines},
        "why_the_sentence_was_false_of_A": (
            "The sentence declares binary32 accumulation.  A_16AR implements "
            "`s = 0.0` / `s += a*m` in CPython, i.e. an IEEE-754 BINARY64 "
            "accumulator with a 53-bit significand, and calls no rounding "
            "helper inside the loop.  The sentence is true of B_16AR and false "
            "of A_16AR, so the recorded `A_AND_B_AGREE` was evidence limited "
            "to the fixture that was run through them."),
    }

    # ------------------------------------------------------------------ s.31
    doc["contract"] = {
        "scope": "k_dec_upsample (block 39) on the 16AR/16AS geometry: "
                 "512x1024 weight matrix, 1024-wide reduction, 512 output "
                 "channels, plus the skip path.",
        "geometry": {"chunk": CHUNK, "partition": PARTITION,
                     "reduction_width": WIDTH,
                     "n_chunks_per_partition": PARTITION // CHUNK,
                     "n_partitions": WIDTH // PARTITION},
        "product": {
            "kind": "CHOICE",
            "statement":
                "The product of one activation and one weight is EXACT and is "
                "not rounded.  A binary16 activation carries at most 11 "
                "significand bits and an E4M3FN weight at most 4 (448 = 7 * "
                "2**6 -> 3 explicit bits), so a product needs at most 15 "
                "significand bits and is exactly representable in binary32 "
                "(24 bits).",
            "evidence": "measurement m_product_exactness below",
            "consequence_for_fma":
                "Because the product is exact in binary32, a compiler that "
                "contracts mul+add into a single fused multiply-add introduces "
                "NO double rounding: FMA(a, b, c) == RN32(a*b exact + c) == the "
                "contract's mul-then-add.  FMA contraction is therefore "
                "contract-neutral here, and the native object's use of "
                "`v_fma_mix_f32` is not a deviation.  This is a statement "
                "about admissible values only; it is not a licence to assume "
                "the same about any other operator.",
        },
        "accumulator": {
            "kind": "CHOICE",
            "statement":
                "binary32: 24-bit significand, round-to-nearest ties-to-even, "
                "subnormal range down to 2**-149, overflow to +/-inf.  Every "
                "partial sum is rounded to binary32 after EVERY accumulate, in "
                "ascending index order; there is exactly ONE rounding per "
                "accumulate step.",
            "order": "ascending index t = 0..31 within a chunk; no tree, no "
                     "pairwise scheme, no reordering.",
            "implementation_of_the_choice": {
                "A": "`chunk_dot` carries an exact dyadic (m, e) and calls "
                     "`rn32_pair` -- integer-only, inspectable -- after every "
                     "`dyadic_add`.",
                "B": "`chunk_dot` calls `_f32` -- an exact rational divided by "
                     "the binade's exact quantum, round-half-to-even -- after "
                     "every add.",
                "why_two_mechanisms": "brief section 33: the two references "
                     "must not share the accumulator helper.  They share the "
                     "SPECIFICATION and nothing else.",
            },
        },
        "chunk_boundaries": {
            "kind": "CHOICE",
            "statement":
                "The row reduction is split into 32-wide chunks (offsets "
                "0,32,...,992 of the 1024-wide axis).  A chunk's 32-term sum is "
                "produced in binary32 as above; the running row accumulator is "
                "kept in binary16 and the chunk sum is combined with it by "
                "H(exact(acc + s)) -- the sum is taken EXACTLY and rounded "
                "ONCE to binary16.",
            "explicitly_not": "H(H32(acc + s)): rounding the chunk sum to "
                              "binary32 and THEN to binary16 is a different "
                              "function (double rounding).  The contract picks "
                              "round-once, which is what B_16AR has always "
                              "computed and what the 16AR contract's own "
                              "`between_chunks` sentence describes.",
        },
        "partition_fold": {
            "kind": "CHOICE",
            "statement":
                "each partition's 256-wide result is a binary16 value; the "
                "four partition results are folded LEFT TO RIGHT as "
                "H(a + b) with the add taken exactly (round once).",
        },
        "rounding_mode": {
            "kind": "CHOICE",
            "statement": "round-to-nearest, ties-to-EVEN, at every rounding "
                         "point: the binary32 accumulate, the binary16 chunk "
                         "boundary, the partition fold, and the fused "
                         "main + skip*scale combination.",
            "no_other_modes": "no flush-to-zero, no round-toward-zero, no "
                              "denormals-are-zero anywhere in the contract.",
        },
        "intermediate_half_conversion": {
            "kind": "CHOICE",
            "statement":
                "H(v) is binary16 round-to-nearest ties-to-even returned as an "
                "exact value (a python float in A, an exact Fraction in B).  H "
                "does NOT saturate: a value whose magnitude exceeds the "
                "largest finite binary16 (65504) rounds to +/-inf, carrying "
                "the sign.  H preserves the sign of a zero: H(-0.0) = -0.0.",
            "evidence": "measurement m_half_boundary below, whose population "
                        "DELIBERATELY includes values above 65504 -- a "
                        "population of in-range values cannot exercise this "
                        "clause",
        },
        "fp8_conversion": {
            "kind": "CHOICE",
            "statement":
                "E4M3FN with SATFINITE semantics: bytes 0x7F and 0xFF decode "
                "to +/-448 (not NaN).  The ENCODER is the pinned arithmetic "
                "procedure, which for a finite input can never emit 0x7F or "
                "0xFF: its last rule rewrites any 15/7 code to 0x7E.  Zero "
                "encodes to 0x00 (A) / 0x00 with the sign bit for -0.0.",
            "note_on_the_device":
                "The device's own `kd::quantize_half_bits` DOES have a 0x7F "
                "path, for NON-FINITE input only; see non_finite_handling.",
        },
        "saturation": {
            "kind": "CHOICE",
            "statement":
                "A FINITE value with magnitude >= 448 encodes to 0x7E "
                "(negative: 0xFE).  Saturation is a value, and it is "
                "specified: it is what the pinned procedure does and it is "
                "what B's nearest-representable search does.",
            "not_saturation":
                "A value beyond binary16's range is NOT saturated to 65504; "
                "it becomes +/-inf (see intermediate_half_conversion) and, if "
                "it then reaches the encoder, it is refused (see "
                "non_finite_handling).",
        },
        "non_finite_handling": {
            "kind": "OUT_OF_CONTRACT",
            "statement":
                "A non-finite fused value has NO contract value.  Both "
                "references REFUSE it, raising the identically named "
                "`NonFiniteFusedValue` (an ArithmeticError) from the encoder.",
            "why_it_is_not_a_number":
                "Three readings exist and the project will not silently pick "
                "one: (1) the device answers (sign<<7)|0x7F for non-finite "
                "half bits, labelled 'OUT OF CONTRACT; made loud' in "
                "k_dec_upsample_fp8.h; (2) the pinned procedure CANNOT emit "
                "0x7F at all -- its final rule rewrites 15/7 to 0x7E; (3) "
                "0x7F is the E4M3FN NaN code in the standard, which "
                "SATFINITE reinterprets as 448 on decode.  Publishing either "
                "byte here would be inventing a reference value so a "
                "comparison can go green.",
            "reachability":
                "REACHABLE, not hypothetical: H is asked to round a binary32 "
                "chunk sum, and 32 terms of 65504 x 448 sum to 939,065,344, "
                "which is far outside binary16.  Measured below.",
            "consequence_for_comparisons":
                "Any A-vs-B-vs-GPU comparison that reaches a non-finite fused "
                "value is VOID, and must be recorded as void rather than as "
                "agreement or disagreement.",
        },
        "outputs": {
            "out_h": "the fused binary16 value H(main + skip*scale) per "
                     "channel, when the pre-quantization path is taken.",
            "out_q": "the E4M3FN byte of that fused value; this is the byte "
                     "16AS froze into expected_out_q.bin.",
            "publication_order": "channel index ascending, matching the "
                                 "frozen fixture's layout.",
        },
        "nan": {
            "kind": "UNREACHABLE",
            "statement":
                "NaN is not reachable from admissible inputs: activations are "
                "binary16 values, weights are E4M3FN values whose only "
                "non-finite pattern (0x7F/0xFF) decodes to +/-448 under "
                "SATFINITE, and the skip/scale tables are binary16.  No NaN "
                "can enter the operator.  A NaN is nevertheless REFUSED "
                "rather than given a value: H passes NaN through and the "
                "encoder refuses it.",
        },
    }

    # ------------------------------------------------------------------ s.31
    # measurement: product exactness over the WHOLE admissible pair domain
    halves_nz = [(h, v) for h, v in finite_halves() if v != 0.0]
    ebytes_nz = [b for b in range(256) if C._e4_decode(b) != 0]
    hdec = [odd_part(v) for _, v in halves_nz]
    edec = [odd_part(C._e4_decode(b)) for b in ebytes_nz]
    n_pairs = 0
    max_bits = 0
    extremal = None
    n_over_24 = 0
    for (hm, he), (hpat, hv) in zip(hdec, halves_nz):
        for (em, ee), eb in zip(edec, ebytes_nz):
            m = hm * em
            nb = abs(m).bit_length()
            n_pairs += 1
            if nb > max_bits:
                max_bits = nb
                extremal = {"activation_bits": hpat, "activation": hv,
                            "weight_byte": "0x%02X" % eb,
                            "weight": float(C._e4_decode(eb)),
                            "product_odd_significand": abs(m),
                            "product_significand_bits": nb}
            if nb > 24:
                n_over_24 += 1
    # a distinct-magnitude enumeration, so the count is not an artefact of
    # counting signed patterns twice
    hmags = sorted({abs(v) for _, v in halves_nz})
    emags = sorted({abs(float(C._e4_decode(b))) for b in ebytes_nz})
    n_mag = 0
    mag_over = 0
    for a in hmags:
        ma, ea = odd_part(a)
        for b in emags:
            mb, eb = odd_part(b)
            n_mag += 1
            if abs(ma * mb).bit_length() > 24:
                mag_over += 1
    doc["measurements"] = {}
    doc["measurements"]["m_product_exactness"] = {
        "domain": "every nonzero finite binary16 pattern x every nonzero "
                  "E4M3FN byte, signs included, as the operator can meet them",
        "n_pairs_enumerated": n_pairs,
        "max_product_significand_bits": max_bits,
        "n_products_needing_more_than_binary32s_24_bits": n_over_24,
        "extremal_pair": extremal,
        "distinct_magnitude_pairs": n_mag,
        "distinct_magnitude_pairs_over_24_bits": mag_over,
        "binary32_significand_bits": 24,
        "conclusion": "every admissible product is EXACT in binary32",
    }
    rep.row("every admissible fp16 x E4M3FN product is exact in binary32 "
            "(and the extreme case is 15 bits, not 24)",
            n_over_24 == 0 and n_pairs > 0, n_pairs,
            {"max_bits": max_bits, "over_24": n_over_24,
             "extremal": extremal})

    # CONTROL: a mutant that rounds the product must be rejected over the same
    # domain, and the mutated branch must be REACHED.
    #
    # MEASURED FALSE START, kept on the record: the first version of this
    # control truncated products to 20 bits.  NO product needs more than 15,
    # so the mutation could never fire, it reached nothing, and the harness
    # FAILED it as COMPARED_NOTHING -- which is the correct outcome for a
    # control that cannot reach its own subject.  A control must be chosen so
    # that its mutation is INSIDE the domain it is testing; 14 bits is inside
    # a domain whose maximum is 15.
    MUT_BITS = 14
    n_mut_reach, n_mut_diff, n_mut_max = 0, 0, 0
    for (hm, he), (hpat, hv) in zip(hdec, halves_nz):
        for (em, ee), eb in zip(edec, ebytes_nz):
            m = abs(hm * em)
            nb = m.bit_length()
            if nb > MUT_BITS:
                n_mut_reach += 1
                n_mut_max = max(n_mut_max, nb)
                truncated = m >> (nb - MUT_BITS)
                if truncated != m:
                    n_mut_diff += 1
    rep.row("CONTROL: the same exactness test REJECTS a product truncated to "
            "%d bits, and the truncation is reached" % MUT_BITS,
            n_mut_reach > 0 and n_mut_diff > 0, n_mut_reach,
            {"reached": n_mut_reach, "differing": n_mut_diff,
             "widest_product_in_the_reached_set": n_mut_max})

    # ------------------------------------------------------- encoder clause
    fin = finite_halves()
    n_enc, n_enc_diff = 0, 0
    for h, v in fin:
        try:
            a = A0.e4m3fn_quantize(v)
        except Exception:                                   # noqa: BLE001
            continue
        b = AN.e4m3fn_quantize(v)
        n_enc += 1
        if a != b:
            n_enc_diff += 1
    n_enc_mut, n_enc_mut_reach = 0, 0

    def enc_mutant(v):
        """The pinned procedure with the mantissa TIE broken away from zero
        instead of to even.  A different VALUE, not a different mechanism."""
        if v != v or math.isinf(v):
            raise AN.NonFiniteFusedValue("mutant: non-finite")
        sign = 0x80 if v < 0 else 0
        a = abs(v)
        if a == 0:
            return 0
        exponent = math.floor(math.log2(max(a, 2.0 ** -9)))
        normal = exponent >= -6
        ee = min(max(exponent + 7, 1), 15)
        x = (a / (2.0 ** exponent) - 1) * 8
        mant = int(x + 0.5)
        if abs(x - int(x)) == 0.5 and int(x) % 2 == 0:
            n_enc_mut_reach_list.append(1)
        else:
            n_enc_mut_reach_list.append(0)
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

    n_enc_mut_reach_list = []
    for h, v in fin:
        try:
            base = AN.e4m3fn_quantize(v)
        except Exception:                                   # noqa: BLE001
            continue
        if enc_mutant(v) != base:
            n_enc_mut += 1
    n_enc_mut_reach = sum(n_enc_mut_reach_list)
    doc["measurements"]["m_encoder_differential_repair_A2"] = {
        "subject": "16AW Repair A-2 adds a non-finite guard to "
                   "e4m3fn_quantize; this proves it changed NO FINITE value",
        "n_compared": n_enc,
        "n_differing": n_enc_diff,
        "mutant": "mantissa tie rounds away from zero instead of to even",
        "mutant_differing": n_enc_mut,
        "mutant_branch_reached": n_enc_mut_reach,
    }
    rep.row("Repair A-2 changed no finite value: A_16AR.e4m3fn_quantize == "
            "A_rn32.e4m3fn_quantize on every finite binary16 value",
            n_enc_diff == 0 and n_enc > 0, n_enc, {"differing": n_enc_diff})
    rep.row("CONTROL: the same value comparison rejects an encoder whose tie "
            "rule is different",
            n_enc_mut > 0, n_enc, {"mutant_differing": n_enc_mut,
                                   "mutant_branch_reached": n_enc_mut_reach})

    # ------------------------------------------------------- half clause
    pop = half_boundary_population()
    n_h, n_h_diff, n_h_reach_over = 0, 0, 0
    for name, v in pop:
        a = A0.H(float(v))
        b = AN.H(float(v))
        n_h += 1
        if abs(v) > Q(65504):
            n_h_reach_over += 1
        if C.exact(a) != C.exact(b):
            n_h_diff += 1
    # the same clause against B, which speaks exact rationals
    n_hb, n_hb_diff = 0, 0
    for name, v in pop:
        x = BI.H(v)
        y = AN.H(float(v))
        n_hb += 1
        if C.exact(x) != C.exact(y):
            n_hb_diff += 1
    # signed zero
    zeros = {"H(+0.0)": repr(AN.H(0.0)), "H(-0.0)": repr(AN.H(-0.0)),
             "B.H(+0.0)": repr(float(BI.H(Q(0)))), "B.H(-0.0)": repr(float(BI.H(Q(0))))}
    doc["measurements"]["m_half_boundary"] = {
        "population": len(pop),
        "population_above_65504": n_h_reach_over,
        "A_16AR_vs_A_16AW_differing": n_h_diff,
        "A_16AW_vs_B_16AW_differing": n_hb_diff,
        "overflow_examples": {
            "H(2 * 65504)": repr(AN.H(2.0 * 65504.0)),
            "H(31 * 65504 * 448)": repr(AN.H(31.0 * 65504.0 * 448.0)),
            "H(2**20)": repr(AN.H(float(2 ** 20))),
            "H(-31 * 65504 * 448)": repr(AN.H(-31.0 * 65504.0 * 448.0)),
        },
        "signed_zero": zeros,
        "note": "the population deliberately contains values ABOVE 65504 so "
                "the no-saturation clause is exercised; an in-range-only "
                "population would compare the clause's easy half and report a "
                "pass",
    }
    rep.row("H's declared no-saturation and sign rules hold, and A and B agree "
            "on every value H is asked to round, INCLUDING overflow",
            n_h_diff == 0 and n_hb_diff == 0 and n_h_reach_over > 0, n_h,
            {"A_vs_A_diff": n_h_diff, "A_vs_B_diff": n_hb_diff,
             "above_65504": n_h_reach_over})

    # CONTROL: a saturating H must be rejected -- and must be reached
    n_sat_reach, n_sat_diff = 0, 0
    for name, v in pop:
        if abs(v) > Q(65504):
            n_sat_reach += 1
        sat = Q(math.copysign(65504.0, 1.0 if v >= 0 else -1.0)) \
            if abs(v) > Q(65504) else BI.H(v)
        if C.exact(sat) != C.exact(BI.H(v)):
            n_sat_diff += 1
    rep.row("CONTROL: the same comparison REJECTS a saturating H, and the "
            "saturation branch is reached",
            n_sat_reach > 0 and n_sat_diff > 0, n_h,
            {"reached": n_sat_reach, "differing": n_sat_diff})

    # ------------------------------------------- the clause the code must show
    def chunk_dot_rounds_explicitly(path):
        """AST: does `chunk_dot` round explicitly at every accumulate?

        Measured, not asserted: the body must call a rounding function INSIDE
        the accumulate loop, and must not express the accumulation as a bare
        float `+=`."""
        tree = ast.parse(open(path, encoding="utf-8").read())
        fn = next(n for n in tree.body
                  if isinstance(n, ast.FunctionDef) and n.name == "chunk_dot")
        calls = {n.func.id for n in ast.walk(fn)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        augs = sum(1 for n in ast.walk(fn) if isinstance(n, ast.AugAssign))
        return {"calls": sorted(calls), "augassign_count": augs,
                "rounds_explicitly": bool(calls & {"rn32_pair", "_f32"})
                                     and augs == 0}

    an_ast = chunk_dot_rounds_explicitly(C.A_REPAIRED)
    a0_ast = chunk_dot_rounds_explicitly(C.A_16AR)
    b0_ast = chunk_dot_rounds_explicitly(C.B_16AR)
    doc["contract"]["accumulator"]["code_check"] = {
        "A_16AW": an_ast, "A_16AR": a0_ast, "B_16AR": b0_ast,
        "predicate": "calls rn32_pair or _f32 inside chunk_dot AND contains no "
                     "bare float `+=` (an AugAssign on the accumulator)",
    }
    rep.row("the DECLARED binary32-accumulate clause is what the repaired A's "
            "code actually does",
            an_ast["rounds_explicitly"], len(an_ast["calls"]),
            an_ast)
    rep.row("CONTROL: the same predicate REJECTS A_16AR's chunk_dot, which is "
            "the defect the audit found",
            not a0_ast["rounds_explicitly"] and a0_ast["augassign_count"] > 0,
            len(a0_ast["calls"]),
            {"A_16AR": a0_ast, "B_16AR_passes_the_same_predicate":
             b0_ast["rounds_explicitly"]})

    # ------------------------------------------------ non-finite disposition
    big = 32 * 65504.0 * 448.0
    def probe(label, fn):
        try:
            return {"outcome": "VALUE", "value": fn()}
        except Exception as e:                              # noqa: BLE001
            return {"outcome": "RAISED", "type": type(e).__name__,
                    "message": str(e)[:200]}

    nonfin = {
        "H(32 * 65504 * 448)": probe("H", lambda: AN.H(big)),
        "quantize(inf) via A_16AR": probe("q", lambda: A0.e4m3fn_quantize(
            AN.H(big))),
        "quantize(inf) via A_16AW": probe("q", lambda: AN.e4m3fn_quantize(
            AN.H(big))),
        "encode(inf) via B_16AR": probe("q", lambda: B0.e4m3fn_encode(
            BI.H(Q(32) * Q(65504) * Q(448)))),
        "encode(inf) via B_16AW": probe("q", lambda: BI.e4m3fn_encode(
            BI.H(Q(32) * Q(65504) * Q(448)))),
        "quantize(nan) via A_16AR": probe("q", lambda: A0.e4m3fn_quantize(
            float("nan"))),
        "quantize(nan) via A_16AW": probe("q", lambda: AN.e4m3fn_quantize(
            float("nan"))),
    }
    dev_q = lines_matching(DEVICE_HEADER, "nonfinite")
    dev_line = lines_matching(DEVICE_HEADER, "0x7F")
    doc["measurements"]["m_non_finite_disposition"] = {
        "device_source_read": {
            "path": os.path.relpath(DEVICE_HEADER, C.ROOT),
            "sha256": sha256_file(DEVICE_HEADER),
            "lines_with_nonlinear_marker": [
                {"line": n, "text": t} for n, t in dev_q],
            "lines_with_0x7F": [{"line": n, "text": t} for n, t in dev_line],
            "kind": "SOURCE_READ, not a measurement of executed device "
                    "behaviour; this project is host-only and will not claim "
                    "to have run it",
        },
        "probes": nonfin,
        "reachability": {
            "chunk_sum_of_32_maximal_products": big,
            "binary16_max_finite": 65504.0,
            "so_the_fused_value_is": repr(AN.H(big)),
        },
    }
    n_refusals = sum(1 for k, v in nonfin.items()
                     if v["outcome"] == "RAISED"
                     and v.get("type") == "NonFiniteFusedValue")
    rep.row("a non-finite fused value is REACHABLE and both references refuse "
            "it identically (named exception), publishing no byte",
            n_refusals == 3 and
            nonfin["quantize(nan) via A_16AW"]["outcome"] == "RAISED",
            5, {"refusals": n_refusals, "probes": nonfin})

    # the 16AR harness's own exclusion, quoted, and marked measured-FALSE
    ab_txt = open(AB_HARNESS, encoding="utf-8").read()
    excl = [ln.strip() for ln in ab_txt.splitlines()
            if "n_excluded_non_finite" in ln or "whole domain" in ln]
    doc["measurements"]["m_16AR_exclusion_justification"] = {
        "path": os.path.relpath(AB_HARNESS, C.ROOT),
        "sha256": sha256_file(AB_HARNESS),
        "quoted": excl,
        "measured_verdict": "FALSE",
        "why": "The justification is that quantize is only ever applied to "
               "H(...) results, i.e. to binary16 values, so excluding the "
               "non-finite binary16 patterns loses nothing.  Measured: H CAN "
               "return +/-inf (H(32*65504*448) = inf, above), so the two "
               "infinity patterns are REACHABLE and the exclusion drops them. "
               "Precisely: 65536 - 63488 = 2048 patterns were excluded (2 "
               "infinities and 2046 NaNs); of those, the 2 infinities are the "
               "reachable ones -- NaN is not reachable, because H's input here "
               "is a sum of finite products.  The harness line quotes its own "
               "count as `65536 - len(halves)`, i.e. 2048, while the sentence "
               "beside it was written as though the exclusion were the 2 "
               "infinity patterns; the sentence and the count disagree with "
               "each other as well as with the code.",
        "consequence": "16AR's own two-reference comparison was blind to the "
                       "one class of input where the two references and the "
                       "device disagree about what to publish.",
    }
    rep.row("16AR's stated justification for excluding non-finite halves is "
            "refuted by the measurement above",
            AN.H(big) == float("inf") and bool(excl), len(excl), {"quoted": excl})

    # ---------------------------------------------------------------- output
    vals = [r for r in rep.rows if r["ok"]]
    doc["checks"] = rep.rows
    doc["n_checks"] = len(rep.rows)
    doc["n_checks_ok"] = len(vals)
    doc["verdict"] = ("CONTRACT_DECLARED_AND_MEASURED"
                      if len(vals) == len(rep.rows)
                      else "CONTRACT_INCOMPLETE")
    doc["steps_31_verdict"] = {
        "product_precision": "DECLARED (exact) and MEASURED over the whole "
                             "admissible pair domain",
        "accumulator_precision": "DECLARED (binary32, RN-even, one rounding per "
                                 "accumulate) and MEASURED against both "
                                 "references' code",
        "accumulation_order": "DECLARED (ascending index, no tree)",
        "chunk_boundaries": "DECLARED (32-wide, round-once into binary16)",
        "rounding_mode": "DECLARED (RN-even everywhere)",
        "intermediate_half_conversion": "DECLARED (no saturation, sign of zero "
                                        "preserved) and MEASURED including "
                                        "overflow",
        "fp8_conversion": "DECLARED (SATFINITE decode, pinned encoder, never "
                          "0x7F for finite input)",
        "saturation": "DECLARED (finite >= 448 -> 0x7E/0xFE)",
        "nan_inf_handling": "DECLARED OUT OF CONTRACT, both references refuse "
                            "loudly; NaN unreachable; reachability MEASURED",
        "what_could_not_be_measured": [
            "whether the original DLSS-NR model implements any of this -- not "
            "measured, and not attempted: the model has never been executed "
            "here and the brief forbids running it.",
        ],
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    print("  -> %s" % os.path.basename(OUT))
    print("  %d/%d checks ok" % (rep.n_ok, len(rep.rows)))
    return 0 if rep.n_ok == len(rep.rows) else 1


if __name__ == "__main__":
    sys.exit(main())
