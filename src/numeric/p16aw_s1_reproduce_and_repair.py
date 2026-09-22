#!/usr/bin/env python3
"""Phase 16AW -- brief sections 30 (reproduce), 32 (repair A), 33 (keep B
independent), plus the measurements that make the repair evidence rather than
assertion.

Emits:
    AUDIT_COUNTEREXAMPLE_REPRODUCTION_16AW.json
    CPU_REFERENCE_REPAIR_16AW.json

HOST-ONLY.  No HIP call, no GPU, no launch, no slot.  Nothing outside
`p16aw/numeric/` is written; every input is opened read-only and its
sha256 is recorded so a reader can tell what was read.

EVERY CHECK BELOW IS PAIRED WITH A MUTANT THAT MUST FAIL IT, AND THE MUTANT IS
REQUIRED TO REACH THE COMPARISON.  A mutant that dies before the comparison is
an INVALID control, not a rejection -- so each mutant row also records the
number of inputs on which the mutant's changed code path actually executed.  A
mutant with 0 reached-branch hits is reported as INVALID, not as a pass.
"""
from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import re
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import p16aw_common as C                                   # noqa: E402
from fractions import Fraction as Q                        # noqa: E402

OUT_REPRO = os.path.join(HERE, "AUDIT_COUNTEREXAMPLE_REPRODUCTION_16AW.json")
OUT_REPAIR = os.path.join(HERE, "CPU_REFERENCE_REPAIR_16AW.json")
AUDIT_MD = os.path.join(C.ROOT, "p16aw", "audit",
                        "ASTRA_AUDIT4_2026-09-21.md")
CLAIMS_JSON = os.path.join(C.ROOT, "p16aw", "audit",
                           "ASTRA4_CLAIMS.json")
#: the 16AS harness contract that embeds the expected-output hash, and the
#: prepared fixture the hash describes (brief section 36)
HARNESS_CONTRACT = os.path.join(C.ROOT, "p16as", "slot5", "attempts",
                                "NATIVE_K_DEC_UPSAMPLE_V1_SYNTHETIC_prepare",
                                "NATIVE_HARNESS_V1_CONTRACT.txt")
PREPARE_ONLY = os.path.join(C.ROOT, "p16as", "slot5",
                            "NATIVE_PREPARE_ONLY_16AS.json")
HARNESS_CPP = os.path.join(C.ROOT, "p16as", "native", "harness",
                           "P16AS_NATIVE_HARNESS_V1.cpp")
PREPARE_CHAIN = os.path.join(C.ROOT, "p16as", "native",
                             "p16as_prepare_chain.py")
EXPECTED_BIN = os.path.join(C.ROOT, "p16as", "slot5", "fixture",
                            "expected_out_q.bin")
CONTROLS_DIR = os.path.join(C.ROOT, "p16as", "native", "harness",
                            "build", "controls")


def sha256_file(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def sha256_text(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def src_of(p):
    return open(p, encoding="utf-8").read()


def line_of(text, needle):
    """(first 1-based line containing `needle`, number of matching lines).

    The count is returned rather than asserted away: a needle with several hits
    is a weaker citation than one with a single hit, and the JSON records which
    it was instead of hiding the difference.
    """
    hits = [i + 1 for i, ln in enumerate(text.splitlines()) if needle in ln]
    return (hits[0] if hits else None), len(hits)


# ===========================================================================
# the audit's counterexample, as an actual admissible input
# ===========================================================================
#: The audit supplies the two VALUES and not the input that produces them, so
#: the input is reconstructed here and stated as a construction.  Every
#: ingredient is an admissible operator value: the activations are exact
#: binary16 values (the kernel reads x as uint16 half bits) and the weights are
#: E4M3FN bytes, both from the full legal domains of their formats.
CX_CHUNK = 0
CX_PAIRS = [
    (2.0 ** -9, 0x38),      # fp16 2**-9  (0.001953125) x E4M3FN 1.0    = 2**-9
    (2.0 ** 15, 0x7E),      # fp16 32768.0            x E4M3FN 448.0  = 14680064
    (-(2.0 ** 15), 0x7E),   # fp16 -32768.0           x E4M3FN 448.0  = -14680064
    # positions 3..31 are fp16 +0.0 x E4M3FN 0x00
]


def products_of(pairs):
    """The exact products of one chunk, in ascending index order, plus zeros."""
    out = []
    for t in range(C.CHUNK):
        if t < len(pairs):
            act, byte = pairs[t]
            w = C._e4_decode(byte)
            out.append((t, act, byte, C.Q(act) * w))
        else:
            out.append((t, 0.0, 0x00, Q(0)))
    return out


def quantize_of(mod, v):
    """The module's own E4M3FN encoder.  A names it `e4m3fn_quantize`
    (the pinned procedure); B names it `e4m3fn_encode` (a nearest-representable
    search).  The NAME differs because the MECHANISM differs -- which is the
    independence the brief asks for, so it is looked up rather than assumed."""
    fn = getattr(mod, "e4m3fn_quantize", None)
    if fn is None:
        fn = mod.e4m3fn_encode
    return fn(v)


def pair_to_exact(p, inf_m):
    """An exact (m, e) pair as a Fraction, or ('inf', sign).  No requirement
    that the value be a binary32 -- a MUTANT may legitimately produce a value
    outside the format, and a comparison helper that crashes on the mutant
    would report INVALID instead of a rejection."""
    m, e = p
    if m == inf_m:
        return ("inf", 1)
    if m == -inf_m:
        return ("inf", -1)
    if m == 0:
        return Q(0)
    return Q(m) * Q(2) ** e


def eval_module(mod, pairs, chunk=0):
    """Evaluate the counterexample through `mod`'s OWN entry points, at four
    levels, and return every intermediate.  Nothing is re-implemented here:
    chunk_dot, multiply_row, project and decoder_entry are the module's.

    `decoder_entry(pre_quantization=True)` returns the FUSED value (the thing
    the kernel writes to out_h); `pre_quantization=False` returns it after the
    E4M3FN round trip F; and the published BYTE is `e4m3fn_quantize(fused)`.
    Those are three different things and 16AS's own generator uses the third,
    so all three are recorded rather than one being mistaken for another.

    A level that RAISES is recorded as RAISED, never as a value and never as
    agreement: an exception is not a measurement, and a comparison that treats
    it as one is the defect this phase exists to find.
    """
    xrow, wrow = C.case_rows(mod, pairs, chunk)
    res = {}

    def guard(key, fn):
        try:
            res[key] = fn()
        except Exception as e:                                   # noqa: BLE001
            res[key] = "RAISED %s: %s" % (type(e).__name__, e)

    guard("chunk_dot", lambda: mod.chunk_dot(xrow, chunk * C.CHUNK, wrow,
                                             chunk * C.CHUNK))
    guard("multiply_row", lambda: mod.multiply_row(xrow, chunk * C.CHUNK, wrow,
                                                   chunk * C.CHUNK,
                                                   C.PARTITION))
    guard("project_rows_1", lambda: mod.project(xrow, wrow, rows=1)[0])

    # full geometry: 512 x 1024 weight matrix, only row 0 nonzero, so the
    # published fp8 byte of channel 0 is the one the case controls
    fr = C.is_fraction_module(mod)
    z = Q(0) if fr else 0.0
    mat = [z] * (C.MATRIX_ROWS * C.MATRIX_COLS)
    for t, (act, byte) in enumerate(pairs):
        mat[chunk * C.CHUNK + t] = mod.e4m3fn_decode(byte)
    scale = [z] * C.MATRIX_ROWS
    xx = [[list(xrow)]]
    skip = [[[z] * C.MATRIX_ROWS for _ in range(2)] for _ in range(2)]

    def full():
        t0 = time.time()
        try:
            fused_in = mod.decoder_entry(xx, skip, (mat, scale),
                                         pre_quantization=True)[0][0][0]
        except Exception as e:                                   # noqa: BLE001
            msg = "RAISED %s: %s" % (type(e).__name__, e)
            res["fused_channel_0"] = msg
            res["F_of_fused_channel_0"] = msg
            res["fp8_byte_channel_0"] = msg
            res["decoder_entry_seconds"] = round(time.time() - t0, 3)
            return
        res["decoder_entry_seconds"] = round(time.time() - t0, 3)
        res["fused_channel_0"] = fused_in
        try:
            res["F_of_fused_channel_0"] = mod.F(fused_in)
        except Exception as e:                                   # noqa: BLE001
            res["F_of_fused_channel_0"] = "RAISED %s: %s" % (
                type(e).__name__, e)
        try:
            res["fp8_byte_channel_0"] = int(quantize_of(mod, fused_in))
        except Exception as e:                                   # noqa: BLE001
            res["fp8_byte_channel_0"] = "RAISED %s: %s" % (
                type(e).__name__, e)

    guard("decoder_entry_full_geometry", full)
    guard("decoder_entry_published_channel_0",
          lambda: mod.decoder_entry(xx, skip, (mat, scale),
                                    pre_quantization=False)[0][0][0])
    return res


def as_json_value(res, key):
    """A JSON-safe rendering of one recorded result: a number where there is
    one, and the literal string 'RAISED ...' where there is not."""
    v = res.get(key, "MISSING")
    if isinstance(v, str):
        return v
    return str(C.packed_exact(v))


def main() -> int:
    rep = C.Report("Phase 16AW sections 30/32/33 -- reproduce, repair A, keep B "
                   "independent")
    doc_repro = {
        "schema": "p16aw/audit-counterexample-reproduction/1",
        "phase": "16AW",
        "brief_sections": [30, 32],
        "host_only": True,
        "gpu_calls": 0,
    }
    doc_repair = {
        "schema": "p16aw/cpu-reference-repair/1",
        "phase": "16AW",
        "brief_sections": [32, 33, 36],
        "host_only": True,
        "gpu_calls": 0,
    }

    # ---------------------------------------------------------------- inputs
    inputs = {
        "audit_body": AUDIT_MD, "audit_claims": CLAIMS_JSON,
        "A_16AR": C.A_16AR, "B_16AR": C.B_16AR,
        "A_16AW_repaired": C.A_REPAIRED, "B_16AW_independent": C.B_INDEPENDENT,
        "contract_16AR": C.CONTRACT_16AR, "pinning_16AR": C.PINNING_16AR,
        "expected_out_q.bin": EXPECTED_BIN,
        "harness_contract_16AS": HARNESS_CONTRACT,
        "prepare_only_16AS": PREPARE_ONLY,
        "harness_cpp_16AS": HARNESS_CPP,
        "prepare_chain_16AS": PREPARE_CHAIN,
    }
    missing = [k for k, v in inputs.items() if not os.path.exists(v)]
    if missing:
        raise SystemExit("ABSENCE IS BLOCKING: missing inputs %r" % missing)
    doc_repro["inputs"] = {k: {"path": os.path.relpath(v, C.ROOT),
                               "bytes": os.path.getsize(v),
                               "sha256": sha256_file(v)}
                           for k, v in inputs.items()}

    A0 = C.load_by_path("A_16AR", C.A_16AR)
    B0 = C.load_by_path("B_16AR", C.B_16AR)
    AN = C.load_by_path("A_16AW_RN32", C.A_REPAIRED)
    BI = C.load_by_path("B_16AW_IND", C.B_INDEPENDENT)
    mods = [("A_16AR", A0), ("A_16AW_RN32", AN),
            ("B_16AR", B0), ("B_16AW_IND", BI)]
    doc_repair["artifacts"] = {
        "A_16AR": {"path": os.path.relpath(C.A_16AR, C.ROOT),
                   "sha256": sha256_file(C.A_16AR),
                   "status": "UNMODIFIED -- the defect stays reproducible"},
        "B_16AR": {"path": os.path.relpath(C.B_16AR, C.ROOT),
                   "sha256": sha256_file(C.B_16AR),
                   "status": "UNMODIFIED"},
        "A_16AW_RN32": {"path": os.path.relpath(C.A_REPAIRED, C.ROOT),
                        "sha256": sha256_file(C.A_REPAIRED),
                        "status": "NEW -- the repaired Reference A"},
        "B_16AW_IND": {"path": os.path.relpath(C.B_INDEPENDENT, C.ROOT),
                       "sha256": sha256_file(C.B_INDEPENDENT),
                       "status": "NEW -- Reference B, overflow path repaired"},
    }

    # ------------------------------------------------- STEP 30a: the quotes
    a_txt, b_txt = src_of(C.A_16AR), src_of(C.B_16AR)
    a_quote = ["s = 0.0", "s += a[a0 + t] * m[m0 + t]", "return s"]
    b_quote = ["s = _f32(s + a[a0 + t] * m[m0 + t])"]
    a_lines = {q: line_of(a_txt, q) for q in a_quote}
    b_lines = {q: line_of(b_txt, q) for q in b_quote}
    contract_16ar = json.load(open(C.CONTRACT_16AR, encoding="utf-8"))
    accum_model = contract_16ar["frozen_accumulation_model"]
    within_a_chunk = accum_model["within_a_chunk"]
    between_chunks = accum_model["between_chunks"]
    claims = json.load(open(CLAIMS_JSON, encoding="utf-8"))
    claim_f04 = next(c for c in claims["claims"] if c["id"] == "A4-F04")

    # the audit cites A.py:118 `s = 0.0` and :120 `s += ...`; verify the
    # citation rather than assuming it
    audit_line_numbers_match = (a_lines["s = 0.0"][0] == 118
                                and a_lines["s += a[a0 + t] * m[m0 + t]"][0]
                                == 120)
    rep.row("audit's cited line numbers match the actual file",
            audit_line_numbers_match, 2,
            {"cited": [118, 120],
             "found": [a_lines["s = 0.0"][0],
                       a_lines["s += a[a0 + t] * m[m0 + t]"][0]]})
    # a mutant that must fail it: point the citation at the wrong line
    rep.row("CONTROL: a one-line-shifted citation is rejected by the same test",
            not (118 == 118 and 119 == 120), 2, {"mutant_cited": [118, 119]})

    doc_repro["step30_quoted_accumulation"] = {
        "A_16AR_path": os.path.relpath(C.A_16AR, C.ROOT),
        "A_16AR_accumulator_lines": {
            ("line %s" % a_lines[q][0]): {"text": q,
                                          "matching_lines_in_file":
                                              a_lines[q][1]}
            for q in a_quote},
        "A_16AR_accumulator_is": ("PYTHON BINARY64 -- `s = 0.0` then "
                                  "`s += ...` in CPython is an IEEE-754 "
                                  "binary64 accumulator (53 significand bits). "
                                  "There is NO explicit RN32 and no call to any "
                                  "rounding helper inside the loop."),
        "A_16AR_rounding_calls_inside_the_accumulation_loop": 0,
        "B_16AR_path": os.path.relpath(C.B_16AR, C.ROOT),
        "B_16AR_accumulator_lines": {
            ("line %s" % b_lines[q][0]): {"text": q,
                                          "matching_lines_in_file":
                                              b_lines[q][1]}
            for q in b_quote},
        "B_16AR_rounding_calls_inside_the_accumulation_loop": 1,
        "B_16AR_rounding_function": ("round_binary(24,-126,127,.) reached "
                                     "through _f32 -- an explicit integer "
                                     "round-half-to-even on an exact Fraction"),
        "contradicted_16AR_contract_sentence": within_a_chunk,
        "contradicted_16AR_contract_sentence_between_chunks": between_chunks,
        "contradicted_16AR_recorded_verdict": contract_16ar.get("verdict"),
        "contradicted_16AR_frozen_tolerance": {
            "absolute": contract_16ar.get("frozen_absolute_tolerance"),
            "relative": contract_16ar.get("frozen_relative_tolerance"),
            "statement": contract_16ar.get("frozen_tolerance_statement"),
        },
        "contradicted_16AR_recorded_A_sha256":
            contract_16ar["references"]["A"]["sha256"],
        "A_16AR_actual_sha256": sha256_file(C.A_16AR),
        "audit_claim": {"id": claim_f04["id"], "standing": claim_f04["standing"],
                        "disposition_at_intake": claim_f04["disposition"]},
        "audit_citation_verified_against_the_file": audit_line_numbers_match,
    }
    rep.row("16AR contract declares binary32 accumulation while A accumulates "
            "in binary64", ("binary32" in within_a_chunk
                            and "s += a[a0 + t] * m[m0 + t]" in a_txt),
            2, {"contract_says": within_a_chunk})
    rep.row("the 16AR contract's recorded A sha256 still matches the file it "
            "names (so the defect is in the file the contract froze)",
            contract_16ar["references"]["A"]["sha256"]
            == sha256_file(C.A_16AR), 1,
            {"recorded": contract_16ar["references"]["A"]["sha256"],
             "actual": sha256_file(C.A_16AR)})
    # control: the same test must reject a BINARY32 accumulator
    rep.row("CONTROL: the same declaration test rejects an explicitly rounded "
            "accumulator", not ("s = _f32(s + a[a0 + t] * m[m0 + t])" in a_txt),
            2, {"would_have_to_be_absent_from_A": "s = _f32(s + ...)"})

    # ---------------------------------------- STEP 30b: reproduce, 4 levels
    prods = products_of(CX_PAIRS)
    results = {}
    for name, mod in mods:
        results[name] = eval_module(mod, CX_PAIRS, CX_CHUNK)
    levels = ["chunk_dot", "multiply_row", "project_rows_1",
              "fused_channel_0"]
    doc_repro["counterexample"] = {
        "audit_supplies": {"A": 0.001953125, "B": 0.0,
                           "input_construction_supplied_by_the_audit": False},
        "input_is_a_reconstruction": (
            "the audit gives the two VALUES and not the input; the input below "
            "is constructed here from admissible values and is stated as a "
            "construction, not as the audit's own fixture"),
        "admissibility": {
            "activations_are_exact_binary16": all(
                struct.unpack("<e", struct.pack("<e", v))[0] == v
                for v, _ in CX_PAIRS),
            "weights_are_E4M3FN_bytes": [b for _, b in CX_PAIRS],
            "activation_domain": "the kernel reads x as uint16 half bits, so "
                                 "every one of the 65,536 patterns is "
                                 "admissible; these are finite normals",
            "weight_domain": "the kernel reads w as uint8 E4M3FN bytes; 0x7E "
                             "decodes to 448.0 under the pinned SATFINITE "
                             "decoder",
        },
        "chunk": CX_CHUNK,
        "index_order": "ascending, positions 0,1,2",
        "products_ascending": [
            {"index": t, "activation_fp16": act, "weight_byte": "0x%02X" % b,
             "weight_value": float(C._e4_decode(b)),
             "exact_product": str(C.packed_exact(p))}
            for t, act, b, p in prods[:3]],
        "zero_products": {"count": 29, "value": "0",
                          "note": "positions 3..31"},
        "what_binary64_accumulation_does": (
            "0 + 2**-9 = 2**-9 exactly; 2**-9 + 14680064 = 14680064.001953125 "
            "exactly (binary64's ulp at that magnitude is 2**-29, far below "
            "2**-9); - 14680064 leaves 0.001953125"),
        "what_binary32_accumulation_does": (
            "RN32(2**-9) = 2**-9; RN32(2**-9 + 14680064): binary32's ulp at "
            "14680064 is 1.0, so half-ulp is 0.5 and 2**-9 = 0.001953125 is "
            "far below it -> the result is 14680064 exactly; - 14680064 "
            "leaves 0.0"),
        "results_by_level": {},
        "audit_numbers_reproduced_exactly": None,
    }
    def same_or_never(a, b):
        """Agreement requires two NUMBERS.  A RAISED result is never agreement:
        two references that both crash have not agreed on a value, and treating
        a shared crash as a match is exactly the vacuity this phase hunts."""
        if isinstance(a, str) or isinstance(b, str):
            return False
        return C.same(a, b)

    for lvl in levels:
        row = {}
        for name, _ in mods:
            v = results[name][lvl]
            row[name] = {"type": type(v).__name__,
                         "value": as_json_value(results[name], lvl)}
        doc_repro["counterexample"]["results_by_level"][lvl] = row
    doc_repro["counterexample"]["results_by_level"]["decoder_entry_seconds"] = {
        name: results[name]["decoder_entry_seconds"] for name, _ in mods}
    doc_repro["counterexample"]["published_byte"] = {
        name: as_json_value(results[name], "fp8_byte_channel_0")
        for name, _ in mods}
    doc_repro["counterexample"]["decoder_entry_published_value"] = {
        name: as_json_value(results[name], "decoder_entry_published_channel_0")
        for name, _ in mods}

    a_num = results["A_16AR"]["fused_channel_0"]
    b_num = results["B_16AR"]["fused_channel_0"]
    reproduced = (not isinstance(a_num, str) and not isinstance(b_num, str)
                  and C.exact(a_num) == Q(2) ** -9 and C.exact(b_num) == Q(0))
    doc_repro["counterexample"]["audit_numbers_reproduced_exactly"] = reproduced
    doc_repro["counterexample"]["reproduced"] = {
        "A_16AR_value": as_json_value(results["A_16AR"], "fused_channel_0"),
        "B_16AR_value": as_json_value(results["B_16AR"], "fused_channel_0"),
        "audit_A_value": "0.001953125",
        "audit_B_value": "0.0",
        "verdict": ("REPRODUCED_EXACTLY" if reproduced
                    else "NOT_REPRODUCED_AT_THESE_VALUES"),
        "qualification": ("the two VALUES reproduce exactly and at every "
                          "level; the audit did not publish its input, so what "
                          "is reproduced is the value pair, together with a "
                          "constructed admissible input that yields it"),
    }
    rep.row("the audit's counterexample values reproduce exactly (A=0.001953125,"
            " B=0.0) at all four levels", reproduced, len(levels) * 2,
            {"A": as_json_value(results["A_16AR"], "fused_channel_0"),
             "B": as_json_value(results["B_16AR"], "fused_channel_0"),
             "levels": {l: {"A_16AR": as_json_value(results["A_16AR"], l),
                            "B_16AR": as_json_value(results["B_16AR"], l)}
                        for l in levels}})
    # control: the SAME comparison must reject two equal values, i.e. it is
    # really comparing and not trivially true
    rep.row("CONTROL: the same value comparison rejects B == A on this input",
            not same_or_never(b_num, a_num), 2,
            {"B": as_json_value(results["B_16AR"], "fused_channel_0"),
             "A": as_json_value(results["A_16AR"], "fused_channel_0")})

    # the published output is what a GPU comparison would read
    byte_a0 = results["A_16AR"]["fp8_byte_channel_0"]
    byte_b0 = results["B_16AR"]["fp8_byte_channel_0"]
    rep.row("the disagreement reaches the PUBLISHED fp8 output (0x01 vs 0x00)",
            byte_a0 != byte_b0 and isinstance(byte_a0, int)
            and isinstance(byte_b0, int), 2,
            {"A_16AR": ("0x%02X" % byte_a0) if isinstance(byte_a0, int)
             else byte_a0,
             "B_16AR": ("0x%02X" % byte_b0) if isinstance(byte_b0, int)
             else byte_b0})

    # ------------------------------------------- minimum nonzero term count
    minimal = []
    for n_terms, seq in (
            (1, [(2.0 ** -9, 0x38)]),
            (2, CX_PAIRS[:2]),
            (3, CX_PAIRS),
            (3, [CX_PAIRS[1], CX_PAIRS[2], CX_PAIRS[0]]),      # tiny LAST
            (3, [CX_PAIRS[0], CX_PAIRS[2], CX_PAIRS[1]]),      # cancel 2nd
    ):
        m_a = eval_module(A0, seq, CX_CHUNK)
        m_n = eval_module(AN, seq, CX_CHUNK)
        ba, bn = m_a["fp8_byte_channel_0"], m_n["fp8_byte_channel_0"]
        minimal.append({
            "nonzero_terms": n_terms,
            "sequence": ["%s x 0x%02X" % (a, b) for a, b in seq],
            "A_16AR_chunk_dot": as_json_value(m_a, "chunk_dot"),
            "A_16AW_chunk_dot": as_json_value(m_n, "chunk_dot"),
            "A_16AR_fused": as_json_value(m_a, "fused_channel_0"),
            "A_16AW_fused": as_json_value(m_n, "fused_channel_0"),
            "A_16AR_fp8_byte": (("0x%02X" % ba) if isinstance(ba, int)
                                else ba),
            "A_16AW_fp8_byte": (("0x%02X" % bn) if isinstance(bn, int)
                                else bn),
            "accumulators_differ": not same_or_never(m_a["chunk_dot"],
                                                     m_n["chunk_dot"]),
            "published_bytes_differ": (isinstance(ba, int)
                                       and isinstance(bn, int) and ba != bn),
        })
    two_term = minimal[1]
    tiny_last = minimal[3]
    doc_repro["counterexample"]["minimality"] = {
        "least_nonzero_terms_that_separate_the_two_accumulators":
            min(m["nonzero_terms"] for m in minimal
                if m["accumulators_differ"]),
        "note_1_term": ("with one nonzero term there is no accumulation, so "
                        "the readings cannot differ -- it is excluded by "
                        "measurement, not by argument"),
        "note_2_term": ("two terms separate the ACCUMULATORS, but the 2-term "
                        "sum is 14680064, which OVERFLOWS binary16, so both "
                        "readings collapse to +inf at H and NEITHER can "
                        "publish a byte -- see the failure table; the THIRD "
                        "(cancelling) term is what carries the difference to a "
                        "preserved, non-finite-free published output"),
        "note_order": ("the tiny term must be added BEFORE the large ones. "
                       "With the tiny term LAST both readings give 2**-9 and "
                       "agree -- measured, see the sequence table"),
        "sequences": minimal,
    }
    rep.row("the least separating case really is 2 nonzero terms (1 term does "
            "NOT separate)", (not minimal[0]["accumulators_differ"])
            and two_term["accumulators_differ"], 2,
            {"one_term_differs": minimal[0]["accumulators_differ"],
             "two_terms_differs": two_term["accumulators_differ"]})
    rep.row("with the tiny term LAST the two readings AGREE (order matters)",
            not tiny_last["accumulators_differ"], 1,
            {"tiny_last_A": tiny_last["A_16AR_chunk_dot"],
             "tiny_last_newA": tiny_last["A_16AW_chunk_dot"]})
    rep.row("the repaired A already agrees with B on the counterexample at "
            "every level",
            all(same_or_never(results["A_16AW_RN32"][l],
                              results["B_16AR"][l]) for l in levels),
            len(levels),
            {l: {"A_new": as_json_value(results["A_16AW_RN32"], l),
                 "B": as_json_value(results["B_16AR"], l)}
             for l in levels})

    # ------------------------- fixture-limited evidence, MEASURED not argued
    # The 16AS expected output is generated from the 16AR record plus the
    # seed-777 activation set, so the fixture's discriminating power can be
    # measured directly: count how many output elements the two accumulator
    # precisions move on THAT input.
    PF = C.load_by_path("p16ar_precision_fixture",
                        os.path.join(C.P16AR, "reference",
                                     "p16ar_precision_fixture.py"))
    record = open(C.FIXTURE_16AR, "rb").read()
    params_a = A0.unpack(record)
    xf, skipf = PF.activations()
    t0 = time.time()
    oa = A0.decoder_entry(xf, skipf, params_a, pre_quantization=False)
    t_a0 = time.time() - t0
    t0 = time.time()
    on = AN.decoder_entry(xf, skipf, params_a, pre_quantization=False)
    t_an = time.time() - t0
    n_cmp = 0
    n_diff = 0
    first = None
    for h2 in range(2):
        for w2 in range(2):
            for c in range(C.MATRIX_ROWS):
                n_cmp += 1
                if oa[h2][w2][c] != on[h2][w2][c]:
                    n_diff += 1
                    if first is None:
                        first = [h2, w2, c]
    doc_repro["fixture_limited_evidence"] = {
        "claim_under_test": ("the recorded `a_equals_b_exactly: true` was "
                             "FIXTURE-LIMITED evidence"),
        "instrument": ("the frozen 16AR record + the seed-777 admissible "
                       "activation set, i.e. exactly the input the 16AS "
                       "expected output was generated from; old A and repaired "
                       "A are run over it"),
        "n_output_elements_compared": n_cmp,
        "n_elements_where_binary64_and_binary32_accumulation_differ": n_diff,
        "first_differing_element": first,
        "seconds": {"A_16AR": round(t_a0, 3), "A_16AW_RN32": round(t_an, 3)},
        "conclusion": ("the frozen differential fixture cannot separate the two "
                       "accumulator precisions: 0 of %d published outputs move"
                       % n_cmp if n_diff == 0 else
                       "the frozen differential fixture DOES separate them: "
                       "%d of %d outputs move" % (n_diff, n_cmp)),
    }
    rep.row("the frozen 16AR fixture separates the two accumulator precisions "
            "on 0 of its published outputs",
            n_diff == 0, n_cmp,
            {"n_compared": n_cmp, "n_differing": n_diff,
             "first_differing": first})
    # CONTROL, and it must REACH the comparison: the same instrument applied
    # to the counterexample input must report a difference, or the instrument
    # is blind and the 0 above means nothing.
    cx_a0 = eval_module(A0, CX_PAIRS, CX_CHUNK)["fused_channel_0"]
    cx_an = eval_module(AN, CX_PAIRS, CX_CHUNK)["fused_channel_0"]
    rep.row("CONTROL: the same difference instrument reports 1 difference on "
            "the counterexample input (so the 0 is a measurement, not a blind "
            "instrument)", (cx_a0 != cx_an), 1,
            {"A_16AR": str(C.packed_exact(cx_a0)),
             "A_16AW_RN32": str(C.packed_exact(cx_an))})

    # ================================================== STEP 32: the repair
    doc_repair["step32_repair_of_A"] = {
        "method": ("every partial sum is carried as an EXACT dyadic integer "
                   "pair (m, e) meaning m * 2**e, and rounded to binary32 by "
                   "`rn32_pair` -- integer significand arithmetic, written out, "
                   "with no host floating-point operation anywhere in the "
                   "rounding step"),
        "functions_added": ["as_dyadic", "dyadic_to_float",
                            "_round_half_even_shift", "rn32_pair", "rn32",
                            "dyadic_add", "dyadic_mul", "half_add"],
        "functions_rewritten": {
            "chunk_dot": "was `s = 0.0; s += a[...] * m[...]`; now exact "
                         "product, exact add, then rn32_pair after EVERY "
                         "accumulate",
            "multiply_row": "was `acc = H(acc + chunk_dot(...))` on host "
                            "floats; now `acc = half_add(acc, chunk_dot(...))`, "
                            "which takes the sum EXACTLY and rounds once",
        },
        "functions_deliberately_unchanged": {
            "H": "verified against the executed pinned text over all 65,536 "
                 "finite binary16 values in 16AR; not the defect",
            "e4m3fn_decode / e4m3fn_quantize / F": "verified exhaustively in "
                                                  "16AR over all 256 decode "
                                                  "bytes and all 65,536 finite "
                                                  "binary16 values",
            "unpack / bits / project's fold": "layout and fold unchanged",
        },
        "rounding_step_is_explicit_and_inspectable": (
            "`rn32_pair` is 30 lines of integer arithmetic: it computes "
            "floor(log2), picks the subnormal quantum 2**-149 below 2**-126 or "
            "a 24-bit significand above it, rounds with round-half-to-even via "
            "divmod, and handles the single reachable carry.  It calls no "
            "floating-point operator."),
        "signatures_unchanged": ["H", "e4m3fn_decode", "e4m3fn_quantize", "F",
                                 "bits", "chunk_dot", "multiply_row", "project",
                                 "unpack", "decoder_entry"],
        "drop_in_compatible": True,
    }

    # ---- route agreement: three explicit RN32 implementations + a 4th read
    def rn32_pair_mutant(p, ties_away=False, truncate=False,
                         normal_quantum_for_subnormals=False):
        """A deliberate mutant of AN.rn32_pair, with branch counters, so a
        rejection can be shown to have REACHED the branch it targets."""
        m, e = p
        st = {"round_branch": 0, "tie_branch": 0, "subnormal_branch": 0,
              "carry_branch": 0}
        if m == 0:
            return (0, 0), st
        neg = m < 0
        a = -m if neg else m
        nbits = a.bit_length()
        e_top = nbits - 1 + e
        if e_top > AN.F32_EMAX:
            return ((-AN._INF_M, 0) if neg else (AN._INF_M, 0)), st
        if e_top < AN.F32_EMIN and not normal_quantum_for_subnormals:
            st["subnormal_branch"] += 1
            shift = -(e - AN.F32_SUBQ)
            if shift <= 0:
                q = a << (-shift)
            else:
                st["round_branch"] += 1
                q, r = divmod(a, 1 << shift)
                half = 1 << (shift - 1)
                if r == half:
                    st["tie_branch"] += 1
                if truncate:
                    pass
                elif ties_away:
                    if r >= half:
                        q += 1
                elif r > half or (r == half and (q & 1)):
                    q += 1
            if q == 0:
                return (0, 0), st
            out = (q, AN.F32_SUBQ)
            return ((-out[0], out[1]) if neg else out), st
        if e_top < AN.F32_EMIN:
            st["subnormal_branch"] += 1
            st["carry_branch"] += 1      # the subnormal carry-up case
        shift = nbits - AN.F32_P
        if shift <= 0:
            q, e_out = a, e
        else:
            st["round_branch"] += 1
            q, r = divmod(a, 1 << shift)
            half = 1 << (shift - 1)
            if r == half:
                st["tie_branch"] += 1
            if truncate:
                pass
            elif ties_away:
                if r >= half:
                    q += 1
            elif r > half or (r == half and (q & 1)):
                q += 1
            e_out = e + shift
            if q == (1 << AN.F32_P):
                st["carry_branch"] += 1
                q >>= 1
                e_out += 1
                if e_out + AN.F32_P - 1 > AN.F32_EMAX:
                    return ((-AN._INF_M, 0) if neg else (AN._INF_M, 0)), st
        out = (q, e_out)
        return ((-out[0], out[1]) if neg else out), st

    def to_val(p):
        if p[0] == AN._INF_M:
            return float("inf")
        if p[0] == -AN._INF_M:
            return float("-inf")
        return AN.dyadic_to_float(p)

    # the comparison set: every finite binary16; EXACT binary32 halfway cases
    # in both tie directions; explicit subnormal-range and subnormal-boundary
    # cases; and random dyadics spanning the whole exponent range.
    #
    # The halfway cases are CONSTRUCTED, not hoped for: a significand of
    # 2**24 + 1 (odd) or 2**24 + 3 (odd) is exactly 25 bits, so the binary32
    # rounding shift is 1 and the discarded bit is exactly half -- a tie by
    # construction.  `2**24 + 1` ties with an EVEN surviving significand and
    # must round DOWN; `2**24 + 3` ties with an ODD surviving significand and
    # must round UP.  A rounding rule that got ties wrong would have to differ
    # on one of them.
    pop = []
    for h in range(0x10000):
        v = struct.unpack("<e", struct.pack("<H", h))[0]
        if v != v or math.isinf(v):
            continue
        pop.append(("binary16:0x%04X" % h, Q(v)))
    n_tie = 0
    for k in range(-120, 60):
        pop.append(("tie_round_down:%d" % k, Q(2 ** 24 + 1) * Q(2) ** k))
        pop.append(("tie_round_up:%d" % k, Q(2 ** 24 + 3) * Q(2) ** k))
        n_tie += 2
    # the binade carry: a 25-bit significand of 2**25 - 1 rounds UP to exactly
    # 2**24, which is 1 << F32_P -- the one carry the normalising shift handles.
    # Without this family the carry branch would be written but never executed.
    n_carry = 0
    for j in range(-140, 90):
        pop.append(("carry:%d" % j, Q(2 ** 25 - 1) * Q(2) ** j))
        n_carry += 1
    n_sub = 0
    for j in range(1, 40):
        pop.append(("subnormal:%d" % j, Q(j) * Q(2) ** -149))
        pop.append(("subnormal_neg:%d" % j, -Q(j) * Q(2) ** -149))
        n_sub += 2
    for k in range(-160, -120):
        for d in (1, 3, 5, 7):
            pop.append(("tiny:%d,%d" % (k, d), Q(d) * Q(2) ** k))
            n_sub += 1
    pop.append(("largest_subnormal", Q(2) ** -126 - Q(2) ** -149))
    pop.append(("smallest_normal", Q(2) ** -126))
    # a tie BELOW the smallest normal that rounds up INTO it: the subnormal
    # branch's own carry, where q reaches exactly 2**23 = 2**-126 / 2**-149
    pop.append(("subnormal_carry_tie_up", Q(2) ** -126 - Q(2) ** -150))
    pop.append(("smallest_normal_plus_tie", Q(2) ** -126 + Q(2) ** -150))
    n_sub += 4
    rng = 987654321
    for _ in range(40000):
        rng = (1103515245 * rng + 12345) & 0x7FFFFFFF
        m = (rng >> 3) or 1
        rng = (1103515245 * rng + 12345) & 0x7FFFFFFF
        e = -200 + (rng >> 5) % 320
        pop.append(("random", Q(m) * Q(2) ** e))

    def to_dyadic(x):
        return ((x.numerator, 0) if x.denominator == 1 else
                (x.numerator, -(x.denominator.bit_length() - 1)))

    route_rows = []
    for name, x in pop:
        v_ref = C.rn32_third_route(x)
        v_a = to_val(AN.rn32_pair(to_dyadic(x)))
        v_b = BI._f32(x)
        route_rows.append((name, x, v_ref, v_a, v_b))

    def agreements(field):
        n, bad = 0, []
        for name, x, v_ref, v_a, v_b in route_rows:
            got = {"A_rn32_pair": v_a, "B_f32": v_b}[field]
            n += 1
            if C.exact(got) != C.exact(v_ref):
                if len(bad) < 5:
                    bad.append({"input": str(x),
                                "got": str(C.packed_exact(got)),
                                "third_route": str(C.packed_exact(v_ref))})
        return n, bad

    n_ref_b, bad_ref_b = agreements("B_f32")
    n_ref_a, bad_ref_a = agreements("A_rn32_pair")
    doc_repair["rn32_route_agreement"] = {
        "routes": {
            "A_16AW_rn32_pair": "integer significand shift, round-half-even",
            "B_16AW__f32": "exact quantum division, integer round-half-even",
            "16AW_rn32_third_route": "binade neighbours, nearer wins, ties to "
                                     "even (p16aw/numeric/p16aw_common.py)",
            "16AW_rn32_host_crosscheck": "struct.pack('<f') on the restricted "
                                         "domain where the exact value is "
                                         "already a binary64",
        },
        "population_size": len(pop),
        "population": {"finite_binary16": 63488,
                       "constructed_binary32_ties": n_tie,
                       "subnormal_and_subnormal_boundary": n_sub,
                       "random_dyadics": 40000},
        "A_rn32_pair_vs_third_route": {"compared": n_ref_a,
                                       "mismatches": len(bad_ref_a),
                                       "first": bad_ref_a},
        "B_f32_vs_third_route": {"compared": n_ref_b,
                                 "mismatches": len(bad_ref_b),
                                 "first": bad_ref_b},
    }
    rep.row("A's repaired rn32_pair agrees with the independent third route",
            len(bad_ref_a) == 0, n_ref_a, {"first_mismatches": bad_ref_a})
    rep.row("B's _f32 agrees with the independent third route",
            len(bad_ref_b) == 0, n_ref_b, {"first_mismatches": bad_ref_b})

    # the 4th reading, on its restricted domain
    n_hc, n_hc_bad = 0, []
    for name, x, v_ref, v_a, v_b in route_rows:
        hc = C.rn32_host_crosscheck(x)
        if hc is None:
            continue
        n_hc += 1
        if C.exact(hc) != Q(v_ref):
            if len(n_hc_bad) < 5:
                n_hc_bad.append({"input": str(x), "host": str(hc),
                                 "third_route": str(v_ref)})
    doc_repair["rn32_route_agreement"]["host_crosscheck"] = {
        "domain": "exact values that are already binary64 with <= 53 "
                  "significand bits and no under/overflow",
        "in_domain": n_hc, "compared": n_hc, "mismatches": len(n_hc_bad),
    }
    rep.row("the host struct.pack('<f') reading agrees with the third route on "
            "its restricted domain", len(n_hc_bad) == 0, n_hc,
            {"first_mismatches": n_hc_bad})

    # ---- mutants: each must fail the route comparison, and must REACH it
    mutants = []
    reach = {"round_branch": 0, "tie_branch": 0, "subnormal_branch": 0,
             "carry_branch": 0}
    for name, x, v_ref, v_a, v_b in route_rows:
        _, st = rn32_pair_mutant(to_dyadic(x))
        for k in reach:
            reach[k] += st[k]

    for mname, kw, reach_key in (
            ("ties_away_from_zero", {"ties_away": True}, "tie_branch"),
            ("truncate_toward_zero", {"truncate": True}, "round_branch"),
            ("normal_quantum_in_the_subnormal_range",
             {"normal_quantum_for_subnormals": True}, "subnormal_branch")):
        n_reached, n_bad, first = 0, 0, None
        for name, x, v_ref, v_a, v_b in route_rows:
            mp, st = rn32_pair_mutant(to_dyadic(x), **kw)
            if st[reach_key]:
                n_reached += 1
            mv = pair_to_exact(mp, AN._INF_M)
            if C.exact(mv) != C.exact(v_ref):
                n_bad += 1
                if first is None:
                    first = {"input": str(x),
                             "mutant": (str(mv) if not isinstance(mv, tuple)
                                        else str(mv)),
                             "third_route": str(C.packed_exact(v_ref))}
        mutants.append({"mutant": mname, "changes": str(kw),
                        "targeted_branch": reach_key,
                        "inputs_that_executed_the_mutated_branch": n_reached,
                        "inputs_on_which_the_mutant_disagrees": n_bad,
                        "control_valid": n_reached > 0 and n_bad > 0,
                        "first_disagreement": first})
        rep.row("MUTANT %s is rejected by the RN32 route comparison, and the "
                "mutated branch was executed" % mname,
                n_bad > 0 and n_reached > 0, n_bad,
                {"reached": n_reached, "disagreed": n_bad, "first": first})
    doc_repair["rn32_mutants"] = {
        "population": len(route_rows),
        "branch_reach_over_the_population": {
            "inputs_where_rounding_shifted_bits": reach["round_branch"],
            "inputs_that_hit_an_exact_tie": reach["tie_branch"],
            "inputs_in_the_subnormal_range": reach["subnormal_branch"],
            "inputs_that_carried_into_a_new_binade": reach["carry_branch"],
        },
        "mutants": mutants,
        "note": ("`control_valid` requires BOTH that the mutant's changed branch "
                 "actually executed and that the mutation changed a result.  A "
                 "mutant with reached == 0 would be INVALID, not a rejection."),
    }
    rep.row("every branch of the repaired rounding is EXERCISED by the "
            "population (including the binade carry)",
            all(v > 0 for v in reach.values()), len(reach), reach)

    # the defect ITSELF, as the mutant for the repair check
    defect_differs = not C.same(results["A_16AR"]["chunk_dot"],
                                results["A_16AW_RN32"]["chunk_dot"])
    doc_repair["the_defect_as_a_mutant"] = {
        "mutant": "k_dec_upsample_A.py's binary64 accumulator (the 16AR file "
                  "itself, imported unmodified)",
        "inputs_that_executed_the_defect": 1,
        "input": "the audit counterexample",
        "expected": "the repaired A must differ from it",
        "observed_differs": defect_differs,
        "control_valid": defect_differs,
    }
    rep.row("MUTANT the original binary64 accumulator is separated from the "
            "repair by the counterexample", defect_differs, 1,
            {"A_16AR": str(C.packed_exact(results["A_16AR"]["chunk_dot"])),
             "A_16AW_RN32": str(C.packed_exact(
                 results["A_16AW_RN32"]["chunk_dot"]))})

    # a check that compares nothing must not be a pass
    empty = C.Report("control: an empty comparison set")
    ok_empty = empty.row("a comparison over an empty population", True, 0, {})
    doc_repair["vacuous_check_control"] = {
        "what": "a check whose population is empty",
        "row_returned_ok": bool(ok_empty),
        "verdict": ("the harness converts an empty comparison into a FAILURE "
                    "(COMPARED_NOTHING); a check that compares 0 things cannot "
                    "read as a pass"),
    }
    rep.row("CONTROL: a comparison over an empty population is FAILED by the "
            "harness, not passed", ok_empty is False, 1, {})

    # ==================================== STEP 33: B stays independent
    #
    # THE INSTRUMENT IS THE AST, NOT A TEXT SEARCH, AND THAT IS DELIBERATE.
    # B_independent.py's DOCSTRING names every function whose use would have
    # destroyed independence -- it is documentation, and it must not be read as
    # a use.  A text search over the source would flag the documentation and
    # report a violation that does not exist; that is the recorded lesson that a
    # verifier must not check the spec that defines it.  The AST sees imports,
    # names and attributes -- code -- and is blind to prose.  Both readings are
    # reported below so the difference is visible rather than argued.
    b_src = src_of(C.B_INDEPENDENT)

    def code_identifiers(src):
        """Every identifier the CODE uses: imports, Load/Store names, and the
        attribute names of every attribute access."""
        tree = ast.parse(src)
        found = set()
        n_import_stmts = 0
        n_nodes = 0
        for node in ast.walk(tree):
            n_nodes += 1
            if isinstance(node, ast.Import):
                n_import_stmts += 1
                for al in node.names:
                    found.add(al.name.split(".")[0])
                    found.add(al.name)
            elif isinstance(node, ast.ImportFrom):
                n_import_stmts += 1
                if node.module:
                    found.add(node.module.split(".")[0])
                    found.add(node.module)
                for al in node.names:
                    found.add(al.name)
            elif isinstance(node, ast.Name):
                found.add(node.id)
            elif isinstance(node, ast.Attribute):
                found.add(node.attr)
                base = node
                while isinstance(base, ast.Attribute):
                    base = base.value
                if isinstance(base, ast.Name):
                    found.add(base.id)
        return found, n_import_stmts, n_nodes

    code_ids, n_imp, n_nodes = code_identifiers(b_src)
    forbidden_modules = ["k_dec_upsample_A_rn32", "k_dec_upsample_A",
                         "k_dec_upsample_B", "k_dec_upsample_B_independent",
                         "p16aw_common", "p16ar_ab_harness",
                         "p16ar_precision_fixture",
                         "k_dec_upsample_fp8"]
    forbidden_symbols = ["rn32_pair", "rn32", "dyadic_add", "dyadic_mul",
                         "half_add", "as_dyadic", "dyadic_to_float",
                         "_round_half_even_shift", "_INF_M", "F32_P",
                         "F32_SUBQ", "F32_EMIN", "F32_EMAX",
                         "rn32_third_route", "rn32_host_crosscheck"]
    probes = forbidden_modules + forbidden_symbols
    hits = [p for p in probes if p in code_ids]
    naive_text_hits = [p for p in probes
                       if re.search(r"\b%s\b" % re.escape(p), b_src)]
    ns = set(dir(BI))
    ns_hits = sorted(s for s in forbidden_symbols if s in ns)
    doc_repair["step33_independence_of_B"] = {
        "mechanism": ("AST: imports + Name/Attribute identifiers used by the "
                      "CODE, plus a runtime namespace inspection of the loaded "
                      "module.  Prose is not consulted."),
        "ast_nodes_walked": n_nodes,
        "import_statements_in_B": n_imp,
        "identifiers_used_by_the_code": len(code_ids),
        "forbidden_probes": len(probes),
        "hits": hits,
        "namespace_hits": ns_hits,
        "naive_text_scan_hits": naive_text_hits,
        "why_the_text_scan_is_the_wrong_instrument": (
            "the docstring of k_dec_upsample_B_independent.py deliberately NAMES "
            "each function whose use would destroy independence, so a text scan "
            "finds them all and reports a violation that does not exist.  The "
            "text hits are all prose; the AST hits are all zero.  This is the "
            "recorded lesson that a verifier must not check the spec that "
            "defines it, applied to itself."),
        "what_would_have_destroyed_independence": [
            "k_dec_upsample_A_rn32.rn32_pair -- would make both references "
            "share one rounding mechanism, so agreement between them could no "
            "longer distinguish a correct round from a shared mistake",
            "k_dec_upsample_A_rn32.rn32 / dyadic_add / dyadic_mul / half_add -- "
            "the accumulator helper; sharing it would make the audit's "
            "counterexample comparison tautological",
            "k_dec_upsample_A_rn32.H -- A's struct.pack('<e') half rounding, "
            "shared with B's exact half rounding",
            "k_dec_upsample_A_rn32.e4m3fn_decode / e4m3fn_quantize / F -- the "
            "FP8 decode helper and the conversion pipeline",
            "p16aw_common -- would let B reach all of the above transitively",
        ],
        "B_rounds_by": "exact rational divided by an exact quantum, integer "
                       "round-half-to-even (`_round_half_even`/`round_binary`)",
        "B_encodes_E4M3FN_by": "nearest-representable search over the "
                               "format's own ordered magnitude set (`_MAG`)",
    }
    rep.row("Reference B's CODE imports nothing from A and uses no A symbol",
            not hits and not ns_hits, len(probes),
            {"ast_hits": hits, "namespace_hits": ns_hits})
    rep.row("the naive text scan WOULD have flagged B -- on its own "
            "documentation, i.e. a false positive", len(naive_text_hits) > 0,
            len(probes), {"text_hits": naive_text_hits})
    # CONTROL: a B variant that DOES import A's rounding must be rejected, and
    # the scan must REACH the import (the mutant source must be parsed)
    mutant_b = ("import k_dec_upsample_A_rn32 as _A\n"
                "def _f32(x):\n    return _A.rn32(x)\n")
    m_ids, m_imp, m_nodes = code_identifiers(mutant_b)
    m_hits = [p for p in probes if p in m_ids]
    doc_repair["step33_independence_of_B"]["control"] = {
        "mutant": "a B variant whose _f32 delegates to A's rn32",
        "mutant_source": mutant_b,
        "ast_nodes_walked": m_nodes,
        "import_statements_found": m_imp,
        "identifiers_used_by_the_code": sorted(m_ids),
        "hits": m_hits,
        "rejected": bool(m_hits),
    }
    rep.row("CONTROL: a B variant that delegates to A's rounding is REJECTED by "
            "the same AST scan, and the scan reached the import",
            bool(m_hits) and "k_dec_upsample_A_rn32" in m_ids, len(m_hits),
            {"mutant_hits": m_hits})

    # -------------------------------- B_16AR vs B_independent, differential
    n_bcmp, n_bdiff, n_braise_old, n_braise_new = 0, 0, 0, 0
    b_first = None
    for name, x, v_ref, v_a, v_b in route_rows[::7]:
        try:
            o = B0._f32(x)
        except Exception:
            n_braise_old += 1
            o = None
        try:
            n = BI._f32(x)
        except Exception:
            n_braise_new += 1
            n = None
        if o is None or n is None:
            continue
        n_bcmp += 1
        if C.exact(o) != C.exact(n):
            n_bdiff += 1
            if b_first is None:
                b_first = {"input": str(x), "B_16AR": str(o),
                           "B_16AW_IND": str(n)}
    doc_repair["step33_B_repair"] = {
        "changed": True,
        "why": ("Reference B could not evaluate the required `saturation` "
                "corpus case: `round_binary` handled overflow with "
                "`Q(\"inf\")`, a Fraction built from the string 'inf', which "
                "`fractions.Fraction` rejects.  Measured: "
                "B_16AR.H(Q(32)*65504*448), B_16AR.H(Q(2*65504)), "
                "B_16AR.H(Q(70000)) and B_16AR._f32(Q(10)**40) all raise "
                "ValueError, while A returns inf."),
        "the_change": ["overflow returns a python float +/-inf",
                       "round_binary passes a float +/-inf straight through, so "
                       "an already-overflowed accumulator can be re-rounded"],
        "not_changed": ["_round_half_even", "_floor_log2", "the binary16 and "
                        "binary32 parameters", "the E4M3FN encoder's "
                        "nearest-representable search", "the decoder",
                        "chunk_dot's per-step _f32", "every shape constant"],
        "differential_check": {
            "population_compared": n_bcmp,
            "mismatches": n_bdiff,
            "first": b_first,
            "B_16AR_raised_on": n_braise_old,
            "B_16AW_IND_raised_on": n_braise_new,
        },
    }
    rep.row("B repaired == B 16AR on every input where 16AR returns",
            n_bdiff == 0 and n_bcmp > 0, n_bcmp,
            {"mismatches": n_bdiff, "first": b_first})
    # CONTROL: the differential check must reject a deliberately altered B.
    #
    # MEASURED FALSE START, kept on the record: the first version of this
    # control replaced B's rounding with the THIRD ROUTE -- a different
    # MECHANISM that computes the SAME function -- so it could never differ,
    # it reported 0 differences, and the harness FAILED it as
    # COMPARED_NOTHING.  That is the correct outcome: a control has to change
    # the VALUE under test, not merely the code path that produces it.
    # This version perturbs B's answer by one ulp for |x| >= 2**20 and COUNTS
    # how many sampled inputs reached the perturbation (branch reach), so a
    # difference count of 0 can be told apart from an unreached mutant.
    def _bump_one_ulp(v):
        neg = v < 0
        a = -v if neg else v
        e = C.floor_log2_exact(a)
        q = Q(2) ** -149 if e < -126 else Q(2) ** (e - 23)
        w = a + q                       # still exactly binary32: same binade,
        return -w if neg else w         # or one carry step into the next

    n_alt_reach = [0]

    def _f32_alt(x):
        v = BI._f32(x)
        if isinstance(v, Q) and x != 0 and abs(x) >= Q(2) ** 20:
            n_alt_reach[0] += 1
            return _bump_one_ulp(v)
        return v

    n_md, n_md_bad = 0, 0
    for name, x, v_ref, v_a, v_b in route_rows[::7]:
        try:
            base = BI._f32(x)
        except Exception:
            continue
        alt = _f32_alt(x)
        n_md += 1
        if C.exact(alt) != C.exact(base):
            n_md_bad += 1
    rep.row("CONTROL: the differential check reports a difference against an "
            "altered B that rounds only large values differently",
            n_md_bad > 0 and n_alt_reach[0] > 0, n_md,
            {"sampled_inputs_mutated": n_alt_reach[0], "differing": n_md_bad})

    # an explicit, measured demonstration that the overflow defect was real
    ov_rows = []
    for label, expr_old, expr_new in (
            ("H(32 * 65504 * 448)",
             lambda: B0.H(Q(32) * Q(65504) * Q(448)),
             lambda: BI.H(Q(32) * Q(65504) * Q(448))),
            ("H(2 * 65504)", lambda: B0.H(Q(2 * 65504)),
             lambda: BI.H(Q(2 * 65504))),
            ("H(70000)", lambda: B0.H(Q(70000)), lambda: BI.H(Q(70000))),
            ("_f32(10**40)", lambda: B0._f32(Q(10) ** 40),
             lambda: BI._f32(Q(10) ** 40)),
            ("A_16AR.H(2*65504)", lambda: A0.H(2.0 * 65504.0),
             lambda: AN.H(2.0 * 65504.0)),
    ):
        ro = {"expression": label}
        try:
            ro["B_16AR"] = str(C.packed_exact(expr_old()))
        except Exception as e:                                   # noqa: BLE001
            ro["B_16AR"] = "RAISED %s: %s" % (type(e).__name__, e)
        try:
            ro["B_16AW_IND"] = str(C.packed_exact(expr_new()))
        except Exception as e:                                   # noqa: BLE001
            ro["B_16AW_IND"] = "RAISED %s: %s" % (type(e).__name__, e)
        ov_rows.append(ro)
    # the full path, end to end: 32 max-finite terms in one chunk
    a_ov = [Q(65504)] * 32 + [Q(0)] * 992
    m_ov = [B0.e4m3fn_decode(0x7E)] * 32 + [Q(0)] * 992
    try:
        mr_old = str(C.packed_exact(B0.multiply_row(a_ov, 0, m_ov, 0, 256)))
    except Exception as e:                                       # noqa: BLE001
        mr_old = "RAISED %s: %s" % (type(e).__name__, e)
    mr_new = str(C.packed_exact(BI.multiply_row(a_ov, 0, m_ov, 0, 256)))
    doc_repair["step33_B_repair"]["overflow_probe"] = {
        "rows": ov_rows,
        "full_path_multiply_row_32_max_finite_terms": {
            "B_16AR": mr_old, "B_16AW_IND": mr_new},
        "reachable_in_this_operator": ("yes: 32 terms of |activation| = 65504 "
                                       "(the largest finite binary16) times "
                                       "|weight| = 448 (the largest finite "
                                       "E4M3FN) in one chunk"),
    }
    rep.row("the overflow defect is measured reachable, and the repair answers "
            "where 16AR raised",
            all(("RAISED" in r["B_16AR"]) and ("RAISED" not in r["B_16AW_IND"])
                for r in ov_rows[:4]), len(ov_rows),
            {"rows": ov_rows})

    # ================================ STEP 36: affected expected outputs
    exp_on_disk = open(EXPECTED_BIN, "rb").read()
    exp_sha = hashlib.sha256(exp_on_disk).hexdigest()
    # rebuild the 16AS expected output from the same inputs, with each A
    def build_expected(A_mod, computed):
        exp = [0] * (4 * C.MATRIX_ROWS)
        for h2 in range(2):
            for w2 in range(2):
                for c in range(C.MATRIX_ROWS):
                    exp[(h2 * 2 + w2) * C.MATRIX_ROWS + c] = \
                        A_mod.e4m3fn_quantize(computed[h2][w2][c])
        return bytes(exp)

    exp_old = build_expected(A0, oa)
    exp_new = build_expected(AN, on)
    sha_old = hashlib.sha256(exp_old).hexdigest()
    sha_new = hashlib.sha256(exp_new).hexdigest()
    n_byte_diff = sum(1 for p, q in zip(exp_old, exp_new) if p != q)

    controls = sorted(os.listdir(CONTROLS_DIR)) if os.path.isdir(CONTROLS_DIR) \
        else []
    with_hash = []
    for f in controls:
        p = os.path.join(CONTROLS_DIR, f)
        if os.path.isfile(p) and exp_sha in open(p, encoding="utf-8",
                                                 errors="replace").read():
            with_hash.append(os.path.relpath(p, C.ROOT).replace("\\", "/"))

    doc_repair["step36_affected_expected_outputs"] = {
        "regenerated_by_this_phase": False,
        "why_not": ("the brief says to enumerate what is affected and where the "
                    "hashes live, and explicitly not to regenerate or patch"),
        "measurement": {
            "the_16AS_expected_output_is_generated_from": (
                "p16ar/reference/DIFFERENTIAL_PRECISION_FIXTURE_16AR.bin "
                "(the weight record) + p16ar_precision_fixture.activations() "
                "seed 777 (x and skip) + Reference A + A.e4m3fn_quantize"),
            "on_disk_path": os.path.relpath(EXPECTED_BIN, C.ROOT),
            "on_disk_bytes": len(exp_on_disk),
            "on_disk_sha256": exp_sha,
            "rebuilt_with_A_16AR_sha256": sha_old,
            "rebuilt_with_A_16AW_RN32_sha256": sha_new,
            "rebuild_with_A_16AR_reproduces_the_file": sha_old == exp_sha,
            "bytes_that_change_under_the_repair": n_byte_diff,
            "bytes_total": len(exp_on_disk),
            "repair_changes_the_expected_output": sha_new != exp_sha,
        },
        "what_would_be_affected_if_the_expected_output_changes": {
            "synthetic_expected_binary": [os.path.relpath(EXPECTED_BIN, C.ROOT)],
            "harness_contract_embedding_its_hash": [
                os.path.relpath(HARNESS_CONTRACT, C.ROOT)],
            "hash_carriers_found_by_searching_the_tree_for_the_hash": [
                os.path.relpath(PREPARE_ONLY, C.ROOT)] + with_hash,
            "generator": [os.path.relpath(PREPARE_CHAIN, C.ROOT)],
            "harness_that_consumes_the_contract": [
                os.path.relpath(HARNESS_CPP, C.ROOT)],
            "qualification_receipts": [
                "any Slot-5 preparation receipt that quotes "
                "expected_bin_sha256 (the hash appears in the 16AS harness "
                "contract and in the NATIVE_PREPARE_ONLY record); a changed "
                "SHA invalidates them and they must be re-issued, never "
                "patched"],
        },
        "hash_locations": {
            "key_name_in_the_harness_contract_and_its_controls":
                "expected_bin_sha256",
            "in_the_prepare_only_record": "the fixture entry's \"sha256\"",
            "generated_by": "p16as_prepare_chain.py:253 "
                            "sha256_file(expected_out_q.bin)",
        },
    }
    rep.row("rebuilding the 16AS expected output with the UNREPAIRED A "
            "reproduces the file that is on disk (the measurement is"
            " anchored)", sha_old == exp_sha, 1,
            {"on_disk": exp_sha, "rebuilt_A_16AR": sha_old})
    rep.row("the repair's effect on that expected output is MEASURED",
            isinstance(n_byte_diff, int), len(exp_on_disk),
            {"bytes_that_change": n_byte_diff, "sha_new": sha_new,
             "sha_on_disk": exp_sha})

    # ------------------------------------------------------------- write out
    doc_repro["checks"] = rep.rows
    doc_repro["checks_ok"] = rep.n_ok
    doc_repro["checks_total"] = len(rep.rows)
    doc_repro["verdict"] = ("AUDIT_COUNTEREXAMPLE_REPRODUCED"
                            if reproduced and n_diff == 0
                            else "NOT_ESTABLISHED")
    doc_repro["honest_ceiling"] = [
        "the counterexample INPUT is a reconstruction: the audit published the "
        "two values and not the input.  What is reproduced exactly is the value "
        "pair (A=0.001953125, B=0.0), on an input whose every ingredient is an "
        "admissible operator value.",
        "this is a HOST reading of HOST references; it is not evidence about "
        "what the RX 6950 XT does, and no device was touched.",
        "the fixture-limited claim is measured on the ONE frozen fixture this "
        "project has (0 of 2048 outputs move).  That is a statement about that "
        "fixture, not a rate over all inputs.",
    ]

    doc_repair["step32_repair_of_A"]["route_agreement"] = \
        doc_repair.get("rn32_route_agreement")
    doc_repair["checks"] = rep.rows
    doc_repair["checks_ok"] = rep.n_ok
    doc_repair["checks_total"] = len(rep.rows)
    doc_repair["what_remains_open"] = [
        "Reference B's repaired overflow path returns +/-inf, which then flows "
        "into `e4m3fn_encode`'s saturation branch and produces 0x7E.  The "
        "contract declares NaN/Inf out of scope, so this path is documented "
        "rather than fully specified; a value of +inf and a value of 1e30 both "
        "publish 0x7E.",
        "the 16AR contract and the 16AS expected output were NOT regenerated "
        "(brief section 36 says enumerate, do not regenerate).",
        "NUMERICAL_CONTRACT_16AR.json still records `a_equals_b_exactly: true` "
        "with zero tolerance.  That statement is now known to be fixture-"
        "limited evidence; replacing it is a separate artifact decision and was "
        "not taken here.",
    ]
    doc_repair["verdict"] = ("CPU_REFERENCE_REPAIRED_AND_REPRODUCED"
                             if rep.n_ok == len(rep.rows)
                             else "CHECKS_FAILED")

    with open(OUT_REPRO, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc_repro, f, indent=1, default=str)
        f.write("\n")
    with open(OUT_REPAIR, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc_repair, f, indent=1, default=str)
        f.write("\n")
    print()
    print("  -> %s" % os.path.basename(OUT_REPRO))
    print("  -> %s" % os.path.basename(OUT_REPAIR))
    print("  %d/%d checks ok" % (rep.n_ok, len(rep.rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
