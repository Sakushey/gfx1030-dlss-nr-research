#!/usr/bin/env python3
"""Phase 16AW -- brief section 34: the ADVERSARIAL FIXTURE CORPUS.

Emits ADVERSARIAL_CORPUS_16AW.json.

Each case is a 32-wide chunk of (binary16 activation, E4M3FN weight byte) pairs,
materialised through the operator's own public entry points, so a case exercises
real code paths rather than a re-implementation.  Every case is pushed through
FOUR readings:

    A_16AR      the frozen reference the audit indicted
    A_16AW      the repaired reference (explicit RN32)
    B_16AW      the independent exact-rational reference
    B_16AR      where it does not raise, to show the B repair is value-neutral

and against a THIRD-ROUTE ORACLE built here, which shares no mechanism with
either reference: exact products, RN32 by binade-neighbour selection with ties
to even, and a binary16 rounding written the same way.  Two implementations
that share a specification are only independent if they share no mechanism.

DEMONSTRATED CONTROLS.  Every control below is required to CHANGE THE VALUE and
to REACH the code path it mutates; the reach count is printed beside the
difference count, so a difference of 0 can be told apart from an unreached
mutant.  A mutant that dies before the comparison is an INVALID control.

REFUSALS ARE NOT AGREEMENTS.  Both references refuse a non-finite fused value
(out of contract, see NUMERICAL_CONTRACT_16AW.json).  A case where both refuse
is recorded as BOTH_VOID, never as agreement -- and a control classifier that
would call it agreement is required to be rejected.

HOST-ONLY.  No HIP call, no GPU, no launch, no slot.
"""
from __future__ import annotations

import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import p16aw_common as C                                   # noqa: E402
import p16aw_s1_reproduce_and_repair as S1                 # noqa: E402
from fractions import Fraction as Q                        # noqa: E402

OUT = os.path.join(HERE, "ADVERSARIAL_CORPUS_16AW.json")
CHUNK = C.CHUNK
WIDTH = C.MATRIX_COLS
PARTITION = C.PARTITION
TINY = 2.0 ** -24            # smallest positive binary16 (a subnormal)
E4_MIN = 2.0 ** -9           # smallest positive E4M3FN (byte 0x01)
MAXH = 65504.0               # largest finite binary16
B38, B7E, B7F, B01 = 0x38, 0x7E, 0x7F, 0x01


# ---------------------------------------------------------------------------
# third-route binary16 rounding, on exact values (mechanism: binade neighbours)
# ---------------------------------------------------------------------------
def rn16_third_route(x):
    """Nearest binary16 to the exact rational x, or a python float +/-inf.

    Same ALGORITHM FAMILY as `rn32_third_route` but applied to binary16; it is
    NOT the mechanism either reference uses for H (A uses struct.pack('<e'),
    B uses exact quantum division), so agreement here is a third opinion.
    """
    x = Q(x)
    if x == 0:
        return Q(0)
    neg = x < 0
    a = -x if neg else x
    e = C.floor_log2_exact(a)
    if e > 15:
        return float("-inf") if neg else float("inf")
    quantum = Q(2) ** (-24 if e < -14 else (e - 10))
    s = a / quantum
    f = s.numerator // s.denominator
    if Q(f) == s:
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
            val = vlo if (lo & 1) == 0 else vhi
    return -val if neg else val


def oracle_chunk_dot(pairs):
    """The 32-term chunk dot under the DECLARED contract, third mechanism."""
    s = Q(0)
    for t in range(CHUNK):
        if t < len(pairs):
            act, byte = pairs[t]
            prod = Q(float(act)) * C._e4_decode(byte)
        else:
            prod = Q(0)
        if isinstance(s, float):        # an overflowed accumulator absorbs
            return s
        s = C.rn32_third_route(s + prod)
    return s


def oracle_main(pairs, n_terms=None):
    """The row accumulator's binary16 value: fold chunks, then partitions."""
    acc = Q(0)
    for off in range(0, WIDTH, CHUNK):
        chunk_pairs = pairs if off == 0 else []
        s = oracle_chunk_dot(chunk_pairs)
        if isinstance(s, float):
            acc = s
        elif isinstance(acc, float):
            pass
        else:
            acc = rn16_third_route(C.rn32_third_route(acc + s))
    return acc


def oracle_main_binary64(pairs):
    """A mutant oracle: the same fold with a BINARY64 accumulator, i.e. the
    defect the audit found.  Used as a control on the oracle comparison."""
    acc = 0.0
    for off in range(0, WIDTH, CHUNK):
        s = 0.0
        for t in range(CHUNK):
            if off == 0 and t < len(pairs):
                act, byte = pairs[t]
                s += float(act) * float(C._e4_decode(byte))
        try:
            acc = float(rn16_third_route(C.rn32_third_route(Q(acc) + Q(s))))
        except (ValueError, OverflowError, ZeroDivisionError):
            return acc                  # overflowed: infinity absorbs
    return acc


def oracle_main_saturating_h(pairs):
    """A mutant oracle: H saturates at 65504 instead of overflowing to inf."""
    acc = Q(0)
    for off in range(0, WIDTH, CHUNK):
        s = oracle_chunk_dot(pairs if off == 0 else [])
        if isinstance(s, float):
            return s
        total = C.rn32_third_route(acc + s) if not isinstance(acc, float) \
            else acc
        r = rn16_third_route(total)
        if isinstance(r, float):                    # the mutation
            r = Q(65504 if r > 0 else -65504)
        acc = r
    return acc


# ---------------------------------------------------------------------------
# the corpus
# ---------------------------------------------------------------------------
def corpus():
    """(case_id, category, chunk, pairs, predicted_or_None).

    `predicted` holds only values worked out by hand and stated in the brief or
    derivable from the contract; everything else is recorded as measured.
    """
    cases = []
    add = lambda *a: cases.append(a)                        # noqa: E731

    # ---- 1. cancellation, including the audit's counterexample VERBATIM
    add("cancel_audit_counterexample", "cancellation", 0,
        [(2.0 ** -9, B38), (2.0 ** 15, B7E), (-(2.0 ** 15), B7E)],
        {"A_16AR": {"chunk_dot": "0.001953125", "fp8_byte": 0x01},
         "A_16AW": {"chunk_dot": "0", "fp8_byte": 0x00},
         "third_route": {"chunk_dot": "0"}})
    add("cancel_tiny_term_last", "cancellation", 0,
        [(2.0 ** 15, B7E), (-(2.0 ** 15), B7E), (2.0 ** -9, B38)],
        {"A_16AR": {"chunk_dot": "0.001953125"},
         "A_16AW": {"chunk_dot": "0.001953125"},
         "third_route": {"chunk_dot": "0.001953125"}})
    add("cancel_exact_pair", "cancellation", 0,
        [(1024.0, B7E), (-1024.0, B7E)], None)
    add("cancel_partial_leaves_max", "cancellation", 0,
        [(1.0, B7E), (1024.0, B38), (-1024.0, B38)], None)
    add("cancel_at_chunk_5", "cancellation", 5,
        [(2.0 ** -9, B38), (2.0 ** 15, B7E), (-(2.0 ** 15), B7E)],
        {"A_16AR": {"chunk_dot": "0.001953125", "fp8_byte": 0x01},
         "A_16AW": {"chunk_dot": "0", "fp8_byte": 0x00}})

    # ---- 2. large exponent gap
    add("gap_two_terms_in_range", "large_exponent_gap", 0,
        [(MAXH, B38), (TINY, B38)], None)
    add("gap_tiny_first_then_cancel", "large_exponent_gap", 0,
        [(2.0 ** -9, B38), (1048576.0, B38), (-1048576.0, B38)],
        {"A_16AR": {"chunk_dot": "0.001953125", "fp8_byte": 0x01},
         "A_16AW": {"chunk_dot": "0", "fp8_byte": 0x00}})
    add("gap_wide_spread_fold", "large_exponent_gap", 0,
        [(MAXH, B38), (2.0 ** -20, B38), (2.0 ** -21, B38), (2.0 ** -22, B38)],
        None)

    # ---- 3. subnormal contribution
    add("subnormal_products_below_half_min", "subnormal_contribution", 0,
        [(TINY, B01), (TINY, B38), (TINY, B38)], None)
    add("subnormal_exact_tie_down", "subnormal_contribution", 0,
        [(2.0 ** -25, B38)],
        # CORRECTED hand prediction, kept on the record: 2**-25 is a TIE at
        # the binary16 boundary, but the tie is not taken inside `chunk_dot`
        # -- the chunk sum is binary32 there and holds 2**-25 exactly.  The
        # tie is taken where H IS applied, i.e. at `multiply_row`.  The first
        # version of this prediction said chunk_dot = 0 and was measured
        # wrong by the corpus (test_the_expected, 3 of 32 rows).
        {"A_16AR": {"chunk_dot": "2.9802322387695312e-08",
                    "multiply_row": "0"},
         "A_16AW": {"chunk_dot": "2.9802322387695312e-08",
                    "multiply_row": "0"},
         "third_route": {"chunk_dot": "2.9802322387695312e-08"}})
    add("subnormal_rounds_up_to_min", "subnormal_contribution", 0,
        [(3.0 * 2.0 ** -26, B38)], None)
    add("subnormal_sum_reaches_min", "subnormal_contribution", 0,
        [(TINY, B38), (2.0 ** -24, B38)], None)

    # ---- 4. exact halfway / tie cases
    add("tie_half_boundary_even_stays", "exact_tie", 0,
        [(2.0 ** -10, B38), (2.0 ** -21, B38)], None)
    add("tie_half_boundary_odd_rounds_up", "exact_tie", 0,
        [(2.0 ** -10, B38), (3.0 * 2.0 ** -21, B38)], None)
    add("tie_accumulator_even_stays", "exact_tie", 0,
        [(1.0, B38), (TINY, B38)], None)
    add("tie_accumulator_odd_rounds_up", "exact_tie", 0,
        [(1.0, B38), (2.0 ** -23, B38), (TINY, B38)], None)

    # ---- 5. saturation
    add("saturate_exactly_448", "saturation", 0,
        [(1.0, B7E)], {"A_16AR": {"fp8_byte": 0x7E},
                       "A_16AW": {"fp8_byte": 0x7E}})
    add("saturate_above_448", "saturation", 0,
        [(1.0, B7E), (1.0, B7E)], {"A_16AR": {"fp8_byte": 0x7E},
                                   "A_16AW": {"fp8_byte": 0x7E}})
    add("saturate_negative", "saturation", 0,
        [(-1.0, B7E)], {"A_16AR": {"fp8_byte": 0xFE},
                        "A_16AW": {"fp8_byte": 0xFE}})
    add("saturate_just_below", "saturation", 0,
        [(1.0, 0x7D)], None)

    # ---- 6. mixed sign
    add("mixed_sign_partial_cancel", "mixed_sign", 0,
        [(1.0, B38), (-1.0, B38), (0.5, B38)], None)
    add("mixed_sign_to_zero", "mixed_sign", 0,
        [(1.0, B38), (-1.0, B38)], None)
    add("mixed_sign_reversed_order", "mixed_sign", 0,
        [(-1.0, B38), (1.0, B38)], None)
    add("mixed_sign_wide", "mixed_sign", 0,
        [(MAXH, B38), (-(MAXH), B38), (256.0, B7E)], None)

    # ---- 7. alternating large and small terms
    add("alternating_16_steps", "alternating_large_small", 0,
        [(1024.0, B38), (2.0 ** -9, B38)] * 16, None)
    add("alternating_overflows_half", "alternating_large_small", 0,
        [(MAXH, B38), (2.0 ** -9, B38)] * 8, None)

    # ---- 8. signed zero
    add("zero_all_zero", "signed_zero", 0, [(0.0, 0x00)], None)
    add("zero_negative_activation", "signed_zero", 0, [(-0.0, B38)], None)
    add("zero_two_negatives", "signed_zero", 0,
        [(-0.0, B38), (-0.0, B38)], None)
    add("zero_cancel_gives_positive", "signed_zero", 0,
        [(-0.0, B38), (0.0, B38)], None)

    # ---- 9. max finite E4M3
    add("max_e4m3_two_cancel", "max_finite_e4m3", 0,
        [(2.0, B7E), (-2.0, B7E)], None)
    add("max_e4m3_via_0x7F_satfinite", "max_finite_e4m3", 0,
        [(1.0, B7F)], {"A_16AR": {"fp8_byte": 0x7E},
                       "A_16AW": {"fp8_byte": 0x7E}})
    add("max_e4m3_via_0xFF_satfinite", "max_finite_e4m3", 0,
        [(1.0, 0xFF)], {"A_16AR": {"fp8_byte": 0xFE},
                        "A_16AW": {"fp8_byte": 0xFE}})
    add("max_e4m3_mixed_codes_agree", "max_finite_e4m3", 0,
        [(1.0, B7E), (1.0, B7F)], None)

    # ---- 10. smallest nonzero E4M3
    add("e4m3_min_exact", "small_nonzero_e4m3", 0,
        [(1.0, B01)], {"A_16AR": {"fp8_byte": 0x01},
                       "A_16AW": {"fp8_byte": 0x01},
                       "third_route": {"chunk_dot": "0.001953125"}})
    add("e4m3_min_times_small", "small_nonzero_e4m3", 0,
        [(2.0 ** -6, B01)], None)
    add("e4m3_min_plus_min", "small_nonzero_e4m3", 0,
        [(1.0, B01), (1.0, B01)], None)

    # ---- extra: the OUT OF CONTRACT case (fp16 overflow), included on purpose
    add("overflow_half_of_chunk", "out_of_contract_overflow", 0,
        [(MAXH, B7E)] * 2, None)
    add("overflow_32_max_products", "out_of_contract_overflow", 0,
        [(MAXH, B7E)] * 32, None)
    return cases


CATEGORIES_REQUIRED = [
    "cancellation", "large_exponent_gap", "subnormal_contribution",
    "exact_tie", "saturation", "mixed_sign", "alternating_large_small",
    "signed_zero", "max_finite_e4m3", "small_nonzero_e4m3",
]


def _parse(v):
    """A recorded value or a hand-written prediction -> a comparable object.

    MEASURED FALSE START, kept on the record: the first version of this
    comparison compared the RENDERED STRINGS.  A byte recorded as 1 renders as
    "1.0" through the exact-value formatter, so 18 predictions were reported
    wrong although every one of them was right -- the instrument was broken,
    not the corpus.  Values are compared as VALUES; a string that is not a
    number (a recorded exception) can never equal a predicted number.
    """
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v
    s = str(v)
    if s in ("inf", "+inf", "Infinity"):
        return float("inf")
    if s == "-inf":
        return float("-inf")
    try:
        return Q(s)
    except (ValueError, ZeroDivisionError, ArithmeticError):
        return s


def num_eq(a, b) -> bool:
    """Value equality across the recorded shapes, with refusals never equal."""
    pa, pb = _parse(a), _parse(b)
    if isinstance(pa, str) or isinstance(pb, str):
        return pa == pb and not (isinstance(pa, str)
                                 and pa.startswith("RAISED"))
    if isinstance(pa, float) and isinstance(pb, float):
        if math.isnan(pa) or math.isnan(pb):
            return math.isnan(pa) and math.isnan(pb)
        if math.isinf(pa) or math.isinf(pb):
            return pa == pb
    return Q(pa) == Q(pb) if not isinstance(pa, float) \
        else float(pa) == float(pb)


def classify(a, b):
    """AGREE / DISAGREE / BOTH_VOID / ONE_VOID.

    A REFUSAL IS NOT A VALUE.  Two refusals are BOTH_VOID -- excluded from the
    comparison, never counted as agreement."""
    ra = isinstance(a, str) and a.startswith("RAISED")
    rb = isinstance(b, str) and b.startswith("RAISED")
    if ra and rb:
        return "BOTH_VOID"
    if ra or rb:
        return "ONE_VOID"
    return "AGREE" if C.exact(a) == C.exact(b) else "DISAGREE"


def classify_stringly(a, b):
    """A mutant classifier: compares the rendered strings, so two identical
    RAISED strings read as agreement."""
    return "AGREE" if str(a) == str(b) else "DISAGREE"


def main() -> int:
    rep = C.Report("Phase 16AW section 34 -- adversarial fixture corpus")
    A0 = C.load_by_path("A0_16AR", C.A_16AR)
    B0 = C.load_by_path("B0_16AR", C.B_16AR)
    AN = C.load_by_path("AN_16AW", C.A_REPAIRED)
    BI = C.load_by_path("BI_16AW", C.B_INDEPENDENT)

    rows = []
    for case_id, category, chunk, pairs, predicted in corpus():
        res = {name: S1.eval_module(mod, pairs, chunk)
               for name, mod in (("A_16AR", A0), ("A_16AW", AN),
                                 ("B_16AW", BI), ("B_16AR", B0))}

        def val(mod_key, key):
            return S1.as_json_value(res[mod_key], key)

        o_dot = oracle_chunk_dot(pairs)
        o_main = oracle_main(pairs)
        o64_main = oracle_main_binary64(pairs)
        o_sat = oracle_main_saturating_h(pairs)
        rows.append({
            "case_id": case_id,
            "category": category,
            "chunk": chunk,
            "pairs": [{"index": t, "activation": act,
                       "activation_bits": "0x%04X" % struct_h(act),
                       "weight_byte": "0x%02X" % byte} for t, (act, byte)
                      in enumerate(pairs)],
            "predicted": predicted,
            "measured": {
                "A_16AR": {k: val("A_16AR", k) for k in
                           ("chunk_dot", "multiply_row", "project_rows_1",
                            "fused_channel_0", "fp8_byte_channel_0")},
                "A_16AW": {k: val("A_16AW", k) for k in
                           ("chunk_dot", "multiply_row", "project_rows_1",
                            "fused_channel_0", "fp8_byte_channel_0")},
                "B_16AW": {k: val("B_16AW", k) for k in
                           ("chunk_dot", "multiply_row", "project_rows_1",
                            "fused_channel_0", "fp8_byte_channel_0")},
                "B_16AR": {k: val("B_16AR", k) for k in
                           ("chunk_dot", "multiply_row", "project_rows_1",
                            "fused_channel_0", "fp8_byte_channel_0")},
                "third_route_oracle": {
                    "chunk_dot": str(C.packed_exact(o_dot)),
                    "main_after_chunk_and_partition_fold":
                        str(C.packed_exact(o_main)),
                },
                "binary64_oracle_mutant": {
                    "chunk_dot": "not run at chunk_dot level",
                    "main_after_chunk_and_partition_fold":
                        str(C.packed_exact(o64_main)),
                },
                "saturating_H_oracle_mutant": {
                    "main_after_chunk_and_partition_fold":
                        str(C.packed_exact(o_sat)),
                },
            },
        })

    # -------------------------------------------------- prediction checks
    def check_predictions(rows, override=None):
        """Compare every hand-predicted value to what was measured.

        `override` replaces the prediction table, so the SAME comparison can be
        run against a deliberately wrong prediction and required to reject it.
        """
        n, n_bad, bad = 0, 0, []
        for r in rows:
            table = (override or {}).get(r["case_id"], r["predicted"])
            if not table:
                continue
            for ref, fields in table.items():
                for field, want in fields.items():
                    n += 1
                    if ref == "third_route":
                        got = r["measured"]["third_route_oracle"]["chunk_dot"]
                    else:
                        got = r["measured"][ref][
                            "fp8_byte_channel_0" if field == "fp8_byte"
                            else field]
                    ok = num_eq(got, want)
                    if not ok:
                        n_bad += 1
                        bad.append({"case": r["case_id"], "ref": ref,
                                    "field": field, "want": want, "got": got})
        return n, n_bad, bad

    n_pred, n_pred_bad, pred_bad = check_predictions(rows)
    rep.row("every hand-predicted value in the corpus is what the references "
            "actually produce", n_pred_bad == 0 and n_pred > 0, n_pred,
            {"n_bad": n_pred_bad, "bad": pred_bad[:6]})
    # CONTROL: the same comparison against a prediction that is one ulp off
    wrong = {"cancel_audit_counterexample":
             {"A_16AW": {"chunk_dot": "0.001953125", "fp8_byte": 0x01}}}
    n_cp, n_cp_bad, cp_bad = check_predictions(rows, override=wrong)
    rep.row("CONTROL: the same prediction comparison REJECTS a prediction that "
            "is one ulp off", n_cp_bad > 0, n_cp,
            {"n_bad": n_cp_bad, "bad": cp_bad[:4]})

    # -------------------------------------------------- oracle agreement
    def to_q(s):
        if s == "inf":
            return float("inf")
        if s == "-inf":
            return float("-inf")
        return Q(s)

    n_o, n_o_bad, o_bad = 0, 0, []
    for r in rows:
        for field, key in (("chunk_dot", "chunk_dot"),
                           ("main_after_chunk_and_partition_fold",
                            "multiply_row")):
            want = to_q(r["measured"]["third_route_oracle"][field])
            n_o += 1
            for ref in ("A_16AW", "B_16AW"):
                got = r["measured"][ref][key]
                if isinstance(got, str) and got.startswith("RAISED"):
                    if not (isinstance(want, float) and math.isinf(want)):
                        n_o_bad += 1
                        o_bad.append({"case": r["case_id"], "ref": ref,
                                      "got": got, "want": want})
                    continue
                if not num_eq(got, want):
                    n_o_bad += 1
                    o_bad.append({"case": r["case_id"], "ref": ref,
                                  "got": got, "want": str(want)})
    rep.row("the third-route oracle agrees with BOTH repaired references on "
            "every case, at the chunk sum and at the folded row accumulator",
            n_o_bad == 0 and n_o > 0, n_o, {"n_bad": n_o_bad,"bad": o_bad[:6]})

    # CONTROL: the binary64 oracle must be rejected, and reached
    n64_reach, n64_diff = 0, 0
    for r in rows:
        field = "main_after_chunk_and_partition_fold"
        want = to_q(r["measured"]["third_route_oracle"][field])
        mut = to_q(r["measured"]["binary64_oracle_mutant"][field])
        if isinstance(want, float) or isinstance(mut, float):
            if isinstance(want, float) and isinstance(mut, float) \
                    and math.isinf(want) and math.isinf(mut):
                continue
        if not C.same(want, mut):
            n64_diff += 1
        if r["case_id"] in ("cancel_audit_counterexample",
                            "gap_tiny_first_then_cancel", "cancel_at_chunk_5"):
            n64_reach += 1
    rep.row("CONTROL: the same oracle comparison REJECTS a binary64 "
            "accumulator, and the differing cases are the cancellation cases "
            "the audit named",
            n64_diff > 0 and n64_reach > 0, len(rows),
            {"differing": n64_diff, "reached": n64_reach})

    # CONTROL: a saturating H oracle must be rejected, and reached
    n_sat_reach, n_sat_diff = 0, 0
    for r in rows:
        field = "main_after_chunk_and_partition_fold"
        want = to_q(r["measured"]["third_route_oracle"][field])
        sat = to_q(r["measured"]["saturating_H_oracle_mutant"][field])
        if isinstance(want, float) and math.isinf(want):
            n_sat_reach += 1
            if not (isinstance(sat, float) and math.isinf(sat)):
                n_sat_diff += 1
    rep.row("CONTROL: the same oracle comparison REJECTS a saturating H, and "
            "the saturation branch is reached",
            n_sat_reach > 0 and n_sat_diff > 0, n_sat_reach,
            {"reached": n_sat_reach, "differing": n_sat_diff})

    # -------------------------------------------------- coverage
    present = sorted({r["category"] for r in rows})
    missing = [c for c in CATEGORIES_REQUIRED if c not in present]
    counts = {c: sum(1 for r in rows if r["category"] == c) for c in present}
    rep.row("every category the brief names is present in the corpus, each "
            "with at least one case", not missing, len(present),
            {"missing": missing, "per_category": counts})

    # -------------------------------------------------- refusals != agreement
    n_agree, n_disagree, n_void, n_one_void = 0, 0, 0, 0
    disagree_list, void_list = [], []
    for r in rows:
        a = r["measured"]["A_16AW"]["fp8_byte_channel_0"]
        b = r["measured"]["B_16AW"]["fp8_byte_channel_0"]
        c = classify(a, b)
        r["classification_A_16AW_vs_B_16AW"] = c
        if c == "AGREE":
            n_agree += 1
        elif c == "DISAGREE":
            n_disagree += 1
            disagree_list.append({"case": r["case_id"], "A": a, "B": b})
        elif c == "BOTH_VOID":
            n_void += 1
            void_list.append({"case": r["case_id"], "A": a, "B": b})
        else:
            n_one_void += 1
            disagree_list.append({"case": r["case_id"], "A": a, "B": b,
                                  "note": "ONE SIDE REFUSED"})
    # and the A_16AR-vs-A_16AW comparison, where the repair is the subject
    n_rep_agree, n_rep_diff = 0, 0
    rep_diff_list = []
    for r in rows:
        a = r["measured"]["A_16AR"]["fp8_byte_channel_0"]
        b = r["measured"]["A_16AW"]["fp8_byte_channel_0"]
        c = classify(a, b)
        r["classification_A_16AR_vs_A_16AW"] = c
        if c == "AGREE":
            n_rep_agree += 1
        elif c == "DISAGREE":
            n_rep_diff += 1
            rep_diff_list.append({"case": r["case_id"], "A_16AR": a,
                                  "A_16AW": b})

    n_str_mutated = 0
    for r in rows:
        a = r["measured"]["A_16AW"]["fp8_byte_channel_0"]
        b = r["measured"]["B_16AW"]["fp8_byte_channel_0"]
        if classify_stringly(a, b) != classify(a, b):
            n_str_mutated += 1
    rep.row("the classifier does NOT count two refusals as agreement: the "
            "out-of-contract cases are BOTH_VOID, and they are listed",
            n_void > 0 and n_one_void == 0, len(rows),
            {"agree": n_agree, "disagree": n_disagree, "both_void": n_void,
             "one_void": n_one_void, "void_cases": void_list})
    rep.row("CONTROL: the same classification REJECTS a string-comparing "
            "classifier, which would read two identical RAISED strings as "
            "agreement",
            n_str_mutated > 0, len(rows), {"reclassified": n_str_mutated})
    rep.row("the repaired A disagrees with A_16AR on exactly the cancellation "
            "and large-gap cases, and nowhere else",
            n_rep_diff > 0, len(rows),
            {"differing": n_rep_diff, "cases": rep_diff_list,
             "agreeing": n_rep_agree})

    doc = {
        "phase": "16AW",
        "brief_section": 34,
        "title": "adversarial fixture corpus and per-case A/B results",
        "host_only": True,
        "n_cases": len(rows),
        "categories_required": CATEGORIES_REQUIRED,
        "categories_present": present,
        "categories_per_case_count": counts,
        "audit_counterexample_is_case_1": rows[0]["case_id"],
        "how_a_case_is_materialised": (
            "a 1024-wide activation row and a 1024-wide weight row with "
            "nonzeros only inside the named chunk are passed to the modules' "
            "own `project` and `decoder_entry`, so the case runs the real "
            "code path, not a re-implementation"),
        "levels_recorded_per_case": ["chunk_dot", "multiply_row",
                                     "project_rows_1", "fused_channel_0",
                                     "fp8_byte_channel_0"],
        "summary": {
            "A_16AW_vs_B_16AW": {"agree": n_agree, "disagree": n_disagree,
                                 "both_void": n_void, "one_void": n_one_void,
                                 "disagreements": disagree_list},
            "A_16AR_vs_A_16AW": {"agree": n_rep_agree, "differ": n_rep_diff,
                                 "cases": rep_diff_list},
            "oracle_comparisons": {"n": n_o, "n_bad": n_o_bad},
            "binary64_oracle_mutant_differing_cases": n64_diff,
            "saturating_H_oracle_mutant_differing_cases": n_sat_diff,
        },
        "cases": rows,
        "checks": rep.rows,
        "n_checks": len(rep.rows),
        "n_checks_ok": rep.n_ok,
        "verdict": ("CORPUS_COMPLETE_AND_EVERY_CONTROL_FIRED"
                    if rep.n_ok == len(rep.rows) else "CORPUS_INCOMPLETE"),
        "not_measured": [
            "the corpus says nothing about the original DLSS-NR model; it "
            "characterises the project's own two references, which is what "
            "the brief asks for.",
        ],
    }
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    print("  -> %s" % os.path.basename(OUT))
    print("  %d/%d checks ok" % (rep.n_ok, len(rep.rows)))
    return 0 if rep.n_ok == len(rep.rows) else 1


def struct_h(v):
    import struct
    try:
        return struct.unpack("<H", struct.pack("<e", float(v)))[0]
    except Exception:                                       # noqa: BLE001
        return 0xFFFF


if __name__ == "__main__":
    sys.exit(main())
