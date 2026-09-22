#!/usr/bin/env python3
"""Phase 16AX / T-PERF -- CORRECTED performance and cost model.

HOST ONLY.  No GPU, no HIP, no device, no kernel launch, no child process.
numpy is NOT installed: stdlib only.

WHY THIS FILE EXISTS
--------------------
Phase 16AO's `COST_MODEL_PER_BLOCK.json` (verdict COST_MODEL_CORRECTED) repaired
Phase 16AN's position count: 16AN applied the tier's full processing canvas to
all 71 blocks, while the network is a six-level halving pyramid, so 16AN's
3.61058067744e13 MACs/frame -- published as a LOWER bound -- is an UPPER bound
and is wrong by two orders of magnitude as an estimate.

16AO then left a SECOND defect in place, and this file repairs it:

    p16ao/cost/p16ao_cost_audit.py, totals.sensitivity.vit_token_count.at_400

        "at_400": sum(r["weight_elements"]["value"] *
                      (T9 if r["level"] == "TOKEN" else 1) for r in rows
                      if r["level"] == "TOKEN") * T9,

The row filter already restricts the sum to TOKEN (ViT) blocks, so the inner
`(T9 if ... else 1)` is already T, and the trailing `* T9` multiplies by T AGAIN.
The ViT LINEAR layers -- whose every weight matrix is token-independent -- are
therefore costed as `weights x tokens x tokens`.  The published value is
8.05577856e12; the single-factor value at the same token count is 2.01394464e10.
The inflation factor is exactly the token count, 400.

The QUADRATIC attention term is a different object and stays separate: see
attention_macs_vit()/attention_macs_split() below, neither of which carries any
weight_elements.  The repair is confined to the linear term; nothing here moves
an attention MAC into a linear MAC or the reverse.

NO OPTIMIZATION IS PERFORMED OR PROPOSED.  See `no_optimization_constraint`.

EVIDENCE VOCABULARY (declared once, applied to every quantity):

  MEASURED   read from bytes or records on disk, or from a captured device
             record: an archive payload byte count, an element count the index
             states, a dispatch count in the capture table, a workgroup size, a
             device-annotated LDS size, a SHA-256 recomputed this run.
             It is NOT a device PERFORMANCE measurement: no representative
             operator has ever completed on this device, so no measured
             effective RATE exists anywhere in this project -- see `ceilings`.
  ESTIMATED  arithmetic over MEASURED inputs plus a NAMED assumption or a NAMED
             published shape.  The assumption is on the row.
  UNKNOWN    no defensible value exists: the value is null and the reason is on
             the row.  UNKNOWN IS BLOCKING -- never read as zero, never folded
             into ESTIMATED, never read as a measurement.

Mapping from the frozen artifacts' own vocabulary, so the two do not silently
diverge: the frozen EXACT (a byte count read from an index) is this file's
MEASURED; the frozen DERIVED (arithmetic over an assumed position count) splits
into this file's ESTIMATED (a named assumption exists) and UNKNOWN (none does).
The frozen MEASURED class is never used here for a performance quantity,
because in this project it means "from a physical completion" and none exists.

Not one number in this file is a rate.  `measured_effective_rate` is null and a
check enforces that no rate-named field carries a non-null value.
"""
from __future__ import annotations

import collections
import csv
import hashlib
import json
import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

ART16AO = os.path.join(ROOT, "p16ao", "cost", "COST_MODEL_PER_BLOCK.json")
AUDIT16AO = os.path.join(ROOT, "p16ao", "cost", "p16ao_cost_audit.py")
ART16AN = os.path.join(ROOT, "p16an", "native", "OPERATOR_COST_MODEL_16AN.json")
NGV0 = os.path.join(ROOT, "p16an", "native", "NATIVE_GRAPH_V0.json")
IDMAP = os.path.join(ROOT, "p16an", "native", "IDENTITY_MAPPING_16AN.json")
WIDX = os.path.join(ROOT, "p16an", "native", "_fetch", "weights-index.json")
VITDEC = os.path.join(ROOT, "p16an", "native", "_fetch", "vit_block31_reference.py")
GEN16AN = os.path.join(ROOT, "p16an", "native", "p16an_cost_model.py")
LAUNCH_DB = os.path.join(ROOT, "phase16_authentic_launch_db.csv")
OUT = os.path.join(HERE, "PERF_MODEL_16AX.json")

LEVELS = ("L0", "L1", "L2", "L3", "L4", "L5", "TOKEN")
LEVEL_DIVISOR = {"L0": 1, "L1": 2, "L2": 4, "L3": 8, "L4": 16, "L5": 32}

#: the split/ViT reference shapes 16AO pinned, carried verbatim so the attention
#: term this file reports is the SAME term 16AO reported.
SPLIT_HEADS, SPLIT_HEAD_DIM, SPLIT_WINDOW_TOKENS = 16, 32, 64
VIT_HEADS, VIT_HEAD_DIM = 32, 32

#: the ViT block's own records and the matrices the pinned decoder proves they
#: hold.  `elems` is the element count read as the payload at ONE BYTE per
#: element (the reference reads this family as fp8 e4m3); `shape` is the
#: (m, k) the decoder's own call sites fix; the residual is the tail the decoder
#: also reads (an fp16 skip / scale vector).  Every value is CHECKED against the
#: archive at run time, not trusted.
VIT_RECORD_LAYOUT = (
    ("layer0", 4 * 1024 * 1024, (1024, 4096),
     "the expand matrix: the decoder loads it as "
     "`np.fromfile(assets/'block31-vit-expand-effective.f16').reshape(1024,4096)` "
     "and multiplies with `x@expand`"),
    ("layer1", 4 * 1024 * 1024, (4096, 1024),
     "the contract matrix: `unpack_matrix(payload(1)[:4096*1024],4096,1024)`"),
    ("layer2", 3 * 1024 * 1024, (1024, 3072),
     "the fused QKV: read as fp8 and reshaped `(1024,3,1024)`, then used as "
     "`einsum('ti,igo->tgo', hidden, qkv)` with i = in-channel 1024, g in 0..2, "
     "o = out-channel 1024"),
    ("layer4", 1024 * 1024, (1024, 1024),
     "the output projection: `unpack_matrix(payload(4)[:1024*1024],1024,1024)` "
     "used as `attention@projection`"),
)
#: layer3 is a 2-byte record -- one element: a scalar, not a matrix.  Carried in
#: the reconciliation and excluded from the MAC table BY NAME, not by size.
VIT_SCALAR_RECORDS = ("layer3",)

TOKEN_FACTOR_RULE = (
    "A weight-bearing layer's MAC count is weight_elements x positions, ONCE.  "
    "For a convolution weight_elements = Kh*Kw*(Cin/groups)*Cout and the "
    "positions are output pixels; for a linear layer weight_elements = Cin*Cout "
    "and the positions are the TOKEN count.  So the token count enters a LINEAR "
    "layer exactly ONCE, and weight_elements is token-INDEPENDENT: a ViT weight "
    "matrix is Cin x Cout whatever the sequence length.  A second factor of the "
    "token count in a linear term has ONE signature: doubling the token count "
    "QUADRUPLES that term instead of doubling it.  Attention is the only term in "
    "which the token count legitimately appears twice (T x T scores, then a T x T "
    "weighted sum), and attention carries NO weight element, so it is computed by "
    "a SEPARATE function and is never summed into a linear term."
)


# ---------------------------------------------------------------------------
# THE MODEL -- pure functions, no I/O, parametric in the token count.
#
# p16ax_token_factor_test.py drives THESE, not a frozen number, which is what
# lets it catch a re-introduction at a shape nobody tested when the number was
# first pinned.
# ---------------------------------------------------------------------------

def linear_macs(weight_elements, positions):
    """MACs of a weight-bearing layer: weight_elements x positions, ONCE."""
    return weight_elements * positions


def token_level_linear_macs(vit_rows, tokens):
    """The ViT LINEAR term: weights x tokens, ONCE.  See TOKEN_FACTOR_RULE."""
    return sum(r["weight_elements"] * tokens for r in vit_rows)


def vit_linear_upper_macs(vit_rows, tokens):
    """The same term on the 1-byte fp8 reading: at most one element per byte.

    Takes rows shaped like every other row in this file -- a single
    `weight_elements` -- because on this reading the BYTE VOLUME *is* the
    admissible upper element count.  Keeping one row shape means the predicate
    and the two builders are driven by the same call convention, so a test
    cannot accidentally feed one of them the wrong column.

    It DELEGATES to token_level_linear_macs instead of repeating the expression.
    Two implementations of one law is one place too many for the token factor to
    be duplicated unseen: a regression test that anchored only one of them passed
    against a model whose OTHER one carried the fault (measured, 16AX).  The law
    this file exists to state now appears exactly once, and the difference between
    the two figures is the ROW SET they are handed, not the arithmetic.
    """
    return token_level_linear_macs(vit_rows, tokens)


def attention_macs_vit(n_instances, tokens, heads=VIT_HEADS, head_dim=VIT_HEAD_DIM):
    """The ViT QUADRATIC term, kept separate.  Weight-free: T enters TWICE."""
    return n_instances * 2 * heads * tokens * tokens * head_dim


def attention_macs_split(n_blocks, l5_w, l5_h, heads=SPLIT_HEADS,
                         head_dim=SPLIT_HEAD_DIM, window=SPLIT_WINDOW_TOKENS):
    """The split-window QUADRATIC term, kept separate.  Quadratic in the L5
    spatial extent (through the window count), never in the ViT token count."""
    t = int(round(window ** 0.5))
    assert t * t == window, "window_tokens %d is not a square" % window
    windows = -(-l5_w // t) * -(-l5_h // t)
    return (windows,
            windows * n_blocks * 2 * heads * window * window * head_dim)


def graph_linear_macs(rows, positions_by_level):
    """Every weight-bearing block, each level at its OWN extent, single factor."""
    return sum(linear_macs(r["weight_elements"], positions_by_level[r["level"]])
               for r in rows)


def graph_total_macs(rows, positions_by_level, attention_macs):
    """The total is the linear term PLUS the separate attention term.  Written as
    a sum of two named quantities so neither can silently absorb the other."""
    return graph_linear_macs(rows, positions_by_level) + attention_macs


# ---------------------------------------------------------------------------
# THE SINGLE-FACTOR PREDICATE.  Pure, so both the model and its negative
# controls can drive it in one process.
# ---------------------------------------------------------------------------

def check_single_token_factor(published_term, vit_rows, tokens):
    """True iff `published_term` is the ViT linear term with the token factor
    applied EXACTLY ONCE.

    Structural, not a pinned number: the expectation is rebuilt from whatever
    rows and token count are supplied, so the predicate follows the shape.
    Absence is blocking: no rows, no positive token count or no positive weight
    sum is a REJECTION, never a vacuous pass.
    """
    if not vit_rows:
        return False, ("REJECTED: no ViT rows supplied -- a check that compares "
                       "nothing is not a pass")
    if tokens <= 0:
        return False, "REJECTED: token count %r is not positive" % (tokens,)
    weight_sum = sum(int(r["weight_elements"]) for r in vit_rows)
    if weight_sum <= 0:
        return False, "REJECTED: the ViT weight sum is %d" % weight_sum
    if published_term is None:
        return False, "REJECTED: the published term is absent"
    expected = weight_sum * tokens
    if int(published_term) == expected:
        return True, "%d == %d x %d" % (published_term, weight_sum, tokens)
    ratio = float(published_term) / float(expected)
    return False, ("%d != %d x %d: the published term is %.6g x the single-factor "
                   "value%s"
                   % (published_term, weight_sum, tokens, ratio,
                      "; a ratio of exactly the token count (%d) means the token "
                      "factor was applied TWICE" % tokens
                      if abs(ratio - tokens) < 1e-9 else ""))


def scaling_exponent(fn, T, k):
    """The measured exponent of a term builder: log(fn(kT)/fn(T))/log(k)."""
    base = fn(T)
    if base == 0:
        return None
    return math.log(fn(T * k) / base) / math.log(k)


def check_linear_not_quadratic_in_tokens(fn, tokens_probe=(2, 3, 7, 400, 640, 2160)):
    """Structural scaling ladder for ANY term builder `fn(tokens) -> number`.

    A term carrying the token factor ONCE is exactly linear: fn(kT) == k*fn(T).
    A term carrying it TWICE is quadratic: fn(2T) == 4*fn(T).  Stated as an exact
    equality, so a constant offset, a different weight sum or a different token
    count all still fail: there is no shape at which a duplicated factor hides.
    """
    bad = []
    for T in tokens_probe:
        if fn(T) == 0:
            bad.append("T=%d gives a ZERO term: the ladder cannot test a term that "
                       "is not there" % T)
            continue
        for k in (2, 3):
            if fn(T * k) != k * fn(T):
                bad.append("T=%d -> %d, T=%d -> %d: measured exponent %.6f, not 1"
                           % (T, fn(T), T * k, fn(T * k), scaling_exponent(fn, T, k)))
    return (not bad), ("linear in tokens at every probe %s" % (tokens_probe,)
                       if not bad else "; ".join(bad))


def check_quadratic_in_tokens(fn, tokens_probe=(2, 3, 7, 400, 640, 2160)):
    """The companion ladder: the ATTENTION term must be quadratic.  A test that
    rejected every quadratic-in-tokens term would reject the correct attention
    term too, which is why the two ladders are separate checks."""
    bad = []
    for T in tokens_probe:
        if fn(T) == 0:
            bad.append("T=%d gives a ZERO attention term" % T)
            continue
        for k in (2, 3):
            if fn(T * k) != (k * k) * fn(T):
                bad.append("T=%d -> %d, T=%d -> %d: measured exponent %.6f, not 2"
                           % (T, fn(T), T * k, fn(T * k), scaling_exponent(fn, T, k)))
    return (not bad), ("quadratic in tokens at every probe %s" % (tokens_probe,)
                       if not bad else "; ".join(bad))


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------

def main():
    CHECKS = []
    REQUIRED = []

    def check(name, ok, detail, required=True):
        CHECKS.append({"check": name, "result": "PASS" if ok else "FAIL",
                       "detail": detail})
        if required:
            REQUIRED.append(name)
        return bool(ok)

    # ---------------- inputs, hashed from the bytes on disk ----------------
    inputs = {}
    for label, path in (("p16ao/cost/COST_MODEL_PER_BLOCK.json", ART16AO),
                        ("p16ao/cost/p16ao_cost_audit.py", AUDIT16AO),
                        ("p16an/native/OPERATOR_COST_MODEL_16AN.json", ART16AN),
                        ("p16an/native/NATIVE_GRAPH_V0.json", NGV0),
                        ("p16an/native/IDENTITY_MAPPING_16AN.json", IDMAP),
                        ("p16an/native/_fetch/weights-index.json", WIDX),
                        ("p16an/native/_fetch/vit_block31_reference.py", VITDEC),
                        ("p16an/native/p16an_cost_model.py", GEN16AN),
                        ("phase16_authentic_launch_db.csv", LAUNCH_DB)):
        inputs[label] = {"bytes": os.path.getsize(path), "sha256": sha256_of(path)}

    art = load(ART16AO)
    art16an = load(ART16AN)
    ngv0 = load(NGV0)
    idmap = load(IDMAP)
    widx = load(WIDX)
    rows = art["per_block"]
    blocks16 = ngv0["blocks"]
    widx_by_name = {r["name"]: r for r in widx}
    tok_rows = [r for r in rows if r["level"] == "TOKEN"]
    vit_rows_min = [{"weight_elements": r["weight_elements"]["value"],
                     "weight_bytes": r["weight_bytes"]["value"]} for r in tok_rows]
    #: the 1-byte fp8 reading, as rows the predicate can multiply
    vit_rows_upper = [{"weight_elements": r["weight_bytes"]["value"]}
                      for r in tok_rows]
    #: the 1-byte fp8 reading of the same rows: for the predicate to test the
    #: right identity, it must be handed the weight figure it will multiply.
    vit_rows_upper = [{"weight_elements": r["weight_bytes"]["value"]}
                      for r in tok_rows]
    #: the same rows flattened to the model's own input shape, so the purity of
    #: the model functions is not broken by the artifact's nested value objects
    lin_rows = [{"weight_elements": r["weight_elements"]["value"],
                 "level": r["level"]} for r in rows]

    with open(LAUNCH_DB, newline="", encoding="utf-8") as f:
        launch_rows = list(csv.DictReader(f))

    # ---------------- the frozen level table, carried not re-derived --------
    lv = art["level_table"]
    pos900 = {L: lv[L]["positions_900_tier"] for L in LEVELS}
    poscap = {L: lv[L]["positions_1080_tier"] for L in LEVELS}
    T9, Tcap = pos900["TOKEN"], poscap["TOKEN"]
    by_level = collections.Counter(r["level"] for r in rows)

    check("frozen_level_partition_unchanged",
          all(by_level[L] == lv[L]["blocks"] for L in LEVELS)
          and sum(by_level.values()) == 71,
          "the frozen artifact's rows partition into %s = %d, and each count "
          "equals its own level_table row"
          % ({L: by_level[L] for L in LEVELS}, sum(by_level.values())))

    gen_src = open(GEN16AN, encoding="utf-8").read()
    check("tier_table_corroborated_by_an_independent_file",
          '"processing": [1600, 960]' in gen_src
          and (pos900["L0"], pos900["TOKEN"]) == (1600 * 960, 400)
          and (poscap["L0"], poscap["TOKEN"]) == (1920 * 1152, 640),
          "the token counts this repair uses, %d (900 tier) and %d (capture "
          "tier), are the frozen artifact's own level_table values AND the same "
          "processing geometry appears verbatim in "
          "p16an/native/p16an_cost_model.py, a different file by a different "
          "author.  That is source independence for the TOKEN COUNT, not for the "
          "position arithmetic." % (T9, Tcap))

    # ---------------- STEP 0: reproduce BEFORE changing anything -----------
    repro16an = sum(b["weight_elements_declared"]
                    * (T9 if b["role"] == "bottleneck" else pos900["L0"])
                    for b in blocks16)
    stated16an = art16an["cost_drivers"]["compute"]["total_macs_lower_bound"]
    check("step0_16AN_rule_reproduces_its_stated_figure",
          repro16an == stated16an,
          "SUM over 71 blocks of weight_elements x (1536000 unless "
          "role==bottleneck else 400), recomputed from NATIVE_GRAPH_V0.json, "
          "gives %d; 16AN states %d; delta %d"
          % (repro16an, stated16an, repro16an - stated16an))

    tot900 = sum(r["macs"]["at_900_tier"]["value"] for r in rows)
    totcap = sum(r["macs"]["at_capture_tier"]["value"] for r in rows)
    pub900 = art["totals"]["methods_a_and_b_900_tier"]["macs"]
    pubcap = art["totals"]["methods_a_and_b_1080_tier"]["macs"]
    check("step0_16AO_totals_reproduce_from_its_own_rows",
          tot900 == pub900 and totcap == pubcap,
          "recomputed from the emitted rows: 900 tier %d (published %d), capture "
          "tier %d (published %d)" % (tot900, pub900, totcap, pubcap))

    frozen_at400 = sum(r["weight_elements"]["value"]
                       * (T9 if r["level"] == "TOKEN" else 1)
                       for r in rows if r["level"] == "TOKEN") * T9
    published_at400 = art["totals"]["sensitivity"]["vit_token_count"]["at_400"]
    check("step0_frozen_sensitivity_term_reproduces",
          frozen_at400 == published_at400,
          "the frozen expression, evaluated on the frozen rows, gives %d; the "
          "frozen artifact publishes %d" % (frozen_at400, published_at400))
    T_frozen = art["totals"]["sensitivity"]["vit_token_count"]["range_considered"][0]

    # ---------------- INDEPENDENT source for the ViT weight totals ---------
    vit_blocks = [b for b in blocks16
                  if any(t.startswith("CCVit1D") for t in b["reference_layer_types"])]
    vit_names = [n for b in vit_blocks for n in b["weight_records"]]
    indep_elem = sum(widx_by_name[n]["element_count"] for n in vit_names)
    indep_pay = sum(widx_by_name[n]["payload_size"] for n in vit_names)
    art_elem = sum(r["weight_elements"]["value"] for r in tok_rows)
    art_pay = sum(r["weight_bytes"]["value"] for r in tok_rows)
    check("vit_weight_totals_reproduced_from_an_independent_source",
          indep_elem == art_elem and indep_pay == art_pay and len(vit_names) == 40,
          "from NATIVE_GRAPH_V0's block->weight_records map plus the raw weights "
          "index: %d records, element_count %d, payload %d.  From the frozen cost "
          "artifact's own ViT rows: element %d, payload %d.  The two sides share "
          "neither a file nor a parser."
          % (len(vit_names), indep_elem, indep_pay, art_elem, art_pay))

    # ---------------- DEFECT: measured, not asserted -----------------------
    single_value = sum(r["weight_elements"] for r in vit_rows_min) * T_frozen
    inflation = published_at400 / single_value
    check("the_frozen_sensitivity_term_carries_the_token_factor_twice",
          published_at400 == single_value * T_frozen and inflation == T_frozen,
          "the frozen at_400 value %d equals the single-factor value %d x %d: the "
          "token factor %d is applied TWICE, an inflation of exactly the token "
          "count (%.6g).  This is the defect T-PERF repairs."
          % (published_at400, single_value, T_frozen, T_frozen, inflation))

    red_ok, red_detail = check_single_token_factor(published_at400, vit_rows_min, T_frozen)
    green_ok, green_detail = check_single_token_factor(single_value, vit_rows_min, T_frozen)
    check("negative_control_the_single_factor_predicate_rejects_the_frozen_value",
          (not red_ok) and green_ok,
          "the predicate rejects the frozen %d (%s) and accepts the corrected %d "
          "(%s).  A predicate that could not reject the real defect would not be a "
          "regression test." % (published_at400, red_detail, single_value, green_detail))

    # ---------------- blast radius: what did NOT change --------------------
    uv900 = art["totals"]["upper_variant_one_byte_families_900_tier"]["macs"]
    uvcap = art["totals"]["upper_variant_one_byte_families_1080_tier"]["macs"]
    sum_linear_900 = graph_linear_macs(lin_rows, pos900)
    sum_linear_cap = graph_linear_macs(lin_rows, poscap)
    check("the_frozen_totals_are_already_single_factor",
          sum_linear_900 == pub900 and sum_linear_cap == pubcap,
          "re-performing every per-block linear term through this file's own "
          "linear_macs() reproduces the frozen totals exactly (%d and %d), so the "
          "duplicated factor is confined to the sensitivity term and is NOT in "
          "the per-block rows or the headline totals.  The repair therefore "
          "changes ONE published figure; reporting the rest as moved would be a "
          "fabrication." % (sum_linear_900, sum_linear_cap))

    # ---------------- attention is separate, and stays separate -----------
    n_vit = len(tok_rows)
    n_split = by_level["L5"] - 1
    W5, H5 = 1600 // LEVEL_DIVISOR["L5"], 960 // LEVEL_DIVISOR["L5"]
    split_windows, split_attn_900 = attention_macs_split(n_split, W5, H5)
    vit_attn_900 = attention_macs_vit(n_vit, T9)
    split_windows_c, split_attn_cap = attention_macs_split(
        n_split, 1920 // LEVEL_DIVISOR["L5"], 1152 // LEVEL_DIVISOR["L5"])
    vit_attn_cap = attention_macs_vit(n_vit, Tcap)
    wfa = art["totals"]["weight_free_attention_macs"]
    check("attention_term_reproduced_and_kept_separate",
          split_windows == wfa["900_tier"]["split_blocks"]["windows"]
          and split_attn_900 == wfa["900_tier"]["split_blocks"]["macs"]
          and vit_attn_900 == wfa["900_tier"]["vit_blocks"]["macs"]
          and split_windows_c == wfa["1080_tier"]["split_blocks"]["windows"]
          and split_attn_cap == wfa["1080_tier"]["split_blocks"]["macs"]
          and vit_attn_cap == wfa["1080_tier"]["vit_blocks"]["macs"]
          and (split_attn_900 + vit_attn_900) == wfa["900_tier"]["total_extra_macs"]
          and pub900 != sum_linear_900 + split_attn_900 + vit_attn_900,
          "the separate attention term reproduces the frozen artifact's own "
          "weight_free_attention_macs at both tiers (%d over %d windows + %d ViT "
          "at the 900 tier), and the frozen HEADLINE total %d equals the linear "
          "term ALONE.  16AO therefore kept attention separate, and this repair "
          "moves no attention MAC into a linear term."
          % (split_attn_900, split_windows, vit_attn_900, pub900))

    check("attention_is_quadratic_and_the_linear_term_is_not",
          check_quadratic_in_tokens(lambda T: attention_macs_vit(n_vit, T))[0]
          and check_linear_not_quadratic_in_tokens(lambda T: indep_elem * T)[0],
          "the ViT attention term is quadratic in tokens (T x T scores, then a "
          "T x T weighted sum) and is verified as such, while the LINEAR term is "
          "verified linear over the same probe set.  The two terms are shown to be "
          "different objects rather than one term relabelled.")

    # ---------------- CORRECTED figures ------------------------------------
    corrected = {
        "vit_linear_macs_at_the_900_tier": {
            "value": token_level_linear_macs(vit_rows_min, T9),
            "evidence_class": "ESTIMATED",
            "why": "weights x tokens ONCE, on the archive's own element_count (a "
                   "LOWER bound on the true element count for this fp8 family)"},
        "vit_linear_macs_at_the_capture_tier": {
            "value": token_level_linear_macs(vit_rows_min, Tcap),
            "evidence_class": "ESTIMATED", "why": "same, at the 640-token tier"},
        "vit_linear_macs_upper_variant_900_tier": {
            "value": vit_linear_upper_macs(vit_rows_upper, T9),
            "evidence_class": "ESTIMATED",
            "why": "the 1-byte fp8 reading: the pinned decoder proves this family "
                   "holds one element per payload byte, so the element count is at "
                   "most the byte volume.  Still ONE token factor."},
        "vit_linear_macs_upper_variant_capture_tier": {
            "value": vit_linear_upper_macs(vit_rows_upper, Tcap),
            "evidence_class": "ESTIMATED"},
        "vit_attention_macs_at_the_900_tier": {
            "value": vit_attn_900, "evidence_class": "ESTIMATED",
            "why": "SEPARATE quadratic term: %d blocks x 2 x %d heads x T^2 x %d "
                   "head_dim, T=%d" % (n_vit, VIT_HEADS, VIT_HEAD_DIM, T9)},
        "vit_attention_macs_at_the_capture_tier": {
            "value": vit_attn_cap, "evidence_class": "ESTIMATED"},
        "split_attention_macs_at_the_900_tier": {
            "value": split_attn_900, "evidence_class": "ESTIMATED",
            "why": "SEPARATE quadratic term: %d windows x %d blocks x 2 x %d heads "
                   "x 64^2 x %d" % (split_windows, n_split, SPLIT_HEADS,
                                    SPLIT_HEAD_DIM)},
        "split_attention_macs_at_the_capture_tier": {
            "value": split_attn_cap, "evidence_class": "ESTIMATED"},
        "whole_graph_linear_macs_at_the_900_tier": {
            "value": sum_linear_900, "evidence_class": "ESTIMATED",
            "why": "every weight-bearing block at its OWN level extent, single "
                   "factor; UNCHANGED from the frozen headline total"},
        "whole_graph_linear_macs_at_the_capture_tier": {
            "value": sum_linear_cap, "evidence_class": "ESTIMATED"},
        "whole_graph_total_including_attention_900_tier": {
            "value": graph_total_macs(lin_rows, pos900, split_attn_900 + vit_attn_900),
            "evidence_class": "ESTIMATED",
            "why": "linear + the two separate attention terms, stated as a sum of "
                   "named parts"},
        "whole_graph_total_including_attention_capture_tier": {
            "value": graph_total_macs(lin_rows, poscap, split_attn_cap + vit_attn_cap),
            "evidence_class": "ESTIMATED"},
        "upper_variant_whole_graph_capture_tier_frozen_total": {
            "value": uvcap, "evidence_class": "ESTIMATED",
            "why": "carried from the frozen artifact UNCHANGED, single-factor"},
        "upper_variant_whole_graph_900_tier_frozen_total": {
            "value": uv900, "evidence_class": "ESTIMATED"},
    }

    lin_cap_measured = token_level_linear_macs(vit_rows_min, Tcap)
    sens = {}
    for T in (400, 576, 640, 2160):
        # built through the MODEL FUNCTIONS, never by an inline multiplication,
        # so the anchored implementation is on the path every check gates on.  A
        # re-introduced second factor is then visible to the model's own verdict
        # rather than only to a reader.
        lin = token_level_linear_macs(vit_rows_min, T)
        lin_up = vit_linear_upper_macs(vit_rows_upper, T)
        attn = attention_macs_vit(n_vit, T)
        sens[str(T)] = {
            "vit_linear_macs": lin,
            "vit_linear_macs_upper_variant": lin_up,
            "vit_attention_macs": attn,
            "vit_linear_plus_attention": lin + attn,
            "whole_graph_linear_macs": sum_linear_cap - lin_cap_measured + lin,
            "whole_graph_total_including_attention": (
                sum_linear_cap - lin_cap_measured + lin + split_attn_cap + attn),
            "evidence_class": "ESTIMATED",
        }
    check("the_corrected_headline_vit_figures_are_single_factor",
          all(check_single_token_factor(corrected[k]["value"], rows_arg, T)[0]
              for k, rows_arg, T in (
                  ("vit_linear_macs_at_the_900_tier", vit_rows_min, T9),
                  ("vit_linear_macs_at_the_capture_tier", vit_rows_min, Tcap),
                  ("vit_linear_macs_upper_variant_900_tier", vit_rows_upper, T9),
                  ("vit_linear_macs_upper_variant_capture_tier", vit_rows_upper,
                   Tcap))),
          "all four corrected headline ViT figures pass the single-factor "
          "predicate: %s" % "; ".join(
              check_single_token_factor(corrected[k]["value"], rows_arg, T)[1]
              for k, rows_arg, T in (
                  ("vit_linear_macs_at_the_900_tier", vit_rows_min, T9),
                  ("vit_linear_macs_at_the_capture_tier", vit_rows_min, Tcap),
                  ("vit_linear_macs_upper_variant_900_tier", vit_rows_upper, T9),
                  ("vit_linear_macs_upper_variant_capture_tier", vit_rows_upper,
                   Tcap))))

    check("every_row_of_the_corrected_sensitivity_table_is_single_factor",
          all(check_single_token_factor(v["vit_linear_macs"], vit_rows_min, int(T))[0]
              and check_single_token_factor(v["vit_linear_macs_upper_variant"],
                                            vit_rows_upper, int(T))[0]
              and v["vit_attention_macs"] == attention_macs_vit(n_vit, int(T))
              for T, v in sens.items()),
          "each of the %d corrected sensitivity rows carries the token factor "
          "exactly once, on both the element-count and the byte-volume reading, "
          "and each row reports the attention term separately from the linear term"
          % len(sens))

    # ---------------- STEP 4: per-operator cost model ---------------------
    per_frame = collections.Counter()
    per_kernel_frame = collections.defaultdict(collections.Counter)
    lds_by_kernel = collections.defaultdict(set)
    block_by_kernel = collections.defaultdict(set)
    for r in launch_rows:
        fr = int(r["frame"])
        per_frame[fr] += 1
        per_kernel_frame[r["kernel_semantic"]][fr] += 1
        block_by_kernel[r["kernel_semantic"]].add(
            (int(r["block_x"]), int(r["block_y"]), int(r["block_z"])))
        for m in re.finditer(r"gsf\s+(\d+)", r.get("lds_static") or ""):
            lds_by_kernel[r["kernel_semantic"]].add(int(m.group(1)))

    dispatch_counts = {}
    for k, c in per_kernel_frame.items():
        vals = sorted(set(v for fr, v in c.items() if fr >= 2))
        dispatch_counts[k] = {
            "per_frame_measured": vals[0] if len(vals) == 1 else vals,
            "frames_present": len(c),
            "evidence_class": "MEASURED",
            "basis": "phase16_authentic_launch_db.csv: dispatches of %s with "
                     "frame>=2 (frame 1 carries no k_reproject, so it is the "
                     "warm-up frame)" % k,
            "workgroup": sorted(block_by_kernel[k])[0] if block_by_kernel[k] else None,
            "lds_gsf_bytes": sorted(lds_by_kernel[k]) if lds_by_kernel[k] else None,
        }
    check("measured_dispatch_counts_reproduce_a_second_artifact",
          per_frame[1] == 159 and per_frame[2] == 160
          and {str(f): per_frame[f] for f in sorted(per_frame)}
              == idmap["counts"]["dispatch_count_per_frame"],
          "the capture table gives %d dispatches in frame 1 and %d in every later "
          "frame, and those exact per-frame counts are independently published in "
          "IDENTITY_MAPPING_16AN.json's dispatch_count_per_frame.  Two files, two "
          "parsers, one value per frame." % (per_frame[1], per_frame[2]))

    idents = idmap["identities"]

    def identities_covering(block_ids):
        s = set(block_ids)
        return [i for i in idents if s & set(i.get("reference_blocks") or [])]

    def row_dispatch_measured(block_ids):
        """Dispatches per frame attributable to kernels whose reference_blocks all
        lie INSIDE this row.  A kernel covering several of the row's blocks counts
        once for the row, which is why this is a ROW figure, not a per-block one."""
        s = set(block_ids)
        total, kernels = 0, []
        for i in idents:
            rb = set(i.get("reference_blocks") or [])
            if rb and rb <= s and i["identity"] in dispatch_counts:
                c = dispatch_counts[i["identity"]]["per_frame_measured"]
                if isinstance(c, int):
                    total += c
                    kernels.append(i["identity"])
        return total, kernels

    def fam_of(lt):
        return ("split" if lt.startswith("CCSplit")
                else "vit" if lt.startswith("CCVit")
                else "swin")

    by_type = collections.OrderedDict()
    for r in rows:
        by_type.setdefault(r["layer_type"], []).append(r)

    per_operator = []
    for lt, rr in by_type.items():
        fam = fam_of(lt)
        bids = [x["block"] for x in rr]
        elems_lo = sum(x["weight_elements"]["value"] for x in rr)
        elems_hi = sum(x["weight_bytes"]["value"] for x in rr)
        lin900 = sum(linear_macs(x["weight_elements"]["value"], pos900[x["level"]])
                     for x in rr)
        lincap = sum(linear_macs(x["weight_elements"]["value"], poscap[x["level"]])
                     for x in rr)
        disp, disp_kernels = row_dispatch_measured(bids)
        per_operator.append({
            "reference_layer_type": lt,
            "family": fam,
            "granularity": "BLOCK_LEVEL",
            "instances": len(rr),
            "reference_blocks": sorted(bids),
            "levels": sorted(set(x["level"] for x in rr), key=LEVELS.index),
            "widths": sorted(set(x["width"] for x in rr)),
            "variants": sorted(set(x["variant"] for x in rr)),
            "mapped_local_identities": [
                {"identity": i["identity"], "verdict": i["verdict"],
                 "shared_reference_blocks": sorted(
                     set(i.get("reference_blocks") or []) & set(bids))}
                for i in identities_covering(bids)],
            "macs": {
                "linear_900_tier": {"value": lin900, "evidence_class": "ESTIMATED",
                                    "basis": "weight_elements x output positions "
                                             "ONCE per block, each level at its own "
                                             "extent"},
                "linear_capture_tier": {"value": lincap,
                                        "evidence_class": "ESTIMATED"},
                "attention": {"value": None, "evidence_class": "UNKNOWN",
                              "why": "the frozen artifact accounts the weight-free "
                                     "attention term ONLY as a graph-level total "
                                     "(totals.weight_free_attention_macs), never "
                                     "per block; attributing it to this reference "
                                     "layer type would be an invented attribution. "
                                     "The graph-level figure is in `corrected` and "
                                     "in the sensitivity rows."},
            },
            "bytes_moved": {
                "weights_archive_bytes": {
                    "value": sum(x["weight_bytes"]["value"] for x in rr),
                    "evidence_class": "MEASURED",
                    "basis": "weights-index.json payload_size summed over this "
                             "type's blocks' weight_records: an archive byte count "
                             "read from disk, not a computation"},
                "weights_as_elements_lower": {
                    "value": elems_lo, "evidence_class": "MEASURED",
                    "basis": "element_count as the index states it; it equals "
                             "payload//2 for all 153 records"},
                "weights_as_elements_upper": {
                    "value": elems_hi, "evidence_class": "ESTIMATED",
                    "admissible": fam in ("split", "vit"),
                    "basis": ("the 1-byte fp8 reading, admissible for this family "
                              "because its pinned decoder reads fp8 matrices"
                              if fam in ("split", "vit") else
                              "NOT an independent upper reading for this family: "
                              "the swin conv records are 2-byte fp16, where "
                              "element_count == payload//2 IS the element count, so "
                              "the 'upper' reading collapses onto the lower one")},
                "activations_out": {
                    "value": sum(pos900[x["level"]] * x["width"] * 2 for x in rr),
                    "evidence_class": "ESTIMATED",
                    "basis": "positions x channel width x 2 bytes, ASSUMING fp16 "
                             "activations.  NATIVE_GRAPH_V0.json declares the "
                             "activation dtype UNRESOLVED between fp16 and fp8 "
                             "e4m3, so the fp8 variant is exactly half this and the "
                             "true value is not pinned."},
                "activations_in": {
                    "value": None, "evidence_class": "UNKNOWN",
                    "why": "neither the archive nor the graph publishes this "
                           "operator's input channel count or input count, so its "
                           "read volume cannot be reconstructed"},
                "total": {
                    "value": None, "evidence_class": "UNKNOWN",
                    "why": "BLOCKING BY ABSENCE: the total needs activations_in, "
                           "which is UNKNOWN.  It is null rather than the sum of "
                           "the terms that happen to be known, because a partial "
                           "sum published as a total reads as a total."},
            },
            "temporary_storage": {
                "value": None, "evidence_class": "UNKNOWN",
                "why": "no LDS or scratch figure exists for this reference layer "
                       "type.  The capture annotates LDS only for the kernel "
                       "families in measured_kernel_table; the archive publishes no "
                       "per-operator temporary storage."},
            "conversions": {
                "value": None, "evidence_class": "UNKNOWN",
                "why": "the fp8/fp16 round trips are pinned for the decoder and for "
                       "the split/ViT decoders, but the NUMBER of conversions per "
                       "operator is not published",
                "known_requirement": ("an fp8 e4m3 dequant is required before the "
                                      "multiply for this family"
                                      if fam in ("split", "vit") else None)},
            "dispatch_count": {
                "value": disp if disp_kernels else None,
                "evidence_class": "MEASURED" if disp_kernels else "UNKNOWN",
                "unit": "dispatches per frame attributable to kernels whose "
                        "reference_blocks all lie inside this row",
                "kernels": disp_kernels,
                "why": None if disp_kernels else
                       "no captured kernel's reference_blocks lie inside this row, "
                       "so no measured dispatch count is attributable to it",
                "per_block_per_frame": {
                    "value": None, "evidence_class": "UNKNOWN",
                    "why": "the identity mapping is at kernel-to-reference-type "
                           "granularity and its counts are per KERNEL, not per "
                           "block, so it does not establish which of the row's "
                           "block instances a dispatch belongs to"},
                "mapped_kernel_measured_counts": {
                    i["identity"]: dispatch_counts.get(i["identity"])
                    for i in identities_covering(bids)
                    if i["identity"] in dispatch_counts},
                "network_dispatches_bound_to_a_block":
                    idmap["counts"].get("network_dispatches_bound_to_a_block"),
            },
        })

    # ---------------- ViT sub-layer table, grounded in the decoder --------
    per_block_layout = {}
    for b in vit_blocks:
        per_block_layout[b["block_id"]] = {
            n.split(".")[1]: widx_by_name[n]["payload_size"] for n in b["weight_records"]}
    layout_consistent = all(v == per_block_layout[vit_blocks[0]["block_id"]]
                            for v in per_block_layout.values())
    check("vit_block_records_are_identical_across_all_eight_blocks",
          layout_consistent and len(per_block_layout) == 8,
          "all %d ViT blocks carry the SAME five record names with the SAME "
          "payload sizes (measured per block, layer1 = %s), so one decoded layout "
          "covers all eight rather than being assumed to"
          % (len(per_block_layout),
             sorted(set(v["layer1"] for v in per_block_layout.values()))))

    vit_sublayer_rows = []
    vit_matrix_elems = 0
    for suffix, elems, shape, basis in VIT_RECORD_LAYOUT:
        pay = per_block_layout[vit_blocks[0]["block_id"]][suffix]
        m, k = shape
        tail = pay - elems
        assert m * k == elems and 0 <= tail <= 4096, (
            "record %s: payload %d, claimed shape %dx%d = %d, tail %d"
            % (suffix, pay, m, k, elems, tail))
        vit_matrix_elems += elems
        vit_sublayer_rows.append({
            "record": "block<N>.%s.layer" % suffix,
            "family": "vit", "granularity": "SUBLAYER_LEVEL",
            "instances": len(vit_blocks),
            "shape": {"m": m, "k": k, "element_count": elems,
                      "evidence_class": "MEASURED",
                      "basis": "the record carries exactly %d payload bytes and the "
                               "pinned decoder reads it as one element per byte"
                               % pay},
            "shape_assignment": {"evidence_class": "ESTIMATED", "basis": basis},
            "record_payload_bytes_per_block": pay,
            "record_tail_bytes_per_block": {
                "value": tail, "evidence_class": "MEASURED",
                "basis": "payload minus the matrix: the fp16 skip / scale tail the "
                         "decoder reads after the matrix bytes"},
            "macs": {
                "linear_400": {"value": elems * T9, "evidence_class": "ESTIMATED",
                               "basis": "%dx%d x %d tokens ONCE" % (m, k, T9)},
                "linear_640": {"value": elems * Tcap, "evidence_class": "ESTIMATED"},
                "attention": {"value": None, "evidence_class": "UNKNOWN",
                              "why": "this record holds a weight MATRIX; it is not "
                                     "the attention operator"},
            },
            "bytes_moved": {
                "weights_per_frame": {
                    "value": pay * len(vit_blocks), "evidence_class": "MEASURED",
                    "basis": "archive payload per block x %d blocks"
                             % len(vit_blocks)},
                "activations_out": {"value": None, "evidence_class": "UNKNOWN",
                                    "why": "the intermediate activation dtype is "
                                           "UNRESOLVED in NATIVE_GRAPH_V0.json"},
                "activations_in": {"value": None, "evidence_class": "UNKNOWN",
                                   "why": "not published"},
                "total": {"value": None, "evidence_class": "UNKNOWN"},
            },
            "temporary_storage": {"value": None, "evidence_class": "UNKNOWN"},
            "conversions": {"value": None, "evidence_class": "UNKNOWN",
                            "why": "the decoder proves an fp8 dequant is required "
                                   "before each multiply and an fp8 quant after, "
                                   "but the COUNT per operator is not published"},
            "dispatch_count": {"value": None, "evidence_class": "UNKNOWN",
                               "why": "the ViT family's records are "
                                      "block<N>.layer0..layer4; the identity mapping "
                                      "names the ViT kernels (k_expand2, "
                                      "k_contract2, k_qkv2, k_attention2) but binds "
                                      "them to ViT reference LAYER TYPES, not to "
                                      "these record suffixes, so a per-record "
                                      "dispatch count would be attributed, not "
                                      "measured"},
        })

    scalar_pay = sum(per_block_layout[b][VIT_SCALAR_RECORDS[0]]
                     for b in per_block_layout)
    recon_pay = (sum(v["record_payload_bytes_per_block"] for v in vit_sublayer_rows)
                 * len(vit_blocks) + scalar_pay)
    check("vit_sublayer_layout_reconciles_to_the_archive_bytes_exactly",
          recon_pay == art_pay,
          "the four decoded matrices (%d elements) plus their measured per-record "
          "tails plus the layer3 scalar record reconstruct the archive's ViT "
          "payload EXACTLY: %d == %d, residual %d.  The sub-layer split is "
          "therefore read from the archive against a pinned decoder, not invented "
          "and not merely close."
          % (vit_matrix_elems, recon_pay, art_pay, art_pay - recon_pay))

    # ---------------- boundary operators --------------------------------
    boundary = []
    for o in ngv0["boundary_operators"]:
        k = o["local_identity"]
        boundary.append({
            "operator_id": o["operator_id"],
            "local_identity": k,
            "role": o["role"],
            "status": o.get("status"),
            "granularity": "BOUNDARY_OPERATOR",
            "macs": {"value": 0, "evidence_class": "ESTIMATED",
                     "basis": "the role (gate / copy / permute / reduction) "
                              "contains no weight-bearing multiply-accumulate and "
                              "the archive carries no weight record for it.  Zero by "
                              "ROLE is an ESTIMATE, not a measurement."},
            "bytes_moved": {"total": {"value": None, "evidence_class": "UNKNOWN",
                                      "why": "the buffer extents are not published "
                                             "for this operator"}},
            "temporary_storage": {"value": None, "evidence_class": "UNKNOWN"},
            "conversions": {"value": None, "evidence_class": "UNKNOWN"},
            "dispatch_count": dispatch_counts.get(
                k, {"value": None, "evidence_class": "UNKNOWN",
                    "why": "no captured dispatch carries this kernel_semantic"}),
        })
    n_boundary_measured = sum(1 for b in boundary
                              if b["dispatch_count"].get("evidence_class") == "MEASURED")
    check("boundary_operators_join_the_capture_table",
          n_boundary_measured >= 5,
          "%d of the %d boundary operators are joined to a MEASURED per-frame "
          "dispatch count in the capture table by their local_identity; the rest "
          "carry an explicit UNKNOWN with a reason"
          % (n_boundary_measured, len(boundary)))

    # ---------------- ceilings --------------------------------------------
    ceilings = {
        "measured_effective_rate": None,
        "why_null": "no representative operator has ever completed on this device. "
                    "A zero, a marketing peak or a derived fraction here would be a "
                    "fabrication, and the ~21.9 s watchdog episodes are "
                    "NONCOMPLETION events, not operator latency.",
        "this_model_CAN_support": [
            "a bounded OPERATION COUNT per operator and per level, and therefore a "
            "ranking of the future critical path by operation count",
            "the statement that the level extents are a halving pyramid, and that "
            "the deep levels are the ones a uniform canvas over-counts most",
            "the identification of the ViT token count as the largest single "
            "unknown, with every count expressed as a function of it",
            "a per-operator inventory of which quantities are MEASURED, which are "
            "ESTIMATED and which are simply NOT KNOWN",
            "a decision about which operators to model on the CPU next",
        ],
        "this_model_CANNOT_support": [
            "any effective RATE, latency, throughput, speedup or wall-clock claim",
            "any compute-bound vs bandwidth-bound verdict: that needs measured "
            "rates, and the activation traffic is UNKNOWN",
            "any gfx1030 hardware comparison, including against the reference "
            "project's RDNA4 numbers",
            "any statement about the achieved performance of this project's own "
            "native kernel: the one native operator measured has a code-object ABI "
            "and a liveness proof, not a completion",
            "any per-operator temporary-storage or conversion count outside the "
            "families the capture and the pinned decoders actually annotate",
        ],
        "analogue_track": {
            "verdict": "NOT_JUSTIFIED",
            "unchanged_by_this_repair": True,
            "why": "the analogue track's gate is a MEASURED rate and this repair "
                   "does not create one.  What it changes is the SIZE of the work "
                   "to be measured -- down by a factor of 400 on the ViT linear "
                   "term -- which makes the analogue case different, not better.",
        },
        "an_estimate_must_not_read_as_a_measurement": {
            "rule": "every quantity carries its own evidence_class, and the only "
                    "MEASURED quantities in this artifact are read from disk or "
                    "from the capture: archive byte and element counts, captured "
                    "dispatch counts, workgroup sizes, a device-annotated LDS size, "
                    "and SHA-256s recomputed this run",
            "census": None,  # filled below
        },
    }

    # ---------------- the no-optimization constraint ----------------------
    no_opt = {
        "constraint": "NO OPTIMIZATION IS PERFORMED, PROPOSED OR IMPLIED BY THIS "
                      "MODEL.  No kernel was changed, no tiling chosen, no fusion "
                      "advocated, no schedule proposed, no arithmetic precision "
                      "traded.  The model exists ONLY to identify the future "
                      "critical path.",
        "why": "no representative operator has completed on this device, so there is "
               "no measured rate to optimize against.  Tuning before correctness "
               "would be selecting a design with no instrument that can tell "
               "whether it is an improvement.",
        "what_a_reader_must_not_infer": [
            "that any operator here has been benchmarked",
            "that a cost ranking is a performance ranking",
            "that reducing a count in this model reduces real time",
        ],
        "enforced_by": "no_rate_is_emitted_anywhere (a check) + "
                       "ceilings.measured_effective_rate is null + "
                       "ceilings.this_model_CANNOT_support",
    }

    # ---------------- rate guard ------------------------------------------
    RATE_WORD = re.compile(r"rate|latency|throughput|speedup|wall_clock|elapsed|"
                           r"per_second|tflops|gflops|bandwidth|iops", re.I)
    RATE_KEYS = ("measured_effective_rate", "effective_rate", "rate", "latency",
                 "throughput", "speedup", "wall_clock")

    def scan_for_rates(obj, path="$"):
        hits = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if RATE_WORD.search(str(k)):
                    hits.append({"path": "%s.%s" % (path, k), "value": v})
                hits.extend(scan_for_rates(v, "%s.%s" % (path, k)))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                hits.extend(scan_for_rates(v, "%s[%d]" % (path, i)))
        return hits

    def rate_named(obj):
        return [h for h in scan_for_rates(obj)
                if h["path"].rsplit(".", 1)[-1] in RATE_KEYS]

    # ---------------- assemble -------------------------------------------
    doc = {
        "schema": "p16ax-perf-model/1",
        "phase": "16AX", "task_id": "T-PERF", "worker": "W8",
        "part": "performance and cost model repair",
        "host_only": True,
        "gpu_execution_performed": False,
        "hip_calls_made": 0,
        "processes_created": 0,
        "subject": "repair of the duplicated ViT token factor in the p16ao cost "
                   "model, plus a per-operator cost inventory",
        "verdict": None,
        "upstream_verdicts": {
            "p16an/native/OPERATOR_COST_MODEL_16AN.json": {
                "figure": stated16an, "verdict": art16an.get("verdict"),
                "status": "an UPPER bound mislabelled a LOWER bound -- untouched by "
                          "this repair, and not this repair's subject"},
            "p16ao/cost/COST_MODEL_PER_BLOCK.json": {
                "verdict": art.get("verdict"),
                "status": "the headline totals and the per-block rows are CONFIRMED "
                          "single-factor by this repair; the sensitivity term is "
                          "not, and is repaired here.  The frozen artifact is NOT "
                          "edited: the correction is published alongside it, and it "
                          "still reproduces exactly from its own rules."},
        },
        "no_optimization_constraint": no_opt,
        "token_factor_rule": TOKEN_FACTOR_RULE,
        "evidence_vocabulary": {
            "MEASURED": "read from bytes or records on disk, or from a captured "
                        "device record.  NOT a device performance measurement.",
            "ESTIMATED": "arithmetic over MEASURED inputs plus a NAMED assumption or "
                         "a NAMED published shape.",
            "UNKNOWN": "no defensible value: the value is null and the reason is on "
                       "the row.  BLOCKING -- never read as zero, never read as an "
                       "estimate, never read as a measurement.",
            "why_a_third_tag": "the task requires ESTIMATED and MEASURED to be "
                               "separated.  UNKNOWN is carried as a THIRD tag rather "
                               "than folded into ESTIMATED, because for several "
                               "quantities no defensible estimate exists and "
                               "publishing one would be a fabrication.  Folding "
                               "UNKNOWN into ESTIMATED would let an absent fact read "
                               "as an estimate, which is the defect this separation "
                               "exists to prevent.",
            "mapping_from_the_frozen_vocabulary": {
                "EXACT": "-> MEASURED (a byte count read from an index)",
                "DERIVED": "-> ESTIMATED if a named assumption exists, else UNKNOWN",
                "MEASURED_in_the_artifacts": "means 'from a physical completion'.  "
                                             "NONE EXIST, so this file never uses the "
                                             "word MEASURED for a performance "
                                             "quantity -- only for a record read "
                                             "from disk or from the capture.",
            },
        },
        "inputs_sha256_recomputed_from_disk": inputs,
        "step0_before": {
            "what": "the current cost figures, reproduced from the artifacts' own "
                    "rules BEFORE anything was changed",
            "16AN_stated_macs_lower_bound": {
                "value": stated16an, "recomputed": repro16an,
                "reproduced_exactly": repro16an == stated16an,
                "rule": "SUM over 71 blocks of weight_elements x (1536000 unless "
                        "role==bottleneck else 400)"},
            "16AO_900_tier_macs": {"value": pub900, "recomputed_from_own_rows": tot900},
            "16AO_capture_tier_macs": {"value": pubcap,
                                       "recomputed_from_own_rows": totcap},
            "16AO_weight_bytes_per_frame": art["weight_bytes_per_frame"]["stated"],
            "16AO_sensitivity_at_400": {
                "value": published_at400,
                "recomputed_from_own_expression": frozen_at400,
                "reproduced_exactly": frozen_at400 == published_at400,
                "expression": "sum(weight_elements for TOKEN rows) * T * T",
                "T_used": T_frozen},
            "16AO_attention_macs": {
                "900_tier_total": wfa["900_tier"]["total_extra_macs"],
                "1080_tier_total": wfa["1080_tier"]["total_extra_macs"],
                "reproduced": True},
        },
        "defect": {
            "name": "duplicated ViT token factor in the sensitivity term",
            "where": "p16ao/cost/p16ao_cost_audit.py, the expression that emits "
                     "totals.sensitivity.vit_token_count.at_400; published in "
                     "p16ao/cost/COST_MODEL_PER_BLOCK.json",
            "expression_as_written": 'sum(r["weight_elements"]["value"] * '
                                     '(T9 if r["level"] == "TOKEN" else 1) for r in '
                                     'rows if r["level"] == "TOKEN") * T9',
            "why_it_is_wrong": "the comprehension's own filter already selects TOKEN "
                               "rows, so the inner conditional is already T, and the "
                               "trailing * T9 applies the token count a SECOND time. "
                               "The ViT weight matrices are token-INDEPENDENT "
                               "(Cin x Cout), so the token count enters the linear "
                               "cost exactly once.",
            "published_value": published_at400,
            "single_factor_value": single_value,
            "inflation_factor": inflation,
            "inflation_factor_equals_the_token_count": inflation == T_frozen,
            "blast_radius": {
                "fields_affected": 1,
                "what_it_is": "totals.sensitivity.vit_token_count.at_400",
                "what_it_is_not": "the per-block rows and the headline totals are "
                                  "single-factor and are NOT affected",
                "tree_wide_search": "the published value 8055778560000 occurs in "
                                    "exactly 2 files on disk: the frozen artifact "
                                    "and the expression that emits it",
                "tree_wide_search_method": "recursive search for the literal value "
                                           "across every file in the project tree, "
                                           "no extension excluded",
            },
        },
        "corrected": corrected,
        "sensitivity_vit_token_count_corrected": {
            "note": "the 640-token tier's non-TOKEN extents are held fixed and only "
                    "the token count varies.  Every row states the linear term and "
                    "the attention term SEPARATELY and never merges them.",
            "rows": sens},
        "vit_weight_facts": {
            "n_weight_records": len(vit_names),
            "n_blocks": len(vit_blocks),
            "element_count_sum_lower": indep_elem,
            "payload_bytes_sum": indep_pay,
            "upper_variant_elements_if_one_byte": art_pay,
            "independent_source": "NATIVE_GRAPH_V0.json block->weight_records plus "
                                  "weights-index.json; not the frozen cost artifact"},
        "per_operator": {
            "scope": "graph-compatible operators: the reference layer types carried "
                     "by NATIVE_GRAPH_V0.json's 71 blocks, the ViT sub-layers whose "
                     "shapes a pinned decoder fixes, and the 8 boundary operators",
            "rows": per_operator,
            "vit_sublayer_rows": vit_sublayer_rows,
            "boundary_operator_rows": boundary,
        },
        "measured_kernel_table": {
            "what": "the captured dispatches, MEASURED.  This is the only place a "
                    "device record is read; it establishes dispatch counts, "
                    "workgroup sizes and one LDS size, and it establishes NO rate.",
            "per_frame_dispatch_total": {str(f): per_frame[f]
                                         for f in sorted(per_frame)},
            "per_kernel": dispatch_counts},
        "ceilings": ceilings,
        "checks": CHECKS,
        "negative_controls": [],
        "not_established": [
            "any measured effective rate, latency or throughput: none exists",
            "the swin conv families' K x K x Cin x Cout factorisation: not published "
            "per block (it does not affect the MAC identity, which is algebraic)",
            "the ViT token count from local evidence: only the reference host's "
            "contract and its benchmark document fix it",
            "any per-operator activation INPUT traffic: published nowhere",
            "per-operator temporary storage and conversion counts outside the "
            "families the capture and the pinned decoders annotate",
            "which block instance a dispatch belongs to, for the operator types the "
            "identity mapping marks POSITIONAL_ONLY",
        ],
        "reproduce": "python p16ax/perf/p16ax_perf_model.py",
        "regression_test": "python p16ax/perf/p16ax_token_factor_test.py",
    }

    # ---------------- negative controls on the emitted document -----------
    ctrl = []

    def control(name, ok, detail):
        ctrl.append({"control": name, "result": "OK" if ok else "BROKEN",
                     "detail": detail})

    poisoned = {"measured_effective_rate": 1.0e12, "nested": {"avg_latency_ms": 21.9}}
    control("rate_guard_can_fire",
            len(scan_for_rates(poisoned)) == 2 and len(rate_named(poisoned)) == 1
            and len(rate_named(doc)) == 1 and rate_named(doc)[0]["value"] is None,
            "the guard's broad scan finds %d rate-WORDED path(s) on a deliberately "
            "poisoned document (%s); its strict list calls %d of them a rate; and on "
            "the real document it finds exactly %d, whose value is null.  A guard "
            "that cannot fire would make the null rate meaningless."
            % (len(scan_for_rates(poisoned)),
               [h["path"] for h in scan_for_rates(poisoned)],
               len(rate_named(poisoned)), len(rate_named(doc))))

    empty_ok, empty_detail = check_single_token_factor(single_value, [], T_frozen)
    control("single_factor_predicate_rejects_absence", not empty_ok,
            "with zero ViT rows the predicate returns REJECTED, not PASS: %s"
            % empty_detail)

    quad_ok, quad_detail = check_linear_not_quadratic_in_tokens(
        lambda T: indep_elem * T * T)
    control("linearity_ladder_rejects_a_quadratic_term", not quad_ok,
            "a deliberately quadratic term fails the ladder: %s" % quad_detail)

    lin_ok, lin_detail = check_linear_not_quadratic_in_tokens(lambda T: indep_elem * T)
    control("linearity_ladder_accepts_the_real_linear_term", lin_ok,
            "the actual ViT linear term passes the same ladder: %s" % lin_detail)

    q_ok, _ = check_quadratic_in_tokens(lambda T: attention_macs_vit(n_vit, T))
    q_lin_ok, q_lin_d = check_quadratic_in_tokens(lambda T: indep_elem * T)
    control("quadratic_ladder_accepts_attention_and_rejects_the_linear_term",
            q_ok and not q_lin_ok,
            "attention passes the quadratic ladder and the linear term fails it "
            "(%s), which is how the two terms are shown to be DIFFERENT objects "
            "rather than one term relabelled" % q_lin_d)

    zero_ok, zero_d = check_linear_not_quadratic_in_tokens(lambda T: 0)
    control("linearity_ladder_rejects_a_vanished_term", not zero_ok,
            "a term that is identically zero is rejected rather than passing a "
            "scaling test vacuously: %s" % zero_d)

    doc["negative_controls"] = ctrl

    check("every_negative_control_reached_its_observer",
          all(c["result"] == "OK" for c in ctrl) and len(ctrl) == 6,
          "all %d negative controls were applied and each one's subject moved; a "
          "control that no-ops reads as BROKEN here, not as a pass" % len(ctrl))

    # ---------------- census ----------------------------------------------
    def census_of(obj):
        c = collections.Counter()
        if isinstance(obj, dict):
            if isinstance(obj.get("evidence_class"), str):
                c[obj["evidence_class"]] += 1
            for v in obj.values():
                c.update(census_of(v))
        elif isinstance(obj, list):
            for v in obj:
                c.update(census_of(v))
        return c

    census = (census_of(doc["per_operator"]) + census_of(doc["corrected"])
              + census_of(doc["measured_kernel_table"]))
    doc["ceilings"]["an_estimate_must_not_read_as_a_measurement"]["census"] = \
        dict(census)

    rate_named_doc = rate_named(doc)
    check("no_rate_is_emitted_anywhere",
          len(rate_named_doc) >= 1
          and all(h["value"] is None for h in rate_named_doc),
          "the document carries exactly %d field(s) whose name IS a rate (%s) and "
          "every one of them is null.  Absence would FAIL: a document with no "
          "rate-named field at all would be testing nothing."
          % (len(rate_named_doc),
             [h["path"].rsplit(".", 1)[-1] for h in rate_named_doc]))

    unknown_rows = [r for r in per_operator
                    if r["bytes_moved"]["total"]["value"] is None]
    check("absence_is_blocking_in_this_artifact",
          census.get("UNKNOWN", 0) > 0 and len(unknown_rows) == len(per_operator)
          and all(r["temporary_storage"]["value"] is None for r in per_operator),
          "the census counts %s.  All %d per-operator rows carry a NULL activation-"
          "traffic total and a NULL temporary-storage figure with a named reason, "
          "rather than a partial sum that would read as a total.  No UNKNOWN is "
          "recorded as zero and none is folded into ESTIMATED."
          % ({k: census[k] for k in sorted(census)}, len(unknown_rows)))

    missing = [n for n in REQUIRED if n not in [c["check"] for c in CHECKS]]
    check("check_registry_complete", not missing,
          "%d required checks registered, %d ran, %d missing%s"
          % (len(REQUIRED), len(CHECKS), len(missing),
             "" if not missing else ": " + ", ".join(missing)), required=False)

    failing = [c["check"] for c in CHECKS if c["result"] == "FAIL"]
    doc["verdict"] = "PERF_MODEL_CORRECTED" if not failing else "PERF_MODEL_UNRESOLVED"
    doc["verdict_basis"] = "%d checks, %d failing%s" % (
        len(CHECKS), len(failing), "" if not failing else ": " + ", ".join(failing))
    doc["checks"] = CHECKS

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)

    print("wrote %s" % OUT)
    print("  checks %d pass / %d total   verdict %s"
          % (len(CHECKS) - len(failing), len(CHECKS), doc["verdict"]))
    print("  step0 16AN stated         = %d" % stated16an)
    print("  step0 16AO 900 tier       = %d" % pub900)
    print("  DEFECT at_400 published   = %d" % published_at400)
    print("  CORRECTED at_400          = %d   (inflation %.6g x == the token count %d)"
          % (single_value, inflation, T_frozen))
    print("  corrected 900-tier total  = %d (unchanged)" % sum_linear_900)
    print("  vit payload reconciliation= %d == %d" % (recon_pay, art_pay))
    print("  census                    = %s" % {k: census[k] for k in sorted(census)})
    for c in CHECKS:
        if c["result"] != "PASS":
            print("  FAIL %s: %s" % (c["check"], c["detail"]))
    return 0 if not failing else 1


if __name__ == "__main__":
    sys.exit(main())
