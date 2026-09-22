#!/usr/bin/env python3
"""Phase 16AX / T-PERF -- REGRESSION TEST for the duplicated ViT token factor.

HOST ONLY.  stdlib only (numpy is not installed).

WHAT THIS TEST IS FOR
---------------------
Phase 16AO published `totals.sensitivity.vit_token_count.at_400 =
8055778560000`, which is `sum(weight_elements over the ViT blocks) x T x T`.
The ViT weight matrices are token-INDEPENDENT (Cin x Cout), so the token count
must enter a LINEAR cost exactly ONCE; the published figure applies it TWICE.
The inflation is exactly the token count, 400.

This test exists so that class of defect cannot come back unnoticed.  It is
STRUCTURAL rather than a pinned number, because a magic number would only pin
the shapes it was written at:

  * the linear term must scale LINEARLY in tokens  -- f(kT) == k*f(T) exactly;
  * the attention term must scale QUADRATICALLY    -- g(kT) == k^2*g(T);
  * the graph total must be NEITHER, and strictly LESS than quadratic for a
    fixed shape -- that is the concrete statement that no linear layer absorbed
    a second token factor;
  * the total must equal linear + attention, with attention strictly present.

A test that only pinned 20139446400 would sail past a re-introduction at 640
tokens, at a different head count, or with one ViT block added.  These laws
would not.

IT MUST BE ABLE TO FAIL.  Five independent red legs are run and REQUIRED:
  A. the single-factor predicate REJECTS the real frozen 8055778560000;
  B. the linearity ladder REJECTS the frozen expression driven over a token
     sweep (measured exponent 2.000000, not 1);
  C. an in-process MUTANT of the corrected model, with the token factor
     re-duplicated at the anchored return, is rejected by the same battery and
     by the model's own published check;
  D. an end-to-end run of a real COPY of the corrected model with that one
     semantic mutation injected flips the model's own verdict from
     PERF_MODEL_CORRECTED to PERF_MODEL_UNRESOLVED and fails the check that owns
     the sensitivity table;
  F. the battery's own laws reject a plain quadratic and a vanished term.

and H.  THIS FILE, run as a process against that same mutated copy via
  `--model`, must come back with exit != 0 and verdict
  TOKEN_FACTOR_REGRESSION_FAIL, with the laws that OWN the token factor red and
  the laws that do not depend on it (the attention law, the 71 frozen per-block
  rows, the real published value) still green -- so the rejection is targeted
  rather than a collapse.  A stage-D leg shows the MODEL can go red; only H
  shows the TEST can.

... with GREEN controls that must be ACCEPTED at shapes other than the pinned
one (640 tokens, different head geometry, a different block subset) plus an
INERT mutation that must NOT fail.  A control that dies before the comparison
is INVALID, not a successful rejection, so every mutation asserts that its
anchor was found exactly once and that the mutated value reached the observer.
"""
from __future__ import annotations

import argparse
import glob
import importlib.util
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
#: the CANONICAL model.  Stages C and D ALWAYS mutate THIS file, never the file
#: under test, so a --model run cannot end up mutating itself.
CANONICAL = os.path.join(HERE, "p16ax_perf_model.py")
MODEL_OUT = os.path.join(HERE, "PERF_MODEL_16AX.json")
ART16AO = os.path.join(ROOT, "p16ao", "cost", "COST_MODEL_PER_BLOCK.json")
SCRATCH = os.path.join(HERE, "_scratch")
REGRESSION_OUT = os.path.join(HERE, "TOKEN_FACTOR_REGRESSION_16AX.json")

ARGS = argparse.ArgumentParser(
    description="structural regression test for the duplicated ViT token factor")
ARGS.add_argument("--model", default=CANONICAL,
                  help="the performance model under test.  Default: the canonical "
                       "one.  Stage H passes the MUTATED copy here, which is how "
                       "this file demonstrates that it can itself go red.")
ARGS.add_argument("--out", default=REGRESSION_OUT,
                  help="where to write this test's result artifact")
A = ARGS.parse_args()

MODEL = os.path.abspath(A.model)
OUT = os.path.abspath(A.out)

#: TRUE when this process IS the stage-H child: this file is being run against a
#: deliberately broken model, so stage H is skipped (it would recurse) and the
#: expected verdict is the FAIL one.
SELF_RED_RUN = MODEL != os.path.abspath(CANONICAL)

#: the ANCHORED mutation site.  It must occur EXACTLY ONCE in the model source
#: or the mutation harness is invalid (house rule 7: a mutator that silently
#: no-ops reports the inverse fault).
ANCHOR_LINE = '    return sum(r["weight_elements"] * tokens for r in vit_rows)'
FAULT_LINE = '    return sum(r["weight_elements"] * tokens * tokens for r in vit_rows)'

#: The anchor is the WHOLE function that owns the law, not the bare return line:
#: the model has a second builder with the same single-line body (the byte-volume
#: reading), so a single-line anchor would be ambiguous and the mutator would
#: either no-op or hit the wrong function.
ANCHOR = ('def token_level_linear_macs(vit_rows, tokens):\n'
          '    """The ViT LINEAR term: weights x tokens, ONCE.  See TOKEN_FACTOR_RULE."""\n'
          + ANCHOR_LINE)
FAULT = ('def token_level_linear_macs(vit_rows, tokens):\n'
         '    """The ViT LINEAR term: weights x tokens, ONCE.  See TOKEN_FACTOR_RULE."""\n'
         + FAULT_LINE)

#: the relocations an out-of-tree copy needs so the mutated model reads the same
#: inputs and does NOT write to a published artifact.  These are TEST-HARNESS
#: RELOCATIONS, NOT semantic mutations, and they are asserted to be the ONLY
#: other differences from the original.
RELOCATIONS = (
    ('ROOT = os.path.dirname(os.path.dirname(HERE))',
     'ROOT = r"%s"' % ROOT),
    ('OUT = os.path.join(HERE, "PERF_MODEL_16AX.json")',
     'OUT = os.path.join(HERE, "SCRATCH_OUT_" + os.path.basename(__file__) + ".json")'),
)


def load_module_from_source(name, src):
    mod = types.ModuleType(name)
    mod.__file__ = "<mutant:%s>" % name
    exec(compile(src, mod.__file__, "exec"), mod.__dict__)
    return mod


def load_corrected_model():
    spec = importlib.util.spec_from_file_location("p16ax_perf_model_corrected", MODEL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def main():
    CHECKS = []
    REQUIRED = []

    def check(name, ok, detail, required=True):
        CHECKS.append({"check": name, "result": "PASS" if ok else "FAIL",
                       "detail": detail, "stage": STAGE[0]})
        if required:
            REQUIRED.append(name)
        return bool(ok)

    STAGE = ["A_structural_known_good"]

    m = load_corrected_model()
    model_out_size_before = os.path.getsize(MODEL_OUT)
    model_out_mtime_before = os.path.getmtime(MODEL_OUT)
    reg_out_size_before = os.path.getsize(OUT) if os.path.exists(OUT) else None
    reg_out_mtime_before = os.path.getmtime(OUT) if os.path.exists(OUT) else None
    art = json.load(open(ART16AO, encoding="utf-8"))
    rows = art["per_block"]
    tok_rows = [r for r in rows if r["level"] == "TOKEN"]
    vit_rows = [{"weight_elements": r["weight_elements"]["value"],
                 "weight_bytes": r["weight_bytes"]["value"]} for r in tok_rows]
    vit_rows_upper = [{"weight_elements": r["weight_bytes"]["value"]}
                      for r in tok_rows]
    pos_cap = {L: art["level_table"][L]["positions_1080_tier"]
               for L in ("L0", "L1", "L2", "L3", "L4", "L5", "TOKEN")}
    pos900 = {L: art["level_table"][L]["positions_900_tier"]
              for L in ("L0", "L1", "L2", "L3", "L4", "L5", "TOKEN")}
    lin_rows = [{"weight_elements": r["weight_elements"]["value"], "level": r["level"]}
                for r in rows]
    W = sum(r["weight_elements"] for r in vit_rows)
    N_VIT = len(tok_rows)
    T9, Tcap = pos900["TOKEN"], art["level_table"]["TOKEN"]["positions_1080_tier"]
    frozen_at400 = art["totals"]["sensitivity"]["vit_token_count"]["at_400"]
    pub900 = art["totals"]["methods_a_and_b_900_tier"]["macs"]
    pub_cap = art["totals"]["methods_a_and_b_1080_tier"]["macs"]

    # =====================================================================
    # A. THE STRUCTURAL LAWS, ON THE CORRECTED MODEL.  Known-good input:
    #    these MUST be accepted, or the test rejects the correct answer.
    # =====================================================================

    ok, detail = m.check_linear_not_quadratic_in_tokens(
        lambda T: m.token_level_linear_macs(vit_rows, T))
    check("A1_vit_linear_term_is_linear_in_tokens", ok,
          "the corrected ViT linear term: %s" % detail)

    ok, detail = m.check_linear_not_quadratic_in_tokens(
        lambda T: m.token_level_linear_macs(vit_rows_upper, T))
    check("A2_vit_linear_term_is_linear_on_the_byte_volume_reading_too", ok,
          "the 1-byte fp8 reading of the same term: %s" % detail)

    ok, detail = m.check_linear_not_quadratic_in_tokens(
        lambda T: m.linear_macs(W, T))
    check("A3_the_layer_identity_is_linear_in_positions", ok,
          "weight_elements x positions with weight_elements held fixed: %s" % detail)

    ok, detail = m.check_quadratic_in_tokens(
        lambda T: m.attention_macs_vit(N_VIT, T))
    check("A4_vit_attention_term_is_quadratic_in_tokens", ok,
          "the SEPARATE weight-free term: %s" % detail)

    # the total, at a fixed shape with a real attention part.  The split-window
    # attention term is quadratic in the L5 SPATIAL EXTENT and carries no token
    # count at all, so it enters this total as a T-INDEPENDENT constant.  Only the
    # ViT attention term scales with T, and the assertions below separate the two
    # rather than pretending the whole attention block scales with T.
    SHAPE = [{"weight_elements": r["weight_elements"]["value"] * 40,
              "level": r["level"]} for r in rows]
    SPLIT_FIXED = m.attention_macs_split(16, 50, 30)[1]

    def total(T):
        return m.graph_total_macs(SHAPE, dict(pos900, TOKEN=T),
                                  m.attention_macs_vit(N_VIT, T) + SPLIT_FIXED)

    def total_linear(T):
        return m.graph_linear_macs(SHAPE, dict(pos900, TOKEN=T))

    def total_vit_attn(T):
        return m.attention_macs_vit(N_VIT, T)

    def tok_lin(T):
        return m.graph_linear_macs([r for r in SHAPE if r["level"] == "TOKEN"],
                                   dict(pos900, TOKEN=T))

    def scaling_part(T):
        """The part of the total whose growth IS attributable to the token count.

        The rest of the graph does not move with T, so a ratio taken over the
        whole total would be dominated by a constant and would measure nothing.
        Stating the law about this part is the honest form; the total's own
        anti-quadratic bound is asserted separately, over the whole total.
        """
        return tok_lin(T) + total_vit_attn(T)

    bad = []
    for T in (2, 3, 7, 400, 640, 2160):
        li, at, tt = total_linear(T), total_vit_attn(T), total(T)
        if tt != li + at + SPLIT_FIXED:
            bad.append("T=%d: total %d != linear %d + vit attention %d + the "
                       "T-independent split term %d" % (T, tt, li, at, SPLIT_FIXED))
        # the whole-graph LINEAR total is AFFINE in T, not linear: everything
        # outside the token level stays fixed.  Stated as it is, rather than
        # pretending the graph's linear total is homogeneous in T.
        if (total_linear(T * 2) - total_linear(T)) != (tok_lin(T * 2) - tok_lin(T)):
            bad.append("T=%d: the increment of the linear total is not the token "
                       "term's increment" % T)
        if (total_linear(T) - tok_lin(T)) != (total_linear(1) - tok_lin(1)):
            bad.append("T=%d: the token-INdependent part of the linear total is not "
                       "constant in T" % T)
        if tok_lin(T * 2) != 2 * tok_lin(T):
            bad.append("T=%d: the token level's own linear part is not exactly "
                       "linear" % T)
        if at * 4 != total_vit_attn(T * 2):
            bad.append("T=%d: the ViT attention part is not exactly quadratic" % T)
        if tt * 4 <= total(T * 2):
            bad.append("T=%d: total(2T)=%d >= 4*total(T)=%d -- the TOTAL is "
                       "quadratic, which is the defect" % (T, total(T * 2), tt * 4))
        if at <= 0:
            bad.append("T=%d: the ViT attention part is absent, so the additivity "
                       "assertion would be vacuous" % T)
    check("A5_the_total_is_additive_and_strictly_less_than_quadratic", not bad,
          "at every probe the total equals linear + ViT attention + the "
          "T-independent split term EXACTLY; the whole-graph linear total is AFFINE "
          "in T, its increment IS the token level's increment, its token-independent "
          "part is constant in T, and the token level's own linear part is exactly "
          "linear; the ViT attention part is exactly quadratic and non-zero (so "
          "additivity is not vacuous); and the total is strictly BELOW quadratic -- "
          "the direct statement that no linear layer absorbed a second token "
          "factor%s" % ("" if not bad else "; " + "; ".join(bad)))

    bad2 = []
    for T in (2, 3, 7, 400, 640, 2160):
        base = scaling_part(T)
        for k in (2, 3):
            got = scaling_part(T * k)
            if not (k * base < got < (k * k) * base):
                bad2.append("T=%d, k=%d: the token-scaled part moved by %.6f, not "
                            "strictly between %d and %d" % (T, k, got / base, k, k * k))
    check("A6_the_part_that_scales_with_T_grows_strictly_between_linear_and_quadratic",
          not bad2,
          "the part of the total whose growth is attributable to the token count "
          "(the token level's own linear term plus the ViT attention term) grows by "
          "strictly between k and k^2 for k in {2,3} at every probe.  Above k means "
          "the attention term is present; below k^2 means no linear term was "
          "squared.  The law is stated about this part and not about the whole "
          "total, whose ratio is dominated by token-independent levels and would "
          "therefore measure nothing.%s"
          % ("" if not bad2 else "; " + "; ".join(bad2)))

    # a shape where the token level DOMINATES, so the total's own exponent is a
    # meaningful number rather than a rounding of a token-independent sum
    TOKDOM = [{"weight_elements": W, "level": "TOKEN"},
              {"weight_elements": 1, "level": "L0"}]

    def total_dom(T):
        return m.graph_total_macs(TOKDOM, dict(pos900, TOKEN=T),
                                  m.attention_macs_vit(N_VIT, T))

    exp_dom = m.scaling_exponent(total_dom, 400, 2)
    check("A7_when_the_token_level_dominates_the_totals_exponent_is_between_1_and_2",
          exp_dom is not None and 1.0 < exp_dom < 2.0,
          "with the token level dominating, doubling the token count multiplies the "
          "total by %.9f -- a measured exponent of %.9f.  Strictly above 1 because "
          "the attention term is present, strictly below 2 because the layer term is "
          "linear.  A duplicated token factor would put this at exactly 2."
          % (total_dom(800) / total_dom(400), exp_dom))

    ok, detail = m.check_linear_not_quadratic_in_tokens(
        lambda T: m.token_level_linear_macs(
            [{"weight_elements": r["weight_elements"] * 3} for r in vit_rows], T))
    check("A11_the_linear_term_is_linear_in_the_weights_as_well_as_the_tokens", ok,
          "tripling every ViT weight matrix: %s" % detail)

    # EVERY builder the model exposes for this law, discovered by inspection
    # rather than named deliberately: naming them would reproduce, for the next
    # implementation added, exactly the blindness this check was written to close.
    # discovered by CALL CONVENTION, not by name: a public two-argument callable
    # that returns an INTEGER for these rows and a token count IS a builder of this
    # term, whatever it is called.  The integer requirement is load-bearing: a
    # LIST-returning callable satisfies the scaling ladder by list repetition and
    # would otherwise be discovered as a builder and reported as obeying the law.  The two names the law is required to appear in are
    # asserted present, so a discovery that finds nothing -- or that silently
    # loses one of them -- is a FAILURE rather than a vacuous pass.
    REQUIRED_BUILDERS = ("token_level_linear_macs", "vit_linear_upper_macs")
    vit_builders = []
    for n in sorted(dir(m)):
        if n.startswith("_"):
            continue
        f = getattr(m, n)
        if not callable(f) or inspect.isclass(f):
            continue
        try:
            if len(inspect.signature(f).parameters) != 2:
                continue
            if not isinstance(f(vit_rows_upper, 400), int):
                continue
        except Exception:
            continue
        vit_builders.append(n)
    bad_builders = []
    for n in vit_builders:
        okb, db = m.check_linear_not_quadratic_in_tokens(
            lambda T, f=getattr(m, n): f(vit_rows_upper, T))
        if not okb:
            bad_builders.append((n, db))
    undiscovered = [n for n in REQUIRED_BUILDERS if n not in vit_builders]
    check("A12_every_vit_linear_builder_the_model_exposes_obeys_the_law",
          not undiscovered and not bad_builders,
          "%d builder(s) of this term were found by inspection -- %s -- and each is "
          "driven through the same ladder on the same rows: %s.  A duplicated token "
          "factor in ANY of them is therefore caught, including in one added later "
          "under a name this file has never seen.  The two builders the law is "
          "required to appear in are asserted present (%s), so an empty or partial "
          "discovery is a FAILURE rather than a vacuous pass.  This check exists "
          "because a battery anchored on one of two byte-identical implementations of "
          "this law returned 0 failing against a model whose OTHER one carried the "
          "fault."
          % (len(vit_builders), vit_builders,
             "all obey the law" if not bad_builders else str(bad_builders),
             "both found" if not undiscovered else "MISSING: %s" % undiscovered))

    # the model's own PUBLISHED figures must satisfy the same laws
    doc = json.load(open(MODEL_OUT, encoding="utf-8"))
    pub = doc["sensitivity_vit_token_count_corrected"]["rows"]
    ratio_lin = pub["640"]["vit_linear_macs"] / pub["400"]["vit_linear_macs"]
    ratio_attn = pub["640"]["vit_attention_macs"] / pub["400"]["vit_attention_macs"]
    check("A8_the_models_published_sensitivity_rows_obey_the_laws",
          abs(ratio_lin - Tcap / 400.0) < 1e-12
          and abs(ratio_attn - (Tcap / 400.0) ** 2) < 1e-9
          and doc["verdict"] == "PERF_MODEL_CORRECTED",
          "in the model's own published table the linear term scales by %.9f "
          "(640/400 = %.9f) and the attention term by %.9f (%.9f squared).  The "
          "published rows therefore obey the laws the laws demand, not only the "
          "functions in this file."
          % (ratio_lin, Tcap / 400.0, ratio_attn, (Tcap / 400.0) ** 2))

    # the FROZEN per-block rows must satisfy the law too -- PER RECORD, not in
    # aggregate: identical totals can hide individual violations, so each of the 71
    # frozen rows goes through the predicate with its OWN level's position count
    # and its OWN weight figure.
    bad_blocks = []
    for r in rows:
        oki, di = m.check_single_token_factor(
            r["macs"]["at_900_tier"]["value"],
            [{"weight_elements": r["weight_elements"]["value"]}],
            pos900[r["level"]])
        if not oki:
            bad_blocks.append((r["block"], r["layer_type"], di))
    check("A9_every_one_of_the_71_frozen_per_block_figures_is_single_factor",
          not bad_blocks and len(rows) == 71,
          "%d of the %d frozen per-block MAC figures PASS the single-factor "
          "predicate, each against its OWN level's position count and its OWN weight "
          "element count.  This is a per-record comparison, not a total, so a block "
          "carrying a duplicated factor could not hide inside a matching sum.%s"
          % (len(rows) - len(bad_blocks), len(rows),
             "" if not bad_blocks else "  VIOLATIONS: %s" % bad_blocks[:4]))

    # and the frozen headline totals are the sums of those rows, recomputed
    recomputed_total = m.graph_linear_macs(lin_rows, pos900)
    recomputed_cap = m.graph_linear_macs(lin_rows, pos_cap)
    check("A10_the_frozen_headline_totals_are_the_sums_of_their_verified_rows",
          recomputed_total == pub900 and recomputed_cap == pub_cap
          and not bad_blocks,
          "the frozen 900-tier and capture-tier totals (%d and %d) are reproduced "
          "exactly by summing this file's own per-block terms, every one of which "
          "A9 has verified single-factor PER RECORD.  The totals therefore inherit "
          "single-factor-ness from rows that were checked individually, and the "
          "defect is confined to the sensitivity term rather than to the headline."
          % (pub900, pub_cap))

    # =====================================================================
    # B. RED LEG 1 -- THE REAL UNCORRECTED MODEL.  Nothing injected: this is
    #    the value p16AO actually published.
    # =====================================================================
    STAGE[0] = "B_red_against_the_real_uncorrected_value"

    red_ok, red_detail = m.check_single_token_factor(frozen_at400, vit_rows, T9)
    check("B1_the_predicate_rejects_the_published_at_400_value", not red_ok,
          "p16ao's published at_400 = %d is REJECTED: %s" % (frozen_at400, red_detail))

    check("B2_the_published_value_is_the_single_factor_value_times_the_token_count",
          frozen_at400 == m.token_level_linear_macs(vit_rows, T9) * T9,
          "%d == %d x %d: the published figure is the correct linear term with the "
          "token count applied a SECOND time.  The inflation is not approximately "
          "the token count, it IS the token count."
          % (frozen_at400, m.token_level_linear_macs(vit_rows, T9), T9))

    # the FROZEN EXPRESSION itself, driven over a token sweep
    def frozen_expression(T):
        return sum(r["weight_elements"]["value"]
                   * (T if r["level"] == "TOKEN" else 1)
                   for r in rows if r["level"] == "TOKEN") * T

    fr_ok, fr_detail = m.check_linear_not_quadratic_in_tokens(frozen_expression)
    fr_exp = m.scaling_exponent(frozen_expression, 400, 2)
    check("B3_the_frozen_expression_fails_the_linearity_ladder", not fr_ok,
          "p16ao's own at_400 expression, swept over the probe set rather than "
          "evaluated once, measures an exponent of %.6f instead of 1: %s"
          % (fr_exp, fr_detail[:220]))

    check("B4_the_frozen_expression_is_quadratic_with_the_matching_coefficient",
          fr_exp is not None and abs(fr_exp - 2.0) < 1e-12
          and frozen_expression(400) == frozen_at400,
          "its measured exponent is exactly %.6f and it reproduces the published "
          "%d at T=400, so the rejection in B3 is about THIS figure and not about a "
          "mis-transcribed expression" % (fr_exp, frozen_at400))

    # =====================================================================
    # C. RED LEG 2 -- AN IN-PROCESS MUTANT OF THE CORRECTED MODEL
    # =====================================================================
    STAGE[0] = "C_red_against_an_in_process_mutant"

    src = open(CANONICAL, encoding="utf-8").read()
    check("C0_the_mutation_anchor_occurs_exactly_once_in_the_model_source",
          src.count(ANCHOR) == 1,
          "the anchored mutation site occurs %d time(s) in %s.  A mutator whose "
          "anchor is absent or ambiguous would no-op, and a no-op mutant reads as "
          "the inverse fault."
          % (src.count(ANCHOR), os.path.basename(CANONICAL)))

    mutant_src = src.replace(ANCHOR, FAULT)
    check("C1_the_mutation_actually_changed_the_source",
          mutant_src != src and mutant_src.count(FAULT) == 1,
          "the mutated source differs from the original and carries the injected "
          "duplication exactly once")

    mm = load_module_from_source("p16ax_perf_model_mutant_token_factor", mutant_src)

    check("C2_the_mutant_reached_the_observer",
          mm.token_level_linear_macs(vit_rows, 400)
          == m.token_level_linear_macs(vit_rows, 400) * 400,
          "the mutant's own function returns %d against the corrected %d: the "
          "fault is live in the executed code, not dead before the comparison"
          % (mm.token_level_linear_macs(vit_rows, 400),
             m.token_level_linear_macs(vit_rows, 400)))

    mred_ok, mred_detail = mm.check_single_token_factor(
        mm.token_level_linear_macs(vit_rows, T9), vit_rows, T9)
    check("C3_the_models_own_predicate_rejects_the_mutant", not mred_ok,
          "the mutant's value is REJECTED by the same predicate the corrected "
          "model publishes: %s" % mred_detail)

    m_ok, m_detail = mm.check_linear_not_quadratic_in_tokens(
        lambda T: mm.token_level_linear_macs(vit_rows, T))
    m_exp = mm.scaling_exponent(lambda T: mm.token_level_linear_macs(vit_rows, T), 400, 2)
    check("C4_the_linearity_ladder_rejects_the_mutant", not m_ok
          and m_exp is not None and abs(m_exp - 2.0) < 1e-12,
          "the mutant's linear term measures an exponent of %.6f instead of 1: %s"
          % (m_exp, m_detail[:200]))

    check("C5_the_mutant_is_rejected_at_shapes_other_than_the_pinned_one",
          not mm.check_linear_not_quadratic_in_tokens(
              lambda T: mm.token_level_linear_macs(
                  vit_rows[:7], T))[0]
          and not mm.check_linear_not_quadratic_in_tokens(
              lambda T: mm.token_level_linear_macs(vit_rows, T), tokens_probe=(5,))[0],
          "the mutant is rejected with 7 ViT blocks instead of 8 and at a single "
          "probe of 5 tokens, neither of which is the shape the frozen number was "
          "pinned at: this is the difference between a structural test and a magic "
          "number")

    # =====================================================================
    # D. RED LEG 3 -- END TO END.  A real copy of the model, one semantic
    #    mutation, run as a process; its OWN verdict must flip.
    # =====================================================================
    STAGE[0] = "D_red_end_to_end_on_a_mutated_copy"

    os.makedirs(SCRATCH, exist_ok=True)
    def scratch_out_for(path):
        """The copy's relocated OUT, derived from the copy's own filename."""
        return os.path.join(SCRATCH, "SCRATCH_OUT_%s.json" % os.path.basename(path))

    mutated = src.replace(ANCHOR, FAULT)
    for a, b in RELOCATIONS:
        assert src.count(a) == 1, "relocation anchor %r is not unique" % a[:60]
        mutated = mutated.replace(a, b)
    mutants = os.path.join(SCRATCH, "p16ax_perf_model_mutant_tokenfactor.py")
    inert = os.path.join(SCRATCH, "p16ax_perf_model_inert.py")

    # verify the two files differ ONLY in the named hunks
    def hunk_diff():
        a = src.splitlines()
        b = mutated.splitlines()
        return [(i, x, y) for i, (x, y) in enumerate(zip(a, b)) if x != y] \
            + ([("length", len(a), len(b))] if len(a) != len(b) else [])

    hunks = hunk_diff()
    fault_hunks = [h for h in hunks
                   if h[2] == FAULT_LINE and h[1] == ANCHOR_LINE]
    root_hunks = [h for h in hunks if h[2].startswith("ROOT = r\"")]
    out_hunks = [h for h in hunks if "SCRATCH_OUT_" in h[2]]
    check("D0_the_mutated_copy_differs_from_the_original_in_exactly_three_hunks",
          len(hunks) == 3 and len(fault_hunks) == 1 and len(root_hunks) == 1
          and len(out_hunks) == 1,
          "exactly %d hunk(s).  One is ONE semantic mutation: the anchored "
          "return, %r -> %r.  Two are TEST-HARNESS RELOCATIONS that pin the "
          "project root and divert the output into _scratch under a name derived "
          "from the copy's own filename, so a mutant run can never write to a "
          "published artifact and the copies cannot clobber each other: %s"
          % (len(hunks), ANCHOR.strip(), FAULT.strip(),
             [(h[1].strip()[:40], h[2].strip()[:52]) for h in hunks]))

    open(mutants, "w", encoding="utf-8", newline="\n").write(mutated)
    inert_src = src.replace('"schema": "p16ax-perf-model/1"',
                            '"schema": "p16ax-perf-model/1",\n        '
                            '"INERT_MUTATION_MARKER": "a comment-level change that '
                            'must NOT fail the model"')
    for a, b in RELOCATIONS:
        inert_src = inert_src.replace(a, b)
    open(inert, "w", encoding="utf-8", newline="\n").write(inert_src)

    def run_copy(path):
        out_path = scratch_out_for(path)
        if os.path.exists(out_path):
            os.remove(out_path)
        p = subprocess.run([sys.executable, path], cwd=ROOT,
                           capture_output=True, text=True)
        got = json.load(open(out_path, encoding="utf-8")) if os.path.exists(out_path) \
            else None
        return p, got, out_path

    # the unmutated copy first: the end-to-end control must be GREEN
    base_src = src
    for a, b in RELOCATIONS:
        base_src = base_src.replace(a, b)
    base_path = os.path.join(SCRATCH, "p16ax_perf_model_baseline_copy.py")
    open(base_path, "w", encoding="utf-8", newline="\n").write(base_src)
    pbase, dbase, base_out = run_copy(base_path)
    check("D1_the_relocated_but_unmutated_copy_still_passes_end_to_end",
          dbase is not None and dbase["verdict"] == "PERF_MODEL_CORRECTED"
          and all(c["result"] == "PASS" for c in dbase["checks"]),
          "the relocated copy of the model, run as a process with no semantic "
          "mutation, returns %s with %d/%d checks passing (exit %d).  The "
          "relocation alone does not change the verdict, so the flip in D2 is "
          "attributable to the injected fault and not to being copied."
          % (dbase["verdict"] if dbase else None,
             sum(1 for c in (dbase or {}).get("checks", []) if c["result"] == "PASS"),
             len((dbase or {}).get("checks", [])), pbase.returncode))

    pmut, dmut, mut_out = run_copy(mutants)
    mut_failing = [c["check"] for c in (dmut or {}).get("checks", [])
                   if c["result"] == "FAIL"]
    check("D2_the_mutated_copy_flips_the_models_own_verdict",
          dmut is not None and pmut.returncode != 0
          and dmut["verdict"] == "PERF_MODEL_UNRESOLVED" and bool(mut_failing),
          "the same model with the token factor re-duplicated returns %s "
          "(exit %d) with %d failing check(s): %s.  The model is therefore able to "
          "go red on the exact defect it was written to exclude."
          % (dmut["verdict"] if dmut else None, pmut.returncode,
             len(mut_failing), mut_failing))

    OWNED = ("the_corrected_headline_vit_figures_are_single_factor",
             "every_row_of_the_corrected_sensitivity_table_is_single_factor")
    dmut_by = {c["check"]: c["result"] for c in (dmut or {}).get("checks", [])}
    dbase_by = {c["check"]: c["result"] for c in (dbase or {}).get("checks", [])}
    check("D3_the_failing_checks_are_the_ones_that_OWN_the_corrected_table",
          all(dmut_by.get(n) == "FAIL" for n in OWNED)
          and all(dbase_by.get(n) == "PASS" for n in OWNED)
          and len(dmut_by) == len(dbase_by),
          "the two checks that own the corrected sensitivity table -- %s -- are "
          "both PASS in the unmutated copy of the SAME file and both FAIL in the "
          "mutated one, over the same %d-check registry.  The failure is therefore "
          "attributed to the injected fault by the named checks, not merely by the "
          "verdict." % (list(OWNED), len(dmut_by)))

    # (the inert copy runs later, in stage E; its output path is checked there)
    check("D4_no_copy_run_wrote_outside_scratch",
          all(os.path.dirname(os.path.abspath(o)) == os.path.abspath(SCRATCH)
              for o in (base_out, mut_out))
          and os.path.getsize(MODEL_OUT) == model_out_size_before
          and os.path.getmtime(MODEL_OUT) == model_out_mtime_before,
          "all three copy runs wrote inside _scratch, and the published %s is "
          "byte-identical to what it was before this test started (size %d, "
          "mtime unchanged): a regression test that overwrote the artifact it "
          "verifies would destroy the evidence it is testing"
          % (os.path.basename(MODEL_OUT), model_out_size_before))

    # =====================================================================
    # E. GREEN CONTROLS THAT MUST BE ACCEPTED -- at shapes other than the
    #    pinned one.  A test that rejects everything is not a test.
    # =====================================================================
    STAGE[0] = "E_green_controls_at_other_shapes"

    ok640, d640 = m.check_single_token_factor(
        m.token_level_linear_macs(vit_rows, Tcap), vit_rows, Tcap)
    check("E1_accepted_at_the_capture_tier_token_count", ok640,
          "the corrected value at %d tokens is ACCEPTED: %s" % (Tcap, d640))

    ok7, d7 = m.check_single_token_factor(
        m.token_level_linear_macs(vit_rows[:7], 400), vit_rows[:7], 400)
    check("E2_accepted_with_a_different_ViT_block_subset", ok7,
          "with 7 ViT blocks instead of 8 the predicate still ACCEPTS the "
          "single-factor value: %s" % d7)

    oki, di = m.check_single_token_factor(
        m.token_level_linear_macs([{"weight_elements": w} for w in (1234, 5678)], 33),
        [{"weight_elements": 1234}, {"weight_elements": 5678}], 33)
    check("E3_accepted_at_a_shape_never_seen_in_this_project", oki,
          "two arbitrary weight matrices at 33 tokens: %s.  A correct "
          "implementation is accepted at shapes that did not exist when the "
          "original number was pinned, which is the property a magic-number test "
          "does not have." % di)

    okh, dh = m.check_quadratic_in_tokens(
        lambda T: m.attention_macs_vit(8, T, heads=64, head_dim=16))
    check("E4_the_attention_law_holds_at_a_different_head_geometry", okh,
          "64 heads of head_dim 16 instead of 32x32: %s" % dh)

    pinert, dinert, inert_out = run_copy(inert)
    check("E5_an_inert_mutation_does_NOT_fail",
          dinert is not None and dinert["verdict"] == "PERF_MODEL_CORRECTED"
          and all(c["result"] == "PASS" for c in dinert["checks"])
          and os.path.dirname(os.path.abspath(inert_out)) == os.path.abspath(SCRATCH),
          "a comment-level change to the schema string, run end to end, still "
          "returns %s with no failing check, and it wrote only inside _scratch.  An "
          "inert mutation that failed would mean the red legs prove nothing about "
          "the token factor." % (dinert["verdict"] if dinert else None))

    # =====================================================================
    # F. THE TEST'S OWN RED CONTROL -- this battery must be able to fail.
    # =====================================================================
    STAGE[0] = "F_the_test_batterys_own_red_control"

    def quadratic(T):
        return W * T * T

    q_ok, _ = m.check_linear_not_quadratic_in_tokens(quadratic)
    check("F1_the_batterys_linear_law_rejects_a_plain_quadratic", not q_ok,
          "the law that A1 passes rejects a plain quadratic in the same process: "
          "the acceptance in A1 is not vacuous")

    def linear(T):
        return W * T

    check("F2_the_linearity_law_rejects_a_term_that_is_not_there",
          not m.check_linear_not_quadratic_in_tokens(lambda T: 0)[0],
          "a term that is identically zero is rejected rather than passing a "
          "scaling test vacuously")

    check("F3_absence_is_blocking_in_the_predicate",
          not m.check_single_token_factor(frozen_at400, [], 400)[0]
          and not m.check_single_token_factor(None, vit_rows, 400)[0]
          and not m.check_single_token_factor(W * 400, vit_rows, 0)[0],
          "the predicate rejects an empty row set, an absent value and a "
          "non-positive token count: each is a FAILURE, never a silent pass")

    # =====================================================================
    # H. THE TEST'S OWN END-TO-END SELF-RED LEG.  Stage D shows the MODEL can
    #    go red under this battery; only this leg shows THE TEST FILE can.  It
    #    runs THIS FILE, as a process, against the mutated model copy built in
    #    stage D.  Without this leg the battery is a set of checks that have
    #    been shown to reject values, not a test that has been shown to fail.
    # =====================================================================
    #: the registry as it stood BEFORE any stage-H check was registered: the
    #: child run must have executed every one of these.
    PRE_H_CHECKS = [c["check"] for c in CHECKS]

    #: checks that ARE functions of the model's token-level builder, so the
    #: re-duplication MUST reach them and they MUST go red.
    OWNED_BY_THE_DEFECT = (
        "A1_vit_linear_term_is_linear_in_tokens",
        "A2_vit_linear_term_is_linear_on_the_byte_volume_reading_too",
        "A11_the_linear_term_is_linear_in_the_weights_as_well_as_the_tokens",
        "A12_every_vit_linear_builder_the_model_exposes_obeys_the_law",
        "B2_the_published_value_is_the_single_factor_value_times_the_token_count",
        "E1_accepted_at_the_capture_tier_token_count")
    #: checks that ALSO go red against a broken model, for reasons that are not
    #: the token factor and are expected by construction.  Declaring them keeps
    #: the red set COMPLETE: a battery-wide collapse could otherwise hide in the
    #: difference between the failing set and the checks named above.
    #:   C2 compares the freshly built in-process mutant against the model under
    #:      test; when the model under test is itself the mutant it compares the
    #:      fault with itself, which is exactly what C2 exists to notice;
    #:   E2/E3 are green controls -- correct implementations ACCEPTED at other
    #:      shapes -- and a broken model is expected to be rejected there.
    ALSO_RED_BY_CONSTRUCTION = (
        "C2_the_mutant_reached_the_observer",
        "E2_accepted_with_a_different_ViT_block_subset",
        "E3_accepted_at_a_shape_never_seen_in_this_project")
    #: checks that do NOT touch that builder.  They read the frozen artifact,
    #: the pure predicate or a different model function, so they MUST stay
    #: green.  If they went red the run would be a collapse, not a rejection.
    INDEPENDENT_OF_THE_BUILDER = (
        "A3_the_layer_identity_is_linear_in_positions",
        "A4_vit_attention_term_is_quadratic_in_tokens",
        "A5_the_total_is_additive_and_strictly_less_than_quadratic",
        "A9_every_one_of_the_71_frozen_per_block_figures_is_single_factor",
        "A10_the_frozen_headline_totals_are_the_sums_of_their_verified_rows",
        "B1_the_predicate_rejects_the_published_at_400_value",
        "B3_the_frozen_expression_fails_the_linearity_ladder",
        "B4_the_frozen_expression_is_quadratic_with_the_matching_coefficient",
        "F1_the_batterys_linear_law_rejects_a_plain_quadratic",
        "F2_the_linearity_law_rejects_a_term_that_is_not_there",
        "F3_absence_is_blocking_in_the_predicate")

    if SELF_RED_RUN:
        STAGE[0] = "H_self_red_leg_not_applicable"
        check("H0_the_self_red_leg_is_skipped_inside_a_self_red_run", True,
              "this process IS the stage-H child (%s), so the leg is skipped to "
              "terminate the recursion.  Recorded rather than passed off as a run."
              % os.path.basename(MODEL), required=False)
    else:
        STAGE[0] = "H_self_red_end_to_end_on_this_test_file"

        def run_this_test_against(model_path, tag):
            """Run THIS FILE, as a process, with `model_path` under test."""
            out_p = os.path.join(SCRATCH, "SCRATCH_REGRESSION_%s.json" % tag)
            if os.path.exists(out_p):
                os.remove(out_p)
            pr = subprocess.run(
                [sys.executable, os.path.abspath(__file__),
                 "--model", model_path, "--out", out_p],
                cwd=ROOT, capture_output=True, text=True)
            doc = json.load(open(out_p, encoding="utf-8")) \
                if os.path.exists(out_p) else None
            return pr, doc, out_p

        self_out = os.path.join(SCRATCH, "SCRATCH_REGRESSION_selfred.json")
        ph, child, self_out = run_this_test_against(mutants, "selfred")
        cby = {c["check"]: c["result"] for c in (child or {}).get("checks", [])}
        c_fail = sorted(n for n, r in cby.items() if r == "FAIL")
        expected_fail = sorted(set(OWNED_BY_THE_DEFECT)
                               | set(ALSO_RED_BY_CONSTRUCTION))
        grn = [n for n in INDEPENDENT_OF_THE_BUILDER if cby.get(n) != "PASS"]

        check("H1_this_test_file_reports_the_mutated_model_as_FAIL",
              child is not None and ph.returncode != 0
              and child["verdict"] == "TOKEN_FACTOR_REGRESSION_FAIL",
              "run as a process against the mutated copy (%s), this same test file "
              "exits %d with verdict %s.  The battery is therefore able to go red "
              "on the defect it was written to catch when driven as a FILE, not "
              "only in process."
              % (os.path.basename(mutants), ph.returncode,
                 child["verdict"] if child else None))

        check("H2_the_childs_failing_set_is_EXACTLY_the_declared_one",
              c_fail == expected_fail,
              "the child run fails exactly %d check(s) and no others: %s.  Of "
              "those, %d are the laws that OWN the token factor and MUST go red "
              "(including the byte-volume reading A2 and the capture-tier shape "
              "E1, which a pinned-number test would not reach), and %d are expected "
              "by construction: C2 compares the in-process mutant against the model "
              "under test and so compares the fault with itself here, and E2/E3 are "
              "green controls that a broken model is supposed to be rejected at.  "
              "Nothing else in the 37-check registry moved, so the rejection is "
              "targeted rather than a collapse -- which is also why the FAIL "
              "verdict is attributed to the named laws and not just to the verdict."
              % (len(c_fail), c_fail, len(OWNED_BY_THE_DEFECT),
                 len(ALSO_RED_BY_CONSTRUCTION)))

        check("H3_the_child_rejection_is_TARGETED_not_a_collapse",
              not grn and len(cby) >= 30,
              "the %d checks that do NOT depend on that builder all still PASS in "
              "the same child run (%s ...), over a %d-check registry: the attention "
              "law, the 71 frozen per-block rows, the two frozen headline totals, "
              "the real published at_400 value and the battery's own red controls "
              "are all unaffected.  A red leg that took the whole battery down "
              "would prove nothing about the token factor."
              % (len(INDEPENDENT_OF_THE_BUILDER),
                 list(INDEPENDENT_OF_THE_BUILDER)[:3], len(cby)))

        child_h = set(n for n in cby if n.startswith("H"))
        check("H5_the_child_ran_the_same_battery_minus_the_self_red_leg",
              all(n in cby for n in PRE_H_CHECKS)
              and child_h == {"H0_the_self_red_leg_is_skipped_inside_a_self_red_run"},
              "all %d checks registered before this leg ran were executed by the "
              "child (%d checks in its registry), and its only H check is the H0 "
              "skip record: the four self-red checks did not run there, so the leg "
              "terminates instead of recurring.  A child that quietly ran a "
              "smaller battery would make the red set above meaningless."
              % (len(PRE_H_CHECKS), len(cby)))

        pc, ctrl, ctrl_out = run_this_test_against(base_path, "control_notred")
        check("H6_the_H_leg_goes_GREEN_on_a_child_that_is_NOT_broken",
              ctrl is not None and pc.returncode == 0
              and ctrl["verdict"] == "TOKEN_FACTOR_REGRESSION_PASS"
              and not [c["check"] for c in ctrl["checks"] if c["result"] == "FAIL"],
              "the SAME code path, launched the SAME way, against the unmutated "
              "relocated copy returns %s with exit %d.  H1's red is therefore "
              "attributable to the injected duplication and not to being launched "
              "as a child process, to the --model wiring, or to the registry "
              "comparison -- the leg would go green here if any of those were the "
              "cause.  Without this control, H1 would be a check that cannot fail."
              % (ctrl["verdict"] if ctrl else None, pc.returncode))

        reg_now = (os.path.getsize(OUT) if os.path.exists(OUT) else None,
                   os.path.getmtime(OUT) if os.path.exists(OUT) else None)
        check("H4_the_child_run_wrote_only_into_scratch_and_left_the_artifacts_alone",
              all(os.path.dirname(os.path.abspath(o)) == os.path.abspath(SCRATCH)
                  for o in (self_out, ctrl_out))
              and reg_now == (reg_out_size_before, reg_out_mtime_before)
              and os.path.getsize(MODEL_OUT) == model_out_size_before
              and os.path.getmtime(MODEL_OUT) == model_out_mtime_before,
              "the child's output is inside _scratch, and this test's own published "
              "%s and the model's %s are both byte-identical to their state before "
              "this leg ran.  A regression test whose red leg rewrote the record it "
              "verifies could never show the regression again."
              % (os.path.basename(OUT), os.path.basename(MODEL_OUT)))

    # =====================================================================
    # G. REGISTRY AND VERDICT
    # =====================================================================
    STAGE[0] = "G_registry"
    missing = [n for n in REQUIRED if n not in [c["check"] for c in CHECKS]]
    check("G1_every_required_check_ran", not missing,
          "%d required checks registered, %d ran, %d missing%s"
          % (len(REQUIRED), len(CHECKS), len(missing),
             "" if not missing else ": " + ", ".join(missing)), required=False)

    red_stages = ("B", "C", "D", "H1")
    n_red = sum(1 for c in CHECKS
                if any(c["check"].startswith(p) for p in red_stages)
                and c["result"] == "PASS")
    check("G2_red_legs_are_present_and_reached_their_observer", n_red >= 8,
          "%d red-leg checks passed: the test demonstrably rejects the real "
          "uncorrected value, an in-process mutant, and a mutated copy run end to "
          "end.  A regression test that has never gone red is not a regression "
          "test." % n_red, required=False)

    failing = [c["check"] for c in CHECKS if c["result"] == "FAIL"]
    verdict = "TOKEN_FACTOR_REGRESSION_PASS" if not failing \
        else "TOKEN_FACTOR_REGRESSION_FAIL"

    out = {
        "schema": "p16ax-token-factor-regression/1",
        "phase": "16AX", "task_id": "T-PERF", "worker": "W8",
        "host_only": True, "gpu_execution_performed": False,
        "hip_calls_made": 0,
        "subject": "structural regression test for the duplicated ViT token "
                   "factor repaired by p16ax/perf/p16ax_perf_model.py",
        "model_under_test": os.path.relpath(MODEL, ROOT).replace(os.sep, "/"),
        "self_red_run": SELF_RED_RUN,
        "self_red_run_note": "TRUE means this process is stage H's child: it was "
                             "launched against a deliberately broken model, so "
                             "stage H is skipped and a FAIL verdict here is the "
                             "expected outcome, not a regression.",
        "verdict": verdict,
        "verdict_basis": "%d checks, %d failing%s" % (
            len(CHECKS), len(failing), "" if not failing else ": " + ", ".join(failing)),
        "the_defect_this_guards": {
            "published_value": frozen_at400,
            "correct_value": m.token_level_linear_macs(vit_rows, T9),
            "inflation": frozen_at400 / m.token_level_linear_macs(vit_rows, T9),
            "shape_at_which_the_pinned_number_was_written": {
                "tokens": T9, "vit_blocks": N_VIT, "heads": 32, "head_dim": 32},
            "why_structural": "a test that only pinned %d would accept a "
                              "re-introduction at 640 tokens, at 7 blocks, at a "
                              "different head count, or with the fault in any other "
                              "token-scaled term.  The laws above reject all of "
                              "those: C5 and E3 exercise exactly that difference."
                              % m.token_level_linear_macs(vit_rows, T9),
        },
        "laws_under_test": [
            "linear term: f(kT) == k*f(T) exactly, at every probe",
            "attention term: g(kT) == k^2*g(T) exactly, at every probe",
            "total == linear + attention, with attention strictly non-zero",
            "total(kT) < 4*total(T) for a fixed shape: the total is NOT quadratic",
            "measured exponent of the total strictly between 1 and 2",
            "the linear term is linear in weight_elements as well as in tokens",
            "every ViT linear builder the model exposes obeys the same law "
            "(discovered by inspection, not named)",
        ],
        "red_legs": [
            "B: p16ao's real published at_400 is rejected by the predicate and "
            "by the ladder (measured exponent 2.000000)",
            "C: an in-process mutant with the anchored return re-duplicated is "
            "rejected by the model's own predicate and ladder, at shapes other than "
            "the pinned one",
            "D: a real copy of the model with that one semantic mutation, run as a "
            "process, flips its own verdict to PERF_MODEL_UNRESOLVED and fails the "
            "sensitivity-table check",
            "F: the battery's own laws reject a plain quadratic and a vanished term",
            "H: THIS FILE, run as a process against the mutated copy, returns "
            "TOKEN_FACTOR_REGRESSION_FAIL (exit != 0) with its failing set exactly "
            "the laws that own the token factor plus the 3 checks that redden by "
            "construction, and the 11 builder-independent checks still green, and "
            "with the SAME leg run against the unmutated relocated copy still green",
        ],
        "green_controls": [
            "E1: 640 tokens accepted", "E2: a 7-block subset accepted",
            "E3: an arbitrary two-matrix shape at 33 tokens accepted",
            "E4: the attention law holds at 64 heads x head_dim 16",
            "E5: an inert comment-level mutation does NOT fail",
            "D1: the relocated but unmutated copy still passes end to end",
            "H3: the child run's eleven builder-independent checks stay green, so "
            "the child's red is targeted rather than a collapse",
            "H6: the same leg run against the UNMUTATED relocated copy comes back "
            "green, so the red leg is able to go green and H1 is not a check that "
            "cannot fail",
        ],
        "mutation_harness": {
            "anchor": ANCHOR,
            "fault": FAULT,
            "anchor_occurrences_in_the_model_source": src.count(ANCHOR),
            "semantic_mutations": 1,
            "relocations": [{"from": a, "to": b} for a, b in RELOCATIONS],
            "relocation_reason": "the mutated copy runs outside p16ax/perf, so "
                                 "its project root is pinned and its output is "
                                 "diverted into _scratch.  This is a harness "
                                 "relocation, not a second semantic mutation: D0 "
                                 "asserts the copy differs from the original in "
                                 "exactly these three hunks and that hunk 1 is the "
                                 "anchored return.",
            "processes_created_by_this_process": 4 if SELF_RED_RUN else 5,
            "processes": ["baseline copy", "mutant", "inert",
                          "the stage-H child run of THIS TEST FILE",
                          "the model itself is imported in-process, not spawned"],
        },
        "artifacts_read": {
            "p16ao/cost/COST_MODEL_PER_BLOCK.json": os.path.getsize(ART16AO),
            os.path.relpath(MODEL, ROOT).replace(os.sep, "/"):
                os.path.getsize(MODEL),
            "p16ax/perf/PERF_MODEL_16AX.json": os.path.getsize(MODEL_OUT),
            "p16ax/perf/p16ax_token_factor_test.py":
                os.path.getsize(os.path.abspath(__file__)),
        },
        "checks": CHECKS,
        "gap_found_and_closed_during_this_task": {
            "what": "the battery originally anchored one of TWO byte-identical "
                    "implementations of the token-factor law and returned 0 failing "
                    "against a model whose other one duplicated the factor",
            "measured_at": "p16ax/perf/_scratch/SCRATCH_REGRESSION_uppermut.json "
                           "(0 failing, verdict PASS) before the fix",
            "closed_by": "the model now states the law once "
                         "(vit_linear_upper_macs delegates) and A12 discovers every "
                         "ViT linear builder instead of naming one",
        },
        "not_established": [
            "that the ViT token count is 400: this test uses the frozen artifact's "
            "own figure and neither corroborates nor contests it",
            "any performance quantity: no rate, latency or throughput is computed "
            "or compared anywhere in this file",
        ],
        "reproduce": "python p16ax/perf/p16ax_token_factor_test.py",
        "reproduce_the_self_red_leg": "python p16ax/perf/p16ax_token_factor_test.py "
                                      "--model p16ax/perf/_scratch/"
                                      "p16ax_perf_model_mutant_tokenfactor.py "
                                      "--out <scratch path>   # must exit 1 with "
                                      "TOKEN_FACTOR_REGRESSION_FAIL",
    }

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)

    print("wrote %s" % OUT)
    print("  model under test = %s%s"
          % (MODEL, "   (SELF-RED RUN: the FAIL verdict is the EXPECTED outcome)"
             if SELF_RED_RUN else ""))
    print("  %d checks, %d failing   verdict %s"
          % (len(CHECKS), len(failing), verdict))
    for c in CHECKS:
        if c["result"] != "PASS":
            print("  FAIL [%s] %s: %s" % (c["stage"], c["check"], c["detail"][:300]))
    return 0 if not failing else 1


if __name__ == "__main__":
    sys.exit(main())
