#!/usr/bin/env python3
"""Phase 16T -- re-run the ENTIRE Phase 16S 16-mnemonic independent oracle
suite under a named emulator source revision, plus a well-posed replacement
for the two vector families whose Phase 16S expectation is ill-posed.

HOST ONLY.  No GPU, no HIP, no game, nothing armed.  Reads only.

TWO SUITES
----------
1. `phase16s_vectors` -- the 146 vectors recorded in
   `phase16s/isa/ISA_ORACLE_16.json`, re-executed UNCHANGED.  The recorded
   expectation is used verbatim; nothing in this tool recomputes it.

2. `mix_16t` -- 32 NEW vectors for `v_fma_mixlo_f16` / `v_fma_mixhi_f16`
   whose expectation is well-posed.  See `THE PHASE 16S MIX DEFECT` below.

THE PHASE 16S MIX DEFECT (measured here, and recorded in the artifact)
---------------------------------------------------------------------
Every Phase 16S MIX vector is built by `_fma_vecs` in
`phase16s/isa/build_oracle_vectors.py:1341` as

    V(mnem, name, "v1", ["v1", "v2", "v3"],
      {"v1": LANES(a), "v2": LANES(b), "v3": LANES(c), "v0": LANES(dst)}, ...)

so the destination token is `v1` -- the register that holds source S0 -- while
the value the expectation calls the "pre-set destination", `dst = 0xAAAA5555`,
is seeded into **`v0`**, a register the instruction never reads.  The oracle
side then computes `dst16_lo/hi(0xAAAA5555, r, "preserve")`.

The declared reading and the declared state therefore disagree: measured
through `Harness.probe`, `v1` holds `a` (0x00003C00 for the J3-shape vector),
not 0xAAAA5555, so the correctly rounded answer for the state the vector
actually sets up is `dst16_*(a, r, "preserve")`, not `dst16_*(0xAAAA5555, r,
"preserve")`.  That is why 15 of the 16 MIX vectors "disagree" while the
primary destination field is `value: null`-free.

This is a defect of the TEST, and it is recorded rather than quietly fixed:
the 146 recorded vectors are re-run exactly as recorded, and the two MIX rows
carry the measured consequence.  The `mix_16t` family is an ADDITION -- same
source values, destination seeded where the instruction actually reads it, in
two shapes -- so the repair can be judged on a well-posed comparison as well.

It does NOT rescue the pre-revision implementation: that body reads each
source's FULL 32 bits as an f32, so `f32(0x3C00) * f32(0x4000)` underflows to
zero and it writes 0x00000000 over the whole destination where the ISA value
is 0xAAAA4000.  Both suites are run under both revisions; the numbers are in
the artifact.

Usage:
    python phase16t/isa/t16_oracle.py --rev live     --out PATH
    python phase16t/isa/t16_oracle.py --rev revision --out PATH
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
T = os.path.dirname(HERE)
ROOT = os.path.dirname(T)
sys.path.insert(0, HERE)

import t16_probe as P                                            # noqa: E402

LANES_N = 32

#: The same binary16 constants `phase16s/isa/build_oracle_vectors.py:1233`
#: uses, so the 16T family is comparable vector-for-vector with the 16S one.
F16 = {
    "pos_zero": 0x0000, "neg_zero": 0x8000,
    "smallest_sub": 0x0001, "largest_sub": 0x03FF, "smallest_norm": 0x0400,
    "one": 0x3C00, "one_plus_2m10": 0x3C01, "one_and_half": 0x3E00,
    "two": 0x4000, "neg_one": 0xBC00, "neg_one_plus_2m10": 0xBC01,
    "max": 0x7BFF, "inf": 0x7C00, "ninf": 0xFC00, "qnan": 0x7E00,
}


def _lanes(v):
    return [v] * LANES_N


#: (name, a, b, c, declared reading of the result, note)
MIX_CASES = [
    ("j3_one_times_two_plus_zero", F16["one"], F16["two"], 0x0000, None,
     "J3 operand shape, verbatim: v_fma_mixlo_f16 v1, v8, v16, 0. "
     "1.0 * 2.0 + 0 = 2.0."),
    ("hi_vs_lo_separator", F16["one_and_half"], F16["two"], 0x0000, None,
     "SEPARATOR for the lo/hi distinction: 1.5 * 2 = 3.0 = 0x4200."),
    ("pos_zero", 0x0000, 0x0000, 0x0000, None,
     "NON-DISCRIMINATING control: all-zero sources, so the declared, "
     "zero-half and double-rounding readings all agree."),
    ("neg_zero_product_and_addend", F16["neg_zero"], F16["one"],
     F16["neg_zero"], "OPEN",
     "-0 * 1 + (-0). IEEE 754 gives -0 only when both terms are -0, which "
     "holds here."),
    ("mixed_sign_zero_sum", F16["neg_zero"], F16["one"], 0x0000, "OPEN",
     "-0 * 1 + +0 -> +0 under RNE (mixed-sign zero sum)."),
    ("smallest_subnormal", F16["smallest_sub"], F16["one"], 0x0000, None,
     "Smallest subnormal: 2^-24 * 1 + 0."),
    ("largest_subnormal", F16["largest_sub"], F16["one"], 0x0000, None,
     "Largest subnormal: 1023 * 2^-24."),
    ("smallest_normal", F16["smallest_norm"], F16["one"], 0x0000, None,
     "Smallest normal: 2^-14."),
    ("max_finite", F16["max"], F16["one"], 0x0000, None,
     "Largest finite: 65504 * 1 + 0."),
    ("overflow_to_infinity", F16["max"], F16["two"], 0x0000, None,
     "65504 * 2 exceeds the f16 range -> infinity."),
    ("infinity_times_one", F16["inf"], F16["one"], 0x0000, None,
     "Inf * 1 + 0 -> Inf."),
    ("infinity_times_zero", F16["inf"], 0x0000, F16["one"], "OPEN",
     "Inf * 0 is the IEEE invalid operation -> quiet NaN."),
    ("qnan_propagation", F16["qnan"], F16["one"], 0x0000, "OPEN",
     "A NaN operand -> the declared reading is the quiet NaN."),
    ("fused_single_rounding", F16["one_plus_2m10"], F16["one_plus_2m10"],
     F16["neg_one"], None,
     "FUSED vs DOUBLE ROUNDING: a = b = 1 + 2^-10, c = -1; the exact value is "
     "2^-9 + 2^-20, which rounds to 2^-9, while a multiply-round-then-add "
     "reading gets 0."),
    ("fused_tie_in_the_subnormal_grid", F16["one_plus_2m10"],
     F16["one_plus_2m10"], F16["neg_one_plus_2m10"], None,
     "FUSED TIE in the subnormal grid."),
    ("exact_cancellation_positive_zero", F16["one"], F16["one"],
     F16["neg_one"], None,
     "Exact cancellation: 1 * 1 - 1 = +0."),
]

MIX_HALVES = (("v_fma_mixlo_f16", False), ("v_fma_mixhi_f16", True))


def build_mix_16t(oracle):
    """The well-posed replacement family, expectations from `oracle16` only."""
    out = []
    for mnem, hi in MIX_HALVES:
        fold = oracle.dst16_hi if hi else oracle.dst16_lo
        half = "HIGH" if hi else "LOW"
        other = "low" if hi else "high"
        for name, a, b, c, level, note in MIX_CASES:
            for shape in ("dst_separate", "j3_dst_is_src0"):
                if shape == "dst_separate":
                    ops = ["v0", "v1", "v2", "v3"]
                    dst = "v0"
                    dst_old = 0xAAAA5555
                    setup = {"v0": 0xAAAA5555, "v1": _lanes(a),
                             "v2": _lanes(b), "v3": _lanes(c)}
                else:
                    ops = ["v1", "v1", "v2", "v3"]
                    dst = "v1"
                    dst_old = a
                    setup = {"v1": _lanes(a), "v2": _lanes(b), "v3": _lanes(c)}
                r = oracle.f16_fma(a, b, c)
                alts = {
                    "other_half_zeroed": fold(dst_old, r, "zero"),
                    "double_rounding_mul_then_add":
                        fold(dst_old, oracle.fma_double_rounding(a, b, c),
                             "preserve"),
                }
                spec = {
                    "suite": "MIX_16T", "name": "%s__%s" % (name, shape),
                    "mnem": mnem, "ops": ops, "dst": dst, "setup": setup,
                    "expect": {"value": fold(dst_old, r, "preserve"),
                               "scc": None, "exec": None, "extra": {}},
                    "alt": alts,
                    "level": level,
                    "note": ("%s  %s-half result; the destination register is "
                             "seeded where the instruction actually reads it "
                             "(%s = 0x%08X), which the Phase 16S MIX vectors "
                             "did not do." % (note, half, dst, dst_old)),
                    "source": ("ISA rdna2_isa.txt:%s  D.f[%s] = S0.f*S1.f+S2.f"
                               % ("9367-9374" if hi else "9355-9361",
                                  "31:16" if hi else "15:0")),
                }
                out.append(spec)
    return out


def recompute_s16_mix(res16, oracle):
    """The 16S MIX vectors with the expectation derived from the state the
    vector ACTUALLY sets up.

    Same setup dicts, same operand strings, same probe observations -- only
    the expectation changes, from `dst16_*(0xAAAA5555, r)` (the value the
    vector seeds into the unused `v0`) to `dst16_*(dst_reg_old, r)`, where
    `dst_reg_old` is the value the vector seeds into the register its own
    `dst` token names.  Nothing else is touched, and the emulator's
    observation is the one already measured, not a re-run.
    """
    out = []
    for r in res16:
        if r["mnem"] not in ("v_fma_mixlo_f16", "v_fma_mixhi_f16"):
            continue
        hi = r["mnem"] == "v_fma_mixhi_f16"
        fold = oracle.dst16_hi if hi else oracle.dst16_lo
        dst = r["dst"]
        s = r["setup"].get(dst)
        if s is None:
            out.append({"name": r["name"], "status":
                        "DESTINATION_NOT_SEEDED_BY_THE_VECTOR"})
            continue
        dst_old = (s[0] if isinstance(s, list) else s) & 0xFFFFFFFF
        ops = r["ops"]
        a = r["setup"].get(ops[1])
        b = r["setup"].get(ops[2])
        c = r["setup"].get(ops[3])
        a = (a[0] if isinstance(a, list) else a) & 0xFFFF
        b = (b[0] if isinstance(b, list) else b) & 0xFFFF
        c = (c[0] if isinstance(c, list) else c) & 0xFFFF
        rr = oracle.f16_fma(a, b, c)
        want = fold(dst_old, rr, "preserve")
        want_zero = fold(dst_old, rr, "zero")
        want_dr = fold(dst_old, oracle.fma_double_rounding(a, b, c), "preserve")
        obs_v = r["obs"].get("value")
        out.append({
            "name": r["name"], "mnem": r["mnem"], "ops": ops, "dst": dst,
            "destination_register_old_value": dst_old,
            "the_value_the_16s_expectation_used": 0xAAAA5555,
            "sixteen_s_expectation": r["oracle"]["value"],
            "sixteen_s_agreed": not r["diffs"],
            "sources": {"a": a, "b": b, "c": c},
            "recomputed_expectation_preserve": want,
            "recomputed_expectation_zero_half": want_zero,
            "recomputed_expectation_double_rounding": want_dr,
            "emulator_observed": obs_v,
            "emulator_error": r["obs"].get("error"),
            "emulator_agrees_with_recomputed":
                (r["obs"].get("error") is None and obs_v == want),
            "emulator_matches_an_alternate":
                (obs_v == want_zero) or (obs_v == want_dr),
            "which_alternate": ("zero_half" if obs_v == want_zero else
                                "double_rounding" if obs_v == want_dr else None),
        })
    return out


def run_suite(harness, R16, vectors, suite):
    results = []
    n_cmp = 0
    for v in vectors:
        spec = {"mnem": v["mnem"], "ops": v["ops"], "dst": v["dst"],
                "setup": v["setup"], "expect": v["expect"],
                "alt": v.get("alt") or {}, "name": v["name"]}
        obs = harness.probe(spec)
        diffs = R16._obs_diffs(obs, v["expect"])
        hits = R16.alts_that_explain(spec, obs, diffs)
        n_cmp += 1 + len(v["expect"].get("extra") or {})
        n_cmp += sum(1 for k in ("scc", "exec")
                     if v["expect"].get(k) is not None)
        results.append({"suite": suite, "mnem": v["mnem"], "name": v["name"],
                        "ops": v["ops"], "dst": v["dst"], "setup": v["setup"],
                        "oracle": v["expect"], "alt": v.get("alt") or {},
                        "obs": obs, "diffs": diffs, "alt_hits": hits,
                        "note": v.get("note"), "source": v.get("source")})
    return results, n_cmp


def rollup(results):
    per = {}
    for m in sorted(set(r["mnem"] for r in results)):
        rs = [r for r in results if r["mnem"] == m]
        dis = [r for r in rs if r["diffs"]]
        unexp = [r for r in dis if not r["alt_hits"]]
        per[m] = {
            "vectors": len(rs),
            "comparisons": sum(1 + len(r["oracle"].get("extra") or {})
                               + sum(1 for k in ("scc", "exec")
                                     if r["oracle"].get(k) is not None)
                               for r in rs),
            "agree": len(rs) - len(dis),
            "disagree": len(dis),
            "disagree_matching_a_recorded_alternate": len(dis) - len(unexp),
            "disagree_unexplained": len(unexp),
            "status": ("VERIFIED_INDEPENDENTLY" if not dis
                       else "OPEN_SEMANTICS" if not unexp else "DISAGREES"),
        }
    return per


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev", choices=("live", "revision"), required=True)
    ap.add_argument("--rev-tree", default=None,
                    help="an alternative revision tree (used by the "
                         "known-bad mutation controls)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    t0 = time.time()

    harness, R16, m2, revdir = P.prepare(args.rev, getattr(args, "rev_tree", None))
    prov = P.provenance(args.rev, revdir, harness, m2)
    prov["load_emulator_problems"] = getattr(m2, "_LAST_PROBLEMS", None)
    if args.rev == "revision" and not prov["edited_modules_from_revision_tree"]:
        raise SystemExit("PROVENANCE FAILURE: %s"
                         % json.dumps(prov["modules"], indent=1))
    if args.rev == "live":
        for mod in P.EDITED:
            if prov["modules"][mod]["from_revision_tree"]:
                raise SystemExit("PROVENANCE FAILURE: live run loaded %s from a "
                                 "revision tree" % mod)

    # the independent oracle, imported from phase16s/isa (read-only).  It
    # imports nothing, so importing it here cannot drag in the emulator.
    sys.path.insert(0, os.path.join(ROOT, "phase16s", "isa"))
    import oracle16 as O                                        # noqa: E402

    doc, art_hash = P.load_vectors()
    s16 = doc["vectors"]
    mix = build_mix_16t(O)

    res16, cmp16 = run_suite(harness, R16, s16, "PHASE16S_RECORDED")
    resmx, cmpmx = run_suite(harness, R16, mix, "MIX_16T")

    per16 = rollup(res16)
    permx = rollup(resmx)

    rec = {
        "schema": "phase16t-t16-oracle/1", "phase": "16T",
        "host_only": True, "gpu_execution_performed": False,
        "gta_launched": False, "currently_armed": False,
        "what": ("the whole Phase 16S 16-mnemonic independent oracle suite "
                 "re-executed under one named source revision, plus a "
                 "well-posed replacement family for the two MIX mnemonics"),
        "run": {"command": "python phase16t/isa/t16_oracle.py --rev %s%s --out %s"
                          % (args.rev,
                             (" --rev-tree " + args.rev_tree) if args.rev_tree else "",
                             args.out),
                "cwd": ROOT, "python": sys.version.split()[0],
                "s1_artifact": P.S1_ARTIFACT,
                "s1_artifact_sha256": art_hash,
                "oracle_module_sha256": P.sha256_file(
                    os.path.join(ROOT, P.S1_ORACLE)),
                "wall_s": None},
        "provenance": prov,
        "phase16s_vectors": {
            "n": len(res16), "n_comparisons": cmp16,
            "n_disagreeing": sum(1 for r in res16 if r["diffs"]),
            "n_disagreeing_unexplained":
                sum(1 for r in res16 if r["diffs"] and not r["alt_hits"]),
            "per_mnemonic": per16, "vectors": res16},
        "mix_16t_vectors": {
            "n": len(resmx), "n_comparisons": cmpmx,
            "n_disagreeing": sum(1 for r in resmx if r["diffs"]),
            "n_disagreeing_unexplained":
                sum(1 for r in resmx if r["diffs"] and not r["alt_hits"]),
            "per_mnemonic": permx, "vectors": resmx},
        "the_phase16s_mix_defect": {
            "where": "phase16s/isa/build_oracle_vectors.py:1341 (_fma_vecs)",
            "what": ("the vector declares dst = v1 -- the register holding "
                     "S0 -- while seeding the 'pre-set destination' 0xAAAA5555 "
                     "into v0, which the instruction never reads; the "
                     "expectation is then computed against 0xAAAA5555."),
            "consequence": ("the recorded 'preserve the other half' "
                            "expectation is not the correctly rounded value "
                            "for the state the vector sets up"),
            "how_handled": ("the 146 recorded vectors are re-run UNCHANGED and "
                            "the consequence is reported; the MIX_16T family "
                            "is an addition, not a replacement"),
            "measured_consequence": None,
        },
        "phase16s_mix_recomputed": None,
        "n_comparisons_total": cmp16 + cmpmx,
        "status_counts_union": {},
    }
    rec["phase16s_mix_recomputed"] = recompute_s16_mix(res16, O)
    # the union status per mnemonic, over both suites
    union = {}
    for m in sorted(set(list(per16) + list(permx))):
        a = per16.get(m)
        b = permx.get(m)
        if a and b:
            union[m] = ("VERIFIED_INDEPENDENTLY" if not a["disagree"]
                        and not b["disagree"] else "DISAGREES")
        else:
            union[m] = (a or b)["status"]
    rec["status_counts_union"] = {
        "VERIFIED_INDEPENDENTLY": sum(
            1 for v in union.values() if v == "VERIFIED_INDEPENDENTLY"),
        "DISAGREES": sum(1 for v in union.values() if v == "DISAGREES"),
        "n_mnemonics": len(union)}
    rec["per_mnemonic_union"] = union

    bad16 = [r for r in res16 if r["diffs"] and r["mnem"].startswith(
        ("v_fma_mixlo", "v_fma_mixhi"))]
    rec["the_phase16s_mix_defect"]["measured_consequence"] = {
        "vectors_affected": len(bad16),
        "of_vectors": len([r for r in res16 if r["mnem"].startswith(
            ("v_fma_mixlo", "v_fma_mixhi"))]),
        "their_oracle_value": sorted(set(
            r["oracle"]["value"] for r in bad16)),
        "their_dst_old_actually_used_by_the_instruction":
            "the value of the register the vector names as dst, which for "
            "every one of these vectors is a SOURCE register (v1 = S0)",
    }

    rec["run"]["wall_s"] = round(time.time() - t0, 1)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)

    for label, per, n, c in (("PHASE-16S RECORDED", per16, len(res16), cmp16),
                             ("MIX_16T (well-posed)", permx, len(resmx), cmpmx)):
        print("== %s : %d vectors / %d comparisons" % (label, n, c))
        print("   %-24s %5s %6s %6s %6s %7s  %s"
              % ("mnemonic", "vecs", "agree", "dis", "alt", "UNEXPL", "status"))
        for m, d in per.items():
            print("   %-24s %5d %6d %6d %6d %7d  %s"
                  % (m, d["vectors"], d["agree"], d["disagree"],
                     d["disagree_matching_a_recorded_alternate"],
                     d["disagree_unexplained"], d["status"]))
    rc = rec["phase16s_mix_recomputed"]
    n_ok = sum(1 for x in rc if x.get("emulator_agrees_with_recomputed"))
    n_alt = sum(1 for x in rc if x.get("emulator_matches_an_alternate")
                and not x.get("emulator_agrees_with_recomputed"))
    print("\n== PHASE-16S MIX VECTORS, expectation recomputed from the state "
          "the vector sets up")
    print("   %d of %d agree with the recomputed expectation; %d more match a "
          "recorded ALTERNATE reading; %d match neither"
          % (n_ok, len(rc), n_alt, len(rc) - n_ok - n_alt))
    for x in rc:
        if not x.get("emulator_agrees_with_recomputed"):
            print("   %-34s dst_old=0x%08X 16S_exp=0x%08X recomp=0x%08X "
                  "obs=0x%08X alt=%s"
                  % (x["name"], x["destination_register_old_value"],
                     x["sixteen_s_expectation"],
                     x["recomputed_expectation_preserve"],
                     x.get("emulator_observed") or 0, x.get("which_alternate")))
    print("\nunion: %s" % json.dumps(rec["status_counts_union"]))
    print("wrote %s" % args.out)
    if rec["n_comparisons_total"] <= 0:
        print("FAILURE: 0 comparisons -- refused")
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
