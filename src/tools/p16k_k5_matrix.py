#!/usr/bin/env python3
"""Phase 16K-K5 -- the five-variant SWIN host-gate matrix.

Builds `phase16k_swin_matrix.csv` from MEASURED artifacts rather than from
the prose in the K3/K4 reports.  Every number in the CSV is read out of a
JSON this phase produced; nothing is retyped from a markdown table.

Vocabulary is the brief's, and there is no AMBER:

  CLEAN            every gate passes under the corrected arena model.
  EXPLAINED_VALID  a gate fires, the firing is fully explained, and the
                   access is shown to be legitimate (a harness artefact).
  BLOCKED          a gate fires and the access is NOT shown to be valid.

An unexplained firing is BLOCKED, never EXPLAINED_VALID.  "We know which
site it is" is not "we know it is fine".

Cross-check: the LDS outside count is taken from the K3 re-run's own
`lds_counters` AND from the independent K4 census files, and the two must
agree before a row is emitted.  A matrix that silently preferred one source
would be the "verify artifacts, not exit codes" failure again.

Host-only.  Reads JSON; writes the CSV and its companion markdown.
"""
from __future__ import annotations

import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.dirname(HERE)
RERUN = os.path.join(OUT, "k3_arena", "p16k_arena_rerun.json")
K4 = os.path.join(OUT, "k4_lds")

VARIANTS = ["swin32f", "swin32t", "swin64f", "swin128f", "swin256f"]
CELL = {"swin32f": "<32,false>", "swin32t": "<32,true>", "swin64f": "<64,false>",
        "swin128f": "<128,false>", "swin256f": "<256,false>"}
KERNEL = {
    "swin32f": "_Z10k_swin_varILi32ELb0EEv9VarParams",
    "swin32t": "_Z10k_swin_varILi32ELb1EEv9VarParams",
    "swin64f": "_Z10k_swin_varILi64ELb0EEv9VarParams",
    "swin128f": "_Z10k_swin_varILi128ELb0EEv9VarParams",
    "swin256f": "_Z10k_swin_varILi256ELb0EEv9VarParams",
}

# The K4 census files that independently report `n_outside` for a variant.
K4_CENSUS = {
    "swin128f": "p16k_lds_census_swin128f_w8_genA_postK1.json",
    "swin256f": "p16k_lds_census_swin256f_w8.json",
}

# The two sites Phase 16J called "entry-SGPR reads".  K2 proved by CFG
# dominance that they do NOT read entry state: `s_load_dwordx8 s[8:15],
# s[0:1], 0x30` strictly dominates them and is the sole dominating writer of
# s12, so the bases are VarParams[0x40]/[0x48] -- kernarg fields the host
# zeroes.  The label below is K2's, not Phase 16J's.
VARPARAMS_40_48_SITES = {"0x000941FC", "0x00094204"}


def load():
    return json.load(open(RERUN, encoding="utf-8"))


def k4_lds_outside(tag):
    """Independent LDS outside count from the K4 census, or None."""
    fn = K4_CENSUS.get(tag)
    if not fn:
        return None
    p = os.path.join(K4, fn)
    if not os.path.exists(p):
        return None
    d = json.load(open(p, encoding="utf-8"))
    return d["census"]["n_outside"]


def classify(global_res, lds_out, vp_n, canvas_n):
    """Return (verdict, reason).  No AMBER, no benefit of the doubt."""
    if global_res == 0 and lds_out == 0:
        return "CLEAN", "every gate passes under the corrected arena model"
    parts = []
    if global_res:
        detail = []
        if vp_n:
            detail.append("%d reads of VarParams[0x40]/[0x48], kernarg "
                          "fields the host zeroes (K2; NOT entry SGPRs as "
                          "Phase 16J classified them)" % vp_n)
        if canvas_n:
            detail.append("%d canvas-family reads beyond the mod's own "
                          "allocation" % canvas_n)
        parts.append("%d global OOB reads: %s"
                     % (global_res, "; ".join(detail) or "unattributed"))
    if lds_out:
        parts.append("%d LDS accesses outside the declared group segment"
                     % lds_out)
    return "BLOCKED", "; ".join(parts)


def build():
    d = load()
    rows = []
    xchecks = []
    for tag in VARIANTS:
        v = d["variants"][tag]
        co = v["canvas_only"]
        cmp_ = v["comparison"]
        lds = co["lds_counters"]

        global_res = co["oob_reads"]
        lds_out = lds["n_rw_outside_declared_bound"]

        # Independent cross-check of the LDS count.  A variant with no
        # independent source is recorded as NOT CHECKED, never as agreed --
        # counting an absent comparison as a pass is the vacuous-verifier
        # failure this project has hit before.
        k4 = k4_lds_outside(tag)
        xchecks.append({"variant": tag, "rerun_lds_outside": lds_out,
                        "k4_census_lds_outside": k4,
                        "checked": k4 is not None,
                        "agree": (k4 == lds_out) if k4 is not None else None})

        rs = cmp_.get("residual_sites_after") or {}
        vp_n = sum(v2["n"] for k, v2 in rs.items()
                   if k in VARPARAMS_40_48_SITES)
        canvas_n = sum(v2["n"] for k, v2 in rs.items()
                       if k not in VARPARAMS_40_48_SITES)

        verdict, reason = classify(global_res, lds_out, vp_n, canvas_n)
        rows.append({
            "variant": tag,
            "cell": CELL[tag],
            "kernel": KERNEL[tag],
            "waves": d["waves"],
            "generator": d["generator"],
            "global_oob_baseline": cmp_["oob_reads_before"],
            "global_oob_after_canvas_fix": global_res,
            "explained_by_real_canvas": cmp_["explained_by_real_canvas"],
            "residual_varparams_40_48_reads": vp_n,
            "residual_canvas_family_reads": canvas_n,
            "lds_group_segment_bytes": lds["group_segment_fixed_size"],
            "lds_rw_total": lds["n_rw"],
            "lds_outside_bound": lds_out,
            "lds_ea_max": "0x%X" % lds["ea_max"],
            "ticks": co["ticks"],
            "execution_signature": co["execution_signature"],
            "gates_pass": co["all_gates_pass"],
            "gates_failing": ";".join(cmp_["gates_failing_after"]) or "none",
            "verdict": verdict,
            "reason": reason,
        })
    return d, rows, xchecks


def write_csv(rows, path):
    cols = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main():
    d, rows, xchecks = build()

    bad = [x for x in xchecks if x["agree"] is False]
    if bad:
        print("LDS CROSS-CHECK FAILED -- refusing to emit the matrix")
        for x in bad:
            print("  %s rerun=%s k4=%s" % (x["variant"],
                                           x["rerun_lds_outside"],
                                           x["k4_census_lds_outside"]))
        return 1

    csv_path = os.path.join(OUT, "phase16k_swin_matrix.csv")
    write_csv(rows, csv_path)
    json_path = os.path.join(OUT, "phase16k_swin_matrix.json")
    json.dump({"schema": "phase16k_swin_matrix/1",
               "phase": "16K", "host_only": True,
               "gpu_execution_performed": False, "gta_launched": False,
               "source": "k3_arena/p16k_arena_rerun.json (canvas_only mode)",
               "cross_checks": xchecks,
               "rows": rows},
              open(json_path, "w", encoding="utf-8"), indent=1)

    print("=" * 100)
    print("K5 -- five-variant SWIN host-gate matrix (8 waves, generator A)")
    print("=" * 100)
    hdr = ("variant", "cell", "g_oob", "vp40/48", "canvas", "lds_out",
           "verdict")
    print("%-10s %-12s %6s %8s %7s %8s  %s" % hdr)
    for r in rows:
        print("%-10s %-12s %6d %6d %7d %8d  %s"
              % (r["variant"], r["cell"], r["global_oob_after_canvas_fix"],
                 r["residual_varparams_40_48_reads"],
                 r["residual_canvas_family_reads"], r["lds_outside_bound"],
                 r["verdict"]))
    print()
    for r in rows:
        print("  %-10s %s" % (r["variant"], r["reason"]))
    print()
    tally = {}
    for r in rows:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    print("tally: %s" % ", ".join("%s=%d" % kv for kv in sorted(tally.items())))
    nchk = sum(1 for x in xchecks if x["checked"])
    nok = sum(1 for x in xchecks if x["agree"] is True)
    print("LDS cross-check: %d/%d checked, %d agree, %d unchecked"
          % (nchk, len(xchecks), nok, len(xchecks) - nchk))
    print("wrote %s" % csv_path)
    print("wrote %s" % json_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
