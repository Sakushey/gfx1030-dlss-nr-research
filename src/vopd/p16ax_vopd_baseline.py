#!/usr/bin/env python3
"""Phase 16AX T-VOPD -- STEP 0: re-establish the 16AW baseline.

WHY
  A baseline that does not reproduce is itself the finding.  Before any change,
  the published 16AW numbers must come back from the published inputs.

HOW IT AVOIDS MUTATING p16aw/
  The 16AW driver scripts write their census JSON next to themselves.  T-VOPD
  may not write under p16aw/, so this module IMPORTS both 16AW modules and
  drives their functions directly, writing its output here.  It hashes every
  p16aw/vopd artefact before and after and asserts the digest is unchanged,
  so "I did not write there" is measured, not asserted.

WHAT IT CHECKS  (per-record, not by aggregate count -- house rule 6)
  B1  symbol census: 123 pairs, 11 hazard, 1 left-before-right, 11/11 controls
  B2  every one of the 123 per-site records equals the published record
  B3  the 11 published hazard records equal the recomputed ones, value by value
  B4  cross-kernel census: 68 symbols / 1509 vopd / 13 l2r / 80 r2l / 53 unk
      / 10 kernels with a left-before-right site, and every per-kernel row equal
  B5  the mandatory regression: 0xCB8DC with v0=8 -> old v1 = 0x100,
      atomic v54 = 0x100, printed-order-sequential v54 = 0x000
  B6  all six p16aw artefacts byte-identical before and after

WHAT THIS DOES NOT ESTABLISH
  Nothing about any lowered stream and nothing about the GPU.  It is a
  reproduction record only.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

import p16ax_vopd_model as M  # noqa: E402

V = M.V

FROZEN = [
    M.AW_ANALYZER,
    os.path.join(M.AW_VOPD, "p16aw_vopd_cross_kernel.py"),
    M.AW_CENSUS,
    M.AW_CROSS,
    M.AW_SYM_DIS,
    M.AW_FULL_DIS,
    M.CF_FULL_DIS,
]


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def digest_set():
    return {os.path.relpath(p, ROOT).replace("\\", "/"): sha256(p) for p in FROZEN}


def main():
    checks = []

    def check(cid, what, ok, detail):
        checks.append({"id": cid, "what": what, "ok": bool(ok), "detail": detail})
        print("[%s] %-4s %s" % ("PASS" if ok else "FAIL", cid, what))
        if not ok:
            print("       %s" % (detail,))

    before = digest_set()

    # ---------------- B1/B2/B3  symbol census ----------------
    pairs, skipped = V.parse_disassembly(M.AW_SYM_DIS)
    rows = []
    hist = {}
    for p in pairs:
        c = V.classify_pair(p["x"], p["y"])
        hist[c["class"]] = hist.get(c["class"], 0) + 1
        rows.append({"addr": "0x%X" % p["addr"], "x": p["x"], "y": p["y"],
                     "class": c["class"],
                     "left_writes_right_reads": c.get("left_writes_right_reads"),
                     "right_writes_left_reads": c.get("right_writes_left_reads"),
                     "implicit_dest_read_present": c.get("implicit_dest_read_present"),
                     "why": c.get("why")})
    ctrl_rows, ctrl_ok = V.run_controls()

    pub = json.load(open(M.AW_CENSUS, encoding="utf-8"))

    check("B1.1", "symbol census: 123 VOPD pairs", len(pairs) == 123, "got %d" % len(pairs))
    check("B1.2", "symbol census: 0 unparsed lines", len(skipped) == 0, "got %d" % len(skipped))
    check("B1.3", "symbol census: histogram equals published",
          hist == pub["classification_histogram"],
          "recomputed=%s published=%s" % (hist, pub["classification_histogram"]))
    check("B1.4", "symbol census: 11 cross-dependent sites",
          pub["n_hazard_sites_total"] == 11 and
          sum(v for k, v in hist.items() if k.startswith("HAZARD")) == 11,
          "published=%s recomputed=%s" % (pub["n_hazard_sites_total"],
                                          sum(v for k, v in hist.items() if k.startswith("HAZARD"))))
    check("B1.5", "symbol census: exactly 1 LEFT_BEFORE_RIGHT",
          hist.get("HAZARD_LEFT_BEFORE_RIGHT", 0) == 1,
          "got %d" % hist.get("HAZARD_LEFT_BEFORE_RIGHT", 0))
    check("B1.6", "analyzer controls: 11/11 pass", ctrl_ok == 11 and len(ctrl_rows) == 11,
          "got %d/%d" % (ctrl_ok, len(ctrl_rows)))
    check("B1.7", "every control reached the classifier (no silent no-op)",
          all(r["got"] is not None for r in ctrl_rows),
          "a control with got=None died before the comparison")

    # B2: per-record equality, address by address
    pub_pairs = {r["addr"]: r for r in pub["all_pairs"]}
    mism = []
    for r in rows:
        q = pub_pairs.get(r["addr"])
        if q is None:
            mism.append((r["addr"], "missing from published"))
        elif q != r:
            diff = {k: (r.get(k), q.get(k)) for k in set(r) | set(q) if r.get(k) != q.get(k)}
            mism.append((r["addr"], diff))
    check("B2.1", "all 123 per-site records reproduce value-by-value",
          len(rows) == 123 and not mism,
          "%d mismatching records, first: %s" % (len(mism), mism[:1]))

    # B3: hazard records value by value
    pub_haz = {r["addr"]: r for r in pub["hazard_sites"]}
    haz = [r for r in rows if r["class"].startswith("HAZARD")]
    hazm = [(r["addr"], {k: (r.get(k), pub_haz[r["addr"]].get(k))
                         for k in set(r) | set(pub_haz[r["addr"]])
                         if r.get(k) != pub_haz[r["addr"]].get(k)})
            for r in haz if r["addr"] in pub_haz and r != pub_haz[r["addr"]]]
    check("B3.1", "all 11 hazard records reproduce value-by-value",
          len(haz) == 11 and len(pub_haz) == 11 and not hazm,
          "%d hazard records, %d mismatching: %s" % (len(haz), len(hazm), hazm[:1]))

    # ---------------- B5  mandatory regression ----------------
    site = [p for p in pairs if p["addr"] == 0xCB8DC]
    if len(site) != 1:
        check("B5.1", "0xCB8DC present exactly once", False, "found %d" % len(site))
        reg = None
    else:
        p = site[0]
        check("B5.1", "0xCB8DC is the published left-before-right site",
              p["x"] == "v_dual_mov_b32 v1, 0" and p["y"] == "v_dual_and_b32 v54, 0x180, v1"
              and V.classify_pair(p["x"], p["y"])["class"] == "HAZARD_LEFT_BEFORE_RIGHT",
              "%s :: %s" % (p["x"], p["y"]))
        # the preceding instruction that makes old v1 = 0x100 for v0 = 8
        pre = None
        for raw in open(M.AW_SYM_DIS, encoding="utf8", errors="replace"):
            if "0000000CB8D8:" in raw:
                pre = raw.strip()
                break
        check("B5.2", "the preceding instruction is v_lshlrev_b32 v1, 5, v0",
              pre is not None and "v_lshlrev_b32_e32 v1, 5, v0" in pre, str(pre))
        old_v1 = (8 << 5) & 0xFFFFFFFF
        check("B5.3", "v0 = 8 -> old v1 = 0x100",
              old_v1 == 0x100, "got 0x%X" % old_v1)
        r = V.atomic_vs_sequential(p["x"], p["y"], {"v0": 8, "v1": old_v1})
        reg = {"old_v1": "0x%X" % old_v1, "atomic": {"v1": "0x%X" % r["atomic"]["v1"],
                                                     "v54": "0x%X" % r["atomic"]["v54"]},
               "sequential_printed_order": {
                   "v1": "0x%X" % r["sequential_left_then_right"]["v1"],
                   "v54": "0x%X" % r["sequential_left_then_right"]["v54"]},
               "discriminating": r["discriminating"]}
        check("B5.4", "atomic v54 = 0x100 (reads the PRE-instruction v1)",
              r["atomic"]["v54"] == 0x100, "got 0x%X" % r["atomic"]["v54"])
        check("B5.5", "printed-order sequential v54 = 0x000 (reads the NEW v1)",
              r["sequential_left_then_right"]["v54"] == 0x000,
              "got 0x%X" % r["sequential_left_then_right"]["v54"])
        check("B5.6", "the site is discriminating", r["discriminating"] is True, "not discriminating")

    # ---------------- B4  cross-kernel census ----------------
    import p16aw_vopd_cross_kernel as CK  # noqa: E402

    syms = CK.elf_kernel_symbols(M.PARENT_ELF)
    full_pairs, full_skipped = V.parse_disassembly(M.AW_FULL_DIS)
    bounds = sorted((v[0], v[0] + v[1], n) for n, v in syms.items())
    krows = []
    for lo, hi, name in bounds:
        inside = [p for p in full_pairs if lo <= p["addr"] < hi]
        l2r = r2l = unk = 0
        for p in inside:
            k = V.classify_pair(p["x"], p["y"])["class"]
            if k == "UNKNOWN_BLOCKING":
                unk += 1
            elif k == "HAZARD_LEFT_BEFORE_RIGHT":
                l2r += 1
            elif k == "HAZARD_RIGHT_BEFORE_LEFT":
                r2l += 1
            elif k == "HAZARD_BOTH_DIRECTIONS":
                l2r += 1
                r2l += 1
        krows.append({"kernel": name, "symbol_va": "0x%X" % lo, "symbol_size": hi - lo,
                      "n_vopd": len(inside), "n_hazard_l2r": l2r,
                      "n_hazard_r2l": r2l, "n_unknown": unk})
    krows.sort(key=lambda r: (-r["n_hazard_l2r"], -r["n_vopd"], r["kernel"]))
    cpub = json.load(open(M.AW_CROSS, encoding="utf-8"))
    tot_l2r = sum(r["n_hazard_l2r"] for r in krows)
    tot_r2l = sum(r["n_hazard_r2l"] for r in krows)
    tot_v = sum(r["n_vopd"] for r in krows)
    tot_u = sum(r["n_unknown"] for r in krows)
    with_l2r = [r["kernel"] for r in krows if r["n_hazard_l2r"]]

    check("B4.1", "cross-kernel: 68 kernel symbols", len(syms) == 68, "got %d" % len(syms))
    check("B4.2", "cross-kernel: 1509 VOPD pairs, 0 unparsed",
          len(full_pairs) == 1509 and len(full_skipped) == 0,
          "got %d pairs / %d unparsed" % (len(full_pairs), len(full_skipped)))
    check("B4.3", "cross-kernel: 13 left-before-right", tot_l2r == 13, "got %d" % tot_l2r)
    check("B4.4", "cross-kernel: 80 right-before-left", tot_r2l == 80, "got %d" % tot_r2l)
    check("B4.5", "cross-kernel: 53 UNKNOWN_BLOCKING", tot_u == 53, "got %d" % tot_u)
    check("B4.6", "cross-kernel: 10 kernels carry a left-before-right site",
          len(with_l2r) == 10, "got %d" % len(with_l2r))
    check("B4.7", "cross-kernel: the 10 kernel NAMES reproduce",
          with_l2r == cpub["kernels_with_a_left_before_right_site"],
          "recomputed=%s published=%s" % (with_l2r, cpub["kernels_with_a_left_before_right_site"]))
    pubk = {r["kernel"]: r for r in cpub["per_kernel"]}
    km = []
    for r in krows:
        q = pubk.get(r["kernel"])
        if q is None:
            km.append((r["kernel"], "missing"))
            continue
        diff = {k: (r[k], q.get(k)) for k in r if r[k] != q.get(k)}
        if diff:
            km.append((r["kernel"], diff))
    check("B4.8", "cross-kernel: all 68 per-kernel rows reproduce value-by-value",
          not km, "%d rows differ, first: %s" % (len(km), km[:1]))

    # ---------------- B6  no mutation under p16aw/ ----------------
    after = digest_set()
    changed = {k: (before[k], after[k]) for k in before if before[k] != after[k]}
    check("B6.1", "all 7 p16aw artefacts byte-identical before and after",
          not changed, "CHANGED: %s" % (changed,))

    n_pass = sum(1 for c in checks if c["ok"])
    verdict = "BASELINE_REPRODUCED" if n_pass == len(checks) else "BASELINE_DOES_NOT_REPRODUCE"

    out = {
        "schema": "p16ax/vopd-baseline/1",
        "worker": "W1",
        "task_id": "T-VOPD",
        "phase": "16AX",
        "host_only": True,
        "gpu_calls": 0,
        "what": "STEP 0 -- reproduce the 16AW VOPD baseline before changing anything",
        "how_without_mutating_p16aw": (
            "both 16AW modules are IMPORTED and driven from here; the 16AW driver "
            "scripts are never executed, so their census JSON is never rewritten"),
        "published_numbers_claimed": {
            "symbol": {"n_vopd_pairs": 123, "n_hazard": 11,
                       "n_hazard_left_before_right": 1, "controls": "11/11"},
            "cross_kernel": {"n_kernel_symbols": 68, "n_vopd_total": 1509,
                             "n_hazard_left_before_right": 13,
                             "n_hazard_right_before_left": 80,
                             "n_unknown_blocking": 53,
                             "kernels_with_a_left_before_right_site": 10},
        },
        "recomputed": {
            "symbol": {"n_vopd_pairs": len(pairs), "histogram": hist,
                       "n_hazard": sum(v for k, v in hist.items() if k.startswith("HAZARD"))},
            "controls": {"n": len(ctrl_rows), "n_passed": ctrl_ok},
            "cross_kernel": {"n_kernel_symbols": len(syms), "n_vopd_total": tot_v,
                             "n_hazard_left_before_right": tot_l2r,
                             "n_hazard_right_before_left": tot_r2l,
                             "n_unknown_blocking": tot_u,
                             "kernels_with_a_left_before_right_site": with_l2r},
        },
        "mandatory_regression_0xCB8DC": reg,
        "checks": checks,
        "n_checks": len(checks),
        "n_passed": n_pass,
        "verdict": verdict,
        "what_this_establishes": (
            "the 16AW analyzer and cross-kernel census reproduce their published "
            "numbers per-record from the published inputs, and p16aw/ was not "
            "written to while doing it"),
        "what_this_does_NOT_establish": (
            "it says nothing about any lowered stream, about Candidate F, or about "
            "the GPU.  A reproduced baseline is not a correct fix."),
    }
    path = os.path.join(HERE, "BASELINE_REPRODUCTION_16AX.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("\n%d/%d checks passed -> %s" % (n_pass, len(checks), verdict))
    print("wrote", path)
    return 0 if n_pass == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
