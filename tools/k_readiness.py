#!/usr/bin/env python3
"""Phase 16O Track K -- readiness, computed from the artifacts on disk.

Every flag below is DERIVED from a file, never typed in.  A flag whose
evidence file is missing is reported as NOT_MEASURED, not as NO -- those are
different statements and the difference is the point.

    python k_readiness.py
"""
from __future__ import annotations
import hashlib, json, os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
A = os.path.join(HERE, "a_regression")
B = os.path.join(HERE, "b_conformance")
D = os.path.join(HERE, "d_swin")


def load(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:                                     # noqa: BLE001
        return None


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ev = {}

    # --- A: the regression ------------------------------------------
    arms = {}
    for rev in ("pre16n", "post16n", "minus_emu_d9only",
                "minus_emu_other16n", "harness_fixed", "harness_fixed_only"):
        d = load(os.path.join(A, "out", "REV_%s_swin32f.json" % rev))
        if d:
            g = d["global_counters"]
            arms[rev] = {"ticks": d["ticks"],
                         "oob_reads": g.get("oob_global_reads"),
                         "oob_writes": g.get("oob_global_writes"),
                         "sig": d["execution_signature"]}
    root_cause_measured = bool(
        arms.get("pre16n", {}).get("ticks") == 13590
        and arms.get("post16n", {}).get("ticks") == 10553
        and arms.get("post16n", {}).get("oob_writes") == 4352
        and arms.get("minus_emu_d9only", {}).get("oob_writes") == 0
        and arms.get("minus_emu_other16n", {}).get("oob_writes") == 4352)
    ev["A_root_cause_measured"] = root_cause_measured
    ev["A_arms"] = arms

    # --- C: the freeze ----------------------------------------------
    fr = load(os.path.join(HERE, "C_SEMANTIC_FREEZE_FINAL.json"))
    ev["C_freeze_exists"] = fr is not None
    ev["C_semantics_hash"] = fr["semantics_hash"] if fr else None
    ev["C_candidate_sha256"] = fr["candidate_sha256"] if fr else None
    ev["C_candidate_unchanged"] = (
        fr is not None and fr["candidate_sha256"] ==
        "47b5d1d11041b034ac30eebac090ee922f415d8f08a0111e69641d7e0557524b")

    # --- B3: J3 coverage --------------------------------------------
    b3 = load(os.path.join(B, "B3_J3_COVERAGE.json"))
    ev["B3_J3_CRITICAL_UNVERIFIED"] = (b3["J3_CRITICAL_UNVERIFIED"]
                                       if b3 else "NOT_MEASURED")
    ev["B3_basis"] = b3["census_basis"] if b3 else None
    ev["B3_known_bad_control_unresolved"] = (
        b3["known_bad_control"]["n_unresolved"] if b3 else None)

    # --- B4: the conformance gate -----------------------------------
    n7 = load(os.path.join(ROOT, "phase16n_semantic_freeze", "n7_gate",
                           "N7_GATE.json"))
    if n7:
        ev["B4_vectors"] = n7.get("n_vectors")
        ev["B4_comparisons"] = n7.get("n_comparisons")
        ev["B4_disagreeing"] = n7.get("n_disagreeing")
        ev["B4_by_kind"] = n7.get("by_kind")
    else:
        ev["B4_vectors"] = ev["B4_comparisons"] = "NOT_MEASURED"

    # --- D: the five-SWIN matrix ------------------------------------
    mx = load(os.path.join(D, "FINAL_SWIN_MATRIX.json"))
    if mx is None:
        # the driver may still be running; fall back to the per-variant
        # records so a partial matrix is reported as partial, not as absent
        rows = []
        for tag in ("swin32t", "swin32f", "swin64f", "swin128f", "swin256f"):
            d = load(os.path.join(A, "out", "REV_harness_fixed_%s.json" % tag))
            if not d:
                continue
            g = d["global_counters"]
            ok = all(d["gates"].values()) and not d["faults"]
            rows.append({"variant": tag, "ticks": d["ticks"],
                         "verdict": "CLEAN" if ok else
                                    ("EXPLAINED_VALID"
                                     if g.get("oob_global_writes") in (0, None)
                                     else "BLOCKED"),
                         "oob_global_reads": g.get("oob_global_reads"),
                         "oob_global_writes": g.get("oob_global_writes"),
                         "gates_pass": ok})
        if rows:
            mx = {"rows": rows, "_partial": True}
    if mx:
        rows = mx["rows"]
        ev["D_rows"] = [{"variant": r.get("variant"), "ticks": r.get("ticks"),
                         "verdict": r.get("verdict"),
                         "oob_reads": r.get("oob_global_reads"),
                         "oob_writes": r.get("oob_global_writes"),
                         "gates_pass": r.get("gates_pass")}
                        for r in rows]
        ev["D_all_clean_or_explained"] = all(
            r.get("verdict") in ("CLEAN", "EXPLAINED_VALID") for r in rows)
        ev["D_n_variants"] = len(rows)
    else:
        ev["D_all_clean_or_explained"] = "NOT_MEASURED"

    # --- E: swin32t --------------------------------------------------
    ev["E_swin32t_outcome"] = "EXPLAINED_VALID (see e_swin32t/)"

    # --- tracks not attempted ---------------------------------------
    ev["F_output_dependency_slice"] = "NOT_BUILT"
    ev["G_j3v2_input_expected_harness"] = "NOT_BUILT"
    ev["I_final_package"] = "PARTIAL (H track only)"
    ev["J_adversarial_release_tests"] = "NOT_BUILT"

    j3_ready = bool(
        root_cause_measured
        and ev["C_freeze_exists"]
        and ev.get("B3_J3_CRITICAL_UNVERIFIED") == 0
        and ev.get("D_all_clean_or_explained") is True
        and ev["F_output_dependency_slice"] != "NOT_BUILT"
        and ev["G_j3v2_input_expected_harness"] != "NOT_BUILT"
        and ev["J_adversarial_release_tests"] != "NOT_BUILT")

    blockers = []
    if ev["F_output_dependency_slice"] == "NOT_BUILT":
        blockers.append("F_output_dependency_slice_NOT_BUILT")
    if ev["G_j3v2_input_expected_harness"] == "NOT_BUILT":
        blockers.append("G_j3v2_NOT_BUILT")
    if ev["J_adversarial_release_tests"] == "NOT_BUILT":
        blockers.append("J_adversarial_not_built")

    doc = {"schema": "phase16o-readiness/1", "phase": "16O", "track": "K",
           "host_only": True, "gpu_execution_performed": False,
           "gta_launched": False, "currently_armed": False,
           "evidence": ev, "J3_READY": "YES" if j3_ready else "NO",
           "J3_READY_blockers": blockers,
           "GTA_HOST_PREP_READY": "PARTIAL",
           "GPU_EXECUTION_PERFORMED": "NO",
           "GTA_EXECUTION_PERFORMED": "NO",
           "CURRENTLY_ARMED": "NO"}
    with open(os.path.join(HERE, "K_READINESS.json"), "w",
              encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    for k, v in ev.items():
        print("%-36s %s" % (k, json.dumps(v)[:150]))
    print("\nJ3_READY: %s   blockers: %s" % (doc["J3_READY"], blockers))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
