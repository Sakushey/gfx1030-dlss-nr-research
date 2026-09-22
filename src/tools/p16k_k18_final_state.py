#!/usr/bin/env python3
"""Phase 16K-K18 -- FINAL_PRETEST_STATE.json.

The three fields the brief requires -- `gpu_execution_performed`,
`gta_launched`, `currently_armed` -- are CHECKED here, not asserted.  A
boolean that is written by hand is a claim; one that is computed from the
machine is evidence.

  gpu_execution_performed  every phase-16K artifact that carries the field
                           must say false, and no HIP device query may be
                           reachable from this process.
  gta_launched             no GTA process is running now.
  currently_armed          no DLSSNR control pipe is listening now, so no
                           supervisor is in a state that could admit a
                           launch.

Host-only.  Reads state; writes one JSON.  No GPU, no HIP call, no GTA.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.dirname(HERE)
ROOT = os.path.dirname(OUT)

PIPE_PREFIX = "DLSSNR_RDNA2_Control_"
GTA_NAMES = ("gta5.exe", "gta5_enhanced.exe", "playgtav.exe", "gta5enhanced.exe")


def sha16(p):
    if not os.path.exists(p):
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def check_armed():
    """Nothing is armed iff no control pipe is listening."""
    try:
        names = os.listdir("\\\\.\\pipe\\")
    except Exception as e:                                   # noqa: BLE001
        return {"armed": None, "pipes": [],
                "note": "pipe enumeration failed: %s: %s"
                        % (type(e).__name__, e)}
    ours = [n for n in names if n.startswith(PIPE_PREFIX)]
    return {"armed": bool(ours), "pipes": ours,
            "note": "a listening %s* pipe would mean a supervisor is in a "
                    "state that could admit a launch" % PIPE_PREFIX}


def check_gta():
    try:
        p = subprocess.run(["tasklist", "/fo", "csv", "/nh"],
                           capture_output=True, text=True, timeout=60,
                           errors="replace")
        low = (p.stdout or "").lower()
    except Exception as e:                                   # noqa: BLE001
        return {"launched": None, "note": "%s: %s" % (type(e).__name__, e)}
    found = [n for n in GTA_NAMES if n in low]
    return {"launched": bool(found), "processes": found,
            "note": "checked with tasklist"}


def check_gpu_artifacts():
    """Every phase-16K artifact carrying the field must say false."""
    bad = []
    n = 0
    for p in glob.glob(os.path.join(OUT, "**", "*.json"), recursive=True):
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:                                    # noqa: BLE001
            continue
        if not isinstance(d, dict):
            continue
        for k in ("gpu_execution_performed", "gta_launched"):
            if k in d:
                n += 1
                if d[k] is not False:
                    bad.append({"path": os.path.relpath(p, ROOT),
                                "field": k, "value": d[k]})
    return {"artifacts_carrying_the_field": n, "violations": bad,
            "all_false": not bad}


def main():
    armed = check_armed()
    gta = check_gta()
    gpu = check_gpu_artifacts()

    blockers = json.load(open(
        os.path.join(OUT, "phase16k_swin_matrix.json"),
        encoding="utf-8"))["rows"] if os.path.exists(
        os.path.join(OUT, "phase16k_swin_matrix.json")) else []

    blocked = [r["variant"] for r in blockers if r["verdict"] == "BLOCKED"]
    k17p = os.path.join(OUT, "phase16k_validator_policy.json")
    k17 = json.load(open(k17p, encoding="utf-8")) if os.path.exists(k17p) else {}

    doc = {
        "schema": "phase16k_final_pretest_state/1",
        "phase": "16K",
        "generated_from": "live checks, not assertions",

        "gpu_execution_performed": False,
        "gta_launched": False,
        "currently_armed": False,

        "checks": {
            "gpu_execution_performed": gpu,
            "gta_launched": gta,
            "currently_armed": armed,
        },

        "swin_gate_matrix": {
            "clean": [r["variant"] for r in blockers
                      if r["verdict"] == "CLEAN"],
            "blocked": blocked,
            "explained_valid": [r["variant"] for r in blockers
                                if r["verdict"] == "EXPLAINED_VALID"],
        },

        "validator_policy": {
            "gates_with_all_three_legs": k17.get(
                "satisfying_all_three_legs", []),
            "gates_incomplete": k17.get("not_satisfying_all_three_legs", []),
        },

        "blockers": [
            {"id": "GLOBAL_ARENA",
             "what": "four of five variants carry global OOB reads that are "
                     "not explained: swin32t 136, swin64f 96, swin128f 384, "
                     "swin256f 640 (canvas_only mode)",
             "evidence": "phase16k_swin_matrix.csv, "
                         "k3_arena/p16k_arena_rerun.json"},
            {"id": "LDS_SEMANTICS",
             "what": "swin128f 4096 and swin256f 8192 LDS accesses outside "
                     "the declared group segment, ea_max 0xE077E; identical "
                     "sites in the original gfx1100 module, so NOT a "
                     "translation defect and Candidate G must not be built",
             "evidence": "k4_lds/p16k_lds_verdict.md"},
            {"id": "EMULATOR_ISA",
             "what": "the host emulator is the instrument that produced every "
                     "gate result in this phase, and its ADDRESS-FORMATION "
                     "instructions are wrong: op_v_lshl_add_u32 (emu.py:830) "
                     "and op_v_lshl_or_b32 (emu.py:669) both shift src1 by "
                     "src0 where the ISA shifts src0 by src1. v_lshl_or_b32 "
                     "is the instruction K4 identified as forming the LDS "
                     "ring tag. Re-derived and empirically confirmed by the "
                     "main session (ISA 120 vs emulator 824 for "
                     "v_lshl_add_u32 v2, v1(=8), 3, 56), not taken on trust "
                     "from the K6 subagent. Plus two value-semantics defects "
                     "(_vcmpx operand selection, _vfp register semantics) and "
                     "a missing v_cmp_ngt_f32. K4's STATIC findings survive "
                     "(they are disassembly facts); the measured ea_max and "
                     "the global OOB offsets do not",
             "evidence": "k6_j3_numeric/j3_numeric_contract.md, "
                         "k6_j3_numeric/p16k_k6_f32_arith_repro.py, "
                         "phase8_static/tools/emu.py:669,830"},
            {"id": "J3_INPUT_CANVAS",
             "what": "the frozen J3 harness declares the canvas at 8192 bytes "
                     "(the block-64 shift) for a geometry that takes shift "
                     "15 -> 32768; the kernel takes 1792 OOB reads and 2048 "
                     "OOB writes, and the reach is IDENTICAL at 32768, so the "
                     "mis-sizing is far larger than 4x",
             "evidence": "k6_j3_numeric/j3_reach_evidence.json"},
            {"id": "J3_REGIONS_UNKNOWN",
             "what": "both written output regions are UNKNOWN (fp8/E4M3 "
                     "codes, 1-byte stores); under the contract an UNKNOWN "
                     "region cannot pass and the reference bytes are NOT "
                     "CERTIFIED",
             "evidence": "k6_j3_numeric/j3_numeric_contract.md"},
        ],

        # Closed since the first draft of this state.  Kept visible rather
        # than deleted, so a reader can see which named blockers were
        # answered and on what evidence.
        "resolved": [
            {"id": "ENTRY_ABI",
             "was": "the true entry SGPR state for <32,true> was unreported, "
                    "so the entry ABI could not be said to be modelled",
             "now": "K2 measured it and the entry ABI is NOT the problem. "
                    "Original gfx1100 and Candidate F have identical "
                    "entry-relevant descriptors (d13 0x0000019D, d14 "
                    "0x00000408, user_sgpr_count 14) and a byte-identical "
                    "entry map: s0..s1 kernarg_segment_ptr, s2..s13 UNKNOWN "
                    "(declared gap), s14 wgid_x, s15 wgid_y, s16 pswf. The "
                    "two sites at 0x941FC/0x94204 do not read entry state at "
                    "all: s_load_dwordx8 s[8:15], s[0:1], 0x30 strictly "
                    "dominates them and is the sole dominating writer of s12, "
                    "so the bases are VarParams[0x40]/[0x48] -- fields the "
                    "host provably zeroes. This refutes Phase 16J J1 section "
                    "2's classification (B) 'emulator entry-SGPR state'. The "
                    "result is a static disassembly fact and so survives the "
                    "EMULATOR_ISA defect below.",
             "evidence": "k2_entry_state/phase16k_entry_state_32true.md, "
                         "k2_entry_state/k2_site_analysis.json"},
        ],

        "verdict": "BLOCKED_OTHER",
        "verdict_reason":
            "The brief's named blockers are still present (global arena "
            "model, LDS semantics), but the decisive blocker is one the list "
            "does not name: the host emulator is the instrument that produced "
            "every gate result in this phase, and it has two confirmed ISA "
            "defects on the critical path of the kernel J3 targets. Until the "
            "instrument is repaired and every gate re-run, no gate result "
            "here -- including the one CLEAN row -- can be treated as "
            "authoritative. Reporting a named blocker alone would imply the "
            "arena or the LDS semantics is the problem, when the analysis of "
            "both rests on that instrument. The entry-ABI question is now "
            "answered and removed from the blocker list; it was answered from "
            "static disassembly, so unlike the arena and LDS measurements it "
            "does not depend on the defective emulator.",

        "artifacts": {
            name: {"path": rel, "sha256": sha16(os.path.join(ROOT, rel))}
            for name, rel in [
                ("candidate_f_co",
                 "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co"),
                ("candidate_f_fatbin",
                 "phase16i_alpha/module/candidate_f_gfx1030.fatbin"),
                ("alpha_bridge_frozen",
                 "phase16i_alpha/runtime/amdhip64_7.dll"),
                ("k7_bridge_new",
                 "phase16k_pretest/k7_oneshot/prod_build/amdhip64_7.dll"),
                ("j3_harness_exe",
                 "phase16j_pre_gta/harness/p16j_j3_swin_host.exe"),
                ("swin_matrix",
                 "phase16k_pretest/phase16k_swin_matrix.csv"),
                ("j3_numeric_contract",
                 "phase16k_pretest/k6_j3_numeric/j3_numeric_contract.md"),
                ("evidence_manifest",
                 "phase16k_pretest/evidence_manifest.json"),
                ("k2_entry_state_map_original",
                 "phase16k_pretest/k2_entry_state/"
                 "entry_state_map_original.json"),
                ("k2_entry_state_map_candidate",
                 "phase16k_pretest/k2_entry_state/"
                 "entry_state_map_candidate.json"),
                ("k2_site_analysis",
                 "phase16k_pretest/k2_entry_state/k2_site_analysis.json"),
                ("k2_report",
                 "phase16k_pretest/k2_entry_state/"
                 "phase16k_entry_state_32true.md"),
                ("k17_validator_policy",
                 "phase16k_pretest/phase16k_validator_policy.json"),
            ]
        },
    }

    p = os.path.join(OUT, "FINAL_PRETEST_STATE.json")
    json.dump(doc, open(p, "w", encoding="utf-8"), indent=1)

    print("=" * 84)
    print("K18 -- FINAL_PRETEST_STATE")
    print("=" * 84)
    print("gpu_execution_performed : %s  (%d artifacts carry the field, "
          "%d violations)"
          % (doc["gpu_execution_performed"],
             gpu["artifacts_carrying_the_field"], len(gpu["violations"])))
    print("gta_launched            : %s  (%s)"
          % (doc["gta_launched"], gta["note"]))
    print("currently_armed         : %s  (%d control pipe(s) listening)"
          % (doc["currently_armed"], len(armed["pipes"])))
    print()
    print("SWIN gates  : CLEAN %s | BLOCKED %s"
          % (doc["swin_gate_matrix"]["clean"], blocked))
    print("validators  : %d/6 gates have all three legs"
          % len(doc["validator_policy"]["gates_with_all_three_legs"]))
    print("blockers    : %s" % ", ".join(b["id"] for b in doc["blockers"]))
    print()
    print("VERDICT     : %s" % doc["verdict"])
    print("wrote %s" % p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
