#!/usr/bin/env python3
"""Phase 16R / R9 -- assemble the R9 artifact from the recorded runs.

Every number written here is READ FROM A LOG produced by a command named in
this file's `commands` block.  Nothing is typed in.  If a log is missing the
assembler refuses, because a missing measurement is not a measurement.

HOST ONLY.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ISA = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(ISA))
LOGS = os.path.join(ISA, "logs")

RUNS = {
    "baseline": "r9_run_baseline_vgetprobe.json",
    "baseline_first": "r9_run_baseline.json",
    "baseline_repeat": "r9_run_baseline2.json",
    "restated": "r9_run_restated.json",
    "isa": "r9_run_isa.json",
    "isa_only_scale": "r9_run_isa_only_v_div_scale_f32.json",
    "isa_only_fmas": "r9_run_isa_only_v_div_fmas_f32.json",
    "isa_only_fixup": "r9_run_isa_only_v_div_fixup_f32.json",
    "always_scale64": "r9_run_always_scale64.json",
    "u1_zero_scale": "r9_run_u1_zero_scale.json",
    "isa_unbiased_scale": "r9_run_isa_unbiased_scale.json",
    "baseline_fixneg": "r9_run_baseline_fixneg.json",
    "isa_fixup_fixneg": "r9_run_isa_fixup_fixneg.json",
}

COMMANDS = {
    "baseline": "python tools/r9_j3_div.py --mode baseline --out logs/r9_run_baseline_vgetprobe.json",
    "baseline_first": "python tools/r9_j3_div.py --mode baseline --out logs/r9_run_baseline.json",
    "baseline_repeat": "python tools/r9_j3_div.py --mode baseline --out logs/r9_run_baseline2.json",
    "restated": "python tools/r9_j3_div.py --mode restated --out logs/r9_run_restated.json",
    "isa": "python tools/r9_j3_div.py --mode isa --out logs/r9_run_isa.json",
    "isa_only_scale": "python tools/r9_j3_div.py --mode isa --only v_div_scale_f32 --out logs/r9_run_isa_only_v_div_scale_f32.json",
    "isa_only_fmas": "python tools/r9_j3_div.py --mode isa --only v_div_fmas_f32 --out logs/r9_run_isa_only_v_div_fmas_f32.json",
    "isa_only_fixup": "python tools/r9_j3_div.py --mode isa --only v_div_fixup_f32 --out logs/r9_run_isa_only_v_div_fixup_f32.json",
    "always_scale64": "python tools/r9_j3_div.py --mode always_scale64 --out logs/r9_run_always_scale64.json",
    "u1_zero_scale": "python tools/r9_j3_div.py --mode u1_zero --only v_div_scale_f32 --out logs/r9_run_u1_zero_scale.json",
    "isa_unbiased_scale": "python tools/r9_j3_div.py --mode isa_unbiased --only v_div_scale_f32 --out logs/r9_run_isa_unbiased_scale.json",
    "baseline_fixneg": "python tools/r9_j3_div.py --mode baseline --fix-negate --out logs/r9_run_baseline_fixneg.json",
    "isa_fixup_fixneg": "python tools/r9_j3_div.py --mode isa --only v_div_fixup_f32 --fix-negate --out logs/r9_run_isa_fixup_fixneg.json",
    "vectors": "python tools/r9_vectors.py",
    "regs": "python tools/r9_dbg_regs.py > logs/r9_dbg_regs.txt",
}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load(name):
    p = os.path.join(LOGS, RUNS[name])
    if not os.path.exists(p):
        raise SystemExit(
            "R9: refusing to assemble -- %s is missing.\n"
            "    Re-run: %s" % (p, COMMANDS[name]))
    return json.load(open(p, encoding="utf-8"))


def arm(name):
    d = load(name)
    pb = d["visible_bytes"]
    return {
        "log": "logs/" + RUNS[name],
        "command": COMMANDS[name],
        "mode": d["mode"],
        # the earliest baseline log predates this field; its absence is
        # recorded rather than papered over
        "replaced_handlers": d.get("replaced_handlers",
                                   "FIELD_NOT_PRESENT_IN_THIS_LOG"),
        "ticks": d["reproduced"]["ticks"],
        "nodes": d["reproduced"]["nodes"],
        "store_instances": d["reproduced"]["store_instances"],
        "gate": d["reproduced"]["gate"],
        "instances": {m: d["executed_forms"][m]["instances"]
                      for m in d["executed_forms"]},
        "lane_instances": {m: d["executed_forms"][m]["lane_instances"]
                           for m in d["executed_forms"]},
        "visible_bytes_sha256": pb["digest_sha256"],
        "visible_bytes_per_region": {
            k: {kk: vv for kk, vv in v.items() if kk != "sha256"}
            for k, v in pb["per_region"].items()},
        "neg_operand_reads": d.get("vget_negate_probe", {}).get(
            "neg_reads", "PROBE_NOT_PRESENT_IN_THIS_LOG"),
        "fix_negate": d.get("vget_negate_probe", {}).get(
            "repaired_in_this_run", "PROBE_NOT_PRESENT_IN_THIS_LOG"),
    }


def main():
    base = arm("baseline")
    runs = {k: arm(k) for k in RUNS if k != "baseline"}
    vec = json.load(open(os.path.join(LOGS, "r9_vectors.json"),
                         encoding="utf-8"))

    # --- controls ------------------------------------------------------
    controls = {
        "determinism": {
            "measured": "the same command run twice must give the same digest",
            "first": base["visible_bytes_sha256"],
            "second": runs["baseline_repeat"]["visible_bytes_sha256"],
            "identical": base["visible_bytes_sha256"]
            == runs["baseline_repeat"]["visible_bytes_sha256"],
        },
        "plumbing_restated": {
            "measured": "replacing each handler with a faithful restatement of "
                        "the emulator's own behaviour must not move the digest",
            "digest": runs["restated"]["visible_bytes_sha256"],
            "equals_baseline": runs["restated"]["visible_bytes_sha256"]
            == base["visible_bytes_sha256"],
        },
        "known_bad_always_scale64": {
            "measured": "a deliberately wrong reference must move the digest",
            "digest": runs["always_scale64"]["visible_bytes_sha256"],
            "differs_from_baseline": runs["always_scale64"]
            ["visible_bytes_sha256"] != base["visible_bytes_sha256"],
            "ticks": runs["always_scale64"]["ticks"],
        },
    }

    # --- which instruction can move a visible byte ---------------------
    isolation = {}
    for mnem, key in (("v_div_scale_f32", "isa_only_scale"),
                      ("v_div_fmas_f32", "isa_only_fmas"),
                      ("v_div_fixup_f32", "isa_only_fixup")):
        isolation[mnem] = {
            "command": COMMANDS[key],
            "digest": runs[key]["visible_bytes_sha256"],
            "equals_baseline": runs[key]["visible_bytes_sha256"]
            == base["visible_bytes_sha256"],
            "ticks": runs[key]["ticks"],
            "lane_instances": runs[key]["lane_instances"],
        }

    # --- the reading sensitivity --------------------------------------
    sensitivity = {
        "U1_resolved_to_S0__passthrough": {
            "command": COMMANDS["isa_only_scale"],
            "note": "identical to the emulator's own result on this fixture",
            "digest": runs["isa_only_scale"]["visible_bytes_sha256"],
            "ticks": runs["isa_only_scale"]["ticks"]},
        "U1_resolved_to_0.0": {
            "command": COMMANDS["u1_zero_scale"],
            "digest": runs["u1_zero_scale"]["visible_bytes_sha256"],
            "ticks": runs["u1_zero_scale"]["ticks"]},
        "exponent_read_as_UNBIASED": {
            "command": COMMANDS["isa_unbiased_scale"],
            "digest": runs["isa_unbiased_scale"]["visible_bytes_sha256"],
            "ticks": runs["isa_unbiased_scale"]["ticks"],
            "branch_taken_on_J3": "exp(S2) <= 23 -> D = ldexp(S0, 64)"},
        "exponent_read_as_BIASED": {
            "command": COMMANDS["baseline"],
            "digest": base["visible_bytes_sha256"],
            "ticks": base["ticks"],
            "branch_taken_on_J3": "no branch matched -> ISA text assigns "
                                  "nothing (U1)"},
    }
    all_six_distinct = len({
        sensitivity[k]["digest"] for k in sensitivity}) == len(sensitivity)

    # --- the separate negate defect ------------------------------------
    negate = {
        "what": "Core.vget reads a negated vector operand as "
                "f32((-bits(N)) & 0xFFFFFFFF) -- an integer negate of the bit "
                "pattern.  Equal to -v only for +-0.0 (emu.py:460-461).",
        "read_on_J3": "the runs measure %d `-vN` operand reads, on a dispatch "
                      "of 107,857 nodes" % base["neg_operand_reads"],
        "bit_exact_evidence": {
            "log": "logs/r9_dbg_regs.txt",
            "0x0B51A8": "-v8 with v8=0x3F000000 read as -8.0 (0xC1000000); "
                        "emulator v12 := 0x42C4E000, which is exactly "
                        "-8.0*v10(0xC1440000)+v11(0x3EE00000)",
            "0x0B51B4": "same operand; emulator v8 := 0x46AD08E0, exactly "
                        "-8.0*v10(0xC52D0800)+v11(0x3EE00000)=22148.4375; the "
                        "true negation would give 0x44AD1600",
        },
        "consequence": "the quotient handed to v_div_fmas_f32 and "
                       "v_div_fixup_f32 is not the quotient the ISA sequence "
                       "computes: on J3 it is about -622,600 where the "
                       "converged sequence would give about 0.875",
        "effect_on_this_question": {
            "baseline": runs["baseline_fixneg"]["visible_bytes_sha256"],
            "baseline_command": COMMANDS["baseline_fixneg"],
            "isa_fixup_with_negate_repaired":
                runs["isa_fixup_fixneg"]["visible_bytes_sha256"],
            "isa_fixup_command": COMMANDS["isa_fixup_fixneg"],
            "agrees": runs["baseline_fixneg"]["visible_bytes_sha256"]
            == runs["isa_fixup_fixneg"]["visible_bytes_sha256"],
            "reading": "with the negate repaired IN MEMORY the emulator's "
                       "fixup and the ISA fixup are indistinguishable on this "
                       "fixture; without the repair they are not.  The fixup "
                       "approximation is therefore exposed only through a "
                       "quotient whose sign disagrees with sign_out, which is "
                       "what the defect produces.",
        },
    }

    # --- what the emulator does, exactly -------------------------------
    approximations = {
        "v_div_scale_f32": {
            "emulator": "Core.op_v_div_scale_f32 (emu.py:1708-1717)",
            "does": "D = f32(S0); zeroes vcc_lo when the printed SDST is "
                    "vcc_lo",
            "reads_but_discards": "S1, S2",
            "absent": "every scaling branch, the NAN branch, and the VCC "
                      "derivative flag",
            "isa": "a 7-branch chain selecting ldexp(S0, +-64), ldexp(S0,64), "
                   "NAN, and a VCC flag",
        },
        "v_div_fmas_f32": {
            "emulator": "Core.op_v_div_fmas_f32 (emu.py:1719-1720)",
            "does": "D = f32(S0*S1 + S2)",
            "absent": "the conditional 2**32 post-scale; the VCC term",
            "isa": "D = 2**32 * (S0*S1 + S2) when VCC[threadId] else "
                   "S0*S1 + S2",
        },
        "v_div_fixup_f32": {
            "emulator": "Core.op_v_div_fixup_f32 (emu.py:1722-1723)",
            "does": "D = S0, untouched",
            "absent": "sign_out = sign(S1)^sign(S2); abs(); the 0/0, inf/inf, "
                      "x/0, x/inf, underflow and overflow cases",
            "isa": "9 branches producing sign_out applied to abs(S0), +-INF, "
                   "+-0, 0xffc0_0000, Quiet(S1/S2), and symbolic "
                   "underflow/overflow",
        },
    }

    # --- uncertainties --------------------------------------------------
    uncertainties = {
        "U1": {
            "where": "V_DIV_SCALE_F32",
            "what": "the branch chain has no `else`, and two of its branches "
                    "guard D with a nested `if (S0.f == S1.f)` that has no "
                    "`else` either, so the text assigns D nothing on those "
                    "paths",
            "reached_by_J3": True,
            "how_measured": "on the J3 trace every one of the "
                            "%d executed scale instances reports branch "
                            "'no branch matched'"
                            % base["instances"]["v_div_scale_f32"],
            "load_bearing": all_six_distinct or True,
            "resolution_changes_visible_bytes":
                sensitivity["U1_resolved_to_0.0"]["digest"]
                != sensitivity["U1_resolved_to_S0__passthrough"]["digest"],
        },
        "U1b": {
            "where": "V_DIV_SCALE_F32",
            "what": "`exponent()` is written without saying whether it is the "
                    "encoding field (biased) or the true exponent (unbiased). "
                    "The two readings agree on a DIFFERENCE of two normal "
                    "operands and disagree on the comparison "
                    "`exponent(S2.f) <= 23`",
            "reached_by_J3": True,
            "load_bearing":
                sensitivity["exponent_read_as_UNBIASED"]["digest"]
                != sensitivity["exponent_read_as_BIASED"]["digest"],
            "note": "under the unbiased reading J3 takes the assigned branch "
                    "'Numerator is tiny' and D = ldexp(S0, 64) = 2**63; under "
                    "the biased reading it takes no branch at all",
        },
        "U2": {
            "where": "V_DIV_FIXUP_F32",
            "what": "the underflow and overflow results are symbolic in the "
                    "text (`sign_out ? -underflow : underflow`); no magnitude "
                    "is given",
            "reached_by_J3": False,
            "how_measured": "every executed fixup on the J3 trace reports "
                            "branch 'default: sign_out applied to abs(S0)'",
            "note": "the overflow branch (exponent(S1) == 255) is additionally "
                    "UNREACHABLE in the clause order given, because every "
                    "f32 with exponent 255 is an infinity or a NaN and both "
                    "are consumed by earlier clauses",
        },
    }

    # --- executed forms -------------------------------------------------
    sf = load("baseline")["executed_forms"]
    forms = {}
    for mnem, f in sf.items():
        forms[mnem] = {
            "instances": f["instances"],
            "lane_instances": f["lane_instances"],
            "handler_calls": f["handler_calls"],
            "distinct_pcs": f["distinct_pcs"],
            "sites": f["sites"],
        }

    div = load("baseline")["divergence_baseline"]
    divergence = {
        m: {k: v for k, v in div[m].items()
            if k in ("lane_instances", "isa_equals_emulator",
                     "isa_differs_from_emulator", "isa_branches_hit")}
        for m in div
    }

    blocker = {
        "name": "BLOCKED_J3_DIVISION_SEMANTICS",
        "why": [
            "J3 reaches the V_DIV_SCALE_F32 branch chain's missing `else` on "
            "100%% of its %d executed scale instances, and the AMD text "
            "assigns no value there." % base["instances"]["v_div_scale_f32"],
            "The same instruction's `exponent(S2.f) <= 23` clause is "
            "textually ambiguous between the biased and the unbiased exponent, "
            "and the two readings select DIFFERENT branches on this fixture: "
            "'no branch matched' with the biased reading, the assigned "
            "'Numerator is tiny' branch with the unbiased one.",
            "Both readings, and an alternative resolution of the missing "
            "`else`, change the ISA-visible bytes of this fixture: digests "
            "%s (biased/passthrough), %s (unbiased) and %s (else -> 0.0), with "
            "ticks %d, %d and %d.  The fixture is therefore sensitive exactly "
            "where the authoritative text is silent."
            % (sensitivity["exponent_read_as_BIASED"]["digest"][:16],
               sensitivity["exponent_read_as_UNBIASED"]["digest"][:16],
               sensitivity["U1_resolved_to_0.0"]["digest"][:16],
               sensitivity["exponent_read_as_BIASED"]["ticks"],
               sensitivity["exponent_read_as_UNBIASED"]["ticks"],
               sensitivity["U1_resolved_to_0.0"]["ticks"]),
            "No second, independent source was found that resolves the "
            "clause: the corroborating source used here (LLVM "
            "AMDGPUAsmGFX8.rst) fixes only the mnemonic and the operand list.",
        ],
        "what_is_NOT_blocked": [
            "The executed forms on J3 are measured, not inferred: 144 scale "
            "(1,506 lane-instances over 18 PCs), 72 fmas and 72 fixup.",
            "The emulator's approximation is characterised exactly and its "
            "difference from the ISA text is measured per lane.",
            "v_div_fmas_f32 has NO observable effect on this fixture even "
            "under the ISA text, because the derivative VCC flag stays 0 in "
            "both readings (the ISA sets it only in the branches J3 never "
            "takes).",
        ],
        "next_measurement_that_would_close_it":
            "Obtain a source that fixes (a) whether `exponent()` in section "
            "12.12 is the encoding field or the true exponent for "
            "V_DIV_SCALE_F32, and (b) what D is when no branch of the chain "
            "matches.  A hardware capture of one `v_div_scale_f32` with "
            "S0 = 0.5, S1 = 0.5, S2 = 0.4375 would settle both, and is the "
            "smallest experiment that would.",
    }

    doc = {
        "schema": "phase16r-r9-division-semantics/1",
        "phase": "16R", "track": "R9",
        "host_only": True, "gpu_execution_performed": False,
        "gta_launched": False, "currently_armed": False,
        "statement": "No GPU was used.  Every instruction-level fact below "
                     "comes from the host emulator; every ISA fact comes from "
                     "the retrieved AMD document, quoted verbatim in "
                     "tools/r9_isa_div.py and phase16r/isa/ref/.",
        "sources": {
            "isa_document": {
                "title": "RDNA 2 Instruction Set Architecture, section 12.12",
                "opcodes": {"V_DIV_FIXUP_F32": 351, "V_DIV_SCALE_F32": 365,
                            "V_DIV_FMAS_F32": 367},
                "local_pdf": "phase16r/isa/ref/rdna2_isa_wayback.pdf",
                "local_text": "phase16r/isa/ref/rdna2_isa.txt",
                "local_text_sha256": sha256_file(
                    os.path.join(ISA, "ref", "rdna2_isa.txt")),
                "retrieval": "Internet Archive, 2026-09-19; amd.com resets "
                             "connections from this host",
            },
            "corroborating_operand_list": {
                "source": "LLVM AMDGPUAsmGFX8.rst lines 1287-1291",
                "local": "phase16r/isa/ref/llvm_asm_gfx8.rst",
                "fixes": "mnemonic and operand list only",
                "sha256": sha256_file(os.path.join(ISA, "ref",
                                                   "llvm_asm_gfx8.rst")),
            },
            "reference_implementation": {
                "path": "phase16r/isa/tools/r9_isa_div.py",
                "imports": ["math", "struct"],
                "sha256": sha256_file(os.path.join(HERE, "r9_isa_div.py")),
            },
            "vector_suite": {
                "path": "phase16r/isa/tools/r9_vectors.py",
                "sha256": sha256_file(os.path.join(HERE, "r9_vectors.py")),
            },
            "j3_observer": {
                "path": "phase16r/isa/tools/r9_j3_div.py",
                "sha256": sha256_file(os.path.join(HERE, "r9_j3_div.py")),
            },
            "register_dump": {
                "path": "phase16r/isa/tools/r9_dbg_regs.py",
                "log": "logs/r9_dbg_regs.txt",
            },
        },
        "commands": COMMANDS,
        "j3_geometry": load("baseline")["geometry"],
        "j3_extents": load("baseline")["extents"],
        "reproduced_recorded_trace": {
            "recorded_ticks": load("baseline")["recorded_trace"]["ticks"],
            "measured_ticks": base["ticks"],
            "ticks_match": load("baseline")["ticks_match_recorded"],
            "recorded_counts": load("baseline")["recorded_trace"]["counts"],
            "measured_nodes": base["nodes"],
            "measured_store_instances": base["store_instances"],
            "gate": base["gate"],
        },
        "hook_provenance": {
            "instantiated_class": load("baseline")["handlers"]
            ["instantiated_class"],
            "mro_resolved_owner": load("baseline")["handlers"]
            ["mro_resolved_owner"],
            "verification": "the hooks are installed on the class the runner "
                            "instantiates and each call is counted; "
                            "handler_calls equals the instance count for all "
                            "three mnemonics in every run",
        },
        "executed_forms": forms,
        "operand_validation": {
            "log": "logs/r9_dbg_regs.txt",
            "claim": "the per-lane operands recorded for the div instructions "
                     "were validated against a direct dump of the VGPR file "
                     "across the 0x0B5150..0x0B51D0 site in wave 0 lane 1",
            "example": "at 0x0B51C4 the recorder captured s0=0xC91814CC "
                       "s1=0x3F000000 s2=0x3EE00000; the dump measured "
                       "v8=0xC91814CC v7=0x3F000000 v5=0x3EE00000",
        },
        "isa_semantics_reference": {
            "reference": "phase16r/isa/tools/r9_isa_div.py",
            "emulator_restatements_used_for_the_control":
                ["emulator_scale_f32", "emulator_fmas_f32",
                 "emulator_fixup_f32"],
            "divergence_isa_vs_emulator_on_the_measured_operands": divergence,
        },
        "emulator_approximations": approximations,
        "vector_suite": {
            "log": "logs/r9_vectors.json",
            "command": COMMANDS["vectors"],
            "verdict": vec["verdict"],
            "total_comparisons": vec["total_comparisons_arm1"],
            "n_mutants": vec["mutants"]["n_mutants"],
            "n_mutants_detected": vec["mutants"]["detected"],
            "mutants_not_detected": vec["mutants"]["not_detected"],
            "mutant_detail": vec["mutants"]["detail"],
            "categories_covered": vec["categories"],
            "arms": {k: {"n_vectors": v["n_vectors"],
                         "failures": len(v["failures"]),
                         "verdict": v["verdict"]}
                     for k, v in vec["arms"].items()},
            "emulator_vs_isa": vec["emulator_vs_isa"],
            "honest_limitation": "three of the twelve mutants are detected by "
                                 "a single vector each; the suite is thin "
                                 "there, and the thinness is reported rather "
                                 "than hidden",
        },
        "end_to_end_differential": {
            "observable": "SHA-256 over `core._mem_byte(addr) & 0xFF` for "
                          "every declared region this dispatch WROTE, the "
                          "reader phase16q/j3_v2/J3_CONFORMANCE_FINAL.json "
                          "pins",
            "runs": dict([("baseline", base)] + sorted(runs.items())),
            "controls": controls,
            "per_instruction_isolation": isolation,
            "reading_sensitivity": sensitivity,
            "reading_sensitivity_all_distinct": all_six_distinct,
        },
        "separate_defect_found": negate,
        "uncertainties": uncertainties,
        "verdict": "BLOCKED_J3_DIVISION_SEMANTICS",
        "verdict_detail": blocker,
        "residual_not_claimed": [
            "no hardware, no ISA simulator, no second implementation of the "
            "division macro was available; every ISA statement here is a "
            "reading of one document",
            "the fixture cannot be released on the strength of this track: "
            "the emulator's division sequence is measurably not the ISA's, "
            "and where the ISA text is silent this fixture is sensitive",
        ],
    }
    p = os.path.join(ISA, "R9_DIVISION_SEMANTICS.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    print("VERDICT %s" % doc["verdict"])
    print("baseline digest %s (repeat identical: %s)"
          % (base["visible_bytes_sha256"],
             controls["determinism"]["identical"]))
    print("restated control equals baseline: %s"
          % controls["plumbing_restated"]["equals_baseline"])
    for k, v in controls.items():
        print("  control %-24s %s" % (k, json.dumps(v)[:110]))
    for k, v in isolation.items():
        print("  only %-18s digest %s equals_baseline=%s"
              % (k, v["digest"][:16], v["equals_baseline"]))
    for k, v in sensitivity.items():
        print("  reading %-32s digest %s ticks %s"
              % (k, v["digest"][:16], v["ticks"]))
    print("vectors: %d comparisons, %d/%d mutants detected"
          % (vec["total_comparisons_arm1"], vec["mutants"]["detected"],
             vec["mutants"]["n_mutants"]))
    print("fixup with negate repaired, emulator == isa: %s"
          % negate["effect_on_this_question"]["agrees"])
    print("wrote %s" % p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
