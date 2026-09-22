#!/usr/bin/env python3
"""Phase 16AM -- run every truth vector against the frozen emulator and the
repaired revision, and prove the vectors can reject a wrong handler.

WHAT THIS MEASURES

For each of the 20 scalar instructions whose SCC side effect Phase 16AM
repaired, `TRUTH_VECTORS_16AM.json` carries vectors whose expected
destination and expected SCC were computed from the ISA text (see
`p16am_build_truth_vectors.py`).  This runner executes every vector against
BOTH revisions and reports a per-vector PASS/FAIL for each.

THE NEGATIVE CONTROL -- WHY IT IS THE POINT OF THE WHOLE FILE

A conformance suite that has never rejected anything is not evidence.  So
this runner builds deliberately WRONG variants of the repaired handlers by
textual substitution of the repaired source, executes the same vectors
against them, and reports that they were rejected.  Three mutants:

  M1 scc_inverted_and      op_s_and_b32 sets SCC = (D == 0)
  M2 dst_dropped_or        op_s_or_b32 does not write the destination
  M3 saveexec_scc_old      _saveexec sets SCC from EXEC_old, not EXEC_new

Each substitution asserts that it CHANGED the source before the mutant is
used: a mutator that silently does not apply reports the inverse fault, and
this project has already lost a phase to exactly that.

A third, weaker check is also recorded because it needs no mutation at all:
the FROZEN revision is itself a wrong variant of every repaired handler
(it is the defect), so the vectors must reject it per instruction.

HOST ONLY.  No GPU, no HIP, no kernel launch, no system setting.  Reads only
phase16r/isa/ref/rdna2_isa.txt (as text, for the citation fingerprint),
phase16t/semantic/revision_16t/emu.py and p16am/semantic/revision_16am/
emu.py.  Writes only p16am/semantic/SEMANTIC_CONFORMANCE_16AM.json.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

FROZEN = os.path.join(ROOT, "phase16t", "semantic", "revision_16t", "emu.py")
REPAIRED = os.path.join(HERE, "revision_16am", "emu.py")
VECTORS = os.path.join(HERE, "TRUTH_VECTORS_16AM.json")
ISA = os.path.join(ROOT, "phase16r", "isa", "ref", "rdna2_isa.txt")
OUT = os.path.join(HERE, "SEMANTIC_CONFORMANCE_16AM.json")

U32 = 0xFFFFFFFF


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def load_module(name, path, source=None):
    """Load emu.py as a fresh, private module -- never via sys.modules, so
    the two revisions and every mutant are separate Core classes and no
    monkeypatch can land on a shadowed copy."""
    src = source if source is not None else open(path, encoding="utf-8").read()
    spec = importlib.util.spec_from_loader(name, loader=None)
    mod = importlib.util.module_from_spec(spec)
    mod.__file__ = path
    exec(compile(src, path, "exec"), mod.__dict__)
    return mod


# ------------------------------------------------------------------ the run
def run_vector(core, handler_name, v):
    """Execute one vector.  Returns (dst_ok, scc_ok, exec_ok, detail)."""
    try:
        core.scc = v["setup"]["scc"]
        core.exec_l = v["setup"]["exec"] & ((1 << core.lanes) - 1)
        for idx, val in v["setup"]["s"].items():
            core.s[int(idx)] = val & U32
        fn = getattr(core, handler_name)
    except Exception as e:                                   # noqa: BLE001
        return False, False, None, "setup: %s: %s" % (type(e).__name__, e)

    try:
        fn(None, list(v["operands"]))
    except Exception as e:                                   # noqa: BLE001
        return False, False, None, "execute: %s: %s" % (type(e).__name__, e)

    tok = v["expect"]["dst_token"]
    if tok.startswith("s[") or tok.startswith("s["):
        lo_tok = tok
        got = core.spair(lo_tok) if hasattr(core, "spair") else None
    else:
        got = core.s[int(tok[1:])]
    exp = v["expect"]["dst_value"]
    if v.get("expect_pair_hi") is not None:
        exp = exp | (v["expect_pair_hi"] << 32)
    dst_ok = (got == exp)

    scc_ok = (core.scc == v["expect"]["scc"])

    exec_ok = None
    if v["expect"].get("exec_after") is not None:
        exec_ok = (core.exec_l == v["expect"]["exec_after"])

    detail = "dst got=%s exp=%s | scc got=%s exp=%s" % (
        got, exp, core.scc, v["expect"]["scc"])
    if exec_ok is not None:
        detail += " | exec got=%s exp=%s" % (core.exec_l,
                                             v["expect"]["exec_after"])
    return dst_ok, scc_ok, exec_ok, detail


def run_all(mod, vectors, label):
    """Run every vector against `mod`.  A fresh Core per vector, so no
    handler can inherit state from the vector before it."""
    results = []
    for v in vectors:
        core = mod.Core([], lanes=32)
        dst_ok, scc_ok, exec_ok, detail = run_vector(
            core, v["handler"], v)
        ok = bool(dst_ok and scc_ok and (exec_ok is None or exec_ok))
        results.append({
            "id": v["id"], "instruction": v["instruction"],
            "case": v["case"], "pass": ok,
            "dst_ok": dst_ok, "scc_ok": scc_ok, "exec_ok": exec_ok,
            "detail": detail,
        })
    return results


def summarise(results):
    per = {}
    for r in results:
        s = per.setdefault(r["instruction"],
                           {"vectors": 0, "passed": 0, "failed": 0,
                            "scc_mismatch": 0, "dst_mismatch": 0})
        s["vectors"] += 1
        s["passed" if r["pass"] else "failed"] += 1
        if not r["scc_ok"]:
            s["scc_mismatch"] += 1
        if not r["dst_ok"]:
            s["dst_mismatch"] += 1
    return per


# ------------------------------------------------------- the negative controls
#: (mutant name, target instruction, old text, new text)
#: The old text must occur EXACTLY ONCE; the substitution is asserted.
MUTANTS = [
    ("M1_scc_inverted_and", "s_and_b32",
     "        d = (self.sget(ops[1]) & self.sget(ops[2])) & U32\n"
     "        self.sset(ops[0], d)\n"
     "        self._scc_of(d)\n",
     "        d = (self.sget(ops[1]) & self.sget(ops[2])) & U32\n"
     "        self.sset(ops[0], d)\n"
     "        self.scc = 1 if d == 0 else 0        # MUTANT M1: inverted\n"),
    ("M2_dst_dropped_or", "s_or_b32",
     "        d = (self.sget(ops[1]) | self.sget(ops[2])) & U32\n"
     "        self.sset(ops[0], d)\n"
     "        self._scc_of(d)\n",
     "        d = (self.sget(ops[1]) | self.sget(ops[2])) & U32\n"
     "        # MUTANT M2: destination write dropped\n"
     "        self._scc_of(d)\n"),
    ("M3_saveexec_scc_old", "s_and_saveexec_b32",
     "        new = newmask & ((1 << self.lanes) - 1)\n"
     "        self.exec_l = new\n"
     "        self.scc = 1 if new != 0 else 0\n",
     "        new = newmask & ((1 << self.lanes) - 1)\n"
     "        self.exec_l = new\n"
     "        self.scc = 1 if old != 0 else 0      # MUTANT M3: stale EXEC\n"),
]


def build_mutants(repaired_src):
    out = []
    for name, target, old, new in MUTANTS:
        n = repaired_src.count(old)
        if n != 1:
            raise SystemExit(
                "mutator %s matched %d sites, expected exactly 1 -- a mutator "
                "that does not apply reports the inverse fault" % (name, n))
        src = repaired_src.replace(old, new)
        if src == repaired_src:
            raise SystemExit("mutator %s was a silent no-op" % name)
        out.append({"name": name, "target": target, "source": src})
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    vdoc = json.load(open(VECTORS, encoding="utf-8"))
    vectors = vdoc["vectors"]
    repaired_src = open(REPAIRED, encoding="utf-8").read()

    frozen = load_module("emu_frozen_16am", FROZEN)
    repaired = load_module("emu_repaired_16am", REPAIRED)

    # --- coverage of the repair itself, independent of any vector ---------
    repaired_handlers = sorted({v["handler"] for v in vectors})
    live = {}
    for h in repaired_handlers:
        ffn = getattr(frozen.Core, h, None)
        rfn = getattr(repaired.Core, h, None)
        live[h] = {
            "frozen_has_handler": ffn is not None,
            "repaired_has_handler": rfn is not None,
            "body_changed_at_this_name": (
                ffn is not None and rfn is not None
                and (ffn.__code__.co_code != rfn.__code__.co_code)),
        }
    # the five saveexec handlers share `_saveexec`; that carrier must differ
    live["_saveexec"] = {
        "frozen_has_handler": hasattr(frozen.Core, "_saveexec"),
        "repaired_has_handler": hasattr(repaired.Core, "_saveexec"),
        "body_changed_at_this_name": (
            frozen.Core._saveexec.__code__.co_code
            != repaired.Core._saveexec.__code__.co_code),
    }

    # --- the two real results --------------------------------------------
    fro = run_all(frozen, vectors, "frozen")
    rep = run_all(repaired, vectors, "repaired")
    fro_per, rep_per = summarise(fro), summarise(rep)

    # --- instructions the ISA names as SCC writers with no handler --------
    not_implemented = {}
    for m in ("op_s_sub_u32", "op_s_subb_u32", "op_s_min_u32", "op_s_max_i32",
              "op_s_max_u32", "op_s_nand_b32", "op_s_nor_b32",
              "op_s_xnor_b32", "op_s_orn2_b32", "op_s_lshr_b64",
              "op_s_ashr_i64", "op_s_bfm_b32", "op_s_not_b32",
              "op_s_andn1_b32", "op_s_orn1_b32", "op_s_andn2_wrexec_b32"):
        not_implemented[m] = {
            "frozen": hasattr(frozen.Core, m),
            "repaired": hasattr(repaired.Core, m),
        }

    # --- the negative controls -------------------------------------------
    neg = []
    for mut in build_mutants(repaired_src):
        mod = load_module("emu_mutant_%s" % mut["name"],
                          REPAIRED, source=mut["source"])
        # prove the mutant is live by behaviour, not by reading the source
        probe = mod.Core([], lanes=32)
        probe.scc = 1
        probe.s[11] = 0x00000000
        probe.s[12] = 0x00000000
        probe.op_s_and_b32(None, ["s10", "s11", "s12"])
        behaved = (probe.scc == 1 and probe.s[10] == 0)
        res = run_all(mod, vectors, mut["name"])
        per = summarise(res)
        failed_targets = sorted({r["instruction"] for r in res
                                 if not r["pass"]})
        rejected = any(not r["pass"] for r in res)
        neg.append({
            "mutant": mut["name"],
            "target_instruction": mut["target"],
            "substitution_applied": True,
            "source_changed": True,
            "vectors_run": len(res),
            "vectors_failed": sum(1 for r in res if not r["pass"]),
            "instructions_rejected": failed_targets,
            "target_was_rejected": mut["target"] in failed_targets,
            "rejected": rejected,
            "per_instruction": per,
            "behavioural_probe": {
                "probe": "op_s_and_b32 s10, s11(=0), s12(=0) with scc preset 1",
                "mutant_is_live_by_behaviour": bool(behaved),
                "note": "M1 is the only mutant whose probe changes SCC here; "
                        "M2/M3 are covered by their own vector failures",
            },
        })

    # --- verdicts ---------------------------------------------------------
    repaired_all_pass = all(r["pass"] for r in rep)
    # Behavioural, not textual: an instruction is "repaired" only if the
    # frozen revision FAILS at least one of its vectors.  A bytecode compare
    # would be the wrong test -- five saveexec handlers and the ANDN2 alias
    # are repaired through a changed callee, so their own bodies are
    # legitimately identical.  The bytecode fact is reported as information.
    repaired_instructions = sorted(i for i in rep_per if i != "s_addc_u32")
    frozen_rejected_every_repaired_instr = all(
        fro_per[i]["failed"] > 0 for i in repaired_instructions)
    per_instruction_repair_evidence = {
        i: {"frozen_failed": fro_per[i]["failed"],
            "frozen_passed": fro_per[i]["passed"],
            "repaired_failed": rep_per[i]["failed"],
            "own_body_changed": live.get("op_" + i, {}).get(
                "body_changed_at_this_name"),
            "criterion": "repaired iff frozen_failed > 0",
            "repaired": fro_per[i]["failed"] > 0}
        for i in repaired_instructions}
    # positive control: the ISA-conformant instruction that was NOT repaired
    # must be accepted by the frozen revision too -- a checker that rejects
    # the known-good case is broken, not strict.
    addc_accepted_by_both = (fro_per["s_addc_u32"]["failed"] == 0
                             and rep_per["s_addc_u32"]["failed"] == 0)
    controls_rejected = all(n["rejected"] for n in neg)
    controls_hit_target = all(n["target_was_rejected"] for n in neg)

    # SCOPE OF THE REPAIR, MEASURED.  The claim "this repair adds SCC and
    # changes nothing else" is checkable: the frozen revision must already
    # agree with the expected destination on every vector, and with the
    # expected EXEC on every saveexec vector.  If it did not, the repair
    # would have changed an architectural result and not just a flag.
    frozen_only_scc_differs = all(r["dst_ok"] for r in fro)
    frozen_exec_already_right = all(r["exec_ok"] is not False for r in fro)
    frozen_dst_mismatches = sum(1 for r in fro if not r["dst_ok"])
    frozen_exec_mismatches = sum(1 for r in fro if r["exec_ok"] is False)

    checks = {
        "every_vector_passes_on_the_repaired_revision": repaired_all_pass,
        "the_frozen_revision_is_rejected_for_every_repaired_instruction":
            frozen_rejected_every_repaired_instr,
        "the_unrepaired_instruction_is_accepted_by_both_revisions":
            addc_accepted_by_both,
        "every_negative_control_was_rejected": controls_rejected,
        "every_negative_control_rejected_its_target_instruction":
            controls_hit_target,
        "vectors_cannot_pass_a_handler_that_omits_the_scc_write":
            all(v["setup"]["scc"] != v["scc_expected"] for v in vectors
                if v["instruction"] != "s_addc_u32"),
        "the_shared_saveexec_carrier_body_differs":
            live["_saveexec"]["body_changed_at_this_name"],
        "the_repair_changed_only_scc_not_the_destination":
            frozen_only_scc_differs,
        "the_repair_changed_only_scc_not_the_saveexec_exec_value":
            frozen_exec_already_right,
    }

    doc = {
        "schema": "p16am-semantic-conformance/1",
        "phase": "16AM",
        "host_only": True,
        "gpu_execution_performed": False,
        "hip_calls_made": 0,
        "physical_launches_by_this_tool": 0,
        "question": "for every scalar instruction whose SCC side effect was "
                    "repaired, do independent ISA-derived truth vectors accept "
                    "the repaired revision, reject the frozen revision, and "
                    "reject deliberately wrong variants?",
        "commands_run": [
            "python p16am/semantic/p16am_build_truth_vectors.py",
            "python p16am/semantic/p16am_semantic_conformance.py",
            "sha256sum phase16t/semantic/revision_16t/emu.py "
            "p16am/semantic/revision_16am/emu.py",
        ],
        "artefacts": {
            "frozen_emu": {"path": "phase16t/semantic/revision_16t/emu.py",
                           "sha256": sha256_file(FROZEN),
                           "bytes": os.path.getsize(FROZEN)},
            "repaired_emu": {"path": "p16am/semantic/revision_16am/emu.py",
                             "sha256": sha256_file(REPAIRED),
                             "bytes": os.path.getsize(REPAIRED)},
            "isa_text": {"path": "phase16r/isa/ref/rdna2_isa.txt",
                         "sha256": sha256_file(ISA)},
            "vectors": {"path": "p16am/semantic/TRUTH_VECTORS_16AM.json",
                        "sha256": sha256_file(VECTORS),
                        "vector_count": len(vectors)},
        },
        "vector_count": len(vectors),
        "vector_count_per_instruction": vdoc["vector_count_per_instruction"],
        "frozen_verdict_per_instruction": fro_per,
        "repaired_verdict_per_instruction": rep_per,
        "frozen_totals": {
            "vectors": len(fro),
            "passed": sum(1 for r in fro if r["pass"]),
            "failed": sum(1 for r in fro if not r["pass"]),
            "destination_mismatches": frozen_dst_mismatches,
            "exec_value_mismatches": frozen_exec_mismatches,
            "scc_only_mismatches": sum(
                1 for r in fro if r["dst_ok"] and not r["scc_ok"]
                and r["exec_ok"] is not False),
            "interpretation": "the frozen revision already produces the "
                              "correct destination and the correct saveexec "
                              "EXEC on every vector; what it omits is the SCC "
                              "write, so the repair is a flag repair and not "
                              "an architectural-result change",
        },
        "repaired_totals": {
            "vectors": len(rep),
            "passed": sum(1 for r in rep if r["pass"]),
            "failed": sum(1 for r in rep if not r["pass"]),
        },
        "repaired_failures": [r for r in rep if not r["pass"]],
        "frozen_failure_examples": [r for r in fro if not r["pass"]][:20],
        "handler_coverage": live,
        "per_instruction_repair_evidence": per_instruction_repair_evidence,
        "transitive_repair_note": {
            "carriers_changed": ["_saveexec", "_scc_of (new)"],
            "handlers_repaired_through_a_changed_callee": [
                "op_s_andn2_b32 (calls op_s_and_not1_b32)",
                "op_s_and_saveexec_b32 (calls _saveexec)",
                "op_s_andn2_saveexec_b32 (calls _saveexec)",
                "op_s_or_saveexec_b32 (calls _saveexec)",
                "op_s_xor_saveexec_b32 (calls _saveexec)",
                "op_s_and_not1_saveexec_b32 (calls _saveexec)",
            ],
            "why_this_is_measured_not_assumed": "each of those six is listed "
                "in per_instruction_repair_evidence with frozen_failed > 0, "
                "so the repair is proven by behaviour and not by reading "
                "the source",
        },
        "scc_writers_with_no_handler": not_implemented,
        "negative_controls": neg,
        "negative_control_summary": {
            "mutants": len(neg),
            "all_rejected": controls_rejected,
            "all_rejected_their_target": controls_hit_target,
        },
        "checks": checks,
        "verdict": "PASS" if all(checks.values())
                   else "FAIL: " + ",".join(k for k, v in checks.items()
                                            if not v),
        "interpretation": {
            "scope": "this establishes that the repaired revision implements "
                     "the SCC side effect of these 20 scalar instructions as "
                     "the local ISA text prescribes, and that the frozen "
                     "revision did not.  It says nothing about SCC consumers, "
                     "about the physical kernel, or about instructions this "
                     "emulator does not implement at all.",
        },
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")

    print(json.dumps({
        "verdict": doc["verdict"],
        "vector_count": len(vectors),
        "repaired_passed": doc["repaired_totals"]["passed"],
        "repaired_failed": doc["repaired_totals"]["failed"],
        "frozen_passed": doc["frozen_totals"]["passed"],
        "frozen_failed": doc["frozen_totals"]["failed"],
        "negative_controls": [{"mutant": n["mutant"],
                               "vectors_failed": n["vectors_failed"],
                               "target_rejected": n["target_was_rejected"]}
                              for n in neg],
        "checks": checks,
        "out": args.out,
    }, indent=1))
    return 0 if doc["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
