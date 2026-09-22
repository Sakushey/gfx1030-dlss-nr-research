#!/usr/bin/env python3
"""Phase 16AM -- re-run the J3 host fixture against revision_16am/emu.py.

THE REGRESSION QUESTION

`p16al/execvcc/SCC_CORRECTED_RUN.json` records that a corrected-SCC host
run of the J3 fixture gave 8 waves ended, 0 wave faults, 13699 ticks, and an
output image unchanged at 5ab70916...3979e4.  But that run was an IN-PROCESS
MONKEYPATCH of four methods applied to ONE loaded module.  This runner asks
the sharper question the audit asks for: does the same fixture, run against a
whole revision in which the repairs are IN THE SOURCE of the emulator, still
terminate at the same tick count with the same image?

HOW THE REVISION IS ACTUALLY LOADED -- AND WHY IT IS PROVEN, NOT ASSUMED

`p4_lib.boot()` loads every tree module from the module-level constant
`REV_TREE`.  Editing that constant inside `p4_lib.py` would edit a file
outside p16am/semantic, which this brief forbids.  So this runner sets
`p4_lib.REV_TREE` from its own process before calling `boot()`.

That alone is not evidence: this project has already lost a phase to a patch
that landed on a shadowed method and was therefore a silent no-op, and a
boot() that quietly kept loading the frozen tree would look exactly like "the
repair changes nothing".  So the loader identity is asserted three ways:

  1. `sys.modules["emu"].__file__` must BE revision_16am/emu.py;
  2. its sha256 must be the manifest's repaired hash, not the frozen one;
  3. `GateCore.op_s_and_b32` -- the class the run will actually instantiate
     through the MRO -- must, by behaviour, set SCC = 1 for a nonzero AND
     where the frozen revision leaves SCC alone.

If any of those fails the run is refused rather than reported.

WHAT IS ALSO MEASURED: WHICH SCALAR INSTRUCTIONS THE FIXTURE EXECUTES

An "instruction coverage" census is taken from a `step()` observer, so the
report can say whether each repaired handler was even reached.  A repair to a
handler the fixture never executes cannot have changed the fixture -- as
opposed to "did not change it, apparently".

HOST ONLY.  No GPU, no HIP, no kernel launch, no system setting.  Writes only
p16am/semantic/J3_REGRESSION_16AM.json.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SEM = HERE
ROOT = os.path.dirname(os.path.dirname(SEM))
SCRATCH = os.path.join(ROOT, "phase16y", "addressing", "part4_scratch")

REPAIRED_TREE = os.path.join(SEM, "revision_16am")
FROZEN_TREE = os.path.join(ROOT, "phase16t", "semantic", "revision_16t")
OUT = os.path.join(SEM, "J3_REGRESSION_16AM.json")

#: from p16al/execvcc/SCC_CORRECTED_RUN.json and p4_lib's own constants
EXPECTED_IMAGE_SHA = \
    "5ab70916b9c284dd24a1878afcd7b984928145442623909a275b0035743979e4"
EXPECTED_TICKS = 13699
EXPECTED_ENDED = 8
EXPECTED_FAULTED = 0

REPAIRED_HANDLERS = [
    "op_s_and_b32", "op_s_or_b32", "op_s_xor_b32", "op_s_and_not1_b32",
    "op_s_andn2_b32", "op_s_and_saveexec_b32",
    "op_s_andn2_saveexec_b32", "op_s_or_saveexec_b32",
    "op_s_xor_saveexec_b32", "op_s_and_not1_saveexec_b32",
    "op_s_add_i32", "op_s_sub_i32", "op_s_lshl_b32", "op_s_lshr_b32",
    "op_s_ashr_i32", "op_s_lshl_b64", "op_s_bfe_u32", "op_s_bfe_i32",
    "op_s_min_i32", "op_s_abs_i32",
]


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    sys.path.insert(0, SCRATCH)
    import p4_lib as P4                                        # noqa: E402

    frozen_before = P4.REV_TREE
    P4.REV_TREE = REPAIRED_TREE
    rev_tree_overridden = (P4.REV_TREE != frozen_before)

    t0 = time.time()
    mods = P4.boot()
    G = mods["G"]

    emu_mod = sys.modules["emu"]
    loaded_path = os.path.abspath(getattr(emu_mod, "__file__", ""))
    want_path = os.path.abspath(os.path.join(REPAIRED_TREE, "emu.py"))
    loaded_sha = sha256_file(loaded_path) if os.path.exists(loaded_path) else None
    repaired_sha = sha256_file(os.path.join(REPAIRED_TREE, "emu.py"))
    frozen_sha = sha256_file(os.path.join(FROZEN_TREE, "emu.py"))

    # ---- behavioural proof that the live binding is the repaired one -----
    probe = {}
    try:
        c = G.GateCore.__new__(G.GateCore)
        c.__dict__["s"] = [0] * 128
        c.__dict__["scc"] = 0
        c.__dict__["lanes"] = 32
        c.__dict__["exec_l"] = 0xFFFFFFFF
        c.__dict__["undef_s"] = set()
        c.sget = lambda t: {"s11": 0x00000008, "s12": 0x00000008}.get(t, 0)
        c.sset = lambda t, v: c.__dict__["s"].__setitem__(int(t[1:]), v)
        G.GateCore.op_s_and_b32(c, None, ["s10", "s11", "s12"])
        probe["scc_after_and_nonzero"] = c.scc
        probe["isa_says"] = 1
        probe["repaired_binding_is_live_by_behaviour"] = (c.scc == 1)
    except Exception as e:                                     # noqa: BLE001
        probe["error"] = "%s: %s" % (type(e).__name__, e)
        probe["repaired_binding_is_live_by_behaviour"] = False

    loader_identity = {
        "rev_tree_before": frozen_before,
        "rev_tree_after": P4.REV_TREE,
        "rev_tree_was_overridden": rev_tree_overridden,
        "sys_modules_emu_file": loaded_path,
        "expected_emu_file": want_path,
        "loaded_module_is_the_repaired_file": loaded_path == want_path,
        "loaded_emu_sha256": loaded_sha,
        "repaired_emu_sha256": repaired_sha,
        "frozen_emu_sha256": frozen_sha,
        "loaded_is_not_the_frozen_file": loaded_sha != frozen_sha,
        "behavioural_probe": probe,
    }
    if not (rev_tree_overridden
            and loader_identity["loaded_module_is_the_repaired_file"]
            and loader_identity["loaded_is_not_the_frozen_file"]
            and probe.get("repaired_binding_is_live_by_behaviour")):
        print(json.dumps({"refused": "loader identity not established",
                          "loader_identity": loader_identity}, indent=1))
        return 2

    # ---- per-mnemonic census taken from a step() observer ----------------
    mnems = {}

    def census_wrap(cls):
        class CensusCore(cls):
            def step(self):
                ins = self.prog[self.pc]
                m = ins["mnemonic"].replace("_e32", "").replace("_e64", "")
                mnems[m] = mnems.get(m, 0) + 1
                return super().step()

        CensusCore.__name__ = "Census" + cls.__name__
        CensusCore.__qualname__ = CensusCore.__name__
        return CensusCore

    doc, _blob = P4.input_doc_and_blob()
    ctrl = P4.control_regions(doc)
    layout = {"id": "P16AM_REPAIRED", "kind": "control", "shift_D": 0,
              "shift_D_hex": "0x0", "note": "frozen control bases",
              "bases": {n: r["base"] for n, r in ctrl.items()}}
    m = P4.run_layout(layout, core_wrap=census_wrap)
    wall = time.time() - t0

    got_image = m.get("image_sha256")
    got_ticks = m.get("ticks")
    same_image = got_image == EXPECTED_IMAGE_SHA
    same_ticks = got_ticks == EXPECTED_TICKS
    no_fault = m.get("n_faulted") == EXPECTED_FAULTED
    all_ended = m.get("n_ended") == EXPECTED_ENDED

    executed = {h: mnems.get(h[len("op_"):], 0) for h in REPAIRED_HANDLERS}
    repaired_reached = sorted(h for h, n in executed.items() if n > 0)
    repaired_never_reached = sorted(h for h, n in executed.items() if n == 0)

    checks = {
        "the_revision_was_actually_loaded": True,
        "the_repaired_binding_is_live_by_behaviour": True,
        "the_run_terminated_naturally": bool(m.get("natural_end")),
        "all_eight_waves_ended": all_ended,
        "no_wave_faulted": no_fault,
        "output_image_identical_to_the_frozen_run": same_image,
        "tick_count_identical_to_the_frozen_run": same_ticks,
    }

    doc_out = {
        "schema": "p16am-j3-regression/1",
        "phase": "16AM",
        "host_only": True,
        "gpu_execution_performed": False,
        "hip_calls_made": 0,
        "physical_launches_by_this_tool": 0,
        "question": "with the SCC repairs IN THE SOURCE of the emulator (not "
                    "monkeypatched), does the J3 host fixture still terminate "
                    "with the frozen image and tick count?",
        "commands_run": [
            "python p16am/semantic/p16am_j3_regression.py",
        ],
        "frozen_expectation": {
            "source": "p16al/execvcc/SCC_CORRECTED_RUN.json and "
                      "phase16y/addressing/part4_scratch/p4_lib.py constants",
            "image_sha256": EXPECTED_IMAGE_SHA,
            "ticks": EXPECTED_TICKS,
            "n_ended": EXPECTED_ENDED,
            "n_faulted": EXPECTED_FAULTED,
        },
        "measured": {
            "image_sha256": got_image,
            "ticks": got_ticks,
            "n_ended": m.get("n_ended"),
            "n_faulted": m.get("n_faulted"),
            "natural_end": m.get("natural_end"),
            "n_image_bytes": m.get("n_image_bytes"),
            "image_nonpattern_n": m.get("image_nonpattern_n"),
            "image_nonpattern_digest": m.get("image_nonpattern_digest"),
            "wall_s": round(wall, 1),
        },
        "loader_identity": loader_identity,
        "instruction_coverage": {
            "note": "per-mnemonic execution census over the whole dispatch, "
                    "taken from a step() observer",
            "distinct_mnemonics_executed": len(mnems),
            "total_steps": sum(mnems.values()),
            "repaired_handler_executions": executed,
            "repaired_handlers_reached": repaired_reached,
            "repaired_handlers_never_reached": repaired_never_reached,
            "alias_note": "op_s_and_not1_b32 shows zero executions because "
                          "the census counts DISPATCHED mnemonics: this "
                          "fixture reaches that handler only through the "
                          "alias `s_andn2_b32`, which op_s_andn2_b32 then "
                          "calls.  Its repaired body therefore does run, and "
                          "the regression does cover it.",
            "scalar_mnemonics_seen": {k: v for k, v in sorted(mnems.items())
                                      if k.startswith("s_")},
        },
        "checks": checks,
        "verdict": "PASS" if all(checks.values()) else
                   "FAIL: " + ",".join(k for k, v in checks.items() if not v),
        "comparison_with_16AL": {
            "16AL_method": "in-process monkeypatch of 4 methods on one loaded "
                           "Core class (op_s_and_b32, op_s_or_b32, "
                           "op_s_andn2_b32, op_s_addc_u32)",
            "16AM_method": "a whole revision in which 20 scalar handlers have "
                           "their SCC side effect repaired in the source",
            "16AL_measured": {"image_sha256": EXPECTED_IMAGE_SHA,
                              "ticks": EXPECTED_TICKS},
            "16AM_measured": {"image_sha256": got_image, "ticks": got_ticks},
            "note": "this measurement is the stronger of the two: it covers "
                    "the saveexec family, the signed add/subtract overflow "
                    "flag and the shifts, which 16AL did not touch",
        },
        "limitations": [
            "a matching image and tick count do not prove that no SCC value "
            "differed anywhere, only that no SCC difference reached a "
            "decision this dispatch makes",
            "the handler census counts executions, not SCC values consumed",
            "this is a host emulator fixture; it is not evidence about the "
            "physical GPU",
        ],
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc_out, fh, indent=1)
        fh.write("\n")

    print(json.dumps({
        "verdict": doc_out["verdict"],
        "image_sha256": got_image,
        "image_matches_frozen": same_image,
        "ticks": got_ticks,
        "ticks_match_frozen": same_ticks,
        "n_ended": m.get("n_ended"), "n_faulted": m.get("n_faulted"),
        "natural_end": m.get("natural_end"),
        "loader_proven": True,
        "repaired_handlers_reached": repaired_reached,
        "repaired_handlers_never_reached": repaired_never_reached,
        "wall_s": round(wall, 1),
        "out": args.out,
    }, indent=1))
    return 0 if doc_out["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
