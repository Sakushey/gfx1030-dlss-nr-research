#!/usr/bin/env python3
"""Phase 16L-L3 -- run the scalar / address vectors through BOTH the emulator and
the independent scalar oracle.

Same discipline as `verify_against_oracle.py`: the expected value comes from an
oracle that imports no emulator code, the emulator is loaded BY FILE PATH with
its identity asserted, and every disagreement is reported with the lane or
field that differs.

The address-formation vectors are evaluated by the ORACLE only, and their
expected values are hand-checked against the architectural rule stated in
`isa_oracle_scalar.py`.  They cannot be run "through the emulator" as a single
instruction because address formation is distributed across the handlers, so
they are recorded as oracle-side reference values and cited where the handlers
are read in `ISA_CONFORMANCE_MATRIX.md`.

usage:
    python verify_scalar_against_oracle.py --label post_fix
    python verify_scalar_against_oracle.py --label pre_fix \
        --emu ../frozen_16k/emulator_base__emu.py

Host-only.  No GPU.
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
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "phase8_static", "tools"))

import isa_oracle_scalar as OS                          # noqa: E402

EMU_PATH = os.path.join(ROOT, "phase8_static", "tools", "emu.py")
_ap = argparse.ArgumentParser(add_help=False)
_ap.add_argument("--emu", default=None)
_known, _ = _ap.parse_known_args()
if _known.emu:
    EMU_PATH = os.path.abspath(_known.emu)

sys.modules.pop("emu", None)
for _m in [k for k in sys.modules if k.startswith("emu.")]:
    sys.modules.pop(_m, None)
if os.path.basename(EMU_PATH) != "emu.py":
    _spec = importlib.util.spec_from_file_location("emu", EMU_PATH)
    E = importlib.util.module_from_spec(_spec)
    sys.modules["emu"] = E
    _spec.loader.exec_module(E)
else:
    import emu as E                                     # noqa: E402
assert os.path.abspath(E.__file__) == EMU_PATH, E.__file__

# WHICH IMPLEMENTATION OF A HANDLER IS "THE" IMPLEMENTATION?
#
# The gates dispatch through `p16j_execcache.BothCore`, whose MRO is
#     Both, ScrtISACore, ScrtGateCore, DescLdsCore, GateCore, E16Core, HWCore,
#     WG_SwinCore, SwinCore, RecCore, Core8, Core, ...
# so for any given opcode the method that RUNS is the first one that MRO finds.
# For `s_bfe_u32` that is `Core8`'s, not `emu.Core`'s -- `Core8` handles the
# real packed-immediate form (`s_bfe_u32 s17, s14, 0x10007`) while `emu.Core`'s
# version expects three separate operands and raises IndexError on it.
#
# `BothCore` itself cannot be instantiated outside its driver (it needs a
# program reference and a reset boundary set), and that machinery is not what
# this file is testing.  So the driver builds a bare `Core` and then **binds
# the production implementation of each handler under test onto it**, resolved
# through the real MRO.  The artifact records, per vector, which class the
# executed method came from -- so a reader can see it was not testing a
# different function from the one that runs.
sys.path.insert(0, os.path.join(ROOT, "phase16j_pre_gta", "tools"))
sys.path.insert(0, os.path.join(ROOT, "phase16i_closure", "tools"))
sys.path.insert(0, os.path.join(ROOT, "phase16h_pcrel_fix", "tools"))
sys.path.insert(0, os.path.join(ROOT, "phase16e_candidate_e", "tools"))
sys.path.insert(0, os.path.join(ROOT, "phase14e_static", "tools"))
sys.path.insert(0, os.path.join(ROOT, "phase14eh_tools"))
sys.path.insert(0, os.path.join(ROOT, "phase14e_forensics", "tools"))
sys.path.insert(0, os.path.join(ROOT, "phase14d11_static"))
sys.path.insert(0, os.path.join(ROOT, "phase14d_static", "tools"))
sys.path.insert(0, os.path.join(ROOT, "phase14d8_static", "tools"))
import p16j_execcache as _EC                            # noqa: E402
CORE_CLASS = _EC.BothCore
CORE_CLASS_NAME = "BothCore"
def _prod_handler_class(name):
    """The class in the production MRO whose `name` would run.

    `RecCore` overrides `step` only to call a *recorder* before delegating, and
    the recorder needs a program reference and a workgroup context this driver
    does not build.  It is skipped so the executed dispatch is `Core.step`,
    which is what `RecCore.step` delegates to anyway; skipping it removes a
    harness dependency without changing the semantics under test.
    """
    for k in CORE_CLASS.__mro__:
        if name == "step" and k.__name__ == "RecCore":
            continue
        if name in k.__dict__:
            return k
    return None


def emu_hash():
    h = hashlib.sha256()
    with open(EMU_PATH, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


SCALAR_FAMILIES = ("scmp", "sbit", "salu", "slogic", "sshift", "sbfe", "sexec",
                   "ssel")


def build_core(vec):
    """A `Core` holding ONE scalar instruction and the vector's entry state."""
    ops = vec["operands"]
    prog = [{"mnemonic": vec["mnem"] + "_e32" if _is_e32(vec["mnem"])
             else vec["mnem"],
             "operands": ", ".join(ops),
             "address": 0x1000,
             "text": vec["mnem"] + " " + ", ".join(ops),
             "target": None}]
    core = E.Core(prog, lanes=32)
    # bind the handler the production MRO would select, so bare-Core quirks
    # cannot masquerade as defects
    name = "op_" + vec["mnem"] if not vec["mnem"].startswith(
        ("s_", "ds_", "global_", "scratch_", "buffer_"))         else "op_" + vec["mnem"]
    core._prog_ref = prog
    # The handler's own private helpers must come from the same class, or the
    # bound method fails with AttributeError on a name the production chain
    # defines (`Core8._cmp2`, `E16Core._salu_reg`).  Copying the helpers is not
    # "testing a different function": the function under test is bound from the
    # production class, and its helpers are the ones it would call there.
    src_cls0 = _prod_handler_class(name)
    if src_cls0 is not None:
        for hname, hval in src_cls0.__dict__.items():
            if hname.startswith("_") and not hname.startswith("__")                     and callable(hval) and not hasattr(core, hname):
                try:
                    setattr(core, hname, hval.__get__(core, type(core)))
                except Exception:                            # noqa: BLE001
                    pass
    src_cls = _prod_handler_class(name)
    if src_cls is not None and src_cls is not E.Core:
        setattr(core, name, src_cls.__dict__[name].__get__(core, type(core)))
        core._handler_from = src_cls.__name__
    else:
        core._handler_from = "emu.Core"
    for i in range(128):
        core.s[i] = 0xDEADBEEF
    for k, v in vec["setup"].items():
        if k == "exec":
            core.exec_l = v & ((1 << 32) - 1)
        elif k == "scc":
            core.scc = v & 1
        elif k.startswith("s") and k[1:].isdigit():
            core.s[int(k[1:])] = v & 0xFFFFFFFF
    return core


_E32 = {"s_cmp_eq_u32", "s_cmp_lg_u32", "s_cmp_lt_u32", "s_cmp_le_u32",
        "s_cmp_gt_u32", "s_cmp_ge_u32", "s_cmp_lt_i32", "s_cmp_le_i32",
        "s_cmp_gt_i32", "s_cmp_ge_i32", "s_cmp_eq_i32", "s_cmp_lg_i32",
        "s_bitcmp0_b32", "s_bitcmp1_b32", "s_add_u32", "s_add_i32",
        "s_addc_u32", "s_sub_u32", "s_sub_i32", "s_subb_u32", "s_mul_i32",
        "s_mul_hi_u32", "s_mul_hi_i32", "s_abs_i32", "s_sext_i32_i8",
        "s_sext_i32_i16", "s_min_i32", "s_max_i32", "s_min_u32", "s_max_u32",
        "s_and_b32", "s_or_b32", "s_xor_b32", "s_not_b32", "s_andn2_b32",
        "s_orn2_b32", "s_nand_b32", "s_nor_b32", "s_xnor_b32", "s_lshl_b32",
        "s_lshr_b32", "s_ashr_i32", "s_bfe_u32", "s_bfe_i32", "s_cselect_b32",
        "s_mov_b32"}


def _is_e32(m):
    return m in _E32


def run_emulator(vec):
    """Execute the vector's instruction on the emulator and read back the
    architectural destinations.

    TWO OPERAND-CONVENTION DETAILS THIS MUST GET RIGHT, learned by getting them
    wrong first (the first draft reported every scalar vector as "raised"):

      * `Core.sget` reads the destination token too, so a printed IMMEDIATE in
        an operand of a `s_vop3`-shaped scalar instruction hits `int("0x1F")`
        and raises.  The emulator's own handlers slice their operands, so the
        driver must do the same rather than assuming ops[0] is always a
        register.
      * `s_cselect_b32` and `s_bfe_*` take their sources at indices 1..n and
        write ops[0]; the compare forms write SCC and may write ops[0] as well.
    """
    core = build_core(vec)
    ins = core.prog[0]
    dst = vec["operands"][0]
    before = {"scc": core.scc, "exec": core.exec_l}
    try:
        core.step()
        err = None
    except Exception as exc:                                # noqa: BLE001
        err = "%s: %s" % (type(exc).__name__, exc)
    out = {"error": err, "scc": core.scc, "exec": core.exec_l,
           "scc_before": before["scc"], "dst": dst, "value": None,
           "handler_from": getattr(core, "_handler_from", "emu.Core")}
    if dst == "scc":
        out["value"] = core.scc
    elif dst == "exec_lo":
        out["value"] = core.exec_l
    elif dst.startswith("s") and dst[1:].isdigit():
        out["value"] = core.s[int(dst[1:])]
    return out


def run_oracle(vec):
    try:
        r = OS.eval_scalar(vec)
    except Exception as exc:                                # noqa: BLE001
        return {"error": "%s: %s" % (type(exc).__name__, exc), "scc": None,
                "exec": None, "dst": vec["operands"][0], "value": None}
    setup = vec["setup"]
    exec_after = r.get("exec", setup.get("exec", 0xFFFFFFFF))
    # The scalar forms write their result to ops[0] AND, for the compare and
    # bit-test families, to SCC.
    dst = vec["operands"][0]
    value = r.get("value")
    return {"error": None, "scc": r.get("scc", setup.get("scc", 0)),
            "exec": exec_after, "dst": dst, "value": value}


def compare(vec, emu_r, or_r):
    diffs = []
    if emu_r["error"] != or_r["error"]:
        diffs.append({"field": "error", "oracle": or_r["error"],
                      "emulator": emu_r["error"]})
    if or_r.get("scc") is not None and emu_r.get("scc") != or_r.get("scc"):
        diffs.append({"field": "scc", "oracle": or_r["scc"],
                      "emulator": emu_r.get("scc")})
    if or_r.get("exec") is not None and emu_r.get("exec") != or_r.get("exec"):
        diffs.append({"field": "exec", "oracle": or_r["exec"],
                      "emulator": emu_r.get("exec")})
    if or_r.get("value") is not None:
        if emu_r.get("value") != or_r.get("value"):
            diffs.append({"field": "dst(%s)" % or_r.get("dst"),
                          "oracle": "0x%08X" % (or_r.get("value") or 0),
                          "emulator": "0x%08X" % (emu_r.get("value") or 0)})
    return diffs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--emu", default=None)
    a = ap.parse_args()

    vectors = [v for v in OS.build_scalar_vectors()
               if v["family"] in SCALAR_FAMILIES]
    results, fam = [], {}
    for vec in vectors:
        or_r = run_oracle(vec)
        emu_r = run_emulator(vec)
        diffs = compare(vec, emu_r, or_r)
        f = fam.setdefault(vec["family"], {"n": 0, "fail": 0, "raised": 0})
        f["n"] += 1
        if diffs:
            f["fail"] += 1
        if emu_r.get("error"):
            f["raised"] += 1
        results.append({"family": vec["family"], "name": vec["name"],
                        "mnem": vec["mnem"], "operands": vec["operands"],
                        "note": vec["note"], "oracle": or_r,
                        "emulator": emu_r, "agree": not diffs,
                        "differences": diffs[:4],
                        "n_differences": len(diffs)})

    # The address-formation vectors are oracle-only reference values; they are
    # recorded so a reader can check the rule by hand.
    addr = []
    for vec in OS.build_scalar_vectors():
        if vec["family"] != "addr":
            continue
        r = OS.eval_address(vec)
        addr.append({"name": vec["name"], "mnem": vec["mnem"],
                     "operands": [("0x%X" % x) if isinstance(x, int) and x > 9
                                  else x for x in vec["operands"]],
                     "expected": "0x%X" % r["value"], "note": vec["note"]})

    doc = {
        "schema": "phase16l_isa_scalar_conformance/1",
        "phase": "16L", "label": a.label,
        "emulator_path": os.path.relpath(EMU_PATH, ROOT).replace(os.sep, "/"),
        "emulator_loaded_from": os.path.abspath(E.__file__),
        "emulator_sha256": emu_hash(),
        "core_class_under_test": CORE_CLASS_NAME,
        "core_class_mro": [k.__name__ for k in CORE_CLASS.__mro__],
        "oracle_imports_emulator": False,
        "n_vectors": len(vectors),
        "n_agree": sum(1 for r in results if r["agree"]),
        "n_disagree": sum(1 for r in results if not r["agree"]),
        "by_family": fam,
        "address_reference_values": addr,
        "host_only": True, "gpu_execution_performed": False,
        "results": results,
    }
    out = a.out or os.path.join(HERE, "%s_SCALAR_RESULT.json" % a.label.upper())
    json.dump(doc, open(out, "w", encoding="utf-8"), indent=1)

    print("=" * 96)
    print("SCALAR / ADDRESS CONFORMANCE -- label %s" % a.label)
    print("emu.py sha256 %s" % doc["emulator_sha256"])
    print("loaded from    %s" % doc["emulator_loaded_from"])
    print("=" * 96)
    for f, s in sorted(fam.items()):
        print("  %-8s %3d vectors, %3d disagree, %3d raised"
              % (f, s["n"], s["fail"], s["raised"]))
    print("-" * 96)
    print("TOTAL %d vectors, %d agree, %d disagree"
          % (doc["n_vectors"], doc["n_agree"], doc["n_disagree"]))
    for r in results:
        if r["agree"]:
            continue
        print("  DISAGREE %-8s %-30s %s %s"
              % (r["family"], r["name"], r["mnem"], r["operands"]))
        if r["emulator"].get("error"):
            print("      emulator raised: %s" % r["emulator"]["error"])
        for d in r["differences"]:
            print("      %s oracle=%s emulator=%s"
                  % (d["field"], d.get("oracle"), d.get("emulator")))
    print()
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
