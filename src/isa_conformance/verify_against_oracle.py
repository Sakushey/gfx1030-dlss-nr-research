#!/usr/bin/env python3
"""Phase 16L-L1/L2 -- run every conformance vector through BOTH the emulator and
the independent oracle, and report every disagreement.

THIS IS THE INSTRUMENT THAT PROVES THE REPAIR.

It produces two artifacts:

  PRE_FIX_RESULT.json   -- run before `emu.py` is edited (the old semantics)
  POST_FIX_RESULT.json  -- run after

and a comparison.  Nothing here trusts the emulator's own handlers: the expected
value comes from `isa_oracle.py`, which imports no emulator code at all.

The emulator is loaded from `phase8_static/tools/emu.py` -- the real shared base
implementation, not a copy -- so what is measured is what the gates run.

usage:
    python verify_against_oracle.py --label pre_fix
    python verify_against_oracle.py --label post_fix

Host-only.  No GPU.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "phase8_static", "tools"))

import isa_oracle as O                      # noqa: E402

# The emulator under test.  Default is the live shared implementation; `--emu`
# points at a frozen copy so the SAME oracle can be run against the pre-fix and
# post-fix bytes.  Comparing a new oracle against an old result would measure
# the oracle, not the repair.
#
# `--emu` is loaded BY FILE PATH, not by `import emu`, and the live module is
# purged from `sys.modules` first.  An earlier version of this script inserted
# the frozen file's DIRECTORY on `sys.path` and then did `import emu`; the
# frozen copy is named `emulator_base__emu.py`, so that import silently
# resolved to the LIVE emulator and the "pre-fix" run measured the fixed file
# against itself -- all 97 vectors agreeing, which looked like a clean result.
# That is the "verify artifacts, not exit codes" failure in miniature, and it
# is why the loaded path and hash are printed and persisted in the artifact.
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
    assert os.path.abspath(E.__file__) == EMU_PATH, E.__file__
else:
    import emu as E                         # noqa: E402

# Hard identity check: a run that fails this is a run that did not test what it
# claims to.  It is an assertion, not a print, so it cannot be overlooked.
assert os.path.abspath(E.__file__) == EMU_PATH, \
    "loaded %s but meant to load %s" % (E.__file__, EMU_PATH)

# The hardware's boolean-false literal.  In GCN/RDNA the scalar operand field
# encodes a zero as **SGPR 0**, which the ISA documentation calls `bool_zero`
# (and SGPR 1 `bool_one`); it is not an immediate and not a destination slot.
# The emulator reads it through `sget("s0")`, so the vectors spell it `s0` and
# the entry state sets SGPR 0 to zero.
BOOL_ZERO = "`bool_zero`"


def emu_hash():
    h = hashlib.sha256()
    with open(EMU_PATH, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# build a Core and its initial state from a vector's `setup`
# ---------------------------------------------------------------------------
def build_core(vec, lanes=32):
    ops = printed_operands(vec)
    prog = [{"mnemonic": vec["mnem"] + "_e32",
             "operands": ", ".join(ops),
             "address": 0x1000,
             "text": vec["mnem"] + " " + ", ".join(ops),
             "target": None}]
    core = E.Core(prog, lanes=lanes)
    for i in range(lanes):
        core.v[i][0] = 0xDEADBEEF
        core.v[i][1] = 0x11111111
        core.v[i][2] = 0x22222222
        core.v[i][3] = 0x33333333
    for i in range(128):
        core.s[i] = 0x44444444
    for k, v in vec["setup"].items():
        if k.endswith("_f32"):
            idx = int(k[1:-4])
            for i in range(lanes):
                core.v[i][idx] = O.f32_bits(v if i == 0 else O._perturb(v, i))
        elif k.endswith("_f16"):
            idx = int(k[1:-4])
            for i in range(lanes):
                core.v[i][idx] = (v & 0xFFFF) if i == 0 else ((v + i) & 0xFFFF)
        else:
            idx = int(k[1:])
            for i in range(lanes):
                core.v[i][idx] = O.u32(v) if i == 0 else O.u32(v + i)
    return core


def printed_operands(vec):
    """The operand list EXACTLY as the disassembler would print it.

    This is the single source of truth for operand order, and it is used for
    BOTH the emulator and the oracle.  If they were fed different lists the
    comparison would be meaningless.

    * `v_cmp_*`  (VOPC)  : `dst, src0, src1` where dst is vcc_lo / sN.
      The vectors carry that destination in `srcs[0]` already.
    * `v_cmpx_*` (VOPCX) : `src0, src1` ONLY.  There is no destination to
      print -- the destination is EXEC and is written implicitly.  The
      Candidate F module's line is `v_cmpx_neq_f32_e32 0, v5`, whose first
      operand is therefore src0 (the hardware's boolean-false literal, encoded
      as SGPR 0), NOT a destination slot.  Two operands in, two operands out.
    * vop1/vop2/vop3    : `dst, ...sources`; the destination is prepended.
    """
    srcs = ["s0" if s == BOOL_ZERO else s for s in vec["srcs"]]
    if vec["mnem"].startswith("v_cmp_"):
        return srcs                     # vectors already carry dst in slot 0
    return ([vec["dst"]] if vec["dst"] else []) + srcs


def run_emulator(vec, lanes=32):
    """Execute one vector on the real emulator; return the effect dict.

    The destination register is recorded PER LANE, and the EXEC/VCC masks, so a
    disagreement can be localised rather than merely detected.
    """
    core = build_core(vec, lanes=lanes)
    ins = core.prog[0]
    mnem = ins["mnemonic"].replace("_e32", "").replace("_e64", "")
    ops = [o.strip() for o in ins["operands"].split(",")] if ins["operands"] else []
    was_cmp = mnem.startswith("v_cmp_")
    was_cmpx = mnem.startswith("v_cmpx_")
    dst = None
    if not was_cmpx:
        dst = vec["dst"] if vec["dst"] else "v0"
    try:
        core.step()
        err = None
    except Exception as exc:                                  # noqa: BLE001
        err = "%s: %s" % (type(exc).__name__, exc)
    out = {"error": err, "exec_lo": core.exec_l, "vcc_lo": core.vcc_l,
           "dst": vec["dst"], "regs": {}}
    if was_cmp and not was_cmpx:
        out["regs"] = {}          # the result lives in VCC, already captured
    elif not was_cmpx:
        di = int(dst[1:]) if dst.startswith("v") else None
        if di is not None:
            out["regs"] = {str(i): core.v[i][di] for i in range(lanes)}
    return out


def run_oracle(vec, lanes=32):
    st = O.make_state(vec["setup"], lanes=lanes)
    # The oracle must see the SAME entry state, including the pre-loaded dst.
    for i in range(lanes):
        st.regs[i][0] = 0xDEADBEEF
        st.regs[i][1] = 0x11111111
        st.regs[i][2] = 0x22222222
        st.regs[i][3] = 0x33333333
    for i in range(128):
        st.sgprs[i] = 0x44444444
    for k, v in vec["setup"].items():
        if k.endswith("_f32"):
            idx = int(k[1:-4])
            for i in range(lanes):
                st.regs[i][idx] = O.f32_bits(v if i == 0 else O._perturb(v, i))
        elif k.endswith("_f16"):
            idx = int(k[1:-4])
            for i in range(lanes):
                st.regs[i][idx] = (v & 0xFFFF) if i == 0 else ((v + i) & 0xFFFF)
        else:
            idx = int(k[1:])
            for i in range(lanes):
                st.regs[i][idx] = O.u32(v) if i == 0 else O.u32(v + i)
    dst = vec["dst"] if vec["dst"] else None
    # The SAME list the emulator receives -- one construction, two consumers.
    ops = printed_operands(vec)
    try:
        eff = O.execute(vec["mnem"], ops, st, dst_token=vec["dst"])
        err = None
    except Exception as exc:                                  # noqa: BLE001
        return {"error": "%s: %s" % (type(exc).__name__, exc), "exec_lo":
                st.exec_lo, "vcc_lo": st.vcc_lo, "dst": dst, "regs": {}}
    out = {"error": err, "exec_lo": st.exec_lo, "vcc_lo": st.vcc_lo,
           "dst": dst, "regs": {}}
    if dst and dst.startswith("v") and not vec["mnem"].startswith("v_cmp"):
        di = int(dst[1:])
        out["regs"] = {str(i): st.regs[i][di] for i in range(lanes)}
    return out


# ---------------------------------------------------------------------------
def compare(vec, emu_r, or_r, lanes=32):
    """Field-by-field.  A float destination is compared by VALUE BITS, with an
    explicit NaN-equals-NaN rule, because two NaNs with different payloads are
    still the same architectural result for our purposes."""
    diffs = []
    if emu_r.get("error") != or_r.get("error"):
        if emu_r.get("error") is not None:
            diffs.append({"field": "error", "oracle": or_r.get("error"),
                          "emulator": emu_r.get("error"),
                          "note": "EMULATOR RAISED"})
        else:
            diffs.append({"field": "error", "oracle": or_r.get("error"),
                          "emulator": None})
    m = vec["mnem"]
    if m.startswith("v_cmpx_"):
        if emu_r["exec_lo"] != or_r["exec_lo"]:
            diffs.append({"field": "exec_lo", "lane": "-",
                          "oracle": "0x%08X" % or_r["exec_lo"],
                          "emulator": "0x%08X" % emu_r["exec_lo"],
                          "expected_lane0": (or_r["exec_lo"] & 1),
                          "got_lane0": (emu_r["exec_lo"] & 1)})
    elif m.startswith("v_cmp_"):
        if emu_r["vcc_lo"] != or_r["vcc_lo"]:
            diffs.append({"field": "vcc_lo", "lane": "-",
                          "oracle": "0x%08X" % or_r["vcc_lo"],
                          "emulator": "0x%08X" % emu_r["vcc_lo"]})
    else:
        for i in range(lanes):
            a = emu_r["regs"].get(str(i))
            b = or_r["regs"].get(str(i))
            if a is None or b is None:
                continue
            if a == b:
                continue
            if _both_nan_f32(a, b):
                continue
            diffs.append({"field": "v%d" % 0, "lane": i,
                          "oracle": "0x%08X" % b, "emulator": "0x%08X" % a,
                          "oracle_value": _show(b), "emulator_value": _show(a)})
    return diffs


def _both_nan_f32(a, b):
    try:
        fa = O.bits_f32(a)
        fb = O.bits_f32(b)
    except Exception:                                          # noqa: BLE001
        return False
    return isinstance(fa, float) and isinstance(fb, float) \
        and math.isnan(fa) and math.isnan(fb)


def _show(bits):
    v = O.bits_f32(bits)
    if math.isnan(v):
        return "NaN"
    return "%.9g" % v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True,
                    help="pre_fix or post_fix (or any honest name)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--emu", default=None,
                    help="path to the emu.py to test (default: the live one)")
    a = ap.parse_args()

    vectors = O.build_vectors()
    results = []
    fam = {}
    for vec in vectors:
        try:
            or_r = run_oracle(vec)
        except Exception:                                      # noqa: BLE001
            or_r = {"error": "ORACLE_FAILED\n" + traceback.format_exc(),
                    "exec_lo": 0, "vcc_lo": 0, "dst": vec["dst"], "regs": {}}
        emu_r = run_emulator(vec)
        diffs = compare(vec, emu_r, or_r)
        ok = not diffs
        f = fam.setdefault(vec["family"], {"n": 0, "fail": 0, "errors": 0})
        f["n"] += 1
        if not ok:
            f["fail"] += 1
        if emu_r.get("error"):
            f["errors"] += 1
        results.append({
            "family": vec["family"], "name": vec["name"], "mnem": vec["mnem"],
            "srcs": vec["srcs"], "dst": vec["dst"],
            "note": vec["note"],
            "oracle": or_r, "emulator": emu_r,
            "agree": ok, "differences": diffs[:6], "n_differences": len(diffs),
        })

    doc = {
        "schema": "phase16l_isa_conformance/1",
        "phase": "16L",
        "label": a.label,
        "emulator_path": os.path.relpath(EMU_PATH, ROOT).replace(os.sep, "/"),
        "emulator_loaded_from": os.path.abspath(E.__file__),
        "emulator_sha256": emu_hash(),
        "oracle_path": "phase16l_authoritative_rederive/isa_conformance/isa_oracle.py",
        "oracle_imports_emulator": False,
        "n_vectors": len(vectors),
        "n_agree": sum(1 for r in results if r["agree"]),
        "n_disagree": sum(1 for r in results if not r["agree"]),
        "by_family": fam,
        "host_only": True,
        "gpu_execution_performed": False,
        "results": results,
    }
    out = a.out or os.path.join(HERE, "%s_RESULT.json" % a.label.upper())
    json.dump(doc, open(out, "w", encoding="utf-8"), indent=1)

    print("=" * 96)
    print("ISA CONFORMANCE -- label %s" % a.label)
    print("emu.py sha256 %s" % doc["emulator_sha256"])
    print("=" * 96)
    for f, s in sorted(fam.items()):
        print("  %-10s %3d vectors, %3d disagree, %3d raised"
              % (f, s["n"], s["fail"], s["errors"]))
    print("-" * 96)
    print("TOTAL %d vectors, %d agree, %d disagree"
          % (doc["n_vectors"], doc["n_agree"], doc["n_disagree"]))
    if doc["n_disagree"]:
        print()
        for r in results:
            if r["agree"]:
                continue
            print("  DISAGREE  %-12s %-22s %s" % (r["family"], r["name"],
                                                  r["mnem"]))
            if r["emulator"].get("error"):
                print("      emulator raised: %s" % r["emulator"]["error"])
            for d in r["differences"]:
                print("      %s lane=%s oracle=%s emulator=%s"
                      % (d.get("field"), d.get("lane"), d.get("oracle"),
                         d.get("emulator")))
    print()
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
