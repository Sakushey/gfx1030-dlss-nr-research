#!/usr/bin/env python3
"""Phase 16I-ISA -- verify the ISA closure, statically and dynamically.

STATIC: for every kernel in Candidate F, resolve every instruction's handler
exactly as `emu.Core.step()` does, using a real instance of the
ISA-closed core.  A kernel is ISA-clean iff every instruction resolves.  This
is the closure claim, and it is falsifiable: any mnemonic still missing is
named with its PC.

DYNAMIC: run each formerly-affected kernel with the ISA-closed core and a
zeroed kernarg, and report whether it now executes past the PC where it used
to fault, or faults somewhere else.  A dynamic run with a zeroed kernarg is
NOT numerical validation -- it only shows the instruction no longer blocks
dispatch.  The report says so explicitly.

Host-only.  No GPU.

Usage:
  p16i_isa_close.py [--kernel SYM] [--rounds N] [--json OUT]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
for p in ("phase16i_closure/tools", "phase16h_pcrel_fix/tools",
          "phase16e_candidate_e/tools", "phase14e_static/tools",
          "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
          "phase14d11_static", "phase14d_static/tools", "phase8_static/tools",
          "phase14d8_static/tools"):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)

import p16i_isa as ISA          # noqa: E402
import p16h_lib as L            # noqa: E402
import p16h_global_gate as G    # noqa: E402
import p16h_p12_emulate as P12  # noqa: E402
import p16e_rec as rec          # noqa: E402

CO = os.path.join(ROOT, "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co")
DIS = os.path.join(ROOT,
                   "phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt")


def handler_of(core, ins):
    """Resolve exactly as emu.Core.step() does; return (kind, detail)."""
    mnem = ins["mnemonic"].replace("_e32", "").replace("_e64", "")
    if mnem.startswith("v_dual_"):
        mnem = "v_" + mnem[len("v_dual_"):]
    if mnem.startswith("v_cmp_") or mnem.startswith("v_cmpx_"):
        # `_cmp_dispatch` / `_cmpx_dispatch` resolve against the *v_cmp_*
        # table with the full mnemonic as the key; the cmpx form is folded
        # to the cmp name before lookup.
        name = "v_cmp_" + mnem[len("v_cmpx_" if mnem.startswith("v_cmpx_")
                                  else "v_cmp_"):]
        for fn in (core._int_cmp_cond, core._fp_cmp_cond):
            try:
                fn(name)
                return ("CMP", name)
            except Exception:                            # noqa: BLE001
                pass
        return ("MISSING_CMP", mnem)
    key = mnem
    f = getattr(type(core), "op_" + key, None)
    if f is None:
        f = getattr(core, "op_" + key, None)
    if f is not None:
        mod = getattr(f, "__module__", "")
        return ("OP", "%s.%s" % (mod, getattr(f, "__qualname__", key)))
    return ("MISSING", mnem)


def static_census(symbols):
    elf = L.Elf(CO)
    base = ISA.p16i_isa_core(P12.P12Core)
    core = base.__new__(base)
    out = {}
    for sym in symbols:
        try:
            prog, _r, _i = G.PE.slice_program(DIS, sym)
        except Exception as e:                       # noqa: BLE001
            out[sym] = {"error": "slice: %s" % e}
            continue
        missing = {}
        n = 0
        for ins in prog:
            n += 1
            kind, detail = handler_of(core, ins)
            if kind in ("MISSING", "MISSING_CMP"):
                key = "0x%X" % (ins.get("address") or 0)
                missing.setdefault(detail, []).append(key)
        out[sym] = {"n_insn": n, "clean": not missing,
                    "missing": {k: v[:6] for k, v in missing.items()}}
    return out


def dynamic_run(sym, rounds, region_mib):
    """Run with a zeroed kernarg + declared regions, ISA-closed core."""
    prog, _r, _i = G.PE.slice_program(DIS, sym)
    dw = G.P11.dw16(CO, sym)
    elf = L.Elf(CO)
    ks = G.kernarg_size(elf, sym + ".kd") or 256
    fields = {}

    ggate = G.GlobalGate()
    for lo, size, name in G.module_regions(elf):
        ggate.declare(lo, size, "module:" + name)
    ggate.declare(G.KERNARG, ks, "kernarg")
    ggate.declare(G.PACKET, 64, "aql_packet")
    # A generous single arena for whatever pointers the zeroed kernarg
    # happens to carry; the point of this run is ISA reachability, not
    # address validation, and the report says so.
    ggate.declare(0x100000000, region_mib * 1024 * 1024, "zero_arena")

    base = ISA.p16i_isa_core(P12.P12Core)
    for attr, val in (("gate", ggate), ("wave_index", 0), ("oob_sem", "u32"),
                      ("alloc", 16384), ("lds_img", 0x10000)):
        setattr(base, attr, val)
    base.scrt_gate = None

    prev = G.p14eh.HWCore
    G.p14eh.HWCore = base
    try:
        orig = G.PE.text_mem_map
        G.PE.text_mem_map = G.module_mem_map
        try:
            res = G.p14eh.run_workgroup_hw(
                prog, dw, "p16i_isa_" + sym[:24], (1, 1, 1), (256, 1, 1),
                fields, text_path=CO, wave_count=8, oob_sem="u32",
                alloc=16384, wgid=(0, 0, 0), round_cap=rounds)
        finally:
            G.PE.text_mem_map = orig
    finally:
        G.p14eh.HWCore = prev
    G.p14eh.HWCore.registry = []

    faults = [w.get("fault") for w in res["per_wave"] if w.get("fault")]
    return {"outcome": str(res.get("outcome")), "ticks": res.get("ticks"),
            "faults": [list(f) if isinstance(f, (list, tuple)) else f
                       for f in faults],
            "gate": ggate.summary()["gate"],
            "oob_reads": ggate.summary()["oob_global_reads"],
            "oob_writes": ggate.summary()["oob_global_writes"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=20000)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--json", default=os.path.join(
        ROOT, "phase16i_closure/out/p16i_isa_close.json"))
    ap.add_argument("--no-dynamic", action="store_true")
    a = ap.parse_args()

    # the 9 GTA-used kernels the census flagged, plus the 13 clean ones and
    # the 11 never-dispatched, so the closure claim is whole-module
    import csv
    census = os.path.join(ROOT, "phase16i_closure/out/p16i_isa_census.csv")
    syms = sorted({r["kernel_mangled"]
                   for r in csv.DictReader(open(census, encoding="utf-8"))})

    st = static_census(syms)
    still = {s: v for s, v in st.items() if not v.get("clean")}
    print("STATIC: %d symbols; %d still not ISA-clean"
          % (len(st), len(still)))
    for s, v in still.items():
        print("   %-52s %s" % (s[:52], v.get("missing") or v.get("error")))

    dyn = {}
    if not a.no_dynamic:
        affected = [r["kernel_mangled"] for r in
                    csv.DictReader(open(census, encoding="utf-8"))
                    if r["gta_used"] == "True"
                    and r["handler_status"] == "UNSUPPORTED"]
        for s in sorted(set(affected)):
            try:
                dyn[s] = dynamic_run(s, a.rounds, a.region_mib)
                d = dyn[s]
                print("DYNAMIC %-50s outcome=%-16s ticks=%-7s fault=%s"
                      % (s[:50], d["outcome"], d["ticks"],
                         (d["faults"][:1] or ["none"])[0]))
            except Exception as e:                   # noqa: BLE001
                dyn[s] = {"error": "%s: %s" % (type(e).__name__, e)}
                print("DYNAMIC %-50s ERROR %s" % (s[:50], e))

    json.dump({"static": st, "dynamic": dyn,
               "coverage_audit": ISA.audit_census(),
               "note": ("dynamic runs use a ZEROED kernarg and show only that "
                        "the instruction no longer blocks dispatch; they are "
                        "not numerical validation")},
              open(a.json, "w", encoding="utf-8"), indent=1)
    print("wrote " + a.json)
    return 0 if not still else 1


if __name__ == "__main__":
    sys.exit(main())
