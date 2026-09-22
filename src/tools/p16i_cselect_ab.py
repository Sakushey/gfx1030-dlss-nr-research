#!/usr/bin/env python3
"""Phase 16I-ISA -- A/B the `s_cselect_b32` operand order.

THE DEFECT

`phase8_static/tools/emu.py:294`:

    def op_s_cselect_b32(self, ins, ops):
        self.sset(ops[0], self.sget(ops[1] if not self.scc else ops[2]))

i.e.  dst = SCC ? src1 : src0.

The AMD RDNA/GCN ISA defines `S_CSELECT_B32 sdst, src0, src1` as

    sdst = SCC ? src0 : src1

so the emulator's two arms are swapped.  The module's own code makes the
direction unambiguous without an ISA document: the idiom

    s_cmp_<cond> ...
    s_cselect_b32 sN, -1, 0

is the standard scalar "predicate -> all-ones mask" conversion, and it is
only meaningful as `SCC ? -1 : 0`.  Under the emulator's order it yields
`SCC ? 0 : -1`, the *negation* of the predicate.  (Occurrences in
`phase14d11_static/out/trace_*.txt`.)

WHY IT MATTERS HERE

Every `s_cselect_b32` in a guard chain is a candidate for flipping which
arm of a bounds check is taken.  The four residual address-0 accesses in
the P8 gate sit behind exactly such chains.

WHAT THIS MEASURES

The authentic one-frame dispatch of `k_swin_var<32,false>` run twice --
baseline, and with the corrected operand order -- and reports outcome,
tick count, global gate verdict and the residual sites for each.  The
correction is supplied as a mixin so nothing is edited to take the
measurement.

Host-only.  No GPU.

Usage:
  p16i_cselect_ab.py [--tag swin32f] [--round-cap N]
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

import p16h_global_gate as G         # noqa: E402
import p16i_isa as ISA               # noqa: E402
import p16i_authentic_harness as AH  # noqa: E402


class CSelectFixed:
    """`s_cselect_b32 sdst, src0, src1` = SCC ? src0 : src1."""

    def op_s_cselect_b32(self, ins, ops):
        self.sset(ops[0], self.sget(ops[1] if self.scc else ops[2]))


def run_one(tag, csv, waves, region_mib, round_cap, out_path, fixed):
    base = G.GateCore
    if fixed:
        base = type("CSelectFixedCore", (CSelectFixed, G.GateCore), {})
    core = ISA.p16i_isa_core(base)
    # `GateCore._gl_addr` reads `GateCore.gate` by name, so the base must be
    # armed regardless of which class is dispatched (AH.run does this).
    return AH.run(tag, csv, None, None, waves, region_mib, round_cap,
                  out_path, core_cls=core)


def summarize(res, label):
    g = res["gate"]
    return {
        "label": label,
        "outcome": res["outcome"],
        "ticks": res["ticks"],
        "faults": res["faults"],
        "gate": g["gate"],
        "oob_global_reads": g["oob_global_reads"],
        "oob_global_writes": g["oob_global_writes"],
        "n_global_reads": g["n_global_reads"],
        "n_global_writes": g["n_global_writes"],
        "n_unmeasured": g["n_unmeasured_global_ops"],
        "sites": sorted(res.get("oob_reach_by_site", {}).keys()),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="swin32f")
    ap.add_argument("--csv", default=os.path.join(
        ROOT, "phase16_authentic_decode_swin.csv"))
    ap.add_argument("--waves", type=int, default=8)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--round-cap", type=int, default=2000000)
    ap.add_argument("--json", default=os.path.join(
        ROOT, "phase16i_closure/out/p16i_cselect_ab.json"))
    a = ap.parse_args()

    out = {"tag": a.tag, "runs": {}}
    for label, fixed in (("baseline", False), ("cselect_fixed", True)):
        p = os.path.join(ROOT,
                         "phase16i_closure/out/p16i_cselect_%s_%s.json"
                         % (a.tag, label))
        res = run_one(a.tag, a.csv, a.waves, a.region_mib, a.round_cap, p,
                      fixed)
        out["runs"][label] = summarize(res, label)
        out["runs"][label]["json"] = os.path.relpath(p, ROOT)

    for label in ("baseline", "cselect_fixed"):
        r = out["runs"][label]
        print("%-16s outcome=%-22s ticks=%-8s gate=%-4s oob_r=%-6s oob_w=%-6s "
              "n_r=%-8s n_w=%-6s sites=%d"
              % (label, r["outcome"], r["ticks"], r["gate"],
                 r["oob_global_reads"], r["oob_global_writes"],
                 r["n_global_reads"], r["n_global_writes"], len(r["sites"])))
    b, f = out["runs"]["baseline"], out["runs"]["cselect_fixed"]
    out["delta"] = {
        "oob_reads": f["oob_global_reads"] - b["oob_global_reads"],
        "oob_writes": f["oob_global_writes"] - b["oob_global_writes"],
        "ticks": (f["ticks"] - b["ticks"])
        if isinstance(f["ticks"], int) and isinstance(b["ticks"], int)
        else None,
        "sites_only_in_baseline": sorted(set(b["sites"]) - set(f["sites"])),
        "sites_only_in_fixed": sorted(set(f["sites"]) - set(b["sites"])),
    }
    print("delta: %s" % json.dumps(out["delta"]))

    json.dump(out, open(a.json, "w", encoding="utf-8"), indent=1)
    print("wrote " + a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
