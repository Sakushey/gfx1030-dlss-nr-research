#!/usr/bin/env python3
"""Phase 16I — attribute the perturbation re-derivation's memory growth.

The re-derivation (p16i_perturb.py) died at ~15 GB with zero output.  Two
candidate causes were written down and BOTH turned out to be wrong or
incomplete, so this tool measures instead of reasoning:

  1. `p16h_global_gate.GlobalGate` retaining a record per OOB access under
     an unbounded `P14_OOB_REC_CAP` default.  FALSIFIED: a run with the cap
     set to 2000 still grew at the same rate.
  2. `HWCore.registry` retaining every core ever built (a class-level list
     nothing clears).  Real, and it does explain cross-case retention -- but
     it cannot explain growth WITHIN a single case.

This tool runs ONE case (baseline, the non-terminating one) with a small
step cap and reports the retained size of the three per-access lists that
`p14eh.HWCore` accumulates -- `hw_ev`, `hw_memviol`, `ds_ops` -- against the
process's own RSS delta.  If the lists account for the growth, cause is
attributed; if they do not, it is not, and the next hypothesis is someone
else's problem to earn.

Usage: python p16i_perturb_memdiag.py [--cap N]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "phase16i_closure", "out")
os.makedirs(OUT, exist_ok=True)
for p in ("phase16e_candidate_e/tools", "phase14e_static/tools",
          "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
          "phase14d11_static"):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)

import p16e_lib          # noqa: E402,F401
import p16e_rec          # noqa: E402
import p16e_cand_wg      # noqa: E402,F401
import p14eh             # noqa: E402
from p14eh import PE     # noqa: E402
import p14d11_emu as P11  # noqa: E402

SYM = "_Z10k_swin_varILi32ELb0EEv9VarParams"
DIS = os.path.join(ROOT, "phase16e_candidate_e", "disasm",
                   "candidate_e_gfx1030_disasm.txt")
CO = os.path.join(ROOT, "phase16e_candidate_e",
                  "gfx1030_dlssnr_candidate_e.co")


def rss_mb():
    """Working set of this process, via the Win32 API (no psutil dep)."""
    import ctypes
    import ctypes.wintypes as wt

    class PMC(ctypes.Structure):
        _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t)]
    pmc = PMC()
    pmc.cb = ctypes.sizeof(PMC)
    ctypes.windll.psapi.GetProcessMemoryInfo(
        ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb)
    return pmc.WorkingSetSize / (1024.0 * 1024.0)


def deep_size(obj, _seen=None):
    """Approximate retained bytes for the list/dict/tuple/int shapes these
    three accumulators actually hold.  Good to ~10%, which is all the
    attribution needs."""
    if _seen is None:
        _seen = set()
    oid_ = id(obj)
    if oid_ in _seen:
        return 0
    _seen.add(oid_)
    s = sys.getsizeof(obj)
    if isinstance(obj, dict):
        for k, v in obj.items():
            s += deep_size(k, _seen) + deep_size(v, _seen)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for x in obj:
            s += deep_size(x, _seen)
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cap", type=int, default=150_000)
    args = ap.parse_args()

    prog, _r, _i = PE.slice_program(DIS, SYM)
    dw = P11.dw16(CO, SYM)
    cell = p16e_rec.CELLS["A"]
    fields = p16e_rec.fields_for(cell)

    p14eh.HWCore = p16e_rec.E16Core
    p14eh.HWCore.oob_sem = "u32"
    p14eh.HWCore.alloc = 16384
    p14eh.HWCore.lds_img = 0x10000
    p14eh.HWCore.registry = []

    r0 = rss_mb()
    res = p14eh.run_workgroup_hw(
        prog, dw, "p16i_memdiag", (1, 1, 1), (256, 1, 1), fields,
        text_path=CO, wave_count=8, oob_sem="u32", alloc=16384,
        wgid=(0, 0, 0), per_wave_step_cap=args.cap, round_cap=args.cap)
    r1 = rss_mb()

    cores = list(p14eh.HWCore.registry)
    tot = {"hw_ev": 0, "hw_memviol": 0, "ds_ops": 0}
    n = {"hw_ev": 0, "hw_memviol": 0, "ds_ops": 0}
    for c in cores:
        for name in tot:
            lst = getattr(c, name, None)
            if lst is None:
                continue
            n[name] += len(lst)
            tot[name] += deep_size(lst)

    print("=" * 72)
    print("cap=%d  outcome=%s  ticks=%s" % (args.cap, res["outcome"],
                                            res["ticks"]))
    print("cores retained: %d" % len(cores))
    print("-" * 72)
    print("%-12s %12s %14s" % ("list", "records", "retained MB"))
    for name in ("hw_ev", "hw_memviol", "ds_ops"):
        print("%-12s %12d %14.2f" % (name, n[name], tot[name] / 1048576.0))
    acc = sum(tot.values()) / 1048576.0
    print("-" * 72)
    print("accumulators total : %8.2f MB" % acc)
    print("RSS before run     : %8.2f MB" % r0)
    print("RSS after  run     : %8.2f MB" % r1)
    print("RSS delta          : %8.2f MB" % (r1 - r0))
    if r1 > r0:
        print("accumulators / RSS delta = %.2f" % (acc / (r1 - r0)))
    print("=" * 72)

    json.dump({"cap": args.cap, "outcome": str(res["outcome"]),
               "ticks": res["ticks"], "cores": len(cores),
               "n": n, "retained_mb": {k: v / 1048576.0
                                       for k, v in tot.items()},
               "rss_before_mb": r0, "rss_after_mb": r1,
               "rss_delta_mb": r1 - r0},
              open(os.path.join(OUT, "p16i_perturb_memdiag.json"), "w"),
              indent=1)


if __name__ == "__main__":
    main()
