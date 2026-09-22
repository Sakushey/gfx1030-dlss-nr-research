#!/usr/bin/env python3
# Phase 16I re-derivation of the Phase-16G perturbation matrix.
# Byte-identical to phase16g_forensics/tools/p16g_perturb.py except for the
# OUTPUT path, so the frozen p16g_perturb.json stays intact as the record of
# what the inverted emulator asserted.  The Phase-16G assertion this
# re-derivation falsifies is the "baseline" case note:
#     "must reproduce ALL_ENDED 16945"
#
# MEMORY -- two separate causes, both measured, neither guessed:
#
#   (1) `HWCore.registry` (p14eh.py:138) is a CLASS attribute and
#       `HWCore.__init__` appends every core to it.  Nothing clears it, so a
#       per-case sweep retains one full core per case.  Fixed by the
#       `p14eh.HWCore.registry = []` in the finally block below.
#
#   (2) `hw_ev`, `hw_memviol` and `ds_ops` are unbounded per-active-lane
#       access record lists on the core, and they are what actually grows
#       WITHIN a case -- `p16h_p14_variants.py:79` already says so.  Measured
#       here: the baseline case alone retains 366,592 `hw_ev` dicts =
#       168.6 MB for a 9,933-tick run, ~37 records per tick.  A case that
#       runs to the 3M/12M step caps therefore reaches tens of GB on its own,
#       which no amount of registry clearing can bound.  Fixed by running the
#       core with counters instead of lists (AggEv / AggE16Core below).
#
# `p14eh.run_workgroup_hw` reads these three only for their counts, and this
# tool reads only `outcome` / `ticks` / `per_wave` / `barrier_epochs` -- so
# aggregating them is result-neutral for everything reported here.
"""Phase16G — emulator perturbation matrix for swin_var<32,false>.

Host-only, zero GPU.  Re-runs the Phase-16F physical-mirror geometry
(grid 1x1x1, block 256x1x1, wgid 0,0,0, authentic cell-A VarParams) and
perturbs ONE emulator input at a time.  The purpose is to find which
single assumption, if it does not hold on the real gfx1030, turns the
emulator's ALL_ENDED into non-termination -- i.e. to localise the second
emulator<->physical divergence by search rather than by intuition.

Usage: python p16g_perturb.py [--only NAME] [--cap N]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT = os.path.join(ROOT, "phase16i_closure", "out")
os.makedirs(OUT, exist_ok=True)
# The cases are independent and host-only, so several may run at once -- but
# each rewrites the whole result file, so concurrent writers would clobber
# each other.  `P16I_PERTURB_OUT` gives each run its own file; merge after.
# (Same pattern as `P14_OUT_NAME` in p16h_p14_variants.py:92.)
OUT_NAME = os.environ.get("P16I_PERTURB_OUT", "p16i_perturb_regen.json")
OUT_PATH = os.path.join(OUT, OUT_NAME)
for p in ("phase16e_candidate_e/tools", "phase14e_static/tools",
          "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
          "phase14d11_static"):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)

import p16e_lib          # noqa: E402
import p16e_rec          # noqa: E402
import p16e_cand_wg      # noqa: E402
import p14eh             # noqa: E402
from p14eh import PE     # noqa: E402
import p14d11_emu as P11  # noqa: E402

SYM = "_Z10k_swin_varILi32ELb0EEv9VarParams"
DIS = os.path.join(ROOT, "phase16e_candidate_e", "disasm",
                   "candidate_e_gfx1030_disasm.txt")
CO = os.path.join(ROOT, "phase16e_candidate_e",
                  "gfx1030_dlssnr_candidate_e.co")

KERNARG = P11.KERNARG


class AggEv:
    """Stand-in for an unbounded per-access record list: keeps the counts,
    stores nothing.  `__len__` is exact (p14eh reads it for `memviol`), and
    the per-kind totals stay available as attributes.  `__iter__` is empty,
    so p14eh's `n_rw` / `n_bp` come out 0 under aggregation -- this tool does
    not consume either, and the true totals are carried into the output JSON
    under `agg_n_rw` / `agg_n_bp` so they are not silently lost.
    """

    __slots__ = ("n", "n_rw", "n_bp")

    def __init__(self, *a, **k):
        self.n = self.n_rw = self.n_bp = 0

    def append(self, x):
        self.n += 1
        k = x.get("kind") if isinstance(x, dict) else None
        if k == "rw":
            self.n_rw += 1
        elif k == "bp":
            self.n_bp += 1

    def __len__(self):
        return self.n

    def __iter__(self):
        return iter(())


class AggE16Core(p16e_rec.E16Core):
    """E16Core with the three unbounded accumulators replaced by counters.
    See the MEMORY note at the top of this file."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.hw_ev = AggEv()
        self.hw_memviol = AggEv()
        self.ds_ops = AggEv()


def make_swin_mem(base_swin_mem, overrides):
    """Return a swin_mem replacement applying `overrides` after the
    standard hidden-arg fill.  overrides: {kernarg_offset: value}."""
    def _f(fields, grid, block):
        mem = base_swin_mem(fields, grid, block)
        for off, val in overrides.items():
            mem[KERNARG + off] = val & 0xFFFFFFFF
        return mem
    return _f


CASES = [
    # name, grid, block, {kernarg_off: value} overrides, note
    ("baseline", (1, 1, 1), (256, 1, 1), {},
     "exact Phase-16F physical geometry; must reproduce ALL_ENDED 16945"),
    ("hid_gsx0", (1, 1, 1), (256, 1, 1), {0xA8 + 12: 0},
     "hidden_group_size_x = 0 (runtime left the u16 at 0xB4 unfilled)"),
    ("hid_bcx0", (1, 1, 1), (256, 1, 1), {0xA8: 0},
     "hidden_block_count_x = 0 (0xA8 unfilled)"),
    ("hid_all0", (1, 1, 1), (256, 1, 1),
     {0xA8: 0, 0xAC: 0, 0xB0: 0, 0xB4: 0, 0xB8: 0, 0xBA: 0, 0xBC: 0,
      0xD0: 0, 0xD8: 0, 0xE0: 0, 0xE8: 0},
     "the whole 0xA8..0xBF + global-offset + grid_dims tail left zero"),
    ("grid_authentic", (120, 72, 1), (256, 1, 1), {},
     "authentic GTA grid instead of the 1x1x1 harness grid"),
    ("hid_gsy0", (1, 1, 1), (256, 1, 1), {0xA8 + 14: 0},
     "hidden_group_size_y = 0"),
    ("p48_zero", (1, 1, 1), (256, 1, 1), {0x48: 0, 0x4C: 0},
     "kernarg +0x48 = 0 (authentic host leaves 0x40..0x9F zeroed)"),
    ("p98_zero", (1, 1, 1), (256, 1, 1), {0x98: 0, 0x9C: 0},
     "kernarg +0x98 = 0 (already zero in the harness; control)"),
    ("flags0", (1, 1, 1), (256, 1, 1), {0x28: 0},
     "VarParams flags = 0 instead of 0x1"),
    ("flags14", (1, 1, 1), (256, 1, 1), {0x28: 0x14},
     "VarParams flags = 0x14 (a flags value seen on other instances)"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    ap.add_argument("--cap", type=int, default=3_000_000,
                    help="per-wave step cap; keeps a hang cheap to detect")
    ap.add_argument("--roundcap", type=int, default=12_000_000)
    args = ap.parse_args()

    prog, _r, _i = PE.slice_program(DIS, SYM)
    dw = P11.dw16(CO, SYM)
    cell = p16e_rec.CELLS["A"]
    fields = p16e_rec.fields_for(cell)
    print("cell:", {k: v for k, v in cell.items() if k != "wgid"})

    base_swin_mem = PE.swin_mem
    prev_hw = p14eh.HWCore
    rows = []
    for name, grid, block, ovr, note in CASES:
        if args.only and name != args.only:
            continue
        p14eh.HWCore = AggE16Core
        p14eh.HWCore.oob_sem = "u32"
        p14eh.HWCore.alloc = 16384
        p14eh.HWCore.lds_img = 0x10000
        p14eh.HWCore.registry = []
        PE.swin_mem = make_swin_mem(base_swin_mem, ovr)
        t0 = time.time()
        agg = {}
        try:
            res = p14eh.run_workgroup_hw(
                prog, dw, "p16g_" + name, grid, block, fields,
                text_path=CO, wave_count=8, oob_sem="u32", alloc=16384,
                wgid=(0, 0, 0),
                per_wave_step_cap=args.cap, round_cap=args.roundcap)
            outcome = str(res["outcome"])
            ticks = res["ticks"]
            epochs = len(res["barrier_epochs"])
            pw = [(p["wave"], p["state"], p["steps"], p["barriers"],
                   p["memviol"]) for p in res["per_wave"]]
            # totals the aggregated counters hold, read before the finally
            # clears the registry -- see AggEv's docstring.
            _c = list(p14eh.HWCore.registry)
            agg = {"n_rw": sum(getattr(c.hw_ev, "n_rw", 0) for c in _c),
                   "n_bp": sum(getattr(c.hw_ev, "n_bp", 0) for c in _c),
                   "memviol": sum(len(c.hw_memviol) for c in _c),
                   "ds_ops": sum(len(c.ds_ops) for c in _c)}
        except Exception as e:                       # noqa: BLE001
            outcome = "EXC %s: %s" % (type(e).__name__, e)
            ticks = epochs = -1
            pw = []
        finally:
            PE.swin_mem = base_swin_mem
            # Cause (1) in the MEMORY note.  `HWCore.__init__` does
            # `HWCore.registry.append(self)` against whichever class is
            # bound at the time -- so the cores of THIS case live on
            # AggE16Core, and clearing prev_hw's list alone would miss them.
            AggE16Core.registry = []
            p14eh.HWCore = prev_hw
            p14eh.HWCore.registry = []
        secs = round(time.time() - t0, 1)
        print("=" * 78)
        print("%-16s grid=%s block=%s  overrides=%s" % (name, grid, block,
                                                        ovr))
        print("   note    : %s" % note)
        print("   outcome : %s   ticks=%s  epochs=%s  (%.1fs)"
              % (outcome, ticks, epochs, secs))
        for w in pw:
            print("      wave %d state=%s steps=%d barriers=%d memviol=%d" % w)
        rows.append(dict(name=name, grid=list(grid), block=list(block),
                         overrides={hex(k): v for k, v in ovr.items()},
                         note=note, outcome=outcome, ticks=ticks,
                         epochs=epochs, secs=secs, per_wave=pw,
                         agg_n_rw=agg.get("n_rw"), agg_n_bp=agg.get("n_bp"),
                         agg_memviol=agg.get("memviol"),
                         agg_ds_ops=agg.get("ds_ops")))
        # Written after EVERY case, not once at the end.  The first two
        # attempts at this re-derivation each ran for hours and died with
        # zero bytes of output, which threw away all of their work.
        json.dump(rows, open(OUT_PATH, "w"), indent=1)

    print("\nwrote", OUT_PATH)


if __name__ == "__main__":
    main()
