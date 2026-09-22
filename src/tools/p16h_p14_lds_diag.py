#!/usr/bin/env python3
"""Phase 16H — P14 addendum: characterise the LDS violations of `<128,false>`.

Host-only.  No GPU, no HIP launch, no driver interaction.

WHY THIS EXISTS

`<128,false>` terminates cleanly (ALL_ENDED, 39 epochs, zero scratch OOB)
but reports **593,950** LDS violations, against 0 for `<32,false>` and 63
for `<64,false>`.  A number that large is not self-explanatory, and the
P14 run does not retain the violating records, so the count alone cannot
say whether it is

  (a) the documented C2-B high-bit wrap class (vaddr >= 0x10000), or
  (b) a mismatch between `HWCore.alloc` (the *declared*
      group_segment_fixed_size, 16384 here) and the emulator's LDS image
      (a fixed 0x10000), i.e. accesses the model has memory for but the
      declared segment does not cover, or
  (c) genuine addressing beyond both.

`_ea` makes the distinction observable: every record carries `a15872`,
`a16384` and `a65536` booleans, so the violations can be bucketed by which
bound they actually exceed.

This runs a SHORT prefix (a few thousand ticks) rather than the full
160,642: the violations are produced continuously throughout the kernel, so
a prefix gives a representative distribution for a fraction of the cost.
It does not write `out/p14_variants.json`.

Emits out/p14_lds_diag.json.
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p16h_lib as L  # noqa: E402
import p16h_global_gate as G  # noqa: E402
import p16h_scratch_probe as SP  # noqa: E402
import p16h_p12_emulate as P12  # noqa: E402

import p16e_rec  # noqa: E402

F_CO = "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co"
F_DIS = "phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt"

TAG = "swin128f"
SYM = "_Z10k_swin_varILi128ELb0EEv9VarParams"
CELL = {"X": 144, "Y": 240, "pl": 0, "ph": 0, "flags": 1,
        "grid": (30, 18, 1), "wgid": (0, 0, 0)}
WAVES = 8
ROUND_CAP = int(os.environ.get("P14_DIAG_ROUND_CAP", "12000"))


def bucket(rec):
    """Bucket a violation by the RAW (untruncated) 32-bit EA.

    The violation test itself uses `ea = raw` (`oob_sem="u32"`), so the
    buckets must be computed on `raw` too.  The record's `a16384`/`a65536`
    booleans are computed on `ea_dp = raw & dp_mask`, which encodes the
    *truncating* datapath hypothesis instead -- a different question.
    """
    end = rec["ea_u32"] + rec["w"]
    if end <= 16384:
        return "le_16384_declared"      # not a violation under u32
    if end <= 65536:
        return "16384_to_65536"         # inside a 64-KiB LDS image
    return "gt_65536"                   # the C2-B high-bit class


def main():
    OUT = os.path.join(L.P16H, "out")
    os.makedirs(OUT, exist_ok=True)

    co = os.path.join(L.ROOT, F_CO)
    dis = os.path.join(L.ROOT, F_DIS)
    prog, _rows, _i = G.PE.slice_program(dis, SYM)
    dw = G.P11.dw16(co, SYM)
    fields = p16e_rec.fields_for(CELL)

    elf = L.Elf(co)
    ks = G.kernarg_size(elf, SYM + ".kd")
    psz = SP.private_segment_size(co, SYM + ".kd")

    ggate = G.GlobalGate()
    for lo, size, name in G.module_regions(elf):
        ggate.declare(lo, size, "module:" + name)
    if ks:
        ggate.declare(G.KERNARG, ks, "kernarg")
    ggate.declare(G.PACKET, 64, "aql_packet")
    for _o, k in ((0x00, 0), (0x08, 1), (0x10, 2), (0x30, 3), (0x38, 4),
                  (0x48, 5), (0x78, 6), (0x80, 7), (0xA0, 8)):
        ggate.declare(G.SLOT + k * G.STRIDE, G.STRIDE, "harness_slot_%d" % k)

    sgate = SP.ScratchGate(psz if psz is not None else 0)

    for cls in (G.GateCore, P12.P12Core):
        cls.gate = ggate
        cls.wave_index = 0
        cls.oob_sem = "u32"
        cls.alloc = 16384
        cls.lds_img = 0x10000
    SP.ScrtGateCore.scrt_gate = sgate
    P12.P12Core.scrt_gate = sgate
    P12.P12Core.instances = []

    prev = G.p14eh.HWCore
    G.p14eh.HWCore = P12.P12Core
    try:
        orig_tmm = G.PE.text_mem_map
        G.PE.text_mem_map = G.module_mem_map
        try:
            res = G.p14eh.run_workgroup_hw(
                prog, dw, TAG, CELL["grid"], (256, 1, 1), fields,
                text_path=co, wave_count=WAVES, oob_sem="u32",
                alloc=16384, wgid=CELL["wgid"], round_cap=ROUND_CAP)
        finally:
            G.PE.text_mem_map = orig_tmm
    finally:
        G.p14eh.HWCore = prev

    cores = list(P12.P12Core.instances)
    P12.P12Core.instances = []
    G.p14eh.HWCore.registry = []

    # ---- aggregate the violating records ------------------------------
    n_viol = 0
    by_bucket = Counter()
    by_site = Counter()
    by_mnem = Counter()
    by_site_bucket = {}
    ea_min = None
    ea_max = None
    n_ev_total = 0
    n_ds_ops = 0
    n_in_range_if_trunc16 = 0

    for c in cores:
        n_ev_total += len(c.hw_ev)
        n_ds_ops += len(c.ds_ops)
        for r in c.hw_memviol:
            n_viol += 1
            # Would this access be in-range under the *truncating* datapath
            # hypothesis (ea = raw & 0xFFFF), i.e. is it a modelling
            # mismatch rather than genuine addressing past the segment?
            if ((r["ea_u32"] & 0xFFFF) + r["w"]) <= 16384:
                n_in_range_if_trunc16 += 1
            b = bucket(r)
            by_bucket[b] += 1
            s = "0x%08X" % (r["site"] or 0)
            by_site[s] += 1
            by_mnem[r["mnem"]] += 1
            by_site_bucket.setdefault(s, Counter())[b] += 1
            ea = r["ea_u32"]
            ea_min = ea if ea_min is None else min(ea_min, ea)
            ea_max = ea if ea_max is None else max(ea_max, ea)

    declared = psz
    out = {
        "tag": TAG, "symbol": SYM, "round_cap": ROUND_CAP,
        "ticks_run": res["ticks"], "outcome": str(res["outcome"]),
        "waves": len(cores),
        "declared_group_segment_fixed_size": 16384,
        "declared_private_segment_fixed_size": declared,
        "emulator_lds_image": "0x10000",
        "oob_sem": "u32", "alloc": 16384,
        "n_lds_rw_events_retained": n_ev_total,
        "n_ds_ops": n_ds_ops,
        "n_violations": n_viol,
        "n_in_range_if_trunc16": n_in_range_if_trunc16,
        "by_bucket": dict(by_bucket),
        "by_site": dict(by_site.most_common(40)),
        "by_mnem": dict(by_mnem.most_common(40)),
        "by_site_bucket": {k: dict(v) for k, v in
                           sorted(by_site_bucket.items())},
        "ea_u32_min": ("0x%08X" % ea_min) if ea_min is not None else None,
        "ea_u32_max": ("0x%08X" % ea_max) if ea_max is not None else None,
        "per_wave_violations": [len(c.hw_memviol) for c in cores],
    }
    jp = os.path.join(OUT, "p14_lds_diag.json")
    json.dump(out, open(jp, "w", encoding="utf-8"), indent=1, default=str)

    print("=" * 78)
    print("P14 LDS diagnostic — %s, prefix of %d ticks (of 160,642)"
          % (TAG, res["ticks"]))
    print("=" * 78)
    print("outcome=%s  waves=%d" % (res["outcome"], len(cores)))
    print("LDS rw events retained (hw_ev): %d" % n_ev_total)
    print("violations (hw_memviol):        %d" % n_viol)
    print("per-wave violations: %s" % out["per_wave_violations"])
    print("\nviolations by which bound they exceed:")
    for b, n in by_bucket.most_common():
        print("  %-20s %8d  %6.2f%%" % (b, n, 100.0 * n / max(n_viol, 1)))
    print("\nEA range (u32): %s .. %s" % (out["ea_u32_min"], out["ea_u32_max"]))
    print("would be in-range under trunc16 (raw & 0xFFFF): %d (%.2f%%)"
          % (n_in_range_if_trunc16,
             100.0 * n_in_range_if_trunc16 / max(n_viol, 1)))
    print("\ntop violating sites:")
    for s, n in by_site.most_common(12):
        print("  %-12s %8d   %s" % (s, n, out["by_site_bucket"].get(s)))
    print("\ntop mnemonics:")
    for m, n in by_mnem.most_common(12):
        print("  %-28s %8d" % (m, n))
    print("\nwrote", jp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
