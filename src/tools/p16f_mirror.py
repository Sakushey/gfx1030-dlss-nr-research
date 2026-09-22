#!/usr/bin/env python3
"""Phase 16F — physical-mirror emulator run (host-only, zero GPU).

Runs the CANDIDATE-E <32,false> body at the EXACT geometry the physical
harness will use: grid (1,1,1), block (256,1,1), wgid (0,0,0), 8 waves,
authentic cell-A VarParams (X=576 Y=960 pair 0/0 flags 0x1), measured
u32 EA model with alloc 16,384.

Expected: ALL_ENDED, 14 barrier epochs, 0 LDS memviol per wave (the
closed-body signature). Additionally reports the global per-slot
load/store offset reach of every wave (from each core's g_ops) so the
physical harness buffer sizes can be chosen with margin, and any global
access outside all modeled windows.

Emits phase16f_runtime/out/p16f_mirror_swin32f_A_g1.json.
"""
from __future__ import annotations

import json
import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", ".."))
OUT = os.path.join(ROOT, "phase16f_runtime", "out")
os.makedirs(OUT, exist_ok=True)
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

SLOT = P11.SLOT
GUARD = P11.GUARD
STRIDE = P11.STRIDE
KERNARG = P11.KERNARG
PACKET = P11.PACKET
TEXT_BASE = 0x3000_0000

def main():
    prog, _r, _i = PE.slice_program(DIS, SYM)
    dw = P11.dw16(CO, SYM)
    cell = p16e_rec.CELLS["A"]
    fields = p16e_rec.fields_for(cell)
    label = "p16f_mirror_swin32f_A_g1"

    prev_hw = p14eh.HWCore
    p14eh.HWCore = p16e_rec.E16Core
    p14eh.HWCore.oob_sem = "u32"
    p14eh.HWCore.alloc = 16384
    p14eh.HWCore.lds_img = 0x10000
    n0 = len(p14eh.HWCore.registry)
    t0 = time.time()
    # This tool reads every core's `g_ops` for its per-slot reach census, so
    # it declares FULL_TRACE for the run rather than reading the AGGREGATE
    # sample.  Phase 16K-K1: `g_ops` is bounded by default now.
    try:
        with P11.REC.full_trace(label="p16f_mirror.g_ops",
                                max_events=8 << 20):
            res = p14eh.run_workgroup_hw(
                prog, dw, label, (1, 1, 1), (256, 1, 1), fields,
                text_path=CO, wave_count=8, oob_sem="u32", alloc=16384,
                wgid=(0, 0, 0))
    finally:
        p14eh.HWCore = prev_hw
    secs = round(time.time() - t0, 1)

    cores = p14eh.HWCore.registry[n0:]
    # global windows (same convention as trace())
    text_hi = 0
    import p14d_kd as kd
    data, sections, _syms = kd.parse_elf(CO)
    for s in sections:
        if s.get("name") in (".text", ".text.1") and s.get("type") == 1:
            text_hi = max(text_hi, s["offset"] + s["size"])
    windows = [(KERNARG - 0x2000, KERNARG + 0x2000),
               (PACKET - 0x100, PACKET + 0x100),
               (0, text_hi + 0x100)]
    for k in range(16):
        windows.append((SLOT + k * STRIDE, SLOT + k * STRIDE + STRIDE))

    slots = {}
    oob_global = []
    oob_by_site = {}
    for w, core in enumerate(cores):
        for is_store, addr, nb, site in getattr(core, "g_ops", []):
            hit = None
            for k in range(16):
                if SLOT + k * STRIDE <= addr < SLOT + (k + 1) * STRIDE:
                    hit = k
                    break
            if hit is None:
                oob_global.append({"wave": w, "store": bool(is_store),
                                   "addr": addr, "nb": nb, "site": site})
                oob_by_site.setdefault(site, {"n": 0, "st": 0, "mn": None,
                                              "mx": 0})
                oob_by_site[site]["n"] += 1
                oob_by_site[site]["st"] += int(is_store)
                oob_by_site[site]["mn"] = addr if oob_by_site[site]["mn"] is None \
                    else min(oob_by_site[site]["mn"], addr)
                oob_by_site[site]["mx"] = max(oob_by_site[site]["mx"],
                                              addr + nb)
                continue
            off = addr - (SLOT + hit * STRIDE + GUARD)
            d = slots.setdefault(hit, {"ld": [], "st": []})
            d["st" if is_store else "ld"].append([off, off + nb])
    slot_sum = {}
    for k, d in sorted(slots.items()):
        row = {}
        for q in ("ld", "st"):
            v = d[q]
            if v:
                row[q] = {"count": len(v),
                          "min_off": min(x[0] for x in v),
                          "max_end": max(x[1] for x in v)}
            else:
                row[q] = {"count": 0}
        slot_sum[k] = row
    need = {"payload": {}, "max_reach": {}}
    for k, d in slot_sum.items():
        reach = max([x.get("max_end", 0) for x in d.values()] or [0])
        ld_end = max([x.get("max_end", 0) for x in [d["ld"]]] or [0])
        need["max_reach"][k] = reach
        need["payload"][k] = ld_end

    summary = {
        "label": label, "cell": "A-fields", "grid": [1, 1, 1],
        "block": [256, 1, 1], "wgid": [0, 0, 0],
        "fields": {k: v for k, v in cell.items() if k != "wgid"},
        "outcome": str(res["outcome"]), "ticks": res["ticks"],
        "epochs": len(res["barrier_epochs"]), "diverged": res["diverged"],
        "secs": secs,
        "per_wave": [{k: v for k, v in w.items() if k != "core"}
                     for w in res["per_wave"]],
        "slot_global": slot_sum,
        "oob_global_count": len(oob_global),
        "oob_global_stores": sum(1 for e in oob_global if e["store"]),
        "oob_global": oob_global[:8],
        "oob_by_site": {hex(k): v for k, v in sorted(oob_by_site.items())},
        "max_load_end_per_slot": {str(k): d["ld"]["max_end"]
                                  for k, d in slot_sum.items()
                                  if d["ld"].get("count")},
    }
    with open(os.path.join(OUT, "p16f_mirror_swin32f_A_g1.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, indent=1, default=str)
    print(json.dumps({k: summary[k] for k in
                      ("outcome", "ticks", "epochs", "diverged", "secs")}))
    print("per-wave:", [(p["wave"], p["state"], p["memviol"],
                         p["oob_read_zero"], p["oob_write_discard"])
                        for p in res["per_wave"]])
    print("global slots reached:", {k: v for k, v in slot_sum.items()})
    print("oob_global:", len(oob_global), oob_global[:3])
    ok = (res["outcome"][0] == "ALL_ENDED"
          and all(p["memviol"] == 0 for p in res["per_wave"])
          and all(p["oob_read_zero"] == 0 and p["oob_write_discard"] == 0
                  for p in res["per_wave"]))
    print("MIRROR RESULT:", "CLOSED" if ok else "NOT-CLOSED")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
