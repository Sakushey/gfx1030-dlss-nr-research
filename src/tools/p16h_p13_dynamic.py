#!/usr/bin/env python3
"""Phase 16H — P13 (dynamic half): which fixed sites does the authentic
dispatch actually execute?

Host-only emulation.  No GPU, no HIP launch, no driver interaction.

The static P13 audit joins the module inventory, the authentic GTA
dispatch record and the 82-site PC-relative census.  This adds the
missing dimension: of the 82 sites Candidate F rewrites, how many lie on
a path the authentic `<32,false>` dispatch really walks?

Mechanism: the emulator fetches each instruction with `ins = prog[pc]`.
Wrapping `prog` in a list subclass that records integer subscripts yields
the exact executed-PC set without touching the emulator.

A site counts as EXERCISED if any executed instruction lies in
[site_pc, site_pc+16) -- the `s_getpc_b64` / `s_add_u32` / `s_addc_u32`
triple plus its consumer.

Emits out/p13_dynamic_exercise.json.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p16h_lib as L  # noqa: E402
import p16h_global_gate as G  # noqa: E402
import p16h_scratch_probe as SP  # noqa: E402
import p16h_p12_emulate as P12  # noqa: E402

import p16e_rec  # noqa: E402

SYM = G.SYM
CELL = "A"
WAVES = 8
F_CO = "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co"
F_DIS = ("phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt")
FIX_MANIFEST = os.path.join(L.ROOT, "phase16h_candidate_f",
                            "pcrel_fix_manifest.json")


class RecordingProg(list):
    """A program list that records every integer subscript it serves."""

    def __init__(self, items):
        super().__init__(items)
        self.fetched = set()

    def __getitem__(self, k):
        if isinstance(k, int) and k >= 0:
            self.fetched.add(k)
        return super().__getitem__(k)


def main():
    OUT = os.path.join(L.P16H, "out")
    os.makedirs(OUT, exist_ok=True)

    co = os.path.join(L.ROOT, F_CO)
    dis = os.path.join(L.ROOT, F_DIS)
    prog, _rows, _i = G.PE.slice_program(dis, SYM)
    dw = G.P11.dw16(co, SYM)
    c = p16e_rec.CELLS[CELL]
    fields = p16e_rec.fields_for(c)

    elf = L.Elf(co)
    kd = SYM + ".kd"
    ks = G.kernarg_size(elf, kd)
    psz = SP.private_segment_size(co, kd)

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

    rprog = RecordingProg(prog)
    prev = G.p14eh.HWCore
    G.p14eh.HWCore = P12.P12Core
    try:
        orig_tmm = G.PE.text_mem_map
        G.PE.text_mem_map = G.module_mem_map
        try:
            res = G.p14eh.run_workgroup_hw(
                rprog, dw, "p13dyn", c["grid"], (256, 1, 1), fields,
                text_path=co, wave_count=WAVES, oob_sem="u32",
                alloc=16384, wgid=c["wgid"])
        finally:
            G.PE.text_mem_map = orig_tmm
    finally:
        G.p14eh.HWCore = prev

    exec_addrs = set()
    for i in rprog.fetched:
        if 0 <= i < len(rprog):
            exec_addrs.add(rprog[i]["address"])

    print("=" * 80)
    print("P13 (dynamic) — fixed-site exercise by the authentic <32,false> run")
    print("=" * 80)
    print("  outcome=%s ticks=%d epochs=%d"
          % (res["outcome"], res["ticks"], len(res["barrier_epochs"])))
    print("  instructions fetched: %d distinct addresses of %d in program"
          % (len(exec_addrs), len(prog)))

    fix = json.load(open(FIX_MANIFEST))
    rows = fix["resolution"]

    by_kernel = {}
    n_ex = 0
    for r in rows:
        pc = int(r["new_cand_pc"], 16)
        hit = any(pc + d in exec_addrs for d in (0, 4, 8, 12, 16))
        r["exercised"] = hit
        if hit:
            n_ex += 1
        k = by_kernel.setdefault(r["symbol"], {"n": 0, "ex": 0,
                                               "targets": set()})
        k["n"] += 1
        k["ex"] += 1 if hit else 0
        k["targets"].add(r["label"])

    print("  of the 82 fixed sites, EXERCISED by this dispatch: %d" % n_ex)
    print("  not exercised: %d" % (len(rows) - n_ex))
    print()
    print("  %-54s %-6s %s" % ("kernel", "sites", "exercised"))
    for k, v in sorted(by_kernel.items(), key=lambda kv: (-kv[1]["n"],
                                                          kv[0])):
        print("  %-54s %-6d %d/%d" % (k[:54], v["n"], v["ex"], v["n"]))

    print()
    print("  --- the 3 swin_layer CALL sites ---")
    for r in rows:
        if r["label"] == "_Z10swin_layerR7SwinLDSPKhRK10BlobLayouti":
            print("     %-50s pc=%s exercised=%s"
                  % (r["symbol"][:50], r["new_cand_pc"], r["exercised"]))

    print()
    print("  --- the 79 g_e4m3_lut sites, by kernel ---")
    lut = [r for r in rows if r["label"] == "g_e4m3_lut"]
    print("     total %d ; exercised %d"
          % (len(lut), sum(1 for r in lut if r["exercised"])))

    out = {
        "outcome": str(res["outcome"]), "ticks": res["ticks"],
        "barrier_epochs": len(res["barrier_epochs"]),
        "n_instructions_fetched": len(exec_addrs),
        "n_sites": len(rows), "n_sites_exercised": n_ex,
        "n_sites_not_exercised": len(rows) - n_ex,
        "by_kernel": {k: {"n": v["n"], "exercised": v["ex"],
                          "targets": sorted(v["targets"])}
                      for k, v in by_kernel.items()},
        "sites": [{"symbol": r["symbol"], "label": r["label"],
                   "new_cand_pc": r["new_cand_pc"],
                   "new_target": r["new_target"],
                   "exercised": r["exercised"]} for r in rows],
    }
    json.dump(out, open(os.path.join(OUT, "p13_dynamic_exercise.json"), "w"),
              indent=1)
    print("\nwrote", os.path.join(OUT, "p13_dynamic_exercise.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
