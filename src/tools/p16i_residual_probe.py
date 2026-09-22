#!/usr/bin/env python3
"""Phase 16I-P8 -- why do four accesses land on address 0?

The authentic-VarParams run of `k_swin_var<32,false>` ends cleanly
(`ALL_ENDED`, no fault) with exactly four out-of-region accesses at address
0x0:

    0x0AB8F0  global_load_dwordx3   base v[19:20]
    0x0AB8F8  global_load_dwordx3   base v[12:13]
    0x0C12A0  global_load_dword     base v[3:4]
    0x0C0CEC  global_store_dwordx4  base v[6:7]

This probe answers the question that decides whether they are a kernel
defect or an emulator artefact: **at the instant each fires, had the SGPRs
that formed its base address ever been written?**

Two facts make that question sharp:

  * `entry_plan` places `s[2:13]` in the kernel's UNDEFINED gap (the
    descriptor declares 14 user SGPRs but the emulator only knows how to
    name `s[0:1]` as the kernarg pointer).  `fill_entry` seeds those into
    `undef_s`, and `sget` / `spair` fail closed on them via `_chk_def`.
  * The disassembly never writes `s[12:13]` as a pair anywhere, and writes
    `s12` (single) for the first time at 0x0AC6A4.

Two earlier attempts to measure this were themselves defective and are
recorded here so the mistake is not repeated:

  1. `GateCore._gl_addr` reads its gate through the hard-coded class name
     (`GateCore.gate`), NOT through `self`.  Arming only the subclass left
     the real gate unarmed; every global access then raised on a None gate,
     every wave faulted at its first global access, and the run reported a
     clean `oob=0` PASS.  Both must be armed.
  2. `GateCore.wave_index` is a class attribute that `run_workgroup_hw`
     never sets per wave, so the gate labels EVERY wave's record as wave 0.
     The Phase-16H "wave 0, lane 0" observation therefore carries no
     information, and a class-level trace list interleaves all waves,
     which destroys any before/after argument drawn from trace order.

This probe therefore keeps a SEPARATE trace per core instance, and stamps
the gate's `wave_index` with the instance id so records are attributable.

Host-only.  No GPU.  Reads nothing frozen; only subclasses GateCore.

Usage:
  p16i_residual_probe.py [--tag swin32f] [--waves 8] [--trace-cap 200000]
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

import p16h_lib as L            # noqa: E402
import p16h_global_gate as G    # noqa: E402
import p16i_authentic_harness as AH  # noqa: E402

SITES = {0xAB8F0: "v[19:20]", 0xAB8F8: "v[12:13]",
         0xC12A0: "v[3:4]", 0xC0CEC: "v[6:7]"}
# SGPR indices that formed the base of each site, read off the disassembly.
SITE_SGPRS = {0xAB8F0: (12, 13), 0xAB8F8: (12, 13),
              0xC12A0: (3, 4), 0xC0CEC: (6, 7)}
# First textual writer of each base SGPR in the slice.
FIRST_WRITER = {"s12": 0xAC6A4, "s13": 0xAC6B4, "s3": None, "s4": None,
                "s6": None, "s7": None}


class ProbeCore(G.GateCore):
    """GateCore that keeps a per-instance trace and records site pre-state."""

    n_made = 0
    traces = None           # {wid: [[pc, addr, mnem, undef_cnt, undef_bits]]}
    hits = None             # {"0xADDR": {...}} aggregated
    step_cap = 0
    lanes_cap = 8

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        ProbeCore.n_made += 1
        self.wid = ProbeCore.n_made
        if ProbeCore.traces is not None:
            ProbeCore.traces[self.wid] = []
        # stamp the gate so its records are attributable to a wave
        G.GateCore.wave_index = self.wid

    def step(self):
        ins = self.prog[self.pc]
        addr = ins.get("address")
        tr = ProbeCore.traces.get(self.wid) if ProbeCore.traces else None
        if tr is not None and len(tr) < ProbeCore.step_cap:
            bits = 0
            for i in (2, 3, 4, 6, 7, 12, 13):
                if i in self.undef_s:
                    bits |= 1 << i
            tr.append([self.pc, addr, ins["mnemonic"], bits,
                       self.s[12], self.s[13]])
        if addr in SITES and ProbeCore.hits is not None:
            key = "0x%06X" % addr
            rec = ProbeCore.hits.setdefault(key, {
                "address": addr, "mnem": ins["mnemonic"],
                "operands": ins.get("operands"),
                "n_exec": 0, "waves": [], "exec_by_wave": {},
                "first": None})
            rec["n_exec"] += 1
            if self.wid not in rec["waves"]:
                rec["waves"].append(self.wid)
            rec["exec_by_wave"][str(self.wid)] = \
                rec["exec_by_wave"].get(str(self.wid), 0) + 1
            if rec["first"] is None:
                idx = len(tr) - 1 if tr is not None else None
                sgpr = SITE_SGPRS.get(addr, ())
                rec["first"] = {
                    "wid": self.wid, "wave_trace_index": idx,
                    "undef": {"s%d" % i: (i in self.undef_s) for i in sgpr},
                    "sgpr_value": {"s%d" % i: self.s[i] for i in sgpr},
                    "vbase": {k: "0x%016X" % v for k, v in
                              G._bases_of(self, ins["operands"].split(","),
                                          self.lanes - 1).items()},
                    "exec_l": self.exec_l,
                    "lane0_active": bool(self.exec_l & 1),
                    "active_lane_lo": (self.exec_l & -self.exec_l).bit_length() - 1
                    if self.exec_l else None,
                }
        return super().step()


def wave_first_index(trace, addr):
    for n, t in enumerate(trace):
        if t[1] == addr:
            return n
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="swin32f")
    ap.add_argument("--csv", default=os.path.join(
        ROOT, "phase16_authentic_decode_swin.csv"))
    ap.add_argument("--waves", type=int, default=8)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--round-cap", type=int, default=2000000)
    ap.add_argument("--trace-cap", type=int, default=200000)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    variant = AH.DISPLAY[a.tag]
    sym = AH.SYM[a.tag]
    vals, meta = AH.load_cell(a.csv, a.tag, None, None)
    grid, block = meta["grid"], meta["block"]

    co = os.path.join(ROOT, "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co")
    dis = os.path.join(ROOT,
                       "phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt")
    prog, _rows, _i = G.PE.slice_program(dis, sym)
    dw = G.P11.dw16(co, sym)
    fields = AH.authentic_fields(vals)

    elf = L.Elf(co)
    ks = G.kernarg_size(elf, sym + ".kd")
    canvas_size = grid[0] * grid[1] * 8192
    tensor_size = a.region_mib * 1024 * 1024

    ggate = G.GlobalGate()
    for lo, size, name in G.module_regions(elf):
        ggate.declare(lo, size, "module:" + name)
    if ks:
        ggate.declare(G.KERNARG, ks, "kernarg")
    ggate.declare(G.PACKET, 64, "aql_packet")
    for off, val in sorted(vals.items()):
        if val:
            ggate.declare(val, canvas_size if off == 0xA0 else tensor_size,
                          "authentic_0x%02X" % off)

    # See the module docstring: _gl_addr reads `GateCore.gate`, not
    # `self.gate`, so the base class must be armed too.
    G.GateCore.gate = ggate
    ProbeCore.gate = ggate
    ProbeCore.oob_sem = "u32"
    ProbeCore.alloc = 16384
    ProbeCore.lds_img = 0x10000
    ProbeCore.n_made = 0
    ProbeCore.traces = {}
    ProbeCore.hits = {}
    ProbeCore.step_cap = a.trace_cap

    prev = G.p14eh.HWCore
    G.p14eh.HWCore = ProbeCore
    try:
        orig = G.PE.text_mem_map
        G.PE.text_mem_map = G.module_mem_map
        try:
            res = G.p14eh.run_workgroup_hw(
                prog, dw, "p16i_probe_" + a.tag, grid, block, fields,
                text_path=co, wave_count=a.waves, oob_sem="u32", alloc=16384,
                wgid=(0, 0, 0), round_cap=a.round_cap)
        finally:
            G.PE.text_mem_map = orig
    finally:
        G.p14eh.HWCore = prev

    g = ggate.summary()
    traces = ProbeCore.traces
    hits = ProbeCore.hits

    per_wave = {}
    for wid, tr in sorted(traces.items()):
        d = {"steps": len(tr), "site_index": {}, "first_s12_write": None}
        for addr in sorted(SITES):
            d["site_index"]["0x%06X" % addr] = wave_first_index(tr, addr)
        d["first_s12_write"] = wave_first_index(tr, 0xAC6A4)
        d["first_s13_write"] = wave_first_index(tr, 0xAC6B4)
        per_wave[str(wid)] = d

    out = {
        "variant": variant, "kernel": sym, "cell": meta,
        "outcome": str(res.get("outcome")), "ticks": res.get("ticks"),
        "faults": [w.get("fault") for w in res.get("per_wave", [])
                   if w.get("fault")],
        "gate": g,
        "first_writer_addr": {k: v for k, v in FIRST_WRITER.items()},
        "per_wave": per_wave,
        "hits": hits,
        "sites": {"0x%06X" % k: v for k, v in sorted(SITES.items())},
    }
    out_path = a.out or os.path.join(
        ROOT, "phase16i_closure/out/p16i_residual_probe_%s.json" % a.tag)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print("outcome=%s ticks=%s faults=%s"
          % (out["outcome"], out["ticks"], out["faults"] or "none"))
    print("GATE %s  oob_r=%s oob_w=%s  n_r=%s n_w=%s"
          % (g["gate"], g["oob_global_reads"], g["oob_global_writes"],
             g["n_global_reads"], g["n_global_writes"]))
    print("cores created: %d" % ProbeCore.n_made)
    print()
    print("%-4s %-8s %-12s %-12s %-12s %-12s %-12s"
          % ("wave", "steps", "0xAB8F0", "0xAB8F8", "0xC12A0", "0xC0CEC",
             "s12-write"))
    for wid, d in sorted(per_wave.items(), key=lambda kv: int(kv[0])):
        si = d["site_index"]
        print("%-4s %-8d %-12s %-12s %-12s %-12s %-12s"
              % (wid, d["steps"], si["0x0AB8F0"], si["0x0AB8F8"],
                 si["0x0C12A0"], si["0x0C0CEC"], d["first_s12_write"]))
    print()
    for k, v in sorted(hits.items()):
        f = v["first"]
        print("%s  %s %s" % (k, v["mnem"], v["operands"]))
        print("    executed %d time(s) by waves %s  (per wave: %s)"
              % (v["n_exec"], v["waves"], v["exec_by_wave"]))
        print("    FIRST exec: wave %s at that wave's trace index %s"
              % (f["wid"], f["wave_trace_index"]))
        print("      base SGPR undef-before = %s   value = %s"
              % (f["undef"], f["sgpr_value"]))
        print("      vector base = %s" % f["vbase"])
        print("      exec_lo=0x%X  lane0_active=%s  lowest_active_lane=%s"
              % (f["exec_l"], f["lane0_active"], f["active_lane_lo"]))
    print("wrote " + out_path)


if __name__ == "__main__":
    main()
