#!/usr/bin/env python3
"""Phase 16H — P10: scratch / private-segment ABI closure.

Host-only emulation.  No GPU, no HIP launch.

THE QUESTION

`k_swin_var<32,false>` executes 22 `scratch_*` instructions.  Its kernel
descriptor declares `private_segment_fixed_size = 24`.  Is the private
segment the code actually addresses contained in those 24 bytes?

THE MODEL'S GAP

`p16e_rec.E16Core._scratch_xfer` computes

    ea = (v[vaddr_reg] + imm) & 0xFFFFFFFF

into a per-lane byte dict `self._scrt[lane]`.  There is no declared
region and no bound: a store at offset 4096 would be accepted silently,
exactly the defect P6 fixed on the global path.  This probe measures the
real address range so the bound can be stated as a fact rather than
assumed -- and so the P12 scratch model can be corrected on evidence.

WHAT IS MEASURED

Every scratch access, per wave and lane: the effective address, the
access width, the site PC and the mnemonic.  Reported:

  * min / max byte offset touched, across all lanes and waves;
  * the number of accesses whose [ea, ea+n) is NOT wholly inside
    [0, private_segment_fixed_size);
  * the distinct offset set, so the shape of the private object is
    visible.

The declared size is read from the kernel descriptor itself, never
hard-coded.
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p16h_lib as L  # noqa: E402
import p16h_global_gate as G  # noqa: E402

import p16e_rec  # noqa: E402

SYM = G.SYM
RE_VREG = p16e_rec.RE_VREG


class ScratchGate:
    """Declared private-segment region + hard bound accounting."""

    def __init__(self, size):
        self.size = size          # private_segment_fixed_size
        self.n_dispatch = 0       # scratch instructions issued
        self.n_dispatch_live = 0  # ... with at least one lane in EXEC
        self.by_disp = {}         # pc -> {n, live, mnems}
        self.n_ops = 0
        self.n_reads = 0
        self.n_writes = 0
        self.offsets = {}         # offset -> count
        self.oob = []             # accesses outside [0, size)
        self.by_site = {}         # pc -> {n, min, max, mnems, offs}
        self.by_lane = {}         # lane -> {min, max}

    def dispatch(self, store, site, mnem, live_lanes):
        """The instruction was issued; `live_lanes` had EXEC set."""
        self.n_dispatch += 1
        self.n_dispatch_live += 1 if live_lanes else 0
        d = self.by_disp.setdefault(site, {"n": 0, "live": 0, "mnems": set()})
        d["n"] += 1
        d["live"] += 1 if live_lanes else 0
        d["mnems"].add(mnem)

    def note(self, store, lane, ea, nbytes, site, mnem):
        self.n_ops += 1
        self.n_reads += 0 if store else 1
        self.n_writes += 1 if store else 0
        self.offsets[ea] = self.offsets.get(ea, 0) + 1
        bl = self.by_lane.setdefault(lane, {"min": ea, "max": ea + nbytes})
        bl["min"] = min(bl["min"], ea)
        bl["max"] = max(bl["max"], ea + nbytes)
        e = self.by_site.setdefault(site, {"n": 0, "min": ea,
                                           "max": ea + nbytes,
                                           "mnems": set(), "offs": set()})
        e["n"] += 1
        e["min"] = min(e["min"], ea)
        e["max"] = max(e["max"], ea + nbytes)
        e["mnems"].add(mnem)
        e["offs"].add(ea)
        if ea + nbytes > self.size:
            self.oob.append({"store": bool(store), "lane": lane, "ea": ea,
                             "n": nbytes, "site": site, "mnem": mnem,
                             "hi": ea + nbytes})

    @property
    def ok(self):
        return not self.oob

    def summary(self):
        offs = sorted(self.offsets)
        return {
            "declared_private_segment_fixed_size": self.size,
            "n_scratch_dispatch": self.n_dispatch,
            "n_scratch_dispatch_live": self.n_dispatch_live,
            "n_scratch_ops": self.n_ops,
            "n_scratch_reads": self.n_reads,
            "n_scratch_writes": self.n_writes,
            "offset_min": (offs[0] if offs else None),
            "offset_max": (offs[-1] if offs else None),
            "distinct_offsets": offs,
            "n_distinct_offsets": len(offs),
            "oob_scratch_accesses": len(self.oob),
            "gate": "PASS" if self.ok else "FAIL",
            "oob_samples": [
                {"kind": "write" if r["store"] else "read", "lane": r["lane"],
                 "ea": r["ea"], "n": r["n"], "hi": r["hi"],
                 "site": ("0x%08X" % r["site"]) if r["site"] else None,
                 "mnem": r["mnem"]} for r in self.oob[:20]],
            "by_site": {
                "0x%08X" % (k or 0): {"n": v["n"], "off_min": v["min"],
                                      "off_max_excl": v["max"],
                                      "mnems": sorted(v["mnems"]),
                                      "offsets": sorted(v["offs"])}
                for k, v in sorted(self.by_site.items())},
            "by_dispatch": {
                "0x%08X" % (k or 0): {"n": v["n"], "live": v["live"],
                                      "mnems": sorted(v["mnems"])}
                for k, v in sorted(self.by_disp.items())},
            "by_lane": {str(k): v for k, v in sorted(self.by_lane.items())},
        }


class ScrtGateCore(G.GateCore):
    """GateCore + a hard bound check on every scratch access.

    The vaddr register and the access width are derived with the parent's
    own operand grammar (stores print `vaddr|off, vdata, saddr`; loads
    print `vdst, vaddr|off, saddr`), so the measurement describes the
    instruction the model actually executed -- not a re-parse.
    """

    scrt_gate = None

    def _scratch_xfer(self, ins, store, nbytes=None):
        g = ScrtGateCore.scrt_gate
        ops = [o.strip() for o in (ins.get("operands") or "").split(",")]
        if g is not None and ops:
            lo = hi = None
            vaddr_reg = None
            if store:
                for tok in ops[1:]:
                    mt = RE_VREG.search(tok)
                    if mt:
                        lo, hi = ((int(mt.group(1)), int(mt.group(2)))
                                  if mt.group(1) is not None
                                  else (int(mt.group(3)), int(mt.group(3))))
                        break
                mt = RE_VREG.search(ops[0])
                if mt:
                    vaddr_reg = (int(mt.group(1)) if mt.group(1) is not None
                                 else int(mt.group(3)))
            else:
                mt = RE_VREG.search(ops[0])
                if mt:
                    lo, hi = ((int(mt.group(1)), int(mt.group(2)))
                              if mt.group(1) is not None
                              else (int(mt.group(3)), int(mt.group(3))))
                for tok in ops[1:]:
                    mt = RE_VREG.search(tok)
                    if mt:
                        vaddr_reg = (int(mt.group(1))
                                     if mt.group(1) is not None
                                     else int(mt.group(3)))
                        break
            if lo is not None:
                m = p16e_rec.RE_OFF.search(ins.get("operands") or "")
                imm = int(m.group(1)) if m else 0
                nbytes = (hi - lo + 1) * 4          # PRE-16N: span rule
                mnem = ins.get("mnemonic") or ""
                site = ins.get("address")
                live = [ln for ln in range(self.lanes)
                        if (self.exec_l >> ln) & 1]
                g.dispatch(store, site, mnem, live)
                for lane in live:
                    base = (self.v[lane][vaddr_reg] & 0xFFFFFFFF
                            if vaddr_reg is not None else 0)
                    ea = (base + imm) & 0xFFFFFFFF
                    g.note(store, lane, ea, nbytes, site, mnem)
        super()._scratch_xfer(ins, store, nbytes)


def _kd_dword(path, kd_name, idx):
    import struct as _s
    e = L.Elf(path)
    for s in e.symbols:
        if s["name"] == kd_name and s["size"] == 64:
            b = e.read_va(s["value"], 64)
            if b:
                return _s.unpack_from("<I", b, 4 * idx)[0]
    return None


def private_segment_size(path, kd_name):
    """`private_segment_fixed_size` = kernel descriptor dword 1 (byte 4).

    Layout: dw0 group_segment_fixed_size, dw1 private_segment_fixed_size,
    dw2 kernarg_size, dw3 reserved.
    """
    return _kd_dword(path, kd_name, 1)


def group_segment_size(path, kd_name):
    """`group_segment_fixed_size` = kernel descriptor dword 0 (byte 0).

    This is the kernel's OWN declaration of how much LDS it uses, and it is
    the bound every LDS range check must be made against.  It is not a
    constant: measured on Candidate F it is 16,384 for four of the five SWIN
    variants and **19,200** for `<256,false>`.  A hard-coded 16,384 scores
    32,768 legitimate `<256,false>` accesses as violations.

    Kept separate from the *logical ring* normalisation (`& 0x3FFF` on the
    legacy value path), which is a datapath-mask question, not an
    allocation-size question.
    """
    return _kd_dword(path, kd_name, 0)


def run_case(co_path, dis_path, tag, cell="A", wave_count=8):
    co = os.path.join(L.ROOT, co_path)
    dis = os.path.join(L.ROOT, dis_path)
    prog, _rows, _i = G.PE.slice_program(dis, SYM)
    dw = G.P11.dw16(co, SYM)
    c = p16e_rec.CELLS[cell]
    fields = p16e_rec.fields_for(c)

    elf = L.Elf(co)
    kd_name = SYM + ".kd"
    psz = private_segment_size(co, kd_name)
    ks = G.kernarg_size(elf, kd_name)

    ggate = G.GlobalGate()
    for lo, size, name in G.module_regions(elf):
        ggate.declare(lo, size, "module:" + name)
    if ks:
        ggate.declare(G.KERNARG, ks, "kernarg")
    ggate.declare(G.PACKET, 64, "aql_packet")
    for _o, k in ((0x00, 0), (0x08, 1), (0x10, 2), (0x30, 3), (0x38, 4),
                  (0x48, 5), (0x78, 6), (0x80, 7), (0xA0, 8)):
        ggate.declare(G.SLOT + k * G.STRIDE, G.STRIDE, "harness_slot_%d" % k)

    sgate = ScratchGate(psz if psz is not None else 0)

    # `GateCore._gl_addr` resolves `GateCore.gate` / `GateCore.wave_index`
    # through p16h_global_gate's module globals -- i.e. against the BASE
    # class, not the subclass.  Both must be bound on `G.GateCore` or every
    # global access raises and the wave dies at its first load.
    G.GateCore.gate = ggate
    G.GateCore.wave_index = 0
    G.GateCore.oob_sem = "u32"
    G.GateCore.alloc = 16384
    G.GateCore.lds_img = 0x10000
    ScrtGateCore.gate = ggate
    ScrtGateCore.scrt_gate = sgate
    ScrtGateCore.wave_index = 0
    ScrtGateCore.oob_sem = "u32"
    ScrtGateCore.alloc = 16384
    ScrtGateCore.lds_img = 0x10000
    prev = G.p14eh.HWCore
    G.p14eh.HWCore = ScrtGateCore
    try:
        orig_tmm = G.PE.text_mem_map
        G.PE.text_mem_map = G.module_mem_map
        try:
            res = G.p14eh.run_workgroup_hw(
                prog, dw, "p10_" + tag, c["grid"], (256, 1, 1), fields,
                text_path=co, wave_count=wave_count, oob_sem="u32",
                alloc=16384, wgid=c["wgid"])
        finally:
            G.PE.text_mem_map = orig_tmm
    finally:
        G.p14eh.HWCore = prev

    return {"tag": tag, "co": co_path,
            "outcome": str(res["outcome"]), "ticks": res["ticks"],
            "epochs": len(res["barrier_epochs"]),
            "scratch": sgate.summary()}


def main():
    OUT = os.path.join(L.P16H, "out")
    os.makedirs(OUT, exist_ok=True)

    F = ("phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co",
         "phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt")
    E = ("phase16e_candidate_e/gfx1030_dlssnr_candidate_e.co",
         "phase16e_candidate_e/disasm/candidate_e_gfx1030_disasm.txt")

    print("=" * 74)
    print("P10 — scratch / private-segment bound probe (host-only)")
    print("=" * 74)

    res = {}
    for tag, (co, dis) in (("candidate_F", F), ("candidate_E", E)):
        r = run_case(co, dis, tag)
        res[tag] = r
        s = r["scratch"]
        print("\n--- %s ---" % tag)
        print("  outcome=%s ticks=%d epochs=%d"
              % (r["outcome"], r["ticks"], r["epochs"]))
        print("  declared private_segment_fixed_size = %s"
              % s["declared_private_segment_fixed_size"])
        print("  scratch issued=%d (with a live lane: %d)  lane-accesses=%d "
              "(r=%d w=%d)"
              % (s["n_scratch_dispatch"], s["n_scratch_dispatch_live"],
                 s["n_scratch_ops"], s["n_scratch_reads"],
                 s["n_scratch_writes"]))
        print("  distinct scratch PCs issued: %d of the module's 22"
              % len(s["by_dispatch"]))
        print("  byte offset range touched: [%s, %s)  distinct offsets=%d"
              % (s["offset_min"], s["offset_max"], s["n_distinct_offsets"]))
        print("  distinct offsets: %s" % s["distinct_offsets"][:40])
        print("  accesses outside the declared segment: %d  -> SCRATCH GATE %s"
              % (s["oob_scratch_accesses"], s["gate"]))
        if s["oob_samples"]:
            for x in s["oob_samples"][:8]:
                print("     %s lane=%d ea=%d n=%d hi=%d site=%s %s"
                      % (x["kind"], x["lane"], x["ea"], x["n"], x["hi"],
                         x["site"], x["mnem"]))
        if s["by_site"]:
            print("  per-site offsets:")
            for k, v in list(s["by_site"].items())[:24]:
                print("     site %s  n=%-5d offs=%s  %s"
                      % (k, v["n"], v["offsets"], ",".join(v["mnems"])))

    json.dump(res, open(os.path.join(OUT, "p10_scratch.json"), "w"), indent=1)
    print("\nwrote", os.path.join(OUT, "p10_scratch.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
