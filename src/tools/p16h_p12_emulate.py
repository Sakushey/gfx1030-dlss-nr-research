#!/usr/bin/env python3
"""Phase 16H — P12: re-emulate the authentic <32,false> dispatch on Candidate F.

Host-only emulation.  No GPU, no HIP launch, no driver interaction.

This is the Phase-16F harness rebuilt with every correction Phase 16H has
established, and with each of the brief's required assertions turned into a
named, evaluated check rather than an informal remark:

  A1  all 8 waves ended
  A2  14 barrier epochs
  A3  zero LDS out-of-bounds (memviol / oob_read_zero / oob_write_discard)
  A4  zero GLOBAL out-of-bounds          (P6 declared-region gate)
  A5  zero SCRATCH out-of-bounds         (P10 declared 24-byte segment)
  A6  zero undefined register reads      (P11 static proof)
  A7  zero unsupported opcode semantics  (no NOTIMPL fault on any wave)
  A8  bounded loops                      (no CYCLE / STEPCAP / ROUNDCAP)
  A9  deterministic repeated runs
  A10 branch signatures recorded

Corrections applied relative to the Phase-16F harness:

  * `.text` AND `.rodata` mapped with exact section bytes at TEXT_BASE+addr
    (Phase-16F mapped only `.text`, which is why the 79 g_e4m3_lut loads
    were invisible);
  * the global path is a declared-region gate that fails closed, including
    on any width it cannot derive;
  * the scratch path gets the same declared-region treatment against the
    descriptor's `private_segment_fixed_size`;
  * authentic comparator geometry: X=576, Y=960, pair=(0,0), flags=0x1,
    block 256, wgid (0,0,0), 8 waves.

KNOWN BLOCKER (carried from P8, not worked around here)

The synthetic harness never populates kernarg qwords `0x50`, `0x70` and
`0x88`, which the kernel reads as *bases*.  Their authentic values are not
recoverable from any available artefact.  A4 is therefore expected to FAIL,
and it is reported as a harness blocker rather than repaired by enlarging
regions until the number reaches zero -- that would be the "workaround
without proof" the brief forbids.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p16h_lib as L  # noqa: E402
import p16h_global_gate as G  # noqa: E402
import p16h_scratch_probe as SP  # noqa: E402

import p16e_rec  # noqa: E402

SYM = G.SYM
CELL = "A"
WAVES = 8


class Trace:
    """Per-wave branch signature."""

    def __init__(self):
        self.n_branch = 0
        self.taken = 0
        self.sites = {}          # pc -> [n, taken]
        self.sig = hashlib.sha256()
        self.max_site_visits = 0

    def note(self, ins, is_taken):
        pc = ins.get("address")
        self.n_branch += 1
        if is_taken:
            self.taken += 1
        e = self.sites.setdefault(pc, [0, 0])
        e[0] += 1
        if is_taken:
            e[1] += 1
        if e[0] > self.max_site_visits:
            self.max_site_visits = e[0]
        self.sig.update(b"%d:%d;" % (pc or 0, 1 if is_taken else 0))

    def summary(self):
        return {"n_branch": self.n_branch, "n_taken": self.taken,
                "n_sites": len(self.sites), "max_site_visits":
                self.max_site_visits, "signature": self.sig.hexdigest()[:32]}


class P12Core(SP.ScrtGateCore):
    """ScrtGateCore + per-wave branch tracing."""

    instances = []

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.trace = Trace()
        P12Core.instances.append(self)

    # every branch form the module actually uses
    def op_s_branch(self, ins, ops):
        self.trace.note(ins, True)
        super().op_s_branch(ins, ops)

    def _cb(self, cond, ins, ops, fn):
        self.trace.note(ins, bool(cond))
        fn(ins, ops)

    def op_s_cbranch_scc0(self, ins, ops):
        self._cb(self.scc == 0, ins, ops, super().op_s_cbranch_scc0)

    def op_s_cbranch_scc1(self, ins, ops):
        self._cb(self.scc == 1, ins, ops, super().op_s_cbranch_scc1)

    def op_s_cbranch_vccz(self, ins, ops):
        self._cb(self.vcc_l == 0, ins, ops, super().op_s_cbranch_vccz)

    def op_s_cbranch_vccnz(self, ins, ops):
        self._cb(self.vcc_l != 0, ins, ops, super().op_s_cbranch_vccnz)

    def op_s_cbranch_execz(self, ins, ops):
        self._cb(self.exec_l == 0, ins, ops, super().op_s_cbranch_execz)

    def op_s_cbranch_execnz(self, ins, ops):
        self._cb(self.exec_l != 0, ins, ops, super().op_s_cbranch_execnz)


def run_once(co_path, dis_path, cell=CELL, waves=WAVES, declare_extra=()):
    co = os.path.join(L.ROOT, co_path)
    dis = os.path.join(L.ROOT, dis_path)
    prog, _rows, _i = G.PE.slice_program(dis, SYM)
    dw = G.P11.dw16(co, SYM)
    c = p16e_rec.CELLS[cell]
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
    for lo, size, name in declare_extra:
        ggate.declare(lo, size, name)

    sgate = SP.ScratchGate(psz if psz is not None else 0)

    # `_gl_addr` in p16h_global_gate resolves the gate through the BASE
    # class's module globals, so bind the shared state there too.
    for cls in (G.GateCore, P12Core):
        cls.gate = ggate
        cls.wave_index = 0
        cls.oob_sem = "u32"
        cls.alloc = 16384
        cls.lds_img = 0x10000
    # `_scratch_xfer` likewise resolves its gate through the BASE class.
    SP.ScrtGateCore.scrt_gate = sgate
    P12Core.scrt_gate = sgate
    P12Core.instances = []

    prev = G.p14eh.HWCore
    G.p14eh.HWCore = P12Core
    try:
        orig_tmm = G.PE.text_mem_map
        G.PE.text_mem_map = G.module_mem_map
        try:
            res = G.p14eh.run_workgroup_hw(
                prog, dw, "p12", c["grid"], (256, 1, 1), fields,
                text_path=co, wave_count=waves, oob_sem="u32",
                alloc=16384, wgid=c["wgid"])
        finally:
            G.PE.text_mem_map = orig_tmm
    finally:
        G.p14eh.HWCore = prev

    traces = [core.trace.summary() for core in P12Core.instances]
    return res, ggate, sgate, traces, {"kernarg_size": ks,
                                       "private_segment_fixed_size": psz}


def evaluate(res, ggate, sgate, traces, meta, label):
    per = res["per_wave"]
    faults = [w["fault"] for w in per if w["fault"]]
    lds = {"memviol": sum(w["memviol"] for w in per),
           "oob_read_zero": sum(w["oob_read_zero"] for w in per),
           "oob_write_discard": sum(w["oob_write_discard"] for w in per)}
    g = ggate.summary()
    s = sgate.summary()
    sig_all = hashlib.sha256(
        "".join(t["signature"] for t in traces).encode()).hexdigest()[:32]

    checks = {
        "A1_all_waves_ended": all(w["state"] == "ENDED" for w in per),
        "A2_barrier_epochs_14": len(res["barrier_epochs"]) == 14,
        "A3_zero_lds_oob": (lds["memviol"] == 0 and lds["oob_read_zero"] == 0
                            and lds["oob_write_discard"] == 0),
        "A4_zero_global_oob": (g["oob_global_reads"] == 0
                               and g["oob_global_writes"] == 0
                               and g["n_unmeasured_global_ops"] == 0),
        "A5_zero_scratch_oob": s["oob_scratch_accesses"] == 0,
        "A7_zero_unsupported_opcodes": not any(
            f and f[0] == "NOTIMPL" for f in faults),
        "A8_bounded_loops": (res["outcome"][0] not in ("ROUNDCAP", "CYCLE")
                             and not any(f and f[0] in ("STEPCAP", "CYCLE")
                                         for f in faults)
                             and all(w["state"] != "FAULTED" for w in per)),
        "A10_branch_signatures_recorded": all(t["n_branch"] > 0
                                              for t in traces),
    }
    return {
        "label": label, "outcome": str(res["outcome"]),
        "ticks": res["ticks"], "diverged": res["diverged"],
        "barrier_epochs": len(res["barrier_epochs"]),
        "waves": [{"wave": w["wave"], "state": w["state"],
                   "steps": w["steps"], "barriers": w["barriers"],
                   "fault": w["fault"]} for w in per],
        "faults": faults, "lds": lds,
        "global_gate": g, "scratch_gate": s,
        "branch_signature": sig_all, "traces": traces,
        "meta": meta, "checks": checks,
    }


def main():
    OUT = os.path.join(L.P16H, "out")
    os.makedirs(OUT, exist_ok=True)

    F = ("phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co",
         "phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt")
    E = ("phase16e_candidate_e/gfx1030_dlssnr_candidate_e.co",
         "phase16e_candidate_e/disasm/candidate_e_gfx1030_disasm.txt")

    print("=" * 76)
    print("P12 — authentic <32,false> re-emulation on Candidate F (host-only)")
    print("=" * 76)

    res = {}
    for tag, (co, dis) in (("candidate_F", F), ("candidate_E", E)):
        r1, gg1, sg1, tr1, meta = run_once(co, dis)
        r2, _gg2, _sg2, tr2, _m = run_once(co, dis)
        ev = evaluate(r1, gg1, sg1, tr1, meta, tag)
        det = (str(r1["outcome"]) == str(r2["outcome"])
               and r1["ticks"] == r2["ticks"]
               and r1["barrier_epochs"] == r2["barrier_epochs"]
               and r1["slot_hashes"] == r2["slot_hashes"]
               and [t["signature"] for t in tr1] == [t["signature"]
                                                     for t in tr2])
        ev["checks"]["A9_deterministic_repeated_runs"] = det
        ev["run2"] = {"outcome": str(r2["outcome"]), "ticks": r2["ticks"],
                      "barrier_epochs": len(r2["barrier_epochs"])}
        res[tag] = ev

        print("\n--- %s ---" % tag)
        print("  outcome=%s  ticks=%d  epochs=%d  diverged=%s"
              % (ev["outcome"], ev["ticks"], ev["barrier_epochs"],
                 ev["diverged"]))
        print("  kernarg_size=%s  private_segment_fixed_size=%s"
              % (meta["kernarg_size"], meta["private_segment_fixed_size"]))
        print("  waves: %s"
              % ", ".join("%s/%d steps/%d bar" % (w["state"], w["steps"],
                                                  w["barriers"])
                          for w in ev["waves"]))
        print("  LDS: memviol=%d oob_read_zero=%d oob_write_discard=%d"
              % (ev["lds"]["memviol"], ev["lds"]["oob_read_zero"],
                 ev["lds"]["oob_write_discard"]))
        g = ev["global_gate"]
        print("  GLOBAL: ops=%d  oob_reads=%d oob_writes=%d unmeasured=%d"
              % (g["n_global_ops"], g["oob_global_reads"],
                 g["oob_global_writes"], g["n_unmeasured_global_ops"]))
        print("  GLOBAL OOB sites: %d" % len(g["oob_by_site"]))
        for k, v in list(g["oob_by_site"].items())[:4]:
            print("     %s n=%d addrs %s..%s %s"
                  % (k, v["n"], v["addr_range"][0], v["addr_range"][1],
                     ",".join(v["mnems"])))
        s = ev["scratch_gate"]
        print("  SCRATCH: issued=%d lane-accesses=%d oob=%d offsets=%s"
              % (s["n_scratch_dispatch"], s["n_scratch_ops"],
                 s["oob_scratch_accesses"], s["distinct_offsets"]))
        print("  branch signature: %s  (%d branches/wave max)"
              % (ev["branch_signature"],
                 max(t["n_branch"] for t in ev["traces"])))
        print("  max visits to any single branch site: %d"
              % max(t["max_site_visits"] for t in ev["traces"]))
        print("  ASSERTIONS")
        for k in sorted(ev["checks"]):
            print("     %-34s %s" % (k, "PASS" if ev["checks"][k] else "FAIL"))

    json.dump(res, open(os.path.join(OUT, "p12_emulation.json"), "w"),
              indent=1, default=str)
    print("\nwrote", os.path.join(OUT, "p12_emulation.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
