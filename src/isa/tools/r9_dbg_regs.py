#!/usr/bin/env python3
"""Phase 16R / R9 -- debug aid: dump the VGPR file across one J3 division site.

NOT part of the verifier.  It exists because the recorded operand values at
the executed `v_div_fixup_f32` site did not match the arithmetic the
disassembly implies, and a disagreement between a measurement and a
derivation must be resolved by measuring, not by picking the one that reads
better.  HOST ONLY.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ISA = os.path.dirname(HERE)                     # phase16r/isa
ROOT = os.path.dirname(os.path.dirname(ISA))    # project root
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "phase16p", "j3_v2", "tools"))

import p16p_trace as T          # noqa: E402
import p16p_j3cfg as J3         # noqa: E402

WATCH_FROM = 0x0B5150
WATCH_TO = 0x0B51D0
WANT_WAVE = 0
WANT_LANE = 1


def main():
    import p16h_global_gate as G
    vals, meta = J3.load_authentic_cell()
    tr_art = json.load(open(os.path.join(
        ROOT, "phase16p", "j3_v2", "out", "J3_TRACE_SUMMARY.json"),
        encoding="utf-8"))
    tensor = canvas = None
    for r in tr_art["regions"]:
        if r["name"] == "slot_0xA0":
            canvas = r["size"]
        elif tensor is None:
            tensor = r["size"]
    regions = J3.j3_regions(vals, tensor_bytes=tensor, canvas_bytes=canvas)

    core_cls = G.GateCore
    counter = {"n": 0, "cur": -1}
    old_init = core_cls.__init__

    def init(self, *a, **k):
        old_init(self, *a, **k)
        self._r9_wave = counter["n"]
        counter["n"] += 1
    core_cls.__init__ = init

    rows = []
    old_step = core_cls.step

    def step(self):
        ins = self.prog[self.pc]
        ad = ins.get("address")
        watch = (ad is not None and WATCH_FROM <= ad <= WATCH_TO
                 and getattr(self, "_r9_wave", -1) == WANT_WAVE)
        if watch:
            before = list(self.v[WANT_LANE])
            vcc_before = self.vcc_l
        r = old_step(self)
        if watch:
            after = list(self.v[WANT_LANE])
            delta = ["v%d:%08X->%08X" % (i, before[i], after[i])
                     for i in range(len(before)) if before[i] != after[i]]
            rows.append({
                "pc": "0x%06X" % ad,
                "mnem": ins["mnemonic"],
                "ops": ins["operands"],
                "exec_lane1": (self.exec_l >> WANT_LANE) & 1,
                "v": ["0x%08X" % x for x in after],
                "vcc_lo": "0x%08X" % self.vcc_l,
                "vcc_before": "0x%08X" % vcc_before,
                "delta": delta,
            })
        return r
    core_cls.step = step

    res, ggate, hw = T.run_j3(vals, regions, wave_count=J3.J3_WAVES,
                              round_cap=2_000_000)
    print("outcome=%s ticks=%s rows=%d" % (res["outcome"], res["ticks"],
                                           len(rows)))
    for r in rows[:40]:
        print("%s %-24s %-34s e1=%d vcc=%s"
              % (r["pc"], r["mnem"], r["ops"], r["exec_lane1"], r["vcc_lo"]))
        print("      changed: %s" % (" ".join(r["delta"]) or "(none)"))
    with open(os.path.join(HERE, os.pardir, "logs", "r9_dbg_regs.json"),
              "w", encoding="utf-8") as f:
        json.dump({"rows": rows[:200]}, f, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
