#!/usr/bin/env python3
"""Phase 16O Track A / A4 -- full def-use provenance of a bad global address.

WHY THIS EXISTS

Phase 16N measured swin32f moving from 13,590 ticks / 0 global OOB to
10,553 ticks / 4,352 global OOB writes (every write).  Phase 16N's runtime
bisect failed to attribute it.  Reasoning backwards from the final address
was explicitly forbidden by the 16O brief, so this probe walks FORWARD from
the definition of the address register instead.

WHAT IT DOES

It re-runs one cell with the production core, plus a `step()` wrapper that
maintains a last-writer map for every SGPR and VGPR.  The FIRST out-of-bounds
global access at a chosen site is captured at access time, and the def-use
chain of every register token in the offending instruction -- and of the
scalar base registers -- is walked back through that map.

The map records, per definition: the site, the mnemonic, the raw operand
text, the operand values for the active lanes, and the value written.  A
chain therefore ends either at an entry with no recorded producer (an
entry-state register) or at a literal.

Host-only.  No GPU.  Nothing armed.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
PHASE16O = os.path.join(ROOT, "phase16o_final")

K3 = os.path.join(ROOT, "phase16k_pretest", "k3_arena")
sys.path.insert(0, K3)
sys.path.insert(0, os.path.join(ROOT, "phase16j_pre_gta", "tools"))
for p in ("phase16i_closure/tools", "phase16h_pcrel_fix/tools",
          "phase16e_candidate_e/tools", "phase14e_static/tools",
          "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
          "phase14d11_static", "phase14d_static/tools", "phase8_static/tools",
          "phase14d8_static/tools", HERE):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)

import p16j_execcache as EC              # noqa: E402
import p16h_global_gate as G             # noqa: E402
import p16i_authentic_harness as AH      # noqa: E402
import p16j_input as IN                  # noqa: E402
import p16j_scratch_isa as SI            # noqa: E402
import p16e_rec as E16                   # noqa: E402
import p16i_isa as ISA                   # noqa: E402
import p16i_lds_descriptor as LD         # noqa: E402
import p16i_scratch_close as SC          # noqa: E402

CAND_CO = os.path.join(ROOT,
                       "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co")
CSV = os.path.join(ROOT, "phase16_authentic_decode_swin.csv")

_SV = re.compile(r"^s(\d+)$")
_VV = re.compile(r"^v(\d+)$")
_SR = re.compile(r"^s\[(\d+):(\d+)\]$")
_VR = re.compile(r"^v\[(\d+):(\d+)\]$")


def _tokens(operands_raw):
    return [o.strip() for o in operands_raw.split(",")] if operands_raw else []


class DefUseMixin:
    """Last-writer tracking over SGPRs and VGPRs, recorded per instruction."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        # (space, index) -> definition record.  space is "s" or "v".
        self.du_lw = {}
        # every write to the registers a caller asked to watch, in order
        self.du_watch = set()
        self.du_hist = []
        self.du_steps = 0
        self.du_capture = None

    # ---- helpers -----------------------------------------------------
    def _rec(self, space, idx, ins, ops, lane):
        tok = ("s%d" if space == "s" else "v%d") % idx
        val = self.s[idx] if space == "s" else self.v[lane][idx]
        return {"space": space, "reg": tok, "site": ins.get("address"),
                "mnemonic": ins.get("mnemonic"),
                "operands": ins.get("operands"),
                "ops": ops,
                "raw": ins.get("text"),
                "written": "0x%08X" % (val & 0xFFFFFFFF),
                "lane": lane, "step": self.du_steps,
                "wave": getattr(type(self), "wave_index", None)}

    def _defs_of(self, ins, ops, lane):
        """Which registers does this instruction write?"""
        out = []
        m = ins.get("mnemonic") or ""
        if not ops:
            return out
        dst = ops[0]
        mm = _SV.match(dst)
        if mm:
            out.append(("s", int(mm.group(1))))
        mr = _SR.match(dst)
        if mr:
            a, b = int(mr.group(1)), int(mr.group(2))
            for i in range(min(a, b), max(a, b) + 1):
                out.append(("s", i))
        mv = _VV.match(dst)
        if mv:
            out.append(("v", int(mv.group(1))))
        vr = _VR.match(dst)
        if vr:
            a, b = int(vr.group(1)), int(vr.group(2))
            for i in range(min(a, b), max(a, b) + 1):
                out.append(("v", i))
        # an `_e64` v_ op can carry a scalar destination in ops[1]
        if len(ops) > 1 and m.startswith("v_") and _SV.match(ops[1]):
            out.append(("s", int(_SV.match(ops[1]).group(1))))
        # saveexec/cselect style: s_and_saveexec writes both
        if m.endswith("_saveexec_b32") and len(ops) > 1:
            m2 = _SV.match(ops[1])
            if m2:
                out.append(("s", int(m2.group(1))))
        return out

    def step(self):
        ins = self.prog[self.pc] if 0 <= self.pc < len(self.prog) else None
        self.du_steps += 1
        super().step()
        if ins is None:
            return
        ops = _tokens(ins.get("operands"))
        for space, idx in self._defs_of(ins, ops, 0):
            for lane in self._lane_list(space):
                self.du_lw[(space, idx)] = self._rec(space, idx, ins, ops, lane)
            if (space, idx) in self.du_watch or ("*",) in self.du_watch:
                self.du_hist.append(self._rec(space, idx, ins, ops, 0))

    def _lane_list(self, space):
        if space == "s":
            return [0]
        ex = self.exec_l
        return [ln for ln in range(self.lanes) if (ex >> ln) & 1]

    # ---- capture ------------------------------------------------------
    def capture(self, ins, ops, lane, addr):
        """Record the access-time state and the chain for every operand."""
        snap = {
            "site": "0x%08X" % (ins.get("address") or 0),
            "mnemonic": ins.get("mnemonic"),
            "operands": ins.get("operands"),
            "raw": ins.get("text"),
            "lane": lane, "addr": "0x%016X" % addr,
            "wave": getattr(type(self), "wave_index", None),
            "step": self.du_steps,
            "exec": "0x%08X" % self.exec_l,
            "scc": self.scc, "vcc": "0x%08X" % self.vcc_l,
            "v": {("v%d" % i): "0x%08X" % self.v[lane][i]
                  for i in set(self._touched(ops, "v"))},
            "s": {("s%d" % i): "0x%08X" % self.s[i]
                  for i in set(self._touched(ops, "s"))},
            "chains": {},
        }
        for tok in ops:
            snap["chains"][tok] = self.walk(tok, lane, 0)
        self.du_capture = snap

    @staticmethod
    def _touched(ops, space):
        out = []
        for tok in ops:
            t = tok.split()[0]
            m = _SV.match(t)
            if space == "s" and m:
                out.append(int(m.group(1)))
            m = _VV.match(t)
            if space == "v" and m:
                out.append(int(m.group(1)))
            m = _SR.match(t)
            if space == "s" and m:
                out.extend(range(int(m.group(1)), int(m.group(2)) + 1))
            m = _VR.match(t)
            if space == "v" and m:
                out.extend(range(int(m.group(1)), int(m.group(2)) + 1))
        return out

    def walk(self, tok, lane, depth):
        """Follow a register token back through its producers."""
        if depth > 8:
            return {"reg": tok, "stop": "depth"}
        t = tok.split()[0]
        space = None
        idx = None
        m = _SV.match(t)
        if m:
            space, idx = "s", int(m.group(1))
        m = _VV.match(t)
        if m:
            space, idx = "v", int(m.group(1))
        m = _SR.match(t)
        if m:
            space, idx = "s", int(m.group(1))
        m = _VR.match(t)
        if m:
            space, idx = "v", int(m.group(1))
        if space is None:
            return {"tok": tok, "kind": "literal_or_other"}
        node = dict(self.du_lw.get((space, idx)) or
                    {"reg": "%s%d" % (space, idx), "stop": "no_producer"})
        node["queried_as"] = tok
        node["value_now"] = ("0x%08X"
                             % ((self.s[idx] if space == "s"
                                 else self.v[lane][idx]) & 0xFFFFFFFF))
        if "ops" in node:
            node["parents"] = [self.walk(p, lane, depth + 1)
                               for p in node["ops"][1:]]
            del node["ops"]
        return node


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="swin32f")
    ap.add_argument("--waves", type=int, default=8)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--round-cap", type=int, default=2_000_000)
    ap.add_argument("--site", default="0x000ACC24",
                    help="OOB site to capture (hex)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    capture_site = int(args.site, 16)

    base = EC.BothCore

    class ProbeCore(DefUseMixin, base):
        gate = None
        alloc = 0

        def _gl_addr(self, ins, lane, ops, store=False):
            addr = super()._gl_addr(ins, lane, ops, store)
            if (self.du_capture is None
                    and ins.get("address") == capture_site):
                g = G.GateCore.gate
                n = g and self._width_of(ins.get("mnemonic") or "")
                if g is not None and n and g.locate(addr, n) is None:
                    self.capture(ins, ops, lane, addr)
            return addr

    vals, meta = AH.load_cell(CSV, args.tag, None, None)
    canvas = meta["grid"][0] * meta["grid"][1] * 8192
    tensor = args.region_mib * 1024 * 1024
    sym = AH.SYM[args.tag]
    kd = sym + ".kd"
    psz = EC.SP.private_segment_size(CAND_CO, kd)
    gs = LD.kd_group_segment(CAND_CO, kd)

    sgate = SC.ScrtCloseGate(psz)
    SI.ScrtISACore.scrt_close = sgate
    EC.SP.ScrtGateCore.scrt_gate = None

    bounds = [("desc_%d" % gs, gs)] + LD.FIXED_BOUNDS
    LD.DescLdsCore.reset(bounds)

    core = ISA.p16i_isa_core(ProbeCore)
    core.reset(bounds)
    core.counts_auth_limit = gs
    core.counts_cand_limit = gs

    holder = {}
    fill = IN.make_fill(vals, canvas, tensor, gen_name="A")

    def fill_hook(mem):
        pm = IN.PatternMem(mem, IN.regions_for(vals, canvas, tensor),
                           gen=IN.GENERATORS["A"])
        holder["mem"] = pm
        return pm

    try:
        res = AH.run(args.tag, CSV, None, None, args.waves, args.region_mib,
                     args.round_cap,
                     os.path.join(PHASE16O, "a_regression", "out",
                                  "_probe_raw_%s.json" % args.tag),
                     core_cls=core, fill_payload=fill_hook)
    finally:
        SI.ScrtISACore.scrt_close = None

    cores = list(getattr(core, "registry", []) or [])
    cap = None
    cap_wave = None
    for wi, c in enumerate(cores):
        if c.du_capture is not None:
            cap = c.du_capture
            cap_wave = wi
            break
    if cap is None:
        cap = next((getattr(c, "du_capture", None) for c in cores
                    if getattr(c, "du_capture", None)), None)

    g = G.GateCore.gate.summary() if G.GateCore.gate else {}
    doc = {
        "schema": "phase16o-a-defuse/1", "phase": "16O", "track": "A4",
        "host_only": True, "gpu_execution_performed": False,
        "gta_launched": False, "currently_armed": False,
        "tag": args.tag, "capture_site": args.site,
        "ticks": res.get("ticks"), "outcome": str(res.get("outcome")),
        "n_waves_run": len(cores),
        "gate_summary": {k: g.get(k) for k in
                         ("oob_global_reads", "oob_global_writes",
                          "n_global_reads", "n_global_writes", "gate")},
        "captured": cap,
        "captured_wave": cap_wave,
    }
    out = args.out or os.path.join(PHASE16O, "a_regression", "out",
                                   "A4_DEFUSE_%s.json" % args.tag)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    print("ticks=%s outcome=%s waves=%d" % (doc["ticks"], doc["outcome"],
                                            len(cores)))
    print("gate: %s" % doc["gate_summary"])
    if cap:
        print("captured %s %s lane=%d wave=%s addr=%s"
              % (cap["site"], cap["mnemonic"], cap["lane"], cap["wave"],
                 cap["addr"]))
        print("  operands: %s" % cap["operands"])
        for tok, ch in cap["chains"].items():
            print("  chain[%s] -> site=%s mnem=%s operands=%s written=%s %s"
                  % (tok, ch.get("site"), ch.get("mnemonic"),
                     ch.get("operands"), ch.get("written"),
                     ch.get("stop") or ""))
    else:
        print("NO OOB capture at site %s" % args.site)
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
