#!/usr/bin/env python3
"""Phase 16I-3 -- make the scratch (private-segment) validator fail closed.

THE DEFECT

`p16h_scratch_probe.ScrtGateCore._scratch_xfer` gates a scratch access only
when three things all hold:

    g = ScrtGateCore.scrt_gate        # read via the CLASS NAME, not `self`
    if g is not None and ops:         # 1. the gate must be armed
        ...
        if lo is not None:            # 2. the operand grammar must resolve
            ... g.dispatch(...); g.note(...)

Anything that falls through is *silently unchecked*, and an unchecked
access is indistinguishable from a checked one in the summary: the gate
reports `oob_scratch_accesses: 0` and `gate: PASS`.  This is the same
fail-open shape that `GateCore._gl_addr` was rewritten to remove on the
global path (a global access whose width cannot be derived is now counted
UNMEASURED and fails the gate outright).  The scratch path never got that
treatment.

There is a second, sharper instance of the same bug: `scrt_gate` is read
through the class name `ScrtGateCore`, so arming a SUBCLASS (as `P12Core`
and every ISA-composed core are) leaves the real gate unarmed.  Measured
directly during Phase 16I: a run with the gate armed only on the subclass
reported `oob=0 PASS` while every wave had actually faulted at its first
global access on a None gate.  A fail-open validator that reports PASS is
worse than no validator.

THE FIX

`ScrtCloseCore` derives the address and width with the parent's own operand
grammar and then *always* classifies the access:

  * measured   -- address and width derived; bound-checked against
                  [0, private_segment_fixed_size);
  * unmeasured -- the instruction was issued with at least one lane in EXEC
                  but no address/width could be derived.  Counted and
                  fatal.

The gate fails if there is ANY unmeasured dispatch or ANY out-of-bounds
access.  It is armed on the class that actually executes, and the parent's
own (unarmed) gate is explicitly cleared so nothing is double-counted.

Both halves are checked:

  STATIC  -- every `scratch_*` mnemonic in the module resolves to a handler,
             and every such handler routes through `_scratch_xfer`.
  DYNAMIC -- the authentic one-frame dispatch for each of the five SWIN
             variants, run against the fail-closed gate.

Host-only.  No GPU.  Nothing frozen is modified.

Usage:
  p16i_scratch_close.py [--tags swin32f,...] [--static-only]
"""
from __future__ import annotations

import argparse
import json
import os
import re
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

import p16h_lib as L                 # noqa: E402
import p16h_global_gate as G         # noqa: E402
import p16h_scratch_probe as SP      # noqa: E402
import p16e_rec as rec               # noqa: E402
import p16i_authentic_harness as AH  # noqa: E402

RE_VREG = rec.RE_VREG
RE_OFF = rec.RE_OFF

SCRATCH_HANDLER = re.compile(r"^op_scratch_")


class ScrtCloseGate:
    """Fail-closed private-segment validator.

    `unmeasured` is the point of the class: an access that cannot be
    bounded is not a pass, it is a failure.
    """

    def __init__(self, size):
        self.size = size
        self.n_dispatch = 0
        self.n_dispatch_live = 0
        self.n_measured = 0
        self.n_ops = 0
        self.n_reads = 0
        self.n_writes = 0
        self.unmeasured = []
        self.oob = []
        self.offsets = {}
        self.by_site = {}

    def dispatch(self, store, site, mnem, live):
        self.n_dispatch += 1
        if live:
            self.n_dispatch_live += 1

    def unmeasured_dispatch(self, store, site, mnem, live, why):
        self.unmeasured.append({
            "site": ("0x%08X" % site) if site else None,
            "mnem": mnem, "store": bool(store), "n_live": len(live),
            "why": why})

    def note(self, store, lane, ea, nbytes, site, mnem):
        self.n_ops += 1
        self.n_reads += 0 if store else 1
        self.n_writes += 1 if store else 0
        self.offsets[ea] = self.offsets.get(ea, 0) + 1
        e = self.by_site.setdefault(site, {"n": 0, "min": ea,
                                           "max": ea + nbytes})
        e["n"] += 1
        e["min"] = min(e["min"], ea)
        e["max"] = max(e["max"], ea + nbytes)
        if ea + nbytes > self.size:
            self.oob.append({"store": bool(store), "lane": lane, "ea": ea,
                             "n": nbytes, "hi": ea + nbytes, "site": site,
                             "mnem": mnem})

    @property
    def ok(self):
        return not self.oob and not self.unmeasured

    def summary(self):
        offs = sorted(self.offsets)
        return {
            "declared_private_segment_fixed_size": self.size,
            "n_scratch_dispatch": self.n_dispatch,
            "n_scratch_dispatch_live": self.n_dispatch_live,
            "n_scratch_measured": self.n_measured,
            "n_scratch_ops": self.n_ops,
            "n_scratch_reads": self.n_reads,
            "n_scratch_writes": self.n_writes,
            "n_unmeasured": len(self.unmeasured),
            "unmeasured": self.unmeasured[:20],
            "offset_min": (offs[0] if offs else None),
            "offset_max": (offs[-1] if offs else None),
            "n_distinct_offsets": len(offs),
            "oob_scratch_accesses": len(self.oob),
            # The Phase 16J brief gates scratch OOB reads and writes
            # separately.  `oob` records carry the direction, but `summary`
            # truncated them to 20 samples, so a run with 21 OOB reads and 0
            # OOB writes was indistinguishable from one with 0 and 21.  The
            # counts are exact and full-length; `ok` is unchanged.
            "oob_scratch_reads": sum(1 for o in self.oob if not o["store"]),
            "oob_scratch_writes": sum(1 for o in self.oob if o["store"]),
            "oob_samples": self.oob[:20],
            "gate": "PASS" if self.ok else "FAIL",
            "by_site": {"0x%08X" % (k or 0): v
                        for k, v in sorted(self.by_site.items())},
        }


class ScrtCloseCore(SP.ScrtGateCore):
    """ScrtGateCore with a fail-closed scratch classification.

    Reads its gate through `ScrtCloseCore.scrt_close`, never through the
    parent's class-level `scrt_gate`, so a subclass cannot be armed into a
    silent no-op.
    """

    scrt_close = None
    wave_index = 0

    def _scratch_xfer(self, ins, store):
        g = ScrtCloseCore.scrt_close
        if g is not None:
            ops = [o.strip() for o in (ins.get("operands") or "").split(",")]
            live = [ln for ln in range(self.lanes)
                    if (self.exec_l >> ln) & 1]
            site = ins.get("address")
            mnem = ins.get("mnemonic") or ""
            g.dispatch(store, site, mnem, live)
            lo = hi = None
            vaddr_reg = None
            why = None
            if not ops:
                why = "no operands"
            elif store:
                for tok in ops[1:]:
                    mt = RE_VREG.search(tok)
                    if mt:
                        lo, hi = ((int(mt.group(1)), int(mt.group(2)))
                                  if mt.group(1) is not None
                                  else (int(mt.group(3)), int(mt.group(3))))
                        break
                if lo is None:
                    why = "no data vreg token"
                else:
                    mt = RE_VREG.search(ops[0])
                    vaddr_reg = ((int(mt.group(1)) if mt.group(1) is not None
                                  else int(mt.group(3))) if mt else None)
                    if vaddr_reg is None:
                        why = "no vaddr vreg token"
            else:
                mt = RE_VREG.search(ops[0])
                if mt:
                    lo, hi = ((int(mt.group(1)), int(mt.group(2)))
                              if mt.group(1) is not None
                              else (int(mt.group(3)), int(mt.group(3))))
                if lo is None:
                    why = "no destination vreg token"
                else:
                    for tok in ops[1:]:
                        mt = RE_VREG.search(tok)
                        if mt:
                            vaddr_reg = (int(mt.group(1))
                                         if mt.group(1) is not None
                                         else int(mt.group(3)))
                            break
                    if vaddr_reg is None:
                        why = "no vaddr vreg token"
            if why is None:
                m = RE_OFF.search(ins.get("operands") or "")
                imm = int(m.group(1)) if m else 0
                nbytes = (hi - lo + 1) * 4
                g.n_measured += 1
                for lane in live:
                    base = (self.v[lane][vaddr_reg] & 0xFFFFFFFF
                            if vaddr_reg is not None else 0)
                    g.note(store, lane, (base + imm) & 0xFFFFFFFF, nbytes,
                           site, mnem)
            elif live:
                g.unmeasured_dispatch(store, site, mnem, live, why)
        super()._scratch_xfer(ins, store)


# --------------------------------------------------------------------------
# static half
# --------------------------------------------------------------------------
def static_census(prog, core_cls):
    """Every scratch mnemonic must resolve, and must route via _scratch_xfer."""
    mnems = sorted({i["mnemonic"].replace("_e32", "").replace("_e64", "")
                    for i in prog
                    if (i["mnemonic"] or "").startswith("scratch_")})
    out = {}
    for m in mnems:
        fn = getattr(core_cls, "op_" + m, None)
        if fn is None:
            out[m] = {"handler": None, "status": "NO_HANDLER"}
            continue
        # does its body reach _scratch_xfer?
        import inspect
        try:
            src = inspect.getsource(fn)
        except Exception:                             # noqa: BLE001
            src = ""
        routes = "_scratch_xfer" in src
        out[m] = {"handler": "%s.%s" % (fn.__module__,
                                        getattr(fn, "__qualname__", m)),
                  "routes_to_scratch_xfer": routes,
                  "status": "OK" if routes else "NOT_ROUTED"}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tags", default="swin32t,swin32f,swin64f,swin128f")
    ap.add_argument("--csv", default=os.path.join(
        ROOT, "phase16_authentic_decode_swin.csv"))
    ap.add_argument("--waves", type=int, default=8)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--round-cap", type=int, default=2000000)
    ap.add_argument("--static-only", action="store_true")
    ap.add_argument("--json", default=os.path.join(
        ROOT, "phase16i_closure/out/p16i_scratch_close.json"))
    a = ap.parse_args()

    import p16i_isa as ISA
    core = ISA.p16i_isa_core(ScrtCloseCore)
    # the parent's own gate must stay unarmed, or every access is counted
    # twice (once by the parent, once here)
    SP.ScrtGateCore.scrt_gate = None

    co = os.path.join(ROOT, "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co")
    dis = os.path.join(ROOT,
                       "phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt")
    elf = L.Elf(co)

    # ---- static: whole module, every scratch mnemonic in every kernel
    static = {}
    for tag, sym in sorted(AH.SYM.items()):
        prog, _r, _i = G.PE.slice_program(dis, sym)
        static[sym] = static_census(prog, core)
    bad = {s: {m: v for m, v in d.items() if v["status"] != "OK"}
           for s, d in static.items()}
    bad = {s: v for s, v in bad.items() if v}
    n_mnem = len({m for d in static.values() for m in d})
    print("STATIC: %d scratch mnemonics across %d kernels; %d kernels with "
          "a non-OK mnemonic" % (n_mnem, len(static), len(bad)))
    for s, v in bad.items():
        print("   %-50s %s" % (s[:50], v))

    out = {"static": static, "n_scratch_mnemonics": n_mnem,
           "static_bad": bad, "dynamic": {}}

    if not a.static_only:
        for tag in [t.strip() for t in a.tags.split(",") if t.strip()]:
            sym = AH.SYM[tag]
            ks = G.kernarg_size(elf, sym + ".kd")
            psz = SP.private_segment_size(co, sym + ".kd")
            g = ScrtCloseGate(psz)
            ScrtCloseCore.scrt_close = g
            out_path = os.path.join(
                ROOT, "phase16i_closure/out/p16i_scratch_%s.json" % tag)
            try:
                AH.run(tag, a.csv, None, None, a.waves, a.region_mib,
                       a.round_cap, out_path, core_cls=core)
                s = g.summary()
                out["dynamic"][tag] = s
                print("DYNAMIC %-9s psz=%-4s dispatch=%-6s measured=%-6s "
                      "unmeasured=%-3s oob=%-3s  %s"
                      % (tag, psz, s["n_scratch_dispatch"],
                         s["n_scratch_measured"], s["n_unmeasured"],
                         s["oob_scratch_accesses"], s["gate"]))
                if s["unmeasured"]:
                    for u in s["unmeasured"][:6]:
                        print("      UNMEASURED %s" % u)
                if s["oob_samples"]:
                    for o in s["oob_samples"][:6]:
                        print("      OOB %s" % o)
            except Exception as e:                    # noqa: BLE001
                out["dynamic"][tag] = {"error": "%s: %s"
                                       % (type(e).__name__, e)}
                print("DYNAMIC %-9s ERROR %s: %s" % (tag, type(e).__name__, e))
            finally:
                ScrtCloseCore.scrt_close = None

    json.dump(out, open(a.json, "w", encoding="utf-8"), indent=1)
    print("wrote " + a.json)
    ok = (not bad and all(v.get("gate") == "PASS"
                          for v in out["dynamic"].values()))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
