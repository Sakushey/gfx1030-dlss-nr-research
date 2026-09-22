#!/usr/bin/env python3
"""Phase 16O Track A -- log every scalar load and its resolved address.

Phase 16N's OOB sites are addressed through SGPR PAIRS (s[38:39], s[2:3])
that the kernel fills from `s_load_dword*` off the kernarg pointer.  This
probe records each scalar load with the base pair it used, the byte address
it resolved to, the words it produced, and -- for the dword-keyed region --
what the old `mem.get(addr, 0)` model would have returned instead.

That last column is the discriminator between the two emulator revisions
without needing either tree: it evaluates both readers on the SAME map.

Host-only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
PHASE16O = os.path.join(ROOT, "phase16o_final")

sys.path.insert(0, os.path.join(ROOT, "phase16k_pretest", "k3_arena"))
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
import p16i_isa as ISA                   # noqa: E402
import p16i_lds_descriptor as LD         # noqa: E402
import p16i_scratch_close as SC          # noqa: E402

CAND_CO = os.path.join(ROOT,
                       "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co")
CSV = os.path.join(ROOT, "phase16_authentic_decode_swin.csv")

LOG = []          # module-level: survives per-wave core creation


class SloadProbe:
    """Wrap `_sload` (and the D9 reader) to record what each load resolved."""

    SITES = None          # None = log every scalar load
    _DUMPED = False

    def _sload(self, ins, ops, nwords):
        site = ins.get("address")
        base = self.spair(ops[1])
        off = self.sget(ops[2]) if len(ops) > 2 else 0
        addr = (base + off) & ((1 << 64) - 1)
        words = [self._read_u32(addr + 4 * i) for i in range(nwords)]
        # what the PRE-16N reader (`mem.get(addr, 0)`) would have returned,
        # evaluated on the SAME live map
        old = []
        for i in range(nwords):
            a = (addr + 4 * i) & ((1 << 64) - 1)
            try:
                v = self.mem.get(a, 0)
            except Exception as e:                       # noqa: BLE001
                v = "ERR:%s" % e
            old.append(v)
        if not SloadProbe._DUMPED:
            SloadProbe._DUMPED = True
            m = self.mem
            win = {}
            for k in range(0x10000, 0x101B0):
                if dict.__contains__(m, k):
                    win["0x%X" % k] = "0x%X" % m[k]
            LOG.append({
                "_debug": "map state at first scalar load",
                "len_mem": len(m),
                "type": type(m).__name__,
                "dict_contains_0x10098": dict.__contains__(m, 0x10098),
                "contains_0x10098": (0x10098 in m),
                "base_of_0x10098": m._base_of(0x10098)
                if hasattr(m, "_base_of") else "n/a",
                "get_0x10098": m.get(0x10098, "MISS"),
                "contains_0x100A1": (0x100A1 in m),
                "get_0x100A1": m.get(0x100A1, "MISS"),
                "regions_head": [list(r) for r in
                                 getattr(m, "regions", [])][:6],
                "kernarg_window": win,
            })
        if self.SITES is None or site in self.SITES:
            LOG.append({
                "wave": getattr(type(self), "wave_index", None),
                "step": self.steps, "site": site,
                "mnem": ins.get("mnemonic"), "ops": ins.get("operands"),
                "base_pair": "0x%016X" % base, "off": "0x%X" % off,
                "addr": "0x%016X" % addr,
                "nwords": nwords,
                "new_words": ["0x%08X" % (w & 0xFFFFFFFF) for w in words],
                "old_words": ["0x%08X" % (w & 0xFFFFFFFF)
                              if isinstance(w, int) else str(w) for w in old],
                "dst": ops[0],
                "s0_1": "0x%016X" % (self.s[0] | (self.s[1] << 32)),
            })
        # replicate the production behaviour
        dst = ops[0]
        bd = self._bounds(dst)
        if bd:
            a, b = bd
            for j, i in enumerate(range(a, b + 1)):
                self.s[i] = words[j]
                self.undef_s.discard(i)
        else:
            self.sset(dst, words[0])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="swin32f")
    ap.add_argument("--waves", type=int, default=1)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--round-cap", type=int, default=2_000_000)
    ap.add_argument("--limit", type=int, default=40)
    ap.add_argument("--pointer-regions-only", action="store_true",
                    help="declare synthetic regions ONLY at the authentic "
                         "POINTER fields, not at every field value")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    if args.pointer_regions_only:
        _orig_regions_for = IN.regions_for

        def _fixed_regions_for(vals, canvas_size, tensor_size, extra=()):
            out = []
            for off in AH.POINTER_OFFSETS:
                val = vals.get(off)
                if not val:
                    continue
                size = canvas_size if off == 0xA0 else tensor_size
                out.append((val, val + size, "authentic_0x%02X" % off))
            out.extend(extra)
            return out

        IN.regions_for = _fixed_regions_for

    base = EC.BothCore

    class ProbeCore(SloadProbe, base):
        gate = None
        alloc = 0

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

    def fill_hook(mem):
        return IN.PatternMem(mem, IN.regions_for(vals, canvas, tensor),
                             gen=IN.GENERATORS["A"])

    try:
        res = AH.run(args.tag, CSV, None, None, args.waves, args.region_mib,
                     args.round_cap,
                     os.path.join(PHASE16O, "a_regression", "out",
                                  "_sload_raw_%s.json" % args.tag),
                     core_cls=core, fill_payload=fill_hook)
    finally:
        SI.ScrtISACore.scrt_close = None

    print("ticks=%s outcome=%s  n_sload_logged=%d"
          % (res.get("ticks"), res.get("outcome"), len(LOG)))
    seen = set()
    shown = 0
    for r in LOG:
        if r.get("_debug"):
            print("[map@first-load] len=%d type=%s" % (r["len_mem"], r["type"]))
            print("   0x10098 in mem: dict=%s contains=%s base_of=%s get=%s"
                  % (r["dict_contains_0x10098"], r["contains_0x10098"],
                     r["base_of_0x10098"], r["get_0x10098"]))
            print("   0x100A1 contains=%s get=%s"
                  % (r["contains_0x100A1"], r["get_0x100A1"]))
            print("   regions: %s" % (r["regions_head"],))
            print("   kernarg window: %s" % r["kernarg_window"])
            continue
        key = (r["site"], r["dst"], r["base_pair"], r["addr"])
        if key in seen:
            continue
        seen.add(key)
        print("site=%s %-18s %-28s base=%s off=%s addr=%s"
              % (r["site"] and "0x%08X" % r["site"], r["mnem"], r["ops"],
                 r["base_pair"], r["off"], r["addr"]))
        print("      dst=%-10s new=%s" % (r["dst"], r["new_words"]))
        print("      %-14s old=%s" % ("", r["old_words"]))
        shown += 1
        if shown >= args.limit:
            print("... (%d distinct sites logged)" % len(seen))
            break

    out = args.out or os.path.join(PHASE16O, "a_regression", "out",
                                   "A_SLOAD_%s.json" % args.tag)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"schema": "phase16o-a-sload/1", "phase": "16O",
                   "track": "A", "host_only": True,
                   "gpu_execution_performed": False, "gta_launched": False,
                   "tag": args.tag, "waves": args.waves,
                   "ticks": res.get("ticks"),
                   "outcome": str(res.get("outcome")),
                   "n_loads": len(LOG), "loads": LOG[:4000]}, f, indent=1)
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
