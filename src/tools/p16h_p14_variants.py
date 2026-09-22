#!/usr/bin/env python3
"""Phase 16H — P14: host-side closure of the remaining SWIN variants.

Host-only emulation.  No GPU, no HIP launch, no driver interaction.
NO PHYSICAL TEST IS AUTHORIZED OR PERFORMED.

Runs Candidate F for each of the four remaining authentic SWIN variants

    <32,true>   <64,false>   <128,false>   <256,false>

at its authentic comparator geometry, with every Phase-16H correction
applied (module `.text`+`.rodata` map, declared-region global gate that
fails closed, declared-region scratch gate, authentic hidden args), and
reports the five properties the brief requires per cell:

    termination, zero LDS OOB, zero global OOB, correct barriers,
    authentic kernarg/pointer semantics.

The PC-relative correction itself is already module-wide: the translator
emits symbolic `R_AMDGPU_REL32_LO/HI` relocations for every one of the 82
sites in all five variants (P13).  What P14 tests is whether each variant
*runs* under that correction.

Expected honest outcome: the same P8 harness blocker that fails A4 for
`<32,false>` applies to all four, because the harness still cannot
populate kernarg qwords 0x50/0x70/0x88.  Those failures are reported, not
repaired.

Emits out/p14_variants.json.
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

F_CO = "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co"
F_DIS = "phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt"
E_CO = "phase16e_candidate_e/gfx1030_dlssnr_candidate_e.co"
E_DIS = "phase16e_candidate_e/disasm/candidate_e_gfx1030_disasm.txt"

WAVES = 8

# The Phase-16F/G harnesses cap at 200,000,000 rounds -- ~12,000x the 16,945
# ticks the authentic <32,false> cell needs, i.e. hours of wall clock at this
# emulator's ~10 ms/tick.  A variant that has not terminated by 200,000
# rounds (11.8x the reference, ~33 min worst case) is not "slow", it is
# non-terminating, and the run should say ROUNDCAP rather than hang.
ROUND_CAP = int(os.environ.get("P14_ROUND_CAP", "200000"))

# Authentic comparator cells, taken from phase16_authentic_launch_db.csv.
# Each is the `flags=0x1` / `pair=(0,0)` instance of that variant, which is
# the one the mod prints as the SWIN comparator for that scale.
CELLS14 = {
    "swin32t":  {"X": 576, "Y": 960, "pl": 0, "ph": 0, "flags": 8,
                 "grid": (120, 72, 1), "wgid": (0, 0, 0)},
    "swin64f":  {"X": 288, "Y": 480, "pl": 0, "ph": 0, "flags": 1,
                 "grid": (60, 36, 1), "wgid": (0, 0, 0)},
    "swin128f": {"X": 144, "Y": 240, "pl": 0, "ph": 0, "flags": 1,
                 "grid": (30, 18, 1), "wgid": (0, 0, 0)},
    "swin256f": {"X": 72, "Y": 120, "pl": 0, "ph": 0, "flags": 1,
                 "grid": (15, 9, 1), "wgid": (0, 0, 0)},
    # the Phase-16H reference cell, for continuity with P12
    "swin32f":  {"X": 576, "Y": 960, "pl": 0, "ph": 0, "flags": 1,
                 "grid": (120, 72, 1), "wgid": (0, 0, 0)},
}

ORDER = ["swin32f", "swin32t", "swin64f", "swin128f", "swin256f"]

# `HWCore.hw_ev` holds one dict per active-lane LDS access and `hw_memviol`
# the OOB subset, both unbounded.  On `<128,false>` that is millions of
# records and several GB of RSS -- it, and not the OOB *records* the gate
# retains, is what grows.  P14's evaluation reads neither list, only their
# counts (and, for violations, their distribution), so under
# `P14_AGG_LDS=1` they are replaced by counters that keep exactly that and
# store nothing.  Result-neutral by construction.
AGG_LDS = os.environ.get("P14_AGG_LDS", "0") == "1"

# Two variants may be run concurrently (they are independent), but the
# results file is read-modify-written per variant, so concurrent writers
# would clobber each other.  `P14_OUT_NAME` lets a concurrent run write
# somewhere else; the entries are merged afterwards.
OUT_NAME = os.environ.get("P14_OUT_NAME", "p14_variants.json")


class AggCounter:
    """Stand-in for an unbounded record list: counts, stores nothing."""

    __slots__ = ("n", "sink")

    def __init__(self, sink=None):
        self.n = 0
        self.sink = sink

    def append(self, x):
        self.n += 1
        if self.sink is not None:
            self.sink(x)

    def __len__(self):
        return self.n

    def __iter__(self):
        return iter(())


class LdsAgg:
    """Distribution of LDS violations, bounded by site count."""

    def __init__(self, alloc=16384):
        self.alloc = alloc
        self.n = 0
        self.by_bucket = {}
        self.by_site = {}
        self.by_mnem = {}
        self.by_site_bucket = {}
        self.n_in_range_if_trunc16 = 0
        self.ea_min = None
        self.ea_max = None

    def __call__(self, r):
        self.n += 1
        raw = r["ea_u32"]
        w = r["w"]
        end = raw + w
        if end <= 16384:
            b = "le_16384_declared"
        elif end <= 65536:
            b = "16384_to_65536"
        else:
            b = "gt_65536"
        self.by_bucket[b] = self.by_bucket.get(b, 0) + 1
        if ((raw & 0xFFFF) + w) <= self.alloc:
            self.n_in_range_if_trunc16 += 1
        s = "0x%08X" % (r["site"] or 0)
        self.by_site[s] = self.by_site.get(s, 0) + 1
        self.by_mnem[r["mnem"]] = self.by_mnem.get(r["mnem"], 0) + 1
        d = self.by_site_bucket.setdefault(s, {})
        d[b] = d.get(b, 0) + 1
        self.ea_min = raw if self.ea_min is None else min(self.ea_min, raw)
        self.ea_max = raw if self.ea_max is None else max(self.ea_max, raw)

    def summary(self):
        return {
            "n_violations": self.n,
            "by_bucket": self.by_bucket,
            "by_site": dict(sorted(self.by_site.items(),
                                   key=lambda kv: -kv[1])[:40]),
            "by_mnem": dict(sorted(self.by_mnem.items(),
                                   key=lambda kv: -kv[1])[:40]),
            "by_site_bucket": {k: self.by_site_bucket[k]
                               for k in sorted(self.by_site_bucket)},
            "n_in_range_if_trunc16": self.n_in_range_if_trunc16,
            "ea_u32_min": ("0x%08X" % self.ea_min
                           if self.ea_min is not None else None),
            "ea_u32_max": ("0x%08X" % self.ea_max
                           if self.ea_max is not None else None),
        }


def merge_lds_aggs(aggs):
    """Combine the per-core `LdsAgg`s of one workgroup."""
    m = LdsAgg()
    for a in aggs:
        if a is None:
            continue
        m.n += a.n
        m.n_in_range_if_trunc16 += a.n_in_range_if_trunc16
        for dst, src in ((m.by_bucket, a.by_bucket),
                         (m.by_site, a.by_site),
                         (m.by_mnem, a.by_mnem)):
            for k, v in src.items():
                dst[k] = dst.get(k, 0) + v
        for s, bd in a.by_site_bucket.items():
            t = m.by_site_bucket.setdefault(s, {})
            for k, v in bd.items():
                t[k] = t.get(k, 0) + v
        if a.ea_min is not None:
            m.ea_min = (a.ea_min if m.ea_min is None
                        else min(m.ea_min, a.ea_min))
        if a.ea_max is not None:
            m.ea_max = (a.ea_max if m.ea_max is None
                        else max(m.ea_max, a.ea_max))
    return m


def agg_core_class(base):
    """A `base` subclass whose LDS record lists aggregate instead of store."""

    class AggCore(base):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.lds_agg = LdsAgg(alloc=getattr(self, "alloc", 16384))
            self.hw_ev = AggCounter()
            self.hw_memviol = AggCounter(sink=self.lds_agg)

    return AggCore


def run_once(tag, co_path, dis_path, waves=WAVES):
    sym = p16e_rec.SYM[tag]
    c = CELLS14[tag]
    co = os.path.join(L.ROOT, co_path)
    dis = os.path.join(L.ROOT, dis_path)

    prog, _rows, _i = G.PE.slice_program(dis, sym)
    dw = G.P11.dw16(co, sym)
    fields = p16e_rec.fields_for(c)

    elf = L.Elf(co)
    kd = sym + ".kd"
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

    core_cls = agg_core_class(P12.P12Core) if AGG_LDS else P12.P12Core
    prev = G.p14eh.HWCore
    G.p14eh.HWCore = core_cls
    try:
        orig_tmm = G.PE.text_mem_map
        G.PE.text_mem_map = G.module_mem_map
        try:
            res = G.p14eh.run_workgroup_hw(
                prog, dw, tag, c["grid"], (256, 1, 1), fields,
                text_path=co, wave_count=waves, oob_sem="u32",
                alloc=16384, wgid=c["wgid"], round_cap=ROUND_CAP)
        finally:
            G.PE.text_mem_map = orig_tmm
    finally:
        G.p14eh.HWCore = prev

    cores = list(P12.P12Core.instances)
    traces = [core.trace.summary() for core in cores]
    lds_agg = merge_lds_aggs([getattr(x, "lds_agg", None)
                              for x in cores]).summary() if AGG_LDS else None
    # `HWCore.__init__` appends every core it constructs to `HWCore.registry`
    # (an explicit class reference, not `self.__class__`), and nothing drains
    # it on the hardware path.  Each retained core holds its wave's full
    # module memory image -- ~1.2 GB per variant across 8 waves.  Release
    # the list on the class that actually owns it.
    G.p14eh.HWCore.registry = []
    P12.P12Core.instances = []
    return res, ggate, sgate, traces, {
        "kernarg_size": ks, "private_segment_fixed_size": psz,
        "n_insn": len(prog), "cell": c, "lds_agg": lds_agg}


def evaluate(res, ggate, sgate, traces, meta, tag):
    per = res["per_wave"]
    faults = [w["fault"] for w in per if w["fault"]]
    lds = {"memviol": sum(w["memviol"] for w in per),
           "oob_read_zero": sum(w["oob_read_zero"] for w in per),
           "oob_write_discard": sum(w["oob_write_discard"] for w in per)}
    g = ggate.summary()
    s = sgate.summary()

    # "correct barriers" for a 256-thread workgroup: 8 waves, every wave
    # must reach the same number of barrier epochs, and none may be stuck.
    nbar = [w["barriers"] for w in per]
    barriers_ok = (len(set(nbar)) == 1 and nbar[0] > 0
                   and all(w["state"] == "ENDED" for w in per))

    checks = {
        "termination": (all(w["state"] == "ENDED" for w in per)
                        and res["outcome"][0] not in ("ROUNDCAP", "CYCLE")),
        "zero_lds_oob": (lds["memviol"] == 0 and lds["oob_read_zero"] == 0
                         and lds["oob_write_discard"] == 0),
        "zero_global_oob": (g["oob_global_reads"] == 0
                            and g["oob_global_writes"] == 0
                            and g["n_unmeasured_global_ops"] == 0),
        "zero_scratch_oob": s["oob_scratch_accesses"] == 0,
        "correct_barriers": barriers_ok,
        "no_unsupported_opcode": not any(f and f[0] == "NOTIMPL"
                                         for f in faults),
        "authentic_kernarg": None,   # filled in by the caller from P8's audit
    }
    return {
        "tag": tag, "symbol": p16e_rec.SYM[tag],
        "outcome": str(res["outcome"]), "ticks": res["ticks"],
        "diverged": res["diverged"],
        "barrier_epochs": len(res["barrier_epochs"]),
        "waves": [{"wave": w["wave"], "state": w["state"], "steps": w["steps"],
                   "barriers": w["barriers"], "fault": w["fault"]}
                  for w in per],
        "faults": faults, "lds": lds, "lds_agg": meta.get("lds_agg"),
        "global_gate": g, "scratch_gate": s,
        "branch_sig": [t["signature"] for t in traces],
        "max_branch_visits": max((t["max_site_visits"] for t in traces),
                                 default=0),
        "meta": meta, "checks": checks,
    }


def main():
    OUT = os.path.join(L.P16H, "out")
    os.makedirs(OUT, exist_ok=True)

    want = sys.argv[1:] or ORDER
    for t in want:
        if t not in CELLS14:
            raise SystemExit("unknown variant %r; known: %s"
                             % (t, ", ".join(ORDER)))

    print("=" * 84, flush=True)
    print("P14 — host-side closure of the remaining SWIN variants "
          "(Candidate F, host-only)", flush=True)
    print("=" * 84, flush=True)

    res = {}
    for tag in want:
        sym = p16e_rec.SYM[tag]
        c = CELLS14[tag]
        print("\n=== %s  (%s) ===" % (tag, sym), flush=True)
        print("  cell: X=%d Y=%d pair=(%d,%d) flags=0x%x grid=%s wgid=%s"
              % (c["X"], c["Y"], c["pl"], c["ph"], c["flags"], c["grid"],
                 c["wgid"]), flush=True)
        try:
            r1, gg1, sg1, tr1, meta = run_once(tag, F_CO, F_DIS)
        except Exception as exc:
            print("  RUN FAILED: %s: %s" % (type(exc).__name__, exc),
                  flush=True)
            res[tag] = {"tag": tag, "symbol": sym, "run_failed":
                        "%s: %s" % (type(exc).__name__, exc)}
            continue
        ev = evaluate(r1, gg1, sg1, tr1, meta, tag)
        res[tag] = ev

        print("  n_insn=%d  kernarg=%s  private=%s"
              % (meta["n_insn"], meta["kernarg_size"],
                 meta["private_segment_fixed_size"]), flush=True)
        print("  outcome=%s ticks=%d epochs=%d diverged=%s"
              % (ev["outcome"], ev["ticks"], ev["barrier_epochs"],
                 ev["diverged"]), flush=True)
        print("  waves: %s"
              % ", ".join("%s/%d steps/%d bar" % (w["state"], w["steps"],
                                                  w["barriers"])
                          for w in ev["waves"]), flush=True)
        if ev["faults"]:
            print("  faults: %s" % ev["faults"][:4], flush=True)
        g = ev["global_gate"]
        print("  GLOBAL: ops=%d oob_reads=%d oob_writes=%d sites=%d "
              "unmeasured=%d" % (g["n_global_ops"], g["oob_global_reads"],
                                 g["oob_global_writes"],
                                 len(g["oob_by_site"]),
                                 g["n_unmeasured_global_ops"]), flush=True)
        s = ev["scratch_gate"]
        print("  SCRATCH: issued=%d lane-accesses=%d oob=%d offsets=%s"
              % (s["n_scratch_dispatch"], s["n_scratch_ops"],
                 s["oob_scratch_accesses"], s["distinct_offsets"]), flush=True)
        print("  LDS: memviol=%d oob_read_zero=%d oob_write_discard=%d"
              % (ev["lds"]["memviol"], ev["lds"]["oob_read_zero"],
                 ev["lds"]["oob_write_discard"]), flush=True)
        la = ev.get("lds_agg")
        if la:
            print("  LDS violations by bound exceeded: %s"
                  % ", ".join("%s=%d" % kv
                              for kv in sorted(la["by_bucket"].items())),
                  flush=True)
            print("  LDS violations in-range under trunc16: %d (%.2f%%)  "
                  "EA %s..%s"
                  % (la["n_in_range_if_trunc16"],
                     100.0 * la["n_in_range_if_trunc16"]
                     / max(la["n_violations"], 1),
                     la["ea_u32_min"], la["ea_u32_max"]), flush=True)
            print("  LDS violating sites (top): %s"
                  % ", ".join("%s:%d" % kv
                              for kv in list(la["by_site"].items())[:8]),
                  flush=True)
        print("  max visits to any branch site: %d"
              % ev["max_branch_visits"], flush=True)
        for k in sorted(ev["checks"]):
            v = ev["checks"][k]
            print("     %-26s %s" % (k, "PASS" if v else
                                     ("FAIL" if v is False else "n/a")),
                  flush=True)

        # write incrementally so a later variant cannot lose an earlier result
        prev = {}
        jp = os.path.join(OUT, OUT_NAME)
        if os.path.exists(jp):
            try:
                prev = json.load(open(jp, encoding="utf-8"))
            except Exception:
                prev = {}
        prev.update(res)
        json.dump(prev, open(jp, "w", encoding="utf-8"), indent=1,
                  default=str)

    # ---- summary matrix ----------------------------------------------
    print("\n" + "=" * 84, flush=True)
    print("summary — the brief's five required properties per cell", flush=True)
    print("=" * 84, flush=True)
    print("%-10s %-10s %-10s %-12s %-11s %s"
          % ("variant", "terminate", "LDS-OOB", "global-OOB", "barriers",
             "kernarg"), flush=True)
    for tag in want:
        ev = res.get(tag, {})
        if ev.get("run_failed"):
            print("%-10s RUN FAILED: %s" % (tag, ev["run_failed"][:50]),
                  flush=True)
            continue
        ch = ev["checks"]
        print("%-10s %-10s %-10s %-12s %-11s %s"
              % (tag,
                 "PASS" if ch["termination"] else "FAIL",
                 "PASS" if ch["zero_lds_oob"] else "FAIL",
                 "PASS" if ch["zero_global_oob"] else "FAIL",
                 "PASS" if ch["correct_barriers"] else "FAIL",
                 "BLOCKED (P8)"), flush=True)

    print("\nwrote", os.path.join(OUT, OUT_NAME), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
