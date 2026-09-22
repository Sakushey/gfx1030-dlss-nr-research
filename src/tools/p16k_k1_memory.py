#!/usr/bin/env python3
"""Phase 16K-K1 -- measure what a production dispatch actually retains.

Runs a real dispatch, samples peak RSS and every container length on the
core, and reports the result.  The point is to replace "this list looks
unbounded" with a number, and to do it for the LARGEST variant rather than
the cheapest one -- a leak that is invisible at `<32,false>` is the one that
matters at `<256,false>`.

Peak RSS is read from the Windows process counters via `ctypes`, not from
`resource` (absent on Windows) and not from `psutil` (not installed).

Host-only.  No GPU.

usage:
  p16k_k1_memory.py --tag swin256f --waves 8
  p16k_k1_memory.py --tag swin128f --waves 8 --sample-every 2000
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
for p in ("phase16i_closure/tools", "phase16h_pcrel_fix/tools",
          "phase16e_candidate_e/tools", "phase14e_static/tools",
          "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
          "phase14d11_static", "phase14d_static/tools", "phase8_static/tools",
          "phase14d8_static/tools", "phase16j_pre_gta/tools", HERE):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)

import p16j_execcache as EC          # noqa: E402
import p16i_authentic_harness as AH  # noqa: E402
import p16j_input as IN              # noqa: E402
import p16j_scratch_isa as SI        # noqa: E402
import p16i_lds_descriptor as LD     # noqa: E402
import p16i_isa as ISA               # noqa: E402
import p16i_scratch_close as SC      # noqa: E402
import p16h_scratch_probe as SP      # noqa: E402
import p16k_recorder as REC          # noqa: E402


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def _bind_psapi():
    """Bind GetProcessMemoryInfo with 64-bit-correct types.

    Without explicit argtypes ctypes marshals the HANDLE as a C int and the
    call fails (returns 0) on 64-bit Windows -- which is exactly how the
    first run of this tool reported a peak RSS of 0.0 MiB for every sample.
    The measurement is the whole point, so the binding is asserted once.
    """
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    k32.GetCurrentProcess.restype = wt.HANDLE
    k32.GetCurrentProcess.argtypes = []
    psapi.GetProcessMemoryInfo.restype = wt.BOOL
    psapi.GetProcessMemoryInfo.argtypes = [wt.HANDLE,
                                           ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                                           wt.DWORD]
    return k32, psapi


_K32, _PSAPI = _bind_psapi()
_ME = _K32.GetCurrentProcess()


def peak_rss_bytes():
    """Peak working set of THIS process, from the Win32 counters."""
    c = PROCESS_MEMORY_COUNTERS()
    c.cb = ctypes.sizeof(c)
    if _PSAPI.GetProcessMemoryInfo(_ME, ctypes.byref(c), c.cb):
        return c.PeakWorkingSetSize
    raise OSError("GetProcessMemoryInfo failed: %d"
                  % ctypes.get_last_error())


def run(tag, gen_name, waves, region_mib, round_cap, sample_every):
    import p14eh
    import p14d11_emu as P11

    csv = EC.CSV
    vals, meta = AH.load_cell(csv, tag, None, None)
    canvas = meta["grid"][0] * meta["grid"][1] * 8192
    tensor = region_mib * 1024 * 1024
    sym = AH.SYM[tag]
    kd = sym + ".kd"
    psz = SP.private_segment_size(EC.CAND_CO, kd)
    gs = LD.kd_group_segment(EC.CAND_CO, kd)

    sgate = SC.ScrtCloseGate(psz)
    SI.ScrtISACore.scrt_close = sgate
    SP.ScrtGateCore.scrt_gate = None
    bounds = [("desc_%d" % gs, gs)] + LD.FIXED_BOUNDS
    LD.DescLdsCore.reset(bounds)
    core_cls = ISA.p16i_isa_core(EC.BothCore)
    core_cls.reset(bounds)
    core_cls.counts_auth_limit = gs
    core_cls.counts_cand_limit = gs

    cores_seen = []
    timeline = []
    orig_step = P11.RecCore.step
    state = {"n": 0, "next": sample_every}

    def step_wrapper(self):
        if not cores_seen or cores_seen[-1] is not self:
            cores_seen.append(self)
        state["n"] += 1
        if state["n"] >= state["next"]:
            state["next"] += sample_every
            timeline.append({"tick": state["n"],
                             "rss_mib": round((peak_rss_bytes() or 0)
                                              / 1048576.0, 1),
                             "g_ops": len(self.g_ops),
                             "global_stores": len(getattr(
                                 self, "global_stores", []) or [])})
        return orig_step(self)

    P11.RecCore.step = step_wrapper
    fill = IN.make_fill(vals, canvas, tensor, gen_name=gen_name)
    holder = {}

    def fill_hook(mem):
        pm = IN.PatternMem(mem, IN.regions_for(vals, canvas, tensor),
                           gen=IN.GENERATORS[gen_name])
        holder["mem"] = pm
        return pm

    t0 = time.perf_counter()
    try:
        r = AH.run(tag, csv, None, None, waves, region_mib, round_cap,
                   os.path.join(ROOT, "phase16k_pretest/out",
                                "_k1mem_raw_%s.json" % tag),
                   core_cls=core_cls, fill_payload=fill_hook)
    finally:
        P11.RecCore.step = orig_step
        SI.ScrtISACore.scrt_close = None
    wall = time.perf_counter() - t0

    finals = {}
    retained = {}
    for c in cores_seen:
        for name in ("g_ops", "global_stores", "ds_ops", "hw_ev",
                     "hw_memviol", "mem"):
            v = getattr(c, name, None)
            if v is None:
                continue
            n = len(v) if hasattr(v, "__len__") else -1
            finals[name] = max(finals.get(name, 0), n)
            # `len()` on a bounded recorder is the TOTAL event count (the
            # list-compatible reading).  The memory question is what is
            # actually RETAINED, so measure that separately.
            kept = getattr(v, "_kept", None)
            if kept is not None:
                retained[name] = max(retained.get(name, 0), len(kept))

    gsum = None
    for c in cores_seen:
        g = getattr(c, "g_ops", None)
        if g is not None and hasattr(g, "summary"):
            gsum = g.summary()
            break

    return {"tag": tag, "waves": waves, "outcome": str(r["outcome"]),
            "ticks": r.get("ticks"), "wall_s": round(wall, 1),
            "peak_rss_mib": round((peak_rss_bytes() or 0) / 1048576.0, 1),
            "final_containers": finals, "retained_records": retained,
            "g_ops_summary": gsum,
            "recorder_mode": REC.RecorderConfig.as_dict(),
            "timeline": timeline,
            "n_global_reads": r["gate"]["n_global_reads"],
            "n_global_writes": r["gate"]["n_global_writes"],
            "gates": {k: bool(v) for k, v in
                      {"oob_reads_0": r["gate"]["oob_global_reads"] == 0,
                       "oob_writes_0": r["gate"]["oob_global_writes"] == 0,
                       "natural_end": bool(r.get("natural_end")),
                       "faults_empty": not r.get("faults")}.items()}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="swin256f")
    ap.add_argument("--pattern", default="A")
    ap.add_argument("--waves", type=int, default=8)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--round-cap", type=int, default=2000000)
    ap.add_argument("--sample-every", type=int, default=5000)
    ap.add_argument("--json", default=os.path.join(
        ROOT, "phase16k_pretest/out/k1_memory.json"))
    a = ap.parse_args()

    print("=" * 78)
    print("K1 memory: %s pattern %s, %d wave(s), recorder=%s"
          % (a.tag, a.pattern, a.waves, REC.RecorderConfig.mode))
    print("=" * 78)
    r = run(a.tag, a.pattern, a.waves, a.region_mib, a.round_cap,
            a.sample_every)
    print("outcome=%s ticks=%s wall=%.1fs peak_rss=%.1f MiB"
          % (r["outcome"], r["ticks"], r["wall_s"], r["peak_rss_mib"]))
    print("global reads=%s writes=%s"
          % (r["n_global_reads"], r["n_global_writes"]))
    print("final container lengths (max across waves; TOTAL events for "
          "bounded recorders):")
    for k, v in sorted(r["final_containers"].items(), key=lambda kv: -kv[1]):
        ret = r["retained_records"].get(k)
        print("   %-18s %10d%s" % (k, v, "" if ret is None
                                   else "   (retained records: %d)" % ret))
    g = r["g_ops_summary"]
    if g:
        print("g_ops: n=%d kept=%d dropped=%d distinct_pcs=%d "
              "distinct_opcodes=%d min=0x%X max=0x%X"
              % (g["n"], g["n_events_kept"], g["n_events_dropped"],
                 g["n_distinct_pcs"], g["n_distinct_opcodes"],
                 g["addr_min"] or 0, g["addr_max"] or 0))
    print("gates: %s" % r["gates"])
    print("RSS timeline (tick, MiB, g_ops, global_stores):")
    for t in r["timeline"][:20]:
        print("   %8d  %8.1f  %9d  %9d" % (t["tick"], t["rss_mib"],
                                           t["g_ops"], t["global_stores"]))
    json.dump(r, open(a.json, "w", encoding="utf-8"), indent=1)
    print("wrote %s" % a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
