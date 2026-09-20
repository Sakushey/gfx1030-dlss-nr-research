#!/usr/bin/env python3
"""Phase 16J -- how many concurrent producers actually help?

The addendum asks for process-level parallelism, up to 4 heavy producers
initially and 5 then 6 only if RAM stays comfortably below 75%, Windows
stays responsive, and **total ticks/sec actually improves**.  This measures
exactly that and nothing else.

Method: pick one work unit (a real dispatch), run N copies of it as separate
processes, and measure the wall clock for all N to finish.  Throughput is
sum(ticks)/wall.  Identical units, so a rise in aggregate ticks/sec is a
real gain rather than a mix of differently-sized jobs.

The unit is small on purpose.  Measuring at the production size would take
hours per level; the shape of the curve (where it stops scaling) is a
property of the machine, not of the unit's size.

Guards, per the addendum: a level is refused if system memory use would
exceed 75%, and the run records the machine's memory state throughout.

usage:
  p16j_throughput.py --levels 1,2,4,6 --unit swin32t:A:scratch --waves 8

Host-only.  No GPU.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


def mem_load_pct():
    """System memory load, 0-100, straight from the OS."""
    st = MEMORYSTATUSEX()
    st.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st))
    return st.dwMemoryLoad


CHILD = r"""
import json, os, sys, time
sys.path.insert(0, r"{here}")
import p16j_j2_freeze as J
tag, pat, core = "{tag}", "{pat}", "{core}"
t0 = time.perf_counter()
r = J.dispatch(tag, pat, core, {region_mib}, {waves}, {round_cap}, r"{out}")
print(json.dumps({{"ticks": r["ticks"], "wall": time.perf_counter() - t0}}))
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--unit", default="swin32t:A:scratch")
    ap.add_argument("--levels", default="1,2,4,6")
    ap.add_argument("--waves", type=int, default=8)
    ap.add_argument("--round-cap", type=int, default=2000000)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--outdir", default=os.path.join(
        ROOT, "phase16j_pre_gta/out/prof/throughput"))
    ap.add_argument("--json", default=None)
    a = ap.parse_args()

    tag, pat, core = a.unit.split(":")
    os.makedirs(a.outdir, exist_ok=True)
    levels = [int(x) for x in a.levels.split(",") if x.strip()]

    print("=" * 78)
    print("concurrency throughput: unit=%s waves=%d levels=%s"
          % (a.unit, a.waves, levels))
    print("=" * 78)

    doc = {"unit": a.unit, "waves": a.waves, "levels": [],
           "mem_load_before": mem_load_pct()}
    print("system memory load before: %d%%" % doc["mem_load_before"])

    base_tps = None
    for n in levels:
        before = mem_load_pct()
        if before >= 75:
            print("  level %d REFUSED: memory load %d%% >= 75%%" % (n, before))
            doc["levels"].append({"n": n, "refused": True, "mem_load": before})
            continue

        peak = [before]
        stop = threading.Event()

        def sampler():
            while not stop.wait(0.5):
                peak[0] = max(peak[0], mem_load_pct())

        th = threading.Thread(target=sampler, daemon=True)
        th.start()

        procs = []
        for i in range(n):
            src = CHILD.format(here=HERE, tag=tag, pat=pat, core=core,
                               region_mib=a.region_mib, waves=a.waves,
                               round_cap=a.round_cap,
                               out=os.path.join(a.outdir, "unit_%d_%d.json"
                                                % (n, i)))
            procs.append(subprocess.Popen([sys.executable, "-c", src],
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL,
                                          text=True))

        t0 = time.perf_counter()
        ticks, walls = [], []
        for p in procs:
            out, _ = p.communicate()
            try:
                d = json.loads(out.strip().splitlines()[-1])
                ticks.append(d["ticks"])
                walls.append(d["wall"])
            except Exception:                            # noqa: BLE001
                pass
        wall = time.perf_counter() - t0
        stop.set()
        th.join(timeout=2)

        tps = (sum(ticks) / wall) if wall else 0.0
        if base_tps is None:
            base_tps = tps
        print("  n=%-2d wall=%7.2fs  ticks=%9d  ticks/sec=%9.0f  "
              "speedup=%4.2fx  peak_mem=%d%%  ok=%d/%d"
              % (n, wall, sum(ticks), tps, tps / base_tps if base_tps else 0,
                 peak[0], len(ticks), n))
        doc["levels"].append({"n": n, "wall_s": wall, "ticks": sum(ticks),
                              "ticks_per_sec": tps,
                              "speedup_vs_n1": tps / base_tps if base_tps else None,
                              "peak_mem_load_pct": peak[0],
                              "children_ok": len(ticks), "children": n,
                              "child_walls": walls})

    doc["mem_load_after"] = mem_load_pct()
    if a.json:
        json.dump(doc, open(a.json, "w", encoding="utf-8"), indent=1)
        print("wrote " + a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
