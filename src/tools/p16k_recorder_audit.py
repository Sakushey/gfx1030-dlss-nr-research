#!/usr/bin/env python3
"""Phase 16K-K1 -- find every accumulator on the production core, by
measurement rather than by reading.

Two passes:

  STATIC   walks `BothCore.__mro__`, and for each class in it finds
           `self.<name> = []` / `= {}` in `__init__` and every
           `self.<name>.append(...)` / `[...] = ...` call site.  This says
           what COULD accumulate.

  RUNTIME  builds the real production core, runs a dispatch, and samples
           `len()` of every container attribute on the core at intervals.
           This says what DOES accumulate, and by how much per tick.

The second pass is the one that decides.  A static census cannot tell a
list that is drained per dispatch from one that is not, and getting that
wrong is exactly how `g_ops` survived the earlier leak work: it was created
in a different module from the one being audited.

Host-only.  No GPU.
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
          "phase14d8_static/tools", "phase16j_pre_gta/tools"):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)

import p16j_execcache as EC     # noqa: E402
import p16i_authentic_harness as AH  # noqa: E402
import p16j_input as IN         # noqa: E402
import p16j_scratch_isa as SI   # noqa: E402
import p16i_lds_descriptor as LD  # noqa: E402
import p16i_isa as ISA         # noqa: E402
import p16i_scratch_close as SC  # noqa: E402
import p16h_scratch_probe as SP  # noqa: E402

INIT_RE = re.compile(r"self\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\[\]|\{\})")
APPEND_RE = re.compile(r"self\.([A-Za-z_][A-Za-z0-9_]*)\.append\s*\(")


def static_census():
    """Per class in the production MRO: containers created, and append sites."""
    out = {}
    for cls in EC.BothCore.__mro__:
        mod = sys.modules.get(cls.__module__)
        path = getattr(mod, "__file__", None)
        if not path or not os.path.exists(path):
            continue
        src = open(path, encoding="utf-8", errors="replace").read()
        # Only the class body: slice from the class statement to the next
        # top-level `class ` / `def ` at column 0.
        m = re.search(r"^class\s+%s\b" % re.escape(cls.__name__), src, re.M)
        if not m:
            continue
        rest = src[m.end():]
        nxt = re.search(r"^(class|def)\s", rest, re.M)
        body = rest[:nxt.start()] if nxt else rest
        created = sorted(set(INIT_RE.findall(body)))
        appended = sorted(set(APPEND_RE.findall(body)))
        # own __init__ / _record_ds / step ownership, from the class dict
        out[cls.__name__] = {
            "module": cls.__module__,
            "file": os.path.relpath(path, ROOT),
            "containers_created": [c[0] for c in created],
            "append_sites": appended,
            "owns": [k for k in ("__init__", "step", "_record_ds", "_gl_addr",
                                 "_scratch_xfer", "_xfer", "vget", "vset")
                     if k in cls.__dict__],
        }
    return out


def _containers(core):
    """Every list/dict/set attribute on the core, with its current length."""
    out = {}
    for name in dir(core):
        if name.startswith("__"):
            continue
        try:
            v = getattr(core, name)
        except Exception:                                  # noqa: BLE001
            continue
        if isinstance(v, (list, dict, set)):
            try:
                out[name] = len(v)
            except Exception:                              # noqa: BLE001
                out[name] = -1
    return out


def runtime_probe(tag="swin32f", gen_name="A", waves=1, region_mib=64,
                  round_cap=2000000, sample_ticks=(1, 50, 200, 1000, 3000)):
    """Run a real dispatch and sample every container length over time."""
    import p14eh
    from p14eh import HWCore

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

    # Sample from inside the run: `RecCore.step` is the production `step`,
    # so wrapping the *instance* is enough to observe the core as it runs.
    samples = []
    seen = {}

    def probe(core, tick):
        cur = _containers(core)
        for k, v in cur.items():
            seen[k] = v
        samples.append({"tick": tick, "containers": cur})

    import p14d11_emu as P11
    orig_step = P11.RecCore.step

    class _Probe:
        pass

    state = {"n": 0}

    def step_wrapper(self):
        state["n"] += 1
        if state["n"] in sample_ticks:
            probe(self, state["n"])
        return orig_step(self)

    P11.RecCore.step = step_wrapper
    try:
        fill = IN.make_fill(vals, canvas, tensor, gen_name=gen_name)
        holder = {}

        def fill_hook(mem):
            pm = IN.PatternMem(mem, IN.regions_for(vals, canvas, tensor),
                               gen=IN.GENERATORS[gen_name])
            holder["mem"] = pm
            return pm

        r = AH.run(tag, csv, None, None, waves, region_mib, round_cap,
                   os.path.join(HERE, "..", "out",
                                "_audit_raw_%s.json" % tag),
                   core_cls=core_cls, fill_payload=fill_hook)
    finally:
        P11.RecCore.step = orig_step
        SI.ScrtISACore.scrt_close = None

    return {"tag": tag, "waves": waves, "outcome": str(r["outcome"]),
            "ticks": r.get("ticks"), "samples": samples,
            "final_containers": seen,
            "group_segment": gs, "private_segment": psz}


def growth_report(probe):
    """Which containers grew, and by how much per sampled tick."""
    s = probe["samples"]
    if len(s) < 2:
        return {}
    first, last = s[0]["containers"], s[-1]["containers"]
    t0, t1 = s[0]["tick"], s[-1]["tick"]
    out = {}
    for k in sorted(set(first) | set(last)):
        a, b = first.get(k, 0), last.get(k, 0)
        if b == a:
            continue
        out[k] = {"at_tick_%d" % t0: a, "at_tick_%d" % t1: b,
                  "delta": b - a,
                  "per_tick": round((b - a) / max(1, t1 - t0), 4)}
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="swin32f")
    ap.add_argument("--waves", type=int, default=1)
    ap.add_argument("--pattern", default="A")
    ap.add_argument("--out", default=os.path.join(
        ROOT, "phase16k_pretest/out/k1_recorder_audit.json"))
    a = ap.parse_args()

    print("=" * 78)
    print("K1 -- accumulator audit of the production core")
    print("=" * 78)
    print("production MRO (read from BothCore.__mro__, not inferred):")
    for c in EC.BothCore.__mro__:
        print("   %-34s %s" % (c.__module__ + "." + c.__name__,
                               ",".join(k for k in
                                        ("__init__", "step", "_record_ds",
                                         "_gl_addr") if k in c.__dict__)))

    st = static_census()
    print("\nSTATIC census -- containers created and append sites:")
    for name, d in st.items():
        if not d["containers_created"] and not d["append_sites"]:
            continue
        print("  %-14s %s" % (name, d["file"]))
        print("      creates: %s" % (d["containers_created"] or "-"))
        print("      appends: %s" % (d["append_sites"] or "-"))

    print("\nRUNTIME probe: %s pattern %s, %d wave(s)"
          % (a.tag, a.pattern, a.waves))
    pr = runtime_probe(a.tag, a.pattern, a.waves)
    print("  outcome=%s ticks=%s" % (pr["outcome"], pr["ticks"]))
    gr = growth_report(pr)
    print("  containers that GREW during the run:")
    if not gr:
        print("     (none)")
    for k, v in sorted(gr.items(), key=lambda kv: -kv[1]["delta"]):
        print("     %-22s %s  (+%d over %d ticks, %.2f/tick)"
              % (k, {kk: vv for kk, vv in v.items()
                     if kk.startswith("at_")}, v["delta"],
                 max(1, pr["samples"][-1]["tick"] - pr["samples"][0]["tick"]),
                 v["per_tick"]))
    print("\n  ALL container lengths at end of run:")
    for k, v in sorted(pr["final_containers"].items(), key=lambda kv: -kv[1]):
        print("     %-22s %d" % (k, v))

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump({"mro": [c.__module__ + "." + c.__name__
                       for c in EC.BothCore.__mro__],
               "static": st, "probe": pr, "growth": gr},
              open(a.out, "w", encoding="utf-8"), indent=1)
    print("\nwrote %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
