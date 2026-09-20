"""Summarize the cached §10 workgroup-matrix runs into the compare table
rows used by phase14eh_hwmodel_workgroup_compare.md."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUTD = os.path.join(HERE, "out")
CASES = ["ent_legacy", "orig_legacy", "ent_u32_16384", "ent_u32_15872",
         "ent_u32_65536", "ent_t16_16384", "orig_u32_16384",
         "orig_t16_16384", "ent_legacy_nz", "ent_u32_16384_nz",
         "orig_u32_16384_nz"]

for c in CASES:
    p = os.path.join(OUTD, f"wg_{c}.json")
    if not os.path.exists(p):
        print(f"{c:18s} (not run)")
        continue
    r = json.load(open(p))
    o = r["outcome"]
    oo = o[0] if isinstance(o, list) else o
    waves = r["per_wave"]
    steps = [w["steps"] for w in waves]
    mv = sum(w["memviol"] for w in waves)
    oobr = sum(w["oob_read_zero"] for w in waves)
    oobw = sum(w["oob_write_discard"] for w in waves)
    faulted = [w["wave"] for w in waves if w["state"] != "ENDED"]
    print(f"{c:18s} out={oo:28s} ticks={r['ticks']:6d} "
          f"epochs={len(r['barrier_epochs']):2d} "
          f"steps={min(steps)}..{max(steps)} "
          f"memviol={mv} oobR={oobr} oobW={oobw} "
          f"not_ended={faulted or '-'}")
