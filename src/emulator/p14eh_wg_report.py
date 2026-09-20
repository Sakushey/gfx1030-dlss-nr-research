"""Phase 14E-H §10: 8-wave workgroup runs under MODEL_HW_GFX1030 (and the
legacy MODEL_B baseline) for BOTH streams, with per-case JSON cache.

Cases (run arg = space-free comma list or 'all'):
  ent_legacy      translated gfx1030, MODEL_B value semantics (baseline)
  orig_legacy     original gfx1100,  MODEL_B (baseline)
  ent_u32_16384   MODEL_HW: u32 EA, alloc hyp 16,384, RDNA2 OOB zero/discard
  ent_u32_15872   MODEL_HW: u32 EA, alloc hyp 15,872
  ent_u32_65536   MODEL_HW: u32 EA, alloc hyp 65,536 (whole-CU hypothesis)
  ent_t16_16384   MODEL_HW: trunc16 datapath, alloc hyp 16,384
  orig_u32_16384  original under MODEL_HW (u32, 16,384)
  orig_t16_16384  original under MODEL_HW (trunc16, 16,384)
  *_nonzero       same geometry with deterministic nonzero payloads

Output per case: outcome, ticks, epochs, per-wave {state, steps, barriers,
memviol, oob_read_zero, oob_write_discard}; first OOB samples.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUTD = os.path.join(HERE, "out")
ROOT = os.path.abspath(os.path.join(HERE, ".."))
for p in (HERE, os.path.join(ROOT, "phase14e_static", "tools"),
          os.path.join(ROOT, "phase14eg_tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import p14eh  # noqa: E402

CASES = {
    "ent_legacy":      ("ent", "legacy", 16384, False),
    "orig_legacy":     ("orig", "legacy", 16384, False),
    "ent_u32_16384":   ("ent", "u32", 16384, False),
    "ent_u32_15872":   ("ent", "u32", 15872, False),
    "ent_u32_65536":   ("ent", "u32", 65536, False),
    "ent_t16_16384":   ("ent", "trunc16", 16384, False),
    "orig_u32_16384":  ("orig", "u32", 16384, False),
    "orig_t16_16384":  ("orig", "trunc16", 16384, False),
    "ent_legacy_nz":   ("ent", "legacy", 16384, True),
    "ent_u32_16384_nz": ("ent", "u32", 16384, True),
    "orig_legacy_nz":  ("orig", "legacy", 16384, True),
    "orig_u32_16384_nz": ("orig", "u32", 16384, True),
}


def cache_path(case):
    return os.path.join(OUTD, f"wg_{case}.json")


def run_case(case):
    which, sem, alloc, nz = CASES[case]
    r = p14eh.run_ef(which, label=case, wave_count=8, oob_sem=sem,
                     alloc=alloc, nonzero=nz)
    r["case"] = case
    with open(cache_path(case), "w") as f:
        json.dump(r, f, indent=1, default=str)
    return r


def main():
    want = sys.argv[1].split(",") if len(sys.argv) > 1 else \
        sorted(CASES)
    for case in want:
        if case not in CASES:
            print("unknown case", case)
            continue
        if os.path.exists(cache_path(case)):
            print(case, "cached - skip")
            continue
        print(f"RUN {case} ...", flush=True)
        r = run_case(case)
        per = [(p["wave"], p["state"], p["steps"], p["barriers"],
                p["fault"], p["memviol"], p["oob_read_zero"],
                p["oob_write_discard"]) for p in r["per_wave"]]
        print(f"  {case}: {r['outcome']} ticks={r['ticks']} "
              f"epochs={len(r['barrier_epochs'])}", flush=True)
        print("   per-wave:", per, flush=True)


if __name__ == "__main__":
    main()
