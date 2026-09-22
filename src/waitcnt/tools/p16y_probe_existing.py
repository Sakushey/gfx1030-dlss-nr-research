#!/usr/bin/env python3
"""Bounded read of the existing frozen J3 trace artifact (host-only).

Reports the fields the 16Y-WAITCNT brief quotes as ground truth so each can be
re-verified rather than trusted.
"""
import json
import os
import sys

ROOT = r"<PROJECT_ROOT>"
d = json.load(open(os.path.join(ROOT, "phase16t", "j3", "out",
                               "j3_revision.json"), encoding="utf-8"))
print("KEYS", sorted(d.keys()))
for k in ("ticks", "natural_end", "outcome", "capped", "by_pc_n",
          "n_ended", "n_faulted", "diverged", "control_flow_signature",
          "candidate_sha256", "wall_s"):
    print("%s = %s" % (k, d.get(k)))
print("PER_WAVE", json.dumps(d.get("per_wave"), indent=1)[:2000])
be = d.get("barrier_epochs")
print("BARRIER_EPOCHS type=%s len=%s" % (type(be).__name__,
                                         len(be) if hasattr(be, "__len__") else "?"))
print("BARRIER_EPOCHS", json.dumps(be)[:1500])
print("MODULES", json.dumps({k: v.get("file") for k, v in
                             d.get("modules_loaded", {}).items()}, indent=1))
