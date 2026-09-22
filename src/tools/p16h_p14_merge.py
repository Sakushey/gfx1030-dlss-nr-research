#!/usr/bin/env python3
"""Phase 16H — P14: assemble the canonical SWIN-closure results file.

`p16h_p14_variants.py` read-modify-writes one JSON per variant, so
concurrent runs must write to separate files (`P14_OUT_NAME`).  This
merges those files into the canonical `out/p14_variants.json`.

Later sources win, and the merge is recorded in the output under
`_provenance` so the assembled file states where each entry came from
rather than presenting a merged result as if it were written in one pass.

Host-only; reads and writes JSON, executes nothing.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p16h_lib as L  # noqa: E402

ORDER = ["swin32f", "swin32t", "swin64f", "swin128f", "swin256f"]


def main():
    out = os.path.join(L.P16H, "out")
    # earliest first, so later (more authoritative) sources win
    sources = sys.argv[1:] or [
        "p14_variants.json",
        "p14_variants_regen.json",
        "p14_variants_128f.json",
    ]
    merged = {}
    provenance = {}
    for name in sources:
        p = os.path.join(out, name)
        if not os.path.exists(p):
            print("  skip (absent): %s" % name)
            continue
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception as exc:
            print("  skip (unreadable: %s): %s" % (exc, name))
            continue
        n = 0
        for k, v in d.items():
            if k.startswith("_"):
                continue
            merged[k] = v
            provenance[k] = name
            n += 1
        print("  merged %d entr%s from %s" % (n, "y" if n == 1 else "ies",
                                              name))

    missing = [t for t in ORDER if t not in merged]
    extra = [k for k in merged if k not in ORDER]
    merged["_provenance"] = provenance

    dest = os.path.join(out, "p14_variants.json")
    json.dump(merged, open(dest, "w", encoding="utf-8"), indent=1,
              default=str)

    print("\nwrote %s" % dest)
    print("variants present: %s" % ", ".join(t for t in ORDER
                                             if t in merged))
    if missing:
        print("MISSING: %s" % ", ".join(missing))
    if extra:
        print("UNEXPECTED keys: %s" % ", ".join(extra))
    for t in ORDER:
        v = merged.get(t)
        if not v:
            continue
        if v.get("run_failed"):
            print("  %-10s RUN FAILED %s" % (t, str(v["run_failed"])[:60]))
            continue
        la = v.get("lds_agg") or {}
        print("  %-10s %-22s lds_memviol=%-9s lds_agg=%s"
              % (t, v.get("outcome"), v.get("lds", {}).get("memviol"),
                 la.get("by_bucket", "-")))
    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main())
