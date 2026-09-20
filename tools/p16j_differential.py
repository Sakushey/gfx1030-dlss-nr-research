#!/usr/bin/env python3
"""Phase 16J -- differential test: does a faster emulator change any answer?

An optimisation is only safe if it is invisible in the results.  This
re-runs a dispatch with the CURRENT emulator and compares the resulting
record, field by field and recursively, against a record that was produced
by the emulator as it stood BEFORE the change.  The comparison is against a
persisted artifact, not against a second run of the same code -- two runs of
one implementation agreeing proves determinism, not equivalence.

Nothing is excluded from the comparison.  The per-run records carry no
paths, timestamps or other free fields, so a difference anywhere is a real
difference.  If that stops being true this tool must gain an exclusion list
rather than a tolerance.

Sources of the reference record:
  --from-frozen <file>     a per-run JSON written by the driver
  --from-aggregate <file>  a `p16j_<job>_frozen.json`, indexed by
                           results[tag]["patterns"][pattern][core]

usage:
  p16j_differential.py --from-frozen phase16j_pre_gta/out/p16j_j4_swin32t_A_scratch.json \
      --tag swin32t --pattern A --core scratch --waves 8

Host-only.  No GPU.  Writes only under --outdir.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import p16j_j2_freeze as J                # noqa: E402


def deep_diff(x, y, path=""):
    """Every leaf that differs, with its path.  No tolerance, no exclusions."""
    if type(x) is not type(y):
        return [(path or "/", "%s %r" % (type(x).__name__, x),
                 "%s %r" % (type(y).__name__, y))]
    if isinstance(x, dict):
        out = []
        # Keys are not all one type: the gate records address-keyed maps
        # alongside name-keyed ones, and a bare `sorted` over the union
        # raises `TypeError: '<' not supported between 'int' and 'str'`.
        # Sorting on a type-tagged string key keeps the walk total, and the
        # order only has to be deterministic, not meaningful.
        keys = sorted(set(x) | set(y),
                      key=lambda k: (type(k).__name__, str(k)))
        for k in keys:
            # The path is a report label, so a non-string key (address-keyed
            # gate maps) is stringified rather than concatenated.
            kp = path + "/" + str(k)
            if k not in x:
                out.append((kp, "<absent>", repr(y[k])))
            elif k not in y:
                out.append((kp, repr(x[k]), "<absent>"))
            else:
                out += deep_diff(x[k], y[k], kp)
        return out
    if isinstance(x, list):
        out = []
        if len(x) != len(y):
            out.append((path + "/len", str(len(x)), str(len(y))))
        for i, (u, v) in enumerate(zip(x, y)):
            out += deep_diff(u, v, "%s[%d]" % (path, i))
        return out
    if x != y:
        return [(path or "/", repr(x), repr(y))]
    return []


def reference(frozen, aggregate, tag, pattern, core):
    if frozen:
        return json.load(open(frozen, encoding="utf-8"))
    doc = json.load(open(aggregate, encoding="utf-8"))
    return doc["results"][tag]["patterns"][pattern][core]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-frozen", default=None)
    ap.add_argument("--from-aggregate", default=None)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--pattern", required=True)
    ap.add_argument("--core", required=True, choices=("scratch", "lds"))
    ap.add_argument("--waves", type=int, default=8)
    ap.add_argument("--round-cap", type=int, default=2000000)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--outdir", default=os.path.join(
        ROOT, "phase16j_pre_gta/out/prof"))
    ap.add_argument("--json", default=None)
    a = ap.parse_args()
    if not (a.from_frozen or a.from_aggregate):
        print("need --from-frozen or --from-aggregate")
        return 2

    os.makedirs(a.outdir, exist_ok=True)
    ref = reference(a.from_frozen, a.from_aggregate, a.tag, a.pattern, a.core)

    # Compare FILE to FILE, not file to return value.  `dispatch` writes the
    # harness's full summary to `out_path` and separately returns a reduced
    # dict; comparing the reference file against that reduced return reports
    # a difference in shape (every key the reduction drops, plus every key
    # the reduction adds) as if it were a difference in results.  It did
    # exactly that: 52 "differences" that were all shape.
    got_path = os.path.join(a.outdir, "p16j_diff_%s_%s_%s.json"
                            % (a.tag, a.pattern, a.core))
    t0 = time.perf_counter()
    J.dispatch(a.tag, a.pattern, a.core, a.region_mib, a.waves,
               a.round_cap, got_path)
    wall = time.perf_counter() - t0
    got = json.load(open(got_path, encoding="utf-8"))

    diffs = deep_diff(ref, got)
    print("=" * 78)
    print("differential: %s pattern %s core %s  (%d waves, %.1fs)"
          % (a.tag, a.pattern, a.core, a.waves, wall))
    print("=" * 78)
    print("  ticks   ref=%s  got=%s" % (ref.get("ticks"), got.get("ticks")))
    print("  outcome ref=%s  got=%s" % (ref.get("outcome"), got.get("outcome")))
    print("  fields differing: %d" % len(diffs))
    for p, x, y in diffs[:40]:
        print("    %-40s ref=%s" % (p, x[:90]))
        print("    %-40s got=%s" % ("", y[:90]))
    print("DIFFERENTIAL: %s" % ("EQUIVALENT" if not diffs else "DIFFERS"))
    if a.json:
        json.dump({"tag": a.tag, "pattern": a.pattern, "core": a.core,
                   "waves": a.waves, "wall_s": wall,
                   "n_diff": len(diffs),
                   "diffs": [{"path": p, "ref": x, "got": y}
                             for p, x, y in diffs],
                   "equivalent": not diffs},
                  open(a.json, "w", encoding="utf-8"), indent=1)
        print("wrote " + a.json)
    return 0 if not diffs else 1


if __name__ == "__main__":
    sys.exit(main())
