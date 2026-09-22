#!/usr/bin/env python3
"""Phase 16H — P1 (end of phase): recompute every frozen hash.

`evidence_manifest.json` records a sha256 for every artefact Phase 16H
depends on, taken at the start of the phase.  The brief requires those
hashes to be recomputed at the END of the phase: any change means an
artefact was mutated, and the Phase-16H constraints forbid mutating the
reference module or Candidate E.

This tool recomputes each entry, reports every mismatch, and writes the
result back into the manifest under `verification["end"]`.  It never
writes to any frozen artefact.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p16h_lib as L  # noqa: E402

MANIFEST = os.path.join(L.P16H, "evidence_manifest.json")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def entries(node, out):
    if isinstance(node, dict):
        if "path" in node and "sha256" in node:
            out.append(node)
        else:
            for v in node.values():
                entries(v, out)
    elif isinstance(node, list):
        for v in node:
            entries(v, out)


def main():
    man = json.load(open(MANIFEST, encoding="utf-8"))
    frozen = man["frozen"]

    recs = []
    entries(frozen, recs)

    unchanged, changed, missing = [], [], []
    for r in recs:
        p = os.path.join(L.ROOT, r["path"])
        if not os.path.exists(p):
            missing.append(r["path"])
            continue
        now = sha(p)
        if now == r["sha256"]:
            unchanged.append(r["path"])
        else:
            changed.append({"path": r["path"], "start": r["sha256"],
                            "end": now})

    print("=" * 74)
    print("P1 end-of-phase freeze verification")
    print("=" * 74)
    print("  entries hashed at start : %d" % len(recs))
    print("  unchanged at end        : %d" % len(unchanged))
    print("  CHANGED                 : %d" % len(changed))
    print("  missing                 : %d" % len(missing))
    for c in changed:
        print("     CHANGED %s" % c["path"])
        print("        start %s" % c["start"])
        print("        end   %s" % c["end"])
    for m in missing:
        print("     MISSING %s" % m)

    ok = not changed and not missing
    print("\n  VERDICT: %s" % ("NO FROZEN ARTEFACT WAS MUTATED"
                               if ok else "MUTATION DETECTED"))

    man.setdefault("verification", {})
    man["verification"]["end"] = {
        "n_entries": len(recs),
        "n_unchanged": len(unchanged),
        "n_changed": len(changed),
        "n_missing": len(missing),
        "changed": changed,
        "missing": missing,
        "verdict": ("NO_FROZEN_ARTEFACT_MUTATED" if ok
                    else "MUTATION_DETECTED"),
    }
    json.dump(man, open(MANIFEST, "w", encoding="utf-8"), indent=1)
    print("  updated", MANIFEST)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
