#!/usr/bin/env python3
"""Phase 16I-1 -- evidence-manifest hygiene.

THE DEFECT

`phase16h_pcrel_fix/evidence_manifest.json` froze `SESSION_REPORT.md` under
the key `phase16g_report`.  But `SESSION_REPORT.md` is a *living* file: the
project's standing instruction (CLAUDE.md) is to refresh it with the newest
session report at the end of every session.  Freezing a file the workflow
guarantees will change makes the end-of-phase verdict permanently
`MUTATION_DETECTED` for exactly one expected entry, which trains the reader
to ignore the verdict.  Phase 16H's own verification block shows this:

    n_entries 145, n_unchanged 144, n_changed 1,
    changed: [SESSION_REPORT.md], verdict: MUTATION_DETECTED

THE FIX

1. Snapshot the report as it stands now under an immutable, phase-specific
   name: `phase16h_pcrel_fix/phase16h_report.md`.  This preserves the
   Phase-16H deliverable byte-for-byte.
2. Repoint the frozen entry at the snapshot and drop the live
   `SESSION_REPORT.md` from the frozen set entirely.
3. Record the retired entry, with both of its historical hashes, so the
   fact that the live file drifted is not erased.
4. Recompute every frozen hash and write the verdict.  A correct result is
   `NO_FROZEN_ARTEFACT_MUTATED` with zero changed entries.

Idempotent: re-running leaves an already-correct manifest untouched.

Usage:
  p16i_manifest_hygiene.py [--apply]      (default: dry run)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
P16H = os.path.join(ROOT, "phase16h_pcrel_fix")
MANIFEST = os.path.join(P16H, "evidence_manifest.json")
LIVE = os.path.join(ROOT, "SESSION_REPORT.md")
SNAPSHOT = os.path.join(P16H, "phase16h_report.md")
SNAPSHOT_REL = "phase16h_pcrel_fix/phase16h_report.md"
OLD_KEY = "phase16g_report"
NEW_KEY = "phase16h_report"


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def walk(node, out):
    if isinstance(node, dict):
        if "path" in node:
            out.append(node)
        else:
            for v in node.values():
                walk(v, out)
    elif isinstance(node, list):
        for v in node:
            walk(v, out)


def ent(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        return dict(path=rel, exists=False)
    return dict(path=rel, exists=True, size=os.path.getsize(p), sha256=sha(p))


def verify(man):
    recs = []
    walk(man["frozen"], recs)
    unchanged, changed, missing = [], [], []
    for r in recs:
        p = os.path.join(ROOT, r["path"])
        if not os.path.exists(p):
            missing.append(r["path"])
            continue
        cur = sha(p)
        if cur == r.get("sha256"):
            unchanged.append(r["path"])
        else:
            changed.append({"path": r["path"],
                            "frozen": r.get("sha256"), "now": cur})
    ok = not changed and not missing
    return {"n_entries": len(recs), "n_unchanged": len(unchanged),
            "n_changed": len(changed), "n_missing": len(missing),
            "changed": changed, "missing": missing,
            "verdict": "NO_FROZEN_ARTEFACT_MUTATED" if ok
                       else "MUTATION_DETECTED"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()

    man = json.load(open(MANIFEST, encoding="utf-8"))
    frozen = man["frozen"]

    already = NEW_KEY in frozen and OLD_KEY not in frozen
    if already:
        print("manifest already hygienic (%s present, %s absent)"
              % (NEW_KEY, OLD_KEY))
    else:
        old = frozen.get(OLD_KEY)
        if not old or old.get("path") != "SESSION_REPORT.md":
            sys.exit("unexpected manifest shape: %s = %r" % (OLD_KEY, old))
        live_now = ent("SESSION_REPORT.md")
        print("live SESSION_REPORT.md  sha256=%s" % live_now["sha256"])
        print("frozen  entry %s     sha256=%s" % (OLD_KEY, old.get("sha256")))
        if os.path.exists(SNAPSHOT):
            s = sha(SNAPSHOT)
            print("snapshot already exists sha256=%s" % s)
            if s != live_now["sha256"]:
                sys.exit("REFUSING: %s exists with different content; the "
                         "immutable snapshot must never be overwritten"
                         % SNAPSHOT_REL)
        else:
            print("would create %s (copy of the current report)" % SNAPSHOT_REL)

        if a.apply:
            if not os.path.exists(SNAPSHOT):
                shutil.copyfile(LIVE, SNAPSHOT)
            man.setdefault("retired_frozen_entries", {})[OLD_KEY] = {
                "reason": ("SESSION_REPORT.md is a living file (CLAUDE.md: "
                           "refreshed every session); freezing it guarantees "
                           "MUTATION_DETECTED"),
                "retired_at": "phase16i",
                "live_path": "SESSION_REPORT.md",
                "sha256_at_16h_start": (man.get("verification", {})
                                        .get("end", {}).get("changed", [{}])[0]
                                        .get("start")),
                "sha256_at_16h_end": old.get("sha256"),
                "replaced_by": SNAPSHOT_REL,
            }
            del frozen[OLD_KEY]
            frozen[NEW_KEY] = ent(SNAPSHOT_REL)
            print("applied: %s -> %s" % (OLD_KEY, SNAPSHOT_REL))

    v = verify(man)
    print("\nverification: %d entries, %d unchanged, %d changed, %d missing"
          % (v["n_entries"], v["n_unchanged"], v["n_changed"], v["n_missing"]))
    for c in v["changed"]:
        print("   CHANGED %s\n     frozen %s\n     now    %s"
              % (c["path"], c["frozen"], c["now"]))
    for m in v["missing"]:
        print("   MISSING %s" % m)
    print("verdict: %s" % v["verdict"])

    if a.apply:
        man.setdefault("verification", {})["end_16i"] = v
        json.dump(man, open(MANIFEST, "w", encoding="utf-8"), indent=1)
        print("wrote %s" % os.path.relpath(MANIFEST, ROOT))
    else:
        print("\n(dry run -- pass --apply to write)")
    return 0 if v["verdict"] == "NO_FROZEN_ARTEFACT_MUTATED" else 1


if __name__ == "__main__":
    sys.exit(main())
