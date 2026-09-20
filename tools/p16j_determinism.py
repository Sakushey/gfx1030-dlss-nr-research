#!/usr/bin/env python3
"""Phase 16J -- deterministic repeat, checked rather than asserted.

The brief requires J2 to show a *deterministic repeat*.  Comparing a run
against itself in the same process would not show that: the interesting
failure is a run that differs between processes (dict ordering, set
iteration, an uninitialised accumulator, a hash seed).  So this compares two
independently produced frozen files.

It is deliberately strict about which fields must match.  The execution
signature, the outcome, the tick count, the fault list, the global gate and
the per-core gate summaries must all be identical.  The canvas digest is
compared on `sha256_full`, not on the sampled `sha256`, so a difference in
bytes the sampler skipped cannot pass as agreement.

usage: p16j_determinism.py <frozen_a.json> <frozen_b.json> [--json out.json]

Host-only.  No GPU.  Nothing frozen is modified.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# `output_digest` gained `sha256_full` partway through this phase, so runs
# from before that edit carry only the sampled `sha256`.  Falling back is
# allowed ONLY when the fallback is provably lossless: `output_digest`
# samples with `step = max(1, n_written // 4096)`, so for `n_written` at or
# below the 4096 sample budget `step == 1` and every written byte is
# already covered.  Above that the fallback silently stops being a full
# comparison, so it is refused rather than quietly used.
SAMPLE_BUDGET = 4096


def canvas_digest(r):
    o = r.get("output") or {}
    if o.get("sha256_full"):
        return o["sha256_full"]
    if o.get("n_written") is not None and o["n_written"] <= SAMPLE_BUDGET:
        return o.get("sha256")
    return None


def canvas_digest_basis(r):
    """Name which digest is being compared, so a weak basis is visible."""
    o = r.get("output") or {}
    if o.get("sha256_full"):
        return "sha256_full"
    if o.get("n_written") is not None and o["n_written"] <= SAMPLE_BUDGET:
        return "sha256 (lossless: n_written <= %d)" % SAMPLE_BUDGET
    return "UNAVAILABLE (sampled digest, n_written > %d)" % SAMPLE_BUDGET


# Fields that must be bit-identical between the two runs, per
# (tag, pattern, core).  Anything not listed here is either a path, a
# timestamp, or a deliberately free value.
COMPARED = [
    ("outcome", lambda r: r.get("outcome")),
    ("ticks", lambda r: r.get("ticks")),
    ("natural_end", lambda r: r.get("natural_end")),
    ("capped", lambda r: r.get("capped")),
    ("faults", lambda r: r.get("faults")),
    ("execution_signature", lambda r: (r.get("execution_signature") or {})
     .get("sha256")),
    ("global_gate", lambda r: (r.get("global") or {}).get("gate")),
    ("global_oob_reads", lambda r: (r.get("global") or {})
     .get("oob_global_reads")),
    ("global_oob_writes", lambda r: (r.get("global") or {})
     .get("oob_global_writes")),
    ("n_unmeasured_global_ops", lambda r: (r.get("global") or {})
     .get("n_unmeasured_global_ops")),
    ("canvas_digest", lambda r: canvas_digest(r)),
    ("canvas_digest_basis", lambda r: canvas_digest_basis(r)),
    ("canvas_n_written", lambda r: (r.get("output") or {}).get("n_written")),
    ("scratch_gate", lambda r: (r.get("scratch") or {}).get("gate")),
    ("scratch_unmeasured", lambda r: (r.get("scratch") or {})
     .get("n_unmeasured")),
    ("scratch_oob_reads", lambda r: (r.get("scratch") or {})
     .get("oob_scratch_reads")),
    ("scratch_oob_writes", lambda r: (r.get("scratch") or {})
     .get("oob_scratch_writes")),
    ("lds_outside_bound", lambda r: (r.get("lds") or {})
     .get("n_rw_outside_declared_bound")),
    ("lds_errors", lambda r: (r.get("lds") or {}).get("errors")),
]


def runs_of(doc):
    """(tag, pattern, core) -> the dispatch record."""
    out = {}
    for tag, tr in (doc.get("results") or {}).items():
        for pat, rec in (tr.get("patterns") or {}).items():
            for core in ("scratch", "lds"):
                if core in rec:
                    out[(tag, pat, core)] = rec[core]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--json", default=None)
    # A repeat run may legitimately cover FEWER patterns than its reference
    # (that is how this check is normally driven: one pattern is enough to
    # test determinism).  Missing runs are a coverage statement, not a
    # mismatch, so they are reported always and fatal only by default.
    ap.add_argument("--allow-subset", action="store_true",
                    help="do not fail when B covers fewer runs than A; "
                         "the reduced coverage is recorded in the output")
    a = ap.parse_args()

    da = json.load(open(a.a, encoding="utf-8"))
    db = json.load(open(a.b, encoding="utf-8"))
    ra, rb = runs_of(da), runs_of(db)

    print("=" * 74)
    print("deterministic repeat: %s  vs  %s"
          % (os.path.basename(a.a), os.path.basename(a.b)))
    print("=" * 74)

    res = {"a": a.a, "b": a.b, "keys": [], "mismatches": [], "ok": True}
    only_a = sorted(set(ra) - set(rb))
    only_b = sorted(set(rb) - set(ra))
    res["only_in_a"] = [list(k) for k in only_a]
    res["only_in_b"] = [list(k) for k in only_b]
    res["subset_allowed"] = bool(a.allow_subset)
    if only_a or only_b:
        print("!! run sets differ: only in A %s ; only in B %s"
              % (only_a, only_b))
        if only_b or not a.allow_subset:
            # A run present only in B means B did MORE than A, which no
            # intentional narrowing explains; and a narrowing that was not
            # declared is not something this tool should wave through.
            res["mismatches"].append({"reason": "run sets differ",
                                      "only_a": only_a, "only_b": only_b})
            res["ok"] = False
        else:
            print("   (--allow-subset: B covers fewer runs than A; the "
                  "compared runs are still required to be identical)")
    else:
        print("run sets: identical (%d runs)" % len(ra))

    for key in sorted(set(ra) & set(rb)):
        tag, pat, core = key
        bad = []
        for name, get in COMPARED:
            va, vb = get(ra[key]), get(rb[key])
            if va != vb:
                bad.append({"field": name, "a": va, "b": vb})
        basis_a = canvas_digest_basis(ra[key])
        basis_b = canvas_digest_basis(rb[key])
        # A digest that could not be established on both sides is not a
        # pass; the canvas comparison would otherwise be None == None.
        if canvas_digest(ra[key]) is None or canvas_digest(rb[key]) is None:
            bad.append({"field": "canvas_digest_basis",
                        "a": basis_a, "b": basis_b,
                        "why": "no full-fidelity canvas digest on both sides"})
        res["keys"].append({"tag": tag, "pattern": pat, "core": core,
                            "compared": len(COMPARED),
                            "canvas_basis_a": basis_a,
                            "canvas_basis_b": basis_b,
                            "mismatches": bad})
        status = "IDENTICAL" if not bad else "DIFFERS"
        print("  %-9s pattern %-2s core %-7s %2d fields  %s"
              % (tag, pat, core, len(COMPARED), status))
        print("      canvas basis: %s" % basis_a)
        for m in bad:
            print("      %-24s A=%s  B=%s"
                  % (m["field"], m["a"], m["b"]))
        if bad:
            res["ok"] = False
            res["mismatches"].append({"tag": tag, "pattern": pat,
                                      "core": core, "fields": bad})

    n = len(res["keys"])
    print("\n%d run(s) compared over %d field(s) each" % (n, len(COMPARED)))
    print("DETERMINISTIC REPEAT: %s"
          % ("IDENTICAL" if res["ok"] else "DIFFERS -- investigate"))
    if a.json:
        os.makedirs(os.path.dirname(os.path.abspath(a.json)), exist_ok=True)
        json.dump(res, open(a.json, "w", encoding="utf-8"), indent=1)
        print("wrote " + a.json)
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
