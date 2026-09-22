#!/usr/bin/env python3
"""Phase 16O Track A -- run ONE cell under ONE source revision, in a fresh
process, and print the provenance the brief requires.

    source-root path
    hashes loaded (of the files ACTUALLY imported, by module __file__)
    MRO
    Candidate hash
    fixture hash

then the measurement: ticks, per-space counters, first OOB PC, result hash.

Exactly one revision tree is prepended to `sys.path`; nothing is imported
from a second revision, and no runtime patch is applied.  The import cache
is asserted to contain no module loaded from outside the revision tree for
the seven edited files.

usage:
  python a_run_rev.py --rev pre16n --tag swin32f
  python a_run_rev.py --rev post16n --tag swin32f
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
OUT = os.path.join(ROOT, "phase16o_final", "a_regression")

REV_DIRS = {
    "post16n": "rev_post16n",
    "pre16n": "rev_pre16n",
    "minus_emu": "rev_minus_emu",
    "minus_p14d8_core": "rev_minus_p14d8_core",
    "minus_p14e_emu": "rev_minus_p14e_emu",
    "minus_p14eh": "rev_minus_p14eh",
    "minus_p16e_rec": "rev_minus_p16e_rec",
    "minus_p16h_scratch_probe": "rev_minus_p16h_scratch_probe",
    "minus_p16j_scratch_isa": "rev_minus_p16j_scratch_isa",
    "harness_fixed": "rev_harness_fixed",
    "harness_fixed_only": "rev_harness_fixed_only",
    "minus_emu_d9only": "rev_minus_emu_d9only",
    "minus_emu_other": "rev_minus_emu_other",
    "minus_emu_other16n": "rev_minus_emu_other16n",
}

# module name -> the revision-tree basename that must supply it
EDIT_MODULES = {
    "emu": "emu.py",
    "p14d8_core": "p14d8_core.py",
    "p14e_emu": "p14e_emu.py",
    "p14eh": "p14eh.py",
    "p16e_rec": "p16e_rec.py",
    "p16h_scratch_probe": "p16h_scratch_probe.py",
    "p16j_scratch_isa": "p16j_scratch_isa.py",
    "p16j_input": "p16j_input.py",
}


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


# Dependency order: a module is registered before the one that imports it.
LOAD_ORDER = ["emu", "p16j_input", "p14d8_core", "p14e_emu", "p14eh",
              "p16e_rec", "p16h_scratch_probe", "p16j_scratch_isa"]


def load_revision(revdir):
    """Register the revision's copies under their own module names."""
    import importlib.util
    for name in LOAD_ORDER:
        path = os.path.join(revdir, name + ".py")
        if not os.path.exists(path):
            raise SystemExit("revision tree is missing %s" % path)
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod          # before exec: cyclic imports resolve
        spec.loader.exec_module(mod)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev", required=True)
    ap.add_argument("--tag", default="swin32f")
    ap.add_argument("--waves", type=int, default=8)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--round-cap", type=int, default=2_000_000)
    ap.add_argument("--pattern", default="A")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    if args.rev not in REV_DIRS:
        raise SystemExit("unknown revision %r" % args.rev)
    revdir = os.path.join(OUT, REV_DIRS[args.rev])
    if not os.path.isdir(revdir):
        raise SystemExit("revision tree missing: %s (run a_build_revs.py)"
                         % revdir)

    # Revdir must end up FIRST.  Every path is inserted at position 0, so
    # the revision tree is inserted LAST -- inserting it first would leave
    # it below all the others and the edited modules would resolve to the
    # live tree instead.
    for p in ("phase16k_pretest/k3_arena", "phase16j_pre_gta/tools",
              "phase16i_closure/tools", "phase16h_pcrel_fix/tools",
              "phase16e_candidate_e/tools", "phase14e_static/tools",
              "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
              "phase14d11_static/tools", "phase14d11_static",
              "phase14d_static/tools",
              "phase8_static/tools", "phase14d8_static/tools"):
        pp = os.path.join(ROOT, p)
        if pp not in sys.path:
            sys.path.insert(0, pp)
    # The edited modules derive their project root from their own location
    # (`ROOT = HERE/../..` for four of them, `HERE/..` for `p14eh`), so a
    # revision tree cannot be a drop-in `sys.path` shadow: the two depths
    # disagree.  They are loaded EXPLICITLY, by file path, and registered
    # under their own module names before anything else can import them, so
    # every transitive `import p14e_emu` resolves to the revision's copy
    # while everything else comes from the live tree.  The only thing a
    # revision tree's wrong ROOT affects is its own `sys.path.insert` calls,
    # which insert directories that do not exist; the real ones are already
    # here.
    load_revision(revdir)

    import p16j_execcache as EC              # noqa: E402
    import p16i_authentic_harness as AH      # noqa: E402

    # ---- provenance -------------------------------------------------
    loaded = {}
    for mod, base in EDIT_MODULES.items():
        m = sys.modules.get(mod)
        if m is None:
            loaded[mod] = {"status": "NOT_IMPORTED"}
            continue
        f = getattr(m, "__file__", None)
        loaded[mod] = {
            "file": os.path.relpath(f, ROOT) if f else None,
            "from_revision_tree": bool(f) and os.path.abspath(f).startswith(
                os.path.abspath(revdir)),
            "sha256": sha256_file(f) if f and os.path.exists(f) else None,
        }
    outside = [m for m, v in loaded.items()
               if v.get("file") and not v.get("from_revision_tree")]
    if outside:
        raise SystemExit(
            "PROVENANCE FAILURE: %s resolved outside the revision tree %s"
            % (outside, revdir))

    mro = [c.__name__ for c in EC.BothCore.__mro__]
    cand = os.path.join(ROOT,
                        "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co")
    cand_hash = sha256_file(cand)
    fixture = os.path.join(ROOT, "phase16_authentic_decode_swin.csv")
    fixture_hash = sha256_file(fixture)

    # `EC.semantics_hash()` hashes the LIVE files, so it would be identical
    # for every revision -- useless as a revision identity.  Build one over
    # the sources ACTUALLY loaded: the edited files from this tree, the rest
    # from the live tree.  This is the hash a cache key must be built from.
    h = hashlib.sha256()
    for rel in sorted(EC.SEMANTICS_SOURCES):
        base = os.path.basename(rel)
        if base in EDIT_MODULES.values():
            p = os.path.join(revdir, base)
        else:
            p = os.path.join(ROOT, rel)
        h.update(rel.encode())
        h.update(b"\0")
        h.update((sha256_file(p) if os.path.exists(p) else "<absent>")
                 .encode())
        h.update(b"\n")
    revision_semantics = h.hexdigest()

    provenance = {
        "revision": args.rev,
        "revision_semantics_hash": revision_semantics,
        "live_tree_semantics_hash": EC.semantics_hash(),
        "source_root": os.path.relpath(revdir, ROOT),
        "absolute_source_root": revdir,
        "hashes_loaded": loaded,
        "mro": mro,
        "candidate_co": os.path.relpath(cand, ROOT),
        "candidate_sha256": cand_hash,
        "fixture_csv": os.path.relpath(fixture, ROOT),
        "fixture_sha256": fixture_hash,
        "semantics_hash": revision_semantics,
    }
    print("=== revision %s ===" % args.rev)
    print("source-root : %s" % provenance["source_root"])
    for m, v in sorted(loaded.items()):
        print("   %-24s %s  %s" % (m, (v.get("sha256") or "-")[:16],
                                   v.get("file")))
    print("MRO         : %s" % " -> ".join(mro))
    print("candidate   : %s  %s" % (cand_hash[:16], args.tag))
    print("fixture     : %s" % fixture_hash[:16])
    print("semantics   : %s  (revision)" % revision_semantics[:16])

    cache = os.path.join(OUT, "out",
                         "cache_%s_%s" % (args.rev, revision_semantics[:12]))
    t0 = time.time()
    art, cached = EC.execute(args.tag, args.pattern, args.waves,
                             args.region_mib, args.round_cap, cache,
                             use_cache=True, verbose=False)
    wall = time.time() - t0

    gc = art["counters"]["global"]
    first_site = None
    ggate = None
    for k in sorted(gc):
        pass
    rec = {
        "schema": "phase16o-a-revision-run/1", "phase": "16O", "track": "A1",
        "host_only": True, "gpu_execution_performed": False,
        "gta_launched": False, "currently_armed": False,
        "tag": args.tag, "pattern": args.pattern, "waves": args.waves,
        "region_mib": args.region_mib, "from_cache": cached,
        "wall_s": round(wall, 1),
        "provenance": provenance,
        "ticks": art["ticks"], "outcome": art["outcome"],
        "faults": art.get("faults") or [],
        "natural_end": art.get("natural_end"),
        "capped": art.get("capped"),
        "gates": art["gates"], "all_gates_pass": all(art["gates"].values()),
        "gate_failures": [k for k, v in art["gates"].items() if not v],
        "execution_signature": art["execution_signature"]["sha256"],
        "global_counters": gc,
        "lds_counters": {k: v for k, v in art["counters"]["lds"].items()
                         if k != "counts"},
        "scratch_counters": art["counters"]["scratch"],
        "output_digest": art.get("output"),
        "cache_key": art["cache_key"],
    }
    out = args.out or os.path.join(OUT, "out",
                                   "REV_%s_%s.json" % (args.rev, args.tag))
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)

    print("ticks=%-8s gates=%-5s oob_r=%-7s oob_w=%-7s sig=%s"
          % (rec["ticks"], "PASS" if rec["all_gates_pass"] else "FAIL",
             gc.get("oob_global_reads"), gc.get("oob_global_writes"),
             rec["execution_signature"][:16]))
    print("wrote %s" % out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
