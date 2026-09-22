#!/usr/bin/env python3
"""Phase 16T -- run the Phase 16S instruction oracle vectors against a chosen
emulator source revision, in a fresh process.

WHY A NEW TOOL AND NOT A FLAG ON `build_oracle_vectors.py`
----------------------------------------------------------
That tool pins `EMU_SHA256` and returns rc 3 when the loaded `emu.py` is not
the frozen one -- which is exactly what a revision run needs to be.  It also
writes into `phase16s/isa/`, which is 16S evidence and is not touched here.
This tool imports the SAME vector set from the recorded artifact
(`phase16s/isa/ISA_ORACLE_16.json`, read-only), the SAME independent oracle
module (`phase16s/isa/oracle16.py`, which imports nothing), the SAME composed
class factory and the SAME `HarnessS1.probe`, and changes only WHICH SOURCE
TREE supplies the two edited modules.

HOW A REVISION IS LOADED
------------------------
This is `phase16o_final/a_regression/tools/a_run_rev.py`'s mechanism,
unchanged: the revision tree's copies are loaded EXPLICITLY by file path and
registered under their own module names in `sys.modules` BEFORE anything else
can import them, so every transitive `import emu` resolves to the revision's
copy while everything else comes from the live tree.  The revision tree cannot
be a `sys.path` shadow because the edited modules derive their project root
from their own location and the two depths disagree.

The provenance block asserts, from `sys.modules[...].__file__` -- not from a
path this tool typed -- that the modules actually imported came from the tree
this run names.

Usage:
    python phase16t/isa/t16_probe.py --rev live      --out ...
    python phase16t/isa/t16_probe.py --rev revision  --out ...
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
T = os.path.dirname(HERE)
ROOT = os.path.dirname(T)

REV_TREE = os.path.join(T, "semantic", "revision_16t")
S1_ARTIFACT = "phase16s/isa/ISA_ORACLE_16.json"
S1_ORACLE = "phase16s/isa/oracle16.py"

#: The eight modules a revision tree carries (it must carry all eight because
#: the loader reads them by file path), in dependency order.
TREE_MODULES = ["emu", "p16j_input", "p14d8_core", "p14e_emu", "p14eh",
                "p16e_rec", "p16h_scratch_probe", "p16j_scratch_isa"]

#: The two the 16T revision actually edits.
EDITED = ("emu", "p14d8_core")

PATHS = ["phase16k_pretest/k3_arena", "phase16j_pre_gta/tools",
         "phase16i_closure/tools", "phase16h_pcrel_fix/tools",
         "phase16e_candidate_e/tools", "phase14e_static/tools",
         "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
         "phase14d11_static/tools", "phase14d11_static",
         "phase14d_static/tools", "phase8_static/tools",
         "phase14d8_static/tools"]


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def load_revision(revdir):
    for name in TREE_MODULES:
        path = os.path.join(revdir, name + ".py")
        if not os.path.exists(path):
            raise SystemExit("revision tree is missing %s" % path)
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod          # before exec: cyclic imports resolve
        spec.loader.exec_module(mod)


def prepare(rev, tree=None):
    """Put the chosen source tree in front, then import the composed core."""
    for p in PATHS:
        pp = os.path.join(ROOT, p)
        if pp not in sys.path:
            sys.path.insert(0, pp)
    revdir = None
    if rev == "revision":
        revdir = tree or REV_TREE
        load_revision(revdir)
    sys.path.insert(0, os.path.join(ROOT, "phase16r", "isa", "tools"))
    sys.path.insert(0, os.path.join(ROOT, "phase16s", "isa", "tools"))
    sys.path.insert(0, os.path.join(ROOT, "phase16m_final_host", "m2_isa"))
    import r11_j3_matrix_16s as R16
    import verify_m2 as m2
    env = m2.load_emulator()
    harness = R16.HarnessS1(env, m2)
    return harness, R16, m2, revdir


def provenance(rev, revdir, harness, m2):
    """Where did each edited module ACTUALLY come from?"""
    loaded = {}
    for mod in TREE_MODULES:
        m = sys.modules.get(mod)
        f = getattr(m, "__file__", None) if m else None
        loaded[mod] = {
            "file": os.path.relpath(f, ROOT).replace("\\", "/") if f else None,
            "sha256": sha256_file(f) if f and os.path.exists(f) else None,
            "from_revision_tree": bool(f and revdir and os.path.abspath(
                f).startswith(os.path.abspath(revdir))),
        }
    # the composed class the harness INSTANTIATES
    both = harness.BOTH
    owners = {}
    for attr in ("op_v_cvt_f16_f32", "op_v_pack_b32_f16", "op_v_fma_mixlo_f16",
                 "op_v_fma_mixhi_f16", "op_v_add_co_ci_u32"):
        h = getattr(both, attr, None)
        owners[attr] = h.__qualname__.split(".")[0] if h else None
        fm = sys.modules.get(h.__module__) if h else None
        if fm is not None:
            owners[attr] += " @ " + os.path.relpath(
                fm.__file__, ROOT).replace("\\", "/")
    return {
        "revision": rev,
        "revision_tree": (os.path.relpath(revdir, ROOT).replace("\\", "/")
                          if revdir else None),
        "instantiated_class": both.__name__,
        "mro": [c.__name__ for c in both.__mro__],
        "handler_owners": owners,
        "modules": loaded,
        "edited_modules_from_revision_tree": all(
            loaded[m]["from_revision_tree"] for m in EDITED) if revdir else None,
        "load_emulator_problems": None,   # filled by the caller
    }


def load_vectors():
    p = os.path.join(ROOT, S1_ARTIFACT.replace("/", os.sep))
    with open(p, encoding="utf-8") as f:
        doc = json.load(f)
    return doc, sha256_file(p)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--rev", choices=("live", "revision"), required=True)
    ap.add_argument("--rev-tree", default=None,
                    help="an alternative revision tree (used by the "
                         "known-bad mutation controls)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", default=None,
                    help="comma-separated mnemonics to restrict to")
    args = ap.parse_args(argv)

    t0 = time.time()
    harness, R16, m2, revdir = prepare(args.rev, args.rev_tree)
    doc, art_hash = load_vectors()
    prov = provenance(args.rev, revdir, harness, m2)
    prov["load_emulator_problems"] = getattr(m2, "_LAST_PROBLEMS", None)

    if args.rev == "revision":
        if not prov["edited_modules_from_revision_tree"]:
            raise SystemExit("PROVENANCE FAILURE: an edited module did not "
                             "resolve to the revision tree: %s"
                             % json.dumps(prov["modules"], indent=1))
    else:
        for mod in EDITED:
            if prov["modules"][mod]["from_revision_tree"]:
                raise SystemExit("PROVENANCE FAILURE: the live run loaded %s "
                                 "from a revision tree" % mod)

    vectors = doc["vectors"]
    if args.only:
        want = set(x.strip() for x in args.only.split(","))
        vectors = [v for v in vectors if v["mnem"] in want]

    results = []
    n_cmp = 0
    for v in vectors:
        spec = {"mnem": v["mnem"], "ops": v["ops"], "dst": v["dst"],
                "setup": v["setup"], "expect": v["expect"],
                "alt": v.get("alt") or {}, "name": v["name"]}
        obs = harness.probe(spec)
        diffs = R16._obs_diffs(obs, v["expect"])
        hits = R16.alts_that_explain(spec, obs, diffs)
        n_cmp += 1 + len(v["expect"].get("extra") or {})
        n_cmp += sum(1 for k in ("scc", "exec") if v["expect"].get(k) is not None)
        results.append({"mnem": v["mnem"], "name": v["name"], "ops": v["ops"],
                        "setup": v["setup"], "oracle": v["expect"],
                        "alt": v.get("alt") or {}, "obs": obs,
                        "diffs": diffs, "alt_hits": hits,
                        "note": v.get("note"), "source": v.get("source")})

    per = {}
    for m in sorted(set(r["mnem"] for r in results)):
        rs = [r for r in results if r["mnem"] == m]
        dis = [r for r in rs if r["diffs"]]
        unexplained = [r for r in dis if not r["alt_hits"]]
        per[m] = {
            "vectors": len(rs),
            "comparisons": sum(1 + len(r["oracle"].get("extra") or {})
                               + sum(1 for k in ("scc", "exec")
                                     if r["oracle"].get(k) is not None)
                               for r in rs),
            "agree": len(rs) - len(dis),
            "disagree": len(dis),
            "disagree_explained_by_a_recorded_alternate": len(dis) - len(unexplained),
            "disagree_unexplained": len(unexplained),
        }

    rec = {
        "schema": "phase16t-t16-probe/1", "phase": "16T",
        "host_only": True, "gpu_execution_performed": False,
        "gta_launched": False, "currently_armed": False,
        "what": ("the Phase 16S independent ISA-oracle vectors, executed "
                 "through the composed core of ONE named source revision"),
        "run": {
            "command": "python phase16t/isa/t16_probe.py --rev %s --out %s"
                       % (args.rev, args.out),
            "cwd": ROOT, "python": sys.version.split()[0],
            "wall_s": None, "s1_artifact": S1_ARTIFACT,
            "s1_artifact_sha256": art_hash,
            "oracle_module": {
                "path": S1_ORACLE,
                "sha256": sha256_file(os.path.join(ROOT, S1_ORACLE)),
                "imports": "nothing -- verified in phase16s/isa/ISA_ORACLE_16.json"
            },
        },
        "provenance": prov,
        "n_vectors": len(results),
        "n_comparisons": n_cmp,
        "n_vectors_disagreeing": sum(1 for r in results if r["diffs"]),
        "n_vectors_disagreeing_unexplained":
            sum(1 for r in results if r["diffs"] and not r["alt_hits"]),
        "per_mnemonic": per,
        "vectors": results,
    }
    rec["run"]["wall_s"] = round(time.time() - t0, 1)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=1)

    print("revision        : %s  (%s)" % (args.rev, prov["revision_tree"]))
    print("instantiated    : %s" % prov["instantiated_class"])
    for a, o in prov["handler_owners"].items():
        print("   %-22s %s" % (a, o))
    print("vectors         : %d   comparisons: %d" % (len(results), n_cmp))
    print("%-24s %6s %6s %6s %6s %6s" % ("mnemonic", "vecs", "agree", "dis",
                                         "alt", "UNEXPL"))
    for m, d in per.items():
        print("%-24s %6d %6d %6d %6d %6d"
              % (m, d["vectors"], d["agree"], d["disagree"],
                 d["disagree_explained_by_a_recorded_alternate"],
                 d["disagree_unexplained"]))
    print("wrote %s" % args.out)
    if n_cmp <= 0:
        print("FAILURE: 0 comparisons -- this run proves nothing and is refused")
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
