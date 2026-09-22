#!/usr/bin/env python3
"""Phase 16K-K0 -- freeze Phase 16J and record the evidence manifest.

WHY THIS EXISTS

Phase 16J is authoritative for everything Phase 16K builds on, and its report
is a live file that Phase 16K is required to overwrite at the end of the
session.  Freezing it first means the 16K report can be compared against a
byte-identical copy of what it claims to supersede.

The manifest is a separate question: which exact bytes were measured.  Every
entry carries the SHA-256 of the file as it exists now, plus the size, so a
later `--verify` can detect a mutation rather than merely a rename.

WHAT IS NOT FROZEN

`SESSION_REPORT.md` itself.  The brief says so explicitly: the frozen copy is
`frozen/phase16j_SESSION_REPORT.md`, and the live file stays live.

Host-only.  Reads files; writes two artefacts.  No GPU.

Usage:
  p16k_manifest.py                 # build the manifest (idempotent)
  p16k_manifest.py --verify        # recompute and compare; exit 1 on drift
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(ROOT, "phase16k_pretest")
FROZEN = os.path.join(OUT, "frozen")

# The report Phase 16J left behind.  Frozen under a phase-specific name so
# the live file can be rewritten without destroying the record.
FROZEN_REPORT_SRC = "SESSION_REPORT.md"
FROZEN_REPORT_DST = "frozen/phase16j_SESSION_REPORT.md"

# Every source file whose behaviour can change what a dispatch computes.
# This is the same set `p16j_execcache.SEMANTICS_SOURCES` hashes into its
# cache key -- kept in one place per phase, and cross-checked below, because
# a manifest that disagrees with the cache key would certify bytes the cache
# would not recognise.
EMULATOR_SEMANTICS = [
    "phase8_static/tools/emu.py",
    "phase14d8_static/tools/p14d8_core.py",
    "phase14d11_static/tools/p14d11_emu.py",
    "phase14e_static/tools/p14e_emu.py",
    "phase14e_forensics/tools/wg_emu.py",
    "phase14eh_tools/p14eh.py",
    "phase16e_candidate_e/tools/p16e_rec.py",
    "phase16h_pcrel_fix/tools/p16h_global_gate.py",
    "phase16h_pcrel_fix/tools/p16h_scratch_probe.py",
    "phase16i_closure/tools/p16i_lds_descriptor.py",
    "phase16i_closure/tools/p16i_isa.py",
    "phase16j_pre_gta/tools/p16j_scratch_isa.py",
    "phase16j_pre_gta/tools/p16j_input.py",
]

# name -> (path, role).  Roles are the brief's own list; the mapping from a
# role to a file is a claim this manifest makes explicit so it can be
# checked, rather than left implicit in a script.
ARTEFACTS = [
    ("candidate_f_co", "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co",
     "Candidate F code object"),
    ("candidate_f_fatbin", "phase16i_alpha/module/candidate_f_gfx1030.fatbin",
     "Candidate-F fatbin payload handed to the loader"),
    ("alpha_bridge", "phase16i_alpha/runtime/amdhip64_7.dll",
     "alpha HIP bridge (amdhip64_7.dll)"),
    ("version_dll_gfx1030accept",
     "phase16i_alpha/runtime/version.dll.gfx1030accept",
     "version.dll gfx1030 accept copy"),
    ("j3_harness_exe", "phase16j_pre_gta/harness/p16j_j3_swin_host.exe",
     "J3 harness binary"),
    ("j3_harness_src", "phase16j_pre_gta/harness/p16j_j3_swin_host.cpp",
     "J3 harness source"),
    ("j3_input_generator_c", "phase16j_pre_gta/harness/p16j_pattern.h",
     "J3 input generator (C, the physical side)"),
    ("j3_input_generator_py", "phase16j_pre_gta/tools/p16j_input.py",
     "J3 input generator (host reference side)"),
    ("execution_cache", "phase16j_pre_gta/tools/p16j_execcache.py",
     "execution-cache implementation"),
    ("outcome_reducer", "phase14eh_tools/p14eh.py",
     "outcome reducer (run_workgroup_hw verdict logic)"),
    ("outcome_regression", "phase16j_pre_gta/tools/p16j_outcome_regression.py",
     "outcome-reducer regression test (all-faulted case)"),
    ("scratch_validator_isa",
     "phase16j_pre_gta/tools/p16j_scratch_isa.py",
     "scratch validator (ISA-grammar store/load model)"),
    ("scratch_validator_probe",
     "phase16h_pcrel_fix/tools/p16h_scratch_probe.py",
     "scratch validator (private-segment probe)"),
    ("lds_validator", "phase16i_closure/tools/p16i_lds_descriptor.py",
     "LDS descriptor-bound validator"),
    ("authentic_harness", "phase16i_closure/tools/p16i_authentic_harness.py",
     "authentic VarParams harness"),
    ("authentic_decode_csv", "phase16_authentic_decode_swin.csv",
     "captured authentic VarParams rows (all five variants)"),
]

# Hashes the brief states as authoritative for the current state.  Checked,
# not assumed: a mismatch is reported as a failure of THIS manifest rather
# than silently recorded as the new truth.
EXPECTED = {
    "candidate_f_co":
        "47b5d1d11041b034ac30eebac090ee922f415d8f08a0111e69641d7e0557524b",
    "alpha_bridge":
        "934844286c79999a763146b98bff217fcfdbb0e3d23d6b334b0323c37f3abfe0",
    "j3_harness_exe":
        "72335a20c96d734e26b757e29955c0ef58fe3fe32c72e89da79024e2ed3e13f3",
}

# Phase 16K-K1 changed two emulator semantic sources on purpose.  The K0
# hash stays recorded as what was MEASURED at K0; the change is declared
# here rather than written over, because silently recording the new bytes as
# the old truth is the failure this manifest exists to prevent (see the
# EXPECTED comment above).
#
# A declared supersession does NOT make the verifier blind.  `verify()`
# compares the file on disk against the K0 hash and accepts the result only
# if it is one of the declared `to` values; any OTHER byte is still
# EVIDENCE_MUTATED.  `--self-test` proves that by injecting exactly such a
# byte and requiring the verifier to fail.
DECLARED_SUPERSESSIONS = {
    "phase14d11_static/tools/p14d11_emu.py": [{
        "phase": "16K-K1",
        "from": "43fac7bf5f2cb61b9e038e14c6f77a8e8736c5edf566f60a83c9f67392196567",
        "to": "0324f659bff55d5191b41bfe64429475f2bddfc48f96093456a6c5e10def2aac",
        "reason": "`RecCore.g_ops` was `self.g_ops = []` and `_gl_addr` "
                  "appended one 4-tuple per global lane-access with nothing "
                  "ever draining it; RecCore is on the production path "
                  "(BothCore MRO), so swin256f retained 8,370,176 live "
                  "4-tuples. Replaced with an explicit-mode bounded "
                  "recorder (`p16k_recorder.recorder_for`), default "
                  "AGGREGATE. Semantics unchanged: same events, same "
                  "counts, same min/max.",
        "evidence": [
            "phase16k_pretest/out/k1_diff/k1_diff_swin32f_A_scratch.json",
            "phase16k_pretest/out/k1_diff/k1_diff_swin32t_A_scratch.json",
            "phase16k_pretest/out/k1_diff/k1_diff_swin64f_A_scratch.json",
            "phase16k_pretest/out/k1_diff_recheck/k1_recheck_swin32f.json",
        ],
        "differential": "0 differing fields on all three required "
                        "variants, against persisted PRE-change artifacts "
                        "(p16j_prof_swin32f_A_scratch_w8.json, "
                        "p16j_diff_swin32t_A_scratch.json, "
                        "p16j_diff_swin64f_A_scratch.json; all mtimes "
                        "12:44-12:46, before the 13:43 edit).",
    }],
    "phase14e_static/tools/p14e_emu.py": [{
        "phase": "16K-K1",
        "from": "6cd7a4d2a2c802c09090bed271781b2da567718b569d7afbae1b46f9e1e77617",
        "to": "f6cca76f5ba731a62d1edf34fb7842ad8c4c1798efe3bd1f577268be15de09d9",
        "reason": "Same leak, consumer side: the global/ds_ops trace readers "
                  "now declare the mode they need (`REC.force_full`) instead "
                  "of silently reading whatever the bounded AGGREGATE "
                  "sample happened to hold. A reader that needs every event "
                  "must now say so.",
        "evidence": [
            "phase16k_pretest/out/k1_diff/k1_diff_swin32f_A_scratch.json",
            "phase16k_pretest/out/k1_diff/k1_diff_swin32t_A_scratch.json",
            "phase16k_pretest/out/k1_diff/k1_diff_swin64f_A_scratch.json",
        ],
        "differential": "0 differing fields on all three required variants, "
                        "same pre-change references as above.",
    }],
}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def entry(rel, role):
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        # A missing file is recorded as missing, never skipped.  Dropping a
        # component silently would make the manifest strongest exactly when
        # the tree is in an unexpected state.
        return {"path": rel, "role": role, "present": False}
    return {"path": rel, "role": role, "present": True,
            "size": os.path.getsize(p), "sha256": sha256_file(p)}


def freeze_report():
    """Copy the live report to its frozen name, once.

    Refuses to overwrite an existing frozen copy with different bytes: a
    second run must not be able to quietly redefine what Phase 16J said.
    """
    src = os.path.join(ROOT, FROZEN_REPORT_SRC)
    dst = os.path.join(OUT, FROZEN_REPORT_DST)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if not os.path.exists(src):
        return {"frozen": False, "reason": "live report absent"}
    new = sha256_file(src)
    if os.path.exists(dst):
        old = sha256_file(dst)
        if old == new:
            return {"frozen": True, "path": FROZEN_REPORT_DST,
                    "sha256": old, "note": "already frozen, identical"}
        return {"frozen": True, "path": FROZEN_REPORT_DST,
                "sha256": old, "note": "already frozen, live file differs "
                "(expected after this phase rewrites it)",
                "live_sha256_now": new}
    shutil.copy2(src, dst)
    return {"frozen": True, "path": FROZEN_REPORT_DST,
            "sha256": sha256_file(dst), "note": "frozen this run"}


def build():
    os.makedirs(OUT, exist_ok=True)
    fr = freeze_report()

    man = {
        "schema": "phase16k_evidence_manifest/1",
        "phase": "16K",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host_only": True,
        "gpu_execution_performed": False,
        "gta_launched": False,
        "frozen_report": fr,
        "artefacts": {},
        "emulator_semantics_sources": {},
        "expected_hashes": EXPECTED,
    }

    for name, rel, role in ARTEFACTS:
        man["artefacts"][name] = entry(rel, role)

    for rel in EMULATOR_SEMANTICS:
        man["emulator_semantics_sources"][rel] = entry(
            rel, "emulator semantic source (in the execution-cache key)")

    # Declared supersessions are attached to the entry they affect, and the
    # entry's `sha256` is REWOUND to the K0 value so `verify()` keeps
    # checking the file against what was actually measured at K0 rather
    # than against whatever is on disk now.
    for rel, sups in DECLARED_SUPERSESSIONS.items():
        rec = man["emulator_semantics_sources"].get(rel)
        if rec is None or not rec.get("present"):
            continue
        rec["superseded"] = sups
        rec["sha256_now"] = rec["sha256"]
        rec["sha256"] = sups[-1]["from"]

    # The manifest must not disagree with the cache key about which files
    # carry semantics.  Import the cache module and compare its list.
    sys.path.insert(0, os.path.join(ROOT, "phase16j_pre_gta", "tools"))
    try:
        import p16j_execcache as EC
        cache_set = sorted(EC.SEMANTICS_SOURCES)
        man_set = sorted(EMULATOR_SEMANTICS)
        man["semantics_list_cross_check"] = {
            "agrees_with_execution_cache": cache_set == man_set,
            "only_in_cache": [x for x in cache_set if x not in man_set],
            "only_in_manifest": [x for x in man_set if x not in cache_set],
        }
    except Exception as e:                                  # noqa: BLE001
        man["semantics_list_cross_check"] = {
            "agrees_with_execution_cache": False,
            "error": "%s: %s" % (type(e).__name__, e),
        }

    # Expected-hash check.  A mismatch is surfaced, not overwritten.
    checks = {}
    for name, want in EXPECTED.items():
        got = man["artefacts"].get(name, {}).get("sha256")
        checks[name] = {"expected": want, "got": got, "match": got == want}
    man["expected_hash_checks"] = checks
    man["all_expected_hashes_match"] = all(c["match"] for c in checks.values())
    man["all_present"] = all(a["present"] for a in man["artefacts"].values())

    path = os.path.join(OUT, "evidence_manifest.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(man, f, indent=1)
    return man, path


def verify(root=None, manifest_path=None):
    """Recompute every hash and compare against the recorded manifest.

    A file whose bytes differ from the K0 hash is accepted ONLY if the new
    bytes are exactly a declared supersession's `to` value.  Anything else
    is a mutation, including a third value for a file that has a declared
    change -- so declaring one change does not buy immunity for the next.
    """
    root = root or ROOT
    path = manifest_path or os.path.join(OUT, "evidence_manifest.json")
    if not os.path.exists(path):
        print("NO MANIFEST at %s -- run without --verify first" % path)
        return 1
    old = json.load(open(path, encoding="utf-8"))
    drift = []
    superseded = []
    missing = []
    for section in ("artefacts", "emulator_semantics_sources"):
        for name, rec in (old.get(section) or {}).items():
            rel = rec["path"]
            p = os.path.join(root, rel)
            if not os.path.exists(p):
                if rec.get("present"):
                    missing.append(rel)
                continue
            if not rec.get("present"):
                drift.append((rel, "<absent>", sha256_file(p)))
                continue
            now = sha256_file(p)
            if now == rec["sha256"]:
                continue
            declared = [s for s in (rec.get("superseded") or [])
                        if s.get("from") == rec["sha256"] and s.get("to") == now]
            if declared:
                superseded.append((rel, rec["sha256"], now, declared[0]))
            else:
                drift.append((rel, rec["sha256"], now))
    fr = old.get("frozen_report") or {}
    if fr.get("path"):
        fp = os.path.join(OUT, fr["path"])
        if not os.path.exists(fp):
            missing.append(fr["path"])
        elif sha256_file(fp) != fr["sha256"]:
            drift.append((fr["path"], fr["sha256"], sha256_file(fp)))

    for rel in missing:
        print("MISSING  %s" % rel)
    for rel, a, b, s in superseded:
        print("SUPERSEDED (declared)  %s\n   k0  %s\n   now %s\n   by  %s"
              % (rel, a, b, s.get("phase")))
    for rel, a, b in drift:
        print("DRIFT    %s\n   was %s\n   now %s" % (rel, a, b))
    n = len(old.get("artefacts") or {}) + len(
        old.get("emulator_semantics_sources") or {}) + 1
    print("checked %d entries: %d missing, %d drifted, %d superseded-declared"
          % (n, len(missing), len(drift), len(superseded)))
    print("VERDICT: %s" % ("EVIDENCE_INTACT" if not missing and not drift
                           else "EVIDENCE_MUTATED"))
    return 0 if not missing and not drift else 1


def self_test():
    """The verifier must FAIL on an undeclared mutation.

    Copies the tree's manifest to a temp dir, points `verify` at a scratch
    copy of the tree with ONE byte appended to a file that carries a
    declared supersession, and requires EVIDENCE_MUTATED.  A declared
    change must not make the file immune to the next one.
    """
    import tempfile
    src = os.path.join(OUT, "evidence_manifest.json")
    if not os.path.exists(src):
        print("SELF-TEST: no manifest to test against")
        return 1
    ok = True

    # 1. Baseline: the real tree must verify clean.
    rc = verify()
    print("  [1] baseline verify rc=%d (want 0)" % rc)
    ok = ok and rc == 0

    with tempfile.TemporaryDirectory() as td:
        man = json.load(open(src, encoding="utf-8"))
        # 2. Inject an UNDECLARED mutation into a file that HAS a declared
        #    supersession.  The point of the test: a third value must fail.
        victim_rel = "phase14d11_static/tools/p14d11_emu.py"
        vroot = os.path.join(td, "tree")
        shutil.copytree(ROOT, vroot,
                        ignore=shutil.ignore_patterns(".git", "__pycache__"))
        vp = os.path.join(vroot, victim_rel)
        with open(vp, "ab") as f:
            f.write(b"\n# undeclared mutation for the K17 negative test\n")
        vman = os.path.join(td, "manifest.json")
        json.dump(man, open(vman, "w", encoding="utf-8"), indent=1)
        print("  [2] undeclared mutation of a DECLARED file:")
        rc2 = verify(root=vroot, manifest_path=vman)
        print("      rc=%d (want 1)" % rc2)
        ok = ok and rc2 == 1

        # 3. Inject an undeclared mutation into a FROZEN artefact.
        frozen_rel = "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co"
        fp = os.path.join(vroot, frozen_rel)
        if os.path.exists(fp):
            with open(fp, "r+b") as f:
                f.seek(64)
                b = f.read(1)
                f.seek(64)
                f.write(bytes([b[0] ^ 0x01]))
            print("  [3] undeclared mutation of a FROZEN artefact:")
            rc3 = verify(root=vroot, manifest_path=vman)
            print("      rc=%d (want 1)" % rc3)
            ok = ok and rc3 == 1
        else:
            print("  [3] SKIPPED: %s absent" % frozen_rel)
            ok = False

    print("SELF-TEST: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--self-test", action="store_true",
                    help="prove the verifier FAILS on an undeclared mutation")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if a.verify:
        return verify()

    man, path = build()
    print("=" * 74)
    print("K0 -- Phase 16J frozen, evidence manifest recorded")
    print("=" * 74)
    fr = man["frozen_report"]
    print("frozen report : %s  %s" % (fr.get("path"), fr.get("note")))
    if fr.get("sha256"):
        print("              %s" % fr["sha256"])
    print()
    print("%-30s %-12s %s" % ("artefact", "size", "sha256"))
    for name, rec in sorted(man["artefacts"].items()):
        if rec.get("present"):
            print("%-30s %-12d %s" % (name, rec["size"], rec["sha256"]))
        else:
            print("%-30s %-12s %s" % (name, "-", "ABSENT"))
    print()
    for rel, sups in sorted(DECLARED_SUPERSESSIONS.items()):
        for s in sups:
            print("declared change %s by %s" % (rel, s["phase"]))
            print("   k0  %s" % s["from"])
            print("   now %s" % s["to"])
    print()
    for name, c in sorted(man["expected_hash_checks"].items()):
        print("expected %-24s %s" % (name, "MATCH" if c["match"] else
                                     "MISMATCH (got %s)" % c["got"]))
    xc = man["semantics_list_cross_check"]
    print("semantics list agrees with execution cache: %s"
          % xc.get("agrees_with_execution_cache"))
    print("all artefacts present: %s" % man["all_present"])
    print("all expected hashes match: %s" % man["all_expected_hashes_match"])
    print("wrote %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
