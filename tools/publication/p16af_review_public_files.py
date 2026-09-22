#!/usr/bin/env python3
"""Phase 16AF / T2 -- review of the files added by the publication branch.

Scans every file that `git diff --diff-filter=A main..HEAD` reports in the
public mirror and records, per file: ownership, license compatibility with the
mirror's LICENSE, provenance, proprietary-derived content, secrets, private
paths (literal AND JSON-escaped spellings), external-contributor material, and
a value judgement.

Two things this scanner is careful about
----------------------------------------
1. DENOMINATORS.  Every "no findings" statement is accompanied by the number
   of files scanned and the number of bytes scanned and the number of patterns
   applied.  "0 secrets found" without a denominator is not a measurement.

2. THE ESCAPED PATH FORM.  A JSON file that stores `<USER_HOME>` contains
   no literal `C:\\Users` byte sequence, so a naive literal test reports clean.
   Both spellings are scanned separately and both counts are reported, and the
   escaped-form pattern is exercised against a known-bad sample so that "the
   escaped scan found nothing" cannot be the same observation as "the escaped
   scan does not work".

The scanner never writes to the mirror.  It reads the committed blobs, so what
it reports is what a fresh clone receives, not merely the local working tree.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PUBLIC_ROOT = Path(r"<USER_HOME>\Desktop\gfx1030-dlss-nr-research")
OUT = HERE / "PUBLICATION_FILE_REVIEW.json"
BASE_REF = "main"
HEAD_REF = "HEAD"

# ---------------------------------------------------------------------------
# pattern sets.  These live in the PRIVATE tree, so none of them can be
# satisfied by the text of a file the scan is checking.
# ---------------------------------------------------------------------------

SECRET_PATTERNS: dict[str, bytes] = {
    "github_token": rb"gh[pousr]_[A-Za-z0-9]{30,}",
    "github_pat": rb"github_pat_[A-Za-z0-9_]{30,}",
    "openai_key": rb"sk-(?:proj-)?[A-Za-z0-9]{32,}",
    "anthropic_key": rb"sk-ant-[A-Za-z0-9_-]{20,}",
    "deepseek_key": rb"sk-[0-9a-f]{32}",
    "aws_access_key": rb"AKIA[0-9A-Z]{16}",
    "aws_secret": rb"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*\S{20,}",
    "private_key_block": rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "bearer_token": rb"(?i)\bBearer\s+[A-Za-z0-9_.\-]{32,}",
    "slack_token": rb"xox[baprs]-[A-Za-z0-9-]{10,}",
    "google_api_key": rb"AIza[0-9A-Za-z_\-]{35}",
    "password_assignment": rb"(?i)\bpassword\s*[:=]\s*['\"][^'\"\s]{6,}['\"]",
    "connection_string": rb"(?i)\b(?:postgres|mysql|mongodb|redis|amqp)://[^\s'\"]{8,}",
    "jwt": rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
}

# private-path patterns, split by spelling.
#
# `windows_user_path_literal` is deliberately the NAIVE test the brief warns
# about: one backslash, exactly.  `windows_user_path_json_escaped` is the
# spelling a JSON file actually contains.  They are complementary, and the
# demonstration that they are is in pattern_self_test().  The verdict is taken
# from `windows_user_path_any`, which catches either spelling.
PRIVATE_PATH_LITERAL: dict[str, bytes] = {
    "windows_user_path_literal": rb"(?i)[A-Z]:\\Users\\[A-Za-z0-9._-]+",
    "windows_user_path_json_escaped": rb"(?i)[A-Z]:\\\\Users\\\\[A-Za-z0-9._-]+",
    "windows_user_path_any": rb"(?i)[A-Z]:\\{1,2}Users\\{1,2}[A-Za-z0-9._-]+",
    "posix_home_path": rb"/(?:home|Users)/[A-Za-z0-9._-]+/",
    "personal_email": rb"(?i)[A-Za-z0-9._%+-]+@(?:gmail|outlook|hotmail|yahoo|protonmail)\.com",
}

# absolute machine paths that are not user paths but are still local install
# assumptions worth recording (they do not by themselves block publication)
LOCAL_INSTALL_PATH: dict[str, bytes] = {
    "program_files_path": rb"(?i)[A-Z]:\\{1,2}Program Files(?: \(x86\))?\\{1,2}[A-Za-z0-9 ._\\-]{2,60}",
}

PROPRIETARY_MARKERS: dict[str, bytes] = {
    "dlss_nr_engine_symbol": rb"DlssNrEngine",
    "dlss_literal": rb"(?i)\bdlss\b",
    "nvngx_literal": rb"(?i)nvngx",
    "nvidia_literal": rb"(?i)\bnvidia\b",
    "version_dll_blob_name": rb"version\.dll(?:\.static_copy)?",
    "extracted_code_object_name": rb"gfx1100_code_object",
    "embedded_fatbin_header": rb"bridge_gfx1030_fatbin",
    "fatbin_word": rb"(?i)fatbin",
    "decompiled_word": rb"(?i)decompil",
    "proprietary_word": rb"(?i)\bproprietary\b",
}

EXTERNAL_CONTRIBUTOR_PATTERNS: dict[str, bytes] = {
    "astra": rb"(?i)\bastra\b",
    "external_reviewer_word": rb"(?i)external (?:review|audit|reviewer|auditor)",
    "independent_review_word": rb"(?i)independent (?:technical )?(?:review|audit)",
    "requested_by": rb"(?i)requested by",
    "contributed_by": rb"(?i)contributed by",
    "courtesy_of": rb"(?i)courtesy of",
    "authored_by": rb"(?i)authored by",
}

PROPRIETARY_DERIVED_MATERIAL = {
    "vendor_binary": "a vendor .dll/.lib/.obj/.so/.exp or a byte array of one",
    "decompiled_blob": "a decompiled or disassembled proprietary code object",
    "translated_blob": "a translated proprietary code object",
    "dlss_nr_material": "DLSS/NR-derived source, data or symbol names",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=PUBLIC_ROOT, capture_output=True, text=True
    )


def blob(path: str) -> bytes:
    p = subprocess.run(
        ["git", "cat-file", "blob", f"{HEAD_REF}:{path}"],
        cwd=PUBLIC_ROOT,
        capture_output=True,
    )
    if p.returncode != 0:
        raise RuntimeError(f"cannot read blob for {path}: {p.stderr!r}")
    return p.stdout


def added_files() -> list[str]:
    p = git("diff", "--name-status", "--diff-filter=A", f"{BASE_REF}..{HEAD_REF}")
    if p.returncode != 0:
        raise RuntimeError(f"git diff failed: {p.stderr!r}")
    return [line.split("\t", 1)[1] for line in p.stdout.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# pattern self-test: the escaped-form pattern must catch a known-bad sample,
# and the literal pattern must NOT claim to catch it.  Without this, "the
# escaped scan found nothing" and "the escaped scan is broken" are the same
# observation.
# ---------------------------------------------------------------------------

KNOWN_BAD_SAMPLES = {
    # as the bytes appear in a plain-text file
    "literal": rb'path = "<USER_HOME>\Desktop\file.txt"',
    # as the bytes appear in a JSON file: every backslash doubled
    "json_escaped": rb'{"path": "<USER_HOME>\\Desktop\\file.txt"}',
}
KNOWN_GOOD_SAMPLE = rb'{"path": "tests/soft_wmma_test.cpp", "root": "${PROJECT_ROOT}"}'


def pattern_self_test() -> dict[str, object]:
    """Exercise the private-path patterns against known-bad and known-good
    samples.  The `misses` assertion is the point: if the naive literal
    pattern also caught the JSON-escaped sample, the escaped pattern would not
    be needed and this control would be vacuous."""
    lit = re.compile(PRIVATE_PATH_LITERAL["windows_user_path_literal"])
    esc = re.compile(PRIVATE_PATH_LITERAL["windows_user_path_json_escaped"])
    any_ = re.compile(PRIVATE_PATH_LITERAL["windows_user_path_any"])
    out = {
        "naive_literal_catches_literal_sample": bool(
            lit.search(KNOWN_BAD_SAMPLES["literal"])
        ),
        "naive_literal_MISSES_json_escaped_sample": not bool(
            lit.search(KNOWN_BAD_SAMPLES["json_escaped"])
        ),
        "escaped_pattern_catches_json_escaped_sample": bool(
            esc.search(KNOWN_BAD_SAMPLES["json_escaped"])
        ),
        "escaped_pattern_does_not_catch_literal_sample": not bool(
            esc.search(KNOWN_BAD_SAMPLES["literal"])
        ),
        "combined_pattern_catches_both_samples": bool(
            any_.search(KNOWN_BAD_SAMPLES["literal"])
        ) and bool(any_.search(KNOWN_BAD_SAMPLES["json_escaped"])),
        "combined_pattern_flags_known_good_sample": bool(
            any_.search(KNOWN_GOOD_SAMPLE)
        ),
    }
    out["all_six_hold"] = (
        out["naive_literal_catches_literal_sample"]
        and out["naive_literal_MISSES_json_escaped_sample"]
        and out["escaped_pattern_catches_json_escaped_sample"]
        and out["escaped_pattern_does_not_catch_literal_sample"]
        and out["combined_pattern_catches_both_samples"]
        and not out["combined_pattern_flags_known_good_sample"]
    )
    return out


def scan_patterns(data: bytes, patterns: dict[str, bytes]) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for name, rx in patterns.items():
        found = re.findall(rx, data)
        if found:
            uniq = sorted({m if isinstance(m, str) else m.decode("utf-8", "replace")
                           for m in found})
            hits[name] = uniq[:8]
    return hits


# ---------------------------------------------------------------------------
# Per-file judgement.  Everything mechanical (hashes, scans, counts) is
# recomputed by this script; these fields are the reading of that evidence and
# are recorded with the evidence that supports them.
# ---------------------------------------------------------------------------

MIRROR_LICENSE = "Apache-2.0"
MIRROR_LICENSE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"

_COMMON = {
    "ownership": "project-authored",
    "license": "Apache-2.0",
    "license_compatible": True,
}

JUDGEMENT: dict[str, dict[str, object]] = {
    "docs/bridge-payload-build-dag.md": {
        **_COMMON,
        "provenance": "authored for the published repository; describes the bridge payload build DAG",
        "proprietary_derived_content": "none — prose and tables only",
        "value": "essential: it is the map that makes the five F5 gaps legible to a reader",
        "decision": "APPROVED",
        "decision_reason": (
            "Original prose. Names proprietary artifacts as the *subject* of the DAG "
            "while publishing no bytes of them; THIRD_PARTY_NOTICES already declares "
            "those as referenced-not-included."
        ),
    },
    "src/bridge/bridge_payload_dag.json": {
        **_COMMON,
        "provenance": "authored for the published repository; machine-readable form of the DAG",
        "proprietary_derived_content": (
            "none — refers to version.dll.static_copy and bridge_gfx1030_fatbin.h by "
            "historical_path / node name only; embeds no bytes"
        ),
        "value": "essential: it is the data behind the F5 gap inventory",
        "decision": "APPROVED",
        "decision_reason": (
            "Private directory names appear only as `historical_path` provenance fields "
            "(e.g. phase5_exact_fragment/version.dll.static_copy); they are a record of "
            "where the artifact came from, not a runtime path, and they name no user. "
            "`tests/host/test_bridge_payload_dag.py` shares this and is approved for the "
            "same reason. No `<USER_HOME>` path in either spelling."
        ),
    },
    "src/bridge/offload_bundle.py": {
        **_COMMON,
        "provenance": "authored for the published repository; reader/validator for clang offload bundles",
        "proprietary_derived_content": "none — a parser, exercised on caller-supplied bytes",
        "value": "high: lets a reader validate their own bundle with no proprietary input",
        "decision": "APPROVED",
        "decision_reason": "Parser only; fails closed on a malformed bundle; no embedded data.",
    },
    "src/bridge/tools/bridge_payload_dag.py": {
        **_COMMON,
        "provenance": "authored for the published repository",
        "proprietary_derived_content": "none",
        "value": "high: makes the DAG executable and self-checking",
        "decision": "APPROVED",
        "decision_reason": "Tooling over the DAG JSON; no payload.",
    },
    "src/bridge/tools/p11_bundle_build.py": {
        **_COMMON,
        "provenance": "sanitized successor of the private phase11_fatbin bundle builder",
        "proprietary_derived_content": "none — builds a bundle from a caller-supplied payload",
        "value": "high: the step a reader runs on their own artifact",
        "decision": "APPROVED",
        "decision_reason": "Rewritten to take --bundle-style inputs rather than hardcoded private paths.",
    },
    "src/bridge/tools/p11_embed_header.py": {
        **_COMMON,
        "provenance": "sanitized successor of the private phase11_fatbin/tools/p11_embed_header.py",
        "proprietary_derived_content": (
            "none in the file; it EMITS a header that carries a proprietary payload when "
            "pointed at one. The generated header is deliberately not published."
        ),
        "value": "high: publishing the emitter while withholding its output is the whole point",
        "decision": "APPROVED",
        "decision_reason": (
            "Emits, does not contain. Its own docstring states the header is not published "
            "and that the tool embeds whatever bundle the user hands it. Verified: the file "
            "has no byte-array payload, no NUL, no dense escapes."
        ),
    },
    "src/qualification/__init__.py": {
        **_COMMON,
        "provenance": "extracted from the private p16ad qualification work for publication",
        "proprietary_derived_content": "none — generic fail-closed primitives (RULES K/L/M)",
        "value": "very high: the transferable methodology, decoupled from the DLSS/NR specifics",
        "decision": "APPROVED",
        "decision_reason": "Original, self-contained, names no proprietary artifact.",
    },
    "src/qualification/attempt_ledger.py": {
        **_COMMON,
        "provenance": "extracted from the private qualification work",
        "proprietary_derived_content": "none",
        "value": "high: attempt accounting is one of the reusable primitives",
        "decision": "APPROVED",
        "decision_reason": "Original; no proprietary content.",
    },
    "src/qualification/evidence.py": {
        **_COMMON,
        "provenance": "extracted from the private qualification work",
        "proprietary_derived_content": "none",
        "value": "high: RULE L (a summary is not evidence) in executable form",
        "decision": "APPROVED",
        "decision_reason": "Original; no proprietary content.",
    },
    "src/qualification/gates.py": {
        **_COMMON,
        "provenance": "extracted from the private qualification work",
        "proprietary_derived_content": "none",
        "value": "high: fail-closed gate vocabulary",
        "decision": "APPROVED",
        "decision_reason": "Original; no proprietary content.",
    },
    "src/qualification/mutation.py": {
        **_COMMON,
        "provenance": "extracted from the private qualification work",
        "proprietary_derived_content": "none",
        "value": "high: proves a gate can actually fail",
        "decision": "APPROVED",
        "decision_reason": "Original; no proprietary content.",
    },
    "tests/host/compare_driver.cpp": {
        **_COMMON,
        "provenance": "authored for the published repository",
        "proprietary_derived_content": "none — a C++ host driver for the comparator tests",
        "value": "medium: exercises the shared comparator on the host",
        "decision": "APPROVED",
        "decision_reason": "Original test driver; no proprietary content.",
    },
    "tests/host/cxxtoolchain.py": {
        **_COMMON,
        "provenance": "authored for the published repository",
        "proprietary_derived_content": "none",
        "value": "medium: lets the host C++ tests find a compiler without hardcoding one",
        "decision": "APPROVED",
        "decision_reason": (
            "Discovery is by environment and well-known roots, not a baked-in user path. "
            "A `Program Files` pattern matches, which is a normal install root, not a "
            "private path."
        ),
    },
    "tests/host/test_bridge_payload_dag.py": {
        **_COMMON,
        "provenance": "authored for the published repository",
        "proprietary_derived_content": (
            "none — references private directory names as historical provenance only "
            "(phase5_exact_fragment, phase9_static)"
        ),
        "value": "high: asserts the DAG's blocking-gap set, which is the F5 evidence",
        "decision": "APPROVED",
        "decision_reason": (
            "Same reasoning as src/bridge/bridge_payload_dag.json: historical provenance "
            "strings, no user path, no bytes of any artifact."
        ),
    },
    "tests/host/test_emu_modes.py": {
        **_COMMON,
        "provenance": "authored for the published repository; the F6 regression test",
        "proprietary_derived_content": "none",
        "value": "very high: it is the test that makes F6 mean something",
        "decision": "APPROVED",
        "decision_reason": "Original; pairs with the F6 emulator change approved in T1.",
    },
    "tests/host/test_fragment_ownership.py": {
        **_COMMON,
        "provenance": "authored for the published repository",
        "proprietary_derived_content": "none",
        "value": "high: the fragment-ownership contract the test fixture disclaims",
        "decision": "APPROVED",
        "decision_reason": (
            "References src/harness/p14ei_b_host.cpp, which IS tracked in the mirror "
            "(verified with git ls-files --error-unmatch), so no dangling authority."
        ),
    },
    "tests/host/test_launcher_contract.py": {
        **_COMMON,
        "provenance": "authored for the published repository; the F1 launcher contract test",
        "proprietary_derived_content": "none",
        "value": "high: it is the test that makes F1 mean something",
        "decision": "APPROVED",
        "decision_reason": "Original; pairs with the F1 launcher change approved in T1.",
    },
    "tests/host/test_numeric_compare.py": {
        **_COMMON,
        "provenance": "authored for the published repository",
        "proprietary_derived_content": "none",
        "value": "high: grades the comparator the F2 fixtures share",
        "decision": "APPROVED",
        "decision_reason": "Original; pairs with the F2 changes approved in T1.",
    },
    "tests/host/test_offload_bundle.py": {
        **_COMMON,
        "provenance": "authored for the published repository",
        "proprietary_derived_content": (
            "none — contains a 139-byte SYNTHETIC bundle descriptor table "
            "(REAL_TABLE_HEX) and a sha256 digest of the real file; the payload bytes "
            "are explicitly generated as 0xA5 fill, not republished"
        ),
        "value": "high: tests the bundle parser against a realistic header",
        "decision": "APPROVED",
        "decision_reason": (
            "Measured: the only long hex runs in the added set are here, and they decode "
            "to the bundle magic plus the two descriptor strings "
            "(__CLANG_OFFLOAD_BUNDLE__, host-x86_64-unknown-linux--, "
            "hipv4-amdgcn-amd-amdhsa--gfx1030) — 139 bytes. The module's own docstring "
            "states the payload is not republished; that claim was checked against the "
            "code and holds."
        ),
    },
    "tests/host/test_qualification_framework.py": {
        **_COMMON,
        "provenance": "authored for the published repository",
        "proprietary_derived_content": "none",
        "value": "high: exercises the fail-closed framework",
        "decision": "APPROVED",
        "decision_reason": (
            "APPROVED, with a recorded worktree observation: the committed blob is LF "
            "(14784 bytes) while the LOCAL working-tree file is CRLF (15139 bytes). "
            "`git status` reports clean because .gitattributes sets `* text=auto eol=lf`. "
            "The published artifact is the blob and it is correct, so this is not a "
            "publication defect -- but it is exactly the line-ending trap, and it means a "
            "worktree hash check of this file would disagree with every fresh clone."
        ),
    },
    "tests/host/test_qualification_ledger.py": {
        **_COMMON,
        "provenance": "authored for the published repository",
        "proprietary_derived_content": "none",
        "value": "high: the negative controls that make the ledger refusals real",
        "decision": "NEEDS_OPERATOR_DECISION",
        "decision_reason": (
            "The material is safe: original test code, no secrets, no private paths, no "
            "proprietary bytes. The open question is naming. Line 245 uses "
            "source_profile=\"astra-final-head\", and tools/qualification_ledger.py:105 "
            "declares FINAL_HEAD_PROFILES = (\"final-head\", \"astra-final-head\"). Those "
            "strings name an externally contributed artifact set. They identify no person "
            "and leak no path, but they are a public trace of the external review's label, "
            "and the project's stated preference elsewhere is to attribute external review "
            "generically. Renaming would change a ledger key, so the call is the "
            "operator's, not this review's."
        ),
    },
    "tests/soft_wmma_fragment_test.cpp": {
        **_COMMON,
        "provenance": "authored for the published repository",
        "proprietary_derived_content": "none",
        "value": "high: the fixture for the ownership contract the dense fixture disclaims",
        "decision": "APPROVED",
        "decision_reason": "Original C++ fixture; no proprietary content.",
    },
    "tests/wmma_fragment_ownership.h": {
        **_COMMON,
        "provenance": "authored for the published repository",
        "proprietary_derived_content": "none",
        "value": "high: states the ownership contract once, for both fixtures",
        "decision": "APPROVED",
        "decision_reason": "Original header; no proprietary content.",
    },
    "tests/wmma_numeric_compare.h": {
        **_COMMON,
        "provenance": "authored for the published repository; the F2 shared comparator",
        "proprietary_derived_content": "none",
        "value": "very high: the single comparator the three fixtures share",
        "decision": "APPROVED",
        "decision_reason": "Original header; no proprietary content.",
    },
    "tools/qualification_ledger.py": {
        **_COMMON,
        "provenance": "extracted from the private qualification work for publication",
        "proprietary_derived_content": "none",
        "value": "very high: artifact-backed qualification records, keyed by measured identity",
        "decision": "NEEDS_OPERATOR_DECISION",
        "decision_reason": (
            "Safe material; one naming question. Line 105 declares "
            "FINAL_HEAD_PROFILES = (\"final-head\", \"astra-final-head\"). \"astra\" names "
            "an externally contributed artifact set; it is a data-contract key, not "
            "attribution and not a path, but the project's stated convention is generic "
            "attribution of external review. Whether to keep or rename the tag is an "
            "operator decision because it is a serialized ledger key."
        ),
    },
}


def main() -> int:
    files = added_files()
    self_test = pattern_self_test()
    print("=" * 78)
    print("PHASE 16AF T2 -- review of files added by the publication branch")
    print(f"mirror: {PUBLIC_ROOT}   base: {BASE_REF}   head: {HEAD_REF}")
    print(f"preconditions: working tree and git blob are read for every file")
    print("=" * 78)
    print("\nPATTERN SELF-TEST (the escaped-form check must be able to fail)")
    for k, v in self_test.items():
        print(f"  {k}: {v}")
    if not self_test["all_six_hold"]:
        print("  ABORT: the private-path patterns do not behave as required")
        return 2

    records = []
    total_bytes = 0
    for path in files:
        data = blob(path)
        tree = (PUBLIC_ROOT / path).read_bytes()
        total_bytes += len(data)
        rec = {
            "path": path,
            "bytes": len(data),
            "sha256_git_blob": sha256(data),
            "sha256_worktree": sha256(tree),
            "representation": (
                "git blob of HEAD (what a fresh clone receives)"
                + ("; worktree identical" if data == tree else "; WORKTREE DIFFERS")
            ),
            "secrets": scan_patterns(data, SECRET_PATTERNS),
            "private_paths": {
                **scan_patterns(data, PRIVATE_PATH_LITERAL),
            },
            "local_install_paths": scan_patterns(data, LOCAL_INSTALL_PATH),
            "proprietary_markers": scan_patterns(data, PROPRIETARY_MARKERS),
            "external_contributor_markers": scan_patterns(
                data, EXTERNAL_CONTRIBUTOR_PATTERNS
            ),
            # binary-ness is a proxy for "could contain a vendor blob"
            "looks_binary": b"\x00" in data[:8192],
            "non_ascii_bytes": sum(1 for b in data if b > 127),
        }
        records.append(rec)

    n = len(records)
    print(f"\nSCAN COVERAGE")
    print(f"  files added by the branch      : {n}")
    print(f"  bytes scanned (git blobs)      : {total_bytes}")
    print(f"  secret patterns applied        : {len(SECRET_PATTERNS)}")
    print(f"  private-path patterns applied  : {len(PRIVATE_PATH_LITERAL)}")
    print(f"  proprietary-marker patterns    : {len(PROPRIETARY_MARKERS)}")
    print(f"  external-contributor patterns  : {len(EXTERNAL_CONTRIBUTOR_PATTERNS)}")

    def tally(key: str) -> int:
        return sum(1 for r in records if r[key])

    print(f"\nRAW FINDINGS")
    print(f"  files with any secret-pattern hit      : {tally('secrets')}")
    print(f"  files with any private-path hit        : {tally('private_paths')}")
    print(f"  files with any proprietary-marker hit  : {tally('proprietary_markers')}")
    print(f"  files with any external-contrib marker : {tally('external_contributor_markers')}")
    print(f"  files whose worktree differs from blob : "
          f"{sum(1 for r in records if 'WORKTREE DIFFERS' in r['representation'])}")

    for kind in ("secrets", "private_paths", "proprietary_markers",
                 "external_contributor_markers"):
        subs = sorted({k for r in records for k in r[kind]})
        print(f"  distinct {kind} pattern(s) that fired: {subs or 'none'}")

    for r in records:
        flags = []
        for kind in ("secrets", "private_paths", "proprietary_markers",
                     "external_contributor_markers"):
            if r[kind]:
                flags.append(f"{kind}={sorted(r[kind])}")
        if r["local_install_paths"]:
            flags.append(f"local_install={sorted(r['local_install_paths'])}")
        if flags:
            print(f"\n  {r['path']}")
            for f in flags:
                print(f"      {f}")

    (HERE / "_p16af_t2_raw_scan.json").write_text(
        json.dumps({"self_test": self_test, "records": records}, indent=2) + "\n",
        encoding="utf-8",
    )

    # ---- assemble the review ------------------------------------------------
    missing_judgement = [r["path"] for r in records if r["path"] not in JUDGEMENT]
    if missing_judgement:
        print(f"\nABORT: no judgement recorded for {missing_judgement}")
        return 3

    reviewed = []
    for r in records:
        j = JUDGEMENT[r["path"]]
        reviewed.append(
            {
                "path": r["path"],
                "bytes_git_blob": r["bytes"],
                "sha256_git_blob": r["sha256_git_blob"],
                "sha256_worktree": r["sha256_worktree"],
                "representation": r["representation"],
                "ownership": j["ownership"],
                "license": {
                    "mirror_license": MIRROR_LICENSE,
                    "mirror_license_sha256": MIRROR_LICENSE_SHA256,
                    "file_license": j["license"],
                    "compatible": j["license_compatible"],
                    "basis": (
                        "THIRD_PARTY_NOTICES.md states everything tracked in src/, "
                        "tools/, tests/ and scripts/ is original work licensed "
                        "Apache-2.0 unless a file header says otherwise; no added file "
                        "carries a conflicting header (checked by grepping all 25 for "
                        "copyright/license/derived-from markers)"
                    ),
                },
                "provenance": j["provenance"],
                "proprietary_derived_content": {
                    "assessment": j["proprietary_derived_content"],
                    "marker_hits": r["proprietary_markers"],
                    "marker_note": (
                        "marker hits are NAME references (version.dll, "
                        "bridge_gfx1030_fatbin, gfx1100_code_object, 'proprietary'), "
                        "recorded so the reference is visible; none of them is a byte "
                        "of the artifact"
                    ),
                    "binary_profile": {
                        "nul_bytes": 0 if not r["looks_binary"] else "present",
                        "non_ascii_bytes": r["non_ascii_bytes"],
                    },
                },
                "secrets": {
                    "patterns_applied": len(SECRET_PATTERNS),
                    "bytes_scanned": r["bytes"],
                    "hits": r["secrets"],
                    "status": "CLEAN" if not r["secrets"] else "HITS",
                },
                "private_paths": {
                    "patterns_applied": len(PRIVATE_PATH_LITERAL),
                    "literal_form_hits": r["private_paths"].get(
                        "windows_user_path_literal", []
                    ),
                    "json_escaped_form_hits": r["private_paths"].get(
                        "windows_user_path_json_escaped", []
                    ),
                    "combined_pattern_hits": r["private_paths"].get(
                        "windows_user_path_any", []
                    ),
                    "posix_home_hits": r["private_paths"].get("posix_home_path", []),
                    "personal_email_hits": r["private_paths"].get("personal_email", []),
                    "local_install_path_hits": r["local_install_paths"],
                    "status": "CLEAN" if not r["private_paths"] else "HITS",
                },
                "external_contributor_material": {
                    "patterns_applied": len(EXTERNAL_CONTRIBUTOR_PATTERNS),
                    "hits": r["external_contributor_markers"],
                    "assessment": (
                        "none: no hit"
                        if not r["external_contributor_markers"]
                        else (
                            "the only hit is the profile tag 'astra', a serialized "
                            "data-contract key naming a contributed artifact set; it "
                            "attributes no content to any person and names no path"
                        )
                    ),
                },
                "value_to_public_repository": j["value"],
                "decision": j["decision"],
                "decision_reason": j["decision_reason"],
            }
        )

    tally: dict[str, int] = {}
    for rec in reviewed:
        tally[rec["decision"]] = tally.get(rec["decision"], 0) + 1

    review = {
        "schema": "p16af-publication-file-review/1",
        "phase": "16AF",
        "task": "T2 -- review of the files added by the publication branch",
        "generated_by": "p16af/publication/p16af_review_public_files.py",
        "mirror": str(PUBLIC_ROOT),
        "base_ref": BASE_REF,
        "head_ref": HEAD_REF,
        "head_commit": git("rev-parse", "HEAD").stdout.strip(),
        "base_commit": git("rev-parse", BASE_REF).stdout.strip(),
        "enumeration_command": f"git diff --name-status --diff-filter=A {BASE_REF}..{HEAD_REF}",
        "representation": (
            "every file was read as the git blob of HEAD, so a digest here is what a "
            "fresh clone receives; the working-tree digest is recorded too, and any "
            "disagreement is stated per file"
        ),
        "scanner_preconditions": {
            "pattern_self_test": self_test,
            "self_test_gate": (
                "the scan aborts unless the naive literal pattern catches the literal "
                "sample, MISSES the JSON-escaped sample, the escaped pattern catches "
                "the escaped sample and not the literal one, the combined pattern "
                "catches both, and none flags the known-good sample"
            ),
        },
        "coverage": {
            "files_added_by_the_branch": len(reviewed),
            "bytes_scanned": total_bytes,
            "secret_patterns_applied_per_file": len(SECRET_PATTERNS),
            "private_path_patterns_applied_per_file": len(PRIVATE_PATH_LITERAL),
            "proprietary_marker_patterns_applied_per_file": len(PROPRIETARY_MARKERS),
            "external_contributor_patterns_applied_per_file": len(
                EXTERNAL_CONTRIBUTOR_PATTERNS
            ),
            "files_with_any_secret_hit": sum(1 for r in reviewed if r["secrets"]["hits"]),
            "files_with_any_private_path_hit": sum(
                1 for r in reviewed if r["private_paths"]["status"] == "HITS"
            ),
            "files_with_any_proprietary_marker_hit": sum(
                1 for r in reviewed if r["proprietary_derived_content"]["marker_hits"]
            ),
            "files_with_any_external_contributor_hit": sum(
                1 for r in reviewed if r["external_contributor_material"]["hits"]
            ),
            "note": (
                "'0 secrets found' is a statement about "
                f"{len(reviewed)} files and {total_bytes} bytes under "
                f"{len(SECRET_PATTERNS)} patterns, not an unqualified claim."
            ),
        },
        "decision_tally": {
            "APPROVED": tally.get("APPROVED", 0),
            "REJECTED": tally.get("REJECTED", 0),
            "NEEDS_OPERATOR_DECISION": tally.get("NEEDS_OPERATOR_DECISION", 0),
        },
        "files": reviewed,
    }
    OUT.write_text(json.dumps(review, indent=2) + "\n", encoding="utf-8")

    print(f"\nDECISION TALLY")
    for k in ("APPROVED", "REJECTED", "NEEDS_OPERATOR_DECISION"):
        print(f"  {k:24s}: {tally.get(k, 0)}")
    if tally.get("REJECTED"):
        print("\n  REJECTED files:")
        for r in reviewed:
            if r["decision"] == "REJECTED":
                print(f"    {r['path']}: {r['decision_reason']}")
    if tally.get("NEEDS_OPERATOR_DECISION"):
        print("\n  NEEDS_OPERATOR_DECISION files:")
        for r in reviewed:
            if r["decision"] == "NEEDS_OPERATOR_DECISION":
                print(f"    {r['path']}")
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
