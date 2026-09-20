#!/usr/bin/env python3
"""Prepare a conservative refresh of the curated public mirror.

Default mode is read-only:
    python scripts/prepare_publication_sync.py --source-root <private-project>

Apply mode copies only already-approved changed mappings:
    python scripts/prepare_publication_sync.py --source-root <private-project> --apply

The script never discovers new public files and never commits or pushes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "audit" / "PUBLICATION_MANIFEST.json"

SAFE_CATEGORIES = {
    "PUBLIC_ORIGINAL_SOURCE",
    "PUBLIC_ORIGINAL_TOOLING",
    "PUBLIC_SAFE_TEST",
    "PUBLIC_DOCUMENTATION_SOURCE",
}

SAFE_SUFFIXES = {
    ".py", ".cpp", ".c", ".cc", ".cxx", ".h", ".hpp", ".hh",
    ".ps1", ".md", ".json", ".txt", ".def", ".toml", ".ini",
    ".yml", ".yaml",
}

SECRET_PATTERNS = {
    "github_token": re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),
    "github_pat": re.compile(rb"github_pat_[A-Za-z0-9_]{30,}"),
    "openai_key": re.compile(rb"sk-(?:proj-)?[A-Za-z0-9]{32,}"),
    "anthropic_key": re.compile(rb"sk-ant-[A-Za-z0-9_-]{20,}"),
    "aws_access_key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "private_key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "bearer": re.compile(rb"(?i)\bBearer\s+[A-Za-z0-9_.-]{32,}"),
}

PERSONAL_PATTERNS = {
    "windows_user_path": re.compile(rb"(?i)[A-Z]:[\\/]+Users[\\/]+(?!<|path|your)"),
    "posix_home_path": re.compile(rb"/(?:home|Users)/[A-Za-z0-9._-]+/"),
    "personal_email": re.compile(
        rb"(?i)[A-Za-z0-9._%+-]+@(?:gmail|outlook|hotmail|yahoo|protonmail)\.com"
    ),
}

RECOGNIZED_MODIFICATIONS = {
    "none",
    "line endings normalised CRLF -> LF",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def transform(data: bytes, modification: str) -> bytes:
    if modification == "none":
        return data
    if modification == "line endings normalised CRLF -> LF":
        return data.replace(b"\r\n", b"\n")
    raise RuntimeError(f"unrecognized publication transform: {modification!r}")


def scan_candidate(rel: str, data: bytes) -> list[str]:
    findings: list[str] = []
    for name, rx in SECRET_PATTERNS.items():
        if rx.search(data):
            findings.append(f"{rel}: secret-like content [{name}]")
    for name, rx in PERSONAL_PATTERNS.items():
        if rx.search(data):
            findings.append(f"{rel}: personal/machine-specific content [{name}]")
    return findings


def git_status_porcelain() -> list[str]:
    p = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in p.stdout.splitlines() if line.strip()]


def run_verifier() -> None:
    p = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_publication.py")],
        cwd=ROOT,
    )
    if p.returncode != 0:
        raise RuntimeError("publication verifier failed after apply")


def load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--source-root",
        required=True,
        help="Private source-project root. It is read only.",
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Apply already-approved changed mappings to this public worktree.",
    )
    ns = ap.parse_args()

    source_root = Path(ns.source_root).expanduser().resolve()
    if not source_root.is_dir():
        raise SystemExit("source root does not exist or is not a directory")
    if source_root == ROOT.resolve():
        raise SystemExit("source root and public repository must be different directories")

    manifest = load_manifest()
    files = manifest.get("files")
    if not isinstance(files, list):
        raise SystemExit("publication manifest has no files list")

    if ns.apply:
        dirty = git_status_porcelain()
        if dirty:
            raise SystemExit(
                "public repository is not clean; refusing --apply:\n" + "\n".join(dirty)
            )

    changes: list[dict[str, Any]] = []
    unchanged = 0
    missing: list[str] = []
    blockers: list[str] = []

    for entry in files:
        src_rel = entry.get("source_path")
        dst_rel = entry.get("public_path")
        category = entry.get("publication_category")
        modification = entry.get("modifications", "none")

        if not all(isinstance(x, str) for x in (src_rel, dst_rel, category, modification)):
            blockers.append(f"malformed manifest entry: {entry!r}")
            continue
        if category not in SAFE_CATEGORIES:
            blockers.append(f"{dst_rel}: category is not auto-sync eligible: {category}")
            continue
        if modification not in RECOGNIZED_MODIFICATIONS:
            blockers.append(f"{dst_rel}: unrecognized transform: {modification}")
            continue

        src = source_root / src_rel
        dst = ROOT / dst_rel
        if not inside(source_root, src):
            blockers.append(f"{dst_rel}: source path escapes source root")
            continue
        if not inside(ROOT, dst):
            blockers.append(f"{dst_rel}: public path escapes repository root")
            continue
        if dst.suffix.lower() not in SAFE_SUFFIXES:
            blockers.append(f"{dst_rel}: suffix is not eligible for automatic sync")
            continue
        if not src.is_file():
            missing.append(src_rel)
            continue
        if not dst.is_file():
            blockers.append(f"{dst_rel}: mapped public file is missing")
            continue

        src_bytes = src.read_bytes()
        old_public = dst.read_bytes()
        current_public_sha = sha256(old_public)
        recorded_public_sha = entry.get("public_sha256")

        if current_public_sha != recorded_public_sha:
            blockers.append(
                f"{dst_rel}: public file drifted from recorded manifest "
                f"({current_public_sha[:12]} != {str(recorded_public_sha)[:12]})"
            )
            continue

        source_sha = sha256(src_bytes)
        if source_sha == entry.get("source_sha256"):
            unchanged += 1
            continue

        public_bytes = transform(src_bytes, modification)
        candidate_sha = sha256(public_bytes)
        findings = scan_candidate(dst_rel, public_bytes)
        if findings:
            blockers.extend(findings)
            continue

        changes.append(
            {
                "source_path": src_rel,
                "public_path": dst_rel,
                "old_source_sha256": entry.get("source_sha256"),
                "new_source_sha256": source_sha,
                "old_public_sha256": recorded_public_sha,
                "new_public_sha256": candidate_sha,
                "source_bytes": len(src_bytes),
                "public_bytes": len(public_bytes),
                "_payload": public_bytes,
                "_entry": entry,
            }
        )

    result = {
        "mode": "apply" if ns.apply else "check",
        "mapped_files": len(files),
        "unchanged": unchanged,
        "changed": len(changes),
        "missing_source_files": missing,
        "blockers": blockers,
        "changes": [
            {k: v for k, v in item.items() if not k.startswith("_")}
            for item in changes
        ],
        "requires_curated_status_review": bool(changes),
        "note": (
            "New/unmapped source files and public status prose are intentionally not "
            "auto-included. They require explicit provenance/publication review."
        ),
    }

    if blockers or missing:
        print(json.dumps(result, indent=2))
        print("\nNO APPLY: blockers or missing mapped source files exist.", file=sys.stderr)
        return 2

    if not ns.apply:
        print(json.dumps(result, indent=2))
        return 0

    dirty = git_status_porcelain()
    if dirty:
        raise SystemExit("public repository became dirty before apply; refusing")

    for item in changes:
        dst = ROOT / item["public_path"]
        dst.write_bytes(item["_payload"])
        entry = item["_entry"]
        entry["source_sha256"] = item["new_source_sha256"]
        entry["public_sha256"] = item["new_public_sha256"]
        entry["source_bytes"] = item["source_bytes"]
        entry["bytes"] = item["public_bytes"]

    if changes:
        tmp = MANIFEST.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, MANIFEST)

    run_verifier()

    print(json.dumps(result, indent=2))
    print(
        "\nAPPLY COMPLETE. No commit or push was performed. "
        "Review git diff, curate public status documents, then use a "
        "publication-sync branch and PR."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
