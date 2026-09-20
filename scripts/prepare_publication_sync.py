#!/usr/bin/env python3
"""Prepare a conservative refresh of the curated public mirror.

Default mode is read-only:
    python scripts/prepare_publication_sync.py --source-root <private-project>

Optional authoritative-status fingerprinting (still read-only):
    python scripts/prepare_publication_sync.py --source-root <private-project> \
        --status-file <private-project>/SESSION_REPORT.md

Apply mode copies only already-approved changed mappings. It refuses to run
anywhere but a `publication-sync/*` branch, and rolls back completely if the
publication verifier fails:
    python scripts/prepare_publication_sync.py --source-root <private-project> --apply

Mark authoritative status as reviewed (local-only state, never a commit):
    python scripts/prepare_publication_sync.py --source-root <private-project> \
        --status-file <private-project>/SESSION_REPORT.md --mark-status-reviewed

The script never discovers new public files and never commits or pushes.

Publication freshness has two independent dimensions:

  A. MAPPED_IMPLEMENTATION_DRIFT  — an already-approved mapped source file
     changed and could be refreshed.
  B. AUTHORITATIVE_STATUS_DRIFT  — the private authoritative status report
     changed since a reviewer last marked it reviewed.

Either one yields PUBLICATION_SYNC_PENDING. `changed = 0` alone does not mean
the public project is current.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "audit" / "PUBLICATION_MANIFEST.json"

# Local-only review state. It lives inside .git, so it can never become
# repository content and can never be published.
STATE = ROOT / ".git" / "publication-sync-state.json"

SAFE_CATEGORIES = {
    "PUBLIC_ORIGINAL_SOURCE",
    "PUBLIC_ORIGINAL_TOOLING",
    "PUBLIC_SAFE_TEST",
    "PUBLIC_DOCUMENTATION_SOURCE",
}

SAFE_SUFFIXES = {
    ".py", ".cpp", ".c", ".cc", ".cxx", ".h", ".hpp", ".hh",
    ".ps1", ".bat", ".md", ".json", ".txt", ".def", ".toml", ".ini",
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

PUBLICATION_BRANCH_PREFIX = "publication-sync/"

STATE_SCHEMA = 1


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


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True
    )


def git_out(*args: str) -> str:
    p = git(*args)
    return p.stdout.strip() if p.returncode == 0 else ""


def git_status_porcelain() -> list[str]:
    return [line for line in git_out("status", "--porcelain").splitlines()
            if line.strip()]


def current_branch() -> str:
    return git_out("rev-parse", "--abbrev-ref", "HEAD")


def run_verifier() -> None:
    p = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "verify_publication.py")],
        cwd=ROOT,
    )
    if p.returncode != 0:
        raise RuntimeError("publication verifier failed after apply")


def load_manifest() -> dict[str, Any]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


# --- local-only review state -------------------------------------------------


def load_state() -> dict[str, Any]:
    if not STATE.is_file():
        return {"schema": STATE_SCHEMA}
    try:
        data = json.loads(STATE.read_text(encoding="utf-8"))
    except Exception:
        return {"schema": STATE_SCHEMA}
    if not isinstance(data, dict):
        return {"schema": STATE_SCHEMA}
    data.setdefault("schema", STATE_SCHEMA)
    return data


def save_state(state: dict[str, Any]) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, STATE)


def status_sha(path_str: str) -> str:
    """Hash the private authoritative status report.

    The contents are read, hashed, and discarded. They are never returned,
    printed, excerpted, or written anywhere outside this function.
    """
    return sha256(Path(path_str).expanduser().read_bytes())


# --- manifest / source scan --------------------------------------------------


def scan_manifest(
    source_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    """Return (manifest, result, changes). Never mutates anything on disk."""
    manifest = load_manifest()
    files = manifest.get("files")
    if not isinstance(files, list):
        raise SystemExit("publication manifest has no files list")

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
        "mapped_files": len(files),
        "unchanged": unchanged,
        "changed": len(changes),
        "missing_source_files": missing,
        "blockers": blockers,
    }
    return manifest, result, changes


# --- apply -------------------------------------------------------------------


def check_apply_preconditions() -> list[str]:
    """Return a list of refusal reasons. Empty means apply may proceed.

    Semantics (deliberately strict but not self-defeating):
      * the current branch must be a `publication-sync/*` branch, so a
        publication mutation can never land on `main`;
      * `origin/main` must exist locally as a remote-tracking ref;
      * the branch must not be behind `origin/main` — equivalently,
        `origin/main` is an ancestor of HEAD (which is also what
        `merge-base(origin/main, HEAD) == origin/main` states). This permits
        legitimate publication commits made on this branch after it was cut
        from the current `origin/main`.
    """
    reasons: list[str] = []
    branch = current_branch()
    if not branch.startswith(PUBLICATION_BRANCH_PREFIX):
        reasons.append(
            f"refusing --apply on branch {branch!r}: "
            f"apply is only allowed on {PUBLICATION_BRANCH_PREFIX}* branches"
        )
    if not git_out("rev-parse", "--verify", "--quiet", "refs/remotes/origin/main"):
        reasons.append("refusing --apply: origin/main is not available locally")
    else:
        p = git("merge-base", "--is-ancestor", "origin/main", "HEAD")
        if p.returncode != 0:
            reasons.append(
                "refusing --apply: this branch is behind origin/main; "
                "fast-forward or rebase before publishing"
            )
    return reasons


def apply_transactionally(
    manifest: dict[str, Any], changes: list[dict[str, Any]]
) -> int:
    """Write approved changes, verify, and roll back completely on failure.

    `manifest` must be the same object the change entries were taken from, so
    that the updated hashes written back are the ones actually persisted.
    """
    manifest_old = MANIFEST.read_bytes()

    # Retain the prior bytes of every destination we are about to touch.
    backups: dict[str, bytes | None] = {}
    for item in changes:
        dst = ROOT / item["public_path"]
        backups[item["public_path"]] = dst.read_bytes() if dst.is_file() else None

    def write_atomic(path: Path, data: bytes) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)

    def rollback() -> bool:
        for rel, old in backups.items():
            target = ROOT / rel
            if old is None:
                if target.is_file():
                    target.unlink()
            else:
                write_atomic(target, old)
        write_atomic(MANIFEST, manifest_old)
        # Confirm the tree matches the pre-apply state.
        return git("diff", "--exit-code").returncode == 0

    try:
        for item in changes:
            write_atomic(ROOT / item["public_path"], item["_payload"])
            entry = item["_entry"]
            entry["source_sha256"] = item["new_source_sha256"]
            entry["public_sha256"] = item["new_public_sha256"]
            entry["source_bytes"] = item["source_bytes"]
            entry["bytes"] = item["public_bytes"]
        write_atomic(
            MANIFEST, (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
        )
        run_verifier()
    except BaseException as exc:  # verifier failure or any write error
        restored = rollback()
        print(
            json.dumps(
                {
                    "apply": "rolled_back",
                    "restored_clean": restored,
                    "reason": type(exc).__name__,
                },
                indent=2,
            )
        )
        print("\nAPPLY_ROLLED_BACK", file=sys.stderr)
        return 3
    return 0


# --- main --------------------------------------------------------------------


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
    ap.add_argument(
        "--status-file",
        default=None,
        help=(
            "Private authoritative status report. Read only, hashed only; "
            "its contents are never copied, printed, or stored in tracked files."
        ),
    )
    ap.add_argument(
        "--mark-status-reviewed",
        action="store_true",
        help="Record the current status-file hash as reviewed, in local-only state.",
    )
    ap.add_argument(
        "--mark-new-file-review-pending",
        action="store_true",
        help="Set the explicit new-file-review marker (forces PENDING).",
    )
    ap.add_argument(
        "--clear-new-file-review-pending",
        action="store_true",
        help="Clear the explicit new-file-review marker.",
    )
    ns = ap.parse_args()

    source_root = Path(ns.source_root).expanduser().resolve()
    if not source_root.is_dir():
        raise SystemExit("source root does not exist or is not a directory")
    if source_root == ROOT.resolve():
        raise SystemExit("source root and public repository must be different directories")

    # --- marker-only operations ---------------------------------------------
    if ns.mark_new_file_review_pending or ns.clear_new_file_review_pending:
        state = load_state()
        state["new_file_review_pending"] = bool(ns.mark_new_file_review_pending)
        save_state(state)
        print(json.dumps(
            {
                "mode": "mark-new-file-review",
                "new_file_review_pending": state["new_file_review_pending"],
            },
            indent=2,
        ))
        return 0

    # --- mark authoritative status reviewed ----------------------------------
    if ns.mark_status_reviewed:
        if not ns.status_file:
            raise SystemExit("--mark-status-reviewed requires --status-file")
        dirty = git_status_porcelain()
        if dirty:
            raise SystemExit(
                "public worktree is not clean; refusing to mark status reviewed:\n"
                + "\n".join(dirty)
            )
        local_main = git_out("rev-parse", "--verify", "--quiet", "refs/heads/main")
        remote_main = git_out(
            "rev-parse", "--verify", "--quiet", "refs/remotes/origin/main"
        )
        if not local_main or not remote_main or local_main != remote_main:
            raise SystemExit(
                "refusing to mark status reviewed: local main is not equal to "
                "origin/main (fast-forward the mirror first)"
            )
        state = load_state()
        state["schema"] = STATE_SCHEMA
        state["reviewed_status_sha256"] = status_sha(ns.status_file)
        state["reviewed_at_utc"] = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        save_state(state)
        # Deliberately does not echo the hash or the private path.
        print(json.dumps({"mode": "mark-status-reviewed", "marked": True}, indent=2))
        return 0

    # --- normal check / apply -------------------------------------------------
    manifest, result, changes = scan_manifest(source_root)
    missing = result["missing_source_files"]
    blockers = result["blockers"]

    # --- status fingerprint ---------------------------------------------------
    state = load_state()
    status_drift = False
    if ns.status_file:
        current = status_sha(ns.status_file)
        recorded = state.get("reviewed_status_sha256")
        status_drift = (recorded != current)

    new_file_pending = bool(state.get("new_file_review_pending"))

    has_real_blocker = bool(blockers or missing)
    if has_real_blocker:
        publication_state = "PUBLICATION_SYNC_BLOCKED"
    elif changes or status_drift or new_file_pending:
        publication_state = "PUBLICATION_SYNC_PENDING"
    else:
        publication_state = "PUBLICATION_SYNC_NONE"

    out: dict[str, Any] = {
        "mode": "apply" if ns.apply else "check",
        "mapped_files": result["mapped_files"],
        "unchanged": result["unchanged"],
        "changed": result["changed"],
        "missing_source_files": missing,
        "blockers": blockers,
        "changes": [
            {k: v for k, v in item.items() if not k.startswith("_")}
            for item in changes
        ],
    }
    # Only these two facts about the status file are ever emitted — never the
    # hash, never the path, never any excerpt.
    if ns.status_file:
        out["status_file_supplied"] = True
        out["status_drift"] = status_drift
    if new_file_pending:
        out["new_file_review_pending"] = True
    out["publication_state"] = publication_state
    out["requires_curated_status_review"] = bool(
        changes or status_drift or new_file_pending
    )
    out["note"] = (
        "New/unmapped source files and public status prose are intentionally not "
        "auto-included. They require explicit provenance/publication review."
    )

    if has_real_blocker:
        print(json.dumps(out, indent=2))
        print("\nNO APPLY: blockers or missing mapped source files exist.", file=sys.stderr)
        return 2

    if not ns.apply:
        print(json.dumps(out, indent=2))
        return 0

    # --- apply path -----------------------------------------------------------
    reasons = check_apply_preconditions()
    if reasons:
        print(json.dumps({**out, "apply_refused": reasons}, indent=2))
        print("\nAPPLY_REFUSED", file=sys.stderr)
        return 4

    dirty = git_status_porcelain()
    if dirty:
        raise SystemExit(
            "public repository is not clean; refusing --apply:\n" + "\n".join(dirty)
        )

    rc = apply_transactionally(manifest, changes)
    if rc != 0:
        return rc

    print(json.dumps(out, indent=2))
    print(
        "\nAPPLY COMPLETE. No commit or push was performed. "
        "Review git diff, curate public status documents, then use a "
        "publication-sync branch and PR."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
