#!/usr/bin/env python3
"""Publication verifier.

Fails closed. Every check reports PASS/FAIL and the process exits non-zero
if any check fails, so it is usable as a gate locally and in CI.

Never prints matched secret content: only the path, the category, and a
redacted fingerprint.

Usage:
    python scripts/verify_publication.py            # verify the working tree
    python scripts/verify_publication.py --git-head # verify committed blobs
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REQUIRED = [
    "README.md", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md",
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md", "SUPPORT.md",
    "STATUS.md", "ROADMAP.md", "ARCHITECTURE.md", "REPRODUCIBILITY.md",
    "CHANGELOG.md", "CITATION.cff", "requirements-ci.txt",
    ".gitignore", ".gitattributes",
    ".github/PULL_REQUEST_TEMPLATE.md", ".github/CODEOWNERS",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/research_validation.yml",
    ".github/ISSUE_TEMPLATE/hardware_test_result.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/documentation.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/publication-audit.yml",
    "src/emulator/emu.py", "src/oracle/isa_oracle_scalar.py",
    "scripts/verify-publication.ps1",
    "audit/PUBLICATION_MANIFEST.json", "audit/GITHUB_READINESS.json",
]

SECRET_PATTERNS = {
    "github_token": re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),
    "github_pat": re.compile(rb"github_pat_[A-Za-z0-9_]{30,}"),
    "openai_key": re.compile(rb"sk-(proj-)?[A-Za-z0-9]{32,}"),
    "aws_akid": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "aws_secret": re.compile(rb"aws_secret_access_key\s*[=:]\s*\S{20,}", re.I),
    "private_key": re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "bearer": re.compile(rb"[Bb]earer\s+[A-Za-z0-9_\-\.]{32,}"),
    "basic_auth": re.compile(rb"[Aa]uthorization\s*:\s*Basic\s+\S{20,}"),
    "slack_token": re.compile(rb"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    "anthropic_key": re.compile(rb"sk-ant-[A-Za-z0-9_\-]{20,}"),
}

PERSONAL_PATTERNS = {
    "windows_user_path": re.compile(rb"[Cc]:[\\/]Users[\\/](?!<|path|your)", re.I),
    "posix_user_path": re.compile(rb"/(?:home|Users)/[A-Za-z0-9._-]+/"),
    "game_library_path": re.compile(rb"[A-Za-z]:[\\/](?:BattleNet|Games|SteamLibrary)"),
    "personal_email": re.compile(
        rb"[A-Za-z0-9._%+-]+@(?:gmail|outlook|hotmail|yahoo|protonmail)\.com", re.I
    ),
}

# extensions that must never be tracked
FORBIDDEN_EXT = {
    ".co", ".fatbin", ".hipfb", ".hipi", ".bundle", ".bin",
    ".dll", ".exe", ".o", ".obj", ".lib", ".exp", ".pre", ".bc",
    ".dmp", ".zip", ".pyc", ".gfx1030accept",
}

YAML_EXT = (".yml", ".yaml", ".cff")

# External GitHub Actions must be pinned to an immutable commit SHA. A moving
# tag such as `@v7` can be re-pointed by the upstream owner, which would let
# unreviewed code run with this repository's CI token.
ACTION_REF_RX = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)\s*(?:#.*)?$")
SHA40_RX = re.compile(r"^[0-9a-fA-F]{40}$")

MAX_BYTES = 100 * 1024 * 1024
WARN_BYTES = 1 * 1024 * 1024

RESULTS: list[tuple[bool, str, str]] = []


def record(ok: bool, name: str, detail: str = "") -> None:
    RESULTS.append((ok, name, detail))


def iter_files(head: bool):
    if not head:
        # Prefer git's own enumeration, which honours .gitignore and
        # .git/info/exclude, so local-only files (build records, handoff
        # notes) are correctly out of scope for the published-tree audit.
        try:
            p = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"],
                               cwd=ROOT, capture_output=True, text=True,
                               check=True)
            listed = [l for l in p.stdout.splitlines() if l.strip()]
            if listed:
                for l in listed:
                    yield l.strip()
                return
        except Exception:
            pass
        for dp, dns, fns in os.walk(ROOT):
            dns[:] = [d for d in dns if d not in (".git", "__pycache__")]
            for fn in fns:
                yield os.path.relpath(os.path.join(dp, fn), ROOT).replace("\\", "/")
        return
    out = subprocess.run(["git", "ls-tree", "-r", "--name-only", "HEAD"],
                         cwd=ROOT, capture_output=True, text=True, check=True)
    for line in out.stdout.splitlines():
        if line.strip():
            yield line.strip()


def blob_bytes(head: bool, rel: str) -> bytes | None:
    if not head:
        try:
            with open(os.path.join(ROOT, rel.replace("/", os.sep)), "rb") as f:
                return f.read()
        except OSError:
            return None
    p = subprocess.run(["git", "show", f"HEAD:{rel}"], cwd=ROOT,
                       capture_output=True)
    return p.stdout if p.returncode == 0 else None


def check_secrets(head: bool, files: list[str]) -> None:
    hits = []
    for rel in files:
        ext = os.path.splitext(rel)[1].lower()
        if ext in {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf"}:
            continue
        data = blob_bytes(head, rel)
        if not data or len(data) > 8 * 1024 * 1024:
            continue
        for name, rx in SECRET_PATTERNS.items():
            m = rx.search(data)
            if m:
                fp = hashlib.sha256(m.group(0)).hexdigest()[:12]
                hits.append(f"{rel} [{name} redacted:{fp}]")
    record(not hits, "secret scan",
           "; ".join(hits) if hits else f"{len(files)} files clean")


def check_personal(head: bool, files: list[str]) -> None:
    hits = []
    allowlist_suffix = ("scripts/verify_publication.py",)
    for rel in files:
        if rel.endswith(allowlist_suffix):
            continue  # this file defines the patterns
        data = blob_bytes(head, rel)
        if not data or len(data) > 8 * 1024 * 1024:
            continue
        for name, rx in PERSONAL_PATTERNS.items():
            for m in rx.finditer(data):
                ctx = data[max(0, m.start() - 48):m.end() + 48]
                if b"path/to" in ctx or b"<PROJECT_ROOT>" in ctx or b"<user>" in ctx:
                    continue
                line = data[:m.start()].count(b"\n") + 1
                hits.append(f"{rel}:{line} [{name}]")
    # a handful of literal placeholder usages are fine; real hits are not
    record(not hits, "privacy scan",
           "; ".join(hits[:20]) if hits else f"{len(files)} files clean")


def check_forbidden_artifacts(files: list[str]) -> None:
    bad = [f for f in files if os.path.splitext(f)[1].lower() in FORBIDDEN_EXT]
    record(not bad, "prohibited artifact scan",
           "; ".join(bad[:20]) if bad else "no prohibited extensions tracked")


def check_large_files(head: bool, files: list[str]) -> None:
    oversize, warn = [], []
    for rel in files:
        data = blob_bytes(head, rel)
        if data is None:
            continue
        n = len(data)
        if n >= MAX_BYTES:
            oversize.append(f"{rel} ({n/1e6:.1f}MB)")
        elif n > WARN_BYTES:
            warn.append(f"{rel} ({n/1e6:.1f}MB)")
    record(not oversize, "large-file scan",
           ("oversize: " + "; ".join(oversize)) if oversize
           else (f"ok; >1MiB: {', '.join(warn)}" if warn else "all files < 1MiB"))


def check_json(head: bool, files: list[str]) -> None:
    bad = []
    for rel in files:
        if not rel.endswith(".json"):
            continue
        data = blob_bytes(head, rel)
        if not data:
            continue
        try:
            json.loads(data.decode("utf-8"))
        except Exception as e:
            bad.append(f"{rel}: {e}")
    record(not bad, "JSON validity", "; ".join(bad[:10]) if bad else "all parse")


def _structural_yaml_check(text: str, rel: str) -> list[str]:
    """Fallback validator used when PyYAML is unavailable.

    Checks the properties this repository actually depends on, so it can
    still fail on a real defect: no tab indentation, no unclosed quotes on
    scalar lines, unique `id:` values, `name`/`description`/`body` present in
    issue forms, and every `type: dropdown` carrying an `options:` list.
    """
    problems: list[str] = []
    ids: list[str] = []
    n_dropdown = 0
    n_options = 0
    in_block_scalar = False
    for i, line in enumerate(text.splitlines(), 1):
        # A line at or below the block-scalar key's indentation ends it.
        if in_block_scalar:
            if line.strip() and not line.startswith((" ", "\t")):
                in_block_scalar = False
        # Block-scalar bodies (| and >) contain arbitrary text; skip them.
        if in_block_scalar:
            continue
        if "\t" in line[: len(line) - len(line.lstrip())]:
            problems.append(f"{rel}:{i} tab indentation")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # Only inspect scalars that *begin* with a quote; apostrophes inside
        # unquoted prose ("the project's policy") are not delimiters.
        m_q = re.match(r"^\s*(?:- )?[^:#]+:\s*([\"'])(.*)$", line)
        if m_q:
            q, body = m_q.group(1), m_q.group(2).rstrip()
            if not body.endswith(q) or len(body) < 2:
                problems.append(f"{rel}:{i} unterminated quoted scalar")
        # Block scalars (| and >) legitimately contain arbitrary text, so skip
        # bracket balance for their bodies.
        if re.match(r"^\s*(?:- )?[^:#]+:\s*[|>][-+]?\s*$", line):
            in_block_scalar = True
            continue
        for open_c, close_c in (("[", "]"), ("{", "}")):
            if line.count(open_c) != line.count(close_c):
                problems.append(
                    f"{rel}:{i} unbalanced flow collection ({open_c}{close_c})"
                )
        if re.match(r"^\s*-\s*id:\s*\S+", line):
            ids.append(stripped.split("id:", 1)[1].strip())
        if re.match(r"^\s*type:\s*dropdown\s*$", line):
            n_dropdown += 1
        if re.match(r"^\s*options:\s*$", line):
            n_options += 1
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        problems.append(f"{rel} duplicate id(s): {', '.join(sorted(dupes))}")
    if n_dropdown and n_options < n_dropdown:
        problems.append(
            f"{rel} {n_dropdown} dropdown(s) but only {n_options} options block(s)"
        )
    if "/ISSUE_TEMPLATE/" in rel and rel.endswith((".yml", ".yaml")):
        base = os.path.basename(rel)
        if base not in ("config.yml",):
            for key in ("name:", "description:", "body:"):
                if not re.search(rf"^{key}", text, re.M):
                    problems.append(f"{rel} missing top-level `{key}`")
    return problems


def check_yaml(head: bool, files: list[str]) -> None:
    try:
        import yaml  # type: ignore
    except ImportError:
        yaml = None

    bad = []
    n = 0
    for rel in files:
        if not rel.endswith(YAML_EXT):
            continue
        data = blob_bytes(head, rel)
        if not data:
            continue
        n += 1
        text = data.decode("utf-8", "ignore")
        if yaml is not None:
            try:
                yaml.safe_load(text)
            except Exception as e:
                bad.append(f"{rel}: {e}")
            continue
        bad.extend(_structural_yaml_check(text, rel))

    mode = "PyYAML" if yaml is not None else "structural fallback"
    record(not bad, "YAML validity",
           "; ".join(bad[:10]) if bad else f"{n} files ok ({mode})")


def check_required(files: list[str]) -> None:
    present = set(files)
    missing = [r for r in REQUIRED if r not in present]
    record(not missing, "required files", "; ".join(missing) if missing
           else f"{len(REQUIRED)} required files present")


def check_manifest(head: bool, files: list[str]) -> None:
    data = blob_bytes(head, "audit/PUBLICATION_MANIFEST.json")
    if not data:
        record(False, "publication manifest", "audit/PUBLICATION_MANIFEST.json missing")
        return
    try:
        man = json.loads(data.decode("utf-8"))
    except Exception as e:
        record(False, "publication manifest", f"unparseable: {e}")
        return
    tracked = set(files)
    listed = {f["public_path"] for f in man.get("files", [])}
    newly_authored = {e["public_path"]
                      for e in man.get("newly_authored", [])}
    listed |= newly_authored
    # every manifest entry must be tracked
    absent = sorted(listed - tracked)
    # every tracked non-scaffolding file should be accounted for
    scaffolding_prefixes = (
        ".github/", "audit/", "docs/", "scripts/", "conftest.py",
    )
    scaffolding_exact = {
        "README.md", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md",
        "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SECURITY.md",
        "SUPPORT.md", "STATUS.md", "ROADMAP.md", "ARCHITECTURE.md",
        "REPRODUCIBILITY.md", "CHANGELOG.md", "CITATION.cff",
        "requirements-ci.txt", ".gitignore", ".gitattributes",
    }
    unaccounted = [
        f for f in tracked
        if f not in listed
        and not f.startswith(scaffolding_prefixes)
        and f not in scaffolding_exact
    ]
    ok = not absent and not unaccounted
    detail = []
    if absent:
        detail.append("manifest entries not tracked: " + "; ".join(absent[:10]))
    if unaccounted:
        detail.append("tracked files not in manifest: " + "; ".join(unaccounted[:10]))
    record(ok, "publication manifest",
           "; ".join(detail) if detail else f"{len(listed)} manifest entries match")


def check_tracked_file_list(head: bool, files: list[str]) -> None:
    data = blob_bytes(head, "audit/TRACKED_FILES.txt")
    if not data:
        record(False, "tracked-file inventory", "audit/TRACKED_FILES.txt missing")
        return
    listed_lines = [line.strip().replace("\\", "/")
                    for line in data.decode("utf-8", "replace").splitlines()
                    if line.strip()]
    listed = set(listed_lines)
    actual = set(files)
    duplicates = sorted({p for p in listed_lines if listed_lines.count(p) > 1})
    absent = sorted(listed - actual)
    unlisted = sorted(actual - listed)
    ok = not duplicates and not absent and not unlisted
    detail = []
    if duplicates:
        detail.append("duplicate entries: " + "; ".join(duplicates[:10]))
    if absent:
        detail.append("listed paths absent from tree: " + "; ".join(absent[:10]))
    if unlisted:
        detail.append("tree paths missing from inventory: " + "; ".join(unlisted[:10]))
    record(ok, "tracked-file inventory",
           "; ".join(detail) if detail else f"all {len(actual)} tree paths listed exactly once")


def check_readme_links(head: bool) -> None:
    data = blob_bytes(head, "README.md")
    if not data:
        record(False, "README links", "README.md missing")
        return
    text = data.decode("utf-8", "ignore")
    targets = re.findall(r"\]\((?!https?://|#)([^)#]+)", text)
    tracked = set(iter_files(head))
    missing = []
    for t in targets:
        t = t.strip()
        if t.startswith("mailto:"):
            continue
        if t not in tracked:
            missing.append(t)
    record(not missing, "README relative links",
           "; ".join(missing[:10]) if missing else f"{len(targets)} links resolve")


def action_ref_problems(rel: str, text: str) -> list[str]:
    """Every external action reference must be a full 40-hex commit SHA.

    Local actions (`./...`) are exempt: they are this repository's own code.
    """
    problems: list[str] = []
    for i, line in enumerate(text.splitlines(), 1):
        m = ACTION_REF_RX.match(line)
        if not m:
            continue
        ref = m.group(1).strip().strip('"').strip("'")
        if ref.startswith("./"):
            continue
        if "@" not in ref:
            problems.append(f"{rel}:{i} `uses: {ref}` carries no ref")
            continue
        pinned = ref.rpartition("@")[2]
        if not SHA40_RX.match(pinned):
            problems.append(
                f"{rel}:{i} `uses: {ref}` is not pinned to a 40-hex commit SHA"
            )
    return problems


def check_workflow_pins(head: bool, files: list[str]) -> None:
    bad: list[str] = []
    n = 0
    for rel in files:
        norm = rel.replace("\\", "/")
        if not norm.startswith(".github/workflows/"):
            continue
        if not norm.endswith(YAML_EXT):
            continue
        data = blob_bytes(head, rel)
        if not data:
            continue
        n += 1
        bad.extend(action_ref_problems(norm, data.decode("utf-8", "ignore")))
    record(not bad, "action pinning",
           "; ".join(bad[:10]) if bad else f"{n} workflow(s) fully SHA-pinned")


def check_no_pycache(files: list[str]) -> None:
    bad = [f for f in files if "__pycache__" in f or f.endswith(".pyc")]
    record(not bad, "no bytecode caches tracked",
           "; ".join(bad[:10]) if bad else "clean")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--git-head", action="store_true",
                    help="verify committed blobs instead of the working tree")
    args = ap.parse_args()

    if args.git_head:
        try:
            subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                           capture_output=True, check=True)
        except Exception:
            print("FAIL  no git HEAD to verify")
            return 1

    files = sorted(iter_files(args.git_head))
    scope = "HEAD" if args.git_head else "working tree"
    print(f"verify-publication: {len(files)} files in {scope}\n")

    check_secrets(args.git_head, files)
    check_personal(args.git_head, files)
    check_forbidden_artifacts(files)
    check_large_files(args.git_head, files)
    check_json(args.git_head, files)
    check_yaml(args.git_head, files)
    check_required(files)
    check_manifest(args.git_head, files)
    check_tracked_file_list(args.git_head, files)
    check_readme_links(args.git_head)
    check_workflow_pins(args.git_head, files)
    check_no_pycache(files)

    failed = 0
    for ok, name, detail in RESULTS:
        tag = "PASS" if ok else "FAIL"
        print(f"{tag}  {name:32s} {detail}")
        if not ok:
            failed += 1
    print()
    if failed:
        print(f"PUBLICATION VERIFY: FAIL ({failed} check(s))")
        return 1
    print("PUBLICATION VERIFY: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
