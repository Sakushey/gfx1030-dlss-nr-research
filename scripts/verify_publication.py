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

# --- independent corroboration ----------------------------------------------
#
# `audit/PUBLICATION_MANIFEST.json` is written by the same program that copies
# the published bytes, so it cannot corroborate itself. A separate program --
# one that never writes a published file -- measures both sides and records
# what it found. This verifier consumes that artefact, and treats its `verified`
# style summary fields as non-authoritative: the decision below is recomputed
# from raw per-side facts plus bytes read here, so an author cannot satisfy the
# verifier by asserting a flag.
CORROBORATION_REL = "audit/PUBLICATION_BYTE_CORROBORATION.json"
CORROBORATION_SCHEMA = 1

CURATED_DERIVATIVE = (
    "curated derivative: no mechanical transform reproduces the public bytes "
    "from the private original"
)

#: Fields the manifest is FORBIDDEN to carry, because a measured fact asserted
#: by the artefact's own author is not a measurement.
FORBIDDEN_MANIFEST_FACT_KEYS = ("measured_byte_facts", "measured_facts",
                                "corroborated_facts")

#: The declarations a `modifications` value is allowed to make, and the exact
#: chain each must be reproduced by. Anything not here is rejected.
MECHANICAL_DECLARATIONS = {
    "line endings normalised CRLF -> LF": ["crlf_to_lf"],
    "UTF-8 BOM removed": ["strip_utf8_bom"],
    "UTF-8 BOM added": ["add_utf8_bom"],
}

UTF8_BOM = b"\xef\xbb\xbf"
UTF16LE_BOM = b"\xff\xfe"
UTF16BE_BOM = b"\xfe\xff"
UTF32LE_BOM = b"\xff\xfe\x00\x00"
UTF32BE_BOM = b"\x00\x00\xfe\xff"
_BOMS = ((UTF32LE_BOM, "UTF-32LE"), (UTF32BE_BOM, "UTF-32BE"),
         (UTF8_BOM, "UTF-8"), (UTF16LE_BOM, "UTF-16LE"),
         (UTF16BE_BOM, "UTF-16BE"))

# --- private-identity leakage ------------------------------------------------
#
# The private tree's own name, and the LIVE private phase family. Historical
# private-phase provenance tokens (`phase16o`, `phase16j`, ...) are pervasive in
# the approved published tree -- 65 of 171 tracked files carry one -- and are
# deliberately NOT matched here: rejecting them would reject the known-good
# case. This constant is a maintenance point and must be advanced as the private
# series advances.
LIVE_PRIVATE_PHASE_FAMILY = "phase16a"

IDENTITY_PATTERNS = {
    "private_project_dirname": re.compile(rb"(?i)gfx1030_soft_wmma_phase1"),
    "private_windows_profile": re.compile(
        rb"(?i)[A-Z]:[\\/]+Users[\\/]+(?!<|path|your)"),
    "live_private_phase_token": re.compile(
        rb"(?i)" + LIVE_PRIVATE_PHASE_FAMILY.encode("ascii")),
}

#: A private absolute path written with TWO backslashes -- the form a C/C++
#: string literal produces -- is invisible to the single-separator pattern
#: `check_personal` uses. This pattern tolerates any escape depth. Measured: it
#: finds a real private path in `src/bridge/bridge_config.h` that the
#: single-separator pattern does not.
PRIVATE_PATH_ANY_ESCAPE = re.compile(
    rb"(?i)[A-Z]:[\\/]+Users[\\/]+(?!<|path|your)")

#: Published files KNOWN to carry a private path, as an exact expected count of
#: occurrences. A finite, reviewable register rather than a blanket exemption:
#: a file NOT on this register fails, and a registered file whose count CHANGES
#: fails too. Removing an entry from this register is publication work (the
#: published bytes must change), which is why these are reported rather than
#: silently accepted.
KNOWN_PRIVATE_PATH_REGISTER = {
    "src/bridge/bridge_config.h": 1,
}

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
    # every manifest entry must be tracked
    absent = sorted(listed - tracked)
    # every tracked non-scaffolding file should be accounted for
    scaffolding_prefixes = (
        ".github/", "audit/", "docs/", "scripts/", "conftest.py",
    )
    newly_authored = {e["public_path"]
                      for e in man.get("newly_authored", [])}
    listed |= newly_authored
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


# --- corroboration -----------------------------------------------------------


def bom_label(data: bytes) -> str | None:
    for prefix, name in _BOMS:
        if len(prefix) >= 2 and data.startswith(prefix):
            return name
    return None


def public_facts_bytes(data: bytes) -> dict:
    """The public-side byte facts, recomputed here from the actual bytes."""
    crlf = data.count(b"\r\n")
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bom": bom_label(data),
        "crlf_pairs": crlf,
        "lone_lf": data.count(b"\n") - crlf,
        "lone_cr": data.count(b"\r") - crlf,
    }


def read_public_facts(head: bool, rel: str) -> dict | None:
    data = blob_bytes(head, rel)
    return None if data is None else public_facts_bytes(data)


def load_corroboration(head: bool):
    """Return (artefact, error). Never raises."""
    data = blob_bytes(head, CORROBORATION_REL)
    if data is None:
        scope = "HEAD" if head else "the working tree"
        return None, f"{CORROBORATION_REL} is absent from {scope}"
    try:
        return json.loads(data.decode("utf-8")), None
    except Exception as e:  # noqa: BLE001
        return None, f"{CORROBORATION_REL} is unparseable: {e}"


def _declaration_problems(rel: str, modification: str,
                          src: dict, pub: dict, search: dict) -> list[str]:
    """Is the declared transform TRUE of these measured facts?

    A declaration is accepted only when it is the SHORTEST reproduction of the
    public bytes from the source bytes. A longer chain that happens to end in
    the right place would mean the declared transform is not what happened.
    """
    out: list[str] = []
    chain = search.get("minimal_chain")
    vocab = search.get("vocabulary")
    if isinstance(vocab, list):
        for op in (chain or []):
            if op not in vocab:
                out.append(f"{rel}: reproduction chain names {op!r}, which is "
                           f"not in the declared vocabulary")

    if modification == "none":
        if src["sha256"] != pub["sha256"]:
            out.append(f"{rel}: declares no transform but the measured bytes "
                       f"differ ({src['sha256'][:12]} != {pub['sha256'][:12]})")
        if not search.get("exact_match"):
            out.append(f"{rel}: declares no transform but the search found no "
                       f"reproduction at all")
        return out

    if modification == CURATED_DERIVATIVE:
        if search.get("exact_match"):
            out.append(
                f"{rel}: declares a curated derivative, but "
                f"{chain!r} reproduces the public bytes exactly, so a "
                f"mechanical transform does exist and the declaration is false"
            )
        if src["sha256"] == pub["sha256"]:
            out.append(f"{rel}: declares a curated derivative but the measured "
                       f"bytes are identical")
        return out

    expected = MECHANICAL_DECLARATIONS.get(modification)
    if expected is None:
        out.append(f"{rel}: unrecognized modification declaration "
                   f"{modification!r}")
        return out

    if chain != expected:
        out.append(
            f"{rel}: declares {modification!r}, which is {expected}, but the "
            f"measured reproduction is {chain!r}"
        )

    if modification == "line endings normalised CRLF -> LF":
        if src["crlf_pairs"] == 0:
            out.append(f"{rel}: declares CRLF normalisation but the measured "
                       f"source has 0 CRLF pairs, so the declaration is false")
        if pub["crlf_pairs"] != 0:
            out.append(f"{rel}: declares CRLF normalisation but the measured "
                       f"public copy still has {pub['crlf_pairs']} CRLF pairs")
    elif modification == "UTF-8 BOM removed":
        if src["bom"] != "UTF-8":
            out.append(f"{rel}: declares a UTF-8 BOM was removed but the "
                       f"measured source BOM is {src['bom']!r}")
        if pub["bom"] is not None:
            out.append(f"{rel}: declares a UTF-8 BOM was removed but the "
                       f"measured public BOM is {pub['bom']!r}")
    elif modification == "UTF-8 BOM added":
        if src["bom"] is not None:
            out.append(f"{rel}: declares a UTF-8 BOM was added but the "
                       f"measured source BOM is {src['bom']!r}")
        if pub["bom"] != "UTF-8":
            out.append(f"{rel}: declares a UTF-8 BOM was added but the "
                       f"measured public BOM is {pub['bom']!r}")
    return out


def corroboration_problems(manifest: dict, corroboration, facts_of,
                           load_error: str | None = None) -> list[str]:
    """Pure decision function. Reads NO `verified`-style summary field.

    `facts_of(public_path)` must return the public-side byte facts read from
    the artefact under audit, or None. The verdict is a function of the
    manifest facts, the corroborator's raw per-side facts, and bytes read by
    the caller -- nothing else, so a flag cannot satisfy it.
    """
    if corroboration is None:
        return [load_error or f"{CORROBORATION_REL} is unavailable"]

    problems: list[str] = []
    if corroboration.get("schema") != CORROBORATION_SCHEMA:
        problems.append(f"{CORROBORATION_REL}: schema is "
                        f"{corroboration.get('schema')!r}, expected "
                        f"{CORROBORATION_SCHEMA}")

    producer = str(corroboration.get("generated_by") or "")
    independent_of = str(corroboration.get("independent_of") or "")
    if not producer:
        problems.append(f"{CORROBORATION_REL}: declares no generator")
    if not independent_of:
        problems.append(f"{CORROBORATION_REL}: does not declare what it is "
                        f"independent of")
    # The producer must not BE the manifest author. `independent_of` is
    # expected to NAME the manifest author -- that is what it is for -- so it is
    # checked for presence, not for the author's name.
    if "build_public" in producer:
        problems.append(f"{CORROBORATION_REL}: generated_by names the manifest "
                        f"author, so it corroborates nothing")
    if producer and producer == independent_of:
        problems.append(f"{CORROBORATION_REL}: generator and the thing it "
                        f"claims independence from are the same")

    vocab = corroboration.get("defect_vocabulary")
    if not isinstance(vocab, list) or not vocab:
        problems.append(f"{CORROBORATION_REL}: declares no defect vocabulary, "
                        f"so a 'no transform found' result would be vacuous")

    pairs = corroboration.get("pairs")
    if not isinstance(pairs, list) or not pairs:
        problems.append(f"{CORROBORATION_REL}: contains no pairs")
        return problems

    by_path = {}
    for p in pairs:
        if isinstance(p, dict) and isinstance(p.get("public_path"), str):
            by_path[p["public_path"]] = p

    entries = manifest.get("files") or []
    mapped = {}

    # The manifest may not assert a measured fact; it may only point at one.
    for entry in entries:
        rel = entry.get("public_path")
        if not isinstance(rel, str):
            continue
        mapped[rel] = entry
        for key in FORBIDDEN_MANIFEST_FACT_KEYS:
            if key in entry:
                problems.append(
                    f"{rel}: manifest asserts measured facts in {key!r}; "
                    f"measured facts must come from the corroboration artefact"
                )

    for rel, entry in sorted(mapped.items()):
        rec = by_path.get(rel)
        if rec is None:
            problems.append(f"{rel}: mapped in the manifest but absent from "
                            f"{CORROBORATION_REL}, so nothing corroborates it")
            continue
        if rec.get("public_path") != entry.get("public_path"):
            problems.append(f"{rel}: corroboration pair is mis-keyed")
            continue

        src = rec.get("source")
        pub = rec.get("public")
        search = rec.get("transform_search")
        if not isinstance(src, dict) or not isinstance(pub, dict) \
                or not isinstance(search, dict):
            problems.append(f"{rel}: corroboration pair is unmeasured or "
                            f"malformed")
            continue
        if search.get("n_chains_searched", 0) <= 0:
            problems.append(f"{rel}: corroboration searched no chains")
        if rec.get("source_path") != entry.get("source_path"):
            problems.append(f"{rel}: corroboration maps a different source "
                            f"path than the manifest")

        # manifest vs corroborator, source side (facts the verifier cannot read)
        if entry.get("source_sha256") != src.get("sha256"):
            problems.append(
                f"{rel}: manifest source_sha256 "
                f"{str(entry.get('source_sha256'))[:12]} does not match the "
                f"corroborated source hash {str(src.get('sha256'))[:12]}"
            )
        if entry.get("source_bytes") != src.get("bytes"):
            problems.append(f"{rel}: manifest source_bytes "
                            f"{entry.get('source_bytes')} does not match the "
                            f"corroborated {src.get('bytes')}")

        # manifest vs corroborator vs THE ACTUAL PUBLIC BYTES, read here
        actual = facts_of(rel)
        if actual is None:
            problems.append(f"{rel}: mapped public file could not be read")
            continue
        for key in ("bytes", "sha256", "bom", "crlf_pairs", "lone_lf",
                    "lone_cr"):
            if actual.get(key) != pub.get(key):
                problems.append(
                    f"{rel}: corroborated public {key}={pub.get(key)!r} does "
                    f"not match the file ({actual.get(key)!r})"
                )
        if entry.get("public_sha256") != actual["sha256"]:
            problems.append(
                f"{rel}: published bytes do not match the manifest's recorded "
                f"public_sha256 ({actual['sha256'][:12]} != "
                f"{str(entry.get('public_sha256'))[:12]})"
            )
        if entry.get("bytes") != actual["bytes"]:
            problems.append(f"{rel}: manifest bytes={entry.get('bytes')} does "
                            f"not match the published file ({actual['bytes']})")

        modification = entry.get("modifications", "none")
        problems.extend(_declaration_problems(rel, modification, src, pub,
                                              search))

        if modification == CURATED_DERIVATIVE:
            ref = entry.get("measured_byte_facts_ref")
            if not isinstance(ref, dict):
                problems.append(f"{rel}: a curated derivative must carry a "
                                f"measured_byte_facts_ref pointer")
            elif ref.get("artefact") != CORROBORATION_REL:
                problems.append(f"{rel}: measured_byte_facts_ref names "
                                f"{ref.get('artefact')!r}, not "
                                f"{CORROBORATION_REL!r}")
            elif (ref.get("select") or {}).get("public_path") != rel:
                problems.append(f"{rel}: measured_byte_facts_ref selects a "
                                f"different public path")
            if not entry.get("declared_intent"):
                problems.append(f"{rel}: a curated derivative must carry "
                                f"declared_intent")
            if not entry.get("provenance_note"):
                problems.append(f"{rel}: a curated derivative must carry "
                                f"provenance_note")

    unlisted = sorted(set(by_path) - set(mapped))
    if unlisted:
        problems.append(f"{CORROBORATION_REL}: corroborates "
                        f"{len(unlisted)} path(s) the manifest does not map: "
                        + "; ".join(unlisted[:10]))
    return problems


def check_corroboration(head: bool) -> None:
    data = blob_bytes(head, "audit/PUBLICATION_MANIFEST.json")
    if not data:
        record(False, "independent corroboration",
               "publication manifest missing, so nothing could be corroborated")
        return
    try:
        manifest = json.loads(data.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        record(False, "independent corroboration", f"manifest unparseable: {e}")
        return
    corroboration, err = load_corroboration(head)
    problems = corroboration_problems(
        manifest, corroboration, lambda rel: read_public_facts(head, rel), err)
    record(not problems, "independent corroboration",
           ("; ".join(problems[:10]) + (f" (+{len(problems) - 10} more)"
                                        if len(problems) > 10 else ""))
           if problems else
           f"{len(manifest.get('files') or [])} mapped pairs corroborated "
           f"against {CORROBORATION_REL}")


# --- private-identity leakage ------------------------------------------------


def identity_strings(manifest: dict, corroboration) -> list[tuple[str, str]]:
    """(where, value) for every prose string in the publication artefacts.

    Every string is in scope, including values reached through a `source_path`
    key. An earlier revision exempted `source_path` on the theory that its
    historical phase tokens were approved provenance; MEASURED, the exemption
    was unnecessary and was removed: all 176 source_path values are plain
    relative paths, and scanning them changes the verdict on the known-good
    artefacts not at all (0 hits either way). The patterns match the private
    tree's own name and the LIVE phase family only, so a historical token such
    as `phase16o` is not a match and never was. Keeping the exemption would have
    meant a new mapping whose source_path named the live private phase would be
    published unquestioned.
    """
    out: list[tuple[str, str]] = []

    def walk(obj, where: str) -> None:
        if isinstance(obj, str):
            out.append((where, obj))
        elif isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, f"{where}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, f"{where}[{i}]")

    walk(manifest, "PUBLICATION_MANIFEST.json")
    if isinstance(corroboration, dict):
        walk(corroboration, "PUBLICATION_BYTE_CORROBORATION.json")
    return out


def publication_identity_problems(manifest: dict, corroboration) -> list[str]:
    """Private-identity leakage in strings an author writes by hand.

    Matched text is never echoed -- only the location, the pattern name, and a
    redacted fingerprint, matching this file's existing discipline.
    """
    problems: list[str] = []
    for where, value in identity_strings(manifest, corroboration):
        raw = value.encode("utf-8", "replace")
        for name, rx in IDENTITY_PATTERNS.items():
            m = rx.search(raw)
            if m:
                fp = hashlib.sha256(m.group(0)).hexdigest()[:12]
                problems.append(f"{where} [{name} redacted:{fp}]")
    return problems


def check_publication_identity(head: bool) -> None:
    data = blob_bytes(head, "audit/PUBLICATION_MANIFEST.json")
    corroboration, _err = load_corroboration(head)
    if not data:
        record(False, "private-identity leakage",
               "publication manifest missing, so nothing could be scanned")
        return
    try:
        manifest = json.loads(data.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        record(False, "private-identity leakage", f"manifest unparseable: {e}")
        return
    problems = publication_identity_problems(manifest, corroboration)
    record(not problems, "private-identity leakage",
           "; ".join(problems[:10]) if problems else
           f"{len(identity_strings(manifest, corroboration))} prose strings "
           f"clean of the private tree name and the live private phase")


def published_private_path_problems(manifest: dict, facts_of) -> list[str]:
    """Escape-aware private-path scan over the published bytes.

    Every mapped public file is scanned. A file absent from
    KNOWN_PRIVATE_PATH_REGISTER must have zero occurrences; a registered file
    must have exactly the recorded count, so the register cannot silently
    absorb a new occurrence or be quietly outgrown.
    """
    problems: list[str] = []
    counts: dict[str, int] = {}
    entries = manifest.get("files") or []
    for entry in entries:
        rel = entry.get("public_path")
        if not isinstance(rel, str):
            continue
        data = facts_of(rel)
        if data is None:
            continue  # unreadable files are reported by the corroboration check
        n = len(list(PRIVATE_PATH_ANY_ESCAPE.finditer(data)))
        if n:
            counts[rel] = n

    for rel, n in sorted(counts.items()):
        expected = KNOWN_PRIVATE_PATH_REGISTER.get(rel)
        if expected is None:
            problems.append(f"{rel}: {n} private absolute path(s) in the "
                            f"published bytes and the file is not on the "
                            f"known-leak register")
        elif n != expected:
            problems.append(f"{rel}: register records {expected} private "
                            f"absolute path(s), the published bytes carry {n}")

    for rel, expected in sorted(KNOWN_PRIVATE_PATH_REGISTER.items()):
        if rel not in counts:
            problems.append(f"{rel}: on the known-leak register with "
                            f"{expected} occurrence(s) but none was found; the "
                            f"register is stale and must be re-reviewed")
    return problems


def _published_bytes_reader(head: bool):
    cache: dict[str, bytes | None] = {}

    def read(rel: str):
        if rel not in cache:
            cache[rel] = blob_bytes(head, rel)
        return cache[rel]

    return read


def check_private_path_register(head: bool, files: list[str]) -> None:
    data = blob_bytes(head, "audit/PUBLICATION_MANIFEST.json")
    if not data:
        record(False, "known private-path register",
               "publication manifest missing, so nothing could be scanned")
        return
    try:
        manifest = json.loads(data.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        record(False, "known private-path register", f"manifest unparseable: {e}")
        return
    problems = published_private_path_problems(
        manifest, _published_bytes_reader(head))
    registered = ", ".join(f"{k} ({v})" for k, v in
                           sorted(KNOWN_PRIVATE_PATH_REGISTER.items()))
    record(not problems, "known private-path register",
           ("; ".join(problems[:10]) + "; " if problems else "")
           + f"on the register: {registered}")


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
    check_corroboration(args.git_head)
    check_publication_identity(args.git_head)
    check_private_path_register(args.git_head, files)
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
