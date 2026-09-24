#!/usr/bin/env python3
"""Three-gate merge identity audit (GitHub issue #42).

Phase 16BJ, directive section 62 / Issue #42.

WHY THREE GATES
---------------
A single identity check cannot cover a squash-merge contribution, because
each stage has a DIFFERENT subject and a different failure mode:

  Gate A -- contributor PR commits.
      Audits the actual contributor commits (author, committer, and
      Co-authored-by trailers) at the PR head -- NOT GitHub's synthetic
      `refs/pull/N/merge` checkout (the 16BG-measured defect: auditing the
      merge ref judges a commit the contributor did not author, producing
      both false rejections and false acceptances).

  Gate B -- the canonical integration commit BEFORE merge.
      The commit that would land must already carry a project-safe /
      noreply author and committer identity.  GitHub squash settings are not
      assumed to preserve safe contributor metadata.

  Gate C -- the ACTUAL resulting `main` commit AFTER merge.
      Audits the real tip of `main` (default ref `main`, overridable to
      `origin/main`).  It refuses to accept a PR head sha as its subject:
      the whole point of Gate C is that it looks at what actually landed.
      Fail/alert if an unexpected personal non-noreply identity appears.

IDENTITY POLICY
---------------
An email is ACCEPTED only when it is:

  * a verified GitHub noreply address: `<id>+<name>@users.noreply.github.com`
    or `<name>@users.noreply.github.com`; or
  * an explicit GitHub service address on the project-safe allowlist
    (`noreply@github.com` etc.); or
  * listed in a policy file as explicitly public/project-safe AND the policy
    allows it (`allowed_emails` / `allowed_domains` entries).

Everything else -- personal provider domains and any unlisted address -- is
REJECTED.  The policy file is the ONLY way a non-noreply address becomes
acceptable, so "explicitly public/project-safe and policy allows" is a real
gate, not a comment.

The audit never rewrites history, never pushes, never writes to any git
ref -- it only READS commits and prints a JSON verdict.  Personal addresses
are redacted in output (first letter + domain) so audit summaries do not
republish the very address they are guarding (directive section 62: "Do not
output the private address itself in normal audit summaries").

USAGE
-----
  # Gate A: contributor PR commits (head sha, or a range base..head)
  python tools/merge_identity_audit.py --gate a --repo <git-dir> --head <sha>
  python tools/merge_identity_audit.py --gate a --repo <git-dir> --base <sha> --head <sha>

  # Gate B: prospective canonical commit before merge
  python tools/merge_identity_audit.py --gate b --repo <git-dir> --commit <sha>

  # Gate C: the actual main commit after merge
  python tools/merge_identity_audit.py --gate c --repo <git-dir>
  python tools/merge_identity_audit.py --gate c --repo <git-dir> --ref origin/main

  # optional: scan release notes / generated provenance files for emails
  python tools/merge_identity_audit.py --gate b --repo <git-dir> \
      --commit <sha> --extra-text RELEASE_NOTES.md --extra-text provenance.json

Exit codes: 0 ACCEPTED, 2 REJECTED, 3 usage/subject error (Gate C refused a
non-main subject, missing sha, git failure).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict

sys.dont_write_bytecode = True

SCHEMA = "tools/merge_identity_audit/1"

GATE_A = "A_PR_HEAD_COMMITS"
GATE_B = "B_PROSPECTIVE_CANONICAL_COMMIT"
GATE_C = "C_ACTUAL_MAIN_COMMIT"

# --- email classification -----------------------------------------------------

GITHUB_NOREPLY_RX = re.compile(
    r"(?i)^[0-9]*\+?[A-Za-z0-9_.-]+@users\.noreply\.github\.com$"
)

# Explicit GitHub service addresses that are project-safe by policy.
GITHUB_SERVICE_ALLOWLIST = frozenset(
    {
        "noreply@github.com",
        "no-reply@github.com",
        "github-actions[bot]@users.noreply.github.com",
        "web-flow@users.noreply.github.com",
    }
)

PERSONAL_PROVIDER_RX = re.compile(
    r"(?i)^[A-Za-z0-9._%+-]+@(gmail|outlook|hotmail|yahoo|protonmail|proton"
    r"|icloud|aol|gmx|mail\.ru|yandex|qq|163|live|msn)\.(com|de|ru|cn|me)$"
)

EMAIL_RX = re.compile(
    r"(?i)\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
)

CO_AUTHORED_RX = re.compile(r"(?im)^Co-authored-by:\s*(.+?)\s*<([^>]+)>\s*$")


@dataclass
class Policy:
    """Explicit public/project-safe allowlist.  The ONLY escape hatch from
    the noreply rule.  Default: none beyond GitHub's own addresses."""

    allowed_emails: frozenset = frozenset()
    allowed_domains: frozenset = frozenset()
    allow_non_noreply: bool = False  # must be consciously set by a policy file

    @classmethod
    def load(cls, path: str | None) -> "Policy":
        if not path:
            return cls()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise SystemExit(f"policy file {path} must be a JSON object")
        if data.get("allow_non_noreply") is not True and not (
            data.get("allowed_emails") or data.get("allowed_domains")
        ):
            # a policy that lists nothing and flips nothing is fine (strict)
            pass
        return cls(
            allowed_emails=frozenset(
                e.lower() for e in data.get("allowed_emails", []) if isinstance(e, str)
            ),
            allowed_domains=frozenset(
                d.lower().lstrip("@") for d in data.get("allowed_domains", [])
                if isinstance(d, str)
            ),
            allow_non_noreply=bool(data.get("allow_non_noreply", False)),
        )


def classify_email(email: str, policy: Policy) -> tuple[str, bool, str]:
    """Return (classification, accepted, explanation)."""
    e = (email or "").strip().lower()
    if not e or "@" not in e:
        return "INVALID", False, "not an email address"
    if e in GITHUB_SERVICE_ALLOWLIST:
        return "GITHUB_SERVICE", True, "explicit GitHub service address (allowlisted)"
    if GITHUB_NOREPLY_RX.match(e):
        return "GITHUB_NOREPLY", True, "verified GitHub noreply identity"
    if e in policy.allowed_emails:
        return (
            "POLICY_ALLOWED_EMAIL",
            True,
            "listed in policy as explicitly public/project-safe",
        )
    domain = e.rsplit("@", 1)[1]
    if domain in policy.allowed_domains:
        return (
            "POLICY_ALLOWED_DOMAIN",
            True,
            "domain listed in policy as explicitly public/project-safe",
        )
    if PERSONAL_PROVIDER_RX.match(e):
        return (
            "PERSONAL_EMAIL",
            False,
            "personal provider domain -- rejected unless policy explicitly "
            "allows this exact address/domain",
        )
    if policy.allow_non_noreply:
        return (
            "POLICY_ALLOWED_NON_NOREPLY",
            True,
            "policy allow_non_noreply=true (explicitly enabled)",
        )
    return (
        "UNLISTED_NON_NOREPLY",
        False,
        "not a GitHub noreply/service address and not in the policy allowlist "
        "(fail closed)",
    )


def redact(email: str) -> str:
    """First letter + *** + domain.  The address itself never appears in
    normal audit summaries (directive section 62)."""
    e = (email or "").strip()
    if "@" not in e:
        return "<invalid>"
    local, domain = e.split("@", 1)
    head = local[:1] if local else ""
    return f"{head}***@{domain}"


# --- git reading (read-only) ---------------------------------------------------

def _git(repo: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", repo, *args],
        capture_output=True, text=True, timeout=60,
    )


def _git_ok(repo: str, *args: str) -> str:
    p = _git(repo, *args)
    if p.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed in {repo}: {p.stderr.strip()[:300]}"
        )
    return p.stdout


def resolve_commit(repo: str, spec: str) -> str:
    out = _git_ok(repo, "rev-parse", "--verify", f"{spec}^{{commit}}")
    return out.strip()


def read_commit(repo: str, sha: str) -> dict:
    """Read one commit's identity fields and full message.  Read-only."""
    fmt = "%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B"
    out = _git_ok(repo, "log", "-1", f"--format={fmt}", sha)
    parts = out.split("\x00")
    if len(parts) < 6:
        raise RuntimeError(f"unexpected git log output for {sha}")
    return {
        "sha": parts[0],
        "author_name": parts[1],
        "author_email": parts[2],
        "committer_name": parts[3],
        "committer_email": parts[4],
        "message": parts[5],
    }


def list_commits(repo: str, base: str | None, head: str) -> list[str]:
    """Commit shas for Gate A: base..head when base given, else the head
    commit and up to 100 ancestors reachable only from head... Keep it
    precise: without a base we audit exactly the head commit plus a
    --max-count 100 window, recorded in the verdict so scope is visible."""
    if base:
        out = _git_ok(repo, "rev-list", f"{base}..{head}")
        shas = [s for s in out.split() if s]
        if not shas:
            raise RuntimeError(f"empty range {base}..{head}")
        return shas
    out = _git_ok(repo, "rev-list", "--max-count", "100", head)
    return [s for s in out.split() if s]


def current_head(repo: str) -> str:
    return resolve_commit(repo, "HEAD")


def current_branch(repo: str) -> str | None:
    p = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    if p.returncode != 0:
        return None
    name = p.stdout.strip()
    return None if name == "HEAD" else name


# --- audit core -----------------------------------------------------------------

@dataclass
class Finding:
    where: str            # e.g. "commit <sha12> author" / "co-authored-by" / "file <name>"
    email_redacted: str
    classification: str
    accepted: bool
    explanation: str


@dataclass
class AuditResult:
    schema: str
    gate: str
    verdict: str          # ACCEPTED | REJECTED | REFUSED
    subject: dict
    findings: list[dict] = field(default_factory=list)
    refusals: list[str] = field(default_factory=list)
    policy: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _audit_email(where: str, email: str, policy: Policy) -> Finding:
    cls, ok, why = classify_email(email, policy)
    return Finding(
        where=where,
        email_redacted=redact(email),
        classification=cls,
        accepted=ok,
        explanation=why,
    )


def audit_commit_identity(commit: dict, policy: Policy, label: str) -> list[Finding]:
    findings: list[Finding] = []
    findings.append(
        _audit_email(f"{label} author", commit["author_email"], policy)
    )
    findings.append(
        _audit_email(f"{label} committer", commit["committer_email"], policy)
    )
    for m in CO_AUTHORED_RX.finditer(commit["message"]):
        findings.append(
            _audit_email(f"{label} co-authored-by", m.group(2), policy)
        )
    return findings


def scan_text_for_emails(text: str, policy: Policy, where: str) -> list[Finding]:
    """Release notes / generated provenance: every email-shaped token is
    classified; unlisted non-noreply REJECTS the whole gate."""
    out: list[Finding] = []
    seen: set[str] = set()
    for m in EMAIL_RX.finditer(text):
        e = m.group(1).lower()
        if e in seen:
            continue
        seen.add(e)
        out.append(_audit_email(where, m.group(1), policy))
    return out


# --- gates -----------------------------------------------------------------------

def gate_a(repo: str, head: str, base: str | None, policy: Policy) -> AuditResult:
    """Contributor PR commits: the actual commits, not the merge ref."""
    res = AuditResult(
        schema=SCHEMA, gate=GATE_A, verdict="ACCEPTED",
        subject={"repo": os.path.abspath(repo), "head": head, "base": base},
        policy=_policy_dict(policy),
    )
    try:
        head_sha = resolve_commit(repo, head)
        base_sha = resolve_commit(repo, base) if base else None
    except RuntimeError as exc:
        res.verdict = "REFUSED"
        res.refusals.append(str(exc))
        return res
    res.subject["head_sha"] = head_sha
    res.subject["base_sha"] = base_sha
    try:
        shas = list_commits(repo, base_sha, head_sha)
    except RuntimeError as exc:
        res.verdict = "REFUSED"
        res.refusals.append(str(exc))
        return res
    res.subject["commit_count"] = len(shas)
    res.subject["subject_kind"] = (
        "contributor range" if base_sha else "head commit + ancestry window"
    )
    if not base_sha:
        res.notes.append(
            "no --base given: audited the head commit plus its 100-ancestor "
            "window; pass --base for an exact PR range"
        )
    for sha in shas:
        try:
            c = read_commit(repo, sha)
        except RuntimeError as exc:
            res.verdict = "REFUSED"
            res.refusals.append(str(exc))
            return res
        res.findings.extend(
            asdict(f) for f in audit_commit_identity(c, policy, f"commit {sha[:12]}")
        )
    return _finish(res)


def gate_b(
    repo: str, commit: str, policy: Policy, extra_texts: list[tuple[str, str]]
) -> AuditResult:
    """Prospective canonical integration commit BEFORE merge."""
    res = AuditResult(
        schema=SCHEMA, gate=GATE_B, verdict="ACCEPTED",
        subject={"repo": os.path.abspath(repo)}, policy=_policy_dict(policy),
    )
    try:
        sha = resolve_commit(repo, commit)
    except RuntimeError as exc:
        res.verdict = "REFUSED"
        res.refusals.append(str(exc))
        return res
    res.subject["commit_sha"] = sha
    branch = current_branch(repo)
    if branch is not None:
        res.subject["branch"] = branch
    try:
        c = read_commit(repo, sha)
    except RuntimeError as exc:
        res.verdict = "REFUSED"
        res.refusals.append(str(exc))
        return res
    res.findings.extend(
        asdict(f) for f in audit_commit_identity(c, policy, f"prospective {sha[:12]}")
    )
    for name, text in extra_texts:
        res.findings.extend(
            asdict(f) for f in scan_text_for_emails(text, policy, f"extra-text {name}")
        )
    return _finish(res)


def gate_c(
    repo: str,
    ref: str,
    policy: Policy,
    extra_texts: list[tuple[str, str]],
    expected_main_ref: str = "main",
) -> AuditResult:
    """The ACTUAL resulting main commit AFTER merge.

    Subject-selection rule (the point of Gate C): the audited commit is
    resolved from `--ref` (default `main`).  A 40-hex sha passed as --ref is
    REFUSED unless it is currently reachable as the tip of the expected ref
    -- a PR head sha must never be silently accepted as "the merge result".
    """
    res = AuditResult(
        schema=SCHEMA, gate=GATE_C, verdict="ACCEPTED",
        subject={"repo": os.path.abspath(repo), "requested_ref": ref},
        policy=_policy_dict(policy),
    )
    subject_spec = ref
    if re.fullmatch(r"[0-9a-f]{40}", ref or ""):
        # refuse PR-head-style subjects: must be the tip of the main ref
        try:
            tip = resolve_commit(repo, expected_main_ref)
        except RuntimeError as exc:
            res.verdict = "REFUSED"
            res.refusals.append(
                f"--ref given as a bare sha but {expected_main_ref} cannot be "
                f"resolved: {exc}"
            )
            return res
        if tip.lower() != ref.lower():
            res.verdict = "REFUSED"
            res.refusals.append(
                f"Gate C examines the ACTUAL {expected_main_ref} commit, not an "
                f"arbitrary sha: {ref[:12]} is not the tip of {expected_main_ref} "
                f"({tip[:12]})"
            )
            return res
        subject_spec = expected_main_ref
    try:
        sha = resolve_commit(repo, subject_spec)
    except RuntimeError as exc:
        res.verdict = "REFUSED"
        res.refusals.append(str(exc))
        return res
    res.subject["ref_resolved"] = subject_spec
    res.subject["merge_commit_sha"] = sha
    branch = current_branch(repo)
    if branch is not None:
        res.subject["checked_out_branch"] = branch
    try:
        c = read_commit(repo, sha)
    except RuntimeError as exc:
        res.verdict = "REFUSED"
        res.refusals.append(str(exc))
        return res
    res.findings.extend(
        asdict(f) for f in audit_commit_identity(c, policy, f"main-tip {sha[:12]}")
    )
    for name, text in extra_texts:
        res.findings.extend(
            asdict(f) for f in scan_text_for_emails(text, policy, f"extra-text {name}")
        )
    res.notes.append(
        "this verdict is about the commit that ACTUALLY landed on "
        f"{subject_spec}; a passing Gate A/B does not transfer to it"
    )
    return _finish(res)


def _policy_dict(policy: Policy) -> dict:
    return {
        "allowed_emails": sorted(policy.allowed_emails),
        "allowed_domains": sorted(policy.allowed_domains),
        "allow_non_noreply": policy.allow_non_noreply,
        "rule": "GitHub noreply/service addresses + explicit policy entries only; "
                "everything else fail-closed REJECTED",
    }


def _finish(res: AuditResult) -> AuditResult:
    if res.verdict == "REFUSED":
        return res
    rejected = [f for f in res.findings if not f["accepted"]]
    if rejected:
        res.verdict = "REJECTED"
        res.notes.append(f"{len(rejected)} identity finding(s) rejected the gate")
    else:
        res.verdict = "ACCEPTED"
        if not res.findings:
            res.notes.append("no identity fields found to audit (empty?)")
    return res


# --- CLI --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--gate", required=True, choices=["a", "b", "c"])
    ap.add_argument("--repo", required=True, help="path to a git working tree")
    ap.add_argument("--head", help="Gate A: PR head sha/ref")
    ap.add_argument("--base", help="Gate A: PR base sha/ref (exact range)")
    ap.add_argument("--commit", help="Gate B: prospective canonical commit")
    ap.add_argument(
        "--ref", default="main",
        help="Gate C: ref whose ACTUAL tip is audited (default: main)",
    )
    ap.add_argument(
        "--expected-main-ref", default="main",
        help="Gate C: the ref that defines 'actual main' when --ref is a sha",
    )
    ap.add_argument(
        "--policy", default=None,
        help="JSON policy file with allowed_emails/allowed_domains/"
             "allow_non_noreply (the only escape hatch from the noreply rule)",
    )
    ap.add_argument(
        "--extra-text", action="append", default=[], metavar="FILE",
        help="release-notes / generated-provenance file to scan for emails "
             "(repeatable)",
    )
    ns = ap.parse_args()

    if not os.path.isdir(ns.repo) or not os.path.isdir(os.path.join(ns.repo, ".git")) \
            and not os.path.isfile(os.path.join(ns.repo, ".git")):
        # allow running against a bare repo (no .git dir) too
        p = _git(ns.repo, "rev-parse", "--git-dir")
        if p.returncode != 0:
            print(
                json.dumps(
                    {"verdict": "REFUSED", "error": f"not a git repo: {ns.repo}"},
                    indent=1,
                )
            )
            return 3

    try:
        policy = Policy.load(ns.policy)
    except Exception as exc:
        print(json.dumps({"verdict": "REFUSED", "error": f"policy load: {exc}"}, indent=1))
        return 3

    extra: list[tuple[str, str]] = []
    for path in ns.extra_text:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                extra.append((os.path.basename(path), f.read()))
        except OSError as exc:
            print(json.dumps({"verdict": "REFUSED", "error": f"extra-text: {exc}"}, indent=1))
            return 3

    if ns.gate == "a":
        if not ns.head:
            print(json.dumps({"verdict": "REFUSED", "error": "Gate A requires --head"}), end="")
            print()
            return 3
        res = gate_a(ns.repo, ns.head, ns.base, policy)
    elif ns.gate == "b":
        if not ns.commit:
            print(json.dumps({"verdict": "REFUSED", "error": "Gate B requires --commit"}), end="")
            print()
            return 3
        res = gate_b(ns.repo, ns.commit, policy, extra)
    else:
        res = gate_c(ns.repo, ns.ref, policy, extra, ns.expected_main_ref)

    print(json.dumps(asdict(res), indent=1))
    if res.verdict == "ACCEPTED":
        return 0
    if res.verdict == "REJECTED":
        return 2
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
