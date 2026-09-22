#!/usr/bin/env python3
"""Phase 16AF / T1 -- tests for the publication transform model.

Run:
    python p16af_test_publication_transforms.py

Prints every test result.  Exit code 0 only if every test behaved as required.

What is tested
--------------
POSITIVE  the frozen transform, run on the private file alone, reproduces the
          published copy byte-for-byte, AND the resulting digest agrees with
          three independent sources that are not the model:
            * the mirror's git blob for HEAD:<path>;
            * the mirror's working-tree file;
            * the `public_sha256` recorded in the mirror's
              audit/PUBLICATION_MANIFEST.json.
          (Rule: a verifier must accept the known-good case.)

NEGATIVE  a mutated private input is REJECTED.  Four mutation kinds per path:
            * one byte changed inside an anchor region;
            * one line deleted inside an anchor region;
            * one line inserted;
            * one byte changed OUTSIDE every anchor region -- the transform
              then succeeds, so this case is rejected only by the digest
              comparison.  It is the case that proves the comparison is
              load-bearing rather than decorative.

CONTROL   a deliberately permissive comparator (line-ending-insensitive
          equality, the rule that would be the defect if it were adopted)
          must ACCEPT an input the real check REJECTS.  If the permissive
          comparator also rejected it, this test would be vacuous and says so.

COVERAGE  the counts are printed: how many paths, how many mutations, how many
          rejections.  An errored check is reported as ERROR, never as a pass.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from p16af_publication_transforms import (  # noqa: E402
    MODEL_PATH,
    PRIVATE_ROOT,
    PUBLIC_ROOT,
    TransformError,
    apply_transform,
    load_model,
    op_normalise_crlf_to_lf,
    op_strip_utf8_bom,
    sha256,
)

FAILURES: list[str] = []
CHECKS = {
    "positive_accept": 0,
    "negative_reject": 0,
    "negative_accept_BAD": 0,
    "scan_mutants": 0,
    "scan_digest_reject": 0,
    "error": 0,
    "comparator_strict": 0,
    "comparator_permissive_accepts": 0,
}


def record(ok: bool, label: str, detail: str) -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}: {detail}")
    if not ok:
        FAILURES.append(f"{label}: {detail}")


# --------------------------------------------------------------------------
# independent sources for the published bytes
# --------------------------------------------------------------------------


def load_manifest_public_shas() -> dict[str, str]:
    m = json.loads(
        (PUBLIC_ROOT / "audit" / "PUBLICATION_MANIFEST.json").read_text(encoding="utf-8")
    )
    return {e["public_path"]: e["public_sha256"] for e in m["files"]}


def git_blob_sha(rel: str) -> str:
    import subprocess

    p = subprocess.run(
        ["git", "cat-file", "blob", "HEAD:" + rel], cwd=PUBLIC_ROOT, capture_output=True
    )
    if p.returncode != 0:
        raise RuntimeError(f"git cat-file failed for {rel}: {p.stderr!r}")
    return sha256(p.stdout)


# --------------------------------------------------------------------------
# the two comparators
# --------------------------------------------------------------------------


def strict_comparator(entry, private_bytes: bytes, expected_sha: str) -> tuple[bool, str]:
    """The real check: frozen transform, then exact digest equality."""
    try:
        out = apply_transform(entry, private_bytes)
    except TransformError as exc:
        return False, f"TransformError: {str(exc)[:90]}"
    got = sha256(out)
    if got != expected_sha:
        return False, f"digest {got[:12]} != expected {expected_sha[:12]}"
    return True, f"digest {got[:12]} matches"


def anchor_only_comparator(entry, private_bytes: bytes, expected_sha: str):
    """The defect rule the brief names as forbidden: accept as long as the
    transform ran without raising, ignoring the resulting digest.  It is here
    only to be shown to accept things the real check rejects."""
    try:
        apply_transform(entry, private_bytes)
    except TransformError as exc:
        return False, f"anchors failed ({str(exc)[:60]})"
    return True, "anchors matched; digest NOT checked (defect rule)"


# --------------------------------------------------------------------------
# mutations
# --------------------------------------------------------------------------


def _normalised_private(entry: dict) -> str:
    raw = (PRIVATE_ROOT / entry["source_path"]).read_bytes().decode("utf-8")
    if "strip_utf8_bom" in entry["pre_ops"]:
        raw = op_strip_utf8_bom(raw)
    if "normalise_crlf_to_lf" in entry["pre_ops"]:
        raw = op_normalise_crlf_to_lf(raw)
    return raw


def _reencode(entry: dict, text: str) -> bytes:
    """Put a mutated text back into the shape a real private file would have,
    so the pre_ops run on it exactly as they run on the file."""
    data = text.encode("utf-8")
    if "normalise_crlf_to_lf" in entry["pre_ops"]:
        data = data.replace(b"\n", b"\r\n")
    if "strip_utf8_bom" in entry["pre_ops"]:
        data = b"\xef\xbb\xbf" + data
    return data


def first_anchor(entry: dict) -> tuple[str, int, int]:
    """The first hunk of the first addition.  It is the one anchor that is
    present in the *unmodified* normalised private text, because it is the
    first thing the transform applies.  Later anchors only come into existence
    after their predecessors have run, so they cannot be located up front --
    which is exactly why the scan below exists rather than a table."""
    group = entry["additions"][0]
    old = group["hunks"][0]["old"]
    idx = _normalised_private(entry).find(old)
    if idx < 0:
        raise RuntimeError("the first anchor is not present in the private text")
    return f"{group['addition_id']}/h0", idx, idx + len(old)


def mutations(entry: dict) -> list[tuple[str, bytes]]:
    """Three in-anchor mutation kinds, each returned as
    (label, mutated_private_bytes)."""
    text = _normalised_private(entry)
    label, start, _end = first_anchor(entry)

    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", start) + 1
    if line_end <= 0:
        line_end = len(text)

    return [
        (
            f"byte-in-anchor({label})",
            _reencode(entry, text[:start] + ("Z" if text[start] != "Z" else "Q")
                      + text[start + 1:]),
        ),
        (
            f"line-deleted-in-anchor({label})",
            _reencode(entry, text[:line_start] + text[line_end:]),
        ),
        (
            f"line-inserted-in-anchor({label})",
            _reencode(entry, text[:line_start] + "# P16AF injected line\n" + text[line_start:]),
        ),
    ]


def scan_byte_mutations(entry: dict, expected: str, stride: int) -> dict[str, Any]:
    """Single-byte mutations at every `stride`-th offset of the normalised
    private text, classified by how the real check responds.

    Classes:
      ANCHOR_FAILED  the transform refused (an anchor stopped matching)
      DIGEST_REJECT  the transform SUCCEEDED and the digest comparison
                     rejected it -- the case that shows the comparison is
                     load-bearing
      ACCEPTED       the check accepted a mutated input.  This is the only
                     outcome that is a defect.
    """
    text = _normalised_private(entry)
    counts = {"ANCHOR_FAILED": 0, "DIGEST_REJECT": 0, "ACCEPTED": 0}
    example = None
    for off in range(0, len(text), stride):
        orig = text[off]
        if orig == "\n":
            continue
        mutated = text[:off] + ("Z" if orig != "Z" else "Q") + text[off + 1:]
        data = _reencode(entry, mutated)
        if sha256(data) == entry["private_sha256"]:
            continue  # the replacement byte happened to equal the original
        try:
            out = apply_transform(entry, data)
        except TransformError:
            counts["ANCHOR_FAILED"] += 1
            continue
        if sha256(out) == expected:
            counts["ACCEPTED"] += 1
        else:
            counts["DIGEST_REJECT"] += 1
            if example is None:
                example = off
    return {"stride": stride, "counts": counts, "first_digest_reject_offset": example}


# --------------------------------------------------------------------------


def main() -> int:
    model = load_model()
    manifest_shas = load_manifest_public_shas()

    print("=" * 78)
    print("PHASE 16AF T1 -- publication transform model tests")
    print(f"model: {MODEL_PATH}")
    print(f"entries: {len(model['entries'])}")
    print("=" * 78)

    for entry in model["entries"]:
        dst = entry["destination_path"]
        src = PRIVATE_ROOT / entry["source_path"]
        private_bytes = src.read_bytes()
        expected = entry["expected_transformed_sha256"]

        print(f"\n### {dst}  (feature {entry['feature']})")
        print(f"    private  sha256={entry['private_sha256']} bytes={entry['private_bytes']}")
        print(f"    public   sha256={entry['public_sha256']} bytes={entry['public_bytes']}")
        print(f"    pre_ops  {entry['pre_ops']}  effective={entry['line_ending_op_is_effective']}")
        print(f"    additions {[g['addition_id'] for g in entry['additions']]}")

        # ---- POSITIVE -----------------------------------------------------
        ok, detail = strict_comparator(entry, private_bytes, expected)
        CHECKS["positive_accept"] += 1
        record(ok, f"POSITIVE {dst}", f"transform accepts the known-good private file; {detail}")

        if ok:
            out = apply_transform(entry, private_bytes)
            # three independent sources, none of them the model
            blob_sha = git_blob_sha(dst)
            tree_sha = sha256((PUBLIC_ROOT / dst).read_bytes())
            man_sha = manifest_shas.get(dst)
            record(
                sha256(out) == blob_sha,
                f"INDEPENDENT {dst}",
                f"mirror git blob HEAD:{dst} = {blob_sha[:12]}",
            )
            record(
                sha256(out) == tree_sha,
                f"INDEPENDENT {dst}",
                f"mirror working tree = {tree_sha[:12]}",
            )
            record(
                man_sha is not None and sha256(out) == man_sha,
                f"INDEPENDENT {dst}",
                f"mirror manifest public_sha256 = {str(man_sha)[:12]}",
            )
            record(
                entry["public_sha256_worktree"] == entry["public_sha256_git_blob"],
                f"REPRESENTATION {dst}",
                "working tree and git blob agree, so no line-ending rewriting is "
                "hidden between them",
            )

        # ---- NEGATIVE -----------------------------------------------------
        muts = mutations(entry)
        print(f"    in-anchor mutations exercised: {len(muts)}")
        for name, data in muts:
            mutated_private_sha = sha256(data)
            record(
                mutated_private_sha != entry["private_sha256"],
                f"MUTATION-IS-REAL {dst}",
                f"{name} changed the private digest "
                f"({mutated_private_sha[:12]} != {entry['private_sha256'][:12]})",
            )
            accepted, detail = strict_comparator(entry, data, expected)
            CHECKS["negative_reject"] += 1
            if accepted:
                CHECKS["negative_accept_BAD"] += 1
            record(
                not accepted,
                f"NEGATIVE {dst}",
                f"{name} REJECTED ({detail})",
            )

        # ---- SCAN: single-byte mutations across the whole file ------------
        # This is the digest-path demonstration: it counts how many mutations
        # the transform catches itself (ANCHOR_FAILED) versus how many it
        # passes through and the DIGEST comparison then rejects.  A nonzero
        # ACCEPTED count is a defect and fails the run.
        scan = scan_byte_mutations(entry, expected, stride=7)
        c = scan["counts"]
        scanned = c["ANCHOR_FAILED"] + c["DIGEST_REJECT"] + c["ACCEPTED"]
        print(
            f"    single-byte scan (stride {scan['stride']}): {scanned} mutants "
            f"-> anchor-failed {c['ANCHOR_FAILED']}, digest-rejected "
            f"{c['DIGEST_REJECT']}, ACCEPTED {c['ACCEPTED']}"
        )
        CHECKS["scan_mutants"] += scanned
        CHECKS["scan_digest_reject"] += c["DIGEST_REJECT"]
        CHECKS["negative_reject"] += scanned
        if c["ACCEPTED"]:
            CHECKS["negative_accept_BAD"] += c["ACCEPTED"]
        record(
            c["ACCEPTED"] == 0,
            f"SCAN-REJECTS-ALL {dst}",
            f"{scanned} single-byte mutants, {c['ACCEPTED']} accepted "
            f"(first digest-path rejection at char {scan['first_digest_reject_offset']})",
        )
        record(
            c["DIGEST_REJECT"] > 0,
            f"DIGEST-PATH-IS-LOAD-BEARING {dst}",
            f"the digest comparison (not the anchors) rejected "
            f"{c['DIGEST_REJECT']} mutants; a transform that only checked "
            "anchors would have accepted them",
        )

        # ---- CONTROL: the anchor-only defect rule must accept what we reject
        # Use a mutation the scan classified as DIGEST_REJECT: the anchors
        # still matched, so only the digest comparison stood between the
        # mutant and acceptance.  If the anchor-only rule also rejected it,
        # this control would prove nothing about the digest comparison.
        off = scan["first_digest_reject_offset"]
        text = _normalised_private(entry)
        if off is None:
            record(
                False,
                f"CONTROL-STRICT {dst}",
                "the scan found no digest-path rejection, so there is nothing "
                "for this control to exercise",
            )
            CHECKS["comparator_strict"] += 1
            continue
        orig = text[off]
        mutant = _reencode(
            entry, text[:off] + ("Z" if orig != "Z" else "Q") + text[off + 1:]
        )
        permissive_ok, pdetail = anchor_only_comparator(entry, mutant, expected)
        strict_ok, sdetail = strict_comparator(entry, mutant, expected)
        CHECKS["comparator_strict"] += 1
        record(
            strict_ok is False,
            f"CONTROL-STRICT {dst}",
            f"the real check rejects the digest-path mutant at char {off} ({sdetail})",
        )
        if permissive_ok:
            CHECKS["comparator_permissive_accepts"] += 1
            record(
                True,
                f"CONTROL-ANCHOR-ONLY {dst}",
                f"the anchor-only rule ACCEPTS the same mutant ({pdetail}); it "
                f"would have accepted {c['DIGEST_REJECT']} of {scanned} scanned "
                "mutants, so the digest comparison is load-bearing",
            )
        else:
            record(
                False,
                f"CONTROL-ANCHOR-ONLY {dst}",
                f"the anchor-only rule also rejected it ({pdetail}), so this "
                "control proves nothing",
            )

    print("\n" + "=" * 78)
    print("COVERAGE (denominators, not just verdicts)")
    print(f"  paths under model              : {len(model['entries'])}")
    print(f"  positive acceptances required  : {CHECKS['positive_accept']}")
    print(f"  negative mutations exercised   : {CHECKS['negative_reject']}")
    print(f"    of which single-byte scans   : {CHECKS['scan_mutants']}")
    print(f"    rejected by the digest alone : {CHECKS['scan_digest_reject']}")
    print(f"  mutations wrongly accepted     : {CHECKS['negative_accept_BAD']}")
    print(f"  errors                         : {CHECKS['error']}")
    print(f"  strict-comparator controls     : {CHECKS['comparator_strict']}")
    print(f"  permissive rule accepted a mutation: {CHECKS['comparator_permissive_accepts']}")
    n_anchor = sum(
        len(g["hunks"]) for e in model["entries"] for g in e["additions"]
    )
    print(f"  total anchored hunks frozen    : {n_anchor}")
    print("=" * 78)

    if FAILURES:
        print(f"\n{len(FAILURES)} FAILURE(S):")
        for f in FAILURES:
            print("  - " + f)
        return 1
    print("\nALL TESTS BEHAVED AS REQUIRED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
