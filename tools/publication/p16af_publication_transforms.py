#!/usr/bin/env python3
"""Phase 16AF / T1 -- path-scoped publication transform model.

Why this file exists
--------------------
The public mirror's `scripts/prepare_publication_sync.py` maps 88 private
files to public ones.  Five of those mappings are BLOCKED because the
published copy is not a byte-for-byte transform of the private original: on
top of the declared normalisation it carries public-only additions.

The helper refuses those five with `unrecognized transform`, which is the
correct conservative behaviour -- but "unrecognized" is not an explanation.
This module replaces the parenthetical with a *measured* transform per path:
an ordered, anchored, byte-exact recipe that, run on the private file alone,
reproduces the published copy exactly; and that fails closed (hard error,
never a silent accept) if the private input no longer matches the anchors.

Design rules
------------
1. The transform reads the PRIVATE file only.  The published copy is not read
   at transform time; it is read (once) when the model is derived, and the
   resulting literal blocks are frozen into the model JSON.  A transform that
   consulted the published file at run time would be vacuous.
2. Every edit is an exact literal `old` -> `new` replacement that must occur
   EXACTLY ONCE in the text as it stands at that point.  Zero occurrences or
   two occurrences is an error, not a skip.
3. Edits are ordered and applied sequentially.
4. After all ops the result is hashed.  The caller compares that hash to the
   recorded `expected_transformed_sha256`.  Hash mismatch is a rejection.
5. There is no wildcard, no fuzzy match, no line-ending-insensitive compare,
   and no "accept if the diff is small" rule anywhere in this file.

Usage
-----
    # regenerate PUBLICATION_TRANSFORM_MODEL.json from both trees
    python p16af_publication_transforms.py --emit-model

    # verify the frozen model against the private tree (read-only)
    python p16af_publication_transforms.py --verify

    # apply one path's transform and print the result hash
    python p16af_publication_transforms.py --apply src/emulator/emu.py
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
MODEL_PATH = HERE / "PUBLICATION_TRANSFORM_MODEL.json"

PRIVATE_ROOT = Path(r"<PROJECT_ROOT>")
PUBLIC_ROOT = Path(r"<USER_HOME>\Desktop\gfx1030-dlss-nr-research")

# The five blocked mappings, exactly as the helper's manifest names them.
BLOCKED_MAPPINGS: list[dict[str, str]] = [
    {
        "transform_id": "P16AF_T1_EMU_PY_F6",
        "source_path": "phase16o_final/a_regression/rev_harness_fixed/emu.py",
        "destination_path": "src/emulator/emu.py",
        "feature": "F6",
        "feature_summary": (
            "explicit CONTROL_ONLY/NUMERICAL emulation modes, a declared-stub "
            "registry, and an UNSUPPORTED_NUMERIC refusal"
        ),
    },
    {
        "transform_id": "P16AF_T1_K_READINESS_PY_F7",
        "source_path": "phase16o_final/k_readiness.py",
        "destination_path": "tools/k_readiness.py",
        "feature": "F7",
        "feature_summary": (
            "the four literal track flags are read from "
            "audit/QUALIFICATION_LEDGER.json via tools/qualification_ledger.py "
            "instead of being typed in"
        ),
    },
    {
        "transform_id": "P16AF_T1_SOFT_WMMA_TEST_CPP_F2F3",
        "source_path": "soft_wmma_test.cpp",
        "destination_path": "tests/soft_wmma_test.cpp",
        "feature": "F2+F3",
        "feature_summary": (
            "includes tests/wmma_numeric_compare.h and carries the "
            "dense-fixture disclaimer required by F3"
        ),
    },
    {
        "transform_id": "P16AF_T1_SOFT_WMMA_BENCH_CPP_F2",
        "source_path": "soft_wmma_bench.cpp",
        "destination_path": "tests/soft_wmma_bench.cpp",
        "feature": "F2",
        "feature_summary": "includes tests/wmma_numeric_compare.h",
    },
    {
        "transform_id": "P16AF_T1_RUN_TEST_PS1_F1",
        "source_path": "run_test.ps1",
        "destination_path": "scripts/run_test.ps1",
        "feature": "F1",
        "feature_summary": (
            "source resolved under tests/, a -BuildOnly switch, an explicit "
            "-HipRoot, and layered Visual Studio discovery"
        ),
    },
]

CONTEXT_LINES = 3


class TransformError(RuntimeError):
    """The private input no longer matches the anchors, or the model is unusable."""


# --------------------------------------------------------------------------
# ops
# --------------------------------------------------------------------------


def op_strip_utf8_bom(text: str) -> str:
    if text.startswith("\ufeff"):
        return text[1:]
    return text


def op_normalise_crlf_to_lf(text: str) -> str:
    return text.replace("\r\n", "\n")


OPS = {
    "strip_utf8_bom": op_strip_utf8_bom,
    "normalise_crlf_to_lf": op_normalise_crlf_to_lf,
}


def apply_edit(text: str, edit: dict[str, str], where: str) -> str:
    old = edit["old"]
    new = edit["new"]
    n = text.count(old)
    if n != 1:
        raise TransformError(
            f"{where}: anchored edit occurs {n} time(s), expected exactly 1; "
            f"first line of anchor was {old.splitlines()[0]!r}"
        )
    return text.replace(old, new, 1)


def apply_transform(entry: dict[str, Any], private_bytes: bytes) -> bytes:
    """Run one model entry's ordered ops on the private bytes. Fail closed."""
    try:
        text = private_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TransformError(f"{entry['transform_id']}: private file is not UTF-8: {exc}")
    for i, op in enumerate(entry["pre_ops"]):
        fn = OPS.get(op)
        if fn is None:
            raise TransformError(f"{entry['transform_id']}: unknown pre_op {op!r}")
        text = fn(text)
    for group in entry["additions"]:
        for j, edit in enumerate(group["hunks"]):
            where = f"{entry['transform_id']} :: {group['addition_id']} :: hunk {j}"
            text = apply_edit(text, edit, where)
    return text.encode("utf-8")


# --------------------------------------------------------------------------
# derivation (reads BOTH trees; run once, then frozen)
# --------------------------------------------------------------------------


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob(repo: Path, rel: str) -> bytes:
    p = subprocess.run(
        ["git", "cat-file", "blob", "HEAD:" + rel], cwd=repo, capture_output=True
    )
    if p.returncode != 0:
        raise TransformError(f"git cat-file failed for {rel}: {p.stderr!r}")
    return p.stdout


def derive_edits(private_text: str, public_text: str) -> list[dict[str, Any]]:
    """Greedy anchored decomposition of public_text against private_text.

    Each step takes the first non-equal opcode, expands it with up to
    CONTEXT_LINES of surrounding context on both sides until the block is
    unique in the current text, applies it, and repeats.  Converges on
    public_text; a non-convergent or non-unique step raises.
    """
    edits: list[dict[str, Any]] = []
    cur = private_text
    for _ in range(500):
        a = cur.splitlines(keepends=True)
        b = public_text.splitlines(keepends=True)
        sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
        op = next((o for o in sm.get_opcodes() if o[0] != "equal"), None)
        if op is None:
            break
        tag, i1, i2, j1, j2 = op
        pre = min(CONTEXT_LINES, i1)
        post = min(CONTEXT_LINES, len(a) - i2)
        lead = "".join(a[i1 - pre:i1])
        tail = "".join(a[i2:i2 + post])

        def block(pre: int, post: int) -> tuple[str, str]:
            before = "".join(a[i1 - pre:i1])
            after = "".join(a[i2:i2 + post])
            return before + "".join(a[i1:i2]) + after, before + "".join(b[j1:j2]) + after

        old, new = block(pre, post)
        while cur.count(old) != 1 and pre < i1:
            pre += 1
            old, new = block(pre, post)
        while cur.count(old) != 1 and post < len(a) - i2:
            post += 1
            old, new = block(pre, post)
        if cur.count(old) != 1:
            raise TransformError(
                f"cannot anchor an edit at private lines [{i1}:{i2}] "
                f"(occurrences={cur.count(old)})"
            )
        cur = cur.replace(old, new, 1)
        edits.append(
            {
                "opcode": tag,
                "private_lines": [i1, i2],
                "lines_removed": i2 - i1,
                "lines_added": j2 - j1,
                "old": old,
                "new": new,
            }
        )
    if cur != public_text:
        raise TransformError("anchored decomposition did not converge on the public copy")
    return edits


# Named additions per path.  Each entry lists the indices of the derived edits
# that belong to it; the classification was made by reading every edit's body,
# and any edit whose body straddles two additions is recorded in
# `straddles` rather than being silently assigned.
ADDITION_MAP: dict[str, list[dict[str, Any]]] = {
    "src/emulator/emu.py": [
        {
            "addition_id": "A1",
            "name": "F6: EmuMode / declared stubs / UnsupportedNumeric refusal",
            "edits": list(range(0, 9)),
        }
    ],
    "tools/k_readiness.py": [
        {
            "addition_id": "A1",
            "name": "F7: four track flags read from the qualification ledger",
            "edits": list(range(0, 5)),
        }
    ],
    "tests/soft_wmma_test.cpp": [
        {
            "addition_id": "A1",
            "name": "F2: include wmma_numeric_compare.h + shared comparator, guards, sentinel",
            "edits": [1, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            "straddles": (
                "edit 4 also rewrites the run banner ('phase-1 smoke test' -> "
                "'dense software-matrix arithmetic fixture'), which is F3 wording"
            ),
        },
        {
            "addition_id": "A2",
            "name": "F3: dense-fixture disclaimer and fragment-ownership caveat",
            "edits": [0, 2, 3],
        },
    ],
    "tests/soft_wmma_bench.cpp": [
        {
            "addition_id": "A1",
            "name": "F2: include wmma_numeric_compare.h + shared comparator, guards, sentinel",
            "edits": list(range(0, 15)),
            "straddles": (
                "edit 0 is the benchmark's header comment, which carries the "
                "same fragment-ownership disclaimer wording as F3"
            ),
        }
    ],
    "scripts/run_test.ps1": [
        {
            "addition_id": "A1",
            "name": "F1: comment-based help + [CmdletBinding()] parameter block",
            "edits": [0],
        },
        {
            "addition_id": "A2",
            "name": "F1: HIP root resolution (-HipRoot / $env:GFX1030_HIP_ROOT / default)",
            "edits": [1, 3, 4],
        },
        {
            "addition_id": "A3",
            "name": "F1: Source/Exe resolved under tests/ from the repository root",
            "edits": [2, 5],
            "straddles": (
                "edit 2 introduces $Repo, which A2 also uses; the split is by "
                "which parameter each block resolves"
            ),
        },
        {
            "addition_id": "A4",
            "name": "F1: hipInfo.exe demoted to a RUN-phase-only dependency",
            "edits": [6, 7, 8, 16],
        },
        {
            "addition_id": "A5",
            "name": "F1: layered Visual Studio discovery (vswhere -> well-known roots -> MSFT_VSInstance)",
            "edits": [9, 10, 11, 12],
        },
        {
            "addition_id": "A6",
            "name": "F1: -BuildOnly compile-only gate, include path, early exit",
            "edits": [13, 14, 15],
        },
    ],
}

INTENTIONAL: dict[str, dict[str, Any]] = {
    "src/emulator/emu.py": {
        "intentional": True,
        "evidence": (
            "Every added block is a self-describing capability (EmuMode, "
            "UnsupportedNumeric, value_stub, control_only_vacuous) that only "
            "ever tightens behaviour: the NUMERICAL gate raises where the "
            "private file silently returned, and CONTROL_ONLY stays the "
            "default so existing callers are unchanged. The published copy "
            "imports nothing private, names no private path, and references "
            "published files only (tests/host/test_emu_modes.py is itself a "
            "new public file). The one removal is the stale private comment "
            "'accumulate conservative junk', deleted by F6 because it "
            "described a body that accumulated nothing."
        ),
    },
    "tools/k_readiness.py": {
        "intentional": True,
        "evidence": (
            "The change replaces four hardcoded literals with reads from a "
            "published ledger module; it strictly reduces unbacked claims. "
            "The import is `from qualification_ledger import ...`, a "
            "published sibling (tools/qualification_ledger.py is a new public "
            "file), and the ledger path is relative to the script root."
        ),
    },
    "tests/soft_wmma_test.cpp": {
        "intentional": True,
        "evidence": (
            "The additions pull grading into one shared comparator "
            "(tests/wmma_numeric_compare.h, itself a new public file), add "
            "out-of-range guards and a sentinel fill, and add a disclaimer "
            "that narrows what the fixture claims. The narrowing is in the "
            "public direction: the private banner said 'smoke test' and the "
            "public one says exactly which arithmetic is graded and which "
            "ownership contract is not."
        ),
    },
    "tests/soft_wmma_bench.cpp": {
        "intentional": True,
        "evidence": (
            "Same shape as the test fixture: the private max_abs_error helper "
            "is replaced by the shared comparator so the benchmark cannot "
            "report throughput for a run the comparator would reject. The "
            "deleted helper was private-only code with no public consumer."
        ),
    },
    "scripts/run_test.ps1": {
        "intentional": True,
        "evidence": (
            "The additions make the launcher safe on a machine with no GPU "
            "(-BuildOnly gates every device-touching step behind an early "
            "exit) and portable (HIP root is a parameter, not a literal). "
            "The two removals are relocations, not deletions of capability: "
            "the hipInfo.exe existence check and the device check move to "
            "below the -BuildOnly gate, which is what makes -BuildOnly unable "
            "to enumerate a device. The private copy hardcoded "
            "<ROCM_ROOT>\\6.4 and a BOM; both are gone."
        ),
    },
}


def derive_model() -> dict[str, Any]:
    entries = []
    for mapping in BLOCKED_MAPPINGS:
        src = PRIVATE_ROOT / mapping["source_path"]
        dst = PUBLIC_ROOT / mapping["destination_path"]
        private_bytes = src.read_bytes()
        public_bytes = dst.read_bytes()
        blob = git_blob(PUBLIC_ROOT, mapping["destination_path"])

        text = private_bytes.decode("utf-8")
        pre_ops: list[str] = []
        if text.startswith("\ufeff"):
            pre_ops.append("strip_utf8_bom")
            text = op_strip_utf8_bom(text)
        if "\r\n" in text:
            pre_ops.append("normalise_crlf_to_lf")
            text = op_normalise_crlf_to_lf(text)
        normalised = text.encode("utf-8")

        edits = derive_edits(text, public_bytes.decode("utf-8"))

        groups = []
        used: set[int] = set()
        for spec in ADDITION_MAP[mapping["destination_path"]]:
            hunks = [edits[i] for i in spec["edits"]]
            used.update(spec["edits"])
            g: dict[str, Any] = {
                "addition_id": spec["addition_id"],
                "name": spec["name"],
                "hunk_count": len(hunks),
                "lines_added": sum(h["lines_added"] for h in hunks),
                "lines_removed": sum(h["lines_removed"] for h in hunks),
                "hunks": [{"old": h["old"], "new": h["new"]} for h in hunks],
            }
            if "straddles" in spec:
                g["straddles"] = spec["straddles"]
            groups.append(g)
        if used != set(range(len(edits))):
            raise TransformError(
                f"{mapping['destination_path']}: addition map covers "
                f"{sorted(used)} but the derivation produced "
                f"{sorted(range(len(edits)))}"
            )

        entry: dict[str, Any] = {
            "transform_id": mapping["transform_id"],
            "source_path": mapping["source_path"],
            "destination_path": mapping["destination_path"],
            "feature": mapping["feature"],
            "feature_summary": mapping["feature_summary"],
            "private_representation": "working-tree bytes as the private file is on disk",
            "private_sha256": sha256(private_bytes),
            "private_bytes": len(private_bytes),
            "private_line_endings": {
                "crlf_pairs": private_bytes.count(b"\r\n"),
                "bare_lf": private_bytes.count(b"\n") - private_bytes.count(b"\r\n"),
                "bare_cr": len(private_bytes) - len(private_bytes.replace(b"\r", b""))
                - private_bytes.count(b"\r\n"),
                "utf8_bom": private_bytes[:3] == b"\xef\xbb\xbf",
            },
            "public_representation": "mirror working-tree bytes",
            "public_sha256": sha256(public_bytes),
            "public_bytes": len(public_bytes),
            "public_sha256_worktree": sha256(public_bytes),
            "public_sha256_git_blob": sha256(blob),
            "public_worktree_equals_git_blob": public_bytes == blob,
            "public_line_endings": {
                "crlf_pairs": public_bytes.count(b"\r\n"),
                "bare_lf": public_bytes.count(b"\n") - public_bytes.count(b"\r\n"),
                "utf8_bom": public_bytes[:3] == b"\xef\xbb\xbf",
            },
            "pre_ops": pre_ops,
            "normalised_private_sha256": sha256(normalised),
            "normalised_private_bytes": len(normalised),
            "line_ending_op_is_effective": normalised != private_bytes,
            "additions": groups,
            "diff_unified": "".join(
                difflib.unified_diff(
                    text.splitlines(keepends=True),
                    public_bytes.decode("utf-8").splitlines(keepends=True),
                    fromfile="PRIVATE(" + "+".join(pre_ops or ["none"]) + "):"
                    + mapping["source_path"],
                    tofile="PUBLIC:" + mapping["destination_path"],
                    n=3,
                )
            ),
            "intentional_public_superset": INTENTIONAL[mapping["destination_path"]],
        }

        # ---- decomposition, reconciled against the raw diff ---------------
        # (a) the normalisation component.  Its byte effect is the number of
        #     CRLF pairs rewritten plus 3 for a stripped BOM; its LINE effect
        #     is zero by construction, and if the op has nothing to do the
        #     component is recorded as not applying rather than as a no-op
        #     that pretends to contribute.
        crlf_pairs = private_bytes.count(b"\r\n")
        bom_bytes = 3 if private_bytes[:3] == b"\xef\xbb\xbf" else 0
        norm_bytes = crlf_pairs + bom_bytes
        entry["decomposition"] = {
            "a_normalisation": {
                "applies": normalised != private_bytes,
                "ops": pre_ops,
                "bytes_changed": norm_bytes,
                "lines_changed": 0,
                "detail": (
                    f"{crlf_pairs} CRLF pair(s) rewritten to LF"
                    + (f"; {bom_bytes}-byte UTF-8 BOM stripped" if bom_bytes else "")
                    if normalised != private_bytes
                    else (
                        "no normalisation applies: the private file is already "
                        "LF and carries no BOM, so this component contributes "
                        "0 bytes and 0 lines. The helper's recorded transform "
                        "'line endings normalised CRLF -> LF' is therefore not "
                        "what separates this pair of files."
                    )
                ),
            },
            "b_additions": [
                {
                    "addition_id": g["addition_id"],
                    "name": g["name"],
                    "hunks": g["hunk_count"],
                    "lines_added": g["lines_added"],
                    "lines_removed": g["lines_removed"],
                }
                for g in groups
            ],
            "totals": {
                "private_bytes": len(private_bytes),
                "normalised_private_bytes": len(normalised),
                "public_bytes": len(public_bytes),
                "net_bytes_added_by_additions": len(public_bytes) - len(normalised),
                "lines_added": sum(g["lines_added"] for g in groups),
                "lines_removed": sum(g["lines_removed"] for g in groups),
                "hunks": sum(g["hunk_count"] for g in groups),
            },
        }

        # The raw single-shot diff's own counts, to reconcile against.
        raw_sm = difflib.SequenceMatcher(
            None,
            text.splitlines(keepends=True),
            public_bytes.decode("utf-8").splitlines(keepends=True),
            autojunk=False,
        )
        raw_added = sum(
            j2 - j1 for t, _i1, _i2, j1, j2 in raw_sm.get_opcodes() if t != "equal"
        )
        raw_removed = sum(
            i2 - i1 for t, i1, i2, _j1, _j2 in raw_sm.get_opcodes() if t != "equal"
        )
        entry["decomposition"]["reconciliation"] = {
            "raw_diff_lines_added": raw_added,
            "raw_diff_lines_removed": raw_removed,
            "model_lines_added": entry["decomposition"]["totals"]["lines_added"],
            "model_lines_removed": entry["decomposition"]["totals"]["lines_removed"],
            "agrees": (
                raw_added == entry["decomposition"]["totals"]["lines_added"]
                and raw_removed == entry["decomposition"]["totals"]["lines_removed"]
            ),
            "note": (
                "raw counts come from a single-shot diff of normalised-private "
                "against public; model counts are the sum over the frozen "
                "hunks. They must be equal, and the JSON records the equality "
                "rather than asserting it in prose."
            ),
        }
        entry["public_superset_is_strict"] = (
            entry["decomposition"]["totals"]["lines_removed"] == 0
        )
        if not entry["public_superset_is_strict"]:
            entry["public_superset_removals_note"] = (
                "The published copy is a superset in capability, not in lines: "
                f"{entry['decomposition']['totals']['lines_removed']} private "
                "line(s) were removed. Every removal is attributed to the named "
                "addition(s) that carry it, above."
            )
        # The expected hash is produced by ACTUALLY RUNNING the transform.
        result = apply_transform(entry, private_bytes)
        entry["expected_transformed_sha256"] = sha256(result)
        entry["expected_transformed_bytes"] = len(result)
        entry["reproduces_published_copy"] = result == public_bytes
        entries.append(entry)

    return {
        "schema": "p16af-publication-transform-model/1",
        "phase": "16AF",
        "task": "T1 -- per-path transform model for the five blocked mappings",
        "generated_by": "p16af/publication/p16af_publication_transforms.py",
        "private_root": str(PRIVATE_ROOT),
        "public_root": str(PUBLIC_ROOT),
        "public_branch": "publication-sync/post-astra-16af-20260920",
        "public_head": "ba776cc",
        "blocked_count": len(entries),
        "transform_semantics": {
            "pre_ops": (
                "ordered, applied to the decoded private text: "
                "strip_utf8_bom removes a leading U+FEFF; "
                "normalise_crlf_to_lf replaces every CRLF pair with LF. "
                "A pre_op that has nothing to do is recorded as absent, not as "
                "a no-op placeholder, so `line_ending_op_is_effective` can be "
                "false and say so."
            ),
            "additions": (
                "ordered named additions; each carries an ordered list of "
                "hunks; each hunk is an exact literal old->new replacement "
                "that must occur EXACTLY ONCE in the text at that point"
            ),
            "failure_mode": (
                "any anchor that is absent or non-unique raises TransformError; "
                "no edit is skipped and nothing is approximated"
            ),
            "acceptance": (
                "the caller hashes the transform output and requires equality "
                "with expected_transformed_sha256; the transform never "
                "compares itself to the published copy"
            ),
        },
        "provenance_of_the_model": (
            "The literal hunk bodies were derived by diffing the private file "
            "(after its declared normalisation) against the mirror copy, once, "
            "and are now frozen in this JSON. At transform time only the "
            "private file is read. Deriving the recipe required reading the "
            "published copy -- that is what it means to explain a divergence "
            "-- but the frozen model does not consult it."
        ),
        "entries": entries,
    }


# --------------------------------------------------------------------------
# verification (reads the PRIVATE tree only)
# --------------------------------------------------------------------------


def load_model() -> dict[str, Any]:
    return json.loads(MODEL_PATH.read_text(encoding="utf-8"))


def verify() -> int:
    model = load_model()
    bad = 0
    for entry in model["entries"]:
        src = PRIVATE_ROOT / entry["source_path"]
        private_bytes = src.read_bytes()
        got_priv = sha256(private_bytes)
        problems = []
        if got_priv != entry["private_sha256"]:
            problems.append(
                f"private drift: {got_priv[:12]} != recorded "
                f"{entry['private_sha256'][:12]}"
            )
        if len(private_bytes) != entry["private_bytes"]:
            problems.append(
                f"private byte count {len(private_bytes)} != recorded "
                f"{entry['private_bytes']}"
            )
        try:
            out = apply_transform(entry, private_bytes)
            got = sha256(out)
            if got != entry["expected_transformed_sha256"]:
                problems.append(
                    f"transform output {got[:12]} != expected "
                    f"{entry['expected_transformed_sha256'][:12]}"
                )
            status = "REPRODUCES" if entry["reproduces_published_copy"] else "DIVERGES"
        except TransformError as exc:
            problems.append(f"TransformError: {exc}")
            status = "ANCHOR_FAILED"
        print(
            f"{entry['destination_path']:32s} {entry['feature']:8s} "
            f"private={got_priv[:12]} expected_out="
            f"{entry['expected_transformed_sha256'][:12]} {status}"
        )
        for p in problems:
            print(f"    PROBLEM: {p}")
            bad += 1
    print(f"\n{len(model['entries'])} entries, {bad} problem(s)")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit-model", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--apply", metavar="DESTINATION_PATH")
    ns = ap.parse_args()

    if ns.emit_model:
        model = derive_model()
        MODEL_PATH.write_text(
            json.dumps(model, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        print(f"wrote {MODEL_PATH}")
        for e in model["entries"]:
            print(
                f"  {e['destination_path']:32s} pre_ops={e['pre_ops']} "
                f"reproduces={e['reproduces_published_copy']} "
                f"out_sha={e['expected_transformed_sha256'][:12]}"
            )
        return 0

    if ns.apply:
        model = load_model()
        entry = next(
            (e for e in model["entries"] if e["destination_path"] == ns.apply), None
        )
        if entry is None:
            raise SystemExit(f"no model entry for {ns.apply}")
        private_bytes = (PRIVATE_ROOT / entry["source_path"]).read_bytes()
        out = apply_transform(entry, private_bytes)
        print(f"{ns.apply}: {sha256(out)} ({len(out)} bytes)")
        return 0

    return verify()


if __name__ == "__main__":
    raise SystemExit(main())
