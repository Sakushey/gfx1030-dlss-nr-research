"""T-PUB step 4: apply the scanners and the rule table to every file.

Reads TREE_SNAPSHOT_16AX.json (produced by p16ax_inventory.py), runs the three
scanners and the classification rule table over every file in the snapshot,
and writes:

    PUBLIC_EXPORT_INVENTORY_16AX.json   every file, exactly one class
    PRIVACY_SCAN_16AX.json              privacy findings
    SECRET_SCAN_16AX.json               secret findings (masked)
    LICENCE_SCAN_16AX.json              external-repository findings
    JSON_VALIDATION_16AX.json           parse status of every publishable .json

Honesty rules applied here:
  * a file that cannot be read is recorded as a finding, not skipped;
  * a file too large for the full pattern set records WHICH scans were skipped
    and why, so "no finding" is never confused with "not examined";
  * the inventory asserts no review it did not perform -- see `ceiling`.
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import p16ax_rules as R  # noqa: E402
import p16ax_scanners as S  # noqa: E402

SRC = r"<PROJECT_ROOT>"
SNAP = os.path.join(HERE, "TREE_SNAPSHOT_16AX.json")

# Above this size the REVIEW-severity patterns and the entropy heuristic are
# skipped (they are the expensive ones and the ones that would produce a wall
# of hits).  The BLOCKER patterns and the privacy patterns still run.
FULL_SCAN_LIMIT = 8 * 1024 * 1024
# Above this the file is not read at all; recorded as SKIPPED_TOO_LARGE.
READ_LIMIT = 96 * 1024 * 1024
# Window used for the expensive patterns on a large file.
WINDOW_HEAD = 4 * 1024 * 1024
WINDOW_TAIL = 256 * 1024

CLONE_ROOTS = [r["clone_root"] for r in S.EXTERNAL_REPOS]
VENDOR_DOC_MARKERS = ("rdna2_isa_wayback", "rdna2_isa.txt", "llvm_asm_gfx8")


def is_classifying_blocker(h: dict) -> bool:
    """Does this secret hit make the FILE credential-bearing?

    Severity alone is not the answer.  Every match is reported at its severity,
    but one measured fact can make a BLOCKER hit non-classifying, and that fact
    is recorded ON THE HIT so nothing is hidden:

      * a `private_key_block` whose header has no base64 body and whose footer
        is adjacent -- a crypto library's label table inside a binary.

    A hit whose annotation is ABSENT is treated as blocking, so "not measured"
    can never mean "relaxed".  The hit still appears in SECRET_SCAN_16AX.json
    with its measurement, and every non-classifying blocker is listed in
    `secret_false_positives` in the inventory.
    """
    if h.get("severity") != "BLOCKER":
        return False
    if h.get("pattern") == "private_key_block" and h.get("pem_body_present") is False:
        return False
    return True


def classify_all(snap: dict, mapped: dict) -> tuple[list, dict, dict, dict, dict]:
    inv = []
    privacy_hits: list[dict] = []
    secret_hits: list[dict] = []
    licence_hits: list[dict] = []
    unreadable: list[dict] = []
    read_too_large: list[dict] = []
    partial_scan: list[dict] = []
    json_results: list[dict] = []
    json_not_validated: list[dict] = []
    rule_counts: Counter = Counter()
    class_counts: Counter = Counter()
    reason_counts: Counter = Counter()
    category_counts: Counter = Counter()
    parse_failures: list[dict] = []
    secret_false_positives: list[dict] = []
    vendor_listings: list[dict] = []

    files = snap["files"]
    total = len(files)
    for i, row in enumerate(files, 1):
        rel = row["source_path"]
        base = rel.rsplit("/", 1)[-1]
        ext = row["extension"]
        full = os.path.join(SRC, rel.replace("/", os.sep))
        size = row["bytes"]

        data: bytes | None = None
        skipped = []
        secret_blocker = False
        own_privacy_patterns: set[str] = set()
        if size > READ_LIMIT:
            read_too_large.append(
                {"source_path": rel, "bytes": size,
                 "reason": f"exceeds READ_LIMIT {READ_LIMIT}"})
            skipped = ["privacy", "secret", "licence", "entropy"]
        else:
            try:
                with open(full, "rb") as f:
                    data = f.read()
            except OSError as exc:
                unreadable.append({"source_path": rel, "error": type(exc).__name__})
                skipped = ["privacy", "secret", "licence", "entropy"]

        if data is not None:
            if size > FULL_SCAN_LIMIT:
                # Large file: the whole-file BLOCKER token scan is cheap (its
                # probes are rare literals), but the full pattern set costs
                # ~1-3 s per pattern per 56 MB.  The expensive patterns run
                # over a bounded window instead, and the window is RECORDED.
                # A file scanned this way is never classed PUBLISH_*, so no
                # publication decision rests on the bounded scan.
                window = data[:WINDOW_HEAD] + (
                    data[-WINDOW_TAIL:] if size > WINDOW_HEAD else b"")
                ph = S.scan_privacy(rel, window)
                sh = S.scan_secret_core(rel, data)
                lh = S.scan_licence(rel, window)
                skipped = [
                    f"secret:high_entropy_run (needs full-text scan)",
                    f"secret:REVIEW patterns (window only)",
                    f"privacy:patterns (window only: first {WINDOW_HEAD} B + "
                    f"last {WINDOW_TAIL} B of {size} B)",
                    f"licence:content patterns (window only)",
                ]
                partial_scan.append(
                    {"source_path": rel, "bytes": size,
                     "scans_not_run": skipped,
                     "scans_run_full_file": ["secret:BLOCKER patterns"],
                     "scans_run_on_window": ["privacy", "secret:REVIEW",
                                             "licence"],
                     "reason": f"exceeds FULL_SCAN_LIMIT {FULL_SCAN_LIMIT}"})
            else:
                ph = S.scan_privacy(rel, data)
                sh = S.scan_secret(rel, data)
                lh = S.scan_licence(rel, data)
            privacy_hits.extend(ph)
            own_privacy_patterns = {
                h["pattern"] for h in ph if h["context_class"] == "PROJECT"
            }
            secret_hits.extend(sh)
            licence_hits.extend(lh)
            secret_blocker = any(is_classifying_blocker(h) for h in sh)
            for h in sh:
                if h.get("severity") == "BLOCKER" and not is_classifying_blocker(h):
                    secret_false_positives.append({
                        "source_path": rel,
                        "pattern": h["pattern"],
                        "context_class": h.get("context_class"),
                        "pem_body_present": h.get("pem_body_present"),
                        "byte_offset": h["byte_offset"],
                        "why_not_classifying": (
                            "PEM header with no base64 body and an adjacent "
                            "footer: a crypto library's label table, not key "
                            "material"
                            if h.get("pem_body_present") is False else
                            "annotation absent: treated as blocking"
                        ),
                    })

        disasm = (S.looks_like_vendor_disassembly(data) if data is not None
                  else {"disassembly_listing": False, "measured": False})
        features = {
            "secret_blocker": secret_blocker,
            "licence_clone_root": any(rel.startswith(c) for c in CLONE_ROOTS),
            "licence_vendor_doc": any(m in rel.lower() for m in VENDOR_DOC_MARKERS),
            "capture_data": False,
            "empty": size == 0,
            "vendor_disassembly_listing": disasm["disassembly_listing"],
        }
        rule_id, klass, reason = R.decide(rel, base, ext, features)
        if disasm["disassembly_listing"]:
            vendor_listings.append({
                "source_path": rel, "bytes": size,
                "instruction_lines": disasm["instruction_lines"],
                "nonblank_lines": disasm["nonblank_lines"],
                "instruction_fraction": disasm["instruction_fraction"],
            })
        rule_counts[rule_id] += 1
        reason_counts[reason] += 1

        cat = R.publish_category(rel)
        if cat:
            category_counts[cat] += 1

        # ---- sanitisation need, measured from the scan findings ----------
        sanitise_reasons = sorted(own_privacy_patterns)
        if data is not None:
            if b"<PROJECT_ROOT>" in data:
                sanitise_reasons.append("identity:private_project_dirname")
            if b"p16a" in data:
                sanitise_reasons.append("identity:live_private_phase_token")
        sanitise_reasons = sorted(set(sanitise_reasons))

        if klass.startswith("PUBLISH"):
            if sanitise_reasons:
                klass = "PUBLISH_SANITIZED"
            else:
                klass = "PUBLISH_EXACT"

        # ---- JSON parse validation --------------------------------------
        #
        # DELIVERABLE 3 is: every .json PROPOSED TO PUBLISH must parse.  The
        # two cases are therefore kept strictly apart, because conflating them
        # makes the verdict unable to state the fact it exists to state:
        #
        #   * a publishable .json must be read AND must parse.  If it cannot be
        #     read, that is a FAILURE -- absence is blocking, not a pass.
        #   * a non-publishable .json is not proposed for publication, so its
        #     parse status is recorded for information and is NOT a failure.
        #     It is reported in `not_validated` and never as a parse failure.
        #
        # Measured 2026-09-22 on the first build: all three "failures" were
        # KEEP_PRIVATE_AUDIT files too large to read, i.e. files nobody proposed
        # to publish, and the verdict read JSON_PARSE_FAILURES_PRESENT while
        # every publishable .json parsed.
        if ext == ".json":
            publishable = klass.startswith("PUBLISH")
            if data is None:
                rec = {
                    "source_path": rel, "class": klass, "bytes": size,
                    "publishable": publishable, "parses": None,
                    "error": ("NOT_READ: exceeds READ_LIMIT %d" % READ_LIMIT
                              if size > READ_LIMIT else
                              "NOT_READ: unreadable"),
                }
                json_results.append(rec)
                if publishable:
                    parse_failures.append({
                        "source_path": rel, "error": rec["error"],
                        "publishable": True,
                    })
                else:
                    json_not_validated.append(rec)
            else:
                ok, err = _json_ok(data)
                json_results.append({
                    "source_path": rel, "class": klass, "bytes": size,
                    "publishable": publishable, "parses": ok, "error": err,
                })
                if not ok:
                    if publishable:
                        parse_failures.append({
                            "source_path": rel, "error": err,
                            "publishable": True,
                        })
                    else:
                        # A .json that does not parse and is NOT proposed for
                        # publication is a recorded observation, not a failure
                        # of DELIVERABLE 3.  Counting it as a failure would make
                        # the verdict unable to state the fact it exists to
                        # state -- measured 2026-09-22: 148 such files made a
                        # run in which all 20 publishable .json parsed report
                        # 148 failures.
                        json_not_validated.append({
                            "source_path": rel, "class": klass, "bytes": size,
                            "publishable": False, "parses": False, "error": err,
                        })

        entry = {
            "source_path": rel,
            "class": klass,
            "rule_id": rule_id,
            "reason_code": reason,
            "bytes": size,
            "extension": ext,
            "sha256": row["sha256"],
            "sha256_skipped": row["sha256_skipped"],
        }
        e = mapped.get(rel)
        if e is not None:
            entry["published_previously"] = True
            entry["published_public_path"] = e.get("public_path")
            entry["published_source_sha256_matches_snapshot"] = (
                e.get("source_sha256") == row["sha256"])
        if klass.startswith("PUBLISH"):
            entry["publication_category"] = cat
            entry["sanitisation_reasons"] = sanitise_reasons
            entry["sanitisation_required"] = bool(sanitise_reasons)
        if skipped:
            entry["scans_not_run"] = skipped
        inv.append(entry)
        if i % 2000 == 0:
            print(f"  ...{i}/{total}", file=sys.stderr, flush=True)

    # Recompute class counts from the FINAL classes (PUBLISH_* split above
    # happens after the first count and would otherwise be wrong).
    final_counts = Counter(e["class"] for e in inv)

    summary = {
        "file_count": len(inv),
        "class_counts": dict(final_counts),
        "rule_counts": dict(rule_counts),
        "reason_counts": dict(reason_counts),
        "publication_category_counts": dict(category_counts),
    }
    return inv, summary, {
        "privacy": privacy_hits,
        "secret": secret_hits,
        "licence": licence_hits,
    }, {
        "unreadable": unreadable,
        "read_too_large": read_too_large,
        "partial_scan": partial_scan,
        "secret_false_positives": secret_false_positives,
        "vendor_disassembly_listings": vendor_listings,
    }, {
        "json_results": json_results,
        "parse_failures": parse_failures,
        "not_validated": json_not_validated,
    }


def _json_ok(data: bytes) -> tuple[bool, str | None]:
    try:
        json.loads(data.decode("utf-8"))
        return True, None
    except UnicodeDecodeError as exc:
        return False, f"UnicodeDecodeError: {exc}"
    except ValueError as exc:
        return False, f"JSONDecodeError: {exc}"


def outside_snapshot(mapped_snapshot: dict) -> list[dict]:
    """Classify this task's own outputs that were written AFTER the snapshot.

    NO SILENT OMISSION applies to this task's own files too.  The snapshot is
    taken first and the artefacts are written second, so the artefacts
    themselves are not in the snapshot they describe -- and a reader scanning
    the inventory's file list for them would find nothing.  They are therefore
    enumerated here and run through the same rule table, so their disposition
    is a decision on the record rather than an absence.

    The one thing this does NOT do is claim a verified digest for them: the
    digest recorded elsewhere belongs to the snapshot revision, and the file on
    disk is the file this run just wrote.  That gap is stated, not hidden.
    """
    rows = []
    if not os.path.isdir(HERE):
        return rows
    for name in sorted(os.listdir(HERE)):
        full = os.path.join(HERE, name)
        rel = "p16ax/publication/" + name
        if os.path.isdir(full):
            rows.append({
                "source_path": rel, "kind": "directory",
                "in_snapshot": rel in mapped_snapshot,
                "rule_id": None, "class": None,
                "note": "directory; its files are enumerated individually",
            })
            continue
        if rel in mapped_snapshot:
            continue
        base = name
        ext = os.path.splitext(name)[1].lower()
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            data = None
        features = {
            "secret_blocker": False,
            "licence_clone_root": False,
            "licence_vendor_doc": False,
            "capture_data": False,
            "empty": os.path.getsize(full) == 0,
            "vendor_disassembly_listing": False,
        }
        if data is not None:
            sh = S.scan_secret(rel, data)
            features["secret_blocker"] = any(is_classifying_blocker(h) for h in sh)
            features["vendor_disassembly_listing"] = \
                S.looks_like_vendor_disassembly(data)["disassembly_listing"]
        rule_id, klass, reason = R.decide(rel, base, ext, features)
        rows.append({
            "source_path": rel, "kind": "file",
            "bytes": os.path.getsize(full),
            "in_snapshot": False,
            "rule_id": rule_id, "class": klass, "reason_code": reason,
            "note": (
                "written by this task after the snapshot was taken; classified "
                "here by the same rule table, but the inventory's per-file "
                "digest does not cover it and the PUBLICATION_RECOMMENDATION "
                "excludes it"
            ),
        })
    return rows


def main() -> int:
    with open(SNAP, encoding="utf-8") as f:
        snap = json.load(f)
    mapped = R.load_mapped()
    mapped_status = (
        "LOADED" if mapped else "UNRESOLVABLE_OR_EMPTY"
    )
    print(f"mapped manifest: {mapped_status} ({len(mapped)} entries)",
          file=sys.stderr)

    inv, summary, scans, gaps, jsons = classify_all(snap, mapped)

    snap_paths = {r["source_path"] for r in snap["files"]}
    outside = outside_snapshot(snap_paths)

    # ---------------- inventory ----------------
    out = {
        "schema": "p16ax/publication/export-inventory/1",
        "phase": "16AX",
        "task_id": "T-PUB",
        "source_root": SRC,
        "snapshot_captured_utc": snap["captured_utc"],
        "build_utc_note": (
            "the source tree is LIVE and other workers write into it; this "
            "inventory covers exactly the snapshot's file set and nothing more"
        ),
        "class_vocabulary": R.CLASSES,
        "rule_table": [
            {"rule_id": r[0], "class": r[1], "reason_code": r[2],
             "description": r[3]}
            for r in R.RULE_TABLE
        ],
        "rule_ordering": (
            "rules are evaluated in table order; the FIRST match wins. The "
            "order encodes severity: the restriction that must never be relaxed "
            "is the one that wins."
        ),
        "governing_policy": {
            "source": "p16aw/audit/ASTRA_AUDIT4_2026-09-21.md section 150",
            "do_not_publish": [
                "raw Astra reports", "proprietary binaries",
                "proprietary weights", "raw GTA capture blobs",
                "vendor disassembly", "private file paths", "secrets",
                "private session reports",
            ],
            "extended_by_brief": [
                "NVIDIA/AMD proprietary binaries",
                "extracted proprietary device code",
                "raw proprietary weight data",
                "crash dumps containing sensitive memory",
                "files whose licence status is unverified if they derive from a "
                "third-party repository",
            ],
        },
        "summary": summary,
        "files_written_after_the_snapshot": outside,
        "files_written_after_the_snapshot_note": (
            "NO SILENT OMISSION covers this task's own outputs. The snapshot is "
            "taken first and the artefacts are written second, so the artefacts "
            "are not in the snapshot they describe. They are enumerated and run "
            "through the same rule table rather than left as an absence. Their "
            "digest is NOT asserted here: the file on disk is the revision this "
            "run wrote."
        ),
        "scan_gaps": {
            "unreadable": gaps["unreadable"],
            "not_read_too_large": gaps["read_too_large"],
            "partial_scan": gaps["partial_scan"],
            "secret_false_positives": gaps["secret_false_positives"],
            "secret_false_positive_count": len(gaps["secret_false_positives"]),
            "secret_false_positive_note": (
                "BLOCKER hits that were reported and then measured NOT to make "
                "their file credential-bearing. Each entry carries the "
                "measurement. A hit with no measurement is treated as blocking, "
                "so absence of an annotation never relaxes anything."
            ),
            "vendor_disassembly_listings": gaps["vendor_disassembly_listings"],
            "vendor_disassembly_listing_count": len(gaps["vendor_disassembly_listings"]),
            "vendor_disassembly_listing_note": (
                "files whose bytes are dominated by ISA instruction lines, i.e. "
                "listings of a proprietary object. Measured from content, not "
                "from the filename; held private under policy section 150"
            ),
            "mapped_manifest_status": mapped_status,
            "mapped_manifest_locator": R.MAPPED_MANIFEST,
            "absence_is_blocking_note": (
                "an unreadable file, a file too large to read, or a partial "
                "scan is a recorded gap, never a silent pass"
            ),
        },
        "ceiling": (
            "A class states what this policy PERMITS for a file; it is not a "
            "review. PUBLISH_EXACT asserts only that the named scanners found "
            "no hit in that file and that no absolute personal path is present "
            "in the bytes scanned -- it does not assert the file is safe to "
            "publish, because a pattern scanner cannot find what it has no "
            "pattern for. PUBLISH_SANITIZED additionally requires the listed "
            "sanitisation actions before the bytes may leave the private tree. "
            "Only the paths named in PUBLICATION_RECOMMENDATION_16AX.json were "
            "examined individually for this phase."
        ),
        "files": inv,
    }
    dst = os.path.join(HERE, "PUBLIC_EXPORT_INVENTORY_16AX.json")
    with open(dst, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=1)

    # ---------------- scans ----------------
    _write_scan("PRIVACY_SCAN_16AX.json", "privacy", scans["privacy"], snap)
    _write_scan("SECRET_SCAN_16AX.json", "secret", scans["secret"], snap)
    _write_scan("LICENCE_SCAN_16AX.json", "licence", scans["licence"], snap)

    # ---------------- json validation ----------------
    pub_checked = [r for r in jsons["json_results"] if r["publishable"]]
    jv = {
        "schema": "p16ax/publication/json-validation/1",
        "purpose": (
            "every .json file proposed for publication must parse; a file that "
            "does not parse, or that could not be read, is reported as a "
            "FAILURE rather than dropped"
        ),
        "publishable_json_checked": len(pub_checked),
        "publishable_json_parsed": sum(1 for r in pub_checked if r["parses"] is True),
        "non_publishable_json_not_validated": len(jsons["not_validated"]),
        "files_checked_total": len(jsons["json_results"]),
        "parse_failures": jsons["parse_failures"],
        "parse_failure_count": len(jsons["parse_failures"]),
        "results": jsons["json_results"],
        "not_validated": jsons["not_validated"],
        "not_validated_note": (
            "these .json files are NOT proposed for publication, so their parse "
            "status is recorded for information and is deliberately not counted "
            "as a failure. Conflating the two would make `parse_failures` unable "
            "to state the fact it exists to state."
        ),
        "verdict": ("ALL_PUBLISHABLE_JSON_PARSES"
                    if not jsons["parse_failures"]
                    else "JSON_PARSE_FAILURES_PRESENT"),
    }
    with open(os.path.join(HERE, "JSON_VALIDATION_16AX.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(jv, f, indent=1)

    print(f"wrote inventory: {summary['file_count']} files")
    for k, v in sorted(summary["class_counts"].items(), key=lambda x: -x[1]):
        print(f"  {k:32s} {v}")
    print(f"json publishable checked: {len(pub_checked)}, "
          f"parsed: {jv['publishable_json_parsed']}, "
          f"failures: {len(jsons['parse_failures'])}, "
          f"not_validated(non-publishable): {len(jsons['not_validated'])}")
    print(f"secret false positives (measured non-classifying): "
          f"{len(gaps['secret_false_positives'])}")
    return 0


def _write_scan(name: str, which: str, hits: list[dict], snap: dict) -> None:
    by_path = Counter(h["source_path"] for h in hits)
    by_pattern = Counter(h["pattern"] for h in hits)
    # An absent context_class is reported as UNSET, never defaulted to PROJECT.
    # Defaulting was a real defect: the licence scanner omitted the field, so
    # this histogram read "PROJECT: 12396" while the count below read 0 -- one
    # artefact, two contradictory answers, from the same hits.
    by_context = Counter(h.get("context_class", "UNSET") for h in hits)
    unset = sum(1 for h in hits if "context_class" not in h)
    real = [h for h in hits if h.get("context_class") == "PROJECT"]
    if which == "secret":
        blockers = [h for h in real if h.get("severity") == "BLOCKER"]
        blocking_definition = (
            "a BLOCKER-severity hit in a PROJECT-context file: the file carries "
            "credential-shaped material")
    elif which == "licence":
        blockers = real
        blocking_definition = (
            "any hit in a PROJECT-context file: the file quotes or derives from "
            "an external repository and its licence status must be established "
            "before the file may move -- no licence is ever assumed")
    else:
        blockers = real
        blocking_definition = (
            "any hit in a PROJECT-context file: personal path, name, machine "
            "name or e-mail address that must not leave the private tree")
    out = {
        "schema": f"p16ax/publication/{which}-scan/1",
        "scanner": which,
        "snapshot_captured_utc": snap["captured_utc"],
        "files_in_snapshot": snap["file_count"],
        "raw_hit_count": len(hits),
        "hit_count_excluding_self_reference_and_controls": len(real),
        "blocking_hit_count": len(blockers),
        "blocking_definition": blocking_definition,
        "hits_missing_context_class": unset,
        "distinct_paths_hit": len(by_path),
        "hits_by_pattern": dict(by_pattern.most_common()),
        "hits_by_context_class": dict(by_context.most_common()),
        "hit_paths": sorted(by_path),
        "hits": hits,
        "context_class_vocabulary": {
            "PROJECT": "a file outside this task's own directory: a real finding",
            "SELF_REFERENCE": "this task's own package, which necessarily holds "
                              "the pattern literals and the absolute source root",
            "SEEDED_CONTROL": "a deliberately planted synthetic dart under "
                              "p16ax/publication/_selftest/",
            "UNSET": "the scanner did not set the field -- a defect, reported "
                     "rather than defaulted",
        },
        "masking_note": (
            "every excerpt is masked: the matched token keeps at most its first "
            "6 characters and the remainder is discarded, not hashed, so it "
            "cannot be recovered. No secret value appears in this artefact."
        ),
    }
    with open(os.path.join(HERE, name), "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=1)
    print(f"  {name}: {len(hits)} hits, {len(by_path)} distinct paths, "
          f"{len(blockers)} blocking", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
