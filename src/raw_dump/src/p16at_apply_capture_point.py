#!/usr/bin/env python3
"""Phase 16AT RAW_DUMP -- wire the capture point into the bridge, without
modifying the bridge.

The recorder has to be reachable from inside
phase16_bridge_telemetry/src/amdhip64_7.cpp. That file is outside p16at/
and must not be modified, so this script produces a TRANSFORMED COPY under
p16at/raw_dump/_work/ and proves the transformation is exactly the two
blank-line-separated insertions it claims to be.

The proof, all of it measured here rather than asserted:

  P1  the include anchor  and the statement anchor each occur EXACTLY ONCE in
      the original; if either count is not 1 the script refuses to run.
  P2  the transformed file, with the inserted lines removed again, is
      byte-identical to the original (sha256 equality).
  P3  the transformed file differs from the original in exactly
      len(inserted lines) added lines and 0 removed lines, and no line of the
      original was reordered or altered.
  P4  a unified diff is written, and re-applying it to the original reproduces
      the transformed file byte-for-byte.

The rehearsal builds the TRANSFORMED copy, so the code under test is the code
the patch describes. What the rehearsal does not test is the original file --
the patch's applicability to it is what P1-P4 establish.

Usage:
  python p16at_apply_capture_point.py
"""

import difflib
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW_DUMP = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(RAW_DUMP))

ORIGINAL = os.path.join(ROOT, "phase16_bridge_telemetry", "src", "amdhip64_7.cpp")
WORK = os.path.join(RAW_DUMP, "_work")
TRANSFORMED = os.path.join(WORK, "amdhip64_7_capture.cpp")
PATCH = os.path.join(HERE, "amdhip64_7_capture_point.patch")
PROVENANCE = os.path.join(WORK, "capture_point_application.json")

INCLUDE_ANCHOR = '#include "kernel_policy_map.h"'
STATEMENT_ANCHOR = "    decode_launch_args(name, args);"

INCLUDE_INSERT = ['#include "raw_dump_capture_point.h"  /* 16AT RAW_DUMP */']
STATEMENT_INSERT = [
    "    /* --- 16AT RAW_DUMP capture point -------------------------------",
    "       The complete host by-value parameter image exists (the caller",
    "       built it before entering the bridge) and nothing has written to",
    "       it: decode_launch_args only reads. This is after blob",
    "       construction and before the launch gate's early return and",
    "       before the backend submission fn(...) can pack or mutate it. */",
    "    raw_dump_at_launch_capture_point(name, function_address, args,",
    "                                     launch_ordinal);",
]


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(p):
    with open(p, "rb") as f:
        return sha256_bytes(f.read())


def transform(original_text):
    """Return (transformed_text, inserted_lines, report)."""
    lines = original_text.split("\n")
    inc_idx = [i for i, l in enumerate(lines) if l.strip() == INCLUDE_ANCHOR]
    st_idx = [i for i, l in enumerate(lines) if l.rstrip() == STATEMENT_ANCHOR]
    report = {
        "include_anchor": INCLUDE_ANCHOR,
        "include_anchor_occurrences": len(inc_idx),
        "include_anchor_lines": [i + 1 for i in inc_idx],
        "statement_anchor": STATEMENT_ANCHOR,
        "statement_anchor_occurrences": len(st_idx),
        "statement_anchor_lines": [i + 1 for i in st_idx],
    }
    if len(inc_idx) != 1 or len(st_idx) != 1:
        raise SystemExit(
            "ANCHOR NOT UNIQUE -- refusing to transform.\n"
            "  include anchor occurrences: %d\n  statement anchor occurrences: %d"
            % (len(inc_idx), len(st_idx)))

    inserted = []
    out = []
    for i, l in enumerate(lines):
        if i == inc_idx[0]:
            out.append(l)
            out.extend(INCLUDE_INSERT)
            inserted.extend(INCLUDE_INSERT)
            continue
        if i == st_idx[0]:
            out.append(l)
            out.extend(STATEMENT_INSERT)
            inserted.extend(STATEMENT_INSERT)
            continue
        out.append(l)
    report["inserted_lines"] = inserted
    report["n_inserted_lines"] = len(inserted)
    # The statement insertion is inside a function body, so the include must be
    # declared before it: verify the ordering we claim.
    report["include_insert_line"] = inc_idx[0] + 2
    report["statement_insert_line"] = st_idx[0] + 2 + len(INCLUDE_INSERT)
    if report["include_insert_line"] >= report["statement_insert_line"]:
        raise SystemExit("include insertion would land after the statement")
    return "\n".join(out), inserted, report


def main():
    with open(ORIGINAL, "rb") as f:
        orig_bytes = f.read()
    orig_text = orig_bytes.decode("utf-8")

    transformed_text, inserted, report = transform(orig_text)
    trans_bytes = transformed_text.encode("utf-8")

    # P2: removing the inserted lines reproduces the original exactly. Each
    # inserted line must occur EXACTLY ONCE in the transformed file, which is
    # also what makes the P3 line accounting below meaningful.
    tl = transformed_text.split("\n")
    strip_idx = set()
    for ins in inserted:
        hits = [i for i, l in enumerate(tl) if l == ins]
        if len(hits) != 1:
            raise SystemExit(
                "P2 FAILS: inserted line %r occurs %d times in the transformed "
                "file" % (ins, len(hits)))
        strip_idx.add(hits[0])
    back = "\n".join(l for i, l in enumerate(tl) if i not in strip_idx).encode("utf-8")
    p2 = (back == orig_bytes)
    if not p2:
        raise SystemExit("P2 FAILS: round-trip is not byte-identical to the "
                         "original")

    # P3: line counts.
    ol = orig_text.split("\n")
    tl2 = transformed_text.split("\n")
    added = [l for l in tl2 if l not in ol]
    removed = [l for l in ol if l not in tl2]
    p3 = (len(added) == len(inserted) and len(removed) == 0)

    # P4: patch round-trip.
    diff = list(difflib.unified_diff(
        ol, tl2, fromfile="a/phase16_bridge_telemetry/src/amdhip64_7.cpp",
        tofile="b/phase16_bridge_telemetry/src/amdhip64_7.cpp", lineterm="",
        n=3))
    patch_text = "\n".join(diff) + "\n"
    p4 = apply_patch(ol, diff) == tl2

    os.makedirs(WORK, exist_ok=True)
    with open(TRANSFORMED, "wb") as f:
        f.write(trans_bytes)
    with open(PATCH, "w", encoding="utf-8", newline="\n") as f:
        f.write(patch_text)

    prov = {
        "schema": "p16at/raw-dump-capture-point-application/1",
        "phase": "16AT",
        "host_only": True,
        "gpu_execution_performed": False,
        "original_file": os.path.relpath(ORIGINAL, ROOT).replace("\\", "/"),
        "original_sha256": sha256_bytes(orig_bytes),
        "original_bytes": len(orig_bytes),
        "original_lines": len(ol),
        "transformed_file": os.path.relpath(TRANSFORMED, ROOT).replace("\\", "/"),
        "transformed_sha256": sha256_bytes(trans_bytes),
        "transformed_bytes": len(trans_bytes),
        "transformed_lines": len(tl2),
        "patch_file": os.path.relpath(PATCH, ROOT).replace("\\", "/"),
        "patch_sha256": sha256_bytes(patch_text.encode("utf-8")),
        "original_was_modified": False,
        "transformation": report,
        "proofs": {
            "P1_anchors_unique": (report["include_anchor_occurrences"] == 1 and
                                  report["statement_anchor_occurrences"] == 1),
            "P2_stripping_insertions_reproduces_the_original":
                bool(p2) and sha256_bytes(back) == sha256_bytes(orig_bytes),
            "P2_original_sha256_recovered": sha256_bytes(back),
            "P3_added_lines_equals_insertions_and_nothing_removed":
                bool(p3),
            "P3_added": len(added),
            "P3_removed": len(removed),
            "P4_patch_round_trip_reproduces_the_transformed_file": bool(p4),
        },
        "what_this_does_not_prove": (
            "that the transformed copy behaves like a bridge with the capture "
            "point wired in -- that is what the rehearsal measures. This file "
            "establishes only that the wiring is exactly these inserted lines "
            "and nothing else."),
    }
    with open(PROVENANCE, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(prov, indent=1) + "\n")

    ok = all([prov["proofs"]["P1_anchors_unique"],
              prov["proofs"]["P2_stripping_insertions_reproduces_the_original"],
              prov["proofs"]["P3_added_lines_equals_insertions_and_nothing_removed"],
              prov["proofs"]["P4_patch_round_trip_reproduces_the_transformed_file"]])
    print("original   %s  %d B  %s" % (prov["original_sha256"][:16],
                                      len(orig_bytes), ORIGINAL))
    print("transformed %s  %d B" % (prov["transformed_sha256"][:16],
                                    len(trans_bytes)))
    print("insertions: %d lines (include %d, statement %d)"
          % (len(inserted), len(INCLUDE_INSERT), len(STATEMENT_INSERT)))
    print("P1 anchors unique        : %s" % prov["proofs"]["P1_anchors_unique"])
    print("P2 strip -> original     : %s"
          % prov["proofs"]["P2_stripping_insertions_reproduces_the_original"])
    print("P3 added=%d removed=%d   : %s"
          % (len(added), len(removed),
             prov["proofs"]["P3_added_lines_equals_insertions_and_nothing_removed"]))
    print("P4 patch round-trip      : %s"
          % prov["proofs"]["P4_patch_round_trip_reproduces_the_transformed_file"])
    print("APPLY_CAPTURE_POINT %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


def apply_patch(orig_lines, diff_lines):
    """Apply a unified diff with no fuzz. Returns the resulting line list."""
    out = []
    i = 0
    orig_pos = 0
    while i < len(diff_lines):
        l = diff_lines[i]
        if l.startswith("---") or l.startswith("+++"):
            i += 1
            continue
        if l.startswith("@@"):
            hdr = l.split("@@")[1].strip()
            a = hdr.split(" ")[0]
            start = int(a[1:].split(",")[0]) - 1
            out.extend(orig_lines[orig_pos:start])
            orig_pos = start
            i += 1
            while i < len(diff_lines) and not diff_lines[i].startswith("@@"):
                d = diff_lines[i]
                if d.startswith(" "):
                    if orig_lines[orig_pos] != d[1:]:
                        raise SystemExit("P4 FAILS: context mismatch at %d"
                                         % orig_pos)
                    out.append(d[1:])
                    orig_pos += 1
                elif d.startswith("-"):
                    if orig_lines[orig_pos] != d[1:]:
                        raise SystemExit("P4 FAILS: removal mismatch at %d"
                                         % orig_pos)
                    orig_pos += 1
                elif d.startswith("+"):
                    out.append(d[1:])
                i += 1
            continue
        i += 1
    out.extend(orig_lines[orig_pos:])
    return out


if __name__ == "__main__":
    sys.exit(main())
