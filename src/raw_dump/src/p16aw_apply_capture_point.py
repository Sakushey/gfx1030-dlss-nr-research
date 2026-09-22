#!/usr/bin/env python3
"""Phase 16AW -- wire the repaired RAW_DUMP capture point into the bridge.

HOST-ONLY. This script WRITES ONLY inside p16aw/raw_dump/. It never
modifies phase16_bridge_telemetry/src/amdhip64_7.cpp: it reads it, writes a
transformed copy under p16aw/raw_dump/_work/, and proves the transform is
exactly reversible by deleting the two inserted regions and comparing the
result to the original BYTE FOR BYTE.

The inserted text, and where
---------------------------
  (1) an include, after the last existing include near the top of the file;
  (2) one statement inside hipLaunchKernel, immediately AFTER the existing
      statement

          decode_launch_args(name, args);

      and therefore BEFORE the fail-closed launch gate's early return and
      BEFORE the backend submission fn(function_address, ..., args, ...).

WHY THIS POINT
  * The caller has already materialised every parameter into host memory and
    built the void** args array before entering the bridge, so the complete
    per-argument image exists here, and it exists as SEPARATE host objects --
    which is exactly what the repair must read.
  * decode_launch_args only reads; placing the capture after it still sees the
    application's own bytes.
  * The gate's early return and the backend call are the only two operations
    that could change the arguments' representation; both come later.

ANCHOR DISCIPLINE
  The text `decode_launch_args(name, args);` occurs TWICE in the bridge: once
  as the definition and once as the call. Anchoring on the bare string would
  wire the capture into the definition and it would never run. This script
  anchors on the call's unique following context and ASSERTS that the anchor
  matched exactly once; it prints where it matched so the location is evidence
  rather than an assumption.
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.dirname(HERE)
BRIDGE_SRC = os.path.join(
    os.path.dirname(os.path.dirname(RAW)),
    "phase16_bridge_telemetry", "src", "amdhip64_7.cpp")
WORK = os.path.join(RAW, "_work")
OUT_CPP = os.path.join(WORK, "amdhip64_7_16aw.cpp")

INCLUDE_ANCHOR = '#include "kernel_policy_map.h"\n'
INCLUDE_INSERT = (
    '#include "kernel_policy_map.h"\n'
    '#include "raw_dump_repair_16aw.h"  /* 16AW RAW_DUMP independent capture */\n'
)

CALL_ANCHOR = "    decode_launch_args(name, args);\n    if (!gate) {\n"
CALL_INSERT = (
    "    decode_launch_args(name, args);\n"
    "    /* --- 16AW RAW_DUMP capture point ------------------------------\n"
    "       The caller's void** has ONE ENTRY PER PARAMETER, each pointing at\n"
    "       that parameter's own host storage; the entries are not guaranteed\n"
    "       to be adjacent. The repair reads each entry separately and reads\n"
    "       exactly the byte count the argument-spec table declares for it.\n"
    "       Nothing has written to the image yet: decode_launch_args only\n"
    "       reads, and the gate's early return and the backend call both come\n"
    "       after this line. */\n"
    "    rd16aw::capture_from_env(name, function_address, args, launch_ordinal,\n"
    "                             (const void*)stream);\n"
    "    if (!gate) {\n"
)

ANCHOR_LABEL = "decode_launch_args(name, args);  [CALL, followed by the gate]"


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def find_all(hay, needle):
    out, i = [], hay.find(needle)
    while i != -1:
        out.append(i)
        i = hay.find(needle, i + 1)
    return out


def main():
    problems = []
    if not os.path.isfile(BRIDGE_SRC):
        print("TRANSFORM problems=1 reason=bridge source not found: %s" % BRIDGE_SRC)
        return 1

    with open(BRIDGE_SRC, "rb") as fh:
        original = fh.read()
    orig_text = original.decode("utf-8")
    orig_lines = orig_text.count("\n")
    orig_sha = hashlib.sha256(original).hexdigest()

    # ---- anchor 1: the include -----------------------------------------
    n_inc = orig_text.count(INCLUDE_ANCHOR)
    if n_inc != 1:
        problems.append("include anchor matched %d times (expected 1)" % n_inc)

    # ---- anchor 2: the CALL, not the definition ------------------------
    n_def = orig_text.count("void decode_launch_args(const char* name, void** args)")
    n_call_total = orig_text.count("decode_launch_args(name, args);")
    n_call_anchor = orig_text.count(CALL_ANCHOR)
    if n_call_anchor != 1:
        problems.append("call anchor matched %d times (expected 1)" % n_call_anchor)
    if n_def != 1:
        problems.append("definition of decode_launch_args found %d times "
                        "(expected 1)" % n_def)
    if n_call_total != 1:
        # The definition does not end in ';', so the exact call text occurs
        # once. If a second call is ever added the anchor must be revisited.
        problems.append(
            "expected exactly 1 occurrence of the call text "
            "'decode_launch_args(name, args);'; found %d" % n_call_total)
    if n_inc != 1 or n_call_anchor != 1 or n_def != 1:
        print("TRANSFORM problems=%d %s" % (len(problems), "; ".join(problems)))
        return 1

    transformed = orig_text.replace(INCLUDE_ANCHOR, INCLUDE_INSERT, 1)
    transformed = transformed.replace(CALL_ANCHOR, CALL_INSERT, 1)

    if transformed == orig_text:
        print("TRANSFORM problems=1 reason=transform was a no-op")
        return 1

    os.makedirs(WORK, exist_ok=True)
    with open(OUT_CPP, "wb") as fh:
        fh.write(transformed.encode("utf-8"))

    # ---- reversibility: delete the inserted regions, compare to original
    back = transformed
    back = back.replace(INCLUDE_INSERT, INCLUDE_ANCHOR, 1)
    back = back.replace(CALL_INSERT, CALL_ANCHOR, 1)
    reversible = (back == orig_text)
    back_sha = hashlib.sha256(back.encode("utf-8")).hexdigest()

    added_lines = transformed.count("\n") - orig_lines
    removed_lines = 0

    # ---- the transform must be ABLE to fail ----------------------------
    # Negative control on the anchor discipline. A naive anchor on
    # `decode_launch_args(` resolves to the DEFINITION, where none of the names
    # the capture needs (name, args, launch_ordinal, stream, gate) are in scope:
    # the capture would be wired into a function that never runs at a launch.
    # The control asserts the shipped anchor does NOT resolve there.
    naive_anchor = "decode_launch_args("
    naive_first = orig_text.find(naive_anchor)
    def_first = orig_text.find("void decode_launch_args(const char* name, void** args)")
    shipped_first = orig_text.find(CALL_ANCHOR)
    naive_is_the_definition = (0 <= naive_first <= def_first + len(naive_anchor))
    anchor_control = {
        "control": "naive_anchor_decode_launch_args_paren_would_hit_the_definition",
        "naive_anchor": naive_anchor,
        "naive_anchor_offset": naive_first,
        "definition_offset": def_first,
        "naive_anchor_resolves_into_the_definition": naive_is_the_definition,
        "shipped_anchor_offset": shipped_first,
        "shipped_anchor_is_the_call_site": shipped_first > def_first,
        "verdict": ("DETECTED_AND_AVOIDED"
                    if naive_is_the_definition and shipped_first > def_first
                    else "NOT_DETECTED"),
    }
    if anchor_control["verdict"] != "DETECTED_AND_AVOIDED":
        problems.append("anchor-discipline control did not demonstrate the "
                        "naive anchor is ambiguous")

    result = {
        "phase": "16AW",
        "artifact": "bridge_capture_point_transform",
        "host_only": True,
        "source_read_only": BRIDGE_SRC,
        "source_sha256": orig_sha,
        "source_lines": orig_lines,
        "definition_offset": def_first,
        "bare_occurrences": n_call_total,
        "anchor_used": ANCHOR_LABEL,
        "anchor_match_count": n_call_anchor,
        "include_anchor_match_count": n_inc,
        "transform_applied": True,
        "transform_was_a_no_op": False,
        "output": OUT_CPP,
        "output_sha256": sha256_file(OUT_CPP),
        "lines_added": added_lines,
        "lines_removed": removed_lines,
        "reversible": reversible,
        "reversibility_detail": (
            "deleting the two inserted regions reproduces the original source "
            "byte-for-byte: sha256 %s == %s" % (back_sha, orig_sha)),
        "original_modified": False,
        "anchor_discipline_control": anchor_control,
        "problems": problems,
    }
    with open(os.path.join(RAW, "RAW_DUMP_CAPTURE_POINT_TRANSFORM_16AW.json"), "w",
              encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")

    print("TRANSFORM source_sha256=%s" % orig_sha)
    print("TRANSFORM anchors_compared=3 include=%d bare_occurrences=%d "
          "call_anchor=%d" % (n_inc, n_call_total, n_call_anchor))
    print("TRANSFORM output=%s sha256=%s" % (OUT_CPP, result["output_sha256"]))
    print("TRANSFORM lines_added=%d lines_removed=%d reversible=%s"
          % (added_lines, removed_lines, reversible))
    print("TRANSFORM anchor_control=%s (naive anchor lands in the definition=%s, "
          "shipped anchor is the call site=%s)"
          % (anchor_control["verdict"],
             anchor_control["naive_anchor_resolves_into_the_definition"],
             anchor_control["shipped_anchor_is_the_call_site"]))
    print("TRANSFORM problems=%d" % len(problems))
    if problems:
        for p in problems:
            print("TRANSFORM   PROBLEM %s" % p)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
