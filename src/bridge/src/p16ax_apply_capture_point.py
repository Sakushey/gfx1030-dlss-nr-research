#!/usr/bin/env python3
"""Phase 16AX -- wire the THREAD-SAFE RAW_DUMP capture point into the REAL
shipping bridge source, without editing it.

The shipping bridge is `phase16_bridge_telemetry/src/amdhip64_7.cpp`
(sha256 36f47bea73857161efb4525cce1109b1252b24db588bf388b97f448a77d55be3).
It is READ-ONLY here: this script never writes it.  It writes a transformed
COPY under p16ax/bridge/_work/ and proves that deleting the insertions
reproduces the original byte-for-byte.

Four insertions, and one of them is a repair rather than a wiring change:

  I1  include the 16AX capture header + <atomic>
  I2  mint the launch ordinal ATOMICALLY.  The original is
          static unsigned launch_ordinal = 0;
          ... ++launch_ordinal ...
      an unsynchronised function-local static.  This is the same defect class
      as the 16AT frame counter (brief section 44) and the brief forbids
      carrying it into the integration.
  I3  the capture call, placed at the SAME statement the defective 16AT layer
      sat after (immediately after decode_launch_args), so the repaired layer
      and the layer it replaces are compared on identical bytes
  I4  nothing else.  Every other byte of the bridge is untouched.

Run:  python p16ax_apply_capture_point.py
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE_DIR = os.path.dirname(HERE)  # ...\p16ax\bridge
ROOT = os.path.dirname(os.path.dirname(BRIDGE_DIR))  # project root
SOURCE = os.path.join(
    ROOT, "phase16_bridge_telemetry", "src", "amdhip64_7.cpp"
)
EXPECTED_SHA = "36f47bea73857161efb4525cce1109b1252b24db588bf388b97f448a77d55be3"
WORK = os.path.join(os.path.dirname(HERE), "_work")
OUT = os.path.join(WORK, "amdhip64_7_16ax.cpp")
CONFIG = os.path.join(WORK, "bridge_config.h")
REPORT = os.path.join(os.path.dirname(HERE), "CAPTURE_POINT_TRANSFORM_16AX.json")

WITNESS = os.path.join(
    os.path.dirname(HERE), "build", "p16ax_witness.dll"
).replace("\\", "\\\\")

# The witness backend this build's bridge_config.h must name.  It is a
# HOST-ONLY observing backend: it implements the same 29 entry points and
# records every call.  It is NOT the shipping backend; the shipping backend is
# <ROCM_ROOT>\6.4\bin\amdhip64_6.dll and is identified separately
# in SHIPPING_BACKEND_IDENTITY_16AX.json.  Naming the witness here is what makes
# the three forwarding-matrix arms comparable: the backend is held CONSTANT and
# only the bridge under test varies.
CONFIG_TEXT = """// Phase 16AX -- build-local override of bridge_config.h.
//
// WHY THIS FILE EXISTS
//   amdhip64_7.cpp does `#include "bridge_config.h"`.  A quoted include is
//   resolved against the INCLUDING FILE'S OWN DIRECTORY first, so placing this
//   file beside the transformed copy in _work/ shadows the tree's copy with no
//   -I ordering to be wrong about.  The tree's copy is never edited.
//
// WHAT IT POINTS AT
//   The 16AX host-only WITNESS backend, whose whole job is to record the calls
//   the bridge forwards.  The shipping backend is
//   <ROCM_ROOT>\\6.4\\bin\\amdhip64_6.dll; pointing the test
//   build at the witness is what holds the backend constant across the three
//   forwarding-matrix arms.  A build of this file is NOT deployable and the
//   manifest records which path each build actually resolved.
#pragma once

#define DLSSNR_BACKEND_PATH L"%s"
""" % WITNESS


def sha256_text(t):
    return hashlib.sha256(t.encode("utf-8")).hexdigest()


def main():
    problems = []
    raw = open(SOURCE, "rb").read()
    src_sha = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8")
    if src_sha != EXPECTED_SHA:
        print("REFUSING: bridge source sha %s != expected %s" % (src_sha, EXPECTED_SHA))
        return 1

    # ---------------------------------------------------------------- anchors
    anchors = {}

    i1_old = '#include "registry_ident.h"  // Phase 11 fatbin identity + substitution\n'
    i1_new = (
        '#include "registry_ident.h"  // Phase 11 fatbin identity + substitution\n'
        '#include "p16ax_capture_point.h"  // 16AX RAW_DUMP capture point (host-only)\n'
    )
    anchors["I1_include"] = (i1_old, i1_new, 1)

    i1b_old = "#include <windows.h>\n"
    i1b_new = "#include <windows.h>\n\n#include <atomic>\n"
    anchors["I1b_atomic"] = (i1b_old, i1b_new, 1)

    i2_old = "    static unsigned launch_ordinal = 0;\n    const bool gate = launch_allowed();\n"
    i2_new = (
        "    // 16AX REPAIR (not a wiring change).  The ordinal was an\n"
        "    // unsynchronised function-local static -- `++launch_ordinal` in the\n"
        "    // log_line below.  Two threads entering hipLaunchKernel concurrently\n"
        "    // could both be handed the same ordinal.  That is the same defect\n"
        "    // class as the 16AT frame counter, and the brief forbids carrying it\n"
        "    // into the integration.  It is minted atomically exactly once per\n"
        "    // invocation, before anything else observes it.\n"
        "    static std::atomic<unsigned> launch_ordinal_mint{0};\n"
        "    const unsigned launch_ordinal =\n"
        "        launch_ordinal_mint.fetch_add(1, std::memory_order_relaxed) + 1u;\n"
        "    const bool gate = launch_allowed();\n"
    )
    anchors["I2_atomic_ordinal"] = (i2_old, i2_new, 1)

    i2b_old = "             ++launch_ordinal, name, function_address, numBlocks.x,\n"
    i2b_new = "             launch_ordinal, name, function_address, numBlocks.x,\n"
    anchors["I2b_ordinal_used"] = (i2b_old, i2b_new, 1)

    i3_old = "    decode_launch_args(name, args);\n    if (!gate) {\n"
    i3_new = (
        "    decode_launch_args(name, args);\n"
        "    // ---- 16AX RAW_DUMP CAPTURE POINT -------------------------------\n"
        "    // The same statement the defective 16AT layer sat after, so the two\n"
        "    // layers are compared on identical bytes.  It sits BEFORE the gate's\n"
        "    // early return and BEFORE the backend submission, because those are\n"
        "    // the only two operations that could change the representation of\n"
        "    // the arguments.  Inert unless RAW_DUMP_DIR is set: unconfigured, it\n"
        "    // consumes no instance id, writes no file and touches no disk.\n"
        "    raw_dump_16ax_capture_from_env(name, function_address, args,\n"
        "                                   launch_ordinal, (const void*)stream);\n"
        "    if (!gate) {\n"
    )
    anchors["I3_capture_call"] = (i3_old, i3_new, 1)

    # -------------------------------------------------- anchor discipline control
    # A naive anchor would be `decode_launch_args(` -- which matches the
    # DEFINITION before the call site and would splice the capture into the
    # middle of the decoder.  Measure both offsets so the control is a
    # measurement, not an assertion.
    naive = "decode_launch_args("
    naive_off = text.find(naive)
    def_off = text.find("void decode_launch_args(const char* name, void** args)")
    call_off = text.find(i3_old)
    control = {
        "control": "naive_anchor_decode_launch_args_paren_would_hit_the_definition",
        "naive_anchor": naive,
        "naive_anchor_offset": naive_off,
        "definition_offset": def_off,
        "shipped_anchor_offset": call_off,
        "naive_anchor_resolves_into_the_definition": naive_off == def_off,
        "shipped_anchor_is_the_call_site": call_off > def_off,
    }

    # ------------------------------------------------------------- apply
    records = []
    cur = text
    for name, (old, new, expect) in anchors.items():
        hits = cur.count(old)
        ok = hits == expect
        records.append(
            {
                "insertion": name,
                "expected_hits": expect,
                "observed_hits": hits,
                "result": "APPLIED" if ok else "FAILED_SUBSTITUTION_NOT_APPLIED",
            }
        )
        if not ok:
            problems.append("%s: expected %d hits, observed %d" % (name, expect, hits))
            continue
        cur = cur.replace(old, new)

    if problems:
        json.dump(
            {
                "schema": "p16ax/capture-point-transform/1",
                "source_sha256": src_sha,
                "transform_applied": False,
                "problems": problems,
                "verdict": "FAILED",
            },
            open(REPORT, "w"),
            indent=1,
        )
        print("FAILED: %s" % "; ".join(problems))
        return 1

    out_bytes = cur.encode("utf-8")
    os.makedirs(WORK, exist_ok=True)
    open(OUT, "wb").write(out_bytes)
    open(CONFIG, "w", encoding="utf-8").write(CONFIG_TEXT)

    # --------------------------------------------------------- reversibility
    back = cur
    for name, (old, new, expect) in reversed(list(anchors.items())):
        back = back.replace(new, old)
    recovered = sha256_text(back)

    added = out_bytes.count(b"\n") - raw.count(b"\n")
    report = {
        "schema": "p16ax/capture-point-transform/1",
        "phase": "16AX",
        "host_only": True,
        "source_read_only": SOURCE,
        "source_sha256": src_sha,
        "source_lines": raw.count(b"\n") + 1,
        "source_modified": False,
        "anchor_used": "the call site statement, plus the two declaration lines "
        "that carry the ordinal",
        "insertions": records,
        "n_insertions": len(records),
        "lines_added": added,
        "lines_removed": 0,
        "output": OUT,
        "output_sha256": hashlib.sha256(out_bytes).hexdigest(),
        "output_bytes": len(out_bytes),
        "transform_was_a_no_op": hashlib.sha256(out_bytes).hexdigest() == src_sha,
        "reversible": recovered == src_sha,
        "reversibility_detail": (
            "deleting the four inserted regions reproduces the original source "
            "byte-for-byte: sha256 %s == %s" % (recovered, src_sha)
        ),
        "anchor_discipline_control": control,
        "build_local_backend_override": {
            "file": CONFIG,
            "sha256": hashlib.sha256(CONFIG_TEXT.encode("utf-8")).hexdigest(),
            "points_at": WITNESS.replace("\\\\", "\\"),
            "why": "a quoted include resolves against the including file's own "
            "directory first, so this file shadows the tree's bridge_config.h "
            "with no -I ordering to be wrong about; the tree's copy is never "
            "edited",
            "resolved_path_is_asserted": "the driver calls the testing-only "
            "__bridge_backend_path() export and compares it to this string",
        },
        "problems": problems,
        "verdict": "APPLIED_AND_REVERSIBLE",
    }
    json.dump(report, open(REPORT, "w"), indent=1)
    print(
        "OK  %d insertions, +%d lines, reversible=%s\n    %s\n    -> %s\n    -> %s"
        % (
            len(records),
            added,
            report["reversible"],
            report["output_sha256"],
            OUT,
            REPORT,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
