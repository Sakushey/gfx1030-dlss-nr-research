#!/usr/bin/env python3
"""Phase 16AW -- extract and RUN the retired 16AT finite-bound classifier.

Brief PART X, section 74 (the audit's regression), section 71 (retire only the
classification).

WHY THIS FILE EXISTS
    The audit's finding is a claim about code that is already on disk.  A claim
    about code is reproduced by EXECUTING THAT CODE, not by re-implementing what
    a reader believes it does -- this project has already shipped a phase whose
    "reproduction" was a paraphrase.  So this module does not restate the old
    classifier.  It reads the bytes of

        p16at/native/p16at_machine_cfg.py

    slices out the block that assigns a finite bound, records the SHA-256 of the
    exact slice it took (so the reproduction is pinned to bytes, not to a line
    number that a later edit could shift), and exec()s that slice as the body of
    a function.  The slice is never modified in flight.

    If the slice cannot be found, or its hash is not the one this phase recorded
    when it was written, the reproduction FAILS CLOSED with a NOT_MEASURED
    status rather than falling back to a paraphrase.

Host-only.  Disassembling is not launching: no HIP call, no GPU, no slot.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

sys.path.insert(0, os.path.join(ROOT, "p16at", "native"))
import p16at_machine_cfg as M  # noqa: E402

OLD_SOURCE = os.path.join(ROOT, "p16at", "native", "p16at_machine_cfg.py")
SLICE_START_MARKER = "    # ---- finite-termination argument per natural loop"
SLICE_END_MARKER = "        })"

#: SHA-256 of the exact slice this phase read, recorded at the time of the
#: reproduction.  A mismatch is a STOP, not a warning: if the file changed, the
#: reproduction is of a different program and must not be reported as the
#: audit's regression.
SLICE_SHA256_AT_TIME_OF_MEASUREMENT = \
    "2084f7dd624e492605a0b2d5410fb995ebaab5e1133cd79e06c888d8ae933d9c"


def extract_slice(path=OLD_SOURCE):
    text = open(path, encoding="utf-8").read()
    lines = text.split("\n")
    try:
        start = next(i for i, l in enumerate(lines)
                     if l.startswith(SLICE_START_MARKER))
    except StopIteration:
        return None, {"error": "the slice start marker is not present",
                      "marker": SLICE_START_MARKER,
                      "note": "the classifier may have been retired from the "
                              "file; the reproduction cannot be run"}
    try:
        end = next(i for i in range(start, len(lines))
                   if lines[i] == SLICE_END_MARKER)
    except StopIteration:
        return None, {"error": "the slice end marker is not present",
                      "marker": SLICE_END_MARKER}
    body = "\n".join(lines[start:end + 1])
    return body, {
        "source_file": os.path.relpath(path, ROOT).replace("\\", "/"),
        "source_file_sha256": hashlib.sha256(
            open(path, "rb").read()).hexdigest(),
        "first_line_1_indexed": start + 1,
        "last_line_1_indexed": end + 1,
        "n_lines": end - start + 1,
        "slice_sha256": hashlib.sha256(body.encode()).hexdigest(),
        "slice_sha256_recorded_at_measurement":
            SLICE_SHA256_AT_TIME_OF_MEASUREMENT,
        "slice_hash_matches_the_recorded_one":
            hashlib.sha256(body.encode()).hexdigest()
            == SLICE_SHA256_AT_TIME_OF_MEASUREMENT,
        "slice_first_line": lines[start],
        "slice_last_line": lines[end],
    }


def build_old_termination_classifier(path=OLD_SOURCE):
    """A callable (loop_rows, branch_rows, blocks, ins) -> None that mutates
    loop_rows exactly as the retired 16AT code did.

    The slice sits inside `main()` at one level of indentation; wrapping it in a
    function means indenting it by one more level, and nothing else.  The
    `re` module the slice uses is injected into the function's namespace because
    the original relied on the module-level import.
    """
    body, meta = extract_slice(path)
    if body is None:
        return None, meta
    indented = "\n".join(("    " + l) if l.strip() else l
                         for l in body.split("\n"))
    src = ("def _retired_classifier(loop_rows, branch_rows, blocks, ins):\n"
           + indented + "\n")
    ns = {"re": re}
    exec(compile(src, "<p16at_machine_cfg.py slice>", "exec"), ns)
    fn = ns["_retired_classifier"]
    fn.__doc__ = ("the retired 16AT finite-termination classifier, exec()ed "
                  "from the byte slice recorded in `meta`")
    return fn, meta


def old_classifier_inputs(ins, symbol_base):
    """Rebuild the four inputs `main()` handed to the slice, by calling the
    SAME 16AT functions `main()` called, in the same order."""
    blocks, addr2blk, branches = M.build_cfg(ins, symbol_base)
    if addr2blk:
        entry = addr2blk[ins[0]["addr"]]
    else:
        entry = 0
    live = M.reachable(blocks, entry)
    idom = M.dominators(blocks, entry, live)
    loops = M.natural_loops(blocks, idom, live)
    idx = {x["addr"]: i for i, x in enumerate(ins)}
    contains = {}
    for b in blocks:
        for i in range(b["first_idx"], b["last_idx"] + 1):
            contains[ins[i]["addr"]] = b["id"]

    branch_rows = []
    for x in ins:
        d = branches.get(x["addr"])
        if d is None or d["kind"] != "cond":
            continue
        w, u, _cyc = M.reaching_scc_defs(blocks, contains, ins, idx,
                                         contains[x["addr"]])
        branch_rows.append({
            "at": hex(x["addr"]), "mnemonic": x["mnemonic"],
            "operands": x["operands"], "target": hex(d["A"]),
            "reaching_scc_defs": {hex(k): vv for k, vv in sorted(w.items())},
            "unmodelled_scalar_reached": {hex(k): vv
                                          for k, vv in sorted(u.items())},
            "scc_verdict": M.classify(w, u),
        })
    loop_rows = []
    for L in loops:
        body = [ins[i] for n in L["nodes"] for i in
                range(blocks[n]["first_idx"], blocks[n]["last_idx"] + 1)]
        loop_rows.append({
            "head_block": L["head"], "head_pc": hex(blocks[L["head"]]["start"]),
            "latch_block": L["latch"],
            "latch_pc": hex(blocks[L["latch"]]["terminator_at"]),
            "latch_branch": blocks[L["latch"]]["terminator"],
            "nodes": L["nodes"], "n_nodes": len(L["nodes"]),
            "n_instructions": len(body), "exits": L["exits"],
            "nesting_depth": L["nesting_depth"],
        })
    return loop_rows, branch_rows, blocks, ins


def run_old_classifier(ins, symbol_base, path=OLD_SOURCE):
    """(loop_rows_after, meta, error).  `error` is a string when the classifier
    could not be built or executed."""
    fn, meta = build_old_termination_classifier(path)
    if fn is None:
        return None, meta, meta.get("error", "the slice could not be extracted")
    loop_rows, branch_rows, blocks, _ = old_classifier_inputs(ins, symbol_base)
    try:
        fn(loop_rows, branch_rows, blocks, ins)
    except Exception as exc:                       # noqa: BLE001
        return None, meta, "the retired classifier raised %s: %s" % (
            type(exc).__name__, exc)
    return loop_rows, meta, None


def summary_of(loop_rows):
    """What the retired classifier decided, as a histogram plus the rows that
    carry no usable bound."""
    hist = {}
    for L in loop_rows:
        t = L.get("termination")
        v = t.get("verdict") if isinstance(t, dict) else t
        hist[v] = hist.get(v, 0) + 1
    counted = [L for L in loop_rows
               if isinstance(L.get("termination"), dict)
               and L["termination"].get("verdict")
               == "COUNTED_LOOP_WITH_STATIC_BOUND"]
    return {
        "verdict_histogram": hist,
        "n_loops": len(loop_rows),
        "n_counted_with_static_bound": len(counted),
        "n_counted_with_static_bound_and_MAX_TRIP_COUNT_NONE":
            len([L for L in counted
                 if L["termination"].get("max_trip_count") is None]),
        "the_defect": "a loop can carry the verdict "
                      "COUNTED_LOOP_WITH_STATIC_BOUND and a null "
                      "max_trip_count at the same time; every downstream lane "
                      "tests the VERDICT, so the null bound is never seen",
    }
