#!/usr/bin/env python3
"""Phase 16AW -- run the replacement prover over the FINAL Slot-5 object.

Brief PART X, section 77: every loop in the exact final Slot-5 `.text` must get
a finite bound, or Slot 5 is blocked.

WHAT IS PROVED HERE
    The object is p16as/native/hip/build/k_dec_upsample_b64.co.  Its `.text`
    section is hashed and compared against the SHA-256 quoted in the brief, so
    this is provably a statement about the artefact under discussion and not
    about a rebuild that happens to sit at the same path.  The disassembly is
    parsed by the 16AT front end (brief section 71 keeps that work), the CFG,
    the dominators, the natural loops and the SCC reaching definitions come from
    the same place, and each natural loop is then put through the replacement
    recurrence prover.

    If no disassembly could be obtained this script fails with NOT_MEASURED
    rather than analysing something else: inventing loop bodies is the one thing
    a proof of bounds must never do.

Host-only.  Disassembling is not launching: no HIP call, no GPU, no slot.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(ROOT, "p16aw", "liveness")

sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "p16at", "native"))
import p16at_machine_cfg as M             # noqa: E402
import p16aw_loop_recurrence_prover as P  # noqa: E402
import p16aw_old_classifier as OLD        # noqa: E402

#: the `.text` section hash the brief quotes for the final Slot-5 object
TEXT_SHA256_IN_THE_BRIEF = \
    "ec11c135cf9a548cfd2e263757723a178b74bb148496be35bd47b2a95a85312e"


def _u(b, off, n):
    return int.from_bytes(b[off:off + n], "little")


def elf_sections(co):
    """ROUTE 1 to the section layout: the ELF section header table, parsed from
    the file's own bytes.

    `llvm-objdump -h` on this object prints Idx/Name/Size/VMA/Type and NOT the
    file offset, so the offset cannot come from it.  It is read here instead of
    being hard-coded, because a hard-coded 0x800 would silently hash the wrong
    bytes if the object were ever relinked.
    """
    b = open(co, "rb").read()
    if b[:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
        return None, "not a little-endian ELF64 file"
    shoff, shentsize, shnum, shstrndx = (_u(b, 0x28, 8), _u(b, 0x3A, 2),
                                         _u(b, 0x3C, 2), _u(b, 0x3E, 2))
    raw = []
    for i in range(shnum):
        o = shoff + i * shentsize
        raw.append({"idx": i, "name_off": _u(b, o, 4), "type": _u(b, o + 4, 4),
                    "addr": _u(b, o + 16, 8), "offset": _u(b, o + 24, 8),
                    "size": _u(b, o + 32, 8)})
    st = raw[shstrndx]
    names = b[st["offset"]:st["offset"] + st["size"]]
    for s in raw:
        end = names.find(b"\x00", s["name_off"])
        s["name"] = names[s["name_off"]:end].decode("ascii", "replace")
    return {s["name"]: s for s in raw}, None


def objdump_h(co):
    """ROUTE 2 to the same fact: `llvm-objdump -h`.  It confirms the section's
    NAME, SIZE and VMA by an independent parser and an independent tool."""
    r = subprocess.run([M.OBJDUMP_64, "-h", co], capture_output=True, text=True)
    out = {}
    for line in r.stdout.splitlines():
        m = re.match(r"\s*(\d+)\s+(\.\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+(\S+)",
                     line)
        if m:
            out[m.group(2)] = {"idx": int(m.group(1)),
                               "size": int(m.group(3), 16),
                               "vma": int(m.group(4), 16),
                               "type": m.group(5)}
    return out


def text_section(co):
    secs, err = elf_sections(co)
    if secs is None:
        return None, err, None
    if ".text" not in secs:
        return None, "the ELF section header table has no .text section", None
    s = secs[".text"]
    data = open(co, "rb").read()[s["offset"]:s["offset"] + s["size"]]
    s["sha256"] = hashlib.sha256(data).hexdigest()
    s["n_bytes_hashed"] = len(data)
    other = objdump_h(co).get(".text")
    s["second_route"] = {
        "tool": "llvm-objdump -h",
        "size": None if other is None else other["size"],
        "vma": None if other is None else other["vma"],
        "agrees": bool(other and other["size"] == s["size"]
                       and other["vma"] == s["addr"]),
    }
    return s, None, {"elf_section_headers": len(secs), "objdump_sections":
                     len(objdump_h(co))}


def prove_slot5(co=None):
    co = co or M.CO
    whole_sha = hashlib.sha256(open(co, "rb").read()).hexdigest()
    sec, sec_err, sec_meta = text_section(co)
    if sec is None:
        return {"verdict": "NOT_MEASURED", "object_path": co,
                "whole_file_sha256": whole_sha,
                "why": "the .text section could not be located in the object: "
                       "%s" % sec_err}
    try:
        dis = M.disassemble(M.OBJDUMP_64, co)
    except Exception as exc:                        # noqa: BLE001
        return {"verdict": "NOT_MEASURED", "object_path": co,
                "whole_file_sha256": whole_sha,
                "why": "llvm-objdump could not disassemble the object: %s: %s"
                       % (type(exc).__name__, exc)}
    if not dis.strip():
        return {"verdict": "NOT_MEASURED", "object_path": co,
                "whole_file_sha256": whole_sha,
                "why": "llvm-objdump produced no output for the object"}
    ins, symbol_base = M.parse_disassembly(dis)
    if not ins:
        return {"verdict": "NOT_MEASURED", "object_path": co,
                "whole_file_sha256": whole_sha,
                "why": "the disassembly parsed to zero instructions"}

    ctx = P.build_context(ins, symbol_base)
    rows = P.prove_all(ctx)

    #: every backward branch must be covered by a natural loop.  A backward
    #: branch with no natural loop means the CFG's loop recognition missed a
    #: loop, and a bound proved over the loops that WERE found would then say
    #: nothing about the ones that were not.
    backward = [{"at": hex(x["addr"]),
                 "insn": "%s %s" % (x["mnemonic"], x["operands"]),
                 "target": hex(ctx["branches"][x["addr"]]["A"])}
                for x in ins
                if x["addr"] in ctx["branches"]
                and ctx["branches"][x["addr"]]["A"] is not None
                and ctx["branches"][x["addr"]]["A"] <= x["addr"]]
    back_edge_latches = {r["latch_pc"] for r in rows}
    uncovered = [b for b in backward if b["at"] not in back_edge_latches]

    # ---- the retired classifier, run on the same bytes -------------------
    old_rows, old_meta, old_err = OLD.run_old_classifier(ins, symbol_base)
    cross = []
    if old_rows is not None:
        old_by_latch = {L["latch_pc"]: L for L in old_rows}
        for r in rows:
            o = old_by_latch.get(r["latch_pc"], {})
            ot = o.get("termination") if isinstance(o.get("termination"),
                                                     dict) else None
            cross.append({
                "latch_pc": r["latch_pc"], "head_pc": r["head_pc"],
                "retired_verdict": (ot or {}).get("verdict")
                if ot else o.get("termination"),
                "retired_max_trip_count": (ot or {}).get("max_trip_count"),
                "prover_verdict": r["verdict"],
                "prover_max_trip_count": r.get("max_trip_count"),
                "agree": (ot is not None
                          and ot.get("verdict")
                          == "COUNTED_LOOP_WITH_STATIC_BOUND"
                          and r["verdict"] == P.VERDICT_PROVEN
                          and ot.get("max_trip_count")
                          == r.get("max_trip_count")),
            })
    n_none_bound = len([c for c in cross
                        if c["retired_max_trip_count"] is None
                        and c["retired_verdict"]
                        == "COUNTED_LOOP_WITH_STATIC_BOUND"])
    n_proven = len([r for r in rows
                    if r["verdict"] == P.VERDICT_PROVEN])
    unproven = [r for r in rows if r["verdict"] != P.VERDICT_PROVEN]
    hist = {}
    for r in rows:
        hist[r["verdict"]] = hist.get(r["verdict"], 0) + 1

    text_ok = sec["sha256"] == TEXT_SHA256_IN_THE_BRIEF
    if unproven or uncovered or not text_ok:
        verdict = "SLOT5_BLOCKED"
    else:
        verdict = "ALL_LOOPS_PROVEN_WITH_A_FINITE_BOUND"

    return {
        "schema": "p16aw/machine-loop-recurrence-proofs/1",
        "phase": "16AW",
        "brief_sections": [71, 72, 73, 77],
        "object": {
            "path": os.path.relpath(co, ROOT).replace("\\", "/"),
            "whole_file_sha256": whole_sha,
            "text_section": {"sha256": sec["sha256"], "size": sec["size"],
                             "file_offset": sec["offset"],
                             "vma": hex(sec["addr"]),
                             "n_bytes_hashed": sec["n_bytes_hashed"],
                             "how_the_offset_was_obtained":
                                 "parsed from the object's own ELF section "
                                 "header table",
                             "second_route_to_the_section_layout":
                                 sec["second_route"],
                             "sections_parsed": sec_meta},
            "text_sha256_quoted_in_the_brief": TEXT_SHA256_IN_THE_BRIEF,
            "text_sha256_matches_the_brief": text_ok,
            "n_instructions": len(ins),
        },
        "cfg": {
            "n_blocks": len(ctx["blocks"]),
            "n_reachable_blocks": len(ctx["live"]),
            "n_branch_instructions": len(ctx["branches"]),
            "n_backward_branches": len(backward),
            "n_natural_loops": len(rows),
            "n_backward_branches_not_covered_by_a_natural_loop": len(uncovered),
            "backward_branches_not_covered": uncovered,
            "how_the_loops_were_found": "u -> v is a natural loop back edge iff "
                                        "v dominates u (Cooper-Harvey-Kennedy "
                                        "dominators, 16AT, kept per brief "
                                        "section 71)",
        },
        "prover": {
            "requirements": [{"id": k, "name": v} for k, v in P.REQUIREMENTS],
            "n_requirements": len(P.REQUIREMENTS),
            "n_requirements_from_brief_section_72": len(
                P.SECTION_72_REQUIREMENTS),
            "transitive_spin_requirement_from_brief_section": 76,
            "cap_trips": P.CAP_TRIPS,
            "fail_closed_verdict": P.VERDICT_UNKNOWN,
            "two_routes_to_the_trip_count": [
                "ROUTE SIM: bit-exact 32-bit simulation of the recurrence",
                "ROUTE FORM: an exact linear congruence for the eq/lg family, "
                "a monotone threshold for the ordered family, credited only "
                "when ROUTE SIM confirms the same index",
            ],
        },
        "verdict": verdict,
        "n_loops": len(rows),
        "n_loops_proven_with_a_finite_bound": n_proven,
        "n_loops_unproven": len(unproven),
        "verdict_histogram": hist,
        "loops": rows,
        "cross_check_against_the_retired_classifier": {
            "slice": old_meta, "error": old_err,
            "per_loop": cross,
            "n_loops_where_they_agree": len([c for c in cross if c["agree"]]),
            "n_loops_where_they_disagree": len([c for c in cross
                                                if not c["agree"]]),
            "n_loops_the_retired_classifier_called_counted_with_a_NULL_bound":
                n_none_bound,
            "why_that_matters": "the retired verdict and the retired bound can "
                                "disagree with each other, and every downstream "
                                "lane tested the verdict, so a loop with no "
                                "computed bound was carried as bounded",
        },
        "slot5_disposition": (
            "NOT BLOCKED by brief section 77: all %d machine loops carry a "
            "proved finite maximum trip count" % n_proven if
            verdict == "ALL_LOOPS_PROVEN_WITH_A_FINITE_BOUND" else
            "BLOCKED by brief section 77: %d machine loops have no proved "
            "finite bound" % len(unproven)),
        "what_remains_open": [
            "the supported recurrence form is stated in the prover's header; "
            "loops outside it are refused, and a refusal is not a proof that "
            "the loop fails to terminate",
            "the trip counts are STATIC maxima for these machine loops, not a "
            "prediction of runtime behaviour; the argument that the loops stay "
            "within their buffers is the 16AS memory-bounds work",
            "nothing here says the kernel is correct or that it was launched",
        ],
    }


def main() -> int:
    out = prove_slot5()
    with open(os.path.join(OUT, "MACHINE_LOOP_RECURRENCE_PROOFS_16AW.json"),
              "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)

    print("object            %s"
          % out.get("object", {}).get("path", out.get("object_path")))
    print("whole-file sha256 %s"
          % out.get("object", {}).get("whole_file_sha256",
                                      out.get("whole_file_sha256")))
    if out["verdict"] == "NOT_MEASURED":
        print("NOT_MEASURED      %s" % out["why"])
        return 1
    print(".text sha256      %s" % out["object"]["text_section"]["sha256"])
    print("  matches the brief's  %s"
          % out["object"]["text_sha256_matches_the_brief"])
    print("instructions      %d" % out["object"]["n_instructions"])
    print("blocks            %d (%d reachable)"
          % (out["cfg"]["n_blocks"], out["cfg"]["n_reachable_blocks"]))
    print("branches          %d (%d backward)"
          % (out["cfg"]["n_branch_instructions"], out["cfg"]["n_backward_branches"]))
    print("natural loops     %d" % out["cfg"]["n_natural_loops"])
    print("backward branches not covered by a natural loop  %d"
          % out["cfg"]["n_backward_branches_not_covered_by_a_natural_loop"])
    print("loops proven      %d of %d" % (out["n_loops_proven_with_a_finite_bound"],
                                          out["n_loops"]))
    print("verdict histogram %s" % out["verdict_histogram"])
    cc = out["cross_check_against_the_retired_classifier"]
    print("retired classifier: agree %d, disagree %d, NULL-bound-but-counted %d"
          % (cc["n_loops_where_they_agree"], cc["n_loops_where_they_disagree"],
             cc["n_loops_the_retired_classifier_called_counted_with_a_NULL_bound"]))
    print("VERDICT           %s" % out["verdict"])
    for r in out["loops"]:
        print("  head %-8s latch %-8s nodes %-3d %-38s trips=%s"
              % (r["head_pc"], r["latch_pc"], r["n_nodes"], r["verdict"],
                 r.get("max_trip_count")))
    return 0 if out["verdict"] == "ALL_LOOPS_PROVEN_WITH_A_FINITE_BOUND" else 1


if __name__ == "__main__":
    sys.exit(main())
