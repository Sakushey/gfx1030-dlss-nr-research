#!/usr/bin/env python3
"""Phase 16AM -- build REVISION_16AM_MANIFEST.json.

The before/after code in the manifest is extracted from the two files with
`ast`, not retyped.  A manifest whose "after" text is transcribed by hand is
a second copy of the code that can silently disagree with the code it
describes -- this project already carries a phase whose recorded cause did
not match the artefact.

The frozen file's identity is re-hashed here and compared against the value
recorded before any work began, so "the old revision was not replaced" is a
measurement and not a promise.

Writes only p16am/semantic/revision_16am/REVISION_16AM_MANIFEST.json.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SEM = HERE
ROOT = os.path.dirname(os.path.dirname(SEM))
OLD = os.path.join(ROOT, "phase16t", "semantic", "revision_16t", "emu.py")
NEW = os.path.join(SEM, "revision_16am", "emu.py")
OUT = os.path.join(SEM, "revision_16am", "REVISION_16AM_MANIFEST.json")

#: recorded by sha256sum BEFORE any Phase 16AM work touched anything
OLD_SHA_AT_INTAKE = \
    "fa4797b389b4c00fafeb35b2b3764334b177a7b930acef4013eeaeda40acc371"
OLD_BYTES_AT_INTAKE = 92243

ISA = "phase16r/isa/ref/rdna2_isa.txt"

#: handler -> the scalar instructions whose SCC side effect it now writes
REPAIR_TABLE = [
    ("op_s_and_b32", "s_and_b32", None, [ISA + " 5303-5304",
                                         ISA + " 1991"],
     "D = S0 & S1; SCC = (D != 0)"),
    ("op_s_or_b32", "s_or_b32", None, [ISA + " 5311-5312", ISA + " 1991"],
     "D = S0 | S1; SCC = (D != 0)"),
    ("op_s_xor_b32", "s_xor_b32", None, [ISA + " 5319-5320", ISA + " 1991"],
     "D = S0 ^ S1; SCC = (D != 0)"),
    ("op_s_and_not1_b32", "s_and_not1_b32", None,
     [ISA + " 5327-5328", ISA + " 1993"],
     "D = S0 & ~S1; SCC = (D != 0)  [ISA name S_ANDN2_B32; the module's "
     "disassembly uses the s_and_not1_b32 spelling]"),
    ("op_s_andn2_b32", "s_andn2_b32", None, [ISA + " 5327-5328"],
     "alias of op_s_and_not1_b32; repaired transitively"),
    ("_saveexec", "shared carrier", None,
     [ISA + " 6416-6418", ISA + " 6429-6431", ISA + " 6439-6441",
      ISA + " 6449-6451", ISA + " 6502-6504"],
     "SCC = (EXEC_new != 0), from the MASKED new EXEC"),
    ("op_s_and_saveexec_b32", "s_and_saveexec_b32", None, [ISA + " 6416-6418"],
     "D = EXEC_old; EXEC = S0 & EXEC; SCC = (EXEC_new != 0)"),
    ("op_s_andn2_saveexec_b32", "s_andn2_saveexec_b32", None,
     [ISA + " 6449-6451"],
     "D = EXEC_old; EXEC = S0 & ~EXEC; SCC = (EXEC_new != 0)"),
    ("op_s_or_saveexec_b32", "s_or_saveexec_b32", None,
     [ISA + " 6429-6431"],
     "D = EXEC_old; EXEC = S0 | EXEC; SCC = (EXEC_new != 0)"),
    ("op_s_xor_saveexec_b32", "s_xor_saveexec_b32", None,
     [ISA + " 6439-6441"],
     "D = EXEC_old; EXEC = S0 ^ EXEC; SCC = (EXEC_new != 0)"),
    ("op_s_and_not1_saveexec_b32", "s_and_not1_saveexec_b32", None,
     [ISA + " 6502-6504"],
     "D = EXEC_old; EXEC = ~S0 & EXEC; SCC = (EXEC_new != 0)  [ISA name "
     "S_ANDN1_SAVEEXEC_B32]"),
    ("op_s_add_i32", "s_add_i32", None, [ISA + " 5252-5254", ISA + " 1902"],
     "D.i = S0.i + S1.i; SCC = signed overflow"),
    ("op_s_sub_i32", "s_sub_i32", None, [ISA + " 5261-5263", ISA + " 1904"],
     "D.i = S0.i - S1.i; SCC = signed overflow"),
    ("op_s_lshl_b32", "s_lshl_b32", None, [ISA + " 5373-5374",
                                           ISA + " 1997"],
     "D.u = S0.u << S1.u[4:0]; SCC = (D.u != 0)"),
    ("op_s_lshr_b32", "s_lshr_b32", None, [ISA + " 5381-5382",
                                           ISA + " 1999"],
     "D.u = S0.u >> S1.u[4:0]; SCC = (D.u != 0)"),
    ("op_s_ashr_i32", "s_ashr_i32", None, [ISA + " 5389-5390",
                                           ISA + " 2001"],
     "D.i = signext(S0.i) >> S1.u[4:0]; SCC = (D.i != 0)"),
    ("op_s_lshl_b64", "s_lshl_b64", None, [ISA + " 5377-5378",
                                           ISA + " 1997"],
     "D.u64 = S0.u64 << S1.u[5:0]; SCC = (D.u64 != 0)"),
    ("op_s_bfe_u32", "s_bfe_u32", None, [ISA + " 5414-5415"],
     "D.u = (S0.u >> off) & ((1<<width)-1); SCC = (D.u != 0)"),
    ("op_s_bfe_i32", "s_bfe_i32", None, [ISA + " 5420-5421"],
     "D.i = signext(...); SCC = (D.i != 0)"),
    ("op_s_min_i32", "s_min_i32", None, [ISA + " 5275-5276", ISA + " 1916"],
     "D.i = (S0.i < S1.i) ? S0.i : S1.i; SCC = (S0.i < S1.i)"),
    ("op_s_abs_i32", "s_abs_i32", None, [ISA + " 1925"],
     "D.i = abs(S0.i); SCC = (result not zero)"),
]

#: scalar instructions the ISA says write SCC with NO handler in either
#: revision -- so there is no silent omission to repair, only an explicit
#: NotImpl.  (Measured: getattr(Core, name) is None.)
NOT_IMPLEMENTED = [
    ("op_s_sub_u32", ISA + " 5244-5245", "D = S0 - S1; SCC = carry-out"),
    ("op_s_subb_u32", ISA + " 5271-5272",
     "D = S0 - S1 - SCC; SCC = (S1.u + SCC > S0.u)"),
    ("op_s_min_u32", ISA + " 5279-5280", "SCC = (S0.u < S1.u)"),
    ("op_s_max_i32", ISA + " 5283-", "SCC = (S0.i > S1.i)"),
    ("op_s_max_u32", ISA + " 5285-", "SCC = (S0.u > S1.u)"),
    ("op_s_orn2_b32", ISA + " 5335-5336", "D = S0 | ~S1; SCC = (D != 0)"),
    ("op_s_nand_b32", ISA + " 5349-5350", "D = ~(S0 & S1); SCC = (D != 0)"),
    ("op_s_nor_b32", ISA + " 5357-5358", "D = ~(S0 | S1); SCC = (D != 0)"),
    ("op_s_xnor_b32", ISA + " 5365-5366", "D = ~(S0 ^ S1); SCC = (D != 0)"),
    ("op_s_lshr_b64", ISA + " 5385-5386", "SCC = (D.u64 != 0)"),
    ("op_s_ashr_i64", ISA + " 5393-5394", "SCC = (D.i64 != 0)"),
    ("op_s_bfm_b32", ISA + " 5397", "no SCC (ISA gives no SCC for BFM)"),
    ("op_s_not_b32", ISA + " 2013", "D = ~S0; SCC = (D != 0)"),
    ("op_s_andn1_b32", ISA + " 6498-6504",
     "D = ~S0 & S1; SCC = (D != 0)  [plain, non-SAVEEXEC form]"),
    ("op_s_orn1_b32", ISA + " 6506-6514", "D = ~S0 | S1; SCC = (D != 0)"),
    ("op_s_andn2_wrexec_b32", ISA + " 6530-", "SCC = (EXEC_LO != 0)"),
    ("op_s_andn1_wrexec_b32", ISA + " 6516-", "SCC = (EXEC_LO != 0)"),
]

#: scalar handlers examined, ISA says they do NOT write SCC -> no repair due
NOT_A_SCC_WRITER = [
    ("op_s_mov_b32", ISA + " 1987", "S_MOV_{B32,B64}  Sets SCC? n"),
    ("op_s_mov_b64", ISA + " 1987", "S_MOV_{B32,B64}  Sets SCC? n"),
    ("op_s_movk_i32", ISA + " 1989", "S_MOVK_I32  Sets SCC? n"),
    ("op_s_cselect_b32", ISA + " 1939-1941",
     "S_CSELECT_{B32,B64}  Sets SCC? n  (it READS SCC)"),
    ("op_s_mul_i32", ISA + " 1920", "S_MUL_I32  Sets SCC? n"),
    ("op_s_mul_hi_u32", ISA + " 5499-5501", "no SCC given for S_MUL_HI_U32"),
    ("op_s_mul_hi_i32", ISA + " 5503-5505", "no SCC given for S_MUL_HI_I32"),
    ("op_s_sext_i32_i8", ISA + " 1928", "S_SEXT_I32_I8  Sets SCC? n"),
    ("op_s_sext_i32_i16", ISA + " 1926-1928", "S_SEXT_I32_I16  Sets SCC? n"),
    ("op_s_addc_u32", ISA + " 5266-5267",
     "ALREADY CONFORMANT: it already writes SCC = carry-out of the full "
     "S0 + S1 + carry_in sum, so there is no omission to repair"),
    ("op_s_cmp_eq_u32", ISA + " 1970-1974", "SOPC compare, Sets SCC? y; "
     "the handler already writes it"),
    ("op_s_cmp_lg_u32", ISA + " 1970-1974", "already writes SCC"),
    ("op_s_cmp_ge_u32", ISA + " 1970-1974", "already writes SCC"),
    ("op_s_cmp_lt_u32", ISA + " 1970-1974", "already writes SCC"),
    ("op_s_cmp_gt_i32", ISA + " 1970-1974", "already writes SCC"),
    ("op_s_cmp_ge_i32", ISA + " 1970-1974", "already writes SCC"),
    ("op_s_add_u32", ISA + " 5239-5240", "already writes SCC = carry-out"),
    ("op_s_branch", ISA + " n/a", "control flow; writes no SCC"),
    ("op_s_cbranch_scc0", ISA + " 1970-1974",
     "READS SCC to decide; writes none"),
    ("op_s_cbranch_scc1", ISA + " 1970-1974", "READS SCC; writes none"),
    ("op_s_cbranch_vccz", ISA + " n/a", "READS VCC; writes no SCC"),
    ("op_s_cbranch_vccnz", ISA + " n/a", "READS VCC; writes no SCC"),
    ("op_s_cbranch_execz", ISA + " n/a", "READS EXEC; writes no SCC"),
    ("op_s_cbranch_execnz", ISA + " n/a", "READS EXEC; writes no SCC"),
    ("op_s_endpgm", ISA + " n/a", "halts the wave; writes no SCC"),
    ("op_s_load_b32", ISA + " n/a", "scalar load; the ISA gives it no SCC"),
    ("op_s_load_b64", ISA + " n/a", "scalar load; no SCC"),
    ("op_s_load_b128", ISA + " n/a", "scalar load; no SCC"),
]

#: handlers whose OWN body is byte-identical but which are repaired through a
#: changed callee -- listed so the completeness count can be closed
TRANSITIVELY_REPAIRED = [
    "op_s_andn2_b32",                 # -> op_s_and_not1_b32
    "op_s_and_saveexec_b32",          # -> _saveexec
    "op_s_andn2_saveexec_b32",        # -> _saveexec
    "op_s_or_saveexec_b32",           # -> _saveexec
    "op_s_xor_saveexec_b32",          # -> _saveexec
    "op_s_and_not1_saveexec_b32",     # -> _saveexec
]

#: defects FOUND but deliberately not repaired, with the reason
NOT_REPAIRED = [
    {
        "id": "bfe_operand_encoding_divergence",
        "handlers": ["op_s_bfe_u32", "op_s_bfe_i32"],
        "defect": "the handler decodes `ops[2]` as the field offset and "
                  "`ops[3]` as the field width -- a four-operand form.  The "
                  "ISA packs both into ONE source operand (S1[4:0] = offset, "
                  "S1[22:16] = width, " + ISA + " lines 5411-5412 and "
                  "5417-5418), and this project's own disassembly uses that "
                  "packed three-operand form "
                  "(`s_bfe_i32 s18, s17, 0x80000`, phase14d9_static/out/"
                  "entryfixed_gfx1030_disasm.txt line 2921, i.e. width 8 at "
                  "offset 0).",
        "measured_consequence": "on a three-operand site the handler reads "
                                "`ops[3]` and raises IndexError -- a loud "
                                "failure, not a silently wrong value",
        "why_not_repaired": "it is an operand-DECODE defect, not an SCC "
                            "side-effect defect.  Repairing it changes which "
                            "value D takes, which is outside this brief's "
                            "scope and would invalidate the truth vectors "
                            "that were derived for the SCC question.  The "
                            "SCC side effect was repaired; the decode was "
                            "left exactly as it was and is recorded here.",
        "reported_upstream": True,
    },
    {
        "id": "s_addc_u32_examined_no_omission",
        "handlers": ["op_s_addc_u32"],
        "defect": "none found",
        "measured": "the frozen handler already computes "
                    "SCC = (S0 + S1 + carry_in >= 2**32), and its 8 truth "
                    "vectors (carry-in 0 and 1, including 0xffffffff + 0 + "
                    "carry_in = 1 -> carry-out 1) all pass on BOTH revisions",
        "why_not_repaired": "there is nothing to repair; recording a repair "
                            "here would be inventing a defect",
    },
    {
        "id": "s_subb_u32_examined_no_handler",
        "handlers": ["op_s_subb_u32"],
        "defect": "none found",
        "measured": "no handler exists in either revision, so a site would "
                    "raise NotImpl -- an explicit failure, not an omitted "
                    "side effect",
        "why_not_repaired": "the ISA text for it IS available locally (" +
                            ISA + " lines 5271-5272) and could be used to "
                            "add a handler, but adding an unimplemented "
                            "instruction is a new feature, not a repair of "
                            "an omission, and it is outside this brief",
    },
]


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def defs(path):
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            out.setdefault(node.name, ast.get_source_segment(src, node))
    return out


def main():
    old_src = open(OLD, encoding="utf-8").read()
    new_src = open(NEW, encoding="utf-8").read()
    o, n = defs(OLD), defs(NEW)

    repaired = []
    for name, instr, _unused, cites, rule in REPAIR_TABLE:
        before = o.get(name)
        after = n.get(name)
        if before is None or after is None:
            raise SystemExit("manifest: %s missing from one revision" % name)
        repaired.append({
            "handler": name,
            "instruction": instr,
            "isa_citations": cites,
            "isa_rule": rule,
            "code_changed": before != after,
            "before": before,
            "after": after,
        })

    changed_names = sorted(k for k in set(o) & set(n) if o[k] != n[k])
    declared = sorted(r["handler"] for r in repaired if r["code_changed"])
    only_new = sorted(set(n) - set(o))
    if changed_names != declared:
        raise SystemExit(
            "manifest disagreees with the files: changed=%s declared=%s"
            % (changed_names, declared))
    if only_new != ["_scc_of"]:
        raise SystemExit("unexpected new definitions: %s" % only_new)

    # the sibling modules carried into revision_16am must be byte-identical
    # to the frozen ones -- MEASURED, because "identical by construction" is
    # how a drifted copy gets into a revision tree unnoticed
    sib_names = ["p16j_input.py", "p14d8_core.py", "p14e_emu.py", "p14eh.py",
                 "p16e_rec.py", "p16h_scratch_probe.py",
                 "p16j_scratch_isa.py"]
    siblings = {}
    for s in sib_names:
        fp = os.path.join(ROOT, "phase16t", "semantic", "revision_16t", s)
        np_ = os.path.join(SEM, "revision_16am", s)
        fh_, nh_ = sha256_file(fp), sha256_file(np_)
        siblings[s] = {"frozen_sha256": fh_, "revision_16am_sha256": nh_,
                       "identical": fh_ == nh_}
    sib_ok = all(v["identical"] for v in siblings.values())

    old_sha = sha256_file(OLD)
    new_sha = sha256_file(NEW)
    old_bytes = os.path.getsize(OLD)
    new_bytes = os.path.getsize(NEW)

    if old_sha != OLD_SHA_AT_INTAKE or old_bytes != OLD_BYTES_AT_INTAKE:
        raise SystemExit(
            "REFUSING: the frozen revision has changed since intake "
            "(%s/%d, intake %s/%d)"
            % (old_sha, old_bytes, OLD_SHA_AT_INTAKE, OLD_BYTES_AT_INTAKE))

    # every claimed-not-implemented handler must really be absent
    sys.path.insert(0, SEM)
    import importlib.util
    spec = importlib.util.spec_from_loader("emu_frozen_manifest", loader=None)
    fm = importlib.util.module_from_spec(spec)
    exec(compile(old_src, OLD, "exec"), fm.__dict__)
    spec2 = importlib.util.spec_from_loader("emu_new_manifest", loader=None)
    nm = importlib.util.module_from_spec(spec2)
    exec(compile(new_src, NEW, "exec"), nm.__dict__)
    absent = {}
    for name, _c, _r in NOT_IMPLEMENTED:
        absent[name] = {"frozen_has_handler": hasattr(fm.Core, name),
                        "repaired_has_handler": hasattr(nm.Core, name)}
    bad = [k for k, v in absent.items()
           if v["frozen_has_handler"] or v["repaired_has_handler"]]
    if bad:
        raise SystemExit("these handlers DO exist, so 'not implemented' is "
                         "false for them: %s" % bad)

    scalar_handlers = sorted(k for k in set(o) | set(n)
                             if k.startswith("op_s_"))
    accounted = set(declared) | {x[0] for x in NOT_IMPLEMENTED} \
        | {x[0] for x in NOT_A_SCC_WRITER} | set(only_new) \
        | set(TRANSITIVELY_REPAIRED)
    unaccounted = [k for k in scalar_handlers if k not in accounted]

    doc = {
        "schema": "p16am-revision-manifest/1",
        "phase": "16AM",
        "host_only": True,
        "gpu_execution_performed": False,
        "hip_calls_made": 0,
        "built_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "old_revision": {
            "path": "phase16t/semantic/revision_16t/emu.py",
            "sha256": old_sha,
            "bytes": old_bytes,
            "lines": old_src.count("\n") + 1,
            "sha256_recorded_at_intake": OLD_SHA_AT_INTAKE,
            "bytes_recorded_at_intake": OLD_BYTES_AT_INTAKE,
            "unchanged_since_intake": (old_sha == OLD_SHA_AT_INTAKE
                                       and old_bytes == OLD_BYTES_AT_INTAKE),
            "mtime_utc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(OLD))),
        },
        "new_revision": {
            "path": "p16am/semantic/revision_16am/emu.py",
            "sha256": new_sha,
            "bytes": new_bytes,
            "lines": new_src.count("\n") + 1,
        },
        "preservation_statement": {
            "statement": "The frozen revision phase16t/semantic/"
                         "revision_16t/emu.py is PRESERVED AS HISTORICAL "
                         "EVIDENCE.  It was NOT replaced, NOT renamed, NOT "
                         "moved and NOT edited by Phase 16AM.  The repaired "
                         "revision is a separate file in a separate "
                         "directory, and every downstream artefact that named "
                         "the frozen revision still names it.",
            "how_this_is_measured_not_promised": [
                "the frozen file's sha256 is re-read at manifest build time "
                "and compared with the value recorded before any Phase 16AM "
                "work began: %s" % OLD_SHA_AT_INTAKE,
                "the byte count is re-read and compared: %d" % OLD_BYTES_AT_INTAKE,
                "the comparison is a hard refusal in this builder, so the "
                "manifest cannot be produced at all after such a change",
            ],
            "nothing_outside_p16am/semantic_was_written": True,
        },
        "new_definitions": [{
            "handler": "_scc_of",
            "why": "the single place that turns a destination value into SCC, "
                   "so every repaired handler reads one rule instead of "
                   "repeating it",
            "isa_citations": [ISA + " line 1891"],
            "isa_rule": "SCC = (result != 0)",
            "before": None,
            "after": n["_scc_of"],
        }],
        "repair_summary": {
            "handlers_with_changed_code": len(declared),
            "new_helper": "_scc_of",
            "repair_entries_including_the_shared_carrier": len(repaired),
            "scalar_instructions_now_writing_scc": [
                r["instruction"] for r in repaired
                if r["instruction"] != "shared carrier"],
            "instruction_count": sum(1 for r in repaired
                                     if r["instruction"] != "shared carrier"),
            "handlers_repaired_through_a_changed_callee": [
                "op_s_andn2_b32 -> op_s_and_not1_b32",
                "op_s_and_saveexec_b32 -> _saveexec",
                "op_s_andn2_saveexec_b32 -> _saveexec",
                "op_s_or_saveexec_b32 -> _saveexec",
                "op_s_xor_saveexec_b32 -> _saveexec",
                "op_s_and_not1_saveexec_b32 -> _saveexec",
            ],
            "other_files_in_revision_16am": {
                "why": "p4_lib.boot() loads a whole module tree from one "
                       "directory, so the J3 regression can only import the "
                       "repaired emulator if its siblings are present.  These "
                       "are byte-identical copies, so the regression loads "
                       "the repair from the SOURCE rather than through a "
                       "monkeypatch -- a monkeypatch on a shadowed method is "
                       "a silent no-op, which this project has already lost a "
                       "phase to",
                "modules": siblings,
                "all_identical_to_the_frozen_tree": sib_ok,
            },
        },
        "repaired_handlers": repaired,
        "instructions_repaired": [r["instruction"] for r in repaired],
        "not_implemented_scc_writers": {
            "note": "the ISA says these write SCC; NEITHER revision has a "
                    "handler for them, so a site raises NotImpl rather than "
                    "omitting a side effect.  Verified absent by "
                    "hasattr(Core, name).",
            "entries": [{"handler": k, "isa": c, "isa_rule": r,
                         "frozen_has_handler": absent[k]["frozen_has_handler"],
                         "repaired_has_handler":
                             absent[k]["repaired_has_handler"]}
                        for k, c, r in NOT_IMPLEMENTED],
        },
        "examined_no_repair_due": {
            "note": "scalar handlers examined and deliberately left alone, "
                    "with the ISA line that justifies leaving them alone",
            "entries": [{"handler": k, "isa": c, "reason": r}
                        for k, c, r in NOT_A_SCC_WRITER],
        },
        "not_repaired": NOT_REPAIRED,
        "audit_completeness": {
            "scalar_handlers_in_either_revision": len(scalar_handlers),
            "accounted_for": len(scalar_handlers) - len(unaccounted),
            "unaccounted": unaccounted,
            "method": "every `op_s_*` definition in either revision is "
                      "classified into exactly one of: repaired, "
                      "not-implemented, examined-no-repair-due",
        },
        "isa_text": {
            "path": ISA,
            "sha256": sha256_file(os.path.join(ROOT, ISA)),
            "citation_caveat": "the section 12.1 SOP2 opcode table is "
                               "OCR-interleaved (Description column runs four "
                               "opcodes behind the Opcode/Name column).  The "
                               "pairing used here was fixed by the "
                               "per-instruction caption lines and is "
                               "corroborated by Table 11 (line 1898) and "
                               "Table 14 (line 1982).",
        },
        "verification_entry_points": [
            "python p16am/semantic/p16am_build_truth_vectors.py",
            "python p16am/semantic/p16am_semantic_conformance.py",
            "python p16am/semantic/p16am_j3_regression.py",
        ],
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    print(json.dumps({
        "old_sha256": old_sha, "new_sha256": new_sha,
        "old_bytes": old_bytes, "new_bytes": new_bytes,
        "handlers_changed": len(declared),
        "instructions_repaired": len(repaired),
        "scalar_handlers_accounted": "%d/%d" % (
            len(scalar_handlers) - len(unaccounted), len(scalar_handlers)),
        "unaccounted": unaccounted,
        "frozen_unchanged_since_intake": doc["old_revision"][
            "unchanged_since_intake"],
        "out": OUT,
    }, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
