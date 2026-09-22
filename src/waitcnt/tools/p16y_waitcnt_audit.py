#!/usr/bin/env python3
"""Phase 16Y / WAITCNT / PART III -- executed-path waitcnt ordering audit.

HOST ONLY.  No GPU, no HIP import, no ROCm runtime, no kernel launch, no
harness executable, no device, no clock/voltage/driver/registry change.  The
only external tool invoked is ROCm 6.4's OFFLINE `llvm-objdump.exe`, on a
scratch COPY of the Candidate F code object.  `llvm-objcopy` is never used.

WHAT THIS IS
    A semantic ORDERING check over the ACTUAL DYNAMIC PATH.  Input is
    `phase16y/waitcnt/out/j3_executed_pcs.json`
    (schema phase16y-waitcnt-executed-pcs/1), whose
    `executed_prog_index_by_wave` is the exact instruction order each of the 8
    waves retired.

WHY IT IS NEEDED
    `revision_16t/emu.py` binds `op_s_waitcnt` and `op_s_waitcnt_depctr` to
    `_noop` and executes every memory op synchronously.  A clean emulated run
    therefore CANNOT be evidence that Candidate F's waits are correct: the
    emulator's `natural_end` and its fault lists say nothing about ordering.

RAW ENCODINGS ARE MEASURED, NOT INFERRED
    `instruction_table` carries no raw word.  Words used here come from a
    fresh `llvm-objdump -d --mcpu=gfx1030` of a scratch COPY of
    `phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co`.  The copy's sha256 is
    asserted equal to the J3 run's `candidate_sha256`, the source is re-hashed
    after the dump, and every one of the 17478 instructions is asserted to sit
    at the same address and disassemble to the same text.

Usage:
    python phase16y/waitcnt/tools/p16y_waitcnt_audit.py
"""
from __future__ import annotations

import collections
import hashlib
import itertools
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WC = os.path.dirname(HERE)                       # phase16y/waitcnt
ROOT = os.path.dirname(os.path.dirname(WC))      # ...<PROJECT_ROOT>
SCRATCH = os.path.join(WC, "part3_scratch")
OUT_JSON = os.path.join(WC, "PART_III_WAITCNT_AUDIT_16Y.json")
OUT_MD = os.path.join(WC, "PART_III_REPORT_16Y.md")

EXEC_PCS = os.path.join(WC, "out", "j3_executed_pcs.json")
PROBE = os.path.join(WC, "probe", "probe_results.json")
CO = os.path.join(ROOT, "phase16h_candidate_f",
                  "gfx1030_dlssnr_candidate_f.co")
CO_SHA = "47b5d1d11041b034ac30eebac090ee922f415d8f08a0111e69641d7e0557524b"
LLVM_OBJDUMP = r"<ROCM_ROOT>\6.4\bin\llvm-objdump.exe"
LLVM_MC = r"<ROCM_ROOT>\6.4\bin\llvm-mc.exe"
ARCH = "gfx1030"
SYM_PREFIX = "00000000000ab500 <_Z10k_swin_varILi32ELb0EEv9VarParams>"


#: Previous revisions of this audit's headline numbers, kept visible rather
#: than overwritten.  rev 1 = the first 16Y Part III delivery; rev 2 = this.
HISTORY = {
    "rev1": {
        "date": "2026-09-20",
        "classifier": "VALU format decided from raw encoding bits "
                      "(bits[31:26]==0x35 VOP3, ==0x33 VOP3P, bits[31:25] "
                      "0x3F VOP1/VOPC, 0x3E VOPC, <=0x3D VOP2)",
        "decoder_entries_compared": 49, "decoder_field_comparisons": 132,
        "decoder_mismatches": 0,
        "distinct_executed_waits": 1277,
        "producers_total": 20608,
        "hazards_total": 0,
        "unclassified_dynamic_executions": 784,
        "unclassified_by_reason": {
            "VOP2 e32 with 4 operands -- an implicit src0 would have to be "
            "modelled": 784},
        "tracer_crosscheck": "MATCH, 477 = 477, symmetric difference 0",
        "negative_controls": "5 fired incl. the vacuous-input control",
        "verdict": "PASS"},
    "rev2_change": (
        "The rev-1 reason string 'VOP2 e32 with 4 operands -- an implicit src0 "
        "would have to be modelled' was a GUESS written into the code, not a "
        "measurement.  Measured this revision: the implicit-src0 form does not "
        "occur (0 of 17478 instructions print a single operand; 0 of the "
        "two-operand forms have dst == src0).  The 784 executions were "
        "4-operand ordinary dst+3-source VALU forms, and the blind spot was "
        "closed by modelling operand roles from the mnemonic plus an llvm-mc "
        "probe of the op1 field instead of from raw encoding bits.  A REAL "
        "defect of the same family was found and fixed in the same pass: "
        "`v_cmpx_*_e32` prints its two SOURCES and no destination, and rev 1 "
        "read op0 as a destination and dropped it as a use."),
    "rev3_change": (
        "The rev-1/rev-2 concern that the flagged 4-operand forms were "
        "invisible CONSUMERS is REFUTED by measurement, and the control meant "
        "to demonstrate that gap was repaired and re-scoped.  Measured over "
        "all 17478 static instructions: the pre-fix classifier flagged 240 "
        "unclassifiable, of which 133 (including EVERY one of the 98 "
        "dynamically executed instances / 784 executions) still carried "
        "defs=op0 and uses=op[1:] -- the exact sets the fixed model computes "
        "for them -- so no consumer edge was hidden and the hazard count could "
        "not change (0 before, 0 after).  The remaining 107 were the genuine "
        "pre-fix blind class (empty defs AND empty uses), and 0 of those are "
        "dynamically executed, so 0 of them touch the audited path.  Control "
        "(g) was INVALID as built in rev 2: it took the first "
        "`v_cndmask_b32_e32` in address order, which reads a different "
        "register, so it reported 0/0 and could not fire.  Selection is now "
        "by PREDICATE (the consumer must read a register the producer "
        "defines); (g) now reports HAZARD BEFORE and AFTER -- i.e. the worker "
        "reports plainly that the hazard is CAUGHT BEFORE THE FIX and the "
        "coordinator's premise about the gap is wrong for this class.  A new "
        "control (g2) uses one of the 107 genuinely-blind instructions as the "
        "consumer and does report MISSED before / HAZARD after, which is the "
        "real pre-fix gap, alongside the (h) `v_cmpx` defect control."),
}


# ============================================================== STEP 1 ======

def decode_waitcnt(word: int) -> dict:
    """The layout the brief asks to VERIFY (bit positions per GFX10/RDNA2
    S_WAITCNT).  Fitted against every probe in probe_results.json, see
    step1_decoder()."""
    return {"vmcnt": (((word >> 14) & 0x3) << 4) | (word & 0xF),
            "expcnt": (word >> 4) & 0x7,
            "lgkmcnt": (word >> 8) & 0x3F,
            "bit7": (word >> 7) & 0x1}


def decode_waitcnt_naive(word: int) -> dict:
    """Deliberately WRONG layout; the decoder's negative control only."""
    return {"vmcnt": word & 0x3F, "expcnt": (word >> 4) & 0x7,
            "lgkmcnt": (word >> 8) & 0x3F, "bit7": (word >> 7) & 0x1}


def step1_decoder() -> dict:
    probes = json.load(open(PROBE, encoding="utf-8"))
    rows, fails = [], []
    n_wait = n_dep = n_field_cmp = 0
    for k in sorted(probes):
        e = probes[k]
        w = int(e["word"], 16)
        want = e["operands"]
        if "depctr" in want:
            n_dep += 1
            got = w & 0xFFF
            ok = (w >> 16) == 0xBFA3 and got == want["depctr"]
            rows.append({"key": k, "kind": "s_waitcnt_depctr",
                         "word": e["word"], "line": e["line"],
                         "decoded": {"depctr": got, "opcode_hi16": "0xBFA3"},
                         "expected": {"depctr": want["depctr"]}, "ok": ok})
        else:
            n_wait += 1
            n_field_cmp += 3
            got = decode_waitcnt(w)
            dec = {f: got[f] for f in ("vmcnt", "lgkmcnt", "expcnt")}
            exp = {f: want[f] for f in ("vmcnt", "lgkmcnt", "expcnt")}
            ok = dec == exp and (w >> 16) == 0xBF8C
            rows.append({"key": k, "kind": "s_waitcnt", "word": e["word"],
                         "line": e["line"], "decoded": dec, "expected": exp,
                         "bit7": got["bit7"], "ok": ok})
        if not rows[-1]["ok"]:
            fails.append(rows[-1])
    na = sum(1 for k, e in probes.items() if "depctr" not in e["operands"]
             and decode_waitcnt_naive(int(e["word"], 16))
             != {f: e["operands"][f] for f in ("vmcnt", "lgkmcnt", "expcnt")})
    return {
        "entries_compared": len(probes),
        "s_waitcnt_entries": n_wait,
        "s_waitcnt_field_comparisons": n_field_cmp,
        "s_waitcnt_depctr_entries": n_dep,
        "mismatches": len(fails),
        "failed_entries": fails,
        "bit7_set_on_any_entry": sum(1 for r in rows if r.get("bit7")),
        "opcode_hi16_asserted": {"s_waitcnt": "0xBF8C",
                                 "s_waitcnt_depctr": "0xBFA3"},
        "per_entry": rows,
        "negative_control": {
            "mutation": "decode vmcnt as one contiguous 6-bit field at bits[5:0]",
            "mismatching_entries": na, "of_entries": n_wait,
            "verdict": "decoder rejects a wrong layout" if na else
                       "VACUOUS -- a wrong layout passed"},
        "measured_vs_inferred": (
            "MEASURED: every field position, because the fit predicts all %d "
            "probe words and the wrong-layout control fails on %d of %d.  "
            "INFERRED: nothing in this decoder." % (len(probes), na, n_wait)),
    }


# ==================================================== raw word provenance ==

def valu_form_inventory(table, paths) -> dict:
    """Measure, from the ACTUAL instruction texts, which operand forms the
    kernel really contains.  This is the measurement that decides whether a
    'destination with an implicit src0' form exists at all."""
    per = collections.defaultdict(collections.Counter)
    ex = collections.defaultdict(dict)
    n_exec = collections.Counter()
    counts = {w: collections.Counter(paths[w]) for w in paths}
    for t in table:
        m = t["mnem"] or ""
        if not m.startswith("v_"):
            continue
        n = len(split_ops(t["ops"]))
        per[m][n] += 1
        ex[m].setdefault(n, {"pc": "0x%X" % t["addr"], "text": t["text"],
                             "raw_word": "0x%08X" % t["w0"]})
    for w in counts:
        for gi, k in counts[w].items():
            m = table[gi]["mnem"] or ""
            if m.startswith("v_"):
                n_exec[(m, len(split_ops(table[gi]["ops"])))] += k
    one = {m: dict(c) for m, c in per.items() if 1 in c}
    two = {}
    for m, c in sorted(per.items()):
        if 2 not in c:
            continue
        a = split_ops(ex[m][2]["text"].split(None, 1)[1])
        dst_eq_src0 = bool(a) and len(a) > 1 and a[0] == a[1]
        two[m] = {"static_count": c[2], "example": ex[m][2]["text"],
                  "dst_equals_src0": dst_eq_src0}
    cmpx = [m for m in two if m.startswith("v_cmpx")]
    return {
        "valu_mnemonics": len(per),
        "operand_count_forms": [
            {"mnemonic": m, "operand_counts": dict(per[m]),
             "example": ex[m][min(per[m])]["text"],
             "example_pc": ex[m][min(per[m])]["pc"],
             "raw_word": ex[m][min(per[m])]["raw_word"]}
            for m in sorted(per)],
        "valu_with_one_printed_operand": {"mnemonics": len(one), "detail": one,
                                          "executions": 0},
        "valu_with_two_printed_operands": {
            "mnemonics": len(two),
            "vopc_cmpx_e32_src0_src1_with_implicit_exec_dst": cmpx,
            "unary_dst_src0": [m for m in two if m not in cmpx],
            "any_two_operand_form_with_dst_equals_src0":
                [m for m in two if two[m]["dst_equals_src0"]],
            "detail": two},
        "conclusion": (
            "MEASURED over all %d static instructions: the printed operand "
            "count is CONSTANT per mnemonic, and NO VALU instruction prints a "
            "single operand.  The hypothesised 'VOP2 e32 with a dst and one "
            "explicit source whose implicit src0 is the destination' form "
            "does not occur (%d mnemonics with 1 operand, %d two-operand "
            "forms whose dst equals its src0).  The 2-operand forms are %d "
            "unary VOP1-style (dst, src0) and %d `v_cmpx_*` VOPC forms whose "
            "two printed operands are BOTH sources -- the VOPC destination is "
            "the EXEC mask, which is not printed (ISA: 'All V_CMPX "
            "instructions write the result of their comparison ... to the "
            "EXEC mask').  The 4-operand forms are ordinary dst+3-source "
            "VALU forms, not a 2-source form with an implicit source."
            % (len(table), len(one),
               sum(1 for m in two if two[m]["dst_equals_src0"]),
               len(two) - len(cmpx), len(cmpx))),
        "executions_by_form": {"%s/%d_op" % k: v
                               for k, v in sorted(n_exec.items())}}


def op1_role_probe(table) -> dict:
    """Decide, by MEASUREMENT on this kernel, whether op1 of each >=4-operand
    VALU mnemonic is a DEF (a VOP3B scalar destination) or a USE (src0).

    Rule: a VGPR can never occupy an SDST slot, so rewrite op1 to `v1` and ask
    llvm-mc.  Rejected  => op1 sits in the SDST field (a DEF).
    Accepted         => op1 is a source (a USE).
    The prediction from the ISA carry-out family is compared against the
    measurement, so the probe can disagree and be caught disagreeing."""
    seen = {}
    os.makedirs(SCRATCH, exist_ok=True)
    for t in table:
        m = t["mnem"] or ""
        if not m.startswith("v_"):
            continue
        o = split_ops(t["ops"])
        if len(o) < 4 or m in seen:
            continue
        seen[m] = t
    rows, n_cmp, n_dis = [], 0, 0
    tmp = os.path.join(SCRATCH, "op1probe.s")
    for m in sorted(seen):
        t = seen[m]
        o = split_ops(t["ops"])
        o[1] = "v1"
        text = m + " " + ", ".join(o)
        try:
            open(tmp, "w", encoding="utf-8").write(text + "\n")
            r = subprocess.run([LLVM_MC, "-triple=amdgcn", "-mcpu=%s" % ARCH,
                                "-show-encoding", tmp],
                               capture_output=True, text=True)
            accepted = r.returncode == 0 and "encoding" in r.stdout
        except Exception:                                   # noqa: BLE001
            accepted = None
        measured = "source" if accepted else "sdst"
        predicted = "sdst" if m in ISA_SDST else "source"
        n_cmp += 1
        agree = measured == predicted
        if not agree:
            n_dis += 1
        rows.append({"mnemonic": m, "operand_count": len(t["ops"].split(",")),
                     "original_op1": t["ops"].split(",")[1].strip(),
                     "original_text": t["text"],
                     "probe_text": text, "probe_accepted": accepted,
                     "measured_role_of_op1": measured,
                     "isa_family_prediction": predicted,
                     "agrees": agree})
    measured_sdst = {r["mnemonic"] for r in rows
                     if r["measured_role_of_op1"] == "sdst"}
    no_instance = {m for m in ISA_SDST if m not in seen}
    VALU_SDST.clear()
    VALU_SDST.update(measured_sdst | no_instance)
    return {
        "rule": "op1 rewritten to `v1`; llvm-mc rejection => op1 is an SDST "
                "(a VGPR can never be an SDST); acceptance => op1 is a source",
        "mnemonics_probed": len(rows), "comparisons_performed": n_cmp,
        "disagreements_with_the_isa_family": n_dis,
        "measured_sdst_mnemonics": sorted(measured_sdst),
        "isa_sdst_mnemonics_with_no_>=4_operand_instance": sorted(no_instance),
        "effective_VALU_SDST_used_by_the_classifier": sorted(VALU_SDST),
        "inconclusive_probes": [r["mnemonic"] for r in rows
                                if r["probe_accepted"] is None],
        "detail": rows}


def obtain_raw_words() -> tuple:
    os.makedirs(SCRATCH, exist_ok=True)
    before = hashlib.sha256(open(CO, "rb").read()).hexdigest()
    copy = os.path.join(SCRATCH, "cand_f_copy.co")
    shutil.copyfile(CO, copy)
    after = hashlib.sha256(open(CO, "rb").read()).hexdigest()
    dump = subprocess.run([LLVM_OBJDUMP, "-d", "--mcpu=%s" % ARCH, copy],
                          capture_output=True, text=True)
    if dump.returncode != 0:
        raise SystemExit("llvm-objdump failed: %s" % dump.stderr[:400])
    line = re.compile(r"^\s*(.*?)\s*//\s*([0-9A-Fa-f]{8,16}):"
                      r"\s*((?:[0-9A-Fa-f]{8}\s*)+)")
    words, inside, nlines = {}, False, 0
    for ln in dump.stdout.splitlines():
        if ln.startswith(SYM_PREFIX):
            inside = True
            continue
        if inside and re.match(r"^[0-9A-Fa-f]{8,16} <", ln):
            break
        if not inside:
            continue
        m = line.match(ln)
        if not m:
            continue
        nlines += 1
        hx = m.group(3).split()
        words[int(m.group(2), 16)] = {"w0": int(hx[0], 16),
                                      "text": m.group(1).strip(),
                                      "nwords": len(hx)}
    return words, {
        "source": os.path.relpath(CO, ROOT).replace("\\", "/"),
        "sha256_before": before, "sha256_after": after,
        "sha256_unchanged_by_this_run": before == after,
        "sha256_equals_j3_candidate_sha256": before == CO_SHA,
        "read_via": "scratch COPY in phase16y/waitcnt/part3_scratch/",
        "disassembler": "llvm-objdump -d --mcpu=gfx1030",
        "symbol": SYM_PREFIX.split("<")[1].rstrip(">"),
        "instructions_parsed": nlines,
        "llvm_objcopy_used": False}


# ============================================================== parser =====

RE_VI = re.compile(r"^(v|s)(\d+)$")
RE_VR = re.compile(r"^(v|s)\[(\d+):(\d+)\]$")
NAMED = ("vcc_lo", "vcc_hi", "exec_lo", "exec_hi", "m0", "null", "off")
SCALAR_LIKE = re.compile(
    r"^(s(\[\d+:\d+\]|\d+)?|vcc_lo|vcc_hi|exec_lo|exec_hi|null|m0)$")
VREG_LIKE = re.compile(r"^v(\[\d+:\d+\]|\d+)$")

#: VALU mnemonics whose VOP3B encoding carries a scalar destination at op1.
#: ISA (phase16r/isa/ref/rdna2_isa.txt:2213-2214): "Instructions producing a
#: carry-out (integer add and subtract) write their result to VCC when used in
#: the VOP2 form, and to an arbitrary SGPR-pair when used in the VOP3 form."
#: This is only the DEFAULT: `op1_role_probe()` REPLACES it with the measured
#: set before any classification happens, and reports every disagreement.
ISA_SDST = {
    "v_add_co_u32", "v_add_co_ci_u32", "v_add_co_u32_e64",
    "v_add_co_ci_u32_e64", "v_sub_co_u32", "v_sub_co_u32_e64",
    "v_sub_co_ci_u32", "v_sub_co_ci_u32_e64", "v_subrev_co_u32",
    "v_subrev_co_ci_u32", "v_addc_co_u32", "v_subb_co_u32",
    "v_subbrev_co_u32", "v_mad_u64_u32", "v_mad_i64_u32", "v_div_scale_f32",
}
VALU_SDST = set(ISA_SDST)

#: VOP3 (bits[31:26]==0x35) -> (explicit source count, carries an SDST).
#: Used ONLY by `classify_legacy()`, the 'before' arm of the negative control.
VOP3_TABLE = {
    "v_cndmask_b32_e64": (3, 0), "v_cvt_f32_f16_e64": (1, 0),
    "v_add_co_ci_u32_e64": (3, 1), "v_fma_f32": (3, 0),
    "v_add_co_u32": (2, 1), "v_ldexp_f32": (2, 0), "v_lshlrev_b16": (2, 0),
    "v_div_scale_f32": (3, 1), "v_pack_b32_f16": (2, 0), "v_bfe_u32": (3, 0),
    "v_lshl_add_u32": (3, 0), "v_div_fmas_f32": (3, 0),
    "v_div_fixup_f32": (3, 0), "v_and_or_b32": (3, 0), "v_med3_f32": (3, 0),
    "v_add_nc_u16": (2, 0), "v_lshlrev_b64": (2, 0), "v_lshl_or_b32": (3, 0),
    "v_mad_u32_u24": (3, 0), "v_add_lshl_u32": (3, 0),
    "v_cmp_gt_u32_e64": (2, 0), "v_add3_u32": (3, 0),
    "v_lshrrev_b16": (2, 0), "v_or3_b32": (3, 0), "v_mad_u64_u32": (3, 1),
    "v_mul_lo_u16": (2, 0), "v_cmp_gt_i32_e64": (2, 0),
    "v_cmp_lt_i32_e64": (2, 0), "v_bfe_i32": (3, 0), "v_sub_nc_u16": (2, 0),
    "v_cmp_lt_u16_e64": (2, 0), "v_mbcnt_lo_u32_b32": (2, 0),
    "v_cmp_ne_u32_e64": (2, 0),
}

VMEM_LOAD = ("global_load", "flat_load", "buffer_load", "tbuffer_load",
             "scratch_load")
VMEM_STORE = ("global_store", "flat_store", "buffer_store", "tbuffer_store",
              "scratch_store")
VMEM_OTHER = ("buffer_gl0_inv", "buffer_wbinvl1", "buffer_inv")
LDS_READ = ("ds_read",)
LDS_WRITE = ("ds_write",)
LDS_BPERM = ("ds_bpermute", "ds_permute", "ds_swizzle")
SMEM_LOAD = ("s_load", "s_buffer_load", "s_dcache")
SMEM_STORE = ("s_store", "s_buffer_store", "s_dcache_wb", "s_dcache_inv")

SOPP_NODEF = ("s_barrier", "s_branch", "s_cbranch", "s_endpgm", "s_nop",
              "s_waitcnt", "s_sleep", "s_trap", "s_rfe", "s_sethalt",
              "s_setkill", "s_setprio", "s_incperflevel", "s_decperflevel",
              "s_ttracedata", "s_code_end", "s_clause", "s_inst_prefetch")
SOPC = ("s_cmp", "s_cmpk", "s_bitcmp")
CONTROL_FEED = ("s_cbranch", "s_branch", "s_cmp", "s_cmpk", "s_bitcmp",
                "s_and_saveexec", "s_andn2_saveexec", "s_or_saveexec",
                "s_xor_saveexec", "s_cselect", "s_cmov", "v_cmp", "v_cmpx")


def expand(tok: str):
    """Register names one operand contributes.  Modifiers (|abs|, -neg,
    sext(...)) are stripped, never guessed at."""
    t = tok.strip()
    for ch in "|-":
        t = t.replace(ch, "")
    t = t.replace("sext(", "").replace(")", "").strip()
    out = []
    for part in t.split("+"):
        part = part.strip().split(" ")[0]
        m = RE_VR.match(part)
        if m:
            a, b = int(m.group(2)), int(m.group(3))
            out += ["%s%d" % (m.group(1), i)
                    for i in range(min(a, b), max(a, b) + 1)]
            continue
        m = RE_VI.match(part)
        if m:
            out.append("%s%d" % (m.group(1), int(m.group(2))))
            continue
        if part in NAMED:
            out.append(part)
    return out


def split_ops(ops):
    return [] if not ops else [o.strip() for o in ops.split(",")]


def classify(mnem: str, ops: str, w0: int) -> dict:
    """{kind, defs, uses, addr_uses, ok, reason}.  Never guesses: anything it
    cannot place comes back ok=False with a reason, and is counted."""
    o = split_ops(ops)
    r = {"kind": "other", "defs": [], "uses": [], "addr_uses": [],
         "ok": True, "reason": None}

    def rg(i):
        return expand(o[i]) if 0 <= i < len(o) else []

    def flat(lo, hi):
        return list(itertools.chain.from_iterable(rg(i)
                                                  for i in range(lo, hi)))

    def allops():
        return flat(0, len(o))

    if mnem.startswith(VMEM_LOAD):
        r.update(kind="vmem_load", defs=rg(0), uses=flat(1, len(o)),
                 addr_uses=flat(1, len(o)))
        return r
    if mnem.startswith(VMEM_STORE):
        r.update(kind="vmem_store", uses=allops(), addr_uses=rg(0) + flat(2, len(o)))
        return r
    if mnem.startswith(VMEM_OTHER):
        r["kind"] = "vmem_other"
        return r
    if mnem.startswith(LDS_WRITE):
        r.update(kind="lds_write", uses=allops(), addr_uses=rg(0))
        return r
    if mnem.startswith(LDS_READ):
        r.update(kind="lds_read", defs=rg(0), uses=flat(1, len(o)),
                 addr_uses=rg(1))
        return r
    if mnem.startswith(LDS_BPERM):
        r.update(kind="lds_read", defs=rg(0), uses=flat(1, len(o)),
                 addr_uses=rg(1))
        return r
    if mnem.startswith("ds_"):                       # LDS atomic
        r.update(kind="lds_atomic", defs=rg(0), uses=allops(),
                 addr_uses=rg(1))
        return r
    if mnem.startswith(SMEM_LOAD):
        r.update(kind="smem_load", defs=rg(0), uses=flat(1, len(o)),
                 addr_uses=rg(1))
        return r
    if mnem.startswith(SMEM_STORE):
        r.update(kind="smem_store", uses=allops(), addr_uses=rg(0))
        return r

    if mnem.startswith("s_"):
        if mnem.startswith(SOPP_NODEF):
            r["kind"] = "sopp"
            return r
        if mnem.startswith(SOPC):
            r.update(kind="sopc", uses=allops())
            return r
        r.update(kind="sop", defs=rg(0), uses=flat(1, len(o)))
        if len(o) and not r["defs"]:
            r.update(ok=False,
                     reason="SOP dst operand %r did not parse as a register"
                            % o[0])
        if mnem.startswith(("s_and_saveexec", "s_andn2_saveexec",
                            "s_or_saveexec", "s_xor_saveexec")):
            r["defs"] += ["exec_lo", "exec_hi"]
            r["uses"] += ["exec_lo", "exec_hi"]
        return r

    if mnem.startswith("v_"):
        # VALU operand roles come from the MNEMONIC and the printed operand
        # list, not from the raw encoding bits.  Justification (see
        # `valu_form_inventory` and `op1_role_probe` in the output): the
        # printed operand count is constant per mnemonic over all 17478 static
        # instructions, no VALU instruction prints fewer than 2 operands, and
        # whether op1 is a DEF (a VOP3B sdst) or a USE (src0) is decided by a
        # host-only llvm-mc probe that the sdst-family prediction must agree
        # with.  Three independent sources agree on every case: the assembler
        # probe, the ISA text, and revision_16t/emu.py's own handlers.
        r["kind"] = "valu"
        if mnem.startswith("v_cmpx"):
            # VOPC `v_cmpx_*` writes EXEC.  The `_e32` form prints its two
            # SOURCES and no destination; the `_e64` form prints sdst first.
            # ISA: "All V_CMPX instructions write the result of their
            # comparison (one bit per thread) to the EXEC mask", and VOPC has
            # two inputs -- so a 2-operand `_e32` text is (src0, src1).
            r["defs"] = ["exec_lo", "exec_hi"]
            r["uses"] = allops()
            if len(o) >= 3:                      # `v_cmpx_*_e64 sN, s0, s1`
                r["defs"] = rg(0) + ["exec_lo", "exec_hi"]
                r["uses"] = flat(1, len(o))
            if len(o) < 2:
                r.update(ok=False, reason="v_cmpx with %d operands" % len(o))
            return r
        if mnem.startswith("v_cmp"):
            # VOPC: dst is op0 (vcc_lo in the e32 form, an SGPR in the e64).
            r["defs"] = rg(0)
            r["uses"] = flat(1, len(o))
            if not r["defs"]:
                r.update(ok=False,
                         reason="VOPC dst operand %r did not parse as a "
                                "register" % o[0])
            if len(o) < 2:
                r.update(ok=False, reason="v_cmp with %d operands" % len(o))
            return r
        if mnem in VALU_SDST:
            # ISA: "Instructions producing a carry-out (integer add and
            # subtract) write their result to VCC when used in the VOP2 form,
            # and to an arbitrary SGPR-pair when used in the VOP3 form."  In
            # the VOP3B encoding LLVM prints that sdst as op1 and it is a DEF.
            # With 3 operands this is the VOP2 form: op1 is src0 and the
            # carry-out is implicitly VCC.
            if len(o) >= 4:
                r["defs"] = rg(0) + rg(1)
                r["uses"] = flat(2, len(o))
                if not rg(1):
                    r.update(ok=False,
                             reason="%s sdst operand %r did not parse as a "
                                    "register" % (mnem, o[1]))
                return r
            r["defs"] = rg(0) + ["vcc_lo"]
            r["uses"] = flat(1, len(o))
            return r
        r["defs"] = rg(0)
        r["uses"] = flat(1, len(o))
        if not r["defs"]:
            r.update(ok=False,
                     reason="VALU dst operand %r did not parse as a register"
                            % (o[0] if o else "<none>"))
            return r
        if len(o) < 2:
            # Measured: this does not occur (0 of 17478).  If it ever does,
            # the only sound reading is a unary op whose src0 is its own
            # destination, so close it conservatively rather than guess.
            r["uses"] = list(r["uses"]) + rg(0)
            r["note"] = "single-operand VALU: src0 conservatively taken to " \
                        "be the destination register"
        return r

    r.update(ok=False, reason="mnemonic not placed by the classifier")
    return r


def classify_legacy(mnem: str, ops: str, w0: int) -> dict:
    """The pre-fix classifier, kept verbatim as the 'before' arm of the
    through-VOP2 negative control.  It decides VALU format from raw encoding
    bits, which mis-spells the 4-operand VOP2-family forms as unclassifiable."""
    o = split_ops(ops)
    r = {"kind": "other", "defs": [], "uses": [], "addr_uses": [],
         "ok": True, "reason": None, "note": None}

    def rg(i):
        return expand(o[i]) if 0 <= i < len(o) else []

    def flat(lo, hi):
        return list(itertools.chain.from_iterable(rg(i)
                                                  for i in range(lo, hi)))

    def allops():
        return flat(0, len(o))

    if mnem.startswith(VMEM_LOAD):
        r.update(kind="vmem_load", defs=rg(0), uses=flat(1, len(o)),
                 addr_uses=flat(1, len(o)))
        return r
    if mnem.startswith(VMEM_STORE):
        r.update(kind="vmem_store", uses=allops(),
                 addr_uses=rg(0) + flat(2, len(o)))
        return r
    if mnem.startswith(("buffer_gl0_inv", "buffer_wbinvl1")):
        r["kind"] = "vmem_other"
        return r
    if mnem.startswith(LDS_WRITE):
        r.update(kind="lds_write", uses=allops(), addr_uses=rg(0))
        return r
    if mnem.startswith(("ds_read", "ds_bpermute", "ds_permute", "ds_swizzle")):
        r.update(kind="lds_read", defs=rg(0), uses=flat(1, len(o)),
                 addr_uses=rg(1))
        return r
    if mnem.startswith("ds_"):
        r.update(kind="lds_atomic", defs=rg(0), uses=allops(),
                 addr_uses=rg(1))
        return r
    if mnem.startswith(SMEM_LOAD):
        r.update(kind="smem_load", defs=rg(0), uses=flat(1, len(o)),
                 addr_uses=rg(1))
        return r
    if mnem.startswith(SMEM_STORE):
        r.update(kind="smem_store", uses=allops(), addr_uses=rg(0))
        return r
    if mnem.startswith("s_"):
        if mnem.startswith(SOPP_NODEF):
            r["kind"] = "sopp"
            return r
        if mnem.startswith(SOPC):
            r.update(kind="sopc", uses=allops())
            return r
        r.update(kind="sop", defs=rg(0), uses=flat(1, len(o)))
        if len(o) and not r["defs"]:
            r.update(ok=False, reason="SOP dst operand %r did not parse as a "
                                      "register" % o[0])
        if mnem.startswith(("s_and_saveexec", "s_andn2_saveexec",
                            "s_or_saveexec", "s_xor_saveexec")):
            r["defs"] += ["exec_lo", "exec_hi"]
            r["uses"] += ["exec_lo", "exec_hi"]
        return r
    if mnem.startswith("v_"):
        fmt = (w0 >> 26) & 0x3F
        top7 = (w0 >> 25) & 0x7F
        if fmt == 0x35:
            r["kind"] = "valu"
            if mnem not in VOP3_TABLE:
                r.update(ok=False, reason="VOP3 mnemonic %r not in the fitted "
                                          "operand table" % mnem)
                return r
            nsrc, sdst = VOP3_TABLE[mnem]
            if len(o) not in (1 + nsrc, 2 + nsrc):
                r.update(ok=False, reason="VOP3 %s operand count %d "
                                          "contradicts table" % (mnem, len(o)))
                return r
            r["defs"] = rg(0)
            r["uses"] = flat(1 + sdst, len(o))
            if sdst:
                r["defs"] += rg(1)
            if mnem.startswith("v_cmpx"):
                r["defs"] += ["exec_lo", "exec_hi"]
            return r
        if fmt == 0x33:
            r.update(kind="valu", defs=rg(0), uses=flat(1, len(o)))
            return r
        if top7 == 0x3F:
            r.update(kind="valu", defs=rg(0), uses=flat(1, len(o)))
            if len(o) != 2:
                r.update(ok=False, reason="VOP1 e32 with %d operands" % len(o))
            return r
        if top7 == 0x3E:
            r.update(kind="valu", defs=rg(0), uses=flat(1, len(o)))
            if mnem.startswith("v_cmpx"):
                r["defs"] += ["exec_lo", "exec_hi"]
            if len(o) < 2:
                r.update(ok=False, reason="VOPC e32 with %d operands" % len(o))
            return r
        if top7 <= 0x3D:
            r.update(kind="valu", defs=rg(0), uses=flat(1, len(o)))
            if len(o) != 3:
                r.update(ok=False,
                         reason="VOP2 e32 with %d operands -- an implicit "
                                "src0 would have to be modelled" % len(o))
            return r
        r.update(ok=False, reason="unrecognised VALU encoding "
                                  "bits[31:26]=0x%02X" % fmt)
        return r
    r.update(ok=False, reason="mnemonic not placed by the classifier")
    return r


# ============================================================= dataflow ====

PLACEHOLDER = None


def retire(q, n, step, prods):
    while len(q) > n:
        pid = q.pop(0)
        if pid is None:
            continue
        R = prods[pid]
        if not R["retired"]:
            R["retired"] = True
            R["retire_step"] = step


def run_wave(wid, path, table, cls, mutate=None) -> dict:
    mutate = mutate or {}
    prods = {}
    vmem_q, lgkm_q, vscnt_q = [], [], []
    owner = {}
    hazards = []
    barriers = []
    n_ok = n_unclass = n_use_checks = 0
    unclass = collections.Counter()
    n_prod = collections.Counter()

    drop = mutate.get("drop_wait_at", {})
    bump = mutate.get("bump_wait_at", {})
    moves = mutate.get("move_wait_after", {})
    dep_fence = mutate.get("depctr_is_full_fence", False)
    no_gl0inv = mutate.get("gl0inv_not_vmem", False)

    if moves:
        for k in sorted(moves, reverse=True):
            src, dst = moves[k]
            item = path.pop(src)
            path.insert(dst, item)

    for step, gi in enumerate(path):
        e = table[gi]
        mnem = e["mnem"] or ""
        c = cls[gi]
        if c["ok"]:
            n_ok += 1
        else:
            n_unclass += 1
            unclass[c["reason"]] += 1

        # ---- (1) USES, before defs, so `global_load v1, v1, ...` reads v1
        for r in c["uses"]:
            n_use_checks += 1
            pid = owner.get(r)
            if pid is None:
                continue
            R = prods[pid]
            if R["first_consumer_step"] is None:
                R["first_consumer_step"] = step
                R["first_consumer_retired"] = R["retired"]
                R["first_consumer"] = {"pc": e["addr"], "mnem": mnem,
                                       "reg": r, "step": step}
            if not R["retired"] and R["hazard"] is None:
                role = ("branch/control" if mnem.startswith(CONTROL_FEED)
                        else "address" if r in c["addr_uses"] else "data")
                h = {"wave": wid, "producer_pc": R["pc"],
                     "producer_mnem": R["mnem"], "producer_kind": R["kind"],
                     "producer_step": R["step"], "reg": r,
                     "consumer_pc": e["addr"], "consumer_mnem": mnem,
                     "consumer_step": step, "role": role}
                R["hazard"] = h
                hazards.append(h)

        # ---- (2) WAITS
        if mnem == "s_waitcnt":
            if step not in drop:
                d = decode_waitcnt(e["w0"])
                vm, lg = d["vmcnt"], d["lgkmcnt"]
                if step in bump:
                    vm, lg = bump[step]
                if vm < 63:
                    retire(vmem_q, vm, step, prods)
                if lg < 63:
                    retire(lgkm_q, lg, step, prods)
        elif mnem == "s_waitcnt_vscnt":
            mm = re.search(r",\s*(0x[0-9a-fA-F]+|\d+)", e["ops"] or "")
            if mm:
                retire(vscnt_q, int(mm.group(1), 16), step, prods)
        elif mnem == "s_waitcnt_depctr":
            if dep_fence:
                retire(vmem_q, 0, step, prods)
                retire(lgkm_q, 0, step, prods)
        elif mnem == "s_barrier":
            ov = [prods[p] for p in vmem_q if p is not None]
            ol = [prods[p] for p in lgkm_q if p is not None]
            barriers.append({"wave": wid, "step": step, "pc": e["addr"],
                             "outstanding_vmem": len(ov),
                             "outstanding_lgkm": len(ol),
                             "outstanding_vmem_pcs": sorted(set(
                                 p["pc"] for p in ov)),
                             "outstanding_lgkm_pcs": sorted(set(
                                 p["pc"] for p in ol))})

        # ---- (3) DEFS
        kind = c["kind"]
        if kind in ("vmem_load", "lds_read", "lds_atomic", "smem_load"):
            pid = len(prods)
            prods[pid] = {"id": pid, "pc": e["addr"], "mnem": mnem,
                          "kind": kind, "regs": sorted(set(c["defs"])),
                          "step": step, "retired": False, "retire_step": None,
                          "wave": wid, "first_consumer_step": None,
                          "first_consumer_retired": None,
                          "first_consumer": None, "hazard": None,
                          "in_vmem": kind == "vmem_load"}
            for r in c["defs"]:
                owner[r] = pid
            n_prod[kind] += 1
            (vmem_q if kind == "vmem_load" else lgkm_q).append(pid)
        else:
            if kind == "vmem_store":
                vscnt_q.append(PLACEHOLDER)
            elif kind in ("lds_write", "smem_store"):
                lgkm_q.append(PLACEHOLDER)
            elif kind == "vmem_other" and not no_gl0inv:
                vmem_q.append(PLACEHOLDER)
            for r in c["defs"]:
                owner[r] = None

    pc = collections.Counter()
    for R in prods.values():
        if R["first_consumer_step"] is None:
            pc["no_consumer_seen"] += 1
        elif R["first_consumer_retired"]:
            pc["retired_before_first_consumer"] += 1
        else:
            pc["first_consumer_while_outstanding"] += 1
    return {"wave": wid, "steps": len(path), "hazards": hazards,
            "barriers": barriers, "classified": n_ok,
            "unclassified": n_unclass, "unclassified_reasons": dict(unclass),
            "producers": dict(n_prod), "use_checks": n_use_checks,
            "producers_total": sum(n_prod.values()),
            "producer_outcome": dict(pc),
            "leaked_outstanding_vmem_at_end": len([x for x in vmem_q
                                                   if x is not None]),
            "leaked_outstanding_lgkm_at_end": len([x for x in lgkm_q
                                                   if x is not None])}


def run_all(paths, table, cls, mutate=None):
    return [run_wave(w, list(paths[w]), table, cls, mutate)
            for w in sorted(paths, key=int)]


def summarise(runs) -> dict:
    hz = [h for r in runs for h in r["hazards"]]
    prod = collections.Counter()
    unclass = collections.Counter()
    outcome = collections.Counter()
    for r in runs:
        prod.update(r["producers"])
        unclass.update(r["unclassified_reasons"])
        outcome.update(r["producer_outcome"])
    return {
        "waves_analysed": len(runs),
        "steps_analysed": sum(r["steps"] for r in runs),
        "classified_instructions": sum(r["classified"] for r in runs),
        "unclassified_instructions": sum(r["unclassified"] for r in runs),
        "unclassified_reasons": dict(unclass),
        "register_use_checks": sum(r["use_checks"] for r in runs),
        "producers_by_kind": dict(prod),
        "producers_total": sum(prod.values()),
        "producer_outcome": dict(outcome),
        "hazards_total": len(hz),
        "producers_with_hazard": len(hz),
        "hazards_by_role": dict(collections.Counter(h["role"] for h in hz)),
        "hazards_by_kind_to_role": dict(collections.Counter(
            "%s -> %s" % (h["producer_kind"], h["role"]) for h in hz)),
        "barriers_executed": sum(len(r["barriers"]) for r in runs),
        "barriers_with_outstanding_vmem": sum(
            1 for r in runs for b in r["barriers"] if b["outstanding_vmem"]),
        "barriers_with_outstanding_lgkm": sum(
            1 for r in runs for b in r["barriers"] if b["outstanding_lgkm"]),
        "hazards": hz,
        "barrier_detail": [b for r in runs for b in r["barriers"]]}


# ==================== synthetic through-VALU-consumer controls =============

def synth_control(table, cls_new, cls_old_list, prod_gi, cons_gi, label, note,
                  mutate=None, intended_before="HAZARD") -> dict:
    """Build a 2-instruction in-memory path (real producer text, real consumer
    text, no wait between them) and run BOTH the fixed and the pre-fix
    classifier over it.  `prod_gi` must be a VMEM load and `cons_gi` must read
    the register that load defines.

    `intended_before` is the verdict the PRE-FIX arm is EXPECTED to return:
    "HAZARD" for a control that the pre-fix model already handled, "MISSED"
    for a control the pre-fix model was blind to.  `matches_intent` is only
    true when the pre-fix arm matches `intended_before` AND the fixed arm
    reports HAZARD -- so a control that does not fire is never scored ok.

    Nothing on disk is touched: the synthetic table is built in memory and the
    addresses are nominated markers, not real PCs."""
    P = dict(table[prod_gi])
    C = dict(table[cons_gi])
    P["addr"], C["addr"] = 0xDEAD0000, 0xDEAD0004
    stab = [P, C]
    sc_new = [classify(P["mnem"] or "", P["ops"] or "", P["w0"]),
              classify(C["mnem"] or "", C["ops"] or "", C["w0"])]
    sc_old = [cls_old_list[prod_gi], cls_old_list[cons_gi]]
    path = [0, 1]
    after = summarise([run_wave(0, list(path), stab, sc_new, mutate)])
    before = summarise([run_wave(0, list(path), stab, sc_old, mutate)])
    reg = sorted(set(sc_new[1]["uses"]) & set(sc_new[0]["defs"]))
    return {
        "control": label,
        "note": note,
        "synthetic_path": [
            {"role": "producer", "pc": "0xDEAD0000",
             "text": P["text"], "raw_word": "0x%08X" % P["w0"],
             "classified_by_fixed": sc_new[0],
             "classified_by_legacy": sc_old[0]},
            {"role": "consumer", "pc": "0xDEAD0004",
             "text": C["text"], "raw_word": "0x%08X" % C["w0"],
             "classified_by_fixed": sc_new[1],
             "classified_by_legacy": sc_old[1]}],
        "register_the_producer_defines_and_the_consumer_reads": reg,
        "comparisons_performed": len(sc_new[1]["uses"])
                               + len(sc_new[0]["defs"]),
        "hazards_before_the_fix_legacy_classifier": before["hazards_total"],
        "hazards_after_the_fix": after["hazards_total"],
        "before_the_fix_verdict": ("HAZARD" if before["hazards_total"]
                                   else "MISSED"),
        "after_the_fix_verdict": ("HAZARD" if after["hazards_total"]
                                  else "MISSED"),
        "expected_before_the_fix": intended_before,
        "fixed_arm_would_have_been_blind": sc_new[1]["uses"] == [],
        "example_hazard_after_the_fix": (after["hazards"][0]
                                         if after["hazards"] else None),
        "matches_intent": (("HAZARD" if before["hazards_total"] else "MISSED")
                           == intended_before
                           and after["hazards_total"] > 0),
        "legal_producer_and_consumer_text": bool(P["text"] and C["text"])}


# ========================================================= cross-check =====

GLOBAL_OK = re.compile(r"^global_(load|store)")


def tracer_crosscheck(paths, table, tracer_tb) -> dict:
    parsed, seen = {}, set()
    for w in sorted(paths, key=int):
        for gi in paths[w]:
            e = table[gi]
            m = e["mnem"] or ""
            if not GLOBAL_OK.match(m) or e["addr"] in seen:
                continue
            seen.add(e["addr"])
            parsed[e["addr"]] = (m, m.startswith("global_store"))
    p_read = {p for p, (m, s) in parsed.items() if not s}
    p_store = {p for p, (m, s) in parsed.items() if s}
    t_read = {int(k) for k, v in tracer_tb.items()
              if k != "<no-context>" and not v["store"]}
    t_store = {int(k) for k, v in tracer_tb.items()
               if k != "<no-context>" and v["store"]}
    mismatch, n_cmp = [], 0
    n_cmp += len(p_read | p_store) + len(t_read | t_store)
    for pc in sorted(p_read | p_store):
        if pc not in t_read and pc not in t_store:
            mismatch.append({"pc": pc,
                             "issue": "parser calls it a global access, "
                                      "tracer_by_pc has no entry"})
    for pc in sorted(t_read | t_store):
        if pc not in p_read and pc not in p_store:
            mismatch.append({"pc": pc,
                             "issue": "tracer_by_pc entry the parser did not "
                                      "call a global access"})
    for pc, (m, s) in sorted(parsed.items()):
        t = tracer_tb.get(str(pc))
        if t is None:
            continue
        n_cmp += 2
        if bool(t["store"]) != s:
            mismatch.append({"pc": pc, "issue": "store flag disagrees",
                             "parser": s, "tracer": bool(t["store"])})
        if t["mnem"] != m:
            mismatch.append({"pc": pc, "issue": "mnemonic disagrees",
                             "parser": m, "tracer": t["mnem"]})
    return {"comparisons_performed": n_cmp,
            "parser_global_pcs": len(parsed),
            "parser_global_read_pcs": len(p_read),
            "parser_global_store_pcs": len(p_store),
            "tracer_global_pcs": len(t_read | t_store),
            "tracer_global_read_pcs": len(t_read),
            "tracer_global_store_pcs": len(t_store),
            "set_symmetric_difference": len((p_read | p_store)
                                            ^ (t_read | t_store)),
            "mismatches": mismatch,
            "verdict": "MATCH" if not mismatch else "MISMATCH",
            "note_on_per_pc_n": (
                "tracer_by_pc[...]['n'] is a LANE-RESOLVED access count, not "
                "an instruction count: n / (dynamic executions of that PC) is "
                "an exact integer for every PC (128/256/512/1024/2048).  It is "
                "therefore used only for SET membership and flags, never for "
                "counts.  tracer_totals does not reconcile with the sum of the "
                "per-PC n fields; that discrepancy is in the input artifact, is "
                "not used by this audit, and is not a verdict input."),
            "tracer_no_context_bucket_n": tracer_tb.get("<no-context>", {}).get("n")}


# ================================================================ main =====

def main() -> int:
    print("[1] decoding s_waitcnt against probe_results.json ...")
    dec = step1_decoder()
    print("    entries=%d field_comparisons=%d mismatches=%d"
          % (dec["entries_compared"], dec["s_waitcnt_field_comparisons"],
             dec["mismatches"]))
    if dec["mismatches"]:
        print("    DECODER FAILED -- stopping")
        return 2

    print("[2] raw words from a scratch copy of Candidate F ...")
    raw, rawprov = obtain_raw_words()
    print("    parsed=%d co_sha_unchanged=%s co_matches_j3=%s"
          % (rawprov["instructions_parsed"],
             rawprov["sha256_unchanged_by_this_run"],
             rawprov["sha256_equals_j3_candidate_sha256"]))
    if not rawprov["sha256_equals_j3_candidate_sha256"]:
        print("    .co does not match the J3 candidate sha -- stopping")
        return 2

    J = json.load(open(EXEC_PCS, encoding="utf-8"))
    table_in = J["instruction_table"]
    tracer_tb = J["tracer_by_pc"]

    n_addr = n_text = 0
    textdiff, table = [], []
    for e in table_in:
        w = raw.get(e["addr"])
        if w is None:
            raise SystemExit("0x%X absent from the .co disassembly" % e["addr"])
        n_addr += 1
        a = " ".join((e["text"] or "").split())
        b = " ".join(w["text"].split())
        if a == b:
            n_text += 1
        else:
            textdiff.append({"addr": hex(e["addr"]), "emu": a, "co": b})
        table.append({"n": e["n"], "addr": e["addr"], "mnem": e["mnem"],
                      "ops": e["ops"], "text": e["text"], "w0": w["w0"],
                      "nwords": w["nwords"]})
    print("    addr match %d/%d ; text match %d/%d"
          % (n_addr, len(table_in), n_text, len(table_in)))

    paths = {int(k): v for k, v in J["executed_prog_index_by_wave"].items()}

    # Measured operand-form model first, THEN classify.  Order matters: the
    # probe replaces VALU_SDST with what the assembler actually says.
    print("[3] measuring the VALU operand forms actually present ...")
    inv = valu_form_inventory(table, paths)
    print("    VALU mnemonics=%d ; with 1 printed operand=%d ; with 2=%d "
          "(v_cmpx=%d)"
          % (inv["valu_mnemonics"],
             inv["valu_with_one_printed_operand"]["mnemonics"],
             inv["valu_with_two_printed_operands"]["mnemonics"],
             len(inv["valu_with_two_printed_operands"]
                 ["vopc_cmpx_e32_src0_src1_with_implicit_exec_dst"])))
    print("[3b] probing whether op1 is a DEF (sdst) or a USE (src0) ...")
    probe = op1_role_probe(table)
    print("    probed=%d comparisons=%d disagreements_with_the_ISA=%d"
          % (probe["mnemonics_probed"], probe["comparisons_performed"],
             probe["disagreements_with_the_isa_family"]))
    print("[3c] classifying every instruction with the measured model ...")
    cls = [classify(t["mnem"] or "", t["ops"] or "", t["w0"]) for t in table]
    cls_old = [classify_legacy(t["mnem"] or "", t["ops"] or "", t["w0"])
               for t in table]
    legacy_unclass_static = collections.Counter(
        c["reason"] for c in cls_old if not c["ok"])
    legacy_unclass_mnem = collections.Counter(
        t["mnem"] for t, c in zip(table, cls_old) if not c["ok"])
    print("    legacy classifier: %d of %d instructions unclassifiable"
          % (sum(legacy_unclass_static.values()), len(table)))
    new_unclass_static = collections.Counter(
        c["reason"] for c in cls if not c["ok"])
    print("    fixed classifier : %d of %d instructions unclassifiable"
          % (sum(new_unclass_static.values()), len(table)))

    # VOP3 operand-count fit over the WHOLE static table (not just dynamic)
    nv3 = nv3bad = nv3missing = 0
    v3bad, v3missing = [], []
    for t, c in zip(table, cls):
        fmt = (t["w0"] >> 26) & 0x3F
        if fmt not in (0x35, 0x33):
            continue
        m = t["mnem"] or ""
        if m not in VOP3_TABLE:
            if fmt == 0x35:
                nv3missing += 1
                v3missing.append({"pc": "0x%X" % t["addr"], "mnem": m,
                                  "issue": "VOP3 mnemonic absent from table"})
            continue
        nv3 += 1
        nsrc, sdst = VOP3_TABLE[m]
        n = len(split_ops(t["ops"]))
        if n not in (1 + nsrc, 2 + nsrc):
            nv3bad += 1
            v3bad.append({"pc": "0x%X" % t["addr"], "mnem": m,
                          "observed_ops": n, "nsrc": nsrc, "sdst": sdst})
    print("    VOP3 operand-count fit: %d checked, %d mismatches, %d VOP3 "
          "mnemonics absent from the table" % (nv3, nv3bad, nv3missing))

    # ---- dynamic wait inventory -----------------------------------------
    dyn = set()
    for v in paths.values():
        dyn.update(v)
    counts = {w: collections.Counter(paths[w]) for w in paths}
    waits = {}
    for gi in sorted(dyn):
        t = table[gi]
        if not (t["mnem"] or "").startswith("s_waitcnt"):
            continue
        d = decode_waitcnt(t["w0"]) if t["mnem"] == "s_waitcnt" else None
        waits[gi] = {"pc": t["addr"], "pc_hex": "0x%X" % t["addr"],
                     "mnem": t["mnem"], "raw_word": "0x%08X" % t["w0"],
                     "ops": t["ops"], "text": t["text"],
                     "decoded": ({k: d[k] for k in ("vmcnt", "lgkmcnt",
                                                    "expcnt")} if d else None),
                     "exec_count": sum(counts[w][gi] for w in counts),
                     "exec_by_wave": {str(w): counts[w][gi] for w in
                                      sorted(counts) if counts[w][gi]}}
    print("    distinct dynamically executed waits: %d" % len(waits))

    print("[4] def-use walk over the dynamic path ...")
    runs = run_all(paths, table, cls)
    base = summarise(runs)
    print("    steps=%d producers=%d hazards=%d unclassified=%d"
          % (base["steps_analysed"], base["producers_total"],
             base["hazards_total"], base["unclassified_instructions"]))
    print("    producer outcome: %s" % base["producer_outcome"])

    print("[5] tracer cross-check ...")
    xc = tracer_crosscheck(paths, table, tracer_tb)
    print("    comparisons=%d mismatches=%d (%s)"
          % (xc["comparisons_performed"], len(xc["mismatches"]), xc["verdict"]))

    # ---- sensitivity -----------------------------------------------------
    sens = {}
    for name, mut in (("depctr_modelled_as_full_fence",
                       {"depctr_is_full_fence": True}),
                      ("buffer_gl0_inv_not_counted_as_vmem",
                       {"gl0inv_not_vmem": True})):
        s = summarise(run_all(paths, table, cls, mut))
        sens[name] = {"hazards_total": s["hazards_total"],
                      "hazards_by_role": s["hazards_by_role"],
                      "barriers_with_outstanding_vmem":
                          s["barriers_with_outstanding_vmem"],
                      "barriers_with_outstanding_lgkm":
                          s["barriers_with_outstanding_lgkm"]}
    # Operand-role ambiguity: op1 of an SDST mnemonic is the only position
    # whose def/use role could be argued either way.  Both alternative models
    # are run so the verdict cannot depend on that argument.
    def reclassify(sdst_mode):
        out = []
        for t in table:
            c = classify(t["mnem"] or "", t["ops"] or "", t["w0"])
            if sdst_mode and (t["mnem"] or "") in VALU_SDST:
                o = split_ops(t["ops"])
                if len(o) >= 4:
                    extra = expand(o[1])
                    c = dict(c)
                    c["uses"] = list(c["uses"]) + extra
                    if sdst_mode == "use_only":
                        c["defs"] = [r for r in c["defs"] if r not in extra]
            out.append(c)
        return out

    for name, mode in (
            ("sdst_mnemonics_op1_treated_as_a_source_not_a_def", "use_only"),
            ("sdst_mnemonics_op1_treated_as_BOTH_def_and_source", "both")):
        s = summarise(run_all(paths, table, reclassify(mode)))
        sens[name] = {"hazards_total": s["hazards_total"],
                      "hazards_by_role": s["hazards_by_role"],
                      "unclassified_instructions":
                          s["unclassified_instructions"],
                      "verdict_unchanged": s["hazards_total"]
                                          == base["hazards_total"]}

    # ---- focus sub-audits ------------------------------------------------
    print("[6] focus sub-audits ...")
    idx_of = {t["addr"]: i for i, t in enumerate(table)}
    FOCUS = [0xBA730, 0xBBE2C, 0xBBE20, 0xBA70C, 0xBBF24]
    focus = {}
    for a in FOCUS:
        gi = idx_of[a]
        t = table[gi]
        win = [{"pc": "0x%X" % table[k]["addr"], "mnem": table[k]["mnem"],
                "text": table[k]["text"]}
               for k in range(max(0, gi - 8), min(len(table), gi + 9))]
        focus["0x%X" % a] = {
            "mnem": t["mnem"], "text": t["text"],
            "raw_word": "0x%08X" % t["w0"],
            "exec_count": sum(counts[w][gi] for w in counts),
            "window": win,
            "hazards_touching_pc": [h for h in base["hazards"]
                                    if h["consumer_pc"] == a
                                    or h["producer_pc"] == a]}

    barrier_detail = []
    for w in sorted(paths, key=int):
        p = paths[w]
        for st, gi in enumerate(p):
            if (table[gi]["mnem"] or "") != "s_barrier":
                continue
            prev = None
            for j in range(st - 1, max(-1, st - 16), -1):
                if (table[p[j]]["mnem"] or "").startswith("s_waitcnt"):
                    prev = {"pc": "0x%X" % table[p[j]]["addr"],
                            "text": table[p[j]]["text"],
                            "distance": st - j,
                            "decoded": (decode_waitcnt(table[p[j]]["w0"])
                                        if table[p[j]]["mnem"] == "s_waitcnt"
                                        else None)}
                    break
            barrier_detail.append({"wave": w, "step": st,
                                   "pc": "0x%X" % table[gi]["addr"],
                                   "nearest_preceding_wait": prev})
    focus["barrier_adjacency"] = {
        "dynamically_executed_barriers": len(barrier_detail),
        "barriers_with_no_wait_in_the_16_preceding_instructions":
            sum(1 for b in barrier_detail
                if b["nearest_preceding_wait"] is None),
        "barriers_crossed_with_outstanding_vmem":
            base["barriers_with_outstanding_vmem"],
        "barriers_crossed_with_outstanding_lgkm":
            base["barriers_with_outstanding_lgkm"],
        "detail": barrier_detail,
        "outstanding_at_each_barrier": [
            {k: b[k] for k in ("wave", "step", "pc", "outstanding_vmem",
                               "outstanding_lgkm",
                               "outstanding_vmem_pcs",
                               "outstanding_lgkm_pcs")}
            for b in base["barrier_detail"]]}

    depctx = []
    for gi in sorted(dyn):
        if table[gi]["mnem"] != "s_waitcnt_depctr":
            continue
        nxt, prv = None, None
        for k in range(gi + 1, min(len(table), gi + 7)):
            if classify(table[k]["mnem"] or "", table[k]["ops"] or "",
                        table[k]["w0"])["kind"] in (
                        "vmem_load", "lds_read", "lds_write", "lds_atomic",
                        "smem_load"):
                nxt = {"pc": "0x%X" % table[k]["addr"],
                       "text": table[k]["text"]}
                break
        for k in range(gi - 1, max(-1, gi - 7), -1):
            if classify(table[k]["mnem"] or "", table[k]["ops"] or "",
                        table[k]["w0"])["kind"] in (
                        "vmem_load", "lds_read", "lds_write", "lds_atomic",
                        "smem_load"):
                prv = {"pc": "0x%X" % table[k]["addr"],
                       "text": table[k]["text"]}
                break
        depctx.append({"pc": "0x%X" % table[gi]["addr"],
                       "ops": table[gi]["ops"], "text": table[gi]["text"],
                       "exec_count": sum(counts[w][gi] for w in counts),
                       "nearest_preceding_memory_op_within_6": prv,
                       "nearest_following_memory_op_within_6": nxt})

    # ---- negative controls ------------------------------------------------
    print("[7] negative controls ...")
    controls = []

    # pick a (wait, producer, consumer) triple the BASELINE covers
    triple = None
    for w in sorted(paths, key=int):
        p = paths[w]
        for st, gi in enumerate(p):
            if (table[gi]["mnem"] or "") != "s_waitcnt":
                continue
            d = decode_waitcnt(table[gi]["w0"])
            if d["vmcnt"] > 4:
                continue
            owner = {}
            for k in range(st):
                ck = cls[p[k]]
                for r in ck["defs"]:
                    owner[r] = (k, table[p[k]]["addr"], table[p[k]]["mnem"],
                                ck["kind"])
            for k in range(st + 1, min(len(p), st + 600)):
                ck = cls[p[k]]
                hit = [r for r in ck["uses"] if r in owner
                       and owner[r][3] == "vmem_load"]
                if hit:
                    triple = {"wave": w, "wait_step": st,
                              "wait_pc": "0x%X" % table[gi]["addr"],
                              "wait_text": table[gi]["text"],
                              "wait_decoded": d,
                              "producer_step": owner[hit[0]][0],
                              "producer_pc": "0x%X" % owner[hit[0]][1],
                              "producer_mnem": owner[hit[0]][2],
                              "consumer_step": k,
                              "consumer_pc": "0x%X" % table[p[k]]["addr"],
                              "consumer_mnem": table[p[k]]["mnem"],
                              "reg": hit[0]}
                    break
            if triple:
                break
        if triple:
            break

    def control(name, mutation, intended, mut, expect_detect=True):
        try:
            s = summarise(run_all(paths, table, cls, mut))
            hz = s["hazards_total"]
            det = hz > 0
            controls.append({
                "control": name, "mutation": mutation,
                "intended_verdict": intended,
                "actual_verdict": ("HAZARD_DETECTED (%d hazards)" % hz)
                if det else "NO_HAZARD",
                "detected": det, "matches_intent": det == expect_detect,
                "example_broken_pair": s["hazards"][0] if s["hazards"] else None,
                "vacuous": s["producers_total"] == 0})
        except Exception as ex:                              # noqa: BLE001
            controls.append({"control": name, "mutation": mutation,
                             "intended_verdict": intended,
                             "actual_verdict": "ERROR %s" % ex,
                             "detected": False, "matches_intent": False})

    if triple:
        ws, cs = triple["wait_step"], triple["consumer_step"]
        baseline_hz = base["hazards_total"]
        control("(a) delete a required wait",
                "remove the s_waitcnt at wave %d step %d (%s, %s) from the "
                "analysed path" % (triple["wave"], ws, triple["wait_pc"],
                                   triple["wait_text"]),
                "HAZARD for the pair it covered", {"drop_wait_at": {ws: True}})
        control("(b) raise the wait's vmcnt so it no longer covers its producer",
                "rewrite %s at wave %d step %d to vmcnt(63)=no-wait, lgkmcnt "
                "kept at %d" % (triple["wait_text"], triple["wave"], ws,
                                triple["wait_decoded"]["lgkmcnt"]),
                "HAZARD for the pair it covered",
                {"bump_wait_at": {ws: (63, triple["wait_decoded"]["lgkmcnt"])}})
        control("(c) move the wait to AFTER its consumer",
                "move the s_waitcnt at wave %d step %d to step %d (past its "
                "first consumer at %s)"
                % (triple["wave"], ws, cs + 1, triple["consumer_pc"]),
                "HAZARD for the pair it covered",
                {"move_wait_after": {ws: (ws, cs + 1)}})
        for c in controls:
            c["baseline_hazards_for_this_comparison"] = baseline_hz
            if c["control"].startswith(("(a)", "(b)", "(c)")):
                c["producer_consumer_pair_the_mutation_breaks"] = {
                    "producer_pc": triple["producer_pc"],
                    "producer_mnem": triple["producer_mnem"],
                    "producer_step": triple["producer_step"],
                    "consumer_pc": triple["consumer_pc"],
                    "consumer_mnem": triple["consumer_mnem"],
                    "register": triple["reg"],
                    "wait_that_covered_it": triple["wait_pc"] + " " +
                                            triple["wait_text"],
                    "wait_step": ws}
    else:
        controls.append({"control": "(a/b/c) wait-mutation controls",
                         "intended_verdict": "HAZARD",
                         "actual_verdict": "NOT RUN -- no (wait, producer, "
                                           "consumer) triple found",
                         "detected": False, "matches_intent": False})

    # (d) empty / decoy path -> VACUOUS, never PASS
    empty = {w: [] for w in paths}
    es = summarise(run_all(empty, table, cls))
    controls.append({
        "control": "(d) empty/decoy executed-PC set",
        "mutation": "replace every wave's executed path with []",
        "intended_verdict": "VACUOUS FAILURE, never PASS",
        "actual_verdict": ("VACUOUS (steps=%d producers=%d hazards=%d)"
                           % (es["steps_analysed"], es["producers_total"],
                              es["hazards_total"])),
        "detected": es["producers_total"] == 0 and es["steps_analysed"] == 0,
        "matches_intent": es["producers_total"] == 0,
        "note": "the verdict function computes vacuity from steps_analysed, "
                "producers_total and the tracer comparison count, all of which "
                "are printed; a zero-comparison run cannot be a PASS."})
    empty_hz = es["hazards_total"]
    controls[-1]["vacuous_reported_not_pass"] = (
        es["producers_total"] == 0 and es["hazards_total"] == 0)

    # (e) cross-check must be able to fail
    victim = None
    for gi in sorted(dyn):
        if (table[gi]["mnem"] or "").startswith("global_load"):
            victim = gi
            break
    if victim is not None:
        good = tracer_crosscheck(paths, table, tracer_tb)
        saved = table[victim]["mnem"]
        table[victim]["mnem"] = "s_nop"
        bad = tracer_crosscheck(paths, table, tracer_tb)
        table[victim]["mnem"] = saved
        again = tracer_crosscheck(paths, table, tracer_tb)
        controls.append({
            "control": "(e) tracer_by_pc cross-check can fail",
            "mutation": "re-label the dynamically executed global load at PC "
                        "%s as s_nop in the classification handed to the "
                        "cross-check" % ("0x%X" % table[victim]["addr"]),
            "intended_verdict": "MISMATCH",
            "actual_verdict": "MISMATCH (%d) after corruption, %d before, %d "
                              "after restore" % (len(bad["mismatches"]),
                                                 len(good["mismatches"]),
                                                 len(again["mismatches"])),
            "detected": len(bad["mismatches"]) > 0
            and not good["mismatches"] and not again["mismatches"],
            "matches_intent": len(bad["mismatches"]) > 0
            and not good["mismatches"],
            "example_broken_pair": bad["mismatches"][0] if bad["mismatches"]
            else None})

    # (f) decoder wrong-layout control is inside step1_decoder()

    # (g),(h) hazards planted THROUGH the two VALU forms the pre-fix
    # classifier could not see.  Both arms use real instruction texts.
    print("[7b] through-VALU-consumer controls (before vs after the fix) ...")
    v21_prod = None
    cmpx_cons = None
    for gi in sorted(dyn):
        m = table[gi]["mnem"] or ""
        o = split_ops(table[gi]["ops"])
        if (v21_prod is None and m.startswith("global_load")
                and o and expand(o[0]) == ["v21"]):
            v21_prod = gi
        if (cmpx_cons is None and m == "v_cmpx_o_f16_e32"
                and len(o) >= 2 and expand(o[0]) == ["v4"]):
            cmpx_cons = gi
        if v21_prod is not None and cmpx_cons is not None:
            break
    # Consumer selection is by PREDICATE, never by address order: the consumer
    # must really read a register the producer defines.  (Revision 1 of this
    # block walked `sorted(dyn)` and took the first `v_cndmask_b32_e32`, which
    # reads a different register entirely, so the control could not fire and
    # reported 0/0.  That mistake is recorded in the history rather than
    # quietly re-chosen.)
    # (g) must plant its hazard THROUGH one of the instances the pre-fix
    # classifier flagged, so BOTH members of the pair are drawn from that
    # class on the dynamic path -- selected CONSUMER-FIRST, because the
    # consumer's real operands decide which real load can feed it.  (Revision 2
    # walked the table in address order and picked a consumer that reads
    # neither the producer's register nor the flagged class at all.)
    flagged_dyn_pool = [gi for gi in sorted(dyn) if not cls_old[gi]["ok"]]
    vmem_prod_pool = [gi for gi in sorted(dyn)
                      if cls[gi]["kind"] == "vmem_load"]
    g_pair, g_tried = None, 0
    for cons_gi in flagged_dyn_pool:
        g_tried += 1
        for prod_gi in vmem_prod_pool:
            if set(cls[cons_gi]["uses"]) & set(cls[prod_gi]["defs"]):
                g_pair = (prod_gi, cons_gi)
                break
        if g_pair:
            break

    cnd_cons = g_pair[1] if g_pair else None
    g_prod = g_pair[0] if g_pair else None

    if g_pair is not None:
        controls.append(synth_control(
            table, cls, cls_old, g_prod, cnd_cons,
            "(g) hazard planted THROUGH a 4-operand VOP2-family consumer "
            "(`v_cndmask_b32_e32`) -- the class the pre-fix classifier "
            "reported as UNCLASSIFIED (784 dynamic executions)",
            "MEASURED RESULT: the pre-fix classifier FLAGGED this class "
            "ok=False but still filled defs=op0 and uses=op[1:], which is "
            "exactly what the fixed model computes.  The hazard is therefore "
            "CAUGHT BEFORE THE FIX too, so this control cannot discriminate "
            "the two models.  The premise that the 784 were invisible "
            "consumers is REFUTED (see def_use_model_agreement).  Both "
            "members of this pair are real unmutated instructions drawn from "
            "the flagged class and from the dynamic path.",
            intended_before="HAZARD"))
    else:
        controls.append({"control": "(g) through-VOP2 hazard control",
                         "actual_verdict": "NOT RUN -- no real producer/"
                                           "consumer pair located",
                         "consumer_candidates_tried": g_tried,
                         "comparisons_performed": 0,
                         "matches_intent": False})

    # (g2) The class the pre-fix classifier really WAS blind to: it returned
    # empty defs AND empty uses, so the consumer edge was invisible to it.
    # VOP3-encoded mnemonics absent from the pre-fix VOP3 operand table.
    blind_pool = [gi for gi in range(len(table))
                  if not cls_old[gi]["ok"] and not cls_old[gi]["defs"]
                  and not cls_old[gi]["uses"]]
    prod_pool = [gi for gi in range(len(table))
                 if cls[gi]["kind"] in ("vmem_load", "lds_read", "lds_atomic",
                                        "smem_load")]
    g2 = None
    for cons_gi in blind_pool:
        for prod_gi in prod_pool:
            # the producer must be seen IDENTICALLY by both models, so any
            # difference in the outcome is attributable to the consumer alone
            if cls_old[prod_gi]["ok"] and cls_old[prod_gi]["defs"] == \
                    cls[prod_gi]["defs"] and \
                    set(cls[cons_gi]["uses"]) & set(cls[prod_gi]["defs"]):
                g2 = (prod_gi, cons_gi)
                break
        if g2:
            break

    if g2 is not None:
        controls.append(synth_control(
            table, cls, cls_old, g2[0], g2[1],
            "(g2) hazard planted THROUGH a VOP3-encoded consumer the pre-fix "
            "classifier could NOT classify at all (empty defs AND empty uses)",
            "MEASURED RESULT: for this class the pre-fix model recorded "
            "nothing, so the outstanding producer is never seen as consumed "
            "and the hazard is MISSED before the fix and CAUGHT after it.  "
            "This is the genuine pre-fix blind class; note it is NOT the "
            "v_cndmask family the audit flagged (see "
            "def_use_model_agreement.genuinely_blind_class).",
            intended_before="MISSED"))
    else:
        controls.append({"control": "(g2) genuinely-blind VOP3 consumer "
                                    "hazard control",
                         "actual_verdict": "NOT RUN -- no pair located",
                         "comparisons_performed": 0,
                         "matches_intent": False})

    if v21_prod is not None and cmpx_cons is not None:
        # The measured instance is `v_cmpx_o_f16_e32 v4, v4`, where op0 == op1,
        # which hides the role confusion.  Vary op1 so the two roles separate.
        #
        # The hazard must be planted on the register the DEFECT drops.  The
        # pre-fix arm for top7==0x3E does `defs=rg(0), uses=flat(1,..)`, i.e.
        # it reads printed op0 as a DESTINATION and never as a use; the
        # operand it loses is the FIRST printed one.  So the producer must
        # define v4, the op0 of `v_cmpx_o_f16_e32 v4, v7`.
        # Both arms receive the IDENTICAL mutated text, and each arm's
        # classification is computed from that text (never reused from the
        # unmutated instance), so the only difference between the arms is the
        # classifier.
        c = dict(table[cmpx_cons])
        o = split_ops(c["ops"])
        o[1] = "v7"
        c["ops"] = ", ".join(o)
        c["text"] = c["text"].replace("v4, v4", "v4, v7")
        c["addr"] = 0xDEAD0004
        P = dict(table[v21_prod])
        o = split_ops(P["ops"])
        o[0] = "v4"
        P["ops"] = ", ".join(o)
        P["text"] = P["text"].replace("v21", "v4", 1)
        P["addr"] = 0xDEAD0000
        stab = [P, c]
        sn = [classify(P["mnem"] or "", P["ops"] or "", P["w0"]),
              classify(c["mnem"] or "", c["ops"] or "", c["w0"])]
        so = [classify_legacy(P["mnem"] or "", P["ops"] or "", P["w0"]),
              classify_legacy(c["mnem"] or "", c["ops"] or "", c["w0"])]
        af = summarise([run_wave(0, [0, 1], stab, sn)])
        bf = summarise([run_wave(0, [0, 1], stab, so)])
        controls.append({
            "control": "(h) hazard planted THROUGH a `v_cmpx_*_e32` consumer "
                       "-- the VOPC form whose printed op0 is a SOURCE, not a "
                       "destination",
            "note": "The measured `v_cmpx_o_f16_e32 v4, v4` has op0 == op1, "
                    "which masks the role confusion, so op1 is varied to v7 "
                    "to separate the two roles, and the producer defines v4 -- "
                    "the operand the pre-fix model treats as a destination "
                    "and so drops as a use.  The instruction text is the real "
                    "one; only the operands differ.  Both arms classify the "
                    "same mutated text.",
            "register_the_defect_drops": "v4",
            "register_the_producer_defines_and_the_consumer_reads":
                sorted(set(sn[1]["uses"]) & set(sn[0]["defs"])),
            "synthetic_path": [
                {"role": "producer", "pc": "0xDEAD0000", "text": P["text"],
                 "classified_by_fixed": sn[0], "classified_by_legacy": so[0]},
                {"role": "consumer", "pc": "0xDEAD0004", "text": c["text"],
                 "classified_by_fixed": sn[1], "classified_by_legacy": so[1]}],
            "hazards_before_the_fix_legacy_classifier": bf["hazards_total"],
            "hazards_after_the_fix": af["hazards_total"],
            "comparisons_performed": len(sn[1]["uses"]) + len(sn[0]["defs"]),
            "before_the_fix_verdict": "HAZARD" if bf["hazards_total"]
                                      else "MISSED",
            "after_the_fix_verdict": "HAZARD" if af["hazards_total"]
                                     else "MISSED",
            "expected_before_the_fix": "MISSED",
            "matches_intent": (bf["hazards_total"] == 0
                               and af["hazards_total"] > 0),
            "example_hazard_after_the_fix": (af["hazards"][0]
                                             if af["hazards"] else None)})
    else:
        controls.append({"control": "(h) through-v_cmpx hazard control",
                         "actual_verdict": "NOT RUN -- no real "
                                           "`v_cmpx_*_e32` instance located",
                         "matches_intent": False})

    # ---- what the pre-fix model ACTUALLY did with the flagged class -------
    # The coordinator's concern was that a flagged instruction cannot be
    # recognised as a CONSUMER.  That is measurable per instruction: compare
    # the def/use SETS the two models produce, not their ok flags.
    eq = [i for i in range(len(table))
          if cls[i]["defs"] == cls_old[i]["defs"]
          and cls[i]["uses"] == cls_old[i]["uses"]]
    ne = [i for i in range(len(table)) if i not in set(eq)]
    ne_dyn = [i for i in ne if i in dyn]
    flagged = [i for i in range(len(table)) if not cls_old[i]["ok"]]
    flagged_parsed = [i for i in flagged if cls_old[i]["defs"]
                      or cls_old[i]["uses"]]
    flagged_empty = [i for i in flagged if not cls_old[i]["defs"]
                     and not cls_old[i]["uses"]]
    flagged_dyn = [i for i in flagged if i in dyn]
    model_agreement = {
        "method": "per-instruction equality of the (defs, uses) SETS each "
                  "model computes, over all %d static instructions and over "
                  "the %d distinct dynamically executed addresses; the ok "
                  "flag is deliberately NOT part of this comparison"
                  % (len(table), len(dyn)),
        "static_instructions_compared": len(table),
        "static_defs_and_uses_identical": len(eq),
        "static_defs_or_uses_differ": len(ne),
        "dynamic_addresses_compared": len(dyn),
        "dynamic_defs_and_uses_identical": sum(1 for i in dyn if i in set(eq)),
        "pre_fix_unclassifiable_instructions": len(flagged),
        "pre_fix_unclassifiable_with_defs_AND_uses_FILLED": len(flagged_parsed),
        "pre_fix_unclassifiable_with_defs_AND_uses_EMPTY": len(flagged_empty),
        "pre_fix_unclassifiable_dynamically_executed": len(flagged_dyn),
        "pre_fix_unclassifiable_dynamically_executed_with_EMPTY_defs_uses":
            sum(1 for i in flagged_empty if i in dyn),
        "dynamic_executions_of_the_flagged_class":
            sum(counts[w][i] for w in counts for i in flagged_dyn),
        "dynamic_executions_of_the_genuinely_blind_class":
            sum(counts[w][i] for w in counts for i in flagged_empty if i in dyn),
        "conclusion": (
            "of the %d pre-fix unclassifiable instructions, %d (including "
            "every one of the %d dynamically executed instances) had defs AND "
            "uses filled with EXACTLY the sets the fixed model computes -- "
            "they were FLAGGED, not invisible.  The remaining %d are the "
            "genuine pre-fix blind class (empty defs and empty uses), and "
            "%d of them are dynamically executed."
            % (len(flagged), len(flagged_parsed), len(flagged_dyn),
               len(flagged_empty),
               sum(1 for i in flagged_empty if i in dyn))),
        "bytes_of_dynamic_path_affected": (
            0 if not [i for i in flagged_empty if i in dyn] else None),
        "differing_detail": [
            {"pc": "0x%X" % table[i]["addr"], "text": table[i]["text"],
             "pre_fix_defs": cls_old[i]["defs"],
             "pre_fix_uses": cls_old[i]["uses"],
             "fixed_defs": cls[i]["defs"], "fixed_uses": cls[i]["uses"],
             "dynamically_executed": i in dyn} for i in ne],
        "dynamic_footprint_of_the_two_real_defects": {
            "note": "The static comparison above includes the `v_cmpx_*_e32` "
                    "role defect (pre-fix: defs=op0, uses=op[1:]; fixed: "
                    "uses=op0+op1, defs=EXEC).  Measured below.",
            "dynamically_executed_instructions_where_the_models_disagree":
                sum(1 for i in ne if i in dyn),
            "by_mnemonic": dict(collections.Counter(
                table[i]["mnem"] for i in ne if i in dyn)),
            "all_instances_have_op0_equal_to_op1":
                all(split_ops(table[i]["ops"])[0] == split_ops(table[i]["ops"])[1]
                    for i in ne if i in dyn
                    and table[i]["mnem"].startswith("v_cmpx")
                    and len(split_ops(table[i]["ops"])) >= 2),
            "consequence": "the operand the pre-fix model drops as a use is "
                           "the SAME register it keeps via op1, so the defect "
                           "is INERT on this trace; the model difference is a "
                           "spurious DEF of op0 (owner[v] := None), which "
                           "could MASK a hazard rather than create one, and "
                           "the fixed model has the correct defs and still "
                           "reports 0 hazards, so nothing is masked in the "
                           "reported verdict."}}

    # ---- where the pre-fix blind spot sat on the dynamic path ------------
    LH, EX, BAR, EXECMAN = 0xBA71C, 0xBA730, 0xBBE20, 0xBBE2C
    blind = []
    for gi in sorted(dyn):
        t = table[gi]
        if cls_old[gi]["ok"]:
            continue
        blind.append({"pc": "0x%X" % t["addr"], "addr": t["addr"],
                      "mnem": t["mnem"], "text": t["text"],
                      "ops_len": len(split_ops(t["ops"])),
                      "exec_count": sum(counts[w][gi] for w in counts),
                      "legacy_reason": cls_old[gi]["reason"],
                      "pre_fix_defs_and_uses_were_empty":
                          not cls_old[gi]["defs"] and not cls_old[gi]["uses"],
                      "fixed_ok": cls[gi]["ok"],
                      "fixed_uses": cls[gi]["uses"],
                      "in_loop_header_to_exit_test": LH <= t["addr"] <= EX,
                      "within_64B_of_barrier_0xBBE20":
                          abs(t["addr"] - BAR) <= 64,
                      "within_64B_of_exec_manipulation_0xBBE2C":
                          abs(t["addr"] - EXECMAN) <= 64})
    blind_exec = sum(b["exec_count"] for b in blind)
    region = [b for b in blind if b["in_loop_header_to_exit_test"]
              or b["within_64B_of_barrier_0xBBE20"]
              or b["within_64B_of_exec_manipulation_0xBBE2C"]]
    # The class that matters for the hazard count is the one the pre-fix model
    # recorded NOTHING for.  The flagged-but-parsed class cannot hide a
    # consumer edge, because the edge is derived from `uses`.
    really_blind = [b for b in blind if b["pre_fix_defs_and_uses_were_empty"]]
    blind_spot = {
        "instructions_the_pre_fix_classifier_flagged_unclassifiable":
            len(blind),
        "dynamic_executions_of_those": blind_exec,
        "split_by_whether_the_pre_fix_model_still_parsed_defs_and_uses": {
            "flagged_but_defs_and_uses_were_FILLED": {
                "instructions": len(blind) - len(really_blind),
                "dynamic_executions": blind_exec
                - sum(b["exec_count"] for b in really_blind),
                "hazard_edge_visible_to_the_pre_fix_model": True},
            "flagged_and_defs_and_uses_were_EMPTY_the_genuine_blind_class": {
                "instructions": len(really_blind),
                "dynamic_executions":
                    sum(b["exec_count"] for b in really_blind),
                "hazard_edge_visible_to_the_pre_fix_model": False}},
        "by_mnemonic": dict(collections.Counter(b["mnem"] for b in blind)),
        "by_operand_count_and_mnemonic": dict(collections.Counter(
            "%s / %d operands" % (b["mnem"], b["ops_len"]) for b in blind)),
        "all_reclassified_ok_by_the_fixed_model":
            all(b["fixed_ok"] for b in blind),
        "address_histogram": dict(collections.Counter(
            "0x%X-0x%X" % (b["addr"] & ~0xFF, (b["addr"] & ~0xFF) + 0xFF)
            for b in blind)),
        "on_the_liveness_critical_region": {
            "definition": "inside [0x%X, 0x%X] (loop header to loop-exit "
                          "test) OR within 64 bytes of the barrier at 0x%X OR "
                          "within 64 bytes of the EXEC manipulation at 0x%X"
                          % (LH, EX, BAR, EXECMAN),
            "instructions_flagged_class": len(region), "dynamic_executions":
                sum(b["exec_count"] for b in region),
            "instructions_of_the_genuine_blind_class":
                len([b for b in region
                     if b["pre_fix_defs_and_uses_were_empty"]]),
            "dynamic_executions_of_the_genuine_blind_class":
                sum(b["exec_count"] for b in region
                    if b["pre_fix_defs_and_uses_were_empty"]),
            "detail": region},
        "detail": blind}

    # ---- verdict ---------------------------------------------------------
    LIVENESS_ROLES = ("branch/control", "address")
    live = [h for h in base["hazards"] if h["role"] in LIVENESS_ROLES]
    barrier_hz = (base["barriers_with_outstanding_vmem"]
                  + base["barriers_with_outstanding_lgkm"])
    vacuous = (base["producers_total"] == 0
               or base["steps_analysed"] == 0
               or base["classified_instructions"] == 0
               or xc["comparisons_performed"] == 0
               or n_addr == 0)
    if vacuous:
        verdict = "VACUOUS"
    elif base["hazards_total"] == 0 and barrier_hz == 0:
        verdict = "PASS"
    else:
        verdict = "FAIL"

    out = {
        "schema": "phase16y-waitcnt-executed-path/1",
        "phase": "16Y PART III -- waitcnt executed-path audit",
        "host_only": True, "gpu_execution_performed": False,
        "kernel_launch_count": 0, "llvm_objcopy_used": False,
        "input": {
            "executed_pcs": os.path.relpath(EXEC_PCS, ROOT).replace("\\", "/"),
            "candidate_sha256_from_j3": J["candidate_sha256"],
            "waves": J["waves"], "ticks": J["ticks"],
            "non_perturbation_verified_against":
                J.get("non_perturbation_verified_against"),
            "emulator_waitcnt_semantics": J["emulator_waitcnt_semantics"]},
        "step1_decoder_validation": dec,
        "raw_word_provenance": rawprov,
        "instruction_table_identity": {
            "entries": len(table_in), "address_matched": n_addr,
            "text_matched": n_text, "text_differences": textdiff,
            "note": "the emulator's decoded program and a fresh disassembly of "
                    "the Candidate F .co agree on all %d addresses and all %d "
                    "instruction texts, so the .co raw words are the raw words "
                    "of the executed program." % (n_addr, n_text)},
        "vop3_operand_fit": {
            "checked": nv3, "mismatches": nv3bad, "details": v3bad,
            "vop3_mnemonics_absent_from_table": nv3missing,
            "absent_details": v3missing,
            "note": "decides, from the raw word, whether a VOP3 instruction "
                    "prints an SDST operand; a wrong answer shows up as an "
                    "operand-count mismatch rather than as a silent mis-parse.",
            "used_by": "classify_legacy() only -- the 'before' arm of the "
                       "negative controls"},
        "valu_form_inventory": inv,
        "op1_role_probe": probe,
        "unclassified_instruction_audit": {
            "pre_fix_classifier_static_unclassifiable": {
                "count": sum(legacy_unclass_static.values()),
                "of": len(table),
                "by_reason": dict(legacy_unclass_static),
                "by_mnemonic": dict(legacy_unclass_mnem)},
            "fixed_classifier_static_unclassifiable": {
                "count": sum(new_unclass_static.values()),
                "of": len(table),
                "by_reason": dict(new_unclass_static)},
            "on_the_dynamic_path_after_the_fix": {
                "instructions": base["unclassified_instructions"],
                "by_reason": base["unclassified_reasons"]},
            "pre_fix_blind_spot_accounting": blind_spot},
        "def_use_model_agreement": model_agreement,
        "dynamic_wait_list": {
            "distinct_executed_waits": len(waits),
            "distinct_executed_s_waitcnt": sum(
                1 for v in waits.values() if v["mnem"] == "s_waitcnt"),
            "distinct_executed_s_waitcnt_depctr": sum(
                1 for v in waits.values() if v["mnem"] == "s_waitcnt_depctr"),
            "distinct_executed_s_waitcnt_vscnt": sum(
                1 for v in waits.values() if v["mnem"] == "s_waitcnt_vscnt"),
            "operand_histogram": dict(collections.Counter(
                v["text"] for v in waits.values())),
            "waits": [waits[k] for k in sorted(waits)]},
        "depctr_context": {
            "operand_histogram": dict(collections.Counter(d["ops"]
                                                          for d in depctx)),
            "occurrences": depctx,
            "modelled_as": "NO effect on the VMEM/LGKM counters in the base "
                           "model (DEPCTR is a separate derived-op counter).  "
                           "The 'depctr_modelled_as_full_fence' sensitivity "
                           "above shows what changes if that is wrong."},
        "def_use_audit": base,
        "tracer_crosscheck": xc,
        "focus_sub_audits": focus,
        "negative_controls": controls,
        "sensitivity": sens,
        "history": HISTORY,
        "verdict": verdict,
        "verdict_basis": {
            "liveness_relevant_hazards_branch_or_address": len(live),
            "all_hazards": base["hazards_total"],
            "hazards_by_role": base["hazards_by_role"],
            "barriers_with_outstanding_memory": barrier_hz,
            "vacuous_input_detected": vacuous},
        "limits": [
            "First-CONSUMER register-level def-use only: a hazard is raised "
            "when the FIRST instruction that reads a producer's destination "
            "register on the dynamic path runs while that producer is still "
            "outstanding.  A dependency that only reaches a branch through two "
            "or more further instructions is not followed.",
            "Per-wave analysis.  Cross-wave ordering through s_barrier is not "
            "provable from one wave's trace; it is covered only by the "
            "barrier-adjacency sub-audit (outstanding-op count AT the barrier).",
            "The dynamic path is the one the emulator retires with waitcnt "
            "bound to _noop.  Dropping a wait cannot change the path there; on "
            "hardware it could in principle change a register value and hence "
            "the path, so the audit checks THIS path, which is the path the "
            "values imply.",
            "s_waitcnt vmcnt/expcnt/lgkmcnt are modelled as counters over an "
            "in-order issue queue ('all but the newest N complete'), the "
            "standard conservative model.  GFX10 splits VMEM loads (vmcnt) "
            "from stores (vscnt); store entries are kept in a separate queue "
            "and never retire a load.  MEASURED support for the split: "
            "Candidate F contains s_waitcnt_vscnt, which only exists if the "
            "counters are separate."]}

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    print("[8] wrote %s" % OUT_JSON)
    print("    VERDICT: %s" % verdict)
    return 0


if __name__ == "__main__":
    sys.exit(main())
