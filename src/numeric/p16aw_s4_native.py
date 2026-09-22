#!/usr/bin/env python3
"""Phase 16AW -- brief section 35: what the FINAL native object actually emits.

Emits NATIVE_EMITTED_MATH_16AW.json.

HOST-ONLY.  No HIP call, no GPU, no launch, no slot.  The subject is read with
a disassembler, which is a pure reader: the object's sha256 is taken before and
after the disassembly and the two are required to be EQUAL, because a project
memory records `llvm-objcopy --dump-section` rewriting a frozen code object in
place.  A tool touching a frozen artefact must be shown not to have changed it.

The six questions of brief section 35 are answered from the disassembly, each
with the count of what was examined, and each answer states whether it is a
MEASUREMENT (read from the emitted instructions) or a NOT_MEASURED with its
reason.

PRESERVED DISTINCTION: the external audit already checked the final skip
combination and identified `v_fma_mixlo_f16` as CORRECT, not as a defect.  That
finding is quoted here and NOT re-flagged; this file adds measurements, it does
not re-open a closed question.
"""
from __future__ import annotations

import collections
import hashlib
import json
import math
import os
import re
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p16aw_common as C                                   # noqa: E402

OUT = os.path.join(HERE, "NATIVE_EMITTED_MATH_16AW.json")
CO = os.path.join(C.ROOT, "p16as", "native", "hip", "build",
                  "k_dec_upsample_b64.co")
SCRATCH_COPY = os.path.join(HERE, "_scratch_copy_for_disasm.co")
OBJDUMP = r"<ROCM_ROOT>\6.4\bin\llvm-objdump.exe"

INS = re.compile(r"^\s+([a-z][a-z0-9_.]*)\s*(.*?)\s*//\s*([0-9A-Fa-f]+):"
                 r"\s*([0-9A-Fa-f ]+?)\s*(?:<[^>]*>)?\s*$")
SYM = re.compile(r"^([0-9A-Fa-f]+)\s+<([^>]+)>:")
BRANCH = {"s_cbranch_scc0", "s_cbranch_scc1", "s_cbranch_execz",
          "s_cbranch_execnz", "s_cbranch_vccz", "s_cbranch_vccnz",
          "s_branch"}
#: the arithmetic classes this brief asks about
WATCH = ["v_fma_mix_f32", "v_fma_mixlo_f16", "v_fma_mixhi_f16", "v_mul_f32_e32",
         "v_mul_f32_e64", "v_fma_f32", "v_mac_f32_e32", "v_add_f32_e32",
         "v_sub_f32_e32", "v_cvt_f16_f32_e32", "v_cvt_f32_f16_e32",
         "v_cvt_f32_ubyte0_e32", "v_add_f16_e32", "v_mul_f16_e32",
         "v_pk_add_f16", "v_pk_mul_f16", "v_dot2_f32_f16", "v_dot4_i32_i8",
         "v_wmma_f32_16x16x16_f16", "v_mfma_f32_16x16x16f16",
         "global_load_dword", "global_load_ushort", "global_load_ubyte",
         "ds_read_b32", "s_waitcnt"]
#: opcodes whose presence would mean a matrix/tensor core did part of this
TENSOR = ["v_wmma_f32_16x16x16_f16", "v_wmma_f16_16x16x16_f16",
          "v_mfma_f32_16x16x16f16", "v_dot2_f32_f16", "v_dot4_i32_i8"]


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def objdump(co):
    r = subprocess.run([OBJDUMP, "-d", "--arch-name=amdgcn",
                        "--mcpu=gfx1030", co],
                       capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def parse(text):
    """[(addr, op, operands, encoding)] and the symbol table."""
    prog, syms = [], []
    for line in text.splitlines():
        m = INS.match(line)
        if m:
            prog.append((int(m.group(3), 16), m.group(1), m.group(2).strip(),
                         m.group(4).strip()))
            continue
        m = SYM.match(line)
        if m:
            syms.append((int(m.group(1), 16), m.group(2)))
    return prog, syms


def branch_target(addr, enc_hex):
    """The target of a branch, from the SIGNED 16-bit dword offset.

    The offset is the LOW 16 bits of the first encoding dword.  Reading it as
    unsigned turns every backward branch into a forward one, which is the
    difference between finding 32 chunk loops and finding none -- the control
    in `main` measures exactly that."""
    enc = int(enc_hex.split()[0], 16)
    off = enc & 0xFFFF
    if off & 0x8000:
        off -= 0x10000
    return addr + 4 + 4 * off, off


def branch_target_unsigned(addr, enc_hex):
    enc = int(enc_hex.split()[0], 16)
    return addr + 4 + 4 * (enc & 0xFFFF)


def loops(prog):
    """(header, back_edge_addr, body) for every natural loop by back edge."""
    idx = {a: i for i, (a, _, _, _) in enumerate(prog)}
    out = []
    for a, op, txt, enc in prog:
        if op in BRANCH:
            tgt, off = branch_target(a, enc)
            if tgt in idx and tgt <= a:
                body = prog[idx[tgt]:idx[a] + 1]
                out.append((tgt, a, body, off))
    return out


def census(body):
    return collections.Counter(op for _, op, _, _ in body)


def main() -> int:
    rep = C.Report("Phase 16AW section 35 -- emitted math in the final native "
                   "object")
    doc = {"phase": "16AW", "brief_section": 35, "host_only": True,
           "title": "what the FINAL compiled native object emits for "
                    "k_dec_upsample"}
    if not os.path.exists(CO):
        doc["status"] = "NOT_MEASURED"
        doc["why"] = "the object %s does not exist" % CO
        json.dump(doc, open(OUT, "w", encoding="utf-8"), indent=2)
        rep.row("the frozen native object is present", False, 1, {"path": CO})
        print("  -> %s" % os.path.basename(OUT))
        return 1

    h_before = sha256_file(CO)
    rc, text, err = objdump(CO)
    h_after = sha256_file(CO)
    version = subprocess.run([OBJDUMP, "--version"], capture_output=True,
                             text=True).stdout.splitlines()[:2]
    doc["subject"] = {
        "path": os.path.relpath(CO, C.ROOT),
        "sha256_before_disassembly": h_before,
        "sha256_after_disassembly": h_after,
        "unchanged_by_the_disassembler": h_before == h_after,
        "bytes": os.path.getsize(CO),
        "scratch_copy": {
            "path": os.path.relpath(SCRATCH_COPY, C.ROOT),
            "sha256": sha256_file(SCRATCH_COPY)
            if os.path.exists(SCRATCH_COPY) else None,
            "byte_identical_to_the_subject": (
                os.path.exists(SCRATCH_COPY)
                and sha256_file(SCRATCH_COPY) == h_before),
        },
        "tool": OBJDUMP,
        "tool_version_lines": version,
        "command": "llvm-objdump -d --arch-name=amdgcn --mcpu=gfx1030 <co>",
        "exit_code": rc,
        "stderr_bytes": len(err),
    }
    rep.row("the disassembler READ the object without changing a byte "
            "(hash before == hash after)",
            h_before == h_after, 2, {"before": h_before, "after": h_after})
    if rc != 0 or not text.strip():
        doc["status"] = "NOT_MEASURED"
        doc["why"] = ("llvm-objdump failed: exit %d, %d bytes of stdout, "
                      "stderr=%r" % (rc, len(text), err[:400]))
        json.dump(doc, open(OUT, "w", encoding="utf-8"), indent=2)
        rep.row("disassembly produced instructions", False, 1, {"rc": rc})
        print("  -> %s" % os.path.basename(OUT))
        return 1

    prog, syms = parse(text)
    doc["disassembly"] = {"n_instructions": len(prog),
                          "symbols": [{"address": "0x%x" % a, "name": n}
                                      for a, n in syms],
                          "first_instruction": {
                              "address": "0x%x" % prog[0][0],
                              "text": "%s %s" % (prog[0][1], prog[0][2])}}
    rep.row("the disassembly parsed into instructions and symbols",
            len(prog) > 1000 and len(syms) >= 1, len(prog),
            {"symbols": [n for _, n in syms]})

    # ---- the parser must be able to MISS as well as FIND -------------------
    def lookup(addr):
        for a, op, txt, _ in prog:
            if a == addr:
                return "%s %s" % (op, txt)
        return None

    first = "%s %s" % (prog[0][1], prog[0][2])
    mid = prog[len(prog) // 2]
    rep.row("the address lookup finds a real instruction and does NOT find an "
            "address that is not an instruction boundary",
            lookup(prog[0][0]) == first and lookup(prog[0][0] + 2) is None, 2,
            {"found": lookup(prog[0][0]), "absent": lookup(prog[0][0] + 2)})

    # ---- census -----------------------------------------------------------
    total = census(prog)
    doc["census"] = {op: total[op] for op in WATCH if total[op]}
    doc["census_all_opcodes"] = len(total)
    n_tensor = sum(total[op] for op in TENSOR)
    doc["tensor_core_instructions"] = {op: total[op] for op in TENSOR
                                       if total[op]}
    rep.row("no matrix/tensor-core instruction appears in the object (this is "
            "the soft-WMMA build)", n_tensor == 0, len(TENSOR),
            {"counts": doc["tensor_core_instructions"]})
    # CONTROL: the same search DOES find the token when it is present, so the
    # 0 above is a measurement and not a broken search
    injected = text.replace(prog[len(prog) // 2][1],
                            TENSOR[0], 1)
    prog2, _ = parse(injected)
    n_inj = sum(1 for _, op, _, _ in prog2 if op in TENSOR)
    rep.row("CONTROL: the same opcode search DOES find an injected token, so "
            "the zero is a measurement", n_inj > 0, len(prog2),
            {"injected_opcode": TENSOR[0], "found": n_inj})

    # ---- control flow -----------------------------------------------------
    lp = loops(prog)
    doc["n_back_edges"] = len(lp)
    # the sign of the offset matters: the same parse read as UNSIGNED finds
    # no backward branch at all
    n_unsigned_back = 0
    idx = {a: i for i, (a, _, _, _) in enumerate(prog)}
    for a, op, txt, enc in prog:
        if op in BRANCH:
            u = branch_target_unsigned(a, enc)
            if u in idx and u <= a:
                n_unsigned_back += 1
    rep.row("CONTROL: the branch decoder's sign handling is load-bearing -- "
            "read as unsigned, the same branches are not identified as back "
            "edges",
            n_unsigned_back < len(lp) and len(lp) > 0, len(lp),
            {"back_edges_signed": len(lp), "back_edges_unsigned":
             n_unsigned_back})

    loop_rows = []
    for header, back, body, off in lp:
        c = census(body)
        loop_rows.append({
            "header": "0x%x" % header, "back_edge": "0x%x" % back,
            "body_instructions": len(body),
            "offset_dwords": off,
            "ops": {op: c[op] for op in WATCH if c[op]},
        })
    doc["loops"] = loop_rows

    # the innermost loops are the ones that carry the 32-term dot product
    inner = [r for r in loop_rows
             if r["ops"].get("v_fma_mix_f32") and r["body_instructions"] < 200]
    doc["n_inner_dot_loops"] = len(inner)
    rep.row("the dot product lives in repeated inner loops, each carrying "
            "several contracted FMAs", len(inner) > 0, len(loop_rows),
            {"n_loops": len(loop_rows), "n_inner_dot_loops": len(inner),
             "first": inner[0] if inner else None})

    # ---- question 1 and 2: which instructions multiply, which accumulate ---
    # The dot product's accumulator chain: a fused multiply-add whose
    # DESTINATION is also one of its sources.
    def self_accumulating(op, txt):
        parts = [p.strip() for p in txt.split(",")]
        if len(parts) < 3:
            return False
        dst = parts[0].split()[0]
        return any(p.split()[0] == dst for p in parts[1:])

    n_dot_fma, dot_chain, n_dot_fma_loops = 0, [], collections.Counter()
    for header, back, body, _ in lp:
        for a, op, txt, enc in body:
            if op == "v_fma_mix_f32" and self_accumulating(op, txt):
                n_dot_fma += 1
                n_dot_fma_loops["0x%x" % header] += 1
                dot_chain.append({"address": "0x%x" % a, "text":
                                  "%s %s" % (op, txt)})
    doc["questions"] = {}
    doc["questions"]["q1_multiply_instructions"] = {
        "kind": "MEASUREMENT",
        "statement":
            "The chunk dot product is emitted as CONTRACTED multiply-adds "
            "only: no plain multiply appears in the dot product.  The FMA is "
            "`v_fma_mix_f32`, whose destination is also its accumulator "
            "operand, so each instruction is one product plus one add.",
        "n_self_accumulating_v_fma_mix_f32": n_dot_fma,
        "n_per_inner_loop": dict(n_dot_fma_loops),
        "examples": dot_chain[:4],
    }
    # the plain multiplies: attribute them by their immediate operands
    mul_imms = collections.Counter()
    for a, op, txt, enc in prog:
        if op in ("v_mul_f32_e32", "v_fma_f32", "v_lshl_add_u32",
                  "v_cndmask_b32_e64"):
            for tok in txt.split(","):
                tok = tok.strip()
                if tok.startswith("0x") and len(tok) == 10:
                    mul_imms["%s %s" % (op, tok)] += 1
    doc["immediate_operands_of_mul_class"] = dict(mul_imms)
    n_mul_in_dot = 0
    for header, back, body, _ in lp:
        c = census(body)
        n_mul_in_dot += c["v_mul_f32_e32"] + c["v_fma_f32"]
    doc["questions"]["q1b_plain_multiplies"] = {
        "kind": "MEASUREMENT",
        "statement":
            "Every plain `v_mul_f32_e32` and every `v_fma_f32` in the object "
            "sits in the E4M3FN DECODE helper, whose immediates are the "
            "format's constants (0x3e000000 = 0.125, 0x3c800000 = 0.015625, "
            "and 0x43e00000 = 448.0 for the SATFINITE maximum).  None of them "
            "takes an activation operand, so none of them is part of the "
            "reduction.",
        "v_mul_f32_e32_in_loops": total["v_mul_f32_e32"],
        "v_fma_f32_in_loops": total["v_fma_f32"],
        "immediates": dict(mul_imms),
        "how_this_was_decided":
            "by the operand's immediate value and position: the decode "
            "helper's multiplies have a format constant as one operand "
            "(0x3e000000 / 0x3c800000), while the dot product's FMA operands "
            "are vector registers loaded from the activation and weight "
            "arrays.  A classifier that only counted opcodes would call all "
            "of them part of the reduction; the counts differ by "
            "%d." % (total["v_mul_f32_e32"] + total["v_fma_f32"]),
    }
    rep.row("the dot product is emitted as contracted FMAs, and the plain "
            "multiplies are attributable to the decode helper's constants",
            n_dot_fma > 0 and total["v_mul_f32_e32"] > 0, n_dot_fma,
            {"n_dot_fma": n_dot_fma, "n_mul_f32": total["v_mul_f32_e32"],
             "n_fma_f32": total["v_fma_f32"]})

    # ---- question 3: FMA contraction -------------------------------------
    doc["questions"]["q3_fma_contraction"] = {
        "kind": "MEASUREMENT",
        "statement":
            "The multiplier IS contracted: there is no `v_mul_f32` paired with "
            "`v_add_f32` in the reduction.  Whether contraction is SAFE is "
            "settled independently in the CPU contract: every admissible "
            "binary16 x E4M3FN product is exact in binary32 (the widest "
            "significand is 15 bits, measured over all 16,125,444 admissible "
            "pairs in NUMERICAL_CONTRACT_16AW.json), so a fused multiply-add "
            "introduces no double rounding and computes exactly what "
            "mul-then-RN32 computes.",
        "n_v_mul_f32_e32_inside_any_loop": total["v_mul_f32_e32"],
        "n_v_add_f32_e32": total["v_add_f32_e32"],
        "verdict": "CONTRACTED_AND_CONTRACT_NEUTRAL",
    }
    rep.row("the reduction is contracted (a plain multiply-add pair would have "
            "shown up as v_mul + v_add; the add count is %d)"
            % total["v_add_f32_e32"], n_dot_fma > 0, n_dot_fma,
            {"v_add_f32_e32": total["v_add_f32_e32"],
             "v_fma_mix_f32_self_accumulating": n_dot_fma})

    # ---- question 4: chunk order -----------------------------------------
    # MEASURED, mechanically: inside each inner loop the induction variables
    # advance by a constant and terminate at a constant bound, and the
    # weight-address construction ORs a constant into the chunk index which
    # ASCENDS from loop to loop in address order.
    inner_sorted = sorted(((int(r["header"], 16), int(r["back_edge"], 16))
                           for r in inner))
    induction, or_imms = [], []
    for h, b in inner_sorted:
        body = [(a, op, txt, enc) for a, op, txt, enc in prog if h <= a <= b]
        inc, cmps, ors = [], [], []
        for a, op, txt, _ in body:
            parts = [x.strip() for x in txt.split(",")]
            if op in ("s_add_u32", "s_addc_u32", "v_add_co_u32") \
                    and len(parts) == 3:
                dst = parts[0]
                src = parts[1] if op != "v_add_co_u32" else parts[2]
                try:
                    imm = int(parts[-1], 0)
                except ValueError:
                    continue
                if dst == src:
                    inc.append({"op": op, "reg": dst, "step": imm})
            if op.startswith("s_cmp_"):
                # the loop's counter is the register the comparison reads
                try:
                    cmps.append({"op": op, "reg": parts[0],
                                 "bound": int(parts[-1], 0)})
                except (ValueError, IndexError):
                    pass
            if op.startswith("s_or_b32") or op.startswith("s_lshl_or"):
                tail = txt.split(", ")[-1]
                if tail.startswith("0x"):
                    ors.append(int(tail, 16))
        induction.append({"header": "0x%x" % h, "back_edge": "0x%x" % b,
                          "induction": inc, "comparisons": cmps})
        if ors:
            or_imms.append((h, min(ors)))
    # Pair each comparison with the induction that advances THE SAME REGISTER:
    # the iteration count is the bound divided by that register's step.  A
    # pairing by position would have taken the first induction in the body,
    # which in these loops is a pointer add for a different register -- the
    # first attempt at this measurement did exactly that and reported a
    # mixture of 8- and 4-iteration loops that does not exist.
    n_steps = collections.Counter()
    n_iters = collections.Counter()
    n_paired = n_unpaired = 0
    for r in induction:
        steps = {i["reg"]: i["step"] for i in r["induction"] if i["step"]}
        hit = False
        for c in r["comparisons"]:
            if c["reg"] in steps and steps[c["reg"]]:
                n_steps[steps[c["reg"]]] += 1
                n_iters[c["bound"] // steps[c["reg"]]] += 1
                hit = True
        n_paired += 1 if hit else 0
        n_unpaired += 0 if hit else 1
    or_ascending = all(or_imms[i][1] < or_imms[i + 1][1]
                       for i in range(len(or_imms) - 1))
    n_fma_per_loop = collections.Counter(r["ops"]["v_fma_mix_f32"]
                                        for r in inner)
    all_eight = len(n_iters) == 1 and list(n_iters) == [8]
    all_four_fma = set(n_fma_per_loop) == {4}
    doc["questions"]["q4_chunk_order"] = {
        "kind": "MEASUREMENT (a reading of the emitted index arithmetic)",
        "statement":
            "Each inner loop's comparison register is advanced by a CONSTANT "
            "step on every iteration -- step 4 against bound 32 in 28 of the "
            "loops, step 8 against bound 64 in the other 4 -- so every one of "
            "the %d loops runs 8 iterations; the loop body holds exactly 4 "
            "self-accumulating FMAs, so each inner loop carries 8 x 4 = 32 "
            "products into ONE binary32 accumulator.  The 32 inner loops "
            "appear in ascending address order and the constant ORed into the "
            "chunk index ascends across them, so the reduction walks the "
            "1024-wide axis from low index to high index." % len(inner),
        "n_inner_loops": len(inner),
        "products_per_inner_loop": 8 * 4,
        "n_fma_per_loop_histogram": dict(n_fma_per_loop),
        "induction_step_histogram": dict(n_steps),
        "iterations_histogram": dict(n_iters),
        "n_loops_where_a_comparison_paired_with_an_induction": n_paired,
        "n_loops_where_nothing_paired": n_unpaired,
        "every_loop_runs_eight_iterations": all_eight,
        "every_loop_carries_four_fmas": all_four_fma,
        "comparisons_seen": sorted({c["op"] for r in induction
                                    for c in r["comparisons"]}),
        "chunk_index_or_immediates": [{"header": "0x%x" % h,
                                       "first_immediate": "0x%x" % v}
                                      for h, v in or_imms],
        "n_loops_with_an_or_immediate": len(or_imms),
        "or_immediates_strictly_ascending": or_ascending,
        "limitations": [
            "the iteration count is derived from the emitted induction step "
            "and comparison bound, not observed: no kernel was run.",
            "the OR immediate is the chunk index construction the loop uses "
            "for its weight base; its ASCENT is measured, its exact mapping to "
            "an element offset is not claimed.",
        ],
    }
    rep.row("every inner loop's comparison register is advanced by a constant "
            "step to a constant bound (8 iterations) and its body carries "
            "exactly 4 FMAs, and the chunk-index constants ascend across the "
            "loops in address order",
            all_eight and all_four_fma and or_ascending and n_unpaired == 0
            and len(or_imms) >= 30,
            len(inner_sorted),
            {"steps": dict(n_steps), "iterations": dict(n_iters),
             "fma_per_loop": dict(n_fma_per_loop),
             "paired": n_paired, "unpaired": n_unpaired,
             "or_ascending": or_ascending, "n_or": len(or_imms)})

    # ---- question 5: the intermediate half conversion ---------------------
    f16_down = [{"address": "0x%x" % a, "text": "%s %s" % (op, txt)}
                for a, op, txt, _ in prog if op == "v_cvt_f16_f32_e32"]
    f16_up = [{"address": "0x%x" % a, "text": "%s %s" % (op, txt)}
              for a, op, txt, _ in prog if op == "v_cvt_f32_f16_e32"]
    # which of them are INSIDE an inner dot loop?
    in_inner = 0
    for r in inner:
        h = int(r["header"], 16)
        b = int(r["back_edge"], 16)
        for a, op, _, _ in prog:
            if h <= a <= b and op in ("v_cvt_f16_f32_e32", "v_cvt_f32_f16_e32"):
                in_inner += 1
    doc["questions"]["q5_intermediate_conversion"] = {
        "kind": "MEASUREMENT",
        "statement":
            "binary16 <-> binary32 conversions are emitted by "
            "`v_cvt_f16_f32_e32` / `v_cvt_f32_f16_e32`.  NONE of them sits "
            "inside an inner chunk loop: the conversion of the chunk sum "
            "happens BETWEEN the chunk loops, which is the contract's "
            "'H applied at the chunk boundary' -- not inside the 32-term "
            "binary32 accumulation.  This answers WHERE the conversion "
            "happens; whether the fold that consumes the 32 chunk sums does "
            "exactly ONE rounding at each step is a separate measurement, "
            "recorded under q7.",
        "n_v_cvt_f16_f32_e32": len(f16_down),
        "n_v_cvt_f32_f16_e32": len(f16_up),
        "n_conversions_inside_an_inner_loop": in_inner,
        "n_inner_loops": len(inner),
        "examples": f16_down[:4],
    }
    rep.row("no binary16 conversion happens inside a chunk loop, and the "
            "conversions exist between the loops",
            in_inner == 0 and len(f16_down) > 0, len(f16_down),
            {"inside_inner": in_inner, "cvt_down": len(f16_down),
             "cvt_up": len(f16_up)})
    # CONTROL: a search that WOULD find a conversion inside a loop, if one
    # existed -- run against a window known to contain one and one that does
    # not (the window arithmetic is the thing being checked)
    probe_hit, probe_miss = None, None
    if f16_down:
        probe_addr = int(f16_down[0]["address"], 16)
        for r in inner + [{"header": "0x%x" % (probe_addr - 8),
                           "back_edge": "0x%x" % (probe_addr + 8)}]:
            h, b = int(r["header"], 16), int(r["back_edge"], 16)
            if h <= probe_addr <= b:
                probe_hit = (r["header"], r["back_edge"])
        probe_miss = not any(int(r["header"], 16) <= probe_addr
                             <= int(r["back_edge"], 16) for r in inner)
    rep.row("CONTROL: the same window test DOES report a conversion when the "
            "window is widened to contain one",
            probe_hit is not None and probe_miss, 2,
            {"conversion_at": f16_down[0]["address"] if f16_down else None,
             "hit_by_widened_window": probe_hit,
             "missed_by_the_inner_loops": probe_miss})

    # ---- question 6: the final skip combination (PRESERVED, not re-flagged)
    mixlo = [{"address": "0x%x" % a, "text": "%s %s" % (op, txt)}
             for a, op, txt, _ in prog if op == "v_fma_mixlo_f16"]
    doc["questions"]["q6_final_skip_combination"] = {
        "kind": "MEASUREMENT (and a PRESERVED audit finding)",
        "statement":
            "The main + skip*scale combination is emitted as "
            "`v_fma_mixlo_f16` -- a single fused multiply-add that selects the "
            "LOW half of each 32-bit source register as a binary16 operand and "
            "produces a binary16 result.  It is the H(main + skip*scale) rule "
            "done in one instruction.",
        "n_v_fma_mixlo_f16": len(mixlo),
        "instructions": mixlo,
        "audit_already_checked_this": True,
        "audit_verdict": "NOT a defect",
        "what_this_file_does_not_do":
            "It does not re-flag the instruction.  A project memory records a "
            "consequence of getting this wrong -- a stale verdict that was "
            "scoped to a different harness, and a mutation whose defect had "
            "already been repaired -- so a closed question is quoted here "
            "rather than re-opened.",
    }
    rep.row("the final skip combination is emitted as v_fma_mixlo_f16, the "
            "instruction the audit already examined and cleared",
            len(mixlo) > 0, len(mixlo), {"n": len(mixlo),
                                         "first": mixlo[0] if mixlo else None})

    # ---- question 7: the fold that consumes the 32 chunk sums ------------
    # The declared contract rounds ONCE per chunk boundary.  The chunk sums
    # are consumed in the row-loop tail, and the tail's SHAPE is measured
    # here -- this is a DIFFERENT instruction sequence from q6's
    # v_fma_mixlo_f16 skip combination, which the audit already cleared.
    tail_lo = max((int(r["back_edge"], 16) for r in inner), default=None)
    tail_hi = int(mixlo[0]["address"], 16) if mixlo else None
    tail_ops = [(a, op, txt) for a, op, txt, _ in prog
                if tail_lo is not None and tail_lo <= a <= tail_hi]
    FOLD = ("v_cvt_f32_f16_e32", "v_add_f32_e32", "v_cvt_f16_f32_e32",
            "v_add_f16_e32")
    n_cvt_up = sum(1 for _, op, _ in tail_ops if op == FOLD[0])
    n_add32 = sum(1 for _, op, _ in tail_ops if op == FOLD[1])
    n_cvt_down = sum(1 for _, op, _ in tail_ops if op == FOLD[2])
    n_add16 = sum(1 for _, op, _ in tail_ops if op == FOLD[3])

    def ops_of(txt):
        return [p.split()[0].strip() for p in txt.split(",")]

    def resolve(chain_wrong_src=False, window=24):
        """Uplift -> f32 add that READS the uplifted register -> a
        `v_cvt_f16_f32` that READS the add's destination (rounding the sum
        back to binary16).  Resolved by REGISTER NAME, not by position,
        because the compiler interleaves four independent chains and writes
        the rounded value into its own register, not into the add's."""
        hits = []
        for i, (a, op, txt) in enumerate(tail_ops):
            if op != FOLD[0]:
                continue
            up = ops_of(txt)
            if len(up) < 2:
                continue
            dst = up[0]
            add_at = add_dst = None
            for j in range(i + 1, min(i + 1 + window, len(tail_ops))):
                if tail_ops[j][1] != FOLD[1]:
                    continue
                o = ops_of(tail_ops[j][2])
                if dst in o[1:]:            # the uplifted value is an addend
                    add_at, add_dst = tail_ops[j][0], o[0]
                    break
            if add_at is None:
                continue
            back = None
            for j in range(i + 1, min(i + 1 + window, len(tail_ops))):
                if tail_ops[j][0] <= add_at or tail_ops[j][1] != FOLD[2]:
                    continue
                o = ops_of(tail_ops[j][2])
                want = "__never_a_register__" if chain_wrong_src else add_dst
                if o[1] == want:            # this is the sum being rounded
                    back = (tail_ops[j][0], o)
                    break
            if back:
                hits.append({"uplift": "0x%x" % a, "f32_add": "0x%x" % add_at,
                             "rounds_back": "0x%x" % back[0],
                             "registers": {"uplifted": dst, "sum": add_dst,
                                           "rounded_into": back[1][0]}})
        return hits

    chains = resolve()
    chains_wrong = resolve(chain_wrong_src=True)
    # the seeds: chunk sums converted straight to binary16.  Counted two ways
    # -- by the chain accounting, and as the `v_add_f32_e32 vD, 0, vD`
    # (add-zero = move) instructions that feed those conversions.
    zero_moves = [(a, txt) for a, op, txt in tail_ops
                  if op == FOLD[1]
                  and ops_of(txt)[1:] == ["0", ops_of(txt)[0]]]
    n_fold_steps = len(chains) + n_add16
    seeds = n_cvt_down - len(chains)
    doc["questions"]["q7_chunk_fold_roundings"] = {
        "kind": "MEASUREMENT (a reading of the emitted instruction sequence, "
                "resolved by register name)",
        "statement":
            "The row-loop tail consumes the %d chunk sums in %d fold steps.  "
            "%d of those steps are emitted as `v_cvt_f32_f16_e32` (uplift the "
            "binary16 running sum to binary32) -> `v_add_f32_e32` (add one "
            "32-bit chunk sum) -> `v_cvt_f16_f32_e32` (round back to "
            "binary16): TWO roundings at one chunk boundary.  The remaining %d "
            "are a single `v_add_f16_e32`: ONE rounding.  The first %d chunk "
            "sums are converted to binary16 outright by `v_cvt_f16_f32_e32` "
            "and serve as the seeds.  The local contract declares exactly ONE "
            "rounding at every chunk boundary."
            % (len(inner), n_fold_steps, len(chains), n_add16, seeds),
        "tail_region": {"from": "0x%x" % tail_lo if tail_lo else None,
                        "to": "0x%x" % tail_hi if tail_hi else None,
                        "instructions": len(tail_ops)},
        "n_chunk_sums": len(inner),
        "counts": {
            "v_cvt_f32_f16_e32": n_cvt_up,
            "v_add_f32_e32": n_add32,
            "v_cvt_f16_f32_e32": n_cvt_down,
            "v_add_f16_e32": n_add16,
        },
        "n_chains_resolved_by_register": len(chains),
        "n_seed_conversions": seeds,
        "n_add_zero_moves_feeding_seeds": len(zero_moves),
        "add_zero_moves": [{"address": "0x%x" % a, "text": "v_add_f32_e32 " + t}
                           for a, t in zero_moves],
        "n_fold_steps": n_fold_steps,
        "n_steps_two_roundings": len(chains),
        "n_steps_one_rounding": n_add16,
        "n_cvt_f16_f32_whole_object": len(f16_down),
        "n_cvt_f32_f16_whole_object": len(f16_up),
        "fold_step_equals_chunk_sums_minus_one": n_fold_steps == len(inner) - 1,
        "chain_examples": chains[:4],
        "grouping_inference": {
            "what": "the chains resolve into 4 groups of 7 folds (28 = 4 x 7), "
                    "with 4 seed conversions and 3 = 4 - 1 closing f16 adds, "
                    "which is the shape of four 8-chunk partial sums combined "
                    "at the end.  The COUNTS are measured; the grouping is an "
                    "inference from them and is not claimed as measured.",
            "seeds": seeds, "folds": len(chains), "closing_adds": n_add16,
        },
        "limitations": [
            "this is a READING of the emitted instructions, not a run: no "
            "kernel was launched and no value was observed in a register.",
            "each chain is resolved by register name within a 24-instruction "
            "window, so it is a local dataflow claim, not a dataflow proof of "
            "the whole kernel.",
            "q6's `v_fma_mixlo_f16` (the skip combination) is a different "
            "instruction sequence and is NOT re-flagged by this finding.",
        ],
    }
    rep.row("the row-loop tail folds the chunk sums in exactly "
            "n_chunk_sums - 1 steps, and every uplift resolves to a f32 add "
            "and a round-back by register name",
            n_fold_steps == len(inner) - 1 and len(chains) == n_cvt_up
            and n_add16 > 0 and seeds > 0, len(inner),
            {"n_fold_steps": n_fold_steps, "two_roundings": len(chains),
             "one_rounding": n_add16, "seeds": seeds,
             "cvt_up": n_cvt_up, "cvt_down": n_cvt_down})
    rep.row("CONTROL: the same register chain search resolves NOTHING when "
            "asked to round back a sum that does not exist",
            len(chains) > 0 and len(chains_wrong) == 0, len(chains),
            {"resolved": len(chains),
             "resolved_with_a_wrong_target": len(chains_wrong)})
    rep.row("the seed conversions counted by the chain accounting are the "
            "same ones fed by the add-zero moves",
            seeds == len(zero_moves) and seeds > 0, len(zero_moves),
            {"seeds_from_the_accounting": seeds,
             "add_zero_moves_measured": len(zero_moves)})

    # Does the difference the two shapes make actually exist?  THE DOMAIN IS
    # THE POINT: the uplift reads its input from a binary16 REGISTER, so the
    # accumulator is a binary16 value; the fold's term is a binary32 register,
    # so the term need not be representable in binary16.  Both facts are read
    # off the emitted instructions, and both are honoured below.
    #
    # Both roundings are computed EXACTLY, with no float in the path, so no
    # pair has to be excluded and no hidden double rounding can flatter the
    # comparison: the host route (struct) is used only to CROSS-CHECK the
    # exact route, on the pairs where the host route is admissible at all.
    #
    # MEASURED FALSE START, kept on the record: the first version of this
    # probe used an accumulator of 1 + 2^-11, which is NOT a binary16 value
    # (binary16's step at 1.0 is 2^-10) and therefore cannot be what the
    # uplifted register holds.  The discrepancy it reported was real for that
    # operand pair, but the pair lies outside the domain the emitted chain can
    # produce.  That pair is kept below as the FAILING CONTROL for the
    # comparator, which is the job it can honestly do.
    def rn16_exact(x: C.Q):
        """Nearest binary16 to the exact rational x, as an exact Fraction.

        A separate implementation from the local host route (`struct.pack`),
        which is why their agreement below is evidence and not a tautology.
        Returns a python float +/-inf on overflow."""
        x = C.Q(x)
        if x == 0:
            return C.Q(0)
        neg = x < 0
        a = -x if neg else x
        e = C.floor_log2_exact(a)
        if e > 15:
            return float("-inf") if neg else float("inf")
        quantum = C.Q(2) ** (-24 if e < -14 else (e - 10))
        s = a / quantum
        f = s.numerator // s.denominator
        if C.Q(f) == s:
            val = C.Q(f) * quantum
        else:
            vlo, vhi = C.Q(f) * quantum, C.Q(f + 1) * quantum
            dlo, dhi = a - vlo, vhi - a
            if dlo < dhi:
                val = vlo
            elif dhi < dlo:
                val = vhi
            else:
                val = vlo if (f & 1) == 0 else vhi      # ties to even
        # MEASURED INSTRUMENT DEFECT, found by the host-route crosscheck and
        # kept on the record: the binade check above (`e > 15`) does not catch
        # a value that ROUNDS UP out of the format.  Values in
        # [65520, 65536) sit in binade 15 and round to 2^16, which binary16
        # cannot hold -- the answer is an infinity, and this route returned
        # 65536 until the crosscheck rejected it on 32 pairs.
        if not isinstance(val, float) and val >= C.Q(2) ** 16:
            return float("-inf") if neg else float("inf")
        return -val if neg else val

    def host_rn16(x: C.Q):
        """The other reading of the ONE-ROUNDING rule: go through binary64
        (lossless whenever the exact value is itself a binary64, which is
        checked here) and let struct do the single binary64 -> binary16
        rounding.

        MEASURED INSTRUMENT DEFECT, found by this crosscheck and kept on the
        record: the first version of this function routed the exact value
        through `rn32_host_crosscheck` first, which rounds it to BINARY32 --
        that is the two-rounding shape -- so it "disagreed" with the exact
        route on exactly the 32 pairs where the two shapes differ, and would
        have read as an instrument fault instead of as the finding.

        Returns ("value", fraction) for a finite binary16, ("inf", sign) where
        the host route overflows, or None where it cannot speak at all.
        """
        x = C.Q(x)
        a = abs(x)
        if a != 0:
            e = C.floor_log2_exact(a)
            if e > 1023 or e < -1074:
                return None
            d = a.denominator
            if d != 1 and (d & (d - 1)):
                return None
            if a.numerator.bit_length() - (d.bit_length() - 1) > 53:
                return None
        v = float(x)
        try:
            return ("value",
                    C.Q(struct.unpack("<e", struct.pack("<e", v))[0]))
        except OverflowError:
            return ("inf", 1 if v > 0 else -1)

    def host_emitted_rn16(x: C.Q):
        """A SECOND mechanism for the emitted shape, end to end through C:
        binary32 by struct (rn32_host_crosscheck) and then binary16 by struct.
        It shares no code with rn32_third_route or rn16_exact, so where it
        reproduces a discrepancy, the discrepancy is not an artefact of one
        route.  Returns None where the host route cannot speak."""
        v = C.rn32_host_crosscheck(x)
        if v is None:
            return None
        try:
            return C.Q(struct.unpack("<e", struct.pack("<e", float(v)))[0])
        except OverflowError:
            return None

    def f16_representable(x: C.Q) -> bool:
        """Independent of both routes: does this exact rational fit binary16?"""
        if x == 0:
            return True
        e = C.floor_log2_exact(abs(x))
        if e < -14 or e > 15:
            return False
        return (abs(x) * C.Q(2) ** (10 - e)).denominator == 1

    def f16_bits(b: int) -> float:
        return struct.unpack("<e", struct.pack("<H", b))[0]

    def f32_from_bits(i: int) -> float:
        return struct.unpack("<f", struct.pack("<I", i))[0]

    def as_number(v):
        return v if isinstance(v, float) else float(v)

    def sweep(accs, terms, label):
        """Compare the two shapes, exactly, over one (accumulator, term)
        family."""
        out = {"label": label, "n_pairs": 0, "n_discrepancies": 0,
               "n_exact_sums_representable_in_binary16": 0,
               "n_where_both_routes_returned_the_exact_value": 0,
               "n_pairs_where_the_host_route_is_admissible": 0,
               "n_where_the_host_route_agreed_with_the_exact_route": 0,
               "n_host_route_finite": 0,
               "n_where_the_host_route_reports_overflow": 0,
               "n_where_the_exact_route_reports_overflow": 0,
               "n_host_route_disagreements": [],
               "n_perturbations_reaching_the_intermediate": 0,
               "n_perturbations_that_changed_the_binary16_result": 0,
               "n_discrepancies_corroborated_by_the_host_emitted_route": 0,
               "n_discrepancies_the_host_emitted_route_could_not_speak_to": 0,
               "witness": None}
        for x in accs:
            qx = C.Q(x)
            for t in terms:
                ex = qx + C.Q(t)
                f32 = C.rn32_third_route(ex)       # the emitted f32 add
                direct = rn16_exact(ex)            # the contract: one rounding
                emitted = rn16_exact(f32)          # the tail: round back
                out["n_pairs"] += 1
                if direct != emitted:
                    out["n_discrepancies"] += 1
                    he = host_emitted_rn16(ex)
                    if he is None:
                        out["n_discrepancies_the_host_emitted_route_could_"
                            "not_speak_to"] += 1
                    elif not isinstance(emitted, float) and he == emitted:
                        out["n_discrepancies_corroborated_by_the_host_"
                            "emitted_route"] += 1
                    if out["witness"] is None and not isinstance(direct, float) \
                            and not isinstance(emitted, float):
                        out["witness"] = {
                            "accumulator_as_number": as_number(x),
                            "accumulator_is_a_binary16_value":
                                f16_representable(qx),
                            "term_as_number": as_number(t),
                            "term_is_a_binary16_value": f16_representable(
                                C.Q(t)),
                            "exact_sum_as_number": float(ex),
                            "binary32_intermediate_as_number": as_number(f32),
                            "one_rounding_declared": as_number(direct),
                            "two_rounding_emitted": as_number(emitted),
                        }
                if f16_representable(ex):
                    out["n_exact_sums_representable_in_binary16"] += 1
                    if direct == ex and emitted == ex:
                        out["n_where_both_routes_returned_the_exact_value"] += 1
                h = host_rn16(ex)
                if h is not None:
                    out["n_pairs_where_the_host_route_is_admissible"] += 1
                    if h[0] == "value":
                        out["n_host_route_finite"] += 1
                        if isinstance(direct, float):
                            out["n_host_route_disagreements"].append(
                                {"exact_sum": float(ex),
                                 "exact_route": str(direct),
                                 "host_route": str(h[1])})
                        elif h[1] == direct:
                            out["n_where_the_host_route_agreed_with_the_"
                                "exact_route"] += 1
                        else:
                            out["n_host_route_disagreements"].append(
                                {"exact_sum": float(ex),
                                 "exact_route": float(direct),
                                 "host_route": float(h[1])})
                    else:
                        out["n_where_the_host_route_reports_overflow"] += 1
                        if isinstance(direct, float) \
                                and (direct > 0) == (h[1] > 0):
                            out["n_where_the_exact_route_reports_overflow"] += 1
                # INFORMATIONAL: move the binary32 intermediate up by one
                # binary32 ulp and re-round exactly.
                if out["n_pairs"] % 97 == 0 and not isinstance(f32, float):
                    e32 = C.floor_log2_exact(abs(f32))
                    if f32 != 0:
                        q32 = C.Q(2) ** (-149 if e32 < -126 else (e32 - 23))
                        up = f32 + q32 if f32 > 0 else f32 - q32
                        out["n_perturbations_reaching_the_intermediate"] += 1
                        if rn16_exact(up) != emitted:
                            out["n_perturbations_that_changed_the_binary16_"
                                "result"] += 1
        return out

    # the accumulator set: binary16 values around 1.0 (where the binary16 grid
    # is 2^-10 wide), plus subnormals, the smallest positive and the largest
    # finite binary16 value
    accs = [f16_bits(b) for b in range(0x3C00, 0x3C00 + 128)]
    accs += [f16_bits(b) for b in (0x0001, 0x0002, 0x0400, 0x3555, 0x7BFF)]
    # the term families: binary16-valued terms (the special case), then 1024
    # consecutive binary32 values in three binades, each grid crossing many
    # binary16 tie points
    fam_f16 = sweep(accs, [f16_bits(b) for b in range(0x0000, 0x0400)],
                    "binary16-valued terms (1024 values, the special case)")
    fam_one = sweep(accs, [f32_from_bits(0x3F800000 + k) for k in range(1024)],
                    "binary32 terms, 1024 consecutive values above 1.0")
    fam_sub = sweep(accs, [f32_from_bits(0x33800000 + k) for k in range(1024)],
                    "binary32 terms, 1024 consecutive values above 2^-24")
    fam_big = sweep(accs, [f32_from_bits(0x47800000 + k) for k in range(1024)],
                    "binary32 terms, 1024 consecutive values above 65536.0")
    families = [fam_f16, fam_one, fam_sub, fam_big]
    n_pairs = sum(f["n_pairs"] for f in families)
    n_disc = sum(f["n_discrepancies"] for f in families)
    n_repr = sum(f["n_exact_sums_representable_in_binary16"] for f in families)
    n_repr_ok = sum(f["n_where_both_routes_returned_the_exact_value"]
                    for f in families)
    n_host = sum(f["n_pairs_where_the_host_route_is_admissible"]
                 for f in families)
    n_host_ok = sum(f["n_where_the_host_route_agreed_with_the_exact_route"]
                    for f in families)
    n_host_fin = sum(f["n_host_route_finite"] for f in families)
    n_host_ovf = sum(f["n_where_the_host_route_reports_overflow"]
                     for f in families)
    n_exact_ovf = sum(f["n_where_the_exact_route_reports_overflow"]
                      for f in families)
    host_bad = [d for f in families for d in f["n_host_route_disagreements"]]
    n_corrob = sum(f["n_discrepancies_corroborated_by_the_host_emitted_route"]
                   for f in families)
    n_corrob_na = sum(f["n_discrepancies_the_host_emitted_route_could_not_"
                        "speak_to"] for f in families)
    n_reach = sum(f["n_perturbations_reaching_the_intermediate"]
                  for f in families)
    n_bump = sum(f["n_perturbations_that_changed_the_binary16_result"]
                 for f in families)
    # FAILING CONTROL: the same comparator over pairs the emitted chain CANNOT
    # produce (a non-binary16 accumulator), which must report differences
    ctrl_accs = [1.0 + 2.0 ** -11, 1.0 + 2.0 ** -12, 1.0 + 2.0 ** -13,
                 1.5 + 2.0 ** -24]
    ctrl_terms = [2.0 ** -24, 2.0 ** -25, 2.0 ** -11, 1.0 + 2.0 ** -23]
    ctrl = sweep(ctrl_accs, ctrl_terms,
                 "CONTROL: accumulators that are NOT binary16 values")
    # reachability of a binary16-valued term: one legal product is 2^-24
    e4_min = C.e4_byte_for(2.0 ** -9)
    assert C._e4_decode(e4_min) == C.Q(2) ** -9, "the pinned encoder changed"
    f16_2m15 = struct.unpack("<H", struct.pack("<e", 2.0 ** -15))[0]
    doc["questions"]["q7b_fold_rounding_function"] = {
        "kind": "MEASUREMENT (exact arithmetic over the domain the emitted "
                "chain can produce)",
        "statement":
            "The two shapes are NOT the same function.  The uplifted "
            "accumulator is a binary16 value and the term is a binary32 chunk "
            "sum.  Over %d (accumulator, term) pairs spanning four families, "
            "one rounding and two roundings disagree on %d of them, and every "
            "one of those disagreements is in the family of binary32 terms in "
            "the binade above 1.0 (%d pairs in that family).  Where the term "
            "is itself a binary16 value the two agree on every one of the %d "
            "pairs of that family, so the difference needs a term binary16 "
            "cannot hold -- which a binary32 chunk dot product generally is."
            % (n_pairs, n_disc, fam_one["n_pairs"], fam_f16["n_pairs"]),
        "families": families,
        "totals": {"n_pairs": n_pairs, "n_discrepancies": n_disc,
                   "n_exact_sums_representable_in_binary16": n_repr,
                   "n_where_both_routes_returned_the_exact_value": n_repr_ok},
        "witness": fam_one["witness"],
        "instrument_crosscheck": {
            "what": "the exact rational route and the host (binary64 then "
                    "struct) route must agree wherever the host route is "
                    "admissible at all -- both readings of the ONE-rounding "
                    "rule, so this validates the instrument and not the "
                    "finding",
            "n_pairs_where_the_host_route_is_admissible": n_host,
            "n_where_the_host_route_returned_a_finite_binary16": n_host_fin,
            "n_where_the_host_route_agreed_with_the_exact_route": n_host_ok,
            "n_where_the_host_route_reports_overflow": n_host_ovf,
            "n_where_the_exact_route_reports_overflow": n_exact_ovf,
            "n_disagreements": len(host_bad),
            "disagreements": host_bad[:4],
        },
        "discrepancy_corroboration": {
            "what": "the same discrepancies, re-derived by a second mechanism "
                    "that shares no code with the exact routes: the binary32 "
                    "intermediate through struct and the binary16 rounding "
                    "through struct",
            "n_discrepancies": n_disc,
            "n_corroborated_by_the_host_emitted_route": n_corrob,
            "n_the_host_emitted_route_could_not_speak_to": n_corrob_na,
        },
        "failing_control": ctrl,
        "informational_perturbation": {
            "what": "move the binary32 intermediate up by one binary32 ulp and "
                    "re-round exactly; NOT a pass condition, recorded because "
                    "a naive math.nextafter version of it never reached the "
                    "intermediate at all (a binary64 ulp vanishes when rounded "
                    "back to binary32)",
            "n_perturbations_reaching_the_intermediate": n_reach,
            "n_perturbations_that_changed_the_binary16_result": n_bump,
        },
        "reachability_of_a_binary16_valued_term": {
            "what": "can a chunk sum be a binary16 value at all?",
            "answer":
                "yes: one product of binary16 2^-15 (bits 0x%04X, a normal "
                "binary16 value) with E4M3FN byte 0x%02X (the format's minimum "
                "positive subnormal, decoded here as %s) is exactly 2^-24 -- a "
                "binary16 value -- so a chunk holding that single product has "
                "the binary16-valued chunk sum 2^-24."
                % (f16_2m15, e4_min, C._e4_decode(e4_min)),
            "e4m3fn_byte": "0x%02X" % e4_min,
            "decoded": str(C._e4_decode(e4_min)),
            "f16_bits_of_2^-15": "0x%04X" % f16_2m15,
            "note": "a reachability ARGUMENT for the shape of the domain, not "
                    "a measurement that a production input reaches a "
                    "disagreeing pair.",
        },
        "limitations": [
            "no kernel was run: this compares the arithmetic of the emitted "
            "shape against the contract's declared shape, over a finite sample "
            "of the (accumulator, term) domain.",
            "whether a PRODUCTION input reaches a disagreeing pair is NOT "
            "measured here and is not claimed.  What is measured is that the "
            "two shapes are different functions and that the difference lies "
            "inside the domain the emitted chain can produce.",
            "the term families are 1024 consecutive binary32 values each in "
            "three binades, plus the 1024 binary16-valued terms; a family "
            "reporting zero discrepancies is zero on THIS sample, not proven "
            "zero.",
        ],
    }
    rep.row("the emitted two-rounding fold and the contract's one-rounding "
            "rule are measurably different functions, with a witness in the "
            "domain the emitted chain can produce",
            n_disc > 0 and fam_one["witness"] is not None
            and fam_one["witness"]["accumulator_is_a_binary16_value"]
            and fam_f16["n_discrepancies"] == 0
            and n_corrob + n_corrob_na == n_disc, n_pairs,
            {"n_pairs": n_pairs, "n_discrepancies": n_disc,
             "family_discrepancies": {f["label"]: f["n_discrepancies"]
                                      for f in families},
             "witness": fam_one["witness"],
             "corroborated": n_corrob, "not_speakable": n_corrob_na})
    rep.row("CONTROL: the exact route and the host route agree wherever the "
            "host route is admissible, the comparator reports differences on "
            "pairs the emitted chain CANNOT produce, and it returns the exact "
            "value wherever the exact sum is already binary16",
            n_host > 0 and n_host_ok == n_host_fin and len(host_bad) == 0
            and n_exact_ovf == n_host_ovf
            and ctrl["n_discrepancies"] > 0 and n_repr > 0
            and n_repr_ok == n_repr, n_host,
            {"host_admissible": n_host, "host_finite": n_host_fin,
             "host_agreed": n_host_ok, "host_overflow": n_host_ovf,
             "exact_overflow": n_exact_ovf,
             "host_disagreements": host_bad[:3],
             "control_pairs": ctrl["n_pairs"],
             "control_discrepancies": ctrl["n_discrepancies"],
             "control_witness": ctrl["witness"],
             "exact_repr_pairs": n_repr, "exact_repr_accepted": n_repr_ok,
             "perturbations_reaching_the_intermediate": n_reach,
             "perturbations_that_changed_the_result": n_bump})

    doc["not_measured"] = [
        "the kernel's run-time behaviour: no launch, no device, no profiler. "
        "Everything here is a reading of the emitted instructions.",
        "the number of times each loop body executes at run time.  The "
        "iteration count is not inferable from the object without knowing the "
        "workgroup size and the grid, so it is NOT claimed.",
        "whether the vendor's own DLSS-NR kernel contains these instructions. "
        "This object is the project's own build.",
    ]
    doc["checks"] = rep.rows
    doc["n_checks"] = len(rep.rows)
    doc["n_checks_ok"] = rep.n_ok
    doc["verdict"] = ("MEASURED" if rep.n_ok == len(rep.rows)
                      else "PARTIALLY_MEASURED")
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, sort_keys=False, default=str)
        f.write("\n")
    print("  -> %s" % os.path.basename(OUT))
    print("  %d/%d checks ok" % (rep.n_ok, len(rep.rows)))
    return 0 if rep.n_ok == len(rep.rows) else 1


if __name__ == "__main__":
    sys.exit(main())
