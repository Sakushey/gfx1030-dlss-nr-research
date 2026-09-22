#!/usr/bin/env python3
"""Phase 16AM -- build TRUTH_VECTORS_16AM.json from the ISA, not the emulator.

WHY THIS FILE EXISTS SEPARATELY FROM THE RUNNER

The audit finding is that the frozen host emulator omitted SCC side effects.
The obvious way to write a conformance vector is to run the emulator and
record what it did -- and that is precisely the defect being audited, because
it makes the emulator the definition of correctness.  Every expected value in
this file is therefore computed here, in plain Python integer arithmetic,
from the ISA sentence quoted alongside it.  The emulator is never imported,
never executed, and does not appear in this file at all.

THE ONE DESIGN RULE THAT MAKES THE VECTORS ABLE TO FAIL

For every instruction whose ISA rule *overwrites* SCC, the vector's incoming
SCC is set to the NEGATION of the expected SCC.  A handler that omits the
write therefore leaves the pre-set opposite value behind and fails.  Without
that rule a "no write" implementation would pass every vector whose expected
SCC happens to be 0, and the suite would read as strict while rejecting
nothing.  The property is asserted in `assert_scc_in_can_detect_omission`.

`S_ADDC_U32` is the exception: there SCC is a genuine INPUT (the carry-in),
so both carry-in 0 and carry-in 1 vectors are supplied and the negation rule
does not apply.

CITATION CAVEAT -- THE OCR COLUMN LAG

In `phase16r/isa/ref/rdna2_isa.txt` the SOP2 opcode table (section 12.1,
~lines 5236-5435) is OCR-interleaved: the "Description" column runs four
opcodes behind the "Opcode/Name" column, and each opcode occupies exactly two
lines.  The pairing used below was established by the opcode-name captions,
which are distinct per instruction ("Bitwise AND." vs "Logical shift left."
vs "Minimum of two signed integers."), and is corroborated independently by
the summary tables -- Table 11 (line 1898) for arithmetic and Table 14
(line 1982) for bit-wise.  Where a citation is a description body rather than
a table row, the file records the exact line numbers so a reader can read the
surrounding lines and check the pairing themselves.

This file writes ONLY p16am/semantic/TRUTH_VECTORS_16AM.json.
Host-only: no GPU, no HIP, no kernel, no system setting.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SEM = HERE
ROOT = os.path.dirname(os.path.dirname(SEM))
OUT = os.path.join(SEM, "TRUTH_VECTORS_16AM.json")

ISA = "phase16r/isa/ref/rdna2_isa.txt"
U32 = 0xFFFFFFFF

# ---------------------------------------------------------------- ISA quotes
Q_SCC_OVERVIEW = {
    "lines": [1891],
    "quote": "   · Bit/logical operations: 1 = result was not zero.",
    "rule": "SCC = (result != 0)",
}
Q_TABLE14_BITWISE = {
    "lines": [1991, 1993],
    "quote": "{S_AND,S_OR,S_XOR}_{B32,B64}           SOP2        y"
             "         D = S0 & S1, S0 OR S1, S0 XOR S1\n"
             "{S_ANDN2,S_ORN2}_{B32,B64}             SOP2        y"
             "         D = S0 & ~S1, S0 OR ~S1, S0 XOR ~S1,",
    "rule": "the bit-wise SOP2 group sets SCC",
}
Q_TABLE14_SHIFT = {
    "lines": [1997, 1999, 2001],
    "quote": "S_LSHL_{B32,B64}                       SOP2        y"
             "         D = S0 << S1[4:0], [5:0] for B64.\n"
             "S_LSHR_{B32,B64}                       SOP2        y"
             "         D = S0 >> S1[4:0], [5:0] for B64.\n"
             "S_ASHR_{I32,I64}                       SOP2        y"
             "         D = sext(S0 >> S1[4:0]) ([5:0] for I64).",
    "rule": "the SOP2 shift group sets SCC",
}
Q_TABLE14_SHIFT_NOTE = \
    "Table 14 gives the SCC column but not the value; the value comes from "\
    "the per-opcode body (SCC = (D != 0))."

# per-instruction citation: (lines, quote, rule)
CIT = {
    "s_and_b32": ([5303, 5304],
                  "                              D = S0 & S1;\n"
                  "18      S_XOR_B32             SCC = (D != 0).",
                  "D = S0 & S1; SCC = (D != 0)  [opcode 14 S_AND_B32]"),
    "s_or_b32": ([5311, 5312],
                 "                              D = S0 | S1;\n"
                 "22      S_ORN2_B32            SCC = (D != 0).",
                 "D = S0 | S1; SCC = (D != 0)  [opcode 16 S_OR_B32]"),
    "s_xor_b32": ([5319, 5320],
                  "                              D = S0 ^ S1;\n"
                  "                              SCC = (D != 0).",
                  "D = S0 ^ S1; SCC = (D != 0)  [opcode 18 S_XOR_B32]"),
    "s_and_not1_b32": ([5327, 5328],
                       "                              D = S0 & ~S1;\n"
                       "                              SCC = (D != 0).",
                       "D = S0 & ~S1; SCC = (D != 0)  [opcode 20 "
                       "S_ANDN2_B32; this revision's disassembly spells it "
                       "s_and_not1_b32]"),
    "s_andn2_b32": ([5327, 5328],
                    "                              D = S0 & ~S1;\n"
                    "                              SCC = (D != 0).",
                    "same instruction as s_and_not1_b32 (opcode 20 "
                    "S_ANDN2_B32); the emulator aliases the two names"),
    "s_lshl_b32": ([5373, 5374],
                   "                              D.u = S0.u << S1.u[4:0];\n"
                   "                              SCC = (D.u != 0).",
                   "D.u = S0.u << S1.u[4:0]; SCC = (D.u != 0)  "
                   "[opcode 30 S_LSHL_B32]"),
    "s_lshr_b32": ([5381, 5382],
                   "                              D.u = S0.u >> S1.u[4:0];\n"
                   "                              SCC = (D.u != 0).",
                   "D.u = S0.u >> S1.u[4:0]; SCC = (D.u != 0)  "
                   "[opcode 32 S_LSHR_B32]"),
    "s_ashr_i32": ([5389, 5390],
                   "                              D.i = signext(S0.i) >> S1.u[4:0];\n"
                   "                              SCC = (D.i != 0).",
                   "D.i = signext(S0.i) >> S1.u[4:0]; SCC = (D.i != 0)  "
                   "[opcode 34 S_ASHR_I32]"),
    "s_lshl_b64": ([5377, 5378],
                   "                              D.u64 = S0.u64 << S1.u[5:0];\n"
                   "                              SCC = (D.u64 != 0).",
                   "D.u64 = S0.u64 << S1.u[5:0]; SCC = (D.u64 != 0)  "
                   "[opcode 31 S_LSHL_B64]"),
    "s_bfe_u32": ([5414, 5415],
                  "40      S_BFE_I32             D.u = (S0.u >> S1.u[4:0]) & "
                  "((1 << S1.u[22:16]) - 1);\n"
                  "                              SCC = (D.u != 0).",
                  "D.u = (S0.u >> offset) & ((1 << width) - 1); "
                  "SCC = (D.u != 0)  [opcode 39 S_BFE_U32]"),
    "s_bfe_i32": ([5420, 5421],
                  "41      S_BFE_U64             D.i = signext((S0.i >> "
                  "S1.u[4:0]) & ((1 << S1.u[22:16]) - 1));\n"
                  "                              SCC = (D.i != 0).",
                  "D.i = signext((S0.i >> offset) & ((1 << width) - 1)); "
                  "SCC = (D.i != 0)  [opcode 40 S_BFE_I32]"),
    "s_min_i32": ([5275, 5276],
                  "                              D.i = (S0.i < S1.i) ? S0.i : S1.i;\n"
                  "                              SCC = (S0.i < S1.i).",
                  "D.i = (S0.i < S1.i) ? S0.i : S1.i; SCC = (S0.i < S1.i)  "
                  "[opcode 6 S_MIN_I32]"),
    "s_abs_i32": ([1925],
                  "                                         D.i = abs (S0.i). "
                  "SCC=result not zero.",
                  "D.i = abs(S0.i); SCC = (result not zero)  "
                  "[Table 11, S_ABS_I32]"),
    "s_add_i32": ([5252, 5253, 5254],
                  "8       S_MAX_I32             D.i = S0.i + S1.i;\n"
                  "                              SCC = (S0.u[31] == S1.u[31] && "
                  "S0.u[31] != D.u[31]). // signed\n"
                  "                         overflow.",
                  "D.i = S0.i + S1.i; SCC = signed overflow  "
                  "[opcode 2 S_ADD_I32]"),
    "s_sub_i32": ([5261, 5262, 5263],
                  "                              D.i = S0.i - S1.i;\n"
                  "                              SCC = (S0.u[31] != S1.u[31] && "
                  "S0.u[31] != D.u[31]). // signed\n"
                  "                         overflow.",
                  "D.i = S0.i - S1.i; SCC = signed overflow  "
                  "[opcode 3 S_SUB_I32]"),
    "s_addc_u32": ([5266, 5267],
                   "                              D.u32 = S0.u32 + S1.u32 + SCC;\n"
                   "                              SCC = S0.u32 + S1.u32 + SCC >= "
                   "0x100000000ULL ? 1 : 0.",
                   "D.u32 = S0+S1+SCC; SCC = carry-out of the full sum  "
                   "[opcode 4 S_ADDC_U32]"),
    "s_and_saveexec_b32": ([6416, 6417, 6418],
                           "                                       D.u32 = EXEC_LO;\n"
                           "                                       EXEC_LO = S0.u32 & EXEC_LO;\n"
                           "                                       SCC = (EXEC_LO != 0).",
                           "D = EXEC_old; EXEC = S0 & EXEC; SCC = (EXEC_new != 0)  "
                           "[SOP1 opcode 60]"),
    "s_or_saveexec_b32": ([6429, 6430, 6431],
                          "                                       D.u32 = EXEC_LO;\n"
                          "                                       EXEC_LO = S0.u32 | EXEC_LO;\n"
                          "                                       SCC = (EXEC_LO != 0).",
                          "D = EXEC_old; EXEC = S0 | EXEC; SCC = (EXEC_new != 0)  "
                          "[SOP1 opcode 61]"),
    "s_xor_saveexec_b32": ([6439, 6440, 6441],
                           "                                       D.u32 = EXEC_LO;\n"
                           "                                       EXEC_LO = S0.u32 ^ EXEC_LO;\n"
                           "                                       SCC = (EXEC_LO != 0).",
                           "D = EXEC_old; EXEC = S0 ^ EXEC; SCC = (EXEC_new != 0)  "
                           "[SOP1 opcode 62]"),
    "s_andn2_saveexec_b32": ([6449, 6450, 6451],
                             "                                       D.u32 = EXEC_LO;\n"
                             "                                       EXEC_LO = S0.u32 & ~EXEC_LO;\n"
                             "                                       SCC = (EXEC_LO != 0).",
                             "D = EXEC_old; EXEC = S0 & ~EXEC; "
                             "SCC = (EXEC_new != 0)  [SOP1 opcode 63]"),
    "s_and_not1_saveexec_b32": ([6502, 6503, 6504],
                                "                                       D.u32 = EXEC_LO;\n"
                                "                                       EXEC_LO = ~S0.u32 & EXEC_LO;\n"
                                "                                       SCC = (EXEC_LO != 0).",
                                "D = EXEC_old; EXEC = ~S0 & EXEC; "
                                "SCC = (EXEC_new != 0)  [SOP1 opcode 68 "
                                "S_ANDN1_SAVEEXEC_B32; this revision's "
                                "disassembly spells it s_and_not1_saveexec_b32]"),
}

# ------------------------------------------------------------------ helpers
def s32(v):
    v &= U32
    return v - (1 << 32) if v & 0x80000000 else v


def carry_of(a, b):
    return 1 if (a & U32) + (b & U32) > U32 else 0


def add_ovf(a, b):
    d = (a + b) & U32
    sa, sb, sd = (a >> 31) & 1, (b >> 31) & 1, (d >> 31) & 1
    return d, (1 if (sa == sb and sa != sd) else 0)


def sub_ovf(a, b):
    d = (a - b) & U32
    sa, sb, sd = (a >> 31) & 1, (b >> 31) & 1, (d >> 31) & 1
    return d, (1 if (sa != sb and sa != sd) else 0)


VECTORS = []
_NOTES = []


def vec(instruction, case, setup, ops, dst_token, dst_val, scc, extra=None):
    """Append one truth vector.

    `setup` is {"s": {index: value}, "scc": int, "exec": int}.
    """
    lines, quote, rule = CIT[instruction]
    v = {
        "id": "%s/%s/%02d" % (instruction, case,
                              sum(1 for x in VECTORS
                                  if x["instruction"] == instruction
                                  and x["case"] == case) + 1),
        "instruction": instruction,
        "handler": "op_" + instruction,
        "case": case,
        "isa": {"file": ISA, "lines": lines, "quote": quote, "rule": rule},
        "setup": setup,
        "operands": ops,
        "expect": {"dst_token": dst_token, "dst_value": dst_val & U32
                   if dst_val is not None else None,
                   "scc": scc, "exec_after": None},
        "scc_expected": scc,
    }
    if extra:
        v.update(extra)
    VECTORS.append(v)
    return v


def sec(overwrite_scc=True):
    """Incoming SCC for a vector whose handler must OVERWRITE SCC.

    Always the negation of the expected SCC, so a handler that omits the
    write cannot pass.  `assert_scc_in_can_detect_omission` proves it.
    """
    return None if overwrite_scc else 0


def negation_pair(expected_scc):
    """scc_in chosen so that 'no write' leaves the wrong value behind."""
    return 1 - expected_scc


# ------------------------------------------------------------------ builders
LOGICAL32 = {
    "s_and_b32": lambda a, b: (a & b) & U32,
    "s_or_b32": lambda a, b: (a | b) & U32,
    "s_xor_b32": lambda a, b: (a ^ b) & U32,
    "s_and_not1_b32": lambda a, b: (a & (~b & U32)) & U32,
    "s_andn2_b32": lambda a, b: (a & (~b & U32)) & U32,
}


def build_logical32():
    pairs = [
        ("zeros", 0, 0),
        ("all-ones/all-ones", U32, U32),
        ("all-ones/zero", U32, 0),
        ("zero/all-ones", 0, U32),
        ("sign-boundary-pos/neg", 0x7FFFFFFF, 0x80000000),
        ("sign-boundary-neg/pos", 0x80000000, 0x7FFFFFFF),
        ("sign-boundary-neg/neg", 0x80000000, 0x80000000),
        ("high-bit-single", 0x80000000, 0x00000001),
        ("mixed-pattern", 0xDEADBEEF, 0x0F0F0F0F),
        ("one/zero", 1, 0),
    ]
    for name, fn in LOGICAL32.items():
        for cname, a, b in pairs:
            d = fn(a, b)
            vec(name, cname, {"s": {11: a, 12: b}, "scc": negation_pair(
                1 if d else 0), "exec": U32},
                ["s10", "s11", "s12"], "s10", d, 1 if d else 0)
        # operand aliasing: src0 == src1
        for cname, a in (("alias-src0-eq-src1-one",
                          0xFFFFFFFF), ("alias-src0-eq-src1-zero", 0)):
            d = fn(a, a)
            vec(name, cname, {"s": {11: a, 12: a},
                              "scc": negation_pair(1 if d else 0),
                              "exec": U32},
                ["s10", "s11", "s12"], "s10", d, 1 if d else 0)
        # operand aliasing: dst == src0
        for cname, a, b in (("alias-dst-eq-src0-nonzero", 0xFFFFFFFF, 0),
                            ("alias-dst-eq-src0-zero", 0, 0xFFFFFFFF)):
            d = fn(a, b)
            vec(name, cname, {"s": {10: a, 12: b},
                              "scc": negation_pair(1 if d else 0),
                              "exec": U32},
                ["s10", "s10", "s12"], "s10", d, 1 if d else 0)
        # operand aliasing: dst == src1
        d = fn(0x0F0F0F0F, 0xF0F0F0F0)
        vec(name, "alias-dst-eq-src1", {"s": {11: 0x0F0F0F0F, 10: 0xF0F0F0F0},
                                        "scc": negation_pair(1 if d else 0),
                                        "exec": U32},
            ["s10", "s11", "s10"], "s10", d, 1 if d else 0)


def build_shift32():
    vals = [0, 1, 0x80000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x40000000]
    shifts = [0, 1, 31, 32, 33, 63]
    for name in ("s_lshl_b32", "s_lshr_b32", "s_ashr_i32"):
        for a in vals:
            for sh in shifts:
                m = sh & 31
                if name == "s_lshl_b32":
                    d = (a << m) & U32
                elif name == "s_lshr_b32":
                    d = (a & U32) >> m
                else:
                    d = a if m == 0 else (s32(a) >> m) & U32
                vec(name, "a=0x%08x/sh=%d" % (a, sh),
                    {"s": {11: a, 12: sh}, "scc": negation_pair(1 if d else 0),
                     "exec": U32},
                    ["s10", "s11", "s12"], "s10", d, 1 if d else 0)
        # aliasing dst == src0 and dst == shift amount
        for cname, a, sh in (("alias-dst-eq-src0-nonzero", 0xFFFFFFFF, 4),
                             ("alias-dst-eq-src0-zero", 0, 4),
                             ("alias-dst-eq-amount", 0x00000001, 0x00000001)):
            m = sh & 31
            if name == "s_lshl_b32":
                d = (a << m) & U32
            elif name == "s_lshr_b32":
                d = (a & U32) >> m
            else:
                d = a if m == 0 else (s32(a) >> m) & U32
            vec(name, cname, {"s": {10: a, 11: sh},
                              "scc": negation_pair(1 if d else 0),
                              "exec": U32},
                ["s10", "s10", "s11"], "s10", d, 1 if d else 0)


def build_lshl_b64():
    vals = [0, 1, 0x80000000, 0x0000000080000000, 0xFFFFFFFFFFFFFFFF,
            0x0000000100000001, 0x7FFFFFFFFFFFFFFF]
    shifts = [0, 1, 31, 32, 63, 64]
    for v in vals:
        for sh in shifts:
            m = sh & 63
            d = (v << m) & ((1 << 64) - 1)
            vec("s_lshl_b64", "v=0x%016x/sh=%d" % (v, sh),
                {"s": {22: v & U32, 23: (v >> 32) & U32},
                 "scc": negation_pair(1 if d else 0), "exec": U32},
                ["s[20:21]", "s[22:23]", str(sh)], "s[20:21]",
                d & U32, 1 if d else 0, {"expect_pair_hi": (d >> 32) & U32})
    # aliasing: dst pair == source pair (the module's real form:
    # `s_lshl_b64 s[8:9], s[8:9], 13`)
    for cname, v, sh in (("alias-dst-eq-src-nonzero", 0x0000000000000001, 13),
                         ("alias-dst-eq-src-zero", 0, 13),
                         ("alias-dst-eq-src-highbit", 0x8000000000000000, 1)):
        m = sh & 63
        d = (v << m) & ((1 << 64) - 1)
        vec("s_lshl_b64", cname,
            {"s": {20: v & U32, 21: (v >> 32) & U32},
             "scc": negation_pair(1 if d else 0), "exec": U32},
            ["s[20:21]", "s[20:21]", str(sh)], "s[20:21]",
            d & U32, 1 if d else 0, {"expect_pair_hi": (d >> 32) & U32})


def build_bfe():
    """Offset/width are supplied as SEPARATE operands (the handler's own
    four-operand decode).  Both are kept inside the ISA field widths
    (offset <= 31, width <= 31) so the handler's `& 31` masks are no-ops and
    the ONLY property under test is the SCC side effect."""
    data = [0, 1, 0x80000000, 0xFFFFFFFF, 0x7FFFFFFF, 0x0000FF00, 0xDEADBEEF]
    ow = [(0, 1), (8, 8), (16, 16), (0, 31), (4, 4), (24, 8), (0, 0)]
    for a in data:
        for (o, w) in ow:
            du = ((a >> o) & ((1 << w) - 1)) & U32 if w else 0
            vec("s_bfe_u32", "d=0x%08x/o=%d/w=%d" % (a, o, w),
                {"s": {11: a, 12: o, 13: w},
                 "scc": negation_pair(1 if du else 0), "exec": U32},
                ["s10", "s11", "s12", "s13"], "s10", du, 1 if du else 0)
            if w == 0:
                di = 0
            else:
                r = (a >> o) & U32
                if o + w < 32:
                    r &= (1 << w) - 1
                    if r & (1 << (w - 1)):
                        r |= (U32 << w) & U32
                di = r & U32
            vec("s_bfe_i32", "d=0x%08x/o=%d/w=%d" % (a, o, w),
                {"s": {11: a, 12: o, 13: w},
                 "scc": negation_pair(1 if di else 0), "exec": U32},
                ["s10", "s11", "s12", "s13"], "s10", di, 1 if di else 0)
    # aliasing: dst == data source
    for cname, a, o, w in (("alias-dst-eq-src-nonzero", 0xDEADBEEF, 8, 8),
                           ("alias-dst-eq-src-zero", 0x00FF0000, 8, 8)):
        du = ((a >> o) & ((1 << w) - 1)) & U32
        vec("s_bfe_u32", cname, {"s": {10: a, 12: o, 13: w},
                                 "scc": negation_pair(1 if du else 0),
                                 "exec": U32},
            ["s10", "s10", "s12", "s13"], "s10", du, 1 if du else 0)


def build_min_abs():
    pairs = [
        ("zeros", 0, 0),
        ("all-ones/all-ones", U32, U32),
        ("neg-pos", 0xFFFFFFFF, 1),
        ("pos-neg", 1, 0xFFFFFFFF),
        ("sign-boundary", 0x80000000, 0x7FFFFFFF),
        ("sign-boundary-rev", 0x7FFFFFFF, 0x80000000),
        ("equal-nonzero", 0x12345678, 0x12345678),
        ("neg-more-negative", 0xFFFFFFFE, 0xFFFFFFFF),
        ("mixed", 0xDEADBEEF, 0x0F0F0F0F),
    ]
    for cname, a, b in pairs:
        d = min(s32(a), s32(b)) & U32
        scc = 1 if s32(a) < s32(b) else 0
        vec("s_min_i32", cname, {"s": {11: a, 12: b},
                                 "scc": negation_pair(scc), "exec": U32},
            ["s10", "s11", "s12"], "s10", d, scc)
    # MUST-FAIL-CASE note: equal operands leave SCC = 0 even though D != 0.
    for cname, a, b in (("alias-dst-eq-src0-lt", 0xFFFFFFFF, 0x00000001),
                        ("alias-dst-eq-src0-eq", 0x00000005, 0x00000005)):
        d = min(s32(a), s32(b)) & U32
        scc = 1 if s32(a) < s32(b) else 0
        vec("s_min_i32", cname, {"s": {10: a, 12: b},
                                 "scc": negation_pair(scc), "exec": U32},
            ["s10", "s10", "s12"], "s10", d, scc)

    for cname, a in (("zero", 0), ("one", 1), ("neg-one", 0xFFFFFFFF),
                     ("int-min", 0x80000000), ("int-max", 0x7FFFFFFF),
                     ("alias-dst-eq-src", 0xFFFFFFFE)):
        d = abs(s32(a)) & U32
        scc = 1 if d else 0
        if cname == "alias-dst-eq-src":
            # dst and src are the same token, so the value must be seeded
            # into THAT register.  Seeding s11 while reading s10 made this
            # vector read a zero -- the harness bug that this vector caught
            # on its first run.
            setup = {"s": {10: a}, "scc": negation_pair(scc), "exec": U32}
            toks = ["s10", "s10"]
        else:
            setup = {"s": {11: a}, "scc": negation_pair(scc), "exec": U32}
            toks = ["s10", "s11"]
        vec("s_abs_i32", cname, setup, toks, "s10", d, scc)


def build_add_sub_i32():
    cases = [
        ("zeros", 0, 0),
        ("all-ones/all-ones", U32, U32),
        ("pos-overflow", 0x7FFFFFFF, 1),
        ("neg-overflow", 0x80000000, 0xFFFFFFFF),
        ("sign-boundary", 0x7FFFFFFF, 0x80000000),
        ("no-overflow-mixed", 0x7FFFFFFF, 0x00000001 - 1),
        ("carry-only-no-signed-overflow", 0xFFFFFFFF, 0xFFFFFFFF),
        ("neg-pos-no-overflow", 0xFFFFFFFF, 1),
        ("mixed", 0xDEADBEEF, 0x0F0F0F0F),
        ("exact-negative-limit", 0x80000000, 0x80000000),
    ]
    for cname, a, b in cases:
        d, scc = add_ovf(a, b)
        vec("s_add_i32", cname, {"s": {11: a, 12: b},
                                 "scc": negation_pair(scc), "exec": U32},
            ["s10", "s11", "s12"], "s10", d, scc)
    for cname, a, b in (("alias-dst-eq-src0-ovf", 0x7FFFFFFF, 1),
                        ("alias-dst-eq-src0-noovf", 0x00000001, 1),
                        ("alias-dst-eq-src1", 1, 0x7FFFFFFF)):
        d, scc = add_ovf(a, b)
        tok = ["s10", "s10", "s12"] if cname != "alias-dst-eq-src1" \
            else ["s10", "s11", "s10"]
        setup = {"s": {10: a, 12: b}, "scc": negation_pair(scc), "exec": U32} \
            if cname != "alias-dst-eq-src1" else \
            {"s": {11: a, 10: b}, "scc": negation_pair(scc), "exec": U32}
        vec("s_add_i32", cname, setup, tok, "s10", d, scc)

    subcases = [
        ("zeros", 0, 0),
        ("all-ones/all-ones", U32, U32),
        ("pos-overflow", 0x7FFFFFFF, 0xFFFFFFFF),
        ("neg-overflow", 0x80000000, 1),
        ("sign-boundary", 0x80000000, 0x7FFFFFFF),
        ("borrow-no-signed-overflow", 0, 1),
        ("carry-no-signed-overflow", U32, U32),
        ("equal-nonzero", 0x12345678, 0x12345678),
        ("mixed", 0xDEADBEEF, 0x0F0F0F0F),
        ("exact", 0x40000000, 0x80000000),
    ]
    for cname, a, b in subcases:
        d, scc = sub_ovf(a, b)
        vec("s_sub_i32", cname, {"s": {11: a, 12: b},
                                 "scc": negation_pair(scc), "exec": U32},
            ["s10", "s11", "s12"], "s10", d, scc)
    for cname, a, b in (("alias-dst-eq-src0-ovf", 0x7FFFFFFF, 0xFFFFFFFF),
                        ("alias-dst-eq-src0-noovf", 0x00000000, 0x00000001),
                        ("alias-dst-eq-src1", 0xFFFFFFFF, 0x7FFFFFFF)):
        d, scc = sub_ovf(a, b)
        tok = ["s10", "s10", "s12"] if cname != "alias-dst-eq-src1" \
            else ["s10", "s11", "s10"]
        setup = {"s": {10: a, 12: b}, "scc": negation_pair(scc), "exec": U32} \
            if cname != "alias-dst-eq-src1" else \
            {"s": {11: a, 10: b}, "scc": negation_pair(scc), "exec": U32}
        vec("s_sub_i32", cname, setup, tok, "s10", d, scc)


SAVEEXEC_OP = {
    "s_and_saveexec_b32": lambda s0, e: s0 & e,
    "s_or_saveexec_b32": lambda s0, e: s0 | e,
    "s_xor_saveexec_b32": lambda s0, e: s0 ^ e,
    "s_andn2_saveexec_b32": lambda s0, e: s0 & (~e & U32),
    "s_and_not1_saveexec_b32": lambda s0, e: (~s0 & U32) & e,
}

EXEC_IN = [0xFFFFFFFF, 0x00000000, 0x0000FFFF, 0xFFFF0000, 0x55555555,
           0xAAAAAAAA, 0x80000000, 0x00000001]
S0_IN = [0xFFFFFFFF, 0x00000000, 0x0000FFFF, 0xFFFF0000, 0x55555555,
         0xAAAAAAAA, 0x80000000, 0x00000001]


def build_saveexec():
    for name, fn in SAVEEXEC_OP.items():
        for e in EXEC_IN:
            for s0 in S0_IN:
                new = fn(s0, e) & U32
                scc = 1 if new else 0
                vec(name, "exec=0x%08x/s0=0x%08x" % (e, s0),
                    {"s": {11: s0}, "scc": negation_pair(scc), "exec": e},
                    ["s20", "s11"], "s20", e, scc,
                    {"expect_exec_after": new})
        # dst == src aliasing, which is the module's actual form
        for cname, e, s0 in (("alias-dst-eq-src-nonzero", 0xFFFFFFFF,
                              0x0000000F),
                             ("alias-dst-eq-src-zero", 0x00000000, 0x0000000F),
                             ("inactive-lanes-all-masked-off", 0x00000000,
                              0x00000000)):
            new = fn(s0, e) & U32
            scc = 1 if new else 0
            vec(name, cname, {"s": {20: s0}, "scc": negation_pair(scc),
                              "exec": e},
                ["s20", "s20"], "s20", e, scc,
                {"expect_exec_after": new})

    # A pair of vectors that DISCRIMINATE s_andn2_saveexec_b32 from
    # s_and_not1_saveexec_b32.  The project already lost a phase to two
    # implementations that agreed because the vector could not tell the two
    # readings apart, so the discrimination is asserted here, not assumed.
    e, s0 = 0x0F0F0F0F, 0x00FF00FF
    n2 = SAVEEXEC_OP["s_andn2_saveexec_b32"](s0, e) & U32
    n1 = SAVEEXEC_OP["s_and_not1_saveexec_b32"](s0, e) & U32
    _NOTES.append({
        "note": "discriminating pair for the ANDN2/ANDN1 saveexec readings",
        "exec_in": e, "s0_in": s0,
        "andn2_expect_exec": n2, "andn1_expect_exec": n1,
        "the_two_readings_differ": n2 != n1,
    })
    assert n2 != n1, "the discriminating saveexec vector does not discriminate"


def build_addc():
    """S_ADDC_U32 is NOT repaired (it already conforms).  These vectors are
    the measurement that justifies that verdict, and they carry carry-in 0
    and carry-in 1 as a genuine INPUT, so the negation rule does not apply.
    """
    cases = [
        ("carry-in-0-no-carry-out", U32, 0, 0),
        ("carry-in-1-carry-out", U32, 0, 1),
        ("carry-in-1-low-bits-no-carry", 0, 0, 1),
        ("carry-in-0-high-bits", 0x80000000, 0x80000000, 0),
        ("carry-in-1-high-bits", 0x80000000, 0x80000000, 1),
        ("carry-in-0-zeros", 0, 0, 0),
        ("carry-in-1-zeros", 0, 0, 1),
        ("carry-in-1-all-ones-both", U32, U32, 1),
    ]
    for cname, a, b, cin in cases:
        r = a + b + cin
        d = r & U32
        scc = 1 if r > U32 else 0
        vec("s_addc_u32", cname, {"s": {11: a, 12: b}, "scc": cin,
                                  "exec": U32},
            ["s10", "s11", "s12"], "s10", d, scc)


def assert_scc_in_can_detect_omission():
    """Every vector for a repaired instruction must be able to FAIL a handler
    that omits the SCC write entirely."""
    bad = []
    for v in VECTORS:
        if v["instruction"] == "s_addc_u32":
            continue                     # carry-in is a real input there
        if v["setup"]["scc"] == v["scc_expected"]:
            bad.append(v["id"])
    assert not bad, ("these vectors cannot detect a missing SCC write: %s"
                     % bad[:8])


def main():
    build_logical32()
    build_shift32()
    build_lshl_b64()
    build_bfe()
    build_min_abs()
    build_add_sub_i32()
    build_saveexec()
    build_addc()
    assert_scc_in_can_detect_omission()

    per = {}
    for v in VECTORS:
        per.setdefault(v["instruction"], 0)
        per[v["instruction"]] += 1

    doc = {
        "schema": "p16am-truth-vectors/1",
        "phase": "16AM",
        "host_only": True,
        "gpu_execution_performed": False,
        "hip_calls_made": 0,
        "purpose": "independent truth vectors for every scalar instruction "
                   "whose SCC side effect Phase 16AM repaired in "
                   "revision_16am/emu.py",
        "provenance": {
            "source": "first principles + the ISA text quoted in `isa` on "
                      "every vector",
            "emulator_imported_by_this_file": False,
            "emulator_executed_by_this_file": False,
            "note": "an expectation copied out of the emulator would make the "
                    "emulator the definition of correctness, which is the "
                    "defect under audit",
        },
        "incoming_scc_rule": {
            "rule": "for every instruction the ISA says OVERWRITES SCC, "
                    "setup.scc is 1 - expect.scc",
            "why": "so a handler that omits the write leaves the opposite "
                   "value behind and the vector fails",
            "exception": "s_addc_u32, where SCC is the carry-in input",
            "asserted_by": "assert_scc_in_can_detect_omission()",
        },
        "citation_caveat": {
            "file": ISA,
            "issue": "the section 12.1 SOP2 opcode table is OCR-interleaved: "
                     "the Description column runs four opcodes behind the "
                     "Opcode/Name column, two lines per opcode",
            "how_the_pairing_was_fixed": "by the per-instruction caption "
                                         "lines, which are distinct, and "
                                         "corroborated by Table 11 (line "
                                         "1898) and Table 14 (line 1982)",
            "consequence": "line numbers are given so the reader can read "
                           "the surrounding lines and check the pairing",
        },
        "vector_count": len(VECTORS),
        "vector_count_per_instruction": dict(sorted(per.items())),
        "discrimination_notes": _NOTES,
        "vectors": VECTORS,
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    print(json.dumps({"vectors": len(VECTORS),
                      "per_instruction": dict(sorted(per.items())),
                      "discrimination": _NOTES,
                      "out": OUT}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
