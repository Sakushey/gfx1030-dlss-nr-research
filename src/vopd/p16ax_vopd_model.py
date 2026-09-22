#!/usr/bin/env python3
"""Phase 16AX T-VOPD -- shared operand model for the general VOPD lowering.

WHY THIS FILE EXISTS
  Phase 16AW's `p16aw_vopd_dependency.py` implements the dependency rule and
  carries 11 controls that make it able to fail.  T-VOPD must NOT write a second
  classifier: two implementations of one rule are two chances to disagree.
  So this module IMPORTS the 16AW classifier and reuses `classify_pair`
  verbatim.  What it adds is ONLY the operand *table* -- the data the 16AW
  analyzer itself declares as its extension point -- plus the status/EXEC
  dimension, which the 16AW analyzer does not model at all.

WHAT IS REUSED vs ADDED  (stated so the provenance is auditable)
  reused verbatim : V.parse_operand, V.split_operands, V.analyse_op,
                    V.classify_pair, V.parse_disassembly, V.eval_op
  added here      : the 4 missing operand shapes, the standalone-mnemonic
                    table, the status/EXEC read-write dimension, and the
                    emit-one-instruction splicer.

WHAT THIS DOES *NOT* ESTABLISH
  * it does not establish that the emitted standalone text is encodable --
    that is measured separately by actually running llvm-mc (p16ax_vopd_encode).
  * it does not establish the RUNTIME behaviour of any instruction; every
    statement here is about instruction text.
"""

from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
AW_VOPD = os.path.join(ROOT, "p16aw", "vopd")

if AW_VOPD not in sys.path:
    sys.path.insert(0, AW_VOPD)

import p16aw_vopd_dependency as V  # noqa: E402  (16AW analyzer, unmodified)

AW_ANALYZER = os.path.join(AW_VOPD, "p16aw_vopd_dependency.py")
AW_CENSUS = os.path.join(AW_VOPD, "VOPD_DEPENDENCY_CENSUS_16AW.json")
AW_CROSS = os.path.join(AW_VOPD, "VOPD_CROSS_KERNEL_CENSUS_16AW.json")
AW_SYM_DIS = os.path.join(AW_VOPD, "ACTUAL_PARENT_sym.dis")
AW_FULL_DIS = os.path.join(AW_VOPD, "ACTUAL_PARENT_full.dis")
CF_FULL_DIS = os.path.join(AW_VOPD, "CANDIDATE_F_full.dis")
PARENT_ELF = os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_code_object.o")

# --------------------------------------------------------------------------
# 1. the operand shapes the 16AW model is missing
# --------------------------------------------------------------------------
# Measured, not guessed: these are the only four mnemonics that appear in a
# `v_dual_` slot in the actual parent object and are absent from
# V.OPERAND_SHAPE.  See COVERAGE_16AX.json for the census that produced them.
EXT_SHAPES = {
    "cndmask_b32": "D,S,S",       # VOP2 form: VCC is read IMPLICITLY
    "fmamk_f32":   "D,S,S,S",     # dst = src0 * imm(src1) + src2 ; dst not read
    "max_f32":     "D,S,S",
    "min_f32":     "D,S,S",
}

#: dst is read as an input (accumulator form).  Inherited from 16AW, then the
#: 16AX additions are declared explicitly so the set is auditable in one place.
ACCUMULATOR_MNEMONICS = set(V.IMPLICIT_DEST_READ) | set()
#   v_fmac_f32  dst = dst * src0 + src1     -> dst IS read  (16AW models it)
#   v_fmaak_f32 dst = src0 * src1 + src2    -> dst NOT read
#   v_fmamk_f32 dst = src0 * src1 + src2    -> dst NOT read
#: dot-accumulate forms (v_dot*, v_mad_f32 dst-as-source-by-encoding) are NOT
#: present in the actual parent object and are therefore NOT modelled; they
#: stay UNSUPPORTED rather than being guessed at.  See HAZARD classes below.

#: mnemonics whose DESTINATION is also read, but only because the operand text
#: names it explicitly (e.g. `v_dual_cndmask_b32 v9, v10, v9`).  Listed so the
#: "implicit dest read is modelled" claim can be checked rather than believed.
DEST_NAMED_AS_SOURCE = {"cndmask_b32"}

# --------------------------------------------------------------------------
# 2. standalone spellings
# --------------------------------------------------------------------------
# Derived by MEASURING the actual parent object's own non-dual instances (the
# `grep` census recorded in COVERAGE_16AX.json), then confirmed to assemble for
# gfx1030 by llvm-mc in p16ax_vopd_encode.py.  Not guessed from the ISA manual.
STANDALONE = {
    "mov_b32":     "v_mov_b32_e32",
    "add_f32":     "v_add_f32_e32",
    "sub_f32":     "v_sub_f32_e32",
    "mul_f32":     "v_mul_f32_e32",
    "max_f32":     "v_max_f32_e32",
    "min_f32":     "v_min_f32_e32",
    "and_b32":     "v_and_b32_e32",
    "lshlrev_b32": "v_lshlrev_b32_e32",
    "add_nc_u32":  "v_add_nc_u32_e32",
    "cndmask_b32": "v_cndmask_b32_e32",
    "fmac_f32":    "v_fmac_f32_e32",
    "fmaak_f32":   "v_fmaak_f32",      # VOP3 form: no _e32 suffix
    "fmamk_f32":   "v_fmamk_f32",      # VOP3 form: no _e32 suffix
}

# --------------------------------------------------------------------------
# 3. status / EXEC dimension  (16AW does not model this at all)
# --------------------------------------------------------------------------
#: status registers READ (not written) by the instruction
STATUS_READ = {
    "cndmask_b32": frozenset({"vcc_lo"}),   # VOP2 cndmask predicates on VCC
}
#: status registers WRITTEN by the instruction.  Every mnemonic that a gfx11
#: VOPD slot can carry from this object is status-neutral; the ones that DO
#: write status (v_add_co_ci_u32 -> vcc, v_cmp_* -> vcc+scc, v_add_co_u32 ->
#: vcc) are asserted absent by `assert_no_status_writer` rather than assumed.
STATUS_WRITE = {}
#: mnemonics that write a status register and are therefore NOT status-neutral
KNOWN_STATUS_WRITERS = ("add_co_ci_u32", "add_co_u32", "sub_co_ci_u32", "cmp_")

STATUS_REGISTERS = frozenset({"vcc", "vcc_lo", "vcc_hi", "scc"})


def ensure_extended():
    """Extend the 16AW operand table IN THIS PROCESS.

    The 16AW file on disk is never written: this mutates the dict object the
    imported module already holds.  `classify_pair` reads that same dict at
    call time, so the classifier's LOGIC is reused byte-for-byte.
    """
    for k, shape in EXT_SHAPES.items():
        V.OPERAND_SHAPE[k] = shape
    for k in ACCUMULATOR_MNEMONICS:
        V.IMPLICIT_DEST_READ.add(k)
    return V.OPERAND_SHAPE


def status_writers_in(text):
    """Names of status-writing mnemonics appearing in this instruction text."""
    return [w for w in KNOWN_STATUS_WRITERS if w in text]


def assert_no_status_writer(side_text):
    """Raise if the side writes a status register that this model does not
    understand.  Fail closed: an unmodelled status writer is never 'safe'."""
    hits = status_writers_in(side_text)
    if hits:
        raise ValueError("status-writing mnemonic not modelled: %s (%s)"
                         % (hits, side_text.strip()))


# --------------------------------------------------------------------------
# 4. per-side analysis
# --------------------------------------------------------------------------

RE_STANDALONE_SUFFIX = re.compile(r"^(v_[A-Za-z0-9_]+?)_e(32|64)$")


def normalise_for_analysis(text):
    """Rewrite a STANDALONE spelling back to its canonical dual mnemonic so the
    SAME operand table analyses both dialects.

    This is the inverse of `emit_one`, and it exists so the corpus can feed the
    emitted stream back through the 16AW model.  It is not a second model: it
    changes only the mnemonic token, never an operand.

    Note the two cases.  16AW's own regex is `^(v_dual_)?(\\w+)\\s*(.*)$`, so a
    `v_dual_*` mnemonic is stripped for it, but a standalone `v_and_b32_e32` is
    NOT -- `\\w+` swallows the whole token and the lookup then misses.  Every
    standalone form must therefore be mapped back explicitly.  A first draft
    only handled the `_e32`/`_e64` suffixed spellings, which left
    `v_fmaak_f32` / `v_fmamk_f32` (the two VOP3 forms that carry no suffix)
    unmodelled, and 78 corpus sites reported as "not modelled" -- an instrument
    failure that would have read as a lowering failure.
    """
    m = re.match(r"^(\s*)(v_[A-Za-z0-9_]+)(\s*)(.*)$", text, re.S)
    if not m:
        return text
    tok, rest = m.group(2), m.group(4)
    if tok.startswith("v_dual_"):
        return text
    sm = RE_STANDALONE_SUFFIX.match(tok)
    body = sm.group(1)[2:] if sm else tok[2:]
    if body in STANDALONE:
        return "v_dual_%s %s" % (body, rest)
    return text


def analyse_ext(text):
    """V.analyse_op + the status/EXEC dimension + a `standalone` spelling.

    Accepts BOTH dialects (`v_dual_and_b32` and `v_and_b32_e32`).  Returns None
    only when V.analyse_op cannot even parse the text.
    """
    base = V.analyse_op(normalise_for_analysis(text))
    if base is None:
        return None
    mnem = base["mnemonic"]
    out = dict(base)
    out["status_reads"] = set(STATUS_READ.get(mnem, frozenset()))
    out["status_writes"] = set(STATUS_WRITE.get(mnem, frozenset()))
    out["exec_write"] = False          # no v_ op in this object writes EXEC
    out["standalone"] = STANDALONE.get(mnem)
    out["dest_named_as_source"] = mnem in DEST_NAMED_AS_SOURCE
    out["accumulator"] = mnem in ACCUMULATOR_MNEMONICS
    if base["modelled"]:
        try:
            assert_no_status_writer(text)
        except ValueError as e:
            out["modelled"] = False
            out["reason"] = str(e)
    return out


def classify_pair_ext(x_text, y_text):
    """The 16AW classifier's verdict, with the extended operand table active.

    The returned `class`/`left_writes_right_reads`/`right_writes_left_reads`
    come from V.classify_pair UNCHANGED.  `status_conflict` is computed here,
    additively -- it is a different dimension, not a re-implementation.

    BOTH sides are normalised first.  16AW's classifier is written for the
    `v_dual_*` dialect only: handed a standalone `v_and_b32_e32` its regex keeps
    the `v_` prefix, the mnemonic lookup misses, and it returns
    UNKNOWN_BLOCKING.  A first draft of this function passed the raw text
    through, so a census over EMITTED text classified every pair as
    UNKNOWN_BLOCKING -- and a "left-before-right == 0" claim built on that reads
    as a pass while having compared nothing.  The negative control in
    p16ax_vopd_correct.py is what exposed it.
    """
    c = V.classify_pair(normalise_for_analysis(x_text),
                        normalise_for_analysis(y_text))
    X = analyse_ext(x_text)
    Y = analyse_ext(y_text)
    conf = None
    if X and Y and X["modelled"] and Y["modelled"]:
        # a status register written by one side and read by the other would be
        # reordered too -- and would ALSO be invisible to the vector-register
        # classifier above.
        if X["status_writes"] & Y["status_reads"]:
            conf = ("X writes status read by Y", sorted(X["status_writes"] & Y["status_reads"]))
        elif Y["status_writes"] & X["status_reads"]:
            conf = ("Y writes status read by X", sorted(Y["status_writes"] & X["status_reads"]))
        elif X["status_writes"] and Y["status_writes"]:
            conf = ("both sides write status", sorted(X["status_writes"] | Y["status_writes"]))
    c["status_conflict"] = conf
    if conf is not None:
        c["class"] = "UNKNOWN_BLOCKING"
        c["why"] = "status/EXEC conflict: %s" % (conf,)
    return c


# --------------------------------------------------------------------------
# 5. emit
# --------------------------------------------------------------------------

RE_SIDE = re.compile(r"^(v_dual_)?([A-Za-z_][A-Za-z0-9_]*)\s*(.*)$", re.S)


def split_side(text):
    m = RE_SIDE.match(text.strip())
    if not m:
        raise ValueError("unparseable side: %r" % text)
    return m.group(2), m.group(3).strip()


def emit_one(text):
    """One `v_dual_*` side -> the standalone instruction text for gfx10.

    The operand list is copied VERBATIM, so every modifier (negation, absolute,
    literal, half selection) travels with it by construction rather than by
    a re-serialisation that could drop one.
    """
    mn, rest = split_side(text)
    if mn not in STANDALONE:
        raise ValueError("no standalone spelling modelled for %r" % mn)
    return "%s %s" % (STANDALONE[mn], rest)


def emit_sequence(sides):
    """Emit a whole corrected pair from an ordered list of sides."""
    return [emit_one(s) for s in sides]


# --------------------------------------------------------------------------

if __name__ == "__main__":
    ensure_extended()
    print("16AW analyzer:", AW_ANALYZER)
    print("extended shapes:", sorted(EXT_SHAPES))
    print("classify_pair reused from:", V.__file__)
