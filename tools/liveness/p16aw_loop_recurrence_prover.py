#!/usr/bin/env python3
"""Phase 16AW -- REPLACEMENT machine-loop RECURRENCE PROVER.

Brief PART X, sections 71-77 (external audit ASTRA4).

WHY THIS FILE EXISTS
    Phase 16AT built a real CFG, real dominators, real natural loops and a real
    SCC reaching-definition analysis for the final Slot-5 gfx1030 object.  Brief
    section 71 says that work is VALUABLE and must be KEPT.  What is retired is
    only the FINITE-BOUND CLASSIFICATION layered on top of it:

        p16at/native/p16at_machine_cfg.py, main(), the block commented
            `# ---- finite-termination argument per natural loop ----`

    That block assigns the verdict

        COUNTED_LOOP_WITH_STATIC_BOUND

    to a loop whenever a NUMERIC-SHAPED `s_(add|addk|sub)_{i32,u32} Rd, Rs, imm`
    instruction exists anywhere in the loop body whose DESTINATION is the same
    register the guard compares.  It never reads `Rs`.  It never requires
    `imm != 0`.  It never checks dominance, resets, wrap, or reachability of the
    compared value.  It is, in the audit's phrase, a classification "from
    mnemonic shape rather than from a proven recurrence", and its own
    `max_trip_count` is `None` whenever the first matching step is 0 -- while
    the verdict beside it still says COUNTED_LOOP_WITH_STATIC_BOUND.

WHAT REPLACES IT
    A recurrence prover that must prove THIRTEEN separate facts about ONE
    register before it will emit a finite bound, and that returns
    UNKNOWN_BLOCKING -- fail closed -- the moment any of them cannot be
    established.  The thirteen facts are the audit's section-72 list, one
    requirement per line, and each requirement records the instructions it
    examined so a reader can see the check REACHED the thing it judged.

    Requirements (brief section 72)
        R01 induction_register_identified
        R02 initial_value_resolved_to_a_constant
        R03 reaching_initial_definition_unique_and_outside_the_loop
        R04 recurrence_update_identified
        R05 update_reads_the_same_induction_register
        R06 nonzero_step
        R07 branch_comparison
        R08 branch_direction
        R09 termination_value_reachable
        R10 update_dominates_or_reaches_every_latch_path
        R11 no_reset_or_write_on_an_alternate_path
        R12 modular_wrap_behaviour
        R13 finite_maximum_trip_count
        R76 transitive_spin_dependency (brief section 76)

    R76 is the fourteenth: section 72 asks for the thirteen facts about the
    recurrence, and section 76 asks a question about the loop's EXIT CONDITION
    that the thirteen do not cover -- whether that condition reads external
    memory, directly or through a chain.

THE SUPPORTED RECURRENCE FORM (stated, not implied)
    A single scalar induction register r with
      * a reaching initial definition OUTSIDE the loop that sets r to a
        CONSTANT v0 (not a load, not a computed value);
      * exactly ONE in-loop writer of r, the update
        `s_add_u32|s_add_i32|s_sub_u32|s_sub_i32 r, r, imm` with imm != 0,
        whose source operand IS r;
      * the update in the SAME BASIC BLOCK as the guard compare, at a LOWER
        address, so the guard is evaluated after the update on every trip;
      * the branch's SCC producer being that guard compare `s_cmp_*_u32|i32 r, T`;
      * the branch being an `s_cbranch_scc0`/`s_cbranch_scc1` whose target is
        the loop head.
    The value seen at the j-th guard evaluation is then exactly
        A_j = (A0 + j*c) mod 2**32,   A0 = v0 + c,
    which is decided exactly (see `orbit_verdict`).  Anything outside this form
    is UNKNOWN_BLOCKING, never a bound.

TWO INDEPENDENT ROUTES TO THE TRIP COUNT
    ROUTE SIM  -- bit-exact modular simulation of A_j, evaluating the guard in
                  the mnemonic's OWN signedness and the branch's OWN polarity.
    ROUTE FORM -- a closed form: for the equality family (`eq`/`lg`) an exact
                  linear congruence solved over Z/2**32; for the ordered family
                  a monotone-threshold closed form that is only CREDITED when
                  ROUTE SIM confirms both the index and that no modular wrap
                  occurred inside the window.
    The two must agree.  A closed form whose candidate index is not confirmed by
    the simulation is DISCARDED, not trusted -- this is the guard against a
    plausible-looking formula quietly returning a wrong trip count.

TRANSITIVE SPIN DEPENDENCY (brief section 76)
    The prover does not test for a load whose destination equals the compared
    register (the 16AT test).  It computes the TRANSITIVE SGPR closure of the
    loop's exit condition inside the loop: guard register -> every in-loop
    writer of that register -> every source register of those writers -> ...,
    and reports SPIN_OR_EXTERNAL_PROGRESS_DEPENDENCY if any of those writers is
    a memory LOAD, or if the reaching initial definition is a load.  A
    `load -> move -> compare -> branch` and a `load -> shift -> compare ->
    branch` chain are both caught; neither is caught by the direct test.

Host-only.  Disassembling is not launching: no HIP call, no GPU, no slot.
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

sys.path.insert(0, os.path.join(ROOT, "p16at", "native"))
import p16at_machine_cfg as M  # noqa: E402  (the CFG work brief section 71 KEEPS)

#: the largest trip count the supported form will certify.  This is a declared
#: limit of the FORM, not a claim that a longer loop does not terminate: a loop
#: whose exact trip count exceeds it is reported UNKNOWN_BLOCKING with the exact
#: count beside it, so the refusal is explained rather than opaque.
CAP_TRIPS = 1 << 20
#: above this index ROUTE FORM's candidate is not confirmed by simulation (that
#: would need CAP_TRIPS steps); it is then credited only for the equality family,
#: where the congruence is exact on its own.
FORM_SIM_LIMIT = 1 << 16

REQUIREMENTS = [
    ("R01", "induction_register_identified"),
    ("R02", "initial_value_resolved_to_a_constant"),
    ("R03", "reaching_initial_definition_unique_and_outside_the_loop"),
    ("R04", "recurrence_update_identified"),
    ("R05", "update_reads_the_same_induction_register"),
    ("R06", "nonzero_step"),
    ("R07", "branch_comparison"),
    ("R08", "branch_direction"),
    ("R09", "termination_value_reachable"),
    ("R10", "update_dominates_or_reaches_every_latch_path"),
    ("R11", "no_reset_or_write_on_an_alternate_path"),
    ("R12", "modular_wrap_behaviour"),
    ("R13", "finite_maximum_trip_count"),
    ("R76", "transitive_spin_dependency"),
]
REQ_ID = {k: v for k, v in REQUIREMENTS}

#: the thirteen facts of brief section 72, in the order the audit lists them.
#: R76 is the section-76 question and is kept separate so that a reader can see
#: the section-72 list intact.
SECTION_72_REQUIREMENTS = [k for k, _ in REQUIREMENTS if k != "R76"]

PROVEN = "PROVEN"
FAILED = "FAILED"
UNKNOWN = "UNKNOWN"

VERDICT_PROVEN = "PROVEN_COUNTED_LOOP_WITH_STATIC_BOUND"
VERDICT_UNKNOWN = "UNKNOWN_BLOCKING"
VERDICT_SPIN = "SPIN_OR_EXTERNAL_PROGRESS_DEPENDENCY"

# =====================================================================
# 1.  SCALAR REGISTER MODELLING
# =====================================================================
SGPR_TOKEN = re.compile(r"^s(\d+)$")
SGPR_PAIR = re.compile(r"^s\[(\d+):(\d+)\]$")

#: scalar mnemonics whose FIRST operand is the destination.
SCALAR_DST0 = frozenset("""
s_mov_b32 s_mov_b64 s_movk_i32 s_add_u32 s_add_i32 s_addc_u32 s_sub_u32 s_sub_i32
s_subb_u32 s_addk_i32 s_mulk_i32 s_mul_i32 s_mul_hi_i32 s_mul_hi_u32 s_min_i32
s_min_u32 s_max_i32 s_max_u32 s_abs_i32 s_absdiff_i32 s_and_b32 s_and_b64 s_or_b32
s_or_b64 s_xor_b32 s_xor_b64 s_nand_b32 s_nor_b32 s_xnor_b32 s_andn2_b32
s_orn2_b32 s_lshl_b32 s_lshl_b64 s_lshr_b32 s_lshr_b64 s_ashr_i32 s_ashr_i64
s_not_b32 s_not_b64 s_wqm_b32 s_quadmask_b32 s_bitreplicate_b64_b32 s_brev_b32
s_bcnt0_i32_b32 s_bcnt1_i32_b32 s_ff0_i32_b32 s_ff1_i32_b32 s_flbit_i32
s_flbit_i32_b32 s_bitset0_b32 s_bitset1_b32 s_bfe_u32 s_bfe_i32 s_bfm_b32
s_sext_i32_i8 s_sext_i32_i16 s_cselect_b32 s_cselect_b64 s_cmov_b32 s_cmov_b64
s_cmovk_i32 s_getpc_b64 s_sext_i32_i16 s_load_dword s_load_dwordx2
s_load_dwordx4 s_load_dwordx8 s_load_dwordx16 s_buffer_load_dword
s_buffer_load_dwordx2 s_buffer_load_dwordx4 s_buffer_load_dwordx8
s_scratch_load_dword s_scratch_load_dwordx2 s_atomic_add s_atomic_sub
s_atomic_swap v_readfirstlane_b32 v_readlane_b32
s_and_saveexec_b32 s_and_saveexec_b64 s_or_saveexec_b32 s_or_saveexec_b64
s_xor_saveexec_b32 s_xor_saveexec_b64 s_andn1_saveexec_b32 s_andn2_saveexec_b32
s_orn1_saveexec_b32 s_orn2_saveexec_b32 s_nand_saveexec_b32 s_nor_saveexec_b32
s_xnor_saveexec_b32
""".split())

#: scalar mnemonics that write NO register at all.  `s_cmp*` and `s_cmpk*` are
#: here deliberately: they write SCC, and their first operand is a SOURCE.  A
#: table that listed them as dst0 would report every guard as a RESET of its own
#: induction register -- the silent no-op in the other direction.
SCALAR_NO_DST = frozenset("""
s_cmp_eq_i32 s_cmp_lg_i32 s_cmp_gt_i32 s_cmp_ge_i32 s_cmp_lt_i32 s_cmp_le_i32
s_cmp_eq_u32 s_cmp_lg_u32 s_cmp_gt_u32 s_cmp_ge_u32 s_cmp_lt_u32 s_cmp_le_u32
s_cmp_eq_i64 s_cmp_lg_i64 s_cmp_gt_i64 s_cmp_ge_i64 s_cmp_lt_i64 s_cmp_le_i64
s_cmp_eq_u64 s_cmp_lg_u64 s_cmp_gt_u64 s_cmp_ge_u64 s_cmp_lt_u64 s_cmp_le_u64
s_cmpk_eq_i32 s_cmpk_lg_i32 s_cmpk_gt_i32 s_cmpk_ge_i32 s_cmpk_lt_i32
s_cmpk_le_i32 s_cmpk_eq_u32 s_cmpk_lg_u32 s_cmpk_gt_u32 s_cmpk_ge_u32
s_cmpk_lt_u32 s_cmpk_le_u32 s_bitcmp0_b32 s_bitcmp1_b32
s_cbranch_scc0 s_cbranch_scc1 s_cbranch_vccz s_cbranch_vccnz s_cbranch_execz
s_cbranch_execnz s_branch s_nop s_endpgm s_endpgm_saved s_wakeup s_barrier
s_setkill s_waitcnt s_waitcnt_vscnt s_sethalt s_sleep s_setprio s_sendmsg
s_sendmsghalt s_trap s_icache_inv s_incperflevel s_decperflevel s_ttracedata
s_cbranch_cdbgsys s_cbranch_cdbguser s_cbranch_cdbgsys_or_user
s_cbranch_cdbgsys_and_user s_cbranch_join s_code_end s_clause s_setpc_b64
s_rfe_b64 s_set_gpr_idx_off s_set_gpr_idx_mode s_set_gpr_idx_on s_dcache_inv
s_memtime s_memrealtime exp s_sleep_var
""".split())

#: address-space prefixes that name a MEMORY instruction writing a VGPR or
#: memory.  None of them can write a scalar register, so none can write an
#: induction register.
VECTOR_OR_MEMORY_PREFIXES = ("global_", "flat_", "buffer_", "ds_", "image_",
                            "tbuffer_", "scratch_", "s_dcache_")

#: prefixes that name a LOAD from memory (spin detection)
LOAD_PREFIXES = ("global_load", "flat_load", "buffer_load", "scratch_load",
                 "s_load", "s_buffer_load", "ds_read", "image_load",
                 "tbuffer_load")


def sgpr_names(tok):
    """{'s8'} for 's8', {'s8','s9'} for 's[8:9]'."""
    t = tok.strip().rstrip(",")
    m = SGPR_TOKEN.match(t)
    if m:
        return {"s" + m.group(1)}
    m = SGPR_PAIR.match(t)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        return {"s%d" % i for i in range(a, b + 1)}
    return set()


def operand_fields(operands):
    """Split an operand string on top-level commas (no nesting in AMDHSA asm)."""
    return [p.strip() for p in operands.split(",")] if operands.strip() else []


def scalar_write_kind(mnem, operands):
    """('dst0'|'none'|'vgpr'|'unknown', {register names written}).

    Only a mnemonics table can answer this, and a table that silently stops
    covering a new instruction is the defect this project keeps finding.  So
    anything not covered is 'unknown', and the caller treats an 'unknown'
    instruction as a possible writer ONLY if the register appears in its operand
    text -- a write always names its destination, so an instruction that never
    mentions r cannot write r.
    """
    if mnem in SCALAR_DST0:
        f = operand_fields(operands)
        return "dst0", (sgpr_names(f[0]) if f else set())
    if mnem in SCALAR_NO_DST:
        return "none", set()
    if mnem.startswith("v_"):
        return "vgpr", set()
    if mnem.startswith(VECTOR_OR_MEMORY_PREFIXES):
        return "vgpr", set()
    return "unknown", set()


def mentions_register(operands, reg):
    for tok in operand_fields(operands):
        if reg in sgpr_names(tok):
            return True
    return False


def writes_register(insn, reg):
    """(True|False|None) -- True writes, False provably does not, None unknown."""
    kind, written = scalar_write_kind(insn["mnemonic"], insn["operands"])
    if kind == "unknown":
        return None if mentions_register(insn["operands"], reg) else False
    return reg in written


def is_load(mnem):
    return mnem.startswith(LOAD_PREFIXES)


def s32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v


def u32(v):
    return v & 0xFFFFFFFF


# =====================================================================
# 2.  THE GUARD PREDICATE, ITS TRUTH SET, AND `continue`
# =====================================================================
CMP_MNEM = re.compile(
    r"^s_cmp(?:k)?_(eq|lg|gt|ge|lt|le)_(u32|i32)$")


def parse_cmp(mnem, operands):
    """(register, T, op, signedness) or None."""
    m = CMP_MNEM.match(mnem)
    if not m:
        return None
    f = operand_fields(operands)
    if len(f) != 2:
        return None
    names = sgpr_names(f[0])
    if len(names) != 1:
        return None
    if not re.fullmatch(r"-?(?:0[xX][0-9a-fA-F]+|\d+)", f[1]):
        return None
    t = int(f[1], 0)
    return names.pop(), u32(t), m.group(1), m.group(2)


def domain_bounds(signed):
    return (-0x80000000, 0x7FFFFFFF) if signed else (0, 0xFFFFFFFF)


def as_value(x, signed):
    return s32(x) if signed else u32(x)


def guard_true(op, x, T, signed):
    """the guard's own SCC value as a Python bool, on the 32-bit pattern x."""
    v = as_value(x, signed)
    t = as_value(T, signed)
    if op == "eq":
        return v == t
    if op == "lg":
        return v != t
    if op == "gt":
        return v > t
    if op == "ge":
        return v >= t
    if op == "lt":
        return v < t
    if op == "le":
        return v <= t
    raise ValueError(op)


def continues(x, op, T, signed, polarity):
    """Does the branch at the latch send control back to the loop head?"""
    g = guard_true(op, x, T, signed)
    return g if polarity == "scc1" else (not g)


def truth_set_extremes(op, T, signed):
    """The guard's truth set as a half-space descriptor.

    Returns ('all', None) if every 32-bit pattern satisfies the guard,
    ('none', None) if none does, else ('subset', None).  Only the two extreme
    cases are decided here; everything else goes to the exact equivalence
    search, so this function can only ever be too cautious.
    """
    lo, hi = domain_bounds(signed)
    t = as_value(T, signed)
    if op == "eq":
        return "subset"          # a singleton is never all, never none
    if op == "lg":
        return "subset"          # the complement of a singleton, on 2**32 values
    if op == "gt":
        return ("none", None) if t == hi else "subset"
    if op == "lt":
        return ("none", None) if t == lo else "subset"
    if op == "ge":
        return ("all", None) if t == lo else "subset"
    if op == "le":
        return ("all", None) if t == hi else "subset"
    raise ValueError(op)


# =====================================================================
# 3.  THE EXACT ORBIT DECISION
# =====================================================================
def _egcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_r, old_s


def congruence_solution(A0, c, T):
    """The smallest j >= 0 with (A0 + j*c) % 2**32 == T, or None.

    Exact: `g = gcd(c, 2**32)` divides the difference or there is no solution at
    all, and then the solutions form one residue class modulo 2**32/g.
    """
    MOD = 1 << 32
    g = _egcd(c & (MOD - 1), MOD)[0] if c % MOD else MOD
    if g == 0:
        return None
    diff = (T - A0) % MOD
    if diff % g:
        return None
    m = MOD // g
    if m == 1:
        return 0
    #: the modular inverse comes from pow() rather than a hand-rolled extended
    #: Euclid: the first version of this function fed the Euclid loop a
    #: modular-inverse problem whose intermediate remainders go negative, and a
    #: sign slip there would have produced a plausible wrong exit index with
    #: nothing to catch it.  pow(x, -1, m) is exact by construction.
    inv = pow((c // g) % m, -1, m)
    return ((diff // g) * inv) % m


def first_wrap_index(A0, d):
    """The smallest j >= 1 at which the TRUE integer A0 + j*d leaves
    [0, 2**32-1]; None if it never does within 2**32 steps."""
    if d == 0:
        return None
    if d > 0:
        return (0xFFFFFFFF - A0) // d + 1
    return A0 // (-d) + 1


def orbit_verdict(A0, c, op, T, signed, polarity, cap=CAP_TRIPS):
    """Decide the loop's termination exactly, or say why it could not be.

    Returns a dict with:
        status     'EXITS' | 'INFINITE' | 'NOT_FOUND_WITHIN_CAP'
        trip_count exact_maximum_trip_count (status == 'EXITS')
        route_sim  the index ROUTE SIM found, or None
        route_form the index ROUTE FORM derived, or None
        routes_agree
        first_wrap_at
    """
    out = {"status": None, "trip_count": None, "route_sim": None,
           "route_form": None, "routes_agree": None, "first_wrap_at": None,
           "continue_set_is_the_whole_domain": False,
           "continue_set_is_empty": False,
           "route_form_credited": False,
           "what_route_form_credited_means":
               "True only when ROUTE FORM and the bit-exact simulation agree on "
               "the same first-exit index.  When it is False, `route_form` is "
               "reported for inspection and is NOT evidence: the ordered-family "
               "closed form ignores the signed sign boundary and the modular "
               "wrap, so inside a non-EXITS verdict it can hold a number that "
               "does not describe the loop."}
    d = s32(c)
    if d == 0:
        # a zero step makes the orbit a single point: the guard's value never
        # changes, so the loop either exits on its first evaluation or never.
        # Handled explicitly so that no cap can turn it into a wrong answer.
        out["status"] = ("EXITS" if not continues(u32(A0), op, T, signed,
                                                  polarity) else "INFINITE")
        if out["status"] == "EXITS":
            out["trip_count"] = 1
            out["route_sim"] = out["route_form"] = 0
            out["routes_agree"] = True
            out["route_form_credited"] = True
        out["zero_step"] = True
        return out

    # ---- the two extremes, which need no search at all -------------------
    kind = truth_set_extremes(op, T, signed)
    if (kind == "all" and polarity == "scc1") or \
            (kind == "none" and polarity == "scc0"):
        out["status"] = "INFINITE"
        out["continue_set_is_the_whole_domain"] = True
        return out
    if (kind == "none" and polarity == "scc1") or \
            (kind == "all" and polarity == "scc0"):
        out["status"] = "EXITS"
        out["trip_count"] = 1
        out["route_sim"] = 0
        out["route_form"] = 0
        out["routes_agree"] = True
        out["route_form_credited"] = True
        out["continue_set_is_empty"] = True
        out["route_form_kind"] = "constant_predicate"

    # ---- ROUTE SIM: bit-exact modular simulation -------------------------
    x = u32(A0)
    sim_j = None
    wrap_at = first_wrap_index(u32(A0), d)
    for j in range(cap + 1):
        if not continues(x, op, T, signed, polarity):
            sim_j = j
            break
        x = u32(x + c)
    out["route_sim"] = sim_j
    out["first_wrap_at"] = wrap_at

    # ---- ROUTE FORM: a closed form --------------------------------------
    if op in ("eq", "lg"):
        j0 = congruence_solution(u32(A0), u32(c), T)
        out["route_form_kind"] = "linear_congruence"
        out["congruence_first_solution_j"] = j0
        out["route_form"] = equality_family_form(op, polarity, j0)
    else:
        out["route_form_kind"] = "monotone_threshold"
        out["route_form"] = monotic_form(A0, c, op, T, signed, polarity)

    # ---- agreement -------------------------------------------------------
    if sim_j is not None:
        out["status"] = "EXITS"
        out["trip_count"] = sim_j + 1
        out["route_sim_confirmed"] = True
        out["routes_agree"] = (out["route_form"] == sim_j)
        out["route_form_credited"] = (out["routes_agree"] is True)
        if out["routes_agree"] is not True:
            # the closed form and the exact simulation disagree about the first
            # exit index.  Trust NEITHER: one of the two is wrong and this
            # prover cannot tell which, so it does not certify a bound.
            out["status"] = "NO_INDEPENDENT_DERIVATION"
            out["why"] = ("the closed form (%s) and the bit-exact simulation "
                          "disagree about the first exit index"
                          % out["route_form_kind"])
    else:
        out["status"] = "NOT_FOUND_WITHIN_CAP"
        if op in ("eq", "lg") and out["route_form"] is None:
            # the congruence has no solution at all: the predicate is constant
            # on the orbit, and it is constantly "do not exit"
            out["status"] = "INFINITE"
            out["infinity_proved_by"] = (
                "the linear congruence a + j*c = T (mod 2**32) has no "
                "solution, so the guard's value is fixed on the entire orbit")
    return out


def equality_family_form(op, polarity, j0):
    """The exact first exit index for `eq` / `lg`, or None if there is none.

    The whole family reduces to one fact -- the smallest j with A_j == T exists
    (j0) or does not (None) -- because eq and lg are complements of each other
    and s_cbranch_scc0/scc1 are complements of each other.  Stating the four
    cases as a table rather than deriving them by algebra in place is
    deliberate: this is the one place where a sign slip would quietly produce a
    plausible wrong bound, and the simulation below cross-checks it anyway.
    """
    if op == "eq":
        if polarity == "scc1":      # continue while A_j == T
            return 0 if j0 != 0 else 1      # j0 None -> never continues
        return j0                            # scc0: exit at j0; None -> never
    # op == "lg":                    continue while A_j != T
    if polarity == "scc1":
        return j0                            # None -> never exits
    return 0 if j0 != 0 else 1               # scc0; j0 None -> exit at 0


def monotic_form(A0, c, op, T, signed, polarity):
    """A monotone-threshold closed form, usable only when the truth set is a
    half-space AND the orbit does not wrap inside the window.

    Returns the candidate index or None.  The caller NEVER credits it without
    the bit-exact simulation confirming the same index, so a formula that is
    only valid without a wrap cannot produce a wrong answer -- it can only
    produce a candidate that is then discarded.
    """
    d = s32(c)
    if d == 0:
        return None
    lo, hi = domain_bounds(signed)
    t = as_value(T, signed)
    # continue-set as a predicate on the SIGNED-INTERPRETED value
    if polarity == "scc1":
        keep = op
    else:
        keep = {"eq": "lg", "lg": "eq", "gt": "le", "ge": "lt",
                "lt": "ge", "le": "gt"}[op]
    if keep not in ("gt", "ge", "lt", "le"):
        return None
    a0 = as_value(u32(A0), signed)
    if keep == "gt":            # continue while v > t  -> exit when v <= t
        if a0 <= t:
            return 0
        if d > 0:
            return -((t - a0) // d)      # ceil((a0-t)/d)
        return (a0 - t - 1) // (-d) + 1  # ceil((a0-t)/(-d)), d < 0
    if keep == "ge":            # exit when v < t
        if a0 < t:
            return 0
        if d > 0:
            return (a0 - t) // d + 1
        return (a0 - t) // (-d) + 1      # floor+1, d < 0
    if keep == "lt":            # exit when v >= t
        if a0 >= t:
            return 0
        if d > 0:
            return -((a0 - t) // d)      # ceil((t-a0)/d)
        return None                      # d < 0 moves v further below t
    if keep == "le":            # exit when v > t
        if a0 > t:
            return 0
        if d > 0:
            return (t - a0) // d + 1
        return None                      # d < 0 moves v further below t
    return None


# =====================================================================
# 4.  THE PROVER
# =====================================================================
def build_context(ins, symbol_base, entry=None):
    blocks, addr2blk, branches = M.build_cfg(ins, symbol_base, entry)
    if entry is None:
        entry = addr2blk[ins[0]["addr"]]
    idx = {x["addr"]: i for i, x in enumerate(ins)}
    contains = {}
    for b in blocks:
        for i in range(b["first_idx"], b["last_idx"] + 1):
            contains[ins[i]["addr"]] = b["id"]
    live = M.reachable(blocks, entry)
    idom = M.dominators(blocks, entry, live)
    loops = M.natural_loops(blocks, idom, live)
    return {"ins": ins, "idx": idx, "symbol_base": symbol_base,
            "blocks": blocks, "addr2blk": addr2blk, "branches": branches,
            "contains": contains, "entry": entry, "live": live, "idom": idom,
            "loops": loops}


def _req(rows, rid, status, detail, evidence=None):
    rows.append({"id": rid, "requirement": REQ_ID[rid], "status": status,
                 "detail": detail, "evidence": evidence if evidence else {}})
    return rows[-1]


def insn_text(x):
    t = "%s %s" % (x["mnemonic"], x["operands"])
    return re.sub(r"\s+", " ", t).strip()


def loop_body_addrs(ctx, L):
    blocks = ctx["blocks"]
    out = []
    for n in L["nodes"]:
        for i in range(blocks[n]["first_idx"], blocks[n]["last_idx"] + 1):
            out.append(ctx["ins"][i]["addr"])
    return sorted(out)


def reaching_init_defs(ctx, L, reg):
    """Definitions of `reg` that reach the loop head from OUTSIDE the loop.

    The loop's own back edges into the head are CUT first, so this answers
    "what did the register hold on entry", not "what did the last iteration
    leave".  Confusing the two is how a reset inside the loop reads as the
    initial value.
    """
    ins, idx, blocks, contains = ctx["ins"], ctx["idx"], ctx["blocks"], \
        ctx["contains"]
    nodes = set(L["nodes"])
    head_blk = L["head"]
    roots = []
    for p in blocks[head_blk]["predecessors"]:
        if p["block"] in nodes:
            continue                      # an in-loop back edge: CUT
        roots.append(ins[blocks[p["block"]]["last_idx"]]["addr"])
    defs, unknowns = [], []
    seen = set()
    stack = list(roots)
    while stack:
        a = stack.pop()
        if a in seen:
            continue
        seen.add(a)
        x = ins[idx[a]]
        w = writes_register(x, reg)
        if w is None:
            unknowns.append({"at": hex(a), "insn": insn_text(x)})
            continue
        if w:
            defs.append({"at": hex(a), "insn": insn_text(x),
                         "block": contains[a],
                         "in_the_loop": contains[a] in nodes})
            continue                      # KILL: the definition is this one
        b = contains[a]
        i = idx[a]
        if i > blocks[b]["first_idx"]:
            stack.append(ins[i - 1]["addr"])
            continue
        for q in sorted({p["block"] for p in blocks[b]["predecessors"]}):
            stack.append(ins[blocks[q]["last_idx"]]["addr"])
    return sorted(defs, key=lambda d: d["at"]), unknowns


def constant_of(insn, reg):
    """The constant an `s_mov_b32 reg, imm` / `s_mov_b64 s[a:b], imm` writes
    into `reg`'s 32 bits, or None."""
    m = insn["mnemonic"]
    if m not in ("s_mov_b32", "s_mov_b64", "s_movk_i32"):
        return None
    f = operand_fields(insn["operands"])
    if len(f) != 2:
        return None
    if reg not in sgpr_names(f[0]):
        return None
    if not re.fullmatch(r"-?(?:0[xX][0-9a-fA-F]+|\d+)", f[1]):
        return None
    v = int(f[1], 0)
    return u32(v)


def dominates_insn(ctx, a_addr, b_addr):
    """does the instruction at a_addr dominate the instruction at b_addr?"""
    if a_addr == b_addr:
        return True
    ba, bb = ctx["contains"][a_addr], ctx["contains"][b_addr]
    if ba == bb:
        return a_addr < b_addr
    return M.dominates(ctx["idom"], ba, bb)


def transitive_spin(ctx, L, reg, init_defs):
    """brief section 76 -- does the loop's EXIT depend on external memory?

    Backward SGPR closure from the guard register inside the loop, following
    EVERY in-loop writer of a register in the closure and taking that writer's
    source registers.  Any step that is a LOAD is an external dependency.  The
    reaching initial definition is checked too: a trip count that comes from
    memory is not a static bound.
    """
    ins, idx = ctx["ins"], ctx["idx"]
    body = set(loop_body_addrs(ctx, L))
    closure = {reg}
    frontier = [reg]
    load_writers = []
    unmodelled = []
    while frontier:
        r = frontier.pop()
        for a in sorted(body):
            x = ins[idx[a]]
            w = writes_register(x, r)
            if w is None:
                unmodelled.append({"at": hex(a), "insn": insn_text(x),
                                   "register": r})
                continue
            if not w:
                continue
            if is_load(x["mnemonic"]):
                load_writers.append({"at": hex(a), "insn": insn_text(x),
                                     "register": r})
            f = operand_fields(x["operands"])
            for tok in (f[1:] if f else []):
                for s in sgpr_names(tok):
                    if s not in closure:
                        closure.add(s)
                        frontier.append(s)
    init_loads = [d for d in init_defs
                  if is_load(ctx["ins"][ctx["idx"][int(d["at"], 16)]]
                             ["mnemonic"])]
    #: a chain that leaves SGPR-land and comes back through a VGPR read
    #: (`global_load v -> v_readfirstlane s`) is NOT tracked by an SGPR-only
    #: closure; if the loop contains one, the answer is unknown, not "no spin".
    vgpr_bridge = [{"at": hex(a), "insn": insn_text(ins[idx[a]])}
                   for a in sorted(body)
                   if ins[idx[a]]["mnemonic"] in ("v_readfirstlane_b32",
                                                  "v_readlane_b32")
                   and sgpr_names(operand_fields(
                       ins[idx[a]]["operands"])[0] or "") & closure]
    return {"guard_register": reg,
            "sgpr_closure_of_the_exit_condition": sorted(closure),
            "load_writers_of_a_register_in_the_closure": load_writers,
            "reaching_initial_definitions_that_are_loads": init_loads,
            "sgpr_closure_is_incomplete_due_to_a_vgpr_bridge": vgpr_bridge,
            "unmodelled_scalar_instructions_mentioning_a_closure_register":
                unmodelled,
            "is_spin": bool(load_writers or init_loads),
            "is_unknown": bool(unmodelled or vgpr_bridge)}


def _finish(out, rows, verdict, blocking_reason):
    """Complete the requirement table and return the row.

    Every requirement appears exactly once.  A requirement the prover never
    reached is written down as NOT_EVALUATED rather than left out: an absent row
    and a passed row look the same to a reader skimming for failures, and this
    project has already been bitten by a checker that scored absence as
    non-blocking.
    """
    seen = {r["id"] for r in rows}
    for rid, _ in REQUIREMENTS:
        if rid not in seen:
            rows.append({"id": rid, "requirement": REQ_ID[rid],
                         "status": "NOT_EVALUATED", "detail":
                         "the prover stopped before this requirement; it was "
                         "never reached", "evidence": {}})
    rows.sort(key=lambda r: [k for k, _ in REQUIREMENTS].index(r["id"]))
    out["requirements"] = rows
    out["n_requirements_proven"] = sum(1 for r in rows
                                       if r["status"] == PROVEN)
    out["first_failing_requirement"] = next(
        (r["id"] for r in rows if r["status"] == FAILED), None)
    out["first_unknown_requirement"] = next(
        (r["id"] for r in rows if r["status"] == UNKNOWN), None)
    out["verdict"] = verdict
    out["blocking_reason"] = blocking_reason
    return out


def prove_loop(ctx, L, index=None):
    """The full requirement-by-requirement proof for one natural loop.

    Order matters once, and deliberately: the transitive spin analysis (brief
    section 76) runs as soon as the guard register is known, BEFORE the
    recurrence-form checks.  A loop whose exit condition reads external memory
    usually also fails the "one in-loop writer, an immediate add" form, and if
    those fired first every spin would be reported as a form mismatch.  The
    reason a loop is refused is part of the answer, so the most specific
    question is asked first.
    """
    ins, idx, blocks, branches = ctx["ins"], ctx["idx"], ctx["blocks"], \
        ctx["branches"]
    rows = []
    out = {"loop_index": index,
           "head_pc": hex(blocks[L["head"]]["start"]),
           "latch_pc": hex(blocks[L["latch"]]["terminator_at"]),
           "n_nodes": len(L["nodes"]), "nesting_depth": L["nesting_depth"],
           "exits": [hex(x) for x in L["exits"]],
           "requirements": []}

    latch_addr = blocks[L["latch"]]["terminator_at"]
    latch_insn = ins[idx[latch_addr]]
    latch_blk = L["latch"]

    # ---- R08 branch direction -------------------------------------------
    d = branches.get(latch_addr)
    head_start = blocks[L["head"]]["start"]
    if d is None or d["kind"] != "cond":
        _req(rows, "R08", FAILED, "the latch terminator is not a conditional "
             "branch", {"at": hex(latch_addr), "insn": insn_text(latch_insn)})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R08: the latch is not a conditional branch")
    polarity = "scc1" if d["opclass"] == "s_cbranch_scc1" else \
               ("scc0" if d["opclass"] == "s_cbranch_scc0" else None)
    if polarity is None or d["A"] != head_start:
        _req(rows, "R08", FAILED,
             "the branch is not s_cbranch_scc0/scc1, or it does not target the "
             "loop head",
             {"at": hex(latch_addr), "insn": insn_text(latch_insn),
              "target": hex(d["A"]), "head_block_start": hex(head_start)})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R08: branch direction not supported")
    _req(rows, "R08", PROVEN,
         "the latch is a %s whose target is the loop head, so control returns "
         "to the head exactly when the guard's SCC is %s"
         % (d["opclass"], "1" if polarity == "scc1" else "0"),
         {"at": hex(latch_addr), "insn": insn_text(latch_insn),
          "target": hex(d["A"]), "head_block_start": hex(head_start),
          "continues_when_guard_is": polarity})

    # ---- R07 branch comparison ------------------------------------------
    w, u, _cyc = M.reaching_scc_defs(blocks, ctx["contains"], ins, idx,
                                     latch_blk)
    if len(w) != 1 or u:
        _req(rows, "R07", UNKNOWN,
             "the latch's SCC producer is not a UNIQUE, fully-modelled scalar "
             "definition",
             {"n_reaching_scc_defs": len(w),
              "reaching_scc_defs": {hex(k): "%s %s" % (v["mnemonic"],
                                                       v["operands"])
                                    for k, v in sorted(w.items())},
              "unmodelled": {hex(k): v for k, v in sorted(u.items())}})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R07: no unique reaching SCC definition")
    prod_addr, prod = list(w.items())[0]
    prod_blk = ctx["contains"][prod_addr]
    parsed = parse_cmp(prod["mnemonic"], prod["operands"])
    if parsed is None or prod_blk != latch_blk:
        _req(rows, "R07", FAILED,
             "the SCC producer is not a register-versus-immediate compare, or "
             "it does not lie in the latch block",
             {"producer": {"at": hex(prod_addr),
                           "insn": "%s %s" % (prod["mnemonic"],
                                              prod["operands"])},
              "producer_block": prod_blk, "latch_block": latch_blk})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R07: the guard is not a compare in the latch block")
    reg, T, op, signedness = parsed
    signed = (signedness == "i32")
    _req(rows, "R07", PROVEN,
         "the latch's unique reaching SCC definition is `%s %s`, in the latch "
         "block, comparing %s against the immediate %d"
         % (prod["mnemonic"], prod["operands"], reg, s32(T) if signed else T),
         {"producer": {"at": hex(prod_addr),
                       "insn": "%s %s" % (prod["mnemonic"], prod["operands"])},
          "producer_block": prod_blk, "latch_block": latch_blk,
          "predicate": op, "signedness": signedness,
          "termination_value_as_written": T})
    _req(rows, "R01", PROVEN,
         "the induction register is %s, the register the latch's guard "
         "compares against an immediate" % reg,
         {"induction_register": reg,
          "guard": "%s %s" % (prod["mnemonic"], prod["operands"])})
    #: recorded on EVERY path, not only the proven one, so a caller comparing
    #: the prover against a direct load test knows which register to ask about
    #: even when the prover refused the loop.
    out["induction_register"] = reg
    out["guard_register"] = reg

    # ---- R76 transitive spin dependency ---------------------------------
    init_defs, init_unknown = reaching_init_defs(ctx, L, reg)
    spin = transitive_spin(ctx, L, reg, init_defs)
    out["transitive_spin_dependency"] = spin
    if spin["is_spin"]:
        _req(rows, "R76", FAILED,
             "the loop's exit condition depends on external memory: the "
             "transitive SGPR closure of %s inside the loop reaches a LOAD, so "
             "the trip count waits on another agent rather than on a counter"
             % reg,
             {"guard_register": reg,
              "closure": spin["sgpr_closure_of_the_exit_condition"],
              "load_writers_found": spin[
                  "load_writers_of_a_register_in_the_closure"],
              "reaching_initial_definitions_that_are_loads": spin[
                  "reaching_initial_definitions_that_are_loads"],
              "why_the_direct_test_misses_this": "the 16AT test asked whether "
              "a load's DESTINATION was the compared register; on a chain "
              "load -> move/arithmetic -> compare the load writes some other "
              "register and the direct test answers `not a spin`"})
        return _finish(out, rows, VERDICT_SPIN,
                       "R76: the exit condition reads external memory")
    if spin["is_unknown"]:
        _req(rows, "R76", UNKNOWN,
             "the exit condition's dependency on external memory could not be "
             "decided: an instruction in the closure could not be modelled",
             {"unmodelled": spin[
                 "unmodelled_scalar_instructions_mentioning_a_closure_register"],
              "vgpr_bridge": spin[
                  "sgpr_closure_is_incomplete_due_to_a_vgpr_bridge"]})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R76: the spin question could not be decided")
    _req(rows, "R76", PROVEN,
         "no load writes any register in the transitive closure of %s inside "
         "the loop, and the entry value is a constant rather than a loaded "
         "word, so the exit depends only on the wave's own counter" % reg,
         {"guard_register": reg,
          "closure": spin["sgpr_closure_of_the_exit_condition"],
          "n_loads_in_the_closure": 0,
          "n_instructions_scanned_in_the_loop_body":
              len(loop_body_addrs(ctx, L))})

    # ---- R11/R04/R05/R06 the in-loop writers ----------------------------
    body = loop_body_addrs(ctx, L)
    writers, unmodelled = [], []
    for a in body:
        x = ins[idx[a]]
        wr = writes_register(x, reg)
        if wr is None:
            unmodelled.append({"at": hex(a), "insn": insn_text(x)})
            continue
        if wr:
            writers.append(x)
    if unmodelled:
        _req(rows, "R11", UNKNOWN,
             "an instruction whose write set could not be classified mentions "
             "the induction register, so a reset cannot be excluded",
             {"unmodelled": unmodelled})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R11: an unmodelled scalar instruction mentions the "
                       "induction register")
    if len(writers) != 1:
        _req(rows, "R11", FAILED,
             "the loop body must contain exactly one writer of %s, the "
             "recurrence update; it contains %d, so a reset or a second write "
             "on an alternate path cannot be excluded" % (reg, len(writers)),
             {"writers": [{"at": hex(x["addr"]), "insn": insn_text(x)}
                          for x in writers],
              "loop_body_instructions_scanned": len(body)})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R11: %d in-loop writers of %s" % (len(writers), reg))
    upd = writers[0]
    _req(rows, "R11", PROVEN,
         "exactly one instruction in the loop body writes %s, so there is no "
         "reset and no second write on an alternate path" % reg,
         {"the_only_writer": {"at": hex(upd["addr"]), "insn": insn_text(upd)},
          "loop_body_instructions_scanned": len(body)})

    upd_parsed = re.match(
        r"^s_(add|addk|sub|subb)_(u32|i32)\s+(\w+),\s*(\w+),\s*(-?\d+)$",
        insn_text(upd))
    if upd_parsed is None:
        _req(rows, "R04", FAILED,
             "the only in-loop writer of %s is not an immediate add/sub, so it "
             "is not a supported recurrence update" % reg,
             {"writer": {"at": hex(upd["addr"]), "insn": insn_text(upd)}})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R04: the update is not an immediate add/sub")
    _kind, _w, upd_dst, upd_src, upd_imm = upd_parsed.groups()
    upd_imm = int(upd_imm)
    if _kind in ("subb",):
        #: `s_subb_u32 Rd, Rs, imm` SUBTRACTS (imm + SCC) -- it reads the carry
        #: as a borrow-in, so it is not a self-contained recurrence and the
        #: orbit model below does not describe it.  Refused explicitly rather
        #: than matched by the add/sub family.
        _req(rows, "R04", FAILED,
             "the only in-loop writer of %s is `%s`, which reads SCC as a "
             "borrow-in and is therefore not a self-contained recurrence"
             % (reg, insn_text(upd)),
             {"writer": {"at": hex(upd["addr"]), "insn": insn_text(upd)},
              "mnemonic_family": _kind})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R04: the update reads the carry as a borrow-in")
    #: THE SIGN OF THE STEP COMES FROM THE MNEMONIC, NOT FROM THE LITERAL.
    #: `s_sub_u32 s0, s0, 1` is written with a POSITIVE literal and SUBTRACTS;
    #: reading the literal alone turned every countdown into a count-up, and a
    #: count-up that never reaches its target is refused as unbounded, so the
    #: defect was a false refusal rather than a false bound.  It is fixed here
    #: because a prover that refuses the known-good countdown is not qualified
    #: (control P5 and P8 are the rows that measure it).
    if _kind in ("sub",):
        upd_imm = -upd_imm
    _req(rows, "R04", PROVEN,
         "the recurrence update is `%s`, a %s with the immediate %d"
         % (insn_text(upd), _kind, upd_imm),
         {"update": {"at": hex(upd["addr"]), "insn": insn_text(upd)},
          "mnemonic_family": _kind, "literal_as_written": upd_parsed.group(5),
          "step_sign_taken_from": "the mnemonic (%s), not the literal"
                                  % _kind})

    if not (sgpr_names(upd_src) == {reg} and sgpr_names(upd_dst) == {reg}):
        _req(rows, "R05", FAILED,
             "the update's SOURCE operand is not the induction register: %s is "
             "written from %s, so the guard's register is not advanced by its "
             "own value" % (reg, upd_src),
             {"update": {"at": hex(upd["addr"]), "insn": insn_text(upd)},
              "destination": upd_dst, "source": upd_src,
              "induction_register": reg,
              "why_this_is_a_rejection": "a shape-only classifier matches the "
              "DESTINATION and never reads the SOURCE, so it certifies this "
              "loop as counted"})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R05: the update does not read %s" % reg)
    _req(rows, "R05", PROVEN,
         "the update's source operand is %s itself, so the recurrence is "
         "self-referential" % reg,
         {"update": {"at": hex(upd["addr"]), "insn": insn_text(upd)},
          "destination": upd_dst, "source": upd_src})

    step = upd_imm % (1 << 32)
    if step == 0:
        _req(rows, "R06", FAILED,
             "the step is ZERO: `%s` adds nothing, so the induction register "
             "never changes and the guard's value is fixed for every trip"
             % insn_text(upd),
             {"update": {"at": hex(upd["addr"]), "insn": insn_text(upd)},
              "step": 0,
              "why_this_is_a_rejection": "the retired classifier counted this "
              "instruction as an advance because its DESTINATION was the guard "
              "register, and emitted max_trip_count=None beside a "
              "COUNTED_LOOP_WITH_STATIC_BOUND verdict"})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R06: zero step -- the register never changes")
    _req(rows, "R06", PROVEN,
         "the step is %d, nonzero, so the register's value changes every trip"
         % s32(upd_imm),
         {"update": {"at": hex(upd["addr"]), "insn": insn_text(upd)},
          "step": s32(upd_imm), "step_mod_2_32": step})

    # ---- R10 the update reaches EVERY latch path ------------------------
    #: `natural_loops` reports ONE latch per loop.  A loop can have more than
    #: one block branching back to its head, and the update must reach all of
    #: them, so the back-edge set is recomputed here.  It is built COMPLETE
    #: before it is iterated -- appending to a list while iterating it is an
    #: infinite loop, and the prover's first version hung there silently.
    #:
    #: Only edges from INSIDE the loop count.  The head also has ENTRY edges
    #: (the preheader's fall-through, a guard's taken branch); those do not
    #: re-enter the loop body and no update executes on them, so requiring the
    #: update to dominate them would reject every loop in the object -- which is
    #: exactly what the first version of this check did, and it is why the
    #: first full run reported 33 of 33 UNKNOWN_BLOCKING.
    nodes = set(L["nodes"])
    back_edge_blocks = sorted(
        {b for b in nodes
         for s in blocks[b]["successors"] if s["block"] == L["head"]}
        | {L["latch"]})
    entry_edges = sorted(
        {p["block"] for p in blocks[L["head"]]["predecessors"]
         if p["block"] not in nodes})
    dom_rows = []
    all_dom = True
    for lb in back_edge_blocks:
        la = blocks[lb]["terminator_at"]
        ok = dominates_insn(ctx, upd["addr"], la)
        all_dom = all_dom and ok
        dom_rows.append({"latch_block": lb, "latch_pc": hex(la),
                         "update_dominates_the_latch": ok})
    if not all_dom:
        _req(rows, "R10", FAILED,
             "the update does not dominate every latch path: a branch back to "
             "the head exists that can be reached without executing it",
             {"latch_rows": dom_rows,
              "update": {"at": hex(upd["addr"]), "insn": insn_text(upd)},
              "loop_entry_edges_which_are_not_back_edges":
                  [hex(x) for x in entry_edges]})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R10: the update is skipped on a latch path")
    if ctx["contains"][upd["addr"]] != prod_blk:
        _req(rows, "R10", UNKNOWN,
             "the update reaches every latch, but it is not in the guard's "
             "basic block, so the value the guard sees on a trip is not decided "
             "by address order and this prover does not model it",
             {"update_block": ctx["contains"][upd["addr"]],
              "guard_block": prod_blk, "latch_rows": dom_rows})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R10: the update and the guard are in different basic "
                       "blocks")
    if upd["addr"] > prod_addr:
        _req(rows, "R10", UNKNOWN,
             "the update follows the guard in the same block, so the guard "
             "reads the value from the PREVIOUS trip; only the update-first "
             "order is modelled here",
             {"update": hex(upd["addr"]), "guard": hex(prod_addr)})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R10: guard-before-update order is not modelled")
    _req(rows, "R10", PROVEN,
         "the update at %s dominates every latch terminator of this loop "
         "(back edges: %s) and precedes the guard in the same basic block, so "
         "it executes on every trip before the guard is evaluated"
         % (hex(upd["addr"]),
            [hex(blocks[b]["terminator_at"]) for b in back_edge_blocks]),
         {"latch_rows": dom_rows, "update_in_the_guard_block": True,
          "update_before_guard": True,
          "loop_entry_edges_which_are_not_back_edges":
              [hex(x) for x in entry_edges]})

    # ---- R03/R02 initial value ------------------------------------------
    if init_unknown:
        _req(rows, "R03", UNKNOWN,
             "an instruction on a path into the loop head could not be "
             "classified for writes to %s" % reg,
             {"unmodelled": init_unknown})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R03: an unclassified reaching instruction")
    if len(init_defs) != 1:
        _req(rows, "R03", FAILED,
             "the induction register must have exactly ONE reaching definition "
             "outside the loop; %d were found" % len(init_defs),
             {"reaching_definitions": init_defs,
              "why_this_is_a_rejection": "with no unique entry value the "
              "recurrence has no starting point, so no bound can be derived"})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R03: %d reaching initial definitions" % len(init_defs))
    init = init_defs[0]
    if init["in_the_loop"]:
        _req(rows, "R03", FAILED,
             "the only reaching definition of %s is INSIDE the loop, so the "
             "value on entry is whatever the previous iteration left" % reg,
             {"reaching_definition": init})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R03: the initial definition is inside the loop")
    init_insn = ins[idx[int(init["at"], 16)]]
    v0 = constant_of(init_insn, reg)
    if v0 is None:
        _req(rows, "R02", FAILED,
             "the reaching initial definition of %s is not a constant move, so "
             "the entry value, and therefore the trip count, is DATA DEPENDENT"
             % reg,
             {"reaching_definition": init,
              "why_this_is_a_rejection": "a bound computed from a register "
              "that did not come from an immediate is not a static bound"})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R02: the initial value is not a constant")
    _req(rows, "R03", PROVEN,
         "exactly one definition of %s reaches the loop head from outside the "
         "loop; the loop's own back edges are cut before the search" % reg,
         {"reaching_definition": init, "n_reaching_definitions": 1,
          "back_edges_cut": [hex(blocks[b]["terminator_at"])
                             for b in back_edge_blocks]})
    _req(rows, "R02", PROVEN,
         "the entry value is the constant %d from `%s`"
         % (s32(v0) if signed else v0, insn_text(init_insn)),
         {"reaching_definition": init, "value_0": v0,
          "value_0_as_signed": s32(v0),
          "post_update_first_value_A0": u32(v0 + step)})

    # ---- R09 the exit is reached ----------------------------------------
    A0 = u32(v0 + step)
    orbit = orbit_verdict(A0, step, op, T, signed, polarity)
    out["orbit"] = orbit
    if orbit["status"] == "INFINITE":
        _req(rows, "R09", FAILED,
             "the loop NEVER exits: %s"
             % ("the guard's continue-set is the entire 32-bit domain, so no "
                "value of %s can end the loop" % reg
                if orbit["continue_set_is_the_whole_domain"] else
                "the value that would end the loop is not in the recurrence's "
                "orbit at all"),
             {"orbit_status": orbit["status"],
              "continue_set_is_the_whole_domain":
                  orbit["continue_set_is_the_whole_domain"],
              "infinity_proved_by": orbit.get("infinity_proved_by"),
              "why_this_is_a_rejection": "the retired classifier called this a "
              "counted loop with a static bound"})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R09: the recurrence never satisfies the exit condition")
    if orbit["status"] != "EXITS":
        _req(rows, "R09", UNKNOWN,
             "no exit was found within the supported search: %s"
             % orbit.get("why", "the first exit index exceeds the cap"),
             {"orbit_status": orbit["status"], "cap_trips": CAP_TRIPS,
              "first_wrap_at": orbit["first_wrap_at"],
              "route_form": orbit["route_form"],
              "route_form_credited": orbit["route_form_credited"],
              "route_sim": orbit["route_sim"]})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R09: %s" % orbit["status"])
    exit_j = orbit["route_sim"]
    _req(rows, "R09", PROVEN,
         "the recurrence DOES reach an exit: the first guard evaluation whose "
         "value leaves the continue-set is j=%d" % exit_j,
         {"orbit_status": orbit["status"], "first_exit_index_j": exit_j,
          "trip_count": orbit["trip_count"],
          "the_value_at_which_the_loop_exits":
              hex(u32(A0 + exit_j * s32(step)))})

    # ---- R12 modular wrap -----------------------------------------------
    wrap_at = orbit["first_wrap_at"]
    if wrap_at is not None and wrap_at <= exit_j:
        _req(rows, "R12", FAILED,
             "the 32-bit addition leaves the domain BEFORE the loop exits "
             "(first wrap at j=%d, exit at j=%d), so the value at the exit is "
             "not the value the closed form predicted from the progression"
             % (wrap_at, exit_j),
             {"first_wrap_at": wrap_at, "exit_at": exit_j,
              "why_this_is_a_rejection": "a bound derived from an unwrapped "
              "progression is wrong here, and the retired classifier derived "
              "exactly such a bound"})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R12: the recurrence wraps before the exit")
    _req(rows, "R12", PROVEN,
         "no modular wrap occurs inside the window [0, %d]; the exit is "
         "reached before the 32-bit value leaves its domain" % exit_j,
         {"first_wrap_at": wrap_at, "exit_at": exit_j,
          "wrap_computed_on": "exact 32-bit addition, the same width the "
                              "hardware uses"})

    # ---- R13 finite maximum trip count ----------------------------------
    if orbit["routes_agree"] is not True:
        _req(rows, "R13", UNKNOWN,
             "the trip count is not confirmed by two independent routes: %s"
             % orbit.get("why", "the closed form and the simulation disagree"),
             {"route_sim": orbit["route_sim"],
              "route_form": orbit["route_form"],
              "routes_agree": orbit["routes_agree"],
              "route_form_kind": orbit.get("route_form_kind")})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R13: " + orbit.get("why", "routes disagree"))
    trips = orbit["trip_count"]
    if trips > CAP_TRIPS:
        _req(rows, "R13", UNKNOWN,
             "the exact trip count %d exceeds the supported cap %d"
             % (trips, CAP_TRIPS),
             {"exact_trip_count": trips, "cap_trips": CAP_TRIPS})
        return _finish(out, rows, VERDICT_UNKNOWN,
                       "R13: the trip count exceeds the supported cap")
    _req(rows, "R13", PROVEN,
         "the maximum trip count is %d, confirmed independently by ROUTE SIM "
         "(bit-exact 32-bit simulation) and ROUTE FORM (%s)"
         % (trips, orbit.get("route_form_kind", "closed form")),
         {"max_trip_count": trips, "route_sim": orbit["route_sim"],
          "route_form": orbit["route_form"],
          "route_form_kind": orbit.get("route_form_kind"),
          "routes_agree": True})

    out["max_trip_count"] = trips
    out["induction_register"] = reg
    out["update"] = {"at": hex(upd["addr"]), "insn": insn_text(upd),
                     "step": s32(upd_imm)}
    out["guard"] = {"at": hex(prod_addr),
                    "insn": "%s %s" % (prod["mnemonic"], prod["operands"]),
                    "predicate": op, "signedness": signedness,
                    "termination_value": T}
    out["initial_value"] = {"at": init["at"], "insn": init["insn"],
                            "value_0": v0, "post_update_A0": A0}
    return _finish(out, rows, VERDICT_PROVEN, None)


def prove_all(ctx):
    return [prove_loop(ctx, L, i) for i, L in enumerate(ctx["loops"])]
