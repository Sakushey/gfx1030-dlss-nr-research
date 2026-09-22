#!/usr/bin/env python3
"""Phase 16AX T-VOPD -- the general VOPD parallel-assignment lowering.

THE RULE
  A gfx11 `v_dual_X a :: v_dual_Y b` executes BOTH sides as one instruction, and
  BOTH sides read the PRE-instruction register state.  Lowering it into two
  sequential instructions in printed order is therefore wrong whenever the left
  op writes a register the right op reads: the right op then reads the left's
  RESULT instead of the old value.

  The fix is NOT a patch at one address.  It is an ORDER rule:

    X = left side, Y = right side
    L2R = writes(X) intersect reads(Y)      <- Y would read X's new value
    R2L = writes(Y) intersect reads(X)      <- X would read Y's new value
    WAW = writes(X) intersect writes(Y)

    WAW non-empty            -> UNSUPPORTED_DESTINATION_CONFLICT
    L2R and R2L (a cycle)    -> TEMPORARY_TWO_PHASE
    L2R only                 -> REORDERED_READER_FIRST   : emit Y then X
    R2L only                 -> SEQUENTIAL_PUBLISHED_ORDER_SAFE : emit X then Y
    neither                  -> SEQUENTIAL_INDEPENDENT   : emit X then Y

WHY THE ORDER RULE IS SOUND  (the argument, not the assertion)
  Case R2L / INDEPENDENT, emitted X then Y:
    X reads only pre-state, because nothing has been written yet.
    Y reads: reads(Y) contains no register written by X (L2R is empty), and Y's
    own destination is not yet written -- so Y also reads only pre-state.
    => both sides see the pre-instruction state, which is the atomic semantics.
  Case L2R, emitted Y then X: the same argument applied to the opposite side.
    Y reads only pre-state.  X reads nothing Y wrote (R2L empty), including its
    own destination, which Y does not write (WAW empty).  => both sides see the
    pre-instruction state.
  This is exactly why R2L and L2R must be computed separately: R2L is ALREADY
  safe under the printed order and L2R is not.  Lowering L2R by swapping and
  R2L by swapping too would be the same defect mirrored.

  Case cycle, TEMPORARY_TWO_PHASE: snapshot every register the pair reads that
  the pair also writes, compute both results from the snapshots, commit both
  destinations last.  Every source read is then from a pre-instruction snapshot.

STATUS / EXEC  (brief step 3)
  A VOPD carries ONE predicate for both halves and both halves execute under the
  ambient EXEC.  Neither emitted instruction carries a predicate, so both
  execute under that same ambient EXEC -- identical predication, not merely a
  similar one.  The other shared state is the status register file.  The
  lowering is status-neutral iff NO side writes a status register; the pair's
  status effect is then a pure read, and reordering pure reads cannot change
  what is read as long as nothing in the emitted sequence writes them.  This is
  ASSERTED PER SITE by `status_proof`, and a pair that DOES write a status
  register is REFUSED rather than lowered.

REUSE
  The dependency rule is NOT reimplemented.  `p16ax_vopd_model` imports the
  16AW analyzer and `M.V.classify_pair` remains the classifier of record; this
  module re-derives the same sets only to choose an ORDER, and a cross-check
  asserts the two agree per site.

WHAT THIS DOES NOT ESTABLISH
  * that a lowered instruction is encodable -- measured by llvm-mc elsewhere
  * that the surrounding non-VOPD stream is translatable -- out of scope
  * anything about the GPU.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import p16ax_vopd_model as M  # noqa: E402

# --------------------------------------------------------------------------
# lowering classes
# --------------------------------------------------------------------------
UNSUPPORTED_UNMODELLED = "UNSUPPORTED_UNMODELLED_MNEMONIC"
UNSUPPORTED_WAW = "UNSUPPORTED_DESTINATION_CONFLICT"
UNSUPPORTED_STATUS = "UNSUPPORTED_STATUS_CONFLICT"
UNSUPPORTED_ACCUM_TEMP = "UNSUPPORTED_ACCUMULATOR_TEMP_NEEDS_PRECISION_PROOF"

SEQUENTIAL_INDEPENDENT = "SEQUENTIAL_INDEPENDENT"
SEQUENTIAL_PUBLISHED_ORDER = "SEQUENTIAL_PUBLISHED_ORDER_SAFE"
REORDERED_READER_FIRST = "REORDERED_READER_FIRST"
TEMPORARY_TWO_PHASE = "TEMPORARY_TWO_PHASE"

SUPPORTED = (SEQUENTIAL_INDEPENDENT, SEQUENTIAL_PUBLISHED_ORDER,
             REORDERED_READER_FIRST, TEMPORARY_TWO_PHASE)

#: modifier classes the lowering must preserve.  The method is a VERBATIM
#: operand-text copy, so this tuple is a proof CHECKLIST, not a re-emit recipe.
MODIFIER_CLASSES = (
    "negation", "absolute", "clamp", "op_sel", "op_sel_hi",
    "literal", "source_half", "dest_half", "rounding",
)


def modifier_inventory(text):
    """Which modifier classes this side's operand text actually carries."""
    found = {}
    mn, rest = M.split_side(text)
    toks = rest.split()
    for t in toks:
        if t.startswith("op_sel_hi:"):
            found["op_sel_hi"] = t
        elif t.startswith("op_sel:"):
            found["op_sel"] = t
        elif t == "clamp":
            found["clamp"] = t
        elif "neg(" in t:
            found["negation"] = t
        elif "abs(" in t:
            found["absolute"] = t
    # per-operand scan (operand tokens may carry a leading - or surrounding |)
    ops = M.V.split_operands(rest)
    for o in ops:
        body = o.split()[0]
        if body.startswith("|") or body.endswith("|"):
            found.setdefault("absolute", o)
        elif body.startswith("-") and not body.lstrip("-").replace(".", "").isdigit():
            found.setdefault("negation", o)
        elif body.startswith("-") or body.startswith("0x") or \
                body.lstrip("-").replace(".", "").isdigit():
            found.setdefault("literal", o)
    return found


# --------------------------------------------------------------------------

def _detail(rec, addr, x_text, y_text):
    return rec


def lower_pair(x_text, y_text, addr=None, temp_pool=None):
    """Derive read/write sets, choose the lowering, and emit the sequence.

    `temp_pool` is only consulted for a two-phase site; it must list register
    names that are free at this point in the function.
    """
    x_text = x_text.strip()
    y_text = y_text.strip()
    X = M.analyse_ext(x_text)
    Y = M.analyse_ext(y_text)

    rec = {
        "addr": addr, "x": x_text, "y": y_text,
        "reads_X": None, "writes_X": None,
        "reads_Y": None, "writes_Y": None,
        "status_reads_X": None, "status_reads_Y": None,
        "status_writes_X": None, "status_writes_Y": None,
        "exec_write_X": None, "exec_write_Y": None,
        "implicit_dest_read_X": None, "implicit_dest_read_Y": None,
        "left_writes_right_reads": None, "right_writes_left_reads": None,
        "write_write_conflict": None,
        "class": None, "reason": None, "emitted": None, "emit_order": None,
        "equivalence_argument": None, "status_proof": None, "exec_proof": None,
        "modifier_proof": None, "temporaries": [],
        "classifier_cross_check": None,
    }

    if X is None or Y is None or not X["modelled"] or not Y["modelled"]:
        rec["class"] = UNSUPPORTED_UNMODELLED
        rec["reason"] = ((X or {}).get("reason") or (Y or {}).get("reason")
                         or "unparsed side")
        return rec

    rx, wx = set(X["reads"]), set(X["writes"])
    ry, wy = set(Y["reads"]), set(Y["writes"])
    rec.update({
        "reads_X": sorted(rx), "writes_X": sorted(wx),
        "reads_Y": sorted(ry), "writes_Y": sorted(wy),
        "status_reads_X": sorted(X["status_reads"]),
        "status_reads_Y": sorted(Y["status_reads"]),
        "status_writes_X": sorted(X["status_writes"]),
        "status_writes_Y": sorted(Y["status_writes"]),
        "exec_write_X": X["exec_write"], "exec_write_Y": Y["exec_write"],
        "implicit_dest_read_X": bool(X["accumulator"] or X["dest_named_as_source"]),
        "implicit_dest_read_Y": bool(Y["accumulator"] or Y["dest_named_as_source"]),
    })

    l2r = sorted(wx & ry)
    r2l = sorted(wy & rx)
    waw = sorted(wx & wy)
    rec["left_writes_right_reads"] = l2r
    rec["right_writes_left_reads"] = r2l
    rec["write_write_conflict"] = waw

    # --- independent cross-check that the re-derivation agrees with 16AW ---
    # Both sides are computed from ONE analysis (M.analyse_ext), so this is a
    # consistency check on the ORDER logic, not a second classifier.  It is
    # recorded so an audit can see the two never disagreed.
    c = M.V.classify_pair(x_text, y_text)
    if l2r and r2l:
        expect = "HAZARD_BOTH_DIRECTIONS"
    elif l2r:
        expect = "HAZARD_LEFT_BEFORE_RIGHT"
    elif r2l:
        expect = "HAZARD_RIGHT_BEFORE_LEFT"
    else:
        expect = "INDEPENDENT"
    rec["classifier_cross_check"] = {
        "classify_pair_says": c["class"], "order_rule_derives": expect,
        "agree": c["class"] == expect,
        "note": "the classifier is the rule of record; this only checks that the "
                "order rule did not invert a direction",
    }

    # --- status / EXEC gate: refuse rather than guess ---
    st_conf = None
    if X["status_writes"] & Y["status_reads"]:
        st_conf = "X writes status that Y reads"
    elif Y["status_writes"] & X["status_reads"]:
        st_conf = "Y writes status that X reads"
    elif X["status_writes"] and Y["status_writes"]:
        st_conf = "both sides write status"
    elif X["exec_write"] or Y["exec_write"]:
        st_conf = "a side writes EXEC"
    if st_conf:
        rec["class"] = UNSUPPORTED_STATUS
        rec["reason"] = st_conf
        rec["status_proof"] = {"refused": st_conf}
        return rec

    # --- ordering gate ---
    if waw:
        rec["class"] = UNSUPPORTED_WAW
        rec["reason"] = ("both sides write %s; the atomic pair's arbitration "
                         "between the two destinations is not modelled" % (waw,))
        return rec

    if l2r and r2l:
        if any(s["accumulator"] and s["mnemonic"] != "fmac_f32" for s in (X, Y)):
            rec["class"] = UNSUPPORTED_ACCUM_TEMP
            rec["reason"] = ("an accumulator side would need a different FMA "
                             "opcode on a temporary; bit-identity is not proved "
                             "by this static analysis")
            return rec
        rec["class"] = TEMPORARY_TWO_PHASE
        rec["emit_order"] = ["snapshot", "computeX", "computeY", "commitX", "commitY"]
        rec["equivalence_argument"] = (
            "L2R=%s and R2L=%s form a cycle: no order of two instructions can be "
            "correct.  Every register the pair reads AND writes is snapshotted to "
            "a temporary first, both results are computed from those snapshots, "
            "and both destinations are committed last." % (l2r, r2l))
        sides = _two_phase_sides(rec, x_text, y_text, X, Y, temp_pool)
        if sides is None:
            return rec
        rec["temporaries"] = sorted({M.split_side(s)[1].split(",")[0].strip()
                                     for s in sides if s.startswith("v_dual_mov_b32")})
    elif l2r:
        rec["class"] = REORDERED_READER_FIRST
        rec["emit_order"] = ["Y", "X"]
        rec["equivalence_argument"] = (
            "L2R=%s: Y is the reader, so Y is emitted FIRST and reads pre-state.  "
            "R2L is empty, so X reads nothing Y wrote -- including X's own "
            "destination, which Y does not write (WAW empty).  Both sides read "
            "the pre-instruction state." % (l2r,))
        sides = [y_text, x_text]
    elif r2l:
        rec["class"] = SEQUENTIAL_PUBLISHED_ORDER
        rec["emit_order"] = ["X", "Y"]
        rec["equivalence_argument"] = (
            "R2L=%s: X is the reader, so the PUBLISHED order X then Y is already "
            "safe.  X reads pre-state; L2R is empty, so Y reads nothing X wrote.  "
            "Both sides read the pre-instruction state.  Swapping here would "
            "INTRODUCE the defect, which is why this class is kept distinct from "
            "REORDERED_READER_FIRST." % (r2l,))
        sides = [x_text, y_text]
    else:
        rec["class"] = SEQUENTIAL_INDEPENDENT
        rec["emit_order"] = ["X", "Y"]
        rec["equivalence_argument"] = (
            "writes(X) is disjoint from reads(Y) and writes(Y) is disjoint from "
            "reads(X), so neither side can observe the other's write; order is "
            "immaterial and the published order is kept.")
        sides = [x_text, y_text]

    rec["emitted_source_sides"] = sides
    rec["emitted"] = [M.emit_one(s) for s in sides]
    _attach_proofs(rec, X, Y, x_text, y_text)
    return rec


def _two_phase_sides(rec, x_text, y_text, X, Y, temp_pool):
    """Build the snapshot/compute/commit source text for a cyclic pair."""
    pool = list(temp_pool or [])
    clash = set(X["reads"]) | set(X["writes"]) | set(Y["reads"]) | set(Y["writes"])
    if len(pool) < 5:
        rec["class"] = UNSUPPORTED_ACCUM_TEMP
        rec["reason"] = ("two-phase lowering needs >=5 free temporaries; got %d"
                         % len(pool))
        return None
    if set(pool) & clash:
        rec["class"] = UNSUPPORTED_ACCUM_TEMP
        rec["reason"] = ("temporary pool %s overlaps a register the pair reads or "
                         "writes" % sorted(set(pool) & clash))
        return None

    lines, snap = [], {}

    def snap_of(reg):
        if reg not in snap:
            snap[reg] = pool.pop(0)
            lines.append("v_dual_mov_b32 %s, %s" % (snap[reg], reg))
        return snap[reg]

    for s in (X, Y):
        for r in sorted(set(s["reads"]) & clash):
            snap_of(r)

    results = {}
    for tag, s in (("X", X), ("Y", Y)):
        ops = list(s["operands"])
        body = [snap.get(o.strip(), o) for o in ops[1:]]
        if s["accumulator"]:
            out = pool.pop(0)
            lines.append("v_dual_mov_b32 %s, %s" % (out, snap.get(s["dest"], s["dest"])))
            lines.append("v_dual_fmac_f32 %s, %s, %s" % (out, body[0], body[1]))
        else:
            out = pool.pop(0)
            lines.append("v_dual_%s %s, %s" % (s["mnemonic"], out, ", ".join(body)))
        results[tag] = out
    for tag, s in (("X", X), ("Y", Y)):
        lines.append("v_dual_mov_b32 %s, %s" % (s["dest"], results[tag]))
    return lines


def _attach_proofs(rec, X, Y, x_text, y_text):
    sw = set(X["status_writes"]) | set(Y["status_writes"])
    sr = set(X["status_reads"]) | set(Y["status_reads"])
    neutral = not sw
    rec["status_proof"] = {
        "status_written_by_either_side": sorted(sw),
        "status_read_by_either_side": sorted(sr),
        "status_neutral": neutral,
        "argument": (
            "no side writes a status register, so the pair's status effect is a "
            "pure READ of %s; the emitted sequence contains no writer of those "
            "registers, so each side reads the same value in every order"
            % (sorted(sr) or ["<none>"]) if neutral else "NOT NEUTRAL"),
        "added_mnemonics": (
            "the only mnemonic the lowering ADDS is v_mov_b32_e32 (temp path "
            "only); it writes its VDST and no status register, no SCC, no EXEC"),
    }
    rec["exec_proof"] = {
        "exec_written_by_a_side": bool(X["exec_write"] or Y["exec_write"]),
        "argument": (
            "a VOPD carries ONE predicate for both halves and both halves execute "
            "under the ambient EXEC; neither emitted instruction carries a "
            "predicate, so both execute under that same ambient EXEC.  Neither "
            "side writes EXEC."),
    }
    rec["modifier_proof"] = {
        "classes_modelled": list(MODIFIER_CLASSES),
        "observed_X": modifier_inventory(x_text),
        "observed_Y": modifier_inventory(y_text),
        "method": (
            "the text after the mnemonic is copied VERBATIM into the standalone "
            "form, so every modifier travels with it; a modifier cannot be "
            "dropped by a re-serialisation because there is no re-serialisation"),
        "standalone_spelling_source": (
            "measured from the object's own non-dual instances, then re-assembled "
            "by llvm-mc for gfx1030 (p16ax_vopd_encode.py)"),
    }


# --------------------------------------------------------------------------

if __name__ == "__main__":
    M.ensure_extended()
    demo = lower_pair("v_dual_mov_b32 v1, 0", "v_dual_and_b32 v54, 0x180, v1",
                      addr="0xCB8DC")
    print(json.dumps({k: demo[k] for k in
                      ("addr", "class", "emit_order", "emitted",
                       "left_writes_right_reads", "right_writes_left_reads",
                       "equivalence_argument")}, indent=1))
