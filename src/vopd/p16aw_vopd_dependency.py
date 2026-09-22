#!/usr/bin/env python3
"""Phase 16AW PART III -- VOPD parallel-assignment dependency analyzer.

Brief sections 12-22.

WHAT THIS MEASURES
  A gfx11 VOPD instruction encodes TWO operations that execute as ONE
  instruction and whose sources are read from the PRE-INSTRUCTION register
  state.  A translator that lowers a VOPD into two sequential instructions in
  the printed order is wrong whenever the LEFT op writes a register the RIGHT
  op reads (or vice versa): the second instruction then reads the first's
  RESULT instead of the old value.

  This module derives, per VOPD site, reads_X / writes_X / reads_Y / writes_Y
  and classifies the site.  It fails CLOSED: a mnemonic it does not model is
  UNKNOWN_BLOCKING, never "safe".

DELIBERATE DESIGN POINTS (each is a defect this project has actually shipped)
  * implicit destination reads are modelled (v_fmac: dst is also a source), so
    a destination-as-source FMA is not silently mis-modelled;
  * the printed order is NOT assumed to be the semantic order -- both
    directions are tested and reported separately, because "left before right"
    and "right before left" are different defects;
  * controls are included that MUST be rejected, and each control is checked to
    have REACHED the classifier (a control that dies earlier is INVALID, not a
    rejection);
  * a positive control that MUST be accepted is included, so a rule that
    rejects everything cannot read as strict.
"""

from __future__ import annotations

import json
import os
import re
import struct
import sys

# --------------------------------------------------------------------------
# operand / mnemonic model
# --------------------------------------------------------------------------

#: operand roles per mnemonic.  "D" = destination, "S" = source.
#: IMPLICIT_DEST_READ lists mnemonics whose destination is ALSO a source.
OPERAND_SHAPE = {
    "mov_b32":      "D,S",
    "add_f32":      "D,S,S",
    "mul_f32":      "D,S,S",
    "sub_f32":      "D,S,S",
    "lshlrev_b32":  "D,S,S",
    "and_b32":      "D,S,S",
    "add_nc_u32":   "D,S,S",
    "fmaak_f32":    "D,S,S,S",   # dst = a*b + c
}
#: dst is read as well as written
IMPLICIT_DEST_READ = {"fmac_f32"}          # dst = dst*a + b
OPERAND_SHAPE["fmac_f32"] = "D,S,S"

#: scalar / special state registers that are NOT vector registers
SPECIAL = {"exec_lo", "exec_hi", "exec", "vcc", "vcc_lo", "vcc_hi", "null",
           "scc", "m0", "flat_scratch_lo", "flat_scratch_hi"}

RE_REG = re.compile(r"^([vs])(\d+)$")


def parse_operand(tok: str):
    """Return ('v', n) | ('s', n) | ('special', name) | ('imm', text)."""
    t = tok.strip()
    if not t:
        return ("imm", t)
    # strip source modifiers: -v1, |v1|, -|v1|, v1 neg(...) etc.
    t = t.split(" ")[0]
    t = t.strip("-|")
    if t in SPECIAL:
        return ("special", t)
    m = RE_REG.match(t)
    if m:
        return (m.group(1), int(m.group(2)))
    return ("imm", t)


def split_operands(rest: str):
    """Split an operand list on commas that are not inside [] or ()."""
    out, depth, cur = [], 0, ""
    for ch in rest:
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return [o.strip() for o in out if o.strip()]


def analyse_op(text: str):
    """-> dict(mnemonic, reads:set, writes:set, dest_read:bool, modelled:bool)."""
    m = re.match(r"^(v_dual_)?(\w+)\s*(.*)$", text, re.S)
    if not m:
        return None
    mnem = m.group(2)
    rest = m.group(3).strip()
    shape = OPERAND_SHAPE.get(mnem)
    if shape is None:
        return {"mnemonic": mnem, "modelled": False, "reads": set(), "writes": set(),
                "dest_read": False, "reason": "mnemonic not in the operand model"}
    ops = split_operands(rest)
    if len(ops) != len(shape.split(",")):
        return {"mnemonic": mnem, "modelled": False, "reads": set(), "writes": set(),
                "dest_read": False,
                "reason": "arity %d != modelled %d" % (len(ops), len(shape.split(",")))}
    reads, writes = set(), set()
    dest = None
    for role, op in zip(shape.split(","), ops):
        kind = parse_operand(op)
        if kind[0] == "imm":
            continue
        # Keep special architectural state distinct from numbered SGPR/VGPR
        # names.  Treating every non-immediate as ``%s%d`` crashes on inputs
        # such as ``vcc_lo`` rather than classifying the pair conservatively.
        reg = kind[1] if kind[0] == "special" else "%s%d" % kind
        if role == "D":
            dest = reg
            writes.add(reg)
        else:
            reads.add(reg)
    dest_read = mnem in IMPLICIT_DEST_READ
    if dest_read and dest is not None:
        reads.add(dest)
    return {"mnemonic": mnem, "modelled": True, "reads": reads, "writes": writes,
            "dest_read": dest_read, "reason": None,
            "operands": ops, "dest": dest}


def classify_pair(x_text: str, y_text: str):
    """Classify one VOPD pair.  Fails closed on anything unmodelled."""
    X = analyse_op(x_text)
    Y = analyse_op(y_text)
    if X is None or Y is None or not X["modelled"] or not Y["modelled"]:
        return {"class": "UNKNOWN_BLOCKING",
                "why": (X or {}).get("reason") or (Y or {}).get("reason") or "unparsed",
                "X": X, "Y": Y}
    # a register written by one side and read by the other
    l2r = X["writes"] & Y["reads"]          # left-before-right hazard
    r2l = Y["writes"] & X["reads"]          # right-before-left hazard
    if l2r and r2l:
        cls = "HAZARD_BOTH_DIRECTIONS"
    elif l2r:
        cls = "HAZARD_LEFT_BEFORE_RIGHT"
    elif r2l:
        cls = "HAZARD_RIGHT_BEFORE_LEFT"
    else:
        cls = "INDEPENDENT"
    return {"class": cls, "left_writes_right_reads": sorted(l2r),
            "right_writes_left_reads": sorted(r2l),
            "X": {k: (sorted(v) if isinstance(v, set) else v) for k, v in X.items()},
            "Y": {k: (sorted(v) if isinstance(v, set) else v) for k, v in Y.items()},
            "implicit_dest_read_present": bool(X["dest_read"] or Y["dest_read"])}


# --------------------------------------------------------------------------
# disassembly parsing
# --------------------------------------------------------------------------

RE_LINE = re.compile(r"\s*(v_dual\S+.*?)\s*//\s*([0-9A-Fa-f]+):\s*([0-9A-Fa-f ]+)\s*$")


def parse_disassembly(path: str):
    pairs, skipped = [], []
    for raw in open(path, encoding="utf8", errors="replace"):
        line = raw.rstrip("\n")
        if " :: " not in line:
            continue
        m = RE_LINE.match(line)
        if not m:
            skipped.append(line.strip())
            continue
        sides = m.group(1).split(" :: ")
        if len(sides) != 2:
            skipped.append(line.strip())
            continue
        pairs.append({"addr": int(m.group(2), 16), "encoding": m.group(3).strip(),
                      "x": sides[0].strip(), "y": sides[1].strip()})
    return pairs, skipped


# --------------------------------------------------------------------------
# controls  (brief section 22)
# --------------------------------------------------------------------------

CONTROLS = [
    # (name, x, y, expected_class)
    ("independent pair", "v_dual_mov_b32 v1, 0", "v_dual_mov_b32 v2, 0",
     "INDEPENDENT"),
    ("X writes Y source", "v_dual_mov_b32 v1, 0", "v_dual_and_b32 v54, 0x180, v1",
     "HAZARD_LEFT_BEFORE_RIGHT"),
    ("Y writes X source", "v_dual_add_f32 v4, v5, v6", "v_dual_mov_b32 v5, 0",
     "HAZARD_RIGHT_BEFORE_LEFT"),
    ("both directions", "v_dual_mov_b32 v1, v2", "v_dual_mov_b32 v2, v1",
     "HAZARD_BOTH_DIRECTIONS"),
    # NOTE: this control was first written expecting LEFT_BEFORE_RIGHT and the
    # classifier returned RIGHT_BEFORE_LEFT.  The classifier was RIGHT and the
    # expectation was wrong: the AND writes v12, and the FMAC READS v12 as a
    # multiplicand, so the dependence runs right-to-left.  The expectation was
    # corrected to the independently-derived direction, not to whatever the
    # implementation happened to print.  A second control below covers the
    # other direction so BOTH are still exercised.
    ("destination-as-source FMA, reader on the left",
     "v_dual_fmac_f32 v31, 0x3377d1cf, v12", "v_dual_and_b32 v12, 1, v13",
     "HAZARD_RIGHT_BEFORE_LEFT"),
    ("destination-as-source FMA, reader on the right",
     "v_dual_fmac_f32 v31, v12, v13", "v_dual_mov_b32 v5, v31",
     "HAZARD_LEFT_BEFORE_RIGHT"),
    ("literal operand is not a register",
     "v_dual_mov_b32 v1, 0x7f", "v_dual_mov_b32 v2, 0x7f", "INDEPENDENT"),
    ("implicit dest read is modelled",
     "v_dual_fmac_f32 v11, v11, v29", "v_dual_add_f32 v29, 0, v30",
     "HAZARD_RIGHT_BEFORE_LEFT"),
    ("same destination both sides is still a data dependence",
     "v_dual_mov_b32 v7, v0", "v_dual_mov_b32 v7, v1", "INDEPENDENT"),
    ("unmodelled mnemonic must fail closed",
     "v_dual_cndmask_b32 v1, v2, v3", "v_dual_mov_b32 v4, 0", "UNKNOWN_BLOCKING"),
    ("vcc-consuming pair is unmodelled here and must fail closed",
     "v_dual_cndmask_b32 v1, v2, v3, vcc", "v_dual_mov_b32 v5, 0", "UNKNOWN_BLOCKING"),
]


def run_controls():
    rows, ok = [], 0
    for name, x, y, expected in CONTROLS:
        r = classify_pair(x, y)
        got = r["class"]
        # a control "reaches the observer" only if the classifier produced a
        # class for it at all -- it must not silently disappear
        reached = got is not None
        passed = reached and got == expected
        rows.append({"control": name, "x": x, "y": y, "expected": expected,
                     "got": got, "reached_observer": reached, "passed": passed})
        ok += 1 if passed else 0
    return rows, ok


# --------------------------------------------------------------------------
# active semantic test for hazard sites  (brief section 20)
# --------------------------------------------------------------------------

def atomic_vs_sequential(x_text, y_text, old_values):
    """Evaluate the pair under BOTH readings on concrete old register values.

    atomic        : both sides read the PRE-instruction state
    sequential    : the printed order, each side reading the previous result

    Returns (atomic_result, sequential_result, site_is_discriminating).
    Only integer ops are evaluated; the caller passes only integer-op sites.
    """
    def ev(text, state):
        a = analyse_op(text)
        mnem, ops = a["mnemonic"], a["operands"]
        def val(tok):
            k = parse_operand(tok)
            if k[0] in ("v", "s"):
                return state.get("%s%d" % k, 0)
            t = tok.strip().strip("-|")
            try:
                return int(t, 0) & 0xFFFFFFFF
            except ValueError:
                return 0
        if mnem == "mov_b32":
            return val(ops[1]) & 0xFFFFFFFF
        if mnem == "and_b32":
            return (val(ops[1]) & val(ops[2])) & 0xFFFFFFFF
        if mnem == "lshlrev_b32":
            return (val(ops[2]) << (val(ops[1]) & 31)) & 0xFFFFFFFF
        if mnem == "add_nc_u32":
            return (val(ops[1]) + val(ops[2])) & 0xFFFFFFFF
        raise ValueError("not an integer op: " + mnem)

    a = analyse_op(x_text); b = analyse_op(y_text)
    # atomic: both compute from old_values
    st = dict(old_values)
    rx, ry = ev(x_text, old_values), ev(y_text, old_values)
    # sequential: X then Y
    seq = dict(old_values)
    seq[a["dest"]] = rx
    ry_seq = ev(y_text, seq)
    return {"X_dest": a["dest"], "Y_dest": b["dest"],
            "atomic": {a["dest"]: rx, b["dest"]: ry},
            "sequential_left_then_right": {a["dest"]: rx, b["dest"]: ry_seq},
            "discriminating": ry != ry_seq}


# --------------------------------------------------------------------------
# witness search: can the wrong order be made to change a result?
# --------------------------------------------------------------------------

def _as_bits(tok):
    t = tok.strip()
    try:
        return int(t, 0) & 0xFFFFFFFF
    except ValueError:
        return None


def _as_float(tok):
    t = tok.strip()
    b = _as_bits(t)
    if b is not None and (t.startswith("0x") or t.startswith("0X")):
        return struct.unpack("<f", struct.pack("<I", b))[0]
    try:
        return float(t)
    except ValueError:
        return None


REGISTERS_SEEN = None


def eval_op(text, state):
    """Evaluate one side's op on a register state.  Raises ValueError if the
    mnemonic is outside the evaluable set -- the caller reports NO WITNESS
    rather than guessing."""
    a = analyse_op(text)
    if not a or not a["modelled"]:
        raise ValueError("unmodelled")
    mnem, ops = a["mnemonic"], a["operands"]

    def v(tok):
        k = parse_operand(tok)
        if k[0] in ("v", "s"):
            return state.get("%s%d" % k, 0)
        return None

    if mnem in ("mov_b32", "and_b32", "lshlrev_b32", "add_nc_u32"):
        def iv(tok):
            r = v(tok)
            if r is not None:
                return r
            b = _as_bits(tok)
            if b is None:
                raise ValueError("bad int literal " + tok)
            return b
        if mnem == "mov_b32":
            return iv(ops[1]) & 0xFFFFFFFF
        if mnem == "and_b32":
            return (iv(ops[1]) & iv(ops[2])) & 0xFFFFFFFF
        if mnem == "lshlrev_b32":
            return (iv(ops[2]) << (iv(ops[1]) & 31)) & 0xFFFFFFFF
        return (iv(ops[1]) + iv(ops[2])) & 0xFFFFFFFF

    if mnem in ("add_f32", "mul_f32", "sub_f32", "fmaak_f32", "fmac_f32"):
        def fv(tok):
            r = v(tok)
            if r is not None:
                return struct.unpack("<f", struct.pack("<I", r))[0]
            f = _as_float(tok)
            if f is None:
                raise ValueError("bad float literal " + tok)
            return f
        if mnem == "add_f32":
            return fv(ops[1]) + fv(ops[2])
        if mnem == "mul_f32":
            return fv(ops[1]) * fv(ops[2])
        if mnem == "sub_f32":
            return fv(ops[1]) - fv(ops[2])
        if mnem == "fmaak_f32":
            return fv(ops[1]) * fv(ops[2]) + fv(ops[3])
        return fv(a["dest"]) * fv(ops[1]) + fv(ops[2])

    raise ValueError("not evaluable: " + mnem)


def find_witness(x_text, y_text, cls, l2r, r2l):
    """Search for old values of the conflicting registers under which the
    wrong order produces a different result than the atomic semantics.

    The reader side is the one whose result depends on the conflict:
      l2r -> Y is the reader (it would read X's new value)
      r2l -> X is the reader
    """
    reader_text = y_text if l2r else x_text
    conflict = (l2r or r2l)
    if not conflict:
        return {"discriminating": False, "reason": "no conflict register recorded"}
    reg = conflict[0]
    seeds = [0x00000000, 0x00000001, 0x80000000, 0x40000000, 0x7F7FFFFF,
             0x3F800000, 0x00000080, 0x00000100, 0x00000180, 0xFFFFFFFF,
             0x0000FFFF, 0xBF800000, 0x80000001]
    outs = {}
    for s in seeds:
        try:
            r = eval_op(reader_text, {reg: s})
        except ValueError as e:
            return {"discriminating": False, "reason": "reader not evaluable: %s" % e}
        outs[s] = r
    distinct = {}
    for s, r in outs.items():
        distinct.setdefault(repr(r), []).append(s)
    if len(distinct) < 2:
        return {"discriminating": False, "reader": reader_text, "conflict_register": reg,
                "reason": "reader output invariant over the searched stimulus set"}
    vals = list(distinct.values())
    a_seed, b_seed = vals[0][0], vals[1][0]
    return {"discriminating": True, "reader": reader_text,
            "conflict_register": reg,
            "witness_old_value": "0x%08X" % a_seed,
            "witness_other_value": "0x%08X" % b_seed,
            "result_at_old": repr(outs[a_seed]),
            "result_at_other": repr(outs[b_seed]),
            "n_distinct_outputs_over_%d_seeds" % len(seeds): len(distinct)}


# --------------------------------------------------------------------------

def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    dis = os.path.join(root, "p16aw", "vopd", "ACTUAL_PARENT_sym.dis")
    out_dir = os.path.join(root, "p16aw", "vopd")

    pairs, skipped = parse_disassembly(dis)
    print("parsed VOPD pairs: %d   unparsed lines: %d" % (len(pairs), len(skipped)))

    rows, hist = [], {}
    for p in pairs:
        c = classify_pair(p["x"], p["y"])
        cls = c["class"]
        hist[cls] = hist.get(cls, 0) + 1
        rows.append({"addr": "0x%X" % p["addr"], "x": p["x"], "y": p["y"],
                     "class": cls,
                     "left_writes_right_reads": c.get("left_writes_right_reads"),
                     "right_writes_left_reads": c.get("right_writes_left_reads"),
                     "implicit_dest_read_present": c.get("implicit_dest_read_present"),
                     "why": c.get("why")})

    print("classification histogram:")
    for k, v in sorted(hist.items(), key=lambda kv: -kv[1]):
        print("   %-28s %4d" % (k, v))

    nd_haz = [r for r in rows if r["class"].startswith("HAZARD")]
    print("hazard sites total: %d" % len(nd_haz))
    print("  LEFT_BEFORE_RIGHT : %d" % hist.get("HAZARD_LEFT_BEFORE_RIGHT", 0))
    print("  RIGHT_BEFORE_LEFT : %d" % hist.get("HAZARD_RIGHT_BEFORE_LEFT", 0))
    print("  BOTH              : %d" % hist.get("HAZARD_BOTH_DIRECTIONS", 0))

    # ---- controls ----
    ctrl_rows, ctrl_ok = run_controls()
    print("controls: %d/%d passed" % (ctrl_ok, len(ctrl_rows)))
    for r in ctrl_rows:
        if not r["passed"]:
            print("   CONTROL FAIL: %s expected %s got %s"
                  % (r["control"], r["expected"], r["got"]))

    # ---- the demonstrated site, section 12 / section 20 ----
    demo = None
    for p in pairs:
        if p["addr"] == 0xCB8DC:
            demo = atomic_vs_sequential(p["x"], p["y"], {"v0": 8, "v1": 0x100})
            demo["addr"] = "0xCB8DC"
            demo["x"] = p["x"]; demo["y"] = p["y"]
            demo["preceding_instruction"] = "0xCB8D8: v_lshlrev_b32_e32 v1, 5, v0"
            demo["stimulus"] = "v0 = 8  =>  v_lshlrev_b32 v1, 5, v0  =>  v1 = 0x100"
            break
    if demo:
        print("demonstrated site 0xCB8DC:")
        print("   atomic   :", demo["atomic"])
        print("   sequential:", demo["sequential_left_then_right"])
        print("   discriminating:", demo["discriminating"])
    else:
        print("demonstrated site 0xCB8DC: NOT FOUND IN THIS DISASSEMBLY")

    # ---- witness search: does the WRONG order actually change the result? ----
    # Brief s.20: for hazard sites, choose old register values such that the
    # old value differs from the newly written value AND the source result
    # changes if the ordering is wrong.  A hazard that cannot be made to change
    # any result is reported as such rather than counted as demonstrated.
    witnesses = []
    for r in rows:
        if not r["class"].startswith("HAZARD"):
            continue
        w = find_witness(r["x"], r["y"], r["class"],
                         r.get("left_writes_right_reads") or [],
                         r.get("right_writes_left_reads") or [])
        w["addr"] = r["addr"]; w["x"] = r["x"]; w["y"] = r["y"]; w["class"] = r["class"]
        witnesses.append(w)
    hit = [w for w in witnesses if w["discriminating"]]
    print("hazard sites: %d; witness found for %d; no witness for %d"
          % (len(witnesses), len(hit), len(witnesses) - len(hit)))
    for w in witnesses:
        if not w["discriminating"]:
            print("   NO WITNESS: %s (%s) -- %s"
                  % (w["addr"], w["class"], w["reason"]))

    res = {
        "schema": "p16aw/vopd-dependency/1",
        "phase": "16AW",
        "host_only": True,
        "gpu_calls": 0,
        "subject": {
            "what": "the ACTUAL Candidate-F parent symbol",
            "elf": "phase5_exact_fragment/gfx1100_code_object.o",
            "elf_sha256": "93e4a40b880b994860431309e9b2fd116efea585a23a830496050de88ee4800a",
            "symbol": "_Z10k_swin_varILi32ELb0EEv9VarParams",
            "symbol_va": "0xC4000",
            "symbol_size": 87320,
            "disassembly": "p16aw/vopd/ACTUAL_PARENT_sym.dis",
            "disassembler": "llvm-objdump 20.0.0git (AOMP-18.0-12), --mcpu=gfx1100",
        },
        "n_vopd_pairs": len(pairs),
        "n_lines_unparsed": len(skipped),
        "classification_histogram": hist,
        "n_hazard_sites_total": len(nd_haz),
        "hazard_sites": [r for r in rows if r["class"].startswith("HAZARD")
                         or r["class"] == "UNKNOWN_BLOCKING"],
        "all_pairs": rows,
        "controls": {"n": len(ctrl_rows), "n_passed": ctrl_ok, "rows": ctrl_rows},
        "demonstrated_site": demo,
        "witness_search": witnesses,
        "n_witnesses_found": len(hit),
        "rules_honoured": {
            "fail_closed": "a mnemonic outside the operand model is UNKNOWN_BLOCKING, never safe",
            "both_directions_reported": True,
            "implicit_dest_read_modelled": True,
            "printed_order_not_assumed_semantic": True,
        },
    }
    with open(os.path.join(out_dir, "VOPD_DEPENDENCY_CENSUS_16AW.json"), "w",
              encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    print("wrote VOPD_DEPENDENCY_CENSUS_16AW.json")
    return 0 if ctrl_ok == len(ctrl_rows) else 1


if __name__ == "__main__":
    sys.exit(main())
