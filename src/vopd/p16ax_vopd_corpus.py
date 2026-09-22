#!/usr/bin/env python3
"""Phase 16AX T-VOPD -- STEP 6: the semantic test corpus.

WHAT IS COMPARED
  reference A : the ATOMIC pair semantics -- both sides evaluated from the
                PRE-instruction register state, as a pair-level formula.
  subject     : the LOWERED instruction stream -- the emitted text executed
                step by step by a linear interpreter.

  These are two different mechanisms for the same question.  The pair formula
  never builds a sequence; the subject never sees the pair.  The thing under
  test is the ORDER, so the two share only the per-mnemonic value semantics,
  which is common ground rather than a hidden dependency.  Two further checks
  are added precisely because a shared evaluator would otherwise make the
  comparison self-confirming:

  reference B : hand-derived closed-form constants for the demonstrated site
                (v0 = 8 -> v1 = 0x100 -> v54 = 0x180 & 0x100 = 0x100), written
                into the corpus as LITERALS and never computed by an evaluator.
  reference C : the emitted text re-parsed with the 16AW operand model, to
                confirm the operand list and every modifier survived lowering.

A CORPUS THAT CANNOT FAIL IS NOT EVIDENCE
  The same corpus is run against THREE lowerings:
    - `correct`      : p16ax_vopd_lower.lower_pair
    - `naive`        : the printed-order sequentialisation, i.e. the defect
    - `candidate_f`  : the REAL wrong emission, extracted from the actual
                       Candidate F object's disassembly where it can be matched
  The corpus must ACCEPT `correct` on every site and REJECT `naive` on every
  left-before-right site.  If it accepted `naive` too, it would be vacuous.

WHAT THIS DOES NOT ESTABLISH
  It is a static/symbolic comparison on chosen old-register values.  It is not
  an execution of any kind, on any processor, and it says nothing about whether
  the surrounding translator is otherwise correct.
"""

from __future__ import annotations

import json
import math
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

import p16ax_vopd_model as M  # noqa: E402
import p16ax_vopd_lower as L  # noqa: E402

V = M.V

MASK32 = 0xFFFFFFFF


# --------------------------------------------------------------------------
# float helpers -- every operation is rounded back to binary32
# --------------------------------------------------------------------------

def f32(x):
    """Round to binary32.  Overflow saturates to a signed infinity rather than
    raising: an f32 add of two large f32 values produces inf, not an exception,
    and an exception here would have read as "site not applicable"."""
    try:
        return struct.unpack("<f", struct.pack("<f", x))[0]
    except OverflowError:
        return math.inf if x > 0 else -math.inf


def bits_to_f32(b):
    return struct.unpack("<f", struct.pack("<I", b & MASK32))[0]


def f32_to_bits(x):
    try:
        return struct.unpack("<I", struct.pack("<f", x))[0]
    except (OverflowError, ValueError):
        return 0x7F800000 if x > 0 else 0xFF800000


def _fma(a, b, c):
    """One rounding for a*b+c.

    math.fma RAISES ValueError on an invalid operation (inf*0, or inf + -inf),
    where the hardware produces a quiet NaN.  An uncaught raise here would have
    been reported as "site not applicable" -- a silent pass.  It is caught and
    mapped to NaN so the comparison still happens.
    """
    try:
        return f32(math.fma(a, b, c))
    except ValueError:
        return math.nan
    except AttributeError:                       # pragma: no cover
        from fractions import Fraction
        fa, fb, fc = Fraction(a), Fraction(b), Fraction(c)
        return f32(float(fa * fb + fc))


def _int_literal(bare):
    """An integer operand's value.

    The disassembler prints inline float constants in an INTEGER op with their
    float spelling (`v_mov_b32 v0, 1.0`); on gfx11 that is the inline constant
    whose bits are 0x3F800000.  A first draft called int() on it and raised, and
    the site read as "not applicable".
    """
    try:
        return int(bare, 0) & MASK32
    except ValueError:
        return struct.unpack("<I", struct.pack("<f", float(bare)))[0]


def _fmax(a, b):
    if math.isnan(a):
        return b
    if math.isnan(b):
        return a
    return a if a > b else b


def _fmin(a, b):
    if math.isnan(a):
        return b
    if math.isnan(b):
        return a
    return a if a < b else b


# --------------------------------------------------------------------------
# THE per-mnemonic value semantics (shared ground, deliberately one place)
# --------------------------------------------------------------------------

def _resolve(tok, state, float_op):
    """Register -> value, or a literal parsed in this mnemonic's domain.

    Source modifiers are applied to REGISTERS as well as to literals.  A first
    draft stripped `-`/`|` for the register lookup and then forgot to apply
    them, which would have silently modelled `-v1` as `v1`.  The measured fact
    that no v_dual side in this object carries such a modifier is why the
    corpus still passed -- which is exactly the kind of latent hole that only
    shows up later, so it is closed here rather than relied on.
    """
    t = tok.strip()
    body = t.split()[0]
    if "neg(" in body or "abs(" in body:
        raise ValueError("functional modifier form not modelled: %r" % tok)
    neg = body.startswith("-") or body.startswith("-|")
    ab = body.startswith("|") or body.startswith("-|") or body.endswith("|")
    k = V.parse_operand(body)
    if k[0] in ("v", "s"):
        key = "%s%d" % k
        if key not in state:
            raise KeyError("register %s has no value in the corpus stimulus" % key)
        v = state[key]
        if not float_op:
            v &= MASK32
            if ab:
                v &= 0x7FFFFFFF
            return (-v) & MASK32 if neg else v
        v = bits_to_f32(v) if not float_op else bits_to_f32(v)
        if ab:
            v = abs(v)
        return -v if neg else v
    bare = body.lstrip("-").strip("|")
    if float_op:
        if bare.startswith("0x") or bare.startswith("0X"):
            v = bits_to_f32(int(bare, 16))
        else:
            v = float(bare)
        if ab:
            v = abs(v)
        return -v if neg else v
    v = _int_literal(bare)
    if ab:
        v &= 0x7FFFFFFF
    return (-v) & MASK32 if neg else v


def eval_mnemonic(mnem, operands, dest, state, vcc_bit):
    """Value semantics of one side.  Raises ValueError if not modelled.

    `operands` is the operand list as the 16AW model parses it, i.e. index 0 is
    the DESTINATION and 1.. are sources (OPERAND_SHAPE is "D,S[,S[,S]]").  A
    first draft of this function read source i from operands[i] and therefore
    read the destination as a source; the hand-derived 0xCB8DC control in
    run_corpus() is what caught it.
    """
    float_op = mnem.endswith("_f32") or mnem.endswith("_f16")
    o = operands

    def R(i):
        return _resolve(o[i + 1], state, float_op)

    if mnem == "mov_b32":
        return R(0) & MASK32
    if mnem == "and_b32":
        return (R(0) & R(1)) & MASK32
    if mnem == "lshlrev_b32":
        return (R(1) << (R(0) & 31)) & MASK32
    if mnem == "add_nc_u32":
        return (R(0) + R(1)) & MASK32
    if mnem == "cndmask_b32":                      # reads VCC implicitly
        return (R(0) if vcc_bit else R(1)) & MASK32
    if mnem == "add_f32":
        return f32_to_bits(f32(R(0) + R(1)))
    if mnem == "sub_f32":
        return f32_to_bits(f32(R(0) - R(1)))
    if mnem == "mul_f32":
        return f32_to_bits(f32(R(0) * R(1)))
    if mnem == "max_f32":
        return f32_to_bits(_fmax(R(0), R(1)))
    if mnem == "min_f32":
        return f32_to_bits(_fmin(R(0), R(1)))
    if mnem == "fmaak_f32":
        return f32_to_bits(_fma(R(0), R(1), R(2)))
    if mnem == "fmamk_f32":
        return f32_to_bits(_fma(R(0), R(1), R(2)))
    if mnem == "fmac_f32":                         # dst = dst * src0 + src1
        if dest is None:
            raise ValueError("fmac needs a destination")
        return f32_to_bits(_fma(state[dest], R(0), R(1)))
    raise ValueError("no value semantics modelled for %r" % mnem)


# --------------------------------------------------------------------------
# reference A -- the ATOMIC pair semantics
# --------------------------------------------------------------------------

def atomic_pair(x_text, y_text, pre, vcc_bit=0):
    """Both sides from the PRE-instruction state.  Never builds a sequence."""
    out = {}
    for t in (x_text, y_text):
        a = M.analyse_ext(t)
        if not a or not a["modelled"]:
            raise ValueError("unmodelled side")
        out[a["dest"]] = eval_mnemonic(a["mnemonic"], a["operands"], a["dest"],
                                       pre, vcc_bit)
    return out


# --------------------------------------------------------------------------
# the subject -- a linear interpreter over the LOWERED text
# --------------------------------------------------------------------------

def run_stream(texts, pre, vcc_bit=0):
    """Execute the emitted instruction texts in order, one state update each."""
    state = dict(pre)
    for t in texts:
        mn, _ = M.split_side(t)
        a = M.analyse_ext(t)
        if not a or not a["modelled"]:
            raise ValueError("emitted instruction not modelled: %r" % t)
        state[a["dest"]] = eval_mnemonic(a["mnemonic"], a["operands"], a["dest"],
                                        state, vcc_bit)
    return state


# --------------------------------------------------------------------------
# stimulus
# --------------------------------------------------------------------------

#: deliberately adversarial old-register values.  Includes the boundary cases
#: where a wrong order is invisible (all-zeros, all-ones) precisely so the
#: corpus cannot pass by only ever probing those.
ADVERSARIAL_INTS = [
    0x00000000, 0x00000001, 0x00000002, 0x0000007F, 0x00000080, 0x00000100,
    0x00000180, 0x0000FFFF, 0x00010000, 0x3FFFFFFF, 0x40000000, 0x7FFFFFFF,
    0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF, 0x55555555, 0xAAAAAAAA,
    0x000000FF, 0x000001FF, 0x1FFFFFFF, 0x000003FF,
]
ADVERSARIAL_FLOATS = [
    0x00000000, 0x80000000, 0x3F800000, 0xBF800000, 0x40000000, 0xC0000000,
    0x3F000000, 0xBF000000, 0x00000001, 0x007FFFFF, 0x00800000, 0x7F7FFFFF,
    0x7F800000, 0xFF800000, 0x7FC00000, 0x40490FDB, 0x3E800000, 0x4B000000,
]


def stimulus_values(mnem):
    return ADVERSARIAL_FLOATS if mnem.endswith("_f32") else ADVERSARIAL_INTS


def build_stimuli(rec, max_per_conflict_reg=24):
    """Deterministic adversarial pre-states for one site.

    Every register the pair reads or writes is driven across the adversarial
    set, jointly where a conflict exists, so a wrong order has a chance to show
    and a right order has a chance to be distinguished from it.
    """
    X = M.analyse_ext(rec["x"])
    Y = M.analyse_ext(rec["y"])
    regs = sorted((set(X["reads"]) | set(X["writes"]) |
                   set(Y["reads"]) | set(Y["writes"])))
    conflicts = sorted(set(rec["left_writes_right_reads"] or []) |
                       set(rec["right_writes_left_reads"] or []))
    vals = stimulus_values(X["mnemonic"]) + stimulus_values(Y["mnemonic"])
    vals = list(dict.fromkeys(vals))[:max_per_conflict_reg]

    stim = []
    # (a) each conflict register swept, everything else neutral
    for c in conflicts or regs:
        for v in vals:
            pre = {r: 0 for r in regs}
            pre[c] = v
            stim.append(pre)
    # (b) joint corners: all conflict registers take the same adversarial value
    for v in vals:
        stim.append({r: v for r in regs})
    # (c) the stimulated case from the brief, when the site has one register
    stim.append({r: (0x100 if r in conflicts else 0) for r in regs})
    # dedupe, keep order
    seen, uniq = set(), []
    for s in stim:
        k = tuple(sorted(s.items()))
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return regs, conflicts, uniq


# --------------------------------------------------------------------------
# the three lowerings under test
# --------------------------------------------------------------------------

def lowering_correct(x_text, y_text, rec):
    return list(rec["emitted"])


def lowering_naive(x_text, y_text, rec):
    """The defect: printed order, both sides sequentialised."""
    return [M.emit_one(x_text), M.emit_one(y_text)]


def lowerings_for_role(role, x_text, y_text, rec, temp_pool=None):
    if role == "correct":
        return lowering_correct(x_text, y_text, rec)
    if role == "naive":
        return lowering_naive(x_text, y_text, rec)
    raise ValueError(role)


# --------------------------------------------------------------------------
# the corpus over one site
# --------------------------------------------------------------------------

def run_site(rec, temp_pool=None):
    """Compare atomic vs lowered across the adversarial stimulus set."""
    x_text, y_text = rec["x"], rec["y"]
    regs, conflicts, stim = build_stimuli(rec)

    row = {"addr": rec["addr"], "class": rec["class"], "x": x_text, "y": y_text,
           "conflict_registers": conflicts, "n_stimuli": len(stim),
           "results": {}}

    for role in ("correct", "naive"):
        if role == "correct" and rec["class"] not in L.SUPPORTED:
            row["results"][role] = {"applicable": False,
                                    "why": "lowering is %s" % rec["class"]}
            continue
        seq = lowerings_for_role(role, x_text, y_text, rec, temp_pool)
        disagree, first = 0, None
        for pre in stim:
            try:
                ref = atomic_pair(x_text, y_text, pre)
                got = run_stream(seq, pre)
            except (KeyError, ValueError) as e:
                row["results"][role] = {"applicable": False, "error": str(e)}
                break
            bad = {k: {"atomic": ref[k], "lowered": got.get(k)} for k in ref
                   if got.get(k) != ref[k]}
            if bad:
                disagree += 1
                if first is None:
                    first = {"pre": {k: "0x%08X" % v for k, v in sorted(pre.items())},
                             "mismatch": {k: {"atomic": "0x%08X" % v["atomic"],
                                              "lowered": ("0x%08X" % v["lowered"])
                                              if v["lowered"] is not None else None}
                                          for k, v in bad.items()}}
        else:
            row["results"][role] = {
                "applicable": True, "sequence": seq,
                "n_disagree": disagree, "n_agree": len(stim) - disagree,
                "first_disagreement": first,
                "accepted": disagree == 0,
            }
    return row


# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# reference C -- textual preservation, and the REAL wrong emission
# --------------------------------------------------------------------------

def preservation_check(rec):
    """The emitted text must carry the same operand list and the same modifiers
    as the side it came from, and must name the same destination."""
    out = []
    for tag in ("X", "Y"):
        src = rec[tag.lower()]
        a = M.analyse_ext(src)
        # find the emitted instruction that writes this side's destination
        match = None
        for e in rec["emitted"] or []:
            b = M.analyse_ext(e)
            if b and b["dest"] == a["dest"]:
                match = (e, b)
                break
        if match is None:
            out.append({"side": tag, "preserved": False,
                        "why": "no emitted instruction writes %s" % a["dest"]})
            continue
        e, b = match
        ok = (b["mnemonic"] == a["mnemonic"]
              and [o.strip() for o in b["operands"]] == [o.strip() for o in a["operands"]]
              and b["reads"] == a["reads"]
              and b["dest"] == a["dest"])
        out.append({
            "side": tag, "source": src, "emitted": e, "preserved": ok,
            "source_mnemonic": a["mnemonic"], "emitted_mnemonic": b["mnemonic"],
            "operand_list_identical": ([o.strip() for o in b["operands"]]
                                       == [o.strip() for o in a["operands"]]),
            "reads_identical": b["reads"] == a["reads"],
            "dest_identical": b["dest"] == a["dest"],
            "modifiers_source": L.modifier_inventory(src),
            "modifiers_emitted": L.modifier_inventory(e),
        })
    return out


def load_candidate_f_stream():
    """Every instruction of the ACTUAL Candidate F object, address-ordered.

    The instruction text may contain spaces, so the pattern is anchored on the
    `// <addr>: <encoding>` trailer rather than on a single leading token.  A
    first draft used `\\S+` for the text and matched 443 of ~250k lines, which
    silently made every search "not found" -- a broken instrument reading as a
    negative result.
    """
    import re
    pat = re.compile(r"^(.*?)\s*//\s*([0-9A-Fa-f]+):\s*([0-9A-Fa-f ]+)\s*$")
    stream = []
    for raw in open(M.CF_FULL_DIS, encoding="utf8", errors="replace"):
        m = pat.match(raw.rstrip("\n"))
        if not m:
            continue
        text = m.group(1).strip()
        if not text:
            continue
        stream.append({"addr": int(m.group(2), 16), "text": text})
    return stream


def find_real_candidate_emission(stream, naive_seq):
    """Locate the naive lowering in the REAL Candidate F stream.

    A translator lowers a VOPD into two instructions; if it emitted them in
    printed order, those two texts appear CONSECUTIVELY here.  Matching is on
    the full instruction text, so a register re-allocation by the translator
    simply fails to match -- reported as unmatched rather than guessed at.
    """
    want = [t.strip() for t in naive_seq]
    for i in range(len(stream) - len(want) + 1):
        if [stream[i + j]["text"] for j in range(len(want))] == want:
            return {"matched": True,
                    "addr": "0x%X" % stream[i]["addr"],
                    "texts": want,
                    "index": i}
    return {"matched": False, "want": want}


# --------------------------------------------------------------------------

def run_corpus():
    M.ensure_extended()
    pairs, _ = V.parse_disassembly(M.AW_FULL_DIS)
    cf_stream = load_candidate_f_stream()

    per_site, checks = [], []

    def ctl(cid, what, ok, detail):
        checks.append({"id": cid, "what": what, "ok": bool(ok), "detail": detail})
        print("[%s] %-5s %s" % ("PASS" if ok else "FAIL", cid, what))
        if not ok:
            print("        %s" % (detail,))

    # ---- reference B: hand-derived constants, never computed by an evaluator
    HD = {
        "addr": "0xCB8DC",
        "x": "v_dual_mov_b32 v1, 0",
        "y": "v_dual_and_b32 v54, 0x180, v1",
        "preceding": "v_lshlrev_b32_e32 v1, 5, v0",
        "stimulus": "v0 = 8",
        "derivation": "v1_old = 8 << 5 = 0x100;  mov writes v1 := 0;  "
                      "and computes 0x180 & v1_old = 0x180 & 0x100 = 0x100",
        "expected_atomic": {"v1": 0x00000000, "v54": 0x00000100},
        "expected_emitted_correct": {"v1": 0x00000000, "v54": 0x00000100},
        "expected_naive_printed_order": {"v1": 0x00000000, "v54": 0x00000000},
    }

    # ---- the demonstrated site, end to end
    rec_demo = L.lower_pair(HD["x"], HD["y"], addr=HD["addr"])
    pre = {"v0": 8, "v1": 0x100, "v54": 0x00000000}
    got_atomic = atomic_pair(HD["x"], HD["y"], pre)
    got_correct = run_stream(rec_demo["emitted"], pre)
    got_naive = run_stream(lowering_naive(HD["x"], HD["y"], rec_demo), pre)

    def project(state, keys):
        """Compare only the pair's OWN destinations: the stream carries the rest
        of the register file along, which is not what is under test."""
        return {k: state[k] for k in keys}

    dests = sorted(HD["expected_atomic"])
    ctl("C1.1", "hand-derived atomic semantics: v1 = 0, v54 = 0x100",
        project(got_atomic, dests) == HD["expected_atomic"],
        "got %s" % project(got_atomic, dests))
    ctl("C1.2", "hand-derived lowered semantics: v1 = 0, v54 = 0x100",
        project(got_correct, dests) == HD["expected_emitted_correct"],
        "got %s" % project(got_correct, dests))
    ctl("C1.3", "printed-order sequentialisation yields v54 = 0 (the defect)",
        project(got_naive, dests) == HD["expected_naive_printed_order"],
        "got %s" % project(got_naive, dests))
    ctl("C1.4", "the lowered result equals the atomic result",
        project(got_correct, dests) == project(got_atomic, dests),
        "lowered=%s atomic=%s" % (project(got_correct, dests), project(got_atomic, dests)))
    ctl("C1.5", "the naive result DIFFERS from the atomic result "
                "(the corpus can fail)",
        project(got_naive, dests) != project(got_atomic, dests),
        "both gave %s" % project(got_naive, dests))

    # ---- the REAL Candidate F emission for that site
    real = find_real_candidate_emission(cf_stream,
                                        lowering_naive(HD["x"], HD["y"], rec_demo))
    ctl("C1.6", "the naive lowering is present VERBATIM in the actual "
                "Candidate F object",
        real["matched"], "not found: %s" % (real.get("want"),))
    if real["matched"]:
        got_real = run_stream(real["texts"], pre)
        ctl("C1.7", "the REAL Candidate F emission yields v54 = 0",
            project(got_real, dests) == HD["expected_naive_printed_order"],
            "got %s" % project(got_real, dests))
        ctl("C1.8", "the REAL Candidate F emission is rejected by the corpus",
            project(got_real, dests) != project(got_atomic, dests),
            "real=%s atomic=%s" % (project(got_real, dests), project(got_atomic, dests)))

    # ---- reference C on the demonstrated site
    pres = preservation_check(rec_demo)
    ctl("C2.1", "every operand of the demonstrated site survives lowering "
                "verbatim", all(p["preserved"] for p in pres), "%s" % (pres,))

    # ---- modifier round-trip control: synthetic, since the object has none
    MOD_CTRL = [
        ("v_dual_add_f32 v1, -v2, v3", "v_dual_mov_b32 v4, 0"),
        ("v_dual_add_f32 v1, |v2|, v3", "v_dual_mov_b32 v4, 0"),
        ("v_dual_add_f32 v1, -|v2|, v3", "v_dual_mov_b32 v4, 0"),
        ("v_dual_mov_b32 v1, 0x7f", "v_dual_and_b32 v2, 0x1c0, v1"),
        ("v_dual_add_f32 v1, -0.5, v2", "v_dual_add_f32 v3, -0.5, v4"),
    ]
    mod_ok = True
    mod_rows = []
    for x, y in MOD_CTRL:
        r = L.lower_pair(x, y, addr="<synthetic>")
        if r["class"] not in L.SUPPORTED:
            mod_ok = False
            mod_rows.append({"x": x, "y": y, "lowered": False, "why": r["class"]})
            continue
        p = preservation_check(r)
        ok = all(e["preserved"] for e in p) and \
            all(e["modifiers_source"] == e["modifiers_emitted"] for e in p)
        mod_ok = mod_ok and ok
        mod_rows.append({"x": x, "y": y, "lowered": True, "preserved": ok,
                         "emitted": r["emitted"], "evidence": p})
    ctl("C2.2", "modifier classes survive lowering verbatim (negation, absolute, "
                "literal, negative literal)", mod_ok,
        "a modifier class was dropped: %s" % [m for m in mod_rows if not m.get("preserved")])

    # ---- the whole object
    n_sites = n_supported = n_accept_correct = n_reject_naive = 0
    n_power_sites = n_power_insensitive = n_r2l_sites = 0
    l2r_total = l2r_rejected = 0
    real_matched = real_rejected = 0
    unsupported = {}
    per_site = []
    errors = []
    for p in pairs:
        rec = L.lower_pair(p["x"], p["y"],
                           addr="0x%X" % p["addr"],
                           temp_pool=["v250", "v251", "v252", "v253", "v254", "v255"])
        n_sites += 1
        if rec["class"] not in L.SUPPORTED:
            unsupported[rec["class"]] = unsupported.get(rec["class"], 0) + 1
            continue
        n_supported += 1
        try:
            row = run_site(rec)
        except Exception as e:                       # pragma: no cover
            errors.append({"addr": rec["addr"], "error": repr(e)})
            continue
        c = row["results"]["correct"]
        nv = row["results"]["naive"]
        c_ok = c.get("applicable") and c["accepted"]
        n_ok = nv.get("applicable") and not nv["accepted"]
        n_accept_correct += 1 if c_ok else 0
        # ordering power: the two slots must actually depend on each other for
        # the emitted ORDER to be observable.  SEQUENTIAL_INDEPENDENT means both
        # linear orders compute the same state -- accepting there is vacuous.
        if rec["class"] == L.SEQUENTIAL_INDEPENDENT:
            n_power_insensitive += 1
        else:
            n_power_sites += 1
            if rec["class"] == L.SEQUENTIAL_PUBLISHED_ORDER:
                n_r2l_sites += 1
        if rec["class"] == L.REORDERED_READER_FIRST:
            l2r_total += 1
            if n_ok:
                l2r_rejected += 1
        per_site.append({
            "addr": rec["addr"], "class": rec["class"], "x": rec["x"], "y": rec["y"],
            "emitted": rec["emitted"],
            "correct_accepted": bool(c_ok),
            "correct_n_agree": c.get("n_agree"), "correct_n_disagree": c.get("n_disagree"),
            "naive_rejected": bool(n_ok),
            "naive_n_disagree": nv.get("n_disagree"),
            "naive_first_disagreement": nv.get("first_disagreement"),
        })
        # the REAL Candidate F emission for the left-before-right sites: run the
        # SAME adversarial stimulus set against the text the actual translator
        # emitted.  Locating it is not enough -- it must be REJECTED.
        if rec["class"] == L.REORDERED_READER_FIRST:
            m = find_real_candidate_emission(
                cf_stream, lowering_naive(rec["x"], rec["y"], rec))
            if m["matched"]:
                real_matched += 1
                regs, _conf, stim = build_stimuli(rec)
                rdis, rfirst = 0, None
                for prep in stim:
                    ref = atomic_pair(rec["x"], rec["y"], prep)
                    gr = run_stream(m["texts"], prep)
                    bad = {k: {"atomic": ref[k], "real": gr.get(k)}
                           for k in ref if gr.get(k) != ref[k]}
                    if bad:
                        rdis += 1
                        if rfirst is None:
                            rfirst = {"pre": {k: "0x%08X" % v
                                              for k, v in sorted(prep.items())},
                                      "mismatch": {k: {"atomic": "0x%08X" % v["atomic"],
                                                       "real": "0x%08X" % v["real"]}
                                                   for k, v in bad.items()}}
                if rdis:
                    real_rejected += 1
                per_site[-1]["candidate_f_emission"] = {
                    "addr": m["addr"], "texts": m["texts"],
                    "n_disagree_with_atomic": rdis, "n_stimuli": len(stim),
                    "first_disagreement": rfirst,
                    "rejected": bool(rdis),
                    "reason": "the real translator emitted the printed order here",
                }

    ctl("C3.1", "all %d VOPD sites in the object are either supported or "
                "explicitly refused" % n_sites,
        n_supported + sum(unsupported.values()) == n_sites,
        "supported=%d unsupported=%s" % (n_supported, unsupported))
    ctl("C3.2", "the corpus ACCEPTS the corrected lowering at every supported "
                "site (%d)" % n_supported,
        n_accept_correct == n_supported,
        "accepted %d of %d" % (n_accept_correct, n_supported))
    ctl("C3.3", "the corpus REJECTS the printed-order lowering at every "
                "left-before-right site (%d)" % l2r_total,
        l2r_total > 0 and l2r_rejected == l2r_total,
        "rejected %d of %d" % (l2r_rejected, l2r_total))
    ctl("C3.4", "no site raised an evaluation error", not errors, "%s" % (errors[:3],))
    # The acceptance count is NOT the support for the ordering claim.  State
    # which sites the claim actually rests on, so a headline cannot be read as
    # "ordering verified at every site".
    ctl("C3.4b", "the ordering claim's true support is stated and partitions the "
                 "object: %d sites with ordering power, %d without"
        % (n_power_sites, n_power_insensitive),
        n_power_sites + n_power_insensitive == n_sites
        and n_power_sites == l2r_total + n_r2l_sites
        and n_power_sites > 0 and n_power_insensitive > 0,
        "power=%d insensitive=%d l2r=%d sum=%d/%d"
        % (n_power_sites, n_power_insensitive, l2r_total,
           n_power_sites + n_power_insensitive, n_sites))
    ctl("C3.5", "unsupported classes are named, never silently safe",
        all(k.startswith("UNSUPPORTED") for k in unsupported),
        "unexpected class: %s" % [k for k in unsupported if not k.startswith("UNSUPPORTED")])
    ctl("C3.6", "the REAL Candidate F emission was located VERBATIM for all "
                "%d left-before-right sites" % l2r_total,
        real_matched == l2r_total,
        "located %d of %d" % (real_matched, l2r_total))
    ctl("C3.7", "the REAL Candidate F emission is REJECTED by the corpus at "
                "every one of those sites",
        real_rejected == real_matched and real_matched == l2r_total,
        "rejected %d of %d located" % (real_rejected, real_matched))

    n_pass = sum(1 for c in checks if c["ok"])
    out = {
        "schema": "p16ax/vopd-semantic-corpus/1",
        "worker": "W1", "task_id": "T-VOPD", "phase": "16AX",
        "host_only": True, "gpu_calls": 0, "executions": 0,
        "method": (
            "reference A = atomic pair formula (no sequence is ever built); "
            "subject = a linear interpreter over the emitted text; "
            "reference B = hand-derived closed-form constants; "
            "reference C = operand/modifier preservation by re-parsing"),
        "hand_derived_control": HD,
        "demonstrated_site": {
            "lowered": rec_demo["emitted"], "class": rec_demo["class"],
            "atomic": {"v1": "0x%X" % got_atomic["v1"], "v54": "0x%X" % got_atomic["v54"]},
            "lowered_result": {"v1": "0x%X" % got_correct["v1"],
                               "v54": "0x%X" % got_correct["v54"]},
            "real_candidate_f_emission": real,
        },
        "totals": {
            "n_sites": n_sites, "n_supported": n_supported,
            "n_unsupported": unsupported,
            "n_correct_accepted": n_accept_correct,
            "n_sites_with_ordering_power": n_power_sites,
            "n_sites_whose_agreement_carries_no_information": n_power_insensitive,
            "n_left_before_right": l2r_total,
            "n_left_before_right_rejected_under_naive": l2r_rejected,
            "n_real_candidate_f_emissions_located": real_matched,
            "n_real_candidate_f_emissions_rejected": real_rejected,
        },
        "per_site": per_site,
        "checks": checks, "n_checks": len(checks), "n_passed": n_pass,
        "verdict": "CORPUS_DISCRIMINATES" if (n_pass == len(checks)) else "CORPUS_INVALID",
        "what_this_establishes": (
            "on adversarial pre-instruction register values, the corrected "
            "lowering reproduces the atomic pair semantics at every site, and the "
            "printed-order lowering -- including the REAL text the actual "
            "translator emitted -- is rejected wherever the two differ"),
        "how_far_that_claim_actually_reaches": {
            "n_sites_with_ordering_power": n_power_sites,
            "n_sites_whose_agreement_carries_no_information": n_power_insensitive,
            "read_this_before_quoting_a_headline": (
                "at %d of %d sites the two slots have no dependence on each "
                "other, so BOTH linear orders compute the same architectural "
                "state and the corpus accepting the corrected order there tells "
                "you nothing about ordering.  Ordering power exists only where "
                "one side reads a register the other writes: %d sites.  So the "
                "ordering result is supported at %d sites, NOT at %d."
                % (n_power_insensitive, n_sites, n_power_sites, n_power_sites,
                   n_sites)),
            "two_mechanisms_agree_on_the_bound": (
                "W12 derived the same set from the ENCODING (a read-after-write "
                "hazard between the slots, no value evaluated); %d comes from "
                "W1's operand model.  Two mechanisms, one partition -- WITH THE "
                "QUALIFIER: W12's side is encoding-derived and EXTERNAL to the "
                "lowering under test; W1's side shares the operand table with "
                "that lowering, so it is independent of W12 but NOT of the thing "
                "being judged.  It can corroborate W12; it cannot corroborate "
                "the lowering.  Recorded as an agreement between two mechanisms "
                "of unequal standing, not as two independent checks of the "
                "lowering." % n_power_sites),
            "and_the_pair_is_what_carries_it": (
                "W12's encoding-derived bound covers ORDER-SENSITIVITY only; it "
                "says nothing about operand identity or value.  That direction "
                "is covered by W12's control 2 (perturb one operand per site, "
                "caught 1509/1509, 1448 of them by state comparison), not by the "
                "bound.  Neither check is a single source of truth; the pair "
                "is."),
            "independent_judgement": (
                "p16ax/xref/XREF_JUDGES_VOPD_CORPUS_16AX.json -- verdict "
                "W1_CORPUS_UPHELD, 0 disagreements named by address, 1509/1509 "
                "sites joined, 0 decode disagreements with W1's own text, 0 sites "
                "where the emitted pair is not the same two operations, 97/97 "
                "ordering-power sites where the emitted order equals the atomic "
                "answer and 0 where it differs, 0 sites the judge could not "
                "evaluate.  W12 discloses that its own first version of this "
                "check was green vacuously and that it found and fixed it."),
        },
        "what_this_does_NOT_establish": (
            "it is a symbolic comparison on chosen values, not an execution.  It "
            "does not establish that the surrounding translator is otherwise "
            "correct, that the emitted text is encodable, or anything about the "
            "GPU."),
    }
    path = os.path.join(HERE, "SEMANTIC_CORPUS_16AX.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("\n%d/%d checks passed -> %s" % (n_pass, len(checks), out["verdict"]))
    print("supported %d/%d, unsupported %s" % (n_supported, n_sites, unsupported))
    print("wrote", path)
    return 0 if n_pass == len(checks) else 1


if __name__ == "__main__":
    sys.exit(run_corpus())
