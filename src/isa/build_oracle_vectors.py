#!/usr/bin/env python3
"""phase16s/isa/build_oracle_vectors.py -- Phase 16S item S1.

Builds instruction-level oracle vectors for the sixteen J3 mnemonics that
`phase16r/isa/J3_INSTRUCTION_CONFORMANCE.json` reports as BLOCKED with reason
`NO_INDEPENDENT_ORACLE_VECTOR_FOR_THIS_MNEMONIC`, derives every expected value
from the ISA mathematical definition through `oracle16.py` (which imports
nothing and never sees the emulator), then MEASURES the live emulator through
the R11 tool's own `Harness.probe` and records agree / disagree per field.

Host only.  No GPU, no HIP, no game, nothing armed or deployed.

Run from the project root:

    python phase16s/isa/build_oracle_vectors.py

Writes `ISA_ORACLE_16.json`, `ISA_ORACLE_16.md` and `logs/*` under
`phase16s/isa/` only.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import sys
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HERE = os.path.join(ROOT, "phase16s", "isa")
LOGSDIR = os.path.join(HERE, "logs")

#: The emulator module this run must have loaded.  Asserted, never assumed.
EMU_REL = "phase8_static/tools/emu.py"
EMU_SHA256 = "c6afc641be3ce734789ec505eb7f23ca876db8787cbccb9f00426064edb17205"
#: The MRO owner of six of the sixteen handlers, under the instantiated class.
P14D8_REL = "phase14d8_static/tools/p14d8_core.py"
ISA_REL = "phase16r/isa/ref/rdna2_isa.txt"
ISA_SHA256 = "46fdab001a4de548375ba1147213afaf14e86524a5ce137720e1f640d1108950"
DISASM_REL = "phase16e_candidate_e/disasm/candidate_e_gfx1030_disasm.txt"
J3_KERNEL = "_Z10k_swin_varILi32ELb0EEv9VarParams"
R11_ARTIFACT_REL = "phase16r/isa/J3_INSTRUCTION_CONFORMANCE.json"

SENTINEL = 0xDEADBEEF          # untouched-register sentinel (16R's convention)
FULL = 0xFFFFFFFF
M16 = 0xFFFF

MNEMONICS = [
    "s_mov_b64",
    "v_add_co_u32",
    "v_add_co_ci_u32_e64",
    "v_cmp_gt_i32_e64",
    "v_cmp_gt_u32_e64",
    "v_cmp_lt_i32_e64",
    "v_lshlrev_b16",
    "v_lshrrev_b16",
    "v_min_u32_e32",
    "v_mul_lo_u16",
    "v_mul_u32_u24_e32",
    "v_pack_b32_f16",
    "v_sub_nc_u16",
    "v_cvt_f16_f32_e32",
    "v_fma_mixlo_f16",
    "v_fma_mixhi_f16",
]


def P(msg=""):
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode(), flush=True)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def h32(x):
    return "0x%08X" % (x & 0xFFFFFFFF)


def h64(x):
    return "0x%016X" % (x & 0xFFFFFFFFFFFFFFFF)


# ---------------------------------------------------------------------------
# write-scope audit (recording only; it never raises into the run)
# ---------------------------------------------------------------------------
def _state_of(path):
    try:
        st = os.stat(path)
        return ["file", st.st_size, st.st_mtime_ns]
    except FileNotFoundError:
        return ["absent"]
    except Exception as exc:                                     # noqa: BLE001
        return ["unreadable", type(exc).__name__]


def finalize_write_audit(rec):
    """Record the state of every flagged path at the end of the run.

    16R recorded the same single intent (`os.mkdir` of a pre-existing
    directory) and could show `state_changed: false`; this does the same so a
    reader can see whether the run actually altered anything outside the
    phase directory.
    """
    for w in rec["outside"]:
        after = _state_of(w["path"])
        w["state_after_run"] = after
        w["state_changed"] = (w.get("state_at_attempt") != after)
    rec["n_state_changing_outside"] = sum(
        1 for w in rec["outside"] if w["state_changed"])
    return rec


def install_write_audit():
    allowed = os.path.abspath(os.path.join(ROOT, "phase16s")) + os.sep
    rec = {"n_write_intents_outside_phase16s": 0, "outside": []}

    def hook(event, args):
        try:
            path = None
            if event == "open":
                mode = args[1] if len(args) > 1 else ""
                flags = args[2] if len(args) > 2 else 0
                writing = False
                if isinstance(mode, str) and any(c in mode for c in "wax+"):
                    writing = True
                if isinstance(flags, int) and (
                        flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT
                                 | os.O_APPEND)):
                    writing = True
                if not writing:
                    return
                path = args[0]
            elif event in ("os.mkdir", "os.rmdir", "os.remove", "os.rename",
                           "os.chmod", "shutil.copyfile", "shutil.move"):
                path = args[0]
            else:
                return
            if not isinstance(path, (str, bytes)):
                return
            sp = os.path.abspath(
                path.decode() if isinstance(path, bytes) else path)
            if not sp.startswith(allowed):
                rec["n_write_intents_outside_phase16s"] += 1
                if len(rec["outside"]) < 40:
                    rec["outside"].append({"event": event, "path": sp,
                                           "state_at_attempt": _state_of(sp)})
        except Exception:                                        # noqa: BLE001
            pass

    sys.addaudithook(hook)
    return rec


# ---------------------------------------------------------------------------
# J3 operand samples -- extracted from the J3 kernel's own text, never invented
# ---------------------------------------------------------------------------
def j3_samples():
    """Every instruction line inside the J3 kernel's own address range.

    The J3 stream executes `_Z10k_swin_varILi32ELb0EEv9VarParams` (see
    `phase16p/j3_v2/out/J3_TRACE_SUMMARY.json` `cell/kernel_mangled`) and its
    recorded store-site PCs (0xACC24, 0xB538C, ...) fall inside this range, so
    the range is the J3 module's own text rather than the whole candidate
    module (which carries ten other kernels).
    """
    path = os.path.join(ROOT, DISASM_REL.replace("/", os.sep))
    if not os.path.exists(path):
        raise SystemExit("J3 disassembly missing: " + path)
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    cur = None
    rows = []
    for ln in lines:
        t = ln.strip()
        if t.endswith(">:") and " <" in t:
            cur = t.split("<")[-1][:-2]
            continue
        if cur != J3_KERNEL or "//" not in ln:
            continue
        tail = ln.split("//", 1)[1].strip()
        # the annotation is "0000000AB200: DEADBEEF DEADBEEF" -- twelve hex
        # address digits, then the colon at index 12
        if len(tail) < 13 or tail[12] != ":":
            continue
        try:
            addr = int(tail[:12], 16)
        except ValueError:
            continue
        text = ln.split("//", 1)[0].strip()
        if text:
            rows.append((addr, text))
    if not rows:
        raise SystemExit("no instruction lines found for " + J3_KERNEL)
    by_mnem = collections.defaultdict(list)
    for addr, text in rows:
        by_mnem[text.split()[0]].append((addr, text))
    return {"kernel": J3_KERNEL, "lo": min(a for a, _ in rows),
            "hi": max(a for a, _ in rows), "rows": rows, "by_mnem": by_mnem,
            "path": DISASM_REL, "n_lines": len(rows)}


#: Samples that MUST be verbatim text of the J3 kernel, and the vectors that
#: cite them.  A sample that is not found is recorded as absent; it is never
#: substituted.
J3_WANTED = {
    "s_mov_b64": [("pair_move", ["s[40:41]", "s[4:5]"])],
    "v_add_co_u32": [("sgpr_carry", ["s2", "s38"]), ("vcc_carry", ["vcc_lo"])],
    "v_add_co_ci_u32_e64": [("null_vcc_in", ["null", "vcc_lo"]),
                            ("sgpr_carry_in", ["s29", "s19"])],
    "v_cmp_gt_i32_e64": [("s19_v1", ["s19", "v1"])],
    "v_cmp_gt_u32_e64": [("imm_0x100", ["0x100", "v0"]),
                         ("imm_64", ["64", "v19"])],
    "v_cmp_lt_i32_e64": [("minus1_v5", ["-1", "v5"])],
    "v_lshlrev_b16": [("shift4", ["4", "v52"])],
    "v_lshrrev_b16": [("shift10", ["10", "v13"]), ("shift8", ["8", "v39"])],
    "v_min_u32_e32": [("imm32", ["32", "v18"]), ("v8_v14", ["v8", "v14"])],
    "v_mul_lo_u16": [("imm_0xab", ["0xab", "v9"]), ("times6", ["v17", "6"])],
    "v_mul_u32_u24_e32": [("imm_0x44", ["0x44", "v11"]),
                          ("imm_0x48", ["0x48", "v9"])],
    "v_pack_b32_f16": [("v1_v2", ["v1", "v2"]),
                       ("float_literal", ["v5", "1.0"])],
    "v_sub_nc_u16": [("v41_v17", ["v41", "v17"])],
    "v_cvt_f16_f32_e32": [("v1_v1", ["v1", "v1"])],
    "v_fma_mixlo_f16": [("v8_v16_0", ["v8", "v16"])],
    "v_fma_mixhi_f16": [("v8_v19_0", ["v8", "v19"])],
}


def find_j3_samples(j3):
    """Locate the wanted samples; report what is absent instead of inventing."""
    found, missing = {}, []
    for mnem, wants in J3_WANTED.items():
        cands = sorted(set(j3["by_mnem"].get(mnem) or []))
        found[mnem] = {}
        for label, tokens in wants:
            hit = None
            for addr, text in cands:
                if all(tok in text for tok in tokens):
                    hit = {"addr": "0x%012X" % addr, "text": text,
                           "file": j3["path"], "kernel": j3["kernel"],
                           "tokens": list(tokens)}
                    break
            if hit is None:
                missing.append({"mnemonic": mnem, "sample": label,
                                "tokens": list(tokens),
                                "n_candidate_lines": len(cands)})
            else:
                found[mnem][label] = hit
    return found, missing


def jsrc(sample, *extra):
    parts = ["J3 sample %s: %s" % (sample["addr"], sample["text"])]
    parts.extend(x for x in extra if x)
    return " | ".join(parts)


def j3_form_summary(j3, mnem):
    """Every distinct operand form the J3 module prints for `mnem`.

    This is a STATIC count over the J3 kernel's own disassembly text, not a
    per-instance trace: it says which operand forms exist in the module that
    J3 executes, not which of them executed.  That distinction matters for
    reachability and is stated wherever this is used.
    """
    cands = sorted(set(j3["by_mnem"].get(mnem) or []))
    forms = [{"addr": "0x%012X" % a, "text": t} for a, t in cands]
    real_sdst = 0
    tokens = collections.Counter()
    asym = 0
    n_mod = 0
    lit = 0
    for _, t in cands:
        parts = [p.strip() for p in t.split(" ", 1)[1].split(",")]
        if len(parts) >= 2:
            tokens[parts[1]] += 1
            if parts[1] not in ("null", "vcc_lo"):
                real_sdst += 1
        if len(parts) >= 3 and parts[1] != parts[2]:
            asym += 1
        rest = parts[1:]
        if any(("|" in x) or x.startswith("-v") for x in rest):
            n_mod += 1
        if any(("." in x and not x.startswith("0x") and not x.startswith("v")
                and not x.startswith("s")) for x in rest):
            lit += 1
    out = {"n_distinct_forms_in_the_j3_module": len(forms), "forms": forms,
           "n_forms_whose_two_source_tokens_differ": asym,
           "n_forms_with_an_input_modifier_token": n_mod,
           "n_forms_with_a_float_literal_operand": lit}
    # The scalar-destination reading only means anything for the VOP3B carry
    # forms, where operand 2 IS a destination.  For the other mnemonics it is
    # the ordinary destination and reporting it as an "sdst" would be wrong.
    if cands and all(len(t.split(" ", 1)[1].split(",")) >= 5 for _, t in cands):
        out["second_operand_token_counts"] = dict(tokens.most_common(8))
        out["n_forms_with_a_non_null_non_vcc_scalar_destination"] = real_sdst
    else:
        out["second_operand_token_counts"] = None
        out["n_forms_with_a_non_null_non_vcc_scalar_destination"] = None
        out["note"] = ("this mnemonic's printed operand 2 is its ordinary "
                       "destination, not a VOP3B scalar destination, so no "
                       "scalar-destination count is reported")
    return out


def isrc(*parts):
    return " | ".join(x for x in parts if x)


# ---------------------------------------------------------------------------
# input construction: exact, and asserted by decoding back through the oracle
# ---------------------------------------------------------------------------
def f32_exact(o, sig, exp2, sign=0):
    """Bits of the f32 exactly equal to (-1)^sign * sig * 2**exp2.

    INPUT construction only.  The value is decoded back through the oracle's
    own field splitter and asserted, so a mistyped input cannot survive.
    """
    n = sig.bit_length()
    if n < 24:
        sig <<= (24 - n)
        exp2 -= (24 - n)
    if sig.bit_length() > 24:
        raise ValueError("not representable exactly in f32")
    e = exp2 + 23
    if not (-126 <= e <= 127):
        raise ValueError("outside the normal f32 range")
    bits = (sign << 31) | ((e + 127) << 23) | (sig - (1 << 23))
    assert o._f32_parts(bits) == ("num", sign, sig, exp2), "input round-trip"
    return bits


def LANES(*vals):
    return [vals[i % len(vals)] for i in range(32)]


def V(mnem, name, dst, srcs, setup, solve, note, source, level=None):
    return {"mnem": mnem, "name": name, "dst": dst, "srcs": list(srcs),
            "setup": dict(setup), "solve": solve, "note": note,
            "source": source, "level": level}


def b16(o, dst_old, r16, extra=None, alts=None):
    """The 32-bit destination of a 16-bit-result instruction.

    `expect.value` is the FULL 32-bit destination (the S1 vector model), and
    the S1 brief gives these ops the zero-extending form (`dst = (src1 <<
    src0) & 0xFFFF` and the like), so zero-extension is the DECLARED reading
    here.  The ISA text prints only `D.u[15:0]` and says nothing about bits
    [31:16], so the preserving reading is carried as an alternate and the
    measurement -- not the oracle -- reports which one the emulator
    implements.
    """
    a = dict(alts or {})
    a.setdefault("preserve_high_half_from_the_destination",
                 o.dst16_lo(dst_old, r16, "preserve"))
    return E(value=o.dst16_lo(dst_old, r16, "zero"), extra=extra, alt=a)


def E(value=None, extra=None, scc=None, exec_=None, alt=None):
    return {"value": value, "extra": extra or {}, "scc": scc, "exec": exec_,
            "alt": alt or {}}


# ===========================================================================
# the sixteen vector sets
# ===========================================================================
def vecs_s_mov_b64(j3, S):
    v = []
    s = S["pair_move"]
    v.append(V("s_mov_b64", "j3_pair_move_s40_41_from_s4_5", "s[40:41]",
               ["s[4:5]"],
               {"s4": 0x11223344, "s5": 0x55667788},
               lambda o: E(value=(0x55667788 << 32) | 0x11223344,
                           extra={"s3": SENTINEL, "scc": 0},
                           alt={"swapped_halves":
                                (0x11223344 << 32) | 0x55667788}),
               "J3 operand shape, verbatim. Low half from s4, high half from "
               "s5; the swapped reading gives 0x1122334455667788. The "
               "neighbour s3 is read back to show nothing else moved.",
               jsrc(s, "ISA rdna2_isa.txt:5781-5785 (D.u64 = S0.u64)")))
    v.append(V("s_mov_b64", "imm64_zero", "s[3:4]", ["0"],
               {"s3": SENTINEL, "s4": SENTINEL},
               lambda o: E(value=0),
               "The wider module executes `s_mov_b64 s[0:1], 0`. A move of zero "
               "must clear BOTH halves; 0xDEADBEEF left in the high half is "
               "detectable.",
               "ISA rdna2_isa.txt:5781-5785"))
    v.append(V("s_mov_b64", "imm64_hex_64bit", "s[3:4]", ["0x0123456789ABCDEF"],
               {"s3": SENTINEL, "s4": SENTINEL},
               lambda o: E(value=0x0123456789ABCDEF,
                           alt={"truncated_to_32_bits": 0x89ABCDEF}),
               "A 64-bit literal must reach the high half.",
               "ISA rdna2_isa.txt:5781-5785"))
    v.append(V("s_mov_b64", "imm64_minus_one", "s[3:4]", ["-1"],
               {"s3": SENTINEL, "s4": SENTINEL},
               lambda o: E(value=0xFFFFFFFFFFFFFFFF,
                           alt={"low_half_only": 0xFFFFFFFF}),
               "Sign-sensitive: -1 must fill all 64 bits.",
               "ISA rdna2_isa.txt:5781-5785"))
    v.append(V("s_mov_b64", "single_sgpr_source_zero_extended", "s[3:4]", ["s2"],
               {"s2": 0x80000001, "s3": SENTINEL, "s4": SENTINEL},
               lambda o: E(value=0x80000001,
                           alt={"high_half_from_the_pair_at_s2":
                                (SENTINEL << 32) | 0x80000001}),
               "OPEN: `D.u64 = S0.u64` does not say how a 32-bit source names a "
               "64-bit operand. Declared reading: the named SGPR alone, "
               "zero-extended. The alternative (the pair s[2:3]) is recorded so "
               "the measurement decides.",
               "ISA rdna2_isa.txt:5781-5785", level="OPEN"))
    v.append(V("s_mov_b64", "asymmetric_high_bit_pattern", "s[3:4]", ["s[0:1]"],
               {"s0": 0x00000001, "s1": 0x80000000},
               lambda o: E(value=0x8000000000000001),
               "Every bit distinct across the pair.",
               "ISA rdna2_isa.txt:5781-5785"))
    return v


def vecs_v_add_co_u32(j3, S):
    v = []
    a = S["sgpr_carry"]
    v.append(V("v_add_co_u32", "j3_sgpr_carry_out", "v1", ["s2", "s38", "v1"],
               {"s38": FULL, "v1": LANES(2)},
               lambda o: E(value=1, extra={"s2": FULL, "scc": 0},
                           alt={"carry_30_bit_mask": FULL}),
               "J3 operand shape, verbatim. 0xFFFFFFFF + 2 = 0x100000001: "
               "destination 1, and the carry-out SGPR must read all-ones.",
               jsrc(a, "ISA rdna2_isa.txt:10190-10195")))
    b = S["vcc_carry"]
    v.append(V("v_add_co_u32", "j3_vcc_carry_out", "v1", ["vcc_lo", "s28", "v1"],
               {"s28": 1, "v1": LANES(1), "vcc": SENTINEL},
               lambda o: E(value=2, extra={"vcc": 0}),
               "J3 operand shape with a VCC carry destination: 1 + 1 = 2 with "
               "no carry, so VCC must be WRITTEN 0 rather than left at "
               "0xDEADBEEF.",
               jsrc(b, "ISA rdna2_isa.txt:10190-10195")))
    v.append(V("v_add_co_u32", "j3_null_carry_out", "v0",
               ["null", "0x5800", "v0"],
               {"v0": LANES(0x12345678), "vcc": 0xA5A5A5A5},
               lambda o: E(value=(0x12345678 + 0x5800) & FULL,
                           extra={"vcc": 0xA5A5A5A5}),
               "The wider module's shape: `v_add_co_u32 v0, null, 0x5800, v0`. "
               "The add still happens and VCC must be left completely alone.",
               "ISA rdna2_isa.txt:10190-10195 (J3 shape, other kernels)"))
    v.append(V("v_add_co_u32", "no_carry_below_boundary", "v0", ["s0", "v1", "v2"],
               {"v1": LANES(7), "v2": LANES(5)},
               lambda o: E(value=12, extra={"s0": 0}),
               "Just below the carry boundary: 7 + 5, carry 0.",
               "ISA rdna2_isa.txt:10190-10195"))
    v.append(V("v_add_co_u32", "carry_boundary_exact", "v0", ["s0", "v1", "v2"],
               {"v1": LANES(FULL), "v2": LANES(1)},
               lambda o: E(value=0, extra={"s0": FULL},
                           alt={"carry_test_is_strict_greater": 0}),
               "Exactly at 2^32: result 0, carry 1.",
               "ISA rdna2_isa.txt:10190-10195"))
    v.append(V("v_add_co_u32", "carry_boundary_one_below", "v0",
               ["s0", "v1", "v2"],
               {"v1": LANES(0xFFFFFFFE), "v2": LANES(1)},
               lambda o: E(value=FULL, extra={"s0": 0}),
               "One below 2^32: result all-ones, carry 0. Brackets the "
               "boundary with the vector above.",
               "ISA rdna2_isa.txt:10190-10195"))
    v.append(V("v_add_co_u32", "zero_plus_zero", "v0", ["s0", "v1", "v2"],
               {"v1": LANES(0), "v2": LANES(0)},
               lambda o: E(value=0, extra={"s0": 0}),
               "Zero case; also proves the destination is written (a handler "
               "that leaves it untouched reads 0xDEADBEEF).",
               "ISA rdna2_isa.txt:10190-10195"))
    v.append(V("v_add_co_u32", "all_ones_plus_all_ones", "v0",
               ["s0", "v1", "v2"],
               {"v1": LANES(FULL), "v2": LANES(FULL)},
               lambda o: E(value=0xFFFFFFFE, extra={"s0": FULL}),
               "High-bit case: 2*(2^32-1), result 0xFFFFFFFE, carry 1.",
               "ISA rdna2_isa.txt:10190-10195"))
    v.append(V("v_add_co_u32", "exec_partial", "v0", ["s0", "v1", "v2"],
               {"v1": LANES(FULL), "v2": LANES(1), "exec": 0x0000FFFF,
                "v0": LANES(0xAAAA5555)},
               lambda o: E(value=0,
                           extra={"s0": 0x0000FFFF, "exec": 0x0000FFFF,
                                  "v0@17": 0xAAAA5555, "v0@31": 0xAAAA5555},
                           alt={"carry_out_keeps_inactive_bits":
                                {"extra": {"s0": (SENTINEL & 0xFFFF0000)
                                           | 0xFFFF}}}),
               "EXEC = low 16 lanes. The carry mask must have bits ONLY in "
               "0..15, lanes 17 and 31 must keep 0xAAAA5555, and EXEC itself "
               "must be unchanged. The alt reading leaves the inactive carry "
               "bits as they were -- the document does not say which is "
               "required, so the measurement decides.",
               "ISA rdna2_isa.txt:10190-10195 + 3.3 EXECute Mask",
               level="OPEN"))
    return v


def vecs_v_add_co_ci_u32(j3, S):
    v = []
    a = S["null_vcc_in"]
    v.append(V("v_add_co_ci_u32_e64", "j3_null_sdst_vcc_carry_in", "v10",
               ["null", "0", "v10", "vcc_lo"],
               {"v10": LANES(FULL), "vcc": FULL},
               lambda o: E(value=0, extra={"scc": 0}),
               "J3 operand shape, verbatim: dst, null, src0=0, src1=v10, "
               "carry-in vcc_lo. 0xFFFFFFFF + 0 + 1 = 0 (mod 2^32); the "
               "carry-out is discarded because the destination is `null`.",
               jsrc(a, "ISA rdna2_isa.txt:7275-7284")))
    b = S["sgpr_carry_in"]
    v.append(V("v_add_co_ci_u32_e64", "j3_sgpr_carry_in_per_lane", "v10",
               ["null", "s29", "0", "s19"],
               {"s29": 5, "s19": 0x00000003},
               lambda o: E(value=5 + o.lane_bit(0x00000003, 0),
                           extra={"v10@1": 5 + o.lane_bit(0x00000003, 1),
                                  "v10@2": 5 + o.lane_bit(0x00000003, 2),
                                  "v10@31": 5 + o.lane_bit(0x00000003, 31)}),
               "J3 operand shape with the carry-in taken from an SGPR: lanes 0 "
               "and 1 have carry-in 1 and every other lane 0, so the "
               "destination must be 6 in lanes 0 and 1 and 5 elsewhere. Lanes "
               "1, 2 and 31 are read back directly, which separates a per-lane "
               "carry-in from a single broadcast bit. No alternate reading is "
               "recorded: the document's `VCC` is a per-lane value, so a "
               "broadcast would be a defect rather than an ambiguity.",
               jsrc(b, "ISA rdna2_isa.txt:7281-7284")))
    v.append(V("v_add_co_ci_u32_e64", "carry_out_to_sgpr", "v0",
               ["s0", "v1", "v2", "s19"],
               {"v1": LANES(FULL), "v2": LANES(2), "s19": 0},
               lambda o: E(value=1, extra={"s0": FULL}),
               "DISCRIMINATING: the carry-out destination is an ordinary SGPR, "
               "which is the VOP3B form the document describes at :7277-7281. "
               "0xFFFFFFFF + 2 + 0 = 0x100000001, so s0 must read all-ones. A "
               "handler that writes the carry only to VCC leaves s0 at the "
               "sentinel.",
               "ISA rdna2_isa.txt:7275-7284"))
    v.append(V("v_add_co_ci_u32_e64", "carry_out_to_vcc", "v0",
               ["vcc_lo", "v1", "v2", "s19"],
               {"v1": LANES(FULL), "v2": LANES(0), "s19": FULL, "vcc": 0},
               lambda o: E(value=0, extra={"vcc": FULL}),
               "Carry-out to VCC with a carry-in in EVERY lane (s19 = "
               "0xFFFFFFFF, and the carry-in is the lane's bit of that "
               "register): 0xFFFFFFFF + 0 + 1 = 0, carry 1 in every active "
               "lane.",
               "ISA rdna2_isa.txt:7275-7284"))
    v.append(V("v_add_co_ci_u32_e64", "carry_in_zero_no_carry", "v0",
               ["s0", "v1", "v2", "s19"],
               {"v1": LANES(0), "v2": LANES(0), "s19": 0},
               lambda o: E(value=0, extra={"s0": 0}),
               "Zero case with a zero carry-in: result 0, carry-out 0, and the "
               "carry-out SGPR written rather than left at the sentinel.",
               "ISA rdna2_isa.txt:7275-7284"))
    v.append(V("v_add_co_ci_u32_e64", "carry_boundary_with_zero_carry_in", "v0",
               ["s0", "v1", "v2", "s19"],
               {"v1": LANES(FULL), "v2": LANES(0), "s19": 0},
               lambda o: E(value=FULL, extra={"s0": 0}),
               "0xFFFFFFFF + 0 + 0: one below the boundary, carry 0.",
               "ISA rdna2_isa.txt:7275-7284"))
    v.append(V("v_add_co_ci_u32_e64", "carry_in_from_sgpr_bit_pattern", "v0",
               ["s0", "v1", "v2", "s19"],
               {"v1": LANES(1), "v2": LANES(1), "s19": 0xAAAA5555},
               lambda o: E(value=1 + 1 + o.lane_bit(0xAAAA5555, 0),
                           extra={"s0": 0,
                                  "v0@1": 1 + 1 + o.lane_bit(0xAAAA5555, 1),
                                  "v0@2": 1 + 1 + o.lane_bit(0xAAAA5555, 2)}),
               "Carry-in as a per-lane pattern: 1 + 1 + bit(lane, 0xAAAA5555), "
               "which is 1 in the odd lanes of the pattern. Lanes 1 and 2 are "
               "read back, so a single broadcast bit is separated from the "
               "architectural per-lane carry-in.",
               "ISA rdna2_isa.txt:7275-7284"))
    v.append(V("v_add_co_ci_u32_e64", "exec_partial", "v0",
               ["vcc_lo", "v1", "v2", "s19"],
               {"v1": LANES(FULL), "v2": LANES(0), "s19": FULL, "vcc": 0,
                "exec": 0x0000000F, "v0": LANES(0xAAAA5555)},
               lambda o: E(value=0,
                           extra={"vcc": 0x0000000F, "exec": 0x0000000F,
                                  "v0@17": 0xAAAA5555},
                           alt={"carry_out_keeps_inactive_bits":
                                0xAAAA5550}),
               "EXEC = 4 lanes. Only the four active lanes may be written, in "
               "either the destination or VCC; lane 17 keeps 0xAAAA5555.",
               "ISA rdna2_isa.txt:7275-7284 + 3.3 EXECute Mask", level="OPEN"))
    v.append(V("v_add_co_ci_u32_e64", "operand_order_not_observable", "v0",
               ["s0", "v1", "v2", "s19"],
               {"v1": 0x10000, "v2": 3, "s19": 0},
               lambda o: E(value=0x10003, extra={"s0": 0},
                           alt={"src0_src1_swapped": 0x10003}),
               "Stated plainly: addition is commutative, so NO vector can "
               "separate src0 from src1 here. The vector is kept so the "
               "non-discrimination is visible rather than implied.",
               "ISA rdna2_isa.txt:7275-7284"))
    return v


def cmp_mask(o, pred, lane_vals, exec_mask=FULL):
    """The per-lane compare mask, assembled lane by lane.

    `lane_vals` is broadcast the same way `LANES(...)` broadcasts it, so the
    expected mask is a function of the values actually seeded.
    """
    bits = 0
    for i in range(32):
        if pred(lane_vals[i % len(lane_vals)]):
            bits |= 1 << i
    return o.mask_from_lanes(bits, exec_mask)


def vecs_v_cmp_gt_i32(j3, S):
    v = []
    s = S["s19_v1"]
    PAT = [(-7) & FULL, (-5) & FULL, (-4) & FULL, FULL, 0]
    v.append(V("v_cmp_gt_i32_e64", "j3_s19_vs_v1_mixed_mask", "s0",
               ["s19", "v1"],
               {"s19": (-5) & FULL, "v1": LANES(*PAT), "s1": SENTINEL},
               lambda o: E(value=cmp_mask(o, lambda x: o.v_cmp_gt_i32((-5) & FULL, x),
                                          PAT),
                           extra={"s1": SENTINEL, "scc": 0}),
               "J3 operand shape. The lane pattern makes a MIXED mask (several "
               "lanes true, several false) that no constant-mask handler can "
               "produce; the untouched neighbour s1 is read back.",
               jsrc(s, "ISA rdna2_isa.txt:8690 (opcode 132, D = S0 > S1)")))
    v.append(V("v_cmp_gt_i32_e64", "signedness_trap_min_int_vs_one", "s4",
               ["s0", "v5"],
               {"s0": 0x80000000, "v5": LANES(1), "s5": SENTINEL},
               lambda o: E(value=0, extra={"s5": SENTINEL},
                           alt={"unsigned_reading": FULL}),
               "SIGNEDNESS TRAP. 0x80000000 signed is -2147483648, which is NOT "
               "> 1, so the mask must be 0. Read as unsigned it is 2147483648 > "
               "1 and the mask would be all-ones: the two readings differ in "
               "all 32 bits.",
               "ISA rdna2_isa.txt:8690"))
    v.append(V("v_cmp_gt_i32_e64", "equal_operands", "s4", ["s0", "v5"],
               {"s0": 0xFFFFFFFB, "v5": LANES(0xFFFFFFFB)},
               lambda o: E(value=0),
               "Strict greater-than must be false on equality; a `>=` error "
               "gives all-ones.",
               "ISA rdna2_isa.txt:8690"))
    v.append(V("v_cmp_gt_i32_e64", "signedness_trap_neg_one_vs_zero", "s4",
               ["s0", "v5"],
               {"s0": FULL, "v5": LANES(0)},
               lambda o: E(value=0, alt={"unsigned_reading": FULL}),
               "Second signedness trap in the other direction: 0xFFFFFFFF is "
               "-1 signed and -1 > 0 is false (mask 0); unsigned it is "
               "4294967295 > 0 and the mask would be all-ones.",
               "ISA rdna2_isa.txt:8690"))
    v.append(V("v_cmp_gt_i32_e64", "exec_partial_nibble", "s4", ["s0", "v5"],
               {"s0": 0, "v5": LANES(FULL), "exec": 0x0000000F,
                "s5": SENTINEL},
               lambda o: E(value=0x0000000F,
                           extra={"s5": SENTINEL, "exec": 0x0000000F},
                           alt={"exec_ignored": FULL}),
               "EXEC = low nibble. The mask must have bits 0..3 and no others; "
               "honouring EXEC is architectural (3.3).",
               "ISA rdna2_isa.txt:8690 + 3.3 EXECute Mask", level="OPEN"))
    v.append(V("v_cmp_gt_i32_e64", "destination_aliases_source_read_before_write",
               "s0", ["s0", "v5"],
               {"s0": 5, "v5": LANES((-1) & FULL)},
               lambda o: E(value=FULL,
                           alt={"read_after_destination_write": 0,
                                "unsigned_reading": 0}),
               "J3 uses exactly this shape (`v_cmp_gt_i32_e64 s0, s0, v5`). Old "
               "s0 = 5, v5 = -1: 5 > -1 signed is TRUE -> all-ones. A handler "
               "that reads the destination after overwriting it, or reads the "
               "operands unsigned, gives 0. Three readings, two values.",
               "ISA rdna2_isa.txt:8690 (J3 executes this shape)"))
    v.append(V("v_cmp_gt_i32_e64", "zero_case", "s4", ["s0", "v5"],
               {"s0": 0, "v5": LANES(0), "s5": SENTINEL},
               lambda o: E(value=0, extra={"s5": SENTINEL}),
               "Zero case; the destination is overwritten (not left at the "
               "sentinel) and the neighbour is untouched.",
               "ISA rdna2_isa.txt:8690"))
    return v


def vecs_v_cmp_gt_u32(j3, S):
    v = []
    a = S["imm_0x100"]
    PAT = [0x000000FF, 0x00000100, 0x00000101, 0x80000000]
    v.append(V("v_cmp_gt_u32_e64", "j3_imm_0x100_vs_v0", "s0",
               ["0x100", "v0"],
               {"v0": LANES(*PAT), "s1": SENTINEL},
               lambda o: E(value=cmp_mask(o, lambda x: o.v_cmp_gt_u32(0x100, x),
                                          PAT),
                           extra={"s1": SENTINEL, "scc": 0}),
               "J3 operand shape, values bracketing the constant: 0x100 > 0xFF "
               "true, > 0x100 FALSE (equality is not greater), > 0x101 false. "
               "The 0x80000000 lane is the unsigned high-bit case.",
               jsrc(a, "ISA rdna2_isa.txt:8967 (opcode 196, D = S0 > S1)")))
    b = S["imm_64"]
    PAT2 = [0, 63, 64, 65]
    v.append(V("v_cmp_gt_u32_e64", "j3_imm_64_vs_v19", "s2",
               ["64", "v19"],
               {"v19": LANES(*PAT2), "s3": SENTINEL},
               lambda o: E(value=cmp_mask(o, lambda x: o.v_cmp_gt_u32(64, x),
                                          PAT2),
                           extra={"s3": SENTINEL}),
               "Second J3 operand shape (destination s2, immediate 64).",
               jsrc(b, "ISA rdna2_isa.txt:8967")))
    v.append(V("v_cmp_gt_u32_e64", "signedness_trap_high_bit", "s4",
               ["s0", "v5"],
               {"s0": 0x80000000, "v5": LANES(1)},
               lambda o: E(value=FULL, alt={"signed_reading": 0}),
               "SIGNEDNESS TRAP, the mirror of the v_cmp_gt_i32 vector: as "
               "unsigned 0x80000000 > 1 is TRUE (mask all-ones); read signed it "
               "is -2147483648 > 1, false (mask 0).",
               "ISA rdna2_isa.txt:8967"))
    v.append(V("v_cmp_gt_u32_e64", "equal_operands", "s4", ["s0", "v5"],
               {"s0": 0xDEADBEEF, "v5": LANES(0xDEADBEEF)},
               lambda o: E(value=0),
               "Strict greater-than is false on equality.",
               "ISA rdna2_isa.txt:8967"))
    v.append(V("v_cmp_gt_u32_e64", "all_ones_vs_zero_high_bit", "s4",
               ["s0", "v5"],
               {"s0": FULL, "v5": LANES(0)},
               lambda o: E(value=FULL, alt={"signed_reading": 0}),
               "High-bit case where the two readings agree (0xFFFFFFFF > 0 is "
               "true both ways), kept as the non-discriminating partner of the "
               "trap above.",
               "ISA rdna2_isa.txt:8967"))
    v.append(V("v_cmp_gt_u32_e64", "exec_partial_high_half", "s4", ["s0", "v5"],
               {"s0": FULL, "v5": LANES(0), "exec": 0xFFFF0000,
                "s5": SENTINEL},
               lambda o: E(value=0xFFFF0000, extra={"s5": SENTINEL},
                           alt={"exec_ignored": FULL}),
               "EXEC = high half only; the mask must land in bits 16..31.",
               "ISA rdna2_isa.txt:8967 + 3.3 EXECute Mask", level="OPEN"))
    return v


def vecs_v_cmp_lt_i32(j3, S):
    v = []
    s = S["minus1_v5"]
    PAT = [0xFFFFFFFE, 0xFFFFFFFF, 0, 1]
    v.append(V("v_cmp_lt_i32_e64", "j3_minus1_vs_v5_mixed_mask", "s1",
               ["-1", "v5"],
               {"v5": LANES(*PAT), "s2": SENTINEL},
               lambda o: E(value=cmp_mask(o, lambda x: o.v_cmp_lt_i32((-1) & FULL, x),
                                          PAT),
                           extra={"s2": SENTINEL, "scc": 0}),
               "J3 operand shape, verbatim: `v_cmp_lt_i32_e64 s1, -1, v5`. The "
               "pattern makes a mixed mask (-1 < -2 false, -1 < -1 false, "
               "-1 < 0 true, -1 < 1 true) and exercises the negative-immediate "
               "decode.",
               jsrc(s, "ISA rdna2_isa.txt:8684 (opcode 129, D = S0 < S1)")))
    v.append(V("v_cmp_lt_i32_e64", "signedness_trap_one_vs_min_int", "s4",
               ["s0", "v5"],
               {"s0": 1, "v5": LANES(0x80000000)},
               lambda o: E(value=0, alt={"unsigned_reading": FULL}),
               "SIGNEDNESS TRAP. Signed: 1 < -2147483648 is false -> 0. "
               "Unsigned: 1 < 0x80000000 is true -> all-ones.",
               "ISA rdna2_isa.txt:8684"))
    v.append(V("v_cmp_lt_i32_e64", "signedness_trap_neg_one_vs_zero", "s4",
               ["s0", "v5"],
               {"s0": FULL, "v5": LANES(0)},
               lambda o: E(value=FULL, alt={"unsigned_reading": 0}),
               "The mirror trap: -1 < 0 is true signed (all-ones); unsigned "
               "0xFFFFFFFF < 0 is false.",
               "ISA rdna2_isa.txt:8684"))
    v.append(V("v_cmp_lt_i32_e64", "equal_operands_at_min_int", "s4",
               ["s0", "v5"],
               {"s0": 0x80000000, "v5": LANES(0x80000000)},
               lambda o: E(value=0),
               "Strict less-than is false on equality, taken at the most "
               "negative value where a sign-flip bug shows.",
               "ISA rdna2_isa.txt:8684"))
    v.append(V("v_cmp_lt_i32_e64", "exec_partial_low_half", "s4", ["s0", "v5"],
               {"s0": 0, "v5": LANES(1), "exec": 0x0000FFFF,
                "s5": SENTINEL},
               lambda o: E(value=cmp_mask(o, lambda x: o.v_cmp_lt_i32(0, x),
                                          [1], 0x0000FFFF),
                           extra={"s5": SENTINEL, "exec": 0x0000FFFF},
                           alt={"exec_ignored": FULL}),
               "EXEC = low half with a predicate that is TRUE in every active "
               "lane (0 < 1), so the mask must be exactly the 16 active lanes. "
               "EXEC itself must also be unchanged.",
               "ISA rdna2_isa.txt:8684 + 3.3 EXECute Mask", level="OPEN"))
    v.append(V("v_cmp_lt_i32_e64", "zero_case", "s4", ["s0", "v5"],
               {"s0": 0, "v5": LANES(0), "s5": SENTINEL},
               lambda o: E(value=0, extra={"s5": SENTINEL}),
               "Zero case; the destination is overwritten and the neighbour is "
               "untouched.",
               "ISA rdna2_isa.txt:8684"))
    return v


def vecs_v_lshlrev_b16(j3, S):
    v = []
    s = S["shift4"]
    v.append(V("v_lshlrev_b16", "j3_shift4_of_v52", "v17", ["4", "v52"],
               {"v52": LANES(0x00008001), "v17": LANES(0xFFFF0000)},
               lambda o: b16(o, 0xFFFF0000, o.v_lshlrev_b16(4, 0x8001),
                             alts={"src0_src1_swapped":
                                   o.dst16_lo(0xFFFF0000,
                                              o.v_lshlrev_b16(0x8001, 4))}),
               "J3 operand shape, verbatim. 0x8001 << 4 = 0x80010, low 16 -> "
               "0x0010. One vector separates three readings: the untouched high "
               "half of the destination, a source swap, and the declared one.",
               jsrc(s, "ISA rdna2_isa.txt:10224-10226 "
                       "(D.u[15:0] = S1.u[15:0] << S0.u[3:0])")))
    v.append(V("v_lshlrev_b16", "count_wraps_mod_16", "v0", ["v1", "v2"],
               {"v1": LANES(16), "v2": LANES(0x1234), "v0": LANES(0xFFFF0000)},
               lambda o: b16(o, 0xFFFF0000, o.v_lshlrev_b16(16, 0x1234),
                             alts={"count_ge_16_zeroes":
                                   o.dst16_lo(0xFFFF0000, 0)}),
               "BOUNDARY: the document says the count is `S0.u[3:0]`, so a count "
               "of 16 is a count of 0 and the value is unchanged. A reading "
               "that zeroes at 16 or more is separated.",
               "ISA rdna2_isa.txt:10226"))
    v.append(V("v_lshlrev_b16", "count_15_high_bit", "v0", ["v1", "v2"],
               {"v1": LANES(15), "v2": LANES(1), "v0": LANES(0x11110000)},
               lambda o: b16(o, 0x11110000, o.v_lshlrev_b16(15, 1)),
               "Largest usable count: 1 << 15 = 0x8000, the sign bit of the "
               "16-bit domain.",
               "ISA rdna2_isa.txt:10226"))
    v.append(V("v_lshlrev_b16", "zero_value", "v0", ["v1", "v2"],
               {"v1": LANES(5), "v2": LANES(0), "v0": LANES(0xFFFFFFFF)},
               lambda o: b16(o, 0xFFFFFFFF, o.v_lshlrev_b16(5, 0)),
               "Zero source: the low half must become 0.",
               "ISA rdna2_isa.txt:10226"))
    v.append(V("v_lshlrev_b16", "all_ones_value_count_zero", "v0", ["v1", "v2"],
               {"v1": LANES(0), "v2": LANES(0xFFFF), "v0": LANES(0)},
               lambda o: b16(o, 0, o.v_lshlrev_b16(0, 0xFFFF)),
               "All-ones value with a zero count: identity on the low 16 bits.",
               "ISA rdna2_isa.txt:10226"))
    v.append(V("v_lshlrev_b16", "high_bits_of_count_ignored", "v0", ["v1", "v2"],
               {"v1": LANES(0x10000001), "v2": LANES(0x8001),
                "v0": LANES(0x22220000)},
               lambda o: b16(o, 0x22220000,
                             o.v_lshlrev_b16(0x10000001, 0x8001),
                             alts={"count_uses_all_32_bits":
                                   o.dst16_lo(0x22220000, 0)}),
               "Only S0.u[3:0] is the count: 0x10000001 must behave as a count "
               "of 1, not as a huge count.",
               "ISA rdna2_isa.txt:10226"))
    v.append(V("v_lshlrev_b16", "exec_partial", "v0", ["v1", "v2"],
               {"v1": LANES(4), "v2": LANES(0x8001), "exec": 0x00000003,
                "v0": LANES(0xAAAA0000)},
               lambda o: b16(o, 0xAAAA0000, o.v_lshlrev_b16(4, 0x8001),
                             extra={"v0@17": 0xAAAA0000},
                             alts={"exec_ignored":
                                   o.dst16_lo(0xAAAA0000, 0x0010)}),
               "EXEC = lanes 0,1; lane 17 must keep 0xAAAA0000.",
               "ISA rdna2_isa.txt:10226 + 3.3 EXECute Mask", level="OPEN"))
    return v


def vecs_v_lshrrev_b16(j3, S):
    v = []
    a = S["shift10"]
    b = S["shift8"]
    v.append(V("v_lshrrev_b16", "j3_shift10_of_v13", "v17", ["10", "v13"],
               {"v13": LANES(0x0000FC00), "v17": LANES(0xFFFF0000)},
               lambda o: b16(o, 0xFFFF0000, o.v_lshrrev_b16(10, 0xFC00),
                             alts={"src0_src1_swapped":
                                   o.dst16_lo(0xFFFF0000,
                                              o.v_lshrrev_b16(0xFC00, 10))}),
               "J3 operand shape, verbatim. 0xFC00 >> 10 = 0x3F.",
               jsrc(a, "ISA rdna2_isa.txt:10150-10151 (the expression line at "
                       ":10150 is a copy of V_ADD_NC_U16's and prints a "
                       "MULTIPLY; the reading used is the one the caption, "
                       "V_LSHLREV_B16 (:10226) and V_ASHRREV_I16 (:10153) "
                       "agree on)")))
    v.append(V("v_lshrrev_b16", "j3_shift8_of_v39_logical", "v8", ["8", "v39"],
               {"v39": LANES(0x00008101), "v8": LANES(0x12340000)},
               lambda o: b16(o, 0x12340000, o.v_lshrrev_b16(8, 0x8101),
                             alts={"arithmetic_shift_reading":
                                   o.dst16_lo(0x12340000, 0xFF81)}),
               "Second J3 operand shape. 0x8101 >> 8 = 0x81: a LOGICAL shift, so "
               "the high bit of the 16-bit value must NOT be replicated. The "
               "arithmetic sibling would give 0xFF81, so this vector separates "
               "logical from arithmetic.",
               jsrc(b, "ISA rdna2_isa.txt:10150-10158")))
    v.append(V("v_lshrrev_b16", "count_wraps_mod_16", "v0", ["v1", "v2"],
               {"v1": LANES(16), "v2": LANES(0xBEEF), "v0": LANES(0xFFFF0000)},
               lambda o: b16(o, 0xFFFF0000, o.v_lshrrev_b16(16, 0xBEEF),
                             alts={"count_ge_16_zeroes":
                                   o.dst16_lo(0xFFFF0000, 0)}),
               "BOUNDARY: a count of 16 must behave as a count of 0 "
               "(`S0.u[3:0]`).",
               "ISA rdna2_isa.txt:10150-10151"))
    v.append(V("v_lshrrev_b16", "count_15", "v0", ["v1", "v2"],
               {"v1": LANES(15), "v2": LANES(0x8000), "v0": LANES(0x11110000)},
               lambda o: b16(o, 0x11110000, o.v_lshrrev_b16(15, 0x8000)),
               "Largest usable count on the high bit: 0x8000 >> 15 = 1.",
               "ISA rdna2_isa.txt:10150-10151"))
    v.append(V("v_lshrrev_b16", "operand_order_count_zero", "v0", ["v1", "v2"],
               {"v1": LANES(0), "v2": LANES(0xABCD), "v0": LANES(0)},
               lambda o: b16(o, 0, o.v_lshrrev_b16(0, 0xABCD),
                             alts={"src0_src1_swapped": o.dst16_lo(0, 0)}),
               "Count 0 with a non-zero value: the correct answer is 0xABCD and "
               "the swapped reading gives 0, so operand order IS observable "
               "here.",
               "ISA rdna2_isa.txt:10150-10151"))
    v.append(V("v_lshrrev_b16", "all_ones_count_one_no_sign_fill", "v0",
               ["v1", "v2"],
               {"v1": LANES(1), "v2": LANES(0xFFFF), "v0": LANES(0)},
               lambda o: b16(o, 0, o.v_lshrrev_b16(1, 0xFFFF),
                             alts={"arithmetic_shift_reading":
                                   o.dst16_lo(0, 0xFFFF)}),
               "All-ones value, logical shift: 0x7FFF, no sign fill.",
               "ISA rdna2_isa.txt:10150-10151"))
    v.append(V("v_lshrrev_b16", "exec_partial", "v0", ["v1", "v2"],
               {"v1": LANES(4), "v2": LANES(0x8001), "exec": 0x00000003,
                "v0": LANES(0xAAAA0000)},
               lambda o: b16(o, 0xAAAA0000, o.v_lshrrev_b16(4, 0x8001),
                             extra={"v0@17": 0xAAAA0000},
                             alts={"exec_ignored":
                                   o.dst16_lo(0xAAAA0000, 0x0800)}),
               "EXEC = lanes 0,1; lane 17 must keep 0xAAAA0000.",
               "ISA rdna2_isa.txt:10150-10151 + 3.3 EXECute Mask", level="OPEN"))
    return v


def vecs_v_min_u32(j3, S):
    v = []
    a = S["imm32"]
    b = S["v8_v14"]
    v.append(V("v_min_u32_e32", "j3_imm32_vs_v18", "v18", ["32", "v18"],
               {"v18": LANES(100)},
               lambda o: E(value=o.v_min_u32(32, 100),
                           alt={"max_reading": 100,
                                "signed_min_reading": 32}),
               "J3 operand shape, verbatim: `v_min_u32_e32 v18, 32, v18`. "
               "min(32, 100) = 32; a max instead of a min gives 100.",
               jsrc(a, "ISA rdna2_isa.txt:7224-7226 (D.u32 = S0.u32 < S1.u32 ? "
                       "S0.u32 : S1.u32)")))
    v.append(V("v_min_u32_e32", "j3_v8_vs_v14", "v14", ["v8", "v14"],
               {"v8": LANES(0x00001234), "v14": LANES(0x00004321)},
               lambda o: E(value=o.v_min_u32(0x1234, 0x4321)),
               "Second J3 operand shape: two registers, destination aliases "
               "src1.",
               jsrc(b, "ISA rdna2_isa.txt:7224-7226")))
    v.append(V("v_min_u32_e32", "signedness_trap_all_ones_vs_one", "v0",
               ["v1", "v2"],
               {"v1": LANES(FULL), "v2": LANES(1)},
               lambda o: E(value=1, alt={"signed_min_reading": FULL}),
               "SIGNEDNESS TRAP. Unsigned min(0xFFFFFFFF, 1) = 1; read signed, "
               "min(-1, 1) = -1 = 0xFFFFFFFF. The readings differ in all 32 "
               "bits.",
               "ISA rdna2_isa.txt:7224-7226"))
    v.append(V("v_min_u32_e32", "top_bit_boundary", "v0", ["v1", "v2"],
               {"v1": LANES(0x80000000), "v2": LANES(0x7FFFFFFF)},
               lambda o: E(value=0x7FFFFFFF,
                           alt={"signed_min_reading": 0x80000000}),
               "Either side of the top bit: unsigned min takes 0x7FFFFFFF, "
               "signed min would take 0x80000000.",
               "ISA rdna2_isa.txt:7224-7226"))
    v.append(V("v_min_u32_e32", "equal_operands", "v0", ["v1", "v2"],
               {"v1": LANES(0xDEADBEEF), "v2": LANES(0xDEADBEEF)},
               lambda o: E(value=0xDEADBEEF),
               "Equal operands: both arms agree, so this is the "
               "non-discriminating control for the min/max question.",
               "ISA rdna2_isa.txt:7224-7226"))
    v.append(V("v_min_u32_e32", "zero_case", "v0", ["v1", "v2"],
               {"v1": LANES(0), "v2": LANES(FULL)},
               lambda o: E(value=0),
               "Zero case: min(0, 0xFFFFFFFF) = 0.",
               "ISA rdna2_isa.txt:7224-7226"))
    v.append(V("v_min_u32_e32", "exec_partial", "v0", ["v1", "v2"],
               {"v1": LANES(FULL), "v2": LANES(1), "exec": 0x0000FFFF,
                "v0": LANES(0xAAAA5555)},
               lambda o: E(value=1, extra={"exec": 0x0000FFFF,
                                           "v0@17": 0xAAAA5555}),
               "EXEC = low half; the write is lane-wise, lane 17 keeps "
               "0xAAAA5555, and EXEC is not disturbed.",
               "ISA rdna2_isa.txt:7224-7226 + 3.3 EXECute Mask", level="OPEN"))
    return v


def vecs_v_mul_lo_u16(j3, S):
    v = []
    a = S["imm_0xab"]
    b = S["times6"]
    v.append(V("v_mul_lo_u16", "j3_imm_0xab_vs_v9", "v13", ["0xab", "v9"],
               {"v9": LANES(0x12340007), "v13": LANES(0xFFFF0000)},
               lambda o: b16(o, 0xFFFF0000,
                             o.v_mul_lo_u16(0xAB, 0x12340007),
                             alts={"high_bits_of_sources_used":
                                   o.dst16_lo(0xFFFF0000,
                                              (0xAB * 0x12340007) & M16)}),
               "J3 operand shape, verbatim. 0xAB * 7 = 0x4B5 after the low-16 "
               "mask on BOTH sources; the 0x1234 in the high half of v9 must "
               "not contribute, which the third reading would allow.",
               jsrc(a, "ISA rdna2_isa.txt:10147")))
    v.append(V("v_mul_lo_u16", "j3_v17_times_6", "v17", ["v17", "6"],
               {"v17": LANES(0x0000FFFF)},
               lambda o: b16(o, 0, o.v_mul_lo_u16(0xFFFF, 6)),
               "Second J3 operand shape: max unsigned short times 6, truncated "
               "to 16 bits (0xFFFA).",
               jsrc(b, "ISA rdna2_isa.txt:10147")))
    v.append(V("v_mul_lo_u16", "max_times_max_truncates", "v0", ["v1", "v2"],
               {"v1": LANES(0xFFFF), "v2": LANES(0xFFFF),
                "v0": LANES(0xFFFF0000)},
               lambda o: b16(o, 0xFFFF0000,
                             o.v_mul_lo_u16(0xFFFF, 0xFFFF),
                             alts={"32_bit_product_kept_word":
                                   o.dst16_lo(0xFFFF0000, 0xFFFE0001)}),
               "BOUNDARY: 0xFFFF * 0xFFFF = 0xFFFE0001, so a 16-bit destination "
               "gives 0x0001.",
               "ISA rdna2_isa.txt:10147"))
    v.append(V("v_mul_lo_u16", "zero_case", "v0", ["v1", "v2"],
               {"v1": LANES(0xFFFF), "v2": LANES(0), "v0": LANES(SENTINEL)},
               lambda o: b16(o, SENTINEL, 0),
               "Zero case.",
               "ISA rdna2_isa.txt:10147"))
    v.append(V("v_mul_lo_u16", "source_mask_separator_bit16", "v0",
               ["v1", "v2"],
               {"v1": LANES(0x00010000), "v2": LANES(0x00010000),
                "v0": LANES(0)},
               lambda o: b16(o, 0, o.v_mul_lo_u16(0x00010000, 0x00010000),
                             alts={"full_32_bit_multiply_low16":
                                   o.dst16_lo(0, (0x10000 * 0x10000) & M16)}),
               "SEPARATING VECTOR for the source mask: bit 16 is outside the "
               "16-bit source, so the product must be 0. A full 32-bit "
               "multiply's low 16 bits would also be 0 here, so this vector is "
               "recorded as NOT separating those two readings.",
               "ISA rdna2_isa.txt:10147"))
    v.append(V("v_mul_lo_u16", "source_mask_separator_odd", "v0", ["v1", "v2"],
               {"v1": LANES(0x000000FF), "v2": LANES(0x00000100),
                "v0": LANES(SENTINEL)},
               lambda o: b16(o, SENTINEL, o.v_mul_lo_u16(0x00FF, 0x0100),
                             alts={"full_32_bit_multiply_low16":
                                   o.dst16_lo(SENTINEL,
                                              (0xFF * 0x100) & M16)}),
               "Masked sources: 0xFF * 0x100 = 0xFF00. Bit 8 of src1 is inside "
               "u16 so it must contribute, unlike the vector above.",
               "ISA rdna2_isa.txt:10147"))
    return v


def vecs_v_mul_u32_u24(j3, S):
    v = []
    a = S["imm_0x44"]
    b = S["imm_0x48"]
    v.append(V("v_mul_u32_u24_e32", "j3_imm_0x44_vs_v11", "v11",
               ["0x44", "v11"],
               {"v11": LANES(0x12345678)},
               lambda o: E(value=o.v_mul_u32_u24(0x44, 0x12345678),
                           alt={"full_32_bit_multiply":
                                (0x44 * 0x12345678) & FULL}),
               "J3 operand shape, verbatim. Only the low 24 bits of v11 "
               "(0x345678) take part: 68 * 3430008 = 233240544 = 0x0DE66BE0. "
               "Using all 32 bits gives a different value, so the 24-bit "
               "truncation IS separated.",
               jsrc(a, "ISA rdna2_isa.txt:7129-7139 (D.u32 = S0.u24 * S1.u24)")))
    v.append(V("v_mul_u32_u24_e32", "j3_imm_0x48_vs_v9", "v38", ["0x48", "v9"],
               {"v9": LANES(0x00FFFFFF)},
               lambda o: E(value=o.v_mul_u32_u24(0x48, 0x00FFFFFF)),
               "Second J3 operand shape: 72 * 0xFFFFFF = 0x47FFFFB8, which fits "
               "in 32 bits, so the truncation is not what is tested here.",
               jsrc(b, "ISA rdna2_isa.txt:7139")))
    v.append(V("v_mul_u32_u24_e32", "max_times_max_truncates", "v0",
               ["v1", "v2"],
               {"v1": LANES(0xFFFFFF), "v2": LANES(0xFFFFFF)},
               lambda o: E(value=o.v_mul_u32_u24(0xFFFFFF, 0xFFFFFF)),
               "BOUNDARY: 0xFFFFFF^2 = 0xFFFFFE000001; the low 32 bits are "
               "0xFE000001. A 32-bit-product reading gives the same product "
               "here, so this vector does not separate them.",
               "ISA rdna2_isa.txt:7139"))
    v.append(V("v_mul_u32_u24_e32", "top_byte_of_src0_ignored", "v0",
               ["v1", "v2"],
               {"v1": LANES(0x01000000), "v2": LANES(2),
                "v0": LANES(SENTINEL)},
               lambda o: E(value=o.v_mul_u32_u24(0x01000000, 2),
                           alt={"full_32_bit_multiply":
                                (0x01000000 * 2) & FULL}),
               "SEPARATING VECTOR for the 24-bit mask: bit 24 is OUTSIDE u24, "
               "so the product must be 0. A full 32-bit multiply gives "
               "0x02000000.",
               "ISA rdna2_isa.txt:7139"))
    v.append(V("v_mul_u32_u24_e32", "zero_case", "v0", ["v1", "v2"],
               {"v1": LANES(0xFFFFFF), "v2": LANES(0), "v0": LANES(SENTINEL)},
               lambda o: E(value=0),
               "Zero case.",
               "ISA rdna2_isa.txt:7139"))
    v.append(V("v_mul_u32_u24_e32", "operand_order_not_observable", "v0",
               ["v1", "v2"],
               {"v1": LANES(3), "v2": LANES(0x100000)},
               lambda o: E(value=o.v_mul_u32_u24(3, 0x100000),
                           alt={"src0_src1_swapped":
                                o.v_mul_u32_u24(0x100000, 3)}),
               "Stated plainly: multiplication is commutative, so NO vector can "
               "separate src0 from src1 for this mnemonic. The alt reading is "
               "identical by construction; the vector is kept to make the "
               "non-discrimination visible.",
               "ISA rdna2_isa.txt:7139"))
    return v


def vecs_v_pack_b32_f16(j3, S):
    v = []
    a = S["v1_v2"]
    b = S["float_literal"]
    v.append(V("v_pack_b32_f16", "j3_v1_v2_half_mapping", "v1", ["v1", "v2"],
               {"v1": LANES(0x00003C00), "v2": LANES(0x00004000)},
               lambda o: E(value=o.v_pack_b32_f16(0x3C00, 0x4000),
                           alt={"src0_high_src1_low":
                                o.v_pack_b32_f16(0x4000, 0x3C00)}),
               "J3 operand shape, verbatim. S1 (0x4000) belongs in bits 31:16 "
               "and S0 (0x3C00) in bits 15:0, so the expected value is "
               "0x40003C00; the alt reading is the half mapping reversed "
               "(0x3C004000). The two candidates differ in every bit of the "
               "packed value.",
               jsrc(a, "ISA rdna2_isa.txt:10207-10210")))
    v.append(V("v_pack_b32_f16", "j3_float_literal_operand", "v11",
               ["v5", "1.0"],
               {"v5": LANES(0x0000BC00)},
               lambda o: E(value=o.v_pack_b32_f16(0xBC00, 0x3C00),
                           alt={"src0_high_src1_low":
                                o.v_pack_b32_f16(0x3C00, 0xBC00)}),
               "J3 operand shape taken VERBATIM, including the float literal: "
               "`v_pack_b32_f16 v11, v5, 1.0`. The architectural operand is an "
               "FP16 value, so 1.0 is 0x3C00. Whether the emulator's operand "
               "parser accepts this printed form at all is part of the "
               "measurement.",
               jsrc(b, "ISA rdna2_isa.txt:10207-10210")))
    v.append(V("v_pack_b32_f16", "high_bits_of_sources_ignored", "v0",
               ["v1", "v2"],
               {"v1": LANES(0x1234ABCD), "v2": LANES(0x5678EF01)},
               lambda o: E(value=o.v_pack_b32_f16(0xABCD, 0xEF01),
                           alt={"src0_high_src1_low":
                                o.v_pack_b32_f16(0xEF01, 0xABCD)}),
               "Only the low 16 bits of each source are packed: 0xEF01ABCD, "
               "with the half order still observable.",
               "ISA rdna2_isa.txt:10207-10210"))
    v.append(V("v_pack_b32_f16", "zero_case", "v0", ["v1", "v2"],
               {"v1": LANES(0), "v2": LANES(0), "v0": LANES(SENTINEL)},
               lambda o: E(value=0),
               "Both sources zero: the whole destination becomes 0, so a "
               "handler that leaves the destination untouched is separated too.",
               "ISA rdna2_isa.txt:10207-10210"))
    v.append(V("v_pack_b32_f16", "all_ones_case", "v0", ["v1", "v2"],
               {"v1": LANES(0xFFFF), "v2": LANES(0xFFFF)},
               lambda o: E(value=0xFFFFFFFF),
               "All-ones: both halves set. Symmetric, so it separates a "
               "half-swap only weakly; included for the all-ones branch.",
               "ISA rdna2_isa.txt:10207-10210"))
    v.append(V("v_pack_b32_f16", "exec_zero_writes_nothing", "v0",
               ["v1", "v2"],
               {"v1": LANES(0x3C00), "v2": LANES(0x4000), "exec": 0x00000000,
                "v0": LANES(0xAAAA5555)},
               lambda o: E(value=0xAAAA5555,
                           alt={"exec_ignored":
                                o.v_pack_b32_f16(0x3C00, 0x4000)}),
               "SEPARATING VECTOR for EXEC: EXEC = 0, so NOTHING may be written "
               "and the destination must stay 0xAAAA5555.",
               "ISA rdna2_isa.txt:10207-10210 + 3.3 EXECute Mask"))
    v.append(V("v_pack_b32_f16", "exec_partial", "v0", ["v1", "v2"],
               {"v1": LANES(0x3C00), "v2": LANES(0x4000), "exec": 0x00000003,
                "v0": LANES(0xAAAA5555)},
               lambda o: E(value=o.v_pack_b32_f16(0x3C00, 0x4000),
                           extra={"v0@2": 0xAAAA5555, "v0@17": 0xAAAA5555},
                           alt={"src0_high_src1_low":
                                o.v_pack_b32_f16(0x4000, 0x3C00)}),
               "EXEC = lanes 0,1; lanes 2 and 17 must keep 0xAAAA5555.",
               "ISA rdna2_isa.txt:10207-10210 + 3.3 EXECute Mask"))
    return v


def vecs_v_sub_nc_u16(j3, S):
    v = []
    s = S["v41_v17"]
    v.append(V("v_sub_nc_u16", "j3_v41_minus_v17", "v52", ["v41", "v17"],
               {"v41": LANES(0x00010005), "v17": LANES(0x00020003),
                "v52": LANES(0xFFFF0000)},
               lambda o: b16(o, 0xFFFF0000,
                             o.v_sub_nc_u16(0x00010005, 0x00020003),
                             alts={"add_instead_of_subtract":
                                   o.dst16_lo(0xFFFF0000, (5 + 3) & M16),
                                   "src0_src1_swapped":
                                   o.dst16_lo(0xFFFF0000,
                                              o.v_sub_nc_u16(0x00020003,
                                                             0x00010005))}),
               "J3 operand shape, verbatim. Only the low 16 bits of each source "
               "take part: 5 - 3 = 2. Four readings are separated by this one "
               "vector: the `+` the document's own expression line at :10139 "
               "prints, operand order, the untouched high half, and the "
               "declared subtraction.",
               jsrc(s, "ISA rdna2_isa.txt:10139-10145")))
    v.append(V("v_sub_nc_u16", "borrow_wraps_to_all_ones", "v0", ["v1", "v2"],
               {"v1": LANES(0), "v2": LANES(1), "v0": LANES(0x11110000)},
               lambda o: b16(o, 0x11110000, o.v_sub_nc_u16(0, 1),
                             alts={"saturating_reading":
                                   o.dst16_lo(0x11110000, 0)}),
               "BORROW BOUNDARY: 0 - 1 wraps to 0xFFFF (no carry out of a "
               "16-bit domain and CLAMP is not set). The saturating alternative "
               "-- which the document mentions as a MODIFIER -- gives 0.",
               "ISA rdna2_isa.txt:10141-10145"))
    v.append(V("v_sub_nc_u16", "asymmetric_operand_order", "v0", ["v1", "v2"],
               {"v1": LANES(3), "v2": LANES(10), "v0": LANES(0)},
               lambda o: b16(o, 0, o.v_sub_nc_u16(3, 10),
                             alts={"src0_src1_swapped":
                                   o.dst16_lo(0, o.v_sub_nc_u16(10, 3))}),
               "Operand order IS observable for subtraction: 3 - 10 = 0xFFF9, "
               "the swap gives 7.",
               "ISA rdna2_isa.txt:10145"))
    v.append(V("v_sub_nc_u16", "equal_operands", "v0", ["v1", "v2"],
               {"v1": LANES(0x1234), "v2": LANES(0x1234),
                "v0": LANES(SENTINEL)},
               lambda o: b16(o, SENTINEL, o.v_sub_nc_u16(0x1234, 0x1234)),
               "Equal operands: the low half becomes 0 (the high half is a "
               "separate, recorded reading).",
               "ISA rdna2_isa.txt:10145"))
    v.append(V("v_sub_nc_u16", "all_ones_minus_zero", "v0", ["v1", "v2"],
               {"v1": LANES(0xFFFF), "v2": LANES(0), "v0": LANES(0)},
               lambda o: b16(o, 0, o.v_sub_nc_u16(0xFFFF, 0)),
               "All-ones high-bit case with a zero subtrahend: identity.",
               "ISA rdna2_isa.txt:10145"))
    v.append(V("v_sub_nc_u16", "high_bits_of_sources_ignored", "v0",
               ["v1", "v2"],
               {"v1": LANES(0xFFFF0005), "v2": LANES(0xFFFF0003),
                "v0": LANES(0)},
               lambda o: b16(o, 0, o.v_sub_nc_u16(0xFFFF0005, 0xFFFF0003)),
               "The 0xFFFF in each source's high half must not contribute: "
               "5 - 3 = 2.",
               "ISA rdna2_isa.txt:10145"))
    v.append(V("v_sub_nc_u16", "exec_partial", "v0", ["v1", "v2"],
               {"v1": LANES(0), "v2": LANES(1), "exec": 0x0000000F,
                "v0": LANES(0xAAAA5555)},
               lambda o: b16(o, 0xAAAA5555, o.v_sub_nc_u16(0, 1),
                             extra={"v0@17": 0xAAAA5555},
                             alts={"exec_ignored":
                                   o.dst16_lo(0xAAAA5555, 0xFFFF)}),
               "EXEC = low nibble; lane 17 must keep 0xAAAA5555.",
               "ISA rdna2_isa.txt:10145 + 3.3 EXECute Mask", level="OPEN"))
    return v


#: f16 inputs for the FP16 mnemonic vectors, decoded back and asserted.
F16 = {
    "pos_zero": 0x0000, "neg_zero": 0x8000,
    "smallest_sub": 0x0001, "largest_sub": 0x03FF, "smallest_norm": 0x0400,
    "one": 0x3C00, "one_plus_2m10": 0x3C01, "one_and_half": 0x3E00,
    "two": 0x4000, "neg_one": 0xBC00, "neg_one_plus_2m10": 0xBC01,
    "max": 0x7BFF, "inf": 0x7C00, "ninf": 0xFC00, "qnan": 0x7E00,
}


def vecs_v_cvt_f16_f32(j3, S):
    o = None
    j3 = S["v1_v1"]
    out = []

    def add(name, x, note, level=None, alt=None, srcs=("v1",), value_x=None):
        srcs = list(srcs)
        vx = x if value_x is None else value_x

        def solve(o, _x=x, _vx=vx):
            # dst and src are the same register for every one of these vectors
            # (the J3 shape is `v_cvt_f16_f32_e32 v1, v1`), so the OLD
            # destination value is the source value.
            base = o.cvt_f16_dst(_vx, _x, "zero")
            a = dict(alt or {})
            a.setdefault("preserve_dst_high_half",
                         o.cvt_f16_dst(_vx, _x, "preserve"))
            return E(value=base, alt=a)
        out.append(V("v_cvt_f16_f32_e32", name, "v1", srcs,
                     {"v1": LANES(x)}, solve, note,
                     jsrc(j3, "ISA rdna2_isa.txt:7571-7577 "
                              "(D.f16 = flt32_to_flt16(S0.f))")
                     if name.startswith("j3") else
                     "ISA rdna2_isa.txt:7571-7577 (D.f16 = flt32_to_flt16(S0.f))",
                     level=level))

    def fe(sig, exp2, sign=0):
        return f32_exact(sys.modules["oracle16"], sig, exp2, sign)

    add("j3_convert_1_5", fe(3, -1),
        "J3 operand shape, verbatim: `v_cvt_f16_f32_e32 v1, v1`, source and "
        "destination the same register. 1.5 converts exactly to 0x3E00, so the "
        "only thing this vector tests is the framing.")
    add("exact_one", fe(1, 0), "Exact normal: 1.0 -> 0x3C00.")
    add("pos_zero", 0x00000000, "+0.0 -> 0x0000.")
    add("neg_zero", 0x80000000, "-0.0 -> 0x8000: the sign is carried.")
    add("smallest_f16_subnormal", fe(1, -24),
        "Smallest subnormal: 2^-24 -> 0x0001. Exercises the denormal path the "
        "document requires (`creates FP16 denormals when appropriate`).")
    add("largest_f16_subnormal", fe(1023, -24),
        "Largest subnormal: 1023*2^-24 -> 0x03FF.")
    add("smallest_f16_normal", fe(1, -14),
        "Smallest normal: 2^-14 -> 0x0400.")
    add("max_f16_finite", fe(65504, 0), "Largest finite: 65504 -> 0x7BFF.")
    add("overflow_just_above_max", fe(65505, 0),
        "OVERFLOW BOUNDARY just above the largest finite and below the tie: "
        "65505 rounds DOWN to 65504, so 0x7BFF. A truncating or "
        "round-half-up reading would give infinity here.")
    add("overflow_tie_at_65520", fe(65520, 0),
        "ROUNDING TIE AT OVERFLOW: 65520 is exactly half way between 65504 "
        "(significand LSB 1, odd) and 65536, which is infinity (LSB 0, even). "
        "Round-to-nearest-EVEN therefore gives infinity -> 0x7C00.")
    add("overflow_above_tie", fe(65521, 0),
        "Above the tie -> infinity -> 0x7C00.")
    add("overflow_far", fe(65536, 0), "2^16 -> infinity.")
    add("pos_infinity", 0x7F800000, "+Inf -> 0x7C00.")
    add("neg_infinity", 0xFF800000, "-Inf -> 0xFC00.")
    add("qnan_pos", 0x7FC00000,
        "OPEN: the document says nothing about NaN for this conversion. "
        "Declared reading: quiet NaN -> 0x7E00 with the sign cleared; the alt "
        "is the sign-preserving 0xFE00. The measurement names the one "
        "implemented.", level="OPEN", alt={"nan_sign_preserved": 0xFE00})
    add("qnan_neg", 0xFFC00000,
        "OPEN: sign of NaN, as above.", level="OPEN",
        alt={"nan_sign_preserved": 0xFE00})
    add("snan_pos", 0x7F800001,
        "OPEN: signalling NaN. Declared reading: quieted to 0x7E00; a "
        "payload-preserving conversion would give 0x7C01.", level="OPEN",
        alt={"nan_payload_preserved": 0x7C01})
    add("round_tie_down_to_even", fe(2049, -11),
        "ROUNDING TIE in the normal range: 1 + 2^-11 is exactly half way "
        "between 1.0 (LSB 0, even) and 1 + 2^-10 (LSB 1, odd); "
        "round-to-nearest-even keeps 1.0 -> 0x3C00.")
    add("round_tie_up_to_even", fe(2051, -11),
        "ROUNDING TIE the other way: 1 + 3*2^-11 is half way between "
        "1 + 2^-10 (odd) and 1 + 2^-9 (even); RNE gives 0x3C02.")
    add("subnormal_round_up", fe(3, -26),
        "SUBNORMAL ROUNDING: 3*2^-26 = 0.75 * 2^-24 lies between zero and the "
        "smallest subnormal and is more than half way up, so the correct RNE "
        "result is 0x0001. The value is BELOW 2^-24, which is the region a "
        "flush-to-zero reading would lose.")
    add("subnormal_half_tie", fe(1, -25),
        "SUBNORMAL TIE: 2^-25 is exactly half of the smallest subnormal; RNE "
        "takes the even candidate, which is zero -> 0x0000. Its partner above is "
        "the same magnitude region and must differ from it.")
    add("subnormal_just_below_normal", fe(4095, -26),
        "Top of the subnormal range: 4095*2^-26 = 1023.75*2^-24 rounds to "
        "1024*2^-24, the smallest NORMAL -> 0x0400.")
    add("f32_subnormal_input", 0x00080000,
        "An f32 SUBNORMAL input (2^-130) is far below the f16 range and must "
        "round to zero.")
    add("negate_input_modifier", fe(3, -1),
        "INPUT MODIFIER: the document says this conversion `supports input "
        "modifiers`. `-v1` with v1 = 1.5 must give -1.5 = 0xBE00: the negate "
        "applies to the f32 value and RNE then converts.", srcs=("-v1",),
        value_x=fe(3, -1, sign=1))
    return out


def _fma_vecs(j3, S, hi):
    """V_FMA_MIXLO_F16 (hi=False) and V_FMA_MIXHI_F16 (hi=True)."""
    mnem = "v_fma_mixhi_f16" if hi else "v_fma_mixlo_f16"
    sample = S["v8_v19_0"] if hi else S["v8_v16_0"]
    isa = ("ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)" if hi
           else "ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)")
    out = []

    def add(name, a, b, c, note, level=None, alt=None, dst=0xAAAA5555):
        def solve(o, _a=a, _b=b, _c=c, _d=dst, _hi=hi):
            r = o.f16_fma(_a, _b, _c)
            fold = o.dst16_hi if _hi else o.dst16_lo
            alt_zero = fold(_d, r, "zero")
            a_alt = dict(alt or {})
            a_alt.setdefault("other_half_zeroed", alt_zero)
            a_alt.setdefault("double_rounding_mul_then_add",
                             fold(_d, o.fma_double_rounding(_a, _b, _c)))
            return E(value=fold(_d, r, "preserve"), alt=a_alt)
        src_line = jsrc(sample, isa) if name.startswith("j3") else isa
        out.append(V(mnem, name, "v1", ["v1", "v2", "v3"],
                     {"v1": LANES(a), "v2": LANES(b), "v3": LANES(c),
                      "v0": LANES(dst)},
                     solve, note, src_line, level=level))

    half = "HIGH" if hi else "LOW"
    other = "low" if hi else "high"
    add("j3_one_times_two_plus_zero", F16["one"], F16["two"], 0x0000,
        "J3 operand shape, verbatim. 1.0 * 2.0 + 0 = 2.0, placed in the %s "
        "half: destination bits 15:0 %s. The declared reading PRESERVES the %s "
        "half (dst pre-set 0xAAAA5555); the alt zeroes it." % (half, other,
                                                               other))
    add("hi_vs_lo_separator", F16["one_and_half"], F16["two"], 0x0000,
        "SEPARATOR for the MIX lo/hi distinction: 1.5 * 2 = 3.0 = 0x4200 in the "
        "%s half. The %s-half reading of the same arithmetic gives a value that "
        "differs in the whole written half." % (half, other))
    add("pos_zero", 0x0000, 0x0000, 0x0000,
        "Declared NON-DISCRIMINATING control: all-zero sources with a zero "
        "destination, so the declared, zero-half and double-rounding readings "
        "all agree. Kept so the disagreeing vectors can be seen not to be "
        "disagreeing everywhere.", dst=0x00000000)
    add("neg_zero_product_and_addend", F16["neg_zero"], F16["one"],
        F16["neg_zero"],
        "OPEN: -0 * 1 + (-0). IEEE 754 gives -0 only when both terms are -0, "
        "which holds here -> 0x8000 in the %s half. The alt reading is +0."
        % half, level="OPEN", alt={"positive_zero":
                                   (0x0000 if not hi else 0x00000000)})
    add("mixed_sign_zero_sum", F16["neg_zero"], F16["one"], 0x0000,
        "OPEN: -0 * 1 + +0 -> +0 under RNE (mixed-sign zero sum). The alt "
        "reading is -0.", level="OPEN",
        alt={"negative_zero": (0x8000 if not hi else 0x80000000)})
    add("smallest_subnormal", F16["smallest_sub"], F16["one"], 0x0000,
        "Smallest subnormal: 2^-24 * 1 + 0.")
    add("largest_subnormal", F16["largest_sub"], F16["one"], 0x0000,
        "Largest subnormal: 1023*2^-24.")
    add("smallest_normal", F16["smallest_norm"], F16["one"], 0x0000,
        "Smallest normal: 2^-14.")
    add("max_finite", F16["max"], F16["one"], 0x0000,
        "Largest finite: 65504 * 1 + 0 -> 0x7BFF.")
    add("overflow_to_infinity", F16["max"], F16["two"], 0x0000,
        "OVERFLOW: 65504 * 2 = 131008 exceeds the f16 range -> infinity.")
    add("infinity_times_one", F16["inf"], F16["one"], 0x0000,
        "Inf * 1 + 0 -> Inf.")
    add("infinity_times_zero", F16["inf"], 0x0000, F16["one"],
        "OPEN: Inf * 0 is the IEEE invalid operation -> quiet NaN. The "
        "document's expression `S0.f*S1.f+S2.f` gives no value for it; the "
        "declared reading is 0x7E00.", level="OPEN")
    add("qnan_propagation", F16["qnan"], F16["one"], 0x0000,
        "OPEN: a NaN operand -> the declared reading is the quiet NaN 0x7E00.",
        level="OPEN")
    add("fused_single_rounding", F16["one_plus_2m10"], F16["one_plus_2m10"],
        F16["neg_one"],
        "FUSED vs DOUBLE ROUNDING. a = b = 1 + 2^-10, c = -1. The exact product "
        "is 1 + 2^-9 + 2^-20; adding -1 leaves 2^-9 + 2^-20, which rounds (RNE, "
        "tie to even) to 2^-9. A multiply-round-then-add implementation rounds "
        "the product to 1 + 2^-9 first and then gets 0. The two readings differ "
        "and only one of them is 'fused'.")
    add("fused_tie_in_the_subnormal_grid", F16["one_plus_2m10"],
        F16["one_plus_2m10"], F16["neg_one_plus_2m10"],
        "FUSED TIE: a = b = 1 + 2^-10, c = -(1 + 2^-10). The exact value is "
        "(1+2^-10)^2 - (1+2^-10) = 2^-10 + 2^-20, which is below the smallest "
        "normal, so the single rounding happens on the SUBNORMAL grid. Kept "
        "separate from the vector above because the rounding grid differs.")
    add("exact_cancellation_positive_zero", F16["neg_one"], F16["two"],
        F16["two"],
        "(-1) * 2 + 2 = 0: an exact cancellation, so the sign is +0 under RNE.",
        alt={"negative_zero": (0x8000 if not hi else 0x80000000)})
    return out


# ===========================================================================
# assembled set
# ===========================================================================
BUILDERS = {
    "s_mov_b64": vecs_s_mov_b64,
    "v_add_co_u32": vecs_v_add_co_u32,
    "v_add_co_ci_u32_e64": vecs_v_add_co_ci_u32,
    "v_cmp_gt_i32_e64": vecs_v_cmp_gt_i32,
    "v_cmp_gt_u32_e64": vecs_v_cmp_gt_u32,
    "v_cmp_lt_i32_e64": vecs_v_cmp_lt_i32,
    "v_lshlrev_b16": vecs_v_lshlrev_b16,
    "v_lshrrev_b16": vecs_v_lshrrev_b16,
    "v_min_u32_e32": vecs_v_min_u32,
    "v_mul_lo_u16": vecs_v_mul_lo_u16,
    "v_mul_u32_u24_e32": vecs_v_mul_u32_u24,
    "v_pack_b32_f16": vecs_v_pack_b32_f16,
    "v_sub_nc_u16": vecs_v_sub_nc_u16,
    "v_cvt_f16_f32_e32": vecs_v_cvt_f16_f32,
    "v_fma_mixlo_f16": lambda j3, S: _fma_vecs(j3, S, False),
    "v_fma_mixhi_f16": lambda j3, S: _fma_vecs(j3, S, True),
}

#: The reading each side implements, one or more sentences per defect.  Every
#: mnemonic with an unexplained disagreement MUST appear here: the driver
#: refuses to finish otherwise, so a defect cannot be published without a
#: stated reading for both sides.
DEFECT_READINGS = {
    "v_pack_b32_f16": [
        "The ISA takes the FIRST source (S0) into the LOW half and the SECOND "
        "(S1) into the HIGH half of the packed word (rdna2_isa.txt:10209-10210, "
        "`D[31:16].f16 = S1.f16; D[15:0].f16 = S0.f16.`); the live handler "
        "computes `((src0 & 0xFFFF) << 16) | (src1 & 0xFFFF)`, i.e. it puts "
        "src0 in the HIGH half and src1 in the LOW half -- the two operands are "
        "exchanged.",
        "The J3 site `v_pack_b32_f16 v11, v5, 1.0` passes a FLOAT LITERAL for "
        "the second source. The architectural operand is an FP16 value, so the "
        "literal means the bit pattern 0x3C00. The live handler is "
        "`Core8.op_v_pack_b32_f16` (phase14d8_static/tools/p14d8_core.py:685), "
        "which calls `self._vbin(ins, ops, ...)`; `_vbin` "
        "(phase8_static/tools/emu.py:789-790) reads each source with "
        "`self.vget(lane, ops[i])` and passes NO `fp` argument, so the operand "
        "is read with the default `fp=False`. That reaches the last two lines "
        "of `vget` (phase8_static/tools/emu.py:473-476):\n"
        "        elif fp:\n"
        "            return float(tok)\n"
        "        else:\n"
        "            return int(tok)\n"
        "so a non-register token is decoded with `int(tok)` and `int('1.0')` "
        "raises. MEASURED, through this tool's own Harness.probe: "
        "`{'error': \"ValueError: invalid literal for int() with base 10: "
        "'1.0'\"}` for the token `1.0`, against `error: None` for the tokens "
        "`2` and `0x3C00`. The coordinator's correction describes the `fp=True` "
        "arm of that branch, which this mnemonic does not take -- the caller is "
        "the integer path, not `_vfp`. The defect is therefore an exception "
        "rather than a silently wrong value, and it is recorded with the "
        "measured error string.",
    ],
    "v_cvt_f16_f32_e32": [
        "SIGN. The ISA takes the sign of the result from the sign of the f32 "
        "input (`D.f16 = flt32_to_flt16(S0.f)`, rdna2_isa.txt:7577). The live "
        "handler takes it from bit 16 of the f32 pattern (`s = (b >> 16) & 1` "
        "where `b` is the packed binary32 word), i.e. from the low mantissa "
        "bit of the second byte, so any input whose bit 16 is 1 -- 65504.0, "
        "the largest subnormal, every negative value with that mantissa bit "
        "clear -- comes back with the wrong sign.",
        "SUBNORMAL FLUSH. The ISA requires FP16 DENORMALS to be created when an "
        "f32 value rounds into the subnormal range (rdna2_isa.txt:7573-7575, "
        "`creates FP16 denormals when appropriate`). The live handler returns a "
        "signed zero whenever the biased exponent is below -24, so a magnitude "
        "that rounds UP to the smallest subnormal (2^-24) is flushed to zero.",
        "SUBNORMAL CLAMP AT THE TOP OF THE RANGE. Rounding a subnormal "
        "magnitude up to exactly 2^-14 must give the smallest NORMAL "
        "(0x0400). The live handler clamps the subnormal significand with "
        "`min(frac, 0x3FF)`, so 1024 is clamped back to 1023 and the result is "
        "0x03FF, one quantum low.",
        "INPUT MODIFIER `-vN`. The ISA says this conversion `supports input "
        "modifiers`, i.e. the f32 VALUE is negated before conversion. The live "
        "operand reader negates the raw 32-bit pattern with two's-complement "
        "integer arithmetic and then reinterprets it as f32, so `-1.5` becomes "
        "the f32 value -3.0 (0x3FC00000 -> 0xC0400000).",
    ],
    "v_add_co_ci_u32_e64": [
        "The ISA form is VOP3B: `V_ADD_CO_CI_U32` stores the carry-out to the "
        "scalar destination the encoding names (rdna2_isa.txt:7275-7281, `In "
        "VOP3 the VCC destination may be an arbitrary SGPR-pair`). The live "
        "handler writes the carry-out only when the destination token is "
        "`vcc_lo`; any other destination is silently dropped.",
        "The ISA's carry-in is the per-lane VCC bit of the source the "
        "encoding names; the live handler reads it as bit `lane` of the named "
        "register, which this suite MEASURED to agree, so the carry-in side is "
        "not part of this finding.",
    ],
    "v_fma_mixlo_f16": [
        "The ISA computes a FP16 fused multiply-add on the FP16 operands and "
        "writes the 16-bit result into the LOW half of the destination "
        "(rdna2_isa.txt:9355-9361, `D.f[15:0] = S0.f * S1.f + S2.f.`). The live "
        "handler decodes each source's FULL 32-bit register as an f32 value, "
        "evaluates `a * b + c` in f32 and writes the 32-bit f32 result over the "
        "WHOLE destination, so neither the operand width nor the result "
        "placement is the ISA's.",
    ],
    "v_fma_mixhi_f16": [
        "The ISA computes a FP16 fused multiply-add and writes the 16-bit "
        "result into the HIGH half of the destination (rdna2_isa.txt:9367-9374, "
        "`D.f[31:16] = S0.f * S1.f + S2.f.`). The live handler decodes each "
        "source's FULL 32-bit register as an f32 value, evaluates `a * b + c` "
        "in f32 and writes the 32-bit f32 result over the WHOLE destination -- "
        "the same reading as the MIXLO handler, with no HIGH-half placement at "
        "all.",
    ],
}

#: Open questions the ISA text leaves unanswered, per mnemonic.
OPEN_QUESTIONS = {
    "s_mov_b64": [
        "How a 32-bit SGPR source names a 64-bit operand is not stated; the "
        "declared reading is zero-extension of the named SGPR."],
    "v_add_co_u32": [
        "The value the carry-out register takes in lanes where EXEC is clear is "
        "not stated; two admissible readings are recorded on the EXEC vector."],
    "v_add_co_ci_u32_e64": [
        "Carry-in source: the text says `VCC` at :7283 and `the SGPR-pair at "
        "S2.u` at :7281; a per-lane bit of the named register is the declared "
        "reading.",
        "The value the carry-out register takes in EXEC-clear lanes is not "
        "stated."],
    "v_lshlrev_b16": [
        "Bits [31:16] of the destination: the text gives D.u[15:0] only. "
        "Declared reading is preservation, inferred from V_MAD_U16 "
        "(:10244-10248), which states the convention for itself; the "
        "zero-extending alternative is measured."],
    "v_lshrrev_b16": [
        "The expression line at :10150 is WRONG: it prints `D.u16 = S0.u16 * "
        "S1.u16.` under the caption `Logical shift right, count is in the first "
        "operand`. The reading used is the one V_LSHLREV_B16 (:10226) and "
        "V_ASHRREV_I16 (:10153) agree on.",
        "Bits [31:16] of the destination, as above."],
    "v_min_u32_e32": [
        "No semantic ambiguity found in the text for this mnemonic."],
    "v_mul_lo_u16": [
        "The document gives no expression line for this mnemonic at all, only "
        "the prose 'Multiply two unsigned shorts.'; the 16-bit truncation is "
        "from the destination width.",
        "Bits [31:16] of the destination, as above."],
    "v_mul_u32_u24_e32": [
        "No semantic ambiguity found in the text for this mnemonic."],
    "v_pack_b32_f16": [
        "The half-to-position mapping is stated explicitly; only how an out-of-"
        "range or float-literal operand token is spelled is unstated."],
    "v_sub_nc_u16": [
        "The block prints BOTH `D.u16 = S0.u16 + S1.u16.` (:10139) and "
        "`D.u16 = S0.u16 - S1.u16.` (:10145). The declared reading is the "
        "subtraction, which the mnemonic and the caption both say.",
        "Bits [31:16] of the destination, as above."],
    "v_cvt_f16_f32_e32": [
        "NaN handling is not stated at all: the text gives `D.f16 = "
        "flt32_to_flt16(S0.f)` with accuracy and denormal behaviour only. "
        "Declared readings: quiet NaN -> 0x7E00 with the sign cleared; both "
        "alternatives (sign preserved, payload preserved) are measured.",
        "Bits [31:16] of the destination: the text gives a 16-bit destination "
        "only. Declared reading: zero-extension."],
    "v_fma_mixlo_f16": [
        "The half of the destination NOT written is not stated (V_MAD_U16 "
        "states it for itself at :10244-10248; V_FMA_MIX* does not). Declared "
        "reading: preserved; the zero-extending alternative is measured.",
        "OPSEL: the text says `0=src[31:0], 1=src[31:0], 2=src[15:0], "
        "3=src[31:16]`, in which entries 0 and 1 are identical -- one of them "
        "is wrong. Every vector here fixes OPSEL at the low half of each source "
        "and passes no `op_sel` token, so the OPSEL mapping is NOT measured.",
        "NaN / Inf / zero-sign rules are not stated; the declared readings are "
        "IEEE 754's defaults and are recorded on the affected vectors."],
    "v_fma_mixhi_f16": [
        "As V_FMA_MIXLO_F16: the untouched half, the OPSEL mapping and the "
        "NaN / Inf rules are all unstated.",
        "The J3 disassembly prints an `op_sel_hi:[...]` operand for several of "
        "these sites; that token is an assembler annotation and is deliberately "
        "not modelled here."],
}


def build_vectors(j3, samples, oracle):
    out = []
    for mnem in MNEMONICS:
        for v in BUILDERS[mnem](j3, samples[mnem]):
            r = v["solve"](oracle)
            out.append({
                "mnem": mnem, "name": v["name"], "dst": v["dst"],
                "srcs": v["srcs"], "setup": v["setup"],
                "expect": {"value": r["value"], "scc": r["scc"],
                           "exec": r["exec"], "extra": r["extra"]},
                "alt": r["alt"], "note": v["note"], "source": v["source"],
                "open_reading_flag": v["level"],
                "ops": [v["dst"]] + list(v["srcs"]),
            })
    return out


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--break-oracle", default=None,
                    help="negative control A: sabotage one oracle function")
    ap.add_argument("--no-mutations", action="store_true")
    args = ap.parse_args()

    os.chdir(ROOT)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.makedirs(LOGSDIR, exist_ok=True)
    audit = install_write_audit()

    sys.path.insert(0, HERE)
    sys.path.insert(0, os.path.join(HERE, "tools"))
    import oracle16 as O                                          # noqa: E402
    sys.modules["oracle16"] = O

    P("=" * 96)
    P("PHASE 16S / S1 -- INDEPENDENT ISA ORACLE FOR THE 16 BLOCKED J3 MNEMONICS")
    P("host only; no GPU, no HIP, nothing armed")
    P("=" * 96)

    # -- pins ---------------------------------------------------------------
    emu_path = os.path.join(ROOT, EMU_REL.replace("/", os.sep))
    emu_hash = sha256_file(emu_path)
    P("emu.py      %s" % emu_path)
    P("            sha256 %s" % emu_hash)
    if emu_hash != EMU_SHA256:
        P("STOP: emu.py sha256 is NOT the pinned %s" % EMU_SHA256)
        return 3
    isa_path = os.path.join(ROOT, ISA_REL.replace("/", os.sep))
    isa_hash = sha256_file(isa_path)
    P("p14d8_core  sha256 %s   (MRO owner of six of the sixteen handlers)"
      % sha256_file(os.path.join(ROOT, P14D8_REL.replace("/", os.sep))))
    P("ISA text    sha256 %s   %s"
      % (isa_hash, "PINNED" if isa_hash == ISA_SHA256 else "NOT THE PINNED TEXT"))

    # -- J3 samples ---------------------------------------------------------
    j3 = j3_samples()
    P("J3 kernel  %s  0x%X..0x%X  (%d instruction lines)"
      % (j3["kernel"], j3["lo"], j3["hi"], j3["n_lines"]))
    samples, missing = find_j3_samples(j3)
    no_sample = [m for m in MNEMONICS if not samples[m]]
    for m in MNEMONICS:
        got = sorted(samples[m])
        P("   %-22s J3 sample(s): %s"
          % (m, ", ".join("%s@%s" % (k, samples[m][k]["addr"])
                          for k in got) if got else "*** NONE FOUND ***"))
    if missing:
        P("   samples requested but NOT found (recorded, not substituted):")
        for x in missing:
            P("     %s %s %s" % (x["mnemonic"], x["sample"], x["tokens"]))

    # -- 16R cone counts, read read-only for reachability --------------------
    r11 = json.load(open(os.path.join(ROOT, R11_ARTIFACT_REL.replace(
        "/", os.sep)), encoding="utf-8"))
    r11_rows = {r["mnemonic"]: r for r in r11["rows"]}
    r11_trace = (r11.get("cone_record_identity") or {}).get("trace") or {}
    cone = {}
    for m in MNEMONICS:
        r = r11_rows.get(m) or {}
        cone[m] = {
            "executed_count_on_j3_path": r.get("executed_count_on_j3_path"),
            "nodes_in_value_cone": r.get("nodes_in_value_cone"),
            "nodes_in_address_cone": r.get("nodes_in_address_cone"),
            "nodes_in_predicate_cone": r.get("nodes_in_predicate_cone"),
            "nodes_in_union_cone": r.get("nodes_in_union_cone"),
            "contributes_to_written_bytes": r.get("contributes_to_written_bytes"),
        }

    # -- the tool's own harness --------------------------------------------
    sys.path.insert(0, os.path.join(ROOT, "phase16r", "isa", "tools"))
    import r11_j3_matrix as R                                     # noqa: E402
    sys.path.insert(0, os.path.join(ROOT, "phase16s", "isa", "tools"))
    import r11_j3_matrix_16s as R16                               # noqa: E402
    sys.path.insert(0, os.path.join(ROOT, "phase16m_final_host", "m2_isa"))
    import verify_m2 as m2                                        # noqa: E402
    env = m2.load_emulator()
    harness = R16.HarnessS1(env, m2)
    probe = harness.probe
    core_cls = harness.BOTH
    loaded = os.path.abspath(sys.modules["emu"].__file__)
    assert os.path.normcase(loaded) == os.path.normcase(emu_path), loaded
    P("instantiated class %s ; emu module %s (asserted == the pinned path)"
      % (core_cls.__name__, loaded))
    P("harness: %s.probe  (the R11 tool's own probe, subclassed only to widen "
      "register seeding and add extra read-backs)"
      % type(probe).__name__)

    # -- build and measure --------------------------------------------------
    vectors = build_vectors(j3, samples, O)
    if args.break_oracle:
        O.BREAK.add(args.break_oracle)
        P("NEGATIVE CONTROL A ACTIVE: oracle16.BREAK = %r" % (sorted(O.BREAK),))
    P("")
    P("vectors built: %d over %d mnemonics" % (len(vectors), len(MNEMONICS)))

    results = []
    n_cmp = 0
    for v in vectors:
        obs = probe(v)
        diffs = R16._obs_diffs(obs, v["expect"])
        hits = R16.alts_that_explain(v, obs, diffs)
        n_cmp += 1 + len(v["expect"].get("extra") or {})
        n_cmp += sum(1 for k in ("scc", "exec")
                     if v["expect"].get(k) is not None)
        results.append({"vector": v, "obs": obs, "diffs": diffs,
                        "alt_hits": hits})
    n_dis = sum(1 for r in results if r["diffs"])
    P("comparisons (field-level): %d" % n_cmp)
    P("vectors disagreeing: %d of %d" % (n_dis, len(vectors)))
    if n_cmp <= 0:
        P("FAILURE: 0 comparisons -- this run proves nothing and is refused")
        return 4

    # -- per-mnemonic roll-up ----------------------------------------------
    per = {}
    for m in MNEMONICS:
        rs = [r for r in results if r["vector"]["mnem"] == m]
        dis = [r for r in rs if r["diffs"]]
        unexplained = [r for r in dis if not r["alt_hits"]]
        cmp_n = sum(1 + len(r["vector"]["expect"].get("extra") or {})
                    + sum(1 for k in ("scc", "exec")
                          if r["vector"]["expect"].get(k) is not None)
                    for r in rs)
        if not samples[m]:
            status = "NO_J3_SAMPLE"
        elif not dis:
            status = "VERIFIED_INDEPENDENTLY"
        elif not unexplained:
            status = "OPEN_SEMANTICS"
        else:
            status = "DISAGREES"
        per[m] = {
            "mnemonic": m, "status": status,
            "j3_sample": (sorted(samples[m].values(),
                                 key=lambda x: x["addr"])[0]
                          if samples[m] else None),
            "j3_samples_all": sorted(samples[m].values(),
                                     key=lambda x: x["addr"]),
            "j3_samples_absent": [x for x in missing if x["mnemonic"] == m],
            "vector_count": len(rs), "comparisons": cmp_n,
            "disagreement_count": len(dis),
            "unexplained_disagreement_count": len(unexplained),
            "open_semantics_only": bool(dis) and not unexplained,
            "open_questions": OPEN_QUESTIONS.get(m, []),
            "j3_cone": cone[m],
            "defect_reading": DEFECT_READINGS.get(m),
            "agreeing_vectors": [r["vector"]["name"] for r in rs
                                 if not r["diffs"]],
            "disagreeing_vectors": [
                {"name": r["vector"]["name"], "note": r["vector"]["note"],
                 "source": r["vector"]["source"],
                 "mnem": m, "dst": r["vector"]["dst"],
                 "srcs": r["vector"]["srcs"], "ops": r["vector"]["ops"],
                 "setup_hex": {k: (h32(v) if not isinstance(v, list)
                                   else [h32(x) for x in v])
                               for k, v in r["vector"]["setup"].items()},
                 "expect": r["vector"]["expect"],
                 "expect_hex": {
                     "value": (h64(r["vector"]["expect"]["value"])
                               if r["vector"]["dst"].startswith("s[")
                               else h32(r["vector"]["expect"]["value"]))
                     if r["vector"]["expect"]["value"] is not None else None,
                     "extra": {k: h32(x) for k, x in
                               (r["vector"]["expect"].get("extra")
                                or {}).items()}},
                 "measured": r["obs"],
                 "measured_hex": {
                     "value": (h64(r["obs"]["value"])
                               if isinstance(r["obs"]["value"], int)
                               and r["vector"]["dst"].startswith("s[")
                               else h32(r["obs"]["value"]))
                     if isinstance(r["obs"]["value"], int) else None,
                     "extra": {k: h32(x) for k, x in
                               (r["obs"].get("extra") or {}).items()}},
                 "alt": r["vector"]["alt"],
                 "diffs": r["diffs"],
                 "matches_alternate_reading": r["alt_hits"],
                 "reading_the_emulator_implements_if_this_is_the_only_defect":
                     DEFECT_READINGS.get(m)}
                for r in dis],
        }
        per[m]["j3_operand_forms"] = j3_form_summary(j3, m)
        per[m]["j3_reachability_verdict"] = j3_reachability(
            m, per[m]["j3_operand_forms"],
            {"executed_count_on_j3_path": cone[m]["executed_count_on_j3_path"],
             "outcome": r11_trace.get("outcome"),
             "faults": r11_trace.get("faults"),
             "natural_end": r11_trace.get("natural_end"),
             "gate": r11_trace.get("gate")})
        per[m]["defect_reachability"] = {
            "executed_count_on_j3_path": cone[m]["executed_count_on_j3_path"],
            "nodes_in_value_cone": cone[m]["nodes_in_value_cone"],
            "nodes_in_union_cone": cone[m]["nodes_in_union_cone"],
            "contributes_to_written_bytes":
                cone[m]["contributes_to_written_bytes"],
            "j3_operand_forms": per[m]["j3_operand_forms"],
            "statement": (
                "The 16R cone record puts this mnemonic in the J3 output cone "
                "(%d value-cone node(s), %d union-cone node(s)) and marks it as "
                "contributing to written bytes, so the disagreement is on the "
                "J3 output path as an upper bound. The cone is a lane-collapsed "
                "OVER-APPROXIMATION (16R's own INFERRED note), so this is "
                "'cone-reachable', not a proof that a wrong value reached a "
                "store."
                % (cone[m]["nodes_in_value_cone"] or 0,
                   cone[m]["nodes_in_union_cone"] or 0)),
        }

    for m in MNEMONICS:
        P("  %-22s %-22s %2d vectors %3d comparisons %2d disagreements"
          % (m, per[m]["status"], per[m]["vector_count"], per[m]["comparisons"],
             per[m]["disagreement_count"]))

    # -- defects ------------------------------------------------------------
    defective = [m for m in MNEMONICS
                 if per[m]["unexplained_disagreement_count"] > 0]
    for m in defective:
        if not per[m]["defect_reading"]:
            P("REFUSING: %s has an unexplained disagreement and no stated "
              "reading for each side" % m)
            return 7
    P("")
    P("DEFECTS (an unexplained disagreement, with the reading each side "
      "implements):")
    for m in defective:
        P("  %s" % m)
        P("     %s" % per[m]["defect_reading"])
        P("     J3 executions %s, value-cone nodes %s, union-cone nodes %s, "
          "contributes to written bytes %s"
          % (cone[m]["executed_count_on_j3_path"],
             cone[m]["nodes_in_value_cone"], cone[m]["nodes_in_union_cone"],
             cone[m]["contributes_to_written_bytes"]))

    # -- NC_A: the oracle itself can fail -----------------------------------
    # Deliberately sabotage one oracle function, re-derive that mnemonic's
    # expectations and re-measure.  The count MUST change; a control that
    # cannot be made to fail proves nothing.
    mul_before = sum(1 for r in results
                     if r["vector"]["mnem"] == "v_mul_lo_u16" and r["diffs"])
    mul_before_vals = {r["vector"]["name"]: r["vector"]["expect"]["value"]
                       for r in results if r["vector"]["mnem"] == "v_mul_lo_u16"}
    O.BREAK.add("mul_lo_u16")
    try:
        vmul = [v for v in build_vectors(j3, samples, O)
                if v["mnem"] == "v_mul_lo_u16"]
        mul_after_rows = [(v["name"], v["expect"]["value"],
                           R16._obs_diffs(probe(v), v["expect"]))
                          for v in vmul]
    finally:
        O.BREAK.discard("mul_lo_u16")
    mul_after = sum(1 for _, _, d in mul_after_rows if d)
    nc_a = {"name": "NC_A_oracle_self_test_is_falsifiable",
            "what": ("sabotage one oracle function (`v_mul_lo_u16` loses its "
                     "`& 0xFFFF` on both sources), re-derive that mnemonic's "
                     "expectations and re-measure: the disagreement count MUST "
                     "change"),
            "break": "oracle16.BREAK = {'mul_lo_u16'}",
            "mnemonic": "v_mul_lo_u16",
            "disagreements_before": mul_before,
            "disagreements_after": mul_after,
            "changed": mul_after != mul_before,
            "n_vectors": len(mul_after_rows),
            "examples": [
                {"vector": name,
                 "expect_clean": mul_before_vals.get(name),
                 "expect_sabotaged": val,
                 "disagreement_fields": [f["field"] for f in d]}
                for name, val, d in mul_after_rows][:4],
            "other_mnemonics_unaffected": "not re-measured under the break"}
    P("")
    P("NC_A oracle self-test falsifiable: v_mul_lo_u16 disagreements %d -> %d "
      "under the sabotage (%s)"
      % (mul_before, mul_after, "CHANGED" if nc_a["changed"] else "UNCHANGED"))
    if not nc_a["changed"]:
        P("FAILURE: sabotaging the oracle did not change the outcome -- the "
          "comparison is vacuous")
        return 8

    # -- NC_D: the comparator can fail --------------------------------------
    nc_d = {"name": "NC_D_comparator_known_bad", "cases": []}
    step = max(1, len(vectors) // 16)
    for v in vectors[::step][:16]:
        if v["expect"]["value"] is None:
            continue
        bad = dict(v)
        bad["expect"] = dict(v["expect"])
        bad["expect"]["value"] = v["expect"]["value"] ^ 1
        obs = probe(bad)
        d = R16._obs_diffs(obs, bad["expect"])
        nc_d["cases"].append({"vector": v["name"], "mnem": v["mnem"],
                              "sabotage": "expect.value ^ 1",
                              "comparator_reports_disagreement": bool(d),
                              "fields": [f["field"] for f in d]})
    nc_d["n_cases"] = len(nc_d["cases"])
    nc_d["all_fired"] = bool(nc_d["cases"]) and all(
        c["comparator_reports_disagreement"] for c in nc_d["cases"])
    P("")
    P("NC_D comparator known-bad: %d/%d cases reported a disagreement"
      % (sum(1 for c in nc_d["cases"] if c["comparator_reports_disagreement"]),
         nc_d["n_cases"]))
    if not nc_d["all_fired"]:
        P("FAILURE: the comparator did not reject a deliberately wrong "
          "expectation")
        return 5

    # -- NC_B: mutate the live emulator, MRO-resolved ------------------------
    nc_b = {"name": "NC_B_live_emulator_mutation_detected", "cases": []}
    if not args.no_mutations:
        P("")
        P("NC_B: mutating the MRO-resolved handler of the instantiated class")
        for m in MNEMONICS:
            attr = HANDLER_ATTR[m]
            vs = [r["vector"] for r in results if r["vector"]["mnem"] == m]
            rec = mutation_control(R16, probe, core_cls, attr, vs)
            rec["mnemonic"] = m
            nc_b["cases"].append(rec)
            P("   %-22s %-28s owner=%-8s fired=%-5s changed=%2d/%2d"
              % (m, rec.get("shape"), rec.get("patched_class"),
                 rec.get("fired"), rec.get("n_vectors_changed", 0), len(vs)))
    nc_b["n_mnemonics_mutated"] = len(nc_b["cases"])
    nc_b["n_fired"] = sum(1 for c in nc_b["cases"] if c.get("fired"))
    nc_b["n_rejected"] = sum(1 for c in nc_b["cases"]
                             if c.get("mutation_rejected"))
    nc_b["ok"] = nc_b["n_fired"] >= 6 and nc_b["n_rejected"] >= 6
    P("   fired %d/%d ; observation changed %d/%d"
      % (nc_b["n_fired"], nc_b["n_mnemonics_mutated"], nc_b["n_rejected"],
         nc_b["n_mnemonics_mutated"]))

    # -- NC_C ---------------------------------------------------------------
    nc_c = {"name": "NC_C_zero_comparison_run_is_refused",
            "n_comparisons": n_cmp, "refused": n_cmp <= 0, "ok": n_cmp > 0}

    # -- artifact -----------------------------------------------------------
    finalize_write_audit(audit)
    status_counts = collections.Counter(per[m]["status"] for m in MNEMONICS)
    art = {
        "schema": "phase16s-isa-oracle/1",
        "phase": "16S",
        "item": "S1",
        "host_only": True,
        "gpu_execution_performed": False,
        "gta_launched": False,
        "currently_armed": False,
        "what": ("instruction-level independent oracle vectors for the sixteen "
                 "J3 mnemonics that 16R/R11 reported as BLOCKED with reason "
                 "NO_INDEPENDENT_ORACLE_VECTOR_FOR_THIS_MNEMONIC, derived from "
                 "the ISA mathematical definition and measured against the "
                 "live emulator"),
        "supersedes_claim": {
            "artifact": "phase16r/isa/J3_INSTRUCTION_CONFORMANCE.json",
            "J3_INSTRUCTION_SEMANTICS_BLOCKED": 19,
            "of_which_no_independent_oracle_vector": 16,
            "note": ("this artifact supplies oracle vectors for those sixteen; "
                     "the three v_div_* mnemonics (R9) are NOT addressed here"),
        },
        "run": {
            "command": "python phase16s/isa/build_oracle_vectors.py%s"
                       % (" --break-oracle " + args.break_oracle
                          if args.break_oracle else ""),
            "cwd": ROOT, "python": sys.version.split()[0],
            "emulator_sha256_loaded": emu_hash,
            "emulator_sha256_expected": EMU_SHA256,
            "emulator_sha256_asserted": emu_hash == EMU_SHA256,
            "emulator_module_path_asserted": loaded,
            "p14d8_core_sha256": sha256_file(os.path.join(
                ROOT, P14D8_REL.replace("/", os.sep))),
            "isa_text": {"path": ISA_REL, "sha256": isa_hash,
                         "pinned_sha256": ISA_SHA256,
                         "is_the_pinned_text": isa_hash == ISA_SHA256},
            "j3_disassembly": {"path": DISASM_REL, "kernel": j3["kernel"],
                               "lo": "0x%X" % j3["lo"], "hi": "0x%X" % j3["hi"],
                               "n_instruction_lines": j3["n_lines"]},
        },
        "independence": {
            "oracle_module": "phase16s/isa/oracle16.py",
            "oracle_imports": [],
            "imports_the_emulator": False,
            "imports_any_in_tree_oracle": False,
            "reads_emulator_operand_values_as_truth": False,
            "freezes_emulator_output_as_expected": False,
            "fp16_results_by": ("hand-written integer IEEE-754 "
                                "round-to-nearest-even in "
                                "oracle16._round_to_f16 / f16_fma; no native "
                                "float arithmetic is the source of any expected "
                                "binary16 value"),
            "emulator_handler_source_was_read": True,
            "why": ("the handlers in phase8_static/tools/emu.py and "
                    "phase14d8_static/tools/p14d8_core.py were read ONLY to "
                    "learn what semantics are claimed, what the operand tokens "
                    "look like, and which attribute the MRO resolves to for the "
                    "mutation control. No expected value is derived from them; "
                    "every expectation comes from oracle16, which was written "
                    "from phase16r/isa/ref/rdna2_isa.txt and cannot import the "
                    "emulator."),
            "harness": ("phase16s/isa/tools/r11_j3_matrix_16s.py HarnessS1 -- "
                        "the R11 tool's own Harness.probe, subclassed only to "
                        "widen register seeding to all 32 lanes and to add "
                        "`extra` read-backs. NC_E (run by the R11 integration "
                        "tool) measures that both widenings are additive."),
        },
        "n_mnemonics": len(MNEMONICS),
        "n_vectors": len(vectors),
        "n_comparisons": n_cmp,
        "n_vectors_disagreeing": n_dis,
        "status_counts": dict(status_counts),
        "per_mnemonic": per,
        "vectors": [
            {"mnem": r["vector"]["mnem"], "name": r["vector"]["name"],
             "srcs": r["vector"]["srcs"], "dst": r["vector"]["dst"],
             "setup": r["vector"]["setup"], "ops": r["vector"]["ops"],
             "expect": r["vector"]["expect"], "alt": r["vector"]["alt"],
             "note": r["vector"]["note"], "source": r["vector"]["source"],
             "open_reading_flag": r["vector"]["open_reading_flag"],
             "measured": r["obs"], "diffs": r["diffs"],
             "matches_alternate_reading": r["alt_hits"]}
            for r in results],
        "defect_findings": [
            {"mnemonic": m,
             "reading_the_isa_implements_vs_the_emulator":
                 per[m]["defect_reading"],
             "j3_operand_forms": per[m]["j3_operand_forms"],
             "j3_reachability_verdict": per[m]["j3_reachability_verdict"],
             "j3_reachability": per[m]["defect_reachability"],
             "j3_cone": per[m]["j3_cone"],
             "vectors": per[m]["disagreeing_vectors"]}
            for m in defective],
        "open_semantics_only": [m for m in MNEMONICS
                                if per[m]["open_semantics_only"]],
        "negative_controls": {"NC_A": nc_a, "NC_B": nc_b, "NC_C": nc_c,
                              "NC_D": nc_d},
        "write_scope": audit,
        "what_could_not_be_established": [
            "The OPSEL field mapping for V_FMA_MIXLO_F16 / V_FMA_MIXHI_F16: the "
            "text gives `0=src[31:0], 1=src[31:0], 2=src[15:0], 3=src[31:16]`, "
            "where entries 0 and 1 are identical. Every vector fixes OPSEL at "
            "the low half; the J3 sites that print `op_sel_hi:[...]` are NOT "
            "modelled.",
            "Whether bits [31:16] of a 16-bit-result destination are preserved "
            "or zeroed for the B16 ALU ops and V_CVT_F16_F32: the ISA states "
            "this for V_MAD_U16 only, and the measurement reports which reading "
            "the emulator implements rather than resolving the text.",
            "NaN sign and payload propagation for V_CVT_F16_F32 and the "
            "FMA_MIX mnemonics; only the declared readings are compared.",
            "Whether the carry-out register of the VOP3B forms is written in "
            "EXEC-clear lanes.",
            "Whether a wrong value from any of these instructions actually "
            "reaches a global store on the J3 path: the 16R cone is a "
            "lane-collapsed over-approximation, so 'in the cone' is an upper "
            "bound, not a trace of one value to one store.",
            "Anything about real hardware: this is a host-only measurement of a "
            "Python emulator and says nothing about gfx1030 silicon.",
        ],
    }

    out_json = os.path.join(HERE, "ISA_ORACLE_16.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(art, f, indent=1, sort_keys=False)
        f.write("\n")
    P("")
    P("wrote %s" % out_json)

    # -- read back and check properties fixed before the read-back ----------
    back = json.load(open(out_json, encoding="utf-8"))
    checks = {
        "vector_count_matches": len(back["vectors"]) == len(vectors),
        "comparison_count_nonzero": back["n_comparisons"] > 0,
        "per_mnemonic_covers_16": len(back["per_mnemonic"]) == 16,
        "every_vector_has_a_measurement":
            all("measured" in v for v in back["vectors"]),
        "nc_d_fired": back["negative_controls"]["NC_D"]["all_fired"],
        "nc_c_ok": back["negative_controls"]["NC_C"]["ok"],
        "emu_hash_pinned": back["run"]["emulator_sha256_asserted"],
        "host_only": back["host_only"] is True,
        "gpu_execution_performed_false":
            back["gpu_execution_performed"] is False,
        "every_defect_has_a_stated_reading":
            all(d.get("reading_the_isa_implements_vs_the_emulator")
                for d in back["defect_findings"]),
        "all_sixteen_have_a_j3_sample":
            all(back["per_mnemonic"][m]["j3_sample"] for m in MNEMONICS),
    }
    if not args.no_mutations:
        checks["nc_b_at_least_6_rejected"] = (
            back["negative_controls"]["NC_B"]["n_rejected"] >= 6)
    checks["nc_a_changed"] = back["negative_controls"]["NC_A"]["changed"]
    P("read-back checks: %s" % json.dumps(checks))
    if not all(checks.values()):
        P("READ-BACK CHECK FAILED")
        return 6

    write_md(art, checks)
    P("")
    P("VERDICT: %s" % verdict(art))
    return 0


HANDLER_ATTR = {
    "s_mov_b64": "op_s_mov_b64",
    "v_add_co_u32": "op_v_add_co_u32",
    "v_add_co_ci_u32_e64": "op_v_add_co_ci_u32",
    "v_cmp_gt_i32_e64": "_cmp_dispatch",
    "v_cmp_gt_u32_e64": "_cmp_dispatch",
    "v_cmp_lt_i32_e64": "_cmp_dispatch",
    "v_lshlrev_b16": "op_v_lshlrev_b16",
    "v_lshrrev_b16": "op_v_lshrrev_b16",
    "v_min_u32_e32": "op_v_min_u32",
    "v_mul_lo_u16": "op_v_mul_lo_u16",
    "v_mul_u32_u24_e32": "op_v_mul_u32_u24",
    "v_pack_b32_f16": "op_v_pack_b32_f16",
    "v_sub_nc_u16": "op_v_sub_nc_u16",
    "v_cvt_f16_f32_e32": "op_v_cvt_f16_f32",
    "v_fma_mixlo_f16": "op_v_fma_mixlo_f16",
    "v_fma_mixhi_f16": "op_v_fma_mixhi_f16",
}


def obs_field_diffs(a, b):
    fields = set()
    for k in ("error", "value", "scc", "exec"):
        if a.get(k) != b.get(k):
            fields.add(k)
    for k in set(list((a.get("extra") or {}).keys())
                + list((b.get("extra") or {}).keys())):
        if (a.get("extra") or {}).get(k) != (b.get("extra") or {}).get(k):
            fields.add("extra." + k)
    return sorted(fields)


def mutation_control(R16, probe, core_cls, attr, vectors):
    """Patch the MRO-resolved handler, prove the patch fired, measure the delta.

    Uses the shape list the S1 suite defines (the 16R shapes are written for a
    handler signature this matrix does not have), and takes the first shape
    that both fires and changes an observation.  A shape that changes nothing
    is recorded as such and is not evidence.
    """
    R = R16
    owner, orig = R.resolve_attr(core_cls, attr)
    if owner is None or not callable(orig):
        return {"attr": attr, "error": "handler did not resolve on "
                + core_cls.__name__}
    raw = getattr(orig, "__func__", orig)
    base = [probe(v) for v in vectors]
    last = None
    for shape_name, shape in R.S1_MUTATION_SHAPES:
        calls = {"n": 0}

        def counting(fn):
            def h(*a, **k):
                calls["n"] += 1
                return fn(*a, **k)
            return h

        wrapped = shape(counting(raw))
        setattr(owner, attr, wrapped)
        try:
            _, now = R.resolve_attr(core_cls, attr)
            resolves = getattr(now, "__func__", now) is wrapped
        except Exception:                                        # noqa: BLE001
            resolves = None
        try:
            after = [probe(v) for v in vectors]
        finally:
            setattr(owner, attr, orig)
        changed = [i for i, (x, y) in enumerate(zip(base, after)) if x != y]
        fields = sorted({f for i in changed
                         for f in obs_field_diffs(base[i], after[i])})
        last = {"attr": attr, "patched_class": owner.__name__,
                "patched_is_mro_owner": True,
                "attr_resolves_to_patched": resolves, "shape": shape_name,
                "invocations_measured": calls["n"], "fired": bool(calls["n"]),
                "n_vectors_changed": len(changed),
                "vectors_changed": [vectors[i]["name"] for i in changed][:6],
                "changed_fields": fields,
                "mutation_rejected": bool(calls["n"] and changed)}
        if last["mutation_rejected"]:
            return last
    return last


def j3_reachability(mnem, forms, trace):
    """Whether the J3 path can reach THIS defect, from recorded evidence only.

    The emulator builds its `operands` string from the module's disassembly, so
    an executed instance MUST be one of the operand strings that disassembly
    prints -- which makes "no on-disk form can trigger it" a sound
    NOT_REACHED.  Where the trigger depends on run-time VALUES rather than on
    the operand shape, the tree holds no per-instruction value trace for J3 and
    this reports NOT_ESTABLISHED rather than guessing.
    """
    n_forms = forms["n_distinct_forms_in_the_j3_module"]
    faults = trace.get("faults")
    base = {
        "j3_executed_count": trace.get("executed_count_on_j3_path"),
        "n_distinct_operand_forms_in_the_j3_module": n_forms,
        "emulator_operand_strings_are_the_disassembly_text": DISASM_REL,
        "j3_run_outcome": trace.get("outcome"),
        "j3_run_faults": faults,
        "j3_run_natural_end": trace.get("natural_end"),
        "j3_run_gate": trace.get("gate"),
        "how_the_forms_were_obtained":
            "every instruction line of the J3 kernel inside its own address "
            "range in " + DISASM_REL + ", deduplicated by text",
    }
    if mnem == "v_add_co_ci_u32_e64":
        base.update({
            "verdict": "NOT_REACHED_ON_THE_J3_PATH",
            "argument": (
                "The defect fires only when operand 2 (the VOP3B scalar "
                "destination) names a register other than `null`/`vcc_lo`. All "
                "%d distinct operand strings this module prints for this "
                "mnemonic pass `null` (%s of them name a real scalar "
                "destination). The emulator's operand string IS this "
                "disassembly text, so no executable instance of this mnemonic "
                "in this module can trigger the drop: the defect is real, "
                "measured, and LATENT." % (
                    n_forms, forms["n_forms_with_a_non_null_non_vcc_scalar_"
                                   "destination"])),
        })
    elif mnem == "v_pack_b32_f16":
        base.update({
            "verdict": "NOT_ESTABLISHED (half-swap) / NOT_REACHED (float "
                       "literal)",
            "argument": (
                "TWO sub-defects with different reachability. (a) HALF SWAP: "
                "fires when the two source halves differ in VALUE, which is "
                "run-time state; %d of the %d on-disk forms have differing "
                "source TOKENS, so the swap is not structurally excluded, but "
                "whether the values differed on J3 is not decidable from the "
                "recorded evidence -> NOT_ESTABLISHED. (b) FLOAT LITERAL: %d "
                "on-disk form(s) pass a float literal. That form RAISES in the "
                "emulator, and the J3 run recorded outcome=%s, faults=%s, "
                "natural_end=%s, gate=%s -- a raised operand error would have "
                "appeared there. So that form did NOT execute on J3 -> "
                "NOT_REACHED (with the caveat that this project has measured "
                "the wave harness's ALL_ENDED to be fail-open, so the "
                "no-fault record is read together with `natural_end` and the "
                "empty fault list)." % (
                    forms["n_forms_whose_two_source_tokens_differ"], n_forms,
                    forms["n_forms_with_a_float_literal_operand"],
                    trace.get("outcome"), faults, trace.get("natural_end"),
                    trace.get("gate"))),
        })
    elif mnem == "v_cvt_f16_f32_e32":
        base.update({
            "verdict": "NOT_ESTABLISHED (value-driven) / NOT_REACHED (input "
                       "modifier)",
            "argument": (
                "The sign, subnormal-flush and clamp sub-defects are driven by "
                "the VALUE being converted, not by the operand shape: any "
                "input whose bit 16 is set or whose magnitude is subnormal "
                "triggers them. This mnemonic executes %s times on the J3 path "
                "over %d distinct on-disk forms, so the trigger is structurally "
                "available, but the tree holds no per-instruction J3 VALUE "
                "trace that would show whether a triggering value occurred -> "
                "NOT_ESTABLISHED. The `-vN` input-modifier sub-defect IS "
                "shape-driven: %d of the %d on-disk forms carry an input "
                "modifier token, so on this evidence that sub-defect is %s." % (
                    trace.get("executed_count_on_j3_path"), n_forms,
                    forms["n_forms_with_an_input_modifier_token"], n_forms,
                    "NOT_REACHED on the J3 path"
                    if forms["n_forms_with_an_input_modifier_token"] == 0
                    else "REACHABLE on the J3 path")),
        })
    elif mnem in ("v_fma_mixlo_f16", "v_fma_mixhi_f16"):
        base.update({
            "verdict": "REACHABLE_ON_THE_J3_PATH",
            "argument": (
                "The divergence is UNCONDITIONAL: on every execution the "
                "handler decodes each source's full 32-bit register as an f32 "
                "value, evaluates in f32, and writes the 32-bit f32 result "
                "over the whole destination. There is no operand shape or "
                "value for which this handler implements the ISA's FP16 "
                "operand width and half placement, so any one of the %s J3 "
                "executions is a triggering execution -> REACHABLE." % (
                    trace.get("executed_count_on_j3_path"))),
        })
    else:
        base.update({"verdict": "NOT_APPLICABLE",
                     "argument": "this mnemonic has no measured disagreement"})
    return base


def verdict(art):
    sc = art["status_counts"]
    if sc.get("DISAGREES"):
        return "MEASURED_DISAGREEMENTS_IN_%d_OF_16" % sc["DISAGREES"]
    if sc.get("NO_J3_SAMPLE"):
        return "NO_J3_SAMPLE_FOR_%d" % sc["NO_J3_SAMPLE"]
    if sc.get("OPEN_SEMANTICS"):
        return "OPEN_SEMANTICS_ONLY"
    return "ALL_16_VERIFIED_INDEPENDENTLY"


def _compact(setup_hex):
    """Render a setup dict compactly: a value broadcast to every lane is shown
    once with `x32` rather than spelled out thirty-two times."""
    out = {}
    for k, v in sorted(setup_hex.items()):
        if isinstance(v, list) and len(v) == 32:
            if len(set(v)) == 1:
                out[k] = "%s x32" % v[0]
            else:
                out[k] = "%s ... (%d lanes, %d distinct)" % (
                    v[0], len(v), len(set(v)))
        else:
            out[k] = v
    return out


def _hx(x, wide=False):
    if x is None:
        return "None"
    if not isinstance(x, int):
        return str(x)
    return h64(x) if wide else h32(x)


def write_md(art, checks):
    L = []
    A = L.append
    A("# phase16s/isa — ISA_ORACLE_16")
    A("")
    A("Phase 16S item S1. **Host only: no GPU, no HIP, no game, nothing armed "
      "or deployed.** Every number below was measured in the run whose command "
      "is in the artifact's `run` block; the JSON was read back afterwards and "
      "checked against properties fixed before the read-back.")
    A("")
    A("## What this is")
    A("")
    A("`phase16r/isa/J3_INSTRUCTION_CONFORMANCE.json` reports "
      "`J3_INSTRUCTION_SEMANTICS_BLOCKED = 19`, of which sixteen are blocked "
      "with `NO_INDEPENDENT_ORACLE_VECTOR_FOR_THIS_MNEMONIC`. This artifact "
      "supplies instruction-level oracle vectors for those sixteen, derives "
      "every expected value from the ISA mathematical definition through an "
      "independent model (`oracle16.py`, which imports nothing), and measures "
      "the live emulator against it. The three `v_div_*` mnemonics (R9) are "
      "**not** addressed here.")
    A("")
    A("## Result")
    A("")
    A("| | |")
    A("|---|---|")
    A("| verdict | **%s** |" % verdict(art))
    A("| vectors | %d |" % art["n_vectors"])
    A("| comparisons (field-level) | **%d** |" % art["n_comparisons"])
    A("| vectors disagreeing | %d |" % art["n_vectors_disagreeing"])
    for k in sorted(art["status_counts"]):
        A("| status %s | %d |" % (k, art["status_counts"][k]))
    A("| emulator loaded | `%s` |" % art["run"]["emulator_sha256_loaded"])
    A("")
    A("## Per mnemonic")
    A("")
    A("| mnemonic | status | vectors | comparisons | disagreements | "
      "unexplained | J3 execs | value-cone nodes |")
    A("|---|---|---|---|---|---|---|---|")
    for m in MNEMONICS:
        r = art["per_mnemonic"][m]
        A("| `%s` | %s | %d | %d | %d | %d | %s | %d |"
          % (m, r["status"], r["vector_count"], r["comparisons"],
             r["disagreement_count"], r["unexplained_disagreement_count"],
             r["j3_cone"]["executed_count_on_j3_path"],
             r["j3_cone"]["nodes_in_value_cone"] or 0))
    A("")
    if art["defect_findings"]:
        A("## Defect findings")
        A("")
        A("Each entry states, for the mnemonic: the exact input vectors in hex, "
          "the oracle's expected destination, the live emulator's measured "
          "destination, **the reading each side implements**, and the J3 "
          "reachability of the disagreement. Nothing here is a paraphrase: the "
          "expected values come from `oracle16.py` and the measured values are "
          "read back from the emulator by the R11 tool's own `Harness.probe`.")
        A("")
        for d in art["defect_findings"]:
            A("### `%s`" % d["mnemonic"])
            A("")
            A("**Reading each side implements.**")
            A("")
            readings = d["reading_the_isa_implements_vs_the_emulator"]
            if isinstance(readings, str):
                readings = [readings]
            for s in readings:
                A("- %s" % s)
            A("")
            if d.get("j3_operand_forms"):
                f = d["j3_operand_forms"]
                if f.get("second_operand_token_counts"):
                    A("**J3 operand forms (static, from the J3 kernel's own "
                      "disassembly).** %d distinct form(s); second-operand "
                      "(scalar-destination) token counts: `%s` -- %d of them "
                      "name a real scalar destination rather than `null` or "
                      "`vcc_lo`."
                      % (f["n_distinct_forms_in_the_j3_module"],
                         json.dumps(f["second_operand_token_counts"]),
                         f["n_forms_with_a_non_null_non_vcc_scalar_destination"]))
                else:
                    A("**J3 operand forms (static, from the J3 kernel's own "
                      "disassembly).** %d distinct form(s); %s"
                      % (f["n_distinct_forms_in_the_j3_module"],
                         f.get("note", "")))
                A("")
            rv = d.get("j3_reachability_verdict") or {}
            A("**Can J3 reach this defect? — `%s`**" % rv.get("verdict"))
            A("")
            A("%s" % rv.get("argument"))
            A("")
            A("**J3 reachability (cone).** executions on the J3 path: `%s`; "
              "value-cone nodes `%s`; union-cone nodes `%s`; contributes to "
              "written bytes: `%s`.  %s"
              % (d["j3_cone"]["executed_count_on_j3_path"],
                 d["j3_cone"]["nodes_in_value_cone"],
                 d["j3_cone"]["nodes_in_union_cone"],
                 d["j3_cone"]["contributes_to_written_bytes"],
                 d["j3_reachability"]["statement"]))
            A("")
            for v in d["vectors"]:
                A("- **%s** — `%s %s`" % (v["name"], v["mnem"],
                                          ", ".join(v["ops"])))
                A("  - setup (raw 32-bit register contents): `%s`"
                  % json.dumps(_compact(v["setup_hex"])))
                A("  - oracle expected destination `%s`: `%s`"
                  % (v["dst"], v["expect_hex"]["value"]))
                A("  - live emulator measured: `%s`"
                  % v["measured_hex"]["value"])
                for f in v["diffs"]:
                    A("  - differing field `%s`: oracle `%s`, emulator `%s`"
                      % (f["field"], f["oracle"], f["emulator"]))
                if v["alt"]:
                    A("  - admissible alternate readings measured on the same "
                      "vector: `%s`"
                      % ", ".join("%s=%s" % (k, _hx(x) if not isinstance(x, dict)
                                             else json.dumps(x))
                                  for k, x in v["alt"].items()))
                if v["matches_alternate_reading"]:
                    A("  - the emulator's value matches the alternate "
                      "reading(s): %s"
                      % ", ".join(v["matches_alternate_reading"]))
                A("  - source: %s" % v["source"])
                A("  - note: %s" % v["note"])
                A("")
    if art["open_semantics_only"]:
        A("## Mnemonics whose disagreements are explained by an admissible "
          "alternate reading (OPEN SEMANTICS)")
        A("")
        for m in art["open_semantics_only"]:
            A("- `%s`" % m)
        A("")
    A("## Negative controls")
    A("")
    nb = art["negative_controls"]["NC_B"]
    A("- **NC_A** — the oracle's own self-test can fail: %s"
      % json.dumps({k: v for k, v in art["negative_controls"]["NC_A"].items()
                    if k != "what"}))
    A("- **NC_B** — a mutation of the live emulator handler is detected: "
      "%d/%d mnemonics fired, %d/%d changed an observation."
      % (nb["n_fired"], nb["n_mnemonics_mutated"], nb["n_rejected"],
         nb["n_mnemonics_mutated"]))
    A("- **NC_C** — a zero-comparison run is refused: n_comparisons = %d, "
      "refused = %s" % (art["negative_controls"]["NC_C"]["n_comparisons"],
                        art["negative_controls"]["NC_C"]["refused"]))
    A("- **NC_D** — the comparator rejects an expectation with one bit flipped: "
      "%d/%d cases"
      % (sum(1 for c in art["negative_controls"]["NC_D"]["cases"]
             if c["comparator_reports_disagreement"]),
         art["negative_controls"]["NC_D"]["n_cases"]))
    A("")
    A("### NC_B detail")
    A("")
    A("| mnemonic | handler | owner | shape | fired | invocations | vectors "
      "changed | changed fields |")
    A("|---|---|---|---|---|---|---|---|")
    for c in nb["cases"]:
        A("| `%s` | `%s` | %s | %s | %s | %s | %d | %s |"
          % (c["mnemonic"], c.get("attr"), c.get("patched_class"),
             c.get("shape"), c.get("fired"), c.get("invocations_measured"),
             c.get("n_vectors_changed", 0), ",".join(c.get("changed_fields")
                                                     or [])))
    A("")
    A("## What could not be established")
    A("")
    for s in art["what_could_not_be_established"]:
        A("- %s" % s)
    A("")
    A("## Open questions recorded per mnemonic")
    A("")
    for m in MNEMONICS:
        qs = [q for q in art["per_mnemonic"][m]["open_questions"]
              if "No semantic ambiguity" not in q]
        if qs:
            A("- `%s`: %s" % (m, " ".join(qs)))
    A("")
    A("## Read-back checks")
    A("")
    for k, v in checks.items():
        A("- `%s`: %s" % (k, v))
    A("")
    A("## MEASURED vs INFERRED vs DECLARED")
    A("")
    A("- **MEASURED** — every count, every comparison, every differing field, "
      "the emulator sha256 and module path, the mutation invocation counts and "
      "observation deltas, the NC results.")
    A("- **INFERRED** — that the J3 kernel's disassembly range covers the "
      "operand shapes J3 executed (the samples are the module's own text inside "
      "the kernel's address range, which also contains the recorded store-site "
      "PCs); and that cone membership bounds the output path.")
    A("- **DECLARED** — every reading the ISA text does not state: the "
      "untouched half of a 16-bit destination, NaN propagation, the sign of an "
      "exact-zero FMA result, the value of a mask register in EXEC-clear lanes, "
      "the carry-in source token. Each appears under Open questions and each "
      "carries an alternate reading in the JSON, so the measurement -- not the "
      "oracle -- decides which one the emulator implements.")
    A("- **NOT CLAIMED** — nothing about real gfx1030 hardware. A disagreement "
      "here is a disagreement between two host-side models.")
    A("")
    with open(os.path.join(HERE, "ISA_ORACLE_16.md"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(L).rstrip() + "\n")
    P("wrote %s" % os.path.join(HERE, "ISA_ORACLE_16.md"))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:                                            # noqa: BLE001
        traceback.print_exc()
        sys.exit(2)
