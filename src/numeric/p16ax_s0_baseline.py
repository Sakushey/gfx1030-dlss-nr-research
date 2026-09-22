#!/usr/bin/env python3
"""Phase 16AX / T-NUMERIC -- STEP 0: reproduce the existing baseline.

Nothing is changed before this script passes.  It reproduces, from the bytes on
disk in THIS session:

  1. the 39-case adversarial corpus, through the 16AW driver's OWN code with
     its output redirected into this worker's directory -- so the corpus is
     re-run rather than re-read.  Required: 35 agree / 0 disagree / 4
     BOTH_VOID, and BOTH_VOID never counted as agreement.
  2. the NF-1 finding, re-derived from the frozen object's own .text by an
     independent parser and an independent register-chain resolver.
  3. the audit's counterexample (binary64 0.001953125 vs binary32 0.0).

Every digest is recomputed here.  A baseline that does not reproduce is a STOP.

Host-only.  No HIP call, no GPU, no launch, no slot.
"""
from __future__ import annotations

import json
import os
import shutil
import struct
import sys
from fractions import Fraction as Q

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "..", "p16aw",
                                "numeric"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)),
                                "p16aw", "numeric"))

import p16ax_common as C  # noqa: E402

AW = C.P16AW_NUMERIC
OUT = os.path.join(HERE, "STEP0_BASELINE_REPRODUCTION_16AX.json")
WORK = os.path.join(HERE, "_work")


def main() -> int:
    os.makedirs(WORK, exist_ok=True)
    rep = C.Report("Phase 16AX T-NUMERIC -- STEP 0 baseline reproduction")
    doc = {"schema": "p16ax/numeric/step0-baseline/1", "phase": "16AX",
           "worker": "W2", "task_id": "T-NUMERIC",
           "gpu_calls": 0, "host_only": True,
           "what_this_establishes":
               "the 16AW baseline this worker was told to reproduce does "
               "reproduce, measured here rather than inherited"}

    # ---- 0. the inputs, hashed from bytes --------------------------------
    inputs = {}
    for k, p in (("frozen_slot5_object", C.FROZEN_CO),
                 ("native_source", C.NATIVE_SRC),
                 ("native_header", C.NATIVE_HDR),
                 ("A_16AW_rn32", C.A_16AW),
                 ("B_16AW_independent", C.B_16AW),
                 ("A_16AR", C.A_16AR),
                 ("B_16AR", C.B_16AR),
                 ("upstream_pinned_c64_reference", C.UPSTREAM_REF),
                 ("upstream_pinned_c32_reference", C.UPSTREAM_C32),
                 ("pinning_16AR", C.PINNING_16AR),
                 ("NATIVE_EMITTED_MATH_16AW", os.path.join(
                     AW, "NATIVE_EMITTED_MATH_16AW.json")),
                 ("NUMERICAL_CONTRACT_16AW", os.path.join(
                     AW, "NUMERICAL_CONTRACT_16AW.json")),
                 ("ADVERSARIAL_CORPUS_16AW", os.path.join(
                     AW, "ADVERSARIAL_CORPUS_16AW.json")),
                 ("AUDIT_COUNTEREXAMPLE_REPRODUCTION_16AW", os.path.join(
                     AW, "AUDIT_COUNTEREXAMPLE_REPRODUCTION_16AW.json")),
                 ("CPU_REFERENCE_REPAIR_16AW", os.path.join(
                     AW, "CPU_REFERENCE_REPAIR_16AW.json"))):
        if not os.path.exists(p):
            rep.row("input %s is readable" % k, False, 0, {"path": p})
            doc["verdict"] = "STOP: an input is missing"
            _write(doc, rep)
            return 1
        inputs[k] = C.file_record(p)
    doc["step_0_inputs_hashed_from_bytes"] = inputs
    rep.row("every declared input exists and was hashed from its bytes",
            len(inputs) == 15, len(inputs),
            {"n": len(inputs)})

    # the frozen object must still be the object the brief names
    frozen_ok = (inputs["frozen_slot5_object"]["sha256"]
                 == "24f53bd0f621215c232c782444e7aa364d0e57622b1fd9360e78efdb"
                    "43572224")
    rep.row("the frozen Slot-5 object's SHA-256 is the one the brief names",
            frozen_ok, 1,
            {"sha256": inputs["frozen_slot5_object"]["sha256"]})

    # ---- 1. the 39-case corpus, re-run through the 16AW driver -----------
    import p16aw_s3_corpus as S3  # noqa: E402
    redir = os.path.join(WORK, "ADVERSARIAL_CORPUS_16AX_RERUN.json")
    S3.OUT = redir                       # redirect, never write into p16aw
    # The corpus costs ~11 minutes of exact-rational arithmetic.  It was run
    # ONCE in this session; a re-invocation reuses that measured output and
    # says so, with the file's own digest, rather than re-running and calling
    # the second reading independent of the first.
    if os.path.exists(redir) and os.environ.get("P16AX_RERUN_CORPUS") != "1":
        rc = 0
        cached = True
    else:
        rc = S3.main()
        cached = False
    rerun = json.load(open(redir, encoding="utf-8"))
    recorded = json.load(open(os.path.join(AW, "ADVERSARIAL_CORPUS_16AW.json"),
                              encoding="utf-8"))
    doc["step_1_corpus_rerun"] = {
        "driver": "p16aw/numeric/p16aw_s3_corpus.py (IMPORTED and re-run "
                  "with its output path redirected into this worker's "
                  "directory; the frozen 16AW file is not written to)",
        "driver_sha256": C.sha256_file(os.path.join(AW, "p16aw_s3_corpus.py")),
        "exit_code": rc,
        "rerun_file": C.file_record(redir),
        "reused_the_session_run_rather_than_rerunning": cached,
        "classification_observer":
            "fp8_byte_channel_0 -- the SAME observer p16aw/numeric/"
            "p16aw_s3_corpus.py::main() classifies on.  An earlier revision of "
            "this check read fused_channel_0, which never raises (the refusal "
            "is raised by the ENCODER, one level later), so it reported a "
            "BOTH_VOID case as 'a side returned a value'.  The check failed, "
            "which is how the wrong observer was found; the level is now "
            "named rather than assumed.",
        "summary": rerun["summary"],
    }
    s = rerun["summary"]["A_16AW_vs_B_16AW"]
    rep.row("the 39-case corpus reproduces 35 agree / 0 disagree / 4 BOTH_VOID",
            (rerun["n_cases"] == 39 and s["agree"] == 35
             and s["disagree"] == 0 and s["both_void"] == 4
             and s["one_void"] == 0),
            rerun["n_cases"],
            {"n_cases": rerun["n_cases"], "summary": s})

    # per-case value-for-value equality with the 16AW record, not just totals
    diffs = []
    for a, b in zip(recorded["cases"], rerun["cases"]):
        if a["case_id"] != b["case_id"]:
            diffs.append({"why": "case order", "a": a["case_id"],
                          "b": b["case_id"]})
            continue
        for mod in ("A_16AR", "A_16AW", "B_16AW", "B_16AR",
                    "third_route_oracle"):
            if a["measured"].get(mod) != b["measured"].get(mod):
                diffs.append({"case": a["case_id"], "module": mod,
                              "16AW": a["measured"].get(mod),
                              "16AX": b["measured"].get(mod)})
        if (a["classification_A_16AW_vs_B_16AW"]
                != b["classification_A_16AW_vs_B_16AW"]):
            diffs.append({"case": a["case_id"], "why": "classification"})
    n_rec = sum(len(c["measured"]) for c in recorded["cases"])
    rep.row("every recorded PER-CASE VALUE reproduces (matching totals are not "
            "equivalence)", len(diffs) == 0, n_rec,
            {"n_case_module_blocks_compared": n_rec,
             "n_differences": len(diffs), "differences": diffs[:6]})

    # BOTH_VOID must never be counted as agreement -- control a mutant
    void_cases = [c["case_id"] for c in rerun["cases"]
                  if c["classification_A_16AW_vs_B_16AW"] == "BOTH_VOID"]
    ra = [c for c in rerun["cases"]
          if c["classification_A_16AW_vs_B_16AW"] == "BOTH_VOID"
          and not (str(c["measured"]["A_16AW"]["fp8_byte_channel_0"]).
                   startswith("RAISED")
                   and str(c["measured"]["B_16AW"]["fp8_byte_channel_0"]).
                   startswith("RAISED"))]
    rep.row("every BOTH_VOID case really is two REFUSALS, and a classifier "
            "that would call them agreement is rejected",
            len(void_cases) == 4 and len(ra) == 0 and
            S3.classify_stringly("RAISED X", "RAISED X") == "AGREE"
            and S3.classify("RAISED X", "RAISED X") == "BOTH_VOID",
            len(void_cases),
            {"both_void_cases": void_cases,
             "cases_where_a_side_returned_a_value": ra,
             "mutant_classifier_on_two_identical_refusals":
                 S3.classify_stringly("RAISED X", "RAISED X"),
             "the_verifier_of_record_on_the_same_input":
                 S3.classify("RAISED X", "RAISED X")})
    doc["step_1_corpus_rerun"]["per_case_differences"] = diffs
    doc["step_1_corpus_rerun"]["both_void_cases"] = void_cases

    # ---- 2. NF-1 re-derived from the object's own .text ------------------
    subj = os.path.join(WORK, "subject_copy.co")
    shutil.copyfile(C.FROZEN_CO, subj)
    before = C.sha256_file(C.FROZEN_CO)
    ins, _o, _e, rc2 = C.disassemble(subj)
    after = C.sha256_file(C.FROZEN_CO)
    cen = C.census(ins)
    be = C.back_edges(ins)
    be_unsigned = C.back_edges(ins, use_unsigned=True, from_displacement=True)
    be_disp = C.back_edges(ins, from_displacement=True)
    outer = max(be, key=lambda b: b["from"] - b["to"])
    inner = [b for b in be if b is not outer]
    tail_lo = max(b["from"] for b in inner)
    mixlo = [i for i in ins if C.opcode_of(i["text"]) == "v_fma_mixlo_f16"]
    tail_hi = mixlo[0]["addr"]
    chains = C.resolve_fold_chains(ins, tail_lo, tail_hi)
    chains_wrong = C.resolve_fold_chains(ins, tail_lo, tail_hi,
                                         wrong_src_control=True)
    n_add16 = len(C.add16_in(ins, tail_lo, tail_hi))
    zero_moves = C.add_f32_with_zero_src(ins, tail_lo, tail_hi)

    doc["step_2_nf1_from_text"] = {
        "subject": C.file_record(subj),
        "sha256_of_the_frozen_object_before_and_after": [before, after],
        "the_frozen_object_was_not_the_file_disassembled_here":
            os.path.relpath(subj, C.ROOT).replace("\\", "/"),
        "byte_identical_copy": before == C.sha256_file(subj),
        "disassembler": C.OBJDUMP,
        "command": "llvm-objdump -d --arch-name=amdgcn --mcpu=gfx1030 <copy>",
        "n_instructions": len(ins),
        "n_back_edges": len(be),
        "outer_loop": {"from": "0x%x" % outer["from"],
                       "to": "0x%x" % outer["to"]},
        "n_inner_loops": len(inner),
        "tail_region": {"from": "0x%x" % tail_lo, "to": "0x%x" % tail_hi,
                        "instructions": chains["n_in_window"]},
        "counts_in_tail": {
            "v_cvt_f32_f16_e32": chains["n_cvt_f32_f16_e32"],
            "v_add_f32_e32": chains["n_v_add_f32_e32"],
            "v_cvt_f16_f32_e32": chains["n_cvt_f16_f32_e32"],
            "v_add_f16_e32": n_add16},
        "n_chains_two_roundings": chains["n_chains"],
        "n_steps_one_rounding": n_add16,
        "n_fold_steps": chains["n_chains"] + n_add16,
        "fold_steps_equal_chunk_sums_minus_one":
            (chains["n_chains"] + n_add16) == len(inner) - 1,
        "n_seed_conversions": chains["n_cvt_f16_f32_e32"]
                              - chains["n_chains"],
        "add_zero_moves": [{"address": "0x%x" % z["addr"],
                            "text": z["text"]} for z in zero_moves],
        "chain_examples": chains["chains"][:4],
        "chunk_sums_from_the_16AW_record": 32,
    }
    rep.row("the object's own .text re-derives 28 two-rounding fold steps and "
            "3 one-rounding steps, in 31 = 32 - 1 steps",
            (chains["n_chains"] == 28 and n_add16 == 3
             and chains["n_chains"] + n_add16 == 31 and len(be) == 33
             and len(inner) == 32),
            chains["n_in_window"],
            {"chains": chains["n_chains"], "add16": n_add16,
             "steps": chains["n_chains"] + n_add16})
    rep.row("CONTROL: the same chain search resolves NOTHING when the round-"
            "back is asked to read a register that does not exist",
            chains_wrong["n_chains"] == 0, chains["n_chains"],
            {"resolved": chains_wrong["n_chains"]})
    rep.row("CONTROL: the branch decoder's sign handling is load-bearing -- the "
            "same branches read as UNSIGNED are not back edges",
            len(be_unsigned) == 0 and len(be_disp) == len(be) == 33,
            len(be_disp),
            {"signed": len(be_disp), "unsigned": len(be_unsigned)})
    rep.row("the disassembler READ the frozen object and changed no byte",
            before == after, 2, {"before": before, "after": after})
    rep.row("the census reproduces the 16AW record's opcode counts",
            (cen.get("v_cvt_f32_f16_e32") == 28
             and cen.get("v_add_f32_e32") == 32
             and cen.get("v_cvt_f16_f32_e32") == 32
             and cen.get("v_add_f16_e32") == 3
             and cen.get("v_fma_mix_f32") == 128
             and cen.get("v_fma_mixlo_f16") == 4),
            6, {k: cen.get(k) for k in
                ("v_cvt_f32_f16_e32", "v_add_f32_e32", "v_cvt_f16_f32_e32",
                 "v_add_f16_e32", "v_fma_mix_f32", "v_fma_mixlo_f16")})

    # ---- 2b. the NF-1 witness, re-derived here ---------------------------
    acc = Q(1.0009765625)
    term = Q(1) + Q(2) ** -23
    exact = acc + term
    f32 = C.rn32(exact)
    one = C.rn16(exact)
    two = C.rn16(f32)
    host_emitted = C.host_rn16_or_none(C.host_rn32_or_none(exact))
    doc["step_2b_nf1_witness"] = {
        "accumulator_as_number": float(acc),
        "accumulator_bits": "0x%04X" % C.float_to_f16_bits(float(acc)),
        "accumulator_is_a_binary16_value": C.is_binary16_value(acc),
        "term_as_number": float(term),
        "term_bits_as_binary32": "0x%08X" % int.from_bytes(
            struct.pack("<f", float(term)), "little"),
        "term_bits_as_binary16_nearest":
            "0x%04X" % C.float_to_f16_bits(float(term)),
        "term_is_a_binary16_value": C.is_binary16_value(term),
        "term_is_exactly_a_binary32_value": C.host_rn32_or_none(term) == term,
        "exact_sum": float(exact),
        "binary32_intermediate": float(f32),
        "one_rounding_declared": float(one),
        "two_rounding_emitted": float(two),
        "the_two_shapes_disagree_on_this_pair": float(one) != float(two),
        "second_mechanism_host_emitted_route": (
            None if host_emitted is None
            else {"kind": host_emitted[0],
                  "value": (float(host_emitted[1])
                            if host_emitted[0] == "value" else None)}),
    }
    rep.row("the published NF-1 witness reproduces (declared 2.001953125, "
            "emitted 2.0)",
            (float(one) == 2.001953125 and float(two) == 2.0
             and C.is_binary16_value(acc) and not C.is_binary16_value(term)),
            4, doc["step_2b_nf1_witness"])
    rep.row("the witness is PRECONDITION-VALID: the accumulator is exactly a "
            "binary16 value and the term is exactly a binary32 value",
            C.is_binary16_value(acc)
            and C.host_rn32_or_none(term) == term,
            2, {"accumulator_is_f16": C.is_binary16_value(acc),
                "term_is_exactly_f32":
                    C.host_rn32_or_none(term) == term})
    rep.row("the two exact routes agree, and a second mechanism (host struct) "
            "reproduces the emitted value",
            host_emitted is not None and host_emitted[1] == two, 1,
            {"host_emitted": None if host_emitted is None
             else float(host_emitted[1]), "exact_emitted": float(two)})

    # ---- 2c. which SHAPE each reference actually implements --------------
    # This is the measurement the 39-case corpus cannot make: every corpus
    # case occupies ONE chunk, so its only chunk boundary has acc = 0 and both
    # shapes return H(s).  Here the boundary shape is read directly.
    AN2 = C.load_by_path("AN_16AW", C.A_16AW)
    BI2 = C.load_by_path("BI_16AW", C.B_16AW)
    fold = {}
    for name, fn in (("A_16AW.half_add", AN2.half_add),
                     ("B_16AW.H(acc+s)", lambda a, b: BI2.H(Q(a) + Q(b)))):
        try:
            fold[name] = float(fn(float(acc), float(term)))
        except Exception as exc:                     # pragma: no cover
            fold[name] = "RAISED %s" % type(exc).__name__
    doc["step_2c_boundary_shape_by_reference"] = {
        "stimulus": {"accumulator": float(acc), "term": float(term)},
        "one_rounding_declared": float(one),
        "two_rounding_emitted": float(two),
        "by_reference": fold,
        "note": "A_16AW.half_add's docstring says 'taken EXACTLY, then rounded "
                "once'; its code is H(dyadic_to_float(rn32_pair(exact))), i.e. "
                "RN32 then RN16.  The docstring and the code disagree, and the "
                "CODE is what is measured here.",
    }
    rep.row("A_16AW's chunk-boundary fold is the EMITTED (two-rounding) shape, "
            "and B_16AW's is the DECLARED (one-rounding) shape",
            fold.get("A_16AW.half_add") == float(two)
            and fold.get("B_16AW.H(acc+s)") == float(one), 2, fold)

    # ---- 3. the audit's counterexample ----------------------------------
    import p16aw_s1_reproduce_and_repair as S1  # noqa: E402
    A0 = C.load_by_path("A0_16AR", C.A_16AR)
    B0 = C.load_by_path("B0_16AR", C.B_16AR)
    AN = C.load_by_path("AN_16AW", C.A_16AW)
    BI = C.load_by_path("BI_16AW", C.B_16AW)
    pairs = [(2.0 ** -9, 0x38), (2.0 ** 15, 0x7E), (-(2.0 ** 15), 0x7E)]
    res = {name: S1.eval_module(mod, pairs, 0)
           for name, mod in (("A_16AR", A0), ("A_16AW", AN),
                             ("B_16AW", BI), ("B_16AR", B0))}
    got = {k: S1.as_json_value(v, "chunk_dot") for k, v in res.items()}
    doc["step_3_audit_counterexample"] = {
        "input": "chunk 0, positions 0..2 = (2**-9, 0x38), (2**15, 0x7E), "
                 "(-2**15, 0x7E); the audit published the value pair and not "
                 "the input, so this is the SAME reconstruction 16AW used",
        "chunk_dot_by_module": got,
        "audit_published_pair": {"A": "0.001953125", "B": "0.0"},
        "reproduced": (Q(got["A_16AR"]) == Q(1953125, 1000000000)
                       and Q(got["A_16AW"]) == Q(0)
                       and Q(got["B_16AW"]) == Q(0)
                       and Q(got["B_16AR"]) == Q(0)),
    }
    rep.row("the audit's counterexample reproduces: A_16AR 0.001953125 vs "
            "A_16AW/B 0",
            doc["step_3_audit_counterexample"]["reproduced"], 4, got)

    # ---- verdict ---------------------------------------------------------
    hard = [r for r in rep.rows if not r["ok"]]
    doc["checks"] = rep.rows
    doc["n_checks"] = len(rep.rows)
    doc["n_checks_ok"] = rep.n_ok
    doc["verdict"] = ("BASELINE_REPRODUCED" if not hard
                      else "STOP: BASELINE_DID_NOT_REPRODUCE")
    doc["failures"] = [r["check"] for r in hard]
    _write(doc, rep)
    return 0 if not hard else 1


def _write(doc, rep):
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    print("  -> %s" % os.path.relpath(OUT, C.ROOT))


if __name__ == "__main__":
    sys.exit(main())
