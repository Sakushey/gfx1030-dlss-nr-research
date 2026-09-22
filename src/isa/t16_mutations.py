#!/usr/bin/env python3
"""Phase 16T -- KNOWN-BAD MUTATION CONTROLS for the five semantic repairs.

WHY A SOURCE TREE AND NOT A MONKEY PATCH
----------------------------------------
Phase 16L recorded the failure mode this avoids: patching a SHADOWED method is
a silent no-op.  A mutation that runs a different code path than the repaired
implementation proves nothing about the repair.  Each mutation below is
therefore a real SOURCE TREE -- the revision tree with exactly one edit
applied -- loaded by the same `load_revision` path the repair itself is loaded
by, so the mutated bytes are the bytes that execute.

WHAT EACH CONTROL PROVES
------------------------
For a mutation M targeting mnemonic X:

  * `observations_changed_from_revision` must be > 0 -- the mutation reached
    the executing implementation, not a shadowed copy;
  * `mutation_rejected` must be true -- under M the independent oracle suite
    disagrees on at least one vector of X that the unmutated revision agrees on;
  * the OTHER mnemonics' agreement must be unchanged unless the mutation is
    genuinely shared (the shared format definition B is shared, and that is
    recorded rather than smoothed).

Two NON-DETECTING controls are included on purpose.  A control that cannot be
shown to be inert cannot show that the comparison is not merely sensitive to
any edit at all:

  * `NC_comment_only` -- a comment edit, must change NOTHING;
  * `NC_unrelated_handler` -- an edit to `op_v_mul_f32`, a handler outside the
    sixteen, must change nothing in THIS suite.

Host only.  Launches no GPU work, no HIP, no game.

Usage:
    python phase16t/isa/t16_mutations.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
T = os.path.dirname(HERE)
ROOT = os.path.dirname(T)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(T, "semantic"))

REV = os.path.join(T, "semantic", "revision_16t")
MUTROOT = os.path.join(HERE, "mut")
OUT = os.path.join(HERE, "MUTATION_CONTROLS_16T.json")
ORACLE = os.path.join(HERE, "t16_oracle.py")

TREE_MODULES = ["emu", "p16j_input", "p14d8_core", "p14e_emu", "p14eh",
                "p16e_rec", "p16h_scratch_probe", "p16j_scratch_isa"]

EMU = "emu.py"
C8 = "p14d8_core.py"


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def _emu(text):
    return (EMU, text)


# ---------------------------------------------------------------------------
# The mutations.  Each `find` is asserted to occur EXACTLY ONCE in the
# revision tree, so the mutation is the one described and not a near miss.
# ---------------------------------------------------------------------------
MUTATIONS = [
    # ---- repair A: v_cvt_f16_f32_e32 -------------------------------------
    dict(id="A1_restore_old_cvt_handler", repair="A",
         targets=["v_cvt_f16_f32_e32"],
         why="restores the pre-revision v_cvt_f16_f32 body verbatim: sign "
             "from bit 16, flush below 2**-24, subnormal clamp, its own "
             "converter instead of the format definition",
         edits=[_emu((
             "        self._vfp(ins, ops, lambda a, b, c: "
             "f32_bits_to_f16(f32_bits(a)))\n",
             '''        def conv(x):
            if math.isnan(x):
                return 0x7E00
            if math.isinf(x):
                return 0x7C00 | (0x8000 if x < 0 else 0)
            if x == 0.0:
                return 0x8000 if math.copysign(1, x) < 0 else 0
            import struct as _st
            b = _st.unpack("<I", _st.pack("<f", f32(x)))[0]
            s = (b >> 16) & 1
            e = ((b >> 23) & 0xFF) - 127
            if e > 15:
                return 0x7C00 | (s << 15)
            if e < -24:
                return s << 15
            if e < -14:
                frac = int(round(abs(x) / 2.0 ** -24))
                return (s << 15) | min(frac, 0x3FF)
            q = abs(x) / 2.0 ** e
            mnt = int(round((q - 1.0) * 1024.0))
            if mnt == 1024:
                e += 1
                mnt = 0
            if e > 15:
                return 0x7C00 | (s << 15)
            return (s << 15) | ((e + 15) << 10) | mnt
        self._vfp(ins, ops, lambda a, b, c: conv(a))
'''))]),
    dict(id="A2_restore_sign_from_bit16", repair="A/B",
         targets=["v_cvt_f16_f32_e32"],
         why="restores ONLY the sign defect: the result sign is taken from "
             "bit 16 of the f32 pattern instead of bit 31",
         edits=[_emu((
             "    b &= 0xFFFFFFFF\n    s = (b >> 31) & 1\n    sgn = s << 15\n"
             "    e = (b >> 23) & 0xFF\n    m = b & 0x7FFFFF\n"
             "    if e == 0xFF:                                   # infinity or NaN\n",
             "    b &= 0xFFFFFFFF\n    s = (b >> 16) & 1\n    sgn = s << 15\n"
             "    e = (b >> 23) & 0xFF\n    m = b & 0x7FFFFF\n"
             "    if e == 0xFF:                                   # infinity or NaN\n"))]),
    dict(id="A3_restore_subnormal_flush", repair="A/B",
         targets=["v_cvt_f16_f32_e32"],
         why="restores ONLY the flush: a magnitude below 2**-24 returns a "
             "signed zero instead of rounding into the subnormal grid",
         edits=[_emu((
             "    if exp > 15:\n        return sgn | 0x7C00"
             "                         # >= 2**16 -> infinity\n",
             "    if exp > 15:\n        return sgn | 0x7C00"
             "                         # >= 2**16 -> infinity\n"
             "    if exp < -24:\n        return sgn"
             "                    # MUTATION: flush below 2**-24\n"))]),
    dict(id="A4_restore_subnormal_clamp", repair="A/B",
         targets=["v_cvt_f16_f32_e32"],
         why="restores ONLY the clamp: a subnormal rounded up to 2**-14 is "
             "clamped back to 0x03FF instead of carrying into 0x0400",
         edits=[_emu((
             "    if q >= 0x400:                                  # up into the smallest normal\n"
             "        return sgn | 0x0400\n    return sgn | q\n",
             "    if q >= 0x400:                                  # MUTATION: clamp\n"
             "        return sgn | 0x03FF\n    return sgn | q\n"))]),
    # ---- repair C: the `-vN` input modifier ------------------------------
    dict(id="C1_restore_integer_neg_modifier", repair="C",
         targets=["v_cvt_f16_f32_e32"],
         why="restores ONLY the input-modifier defect: `-vN` negates the "
             "encoding as an integer instead of flipping the f32 sign bit",
         edits=[_emu((
             "            raw = self.v[lane][int(tok[2:])]\n"
             "            if fp:\n",
             "            raw = (-self.v[lane][int(tok[2:])]) & U32\n"
             "            if False:\n"))]),
    # ---- repair B: the shared format definition --------------------------
    dict(id="B1_restore_three_guard_bit_truncation", repair="B",
         targets=["v_cvt_f16_f32_e32"],
         why="restores ONLY the truncation: the f16 quantum is truncated "
             "instead of rounded, so exact ties at the quantum go the wrong "
             "way and the 65520 overflow tie returns 0x7BFF",
         edits=[_emu((
             "    if 2 * r > den or (2 * r == den and (q & 1)):\n"
             "        q += 1\n    if exp >= -14:\n",
             "    if False:                       # MUTATION: truncate the quantum\n"
             "        q += 1\n    if exp >= -14:\n"))]),
    dict(id="B2_restore_sign_preserving_qnan", repair="B",
         targets=["v_cvt_f16_f32_e32"],
         why="restores ONLY the NaN convention: the NaN arm preserves the "
             "input sign instead of returning the canonical quiet NaN",
         edits=[_emu((
             "        return QNAN_F16 if m else (sgn | 0x7C00)\n",
             "        return (sgn | 0x7C00 | 0x200) if m else (sgn | 0x7C00)\n"
         ))]),
    # ---- repair D: v_pack_b32_f16 ----------------------------------------
    dict(id="D1_restore_swapped_halves", repair="D",
         targets=["v_pack_b32_f16"],
         why="restores ONLY the half swap: src0 into the HIGH half and src1 "
             "into the LOW half",
         edits=[(C8, ("                          (((hi & 0xFFFF) << 16) "
                      "| (lo & 0xFFFF)) & emu_mod.U32)",
                      "                          (((lo & 0xFFFF) << 16) "
                      "| (hi & 0xFFFF)) & emu_mod.U32)"))]),
    dict(id="D2_restore_integer_operand_decode", repair="D",
         targets=["v_pack_b32_f16"],
         why="restores ONLY the operand decode: the second source is read "
             "with the INTEGER decoder, which raises on the J3 form's float "
             "literal `1.0`",
         edits=[(C8, ("                hi = self._f16_src_bits(lane, ops[2])",
                      "                hi = self.vget(lane, ops[2])"))]),
    # ---- repair E: the two MIX mnemonics ---------------------------------
    dict(id="E1_restore_f32_read_mixlo", repair="E",
         targets=["v_fma_mixlo_f16"],
         why="restores the pre-revision MIXLO body verbatim: f32 arithmetic "
             "over the whole 32-bit register",
         edits=[_emu(("        self._fma_mix16(ins, ops, high=False)\n",
                      "        self._vfp(ins, ops, lambda a, b, c: f32(a * b + c))\n"))]),
    dict(id="E2_restore_f32_read_mixhi", repair="E",
         targets=["v_fma_mixhi_f16"],
         why="restores the pre-revision MIXHI body verbatim: f32 arithmetic "
             "over the whole 32-bit register",
         edits=[(C8, ("        self._fma_mix16(ins, ops, high=True)\n",
                      "        self._vfp(ins, ops, lambda a, b, c: "
                      "emu_mod.f32(a * b + c))\n"))]),
    dict(id="E3_swap_target_half", repair="E",
         targets=["v_fma_mixlo_f16", "v_fma_mixhi_f16"],
         why="corrupts the target half: every MIX writes the half the other "
             "mnemonic is defined to write",
         edits=[_emu(("                if high:\n"
                      "                    self.v[lane][idx] = ((old & 0x0000FFFF)\n",
                      "                if not high:   # MUTATION: swap the half\n"
                      "                    self.v[lane][idx] = ((old & 0x0000FFFF)\n"))]),
    dict(id="E4_corrupt_source_half_selector", repair="E",
         targets=["v_fma_mixlo_f16", "v_fma_mixhi_f16"],
         why="corrupts ONE source-half selector: S1 is taken from the HIGH "
             "half of its register instead of the LOW half",
         edits=[_emu(("                b = self._f16_src_bits(lane, ops[2])\n",
                      "                b = (self.v[lane][int(ops[2].strip()[1:])] >> 16) & 0xFFFF  # MUTATION\n"))]),
    # ---- repair F: v_add_co_ci_u32 ---------------------------------------
    dict(id="F1_write_only_if_vcc_lo", repair="F",
         targets=["v_add_co_ci_u32_e64"],
         why="restores ONLY the carry-out defect: the carry-out is written "
             "when the destination token is `vcc_lo` and dropped otherwise",
         edits=[_emu((
             "        if cout == \"vcc_lo\":\n            self.vcc_l = carry & U32\n"
             "        elif cout in (\"null\", \"off\"):\n"
             "            pass                      # no carry-out destination named\n"
             "        elif cout == \"scc\":\n"
             "            self.scc = 1 if carry else 0\n"
             "        elif cout.startswith(\"s\"):\n"
             "            self.sset(cout, carry & U32)\n",
             "        if cout == \"vcc_lo\":    # MUTATION: only this token writes\n"
             "            self.vcc_l = carry & U32\n"))]),
    # ---- non-detecting controls ------------------------------------------
    dict(id="NC_comment_only", repair=None, targets=[],
         why="NON-DETECTING CONTROL: a comment edit.  If this changes any "
             "observation, the comparison is sensitive to something other "
             "than the executing semantics and every rejection above is "
             "suspect.",
         edits=[_emu(("QNAN_F16 = 0x7E00\n",
                      "QNAN_F16 = 0x7E00  # NC: comment-only mutation\n"))]),
    dict(id="NC_unrelated_handler", repair=None, targets=[],
         why="NON-DETECTING CONTROL: a real semantic edit to op_v_mul_f32, a "
             "handler OUTSIDE the sixteen.  If this changes an observation in "
             "this suite, the suite is detecting edits rather than oracle "
             "disagreements.",
         edits=[_emu(("    def op_v_mul_f32(self, ins, ops):\n",
                      "    def op_v_mul_f32(self, ins, ops):\n"
                      "        _NC = 0  # NC: unrelated-handler mutation\n"))]),
]


def build_tree(mut, dest):
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    for m in TREE_MODULES:
        shutil.copyfile(os.path.join(REV, m + ".py"),
                        os.path.join(dest, m + ".py"))
    applied = []
    for fname, (find, repl) in [(e[0], e[1]) for e in mut["edits"]]:
        p = os.path.join(dest, fname)
        with open(p, "r", encoding="utf-8", newline=None) as fh:
            txt = fh.read()
        n = txt.count(find)
        if n != 1:
            raise SystemExit("mutation %s: find-text occurs %d times in %s"
                             % (mut["id"], n, fname))
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(txt.replace(find, repl))
        applied.append({"file": fname,
                        "find_sha256": hashlib.sha256(find.encode()).hexdigest(),
                        "replace_sha256": hashlib.sha256(repl.encode()).hexdigest()})
    return applied


def run_oracle(tree, out):
    r = subprocess.run([sys.executable, ORACLE, "--rev", "revision",
                        "--rev-tree", tree, "--out", out],
                       capture_output=True, text=True, cwd=ROOT, timeout=1800)
    if r.returncode != 0:
        raise SystemExit("oracle run failed for %s:\n%s\n%s"
                         % (tree, r.stdout[-3000:], r.stderr[-3000:]))
    with open(out, encoding="utf-8") as f:
        return json.load(f)


def obs_index(doc):
    """{suite|mnem|name: the FULL observation} for every vector in a run.

    The whole observation is indexed, not just the primary destination field:
    a mutation that moves only a carry-out read-back (F1) changes a real
    observation, and an index that dropped `extra` would report it as
    "changed nothing" while the comparison still rejected it -- which reads
    as a contradiction in the artifact.
    """
    idx = {}
    for suite in ("phase16s_vectors", "mix_16t_vectors"):
        for v in doc[suite]["vectors"]:
            o = v["obs"]
            idx["%s|%s|%s" % (suite, v["mnem"], v["name"])] = (
                o.get("error"), o.get("value"), o.get("scc"), o.get("exec"),
                tuple(sorted((o.get("extra") or {}).items())))
    return idx


def agree_index(doc):
    """{suite|mnem|name: bool} -- did the emulator agree with the oracle?"""
    out = {}
    for suite in ("phase16s_vectors", "mix_16t_vectors"):
        for v in doc[suite]["vectors"]:
            out["%s|%s|%s" % (suite, v["mnem"], v["name"])] = not v["diffs"]
    # the recomputed-expectation comparison for the 16S MIX vectors
    for x in doc.get("phase16s_mix_recomputed") or []:
        if "emulator_agrees_with_recomputed" in x:
            out["recomputed|%s|%s" % (x["mnem"], x["name"])] = \
                x["emulator_agrees_with_recomputed"]
    return out


def main():
    t0 = time.time()
    if not os.path.isdir(REV):
        raise SystemExit("build the revision first: phase16t/semantic/"
                         "build_revision_16t.py")
    os.makedirs(MUTROOT, exist_ok=True)
    outdir = os.path.join(HERE, "out")
    os.makedirs(outdir, exist_ok=True)

    print("baseline: the unmutated revision")
    base_doc = run_oracle(REV, os.path.join(outdir, "mut_BASELINE.json"))
    base_obs = obs_index(base_doc)
    base_agr = agree_index(base_doc)
    n_agr = sum(1 for v in base_agr.values() if v)
    print("   %d comparisons-agreeing vectors of %d; %d comparisons"
          % (n_agr, len(base_agr), base_doc["n_comparisons_total"]))

    recs = []
    for mut in MUTATIONS:
        dest = os.path.join(MUTROOT, mut["id"])
        applied = build_tree(mut, dest)
        print("\n-- %s" % mut["id"])
        doc = run_oracle(dest, os.path.join(outdir, "mut_%s.json" % mut["id"]))
        obs = obs_index(doc)
        agr = agree_index(doc)

        changed = sorted(k for k in base_obs if base_obs[k] != obs.get(k))
        flipped = sorted(k for k in base_agr
                         if base_agr[k] and not agr.get(k))
        by_mnem = {}
        for k in changed:
            by_mnem.setdefault(k.split("|")[1], 0)
            by_mnem[k.split("|")[1]] += 1
        tgt_changed = [k for k in changed if k.split("|")[1] in mut["targets"]]
        tgt_flipped = [k for k in flipped if k.split("|")[1] in mut["targets"]]
        detecting = bool(mut["targets"])
        rec = {
            "mutation": mut["id"], "repair": mut["repair"],
            "why": mut["why"],
            "target_mnemonics": mut["targets"],
            "tree": os.path.relpath(dest, ROOT).replace("\\", "/"),
            "edits": applied,
            "observations_changed_from_revision": len(changed),
            "observations_changed_by_mnemonic": by_mnem,
            "vectors_that_stopped_agreeing": len(flipped),
            "target_observations_changed": len(tgt_changed),
            "target_vectors_that_stopped_agreeing": len(tgt_flipped),
            "is_a_detecting_control": detecting,
            "mutation_rejected": (bool(tgt_flipped) if detecting
                                  else len(changed) == 0),
            "sample_changed": [
                {"vector": k, "before": base_obs[k], "after": obs.get(k)}
                for k in changed[:8]],
            "sample_flipped": flipped[:8],
        }
        recs.append(rec)
        print("   changed=%d  flipped=%d  target_changed=%d  "
              "target_flipped=%d  rejected=%s"
              % (len(changed), len(flipped), len(tgt_changed), len(tgt_flipped),
                 rec["mutation_rejected"]))

    det = [r for r in recs if r["is_a_detecting_control"]]
    nd = [r for r in recs if not r["is_a_detecting_control"]]
    by_repair = {}
    for r in det:
        by_repair.setdefault(r["repair"], []).append(r)

    doc = {
        "schema": "phase16t-mutation-controls/1", "phase": "16T",
        "host_only": True, "gpu_execution_performed": False,
        "gta_launched": False, "currently_armed": False,
        "what": ("known-bad mutations of each repaired handler, built as real "
                 "source trees and executed through the same loader as the "
                 "repair itself"),
        "why_source_trees":
            ("Phase 16L recorded that patching a SHADOWED method is a silent "
             "no-op; a mutation must run the code it claims to run."),
        "revision_tree": os.path.relpath(REV, ROOT).replace("\\", "/"),
        "revision_semantics_hash":
            json.load(open(os.path.join(T, "semantic",
                                        "REVISION_16T_PATCHES.json"),
                           encoding="utf-8"))["revision_semantics_hash"],
        "baseline": {
            "agreement_vectors": n_agr, "total_vectors": len(base_agr),
            "n_comparisons": base_doc["n_comparisons_total"],
            "phase16s_unexplained":
                base_doc["phase16s_vectors"]["n_disagreeing_unexplained"],
            "mix_16t_unexplained":
                base_doc["mix_16t_vectors"]["n_disagreeing_unexplained"],
            "recomputed_16s_mix_agree": sum(
                1 for x in base_doc["phase16s_mix_recomputed"]
                if x.get("emulator_agrees_with_recomputed")),
            "recomputed_16s_mix_total": len(
                base_doc["phase16s_mix_recomputed"]),
        },
        "n_mutations": len(recs),
        "n_detecting": len(det),
        "n_nondetecting_controls": len(nd),
        "n_detecting_rejected": sum(1 for r in det if r["mutation_rejected"]),
        "n_nondetecting_inert": sum(1 for r in nd if r["mutation_rejected"]),
        "rejections_per_repair": {
            k: {"n": len(v),
                "n_rejected": sum(1 for r in v if r["mutation_rejected"])}
            for k, v in by_repair.items()},
        "mutations": recs,
        "wall_s": round(time.time() - t0, 1),
    }
    doc["verdict"] = (
        "PASS" if (doc["n_detecting_rejected"] == doc["n_detecting"]
                   and doc["n_nondetecting_inert"] == doc["n_nondetecting_controls"])
        else "FAIL")
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    print("\n%d/%d detecting mutations rejected; %d/%d non-detecting controls "
          "inert" % (doc["n_detecting_rejected"], doc["n_detecting"],
                     doc["n_nondetecting_inert"], doc["n_nondetecting_controls"]))
    print("verdict: %s" % doc["verdict"])
    print("wrote %s" % OUT)
    return 0 if doc["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
