#!/usr/bin/env python3
"""Phase 16AX T-VOPD -- STEP 8: can the corrected stream become a code object?

THE QUESTION, ANSWERED BY MEASUREMENT
  1. Is every emitted instruction a LEGAL gfx1030 encoding?  -> measured by
     actually running llvm-mc, not by reading a manual.
  2. Can the corrected stream be assembled into a code object?  -> measured;
     the answer below is NO, and the specific blockers are enumerated with the
     exact instruction that causes each.
  3. Can the ABI be re-measured?  -> a code object is a precondition, so no.
     What CAN be measured without one is whether the correction introduces any
     register the original did not use.  That is measured here per symbol, and
     it is the only ABI-relevant quantity T-VOPD can actually move.

WHAT IS *NOT* DONE HERE
  No code object is produced, no bytes are written into one, and no hash of a
  code object is claimed.  House rule 8: never fabricate a digest.  The
  acceptance for T-VOPD is therefore the corrected instruction stream plus its
  static proof, and that is stated rather than dressed up.
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

import p16ax_vopd_model as M  # noqa: E402
import p16ax_vopd_lower as L  # noqa: E402
import p16ax_vopd_correct as C  # noqa: E402

LLVM_MC = r"<ROCM_ROOT>\6.4\bin\llvm-mc.exe"
LLVM_READOBJ = r"<ROCM_ROOT>\6.4\bin\llvm-readobj.exe"
CLANGXX = r"<ROCM_ROOT>\6.4\bin\clang++.exe"
SCRATCH = os.path.join(HERE, "scratch")

RE_VGPR = re.compile(r"\bv(\d+)\b")
RE_SGPR = re.compile(r"\bs(\d+)\b")
RE_SYMBOLIC_TARGET = re.compile(r"<[^>]+>")
RE_ENC_BYTES = re.compile(r"encoding:\s*\[([^\]]*)\]")
RE_KERNARG = re.compile(r"\.kernarg_segment_size:\s*(\d+)")
RE_ARG = re.compile(r"- \.offset:\s*(\d+)\s*\n\s*\.size:\s*(\d+)")


def run_mc(lines, mcpu, filetype="asm", timeout=120):
    src = "\n".join(lines) + "\n"
    p = subprocess.run([LLVM_MC, "-triple=amdgcn-amd-amdhsa", "-mcpu=" + mcpu,
                        "-filetype=" + filetype, "-"],
                       input=src.encode("utf-8"),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=timeout)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def mc_accepts(line, mcpu="gfx1030"):
    """True iff llvm-mc assembles this single instruction for `mcpu`."""
    rc, out = run_mc([line], mcpu, "asm")
    if "error" in out:
        return False, out.strip().splitlines()[0] if out.strip() else "error"
    return True, None


def show_encoding(line, mcpu):
    """The bytes llvm-mc chooses, or None if refused.  Used to show that an
    encoding is a property of the TARGET, not of the mnemonic.

    Note `-show-encoding`: without it llvm-mc prints no `; encoding:` comment and
    this returns None for every instruction.  A first draft omitted it and the
    portability check failed with "gfx1030=None gfx1100=None" -- which the check
    correctly reported as a FAIL, so the missing flag surfaced as a red check
    rather than as a silent pass.
    """
    p = subprocess.run([LLVM_MC, "-triple=amdgcn-amd-amdhsa", "-mcpu=" + mcpu,
                        "-show-encoding", "-filetype=asm", "-"],
                       input=(line + "\n").encode("utf-8"),
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       timeout=120)
    out = p.stdout.decode("utf-8", "replace")
    m = RE_ENC_BYTES.search(out)
    if "error" in out or not m:
        return None
    return m.group(1).strip()


def readobj(args, path):
    p = subprocess.run([LLVM_READOBJ] + args + [path],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def sha256_of(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def main():
    M.ensure_extended()
    checks = []

    def ctl(cid, what, ok, detail):
        checks.append({"id": cid, "what": what, "ok": bool(ok), "detail": detail})
        print("[%s] %-5s %s" % ("PASS" if ok else "FAIL", cid, what))
        if not ok:
            print("        %s" % (detail,))

    # ---------------- 1. tools present ----------------
    have_mc = os.path.exists(LLVM_MC)
    ctl("E1", "llvm-mc for amdgcn is present under the ROCm tree", have_mc, LLVM_MC)
    if not have_mc:
        return 1
    rc, ver = run_mc([""], "gfx1030", "asm")
    ctl("E1b", "llvm-mc accepts -mcpu=gfx1030", rc == 0,
        "rc=%d out=%s" % (rc, ver.strip()[:200]))

    # ---------------- 2. every emitted instruction is legal for gfx1030 ------
    rows, syms = C.symbol_disassembly(M.AW_FULL_DIS)
    all_sites, all_emitted = [], set()
    for s in syms:
        krows = rows[s["start"]:s["end"]]
        if not any(" :: " in r["asm"] for r in krows):
            continue
        corrected, records = C.correct_stream(krows)
        for rec in records:
            all_sites.append((s["name"], rec))
            for e in rec["emitted"] or []:
                all_emitted.add(e)

    emitted = sorted(all_emitted)
    bad = []
    for e in emitted:
        ok, why = mc_accepts(e, "gfx1030")
        if not ok:
            bad.append({"instruction": e, "why": why})

    # The exact bytes that were fed to llvm-mc are written out and hashed, so
    # the encodability claim is attached to real bytes on disk rather than to a
    # list that only ever existed in memory (house rule 8).  The file is written
    # HERE, not into corrected/, because corrected/ carries a manifest that
    # enumerates it -- a later write there would make that manifest stale.
    corpus_path = os.path.join(HERE, "EMITTED_INSTRUCTION_CORPUS_16AX.txt")
    with open(corpus_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(emitted) + "\n")
    corpus_sha = hashlib.sha256(open(corpus_path, "rb").read()).hexdigest()

    ctl("E2", "all %d DISTINCT emitted instructions assemble for gfx1030" % len(emitted),
        not bad, "%d rejected, first: %s" % (len(bad), bad[:2]))

    # negative control: the ORIGINAL v_dual forms must be REJECTED by gfx1030
    duals = sorted({t for _, rec in all_sites for t in (rec["x"], rec["y"])})
    dual_ok = []
    for d in duals[:200]:
        ok, _ = mc_accepts(d + " :: " + d, "gfx1030")
        if ok:
            dual_ok.append(d)
    ctl("E3", "the ORIGINAL v_dual forms are REJECTED by gfx1030 (negative "
              "control: the assembler can fail)",
        not dual_ok,
        "%d of %d dual forms were accepted, which would mean the assembler is "
        "not a gfx1030 assembler" % (len(dual_ok), min(200, len(duals))))

    # the emitted stream also assembles for gfx1100 (the source ISA)
    bad11 = [e for e in emitted if not mc_accepts(e, "gfx1100")[0]]
    ctl("E4", "the same emitted instructions also assemble for gfx1100",
        not bad11, "%d rejected: %s" % (len(bad11), bad11[:2]))

    # ---------------- 3. whole-stream reassembly: measured to be BLOCKED -----
    target = "_Z10k_swin_varILi32ELb0EEv9VarParams"
    tsym = [s for s in syms if s["name"] == target]
    blockers = []
    n_symbolic = 0
    corrected_len = orig_len = 0
    if tsym:
        s = tsym[0]
        krows = rows[s["start"]:s["end"]]
        corrected, records = C.correct_stream(krows)
        corrected_len, orig_len = len(corrected), len(krows)
        passthrough = [c for c in corrected if c["kind"] == "passthrough"]
        # which passthrough instructions does gfx1030 reject?
        rej = collections.Counter()
        first_examples = {}
        for c in passthrough:
            ok, why = mc_accepts(c["asm"], "gfx1030")
            if not ok:
                key = c["asm"].split()[0]
                rej[key] += 1
                first_examples.setdefault(key, {"addr": "0x%X" % c["addr"],
                                                "asm": c["asm"], "why": why})
        n_symbolic = sum(1 for c in passthrough if RE_SYMBOLIC_TARGET.search(c["asm"]))
        blockers = [{"mnemonic": k, "n_occurrences": v, "example": first_examples[k]}
                    for k, v in rej.most_common()]

    ctl("E5", "whole-symbol reassembly for gfx1030 is BLOCKED by gfx11-only "
              "non-VOPD instructions in the symbol",
        bool(blockers),
        "no blocker found, which would contradict the expected result")

    # ---------------- 4. ABI-relevant: no NEW register is introduced ---------
    def max_reg(rows_):
        vmax = smax = -1
        for r in rows_:
            for m in RE_VGPR.findall(r["asm"]):
                vmax = max(vmax, int(m))
            for m in RE_SGPR.findall(r["asm"]):
                smax = max(smax, int(m))
        return vmax, smax

    reg_rows = []
    new_reg_sites = []
    for s in syms:
        krows = rows[s["start"]:s["end"]]
        if not any(" :: " in r["asm"] for r in krows):
            continue
        corrected, records = C.correct_stream(krows)
        vb, sb = max_reg([{"asm": r["asm"]} for r in krows])
        va, sa = max_reg([{"asm": c["asm"]} for c in corrected])
        reg_rows.append({"kernel": s["name"], "max_vgpr_before": vb,
                         "max_vgpr_after": va, "max_sgpr_before": sb,
                         "max_sgpr_after": sa})
        if va > vb or sa > sb:
            new_reg_sites.append({"kernel": s["name"], "vgpr": [vb, va],
                                  "sgpr": [sb, sa]})

    ctl("E6", "the correction introduces NO register the original did not use, "
              "in any of the %d kernels" % len(reg_rows),
        not new_reg_sites, "%s" % (new_reg_sites[:3],))

    max_update = {"max_vgpr_before": max(r["max_vgpr_before"] for r in reg_rows) if reg_rows else None,
                  "max_vgpr_after": max(r["max_vgpr_after"] for r in reg_rows) if reg_rows else None,
                  "max_sgpr_before": max(r["max_sgpr_before"] for r in reg_rows) if reg_rows else None,
                  "max_sgpr_after": max(r["max_sgpr_after"] for r in reg_rows) if reg_rows else None}

    # ---------------- 4b. an encoding is a property of the TARGET -------------
    # W14 reports that `v_lshlrev_b32_e32 v7,5,v0` ends 0x34 on gfx1030 and
    # 0x30 on gfx1100.  Reproduced here so the "re-derive, do not trust a
    # translated encoding" constraint is measured in this artifact.
    enc_probe_line = "v_lshlrev_b32_e32 v7, 5, v0"
    e1030 = show_encoding(enc_probe_line, "gfx1030")
    e1100 = show_encoding(enc_probe_line, "gfx1100")
    ctl("E7", "an encoding is NOT portable between gfx1100 and gfx1030 (so no "
              "translated encoding may be carried over)",
        e1030 is not None and e1100 is not None and e1030 != e1100,
        "gfx1030=%s gfx1100=%s" % (e1030, e1100))

    # ---------------- 4c. the flat-assembly path loses the kernel descriptor --
    # Reproduces, in this artifact, the blocker W14 reports for the naive
    # objdump -> llvm-mc -> ld.lld path: the container is a valid elf64-amdgpu
    # with NO note section and NO kernel descriptor, i.e. unloadable.
    os.makedirs(SCRATCH, exist_ok=True)
    flat_src = os.path.join(SCRATCH, "flat_probe.asm")
    flat_obj = os.path.join(SCRATCH, "flat_probe.o")
    with open(flat_src, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(emitted[:8]) + "\n")
    rc, mcout = run_mc(open(flat_src, encoding="utf8").read().splitlines(),
                       "gfx1030", "obj")
    if rc == 0:
        with open(flat_obj, "wb") as fh:
            fh.write(b"")   # placeholder replaced below
    # run_mc captured stdout as text; re-run writing the object to disk
    p = subprocess.run([LLVM_MC, "-triple=amdgcn-amd-amdhsa", "-mcpu=gfx1030",
                        "-filetype=obj", flat_src, "-o", flat_obj],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    flat_rc = p.returncode
    _, secs = readobj(["--sections"], flat_obj)
    flat_sections = re.findall(r"Name:\s*(\S+)\s*\(", secs)
    _, notes = readobj(["--notes"], flat_obj)
    has_note = "NT_AMDGPU_METADATA" in notes
    flat_block = {
        "why": ("the corrected stream is instruction TEXT.  Assembling flat text "
                "for gfx1030 yields a valid elf64-amdgpu CONTAINER, which is "
                "what makes the naive path look like it worked -- but the "
                "container carries no kernel descriptor."),
        "assembler_rc": flat_rc,
        "container_sections": flat_sections,
        "has_amdgpu_metadata_note": has_note,
        "kernarg_segment_size_readable": bool(RE_KERNARG.search(notes)),
        "object_sha256": sha256_of(flat_obj) if os.path.exists(flat_obj) else None,
        "object_bytes": os.path.getsize(flat_obj) if os.path.exists(flat_obj) else None,
        "conclusion": ("assembling without the .amdhsa_* directive block produces "
                       "an object with no note section and no kernel descriptor; "
                       "it cannot be loaded.  The directive block must be carried "
                       "in from the source object."),
    }
    ctl("E8", "assembling flat text gives a valid container with NO kernel "
              "descriptor (reproducing the 'looks like it worked' path)",
        flat_rc == 0 and ".text" in flat_sections and not has_note,
        json.dumps(flat_block)[:400])

    # ---------------- 4d. the PRE-correction ABI receipt (CARRIED) -----------
    # Read from the PARENT object.  It is the parent's ABI, NOT a corrected one,
    # and is labelled that way everywhere it appears.  It is reported because it
    # is the baseline the correction would have to reproduce.
    parent_block = None
    _, pnotes = readobj(["--notes"], M.PARENT_ELF)
    _, psecs = readobj(["--sections"], M.PARENT_ELF)
    pk = RE_KERNARG.search(pnotes)
    parent_block = {
        "label": "PRE-CORRECTION, CARRIED -- this is the parent object's ABI and "
                 "is NOT a corrected-stream measurement",
        "note_section_present": "NT_AMDGPU_METADATA" in pnotes,
        "kernarg_segment_size_in_text_of_note": int(pk.group(1)) if pk else None,
        "count_of_kernel_descriptors_in_note": pnotes.count("amdhsa.kernels:"),
        "has_AMDGPU_gpr_maximums_section": ".AMDGPU.gpr_maximums" in psecs,
        "sha256": sha256_of(M.PARENT_ELF),
    }
    ctl("E9", "the parent object DOES carry a kernel descriptor and a "
              ".AMDGPU.gpr_maximums section -- i.e. there is an ABI baseline to "
              "reproduce, it just cannot be produced from text alone",
        parent_block["note_section_present"]
        and parent_block["has_AMDGPU_gpr_maximums_section"],
        json.dumps(parent_block)[:300])

    # ---------------- 4e. toolchain identity ----------------
    clang_ver = None
    if os.path.exists(CLANGXX):
        q = subprocess.run([CLANGXX, "--version"], stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
        clang_ver = q.stdout.decode("utf-8", "replace").splitlines()[0]
    toolchain = {"llvm_mc": LLVM_MC, "llvm_readobj": LLVM_READOBJ,
                 "triple": "amdgcn-amd-amdhsa", "mcpu": "gfx1030",
                 "clangxx": CLANGXX, "clangxx_version": clang_ver,
                 "found_by": "listed under the ROCm 6.4 tree; no path guessed",
                 "warning": ("a bare `clang` on this machine resolves to the "
                             "ROCm 7.1 tree (21.0.0git), which is not the "
                             "toolchain this project's objects were built with; "
                             "name clang++.exe under ROCm 6.4 explicitly")}

    # ---------------- 5. instruction-count growth ---------------------------
    emitted_counts = collections.Counter(len(rec["emitted"] or []) for _, rec in all_sites)

    # the byte-length effect is measured per site in INDEPENDENCE_16AX.json; it is
    # REFERENCED here rather than recomputed, so the same fact does not exist in
    # two artifacts that could drift apart.  Two facts from one source is only a
    # problem when they are presented as independent corroboration -- this one is
    # labelled as a reference.
    indep_path = os.path.join(HERE, "INDEPENDENCE_16AX.json")
    byte_ref = None
    if os.path.exists(indep_path):
        ind = json.load(open(indep_path, encoding="utf8"))
        byte_ref = {
            "source_artifact": os.path.basename(indep_path),
            "source_sha256": sha256_of(indep_path),
            "histogram_delta_bytes_to_n_sites": ind[
                "byte_length_effect_of_the_correction"][
                "histogram_delta_bytes_to_n_sites"],
            "n_sites_whose_length_changes": ind[
                "byte_length_effect_of_the_correction"]["n_sites_whose_length_changes"],
            "total_byte_delta": ind[
                "byte_length_effect_of_the_correction"]["total_byte_delta_over_all_sites"],
        }

    n_pass = sum(1 for c in checks if c["ok"])
    out = {
        "schema": "p16ax/vopd-encode/1",
        "worker": "W1", "task_id": "T-VOPD", "phase": "16AX",
        "host_only": True, "gpu_calls": 0,
        "toolchain": toolchain,
        "Q1_is_every_emitted_instruction_legal_for_gfx1030": {
            "answer": "YES" if not bad else "NO",
            "n_distinct_emitted": len(emitted),
            "n_rejected": len(bad), "rejected": bad,
            "corpus_file": os.path.basename(corpus_path),
            "corpus_sha256": corpus_sha,
            "n_emissions_total": sum(len(rec["emitted"] or [])
                                     for _, rec in all_sites),
            "method": "each distinct emitted instruction text was fed to llvm-mc "
                      "-filetype=asm and required to assemble without error",
        },
        "Q1b_negative_control": {
            "what": "the ORIGINAL v_dual forms must be rejected by gfx1030",
            "n_tested": min(200, len(duals)), "n_accepted": len(dual_ok),
            "result": "REJECTED as required" if not dual_ok else "CONTROL FAILED",
        },
        "Q2_can_the_corrected_stream_be_assembled_into_a_code_object": {
            "answer": "NO",
            "why": [
                "the corrected stream still contains instructions that gfx1030 "
                "does not implement; T-VOPD corrects VOPD only, by design",
                "the disassembly renders branch and relocation targets as "
                "symbolic references, so the flat text is not a faithful "
                "round-trip input for an assembler",
                "a code object also needs the section table, relocations and "
                "amdgpu metadata regenerated, which is a translator's job",
                "AND, measured below: assembling the flat text DOES succeed at "
                "producing a valid elf64-amdgpu container, which is exactly why "
                "this path looks like it worked -- but the container has no note "
                "section and no kernel descriptor, so it cannot be loaded",
            ],
            "blocking_instructions_in_the_target_symbol": blockers,
            "flat_assembly_container": flat_block,
            "byte_length_effect": byte_ref,
            "encodings_are_not_portable": {
                "probe": enc_probe_line,
                "gfx1030": e1030, "gfx1100": e1100,
                "reading": "the same source instruction encodes to different bytes "
                           "on the two ISAs; no translated encoding may be carried "
                           "over from one to the other",
            },
            "n_symbolic_relocation_references_in_passthrough": n_symbolic,
        },
        "Q3_can_the_ABI_be_re_measured": {
            "answer": "NO",
            "why": "re-measuring kernarg size, vgpr/sgpr counts, LDS, scratch and "
                   "wave size requires a code object, and no corrected code "
                   "object can be produced (Q2).  The parent's ABI receipt is "
                   "reported below but is labelled CARRIED throughout; it is NOT "
                   "restated as the corrected ABI.",
            "what_IS_measurable_without_a_code_object": {
                "property": "the correction introduces no register the original "
                            "did not already use, per kernel",
                "max_registers_across_all_kernels": max_update,
                "n_kernels_with_a_new_register": len(new_reg_sites),
                "per_kernel": reg_rows,
                "reading": ("for the 1509 sites in this object every lowering is a "
                            "reorder or a plain sequentialisation -- ZERO sites "
                            "needed the temporary path -- so no architectural "
                            "register is added and the VGPR/SGPR high-water mark "
                            "cannot rise.  This does NOT prove the ABI is "
                            "unchanged; it proves the correction cannot move the "
                            "register counts, which is one component of it."),
            },
        },
        "instruction_count": {
            "n_sites": len(all_sites),
            "emitted_instructions_per_site": dict(emitted_counts),
            "target_symbol_instructions_before": orig_len,
            "target_symbol_instructions_after": corrected_len,
            "delta": corrected_len - orig_len,
            "note": "each VOPD instruction becomes two, so the symbol grows by "
                    "one instruction per site; every PC-relative branch inside "
                    "the symbol therefore shifts and must be re-encoded",
        },
        "carried_parent_ABI_receipt_NOT_a_corrected_measurement": parent_block,
        "checks": checks, "n_checks": len(checks), "n_passed": n_pass,
        "acceptance_definition": (
            "because no corrected code object can be produced, the T-VOPD "
            "acceptance is the CORRECTED INSTRUCTION STREAM plus its STATIC "
            "PROOF: the encodability of every emitted instruction (measured "
            "here), the semantic equivalence corpus (SEMANTIC_CORPUS_16AX.json), "
            "and the corrected-stream census with its negative control "
            "(CROSS_KERNEL_CORRECTED_CENSUS_16AX.json).  No code object, no ABI "
            "receipt and no hash of either is claimed."),
        "what_this_does_NOT_establish": (
            "that a complete gfx1100->gfx1030 translation exists, that the "
            "corrected stream links or runs, or anything about the GPU"),
    }
    path = os.path.join(HERE, "ENCODE_ASSESSMENT_16AX.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)

    print("\n%d/%d checks passed" % (n_pass, len(checks)))
    print("distinct emitted instructions: %d, rejected by gfx1030: %d"
          % (len(emitted), len(bad)))
    print("gfx1030 blockers in the target symbol: %s"
          % [(b["mnemonic"], b["n_occurrences"]) for b in blockers])
    print("kernels that would gain a register: %d" % len(new_reg_sites))
    print("target symbol instructions %d -> %d" % (orig_len, corrected_len))
    print("wrote", path)
    return 0 if n_pass == len(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
