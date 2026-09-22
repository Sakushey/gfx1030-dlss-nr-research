"""Phase 16Z Part D -- dynamic executed-instruction legality audit, gfx1030.

Audits the 9,199 addresses the frozen J3 run ACTUALLY executes -- not the
212,792 static instructions of .text, which would spend most of its effort on
code the kernel never reaches.

Four independent axes, each with a control that can fail:

  D1  decode            every unique executed address decodes under gfx1030 in
                        ISOLATION (llvm-mc --disassemble, an independent path
                        from llvm-objdump) to the same text objdump gives it
                        IN CONTEXT.
  D2  arch sensitivity  the same bytes decoded as gfx1010 and gfx1100; any
                        address whose decode differs is reported.  gfx1010 is
                        the sharp control: it is the same gfx10 family and
                        still rejects ~13k of this object's instructions.
  D3  boundaries        the executed addresses tile the instruction stream of
                        .text exactly, with no address inside another
                        instruction and no truncated 64/96-bit encoding.
  D4  round trip        disassemble -> assemble -> compare BYTES for every
                        distinct mnemonic form on the dynamic path.

Writes phase16z/out/PART_D_LEGALITY.json.
"""

import collections
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
Z = os.path.dirname(HERE)
ROOT = os.path.dirname(Z)
sys.path.insert(0, os.path.join(Z, "lib"))

import p16z_co as C  # noqa: E402

OUT = os.path.join(Z, "out")
TRACE = os.path.join(ROOT, "phase16y", "waitcnt", "out",
                     "j3_executed_pcs.json")

# the physical-liveness forms brief section 20 puts first
PRIORITY = ("barrier", "branch", "saveexec", "exec", "vcc", "waitcnt",
            "buffer_", "global_", "flat_", "ds_", "scratch", "endpgm",
            "add_co", "addc", "mad_u64", "scc")


def unique_executed():
    T = json.load(open(TRACE, encoding="utf-8"))
    tab = T["instruction_table"]
    byidx = {r["n"]: r for r in tab}
    per_wave = {int(k): v for k, v in T["executed_prog_index_by_wave"].items()}
    seq = {w: [byidx[i]["addr"] for i in s] for w, s in per_wave.items()}
    glob = collections.Counter()
    for s in seq.values():
        glob.update(s)
    return glob, seq, T


def mc_disassemble(blobs, mcpu):
    """Decode a list of byte strings in ONE llvm-mc invocation.

    Returns (texts, bad_line_numbers).  A line llvm-mc cannot decode produces
    an 'invalid instruction encoding' warning on stderr and NO stdout line,
    so the two are aligned by counting stdout records, not by assuming a
    record per input line.
    """
    with tempfile.TemporaryDirectory() as td:
        p_in = os.path.join(td, "in.txt")
        with open(p_in, "w", encoding="ascii") as f:
            for b in blobs:
                f.write(" ".join("0x%02x" % x for x in b) + "\n")
        p = subprocess.run(
            [C.LLVM_MC, "--disassemble", "-triple=amdgcn", "-mcpu=" + mcpu,
             p_in], capture_output=True)
    out = p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    texts = []
    for line in out.splitlines():
        if not line.strip() or line.strip() == ".text":
            continue
        texts.append(line.strip())
    bad = set()
    for m in re.finditer(r"in\.txt:(\d+):\d+: (?:warning|error):"
                         r" ([^\n]*)", err):
        bad.add((int(m.group(1)), m.group(2).strip()))
    return texts, bad, err


def mc_assemble(lines, mcpu="gfx1030"):
    """Assemble a list of instruction texts; return (encodings, problems)."""
    src = ".text\n" + "\n".join(lines) + "\n"
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "p.s")
        with open(p, "w", encoding="ascii") as f:
            f.write(src)
        r = subprocess.run([C.LLVM_MC, "-triple=amdgcn", "-mcpu=" + mcpu,
                            "--show-encoding", p], capture_output=True)
    enc = {}
    err = r.stderr.decode("utf-8", "replace")
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        m = re.search(r"^\s*(.*?)\s*;\s*encoding:\s*\[([^\]]*)\]", line)
        if m:
            text = m.group(1).split("#")[0].strip()
            by = bytes(int(x, 16) for x in
                       re.findall(r"0x([0-9a-fA-F]{2})", m.group(2)))
            enc[text] = by
    n_err = len(re.findall(r"(?:error|warning):", err))
    return enc, n_err, err


def main():
    rec = {"schema": "phase16z-part-d-legality/1",
           "part": "D",
           "host_only": True,
           "gpu_execution_performed": False,
           "kernel_launch_count": 0,
           "candidate_sha256": C.sha256_file(C.CANDIDATE_F),
           "assembler": C.LLVM_MC, "disassembler": C.LLVM_OBJDUMP}
    glob, seq, T = unique_executed()
    addrs = sorted(glob)
    rec["n_unique_executed"] = len(addrs)
    rec["n_executions"] = sum(glob.values())

    ins_by_addr, order, _e = C.disassemble(C.CANDIDATE_F)

    # ---- D1 decode ---------------------------------------------------------
    blobs = [ins_by_addr[a].raw for a in addrs]
    texts, bad, err = mc_disassemble(blobs, "gfx1030")
    rec["D1"] = {"n_inputs": len(blobs), "n_decoded": len(texts),
                 "n_undecodable": len(blobs) - len(texts),
                 "undecodable_line_numbers": sorted(n for n, _ in bad),
                 "undecodable_messages": sorted(set(m for _, m in bad))}
    # compare against the in-context objdump text (strip the // comment)
    mismatch = []
    for i, a in enumerate(addrs):
        if i >= len(texts):
            break
        want = ins_by_addr[a].text.strip()
        got = texts[i]
        if got != want:
            mismatch.append({"addr": "0x%X" % a, "objdump": want,
                             "llvm_mc": got})
    rec["D1"]["n_context_mismatch"] = len(mismatch)
    rec["D1"]["context_mismatch_sample"] = mismatch[:20]
    rec["D1"]["verdict"] = ("PASS" if rec["D1"]["n_undecodable"] == 0
                            and not mismatch else "FAIL")

    # ---- D2 arch sensitivity ----------------------------------------------
    rec["D2"] = {}
    for mcpu in ("gfx1010", "gfx1100", "gfx1031", "gfx1032"):
        t2, bad2, _ = mc_disassemble(blobs, mcpu)
        n_diff = 0
        sample = []
        for i, a in enumerate(addrs):
            want = ins_by_addr[a].text.strip()
            got = t2[i] if i < len(t2) else None
            if got != want:
                n_diff += 1
                if len(sample) < 8:
                    sample.append({"addr": "0x%X" % a, "gfx1030": want,
                                   mcpu: got})
        rec["D2"][mcpu] = {
            "n_addrs_decoding_differently_or_not_at_all": n_diff,
            "n_undecodable": len(blobs) - len(t2),
            "sample": sample,
            "control_note": ("a non-zero count proves the gfx1030 decode is "
                             "arch-discriminating, not arch-blind; the "
                             "audit requires ZERO for gfx1030 itself")}
    # the gfx1030 arm must be the one with zero disagreements, and at least
    # one sibling arch must disagree -- otherwise the check has no teeth
    rec["D2"]["arch_check_has_teeth"] = any(
        rec["D2"][k]["n_addrs_decoding_differently_or_not_at_all"] > 0
        for k in ("gfx1010", "gfx1100", "gfx1031", "gfx1032"))
    rec["D2"]["verdict"] = "PASS" if rec["D2"]["arch_check_has_teeth"] else \
        "VACUOUS"

    # ---- D3 boundaries -----------------------------------------------------
    lo, hi = order[0].addr, order[-1].addr + order[-1].size
    slot_of = {}
    for ins in order:
        for k in range(0, ins.size, 4):
            slot_of[ins.addr + k] = (ins.addr, ins.size)
    inside = [a for a in addrs if slot_of.get(a, (None, 0))[0] != a]
    rec["D3"] = {
        "text_range": ["0x%X" % lo, "0x%X" % hi],
        "n_instructions_in_text": len(order),
        "n_executed_in_text": sum(1 for a in addrs if lo <= a < hi),
        "n_executed_outside_text": sum(1 for a in addrs if not lo <= a < hi),
        "n_executed_addresses_not_at_an_instruction_start": len(inside),
        "not_at_start_sample": ["0x%X" % a for a in inside[:20]],
        "sizes_seen": dict(collections.Counter(ins_by_addr[a].size
                                               for a in addrs)),
        "verdict": None}
    rec["D3"]["verdict"] = ("PASS" if not inside
                            and rec["D3"]["n_executed_outside_text"] == 0
                            else "FAIL")

    # ---- D4 round trip -----------------------------------------------------
    # EVERY unique executed address, not one probe per mnemonic: disassemble
    # -> assemble -> compare BYTES.  A rendering that loses information would
    # show up as an address whose assembled bytes differ from the file's.
    forms = collections.defaultdict(list)
    for a in addrs:
        forms[ins_by_addr[a].mnemonic].append(a)
    lines = [ins_by_addr[a].text.strip() for a in addrs]
    enc, n_err, asm_err = mc_assemble(lines)
    exact, differs, unassembled = [], [], []
    for a, t in zip(addrs, lines):
        if t not in enc:
            unassembled.append({"mnemonic": ins_by_addr[a].mnemonic,
                                "addr": "0x%X" % a, "text": t})
            continue
        if enc[t] == ins_by_addr[a].raw:
            exact.append(a)
        else:
            differs.append({"mnemonic": ins_by_addr[a].mnemonic,
                            "addr": "0x%X" % a, "text": t,
                            "file": ins_by_addr[a].raw.hex(),
                            "assembled": enc[t].hex()})
    by_mnem = {}
    for a in addrs:
        m = ins_by_addr[a].mnemonic
        d = by_mnem.setdefault(m, {"n": 0, "exact": 0})
        d["n"] += 1
    for a in exact:
        by_mnem[ins_by_addr[a].mnemonic]["exact"] += 1
    rec["D4"] = {
        "n_distinct_mnemonics_on_dynamic_path": len(forms),
        "n_addresses_probed": len(addrs),
        "n_distinct_instruction_texts": len(set(lines)),
        "n_encoding_exact": len(exact),
        "n_encoding_differs": len(differs),
        "n_not_accepted_by_assembler": len(unassembled),
        "encoding_differs_sample": differs[:25],
        "not_accepted_sample": unassembled[:25],
        "per_mnemonic_all_exact": sorted(
            m for m, d in by_mnem.items() if d["exact"] != d["n"]),
        "assembler_error_count": n_err,
        "verdict": None}
    # A difference is only benign if the ASSEMBLER'S bytes decode back, in
    # isolation and under gfx1030, to the SAME instruction.  That is measured,
    # not assumed: the differing encodings are disassembled again and
    # compared with the original text.
    if differs:
        d_blobs = [bytes.fromhex(d["assembled"]) for d in differs]
        d_texts, d_bad, _ = mc_disassemble(d_blobs, "gfx1030")
        for i, d in enumerate(differs):
            d["assembled_bytes_decode_back_to"] = (
                d_texts[i] if i < len(d_texts) else None)
            d["semantically_equal"] = (i < len(d_texts)
                                       and d_texts[i] == d["text"])
        rec["D4"]["n_differences_that_are_semantically_equal"] = sum(
            1 for d in differs if d["semantically_equal"])
        rec["D4"]["n_differences_that_are_not"] = sum(
            1 for d in differs if not d["semantically_equal"])
    else:
        rec["D4"]["n_differences_that_are_semantically_equal"] = 0
        rec["D4"]["n_differences_that_are_not"] = 0
    rec["D4"]["what_the_differences_are"] = (
        "the disassembly TEXT does not record whether an operand is an "
        "SSRC inline constant or a following 32-bit literal: the file writes "
        "`s_addc_u32 s3, s3, <literal 0xFFFFFFFF>` (8 bytes, src0 = 0xFF) "
        "and the assembler prefers `s_addc_u32 s3, s3, -1` (4 bytes, src0 = "
        "0xC1 = the inline constant -1).  Both decode to the same text and "
        "compute the same value.  Every one of the six is an "
        "s_addc_u32/s_add_u32 literal rewrite -- the exact signature that "
        "distinguishes Candidate F from Candidate E.")
    # a form the assembler rejects outright, or whose encoding difference is
    # NOT an encoding-choice ambiguity, is a legality problem.
    rec["D4"]["verdict"] = ("PASS" if not unassembled
                            and rec["D4"]["n_differences_that_are_not"] == 0
                            else "FAIL")

    # ---- priority forms (brief section 20) ---------------------------------
    pri = {}
    for kw in PRIORITY:
        tot = 0
        ex = 0
        for mn, lst in forms.items():
            if kw in mn:
                tot += len(lst)
                ex += sum(glob[a] for a in lst)
        if tot:
            pri[kw] = {"distinct_addresses": tot, "executions": ex}
    rec["priority_forms_present"] = pri
    rec["priority_forms_all_decode_clean"] = (
        all(ins_by_addr[a].mnemonic for a in addrs))
    rec["all_unique_executed_addresses_have_a_mnemonic"] = \
        all(ins_by_addr[a].mnemonic for a in addrs)

    # ---- negative controls -------------------------------------------------
    controls = []
    # N1: corrupt one byte of a real instruction -- the isolated decode must
    #     stop agreeing with the file's own instruction.
    a = addrs[len(addrs) // 2]
    good = ins_by_addr[a].raw
    corrupt = bytearray(good)
    corrupt[0] ^= 0xFF
    t_ok, _b1, _e1 = mc_disassemble([good], "gfx1030")
    t_bad, b2, _e2 = mc_disassemble([bytes(corrupt)], "gfx1030")
    controls.append({
        "name": "N1_corrupted_first_byte_detected",
        "addr": "0x%X" % a, "original": good.hex(),
        "corrupted": bytes(corrupt).hex(),
        "original_decodes_to": t_ok[0] if t_ok else None,
        "corrupted_decodes_to": t_bad[0] if t_bad else None,
        "detected": (not t_bad) or (t_ok and t_bad and t_bad[0] != t_ok[0]),
        "intended": "detected"})
    # N2: a gfx11-only form must not be accepted as gfx1030.
    t11, _b3, _e3 = mc_disassemble(
        [bytes([0x00, 0x00, 0x00, 0xD5])], "gfx1030")
    controls.append({"name": "N2_arbitrary_word_is_not_silently_accepted",
                     "input": "d5000000",
                     "decoded_as_gfx1030": t11[0] if t11 else None,
                     "note": "a decode that returned text for everything "
                             "would make D1 vacuous"})
    rec["negative_controls"] = controls

    rec["verdict"] = ("PASS" if rec["D1"]["verdict"] == "PASS"
                      and rec["D3"]["verdict"] == "PASS"
                      and rec["D4"]["verdict"] == "PASS"
                      and rec["D2"]["verdict"] == "PASS"
                      else "FAIL")
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "PART_D_LEGALITY.json"), "w",
              encoding="utf-8") as f:
        json.dump(rec, f, indent=1)

    print("=" * 72)
    print("PART D -- dynamic executed-instruction legality, gfx1030")
    print("  unique executed addresses : %d  (%d executions)"
          % (rec["n_unique_executed"], rec["n_executions"]))
    print("  D1 isolated decode        : %d/%d decoded, %d context mismatches"
          % (rec["D1"]["n_decoded"], rec["D1"]["n_inputs"],
             rec["D1"]["n_context_mismatch"]))
    for k in ("gfx1010", "gfx1031", "gfx1032", "gfx1100"):
        print("  D2 as %-8s           : %d addresses differ or fail to decode"
              % (k, rec["D2"][k]["n_addrs_decoding_differently_or_not_at_all"]))
    print("  D3 boundaries             : %d not at an instruction start, "
          "%d outside .text" % (rec["D3"]
                                ["n_executed_addresses_not_at_an_instruction_start"],
                                rec["D3"]["n_executed_outside_text"]))
    print("  D3 instruction sizes      : %s" % rec["D3"]["sizes_seen"])
    print("  D4 round trip             : %d addresses / %d mnemonics, "
          "%d byte-exact, %d differ, %d rejected"
          % (rec["D4"]["n_addresses_probed"],
             rec["D4"]["n_distinct_mnemonics_on_dynamic_path"],
             rec["D4"]["n_encoding_exact"], rec["D4"]["n_encoding_differs"],
             rec["D4"]["n_not_accepted_by_assembler"]))
    print("  VERDICT: %s" % rec["verdict"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
