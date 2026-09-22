#!/usr/bin/env python3
"""Phase 16AW -- synthetic gfx1030 programs whose text is VERIFIED BY DECODE.

Every control program in this phase is assembled with llvm-mc, written into a
COPY of the archived Slot-5 object at fixed addresses, disassembled back with
llvm-objdump, and analysed from THAT decoded text.  Nothing is analysed from a
hand-built mnemonic string: a control that claims to plant
`s_add_u32 s0, s5, 1` and plants something else fails here rather than passing
silently -- which is the failure mode this project has already paid for twice
(a quoted include that picked up the unmutated header, and a whole phase of
mutants that never reached the comparison).

The archived object is never written to.  The copy lives in the phase's own
scratch directory.

Host-only.  Disassembling is not launching: no HIP call, no GPU, no slot.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

sys.path.insert(0, os.path.join(ROOT, "p16at", "native"))
import p16at_machine_cfg as M  # noqa: E402
from p16at_loop_controls import MC, TEXT_OFF, TEXT_VA  # noqa: E402

#: where synthetic programs are planted.  Inside .text (VA 0x1800..0x7DFC) so
#: the bytes land in the section llvm-objdump disassembles as code.
SCRATCH_VA = 0x7000

#: .text is 26112 bytes: 0x1800 .. 0x7DFC.  A program that runs past the end
#: would be written into a different section, so the builder refuses.
TEXT_VA_END = 0x7DFC

BRANCH_MNEM = ("s_cbranch", "s_branch")

#: instructions that genuinely take no operand.  For anything else an empty
#: operand field means llvm-objdump printed something this parser did not
#: understand, and a control built on a mis-parsed instruction is not a control.
ZERO_OPERAND_MNEM = ("s_endpgm", "s_nop", "s_barrier", "s_waitcnt")


def encode_words(asm_line):
    """The instruction's encoding as llvm-mc gives it: a LIST of bytes, because
    some gfx1030 scalar instructions are two words (an `s_load_dword` with an
    immediate offset is 8 bytes), and a builder that assumed 4 would lay the
    rest of the program out at the wrong addresses."""
    r = subprocess.run([MC, "-arch=amdgcn", "-mcpu=gfx1030", "-show-encoding"],
                       input=asm_line + "\n", capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("llvm-mc failed for %r: %s" % (asm_line, r.stderr))
    m = re.search(r"encoding:\s*\[([^\]]+)\]", r.stdout)
    if not m:
        raise RuntimeError("no encoding for %r: %s" % (asm_line, r.stdout))
    return [int(t, 16) for t in m.group(1).split(",")]


def encode(asm_line):
    """The single-word case, for callers that know the instruction is 4 bytes."""
    by = encode_words(asm_line)
    if len(by) != 4:
        raise RuntimeError("%r encodes to %d bytes, not one word"
                           % (asm_line, len(by)))
    return int.from_bytes(bytes(by), "little")


def build_program(prog, obj, scratch_dir, label="prog"):
    """prog: [(asm text, target instruction index or None), ...]

    The addresses are COMPUTED here from the real encoded lengths, so a program
    may contain two-word instructions.  Returns (ins, symbol_base, verification)
    where `ins` carries the text llvm-objdump produced for the bytes actually
    present at each address.
    """
    os.makedirs(scratch_dir, exist_ok=True)
    probe = os.path.join(scratch_dir, "_synth_%s.co" % label)
    shutil.copyfile(obj, probe)

    enc = [encode_words(asm) for asm, _t in prog]
    addrs, a = [], SCRATCH_VA
    for by in enc:
        if len(by) > 4 and a % 8:
            a += 4                       # a two-word form gets 8-byte alignment
        addrs.append(a)
        a += len(by)
    if a > TEXT_VA_END + 4:
        raise RuntimeError("the program runs to %s, past the end of .text"
                           % hex(a))

    requested = []
    for i, ((asm, tgt), by) in enumerate(zip(prog, enc)):
        addr = addrs[i]
        word = int.from_bytes(bytes(by), "little")
        if tgt is not None:
            mn = asm.split(None, 1)[0]
            if not mn.startswith(BRANCH_MNEM):
                raise RuntimeError("%r is not a branch but a target was given"
                                   % asm)
            if not 0 <= tgt < len(prog):
                raise RuntimeError("target index %r is not an instruction in "
                                   "this program" % tgt)
            simm = (addrs[tgt] - (addr + 4)) // 4
            if not -0x8000 <= simm <= 0x7FFF:
                raise RuntimeError("branch offset %d does not fit simm16"
                                   % simm)
            word = (word & ~0xFFFF) | (simm & 0xFFFF)
        if word >= (1 << (8 * len(by))):
            raise RuntimeError("the patched word for %r does not fit its "
                               "%d-byte encoding" % (asm, len(by)))
        requested.append((addr, asm, tgt, word, len(by)))

    with open(probe, "r+b") as f:
        for addr, _asm, _t, word, n in requested:
            f.seek(TEXT_OFF + (addr - TEXT_VA))
            f.write(word.to_bytes(n, "little"))

    r = subprocess.run([M.OBJDUMP_64, "-d", "--triple=amdgcn--amdhsa",
                        "--mcpu=gfx1030", probe], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("llvm-objdump failed on the synthetic program: %s"
                           % r.stderr)
    decoded = {}
    for line in r.stdout.splitlines():
        m = re.search(r"//\s*([0-9a-fA-F]{4,16})\s*:", line)
        if not m:
            continue
        a = int(m.group(1), 16)
        decoded[a] = line[:line.find("//")].strip()

    ins = []
    checks = []
    for addr, asm, target, word, n in requested:
        txt = decoded.get(addr, "")
        parts = txt.split(None, 1)
        mn = parts[0] if parts else ""
        ops = parts[1] if len(parts) > 1 else ""
        want_mn = asm.split(None, 1)[0]
        checks.append({
            "at": hex(addr), "requested": asm, "bytes": n,
            "word": "%0*X" % (2 * n, word), "decoded": txt,
            "mnemonic_matches": mn == want_mn,
        })
        if mn != want_mn:
            raise RuntimeError("the word planted at %s decodes as %r, not as "
                               "the requested %r -- the control would be "
                               "testing a different instruction"
                               % (hex(addr), txt, asm))
        if not ops and not mn.startswith(ZERO_OPERAND_MNEM):
            raise RuntimeError("the instruction at %s decoded with no operands:"
                               " %r" % (hex(addr), txt))
        if ops and mn.startswith(ZERO_OPERAND_MNEM):
            raise RuntimeError("the instruction at %s is an operandless "
                               "mnemonic but decoded as %r" % (hex(addr), txt))
        ins.append({"addr": addr, "size": n, "raw": "%0*X" % (2 * n, word),
                    "mnemonic": mn, "operands": ops, "symbol": None})

    ins.sort(key=lambda x: x["addr"])
    for i in range(1, len(ins)):
        if ins[i]["addr"] <= ins[i - 1]["addr"]:
            raise RuntimeError("synthetic addresses are not ascending")

    #: three independent routes to each branch target, as in the 16AT CFG work:
    #: A the raw bits, C the operand llvm-objdump printed.  B (a resolved
    #: symbol) is deliberately absent -- a synthetic program has no symbol --
    #: and saying so is better than silently substituting an address.
    routes = []
    for x in ins:
        if not x["mnemonic"].startswith(BRANCH_MNEM):
            continue
        d = M.decode_branch(x, None)
        routes.append({"at": hex(x["addr"]), "insn": "%s %s"
                       % (x["mnemonic"], x["operands"]),
                       "A_bit_level": None if d["A"] is None else hex(d["A"]),
                       "C_printed_operand": None if d["C"] is None
                       else hex(d["C"]),
                       "A_equals_C": d["A"] == d["C"],
                       "B_unavailable_because": "a synthetic program has no "
                                                "symbol table entry"})
    verification = {
        "label": label,
        "objective_file_sha256": hashlib.sha256(
            open(obj, "rb").read()).hexdigest(),
        "scratch_copy": os.path.relpath(probe, ROOT).replace("\\", "/"),
        "n_instructions": len(ins),
        "every_planted_word_decoded_to_the_requested_mnemonic":
            all(c["mnemonic_matches"] for c in checks),
        "decode_checks": checks,
        "branch_target_routes": routes,
        "branch_routes_all_agree": all(r["A_equals_C"] for r in routes),
        "how_the_text_was_obtained": "llvm-mc assembled the word, the word was "
                                     "written into a COPY of the archived "
                                     "object at the address shown, and the "
                                     "text analysed is what llvm-objdump read "
                                     "back from that copy",
    }
    return ins, SCRATCH_VA, verification


def assemble(prog, obj, scratch_dir, label="prog"):
    """The common shape: a program laid out from 0x7000 with the encoded
    lengths of its own instructions, a preheader first and an s_endpgm last."""
    return build_program(prog, obj, scratch_dir, label=label)


def direct_load_test(program, guard_reg):
    """THE 16AT DIRECT TEST, reproduced.

    p16at/native/p16at_liveness_final.py, inside `_spin_detector_control`,
    asked whether any LOAD in the loop writes the register the guard compares,
    by looking at the load's DESTINATION operand only.  On a chain
    `load -> move -> compare` the load writes some other register, so the answer
    is "not a spin" -- and the loop is a spin.
    """
    for x in program:
        if not x["mnemonic"].startswith(
                ("global_load", "flat_load", "buffer_load", "scratch_load",
                 "s_load", "ds_read", "s_atomic", "global_atomic",
                 "flat_atomic", "buffer_atomic")):
            continue
        dst = x["operands"].split(",")[0].strip()
        if dst == guard_reg or dst.startswith(guard_reg + ":"):
            return True, x["mnemonic"] + " " + x["operands"]
    return False, None
