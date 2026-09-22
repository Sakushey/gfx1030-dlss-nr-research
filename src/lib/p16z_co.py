"""Phase 16Z -- read-only model of the frozen Candidate F code object.

Nothing here writes to the frozen artefact.  The disassembly it parses is
produced by llvm-objdump from ROCm 6.4 (AOMP-18 / LLVM 20.0.0git), invoked
with the arch the ELF itself declares, which this module also asserts.

The point of the module is that an instruction is identified by its BYTES,
not by its mnemonic: every downstream check compares raw 4/8-byte words, so a
disassembler that changed its mind about a mnemonic could not silently change
a verdict.
"""

import hashlib
import os
import re
import subprocess

ROCM_BIN = r"<ROCM_ROOT>\6.4\bin"
LLVM_OBJDUMP = os.path.join(ROCM_BIN, "llvm-objdump.exe")
LLVM_MC = os.path.join(ROCM_BIN, "llvm-mc.exe")
LLVM_OBJCOPY = os.path.join(ROCM_BIN, "llvm-objcopy.exe")
LLVM_READOBJ = os.path.join(ROCM_BIN, "llvm-readobj.exe")

CANDIDATE_F = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "phase16h_candidate_f", "gfx1030_dlssnr_candidate_f.co")
CANDIDATE_F_SHA = \
    "47b5d1d11041b034ac30eebac090ee922f415d8f08a0111e69641d7e0557524b"

# A disassembly line looks like
#     \tv_fma_f32 v10, 0x3e000000, v10, 1.0   // 00000000BC18: D54B000A 03CA14FF 3E000000
# and a branch may carry a symbol annotation after the bytes:
#     \ts_branch 17                           // 00000000BAD4: BF820011 <_Z16k_swin...>
# An AMDGPU instruction is 4, 8 or 12 bytes: 12 occurs when a 64-bit VOP3 is
# followed by its 32-bit literal constant (measured here: 6,977 such lines in
# Candidate F).  Dropping the annotation cost 6,933 lines on the first parse,
# which the tiling assertion in self_test() then caught.
_LINE = re.compile(
    r"^\s*(?P<text>.*?)\s*//\s*(?P<addr>[0-9A-Fa-f]{8,16}):\s*"
    r"(?P<bytes>[0-9A-Fa-f]{8}(?:\s[0-9A-Fa-f]{8})*)"
    r"(?:\s*<[^>]*>)?\s*$")

VALID_SIZES = (4, 8, 12)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


class Insn(object):
    __slots__ = ("addr", "raw", "size", "text", "mnemonic", "operands",
                 "word0", "word1")

    def __init__(self, addr, raw, text):
        self.addr = addr
        self.raw = raw
        self.size = len(raw)
        self.text = text
        parts = text.split(None, 1)
        self.mnemonic = parts[0] if parts else ""
        self.operands = parts[1] if len(parts) > 1 else ""
        self.word0 = int.from_bytes(raw[0:4], "little")
        self.word1 = int.from_bytes(raw[4:8], "little") if len(raw) >= 8 else None

    @property
    def is_64bit(self):
        return self.size == 8

    def __repr__(self):
        return "<%08X %s>" % (self.addr, self.text)


def disassemble(co_path, mcpu="gfx1030"):
    """Return (insns_by_addr, ordered_list, stderr_text).  Read-only."""
    p = subprocess.run([LLVM_OBJDUMP, "-d", "--mcpu=" + mcpu, co_path],
                       capture_output=True)
    out = p.stdout.decode("utf-8", "replace")
    err = p.stderr.decode("utf-8", "replace")
    by_addr, order = {}, []
    for line in out.splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        addr = int(m.group("addr"), 16)
        # llvm-objdump prints each 32-bit word as the big-endian hex rendering
        # of the little-endian word: the file holds 0A 00 4B D5, objdump
        # writes "D54B000A".  Measured against the file, not assumed.
        raw = b"".join(int(w, 16).to_bytes(4, "little")
                       for w in m.group("bytes").split())
        ins = Insn(addr, raw, m.group("text"))
        by_addr[addr] = ins
        order.append(ins)
    return by_addr, order, err


def sections(co_path):
    """{name: (addr, size)} plus the raw file offset, via llvm-objdump -h."""
    p = subprocess.run([LLVM_OBJDUMP, "-h", co_path], capture_output=True)
    secs = {}
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        f = line.split()
        if len(f) >= 4 and f[1].startswith("."):
            try:
                secs[f[1]] = {"size": int(f[2], 16), "vma": int(f[3], 16)}
            except ValueError:
                pass
    return secs


def text_and_kernarg(co_path):
    """Extract .text and the kernarg segment described by .note, to memory.

    Read-only with respect to `co_path`: every extraction goes through a
    temp file with an EXPLICIT output path (llvm-objcopy rewrites its input
    when given no output -- a defect already measured in this project).
    """
    import tempfile
    res = {}
    with tempfile.TemporaryDirectory() as td:
        for sec in ("text", "note", "rodata"):
            outp = os.path.join(td, sec + ".bin")
            subprocess.run([LLVM_OBJCOPY, "--dump-section",
                            "%s=%s" % (sec if sec != "text" else ".text", outp),
                            co_path], capture_output=True)
            if os.path.exists(outp):
                with open(outp, "rb") as f:
                    res[sec] = f.read()
    return res


def kernarg_segment_size(co_path):
    """(kernarg_segment_size, kernarg_segment_align, group_seg, priv_seg)."""
    p = subprocess.run([LLVM_READOBJ, "--amdgpu-kernel-arg-metadata-table",
                        "--amdgpu-code-properties", "--notes", co_path],
                       capture_output=True)
    txt = p.stdout.decode("utf-8", "replace")
    vals = {}
    for key, pat in (("kernarg_segment_size", r"\.kernarg_segment_size:\s*(\d+)"),
                     ("kernarg_segment_align", r"\.kernarg_segment_align:\s*(\d+)"),
                     ("group_segment_fixed_size",
                      r"\.group_segment_fixed_size:\s*(\d+)"),
                     ("private_segment_fixed_size",
                      r"\.private_segment_fixed_size:\s*(\d+)")):
        m = re.search(pat, txt)
        if m:
            vals[key] = int(m.group(1))
    return vals, txt


def text_bytes_at(co_path, addr, n):
    """Bytes of .text at a module-relative VMA, read from the file."""
    secs = sections(co_path)
    t = secs.get(".text")
    if not t:
        raise SystemExit("no .text in %s" % co_path)
    if not (t["vma"] <= addr < t["vma"] + t["size"]):
        raise ValueError("0x%X is outside .text [0x%X,0x%X)"
                         % (addr, t["vma"], t["vma"] + t["size"]))
    # ELF: find the file offset of .text via readelf-style parse
    off = _section_file_offset(co_path, ".text")
    with open(co_path, "rb") as f:
        f.seek(off + (addr - t["vma"]))
        return f.read(n)


def _section_file_offset(co_path, name):
    """Minimal ELF64 little-endian section-header parse for one offset."""
    import struct
    with open(co_path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit("not a little-endian ELF64: %s" % co_path)
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3a)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3c)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3e)[0]
    strtab_off = struct.unpack_from("<Q", data,
                                    e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        nm = struct.unpack_from("<I", data, base)[0]
        end = data.index(b"\x00", strtab_off + nm)
        if data[strtab_off + nm:end].decode() == name:
            return struct.unpack_from("<Q", data, base + 0x18)[0]
    raise SystemExit("no section %s in %s" % (name, co_path))


def self_test(co_path=CANDIDATE_F):
    """Prove the reader can fail, not just succeed."""
    problems = []
    got = sha256_file(co_path)
    if got != CANDIDATE_F_SHA:
        problems.append("candidate sha %s != %s" % (got, CANDIDATE_F_SHA))
    by_addr, order, err = disassemble(co_path)
    if not by_addr:
        problems.append("disassembly produced no instructions")
    # every instruction must be 4 or 8 bytes and lie inside .text
    secs = sections(co_path)
    t = secs.get(".text")
    for ins in order:
        if ins.size not in VALID_SIZES:
            problems.append("0x%X has size %d" % (ins.addr, ins.size))
            break
        if not (t["vma"] <= ins.addr < t["vma"] + t["size"]):
            problems.append("0x%X outside .text" % ins.addr)
            break
    # instruction slots must tile .text exactly: addr_{i+1} == addr_i + size_i
    for a, b in zip(order, order[1:]):
        if a.addr + a.size != b.addr:
            problems.append("gap/overlap at 0x%X -> 0x%X" % (a.addr, b.addr))
            break
    # the whole of .text must be covered, and every instruction's bytes must
    # equal the file's own bytes at that address
    total = sum(i.size for i in order)
    if total != t["size"]:
        problems.append(".text is %d bytes, instructions cover %d"
                        % (t["size"], total))
    # read .text from the FILE exactly once and compare every instruction's
    # bytes against it -- the earlier per-instruction version re-invoked
    # llvm-objdump for each address and never finished.
    off = _section_file_offset(co_path, ".text")
    with open(co_path, "rb") as f:
        f.seek(off)
        blob = f.read(t["size"])
    if len(blob) != t["size"]:
        problems.append(".text short read")
    ncmp = 0
    for ins in order:
        ncmp += 1
        lo = ins.addr - t["vma"]
        if blob[lo:lo + ins.size] != ins.raw:
            problems.append("file bytes != disassembled bytes at 0x%X"
                            % ins.addr)
            break
    # out-of-range must RAISE, not silently return
    try:
        text_bytes_at(co_path, 0x10, 4)
        problems.append("text_bytes_at(0x10) did not raise")
    except ValueError:
        pass
    return problems, {"n_insns": len(order),
                      "text_lo": hex(t["vma"]),
                      "text_hi": hex(t["vma"] + t["size"]),
                      "stderr": err.strip()[:200]}


if __name__ == "__main__":
    probs, info = self_test()
    print("self_test problems:", probs)
    print("info:", info)
