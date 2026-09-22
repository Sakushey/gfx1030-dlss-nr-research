"""Phase 14E-F3: map __hipRegisterFunction sites -> kernel names -> stub addrs,
then find hipLaunchKernel call sites passing the swin_var<32,false> stub.

Read-only static analysis of version.dll.static_copy + host_full_disasm.txt.
"""
from __future__ import annotations

import os
import re
import struct

ROOT = r"<PROJECT_ROOT>"
VENDOR = os.path.join(ROOT, "phase5_exact_fragment", "version.dll.static_copy")
DIS = os.path.join(ROOT, "phase14e_forensics", "out", "host_full_disasm.txt")
OUTDIR = os.path.join(ROOT, "phase14e_forensics", "out")
TOOLSD = os.path.join(ROOT, "phase14e_forensics", "tools")

# ---------- PE helpers ----------

def sections(data):
    pe = int.from_bytes(data[0x3C:0x40], "little")
    nsec = int.from_bytes(data[pe + 6:pe + 8], "little")
    optsz = int.from_bytes(data[pe + 20:pe + 22], "little")
    base = pe + 24 + optsz
    secs = []
    IMG = 0x180000000  # image base: section VirtualAddress is an RVA; disasm shows VA
    for i in range(nsec):
        off = base + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("latin1")
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, off + 8)
        secs.append((name, vaddr + IMG, vsize, roff, rsize))
    return secs

def off_to_rva(secs, idx):
    for _n, vaddr, _vs, roff, rsize in secs:
        if roff <= idx < roff + rsize:
            return vaddr + (idx - roff)
    return None

def rva_to_off(secs, rva):
    for _n, vaddr, _vs, roff, rsize in secs:
        if vaddr <= rva < vaddr + rsize:
            return roff + (rva - vaddr)
    return None

def find_all(data, needle):
    out, i = [], 0
    while True:
        j = data.find(needle, i)
        if j < 0:
            return out
        out.append(j)
        i = j + 1

# ---------- disasm ----------

def load_disasm(path):
    """Return list of (va, text_without_va_prefix)."""
    lines = []
    for raw in open(path, encoding="utf-8", errors="replace"):
        raw = raw.rstrip("\n")
        m = re.match(r"^([0-9a-f]{8,}): (.*)$", raw)
        if m:
            lines.append((int(m.group(1), 16), raw))
    return lines

def find_line(lines, va):
    """index of line whose address == va (first)."""
    import bisect
    v = [a for a, _ in lines]
    i = bisect.bisect_left(v, va)
    if i < len(v) and v[i] == va:
        return i
    return -1

def main():
    data = open(VENDOR, "rb").read()
    secs = sections(data)
    lines = load_disasm(DIS)
    vasi = [a for a, _ in lines]

    # 1) collect kernel-name style strings in host data sections (.rdata/.data etc,
    #    i.e. outside .text and .hip_fat)
    text_rva = 0x180001000
    text_size = 0x532c6
    names = {}
    for m in re.finditer(rb"(_Z\d{1,2}[A-Za-z_][A-Za-z0-9_~]{2,})", data):
        rva = off_to_rva(secs, m.start())
        if rva is None:
            continue
        # keep only host data sections (.rdata/.data/.retarc/_RDATA/.retard), not fatbin
        if not (0x180055000 <= rva < 0x180074200) and not (0x18044a000 <= rva < 0x18044e1f4):
            continue
        s = m.group(1).decode()
        names.setdefault(s, []).append(rva)
    # only complete 33-kernel set = names whose string ends with a params type etc.
    # filter: keep names containing "VarParams" or listed kernels patterns we know
    ker = {k: v for k, v in names.items() if ("Params" in k or "k_" in k)}
    print(f"host-name candidates: {len(ker)}")
    for k, v in sorted(ker.items()):
        print(f"  {v}  {k}")

    # 2) for each name string rva find registration lea rdx refs in .text
    # registration pattern: lea rdx, [rip+..] # <string rva>
    def rip_refs_of(rva):
        res = []
        for va, raw in lines:
            # comment resolved address
            cm = re.search(r"# 0x([0-9a-f]+)$", raw)
            if cm and int(cm.group(1), 16) == rva:
                res.append(va)
        return res

    regs = []
    for k, rvas in sorted(ker.items()):
        for srva in rvas:
            refs = rip_refs_of(srva)
            for ref in refs:
                # context: which register got the lea, look ahead for call
                i = vasi.index(ref) if ref in vasi else -1
                reg = None
                mi = re.search(r"lea\s+([a-z0-9]+),\s*\[rip", lines[i][1]) if i >= 0 else None
                if mi:
                    reg = mi.group(1)
                regs.append((srva, k, ref, reg))
    print(f"\nregistration refs found: {len(regs)}")
    for r in regs:
        print(f"  str@0x{r[0]:x} reg={r[3]} ref@0x{r[2]:x} {r[1]}")

    # 3) for the target name, dump window and find stub in rcx
    TARGET = "_Z10k_swin_varILi32ELb0EEv9VarParams"
    trows = [r for r in regs if r[1] == TARGET]
    out = []
    for srva, k, ref, reg in trows:
        i = vasi.index(ref)
        lo, hi = max(0, i - 10), min(len(lines), i + 20)
        out.append(f"=== registration window for {k} str@0x{srva:x} ref@0x{ref:x} ===")
        for j in range(lo, hi):
            out.append(lines[j][1])
    open(os.path.join(OUTDIR, "p14e_swin32_reg_windows.txt"), "w", encoding="utf-8").write("\n".join(out) + "\n")
    print(f"\nwrote registration windows -> {os.path.join(OUTDIR, 'p14e_swin32_reg_windows.txt')}")

if __name__ == "__main__":
    main()
