#!/usr/bin/env python3
"""PE constant/string scanner - static analysis helper (no installs, stdlib only).
Scans a PE file for: (a) dword constants of interest in ALL sections,
(b) ASCII strings matching patterns. Prints RVA + section + context.
"""
import sys, struct, re

PATTERNS = {
    0x00010001: "FFX?type 0x10001",
    0x00020003: "FFX?type 0x20003",
    0x00010002: "cand 0x10002",
    0x00020001: "cand 0x20001",
    0x00020002: "cand 0x20002",
    0x00030001: "cand 0x30001",
    0x00030002: "cand 0x30002",
    0x00040001: "cand 0x40001",
    0x00040003: "cand 0x40003",
    0x00000001: "one (noise)",
}

def pe_sections(data):
    if data[:2] != b'MZ':
        raise ValueError("not PE")
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew+4] == b'PE\0\0'
    nsec = struct.unpack_from('<H', data, e_lfanew+6)[0]
    optsz = struct.unpack_from('<H', data, e_lfanew+20)[0]
    sec = []
    off = e_lfanew + 24 + optsz
    for i in range(nsec):
        name = data[off:off+8].rstrip(b'\0').decode('ascii', 'replace')
        vsz, vaddr, rsz, roff = struct.unpack_from('<IIII', data, off+8)
        sec.append((name, vaddr, vsz, roff, rsz))
        off += 40
    return sec

def rva_of(secs, foff):
    for name, va, vsz, ro, rs in secs:
        if ro <= foff < ro + max(rs, vsz):
            return name, va + (foff - ro)
    return None, None

def scan(data, secs, consts):
    hits = []
    pat_bytes = {c: struct.pack('<I', c) for c in consts}
    # byte-reverse scan for qword (8-byte) constants too? keep dword; skip movabs-heavy code regions note
    for c, b in pat_bytes.items():
        start = 0
        while True:
            i = data.find(b, start)
            if i < 0: break
            sec, rva = rva_of(secs, i)
            if sec and sec in (b'.text', b'.rdata', b'.data'):
                ctx = data[max(0,i-12):i+16]
                hits.append((c, i, rva, sec, ctx.hex(' ')))
            start = i + 1
    return hits

def find_strings(data):
    out = []
    for m in re.finditer(rb'[\x20-\x7e]{5,}', data):
        s = m.group().decode('ascii')
        if re.search(r'ffx|Fsr|fsr|staging|residual|network job|route |backbuffer|ready|submitted|dispatch', s, re.I):
            out.append((m.start(), s))
    return out

def main(path):
    data = open(path, 'rb').read()
    secs = pe_sections(data)
    print(f"== {path}  size={len(data)}")
    print("sections:", [(n.decode() if isinstance(n,bytes) else n, hex(va), vsz) for n, va, vsz, _, _ in secs])
    consts = [c for c in PATTERNS if c != 0x00000001]
    hits = scan(data, secs, consts)
    print(f"\n== dword constant hits (text/rdata/data): {len(hits)}")
    for c, foff, rva, sec, ctx in hits:
        print(f"0x{c:08x} {PATTERNS.get(c,'?')}  rva=0x{rva:08x} sec={sec} off=0x{foff:08x} ctx: {ctx}")
    # qword forms of the two big ones
    for c in (0x00010001, 0x00020003, 0x00020002):
        qb = struct.pack('<Q', c)
        start = 0
        while True:
            i = data.find(qb, start)
            if i < 0: break
            sec, rva = rva_of(secs, i)
            if sec in (b'.text', b'.rdata', b'.data'):
                print(f"qword 0x{c:016x} rva=0x{rva:08x} sec={sec} off=0x{i:08x}")
            start = i + 1
    print(f"\n== string hits: ", end="")
    strs = find_strings(data)
    print(len(strs))
    for off, s in strs:
        sec, rva = rva_of(secs, off)
        print(f"0x{off:08x} rva=0x{rva:08x} [{sec}] {s[:160]}")

if __name__ == '__main__':
    main(sys.argv[1])
