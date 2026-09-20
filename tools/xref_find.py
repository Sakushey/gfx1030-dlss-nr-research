#!/usr/bin/env python3
"""Find RIP-relative LEA references to a target RVA in .text of a PE (no installs).
Usage: xref_find.py <pe> <target_rva> [extra_rva...]
Prints file offset of each lea and the RVA of the instruction.
"""
import sys, struct

def sections(data):
    e = struct.unpack_from('<I', data, 0x3C)[0]
    nsec = struct.unpack_from('<H', data, e+6)[0]
    optsz = struct.unpack_from('<H', data, e+20)[0]
    secs = []
    off = e + 24 + optsz
    for i in range(nsec):
        name = data[off:off+8].rstrip(b'\0').decode('ascii','replace')
        vsz, vaddr, rsz, roff = struct.unpack_from('<IIII', data, off+8)
        secs.append((name, vaddr, vsz, roff, rsz))
        off += 40
    return secs

def main(pe, targets):
    data = open(pe, 'rb').read()
    secs = sections(data)
    text = [s for s in secs if s[0] == '.text'][0]
    tname, tva, tvsz, toff, trsz = text
    text_bytes = data[toff:toff+tvsz]
    tset = set(int(t, 0) for t in targets)
    found = {}
    i = 0
    n = len(text_bytes)
    while i < n - 4:
        b = text_bytes[i]
        if b == 0x48 and i+6 < n and text_bytes[i+1] == 0x8d and text_bytes[i+2] in (0x05, 0x0d, 0x15, 0x1d):
            disp = struct.unpack_from('<i', text_bytes, i+3)[0]
            next_rva = tva + (i + 7)
            target = (next_rva + disp) & 0xFFFFFFFFFFFFFFFF
            if target in tset:
                found.setdefault(target, []).append((toff + i, tva + i))
            i += 7
        else:
            i += 1
    for t in tset:
        print(f"target rva 0x{t:08x}: {len(found.get(t, []))} xref(s)")
        for foff, rva in found.get(t, []):
            print(f"   insn file_off=0x{foff:08x} rva=0x{rva:08x}")
    return found

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2:])
