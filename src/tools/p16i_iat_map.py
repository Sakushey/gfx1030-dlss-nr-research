#!/usr/bin/env python3
"""Phase 16I -- map a PE's IAT slots to import names, then find the indirect
call sites in .text that use a chosen slot.

Read-only: opens the PE for reading, writes nothing back to it.

Usage:
  p16i_iat_map.py <pe> [symbol ...]
"""
from __future__ import annotations

import struct
import sys


def parse(pe):
    data = open(pe, "rb").read()
    e = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e:e + 4] == b"PE\0\0"
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    optsz = struct.unpack_from("<H", data, e + 20)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32plus = magic == 0x20B
    image_base = struct.unpack_from("<Q" if pe32plus else "<I", data, opt + 24)[0]
    ddir = opt + (112 if pe32plus else 96)
    imp_rva, imp_sz = struct.unpack_from("<II", data, ddir + 8)
    secs = []
    off = opt + optsz
    for _ in range(nsec):
        name = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsz, vaddr, rsz, roff = struct.unpack_from("<IIII", data, off + 8)
        secs.append((name, vaddr, vsz, roff, rsz))
        off += 40
    return data, secs, image_base, imp_rva


def rva_to_off(secs, rva):
    for _n, va, vsz, ro, rs in secs:
        if va <= rva < va + max(vsz, rs):
            return ro + (rva - va)
    return None


def imports(data, secs, imp_rva):
    """Yield (dll, symbol, iat_rva) in IAT order."""
    out = []
    off = rva_to_off(secs, imp_rva)
    while True:
        oft, ts, fc, name_rva, ft = struct.unpack_from("<IIIII", data, off)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        no = rva_to_off(secs, name_rva)
        dll = data[no:data.index(b"\0", no)].decode("ascii", "replace")
        thunk_rva = oft if oft else ft
        iat_rva = ft
        i = 0
        while True:
            to = rva_to_off(secs, thunk_rva + i * 8)
            v = struct.unpack_from("<Q", data, to)[0]
            if v == 0:
                break
            if v & (1 << 63):
                sym = "ord#%d" % (v & 0xFFFF)
            else:
                so = rva_to_off(secs, v)
                sym = data[so + 2:data.index(b"\0", so + 2)].decode("ascii", "replace")
            out.append((dll, sym, iat_rva + i * 8))
            i += 1
        off += 20
    return out


def indirect_call_sites(data, secs, iat_rva):
    """All `ff 15 disp32` (call qword ptr [rip+disp]) whose target == iat_rva."""
    text = [s for s in secs if s[0] == ".text"][0]
    _n, tva, tvsz, toff, _rs = text
    tb = data[toff:toff + tvsz]
    hits = []
    i = 0
    n = len(tb)
    while i < n - 6:
        if tb[i] == 0xFF and tb[i + 1] == 0x15:
            disp = struct.unpack_from("<i", tb, i + 2)[0]
            tgt = tva + (i + 6) + disp
            if tgt == iat_rva:
                hits.append(tva + i)
            i += 6
        else:
            i += 1
    return hits


def main():
    pe = sys.argv[1]
    want = sys.argv[2:]
    data, secs, base, imp_rva = parse(pe)
    imps = imports(data, secs, imp_rva)
    print("image_base=0x%x  imports=%d" % (base, len(imps)))
    iat_lo = min(x[2] for x in imps)
    iat_hi = max(x[2] for x in imps)
    print("IAT rva range 0x%x..0x%x  (VA 0x%x..0x%x)"
          % (iat_lo, iat_hi, base + iat_lo, base + iat_hi))
    if not want:
        for dll, sym, r in imps:
            print("  va=0x%x  %s!%s" % (base + r, dll, sym))
        return
    for w in want:
        for dll, sym, r in imps:
            if w.lower() in sym.lower():
                sites = indirect_call_sites(data, secs, r)
                print("\n%s!%s  iat_va=0x%x  callsites=%d"
                      % (dll, sym, base + r, len(sites)))
                for s in sites:
                    print("    call site va=0x%x" % (base + s))


if __name__ == "__main__":
    main()
