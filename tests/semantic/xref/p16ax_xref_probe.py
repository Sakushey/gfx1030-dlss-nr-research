#!/usr/bin/env python3
"""T-XREF probe: dump raw bytes at VOPD sites from the parent symbol.

Reads ONLY primary neutral evidence:
  p16aw/provenance/ACTUAL_PARENT_sym_raw.bin  (raw object bytes of the symbol)
  p16aw/vopd/ACTUAL_PARENT_sym.dis            (llvm-objdump text, an INDEPENDENT decoder)

The point of this probe is to establish the VOPD bit layout from the raw bytes,
cross-checked against LLVM's own text.  It never reads another worker's model.
"""
import hashlib
import os
import struct
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
BIN = os.path.join(ROOT, "p16aw", "provenance", "ACTUAL_PARENT_sym_raw.bin")
BASE = 0xC4000                      # symbol_va for _Z10k_swin_varILi32ELb0EEv9VarParams
EXPECT_SHA = "0f7af5614e696e7a9a1df8a67f5ada0bfc7c1a3940d70affd4e30f6e03e83e75"
EXPECT_SIZE = 87320


def main():
    raw = open(BIN, "rb").read()
    sha = hashlib.sha256(raw).hexdigest()
    print("bin      :", BIN)
    print("size     :", len(raw), "(expected", EXPECT_SIZE, ")")
    print("sha256   :", sha)
    print("sha_match:", sha == EXPECT_SHA and len(raw) == EXPECT_SIZE)
    print()

    addrs = [0xC42D8, 0xC43AC, 0xC71E4, 0xC7608, 0xC7720, 0xC86E0,
             0xC8A74, 0xC9538, 0xC91A4, 0xC6118, 0xCB8D8, 0xCB8DC, 0xC4578]
    for a in addrs:
        off = a - BASE
        blob = raw[off:off + 16]
        d = struct.unpack_from("<4I", blob)
        print("0x%X  off=0x%X  d0=%08X d1=%08X d2=%08X d3=%08X" %
              (a, off, d[0], d[1], d[2], d[3]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
