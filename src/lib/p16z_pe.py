"""Read a PE's real import table.

A raw byte scan for b"amdhip64_7.dll" finds the harness's own FORBIDDEN-NAME
string constant, which is in the data section precisely so the harness can
name the module it refuses to run with.  That is not an import, and reading it
as one would either condemn a correct binary or bless a wrong one, depending
on which way the mistake went.  This walks the import directory instead.
"""

import struct
import sys


def imports(path):
    d = open(path, "rb").read()
    if d[:2] != b"MZ":
        raise SystemExit("not a PE: %s" % path)
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    if d[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("no PE signature: %s" % path)
    coff = e_lfanew + 4
    n_sections = struct.unpack_from("<H", d, coff + 2)[0]
    opt_size = struct.unpack_from("<H", d, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", d, opt)[0]
    if magic != 0x20B:
        raise SystemExit("not PE32+: magic 0x%X" % magic)
    # data directory 1 = import table
    dd = opt + 112
    imp_rva, imp_size = struct.unpack_from("<II", d, dd + 8)
    secs = []
    so = opt + opt_size
    for i in range(n_sections):
        b = so + i * 40
        name = d[b:b + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", d, b + 8)
        secs.append((name, va, max(vsize, rsize), rptr))

    def rva2off(rva):
        for _n, va, sz, pr in secs:
            if va <= rva < va + sz:
                return pr + (rva - va)
        return None

    out = []
    off = rva2off(imp_rva)
    if off is None:
        return out
    while True:
        ent = d[off:off + 20]
        if len(ent) < 20 or ent == b"\0" * 20:
            break
        name_rva = struct.unpack_from("<I", ent, 12)[0]
        if name_rva == 0:
            break
        no = rva2off(name_rva)
        end = d.index(b"\0", no)
        out.append(d[no:end].decode("ascii", "replace"))
        off += 20
    return out


if __name__ == "__main__":
    for p in sys.argv[1:]:
        imps = imports(p)
        low = [i.lower() for i in imps]
        print("%s" % p)
        print("   %d imports" % len(imps))
        print("   %s" % ", ".join(sorted(imps)))
        print("   amdhip64_6.dll imported : %s" % ("amdhip64_6.dll" in low))
        print("   amdhip64_7.dll imported : %s" % ("amdhip64_7.dll" in low))
