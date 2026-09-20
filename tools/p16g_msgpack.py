"""Minimal msgpack decoder (Phase16G, host-only, no third-party deps).

Only the subset needed to read the AMDGPU metadata note of a code object:
nil/bool/int/str/bin/array/map.  Returns python objects; byte strings are
returned as `bytes`, everything else native.
"""
from __future__ import annotations

import struct


class MpkError(Exception):
    pass


def _u(b, i, n):
    return int.from_bytes(b[i:i + n], "big"), i + n


def unpack(b: bytes, i: int = 0):
    if i >= len(b):
        raise MpkError("truncated")
    c = b[i]
    i += 1
    if c <= 0x7F:                       # positive fixint
        return c, i
    if c >= 0xE0:                       # negative fixint
        return c - 0x100, i
    if 0x80 <= c <= 0x8F:               # fixmap
        return _map(b, i, c & 0x0F)
    if 0x90 <= c <= 0x9F:               # fixarray
        return _arr(b, i, c & 0x0F)
    if 0xA0 <= c <= 0xBF:               # fixstr
        n = c & 0x1F
        return b[i:i + n].decode("utf-8", "replace"), i + n
    if c == 0xC0:
        return None, i
    if c == 0xC2:
        return False, i
    if c == 0xC3:
        return True, i
    if c == 0xC4:
        n, i = _u(b, i, 1)
        return bytes(b[i:i + n]), i + n
    if c == 0xC5:
        n, i = _u(b, i, 2)
        return bytes(b[i:i + n]), i + n
    if c == 0xC6:
        n, i = _u(b, i, 4)
        return bytes(b[i:i + n]), i + n
    if c == 0xCA:
        return struct.unpack_from(">f", b, i)[0], i + 4
    if c == 0xCB:
        return struct.unpack_from(">d", b, i)[0], i + 8
    if c == 0xCC:
        return b[i], i + 1
    if c == 0xCD:
        return _u(b, i, 2)
    if c == 0xCE:
        return _u(b, i, 4)
    if c == 0xCF:
        return _u(b, i, 8)
    if c == 0xD0:
        return struct.unpack_from(">b", b, i)[0], i + 1
    if c == 0xD1:
        return struct.unpack_from(">h", b, i)[0], i + 2
    if c == 0xD2:
        return struct.unpack_from(">i", b, i)[0], i + 4
    if c == 0xD3:
        return struct.unpack_from(">q", b, i)[0], i + 8
    if c == 0xD9:
        n, i = _u(b, i, 1)
        return b[i:i + n].decode("utf-8", "replace"), i + n
    if c == 0xDA:
        n, i = _u(b, i, 2)
        return b[i:i + n].decode("utf-8", "replace"), i + n
    if c == 0xDB:
        n, i = _u(b, i, 4)
        return b[i:i + n].decode("utf-8", "replace"), i + n
    if c == 0xDC:
        n, i = _u(b, i, 2)
        return _arr(b, i, n)
    if c == 0xDD:
        n, i = _u(b, i, 4)
        return _arr(b, i, n)
    if c == 0xDE:
        n, i = _u(b, i, 2)
        return _map(b, i, n)
    if c == 0xDF:
        n, i = _u(b, i, 4)
        return _map(b, i, n)
    raise MpkError("byte 0x%02x at %d unsupported" % (c, i - 1))


def _arr(b, i, n):
    out = []
    for _ in range(n):
        v, i = unpack(b, i)
        out.append(v)
    return out, i


def _map(b, i, n):
    out = {}
    for _ in range(n):
        k, i = unpack(b, i)
        v, i = unpack(b, i)
        out[k] = v
    return out, i


def parse_note(blob: bytes):
    """Parse an ELF note section -> list of (name, type, desc_bytes)."""
    out = []
    i = 0
    while i + 12 <= len(blob):
        namesz, descsz, ntype = struct.unpack_from("<III", blob, i)
        i += 12
        name = blob[i:i + namesz].rstrip(b"\0").decode("utf-8", "replace")
        i += (namesz + 3) & ~3
        desc = blob[i:i + descsz]
        i += (descsz + 3) & ~3
        out.append((name, ntype, desc))
    return out


def parse_amdgpu_metadata(desc: bytes):
    """The AMDGPU metadata note payload: 'AMDGPU\\0' + msgpack map."""
    if desc[:6] != b"AMDGPU":
        raise MpkError("not an AMDGPU metadata note: %r" % desc[:8])
    j = 6
    if desc[6:7] == b"\0":
        j = 7
    obj, _ = unpack(desc, j)
    return obj


if __name__ == "__main__":
    import sys
    blob = open(sys.argv[1], "rb").read()
    for name, ntype, desc in parse_note(blob):
        print("note", name, ntype, len(desc))
        if name == "AMDGPU":
            md = parse_amdgpu_metadata(desc)
            print("top keys:", list(md))
