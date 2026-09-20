"""Phase 14D kernel-descriptor tooling.

ELF64 (EM_AMDGPU) reader for ET_REL .o and ET_DYN .co code objects:
  - section/symbol tables (handles .dynsym and .symtab + linked strtab)
  - maps every `<kernel>.kd` symbol to its file offset via its own
    section (ET_REL: section-relative value; ET_DYN: vaddr -> file off)
  - 64-byte amdhsa kernel descriptor accessor + field decode driven by an
    empirically measured bit map (see p14d_mcbitmap.py) instead of a
    memorized register layout.

Host-only, read-only on inputs.
"""
from __future__ import annotations

import struct

SHN_UNDEF = 0


def parse_elf(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b"\x7fELF", f"not ELF: {path}"
    assert data[4] == 2, "ELF64 expected"
    assert data[5] == 1, "little-endian expected"
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    assert e_shentsize == 64 and e_shnum > 0
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * 64
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
         sh_link, sh_info, sh_align, sh_entsize) = struct.unpack_from(
            "<IIQQQQIIQQ", data, off)
        sections.append(dict(idx=i, name_off=sh_name, type=sh_type,
                             flags=sh_flags, addr=sh_addr, offset=sh_offset,
                             size=sh_size, link=sh_link, info=sh_info,
                             entsize=sh_entsize))
    # section names
    shstr = sections[e_shstrndx]
    for s in sections:
        base = shstr["offset"] + s["name_off"]
        end = data.index(b"\0", base)
        s["name"] = data[base:end].decode("utf-8", "replace")
    # symbols
    syms = []
    for s in sections:
        if s["name"] not in (".symtab", ".dynsym") or s["type"] != 2:
            continue
        strtab = sections[s["link"]]
        entsize = s["entsize"] or 24
        for i in range(s["size"] // entsize):
            off = s["offset"] + i * entsize
            st_name, st_info, st_other, st_shndx = struct.unpack_from(
                "<IBBH", data, off)
            st_value, st_size = struct.unpack_from("<QQ", data, off + 8)
            end = data.index(b"\0", strtab["offset"] + st_name)
            name = data[strtab["offset"] + st_name:end].decode("utf-8", "replace")
            syms.append(dict(name=name, info=st_info, shndx=st_shndx,
                             value=st_value, size=st_size))
    return data, sections, syms


def kd_file_offset(sym, sections):
    """Map a .kd symbol to its descriptor's file offset."""
    if sym["shndx"] == SHN_UNDEF or sym["shndx"] >= len(sections):
        return None
    sec = sections[sym["shndx"]]
    # ET_DYN: value is a vaddr; ET_REL: value is relative to section start
    # (sh_addr is 0 in ET_REL). addr-mapping works for both.
    return sec["offset"] + (sym["value"] - sec["addr"])


def find_kernel_kds(data, sections, syms, want=None):
    """Return [(kernel_name, file_offset)] for 64-byte *.kd symbols."""
    out = []
    for sym in syms:
        if not sym["name"].endswith(".kd"):
            continue
        if sym["size"] not in (0, 64):
            continue
        kname = sym["name"][:-3]
        if want is not None and kname not in want:
            continue
        base = kd_file_offset(sym, sections)
        if base is None:
            continue
        if base + 64 > len(data):
            continue
        out.append((kname, base))
    return out


def dump_kd(data, base):
    """Raw 16 dwords of a kernel descriptor at file offset base."""
    if base is None:
        return None
    return struct.unpack_from("<16I", data, base)


def fmt_bits(dw, lo, hi):
    """Extract bit field [lo..hi] of dword dw as int."""
    mask = ((1 << (hi - lo + 1)) - 1) << lo
    return (dw & mask) >> lo
