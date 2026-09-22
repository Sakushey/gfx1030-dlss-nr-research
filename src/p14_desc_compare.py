"""Phase 14B static descriptor comparison (no GPU activity).

Decodes amdhsa 64-byte kernel descriptors (.kd) from code objects and
prints the fields that determine the entry convention:
  sizes (group/private/kernarg), compute_pgm_rsrc1/2, user_sgpr_count,
  wave32 flag, entry offset, vgpr/sgpr granules.

Targets:
  1. p14_diag_hidden.co  (hand-authored gfx1030 diagnostic, HIP6 7.1 mc/lld)
  2. ref_probe_dev.elf.o (stock HIP 6.4 clang gfx1030 kernel)
  3. phase5_exact_fragment/gfx1100_code_object.o (original upstream gfx1100
     kernel descriptor — the config that demonstrably ran on retail GPU)
"""
from __future__ import annotations

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

TARGETS = [
    ("p14_diag_hidden.co (hand-authored gfx1030)",
     os.path.join(HERE, "p14_diag_hidden.co")),
    ("ref_probe_dev.elf.o (stock HIP6.4 clang gfx1030)",
     os.path.join(HERE, "ref_probe_dev.elf.o")),
    ("gfx1100_code_object.o (original upstream gfx1100)",
     os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_code_object.o")),
]


def parse_elf(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b"\x7fELF", f"not ELF: {path}"
    is64 = data[4] == 2
    assert is64
    little = data[5] == 1
    endian = "<" if little else ">"
    e_shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from(endian + "H", data, 0x3A)[0]
    e_shnum = struct.unpack_from(endian + "H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from(endian + "H", data, 0x3E)[0]
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type = struct.unpack_from(endian + "II", data, off)
        sh_flags = struct.unpack_from(endian + "Q", data, off + 0x08)[0]
        sh_addr = struct.unpack_from(endian + "Q", data, off + 0x10)[0]
        sh_offset = struct.unpack_from(endian + "Q", data, off + 0x18)[0]
        sh_size = struct.unpack_from(endian + "Q", data, off + 0x20)[0]
        sh_link = struct.unpack_from(endian + "I", data, off + 0x28)[0]
        sh_info = struct.unpack_from(endian + "I", data, off + 0x2C)[0]
        sh_entsize = struct.unpack_from(endian + "Q", data, off + 0x38)[0]
        sections.append(dict(name=sh_name, type=sh_type, addr=sh_addr,
                             offset=sh_offset, size=sh_size, link=sh_link,
                             entsize=sh_entsize))
    shstr = sections[e_shstrndx]
    names = {}
    for i, s in enumerate(sections):
        base = shstr["offset"] + s["name"]
        end = data.index(b"\0", base)
        names[i] = data[base:end].decode("utf-8", "replace")
    for i, s in enumerate(sections):
        s["name"] = names.get(i, "?")
    return data, sections


def find_kd_symbols(data, sections):
    """Return list of (kernel_name, rodata_value, size) for *.kd symbols."""
    symtab = None
    strtab = None
    for s in sections:
        if s["name"] == ".dynsym" or s["name"] == ".symtab":
            symtab = s
            for t in sections:
                if t["name"] == ".dynstr" and t["offset"] != s["offset"] or \
                   t["name"] == ".strtab":
                    strtab = t
                    break
            if strtab is not None:
                break
    if symtab is None:
        return []
    out = []
    entsize = symtab["entsize"] or 24
    for i in range(symtab["size"] // entsize):
        off = symtab["offset"] + i * entsize
        st_name, st_info, st_other = struct.unpack_from("<IBB", data, off)
        st_shndx, = struct.unpack_from("<H", data, off + 6)
        st_value, st_size = struct.unpack_from("<QQ", data, off + 8)
        end = data.index(b"\0", strtab["offset"] + st_name)
        name = data[strtab["offset"] + st_name:end].decode("utf-8", "replace")
        if name.endswith(".kd") and st_size == 64:
            out.append((name[:-3], st_value, st_size))
    return out


def decode_descriptor(data, base):
    """base = file offset of the 64-byte descriptor."""
    endian = "<"
    group, private, kernarg, r0 = struct.unpack_from(
        endian + "IIII", data, base)
    rsrc1, rsrc2 = struct.unpack_from(endian + "II", data, base + 16)
    props, r1 = struct.unpack_from(endian + "II", data, base + 24)
    entry, = struct.unpack_from(endian + "Q", data, base + 48)
    return dict(group=group, private=private, kernarg=kernarg,
                rsrc1=rsrc1, rsrc2=rsrc2, entry=entry)


def describe(d):
    user_sgpr = d["rsrc2"] & 0x3F
    wave32 = (d["rsrc2"] >> 10) & 1
    vgpr_gran = d["rsrc1"] & 0x3F
    sgpr_gran = (d["rsrc1"] >> 6) & 0x3FF
    return (f"group={d['group']} private={d['private']} "
            f"kernarg={d['kernarg']} "
            f"rsrc1=0x{d['rsrc1']:08X} rsrc2=0x{d['rsrc2']:08X} "
            f"user_sgpr_count={user_sgpr} wave32={wave32} "
            f"vgpr_granule={vgpr_gran} sgpr_granule={sgpr_gran} "
            f"entry_off=0x{d['entry']:X}")

for label, path in TARGETS:
    print(f"===== {label} =====")
    if not os.path.exists(path):
        print("  (missing)")
        continue
    data, sections = parse_elf(path)
    rodata = None
    for s in sections:
        if s["name"] == ".rodata":
            rodata = s
    if rodata is None:
        print("  no .rodata"); continue
    kds = find_kd_symbols(data, sections)
    if not kds:
        print("  no .kd symbols found in dynsym/symtab")
    for kname, value, size in kds:
        base = value if value else rodata["offset"]
        if not (rodata["offset"] <= base < rodata["offset"] + rodata["size"]):
            # value is a virtual address; assume addr == offset mapping
            base = rodata["offset"] + (value - rodata["addr"]) if value else 0
        try:
            desc = decode_descriptor(data, base)
            print(f"  kernel {kname}: {describe(desc)}")
        except Exception as exc:  # noqa: BLE001
            print(f"  kernel {kname}: decode error {exc}")
