"""Minimal ELF/AMDGPU metadata reader (host-only, read-only).

Reads .note.amdgpu.metadata (JSON) of the original gfx1100 object and the
translated gfx1030 code object, plus kernel descriptor words when present.
Answers Phase 8C questions: user-SGPR preload configuration (what s[0:1]
holds), kernarg segment size, wavefront, resource counts (sgpr/vgpr), and
Q9 (metadata vs actual register usage).
"""
import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from disasm_lib import parse_translated_asm


def read_elf_sections(path):
    """Return list of (name, type, offset, size, data) for SHDR sections."""
    data = open(path, "rb").read()
    assert data[:4] == b"\x7fELF"
    ei_class = data[4]
    le = data[5] == 1
    endian = "<" if le else ">"
    if ei_class == 1:
        raise ValueError("32-bit ELF not supported")
    (e_shoff,) = struct.unpack_from(endian + "Q", data, 0x28)
    (e_shentsize,) = struct.unpack_from(endian + "H", data, 0x3A)
    (e_shnum,) = struct.unpack_from(endian + "H", data, 0x3C)
    (e_shstrndx,) = struct.unpack_from(endian + "H", data, 0x3E)
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type = struct.unpack_from(endian + "II", data, off)
        sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
            endian + "QQQQ", data, off + 8)
        secs.append((sh_name, sh_type, sh_offset, sh_size, data[sh_offset:sh_offset + sh_size]))
    # string table for names
    name_sec = secs[e_shstrndx]
    strings = name_sec[4]
    out = []
    for sh_name, sh_type, sh_offset, sh_size, sdata in secs:
        end = sdata.find(b"\0", sh_name) if sh_name < len(strings) else -1
        # names index into the *string table section*, offsets absolute to
        # that section's data start
        name = ""
        if sh_name < len(strings):
            e = strings.find(b"\0", sh_name)
            name = strings[sh_name:e].decode()
        out.append((name, sh_type, sh_offset, sh_size, sdata))
    return out


def note_metadata(path):
    """Return dict of kernel symbol -> metadata JSON for .note.amdgpu.metadata
    (and .note.amd.amdgpu.metadata variants)."""
    secs = read_elf_sections(path)
    res = {}
    for name, sh_type, sh_offset, sh_size, sdata in secs:
        if name not in (".note.amdgpu.metadata", ".note.amd.amdgpu.metadata"):
            continue
        # notes: namesz(4) descsz(4) type(4) name pad desc
        pos = 0
        while pos + 12 <= len(sdata):
            namesz, descsz, ntype = struct.unpack_from("<III", sdata, pos)
            name_b = sdata[pos + 12: pos + 12 + namesz]
            desc_off = pos + 12 + ((namesz + 3) & ~3)
            desc = sdata[desc_off: desc_off + descsz]
            txt = desc.decode("utf-8", "replace")
            try:
                obj = json.loads(txt)
                for k in obj:
                    if k == "amdhsa.kernels":
                        for kern in obj[k]:
                            res[kern.get(".name", kern.get("name", "?"))] = kern
                    else:
                        res[k] = obj[k]
            except json.JSONDecodeError:
                pass
            pos = desc_off + ((descsz + 3) & ~3)
    return res


def kernel_descriptors(path):
    """Return dict name -> 64-byte descriptor for *.kd symbols (relocatable)
    or sections named *.kd (linked code objects)."""
    data = open(path, "rb").read()
    secs = read_elf_sections(path)
    descs = {}
    for name, sh_type, sh_offset, sh_size, sdata in secs:
        if name.endswith(".kd") and sh_size >= 0x40:
            descs[name] = sdata[:0x40]
    return descs


def describe(preload):
    """Translate preload boolean dict into s-register slot mapping."""
    order = [
        ("dispatch_ptr", 2), ("queue_ptr", 2), ("kernarg_segment_ptr", 2),
        ("private_segment_buffer", 4), ("tba", 2), ("tma", 2),
        ("flat_scratch", 2), ("xnack_mask", 1),
    ]
    slots = {}
    sgpr = 0
    for key, width in order:
        if preload.get("amdhsa.system_sgpr_" + key, False):
            slots[key] = (sgpr, sgpr + width - 1)
            sgpr += width
    # workgroup-id/grid/group-size/order booleans (v4/v5 metadata)
    extra = [
        ("workgroup_id_x", 1), ("workgroup_id_y", 1), ("workgroup_id_z", 1),
        ("workgroup_info", 1), ("private_segment_wavefront_offset", 1),
        ("workitem_id_x", 1), ("workitem_id_y", 1), ("workitem_id_z", 1),
    ]
    for key, width in extra:
        if preload.get("amdhsa.system_sgpr_" + key, False):
            slots[key] = (sgpr, sgpr + width - 1)
            sgpr += width
    return slots, sgpr


def show_kernel(path, symbol, label):
    meta = note_metadata(path)
    kern = meta.get(symbol)
    print(f"--- {label} [{os.path.basename(path)}] kernel {symbol} ---")
    if not kern:
        print("  no metadata note entry for", symbol)
        return None
    keys = [
        "amdhsa.kernarg_segment_size", "amdhsa.group_segment_fixed_size",
        "amdhsa.private_segment_fixed_size", "amdhsa.sgpr_count",
        "amdhsa.vgpr_count", "amdhsa.wavefront_size",
        "amdhsa.max_flat_workgroup_size", "amdhsa.user_sgpr_count",
        "amdhsa.next_free_vgpr", "amdhsa.next_free_sgpr",
    ]
    for k in keys:
        if k in kern:
            print(f"  {k} = {kern[k]}")
    pre = {k: v for k, v in kern.items() if k.startswith("amdhsa.system_sgpr")}
    slots, total = describe(pre)
    print("  system_sgpr preloads:", pre)
    print("  preload slot map:", slots, "=> preloaded sgprs 0..%d" % (total - 1) if total else "none")
    return kern


def granulated(vgpr, sgpr):
    return vgpr, sgpr


if __name__ == "__main__":
    target = os.path.join(ROOT, "phase7_translation", "k_conv_splitk_translated_gfx1030.co")
    orig = os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_code_object.o")
    if "--translated" in sys.argv or len(sys.argv) == 1:
        show_kernel(target, "_Z13k_conv_splitk12ConvParams1d", "TRANSLATED")
        for name, d in kernel_descriptors(target).items():
            rsrc1 = struct.unpack_from("<I", d, 0x10)[0]
            rsrc2 = struct.unpack_from("<I", d, 0x14)[0]
            gran_vgpr = (rsrc1 & 0x3F)
            gran_sgpr = (rsrc1 >> 6) & 0x3F
            print(f"  descriptor {name}: rsrc1 vgpr_granule={gran_vgpr} "
                  f"sgpr_granule={gran_sgpr} user_sgpr_count={(rsrc2 & 0x3F)}")
    if "--original" in sys.argv or len(sys.argv) == 1:
        show_kernel(orig, "_Z13k_conv_splitk12ConvParams1d", "ORIGINAL")
        for name, d in kernel_descriptors(orig).items():
            if "conv_splitk" not in name:
                continue
            rsrc1 = struct.unpack_from("<I", d, 0x10)[0]
            rsrc2 = struct.unpack_from("<I", d, 0x14)[0]
            print(f"  descriptor {name}: vgpr_granule={(rsrc1 & 0x3F)} "
                  f"sgpr_granule=((rsrc1 >> 6) & 0x3F) user_sgpr_count={(rsrc2 & 0x3F)}")
            print(f"    rsrc1={rsrc1:#x} rsrc2={rsrc2:#x} "
                  f"group_seg={struct.unpack_from('<I', d, 0)[0]} "
                  f"priv_seg={struct.unpack_from('<I', d, 4)[0]} "
                  f"entry_off={struct.unpack_from('<I', d, 8)[0]:#x}")
