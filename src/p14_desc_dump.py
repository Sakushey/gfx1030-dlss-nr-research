"""Dump raw 64-byte kernel descriptors (16 dwords) for side-by-side
comparison. Static only; no GPU.
"""
from __future__ import annotations

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(HERE, "phase14_runtime") if False else HERE)
from p14_desc_compare import parse_elf, find_kd_symbols  # noqa: E402

TARGETS = [
    ("p14_diag_hidden (hand-authored gfx1030)",
     os.path.join(HERE, "p14_diag_hidden.co"), ["p14_diag_hidden"]),
    ("ref_probe (stock HIP6.4 clang gfx1030)",
     os.path.join(HERE, "ref_probe_dev.elf.o"), None),
    ("original upstream gfx1100 k_conv_splitk",
     os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_code_object.o"),
     ["_Z13k_conv_splitk12ConvParams1d"]),
    ("translated gfx1030 k_conv_splitk (phase9 module)",
     os.path.join(ROOT, "phase9_final_module", "gfx1030_dlssnr_module.co"),
     ["_Z13k_conv_splitk12ConvParams1d"]),
]

for label, path, want in TARGETS:
    print(f"===== {label} =====")
    if not os.path.exists(path):
        print("  (missing)"); continue
    data, sections = parse_elf(path)
    rodata = None
    for s in sections:
        if s["name"] == ".rodata":
            rodata = s
    kds = find_kd_symbols(data, sections)
    for kname, value, size in kds:
        if want is not None and kname not in want:
            continue
        # value is the symbol value; try addr, and addr==offset mapping
        base = value
        if rodata is not None and rodata["offset"] <= base < rodata["offset"] + rodata["size"]:
            pass
        elif rodata is not None and rodata["addr"] <= value < rodata["addr"] + rodata["size"]:
            base = rodata["offset"] + (value - rodata["addr"])
        else:
            print(f"  kernel {kname}: descriptor at 0x{value:X} outside .rodata, skipping")
            continue
        dwords = struct.unpack_from("<16I", data, base)
        print(f"  kernel {kname} (descriptor @ file 0x{base:X}):")
        for i in range(0, 16, 4):
            row = " ".join(f"{d:08X}" for d in dwords[i:i + 4])
            print(f"    dword[{i:2d}..{i + 3:2d}] {row}")
