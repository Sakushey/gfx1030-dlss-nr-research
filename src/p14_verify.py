"""Phase 14B pre-launch static verification of p14_diag_hidden.co.

Decodes the AMDGPU metadata note (msgpack) independently of the emitter and
checks the kernel record against the intended Phase 9-style ABI:
48-byte by_value user arg + 13 hidden args at the original offsets,
304-byte kernarg segment, gfx1030 target, declared resources >= usage.
Host-only. No GPU.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "phase9_static", "tools"))
from p9_meta import canon, note_metadata  # noqa: E402

CO = os.path.join(HERE, "p14_diag_hidden.co")

EXPECTED_ARGS = [
    (0, 48, "by_value"),
    (48, 4, "hidden_block_count_x"),
    (52, 4, "hidden_block_count_y"),
    (56, 4, "hidden_block_count_z"),
    (60, 2, "hidden_group_size_x"),
    (62, 2, "hidden_group_size_y"),
    (64, 2, "hidden_group_size_z"),
    (66, 2, "hidden_remainder_x"),
    (68, 2, "hidden_remainder_y"),
    (70, 2, "hidden_remainder_z"),
    (88, 8, "hidden_global_offset_x"),
    (96, 8, "hidden_global_offset_y"),
    (104, 8, "hidden_global_offset_z"),
    (112, 2, "hidden_grid_dims"),
]

meta = note_metadata(CO)
if meta is None:
    sys.exit("FAIL: no AMDGPU metadata note decoded from .co")

top = meta["top"]
if top.get("amdhsa.target") != "amdgcn-amd-amdhsa--gfx1030":
    sys.exit(f"FAIL: target {top.get('amdhsa.target')}")
if top.get("amdhsa.version") != [1, 2]:
    sys.exit(f"FAIL: amdhsa.version {top.get('amdhsa.version')}")

kernels = meta["kernels"]
if len(kernels) != 1:
    sys.exit(f"FAIL: {len(kernels)} kernel records, expected 1")

k = canon(kernels[0])
print(f"kernel name           : {k.get('.name')}")
print(f"symbol                : {k.get('.symbol')}")
print(f"kernarg_segment_size  : {k.get('.kernarg_segment_size')}")
print(f"kernarg_segment_align : {k.get('.kernarg_segment_align')}")
print(f"group_segment_fixed   : {k.get('.group_segment_fixed_size')}")
print(f"private_segment_fixed : {k.get('.private_segment_fixed_size')}")
print(f"vgpr_count            : {k.get('.vgpr_count')}")
print(f"sgpr_count            : {k.get('.sgpr_count')}")
print(f"max_flat_workgroup    : {k.get('.max_flat_workgroup_size')}")
print(f"wavefront_size        : {k.get('.wavefront_size')}")
print(f"args count            : {len(k.get('.args', []))}")

got_args = [(a.get(".offset"), a.get(".size"), a.get(".value_kind"))
            for a in k.get(".args", [])]
if got_args != EXPECTED_ARGS:
    print("FAIL: .args mismatch")
    for g in got_args:
        print("  got", g)
    sys.exit(1)

checks = {
    ".name": "p14_diag_hidden",
    ".kernarg_segment_size": 304,
    ".kernarg_segment_align": 8,
    ".group_segment_fixed_size": 0,
    ".private_segment_fixed_size": 0,
    ".vgpr_count": 8,
    ".sgpr_count": 16,
    ".max_flat_workgroup_size": 256,
    ".wavefront_size": 32,
}
for key, expected in checks.items():
    if k.get(key) != expected:
        sys.exit(f"FAIL: {key} = {k.get(key)!r}, expected {expected!r}")

# resource sanity: declared counts must cover actual usage (vgprs v0..v5,
# sgprs s0..s9 from the disassembly) and hidden reads map to the fields
# the kernel code reads: 0x3c group_size_x, 0x40 group_size_z, 0x30 block_x
offsets = {a.get(".value_kind"): a.get(".offset")
           for a in k.get(".args", [])}
assert offsets["hidden_group_size_x"] == 0x3C
assert offsets["hidden_group_size_y"] == 0x3E
assert offsets["hidden_group_size_z"] == 0x40
assert offsets["hidden_block_count_x"] == 0x30
assert k[".vgpr_count"] >= 6
assert k[".sgpr_count"] >= 10

print("PASS: metadata record strict-checked; hidden offsets 0x3C/0x3E/0x40/0x30")
print("PASS: no GPU work performed by this script")
