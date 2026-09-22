"""Decode the AMDGPU metadata note of the clang-compiled reference probe.
Host-only; no GPU.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "phase9_static", "tools"))
from p9_meta import canon, note_metadata  # noqa: E402

meta = note_metadata(os.path.join(HERE, "ref_probe_dev.elf.o"))
if meta is None:
    sys.exit("FAIL: no note decoded from reference object")
print("target:", meta["top"].get("amdhsa.target"),
      "version:", meta["top"].get("amdhsa.version"))
for k in meta["kernels"]:
    kc = canon(k)
    print("kernel:", kc.get(".name"))
    for key in (".kernarg_segment_size", ".kernarg_segment_align",
                ".group_segment_fixed_size", ".private_segment_fixed_size",
                ".vgpr_count", ".sgpr_count", ".max_flat_workgroup_size",
                ".wavefront_size", ".workgroup_processor_mode",
                ".code_object_version"):
        if key in kc:
            print(f"  {key}: {kc[key]}")
    for a in kc.get(".args", []):
        print(f"  arg offset={a.get('.offset')} size={a.get('.size')} "
              f"kind={a.get('.value_kind')} "
              f"name={a.get('.name')} addrspace={a.get('.address_space')}")
