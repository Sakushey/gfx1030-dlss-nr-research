"""llvm-mc descriptor-layout oracle (host-only).

Assembles minimal gfx1030 kernels whose `.amdhsa` directive block differs
by exactly one flag/value and diffs the emitted 64-byte descriptor to
measure, empirically and with zero guessed bit layouts:

  1. which dword each directive lives in
  2. exact bit position/mask for every flag
  3. granule encoding for next_free_vgpr / next_free_sgpr
  4. where `entry` / other fields sit

The measured map is saved as JSON for p14d_dec.py to use.
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
LLVM_MC = r"C:\Program Files\AMD\ROCm\7.1\bin\llvm-mc.exe"
OUT = os.path.join(ROOT, "phase14d_static", "out")

MINI_CODE = """
.amdgcn_target "amdgcn-amd-amdhsa--gfx1030"
.amdhsa_code_object_version 6
.text
.globl	kprobe
.p2align 8
.type	kprobe,@function
kprobe:
	s_waitcnt vmcnt(0) lgkmcnt(0)
	s_endpgm
.Lfunc_end_kprobe:
.size	kprobe, .Lfunc_end_kprobe-kprobe
"""

BASE_DIRECTIVES = """
	.amdhsa_group_segment_fixed_size 0
	.amdhsa_private_segment_fixed_size 0
	.amdhsa_kernarg_size 64
	.amdhsa_user_sgpr_count 0
	.amdhsa_user_sgpr_private_segment_buffer 0
	.amdhsa_user_sgpr_dispatch_ptr 0
	.amdhsa_user_sgpr_queue_ptr 0
	.amdhsa_user_sgpr_kernarg_segment_ptr 0
	.amdhsa_user_sgpr_dispatch_id 0
	.amdhsa_user_sgpr_flat_scratch_init 0
	.amdhsa_user_sgpr_private_segment_size 0
	.amdhsa_wavefront_size32 0
	.amdhsa_uses_dynamic_stack 0
	.amdhsa_system_sgpr_private_segment_wavefront_offset 0
	.amdhsa_system_sgpr_workgroup_id_x 0
	.amdhsa_system_sgpr_workgroup_id_y 0
	.amdhsa_system_sgpr_workgroup_id_z 0
	.amdhsa_system_sgpr_workgroup_info 0
	.amdhsa_system_vgpr_workitem_id 0
	.amdhsa_next_free_vgpr 8
	.amdhsa_next_free_sgpr 4
	.amdhsa_reserve_vcc 0
	.amdhsa_reserve_flat_scratch 0
	.amdhsa_float_round_mode_32 0
	.amdhsa_float_round_mode_16_64 0
	.amdhsa_float_denorm_mode_32 0
	.amdhsa_float_denorm_mode_16_64 0
	.amdhsa_dx10_clamp 0
	.amdhsa_ieee_mode 0
	.amdhsa_fp16_overflow 0
"""


def assemble(text):
    fd, path = tempfile.mkstemp(suffix=".s", dir=OUT)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    obj = path[:-2] + ".o"
    r = subprocess.run([LLVM_MC, "-triple=amdgcn-amd-amdhsa",
                        "-mcpu=gfx1030", "-filetype=obj", "-o", obj, path],
                       capture_output=True, text=True)
    if r.returncode != 0:
        os.unlink(path)
        raise RuntimeError(f"llvm-mc failed: {r.stderr}")
    os.unlink(path)
    return obj


def get_kd_bytes(obj_path):
    sys.path.insert(0, HERE)
    import p14d_kd as kd
    data, sections, syms = kd.parse_elf(obj_path)
    hits = kd.find_kernel_kds(data, sections, syms, want={"kprobe"})
    if not hits:
        return None, data, sections, syms
    return kd.dump_kd(data, hits[0][1]), data, sections, syms


def build_s(directives):
    return MINI_CODE + "\n.section .rodata,\"a\",@progbits\n" \
        + ".p2align 6, 0x0\n.amdhsa_kernel kprobe\n" + directives \
        + "\t.end_amdhsa_kernel\n"


def main():
    os.makedirs(OUT, exist_ok=True)
    base_obj = assemble(build_s(BASE_DIRECTIVES))
    base_dw, _, _, _ = get_kd_bytes(base_obj)
    if base_dw is None:
        print("oracle: base descriptor not found")
        return 1
    print("base descriptor dwords:")
    for i in range(16):
        print(f"  dword[{i:2d}] = 0x{base_dw[i]:08X}")

    # Binary flag probes: set one .amdhsa flag to 1 at a time.
    bin_flags = [
        ".amdhsa_user_sgpr_private_segment_buffer",
        ".amdhsa_user_sgpr_dispatch_ptr",
        ".amdhsa_user_sgpr_queue_ptr",
        ".amdhsa_user_sgpr_kernarg_segment_ptr",
        ".amdhsa_user_sgpr_dispatch_id",
        ".amdhsa_user_sgpr_flat_scratch_init",
        ".amdhsa_user_sgpr_private_segment_size",
        ".amdhsa_system_sgpr_workgroup_id_x",
        ".amdhsa_system_sgpr_workgroup_id_y",
        ".amdhsa_system_sgpr_workgroup_id_z",
        ".amdhsa_system_sgpr_workgroup_info",
        ".amdhsa_system_sgpr_private_segment_wavefront_offset",
        ".amdhsa_system_vgpr_workitem_id",
        ".amdhsa_wavefront_size32",
        ".amdhsa_uses_dynamic_stack",
        ".amdhsa_dx10_clamp",
        ".amdhsa_ieee_mode",
        ".amdhsa_fp16_overflow",
        ".amdhsa_reserve_vcc",
        ".amdhsa_reserve_flat_scratch",
    ]
    # implied user-sgpr count per enabled user flag (amdhsa order)
    USER_SPAN = {
        ".amdhsa_user_sgpr_private_segment_buffer": 4,
        ".amdhsa_user_sgpr_dispatch_ptr": 2,
        ".amdhsa_user_sgpr_queue_ptr": 2,
        ".amdhsa_user_sgpr_kernarg_segment_ptr": 2,
        ".amdhsa_user_sgpr_dispatch_id": 2,
        ".amdhsa_user_sgpr_flat_scratch_init": 2,
        ".amdhsa_user_sgpr_private_segment_size": 1,
    }
    lines = BASE_DIRECTIVES.splitlines()
    results = {}
    for flag in bin_flags:
        count = USER_SPAN.get(flag, 0)
        d = []
        for l in lines:
            if flag in l:
                d.append(l.replace(flag + " 0", flag + " 1"))
            elif ".amdhsa_user_sgpr_count" in l:
                d.append(f"\t.amdhsa_user_sgpr_count {count}")
            else:
                d.append(l)
        d = "\n".join(d) + "\n"
        obj = assemble(build_s(d))
        dw, _, _, _ = get_kd_bytes(obj)
        diff = [(i, base_dw[i], dw[i]) for i in range(16)
                if base_dw[i] != dw[i]]
        # find byte/bit within first differing dword
        info = []
        for i, b, w in diff:
            delta = b ^ w
            # bit position of highest set bit in delta
            bit = delta.bit_length() - 1
            info.append({"dword": i, "old": "0x%08X" % b,
                         "new": "0x%08X" % w, "delta": "0x%08X" % delta,
                         "bit": bit})
        results[flag] = info
        print(f"{flag:55s} -> {info}")

    # Numeric probes: next_free_vgpr/sgpr at several values + wave32 off/on.
    num_probes = {
        "next_free_vgpr": [8, 12, 16, 24, 32, 53, 64, 65, 104, 128],
        "next_free_sgpr": [4, 8, 16, 24, 32, 42, 48, 56, 64, 80, 96, 112],
    }
    numeric = {}
    for dname, values in num_probes.items():
        row = []
        for v in values:
            d = "\n".join(
                l.replace(dname + " " + l.split(dname + " ")[1].split()[0],
                          dname + " " + str(v)) if dname in l else l
                for l in lines) + "\n"
            obj = assemble(build_s(d))
            dw, _, _, _ = get_kd_bytes(obj)
            row.append((v, dw))
        numeric[dname] = row
        # print granules
        for v, dw in row:
            print(f"{dname}={v:3d} dwords: " +
                  " ".join("d%02d=0x%08X" % (i, dw[i]) for i in range(6)))
    # kernarg/group/private size probes
    for dname, base_val in ((".amdhsa_kernarg_size", 64),
                            (".amdhsa_group_segment_fixed_size", 0),
                            (".amdhsa_private_segment_fixed_size", 0)):
        row = []
        for v in (base_val, base_val + 1, 0x100, 0x10000, 0x100000):
            d = "\n".join(
                l if not l.strip().startswith(dname) else
                f"\t{dname} {v}" for l in lines) + "\n"
            obj = assemble(build_s(d))
            dw, _, _, _ = get_kd_bytes(obj)
            row.append((v, dw))
        numeric[dname] = row
        print(f"{dname}: " +
              " ".join("v=%d dw0..3=%s" % (v, [hex(dw[i]) for i in range(4)])
                       for v, dw in row))

    manifest = {"base": [hex(x) for x in base_dw],
                "bin_flags": results, "numeric": {
                    k: [(v, [hex(x) for x in dw]) for v, dw in rows]
                    for k, rows in numeric.items()}}
    with open(os.path.join(OUT, "p14d_mc_layout_oracle.json"), "w") as f:
        json.dump(manifest, f, indent=1)
    print("saved:", os.path.join(OUT, "p14d_mc_layout_oracle.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
