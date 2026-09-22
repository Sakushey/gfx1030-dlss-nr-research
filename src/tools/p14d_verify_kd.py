"""Cross-verify the empirical descriptor layout by assembling a probe with
the EXACT directive set of the translated conv_splitk and comparing byte
for byte against the real .kd in the phase9 module (and the original
gfx1100 .kd, decoded with the same read path).

Also probes vgpr/sgpr granule encoding across the full 16 dwords.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
LLVM_MC = r"<ROCM_ROOT>\7.1\bin\llvm-mc.exe"
OUT = os.path.join(ROOT, "phase14d_static", "out")
sys.path.insert(0, HERE)
import p14d_kd as kd  # noqa: E402

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

CONV_SPLITK_DIRECTIVES = """
	.amdhsa_group_segment_fixed_size 4096
	.amdhsa_private_segment_fixed_size 0
	.amdhsa_kernarg_size 304
	.amdhsa_user_sgpr_count 6
	.amdhsa_user_sgpr_private_segment_buffer 1
	.amdhsa_user_sgpr_dispatch_ptr 0
	.amdhsa_user_sgpr_queue_ptr 0
	.amdhsa_user_sgpr_kernarg_segment_ptr 1
	.amdhsa_user_sgpr_dispatch_id 0
	.amdhsa_user_sgpr_flat_scratch_init 0
	.amdhsa_user_sgpr_private_segment_size 0
	.amdhsa_wavefront_size32 1
	.amdhsa_uses_dynamic_stack 0
	.amdhsa_system_sgpr_private_segment_wavefront_offset 0
	.amdhsa_system_sgpr_workgroup_id_x 1
	.amdhsa_system_sgpr_workgroup_id_y 0
	.amdhsa_system_sgpr_workgroup_id_z 0
	.amdhsa_system_sgpr_workgroup_info 0
	.amdhsa_system_vgpr_workitem_id 0
	.amdhsa_next_free_vgpr 53
	.amdhsa_next_free_sgpr 42
	.amdhsa_reserve_vcc 0
	.amdhsa_reserve_flat_scratch 0
	.amdhsa_float_round_mode_32 0
	.amdhsa_float_round_mode_16_64 0
	.amdhsa_float_denorm_mode_32 3
	.amdhsa_float_denorm_mode_16_64 3
	.amdhsa_dx10_clamp 1
	.amdhsa_ieee_mode 1
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


def kd_of(path, want):
    data, sections, syms = kd.parse_elf(path)
    hits = kd.find_kernel_kds(data, sections, syms, want={want})
    if not hits:
        return None, data, sections, syms
    return kd.dump_kd(data, hits[0][1]), data, sections, syms


def show(label, dw):
    print(label)
    for i in range(16):
        print(f"  d[{i:2d}] 0x{dw[i]:08X}")


def main():
    os.makedirs(OUT, exist_ok=True)
    obj = assemble(MINI_CODE + "\n.section .rodata,\"a\",@progbits\n"
                   + ".p2align 6, 0x0\n.amdhsa_kernel kprobe\n"
                   + CONV_SPLITK_DIRECTIVES + "\t.end_amdhsa_kernel\n")
    probe_dw, _, _, _ = kd_of(obj, "kprobe")
    show("probe (mc, conv_splitk directive set)", probe_dw)

    real = os.path.join(ROOT, "phase9_final_module",
                        "gfx1030_dlssnr_module.co")
    dw, _, _, _ = kd_of(real, "_Z13k_conv_splitk12ConvParams1d")
    show("REAL translated gfx1030 conv_splitk .kd (module)", dw)
    print("match probe==real:", probe_dw == dw)

    orig = os.path.join(ROOT, "phase5_exact_fragment",
                        "gfx1100_code_object.o")
    dw2, _, _, _ = kd_of(orig, "_Z13k_conv_splitk12ConvParams1d")
    show("REAL ORIGINAL gfx1100 conv_splitk .kd", dw2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
