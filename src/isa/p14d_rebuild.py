"""Phase 14D6 static: regenerate per-kernel gfx1030 assembly with the
ORIGINAL descriptor policy (descriptor-only normalization).

For each kernel .s (phase9_final_module/asm/), rewrite the
.amdhsa_kernel directive block to the kernel's ORIGINAL gfx1100 policy:
  .amdhsa_user_sgpr_count        original declared count (13/14/15)
  .amdhsa_user_sgpr_private_segment_buffer 0
  .amdhsa_user_sgpr_dispatch_ptr {0,1 per original}
  .amdhsa_user_sgpr_kernarg_segment_ptr 1
  .amdhsa_system_sgpr_workgroup_id_x/y/z {0,1 per original}
  .amdhsa_system_sgpr_workgroup_info 0
  .amdhsa_system_sgpr_private_segment_wavefront_offset {0,1 per orig}
  .amdhsa_system_vgpr_workitem_id 0
Everything else untouched (code bodies identical).

Outputs per kernel: patched .s, assembled .o (llvm-mc), and a decode of
the new .kd compared against (a) the ORIGINAL policy words and (b) the
previous .kd. Host-only.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import p14d_kd as kd      # noqa: E402
import p14d_dec as dec    # noqa: E402

LLVM_MC = r"C:\Program Files\AMD\ROCm\7.1\bin\llvm-mc.exe"
ASM_DIR = os.path.join(ROOT, "phase9_final_module", "asm")
ORIG_OBJ = os.path.join(ROOT, "phase5_exact_fragment",
                        "gfx1100_code_object.o")
OUT_DIR = os.path.join(ROOT, "phase14d_static", "out", "norm_asm")
OUT_OBJ = os.path.join(ROOT, "phase14d_static", "out", "norm_obj")

# policy lines inside .amdhsa_kernel blocks we must align with the original
POLICY = {
    ".amdhsa_user_sgpr_count": None,
    ".amdhsa_user_sgpr_private_segment_buffer": 0,
    ".amdhsa_user_sgpr_dispatch_ptr": None,
    ".amdhsa_user_sgpr_queue_ptr": 0,
    ".amdhsa_user_sgpr_kernarg_segment_ptr": 1,
    ".amdhsa_user_sgpr_dispatch_id": 0,
    ".amdhsa_user_sgpr_flat_scratch_init": 0,
    ".amdhsa_user_sgpr_private_segment_size": 0,
    ".amdhsa_system_sgpr_workgroup_id_x": None,
    ".amdhsa_system_sgpr_workgroup_id_y": None,
    ".amdhsa_system_sgpr_workgroup_id_z": None,
    ".amdhsa_system_sgpr_workgroup_info": 0,
    ".amdhsa_system_sgpr_private_segment_wavefront_offset": None,
    ".amdhsa_system_vgpr_workitem_id": 0,
}


def patch_s(path, policy_map):
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            m = re.match(r"^\.amdhsa_([a-z0-9_]+)\s+(\d+)", s)
            if m:
                key = ".amdhsa_" + m.group(1)
                if key in policy_map and policy_map[key] is not None:
                    val = policy_map[key]
                    indent = line[:len(line) - len(line.lstrip())]
                    out.append(f"{indent}{key} {val}\n")
                    continue
            out.append(line)
    return "".join(out)


def build_policy(orig_info):
    """Map an original descriptor decode onto directive values."""
    user = {n for n, _ in orig_info["user_enables"]}
    sys_ = {n for n, _ in orig_info["system_enables"]}
    p = dict(POLICY)
    p[".amdhsa_user_sgpr_count"] = orig_info["user_count"]
    p[".amdhsa_user_sgpr_private_segment_buffer"] = 0
    p[".amdhsa_user_sgpr_dispatch_ptr"] = 1 if "dispatch_ptr" in user else 0
    p[".amdhsa_system_sgpr_workgroup_id_x"] = 1 if "workgroup_id_x" in sys_ else 0
    p[".amdhsa_system_sgpr_workgroup_id_y"] = 1 if "workgroup_id_y" in sys_ else 0
    p[".amdhsa_system_sgpr_workgroup_id_z"] = 1 if "workgroup_id_z" in sys_ else 0
    p[".amdhsa_system_sgpr_private_segment_wavefront_offset"] = (
        1 if "private_segment_wavefront_offset" in sys_ else 0)
    return p


def assemble(path_src, path_obj):
    r = subprocess.run([LLVM_MC, "-triple=amdgcn-amd-amdhsa",
                        "-mcpu=gfx1030", "-filetype=obj",
                        "-o", path_obj, path_src],
                       capture_output=True, text=True)
    return r.returncode, r.stderr


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(OUT_OBJ, exist_ok=True)
    od = {k: dec.dec(dw) for k, dw in dec.dec_kernel_file(ORIG_OBJ)}
    fails = []
    results = []
    for fname in sorted(os.listdir(ASM_DIR)):
        if not fname.endswith(".s"):
            continue
        name = fname[:-2]
        if name not in od:
            continue  # helper swin_layer: no descriptor policy (not launched)
        info_o = od[name]
        p = build_policy(info_o)
        text = patch_s(os.path.join(ASM_DIR, fname), p)
        src = os.path.join(OUT_DIR, fname)
        with open(src, "w", encoding="utf-8") as f:
            f.write(text)
        obj = os.path.join(OUT_OBJ, fname[:-2] + ".o")
        rc, err = assemble(src, obj)
        if rc != 0:
            fails.append((name, err.strip().splitlines()[:1]))
            continue
        # decode the new .kd policy words
        data, sections, syms = kd.parse_elf(obj)
        hits = kd.find_kernel_kds(data, sections, syms, want={name})
        if not hits:
            fails.append((name, "no .kd found"))
            continue
        dw = kd.dump_kd(data, hits[0][1])
        ni = dec.dec(dw)
        match = (
            ni["user_count"] == info_o["user_count"]
            and [n for n, _ in ni["user_enables"]] ==
            [n for n, _ in info_o["user_enables"]]
            and [n for n, _ in ni["system_enables"]] ==
            [n for n, _ in info_o["system_enables"]]
            and ni["wave32"] == info_o["wave32"]
        )
        results.append((name, match, ni, info_o))
        print(f"{name[:48]:50s} match={match}  "
              f"policy: uc={ni['user_count']} "
              f"user={[n for n,_ in ni['user_enables']]} "
              f"sys={[n for n,_ in ni['system_enables']]}")
    print(f"\n{len(results)} kernels rebuilt, "
          f"{sum(1 for _, m, _, _ in results if m)} policy-matched, "
          f"{len(fails)} failures")
    for n, e in fails:
        print("FAIL", n, e)
    return 0 if not fails and all(m for _, m, _, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
