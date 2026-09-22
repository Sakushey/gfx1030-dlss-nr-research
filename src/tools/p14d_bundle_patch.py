"""Phase 14D6 (module): patch the phase9 bundle assembly's per-kernel
.amdhsa_kernel descriptor blocks to the ORIGINAL gfx1100 policies and
rebuild the entry-fixed gfx1030 module (mc + ld.lld -shared).

The phase9 bundle .s = all 34 bodies (YAML docs stripped) + one
.amdgpu_metadata doc. Only the descriptor policy lines inside each
.amdhsa_kernel NAME ... .end_amdhsa_kernel block are rewritten; the code
lines, the metadata doc and every other line stay byte-identical.

Writes phase14_entry_fixed_module/gfx1030_dlssnr_module_entryfixed.co
Host-only.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import p14d_kd as kd          # noqa: E402
import p14d_dec as dec        # noqa: E402
import p14d_rebuild as rb     # noqa: E402

LLVM_MC = r"<ROCM_ROOT>\7.1\bin\llvm-mc.exe"
LD_LLD = r"<ROCM_ROOT>\7.1\bin\ld.lld.exe"
BUNDLE_S = os.path.join(ROOT, "phase9_final_module",
                        "gfx1030_dlssnr_bundle.s")
ORIG_OBJ = os.path.join(ROOT, "phase5_exact_fragment",
                        "gfx1100_code_object.o")
OUTDIR = os.path.join(ROOT, "phase14_entry_fixed_module")


def patch_bundle(text, policy_map, name):
    """Rewrite the .amdhsa_kernel <name> block policy lines."""
    pat = re.compile(
        r"(\.amdhsa_kernel\s+" + re.escape(name) + r"\n)"
        r"(.*?)(\n\t\.end_amdhsa_kernel)", re.S)
    m = pat.search(text)
    if not m:
        raise RuntimeError(f"kernel block not found: {name}")
    body = m.group(2)
    lines = []
    for line in body.split("\n"):
        s = line.strip()
        mm = re.match(r"^\.amdhsa_([a-z0-9_]+)\s+(\d+)", s)
        if mm:
            key = ".amdhsa_" + mm.group(1)
            if key in policy_map and policy_map[key] is not None:
                indent = line[:len(line) - len(line.lstrip())]
                lines.append(f"{indent}{key} {policy_map[key]}")
                continue
        lines.append(line)
    return text[:m.start(2)] + "\n".join(lines) + text[m.end(2):]


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    od = {k: dec.dec(dw) for k, dw in dec.dec_kernel_file(ORIG_OBJ)}
    text = open(BUNDLE_S, encoding="utf-8").read()
    for name, info_o in od.items():
        p = rb.build_policy(info_o)
        text = patch_bundle(text, p, name)
    out_s = os.path.join(OUTDIR, "gfx1030_dlssnr_bundle_entryfixed.s")
    with open(out_s, "w", encoding="utf-8") as f:
        f.write(text)
    obj = os.path.join(OUTDIR, "gfx1030_dlssnr_bundle_entryfixed.o")
    r = subprocess.run([LLVM_MC, "-triple=amdgcn-amd-amdhsa",
                        "-mcpu=gfx1030", "-filetype=obj",
                        "-o", obj, out_s], capture_output=True, text=True)
    if r.returncode != 0:
        print("BUNDLE ASSEMBLY FAILED:\n", (r.stdout + r.stderr)[:3000])
        return 1
    print(f"bundle assembled ({os.path.getsize(obj)} B)")
    mod = os.path.join(OUTDIR, "gfx1030_dlssnr_module_entryfixed.co")
    r = subprocess.run([LD_LLD, "-shared", "-o", mod, obj],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("LINK FAILED:\n", (r.stdout + r.stderr)[:2000])
        return 1
    print(f"module linked ({os.path.getsize(mod)} B)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
