#!/usr/bin/env python3
"""Phase 16H — P9 + P10: hidden-arg and scratch/private-segment ABI closure.

Host-only: compiles small gfx1030 objects with the STOCK toolchain and
reads their metadata.  Nothing is executed, on host or device.

Two questions:

  P9  hidden args.  Is the hidden-argument ABI the module relies on the
      one the stock gfx1030 toolchain actually emits for local/workgroup
      size, workgroup IDs and block/grid counts?

  P10 scratch / private segment.  What does a stock gfx1030 object look
      like when it genuinely uses the private segment (spills, private
      arrays), and does the module's `private_segment_fixed_size = 24`
      and its 22 `scratch_*` instructions sit inside that contract?
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p16h_lib as L  # noqa: E402
sys.path.insert(0, os.path.join(L.ROOT, "phase16g_forensics", "tools"))
import p16g_msgpack as M  # noqa: E402

ROCM = r"<ROCM_ROOT>\7.1"
CLANG = os.path.join(ROCM, "bin", "clang.exe")
OBJDUMP = os.path.join(ROCM, "bin", "llvm-objdump.exe")
OUT = os.path.join(L.P16H, "out", "abi_probe")
SYM = "_Z10k_swin_varILi32ELb0EEv9VarParams"


# The stock gfx1030 toolchain is driven through its OpenCL front end: it
# needs no HIP headers and defines the hidden-argument builtins
# (get_local_size / get_num_groups / get_global_id) directly.
SRC_HIDDEN = r"""
/* P9 probe: exercise every hidden-argument kind the module's descriptor
   declares -- workgroup id, local/workgroup size, block/grid counts. */
__kernel void probe_hidden(__global int *out) {
  int gid  = (int)get_global_id(0);
  int lid  = (int)get_local_id(0);
  int lsz  = (int)get_local_size(0);
  int ng   = (int)get_num_groups(0);
  int gsz  = (int)get_global_size(0);
  out[gid] = lid + lsz + ng + gsz;
}
"""

SRC_SCRATCH = r"""
/* P10 probe: force genuine private-segment use --
   (a) a private array indexed at run time so it cannot be promoted to
       registers, and
   (b) a forced spill via many live values. */
__kernel void probe_priv(__global int *out, int n) {
  volatile float acc[32];
  for (int i = 0; i < 32; ++i) acc[i] = (float)(i + n);
  for (int r = 0; r < 8; ++r)
    for (int i = 0; i < 32; ++i) acc[i] = acc[i] * 1.0001f + (float)r;
  float s = 0.f;
  for (int i = 0; i < 32; ++i) s += acc[i];
  out[(int)get_local_id(0)] = (int)s;
}
"""


def compile_one(name, src, extra=()):
    os.makedirs(OUT, exist_ok=True)
    sp = os.path.join(OUT, name + ".cl")
    op = os.path.join(OUT, name + ".o")
    open(sp, "w", encoding="utf-8").write(src)
    cmd = [CLANG, "-x", "cl", "-cl-std=CL2.0",
           "--target=amdgcn-amd-amdhsa", "-mcpu=gfx1030", "-O2",
           "-c", sp, "-o", op, "-nogpulib"] + list(extra)
    r = subprocess.run(cmd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return op, r


def md_of(path):
    e = L.Elf(path)
    for n, _t, d in M.parse_note(e.secbytes(".note")):
        if n != "AMDGPU":
            continue
        md, _ = M.unpack(d, 0)
        return md
    return None


def kernels(md):
    out = []
    for k in (md or {}).get("amdhsa.kernels", []):
        out.append(dict(
            name=k.get(".name"),
            kernarg_segment_size=k.get(".kernarg_segment_size"),
            kernarg_segment_align=k.get(".kernarg_segment_align"),
            group_segment_fixed_size=k.get(".group_segment_fixed_size"),
            private_segment_fixed_size=k.get(".private_segment_fixed_size"),
            sgpr_count=k.get(".sgpr_count"), vgpr_count=k.get(".vgpr_count"),
            sgpr_spill_count=k.get(".sgpr_spill_count"),
            vgpr_spill_count=k.get(".vgpr_spill_count"),
            uses_flat_scratch=k.get(".uses_flat_scratch_init"),
            args=[dict(offset=a.get(".offset"), size=a.get(".size"),
                       value_kind=a.get(".value_kind"))
                  for a in k.get(".args", [])]))
    return out


def scratch_ops(path, sym=None):
    """Enumerate scratch_* instructions in a disassembly."""
    r = subprocess.run([OBJDUMP, "-d", "--mcpu=gfx1030", path],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    ops = {}
    for ln in r.stdout.splitlines():
        t = ln.strip()
        if t.startswith("scratch_"):
            mnem = t.split(None, 1)[0]
            ops[mnem] = ops.get(mnem, 0) + 1
    return ops, r.stdout


def main():
    print("=" * 74)
    print("P9/P10 — hidden-arg and scratch ABI closure (host-only)")
    print("=" * 74)

    res = {}

    # ---- the module's own descriptors --------------------------------
    for tag, p in (("original_gfx1100", L.ORIG_O),
                   ("candidate_f",
                    os.path.join(L.ROOT, "phase16h_candidate_f",
                                 "gfx1030_dlssnr_candidate_f.co"))):
        md = md_of(p)
        ks = [k for k in kernels(md) if k["name"] == SYM]
        if ks:
            res["module_" + tag] = ks[0]

    print("\n[P9] hidden-arg metadata, module vs module")
    a = res["module_original_gfx1100"]["args"]
    b = res["module_candidate_f"]["args"]
    print("  original gfx1100 args: %d ; Candidate F args: %d" % (len(a), len(b)))
    print("  one-to-one identical (offset, size, value_kind): %s" % (a == b))
    print("  hidden-arg subset identical: %s" % (a[1:] == b[1:]))
    res["hidden_args_identical"] = (a == b)
    res["hidden_arg_table"] = a

    # ---- synthetic stock-tool probes ---------------------------------
    print("\n[P9] synthetic stock gfx1030 object exercising hidden args")
    op, r = compile_one("probe_hidden", SRC_HIDDEN)
    if os.path.exists(op) and os.path.getsize(op):
        k = kernels(md_of(op))
        res["probe_hidden"] = k
        for kk in k:
            print("  %s: kernarg=%s group=%s priv=%s sgpr=%s vgpr=%s"
                  % (kk["name"], kk["kernarg_segment_size"],
                     kk["group_segment_fixed_size"],
                     kk["private_segment_fixed_size"], kk["sgpr_count"],
                     kk["vgpr_count"]))
            for x in kk["args"]:
                print("      off=%-5s size=%-4s kind=%s"
                      % (x["offset"], x["size"], x["value_kind"]))
    else:
        print("  compile failed:", (r.stdout + r.stderr)[:600])
        res["probe_hidden"] = None

    print("\n[P10] synthetic stock gfx1030 object using the private segment")
    op2, r2 = compile_one("probe_priv", SRC_SCRATCH)
    if os.path.exists(op2) and os.path.getsize(op2):
        k2 = kernels(md_of(op2))
        res["probe_priv"] = k2
        for kk in k2:
            print("  %s: group=%s priv=%s sgpr=%s vgpr=%s "
                  "sgpr_spill=%s vgpr_spill=%s flat_scratch=%s"
                  % (kk["name"], kk["group_segment_fixed_size"],
                     kk["private_segment_fixed_size"], kk["sgpr_count"],
                     kk["vgpr_count"], kk["sgpr_spill_count"],
                     kk["vgpr_spill_count"], kk["uses_flat_scratch"]))
        so, _txt = scratch_ops(op2)
        res["probe_priv_scratch_ops"] = so
        print("  scratch_* instructions: %s" % so)
    else:
        print("  compile failed:", (r2.stdout + r2.stderr)[:600])
        res["probe_priv"] = None

    # ---- the module's own scratch census -----------------------------
    print("\n[P10] the module's own scratch usage")
    so_c, txt = scratch_ops(os.path.join(L.ROOT, "phase16h_candidate_f",
                                         "gfx1030_dlssnr_candidate_f.co"))
    res["module_scratch_ops"] = so_c
    print("  scratch_* mnemonics in Candidate F: %s" % so_c)
    print("  total scratch_* instructions: %d" % sum(so_c.values()))
    # per-kernel breakdown (objdump prints `ADDR <mangled>:`)
    import re as _re
    per, cur = {}, None
    for ln in txt.splitlines():
        m = _re.match(r"^[0-9A-Fa-f]+\s+<(.+)>:\s*$", ln.strip())
        if m:
            cur = m.group(1)
            continue
        if cur and ln.strip().startswith("scratch_"):
            per[cur] = per.get(cur, 0) + 1
    res["scratch_ops_per_kernel"] = per
    nz = {k: v for k, v in per.items() if v}
    print("  kernels using scratch: %d of %d" % (len(nz), len(per)))
    for k in sorted(nz, key=lambda x: -nz[x])[:8]:
        print("     %-46s %d" % (k.replace("_Z", ""), nz[k]))
    print("  SWIN32f scratch ops: %d" % per.get(SYM, 0))
    for tag in ("module_original_gfx1100", "module_candidate_f"):
        m = res[tag]
        print("  %-20s private_segment_fixed_size=%s group=%s"
              % (tag, m["private_segment_fixed_size"],
                 m["group_segment_fixed_size"]))

    json.dump(res, open(os.path.join(L.P16H, "out", "p9_p10_abi.json"), "w"),
              indent=1)
    print("\nwrote", os.path.join(L.P16H, "out", "p9_p10_abi.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
