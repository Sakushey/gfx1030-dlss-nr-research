"""Phase 14D kernel-descriptor semantic decoder (empirically calibrated).

Kernel descriptor dword semantics (measured with llvm-mc 7.1 bit-probes on
gfx1030, code objects v4/v5/v6 all identical — see p14d_mcbitmap.py):

  d0  group_segment_fixed_size
  d1  private_segment_fixed_size
  d2  kernarg_segment_size
  d3  reserved
  d4:d5  kernel code entry byte offset (64-bit; filled at link)
  d6..d11 reserved (0 in LLVM objects)
  d12 COMPUTE_PGM_RSRC1-ish word: bit0 wave64 (=1 when not wave32),
      bits 0:5-ish vgpr granule region (encoding per target), bits 6:9 sgpr
      region, bit21 dx10_clamp, bit23 ieee_mode, bit26 fp16_overflow
      (other bits observed: 29-31 constant 0x7 in LLVM encodings)
  d13 "system/user" word:
      bit0  private_segment_wavefront_offset system sgpr enable
      bits1-4  user_sgpr_count << 1   (declared count, may exceed enabled)
      bit7  workgroup_id_x enable
      bit8  workgroup_id_y enable
      bit9  workgroup_id_z enable
      bit10 workgroup_info enable
      bit11 workitem_id (system vgpr) enable
  d14 "user enable" word:
      bit0  private_segment_buffer
      bit1  dispatch_ptr
      bit2  queue_ptr
      bit3  kernarg_segment_ptr
      bit4  dispatch_id
      bit5  flat_scratch_init
      bit6  private_segment_size
      bit10 wave32
      bit11 uses_dynamic_stack
  d15 reserved

AMDHSA user-data placement order (canonical, per preload enable list):
  pb(4) dp(2) qp(2) kernarg(2) did(2) flat(2) pss(1) grid-count… none
  then SYSTEM sgprs at SGPR index = declared user_sgpr_count:
  wgid_x, wgid_y, wgid_z, workgroup_info, private_segment_wavefront_offset
  (workitem id is a VGPR, starts at v0 when enabled).

This module renders a per-kernel initial register map from the enable
bits + declared count under those placement rules.
"""
from __future__ import annotations

import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p14d_kd as kd  # noqa: E402

USER_ORDER = [  # (enable bit in d14, dword span, name)
    (0, 4, "private_segment_buffer"),
    (1, 2, "dispatch_ptr"),
    (2, 2, "queue_ptr"),
    (3, 2, "kernarg_segment_ptr"),
    (4, 2, "dispatch_id"),
    (5, 2, "flat_scratch_init"),
    (6, 1, "private_segment_size"),
]
SYSTEM_ORDER = [  # (enable bit in d13, span, name)
    (7, 1, "workgroup_id_x"),
    (8, 1, "workgroup_id_y"),
    (9, 1, "workgroup_id_z"),
    (10, 1, "workgroup_info"),
    (0, 1, "private_segment_wavefront_offset"),
]


def dec(dw):
    d14 = dw[14]
    d13 = dw[13]
    user = []
    for bit, span, name in USER_ORDER:
        if (d14 >> bit) & 1:
            user.append((name, span))
    system = []
    for bit, span, name in SYSTEM_ORDER:
        if (d13 >> bit) & 1:
            system.append((name, span))
    user_count = (d13 >> 1) & 0xF  # bits1-4 = count<<1 -> count
    return dict(
        group=dw[0], private=dw[1], kernarg_size=dw[2],
        entry=dw[4] | (dw[5] << 32),
        wave64=(dw[12] >> 0) & 1, dx10=(dw[12] >> 21) & 1,
        ieee=(dw[12] >> 23) & 1, fp16_ovf=(dw[12] >> 26) & 1,
        raw_rsrc1="0x%08X" % dw[12],
        user_count=user_count, user_enables=user, system_enables=system,
        wave32=(d14 >> 10) & 1, dyn_stack=(d14 >> 11) & 1,
        workitem_vgpr=(d13 >> 11) & 1,
    )


def register_map(info, vgpr_start=0):
    """Compute initial register assignments per AMDHSA placement rules."""
    regs = {}
    next_sgpr = 0
    for name, span in info["user_enables"]:
        regs[name] = (next_sgpr, span)
        next_sgpr += span
    user_declared = info["user_count"]
    sys_base = user_declared  # system sgprs start at declared count
    n = 0
    sys_regs = {}
    for name, span in info["system_enables"]:
        sys_regs[name] = (sys_base + n, span)
        n += span
    vgprs = {}
    if info["workitem_vgpr"]:
        vgprs["workitem_id_x"] = vgpr_start
        vgprs["workitem_id_y"] = vgpr_start + 1
        vgprs["workitem_id_z"] = vgpr_start + 2
    return regs, sys_regs, vgprs, next_sgpr


def fmt_layout(info):
    regs, sys_regs, vgprs, _ = register_map(info)
    parts = []
    for name, (idx, span) in regs.items():
        parts.append(f"s{idx}" + (f":s{idx+span-1}" if span > 1 else "") +
                     f"={name}")
    for name, (idx, span) in sys_regs.items():
        parts.append(f"s{idx}={name}")
    for name, idx in vgprs.items():
        parts.append(f"v{idx}={name}")
    return ", ".join(parts) if parts else "(none)"


def dec_kernel_file(path, kernel=None):
    data, sections, syms = kd.parse_elf(path)
    out = []
    for kname, base in kd.find_kernel_kds(data, sections, syms):
        if kernel and kname != kernel:
            continue
        dw = kd.dump_kd(data, base)
        out.append((kname, dw))
    return out
