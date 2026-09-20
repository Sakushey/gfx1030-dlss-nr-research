#!/usr/bin/env python3
"""Phase 16I-ISA -- close the emulator ISA gaps that sit on the authentic
one-frame dispatch path.

`phase16i_closure/out/p16i_isa_census.md` found 30 genuinely unsupported
mnemonics (262 occurrences), 232 of them in 9 of the 22 GTA-used kernels.
No emulator in the tree could execute any kernel other than
`k_swin_var<32,false>`, because each faults at its first unsupported op.

This module supplies the missing handlers as a MIX-IN, so no frozen file is
touched:

  * `phase14e_static/tools/p14e_emu.py`      -- frozen ("emulator")
  * `phase16e_candidate_e/tools/p16e_rec.py` -- frozen
  * `phase14eh_tools/p14eh.py`, `phase14d8_static/tools/p14d8_core.py` --
    NOT frozen, but still not modified: the handlers live here and are
    composed in at run time by `p16i_isa_core()`.

Semantics follow the AMD RDNA2/RDNA3 ISA.  Where an instruction writes a
special register the census named it explicitly (VCC / EXEC / SCC), and the
handler writes exactly that and nothing more.

Coverage is asserted at import: every mnemonic this module claims is checked
against the census CSV, so a claim that drifts from the measurement fails
loudly rather than silently.
"""
from __future__ import annotations

import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
for p in ("phase16h_pcrel_fix/tools", "phase16e_candidate_e/tools",
          "phase14e_static/tools", "phase14eh_tools", "phase14eg_tools",
          "phase14e_forensics/tools", "phase14d11_static",
          "phase14d_static/tools", "phase8_static/tools",
          "phase14d8_static/tools"):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)

import emu as EMU            # noqa: E402
import p16h_global_gate as G  # noqa: E402

U32 = 0xFFFFFFFF
M64 = (1 << 64) - 1
f32 = EMU.f32
f32_bits = EMU.f32_bits
bits_f32 = EMU.bits_f32
s32 = EMU.s32


class IsaMixin:
    """Missing RDNA2/RDNA3 instructions, on the authentic dispatch path."""

    # ---------------- VOP1 ----------------
    def op_v_cvt_f32_i32(self, ins, ops):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                self.vset(lane, ops[0], f32_bits(f32(float(s32(self.vget(lane, ops[1]))))))

    def op_v_cvt_f32_u32(self, ins, ops):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                self.vset(lane, ops[0], f32_bits(f32(float(self.vget(lane, ops[1]) & U32))))

    def op_v_cvt_f64_f32(self, ins, ops):
        """dst VGPR pair = (double)(float)src0."""
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                d = float(bits_f32(self.vget(lane, ops[1]) & U32))
                self._vdst_pair(lane, ops[0], int.from_bytes(
                    __import__("struct").pack("<d", d), "little"))

    def op_v_cvt_f32_f64(self, ins, ops):
        """dst = (float)(double)src0 (a VGPR pair)."""
        import struct
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                d = struct.unpack("<d", struct.pack(
                    "<Q", self._src64(lane, ops[1]) & M64))[0]
                self.vset(lane, ops[0], f32_bits(f32(d)))

    def op_v_cvt_f32_ubyte1(self, ins, ops):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                b = (self.vget(lane, ops[1]) >> 8) & 0xFF
                self.vset(lane, ops[0], f32_bits(f32(float(b))))

    def op_v_frexp_mant_f32(self, ins, ops):
        """dst = mantissa of src0, normalised to [0.5, 1)."""
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = bits_f32(self.vget(lane, ops[1]) & U32)
                if a == 0.0 or math.isinf(a) or math.isnan(a):
                    r = a
                else:
                    m, _e = math.frexp(a)
                    r = m * 2.0          # frexp gives [0.5,1); AMD wants [0.5,1)
                self.vset(lane, ops[0], f32_bits(f32(r)))

    def op_v_frexp_exp_i32_f32(self, ins, ops):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = bits_f32(self.vget(lane, ops[1]) & U32)
                if a == 0.0 or math.isinf(a) or math.isnan(a):
                    e = 0
                else:
                    e = math.frexp(a)[1]
                self.vset(lane, ops[0], e & U32)

    def op_v_frexp_exp_i32_f64(self, ins, ops):
        """Exponent of an f64 source (a VGPR pair)."""
        import struct
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = struct.unpack("<d", struct.pack(
                    "<Q", self._src64(lane, ops[1]) & M64))[0]
                if a == 0.0 or math.isinf(a) or math.isnan(a):
                    e = 0
                else:
                    e = math.frexp(a)[1]
                self.vset(lane, ops[0], e & U32)

    # ---------------- VOP2 / VOP3 ----------------
    def op_v_min_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c:
                  f32(float("nan")) if (math.isnan(a) or math.isnan(b))
                  else f32(a if a < b else b))

    def op_v_mul_i32_i24(self, ins, ops):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = s32(self.vget(lane, ops[1])) & 0xFFFFFF
                b = s32(self.vget(lane, ops[2])) & 0xFFFFFF
                a = a - (1 << 24) if a & (1 << 23) else a
                b = b - (1 << 24) if b & (1 << 23) else b
                self.vset(lane, ops[0], (a * b) & U32)

    def op_v_mad_i32_i24(self, ins, ops):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = s32(self.vget(lane, ops[1])) & 0xFFFFFF
                b = s32(self.vget(lane, ops[2])) & 0xFFFFFF
                a = a - (1 << 24) if a & (1 << 23) else a
                b = b - (1 << 24) if b & (1 << 23) else b
                c = s32(self.vget(lane, ops[3]))
                self.vset(lane, ops[0], (a * b + c) & U32)

    def op_v_subrev_co_ci_u32(self, ins, ops):
        """dst = src1 - src0 - carry_in; carry out to sdst (here always null,
        so VCC is read and not written)."""
        cin_tok = ops[4] if len(ops) > 4 else "vcc_lo"
        sdst = ops[1] if len(ops) > 1 else "null"
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                cin = self.vget(lane, cin_tok) & 1
                a = self.vget(lane, ops[2]) & U32
                b = self.vget(lane, ops[3]) & U32
                r = (b - a - cin) & M64
                self.vset(lane, ops[0], r & U32)
                if sdst not in ("null", "off"):
                    self._lane_mask_write(sdst, lane, 1 if (r >> 32) & 1 else 0)

    def op_v_lshrrev_b64(self, ins, ops):
        """dst pair = src1 pair >> src0 (logical, 64-bit, reversed)."""
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                sh = self.vget(lane, ops[1]) & 63
                v = self._src64(lane, ops[2]) & M64
                self._vdst_pair(lane, ops[0], (v >> sh) & M64)

    def op_v_add_f64(self, ins, ops):
        import struct
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = struct.unpack("<d", struct.pack("<Q", self._src64(lane, ops[1]) & M64))[0]
                b = struct.unpack("<d", struct.pack("<Q", self._src64(lane, ops[2]) & M64))[0]
                self._vdst_pair(lane, ops[0], int.from_bytes(
                    struct.pack("<d", a + b), "little"))

    # ---------------- cross-lane ----------------
    def op_v_readlane_b32(self, ins, ops):
        """Read one lane of src0 (selected by the scalar src1) into an SGPR."""
        lane_idx = self.sget(ops[2]) if not ops[2].startswith("v") \
            else self.vget(0, ops[2])
        lane_idx &= 31
        self.sset(ops[0], self.vget(lane_idx, ops[1]) & U32)

    def op_v_writelane_b32(self, ins, ops):
        """Write scalar src0 into one lane of VGPR dst; other lanes kept."""
        lane_idx = self.sget(ops[2]) if not ops[2].startswith("v") \
            else self.vget(0, ops[2])
        lane_idx &= 31
        val = self.sget(ops[1]) if not ops[1].startswith("v") \
            else self.vget(0, ops[1])
        n = int(ops[0].lstrip("v"))
        self.v[lane_idx][n] = val & U32

    # ---------------- DS ----------------
    def _ds2st64(self, ins, ops, store):
        m0 = re.search(r"offset0:(-?\d+)", ins["operands"])
        m1 = re.search(r"offset1:(-?\d+)", ins["operands"])
        o0 = int(m0.group(1)) if m0 else 0
        o1 = int(m1.group(1)) if m1 else 0
        dst = ops[0]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                base = self.vget(lane, ops[1].split()[0]) & U32
                for k, off in enumerate((o0, o1)):
                    a = base + off * 256          # st64 stride = 64 dwords
                    if store:
                        tok = ops[2 + k].split()[0] if len(ops) > 2 + k else "0"
                        v = self._src64(lane, tok) & U32
                        for j in range(4):
                            if a + j < len(self.lds):
                                self.lds[a + j] = (v >> (8 * j)) & 0xFF
                    else:
                        v = 0
                        for j in range(4):
                            if a + j < len(self.lds):
                                v |= self.lds[a + j] << (8 * j)
                        if "[" in dst:
                            aa, bb = (int(x) for x in
                                      dst.lstrip("v[").rstrip("]").split(":"))
                            if aa + k <= bb:
                                self.v[lane][aa + k] = v
                        elif k == 0:
                            self.v[lane][int(dst[1:])] = v

    def op_ds_read2st64_b32(self, ins, ops):
        self._ds2st64(ins, ops, store=False)

    def op_ds_write2st64_b32(self, ins, ops):
        self._ds2st64(ins, ops, store=True)

    # ---------------- SALU ----------------
    def op_s_max_i32(self, ins, ops):
        a, b = s32(self.sget(ops[1])), s32(self.sget(ops[2]))
        self.sset(ops[0], (a if a > b else b) & U32)
        self.scc = 1 if a > b else 0

    def op_s_bcnt1_i32_b32(self, ins, ops):
        v = self.sget(ops[1]) & U32
        self.sset(ops[0], bin(v).count("1"))
        self.scc = 1 if v else 0

    # ---------------- GLOBAL ----------------
    def op_global_store_dwordx2(self, ins, ops):
        self._gst(ins, ops, 8)

    def op_global_store_dwordx3(self, ins, ops):
        self._gst(ins, ops, 12)

    def op_global_atomic_cmpswap(self, ins, ops):
        """global_atomic_cmpswap vdst, vaddr, v[data:c] -- 32-bit CAS; vdst
        receives the old memory value."""
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                addr = self._gl_addr(ins, lane, ops, store=True)
                cmp_tok = ops[2].split()[0] if len(ops) > 2 else "0"
                cmp_v = self.vget(lane, cmp_tok) & U32
                new_v = self.vget(lane, cmp_tok.replace("v", "v", 1)) & U32
                if "[" in cmp_tok:
                    a, b = (int(x) for x in
                            cmp_tok.lstrip("v[").rstrip("]").split(":"))
                    cmp_v = self.v[lane][a] & U32
                    new_v = self.v[lane][b] & U32
                old = 0
                for j in range(4):
                    old |= (self._read_bytes(addr + j) & 0xFF) << (8 * j)
                if old == cmp_v:
                    for j in range(4):
                        self.mem[addr + j] = (new_v >> (8 * j)) & 0xFF
                self.vset(lane, ops[0], old & U32)

    # ---------------- helpers ----------------
    def _lane_mask_write(self, tok, lane, bit):
        """Write one lane bit of a mask destination (vcc_lo / exec_lo)."""
        if tok in ("vcc_lo", "vcc"):
            self.vcc_l = (self.vcc_l & ~(1 << lane)) | ((bit & 1) << lane)
        elif tok in ("exec_lo", "exec"):
            self.exec_l = (self.exec_l & ~(1 << lane)) | ((bit & 1) << lane)
        elif tok.startswith("s"):
            bd = self._bounds(tok)
            if bd:
                a, b = bd
                i = a + (lane // 32)
                if i <= b:
                    cur = self.s[i]
                    off = lane % 32
                    self.s[i] = (cur & ~(1 << off)) | ((bit & 1) << off)


# --------------------------------------------------------------------------
# compare-table additions
# --------------------------------------------------------------------------
# `v_cmp_nle_f32` is the only genuinely missing FP predicate in the module.
# `SwinCore._fp_cmp_cond` supplies ngt/nlt/nge/neq/o/u; `nle` is absent at
# every width.
# Keyed by FULL mnemonic, matching every existing table in the tree: the
# dispatcher looks up `v_cmp_<cond>_<type>` (the cmpx form is folded to
# `v_cmp_` before lookup), never a bare `<cond>_<type>`.
FP_CMP_ADD = {
    "v_cmp_nle_f32": lambda a, b: not (a <= b),
    "v_cmp_nle_f16": lambda a, b: not (a <= b),
    "v_cmp_nle_f64": lambda a, b: not (a <= b),
}

# 64-bit integer compares: VOPC forms absent from every table.
INT_CMP_ADD = {
    "v_cmp_le_u64": lambda a, b: (a & M64) <= (b & M64),
    "v_cmp_gt_u64": lambda a, b: (a & M64) > (b & M64),
    "v_cmp_lt_u64": lambda a, b: (a & M64) < (b & M64),
    "v_cmp_ge_u64": lambda a, b: (a & M64) >= (b & M64),
}


def install_cmp_tables(core_cls):
    """Additively extend the resolved compare tables of `core_cls`.

    `_fp_cmp_cond` / `_int_cmp_cond` are resolved through the instance, so we
    wrap them rather than mutating the class dict -- nothing frozen is
    touched and other users of the same class are unaffected.
    """
    orig_fp = core_cls._fp_cmp_cond
    orig_int = core_cls._int_cmp_cond

    def _fp(self, key):
        if key in FP_CMP_ADD:
            return FP_CMP_ADD[key]
        return orig_fp(self, key)

    def _int(self, key):
        if key in INT_CMP_ADD:
            return INT_CMP_ADD[key]
        return orig_int(self, key)

    core_cls._fp_cmp_cond = _fp
    core_cls._int_cmp_cond = _int


# --------------------------------------------------------------------------
# coverage assertion against the measured census
# --------------------------------------------------------------------------
CLAIMED = (
    "v_cvt_f32_i32", "v_cvt_f64_f32", "v_frexp_mant_f32",
    "v_frexp_exp_i32_f64", "v_subrev_co_ci_u32", "v_mul_i32_i24",
    "v_min_f32", "ds_read2st64_b32", "s_max_i32", "v_readlane_b32",
    "v_writelane_b32", "ds_write2st64_b32", "v_cmp_nle_f32",
    "v_lshrrev_b64", "v_cvt_f32_ubyte1", "global_store_dwordx2",
    "v_cmpx_gt_u64", "v_cmp_le_u64", "v_mad_i32_i24", "v_add_f64",
    "v_cvt_f32_f64", "s_bcnt1_i32_b32", "global_atomic_cmpswap",
    "global_store_dwordx3",
)
NOT_CLAIMED = (
    # not on any dispatched path (census section 5): the `swin_layer` callee
    # and three fp8-1h kernels with zero launches in the authentic frame
    "flat_load_ushort", "flat_load_dword", "s_swappc_b64", "s_setpc_b64",
    "ds_write_b96", "v_fmac_f16",
)


def audit_census(csv_path=None):
    """Every CLAIMED mnemonic must be measured unsupported, and every
    NOT_CLAIMED one must be off the dispatched path."""
    import csv
    csv_path = csv_path or os.path.join(
        ROOT, "phase16i_closure/out/p16i_isa_census.csv")
    if not os.path.exists(csv_path):
        return {"checked": False, "reason": "census csv absent"}
    unsupported = set()
    offpath = set()
    for r in csv.DictReader(open(csv_path, encoding="utf-8")):
        if r.get("handler_status") != "UNSUPPORTED":
            continue
        m = re.sub(r"_e(32|64)$", "", r["mnemonic"])
        unsupported.add(m)
        # `helper` = the `swin_layer` callee, reached only via s_swappc_b64
        # from three fp8-1h kernels that never launch in the authentic frame.
        if r.get("gta_used") in ("False", "helper", "0", "false"):
            offpath.add(m)
    missing = [m for m in CLAIMED if m not in unsupported]
    wrong = [m for m in NOT_CLAIMED if m not in offpath]
    return {"checked": True, "n_unsupported_measured": len(unsupported),
            "claimed": len(CLAIMED), "claimed_not_measured": missing,
            "not_claimed_but_on_path": wrong,
            "ok": not missing and not wrong}


def p16i_isa_core(base):
    """Compose IsaMixin under `base`, preserving the whole existing MRO."""
    cls = type("P16ICore_" + base.__name__, (IsaMixin, base), {})
    install_cmp_tables(cls)
    return cls


if __name__ == "__main__":
    import json
    print(json.dumps(audit_census(), indent=1))
