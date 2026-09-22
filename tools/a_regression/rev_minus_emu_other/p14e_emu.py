"""Phase 14E — host-only pre-launch emulation of k_swin_var<32,false>
(zero GPU execution). Reuses the 14D8 descriptor-driven emulator and the
14D11 recorder (RecCore) unchanged; program = the entry-fixed module's own
disassembly slice for the selected kernel.

State derivation: entry from the module's own .kd (class D: kernarg s0:s1,
gap s2..s13 UNDEFINED, wgid_x s14, wgid_y s15, psw_offset s16); kernarg
bytes built from a field spec derived from the VarParams code census:

  ptr fields  -> distinct 64-KiB modeled slot bases (SLOT + k*0x10000 + G)
  scalar fields -> explicit small values
  hidden args  -> from the logical dispatch (block counts = grid,
                  group sizes = block, same convention as 14D8/14D11)

Recorded per run: outcome class, steps, branches, barriers, per-slot
load/store byte-offset ranges and sites, modeled LDS range, soft-WMMA
(dot2/bpermute) site hit census, oob accesses, scratch-site visits.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUTD = os.path.join(os.path.dirname(HERE), "out")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "phase14d8_static", "tools"))
sys.path.insert(0, os.path.join(ROOT, "phase8_static", "tools"))
sys.path.insert(0, os.path.join(ROOT, "phase14d_static", "tools"))
sys.path.insert(0, os.path.join(ROOT, "phase14d11_static", "tools"))

from p14d11_emu import RecCore, dw16   # noqa: E402
import p14d11_emu as P11               # noqa: E402
import emu as EMU                      # noqa: E402
U32 = EMU.U32
TEXT_BASE = 0x3000_0000   # model base for module .text (disjoint from the
                           # fake kernarg/pointer/slot address space, which
                           # occupies 0..~0x2_0010_0000)


def _f16c(x):
    """f32 value -> f16 bits, round-to-nearest-even, exact.

    Phase 16M M2 found three defects in the previous body of this function
    and Phase 16N repaired all three by replacing the algorithm rather than
    patching it:

      * it took the sign from bit 16 of the binary32 pattern -- a MANTISSA
        bit -- instead of bit 31, so every negative result came out positive;
      * it clamped a rounded subnormal significand with `min(frac, 0x3FF)`
        instead of allowing the carry into the normal range, so
        1023.5 * 2**-24 returned 0x03FF where the format gives 0x0400;
      * it reconstructed the significand with `int(round(...))`, whose tie
        rule is round-half-even only by accident of the host representation
        and was never stated.

    The replacement is `emu.f32_bits_to_f16`: a single explicit RNE rounding
    on a 27-bit integer significand, expressed from the format definition.
    """
    import math as _m
    if _m.isnan(x):
        return 0x7E00
    if _m.isinf(x):
        return 0x7C00 | (0x8000 if x < 0 else 0)
    return EMU.f32_bits_to_f16(EMU.f32_bits(EMU.f32(x)))


def _f16_minmax_bits(a, b, want_max):
    """minNum/maxNum over two f16 operands held as f32 values -> f16 bits.

    NaN in either operand yields the OTHER operand; both NaN yields the
    canonical f16 quiet NaN.  Written as an explicit rule so the asymmetry
    Phase 16M measured cannot come back: there is no code path here that
    can return a NaN because of WHICH operand held it.
    """
    a_nan = a != a
    b_nan = b != b
    if a_nan and b_nan:
        return 0x7E00
    if a_nan:
        return _f16c(b)
    if b_nan:
        return _f16c(a)
    if want_max:
        return _f16c(a if a > b else b)
    return _f16c(a if a < b else b)


class SwinCore(RecCore):
    """(recorder fixes defined first, remaining model methods follow)"""

    @staticmethod
    def _gl_width(ins, ops, store):
        m = ins["mnemonic"]
        if "dwordx4" in m or "b128" in m:
            return 16
        if "dwordx3" in m or "b96" in m:
            return 12
        if "dwordx2" in m or "b64" in m:
            return 8
        if "b32" in m or "dword" in m:
            return 4
        if "b16" in m:
            return 2
        if "b8" in m or "byte" in m:
            return 1
        return 0

    # ---- RDNA2 LDS partition model: ea = (vaddr + offset) & (PART-1) ----
    def _lds_ea(self, vaddr, off):
        return (vaddr + off) & (LDS_PART - 1)

    def _ds_load(self, ins, ops, nbytes):
        dst = ops[0]
        addr_tok, _, off = self._ds_parts(ins["text"], nbytes)
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                ea = self._lds_ea(self.vget(lane, addr_tok), off)
                val = 0
                for i in range(nbytes):
                    val |= self.lds[ea + i] << (8 * i)
                if "[" in dst:
                    aa, bb = (int(x) for x in
                              dst.lstrip('v[').rstrip(']').split(':'))
                    for j, i in enumerate(range(aa, bb + 1)):
                        self.v[lane][i] = (val >> (32 * j)) & U32
                else:
                    self.vset(lane, dst, val & U32)

    def _ds_store(self, ins, ops, nbytes):
        addr_tok, data_toks, off = self._ds_parts(ins["text"], nbytes)
        if not data_toks:
            raise EMU.NotImpl(f"ds store data parse: {ins['text']}")
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                ea = self._lds_ea(self.vget(lane, addr_tok), off)
                dwords = []
                for t in data_toks:
                    dwords.extend(self._ds_data_dwords(lane, t))
                nbytes_left = nbytes
                di = 0
                while nbytes_left > 0 and di < len(dwords):
                    nb = min(4, nbytes_left)
                    v = dwords[di]
                    for j in range(nb):
                        self.lds[ea + di * 4 + j] = (v >> (8 * j)) & 0xFF
                    nbytes_left -= nb
                    di += 1

    def _record_ds(self, ins):
        # corrected recorder: loads/reads carry (dst..., vaddr) with the
        # address as the LAST v-token; stores carry (vaddr, data...).
        import re as _re
        ops_raw = ins.get("operands") or ""
        mnem = ins["mnemonic"]
        olist = [o.strip() for o in ops_raw.split(",")] if ops_raw else []
        vtoks = [o.split()[0] for o in olist
                 if re.match(r'^v\d+$', o.split()[0])]
        if not vtoks:
            return
        is_load = ("load" in mnem or "read" in mnem)
        addr_tok = vtoks[-1] if is_load else vtoks[0]
        n = int(addr_tok.lstrip("v"))
        off = 0
        mm = _re.search(r"offset:(-?0x[0-9a-fA-F]+|-?\d+)", ops_raw)
        if mm:
            off = int(mm.group(1), 0)
        m1 = _re.search(r"offset1:(-?\d+)", ops_raw)
        o1 = int(m1.group(1)) if m1 else 0
        store = ("store" in mnem or "write" in mnem)
        nb = 16 if ("128" in mnem or "x4" in mnem) else \
            8 if ("64" in mnem or "x2" in mnem or "2addr" in mnem or
                  "write2" in mnem or "read2" in mnem) else \
            4 if ("32" in mnem) else \
            2 if ("16" in mnem) else 1
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self._lds_ea(self.v[lane][n], off)
                self.ds_ops.append((store, a, nb, ins.get("address")))
                if "read2" in mnem or "write2" in mnem:
                    unit = 8 if "64" in mnem else 4
                    a2 = self._lds_ea(self.v[lane][n], o1 * unit)
                    self.ds_ops.append((store, a2, nb,
                                        ins.get("address")))
    """14E additive model: IEEE fp-compare predicates the base table lacks
    (unordered/not-* family), same deterministic convention as the existing
    entries (plain negation of the ordered test), plus the 28 instruction
    families the SWIN slice uses that the phase-8/14D emulator did not
    model (fp16 scalar/packed arithmetic, wider ds forms, scratch, few
    scalar/vector ops). All are deterministic; value rounding follows the
    house f32<->f16 approximation used everywhere else in the emulator."""

    def _cmpx_dispatch(self, m, ins, ops):
        name = m.replace("v_cmpx_", "v_cmp_")
        try:
            cond = self._int_cmp_cond(name)
            self._vcmpx(ins, ops, cond, fp=False)
        except KeyError:
            cond = self._fp_cmp_cond(name)
            self._vcmpx(ins, ops, cond, fp=(not name.endswith("_f16")))

    def _cmp_dispatch(self, m, ins, ops):
        # `v_cmp_class_f32` carries a class MASK, not a value, so it has no
        # entry in either table.  This override used to fall straight through
        # to `_fp_cmp_cond` and raise KeyError for it, bypassing the base
        # class's special case.
        if m == "v_cmp_class_f32":
            self._vcmp_class(ins, ops)
            return
        # int table first, fp fallback (covers every int name incl. i8/i16)
        try:
            self._vcmp(ins, ops, self._int_cmp_cond(m), fp=False)
        except KeyError:
            cond = self._fp_cmp_cond(m)
            self._vcmp(ins, ops, cond, fp=(not m.endswith("_f16")))

    def _int_cmp_cond(self, name):
        """Base table + missing i32/i8 families the SWIN slice needs."""
        import emu as _E
        base = {  # mirror of emu.Core._int_cmp_cond (27 keys)
            "v_cmp_eq_i16": lambda a, b: _E._s16(a) == _E._s16(b),
            "v_cmp_eq_i32": lambda a, b: _E.s32(a) == _E.s32(b),
            "v_cmp_eq_i8": lambda a, b: _E._s8(a) == _E._s8(b),
            "v_cmp_eq_u16": lambda a, b: (a & 0xFFFF) == (b & 0xFFFF),
            "v_cmp_eq_u32": lambda a, b: (a & U32) == (b & U32),
            "v_cmp_ge_i16": lambda a, b: _E._s16(a) >= _E._s16(b),
            "v_cmp_ge_i8": lambda a, b: _E._s8(a) >= _E._s8(b),
            "v_cmp_ge_u16": lambda a, b: (a & 0xFFFF) >= (b & 0xFFFF),
            "v_cmp_ge_u32": lambda a, b: (a & U32) >= (b & U32),
            "v_cmp_gt_i16": lambda a, b: _E._s16(a) > _E._s16(b),
            "v_cmp_gt_i32": lambda a, b: _E.s32(a) > _E.s32(b),
            "v_cmp_gt_i8": lambda a, b: _E._s8(a) > _E._s8(b),
            "v_cmp_gt_u16": lambda a, b: (a & 0xFFFF) > (b & 0xFFFF),
            "v_cmp_gt_u32": lambda a, b: (a & U32) > (b & U32),
            "v_cmp_le_i16": lambda a, b: _E._s16(a) <= _E._s16(b),
            "v_cmp_le_i8": lambda a, b: _E._s8(a) <= _E._s8(b),
            "v_cmp_le_u16": lambda a, b: (a & 0xFFFF) <= (b & 0xFFFF),
            "v_cmp_le_u32": lambda a, b: (a & U32) <= (b & U32),
            "v_cmp_lt_i16": lambda a, b: _E._s16(a) < _E._s16(b),
            "v_cmp_lt_i8": lambda a, b: _E._s8(a) < _E._s8(b),
            "v_cmp_lt_u16": lambda a, b: (a & 0xFFFF) < (b & 0xFFFF),
            "v_cmp_lt_u32": lambda a, b: (a & U32) < (b & U32),
            "v_cmp_ne_i16": lambda a, b: _E._s16(a) != _E._s16(b),
            "v_cmp_ne_i32": lambda a, b: _E.s32(a) != _E.s32(b),
            "v_cmp_ne_i8": lambda a, b: _E._s8(a) != _E._s8(b),
            "v_cmp_ne_u16": lambda a, b: (a & 0xFFFF) != (b & 0xFFFF),
            "v_cmp_ne_u32": lambda a, b: (a & U32) != (b & U32),
            # phase-14E additive (SWIN needs them):
            "v_cmp_lt_i32": lambda a, b: _E.s32(a) < _E.s32(b),
            "v_cmp_le_i32": lambda a, b: _E.s32(a) <= _E.s32(b),
            "v_cmp_ge_i32": lambda a, b: _E.s32(a) >= _E.s32(b),
        }
        return base[name]

    # ---- fp compare condition extensions ----
    def _fp_cmp_cond(self, name):
        try:
            return super()._fp_cmp_cond(name)
        except KeyError:
            import math
            f = EMU.f16_to_f32
            extras = {
                "v_cmp_nlt_f16": lambda a, b: not (f(a) < f(b)),
                "v_cmp_nge_f16": lambda a, b: not (f(a) >= f(b)),
                "v_cmp_ngt_f16": lambda a, b: not (f(a) > f(b)),
                "v_cmp_neq_f16": lambda a, b: f(a) != f(b),
                "v_cmp_ngt_f32": lambda a, b: not (a > b),
                "v_cmp_nlt_f64": lambda a, b: not (a < b),
                "v_cmp_nge_f64": lambda a, b: not (a >= b),
                "v_cmp_ngt_f64": lambda a, b: not (a > b),
                "v_cmp_neq_f64": lambda a, b: a != b,
                "v_cmp_o_f64": lambda a, b: not (math.isnan(a)
                                                 or math.isnan(b)),
                "v_cmp_u_f16": lambda a, b: math.isnan(f(a))
                or math.isnan(f(b)),
                "v_cmp_u_f32": lambda a, b: math.isnan(a) or math.isnan(b),
                "v_cmp_u_f64": lambda a, b: math.isnan(a) or math.isnan(b),
            }
            return extras[name]

    # ---- fp16 scalar arithmetic (low 16 bits; upper half preserved) ----
    def _f16_arith(self, ins, ops, fn):
        f = EMU.f16_to_f32
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self._f16_operand(lane, ops[1])
                b = self._f16_operand(lane, ops[2]) if len(ops) > 2 else None
                c = self._f16_operand(lane, ops[3]) if len(ops) > 3 else None
                r = fn(a, b, c)
                # The scalar `_e32` f16 forms WRITE THE WHOLE DESTINATION:
                # the result occupies the low half and the upper half is
                # zeroed.  This used to preserve the destination's upper 16
                # bits, which Phase 16M recorded as AMBIGUOUS because the
                # evidence then available did not settle it.  It is settled
                # by the format of the instruction, and it is checked here
                # against the corpus: every `v_add_f16` in the disassembly is
                # paired with `ds_read_u16` above it and `ds_write_b16` below
                # it, so the upper half is dead in this kernel either way --
                # the change is visible in the vector, not in the SWIN run.
                self.vset(lane, ops[0], _f16c(r) & 0xFFFF)

    def _f16_operand(self, lane, tok):
        """f16 operand -> f32 value: register = raw f16 bits in low half;
        hex literal = f16 bits (post-normalization); remaining float text
        (e.g. -4.0) is already the value."""
        import re as _re
        tok = tok.strip()
        if tok.lower().startswith('0x'):
            return EMU.f16_to_f32(int(tok, 0))
        if tok not in ('null', 'off'):
            try:
                return float(tok)
            except ValueError:
                pass
        return EMU.f16_to_f32(self.vget(lane, tok) & 0xFFFF)

    def op_v_add_f16(self, ins, ops):
        self._f16_arith(ins, ops, lambda a, b, c: a + b)

    def op_v_mul_f16(self, ins, ops):
        self._f16_arith(ins, ops, lambda a, b, c: a * b)

    # ---- packed fp16 (2 lanes/dword) ----
    def _pk_operand(self, lane, tok):
        """packed f16 operand -> (lo_f32, hi_f32). Registers hold two raw
        f16 lanes; numeric literals broadcast to both lanes."""
        import re as _re
        tok = tok.strip()
        if tok.lower().startswith('0x'):
            v = EMU.f16_to_f32(int(tok, 0))
            return v, v
        if tok not in ('null', 'off'):
            try:
                v = float(tok)
                return v, v
            except ValueError:
                pass
        f = EMU.f16_to_f32
        x = self.vget(lane, tok)
        return f(x & 0xFFFF), f((x >> 16) & 0xFFFF)

    def _pk2(self, ins, ops, fn):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                al, ah = self._pk_operand(lane, ops[1])
                bl = bh = cl = ch = None
                if len(ops) > 2:
                    bl, bh = self._pk_operand(lane, ops[2])
                if len(ops) > 3:
                    cl, ch = self._pk_operand(lane, ops[3])
                rl = fn(al, bl, cl)
                rh = fn(ah, bh, ch)
                self.vset(lane, ops[0],
                          ((_f16c(rh) & 0xFFFF) << 16) | (_f16c(rl) & 0xFFFF))

    def op_v_pk_add_f16(self, ins, ops):
        self._pk2(ins, ops, lambda a, b, c: a + b)

    def op_v_pk_mul_f16(self, ins, ops):
        self._pk2(ins, ops, lambda a, b, c: a * b)

    def op_v_pk_fma_f16(self, ins, ops):
        self._pk2(ins, ops, lambda a, b, c: a * b + c)

    # ---- packed f16 min/max: minNum/maxNum, NaN handled explicitly -------
    # Phase 16M M2 defect 3: these were `a if a >= b else b` and
    # `a if a <= b else b`, which return the NaN when it is in src1 but the
    # other operand when it is in src0 -- not even self-consistent, because
    # every IEEE comparison against a NaN is false.  The contract is the
    # minNum/maxNum one the project's own kernels assume: a NaN operand
    # yields the OTHER operand, and two NaNs yield a canonical quiet NaN.
    def _pk_minmax(self, ins, ops, want_max):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                al, ah = self._pk_operand(lane, ops[1])
                bl, bh = self._pk_operand(lane, ops[2])
                rl = _f16_minmax_bits(al, bl, want_max)
                rh = _f16_minmax_bits(ah, bh, want_max)
                self.vset(lane, ops[0], (rh << 16) | rl)

    def op_v_pk_max_f16(self, ins, ops):
        self._pk_minmax(ins, ops, True)

    def op_v_pk_min_f16(self, ins, ops):
        self._pk_minmax(ins, ops, False)

    # ---- misc vector ops ----
    def op_v_alignbit_b32(self, ins, ops):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[1]) & U32
                b = self.vget(lane, ops[2]) & U32
                s = self.vget(lane, ops[3]) & 31
                r = (a >> s) | ((b << (32 - s)) & U32) if s else a
                self.vset(lane, ops[0], r & U32)

    def op_v_not_b32(self, ins, ops):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                self.vset(lane, ops[0], (~self.vget(lane, ops[1])) & U32)

    def op_v_max_f32(self, ins, ops):
        import math
        self._vfp(ins, ops, lambda a, b, c:
                  EMU.f32(a if a >= b else b) if not (math.isnan(a)
                                                      or math.isnan(b))
                  else EMU.f32(float('nan')))

    def op_v_med3_f32(self, ins, ops):
        self._vfp(ins, ops,
                  lambda a, b, c: EMU.f32(
                      max(min(a, b), min(max(a, b), c))))

    def op_v_exp_f32(self, ins, ops):
        """V_EXP_F32 = 2**a.

        Same defect class as `op_v_rsq_f32` above, caught by inspection
        rather than by a run: `2.0 ** a` raises `OverflowError` in Python
        once `a` exceeds 1024, where the architectural result is simply
        `+inf`.  A kernel value that large would abort the dispatch.
        """
        import math
        def f(a, b, c):
            if math.isnan(a):
                return float('nan')
            try:
                return EMU.f32(2.0 ** a)
            except OverflowError:
                return float('inf')
        self._vfp(ins, ops, f)

    def op_v_rsq_f32(self, ins, ops):
        """V_RSQ_F32.

        This override shadows `emu.Core.op_v_rsq_f32`, which DOES guard the
        negative and NaN cases; this one only guarded zero.  Between Phase
        14E and Phase 16M, therefore, a negative operand reached
        `math.sqrt` and raised

            ValueError: expected a nonnegative input, got -199046709248.0

        which aborts the dispatch instead of producing the architectural
        result.  Exactly the shape of Phase 16L's defect G (`v_ldexp_f32`
        aborting on a NaN exponent): a CRASH under the kernel, not a wrong
        value, and therefore invisible to any count that only looks at
        outputs.

        It became reachable in Phase 16M because repairing
        `s_andn2_saveexec_b32` put the divergent else-blocks on the lanes
        they were written for, and swin32t then fed a negative value here.
        The guard is restored to match the base class.
        """
        import math
        def f(a, b, c):
            if math.isnan(a) or a < 0:
                return float('nan')
            if a == 0:
                return EMU.f32(math.copysign(float('inf'), a))
            return EMU.f32(1.0 / math.sqrt(a))
        self._vfp(ins, ops, f)

    def op_v_ffbh_u32(self, ins, ops):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[1]) & U32
                # result = index of most significant set bit (0..31);
                # zero operand -> 0xFFFFFFFF (HW convention for this op)
                r = 0xFFFFFFFF if a == 0 else a.bit_length() - 1
                self.vset(lane, ops[0], r & U32)

    def op_v_fmamk_f32(self, ins, ops):
        # v_fmamk_f32 vd, s0, imm, v2 : vd = s0 * imm + v2
        import struct as _st
        imm_tok = ops[2]
        try:
            imm = int(imm_tok, 0)
        except ValueError:
            imm = int(float(imm_tok))
        immf = _st.unpack('<f', _st.pack('<I', imm & U32))[0]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[1], fp=True)
                c = self.vget(lane, ops[3], fp=True) if len(ops) > 3 else 0
                self.vset(lane, ops[0], EMU.f32_bits(EMU.f32(a * immf + c)))

    def op_v_fma_mix_f32(self, ins, ops):
        # packed mix: sum of two fp16 products added to f32 acc (per the
        # mix family); operands may be f16/f32 per op_sel - approximate
        # with lo/hi f16 pair of ops[1] * pair of ops[2], accumulate fp32.
        f = EMU.f16_to_f32
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[1])
                b = self.vget(lane, ops[2])
                c = self.vget(lane, ops[3], fp=True) if len(ops) > 3 else 0
                r = (f(a & 0xFFFF) * f(b & 0xFFFF)
                     + f((a >> 16) & 0xFFFF) * f((b >> 16) & 0xFFFF) + c)
                self.vset(lane, ops[0], EMU.f32_bits(EMU.f32(r)))

    # ---- scalar extras ----
    def op_s_addk_i32(self, ins, ops):
        # `0x100` and `-4` both occur; `int(tok, 0)` handles the prefixed form
        # but not a bare negative decimal, and `& U32` makes the addition
        # wraparound correct for either.  This handler was already correct --
        # it is recorded here because the Phase 16L scalar oracle was written
        # expecting the three-operand form and had to be corrected instead.
        dst = int(ops[0][1:])
        imm = int(ops[1], 0)
        self.s[dst] = (self.s[dst] + imm) & U32

    def op_s_nor_b32(self, ins, ops):
        dst = int(ops[0][1:])
        a = int(ops[1][1:]) if ops[1].startswith('s') else 0
        self.s[dst] = (~(self.sget(ops[1]) | self.sget(ops[2]))) & U32

    def op_s_orn2_b32(self, ins, ops):
        self.sset(ops[0], (self.sget(ops[1]) | (~self.sget(ops[2]) & U32))
                  & U32)

    def op_s_getpc_b64(self, ins, ops):
        # PC = module .text address of the instruction following this one
        import re as _re
        m = _re.match(r's\[(\d+):(\d+)\]', ops[0])
        pc = TEXT_BASE + (ins.get("address") or 0) + 4
        if m:
            self.s[int(m.group(1))] = pc & U32
            self.s[int(m.group(2))] = (pc >> 32) & U32
        else:
            raise EMU.NotImpl(f"s_getpc_b64 {ins['text']}")

    def op_s_cmp_lg_u64(self, ins, ops):
        import re as _re
        m0 = _re.match(r's\[(\d+):(\d+)\]', ops[0])
        m1 = _re.match(r's\[(\d+):(\d+)\]', ops[1])
        if m0 and m1:
            a = (self.s[int(m0.group(2))] << 32) | self.s[int(m0.group(1))]
            b = (self.s[int(m1.group(2))] << 32) | self.s[int(m1.group(1))]
            self.scc = 1 if (a & ((1 << 64) - 1)) != (b & ((1 << 64) - 1)) \
                else 0
        elif m1 is None:
            a = (self.s[int(m0.group(2))] << 32) | self.s[int(m0.group(1))]
            b = self.sget(ops[1]) & 0xFFFFFFFF
            self.scc = 1 if (a != b) else 0
        else:
            raise EMU.NotImpl(f"s_cmp_lg_u64 {ins['text']}")

    # ---- wider ds forms (byte-accurate on self.lds, bounds-guarded) ----
    def _ds_load_bytes(self, ins, ops, nbytes, d16_hi=False):
        dst = ops[0]
        import re as _re
        addr_tok = ops[1].split()[0]
        off = 0
        mm = _re.search(r'offset:(-?0x[0-9a-fA-F]+|-?\d+)', ins['operands'])
        if mm:
            off = int(mm.group(1), 0)
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                ea = self._lds_ea(self.vget(lane, addr_tok), off)
                val = 0
                for i in range(nbytes):
                    val |= self.lds[ea + i] << (8 * i)
                if "[" in dst:
                    aa, bb = (int(x) for x in
                              dst.lstrip('v[').rstrip(']').split(':'))
                    if bb - aa + 1 != nbytes // 4:
                        raise EMU.NotImpl(f"ds read width {ins['text']}")
                    for j, i in enumerate(range(aa, bb + 1)):
                        self.v[lane][i] = (val >> (32 * j)) & U32
                elif d16_hi:
                    cur = self.vget(lane, dst)
                    self.vset(lane, dst,
                              (cur & 0xFFFF) | ((val & 0xFFFF) << 16))
                else:
                    self.vset(lane, dst, val & U32)

    def _ds_store_bytes(self, ins, ops, nbytes):
        # ds_write_*: [vaddr, vdata...]
        import re as _re
        addr_tok = ops[0].split()[0]
        data_tok = ops[1].split()[0]
        off = 0
        mm = _re.search(r'offset:(-?0x[0-9a-fA-F]+|-?\d+)', ins['operands'])
        if mm:
            off = int(mm.group(1), 0)
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                ea = self._lds_ea(self.vget(lane, addr_tok), off)
                if "[" in data_tok:
                    aa, bb = (int(x) for x in
                              data_tok.lstrip('v[').rstrip(']').split(':'))
                    dvals = [self.v[lane][i] for i in range(aa, bb + 1)]
                else:
                    dvals = [self.v[lane][int(data_tok[1:])]]
                nleft = nbytes
                for j, v in enumerate(dvals):
                    if nleft <= 0:
                        break
                    nb = min(4, nleft)
                    for k in range(nb):
                        self.lds[ea + 4 * j + k] = (v >> (8 * k)) & 0xFF
                    nleft -= nb

    def op_ds_read_b64(self, ins, ops):
        self._ds_load_bytes(ins, ops, 8)

    def op_ds_load_b64(self, ins, ops):
        # original-gfx1100 mnemonic family (pair dst)
        self._ds_load_bytes(ins, ops, 8)

    def op_ds_load_b128(self, ins, ops):
        self._ds_load_bytes(ins, ops, 16)

    def op_ds_read_b128(self, ins, ops):
        self._ds_load_bytes(ins, ops, 16)

    def op_ds_read_b128(self, ins, ops):
        self._ds_load_bytes(ins, ops, 16)

    def op_ds_write_b128(self, ins, ops):
        self._ds_store_bytes(ins, ops, 16)

    def op_ds_read_u16_d16_hi(self, ins, ops):
        self._ds_load_bytes(ins, ops, 2, d16_hi=True)

    def _ds2_b64(self, ins, ops, store):
        # ISA conventions (mirroring validated op_ds_write2_b32/read2_b32):
        #   write2_b64 vaddr, vdata0(2 dw), vdata1(2 dw) [offset0/offset1]
        #   read2_b64  vdata-dst(4 dw), vaddr [offset0/offset1]
        # offsets in units of 8 B for the b64 form.
        import re as _re
        m0 = _re.search(r'offset0:(-?\d+)', ins['operands'])
        m1 = _re.search(r'offset1:(-?\d+)', ins['operands'])
        o0 = int(m0.group(1)) if m0 else 0
        o1 = int(m1.group(1)) if m1 else 0
        if store:
            addr_tok = ops[0].split()[0]
            d0t = ops[1].split()[0]
            d1t = ops[2].split()[0] if len(ops) > 2 else None
        else:
            dst = ops[0]
            addr_tok = ops[1].split()[0]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                base = self.vget(lane, addr_tok)
                for j, o in enumerate((o0, o1)):
                    a8 = self._lds_ea(base, o * 8)
                    if store:
                        t = d0t if j == 0 else d1t
                        if t is None:
                            dw = 0
                        elif '[' in t:
                            aa, bb = (int(x) for x in
                                      t.lstrip('v[').rstrip(']')
                                      .split(':'))
                            dw = self.v[lane][aa] & U32
                            if bb > aa:
                                dw |= (self.v[lane][aa + 1] & U32) << 32
                        else:
                            dw = self.v[lane][int(t[1:])] & U32
                        for k in range(8):
                            self.lds[a8 + k] = (dw >> (8 * k)) & 0xFF
                    else:
                        aa, bb = (int(x) for x in
                                  dst.lstrip('v[').rstrip(']').split(':'))
                        v = 0
                        for k in range(8):
                            v |= self.lds[a8 + k] << (8 * k)
                        if aa + 2 * j + 1 <= bb:
                            self.v[lane][aa + 2 * j] = v & U32
                            self.v[lane][aa + 2 * j + 1] = (v >> 32) & U32

    def op_ds_read2_b64(self, ins, ops):
        self._ds2_b64(ins, ops, store=False)

    def op_ds_write2_b64(self, ins, ops):
        self._ds2_b64(ins, ops, store=True)

    def op_global_store_short(self, ins, ops):
        self._gst(ins, ops, 2)

    # ---- scratch: per-lane private byte regions (implicit scratch) ----
    def _scratch_init(self):
        if not hasattr(self, 'priv'):
            self.priv = [bytearray(0x1000) for _ in range(self.lanes)]

    def op_scratch_store_dword(self, ins, ops):
        self._scratch_init()
        self._scratch_store(ins, ops, 4)

    def op_scratch_store_dwordx4(self, ins, ops):
        self._scratch_init()
        self._scratch_store(ins, ops, 16)

    def op_scratch_load_ubyte(self, ins, ops):
        self._scratch_init()
        self._scratch_load(ins, ops, 1)

    def op_scratch_load_dword(self, ins, ops):
        self._scratch_init()
        self._scratch_load(ins, ops, 4)

    def _scratch_store(self, ins, ops, nbytes):
        import re as _re
        data = None
        for o in ops:
            if o.startswith('v'):
                data = o
                break
        off = 0
        mm = _re.search(r'offset:(-?0x[0-9a-fA-F]+|-?\d+)', ins['operands'])
        if mm:
            off = int(mm.group(1), 0)
        addr = 0
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                base = (addr + off) & 0xFFF
                if "[" in data:
                    aa, bb = (int(x) for x in
                              data.lstrip('v[').rstrip(']').split(':'))
                    dvals = [self.v[lane][i] for i in range(aa, bb + 1)]
                else:
                    dvals = [self.v[lane][int(data[1:])]]
                nleft = nbytes
                for j, v in enumerate(dvals):
                    if nleft <= 0:
                        break
                    nb = min(4, nleft)
                    for k in range(nb):
                        self.priv[lane][(base + 4 * j + k) & 0xFFF] = \
                            (v >> (8 * k)) & 0xFF
                    nleft -= nb

    def _scratch_load(self, ins, ops, nbytes):
        import re as _re
        dst = ops[0]
        addr_tok = ops[1].split()[0]
        off = 0
        mm = _re.search(r'offset:(-?0x[0-9a-fA-F]+|-?\d+)', ins['operands'])
        if mm:
            off = int(mm.group(1), 0)
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                base = (self.vget(lane, addr_tok) + off) & 0xFFF
                if base + nbytes > len(self.priv[lane]):
                    continue
                val = 0
                for i in range(nbytes):
                    val |= self.priv[lane][base + i] << (8 * i)
                self.vset(lane, dst, val & U32)

KERNEL = "_Z10k_swin_varILi32ELb0EEv9VarParams"
ENT_DIS = P11.ENT_DIS
ENT_CO = P11.ENT_CO
ORIG_DIS = P11.ORIG_DIS
ORIG_OBJ = P11.ORIG_OBJ

KERNARG = P11.KERNARG
PACKET = P11.PACKET
SLOT = P11.SLOT
GUARD = P11.GUARD
STRIDE = P11.STRIDE

LDS = 15632          # descriptor group_segment_fixed_size
LDS_PART = 0x4000     # RDNA2 per-wave-slot LDS partition: ds effective
                      # address = (vaddr + offset) & (PART-1); the code
                      # relies on this wrap (negative pre-increment forms)


def slice_program(dispath, kernel):
    return P11.slice_program(dispath, kernel)


def text_mem_map(path):
    """Map the module's .text bytes at their module addresses so PC-relative
    constant-pool loads (s_getpc + delta) read the real embedded values."""
    import p14d_kd as kd
    data, sections, syms = kd.parse_elf(path)
    mem = {}
    for s in sections:
        if s.get('name') in ('.text', '.text.1') and s.get('type') == 1:
            off, size = s['offset'], s['size']
            for i in range(size):
                mem[TEXT_BASE + off + i] = data[off + i]
    return mem


def swin_mem(fields, grid, block):
    """Build kernarg mem dict. fields = {offset(int): ('ptr', k) |
    ('u32', v) | ('u64', v)} ; ptr slot k base = SLOT + k*STRIDE + GUARD.
    Hidden args filled from grid/block (same convention as 14D8 conv_mem:
    block counts = grid dims, group sizes = block dims, rem = grid%block)."""
    mem = {}
    for off, (kind, val) in fields.items():
        if kind == "ptr":
            base = SLOT + val * STRIDE + GUARD
            mem[KERNARG + off] = base & 0xFFFFFFFF
            mem[KERNARG + off + 4] = (base >> 32) & 0xFFFFFFFF
        elif kind == "u32":
            mem[KERNARG + off] = val & 0xFFFFFFFF
        elif kind == "u64":
            mem[KERNARG + off] = val & 0xFFFFFFFF
            mem[KERNARG + off + 4] = (val >> 32) & 0xFFFFFFFF
    gx, gy, gz = grid
    bx, by, bz = block
    H = 168  # hidden args start (this kernel's .note layout)
    mem[KERNARG + H + 0] = gx & 0xFFFFFFFF
    mem[KERNARG + H + 4] = gy & 0xFFFFFFFF
    mem[KERNARG + H + 8] = gz & 0xFFFFFFFF
    mem[KERNARG + H + 12] = (bx & 0xFFFF) | ((by & 0xFFFF) << 16)
    mem[KERNARG + H + 16] = (bz & 0xFFFF) | ((gx % bx) << 16)
    mem[KERNARG + H + 18] = (gy % by) & 0xFFFFFFFF
    mem[KERNARG + H + 20] = (gz % bz) & 0xFFFFFFFF
    mem[KERNARG + H + 40] = 0  # global offsets x (0x88 rel)
    mem[KERNARG + H + 44] = 0
    mem[KERNARG + H + 48] = 0
    mem[KERNARG + H + 52] = 0
    mem[KERNARG + H + 56] = 0
    mem[KERNARG + H + 60] = 0
    mem[KERNARG + H + 64] = 1  # grid_dims
    return mem


_FLOAT_RE = re.compile(r'^-?(?:\d+\.\d+|\.\d+)$')


def _norm_float_ops(prog):
    """The disassembler prints inline fp constants as floats (0.5, -4.0).
    Rewrite them to raw bit tokens: f16 ops -> f16 bits, others -> f32 bits
    (matches how the emulator stores f16/f32 register values)."""
    import struct as _st
    done = False
    for ins in prog:
        mnem = ins.get("mnemonic", "")
        if not ins.get("operands"):
            continue
        parts = ins["operands"].split(",")
        out = []
        changed = False
        for tok in parts:
            tk = tok.strip()
            m = _FLOAT_RE.match(tk)
            if m:
                v = float(tk)
                if "f16" in mnem or "pk_" in mnem or "mix" in mnem:
                    bits = _f16c(v) if False else _f16_bits(v)
                else:
                    bits = _st.unpack("<I", _st.pack("<f", v))[0]
                out.append(f"0x{bits:x}")
                changed = True
            else:
                out.append(tk)
        if changed:
            ins["operands"] = ", ".join(out)
            ins["text"] = ins["mnemonic"] + " " + ins["operands"]
            done = True
    return done


def _f16_bits(x):
    """Exact-ish f32 value -> f16 bits (reuse _f16c path)."""
    return _f16c(x)


def trace(prog, dw16_, label, grid, block, wg, wavebase, fields,
          events_cap=2_000_000, dump_path=None, snap_sites=None,
          lds_size=LDS_PART, text_path=None):
    if not getattr(prog, "_normed_float_ops", False):
        _norm_float_ops(prog)
        try:
            prog._normed_float_ops = True
        except AttributeError:
            pass
    mem = swin_mem(fields, grid, block)
    if text_path is not None:
        tm = text_mem_map(text_path)
        mem.update(tm)
        text_hi = (max(tm) + 1) if tm else 0
    else:
        text_hi = 0
    core = SwinCore(prog, lanes=32, lds_size=lds_size, lds_fill=0,
                    wavebase=wavebase, mem=mem)
    # This trace iterates `core.g_ops` / `core.ds_ops` expecting EVERY event
    # (per-slot reach, the OOB scan, the dump), so it declares FULL_TRACE
    # rather than silently reading the AGGREGATE sample.
    P11.REC.force_full(core, max_events=max(events_cap * 2, 1 << 20),
                       label="p14e.trace")
    core._prog_ref = prog
    plan = P11.entry_plan(dw16_)
    P11.fill_entry(core, plan, kernarg=KERNARG, dispatch_ptr=PACKET,
                   wgid=wg, wavebase=wavebase, block=block)
    snaps = {a: [] for a in (snap_sites or {})}
    n_br = 0
    n_bar = 0
    dot_hits = {}
    bp_hits = {}
    scratch_sites = {}
    exec_stream = []
    outcome = None
    try:
        while core.steps < 6_000_000:
            ins = prog[core.pc]
            mnem = ins["mnemonic"]
            site = ins.get("address")
            exec_stream.append((site, mnem, ins.get("operands", "")))
            if snap_sites and site in snap_sites:
                snaps[site].append([core.s[i] for i in snap_sites[site]])
            if mnem.startswith("s_cbranch") or mnem == "s_branch":
                n_br += 1
            elif "barrier" in mnem:
                n_bar += 1
            elif mnem in ("v_dot2c_f32_f16", "v_wmma_f32_16x16x16_f16"):
                dot_hits[site] = dot_hits.get(site, 0) + 1
            elif mnem == "ds_bpermute_b32":
                bp_hits[site] = bp_hits.get(site, 0) + 1
            elif mnem.startswith("scratch_"):
                scratch_sites[site] = scratch_sites.get(site, 0) + 1
            core.step()
            if core.terminated:
                outcome = ("END", core.steps)
                break
            if len(core.g_ops) > events_cap:
                outcome = ("EVENTCAP", core.steps)
                break
        if outcome is None:
            outcome = ("STEPLIMIT", core.steps)
    except P11.Halt as h:
        outcome = (h.kind, core.steps, getattr(h, "info", None))
    except P11.NotImpl as e:
        outcome = ("NOTIMPL", core.steps, str(e))
    except Exception as e:  # unmodeled instruction family -> fail closed
        site = None
        try:
            prev = prog[core.pc - 1]
            site = prev.get("address")
            outcome = ("EXC", core.steps,
                       f"{type(e).__name__}: {e} @ "
                       f"{(f'0x{site:x}' if site else '?')} "
                       f"{prev['mnemonic']} {prev.get('operands','')[:60]}")
        except Exception:
            outcome = ("EXC", core.steps, f"{type(e).__name__}: {e}")
    # ---- analysis ----
    windows = [(KERNARG - 0x2000, KERNARG + 0x2000),
               (PACKET - 0x100, PACKET + 0x100)]
    if text_hi:
        windows.append((0, text_hi + 0x100))
    n_slots = 16
    for k in range(n_slots):
        windows.append((SLOT + k * STRIDE, SLOT + k * STRIDE + STRIDE))
    oob = []
    for is_store, addr, nb, site in core.g_ops:
        if not any(lo <= addr < hi for lo, hi in windows):
            oob.append((is_store, addr, nb, site))
            if is_store:
                break
    per_slot = {}
    for is_store, addr, nb, site in core.g_ops:
        for k in range(n_slots):
            if SLOT + k * STRIDE <= addr < SLOT + (k + 1) * STRIDE:
                off = addr - (SLOT + k * STRIDE + GUARD)
                per_slot.setdefault(k, {"ld": [], "st": []})
                per_slot[k]["ld" if not is_store else "st"].append(
                    (off, off + nb, nb, site))
                break
    slot_sum = {}
    for k, d in per_slot.items():
        row = {}
        for kind in ("ld", "st"):
            v = d[kind]
            if v:
                row[kind] = {"count": len(v),
                             "min_offset": min(x[0] for x in v),
                             "max_offset": max(x[1] for x in v)}
            else:
                row[kind] = {"count": 0}
        slot_sum[k] = row
    ds_sum = None
    if core.ds_ops:
        mn = min(a for _, a, _, _ in core.ds_ops)
        mx = max(a + nb for _, a, nb, _ in core.ds_ops)
        oob_ds = [x for x in core.ds_ops
                  if x[1] >= LDS_PART or x[1] + x[2] > LDS_PART]
        ds_sum = {"count": len(core.ds_ops), "min_offset": mn,
                  "max_offset": mx, "stores": sum(1 for s, *_ in core.ds_ops
                                                  if s),
                  "oob_over_lds": len(oob_ds), "oob_samples": oob_ds[:5]}
    if dump_path:
        with open(dump_path, "w", encoding="utf-8") as f:
            f.write(f"# trace {label} outcome={outcome} steps={core.steps}\n")
            for site, mnem, ops in exec_stream:
                f.write(f"{site:#08x} {mnem} {ops}\n".rstrip() + "\n")
            for st, addr, nb, site in core.g_ops:
                k = next((k for k in range(n_slots)
                          if SLOT + k * STRIDE <= addr < SLOT + (k+1)*STRIDE),
                         None)
                if k is not None:
                    f.write(f"G{'S' if st else 'L'} slot{k} "
                            f"{addr - (SLOT + k * STRIDE + GUARD):#x} w{nb} "
                            f"@{site:#08x}\n")
    return {
        "label": label, "grid": list(grid), "block": list(block),
        "wg": list(wg), "wavebase": wavebase,
        "outcome": outcome, "steps": core.steps, "branches": n_br,
        "barriers": n_bar, "oob": oob,
        "dot_sites": len(dot_hits), "dot_visits": sum(dot_hits.values()),
        "bpermute_sites": len(bp_hits),
        "scratch_sites_visited": sorted(scratch_sites),
        "slot_access": slot_sum, "ds": ds_sum,
        "snaps": snaps if snap_sites else None,
        "undef": sorted(core.undef_s) if hasattr(core, "undef_s") else [],
    }


def main():
    import sys as _s
    prog, rows, idx = slice_program(ENT_DIS, KERNEL)
    dw = dw16(ENT_CO, KERNEL)
    # slot ids for ptr fields, in field-offset order
    PTR = {}
    _next = [0]
    def ps(off):
        PTR[off] = ('ptr', _next[0]); _next[0] += 1
    ps(0x00); ps(0x08); ps(0x10); ps(0x30); ps(0x38); ps(0x48)
    ps(0x78); ps(0x80); ps(0xa0)          # +0x98 is i32 pair; +0xa0 = ptr
    fields = dict(PTR)
    # dims/ints: s24..27 @ +0x18..0x24 (4 x i32); flags @ +0x28
    D = 64
    fields[0x18] = ('u32', D)
    fields[0x1c] = ('u32', D)
    fields[0x20] = ('u32', D)
    fields[0x24] = ('u32', D)
    fields[0x28] = ('u32', 0)
    fields[0x98] = ('u64', 0)             # +0x98 u64 int pair (s36:37)
    json.dump({f"0x{o:x}": v[0] for o, v in fields.items()},
              open(os.path.join(OUTD, "p14e_fields.json"), "w"), indent=1)
    print("slice", len(prog), "sites; fields:", fields)
    cases = [
        ("P256D64", (1, 1, 1), (256, 1, 1), (0, 0, 0), 0),
        ("P256D64w7", (1, 1, 1), (256, 1, 1), (0, 0, 0), 224),
    ]
    results = {}
    for c in cases:
        label, grid, block, wg, wb = c
        r = trace(prog, dw, f"ef-{label}", grid, block, wg, wb, fields,
                  text_path=ENT_CO)
        results[label] = r
        o = r["outcome"]
        print(f"{label}: {o} steps={r['steps']} br={r['branches']} "
              f"bar={r['barriers']} dot_sites={r['dot_sites']} "
              f"dot_visits={r['dot_visits']} oob={r['oob'][:2]}")
        print("  slots:", {k: {q: (v['count'], v.get('min_offset'),
                                   v.get('max_offset')) for q, v in d.items()}
                           for k, d in r['slot_access'].items()})
        print("  ds:", r['ds'])
        if r['scratch_sites_visited']:
            print("  scratch visited:", [f'{s:#x}' for s in
                                         r['scratch_sites_visited']][:12])
    with open(os.path.join(OUTD, "p14e_emulation.json"), "w") as f:
        json.dump(results, f, indent=1, default=str)
    print("wrote p14e_emulation.json")


if __name__ == "__main__":
    main()
