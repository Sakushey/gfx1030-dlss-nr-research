#!/usr/bin/env python3
"""Phase 16O Track A / A1+A2 -- build the source revisions to bisect.

WHY THIS EXISTS

Phase 16N's bisect patched repairs back at RUNTIME and concluded that none
of them was causal.  The 16O brief retires runtime patching for this
question: a runtime patch is a claim about equivalence that nobody checked,
and in this case it was provably wrong (the `_cmp_dispatch` patch replaced
`SwinCore`'s override with the BASE method for every non-class compare, so
restoring one repair silently changed a different one).

So each revision here is a real SOURCE TREE.  A runner prepends exactly one
tree to `sys.path` and executes in a fresh process; the emulator modules
resolve to the tree's copies by name.

NO BACKUP OF THE PRE-16N SOURCES EXISTS.  The Phase 16N repairs were applied
in place and the originals are gone -- this was checked, not assumed: the
only pre-16N artefact on disk is the SHA-256 of `phase8_static/tools/emu.py`
(`597148aa2f28bad7...`, 62,118 bytes) in
`phase16m_final_host/m0_freeze/P16M_INITIAL_HASHES.json`, and no file of that
size or digest exists in the tree.  PRE16N is therefore a RECONSTRUCTION
from the defects' own recorded descriptions, and it is validated
behaviourally against the recorded pre-16N reference cell rather than
claimed byte-exact.

usage:
  python a_build_revs.py                 # build every revision tree
  python a_build_revs.py --list          # show what would be written
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
OUT = os.path.join(ROOT, "phase16o_final", "a_regression")

# The seven source files Phase 16N edited, by mtime inside the repair window.
EDIT_FILES = {
    "phase8_static/tools/emu.py": "emu.py",
    "phase14d8_static/tools/p14d8_core.py": "p14d8_core.py",
    "phase14e_static/tools/p14e_emu.py": "p14e_emu.py",
    "phase14eh_tools/p14eh.py": "p14eh.py",
    "phase16e_candidate_e/tools/p16e_rec.py": "p16e_rec.py",
    "phase16h_pcrel_fix/tools/p16h_scratch_probe.py": "p16h_scratch_probe.py",
    "phase16j_pre_gta/tools/p16j_scratch_isa.py": "p16j_scratch_isa.py",
    # Phase 16O's own repair target.  It is carried as a revision variable
    # too, because the regression is an INTERACTION: neither the repaired
    # reader alone nor this defect alone reproduces it.
    "phase16j_pre_gta/tools/p16j_input.py": "p16j_input.py",
}


def _sub(text, old, new, what, applied):
    """Exact-text substitution that FAILS LOUDLY if it does not apply."""
    if old not in text:
        raise SystemExit("REVERT FAILED to match: %s" % what)
    if text.count(old) != 1:
        raise SystemExit("REVERT ambiguous (%d matches): %s"
                         % (text.count(old), what))
    applied.append(what)
    return text.replace(old, new)


# ==========================================================================
# emu.py -- defects D4/D11 (class mask), D5 (cndmask arity),
#           D9 (dword-keyed scalar load, with D8 in p14d8_core)
#           D10 (double-rounded fmac), D1/D2 helper origin
# ==========================================================================

# `_mem_byte` + `_read_u32` are reverted as ONE SPAN, because the Phase 16N
# reader and the Phase 16O hardening of it are different revisions of the
# same two functions and a partial textual edit left the docstring dangling.
MEM_SPAN_START = "    def _mem_byte(self, addr):"
MEM_SPAN_END = "\n    # ---------------- vector ops ----------------"

# POST16N as Phase 16N left it -- byte-addressed `_read_u32`, but
# `_mem_byte`'s real-entry test is `in`, which `PatternMem` answers True for
# synthesised addresses.
MEM_16N = '''    def _mem_byte(self, addr):
        """One byte of the ARCHITECTURAL, byte-addressed memory.

        Phase 16N's reader.  A byte key at the address wins; otherwise the
        aligned dword key is split little-endian; otherwise the byte is zero.
        """
        a = addr & ((1 << 64) - 1)
        if a in self.mem:
            return self.mem[a] & 0xFF
        base = a & ~3
        if base in self.mem:
            return (self.mem[base] >> (8 * (a - base))) & 0xFF
        return 0

    def _read_u32(self, addr):
        """A 4-byte little-endian load, through the byte-addressed model."""
        a = addr & ((1 << 64) - 1)
        return (self._mem_byte(a)
                | (self._mem_byte(a + 1) << 8)
                | (self._mem_byte(a + 2) << 16)
                | (self._mem_byte(a + 3) << 24))
'''

# PRE16N -- the dword-keyed readers Phase 16M M2 measured as defects 8 and 9.
MEM_PRE16N = '''    def _mem_byte(self, addr):
        """PRE-16N reconstruction: dword-keyed only (Phase 16M M2 D8/D9)."""
        a = addr & ((1 << 64) - 1)
        if a in self.mem:
            return self.mem[a] & 0xFF
        return 0

    def _read_u32(self, addr):
        """PRE-16N reconstruction: `mem.get(addr, 0)`, dword-keyed only."""
        a = addr & ((1 << 64) - 1)
        v = self.mem.get(a, 0)
        return v & U32 if isinstance(v, int) else 0
'''


def _replace_span(text, start, end, new, what, applied):
    i = text.find(start)
    if i < 0:
        raise SystemExit("SPAN START not found: %s" % what)
    j = text.find(end, i)
    if j < 0:
        raise SystemExit("SPAN END not found: %s" % what)
    applied.append(what)
    return text[:i] + new + text[j + 1:]

EMU_VCMPCLASS_NEW = '''    def _vcmp_class(self, ins, ops):
        """V_CMP_CLASS_F32 dst, src0, src1 -- src1 is the class MASK.'''

EMU_VCMPCLASS_OLD = '''    def _vcmp_class(self, ins, ops):
        """PRE-16N reconstruction: the mask was never read.'''

EMU_VCMPCLASS_BODY_NEW = '''        dst = ops[0]
        out = 0
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                bits = self.vget(lane, ops[1]) & U32
                mask = self.vget(lane, ops[2], fp=False) & U32
                if (mask >> f32_class_bit(bits)) & 1:
                    out |= 1 << lane
        if dst == "vcc_lo" or dst == "vcc":
            self.vcc_l = out
        else:
            self.sset(dst, out)'''

EMU_VCMPCLASS_BODY_OLD = '''        dst = ops[0]
        out = 0
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[1], fp=True)
                if a != a or abs(a) == float("inf"):
                    out |= 1 << lane
        if dst == "vcc_lo" or dst == "vcc":
            self.vcc_l = out
        else:
            self.sset(dst, out)'''

EMU_CMPDISP_NEW = '''        if m == "v_cmp_class_f32":
            # V_CMP_CLASS_F32 dst, src0, src1 where src1 is a 10-BIT INTEGER
            # class mask, not a float.  Reading it with fp=True would decode
            # 0x260 as a denormal f32 and the test would be meaningless; the
            # pre-16N code avoided that only by ignoring the operand entirely.
            self._vcmp_class(ins, ops)
            return
'''
EMU_CMPDISP_OLD = ''

EMU_CNDMASK_NEW = '''        dst = ops[0]
        src0 = ops[1]
        src1 = ops[2]
        cond = ops[3] if len(ops) > 3 else "vcc_lo"
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, src0)
                b = self.vget(lane, src1)
                if cond == "vcc_lo":
                    c = (self.vcc_l >> lane) & 1
                elif cond.startswith("s"):
                    c = (self.sget(cond) >> lane) & 1
                elif cond == "vcc":
                    c = (self.vcc_l >> lane) & 1
                else:
                    c = self.vget(lane, cond)
                self.vset(lane, dst, b if c else a)'''

EMU_CNDMASK_OLD = '''        dst = ops[0]
        src0 = ops[1]
        src1 = ops[2]
        # PRE-16N reconstruction: `ops[3]` read unconditionally, so the
        # 3-operand `_e32` spelling raised IndexError (defect 5).
        cond = ops[3]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, src0)
                b = self.vget(lane, src1)
                if cond == "vcc_lo":
                    c = (self.vcc_l >> lane) & 1
                elif cond.startswith("s"):
                    c = (self.sget(cond) >> lane) & 1
                elif cond == "vcc":
                    c = (self.vcc_l >> lane) & 1
                else:
                    c = self.vget(lane, cond)
                self.vset(lane, dst, b if c else a)'''

EMU_FMAC_NEW = '''        dst = ops[0]
        src0 = ops[1]
        src1 = ops[2]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                c = self.vget(lane, dst) & U32
                a = self.vget(lane, src0) & U32
                b = self.vget(lane, src1) & U32
                self.vset(lane, dst, fma_f32_bits(a, b, c))'''

EMU_FMAC_OLD = '''        dst = ops[0]
        src0 = ops[1]
        src1 = ops[2]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                # PRE-16N reconstruction: host-f64 product plus add, then a
                # second rounding to f32 -- double rounding (defect 10).
                c = self.vget(lane, dst, fp=True)
                b = self.vget(lane, src0, fp=True)
                a = self.vget(lane, src1, fp=True)
                self.vset(lane, dst, f32_bits(f32(c + b * a)))'''


EMU_F32_NEW = '''    try:
        return struct.unpack("<f", struct.pack("<f", x))[0]
    except OverflowError:
        return float("inf") if x > 0 else float("-inf")
    except (TypeError, ValueError):
        return x


def f32_bits(x):
    return struct.unpack("<I", struct.pack("<f", f32(x)))[0]'''

EMU_F32_OLD = '''    # PRE-16O reconstruction: an out-of-range magnitude raised
    # OverflowError out of `struct.pack` and aborted the dispatch.
    return struct.unpack("<f", struct.pack("<f", x))[0]


def f32_bits(x):
    return struct.unpack("<I", struct.pack("<f", x))[0]'''


def revert_emu(text, applied, which):
    t = text
    if which in ("all", "pre16o", "d9", "d8"):
        t = _sub(t, EMU_F32_NEW, EMU_F32_OLD,
                 "emu.f32/f32_bits overflow saturation", applied)
    if which in ("all", "d9", "d8", "mem16o", "other16n"):
        # Phase 16O's hardening of `_mem_byte` is reverted FIRST, so that
        # `mem16o` yields the reader exactly as Phase 16N left it and `d9`
        # then reverts Phase 16N's repair as well.
        t = _replace_span(t, MEM_SPAN_START, MEM_SPAN_END, MEM_16N,
                          "emu._mem_byte/_read_u32 -> 16N reader", applied)
    if which in ("all", "d9", "d8"):
        t = _replace_span(t, MEM_SPAN_START, MEM_SPAN_END, MEM_PRE16N,
                          "emu._mem_byte/_read_u32 -> PRE-16N reader", applied)
    # "other" = every OTHER emu repair reverted and the reader KEPT, which is
    # the complement of "d9" and is what shows the reader is the causal one.
    if which in ("all", "other", "other16n", "d4", "d11"):
        t = _sub(t, EMU_VCMPCLASS_NEW, EMU_VCMPCLASS_OLD,
                 "emu._vcmp_class docstring", applied)
        t = _sub(t, EMU_VCMPCLASS_BODY_NEW, EMU_VCMPCLASS_BODY_OLD,
                 "emu._vcmp_class body", applied)
        t = _sub(t, EMU_CMPDISP_NEW, EMU_CMPDISP_OLD,
                 "emu._cmp_dispatch class branch", applied)
    if which in ("all", "other", "other16n", "d5"):
        t = _sub(t, EMU_CNDMASK_NEW, EMU_CNDMASK_OLD,
                 "emu.op_v_cndmask_b32", applied)
    if which in ("all", "other", "other16n", "d10"):
        t = _sub(t, EMU_FMAC_NEW, EMU_FMAC_OLD, "emu.op_v_fmac_f32", applied)
    return t


# ==========================================================================
# p14d8_core.py -- defect D8 (wide global load from a dword key)
# ==========================================================================

P14D8_SQRT_NEW = '''        def f(a, b, c):
            if math.isnan(a):
                return float("nan")
            if a < 0:
                return float("nan")
            if math.isinf(a):
                return float("inf")
            return emu_mod.f32(math.sqrt(a))
        self._vfp(ins, ops, f)'''

P14D8_SQRT_OLD = '''        # PRE-16O reconstruction: unguarded, so a negative operand raised
        # `ValueError` and aborted the dispatch.
        self._vfp(ins, ops, lambda a, b, c: math.sqrt(a))'''

P14D8_NEW = '        return self._read_u32(addr)'
P14D8_OLD = ('        # PRE-16N reconstruction: the WHOLE dword at the address,\n'
             '        # or 0 -- `_gld` then masked it to one byte (defect 8).\n'
             '        a = addr & ((1 << 64) - 1)\n'
             '        v = self.mem.get(a, 0)\n'
             '        return v & U32 if isinstance(v, int) else 0')


def revert_p14d8(text, applied, which):
    t = text
    if which in ("all", "sqrt16o", "d8", "d9"):
        t = _sub(t, P14D8_SQRT_NEW, P14D8_SQRT_OLD,
                 "p14d8_core.op_v_sqrt_f32 guard", applied)
    if which in ("all", "d8", "d9"):
        t = _sub(t, P14D8_NEW, P14D8_OLD, "p14d8_core._read_bytes", applied)
    return t


# ==========================================================================
# p14e_emu.py -- defects D1/D2 (_f16c), D3/D13 (pk min/max NaN),
#                D12 (v_add_f16 upper half)
# ==========================================================================

F16C_NEW = '''    import math as _m
    if _m.isnan(x):
        return 0x7E00
    if _m.isinf(x):
        return 0x7C00 | (0x8000 if x < 0 else 0)
    return EMU.f32_bits_to_f16(EMU.f32_bits(EMU.f32(x)))'''

F16C_OLD = '''    # PRE-16N RECONSTRUCTION.  The original bytes were edited in place and
    # no backup exists, so this reproduces the three defects Phase 16M M2
    # MEASURED rather than claiming a byte-exact restore: the sign is taken
    # from bit 16 of the binary32 pattern, a rounded subnormal significand
    # is clamped with `min(frac, 0x3FF)`, and the tie rule is whatever
    # `int(round(...))` happens to do.
    import math as _m
    if _m.isnan(x):
        return 0x7E00
    if _m.isinf(x):
        return 0x7C00 | (0x8000 if x < 0 else 0)
    x = EMU.f32(float(x))
    b = EMU.f32_bits(x)
    s = (b >> 16) & 1
    e = ((b >> 23) & 0xFF) - 127
    m = b & 0x7FFFFF
    if e > 15:
        return (s << 15) | 0x7C00
    if e < -24:
        return (s << 15)
    if e >= -14:
        frac = int(round((1.0 + m / float(1 << 23)) * 1024.0)) - 1024
        if frac >= 1024:
            e += 1
            frac -= 1024
        if e > 15:
            return (s << 15) | 0x7C00
        return (s << 15) | ((e + 15) << 10) | (frac & 0x3FF)
    mx = m | 0x800000
    shift = (-14 - e) + 13
    frac = mx >> shift
    rem = mx & ((1 << shift) - 1)
    half = 1 << (shift - 1)
    if rem > half or (rem == half and (frac & 1)):
        frac += 1
    if frac > 0x3FF:
        frac = min(frac, 0x3FF)
    return (s << 15) | (frac & 0x3FF)'''

MINMAX_NEW = '''    a_nan = a != a
    b_nan = b != b
    if a_nan and b_nan:
        return 0x7E00
    if a_nan:
        return _f16c(b)
    if b_nan:
        return _f16c(a)
    if want_max:
        return _f16c(a if a > b else b)
    return _f16c(a if a < b else b)'''

MINMAX_OLD = '''    # PRE-16N reconstruction: one ordered comparison, so the result depends
    # on WHICH operand held the NaN (Phase 16M M2 defect 3).
    if want_max:
        return _f16c(a if a <= b else b)
    return _f16c(a if a <= b else b)'''

F16ARITH_NEW = '''                self.vset(lane, ops[0], _f16c(r) & 0xFFFF)'''

F16ARITH_OLD = '''                cur = self.vget(lane, ops[0]) & 0xFFFF0000
                self.vset(lane, ops[0], cur | (_f16c(r) & 0xFFFF))'''


def revert_p14e(text, applied, which):
    t = text
    if which in ("all", "d1", "d2"):
        t = _sub(t, F16C_NEW, F16C_OLD, "p14e_emu._f16c", applied)
    if which in ("all", "d3", "d13"):
        t = _sub(t, MINMAX_NEW, MINMAX_OLD, "p14e_emu._f16_minmax_bits",
                 applied)
    if which in ("all", "d12"):
        t = _sub(t, F16ARITH_NEW, F16ARITH_OLD, "p14e_emu._f16_arith",
                 applied)
    return t


# ==========================================================================
# p14eh.py -- defect D6 (ds_write_b16_d16_hi wrote the LOW half)
# ==========================================================================

D16HI_NEW = '''        if d16_hi and dvals:
            # `_d16_hi` selects the HIGH 16 bits of VDATA -- symmetric with
            # `_byte_load` above, which already merged into the high half.
            # The pre-16N store path had no such rule and wrote the low half.
            dvals = [dvals[0] >> 16]
'''
D16HI_OLD = ''


def revert_p14eh(text, applied, which):
    if which in ("all", "d6"):
        return _sub(text, D16HI_NEW, D16HI_OLD,
                    "p14eh._byte_store d16_hi rule", applied)
    return text


# ==========================================================================
# p16e_rec.py -- defect D6 (silent _DS_FALLBACK) and D7 (scratch width)
# ==========================================================================

SCRT_WIDTH_NEW = '''        if nbytes is None:
            nbytes = self._scrt_width(ins.get("mnemonic") or "", lo, hi)'''
SCRT_WIDTH_OLD = '''        # PRE-16N reconstruction: the width came from the destination
        # register span, so `scratch_load_ubyte` moved 4 bytes (defect 7).
        if nbytes is None:
            nbytes = (hi - lo + 1) * 4'''

FALLBACK_ANCHOR = '''    # There is deliberately NO `__getattr__` on this class any more.'''

FALLBACK_OLD = '''    # PRE-16N RECONSTRUCTION: the silent opcode fallback.  Any unresolved
    # `op_ds_*` name matched `_DS_FALLBACK` and was answered by the NON-d16
    # byte helper, so `ds_write_b16_d16_hi` was never unhandled, never
    # reported, and wrote the wrong 16 bits (Phase 16N N2 defect 6).
    _DS_FALLBACK = re.compile(
        r"^op_ds_(?P<kind>read|load|write|store)_(?P<form>.+)$")

    def __getattr__(self, name):
        m = self._DS_FALLBACK.match(name)
        if m:
            kind = m.group("kind")
            store = kind in ("write", "store")
            nbytes = 2

            if store:
                def _fallback(self, ins, ops, nbytes=nbytes):
                    self._ds_store_bytes(ins, ops, nbytes)
            else:
                def _fallback(self, ins, ops, nbytes=nbytes):
                    self._ds_load_bytes(ins, ops, nbytes)
            return _fallback
        raise AttributeError(name)

''' + FALLBACK_ANCHOR


def revert_p16e_rec(text, applied, which):
    t = text
    if which in ("all", "d7"):
        t = _sub(t, SCRT_WIDTH_NEW, SCRT_WIDTH_OLD,
                 "p16e_rec._scratch_xfer width", applied)
    if which in ("all", "d6"):
        t = _sub(t, FALLBACK_ANCHOR, FALLBACK_OLD,
                 "p16e_rec.__getattr__ fallback", applied)
    return t


# ==========================================================================
# p16h_scratch_probe.py / p16j_scratch_isa.py -- D7 forwarding
# ==========================================================================

PROBE_W_NEW = '''                if nbytes is None:
                    nbytes = (hi - lo + 1) * 4'''
PROBE_W_OLD = '''                nbytes = (hi - lo + 1) * 4          # PRE-16N: span rule'''

ISA_W_NEW = '''        super()._scratch_xfer(ins, store, nbytes)'''
ISA_W_OLD = '''        # PRE-16N reconstruction: the width was never threaded down, so
        # ScrtGateCore re-derived it from the destination span.
        super()._scratch_xfer(ins, store, None)'''


def revert_p16h(text, applied, which):
    if which in ("all", "d7"):
        return _sub(text, PROBE_W_NEW, PROBE_W_OLD,
                    "p16h_scratch_probe width", applied)
    return text


def revert_p16j(text, applied, which):
    if which in ("all", "d7"):
        return _sub(text, ISA_W_NEW, ISA_W_OLD,
                    "p16j_scratch_isa width forwarding", applied)
    return text


# ==========================================================================
# p16j_input.py -- the Phase 16O harness defect
# ==========================================================================

P16J_REGIONS_NEW = """    out = []
    for off in offsets:
        val = vals.get(off)
        if not val:
            continue
        size = canvas_size if off == 0xA0 else tensor_size
        out.append((val, val + size, "authentic_0x%02X" % off))
    out.extend(extra)
    return out"""

P16J_REGIONS_OLD = """    # PRE-16O reconstruction: EVERY non-empty entry of `vals`, using the
    # entry's VALUE as a region base.  `vals` also carries the scalar kernarg
    # fields, so this declared 64 MiB of pattern-backed memory at address 1,
    # at 0x240 (X) and at 0x3C0 (Y) -- covering the kernarg segment at
    # 0x10000, which is the region Phase 16O measured.
    out = []
    for off, val in sorted(vals.items()):
        if not val:
            continue
        size = canvas_size if off == 0xA0 else tensor_size
        out.append((val, val + size, "authentic_0x%02X" % off))
    out.extend(extra)
    return out"""


def revert_p16j_input(text, applied, which):
    if which in ("all", "buggy"):
        return _sub(text, P16J_REGIONS_NEW, P16J_REGIONS_OLD,
                    "p16j_input.regions_for scalar regions", applied)
    return text


REVERTS = {
    "emu.py": revert_emu,
    "p16j_input.py": revert_p16j_input,
    "p14d8_core.py": revert_p14d8,
    "p14e_emu.py": revert_p14e,
    "p14eh.py": revert_p14eh,
    "p16e_rec.py": revert_p16e_rec,
    "p16h_scratch_probe.py": revert_p16h,
    "p16j_scratch_isa.py": revert_p16j,
}

# Per-file bisect trees: which reverts each one applies.
PER_FILE = {
    "minus_emu": {"emu.py": "all"},
    "minus_p14d8_core": {"p14d8_core.py": "all"},
    "minus_p14e_emu": {"p14e_emu.py": "all"},
    "minus_p14eh": {"p14eh.py": "all"},
    "minus_p16e_rec": {"p16e_rec.py": "all"},
    "minus_p16h_scratch_probe": {"p16h_scratch_probe.py": "all"},
    "minus_p16j_scratch_isa": {"p16j_scratch_isa.py": "all"},
}

# The Phase 16N state carried the harness defect; so does every revision
# whose purpose is to reproduce or bisect THAT state.
BUGGY = {"p16j_input.py": "buggy"}


def read_src(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def write_tree(name, spec, manifest):
    d = os.path.join(OUT, "rev_" + name)
    os.makedirs(d, exist_ok=True)
    applied = []
    hashes = {}
    for rel, mod in EDIT_FILES.items():
        src = read_src(rel)
        which = spec.get(mod)
        if which:
            src = REVERTS[mod](src, applied, which)
        p = os.path.join(d, mod)
        with open(p, "w", encoding="utf-8") as f:
            f.write(src)
        hashes[mod] = hashlib.sha256(src.encode()).hexdigest()
    manifest[name] = {"dir": os.path.relpath(d, ROOT),
                      "applied_reverts": applied, "hashes": hashes}
    print("%-28s reverts=%d" % (name, len(applied)))
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    manifest = {}
    # The two endpoints and every bisect arm run under the BUGGY harness:
    # those are the conditions the pre-16N reference cell and the Phase 16N
    # regression were each measured in.  `post16n` additionally reverts
    # Phase 16O's own hardening of `_mem_byte`, so it is the Phase 16N
    # reader exactly.  `harness_fixed` is the live tree (both 16O fixes);
    # `harness_fixed_only` keeps the 16N reader and fixes only the harness,
    # which is what separates the two 16O changes.
    N16_READER = {"emu.py": "mem16o"}
    build = {
        "post16n": dict(N16_READER, **{"p14d8_core.py": "sqrt16o"}, **BUGGY),
        "pre16n": dict({m: "all" for m in REVERTS}, **BUGGY),
        "harness_fixed": {},
        "harness_fixed_only": dict(N16_READER,
                                   **{"p14d8_core.py": "sqrt16o"}),
        # The minimal-change set, pinned from both sides: only D9 reverted,
        # and its complement (every other emu repair reverted, D9 kept).
        "minus_emu_d9only": dict({"emu.py": "d9"}, **BUGGY),
        # "other16n" = the 16N reader KEPT, every other emu repair reverted.
        # This is the true complement of `minus_emu_d9only`.
        "minus_emu_other16n": dict({"emu.py": "other16n"}, **BUGGY),
        "minus_emu_other": dict({"emu.py": "other"}, **BUGGY),
    }
    S16O = {"p14d8_core.py": "sqrt16o"}
    for name, spec in PER_FILE.items():
        base = {} if name == "minus_emu" else dict(N16_READER)
        base.update(spec)
        build[name] = dict(base, **BUGGY)
        if name != "minus_p14d8_core":
            build[name] = dict(build[name], **S16O)

    if args.list:
        for k, v in build.items():
            print("%-28s %s" % (k, sorted(v) or "(verbatim copies)"))
        return 0

    if os.path.isdir(OUT):
        for name in list(build):
            d = os.path.join(OUT, "rev_" + name)
            if os.path.isdir(d):
                shutil.rmtree(d)
    for name, spec in build.items():
        write_tree(name, spec, manifest)

    import json
    with open(os.path.join(OUT, "REVISION_MANIFEST.json"), "w",
              encoding="utf-8") as f:
        json.dump({"schema": "phase16o-revisions/1", "phase": "16O",
                   "track": "A1", "host_only": True,
                   "gpu_execution_performed": False,
                   "pre16n_is_reconstruction": True,
                   "pre16n_note":
                       "No pre-16N source backup exists. PRE16N is a "
                       "behavioural reconstruction from the recorded defect "
                       "descriptions and is validated against the recorded "
                       "pre-16N reference cell, not claimed byte-exact.",
                   "edit_files": EDIT_FILES,
                   "revisions": manifest}, f, indent=1)
    print("wrote %s" % os.path.join(OUT, "REVISION_MANIFEST.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
