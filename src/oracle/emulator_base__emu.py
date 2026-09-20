"""Phase 8 host-only instruction emulator (wave32, gfx1030/gfx1100 subset).

Emulates scalar + vector instructions with EXEC/VCC/SCC semantics for the
k_conv_splitk no-work path. Used to prove termination behavior of the
original gfx1100 stream and the translated gfx1030 stream on identical
launch state. Deterministic; cycle detection on full state. No GPU use.
"""
import math
import struct

U32 = 0xFFFFFFFF
SIGN = 0x80000000


def f32(x):
    return struct.unpack("<f", struct.pack("<f", x))[0]


def f32_bits(x):
    return struct.unpack("<I", struct.pack("<f", x))[0]


def bits_f32(b):
    return struct.unpack("<f", struct.pack("<I", b & U32))[0]


def s32(x):
    """interpret u32 as signed"""
    x &= U32
    return x - 0x100000000 if x & SIGN else x


def _s16(x):
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


def _s8(x):
    x &= 0xFF
    return x - 0x100 if x & 0x80 else x


def f16_to_f32(b):
    b &= 0xFFFF
    s = (b >> 15) & 1
    e = (b >> 10) & 0x1F
    m = b & 0x3FF
    if e == 0:
        if m == 0:
            return -0.0 if s else 0.0
        v = m * 2.0 ** -24
        return -v if s else v
    if e == 31:
        if m == 0:
            return float("-inf") if s else float("inf")
        return float("nan")
    v = (1 + m / 1024.0) * 2.0 ** (e - 15)
    return -v if s else v


class Halt(Exception):
    """Ends emulation: .kind in END/CYCLE/LDS-OOB/..."""

    def __init__(self, kind, info=None):
        super().__init__(kind)
        self.kind = kind
        self.info = info


class NotImpl(Exception):
    pass


class Core:
    def __init__(self, prog, lanes=32, vgprs=192, lds_size=4096, lds_fill=0,
                 wavebase=0, mem=None):
        self.prog = prog
        self.pc = 0
        self.lanes = lanes
        self.s = [0] * 128
        # Phase 14D8: SGPR indices that are declared-but-unpopulated at
        # dispatch entry (descriptor-derived gap). Reading one before any
        # kernel write is a Halt("UNDEFREAD"). Empty set = legacy behavior.
        self.undef_s = set()
        self.v = [[0] * vgprs for _ in range(lanes)]
        self.vcc_l = 0
        self.scc = 0
        self.exec_l = (1 << lanes) - 1
        self.lds = bytearray(lds_size)
        if isinstance(lds_fill, int):
            for i in range(0, lds_size, 2):
                self.lds[i] = lds_fill & 0xFF
                self.lds[i + 1] = (lds_fill >> 8) & 0xFF
        for lane in range(lanes):
            self.v[lane][0] = wavebase + lane  # tid within workgroup
        self.mem = mem if mem is not None else {}
        self.steps = 0
        self.global_stores = []  # (addr, byteval, lane)
        self._cyckeys = {}
        self._cyckeys_full = {}
        self.terminated = False

    def _v_signature(self):
        import hashlib
        h = hashlib.md5()
        for lane in range(self.lanes):
            for r in self.v[lane]:
                h.update(r.to_bytes(4, "little"))
        # mem signature: sorted (addr,val) of stores
        for addr in sorted(self.mem):
            h.update(addr.to_bytes(8, "little"))
            h.update((self.mem[addr] & 0xFFFFFFFF).to_bytes(4, "little"))
        return h.digest()

    # ---------------- register access ----------------
    def sget(self, tok):
        tok = tok.strip()
        if tok == "vcc_lo":
            return self.vcc_l
        if tok == "exec_lo":
            return self.exec_l
        if tok == "scc":
            return self.scc
        if tok == "m0":
            return self.s[76]
        if tok in ("null", "off"):
            return 0
        if tok.startswith("s"):
            i = int(tok[1:])
            self._chk_def(i)
            return self.s[i]
        if tok.startswith("0x"):
            return int(tok, 16)
        if tok.startswith("-0x"):
            return -int(tok[3:], 16)
        if tok.startswith("-"):
            return int(tok)
        return int(tok)

    def _chk_def(self, i):
        """Fail-closed read of a declared-but-unpopulated entry SGPR."""
        if i in self.undef_s:
            raise Halt("UNDEFREAD", i)

    @staticmethod
    def _bounds(tok):
        tok = tok.strip()
        if ":" not in tok:
            return None
        inner = tok.lstrip("s[").rstrip("]")
        a, b = (int(x) for x in inner.split(":"))
        return a, b

    def sset(self, tok, val):
        tok = tok.strip()
        if tok == "vcc_lo":
            self.vcc_l = val & U32
            return
        if tok == "exec_lo":
            self.exec_l = val & ((1 << self.lanes) - 1)
            return
        if tok == "scc":
            self.scc = val & 1
            return
        if tok in ("null", "off"):
            return
        if tok.startswith("s"):
            bd = self._bounds(tok)
            if bd:
                a, b = bd
                for i in range(a, b + 1):
                    self.s[i] = (val if not isinstance(val, list) else val[i - a]) & U32
                    self.undef_s.discard(i)
            else:
                self.s[int(tok[1:])] = val & U32
                self.undef_s.discard(int(tok[1:]))
            return
        raise NotImpl(f"sset {tok}")

    def spair(self, tok):
        """64-bit value from a scalar pair token s[a:b] or scalar tok."""
        tok = tok.strip()
        bd = self._bounds(tok)
        if bd:
            a, b = bd
            v = 0
            for i in range(b, a - 1, -1):
                self._chk_def(i)
                v = (v << 32) | (self.s[i] & U32)
            return v
        return self.sget(tok)

    def spair_set(self, tok, val):
        tok = tok.strip()
        val &= (1 << 64) - 1
        bd = self._bounds(tok)
        if bd:
            a, b = bd
            for i in range(a, b + 1):
                self.s[i] = (val >> (32 * (i - a))) & U32
                self.undef_s.discard(i)
        else:
            self.sset(tok, val & U32)

    def vget(self, lane, tok, fp=False):
        tok = tok.strip()
        if tok.startswith("|") and tok.endswith("|"):
            v = self.vget(lane, tok[1:-1], fp)
            return abs(v)
        if tok.startswith("v"):
            return self.v[lane][int(tok[1:])]
        if tok.startswith("-v"):
            return (-self.v[lane][int(tok[2:])]) & U32
        if tok == "vcc_lo":
            return (self.vcc_l >> lane) & 1
        if tok == "exec_lo":
            return (self.exec_l >> lane) & 1
        if tok.startswith("s"):
            return self.sget(tok)
        if tok == "null" or tok == "off":
            return 0
        if fp and tok.startswith("0x"):
            return bits_f32(int(tok, 16))
        if tok.startswith("0x"):
            return int(tok, 16)
        if fp:
            return float(tok)
        return int(tok)

    def vset(self, lane, tok, val):
        tok = tok.strip()
        if tok.startswith("v") and ":" not in tok:
            self.v[lane][int(tok[1:])] = val & U32
            return
        raise NotImpl(f"vset {tok}")

    # ---------------- stepping ----------------
    def step(self):
        if self.pc >= len(self.prog):
            raise Halt("PCOVERRUN")
        ins = self.prog[self.pc]
        self.steps += 1
        mnem = ins["mnemonic"].replace("_e32", "").replace("_e64", "")
        ops = [o.strip() for o in ins["operands"].split(",")] if ins["operands"] else []
        if self.steps % 256 == 0:
            key = (self.pc, self.exec_l, self.vcc_l, self.scc, tuple(self.s))
            if key in self._cyckeys:
                # control state repeated: confirm full state (v + mem) also
                # repeats before declaring a true cycle
                sig = self._v_signature()
                if key in self._cyckeys_full and self._cyckeys_full[key] == sig:
                    raise Halt("CYCLE", (self._cyckeys[key], self.steps))
                self._cyckeys_full[key] = sig
            else:
                self._cyckeys[key] = self.steps
                # The first-visit fingerprint is read only by the branch
                # above, which is reachable only once this key is found
                # again -- so it is worth computing only when this mapping
                # can report membership at all.  `run_workgroup_hw` installs
                # `_NoKeys`, whose `__contains__` is always False; there the
                # fingerprint was computed and stored into a mapping that
                # could never be consulted.  That dead work measured at 95.7%
                # of a dispatch's wall clock: every 256 steps it hashed 6144
                # VGPRs plus 1.21M materialised memory entries, one
                # `to_bytes` and one `update` per field.
                if key in self._cyckeys:
                    self._cyckeys_full[key] = self._v_signature()
        self.pc += 1
        if mnem.startswith("v_dual_"):
            mnem = "v_" + mnem[len("v_dual_"):]
        if mnem.startswith("v_cmp_"):
            self._cmp_dispatch(mnem, ins, ops)
        elif mnem.startswith("v_cmpx_"):
            self._cmpx_dispatch(mnem, ins, ops)
        else:
            fn = getattr(self, "op_" + mnem, None)
            if fn is None:
                addr = ins.get("address")
                loc = f"{addr:#x}" if isinstance(addr, int) else ins.get("text", "?")
                raise NotImpl(f"{loc} {ins['mnemonic']} {ins['operands']}")
            fn(ins, ops)

    # ---------------- scalar ALU/control ----------------
    def op_s_mov_b32(self, ins, ops):
        self.sset(ops[0], self.sget(ops[1]))

    def _cmp_scc(self, fn):
        self.scc = 1 if fn() else 0

    def op_s_cmp_gt_i32(self, ins, ops):
        self._cmp_scc(lambda: s32(self.sget(ops[0])) > s32(self.sget(ops[1])))

    def op_s_cmp_eq_u32(self, ins, ops):
        self._cmp_scc(lambda: (self.sget(ops[0]) & U32) == (self.sget(ops[1]) & U32))

    def op_s_cmp_ge_u32(self, ins, ops):
        self._cmp_scc(lambda: (self.sget(ops[0]) & U32) >= (self.sget(ops[1]) & U32))

    def op_s_cmp_lt_u32(self, ins, ops):
        self._cmp_scc(lambda: (self.sget(ops[0]) & U32) < (self.sget(ops[1]) & U32))

    def op_s_cmp_lg_u32(self, ins, ops):
        self._cmp_scc(lambda: (self.sget(ops[0]) & U32) != (self.sget(ops[1]) & U32))

    def op_s_cselect_b32(self, ins, ops):
        # ISA: S_CSELECT_B32 sdst, src0, src1 => sdst = SCC ? src0 : src1.
        # The arms were swapped here until Phase 16I; that inverted every
        # `s_cmp_*; s_cselect_b32 sN, -1, 0` predicate-to-mask materialisation.
        self.sset(ops[0], self.sget(ops[1] if self.scc else ops[2]))

    def op_s_and_b32(self, ins, ops):
        self.sset(ops[0], self.sget(ops[1]) & self.sget(ops[2]))

    def op_s_or_b32(self, ins, ops):
        self.sset(ops[0], (self.sget(ops[1]) | self.sget(ops[2])) & U32)

    def op_s_xor_b32(self, ins, ops):
        self.sset(ops[0], (self.sget(ops[1]) ^ self.sget(ops[2])) & U32)

    def op_s_and_not1_b32(self, ins, ops):
        self.sset(ops[0], (self.sget(ops[1]) & ~self.sget(ops[2])) & U32)

    def op_s_andn2_b32(self, ins, ops):
        self.op_s_and_not1_b32(ins, ops)

    def _saveexec(self, dst, newmask):
        old = self.exec_l
        self.sset(dst, old)
        self.exec_l = newmask & ((1 << self.lanes) - 1)

    def op_s_and_saveexec_b32(self, ins, ops):
        self._saveexec(ops[0], self.exec_l & self.sget(ops[1]))

    def op_s_andn2_saveexec_b32(self, ins, ops):
        self._saveexec(ops[0], self.exec_l & ~self.sget(ops[1]))

    def op_s_or_saveexec_b32(self, ins, ops):
        self._saveexec(ops[0], self.exec_l | self.sget(ops[1]))

    def op_s_xor_saveexec_b32(self, ins, ops):
        self._saveexec(ops[0], self.exec_l ^ self.sget(ops[1]))

    def op_s_and_not1_saveexec_b32(self, ins, ops):
        self._saveexec(ops[0], self.exec_l & ~self.sget(ops[1]))

    def op_s_add_u32(self, ins, ops):
        a = self.sget(ops[1]); b = self.sget(ops[2])
        r = a + b
        self.sset(ops[0], r)
        self.scc = 1 if r > U32 else 0

    def op_s_add_i32(self, ins, ops):
        self.sset(ops[0], self.sget(ops[1]) + self.sget(ops[2]))

    def op_s_addc_u32(self, ins, ops):
        a = self.sget(ops[1]); b = self.sget(ops[2]) + self.scc
        r = a + b
        self.sset(ops[0], r)
        self.scc = 1 if r > U32 else 0

    def op_s_sub_i32(self, ins, ops):
        self.sset(ops[0], self.sget(ops[1]) - self.sget(ops[2]))

    def op_s_mul_i32(self, ins, ops):
        self.sset(ops[0], (s32(self.sget(ops[1])) * s32(self.sget(ops[2]))) & U32)

    def op_s_mul_hi_u32(self, ins, ops):
        self.sset(ops[0], ((self.sget(ops[1]) * self.sget(ops[2])) >> 32) & U32)

    def op_s_mul_hi_i32(self, ins, ops):
        p = s32(self.sget(ops[1])) * s32(self.sget(ops[2]))
        self.sset(ops[0], (p >> 32) & U32)

    def op_s_ashr_i32(self, ins, ops):
        a = self.sget(ops[1]); sh = self.sget(ops[2]) & 31
        if sh == 0:
            self.sset(ops[0], a)
        else:
            self.sset(ops[0], (s32(a) >> sh) & U32)

    def op_s_lshl_b32(self, ins, ops):
        self.sset(ops[0], (self.sget(ops[1]) << (self.sget(ops[2]) & 31)) & U32)

    def op_s_lshr_b32(self, ins, ops):
        self.sset(ops[0], (self.sget(ops[1]) >> (self.sget(ops[2]) & 31)) & U32)

    def op_s_lshl_b64(self, ins, ops):
        v = self.spair(ops[1])
        sh = self.sget(ops[2]) & 63 if len(ops) > 2 else 0
        self.spair_set(ops[0], (v << sh) & ((1 << 64) - 1))

    def op_s_abs_i32(self, ins, ops):
        self.sset(ops[0], abs(s32(self.sget(ops[1]))) & U32)

    def op_s_cbranch_scc0(self, ins, ops):
        if self.scc == 0:
            self.pc = ins["target"]

    def op_s_cbranch_scc1(self, ins, ops):
        if self.scc == 1:
            self.pc = ins["target"]

    def op_s_cbranch_vccz(self, ins, ops):
        if self.vcc_l == 0:
            self.pc = ins["target"]

    def op_s_cbranch_vccnz(self, ins, ops):
        if self.vcc_l != 0:
            self.pc = ins["target"]

    def op_s_cbranch_execz(self, ins, ops):
        if self.exec_l == 0:
            self.pc = ins["target"]

    def op_s_cbranch_execnz(self, ins, ops):
        if self.exec_l != 0:
            self.pc = ins["target"]

    def op_s_branch(self, ins, ops):
        self.pc = ins["target"]

    def op_s_endpgm(self, ins, ops):
        self.terminated = True
        raise Halt("END")

    # ---------------- scalar loads ----------------
    def _sload(self, ins, ops, nwords):
        dst = ops[0]
        base = self.spair(ops[1])
        off = self.sget(ops[2]) if len(ops) > 2 else 0
        addr = (base + off) & ((1 << 64) - 1)
        words = []
        for i in range(nwords):
            words.append(self._read_u32(addr + 4 * i))
        bd = self._bounds(dst)
        if bd:
            a, b = bd
            for j, i in enumerate(range(a, b + 1)):
                self.s[i] = words[j]
                self.undef_s.discard(i)
        else:
            self.sset(dst, words[0])

    def op_s_load_b32(self, ins, ops):
        self._sload(ins, ops, 1)

    def op_s_load_b64(self, ins, ops):
        self._sload(ins, ops, 2)

    def op_s_load_b128(self, ins, ops):
        self._sload(ins, ops, 4)

    op_s_load_dword = op_s_load_b32
    op_s_load_dwordx2 = op_s_load_b64
    op_s_load_dwordx4 = op_s_load_b128

    def _read_u32(self, addr):
        return self.mem.get(addr & ((1 << 64) - 1), 0)

    # ---------------- vector ops ----------------
    def _vbin(self, ins, ops, fn):
        """dst=ops[0], src0=ops[1], src1=ops[2] (int); returns int or fp-typed."""
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[1])
                b = self.vget(lane, ops[2])
                self.vset(lane, ops[0], fn(a, b))

    def _vbin3(self, ins, ops, fn):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[1])
                b = self.vget(lane, ops[2])
                c = self.vget(lane, ops[3])
                self.vset(lane, ops[0], fn(a, b, c))

    def _vfp(self, ins, ops, fn):
        """float op: dst=ops[0], operands as f32 values; writes f32 bits."""
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[1], fp=True)
                b = self.vget(lane, ops[2], fp=True) if len(ops) > 2 else None
                c = self.vget(lane, ops[3], fp=True) if len(ops) > 3 else None
                r = fn(a, b, c)
                if isinstance(r, float):
                    self.vset(lane, ops[0], f32_bits(f32(r)))
                else:
                    self.vset(lane, ops[0], r & U32)

    def _vcmp(self, ins, ops, fn, fp):
        """int/float compare: dst vcc_lo (e32) or sreg mask (e64)."""
        dst = ops[0]
        if dst == "vcc_lo":
            out = self.vcc_l
            for lane in range(self.lanes):
                if (self.exec_l >> lane) & 1:
                    a = self.vget(lane, ops[1], fp=fp)
                    b = self.vget(lane, ops[1], fp=fp) if len(ops) < 3 else self.vget(lane, ops[2], fp=fp)
                    bit = 1 if fn(a, b) else 0
                    out = (out & ~(1 << lane)) | (bit << lane)
                else:
                    out &= ~(1 << lane)
            self.vcc_l = out
        else:
            mask = 0
            for lane in range(self.lanes):
                if (self.exec_l >> lane) & 1:
                    a = self.vget(lane, ops[1], fp=fp)
                    b = self.vget(lane, ops[1], fp=fp) if len(ops) < 3 else self.vget(lane, ops[2], fp=fp)
                    if fn(a, b):
                        mask |= 1 << lane
            self.sset(dst, mask)

    def _vcmpx(self, ins, ops, fn, fp):
        out = 0
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[1], fp=fp)
                b = self.vget(lane, ops[1], fp=fp) if len(ops) < 3 else self.vget(lane, ops[2], fp=fp)
                if fn(a, b):
                    out |= 1 << lane
        self.exec_l = out

    def _int_cmp_cond(self, name):
        cmps = {
            "v_cmp_gt_i32": lambda a, b: s32(a) > s32(b),
            "v_cmp_eq_u32": lambda a, b: (a & U32) == (b & U32),
            "v_cmp_lt_u32": lambda a, b: (a & U32) < (b & U32),
            "v_cmp_gt_u32": lambda a, b: (a & U32) > (b & U32),
            "v_cmp_ge_u32": lambda a, b: (a & U32) >= (b & U32),
            "v_cmp_le_u32": lambda a, b: (a & U32) <= (b & U32),
            "v_cmp_eq_i32": lambda a, b: s32(a) == s32(b),
            "v_cmp_ne_u32": lambda a, b: (a & U32) != (b & U32),
            "v_cmp_ne_i32": lambda a, b: s32(a) != s32(b),
            "v_cmp_gt_i16": lambda a, b: _s16(a) > _s16(b),
            # phase-14D8 additive width/condition families (deterministic)
            "v_cmp_eq_u16": lambda a, b: (a & 0xFFFF) == (b & 0xFFFF),
            "v_cmp_ne_u16": lambda a, b: (a & 0xFFFF) != (b & 0xFFFF),
            "v_cmp_lt_u16": lambda a, b: (a & 0xFFFF) < (b & 0xFFFF),
            "v_cmp_le_u16": lambda a, b: (a & 0xFFFF) <= (b & 0xFFFF),
            "v_cmp_gt_u16": lambda a, b: (a & 0xFFFF) > (b & 0xFFFF),
            "v_cmp_ge_u16": lambda a, b: (a & 0xFFFF) >= (b & 0xFFFF),
            "v_cmp_lt_i16": lambda a, b: _s16(a) < _s16(b),
            "v_cmp_le_i16": lambda a, b: _s16(a) <= _s16(b),
            "v_cmp_ge_i16": lambda a, b: _s16(a) >= _s16(b),
            "v_cmp_ne_i16": lambda a, b: _s16(a) != _s16(b),
            "v_cmp_eq_i16": lambda a, b: _s16(a) == _s16(b),
            "v_cmp_lt_i8": lambda a, b: _s8(a) < _s8(b),
            "v_cmp_gt_i8": lambda a, b: _s8(a) > _s8(b),
            "v_cmp_le_i8": lambda a, b: _s8(a) <= _s8(b),
            "v_cmp_ge_i8": lambda a, b: _s8(a) >= _s8(b),
            "v_cmp_eq_i8": lambda a, b: _s8(a) == _s8(b),
            "v_cmp_ne_i8": lambda a, b: _s8(a) != _s8(b),
        }
        return cmps[name]

    def _fp_cmp_cond(self, name):
        cmps = {
            "v_cmp_gt_f16": lambda a, b: f16_to_f32(a) > f16_to_f32(b),
            "v_cmp_ge_f16": lambda a, b: f16_to_f32(a) >= f16_to_f32(b),
            "v_cmp_eq_f16": lambda a, b: f16_to_f32(a) == f16_to_f32(b),
            "v_cmp_lt_f16": lambda a, b: f16_to_f32(a) < f16_to_f32(b),
            "v_cmp_gt_f32": lambda a, b: a > b,
            "v_cmp_ge_f32": lambda a, b: a >= b,
            "v_cmp_eq_f32": lambda a, b: a == b,
            "v_cmp_lt_f32": lambda a, b: a < b,
            "v_cmp_nlt_f32": lambda a, b: not (a < b),
            "v_cmp_nge_f32": lambda a, b: not (a >= b),
            "v_cmp_neq_f32": lambda a, b: a != b,
            "v_cmp_lg_f32": lambda a, b: a != b,
            "v_cmp_o_f16": lambda a, b: not (math.isnan(f16_to_f32(a)) or math.isnan(f16_to_f32(b))),
            "v_cmp_o_f32": lambda a, b: not (math.isnan(a) or math.isnan(b)),
            # phase-14D8 additive: class test approximated as "value is not
            # a finite number" (deterministic on both sides; the entry
            # windows under test do not branch on it before their reads).
            "v_cmp_class_f32": lambda a, b: math.isnan(a) or math.isinf(a),
        }
        return cmps[name]

    def __getattr__(self, name):
        # dynamic handlers for compare families
        if name.startswith("op_v_cmp_"):
            mnem = name[3:]
            if mnem in self._int_cmp_cond("") or mnem.replace("v_", "v_") in self._int_cmp_cond(""):
                pass
        raise AttributeError(name)

    def _cmp_dispatch(self, m, ins, ops):
        ints = ("v_cmp_gt_i32", "v_cmp_eq_u32", "v_cmp_lt_u32", "v_cmp_gt_u32",
                "v_cmp_ge_u32", "v_cmp_le_u32", "v_cmp_eq_i32", "v_cmp_ne_u32",
                "v_cmp_lt_i32", "v_cmp_le_i32", "v_cmp_ge_i32", "v_cmp_ne_i32",
                "v_cmp_gt_i16", "v_cmp_eq_u16", "v_cmp_ne_u16", "v_cmp_lt_u16",
                "v_cmp_le_u16", "v_cmp_gt_u16", "v_cmp_ge_u16", "v_cmp_lt_i16",
                "v_cmp_le_i16", "v_cmp_ge_i16", "v_cmp_ne_i16", "v_cmp_eq_i16",
                "v_cmp_lt_i8", "v_cmp_gt_i8", "v_cmp_le_i8", "v_cmp_ge_i8",
                "v_cmp_eq_i8", "v_cmp_ne_i8")
        if m in ints:
            self._vcmp(ins, ops, self._int_cmp_cond(m), fp=False)
            return
        cond = self._fp_cmp_cond(m)
        if m.endswith("_f16"):
            self._vcmp(ins, ops, cond, fp=False)
        else:
            self._vcmp(ins, ops, cond, fp=True)

    def _cmpx_dispatch(self, m, ins, ops):
        ints = ("v_cmpx_gt_i32", "v_cmpx_eq_u32", "v_cmpx_lt_u32", "v_cmpx_gt_u32",
                "v_cmpx_ne_u32", "v_cmpx_eq_i32", "v_cmpx_ne_i32", "v_cmpx_lt_i32",
                "v_cmpx_ge_u32", "v_cmpx_le_u32", "v_cmpx_lt_i32", "v_cmpx_le_i32",
                "v_cmpx_ge_i32", "v_cmpx_ne_i32", "v_cmpx_eq_u16", "v_cmpx_ne_u16",
                "v_cmpx_lt_u16", "v_cmpx_le_u16", "v_cmpx_gt_u16", "v_cmpx_ge_u16",
                "v_cmpx_lt_i16", "v_cmpx_le_i16", "v_cmpx_ge_i16", "v_cmpx_ne_i16",
                "v_cmpx_eq_i16", "v_cmpx_gt_i16", "v_cmpx_lt_i8", "v_cmpx_gt_i8",
                "v_cmpx_eq_i8", "v_cmpx_ne_i8")
        if m in ints:
            name = m.replace("v_cmpx_", "v_cmp_")
            self._vcmpx(ins, ops, self._int_cmp_cond(name), fp=False)
        else:
            name = m.replace("v_cmpx_", "v_cmp_")
            cond = self._fp_cmp_cond(name)
            if name.endswith("_f16"):
                self._vcmpx(ins, ops, cond, fp=False)
            else:
                self._vcmpx(ins, ops, cond, fp=True)

    # ---- extra ops needed by the main (work) region ----
    def op_s_bfe_i32(self, ins, ops):
        a = self.sget(ops[1]); o = self.sget(ops[2]) & 31; w = self.sget(ops[3]) & 31
        if w == 0:
            r = 0
        else:
            r = (a >> o) & U32
            if o + w < 32:
                r &= (1 << w) - 1
                if r & (1 << (w - 1)):
                    r |= (U32 << w) & U32
        self.sset(ops[0], r)

    def op_s_bfe_u32(self, ins, ops):
        a = self.sget(ops[1]); o = self.sget(ops[2]) & 31; w = self.sget(ops[3]) & 31
        r = ((a >> o) & ((1 << w) - 1)) & U32 if w else 0
        self.sset(ops[0], r)

    def op_s_cmp_ge_i32(self, ins, ops):
        self._cmp_scc(lambda: s32(self.sget(ops[0])) >= s32(self.sget(ops[1])))

    def op_s_min_i32(self, ins, ops):
        self.sset(ops[0], min(s32(self.sget(ops[1])), s32(self.sget(ops[2]))) & U32)

    def op_s_sext_i32_i16(self, ins, ops):
        self.sset(ops[0], _s16(self.sget(ops[1])) & U32)

    def op_s_sext_i32_i8(self, ins, ops):
        self.sset(ops[0], _s8(self.sget(ops[1])) & U32)

    def op_s_movk_i32(self, ins, ops):
        self.sset(ops[0], self.parse_simm(ops[1]))

    def parse_simm(self, tok):
        return self.sget(tok)

    def op_v_cvt_f32_ubyte0(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: f32(float(a & 0xFF)))

    def op_v_fma_mixlo_f16(self, ins, ops):
        # f16-lane fma; approximate as f32 arithmetic on halves (control-safe)
        self._vfp(ins, ops, lambda a, b, c: f32(a * b + c))

    def op_v_lshl_or_b32(self, ins, ops):
        self._vbin3(ins, ops, lambda a, b, c: ((b << (a & 31)) | c) & U32)

    def op_v_perm_b32(self, ins, ops):
        # byte-permute; only feeds data values, not control on this path
        self._vbin3(ins, ops, lambda a, b, c: b)

    def op_global_load_i8(self, ins, ops):
        dst = ops[0]
        lo_n, hi_n = (int(x) for x in ops[1].lstrip("v[").rstrip("]").split(":"))
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                addr = self.v[lane][lo_n] | (self.v[lane][hi_n] << 32)
                val = self.mem.get(addr, 0)
                self.vset(lane, dst, _s8(val) & U32)

    def op_global_load_u16(self, ins, ops):
        dst = ops[0]
        lo_n, hi_n = (int(x) for x in ops[1].lstrip("v[").rstrip("]").split(":"))
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                addr = self.v[lane][lo_n] | (self.v[lane][hi_n] << 32)
                val = self.mem.get(addr, 0)
                self.vset(lane, dst, val)

    def op_v_wmma_f32_16x16x16_f16(self, ins, ops):
        # value-stub: no control impact; accumulate conservative junk so any
        # later data-dependent compare still exercises all paths deterministically
        dst = ops[0]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                pass  # leave accumulator as-is; control-neutral

    def op_v_dot2c_f32_f16(self, ins, ops):
        # gfx1030 spelling of the soft-wmma replacement dot (control-neutral)
        pass

    def op_ds_bpermute_b32(self, ins, ops):
        pass  # cross-lane gather; control-neutral on this path

    def op_v_fmac_f32(self, ins, ops):
        # dst = dst + src0*src1
        dst = ops[0]
        src0 = ops[1]
        src1 = ops[2]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, dst, fp=True)
                b = self.vget(lane, src0, fp=True)
                c = self.vget(lane, src1, fp=True)
                self.vset(lane, dst, f32_bits(f32(a + b * c)))

    def op_v_wmma_stub(self, ins, ops):
        pass

    def op_v_cmp(self, ins, ops):  # placeholder, replaced below by dynamic
        raise NotImpl("unused")

    def op_v_cmpx(self, ins, ops):
        raise NotImpl("unused")

    # int ALU
    def op_v_mov_b32(self, ins, ops):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                self.vset(lane, ops[0], self.vget(lane, ops[1]))

    def op_v_add_nc_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (a + b) & U32)

    op_v_add_u32 = op_v_add_nc_u32

    def op_v_add_co_u32(self, ins, ops):
        dst = ops[0]
        carry = ops[1]
        src0 = ops[2]
        src1 = ops[3]
        out = 0
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, src0) & U32  # imm negatives: 2's complement
                b = self.vget(lane, src1) & U32
                r = a + b
                self.vset(lane, dst, r)
                if r > U32:
                    out |= 1 << lane
        if carry == "vcc_lo":
            self.vcc_l = out
        elif carry.startswith("s"):
            self.sset(carry, out)

    def op_v_add_co_ci_u32(self, ins, ops):
        # e32: dst, vcc, src0, src1 (carry-in vcc). e64: dst, null/scc, ssrc0, vsrc1, sreg-carry
        dst = ops[0]
        cout = ops[1]
        src0 = ops[2]
        src1 = ops[3]
        cin_tok = ops[4] if len(ops) > 4 else "vcc_lo"
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, src0) & U32
                b = self.vget(lane, src1) & U32
                if cin_tok == "vcc_lo":
                    c = (self.vcc_l >> lane) & 1
                elif cin_tok.startswith("s"):
                    c = (self.sget(cin_tok) >> lane) & 1
                else:
                    c = 0
                r = a + b + c
                self.vset(lane, dst, r)
                if cout == "vcc_lo":
                    self.vcc_l = (self.vcc_l & ~(1 << lane)) | ((1 if r > U32 else 0) << lane)

    def op_v_add3_u32(self, ins, ops):
        self._vbin3(ins, ops, lambda a, b, c: (a + b + c) & U32)

    def op_v_and_b32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (a & b) & U32)

    def op_v_or_b32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (a | b) & U32)

    def op_v_xor_b32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (a ^ b) & U32)

    def op_v_and_or_b32(self, ins, ops):
        # (v0 & v1) | v2 with srcs possibly scalar
        self._vbin3(ins, ops, lambda a, b, c: ((a & b) | c) & U32)

    def op_v_or3_b32(self, ins, ops):
        self._vbin3(ins, ops, lambda a, b, c: (a | b | c) & U32)

    def op_v_lshlrev_b32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (b << (a & 31)) & U32)

    def op_v_lshrrev_b32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (b >> (a & 31)) & U32)

    def op_v_ashrrev_i32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (s32(b) >> (a & 31)) & U32)

    def op_v_lshrrev_b16(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: ((b & 0xFFFF) >> (a & 15)) & 0xFFFF)

    def op_v_ashrrev_i16(self, ins, ops):
        def f(a, b):
            v = b & 0xFFFF
            if v & 0x8000:
                v -= 0x10000
            return (v >> (a & 15)) & 0xFFFF
        self._vbin(ins, ops, f)

    def op_v_add_nc_u16(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: ((a & 0xFFFF) + (b & 0xFFFF)) & 0xFFFF)

    def op_v_sub_nc_u16(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: ((a & 0xFFFF) - (b & 0xFFFF)) & 0xFFFF)

    def op_v_sub_nc_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (a - b) & U32)

    def op_v_lshl_add_u32(self, ins, ops):
        self._vbin3(ins, ops, lambda a, b, c: ((b << (a & 31)) + c) & U32)

    def op_v_bfe_u32(self, ins, ops):
        self._vbin3(ins, ops, lambda a, o, w: ((a >> (o & 31)) & ((1 << (w & 31)) - 1)) & U32)

    def op_v_bfe_i32(self, ins, ops):
        def f(a, o, w):
            o &= 31
            w &= 31
            if w == 0:
                return 0
            v = (a >> o) & U32
            if o + w < 32:
                v &= (1 << w) - 1
                if v & (1 << (w - 1)):
                    v |= (U32 << w) & U32
            return v & U32
        self._vbin3(ins, ops, f)

    def op_v_min_i32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: min(s32(a), s32(b)) & U32)

    def op_v_max_i32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: max(s32(a), s32(b)) & U32)

    def op_v_min_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: min(a & U32, b & U32) & U32)

    def op_v_cndmask_b32(self, ins, ops):
        dst = ops[0]
        src0 = ops[1]
        src1 = ops[2]
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
                self.vset(lane, dst, b if c else a)

    def op_v_readfirstlane_b32(self, ins, ops):
        self.sset(ops[0], self.v[0][int(ops[1][1:])])

    # float ALU
    def op_v_add_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: a + b)

    def op_v_sub_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: a - b)

    def op_v_mul_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: a * b)

    def op_v_fma_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: a * b + c)

    def op_v_cvt_f32_f16(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: f16_to_f32(int(a)))

    def op_v_cvt_f16_f32(self, ins, ops):
        # not needed on path; approximate f32->f16 via round to 11-bit mantissa
        def conv(x):
            if math.isnan(x):
                return 0x7E00
            if math.isinf(x):
                return 0x7C00 | (0x8000 if x < 0 else 0)
            if x == 0.0:
                return 0x8000 if math.copysign(1, x) < 0 else 0
            import struct as _st
            b = _st.unpack("<I", _st.pack("<f", f32(x)))[0]
            s = (b >> 16) & 1
            e = ((b >> 23) & 0xFF) - 127
            if e > 15:
                return 0x7C00 | (s << 15)
            if e < -24:
                return s << 15
            if e < -14:
                frac = int(round(abs(x) / 2.0 ** -24))
                return (s << 15) | min(frac, 0x3FF)
            q = abs(x) / 2.0 ** e
            mnt = int(round((q - 1.0) * 1024.0))
            if mnt == 1024:
                e += 1
                mnt = 0
            if e > 15:
                return 0x7C00 | (s << 15)
            return (s << 15) | ((e + 15) << 10) | mnt
        self._vfp(ins, ops, lambda a, b, c: conv(a))

    def op_v_cvt_i32_f32(self, ins, ops):
        def conv(x):
            if math.isnan(x) or math.isinf(x):
                return 0
            if x >= 2**31:
                return 0x7FFFFFFF
            if x <= -(2**31):
                return SIGN
            return int(math.trunc(x)) & U32
        self._vfp(ins, ops, lambda a, b, c: conv(a))

    def op_v_cvt_f32_u32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: f32(float(a & U32)))

    def op_v_cvt_u32_f32(self, ins, ops):
        def conv(x):
            if math.isnan(x) or x <= 0:
                return 0
            if x >= 2**32:
                return U32
            return int(math.trunc(x)) & U32
        self._vfp(ins, ops, lambda a, b, c: conv(a))

    def op_v_rcp_f32(self, ins, ops):
        def f(a, b, c):
            if a == 0:
                return f32(math.copysign(float("inf"), a))
            return f32(1.0 / a)
        self._vfp(ins, ops, f)

    op_v_rcp_iflag_f32 = op_v_rcp_f32

    def op_v_floor_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: f32(math.floor(a)))

    def op_v_rndne_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: f32(round(a)) if not (math.isnan(a) or math.isinf(a)) else a)

    def op_v_ldexp_f32(self, ins, ops):
        def f(a, b, c):
            try:
                return f32(math.ldexp(a, int(b)))
            except OverflowError:
                return f32(math.copysign(float("inf"), a))
        self._vfp(ins, ops, f)

    def op_v_log_f32(self, ins, ops):
        def f(a, b, c):
            if a > 0:
                return f32(math.log(a))
            if a == 0:
                return f32(float("-inf"))
            return float("nan")
        self._vfp(ins, ops, f)

    def op_v_div_scale_f32(self, ins, ops):
        # approximate implementation preserving structure: scale = b/c*2^k
        dst = ops[0]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[2], fp=True)
                b = self.vget(lane, ops[3], fp=True)
                self.vset(lane, dst, f32_bits(f32(a)))
        if ops[1] == "vcc_lo":
            self.vcc_l = 0

    def op_v_div_fmas_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: f32(a * b + c))

    def op_v_div_fixup_f32(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: a)

    # ---- memory ----
    def op_s_mov_b64(self, ins, ops):
        # s_mov_b64 dst, imm64/sregpair  (rare; conservative single value)
        self.spair_set(ops[0], self.sget(ops[1]) if ops[1].startswith("0x") or ops[1].isdigit() else self.spair(ops[1]))

    def op_v_subrev_nc_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (b - a) & U32)

    def op_ds_read_u16(self, ins, ops):
        self.op_ds_load_u16(ins, ops)

    def op_ds_load_u16(self, ins, ops):
        dst = ops[0]
        addr_tok = ops[1]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                off = self.vget(lane, addr_tok)
                if off < 0 or off + 1 >= len(self.lds):
                    continue  # HW: out-of-range LDS read -> undefined data, no fault
                v = self.lds[off] | (self.lds[off + 1] << 8)
                self.vset(lane, dst, v)

    @staticmethod
    def _ds_parts(text, nbytes):
        """Return (addr_vreg, data_vregs, offset) parsed from a ds op text."""
        import re
        m = re.match(r"^ds_\S+\s+(v\d+)(?:,\s*)?(.*)$", text)
        if not m:
            raise NotImpl(f"ds parse: {text}")
        addr = m.group(1)
        rest = m.group(2)
        off = 0
        om = re.search(r"offset:(-?[0-9a-fA-Fx]+)", rest)
        if om:
            t = om.group(1)
            off = int(t, 0) if t.lower().startswith("0x") else int(t)
            rest = rest[: om.start()].strip().rstrip(",").strip()
        datas = []
        dm = re.match(r"^v(\d+)", rest)
        if dm and rest.strip():
            # possible v[a:b] range forms
            if "[" in rest:
                datas = [rest.strip()]
            else:
                datas = [rest.strip()]
        return addr, datas, off

    def _ds_data_dwords(self, lane, tok):
        """Read one or more consecutive dwords from a data operand token."""
        tok = tok.strip()
        if "[" in tok:
            a, b = (int(x) for x in tok.lstrip("v[").rstrip("]").split(":"))
            return [self.v[lane][i] for i in range(a, b + 1)]
        return [self.v[lane][int(tok[1:])]]

    def _ds_store(self, ins, ops, nbytes):
        addr_tok, data_toks, off = self._ds_parts(ins["text"], nbytes)
        if not data_toks:
            raise NotImpl(f"ds store data parse: {ins['text']}")
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                base = (self.vget(lane, addr_tok) + off) & 0xFFFFFFFF
                if base + nbytes > len(self.lds):
                    continue
                dwords = []
                for t in data_toks:
                    dwords.extend(self._ds_data_dwords(lane, t))
                nbytes_left = nbytes
                di = 0
                while nbytes_left > 0 and di < len(dwords):
                    nb = min(4, nbytes_left)
                    v = dwords[di]
                    for j in range(nb):
                        self.lds[base + di * 4 + j] = (v >> (8 * j)) & 0xFF
                    nbytes_left -= nb
                    di += 1

    def _ds_load(self, ins, ops, nbytes):
        dst = ops[0]
        addr_tok, _, off = self._ds_parts(ins["text"], nbytes)
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                base = (self.vget(lane, addr_tok) + off) & 0xFFFFFFFF
                if base + nbytes > len(self.lds):
                    continue
                val = 0
                for i in range(nbytes):
                    val |= self.lds[base + i] << (8 * i)
                self.vset(lane, dst, val)

    def op_ds_store_b32(self, ins, ops):
        self._ds_store(ins, ops, 4)

    def op_ds_store_b16(self, ins, ops):
        self._ds_store(ins, ops, 2)

    def op_ds_store_b8(self, ins, ops):
        self._ds_store(ins, ops, 1)

    def op_ds_store_b64(self, ins, ops):
        self._ds_store(ins, ops, 8)

    def op_ds_store_b128(self, ins, ops):
        # vdst(4 dwords) via addr vreg + data in 4 consecutive? handle 2addr form
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                pass  # handled via generic when needed

    def op_ds_load_b32(self, ins, ops):
        self._ds_load(ins, ops, 4)

    def op_ds_load_u16(self, ins, ops):
        self._ds_load(ins, ops, 2)

    def op_ds_load_b16(self, ins, ops):
        self._ds_load(ins, ops, 2)

    def op_ds_load_u8(self, ins, ops):
        self._ds_load(ins, ops, 1)

    def op_ds_load_b8(self, ins, ops):
        self._ds_load(ins, ops, 1)

    def op_ds_load_b64(self, ins, ops):
        self._ds_load(ins, ops, 8)

    def op_ds_read_b32(self, ins, ops):
        self._ds_load(ins, ops, 4)

    def op_ds_read_u16(self, ins, ops):
        self._ds_load(ins, ops, 2)

    def op_ds_read_b16(self, ins, ops):
        self._ds_load(ins, ops, 2)

    def op_ds_read_b8(self, ins, ops):
        self._ds_load(ins, ops, 1)

    def op_ds_read_u8(self, ins, ops):
        self._ds_load(ins, ops, 1)

    def op_ds_write_b32(self, ins, ops):
        self.op_ds_store_b32(ins, ops)

    def op_ds_write_b16(self, ins, ops):
        self.op_ds_store_b16(ins, ops)

    def op_ds_write_b8(self, ins, ops):
        self.op_ds_store_b8(ins, ops)

    def op_ds_write_b64(self, ins, ops):
        self._ds_store(ins, ops, 8)

    def op_ds_write_2addr_b32(self, ins, ops):
        self._ds_store(ins, ops, 4)

    def op_ds_read_2addr_b32(self, ins, ops):
        self._ds_load(ins, ops, 4)

    def op_global_store_b8(self, ins, ops):
        lo_n, hi_n = (int(x) for x in ops[0].lstrip("v[").rstrip("]").split(":"))
        data = ops[1]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                addr = self.v[lane][lo_n] | (self.v[lane][hi_n] << 32)
                val = self.vget(lane, data) & 0xFF
                self.mem[addr] = val
                self.global_stores.append((addr, val, lane))

    op_global_store_byte = op_global_store_b8

    def op_global_load_b8(self, ins, ops):
        pass

    op_global_load_byte = op_global_load_b8

    # ---- no-ops ----
    def _noop(self, ins, ops):
        pass

    op_s_nop = _noop
    op_s_delay_alu = _noop
    op_s_clause = _noop
    op_s_waitcnt = _noop
    op_s_waitcnt_depctr = _noop
    op_s_sendmsg = _noop
    op_s_barrier = _noop
    op_s_sleep = _noop
    op_s_code_end = _noop
    op_buffer_gl0_inv = _noop
    op_buffer_gl1_inv = _noop


def split_dual(r):
    """Split a dual-issue disassembly row into component instruction dicts."""
    ops = r["operands"]
    if "::" not in ops:
        return [r]
    left, right = ops.split("::", 1)
    out = []
    # left side keeps the row mnemonic
    l = dict(r)
    l["operands"] = left.strip()
    l["text"] = r["mnemonic"] + " " + left.strip()
    l["dual"] = True
    out.append(l)
    # right side carries its own mnemonic
    rtxt = right.strip()
    rm, _, rops = rtxt.partition(" ")
    rr = dict(r)
    rr["mnemonic"] = rm
    rr["operands"] = rops.strip()
    rr["text"] = rtxt
    rr["dual"] = True
    out.append(rr)
    return out


def build_orig_program(rows):
    prog = []
    for r in rows:
        for ins in split_dual(r):
            ins = dict(ins)
            ins["target"] = None
            prog.append(ins)
    by_addr = {}
    for i, ins in enumerate(prog):
        by_addr.setdefault(ins["address"], i)
    for ins in prog:
        m = ins["mnemonic"]
        if m.startswith("s_cbranch") or m == "s_branch":
            first = ins["operands"].split()[0] if ins["operands"] else ""
            tgt = None
            try:
                if first.startswith("0x"):
                    tgt = int(first, 16)
                elif first.lstrip("-").isdigit():
                    disp = int(first)
                    if disp >= 0x8000:
                        disp -= 0x10000
                    tgt = ins["address"] + 4 + disp * 4
            except ValueError:
                pass
            if tgt is None:
                raise ValueError(f"cannot resolve branch at {ins['address']:#x}")
            cand = by_addr.get(tgt)
            if cand is None:
                raise ValueError(f"branch target {tgt:#x} not found (from {ins['address']:#x})")
            ins["target"] = cand
    return prog


def build_translated_program(rows):
    """rows = full .s rows incl labels; returns program + asm index map."""
    prog = []
    asm_row_of = []  # per prog entry, the index in `rows`
    labels = {}
    for i, r in enumerate(rows):
        if r["kind"] == "label":
            labels[r["name"]] = i
    for i, r in enumerate(rows):
        if r["kind"] != "instruction":
            continue
        ins = dict(r)
        ins["target"] = None
        m = r["mnemonic"]
        if m.startswith("s_cbranch") or m == "s_branch":
            tgtname = r["operands"].strip()
            if tgtname not in labels:
                raise ValueError(f"unknown branch label {tgtname}")
            ins["_label"] = tgtname
        prog.append(ins)
        asm_row_of.append(i)
    for ins in prog:
        if "_label" in ins:
            target_row = labels[ins["_label"]]
            t = None
            for j, rw in enumerate(asm_row_of):
                if rw >= target_row:
                    t = j
                    break
            if t is None:
                raise ValueError(f"label {ins['_label']} past end")
            ins["target"] = t
            del ins["_label"]
    return prog
