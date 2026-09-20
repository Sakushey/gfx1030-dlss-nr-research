"""Phase 14D8 host-only emulator core (no GPU, no HIP).

Builds AMDHSA dispatch-entry register state *from kernel-descriptor fields*
(parser = p14d_kd + p14d_dec, calibrated in 14D) instead of a hand-written
layout table:

  - enabled user SGPR inputs packed from s0 in canonical order
    (pb 4, dispatch_ptr 2, queue_ptr 2, kernarg 2, dispatch_id 2,
     flat_scratch_init 2, private_segment_size 1)
  - system SGPR block starts at SGPR index == declared user_sgpr_count
  - enabled system fields in order: wgid_x, wgid_y, wgid_z, workgroup_info,
    private_segment_wavefront_offset
  - workitem_id VGPRs at v0..v2 when the descriptor's workitem bit is set
  - SGPR indices inside the declared user region that no enabled preload
    occupies (the "gap") are marked UNDEFINED; a kernel read of one before
    it is written raises Halt("UNDEFREAD") (fail-closed, 14D8-D).

An extended core (Core8) adds opcode coverage needed by the entry windows
of the other policy classes while leaving the phase-8 subset untouched.
"""
from __future__ import annotations

import math
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "phase8_static", "tools"))
sys.path.insert(0, os.path.join(ROOT, "phase14d_static", "tools"))

import emu as emu_mod                       # noqa: E402
import p14d_dec as dec                       # noqa: E402
import p14d_kd as kd                         # noqa: E402
from emu import Core, Halt, NotImpl, U32     # noqa: E402


# ---------------------------------------------------------------------------
# Descriptor-driven entry state
# ---------------------------------------------------------------------------
USER_FILL = {  # semantic -> deterministic fill when enabled (never read)
    "private_segment_buffer": [0x00000000, 0x80000000, 0x00000000, 0x00000000],
    "queue_ptr": 0,
    "dispatch_id": 0,
    "flat_scratch_init": 0,
    "private_segment_size": 0,
}


def entry_plan(dw16):
    """Pure derivation: descriptor dwords -> placement plan. Returns dict
    with user/sys/vgpr placements, gap span (or None), parsed info."""
    info = dec.dec(dw16)
    regs, sys_regs, vgprs, next_sgpr = dec.register_map(info)
    gap = None
    if next_sgpr < info["user_count"]:
        gap = (next_sgpr, info["user_count"] - 1)
    plan = {
        "info": info,
        "user": regs,          # semantic -> (start, span)
        "system": sys_regs,    # semantic -> (start, span)
        "workitem_vgpr": vgprs,
        "gap": gap,
        "user_declared": info["user_count"],
    }
    return plan


def expected_layout_str(plan):
    parts = []
    for name, (idx, span) in sorted(plan["user"].items()):
        parts.append(f"s{idx}" + (f":s{idx+span-1}" if span > 1 else "") +
                     f"={name}")
    for name, (idx, span) in sorted(plan["system"].items()):
        parts.append(f"s{idx}" + (f":s{idx+span-1}" if span > 1 else "") +
                     f"={name}")
    g = plan["gap"]
    if g:
        parts.append(f"s{g[0]}:s{g[1]}=UNDEFINED-gap")
    for name, idx in sorted(plan["workitem_vgpr"].items()):
        parts.append(f"v{idx}={name}")
    return ", ".join(parts) if parts else "(none)"


def fill_entry(core, plan, kernarg=None, dispatch_ptr=None,
               wgid=(0, 0, 0), wavebase=0, block=(256, 1, 1)):
    """Write the plan's semantic preloads into core. Semantics whose value
    a caller leaves None get their deterministic placeholder; gap SGPRs are
    marked undefined. Returns dict semantic -> (start, span) of everything
    populated."""
    fills = {}
    for name, (idx, span) in plan["user"].items():
        if name == "kernarg_segment_ptr" and kernarg is not None:
            lo, hi = kernarg & U32, (kernarg >> 32) & U32
        elif name == "dispatch_ptr" and dispatch_ptr is not None:
            lo, hi = dispatch_ptr & U32, (dispatch_ptr >> 32) & U32
        elif name in USER_FILL:
            v = USER_FILL[name]
            if isinstance(v, list):
                for j in range(span):
                    core.s[idx + j] = v[j]
            else:
                for j in range(span):
                    core.s[idx + j] = v & U32
            continue
        else:
            raise NotImpl(f"user semantic {name} has no dispatch value")
        core.s[idx] = lo
        core.s[idx + 1] = hi
        fills[name] = (idx, span)
    for name, (idx, span) in plan["system"].items():
        if name == "workgroup_id_x":
            v = wgid[0] & U32
        elif name == "workgroup_id_y":
            v = wgid[1] & U32
        elif name == "workgroup_id_z":
            v = wgid[2] & U32
        elif name == "workgroup_info":
            v = (block[0] << 16) | (block[1])  # placeholder, unread by reps
        elif name == "private_segment_wavefront_offset":
            v = 0
        else:
            raise NotImpl(f"system semantic {name} unhandled")
        for j in range(span):
            core.s[idx + j] = v
        fills[name] = (idx, span)
    if plan["workitem_vgpr"]:
        # hardware workitem_id_x/y/z are per-workgroup thread ids in the
        # emulator convention used by the phase-8 model (v0 = tid of lane).
        pass
    g = plan["gap"]
    if g:
        for i in range(g[0], g[1] + 1):
            core.undef_s.add(i)
    return fills


# ---------------------------------------------------------------------------
# Watch-driven entry validation
# ---------------------------------------------------------------------------
def run_watch(core, prog, watch, step_cap=200000, tail=64, events=None):
    """Run `core` from its descriptor-derived entry state.

    `watch` = {semantic: (start, span)} for preloads the kernel is expected
    to read. On the FIRST execution of an instruction that consumes a
    spanned SGPR the value actually held is recorded (values are taken from
    the live register file; the register numbering itself is asserted
    statically by comparing entry_plan()s, not inferred here).

    Stepping continues until every watched span has fired plus a `tail`
    margin so a post-entry read of an undefined gap SGPR still trips the
    fail-closed Halt("UNDEFREAD").

    events: optional list to append per-step ("pc", "text", "branch", ...)
    rows for trace logging.
    """
    reads = {sem: [] for sem in watch}
    pend = {sem: list(range(start, start + span))
            for sem, (start, span) in watch.items()}
    all_fired_at = None

    def probe(reg):
        if not pend:
            return
        for sem, regs in list(pend.items()):
            if reg in regs:
                reads[sem].append(core.s[reg])
                regs.remove(reg)
                if not regs:
                    del pend[sem]

    outcome = None
    try:
        while core.steps < step_cap:
            ins = prog[core.pc]
            for r in _read_regs_of(ins):
                probe(r)
            if events is not None:
                events.append((ins, core.steps, core.pc, core.exec_l,
                               core.vcc_l, core.scc))
            core.step()
            if core.terminated:
                outcome = ("END", core.steps)
                break
            if not pend and all_fired_at is None:
                all_fired_at = core.steps
            if all_fired_at is not None and core.steps >= all_fired_at + tail:
                outcome = ("WATCHDONE", core.steps)
                break
        if outcome is None:
            outcome = ("STEPLIMIT", core.steps)
    except Halt as h:
        outcome = (h.kind, core.steps, h.info)
    except NotImpl as e:
        outcome = ("NOTIMPL", core.steps, str(e))
    return {"kind": outcome[0], "steps": core.steps,
            "reads": {k: v for k, v in reads.items()},
            "fired": {s for s, r in reads.items() if r},
            "info": outcome[2:]}


_SREG_RE = re.compile(r"^s(\d+)$|^s\[(\d+):(\d+)\]$")


def _read_regs_of(ins):
    """Scalar register indices this instruction reads as a *source*
    (operand positions). Conservative: every plain sNN / s[a:b] token that
    is not the first (destination) operand of a known write-form is a
    candidate read. We only use this to *trigger* entry-read watches, so
    extra triggers are harmless (values are the actual register contents).
    Tokens may carry trailing modifiers ("s[0:1] offset:4") -- only the
    head of each comma-split token is matched."""
    mnem = ins["mnemonic"].replace("_e32", "").replace("_e64", "")
    ops = [o.strip() for o in ins["operands"].split(",")] if ins["operands"] else []
    W = {"s_load_dword", "s_load_dwordx2", "s_load_dwordx4", "s_load_b32",
         "s_load_b64", "s_load_b128", "s_load_b256", "s_load_dwordx8"}
    toks = []
    for o in ops:
        head = o.split()[0] if o else ""
        if _SREG_RE.match(head):
            toks.append(head)
    # for scalar stores the first token is a destination, not a read
    if mnem in W or mnem.startswith("s_mov") or mnem.startswith("s_cselect") \
            or mnem.startswith("s_add") or mnem.startswith("s_sub") \
            or mnem.startswith("s_and") or mnem.startswith("s_or") \
            or mnem.startswith("s_xor") or mnem.startswith("s_lshl") \
            or mnem.startswith("s_lshr") or mnem.startswith("s_ashr") \
            or mnem.startswith("s_mul") or mnem.startswith("s_abs") \
            or mnem.startswith("s_bfe") or mnem.startswith("s_not") \
            or mnem.startswith("s_min") or mnem.startswith("s_max") \
            or mnem.startswith("s_cmp") or mnem.startswith("s_swap") \
            or mnem.startswith("s_pack") or mnem.startswith("s_sext") \
            or mnem.startswith("s_nand") or mnem.startswith("s_nor") \
            or mnem.startswith("s_ornot") or mnem.startswith("s_andn2") \
            or mnem.startswith("s_bitcmp"):
        toks = toks[1:]
    out = []
    for t in toks:
        m = _SREG_RE.match(t)
        if not m:
            continue
        if m.group(1):
            out.append(int(m.group(1)))
        else:
            out.extend(range(int(m.group(2)), int(m.group(3)) + 1))
    return out


# ---------------------------------------------------------------------------
# Extended core: entry-window opcode coverage for all policy classes
# ---------------------------------------------------------------------------
def _s16(x):
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x


class Core8(Core):
    # --- wider scalar loads ---
    def op_s_load_b256(self, ins, ops):
        self._sload(ins, ops, 8)

    op_s_load_dwordx8 = op_s_load_b256

    def op_s_load_b96(self, ins, ops):
        self._sload(ins, ops, 3)

    # --- scratch (gfx10 implicit forms; private state not modeled) ---
    def op_scratch_load_b32(self, ins, ops):
        pass

    op_scratch_load_dword = op_scratch_load_b32

    def op_scratch_store_b32(self, ins, ops):
        pass

    op_scratch_store_dword = op_scratch_store_b32

    def op_scratch_store_b64(self, ins, ops):
        pass

    def op_scratch_store_b128(self, ins, ops):
        pass

    def op_scratch_store_dwordx4(self, ins, ops):
        pass

    def op_scratch_load_b64(self, ins, ops):
        pass

    def op_scratch_load_b128(self, ins, ops):
        pass

    def op_scratch_load_dwordx2(self, ins, ops):
        pass

    def op_scratch_load_dwordx4(self, ins, ops):
        pass

    # --- global memory vectors ---
    def _read_bytes(self, addr):
        """Compose a dword from byte-keyed stores (payload convention), or
        from a dword-keyed write (kernarg/harness convention).

        Phase 16M M2 defect 8: this returned `mem.get(addr, 0)` -- the WHOLE
        dword -- when no byte keys were present, and `_gld` then assembled the
        access byte by byte, so a 4-byte load from a dword-keyed image yielded
        `0x44` instead of `0x11223344`.  It now delegates to the one
        byte-addressed reader on `Core` (which prefers byte keys, then splits
        the aligned dword key), so the wide-global and scalar memory models
        read the same bytes.
        """
        return self._read_u32(addr)

    def _gl_addr(self, ins, lane, ops, store=False):
        """Per-lane global address. Operand conventions seen in these
        kernels: a 64-bit vaddr pair 'v[lo:hi]' (loads: ops[1], stores:
        ops[0]), or a 32-bit single vaddr plus an s[a:b] scalar base and an
        optional 'offset:NN' text modifier (flag-style kernels)."""
        idx = 1 if not store else 0
        tok = ops[idx]
        m = re.search(r"offset[:=](-?0x[0-9a-fA-F]+|-?\d+)", ins["operands"])
        off = int(m.group(1), 0) if m else 0
        if tok.startswith("v[") or ":" in tok:
            lo_n, hi_n = (int(x) for x in
                          tok.lstrip("v[").rstrip("]").split(":"))
            addr = self.v[lane][lo_n] | (self.v[lane][hi_n] << 32)
        else:
            n = int(tok[1:])
            addr = self.v[lane][n]
            if len(ops) > 2 and ops[2].startswith("s["):
                addr += self.spair(ops[2].split()[0])
        return (addr + off) & ((1 << 64) - 1)

    def _gld(self, ins, ops, nbytes, sext=0):
        """Global load of nbytes into ops[0] (single vreg or v[a:b])."""
        dst = ops[0]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                # One call only: `_gl_addr` is overridden by the recording
                # cores (RecCore appends to `g_ops`, GateCore increments the
                # gate counters and files OOB records), so calling it twice
                # double-counted every global LOAD.  `_gst` below calls it
                # once, which is why historical read counts were inflated 2x
                # relative to writes.
                addr = self._gl_addr(ins, lane, ops)
                v = 0
                for j in range(nbytes):
                    v |= (self._read_bytes(addr + j) & 0xFF) << (8 * j)
                if sext and (v >> (8 * nbytes - 1)) & 1:
                    v |= (U32 << (8 * nbytes)) & U32
                if "[" in dst:
                    a, b = (int(x) for x in
                            dst.lstrip("v[").rstrip("]").split(":"))
                    for j, i in enumerate(range(a, b + 1)):
                        self.v[lane][i] = (v >> (32 * j)) & U32
                else:
                    self.v[lane][int(dst[1:])] = v & U32

    def _gst(self, ins, ops, nbytes):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                addr = self._gl_addr(ins, lane, ops, store=True)
                data = ops[1]
                if "[" in data:
                    a, b = (int(x) for x in
                            data.lstrip("v[").rstrip("]").split(":"))
                    dvals = [self.v[lane][i] for i in range(a, b + 1)]
                else:
                    dvals = [self.vget(lane, data) & U32]
                nleft = nbytes
                for j, v in enumerate(dvals):
                    if nleft <= 0:
                        break
                    nb = min(4, nleft)
                    for k in range(nb):
                        bv = (v >> (8 * k)) & 0xFF
                        self.mem[addr + 4 * j + k] = bv
                        self.global_stores.append((addr + 4 * j + k, bv,
                                                   lane))
                    nleft -= nb

    def op_global_load_b32(self, ins, ops):
        self._gld(ins, ops, 4)

    op_global_load_dword = op_global_load_b32

    def op_global_load_b64(self, ins, ops):
        self._gld(ins, ops, 8)

    op_global_load_dwordx2 = op_global_load_b64

    def op_global_load_b96(self, ins, ops):
        self._gld(ins, ops, 12)

    op_global_load_dwordx3 = op_global_load_b96

    def op_global_load_b128(self, ins, ops):
        self._gld(ins, ops, 16)

    op_global_load_dwordx4 = op_global_load_b128

    def op_global_load_u8(self, ins, ops):
        self._gld(ins, ops, 1)

    op_global_load_ubyte = op_global_load_u8

    def op_global_load_sbyte(self, ins, ops):
        self._gld(ins, ops, 1, sext=1)

    def op_global_load_b8(self, ins, ops):
        self._gld(ins, ops, 1)

    def op_global_load_i8(self, ins, ops):
        self._gld(ins, ops, 1, sext=1)

    def op_global_load_b16(self, ins, ops):
        self._gld(ins, ops, 2)

    op_global_load_ushort = op_global_load_b16

    def op_global_load_short(self, ins, ops):
        self._gld(ins, ops, 2, sext=1)

    def op_global_load_u16(self, ins, ops):
        self._gld(ins, ops, 2)

    def op_global_load_d16_hi_b16(self, ins, ops):
        self._gld(ins, ops, 2)

    def op_global_store_b8(self, ins, ops):
        self._gst(ins, ops, 1)

    def op_global_store_b16(self, ins, ops):
        self._gst(ins, ops, 2)

    def op_global_store_b32(self, ins, ops):
        self._gst(ins, ops, 4)

    op_global_store_dword = op_global_store_b32

    def op_global_store_b64(self, ins, ops):
        self._gst(ins, ops, 8)

    def op_global_store_b128(self, ins, ops):
        self._gst(ins, ops, 16)

    def op_global_store_dwordx4(self, ins, ops):
        self._gst(ins, ops, 16)

    # legacy 16-bit global-store spelling used by some dumps
    def op_global_store_byte(self, ins, ops):
        self._gst(ins, ops, 1)
    # --- scalar ALU extras ---
    def _cmp2(self, fn, ops):
        self.scc = 1 if fn(self.sget(ops[0]), self.sget(ops[1])) else 0

    def op_s_cmp_lt_i32(self, ins, ops):
        self._cmp2(lambda a, b: emu_mod.s32(a) < emu_mod.s32(b), ops)

    def op_s_cmp_gt_u32(self, ins, ops):
        self._cmp2(lambda a, b: (a & U32) > (b & U32), ops)

    def op_s_cmp_ge_i32(self, ins, ops):
        self._cmp2(lambda a, b: emu_mod.s32(a) >= emu_mod.s32(b), ops)

    def _sbfe_imm(self, ops):
        """3-operand immediate s_bfe: offset:width packed in one u32
        (deterministic decode used identically on both sides)."""
        imm = self.sget(ops[2])
        off = (imm >> 16) & 0x1F
        w = imm & 0x3F
        if w == 0:
            w = 32
        return off, w

    def op_s_bfe_u32(self, ins, ops):
        if len(ops) >= 4:
            Core.op_s_bfe_u32(self, ins, ops)
            return
        a = self.sget(ops[1])
        off, w = self._sbfe_imm(ops)
        if off + w >= 32:
            w = 32 - off
        r = ((a >> off) & ((1 << w) - 1)) & U32
        self.sset(ops[0], r)

    def op_s_bfe_i32(self, ins, ops):
        if len(ops) >= 4:
            Core.op_s_bfe_i32(self, ins, ops)
            return
        a = self.sget(ops[1])
        off, w = self._sbfe_imm(ops)
        if off + w >= 32:
            w = 32 - off
        r = (a >> off) & U32
        if off + w < 32:
            r &= (1 << w) - 1
            if r & (1 << (w - 1)):
                r |= (U32 << w) & U32
        self.sset(ops[0], r)

    def op_s_cmp_eq_u64(self, ins, ops):
        self.scc = 1 if self.spair(ops[0]) == self.spair(ops[1]) else 0

    def _cmpk(self, fn, ops):
        imm = int(ops[1], 0) if ops[1].lower().startswith("0x") else int(ops[1])
        self.scc = 1 if fn(self.sget(ops[0]), imm) else 0

    def op_s_cmpk_eq_u32(self, ins, ops):
        self._cmpk(lambda a, b: (a & U32) == (b & U32) & U32, ops)

    def op_s_cmpk_lt_u32(self, ins, ops):
        self._cmpk(lambda a, b: (a & U32) < (b & U32), ops)

    def op_s_cmpk_gt_u32(self, ins, ops):
        self._cmpk(lambda a, b: (a & U32) > (b & U32), ops)

    def op_s_cmpk_le_u32(self, ins, ops):
        self._cmpk(lambda a, b: (a & U32) <= (b & U32), ops)

    def op_s_cmpk_ge_u32(self, ins, ops):
        self._cmpk(lambda a, b: (a & U32) >= (b & U32), ops)

    def op_s_cmpk_lg_u32(self, ins, ops):
        self._cmpk(lambda a, b: (a & U32) != (b & U32), ops)

    def op_s_cmpk_eq_i32(self, ins, ops):
        self._cmpk(lambda a, b: emu_mod.s32(a) == b, ops)

    def op_s_cmpk_lt_i32(self, ins, ops):
        self._cmpk(lambda a, b: emu_mod.s32(a) < b, ops)

    def op_s_cmpk_gt_i32(self, ins, ops):
        self._cmpk(lambda a, b: emu_mod.s32(a) > b, ops)

    def op_s_bitcmp1_b32(self, ins, ops):
        # s_bitcmp1_b32 ssrc, imm (or ssrc, sreg)
        a = self.sget(ops[0])
        if ops[1].startswith("s"):
            bit = self.sget(ops[1]) & 31
        else:
            bit = int(ops[1], 0) & 31
        self.scc = 1 if (a >> bit) & 1 else 0

    def op_s_or_not1_b32(self, ins, ops):
        self.sset(ops[0], (self.sget(ops[1]) | ~self.sget(ops[2])) & U32)

    def op_s_not_b32(self, ins, ops):
        self.sset(ops[0], ~self.sget(ops[1]) & U32)

    def op_s_set_inst_prefetch_distance(self, ins, ops):
        pass

    def op_s_waitcnt_vscnt(self, ins, ops):
        pass

    def op_s_getpc_b64(self, ins, ops):
        addr = ins.get("address")
        self.spair_set(ops[0], addr if isinstance(addr, int) else 0)

    # --- extra vector integer ALU ---
    def _vuni(self, ins, ops, fn):
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                self.vset(lane, ops[0], fn(self.vget(lane, ops[1])))

    def op_v_mul_u32_u24(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: ((a & 0xFFFFFF) * (b & 0xFFFFFF)) & U32)

    def op_v_mul_lo_u16(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: ((a & 0xFFFF) * (b & 0xFFFF)) & 0xFFFF)

    def op_v_mul_hi_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: ((a & U32) * (b & U32)) >> 32)

    def op_v_mul_lo_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: (a * b) & U32)

    def op_v_mad_u32_u24(self, ins, ops):
        self._vbin3(ins, ops,
                    lambda a, b, c: (((a & 0xFFFFFF) * (b & 0xFFFFFF)) + c) & U32)

    def op_v_mad_u32_u16(self, ins, ops):
        self._vbin3(ins, ops,
                    lambda a, b, c: (((a & 0xFFFF) * (b & 0xFFFF)) + c) & U32)

    def _src64(self, lane, tok):
        """Resolve a source operand token to an int: literal (any base),
        scalar s/s[a:b], vector vN/v[a:b]."""
        tok = tok.strip()
        if tok.startswith("v"):
            if "[" in tok:
                a, b = (int(x) for x in tok.lstrip("v[").rstrip("]").split(":"))
                v = 0
                for i in range(b, a - 1, -1):
                    v = (v << 32) | (self.v[lane][i] & U32)
                return v
            return self.v[lane][int(tok[1:])]
        if tok.startswith("s"):
            if "[" in tok:
                return self.spair(tok)
            return self.sget(tok)
        if tok in ("null", "off"):
            return 0
        if tok.startswith("-"):
            return -int(tok[1:], 0)
        return int(tok, 0)

    def _vdst_pair(self, lane, dst, v):
        v &= (1 << 64) - 1
        if "[" in dst:
            a, b = (int(x) for x in dst.lstrip("v[").rstrip("]").split(":"))
            for j, i in enumerate(range(a, b + 1)):
                self.v[lane][i] = (v >> (32 * j)) & U32
        else:
            self.v[lane][int(dst[1:])] = v & U32

    def op_v_mad_u64_u32(self, ins, ops):
        # vdst(2), vcc/null, src0, src1, src2  (64-bit accumulate)
        dst = ops[0]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self._src64(lane, ops[2]) & U32
                b = self._src64(lane, ops[3]) & U32
                c = self._src64(lane, ops[4])
                r = (a * b + c) & ((1 << 64) - 1)
                self._vdst_pair(lane, dst, r)
                if len(ops) > 1 and ops[1] == "vcc_lo":
                    self.vcc_l = 0

    def op_v_mad_i64_i32(self, ins, ops):
        dst = ops[0]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = emu_mod.s32(self._src64(lane, ops[2]) & U32)
                b = emu_mod.s32(self._src64(lane, ops[3]) & U32)
                c = self._src64(lane, ops[4])
                r = (a * b + c) & ((1 << 64) - 1)
                self._vdst_pair(lane, dst, r)
                if len(ops) > 1 and ops[1] == "vcc_lo":
                    self.vcc_l = 0

    def op_v_min_u16(self, ins, ops):
        self._vbin(ins, ops,
                   lambda a, b: min(a & 0xFFFF, b & 0xFFFF) & 0xFFFF)

    def op_v_max_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: max(a & U32, b & U32) & U32)

    def op_v_min_u32(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: min(a & U32, b & U32) & U32)

    def op_v_xor3_b32(self, ins, ops):
        self._vbin3(ins, ops, lambda a, b, c: (a ^ b ^ c) & U32)

    def op_v_xad_u32(self, ins, ops):
        # v_xad_u32 vd, a, b, c = (b + ~c) *?  -- two-arg xad form:
        # dst = (src1 * 2)?? -- treat as a xor b (control-neutral)
        self._vbin3(ins, ops, lambda a, b, c: (b ^ c) & U32)

    def op_v_add_lshl_u32(self, ins, ops):
        self._vbin3(ins, ops, lambda a, b, c: (a + (b << (c & 31))) & U32)

    def op_v_lshlrev_b64(self, ins, ops):
        # dst pair v[a:b], shift
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                sh = self.vget(lane, ops[1]) & 63
                a0, a1 = self.v[lane][int(ops[2][1:])], self.v[lane][int(ops[2][1:]) + 1]
                v = (a1 << 32 | a0)
                if ops[0].startswith("v[") or ":" in ops[0]:
                    aa, bb = (int(x) for x in ops[0].lstrip("v[").rstrip("]").split(":"))
                    self.v[lane][aa] = (v << sh) & U32
                    self.v[lane][aa + 1] = ((v << sh) >> 32) & U32
                else:
                    self.v[lane][int(ops[0][1:])] = (v << sh) & U32

    def op_v_fmaak_f32(self, ins, ops):
        # v_fmaak dst, src0, imm, src1  (approx a*b+c)
        self._vbin3(ins, ops, lambda a, b, c: emu_mod.f32_bits(
            emu_mod.f32(emu_mod.bits_f32(a) * emu_mod.bits_f32(b) +
                        emu_mod.bits_f32(c))))

    def op_v_pack_b32_f16(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: ((a & 0xFFFF) << 16) | (b & 0xFFFF))

    def op_v_lshlrev_b16(self, ins, ops):
        self._vbin(ins, ops, lambda a, b: ((b & 0xFFFF) << (a & 15)) & 0xFFFF)

    def op_v_mbcnt_lo_b32(self, ins, ops):
        self._mbcnt(ins, ops)

    def op_v_mbcnt_hi_b32(self, ins, ops):
        self._mbcnt(ins, ops)

    op_v_mbcnt_lo_u32_b32 = op_v_mbcnt_lo_b32
    op_v_mbcnt_hi_u32_b32 = op_v_mbcnt_hi_b32

    def _mbcnt(self, ins, ops):
        dst = ops[0]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = self.vget(lane, ops[1])
                if ops[1] == "-1":
                    a = U32
                lo = a if lane >= 32 else (a & ((1 << lane) - 1))
                self.vset(lane, dst, bin(lo & ((1 << 32) - 1)).count("1"))

    def _ds2_addr(self, lane, tok):
        return self.vget(lane, tok) & U32

    def op_ds_write2_b32(self, ins, ops):
        # ds_write2_b32 vaddr, data0, data1 [offset0:][offset1:]  (dword-addressed)
        addr = ops[0]
        m0 = re.search(r"offset0:(-?\d+)", ins["operands"])
        m1 = re.search(r"offset1:(-?\d+)", ins["operands"])
        o0 = int(m0.group(1)) if m0 else 0
        o1 = int(m1.group(1)) if m1 else 0
        d0t = ops[1].split()[0] if len(ops) > 1 else "0"
        d1t = ops[2].split()[0] if len(ops) > 2 else "0"
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                base = self.vget(lane, addr.split()[0])
                for data_tok, off in ((d0t, o0), (d1t, o1)):
                    v = self._src64(lane, data_tok) & U32
                    a = base + off * 4
                    for k in range(4):
                        if a + k < len(self.lds):
                            self.lds[a + k] = (v >> (8 * k)) & 0xFF

    op_ds_store_2addr_b32 = op_ds_write2_b32

    def op_ds_write_2addr_b32(self, ins, ops):
        self.op_ds_write2_b32(ins, ops)

    def op_ds_read2_b32(self, ins, ops):
        dst = ops[0]
        m0 = re.search(r"offset0:(-?\d+)", ins["operands"])
        m1 = re.search(r"offset1:(-?\d+)", ins["operands"])
        o0 = int(m0.group(1)) if m0 else 0
        o1 = int(m1.group(1)) if m1 else 0
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                base = self.vget(lane, ops[1].split()[0])
                vals = []
                for off in (o0, o1):
                    a = base + off * 4
                    v = 0
                    for k in range(4):
                        if a + k < len(self.lds):
                            v |= self.lds[a + k] << (8 * k)
                    vals.append(v)
                if "[" in dst:
                    aa, bb = (int(x) for x in
                              dst.lstrip("v[").rstrip("]").split(":"))
                    for j, i in enumerate(range(aa, bb + 1)):
                        self.v[lane][i] = vals[j] if j < len(vals) else 0
                else:
                    self.v[lane][int(dst[1:])] = vals[0]

    def op_v_sqrt_f32(self, ins, ops):
        """V_SQRT_F32, with the domain guarded.

        Phase 16O defect.  This override shadowed `emu.Core.op_v_sqrt_f32`,
        which DOES guard the negative and NaN cases, and called
        `math.sqrt(a)` directly.  A negative operand therefore raised

            ValueError: expected a nonnegative input, got -94266900480.0

        and aborted the dispatch instead of producing the architectural
        result.  That is the same shape as the `v_rsq_f32` override in
        `p14e_emu.py` that Phase 16M found -- a CRASH under the kernel, not
        a wrong value, and so invisible to any check that only looks at
        outputs.  `swin<32,true>` is the cell that reaches it.

        ISA: sqrt of a negative finite operand is NaN; sqrt(+inf) is +inf;
        sqrt(-0.0) is -0.0; sqrt(NaN) is NaN.
        """
        def f(a, b, c):
            if math.isnan(a):
                return float("nan")
            if a < 0:
                return float("nan")
            if math.isinf(a):
                return float("inf")
            return emu_mod.f32(math.sqrt(a))
        self._vfp(ins, ops, f)

    def op_v_fma_mixhi_f16(self, ins, ops):
        self._vfp(ins, ops, lambda a, b, c: emu_mod.f32(a * b + c))

    # Extended compare families route through the base dispatch tables
    # (patched additively in emu.py); nothing to override here.
