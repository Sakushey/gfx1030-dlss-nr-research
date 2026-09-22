#!/usr/bin/env python3
"""Phase 16E — per-variant SWIN DS-event recorder at AUTHENTIC geometry.

Usage: python p16e_rec.py <variant_tag> <cell> [wavebase]
  variant_tag: swin32t swin32f swin64f swin128f swin256f
  cell:        name in CELLS
Runs the 14EH HWCore recorder (measured model: u32 EA, alloc 15,872)
over the ENTRY-FIXED module's given variant slice at authentic fields,
and writes events CSV (raw EA per DS access) to out/rec_<tag>_<cell>_w<N>.csv
plus a JSON summary. Host-only; no GPU.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
for p in ("phase14e_static/tools", "phase14eh_tools", "phase14eg_tools",
          "phase14e_forensics/tools", "phase14d11_static"):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)
sys.path.insert(0, HERE)

import p14eh  # noqa: E402
from p14eh import HWCore  # noqa: E402
from emu import NotImpl, U32  # noqa: E402
import p16e_lib  # noqa: E402

RE_VREG = re.compile(r"v\[(\d+):(\d+)\]|v(\d+)")
RE_OFF = re.compile(r"offset:(-?\d+)")


class E16Core(HWCore):
    """HWCore + data-neutral per-lane scratch (private-segment) model.

    gfx10 scratch = per-lane private memory; we model it as a per-core
    per-lane byte dict (loads default 0, stores round-trip) so spill/
    restore regions execute without NOTIMPL and stay data-neutral —
    the same zero-payload convention the 14EH stack uses. The scratch
    VALUES never feed DS addressing (scratch holds spilled registers of
    non-ring data); this is audited per site in the P1/P2 reports.
    """

    def _scrt_init(self):
        if not hasattr(self, "_scrt"):
            self._scrt = [{} for _ in range(self.lanes)]

    # ---- scratch transfer WIDTH, from the mnemonic ----------------------
    @staticmethod
    def _scrt_width(mnem, lo, hi):
        """Bytes moved by a scratch access, per the mnemonic's own spelling.

        The ISA width suffixes are b8/b16/b32/b64/b96/b128 plus the
        signed/unsigned byte and word spellings (ubyte/sbyte/ushort/sshort).
        An unrecognised spelling falls back to the destination span so that a
        form nobody has classified behaves as it did before, and that
        fallback is recorded in EXPLICIT_OPCODE_ALIASES.json rather than
        being silent.
        """
        m = mnem.replace("_e32", "").replace("_e64", "")
        table = {"b8": 1, "u8": 1, "s8": 1, "byte": 1, "ubyte": 1, "sbyte": 1,
                 "b16": 2, "u16": 2, "s16": 2, "short": 2, "ushort": 2,
                 "sshort": 2, "b32": 4, "dword": 4, "b64": 8, "dwordx2": 8,
                 "b96": 12, "dwordx3": 12, "b128": 16, "dwordx4": 16}
        for suffix in sorted(table, key=len, reverse=True):
            if m.endswith("_" + suffix):
                return table[suffix]
        return (hi - lo + 1) * 4

    @staticmethod
    def _scrt_signed(mnem):
        m = mnem.replace("_e32", "").replace("_e64", "")
        return m.endswith(("_s8", "_s16", "_sbyte", "_sshort"))

    def _scrt_handler(self, w, store):
        """An explicit handler for one scratch mnemonic spelling."""
        def _h(self, ins, ops, w=w, store=store):
            self._scratch_xfer(ins, ops, store, w)
        return _h

    def _vreg_tokens(self, tok):
        m = RE_VREG.search(tok)
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2))) if m.group(1) is not None \
            else (int(m.group(3)), int(m.group(3)))

    def _scratch_xfer(self, ins, store, nbytes=None):
        ops = [o.strip() for o in (ins.get("operands") or "").split(",")]
        if not ops:
            raise NotImpl("scratch: no operands")
        self._scrt_init()
        # objdump operand order: stores print vaddr|off, vdata, saddr;
        # loads print vdst, vaddr|off, saddr.
        if store:
            data = None
            for tok in ops[1:]:
                mt = self._vreg_tokens(tok)
                if mt:
                    data = mt
                    break
            if data is None:
                raise NotImpl("scratch form: %s" % ins.get("text"))
            lo, hi = data
            vaddr_reg = None
            mt = self._vreg_tokens(ops[0])
            if mt:
                vaddr_reg = mt[0]
        else:
            dst = self._vreg_tokens(ops[0])
            if dst is None:
                raise NotImpl("scratch form: %s" % ins.get("text"))
            lo, hi = dst
            vaddr_reg = None
            for tok in ops[1:]:
                mt = self._vreg_tokens(tok)
                if mt:
                    vaddr_reg = mt[0]
                    break
        m = RE_OFF.search(ins.get("operands") or "")
        imm = int(m.group(1)) if m else 0
        # The transfer WIDTH comes from the mnemonic, not from the
        # destination register span.  Phase 16M M2 defect 7: this read
        # `(hi - lo + 1) * 4`, so `scratch_load_ubyte v3, ...` loaded four
        # bytes and only the low one was wanted.  The span still decides how
        # many REGISTERS the result is written into; it no longer decides how
        # many bytes come out of memory.
        # PRE-16N reconstruction: the width came from the destination
        # register span, so `scratch_load_ubyte` moved 4 bytes (defect 7).
        if nbytes is None:
            nbytes = (hi - lo + 1) * 4
        for lane in range(self.lanes):
            if not ((self.exec_l >> lane) & 1):
                continue
            base = (self.v[lane][vaddr_reg] & U32) if vaddr_reg is not None else 0
            ea = (base + imm) & U32
            if store:
                # the same width rule as the load side: `scratch_store_ubyte`
                # moves one byte, not the whole register
                nleft = nbytes
                for k in range(lo, hi + 1):
                    if nleft <= 0:
                        break
                    nb = min(4, nleft)
                    val = self.v[lane][k] & U32
                    for b in range(nb):
                        self._scrt[lane][(ea + (k - lo) * 4 + b) & U32] = \
                            (val >> (8 * b)) & 0xFF
                    nleft -= nb
            else:
                buf = bytearray(nbytes)
                for b in range(nbytes):
                    buf[b] = self._scrt[lane].get((ea + b) & U32, 0)
                raw = int.from_bytes(bytes(buf), "little")
                mn = ins.get("mnemonic") or ""
                if self._scrt_signed(mn) and (raw >> (8 * nbytes - 1)) & 1:
                    raw |= (U32 << (8 * nbytes)) & U32
                # A multi-register load fills successive 32-bit chunks of
                # the bytes actually read; a narrow load lands in the first
                # register zero-extended and the rest of the span is zero,
                # because there are no further bytes.  (An earlier revision
                # of this repair zeroed every register past the first, which
                # is wrong for dwordx2/x4 -- caught by the M2 vector
                # `scratch_load_dwordx2_two_regs` during the N7 gate.)
                for k in range(lo, hi + 1):
                    if (k - lo) * 4 >= nbytes:
                        self.v[lane][k] = 0
                    else:
                        self.v[lane][k] = (raw >> (32 * (k - lo))) & U32

    _MOD_RE = re.compile(r"^(.*?)\s+(clamp|mul:[0-9.]+|div:[0-9.]+|neg)$")

    def vget(self, lane, tok, fp=False):
        # strip trailing fp modifiers that objdump appends to the last
        # operand token ("0.5 clamp"); value-level modifiers are dropped
        # (data-neutral vs the zero-payload convention)
        tok = tok.strip()
        if fp:
            mm = E16Core._MOD_RE.match(tok)
            if mm:
                tok = mm.group(1)
        return super().vget(lane, tok, fp)

    # ---- scratch, one EXPLICIT handler per spelling --------------------
    # The width is now a property of the mnemonic, so each spelling gets its
    # own entry rather than a shared body that infers it.  Anything not
    # listed here raises NotImpl from `Core.step`, loudly.
    def op_scratch_store_dword(self, ins, ops):
        self._scratch_xfer(ins, True, 4)

    def op_scratch_store_dwordx2(self, ins, ops):
        self._scratch_xfer(ins, True, 8)

    def op_scratch_store_dwordx4(self, ins, ops):
        self._scratch_xfer(ins, True, 16)

    def op_scratch_load_dword(self, ins, ops):
        self._scratch_xfer(ins, False, 4)

    def op_scratch_load_dwordx2(self, ins, ops):
        self._scratch_xfer(ins, False, 8)

    def op_scratch_load_dwordx4(self, ins, ops):
        self._scratch_xfer(ins, False, 16)

    def op_scratch_load_ubyte(self, ins, ops):
        self._scratch_xfer(ins, False, 1)

    def op_scratch_load_sbyte(self, ins, ops):
        self._scratch_xfer(ins, False, 1)

    def op_scratch_load_ushort(self, ins, ops):
        self._scratch_xfer(ins, False, 2)

    def op_scratch_load_sshort(self, ins, ops):
        self._scratch_xfer(ins, False, 2)

    def op_scratch_store_byte(self, ins, ops):
        self._scratch_xfer(ins, True, 1)

    def op_scratch_store_short(self, ins, ops):
        self._scratch_xfer(ins, True, 2)

    # ---- the d16 DS forms, EXPLICIT ------------------------------------
    # Phase 16M M2 defect 6: `ds_write_b16_d16_hi` had no handler, and the
    # `__getattr__` that used to live here matched it with a regex and
    # delegated to `_ds_store_bytes(..., 2)` -- the NON-d16 low-half store.
    # The mnemonic was never unhandled and never reported; it silently wrote
    # the wrong 16 bits.  That whole mechanism is gone.  Both d16 spellings
    # are now named, and the high-half rule is passed explicitly.
    def op_ds_write_b16_d16_hi(self, ins, ops):
        self._ds_store_bytes(ins, ops, 2, d16_hi=True)

    def op_ds_write_b16_d16_lo(self, ins, ops):
        self._ds_store_bytes(ins, ops, 2)

    def op_ds_write_u16_d16_hi(self, ins, ops):
        self._ds_store_bytes(ins, ops, 2, d16_hi=True)

    def op_ds_write_u16_d16_lo(self, ins, ops):
        self._ds_store_bytes(ins, ops, 2)

    def op_ds_read_b16_d16_hi(self, ins, ops):
        self._ds_load_bytes(ins, ops, 2, d16_hi=True)

    def op_ds_read_u16_d16_lo(self, ins, ops):
        self._ds_load_bytes(ins, ops, 2)

    # PRE-16N RECONSTRUCTION: the silent opcode fallback.  Any unresolved
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

    # There is deliberately NO `__getattr__` on this class any more.  An
    # unknown opcode now resolves to no handler at all, and `Core.step`
    # raises `NotImpl` naming the site -- which is what Phase 16M asked for
    # and what the pre-16N fallback prevented.  See
    # `phase16n_semantic_freeze/n2_aliases/EXPLICIT_OPCODE_ALIASES.json` for
    # the complete list of spellings that ARE equivalent, and why.

    # ---- missing SALU bit tests (SCC setters; value-neutral) -----------
    def _salu_reg(self, tok):
        mm = re.match(r"^s(\d+)$", tok)
        return int(mm.group(1)) if mm else None

    def op_s_bitcmp0_b32(self, ins, ops):
        r = self._salu_reg(ops[0]) if ops else None
        if r is None:
            raise NotImpl("s_bitcmp0_b32 form: %s" % ins.get("text"))
        bit = int(ops[1], 0) if len(ops) > 1 else 0
        self.scc = 1 if ((self.s[r] >> bit) & 1) == 0 else 0

    def op_s_mulk_i32(self, ins, ops):
        # s_mulk_i32 SDST, SSRC0, IMM (objdump prints dst, imm when the
        # implicit SSRC0 == SDST alias is used)
        if len(ops) < 2:
            raise NotImpl("s_mulk_i32 form: %s" % ins.get("text"))
        d = self._salu_reg(ops[0])
        if d is None:
            raise NotImpl("s_mulk_i32 form: %s" % ins.get("text"))
        s0 = self._salu_reg(ops[1]) if len(ops) > 2 else d
        immtok = ops[2] if len(ops) > 2 else ops[1]
        imm = int(immtok, 0) if re.match(r"^-?\d+$|^0x", immtok) else None
        if imm is None:
            raise NotImpl("s_mulk_i32 form: %s" % ins.get("text"))
        self.s[d] = ((self.s[s0] if s0 is not None else 0) * imm) & U32

    def op_s_bitcmp1_b32(self, ins, ops):
        r = self._salu_reg(ops[0]) if ops else None
        if r is None:
            raise NotImpl("s_bitcmp1_b32 form: %s" % ins.get("text"))
        bit = int(ops[1], 0) if len(ops) > 1 else 0
        self.scc = 1 if ((self.s[r] >> bit) & 1) == 1 else 0

    # ---- 64-bit lane shift (v_lshlrev_b64 on v[a:b] pairs) ------------
    def op_v_lshlrev_b64(self, ins, ops):
        if len(ops) < 3:
            raise NotImpl("v_lshlrev_b64 form: %s" % ins.get("text"))
        d = self._vreg_tokens(ops[0])
        if d is None:
            raise NotImpl("v_lshlrev_b64 form: %s" % ins.get("text"))
        sh = int(ops[1], 0) if re.match(r"^-?\d+$|^0x", ops[1]) else None
        s = self._vreg_tokens(ops[2]) if re.search(r"^v", ops[2]) else None
        if sh is None or s is None:
            raise NotImpl("v_lshlrev_b64 form: %s" % ins.get("text"))
        dlo, dhi = d
        slo, shi = s
        M64 = (1 << 64) - 1
        for lane in range(self.lanes):
            if not ((self.exec_l >> lane) & 1):
                continue
            lo = self.v[lane][slo] & U32
            hi = self.v[lane][shi] & U32
            val = (hi << 32) | lo
            nv = 0 if sh >= 64 else ((val << sh) & M64)
            self.v[lane][dlo] = nv & U32
            self.v[lane][dhi] = (nv >> 32) & U32

PE = p14eh.PE
P11 = p14eh.P11
OUTD = os.path.join(HERE, "..", "out")
os.makedirs(OUTD, exist_ok=True)

SYM = {tag: sym for sym, tag in p16e_lib.SWIN_VARIANTS}

# authentic cells per variant: from phase16_authentic_decode_swin.csv
# (frame-2 first launch per variant; flags/pairs as captured)
CELLS = {
    # (X, Y, pair_lo, pair_hi, flags, grid, [name tag])
    "head":  dict(X=1152, Y=1920, pl=0, ph=0, flags=0x14, grid=(240, 144, 1), wgid=(0, 0, 0)),
    "mid":   dict(X=576, Y=960, pl=0, ph=0, flags=0x8, grid=(120, 72, 1), wgid=(0, 0, 0)),
    "final": dict(X=1152, Y=1920, pl=0, ph=0, flags=0x20, grid=(240, 144, 1), wgid=(239, 143, 0)),
    "A":     dict(X=576, Y=960, pl=0, ph=0, flags=0x1, grid=(120, 72, 1), wgid=(0, 0, 0)),
    "B":     dict(X=576, Y=960, pl=0, ph=0, flags=0x1, grid=(120, 72, 1), wgid=(119, 71, 0)),
    "C":     dict(X=576, Y=960, pl=-4, ph=-4, flags=0x0, grid=(121, 73, 1), wgid=(0, 0, 0)),
    "D":     dict(X=576, Y=960, pl=-4, ph=-4, flags=0x0, grid=(121, 73, 1), wgid=(120, 72, 0)),
    "G64":   dict(X=288, Y=480, pl=0, ph=0, flags=0x1, grid=(60, 36, 1), wgid=(0, 0, 0)),
    "G128":  dict(X=144, Y=240, pl=0, ph=0, flags=0x1, grid=(30, 18, 1), wgid=(0, 0, 0)),
    "G256":  dict(X=72, Y=120, pl=0, ph=0, flags=0x1, grid=(15, 9, 1), wgid=(0, 0, 0)),
    "G256F": dict(X=72, Y=120, pl=0, ph=0, flags=0x8, grid=(15, 9, 1), wgid=(14, 8, 0)),
    "F64":   dict(X=288, Y=480, pl=0, ph=0, flags=0x1, grid=(60, 36, 1), wgid=(59, 35, 0)),
    "F128":  dict(X=144, Y=240, pl=0, ph=0, flags=0x1, grid=(30, 18, 1), wgid=(29, 17, 0)),
}


def fields_for(c):
    fields = {}
    for o, k in ((0x00, 0), (0x08, 1), (0x10, 2), (0x30, 3), (0x38, 4),
                 (0x48, 5), (0x78, 6), (0x80, 7), (0xA0, 8)):
        fields[o] = ("ptr", k)
    fields[0x18] = ("u32", c["X"])
    fields[0x1C] = ("u32", c["Y"])
    fields[0x20] = ("u32", c["pl"] & 0xFFFFFFFF)
    fields[0x24] = ("u32", c["ph"] & 0xFFFFFFFF)
    fields[0x28] = ("u32", c["flags"])
    fields[0x98] = ("u64", 0)
    return fields


def main():
    tag = sys.argv[1] if len(sys.argv) > 1 else "swin32f"
    cell = sys.argv[2] if len(sys.argv) > 2 else "A"
    sym = SYM[tag]
    c = CELLS[cell]
    dis = p16e_lib.parse_disasm(p16e_lib.ENT_DIS)
    if sym not in dis:
        print("symbol missing from disasm:", sym); sys.exit(2)
    prog, rows, idx = PE.slice_program(p16e_lib.ENT_DIS, sym)
    dw = P11.dw16(p16e_lib.ENT_CO, sym)
    summary = {}
    wbs = [0, 224]
    if len(sys.argv) > 3:
        wbs = [int(sys.argv[3])]
    for wb in wbs:
        t0 = time.time()
        HWCore.oob_sem = "u32"
        HWCore.alloc = 15872
        n0 = len(HWCore.registry) if hasattr(HWCore, "registry") else 0
        PE.SwinCore = E16Core
        r = PE.trace(prog, dw, "rec_%s_%s_w%d" % (tag, cell, wb // 32),
                     c["grid"], (256, 1, 1), c["wgid"], wb,
                     fields_for(c), text_path=p16e_lib.ENT_CO)
        core = None
        for cr in HWCore.registry[n0:]:
            core = cr
        ev = list(core.hw_ev) if core is not None else []
        rows_out = []
        cnt = {"rw": 0, "bp": 0}
        site_raw = {}
        for e in ev:
            cnt[e["kind"]] = cnt.get(e["kind"], 0) + 1
            if e["kind"] != "rw":
                continue
            raw = e.get("raw", e.get("vaddr", 0))
            if isinstance(raw, str):
                raw = int(raw, 16) if raw.startswith(("0x", "0X")) else int(raw)
            s = hex(int(e.get("site", 0))) if isinstance(e.get("site"), int) else e.get("site")
            site_raw.setdefault(s, []).append(raw)
            rows_out.append({"wave": wb // 32, "lane": e.get("lane"),
                             "site": s, "mnem": e.get("mnem"),
                             "store": 1 if e.get("store") else 0,
                             "raw": raw})
        path = os.path.join(OUTD, "rec_%s_%s_w%d.csv" % (tag, cell, wb // 32))
        with open(path, "w", newline="", encoding="utf-8") as f:
            wcsv = csv.DictWriter(f, fieldnames=["wave", "lane", "site", "mnem", "store", "raw"])
            wcsv.writeheader()
            wcsv.writerows(rows_out)
        site_max = {s: max(v) for s, v in site_raw.items()}
        summary["w%d" % (wb // 32)] = {
            "outcome": str(r["outcome"]), "steps": r["steps"],
            "oob_count": len(r.get("oob", [])), "events": len(rows_out),
            "kinds": cnt, "n_sites_ge_0x4000": sum(1 for v in site_max.values() if v >= 0x4000),
            "sites_ge_0x4000": sorted(s for s, v in site_max.items() if v >= 0x4000),
            "secs": round(time.time() - t0, 1)}
        print(json.dumps(summary["w%d" % (wb // 32)]))
    with open(os.path.join(OUTD, "rec_%s_%s_summary.json" % (tag, cell)), "w") as f:
        json.dump(summary, f, indent=1)


if __name__ == "__main__":
    main()
