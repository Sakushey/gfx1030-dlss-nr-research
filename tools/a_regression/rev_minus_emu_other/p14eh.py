"""Phase 14E-H — MODEL_HW_GFX1030 host tooling (zero GPU).

One core class (HWCore) that:
  * keeps the validated legacy value semantics available
    (oob_sem='legacy': effective = (vaddr+imm) & 0x3FFF over the 16-KiB
    working image -- reproduces the Phase 14E-G numbers exactly), and
  * implements the hardware-faithful RDNA2 model
    (oob_sem='u32' | 'trunc16'): DS EA arithmetic at exact operand width
    with uint32 wrap BEFORE range checking, per-form immediate semantics
    (byte offsets for single-address forms; offset0/offset1 scaled by 8
    for read2/write2/2addr b64 forms), allocation hypothesis parameter
    (default 16,384 B), and RDNA2 OOB behavior (read -> zero,
    write -> discarded, MEMVIOL event recorded; never traps -- see
    phase14eh_memviol_semantics.md).

Every DS event is recorded per active lane with: kind (rw/bp), direction,
site/PC, mnemonic, ADDR VGPR index, ADDR value u32, immediate (with
scaling note), raw u32 EA, trunc16 EA, width, per-allocation-hypothesis
in-range flags and model behavior -- the input for the phase CSVs.

Driver: run_workgroup_hw() = copy of the validated Phase 14E-F7/F8
workgroup driver (wg_emu.run_workgroup) parameterized by core factory and
LDS image size; legacy-parameter runs must reproduce F7/F8 numbers
(13,077 ticks / 9,175 ticks, 14 epochs) as a parity gate.
"""
from __future__ import annotations

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
OUTD = os.path.join(HERE, "out")
for p in (HERE, os.path.join(ROOT, "phase14e_static", "tools"),
          os.path.join(ROOT, "phase14e_forensics", "tools"),
          os.path.join(ROOT, "phase14d8_static", "tools"),
          os.path.join(ROOT, "phase8_static", "tools"),
          os.path.join(ROOT, "phase14d_static", "tools"),
          os.path.join(ROOT, "phase14d11_static", "tools"),
          os.path.join(ROOT, "phase14eg_tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import p14e_emu as PE                      # noqa: E402
import p14e_emu_g as G                     # noqa: E402
import p14d11_emu as P11                   # noqa: E402
import wg_emu as WG                       # noqa: E402  (also patches emu.f32)
import p14e_emu as E                       # noqa: E402
from emu import Halt, NotImpl, U32          # noqa: E402

KERNEL = PE.KERNEL
LDS_PART = PE.LDS_PART
ALLOC_HYPS = (15872, 16384, 65536)          # 512-B carve | 1-KiB-hyp | CU

# ---------------------------------------------------------------------------
# per-form DS operand / immediate semantics (ISA form table)
# ---------------------------------------------------------------------------

# width from mnemonic (byte count of ONE access)
def _w_from_mnem(m):
    if "128" in m or "x4" in m:
        return 16
    if "64" in m or "x2" in m:
        return 8
    if "32" in m:
        return 4
    if "16" in m:
        return 2
    return 1


PAIR_RE = re.compile(r"offset([01]):(-?\d+)")
OFF_RE = re.compile(r"offset:(-?0x[0-9a-fA-F]+|-?\d+)")


def ds_form(mnem, ops_raw):
    """Return a form descriptor for one ds instruction text.

    out: dict(kind='rw'|'bp', store=bool, w=int,
              imm_note=str, accesses=[(reg_idx, imm_bytes) ...],
              reg_idx)  -- imm_bytes already scaled to bytes.
    For bpermute, accesses carries [(src_lane_reg, 0)] semantics note and
    kind='bp' (not an LDS-memory access). For rw forms the access list is
    the exact ISA access set (single-address: [imm]; read2/2addr pairs:
    [offset0*8, offset1*8]).
    """
    olist = [o.strip() for o in ops_raw.split(",")] if ops_raw else []
    # operands may carry a trailing " offset:..." text on the last token;
    # the register is the first whitespace word of each comma token.
    vtoks = [o.split()[0] for o in olist
             if re.match(r"^v\d+$", o.split()[0])]
    is_load = ("load" in mnem or "read" in mnem)
    is_store = ("store" in mnem or "write" in mnem)
    w = _w_from_mnem(mnem)
    if mnem == "ds_bpermute_b32":
        n = int(vtoks[-1][1:]) if vtoks else None
        return {"kind": "bp", "store": False, "w": 4, "imm_note": "src-lane",
                "accesses": [(n, 0)], "addr_reg": n}
    if mnem.startswith("ds_") and (is_load or is_store):
        a_tok = vtoks[-1] if is_load else vtoks[0]
        n = int(a_tok[1:]) if a_tok else None
        m1 = PAIR_RE.search(ops_raw)  # offset0:/offset1: pair form
        if "read2" in mnem or "write2" in mnem or "2addr" in mnem:
            o0 = int(m1.group(2)) if m1 and m1.group(1) == "0" else 0
            m2 = re.search(r"offset1:(-?\d+)", ops_raw)
            o1 = int(m2.group(1)) if m2 else 0
            unit = 8 if ("64" in mnem or "x2" in mnem) else 4
            return {"kind": "rw", "store": is_store, "w": w,
                    "imm_note": f"pair {unit}B-units",
                    "accesses": [(n, o0 * unit), (n, o1 * unit)],
                    "addr_reg": n}
        mo = OFF_RE.search(ops_raw)
        imm = int(mo.group(1), 0) if mo else 0
        return {"kind": "rw", "store": is_store, "w": w,
                "imm_note": "bytes", "accesses": [(n, imm)],
                "addr_reg": n}
    return None


# ---------------------------------------------------------------------------
# bounded / aggregating record containers
# ---------------------------------------------------------------------------
class AggRecords:
    """Drop-in for one of `HWCore`'s unbounded per-access record lists.

    THE LEAK THIS EXISTS FOR

    `hw_ev` takes one dict per active-lane LDS access and `ds_ops` one tuple
    per DS operation; neither is drained inside a case.  Measured in Phase
    16I: 366,592 `hw_ev` records / 168.59 MB for a single 9,933-tick
    baseline, i.e. ~37 records per tick.  A case that reaches the default
    `per_wave_step_cap` of 3,000,000 therefore reaches tens of GB on its
    own -- which is what killed the first two perturbation re-derivations
    (RSS 15 GB, access violation, zero bytes of output).

    `AggRecords` keeps an EXACT `len()` and an EXACT append count, and by
    default stores nothing.  Everything `run_workgroup_hw` reports about
    these lists is a count, so the aggregation is result-neutral for it by
    construction.  A consumer that needs the records themselves must either
    leave `agg_lds` off (the default) or ask for a bounded prefix sample.

    Truncation is never silent: `n_dropped` is carried in `summary()`.
    """

    __slots__ = ("n", "cap", "sample", "sink")

    def __init__(self, cap=0, sink=None):
        self.n = 0
        self.cap = int(cap or 0)
        self.sample = [] if self.cap else None
        self.sink = sink

    def append(self, rec):
        self.n += 1
        if self.sample is not None and len(self.sample) < self.cap:
            self.sample.append(rec)
        if self.sink is not None:
            self.sink(rec)

    def __len__(self):
        return self.n

    def __bool__(self):
        return self.n > 0

    def __iter__(self):
        return iter(self.sample if self.sample is not None else ())

    def __getitem__(self, i):
        return (self.sample if self.sample is not None else [])[i]

    @property
    def n_dropped(self):
        return self.n - len(self.sample or ())

    def summary(self):
        return {"n": self.n, "sample_cap": self.cap,
                "n_sampled": len(self.sample or ()),
                "n_dropped": self.n_dropped}


# ---------------------------------------------------------------------------
# HW core
# ---------------------------------------------------------------------------
class HWCore(WG.WG_SwinCore):
    """WG_SwinCore + hardware-faithful DS model + per-event recorder.

    Class-level run parameters (set before constructing cores):
      oob_sem: 'legacy' (value path = &0x3FFF, reproduces 14EG numbers)
               'u32'    (final EA = uint32(vaddr+imm), no artificial mask)
               'trunc16'(final EA = (uint32(...)) & 0xFFFF, 64-KiB datapath)
      alloc:   allocation hypothesis in bytes (in-range: ea+w <= alloc)
      lds_img: value LDS image size (always >= alloc; 0x10000 in this tool)
    """

    oob_sem = "legacy"
    alloc = 16384
    lds_img = 0x10000
    registry = []
    # Class flag: replace hw_ev / hw_memviol / ds_ops with exact-count
    # aggregators.  Default False, so nothing that reads the records changes
    # behaviour; `run_workgroup_hw(agg_lds=True)` turns it on for a driver
    # that reads only counts.  NOT flipped globally on purpose: p16e_rec.py
    # (frozen) and p8_diff_emu.py (frozen) both iterate the records, and
    # p16f_mirror.py reads them too.
    agg_lds = False
    agg_sample_cap = 512

    def __init__(self, *a, **k):
        # WG_SwinCore inherits Core.__init__(...); lds_size kw must produce
        # the model image size; enlarge if the caller passed the legacy one.
        lds = k.pop("lds_size", None)
        if lds is not None and lds >= HWCore.lds_img:
            k["lds_size"] = lds
        else:
            k["lds_size"] = HWCore.lds_img
        super().__init__(*a, **k)
        if HWCore.agg_lds:
            cap = HWCore.agg_sample_cap
            self.hw_ev = AggRecords(cap=cap)
            self.hw_memviol = AggRecords(cap=cap)
            self.ds_ops = AggRecords(cap=cap)
        else:
            self.hw_ev = []          # one dict per active lane access
            self.hw_memviol = []     # rw events with final EA outside alloc
        self.hw_oob_read_zero = 0
        self.hw_oob_write_discard = 0
        # exact per-kind event counts, kept beside the lists so the driver's
        # n_rw/n_bp stay exact whether the lists record or aggregate
        self.n_ev_rw = 0
        self.n_ev_bp = 0
        HWCore.registry.append(self)

    @classmethod
    def reset_registry(cls):
        """Release every core the class is holding alive.

        `HWCore.registry` is a CLASS attribute that `__init__` appends to
        and nothing drains, so a run that builds one core per case retains
        every case's core.  Callers that only need the cores they have just
        built read `registry[n0:]`; the ones that are finished with them
        must say so explicitly, which is what this is for.
        """
        cls.registry = []

    # ---- EA layer ------------------------------------------------------
    def _ea(self, lane, reg_idx, imm_bytes, w):
        """raw = uint32(VGPR[ADDR] + imm) computed AT 32-BIT WIDTH (the
        u32 wrap happens BEFORE any range check); final EA per datapath
        hypothesis; in_range against the allocation hypothesis. Returns
        (raw, final_ea, in_range)."""
        if reg_idx is None:
            return None, None, False
        v = self.v[lane][reg_idx] & U32
        raw = (v + imm_bytes) & U32                 # u32 wrap first
        if self.oob_sem == "legacy":
            ea = raw & 0x3FFF                       # 16-KiB working image
        elif self.oob_sem == "trunc16":
            ea = raw & 0xFFFF                       # 64-KiB LDS datapath
        else:                                       # 'u32': no truncation
            ea = raw
        # legacy value model's image is 16,384 B: in-range mirrors the
        # historical (masked) bound exactly so parity runs stay identical.
        limit = 0x4000 if self.oob_sem == "legacy" else HWCore.alloc
        in_range = (ea is not None and 0 <= ea and ea + w <= limit)
        return raw, ea, in_range

    def _record_ds(self, ins):
        """Recorder (called pre-step by RecCore.step). Emulates the GCore
        row coverage/order exactly (active lane x access, kind rw/bp) but
        computes per-form corrected EAs. Also appends the legacy ds_ops
        aggregate tuples so E.trace-style analysis stays sane."""
        mnem = ins["mnemonic"]
        ops_raw = ins.get("operands") or ""
        f = ds_form(mnem, ops_raw)
        if f is None:
            return
        if f["addr_reg"] is None:
            return
        w = f["w"]
        store = f["store"]
        site = ins.get("address")
        dp_mask = 0xFFFF if self.oob_sem == "trunc16" else U32
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                for (n, imm) in f["accesses"]:
                    raw, ea, ok = self._ea(lane, n, imm, w)
                    if raw is None:
                        continue
                    if f["kind"] == "rw":
                        self.ds_ops.append((store, (raw & 0x3FFF), w, site))
                        ea_dp = raw & dp_mask
                        rec = {"kind": "rw", "store": store, "w": w,
                               "site": site, "mnem": mnem, "lane": lane,
                               "addr_reg": n, "vaddr": self.v[lane][n] & U32,
                               "imm": imm, "imm_note": f["imm_note"],
                               "raw": raw, "ea16": raw & 0xFFFF,
                               "ea_u32": raw,
                               "a15872": ea_dp + w <= 15872,
                               "a16384": ea_dp + w <= 16384,
                               "a65536": ea_dp + w <= 65536,
                               "in_alloc": ok}
                        if not ok:
                            self.hw_memviol.append(rec)
                            if store:
                                self.hw_oob_write_discard += 1
                            else:
                                self.hw_oob_read_zero += 1
                        self.n_ev_rw += 1
                        self.hw_ev.append(rec)
                    else:
                        self.n_ev_bp += 1
                        self.hw_ev.append({"kind": "bp", "store": False,
                                           "w": 4, "site": site,
                                           "mnem": mnem, "lane": lane,
                                           "addr_reg": f["addr_reg"],
                                           "vaddr": self.v[lane]
                                           [f["addr_reg"]] & U32,
                                           "imm": 0, "imm_note": "src-lane",
                                           "raw": 0, "ea16": 0,
                                           "ea_u32": 0})

    # ---- unified DS value ops (byte-transfer identical to the validated
    # legacy bodies for in-range accesses; RDNA2 OOB: read zero / write
    # discard) -----------------------------------------------------------
    def _xfer(self, ins, ops, nbytes, store, d16_hi=False):
        ops_raw = ins.get("operands") or ""
        f = ds_form(ins["mnemonic"], ops_raw)
        if f is None:
            raise NotImpl(f"ds form: {ins['text']}")
        dst_or_data = ops[0]
        # loads: dst = ops[0]; stores: addr = ops[0]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                for (n, imm) in f["accesses"]:
                    raw, ea, ok = self._ea(lane, n, imm, nbytes)
                    if f["kind"] == "bp":
                        continue
                    if not ok or ea is None:
                        # RDNA2 OOB: read zero, write discarded
                        if not store:
                            self._oob_zero_lane(lane, ops, nbytes, d16_hi)
                        continue
                    if store:
                        self._byte_store(lane, ea, ops, nbytes, d16_hi)
                    else:
                        self._byte_load(lane, ea, ops, nbytes, d16_hi)

    def _oob_zero_lane(self, lane, ops, nbytes, d16_hi):
        dst = ops[0]
        if "[" in dst:
            aa, bb = (int(x) for x in dst.lstrip("v[").rstrip("]")
                      .split(":"))
            for i in range(aa, min(bb, aa + nbytes // 4 - 1) + 1):
                self.v[lane][i] = 0
        elif d16_hi:
            self.v[lane][int(dst[1:])] &= 0xFFFF
        else:
            self.v[lane][int(dst[1:])] = 0

    def _byte_store(self, lane, ea, ops, nbytes, d16_hi=False):
        data_tok = ops[1].split()[0] if len(ops) > 1 else None
        if data_tok is None:
            return
        if "[" in data_tok:
            aa, bb = (int(x) for x in
                      data_tok.lstrip("v[").rstrip("]").split(":"))
            dvals = [self.v[lane][i] for i in range(aa, bb + 1)]
        else:
            dvals = [self.v[lane][int(data_tok[1:])]]
        if d16_hi and dvals:
            # `_d16_hi` selects the HIGH 16 bits of VDATA -- symmetric with
            # `_byte_load` above, which already merged into the high half.
            # The pre-16N store path had no such rule and wrote the low half.
            dvals = [dvals[0] >> 16]
        nleft = nbytes
        for j, v in enumerate(dvals):
            if nleft <= 0:
                break
            nb = min(4, nleft)
            for kk in range(nb):
                if ea + 4 * j + kk < HWCore.alloc:
                    self.lds[ea + 4 * j + kk] = (v >> (8 * kk)) & 0xFF
            nleft -= nb

    def _byte_load(self, lane, ea, ops, nbytes, d16_hi):
        dst = ops[0]
        val = 0
        for i in range(nbytes):
            if ea + i < HWCore.alloc:
                val |= self.lds[ea + i] << (8 * i)
        if "[" in dst:
            aa, bb = (int(x) for x in
                      dst.lstrip("v[").rstrip("]").split(":"))
            for j, i in enumerate(range(aa, bb + 1)):
                self.v[lane][i] = (val >> (32 * j)) & U32
        elif d16_hi:
            cur = self.vget(lane, dst)
            self.vset(lane, dst, (cur & 0xFFFF) | ((val & 0xFFFF) << 16))
        else:
            self.vset(lane, dst, val & U32)

    # single-address family (all read/load + write/store spellings funnel
    # through these four; b64/b128/u16_d16_hi share the bytes helpers)
    def _ds_load(self, ins, ops, nbytes):
        self._xfer(ins, ops, nbytes, store=False)

    def _ds_store(self, ins, ops, nbytes):
        self._xfer(ins, ops, nbytes, store=True)

    def _ds_load_bytes(self, ins, ops, nbytes, d16_hi=False):
        self._xfer(ins, ops, nbytes, store=False, d16_hi=d16_hi)

    def _ds_store_bytes(self, ins, ops, nbytes, d16_hi=False):
        self._xfer(ins, ops, nbytes, store=True, d16_hi=d16_hi)

    # gfx11 spelling fixes vs the base model (see phase14eh notes):
    #   - emu.Core.op_ds_load_u16 is a special-case that ignores offsets
    #   - emu.Core.op_ds_store_b128 is a silent no-op stub
    def op_ds_load_u16(self, ins, ops):
        self._ds_load(ins, ops, 2)

    def op_ds_store_b128(self, ins, ops):
        self._ds_store_bytes(ins, ops, 16)

    def op_ds_store_b64(self, ins, ops):
        self._ds_store(ins, ops, 8)

    def op_ds_write_b128(self, ins, ops):
        self._ds_store_bytes(ins, ops, 16)

    def op_ds_write_b64(self, ins, ops):
        self._ds_store(ins, ops, 8)

    def op_ds_read_b128(self, ins, ops):
        self._ds_load_bytes(ins, ops, 16)

    def op_ds_load_b128(self, ins, ops):
        self._ds_load_bytes(ins, ops, 16)

    def op_ds_load_b64(self, ins, ops):
        self._ds_load_bytes(ins, ops, 8)

    def op_ds_read_b64(self, ins, ops):
        self._ds_load_bytes(ins, ops, 8)

    def op_ds_read_u16_d16_hi(self, ins, ops):
        self._ds_load_bytes(ins, ops, 2, d16_hi=True)

    def op_ds_load_u16_d16_hi(self, ins, ops):
        self._ds_load_bytes(ins, ops, 2, d16_hi=True)

    def op_ds_read2_b64(self, ins, ops):
        self._ds2_hw(ins, ops, store=False)

    def op_ds_write2_b64(self, ins, ops):
        self._ds2_hw(ins, ops, store=True)

    def op_ds_load_2addr_b64(self, ins, ops):
        self._ds2_hw(ins, ops, store=False)

    def op_ds_store_2addr_b64(self, ins, ops):
        self._ds2_hw(ins, ops, store=True)

    def _ds2_hw(self, ins, ops, store):
        # two 8-B accesses: base + offset0*8, base + offset1*8; identical
        # encoding/meaning on gfx1030 (read2_b64) and gfx1100
        # (load_2addr_b64) -- e.g. D9DC0100 4900004D on both streams.
        ops_raw = ins.get("operands") or ""
        if store:
            addr_tok = ops[0].split()[0]
            d0t = ops[1].split()[0]
            d1t = ops[2].split()[0] if len(ops) > 2 else None
        else:
            addr_tok = ops[1].split()[0]
        m0 = re.search(r"offset0:(-?\d+)", ops_raw)
        m1 = re.search(r"offset1:(-?\d+)", ops_raw)
        o0 = int(m0.group(1)) if m0 else 0
        o1 = int(m1.group(1)) if m1 else 0
        n = int(addr_tok[1:])
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                for j, imm in enumerate((o0 * 8, o1 * 8)):
                    raw, ea, ok = self._ea(lane, n, imm, 8)
                    if store:
                        t = d0t if j == 0 else d1t
                        if ok and ea is not None:
                            self._byte_store_pair(lane, ea, t)
                    else:
                        if ok and ea is not None:
                            self._byte_load_pair(lane, ea, ops, j)
                        elif "[" in ops[0]:
                            aa, bb = (int(x) for x in ops[0]
                                      .lstrip("v[").rstrip("]")
                                      .split(":"))
                            if aa + 2 * j + 1 <= bb:
                                self.v[lane][aa + 2 * j] = 0
                                self.v[lane][aa + 2 * j + 1] = 0

    def _byte_store_pair(self, lane, ea, tok):
        if tok is None:
            dw = 0
        elif "[" in tok:
            aa, bb = (int(x) for x in tok.lstrip("v[").rstrip("]")
                      .split(":"))
            dw = self.v[lane][aa] & U32
            if bb > aa:
                dw |= (self.v[lane][aa + 1] & U32) << 32
        else:
            dw = self.v[lane][int(tok[1:])] & U32
        for kk in range(8):
            if ea + kk < HWCore.alloc:
                self.lds[ea + kk] = (dw >> (8 * kk)) & 0xFF

    def _byte_load_pair(self, lane, ea, ops, j):
        v = 0
        for kk in range(8):
            if ea + kk < HWCore.alloc:
                v |= self.lds[ea + kk] << (8 * kk)
        aa, bb = (int(x) for x in ops[0].lstrip("v[").rstrip("]")
                  .split(":"))
        if aa + 2 * j + 1 <= bb:
            self.v[lane][aa + 2 * j] = v & U32
            self.v[lane][aa + 2 * j + 1] = (v >> 32) & U32


# ---------------------------------------------------------------------------
# workgroup driver (parameterized copy of wg_emu.run_workgroup; the legacy
# parameterization must reproduce the F7/F8 numbers -- parity gate)
# ---------------------------------------------------------------------------
class _NoKeys(dict):
    def __contains__(self, k):
        return False


def run_workgroup_hw(prog, dw16_, label, grid, block, fields, text_path=None,
                     wave_count=8, per_wave_step_cap=8_000_000,
                     round_cap=200_000_000, wgid=(0, 0, 0),
                     oob_sem="legacy", alloc=16384, fill_payload=None,
                     agg_lds=None, release_registry=False):
    """Driver entry point.

    `agg_lds` -- None (honour `HWCore.agg_lds`), or an explicit True/False
    for this run.  True replaces the three unbounded record lists with
    exact-count aggregators; correct for every consumer that reads only
    their counts, which is all this function itself does.

    `release_registry` -- True makes THIS CALL own the cores it builds and
    release them on the way out, success or failure.  Default False because
    several existing readers (p16e_rec.py, p8_diff_emu.py, p16f_mirror.py,
    p16d_auth_cells.py) snapshot `registry[n0:]` AFTER the call returns.
    """
    prev_agg = HWCore.agg_lds
    if agg_lds is not None:
        HWCore.agg_lds = bool(agg_lds)
    reg_n0 = len(getattr(HWCore, "registry", []) or [])
    try:
        return _run_wg_hw(
            prog, dw16_, label, grid, block, fields, text_path=text_path,
            wave_count=wave_count, per_wave_step_cap=per_wave_step_cap,
            round_cap=round_cap, wgid=wgid, oob_sem=oob_sem, alloc=alloc,
            fill_payload=fill_payload)
    finally:
        if agg_lds is not None:
            HWCore.agg_lds = prev_agg
        if release_registry:
            try:
                del HWCore.registry[reg_n0:]
            except Exception:                       # noqa: BLE001
                HWCore.registry = []


def _run_wg_hw(prog, dw16_, label, grid, block, fields, text_path=None,
               wave_count=8, per_wave_step_cap=8_000_000,
               round_cap=200_000_000, wgid=(0, 0, 0),
               oob_sem="legacy", alloc=16384, fill_payload=None):
    """fill_payload: optional callable(kind, slot_idx) -> deterministic
    byte pattern writer for the nonzero-discriminant runs (see §10)."""
    if not getattr(prog, "_normed_float_ops", False):
        PE._norm_float_ops(prog)
        try:
            prog._normed_float_ops = True
        except AttributeError:
            pass
    mem = PE.swin_mem(fields, grid, block)
    if text_path is not None:
        tm = PE.text_mem_map(text_path)
        mem.update(tm)
    if fill_payload is not None:
        mem = fill_payload(mem)
    shared_lds = bytearray(0x10000)
    plan = P11.entry_plan(dw16_)
    waves = []
    HWCore.oob_sem = oob_sem
    HWCore.alloc = alloc
    for w in range(wave_count):
        wb = w * 32
        core = HWCore(prog, lanes=32, lds_size=0x10000, lds_fill=0,
                      wavebase=wb, mem=mem)
        core._prog_ref = prog
        P11.fill_entry(core, plan, kernarg=PE.KERNARG,
                       dispatch_ptr=PE.PACKET, wgid=wgid,
                       wavebase=wb, block=block)
        core.lds = shared_lds
        core.mem = mem
        core._cyckeys = _NoKeys()
        core._cyckeys_full = _NoKeys()
        waves.append({"core": core, "state": "RUNNABLE", "n_bar": 0,
                      "bar_sites": [], "bar_epochs": [], "fault": None,
                      "steps_done": 0})
    barrier_epochs = []
    ticks = 0
    outcome = None
    diverged = False

    def _faults():
        return [{"wave": i, "state": w["state"], "fault": w["fault"]}
                for i, w in enumerate(waves) if w["state"] == "FAULTED"]

    while True:
        ticks += 1
        if ticks > round_cap:
            outcome = ("ROUNDCAP", ticks)
            break
        any_active = False
        for w in waves:
            if w["state"] in ("ENDED", "FAULTED"):
                continue
            core = w["core"]
            any_active = True
            if w["state"] == "WAITING":
                continue
            if core.pc >= len(prog):
                w["state"] = "FAULTED"
                w["fault"] = "PCOVERRUN"
                continue
            ins = prog[core.pc]
            if "barrier" in ins["mnemonic"]:
                w["state"] = "WAITING"
                w["n_bar"] += 1
                w["bar_sites"].append(ins.get("address"))
                continue
            try:
                core.step()
                w["steps_done"] += 1
                if core.terminated:
                    w["state"] = "ENDED"
            except Halt as h:
                if h.kind == "END" or core.terminated:
                    w["state"] = "ENDED"
                else:
                    w["state"] = "FAULTED"
                    w["fault"] = ("HALT", h.kind, getattr(h, "info", None))
            except NotImpl as e:
                w["state"] = "FAULTED"
                w["fault"] = ("NOTIMPL", str(e))
            except Exception as e:
                w["state"] = "FAULTED"
                w["fault"] = ("EXC", f"{type(e).__name__}: {e}")
            if w["steps_done"] > per_wave_step_cap:
                w["state"] = "FAULTED"
                w["fault"] = ("STEPCAP", core.steps)
        if not any_active:
            # EXPLICIT OUTCOME.  "no wave is still active" is NOT success:
            # a workgroup in which every wave FAULTED also reaches this
            # point.  Success requires every wave ENDED, zero faults, and
            # no cap -- anything else is named for what it is.
            f = _faults()
            if not waves:
                # `all()` over an empty sequence is True, so without this
                # branch a dispatch that constructed NO waves at all --
                # a setup failure, not an execution -- reported
                # ("ALL_ENDED", 1) with natural_end True.  That is the same
                # fail-open shape as the Phase 16I defect, one level up:
                # the most reassuring label for a run that never happened.
                outcome = ("ERROR", ticks, {"reason": "NO_WAVES"})
            elif f:
                outcome = ("FAULTED", ticks, f)
            elif all(w["state"] == "ENDED" for w in waves):
                outcome = ("ALL_ENDED", ticks)
            else:
                outcome = ("DEADLOCK", ticks,
                           [{"wave": i, "state": w["state"]}
                            for i, w in enumerate(waves)])
            break
        alive = [w for w in waves if w["state"] not in ("ENDED", "FAULTED")]
        if alive and all(w["state"] == "WAITING" for w in alive):
            sites = {w["bar_sites"][-1] for w in alive}
            if len(sites) != 1:
                diverged = True
                outcome = ("DEADLOCK", ticks,
                           {"reason": "BARRIER_SEQUENCE_DIVERGENCE",
                            "sites": sorted(s for s in sites if s)})
                break
            barrier_epochs.append(sites.pop())
            for w in alive:
                try:
                    w["core"].step()
                    w["steps_done"] += 1
                except Exception as e:
                    w["state"] = "FAULTED"
                    w["fault"] = ("RELEASE-EXC", str(e))
                w["state"] = "RUNNABLE"
    faults = _faults()
    res = {"label": label, "oob_sem": oob_sem, "alloc": alloc,
           "outcome": outcome, "diverged": diverged, "ticks": ticks,
           "n_waves": wave_count,
           "n_ended": sum(1 for w in waves if w["state"] == "ENDED"),
           "n_faulted": len(faults), "faults": faults,
           "capped": outcome[0] == "ROUNDCAP",
           "natural_end": (outcome[0] == "ALL_ENDED"),
           "barrier_epochs": barrier_epochs,
           "per_wave": [{"wave": ww, "state": waves[ww]["state"],
                         "steps": waves[ww]["steps_done"],
                         "barriers": waves[ww]["n_bar"],
                         "fault": waves[ww]["fault"],
                         "n_rw": waves[ww]["core"].n_ev_rw,
                         "n_bp": waves[ww]["core"].n_ev_bp,
                         "memviol": len(waves[ww]["core"].hw_memviol),
                         "oob_read_zero": waves[ww]["core"]
                         .hw_oob_read_zero,
                         "oob_write_discard": waves[ww]["core"]
                         .hw_oob_write_discard}
                        for ww in range(wave_count)]}
    # per-slot payload hashes (discriminant: did output DATA change?)
    import hashlib as _hl
    slot_hash = {}
    for k in range(16):
        base = PE.SLOT + k * PE.STRIDE + PE.GUARD
        h = _hl.sha256()
        for off in range(0, PE.STRIDE - PE.GUARD, 4):
            h.update((mem.get(base + off, 0) & 0xFFFFFFFF).to_bytes(
                4, "little"))
        slot_hash[k] = h.hexdigest()
    res["slot_hashes"] = slot_hash
    return res


def ef_fields(dims=64, nonzero=False):
    fields = {}
    for o, k in ((0x00, 0), (0x08, 1), (0x10, 2), (0x30, 3), (0x38, 4),
                 (0x48, 5), (0x78, 6), (0x80, 7), (0xA0, 8)):
        fields[o] = ("ptr", k)
    for o in (0x18, 0x1C, 0x20, 0x24):
        fields[o] = ("u32", dims)
    fields[0x28] = ("u32", 0)
    fields[0x98] = ("u64", 0)
    return fields


def nonzero_fill(mem):
    """Deterministic nonzero payloads over the modeled pointer slots
    (same bases/slots/geometry as the zero runs; bytes differ only)."""
    import emu as _EMU
    import struct as _st
    base_mem = dict(mem)
    SLOT = PE.SLOT
    STRIDE = PE.STRIDE
    GUARD = PE.GUARD
    for k in range(16):
        for off in range(GUARD, GUARD + 0x10000, 4):
            b = (k * 0x5A5 + off * 7 + (off >> 2) * 13) & 0xFFFFFFFF
            base_mem[SLOT + k * STRIDE + off] = b
    return base_mem


def run_single_case(which, wavebase, oob_sem="legacy", alloc=16384):
    """Single-wave record run (boundary waves 0 / 224) through E.trace with
    HWCore; legacy value semantics reproduce the Phase 14EG single-wave
    numbers (ENT w0 13,085 / w7 12,488 steps) as the record parity gate."""
    src = PE.ENT_DIS if which == "ent" else PE.ORIG_DIS
    co = PE.ENT_CO if which == "ent" else PE.ORIG_OBJ
    prog, rows, idx = PE.slice_program(src, PE.KERNEL)
    dw = P11.dw16(co, PE.KERNEL)
    fields = G.build_fields()
    HWCore.oob_sem = oob_sem
    HWCore.alloc = alloc
    n0 = len(HWCore.registry) if hasattr(HWCore, "registry") else 0
    E.SwinCore = HWCore
    r = E.trace(prog, dw, f"{which}-{oob_sem}-w{wavebase//32}",
                (1, 1, 1), (256, 1, 1), (0, 0, 0), wavebase, fields,
                text_path=co)
    core = None
    for c in HWCore.registry[n0:]:
        core = c
    return r, (core.hw_ev if core is not None else [])


def run_ef(which="ent", label=None, wave_count=8, oob_sem="legacy",
           alloc=16384, nonzero=False):
    """which: 'ent' (entry-fixed gfx1030) | 'orig' (original gfx1100)."""
    if which == "ent":
        src, co = PE.ENT_DIS, PE.ENT_CO
    else:
        src, co = PE.ORIG_DIS, PE.ORIG_OBJ
    prog, rows, idx = PE.slice_program(src, PE.KERNEL)
    dw = P11.dw16(co, PE.KERNEL)
    return run_workgroup_hw(
        prog, dw, label or f"{which}-{oob_sem}-a{alloc}",
        (1, 1, 1), (256, 1, 1), ef_fields(nonzero=nonzero), text_path=co,
        wave_count=wave_count, oob_sem=oob_sem, alloc=alloc,
        fill_payload=nonzero_fill if nonzero else None)


def parity_expected(which):
    return ("ALL_ENDED", 13077, 14) if which == "ent" else \
        ("ALL_ENDED", 9175, 14)


if __name__ == "__main__":
    import json
    which = sys.argv[1] if len(sys.argv) > 1 else "ent"
    sem = sys.argv[2] if len(sys.argv) > 2 else "legacy"
    r = run_ef(which, oob_sem=sem)
    exp = parity_expected(which)
    ok = (r["outcome"][0] == exp[0] and r["ticks"] == exp[1]
          and len(r["barrier_epochs"]) == exp[2])
    print(json.dumps({"result": r["outcome"], "ticks": r["ticks"],
                      "epochs": len(r["barrier_epochs"]),
                      "sem": sem,
                      "parity_ok_for_legacy": ok if sem == "legacy" else None,
                      "per_wave": [(p["wave"], p["state"], p["steps"],
                                    p["barriers"], p["fault"], p["memviol"],
                                    p["oob_read_zero"], p["oob_write_discard"])
                                   for p in r["per_wave"]]}, indent=1))
