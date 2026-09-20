#!/usr/bin/env python3
"""Phase 16H — P6: make global-OOB a hard validation gate.

THE DEFECT (Phase 16G, re-derived here)

The model's global-memory path is a plain dict:

    val = self.mem.get(addr, 0)          # any unmapped address -> 0
    self.mem[addr + 4*j + k] = bv        # any address accepted

There is no declared address space, no bounds check, no counter and no
failure.  A kernel that reads or writes anywhere at all still "runs to
completion" and reports success.  This is why Candidate E -- whose 79
`g_e4m3_lut` sites computed addresses BELOW `TEXT_BASE` (e.g.
`0x2FFF1D74`, outside every mapped section) -- passed the Phase-16F
harness: the reads returned 0, and `g_e4m3_lut` is an all-zero table, so
the *values* were accidentally right.  A value-only comparison cannot
detect this.  Only an address-aware gate can.

THE FIX

A declared-region model.  Every global access is checked against an
explicit set of regions:

  * the module's own mapped sections, taken from the code object itself
    (`.text`, `.text.1`, `.rodata`, `.data`, `.bss`) at
    `TEXT_BASE + section.addr`.  Candidate F's `.rodata` is mapped with
    its EXACT bytes, including `g_e4m3_lut`;
  * the kernarg segment, sized from the kernel descriptor's own
    `kernarg_size`;
  * the AQL dispatch packet;
  * the device allocations the harness actually hands the kernel (one
    64-KiB window per declared pointer argument).

An access that does not lie wholly inside one region is an OOB EVENT.  It
is recorded with site, wave, lane, address and width; the run continues
with RDNA2-ish behaviour (read 0 / discard write) so that ALL violations
are collected rather than only the first.

THE GATE

    oob_global_reads == 0  and  oob_global_writes == 0

LDS is deliberately NOT part of this gate.  The DS path keeps its own
hardware-faithful model (`hw_memviol`, `hw_oob_read_zero`,
`hw_oob_write_discard`), which is a statement about RDNA2 LDS wrap
behaviour, not about whether the translated code is correct.  The two
must not be conflated: the brief requires LDS semantics stay separate.

Host-only.  No GPU.
"""
from __future__ import annotations

import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p16h_lib as L  # noqa: E402

ROOT = L.ROOT
for p in ("phase16e_candidate_e/tools", "phase14e_static/tools",
          "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
          "phase14d11_static", "phase14d_static/tools", "phase8_static/tools",
          "phase14d8_static/tools"):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)

import p16e_lib          # noqa: E402
import p16e_rec          # noqa: E402
import p14eh             # noqa: E402
from p14eh import PE     # noqa: E402
import p14d11_emu as P11  # noqa: E402

TEXT_BASE = PE.TEXT_BASE
KERNARG = P11.KERNARG
PACKET = P11.PACKET
SLOT = P11.SLOT
STRIDE = P11.STRIDE
GUARD = P11.GUARD

# Sections a kernel may legitimately touch at run time.  ELF bookkeeping
# sections (.note, .dynsym, .dynstr, .hash, .gnu.hash, .dynamic,
# .relro_padding) are deliberately excluded: kernel code reading its own
# ELF metadata is a defect, not a legitimate access.
MODULE_DATA_SECTIONS = (".text", ".text.1", ".rodata", ".data", ".bss")


# --------------------------------------------------------------------------
# declared-region model
# --------------------------------------------------------------------------
class GlobalGate:
    """Declared global address space + hard OOB accounting."""

    def __init__(self):
        self.regions = []      # (lo, hi, name)
        self.oob_reads = []
        self.oob_writes = []
        self.n_reads = 0
        self.n_writes = 0
        self.n_global_ops = 0
        self.unmeasured = []   # global ops whose width could not be derived
        # Exact OOB counts, maintained independently of the retained records.
        self.n_oob_reads = 0
        self.n_oob_writes = 0
        self.oob_by_site_counts = {}
        # Per-wave OOB totals, exact and bounded in size (one entry per wave),
        # so truncating the detail records cannot make this number partial.
        self.oob_by_wave_counts = {}
        # A non-terminating kernel emits OOB accesses without bound, and
        # retaining a record for every one exhausts memory long before the
        # round cap fires.  `P14_OOB_REC_CAP` bounds only the *retained*
        # records; every count below stays exact, and the summary switches to
        # its counted form only when something was actually dropped, so a run
        # that stays under the cap reports byte-identically to before.
        #
        # The default used to be 0 (unbounded).  Measured, that was NOT the
        # dominant leak on a runaway run -- `hw_ev`/`ds_ops` are (see
        # `p16i_perturb_memdiag.py`) -- but an unbounded default is still a
        # real failure mode, so it is now bounded.  Set P14_OOB_REC_CAP=0 to
        # deliberately disable the bound when full per-access detail is
        # wanted and the run is known to terminate.
        self.rec_cap = int(os.environ.get("P14_OOB_REC_CAP", "200000"))
        self.recs_dropped = 0

    def declare(self, lo, size, name):
        self.regions.append((lo, lo + size, name))

    def locate(self, addr, n):
        """The region wholly containing [addr, addr+n), or None."""
        for lo, hi, name in self.regions:
            if lo <= addr and addr + n <= hi:
                return name
        return None

    def note(self, store, addr, n, site, wave, lane, mnem, operands="",
             bases=None):
        if store:
            self.n_writes += 1
        else:
            self.n_reads += 1
        if self.locate(addr, n) is not None:
            return True
        if store:
            self.n_oob_writes += 1
        else:
            self.n_oob_reads += 1
        e = self.oob_by_site_counts.setdefault(
            "0x%08X" % (site or 0), {"n": 0, "read": 0, "write": 0})
        e["n"] += 1
        e["write" if store else "read"] += 1
        self.oob_by_wave_counts[wave] = self.oob_by_wave_counts.get(wave, 0) + 1
        if not self.rec_cap or (len(self.oob_reads) + len(self.oob_writes)
                                < self.rec_cap):
            rec = {"store": bool(store), "addr": addr, "n": n, "site": site,
                   "wave": wave, "lane": lane, "mnem": mnem,
                   "operands": operands, "bases": bases or {}}
            (self.oob_writes if store else self.oob_reads).append(rec)
        else:
            self.recs_dropped += 1
        return False

    @property
    def ok(self):
        return (not self.n_oob_reads and not self.n_oob_writes
                and not self.unmeasured)

    def _by_site_counted(self):
        """Per-site OOB totals when the detail records were truncated.

        Counts and address ranges are exact for the sites whose records were
        retained; a site seen only after the cap contributes its exact count
        but no address range, so `addr_range` is omitted rather than faked.
        """
        detail = _by_site(self.oob_reads + self.oob_writes)
        out = {}
        for k, v in self.oob_by_site_counts.items():
            d = detail.get(k)
            e = {"n": v["n"], "read": v["read"], "write": v["write"],
                 "counts_exact": True,
                 "detail_records_retained": (d["n"] if d else 0)}
            if d:
                e["n_distinct_addrs"] = d["n_distinct_addrs"]
                e["addr_range"] = d["addr_range"]
                e["mnems"] = d["mnems"]
                e["operands"] = d["operands"]
                e["base_values"] = d["base_values"]
            out[k] = e
        return {k: out[k] for k in sorted(out)}

    def summary(self):
        return {
            "n_global_ops": self.n_global_ops,
            "n_global_reads": self.n_reads,
            "n_global_writes": self.n_writes,
            "n_unmeasured_global_ops": len(self.unmeasured),
            "unmeasured_mnemonics": sorted({u["mnem"]
                                            for u in self.unmeasured}),
            "oob_global_reads": self.n_oob_reads,
            "oob_global_writes": self.n_oob_writes,
            "oob_total": self.n_oob_reads + self.n_oob_writes,
            "oob_records_retained": (len(self.oob_reads)
                                     + len(self.oob_writes)),
            "oob_records_truncated": self.recs_dropped > 0,
            "oob_records_dropped": self.recs_dropped,
            "gate": "PASS" if self.ok else "FAIL",
            "regions": [{"lo": "0x%X" % lo, "hi": "0x%X" % hi, "name": nm,
                         "size": hi - lo} for lo, hi, nm in self.regions],
            # The counted form is used only when records were actually
            # dropped: a cap that was never reached must not change the
            # summary's shape, or every downstream signature comparison
            # would move for a reason that has nothing to do with the run.
            "oob_by_site": (self._by_site_counted() if self.recs_dropped
                            else _by_site(self.oob_reads + self.oob_writes)),
            "oob_by_wave": {str(k): v for k, v in
                            sorted(self.oob_by_wave_counts.items())},
            "oob_samples": [
                {"kind": "write" if r["store"] else "read",
                 "wave": r["wave"], "lane": r["lane"],
                 "site": ("0x%08X" % r["site"]) if r["site"] else None,
                 "addr": "0x%016X" % r["addr"], "n": r["n"],
                 "mnem": r["mnem"]}
                for r in (self.oob_reads + self.oob_writes)[:20]],
        }


def _by_site(recs):
    out = {}
    for r in recs:
        k = "0x%08X" % (r["site"] or 0)
        e = out.setdefault(k, {"n": 0, "read": 0, "write": 0,
                               "addrs": set(), "mnems": set(),
                               "operands": set(), "bases": {}})
        e["n"] += 1
        e["read" if not r["store"] else "write"] += 1
        e["addrs"].add(r["addr"])
        e["mnems"].add(r["mnem"])
        if r.get("operands"):
            e["operands"].add(r["operands"])
        for kk, vv in (r.get("bases") or {}).items():
            e["bases"].setdefault(kk, set()).add(vv)
    return {k: {"n": v["n"], "read": v["read"], "write": v["write"],
                "n_distinct_addrs": len(v["addrs"]),
                "addr_range": ["0x%016X" % min(v["addrs"]),
                               "0x%016X" % max(v["addrs"])],
                "mnems": sorted(v["mnems"]),
                "operands": sorted(v["operands"])[:3],
                "base_values": {kk: sorted(vv)[:4]
                                for kk, vv in v["bases"].items()}}
            for k, v in sorted(out.items())}


# (_by_wave over the detail records was replaced by the exact per-wave
# counter `GlobalGate.oob_by_wave_counts`, which truncation cannot skew.)


# --------------------------------------------------------------------------
# module mapping (the P6 requirement: map .rodata exactly, not just .text)
# --------------------------------------------------------------------------
def module_mem_map(path):
    """Map every MODULE_DATA_SECTION at TEXT_BASE + section.addr, with the
    section's EXACT bytes.  Supersedes PE.text_mem_map(), which mapped
    only .text and so left .rodata (and therefore g_e4m3_lut) unmapped."""
    import p14d_kd as kd
    data, sections, _syms = kd.parse_elf(path)
    mem = {}
    for s in sections:
        if s.get("name") in MODULE_DATA_SECTIONS and s.get("type") == 1:
            off, size, addr = s["offset"], s["size"], s["addr"]
            for i in range(size):
                mem[TEXT_BASE + addr + i] = data[off + i]
    return mem


def module_regions(elf):
    """Declared module regions, straight from the code object."""
    out = []
    for s in elf.loadable():
        if s["sname"] in MODULE_DATA_SECTIONS:
            out.append((TEXT_BASE + s["addr"], s["size"], s["sname"]))
    return out


def kernarg_size(elf, kd_name):
    """The kernel descriptor's own kernarg_size (dword 2)."""
    for s in elf.symbols:
        if s["name"] == kd_name and s["size"] == 64:
            b = elf.read_va(s["value"], 64)
            if b:
                return struct.unpack_from("<I", b, 8)[0]
    return None


def _bases_of(core, ops, lane):
    """The concrete values of every VGPR / SGPR pair appearing in the
    operands -- the provenance of an OOB effective address."""
    import re as _re
    out = {}
    for tok in ops:
        m = _re.match(r"^v\[(\d+):(\d+)\]", tok)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            out[tok.split()[0]] = "0x%016X" % (
                core.v[lane][a] | (core.v[lane][b] << 32))
            continue
        m = _re.match(r"^v(\d+)$", tok.split()[0])
        if m:
            out[tok.split()[0]] = "0x%08X" % core.v[lane][int(m.group(1))]
            continue
        m = _re.match(r"^s\[(\d+):(\d+)\]", tok)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            out[tok.split()[0]] = "0x%016X" % (
                core.s[a] | (core.s[b] << 32))
    return out


# --------------------------------------------------------------------------
# gated core
# --------------------------------------------------------------------------
class GateCore(p16e_rec.E16Core):
    """E16Core + a per-lane hard check on every global access.

    `_gl_width` is overridden because the inherited table keys on
    `b8`/`b16`/`b32`/`b64` spellings and therefore returns 0 for the
    `_u16` / `_ushort` / `_ubyte` / `_sbyte` spellings this module uses
    (`global_load_u16`, `global_load_sbyte`, ...).  A width of 0 silently
    exempted those accesses from the gate -- including, fatally, the 79
    `g_e4m3_lut` loads.  A global access whose width cannot be determined
    is now counted as UNMEASURED and fails the gate outright, so no future
    mnemonic can escape the check by being unknown.
    """

    gate = None            # GlobalGate, set before the run
    wave_index = 0

    # ordered: most specific first
    _WIDTHS = (
        ("dwordx4", 16), ("b128", 16), ("x4", 16),
        ("dwordx3", 12), ("b96", 12),
        ("dwordx2", 8), ("b64", 8), ("x2", 8), ("u64", 8), ("_i64", 8),
        ("dword", 4), ("b32", 4), ("u32", 4), ("i32", 4),
        ("u16", 2), ("s16", 2), ("b16", 2), ("ushort", 2), ("short", 2),
        ("ubyte", 1), ("sbyte", 1), ("b8", 1), ("u8", 1), ("i8", 1),
        ("byte", 1),
    )

    @classmethod
    def _width_of(cls, mnem):
        m = mnem
        for key, w in cls._WIDTHS:
            if key in m:
                return w
        return 0

    def _gl_addr(self, ins, lane, ops, store=False):
        addr = super()._gl_addr(ins, lane, ops, store)
        mnem = ins.get("mnemonic") or ""
        n = self._width_of(mnem)
        g = GateCore.gate
        g.n_global_ops += 1
        if n == 0:
            g.unmeasured.append({"site": ins.get("address"), "mnem": mnem,
                                 "wave": GateCore.wave_index, "lane": lane})
            return addr
        if g.locate(addr, n) is None:
            g.note(store, addr, n, ins.get("address"), GateCore.wave_index,
                   lane, mnem, operands=ins.get("operands") or "",
                   bases=_bases_of(self, ops, lane))
        else:
            g.note(store, addr, n, ins.get("address"), GateCore.wave_index,
                   lane, mnem)
        return addr


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------
SYM = "_Z10k_swin_varILi32ELb0EEv9VarParams"


def run_case(co_path, dis_path, tag, cell="A", wave_count=8,
             declare_extra=()):
    """Emulate one candidate at the harness geometry with the gate armed."""
    co = os.path.join(ROOT, co_path)
    dis = os.path.join(ROOT, dis_path)
    prog, _rows, _i = PE.slice_program(dis, SYM)
    dw = P11.dw16(co, SYM)
    c = p16e_rec.CELLS[cell]
    fields = p16e_rec.fields_for(c)

    elf = L.Elf(co)
    kd_name = SYM + ".kd"
    ks = kernarg_size(elf, kd_name)

    gate = GlobalGate()
    for lo, size, name in module_regions(elf):
        gate.declare(lo, size, "module:" + name)
    if ks:
        gate.declare(KERNARG, ks, "kernarg")
    gate.declare(PACKET, 64, "aql_packet")
    # device allocations actually handed to the kernel by the harness
    for _o, k in ((0x00, 0), (0x08, 1), (0x10, 2), (0x30, 3), (0x38, 4),
                  (0x48, 5), (0x78, 6), (0x80, 7), (0xA0, 8)):
        gate.declare(SLOT + k * STRIDE, STRIDE, "harness_slot_%d" % k)
    for lo, size, name in declare_extra:
        gate.declare(lo, size, name)

    GateCore.gate = gate
    GateCore.wave_index = 0
    prev = p14eh.HWCore
    p14eh.HWCore = GateCore
    GateCore.oob_sem = "u32"
    GateCore.alloc = 16384
    GateCore.lds_img = 0x10000
    try:
        orig_tmm = PE.text_mem_map
        PE.text_mem_map = module_mem_map
        try:
            res = p14eh.run_workgroup_hw(
                prog, dw, "p6_" + tag, c["grid"], (256, 1, 1), fields,
                text_path=co, wave_count=wave_count, oob_sem="u32",
                alloc=16384, wgid=c["wgid"])
        finally:
            PE.text_mem_map = orig_tmm
    finally:
        p14eh.HWCore = prev

    out = {"tag": tag, "co": os.path.relpath(co, ROOT),
           "kernarg_size": ks,
           "outcome": str(res["outcome"]), "ticks": res["ticks"],
           "epochs": len(res["barrier_epochs"]),
           "per_wave": [{k: v for k, v in wd.items() if k != "core"}
                        for wd in res["per_wave"]],
           "gate": gate.summary()}
    return out


def main():
    OUT = os.path.join(L.P16H, "out")
    os.makedirs(OUT, exist_ok=True)

    E = ("phase16e_candidate_e/gfx1030_dlssnr_candidate_e.co",
         "phase16e_candidate_e/disasm/candidate_e_gfx1030_disasm.txt")
    F = ("phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co",
         "phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt")

    res = {}
    print("=" * 72)
    print("P6 — strengthened global-OOB gate, run against BOTH candidates")
    print("=" * 72)
    for tag, (co, dis) in (("candidate_E", E), ("candidate_F", F)):
        r = run_case(co, dis, tag)
        res[tag] = r
        g = r["gate"]
        print("\n--- %s ---" % tag)
        print("  outcome=%s ticks=%d epochs=%d"
              % (r["outcome"], r["ticks"], r["epochs"]))
        print("  kernarg_size=%s  regions=%d"
              % (r["kernarg_size"], len(g["regions"])))
        print("  global ops=%d  reads=%d writes=%d"
              % (g["n_global_ops"], g["n_global_reads"],
                 g["n_global_writes"]))
        print("  unmeasured global ops=%d %s"
              % (g["n_unmeasured_global_ops"], g["unmeasured_mnemonics"]))
        print("  OOB reads=%d  OOB writes=%d  -> GATE %s"
              % (g["oob_global_reads"], g["oob_global_writes"], g["gate"]))
        if g["oob_by_site"]:
            print("  distinct OOB sites: %d" % len(g["oob_by_site"]))
            for k, v in list(g["oob_by_site"].items())[:6]:
                print("     site %s  n=%d (r=%d w=%d)  addrs %s..%s  %s"
                      % (k, v["n"], v["read"], v["write"],
                         v["addr_range"][0], v["addr_range"][1],
                         ",".join(v["mnems"])))

    res["verdict"] = {
        "candidate_E_gate": res["candidate_E"]["gate"]["gate"],
        "candidate_F_gate": res["candidate_F"]["gate"]["gate"],
        "gate_is_sensitive": res["candidate_E"]["gate"]["gate"] == "FAIL",
        "gate_is_specific": res["candidate_F"]["gate"]["gate"] == "PASS",
    }
    json.dump(res, open(os.path.join(OUT, "p6_global_gate.json"), "w"),
              indent=1)
    print("\nverdict:", json.dumps(res["verdict"]))
    print("wrote", os.path.join(OUT, "p6_global_gate.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
