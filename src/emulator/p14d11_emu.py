"""Phase 14D11-D — host-only pre-launch emulation of the EXACT proposed
k_conv_splitk dispatch (zero GPU execution).

Reuses the Phase 14D8 descriptor-driven emulator unchanged (p14d8_core,
emu, p14d_kd) and drives the conv_splitk program slice built from the
ENTRY-FIXED module's own disassembly (the exact bytes that will run on
the GPU), plus the original gfx1100 stream for side-by-side semantic
equality, on the exact proposed logical dispatch(es).

A recording Core8 subclass additionally logs every per-lane global
load/store address and every modeled LDS access, so the run outputs:

  - outcome class (END / CYCLE / UNDEFREAD / FAULT / NOTIMPL / STEPLIMIT)
  - step count, branch-event count
  - soft-WMMA / WMMA site reach (which dot2/v_wmma sites executed)
  - per-slot global load/store byte-offset ranges (relative to the base
    pointer injected in the kernarg) and per-site widths
  - modeled LDS address range
  - any global access outside the per-slot 64-KiB modeled windows

Fault model identical to 14D8-B: a store (and here also a load) outside
every guarded window kills the run.
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

import p14d8_core as P8                     # noqa: E402
import p14d_kd as kd                        # noqa: E402
from emu import Core, Halt, NotImpl, U32, build_orig_program  # noqa: E402
from disasm_lib import parse_orig_disasm    # noqa: E402
from p14d8_core import Core8, entry_plan, fill_entry  # noqa: E402

# Phase 16K-K1: `g_ops` / `ds_ops` were unbounded plain lists here, and this
# class is on the PRODUCTION path (see the MRO in p16k_recorder's docstring),
# so every global lane-access of every wave appended a 4-tuple that nothing
# ever drained.  They are now bounded recorders whose mode is explicit.
_P16K_TOOLS = os.path.join(ROOT, "phase16k_pretest", "tools")
if _P16K_TOOLS not in sys.path:
    sys.path.insert(0, _P16K_TOOLS)
import p16k_recorder as REC                 # noqa: E402

KERNEL = "_Z13k_conv_splitk12ConvParams1d"
ENT_CO = os.path.join(ROOT, "phase14_entry_fixed_module",
                      "gfx1030_dlssnr_module_entryfixed.co")
ENT_DIS = os.path.join(ROOT, "phase14d9_static", "out",
                       "entryfixed_gfx1030_disasm.txt")
ORIG_OBJ = os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_code_object.o")
ORIG_DIS = os.path.join(ROOT, "phase5_exact_fragment",
                        "gfx1100_disassembly.txt")

KERNARG = 0x10000       # fake kernarg segment base (phase-8 convention)
PACKET = 0x20000        # fake AQL dispatch packet base
SLOT = 0x2_0000_0000
GUARD = 0x1000
N_SLOTS = 5
STRIDE = 0x10000


def dw16(path, kernel):
    data, sections, syms = kd.parse_elf(path)
    for k, base in kd.find_kernel_kds(data, sections, syms):
        if k == kernel:
            return kd.dump_kd(data, base)
    raise KeyError(kernel)


def symbol_ranges(dispath):
    syms = {}
    starts = []
    with open(dispath, encoding="utf-8-sig", errors="replace") as f:
        for raw in f:
            m = re.match(r"^0*([0-9a-f]+) <(_Z[^>]+)>:$", raw.strip())
            if m:
                starts.append((int(m.group(1), 16), m.group(2)))
    for i, (a, n) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else a + 0x100000
        syms[n] = (a, end)
    return syms


_SEL_RE = re.compile(r"\s*op_sel(?:_hi|_mid)?:\[[^\]]*\]")


def slice_program(dispath, kernel):
    rows = parse_orig_disasm(dispath)
    a, end = symbol_ranges(dispath)[kernel]
    sl = sorted((r for r in rows if a <= r["address"] < end),
                key=lambda r: r["address"])
    assert sl, kernel
    for r in sl:
        if r.get("operands"):
            r["operands"] = _SEL_RE.sub("", r["operands"])
    prog = build_orig_program(sl)
    # prog index -> original .text address (absolute, for site reporting)
    idx2addr = {}
    for i, ins in enumerate(prog):
        idx2addr[i] = ins.get("address")
    return prog, sl, idx2addr


class RecCore(Core8):
    """Core8 that records every modeled memory access with its site."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        # Bounded by default (AGGREGATE): exact counts, min/max address,
        # per-PC and per-opcode counts, and a bounded sample.  Both stay
        # list-compatible, so `len()`, iteration and indexing are unchanged
        # for a reader that asks for a full trace.
        self.g_ops = REC.recorder_for("g_ops")
        self.ds_ops = REC.recorder_for("ds_ops")
        self.last_nbytes = 0

    def _gl_addr(self, ins, lane, ops, store=False):
        addr = super()._gl_addr(ins, lane, ops, store)
        nb = self._gl_width(ins, ops, store)
        # The opcode is passed alongside rather than folded into the tuple:
        # existing readers unpack four names, and a 5-tuple would raise.
        self.g_ops.append((store, addr, nb, ins.get("address")),
                          opcode=ins.get("mnemonic"))
        return addr

    @staticmethod
    def _gl_width(ins, ops, store):
        m = ins["mnemonic"]
        if "dwordx4" in m or "b128" in m or "x4" in m:
            return 16
        if "b96" in m:
            return 12
        if "dwordx2" in m or "b64" in m or "x2" in m:
            return 8
        if "b32" in m or "dword" in m:
            return 4
        if "b16" in m:
            return 2
        if "b8" in m or "byte" in m:
            return 1
        return 0

    def step(self):
        """Override dispatch: record LDS access ranges around ds_* ops by
        re-parsing like the emulator does (addr vgpr + offset)."""
        pc = self.pc
        prog = self._prog_ref
        ins = prog[pc]
        mnem = ins["mnemonic"]
        if mnem.startswith("ds_"):
            try:
                self._record_ds(ins)
            except Exception:
                pass  # recorder is best-effort; emulation itself is not
        return super().step()

    def _record_ds(self, ins):
        import re
        text = ins.get("text") or ins.get("operands") or ""
        mnem = ins["mnemonic"]
        ops_raw = ins.get("operands") or ""
        olist = [o.strip() for o in ops_raw.split(",")] if ops_raw else []
        addr_tok = None
        for o in olist:
            if o.startswith("v") and ":" not in o:
                addr_tok = o
                break
        if addr_tok is None:
            return
        n = int(addr_tok.lstrip("v"))
        off = 0
        mm = re.search(r"offset:(-?0x[0-9a-fA-F]+|-?\d+)", ops_raw)
        if mm:
            off = int(mm.group(1), 0)
        store = "store" in mnem or "write" in mnem or mnem in (
            "ds_write2_b32", "ds_write_2addr_b32")
        nb = 16 if ("128" in mnem or "x4" in mnem) else \
            8 if ("64" in mnem or "x2" in mnem or "2addr" in mnem or
                  "write2" in mnem or "read2" in mnem or "2_b32" in mnem) \
            else 4 if ("32" in mnem or "b32" in mnem) else \
            2 if ("16" in mnem) else 1
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                a = (self.v[lane][n] + off) & U32
                self.ds_ops.append((store, a, nb, ins.get("address")))


# bind the program reference the recorder needs
def run_trace(prog, dw16_, label, grid, block, wg, wavebase, split_count,
              softwmma_mnems=("v_dot2c_f32_f16", "v_dot2_f32_f16",
                              "v_dot4c_i32_i8"),
              wmma_mnem="v_wmma_f32_16x16x16_f16", events_cap=400000,
              dump_path=None, slot_vals=None, snap_sites=None):
    mem = {}
    ptrs = slot_vals if slot_vals is not None else \
        [SLOT + k * STRIDE + GUARD for k in range(N_SLOTS)]
    assert len(ptrs) == N_SLOTS
    for k, p in enumerate(ptrs):
        base = KERNARG + 8 * k
        mem[base] = p & U32
        mem[base + 4] = (p >> 32) & U32
    mem[KERNARG + 0x28] = split_count & U32
    gx, gy, gz = grid
    bx, by, bz = block
    mem[KERNARG + 0x30] = gx & U32
    mem[KERNARG + 0x34] = gy & U32
    mem[KERNARG + 0x38] = gz & U32
    mem[KERNARG + 0x3C] = (bx & 0xFFFF) | ((by & 0xFFFF) << 16)
    mem[KERNARG + 0x40] = (bz & 0xFFFF) | ((gx % bx) << 16)   # gz|rem_x
    mem[KERNARG + 0x42] = (gy % by) & U32
    mem[KERNARG + 0x44] = (gz % bz) & U32
    mem[KERNARG + 0x58] = 0
    mem[KERNARG + 0x5C] = 0
    mem[KERNARG + 0x60] = 0
    mem[KERNARG + 0x64] = 0
    mem[KERNARG + 0x68] = 0
    mem[KERNARG + 0x6C] = 0
    mem[KERNARG + 0x70] = 1            # grid_dims
    core = RecCore(prog, lanes=32, lds_size=4096, lds_fill=0,
                   wavebase=wavebase, mem=mem)
    # This tool iterates `core.g_ops` expecting EVERY event (per-slot reach,
    # the OOB scan, the dump), so it declares FULL_TRACE rather than
    # silently reading the AGGREGATE sample.
    REC.force_full(core, max_events=max(events_cap * 2, 1 << 20),
                   label="p14d11.run_trace")
    core._prog_ref = prog
    plan = entry_plan(dw16_)
    fill_entry(core, plan, kernarg=KERNARG, dispatch_ptr=PACKET,
               wgid=wg, wavebase=wavebase, block=block)
    snaps = {a: [] for a in (snap_sites or {})}
    # per-instruction soft-WMMA/WMMA site hit census (all 32 lanes exec the
    # same stream; a dot site executed by any active lane = reached)
    sw_hits = {}
    wm_hits = {}
    n_br = 0
    n_bar = 0
    exec_stream = []
    outcome = None
    try:
        while core.steps < 2_000_000:
            ins = prog[core.pc]
            mnem = ins["mnemonic"]
            exec_stream.append((ins.get("address"), mnem,
                                ins.get("operands", "")))
            site = ins.get("address")
            if snap_sites and site in snap_sites:
                snaps[site].append([core.s[i] for i in snap_sites[site]])
            if mnem.startswith("s_cbranch") or mnem == "s_branch":
                n_br += 1
            elif "barrier" in mnem:
                n_bar += 1
            elif mnem in softwmma_mnems or mnem == wmma_mnem:
                if core.exec_l:
                    (sw_hits if mnem in softwmma_mnems
                     else wm_hits)[ins.get("address")] = \
                        sw_hits.get(ins.get("address"), 0) + 1 \
                        if mnem in softwmma_mnems else 1
            core.step()
            if core.terminated:
                outcome = ("END", core.steps)
                break
            if len(core.g_ops) > events_cap:
                outcome = ("EVENTCAP", core.steps)
                break
        if outcome is None:
            outcome = ("STEPLIMIT", core.steps)
    except Halt as h:
        outcome = (h.kind, core.steps, getattr(h, "info", None))
    except NotImpl as e:
        outcome = ("NOTIMPL", core.steps, str(e))
    # ---- post analysis ----
    windows = [(KERNARG - 0x1000, KERNARG + 0x1000),
               (PACKET - 0x100, PACKET + 0x100)]
    for k in range(N_SLOTS):
        windows.append((SLOT + k * STRIDE, SLOT + k * STRIDE + STRIDE))
    oob = []
    for is_store, addr, nb, site in core.g_ops:
        if not any(lo <= addr < hi for lo, hi in windows):
            oob.append((is_store, addr, nb, site))
            break
    per_slot = {}
    for is_store, addr, nb, site in core.g_ops:
        for k in range(N_SLOTS):
            if SLOT + k * STRIDE <= addr < SLOT + (k + 1) * STRIDE:
                base = SLOT + k * STRIDE + GUARD
                off = addr - base
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
                mn = min(x[0] for x in v)
                mx = max(x[1] for x in v)
                sites = {}
                for off0, off1, nb, site in v:
                    sites.setdefault(site, {"n": 0, "widths": set(),
                                            "min": off0, "max": off1})
                    s = sites[site]
                    s["n"] += 1
                    s["widths"].add(nb)
                    s["min"] = min(s["min"], off0)
                    s["max"] = max(s["max"], off1)
                row[kind] = {"count": len(v), "min_offset": mn,
                             "max_offset": mx, "span": mx - mn,
                             "sites": {f"{a:#x}": {
                                 "n": s["n"],
                                 "widths": sorted(s["widths"]),
                                 "min": s["min"], "max": s["max"]}
                                 for a, s in sites.items()}}
            else:
                row[kind] = {"count": 0}
        slot_sum[k] = row
    ds_sum = None
    if core.ds_ops:
        mn = min(a for _, a, _, _ in core.ds_ops)
        mx = max(a + nb for _, a, nb, _ in core.ds_ops)
        ds_sum = {"count": len(core.ds_ops),
                  "min_offset": mn, "max_offset": mx,
                  "stores": sum(1 for s, *_ in core.ds_ops if s)}
    if dump_path:
        with open(dump_path, "w", encoding="utf-8") as f:
            f.write(f"# trace {label} outcome={outcome} steps={core.steps}\n")
            for site, mnem, ops in exec_stream:
                f.write(f"{site:#08x} {mnem} {ops}\n".rstrip() + "\n")
            f.write("# slot2 stores (addr,width,site) then ds (st,addr,nb)\n")
            for st, addr, nb, site in core.g_ops:
                if SLOT + 2 * STRIDE <= addr < SLOT + 3 * STRIDE:
                    f.write(f"ST2 {addr - (SLOT + 2 * STRIDE + GUARD):#x} "
                            f"w{nb} @{site:#08x}\n")
            for st, addr, nb, site in core.ds_ops:
                f.write(f"DS {'S' if st else 'L'} {addr:#x} w{nb} "
                        f"@{site:#08x}\n")
    return {
        "label": label,
        "grid": list(grid), "block": list(block), "wg": list(wg),
        "wavebase": wavebase, "split_count": split_count,
        "outcome": outcome, "steps": core.steps, "branches": n_br,
        "barriers": n_bar, "oob_access": oob,
        "softwmma_sites_hit": sorted(sw_hits),
        "wmma_sites_hit": sorted(wm_hits),
        "slot_access": slot_sum, "ds_range": ds_sum,
        "snaps": snaps if snap_sites else None,
        "undef_s_reads": sorted(core.undef_s) if hasattr(core, "undef_s")
        else [],
        "gap_reads": [],
    }


def explore():
    """Probe slot roles: which slots must hold small counts vs pointers for
    the fragment (dot-cluster) path to run; snapshot guard scalars."""
    dw_e = dw16(ENT_CO, KERNEL)
    prog_e, rows_e, idx_e = slice_program(ENT_DIS, KERNEL)
    ptrs = [SLOT + k * STRIDE + GUARD for k in range(N_SLOTS)]
    snaps = {0x4a540: [1, 12, 18, 20, 22, 3, 13, 24],
             0x4accc: [20, 22, 26, 28, 24],
             0x4aea4: [18, 20, 24, 29, 30, 33, 34, 14],
             0x4a590: [18, 24, 16, 20]}
    cases = [
        ("s4ptr",   (1, 1, 1), (256, 1, 1), (0, 0, 0), 0, 1,
         list(ptrs)),
        ("s4=0",    (1, 1, 1), (256, 1, 1), (0, 0, 0), 0, 1,
         [ptrs[0], ptrs[1], ptrs[2], ptrs[3], 0]),
        ("s4=32",   (1, 1, 1), (256, 1, 1), (0, 0, 0), 0, 1,
         [ptrs[0], ptrs[1], ptrs[2], ptrs[3], 32]),
        ("s4=256",  (1, 1, 1), (256, 1, 1), (0, 0, 0), 0, 1,
         [ptrs[0], ptrs[1], ptrs[2], ptrs[3], 256]),
        ("s4=256_gx1", (2, 1, 1), (256, 1, 1), (1, 0, 0), 0, 1,
         [ptrs[0], ptrs[1], ptrs[2], ptrs[3], 256]),
        ("s4=256_b32", (1, 1, 1), (32, 1, 1), (0, 0, 0), 0, 1,
         [ptrs[0], ptrs[1], ptrs[2], ptrs[3], 256]),
    ]
    results = {}
    for c in cases:
        label, grid, block, wg, wb, sp, sv = c
        r = run_trace(prog_e, dw_e, f"ef-{label}", grid, block, wg, wb, sp,
                      slot_vals=sv, snap_sites=snaps)
        results[label] = r
        o = r["outcome"]
        print(f"ef-{label}: outcome={o} steps={r['steps']} "
              f"br={r['branches']} sw_sites={len(r['softwmma_sites_hit'])} "
              f"oob={r['oob_access']}")
        for k in sorted(r["slot_access"]):
            s = r["slot_access"][k]
            ld = s["ld"]; st = s["st"]
            print(f"   slot{k}: ld={ld['count']:5d} "
                  f"[{ld.get('min_offset', '-')}:{ld.get('max_offset', '-')}]"
                  f" st={st['count']:5d} "
                  f"[{st.get('min_offset', '-')}:{st.get('max_offset', '-')}]")
        for site, snaps_at in r["snaps"].items():
            if snaps_at:
                print(f"   snap {site:#x}: "
                      f"last={[hex(v) if isinstance(v, int) else v for v in snaps_at[-1]]}"
                      f" n={len(snaps_at)}")
    with open(os.path.join(OUTD, "p14d11_explore.json"), "w",
              encoding="utf-8") as f:
        json.dump(results, f, indent=1, default=str)
    print("wrote", os.path.join(OUTD, "p14d11_explore.json"))


def main():
    import sys as _s
    if len(_s.argv) > 1 and _s.argv[1] == "explore":
        explore()
        return
    dw_e = dw16(ENT_CO, KERNEL)
    prog_e, rows_e, idx_e = slice_program(ENT_DIS, KERNEL)
    plan_e = entry_plan(dw_e)
    print(f"entry-fixed conv_splitk: {len(prog_e)} prog sites, "
          f"plan={P8.expected_layout_str(plan_e)}")
    n_sw = sum(1 for r in rows_e if "dot" in r["mnemonic"])
    print(f"soft-WMMA dot mnemonics in stream: {n_sw}")
    cases = [
        # label            grid      block       wg        wave split
        ("P1b256w0", (1, 1, 1), (256, 1, 1), (0, 0, 0), 0, 1),
        ("P1b256w7", (1, 1, 1), (256, 1, 1), (0, 0, 0), 224, 1),
        ("P1b32w0",  (1, 1, 1), (32, 1, 1),  (0, 0, 0), 0, 1),
        # conservative range probes (NOT physical launch geometry)
        ("Xgx1",     (2, 1, 1), (32, 1, 1),  (1, 0, 0), 0, 1),
        ("Xgy1",     (1, 2, 1), (32, 1, 1),  (0, 1, 0), 0, 1),
        ("Xs2",      (1, 1, 1), (32, 1, 1),  (0, 0, 0), 0, 2),
    ]
    results = {}
    for c in cases:
        label, grid, block, wg, wb, sp = c
        r = run_trace(prog_e, dw_e, f"ef-{label}", grid, block, wg, wb, sp,
                      dump_path=(os.path.join(OUTD, f"trace_{label}.txt")
                                 if label in ("P1b256w0", "P1b32w0")
                                 else None))
        results[f"ef-{label}"] = r
        o = r["outcome"]
        print(f"ef-{label}: outcome={o} steps={r['steps']} "
              f"br={r['branches']} bar={r['barriers']} "
              f"sw_sites={len(r['softwmma_sites_hit'])} "
              f"oob={r['oob_access']}")
        for k in sorted(r["slot_access"]):
            s = r["slot_access"][k]
            ld = s["ld"]; st = s["st"]
            print(f"   slot{k}: ld={ld['count']:5d} "
                  f"[{ld.get('min_offset', '-')}:{ld.get('max_offset', '-')}]"
                  f" st={st['count']:5d} "
                  f"[{st.get('min_offset', '-')}:{st.get('max_offset', '-')}]")
        if r["ds_range"]:
            print(f"   ds: {r['ds_range']}")
    # side-by-side original on the primary candidate
    dw_o = dw16(ORIG_OBJ, KERNEL)
    try:
        prog_o, rows_o, idx_o = slice_program(ORIG_DIS, KERNEL)
        ro = run_trace(prog_o, dw_o, "orig-P1b256w0", (1, 1, 1),
                       (256, 1, 1), (0, 0, 0), 0, 1)
        results["orig-P1b256w0"] = ro
        print(f"orig-P1b256w0: outcome={ro['outcome']} "
              f"steps={ro['steps']} br={ro['branches']} "
              f"wmma_sites={len(ro['wmma_sites_hit'])}")
    except Exception as e:  # informational only
        print("orig side-by-side skipped:", e)
    with open(os.path.join(OUTD, "p14d11_emulation.json"), "w",
              encoding="utf-8") as f:
        json.dump(results, f, indent=1, default=str)
    print("wrote", os.path.join(OUTD, "p14d11_emulation.json"))


if __name__ == "__main__":
    main()
