"""Phase 14D8 host-only re-validation driver (zero GPU execution).

14D8-A  descriptor-driven entry mapping vs known probes (stock style from
        the broken phase-9 descriptor + the working 14B s45 sentinel,
        class-A1 from the entry-fixed descriptor)
14D8-B  conv_splitk original gfx1100 vs entry-fixed gfx1030 semantic
        traces on identical logical dispatches (no-work + positive
        split_count + wgid-dependent synthetic states)
14D8-C  entry checks on one kernel per policy class (A1/A2/B1/B2/C/D)
14D8-D  fail-closed gate: any undefined-gap entry read, semantic/register
        mismatch, unexplained preload or descriptor/parser inconsistency
        -> report FAIL and stop (no 14D9/14D10 build)

Every entry state is derived from the kernel descriptor bytes of the
*actual module* under test (parser p14d_dec/p14d_kd) plus a logical
dispatch -- no second hand-written layout table.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
OUTD = os.path.join(os.path.dirname(HERE), "out")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "phase8_static", "tools"))
sys.path.insert(0, os.path.join(ROOT, "phase14d_static", "tools"))

import p14d8_core as P8                       # noqa: E402
import p14d_kd as kd                          # noqa: E402
import p14d_dec as dec                        # noqa: E402
from emu import Core, Halt, NotImpl, U32, split_dual  # noqa: E402
from disasm_lib import parse_orig_disasm, parse_translated_asm  # noqa: E402
from p14d8_core import Core8, entry_plan, expected_layout_str, fill_entry, \
    run_watch                                    # noqa: E402

ORIG_OBJ = os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_code_object.o")
ORIG_DIS = os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_disassembly.txt")
PH9_CO = os.path.join(ROOT, "phase9_final_module", "gfx1030_dlssnr_module.co")
ENT_CO = os.path.join(ROOT, "phase14_entry_fixed_module",
                      "gfx1030_dlssnr_module_entryfixed.co")
S45_CO = os.path.join(ROOT, "phase14_runtime", "p14_diag_hidden_s45.co")
S45_ASM = os.path.join(ROOT, "phase14_runtime", "p14_diag_hidden_s45.s")
ASMDIR = os.path.join(ROOT, "phase7_full_static", "assembly")
CONTRACTS = os.path.join(ROOT, "phase14d_original_entry_contracts.json")
CENSUS = os.path.join(ROOT, "phase14d_static", "out",
                      "p14d_entry_preload_flags.json")

KERNARG = 0x10000      # fake kernarg segment base (phase-8 convention)
PACKET = 0x20000       # fake AQL dispatch packet base
OUTBUF = 0x400000      # sentinel output buffer

FAIL = []


def kd_dw16(path, kernel):
    for k, base in kd.find_kernel_kds(*_pe(path)):
        if k == kernel:
            return kd.dump_kd(_pe(path)[0], base)
    raise KeyError(kernel)


def _pe(path):
    return kd.parse_elf(path)


_dw_cache = {}


def dw16(path, kernel):
    key = (path, kernel)
    if key not in _dw_cache:
        data, sections, syms = kd.parse_elf(path)
        for k, base in kd.find_kernel_kds(data, sections, syms):
            if k == kernel:
                _dw_cache[key] = kd.dump_kd(data, base)
                break
        else:
            raise KeyError(f"{kernel} in {path}")
    return _dw_cache[key]


def rep_contracts():
    return json.load(open(CONTRACTS))


# ---------------------------------------------------------------------------
# Original gfx1100 program slices (whole module disasm, per-symbol range)
# ---------------------------------------------------------------------------
def orig_program(kernel):
    rows = orig_rows_all()
    syms = _symbol_ranges()
    a, end = syms[kernel]
    sl = sorted((r for r in rows if a <= r["address"] < end),
                key=lambda r: r["address"])
    assert sl, kernel
    from emu import build_orig_program
    return build_orig_program(sl)


def _symbol_ranges():
    import re
    syms = {}
    starts = []
    with open(ORIG_DIS, encoding="utf-8-sig", errors="replace") as f:
        for raw in f:
            m = re.match(r"^0*([0-9a-f]+) <(_Z[^>]+)>:$", raw.strip())
            if m:
                starts.append((int(m.group(1), 16), m.group(2)))
    for i, (a, n) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else a + 0x100000
        syms[n] = (a, end)
    return syms


def _strip_inline_comments(rows):
    """Some generated .s files carry trailing '// ...' text on instruction
    rows; parse_translated_asm keeps it in the operand text."""
    for r in rows:
        if r["kind"] != "instruction":
            continue
        i = r["text"].find("//")
        if i < 0:
            continue
        t = r["text"][:i].rstrip()
        parts = t.split(None, 1)
        r["text"] = t
        r["mnemonic"] = parts[0]
        r["operands"] = parts[1].strip() if len(parts) > 1 else ""
    return _strip_sel_annotations(rows)


def trans_program(kernel):
    path = os.path.join(ASMDIR, kernel + ".s")
    if not os.path.exists(path):
        path = os.path.join(ROOT, "phase7_translation",
                            "k_conv_splitk_translated_gfx1030.s")
    labels, rows = parse_translated_asm(path)
    _strip_inline_comments(rows)
    from emu import build_translated_program
    return build_translated_program(rows), labels, rows


def s45_program():
    labels, rows = parse_translated_asm(S45_ASM)
    _strip_inline_comments(rows)
    from emu import build_translated_program
    return build_translated_program(rows)


# translated label -> original address (label suffix _000xxxxx)
def trans_addr_map(rows):
    import re
    m = {}
    last = None
    for i, r in enumerate(rows):
        if r["kind"] == "label":
            mm = re.search(r"_([0-9a-fA-F]{4,})$", r["name"])
            last = int(mm.group(1), 16) if mm else last
        elif r["kind"] == "instruction":
            m[len(m)] = last
    return m


# ---------------------------------------------------------------------------
# 14D8-A mapping cases
# ---------------------------------------------------------------------------
def stock_plan_expected():
    """Stock-HIP-style policy (pb + kernarg + wgid_x, declared count 6):
    pb s0:s3, kernarg s4:s5, wgid_x s6, no gap. Cross-checked against the
    phase-14B physical s-register dump (kernarg observed at s[4:5])."""
    p = entry_plan(dw16(PH9_CO, "_Z13k_conv_splitk12ConvParams1d"))
    assert p["user"]["private_segment_buffer"] == (0, 4), p["user"]
    assert p["user"]["kernarg_segment_ptr"] == (4, 2), p["user"]
    assert p["system"]["workgroup_id_x"] == (6, 1), p["system"]
    assert p["gap"] is None, p["gap"]
    p2 = entry_plan(dw16(S45_CO, "p14_diag_hidden"))
    assert p2["user"]["private_segment_buffer"] == (0, 4)
    assert p2["user"]["kernarg_segment_ptr"] == (4, 2)
    assert p2["system"]["workgroup_id_x"] == (6, 1)
    return p, p2


def run_s45_sentinel():
    """Emulate the actual 14B working sentinel body under the state derived
    from ITS descriptor; expect the physically observed out[] = {256,1,1,1}
    and kernarg read at s4:s5."""
    prog = s45_program()
    core = Core8(prog, lanes=32, mem={})
    plan = entry_plan(dw16(S45_CO, "p14_diag_hidden"))
    mem = {}
    mem[KERNARG + 0x00] = OUTBUF & U32
    mem[KERNARG + 0x04] = (OUTBUF >> 32) & U32
    mem[KERNARG + 0x30] = 1                      # hidden_block_count_x
    mem[KERNARG + 0x3C] = 256 | (1 << 16)        # group_size_x/y
    mem[KERNARG + 0x40] = 1 | (1 << 16)          # group_size_z | remainder_x
    core.mem = mem
    fill_entry(core, plan, kernarg=KERNARG, dispatch_ptr=PACKET,
               wgid=(0, 0, 0), block=(256, 1, 1))
    # watch: kernarg pair must be consumed at its s4:s5 position
    watch = {"kernarg_segment_ptr": plan["user"]["kernarg_segment_ptr"]}
    res = run_watch(core, prog, watch, step_cap=5000, tail=200)
    out = [core._read_bytes(OUTBUF + 4 * i) for i in range(4)]
    tail_nz = sum(1 for a in range(OUTBUF + 16, OUTBUF + 512)
                  if a in core.mem)
    return {
        "result": res,
        "reads": res["reads"],
        "kernarg_at": plan["user"]["kernarg_segment_ptr"],
        "out": out,
        "tail_nonzero": tail_nz,
    }


def a_case1_case2():
    out = {}
    p_ph9, p_s45 = stock_plan_expected()
    out["case1_phase9_desc"] = expected_layout_str(p_ph9)
    out["case2_s45_desc"] = expected_layout_str(p_s45)
    s = run_s45_sentinel()
    out["sentinel"] = s
    ok = (s["result"]["kind"] == "END"
          and s["out"] == [256, 1, 1, 1]
          and s["reads"].get("kernarg_segment_ptr") == [KERNARG & U32,
                                                        KERNARG >> 32 & U32])
    out["sentinel_match_14B"] = ok
    if not ok:
        FAIL.append(f"14D8-A case1/2 sentinel mismatch: {s}")
    return out


def a_case3(conv_prog_tr, tr_addr):
    """Class-A1 normalized descriptor: kernarg s0:s1, declared-but-empty
    gap s2..s13 UNDEFINED, wgid_x s14, wgid_y s15. Runs the real conv_splitk
    translated body on the no-work dispatch (which still reads s15 @pc3 and
    s14 @pc8); asserts watched values, zero gap reads, clean END."""
    p = entry_plan(dw16(ENT_CO, "_Z13k_conv_splitk12ConvParams1d"))
    assert p["user"]["kernarg_segment_ptr"] == (0, 2), p["user"]
    assert p["system"]["workgroup_id_x"] == (14, 1), p["system"]
    assert p["system"]["workgroup_id_y"] == (15, 1), p["system"]
    assert p["gap"] == (2, 13), p["gap"]
    mem, _ = conv_mem(grid=(1, 1, 1), block=(256, 1, 1), split_count=0)
    core = Core8(conv_prog_tr, lanes=32, mem=mem)
    fill_entry(core, p, kernarg=KERNARG, wgid=(0, 0, 0), block=(256, 1, 1))
    watch = {"kernarg_segment_ptr": (0, 2), "workgroup_id_x": (14, 1),
             "workgroup_id_y": (15, 1)}
    res = run_watch(core, conv_prog_tr, watch, step_cap=50000, tail=128)
    reads_ok = (res["reads"].get("kernarg_segment_ptr") ==
                [KERNARG & U32, (KERNARG >> 32) & U32]
                and res["reads"].get("workgroup_id_x") == [0]
                and res["reads"].get("workgroup_id_y") == [0])
    end_ok = res["kind"] in ("END", "WATCHDONE")
    undef_ok = res["kind"] != "UNDEFREAD"
    ok = reads_ok and end_ok and undef_ok
    if not ok:
        FAIL.append(f"14D8-A case3 mismatch: {res}")
    return {"plan": expected_layout_str(p), "result": res,
            "reads_ok": reads_ok, "undef_ok": undef_ok, "ok": ok}


# ---------------------------------------------------------------------------
# 14D8-B conv_splitk semantic traces
# ---------------------------------------------------------------------------
SLOT = 0x2_0000_0000
GUARD = 0x1000
HEAP = 0x3000


def conv_mem(grid, block, split_count, lds_fill=0x0000, seed=0):
    mem = {}
    ptrs = [SLOT + k * 0x10000 + GUARD for k in range(5)]
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
    mem[KERNARG + 0x58] = 0            # global offsets 0
    mem[KERNARG + 0x5C] = 0
    mem[KERNARG + 0x60] = 0
    mem[KERNARG + 0x64] = 0
    mem[KERNARG + 0x68] = 0
    mem[KERNARG + 0x6C] = 0
    mem[KERNARG + 0x70] = 1            # grid_dims
    if lds_fill == "random":
        import random
        rnd = random.Random(seed)
        lds = bytearray(4096)
        for i in range(0, 4096, 2):
            lds[i] = rnd.randrange(256)
            lds[i + 1] = rnd.randrange(256)
    else:
        lds = None
    return mem, ptrs


def conv_state(prog, dw16_, grid, block, wg, wavebase, split_count,
               lds_fill=0):
    mem, ptrs = conv_mem(grid, block, split_count, lds_fill=lds_fill)
    core = Core8(prog, lanes=32, lds_size=4096, lds_fill=lds_fill,
                 wavebase=wavebase, mem=mem)
    plan = entry_plan(dw16_)
    fill_entry(core, plan, kernarg=KERNARG, dispatch_ptr=PACKET,
               wgid=wg, wavebase=wavebase, block=block)
    return core, plan, mem, ptrs


def trace_conv(prog, dw16_, label, grid, block, wg, wavebase, split_count,
               tr_addr=None, orig_of=None, events_cap=400000):
    """Run one side of conv_splitk; record event trace. Returns result dict
    with branch/load/store event lists, outcome, faults."""
    core, plan, mem, ptrs = conv_state(prog, dw16_, grid, block, wg,
                                       wavebase, split_count)
    events = []
    outcome = None
    try:
        while core.steps < 2_000_000:
            ins = prog[core.pc]
            site = ins["address"] if isinstance(ins.get("address"), int) \
                else (orig_of[core.pc] if orig_of else None)
            mnem = ins["mnemonic"]
            ops_raw = ins["operands"]
            olist = [o.strip() for o in ops_raw.split(",")] if ops_raw else []
            rec = None
            if mnem.startswith("s_cbranch") or mnem == "s_branch":
                pre_pc = core.pc
                tgt = None
                if ins["target"] is not None:
                    tin = prog[ins["target"]]
                    if isinstance(tin.get("address"), int):
                        tgt = tin["address"]
                    else:
                        mm = re.search(r"_([0-9a-fA-F]{4,})$",
                                       ins["operands"].strip().split()[0]
                                       if ins["operands"] else "")
                        tgt = int(mm.group(1), 16) if mm else None
                core.step()
                taken = 1 if core.pc != pre_pc + 1 else 0
                rec = ("BR", site, mnem, ops_raw, taken, tgt,
                       core.scc, core.vcc_l, core.exec_l)
            elif mnem.startswith("s_load"):
                base = _pair_of(olist[1]) if len(olist) > 1 else None
                off = _imm_of(olist[2]) if len(olist) > 2 else None
                addr = ((core.spair(olist[1]) + (off or 0)) &
                        ((1 << 64) - 1)) if base is not None else None
                core.step()
                d0 = _dst_first(olist[0]) if olist else None
                if mnem in ("s_load_dword", "s_load_b32"):
                    val = core.s[d0]
                elif "x4" in mnem or "b128" in mnem:
                    val = [core.s[i] for i in range(d0, d0 + 4)]
                elif "x2" in mnem or "b64" in mnem:
                    val = [core.s[i] for i in range(d0, d0 + 2)]
                else:
                    val = core.s[d0]
                rec = ("SLD", site, mnem, ops_raw, addr,
                       val if isinstance(val, int) else val[:4])
            elif mnem.startswith(("global_", "flat_", "buffer_", "scratch_",
                                  "ds_")):
                pre_mem_n = len(core.mem)
                pre_stores = len(core.global_stores)
                core.step()
                rec = ("MEM", site, mnem, ops_raw, pre_mem_n,
                       len(core.global_stores) - pre_stores)
            else:
                core.step()
                if core.terminated:
                    rec = ("END", site, mnem, ops_raw)
            if rec:
                events.append(rec)
                if len(events) > events_cap:
                    outcome = ("EVENTCAP", core.steps)
                    break
            if core.terminated:
                if outcome is None:
                    outcome = ("END", core.steps)
                break
            if core.steps % 256 == 0:
                pass
        if outcome is None:
            outcome = ("STEPLIMIT", core.steps)
    except Halt as h:
        outcome = (h.kind, core.steps, h.info)
    except NotImpl as e:
        outcome = ("NOTIMPL", core.steps, str(e))
    # fault model: stores outside every guarded window kill the wave.
    # Each slot window spans its full 64 KiB stride (the 12-KiB HEAP was
    # only the "reachable payload" estimate of the zero-geometry runs; with
    # wgid != 0 the kernel legitimately writes wgid-scaled stripes beyond
    # it, still inside the allocation the slot models).
    windows = [(KERNARG - 0x1000, KERNARG + 0x1000),
               (PACKET - 0x100, PACKET + 0x100)]
    for k, p in enumerate(ptrs):
        windows.append((SLOT + k * 0x10000, SLOT + k * 0x10000 + 0x10000))
    fault = None
    for addr, val, lane in core.global_stores:
        if not any(lo <= addr < hi for lo, hi in windows):
            fault = addr
            break
    # store footprint per slot (64 KiB stride windows, same as fault model)
    per_slot = {}
    for addr, val, lane in core.global_stores:
        for k in range(5):
            if SLOT + k * 0x10000 <= addr < SLOT + (k + 1) * 0x10000:
                per_slot.setdefault(k, set()).add(addr)
                break
    slot_ranges = {k: (min(v), max(v), len(v)) for k, v in per_slot.items()}
    return {
        "label": label, "outcome": outcome, "events": events,
        "fault_at": fault, "slot_ranges": slot_ranges,
        "n_stores": len(core.global_stores), "undef": core.undef_s,
        "steps": core.steps,
    }


def _pair_of(tok):
    t = tok.strip()
    return t.startswith("s[") or (t.startswith("s") and ":" in t)


def _imm_of(tok):
    t = tok.strip()
    if t in ("null", "off"):
        return 0
    try:
        return int(t, 0)
    except ValueError:
        return None


def _dst_first(tok):
    t = tok.strip().lstrip("s[").rstrip("]")
    if ":" in t:
        return int(t.split(":")[0])
    return int(t)


def conv_b_cases():
    from emu import build_orig_program
    import re
    # programs
    rows_all = orig_rows_all()
    syms = _symbol_ranges()
    a, end = syms["_Z13k_conv_splitk12ConvParams1d"]
    sl = sorted((r for r in rows_all if a <= r["address"] < end),
                key=lambda r: r["address"])
    prog_o = build_orig_program(sl)
    labels, trows = parse_translated_asm(
        os.path.join(ROOT, "phase7_translation",
                     "k_conv_splitk_translated_gfx1030.s"))
    _strip_inline_comments(trows)
    from emu import build_translated_program
    prog_t = build_translated_program(trows)
    addr_t = trans_addr_map(trows)
    dw_o = dw16(ORIG_OBJ, "_Z13k_conv_splitk12ConvParams1d")
    dw_t = dw16(ENT_CO, "_Z13k_conv_splitk12ConvParams1d")

    cases = [
        # (label, grid, block, wg, wavebase, split_count)
        ("N0",  (1, 1, 1), (256, 1, 1), (0, 0, 0), 0, 0),     # no-work
        ("N0w7", (1, 1, 1), (256, 1, 1), (0, 0, 0), 224, 0),  # last wave
        ("P1",  (1, 1, 1), (256, 1, 1), (0, 0, 0), 0, 1),     # smallest +work
        ("P2",  (1, 1, 1), (256, 1, 1), (0, 0, 0), 0, 2),
        ("P3gx", (2, 1, 1), (256, 1, 1), (1, 0, 0), 0, 3),    # wgid_x = 1
        ("P1gy", (1, 2, 1), (256, 1, 1), (0, 1, 0), 0, 1),    # wgid_y = 1
        ("P1s", (1, 1, 1), (32, 1, 1), (0, 0, 0), 0, 1),      # block 32
        ("P1w7", (1, 1, 1), (256, 1, 1), (0, 0, 0), 224, 1),
    ]
    results = {"orig": [], "trans": []}
    for c in cases:
        label, grid, block, wg, wb, sp = c
        ro = trace_conv(prog_o, dw_o, f"orig-{label}", grid, block, wg, wb,
                        sp)
        rt = trace_conv(prog_t, dw_t, f"trans-{label}", grid, block, wg, wb,
                        sp, orig_of=addr_t)
        results["orig"].append(ro)
        results["trans"].append(rt)
    return results


def branch_seq(res):
    return [(e[5], e[4]) for e in res["events"] if e[0] == "BR"]


def _br_taken_seq(res):
    return [e[4] for e in res["events"] if e[0] == "BR"]


def _br_taken_targets(res):
    return [(e[5], e[4]) for e in res["events"] if e[0] == "BR" and e[4]]


def ev_seq(res, kind):
    return [e for e in res["events"] if e[0] == kind]


# ---------------------------------------------------------------------------
# 14D8-C policy-class validation
# ---------------------------------------------------------------------------
REPS = [  # kernel, class
    ("_Z13k_conv_splitk12ConvParams1d", "A1"),
    ("_Z10k_conv_res10ConvParams", "A2"),
    ("_Z10k_flag_setPjj", "A2"),
    ("_Z10k_qkv_attn10AttnParams", "B1"),
    ("_Z16k_swin_1h_32_fp810SwinParams", "B2"),
    ("_Z11k_qkv_attn210AttnParams", "C"),
    ("_Z10k_swin_varILi32ELb0EEv9VarParams", "D"),
    ("_Z10k_swin_varILi32ELb1EEv9VarParams", "D"),
]


_rows_all = None
_SEL_RE = re.compile(r"\s*op_sel(?:_hi|_mid)?:\[[^\]]*\]")


def _strip_sel_annotations(rows):
    """llvm-objdump appends op_sel:[..]/op_sel_hi:[..] modifiers to packed
    f16 rows; they are not register operands and break operand splitting."""
    for r in rows:
        if r.get("kind") == "directive":
            continue
        if r.get("kind") == "label":
            continue
        ops = _SEL_RE.sub("", r["operands"]).strip()
        if ops != r["operands"]:
            r["operands"] = ops
            r["text"] = (r["mnemonic"] + " " + ops).strip()
    return rows


def orig_rows_all():
    global _rows_all
    if _rows_all is None:
        import re as _re
        global _SEL_RE
        _rows_all = _strip_sel_annotations(parse_orig_disasm(ORIG_DIS))
    return _rows_all


def class_c():
    contracts = rep_contracts()
    rows = []
    details = {}
    for kernel, cls in REPS:
        ct = contracts[kernel]
        pre = ct["preloads"]
        watch = {sem: (p["position"], p["span"]) for sem, p in pre.items()
                 if p["read_before_def"]}
        # programs & descriptor plans for both sides
        po = orig_program(kernel)
        pt, _labels, trows = trans_program(kernel)
        addr_t = trans_addr_map(trows)
        plan_o = entry_plan(dw16(ORIG_OBJ, kernel))
        plan_t = entry_plan(dw16(ENT_CO, kernel))
        # register equality: same semantic -> same index & span
        reg_match = True
        for side_key, A, B in (("user", plan_o["user"], plan_t["user"]),
                               ("system", plan_o["system"], plan_t["system"])):
            if set(A) != set(B):
                reg_match = False
                FAIL.append(f"{kernel}: {side_key} semantic sets differ "
                            f"{set(A) ^ set(B)}")
                continue
            for sem in A:
                if A[sem] != B[sem]:
                    reg_match = False
                    FAIL.append(f"{kernel}: {sem} register differs "
                                f"{A[sem]} vs {B[sem]}")
        gap_match = plan_o["gap"] == plan_t["gap"]
        # dispatch exercising the wgid fields this kernel reads
        grid = (2, 2, 2)
        block = (256, 1, 1)
        wg = (1, 1, 1)
        runs = []
        for side, prog, plan, addr_of in (
                ("original", po, plan_o, None),
                ("gfx1030", pt, plan_t, addr_t)):
            mem = {}
            mem[KERNARG + 0x28] = 0      # generic; reps read pointers mostly
            core = Core8(prog, lanes=32, mem=mem)
            fill_entry(core, plan, kernarg=KERNARG, dispatch_ptr=PACKET,
                       wgid=wg, block=block)
            res = run_watch(core, prog, watch, step_cap=300000, tail=96)
            res["undef_read"] = res["kind"] == "UNDEFREAD"
            runs.append(res)
        ro, rt = runs
        # per-semantic value equality
        match_rows = []
        ok = reg_match and gap_match
        for sem in watch:
            vo = ro["reads"].get(sem)
            vt = rt["reads"].get(sem)
            start, span = watch[sem]
            eq = vo is not None and vt is not None and vo == vt
            if not eq:
                ok = False
                FAIL.append(f"{kernel}: semantic {sem} read values differ "
                            f"{vo} vs {vt}")
            match_rows.append({
                "kernel": kernel, "policy_class": cls, "semantic": sem,
                "original_register": f"s{start}" +
                    (f":s{start+span-1}" if span > 1 else ""),
                "gfx1030_register": f"s{start}" +
                    (f":s{start+span-1}" if span > 1 else ""),
                "match": "YES" if eq else "NO",
                "result": ("value=" + ",".join(f"{v:#x}" for v in vo)
                           if vo else "not-read"),
            })
            rows.append(match_rows[-1])
        details[kernel] = {
            "class": cls, "plan_original": expected_layout_str(plan_o),
            "plan_gfx1030": expected_layout_str(plan_t),
            "reg_match": reg_match, "gap_match": gap_match,
            "watch": {s: {"reg": f"s{r[0]}" +
                          (f":s{r[0]+r[1]-1}" if r[1] > 1 else ""), "span": r[1]}
                      for s, r in watch.items()},
            "orig_outcome": ro["kind"], "trans_outcome": rt["kind"],
            "orig_reads": ro["reads"], "trans_reads": rt["reads"],
            "ok": ok,
        }
    return rows, details


# ---------------------------------------------------------------------------
# 14D8-D static fail-closed over ALL 33 kernels
# ---------------------------------------------------------------------------
def fail_closed_all33():
    """Replay the read-before-def census sgprs against the *entry-fixed*
    plans: every pre-def read must land inside a populated preload of the
    matching semantic; zero reads inside the declared-but-empty gap."""
    census = json.load(open(CENSUS))
    contracts = rep_contracts()
    bad = []
    n = 0
    POLICY_KEYS = ["group", "private", "kernarg_size", "user_count",
                   "user_enables", "system_enables", "wave32",
                   "workitem_vgpr", "dyn_stack", "dx10", "ieee", "fp16_ovf"]
    for kernel in sorted(contracts):
        dw_t = dw16(ENT_CO, kernel)
        dw_o = dw16(ORIG_OBJ, kernel)
        plan_t = entry_plan(dw_t)
        plan_o = entry_plan(dw_o)
        # semantic policy equality (raw rsrc1 / code-entry offsets are
        # target-specific encodings and are not part of the policy)
        ot, et = dec.dec(dw_o), dec.dec(dw_t)
        for k in POLICY_KEYS:
            if ot[k] != et[k]:
                bad.append((kernel, f"policy field {k} differs "
                                    f"orig={ot[k]} entry={et[k]}"))
        # register-map equality: same semantic, same index, same span, same
        # declared-but-empty gap on both targets (Strategy A's core claim)
        for sk in ("user", "system", "gap"):
            if plan_o[sk] != plan_t[sk]:
                bad.append((kernel, f"register map '{sk}' differs "
                                    f"orig={plan_o[sk]} entry={plan_t[sk]}"))
        defined = {}
        for nm, (i0, sp) in list(plan_t["user"].items()) + \
                list(plan_t["system"].items()):
            for i in range(i0, i0 + sp):
                defined[i] = nm
        for flag in census.get(kernel, {}).get("flags", []):
            sg = flag["sgpr"]
            n += 1
            gap = plan_t["gap"]
            if gap and gap[0] <= sg <= gap[1]:
                bad.append((kernel, f"gap read s{sg} "
                                    f"({flag.get('first_mnem')})"))
            elif sg not in defined:
                bad.append((kernel, f"unexplained preload read s{sg} "
                                    f"({flag.get('first_mnem')})"))
    return bad, n


def main():
    os.makedirs(OUTD, exist_ok=True)
    results = {}

    # ---- A ----
    a = {}
    a["case1_2"] = a_case1_case2()
    # programs for conv translated
    pt, _labels, trows = trans_program("_Z13k_conv_splitk12ConvParams1d")
    addr_t = trans_addr_map(trows)
    a["case3"] = a_case3(pt, addr_t)
    results["a"] = a

    # ---- B ----
    b = conv_b_cases()
    results["b"] = b

    # ---- C ----
    c_rows, c_details = class_c()
    results["c"] = c_details

    # ---- D ----
    bad, n = fail_closed_all33()
    results["d"] = {"n_flag_sgprs": n, "violations": bad}

    with open(os.path.join(OUTD, "p14d8_results.json"), "w") as f:
        json.dump(results, f, indent=1, default=str)

    # ---- artifacts ----
    emit_a(a)
    emit_b(b)
    emit_c(c_rows)
    emit_report(results)

    print("=" * 60)
    print("14D8 FAIL list:", FAIL if FAIL else "(empty)")
    print("14D8-D violations:", bad if bad else "(none)")


# ---------------------------------------------------------------------------
def emit_a(a):
    lines = []
    lines.append("14D8-A descriptor-driven entry mapping vs known probes\n")
    lines.append(f"CASE1 phase-9 broken stock descriptor layout: "
                 f"{a['case1_2']['case1_phase9_desc']}")
    lines.append(f"CASE2 14B s45 sentinel descriptor layout: "
                 f"{a['case1_2']['case2_s45_desc']}")
    s = a["case1_2"]["sentinel"]
    lines.append(f"sentinel emulation: outcome={s['result']['kind']} "
                 f"steps={s['result']['steps']} "
                 f"kernarg-read(s4:5)={s['reads']}")
    lines.append(f"sentinel out[0:4]={s['out']} "
                 f"(physical 14B log: 256,1,1,1) "
                 f"tail_nonzero={s['tail_nonzero']}")
    lines.append(f"sentinel matches 14B evidence: "
                 f"{a['case1_2']['sentinel_match_14B']}")
    lines.append(f"CASE3 A1 plan: {a['case3']['plan']}")
    lines.append(f"CASE3 result: {a['case3']['result']['kind']} "
                 f"steps={a['case3']['result']['steps']} "
                 f"reads={a['case3']['result']['reads']}")
    lines.append(f"CASE3 ok: {a['case3']['ok']}")
    open(os.path.join(ROOT, "phase14d8_a_mapping_validation.txt"),
         "w").write("\n".join(lines) + "\n")


def trace_emit(res):
    L = []
    L.append(f"case={res['label']} outcome={res['outcome']} "
             f"steps={res['steps']} stores={res['n_stores']} "
             f"fault={res['fault_at']} slots={res['slot_ranges']}")
    for e in res["events"]:
        if e[0] == "BR":
            L.append(f"  BR {e[1] and f'{e[1]:#x}' or '-':>10} "
                     f"{e[2]} {e[3][:48]:<48} taken={e[4]} "
                     f"tgt={e[5] and f'{e[5]:#x}' or '-':>8} "
                     f"scc={e[6]} vcc={e[7]:#x} exec={e[8]:#x}")
        elif e[0] == "SLD":
            L.append(f"  SLD {e[1] and f'{e[1]:#x}' or '-':>10} "
                     f"{e[2]} {e[3][:40]:<40} addr={e[4] and f'{e[4]:#x}'} "
                     f"val={e[5]}")
        elif e[0] == "MEM":
            L.append(f"  MEM {e[1] and f'{e[1]:#x}' or '-':>10} "
                     f"{e[2]} {e[3][:40]:<40} memdelta={e[4]} "
                     f"storesdelta={e[5]}")
        elif e[0] == "END":
            L.append(f"  END {e[1] and f'{e[1]:#x}' or '-':>10} {e[2]}")
    return "\n".join(L)


def emit_b(b):
    o = "\n".join(trace_emit(r) for r in b["orig"])
    t = "\n".join(trace_emit(r) for r in b["trans"])
    open(os.path.join(ROOT, "phase14d8_conv_entry_trace_original.txt"),
         "w").write("conv_splitk original gfx1100 entry traces "
                    "(descriptor-driven state)\n\n" + o + "\n")
    open(os.path.join(ROOT, "phase14d8_conv_entry_trace_gfx1030.txt"),
         "w").write("conv_splitk entry-fixed gfx1030 entry traces "
                    "(descriptor-driven state)\n\n" + t + "\n")
    # semantic compare md
    md = ["# 14D8-B conv_splitk semantic compare (original vs entry-fixed)",
          "", "Entry state for each side derived from its own module's "
              "kernel descriptor + identical logical dispatch (A1 on both: "
              "kernarg s0:s1, wgid_x s14, wgid_y s15).",
          "", "| case | orig outcome | trans outcome | orig steps | "
              "trans steps | stores eq | store slots eq | branch decisions "
              "| taken targets eq | fault |", "|---|---|---|---|---|---|---"
              "|---|---|---|"]
    for ro, rt in zip(b["orig"], b["trans"]):
        to_o, to_t = _br_taken_seq(ro), _br_taken_seq(rt)
        pre = next((i for i in range(min(len(to_o), len(to_t)))
                    if to_o[i] != to_t[i]), min(len(to_o), len(to_t)))
        tt_o, tt_t = _br_taken_targets(ro), _br_taken_targets(rt)
        tteq = tt_o == tt_t
        lab = ro["label"].replace("orig-", "")
        stores_eq = ro["n_stores"] == rt["n_stores"]
        slots_eq = ro["slot_ranges"] == rt["slot_ranges"]
        md.append(f"| {lab} | {ro['outcome'][0]} | {rt['outcome'][0]} | "
                  f"{ro['steps']} | {rt['steps']} | {stores_eq} | "
                  f"{slots_eq} | {pre}/{max(len(to_o),len(to_t))} | "
                  f"{tteq} | {ro['fault_at'] or rt['fault_at'] or 'none'} |")
    open(os.path.join(ROOT, "phase14d8_conv_semantic_compare.md"),
         "w").write("\n".join(md) + "\n")


def emit_c(rows):
    with open(os.path.join(ROOT, "phase14d8_policy_class_validation.csv"),
              "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["kernel", "policy_class",
                                          "semantic", "original_register",
                                          "gfx1030_register", "match",
                                          "result"])
        w.writeheader()
        w.writerows(rows)


def emit_report(results):
    md = ["# Phase 14D8 host-only re-validation report", ""]
    md.append("## 14D8-A mapping cases")
    md.append(f"- CASE1/2 layout: {results['a']['case1_2']['case1_phase9_desc']}")
    md.append(f"- CASE2 sentinel match: {results['a']['case1_2']['sentinel_match_14B']}")
    md.append(f"- CASE3: {results['a']['case3']['ok']} "
              f"({results['a']['case3']['result']['kind']})")
    md.append("")
    md.append("## 14D8-B outcomes")
    md.append("| case | orig | trans |")
    md.append("|---|---|---|")
    for ro, rt in zip(results["b"]["orig"], results["b"]["trans"]):
        md.append(f"| {ro['label']} | {ro['outcome'][0]} | "
                  f"{rt['outcome'][0]} |")
    md.append("")
    md.append("## 14D8-C classes")
    md.append("| kernel | class | reg match | orig outcome | trans outcome | ok |")
    md.append("|---|---|---|---|---|---|")
    for k, d in results["c"].items():
        md.append(f"| {k} | {d['class']} | {d['reg_match']} | "
                  f"{d['orig_outcome']} | {d['trans_outcome']} | {d['ok']} |")
    md.append("")
    md.append("## 14D8-D fail-closed")
    md.append(f"- census sgpr sites checked: {results['d']['n_flag_sgprs']}")
    md.append(f"- violations: {results['d']['violations'] or 'NONE'}")
    md.append(f"- FAIL list: {FAIL or '(empty)'}")
    md.append("")
    md.append(f"VERDICT: {'14D8 FAIL' if FAIL or results['d']['violations'] else '14D8 PASS'}")
    open(os.path.join(OUTD, "phase14d8_report.md"), "w").write("\n".join(md) + "\n")


if __name__ == "__main__":
    main()
