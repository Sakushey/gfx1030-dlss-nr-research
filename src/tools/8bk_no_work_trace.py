"""Phase 8B/8K driver: host-only symbolic no-work traces of original gfx1100
and translated gfx1030 k_conv_splitk on the historical harness state
(split_count=0, grid(1,1,1), block(256,1,1), 4096 B LDS, five guarded
12-KiB allocations, zeroed payloads, hidden kernarg region zeroed).

Varies: LDS initial content, wave (tid base), the hidden field at
kernarg+0x3c (s16 stride source), and the preloaded s[14:15] pair.
Reports termination (END), step counts, store footprints, and the visited
site set (original addresses) for CFG-equivalence comparison.

HOST-ONLY. No GPU, no HIP.
"""
import os
import sys
import random

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from disasm_lib import parse_orig_disasm, parse_translated_asm
from emu import Core, Halt, NotImpl, build_orig_program, build_translated_program

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "phase8_static", "out")

# ---------- programs ----------
orig_rows = parse_orig_disasm(os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_disassembly.txt"))
orig_rows = [r for r in orig_rows if 0x69000 <= r["address"] <= 0x6B3FF]
orig_rows.sort(key=lambda r: r["address"])
prog_orig = build_orig_program(orig_rows)

labels, trows = parse_translated_asm(
    os.path.join(ROOT, "phase7_translation", "k_conv_splitk_translated_gfx1030.s"))
prog_tr = build_translated_program(trows)

# label names carry original addresses -> per-prog-index original address
addr_of_prog = {}   # prog index -> original address (for translated: from label)
last_label = None
for i, r in enumerate(trows):
    if r["kind"] == "label":
        if r["name"].startswith(".L_kconv_"):
            last_label = int(r["name"].split("_")[-1], 16)
    elif r["kind"] == "instruction":
        addr_of_prog[len(addr_of_prog)] = last_label
tr_pc_addr = addr_of_prog  # index in prog == number of instructions seen so far


def orig_addr_for_prog_idx(prog, idx, kind):
    if kind == "orig":
        return prog[idx]["address"]
    return addr_of_prog[idx]


# ---------- memory model: harness state ----------
KERNARG = 0x1_0000  # fake kernarg base
SLOT = 0x2_0000_0000
GUARD = 0x1000
HEAP = 0x3000  # 12 KiB per slot
ALLOC_BASE = {k: SLOT + k * 0x10000 for k in range(5)}  # allocation windows


def make_mem(split_count=0, hidden_mode="zero"):
    """hidden_mode: 'zero' = runtime leaves hidden area zeroed (interpretation
    (i)); 'hip' = HIP-populated hidden args per the kernel metadata layout
    (block_count 1/1/1 @48, group_size 256/1/1 @60, remainder 1 @66, global
    offsets 0 @88, grid_dims 1 @112) - interpretation (ii)."""
    mem = {}
    ptrs = [SLOT + k * 0x10000 + GUARD for k in range(5)]
    for k, p in enumerate(ptrs):
        base = KERNARG + 8 * k
        mem[base] = p & 0xFFFFFFFF
        mem[base + 4] = (p >> 32) & 0xFFFFFFFF
    mem[KERNARG + 0x28] = split_count & 0xFFFFFFFF
    if hidden_mode == "hip":
        # layout per the ORIGINAL kernel's own metadata (msgpack .args):
        # u32 block_count_x/y/z @48/52/56; u16 group_size_x/y/z @60/62/64;
        # u16 remainder_x/y/z @66/68/70; u64 global_offset_x/y/z @88/96/104;
        # u16 grid_dims @112.  (word-addressed u32 model: each u16 in the low
        # half of its own dword; @60 the u32 covers x|y<<16.)
        mem[KERNARG + 0x30] = 1
        mem[KERNARG + 0x34] = 1
        mem[KERNARG + 0x38] = 1
        mem[KERNARG + 0x3C] = 256 | (1 << 16)   # group_size_x=256, y=1
        mem[KERNARG + 0x40] = 1                 # group_size_z u16 @64
        mem[KERNARG + 0x42] = 1                 # remainder_x @66
        mem[KERNARG + 0x44] = 1                 # remainder_y @68
        mem[KERNARG + 0x46] = 1                 # remainder_z @70
        mem[KERNARG + 0x58] = 0                 # global_offset_x low @88
        mem[KERNARG + 0x5C] = 0                 # high
        mem[KERNARG + 0x60] = 0                 # y low @96
        mem[KERNARG + 0x64] = 0
        mem[KERNARG + 0x68] = 0                 # z low @104
        mem[KERNARG + 0x6C] = 0
        mem[KERNARG + 0x70] = 1                 # grid_dims @112
    return mem, ptrs


def run_case(prog, kind, label, lds_fill, wavebase, hidden_mode, s14=0, s18=0,
             step_limit=2_000_000, seed=None, fault_model=True):
    mem, ptrs = make_mem(split_count=s18, hidden_mode=hidden_mode)
    core = Core(prog, lanes=32, lds_size=4096, lds_fill=lds_fill,
                wavebase=wavebase, mem=mem)
    core.s[0] = KERNARG & 0xFFFFFFFF
    core.s[1] = (KERNARG >> 32) & 0xFFFFFFFF
    core.s[14] = s14 & 0xFFFFFFFF
    core.s[15] = (s14 >> 32) & 0xFFFFFFFF
    if lds_fill == "random":
        if seed is None:
            seed = 0xC0FFEE
        rnd = random.Random(seed)
        for i in range(0, 4096, 2):
            core.lds[i] = rnd.randrange(256)
            core.lds[i + 1] = rnd.randrange(256)
    visited = set()
    outcome = None
    try:
        while core.steps < step_limit:
            ins = prog[core.pc]
            visited.add(orig_addr_for_prog_idx(prog, core.pc, kind))
            core.step()
        outcome = ("STEPLIMIT", core.steps)
    except Halt as h:
        outcome = (h.kind, core.steps, h.info)
    except NotImpl as e:
        outcome = ("NOTIMPL", core.steps, str(e))
    stores = core.global_stores
    # fault model: a global store outside every valid device window kills the
    # wave on real HW (GPU memory fault -> kernel can never complete)
    windows = [(KERNARG - 0x1000, KERNARG + 0x1000)] +               [(b, b + HEAP) for b in ALLOC_BASE.values()]
    fault_at = None
    for addr, val, lane in stores:
        if not any(lo <= addr < hi for lo, hi in windows):
            fault_at = addr
            break
    # classify stores per slot and containment
    per_slot = {}
    off_slot = []
    for addr, val, lane in stores:
        found = None
        for k, p in enumerate(ptrs):
            if p - GUARD <= addr < p - GUARD + HEAP:
                found = k
                break
        if found is not None:
            per_slot.setdefault(found, []).append(addr - (ptrs[found] - GUARD))
        else:
            off_slot.append(addr)
    slot_ranges = {k: (min(v), max(v)) for k, v in per_slot.items()}
    if off_slot:
        slot_ranges["OUTSIDE"] = (min(off_slot), max(off_slot), len(off_slot))
    if fault_at is not None:
        outcome = ("FAULT", core.steps, hex(fault_at))
    return {
        "label": label, "kind": kind, "lds": lds_fill, "wavebase": wavebase,
        "hidden_3c": hidden_mode, "s14": s14, "outcome": outcome,
        "stores": len(stores), "slot_ranges": slot_ranges,
        "steps": core.steps, "visited": visited,
        "exec_end": core.exec_l,
    }


CASES = []
for kind, prog in (("orig", prog_orig), ("trans", prog_tr)):
    for lds in (0x0000, 0x3C00, 0x7C00, 0x7E00, 0xFC00, "random"):
        for wb in (0, 224):
            CASES.append((prog, kind, f"{kind}-lds={lds}-wb={wb}", lds, wb, "zero", 0, 0))
# interpretation (ii): HIP-populated hidden args (group_size_x=256)
for kind, prog in (("orig", prog_orig), ("trans", prog_tr)):
    CASES.append((prog, kind, f"{kind}-hiphidden", 0x0000, 0, "hip", 0, 0))
    CASES.append((prog, kind, f"{kind}-hiphidden-wb224", 0x0000, 224, "hip", 0, 0))
# large-tid control: exit mechanism fires at first pass
for kind, prog in (("orig", prog_orig), ("trans", prog_tr)):
    CASES.append((prog, kind, f"{kind}-tid4096", 0x0000, 4096, "zero", 0, 0))

if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    results = []
    for i, (prog, kind, label, lds, wb, h3c, s14, s18) in enumerate(CASES):
        print(f"[{i+1}/{len(CASES)}] {label} ...", flush=True)
        r = run_case(prog, kind, label, lds, wb, h3c, s14, s18)
        results.append(r)
        print(f"    outcome={r['outcome'][0]:>9} steps={r['steps']:>9} "
              f"stores={r['stores']:>7} slots={r['slot_ranges']}", flush=True)
    import json
    with open(os.path.join(OUT, "8bk_trace_results.json"), "w") as f:
        json.dump([{k: v for k, v in r.items() if k != "visited"} | {"n_visited": len(r["visited"])}
                   for r in results], f, indent=1, default=str)
    # visited-site comparison for the base zero-LDS wave0 runs
    v_orig = next(r for r in results if r["label"] == "orig-lds=0-wb=0")["visited"]
    v_tr = next(r for r in results if r["label"] == "trans-lds=0-wb=0")["visited"]
    vo = {a for a in v_orig if a is not None}
    vt = {a for a in v_tr if a is not None}
    print("visited orig addresses:", len(vo), " trans(label-mapped):", len(vt))
    print("orig-only:", sorted(vo - vt)[:10])
    print("trans-only:", sorted(vt - vo)[:10])
