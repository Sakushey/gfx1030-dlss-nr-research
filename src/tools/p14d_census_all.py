"""All-33-kernel entry-preload census driver (Phase 14D0-C / 14D1 inputs).

For every translated kernel:
  - CFG-aware read-before-def flag list (SGPR dwords)
  - opcode census for scratch/private/buffer/image/atomic/call-ish mnemonics
  - private-segment sizes + descriptor info (original & translated)
  - joins each flagged SGPR with the ORIGINAL layout semantic
    (kernarg / dispatch_ptr / wgid / gap / beyond) and the CURRENT
    translated layout semantic.
Writes CSVs + JSON. Host-only.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import p14d_kd as kd            # noqa: E402
import p14d_dec as dec          # noqa: E402
import p14d_live as live        # noqa: E402

ASM_DIR = os.path.join(ROOT, "phase9_final_module", "asm")
ORIG_OBJ = os.path.join(ROOT, "phase5_exact_fragment",
                        "gfx1100_code_object.o")
TRANS_OBJ = os.path.join(ROOT, "phase9_final_module",
                         "gfx1030_dlssnr_module.co")
OUT = os.path.join(ROOT, "phase14d_static", "out")

# mnemonic families that would need a private-segment-buffer V# or other
# non-flat scratch machinery
SCRATCH_FAMILY = re.compile(
    r"^(v_scratch|s_scratch|scratch_|buffer_(?!gl0|gl1)|tbuffer_|"
    r"image_|mubuf)")
FLAT_SCRATCH_FAMILY = re.compile(r"^(flat_scratch|s_mov.*flat_scratch)")
CALLISH = re.compile(r"^(s_swappc|s_setpc|s_getpc|s_trap|s_sendmsg|"
                     r"v_readlane|v_writelane)")


def main():
    os.makedirs(OUT, exist_ok=True)
    orig_rows = dec.dec_kernel_file(ORIG_OBJ)
    trans_rows = dec.dec_kernel_file(TRANS_OBJ)
    od = {k: dec.dec(dw) for k, dw in orig_rows}
    td = {k: dec.dec(dw) for k, dw in trans_rows}

    census = []
    opc = {}
    json_out = {}
    for fname in sorted(os.listdir(ASM_DIR)):
        if not fname.endswith(".s"):
            continue
        name = fname[:-2]
        info_o = od.get(name)
        info_t = td.get(name)
        if info_o is None and name != "_Z10swin_layerR7SwinLDSPKhRK10BlobLayouti":
            continue  # kernel not in descriptor tables (helper handled below)
        text = live.load_s(os.path.join(ASM_DIR, fname))
        rows = live.parse_asm_text(text)
        instrs = [r for r in rows if r["kind"] == "instr"]
        m = set()
        for r in instrs:
            m.add(r["mnem"].lower())
        scratch = sorted(x for x in m if SCRATCH_FAMILY.match(x))
        flatsc = sorted(x for x in m if x in ("flat_scratch",) or
                        x.startswith("flat_scratch"))
        calls = sorted(x for x in m if CALLISH.match(x))
        if info_o is not None and info_t is not None:
            flags, fr, fw, ins = live.analyze_kernel(rows)
            # per-flag semantic join
            rows_data = []
            by_reg = {}
            for f in flags:
                by_reg.setdefault(f["sgpr"], []).append(f)
            for sg in sorted(by_reg):
                fl = by_reg[sg]
                first = fl[0]
                first_def_pc = ins[fw[sg]]["pc"] if sg in fw else None
                sem_o, sem_t = "beyond", "beyond"
                # original semantic
                o_regs, o_sys, o_v, o_next = dec.register_map(info_o)
                if sg < o_next:
                    for nm, (i0, sp) in o_regs.items():
                        if i0 <= sg < i0 + sp:
                            sem_o = f"user:{nm}"
                else:
                    for nm, (i0, sp) in o_sys.items():
                        if i0 <= sg < i0 + sp:
                            sem_o = f"sys:{nm}"
                    else:
                        gap = [i for i in range(o_next,
                                                 min(16, o_next + 16))]
                        sem_o = "user-gap(no-preload)" if sg < 16 else sem_o
                t_regs, t_sys, t_v, t_next = dec.register_map(info_t)
                if sg < t_next:
                    for nm, (i0, sp) in t_regs.items():
                        if i0 <= sg < i0 + sp:
                            sem_t = f"user:{nm}"
                else:
                    for nm, (i0, sp) in t_sys.items():
                        if i0 <= sg < i0 + sp:
                            sem_t = f"sys:{nm}"
                rows_data.append(dict(
                    kernel=name, sgpr=sg, n_reads=len(fl),
                    first_read_pc=ins[fr[sg]]["pc"] if sg in fr else None,
                    first_write_pc=first_def_pc,
                    first_mnem=first["mnem"], first_ops=first["ops"],
                    orig_semantic=sem_o, trans_semantic=sem_t))
            census.extend(rows_data)
            json_out[name] = {
                "n_instr": len(instrs),
                "flags": rows_data,
                "opcodes_scratch": scratch,
                "opcodes_flatscratch": flatsc,
                "opcodes_calls": calls,
                "orig": {k: (v if not isinstance(v, (list, dict)) else
                             str(v)) for k, v in info_o.items()},
            }
            for x in scratch + flatsc + calls:
                opc[x] = opc.get(x, 0) + 1
            print(f"{name[:48]:50s} instr={len(instrs):6d} "
                  f"flagged_sgpr={sorted(set(f['sgpr'] for f in flags))} "
                  f"scratch={scratch} calls={calls}")
        else:
            # helper swin_layer: opcode census only
            print(f"{name[:48]:50s} instr={len(instrs):6d} (helper) "
                  f"scratch={scratch} calls={calls}")

    with open(os.path.join(OUT, "p14d_entry_preload_flags.json"), "w") as f:
        json.dump(json_out, f, indent=1)
    with open(os.path.join(OUT, "p14d_entry_preload_census.csv"), "w",
              newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "kernel", "sgpr", "n_reads", "first_read_pc", "first_write_pc",
            "first_mnem", "first_ops", "orig_semantic", "trans_semantic"])
        w.writeheader()
        w.writerows(census)
    print("\nopcode census:", opc)
    print("rows:", len(census))


if __name__ == "__main__":
    main()
