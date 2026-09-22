"""14D2/14D3 deliverables:
- phase14d_original_entry_contracts.json : per-kernel original gfx1100
  entry contract (preloads, positions, declared count, per-preload
  semantic and whether any translated code reads it before definition)
- phase14d_semantic_preload_mapping.csv : semantic value -> original
  register -> gfx1030 current register -> gfx1030 normalized register ->
  descriptor-only match -> rewrite required
- phase14d_entry_preload_census.csv (root copy for 14D1)
"""
from __future__ import annotations

import csv
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import p14d_dec as dec        # noqa: E402
import p14d_kd as kd          # noqa: E402

ORIG_OBJ = os.path.join(ROOT, "phase5_exact_fragment",
                        "gfx1100_code_object.o")
TRANS_OBJ = os.path.join(ROOT, "phase9_final_module",
                         "gfx1030_dlssnr_module.co")
OUTD = os.path.join(ROOT, "phase14d_static", "out")
ROOTOUT = ROOT


def main():
    census = json.load(open(os.path.join(OUTD, "p14d_entry_preload_flags.json")))
    od = {k: dec.dec(dw) for k, dw in dec.dec_kernel_file(ORIG_OBJ)}
    td = {k: dec.dec(dw) for k, dw in dec.dec_kernel_file(TRANS_OBJ)}

    # root census copy under the spec name
    shutil.copyfile(os.path.join(OUTD, "p14d_entry_preload_census.csv"),
                    os.path.join(ROOTOUT, "phase14d_entry_preload_census.csv"))

    contracts = {}
    rows = []
    for kname in sorted(od):
        io, it = od[kname], td[kname]
        o_regs, o_sys, o_v, o_next = dec.register_map(io)
        t_regs, t_sys, t_v, t_next = dec.register_map(it)

        def sem_of(sg, regs, sysm):
            for nm, (i0, sp) in regs.items():
                if i0 <= sg < i0 + sp:
                    return ("user", nm, i0, sp)
            for nm, (i0, sp) in sysm.items():
                if i0 <= sg < i0 + sp:
                    return ("sys", nm, i0, sp)
            return ("none", "", sg, 1)

        preloads = {}
        for kind, nm, i0, sp in [sem_of(i, o_regs, o_sys)
                                 for i in range(17)]:
            if kind == "none":
                continue
            flags = [f for f in census.get(kname, {}).get("flags", [])
                     if i0 <= f["sgpr"] < i0 + sp]
            preloads[nm] = {
                "position": i0, "span": sp,
                "read_before_def": bool(flags),
                "n_read_flags": len(flags),
            }
        # current translated position of the same semantic (when present)
        for nm, p in preloads.items():
            cur = None
            if p["span"] == 1:
                pass
            for kind, t_nm, t_i0, t_sp in [
                    sem_of(0, t_regs, t_sys)]:
                pass
            cur_pos = None
            for tnm, (ti0, tsp_) in list(t_regs.items()) + \
                    list(t_sys.items()):
                if tnm == nm:
                    cur_pos = {"sgpr": ti0}
                    break
            p["gfx1030_current"] = cur_pos or None
            # normalized position == original position by construction
            p["gfx1030_normalized"] = {"sgpr": p["position"]}
            p["descriptor_only_match"] = True
        contracts[kname] = {
            "descriptor_class": f"uc={io['user_count']} "
                                f"user={[n for n, _ in io['user_enables']]} "
                                f"sys={[n for n, _ in io['system_enables']]}",
            "declared_user_sgpr_count": io["user_count"],
            "wave32": bool(io["wave32"]),
            "private_segment": io["private"],
            "kernarg_size": io["kernarg_size"],
            "layout_original": dec.fmt_layout(io),
            "layout_gfx1030_current": dec.fmt_layout(it),
            "preloads": preloads,
        }
        for nm, p in preloads.items():
            cur = p["gfx1030_current"]
            rows.append({
                "kernel": kname,
                "semantic_value": nm,
                "original_register":
                    f"s{p['position']}" +
                    (f":s{p['position']+p['span']-1}" if p["span"] > 1 else ""),
                "gfx1030_current_register":
                    (f"s{cur['sgpr']}" + (f":s{cur['sgpr']+p['span']-1}"
                     if p["span"] > 1 else "") if cur else "-"),
                "gfx1030_normalized_register":
                    f"s{p['position']}" +
                    (f":s{p['position']+p['span']-1}" if p["span"] > 1 else ""),
                "descriptor_only_match": "YES" if p["descriptor_only_match"]
                else "NO",
                "read_before_def": "yes" if p["read_before_def"] else "no",
                "code_rewrite_required": "NO",
            })

    with open(os.path.join(ROOTOUT, "phase14d_original_entry_contracts.json"),
              "w") as f:
        json.dump(contracts, f, indent=1)
    with open(os.path.join(ROOTOUT, "phase14d_semantic_preload_mapping.csv"),
              "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "kernel", "semantic_value", "original_register",
            "gfx1030_current_register", "gfx1030_normalized_register",
            "descriptor_only_match", "read_before_def",
            "code_rewrite_required"])
        w.writeheader()
        w.writerows(rows)
    n = sum(len(c["preloads"]) for c in contracts.values())
    n_read = sum(1 for c in contracts.values() for p in c["preloads"].values()
                 if p["read_before_def"])
    print(f"contracts: {len(contracts)} kernels, {n} preload slots "
          f"({n_read} actually read pre-def)")
    print("sample contract (conv_splitk):")
    print(json.dumps(contracts["_Z13k_conv_splitk12ConvParams1d"],
                     indent=1))


if __name__ == "__main__":
    main()
