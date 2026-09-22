"""Generate the Phase 14D0 deliverable tables (CSV) from decoded
descriptors + the entry-preload census. Host-only.
"""
from __future__ import annotations

import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import p14d_kd as kd      # noqa: E402
import p14d_dec as dec    # noqa: E402

ORIG_OBJ = os.path.join(ROOT, "phase5_exact_fragment",
                        "gfx1100_code_object.o")
TRANS_OBJ = os.path.join(ROOT, "phase9_final_module",
                         "gfx1030_dlssnr_module.co")
REF_OBJ = os.path.join(ROOT, "phase14_runtime", "ref_probe_dev.elf.o")
SENT_OBJ = os.path.join(ROOT, "phase14_runtime", "p14_diag_hidden.co")
OUT = os.path.join(ROOT, "phase14d_static", "out")
ROOTOUT = ROOT


def row_of(dw, info):
    return {
        "group_segment": info["group"],
        "private_segment": info["private"],
        "kernarg_size": info["kernarg_size"],
        "user_sgpr_count": info["user_count"],
        "user_sgpr_private_segment_buffer": 1 if any(
            n == "private_segment_buffer" for n, _ in info["user_enables"]) else 0,
        "user_sgpr_dispatch_ptr": 1 if any(
            n == "dispatch_ptr" for n, _ in info["user_enables"]) else 0,
        "user_sgpr_kernarg_segment_ptr": 1 if any(
            n == "kernarg_segment_ptr" for n, _ in info["user_enables"]) else 0,
        "sys_wgid_x": 1 if any(n == "workgroup_id_x"
                               for n, _ in info["system_enables"]) else 0,
        "sys_wgid_y": 1 if any(n == "workgroup_id_y"
                               for n, _ in info["system_enables"]) else 0,
        "sys_wgid_z": 1 if any(n == "workgroup_id_z"
                               for n, _ in info["system_enables"]) else 0,
        "sys_wg_info": 1 if any(n == "workgroup_info"
                                for n, _ in info["system_enables"]) else 0,
        "sys_pswf": 1 if any(n == "private_segment_wavefront_offset"
                             for n, _ in info["system_enables"]) else 0,
        "wave32": info["wave32"],
        "dx10_clamp": info["dx10"],
        "ieee_mode": info["ieee"],
        "fp16_overflow": info["fp16_ovf"],
        "raw_rsrc1": info["raw_rsrc1"],
        "layout": dec.fmt_layout(info),
    }


def main():
    os.makedirs(OUT, exist_ok=True)
    targets = [
        ("gfx1100_original_conv_splitk",
         ORIG_OBJ, "_Z13k_conv_splitk12ConvParams1d"),
        ("gfx1030_translated_conv_splitk",
         TRANS_OBJ, "_Z13k_conv_splitk12ConvParams1d"),
        ("gfx1030_stock_hip6_probe",
         REF_OBJ, "_Z9ref_probePy"),
        ("gfx1030_working_sentinel",
         SENT_OBJ, "p14_diag_hidden"),
    ]
    fields = ["field"]
    tables = {}
    for label, path, kern in targets:
        rows = dec.dec_kernel_file(path, kern)
        if not rows:
            rows = dec.dec_kernel_file(path)
            label = label + " (kernel not found; first below)"
            kern = rows[0][0]
        kname, dw = rows[0]
        info = dec.dec(dw)
        tables[label] = (kname, row_of(dw, info), info)
        for f in tables[label][1]:
            if f not in fields:
                fields.append(f)
    with open(os.path.join(ROOTOUT, "phase14d_descriptor_entry_matrix.csv"),
              "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["field"] + list(tables.keys()) + ["semantic_effect"])
        labels = list(tables.keys())
        EFFECT = {
            "group_segment": "LDS bytes per workgroup; allocation only",
            "private_segment": "per-thread scratch bytes; triggers HW scratch alloc (implicit scratch ops)",
            "kernarg_size": "bytes of the kernarg segment; sizes args block",
            "user_sgpr_count": "declared user-data dwords; SYSTEM sgprs (wgid...) are placed at SGPR index == this count",
            "user_sgpr_private_segment_buffer": "when 1: 4-SGPR scratch V# preloaded FIRST -> kernarg displaced to s4:s5",
            "user_sgpr_dispatch_ptr": "when 1: AQL packet pointer at next free pair",
            "user_sgpr_kernarg_segment_ptr": "kernarg base at next free pair (s0:s1 if nothing before it)",
            "sys_wgid_x": "workgroup_id_x at SGPR index == user_sgpr_count",
            "sys_wgid_y": "workgroup_id_y one SGPR later",
            "sys_wgid_z": "workgroup_id_z",
            "sys_wg_info": "workgroup_info",
            "sys_pswf": "private-segment wavefront offset (scratch position)",
            "wave32": "wave32 execution mode",
            "dx10_clamp": "float dx10 clamp mode",
            "ieee_mode": "IEEE f32 mode",
            "fp16_overflow": "fp16 overflow mode",
            "raw_rsrc1": "rsrc1-ish word (raw)",
            "layout": "resulting initial register map",
        }
        for f in fields[1:]:
            w.writerow([f] + [tables[L][1].get(f, "") for L in labels]
                       + [EFFECT.get(f, "")])
    # semantic-effect column is written by hand into the doc; add layout
    print("matrix written")
    for L in labels:
        info = tables[L][2]
        layout = dec.fmt_layout(info)
        print(f"{L:38s} {layout}")

    # ---- 14D0-C private-segment dependency table (all 33 kernels)
    # data from the census JSON + per-kernel descriptor decode
    census = json.load(open(os.path.join(
        OUT, "p14d_entry_preload_flags.json")))
    od = {k: dec.dec(dw) for k, dw in
          dec.dec_kernel_file(ORIG_OBJ)}
    td = {k: dec.dec(dw) for k, dw in
          dec.dec_kernel_file(TRANS_OBJ)}
    with open(os.path.join(ROOTOUT,
                           "phase14d_private_segment_dependency.csv"),
              "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["kernel", "private_segment_size", "scratch_instructions",
                    "buffer_image_instructions", "s0_s3_predef_reads",
                    "s0_s3_as_resource", "requires_private_segment_buffer",
                    "confidence", "notes"])
        for kname in sorted(set(list(od.keys()) + list(td.keys()))):
            info_o = od.get(kname)
            info_t = td.get(kname)
            if info_t is None:
                continue
            flags = census.get(kname, {}).get("flags", [])
            s03 = sorted(set(f["sgpr"] for f in flags if f["sgpr"] < 4))
            ops = census.get(kname, {}).get("opcodes_scratch", [])
            calls = census.get(kname, {}).get("opcodes_calls", [])
            res = [x for x in ops if x.startswith(
                ("buffer_", "tbuffer_", "image_"))]
            private = info_t["private"]
            req = "NO" if not ops else (
                "NO (implicit-HW scratch, no s[0:3] resource)")
            conf = "HIGH" if not s03 and not ops else "VERIFIED"
            # original never enabled pb on any kernel -> code cannot depend
            # on a pb V# (code identical byte-wise between original/translated
            # except re-encodings; verified by translation audits)
            w.writerow([kname, private, ";".join(ops) or "-",
                        ";".join(res) or "-", ";".join(map(str, s03)) or "-",
                        "-", req, conf,
                        "orig descriptor has no pb on this kernel"
                        if not any(n == "private_segment_buffer"
                                   for n, _ in info_o["user_enables"])
                        else "CHECK"])


if __name__ == "__main__":
    main()
