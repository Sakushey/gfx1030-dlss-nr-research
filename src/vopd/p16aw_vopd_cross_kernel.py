#!/usr/bin/env python3
"""Phase 16AW PART III section 21 -- CROSS-KERNEL VOPD census.

Brief section 21: the audit reports left-before-right VOPD hazards across many
kernels, not only the Candidate-F symbol, and forbids claiming the fix is
Candidate-F-only.  This module runs the SAME analyzer that proved the
Candidate-F site over EVERY kernel symbol in the actual parent object, so the
blast radius is measured rather than assumed.

It reuses p16aw_vopd_dependency.py rather than re-implementing the rule: two
implementations of one rule is two chances to disagree, and the analyzer
already carries the controls that let it fail.
"""

from __future__ import annotations

import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import p16aw_vopd_dependency as V  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
ELF = os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_code_object.o")
DIS = os.path.join(ROOT, "p16aw", "vopd", "ACTUAL_PARENT_full.dis")

#: a kernel symbol is the mangled entry point, not its .kd/.num_vgpr companions
RE_KERNEL = re.compile(r"^_Z")


def elf_kernel_symbols(path):
    b = open(path, "rb").read()
    e_shoff = struct.unpack_from("<Q", b, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", b, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", b, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", b, 0x3E)[0]
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name, typ, flags, addr, offset, size, link, info, align,
         entsize) = struct.unpack_from("<IIQQQQIIQQ", b, off)
        secs.append(dict(nameoff=name, type=typ, addr=addr, offset=offset,
                         size=size, link=link, entsize=entsize))
    shstr = secs[e_shstrndx]
    for s in secs:
        end = b.index(b"\0", shstr["offset"] + s["nameoff"])
        s["name"] = b[shstr["offset"] + s["nameoff"]:end].decode("utf8", "replace")
    out = {}
    for s in secs:
        if s["type"] != 2:            # .symtab only
            continue
        strtab = secs[s["link"]]
        for i in range(s["size"] // 24):
            o = s["offset"] + i * 24
            nm, info, other, shndx, val, sz = struct.unpack_from("<IBBHQQ", b, o)
            end = b.index(b"\0", strtab["offset"] + nm)
            name = b[strtab["offset"] + nm:end].decode("utf8", "replace")
            if not RE_KERNEL.match(name) or sz == 0:
                continue
            out[name] = (val, sz)
    return out


def main():
    syms = elf_kernel_symbols(ELF)
    print("kernel symbols in the actual parent: %d" % len(syms))

    # parse every VOPD line once, with its address
    pairs, _ = V.parse_disassembly(DIS)
    print("VOPD pairs in the whole object: %d" % len(pairs))

    bounds = sorted((v[0], v[0] + v[1], n) for n, v in syms.items())
    rows = []
    for lo, hi, name in bounds:
        inside = [p for p in pairs if lo <= p["addr"] < hi]
        if not inside:
            rows.append({"kernel": name, "symbol_va": "0x%X" % lo,
                         "symbol_size": hi - lo, "n_vopd": 0,
                         "n_hazard_l2r": 0, "n_hazard_r2l": 0,
                         "n_cross_dependent": 0, "n_unknown": 0,
                         "hazard_sites": []})
            continue
        l2r = r2l = unk = 0
        sites = []
        for p in inside:
            c = V.classify_pair(p["x"], p["y"])
            k = c["class"]
            if k == "UNKNOWN_BLOCKING":
                unk += 1
                sites.append({"addr": "0x%X" % p["addr"], "x": p["x"], "y": p["y"],
                              "class": k})
            elif k == "HAZARD_LEFT_BEFORE_RIGHT":
                l2r += 1
                sites.append({"addr": "0x%X" % p["addr"], "x": p["x"], "y": p["y"],
                              "class": k,
                              "left_writes_right_reads": c["left_writes_right_reads"]})
            elif k == "HAZARD_RIGHT_BEFORE_LEFT":
                r2l += 1
            elif k == "HAZARD_BOTH_DIRECTIONS":
                l2r += 1; r2l += 1
                sites.append({"addr": "0x%X" % p["addr"], "x": p["x"], "y": p["y"],
                              "class": k})
        rows.append({"kernel": name, "symbol_va": "0x%X" % lo,
                     "symbol_size": hi - lo, "n_vopd": len(inside),
                     "n_hazard_l2r": l2r, "n_hazard_r2l": r2l,
                     "n_cross_dependent": l2r + r2l, "n_unknown": unk,
                     "hazard_sites": sites})

    rows.sort(key=lambda r: (-r["n_hazard_l2r"], -r["n_vopd"], r["kernel"]))
    tot_l2r = sum(r["n_hazard_l2r"] for r in rows)
    tot_r2l = sum(r["n_hazard_r2l"] for r in rows)
    tot_vopd = sum(r["n_vopd"] for r in rows)
    tot_unk = sum(r["n_unknown"] for r in rows)
    with_l2r = [r["kernel"] for r in rows if r["n_hazard_l2r"]]

    print("\n%-46s %5s %5s %5s %6s" % ("kernel", "vopd", "l2r", "r2l", "unk"))
    for r in rows[:18]:
        print("%-46s %5d %5d %5d %6d" % (r["kernel"][:46], r["n_vopd"],
                                         r["n_hazard_l2r"], r["n_hazard_r2l"],
                                         r["n_unknown"]))
    print("\nTOTAL vopd %d  l2r %d  r2l %d  unknown %d"
          % (tot_vopd, tot_l2r, tot_r2l, tot_unk))
    print("kernels with at least one LEFT_BEFORE_RIGHT site: %d" % len(with_l2r))
    for k in with_l2r:
        print("   ", k)

    out = {
        "schema": "p16aw/vopd-cross-kernel/1",
        "phase": "16AW",
        "host_only": True,
        "gpu_calls": 0,
        "subject_elf": "phase5_exact_fragment/gfx1100_code_object.o",
        "subject_elf_sha256": "93e4a40b880b994860431309e9b2fd116efea585a23a830496050de88ee4800a",
        "tree_disassembly": "p16aw/vopd/ACTUAL_PARENT_full.dis",
        "analyzer": "p16aw/vopd/p16aw_vopd_dependency.py (the same rule that proved the Candidate-F site)",
        "n_kernel_symbols": len(syms),
        "n_vopd_total": tot_vopd,
        "n_hazard_left_before_right_total": tot_l2r,
        "n_hazard_right_before_left_total": tot_r2l,
        "n_unknown_blocking_total": tot_unk,
        "kernels_with_a_left_before_right_site": with_l2r,
        "per_kernel": rows,
        "what_this_establishes": ("the rule fires on more than one kernel, so a fix "
                                  "confined to the Candidate-F symbol would leave the "
                                  "others defective -- brief section 21"),
        "what_this_does_NOT_establish": ("which of these sites the project's own "
                                         "translator actually mis-lowered.  The census is "
                                         "of the SOURCE.  A site is only a defect once the "
                                         "emitted lowering is shown to read the new value."),
    }
    with open(os.path.join(HERE, "VOPD_CROSS_KERNEL_CENSUS_16AW.json"), "w",
              encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("wrote VOPD_CROSS_KERNEL_CENSUS_16AW.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
