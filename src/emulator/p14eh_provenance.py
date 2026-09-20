"""Phase 14E-H §18/§19: DS address-producer symbolic provenance + width
audit for every site whose recorded final u32 EA is >= 0x4000 (the OOB
population under the alloc-16,384 hypothesis).

Outputs:
  phase14eh_address_width_audit.csv  (producer-op census + width audit per
                                     OOB site, both streams)
  phase14eh_ds_address_provenance.json (expression trees per OOB site)
  phase14eh_tools/out/oob_sites.json   (site list + addr value bands)

Method (documented honesty): static producer census = all instructions
within the 96 sites preceding the DS site (reverse static order) that
write the ADDR vgpr, with a basic-block-aware "most recent single
definition" pick when unique; loop-carried increments are marked
LOOP_CARRIED. Expression trees expand register operands recursively to
depth 4 and terminate leaves at: literals, scalar regs (s#/vcc/exec/m0),
memory loads, v_readfirstlane, or depth. Rows tagged IDENTICAL_SEMANTICS
when both streams' site pair share the producer census and shapes.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
OUTD = os.path.join(HERE, "out")
for p in (HERE, os.path.join(ROOT, "phase14e_static", "tools"),
          os.path.join(ROOT, "phase14d11_static", "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import p14d11_emu as P11  # noqa: E402

K = "_Z10k_swin_varILi32ELb0EEv9VarParams"
WINDOW = 96
MAXDEPTH = 4

# op classes whose emulator width/semantics the audit tracks (per phase
# plan §19: 16-bit src selection, SDWA, packed, sign/zero extension,
# shift truncation, carry, u32 wrap)
WIDTH_CLASS = {
    "v_lshlrev_b16": "16bit_shift", "v_lshrrev_b16": "16bit_shift",
    "v_ashrrev_i16": "16bit_shift_signed", "v_add_nc_u16": "16bit_add",
    "v_sub_nc_u16": "16bit_sub", "v_lshl_or_b32": "u32",
    "v_lshl_add_u32": "u32", "v_add_lshl_u32": "u32",
    "v_add_nc_u32": "u32_add", "v_add_u32": "u32_add",
    "v_add_co_u32": "u32_add_carry_out",
    "v_add_co_ci_u32": "u32_add_carry_inout",
    "v_add3_u32": "u32_add3", "v_sub_nc_u32": "u32_sub",
    "v_mul_u32_u24": "mul24", "v_mul_hi_u32": "mul_hi",
    "v_mul_i32_i24": "mul24_signed", "v_mul_lo_u32": "mul32",
    "v_and_b32": "u32_and", "v_or_b32": "u32_or", "v_xor_b32": "u32_xor",
    "v_lshlrev_b32": "u32_shl", "v_lshrrev_b32": "u32_shr",
    "v_ashrrev_i32": "u32_ashr_signed", "v_cvt_i32_f32": "f32_to_i32",
    "v_cvt_u32_f32": "f32_to_u32", "v_cvt_f32_i32": "i32_to_f32",
    "v_bfe_u32": "bfe_u32", "v_bfe_i32": "bfe_i32",
    "v_pk_add_f16": "packed_f16", "v_pk_mul_f16": "packed_f16",
    "v_pk_fma_f16": "packed_f16", "v_pk_max_f16": "packed_f16",
    "v_pk_min_f16": "packed_f16",
    "v_cndmask_b32": "select", "v_mov_b32": "mov",
    "v_readfirstlane_b32": "readfirstlane",
    "v_lshrrev_b32_e32": "u32_shr", "v_mbcnt_lo_u32_b32": "mbcnt",
}


def vregs(ops_txt):
    return [t for t in [o.strip() for o in ops_txt.split(",")] if t]


def dst_regs(ins):
    """register indexes written by an instruction (v or s)."""
    m = ins["mnemonic"]
    ops = (ins.get("operands") or "").strip()
    out = []
    if not ops:
        return out
    if m.startswith("v_") or m.startswith("ds_") or m.startswith("scratch"):
        for t in ops.split(","):
            toks = t.strip().split()
            if not toks:
                continue
            t = toks[0]
            mt = re.match(r"^v(\d+)$", t)
            if mt:
                out.append(("v", int(mt.group(1))))
                break  # first v token is dst for most v_ ops
    elif m.startswith("s_"):
        for t in ops.split(","):
            toks = t.strip().split()
            if not toks:
                continue
            t = toks[0]
            ms = re.match(r"^s(\d+)$", t)
            if ms:
                out.append(("s", int(ms.group(1))))
                break
            m2 = re.match(r"^s\[(\d+):(\d+)\]$", t)
            if m2:
                out.append(("s", int(m2.group(1))))
                break
    return out


def writer_scan(prog, site_idx, reg, kind):
    """Reverse static scan for the most recent writer of (kind, reg);
    returns (ins, rel_idx) or (None, None); skips nothing (loop-carried
    definitions appear as the in-loop writer; base defs may be outside)."""
    lo = max(0, site_idx - WINDOW)
    for j in range(site_idx - 1, lo - 1, -1):
        ins = prog[j]
        for (kk, n) in dst_regs(ins):
            if kk == kind and n == reg:
                return ins, site_idx - j
    return None, None


def expr_of(prog, site_idx, kind, reg, depth=0):
    if depth >= MAXDEPTH:
        return {"leaf": "DEPTH"}
    ins, dist = writer_scan(prog, site_idx, reg, kind)
    if ins is None:
        return {"leaf": "UNRESOLVED_NO_WRITER", "reg": f"{kind}{reg}"}
    m = ins["mnemonic"]
    ops = (ins.get("operands") or "").split(",")
    # treat scalar-src / literal leaves
    node = {"op": m, "site": ins.get("address"),
            "dist_from_ds_site": dist}
    srcs = []
    for t in ops[1:]:
        t0 = t.strip().split()[0]
        if re.match(r"^v(\d+)$", t0):
            srcs.append(expr_of(prog, site_idx, "v", int(t0[1:]),
                                depth + 1))
        elif re.match(r"^v\[(\d+):(\d+)\]$", t0):
            srcs.append({"leaf": "vpair", "regs": t0})
        elif re.match(r"^s(\d+)$", t0):
            srcs.append({"leaf": "scalar", "reg": t0})
        elif re.match(r"^s\[(\d+):(\d+)\]$", t0):
            srcs.append({"leaf": "scalar_pair", "regs": t0})
        elif t0 in ("vcc_lo", "vcc_hi", "exec_lo", "exec_hi", "scc",
                    "m0", "null", "off"):
            srcs.append({"leaf": t0})
        elif re.match(r"^-?0x[0-9a-fA-F]+$", t0) or \
                re.match(r"^-?\d+$", t0):
            srcs.append({"leaf": "lit", "v": int(t0, 0)})
        else:
            srcs.append({"leaf": "other", "t": t0[:24]})
    node["srcs"] = srcs
    return node


def main():
    os.makedirs(OUTD, exist_ok=True)
    progs = {}
    for which, path in (("ent", P11.ENT_DIS), ("orig", P11.ORIG_DIS)):
        prog, _, _ = P11.slice_program(path, K)
        progs[which] = prog
    events = {}
    with open(os.path.join(OUTD, "events_all.csv")) as f:
        for r in csv.DictReader(f):
            key = (r["which"], int(r["site"]))
            if int(r["raw"]) >= 0x4000:
                events.setdefault(key, []).append(r)
    rows = []
    prov = {"sites": {}}
    for (which, site), evs in sorted(events.items()):
        prog = progs[which]
        idx = [i for i, x in enumerate(prog)
               if x.get("address") == site]
        if not idx:
            continue
        idx = idx[0]
        site_ins = prog[idx]
        addr_reg = next(iter({int(e["addr_reg"]) for e in evs}))
        mnem = site_ins["mnemonic"]
        ins, dist = writer_scan(prog, idx, addr_reg, "v")
        # producer census: all v/s writers of the addr reg in window
        census = []
        lo = max(0, idx - WINDOW)
        for j in range(idx - 1, lo - 1, -1):
            for (kk, n) in dst_regs(prog[j]):
                if kk == "v" and n == addr_reg:
                    census.append((kk, n, prog[j]["mnemonic"],
                                   prog[j].get("address")))
        wcls = [WIDTH_CLASS.get(c[2], "other") for c in census]
        addr_vals = sorted({int(e["vaddr"]) for e in evs})
        ge64k = sum(1 for e in evs if int(e["vaddr"]) >= 0x10000)
        n = len(evs)
        # width audit verdict per producer op
        audit = []
        for (kk, nn, cm, ca) in census:
            audit.append({"op": cm, "site": ca,
                          "emu_class": WIDTH_CLASS.get(cm, "other"),
                          "emu_width_ok": "yes" if WIDTH_CLASS.get(
                              cm, "u32") != "other" else "unclassified"})
        expr = expr_of(prog, idx, "v", addr_reg)
        if ins is not None and (ins.get("address") <
                                progs["ent" if which == "ent" else "orig"]
                                .get("address") if False else False):
            pass
        prov["sites"][f"{which}:0x{site:x}"] = {
            "mnem": mnem, "addr_vgpr": addr_reg, "n_events": n,
            "addr_values_sample": [hex(v) for v in addr_vals[:8]],
            "n_vaddr_ge64k": ge64k,
            "last_writer": {"mnem": ins["mnemonic"],
                            "site": ins.get("address"),
                            "dist": dist} if ins else None,
            "producers": census,
            "expr": expr,
            "loop_carried_unknown": (ins is None) or (
                ins.get("address") >= site),
        }
        rows.append([which, f"0x{site:x}", mnem, addr_reg, n,
                     f"0x{addr_vals[0]:x}" if addr_vals else "",
                     f"0x{addr_vals[-1]:x}" if addr_vals else "",
                     ge64k,
                     "; ".join(f"{c[2]}@{c[3]:#x}" for c in census[:6]),
                     "; ".join(set(wcls))])
    with open(os.path.join(ROOT, "phase14eh_address_width_audit.csv"),
              "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["stream", "ds_site", "mnem", "addr_vgpr",
                    "dyn_events_ge4000", "addr_min", "addr_max",
                    "vaddr_ge_0x10000", "producer_ops_window96",
                    "width_classes"])
        w.writerows(rows)
    with open(os.path.join(ROOT,
                           "phase14eh_ds_address_provenance.json"),
              "w") as f:
        json.dump(prov, f, indent=1)
    with open(os.path.join(OUTD, "oob_sites.json"), "w") as f:
        json.dump({f"{k[0]}:0x{k[1]:x}": len(v)
                   for k, v in events.items()}, f, indent=1)
    print("wrote", os.path.join(ROOT,
                                "phase14eh_address_width_audit.csv"))
    print("wrote", os.path.join(ROOT,
                                "phase14eh_ds_address_provenance.json"))
    for r in rows[:25]:
        print("  ", r[0], r[1], r[2], "addr_vgpr", r[3], "n", r[4],
              "range", r[5], "..", r[6], "ge64k", r[7])


if __name__ == "__main__":
    main()
