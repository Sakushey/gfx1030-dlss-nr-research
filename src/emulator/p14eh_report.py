"""Phase 14E-H report generator (host-only): single-wave record runs for
both streams, then writes the §7/§8/§9 CSV deliverables.

Run:  python phase14eh_tools/p14eh_report.py
Writes (project root):
  phase14eh_swin_final_lds_addresses.csv        (§7, ENT w0/w7 records)
  phase14eh_old_raw_address_reclassification.csv(§8, GCore regeneration
                                                 + structural reclassification)
  phase14eh_gfx1100_vs_gfx1030_lds.csv          (§9, site-paired compare)
  phase14eh_tools/out/rec_census.json           (aggregate numbers)
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
          os.path.join(ROOT, "phase14eg_tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import p14eh                       # noqa: E402
import p14e_emu as E               # noqa: E402
import p14e_emu_g as G             # noqa: E402
from p14eh import ds_form           # noqa: E402

WAVES = ((0, "w0"), (224, "w7"))


def run_single(which, wavebase):
    r, ev = p14eh.run_single_case(which, wavebase, oob_sem="legacy")
    rw = [e for e in ev if e["kind"] == "rw"]
    n_bp = sum(1 for e in ev if e["kind"] == "bp")
    return r, rw, n_bp


def bucket(ea, w):
    if ea < 15632:
        return "lt_15632"
    if ea < 15872:
        return "15632_15871"
    if ea < 16384:
        return "15872_16383"
    if ea == 16384:
        return "eq_16384"
    return "gt_16384"


def write_s7(rows):
    """§7 CSV: every real LDS rw dynamically reached in the failed
    dispatch on boundary waves (recorded under corrected per-form EA
    semantics); model columns classify the same event under the u32-EA
    (MODEL_HW headline) and trunc16 datapath lenses."""
    path = os.path.join(ROOT, "phase14eh_swin_final_lds_addresses.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["wave", "lane", "site_pc", "opcode", "dir", "width_b",
                    "addr_vgpr", "addr_val_u32", "imm_bytes", "imm_scaling",
                    "raw_u32_ea", "final_ea_trunc16", "final_ea_u32",
                    "in_alloc_15872", "in_alloc_16384", "in_alloc_65536",
                    "oob_u32_alloc16384", "bucket_trunc16", "bucket_u32",
                    "large_preadd_u32"])
        for e in sorted(rows, key=lambda r: (r["wave"], r["lane"])):
            ea16, eau = e["ea16"], e["ea_u32"]
            oob = not e["a16384"]
            w.writerow([
                e["wave"], e["lane"], f"0x{e['site']:x}", e["mnem"],
                "STORE" if e["store"] else "LOAD", e["w"],
                e["addr_reg"], e["vaddr"], e["imm"], e["imm_note"],
                e["raw"], ea16, eau,
                1 if e["a15872"] else 0, 1 if e["a16384"] else 0,
                1 if e["a65536"] else 0, 1 if oob else 0,
                bucket(ea16, e["w"]), bucket(eau, e["w"]),
                1 if e["raw"] >= 0x10000 else 0])
    return path


def site_ds_form(which, site):
    """ds_form of the static site from the module disassembly."""
    src = E.ENT_DIS if which == "ent" else E.ORIG_DIS
    prog, _, _ = E.slice_program(src, E.KERNEL)
    for i in prog:
        if i.get("address") == site:
            return i["mnemonic"], i.get("operands") or "", \
                ds_form(i["mnemonic"], i.get("operands") or "")
    return None, None, None


def write_s8(ent_rows_w0, ent_rows_w7):
    """§8: regenerate the historical GCore records (exact old code), and
    reclassify every old row with recorded raw >= 0x4000 structurally."""
    path = os.path.join(ROOT, "phase14eh_old_raw_address_reclassification.csv")
    out_rows = []
    stat = {"old_ge4000": 0, "real_oob_u32_16384": 0,
            "host_integer_artifact": 0, "bpermute_rows": 0,
            "other": 0, "new_corrected_ge4000": 0}
    # regenerated old records (unchanged GCore) per boundary wave
    for (wb, wl) in WAVES:
        _, raw_old = G.run_case(E.ENT_DIS, E.ENT_CO, f"ent_{wl}", wb)
        # classify each old rw row with recorded raw >= 0x4000
        mnem_form = {}
        for r_old in raw_old:
            if r_old["kind"] == "bp":
                stat["bpermute_rows"] += 1
                continue
            if r_old["a_raw"] < 0x4000:
                continue
            stat["old_ge4000"] += 1
            site = r_old["site"]
            if site not in mnem_form:
                m, ops, form = site_ds_form("ent", site)
                mnem_form[site] = (m, ops, form)
            m, ops, form = mnem_form[site]
            cls = "UNCLASSIFIED"
            note = ""
            if form is None:
                cls, note = "OTHER", "site not in ENT slice"
            elif form["kind"] == "bp":
                cls = "BPERMUTE_MISCLASSIFICATION"
                stat["bpermute_rows"] += 1
            else:
                # does the recorded raw equal the true first-access EA?
                true_reg = form["addr_reg"]
                # GCore's parse source register
                vtoks = [o.split()[0] for o in
                         [x.strip() for x in ops.split(",")] if ops and
                         re.match(r"^v\d+$", o.split()[0])] \
                    if ops else []
                is_load = ("load" in form["kind"] and True) or \
                    ("load" in r_old["mnem"] or "read" in r_old["mnem"])
                g_reg = vtoks[-1] if (is_load and vtoks) else \
                    (vtoks[0] if vtoks else None)
                pair = "read2" in r_old["mnem"] or "write2" in r_old["mnem"] \
                    or "2addr" in r_old["mnem"]
                if not pair and g_reg is not None and true_reg is not None \
                        and g_reg == true_reg:
                    # clean parse: recorded raw is the hardware u32 EA
                    cls = "REAL_U32_OOB" if r_old["a_raw"] >= 0x4000 else \
                        "REAL_INRANGE"
                    note = "clean single-address form; raw == u32 EA"
                    if cls == "REAL_U32_OOB":
                        stat["real_oob_u32_16384"] += 1
                elif pair:
                    o0 = 0
                    mm = re.search(r"offset0:(-?\d+)", ops)
                    if mm:
                        o0 = int(mm.group(1)) * 8
                    if o0 == 0:
                        cls = "REAL_U32_OOB"
                        note = "pair form offset0=0; recorded raw == EA0"
                        stat["real_oob_u32_16384"] += 1
                    else:
                        cls = "HOST_INTEGER_ARTIFACT"
                        note = ("pair form offset0=%d*8 dropped by old "
                                "recorder (recorded EA0 = vaddr+0); "
                                "corrected EA0 = raw+%d" % (o0 // 8, o0))
                        stat["host_integer_artifact"] += 1
                else:
                    cls = "HOST_INTEGER_ARTIFACT"
                    note = ("old recorder addressed a non-ADDR register "
                            "(offset text attached to the address operand); "
                            "recorded raw is not an LDS EA")
                    stat["host_integer_artifact"] += 1
            out_rows.append([wl, f"0x{site:x}", r_old["mnem"],
                             "STORE" if r_old["store"] else "LOAD",
                             r_old["w"], f"0x{r_old['a_raw']:x}", cls, note])
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["wave", "site_pc", "opcode", "dir", "width_b",
                    "old_recorded_raw_u32", "reclassification",
                    "note"])
        w.writerows(out_rows)
    # corrected census totals from the new records
    allrows = ent_rows_w0 + ent_rows_w7
    stat["new_corrected_ge4000"] = sum(1 for e in allrows
                                       if e["raw"] >= 0x4000)
    stat["new_corrected_oob_u32_16384"] = sum(
        1 for e in allrows if not e["a16384"])
    return path, stat


GFX11_ALIAS = str.maketrans({})
_ALIAS = {"load": "read", "store": "write", "load_2addr": "read2",
          "store_2addr": "write2"}


def norm_cls(m):
    """gfx1100 spelling -> gfx1030 spelling (same encoding, e.g.
    ds_load_2addr_b64 == ds_read2_b64; D9DC0100 on both streams)."""
    out = m
    out = out.replace("load_2addr_b64", "read2_b64").replace(
        "store_2addr_b64", "write2_b64")
    out = out.replace("ds_load_", "ds_read_").replace(
        "ds_store_", "ds_write_")
    return out


def write_s9(ent_rec, orig_rec):
    """§9: static site pairing by (normalized class, order in kernel
    text) with per-site dynamic comparison harvested from the
    boundary-wave record runs (waves 0 and 7 pooled)."""
    ent_sites = {}
    orig_sites = {}
    for which, rec, store in (("ent", ent_rec, ent_sites),
                              ("orig", orig_rec, orig_sites)):
        src = E.ENT_DIS if which == "ent" else E.ORIG_DIS
        prog, _, _ = E.slice_program(src, E.KERNEL)
        cls_order = []
        for i in prog:
            m = i["mnemonic"]
            if m.startswith("ds_") and m != "ds_bpermute_b32":
                cls_order.append((norm_cls(m), i.get("address")))
        per_site = {}
        for e in rec:
            s = per_site.setdefault(e["site"], {"n": 0, "ge4000": 0,
                                                "oob16384": 0,
                                                "raw_min": None,
                                                "raw_max": 0})
            s["n"] += 1
            if e["raw"] >= 0x4000:
                s["ge4000"] += 1
            if not e["a16384"]:
                s["oob16384"] += 1
            s["raw_max"] = max(s["raw_max"], e["raw"])
            s["raw_min"] = e["raw"] if s["raw_min"] is None \
                else min(s["raw_min"], e["raw"])
        pair = {}
        for m, a in cls_order:
            pair.setdefault(m, []).append(a)
        store[which] = (pair, per_site)
    path = os.path.join(ROOT, "phase14eh_gfx1100_vs_gfx1030_lds.csv")
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["class", "idx", "ent_site", "orig_site", "ent_dyn_n",
                    "ent_raw_min", "ent_raw_max", "ent_ge_0x4000",
                    "ent_oob_u32_16384", "orig_dyn_n", "orig_raw_min",
                    "orig_raw_max", "orig_ge_0x4000",
                    "orig_oob_u32_16384",
                    "paired"])
        e_pair, e_ps = ent_sites["ent"]
        o_pair, o_ps = orig_sites["orig"]
        for m in sorted(set(e_pair) | set(o_pair)):
            ea = e_pair.get(m, [])
            oa = o_pair.get(m, [])
            for k in range(max(len(ea), len(oa))):
                es = ea[k] if k < len(ea) else None
                os_ = oa[k] if k < len(oa) else None

                def agg(ps, s):
                    if s is None:
                        return ["", "", "", "", ""]
                    d = ps.get(s, {})
                    return [d.get("n", 0),
                            "" if d.get("raw_min") is None
                            else f"0x{d['raw_min']:x}",
                            f"0x{d.get('raw_max', 0):x}",
                            d.get("ge4000", 0), d.get("oob16384", 0)]
                w.writerow([m, k,
                            f"0x{es:x}" if es else "", f"0x{os_:x}"
                            if os_ else ""] +
                           agg(e_ps, es) + agg(o_ps, os_) +
                           [1 if (es is not None and os_ is not None)
                            else 0])
    return path


EVENTS_CACHE = os.path.join(OUTD, "events_all.csv")


def load_events_cache():
    rec = {}
    if os.path.exists(EVENTS_CACHE):
        with open(EVENTS_CACHE) as f:
            for row in csv.DictReader(f):
                rec.setdefault((row["which"], row["wave"]), []).append(
                    {k: (int(v) if k not in ("which", "wave", "mnem",
                                             "imm_note") and v != ""
                         else v)
                     for k, v in row.items()})
    return rec


def write_events_cache(rec):
    with open(EVENTS_CACHE, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["which", "wave", "lane", "site", "mnem", "store", "w",
                    "addr_reg", "vaddr", "imm", "imm_note", "raw", "ea16",
                    "ea_u32", "a15872", "a16384", "a65536"])
        for which in ("ent", "orig"):
            for wl in ("w0", "w7"):
                for e in rec[which][wl][1]:
                    w.writerow([which, wl, e["lane"], e["site"], e["mnem"],
                                1 if e["store"] else 0, e["w"],
                                e["addr_reg"], e["vaddr"], e["imm"],
                                e["imm_note"], e["raw"], e["ea16"],
                                e["ea_u32"], 1 if e["a15872"] else 0,
                                1 if e["a16384"] else 0,
                                1 if e["a65536"] else 0])


def main():
    os.makedirs(OUTD, exist_ok=True)
    rec = {}
    for which in ("ent", "orig"):
        rec[which] = {}
        for wb, wl in WAVES:
            r, rw, n_bp = run_single(which, wb)
            rec[which][wl] = (r, rw, n_bp)
            print(f"{which} {wl}: outcome={r['outcome']} steps={r['steps']} "
                  f"rw={len(rw)} bp={n_bp}")
    write_events_cache(rec)
    # §7
    ent_rows = []
    for wb, wl in WAVES:
        _, rw, _ = rec["ent"][wl]
        for e in rw:
            e = dict(e)
            e["wave"] = wl
            ent_rows.append(e)
    p7 = write_s7(ent_rows)
    print("wrote", p7)
    # §8
    ent_w0 = [dict(e) for e in rec["ent"]["w0"][1]]
    ent_w7 = [dict(e) for e in rec["ent"]["w7"][1]]
    p8, stat = write_s8(ent_w0, ent_w7)
    print("wrote", p8, stat)
    # §9
    orig_rows = []
    for wb, wl in WAVES:
        for e in rec["orig"][wl][1]:
            e = dict(e)
            e["wave"] = wl
            orig_rows.append(e)
    p9 = write_s9(ent_rows, orig_rows)
    print("wrote", p9)
    # key distribution summary
    summ = {}
    for which in ("ent", "orig"):
        for wb, wl in WAVES:
            rw = rec[which][wl][1]
            def dist(attr):
                from collections import Counter
                return dict(Counter(bucket(e[attr], e["w"])
                                    for e in rw))
            large = sum(1 for e in rw if e["raw"] >= 0x10000)
            summ[f"{which}_{wl}"] = {
                "outcome": str(rec[which][wl][0]["outcome"]),
                "steps": rec[which][wl][0]["steps"],
                "n_rw": len(rw),
                "n_bp": rec[which][wl][2],
                "ge_0x4000_raw": sum(1 for e in rw
                                     if e["raw"] >= 0x4000),
                "raw_ge_0x10000": large,
                "oob_u32_16384": sum(1 for e in rw if not e["a16384"]),
                "oob_trunc16_16384": sum(
                    1 for e in rw if e["ea16"] + e["w"] > 16384),
                "oob_15872": sum(1 for e in rw if not e["a15872"]),
                "dist_trunc16": dist("ea16"),
                "dist_u32": dist("ea_u32")}
    with open(os.path.join(OUTD, "rec_census.json"), "w") as f:
        json.dump(summ, f, indent=1)
    print(json.dumps(summ, indent=1))
    print("all deliverables written")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "s9only":
        # rebuild the §9 CSV from the event cache without re-running
        os.makedirs(OUTD, exist_ok=True)
        cache = load_events_cache()
        ent = [dict(e) for e in cache.get(("ent", "w0"), [])] + \
              [dict(e) for e in cache.get(("ent", "w7"), [])]
        orig = [dict(e) for e in cache.get(("orig", "w0"), [])] + \
               [dict(e) for e in cache.get(("orig", "w7"), [])]
        print("wrote", write_s9(ent, orig))
    else:
        main()
