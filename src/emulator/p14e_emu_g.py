"""Phase 14E-G overlay emulator (host-only, zero GPU).

Purpose: separate, per-class DS accounting for the exact failed SWIN
dispatch (k_swin_var<32,false>, grid(1,1,1) block(256,1,1), synthetic
dims 64 flags 0) on BOTH the entry-fixed translated gfx1030 stream and
the original gfx1100 stream, for boundary waves 0 and 7.

Class separation (per the 14E-G brief):
  A. real LDS read/write ops  -> kind 'rw'   (counts against allocation)
  B. ds_bpermute lane routing -> kind 'bp'   (NOT allocation usage;
     recorded separately; address operand is the source-lane field)
  C. any other ds_*           -> kind 'oth'

Each event records the RAW (pre-mask) logical DS address (vaddr + imm,
32-bit) plus width and site, so physical-allocation questions can be
answered without depending on any assumed wrap model.

The emulation VALUE semantics are left exactly as the validated legacy
model (ea = (vaddr + imm) & 0x3FFF over a 16-KiB image) so control flow
and the END outcomes reproduce p14e_emulation.json unchanged; the raw
recording is purely observational.

Model classification (reported per case):
  MODEL_A  full 32-bit logical EA, bounds-checked vs the allocated group
           segment (no wrap). alloc candidates: 15,872 (512-B granule)
           and 16,384 (1-KiB granule / 16-KiB region).
  MODEL_B  code/legacy alias model: effective = raw & 0x3FFF (16-KiB
           region); raw >= 0x4000 events are ALIAS events.
  MODEL_C  low-16-bit DS EA space (64-KiB bank view, single-WG):
           effective = raw & 0xFFFF; events whose effective span exceeds
           the carve-out are OUT_OF_CARVE events.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
E_TOOLS = os.path.join(ROOT, "phase14e_static", "tools")
OUTD = os.path.join(HERE, "out")
sys.path.insert(0, E_TOOLS)

import p14e_emu as E  # noqa: E402  (imports its own dependency paths)

U32 = 0xFFFFFFFF

# Physical allocation candidates for the 15,632-B request.
FIXED = 15632
ALLOC_512 = 15872          # roundup(FIXED, 512)   (LDS_SIZE 512-B units)
ALLOC_1K = 16384           # roundup(FIXED, 1024)  (1-KiB granule)
REGION16K = 0x4000


class GCore(E.SwinCore):
    """SwinCore + per-class raw DS recorder (legacy value path intact)."""

    registry = []

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.ds_raw = []          # dicts: kind, store, a_raw, w, site
        GCore.registry.append(self)

    def _record_ds(self, ins):
        # Legacy tuple append (unchanged semantics + layout) so trace()'s
        # ds_sum aggregates and the recorded p14e_emulation.json figures
        # reproduce exactly; then append the corrected raw observation.
        mnem = ins["mnemonic"]
        ops_raw = ins.get("operands") or ""
        olist = [o.strip() for o in ops_raw.split(",")] if ops_raw else []

        def _reg(tok):
            m = re.match(r'^v(\d+)$', tok)
            return int(m.group(1)) if m else None

        vtoks = [o for o in olist if _reg(o) is not None]
        if not vtoks:
            return
        mm = re.search(r"offset:(-?0x[0-9a-fA-F]+|-?\d+)", ops_raw)
        off = int(mm.group(1), 0) if mm else 0
        m1 = re.search(r"offset1:(-?\d+)", ops_raw)
        o1 = int(m1.group(1)) if m1 else None
        m2 = re.search(r"offset2:(-?\d+)", ops_raw)
        o2 = int(m2.group(1)) if m2 else None
        is_load = ("load" in mnem or "read" in mnem)
        is_store = ("store" in mnem or "write" in mnem)
        nb = 16 if ("128" in mnem or "x4" in mnem) else \
            8 if ("64" in mnem or "x2" in mnem or "2addr" in mnem or
                  "write2" in mnem or "read2" in mnem) else \
            4 if "32" in mnem or "b32" in mnem else \
            2 if "16" in mnem else 1
        if mnem == "ds_bpermute_b32":
            kind = "bp"
            # ISA operand order: vdst, vdata, vaddr -> LAST v-token is the
            # source-lane/address field (not an LDS allocation access).
            a_tok = vtoks[-1]
            n = _reg(a_tok)
            if n is None:
                return
            addrs = [(n, 0)]
        elif mnem.startswith("ds_"):
            kind = "oth" if not (is_load or is_store) else "rw"
            # loads/reads: (dst..., vaddr) -> address is the last v-token;
            # stores/writes: (vaddr, data...) -> address is the first.
            a_tok = vtoks[-1] if is_load else vtoks[0]
            n = _reg(a_tok)
            if n is None:
                return
            addrs = [(n, off)]
            if o1 is not None:
                unit = 8 if ("64" in mnem or "x2" in mnem) else 4
                addrs.append((n, o1 * unit))
            if o2 is not None:
                unit = 8 if ("64" in mnem or "x2" in mnem) else 4
                addrs.append((n, o2 * unit))
        else:
            return

        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                v = self.v[lane]
                for (n, imm) in addrs:
                    raw = (v[n] + imm) & U32
                    eff = raw & (REGION16K - 1)     # legacy value model
                    # legacy aggregate tuple (masked ea) -- keep old shape
                    self.ds_ops.append((is_store, eff, nb,
                                        ins.get("address")))
                    self.ds_raw.append({"kind": kind, "store": is_store,
                                        "a_raw": raw, "w": nb,
                                        "site": ins.get("address"),
                                        "mnem": mnem})


def classify(rows, alloc):
    """Model verdicts over raw rw events."""
    out = {"A": [], "B": [], "C": []}
    for r in rows:
        if r["kind"] != "rw":
            continue
        a, w = r["a_raw"], r["w"]
        if a + w > alloc:
            out["A"].append(r)            # MODEL_A OOB (bounds-checked)
        if a >= REGION16K:
            out["B"].append(r)            # MODEL_B alias (wrap to <16K)
        eff16 = a & 0xFFFF
        if eff16 + w > alloc:
            out["C"].append(r)            # MODEL_C out of carve
    return out


def summarize(rows, alloc):
    rw = [r for r in rows if r["kind"] == "rw"]
    bp = [r for r in rows if r["kind"] == "bp"]
    oth = [r for r in rows if r["kind"] == "oth"]
    s = {"count_rw": len(rw), "count_bp": len(bp), "count_oth": len(oth)}
    # Address bands over RAW rw starts (window-relevant vs absurd):
    def band(a):
        if a < 0x4000:
            return "lt_16k"
        if a < 0x8000:
            return "16k_32k"
        if a < 0x10000:
            return "32k_64k"
        return "ge_64k"

    bc = {}
    for r in rw:
        bc.setdefault(band(r["a_raw"]), 0)
        bc[band(r["a_raw"])] += 1
    for b in ("lt_16k", "16k_32k", "32k_64k", "ge_64k"):
        s[f"band_{b}"] = bc.get(b, 0)
    s["rw_stores"] = sum(1 for r in rw if r["store"])
    s["over_15872"] = len([r for r in rw if r["a_raw"] + r["w"] > 15872])
    s["over_16384"] = len([r for r in rw if r["a_raw"] + r["w"] > 16384])
    s["raw_ge_0x4000"] = len([r for r in rw if r["a_raw"] >= 0x4000])
    c = classify(rows, alloc)
    for m in ("A", "B", "C"):
        s[f"model_{m}_first"] = None
        if c[m]:
            f = c[m][0]
            s[f"model_{m}_count"] = len(c[m])
            s[f"model_{m}_first"] = {
                "site": f["site"], "mnem": f["mnem"],
                "a_raw": f["a_raw"], "w": f["w"]}
        else:
            s[f"model_{m}_count"] = 0
    # per-site census of the model-A (alloc=15872) population
    from collections import Counter
    geo = Counter((r["site"], r["mnem"]) for r in c["A"])
    s["A_sites_top"] = [{"site": k[0], "mnem": k[1], "n": v}
                        for k, v in geo.most_common(8)]
    return s


def build_fields():
    # identical to p14e_emu.main(): 9 ptr slots + dims/flags
    PTR = {}
    _next = [0]

    def ps(off):
        PTR[off] = ('ptr', _next[0])
        _next[0] += 1

    for off in (0x00, 0x08, 0x10, 0x30, 0x38, 0x48, 0x78, 0x80, 0xA0):
        ps(off)
    fields = dict(PTR)
    for off in (0x18, 0x1c, 0x20, 0x24):
        fields[off] = ('u32', 64)
    fields[0x28] = ('u32', 0)
    fields[0x98] = ('u64', 0)
    return fields


def run_case(src, co, label, wavebase):
    prog, rows, idx = E.slice_program(src, E.KERNEL)
    dw = E.dw16(co, E.KERNEL)
    fields = build_fields()
    n0 = len(GCore.registry)
    E.SwinCore = GCore          # trace() instantiates the module global
    r = E.trace(prog, dw, f"{label}", (1, 1, 1), (256, 1, 1), (0, 0, 0),
                wavebase, fields, text_path=co)
    core = GCore.registry[n0] if len(GCore.registry) > n0 else None
    return r, (core.ds_raw if core is not None else [])


def main():
    import csv as _csv
    P11 = E.P11
    srcs = [
        ("translated_ent", P11.ENT_DIS, P11.ENT_CO),
        ("original_gfx1100", P11.ORIG_DIS, P11.ORIG_OBJ),
    ]
    results = {}
    out_csv = os.path.join(ROOT, "phase14eg_lds_model_matrix.csv")
    with open(out_csv, "w", newline="") as f:
        w = _csv.writer(f)
        w.writerow(["case", "emu_outcome", "emu_steps", "count_rw",
                    "count_bp", "rw_stores",
                    "band_lt_16k", "band_16k_32k", "band_32k_64k",
                    "band_ge_64k",
                    "over_15872", "over_16384",
                    "m_A512_count", "m_A512_first",
                    "m_A16384_count", "m_A16384_first",
                    "m_B_alias_count", "m_B_first",
                    "m_C_carve512_count", "m_C_first",
                    "A512_sites_top"])
        for (sname, sdis, sco) in srcs:
            for wb, wl in ((0, "w0"), (224, "w7")):
                label = f"{sname}_{wl}"
                try:
                    r, raw = run_case(sdis, sco, label, wb)
                except Exception as exc:  # fail closed, recorded
                    row = [label, f"EXC:{type(exc).__name__}", "", "", "",
                           "", "", "", "", "", "", "", "", "", "", "", "",
                           "", "", "", ""]
                    w.writerow(row)
                    results[label] = {"error": f"{type(exc).__name__}: {exc}"}
                    print(f"{label}: ERROR {exc}")
                    continue
                s512 = summarize(raw, ALLOC_512)
                s1k = summarize(raw, ALLOC_1K)
                s = s512
                s.update({"emu_outcome": str(r["outcome"]),
                          "emu_steps": r["steps"],
                          "s_A16384": s1k})
                first512 = s["model_A_first"]
                first1k = s1k["model_A_first"]
                fb = (lambda d: (f"{d['site']:#x} {d['mnem']} "
                                 f"raw={d['a_raw']:#x}+{d['w']}")
                      if d else "")
                tops = "; ".join(
                    f"{t['site']:#x}:{t['mnem']}x{t['n']}"
                    for t in s["A_sites_top"])
                row = [label, str(r["outcome"]), r["steps"],
                       s["count_rw"], s["count_bp"], s["rw_stores"],
                       s["band_lt_16k"], s["band_16k_32k"],
                       s["band_32k_64k"], s["band_ge_64k"],
                       s["over_15872"], s["over_16384"],
                       s["model_A_count"], fb(first512),
                       s1k["model_A_count"], fb(first1k),
                       s["model_B_count"], fb(s["model_B_first"]),
                       s["model_C_count"], fb(s["model_C_first"]),
                       tops]
                w.writerow(row)
                results[label] = {"summary": s, "outcome": r["outcome"],
                                  "steps": r["steps"]}
                print(f"{label}: out={r['outcome']} steps={r['steps']} "
                      f"rw={s['count_rw']} bp={s['count_bp']} "
                      f"bands=[{s['band_lt_16k']},{s['band_16k_32k']},"
                      f"{s['band_32k_64k']},{s['band_ge_64k']}] "
                      f">15872={s['over_15872']} >16384={s['over_16384']} "
                      f"A512={s['model_A_count']} "
                      f"A1K={s1k['model_A_count']} "
                      f"B={s['model_B_count']} C={s['model_C_count']}")
    with open(os.path.join(OUTD, "p14e_emu_g_results.json"), "w") as f:
        json.dump(results, f, indent=1, default=str)
    print("wrote", out_csv)
    print("wrote", os.path.join(OUTD, "p14e_emu_g_results.json"))


if __name__ == "__main__":
    main()
