#!/usr/bin/env python3
"""Phase 16H — P13: module-wide authentic-kernel audit.

Host-only.  No GPU execution.

Joins three independent records into one table:

  * the module's own kernel inventory (every symbol with a 64-byte
    `*.kd` kernel descriptor) -- 34 kernels;
  * the authentic GTA dispatch record
    (`phase16_authentic_kernel_census.csv`, from the mod's own capture)
    -- which kernels GTA actually launched, and how many times;
  * the P2 PC-relative census (`out/pcrel_census.json`, 82 sites) and the
    P4/P5 fix manifest
    (`phase16h_candidate_f/pcrel_fix_manifest.json`, 82 rewrites).

and answers, per kernel: does GTA use it, does it carry PC-relative
address formation, and does Candidate F's rewrite resolve inside the
intended object.

Emits out/p13_module_audit.json.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p16h_lib as L  # noqa: E402
import p16h_global_gate as G  # noqa: E402

CENSUS_CSV = os.path.join(L.ROOT, "phase16_authentic_kernel_census.csv")
FIX_MANIFEST = os.path.join(L.ROOT, "phase16h_candidate_f",
                            "pcrel_fix_manifest.json")
ABI_JSON = os.path.join(L.P16H, "out", "p9_p10_abi.json")
FIX_DIS = os.path.join(L.ROOT, "phase16h_candidate_f", "disasm",
                       "candidate_f_gfx1030_disasm.txt")

KARG_RE = re.compile(
    r"^s_load_\w+\s+s(?:\[\d+:\d+\]|\d+),\s*s\[0:1\],\s*"
    r"(0x[0-9A-Fa-f]+|\d+)")


def emulator_handlers():
    """Every mnemonic the *harness actually used* can execute.

    The set is the union of the MROs of the classes the P12 run instantiates
    -- P12Core (global gate + scratch gate + branch tracing) and the
    Phase-16E E16Core it inherits semantics from.  Scanning only
    `p14eh.HWCore` would miss handlers those subclasses add, e.g.
    `op_scratch_store_dwordx2` in `p16e_rec`.
    """
    import p16e_rec
    import p16h_p12_emulate as P12
    names = set()
    seen = set()
    for root in (P12.P12Core, p16e_rec.E16Core, G.p14eh.HWCore):
        for cls in root.__mro__:
            if cls in seen:
                continue
            seen.add(cls)
            for n in vars(cls):
                if n.startswith("op_"):
                    names.add(n[3:])
    return names


def norm_mnem(m):
    m = m.replace("_e32", "").replace("_e64", "")
    if m.startswith("v_dual_"):
        m = "v_" + m[len("v_dual_"):]
    return m


def kernel_isa(handlers, prog):
    """Mnemonics present in a kernel body with no emulator handler."""
    missing = Counter()
    for ins in prog:
        m = norm_mnem(ins["mnemonic"])
        if m.startswith("v_cmp_") or m.startswith("v_cmpx_"):
            continue
        if m not in handlers:
            missing[ins["mnemonic"]] += 1
    return missing


def kernel_hidden_reads(prog, hidden_lo, kernarg_size):
    """Kernarg offsets >= hidden_lo that the kernel loads from s[0:1]."""
    offs = Counter()
    for ins in prog:
        m = KARG_RE.match(ins["text"].strip())
        if not m:
            continue
        off = int(m.group(1), 16) if m.group(1).startswith("0x") else int(m.group(1))
        if hidden_lo is not None and off >= hidden_lo:
            offs[off] += 1
    return offs


def module_kernels(co):
    """Every kernel descriptor in the module: name -> {kernarg, gsf, psf}."""
    import struct
    e = L.Elf(co)
    out = {}
    for s in e.symbols:
        if not s["name"].endswith(".kd") or s["size"] != 64:
            continue
        b = e.read_va(s["value"], 64)
        if not b:
            continue
        gsf, psf, ks, _r = struct.unpack_from("<IIII", b, 0)
        out[s["name"][:-3]] = {"gsf": gsf, "psf": psf, "kernarg": ks,
                               "kd_va": s["value"]}
    return out


def authentic():
    """mangled -> {launched, launches} from the mod's own capture."""
    out = {}
    with open(CENSUS_CSV, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            out[r["mangled"]] = {
                "launched": r["launched"].strip().lower() == "true",
                "launches": int(r["total_launches"] or 0),
                "policy_class": r["policy_class"],
                "dispatch_ptr": r["dispatch_ptr"] == "1",
            }
    return out


def main():
    OUT = os.path.join(L.P16H, "out")
    os.makedirs(OUT, exist_ok=True)

    # ---- the three records -------------------------------------------
    kerns = module_kernels(L.CAND_CO)
    auth = authentic()
    census = json.load(open(os.path.join(OUT, "pcrel_census.json")))
    fix = json.load(open(FIX_MANIFEST))

    # F's per-site resolution, keyed by (symbol, orig_pc)
    res_by_site = {}
    for r in fix["resolution"]:
        res_by_site[(r["symbol"], r["orig_pc"])] = r
    # normalise the census' orig_pc formatting to the manifest's
    def norm(pc):
        return "0x%08X" % int(pc, 16)

    sites_by_kernel = defaultdict(list)
    for r in census["rows"]:
        sites_by_kernel[r["symbol"]].append(r)

    # ---- the three risk dimensions the brief asks for ----------------
    abi = json.load(open(ABI_JSON))
    scratch_ops = abi.get("scratch_ops_per_kernel", {})
    handlers = emulator_handlers()
    print("emulator handlers: %d distinct mnemonics" % len(handlers))

    # per-kernel hidden-arg start: the lowest offset of any `hidden_*` arg
    # in that kernel's own descriptor, read from the module metadata.
    hidden_start = {kname: None for kname in kerns}
    try:
        import p16h_abi_probe as AP  # noqa: E402
        for rec in AP.kernels(AP.md_of(L.CAND_CO)):
            nm = rec.get("name")
            lo = None
            for a_ in rec.get("args", []):
                if str(a_.get("value_kind", "")).startswith("hidden_"):
                    lo = a_["offset"] if lo is None else min(lo, a_["offset"])
            if nm in hidden_start:
                hidden_start[nm] = lo
    except Exception as exc:  # pragma: no cover - diagnostic only
        print("  (hidden-arg offset extraction unavailable: %s)" % exc)

    # ---- per-kernel table --------------------------------------------
    rows = []
    for name in sorted(kerns):
        k = kerns[name]
        a = auth.get(name)
        ss = sites_by_kernel.get(name, [])
        targets = Counter(s["orig_target"] for s in ss)
        kinds = Counter(s["access_kinds"] for s in ss)
        n_inside = 0
        unresolved = []
        for s in ss:
            rr = res_by_site.get((name, norm(s["orig_pc"])))
            if rr is None:
                unresolved.append(s["orig_pc"])
            elif rr.get("inside"):
                n_inside += 1

        # ISA coverage + hidden-arg reads, over this kernel's own body
        try:
            prog_k, _r, _i = G.PE.slice_program(FIX_DIS, name)
        except Exception:
            prog_k = []
        isa_missing = kernel_isa(handlers, prog_k) if prog_k else Counter()
        h_lo = hidden_start.get(name)
        h_reads = (kernel_hidden_reads(prog_k, h_lo, k["kernarg"])
                   if prog_k and h_lo is not None else Counter())

        rows.append({
            "kernel": name,
            "kernarg": k["kernarg"], "gsf": k["gsf"], "psf": k["psf"],
            "gta_used": bool(a and a["launched"]),
            "launches": a["launches"] if a else 0,
            "in_capture_table": a is not None,
            "n_sites": len(ss),
            "targets": dict(targets),
            "access_kinds": dict(kinds),
            "n_fixed_inside": n_inside,
            "n_fixed_unresolved": len(unresolved),
            "unresolved": unresolved,
            "n_insn": len(prog_k),
            "scratch_ops": scratch_ops.get(name, 0),
            "uses_scratch": (k["psf"] > 0) or scratch_ops.get(name, 0) > 0,
            "hidden_lo": h_lo,
            "hidden_read_offsets": dict(h_reads),
            "n_hidden_reads": sum(h_reads.values()),
            "uses_hidden_args": sum(h_reads.values()) > 0,
            "isa_unimplemented": dict(isa_missing),
            "n_isa_unimplemented": sum(isa_missing.values()),
        })

    used = [r for r in rows if r["gta_used"]]
    unused = [r for r in rows if not r["gta_used"]]
    used_sites = sum(r["n_sites"] for r in used)
    unused_sites = sum(r["n_sites"] for r in unused)
    total_sites = sum(r["n_sites"] for r in rows)
    total_inside = sum(r["n_fixed_inside"] for r in rows)

    # ---- the other four SWIN variants, explicitly ---------------------
    variants = {}
    for name in sorted(kerns):
        if not name.startswith("_Z10k_swin_varILi"):
            continue
        r = next(x for x in rows if x["kernel"] == name)
        variants[name] = {"gta_used": r["gta_used"],
                          "launches": r["launches"],
                          "n_sites": r["n_sites"],
                          "n_fixed_inside": r["n_fixed_inside"],
                          "targets": r["targets"]}

    # ---- print --------------------------------------------------------
    print("=" * 92)
    print("P13 — module-wide authentic-kernel audit (host-only)")
    print("=" * 92)
    print("kernels in module: %d ; in authentic capture table: %d"
          % (len(kerns), sum(1 for r in rows if r["in_capture_table"])))
    print("GTA-used: %d   not used: %d" % (len(used), len(unused)))
    print("PC-relative sites: %d total = %d in GTA-used + %d in unused"
          % (total_sites, used_sites, unused_sites))
    print("Candidate F rewrites resolving inside the intended object: "
          "%d of %d" % (total_inside, total_sites))

    print("\n%-54s %-5s %-7s %-5s %-14s %s"
          % ("kernel", "used", "launch", "sites", "target(s)", "F ok"))
    for r in sorted(rows, key=lambda x: (not x["gta_used"], -x["n_sites"],
                                         x["kernel"])):
        tg = ",".join("%s x%d" % (t.split("x")[-1].lstrip("0") or "0", c)
                      for t, c in sorted(r["targets"].items()))
        print("%-54s %-5s %-7d %-5d %-14s %d/%d"
              % (r["kernel"][:54], "YES" if r["gta_used"] else "-",
                 r["launches"], r["n_sites"], tg or "-",
                 r["n_fixed_inside"], r["n_sites"]))

    print("\n--- the five SWIN variants ---")
    for n, v in variants.items():
        print("  %-46s used=%-5s launches=%-5d sites=%-3d F-ok=%d/%d"
              % (n[:46], v["gta_used"], v["launches"], v["n_sites"],
                 v["n_fixed_inside"], v["n_sites"]))

    print("\n--- sites by access kind (all 82) ---")
    kinds = Counter()
    for r in rows:
        for k, v in r["access_kinds"].items():
            kinds[k] += v
    for k, v in kinds.most_common():
        print("  %-40s %d" % (k, v))

    # ---- the three risk dimensions, over the GTA-used kernels --------
    print("\n--- GTA-used kernels by risk dimension ---")
    print("%-50s %-8s %-9s %-9s" % ("kernel", "scratch", "hidden", "unimpl"))
    for r in sorted(used, key=lambda x: -(x["n_isa_unimplemented"]
                                          + x["n_hidden_reads"])):
        print("%-50s %-8s %-9s %-9d"
              % (r["kernel"][:50],
                 "psf=%d/%dops" % (r["psf"], r["scratch_ops"])
                 if r["uses_scratch"] else "-",
                 "off=%s x%d" % (r["hidden_lo"], r["n_hidden_reads"])
                 if r["uses_hidden_args"] else "-",
                 r["n_isa_unimplemented"]))

    n_scratch = sum(1 for r in used if r["uses_scratch"])
    n_hidden = sum(1 for r in used if r["uses_hidden_args"])
    n_unimpl = sum(1 for r in used if r["n_isa_unimplemented"])
    print("\n  GTA-used kernels: %d ; with scratch: %d ; reading hidden "
          "args: %d ; with any unimplemented mnemonic: %d"
          % (len(used), n_scratch, n_hidden, n_unimpl))

    allmiss = Counter()
    for r in used:
        for m, c in r["isa_unimplemented"].items():
            allmiss[m] += c
    if allmiss:
        print("\n  unimplemented mnemonics in GTA-used kernels:")
        for m, c in allmiss.most_common(30):
            print("     %-40s %d" % (m, c))

    # ---- how many of the sites can the authentic dispatch exercise? ---
    print("\n--- can the authentic capture exercise the fix? ---")
    print("  sites in kernels GTA dispatches      : %d" % used_sites)
    print("  sites in kernels GTA never dispatches: %d" % unused_sites)
    dead = [r for r in unused if r["n_sites"]]
    for r in dead:
        print("     %-52s %d site(s) %s"
              % (r["kernel"][:52], r["n_sites"],
                 ",".join(sorted(r["targets"]))))

    out = {
        "n_kernels_module": len(kerns),
        "n_kernels_gta_used": len(used),
        "n_kernels_unused": len(unused),
        "n_sites_total": total_sites,
        "n_sites_in_gta_used": used_sites,
        "n_sites_in_unused": unused_sites,
        "n_sites_fixed_inside": total_inside,
        "n_sites_fixed_unresolved": total_sites - total_inside,
        "variants": variants,
        "rows": rows,
    }
    json.dump(out, open(os.path.join(OUT, "p13_module_audit.json"), "w"),
              indent=1)
    print("\nwrote", os.path.join(OUT, "p13_module_audit.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
