#!/usr/bin/env python3
"""Phase 16I-P8 -- Candidate F run with an AUTHENTIC VarParams.

Replaces the synthetic harness (`p16e_rec.fields_for`, nine synthetic slot
pointers) with the layout recovered in `phase16i_varparams_proof.md`:

  * 0x00/0x08/0x10/0x30/0x38/0xA0  <- the captured values for the chosen cell
    (real device VAs, not synthetic slot addresses)
  * 0x18/0x1C/0x20/0x24/0x28      <- authentic scalars
  * 0x40..0x9F                    <- ZERO (proven: the host zeroes all 96
    bytes on every launch path).  The synthetic harness instead wrote
    pointers at 0x48/0x78/0x80; those three are the non-authenticities.
  * 0x2C                          <- padding, never written, never read

Region declarations follow the same principle: real VAs, sizes stated
explicitly rather than chosen to make the gate pass.

  * canvas (0xA0): size = grid.x*grid.y*8192, the mod's own allocation
    formula (proven in the proof doc).
  * every other pointer field: `--region-mib` (default 64 MiB), a stated
    harness parameter.  The per-site report prints the maximum offset
    actually reached so the margin is visible and the conclusion auditable.

Host-only.  No GPU.

Usage:
  p16i_authentic_harness.py [--variant swin32f] [--csv phase16_authentic_decode_swin.csv]
                            [--wave 0] [--region-mib 64] [--out OUT.json]
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
for p in ("phase16h_pcrel_fix/tools", "phase16e_candidate_e/tools",
          "phase14e_static/tools", "phase14eh_tools", "phase14eg_tools",
          "phase14e_forensics/tools", "phase14d11_static",
          "phase14d_static/tools", "phase8_static/tools",
          "phase14d8_static/tools"):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)

import p16h_lib as L          # noqa: E402
import p16h_global_gate as G  # noqa: E402
import p16h_p12_emulate as P12  # noqa: E402
import p16h_scratch_probe as SP  # noqa: E402
import p16e_rec as rec        # noqa: E402
import p16e_lib               # noqa: E402

# The LDS bound is the kernel's OWN declaration, read from its descriptor,
# not a constant.  Candidate F declares 16,384 for four of the five SWIN
# variants and 19,200 for `<256,false>`; a hard-coded 16,384 scores 32,768
# legitimate `<256,false>` accesses as out of bounds.
FALLBACK_GROUP_BYTES = 16384

# fields_for is replaced entirely; fail loudly if the synthetic one is used.
assert not hasattr(rec, "_AUTHENTIC"), "harness module already patched"

SYM = rec.SYM
# tag -> the mod's own display name for that instantiation, as printed in
# phase16_authentic_decode_swin.csv
DISPLAY = {"swin32t": "swin<32,true>", "swin32f": "swin<32,false>",
           "swin64f": "swin<64,false>", "swin128f": "swin<128,false>",
           "swin256f": "swin<256,false>"}

# The three struct offsets the synthetic harness populated with pointers that
# are authentically zero.  Recorded here so the report can name them.
SYNTHETIC_POINTER_OFFSETS = (0x48, 0x78, 0x80)


def load_cell(csv_path, tag, frame=None, launch=None):
    """Return the captured field values for one authentic SWIN dispatch."""
    want = DISPLAY[tag]
    rows = list(csv.DictReader(open(csv_path, encoding="utf-8",
                                    errors="replace")))
    for r in rows:
        if r["variant"] != want:
            continue
        if frame is not None and int(r["frame"]) != frame:
            continue
        if launch is not None and int(r["launch_in_frame"]) != launch:
            continue
        f = {}
        for k, off in (("d_p0", 0x00), ("d_p1", 0x08), ("d_p2", 0x10),
                       ("d_p3", 0x30), ("d_p4", 0x38), ("d_pA0", 0xA0)):
            f[off] = int(r[k], 16)
        for k, off in (("d_X", 0x18), ("d_Y", 0x1C), ("d_pair_lo", 0x20),
                       ("d_pair_hi", 0x24), ("d_flags", 0x28)):
            f[off] = int(r[k], 0)
        meta = {"variant": want, "frame": int(r["frame"]),
                "launch_in_frame": int(r["launch_in_frame"]),
                "grid": (int(r["grid_x"]), int(r["grid_y"]), int(r["grid_z"])),
                "block": (int(r["block_x"]), int(r["block_y"]),
                          int(r["block_z"])),
                "kernel_mangled": r["kernel_mangled"],
                "row": r}
        return f, meta
    raise SystemExit("no authentic row for %s" % want)


# The offsets that are POINTERS in the authentic VarParams, and the only
# ones that may be turned into declared memory regions.  Kept as a named
# tuple because the distinction is load-bearing: 0x18/0x1C/0x20/0x24/0x28
# are the scalars X, Y, pair.lo, pair.hi and flags, and declaring a region
# at a scalar's *value* invents memory that does not exist.
POINTER_OFFSETS = (0x00, 0x08, 0x10, 0x30, 0x38, 0xA0)
SCALAR_OFFSETS = (0x18, 0x1C, 0x20, 0x24, 0x28)


def authentic_fields(vals):
    """{offset: (kind, value)} for swin_mem.  Offsets absent from the dict are
    left at 0 by the sparse kernarg model -- which is authentic for
    0x40..0x9F."""
    fields = {}
    for off in POINTER_OFFSETS:
        fields[off] = ("u64", vals[off])
    for off in SCALAR_OFFSETS:
        fields[off] = ("u32", vals[off] & 0xFFFFFFFF)
    # Explicitly pin the three formerly-synthetic offsets to zero.  The
    # sparse model already yields 0, but stating it makes the harness
    # self-documenting and guards against a future default change.
    for off in SYNTHETIC_POINTER_OFFSETS:
        fields[off] = ("u64", 0)
    return fields


SIG_KEYS = ("wave", "state", "steps", "barriers", "fault", "n_rw", "n_bp",
            "memviol", "oob_read_zero", "oob_write_discard")


def execution_signature(res):
    """Everything about the dispatch that a re-run must reproduce.

    Recorded separately from the gate so an input-induced change and a
    gate-model change cannot be confused: the gate describes what the
    memory model saw, this describes what the kernel did.
    """
    import hashlib
    sig = {
        "outcome": res["outcome"][0],
        "ticks": res.get("ticks"),
        "n_waves": res.get("n_waves"),
        "n_ended": res.get("n_ended"),
        "n_faulted": res.get("n_faulted"),
        "capped": res.get("capped"),
        "natural_end": res.get("natural_end"),
        "barrier_epochs": len(res.get("barrier_epochs") or []),
        "per_wave": [{k: w.get(k) for k in SIG_KEYS}
                     for w in res.get("per_wave") or []],
        "slot_hashes": res.get("slot_hashes"),
    }
    sig["sha256"] = hashlib.sha256(
        json.dumps(sig, sort_keys=True).encode()).hexdigest()
    return sig


def run(tag, csv_path, frame, launch, wave_count, region_mib, round_cap,
        out_path, core_cls=None, agg_lds=True, release_registry=True,
        fill_payload=None):
    variant = DISPLAY[tag]
    sym = SYM[tag]
    vals, meta = load_cell(csv_path, tag, frame, launch)
    grid, block = meta["grid"], meta["block"]

    # Candidate F -- NOT `p16e_lib.ENT_CO`, which points at the Phase-14
    # entry-fixed REFERENCE module.  Emulating the reference here would
    # report the reference's g_e4m3_lut defect as if it were Candidate F's.
    co = os.path.join(ROOT, "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co")
    dis = os.path.join(ROOT,
                       "phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt")
    prog, _rows, _i = G.PE.slice_program(dis, sym)
    dw = G.P11.dw16(co, sym)
    fields = authentic_fields(vals)

    elf = L.Elf(co)
    ks = G.kernarg_size(elf, sym + ".kd")
    gsz = SP.group_segment_size(co, sym + ".kd")
    if gsz is None or gsz <= 0:
        gsz = FALLBACK_GROUP_BYTES
    alloc = gsz

    gx, gy = grid[0], grid[1]
    canvas_size = gx * gy * 8192          # the mod's own formula
    tensor_size = region_mib * 1024 * 1024

    ggate = G.GlobalGate()
    for lo, size, name in G.module_regions(elf):
        ggate.declare(lo, size, "module:" + name)
    if ks:
        ggate.declare(G.KERNARG, ks, "kernarg")
    ggate.declare(G.PACKET, 64, "aql_packet")

    # Declare regions for the POINTER fields only.  The previous version
    # looped over every entry in `vals`, which includes the scalars, and so
    # declared a 64 MiB region starting at X (0x480), at Y (0x780) and at
    # flags (0x14) -- inventing three large low-address windows in which a
    # genuinely out-of-bounds read was scored as legitimate.  The
    # `<32,true>` zero-base sites at 0x000941FC/0x00094204 land at 0x0..0xC
    # and stayed OOB only because 0x0 is below all three.
    for off in POINTER_OFFSETS:
        val = vals.get(off)
        if not val:
            continue
        size = canvas_size if off == 0xA0 else tensor_size
        ggate.declare(val, size, "authentic_0x%02X" % off)

    # `GateCore._gl_addr` reads its gate through the hard-coded class name
    # (`GateCore.gate`), not through `self`.  A subclass that arms only its
    # own attribute leaves the real gate unarmed, and every global access
    # then raises on a None gate -- which reads as a clean PASS.  Arm the
    # base class as well as whichever core is actually dispatched.
    core_cls = core_cls or G.GateCore
    G.GateCore.gate = ggate
    G.GateCore.wave_index = 0
    G.GateCore.oob_sem = "u32"
    G.GateCore.alloc = alloc
    G.GateCore.lds_img = 0x10000
    core_cls.gate = ggate
    core_cls.alloc = alloc

    prev = G.p14eh.HWCore
    G.p14eh.HWCore = core_cls
    try:
        orig = G.PE.text_mem_map
        G.PE.text_mem_map = G.module_mem_map
        try:
            res = G.p14eh.run_workgroup_hw(
                prog, dw, "p16i_" + tag, grid, block, fields, text_path=co,
                wave_count=wave_count, oob_sem="u32", alloc=alloc,
                wgid=(0, 0, 0), round_cap=round_cap,
                fill_payload=fill_payload,
                agg_lds=agg_lds, release_registry=release_registry)
        finally:
            G.PE.text_mem_map = orig
    finally:
        G.p14eh.HWCore = prev

    g = ggate.summary()
    # Per-site reach, taken from the gate's own retained records so the
    # margin against each declared region is auditable.
    reach = {}
    for r in ggate.oob_reads + ggate.oob_writes:
        k = "0x%08X" % (r.get("site") or 0)
        d = reach.setdefault(k, {"n": 0, "mnem": r.get("mnem"),
                                 "operands": r.get("operands"),
                                 "min": r["addr"], "max": r["addr"],
                                 "read": 0, "write": 0,
                                 "bases": r.get("bases") or {},
                                 "waves": [], "lanes": []})
        d["n"] += 1
        d["min"] = min(d["min"], r["addr"])
        d["max"] = max(d["max"], r["addr"])
        d["read" if not r["store"] else "write"] += 1
        for key, val in (("waves", r.get("wave")), ("lanes", r.get("lane"))):
            if val is not None and val not in d[key]:
                d[key].append(val)
    for k, v in g.get("oob_by_site", {}).items():
        if k in reach and "addr_range" in v:
            reach[k]["addr_range"] = v["addr_range"]

    out = {
        "variant": variant, "tag": tag, "kernel": sym,
        "cell": {k: v for k, v in meta.items() if k != "row"},
        "authentic_values": {"0x%02X" % k: "0x%016X" % v
                             for k, v in sorted(vals.items())},
        "synthetic_offsets_pinned_zero": ["0x%02X" % o
                                          for o in SYNTHETIC_POINTER_OFFSETS],
        "canvas_size_bytes": canvas_size,
        "tensor_region_bytes": tensor_size,
        "kernarg_size": ks,
        "group_segment_fixed_size": gsz,
        "lds_bound_bytes": alloc,
        "wave_count": wave_count,
        "outcome": str(res.get("outcome")),
        "ticks": res.get("ticks"),
        "barrier_epochs": len(res.get("barrier_epochs") or []),
        "faults": [w["fault"] for w in res["per_wave"] if w.get("fault")],
        "capped": res.get("capped"),
        "natural_end": res.get("natural_end"),
        "agg_lds": agg_lds,
        "execution_signature": execution_signature(res),
        "gate": g,
        "oob_reach_by_site": reach,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print("variant=%s  kernel=%s  frame=%s launch=%s"
          % (variant, sym, meta["frame"], meta["launch_in_frame"]))
    print("authentic kernarg: " + "  ".join(
        "0x%02X=0x%X" % (k, v) for k, v in sorted(vals.items()) if v))
    print("  (0x48/0x78/0x80 pinned to 0; 0x40..0x9F authentic zero)")
    print("regions: canvas=%.1f MiB  tensors=%.0f MiB each"
          % (canvas_size / 1048576.0, tensor_size / 1048576.0))
    print("outcome=%s ticks=%s faults=%s"
          % (out["outcome"], out["ticks"], out["faults"] or "none"))
    print("GATE  %s   oob_global_reads=%s  oob_global_writes=%s"
          "  n_global_reads=%s  n_global_writes=%s  unmeasured=%s"
          % (g["gate"], g["oob_global_reads"], g["oob_global_writes"],
             g["n_global_reads"], g["n_global_writes"],
             g["n_unmeasured_global_ops"]))
    if reach:
        print("residual sites: %d" % len(reach))
        for k in sorted(reach, key=lambda x: -reach[x]["n"])[:14]:
            d = reach[k]
            print("   %s  n=%-7d %-22s r=%-6d w=%-6d addr 0x%X..0x%X  bases=%s"
                  % (k, d["n"], d["mnem"], d["read"], d["write"],
                     d["min"], d["max"], d["bases"]))
    print("wrote " + out_path)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="swin32f")
    ap.add_argument("--csv", default=os.path.join(
        ROOT, "phase16_authentic_decode_swin.csv"))
    ap.add_argument("--frame", type=int, default=None)
    ap.add_argument("--launch", type=int, default=None)
    ap.add_argument("--waves", type=int, default=8)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--round-cap", type=int,
                    default=int(os.environ.get("P16I_ROUND_CAP", "2000000")))
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = a.out or os.path.join(
        ROOT, "phase16i_closure/out/p16i_authentic_%s.json" % a.tag)
    run(a.tag, a.csv, a.frame, a.launch, a.waves, a.region_mib,
        a.round_cap, out)


if __name__ == "__main__":
    main()
