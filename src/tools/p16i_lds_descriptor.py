#!/usr/bin/env python3
"""Phase 16I-4 -- descriptor-aware LDS accounting.

THE DEFECT

Every LDS model in the tree bounds a group-segment access against a
hard-coded `alloc` (16384 in the Phase-16H harnesses) or against the fixed
image size `lds_img = 0x10000`.  Neither is the number the kernel
descriptor actually declares, and the descriptor is the only place the
kernel's own contract is written down.

Measured this session, `.kd` dword 0 (`group_segment_fixed_size`):

    tag        authentic (entry-fixed)   candidate E   candidate F
    swin32f    15632                     16384         16384
    swin32t    15616                     16384         16384
    swin64f    15616                     16384         16384
    swin128f   15616                     16384         16384
    swin256f   19200                     19200         19200

So the candidates inflate the declared group segment by 768 bytes for four
of the five variants.  `phase14eh_lds_layers.md` records the original
gfx1100 `<32,false>` descriptor at 0x3D10 = 15632, matching the entry-fixed
module, so the inflation is candidate-introduced.

That matters because it decides which verdicts are even possible.  An
access at EA 16000 is OOB under the authentic contract and in-range under
the candidate's.  Measuring only against 16384 -- or only against the
original 15616 -- silently answers a different question than the one asked.

WHAT THIS DOES

Classifies every DS read/write event of the authentic one-frame dispatch
against ALL of the bounds at once, and reports the band between the
authentic and candidate declarations separately, per site and per
mnemonic.  It also reports the `trunc16` reclassification, since the
64-KiB-datapath hypothesis is the competing model for the high-bit class.

It does not change `HWCore.alloc`, so the Phase-16H numbers stay
comparable; the classification is computed independently from the same
event stream.

Host-only.  No GPU.  Nothing frozen is modified.

Usage:
  p16i_lds_descriptor.py [--tags swin32f,...] [--round-cap N]
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
for p in ("phase16i_closure/tools", "phase16h_pcrel_fix/tools",
          "phase16e_candidate_e/tools", "phase14e_static/tools",
          "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
          "phase14d11_static", "phase14d_static/tools", "phase8_static/tools",
          "phase14d8_static/tools"):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)

import p16h_lib as L                 # noqa: E402
import p16h_global_gate as G         # noqa: E402
import p16e_rec as rec               # noqa: E402
import p16i_isa as ISA               # noqa: E402
import p16i_authentic_harness as AH  # noqa: E402

AUTH_CO = "phase14_entry_fixed_module/gfx1030_dlssnr_module_entryfixed.co"
CAND_CO = "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co"

U32 = 0xFFFFFFFF

# Fixed comparison bounds, independent of either descriptor.  15872 is the
# CP/program-register granulation recorded in phase14eh_lds_layers.md;
# 16384 is the historical harness constant and the candidate declaration;
# 65536 is the full LDS datapath width.
FIXED_BOUNDS = [("cp_gran_15872", 15872), ("harness_16384", 16384),
                ("datapath_65536", 65536)]


def kd_group_segment(path, kd_name):
    """`group_segment_fixed_size` = kernel descriptor dword 0 (byte 0)."""
    e = L.Elf(path)
    for s in e.symbols:
        if s["name"] == kd_name and s["size"] == 64:
            b = e.read_va(s["value"], 64)
            if b:
                return struct.unpack_from("<I", b, 0)[0]
    return None


class DescLdsCore(G.GateCore):
    """`GateCore` + multi-bound DS classification.

    `RecCore.step` calls `_record_ds` inside a bare `try/except`, so any
    exception here would silently produce zero counts -- indistinguishable
    from a kernel that touches no LDS.  Every failure is therefore caught
    and recorded in `errors`, and `main()` refuses to report a cell whose
    error list is non-empty.
    """

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        # `hw_ev` is drained per dispatch by `_record_ds` below, so it stays
        # a real list: this tool classifies every record it contains.
        # `ds_ops` and `hw_memviol` are never read here -- only their
        # lengths, which `AggRecords` reports exactly -- so they stay
        # aggregated and bounded instead of growing with the run.
        agg = type(self).agg_lds
        if agg:
            assert not isinstance(self.ds_ops, list)
            assert not isinstance(self.hw_memviol, list)
        self.hw_ev = []

    bounds = ()
    counts = None
    trunc16_counts = None
    band = None
    band_by_site = None
    band_by_mnem = None
    n_rw = 0
    n_bp = 0
    ea_min = None
    ea_max = None
    errors = None

    @classmethod
    def reset(cls, bounds):
        cls.bounds = list(bounds)
        cls.counts = {lbl: [0, 0] for lbl, _ in cls.bounds}
        cls.trunc16_counts = {lbl: [0, 0] for lbl, _ in cls.bounds}
        cls.band = {"lo": None, "hi": None, "n_read": 0, "n_write": 0}
        cls.band_by_site = {}
        cls.band_by_mnem = {}
        cls.n_rw = 0
        cls.n_bp = 0
        cls.ea_min = None
        cls.ea_max = None
        cls.errors = []

    def _record_ds(self, ins):
        cls = type(self)
        n0 = len(self.hw_ev)
        try:
            super()._record_ds(ins)
        except Exception as e:                            # noqa: BLE001
            cls.errors.append("super._record_ds: %s: %s"
                              % (type(e).__name__, e))
            return
        if len(self.hw_ev) <= n0:
            return
        recs = self.hw_ev[n0:]
        del self.hw_ev[n0:]
        try:
            for rec in recs:
                if rec.get("kind") != "rw":
                    cls.n_bp += 1
                    continue
                cls.n_rw += 1
                raw = rec["ea_u32"]
                w = rec["w"]
                st = 1 if rec["store"] else 0
                if cls.ea_min is None or raw < cls.ea_min:
                    cls.ea_min = raw
                if cls.ea_max is None or raw > cls.ea_max:
                    cls.ea_max = raw
                for lbl, limit in cls.bounds:
                    if raw + w <= limit:
                        cls.counts[lbl][st] += 1
                t16 = raw & 0xFFFF
                for lbl, limit in cls.bounds:
                    if t16 + w <= limit:
                        cls.trunc16_counts[lbl][st] += 1
                # the band: legal under the candidate, not under the
                # authentic contract
                auth = cls.counts_auth_limit
                cand = cls.counts_cand_limit
                if auth is not None and cand is not None \
                        and raw + w > auth and raw + w <= cand:
                    cls.band["n_read" if not st else "n_write"] += 1
                    if cls.band["lo"] is None or raw < cls.band["lo"]:
                        cls.band["lo"] = raw
                    if cls.band["hi"] is None or raw + w > cls.band["hi"]:
                        cls.band["hi"] = raw + w
                    sk = "0x%08X" % (rec.get("site") or 0)
                    cls.band_by_site[sk] = cls.band_by_site.get(sk, 0) + 1
                    mk = rec.get("mnem") or "?"
                    cls.band_by_mnem[mk] = cls.band_by_mnem.get(mk, 0) + 1
        except Exception as e:                            # noqa: BLE001
            cls.errors.append("classify: %s: %s" % (type(e).__name__, e))

    # limits used for the band, set by main() via the class
    counts_auth_limit = None
    counts_cand_limit = None


def run_tag(tag, csv, waves, region_mib, round_cap, auth_gs, cand_gs):
    bounds = [("auth_%d" % auth_gs, auth_gs),
              ("cand_%d" % cand_gs, cand_gs)] + FIXED_BOUNDS
    # `_record_ds` uses `type(self)`, which is the COMPOSED class, not
    # DescLdsCore.  Reset and read through that same class, or every
    # rebinding counter (`n_rw += 1`, `ea_min = ...`) lands on the subclass
    # while `main()` reads the parent's untouched 0.
    core = ISA.p16i_isa_core(DescLdsCore)
    core.reset(bounds)
    core.counts_auth_limit = auth_gs
    core.counts_cand_limit = cand_gs
    out_path = os.path.join(ROOT,
                            "phase16i_closure/out/p16i_lds_desc_%s.json" % tag)
    res = AH.run(tag, csv, None, None, waves, region_mib, round_cap,
                 out_path, core_cls=core)
    return res, {
        "n_rw": core.n_rw,
        "n_bp": core.n_bp,
        "ea_min": core.ea_min,
        "ea_max": core.ea_max,
        "counts": {k: {"read": v[0], "write": v[1]}
                   for k, v in core.counts.items()},
        "trunc16_counts": {k: {"read": v[0], "write": v[1]}
                           for k, v in core.trunc16_counts.items()},
        "band_auth_to_cand": dict(core.band),
        "band_by_site": dict(core.band_by_site),
        "band_by_mnem": dict(core.band_by_mnem),
        "errors": list(core.errors),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tags", default="swin32f,swin32t,swin64f,swin128f")
    ap.add_argument("--csv", default=os.path.join(
        ROOT, "phase16_authentic_decode_swin.csv"))
    ap.add_argument("--waves", type=int, default=8)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--round-cap", type=int,
                    default=int(os.environ.get("P16I_ROUND_CAP", "2000000")))
    ap.add_argument("--json", default=os.path.join(
        ROOT, "phase16i_closure/out/p16i_lds_descriptor.json"))
    a = ap.parse_args()

    auth_path = os.path.join(ROOT, AUTH_CO)
    cand_path = os.path.join(ROOT, CAND_CO)

    # MERGE, do not clobber.  This tool writes ONE aggregate file for every
    # tag it is given, so a per-tag invocation silently replaced the
    # aggregate an earlier multi-tag run had produced.  That is exactly what
    # happened in Phase 16I: `--tags swin256f` left p16i_lds_descriptor.json
    # holding swin256f alone, dropping swin32f/32t/64f/128f from it, even
    # though their per-tag outputs survived.  Read any existing aggregate
    # and update only the tags processed here.  (Same read-modify-write
    # shape as `P14_OUT_NAME` in p16h_p14_variants.py.)
    out = {}
    if os.path.exists(a.json):
        try:
            out = json.load(open(a.json, encoding="utf-8"))
            if not isinstance(out, dict):
                raise ValueError("aggregate is a %s, not an object"
                                 % type(out).__name__)
            print("merging into existing %s -- %d tag(s) already present: %s"
                  % (a.json, len(out.get("cells") or {}),
                     ", ".join(sorted(out.get("cells") or {})) or "(none)"))
        except Exception as e:                            # noqa: BLE001
            print("WARNING: unreadable existing %s (%s: %s); starting fresh"
                  % (a.json, type(e).__name__, e))
            out = {}
    out["authentic_module"] = AUTH_CO
    out["candidate_module"] = CAND_CO
    out.setdefault("descriptors", {})
    out.setdefault("cells", {})
    print("%-9s %-8s %-8s %-9s %-9s %-9s" %
          ("tag", "auth_gs", "cand_gs", "n_rw", "band", "trunc16_band"))
    for tag in [t.strip() for t in a.tags.split(",") if t.strip()]:
        kd = rec.SYM[tag] + ".kd"
        auth_gs = kd_group_segment(auth_path, kd)
        cand_gs = kd_group_segment(cand_path, kd)
        out["descriptors"][tag] = {"authentic": auth_gs, "candidate": cand_gs}
        if auth_gs is None or cand_gs is None:
            print("%-9s DESCRIPTOR UNREADABLE" % tag)
            out["cells"][tag] = {"error": "descriptor unreadable"}
            continue
        try:
            res, s = run_tag(tag, a.csv, a.waves, a.region_mib, a.round_cap,
                             auth_gs, cand_gs)
        except Exception as e:                            # noqa: BLE001
            out["cells"][tag] = {"error": "%s: %s" % (type(e).__name__, e)}
            print("%-9s ERROR %s: %s" % (tag, type(e).__name__, e))
            continue
        s["outcome"] = res["outcome"]
        s["ticks"] = res["ticks"]
        s["global_gate"] = res["gate"]["gate"]
        out["cells"][tag] = s

        band = s["band_auth_to_cand"]
        tb = (s["trunc16_counts"]["auth_%d" % auth_gs]["read"]
              + s["trunc16_counts"]["auth_%d" % auth_gs]["write"])
        print("%-9s %-8d %-8d %-9d %-9s %-9d" %
              (tag, auth_gs, cand_gs, s["n_rw"],
               band["n_read"] + band["n_write"], tb))
        if s["errors"]:
            print("      ERRORS: %s" % s["errors"][:4])
        elif s["n_rw"] == 0:
            print("      WARNING: zero DS events classified -- recorder "
                  "may not have run (RecCore.step swallows exceptions)")
        c = s["counts"]
        print("      in-range by bound (read/write): " + "  ".join(
            "%s=%d/%d" % (k, v["read"], v["write"]) for k, v in c.items()))
        if s["band_by_site"]:
            print("      band sites: " + ", ".join(
                "%s:%d" % kv for kv in
                sorted(s["band_by_site"].items(), key=lambda x: -x[1])[:8]))
        if s["band_by_mnem"]:
            print("      band mnems: " + ", ".join(
                "%s:%d" % kv for kv in
                sorted(s["band_by_mnem"].items(), key=lambda x: -x[1])[:8]))

    json.dump(out, open(a.json, "w", encoding="utf-8"), indent=1)
    print("wrote " + a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
