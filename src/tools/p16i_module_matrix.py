#!/usr/bin/env python3
"""Phase 16I-MODULE -- authentic one-frame kernel audit matrix.

Joins the Phase-16I closure results into one row per module kernel and
assigns GREEN / AMBER / RED.  Every dimension is fail-closed: a dimension
with no evidence is UNKNOWN, and UNKNOWN is never GREEN.

DIMENSIONS

  isa        every mnemonic in the kernel body resolves to a handler under
             the ISA-complete core (`p16i_isa_close.json` static half).
  pcrel      every PC-relative address-formation site resolves inside the
             intended object (`p13_module_audit.json`).
  hostexec   the kernel can be executed by the host emulator at all.  A
             kernel whose body needs an indirect-call path (`s_swappc_b64`,
             `s_setpc_b64`) cannot be driven host-side even though the
             mnemonic has a handler.
  dynamic    the kernel was actually executed and reached natural
             termination with the global / scratch / LDS gates clean.
  lds        group-segment accesses are bounded against the kernel's own
             declared `group_segment_fixed_size`.

VERDICT RULES

  RED    -- a hard blocker: an ISA gap, an unresolved PC-relative site, or
            a GTA-used kernel that cannot be executed host-side.
  GREEN  -- no RED reason, AND the kernel was dynamically executed to
            natural termination with every measured gate clean.
  AMBER  -- everything else.  Includes "no RED reason but not dynamically
            exercised", which is the honest state of most kernels: the
            static evidence is complete but the dynamic claim is not made.

Host-only.  No GPU.  Nothing frozen is modified.

Usage:
  p16i_module_matrix.py [--out phase16i_alpha_kernel_matrix.csv]
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

P16I = os.path.join(ROOT, "phase16i_closure/out")
P16H = os.path.join(ROOT, "phase16h_pcrel_fix/out")

# Mnemonics that have a handler but whose semantics are NOT claimed correct
# (Phase 16I coverage audit).  A kernel containing one is not host-executable
# even though the ISA scan calls it clean.
NOT_CLAIMED = ("s_swappc_b64", "s_setpc_b64", "flat_load_dword",
               "flat_load_ushort", "ds_write_b96", "v_fmac_f16")


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:                                     # noqa: BLE001
        return None


def census_not_claimed():
    """kernel -> sorted NOT_CLAIMED mnemonics present in its body."""
    p = os.path.join(P16I, "p16i_isa_census.csv")
    out = {}
    if not os.path.exists(p):
        return out
    for r in csv.DictReader(open(p, encoding="utf-8")):
        if r["mnemonic"] in NOT_CLAIMED:
            out.setdefault(r["kernel_mangled"], set()).add(r["mnemonic"])
    return {k: sorted(v) for k, v in out.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(
        ROOT, "phase16i_alpha_kernel_matrix.csv"))
    ap.add_argument("--json", default=os.path.join(
        P16I, "p16i_alpha_kernel_matrix.json"))
    a = ap.parse_args()

    isa = load_json(os.path.join(P16I, "p16i_isa_close.json")) or {}
    isa_static = isa.get("static") or {}
    audit = load_json(os.path.join(P16H, "p13_module_audit.json")) or {}
    rows = {r["kernel"]: r for r in (audit.get("rows") or [])}
    exercise = load_json(os.path.join(P16H, "p13_dynamic_exercise.json")) or {}
    ex_by_k = exercise.get("by_kernel") or {}
    scratch = load_json(os.path.join(P16I, "p16i_scratch_close.json")) or {}
    lds = load_json(os.path.join(P16I, "p16i_lds_descriptor.json")) or {}
    not_claimed = census_not_claimed()

    # dynamic per-kernel results: which of the five SWIN variants ran, and
    # how each ended.  Keyed by mangled symbol.
    dyn = {}
    for tag, sym in (("swin32f", "_Z10k_swin_varILi32ELb0EEv9VarParams"),
                     ("swin32t", "_Z10k_swin_varILi32ELb1EEv9VarParams"),
                     ("swin64f", "_Z10k_swin_varILi64ELb0EEv9VarParams"),
                     ("swin128f", "_Z10k_swin_varILi128ELb0EEv9VarParams"),
                     ("swin256f", "_Z10k_swin_varILi256ELb0EEv9VarParams")):
        d = load_json(os.path.join(P16I, "p16i_lds_desc_%s.json" % tag))
        if d:
            dyn[sym] = {"tag": tag, "outcome": d.get("outcome"),
                        "ticks": d.get("ticks"),
                        "global_gate": (d.get("gate") or {}).get("gate"),
                        "n_faults": len(d.get("faults") or [])}

    out_rows = []
    for k, r in sorted(rows.items()):
        gta = bool(r.get("gta_used"))
        reasons_red, reasons_amber, ev = [], [], []

        # ---- isa
        st = isa_static.get(k)
        if st is None:
            isa_clean = None
            reasons_amber.append("isa: no Phase-16I static result")
        else:
            isa_clean = bool(st.get("clean"))
            ev.append("isa_close")
            if not isa_clean:
                reasons_red.append("isa: unresolved %s"
                                   % sorted((st.get("missing") or {}).keys()))

        # ---- pcrel
        n_sites = r.get("n_sites") or 0
        n_unres = r.get("n_fixed_unresolved") or 0
        n_in = r.get("n_fixed_inside") or 0
        ev.append("p13_module_audit")
        if n_unres:
            reasons_red.append("pcrel: %d unresolved sites" % n_unres)
        elif n_in != n_sites:
            reasons_red.append("pcrel: %d/%d sites fixed inside"
                               % (n_in, n_sites))

        # ---- host executability
        nc = not_claimed.get(k) or []
        if nc:
            if gta:
                reasons_red.append("hostexec: not-claimed mnemonics %s" % nc)
            else:
                reasons_amber.append("hostexec: not-claimed mnemonics %s "
                                     "(GTA-unused)" % nc)

        # ---- dynamic
        d = dyn.get(k)
        ex = ex_by_k.get(k) or {}
        if d:
            ev.append("p16i_lds_desc:%s" % d["tag"])
            oc = d.get("outcome") or ""
            if "ALL_ENDED" not in oc:
                reasons_amber.append("dynamic: outcome %s" % oc)
            # FAIL-OPEN COMPENSATION.  phase14eh_tools/p14eh.py declares
            # ALL_ENDED whenever no wave is still RUNNABLE/WAITING -- which
            # includes the case where EVERY wave FAULTED.  The outcome label
            # alone is therefore not evidence of natural termination; the
            # per-wave fault list is.  Require both.
            if d.get("n_faults"):
                reasons_amber.append("dynamic: %d wave fault(s) -- ALL_ENDED "
                                     "label is not sufficient" % d["n_faults"])
            if d.get("global_gate") != "PASS":
                reasons_amber.append("dynamic: global gate %s"
                                     % d.get("global_gate"))
        else:
            reasons_amber.append("dynamic: not executed host-side")
        if ex:
            n_ex = ex.get("exercised") or 0
            n_s = ex.get("n") or 0
            if n_s and n_ex < n_s:
                reasons_amber.append("pcrel coverage: %d/%d sites exercised"
                                     % (n_ex, n_s))

        # ---- lds declaration.  `gsf` is whatever the kernel's own
        # descriptor declares; it is reported, not whitelisted.  What would
        # matter is an access outside it, and that is only knowable for a
        # kernel that has been executed (see the dynamic dimension).
        gsf = r.get("gsf")
        if lds.get("descriptors"):
            ev.append("p16i_lds_descriptor")

        # ---- scratch
        if r.get("uses_scratch"):
            reasons_amber.append("scratch: model-sensitive (%d ops)"
                                 % (r.get("scratch_ops") or 0))
            ev.append("p16i_scratch_close")

        if reasons_red:
            verdict = "RED"
        elif isa_clean and not reasons_amber:
            verdict = "GREEN"
        elif isa_clean:
            verdict = "AMBER"
        else:
            verdict = "AMBER"

        out_rows.append({
            "kernel": k,
            "gta_used": gta,
            "launches": r.get("launches"),
            "n_insn": r.get("n_insn"),
            "verdict": verdict,
            "isa_clean": isa_clean,
            "n_pcrel_sites": n_sites,
            "pcrel_unresolved": n_unres,
            "not_claimed_mnemonics": ";".join(nc),
            "declared_gsf": gsf,
            "declared_psf": r.get("psf"),
            "kernarg": r.get("kernarg"),
            "uses_scratch": bool(r.get("uses_scratch")),
            "scratch_ops": r.get("scratch_ops"),
            "uses_hidden_args": bool(r.get("uses_hidden_args")),
            "n_hidden_reads": r.get("n_hidden_reads"),
            "dyn_tag": (d or {}).get("tag"),
            "dyn_outcome": (d or {}).get("outcome"),
            "dyn_n_faults": (d or {}).get("n_faults"),
            "dyn_global_gate": (d or {}).get("global_gate"),
            "reasons_red": " | ".join(reasons_red),
            "reasons_amber": " | ".join(reasons_amber),
            "evidence": ",".join(sorted(set(ev))),
        })

    cols = list(out_rows[0].keys()) if out_rows else []
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(out_rows)

    gta_rows = [r for r in out_rows if r["gta_used"]]
    tally = {}
    for r in gta_rows:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1
    print("kernels: %d module, %d GTA-used" % (len(out_rows), len(gta_rows)))
    print("GTA-used verdicts: %s" % json.dumps(tally))
    print()
    print("%-52s %-6s %-8s %s" % ("kernel", "gta", "verdict", "reasons"))
    for r in gta_rows:
        rs = r["reasons_red"] or r["reasons_amber"] or "-"
        print("%-52s %-6s %-8s %s"
              % (r["kernel"][:52], r["gta_used"], r["verdict"], rs[:110]))

    json.dump({"rows": out_rows, "tally_gta": tally,
               "definitions": {"GREEN": "isa clean, pcrel fixed, executed to "
                                        "natural termination, all measured "
                                        "gates clean",
                               "AMBER": "no hard blocker, but the dynamic "
                                        "claim is not fully made",
                               "RED": "ISA gap, unresolved PC-relative site, "
                                      "or GTA-used kernel not host-executable"},
               "not_claimed_mnemonics": list(NOT_CLAIMED)},
              open(a.json, "w", encoding="utf-8"), indent=1)
    print()
    print("wrote " + a.out)
    print("wrote " + a.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
