#!/usr/bin/env python3
"""Phase 16J — which of the files this phase touches are in the frozen set?

The evidence manifest freezes 143 byte-attested artefacts.  A file inside
it must not be edited; a file outside it may be.  This prints the answer
for every file J0..J6 is considering.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
MAN = os.path.join(ROOT, "phase16h_pcrel_fix/evidence_manifest.json")

WANT = [
    "phase14eh_tools/p14eh.py",
    "phase14e_static/tools/p14e_emu.py",
    "phase14eg_tools/p14e_emu_g.py",
    "phase14e_forensics/tools/wg_emu.py",
    "phase8_static/tools/emu.py",
    "phase16e_candidate_e/tools/p16e_rec.py",
    "phase16d_authentic_capture/tools/p16d_auth_cells.py",
    "phase16f_runtime/tools/p16f_mirror.py",
    "phase16g_forensics/tools/p8_diff_emu.py",
    "phase16g_forensics/tools/p16g_perturb.py",
    "phase16h_pcrel_fix/tools/p16h_global_gate.py",
    "phase16h_pcrel_fix/tools/p16h_scratch_probe.py",
    "phase16h_pcrel_fix/tools/p16h_p14_variants.py",
    "phase16h_pcrel_fix/tools/p16h_p14_lds_diag.py",
    "phase16i_closure/tools/p16i_lds_descriptor.py",
    "phase16i_closure/tools/p16i_authentic_harness.py",
    "phase16i_closure/tools/p16i_scratch_close.py",
    "phase16i_closure/tools/p16i_perturb.py",
    "phase16i_closure/tools/p16i_isa.py",
    "phase16i_closure/tools/p16i_isa_close.py",
    "phase16i_closure/tools/p16i_module_matrix.py",
    "phase16i_closure/tools/p16i_residual_probe.py",
]


def main():
    d = json.load(open(MAN, encoding="utf-8"))
    frozen = {}
    for cat, ents in d["frozen"].items():
        for e in ents:
            p = e if isinstance(e, str) else (e.get("path") or e.get("name")
                                              or "")
            frozen[p.replace(os.sep, "/")] = cat
    out = {}
    n_frozen = 0
    for w in WANT:
        hit = None
        for k in frozen:
            if k.replace(os.sep, "/").endswith(w):
                hit = (k, frozen[k])
                break
        out[w] = {"frozen": bool(hit),
                  "entry": hit[0] if hit else None,
                  "category": hit[1] if hit else None}
        n_frozen += 1 if hit else 0
        print("%-58s %s" % (w, ("FROZEN [%s]" % hit[1]) if hit
                            else "free to edit"))
    print("\n%d of %d are frozen" % (n_frozen, len(WANT)))
    dest = os.path.join(ROOT, "phase16j_pre_gta/out/p16j_frozen_check.json")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    json.dump(out, open(dest, "w", encoding="utf-8"), indent=1)
    print("wrote " + dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
