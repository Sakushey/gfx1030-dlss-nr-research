#!/usr/bin/env python3
"""Phase 16H — P1: freeze the Phase-16E/F/G evidence.

Hashes every artefact Phase 16H depends on and writes
``phase16h_pcrel_fix/evidence_manifest.json``.

Nothing is mutated: this tool opens files read-only and only writes into
``phase16h_pcrel_fix/``.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p16h_lib as L  # noqa: E402

ROOT = L.ROOT
P16H = L.P16H


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def ent(rel):
    p = os.path.join(ROOT, rel)
    if not os.path.exists(p):
        return dict(path=rel, exists=False)
    return dict(path=rel, exists=True, size=os.path.getsize(p),
                sha256=sha(p))


def tree(rel, pattern="**/*"):
    out = []
    for p in sorted(glob.glob(os.path.join(ROOT, rel, pattern),
                              recursive=True)):
        if os.path.isfile(p):
            out.append(ent(os.path.relpath(p, ROOT)))
    return out


def main():
    man = {}
    man["phase"] = "16H"
    man["generated_for"] = ("module-layout / PC-relative correction + "
                            "ABI closure (host-only, no GPU execution)")
    man["frozen"] = {}

    F = man["frozen"]

    # --- Phase 16G -----------------------------------------------------
    F["phase16g_report"] = ent("SESSION_REPORT.md")
    F["phase16g_dir"] = tree("phase16g_forensics", "*.md")
    F["phase16g_tools"] = tree("phase16g_forensics/tools", "*.py")
    F["phase16g_out"] = tree("phase16g_forensics/out", "*")
    F["phase16g_evidence_manifest"] = ent(
        "phase16g_forensics/evidence_manifest.json")
    F["phase16g_prefix_variants"] = tree("phase16g_forensics/prefix_variants",
                                         "*/*")

    # --- Candidate E (must stay byte-exact) ----------------------------
    F["candidate_e"] = [
        ent("phase16e_candidate_e/gfx1030_dlssnr_candidate_e.co"),
        ent("phase16e_candidate_e/gfx1030_dlssnr_candidate_e.o"),
        ent("phase16e_candidate_e/gfx1030_dlssnr_candidate_e.s"),
        ent("phase16e_candidate_e/disasm/candidate_e_gfx1030_disasm.txt"),
        ent("phase16e_candidate_e/hashes.txt"),
        ent("phase16e_candidate_e/patch_manifest.json"),
        ent("phase16e_candidate_e/patch_sites.json"),
    ]
    F["candidate_e_tools"] = tree("phase16e_candidate_e/tools", "*.py")

    # --- reference module ----------------------------------------------
    F["reference_module"] = [
        ent("phase14_entry_fixed_module/gfx1030_dlssnr_module_entryfixed.co"),
        ent("phase14_entry_fixed_module/gfx1030_dlssnr_bundle_entryfixed.o"),
        ent("phase14_entry_fixed_module/gfx1030_dlssnr_bundle_entryfixed.s"),
        ent("phase14_entry_fixed_manifest.sha256"),
    ]

    # --- original gfx1100 translation source ---------------------------
    F["original_gfx1100"] = [
        ent("phase5_exact_fragment/gfx1100_code_object.o"),
        ent("phase5_exact_fragment/gfx1100_disassembly.txt"),
        ent("phase5_exact_fragment/gfx1100_kernel_resources.csv"),
    ]
    F["original_bundle"] = [
        ent("phase11_fatbin/gfx1030_dlssnr.fatbin"),
        ent("phase11_fatbin/original_fatbin_extract.bin"),
        ent("phase11_original_fatbin_layout.md"),
    ]

    # --- Phase 16F harness + mirror + gates ----------------------------
    F["phase16f_harness"] = tree("phase16f_runtime", "*")
    F["phase14e_harness"] = tree("phase14e_runtime", "*")

    # --- authentic GTA launch DB ---------------------------------------
    F["authentic_launch_db"] = [
        ent("phase16_authentic_launch_db.csv"),
        ent("phase16_authentic_launch_db.md"),
        ent("phase16_authentic_kernel_census.csv"),
        ent("phase16_authentic_frame_determinism.md"),
        ent("phase16d_authentic_capture/out/auth_cells_summary.json"),
    ]

    # --- emulator / LDS model ------------------------------------------
    F["emulator"] = [
        ent("phase14e_static/tools/p14e_emu.py"),
        ent("phase14eg_tools/p14e_emu_g.py"),
        ent("phase14e_forensics/tools/wg_emu.py"),
        ent("phase14ei_postprobe_hwmodel.md"),
        ent("phase14ei_rootcause_after_probes.md"),
        ent("phase14eh_rootcause.md"),
    ]

    # --- verifier ------------------------------------------------------
    man["verification"] = dict(
        rule=("every sha256 above was recomputed at Phase-16H start and at "
              "Phase-16H end; any change means an artefact was mutated"),
        note=("Candidate E and the reference module are inputs to Candidate F "
              "and are never written by Phase 16H"),
    )

    out = os.path.join(P16H, "evidence_manifest.json")
    json.dump(man, open(out, "w", encoding="utf-8"), indent=1)

    n = sum(len(v) for v in F.values() if isinstance(v, list))
    print("wrote", out)
    print("groups:", len(F), " files hashed:", n)
    for k, v in F.items():
        if isinstance(v, list):
            print("  %-28s %3d files" % (k, len(v)))


if __name__ == "__main__":
    main()
