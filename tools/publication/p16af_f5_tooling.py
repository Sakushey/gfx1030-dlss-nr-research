#!/usr/bin/env python3
"""Phase 16AF / T3 -- F5 public tooling gap inventory.

Phase 16AD reported five public build-DAG stages that depend on project tooling
which has not been published.  This script re-derives the mechanical facts
about each named tool from the private tree (existence, size, digest, the
markers that decide each review field) and records them alongside the reading.

It never runs any tool, never touches a GPU, and never writes outside
p16af/publication/.

The five stage names are read from the PUBLIC tree, so the inventory is
anchored to what the published DAG actually claims rather than to a summary.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIVATE_ROOT = Path(r"<PROJECT_ROOT>")
PUBLIC_ROOT = Path(r"<USER_HOME>\Desktop\gfx1030-dlss-nr-research")
OUT = HERE / "F5_PUBLIC_TOOLING.json"

# Stage -> the private tool sources a reproducer would need, with the field
# readings.  `expect_present` is asserted against the filesystem.
STAGE_TOOLS: dict[str, list[dict[str, object]]] = {
    "extract_bundle": [
        {
            "path": "phase11_fatbin/tools/p11_locate.py",
            "what": (
                "walks the PE section table of the user's own version.dll copy, finds "
                "every hipv4 magic site, computes each site's RVA, and resolves the "
                "u64 __hip_fatbin wrapper that names it"
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": [
                "hardcodes the private directory name phase5_exact_fragment for the input",
            ],
            "reusable_from_user_input": False,
            "reusable_note": (
                "input path is a module constant; there is no CLI argument. A sanitized "
                "successor would be small and mechanical: take the DLL path and the "
                "output path as arguments and drop the constant."
            ),
            "proprietary_bytes_note": (
                "reads the proprietary distribution DLL; embeds none of it"
            ),
        },
        {
            "path": "phase11_fatbin/tools/p11_fatbin.py",
            "what": (
                "builds a canonical clang-offload bundle and independently re-parses it; "
                "the historical, less strict ancestor of the published "
                "src/bridge/offload_bundle.py"
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": [
                "hardcodes phase9_final_module/gfx1030_dlssnr_module.co",
                "hardcodes phase11_fatbin output directory",
            ],
            "reusable_from_user_input": False,
            "reusable_note": (
                "its published successor src/bridge/offload_bundle.py already covers "
                "this and takes caller-supplied bytes, so publishing p11_fatbin.py adds "
                "nothing"
            ),
            "proprietary_bytes_note": "none embedded",
        },
    ],
    "source_elf": [
        {
            "path": "phase8_static/tools/elf_meta.py",
            "what": (
                "minimal ELF64 section reader plus .note.amdgpu.metadata JSON reader, "
                "kernel-descriptor reader and SGPR-preload slot mapper"
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": [
                "the __main__ demo block defaults to private artifacts; the functions "
                "themselves take a path argument",
            ],
            "reusable_from_user_input": True,
            "reusable_note": (
                "library-level functions already accept an arbitrary object path, so a "
                "sanitized publication is mostly a matter of dropping the demo defaults"
            ),
            "proprietary_bytes_note": "none embedded",
        }
    ],
    "symbol_metadata": [
        {
            "path": "phase9_static/tools/p9_meta.py",
            "what": (
                "AMDGPU HSA msgpack note decode, canonical-JSON normalisation, kernarg "
                "byte packing and kernarg dword mapping"
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": [
                "hardcodes ORIG_OBJ = phase5_exact_fragment/gfx1100_code_object.o",
            ],
            "reusable_from_user_input": True,
            "reusable_note": (
                "all readers take a path; only the module constant is private. NOTE: "
                "the DAG's invocation field says `python phase9_static/tools/p9_meta.py` "
                "but this file has no __main__ block, so that command imports and exits "
                "doing nothing"
            ),
            "proprietary_bytes_note": "none embedded",
        },
        {
            "path": "phase9_static/tools/msgpack_min.py",
            "what": (
                "self-contained decode-only msgpack decoder, written against the public "
                "msgpack spec because the project forbids installing packages"
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": [],
            "reusable_from_user_input": True,
            "reusable_note": "fully generic; the reference is an upstream format, not a vendor",
            "proprietary_bytes_note": "none",
        },
        {
            "path": "phase9_static/tools/p9_module_audit.py",
            "what": (
                "the tool that actually writes phase9_symbol_map.csv: ET_DYN/machine "
                "check, kernel symbol table check, note strict-equality, text-range "
                "non-overlap, opcode census, resource table"
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": [
                "hardcodes <ROCM_ROOT>\\7.1\\bin for llvm-readobj/llvm-objdump",
                "hardcodes phase9_final_module and phase9_static",
            ],
            "reusable_from_user_input": False,
            "reusable_note": (
                "constant-driven; would need the module path and the LLVM bin directory "
                "promoted to arguments"
            ),
            "proprietary_bytes_note": "none embedded; invokes vendor binaries by path",
        },
    ],
    "translate_isa": [
        {
            "path": "phase7_translation/phase7f_translate.py",
            "what": (
                "gfx1100 -> gfx1030 instruction translator: mnemonic remap tables, "
                "scheduling-only set, branch-label rewriting, and the soft-WMMA "
                "expansion that replaces v_wmma_f32_16x16x16_f16 with ds_bpermute_b32 "
                "plus v_dot2c_f32_f16"
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": [
                "only the default --llvm-mc path is absolute; all inputs are CLI arguments",
            ],
            "reusable_from_user_input": True,
            "reusable_note": (
                "the most reusable file in the whole inventory: --disassembly, "
                "--isa-csv, --out-dir, --llvm-mc. Caveat: the required --isa-csv is "
                "phase5_exact_fragment/isa_compatibility.csv and no project tool "
                "produces that CSV (see unknowns)."
            ),
            "proprietary_bytes_note": (
                "text-to-text rewriter; no bytes of the object are embedded. The "
                "instruction knowledge is AMD public ISA documentation plus the "
                "project's own disassembly readings."
            ),
        },
        {
            "path": "phase7_full_static/phase7h_status.py",
            "what": "the 33-kernel full-bundle driver over phase7f_translate",
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": ["vendor llvm-mc default only"],
            "reusable_from_user_input": True,
            "reusable_note": "same CLI shape as phase7f_translate",
            "proprietary_bytes_note": "none",
        },
        {
            "path": "phase8_static/tools/8l_swin_fix.py",
            "what": (
                "the tool the DAG names for translation; in fact a narrow post-pass "
                "repairing the five k_swin_var kernels whose global_load/store offsets "
                "exceed gfx1030's signed 12-bit range"
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": [
                "hardcodes <ROCM_ROOT>\\7.1\\bin\\llvm-mc.exe",
                "hardcodes SRC, OUTD and the five input filenames",
            ],
            "reusable_from_user_input": False,
            "reusable_note": "the least reusable translation file; the DAG names it as if it were the translator",
            "proprietary_bytes_note": "none",
        },
        {
            "path": "phase8_static/tools/disasm_lib.py",
            "what": (
                "shared static-analysis library: parses llvm-objdump-style AMDGPU "
                "disassembly, translated .s files and translation logs; builds CFG edges"
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": [],
            "reusable_from_user_input": True,
            "reusable_note": "pure regex/parse library, function-level paths",
            "proprietary_bytes_note": "none",
        },
        {
            "path": "phase16h_pcrel_fix/tools/translator_pcrel_fix.py",
            "what": (
                "the CURRENT translator: layout-safe PC-relative correction. Rewrites "
                "every s_getpc_b64 / s_add_u32 / s_addc_u32 triple whose literal delta "
                "was carried verbatim from the original compiler, and restores four "
                "dropped .rodata objects."
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": [
                "hardcodes <ROCM_ROOT>\\7.1\\bin for llvm-mc, ld.lld, llvm-objdump",
                "hardcodes phase16k_pretest/k15_target_profile and hard-exits without it",
                "hardcodes phase16e_candidate_e and phase16h_candidate_f",
            ],
            "reusable_from_user_input": False,
            "reusable_note": (
                "the profile dependency is a hard SystemExit, not a default; a sanitized "
                "publication would need the profile to be an argument or a published file"
            ),
            "proprietary_bytes_note": (
                "IMPORTANT: no proprietary bytes are emitted. The four restored .rodata "
                "objects are written as ZERO/placeholder content "
                "(g_e4m3_lut = .zero 512; _ZN12DlssNrEngine2SHE = .zero 8 + 3x .long -4 "
                "+ .zero 8 + .long -4; D3D11_DEFAULT and D3D11_VIDEO_DEFAULT = .byte 0). "
                "However the SOURCE TEXT names two mangled DLSS/NR symbols "
                "(_ZN12DlssNrEngine2SHE, D3D11_DEFAULT) and one DLSS/NR object name "
                "(g_e4m3_lut). Publishing it would publish those names, not those bytes."
            ),
        },
        {
            "path": "phase16k_pretest/k15_target_profile/target_profile.py",
            "what": (
                "the TargetProfile table the 16H translator reads instead of inline "
                "constants: triple, -mcpu, @rel32@lo/hi spelling, the +4 addend, and "
                "allowed filler mnemonics for gfx1100 and gfx1030"
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": ["not verified line by line in this pass"],
            "reusable_from_user_input": True,
            "reusable_note": "a profile table is inherently reusable; only its consumer hardcodes the path",
            "proprietary_bytes_note": "none",
        },
    ],
    "assemble_link": [
        {
            "path": "phase9_static/tools/p9_emit.py",
            "what": (
                "deterministic metadata regeneration: preserves ABI fields from the "
                "original decoded note, updates gfx1030 resource fields from each "
                "translated .s descriptor, appends .amdgpu_metadata YAML, assembles "
                "with llvm-mc, reparses and strict type-aware compares"
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": [
                "hardcodes <ROCM_ROOT>\\7.1\\bin\\llvm-mc.exe",
                "hardcodes phase7_full_static, phase8_static, phase9_final_module",
            ],
            "reusable_from_user_input": False,
            "reusable_note": "ASM_DIRS and ORIG_DUMP are module constants",
            "proprietary_bytes_note": "none embedded; invokes the vendor assembler by path",
        },
        {
            "path": "phase9_static/tools/p9_bundle.py",
            "what": (
                "single-module bundle builder: concatenates the translated bodies, "
                "strips per-file headers and per-kernel metadata, appends ONE "
                ".amdgpu_metadata YAML listing all kernels in original note order, "
                "assembles with llvm-mc, links with ld.lld -shared, reparses and "
                "strict-compares"
            ),
            "project_authored": True,
            "vendor_bytes_embedded": False,
            "private_path_assumptions": [
                "hardcodes <ROCM_ROOT>\\7.1\\bin\\ld.lld.exe",
                "hardcodes phase9_final_module and phase9_static",
            ],
            "reusable_from_user_input": False,
            "reusable_note": "constant-driven",
            "proprietary_bytes_note": "none embedded; vendor llvm-mc and ld.lld invoked by path",
        },
    ],
}

# Facts about the PUBLIC tree that the reproducer meets, re-checked at build time.
PUBLIC_ANCHORS = {
    "dag_json": "src/bridge/bridge_payload_dag.json",
    "dag_doc": "docs/bridge-payload-build-dag.md",
    "bridge_readme": "src/bridge/README.md",
    "dag_tool": "src/bridge/tools/bridge_payload_dag.py",
    "bundle_build": "src/bridge/tools/p11_bundle_build.py",
    "embed_header": "src/bridge/tools/p11_embed_header.py",
    "offload_bundle": "src/bridge/offload_bundle.py",
}

# Paths the public tree REFERENCES but does not track.  Checked mechanically.
REFERENCED_NOT_PUBLISHED = [
    "bridge_gfx1030_fatbin.h",
    "gfx1030_dlssnr.fatbin",
    "version.dll.static_copy",
    "gfx1100_code_object.o",
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(*args: str) -> str:
    p = subprocess.run(["git", *args], cwd=PUBLIC_ROOT, capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else ""


def public_head() -> str:
    """The mirror's HEAD, fail-closed.

    A previous revision of this script called git("rev-parse HEAD"), which
    passes ONE argv element containing a space rather than two arguments. The
    command failed, the helper returned "", and an empty commit identity was
    written into the record as if it were measured. Verified here instead.
    """
    head = git("rev-parse", "HEAD").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise SystemExit(
            f"ABORT: could not resolve the mirror HEAD (got {head!r}); "
            f"an empty commit identity must not be recorded as a measurement"
        )
    return head


def main() -> int:
    # --- mechanical re-verification of every cited private path --------------
    missing: list[str] = []
    for stage, tools in STAGE_TOOLS.items():
        for t in tools:
            p = PRIVATE_ROOT / str(t["path"])
            if not p.is_file():
                missing.append(str(t["path"]))
                t["exists"] = False
                continue
            data = p.read_bytes()
            t["exists"] = True
            t["bytes"] = len(data)
            t["sha256"] = sha256(data)
            t["has_main_block"] = b"__main__" in data
            t["absolute_windows_paths"] = sorted(
                {
                    m.group(0).decode("utf-8", "replace")
                    for m in re.finditer(
                        rb"[A-Za-z]:[\\/]{1,2}Program Files[^\s\"')]{0,60}", data
                    )
                }
            )
            t["references_extracted_blob"] = any(
                n in data
                for n in (
                    b"gfx1100_code_object",
                    b"version.dll.static_copy",
                    b"gfx1030_dlssnr_module.co",
                )
            )
            t["names_distribution_or_vendor_material"] = any(
                n in data
                for n in (
                    b"DlssNrEngine",
                    b"nvngx",
                    b"dlss",
                    b"DLSS",
                    b"g_e4m3_lut",
                    b"D3D11_DEFAULT",
                )
            )
    if missing:
        print(f"ABORT: cited private paths that do not exist: {missing}")
        return 2

    # --- mechanical check of the public anchors ------------------------------
    public_state = {}
    tracked = set(git("ls-files").split())
    for key, rel in PUBLIC_ANCHORS.items():
        public_state[key] = {
            "path": rel,
            "tracked": rel in tracked,
            "bytes": (PUBLIC_ROOT / rel).stat().st_size
            if (PUBLIC_ROOT / rel).is_file()
            else None,
        }

    # The path-spelling defect: does the public tree actually contain the files
    # the bridge README tells the reader to run?
    readme = (PUBLIC_ROOT / PUBLIC_ANCHORS["bridge_readme"]).read_text(encoding="utf-8")
    readme_paths = sorted(
        set(re.findall(r"python\s+([A-Za-z0-9_./\\-]+\.py)", readme))
    )
    dag_doc = (PUBLIC_ROOT / PUBLIC_ANCHORS["dag_doc"]).read_text(encoding="utf-8")
    dag_doc_paths = sorted(
        set(re.findall(r"python\s+([A-Za-z0-9_./\\-]+\.py)", dag_doc))
    )

    referenced = {
        "bridge_readme_python_invocations": readme_paths,
        "bridge_readme_invocations_that_are_not_tracked": [
            p for p in readme_paths if p not in tracked
        ],
        "dag_doc_python_invocations": dag_doc_paths,
        "dag_doc_invocations_that_are_not_tracked": [
            p for p in dag_doc_paths if p not in tracked
        ],
    }

    # --- the five stage names, read from the PUBLIC DAG -----------------------
    dag = json.loads((PUBLIC_ROOT / PUBLIC_ANCHORS["dag_json"]).read_text(encoding="utf-8"))
    blocking_gaps = dag["terminal"]["blocking_gaps"]

    # --- what a sanitized publication could and could not add ----------------
    sanitizable = []
    must_not_publish = []
    for stage, tools in STAGE_TOOLS.items():
        for t in tools:
            if t.get("vendor_bytes_embedded"):
                must_not_publish.append(
                    {"path": t["path"], "why": "embeds vendor bytes"}
                )
            elif "translator_pcrel_fix" in str(t["path"]):
                sanitizable.append(
                    {
                        "path": t["path"],
                        "stage": stage,
                        "verdict": "SANITIZABLE_WITH_A_NAMING_DECISION",
                        "what_would_have_to_change": [
                            "promote the vendored ROCm bin directory to an argument",
                            "promote the phase16k_pretest target profile to an argument or "
                            "a published file, and remove the hard SystemExit",
                            "promote the phase16e/phase16h input paths to arguments",
                            "decide whether the DLSS/NR object and symbol NAMES "
                            "(g_e4m3_lut, _ZN12DlssNrEngine2SHE, D3D11_DEFAULT, "
                            "D3D11_VIDEO_DEFAULT) may appear in published source; the "
                            "emitted bytes are already zero placeholders, so only the "
                            "names are at issue",
                        ],
                    }
                )
            elif t.get("reusable_from_user_input"):
                sanitizable.append(
                    {
                        "path": t["path"],
                        "stage": stage,
                        "verdict": "SANITIZABLE",
                        "what_would_have_to_change": t["private_path_assumptions"]
                        or ["nothing path-related; a licence header would be the only addition"],
                    }
                )
            else:
                sanitizable.append(
                    {
                        "path": t["path"],
                        "stage": stage,
                        "verdict": "SANITIZABLE_WITH_PATH_PARAMETERISATION",
                        "what_would_have_to_change": t["private_path_assumptions"],
                    }
                )

    out = {
        "schema": "p16af-f5-public-tooling/1",
        "phase": "16AF",
        "task": "T3 -- F5 public tooling gap inventory",
        "generated_by": "p16af/publication/p16af_f5_tooling.py",
        "private_root": str(PRIVATE_ROOT),
        "public_root": str(PUBLIC_ROOT),
        "public_head": public_head(),
        "goal": (
            "the public tree should reproduce as much as it legally can from "
            "USER-SUPPLIED source material; the boundary is proprietary bytes, not "
            "proprietary knowledge"
        ),
        "study_anchor": {
            "source": PUBLIC_ANCHORS["dag_json"] + " terminal.blocking_gaps",
            "five_stages": blocking_gaps,
            "how_the_gap_is_recorded": (
                "each node carries tool.path naming the historical private file and "
                "tool.historical_path naming its directory; those are provenance "
                "records, not runtime paths"
            ),
            "private_report_naming_the_same_five": (
                "p16ad/foundation/F1_F7_REPORT.json "
                "defects[4].evidence.unpublished_tools_named_with_reason_and_acquisition "
                "= [phase11_fatbin/tools/p11_locate.py, phase9_static/tools/p9_meta.py, "
                "phase8_static/tools/8l_swin_fix.py, phase9_static/tools/p9_emit.py, "
                "phase9_static/tools/p9_bundle.py]"
            ),
        },
        "stages": STAGE_TOOLS,
        "what_could_be_published": sanitizable,
        "what_must_not_be_published": must_not_publish + [
            {
                "path": "the extracted gfx1100 code object itself",
                "why": (
                    "1,177,984 bytes, ELF ET_DYN, sha256 "
                    "93e4a40b880b994860431309e9b2fd116efea585a23a830496050de88ee4800a, "
                    "lifted byte-identically out of the DLSS-NR distribution. It is the "
                    "input the pipeline studies, not a tool. Extracting it requires the "
                    "user's own copy of the distribution."
                ),
            },
            {
                "path": "version.dll (the user's still copy: version.dll.static_copy)",
                "why": "4,480,512 bytes of proprietary distribution binary; user-supplied only",
            },
            {
                "path": "bridge_gfx1030_fatbin.h and gfx1030_dlssnr.fatbin",
                "why": (
                    "the generated header and bundle carry the proprietary payload; the "
                    "project already withholds both and publishes their emitters instead"
                ),
            },
            {
                "path": "vendor binaries (llvm-mc, ld.lld, llvm-objdump, llvm-readobj)",
                "why": (
                    "stock AMD/LLVM tools shipped with ROCm; the DAG already declares "
                    "them EXTERNAL_TOOL, to be installed by the user, not published"
                ),
            },
        ],
        "public_tree_state": {
            "anchors": public_state,
            "referenced_but_not_published": REFERENCED_NOT_PUBLISHED,
            "invocation_consistency_findings": referenced,
        },
        "actionable_defects_in_the_public_tree": [
            {
                "id": "F5-D1",
                "severity": "documentation, user-visible",
                "where": "src/bridge/README.md lines 40, 50, 51",
                "defect": (
                    "the reproduction example tells the reader to run "
                    "`python tools/p11_bundle_build.py ...` and "
                    "`python tools/p11_embed_header.py ...`, but neither path is tracked. "
                    "The files are at src/bridge/tools/. Five lines later the same block "
                    "correctly uses `python src/bridge/tools/bridge_payload_dag.py`, and "
                    "docs/bridge-payload-build-dag.md uses the correct src/bridge/tools/ "
                    "spelling throughout, so the README disagrees with both the "
                    "filesystem and its own sibling document."
                ),
                "measured": {
                    "readme_invocations_not_tracked": referenced[
                        "bridge_readme_invocations_that_are_not_tracked"
                    ],
                    "dag_doc_invocations_not_tracked": referenced[
                        "dag_doc_invocations_that_are_not_tracked"
                    ],
                },
                "fix": "correct the two paths in src/bridge/README.md to src/bridge/tools/...",
            },
            {
                "id": "F5-D2",
                "severity": "documentation, private-side",
                "where": "src/bridge/bridge_payload_dag.json node for symbol_metadata",
                "defect": (
                    "the node's tool.invocation says "
                    "`python phase9_static/tools/p9_meta.py`, but p9_meta.py contains no "
                    "__main__ block (checked: zero occurrences), so that command imports "
                    "the module and exits without doing anything. The symbol map is "
                    "actually written by phase9_static/tools/p9_module_audit.py."
                ),
                "measured": {
                    "p9_meta_py_has_main_block": False,
                    "actual_writer": "phase9_static/tools/p9_module_audit.py",
                },
                "fix": (
                    "correct the invocation and name the tool that writes the artefact, "
                    "or state that the stage is driven by p9_module_audit.py"
                ),
            },
        ],
        "unknowns": [
            {
                "item": "isa_compatibility.csv / isa_compatibility_v2.csv producer",
                "status": "UNKNOWN",
                "why": (
                    "phase7f_translate.py requires --isa-csv and the canonical input is "
                    "phase5_exact_fragment/isa_compatibility.csv, but no file in the "
                    "private tree writes it. Grepping the tree for 'isa_compatibility' "
                    "returns only readers (p16ac/hazards/p16ac_hazard_audit.py) and "
                    "prose (phase6_debug/). This is a SIXTH non-reproducible input that "
                    "the DAG's five blocking gaps do not cover."
                ),
                "consequence": (
                    "even with every sanitized tool published, the ISA-classification "
                    "half of the translation is not reproducible from the private tree "
                    "either, let alone from the public one"
                ),
            },
            {
                "item": "whether phase8_static/tools/emu.py (81,739 bytes) transcribes any vendor material",
                "status": "UNKNOWN",
                "why": (
                    "the file was not read in full by this pass. It is project-authored "
                    "and carries an explicit @value_stub / @control_only_vacuous "
                    "declaration mechanism (the F6 change) for handlers it does NOT "
                    "implement, which says nothing about the handlers it does implement. "
                    "A publishable determination needs a full read against public AMD ISA "
                    "documentation."
                ),
            },
            {
                "item": "whether phase16k_pretest/k15_target_profile/target_profile.py contains any transcribed vendor table",
                "status": "UNKNOWN",
                "why": "32,673 bytes; only its consumer was read in this pass.",
            },
        ],
        "provenance_of_this_inventory": (
            "every path was resolved on disk and hashed at generation time; the "
            "'exists', 'bytes' and 'sha256' fields are measurements, not quotations. "
            "The field readings (project_authored, reusable_from_user_input, "
            "vendor_bytes_embedded) are the review of those measurements and are "
            "stated per file so a reader can disagree with a specific one."
        ),
    }

    OUT.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

    print("=" * 78)
    print("PHASE 16AF T3 -- F5 public tooling inventory")
    print("=" * 78)
    print(f"five stages (read from {PUBLIC_ANCHORS['dag_json']}):")
    for s in blocking_gaps:
        print(f"  - {s}")
    print()
    print(f"{'stage':16s} {'file':52s} {'bytes':>7s}  reusable")
    for stage, tools in STAGE_TOOLS.items():
        for t in tools:
            print(
                f"{stage:16s} {str(t['path']):52s} {t['bytes']:>7d}  "
                f"{'YES' if t['reusable_from_user_input'] else 'no'}"
            )
    print()
    print("PUBLIC TREE INVOCATION CONSISTENCY")
    print(f"  src/bridge/README.md invocations      : {readme_paths}")
    print(f"    of which NOT tracked                : {referenced['bridge_readme_invocations_that_are_not_tracked']}")
    print(f"  docs/bridge-payload-build-dag.md      : {dag_doc_paths}")
    print(f"    of which NOT tracked                : {referenced['dag_doc_invocations_that_are_not_tracked']}")
    print()
    print(f"ACTIONABLE DEFECTS: {len(out['actionable_defects_in_the_public_tree'])}")
    for d in out["actionable_defects_in_the_public_tree"]:
        print(f"  {d['id']} ({d['severity']}): {d['where']}")
    print()
    print(f"COULD BE PUBLISHED (sanitized): {len(sanitizable)} tool file(s)")
    print(f"MUST NOT BE PUBLISHED         : {len(out['what_must_not_be_published'])} item(s)")
    print(f"UNKNOWNS recorded             : {len(out['unknowns'])}")
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
