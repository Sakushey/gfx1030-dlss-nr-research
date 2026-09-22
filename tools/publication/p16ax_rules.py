"""T-PUB step 3: the classification rule table.

Every project file receives EXACTLY ONE class.  The rule that fired is recorded
per file (`rule_id`), so the classification is auditable rather than asserted.

The vocabulary is fixed by the T-PUB brief:

    PUBLISH_EXACT                    bytes may be published unchanged
    PUBLISH_SANITIZED                publishable in kind, but needs sanitising
    KEEP_PRIVATE_PROPRIETARY         vendor binaries / device code / disassembly / weights
    KEEP_PRIVATE_AUDIT               raw audits and generated internal evidence
    KEEP_PRIVATE_SECRET              key material, credential-bearing launchers
    KEEP_PRIVATE_CAPTURE_DATA        raw game captures / frame dumps
    KEEP_PRIVATE_BUILD_ARTIFACT      outputs of a build or a bytecode compiler
    KEEP_PRIVATE_LICENSE_RESTRICTED  third-party-derived with unestablished licence
    KEEP_PRIVATE_IRRELEVANT          no research or publication value

The governing exclusion policy is ASTRA AUDIT #4 section 150 (DO NOT PUBLISH:
raw Astra reports; proprietary binaries; proprietary weights; raw GTA capture
blobs; vendor disassembly; private file paths; secrets; private session
reports), extended by the T-PUB brief's MUST REMAIN PRIVATE list.

ORDERING.  Rules are evaluated in the order below and the FIRST match wins.
The order encodes severity: a file that is both generated evidence and carries
key material is a SECRET, because the restriction that must never be relaxed
is the one that has to win.  The order is part of the policy, not an accident
of implementation.

CEILING.  A class says what MAY be done with a file under this policy.  It is
not a review.  Only the paths named in PUBLICATION_RECOMMENDATION_16AX.json
have been individually examined for this phase's commit series.
"""
from __future__ import annotations

import os
import re

CLASSES = [
    "PUBLISH_EXACT",
    "PUBLISH_SANITIZED",
    "KEEP_PRIVATE_PROPRIETARY",
    "KEEP_PRIVATE_AUDIT",
    "KEEP_PRIVATE_SECRET",
    "KEEP_PRIVATE_CAPTURE_DATA",
    "KEEP_PRIVATE_BUILD_ARTIFACT",
    "KEEP_PRIVATE_LICENSE_RESTRICTED",
    "KEEP_PRIVATE_IRRELEVANT",
]

# --------------------------------------------------------------------------
# Extension tables
# --------------------------------------------------------------------------
# Device code. Never publishable: it is extracted or translated proprietary
# device code, or a compilation of it.  The generator of a project-built object
# is published in its place, so nothing reproducible is lost.
DEVICE_CODE_EXT = {
    ".co", ".fatbin", ".elf", ".bundle", ".hsaco", ".hipi", ".hipfb", ".bc",
    ".cubin", ".ptx", ".sass", ".cso",
}
# Disassembly / low-level emitted text.  A `.s` file cannot be mechanically
# separated into "our assembly" and "objdump of a vendor object", so the whole
# extension keeps the private class; over-keeping is the safe error.
DISASM_EXT = {".td", ".textdump", ".text", ".dis", ".cl", ".pre", ".s"}
# Build outputs produced by a compiler or bytecode compiler.
BUILD_EXT = {
    ".pyc", ".pyo", ".obj", ".o", ".ilk", ".pdb", ".tlog", ".map", ".idb",
    ".res", ".gch", ".pch", ".d", ".ninja_deps", ".ninja_log", ".zip", ".7z",
    ".tar", ".gz", ".whl", ".egg",
}
# Pe/COFF executables and shared libraries.  Vendor ones are caught earlier by
# name; the rest are our own builds.
PE_EXT = {".exe", ".dll", ".sys", ".lib", ".exp", ".msi"}
# Capture / image data.
IMAGE_EXT = {
    ".png", ".jpg", ".jpeg", ".bmp", ".tga", ".dds", ".gif", ".tif", ".tiff",
    ".webp", ".mp4", ".avi", ".mkv", ".wav",
}
# Bytecode/compiled-marshalling of the Python toolchain.
PYC_EXT = {".pyc", ".pyo"}

# Log / trace / record extensions: always generated internal evidence.
LOG_EXT = {".log", ".err", ".ndjson", ".jsonl", ".rec", ".tlog", ".trace"}

# Extensions that can carry publishable authored content.
PUBLISHABLE_EXT = {
    ".py", ".ps1", ".bat", ".cmd", ".def", ".cfg", ".cpp", ".c", ".cc",
    ".cxx", ".h", ".hpp", ".hh", ".cs", ".md", ".txt", ".json", ".csv",
    ".yaml", ".yml", ".toml", ".ini", ".rst", ".html",
}
# Of those, the ones that are usually machine-generated evidence rather than
# authored text.  These need a positive reason (a name shape) to be a
# publication candidate at all.
EVIDENCE_EXT = {".json", ".csv", ".txt", ".ndjson", ".jsonl"}

# --------------------------------------------------------------------------
# Proprietary artefacts recognised by name
# --------------------------------------------------------------------------
VENDOR_BINARY_NAMES = {
    "amdhip64_7.dll", "amdhip64_7.lib", "amdhip64_7.exp", "amdhip64_7.obj",
    "amdhip64_6.dll", "amdhip64_6.lib", "amdhip64_6.exp",
    "mock_hip6.dll", "mock_hip6.lib", "mock_hip6.exp", "mock_hip6.obj",
    "version.dll", "version_v4.dll", "version_v5_flag38.dll",
    "gta5_enhanced.exe", "dlssnr-rdna2-controlcenter.exe", "cdb.exe",
    "nvngx_dlss.dll", "nvngx.dll", "nvapi64.dll",
    "abi_6_4_fingerprint.obj", "abi_7_1_fingerprint.obj",
    "registry_ident.obj", "hip_bridge_smoke.obj", "hip_bridge_reg_smoke.obj",
}
# Paths that hold an actual game tree or a game-binary sandbox.  Deliberately
# narrow: a bare substring "gta" appears in dozens of ordinary phase names
# (phase16j_pre_gta, p16ab/gta_prep) that are authored documentation, and
# sweeping them into the proprietary class would be a false positive.
GAME_TREE_MARKERS = ("/game/", "k11_sandbox/", "runtime/version.dll")
GAME_BINARY_BASENAMES = {"gta5_enhanced.exe", "version.dll",
                         "version_v4.dll", "version_v5_flag38.dll",
                         "dlssnr-rdna2-controlcenter.exe", "cdb.exe"}
GAME_TREE_SUFFIXES = (".gfx1030accept", ".flagsplice", ".original")

# Raw capture data: recorded frame state and authentic capture samples.  These
# are the "raw GTA capture blobs" in the audit's DO-NOT-PUBLISH list.
CAPTURE_PATH_MARKERS = (
    "phase16d_authentic_capture/",
    "p16am/capture/out/",
    "p16ao/authorization/state/",
    "phase16g_forensics/",
    "_frame_dump/",
    "capture_blob",
)
CAPTURE_NAME_MARKERS = ("state_prefix", "conformance_", "auth_a_w", "auth_b_w",
                        "auth_c_w", "auth_d_w", "frame_state", "raw_capture")
# Project-built host executables that happen to share an extension with vendor
# binaries.  Kept private as build artefacts, not as proprietary material.
PROJECT_BUILD_EXE_NAMES = {"soft_wmma_test.exe", "soft_wmma_bench.exe"}

# Weight data: the raw preimage is a proprietary artefact whatever path it sits
# on, and the project already audits its provenance.
WEIGHT_PATH_MARKERS = (
    "weights/pinned/", "weights_preimage", "block39-logical-effective",
    "block39-logical-effective-bias", "WEIGHT_",
)

# --------------------------------------------------------------------------
# Raw audit / supervisor material
# --------------------------------------------------------------------------
def _is_raw_audit(rel: str) -> bool:
    low = rel.lower()
    if "astra_audit" in low or "astra-audit" in low:
        return True
    if re.search(r"(^|/)audit/[^/]*audit[^/]*$", low):
        return True
    base = low.rsplit("/", 1)[-1]
    if base in ("session_report.md", "supervisor_handover.md",
                "current_state.json", "supervisor_state.json",
                "overnight_status.json"):
        return True
    # Worker summaries filed under a phase's audit/ directory are session
    # records of the same kind as SESSION_REPORT.md, and section 150 names
    # private session reports.  They are NOT in the same class as authored
    # tooling merely because a `.json` extension made them parse.
    if base == "worker_summary.json" and "/audit/" in low:
        return True
    if "supervisor_handover_history" in low:
        return True
    return False


# --------------------------------------------------------------------------
# Publication categories
# --------------------------------------------------------------------------
# Prefixes whose authored source, tests, tooling and schemas the brief names as
# things that SHOULD be published where safe.  Each entry is
# (prefix, category) and the category is copied into the report so the mapping
# from brief bullet to path is explicit.
PUBLISH_CATEGORY_PREFIXES: list[tuple[str, str]] = [
    # translator fixes / lowering
    ("p16ax/vopd/", "TRANSLATOR_FIXES"),
    ("p16aw/vopd/", "TRANSLATOR_FIXES"),
    ("phase16z/lib/", "TRANSLATOR_FIXES"),
    ("phase16z/legality/", "TRANSLATOR_FIXES"),
    ("phase16y/addressing/", "TRANSLATOR_FIXES"),
    ("phase16y/waitcnt/", "TRANSLATOR_FIXES"),
    ("phase16r/isa/", "TRANSLATOR_FIXES"),
    ("phase16t/isa/", "TRANSLATOR_FIXES"),
    ("phase16s/isa/", "TRANSLATOR_FIXES"),
    ("phase16s/div/", "TRANSLATOR_FIXES"),
    ("phase16t/div/", "TRANSLATOR_FIXES"),
    ("phase7_translation/", "TRANSLATOR_FIXES"),
    # semantic tests
    ("p16am/semantic/", "SEMANTIC_TESTS"),
    ("phase16t/semantic/", "SEMANTIC_TESTS"),
    ("p16ax/xref/", "SEMANTIC_TESTS"),
    # qualification tooling
    ("p16ax/slot5/", "QUALIFICATION_TOOLS"),
    ("p16at/qualification", "QUALIFICATION_TOOLS"),
    ("p16am/qualification/", "QUALIFICATION_TOOLS"),
    ("p16as/slot5/", "QUALIFICATION_TOOLS"),
    ("phase16o_final/a_regression/", "QUALIFICATION_TOOLS"),
    ("phase16o_final/c_freeze.py", "QUALIFICATION_TOOLS"),
    ("phase16o_final/k_readiness.py", "QUALIFICATION_TOOLS"),
    ("p16aw/consistency/", "QUALIFICATION_TOOLS"),
    ("p16aw/certify/", "QUALIFICATION_TOOLS"),
    # liveness verifier
    ("p16ax/liveness/", "LIVENESS_VERIFIER"),
    ("p16aw/liveness/", "LIVENESS_VERIFIER"),
    ("phase16y/liveness/", "LIVENESS_VERIFIER"),
    ("p16as/native/liveness/", "LIVENESS_VERIFIER"),
    # numerical reference tests
    ("p16ax/numeric/", "NUMERICAL_REFERENCE"),
    ("p16aw/numeric/", "NUMERICAL_REFERENCE"),
    ("phase16l_authoritative_rederive/isa_conformance/", "NUMERICAL_REFERENCE"),
    ("phase16l_authoritative_rederive/frozen_16k/", "NUMERICAL_REFERENCE"),
    # RAW_DUMP framework
    ("p16aw/raw_dump/", "RAW_DUMP_FRAMEWORK"),
    ("p16at/raw_dump/", "RAW_DUMP_FRAMEWORK"),
    ("p16as/raw_dump/", "RAW_DUMP_FRAMEWORK"),
    # shipping-bridge framework (source only; proprietary binaries excluded above)
    ("p16ax/bridge/", "BRIDGE_FRAMEWORK"),
    ("phase10_hip_bridge/", "BRIDGE_FRAMEWORK"),
    ("phase16_bridge_telemetry/", "BRIDGE_FRAMEWORK"),
    # graph schemas / source grounding
    ("p16ax/graph/", "GRAPH_SCHEMAS"),
    ("p16ax/sources/", "SOURCE_GROUNDING"),
    ("p16aw/sources/", "SOURCE_GROUNDING"),
    # performance model
    ("p16ax/perf/", "PERFORMANCE_MODEL"),
    # reproducible synthetic fixtures
    ("p16as/native/harness/", "SYNTHETIC_FIXTURES"),
    ("p16at/raw_dump/_work/mutants/", "SYNTHETIC_FIXTURES"),
    # emulator / ISA model (the already-published core)
    ("phase16o_final/a_regression/rev_harness_fixed/", "EMULATOR_CORE"),
    ("phase8_static/tools/", "EMULATOR_CORE"),
    ("phase14d_static/tools/", "EMULATOR_CORE"),
    ("phase14d8_static/tools/", "EMULATOR_CORE"),
    ("phase14d11_static/tools/", "EMULATOR_CORE"),
    ("phase16k_pretest/tools/", "EMULATOR_CORE"),
    ("phase14e_static/tools/", "EMULATOR_CORE"),
    ("phase14eg_tools/", "EMULATOR_CORE"),
    ("phase14e_forensics/tools/", "EMULATOR_CORE"),
    ("phase14eh_tools/", "EMULATOR_CORE"),
    ("phase16g_forensics/tools/", "EMULATOR_CORE"),
    ("phase16i_closure/tools/", "EMULATOR_CORE"),
    ("phase16h_pcrel_fix/tools/", "EMULATOR_CORE"),
    ("phase16e_candidate_e/tools/", "EMULATOR_CORE"),
    # host harnesses
    ("phase14_runtime/", "HOST_HARNESS"),
    ("phase14d10_probe/", "HOST_HARNESS"),
    ("phase14d11_runtime/", "HOST_HARNESS"),
    ("phase14e_runtime/", "HOST_HARNESS"),
    ("phase14ei_runtime/", "HOST_HARNESS"),
    ("phase16f_runtime/", "HOST_HARNESS"),
    # documentation / methodology
    ("p16ax/audit/", "PUBLIC_SAFE_STATUS"),
    ("p16ax/publication/", "PUBLICATION_TOOLING"),
    ("p16as/publication/", "PUBLICATION_TOOLING"),
    ("p16aw/publication/", "PUBLICATION_TOOLING"),
    ("p16af/publication/", "PUBLICATION_TOOLING"),
    ("p16am/publication/", "PUBLICATION_TOOLING"),
    ("p16ao/publication/", "PUBLICATION_TOOLING"),
]

# Name shapes that mark a JSON/CSV/TXT as an authored schema, contract,
# methodology or sanitised summary rather than a dump of run output.
PUBLISH_NAME_SHAPES = (
    "schema", "contract", "methodology", "spec", "design", "glossary",
    "registry", "matrix", "summary", "readme", "index", "roadmap",
    "procedure", "protocol", "glossary",
)
# Name shapes that mark it as raw generated evidence even inside a candidate
# directory.
EVIDENCE_NAME_MARKERS = (
    "trace", "log", "events", "sites", "dump", "receipt", "raw", "replay",
    "transaction", "journal", "ledger_run", "attempt", "preimage",
)

# A curated allowlist carried over from the previous phase, from the published
# manifest.  These paths were already reviewed and published; the inventory
# records that fact rather than re-deriving it.
MAPPED_MANIFEST = (
    r"<USER_HOME>\Desktop\gfx1030-dlss-nr-research"
    r"\audit\PUBLICATION_MANIFEST.json"
)


def load_mapped() -> dict[str, dict]:
    """Read the published manifest's source paths and their recorded hashes.

    Read-only.  A missing manifest yields an empty map AND is reported by the
    caller as an unresolvable locator (absence is blocking), never silently.
    """
    import json
    if not os.path.isfile(MAPPED_MANIFEST):
        return {}
    try:
        with open(MAPPED_MANIFEST, encoding="utf-8") as f:
            man = json.load(f)
    except (OSError, ValueError):
        return {}
    out = {}
    for e in man.get("files", []):
        sp = e.get("source_path")
        if isinstance(sp, str):
            out[sp] = e
    return out


def publish_category(rel: str) -> str | None:
    for prefix, cat in PUBLISH_CATEGORY_PREFIXES:
        if rel.startswith(prefix):
            return cat
    return None


def evidence_name_is_authored(base: str) -> bool:
    low = base.lower()
    if any(k in low for k in EVIDENCE_NAME_MARKERS):
        return False
    return any(k in low for k in PUBLISH_NAME_SHAPES)


# --------------------------------------------------------------------------
# Rule table
# --------------------------------------------------------------------------
# Each rule: (rule_id, class, reason_code, description)
RULE_TABLE = [
    ("R01_SECRET_LAUNCHER", "KEEP_PRIVATE_SECRET", "CREDENTIAL_LAUNCHER",
     "launcher script that reads the DeepSeek API key from a local file"),
    ("R02_SECRET_CONTENT", "KEEP_PRIVATE_SECRET", "KEY_MATERIAL_IN_CONTENT",
     "secret scanner returned a BLOCKER hit"),
    ("R03_LICENCE_CLONE", "KEEP_PRIVATE_LICENSE_RESTRICTED", "THIRD_PARTY_CLONE",
     "inside a retrieved third-party repository clone"),
    ("R04_LICENCE_VENDOR_DOC", "KEEP_PRIVATE_LICENSE_RESTRICTED",
     "THIRD_PARTY_VENDOR_DOCUMENTATION",
     "quotations of vendor or third-party documentation with unestablished licence"),
    ("R05_PROP_WEIGHT", "KEEP_PRIVATE_PROPRIETARY", "PROPRIETARY_WEIGHT_DATA",
     "raw proprietary weight data or its direct preimage"),
    ("R06_PROP_GAME_TREE", "KEEP_PRIVATE_PROPRIETARY", "GAME_TREE",
     "file inside a game tree or a game-binary sandbox"),
    ("R07_PROP_VENDOR_BINARY", "KEEP_PRIVATE_PROPRIETARY", "VENDOR_BINARY",
     "NVIDIA/AMD or third-party mod binary"),
    ("R08_PROP_DEVICE_CODE", "KEEP_PRIVATE_PROPRIETARY", "DEVICE_CODE_OBJECT",
     "extracted or translated proprietary device code object"),
    ("R09_PROP_DISASM", "KEEP_PRIVATE_PROPRIETARY", "LOW_LEVEL_DERIVED_TEXT",
     "vendor disassembly or derived low-level object text"),
    ("R10_CAPTURE_RAW", "KEEP_PRIVATE_CAPTURE_DATA", "RAW_CAPTURE",
     "raw game capture, frame dump or capture-derived sample data"),
    ("R11_BUILD_PYC", "KEEP_PRIVATE_BUILD_ARTIFACT", "PYTHON_BYTECODE",
     "Python bytecode cache emitted by the interpreter"),
    ("R12_BUILD_OUTPUT", "KEEP_PRIVATE_BUILD_ARTIFACT", "COMPILER_OUTPUT",
     "compiler, linker or archiver output"),
    ("R13_PROJECT_EXE", "KEEP_PRIVATE_BUILD_ARTIFACT", "PROJECT_BINARY",
     "project-built executable or shared library"),
    ("R14_IRRELEVANT_JUNK", "KEEP_PRIVATE_IRRELEVANT", "NO_RESEARCH_VALUE",
     "OS junk, lock file, empty file or editor leftover"),
    ("R15_AUDIT_RAW", "KEEP_PRIVATE_AUDIT", "RAW_AUDIT_OR_SESSION_REPORT",
     "raw Astra/supervisor audit, private session report or handover"),
    ("R16_AUDIT_LOG", "KEEP_PRIVATE_AUDIT", "GENERATED_LOG_OR_TRACE",
     "log, trace or record emitted by a run"),
    ("R17_AUDIT_EVIDENCE", "KEEP_PRIVATE_AUDIT", "GENERATED_INTERNAL_EVIDENCE",
     "generated internal evidence outside any publication category"),
    ("R20_VENDOR_DISASSEMBLY", "KEEP_PRIVATE_PROPRIETARY",
     "VENDOR_DISASSEMBLY_LISTING",
     "a LISTING of a proprietary object, measured from the bytes: instruction "
     "lines dominate the file. Decided on content because a filename heuristic "
     "cannot tell a listing from a document that quotes one"),
    ("R18_PUBLISH_CATEGORY", "PUBLISH_SANITIZED", "CANDIDATE",
     "authored source/test/tool/schema in a publication category"),
    ("R19_IRRELEVANT_OTHER", "KEEP_PRIVATE_IRRELEVANT", "UNCLASSIFIED_KIND",
     "no publication category and no research-evidence character"),
]

RULE_BY_ID = {r[0]: r for r in RULE_TABLE}


def decide(rel: str, base: str, ext: str, features: dict) -> tuple[str, str, str]:
    """Return (rule_id, class, reason_code) for one file.

    `features` carries the measured booleans the rules need:
        secret_blocker, licence_clone_root, licence_vendor_doc
    """
    low = rel.lower()

    # R01 launchers that carry the credential access path
    if base in ("start-claude-flash.ps1",
                "start-claude-v41-flash-high-official.ps1"):
        return RULE_BY_ID["R01_SECRET_LAUNCHER"][0:3]  # type: ignore[return-value]
    if base in (".env", ".env.local", "credentials", "credentials.json",
                "id_rsa", "id_ed25519") or ext in (".pem", ".pfx", ".p12",
                                                   ".keystore", ".jks"):
        return "R01_SECRET_LAUNCHER", "KEEP_PRIVATE_SECRET", "CREDENTIAL_FILE"

    # R02 key material found by the scanner
    if features.get("secret_blocker"):
        return RULE_BY_ID["R02_SECRET_CONTENT"][0:3]  # type: ignore[return-value]

    # R03 / R04 licence
    if features.get("licence_clone_root"):
        return RULE_BY_ID["R03_LICENCE_CLONE"][0:3]  # type: ignore[return-value]
    if features.get("licence_vendor_doc"):
        return RULE_BY_ID["R04_LICENCE_VENDOR_DOC"][0:3]  # type: ignore[return-value]

    # R05 proprietary weights
    if any(m in rel for m in WEIGHT_PATH_MARKERS) and ext in (
            ".bin", ".npy", ".npz", ".safetensors", ".onnx", ".pt", ".pth"):
        return RULE_BY_ID["R05_PROP_WEIGHT"][0:3]  # type: ignore[return-value]

    # R06 game tree
    if any(d in low for d in GAME_TREE_MARKERS):
        return RULE_BY_ID["R06_PROP_GAME_TREE"][0:3]  # type: ignore[return-value]

    # R07 vendor binaries by name
    if base.lower() in VENDOR_BINARY_NAMES or base.lower() in GAME_BINARY_BASENAMES:
        return RULE_BY_ID["R07_PROP_VENDOR_BINARY"][0:3]  # type: ignore[return-value]
    if base.lower().endswith(GAME_TREE_SUFFIXES):
        return ("R07_PROP_VENDOR_BINARY", "KEEP_PRIVATE_PROPRIETARY",
                "THIRD_PARTY_MOD_BINARY_VARIANT")
    if low.startswith("phase10_hip_bridge/") and ext in (".dll", ".lib", ".exp"):
        return "R07_PROP_VENDOR_BINARY", "KEEP_PRIVATE_PROPRIETARY", "BRIDGE_BINARY"
    if base.lower().startswith("amdhip64") or base.lower().startswith("nvngx"):
        return "R07_PROP_VENDOR_BINARY", "KEEP_PRIVATE_PROPRIETARY", "VENDOR_RUNTIME_BINARY"

    # R08 device code
    if ext in DEVICE_CODE_EXT:
        return RULE_BY_ID["R08_PROP_DEVICE_CODE"][0:3]  # type: ignore[return-value]
    # R09 disassembly / derived low-level text
    if ext in DISASM_EXT:
        return RULE_BY_ID["R09_PROP_DISASM"][0:3]  # type: ignore[return-value]

    # R10 raw captures
    if features.get("capture_data") or any(m in low for m in CAPTURE_PATH_MARKERS):
        return RULE_BY_ID["R10_CAPTURE_RAW"][0:3]  # type: ignore[return-value]
    if any(m in base.lower() for m in CAPTURE_NAME_MARKERS):
        return "R10_CAPTURE_RAW", "KEEP_PRIVATE_CAPTURE_DATA", "CAPTURE_DERIVED_SAMPLE"
    if ext in IMAGE_EXT:
        return "R10_CAPTURE_RAW", "KEEP_PRIVATE_CAPTURE_DATA", "IMAGE_DATA"

    # R11 python bytecode
    if ext in PYC_EXT or "/__pycache__/" in rel or rel.startswith("__pycache__/"):
        return RULE_BY_ID["R11_BUILD_PYC"][0:3]  # type: ignore[return-value]

    # R12 compiler output
    if ext in BUILD_EXT:
        return RULE_BY_ID["R12_BUILD_OUTPUT"][0:3]  # type: ignore[return-value]

    # R13 project-built PE
    if ext in PE_EXT:
        return RULE_BY_ID["R13_PROJECT_EXE"][0:3]  # type: ignore[return-value]

    # R14 junk
    if base.lower() in ("thumbs.db", "desktop.ini", ".ds_store", "ehthumbs.db",
                        ".gitkeep", "nul", "con") or ext in (".tmp", ".bak",
                                                              ".swp", ".orig"):
        return RULE_BY_ID["R14_IRRELEVANT_JUNK"][0:3]  # type: ignore[return-value]
    if features.get("empty"):
        return "R14_IRRELEVANT_JUNK", "KEEP_PRIVATE_IRRELEVANT", "EMPTY_FILE"

    # R15 raw audits and session reports
    if _is_raw_audit(rel):
        return RULE_BY_ID["R15_AUDIT_RAW"][0:3]  # type: ignore[return-value]

    # R16 logs / traces / records
    if ext in LOG_EXT:
        return RULE_BY_ID["R16_AUDIT_LOG"][0:3]  # type: ignore[return-value]

    # R20 a disassembly LISTING of a proprietary object.  Decided on the bytes,
    # never on the name: the filename heuristic below let one through because a
    # mangled C++ symbol happened to contain the substring "contract".
    if features.get("vendor_disassembly_listing"):
        return ("R20_VENDOR_DISASSEMBLY", "KEEP_PRIVATE_PROPRIETARY",
                "VENDOR_DISASSEMBLY_LISTING")

    # R18 publication candidates
    cat = publish_category(rel)
    if cat is not None and ext in PUBLISHABLE_EXT:
        if ext in EVIDENCE_EXT and not evidence_name_is_authored(base):
            # Inside a publication category but shaped like a dump: this is
            # generated evidence, not an authored artefact.
            return ("R17_AUDIT_EVIDENCE", "KEEP_PRIVATE_AUDIT",
                    "GENERATED_EVIDENCE_IN_PUBLISH_DIR")
        return ("R18_PUBLISH_CATEGORY", "PUBLISH_SANITIZED", f"CANDIDATE_{cat}")

    # R17 everything else that is generated evidence
    if ext in EVIDENCE_EXT:
        return RULE_BY_ID["R17_AUDIT_EVIDENCE"][0:3]  # type: ignore[return-value]

    # R19 remaining
    if ext in PUBLISHABLE_EXT:
        return ("R19_IRRELEVANT_OTHER", "KEEP_PRIVATE_IRRELEVANT",
                "AUTHORED_BUT_OUTSIDE_CATEGORY")
    return RULE_BY_ID["R19_IRRELEVANT_OTHER"][0:3]  # type: ignore[return-value]
