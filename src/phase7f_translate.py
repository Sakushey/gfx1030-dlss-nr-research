from __future__ import annotations

import argparse
import csv
import re
import subprocess
from collections import Counter
from pathlib import Path

TARGET = "_Z13k_conv_splitk12ConvParams1d"
TARGET_BASE = 0x69000
TARGET_NEXT = 0x6B400

SPECIAL_MAP = {
    "s_load_b32": "s_load_dword",
    "s_load_b64": "s_load_dwordx2",
    "s_load_b128": "s_load_dwordx4",
    "ds_load_u16": "ds_read_u16",
    "ds_store_b16": "ds_write_b16",
    "global_load_i8": "global_load_sbyte",
    "global_load_u16": "global_load_ushort",
    "global_store_b8": "global_store_byte",
    "s_and_not1_b32": "s_andn2_b32",
    "s_and_not1_saveexec_b32": "s_andn2_saveexec_b32",
}

DUAL_MAP = {
    "v_dual_add_f32": "v_add_f32_e32",
    "v_dual_and_b32": "v_and_b32_e32",
    "v_dual_lshlrev_b32": "v_lshlrev_b32_e32",
    "v_dual_mov_b32": "v_mov_b32_e32",
    "v_dual_mul_f32": "v_mul_f32_e32",
}

SCHEDULING_ONLY = {
    "s_delay_alu",
    "s_set_inst_prefetch_distance",
}

BRANCHES = {
    "s_branch",
    "s_cbranch_execz",
    "s_cbranch_scc0",
    "s_cbranch_scc1",
    "s_cbranch_vccnz",
    "s_cbranch_vccz",
}

LINE_RE = re.compile(
    r"^\s*(?P<asm>.*?)\s*//\s+(?P<address>[0-9A-Fa-f]+):\s+(?P<encoding>.*)$"
)
FUNCTION_RE = re.compile(r"^(?P<address>[0-9A-Fa-f]{12,}) <(?P<name>[^>]+)>:$")
TARGET_REF_RE = re.compile(
    re.escape(TARGET) + r"\+0x(?P<offset>[0-9A-Fa-f]+)"
)


def load_isa(path: Path) -> dict[str, dict[str, str]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return {row["mnemonic"]: row for row in csv.DictReader(handle)}


def read_target(path: Path) -> list[dict[str, object]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == f"{TARGET_BASE:016x} <{TARGET}>:":
            start = index + 1
            break
    if start is None:
        raise RuntimeError(f"target function header not found: {TARGET}")

    records: list[dict[str, object]] = []
    for line in lines[start:]:
        if FUNCTION_RE.match(line.strip()):
            break
        match = LINE_RE.match(line)
        if not match:
            continue
        asm = match.group("asm").strip()
        if not asm:
            continue
        address = int(match.group("address"), 16)
        comment = match.group("encoding")
        records.append({"address": address, "asm": asm, "comment": comment})
    if not records:
        raise RuntimeError("target function contains no disassembly records")
    return records


def mnemonic(asm: str) -> str:
    return asm.split(None, 1)[0]


def source_ops(record: dict[str, object]) -> list[str]:
    return [part.strip() for part in str(record["asm"]).split(" :: ")]


def branch_label(record: dict[str, object]) -> str | None:
    match = TARGET_REF_RE.search(str(record["comment"]))
    if not match:
        return None
    address = TARGET_BASE + int(match.group("offset"), 16)
    return f".L_kconv_{address:08X}"


def replace_branch_target(operation: str, label: str | None) -> str:
    if label is None or mnemonic(operation) not in BRANCHES:
        return operation
    parts = operation.split(None, 1)
    if len(parts) == 1:
        return operation
    return f"{parts[0]} {label}"


def wmma_exact_replacement() -> list[str]:
    # Exact reviewed target form: D/C=v[1:8], A=v[9:16], B=v[17:24].
    # v45 and v46 are checked to be dead at the target site by the translator.
    operations = [
        "v_and_b32_e32 v45, 16, v0",
        "v_lshrrev_b32_e32 v45, 4, v45",
        "v_lshlrev_b32_e32 v45, 2, v45",
    ]
    for r in range(8):
        destination = f"v{1 + r}"
        for k in range(0, 16, 2):
            operations.append(f"ds_bpermute_b32 v46, v45, v{9 + k // 2}")
            operations.append("s_waitcnt lgkmcnt(0)")
            operations.append(f"v_dot2c_f32_f16 {destination}, v46, v{17 + k // 2}")
        if r != 7:
            operations.append("v_add_nc_u32_e32 v45, 8, v45")
    return operations


def temp_liveness_ok(records: list[dict[str, object]], wmma_index: int) -> bool:
    # The reviewed replacement uses v45/v46. They must have no use after the
    # WMMA site before their first later definition in the original listing.
    for register in (45, 46):
        seen_definition = False
        token = re.compile(rf"\bv{register}\b|v\[{register}:\d+\]")
        for record in records[wmma_index + 1 :]:
            asm = str(record["asm"])
            if not token.search(asm):
                continue
            operands = asm.split(None, 1)
            first_operand = operands[1].split(",", 1)[0].strip() if len(operands) > 1 else ""
            destination = re.fullmatch(r"v(\d+)", first_operand)
            destination_range = re.fullmatch(r"v\[(\d+):(\d+)\]", first_operand)
            if destination and int(destination.group(1)) == register:
                seen_definition = True
                break
            if destination_range and int(destination_range.group(1)) <= register <= int(destination_range.group(2)):
                seen_definition = True
                break
            if not seen_definition:
                return False
    return True


def classify(op: str, isa: dict[str, dict[str, str]]) -> str:
    name = mnemonic(op)
    if name in SCHEDULING_ONLY:
        return "scheduling-only"
    if name == "s_sendmsg":
        return "scheduling-only"
    if name.startswith("v_dual_"):
        return "dual-reencodable"
    if name == "v_wmma_f32_16x16x16_f16":
        return "WMMA-template"
    if name == "v_minmax_i32":
        return "minmax-replacement"
    if name in SPECIAL_MAP:
        return "spelling-reencodable"
    row = isa.get(name)
    if row is None:
        return "UNRECOGNIZED"
    if row["semantic_class"] == "directly valid gfx1030 instruction":
        return "direct-compatible"
    if row["semantic_class"] == "same semantic operation exists; syntax/encoding differs":
        return "spelling-reencodable"
    if row["semantic_class"] == "GFX11 scheduling/hazard-only instruction":
        return "scheduling-only"
    if row["semantic_class"] == "truly unavailable native semantic operation":
        return "UNSUPPORTED"
    return "UNRECOGNIZED"


def minmax_replacement(op: str) -> list[str] | None:
    match = re.match(r"v_minmax_i32\s+(v\d+),\s*([^,]+),\s*([^,]+),\s*(0|1)$", op)
    if not match:
        return None
    destination, left, right, mode = match.groups()
    if mode == "0":
        return [
            f"v_cmp_lt_i32_e32 vcc_lo, {left}, {right}",
            f"v_cndmask_b32_e32 {destination}, {right}, {left}, vcc_lo",
        ]
    return [
        f"v_cmp_lt_i32_e32 vcc_lo, {left}, {right}",
        f"v_cndmask_b32_e32 {destination}, {left}, {right}, vcc_lo",
    ]


def translate_operation(
    op: str,
    category: str,
    record: dict[str, object],
    records: list[dict[str, object]],
    record_index: int,
    wmma_index: int,
) -> tuple[list[str], str, str]:
    name = mnemonic(op)
    if category == "scheduling-only":
        if name == "s_sendmsg" and "MSG_DEALLOC_VGPRS" not in op:
            return [], "UNRESOLVED", "unknown s_sendmsg payload"
        return [], "high", "removed target scheduling/resource directive"
    if category == "dual-reencodable":
        target_name = DUAL_MAP.get(name)
        if target_name is None:
            return [], "UNRESOLVED", f"no closed dual mapping for {name}"
        operands = op.split(None, 1)[1] if len(op.split(None, 1)) > 1 else ""
        return [f"{target_name} {operands}"], "high", "dual operation unbundled"
    if category == "spelling-reencodable":
        target_name = SPECIAL_MAP.get(name)
        if target_name is None:
            return [], "UNRESOLVED", f"no closed spelling mapping for {name}"
        operands = op.split(None, 1)[1] if len(op.split(None, 1)) > 1 else ""
        return [f"{target_name} {operands}"], "high", "target spelling regenerated"
    if category == "minmax-replacement":
        replacement = minmax_replacement(op)
        if replacement is None:
            return [], "UNRESOLVED", "minmax operand form not recognized"
        return replacement, "medium", "compare/select replacement; requires operand review"
    if category == "WMMA-template":
        if record_index != wmma_index or op != "v_wmma_f32_16x16x16_f16 v[1:8], v[9:16], v[17:24], v[1:8]":
            return [], "UNRESOLVED", "only the reviewed exact WMMA operand form is enabled"
        if not temp_liveness_ok(records, wmma_index):
            return [], "UNRESOLVED", "v45/v46 are not proven dead at the WMMA site"
        return wmma_exact_replacement(), "high", "validated Phase-7D exact inline expansion"
    if category == "UNSUPPORTED":
        return [], "UNRESOLVED", "native semantic blocker has no closed replacement"
    if category == "UNRECOGNIZED":
        return [], "UNRESOLVED", "mnemonic absent from authoritative census"
    return [replace_branch_target(op, branch_label(record))], "high", "retained and reassembled for gfx1030"


def build_metadata() -> list[str]:
    return [
        "\t.section .rodata,\"a\",@progbits",
        "\t.p2align 6, 0x0",
        f"\t.amdhsa_kernel {TARGET}",
        "\t\t.amdhsa_group_segment_fixed_size 4096",
        "\t\t.amdhsa_private_segment_fixed_size 0",
        "\t\t.amdhsa_kernarg_size 304",
        "\t\t.amdhsa_user_sgpr_count 6",
        "\t\t.amdhsa_user_sgpr_private_segment_buffer 1",
        "\t\t.amdhsa_user_sgpr_dispatch_ptr 0",
        "\t\t.amdhsa_user_sgpr_queue_ptr 0",
        "\t\t.amdhsa_user_sgpr_kernarg_segment_ptr 1",
        "\t\t.amdhsa_user_sgpr_dispatch_id 0",
        "\t\t.amdhsa_user_sgpr_flat_scratch_init 0",
        "\t\t.amdhsa_user_sgpr_private_segment_size 0",
        "\t\t.amdhsa_wavefront_size32 1",
        "\t\t.amdhsa_uses_dynamic_stack 0",
        "\t\t.amdhsa_system_sgpr_private_segment_wavefront_offset 0",
        "\t\t.amdhsa_system_sgpr_workgroup_id_x 1",
        "\t\t.amdhsa_system_sgpr_workgroup_id_y 0",
        "\t\t.amdhsa_system_sgpr_workgroup_id_z 0",
        "\t\t.amdhsa_system_sgpr_workgroup_info 0",
        "\t\t.amdhsa_system_vgpr_workitem_id 0",
        "\t\t.amdhsa_next_free_vgpr 51",
        "\t\t.amdhsa_next_free_sgpr 42",
        "\t\t.amdhsa_reserve_vcc 0",
        "\t\t.amdhsa_reserve_flat_scratch 0",
        "\t\t.amdhsa_float_round_mode_32 0",
        "\t\t.amdhsa_float_round_mode_16_64 0",
        "\t\t.amdhsa_float_denorm_mode_32 3",
        "\t\t.amdhsa_float_denorm_mode_16_64 3",
        "\t\t.amdhsa_dx10_clamp 1",
        "\t\t.amdhsa_ieee_mode 1",
        "\t\t.amdhsa_fp16_overflow 0",
        "\t\t.amdhsa_workgroup_processor_mode 1",
        "\t\t.amdhsa_memory_ordered 1",
        "\t\t.amdhsa_forward_progress 1",
        "\t\t.amdhsa_shared_vgpr_count 0",
        "\t\t.amdhsa_exception_fp_ieee_invalid_op 0",
        "\t\t.amdhsa_exception_fp_denorm_src 0",
        "\t\t.amdhsa_exception_fp_ieee_div_zero 0",
        "\t\t.amdhsa_exception_fp_ieee_overflow 0",
        "\t\t.amdhsa_exception_fp_ieee_underflow 0",
        "\t\t.amdhsa_exception_fp_ieee_inexact 0",
        "\t\t.amdhsa_exception_int_div_zero 0",
        "\t.end_amdhsa_kernel",
        "\t.text",
        "\t.amdgpu_metadata",
        "---",
        "amdhsa.kernels:",
        "  - .args:",
        "      - .offset: 0",
        "        .size: 48",
        "        .value_kind: by_value",
        "    .group_segment_fixed_size: 4096",
        "    .kernarg_segment_align: 8",
        "    .kernarg_segment_size: 304",
        "    .language: OpenCL C",
        "    .language_version:",
        "      - 2",
        "      - 0",
        "    .max_flat_workgroup_size: 256",
        f"    .name: {TARGET}",
        "    .private_segment_fixed_size: 0",
        "    .sgpr_count: 42",
        "    .sgpr_spill_count: 0",
        f"    .symbol: {TARGET}.kd",
        "    .uniform_work_group_size: 1",
        "    .uses_dynamic_stack: false",
        "    .vgpr_count: 51",
        "    .vgpr_spill_count: 0",
        "    .wavefront_size: 32",
        "    .workgroup_processor_mode: 1",
        "amdhsa.target: amdgcn-amd-amdhsa--gfx1030",
        "amdhsa.version:",
        "  - 1",
        "  - 2",
        "...",
        "\t.end_amdgpu_metadata",
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--disassembly", type=Path, required=True)
    parser.add_argument("--isa-csv", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--llvm-mc",
        type=Path,
        default=Path(r"<ROCM_ROOT>\7.1\bin\llvm-mc.exe"),
    )
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    isa = load_isa(args.isa_csv)
    records = read_target(args.disassembly)
    wmma_sites = [
        index
        for index, record in enumerate(records)
        if any(mnemonic(op) == "v_wmma_f32_16x16x16_f16" for op in source_ops(record))
    ]
    if len(wmma_sites) != 1:
        raise RuntimeError(f"expected one target WMMA, found {len(wmma_sites)}")
    wmma_index = wmma_sites[0]

    branch_targets = {
        TARGET_BASE + int(match.group("offset"), 16)
        for record in records
        for match in [TARGET_REF_RE.search(str(record["comment"]))]
        if match is not None
    }
    labels = {address: f".L_kconv_{address:08X}" for address in branch_targets}

    log_rows: list[dict[str, object]] = []
    body: list[str] = []
    totals = Counter()
    unresolved: list[str] = []
    token_index = 0
    for record_index, record in enumerate(records):
        address = int(record["address"])
        if address in labels:
            body.append(f"{labels[address]}:")
        for op in source_ops(record):
            category = classify(op, isa)
            generated, confidence, note = translate_operation(
                op, category, record, records, record_index, wmma_index
            )
            if category == "UNRESOLVED":
                unresolved.append(f"0x{address:X}: {op}")
            if confidence == "UNRESOLVED":
                unresolved.append(f"0x{address:X}: {op} ({note})")
            totals[category] += 1
            totals["generated_operations"] += len(generated)
            log_rows.append(
                {
                    "source_address": f"0x{address:012X}",
                    "operation_index": token_index,
                    "source_mnemonic": mnemonic(op),
                    "classification": category,
                    "generated_gfx1030_operations": " || ".join(generated),
                    "confidence": confidence,
                    "note": note,
                    "source_operation": op,
                }
            )
            token_index += 1
            body.extend(f"\t{line}" for line in generated)

    assembly = [
        '.amdgcn_target "amdgcn-amd-amdhsa--gfx1030"',
        ".amdhsa_code_object_version 6",
        ".text",
        f".protected\t{TARGET}",
        f".globl\t{TARGET}",
        f".p2align\t8",
        f".type\t{TARGET},@function",
        f"{TARGET}:",
        *body,
        f".Lfunc_end_{TARGET}:",
        f".size\t{TARGET}, .Lfunc_end_{TARGET}-{TARGET}",
        *build_metadata(),
        "",
    ]
    asm_path = args.out_dir / "k_conv_splitk_translated_gfx1030.s"
    asm_path.write_text("\n".join(assembly), encoding="utf-8")

    log_path = args.out_dir / "k_conv_splitk_translation_log.csv"
    with log_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(log_rows[0]))
        writer.writeheader()
        writer.writerows(log_rows)

    object_path = args.out_dir / "k_conv_splitk_translated_gfx1030.o"
    assembler_exit = None
    assembler_output = ""
    if not unresolved:
        result = subprocess.run(
            [
                str(args.llvm_mc),
                "-triple=amdgcn-amd-amdhsa",
                "-mcpu=gfx1030",
                "-filetype=obj",
                str(asm_path),
                "-o",
                str(object_path),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assembler_exit = result.returncode
        assembler_output = (result.stdout + result.stderr).strip()
    else:
        assembler_output = "closed translation did not assemble because unresolved sites remain"

    summary_path = args.out_dir / "phase7f_translation_summary.md"
    summary = [
        "# Phase 7F — closed translation summary",
        "",
        f"Target: `{TARGET}`",
        "",
        f"- Physical source sites: {len(records)}",
        f"- Source operation tokens: {token_index}",
        f"- WMMA sites: {len(wmma_sites)}",
        f"- Generated gfx1030 operation lines: {totals['generated_operations']}",
        f"- Unresolved sites: {len(unresolved)}",
        f"- Assembler exit: {assembler_exit if assembler_exit is not None else 'not run (fail-closed)'}",
        "",
        "## Classification counts",
        "",
        "| classification | source operation tokens |",
        "|---|---:|",
    ]
    for key in sorted(k for k in totals if k != "generated_operations"):
        summary.append(f"| {key} | {totals[key]} |")
    summary.extend(["", "## Closed-failure details", ""])
    if unresolved:
        summary.extend(f"- `{item}`" for item in unresolved)
    else:
        summary.append("No unresolved sites.")
    summary.extend(["", "## Assembler output", "", "```text", assembler_output, "```", ""])
    summary_path.write_text("\n".join(summary), encoding="utf-8")

    print(f"PHYSICAL_SITES={len(records)}")
    print(f"OPERATION_TOKENS={token_index}")
    print(f"GENERATED_OPERATIONS={totals['generated_operations']}")
    print(f"UNRESOLVED={len(unresolved)}")
    print(f"ASSEMBLER_EXIT={assembler_exit}")
    print(f"ASSEMBLY={asm_path}")
    print(f"LOG={log_path}")
    print(f"SUMMARY={summary_path}")
    return 0 if not unresolved and assembler_exit == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
