"""Shared static-analysis library for Phase 8 (gfx1030 soft-WMMA port).

Parses llvm-objdump-style AMDGPU disassembly, the translated gfx1030
assembly, and the Phase 7F/7H translation logs into structured rows.
HOST-ONLY. Never touches the GPU.
"""
import csv
import re

# llvm-objdump AMDGPU row forms seen in this code object:
#   \tmnemonic operands // 000000069004: F4000480 F8000028
#   \tmnemonic operands// 0000000690B8: BF8701A5            (no space before //)
#   \tmnemonic 1927   // 0000000691B4: BFA20787 <_Z13k_conv_splitk12ConvParams1d+0x1fd4>
#   \tmnemonic op1 :: mnemonic op2 // ...                   (dual)
# Encoding words are hex; a trailing <symbol+off> resolution may follow.
ROW_RE = re.compile(
    r"^[ \t]+([A-Za-z_][A-Za-z0-9_]*)(?:\s+(.*?))?\s*//\s*"
    r"([0-9a-fA-F]+):\s*([0-9A-F]+(?:\s+[0-9A-F]+)*)"
    r"(?:\s+<([^>]*)>)?\s*$"
)
SYM_OFF_RE = re.compile(r"\+0x([0-9a-fA-F]+)\s*$")


def parse_orig_disasm(path):
    """Return list of dicts: address(int), mnemonic, operands, text,
    encodings, dual(bool), branch_target(int or None resolved from the
    <symbol+0xNN> comment suffix, else computed from the signed
    displacement when present)."""
    rows = []
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n").rstrip("\r")
            if not line.strip() or line.lstrip().startswith(("<", "Disassembly", "C:")):
                continue
            m = ROW_RE.match(line)
            if not m:
                continue
            mnem, ops, addr, enc, resolved = m.groups()
            ops = (ops or "").strip()
            if mnem == "s_code_end":
                continue
            dual = "::" in ops
            target = None
            if resolved and (mnem.startswith("s_cbranch") or mnem == "s_branch"):
                mo = SYM_OFF_RE.search(resolved)
                if mo:
                    # symbol base is the function start address; resolve via the
                    # first row's file-relative address below is not possible
                    # here, so we store the function-relative hex and let the
                    # caller rebase. We instead keep the raw text for callers.
                    target = int(mo.group(1), 16)
            rows.append(
                {
                    "address": int(addr, 16),
                    "mnemonic": mnem,
                    "operands": ops,
                    "text": mnem + ((" " + ops) if ops else ""),
                    "encodings": enc.strip(),
                    "dual": dual,
                    "rel_off": target,  # func-relative when resolved; else None
                }
            )
    return rows


# ---------------------------------------------------------------------------
# Translated gfx1030 assembly rows (label + instruction lines)
# ---------------------------------------------------------------------------
LABEL_RE = re.compile(r"^\s*([.\w$]+):\s*$")
TEXT_RE = re.compile(r"^(\s*)(\S+)(?:\s+(.*?))?\s*$")


def parse_translated_asm(path):
    """Return (labels dict name->index, rows list of dicts: kind in
    {label,directive,instruction}, text, mnemonic, operands)."""
    labels = {}
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            m = LABEL_RE.match(line)
            if m:
                labels[m.group(1)] = len(rows)
                rows.append({"kind": "label", "text": line.strip(), "name": m.group(1)})
                continue
            if line.lstrip().startswith((".", "//", ";")) or line.lstrip().startswith("\t."):
                rows.append({"kind": "directive", "text": line.strip()})
                continue
            mm = TEXT_RE.match(line)
            if mm:
                indent, mnem, ops = mm.groups()
                rows.append(
                    {
                        "kind": "instruction",
                        "text": line.strip(),
                        "mnemonic": mnem,
                        "operands": (ops or "").strip(),
                    }
                )
    return labels, rows


# ---------------------------------------------------------------------------
# Translation log rows (Phase 7F per-site log)
# ---------------------------------------------------------------------------
def load_translation_log(path):
    """Return list of dicts keyed by csv header. The generated gfx1030 lines
    live in the 'generated' column joined by ' || '."""
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def generated_lines(row):
    """Split the 'generated' cell into a list of gfx1030 instruction texts."""
    g = row.get("generated", "") or ""
    return [x.strip() for x in g.split("||") if x.strip()]


# ---------------------------------------------------------------------------
# CFG helpers over original disasm rows
# ---------------------------------------------------------------------------
BRANCH_MNEM = {"s_branch": "uncond", "s_cbranch_scc0": "cond", "s_cbranch_scc1": "cond",
               "s_cbranch_vccz": "cond", "s_cbranch_vccnz": "cond", "s_cbranch_execnz": "cond",
               "s_cbranch_execz": "cond", "s_cbranch_scc0": "cond", "s_branch": "uncond"}
RET_MNEM = {"s_endpgm": "end", "s_trap": "trap", "s_code_end": "end"}
VCCZ = re.compile(r"0x([0-9a-f]+)")


def orig_cfg(rows):
    """Build CFG edges from original rows: list of (src_idx, dst_idx, kind).
    Sequential fall-through included. Returns edges and per-row next/prev."""
    by_addr = {r["address"]: i for i, r in enumerate(rows)}
    edges = []
    for i, r in enumerate(rows):
        m = r["mnemonic"]
        if m in RET_MNEM:
            edges.append((i, None, "ret"))
            continue
        if m.startswith("s_cbranch"):
            tgt = VCCZ.search(r["operands"])
            j = by_addr.get(int(tgt.group(1), 16)) if tgt else None
            edges.append((i, j, "cond-taken"))
            # fall-through
            nxt = i + 1
            while nxt < len(rows) and rows[nxt]["address"] == r["address"]:
                nxt += 1
            edges.append((i, nxt if nxt < len(rows) else None, "cond-fall"))
        elif m == "s_branch":
            tgt = VCCZ.search(r["operands"])
            j = by_addr.get(int(tgt.group(1), 16)) if tgt else None
            edges.append((i, j, "uncond"))
    return edges
