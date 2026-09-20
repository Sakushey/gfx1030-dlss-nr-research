"""Phase 16E shared library — module/disasm/.s parsing, site derivation.

Host-only tooling for candidate E (SWIN LDS ring normalization).
"""
from __future__ import annotations

import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", ".."))
ENT_S = os.path.join(ROOT, "phase14_entry_fixed_module",
                     "gfx1030_dlssnr_bundle_entryfixed.s")
ENT_CO = os.path.join(ROOT, "phase14_entry_fixed_module",
                      "gfx1030_dlssnr_module_entryfixed.co")
ENT_DIS = os.path.join(ROOT, "phase14d9_static", "out",
                       "entryfixed_gfx1030_disasm.txt")
ORIG_OBJ = os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_code_object.o")
ORIG_DIS = os.path.join(ROOT, "phase5_exact_fragment",
                        "gfx1100_disassembly.txt")

SWIN_VARIANTS = [
    ("_Z10k_swin_varILi32ELb1EEv9VarParams", "swin32t"),
    ("_Z10k_swin_varILi32ELb0EEv9VarParams", "swin32f"),
    ("_Z10k_swin_varILi64ELb0EEv9VarParams", "swin64f"),
    ("_Z10k_swin_varILi128ELb0EEv9VarParams", "swin128f"),
    ("_Z10k_swin_varILi256ELb0EEv9VarParams", "swin256f"),
]

_RE_INS = re.compile(
    r"^(\s+)(\S.*?)\s*//\s+([0-9A-Fa-f]+):\s*((?:[0-9A-Fa-f]{8}\s*)+)$")
_RE_DEC = re.compile(r"\b(0[xX][0-9A-Fa-f]+)\b")
_RE_SYM = re.compile(r"^[0-9a-f]+\s+<_Z")
_RE_SPLIT = re.compile(r"\s+")


def norm(t: str) -> str:
    """Normalize one instruction text for content comparison."""
    t = t.strip()
    t = re.sub(r"\s+", " ", t)
    # strip _e32/_e64 suffixes from the mnemonic
    m = re.split(r"\s+", t)
    m[0] = re.sub(r"_(e32|e64|e64_gfx10)$", "", m[0])
    # decimal literals -> hex-ish canonical (both sides kept as given after
    # lowercasing is NOT enough for 2048 vs 0x800; convert all integers)
    def _hexlit(mm):
        v = int(mm, 16)
        return "0x%x" % v
    out = [_hexlit(x) if re.match(r"^0[xX][0-9A-Fa-f]+$", x) else
           ("0x%x" % int(x) if re.match(r"^-?\d+$", x) else x)
           for x in m]
    return " ".join(out)


def parse_disasm(path=ENT_DIS):
    """Return {kernel_symbol: [(addr, text)]} from llvm-objdump text."""
    out = {}
    cur = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            if _RE_SYM.search(raw):
                mm = re.search(r"<_Z[^>]+>", raw)
                cur = mm.group(0)[1:-1] if mm else None
                if cur is not None:
                    out.setdefault(cur, [])
                continue
            if cur is None:
                continue
            m = _RE_INS.match(raw.rstrip("\n"))
            if m:
                out[cur].append((int(m.group(3), 16), m.group(2).strip()))
    return out


def kernel_slice_s(lines, sym):
    """Indexes of a kernel's region in the bundle .s (exclusive end)."""
    start = end = None
    for i, ln in enumerate(lines):
        if ln.strip() == sym + ":":
            start = i + 1
        elif start is not None and ln.strip().endswith(":") \
                and not ln.strip().startswith(".L") and ln.strip().startswith("_Z"):
            end = i
            break
    return start, (end if end is not None else len(lines))


def s_insn_lines(lines, start, end):
    """(line_no, text) for instruction lines in a .s kernel region."""
    out = []
    for i in range(start, end):
        t = lines[i].strip()
        if not t or t.startswith(".") or t.endswith(":"):
            continue
        out.append((i, t))
    return out


def site_to_s_lines(lines, sym, dis_list, site_addrs):
    """Map disasm addresses of DS sites to bundle .s line numbers.

    For each site addr in site_addrs: find its disasm text row, then find
    every .s instruction line whose normalized text matches; use the k-th
    occurrence to disambiguate (k = ordinal of the site among matching
    disasm rows of the same normalized text).
    Returns {addr: [(s_line_no, text), ...]} with matched count.
    """
    norm_counts = {}
    for (a, t) in dis_list:
        norm_counts.setdefault(norm(t), []).append(a)
    start, end = kernel_slice_s(lines, sym)
    s_ins = s_insn_lines(lines, start, end)
    s_norm = [(ln, t, norm(t)) for (ln, t) in s_ins]
    # count normalized occurrences in the .s slice
    s_by_norm = {}
    for (ln, t, nt) in s_norm:
        s_by_norm.setdefault(nt, []).append((ln, t))
    res = {}
    for addr in site_addrs:
        row = next((t for (a, t) in dis_list if a == addr), None)
        if row is None:
            res[addr] = []
            continue
        nt = norm(row)
        matches = s_by_norm.get(nt, [])
        k = norm_counts[nt].index(addr) if nt in norm_counts else -1
        if k >= 0 and k < len(matches):
            res[addr] = [matches[k]]
        else:
            res[addr] = []
    return res
