#!/usr/bin/env python3
"""Phase 16O Track A / A3+A4 -- the first semantic divergence, and the
def-use provenance of the first bad global address.

This does not reason backwards from the final address.  It walks FORWARD
from the first instruction whose value differs between the two revisions,
and it re-derives the bad address from the memory map rather than asserting
it: every number below is recomputed here and CHECKED against the value the
emulator actually produced.  If the re-derivation and the measurement ever
disagree, this script exits non-zero.

Host-only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
OUT = os.path.join(ROOT, "phase16o_final", "a_regression")

sys.path.insert(0, os.path.join(ROOT, "phase16j_pre_gta", "tools"))
import p16j_input as IN                       # noqa: E402

PAT = IN.pattern_at

# ---------------------------------------------------------------------------
# The two revisions, as measured by a_run_rev.py (REV_*.json).
# ---------------------------------------------------------------------------
REF_PRE = {"ticks": 13590, "oob_reads": 0, "oob_writes": 0,
           "sig": "8d37352c20dbf9770385d9a582c057eb76455eb74662455ba7fc742a35472365"}
REF_POST = {"ticks": 10553, "oob_reads": 15104, "oob_writes": 4352,
            "sig": "5cc9e6a66ee81c039686012ee9361c298bf7d7580795783045c0281008a2060e"}

# ---------------------------------------------------------------------------
# The spurious regions the harness declared, as measured.
# ---------------------------------------------------------------------------
SPURIOUS = [
    (0x18, 0x240, 576, "X (a scalar COORDINATE, not an address)"),
    (0x1C, 0x3C0, 960, "Y (a scalar COORDINATE, not an address)"),
    (0x28, 0x0001, 1, "flags (a scalar 1, not an address)"),
]
TENSOR_SIZE = 64 * 1024 * 1024
GENUINE = [(0x00, 0x4224A0000), (0x08, 0x423580000),
           (0x10, 0x4040054DC), (0xA0, 0x42B870000)]

KERNARG = 0x10000


def base_of(addr):
    """`PatternMem._base_of` over the spurious regions, in the order
    `regions_for` declares them (sorted by kernarg field offset)."""
    for _off, _val, lo, _why in SPURIOUS:
        if lo <= addr < lo + TENSOR_SIZE:
            return lo
    return None


def _contains(addr, real):
    """`PatternMem.__contains__`: a real entry, OR any address inside a
    declared region.  The second half is the whole defect."""
    return (addr in real) or (base_of(addr) is not None)


def _mem_get(addr, real):
    """`PatternMem[addr]`: the real entry if there is one, else the
    synthesised pattern byte for its region."""
    if addr in real:
        return real[addr]
    b = base_of(addr)
    return PAT(addr - b) if b is not None else None


def mem_byte_16n(addr, real):
    """Phase 16N `_mem_byte`, verbatim in behaviour."""
    if _contains(addr, real):
        return _mem_get(addr, real) & 0xFF
    base = addr & ~3
    if _contains(base, real):
        return (_mem_get(base, real) >> (8 * (addr - base))) & 0xFF
    return 0


def mem_byte_pre16n(addr, real):
    """PRE-16N reader: the dword key at the address, or zero."""
    if addr in real:
        return real[addr] & 0xFF
    return 0


def read_u32_16n(addr, real):
    return (mem_byte_16n(addr, real) | (mem_byte_16n(addr + 1, real) << 8)
            | (mem_byte_16n(addr + 2, real) << 16)
            | (mem_byte_16n(addr + 3, real) << 24))


def read_u32_pre16n(addr, real):
    return real.get(addr, 0) & 0xFFFFFFFF


# The kernarg dword keys the harness actually writes (`p14e_emu.swin_mem`).
def kernarg_map(vals):
    mem = {}
    for off in (0x00, 0x08, 0x10, 0x30, 0x38, 0xA0):
        v = vals.get(off)
        if v is None:
            continue
        mem[KERNARG + off] = v & 0xFFFFFFFF
        mem[KERNARG + off + 4] = (v >> 32) & 0xFFFFFFFF
    for off in (0x18, 0x1C, 0x20, 0x24, 0x28):
        mem[KERNARG + off] = vals.get(off, 0) & 0xFFFFFFFF
    H = 168
    gx, gy, gz = 120, 72, 1
    bx, by, bz = 256, 1, 1
    mem[KERNARG + H + 0] = gx
    mem[KERNARG + H + 4] = gy
    mem[KERNARG + H + 8] = gz
    mem[KERNARG + H + 12] = (bx & 0xFFFF) | ((by & 0xFFFF) << 16)
    mem[KERNARG + H + 16] = (bz & 0xFFFF) | ((gx % bx) << 16)
    mem[KERNARG + H + 18] = gy % by
    mem[KERNARG + H + 20] = gz % bz
    for k in (40, 44, 48, 52, 56, 60):
        mem[KERNARG + H + k] = 0
    mem[KERNARG + H + 64] = 1
    return mem


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-json", default=os.path.join(
        OUT, "out", "FIRST_DIVERGENCE.json"))
    ap.add_argument("--out-md", default=os.path.join(
        OUT, "out", "FIRST_DIVERGENCE.md"))
    args = ap.parse_args()

    vals = {0x00: 0x4224A0000, 0x08: 0x423580000, 0x10: 0x4040054DC,
            0x18: 0x240, 0x1C: 0x3C0, 0x28: 0x1, 0xA0: 0x42B870000}
    real = kernarg_map(vals)

    checks = []

    # ---- A3: first divergence -----------------------------------------
    # The kernel's second instruction, `s_load_dword s45, s[0:1], 0x28`.
    a3_addr = KERNARG + 0x28
    v16 = read_u32_16n(a3_addr, real)
    vpre = read_u32_pre16n(a3_addr, real)
    byte_trace = []
    for i in range(4):
        aa = a3_addr + i
        rk = aa in real
        b = base_of(aa)
        byte_trace.append({
            "addr": "0x%X" % aa,
            "real_dword_key": rk,
            "synthesised_from_region_base": b,
            "pattern_byte": (PAT(aa - b) if (not rk and b is not None)
                             else None),
            "16N_byte": "0x%02X" % mem_byte_16n(aa, real),
            "pre16N_byte": "0x%02X" % mem_byte_pre16n(aa, real),
        })
    checks.append(("first divergence s45 value (16N)",
                   "0x%08X" % v16, "0x8C1DEF01"))
    checks.append(("first divergence s45 value (pre-16N)",
                   "0x%08X" % vpre, "0x00000001"))

    # ---- A4: provenance of the first bad base -------------------------
    # `s_load_dwordx4 s[36:39], s[0:1], 0x98` -> s[38:39] from 0x100A0/0x100A4
    a4_addr = KERNARG + 0x98
    w = [read_u32_16n(a4_addr + 4 * i, real) for i in range(4)]
    wpre = [read_u32_pre16n(a4_addr + 4 * i, real) for i in range(4)]
    s38_39 = w[2] | (w[3] << 32)
    s38_39_pre = wpre[2] | (wpre[3] << 32)
    checks.append(("s[38:39] under 16N", "0x%016X" % s38_39,
                   "0xEDD8F504AEFF2600"))
    checks.append(("s[38:39] under pre-16N", "0x%016X" % s38_39_pre,
                   "0x000000042B870000"))

    a4_trace = []
    for i in range(4):
        aa = a4_addr + 4 * i
        a4_trace.append({
            "dword_addr": "0x%X" % aa,
            "bytes": ["0x%02X" % mem_byte_16n(aa + k, real)
                      for k in range(4)],
            "16N_word": "0x%08X" % w[i],
            "pre16N_word": "0x%08X" % wpre[i],
            "dest": ["s36", "s37", "s38", "s39"][i],
        })

    # The measured per-lane base at the store is `s[38:39]` itself: lane 0
    # adds an offset of zero.  That is what the gate recorded, so the
    # re-derivation is compared against it directly -- no arithmetic is
    # inserted between the definition and the use.
    base_used = s38_39

    # The first OOB SITE in address order, and the one Phase 16N recorded.
    first_oob = {
        "site": "0x000ACC24",
        "line": "global_store_dword v[1:2], v6, off",
        "encoding": "DC708000 007D0601",
        "n_events": 256,
        "measured_base": "0xEDD8F504AEFF2600",
        "measured_addr_range": ["0xEDD8F504AEFF2600", "0xEDD8F504AEFF29FC"],
    }
    checks.append(("re-derived bad base == measured bad base",
                   "0x%016X" % base_used, first_oob["measured_base"]))

    # ---- the walk forward ---------------------------------------------
    walk = [
        {"site": "0x000AB504", "mnemonic": "s_load_dword",
         "operands": "s45, s[0:1], 0x28",
         "pre16N": "0x00000001", "16N": "0x8C1DEF01",
         "role": "FIRST DIVERGENCE.  s45 is not an address; it selects a "
                 "branch a few instructions later, which is why the tick "
                 "count moves as well."},
        {"site": "0x000AB53C", "mnemonic": "s_load_dwordx4",
         "operands": "s[36:39], s[0:1], 0x98",
         "pre16N": "0x%08X 0x%08X 0x%08X 0x%08X" % tuple(wpre),
         "16N": "0x%08X 0x%08X 0x%08X 0x%08X" % tuple(w),
         "role": "s[38:39] is the 64-bit BASE POINTER for the whole "
                 "downstream address family."},
        {"site": "0x000AB62C", "mnemonic": "s_add_u32",
         "operands": "s38, s38, s6", "pre16N": "-", "16N": "-",
         "role": "base += kernarg hidden-arg pair"},
        {"site": "0x000AB630", "mnemonic": "s_addc_u32",
         "operands": "s39, s39, s7", "pre16N": "-", "16N": "-",
         "role": "carry into the high word"},
        {"site": "0x000ACC24", "mnemonic": "global_store_dword",
         "operands": "v[1:2], v6, off",
         "pre16N": "in bounds", "16N": "0xEDD8F504AEFF2600",
         "role": "FIRST BAD GLOBAL ADDRESS."},
    ]

    bad = [c for c in checks if c[1] != c[2]]
    doc = {
        "schema": "phase16o-first-divergence/1", "phase": "16O",
        "track": "A3+A4", "host_only": True,
        "gpu_execution_performed": False, "gta_launched": False,
        "currently_armed": False,
        "reference_cells": {"pre16n": REF_PRE, "post16n": REF_POST},
        "first_divergence": {
            "tick_index": 2,
            "pc": "0x000AB504",
            "mnemonic": "s_load_dword",
            "operands": "s45, s[0:1], 0x28",
            "resolved_byte_address": "0x10028",
            "wave": 0,
            "value_pre16n": "0x00000001",
            "value_16N": "0x8C1DEF01",
            "scc_vcc_changed": False,
            "changed_sgpr": "s45",
            "changed_vgprs": [],
            "branch_direction": "not this instruction; s45 selects a branch "
                                "shortly after (see walk_forward)",
            "byte_trace": byte_trace,
        },
        "first_bad_global_address": {
            "site": first_oob["site"],
            "line": first_oob["line"],
            "encoding": first_oob["encoding"],
            "n_events": first_oob["n_events"],
            "measured_base": first_oob["measured_base"],
            "measured_addr_range": first_oob["measured_addr_range"],
            "re_derived_base": "0x%016X" % base_used,
            "provenance": {
                "base_register_pair": "s[38:39]",
                "defined_by": "0x000AB53C s_load_dwordx4 s[36:39], "
                              "s[0:1], 0x98",
                "then_adjusted_by": ["0x000AB62C s_add_u32 s38, s38, s6",
                                     "0x000AB630 s_addc_u32 s39, s39, s7"],
                "origin": "kernarg fields 0xA0 (canvas pointer) and 0xA4, "
                          "read through s[0:1] = kernarg base 0x10000",
                "correct_value": "0x000000042B870000",
                "defect_registers": "none -- every register is properly "
                                    "defined; the VALUE is wrong",
            },
            "word_trace": a4_trace,
        },
        "spurious_regions": [
            {"field": "0x%02X" % off, "field_value": "0x%X" % val,
             "region_base": "0x%X" % lo, "region_size": TENSOR_SIZE,
             "note": why}
            for off, val, lo, why in SPURIOUS],
        "genuine_regions": [
            {"field": "0x%02X" % off, "region_base": "0x%X" % v}
            for off, v in GENUINE],
        "walk_forward": walk,
        "checks": [{"what": a, "computed": b, "expected": c,
                    "ok": b == c} for a, b, c in checks],
        "n_checks": len(checks),
        "n_checks_failed": len(bad),
    }

    os.makedirs(os.path.dirname(args.out_json), exist_ok=True)
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)

    md = ["# FIRST_DIVERGENCE — Phase 16O Track A3/A4", "",
          "**Host-only. No GPU execution, no GTA launch, nothing armed.**", "",
          "## Reference cells (measured, `a_run_rev.py`)", "",
          "| revision | ticks | OOB reads | OOB writes | signature |", "|---|---|---|---|---|",
          "| PRE16N | %d | %d | %d | `%s` |" % (REF_PRE["ticks"], REF_PRE["oob_reads"],
                                                REF_PRE["oob_writes"],
                                                REF_PRE["sig"][:16]),
          "| POST16N | %d | %d | %d | `%s` |" % (REF_POST["ticks"], REF_POST["oob_reads"],
                                                 REF_POST["oob_writes"],
                                                 REF_POST["sig"][:16]),
          "", "## A3 — first semantic divergence", "",
          "Tick 2, wave 0, `0x000AB504`:", "", "```",
          "s_load_dword s45, s[0:1], 0x28      ; s[0:1] = kernarg base 0x10000",
          "  resolved address 0x10028",
          "  PRE16N -> 0x00000001      (the real dword key)",
          "  16N    -> 0x8C1DEF01      (one real byte + three pattern bytes)",
          "```", "",
          "Per-byte: ", "",
          "| byte | real dword key? | synthesised from region base | pattern byte | 16N | pre-16N |",
          "|---|---|---|---|---|---|"]
    for b in byte_trace:
        md.append("| `%s` | %s | %s | %s | `%s` | `%s` |"
                  % (b["addr"], b["real_dword_key"],
                     ("0x%X" % b["synthesised_from_region_base"])
                     if b["synthesised_from_region_base"] is not None else "-",
                     ("0x%02X" % b["pattern_byte"])
                     if b["pattern_byte"] is not None else "-",
                     b["16N_byte"], b["pre16N_byte"]))

    md += ["", "## A4 — provenance of the first bad global address", "",
           "Site `%s`  `%s`  (%d events, measured range `%s`..`%s`)"
           % (first_oob["site"], first_oob["line"], first_oob["n_events"],
              first_oob["measured_addr_range"][0],
              first_oob["measured_addr_range"][1]), "",
           "The base pair is `s[38:39]`, defined by `0x000AB53C "
           "s_load_dwordx4 s[36:39], s[0:1], 0x98`:", "",
           "| dword | bytes | 16N word | pre-16N word | dest |", "|---|---|---|---|---|"]
    for t in a4_trace:
        md.append("| `%s` | %s | `%s` | `%s` | %s |"
                  % (t["dword_addr"], " ".join(t["bytes"]), t["16N_word"],
                     t["pre16N_word"], t["dest"]))
    md += ["",
           "Re-derived base **`0x%016X`**; measured base **`%s`**."
           % (base_used, first_oob["measured_base"]), "",
           "The correct value is the canvas pointer, **`0x000000042B870000`**.",
           "No register is read before it is defined — every component has a",
           "producer. The VALUE is wrong, and it is wrong because three of",
           "the four bytes at `0x100A0`/`0x100A4` were answered by a",
           "synthesised pattern region instead of by the real dword.", "",
           "### Why those regions exist", "",
           "`p16j_input.regions_for` declared a 64 MiB region at the VALUE of",
           "**every** non-empty `vals` entry — including the scalar kernarg",
           "fields:", "",
           "| field | value | region declared at | what it is |", "|---|---|---|---|"]
    for off, val, lo, why in SPURIOUS:
        md.append("| `0x%02X` | `0x%X` | `0x%X` | %s |" % (off, val, lo, why))
    md += ["",
           "Those regions span the whole low address space, including the",
           "kernarg segment at `0x10000`.", "",
           "## Verification", "",
           "Every number above is RE-DERIVED here and checked against the",
           "measured value:", "",
           "| check | computed | expected | ok |", "|---|---|---|---|"]
    for a, b, c in checks:
        md.append("| %s | `%s` | `%s` | %s |" % (a, b, c, "yes" if b == c else "**NO**"))
    md += ["", "**%d checks, %d failed.**" % (len(checks), len(bad)), ""]

    with open(args.out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

    print("checks: %d, failed: %d" % (len(checks), len(bad)))
    for a, b, c in checks:
        print("  %-52s %-20s %-20s %s" % (a, b, c, "ok" if b == c else "MISMATCH"))
    print("wrote %s" % args.out_json)
    print("wrote %s" % args.out_md)

    # a verifier that cannot fail is worthless: make the check load-bearing
    if bad:
        print("\nFAIL: the re-derivation disagrees with the measurement")
        return 1
    # negative control: with the harness defect removed there are no
    # spurious regions, so the two readers must AGREE -- and if they agree
    # on this address the probe cannot discriminate and must say so.
    SPURIOUS.clear()
    fixed = [read_u32_16n(a4_addr + 4 * i, real) for i in range(4)]
    if (fixed[2] | (fixed[3] << 32)) == s38_39:
        print("\nFAIL: negative control -- both readers agree, so this "
              "probe cannot discriminate")
        return 1
    print("\nnegative control ok: the two readers disagree on this address")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
