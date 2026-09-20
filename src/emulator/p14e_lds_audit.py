"""Phase 14E — LDS access-range audit of the translated swin<32,false>
body (host-only, read-only).

Reads the phase-14E translated body
(phase14e_forensics/out/swin_entryfixed_body.txt) and emits
phase14e_lds_access_ranges.csv at the project root:

For EVERY ds_* instruction row:
  pc_hex                  instruction address
  mnemonic                e.g. ds_bpermute_b32
  operand_text            raw operand text
  imm_offset_field        "offset:N" / "offset0:N" / "offset1:N" if present
  has_preceding_mask_0x3fff
      "yes"/"no"/"uncertain": scans the up to 20 instruction rows above the
      site for the literal 0x3fff appearing on a row that also carries the
      ds instruction's address operand register. (The body file contains no
      0x3fff literal at all, so every row yields "no"; the scan is run
      anyway so the method is the same if the file changes.)
  static_max_ea_note      static-only statement about the effective DS
                          address (vaddr + imm). Anything requiring a
                          register value is "UNKNOWN (reg-dependent)".
                          A trailing block of SUMMARY rows lists the
                          distinct immediate-offset magnitudes (min..max)
                          observed across all sites.

Zero GPU execution. Deterministic, no network, no subprocesses.
"""
from __future__ import annotations

import csv
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
BODY = os.path.join(ROOT, "phase14e_forensics", "out",
                    "swin_entryfixed_body.txt")
OUT = os.path.join(ROOT, "phase14e_lds_access_ranges.csv")

ROW_RE = re.compile(r"^\s*([\w.]+)\s+(.*?)\s+// ([0-9A-F]+):")
OFF_RE = re.compile(r"offset0?:(-?\d+)|offset1:(-?\d+)")
VTOK_RE = re.compile(r"^v(\d+)(\[.*\])?$")


def parse_rows(path):
    rows = []
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = ROW_RE.match(ln.strip())
        if m:
            addr = int(m.group(3), 16)
            mnem, ops = m.group(1), m.group(2)
            rows.append((addr, mnem, ops, ln.rstrip("\n")))
    return rows


def v_tokens(ops):
    toks = []
    for part in ops.split(","):
        p = part.strip()
        m = VTOK_RE.match(p)
        if m:
            toks.append((p, int(m.group(1))))
    return toks


def ds_addr_reg(mnem, ops):
    """RDNA ds operand order used by the phase-14E recorder:
    loads/reads carry (dst..., vaddr) -> address is the LAST v-token;
    stores/writes carry (vaddr, data...) -> address is the FIRST v-token.
    (read2/write2 use one address reg + offset1; ds_bpermute is dst,data,addr.)
    """
    vt = v_tokens(ops)
    if not vt:
        return None
    is_load = ("load" in mnem or "read" in mnem)
    return vt[-1][1] if is_load else vt[0][1]


TOK_RE = re.compile(r"\b(offset0|offset1|offset):(-?\d+)")
IMM_RE = re.compile(r"\b(?:offset0|offset1|offset):(-?\d+)")


def imm_field(ops):
    """Return the exact raw offset tokens as they appear (offset:N /
    offset0:N / offset1:N), joined by '; ', or '' when none."""
    parts = [m.group(0) for m in TOK_RE.finditer(ops)]
    return "; ".join(parts) if parts else ""


def scan_mask(rows, i, addr_reg):
    """Scan up to 20 instruction rows above rows[i]; the row 'contains the
    mask' if the literal 0x3fff appears anywhere in it AND it also mentions
    the ds address register (as a token that could write or hold it)."""
    for j in range(max(0, i - 20), i):
        _a, _m, ops, raw = rows[j]
        low = raw.lower()
        if "0x3fff" not in low:
            continue
        if addr_reg is not None and ("v%d" % addr_reg) in low:
            return "yes"
    return "no"


def main():
    rows = parse_rows(BODY)
    ds_idx = [(i, r) for i, r in enumerate(rows) if r[1].startswith("ds")]
    n_3fff_lines = sum(1 for *_x, raw in rows if "0x3fff" in raw.lower())
    imm_vals = []
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["pc_hex", "mnemonic", "operand_text",
                    "imm_offset_field", "has_preceding_mask_0x3fff",
                    "static_max_ea_note"])
        for i, (addr, mnem, ops, _raw) in ds_idx:
            ar = ds_addr_reg(mnem, ops)
            # magnitude set = the offset fields exactly as coded on the
            # instruction (offset:N / offset0:N / offset1:N).
            offs = [int(m.group(1)) for m in IMM_RE.finditer(ops)]
            for o in offs:
                imm_vals.append(o)
            note = "UNKNOWN (ea = vaddr + imm; register-dependent)"
            if not offs:
                note = "UNKNOWN (ea = vaddr; register-dependent)"
            w.writerow(["0x%08X" % addr, mnem, ops, imm_field(ops),
                        scan_mask(rows, i, ar), note])
        # ---- summary trailer ----
        distinct = sorted(set(imm_vals))
        w.writerow(["SUMMARY", "total_ds_rows", str(len(ds_idx)), "", "", ""])
        w.writerow(["SUMMARY", "distinct_imm_magnitudes", str(len(distinct)),
                    "", "", ""])
        w.writerow(["SUMMARY", "imm_min", str(min(imm_vals) if imm_vals
                                              else "n/a"),
                    "imm_max", str(max(imm_vals) if imm_vals else "n/a"),
                    "largest_imm_hex=0x%X" % (max(imm_vals)
                                              if imm_vals else 0)])
        for chunk in (distinct[i:i + 16] for i in
                      range(0, len(distinct), 16)):
            w.writerow(["SUMMARY", "imm_magnitudes_sorted", "", "", "",
                        ",".join(str(v) for v in chunk)])
        w.writerow(["SUMMARY", "lines_containing_0x3fff_in_body",
                    str(n_3fff_lines), "", "", ""])
        w.writerow(["SUMMARY", "mask_scan_result",
                    "no 0x3fff literal exists anywhere in the body file, so "
                    "has_preceding_mask_0x3fff = no for every row", "", "",
                    ""])
    print("rows:", len(ds_idx), "->", OUT)
    print("distinct imm:", len(distinct), "min", min(imm_vals),
          "max", max(imm_vals), "largest hex 0x%X" % max(imm_vals))
    print("0x3fff lines in body:", n_3fff_lines)


if __name__ == "__main__":
    sys.exit(main())
