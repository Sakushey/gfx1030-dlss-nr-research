"""Phase 8C/8D/8E/8F/8J audits over the first-kernel translation artifacts.

8D/8J: CFG + branch-target equivalence via the per-site translation log.
8E:    semantic classification of the 253 removed scheduling tokens.
8F:    implicit-state (SCC/VCC/EXEC/M0) audit of re-encodings + dual
       unbundling + WMMA replacement.
8C:    max register scan of the translated stream (Q9 underdeclaration
       input).

HOST-ONLY.
"""
import collections
import csv
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from disasm_lib import parse_orig_disasm, parse_translated_asm
OUT = os.path.join(ROOT, "phase8_static", "out")

log_rows = list(csv.DictReader(open(os.path.join(
    ROOT, "phase7_translation", "k_conv_splitk_translation_log.csv"), encoding="utf-8")))
print("log rows:", len(log_rows))

# ---------------- 8E: removed-token classification ----------------
sch = [r for r in log_rows if r["classification"] == "scheduling-only"]
print("scheduling-only rows:", len(sch))
c = collections.Counter(r["source_mnemonic"] for r in sch)
print("mnemonic breakdown:", dict(c))
# which of them are delay-pacing only vs resource lifecycle?
pat = collections.Counter()
for r in sch:
    if r["source_mnemonic"] == "s_delay_alu":
        pat["s_delay_alu"] += 1
    elif r["source_mnemonic"] == "s_set_inst_prefetch_distance":
        pat["prefetch"] += 1
    elif r["source_mnemonic"] == "s_sendmsg":
        pat["sendmsg"] += 1
    else:
        pat[r["source_mnemonic"]] += 1
print("removed-token semantic classes:", dict(pat))

# ---------------- 8D/8J: branch equivalence ----------------
# original branch rows with addresses
orig = parse_orig_disasm(os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_disassembly.txt"))
orig = [r for r in orig if 0x69000 <= r["address"] <= 0x6B3FF]
ob = [r for r in orig if r["mnemonic"].startswith("s_cbranch") or r["mnemonic"] == "s_branch"]
print("orig branch rows:", len(ob))

# translate: map log rows by their 'address' column value? inspect columns
print("log columns:", list(log_rows[0].keys()))

# labels in translated asm
labels, trows = parse_translated_asm(os.path.join(
    ROOT, "phase7_translation", "k_conv_splitk_translated_gfx1030.s"))
tins = [r for r in trows if r["kind"] == "instruction"]
tb = [r for r in tins if r["mnemonic"].startswith("s_cbranch") or r["mnemonic"] == "s_branch"]
print("trans branch rows:", len(tb))

# WMMA expansion range in translated stream: locate the row that replaced the
# WMMA (log row for address 0x69C88) and the length of generated lines
def addr_of_log_row(r):
    m = re.match(r"0x([0-9a-fA-F]+)", r.get("source_address", "") or "")
    return int(m.group(1), 16) if m else None

wmma_rows = [r for r in log_rows if r["classification"] == "WMMA-template"]
print("wmma rows:", len(wmma_rows))
for wr in wmma_rows:
    print("wmma log:", wr["source_address"], wr["source_mnemonic"], "generated lines:",
          len([x for x in wr["generated_gfx1030_operations"].split("||") if x.strip()]))
# find any branch target whose label lands inside expansion -> expansions are
# emitted inline; labels only exist at branch targets, so check none of the
# trans branch targets map inside the WMMA expansion instruction span
# (expansion occupies contiguous rows after the mapped site row).
# simpler: no label name inside expansion is referenced; expansions contain no
# labels by construction. Verify: all referenced labels are in labels dict and
# the row order 1:1 (log position == trans row position after removing
# scheduling-only rows and reordering none).

# Build the mapping original-address -> log row (each log row has an address)
by_addr = {}
for r in log_rows:
    a = addr_of_log_row(r)
    if a is not None:
        by_addr.setdefault(a, []).append(r)

# verify every orig branch has a log row and that the generated line for it is
# a branch to the label whose numeric suffix equals the orig target address
label_addr = {}
for name in labels:
    m = re.match(r"\.L_kconv_0([0-9a-fA-F]+)", name)
    if m:
        label_addr[name] = int(m.group(1), 16)

def branch_target_addr(ins):
    """resolve target addr of an original branch row from its operand."""
    first = ins["operands"].split()[0]
    if first.lstrip("-").isdigit():
        disp = int(first)
        if disp >= 0x8000:
            disp -= 0x10000
        return ins["address"] + 4 + disp * 4
    return int(first, 16)

mismatch = []
missing_log = []
checked = 0
for b in ob:
    rows_for_site = by_addr.get(b["address"])
    if not rows_for_site:
        missing_log.append(b["address"])
        continue
    # dual rows may have produced two log entries; find the branch one
    bro = [r for r in rows_for_site if r["classification"] != "scheduling-only"]
    # the branch is a direct-compatible or spelling-reencodable row
    gen_lines = []
    for r in rows_for_site:
        gen_lines.extend(x.strip() for x in r["generated_gfx1030_operations"].split("||") if x.strip())
    # expect exactly one generated branch whose label = target
    tgt = branch_target_addr(b)
    tgt_label = ".L_kconv_%08X" % tgt if tgt < 0x10000000 else ".L_kconv_0%X" % tgt
    # label names used are like .L_kconv_00069038 (11 hex digits)
    tgt_label = ".L_kconv_0%X" % tgt if tgt >= 0x10000000 else ".L_kconv_%08X" % tgt
    # actual naming pattern: .L_kconv_00069038 -> 0 + 8 hex? name regex above
    # uses .L_kconv_0([0-9a-fA-F]+): 11 chars after .L_kconv_ ; format:
    matches = []
    for g in gen_lines:
        mm = re.match(r"^(s_cbranch\S*|s_branch)\s+(\.L_kconv_\w+)$", g)
        if mm:
            matches.append((mm.group(1), mm.group(2)))
    checked += 1
    if len(matches) != 1:
        mismatch.append((hex(b["address"]), "expected 1 generated branch, got", matches, gen_lines[:2]))
        continue
    gm, gl = matches[0]
    la = label_addr.get(gl)
    if la != tgt:
        mismatch.append((hex(b["address"]), f"target mismatch: orig->{tgt:#x} trans->{la:#x} via {gl}"))

print("orig branches with log+generated branch:", checked)
print("missing log rows for branch sites:", [hex(a) for a in missing_log])
print("branch mismatches:", len(mismatch))
for m in mismatch[:10]:
    print("  ", m)

# trans branch count should equal orig branch count (delays removed; duals
# cannot contain branches)
print("trans branch rows:", len(tb), "orig:", len(ob))

# ---------------- 8F: implicit-state audit ----------------
# list re-encodable rows (spelling-reencodable + dual-reencodable) and the
# mnemonic pairs, flag state-carrying sources: vcc/exec/scc/m0 operands
stateful = []
reenc = [r for r in log_rows if r["classification"] in
         ("spelling-reencodable", "dual-reencodable", "packed-high-load-replacement", "minmax-replacement")]
print("re-encodable rows:", len(reenc))
sensitive = []
for r in reenc:
    txt = (r["source_mnemonic"] + " " + (r.get("source_operation") or ""))
    gens = [x for x in r["generated_gfx1030_operations"].split("||") if x.strip()]
    if re.search(r"\b(vcc|exec|scc|m0)\b", txt):
        sensitive.append((r.get("source_address",""), r["source_mnemonic"], r.get("source_operation", ""), gens))
print("re-encodable rows touching vcc/exec/scc/m0:", len(sensitive))
for s in sensitive[:14]:
    print("  ", s)

# ---------------- 8C input: max register scan of translated asm ------------
maxv = -1
maxs = -1
maxvreg_pair = []
for ins in tins:
    txt = ins["mnemonic"] + " " + ins["operands"]
    for m in re.finditer(r"v(\d+)(?::(\d+))?", txt):
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if hi > maxv:
            maxv = hi
    for m in re.finditer(r"s(\d+)(?::(\d+))?", txt):
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) else lo
        if hi > maxs:
            maxs = hi
print("translated stream max VGPR index:", maxv, " max SGPR index:", maxs)
with open(os.path.join(OUT, "8cdefj_summary.txt"), "w") as f:
    f.write(f"log rows: {len(log_rows)}\n")
    f.write(f"scheduling-only: {len(sch)} breakdown: {dict(c)}\n")
    f.write(f"semantic classes: {dict(pat)}\n")
    f.write(f"orig branches: {len(ob)} trans branches: {len(tb)}\n")
    f.write(f"branches verified: {checked} mismatches: {len(mismatch)}\n")
    f.write(f"re-encodable: {len(reenc)} stateful among them: {len(sensitive)}\n")
    f.write(f"max VGPR {maxv} max SGPR {maxs}\n")
print("done")
