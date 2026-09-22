"""Phase 14E-F3 step 2: find hipLaunchKernel call sites (call 0x180054100) and
check which of them reference the swin_var<32,false> handles:
  E32 = 0x180057a20 (rdata entry passed to __hipRegisterFunction as hostFunction)
  S32 = 0x180023c10 (code pointed to by that entry)
Dumps back-windows for matching sites; prints a per-site rcx-source summary.
"""
from __future__ import annotations

import re

DIS = r"<PROJECT_ROOT>\phase14e_forensics\out\host_full_disasm.txt"
OUT = r"<PROJECT_ROOT>\phase14e_forensics\out"

LAUNCH_THUNK = 0x180054100   # hipLaunchKernel
PUSH_THUNK = 0x180053fd0     # __hipPushCallConfiguration
E32 = 0x180057a20
S32 = 0x180023c10

lines = []
for raw in open(DIS, encoding="utf-8", errors="replace"):
    raw = raw.rstrip("\n")
    m = re.match(r"^([0-9a-f]+): (.*)$", raw)
    if m:
        lines.append((int(m.group(1), 16), raw))

vasi = [a for a, _ in lines]


def window(center_i, back, fwd, out):
    lo, hi = max(0, center_i - back), min(len(lines), center_i + fwd)
    for j in range(lo, hi):
        out.append(lines[j][1])


launch_sites = []
for i, (va, raw) in enumerate(lines):
    m = re.search(r"\tcall\t0x%x(?=[ <]|$)" % LAUNCH_THUNK, raw)
    if m:
        launch_sites.append(i)

push_sites = []
for i, (va, raw) in enumerate(lines):
    if re.search(r"\tcall\t0x%x(?=[ <]|$)" % PUSH_THUNK, raw):
        push_sites.append(i)

print(f"hipLaunchKernel sites: {len(launch_sites)}")
print(f"__hipPushCallConfiguration sites: {len(push_sites)}")

all_sites = sorted(launch_sites + push_sites)
hits = []
for idx in launch_sites:
    va = lines[idx][0]
    lo = max(0, idx - 120)
    ctx = "\n".join(lines[j][1] for j in range(lo, idx))
    hits.append((va, (f"0x{E32:x}" in ctx), (f"0x{S32:x}" in ctx), ctx))

matched = [(va, a, b) for va, a, b, _ in hits if a or b]
print(f"launch sites referencing E32/S32: {len(matched)}")
for va, a, b in matched:
    print(f"  launch@0x{va:x}  refs E32={a} S32={b}")

out = []
for idx in launch_sites:
    va = lines[idx][0]
    lo = max(0, idx - 120)
    ctx = "\n".join(lines[j][1] for j in range(lo, idx))
    if f"0x{E32:x}" in ctx or f"0x{S32:x}" in ctx:
        out.append(f"===== hipLaunchKernel site 0x{va:x} (window 120 insns) =====")
        window(idx, 120, 30, out)
open(rf"{OUT}\p14e_swin32_launch_site_windows.txt", "w", encoding="utf-8").write("\n".join(out) + "\n")
print(f"windows written ({len(out)} lines)")

# csv: site rva -> kind
import csv
with open(rf"{OUT}\p14e_launch_sites.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["kind", "site_rva"])
    for i in push_sites:
        w.writerow(["push", f"0x{lines[i][0]:x}"])
    for i in launch_sites:
        w.writerow(["launch", f"0x{lines[i][0]:x}"])
print("sites csv written")
