"""Phase 8L: statically repair the five k_swin_var gfx1030 assembler
blockers (global load/store offsets outside the gfx1030 signed 12-bit
range).

Every out-of-range site is rewritten to a semantically exact 64-bit
address computation into a fresh temporary VGPR pair (registers above the
kernel's own usage), followed by the same access with offset 0:

  form A (vaddr pair + imm):
      v_add_co_u32_e64   T_lo, C0, N, v_lo
      v_add_co_ci_u32_e64 T_hi, null, 0, v_hi, C0
      global_* dst, v[T_lo:T_hi], off

  form B (32-bit vaddr + saddr base + imm):  EA = s_base + v + N
      v_mov_b32_e32 VZ, 0
      v_add_co_u32_e64   T0,   C0, N,   v
      v_add_co_u32_e64   T_lo, C1, s_lo, T0
      v_add_co_ci_u32_e64 T_hi, null, s_hi, VZ, C0
      v_add_co_ci_u32_e64 T_hi, null, 0, T_hi, C1
      global_* dst, v[T_lo:T_hi], off

Exactness: (a) 64-bit addition of N to the pair (one carry possible);
(b) s + v + N is decomposed as ((v+N) mod 2^32) + s with both carries
added to the high word: T_hi = s_hi + c0 + c1, matching the true sum
floor. The two-ci sequence adds 0/1 twice and is exact for all inputs
(total < 2^33 + 4096; carries c0,c1 <= 1 per lane; c0+c1 <= 2).
No implicit state is touched: e64 forms carry into dedicated SGPR
carriers chosen above the kernel's own SGPR usage (VCC/SCC/EXEC/M0
untouched). The kernel's .amdhsa_next_free_vgpr/.amdhsa_next_free_sgpr
are bumped so the descriptor covers the new registers.

HOST-ONLY: llvm-mc assembly only; no GPU.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "phase7_full_static", "assembly")
OUTD = os.path.join(ROOT, "phase8_static", "out", "swin_fixed")
MC = r"<ROCM_ROOT>\7.1\bin\llvm-mc.exe"
os.makedirs(OUTD, exist_ok=True)

FILES = [
    "_Z10k_swin_varILi32ELb1EEv9VarParams.s",
    "_Z10k_swin_varILi32ELb0EEv9VarParams.s",
    "_Z10k_swin_varILi64ELb0EEv9VarParams.s",
    "_Z10k_swin_varILi128ELb0EEv9VarParams.s",
    "_Z10k_swin_varILi256ELb0EEv9VarParams.s",
]

OP_RE = re.compile(
    r"^(global_\w+)\s+(v(?:\[\d+:\d+\]|\d+)),\s+(v(?:\[\d+:\d+\]|\d+)),\s+"
    r"(off|s\[\d+:\d+\])\s+offset:(-?\d+)\s*$")


def _op_text(mnem, other_operand, is_load, tlo, thi):
    if is_load:
        return f"\t{mnem} {other_operand}, v[{tlo}:{thi}], off"
    # store: address operand comes first, data second
    return f"\t{mnem} v[{tlo}:{thi}], {other_operand}, off"


def vrange(tok):
    m = re.match(r"v\[(\d+):(\d+)\]", tok)
    if m:
        return int(m.group(1)), int(m.group(2))
    return int(tok[1:]), int(tok[1:])


def srange(tok):
    m = re.match(r"s\[(\d+):(\d+)\]", tok)
    return int(m.group(1)), int(m.group(2))


summary = []
for fname in FILES:
    path = os.path.join(SRC, fname)
    lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    txt = "\n".join(lines)
    maxv = max(int(m.group(1)) for m in re.finditer(r"\bv(\d+)", txt))
    maxs = max(int(m.group(1)) for m in re.finditer(r"\bs(\d+)", txt))
    # fresh temps above every use in the file
    T0 = maxv + 1   # form B scratch
    VZ = maxv + 2   # zero vector for form B hi add
    TLO = maxv + 3
    THI = maxv + 4
    C0 = maxs + 1   # carrier sgpr (per-lane carry mask)
    C1 = maxs + 2
    sites = []
    for i, line in enumerate(lines):
        m = OP_RE.match(line.strip())
        if not m:
            continue
        mnem, a1, a2, saddr, off = m.groups()
        off = int(off)
        if -2048 <= off <= 2047:
            continue
        sites.append((i, line, mnem, a1, a2, saddr, off))
    nf_v = nf_s = None
    fixed = list(lines)
    for (i, line, mnem, a1, a2, saddr, off) in sites:
        is_load = mnem.startswith("global_load")
        if is_load:
            dst, vaddr = a1, a2
        else:
            vaddr, dst = a1, a2
        vlo, vhi = vrange(vaddr)
        # the offset's own high word (sign extension) must be added to the
        # high word: -1 for negative offsets, 0 otherwise (hardware
        # sign-extends the imm and adds in 64 bits)
        hi_imm = "-1" if off < 0 else "0"
        if saddr == "off" and vhi > vlo:
            # form A: 64-bit pair + imm
            repl = [
                f"\tv_add_co_u32_e64 v{TLO}, s{C0}, {off}, v{vlo}",
                f"\tv_add_co_ci_u32_e64 v{THI}, null, {hi_imm}, v{vhi}, s{C0}",
            ]
            new_op = _op_text(mnem, dst, is_load, TLO, THI)
        elif saddr == "off" and vhi == vlo:
            raise SystemExit(f"{fname}:{i+1}: unexpected 1-vgpr vaddr with 'off'")
        else:
            # form B: 1-vgpr vaddr + saddr base + imm  (EA = s + v + N)
            slo, shi = srange(saddr)
            repl = [
                f"\tv_mov_b32_e32 v{VZ}, 0",
                f"\tv_add_co_u32_e64 v{T0}, s{C0}, {off}, v{vlo}",
                f"\tv_add_co_u32_e64 v{TLO}, s{C1}, s{slo}, v{T0}",
                f"\tv_add_co_ci_u32_e64 v{THI}, null, s{shi}, v{VZ}, s{C0}",
                f"\tv_add_co_ci_u32_e64 v{THI}, null, {hi_imm}, v{THI}, s{C1}",
            ]
            new_op = _op_text(mnem, dst, is_load, TLO, THI)
        fixed[i] = "\n".join(repl) + "\n" + new_op
        idx = next(k for k, s in enumerate(sites) if s[0] == i)
        sites[idx] = (i, line, mnem, new_op)
    # bump the descriptor register counts
    need_v = maxv + 5
    need_s = maxs + 3
    for i, line in enumerate(fixed):
        m = re.match(r"^(\s*\.amdhsa_next_free_vgpr )(\d+)\s*$", line)
        if m:
            nf_v = max(int(m.group(2)), need_v)
            fixed[i] = f"{m.group(1)}{nf_v}"
        m = re.match(r"^(\s*\.amdhsa_next_free_sgpr )(\d+)\s*$", line)
        if m:
            nf_s = max(int(m.group(2)), need_s)
            fixed[i] = f"{m.group(1)}{nf_s}"
    out_path = os.path.join(OUTD, fname)
    open(out_path, "w", encoding="utf-8").write("\n".join(fixed))
    summary.append((fname, len(sites), maxv, maxs, T0, VZ, TLO, THI, C0, C1,
                    nf_v, nf_s, sites))

for (fname, n, maxv, maxs, T0, VZ, TLO, THI, C0, C1, nf_v, nf_s, sites) in summary:
    print(f"{fname}: fixed {n} sites; temps v{TLO},v{THI} (+v{T0},v{VZ} form B), "
          f"carriers s{C0},s{C1}; next_free vgpr {nf_v} sgpr {nf_s}")
    for s in sites:
        print("   ", s[0] + 1, "|", s[2], "|", s[3][:80])

# assemble
print("\n--- assembling with llvm-mc (ROCm 7.1) ---")
ok = True
for (fname, *_rest) in summary:
    asm = os.path.join(OUTD, fname)
    obj = os.path.join(OUTD, fname[:-2] + ".o")
    r = subprocess.run([MC, "-triple=amdgcn-amd-amdhsa", "-mcpu=gfx1030",
                        "-filetype=obj", asm, "-o", obj],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    status = "PASS" if r.returncode == 0 else "FAIL"
    ok &= r.returncode == 0
    print(f"{fname}: assembler exit {r.returncode} ({status})")
    if r.returncode != 0:
        print((r.stdout + r.stderr)[:600])
print("ALL PASS" if ok else "FAILURES PRESENT")
