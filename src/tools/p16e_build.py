#!/usr/bin/env python3
"""Phase 16E — candidate-E module build (host-only), consolidated.

Applies to a COPY of the entry-fixed bundle .s:
  Form-A (register mask):   v_and_b32_e32 vN, 0x3fff, vN  immediately
                            before the site's DS row (N = DS addr vgpr).
                            Used when the address tag lives in the vgpr.
  Form-B (fold + mask):     v_add_nc_u32_e32 vT, vN, <imm>
                            v_and_b32_e32 vT, 0x3fff, vT
                            and the DS row rewritten to vT with the
                            offset dropped. Used when the DS immediate
                            itself carries >=0x4000-class span (imm>=0x4000
                            or base+imm crossing). vT = first vgpr beyond
                            the kernel's declared count (count bumped).
  group_segment_fixed_size -> 16384 where request < 16384 (both the
                            .amdhsa_kernel directive and the YAML note).
Then llvm-mc -> .o, ld.lld -shared -> candidate .co, objdump, manifest,
hashes. The entry-fixed reference is never modified.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_ROOT = os.path.abspath(os.path.join(HERE, ".."))
ROOT = os.path.abspath(os.path.join(OUT_ROOT, ".."))
sys.path.insert(0, HERE)
import p16e_lib  # noqa: E402

LLVM_MC = r"<ROCM_ROOT>\7.1\bin\llvm-mc.exe"
LD_LLD = r"<ROCM_ROOT>\7.1\bin\ld.lld.exe"
OBJDUMP = r"<ROCM_ROOT>\7.1\bin\llvm-objdump.exe"

CAND_S = os.path.join(OUT_ROOT, "gfx1030_dlssnr_candidate_e.s")
CAND_O = os.path.join(OUT_ROOT, "gfx1030_dlssnr_candidate_e.o")
CAND_CO = os.path.join(OUT_ROOT, "gfx1030_dlssnr_candidate_e.co")
CAND_DIS = os.path.join(OUT_ROOT, "disasm", "candidate_e_gfx1030_disasm.txt")
MANIFEST = os.path.join(OUT_ROOT, "patch_manifest.json")
HASHES = os.path.join(OUT_ROOT, "hashes.txt")

GSF_OLD = {
    "_Z10k_swin_varILi32ELb1EEv9VarParams": 15616,
    "_Z10k_swin_varILi32ELb0EEv9VarParams": 15632,
    "_Z10k_swin_varILi64ELb0EEv9VarParams": 15616,
    "_Z10k_swin_varILi128ELb0EEv9VarParams": 15616,
    "_Z10k_swin_varILi256ELb0EEv9VarParams": 19200,
}
GSF_NEW = 16384
# form-B temp = first vgpr beyond the kernel's declared count
TEMP = {
    "_Z10k_swin_varILi32ELb1EEv9VarParams": 102,
    "_Z10k_swin_varILi32ELb0EEv9VarParams": 100,
    "_Z10k_swin_varILi64ELb0EEv9VarParams": 126,
    "_Z10k_swin_varILi128ELb0EEv9VarParams": 126,
    "_Z10k_swin_varILi256ELb0EEv9VarParams": 143,
}
VCNT_NEW = {  # granularity-4 rounded declared counts with the temp in use
    "_Z10k_swin_varILi32ELb1EEv9VarParams": 104,
    "_Z10k_swin_varILi32ELb0EEv9VarParams": 104,
    "_Z10k_swin_varILi64ELb0EEv9VarParams": 128,
    "_Z10k_swin_varILi128ELb0EEv9VarParams": 128,
    "_Z10k_swin_varILi256ELb0EEv9VarParams": 144,
}
TAG_OF = dict((s, t) for s, t in p16e_lib.SWIN_VARIANTS)


def patch_src():
    lines = open(p16e_lib.ENT_S, encoding="utf-8",
                 errors="replace").read().splitlines(keepends=True)
    plan = json.load(open(os.path.join(OUT_ROOT, "patch_sites.json"),
                          encoding="utf-8"))
    fold_path = os.path.join(OUT_ROOT, "out", "oob_fold_sites.json")
    fold = json.load(open(fold_path, encoding="utf-8")) \
        if os.path.exists(fold_path) else {}
    manifest = {"insertions": [], "fold_forms": [], "gsf_changes": [],
                "vgpr_count_changes": []}
    sym_of = dict(p16e_lib.SWIN_VARIANTS)
    TAG_SYM = dict((t, s) for s, t in p16e_lib.SWIN_VARIANTS)
    all_ins = []
    for sym, tag in sym_of.items():
        recs = plan.get(tag, [])
        if not recs:
            continue
        fold_syms = {f["site"]: f for f in fold.get(tag, [])}
        sites = sorted(recs, key=lambda r: r["s_lines"][0]["no"])
        prev_no, prev_vgpr = None, None
        for r in sites:
            if not r["s_lines"]:
                raise SystemExit("unmapped site %s" % r["site"])
            no = r["s_lines"][0]["no"]
            av = r["addr_vgpr"]
            if av is None:
                raise SystemExit("no addr vgpr for %s" % r["site"])
            if prev_no is not None and no - prev_no <= 8 and av == prev_vgpr \
                    and r["site"] not in fold_syms:
                continue
            if r["site"] in fold_syms:
                f = fold_syms[r["site"]]
                t = TEMP[sym]
                kind = "fold"
                ilines = [
                    "\tv_add_nc_u32_e32 v%d, %d, v%d\n" % (t, f["imm"], av),
                    "\tv_and_b32_e32 v%d, 0x3fff, v%d\n" % (t, t),
                ]

                def _rw(txt, av=av, t=t):
                    is_load = ("read" in txt or "load" in txt)
                    nt = re.sub(r"offset:-?\d+", "", txt)
                    # replace the ADDR token: loads print dst first (addr =
                    # LAST vreg occurrence); stores print addr first (FIRST)
                    vr = r"\bv%d\b" % av
                    if is_load:
                        ms = list(re.finditer(vr, nt))
                        if not ms:
                            return None
                        sp = ms[-1].span()
                        nt2 = nt[:sp[0]] + "v%d" % t + nt[sp[1]:]
                    else:
                        nt2 = re.sub(vr, "v%d" % t, nt, count=1)
                    if nt2.strip() == txt.strip():
                        return None
                    return nt2
                rewrite = _rw
            else:
                kind = "reg"
                ilines = ["\tv_and_b32_e32 v%d, 0x3fff, v%d\n" % (av, av)]
                rewrite = None
            all_ins.append({"at": no, "kind": kind, "lines": ilines,
                            "site": r["site"], "tag": tag,
                            "rewrite": rewrite})
            prev_no, prev_vgpr = no, av
        manifest["insertions"].append(
            {"variant": tag, "symbol": sym,
             "count": sum(1 for x in all_ins if x["tag"] == tag),
             "fold": [x["site"] for x in all_ins
                      if x["tag"] == tag and x["kind"] == "fold"]})
    n_applied = 0
    for it in sorted(all_ins, key=lambda x: x["at"]):
        pos = it["at"] + n_applied
        target_text = lines[pos].strip()
        want = next((r["disasm"].strip() for r in plan.get(it["tag"], [])
                     if r["site"] == it["site"]), "")
        if target_text != want:
            raise SystemExit("insertion position mismatch for %s at %d: %r"
                             % (it["site"], pos, target_text))
        for ln in it["lines"]:
            lines.insert(pos, ln)
            n_applied += 1
            pos += 1
        if it["rewrite"] is not None:
            nt = it["rewrite"](lines[pos])
            if nt is None:
                raise SystemExit("fold rewrite failed for %s at %d: %r"
                                 % (it["site"], pos, lines[pos]))
            lines[pos] = nt
            manifest["fold_forms"].append(
                {"variant": it["tag"], "site": it["site"],
                 "temp_vgpr": TEMP[TAG_SYM[it["tag"]]]})
    # ---- gsf directive per kernel
    for sym, tag in sym_of.items():
        old = GSF_OLD[sym]
        if old >= GSF_NEW:
            manifest["gsf_changes"].append(
                {"variant": tag, "symbol": sym, "old": old, "new": old,
                 "note": "unchanged (>= 16384)"})
            continue
        for i, ln in enumerate(lines):
            if ln.strip() == ".amdhsa_kernel " + sym:
                g = i + 1
                while g < len(lines) and not lines[g].strip():
                    g += 1
                m = re.match(r"^(\s*\.amdhsa_group_segment_fixed_size )%d\s*$"
                             % old, lines[g].rstrip("\n"))
                if not m:
                    raise SystemExit("gsf directive mismatch %s: %r"
                                     % (sym, lines[g]))
                lines[g] = lines[g].replace(str(old), str(GSF_NEW), 1)
                break
        manifest["gsf_changes"].append(
            {"variant": tag, "symbol": sym, "old": old, "new": GSF_NEW})
    # ---- gsf + vgpr_count in the YAML note
    yaml_start = next(i for i, ln in enumerate(lines)
                      if ln.strip() == ".amdgpu_metadata")
    fold_tags = {it["tag"] for it in all_ins if it["kind"] == "fold"}
    for sym in GSF_OLD:
        old_v = GSF_OLD[sym]
        ni = next((i for i in range(yaml_start, len(lines))
                   if ('.name: "%s"' % sym) in lines[i]), None)
        if ni is None:
            raise SystemExit("YAML .name not found: " + sym)
        if old_v < GSF_NEW:
            gi = ni
            while gi > yaml_start and \
                    "group_segment_fixed_size" not in lines[gi]:
                gi -= 1
            if not re.match(r"^\s*\.group_segment_fixed_size:\s*%d\s*$"
                            % old_v, lines[gi].rstrip("\n")):
                raise SystemExit("YAML gsf not found for %s" % sym)
            lines[gi] = lines[gi].replace(str(old_v), str(GSF_NEW), 1)
        if TAG_OF[sym] in fold_tags:
            gi = ni
            while gi < len(lines) and ".vgpr_count" not in lines[gi]:
                gi += 1
            if gi >= len(lines):
                raise SystemExit("YAML vgpr_count below .name not found %s"
                                 % sym)
            m = re.match(r"^(\s*\.vgpr_count:\s*)(\d+)\s*$",
                         lines[gi].rstrip("\n"))
            if not m:
                raise SystemExit("YAML vgpr_count not found for %s" % sym)
            oldc = int(m.group(2))
            newc = VCNT_NEW[sym]
            if newc > oldc:
                lines[gi] = lines[gi].replace(str(oldc), str(newc), 1)
                manifest["vgpr_count_changes"].append(
                    {"variant": TAG_OF[sym], "symbol": sym,
                     "old": oldc, "new": newc,
                     "reason": "fold-form temp v%d in use" % TEMP[sym]})
    with open(CAND_S, "w", encoding="utf-8") as f:
        f.writelines(lines)
    return manifest


def assemble():
    res = subprocess.run(
        [LLVM_MC, "-triple=amdgcn-amd-amdhsa", "-mcpu=gfx1030",
         "-filetype=obj", CAND_S, "-o", CAND_O],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    if res.returncode != 0:
        raise SystemExit("ASSEMBLY FAILED:\n" + (res.stdout + res.stderr)[:6000])
    res = subprocess.run([LD_LLD, "-shared", "-o", CAND_CO, CAND_O],
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace")
    if res.returncode != 0:
        raise SystemExit("LINK FAILED:\n" + (res.stdout + res.stderr)[:3000])
    os.makedirs(os.path.dirname(CAND_DIS), exist_ok=True)
    res = subprocess.run([OBJDUMP, "-d", "--mcpu=gfx1030", CAND_CO],
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace")
    with open(CAND_DIS, "w", encoding="utf-8") as f:
        f.write(res.stdout)


def hashes():
    out = []
    for p in (CAND_S, CAND_O, CAND_CO, CAND_DIS):
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        out.append("%s  %s" % (h, os.path.basename(p)))
    ref_h = hashlib.sha256(open(p16e_lib.ENT_CO, "rb").read()).hexdigest()
    out.append("%s  %s (reference, unchanged)" % (ref_h,
                                                  os.path.basename(p16e_lib.ENT_CO)))
    with open(HASHES, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    return out


def main():
    manifest = patch_src()
    assemble()
    h = hashes()
    manifest["candidate_s_sha256"] = h[0].split()[0]
    manifest["candidate_o_sha256"] = h[1].split()[0]
    manifest["candidate_co_sha256"] = h[2].split()[0]
    manifest["reference_co_sha256"] = h[4].split()[0]
    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
    print("candidate module written:", CAND_CO)
    for tag in manifest["insertions"]:
        print(tag["variant"], tag["count"], "insertions |",
              len(tag["fold"]), "fold-form")
    for g in manifest["gsf_changes"]:
        print(g["variant"], g["old"], "->", g["new"])
    for v in manifest["vgpr_count_changes"]:
        print(v["variant"], "vgpr_count", v["old"], "->", v["new"])
    print("\n".join(h))


if __name__ == "__main__":
    main()
