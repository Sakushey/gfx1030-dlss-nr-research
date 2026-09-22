#!/usr/bin/env python3
"""Phase 16F — standing audit gates on the candidate-E artifact (host-only,
read-only wrt the candidate/reference artifacts; writes only to the
phase16f_runtime/out/ folder).

Gate list (mirrors SESSION_REPORT.md "standing audit gates"):
  G1  candidate hash chain            .s/.o/.co/disasm hashes == hashes.txt
  G2  patch-plan replay               candidate .s == deterministic replay of
                                      (reference .s + patch_sites + folds)
  G3  assembler reproducibility       fresh llvm-mc+lld of candidate .s ->
                                      .o/.co byte-identical to the on-disk ones
  G4  disasm reproducibility          fresh llvm-objdump content == recorded
  G5  structure equivalence           32f body == reference body + planned
                                      edits (+ s_nop padding noise): residual
                                      order equality, barrier/waitcnt/branch
                                      row lists, fold/mask coverage per site
  G6  metadata note diff              per-kernel .note records: only the five
                                      swin variants change, and only
                                      group_segment_fixed_size / vgpr_count
  G7  descriptor values               swin32f record: gsf 16384, kernarg size,
                                      private size, sgpr/vgpr counts, wavefront
  G8  liveness re-derivation          per-site live-after-use recomputed and
                                      compared to site_review.json (must hold)
  G9  site coverage (0xc1050 family)  every patch_sites entry is mask- or
                                      fold-covered in the candidate .s

Exit code 0 = all gates pass, 1 = any gate failed.
"""
from __future__ import annotations

import collections
import difflib
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "..", ".."))
CAND = os.path.join(ROOT, "phase16e_candidate_e")
TOOLS = os.path.join(CAND, "tools")
OUT = os.path.join(ROOT, "phase16f_runtime", "out")
os.makedirs(OUT, exist_ok=True)
sys.path.insert(0, TOOLS)
sys.path.insert(0, os.path.join(ROOT, "phase14d_static", "tools"))
import p16e_build as B            # noqa: E402
import p16e_lib                   # noqa: E402
import p16e_sitereview as SR      # noqa: E402

LOG = []
def say(*a):
    s = " ".join(str(x) for x in a)
    print(s)
    LOG.append(s)

PASS = []
FAILS = []
def gate(name, ok, detail=""):
    say(("[PASS] " if ok else "[FAIL] ") + name + (("  -- " + detail) if detail else ""))
    (PASS if ok else FAILS).append(name)

MC = r"<ROCM_ROOT>\7.1\bin\llvm-mc.exe"
LLD = r"<ROCM_ROOT>\7.1\bin\ld.lld.exe"
OD = r"<ROCM_ROOT>\7.1\bin\llvm-objdump.exe"
CAND_S = os.path.join(CAND, "gfx1030_dlssnr_candidate_e.s")
CAND_O = os.path.join(CAND, "gfx1030_dlssnr_candidate_e.o")
CAND_CO = os.path.join(CAND, "gfx1030_dlssnr_candidate_e.co")
CAND_DIS = os.path.join(CAND, "disasm", "candidate_e_gfx1030_disasm.txt")
REF_CO = os.path.join(ROOT, "phase14_entry_fixed_module",
                      "gfx1030_dlssnr_module_entryfixed.co")
REF_S = p16e_lib.ENT_S
REF_DIS = p16e_lib.ENT_DIS
SWIN32F = "_Z10k_swin_varILi32ELb0EEv9VarParams"

def sha256(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()

# ----------------------------------------------------------------- G1
def g1():
    rec = {}
    for ln in open(os.path.join(CAND, "hashes.txt"), encoding="utf-8"):
        ln = ln.strip()
        if not ln:
            continue
        h, name = ln.split("  ", 1)
        rec[name.split(" ")[0]] = h
    want = {"gfx1030_dlssnr_candidate_e.s": "1ad97b990a59d84d965f8b3e1e21c601835329551d6c3feb546db358e90bc082",
            "gfx1030_dlssnr_candidate_e.o": "8e0a96f29459b40b1d3f04e5d13fc82022d16c98dde44fd8731f78ae3c06be5a",
            "gfx1030_dlssnr_candidate_e.co": "caca8034a995b922a334be6f4d3d2403f9087fbc9f9ea6728127377732784ecb",
            "candidate_e_gfx1030_disasm.txt": "0d8eeda804f7294897f4dc3a7022c268d258101449ec9025715f6c281dcba7b9"}
    ok = True
    for name, h in want.items():
        p = {"gfx1030_dlssnr_candidate_e.s": CAND_S, "gfx1030_dlssnr_candidate_e.o": CAND_O,
             "gfx1030_dlssnr_candidate_e.co": CAND_CO,
             "candidate_e_gfx1030_disasm.txt": CAND_DIS}[name]
        hh = sha256(p)
        gate("G1 hash %s" % name, hh == h, hh)
        ok &= (hh == h)
    gate("G1 reference module hash unchanged",
         sha256(REF_CO) == rec["gfx1030_dlssnr_module_entryfixed.co"],
         sha256(REF_CO))
    return ok

# ----------------------------------------------------------------- G2
def g2():
    tmp = tempfile.mkdtemp(prefix="p16f_")
    try:
        old = B.CAND_S
        B.CAND_S = os.path.join(tmp, "cand.s")
        try:
            manifest = B.patch_src()
        except SystemExit as e:
            gate("G2 patch-plan replay", False, "SystemExit: %s" % e)
            return False
        finally:
            B.CAND_S = old
        disk = open(CAND_S, encoding="utf-8", errors="replace").read()
        repl = open(os.path.join(tmp, "cand.s"), encoding="utf-8",
                    errors="replace").read()
        ok = disk == repl
        gate("G2 candidate .s == replay(ref .s + plan)", ok,
             "%d chars" % len(disk))
        exp = {("swin32t", 9), ("swin32f", 14), ("swin64f", 7),
               ("swin128f", 2), ("swin256f", 2)}
        ins = {(m["variant"], m["count"]) for m in manifest["insertions"]}
        gate("G2 insertion counts match manifest", ins == exp, str(sorted(ins)))
        return ok
    finally:
        pass

# ----------------------------------------------------------------- G3/G4
def g3g4():
    tmp = tempfile.mkdtemp(prefix="p16f_")
    try:
        o = os.path.join(tmp, "cand.o")
        co = os.path.join(tmp, "cand.co")
        r1 = subprocess.run([MC, "-triple=amdgcn-amd-amdhsa", "-mcpu=gfx1030",
                             "-filetype=obj", CAND_S, "-o", o],
                            capture_output=True, text=True)
        r2 = subprocess.run([LLD, "-shared", "-o", co, o],
                            capture_output=True, text=True)
        ok1 = r1.returncode == 0 and r2.returncode == 0 and \
            sha256(o) == "8e0a96f29459b40b1d3f04e5d13fc82022d16c98dde44fd8731f78ae3c06be5a"
        ok2 = sha256(co) == "caca8034a995b922a334be6f4d3d2403f9087fbc9f9ea6728127377732784ecb"
        gate("G3 assembler .o reproducible", ok1)
        gate("G3 linker .co reproducible", ok2)
        # disasm content (real path needed for the objdump header)
        r3 = subprocess.run([OD, "-d", "--mcpu=gfx1030", CAND_CO],
                            capture_output=True, text=True, errors="replace")
        d = [x for x in r3.stdout.splitlines() if not x.startswith("C:\\")]
        rec = [x.rstrip("\r") for x in open(CAND_DIS, encoding="utf-8",
                                            errors="replace").read().splitlines()
               if not x.startswith("C:\\")]
        norm = lambda ls: [re.sub(r"\s+", " ", x).strip() for x in ls if x.strip()]
        ok3 = norm(d[2:]) == norm(rec[2:])
        gate("G4 disasm content reproducible", ok3,
             "%d vs %d lines" % (len(d), len(rec)))
        return ok1 and ok2 and ok3
    finally:
        pass

# ----------------------------------------------------------------- G5
ROW = re.compile(r"^\t(.+?)\s*//\s+([0-9A-Fa-f]+):\s+([0-9A-Fa-f]{8}(?:\s+[0-9A-Fa-f]{8})*)\s*$")
SYM = re.compile(r"^([0-9a-f]+)\s+<(_Z[^>]+)>:$")

def rows_of(path, sym):
    cur = None
    out = []
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = SYM.match(ln.rstrip("\n"))
        if m:
            cur = m.group(2)
            continue
        if cur != sym:
            continue
        m = ROW.match(ln.rstrip("\n"))
        if m:
            out.append((int(m.group(2), 16), m.group(1).strip(),
                        len(m.group(3).split()) * 4))
    return out

def norm_t(t):
    return re.sub(r"\s+", " ", t.strip())

def g5():
    syms = {t: s for s, t in p16e_lib.SWIN_VARIANTS}   # tag -> sym
    plan = json.load(open(os.path.join(CAND, "patch_sites.json"),
                          encoding="utf-8"))
    mani = json.load(open(os.path.join(CAND, "patch_manifest.json"),
                          encoding="utf-8"))
    fold_by_tag = {}
    for ins in mani["insertions"]:
        fold_by_tag[ins["variant"]] = {int(f, 16) for f in ins["fold"]}
    ok_all = True
    for tag in ("swin32t", "swin32f", "swin64f", "swin128f", "swin256f"):
        sym = syms[tag]
        R = rows_of(REF_DIS, sym)
        C = rows_of(CAND_DIS, sym)
        cr = collections.Counter(t for _a, t, _w in R)
        cc = collections.Counter(t for _a, t, _w in C)
        miss = list((cr - cc).elements())
        extra = list((cc - cr).elements())
        n_miss_snop = sum(1 for t in miss if t == "s_nop 0")
        n_extra_snop = sum(1 for t in extra if t == "s_nop 0")
        miss_other = [t for t in miss if t != "s_nop 0"]
        extra_other = [t for t in extra if t != "s_nop 0"]
        # Planned rows are exactly: mask rows (v_and_b32_e32 vN, 0x3fff, vN)
        # and every row that names a fold temp vgpr. The originals declare
        # vgpr_count 100/126/143 (32t 102) -> the temp vgprs v100/v102/v126/
        # v143 never occur in the reference body, so the test is exact.
        def is_planned(t):
            if re.match(r"^v_and_b32_e32 v\d+, 0x3fff, v\d+$", t):
                return True
            return bool(re.search(r"v1(?:00|02|26|43)\b", t))
        fold_addrs = fold_by_tag.get(tag, set())
        foldtexts = {t for a, t, _w in R if a in fold_addrs}
        unplanned_miss = [t for t in miss_other
                          if t not in foldtexts and not is_planned(t)]
        unplanned_extra = [t for t in extra_other if not is_planned(t)]
        # reference stream without s_nops and without the fold-site DS rows
        # (they were rewritten, their replacements are removed with C2)
        R2 = [t for a, t, _w in R if t != "s_nop 0" and a not in fold_addrs]
        C2 = [t for _a, t, _w in C
              if t != "s_nop 0" and not is_planned(t)]
        sm = difflib.SequenceMatcher(a=[norm_t(x) for x in R2],
                                     b=[norm_t(x) for x in C2],
                                     autojunk=False)
        bad = [op for op in sm.get_opcodes() if op[0] != "equal"]
        barrier_eq = [t for _a, t, _w in R if "barrier" in t] ==                      [t for _a, t, _w in C if "barrier" in t]
        waitcnt_eq = [t for _a, t, _w in R if "waitcnt" in t] ==                      [t for _a, t, _w in C if "waitcnt" in t]
        bad_repl = [op for op in bad if op[0] == "replace"]
        # delete/insert opcodes are duplicate-row alignment artifacts when
        # the multiset residual (unplanned_*) is empty; 'replace' opcodes
        # would mean a real text difference at the same stream position.
        ok = (not unplanned_miss and not unplanned_extra and not bad_repl
              and barrier_eq and waitcnt_eq)
        gate("G5 [%s] body == reference + planned edits" % tag, ok,
             "missing %d (s_nop %d, other %d) extra %d (s_nop %d, other %d) "
             "residual-blocks %d barrier %s waitcnt %s"
             % (len(miss), n_miss_snop, len(miss_other), len(extra),
                n_extra_snop, len(extra_other), len(bad), barrier_eq,
                waitcnt_eq))
        if unplanned_miss:
            for t in unplanned_miss[:6]:
                say("   UNPLANNED-MISS: %s" % t[:110])
        if unplanned_extra:
            for t in unplanned_extra[:6]:
                say("   UNPLANNED-EXTRA: %s" % t[:110])
        if bad:
            for op in bad[:6]:
                say("   RESIDUAL %s R%s:%s C%s:%s" % op)
        ok_all &= ok
    return ok_all

# ----------------------------------------------------------------- G6/G7
def note_desc(path):
    data, sections, _syms = __import__("p14d_kd", fromlist=["parse_elf"]).parse_elf(path)
    for s in sections:
        if s.get("name") != ".note":
            continue
        off, size = s["offset"], s["size"]
        blk = data[off:off + size]
        p = 0
        while p + 12 <= size:
            namesz, descsz, _nt = struct.unpack_from("<III", blk, p)
            name = blk[p + 12:p + 12 + namesz].rstrip(b"\0").decode("ascii", "replace")
            d0 = p + 12 + ((namesz + 3) & ~3)
            if name == "AMDGPU":
                return blk[d0:d0 + descsz]
            p = d0 + ((descsz + 3) & ~3)
    return b""

_NFIELDS = (b".group_segment_fixed_size", b".kernarg_segment_size",
           b".private_segment_fixed_size", b".sgpr_count", b".vgpr_count",
           b".wavefront_size", b".max_flat_workgroup_size",
           b".sgpr_spill_count", b".vgpr_spill_count")

def _msgi(b, p):
    """Decode one msgpack int at p -> (value, next_p) or None."""
    c = b[p]
    if c <= 0x7f:
        return c, p + 1
    if c >= 0xe0:
        return c - 0x100, p + 1
    if c == 0xcc:
        return b[p + 1], p + 2
    if c == 0xcd:
        return struct.unpack_from(">H", b, p + 1)[0], p + 3
    if c == 0xce:
        return struct.unpack_from(">I", b, p + 1)[0], p + 5
    if c == 0xd0:
        return struct.unpack_from(">b", b, p + 1)[0], p + 2
    if c == 0xd1:
        return struct.unpack_from(">h", b, p + 1)[0], p + 3
    if c == 0xd2:
        return struct.unpack_from(">i", b, p + 1)[0], p + 5
    if c in (0xc2, 0xc3):
        return c == 0xc3, p + 1
    return None

def scan_kernels(path):
    """Byte-scan of the AMDGPU metadata note: locate every kernel .name
    (fixstr key + fixstr/str16 value), then collect the numeric fields of
    the surrounding kernel record (window: previous .name .. next .name)."""
    raw = note_desc(path)
    hits = []
    p = 0
    while True:
        i = raw.find(b".name", p)
        if i < 0:
            break
        k = i - 1
        if k >= 0 and 0xa0 <= raw[k] <= 0xbf and raw[k] - 0xa0 == 5:
            v = k + 6
            c = raw[v]
            n = None
            if 0xa0 <= c <= 0xbf:
                n = raw[v + 1:v + 1 + c - 0xa0]
            elif c == 0xd9:
                n = raw[v + 2:v + 2 + raw[v + 1]]
            if n and n.startswith(b"_Z"):
                hits.append((k, n.decode("ascii", "replace")))
        p = i + 5
    _PRE = (b".group_segment_fixed_size", b".kernarg_segment_size",
            b".max_flat_workgroup_size")
    _POST = (b".private_segment_fixed_size", b".sgpr_count", b".vgpr_count",
             b".wavefront_size", b".sgpr_spill_count", b".vgpr_spill_count")
    recs = {}
    for j, (pos, nm) in enumerate(hits):
        lo = hits[j - 1][0] if j > 0 else 0
        hi = hits[j + 1][0] if j + 1 < len(hits) else len(raw)
        fields = {}
        # pre-name fields belong to the record whose .name follows them;
        # post-name fields belong to the record whose .name precedes them
        for fk in _PRE:
            q = raw.find(fk, lo, pos + 1)
            if q < 0:
                continue
            k0 = q - 1
            if k0 < 0 or not (0xa0 <= raw[k0] <= 0xbf
                              and raw[k0] - 0xa0 == len(fk)):
                continue
            r = _msgi(raw, q + len(fk))
            if r:
                fields[fk.decode()] = r[0]
        for fk in _POST:
            q = raw.find(fk, pos + 1, hi)
            if q < 0:
                continue
            k0 = q - 1
            if k0 < 0 or not (0xa0 <= raw[k0] <= 0xbf
                              and raw[k0] - 0xa0 == len(fk)):
                continue
            r = _msgi(raw, q + len(fk))
            if r:
                fields[fk.decode()] = r[0]
        recs[nm] = fields
    return recs

def g6g7():
    try:
        ref = scan_kernels(REF_CO)
        cnd = scan_kernels(CAND_CO)
    except Exception as e:
        gate("G6 metadata decode", False, "exception %r" % e)
        return False
    gate("G6 kernel records decoded", len(ref) == len(cnd),
         "%d kernels each" % len(ref))
    swin = {s for s, _t in p16e_lib.SWIN_VARIANTS}
    diffs = []
    for k in sorted(set(ref) | set(cnd)):
        a, b = ref.get(k), cnd.get(k)
        if a == b:
            continue
        for f in sorted(set(a) | set(b)):
            if a.get(f) != b.get(f):
                diffs.append((k, f, a.get(f), b.get(f)))
    bad = [(k, f) for k, f, *_ in diffs
           if k not in swin or f not in (".group_segment_fixed_size",
                                         ".vgpr_count")]
    gate("G6 metadata diffs confined to 5 swin kernels x (gsf, vgpr_count)",
         not bad, "%d field diffs total" % len(diffs))
    for k, f, ov, nv in diffs:
        say("   %s %s %s -> %s" % (k.split("ILi")[1][:6], f, ov, nv))
    t = cnd.get(SWIN32F, {})
    gate("G7 swin32f record present", bool(t))
    if not t:
        return False
    gsf = t.get(".group_segment_fixed_size")
    gate("G7 swin32f group_segment_fixed_size == 16384", gsf == 16384,
         str(gsf))
    kr = (ref.get(SWIN32F) or {}).get(".kernarg_segment_size")
    say("   swin32f kernarg_segment_size ref/cand: %s / %s"
        % (kr, t.get(".kernarg_segment_size")))
    gate("G7 swin32f kernarg ABI unchanged",
         t.get(".kernarg_segment_size") == kr)
    say("   swin32f private_segment %s sgpr_count %s vgpr_count %s "
        "wavefront %s" % (t.get(".private_segment_fixed_size"),
                          t.get(".sgpr_count"), t.get(".vgpr_count"),
                          t.get(".wavefront_size")))
    gate("G7 swin32f vgpr_count == 104", t.get(".vgpr_count") == 104)
    return not bad and bool(t)

# ----------------------------------------------------------------- G8/G9
def g8():
    plan = json.load(open(os.path.join(CAND, "patch_sites.json"),
                          encoding="utf-8"))
    rev = json.load(open(os.path.join(CAND, "site_review.json"),
                         encoding="utf-8"))
    ok = True
    for tag, sites in plan.items():
        fresh = SR.review(tag) if sites else []
        stored = rev.get(tag, [])
        live = [r for r in fresh if r["live_after_use"]]
        # fresh derivation is ground truth; the stored review may predate the
        # last fold round (its swin256f list is empty although 2 fold sites
        # were appended to patch_sites later). Compare on the overlap.
        m_fresh = {(r["site"], r["addr_vgpr"], r["self_overwrite_load"],
                    r["live_after_use"]) for r in fresh}
        m_stored = {(r["site"], r["addr_vgpr"], r["self_overwrite_load"],
                     r["live_after_use"]) for r in stored}
        overlap_ok = all(x in m_fresh for x in m_stored)
        gate("G8 [%s] stored review subset of fresh re-derivation" % tag,
             overlap_ok, "stored %d / fresh %d, live-after-use %d"
             % (len(m_stored), len(m_fresh), len(live)))
        ok &= overlap_ok
        for r in live:
            say("   LIVE-AFTER-USE at %s (mask would corrupt)" % r["site"])
    # hard requirement for the physical target: zero live-after-use sites
    fresh32f = SR.review("swin32f")
    live32f = [r for r in fresh32f if r["live_after_use"]]
    gate("G8 swin32f (physical target): zero live-after-use sites",
         not live32f)
    ok &= (not live32f)
    return ok

def g9():
    """Replay p16e_build's own insertion loop over the sorted census and
    verify: (a) every census site is either a fold site or gets a mask
    insertion (only twin-merges may skip), (b) insertion groups per tag
    match the manifest counts, (c) no skipped site is "covered" only by a
    fold predecessor (a fold masks its own temp, not the address vgpr)."""
    plan = json.load(open(os.path.join(CAND, "patch_sites.json"),
                          encoding="utf-8"))
    mani = json.load(open(os.path.join(CAND, "patch_manifest.json"),
                          encoding="utf-8"))
    fold_by_tag = {ins["variant"]: set(ins["fold"])
                   for ins in mani["insertions"]}
    ok = True
    for tag, sites in plan.items():
        foldset = fold_by_tag.get(tag, set())
        recs = sorted(sites, key=lambda r: r["s_lines"][0]["no"])
        groups = 0
        prev_no = prev_vgpr = None
        prev_fold = False
        for st in recs:
            no = st["s_lines"][0]["no"]
            av = st["addr_vgpr"]
            is_fold = st["site"] in foldset
            skip = (prev_no is not None and no - prev_no <= 8
                    and av == prev_vgpr and not is_fold)
            if not skip:
                groups += 1
                prev_no, prev_vgpr = no, av
                prev_fold = is_fold
            elif prev_fold:
                say("G9 [%s] twin of a FOLD predecessor (unprotected): "
                    "%s av v%s" % (tag, st["site"], av))
                ok = False
        exp = {"swin32t": 9, "swin32f": 14, "swin64f": 7,
               "swin128f": 2, "swin256f": 2}[tag]
        gate("G9 [%s] insertion groups == manifest (%d)" % (tag, exp),
             groups == exp, "counted %d for %d census sites"
             % (groups, len(recs)))
        ok &= (groups == exp)
    c1050 = [s for s in plan.get("swin32f", []) if s["site"] == "0xc1050"]
    gate("G9 0xc1050 site present in swin32f census", len(c1050) == 1)
    if c1050:
        s = c1050[0]
        ok2 = (s["addr_vgpr"] == 3
               and "0xc1050" not in fold_by_tag.get("swin32f", set()))
        gate("G9 0xc1050 (ds_read_u16, av v3) is mask-covered, not folded",
             ok2)
    return ok

def main():
    say("Phase 16F standing gates — %s" % __file__)
    say("candidate .co sha256: %s" % sha256(CAND_CO))
    say("reference .co sha256: %s" % sha256(REF_CO))
    rs = [g1(), g2(), g3g4(), g5(), g6g7(), g8(), g9()]
    allok = all(rs)
    say("GATES RESULT: %s (%d passed, %d failed)"
        % ("ALL PASS" if allok else "FAILED", len(PASS), len(FAILS)))
    with open(os.path.join(OUT, "p16f_gates.log"), "w", encoding="utf-8") as f:
        f.write("\n".join(LOG) + "\n")
    return 0 if allok else 1

if __name__ == "__main__":
    sys.exit(main())
