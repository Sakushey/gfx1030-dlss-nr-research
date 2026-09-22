#!/usr/bin/env python3
"""Phase 16H — P4/P5: the layout-safe PC-relative correction.

Root cause (Phase 16G, re-derived here from the binaries):

  The translated assembly carries the ORIGINAL compiler's PC-relative
  literal deltas verbatim.  `llvm-mc` emits them as immediates and `ld.lld`
  never fixes them, so they are only correct when the rebuild reproduces
  the original instruction-to-target distance.  It does not.

Fix (this is the AMDGPU PC-relative model, not a generic one -- see
`TargetProfile` below; the relocation spelling and the addend are both
profile properties):

  Replace each
        s_getpc_b64 sN:M
        s_add_u32  sN, sN, <stale literal>
        s_addc_u32 sM, sM, <stale literal>
  with
        s_getpc_b64 sN:M
        s_add_u32  sN, sN, SYM@rel32@lo+4
        s_addc_u32 sM, sM, SYM@rel32@hi+4

  SYM is resolved from the ORIGINAL object's own symbol table, so the
  target is named, not numbered.  R_AMDGPU_REL32_LO/HI are then evaluated by
  the linker against the FINAL layout, so the fix survives any future
  change in instruction count or section size.

  The `+4` addend compensates for the linker's P being the address of the
  literal itself rather than of the s_getpc_b64 (verified empirically:
  without it every site lands exactly 4 bytes short).

ARCHITECTURE DEPENDENCE (Phase 16K K15/K16)
-------------------------------------------
This file previously described itself as "generic, not gfx1030-specific".
That was false in four places, and each is now read from a `TargetProfile`
instead of being written inline:

  * the assembler triple and `-mcpu`                 -> PROFILE.triple / .mcpu
  * the relocation spelling `@rel32@lo` / `@rel32@hi` -> PROFILE.pcrel_reloc_lo/hi
  * the `+4` addend                                   -> PROFILE.pcrel_addend
  * which mnemonics a site scan may step over while
    still calling a getpc/add/addc triple "adjacent"  -> PROFILE.pcrel_filler_mnemonics

The last one is the subtle one.  The scan used to tolerate up to two
intervening instructions of ANY kind, unchecked, and its comment described
that as "tolerate one s_nop" -- so the comment, the code and the
architecture all disagreed.

MEASURED on the data this project actually has: at all 82 sites of the
gfx1030 candidate .s AND all 82 sites of the gfx1100 original
disassembly, the gap is 0 -- nothing sits between the `s_getpc_b64` and
its `s_add_u32`.  The tolerance therefore never fires today.  It is a dead
allowance inside the scan that decides whether a PC-relative fix is
applied, which is exactly the kind of thing that should be declared and
bounded rather than left open.  (The original module does contain 9 845
`s_delay_alu` and 1 102 `s_nop`, just never at one of these sites; whether
a filler can appear there is untested.)

The scan now asks the profile, and raises rather than silently stepping
over a mnemonic the profile did not authorise.

The profile is resolved from phase16k_pretest/k15_target_profile/.  If it
cannot be found this module FAILS -- it does not fall back to the values
above, because a fallback is how a hidden assumption survives a refactor.

Secondary defect fixed in the same pass (same root cause -- the .s emitter
dropped every non-descriptor `.rodata` object):

  g_e4m3_lut            (GLOBAL, PROTECTED, 512 B, all zero)
  _ZN12DlssNrEngine2SHE (GLOBAL, PROTECTED,  32 B)
  D3D11_DEFAULT         (WEAK,   PROTECTED,   1 B)
  D3D11_VIDEO_DEFAULT   (WEAK,   PROTECTED,   1 B)

  These four objects are present in the original gfx1100 code object's
  .rodata and absent from the translated module.  g_e4m3_lut is the object
  the 79 .rodata PC-relative sites address, so its restoration is required
  by the PC-relative fix itself.

Never writes to Candidate E, the reference module, or any Phase-16E/F/G
artefact.  Host-only: assembles and links, never executes.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p16h_lib as L  # noqa: E402

# ---- the target profile --------------------------------------------------
# Every architecture-dependent fact this translator used to hard-code now
# comes from here.  Resolved by explicit path; a missing profile is a hard
# failure, never a silent fallback to an inline default.
_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "..", ".."))
_PROFILE_DIR = os.path.join(_ROOT, "phase16k_pretest", "k15_target_profile")
if not os.path.exists(os.path.join(_PROFILE_DIR, "target_profile.py")):
    raise SystemExit(
        "translator_pcrel_fix: TargetProfile not found at %s.  Refusing to "
        "translate with inline architecture constants." % _PROFILE_DIR)
sys.path.insert(0, _PROFILE_DIR)
import target_profile as TP  # noqa: E402

# The target of THIS translation: gfx1030.  Named, not implied.
TARGET_PROFILE_NAME = "gfx1030"
PROFILE = TP.profile_for(TARGET_PROFILE_NAME)

# The SOURCE architecture the original module was compiled for.  The site
# scan runs over the original's disassembly too, and its adjacency rules
# are the original's, not the target's.
SOURCE_PROFILE = TP.profile_for("gfx1100")

LLVM_MC = r"<ROCM_ROOT>\7.1\bin\llvm-mc.exe"
LD_LLD = r"<ROCM_ROOT>\7.1\bin\ld.lld.exe"
OBJDUMP = r"<ROCM_ROOT>\7.1\bin\llvm-objdump.exe"

P16H = L.P16H
OUT = L.ensure_out()

# Candidate F is built from CANDIDATE E's own assembly, never from the
# entry-fixed reference: Candidate F = Candidate E + PC-relative correction.
BASE_S = os.path.join(L.ROOT, "phase16e_candidate_e",
                      "gfx1030_dlssnr_candidate_e.s")

# Deliverable module directory (brief: phase16h_candidate_f/).
CAND_F = os.path.join(L.ROOT, "phase16h_candidate_f")

FIX_S = os.path.join(CAND_F, "source", "gfx1030_dlssnr_candidate_f.s")
FIX_O = os.path.join(CAND_F, "source", "gfx1030_dlssnr_candidate_f.o")
FIX_CO = os.path.join(CAND_F, "gfx1030_dlssnr_candidate_f.co")
FIX_DIS = os.path.join(CAND_F, "disasm", "candidate_f_gfx1030_disasm.txt")

ADD_RE = re.compile(r"^(\s*s_add_u32\s+)(s\d+)(\s*,\s*)(s\d+)(\s*,\s*)"
                    r"(-?(?:0x[0-9A-Fa-f]+|\d+))\s*$")
ADDC_RE = re.compile(r"^(\s*s_addc_u32\s+)(s\d+)(\s*,\s*)(s\d+)(\s*,\s*)"
                     r"(-?(?:0x[0-9A-Fa-f]+|\d+))\s*$")
GETPC_RE = re.compile(r"^\s*s_getpc_b64\s+(s\[\d+:\d+\]|s\d+)\s*$")

# ---- the four .rodata objects the .s emitter dropped ---------------------
RESTORED = [
    dict(name="g_e4m3_lut", bind="globl", size=512, align=6,
         body=["\t.zero 512\n"]),
    dict(name="_ZN12DlssNrEngine2SHE", bind="globl", size=32, align=5,
         body=["\t.zero 8\n", "\t.long -4\n", "\t.long -4\n", "\t.long -4\n",
               "\t.zero 8\n", "\t.long -4\n"]),
    dict(name="D3D11_DEFAULT", bind="weak", size=1, align=0,
         body=["\t.byte 0\n"]),
    dict(name="D3D11_VIDEO_DEFAULT", bind="weak", size=1, align=0,
         body=["\t.byte 0\n"]),
]


# --------------------------------------------------------------------------
def sym_for_target(elf, va):
    """Resolve an original VA to `name` or `name+off` using the object's
    own symbol table (generic -- no hard-coded addresses)."""
    best = None
    for s in elf.symbols:
        if s["type"] not in (1, 2) or not s["value"]:
            continue
        if s["value"] <= va and (best is None or s["value"] > best["value"]):
            best = s
    if best is None:
        return None, None
    if best["value"] == va:
        return best["name"], 0
    if best["size"] and va < best["value"] + best["size"]:
        return best["name"], va - best["value"]
    # nearest preceding symbol, outside its declared size
    return best["name"], va - best["value"]


def kernel_spans(lines):
    """{symbol: (first_insn_line, end_line)} for the .s."""
    out = {}
    starts = []
    for i, ln in enumerate(lines):
        t = ln.strip()
        if t.endswith(":") and not t.startswith(".L") and t.startswith("_Z"):
            starts.append((i, t[:-1]))
    for k, (i, name) in enumerate(starts):
        end = starts[k + 1][0] if k + 1 < len(starts) else len(lines)
        out[name] = (i + 1, end)
    return out


def main():
    o_order, o_bodies, _ = L.parse_disasm(L.ORIG_DIS)
    eo = L.Elf(L.ORIG_O)

    lines = open(BASE_S, encoding="utf-8", errors="replace").readlines()
    spans = kernel_spans(lines)
    print("base assembly:", os.path.relpath(BASE_S, L.ROOT))

    # ---- locate every site in the .s, per symbol ----------------------
    # Whether a line may sit between `s_getpc_b64` and its `s_add_u32` is an
    # ARCHITECTURE fact, not a parsing detail.  Measured on this data the
    # gap is 0 everywhere, so the allowance never fires -- but it is the
    # allowance that decides whether a PC-relative fix is applied, so ask
    # the profile rather than assume.
    s_sites = {}          # symbol -> [(getpc_line, add_line, addc_line)]
    n_filler_skips = 0
    for name, (a, b) in spans.items():
        cur = []
        i = a
        while i < b:
            m = GETPC_RE.match(lines[i])
            if m:
                j = i + 1
                add = addc = None
                skipped = []
                while j < min(i + 5, b):
                    if ADD_RE.match(lines[j]):
                        add = j
                    elif ADDC_RE.match(lines[j]) and add is not None:
                        addc = j
                        break
                    elif add is None:
                        skipped.append(j)
                    j += 1
                for sj in skipped:
                    text = lines[sj].strip()
                    if not text:
                        continue        # not an instruction; not a filler
                    mn = text.split(None, 1)[0]
                    if not PROFILE.may_skip_in_pcrel_scan(mn):
                        raise SystemExit(
                            "site %s:%d: %r sits between s_getpc_b64 and its "
                            "s_add_u32, but profile %s does not list it as a "
                            "permitted filler (%s).  Refusing to guess "
                            "whether this is a PC-relative site."
                            % (name, i + 1, mn, PROFILE.name,
                               ", ".join(PROFILE.pcrel_filler_mnemonics)))
                    n_filler_skips += 1
                if add is None or addc is None:
                    raise SystemExit("incomplete site at %s:%d" % (name, i + 1))
                cur.append((i, add, addc))
                i = addc + 1
                continue
            i += 1
        if cur:
            s_sites[name] = cur

    total_s = sum(len(v) for v in s_sites.values())
    # The ORIGINAL disassembly is gfx1100: scan it with the gfx1100 profile.
    # Its filler set is a superset of the target's (it admits the
    # `s_delay_alu` this target does not have), so a source listing that
    # did place a scheduling token at a site is scanned under the rules of
    # the architecture that produced it, not the target's.
    total_o = sum(len(L.find_sites(v, profile=SOURCE_PROFILE))
                  for v in o_bodies.values())
    print("sites: .s=%d  original disasm=%d" % (total_s, total_o))
    if total_s != total_o:
        raise SystemExit("site count mismatch")

    # ---- build the rewrite plan ---------------------------------------
    plan = []
    per_label = {}
    for name, sites in s_sites.items():
        o_sites = L.find_sites(o_bodies[name], profile=SOURCE_PROFILE)
        if len(o_sites) != len(sites):
            raise SystemExit("per-symbol mismatch %s: %d vs %d"
                             % (name, len(o_sites), len(sites)))
        for (gl, al, cl), osite in zip(sites, o_sites):
            # cross-check: the .s literal must equal the original literal
            m = ADD_RE.match(lines[al])
            if int(m.group(6), 0) & 0xFFFFFFFF != int(osite["lo"], 16):
                raise SystemExit("literal drift at %s:%d" % (name, al + 1))
            tgt = osite["target"]
            sym, off = sym_for_target(eo, tgt)
            if sym is None:
                raise SystemExit("no symbol for target 0x%X (site %s 0x%X)"
                                 % (tgt, name, osite["pc"]))
            label = sym if off == 0 else "%s+%d" % (sym, off)
            plan.append(dict(symbol=name, s_line_getpc=gl + 1,
                             s_line_add=al + 1, s_line_addc=cl + 1,
                             orig_pc="0x%08X" % osite["pc"],
                             orig_target="0x%X" % tgt, label=label,
                             old_lo=osite["lo"], old_hi=osite["hi"]))
            per_label[label] = per_label.get(label, 0) + 1

    print("distinct labels:", per_label)

    # ---- apply the rewrites -------------------------------------------
    nfix = 0
    for p in plan:
        al, cl = p["s_line_add"] - 1, p["s_line_addc"] - 1
        ma = ADD_RE.match(lines[al])
        mc = ADDC_RE.match(lines[cl])
        # The relocation spelling and the addend come from the profile.
        # `pcrel_expr("lo")` is "@rel32@lo+4" for this target.
        lines[al] = "%s%s%s%s%s%s%s\n" % (
            ma.group(1), ma.group(2), ma.group(3), ma.group(4),
            ma.group(5), p["label"], PROFILE.pcrel_expr("lo"))
        lines[cl] = "%s%s%s%s%s%s%s\n" % (
            mc.group(1), mc.group(2), mc.group(3), mc.group(4),
            mc.group(5), p["label"], PROFILE.pcrel_expr("hi"))
        nfix += 1
    print("rewrote %d sites (%d filler instruction(s) stepped over per "
          "profile %s)" % (nfix, n_filler_skips, PROFILE.name))

    # ---- append the dropped .rodata objects ---------------------------
    # Whether the .s emitter drops non-descriptor .rodata objects, and what
    # to do about it, is a property of the toolchain that produced the .s --
    # i.e. of the target profile -- not a property of "the translator".
    if PROFILE.dropped_rodata_policy != "restore-from-original-symtab":
        raise SystemExit(
            "profile %s declares dropped_rodata_policy=%r, which this "
            "translator does not implement.  Refusing to emit a module "
            "whose .rodata contract is unknown."
            % (PROFILE.name, PROFILE.dropped_rodata_policy))
    last_end = max(i for i, ln in enumerate(lines)
                   if ln.strip() == ".end_amdhsa_kernel")
    block = ['\t.section .rodata,"a",@progbits\n']
    for o in RESTORED:
        if o["align"]:
            block.append("\t.p2align %d, 0x0\n" % o["align"])
        block.append("\t.%s\t%s\n" % (o["bind"], o["name"]))
        block.append("\t.protected\t%s\n" % o["name"])
        block.append("\t.type\t%s,@object\n" % o["name"])
        block.append("\t.size\t%s, %d\n" % (o["name"], o["size"]))
        block.append("%s:\n" % o["name"])
        block.extend(o["body"])
    block.append("\t.text\n")
    lines[last_end + 1:last_end + 1] = block
    print("appended %d .rodata objects after .s line %d"
          % (len(RESTORED), last_end + 1))

    # ---- identity guard ----------------------------------------------
    # The emitted document must name exactly the architecture this profile
    # is.  A gfx1030 module is never stamped gfx1031/gfx1032 -- enforced
    # here rather than remembered.
    seen_arch = PROFILE.guard_arch_strings("".join(lines), FIX_S)
    print("architecture strings in the emitted .s: %s" % seen_arch)

    os.makedirs(os.path.dirname(FIX_S), exist_ok=True)
    os.makedirs(os.path.dirname(FIX_DIS), exist_ok=True)
    with open(FIX_S, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    # ---- assemble / link / disassemble --------------------------------
    r = subprocess.run([LLVM_MC, "-triple=" + PROFILE.triple,
                        "-mcpu=" + PROFILE.mcpu,
                        "-filetype=obj", FIX_S, "-o", FIX_O],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    if r.returncode:
        raise SystemExit("ASSEMBLY FAILED:\n" + (r.stdout + r.stderr)[:8000])
    r = subprocess.run([LD_LLD, "-shared", "-o", FIX_CO, FIX_O],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    if r.returncode:
        raise SystemExit("LINK FAILED:\n" + (r.stdout + r.stderr)[:8000])
    r = subprocess.run([OBJDUMP, "-d", "--mcpu=" + PROFILE.mcpu, FIX_CO],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    open(FIX_DIS, "w", encoding="utf-8").write(r.stdout)

    # ---- verify -------------------------------------------------------
    ec = L.Elf(FIX_CO)
    _co, cb, _cs = L.parse_disasm(FIX_DIS)
    report = []
    bad = 0
    for p in plan:
        cs = L.find_sites(cb[p["symbol"]], profile=PROFILE)
        o_sites = L.find_sites(o_bodies[p["symbol"]], profile=SOURCE_PROFILE)
        k = next(i for i, o in enumerate(o_sites)
                 if "0x%08X" % o["pc"] == p["orig_pc"])
        site = cs[k]
        own = ec.owner(site["target"]) if site["complete"] else None
        want = ec.owner(int(p["orig_target"], 16))  # not meaningful; see below
        rep = dict(symbol=p["symbol"], label=p["label"],
                   orig_pc=p["orig_pc"], orig_target=p["orig_target"],
                   new_cand_pc="0x%08X" % site["pc"],
                   new_target=("0x%016X" % site["target"]
                               if site["complete"] else None),
                   new_section=(own["sname"] if own else None),
                   inside=bool(own))
        report.append(rep)
        if not own:
            bad += 1
    print("sites resolving inside a section: %d / %d (outside: %d)"
          % (len(report) - bad, len(report), bad))

    # per-label: does every site with this label land in the object?
    obj_ok = {}
    for p, rep in zip(plan, report):
        base = p["label"].split("+")[0]
        syms = [s for s in ec.symbols if s["name"] == base]
        if not syms:
            obj_ok.setdefault(base, []).append(("MISSING_SYMBOL", rep))
            continue
        v = syms[0]["value"]
        off = int(p["label"].split("+")[1]) if "+" in p["label"] else 0
        want = v + off
        got = int(rep["new_target"], 16)
        obj_ok.setdefault(base, []).append(
            ("OK" if got == want else "MISMATCH want=0x%X got=0x%X"
             % (want, got), rep))

    print("\nper-object resolution:")
    for base, rs in sorted(obj_ok.items()):
        st = [r[0] for r in rs]
        nok = sum(1 for x in st if x == "OK")
        syms = [s for s in ec.symbols if s["name"] == base]
        print("  %-44s n=%-3d ok=%-3d addr=%s" %
              (base, len(rs), nok,
               ("0x%08X" % syms[0]["value"]) if syms else "ABSENT"))
        for x, rep in rs:
            if x != "OK":
                print("      !! %s  %s" % (x, rep["symbol"]))

    man = dict(
        phase="16H", kind="pcrel_fix_manifest",
        method=("symbolic R_AMDGPU_REL32_LO/HI relocations emitted by "
                "llvm-mc and resolved by ld.lld against the final layout; "
                "label resolved from the ORIGINAL object's symbol table"),
        # Phase 16K K15/K16: the manifest now names the profile that
        # produced it, so a reader can tell WHICH architecture's facts
        # (relocation spelling, addend, adjacency rule, .rodata policy)
        # were in force.  Values are unchanged from the frozen run.
        target_profile=PROFILE.name,
        target_arch=PROFILE.target_string,
        source_profile=SOURCE_PROFILE.name,
        reloc_spelling={"lo": PROFILE.pcrel_expr("lo"),
                        "hi": PROFILE.pcrel_expr("hi")},
        reloc_addend="+%d (linker P is the literal's own address)"
                     % PROFILE.pcrel_addend,
        pcrel_filler_mnemonics=list(PROFILE.pcrel_filler_mnemonics),
        n_filler_skips=n_filler_skips,
        n_sites=len(plan),
        n_rewritten=nfix,
        labels=per_label,
        restored_rodata_objects=[dict(name=o["name"], bind=o["bind"],
                                      size=o["size"]) for o in RESTORED],
        per_object={k: dict(n=len(v),
                            ok=sum(1 for x, _ in v if x == "OK"))
                    for k, v in obj_ok.items()},
        sites=plan,
        resolution=report,
    )
    json.dump(man, open(os.path.join(CAND_F, "pcrel_fix_manifest.json"), "w"),
              indent=1)
    print("\nwrote", os.path.join(CAND_F, "pcrel_fix_manifest.json"))
    print("candidate F:", FIX_CO)


if __name__ == "__main__":
    main()
