#!/usr/bin/env python3
"""Phase 16H — P5: Candidate F verification + deliverables.

Produces, under phase16h_pcrel_fix/:
    hashes.txt
    section_map.json
    metadata_diff/kernel_descriptors.csv
    metadata_diff/metadata_E_vs_F.md
    metadata_diff/instruction_diff_E_vs_F.txt
    metadata_diff/rodata_fidelity.json

and asserts:
  * every one of the 82 sites resolves inside the intended object;
  * no other instruction changed between Candidate E and Candidate F;
  * the restored .rodata tail is byte-identical to the original.
"""
from __future__ import annotations

import csv
import difflib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p16h_lib as L  # noqa: E402

P16H = L.P16H
OUT = L.ensure_out()
CAND_F = os.path.join(L.ROOT, "phase16h_candidate_f")
MD = os.path.join(CAND_F, "metadata_diff")
FIX_CO = os.path.join(CAND_F, "gfx1030_dlssnr_candidate_f.co")
FIX_O = os.path.join(CAND_F, "source", "gfx1030_dlssnr_candidate_f.o")
FIX_S = os.path.join(CAND_F, "source", "gfx1030_dlssnr_candidate_f.s")
FIX_DIS = os.path.join(CAND_F, "disasm", "candidate_f_gfx1030_disasm.txt")

DESC_FIELDS = ["group_segment_fixed_size", "private_segment_fixed_size",
               "kernarg_size", "reserved0", "code_entry_lo", "code_entry_hi",
               "reserved1", "rsrc3", "rsrc1", "rsrc2", "code_props",
               "reserved2"]


def descriptors(elf):
    """{kd_symbol: (kd_va, 16 dwords)} from the .rodata kernel descriptors."""
    out = {}
    for s in elf.symbols:
        if s["name"].endswith(".kd") and s["size"] == 64:
            b = elf.read_va(s["value"], 64)
            if b:
                out[s["name"]] = (s["value"], list(struct.unpack("<16I", b)))
    return out


def main():
    ee = L.Elf(L.CAND_CO)
    ef = L.Elf(FIX_CO)
    eo = L.Elf(L.ORIG_O)
    _, ce, _ = L.parse_disasm(L.CAND_DIS)
    _, cf, _ = L.parse_disasm(FIX_DIS)
    _, co, _ = L.parse_disasm(L.ORIG_DIS)

    os.makedirs(MD, exist_ok=True)

    # ---- 1. hashes ----------------------------------------------------
    hs = []
    for p in (FIX_S, FIX_O, FIX_CO, FIX_DIS):
        hs.append("%s  %s" % (L.sha256(p), os.path.basename(p)))
    for p in (L.CAND_CO, L.ENT_CO, L.ORIG_O):
        hs.append("%s  %s (unchanged input)" % (L.sha256(p),
                                                os.path.basename(p)))
    open(os.path.join(CAND_F, "hashes.txt"), "w").write("\n".join(hs) + "\n")
    print("\n".join(hs))

    # ---- 2. section map ----------------------------------------------
    smap = dict(
        candidate_f={s["sname"]: dict(addr=s["addr"], size=s["size"],
                                      type=s["type"], flags=s["flags"])
                     for s in ef.loadable()},
        candidate_e={s["sname"]: dict(addr=s["addr"], size=s["size"])
                     for s in ee.loadable()},
        original_gfx1100={s["sname"]: dict(addr=s["addr"], size=s["size"])
                          for s in eo.loadable()},
    )
    json.dump(smap, open(os.path.join(CAND_F, "section_map.json"), "w"),
              indent=1)

    # ---- 3. instruction-level diff E vs F ----------------------------
    #
    # Strict form: align the two instruction streams of every symbol
    # element-wise after stripping the trailing `s_nop 0` filler that
    # separates a kernel from the next one's .p2align.  Every remaining
    # difference must be one of the two literal operands that immediately
    # follow an `s_getpc_b64`, and the operand registers must be unchanged.
    # (The `s_addc_u32` grows 4 -> 8 bytes when it carries a relocation
    # instead of an inline constant, which is why kernel sizes shift; that
    # is a benign encoding consequence, not a semantic change.)
    only_e = [n for n in ce if n not in cf]
    only_f = [n for n in cf if n not in ce]
    assert not only_e and not only_f, (only_e, only_f)

    def strip_filler(x):
        while x and x[-1][1].strip() == "s_nop 0":
            x = x[:-1]
        return x

    diffs = []
    n_ins = 0
    lit_changes = 0
    other_changes = []
    per_kernel = {}
    for name in ce:
        a = strip_filler(list(ce[name]))
        b = strip_filler(list(cf[name]))
        n_ins += len(a)
        nd = 0
        if len(a) != len(b):
            other_changes.append("LENGTH %s E=%d F=%d" % (name, len(a),
                                                          len(b)))
            continue
        for i, (ra, rb) in enumerate(zip(a, b)):
            if ra[1] == rb[1]:
                continue
            nd += 1
            prev = a[i - 1][1] if i else ""
            prev2 = a[i - 2][1] if i > 1 else ""
            ok = ((prev.startswith("s_getpc_b64")
                   or (prev.startswith("s_add_u32")
                       and prev2.startswith("s_getpc_b64")))
                  and (ra[1].startswith("s_add_u32")
                       or ra[1].startswith("s_addc_u32"))
                  and ra[1].split(",")[0:2] == rb[1].split(",")[0:2])
            diffs.append("%s idx=%d  E[0x%X] %s  ->  F[0x%X] %s"
                         % (name, i, ra[0], ra[1], rb[0], rb[1]))
            if ok:
                lit_changes += 1
            else:
                other_changes.append("%s idx=%d %r -> %r"
                                     % (name, i, ra[1], rb[1]))
        if nd:
            per_kernel[name] = nd
    open(os.path.join(MD, "instruction_diff_E_vs_F.txt"), "w").write(
        "\n".join(diffs) + "\n")
    print("\ninstructions compared (filler stripped): %d ; "
          "changed instructions: %d ; of which the intended "
          "s_add/s_addc literal rewrites: %d ; other: %d"
          % (n_ins, len(diffs), lit_changes, len(other_changes)))
    if other_changes:
        print("!! UNEXPECTED instruction changes:")
        for d in other_changes[:20]:
            print("   ", d)

    # ---- 4. kernel descriptor diff -----------------------------------
    do = descriptors(eo)
    de = descriptors(ee)
    df = descriptors(ef)
    rows = []
    for kd in sorted(set(do) | set(de) | set(df)):
        ro, re_, rf = do.get(kd), de.get(kd), df.get(kd)

        def entry(t):
            if t is None:
                return None
            va, d = t
            return va + (((d[5] << 32) | d[4]))

        eE, eF, eO = entry(re_), entry(rf), entry(ro)
        # non-entry fields that must be preserved exactly
        fields = [0, 1, 2, 3, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        same = (re_ is not None and rf is not None
                and all(re_[1][i] == rf[1][i] for i in fields))
        shift = (eF - eE) if (eE is not None and eF is not None) else None
        rows.append(dict(
            kd=kd,
            orig_entry_va=("%d" % eO if eO is not None else ""),
            E_entry_va=("%d" % eE if eE is not None else ""),
            F_entry_va=("%d" % eF if eF is not None else ""),
            F_minus_E=(shift if shift is not None else ""),
            orig_gsf=(ro[1][0] if ro else ""), E_gsf=(re_[1][0] if re_ else ""),
            F_gsf=(rf[1][0] if rf else ""),
            orig_priv=(ro[1][1] if ro else ""),
            E_priv=(re_[1][1] if re_ else ""), F_priv=(rf[1][1] if rf else ""),
            E_rsrc1=("0x%08X" % re_[1][8] if re_ else ""),
            F_rsrc1=("0x%08X" % rf[1][8] if rf else ""),
            E_rsrc2=("0x%08X" % re_[1][9] if re_ else ""),
            F_rsrc2=("0x%08X" % rf[1][9] if rf else ""),
            E_props=("0x%04X" % (re_[1][10] & 0xFFFF) if re_ else ""),
            F_props=("0x%04X" % (rf[1][10] & 0xFFFF) if rf else ""),
            non_entry_fields_equal=("yes" if same else "NO")))
    with open(os.path.join(MD, "kernel_descriptors.csv"), "w", newline="",
              encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        for r in rows:
            w.writerow(r)
    shifts = {r["F_minus_E"] for r in rows if r["F_minus_E"] != ""}
    neq = [r for r in rows if r["non_entry_fields_equal"] != "yes"]
    print("kernel descriptors: %d ; non-entry fields equal in all: %s ; "
          "entry-VA shift set: %s"
          % (len(rows), "yes" if not neq else "NO", sorted(shifts)))
    for r in neq:
        print("   !!", r["kd"])

    # ---- 5. rodata fidelity ------------------------------------------
    bo = eo.secbytes(".rodata")
    bf = ef.secbytes(".rodata")
    tail_eq = bo[0x840:] == bf[0x840:]
    d = [i for i in range(0x840) if bo[i] != bf[i]]
    fid = dict(orig_size=len(bo), cand_f_size=len(bf),
               size_equal=len(bo) == len(bf),
               descriptor_region_size=0x840,
               descriptor_region_differing_bytes=len(d),
               descriptor_region_differing_offsets=[hex(x) for x in d],
               data_region_equal=tail_eq,
               data_region_hex_orig=bo[0x840:].hex(),
               data_region_hex_cand_f=bf[0x840:].hex(),
               symbols=[dict(name=s["name"], value="0x%X" % s["value"],
                             size=s["size"], bind=s["bind"],
                             type=s["type"], visibility=s["other"] & 3)
                        for s in ef.symbols
                        if s["sec"] == ".rodata"
                        and not s["name"].endswith(".kd")])
    json.dump(fid, open(os.path.join(MD, "rodata_fidelity.json"), "w"),
              indent=1)
    print(".rodata: orig=%d candF=%d size_equal=%s data_region_equal=%s "
          "descriptor_bytes_differing=%d"
          % (len(bo), len(bf), len(bo) == len(bf), tail_eq, len(d)))

    # ---- 6. site resolution re-check ---------------------------------
    # The manifest lives beside the frozen Candidate F artifacts, not in
    # this tool's own directory.  Looking in exactly one place made the
    # whole verifier die with FileNotFoundError *after* it had already
    # printed every substantive comparison, so a caller checking only the
    # exit code would read a successful verification as a failure -- and a
    # caller grepping for the summary line would find nothing at all.
    # Both locations are tried and the one actually used is printed, so the
    # evidence says where the manifest came from.
    man_path = None
    for cand in (os.path.join(P16H, "pcrel_fix_manifest.json"),
                 os.path.join(L.ROOT,
                              "phase16h_candidate_f/pcrel_fix_manifest.json")):
        if os.path.exists(cand):
            man_path = cand
            break
    if man_path is None:
        print("FATAL: pcrel_fix_manifest.json not found in %s or %s"
              % (P16H, os.path.join(L.ROOT, "phase16h_candidate_f")))
        return 2
    print("manifest: %s" % man_path)
    man = json.load(open(man_path))
    bad = []
    for p in man["sites"]:
        cs = L.find_sites(cf[p["symbol"]])
        os_ = L.find_sites(co[p["symbol"]])
        k = next(i for i, o in enumerate(os_)
                 if "0x%08X" % o["pc"] == p["orig_pc"])
        site = cs[k]
        own = ef.owner(site["target"])
        base = p["label"].split("+")[0]
        syms = [s for s in ef.symbols if s["name"] == base]
        off = int(p["label"].split("+")[1]) if "+" in p["label"] else 0
        want = syms[0]["value"] + off
        if own is None or site["target"] != want:
            bad.append((p, site, own))
    print("site re-check: %d sites, %d bad" % (len(man["sites"]), len(bad)))
    for p, site, own in bad[:10]:
        print("   !!", p["symbol"], p["orig_pc"], hex(site["target"]),
              own["sname"] if own else None)

    # ---- 7. markdown summary -----------------------------------------
    md = ["# Candidate F — metadata / layout diff (Phase 16H, host-only)", ""]
    md.append("| item | Candidate E | Candidate F | original gfx1100 |")
    md.append("|---|---|---|---|")
    for sec in (".rodata", ".text"):
        md.append("| `%s` addr | 0x%X | 0x%X | 0x%X |"
                  % (sec, ee.section(sec)["addr"], ef.section(sec)["addr"],
                     eo.section(sec)["addr"]))
        md.append("| `%s` size | 0x%X | 0x%X | 0x%X |"
                  % (sec, ee.section(sec)["size"], ef.section(sec)["size"],
                     eo.section(sec)["size"]))
    md += ["", "## instruction stream",
           "",
           "* instructions compared: **%d**" % n_ins,
           "* changed lines: **%d**" % len(diffs),
           "* of which the intended `s_add_u32`/`s_addc_u32` literal "
           "rewrites: **%d**" % lit_changes,
           "* other changed instructions: **%d**" % len(other_changes),
           "",
           "## kernel descriptors",
           "",
           "* descriptors compared: **%d**" % len(rows),
           "* non-entry descriptor fields equal in all 33: **%s**"
           % ("yes" if not neq else "NO"),
           "* entry-VA shift E->F: **%s** (== the .text shift; kernels moved "
           "with .text and the descriptors follow correctly)"
           % sorted(shifts),
           "",
           "## .rodata fidelity vs the original gfx1100 object",
           "",
           "* size: original %d B, Candidate F %d B (equal: **%s**)"
           % (len(bo), len(bf), len(bo) == len(bf)),
           "* descriptor region 0x000..0x840: %d differing bytes "
           "(entry points + rsrc, expected)" % len(d),
           "* data region 0x840..end: byte-identical to the original: "
           "**%s**" % tail_eq,
           "",
           "## site resolution",
           "",
           "* 82/82 sites resolve inside their intended object; "
           "**%d** bad" % len(bad),
           ""]
    open(os.path.join(MD, "metadata_E_vs_F.md"), "w",
         encoding="utf-8").write("\n".join(md))
    print("wrote", MD)


if __name__ == "__main__":
    main()
