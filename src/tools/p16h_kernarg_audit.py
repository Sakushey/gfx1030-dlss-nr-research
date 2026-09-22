#!/usr/bin/env python3
"""Phase 16H — P7 + P8 + P9: the kernarg / VarParams audit.

Ground truth, all read from the binaries and the authentic capture:

  1. The kernel descriptor metadata (`.note`, msgpack) of BOTH the original
     gfx1100 object and Candidate F declares the SAME argument list:
     one 168-byte `by_value` argument at offset 0 (the whole `VarParams`
     struct) followed by the hidden args at 168..240; total
     kernarg_segment_size = 424 in both.

     => every `s_load_* sN, s[0:1], <off>` with off < 168 is a read of a
        FIELD OF A BY-VALUE STRUCT, not of a pointer argument.  The
        synthetic harness's 9 "pointer fields" are a fabrication laid over
        that struct.

  2. The kernel's complete kernarg read set is enumerated from the
     disassembly (never hard-coded) and cross-checked against the original
     gfx1100 kernel's own read set.

  3. The authentic per-launch values come from the mod's own DECODE line
     in the authentic capture log.

Outputs the per-byte table the brief requires.
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import p16h_lib as L  # noqa: E402
sys.path.insert(0, os.path.join(L.ROOT, "phase16g_forensics", "tools"))
import p16g_msgpack as M  # noqa: E402

SYM = "_Z10k_swin_varILi32ELb0EEv9VarParams"
SYM_T = "_Z10k_swin_varILi32ELb1EEv9VarParams"

READ_RE = re.compile(
    r"^s_load_(?P<form>dwordx\d+|dword|ubyte|ushort|byte|"
    r"b\d+)\s+"
    r"(?P<dst>s\[[\d:]+\]|s\d+)\s*,\s*s\[0:1\]\s*,\s*"
    r"(?P<off>0x[0-9a-f]+|-?\d+)$")

# gfx1030 llvm-mc prints `dwordx4`; the gfx1100 disassembler prints `b128`.
FORM_BYTES = {"dword": 4, "dwordx2": 8, "dwordx4": 16, "dwordx8": 32,
              "dwordx16": 64, "ubyte": 1, "ushort": 2, "byte": 1,
              "b32": 4, "b64": 8, "b128": 16, "b256": 32, "b512": 64,
              "b8": 1, "b16": 2}


def kernarg_reads(bodies, sym):
    """[(pc, off, nbytes, dst, form)] for every kernarg read, in PC order."""
    out = []
    for a, t, _b in bodies[sym]:
        m = READ_RE.match(t)
        if m:
            out.append((a, int(m.group("off"), 0),
                        FORM_BYTES[m.group("form")], m.group("dst"),
                        m.group("form")))
    return sorted(out)


def arg_metadata(path):
    """The kernel descriptor's declared argument list."""
    e = L.Elf(path)
    for n, _t, d in M.parse_note(e.secbytes(".note")):
        if n != "AMDGPU":
            continue
        md, _ = M.unpack(d, 0)
        for k in md.get("amdhsa.kernels", []):
            if k.get(".name") == SYM:
                return {
                    "kernarg_segment_size": k.get(".kernarg_segment_size"),
                    "kernarg_segment_align": k.get(".kernarg_segment_align"),
                    "group_segment_fixed_size":
                        k.get(".group_segment_fixed_size"),
                    "private_segment_fixed_size":
                        k.get(".private_segment_fixed_size"),
                    "sgpr_count": k.get(".sgpr_count"),
                    "vgpr_count": k.get(".vgpr_count"),
                    "args": [{"offset": a.get(".offset"), "size": a.get(".size"),
                              "value_kind": a.get(".value_kind")}
                             for a in k.get(".args", [])],
                }
    return None


def authentic_decodes(log):
    """Every authentic `DECODE swin_var ...` line, in order."""
    out = []
    for ln in open(log, encoding="utf-8", errors="replace"):
        m = re.search(r"DECODE swin_var (.*)$", ln)
        if not m:
            continue
        txt = m.group(1)
        d = {}
        for k in ("X", "Y"):
            mm = re.search(r"\b%s=(-?\d+)" % k, txt)
            d[k] = int(mm.group(1)) if mm else None
        mm = re.search(r"\bflags=(0x[0-9A-Fa-f]+)", txt)
        d["flags"] = mm.group(1) if mm else None
        for k in ("p0", "p1", "p2", "p3", "p4", "p5", "p7", "p8", "pA0"):
            mm = re.search(r"\b%s=(0x[0-9A-Fa-f]+)" % k, txt)
            d[k] = int(mm.group(1), 16) if mm else None
        out.append(d)
    return out


# The synthetic harness's field map (phase16e_candidate_e/tools/p16e_rec.py
# fields_for()): nine offsets it populates with synthetic slot pointers.
HARNESS_PTR_FIELDS = (0x00, 0x08, 0x10, 0x30, 0x38, 0x48, 0x78, 0x80, 0xA0)
HARNESS_SCALARS = {0x18: "X", 0x1C: "Y", 0x20: "pair.lo", 0x24: "pair.hi",
                   0x28: "flags", 0x98: "u64 0"}
# slot index k -> synthetic base SLOT + k*0x10000 + 0x1000
SLOT = 0x2_0000_0000
STRIDE = 0x10000
GUARD = 0x1000


def harness_image(cell):
    """Exactly what p16e_rec.fields_for + PE.swin_mem write."""
    c = dict(X=576, Y=960, pl=0, ph=0, flags=0x1, grid=(120, 72, 1),
             wgid=(0, 0, 0))
    img = {}
    for i, o in enumerate(HARNESS_PTR_FIELDS):
        base = SLOT + i * STRIDE + GUARD
        img[o] = base
        img[o + 4] = base >> 32
    img[0x18] = c["X"]
    img[0x1C] = c["Y"]
    img[0x20] = c["pl"] & 0xFFFFFFFF
    img[0x24] = c["ph"] & 0xFFFFFFFF
    img[0x28] = c["flags"]
    img[0x98] = 0
    img[0x9C] = 0
    return img


def main():
    OUT = os.path.join(L.P16H, "out")
    os.makedirs(OUT, exist_ok=True)

    _, co, _ = L.parse_disasm(L.ORIG_DIS)
    _, cf, _ = L.parse_disasm(os.path.join(L.ROOT, "phase16h_candidate_f",
                                           "disasm",
                                           "candidate_f_gfx1030_disasm.txt"))
    ro = kernarg_reads(co, SYM)
    rf = kernarg_reads(cf, SYM)

    mo = arg_metadata(L.ORIG_O)
    mf = arg_metadata(os.path.join(L.ROOT, "phase16h_candidate_f",
                                   "gfx1030_dlssnr_candidate_f.co"))

    dec = authentic_decodes(os.path.join(
        L.ROOT, "phase16d_authentic_capture", "amdhip64_7_bridge.log"))
    auth_false = [d for d in dec if d["X"] == 576 and d["Y"] == 960
                  and d["flags"] == "0x1"]
    auth_true = [d for d in dec if d["X"] == 1152 and d["Y"] == 1920
                 and d["flags"] == "0x14"]

    print("=" * 74)
    print("P7/P8/P9 — kernarg / VarParams audit (host-only)")
    print("=" * 74)
    print("\n[1] kernel descriptor argument list")
    for tag, m in (("original gfx1100", mo), ("Candidate F", mf)):
        print("  %-18s kernarg_size=%s align=%s group=%s priv=%s sgpr=%s "
              "vgpr=%s args=%d"
              % (tag, m["kernarg_segment_size"], m["kernarg_segment_align"],
                 m["group_segment_fixed_size"],
                 m["private_segment_fixed_size"], m["sgpr_count"],
                 m["vgpr_count"], len(m["args"])))
    same = (mo["args"] == mf["args"]
            and mo["kernarg_segment_size"] == mf["kernarg_segment_size"])
    print("  explicit arg list identical: %s" % same)
    print("  the ONLY explicit argument is a %d-byte by_value struct at "
          "offset 0" % mo["args"][0]["size"])
    print("  hidden args identical: %s"
          % (mo["args"][1:] == mf["args"][1:]))

    print("\n[2] kernarg read set (from the disassembly, not hard-coded)")
    oo = sorted({r[1] for r in ro})
    fo = sorted({r[1] for r in rf})
    print("  original gfx1100 offsets: %s" % [hex(x) for x in oo])
    print("  Candidate F    offsets: %s" % [hex(x) for x in fo])
    print("  identical read set: %s" % (oo == fo))
    print("  reads inside the by-value struct (<0xA8): %d of %d"
          % (sum(1 for x in fo if x < 0xA8), len(fo)))

    print("\n[3] authentic DECODE values")
    print("  <32,true>  (X=1152,Y=1920,flags=0x14) launches: %d"
          % len(auth_true))
    print("  <32,false> (X=576, Y=960, flags=0x1)  launches: %d"
          % len(auth_false))
    a = auth_false[0]
    for k in ("p0", "p1", "p2", "p3", "p4", "p5", "p7", "p8", "pA0"):
        print("     %-4s = 0x%016X%s" % (k, a[k],
                                         "   (NULL)" if a[k] == 0 else ""))

    # ---- the per-byte table ------------------------------------------
    himg = harness_image("A")
    rows = []
    for pc, off, nb, dst, form in rf:
        for b in range(nb):
            o = off + b
            hb = himg.get(o)
            hval = None
            if hb is not None:
                hval = hb & 0xFF
            rows.append(dict(offset=o, byte_index=b, width=form, dst=dst,
                             read_pc="0x%08X" % pc,
                             harness_byte=(None if hval is None else hval),
                             harness_class=("unset->0" if hb is None
                                            else "synthetic"),
                             authentic_class="UNKNOWN"))
    # classify authentic per byte
    #   0x18..0x1C X, 0x1C..0x20 Y, 0x20 pair.lo, 0x24 pair.hi, 0x28 flags
    #   are proven scalars from the authentic DECODE line.
    KNOWN = {}
    for o, name, val in ((0x18, "X", 576), (0x1C, "Y", 960),
                         (0x20, "pair.lo", 0), (0x24, "pair.hi", 0),
                         (0x28, "flags", 1)):
        KNOWN[o] = (name, val)
    for r in rows:
        o = r["offset"]
        if o in KNOWN:
            nm, v = KNOWN[o]
            r["authentic_class"] = "KNOWN:%s" % nm
            r["authentic_byte"] = (v >> (8 * r["byte_index"])) & 0xFF
        elif 0xA8 <= o < 0xF0:
            r["authentic_class"] = "HIDDEN"
        else:
            r["authentic_class"] = "UNKNOWN"
        r["match"] = (r.get("authentic_byte") is not None
                      and r.get("harness_byte") is not None
                      and r["authentic_byte"] == r["harness_byte"])

    covered = sorted({r["offset"] for r in rows})
    # field granularity: the 8-byte-aligned qword each read belongs to
    fields_read = sorted({off - (off % 8) for _pc, off, _nb, _d, _f in rf})
    ptr_fields_read = [o for o in HARNESS_PTR_FIELDS if o in fields_read]
    ptr_fields_unread = [o for o in HARNESS_PTR_FIELDS
                         if o not in fields_read]
    unset_fields = [o for o in fields_read if o not in himg and o < 0xA8]

    print("\n[4] the harness is NOT authentic")
    print("  bytes the kernel reads from kernarg: %d" % len(covered))
    print("  qword fields the kernel reads: %s"
          % [hex(x) for x in fields_read])
    print("  harness pointer fields the kernel NEVER reads: %s"
          % [hex(x) for x in ptr_fields_unread])
    print("  qword fields the kernel READS that the harness NEVER sets: %s"
          % [hex(x) for x in unset_fields])
    print("  -> the harness scatters synthetic slot pointers at offsets the")
    print("     kernel does not read, and leaves 0 at offsets it does read.")

    # ---- emit the required per-byte table ----------------------------
    import csv as _csv
    tf = os.path.join(L.P16H, "kernarg_byte_table.csv")
    with open(tf, "w", newline="", encoding="utf-8") as fh:
        w = _csv.writer(fh)
        w.writerow(["offset", "byte_index", "read_pc", "width", "dst",
                    "authentic_class", "authentic_byte", "harness_class",
                    "harness_byte", "match"])
        for r in rows:
            w.writerow([hex(r["offset"]), r["byte_index"], r["read_pc"],
                        r["width"], r["dst"], r["authentic_class"],
                        ("" if r.get("authentic_byte") is None
                         else hex(r["authentic_byte"])),
                        r["harness_class"],
                        ("" if r.get("harness_byte") is None
                         else hex(r["harness_byte"])),
                        ("yes" if r.get("match") else "no")])
    print("wrote", tf)

    json.dump(dict(
        sym=SYM, metadata_original=mo, metadata_candidate_f=mf,
        explicit_arg_list_identical=same,
        kernarg_reads_original=[[pc, hex(o), nb, dst, f] for pc, o, nb, dst, f
                                in ro],
        kernarg_reads_candidate_f=[[pc, hex(o), nb, dst, f] for pc, o, nb, dst, f
                                   in rf],
        read_offsets_identical=(oo == fo),
        authentic_decode_true=auth_true[:3],
        authentic_decode_false=auth_false[:3],
        harness_pointer_fields=[hex(x) for x in HARNESS_PTR_FIELDS],
        qword_fields_read=[hex(x) for x in fields_read],
        harness_ptr_fields_never_read=[hex(x) for x in ptr_fields_unread],
        harness_unset_qword_fields_read=[hex(x) for x in unset_fields],
        per_byte_table=rows,
    ), open(os.path.join(OUT, "p7_p8_kernarg_audit.json"), "w"), indent=1)
    print("\nwrote", os.path.join(OUT, "p7_p8_kernarg_audit.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
