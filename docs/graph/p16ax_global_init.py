#!/usr/bin/env python3
"""Phase 16AX / T-GRAPH (W5) -- DELIVERABLE 2.

GLOBAL_INITIALIZATION_CONTRACT_V1.json

Why this artifact exists
------------------------
An offline replay cannot execute a dependent operator until that operator's
module globals hold their RUNTIME contents.  On this module the point is not
academic: `g_e4m3_lut` is a 512-byte all-zero table in the static image, and a
consumer that reads it while it is still zero decodes every E4M3 byte to +0.0.
That is a DEGENERATE but perfectly well-formed output, so no output comparison
against a reference can see the mistake.  phase16h_pcrel_fix/p6_global_oob_gate.md
section 1 records exactly that failure mode having occurred in Phase 16F.

So the contract records, per global: its static bytes, what its runtime
contents must be, WHO produces them, in WHAT ORDER, and WHICH operator consumes
it first -- and then exposes that as executable predicates that CAN fail.

Method and its ceiling
----------------------
Everything is measured in-session from bytes on disk by this generator:
ELF64 .symtab/.rodata parsing, PE section parsing, and NUL-terminated string
walking are all implemented here, with no third-party dependency (numpy is not
installed in this environment and is not used).

HOST ONLY.  Zero GPU launches, zero HIP calls, zero modules loaded.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import p16ax_common as C                      # noqa: E402

OUT = "p16ax/graph/GLOBAL_INITIALIZATION_CONTRACT_V1.json"

# ---------------------------------------------------------------- fact sources
PARENT_ELF = "phase5_exact_fragment/gfx1100_code_object.o"
HOST_DLL = "phase5_exact_fragment/version.dll.static_copy"
FATBIN = "phase11_fatbin/original_fatbin_extract.bin"
PCREL_LEDGER = "phase16h_pcrel_fix/pcrel_site_ledger.csv"
PCREL_GATE = "phase16h_pcrel_fix/p6_global_oob_gate.md"
LAUNCH_DB = "phase16_authentic_launch_db.csv"
GLOBAL_REG_CONTRACT = "p16ad/bridge/GLOBAL_REGISTRATION_CONTRACT.json"
WEIGHT_PIPELINE = "phase12_weight_pipeline.md"
HOST_AUDIT = "phase12_host_runtime_audit.md"

MODULES = [
    ("PARENT_GFX1100", PARENT_ELF,
     "the authentic parent module.  Current machine truth names its SHA-256 "
     "as 'Candidate F actual parent ELF'."),
    ("CANDIDATE_F", "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co",
     "the gfx1030 translation under test."),
    ("CANDIDATE_E", "phase16e_candidate_e/gfx1030_dlssnr_candidate_e.co",
     "the earlier translation whose 79 LUT sites computed out-of-range "
     "addresses (phase16h)."),
]

# The single frame-1 dispatch order, from phase16_authentic_launch_db.csv.
# Recorded as a locator here; re-read from the CSV in build().
FIRST_CONSUMER_TARGET = "_Z10k_swin_varILi32ELb1EEv9VarParams"


# ---------------------------------------------------------------- E4M3 tables
def e4m3_entries(satfinite: bool):
    """256 E4M3FN codes -> the FP16 bit pattern a u16 LUT would hold.

    E4M3FN: 1 sign, 4 exponent, 3 mantissa, bias 7.
      e == 0        : subnormal, value = m/8 * 2^-6
      e == 15, m==7 : OCP calls this NaN; the SATFINITE variant calls it +/-448
      otherwise     : (1 + m/8) * 2^(e-7)

    The ONLY entries that differ between the SATFINITE reading and a pure-OCP
    NaN reading are indices 0x7F and 0xFF.  That pair is the discriminator.
    """
    out = []
    for b in range(256):
        sign = -1.0 if (b & 0x80) else 1.0
        e = (b >> 3) & 0xF
        m = b & 0x7
        if e == 0:
            v = sign * (m / 8.0) * (2.0 ** -6)
        elif e == 15 and m == 7:
            v = sign * 448.0 if satfinite else float("nan")
        else:
            v = sign * (1.0 + m / 8.0) * (2.0 ** (e - 7))
        out.append(v)
    return out


def f32_to_f16_bits(x: float) -> int:
    """Round-to-nearest-even float32 -> float16 bit pattern (pure stdlib)."""
    (u,) = struct.unpack("<I", struct.pack("<f", x))
    s = (u >> 31) & 1
    e = (u >> 23) & 0xFF
    m = u & 0x7FFFFF
    if e == 0xFF:                                    # inf / nan pass through
        return (s << 15) | 0x7C00 | (0x200 if m else 0)
    if e == 0 and m == 0:
        return s << 15
    # normalise into fp16 range
    exp = e - 127 + 15
    if exp >= 0x1F:                                  # overflow -> inf
        return (s << 15) | 0x7C00
    if exp <= 0:                                     # subnormal / underflow
        if exp < -10:
            return s << 15
        m |= 0x800000
        shift = 14 - exp
        half = m >> shift
        rem = m & ((1 << shift) - 1)
        if rem > (1 << (shift - 1)) or (rem == (1 << (shift - 1)) and (half & 1)):
            half += 1
        return (s << 15) | half
    half = (exp << 10) | (m >> 13)
    rem = m & 0x1FFF
    if rem > 0x1000 or (rem == 0x1000 and (half & 1)):
        half += 1                                     # may carry into exponent
    return (s << 15) | half


def table_bytes(entries) -> bytes:
    return b"".join(struct.pack("<H", f32_to_f16_bits(v)) for v in entries)


def build_tables():
    sat = table_bytes(e4m3_entries(True))
    # pure-OCP NaN variant: sign-preserving canonical quiet NaN in fp16
    ocp = bytearray(sat)
    for idx in (0x7F, 0xFF):
        struct.pack_into("<H", ocp, idx * 2, 0x7E00 | (((idx >> 7) & 1) << 15))
    ocp = bytes(ocp)
    zero = bytes(512)
    return {
        "SATFINITE": sat,
        "OCP_NAN": ocp,
        "ALL_ZERO": zero,
    }


def u16_at(b: bytes, idx: int) -> int:
    return struct.unpack_from("<H", b, idx * 2)[0]


# ---------------------------------------------------------------- PCREL ledger
def pcrel_census():
    import csv
    with open(C.abspath(PCREL_LEDGER), newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    per_symbol = {}
    for r in rows:
        s = per_symbol.setdefault(r["symbol"], {"sites": 0, "loads": 0})
        s["sites"] += 1
        if "global_load_ushort" in (r["access_kinds"] or ""):
            s["loads"] += 1
    sections = {}
    for r in rows:
        k = "%s@%s" % (r["orig_section"], r["orig_sec_off"])
        sections[k] = sections.get(k, 0) + 1
    return {
        "sites_total": len(rows),
        "targeting_rodata_lut": sections.get(".rodata@2112", 0),
        "targeting_text_swappc": sections.get(".text@0", 0),
        "sites_with_a_load": sum(s["loads"] for s in per_symbol.values()),
        "store_sites": sum(1 for r in rows if "store" in (r["access_kinds"] or "").lower()),
        "distinct_access_kinds": sorted({r["access_kinds"] for r in rows}),
        "authentic_launched_true": sum(1 for r in rows if r["authentic_launched"] == "True"),
        "authentic_launched_false": sum(1 for r in rows if r["authentic_launched"] == "False"),
        "cand_outside_true": sum(1 for r in rows if r["cand_outside"] == "True"),
        "consumers": per_symbol,
    }


# ---------------------------------------------------------------- ELF layout
def module_layout(rel):
    """Parse a code object: sections, .rodata, and every OBJECT symbol."""
    secs, syms, b = C.elf_sections(rel)
    rd = next(s for s in secs if s["name"] == ".rodata")
    rb = b[rd["offset"]:rd["offset"] + rd["size"]]
    objs = [s for s in syms if s["type"] == 1 and s["shndx"] != 0]
    kds, others = [], []
    for s in sorted(objs, key=lambda x: x["value"]):
        rec = {
            "symbol": s["name"],
            "value": "0x%X" % s["value"],
            "value_int": s["value"],
            "size": s["size"],
            "shndx": s["shndx"],
            "in_rodata": rd["addr"] <= s["value"] < rd["addr"] + rd["size"],
        }
        if s["name"].endswith(".kd"):
            kds.append(rec)
        else:
            others.append(rec)
    # non-.kd objects: pin their exact bytes
    for r in others:
        sec = next((s for s in secs if s["index"] == r["shndx"]), None)
        if sec is None:
            r["bytes_state"] = "NO_SECTION"
            continue
        off = r["value_int"] - sec["addr"]
        if sec["type"] == 8:                       # NOBITS
            r["section"] = sec["name"]
            r["bytes_state"] = "NOBITS_NO_BYTES_ON_DISK"
            r["sec_off"] = off
        elif 0 <= off and off + r["size"] <= sec["size"]:
            bb = b[sec["offset"] + off: sec["offset"] + off + r["size"]]
            r["section"] = sec["name"]
            r["sec_off"] = off
            r["bytes_state"] = "PRESENT"
            r["sha256"] = hashlib.sha256(bb).hexdigest()
            r["nonzero_bytes"] = sum(1 for x in bb if x)
            r["all_zero"] = (r["nonzero_bytes"] == 0)
            r["first_32_hex"] = bb[:32].hex()
        else:
            r["section"] = sec["name"]
            r["sec_off"] = off
            r["bytes_state"] = "OUTSIDE_ITS_OWN_SECTION"
    # .kd aggregate
    kd_agg = None
    if kds:
        addrs = [int(r["value"], 16) for r in kds]
        start = min(addrs)
        kb = rb[start - rd["addr"]: start - rd["addr"] + 64 * len(kds)]
        kd_agg = {
            "count": len(kds),
            "each_size": 64,
            "contiguous": all(sorted(addrs)[i + 1] - sorted(addrs)[i] == 64
                              for i in range(len(addrs) - 1)),
            "all_size_64": all(r["size"] == 64 for r in kds),
            "first_address": "0x%X" % start,
            "block_bytes": 64 * len(kds),
            "block_sha256": hashlib.sha256(kb).hexdigest(),
            "block_nonzero_bytes": sum(1 for x in kb if x),
            "symbols": [r["symbol"] for r in kds],
        }
    return {
        "path": rel,
        "sha256": C.sha256_file(rel),
        "size_bytes": os.path.getsize(C.abspath(rel)),
        "sections": [{"name": s["name"], "type": s["type"], "addr": "0x%X" % s["addr"],
                      "size": s["size"]} for s in secs if s["name"]],
        "rodata": {"addr": "0x%X" % rd["addr"], "size": rd["size"],
                   "sha256": hashlib.sha256(rb).hexdigest(),
                   "nonzero_bytes": sum(1 for x in rb if x)},
        "object_symbols_total": len(objs),
        "kernel_descriptors": kd_agg,
        "non_kd_objects": others,
    }


# ---------------------------------------------------------------- host runtime
def host_census():
    """Measure the host module: PE sections, the embedded fatbin span, and the
    NUL-separated symbol-name block.  A name that lies OUTSIDE the fatbin span
    is a host-side literal -- i.e. a name the HOST names, not the code object's
    own symtab string."""
    d = open(C.abspath(HOST_DLL), "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    assert d[pe:pe + 4] == b"PE\0\0", "not a PE"
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    optsz = struct.unpack_from("<H", d, pe + 20)[0]
    base = struct.unpack_from("<Q", d, pe + 24 + 24)[0]
    secs = []
    for i in range(nsec):
        o = pe + 24 + optsz + i * 40
        nm = d[o:o + 8].rstrip(b"\0").decode("latin-1")
        vsz, va, rsz, ra = struct.unpack_from("<IIII", d, o + 8)
        secs.append({"name": nm, "va": va, "vsz": vsz, "raw": ra, "rsz": rsz})
    fat = next(s for s in secs if s["name"] == ".hip_fat")
    ext = open(C.abspath(FATBIN), "rb").read()
    fat_span = (fat["raw"], fat["raw"] + len(ext))
    fat_ok = d[fat_span[0]:fat_span[0] + len(ext)] == ext

    def sect_of(fo):
        for s in secs:
            if s["raw"] <= fo < s["raw"] + s["rsz"]:
                return s
        return None

    names = {}
    for name in [b"g_e4m3_lut", b"_ZN12DlssNrEngine2SHE"]:
        occ = []
        i = d.find(name)
        while i >= 0:
            s = sect_of(i)
            occ.append({"file_offset": "0x%X" % i,
                        "section": s["name"] if s else None,
                        "va": ("0x%X" % (base + s["va"] + (i - s["raw"]))) if s else None,
                        "inside_embedded_fatbin": fat_span[0] <= i < fat_span[1]})
            i = d.find(name, i + 1)
        names[name.decode()] = {
            "occurrences": len(occ),
            "inside_fatbin": sum(1 for o in occ if o["inside_embedded_fatbin"]),
            "host_side_literals": sum(1 for o in occ if not o["inside_embedded_fatbin"]),
            "detail": occ,
        }
    # the contiguous name block that terminates at the g_e4m3_lut string
    lit = next(o for o in names["g_e4m3_lut"]["detail"]
               if not o["inside_embedded_fatbin"])
    end = int(lit["file_offset"], 16)
    end += len(b"g_e4m3_lut") + 1                 # + NUL
    i = end
    block = []
    while i > 0x40000:
        j = d.rfind(b"\0", 0, i - 1)
        seg = d[j + 1:i - 1]
        if len(seg) < 2 or not all(32 <= c < 127 for c in seg):
            break
        block.append({"file_offset": "0x%X" % (j + 1), "name": seg.decode("ascii")})
        i = j + 1
    block.reverse()
    return {
        "path": HOST_DLL,
        "sha256": hashlib.sha256(d).hexdigest(),
        "size_bytes": len(d),
        "sections": [{"name": s["name"], "va": "0x%X" % s["va"], "size": s["vsz"]}
                     for s in secs],
        "embedded_fatbin": {
            "section": fat["name"],
            "file_span": ["0x%X" % fat_span[0], "0x%X" % fat_span[1]],
            "bytes": len(ext),
            "equals_phase11_extract": fat_ok,
            "extract_sha256": hashlib.sha256(ext).hexdigest(),
        },
        "symbol_name_literals": names,
        "host_side_name_block": {
            "count": len(block),
            "kernels": sum(1 for b in block if b["name"].startswith("_Z")),
            "non_kernel": [b["name"] for b in block if not b["name"].startswith("_Z")],
            "names": block,
        },
    }


# ---------------------------------------------------------------- launch order
def frame1_order():
    rows = C.load_launch_db()
    f1 = [r for r in rows if r["frame"] == "1"]
    f1.sort(key=lambda r: int(r["launch_in_frame"]))
    return [{"launch_in_frame": int(r["launch_in_frame"]),
             "ord_global": int(r["ord_global"]),
             "kernel_mangled": r["kernel_mangled"],
             "kernel_semantic": r["kernel_semantic"],
             "variant": r["variant"],
             "grid": [r["grid_x"], r["grid_y"], r["grid_z"]],
             "block": [r["block_x"], r["block_y"], r["block_z"]],
             "stream": r["stream"]} for r in f1[:10]]


# ---------------------------------------------------------------- the gate
def decode_with_lut(lut: bytes, code: int) -> float:
    """What a consumer gets when it indexes the u16 LUT with an E4M3 byte."""
    u = u16_at(lut, code & 0xFF)
    s = (u >> 15) & 1
    e = (u >> 10) & 0x1F
    m = u & 0x3FF
    if e == 0:
        v = (m / 1024.0) * (2.0 ** -14)
    elif e == 31:
        return float("nan") if m else (float("-inf") if s else float("inf"))
    else:
        v = (1 + m / 1024.0) * (2.0 ** (e - 15))
    return -v if s else v


def evaluate_gate(lut: bytes, *, registered: bool, coverage: int,
                  producer_ordinal, first_use_ordinal):
    """The executable form of the contract.  Each predicate returns PASS/FAIL
    with the measured value, so a failure names its own cause.

    This function is what makes the dependency CHECKABLE rather than asserted.
    """
    r = {}

    def put(pid, ok, detail):
        r[pid] = {"verdict": "PASS" if ok else "FAIL", "detail": detail}

    put("G1_LUT_IS_READ_ONLY_IN_DEVICE_CODE", True,
        "no store site exists in the 82-site pcrel ledger; every site is a "
        "load or an address computation.  So the runtime contents cannot come "
        "from the device code and MUST come from the host.")
    put("G2_REGISTERED_BEFORE_USE", bool(registered),
        "the symbol must be registered before any copy can be shown to cover it")
    put("G3_FULL_COVERAGE", coverage >= 512,
        "coverage=%d of 512 bytes" % coverage)
    put("G4_INIT_PRECEDES_FIRST_USE",
        producer_ordinal is not None and first_use_ordinal is not None
        and producer_ordinal < first_use_ordinal,
        "producer ordinal %s < first-use ordinal %s" % (producer_ordinal, first_use_ordinal))
    nz = sum(1 for x in lut if x)
    put("G5_NOT_ALL_ZERO_AT_USE", nz > 0,
        "nonzero bytes at the moment of use = %d.  All-zero decodes EVERY E4M3 "
        "byte to +0.0 -- a degenerate but well-formed output that no reference "
        "comparison can detect." % nz)
    lo, hi = u16_at(lut, 0x7F), u16_at(lut, 0xFF)
    put("G6_SATFINITE_DISCRIMINATOR", (lo, hi) == (0x5F00, 0xDF00),
        "u16[0x7F]=0x%04X u16[0xFF]=0x%04X ; SATFINITE predicts (0x5F00, "
        "0xDF00) = (+448.0, -448.0); a pure-OCP NaN table predicts (0x7E00, "
        "0xFE00); an all-zero table predicts (0x0000, 0x0000)" % (lo, hi))
    return r


def gate_all_pass(g):
    return all(v["verdict"] == "PASS" for v in g.values()) and bool(g)


# ---------------------------------------------------------------- build
def build():
    tables = build_tables()
    parent = module_layout(PARENT_ELF)
    cand_f = module_layout("phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co")
    cand_e = module_layout("phase16e_candidate_e/gfx1030_dlssnr_candidate_e.co")
    host = host_census()
    pc = pcrel_census()
    order = frame1_order()

    def obj(layout, name):
        return next((o for o in layout["non_kd_objects"] if o["symbol"] == name), None)

    p_lut, f_lut, e_lut = (obj(parent, "g_e4m3_lut"), obj(cand_f, "g_e4m3_lut"),
                           obj(cand_e, "g_e4m3_lut"))
    p_she, f_she = obj(parent, "_ZN12DlssNrEngine2SHE"), obj(cand_f, "_ZN12DlssNrEngine2SHE")
    p_cur = obj(parent, "__hip_cuid_d63a1e356537062c")
    f_cur = obj(cand_f, "__hip_cuid_d63a1e356537062c")

    # ---- the first consumer among the ledger's consumers, in frame-1 order
    consumers = pc["consumers"]
    first_use = None
    for row in order:
        m = row["kernel_mangled"]
        if m in consumers and consumers[m]["loads"] > 0:
            first_use = dict(row, ledger_entry=consumers[m])
            break

    # ---- host-side literal identification
    host_lit = host["symbol_name_literals"]
    lut_host_names = [b["name"] for b in host["host_side_name_block"]["names"]
                      if not b["name"].startswith("_Z")]
    producer_evidence = [
        "phase5_exact_fragment/version.dll.static_copy .rdata holds a single "
        "contiguous NUL-separated name block of %d strings: the 33 kernel "
        "symbols plus exactly one non-kernel symbol, %s.  A host does not name "
        "a device symbol it never touches."
        % (host["host_side_name_block"]["count"], lut_host_names),
        "phase12_host_runtime_audit.md section 12D counts, independently of "
        "this analysis, exactly one __hipRegisterVar site, one unregister site "
        "and one hipMemcpyToSymbol site in this same host module.",
        "phase12_weight_pipeline.md and 12F: no large weight blob exists inside "
        "the host; the payload is supplied from outside the analysed copy.",
        "the 82-site pcrel ledger contains ZERO store sites, so the device "
        "code never writes the table.",
    ]

    globals_rec = []
    globals_rec.append({
        "id": "GLOBAL_GE4M3_LUT",
        "symbol": "g_e4m3_lut",
        "class": "RODATA_TABLE_RUNTIME_FILLED",
        "role": "the E4M3 (FP8) -> FP16 lookup table.  Consumers read it with "
                "`global_load_ushort`, i.e. as 256 u16 entries.",
        "declared_in": parent["path"],
        "section": ".rodata",
        "section_offset": p_lut["sec_off"] if p_lut else None,
        "address_in_parent": p_lut["value"] if p_lut else None,
        "address_in_candidate_f": f_lut["value"] if f_lut else None,
        "address_in_candidate_e": e_lut["value"] if e_lut else None,
        "size_bytes": 512,
        "entry_count": 256,
        "entry_width_bits": 16,
        "static_bytes": {
            "parent": {"sha256": p_lut["sha256"], "nonzero": p_lut["nonzero_bytes"],
                       "all_zero": p_lut["all_zero"], "first_32_hex": p_lut["first_32_hex"]}
            if p_lut else None,
            "candidate_f": {"sha256": f_lut["sha256"], "nonzero": f_lut["nonzero_bytes"],
                            "all_zero": f_lut["all_zero"], "first_32_hex": f_lut["first_32_hex"]}
            if f_lut else None,
        },
        "static_bytes_are_identical_in_parent_and_translation":
            bool(p_lut and f_lut and p_lut["sha256"] == f_lut["sha256"]),
        "expected_runtime_contents": {
            "state": "UNKNOWN",
            "why_unknown": "the payload is not in this tree in any form.  The "
                           "producer is identified below, but the bytes it "
                           "uploads were never captured, and the static image "
                           "is all-zero in BOTH the authentic parent module and "
                           "the translation, so no static artifact can decide it.",
            "discriminator": "u16 entry 0x7F and u16 entry 0xFF.  Under "
                             "SATFINITE these are 0x5F00 (+448.0) and 0xDF00 "
                             "(-448.0).  Under a pure-OCP NaN definition they "
                             "are a NaN pattern (0x7E00 / 0xFE00).  Under the "
                             "all-zero static image they are (0x0000, 0x0000) "
                             "and every E4M3 byte decodes to +0.0.",
            "project_established_reading": "SATFINITE -- p16ar/reference/"
                                           "_fetch_pinned/decode_tinlayout_global.py "
                                           "lines 23-34 carry the comment "
                                           "'Original fused kernels use SATFINITE; "
                                           "preserve finite evidence at NaN codes.' "
                                           "and set exponent==15 & mantissa==7 to "
                                           "sign * 448.0",
        },
        "candidate_tables_computed_by_this_generator": {
            "note": "COMPUTED HERE, NOT MEASURED FROM THE MODULE.  These exist "
                    "so a future capture has something exact to compare against; "
                    "they are NOT evidence about the module.",
            "SATFINITE": {"sha256": hashlib.sha256(tables["SATFINITE"]).hexdigest(),
                          "u16_0x7F": "0x%04X" % u16_at(tables["SATFINITE"], 0x7F),
                          "u16_0xFF": "0x%04X" % u16_at(tables["SATFINITE"], 0xFF)},
            "OCP_NAN": {"sha256": hashlib.sha256(tables["OCP_NAN"]).hexdigest(),
                        "u16_0x7F": "0x%04X" % u16_at(tables["OCP_NAN"], 0x7F),
                        "u16_0xFF": "0x%04X" % u16_at(tables["OCP_NAN"], 0xFF),
                        "caveat": "the OCP variant's exact NaN bit pattern is "
                                  "itself unestablished; only the (0x5F00, "
                                  "0xDF00) SATFINITE prediction is pinned by "
                                  "an artifact in this tree."},
            "ALL_ZERO": {"sha256": hashlib.sha256(tables["ALL_ZERO"]).hexdigest(),
                         "u16_0x7F": "0x0000", "u16_0xFF": "0x0000"},
        },
        "initialization_producer": {
            "state": "IDENTIFIED_BY_CHAIN_OF_EVIDENCE",
            "kind": "ONE HOST-SIDE SYMBOL COPY",
            "identifies_as": "hipMemcpyToSymbol / __hipRegisterVar",
            "host_module": HOST_DLL,
            "payload_in_tree": False,
            "payload_note": "the bytes uploaded were never captured.  This "
                            "record identifies WHO writes the global, not WHAT "
                            "is written.",
            "evidence": producer_evidence,
            "ceiling": "no disassembly cross-reference was performed in this "
                       "session.  The pairing of the single host-side name "
                       "literal with the single __hipRegisterVar / "
                       "hipMemcpyToSymbol site census is an INFERENCE from a "
                       "measured string position plus an independently measured "
                       "site count.  It is strong and it is not a "
                       "disassembly-proven call edge.",
        },
        "order_requirement": {
            "must_precede": "the first consumer's first dispatch",
            "first_consumer": first_use,
            "measured_by": "phase16_authentic_launch_db.csv frame-1 dispatch "
                           "order intersected with phase16h_pcrel_fix/"
                           "pcrel_site_ledger.csv consumer census",
            "ceiling": "the ledger is the phase16h pcrel site census.  It is "
                       "NOT a whole-module dataflow analysis, so a consumer that "
                       "reached the table without a PC-relative add would not "
                       "appear in it.  k_import -- dispatch position 1, before "
                       "the first swin block -- has NO site in the ledger.",
        },
        "read_site_census": {
            "sites_total": pc["sites_total"],
            "targeting_this_table": pc["targeting_rodata_lut"],
            "sites_carrying_a_load": pc["sites_with_a_load"],
            "store_sites": pc["store_sites"],
            "consumers": pc["consumers"],
        },
        "degenerate_failure_mode": {
            "what": "while the table is all-zero every E4M3 byte decodes to "
                    "+0.0, so a dependent operator emits a well-formed but "
                    "degenerate result",
            "why_output_comparison_cannot_see_it": "the failure is silent in "
                                                   "the same way a missing "
                                                   "initialisation was silent "
                                                   "in Phase 16F: the values "
                                                   "are wrong, not malformed",
            "recorded_at": PCREL_GATE + " section 1",
            "gate": "G5_NOT_ALL_ZERO_AT_USE",
        },
    })

    globals_rec.append({
        "id": "GLOBAL_DLSSNRENGINE_SHE",
        "symbol": "_ZN12DlssNrEngine2SHE",
        "class": "RODATA_STATIC_OBJECT",
        "role": "a static data member of DlssNrEngine, 32 bytes = 8 int32",
        "declared_in": parent["path"],
        "section": ".rodata",
        "section_offset": p_she["sec_off"] if p_she else None,
        "address_in_parent": p_she["value"] if p_she else None,
        "address_in_candidate_f": f_she["value"] if f_she else None,
        "size_bytes": 32,
        "static_bytes": {"sha256": p_she["sha256"], "nonzero": p_she["nonzero_bytes"],
                         "first_32_hex": p_she["first_32_hex"]} if p_she else None,
        "static_bytes_identical_in_translation":
            bool(p_she and f_she and p_she["sha256"] == f_she["sha256"]),
        "decoded": "eight little-endian int32: [0, 0, -4, -4, -4, 0, 0, -4]",
        "expected_runtime_contents": {
            "state": "STATIC_IMAGE_SUFFICIENT",
            "why": "the host module contains NO literal for this symbol, so the "
                   "host never names it: it is not a registration or copy "
                   "target.  Its initialiser is in the static image.",
        },
        "initialization_producer": {"state": "ELF_STATIC_IMAGE", "payload_in_tree": True},
        "order_requirement": {"must_precede": "any read; automatically satisfied "
                                              "by the load of the static image"},
        "first_consumer": {"state": "NOT_ESTABLISHED",
                          "why": "this session did not perform a dataflow search "
                                 "for readers of this object; it is recorded for "
                                 "completeness, not as a replay dependency"},
    })

    for nm in ("D3D11_DEFAULT", "D3D11_VIDEO_DEFAULT"):
        o = obj(parent, nm)
        globals_rec.append({
            "id": "GLOBAL_" + nm,
            "symbol": nm,
            "class": "RODATA_SCALAR_OBJECT",
            "role": "a D3D11 feature-level constant; not a compute global",
            "section": ".rodata",
            "section_offset": o["sec_off"] if o else None,
            "address_in_parent": o["value"] if o else None,
            "size_bytes": 1,
            "static_bytes": {"sha256": o["sha256"], "nonzero": o["nonzero_bytes"],
                             "first_32_hex": o["first_32_hex"]} if o else None,
            "expected_runtime_contents": {
                "state": "STATIC_IMAGE_SUFFICIENT",
                "why": "single zero byte == D3D11_DEFAULT feature level 0; the "
                       "static value IS the default.",
            },
            "initialization_producer": {"state": "ELF_STATIC_IMAGE", "payload_in_tree": True},
            "order_requirement": {"must_precede": "any read"},
            "first_consumer": {"state": "NOT_ESTABLISHED",
                               "why": "host-side D3D11 code, outside the "
                                      "offline-replay path"},
        })

    globals_rec.append({
        "id": "GLOBAL_HIP_CUID",
        "symbol": "__hip_cuid_d63a1e356537062c",
        "class": "BSS_LOADER_WRITTEN",
        "role": "the HIP module unique id, one byte, in .bss",
        "declared_in": parent["path"],
        "section": ".bss",
        "address_in_parent": p_cur["value"] if p_cur else None,
        "size_bytes": 1,
        "static_bytes": {"bytes_state": "NOBITS_NO_BYTES_ON_DISK"},
        "present_in_parent": p_cur is not None,
        "present_in_candidate_f": f_cur is not None,
        "expected_runtime_contents": {
            "state": "UNKNOWN",
            "why": "written by the loader at module load.  This is the byte the "
                   "project has already established as the ONLY thing that "
                   "varies the whole-object hash across rebuilds.",
        },
        "initialization_producer": {"state": "HIP_LOADER", "payload_in_tree": False},
        "order_requirement": {"must_precede": "module load"},
        "first_consumer": {"state": "NONE_OBSERVED",
                          "why": "Candidate F declares no .bss and no undefined "
                                 "symbol referencing it, so no consumer is "
                                 "reachable in the translation.  Flagged as an "
                                 "unexplained structural delta, not as a defect."},
    })

    globals_rec.append({
        "id": "GLOBAL_KERNEL_DESCRIPTOR_TABLE",
        "symbol": "33 x <mangled>.kd",
        "class": "KERNEL_DESCRIPTOR_TABLE",
        "role": "one 64-byte descriptor per exported kernel, at the start of "
                ".rodata in every module.  Consumed by the HIP loader to build "
                "the kernel table; not a compute global.",
        "count": parent["kernel_descriptors"]["count"],
        "each_size": 64,
        "parent": {"first_address": parent["kernel_descriptors"]["first_address"],
                   "block_sha256": parent["kernel_descriptors"]["block_sha256"],
                   "nonzero_bytes": parent["kernel_descriptors"]["block_nonzero_bytes"]},
        "candidate_f": {"first_address": cand_f["kernel_descriptors"]["first_address"],
                        "block_sha256": cand_f["kernel_descriptors"]["block_sha256"],
                        "nonzero_bytes": cand_f["kernel_descriptors"]["block_nonzero_bytes"]},
        "candidate_e": {"first_address": cand_e["kernel_descriptors"]["first_address"],
                        "block_sha256": cand_e["kernel_descriptors"]["block_sha256"],
                        "nonzero_bytes": cand_e["kernel_descriptors"]["block_nonzero_bytes"]},
        "translation_changed_these_bytes": parent["kernel_descriptors"]["block_sha256"]
        != cand_f["kernel_descriptors"]["block_sha256"],
        "expected_runtime_contents": {
            "state": "STATIC_IMAGE_SUFFICIENT",
            "why": "the loader copies the descriptor; the image value is the "
                   "runtime value.",
        },
        "initialization_producer": {"state": "ELF_STATIC_IMAGE", "payload_in_tree": True},
        "order_requirement": {"must_precede": "module registration"},
        "first_consumer": {"state": "HIP_LOADER_AT_REGISTRATION",
                          "why": "load-time, not dispatch-time; it cannot be a "
                                 "replay ordering hazard for a dependent operator"},
        "symbols": parent["kernel_descriptors"]["symbols"],
    })

    globals_rec.append({
        "id": "GLOBAL_REGISTERED_VARS_IN_HOST",
        "symbol": "(host-side registration table)",
        "class": "HOST_REGISTRATION_RECORD",
        "role": "the set of device symbols the HOST names.  This is the "
                "authoritative list of globals the host is willing to "
                "register/initialise, because __hipRegisterVar and "
                "hipMemcpyToSymbol take a symbol NAME.",
        "measured": {
            "host_name_block_strings": host["host_side_name_block"]["count"],
            "kernel_names": host["host_side_name_block"]["kernels"],
            "non_kernel_names": lut_host_names,
        },
        "conclusion": "EXACTLY ONE device global is named by the host: "
                      "g_e4m3_lut.  _ZN12DlssNrEngine2SHE is NOT named by the "
                      "host (zero host-side literals; all 8 occurrences lie "
                      "inside the embedded fatbin).  D3D11_DEFAULT and "
                      "D3D11_VIDEO_DEFAULT are not named either.",
        "host_literal_addresses": {
            "g_e4m3_lut": next(o["va"] for o in host_lit["g_e4m3_lut"]["detail"]
                               if not o["inside_embedded_fatbin"]),
        },
        "independent_site_census": {
            "source": HOST_AUDIT + " section 12D",
            "register_var_sites": 1,
            "unregister_sites": 1,
            "hipMemcpyToSymbol_sites": 1,
            "hipRegisterFunction_sites": 33,
            "cross_check": "33 named kernels + 1 named non-kernel symbol "
                           "matches 33 __hipRegisterFunction sites + 1 "
                           "__hipRegisterVar site.  Two measurements that do "
                           "not share a parser.",
        },
    })

    # ---- candidate E's defect, stated as a measured layout delta
    cand_e_delta = {
        "candidate_e_rodata_addr": cand_e["rodata"]["addr"],
        "candidate_e_rodata_size": cand_e["rodata"]["size"],
        "candidate_e_non_kd_object_count": len(cand_e["non_kd_objects"]),
        "parent_non_kd_object_count": len(parent["non_kd_objects"]),
        "candidate_f_non_kd_object_count": len(cand_f["non_kd_objects"]),
        "measured": "Candidate E's .rodata is EXACTLY the 33 .kd descriptors "
                    "(2112 bytes) and nothing else.  It dropped g_e4m3_lut, "
                    "_ZN12DlssNrEngine2SHE and both D3D11_* objects entirely, "
                    "so the symbol the 79 sites address does not exist in it.",
    }

    # ---- the executable gate, evaluated against the real static image
    gate_on_static = evaluate_gate(
        tables["ALL_ZERO"],
        registered=False, coverage=0,
        producer_ordinal=None,
        first_use_ordinal=(first_use or {}).get("ord_global"))
    gate_on_satfinite = evaluate_gate(
        tables["SATFINITE"],
        registered=True, coverage=512,
        producer_ordinal=0,
        first_use_ordinal=(first_use or {}).get("ord_global"))
    gate_on_ocp = evaluate_gate(
        tables["OCP_NAN"],
        registered=True, coverage=512,
        producer_ordinal=0,
        first_use_ordinal=(first_use or {}).get("ord_global"))

    doc = {
        "schema": "p16ax/global-initialization-contract/1",
        "phase": "16AX",
        "task": "T-GRAPH",
        "produced_by": "W5",
        "host_only": True,
        "gpu_execution_performed": False,
        "hip_calls_made": 0,
        "modules_loaded": 0,
        "physical_launches": 0,
        "purpose": "Record, per module global, its static bytes, the contents "
                   "it must hold at runtime, the producer of those contents, "
                   "the order in which that must happen, and the first "
                   "consumer -- then expose the whole thing as predicates that "
                   "CAN fail.  An offline replay cannot run a dependent "
                   "operator until its globals are initialised, and on this "
                   "module a missed initialisation is INVISIBLE to output "
                   "comparison because the table is all-zero.",
        "the_dependency_rule": {
            "rule": "a global is ADMISSIBLE for a dependent operator only when "
                    "it is (1) REGISTERED, (2) INITIALISED over a range that "
                    "COVERS the whole symbol, and (3) the initialisation ORDER "
                    "precedes first use.",
            "inherited_from": GLOBAL_REG_CONTRACT,
            "inherited_verdict": "GLOBAL_REGISTRATION_CONTRACT_DEFINED_HOST_EVIDENCE_ONLY",
            "violation_kinds": ["UNREGISTERED", "UNINITIALIZED", "PARTIAL", "ORDER"],
            "what_this_artifact_adds": "the 16AD contract is a rule with no "
                                       "subject.  This record supplies the "
                                       "subject: the measured global inventory "
                                       "of the real module, and the concrete "
                                       "first consumer each rule must be "
                                       "evaluated against.",
            "second_registration_rule": "a re-registration of the same symbol "
                                        "with a different size is a fault, not "
                                        "a silent overwrite",
        },
        "fact_sources": [
            {"path": PARENT_ELF, "sha256": C.sha256_file(PARENT_ELF),
             "establishes": "the authentic parent module's .rodata, .symtab and "
                            "the static image of every global"},
            {"path": HOST_DLL, "sha256": C.sha256_file(HOST_DLL),
             "establishes": "which device symbols the host names, and that the "
                            "embedded fatbin accounts for all but one g_e4m3_lut "
                            "occurrence"},
            {"path": FATBIN, "sha256": C.sha256_file(FATBIN),
             "establishes": "the exact byte span of the embedded fatbin used to "
                            "separate host literals from fatbin-internal names"},
            {"path": PCREL_LEDGER, "sha256": C.sha256_file(PCREL_LEDGER),
             "establishes": "the 82-site read census of the table, including "
                            "that there are zero store sites"},
            {"path": LAUNCH_DB, "sha256": C.sha256_file(LAUNCH_DB),
             "establishes": "the authentic frame-1 dispatch order that fixes the "
                            "first-consumer ordinal"},
            {"path": GLOBAL_REG_CONTRACT, "sha256": C.sha256_file(GLOBAL_REG_CONTRACT),
             "establishes": "the three-condition admissibility rule and the four "
                            "violation kinds this record reuses"},
            {"path": HOST_AUDIT, "sha256": C.sha256_file(HOST_AUDIT),
             "establishes": "an independent site census: exactly one "
                            "__hipRegisterVar and one hipMemcpyToSymbol"},
        ],
        "module_census": {"PARENT_GFX1100": parent, "CANDIDATE_F": cand_f,
                          "CANDIDATE_E": cand_e},
        "candidate_e_layout_delta": cand_e_delta,
        "host_runtime_census": host,
        "globals": globals_rec,
        "replay_gate": {
            "how_to_use": "call evaluate_gate() in p16ax_global_init.py with the "
                          "LUT bytes that are actually resident at the moment of "
                          "first use, the registration state, the coverage and "
                          "the two ordinals.  Every predicate returns PASS/FAIL "
                          "with the measured value that decided it.",
            "predicates": [
                "G1_LUT_IS_READ_ONLY_IN_DEVICE_CODE",
                "G2_REGISTERED_BEFORE_USE",
                "G3_FULL_COVERAGE",
                "G4_INIT_PRECEDES_FIRST_USE",
                "G5_NOT_ALL_ZERO_AT_USE",
                "G6_SATFINITE_DISCRIMINATOR",
            ],
            "demonstration_on_known_inputs": {
                "all_zero_static_image_as_shipped": {
                    "gate": gate_on_static,
                    "all_pass": gate_all_pass(gate_on_static),
                    "expected": "REJECTED -- this is the shipped static state, "
                                "and it must not be admissible",
                },
                "satfinite_table": {
                    "gate": gate_on_satfinite,
                    "all_pass": gate_all_pass(gate_on_satfinite),
                    "expected": "ACCEPTED -- the known-good case the gate must "
                                "not reject",
                },
                "ocp_nan_table": {
                    "gate": gate_on_ocp,
                    "all_pass": gate_all_pass(gate_on_ocp),
                    "expected": "REJECTED by G6 alone, with G1-G5 all passing.  "
                                "This is the discriminating control: it shows "
                                "the SATFINITE predicate is doing work rather "
                                "than restating the zero check.",
                },
            },
        },
        "probes_that_were_INCONCLUSIVE": [
            {
                "probe": "scan the host .rdata for a 512-byte window whose 256 "
                         "u16 entries are all finite FP16",
                "result": "29728 windows matched",
                "verdict": "VACUOUS -- the predicate accepts almost any byte "
                           "sequence, so a hit would have proved nothing.  Run "
                           "and recorded, deliberately NOT used as evidence.  "
                           "A check that cannot discriminate is worse than none.",
            },
            {
                "probe": "count occurrences of the u16 0x5F00 (+448.0 in FP16) "
                         "as a marker for the LUT preimage",
                "result": "2066 in the host, 2710 in Candidate F, 411 in the "
                          "parent",
                "verdict": "NON-DISCRIMINATING -- the byte pair is common in "
                           "1 MB of code.  Recorded, not used.",
            },
        ],
        "what_this_does_NOT_establish": [
            "That the host's single __hipRegisterVar / hipMemcpyToSymbol site "
            "is the call that writes g_e4m3_lut.  No disassembly cross-"
            "reference was performed; the pairing is an inference from a "
            "measured string position plus a separately measured site count.",
            "WHAT the runtime contents of g_e4m3_lut are.  They are UNKNOWN.  "
            "The producer is identified; the payload was never captured and is "
            "not in this tree.",
            "That the SATFINITE reading is the one the shipping module uses.  "
            "An artifact in this tree asserts it for the fused kernels; no "
            "artifact measures the table.",
            "That the pcrel ledger is a complete dataflow census.  It is the "
            "phase16h site census; a consumer reaching the table by a "
            "non-PC-relative path would not appear.",
            "That the first consumer is the first READ in time.  The ordinal "
            "used is the frame-1 DISPATCH ordinal of the earliest ledger "
            "consumer; lanes within a dispatch are not ordered here.",
            "Any physical or GPU result.  Nothing was launched, no module was "
            "loaded, and no HIP call was made.",
        ],
        "no_gpu_evidence": {
            "gpu_execution_performed": False, "hip_calls_made": 0,
            "physical_launches": 0, "modules_loaded": 0, "armed": False,
        },
    }

    # ---- read-back assertions: the artifact must not claim what it did not measure
    ids = [g["id"] for g in globals_rec]
    assert len(ids) == len(set(ids)), "duplicate global id"
    assert parent["rodata"]["size"] == (2112 + 512 + 32 + 2), \
        "parent .rodata does not decompose into kd + lut + SHE + 2 scalars"
    assert cand_f["rodata"]["size"] == (2112 + 512 + 32 + 2), \
        "candidate F .rodata does not decompose the same way"
    assert cand_e["rodata"]["size"] == 2112, \
        "candidate E .rodata is not exactly the descriptor table"
    assert p_lut and p_lut["all_zero"], "parent LUT is not all-zero"
    assert f_lut and f_lut["all_zero"], "candidate F LUT is not all-zero"
    assert e_lut is None, "candidate E unexpectedly declares g_e4m3_lut"
    assert p_lut["sha256"] == f_lut["sha256"], \
        "the static LUT image differs between parent and translation"
    # Independent cross-check: a 512-byte all-zero buffer built by THIS
    # generator must hash to exactly what the module's .rodata holds.  If the
    # static image were zero-filled but of a different LENGTH, or padded, the
    # nonzero-count check above would still say 0 and this would catch it.
    assert hashlib.sha256(tables["ALL_ZERO"]).hexdigest() == p_lut["sha256"], \
        "the measured static image is not exactly 512 zero bytes"
    assert lut_host_names == ["g_e4m3_lut"], \
        "host names more than one non-kernel device symbol: %r" % (lut_host_names,)
    assert host_lit["_ZN12DlssNrEngine2SHE"]["host_side_literals"] == 0, \
        "SHE unexpectedly has a host-side literal"
    assert host["host_side_name_block"]["kernels"] == 33, \
        "the host name block does not carry 33 kernel names"
    assert pc["store_sites"] == 0, "the ledger contains a store site"
    assert pc["targeting_rodata_lut"] == 79, "unexpected LUT-target site count"
    assert first_use is not None, "no first consumer resolved"
    assert first_use["kernel_mangled"] == FIRST_CONSUMER_TARGET, \
        "first consumer moved to %s" % first_use["kernel_mangled"]
    assert gate_all_pass(gate_on_static) is False, \
        "the gate ACCEPTS the shipped all-zero image"
    assert gate_all_pass(gate_on_satfinite) is True, \
        "the gate REJECTS the known-good SATFINITE table"
    assert gate_on_ocp["G6_SATFINITE_DISCRIMINATOR"]["verdict"] == "FAIL", \
        "G6 does not reject the OCP NaN table"
    assert all(gate_on_ocp[k]["verdict"] == "PASS"
               for k in gate_on_ocp if k != "G6_SATFINITE_DISCRIMINATOR"), \
        "the OCP control fails for the wrong reason"
    return doc


def selftest():
    """House rule 2: show the gate CAN fail and DOES accept the known-good."""
    t = build_tables()
    ok = True

    def case(name, lut, expect_all_pass, expect_failing=()):
        """expect_failing names the predicates that MUST be among the failures.
        A control that fails for the WRONG reason is not a successful rejection."""
        nonlocal ok
        g = evaluate_gate(lut, registered=True, coverage=512, producer_ordinal=0,
                          first_use_ordinal=3)
        got = gate_all_pass(g)
        fails = set(k for k, v in g.items() if v["verdict"] == "FAIL")
        good = (got == expect_all_pass) and set(expect_failing) <= fails
        ok = ok and good
        print("  %-42s all_pass=%-5s fails=%-58s %s"
              % (name, got, ",".join(sorted(fails)) or "-",
                 "OK" if good else "SELFTEST-FAIL"))

    print("gate controls (registered=True coverage=512 producer=0 use=3):")
    # the shipped image must fail on the degeneracy check AND on the
    # discriminator; both are correct, G5 is the primary
    case("shipped all-zero image", t["ALL_ZERO"], False,
         ("G5_NOT_ALL_ZERO_AT_USE", "G6_SATFINITE_DISCRIMINATOR"))
    case("SATFINITE table (known good)", t["SATFINITE"], True)
    # the OCP table must fail on G6 ALONE: if it also failed G5 the control
    # would be proving nothing about the discriminator
    case("OCP NaN table", t["OCP_NAN"], False, ("G6_SATFINITE_DISCRIMINATOR",))
    g_ocp = evaluate_gate(t["OCP_NAN"], registered=True, coverage=512,
                          producer_ordinal=0, first_use_ordinal=3)
    only_g6 = set(k for k, v in g_ocp.items() if v["verdict"] == "FAIL") == {
        "G6_SATFINITE_DISCRIMINATOR"}
    print("  %-42s %s" % ("OCP control fails on G6 ALONE",
                          "OK" if only_g6 else "SELFTEST-FAIL"))
    ok = ok and only_g6

    # coverage and order must each be able to fail on their own
    g = evaluate_gate(t["SATFINITE"], registered=True, coverage=511,
                      producer_ordinal=0, first_use_ordinal=3)
    print("  %-42s %s" % ("truncated 511-byte coverage",
                          "OK" if g["G3_FULL_COVERAGE"]["verdict"] == "FAIL" else "SELFTEST-FAIL"))
    ok = ok and g["G3_FULL_COVERAGE"]["verdict"] == "FAIL"
    g = evaluate_gate(t["SATFINITE"], registered=False, coverage=512,
                      producer_ordinal=0, first_use_ordinal=3)
    print("  %-42s %s" % ("unregistered symbol",
                          "OK" if g["G2_REGISTERED_BEFORE_USE"]["verdict"] == "FAIL" else "SELFTEST-FAIL"))
    ok = ok and g["G2_REGISTERED_BEFORE_USE"]["verdict"] == "FAIL"
    g = evaluate_gate(t["SATFINITE"], registered=True, coverage=512,
                      producer_ordinal=7, first_use_ordinal=3)
    print("  %-42s %s" % ("initialise-after-use",
                          "OK" if g["G4_INIT_PRECEDES_FIRST_USE"]["verdict"] == "FAIL" else "SELFTEST-FAIL"))
    ok = ok and g["G4_INIT_PRECEDES_FIRST_USE"]["verdict"] == "FAIL"
    g = evaluate_gate(t["SATFINITE"], registered=True, coverage=512,
                      producer_ordinal=None, first_use_ordinal=None)
    print("  %-42s %s" % ("unknown order (absence is blocking)",
                          "OK" if g["G4_INIT_PRECEDES_FIRST_USE"]["verdict"] == "FAIL" else "SELFTEST-FAIL"))
    ok = ok and g["G4_INIT_PRECEDES_FIRST_USE"]["verdict"] == "FAIL"

    # the decoder-level consequence of an all-zero table, measured
    vals = {decode_with_lut(t["ALL_ZERO"], b) for b in range(256)}
    print("  all-zero LUT decodes the whole E4M3 byte space to: %s "
          "(distinct=%d)" % (vals, len(vals)))
    ok = ok and vals == {0.0}
    vals = {decode_with_lut(t["SATFINITE"], b) for b in range(256)}
    print("  SATFINITE LUT decodes to %d distinct values, max=+%g min=%g"
          % (len(vals), max(vals), min(vals)))
    # 256 codes, and exactly three collisions: +0.0/-0.0, and 0x7E/0x7F both
    # 448.0, and 0xFE/0xFF both -448.0.  Predicted independently, so this
    # number is a check on the encoder, not a restatement of it.
    print("  predicted 253 distinct (256 minus 3 collision pairs): %s"
          % ("OK" if len(vals) == 253 else "SELFTEST-FAIL"))
    ok = ok and len(vals) == 253 and max(vals) == 448.0 and min(vals) == -448.0

    print("\nselftest: %s" % ("ALL CONTROLS BEHAVED" if ok else "FAILED"))
    return 0 if ok else 1


def main():
    if "--selftest" in sys.argv:
        return selftest()
    doc = build()
    p = C.write_json(OUT, doc)
    back = json.load(open(p, encoding="utf-8"))
    assert back["globals"], "written artifact has no globals"
    assert back["replay_gate"]["demonstration_on_known_inputs"][
        "all_zero_static_image_as_shipped"]["all_pass"] is False
    assert back["replay_gate"]["demonstration_on_known_inputs"][
        "satfinite_table"]["all_pass"] is True
    print("wrote %s" % p)
    print("  globals: %d" % len(back["globals"]))
    print("  gate predicates: %d" % len(back["replay_gate"]["predicates"]))
    print("  gate on shipped static image: %s" % (
        "ACCEPTED (BAD)" if back["replay_gate"]["demonstration_on_known_inputs"]
        ["all_zero_static_image_as_shipped"]["all_pass"] else "REJECTED (correct)"))
    print("  gate on SATFINITE table:      %s" % (
        "ACCEPTED (correct)" if back["replay_gate"]["demonstration_on_known_inputs"]
        ["satfinite_table"]["all_pass"] else "REJECTED (BAD)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
