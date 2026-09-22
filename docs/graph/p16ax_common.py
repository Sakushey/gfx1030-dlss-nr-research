#!/usr/bin/env python3
"""Phase 16AX / T-GRAPH (W5) -- shared loaders and evidence helpers.

HOST ONLY.  Zero GPU launches, zero HIP calls, zero amdgpu/amdhip64 modules
loaded.  Pure standard library: numpy is NOT installed in this environment.

Every SHA-256 this module reports is recomputed from the bytes on disk by
`sha256_file` in the session that calls it.  No digest is transcribed from a
downstream artefact and presented as a measurement.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def abspath(rel: str) -> str:
    return os.path.join(ROOT, rel.replace("/", os.sep))


def sha256_file(rel: str) -> str:
    """Recompute SHA-256 from the bytes on disk.  Never fabricated."""
    h = hashlib.sha256()
    with open(abspath(rel), "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(rel: str):
    with open(abspath(rel), "r", encoding="utf-8") as fh:
        return json.load(fh)


def exists(rel: str) -> bool:
    return os.path.exists(abspath(rel))


# ---------------------------------------------------------------- fact sources
LAUNCH_DB = "phase16_authentic_launch_db.csv"
SWIN_DECODE = "phase16_authentic_decode_swin.csv"
GRAPH_V0 = "p16an/native/NATIVE_GRAPH_V0.json"
IDENTITY_MAPPING = "p16an/native/IDENTITY_MAPPING_16AN.json"
MAPPING_VERDICT_16AO = "p16ao/native/mapping/MAPPING_UNIQUENESS_VERDICT.json"
FIRST_FRAME_FIELDS = "p16an/contracts/FIRST_FRAME_REQUIRED_FIELDS.json"
JOB_CONTRACT_REBASE = "p16an/contracts/JOB_CONTRACT_REBASE_V2.json"
GLOBAL_REG_CONTRACT = "p16ad/bridge/GLOBAL_REGISTRATION_CONTRACT.json"
GAP_TABLE = "p16ad/replay/AUTHENTIC_DATA_GAP_TABLE.json"
BLOB_TABLE = "p16at/raw_dump/RAW_DUMP_BLOB_TABLE.json"
RAW_DUMP_ARGS_16AW = "p16aw/raw_dump/RAW_DUMP_ARGSPEC_16AW.json"
WEIGHTS_INDEX = "p16an/native/_fetch/weights-index.json"
NETWORK_GRAPH = "p16an/native/_fetch/network-graph.json"
WEIGHT_AVAILABILITY = "p16ar/weights/WEIGHT_AVAILABILITY_MATRIX.json"
BLOCK39_AUDIT = "p16as/weights/BLOCK39_WEIGHT_PROVENANCE_AUDIT.json"
CODE_OBJECT = "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co"
SOURCE_REGISTER = "p16aw/sources/SOURCE_GROUNDING_REGISTER.json"
CANONICAL_TRACKS = "p16aw/state/CANONICAL_TRACKS_16AW.json"
WEIGHTS_PREIMAGE = "p16as/weights/weights_preimage.bin"
BLOCK39_MATRIX = "p16as/weights/pinned/block39-logical-effective.bin"
BLOCK39_BIAS = "p16as/weights/pinned/block39-logical-effective-bias.bin"

# Candidate-F .rodata object addresses, read from the code object's own
# .symtab in this session (see p16ax_global_init.py).  Recorded here only so
# the readers of this module can name a section offset without re-parsing.
CANDIDATE_F_RODATA_ADDR = 0x9F40
CANDIDATE_F_RODATA_SIZE = 2658
CANDIDATE_F_GE4M3_LUT_ADDR = 0xA780
CANDIDATE_F_GE4M3_LUT_SIZE = 512


# ---------------------------------------------------------------- ELF reader
def elf_sections(path_rel: str):
    """Minimal, dependency-free ELF64 little-endian section + symbol reader.

    Returns (sections, symbols); each section is a dict, each symbol is a
    dict.  Raises on anything that is not a little-endian ELF64, so a silently
    mis-parsed file cannot be read as an empty-but-valid one.
    """
    with open(abspath(path_rel), "rb") as fh:
        b = fh.read()
    if b[:4] != b"\x7fELF":
        raise ValueError("not an ELF: " + path_rel)
    if b[4] != 2:
        raise ValueError("not ELF64: " + path_rel)
    if b[5] != 1:
        raise ValueError("not little-endian: " + path_rel)
    e_shoff = struct.unpack_from("<Q", b, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", b, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", b, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", b, 0x3E)[0]
    if e_shentsize != 64 or e_shnum == 0:
        raise ValueError("unexpected section header geometry: " + path_rel)
    secs = []
    for i in range(e_shnum):
        f = struct.unpack_from("<IIQQQQIIQQ", b, e_shoff + i * e_shentsize)
        secs.append(dict(index=i, name_off=f[0], type=f[1], flags=f[2],
                         addr=f[3], offset=f[4], size=f[5], link=f[6],
                         info=f[7], align=f[8], entsize=f[9]))
    st = secs[e_shstrndx]

    def cstr(base, x):
        end = b.index(b"\0", base + x)
        return b[base + x:end].decode("utf-8", "replace")

    for s in secs:
        s["name"] = cstr(st["offset"], s["name_off"])
    syms = []
    for s in secs:
        if s["type"] != 2:          # SHT_SYMTAB only; .dynsym is not asked for
            continue
        strt = secs[s["link"]]
        for i in range(s["size"] // 24):
            o = s["offset"] + i * 24
            nameo, info, other, shndx, value, size = struct.unpack_from(
                "<IBBHQQ", b, o)
            syms.append(dict(name=cstr(strt["offset"], nameo),
                             bind=info >> 4, type=info & 0xF, shndx=shndx,
                             value=value, size=size))
    return secs, syms, b


def section_bytes(path_rel: str, section_name: str):
    secs, _syms, b = elf_sections(path_rel)
    for s in secs:
        if s["name"] == section_name:
            if s["type"] == 8:      # NOBITS -- no bytes on disk by definition
                return s, b""
            return s, b[s["offset"]:s["offset"] + s["size"]]
    raise KeyError(section_name)


# ---------------------------------------------------------------- launch db
def load_launch_db():
    with open(abspath(LAUNCH_DB), newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def load_swin_decode():
    with open(abspath(SWIN_DECODE), newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


# ---------------------------------------------------------------- helpers
def quantile_counts(values):
    """Distinct-value census with counts, ordered by descending count then
    ascending value.  Used instead of a bare distinct-count so that a
    'distinct' claim can be re-read as the actual multiset."""
    counts = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    return sorted(({"value": k, "count": v} for k, v in counts.items()),
                  key=lambda d: (-d["count"], str(d["value"])))


def write_json(rel: str, obj):
    path = abspath(rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=1, sort_keys=False)
        fh.write("\n")
    return path
