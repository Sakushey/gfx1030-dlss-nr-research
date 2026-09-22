#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 16AX / T-SLOT5 -- Slot-5 Qualification V3: a SUBJECT-BOUND gate.

WHAT THIS REPLACES
------------------
`p16at/slot5/p16at_slot5_decision.py` decided 24 of 26 slot-5 questions by
comparing the world against string literals written into itself.  That is not a
gate: a gate that hardcodes its expected values certifies nothing about the
object it is nominally gating.  It cannot notice that the object was rebuilt,
that the expected output belongs to another experiment, or that a receipt came
from a different slot -- because it never looked at the object.

WHAT THIS DOES INSTEAD
----------------------
Every predicate loads real evidence from disk.  Every expected value is
recomputed in this process from the bytes of the artefact the experiment will
actually launch, and every declaration found anywhere in the package is
compared against that recomputation.  Nothing in this file is a digest, a size,
a count or a verdict about the current object.

The subject is declared in `SLOT5_SUBJECT_16AX.json`, which carries LOCATORS
(where to look), POINTERS (which key inside an artefact holds a fact), BINDINGS
(which artefact claims which identity value), SELECTORS (which role names the
artefact uses), METADATA FIELD NAMES, and the experiment's own required bounds
-- and no measured value at all.  `subject_declaration_is_locator_only`
enforces that mechanically.

STATUS VOCABULARY
-----------------
  PASS                            the evidence resolved and it agrees
  REFUSED                         the evidence is present and is not good enough,
                                  or absent where the contract requires it
  BLOCKED_BY_MEASURED_DEPENDENCY  a file this predicate must read does not exist
                                  yet; the absent path is named.  Absence is
                                  blocking -- it is never a silent pass.

The run verdict is QUALIFIED only if every predicate is PASS; REFUSED if any is
REFUSED; otherwise BLOCKED_BY_MEASURED_DEPENDENCY.

TAUTOLOGY RULE
--------------
If the two sides of a comparison resolve from ONE artefact through ONE pointer,
the comparison is tautological: agreement is guaranteed and certifies nothing.
Such a comparison is recorded with `tautological: true` and fails the run.  This
is why `identity()` returns an `F` carrying full provenance rather than a bare
value: a synthetic provenance label would hide exactly the tautology the rule
exists to catch.

HOST-ONLY.  This file makes no GPU call, launches nothing, and writes nothing
except its own output file.
"""

import datetime as dt
import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SUBJECT_FILE = os.path.join(HERE, "SLOT5_SUBJECT_16AX.json")
DEFAULT_OUT = os.path.join(HERE, "SLOT5_QUALIFICATION_V3.json")

PASS = "PASS"
REFUSED = "REFUSED"
BLOCKED = "BLOCKED_BY_MEASURED_DEPENDENCY"

V_QUALIFIED = "QUALIFIED"
V_REFUSED = "REFUSED"
V_BLOCKED = "BLOCKED_BY_MEASURED_DEPENDENCY"

IDENTITY_KINDS = (
    "experiment_id",
    "manifest_sha256",
    "code_object_sha256",
    "code_object_path",
    "text_section_sha256",
    "source_cpp_sha256",
    "source_header_sha256",
    "kernel_symbol",
    "harness_contract_sha256",
    "execute_descriptor_sha256",
    "descriptor_module_sha256",
    "expected_output_sha256",
)

MUST_BE_BOUND = (
    "experiment_id",
    "manifest_sha256",
    "code_object_sha256",
    "code_object_path",
    "text_section_sha256",
    "source_cpp_sha256",
    "source_header_sha256",
    "kernel_symbol",
    "harness_contract_sha256",
    "execute_descriptor_sha256",
    "descriptor_module_sha256",
    "expected_output_sha256",
)

DTYPE_WIDTH_BYTES = {
    "fp8_e4m3fn": 1, "fp8_e5m2": 1, "fp16": 2, "bf16": 2,
    "fp32": 4, "fp64": 8, "u8": 1, "i8": 1, "u16": 2, "i16": 2,
    "u32": 4, "i32": 4, "u64": 8, "i64": 8,
}

R = {
    "not_a_file": "the file this predicate must read exists on disk",
    "unreadable": "the file can be read as bytes in this process",
    "not_json": "the artefact parses in the reader its own extension selects",
    "wrong_type": "the artefact has the shape this predicate is declared to read",
    "missing_key": "the artefact carries the key this predicate is declared to read",
    "no_binding": "some artefact in the package binds this identity to the subject",
    "foreign_subject": "every declaration of the subject's identity carries the subject's own value",
    "digest_disagreement": "a declared digest equals the digest of the bytes it names",
    "count_disagreement": "a declared count equals the count of the records it heads",
    "not_met": "the measured value satisfies the experiment's declared requirement",
    "malformed": "the artefact is well-formed for its declared schema",
    "vocabulary": "every stated value is inside the vocabulary the artefact itself declares",
    "stale": "the evidence describes the current object, not a superseded one",
}

# Requirements whose failure means "the evidence is not on disk yet".  Every
# other requirement means "the evidence is on disk and is not good enough".
ABSENT_REQUIREMENTS = (R["not_a_file"], R["unreadable"])

PASS_VERDICTS = ("PASS", "OK", "PROVEN", "MEASURED", "BUILT")


class Dep(Exception):
    """A predicate could not be decided, and says which requirement failed."""

    def __init__(self, requirement, locator, detail, kind=None):
        Exception.__init__(self, "%s: %s" % (requirement, detail))
        self.requirement = requirement
        self.locator = locator
        self.detail = detail
        self.kind = kind or (BLOCKED if requirement in ABSENT_REQUIREMENTS else REFUSED)


class F(object):
    """One side of a comparison, WITH PROVENANCE.

    `artifact` is the artefact the value came from and `pointer` is how it was
    obtained inside that artefact.  Two sides sharing both are tautological.  A
    bare value cannot be audited for tautology, which is why this class exists
    and why `identity()` never returns one."""

    __slots__ = ("artifact", "pointer", "value")

    def __init__(self, artifact, pointer, value):
        self.artifact = artifact
        self.pointer = pointer
        self.value = value


class Ledger(object):
    def __init__(self):
        self.rows = []
        # set by the Gate: a normaliser that knows which roots count as "here",
        # so a package staged under a different root still compares paths.
        self.norm = None

    def same(self, a, b, why):
        taut = (a.artifact == b.artifact) and (a.pointer == b.pointer)
        try:
            equal = a.value == b.value
        except Exception:                                     # noqa: BLE001
            equal = False
        self.rows.append({
            "why": why,
            "left": {"artifact": a.artifact, "pointer": a.pointer, "value": _short(a.value)},
            "right": {"artifact": b.artifact, "pointer": b.pointer, "value": _short(b.value)},
            "equal": bool(equal), "tautological": bool(taut)})
        return bool(equal)

    def same_path(self, a, b, why):
        na, nb = (self.norm or _norm_path)(a.value), (self.norm or _norm_path)(b.value)
        taut = (a.artifact == b.artifact) and (a.pointer == b.pointer)
        self.rows.append({
            "why": why,
            "left": {"artifact": a.artifact, "pointer": a.pointer,
                     "value": _short(a.value), "normalised": na},
            "right": {"artifact": b.artifact, "pointer": b.pointer,
                      "value": _short(b.value), "normalised": nb},
            "equal": bool(na == nb), "tautological": bool(taut),
            "compared_as": "path, separators and root prefix normalised"})
        return bool(na == nb)

    def contains(self, a, b, why):
        """Left is a token that must appear inside right, which is a longer
        string (a device arch inside a target triple).  Recorded as its own
        relation rather than forced through equality, where it would either
        always fail or have to be faked by rewriting one side."""
        taut = (a.artifact == b.artifact) and (a.pointer == b.pointer)
        try:
            ok = isinstance(a.value, str) and isinstance(b.value, str) and a.value in b.value
        except Exception:                                     # noqa: BLE001
            ok = False
        self.rows.append({
            "why": why,
            "left": {"artifact": a.artifact, "pointer": a.pointer, "value": _short(a.value)},
            "right": {"artifact": b.artifact, "pointer": b.pointer, "value": _short(b.value)},
            "equal": bool(ok), "tautological": bool(taut),
            "compared_as": "containment, not equality"})
        return bool(ok)

    def tautologies(self):
        return [r for r in self.rows if r["tautological"]]

    def disagreements(self):
        return [r for r in self.rows if not r["equal"]]

    def duplicate_lineage(self):
        """Two rows whose two sides are the same pair of (artefact, pointer)
        are one comparison run twice: the house rule that independence is per
        mechanism, applied to this gate's own ledger."""
        seen, dup = {}, []
        for i, r in enumerate(self.rows):
            key = (r["left"]["artifact"], r["left"]["pointer"],
                   r["right"]["artifact"], r["right"]["pointer"])
            if key in seen:
                dup.append({"rows": [seen[key], i], "provenance": list(key),
                            "why": r["why"]})
            else:
                seen[key] = i
        return dup


def _short(v):
    if isinstance(v, str) and len(v) > 200:
        return v[:200] + "..."
    if isinstance(v, list) and len(v) > 8:
        return v[:8] + ["...(%d more)" % (len(v) - 8)]
    return v


def _norm_path(v):
    return _norm_path_under(v, (ROOT,))


def _norm_path_under(v, prefixes):
    """Normalise a path for comparison: separators, leading ./, and any prefix
    in `prefixes` (the project root, and whatever root this run treats as
    here).  A package staged under its own root can then be compared against a
    declaration that is relative to that root, which is what makes the positive
    control a real run of this gate rather than a special case of it."""
    if not isinstance(v, str) or not v:
        return v
    s = v.replace("\\", "/")
    while s.startswith("./"):
        s = s[2:]
    low = s.lower()
    for pre in prefixes:
        p = pre.replace("\\", "/").lower().rstrip("/") + "/"
        if low.startswith(p):
            s = s[len(p):]
            break
    return os.path.normcase(s.strip("/"))


# --------------------------------------------------------------------------
# byte-level readers -- every digest in this file is recomputed from bytes
# --------------------------------------------------------------------------

def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def utf8_json_sha256(obj):
    return sha256_bytes(json.dumps(obj).encode("utf-8"))


def parse_kv_text(text, locator):
    out = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            raise Dep(R["malformed"], locator, "not a key=value line: %r" % s[:60])
        k, _sep, v = s.partition("=")
        k = k.strip()
        if not k:
            raise Dep(R["malformed"], locator, "empty key in line %r" % s[:60])
        if k in out:
            raise Dep(R["malformed"], locator,
                      "duplicate key %r; a duplicated key makes the file ambiguous and the "
                      "last writer silent" % k)
        out[k] = v.strip()
    if not out:
        raise Dep(R["malformed"], locator, "no key=value lines in this text file")
    return out


def elf_sections(blob):
    """ELF64 section headers -> {name: (file_offset, size, type)}."""
    if blob[:4] != b"\x7fELF":
        raise ValueError("not an ELF object")
    if blob[4] != 2:
        raise ValueError("not ELF64 (EI_CLASS=%d)" % blob[4])
    hdr = struct.unpack_from("<16sHHIQQQIHHHHHH", blob, 0)
    e_shoff, e_shentsize, e_shnum, e_shstrndx = hdr[6], hdr[11], hdr[12], hdr[13]
    if e_shoff == 0 or e_shnum == 0:
        raise ValueError("object has no section header table")
    raw = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ, _f, _a, off, size, _l, _i, _al, _e = struct.unpack_from(
            "<IIQQQQIIQQ", blob, o)
        raw.append({"name_off": name, "type": typ, "off": off, "size": size})
    stro = raw[e_shstrndx]
    st = blob[stro["off"]:stro["off"] + stro["size"]]
    out = {}
    for s in raw:
        nm = st[s["name_off"]:].split(b"\x00")[0].decode("utf-8", "replace")
        if nm:
            out[nm] = (s["off"], s["size"], s["type"])
    return out


def elf_note_bodies(blob):
    secs = elf_sections(blob)
    if ".note" not in secs:
        raise ValueError("object has no .note section")
    off, size, _t = secs[".note"]
    o, end, out = off, off + size, []
    while o + 12 <= end:
        namesz, descsz, ntype = struct.unpack_from("<III", blob, o)
        o += 12
        name = blob[o:o + namesz].split(b"\x00")[0].decode("utf-8", "replace")
        o += (namesz + 3) // 4 * 4
        body = blob[o:o + descsz]
        o += (descsz + 3) // 4 * 4
        out.append((name, ntype, body))
    return out


def mp_decode(buf, pos):
    """A minimal MessagePack reader: enough for an AMDHSA metadata note and
    nothing more.  Deliberately self-contained -- this gate re-measures the ABI
    of the object from the object's own bytes with no external process and no
    import that another phase owns."""
    b = buf[pos]
    pos += 1
    if b <= 0x7f:
        return b, pos
    if b >= 0xe0:
        return b - 0x100, pos
    if 0x80 <= b <= 0x8f:
        out = {}
        for _ in range(b & 0x0f):
            k, pos = mp_decode(buf, pos)
            v, pos = mp_decode(buf, pos)
            out[k] = v
        return out, pos
    if 0x90 <= b <= 0x9f:
        out = []
        for _ in range(b & 0x0f):
            v, pos = mp_decode(buf, pos)
            out.append(v)
        return out, pos
    if 0xa0 <= b <= 0xbf:
        n = b & 0x1f
        return buf[pos:pos + n].decode("utf-8", "replace"), pos + n
    if b == 0xc0:
        return None, pos
    if b == 0xc2:
        return False, pos
    if b == 0xc3:
        return True, pos
    if b == 0xc4:
        n = buf[pos]
        return buf[pos + 1:pos + 1 + n], pos + 1 + n
    if b == 0xc5:
        n = struct.unpack_from(">H", buf, pos)[0]
        return buf[pos + 2:pos + 2 + n], pos + 2 + n
    if b == 0xc6:
        n = struct.unpack_from(">I", buf, pos)[0]
        return buf[pos + 4:pos + 4 + n], pos + 4 + n
    if b == 0xca:
        return struct.unpack_from(">f", buf, pos)[0], pos + 4
    if b == 0xcb:
        return struct.unpack_from(">d", buf, pos)[0], pos + 8
    if b == 0xcc:
        return buf[pos], pos + 1
    if b == 0xcd:
        return struct.unpack_from(">H", buf, pos)[0], pos + 2
    if b == 0xce:
        return struct.unpack_from(">I", buf, pos)[0], pos + 4
    if b == 0xcf:
        return struct.unpack_from(">Q", buf, pos)[0], pos + 8
    if b == 0xd0:
        return struct.unpack_from(">b", buf, pos)[0], pos + 1
    if b == 0xd1:
        return struct.unpack_from(">h", buf, pos)[0], pos + 2
    if b == 0xd2:
        return struct.unpack_from(">i", buf, pos)[0], pos + 4
    if b == 0xd3:
        return struct.unpack_from(">q", buf, pos)[0], pos + 8
    if b == 0xd9:
        n = buf[pos]
        return buf[pos + 1:pos + 1 + n].decode("utf-8", "replace"), pos + 1 + n
    if b == 0xda:
        n = struct.unpack_from(">H", buf, pos)[0]
        return buf[pos + 2:pos + 2 + n].decode("utf-8", "replace"), pos + 2 + n
    if b == 0xdb:
        n = struct.unpack_from(">I", buf, pos)[0]
        return buf[pos + 4:pos + 4 + n].decode("utf-8", "replace"), pos + 4 + n
    if b in (0xdc, 0xdd):
        n = struct.unpack_from(">H" if b == 0xdc else ">I", buf, pos)[0]
        pos += 2 if b == 0xdc else 4
        out = []
        for _ in range(n):
            v, pos = mp_decode(buf, pos)
            out.append(v)
        return out, pos
    if b in (0xde, 0xdf):
        n = struct.unpack_from(">H" if b == 0xde else ">I", buf, pos)[0]
        pos += 2 if b == 0xde else 4
        out = {}
        for _ in range(n):
            k, pos = mp_decode(buf, pos)
            v, pos = mp_decode(buf, pos)
            out[k] = v
        return out, pos
    raise ValueError("unhandled MessagePack byte 0x%02x at %d" % (b, pos - 1))


def amdhsa_metadata(blob):
    """Decode the `amdhsa.kernels` list out of the object's own metadata note.

    This is the ground truth for kernel identity and ABI: it is inside the
    object.  No external tool, no cached extractor artifact, no second file."""
    for name, ntype, body in elf_note_bodies(blob):
        if ntype != 32 or "AMDGPU" not in name:
            continue
        md, pos = mp_decode(body, 0)
        if not isinstance(md, dict):
            raise ValueError("the AMDHSA metadata note did not decode to a map")
        ks = md.get("amdhsa.kernels")
        if not isinstance(ks, list) or not ks:
            raise ValueError("the AMDHSA metadata note names no kernels")
        return {"kernels": ks, "target": md.get("amdhsa.target"),
                "version": md.get("amdhsa.version"), "bytes_consumed": pos,
                "note_bytes": len(body)}
    raise ValueError("no AMDGPU metadata note (type 32) in this object")


def pe_imported_dlls(blob):
    """DLL names in a PE32+ image's import table, walked from the headers."""
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        raise ValueError("not a PE image")
    e_lfanew = struct.unpack_from("<I", blob, 0x3C)[0]
    if blob[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("no PE signature at e_lfanew=%d" % e_lfanew)
    coff = e_lfanew + 4
    n_sections = struct.unpack_from("<H", blob, coff + 2)[0]
    opt_size = struct.unpack_from("<H", blob, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", blob, opt)[0]
    if magic != 0x20B:
        raise ValueError("not PE32+ (optional header magic 0x%x)" % magic)
    rva, _size = struct.unpack_from("<II", blob, opt + 112 + 8 * 1)
    if rva == 0:
        return []
    secs = []
    st = opt + opt_size
    for i in range(n_sections):
        vsize, vaddr, rawsize, praw = struct.unpack_from("<IIII", blob, st + i * 40 + 8)
        secs.append((vaddr, max(vsize, rawsize), praw))

    def off_of(r):
        for vaddr, vsz, praw in secs:
            if vaddr <= r < vaddr + vsz:
                return r - vaddr + praw
        raise ValueError("RVA 0x%x is in no section" % r)

    out = []
    o = off_of(rva)
    while True:
        entry = struct.unpack_from("<IIIII", blob, o)
        if entry == (0, 0, 0, 0, 0):
            break
        if entry[3] == 0:
            break
        no = off_of(entry[3])
        end = blob.find(b"\x00", no)
        if end < 0:
            raise ValueError("unterminated DLL name at 0x%x" % no)
        out.append(blob[no:end].decode("ascii", "replace"))
        o += 20
    return out


def looks_like_hip(dll):
    return "hip" in dll.lower()


class Gate(object):
    def __init__(self, evidence_root=ROOT, subject_file=SUBJECT_FILE, now=None):
        self.root = os.path.abspath(evidence_root)
        self.subject_file = os.path.abspath(subject_file)
        self.now = now
        self.preds = []
        self.led = Ledger()
        self.led.norm = self.norm_path
        self._cache = {}
        self._bcache = {}
        # a declared artefact that is ON DISK but does not state the identity it
        # was declared to state.  Recorded for every predicate that asks the
        # question; FATAL only for the artefact's own predicate, or where the
        # predicate is the package-wide statement of that identity.  One
        # artefact's omission must not be re-reported as six unrelated defects.
        self.binding_gaps = []
        self.self_source = open(os.path.abspath(__file__), "rb").read()

    # -- the subject declaration -------------------------------------------
    def subject(self):
        return self.json_file(self.subject_file)

    def loc(self, name):
        locs = self.subject().get("locators")
        if not isinstance(locs, dict) or name not in locs:
            raise Dep(R["missing_key"], self.subject_file,
                      "the subject declaration declares no locator %r" % name)
        v = locs[name]
        if not isinstance(v, str) or not v:
            raise Dep(R["wrong_type"], self.subject_file,
                      "locator %r is not a non-empty string" % name)
        return v

    def optional_loc(self, name):
        v = (self.subject().get("locators") or {}).get(name)
        return v if isinstance(v, str) and v else None

    def pointer(self, group, name):
        g = ((self.subject().get("pointers") or {}).get(group))
        if not isinstance(g, dict) or name not in g:
            raise Dep(R["missing_key"], self.subject_file,
                      "the subject declaration declares no pointer %s.%s, so this gate "
                      "has no declared place to read that fact from" % (group, name))
        return g[name]

    def selector(self, name):
        s = (self.subject().get("selectors") or {}).get(name)
        if not isinstance(s, str) or not s:
            raise Dep(R["missing_key"], self.subject_file,
                      "the subject declaration declares no selector %r" % name)
        return s

    def terms(self, group, name):
        """A declared sub-vocabulary: a list of the artefact's OWN vocabulary
        terms that carry a particular MEANING (e.g. which of a disposition
        artefact's dispositions mean 'no answer yet').  Declared rather than
        written here, so the gate carries no term of its own; and required to be
        non-empty, so a declaration cannot switch a rule off by emptying it."""
        g = ((self.subject().get("vocabularies") or {}).get(group))
        if not isinstance(g, dict) or name not in g:
            raise Dep(R["missing_key"], self.subject_file,
                      "the subject declaration declares no vocabularies.%s.%s, so the meaning "
                      "of that artefact's own terms would have to be assumed" % (group, name))
        v = g[name]
        if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
            raise Dep(R["vocabulary"], self.subject_file,
                      "vocabularies.%s.%s is not a non-empty list of terms; an empty list would "
                      "turn this rule off while looking like a declaration" % (group, name))
        return v

    def bounds(self):
        b = self.subject().get("required_bounds")
        if not isinstance(b, dict) or not b:
            raise Dep(R["missing_key"], self.subject_file,
                      "the subject declaration declares no required_bounds block, so "
                      "there is no stated requirement for a measurement to satisfy")
        return b

    def metadata_fields(self):
        m = self.subject().get("metadata_fields")
        if not isinstance(m, dict) or not m:
            raise Dep(R["missing_key"], self.subject_file,
                      "the subject declaration declares no metadata_fields map, so a "
                      "recorded resource cannot be bound to the object's own note")
        return m

    # -- reading artefacts --------------------------------------------------
    def path_of(self, locator):
        return os.path.join(self.root, locator.replace("/", os.sep))

    def to_locator(self, p):
        """An absolute or relative path taken from an artefact -> a locator that
        resolves under this gate's evidence root."""
        if not isinstance(p, str) or not p:
            return p
        q = os.path.normpath(p.replace("/", os.sep))
        for base in (self.root, ROOT):
            try:
                r = os.path.relpath(q, base)
            except ValueError:
                continue
            if r != ".." and not r.startswith(".." + os.sep):
                return r.replace(os.sep, "/")
        return q.replace(os.sep, "/")

    def norm_path(self, v):
        """Path normalisation for THIS run: both the project root and this run's
        evidence root count as here, so a package staged elsewhere still has its
        paths compared rather than rejected for living in a different folder.

        The MOST SPECIFIC root is tried first.  A run whose evidence root lives
        under the project root matches BOTH prefixes, and stripping the shorter one
        would leave the fixture's own folder name inside the normalised path -- so
        a path the package states about itself and the same path stated relative to
        the project root would not compare.  This changes no verdict when the two
        roots are equal, which is every run of the real tree."""
        return _norm_path_under(v, tuple(sorted((ROOT, self.root), key=len, reverse=True)))

    def raw(self, locator):
        c = self._cache.setdefault(locator, {})
        if "raw" in c:
            return c["raw"]
        p = self.path_of(locator)
        if not os.path.isfile(p):
            raise Dep(R["not_a_file"], locator, "no file at %s" % p)
        try:
            with open(p, "rb") as fh:
                b = fh.read()
        except OSError as exc:
            raise Dep(R["unreadable"], locator, "%s" % exc)
        c["raw"] = b
        return b

    def raw_sha(self, locator):
        return sha256_bytes(self.raw(locator))

    def json_file(self, path):
        c = self._cache.setdefault(path, {})
        if "doc" in c:
            return c["doc"]
        if not os.path.isfile(path):
            raise Dep(R["not_a_file"], path, "no file at %s" % path)
        try:
            with open(path, "rb") as fh:
                b = fh.read()
        except OSError as exc:
            raise Dep(R["unreadable"], path, "%s" % exc)
        try:
            doc = json.loads(b.decode("utf-8"))
        except Exception as exc:                              # noqa: BLE001
            raise Dep(R["not_json"], path,
                      "not JSON: %s: %s" % (type(exc).__name__, exc))
        c["doc"] = doc
        return doc

    def json(self, locator):
        """Read an artefact as a document.  The reader is chosen by the
        artefact's own extension: `.jsonl` is a record list, `.txt`/`.kv`/`.cfg`
        is `key = value` text, everything else is JSON.  A gate that can only
        read JSON silently skips every artefact that is not JSON."""
        low = locator.lower()
        if low.endswith(".jsonl"):
            rows = []
            for i, line in enumerate(self.raw(locator).decode("utf-8").splitlines(), 1):
                s = line.strip()
                if not s:
                    continue
                try:
                    rows.append(json.loads(s))
                except Exception as exc:                      # noqa: BLE001
                    raise Dep(R["not_json"], locator,
                              "line %d is not JSON: %s" % (i, exc))
            return rows
        if low.endswith((".txt", ".kv", ".cfg")):
            try:
                return parse_kv_text(self.raw(locator).decode("utf-8"), locator)
            except Dep:
                raise
            except Exception as exc:                          # noqa: BLE001
                raise Dep(R["malformed"], locator,
                          "not key=value text: %s: %s" % (type(exc).__name__, exc))
        return self.json_file(self.path_of(locator))

    def need(self, doc, locator, key, kind=None):
        if not isinstance(doc, dict):
            raise Dep(R["wrong_type"], locator,
                      "expected a map to read %r from, got %s" % (key, type(doc).__name__))
        if key not in doc or doc[key] is None:
            raise Dep(R["missing_key"], locator,
                      "the artefact carries no %r key%s"
                      % (key, " with a value" if key in doc else ""))
        v = doc[key]
        if kind is not None and not isinstance(v, kind):
            raise Dep(R["wrong_type"], locator,
                      "%r is %s, expected %s" % (key, type(v).__name__, getattr(kind, "__name__", kind)))
        return v

    def walk(self, locator, pointer):
        """Resolve a `/`-separated pointer inside a declared artefact.  The
        separator is `/` and not `.` because real keys in this project's
        artefacts contain dots (e.g. `expected_out_q.bin`), and a separator that
        appears inside keys makes a pointer ambiguous."""
        cur = self.json(locator)
        for part in pointer.split("/"):
            if isinstance(cur, list):
                try:
                    i = int(part)
                except ValueError:
                    raise Dep(R["missing_key"], locator,
                              "pointer %r indexes a list with %r" % (pointer, part))
                if i < 0 or i >= len(cur):
                    raise Dep(R["missing_key"], locator,
                              "pointer %r indexes %d of %d" % (pointer, i, len(cur)))
                cur = cur[i]
            elif isinstance(cur, dict):
                if part not in cur:
                    raise Dep(R["missing_key"], locator,
                              "pointer %r: the artefact carries no %r key (it has %s)"
                              % (pointer, part, ", ".join(sorted(cur.keys())[:14])))
                cur = cur[part]
            else:
                raise Dep(R["wrong_type"], locator,
                          "pointer %r descends into a %s" % (pointer, type(cur).__name__))
        return cur

    def at(self, artifact, pointer):
        """-> F(artifact, pointer, value)"""
        return F(artifact, pointer, self.walk(self.loc(artifact), pointer))

    def vocabulary(self, doc, locator, key):
        v = self.need(doc, locator, key, list)
        if not v or not all(isinstance(x, str) for x in v):
            raise Dep(R["malformed"], locator, "%r is not a non-empty list of strings" % key)
        return v

    def in_vocab(self, doc, locator, key, value, vocab):
        if value not in vocab:
            raise Dep(R["vocabulary"], locator,
                      "%s = %r, which is not in the vocabulary this artefact declares (%s)"
                      % (key, value, ", ".join(vocab)))
        return value

    # -- the subject's own identity, recomputed from bytes -------------------
    def manifest_loc(self):
        return self.loc("experiment_manifest")

    def experiment_id(self):
        loc = self.manifest_loc()
        eid = self.need(self.json(loc), loc, "experiment_id", str)
        if not eid:
            raise Dep(R["wrong_type"], loc, "experiment_id is empty")
        return eid

    def object_tuple(self):
        loc = self.loc("code_object")
        blob = self.raw(loc)
        return loc, self.path_of(loc), blob, sha256_bytes(blob), elf_sections(blob)

    def text_section(self):
        _loc, _p, _b, _s, secs = self.object_tuple()
        if ".text" not in secs:
            raise Dep(R["not_met"], self.loc("code_object"), "the object has no .text section")
        return secs[".text"][0], secs[".text"][1]

    def text_sha(self):
        _loc, _p, blob, _s, secs = self.object_tuple()
        off, size, _t = secs[".text"]
        return sha256_bytes(blob[off:off + size])

    def kernel_meta(self):
        loc = self.loc("code_object")
        try:
            md = amdhsa_metadata(self.raw(loc))
        except Dep:
            raise
        except Exception as exc:                              # noqa: BLE001
            raise Dep(R["not_met"], loc,
                      "the object's own AMDHSA metadata could not be decoded: %s: %s"
                      % (type(exc).__name__, exc))
        if len(md["kernels"]) != 1:
            raise Dep(R["not_met"], loc,
                      "the object carries %d kernels; this experiment launches exactly "
                      "one, so a symbol binding would be ambiguous" % len(md["kernels"]))
        return md["kernels"][0], md["target"]

    def sources(self):
        loc = self.loc("abi_measurement")
        s = self.need(self.json(loc), loc, "step_1_source_frozen", dict)
        out = {}
        for name, rec in sorted(s.items()):
            if not isinstance(rec, dict) or "sha256" not in rec:
                raise Dep(R["wrong_type"], loc,
                          "step_1_source_frozen[%r] carries no sha256" % name)
            path = rec.get("path") or rec.get("frozen_from")
            if not isinstance(path, str) or not path:
                raise Dep(R["wrong_type"], loc,
                          "step_1_source_frozen[%r] names no source path" % name)
            out[name] = {"path": path, "sha256": rec["sha256"], "record": rec}
        if len(out) < 2:
            raise Dep(R["missing_key"], loc,
                      "step_1_source_frozen names %d source(s); the object is built from a "
                      "translation unit and a header, and both must be frozen" % len(out))
        return out

    def expected_output_locator(self):
        """Where the expected output is: a DECLARED locator.

        The manifest declares no expected-output role -- its buffers ARE the
        experiment's buffers -- so the gate cannot derive the expected output's
        path from the manifest, and it must not invent one.  The declaration
        names the file; the selector names which manifest ROLE's shape and dtype
        that file must fit, so the declaration never gets to assert a length:
        the length is derived from the manifest and compared against the bytes.

        This is the seam the wrong-experiment control attacks: put Candidate-F's
        J3 expected output at this locator and every declaration in the package
        still agrees with every other declaration -- three of them state
        7cd55091 -- while the file on disk is 9,365,817 bytes with a digest that
        no artefact in the package mentions."""
        return self.loc("expected_output")

    def output_buffer_record(self):
        """The manifest's record of the role the expected output belongs to."""
        m_loc = self.manifest_loc()
        m = self.json(m_loc)
        role = self.selector("output_role")
        b = self.need(self.need(m, m_loc, "buffers", dict), m_loc, role, dict)
        shape = self.need(b, m_loc, "shape", str)
        dtype = self.need(b, m_loc, "dtype", str)
        if dtype not in DTYPE_WIDTH_BYTES:
            raise Dep(R["vocabulary"], m_loc,
                      "dtype %r is not a width this gate can compute" % dtype)
        n = 1
        for part in shape.split("x"):
            try:
                n *= int(part)
            except ValueError:
                raise Dep(R["malformed"], m_loc, "shape %r is not NxMx..." % shape)
        return role, b["path"], shape, dtype, n, n * DTYPE_WIDTH_BYTES[dtype]

    def identity(self, kind):
        """Resolve one identity kind to an F whose provenance is complete.

        Every branch reads the bytes of the subject's own artefacts.  There is
        deliberately no default: an unknown kind is a refusal, not a pass."""
        if kind not in IDENTITY_KINDS:
            raise Dep(R["vocabulary"], self.subject_file,
                      "identity kind %r is not one of the declared kinds" % kind)
        m = self.manifest_loc()
        if kind == "experiment_id":
            return F(m, "experiment_id", self.experiment_id())
        if kind == "manifest_sha256":
            return F(m, "sha256_file(the bytes on disk)", self.raw_sha(m))
        if kind == "code_object_sha256":
            loc, _p, _b, sha, _s = self.object_tuple()
            return F(loc, "sha256_file(the bytes on disk)", sha)
        if kind == "code_object_path":
            return F(self.subject_file, "locators.code_object", self.loc("code_object"))
        if kind == "text_section_sha256":
            loc = self.loc("code_object")
            return F(loc, "ELF section header table -> sha256(the .text bytes)", self.text_sha())
        if kind == "kernel_symbol":
            loc = self.loc("code_object")
            k, _t = self.kernel_meta()
            sym = k.get(".symbol")
            if not sym:
                raise Dep(R["no_binding"], loc,
                          "the object's own metadata carries no .symbol, so no symbol "
                          "can be bound to it")
            return F(loc, "AMDHSA note -> amdhsa.kernels[0]['.symbol']", sym)
        if kind in ("source_cpp_sha256", "source_header_sha256"):
            want_cpp = kind == "source_cpp_sha256"
            chosen = None
            for name, rec in sorted(self.sources().items()):
                if name.lower().endswith((".cpp", ".cc", ".cxx")) == want_cpp:
                    chosen = (name, rec)
                    break
            if chosen is None:
                raise Dep(R["no_binding"], self.loc("abi_measurement"),
                          "step_1_source_frozen names no %s source"
                          % ("C++" if want_cpp else "header"))
            name, rec = chosen
            loc = self.to_locator(rec["path"])
            if os.path.isfile(self.path_of(loc)):
                return F(loc, "sha256_file(the bytes on disk)", self.raw_sha(loc))
            raise Dep(R["not_a_file"], loc,
                      "the frozen source %s the ABI record names is not in this package"
                      % rec["path"])
        if kind == "harness_contract_sha256":
            loc = self.loc("harness_contract")
            return F(loc, "sha256_file(the bytes on disk)", self.raw_sha(loc))
        if kind == "execute_descriptor_sha256":
            loc = self.loc("execute_descriptor")
            return F(loc, "sha256_file(the bytes on disk)", self.raw_sha(loc))
        if kind == "descriptor_module_sha256":
            loc = self.loc("descriptor_module")
            return F(loc, "sha256_file(the bytes on disk)", self.raw_sha(loc))
        if kind == "expected_output_sha256":
            loc = self.expected_output_locator()
            return F(loc, "sha256_file(the bytes on disk)", self.raw_sha(loc))
        raise Dep(R["vocabulary"], self.subject_file, "unhandled kind %r" % kind)

    # -- binding declarations to the subject --------------------------------
    def binding_specs(self):
        b = self.subject().get("bindings")
        if not isinstance(b, list) or not b:
            raise Dep(R["missing_key"], self.subject_file,
                      "the subject declaration carries no bindings, so no artefact is "
                      "required to agree with the subject: nothing is bound")
        out = []
        for i, spec in enumerate(b):
            if not isinstance(spec, dict):
                raise Dep(R["wrong_type"], self.subject_file, "bindings[%d] is not a map" % i)
            for k in ("artifact", "pointer", "must_equal"):
                if k not in spec:
                    raise Dep(R["missing_key"], self.subject_file,
                              "bindings[%d] carries no %r" % (i, k))
            if spec["must_equal"] not in IDENTITY_KINDS:
                raise Dep(R["vocabulary"], self.subject_file,
                          "bindings[%d].must_equal = %r is not an identity kind"
                          % (i, spec["must_equal"]))
            out.append(spec)
        return out

    def _bindings_for(self, must_equal, why):
        """Compute once per identity kind, over EVERY declared binding of it, and
        record the three outcomes separately: agreement, disagreement, and a
        declared artefact that is on disk but states nothing.

        Computing over every binding -- even when a caller only cares about one
        artefact -- is what keeps the ledger honest: each (subject, declaration)
        pair is compared exactly once, so the duplicate-lineage audit cannot
        mistake a scoped re-check for a second independent check."""
        rec = self._bcache.get(must_equal)
        if rec is not None:
            rec["why_also"].append(why)
            rec["n_callers"] = rec.get("n_callers", 1) + 1
            if "subject_error" in rec:
                # the subject's own value could not be resolved.  Re-raised for
                # EVERY caller: a cached failure must not read as an empty pass.
                se = rec["subject_error"]
                raise Dep(se["requirement"], self.subject_file, se["detail"])
            return rec
        rec = {"why": why, "why_also": [], "n_callers": 1, "identity": must_equal,
               "rows": [], "disagree": [], "gaps": [], "absent": []}
        self._bcache[must_equal] = rec
        try:
            want = self.identity(must_equal)
        except Dep as d:
            rec["subject_error"] = {"requirement": d.requirement, "detail": d.detail}
            raise
        for spec in self.binding_specs():
            if spec["must_equal"] != must_equal:
                continue
            art, ptr = spec["artifact"], spec["pointer"]
            loc = self.loc(art)
            try:
                got = self.at(art, ptr)
            except Dep as d:
                if d.requirement in ABSENT_REQUIREMENTS:
                    # The artefact is not in this package at all.  The walk does
                    # NOT stop here: an absent declaration is one BLOCKED fact
                    # about one artefact, and stopping would hide the facts the
                    # artefacts that ARE on disk still state.  It is raised, in
                    # scope, by check_bindings below.
                    rec["absent"].append("%s#%s" % (art, ptr))
                    rec["rows"].append({"artifact": art, "locator": loc, "pointer": ptr,
                                        "declares_it": False, "absent": True,
                                        "requirement": d.requirement, "detail": d.detail})
                    continue
                gap = "%s#%s" % (art, ptr)
                rec["gaps"].append(gap)
                self.binding_gaps.append(
                    {"identity": must_equal, "artifact": art, "pointer": ptr,
                     "locator": loc, "requirement": d.requirement, "detail": d.detail})
                rec["rows"].append({"artifact": art, "locator": loc, "pointer": ptr,
                                    "declares_it": False, "requirement": d.requirement})
                continue
            if must_equal == "code_object_path":
                eq = self.led.same_path(got, want, why)
            else:
                eq = self.led.same(got, want, why)
            rec["rows"].append({"artifact": art, "locator": loc, "pointer": ptr,
                                "value": _short(got.value), "declares_it": True,
                                "agrees": bool(eq)})
            if not eq:
                rec["disagree"].append("%s#%s" % (art, ptr))
        return rec

    def check_bindings(self, must_equal, why, only=None, gaps_are_fatal=False):
        """Compare every declaration of one identity against the subject.
        -> (rows, bad)

        `only` scopes the QUESTION to the artefacts whose own predicate is
        asking: in that scope an artefact that is on disk but states nothing is
        fatal, because "this artefact is about this object" is exactly what its
        predicate claims.  Out of scope such an omission is recorded in
        self.binding_gaps and reported by the package-wide predicates -- it is
        one gap in the package's binding, not a second defect of every predicate
        that happens to walk the same list.  A DISAGREEMENT is fatal in every
        scope, filtered or not: an artefact whose declared value is some other
        object's is evidence about another experiment, whichever predicate
        noticed it.  The comparison itself is always computed over the whole
        binding list (see _bindings_for)."""
        rec = self._bindings_for(must_equal, why)
        onlyset = None if only is None else set(only)

        def in_scope(tag):
            return onlyset is None or tag.split("#", 1)[0] in onlyset

        rows = [r for r in rec["rows"] if in_scope(r["artifact"])]
        if onlyset is not None and not rows:
            raise Dep(R["no_binding"], self.subject_file,
                      "nothing among %s is declared to state %r: the artefact's own "
                      "predicate has no declaration to read" % (sorted(onlyset), must_equal))
        bad = [d for d in rec["disagree"] if in_scope(d)]
        if gaps_are_fatal or onlyset is not None:
            bad += ["%s (declared to state %s, states nothing)"
                    % (gp, must_equal) for gp in rec["gaps"] if in_scope(gp)]
        absent = [t for t in rec["absent"] if in_scope(t)]
        if absent and not bad and onlyset is not None:
            locs = sorted({r["locator"] for r in rec["rows"]
                           if r.get("absent") and in_scope(r["artifact"])})
            raise Dep(R["not_a_file"], ", ".join(locs),
                      "the artefact this predicate is about is declared to state %s and is not "
                      "in this package, so the question cannot be answered from what is on disk"
                      % must_equal)
        return rows, bad

    def verify_object_block_present(self, artifact_name, why):
        """Presence check: does this artefact carry a block that names the object
        it is about?  The comparison of that block's values against the object is
        performed by the bindings list, so this adds no second comparison."""
        loc = self.loc(artifact_name)
        p_path = self.pointer(artifact_name, "object_path")
        p_sha = self.pointer(artifact_name, "object_sha256")
        blk = self.walk(loc, p_path.rsplit("/", 1)[0] if "/" in p_path else p_path)
        if not isinstance(blk, dict):
            raise Dep(R["no_binding"], loc,
                      "%s carries no object block (the pointer the declaration gives for "
                      "its object names a %s): it cannot be shown to be about the object "
                      "the experiment will launch.  A proof that names the KERNEL and not "
                      "the OBJECT accepts the retired 16AR proof, which names this kernel "
                      "and carries no object digest at all."
                      % (why, type(blk).__name__))
        for ptr in (p_path, p_sha):
            v = self.walk(loc, ptr)
            if not isinstance(v, str) or not v:
                raise Dep(R["no_binding"], loc,
                          "%s: the object block's %r is %r, so the block binds nothing"
                          % (why, ptr, v))
        return True

    # -- predicate wrapper ---------------------------------------------------
    def pred(self, name, requires, fn):
        """Run one predicate.  A Dep maps to its own kind.  Any OTHER exception
        is a REFUSAL: NO CRASH IS A PASS."""
        try:
            status, detail = fn()
        except Dep as d:
            status = d.kind
            detail = {"requirement_fired": d.requirement,
                      "absent_or_bad_path": d.locator, "detail": d.detail}
        except Exception as exc:                              # noqa: BLE001
            status = REFUSED
            detail = {"requirement_fired": "the predicate raised",
                      "exception": "%s: %s" % (type(exc).__name__, exc)}
        self.preds.append({"predicate": name, "requires": requires,
                           "status": status, "detail": detail})


def _looks_like_a_digest(s):
    if not isinstance(s, str) or len(s) != 64:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in s)


def _int_at(doc, key, locator, convert=False):
    v = doc.get(key)
    if v is None:
        raise Dep(R["missing_key"], locator, "the artefact carries no %r" % key)
    if isinstance(v, bool):
        raise Dep(R["wrong_type"], locator, "%s is a boolean, not a count" % key)
    if isinstance(v, int):
        return v
    if convert and isinstance(v, str):
        try:
            return int(v)
        except ValueError:
            raise Dep(R["malformed"], locator, "%s = %r is not an integer" % (key, v))
    raise Dep(R["wrong_type"], locator, "%s is %s, expected int" % (key, type(v).__name__))


# --------------------------------------------------------------------------
# the predicates
# --------------------------------------------------------------------------

def build_predicates(g):
    P = []

    # ---- the gate's own contract ------------------------------------------
    def p_subject_declaration_is_locator_only():
        s = g.subject()
        if not isinstance(s, dict):
            return REFUSED, {"requirement_fired": R["wrong_type"], "detail": "not a map"}
        for k in ("locators", "pointers", "bindings", "not_subject_evidence"):
            if k not in s:
                return REFUSED, {"requirement_fired": R["missing_key"],
                                 "absent_or_bad_path": g.subject_file,
                                 "detail": "the declaration carries no %r" % k}
        bad = []

        def scan(node, path):
            if isinstance(node, str):
                if _looks_like_a_digest(node):
                    bad.append("%s = %r" % (path, node[:24] + "..."))
                return
            if isinstance(node, list):
                for i, v in enumerate(node):
                    scan(v, "%s[%d]" % (path, i))
                return
            if isinstance(node, dict):
                for k, v in node.items():
                    scan(v, "%s.%s" % (path, k))
        for k in ("locators", "pointers", "bindings", "not_subject_evidence",
                  "required_bounds", "selectors", "metadata_fields", "ceilings", "must_bind"):
            if k in s:
                scan(s[k], k)
        for i, spec in enumerate(s["bindings"]):
            if isinstance(spec, dict):
                extra = sorted(set(spec.keys()) - {"artifact", "pointer", "must_equal"})
                if extra:
                    bad.append("bindings[%d] carries %s; a binding names WHERE a value comes "
                               "from, never what it is" % (i, ", ".join(extra)))
        for name, v in sorted(s["locators"].items()):
            if isinstance(v, str) and (os.path.isabs(v) or ":" in v or v.startswith("/")):
                bad.append("locators.%s = %r is absolute; a locator must resolve under the "
                           "evidence root, or it cannot be relocated to a fixture" % (name, v))
        if bad:
            return REFUSED, {"requirement_fired": R["malformed"],
                             "absent_or_bad_path": g.subject_file,
                             "detail": "the subject declaration carries measured values; a "
                                       "declaration that states the answer cannot be "
                                       "evidence for it",
                             "found": bad[:12], "n": len(bad)}
        names = set()
        for e in s["not_subject_evidence"]:
            if not isinstance(e, dict) or "locator" not in e or "why" not in e:
                return REFUSED, {"requirement_fired": R["wrong_type"],
                                 "absent_or_bad_path": g.subject_file,
                                 "detail": "not_subject_evidence entries must be "
                                           "{locator, why}; got %r" % (e,)}
            names.add(e["locator"])
        for spec in s["bindings"]:
            if isinstance(spec, dict) and spec.get("artifact") in names:
                return REFUSED, {"requirement_fired": R["malformed"],
                                 "absent_or_bad_path": g.subject_file,
                                 "detail": "artefact %r is declared NOT evidence for the "
                                           "subject and is also bound to it" % spec.get("artifact")}
        for spec in s["bindings"]:
            if isinstance(spec, dict) and spec.get("artifact") not in s["locators"]:
                return REFUSED, {"requirement_fired": R["malformed"],
                                 "absent_or_bad_path": g.subject_file,
                                 "detail": "bindings name artifact %r, which has no declared "
                                           "locator, so that binding cannot be read"
                                           % spec.get("artifact")}
        return PASS, {"n_locators": len(s["locators"]), "n_pointers": len(s["pointers"]),
                      "n_bindings": len(s["bindings"]),
                      "n_not_subject_evidence": len(names),
                      "required_bounds": sorted(s["required_bounds"]),
                      "selectors": sorted(s["selectors"]),
                      "no_digest_in_the_declaration": True,
                      "why_this_matters": "the declaration is the gate's own input; if it "
                                          "carried a digest, comparing it against the world "
                                          "would be a comparison of two literals"}

    P.append(("subject_declaration_is_locator_only",
              "the subject declaration carries locators, never values",
              p_subject_declaration_is_locator_only))

    def p_gate_source_carries_no_predicate_literal():
        src = g.self_source.decode("utf-8", "replace")
        found = [t for t in src.replace('"', " ").replace("'", " ").split()
                 if _looks_like_a_digest(t)]
        if found:
            return REFUSED, {"requirement_fired": R["malformed"],
                             "absent_or_bad_path": os.path.abspath(__file__),
                             "detail": "this gate's own source carries %d digest literal(s); "
                                       "a gate that hardcodes its expected values certifies "
                                       "nothing about the object it gates" % len(found),
                             "found": found[:8]}
        _loc, _path, blob, _sha, _secs = g.object_tuple()
        for needle, what in ((str(len(blob)).encode(), "the object's byte length"),):
            if needle in g.self_source:
                return REFUSED, {"requirement_fired": R["malformed"],
                                 "absent_or_bad_path": os.path.abspath(__file__),
                                 "detail": "this gate's own source contains %s as a literal"
                                           % what}
        return PASS, {"gate_source_bytes": len(g.self_source),
                      "no_digest_literal": True,
                      "no_object_byte_count_literal": True,
                      "how": "the source is split into tokens and every 64-hex token is a "
                             "failure; the object's own length is then searched for as a "
                             "literal byte string",
                      "ceiling": "a value could still be encoded indirectly (arithmetic, a "
                                 "list of digits).  This catches the defect that was "
                                 "actually shipped, not every possible encoding of it."}

    P.append(("gate_source_carries_no_predicate_literal",
              "the gate's own source holds no expected value",
              p_gate_source_carries_no_predicate_literal))

    def p_experiment_id_is_one_value_across_the_package():
        rows, bad = g.check_bindings(
            "experiment_id",
            "every artefact that states the experiment id states THIS experiment's id",
            gaps_are_fatal=True)
        if bad:
            return REFUSED, {"requirement_fired": R["foreign_subject"],
                             "detail": "the package does not name ONE experiment: %s.  A "
                                       "declaration that disagrees is evidence about some "
                                       "other experiment; a declaration that is absent means "
                                       "the artefact could be about anything, so it is not "
                                       "evidence about this one." % "; ".join(bad),
                             "compared": rows}
        return PASS, {"experiment_id": g.identity("experiment_id").value,
                      "n_declarations_compared": len(rows),
                      "n_declarations_that_state_it": sum(1 for r in rows
                                                          if r.get("declares_it")),
                      "compared": rows}

    P.append(("experiment_id_is_one_value_across_the_package",
              "every artefact names the same experiment",
              p_experiment_id_is_one_value_across_the_package))

    def p_manifest_bytes_hash_to_their_declared_locator():
        m_loc = g.manifest_loc()
        sha = g.raw_sha(m_loc)
        arts = g.need(g.json(m_loc), m_loc, "artifacts", dict)
        if "code_object" not in arts:
            return REFUSED, {"requirement_fired": R["missing_key"], "absent_or_bad_path": m_loc,
                             "detail": "the manifest declares no artifacts.code_object"}
        co = arts["code_object"]
        if not isinstance(co, dict) or "sha256" not in co or "path" not in co:
            return REFUSED, {"requirement_fired": R["wrong_type"], "absent_or_bad_path": m_loc,
                             "detail": "artifacts.code_object carries no path/sha256 pair"}
        rows, bad = g.check_bindings("manifest_sha256",
                                     "whoever states the manifest's digest must state the "
                                     "digest of the manifest's bytes")
        same = g.led.same_path(
            g.at("experiment_manifest", "artifacts/code_object/path"),
            F(g.subject_file, "locators.code_object", g.loc("code_object")),
            "the object the manifest names vs the object the subject declares")
        obj_eq = g.led.same(
            F(m_loc, "artifacts/code_object/sha256", co["sha256"]),
            g.identity("code_object_sha256"),
            "the manifest's declared object digest vs the object's bytes")
        if bad or not same or not obj_eq:
            return REFUSED, {"requirement_fired": R["digest_disagreement"],
                             "absent_or_bad_path": m_loc,
                             "detail": "the manifest does not describe this experiment's "
                                       "object",
                             "manifest_digest_declarations_disagreeing": bad,
                             "manifest_names_the_subject_object": bool(same),
                             "manifest_object_digest_matches_the_bytes": bool(obj_eq)}
        return PASS, {"manifest_sha256": sha, "manifest_bytes": len(g.raw(m_loc)),
                      "n_declarations_of_the_manifest_digest": len(rows), "compared": rows}

    P.append(("manifest_bytes_hash_to_their_declared_locator",
              "the manifest's bytes are what the package says they are",
              p_manifest_bytes_hash_to_their_declared_locator))

    # ---- the object itself -------------------------------------------------
    def p_source_sha_matches_the_bytes():
        rows, bad = [], []
        for name, rec in sorted(g.sources().items()):
            loc = g.to_locator(rec["path"])
            if not os.path.isfile(g.path_of(loc)):
                raise Dep(R["not_a_file"], loc,
                          "the ABI record freezes source %s" % name)
            got = g.raw_sha(loc)
            eq = g.led.same(F(loc, "sha256_file(the bytes on disk)", got),
                            F(g.loc("abi_measurement"),
                              "step_1_source_frozen/%s/sha256" % name, rec["sha256"]),
                            "the frozen source %s on disk vs its recorded digest" % name)
            rows.append({"source": name, "locator": loc, "sha256": got, "agrees": bool(eq)})
            if not eq:
                bad.append(name)
            if rec["record"].get("copied_byte_exact") is False:
                bad.append("%s: recorded as NOT copied byte-exact" % name)
        for kind in ("source_cpp_sha256", "source_header_sha256"):
            _r, b2 = g.check_bindings(kind, "the frozen source digest must be the source's "
                                            "digest wherever it is restated",
                                      only=("abi_measurement", "memory_bounds"))
            bad.extend(b2)
        if bad:
            return REFUSED, {"requirement_fired": R["digest_disagreement"],
                             "absent_or_bad_path": g.loc("abi_measurement"),
                             "detail": "source digest(s) do not match the bytes: %s"
                                       % ", ".join(sorted(set(bad))), "sources": rows}
        return PASS, {"n_sources": len(rows), "sources": rows}

    P.append(("source_sha_matches_the_bytes",
              "the frozen source on disk hashes to the frozen digest",
              p_source_sha_matches_the_bytes))

    def p_code_object_sha_matches_the_bytes():
        loc, _p, blob, sha, secs = g.object_tuple()
        rows, bad = g.check_bindings(
            "code_object_sha256",
            "whoever states the object's digest must state the digest of THIS object")
        _r2, b2 = g.check_bindings(
            "code_object_path",
            "whoever states which object this is must name the object the subject declares")
        bad.extend(b2)
        if bad:
            return REFUSED, {"requirement_fired": R["foreign_subject"],
                             "absent_or_bad_path": loc,
                             "detail": "artefact(s) %s state a different object; the object "
                                       "on disk hashes to %s" % (", ".join(bad), sha),
                             "compared": rows}
        return PASS, {"code_object": loc, "sha256": sha, "bytes": len(blob),
                      "n_sections": len(secs), "n_declarations_compared": len(rows),
                      "compared": rows,
                      "ceiling": "this digest identifies a BUILD.  The object is not "
                                 "byte-reproducible from source (16AS step_4b: many distinct "
                                 "digests, one reproducible ABI), so this binds a frozen byte "
                                 "sequence, not a derivation."}

    P.append(("code_object_sha_matches_the_bytes",
              "the object's digest is recomputed and every declaration agrees",
              p_code_object_sha_matches_the_bytes))

    def p_archived_byte_copy_is_identical():
        loc, _p, blob, sha, _secs = g.object_tuple()
        d = g.loc("archive")
        full = g.path_of(d)
        if not os.path.isdir(full):
            raise Dep(R["not_a_file"], d, "no archive directory at %s" % full)
        names = sorted(n for n in os.listdir(full) if n.lower().endswith(".co"))
        if len(names) != 1:
            raise Dep(R["not_met"], d,
                      "the write-once archive holds %d .co file(s); a write-once archive of "
                      "one object holds exactly one" % len(names))
        arc = d.rstrip("/") + "/" + names[0]
        abytes = g.raw(arc)
        asha = sha256_bytes(abytes)
        eq = g.led.same(F(arc, "sha256_file(the bytes on disk)", asha),
                        F(loc, "sha256_file(the bytes on disk)", sha),
                        "the archived byte copy vs the live object")
        len_eq = g.led.same(F(arc, "len(the bytes on disk)", len(abytes)),
                            F(loc, "len(the bytes on disk)", len(blob)),
                            "the archived copy's length vs the object's length")
        if not (eq and len_eq and abytes == blob):
            return REFUSED, {"requirement_fired": R["digest_disagreement"],
                             "absent_or_bad_path": arc,
                             "detail": "the archived copy is not byte-identical to the object "
                                       "the experiment will launch",
                             "archive_sha256": asha, "object_sha256": sha,
                             "bytes_differ": sum(1 for x, y in zip(abytes, blob) if x != y)}
        return PASS, {"archive": arc, "sha256": asha, "bytes": len(abytes),
                      "identical_by_hash_by_length_and_by_byte_comparison": True}

    P.append(("archived_byte_copy_is_identical",
              "the archived object is the object the experiment will launch",
              p_archived_byte_copy_is_identical))

    def p_text_section_sha_matches_the_bytes():
        loc, _p, blob, _sha, secs = g.object_tuple()
        off, size, _t = secs[".text"]
        tsha = sha256_bytes(blob[off:off + size])
        lp = g.loc("machine_loop_proof")
        base = g.pointer("machine_loop_proof", "text_section")
        rows, bad = [], []
        for key, want, what in (("sha256_recomputed_from_bytes", tsha, "digest"),
                                ("size", size, "size"),
                                ("file_offset", off, "file offset")):
            got = g.walk(lp, "%s/%s" % (base, key))
            eq = g.led.same(F(lp, "%s.%s" % (base.replace("/", "."), key), got),
                            F(loc, "ELF section header table -> the .text %s" % what, want),
                            "the loop proof's .text %s vs the object's own section header" % what)
            rows.append({"fact": what, "declared": got, "measured": want, "agrees": bool(eq)})
            if not eq:
                bad.append(what)
        _r, b2 = g.check_bindings(
            "text_section_sha256",
            "a statement of the .text digest must be the digest of THIS object's .text",
            only=("machine_loop_proof", "previous_loop_proof"))
        bad.extend(b2)
        if bad:
            return REFUSED, {"requirement_fired": R["foreign_subject"],
                             "absent_or_bad_path": lp,
                             "detail": "the .text facts do not match the object's own section "
                                       "header table: %s" % ", ".join(sorted(set(bad))),
                             "compared": rows}
        return PASS, {"text_sha256": tsha, "file_offset": off, "size": size,
                      "compared": rows,
                      "why_a_text_binding_is_not_enough_on_its_own":
                          "the retired V1 object under p16ar/native/hip/build/ has a "
                          "BYTE-IDENTICAL .text and a DIFFERENT whole-object digest, so a "
                          ".text-only binding cannot tell the two objects apart.  "
                          "code_object_sha256 is therefore a separate predicate."}

    P.append(("text_section_sha_matches_the_bytes",
              "the .text digest is recomputed from the object's own section headers",
              p_text_section_sha_matches_the_bytes))

    def p_abi_is_remeasured_from_the_object():
        loc = g.loc("abi_measurement")
        doc = g.json(loc)
        try:
            k, target = g.kernel_meta()
        except Dep as d:
            raise Dep(R["no_binding"], g.loc("code_object"),
                      "the ABI cannot be bound to the object because the object's own "
                      "metadata is unreadable: %s" % d.detail)
        obj_loc, _p, _b, _osha, _s = g.object_tuple()
        base = g.pointer("abi_measurement", "abi_measured")
        decl = g.walk(loc, base)
        if not isinstance(decl, dict) or not decl:
            raise Dep(R["missing_key"], loc, "no ABI measurement block at %r" % base)
        rows, bad, unstated = [], [], []
        for key in sorted(decl.keys()):
            meta_key = "." + key
            want = k.get(meta_key)
            got = decl[key]
            if got is None:
                unstated.append({"fact": key, "the_16AS_record_says": None,
                                 "the_object_says": want})
                continue
            eq = g.led.same(F(loc, "%s/%s" % (base, key), got),
                            F(obj_loc, "AMDHSA note -> amdhsa.kernels[0]['%s']" % meta_key, want),
                            "the ABI record's %s vs the object's own metadata" % key)
            rows.append({"fact": key, "declared": got, "measured": want, "agrees": bool(eq)})
            if not eq:
                bad.append("%s: record %r, object %r" % (key, got, want))
        if len(rows) < 6:
            raise Dep(R["no_binding"], loc,
                      "only %d ABI fact(s) in the record carry a value, so the record is not "
                      "an ABI measurement" % len(rows))
        args = g.walk(loc, g.pointer("abi_measurement", "abi_arguments"))
        if not isinstance(args, list) or not args:
            raise Dep(R["missing_key"], loc,
                      "the ABI record carries no argument list, so the kernarg layout cannot "
                      "be bound to the object")
        kargs = k.get(".args") or []
        if len(args) != len(kargs):
            raise Dep(R["count_disagreement"], loc,
                      "the record lists %d arguments and the object's own metadata %d"
                      % (len(args), len(kargs)))
        n_arg_facts = 0
        for i, (a, b) in enumerate(zip(args, kargs)):
            for key in ("offset", "size", "value_kind"):
                if not isinstance(a, dict) or key not in a:
                    raise Dep(R["missing_key"], loc, "argument record %d carries no %r" % (i, key))
                eq = g.led.same(
                    F(loc, "%s[%d].%s" % (base.replace("/", ".") + "_arguments", i, key), a[key]),
                    F(obj_loc, "AMDHSA note -> kernels[0]['.args'][%d]['%s']" % (i, "." + key),
                      b.get("." + key)),
                    "argument %d's %s in the record vs the object's own metadata" % (i, key))
                if not eq:
                    bad.append("argument[%d].%s: record %r, object %r"
                               % (i, key, a[key], b.get("." + key)))
                n_arg_facts += 1
        dloc = g.loc("execute_descriptor")
        drows = g.json(dloc)
        arch = g.need(drows, dloc, "device_arch", str)
        arch_ok = g.led.contains(
            F(dloc, "device_arch", arch),
            F(obj_loc, "AMDHSA note -> amdhsa.target", target),
            "the arch the descriptor declares must appear inside the object's own target "
            "triple, which is written into the object at compile time")
        rows.append({"fact": "device_arch", "declared": arch, "measured": target,
                     "agrees": bool(arch_ok)})
        if not arch_ok:
            bad.append("device_arch %r does not appear in the object's target triple %r"
                       % (arch, target))
        ext_rec = g.walk(loc, g.pointer("abi_measurement", "extractor_sha256"))
        ext_desc = g.need(drows, dloc, "abi_source_sha256", str)
        g.led.same(F(dloc, "abi_source_sha256", ext_desc),
                   F(loc, "%s/extractor_sha256" % g.pointer("abi_measurement", "abi"),
                     ext_rec),
                   "the extractor the descriptor names vs the extractor the ABI record names "
                   "(a lineage note: the extractor is not on this predicate's path to the "
                   "object, which is why the ABI is re-read here from the note alone)")
        # The symbol is part of the object's own metadata note, so the same read that
        # gives the ABI gives the symbol: every declaration that names a kernel symbol
        # is compared against it here.  A package whose command would resolve a
        # DIFFERENT symbol is a package for a different kernel.
        sym = k.get(".symbol")
        srows, sbad = g.check_bindings(
            "kernel_symbol",
            "every statement of the kernel symbol must be the symbol the object's own AMDGPU "
            "note names")
        rows.extend(srows)
        for tag in sbad:
            bad.append("%s does not state the symbol the object carries (%r)" % (tag, sym))
        if bad:
            return REFUSED, {"requirement_fired": R["digest_disagreement"],
                             "absent_or_bad_path": loc,
                             "detail": "the ABI record does not match the object's own AMDHSA "
                                       "metadata: %s" % "; ".join(bad[:8]),
                             "compared": rows}
        return PASS, {"facts_compared_against_the_object": len(rows) + n_arg_facts,
                      "argument_facts_compared": n_arg_facts,
                      "facts_the_16AS_record_left_unstated": unstated,
                      "object_target": target,
                      "compared": rows[:24],
                      "how": "the object's own type-32 AMDGPU metadata note, decoded by a "
                             "MessageBox-free MessagePack reader inside this gate; no external "
                             "process and no cached extractor artifact is on this path",
                      "why_the_unstated_facts_are_not_failures": "a field the 16AS record "
                             "leaves null is not a claim that disagrees with the object; it is "
                             "a fact the record did not state.  Every field it DOES state is "
                             "compared, above, and the kernel name and symbol it left null are "
                             "bound to the object by the kernel_symbol binding.",
                      "ceiling": "the extractor's digest (%s) is recorded as provenance for "
                                 "the 16AS record; it is not a source of truth for anything"
                                 % (ext_rec[:16] + "..." if isinstance(ext_rec, str) else None)}

    P.append(("abi_is_remeasured_from_the_object",
              "the ABI is re-read out of the object's own metadata note",
              p_abi_is_remeasured_from_the_object))

    def p_resources_are_declared_zero_and_bound():
        loc = g.loc("abi_measurement")
        doc = g.json(loc)
        blk = g.pointer("abi_measurement", "resources")
        res = g.walk(loc, blk)
        if not isinstance(res, dict) or not res:
            raise Dep(R["missing_key"], loc, "the resource block %r is not a map" % blk)
        req = g.bounds()
        fields = g.metadata_fields()
        k, _t = g.kernel_meta()
        obj_loc = g.loc("code_object")
        rows, bad = [], []
        for key in sorted(req):
            if key not in res:
                raise Dep(R["missing_key"], loc,
                          "the resource record carries no %r, which the subject declaration "
                          "requires" % key)
            want = req[key]
            got = res[key]
            eq = g.led.same(F(loc, "%s/%s" % (blk, key), got),
                            F(g.subject_file, "required_bounds.%s" % key, want),
                            "the measured %s vs the requirement the subject declares" % key)
            rows.append({"resource": key, "measured": got, "required": want,
                         "satisfies": bool(eq)})
            if not eq:
                bad.append("%s=%r, required %r" % (key, got, want))
        for key, tag in sorted(fields.items()):
            if key not in res:
                continue
            obj_val = k.get(tag)
            eq = g.led.same(F(loc, "%s/%s" % (blk, key), res[key]),
                            F(obj_loc, "AMDHSA note -> kernels[0]['%s']" % tag, obj_val),
                            "the recorded %s vs the object's own metadata" % key)
            rows.append({"resource": key, "measured": res[key],
                         "re_measured_from_the_object": obj_val, "satisfies": bool(eq)})
            if not eq:
                bad.append("%s: record %r, object %r" % (key, res[key], obj_val))
        if bad:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "resource requirement(s) not satisfied or not bound to "
                                       "the object: %s" % "; ".join(bad[:8]), "compared": rows}
        return PASS, {"required": req, "n_facts_compared": len(rows), "compared": rows}

    P.append(("resources_are_declared_zero_and_bound",
              "the resource profile satisfies the experiment's own declared bounds",
              p_resources_are_declared_zero_and_bound))

    def p_numerical_oracle_is_current_and_bound():
        loc = g.loc("numerical_oracle")
        doc = g.json(loc)
        if not isinstance(doc, dict):
            raise Dep(R["wrong_type"], loc, "not a map")
        g.verify_object_block_present(
            "numerical_oracle",
            "a numerical disposition stated for a different object or a different experiment "
            "cannot be this experiment's numerical evidence")
        rows, bad = [], []
        for kind in ("experiment_id", "code_object_sha256"):
            r, b = g.check_bindings(kind, "the numerical disposition must be about this "
                                          "experiment and this object",
                                    only=("numerical_oracle",))
            rows.extend(r)
            bad.extend(b)
        vocab = g.vocabulary(doc, loc, "disposition_vocabulary")
        passing = g.vocabulary(doc, loc, "passing_dispositions")
        for d in passing:
            if d not in vocab:
                raise Dep(R["malformed"], loc,
                          "passing_dispositions names %r, which is not in the artefact's own "
                          "disposition_vocabulary" % d)
        v = doc.get("verdict")
        if isinstance(v, dict):
            if "disposition" not in v:
                raise Dep(R["missing_key"], loc,
                          "the verdict block carries no disposition")
            disp = v["disposition"]
        else:
            disp = v
        if not isinstance(disp, str):
            raise Dep(R["missing_key"], loc, "the verdict names no disposition")
        g.in_vocab(doc, loc, "verdict.disposition", disp, vocab)
        if disp not in passing:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "the numerical disposition of record is %r, which the "
                                       "artefact itself does not list among its passing "
                                       "dispositions (%s)" % (disp, ", ".join(passing)),
                             "one_line": v.get("one_line") if isinstance(v, dict) else None,
                             "compared": rows}
        n_checks = g.need(doc, loc, "n_checks", int)
        n_ok = g.need(doc, loc, "n_checks_ok", int)
        if n_checks <= 0:
            raise Dep(R["not_met"], loc,
                      "n_checks = %d; a disposition that ran no check disposes of nothing"
                      % n_checks)
        if not g.led.same(F(loc, "n_checks_ok", n_ok), F(loc, "n_checks", n_checks),
                          "the passing-check count vs the number of checks"):
            bad.append("n_checks_ok %r != n_checks %r" % (n_ok, n_checks))
        if doc.get("failures"):
            bad.append("failures: %r" % (doc.get("failures"),))
        prov = g.need(doc, loc, "provenance", dict)
        for name, rec in sorted(prov.items()):
            if not isinstance(rec, dict) or "sha256" not in rec or "path" not in rec:
                raise Dep(R["wrong_type"], loc,
                          "provenance[%r] carries no path/sha256 pair" % name)
            pl = g.to_locator(rec["path"])
            if not os.path.isfile(g.path_of(pl)):
                raise Dep(R["not_a_file"], pl,
                          "the numerical disposition's provenance names %s" % pl)
            eq = g.led.same(F(pl, "sha256_file(the bytes on disk)", g.raw_sha(pl)),
                            F(loc, "provenance/%s/sha256" % name, rec["sha256"]),
                            "the numerical disposition's provenance item %s" % name)
            if not eq:
                bad.append("provenance:%s" % name)
        dloc = g.loc("execute_descriptor")
        want_contract = g.need(g.json(dloc), dloc, "numerical_contract", str)
        here = g.need(doc, loc, "contract_id", str)
        if not g.led.same(F(loc, "contract_id", here),
                          F(dloc, "numerical_contract", want_contract),
                          "the numerical contract the descriptor declares vs the one the "
                          "disposition is about"):
            bad.append("contract_id %r != the descriptor's numerical_contract %r"
                       % (here, want_contract))
        if bad:
            return REFUSED, {"requirement_fired": R["digest_disagreement"],
                             "absent_or_bad_path": loc,
                             "detail": "the numerical evidence is not current and bound: %s"
                                       % "; ".join(bad), "compared": rows}
        return PASS, {"disposition": disp, "n_checks": n_checks, "contract_id": here,
                      "compared": rows,
                      "what_this_establishes": "there is a current numerical disposition for "
                                               "THIS object and THIS experiment, every check "
                                               "in it passes, and every provenance item it "
                                               "names was re-hashed in this run",
                      "ceiling": "it establishes WHICH disposition is of record and that its "
                                 "evidence is intact; it does not re-derive the "
                                 "double-rounding analysis"}

    P.append(("numerical_oracle_is_current_and_bound",
              "the numerical contract is disposed for this object and experiment",
              p_numerical_oracle_is_current_and_bound))

    def p_expected_output_is_bound():
        m_loc = g.manifest_loc()
        role, m_role_path, shape, dtype, n_elems, predicted = g.output_buffer_record()
        m_role_loc = g.to_locator(m_role_path)
        eo = g.expected_output_locator()
        blob = g.raw(eo)
        eo_sha = sha256_bytes(blob)
        eq = g.led.same(F(eo, "len(the bytes on disk)", len(blob)),
                        F(m_loc, "buffers/%s -> %s elements x %s" % (role, n_elems, dtype),
                          predicted),
                        "the expected output's length vs the length the shape and dtype of "
                        "the role the subject selected imply")
        rows, bad = [], []
        if not eq:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": eo,
                             "detail": "the expected output is %d bytes but the role %r it is "
                                       "declared to belong to is %s x %s, which implies %d bytes; "
                                       "a binary whose length does not fit its declared shape "
                                       "belongs to a different experiment"
                                       % (len(blob), role, shape, dtype, predicted)}
        dloc = g.loc("execute_descriptor")
        drows = g.json(dloc)
        role_key = g.pointer("expected_output", "descriptor_role_key")
        if role_key in drows:
            if not g.led.same(
                    F(dloc, role_key, drows[role_key]),
                    F(g.subject_file, "selectors.%s" % g.pointer("expected_output", "selector"),
                      role),
                    "the output role the descriptor declares vs the role the subject "
                    "declaration selected: this is what makes the SELECTOR itself checkable "
                    "rather than assumed"):
                bad.append("the descriptor declares output role %r; this gate selected %r"
                           % (drows[role_key], role))
        pkey = g.pointer("expected_output", "descriptor_path_key")
        if pkey in drows:
            if not g.led.same_path(
                    F(dloc, pkey, drows[pkey]),
                    F(g.subject_file, "locators.expected_output", eo),
                    "the descriptor's expected binary vs the file the subject declaration "
                    "names as this experiment's expected output"):
                bad.append("the descriptor's expected binary is %r; the expected output the "
                           "declaration names is %r" % (drows[pkey], eo))
        key = "bytes_%s" % role
        if key in drows:
            d_bytes = _int_at(drows, key, dloc, convert=True)
            if not g.led.same(F(dloc, key, d_bytes),
                              F(eo, "len(the bytes on disk)", len(blob)),
                              "the descriptor's byte count for the role %s vs the expected "
                              "output's length" % role):
                bad.append("the descriptor says %s = %d, the expected output is %d bytes"
                           % (key, d_bytes, len(blob)))
        # the descriptor's digest of the DEVICE buffer of that role belongs to the
        # buffer, not to the expected output: it is compared against the file the
        # manifest names for the role, which is the artefact it is about.
        d_sha = drows.get("buf_%s_sha256" % role)
        if isinstance(d_sha, str):
            if not os.path.isfile(g.path_of(m_role_loc)):
                raise Dep(R["not_a_file"], m_role_loc,
                          "the manifest names %s as the buffer for role %r and the descriptor "
                          "states a digest for that buffer" % (m_role_path, role))
            if not g.led.same(F(dloc, "buf_%s_sha256" % role, d_sha),
                              F(m_role_loc, "sha256_file(the bytes on disk)",
                                g.raw_sha(m_role_loc)),
                              "the descriptor's digest for the device buffer of role %s vs the "
                              "bytes the manifest names for that role" % role):
                bad.append("the descriptor's buf_%s_sha256 is not the digest of %s, the buffer "
                           "the manifest names for that role" % (role, m_role_path))
        d_sha_expected = g.need(drows, dloc, "expected_bin_sha256", str)
        if not g.led.same(F(eo, "sha256_file(the bytes on disk)", eo_sha),
                          F(dloc, "expected_bin_sha256", d_sha_expected),
                          "the expected output's bytes vs the digest the descriptor states for "
                          "its expected binary"):
            bad.append("the descriptor's expected_bin_sha256 is %r; the file the declaration "
                       "names hashes to %s" % (d_sha_expected, eo_sha))
        r2, b2 = g.check_bindings(
            "expected_output_sha256",
            "every declaration of the expected output's digest must be the digest of the "
            "expected output THIS experiment will compare against",
            gaps_are_fatal=True)
        rows.extend(r2)
        bad.extend(b2)
        if bad:
            return REFUSED, {"requirement_fired": R["foreign_subject"], "absent_or_bad_path": eo,
                             "detail": "the expected output is not the one this package "
                                       "describes: %s (the file on disk hashes to %s)"
                                       % ("; ".join(bad), eo_sha),
                             "compared": rows}
        return PASS, {"path": eo, "sha256": eo_sha, "bytes": len(blob),
                      "role": role, "shape": shape, "dtype": dtype,
                      "n_declarations_compared": len(rows), "compared": rows}

    P.append(("expected_output_is_bound",
              "the expected output is the one this experiment's manifest names",
              p_expected_output_is_bound))

    def p_machine_loop_proof_is_bound_to_this_object():
        loc = g.loc("machine_loop_proof")
        doc = g.json(loc)
        obj_loc, _p, _b, osha, _s = g.object_tuple()
        g.verify_object_block_present(
            "machine_loop_proof",
            "a loop proof that does not bind this object cannot be this object's liveness "
            "evidence")
        rows, bad = g.check_bindings(
            "code_object_sha256",
            "a loop proof must state the digest of the object it analysed",
            only=("machine_loop_proof",))
        rows2, b2 = g.check_bindings(
            "code_object_path",
            "a loop proof must name the object it analysed",
            only=("machine_loop_proof",))
        rows.extend(rows2)
        bad.extend(b2)
        counts = g.walk(loc, g.pointer("machine_loop_proof", "counts"))
        if not isinstance(counts, dict):
            raise Dep(R["wrong_type"], loc, "the proof's counts block is not a map")
        p = g.pointer("machine_loop_proof", "counts")
        n_loops = _int_at(counts, g.pointer("machine_loop_proof", "n_loops_key"), loc)
        n_proven = _int_at(counts, g.pointer("machine_loop_proof", "n_loops_proven_key"), loc)
        n_uncovered = _int_at(counts, g.pointer("machine_loop_proof", "n_uncovered_key"), loc)
        if n_loops <= 0:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "the proof claims %d natural loops; a proof that found "
                                       "no loop bounds nothing" % n_loops}
        if n_loops != n_proven:
            return REFUSED, {"requirement_fired": R["count_disagreement"],
                             "absent_or_bad_path": loc,
                             "detail": "%d of %d loops have a finite bound; the remainder are "
                                       "unbounded" % (n_proven, n_loops)}
        if n_uncovered != 0:
            return REFUSED, {"requirement_fired": R["count_disagreement"],
                             "absent_or_bad_path": loc,
                             "detail": "%d machine backward branch(es) are covered by no "
                                       "natural loop" % n_uncovered}
        per = g.walk(loc, g.pointer("machine_loop_proof", "per_loop"))
        if not isinstance(per, list) or len(per) != n_loops:
            raise Dep(R["count_disagreement"], loc,
                      "the proof states %d loops and carries %s per-loop records; the count "
                      "in the record must equal the record"
                      % (n_loops, len(per) if isinstance(per, list) else "no"))
        bkey = g.pointer("machine_loop_proof", "per_loop_bound_key")
        bounded, wrong = 0, []
        for i, r in enumerate(per):
            if not isinstance(r, dict):
                raise Dep(R["wrong_type"], loc, "per-loop record %d is not a map" % i)
            v = r.get(bkey)
            if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
                wrong.append("loop %d: %s = %r" % (i, bkey, v))
            else:
                bounded += 1
        if wrong:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "per-loop bound(s) missing or not a positive integer: "
                                       "%s" % "; ".join(wrong[:6])}
        return PASS, {"object": obj_loc, "object_sha256": osha,
                      "n_loops": n_loops, "n_loops_proven_with_a_finite_bound": n_proven,
                      "n_loops_recounted_by_this_gate": bounded,
                      "n_uncovered_backward_branches": n_uncovered,
                      "n_instructions_the_proof_observed":
                          counts.get("n_instructions_object"),
                      "counted_by": "this gate counted the per-loop records and their bounds "
                                    "itself; it did not read a summary count",
                      "ceiling": "a STATIC proof of bounded trip counts.  It does not "
                                 "establish termination on hardware, that the bound is correct "
                                 "for the emitted machine code, or anything about the device."}

    P.append(("machine_loop_proof_is_bound_to_this_object",
              "the loop proof is about this object and every loop has a finite bound",
              p_machine_loop_proof_is_bound_to_this_object))

    def p_memory_bounds_are_bound_to_the_object_and_the_source():
        loc = g.loc("memory_bounds")
        doc = g.json(loc)
        g.verify_object_block_present(
            "memory_bounds",
            "a memory-bounds analysis stated for a different object is not this experiment's "
            "memory-bounds evidence")
        srow = g.walk(loc, g.pointer("memory_bounds", "source"))
        if not isinstance(srow, dict) or not isinstance(srow.get("path"), str):
            raise Dep(R["wrong_type"], loc, "the bounds record's source block names no path")
        src_loc = g.to_locator(srow["path"])
        if not os.path.isfile(g.path_of(src_loc)):
            raise Dep(R["not_a_file"], src_loc, "the bounds record's source")
        ok = g.led.same(F(loc, "source.sha256", srow.get("sha256")),
                        F(src_loc, "sha256_file(the bytes on disk)", g.raw_sha(src_loc)),
                        "the bounds record's source digest vs the source on disk")
        if not ok:
            return REFUSED, {"requirement_fired": R["foreign_subject"], "absent_or_bad_path": loc,
                             "detail": "the memory-bounds record names source %r with digest "
                                       "%s, which is not the digest of that file"
                                       % (srow.get("path"), srow.get("sha256"))}
        _r, b2 = g.check_bindings(
            "source_cpp_sha256",
            "the source the bounds are derived from must be the subject's frozen source",
            only=("memory_bounds",))
        stops = []
        if isinstance(doc.get("verdict"), str) and doc["verdict"] not in PASS_VERDICTS:
            stops.append("%s = %r" % ("verdict", doc["verdict"]))
        for k, v in sorted(doc.items()):
            if isinstance(v, dict) and isinstance(v.get("verdict"), str) \
                    and v["verdict"] not in PASS_VERDICTS:
                stops.append("%s.verdict = %r" % (k, v["verdict"]))
        if stops:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "the memory-bounds record states a stopping verdict, so "
                                       "its access rows are not a bound anything may rely on: "
                                       "%s" % "; ".join(stops),
                             "source": src_loc,
                             "what_a_reader_should_take_from_this": "the 16AS bounds record "
                                 "itself says STOP; it is not a proof that the slot's memory "
                                 "accesses are bounded"}
        acc = g.walk(loc, g.pointer("memory_bounds", "accesses"))
        if not isinstance(acc, list) or not acc:
            raise Dep(R["missing_key"], loc, "the bounds record lists no accesses")
        n_declared = g.walk(loc, g.pointer("memory_bounds", "n_accesses"))
        if n_declared != len(acc):
            raise Dep(R["count_disagreement"], loc,
                      "the record says %r accesses and lists %d" % (n_declared, len(acc)))
        flag_in = g.pointer("memory_bounds", "within_allocation_flag")
        flag_agree = g.pointer("memory_bounds", "two_routes_agree_flag")
        every_in = g.walk(loc, g.pointer("memory_bounds", "every_access_inside"))
        every_agree = g.walk(loc, g.pointer("memory_bounds", "every_route_agrees"))
        bad_rows, rows = [], []
        for i, r in enumerate(acc):
            if not isinstance(r, dict):
                raise Dep(R["wrong_type"], loc, "access %d is not a map" % i)
            cf, en = r.get("closed_form_max_byte_offset"), r.get("enumerated_max_byte_offset")
            alloc, extent = r.get("allocation_bytes"), r.get("final_maximum_extent")
            rows.append({"access": r.get("pointer", i), "allocation_bytes": alloc,
                         "max_extent": extent, "closed_form": cf, "enumerated": en,
                         flag_in: r.get(flag_in), flag_agree: r.get(flag_agree)})
            if r.get(flag_in) is not True:
                bad_rows.append("access %s is not inside its allocation" % r.get("pointer", i))
            if r.get(flag_agree) is not True:
                bad_rows.append("access %s: the two derivations disagree" % r.get("pointer", i))
            if isinstance(cf, int) and isinstance(en, int) and cf != en:
                bad_rows.append("access %s: closed form %d != enumeration %d"
                                % (r.get("pointer", i), cf, en))
            if isinstance(extent, int) and isinstance(alloc, int) and extent > alloc:
                bad_rows.append("access %s: extent %d exceeds the allocation %d"
                                % (r.get("pointer", i), extent, alloc))
        if every_in is not True or every_agree is not True:
            bad_rows.append("the record's own summary flags are %s=%r, %s=%r"
                            % (g.pointer("memory_bounds", "every_access_inside"), every_in,
                               g.pointer("memory_bounds", "every_route_agrees"), every_agree))
        if bad_rows:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "access(es) not bounded: %s" % "; ".join(bad_rows[:8]),
                             "accesses_checked": rows}
        return PASS, {"source": src_loc, "n_accesses_rechecked": len(acc), "accesses": rows,
                      "what_this_establishes": "every declared access was re-derived here from "
                                               "its own record: the extent fits the "
                                               "allocation, the closed form equals the "
                                               "enumeration, and no verdict in the record says "
                                               "STOP or FAIL",
                      "ceiling": "the bound is only as good as the enumeration the record "
                                 "carries; this gate checks the record's internal consistency "
                                 "and its binding to this object, not the disassembly it came "
                                 "from"}

    P.append(("memory_bounds_are_bound_to_the_object_and_the_source",
              "every declared memory access is bounded inside its allocation",
              p_memory_bounds_are_bound_to_the_object_and_the_source))

    def p_execute_backend_is_a_real_backend_and_is_bound():
        bloc = g.loc("execute_backend_build")
        build = g.json(bloc)
        iloc = g.loc("execute_backend_imports")
        imp = g.json(iloc)
        irows = g.need(imp, iloc, "rows", list)
        if not irows:
            raise Dep(R["missing_key"], iloc, "the import table carries no rows")
        by_name = {}
        for r in irows:
            if isinstance(r, dict) and isinstance(r.get("target"), str):
                by_name[os.path.basename(r["target"])] = r
        targets = g.need(build, bloc, "targets", list)
        if not targets:
            raise Dep(R["missing_key"], bloc, "the build record names no targets")
        ek, ak, dk = (g.pointer("execute_backend", "exe_key"),
                      g.pointer("execute_backend", "all_imports_key"),
                      g.pointer("execute_backend", "decoders_agree_key"))
        measured, launchers, others, bad = [], [], [], []
        for t in targets:
            if not isinstance(t, dict):
                raise Dep(R["wrong_type"], bloc, "a target is not a map")
            exe = t.get(ek)
            if not isinstance(exe, str) or not exe:
                raise Dep(R["missing_key"], bloc, "a target names no %r" % ek)
            name = os.path.basename(exe)
            tloc = g.to_locator(exe)
            if not os.path.isfile(g.path_of(tloc)):
                raise Dep(R["not_a_file"], tloc, "the build record names target %s" % name)
            sha = g.raw_sha(tloc)
            decl = t.get(g.pointer("execute_backend", "exe_sha_key"))
            if decl is None:
                raise Dep(R["missing_key"], bloc,
                          "target %s declares no exe digest, so the binary on disk cannot be "
                          "tied to the build record" % name)
            eq = g.led.same(F(tloc, "sha256_file(the bytes on disk)", sha),
                            F(bloc, "targets[]/%s" % g.pointer("execute_backend", "exe_sha_key"),
                              decl),
                            "the built binary %s on disk vs the build record" % name)
            if not eq:
                bad.append("%s: on-disk digest != build record" % name)
            try:
                dlls = sorted(set(pe_imported_dlls(g.raw(tloc))))
            except Exception as exc:                          # noqa: BLE001
                raise Dep(R["not_met"], tloc,
                          "the import table of %s could not be walked: %s: %s"
                          % (name, type(exc).__name__, exc))
            hip = sorted(d for d in dlls if looks_like_hip(d))
            rec = by_name.get(name)
            if rec is None:
                raise Dep(R["missing_key"], iloc, "the import table carries no row for %s" % name)
            if rec.get("present") is not True:
                bad.append("%s: the import table says the binary is not present" % name)
            if rec.get(dk) is not True:
                bad.append("%s: the import table's decoders did not agree" % name)
            d_hip = sorted(rec.get("hip_imports") or [])
            if not g.led.same(
                    F(iloc, "rows/%s/hip_imports" % name, d_hip),
                    F(tloc, "the PE import table, walked in this process", hip),
                    "the recorded HIP imports for %s vs the HIP imports this gate measured"
                    % name):
                bad.append("%s: import table says %r, this gate measured %r" % (name, d_hip, hip))
            t_imp = t.get("imports")
            if isinstance(t_imp, dict) and ak in t_imp:
                if not g.led.same(
                        F(bloc, "targets[]/imports/%s" % ak, sorted(t_imp[ak])),
                        F(tloc, "the PE import table, walked in this process", dlls),
                        "the build record's whole import list for %s vs this gate's "
                        "measurement" % name):
                    bad.append("%s: build record says %r, this gate measured %r"
                               % (name, sorted(t_imp[ak]), dlls))
            measured.append({"target": name, "locator": tloc, "exe_sha256": sha,
                             "all_imports": dlls, "hip_imports": hip,
                             "matches_the_build_record": bool(eq)})
            (launchers if hip else others).append(name)
        if bad:
            return REFUSED, {"requirement_fired": R["digest_disagreement"],
                             "absent_or_bad_path": bloc,
                             "detail": "the build record and the binaries on disk disagree: "
                                       "%s" % "; ".join(bad[:6]), "measured": measured}
        if len(launchers) != 1:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": bloc,
                             "detail": "the build record names %d binary/binaries that import a "
                                       "HIP runtime (%s); a prepare/execute separation has "
                                       "exactly one launch binary.  A backend that is not "
                                       "separated from its preparation or its mock cannot be "
                                       "shown to be the launch path."
                                       % (len(launchers), ", ".join(launchers) or "none"),
                             "measured": measured}
        if not others:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": bloc,
                             "detail": "every named binary imports HIP, so nothing shows that "
                                       "a preparation path exists which cannot launch",
                             "measured": measured}
        r2, b2 = g.check_bindings(
            "descriptor_module_sha256",
            "the descriptor module the binaries were built against must be the module on disk")
        if b2:
            return REFUSED, {"requirement_fired": R["foreign_subject"],
                             "absent_or_bad_path": g.loc("descriptor_module"),
                             "detail": "artefact(s) %s state a different descriptor-module digest"
                                       % ", ".join(b2), "compared": r2}
        return PASS, {"launch_binary": launchers[0], "non_launching_binaries": others,
                      "n_targets": len(targets), "measured": measured,
                      "how": "the HIP import of every named binary was measured in THIS process "
                             "by walking its PE import table; the build record and the import "
                             "table are compared against that measurement, not against each "
                             "other alone",
                      "n_descriptor_module_declarations_compared": len(r2), "compared": r2}

    P.append(("execute_backend_is_a_real_backend_and_is_bound",
              "there is a built binary that can launch, and only one",
              p_execute_backend_is_a_real_backend_and_is_bound))

    def p_positive_mock_execution_reaches_the_expected_output():
        loc = g.loc("positive_mock_execution")
        doc = g.json(loc)
        keys = g.subject()["pointers"]["positive_mock_execution"]
        rows, bad = [], []
        for kind in ("execute_descriptor_sha256", "descriptor_module_sha256"):
            r, b = g.check_bindings(kind, "the mock run must be a run of THIS descriptor",
                                    only=("positive_mock_execution",))
            rows.extend(r)
            bad.extend(b)
        if doc.get(keys.get("expect_qualified_key", "expect_qualified")) is not True:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "the artefact does not expect the positive case to "
                                       "qualify: %s = %r"
                                       % (keys.get("expect_qualified_key"),
                                          doc.get(keys.get("expect_qualified_key")))}
        first = g.need(doc, loc, "first", dict)
        n_ok = 0
        for bucket, on_first in (("must_be_true_on_first", True),
                                 ("must_be_false_on_first", True),
                                 ("must_equal_zero_on_first", True),
                                 ("must_equal_one_on_first", True),
                                 ("must_equal_on_first", True),
                                 ("must_equal_on_top_level", False)):
            for key, want in sorted((keys.get(bucket) or {}).items()):
                src = first if on_first else doc
                got = src.get(key)
                if got != want:
                    bad.append("%s%s = %r, expected %r"
                               % ("" if on_first else "top-level ", key, got, want))
                else:
                    n_ok += 1
        if first.get(keys.get("backend_key", "backend")) != keys.get("backend_is", "mock"):
            raise Dep(R["malformed"], loc,
                      "the positive case did not run on the mock backend (backend = %r); this "
                      "predicate is about a mock run" % first.get(keys.get("backend_key", "backend")))
        n_decl = doc.get(keys.get("expect_qualified_key", "expect_qualified"))
        if n_decl is not None and n_decl is not True:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "the artefact does not expect the positive case to "
                                       "qualify: %s = %r"
                                       % (keys.get("expect_qualified_key"), n_decl)}
        eo_loc = g.expected_output_locator()
        eo_len = len(g.raw(eo_loc))
        rb = keys.get("readback_bytes_key", "readback_bytes")
        if first.get(rb) != eo_len:
            bad.append("%s = %r, expected the expected output's %d bytes"
                       % (rb, first.get(rb), eo_len))
        else:
            n_ok += 1
        mock_note = first.get(keys.get("mock_note_key", "mock_note"))
        if not isinstance(mock_note, str) or not mock_note:
            raise Dep(R["missing_key"], loc,
                      "the mock run states no mock_note; a mock that does not say what it "
                      "planted cannot be told from a real execution")
        steps = first.get("steps")
        if not isinstance(steps, list) or not steps:
            raise Dep(R["missing_key"], loc, "the mock run lists no steps")
        completed = first.get(keys.get("steps_completed_key", "steps_completed"))
        if completed != len(steps):
            bad.append("%s = %r but %d steps are listed" % (keys.get("steps_completed_key"),
                                                            completed, len(steps)))
        else:
            n_ok += 1
        checks = first.get("checks")
        if not isinstance(checks, list) or not checks:
            raise Dep(R["missing_key"], loc, "the mock run lists no checks")
        not_ok = [c.get("id") for c in checks
                  if not isinstance(c, dict) or c.get("ok") is not True]
        if not_ok:
            bad.append("checks not ok: %r" % (not_ok[:6],))
        rb_sha = first.get(keys.get("readback_sha_key", "out_h_readback_sha256"))
        if isinstance(rb_sha, str):
            h_rel = keys.get("device_output_role", "out_h")
            h_loc = None
            for r, b in (g.json(g.manifest_loc()).get("buffers") or {}).items():
                if isinstance(b, dict) and isinstance(b.get("path"), str) \
                        and r == h_rel:
                    h_loc = b["path"]
            if h_loc is None:
                raise Dep(R["missing_key"], g.manifest_loc(),
                          "the manifest names no %r buffer, so the bytes the backend read "
                          "back cannot be compared against an artefact" % h_rel)
            if not g.led.same(
                    F(loc, "first.%s" % keys.get("readback_sha_key"), rb_sha),
                    F(h_loc, "sha256_file(the bytes on disk)", g.raw_sha(h_loc)),
                    "the bytes the backend read back from the device vs the fixture's own "
                    "device-output file"):
                bad.append("the readback does not match %s" % h_loc)
        if bad:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "the positive mock run did not reach the expected output "
                                       "on every measured quantity: %s" % "; ".join(bad[:8]),
                             "compared": rows}
        indep = first.get(keys.get("independent_expectation_key",
                                   "out_h_has_an_independent_expectation"))
        if indep is None:
            raise Dep(R["missing_key"], loc,
                      "the mock run does not state whether the output it planted has an "
                      "independent expectation")
        return PASS, {"n_quantities_verified": n_ok, "n_steps": len(steps),
                      "n_checks": len(checks),
                      "mock_note": mock_note,
                      "out_h_has_an_independent_expectation": indep,
                      "compared": rows,
                      "what_this_establishes": "the orchestration runs end to end on the mock "
                                               "backend -- device selection, allocation, guard "
                                               "fill, upload, module load, symbol resolve, "
                                               "kernarg packing, exactly one launch, readback, "
                                               "byte comparison and guard check -- and reaches "
                                               "the planned output with no fault",
                      "ceiling": "the mock PLANTS the descriptor's expected artifact, byte for "
                                 "byte.  This proves the pipeline reaches the observer; it does "
                                 "NOT prove the arithmetic, the kernel, or the device.  The "
                                 "independent-expectation flag is %r." % (indep,)}

    P.append(("positive_mock_execution_reaches_the_expected_output",
              "a positive mock run reaches the expected output",
              p_positive_mock_execution_reaches_the_expected_output))

    def p_negative_mock_suite_rejects_at_the_named_requirement():
        loc = g.loc("negative_mock_suite")
        doc = g.json(loc)
        if doc.get("errors"):
            return REFUSED, {"requirement_fired": R["malformed"], "absent_or_bad_path": loc,
                             "detail": "the suite reports errors of its own: %r"
                                       % (doc.get("errors"),)}
        for key, want, why in (
                ("one_case_per_process", True, "each case must run in its own process, or a "
                                               "fault in one case can be masked by state from "
                                               "another"),
                ("execute_binary_was_not_executed", True,
                 "the execute binary must not run during a mock suite"),
                ("host_only", True, "the suite must be host-only")):
            if doc.get(key) != want:
                raise Dep(R["not_met"], loc, "%s = %r; %s" % (key, doc.get(key), why))
        if doc.get("gpu_calls") != 0:
            raise Dep(R["not_met"], loc,
                      "the suite reports %r GPU calls; a mock suite makes none"
                      % doc.get("gpu_calls"))
        n_declared = doc.get("n_cases")
        cases = g.need(doc, loc, "cases", list)
        if n_declared != len(cases):
            raise Dep(R["count_disagreement"], loc,
                      "the suite states n_cases = %r and carries %d" % (n_declared, len(cases)))
        listing = g.need(doc, loc, "case_listing_from_the_driver", list)
        listed = []
        for row in listing:
            if not isinstance(row, str):
                raise Dep(R["wrong_type"], loc, "a case-listing row is not a string")
            parts = row.split("\t")
            if len(parts) < 3 or not parts[0]:
                raise Dep(R["malformed"], loc,
                          "a case-listing row is not CASE<TAB>EXPECT_FAULT<TAB>EXPECT_PACK"
                          "<TAB>EXPECT_CHECK: %r" % row[:80])
            listed.append({"CASE": parts[0].strip(), "EXPECT_FAULT": parts[1].strip(),
                           "EXPECT_PACK_MODE": parts[2].strip(),
                           "EXPECT_CHECK": (parts[3].strip() if len(parts) > 3 else "")})
        by_name = {c.get("case"): c for c in cases if isinstance(c, dict)}
        dloc = g.loc("execute_descriptor")
        dsha = g.raw_sha(dloc)
        dup = doc.get("descriptor_sha_on_disk")
        if dup is None:
            raise Dep(R["missing_key"], loc,
                      "the suite does not state the descriptor digest it ran against, so it "
                      "cannot be tied to the descriptor on disk")
        if not g.led.same(F(loc, "descriptor_sha_on_disk", dup),
                          F(dloc, "sha256_file(the bytes on disk)", dsha),
                          "the suite's descriptor digest vs the descriptor on disk"):
            raise Dep(R["foreign_subject"], loc,
                      "the suite ran against descriptor %s; the descriptor on disk hashes to "
                      "%s" % (dup, dsha))
        mdup = doc.get("module_sha_on_disk")
        if mdup is not None:
            if not g.led.same(F(loc, "module_sha_on_disk", mdup),
                              F(g.loc("descriptor_module"), "sha256_file(the bytes on disk)",
                                g.raw_sha(g.loc("descriptor_module"))),
                              "the suite's descriptor-module digest vs the module on disk"):
                raise Dep(R["foreign_subject"], loc,
                          "the suite's module digest is not the module on disk")
        fp = g.pointer("negative_mock_suite", "fingerprint")
        first_case = cases[0] if cases and isinstance(cases[0], dict) else None
        n_reject, n_invalid, n_accept, bad, rows = 0, 0, 0, [], []
        for row in listed:
            name = row["CASE"]
            c = by_name.get(name)
            if c is None:
                raise Dep(R["missing_key"], loc,
                          "the driver listed case %r and the suite carries no record for it"
                          % name)
            if c.get("ok") is not True:
                bad.append("%s: the case record is not ok" % name)
            out = c.get("driver_output")
            if not isinstance(out, str) or "GATE_FINGERPRINT=" not in out:
                bad.append("%s: the driver's own output was not captured" % name)
            elif "GATE_SUMMARY" not in out or "failures=0" not in out:
                bad.append("%s: the driver's summary line is absent or reports failures" % name)
            elif row["EXPECT_CHECK"] and "refused_check=" not in out:
                bad.append("%s: the driver's output does not report which check refused" % name)
            elif row["EXPECT_CHECK"] and ("refused_check=%s" % row["EXPECT_CHECK"]) not in out:
                bad.append("%s: the driver's own output does not name %s as the refusing check"
                           % (name, row["EXPECT_CHECK"]))
            facts = c.get("facts")
            if not isinstance(facts, dict):
                raise Dep(R["missing_key"], loc, "case %s carries no facts block" % name)
            if facts.get("gate_fingerprint") and facts["gate_fingerprint"] not in out:
                bad.append("%s: the fingerprint in the record is not the one the driver printed"
                           % name)
            if facts.get("fault") != row["EXPECT_FAULT"]:
                bad.append("%s: the driver reported fault=%r, the listing expects %r"
                           % (name, facts.get("fault"), row["EXPECT_FAULT"]))
            if facts.get("pack_mode") != row["EXPECT_PACK_MODE"]:
                bad.append("%s: the driver reported pack_mode=%r, the listing expects %r"
                           % (name, facts.get("pack_mode"), row["EXPECT_PACK_MODE"]))
            ev = c.get("evidence")
            if c.get("evidence_written") is not True or not isinstance(ev, str):
                bad.append("%s: no evidence file was written" % name)
            else:
                el = g.to_locator(ev)
                if not os.path.isfile(g.path_of(el)):
                    raise Dep(R["not_a_file"], el,
                              "the evidence file the suite names for case %s" % name)
                try:
                    parsed = json.loads(g.raw(el).decode("utf-8"))
                except Exception as exc:                      # noqa: BLE001
                    raise Dep(R["malformed"], el,
                              "the evidence for case %s is not JSON: %s" % (name, exc))
                if parsed.get("case") != name:
                    bad.append("%s: the evidence file on disk is about case %r"
                               % (name, parsed.get("case")))
                pf = parsed.get("first")
                if not isinstance(pf, dict):
                    bad.append("%s: the evidence file carries no first run" % name)
                else:
                    if pf.get("fault") != facts.get("fault"):
                        bad.append("%s: the evidence file's fault %r != the record's %r"
                                   % (name, pf.get("fault"), facts.get("fault")))
                    if bool(pf.get("qualified")) != bool(facts.get("first_qualified")):
                        bad.append("%s: the evidence file's qualified flag disagrees with the "
                                   "record" % name)
                    if pf.get("refused_check") != facts.get("first_refused_check"):
                        bad.append("%s: the evidence file's refusing check %r != the record's %r"
                                   % (name, pf.get("refused_check"),
                                      facts.get("first_refused_check")))
            if c.get("expect_invalid_case") is True:
                if c.get("expect_check"):
                    bad.append("%s: declared INVALID but names a check %r"
                               % (name, c.get("expect_check")))
                if facts.get("first_qualified") is not True \
                        or facts.get("first_refused") is not False:
                    bad.append("%s: a case declared INVALID must still reach QUALIFIED, to be "
                               "shown to be a fault that was never applied" % name)
                if not str(c.get("why") or "").strip():
                    raise Dep(R["missing_key"], loc,
                              "case %s is declared INVALID without a reason" % name)
                n_invalid += 1
                rows.append({"case": name, "counted_as": "INVALID_CONTROL_NOT_A_REJECTION",
                             "why": _short(c.get("why"))})
                continue
            if c.get("expect_qualified") is True:
                if facts.get("first_qualified") is True:
                    n_accept += 1
                else:
                    bad.append("%s: a declared positive case did not qualify" % name)
                rows.append({"case": name, "counted_as": "ACCEPTED"})
                continue
            if not row["EXPECT_CHECK"]:
                # The driver's own listing names no check for this case, so the case is
                # declared to SUCCEED.  The requirement comes from the driver's listing and
                # the case's own stated reason, not from a literal in this gate.
                why2 = str(c.get("why") or "").strip() or \
                    str(((c.get("raw") or {}) or {}).get("case_why") or "").strip()
                if not why2:
                    raise Dep(R["missing_key"], loc,
                              "case %s is listed with no expected check and states no reason "
                              "to expect success" % name)
                if facts.get("first_qualified") is not True or facts.get("first_refused") is True:
                    bad.append("%s: a case the driver lists with no expected check did not "
                               "qualify" % name)
                else:
                    n_accept += 1
                rows.append({"case": name, "counted_as": "ACCEPTED", "why": _short(why2)})
                continue
            if c.get("expect_check") != row["EXPECT_CHECK"]:
                bad.append("%s: the record expects check %r, the listing says %r"
                           % (name, c.get("expect_check"), row["EXPECT_CHECK"]))
            refused = facts.get("first_refused") is True and \
                facts.get("first_refused_check") == row["EXPECT_CHECK"]
            second = facts.get("second_refused_check") == row["EXPECT_CHECK"]
            if refused or second:
                if facts.get("first_reached_observer") is not True:
                    bad.append("%s: the refusal happened before the observation point, so it is "
                               "INVALID as a control, not a rejection" % name)
                else:
                    n_reject += 1
            else:
                bad.append("%s: not refused at %r (first_refused=%r, first_refused_check=%r, "
                           "second_refused_check=%r)"
                           % (name, row["EXPECT_CHECK"], facts.get("first_refused"),
                              facts.get("first_refused_check"),
                              facts.get("second_refused_check")))
            rows.append({"case": name, "expected_check": row["EXPECT_CHECK"],
                         "refused_at": facts.get("first_refused_check"),
                         "second_refused_at": facts.get("second_refused_check"),
                         "reached_observer": facts.get("first_reached_observer"),
                         "counted_as": "REJECTED_AT_THE_NAMED_REQUIREMENT"
                         if (refused or second)
                         and facts.get("first_reached_observer") is True else "NOT_COUNTED"})
        x = doc.get("cross_executable_fingerprint")
        if not isinstance(x, dict):
            raise Dep(R["missing_key"], loc,
                      "no cross-executable fingerprint block; the suite cannot show that the "
                      "prepare gate and the mock driver were built from one expression over "
                      "one descriptor")
        if x.get("one_value") is not True:
            bad.append("the prepare gate and the mock driver do not share one fingerprint")
        got = set()
        for v in [x.get("prepare_gate_fingerprint")] + list(x.get("mock_driver_gate_fingerprints") or []):
            if v:
                got.add(v)
        if len(got) > 1:
            bad.append("more than one gate fingerprint appears: %r" % (sorted(got),))
        if isinstance(first_case, dict) and isinstance(first_case.get("facts"), dict) \
                and got and first_case["facts"].get("gate_fingerprint") not in got:
            bad.append("the first case's fingerprint is not the shared one")
        prep = doc.get("prepare")
        if isinstance(prep, dict):
            line = prep.get("gate_summary_line") or ""
            if "failures=0" not in line:
                bad.append("the prepare gate's summary line reports failures: %r" % line)
            if prep.get("module_sha_agrees_with_disk") is not True:
                bad.append("the prepare gate's descriptor-module digest does not agree with disk")
            if prep.get("exit_code") not in (0,):
                bad.append("the prepare gate exited %r" % prep.get("exit_code"))
        if n_reject < 1:
            raise Dep(R["not_met"], loc,
                      "no negative case was rejected at its named requirement; a suite where "
                      "nothing reaches the observer proves nothing")
        if n_accept < 1:
            raise Dep(R["not_met"], loc,
                      "no declared positive case was accepted; a suite that rejects everything, "
                      "including its own control, is a broken instrument")
        if bad:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "the negative suite does not hold together: %s"
                                       % "; ".join(bad[:8]), "cases": rows}
        return PASS, {"n_cases": len(cases), "n_listed_by_the_driver": len(listed),
                      "n_rejected_at_the_named_requirement": n_reject,
                      "n_invalid_controls_not_counted_as_rejections": n_invalid,
                      "n_positive_cases_accepted": n_accept,
                      "shared_gate_fingerprint": sorted(got), "cases": rows,
                      "what_this_establishes": "each negative case was refused, at the "
                                               "requirement the driver's OWN listing named, "
                                               "only after reaching the observation point, and "
                                               "the evidence file on disk for the case agrees "
                                               "with the record -- so each is a real rejection "
                                               "rather than an instrument that never ran",
                      "ceiling": "this is a mock suite.  It shows the checks are wired to the "
                                 "quantities they claim to check.  It is not evidence about the "
                                 "device, and the INVALID cases above are excluded from the "
                                 "rejection count."}

    P.append(("negative_mock_suite_rejects_at_the_named_requirement",
              "every negative control is refused at the requirement it names",
              p_negative_mock_suite_rejects_at_the_named_requirement))

    def p_preparation_receipt_is_bound():
        loc = g.loc("preparation_receipt")
        doc = g.json(loc)
        rows, bad = g.check_bindings("experiment_id",
                                     "the receipt must be a receipt for THIS experiment",
                                     only=("preparation_receipt",))
        if bad:
            return REFUSED, {"requirement_fired": R["foreign_subject"], "absent_or_bad_path": loc,
                             "detail": "the receipt names a different experiment"}
        cloc = g.loc("native_prepare_only_chain")
        chain = g.json(cloc)
        argv = g.need(chain, cloc, "argv", list)
        if not argv or not all(isinstance(a, str) for a in argv):
            raise Dep(R["wrong_type"], cloc, "the chain's argv is not a list of strings")
        harness_loc = g.to_locator(argv[0])
        if not os.path.isfile(g.path_of(harness_loc)):
            raise Dep(R["not_a_file"], harness_loc,
                      "the harness the chain invoked, named by its own argv[0]")
        hsha = g.raw_sha(harness_loc)
        decl = g.need(chain, cloc, "harness_sha256", str)
        if not g.led.same(F(harness_loc, "sha256_file(the bytes on disk)", hsha),
                          F(cloc, "harness_sha256", decl),
                          "the harness on disk vs the digest the chain recorded for it"):
            return REFUSED, {"requirement_fired": R["digest_disagreement"],
                             "absent_or_bad_path": harness_loc,
                             "detail": "the harness the chain invoked is not the harness the "
                                       "chain recorded: on disk %s, recorded %s" % (hsha, decl)}
        try:
            dlls = sorted(set(pe_imported_dlls(g.raw(harness_loc))))
        except Exception as exc:                              # noqa: BLE001
            raise Dep(R["not_met"], harness_loc,
                      "the harness's import table could not be walked: %s: %s"
                      % (type(exc).__name__, exc))
        hip = sorted(d for d in dlls if looks_like_hip(d))
        if hip:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": harness_loc,
                             "detail": "the preparation harness imports %r; a preparation path "
                                       "that can reach the runtime is not a preparation-only "
                                       "path" % (hip,)}
        for key, want, why in (("launched", False, "the chain reports launched = %r"),
                               ("harness_hip_imports", [], "the chain records HIP imports %r in "
                                                            "a preparation harness"),
                               ("hip_calls_made_by_this_chain", 0, "the chain records %r HIP "
                                                                   "calls"),
                               ("gates_failed", 0, "the receipt reports %r failed gates")):
            src = chain if key in chain else doc
            got = src.get(key)
            if key == "launched":
                if got not in (False, 0):
                    return REFUSED, {"requirement_fired": R["not_met"],
                                     "absent_or_bad_path": cloc, "detail": why % got}
            elif got != want:
                return REFUSED, {"requirement_fired": R["not_met"],
                                 "absent_or_bad_path": cloc if src is chain else loc,
                                 "detail": why % (got,)}
        n_pass = doc.get("gates_passed")
        if not isinstance(n_pass, int) or n_pass <= 0:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "the receipt reports %r passed gates; a receipt that ran "
                                       "no gate certifies nothing" % (n_pass,)}
        if doc.get("hip_symbols_in_this_binary"):
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "the receipt records HIP symbols %r in the preparation "
                                       "harness" % (doc.get("hip_symbols_in_this_binary"),)}
        if doc.get("verdict") not in PASS_VERDICTS:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "the receipt's verdict is %r" % doc.get("verdict")}
        r2, b2 = g.check_bindings("harness_contract_sha256",
                                  "the contract the receipt is about must be the contract on "
                                  "disk",
                                  only=("preparation_receipt", "native_prepare_only_chain"))
        if b2:
            return REFUSED, {"requirement_fired": R["digest_disagreement"],
                             "absent_or_bad_path": g.loc("harness_contract"),
                             "detail": "artefact(s) %s state a different contract digest"
                                       % ", ".join(b2), "compared": r2}
        dloc = g.loc("execute_descriptor")
        drows = g.json(dloc)
        abi_rows = []
        abi = g.need(doc, loc, "declared_abi", dict)
        for k in sorted(abi.keys()):
            if k not in drows:
                raise Dep(R["missing_key"], dloc,
                          "the receipt declares ABI %r and the descriptor does not carry it" % k)
            want = _int_at(drows, k, dloc, convert=True)
            if not g.led.same(F(loc, "declared_abi/%s" % k, abi[k]), F(dloc, k, want),
                              "the receipt's declared %s vs the descriptor's" % k):
                return REFUSED, {"requirement_fired": R["count_disagreement"],
                                 "absent_or_bad_path": loc,
                                 "detail": "the receipt's declared ABI %s = %r does not match "
                                           "the descriptor's %r" % (k, abi[k], want)}
            abi_rows.append({"fact": k, "receipt": abi[k], "descriptor": want})
        return PASS, {"harness": harness_loc, "harness_sha256": hsha,
                      "harness_imports": dlls, "harness_has_no_hip_import": True,
                      "launched": chain.get("launched"),
                      "harness_hip_imports": chain.get("harness_hip_imports"),
                      "hip_calls_made_by_this_chain": chain.get("hip_calls_made_by_this_chain"),
                      "gates_passed": n_pass,
                      "n_experiment_id_declarations_compared": len(rows),
                      "abi_compared": abi_rows,
                      "compared": r2,
                      "how": "the harness path comes from the chain's own argv[0]; its bytes "
                             "are re-hashed here and its import table is walked here, so the "
                             "receipt's 'no HIP import' claim is re-measured rather than read"}

    P.append(("preparation_receipt_is_bound",
              "the preparation receipt is for this experiment and its harness cannot launch",
              p_preparation_receipt_is_bound))

    def p_validated_command_identity_is_bound():
        cloc = g.loc("native_prepare_only_chain")
        chain = g.json(cloc)
        argv = g.need(chain, cloc, "argv", list)
        claimed = g.need(chain, cloc, "argv_sha256", str)
        got = utf8_json_sha256(argv)
        if not g.led.same(
                F(cloc, "sha256(json.dumps(argv)) computed in this process", got),
                F(cloc, "argv_sha256", claimed),
                "the canonical argv digest vs the stored one"):
            return REFUSED, {"requirement_fired": R["digest_disagreement"],
                             "absent_or_bad_path": cloc,
                             "detail": "the stored argv digest is not the digest of the stored "
                                       "argv", "recomputed": got}
        flag = g.pointer("validated_command", "contract_flag")
        if flag not in argv:
            raise Dep(R["missing_key"], cloc,
                      "the chain's argv carries no %r, so the file the command is validated "
                      "against cannot be located in it" % flag)
        i = argv.index(flag)
        if i + 1 >= len(argv):
            raise Dep(R["malformed"], cloc, "%r is the last element of argv" % flag)
        from_argv = argv[i + 1]
        want = g.path_of(g.loc("harness_contract"))
        if not g.led.same_path(
                F(cloc, "argv[%d] (the value after %s)" % (i + 1, flag), from_argv),
                F(g.subject_file, "locators.harness_contract", want),
                "the contract the command names vs the contract the subject declares"):
            return REFUSED, {"requirement_fired": R["foreign_subject"], "absent_or_bad_path": cloc,
                             "detail": "the validated command names contract %r, which is not "
                                       "the declared contract %r" % (from_argv, want)}
        dloc = g.loc("execute_descriptor")
        drows = g.json(dloc)
        dsha = g.raw_sha(dloc)
        rows, bad = g.check_bindings(
            "execute_descriptor_sha256",
            "whoever states the descriptor's digest must state the digest of the descriptor on "
            "disk")
        if bad:
            return REFUSED, {"requirement_fired": R["foreign_subject"], "absent_or_bad_path": dloc,
                             "detail": "artefact(s) %s state a different descriptor digest; the "
                                       "descriptor on disk hashes to %s" % (", ".join(bad), dsha),
                             "compared": rows}
        rec_loc = g.loc("execute_descriptor_record")
        rec = g.json(rec_loc)
        if rec.get("descriptor_has_no_self_digest") is not True:
            return REFUSED, {"requirement_fired": R["malformed"], "absent_or_bad_path": rec_loc,
                             "detail": "the record does not state that the descriptor carries "
                                       "no self-digest; a descriptor that authenticated itself "
                                       "could be edited to authenticate anything"}
        nbytes = rec.get("descriptor_bytes")
        if nbytes is not None and nbytes != len(g.raw(dloc)):
            return REFUSED, {"requirement_fired": R["count_disagreement"],
                             "absent_or_bad_path": rec_loc,
                             "detail": "the record states %r descriptor bytes; the descriptor is "
                                       "%d bytes" % (nbytes, len(g.raw(dloc)))}
        if rec.get("gpu_calls") not in (0, None):
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": rec_loc,
                             "detail": "the descriptor record reports %r GPU calls"
                                       % (rec.get("gpu_calls"),)}
        pa_desc = g.need(drows, dloc, "physical_authorization", str)
        pa_rec = g.need(rec, rec_loc, "physical_authorization", str)
        if not g.led.same(F(rec_loc, "physical_authorization", pa_rec),
                          F(dloc, "physical_authorization", pa_desc),
                          "the descriptor's declared authorization state vs the record's"):
            return REFUSED, {"requirement_fired": R["malformed"], "absent_or_bad_path": dloc,
                             "detail": "the descriptor and its record disagree about the physical "
                                       "authorization state: %r vs %r" % (pa_desc, pa_rec)}
        lcm = _int_at(drows, "launch_count_max", dloc, convert=True)
        if lcm < 1:
            raise Dep(R["not_met"], dloc,
                      "launch_count_max = %d; a command bounded to no launch is not a launch"
                      % lcm)
        eo_loc = g.expected_output_locator()
        if not g.led.same(F(dloc, "expected_bin_sha256",
                            g.need(drows, dloc, "expected_bin_sha256", str)),
                          F(eo_loc, "sha256_file(the bytes on disk)", g.raw_sha(eo_loc)),
                          "the descriptor's expected-output digest vs the expected output on "
                          "disk"):
            return REFUSED, {"requirement_fired": R["foreign_subject"], "absent_or_bad_path": dloc,
                             "detail": "the descriptor's expected-output digest is not the digest "
                                       "of the expected output the manifest names"}
        n_args = _int_at(drows, "n_args", dloc, convert=True)
        m_loc = g.manifest_loc()
        names = g.need(g.json(m_loc), m_loc, "argument_names", list)
        if n_args != len(names):
            return REFUSED, {"requirement_fired": R["count_disagreement"], "absent_or_bad_path": dloc,
                             "detail": "the descriptor declares %d arguments, the manifest %d"
                                       % (n_args, len(names))}
        arg_rows = []
        for j, nm in enumerate(names):
            name_key = "arg%d_name" % j
            if name_key in drows:
                if not g.led.same(F(dloc, name_key, drows[name_key]),
                                  F(m_loc, "argument_names[%d]" % j, nm),
                                  "the descriptor's name for argument %d vs the manifest's "
                                  "argument order" % j):
                    return REFUSED, {"requirement_fired": R["count_disagreement"],
                                     "absent_or_bad_path": dloc,
                                     "detail": "argument %d is %r in the manifest and %r in the "
                                               "descriptor: the two do not describe one call"
                                               % (j, nm, drows[name_key])}
                arg_rows.append({"index": j, "name": nm,
                                 "offset": drows.get("arg%d_offset" % j),
                                 "size": drows.get("arg%d_size" % j),
                                 "value_kind": drows.get("arg%d_value_kind" % j)})
        return PASS, {"argv_sha256": got, "argv_len": len(argv), "contract_flagged_by": flag,
                      "contract_named_by_the_command": g.to_locator(from_argv),
                      "descriptor_sha256": dsha, "descriptor_bytes": len(g.raw(dloc)),
                      "descriptor_has_no_self_digest": True,
                      "physical_authorization": pa_desc, "launch_count_max": lcm,
                      "n_arguments": n_args, "arguments": arg_rows,
                      "n_descriptor_digest_declarations_compared": len(rows), "compared": rows,
                      "how": "the command is identified by the canonical digest of its own argv, "
                             "and the file it validates against is read out of the argv by the "
                             "flag the declaration names",
                      "ceiling": "this establishes the COMMAND'S IDENTITY and that the path in "
                                 "it is the declared contract.  It does not establish that the "
                                 "command was run, and the descriptor's declared authorization "
                                 "state is recorded here, not decided."}

    P.append(("validated_command_identity_is_bound",
              "the validated command names this experiment's contract and descriptor",
              p_validated_command_identity_is_bound))

    def p_audit4_launch_relevant_claims_are_dispositioned():
        loc = g.loc("audit_disposition")
        doc = g.json(loc)
        vocab = g.vocabulary(doc, loc, "disposition_vocabulary")
        unresolved_terms = g.terms("audit_disposition", "unresolved_terms")
        for t in unresolved_terms:
            if t not in vocab:
                raise Dep(R["vocabulary"], loc,
                          "the declaration calls %r an unresolved term, and the artefact's own "
                          "disposition_vocabulary does not contain it: the declaration and the "
                          "artefact disagree about what the vocabulary means" % t)
        rows = g.need(doc, loc, "rows", list)
        ids = g.walk(loc, g.pointer("audit_disposition", "ids"))
        if not isinstance(ids, list) or not ids or not all(isinstance(x, str) for x in ids):
            raise Dep(R["no_binding"], loc,
                      "the disposition does not name the launch-relevant claims as a non-empty "
                      "list of ids, so it cannot be shown to cover them")
        unresolved = g.walk(loc, g.pointer("audit_disposition", "unresolved"))
        by_id = {}
        for r in rows:
            if isinstance(r, dict) and isinstance(r.get("claim_id"), str):
                by_id[r["claim_id"]] = r
        if not by_id:
            raise Dep(R["missing_key"], loc, "the disposition carries no claim rows")
        open_rows, rowsout, bad, missing = [], [], [], []
        for cid in ids:
            r = by_id.get(cid)
            if r is None:
                missing.append("%s: no row" % cid)
                continue
            d = r.get("disposition")
            if d is None:
                raise Dep(R["missing_key"], loc, "claim %s carries no disposition" % cid)
            g.in_vocab(doc, loc, "rows/%s/disposition" % cid, d, vocab)
            if d in unresolved_terms:
                open_rows.append("%s (the row's own disposition is %r, which the declaration "
                                 "names as meaning 'no answer yet')" % (cid, d))
                rowsout.append({"claim_id": cid, "disposition": d,
                                "disposition_means_unresolved": True})
                continue
            if cid in (unresolved or []):
                open_rows.append(cid)
                rowsout.append({"claim_id": cid, "disposition": d,
                                "listed_unresolved_by_the_disposition": True})
                continue
            ep, es = r.get("evidence_path"), r.get("evidence_sha256")
            if not isinstance(ep, str) or not isinstance(es, str):
                open_rows.append(cid)
                rowsout.append({"claim_id": cid, "disposition": d, "evidence": "<none declared>"})
                continue
            el = g.to_locator(ep)
            if not os.path.isfile(g.path_of(el)):
                raise Dep(R["not_a_file"], el,
                          "the evidence claim %s is disposed against" % cid)
            eq = g.led.same(F(el, "sha256_file(the bytes on disk)", g.raw_sha(el)),
                            F(loc, "rows/%s/evidence_sha256" % cid, es),
                            "the evidence for claim %s vs its recorded digest" % cid)
            rowsout.append({"claim_id": cid, "disposition": d,
                            "listed_unresolved_by_the_disposition": False,
                            "evidence": el, "evidence_intact": bool(eq)})
            if not eq:
                bad.append("%s: the evidence has changed since the disposition" % cid)
        subj = doc.get("subject")
        if isinstance(subj, str):
            sl = g.to_locator(subj)
            sd = doc.get("subject_sha256_recomputed_this_session")
            if isinstance(sd, str) and os.path.isfile(g.path_of(sl)):
                if not g.led.same(F(sl, "sha256_file(the bytes on disk)", g.raw_sha(sl)),
                                  F(loc, "subject_sha256_recomputed_this_session", sd),
                                  "the audited claims file vs the digest the disposition "
                                  "recorded"):
                    bad.append("the audited claims file has changed since the disposition")
            body = doc.get("raw_audit_body")
            bd = doc.get("raw_audit_body_sha256_recomputed_this_session")
            if isinstance(body, str) and isinstance(bd, str):
                bl = g.to_locator(body)
                if os.path.isfile(g.path_of(bl)):
                    if not g.led.same(F(bl, "sha256_file(the bytes on disk)", g.raw_sha(bl)),
                                      F(loc, "raw_audit_body_sha256_recomputed_this_session", bd),
                                      "the audited body vs the digest the disposition recorded"):
                        bad.append("the audited audit body has changed since the disposition")
        if missing or open_rows or bad:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "%d of %d launch-relevant claim(s) are not resolved with "
                                       "verifiable evidence" % (len(open_rows) + len(missing),
                                                                 len(ids)),
                             "unresolved_launch_relevant_claims": open_rows,
                             "no_row_at_all": missing,
                             "evidence_not_intact": bad,
                             "n_launch_relevant": len(ids),
                             "consequence": "a launch-relevant claim that is still open is a "
                                           "question nobody has answered about the payload this "
                                           "slot would run",
                             "rows": rowsout}
        return PASS, {"n_launch_relevant": len(ids), "n_resolved": len(ids), "rows": rowsout,
                      "disposition_vocabulary": vocab}

    P.append(("audit4_launch_relevant_claims_are_dispositioned",
              "every launch-relevant Audit-4 claim is disposed with intact evidence",
              p_audit4_launch_relevant_claims_are_dispositioned))

    def p_authorization_scope_is_live():
        cloc = g.loc("authorization_commit")
        commit = g.json(cloc)
        gen = g.need(commit, cloc, "generation", int)
        batch_id = g.need(commit, cloc, "batch_id", str)
        files = g.need(commit, cloc, "files", dict)
        gdir = os.path.dirname(cloc)
        bn = "BATCH_%s.json" % batch_id
        if bn not in files:
            raise Dep(R["missing_key"], cloc,
                      "the commit's file map does not name %r (it names %s)"
                      % (bn, ", ".join(sorted(files)[:8])))
        bloc = "%s/gen-%06d/%s" % (gdir, gen, bn)
        batch = g.json(bloc)
        decl = files[bn]
        if isinstance(decl, str):
            if not g.led.same(F(bloc, "sha256_file(the bytes on disk)", g.raw_sha(bloc)),
                              F(cloc, "files/%s" % bn, decl),
                              "the batch file the commit names vs the batch file on disk"):
                return REFUSED, {"requirement_fired": R["digest_disagreement"],
                                 "absent_or_bad_path": bloc,
                                 "detail": "the batch on disk is not the batch the commit "
                                           "recorded; the authorization scope has been edited "
                                           "since the commit"}
        max_starts = g.need(batch, bloc, "max_starts", int)
        consuming = g.need(g.need(batch, bloc, "budget_model", dict), bloc,
                           "a_consuming_event_is", list)
        if not consuming or not all(isinstance(x, str) for x in consuming):
            raise Dep(R["malformed"], bloc,
                      "a_consuming_event_is is not a non-empty list of event names")
        allowed = g.need(batch, bloc, "allowed_experiments", list)
        eid = g.identity("experiment_id").value
        # the commit and the batch it names must be the same authorization: the
        # commit's batch_id and the batch's own authorization_id are two
        # statements, in two artefacts, of which batch this is.
        b_id_key = g.pointer("authorization", "batch_authorization_id")
        b_auth = g.walk(bloc, b_id_key)
        if not g.led.same(F(bloc, b_id_key, b_auth), F(cloc, "batch_id", batch_id),
                          "the batch's own authorization id vs the id the commit names"):
            return REFUSED, {"requirement_fired": R["foreign_subject"],
                             "absent_or_bad_path": bloc,
                             "detail": "the file on disk at the path the commit derives is %r's "
                                       "batch, not %r's: the commit and the batch disagree about "
                                       "which authorization this is"
                                       % (b_auth, batch_id)}
        lrow = g.need(commit, cloc, "ledger", dict)
        lfile = g.need(lrow, cloc, "name", str)
        lledger = "%s/gen-%06d/%s" % (gdir, gen, lfile)
        lsha = g.raw_sha(lledger)
        n_lines = len([l for l in g.raw(lledger).decode("utf-8").splitlines() if l.strip()])
        if lrow.get("sha256_after_recomputed") != lsha:
            return REFUSED, {"requirement_fired": R["digest_disagreement"],
                             "absent_or_bad_path": lledger,
                             "detail": "the ledger on disk is not the ledger the commit closed "
                                       "over: the commit records %s, the file hashes to %s"
                                       % (lrow.get("sha256_after_recomputed"), lsha)}
        if lrow.get("n_lines_after") != n_lines:
            return REFUSED, {"requirement_fired": R["count_disagreement"],
                             "absent_or_bad_path": lledger,
                             "detail": "the commit records %r records after the commit; the "
                                       "ledger on disk has %d" % (lrow.get("n_lines_after"),
                                                                  n_lines)}
        if isinstance(files.get(lfile), str) and files[lfile] != lsha:
            return REFUSED, {"requirement_fired": R["digest_disagreement"],
                             "absent_or_bad_path": lledger,
                             "detail": "the commit's file map and its ledger block disagree about "
                                       "the ledger's digest"}
        # -- the ledger this batch was anchored to ---------------------------
        # The batch says which ledger state it was issued against.  That claim is
        # only checkable against bytes: the ledger it names must be the ledger on
        # disk, at the record count it states.  A batch that names a ledger state
        # nobody can produce is not anchored to anything, and a batch whose anchor
        # no longer matches the ledger it names is evidence that the ledger behind
        # this authorization has been edited.
        a_sha_key = g.pointer("authorization", "ledger_anchor_sha")
        a_n_key = g.pointer("authorization", "ledger_anchor_n_lines")
        anchor_sha = g.walk(bloc, a_sha_key)
        anchor_n = g.walk(bloc, a_n_key)
        attempts_loc = g.loc("physical_attempts")
        attempts_sha = g.raw_sha(attempts_loc)
        attempts_n = len([l for l in g.raw(attempts_loc).decode("utf-8").splitlines()
                          if l.strip()])
        before_sha = lrow.get("sha256_before_recomputed")
        before_n = lrow.get("n_lines_before")
        matched = []
        if anchor_sha == attempts_sha and anchor_n == attempts_n:
            matched.append("%s (%d records, hashed in this run)" % (attempts_loc, attempts_n))
        if anchor_sha == before_sha and anchor_n == before_n:
            matched.append("%s at the commit's own before-state (%r records, not on disk any "
                           "more)" % (lledger, before_n))
        sha_ok = g.led.same(F(bloc, a_sha_key, anchor_sha),
                            F(attempts_loc, "sha256_file(the bytes on disk)", attempts_sha),
                            "the digest of the ledger the batch was anchored to vs the digest of "
                            "the ledger on disk it names")
        n_ok = g.led.same(F(bloc, a_n_key, anchor_n),
                          F(attempts_loc, "the number of non-empty lines on disk", attempts_n),
                          "the record count the batch was anchored to vs the record count on "
                          "disk")
        if not matched:
            raise Dep(R["no_binding"], bloc,
                      "the batch's ledger anchor (%s = %r, %s = %r) matches neither the ledger on "
                      "disk %s (%s, %d records) nor the commit's own recorded before-state "
                      "(%r, %r records), so the ledger state this authorization was anchored to "
                      "cannot be identified"
                      % (a_sha_key, anchor_sha, a_n_key, anchor_n, attempts_loc,
                         attempts_sha, attempts_n, before_sha, before_n))
        if not sha_ok or not n_ok:
            return REFUSED, {"requirement_fired": R["stale"], "absent_or_bad_path": bloc,
                             "detail": "the batch is anchored to a ledger state that no longer "
                                       "matches the ledger it names: %s = %r vs %s, %s = %r vs "
                                       "%d records on disk"
                                       % (a_sha_key, anchor_sha, attempts_sha, a_n_key,
                                          anchor_n, attempts_n),
                             "anchor_matches": matched}
        lrows = g.json(lledger)
        if not isinstance(lrows, list):
            raise Dep(R["wrong_type"], lledger, "the ledger is not a record list")
        starts, seen = 0, set()
        for r in lrows:
            if not isinstance(r, dict) or r.get("batch_id") != batch_id:
                continue
            if r.get("event") not in consuming:
                continue
            key = json.dumps({k: r.get(k) for k in sorted(r.keys())}, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            starts += 1
        remaining = max_starts - starts
        expires = (batch.get("expiry") or {}).get("not_after_utc")
        if expires:
            try:
                exp = dt.datetime.fromisoformat(expires.replace("Z", "+00:00"))
            except ValueError:
                raise Dep(R["malformed"], bloc, "expiry.not_after_utc = %r" % expires)
            now = g.now or dt.datetime.now(dt.timezone.utc)
            if exp < now:
                return REFUSED, {"requirement_fired": R["stale"], "absent_or_bad_path": bloc,
                                 "detail": "the authorization expired at %s; it is now %s"
                                           % (expires, now.isoformat())}
        if eid not in allowed:
            added = [r.get("experiment_id") for r in
                     ((batch.get("allowed_experiments_added_by") or {}).get("added") or [])
                     if isinstance(r, dict)]
            amend = g.optional_loc("allowlist_amendment_draft")
            status = None
            if amend:
                try:
                    status = g.json(amend).get("status")
                except Dep:
                    status = "<unreadable>"
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": bloc,
                             "detail": "experiment %r is not on the committed allow-list of batch "
                                       "%r (generation %d).  The amendment draft names it as its "
                                       "proposed value and its status is %r -- and minting a child "
                                       "and committing a batch are coordinator actions, not a "
                                       "worker's." % (eid, batch_id, gen, status),
                             "allowed_experiments": allowed,
                             "added_by_amendment_so_far": added,
                             "amendment_status": status,
                             "budget_derived_anyway": {
                                 "max_starts": max_starts, "consuming_events_counted": starts,
                                 "remaining": remaining,
                                 "why_recorded_here": "the scope question is refused, but the "
                                     "budget was still DERIVED from the ledger in this run, so a "
                                     "reader can see it is not a stored number"},
                             "ledger": lledger, "ledger_records": n_lines,
                             "ledger_anchor_verifies_against": matched}
        if remaining < 1:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": lledger,
                             "detail": "the batch has no remaining starts: max_starts %d, "
                                       "consuming events %d" % (max_starts, starts)}
        return PASS, {"generation": gen, "batch_id": batch_id, "expires": expires,
                      "max_starts": max_starts, "consuming_events_counted": starts,
                      "remaining": remaining, "consuming_event_names": consuming,
                      "experiment_id": eid,
                      "ledger": lledger, "ledger_sha256": lsha, "ledger_records": n_lines,
                      "ledger_anchor_verifies_against": matched,
                      "ledger_anchor_head_recorded_by_the_batch":
                          g.walk(bloc, g.pointer("authorization", "ledger_head_before")),
                      "how": "the budget is DERIVED here: the batch declares what counts as a "
                             "consuming event and this gate counted those events in the ledger "
                             "itself.  Nothing about the budget is stored in this file.",
                      "ceiling": "the count is (batch_id, consuming event) records in ONE "
                                 "ledger.  An event recorded outside that ledger is not visible "
                                 "here.  The batch's recorded ledger HEAD is reported but not "
                                 "re-derived: the head convention (which bytes it hashes) is "
                                 "documented nowhere in the artefacts this gate reads, and a "
                                 "comparison against a convention this gate guessed would either "
                                 "always fail or have to be faked."}

    P.append(("authorization_scope_is_live",
              "the live authorization covers this experiment and has budget left.  Membership "
              "of the experiment id in the batch's allow-list is a SCOPE condition here (is "
              "this authorization's scope this experiment's scope?) and the SUBJECT of "
              "experiment_is_on_the_committed_allow_list, which also reads the amendment; the "
              "overlap is recorded in TAUTOLOGY_AUDIT_16AX.json rather than left for a reader "
              "to find.  It is not a tautology under this gate's rule: the two sides of the "
              "comparison come from two different artefacts (the manifest's experiment id, the "
              "batch's list), and only one of the two predicates puts it in the ledger",
              p_authorization_scope_is_live))

    def p_experiment_is_on_the_committed_allow_list():
        cloc = g.loc("authorization_commit")
        commit = g.json(cloc)
        gen = g.need(commit, cloc, "generation", int)
        batch_id = g.need(commit, cloc, "batch_id", str)
        bloc = "%s/gen-%06d/BATCH_%s.json" % (os.path.dirname(cloc), gen, batch_id)
        batch = g.json(bloc)
        allowed = g.need(batch, bloc, "allowed_experiments", list)
        eid = g.identity("experiment_id").value
        if eid in allowed:
            return PASS, {"experiment_id": eid, "batch_id": batch_id, "generation": gen,
                          "allow_listed": True}
        amend = g.optional_loc("allowlist_amendment_draft")
        status, proposed = None, None
        if amend:
            d = g.json(amend)
            status = d.get("status")
            a = d.get("the_exact_proposed_amendment")
            proposed = a.get("value") if isinstance(a, dict) else None
            if proposed == eid:
                if not g.led.same(F(amend, "the_exact_proposed_amendment.value", proposed),
                                  F(cloc, "the experiment this gate derived", eid),
                                  "the amendment's proposed value vs the experiment id this "
                                  "gate derived from the manifest"):
                    proposed = None
        if proposed != eid:
            raise Dep(R["not_met"], bloc,
                      "experiment %r is not allow-listed and no amendment on disk proposes it "
                      "(the draft proposes %r)" % (eid, proposed))
        return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": bloc,
                         "detail": "experiment %r is not on the committed allow-list; the "
                                   "amendment that would add it exists with status %r.  A draft "
                                   "amendment is not an amendment, and committing it is a "
                                   "coordinator action." % (eid, status),
                         "batch_id": batch_id, "generation": gen,
                         "allowed_experiments": allowed, "amendment_status": status,
                         "amendment_value": proposed}

    P.append(("experiment_is_on_the_committed_allow_list",
              "the experiment is on the allow-list of the current generation's batch",
              p_experiment_is_on_the_committed_allow_list))

    def p_device_health_policy_is_fresh_and_bound():
        loc = g.loc("device_health_policy")
        doc = g.json(loc)
        g.verify_object_block_present(
            "device_health_policy",
            "a device-health policy stated for another experiment or another object is not "
            "health evidence for this slot")
        rows, bad = [], []
        for kind in ("experiment_id", "code_object_sha256"):
            r, b = g.check_bindings(kind, "the health policy must be about this experiment and "
                                          "this object",
                                    only=("device_health_policy",))
            rows.extend(r)
            bad.extend(b)
        if bad:
            return REFUSED, {"requirement_fired": R["foreign_subject"], "absent_or_bad_path": loc,
                             "detail": "the health policy is about something else"}
        req = g.vocabulary(doc, loc, "required_observations")
        obs = g.need(doc, loc, "observations", dict)
        missing = [k for k in req if k not in obs]
        if missing:
            raise Dep(R["missing_key"], loc,
                      "the policy requires %s and does not report %s"
                      % (", ".join(req), ", ".join(missing)))
        captured = g.need(doc, loc, "captured_utc", str)
        try:
            when = dt.datetime.fromisoformat(captured.replace("Z", "+00:00"))
        except ValueError:
            raise Dep(R["malformed"], loc, "captured_utc = %r" % captured)
        now = g.now or dt.datetime.now(dt.timezone.utc)
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        age_h = (now - when).total_seconds() / 3600.0
        maxage = g.need(doc, loc, "max_age_hours", (int, float))
        if age_h > maxage:
            return REFUSED, {"requirement_fired": R["stale"], "absent_or_bad_path": loc,
                             "detail": "the device-health observations are %.1f hours old; the "
                                       "policy allows %.1f" % (age_h, maxage)}
        notgood = [k for k in req if obs[k] is not True]
        if notgood:
            return REFUSED, {"requirement_fired": R["not_met"], "absent_or_bad_path": loc,
                             "detail": "the policy requires %s and the observations report %s"
                                       % (", ".join(req),
                                          ", ".join("%s=%r" % (k, obs[k]) for k in req)),
                             "compared": rows}
        detail = doc.get("evidence")
        if not isinstance(detail, dict) or not detail:
            raise Dep(R["missing_key"], loc,
                      "the health policy carries no evidence block: a boolean is a claim, not "
                      "an observation")
        for name, rec in sorted(detail.items()):
            if not isinstance(rec, dict) or not isinstance(rec.get("path"), str):
                raise Dep(R["wrong_type"], loc, "evidence[%r] carries no path" % name)
            el = g.to_locator(rec["path"])
            if not os.path.isfile(g.path_of(el)):
                raise Dep(R["not_a_file"], el, "the health evidence file %s" % el)
            if isinstance(rec.get("sha256"), str):
                if not g.led.same(F(el, "sha256_file(the bytes on disk)", g.raw_sha(el)),
                                  F(loc, "evidence/%s/sha256" % name, rec["sha256"]),
                                  "the device-health evidence %s" % name):
                    bad.append("evidence:%s" % name)
        if bad:
            return REFUSED, {"requirement_fired": R["digest_disagreement"],
                             "absent_or_bad_path": loc,
                             "detail": "the health evidence is not intact: %s" % ", ".join(bad),
                             "compared": rows}
        return PASS, {"captured_utc": captured, "age_hours": round(age_h, 3),
                      "max_age_hours": maxage, "required_observations": req,
                      "observations": {k: obs[k] for k in req},
                      "n_evidence_files": len(detail), "compared": rows,
                      "ceiling": "this is a POLICY artefact with evidence attached, not a live "
                                 "device read.  This gate did not touch the device."}

    P.append(("device_health_policy_is_fresh_and_bound",
              "a fresh device-health observation is attached to this slot",
              p_device_health_policy_is_fresh_and_bound))

    # ---- coverage and non-tautology ---------------------------------------
    def p_every_evidence_artifact_binds_to_the_subject():
        s = g.subject()
        d = {e["locator"]: e["why"] for e in s["not_subject_evidence"]}
        must = s.get("must_bind")
        if not isinstance(must, list) or not must or not all(isinstance(x, str) for x in must):
            raise Dep(R["missing_key"], g.subject_file,
                      "the subject declaration names no must_bind set, so no artefact is "
                      "required to bind anything and this coverage check would be vacuous")
        must = set(must)
        rows, problems, covered, absent = [], [], set(), []
        for spec in g.binding_specs():
            if spec["artifact"] not in d:
                covered.add(spec["must_equal"])
        for name in sorted(s["locators"]):
            loc = s["locators"][name]
            if name in d:
                rows.append({"artifact": name, "role": "declared not subject evidence",
                             "why": d[name]})
                continue
            if not os.path.exists(g.path_of(loc)):
                absent.append("%s -> %s" % (name, loc))
                continue
            bound = sorted(set(sp["must_equal"] for sp in g.binding_specs()
                               if sp["artifact"] == name))
            if name in must and not bound:
                problems.append("artefact %r binds nothing to the subject" % name)
            rows.append({"artifact": name, "locator": loc, "binds": bound or None,
                         "role": "subject evidence" if bound else "read for structure"})
        missing = [k for k in MUST_BE_BOUND if k not in covered]
        if missing:
            problems.append("no artefact binds %s" % ", ".join(missing))
        for gap in g.binding_gaps:
            problems.append("%s is declared to state %s at %r and the artefact carries no such "
                            "key" % (gap["artifact"], gap["identity"], gap["pointer"]))
        if absent or problems:
            if absent and not problems:
                raise Dep(R["not_a_file"], ", ".join(a.split(" -> ")[1] for a in absent),
                          "the package declares %d artefact(s) it does not have: %s"
                          % (len(absent), "; ".join(absent)))
            return REFUSED, {"requirement_fired": R["no_binding"],
                             "absent_or_bad_path": g.subject_file,
                             "detail": "the package is not bound to the subject: %s"
                                       % "; ".join(problems + ["absent: " + a for a in absent]),
                             "artifacts": rows}
        return PASS, {"n_declared_artifacts": len(s["locators"]),
                      "n_declared_not_subject_evidence": len(d),
                      "n_binding_gaps": 0,
                      "covered_identity_kinds": sorted(covered), "artifacts": rows,
                      "what_this_establishes": "every artefact this gate reads is either bound "
                                               "to the subject's identity by at least one "
                                               "declaration, or is declared in advance as not "
                                               "being subject evidence, with a reason"}

    P.append(("every_evidence_artifact_binds_to_the_subject",
              "every artefact read here is bound to the subject or declared out of scope",
              p_every_evidence_artifact_binds_to_the_subject))

    def p_no_tautological_comparison():
        t = g.led.tautologies()
        if t:
            return REFUSED, {"requirement_fired": R["malformed"],
                             "absent_or_bad_path": os.path.abspath(__file__),
                             "detail": "%d comparison(s) resolve both sides from one artefact "
                                       "through one pointer; agreement is guaranteed and "
                                       "certifies nothing" % len(t),
                             "tautologies": t}
        dup = g.led.duplicate_lineage()
        dis = g.led.disagreements()
        return PASS, {"n_comparisons": len(g.led.rows), "n_tautological": 0,
                      "n_disagreeing": len(dis),
                      "n_comparisons_whose_two_sides_recur_as_one_pair": len(dup),
                      "recurring_pairs": dup[:8],
                      "how": "two sides sharing (artefact, pointer) are a tautology; the whole "
                             "ledger is then scanned for a pair of sides that recurs in more "
                             "than one comparison, which is one comparison run twice"}

    P.append(("no_tautological_comparison",
              "no comparison in this run resolves both sides from one pointer",
              p_no_tautological_comparison))

    return P


def verdict_of(preds):
    if any(p["status"] == REFUSED for p in preds):
        return V_REFUSED
    if any(p["status"] == BLOCKED for p in preds):
        return V_BLOCKED
    return V_QUALIFIED


def run(evidence_root=ROOT, subject_file=SUBJECT_FILE, now=None, quiet=False):
    g = Gate(evidence_root=evidence_root, subject_file=subject_file, now=now)
    for name, requires, fn in build_predicates(g):
        g.pred(name, requires, fn)
        if not quiet:
            p = g.preds[-1]
            sys.stderr.write("  %-30s %s\n" % (p["status"], p["predicate"]))
    v = verdict_of(g.preds)
    return {
        "schema": "p16ax/slot5-qualification/3",
        "phase": "16AX",
        "worker": "W10",
        "task_id": "T-SLOT5",
        "generated_utc": (now or dt.datetime.now(dt.timezone.utc)).isoformat(),
        "evidence_root": os.path.abspath(evidence_root),
        "subject_declaration": os.path.abspath(subject_file),
        "subject_declaration_sha256": sha256_file(os.path.abspath(subject_file))
        if os.path.isfile(subject_file) else None,
        "gate_source": os.path.abspath(__file__),
        "gate_source_sha256": sha256_file(os.path.abspath(__file__)),
        "verdict": v,
        "n_predicates": len(g.preds),
        "n_pass": sum(1 for p in g.preds if p["status"] == PASS),
        "n_refused": sum(1 for p in g.preds if p["status"] == REFUSED),
        "n_blocked": sum(1 for p in g.preds if p["status"] == BLOCKED),
        "refused_predicates": [p["predicate"] for p in g.preds if p["status"] == REFUSED],
        "blocked_predicates": [p["predicate"] for p in g.preds if p["status"] == BLOCKED],
        "predicates": g.preds,
        "comparisons": g.led.rows,
        "n_comparisons": len(g.led.rows),
        "n_tautological_comparisons": len(g.led.tautologies()),
        "tautological_comparisons": g.led.tautologies(),
        "duplicate_lineage_comparisons": g.led.duplicate_lineage(),
        "identity_comparisons": {
            k: {"computed_once_for": v["n_callers"],
                "asked_by": [v["why"]] + v["why_also"],
                "n_declarations_compared": len(v["rows"]),
                "n_declarations_that_state_it": sum(1 for r in v["rows"]
                                                    if r.get("declares_it")),
                "disagreeing": v["disagree"],
                "declared_but_states_nothing": v["gaps"]}
            for k, v in sorted(g._bcache.items())},
        "binding_gaps": g.binding_gaps,
        "n_binding_gaps": len(g.binding_gaps),
        "host_only": True,
        "gpu_calls": 0,
        "launched": False,
        "what_this_does_NOT_establish": [
            "that the object is correct.  It establishes that the package describes THIS "
            "object and that the package's claims about it were re-measured in one process.",
            "anything about the device: no GPU call was made by this gate, and the "
            "device-health predicate reads a policy artefact, not the hardware",
            "that the mock backend's arithmetic is right: the mock plants the expected "
            "artifact, so it shows the pipeline reaches the observer, not that a kernel "
            "computes anything",
            "that the numerical disposition's analysis is correct: the gate checks which "
            "disposition is of record and that its evidence is intact",
            "that the loop or memory bounds are correct derivations: the gate re-checks the "
            "records' internal consistency and their binding to this object",
            "that any artefact was produced honestly.  This gate binds artefacts to each "
            "other and to the object; it cannot audit the process that wrote them.",
        ],
    }


def main(argv):
    args = {"--evidence-root": ROOT, "--subject": SUBJECT_FILE, "--now": None,
            "--out": DEFAULT_OUT, "--quiet": False}
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--quiet":
            args["--quiet"] = True
        elif a in args:
            if i + 1 >= len(argv):
                sys.stderr.write("%s needs a value\n" % a)
                return 2
            args[a] = argv[i + 1]
            i += 1
        else:
            sys.stderr.write("unknown argument %r\n" % a)
            return 2
        i += 1
    now = None
    if args["--now"]:
        now = dt.datetime.fromisoformat(args["--now"].replace("Z", "+00:00"))
    out = run(evidence_root=args["--evidence-root"], subject_file=args["--subject"],
              now=now, quiet=args["--quiet"])
    with open(args["--out"], "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
        fh.write("\n")
    sys.stdout.write("%s  %d/%d PASS  %d REFUSED  %d BLOCKED  -> %s\n"
                     % (out["verdict"], out["n_pass"], out["n_predicates"],
                        out["n_refused"], out["n_blocked"], args["--out"]))
    for p in out["predicates"]:
        if p["status"] != PASS:
            sys.stdout.write("   %-30s %s\n" % (p["status"], p["predicate"]))
    return 0 if out["verdict"] == V_QUALIFIED else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
