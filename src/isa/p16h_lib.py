#!/usr/bin/env python3
"""Phase 16H shared library — ELF + disassembly + PC-relative site model.

Host-only.  No GPU interaction of any kind.

Everything here works on the frozen artefacts named in
``phase16h_pcrel_fix/evidence_manifest.json``:

  * ORIG  = phase5_exact_fragment/gfx1100_code_object.o        (translation source)
  * CAND  = phase16e_candidate_e/gfx1030_dlssnr_candidate_e.co (Candidate E)

Nothing in this module writes to those paths.
"""
from __future__ import annotations

import hashlib
import os
import re
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
P16H = os.path.join(ROOT, "phase16h_pcrel_fix")
OUT = os.path.join(P16H, "out")

ORIG_O = os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_code_object.o")
ORIG_DIS = os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_disassembly.txt")
CAND_CO = os.path.join(ROOT, "phase16e_candidate_e",
                       "gfx1030_dlssnr_candidate_e.co")
CAND_DIS = os.path.join(ROOT, "phase16e_candidate_e", "disasm",
                        "candidate_e_gfx1030_disasm.txt")
ENT_S = os.path.join(ROOT, "phase14_entry_fixed_module",
                     "gfx1030_dlssnr_bundle_entryfixed.s")
ENT_CO = os.path.join(ROOT, "phase14_entry_fixed_module",
                      "gfx1030_dlssnr_module_entryfixed.co")


# --------------------------------------------------------------------------
# ELF
# --------------------------------------------------------------------------
class ProfileAdjacencyError(Exception):
    """A PC-relative site scan stepped over an instruction the target
    profile did not authorise.  Raised instead of silently accepting the
    site, because "it parsed" is not evidence that it is the same site."""


class Elf:
    """Minimal ELF64 reader: sections + symbols + raw bytes."""

    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        d = self.data
        e_shoff = struct.unpack_from("<Q", d, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", d, 0x3A)[0]
        e_shnum = struct.unpack_from("<H", d, 0x3C)[0]
        e_shstrndx = struct.unpack_from("<H", d, 0x3E)[0]
        self.sections = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            (name, typ, flags, addr, off, size, link, info, align,
             ent) = struct.unpack_from("<IIQQQQIIQQ", d, o)
            self.sections.append(dict(name=name, type=typ, flags=flags,
                                      addr=addr, off=off, size=size,
                                      link=link, info=info, align=align,
                                      ent=ent))
        sh = self.sections[e_shstrndx]

        def nm(x):
            s = d[sh["off"] + x:]
            return s[:s.index(b"\0")].decode()

        for s in self.sections:
            s["sname"] = nm(s["name"])
        self._symbols = None

    # -- sections ------------------------------------------------------
    def section(self, name):
        for s in self.sections:
            if s["sname"] == name:
                return s
        return None

    def secbytes(self, name):
        s = self.section(name)
        return self.data[s["off"]:s["off"] + s["size"]]

    def loadable(self):
        """Sections that occupy module address space (SHF_ALLOC, size>0)."""
        out = []
        for s in self.sections:
            if s["size"] and (s["flags"] & 0x2) and s["addr"]:
                out.append(s)
        return out

    def owner(self, va, skip=()):
        for s in self.loadable():
            if s["sname"] in skip:
                continue
            if s["addr"] <= va < s["addr"] + s["size"]:
                return s
        return None

    def read_va(self, va, n):
        s = self.owner(va)
        if s is None:
            return None
        o = va - s["addr"]
        if o + n > s["size"]:
            return None
        return self.data[s["off"] + o:s["off"] + o + n]

    # -- symbols -------------------------------------------------------
    @property
    def symbols(self):
        if self._symbols is not None:
            return self._symbols
        syms = []
        st = self.section(".symtab")
        if st:
            strtab = self.sections[st["link"]]

            def strt(x):
                s = self.data[strtab["off"] + x:]
                return s[:s.index(b"\0")].decode("utf-8", "replace")

            n = st["size"] // st["ent"] if st["ent"] else 0
            for i in range(n):
                o = st["off"] + i * st["ent"]
                (name, info, other, shndx, value, size) = \
                    struct.unpack_from("<IBBHQQ", self.data, o)
                syms.append(dict(name=strt(name), info=info, other=other,
                                 shndx=shndx, value=value, size=size,
                                 type=info & 0xF, bind=info >> 4,
                                 sec=(self.sections[shndx]["sname"]
                                      if 0 < shndx < len(self.sections)
                                      else None)))
        self._symbols = syms
        return syms

    def funcsyms(self):
        """Function symbols (STT_FUNC) with a real value, ordered by VA."""
        out = [s for s in self.symbols
               if s["type"] == 2 and s["value"] and s["size"]]
        out.sort(key=lambda s: s["value"])
        return out


# --------------------------------------------------------------------------
# disassembly text
# --------------------------------------------------------------------------
_LABEL = re.compile(r"^(?P<addr>[0-9A-Fa-f]{8,16})\s+<(?P<name>.+)>:\s*$")
_INS = re.compile(
    r"^\s*(?P<text>.+?)\s+//\s+(?P<addr>[0-9A-Fa-f]{8,16}):\s+"
    r"(?P<bytes>[0-9A-Fa-f ]+?)\s*$")
_SECT = re.compile(r"^Disassembly of section (?P<name>.+):\s*$")


def parse_disasm(path):
    """Return (order, bodies, sections).

    order    : list of (symbol_name, addr) in file order
    bodies   : {symbol_name: [(addr, text, byte_hex), ...]}
    sections : {section_name: [(addr, text, byte_hex), ...]}
    """
    order, bodies, sections = [], {}, {}
    cur_sym = None
    cur_sec = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            m = _SECT.match(line)
            if m:
                cur_sec = m.group("name")
                sections.setdefault(cur_sec, [])
                cur_sym = None
                continue
            m = _LABEL.match(line)
            if m:
                cur_sym = m.group("name")
                if cur_sym not in bodies:
                    bodies[cur_sym] = []
                    order.append((cur_sym, int(m.group("addr"), 16)))
                continue
            m = _INS.match(line)
            if not m:
                continue
            rec = (int(m.group("addr"), 16), m.group("text").strip(),
                   m.group("bytes").strip())
            if cur_sym is not None:
                bodies[cur_sym].append(rec)
            elif cur_sec is not None:
                sections[cur_sec].append(rec)
    return order, bodies, sections


# --------------------------------------------------------------------------
# PC-relative site model
# --------------------------------------------------------------------------
ADD_RE = re.compile(r"^s_add_u32\s+(s\d+)\s*,\s*(s\d+)\s*,\s*"
                    r"(-?0x[0-9A-Fa-f]+|-?\d+)$")
ADDC_RE = re.compile(r"^s_addc_u32\s+(s\d+)\s*,\s*(s\d+)\s*,\s*"
                     r"(-?0x[0-9A-Fa-f]+|-?\d+)$")
GETPC_RE = re.compile(r"^s_getpc_b64\s+(s\[\d+:\d+\]|s\d+)$")


def s64(v):
    v &= (1 << 64) - 1
    return v - (1 << 64) if v >= (1 << 63) else v


def find_sites(insns, profile=None):
    """Find every `s_getpc_b64` + (s_add_u32 / s_addc_u32) triple.

    Returns a list of dicts.  A site is only accepted when the add/addc
    pair writes the same register pair the getpc produced (the canonical
    PC-relative address formation).

    ADJACENCY IS AN ARCHITECTURE FACT (Phase 16K K15/K16)
    ----------------------------------------------------
    How far apart an `s_getpc_b64` and its `s_add_u32` may be, and what may
    sit between them, is not a parsing detail -- it is a property of the
    compiler that emitted the listing, so it belongs to a TargetProfile.

    MEASURED, in this repository (do not overstate this):

      * candidate F's gfx1030 .s: 82 sites, intervening gap = 0 for all 82;
      * the gfx1100 original disassembly: 82 sites, intervening gap = 0 for
        all 82 as well, and the instruction immediately after every
        `s_getpc_b64` is `s_add_u32`.

    So on the data this project actually has, the tolerance NEVER FIRES.
    That is the finding: it is a dead, unlabelled allowance sitting inside
    the scan that decides whether a PC-relative fix is applied.  The
    original module does contain 9 845 `s_delay_alu` and 1 102 `s_nop`,
    just never at one of these 82 sites -- so whether a filler can appear
    there is untested, which is precisely why the allowance should be
    declared and bounded instead of being "any two instructions".

    `profile` is a `TargetProfile` (phase16k_pretest/k15_target_profile/).
    When supplied, an intervening mnemonic is accepted only if the profile
    lists it in `pcrel_filler_mnemonics`, and a violation RAISES.

    `profile=None` keeps the pre-16K behaviour verbatim: skip up to two
    intervening instructions of any kind, unchecked.  That path exists only
    so the frozen/cache-keyed consumers of this module keep working
    unchanged; it is a compatibility mode, not a default architecture.
    """
    out = []
    for i, (a, t, b) in enumerate(insns):
        m = GETPC_RE.match(t)
        if not m:
            continue
        dst = m.group(1)
        lo = hi = None
        lo_txt = hi_txt = None
        lo_pc = hi_pc = None
        skipped = []
        for k in range(i + 1, min(i + 4, len(insns))):
            ak, tk, bk = insns[k]
            m2 = ADD_RE.match(tk)
            m3 = ADDC_RE.match(tk)
            if m2 and lo is None:
                lo, lo_txt, lo_pc = int(m2.group(3), 0), tk, ak
                continue
            if m3 and lo is not None and hi is None:
                hi, hi_txt, hi_pc = int(m3.group(3), 0), tk, ak
                break
            if lo is None:
                skipped.append(tk)
        if profile is not None:
            for tk in skipped:
                mn = tk.strip().split(None, 1)[0] if tk.strip() else ""
                if not mn:
                    continue
                if not profile.may_skip_in_pcrel_scan(mn):
                    raise ProfileAdjacencyError(
                        "0x%X: %r sits between s_getpc_b64 and its "
                        "s_add_u32, but profile %s does not list it as a "
                        "permitted filler (%s)"
                        % (a, mn, profile.name,
                           ", ".join(profile.pcrel_filler_mnemonics)))
        if lo is None or hi is None:
            out.append(dict(pc=a, text=t, dst=dst, lo=None, hi=None,
                            delta=None, pc_next=a + 4, target=None,
                            complete=False, lo_text=None, hi_text=None,
                            lo_pc=None, hi_pc=None, index=i))
            continue
        lom = lo & 0xFFFFFFFF
        him = hi & 0xFFFFFFFF
        delta = s64((him << 32) | lom)
        out.append(dict(pc=a, text=t, dst=dst, lo="0x%08X" % lom,
                        hi="0x%08X" % him, lo_text=lo_txt, hi_text=hi_txt,
                        lo_pc=lo_pc, hi_pc=hi_pc, delta=delta, pc_next=a + 4,
                        target=(a + 4 + delta) & 0xFFFFFFFFFFFFFFFF,
                        complete=True, index=i))
    return out


# --------------------------------------------------------------------------
# misc
# --------------------------------------------------------------------------
def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_out():
    os.makedirs(OUT, exist_ok=True)
    return OUT


# --------------------------------------------------------------------------
# SGPR use/def census (lightweight, label-free)
# --------------------------------------------------------------------------
SGPR_TOK = re.compile(r"\bs\[(\d+):(\d+)\]|\bs(\d+)\b")
VOPC_SDST = re.compile(r"^v_cmp\w*_(e64|s)\b")


def sgpr_written(text):
    """Best-effort: which sgprs does this instruction WRITE (textually)?"""
    t = text.strip()
    mn = t.split(None, 1)[0]
    ops = t.split(None, 1)[1] if " " in t else ""
    first = ops.split(",")[0].strip() if ops else ""
    out = set()

    def expand(tok):
        m = re.match(r"^s\[(\d+):(\d+)\]$", tok)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            return set(range(min(a, b), max(a, b) + 1))
        m = re.match(r"^s(\d+)$", tok)
        return {int(m.group(1))} if m else set()

    # memory loads: dst is operand 0
    if re.match(r"^s_(load|buffer_load|scratch_load|atomic|dmb)", mn):
        return expand(first)
    if re.match(r"^s_(cbranch|branch|setpc|swappc|endpgm|barrier|waitcnt|"
                r"sleep|nop|sethalt|trap|dcache|icache|dmb|wait_idle|"
                r"setkill|set_gpr_idx|rfe|sendmsg|ttracedata|atc|memtime|"
                r"memrealtime|clause|code_end|inst_prefetch|delay_alu|"
                r"wait_idle|sleep_var)", mn):
        return set()
    if mn.startswith("v_"):
        # only VOP3/VOPC forms with an explicit sdst write an sgpr
        if VOPC_SDST.match(mn):
            parts = [p.strip() for p in ops.split(",")]
            if parts and re.match(r"^s(\d+)$", parts[-1]):
                return expand(parts[-1])
        return set()
    return expand(first)


def sgpr_read(text):
    """Every sgpr token that appears in a READ position (best effort)."""
    t = text.strip()
    mn = t.split(None, 1)[0]
    ops = t.split(None, 1)[1] if " " in t else ""
    toks = [p.strip() for p in ops.split(",")]
    reads = set()
    wr = sgpr_written(text)
    # scalar memory: operand0 is dst, rest are base/offset
    for i, tok in enumerate(toks):
        for m in SGPR_TOK.finditer(tok):
            if m.group(1) is not None:
                a, b = int(m.group(1)), int(m.group(2))
                s = set(range(min(a, b), max(a, b) + 1))
            else:
                s = {int(m.group(3))}
            reads |= s
    return reads - wr if not mn.startswith(("s_load", "s_buffer_load",
                                            "s_scratch_load")) else reads - wr
