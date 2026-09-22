#!/usr/bin/env python3
"""Phase 16J-J0.2 -- the gfx1030 scratch (private-segment) address model.

THE DEFECT THIS REPLACES

`p16i_scratch_close.ScrtCloseCore._scratch_xfer` derived the store address
from operand token 0 and reported `UNMEASURED -- no vaddr vreg token` for
every store, because the module's stores print their vaddr slot as `off`:

    scratch_store_dwordx4 off, v[1:4], off
    scratch_store_dword   off, v5,    off offset:16

The gate therefore failed closed on 16 of 144 dispatches for `<32,false>`
and 768 of 1280 for `<128,false>`.  The *executor* (p16e_rec.E16Core, frozen)
had already read `off` as "no vaddr register -> base 0", which turns out to
be right; only the validator could not see it.

THE OPERAND GRAMMAR, ESTABLISHED FROM THE ISA + TOOLCHAIN, NOT GUESSED

objdump orders a scratch store as `vaddr, vdata, saddr` and a scratch load
as `vdst, vaddr, saddr`, with a trailing `offset:<imm>` on the last operand.

The `off` token is NOT "no address": it is the offen-0 form, in which VADDR
contributes nothing and the access lands at `offset` alone.  Both halves of
that were settled by round-tripping the actual module bytes through the
independently installed ROCm 7.1 `llvm-mc -mcpu=gfx1030`, which reproduces
the module's own encoding words exactly:

    scratch_store_dword off, v5, off offset:16
        -> [0x10,0x40,0x70,0xdc, 0x00,0x05,0x7f,0x00]   == module word1 0x007F0500
    scratch_store_dword v0,  v5, off offset:16
        -> [0x10,0x40,0x70,0xdc, 0x00,0x05,0x7d,0x00]
    scratch_load_dword  v1, v0, off offset:4
        -> [0x04,0x40,0x30,0xdc, 0x00,0x00,0x7d,0x01]
    scratch_load_dword  v1, off, off offset:4
        -> [0x04,0x40,0x30,0xdc, 0x00,0x00,0x7f,0x01]

So `off` and `v0` are *different encodings* (word1 byte 6 is 0x7F vs 0x7D),
and the disassembler distinguishes them.  `verify_disasm_encoding()` checks
that on every scratch instruction in the module, so this model is anchored
to the bytes rather than to a re-parse of a printer's text.

The width is the mnemonic's, not the destination register count: a
`scratch_load_ubyte` moves one byte.  The previous model used
`(hi-lo+1)*4` and therefore called a ubyte load 4 bytes wide.

Host-only.  No GPU.  Nothing frozen is modified.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
for p in ("phase16i_closure/tools", "phase16h_pcrel_fix/tools",
          "phase16e_candidate_e/tools", "phase14e_static/tools",
          "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
          "phase14d11_static", "phase14d_static/tools", "phase8_static/tools",
          "phase14d8_static/tools"):
    pp = os.path.join(ROOT, p)
    if pp not in sys.path:
        sys.path.insert(0, pp)

import p16h_lib as L                      # noqa: E402
import p16h_global_gate as G              # noqa: E402
import p16h_scratch_probe as SP           # noqa: E402
import p16i_scratch_close as SC           # noqa: E402
import p16i_authentic_harness as AH       # noqa: E402

RE_VREG = SC.RE_VREG
RE_OFF = SC.RE_OFF

# ISA transfer width per mnemonic suffix (bytes).
WIDTH = {"ubyte": 1, "sbyte": 1, "ushort": 2, "sshort": 2,
         "dword": 4, "dwordx2": 8, "dwordx3": 12, "dwordx4": 16}

# word1 byte 6 is the MUBUF SRSRC slot; for scratch it is a sentinel, and
# the two sentinels encode the two vaddr forms.
SRSRC_OFFEN = 0x7D       # a real VADDR register is encoded
SRSRC_NOOFFEN = 0x7F     # `off`: VADDR contributes nothing


def _vreg(tok):
    """Return (lo, hi) of a `vN` / `v[a:b]` token, or None."""
    m = RE_VREG.search(tok or "")
    if not m:
        return None
    if m.group(1) is not None:
        return int(m.group(1)), int(m.group(2))
    return int(m.group(3)), int(m.group(3))


def parse_scratch(mnem, operands):
    """Resolve one gfx1030 scratch instruction's access.

    Returns dict(store, nbytes, imm, vaddr_reg, offen, vdst, vdata, why).
    `why` non-None means the form could not be resolved (fatal for a gate).
    """
    out = {"store": None, "nbytes": None, "imm": 0, "vaddr_reg": None,
           "offen": None, "vdst": None, "vdata": None, "why": None,
           "mnem": mnem}
    if not mnem.startswith("scratch_"):
        out["why"] = "not a scratch mnemonic"
        return out
    suffix = mnem.split("_")[-1]
    if suffix not in WIDTH:
        out["why"] = "unknown scratch width suffix %r" % suffix
        return out
    out["nbytes"] = WIDTH[suffix]
    out["store"] = "store" in mnem
    toks = [t.strip() for t in (operands or "").split(",")]
    if len(toks) < 3:
        out["why"] = "scratch needs 3 operands, got %d" % len(toks)
        return out
    m = RE_OFF.search(operands or "")
    out["imm"] = int(m.group(1)) if m else 0

    if out["store"]:
        vt, dt = toks[0], toks[1]          # vaddr, vdata
        out["vdata"] = _vreg(dt)
        if out["vdata"] is None:
            out["why"] = "store: no data vreg (operand 1 = %r)" % dt
            return out
    else:
        vt, dt = toks[1], toks[0]          # vaddr, vdst
        out["vdst"] = _vreg(dt)
        if out["vdst"] is None:
            out["why"] = "load: no destination vreg (operand 0 = %r)" % dt
            return out

    if vt == "off":
        # offen-0: VADDR contributes nothing; the access is `offset` alone.
        out["offen"] = False
        out["vaddr_reg"] = None
        return out
    v = _vreg(vt)
    if v is None:
        out["why"] = "vaddr operand %r is neither a vreg nor `off`" % vt
        return out
    if v[0] != v[1]:
        out["why"] = "vaddr operand %r is a register range" % vt
        return out
    out["offen"] = True
    out["vaddr_reg"] = v[0]
    return out


# ---------------------------------------------------------------------------
# disassembler-fidelity check: `off` <-> SRSRC sentinel, on the real bytes
# ---------------------------------------------------------------------------
LINE_RE = re.compile(r"^\s*(scratch_[a-z0-9_]+)\s+(.*?)\s*//\s*([0-9A-Fa-f]+):"
                     r"\s*([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})\s*$")


def verify_disasm_encoding(dis_path):
    """Every scratch line must agree with its own encoding word."""
    rows = []
    bad = []
    with open(dis_path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            m = LINE_RE.match(ln.rstrip("\n"))
            if not m:
                continue
            mnem, ops_txt, pc, w0, w1 = m.groups()
            ops = ops_txt.split("//")[0].strip()
            # strip the trailing `offset:N` from the operand text for parsing
            bare = re.sub(r"\s*offset:-?\d+\s*$", "", ops)
            p = parse_scratch(mnem, bare)
            srsrc = (int(w1, 16) >> 16) & 0xFF
            want = SRSRC_OFFEN if p["offen"] else SRSRC_NOOFFEN
            rec = {"pc": "0x" + pc.upper(), "mnem": mnem, "ops": bare,
                   "offen": p["offen"], "vaddr_reg": p["vaddr_reg"],
                   "srsrc": "0x%02X" % srsrc, "expected_srsrc": "0x%02X" % want,
                   "nbytes": p["nbytes"], "imm": p["imm"], "why": p["why"]}
            rows.append(rec)
            if p["why"] or srsrc != want:
                bad.append(rec)
    return rows, bad


# ---------------------------------------------------------------------------
# gate core
# ---------------------------------------------------------------------------
class ScrtISACore(SP.ScrtGateCore):
    """ScrtGateCore with the ISA scratch grammar and a fail-closed verdict."""

    scrt_close = None                          # the ScrtCloseGate instance
    wave_index = 0

    def _scratch_xfer(self, ins, store, nbytes=None):
        g = ScrtISACore.scrt_close
        if g is not None:
            mnem = ins.get("mnemonic") or ""
            site = ins.get("address")
            live = [ln for ln in range(self.lanes)
                    if (self.exec_l >> ln) & 1]
            g.dispatch(store, site, mnem, live)
            p = parse_scratch(mnem, ins.get("operands") or "")
            if p["why"]:
                if live:
                    g.unmeasured_dispatch(store, site, mnem, live, p["why"])
            else:
                g.n_measured += 1
                for lane in live:
                    base = (self.v[lane][p["vaddr_reg"]] & 0xFFFFFFFF
                            if p["offen"] else 0)
                    g.note(store, lane, (base + p["imm"]) & 0xFFFFFFFF,
                           p["nbytes"], site, mnem)
        # PRE-16N reconstruction: the width was never threaded down, so
        # ScrtGateCore re-derived it from the destination span.
        super()._scratch_xfer(ins, store, None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tags", default="swin32f,swin32t,swin64f,swin128f,"
                                      "swin256f")
    ap.add_argument("--csv", default=os.path.join(
        ROOT, "phase16_authentic_decode_swin.csv"))
    ap.add_argument("--waves", type=int, default=8)
    ap.add_argument("--region-mib", type=int, default=64)
    ap.add_argument("--round-cap", type=int, default=2000000)
    ap.add_argument("--static-only", action="store_true")
    ap.add_argument("--json", default=os.path.join(
        ROOT, "phase16j_pre_gta/out/p16j_scratch_close.json"))
    a = ap.parse_args()

    co = os.path.join(ROOT, "phase16h_candidate_f/gfx1030_dlssnr_candidate_f.co")
    dis = os.path.join(
        ROOT, "phase16h_candidate_f/disasm/candidate_f_gfx1030_disasm.txt")
    elf = L.Elf(co)

    print("=" * 78)
    print("J0.2 -- scratch ISA model (fail-closed), Candidate F")
    print("=" * 78)

    # ---- fidelity: the text model must agree with the encoded bytes ------
    rows, bad = verify_disasm_encoding(dis)
    print("disassembler fidelity: %d scratch lines, %d disagree with their "
          "own encoding" % (len(rows), len(bad)))
    for r in bad[:10]:
        print("   BAD %s %s %s" % (r["pc"], r["mnem"], r["ops"]))
    mnems = sorted({r["mnem"] for r in rows})
    print("  mnemonics: %s" % ", ".join(mnems))
    offen_forms = [r for r in rows if r["offen"]]
    print("  %d with a VADDR register, %d with the offen-0 `off` form"
          % (len(offen_forms), len(rows) - len(offen_forms)))

    import p16i_isa as ISA
    core = ISA.p16i_isa_core(ScrtISACore)
    SP.ScrtGateCore.scrt_gate = None      # parent's gate must stay unarmed

    out = {"disasm_fidelity": {"n_lines": len(rows), "n_bad": len(bad),
                               "bad": bad[:20],
                               "mnemonics": mnems,
                               "n_offen": len(offen_forms),
                               "n_nooffen": len(rows) - len(offen_forms)},
           "static": {}, "static_bad": {}, "dynamic": {}}

    # ---- static ----------------------------------------------------------
    for tag, sym in sorted(AH.SYM.items()):
        prog, _r, _i = G.PE.slice_program(dis, sym)
        out["static"][sym] = SC.static_census(prog, core)
    badk = {s: {m: v for m, v in d.items() if v["status"] != "OK"}
            for s, d in out["static"].items()}
    out["static_bad"] = {s: v for s, v in badk.items() if v}
    print("STATIC: %d kernels, %d with a non-OK scratch mnemonic"
          % (len(out["static"]), len(out["static_bad"])))
    for s, v in out["static_bad"].items():
        print("   %-50s %s" % (s[:50], v))

    # ---- dynamic ---------------------------------------------------------
    if not a.static_only:
        for tag in [t.strip() for t in a.tags.split(",") if t.strip()]:
            sym = AH.SYM[tag]
            psz = SP.private_segment_size(co, sym + ".kd")
            g = SC.ScrtCloseGate(psz)
            ScrtISACore.scrt_close = g
            try:
                AH.run(tag, a.csv, None, None, a.waves, a.region_mib,
                       a.round_cap, os.path.join(
                           ROOT, "phase16j_pre_gta/out/"
                                 "p16j_scratch_run_%s.json" % tag),
                       core_cls=core)
                s = g.summary()
                out["dynamic"][tag] = s
                print("DYNAMIC %-9s psz=%-4s dispatch=%-6s measured=%-6s "
                      "unmeasured=%-3s oob=%-3s writes=%-5s %s"
                      % (tag, psz, s["n_scratch_dispatch"],
                         s["n_scratch_measured"], s["n_unmeasured"],
                         s["oob_scratch_accesses"], s["n_scratch_writes"],
                         s["gate"]))
                for u in s["unmeasured"][:6]:
                    print("      UNMEASURED %s" % u)
                for o in s["oob_samples"][:6]:
                    print("      OOB %s" % o)
            except Exception as e:                  # noqa: BLE001
                out["dynamic"][tag] = {"error": "%s: %s"
                                       % (type(e).__name__, e)}
                print("DYNAMIC %-9s ERROR %s: %s"
                      % (tag, type(e).__name__, e))
            finally:
                ScrtISACore.scrt_close = None

    os.makedirs(os.path.dirname(a.json), exist_ok=True)
    json.dump(out, open(a.json, "w", encoding="utf-8"), indent=1)
    print("wrote " + a.json)

    gate_ok = (not bad) and (not out["static_bad"]) and all(
        (v.get("gate") == "PASS") for v in out["dynamic"].values())
    print("GATES: fidelity=%s static=%s dynamic=%s"
          % ("PASS" if not bad else "FAIL",
             "PASS" if not out["static_bad"] else "FAIL",
             "PASS" if gate_ok else "FAIL"))
    return 0 if gate_ok else 1


if __name__ == "__main__":
    sys.exit(main())
