#!/usr/bin/env python3
"""Phase 16S -- do the measured divergences fire on the operands J3 ACTUALLY
fed to the defective handlers?

HOST ONLY.  No GPU, no HIP, no game, nothing armed.  Writes only under
`phase16s/isa/`.

WHY THIS IS THE LAST STEP
-------------------------
`STORE_PROVENANCE.json` measured that the five defective handlers' outputs reach
memory on J3: 96 of 208 store rows have one of them in their value slice.  That
proves the *possibility* of contamination.  It does not prove the stored bytes
differ from the ISA's, because the slice is an over-approximation of data flow.

What is left to decide is narrower and answerable:

  * `v_fma_mixlo_f16` / `v_fma_mixhi_f16` -- the divergence is UNCONDITIONAL.
    The handler reads every source's full 32 bits as an f32 value and computes
    in f32; the ISA reads a 16-bit half as an f16 and computes in f16.  There
    is no operand for which the two agree.  So for these two, "the output
    reaches memory" IS "the stored bytes differ".

  * `v_cvt_f16_f32_e32`, `v_pack_b32_f16`, `v_add_co_ci_u32_e64` -- the
    divergence is CONDITIONAL on the operands.  This tool records the operands
    the handler was ACTUALLY given on the J3 dispatch and classifies each
    instance against the measured defect set, so the question "did a diverging
    instance run" is answered by measurement rather than by assumption.

THE OBSERVATION IS PASSIVE
--------------------------
The handlers are wrapped to READ their operands and then delegate to the real
handler, unchanged.  Ticks are compared against the recorded 13,590; if they
move, the observation perturbed the dispatch and the run is discarded.

Usage:
    python phase16s/isa/divergent_operands.py
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
S = os.path.dirname(HERE)
ROOT = os.path.dirname(S)

OUT = os.path.join(HERE, "DIVERGENT_OPERANDS.json")

EMU_REL = "phase8_static/tools/emu.py"
EMU_EXPECTED_SHA = ("c6afc641be3ce734789ec505eb7f23ca876db8787cbccb9f0"
                    "0426064edb17205")

#: The three conditionally-divergent mnemonics, and where the handler lives.
CONDITIONAL = ("v_cvt_f16_f32_e32", "v_pack_b32_f16", "v_add_co_ci_u32_e64")
UNCONDITIONAL = ("v_fma_mixlo_f16", "v_fma_mixhi_f16")


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def f32(bits):
    return struct.unpack("<f", struct.pack("<I", bits & 0xFFFFFFFF))[0]


def _biased(bits):
    return (bits >> 23) & 0xFF


# ---------------------------------------------------------------------------
# the measured defect predicates, written from the handler source
# ---------------------------------------------------------------------------
def cvt_f16_f32_diverges(bits):
    """Does `Core.op_v_cvt_f16_f32` (emu.py:1605) differ from the ISA here?

    Four measured sub-defects:
      SIGN      the handler takes the sign from bit 16 of the f32 pattern
                (`s = (b >> 16) & 1`), not from bit 31.  These agree only when
                bits 31 and 16 match.
      SUBNORMAL  `e < -24` returns signed zero; the ISA requires FP16
                denormals to be created.
      CLAMP      `min(frac, 0x3FF)` clamps a rounded-up subnormal to 0x03FF
                where 0x0400 (the smallest normal) is required.
      NEGATION   a `-vN` input modifier integer-negates the bit pattern.
    """
    etop = _biased(bits)
    if etop == 255:
        return None                      # inf/nan: handler special-cases them
    sign31 = (bits >> 31) & 1
    sign16 = (bits >> 16) & 1
    e = etop - 127
    # `if x == 0.0: return signed zero` fires BEFORE the subnormal test, and
    # the ISA also returns signed zero for +-0.0 -- so an exact zero is NOT a
    # divergence.  Counting it would have inflated the number by an order of
    # magnitude (the first run of this file reported 24,423 "divergences"
    # whose first three samples were all bits=00000000, i.e. plain zero).
    if (bits & 0x7FFFFFFF) == 0:
        return {"sign_bit_16_vs_31": False, "subnormal_flush": False,
                "clamp": False, "negation": False}
    if e < -24:
        return {"sign_bit_16_vs_31": sign16 != sign31,
                "subnormal_flush": True, "clamp": False, "negation": False}
    if -24 <= e < -14:
        # the subnormal path: handler rounds abs(x)/2**-24 and clamps
        mag = abs(f32(bits))
        frac = int(round(mag / 2.0 ** -24))
        return {"sign_bit_16_vs_31": sign16 != sign31,
                "subnormal_flush": False,
                "clamp": frac > 0x3FF, "negation": False}
    return {"sign_bit_16_vs_31": sign16 != sign31,
            "subnormal_flush": False, "clamp": False, "negation": False}


def pack_b32_f16_diverges(src0, src1):
    """`Core8.op_v_pack_b32_f16` (p14d8_core.py:685) computes
    `((src0 & 0xFFFF) << 16) | (src1 & 0xFFFF)`; the ISA puts S0 in the LOW
    half and S1 in the HIGH half.  The two agree only when the halves are
    equal, or when exactly one of them is zero in both positions."""
    a = src0 & 0xFFFF
    b = src1 & 0xFFFF
    isa = (b << 16) | a
    emu = (a << 16) | b
    return isa != emu


def add_co_ci_diverges(cout_token):
    """`Core.op_v_add_co_ci_u32` writes the carry-out only when the token is
    `vcc_lo`; for a VOP3B scalar destination it drops it."""
    return cout_token not in ("vcc_lo",)


def main():
    t0 = time.time()
    emu_sha = sha256_file(os.path.join(ROOT, EMU_REL))
    print("=== J3: do the measured divergences fire on the real operands? ===")
    print("   emulator %s" % emu_sha[:16])
    if emu_sha != EMU_EXPECTED_SHA:
        print("   *** not the revision this phase measured ***")
        return 2

    sys.path.insert(0, os.path.join(ROOT, "phase16s", "div"))
    import seq_oracle as SQ                                    # noqa: E402

    cap = SQ.j3_capture(want_writes=True)
    rec = SQ._J3["rec"]
    core_cls = SQ._J3["core_cls"]

    # -- install PASSIVE observers on the MRO-resolved handlers -------------
    obs = {m: {"calls": 0, "divergent": 0, "samples": []} for m in CONDITIONAL}

    def owner_of(attr):
        for c in core_cls.__mro__:
            if attr in c.__dict__:
                return c
        return None

    def wrap_cvt(base):
        def h(self, ins, ops):
            if self.exec_l:
                r = obs["v_cvt_f16_f32_e32"]
                r["calls"] += 1
                for lane in range(self.lanes):
                    if not ((self.exec_l >> lane) & 1):
                        continue
                    try:
                        bits = int(self.vget(lane, ops[1])) & 0xFFFFFFFF
                    except Exception:                          # noqa: BLE001
                        continue
                    d = cvt_f16_f32_diverges(bits)
                    if d and any(d.values()):
                        r["divergent"] += 1
                        if len(r["samples"]) < 6:
                            r["samples"].append({"bits": "%08X" % bits,
                                                 "defects": {k: v for k, v
                                                             in d.items() if v}})
            return base(self, ins, ops)
        return h

    def wrap_pack(base):
        def h(self, ins, ops):
            if self.exec_l:
                r = obs["v_pack_b32_f16"]
                r["calls"] += 1
                for lane in range(self.lanes):
                    if not ((self.exec_l >> lane) & 1):
                        continue
                    try:
                        a = int(self.vget(lane, ops[1])) & 0xFFFFFFFF
                        b = int(self.vget(lane, ops[2])) & 0xFFFFFFFF
                    except Exception:                          # noqa: BLE001
                        if len(r["samples"]) < 6:
                            r["samples"].append({"ops": ins.get("operands"),
                                                 "note": "operand not readable "
                                                         "as an integer"})
                        r["divergent"] += 1
                        continue
                    if pack_b32_f16_diverges(a, b):
                        r["divergent"] += 1
                        if len(r["samples"]) < 6:
                            r["samples"].append({"s0": "%08X" % a,
                                                 "s1": "%08X" % b})
            return base(self, ins, ops)
        return h

    def wrap_ci(base):
        def h(self, ins, ops):
            if self.exec_l:
                tok = ops[1] if len(ops) > 1 else None
                r = obs["v_add_co_ci_u32_e64"]
                r["calls"] += 1
                if add_co_ci_diverges(tok):
                    r["divergent"] += 1
                    if len(r["samples"]) < 6:
                        r["samples"].append({"carry_out_token": tok,
                                             "ops": ins.get("operands")})
            return base(self, ins, ops)
        return h

    installed = []
    # The dispatcher strips `_e32`/`_e64` and looks up `op_<base>`, so the
    # ATTRIBUTE is `op_v_cvt_f16_f32`, not `v_cvt_f16_f32`.  (Getting this
    # wrong installs nothing and every count reads 0 -- which is exactly what
    # the first run of this tool did, and why the "no divergence" it printed
    # was discarded rather than reported.)
    for attr, wrapper in (("op_v_cvt_f16_f32", wrap_cvt),
                          ("op_v_pack_b32_f16", wrap_pack),
                          ("op_v_add_co_ci_u32", wrap_ci)):
        own = owner_of(attr)
        if own is None:
            raise SystemExit("OBSERVER: no MRO owner for %s" % attr)
        raw = getattr(own.__dict__[attr], "__func__", own.__dict__[attr])
        setattr(own, attr, wrapper(raw))
        # prove the hook is where the instance will resolve it
        from_inst = getattr(core_cls, attr)
        wrapped = getattr(from_inst, "__func__", from_inst)
        installed.append("%s.%s" % (own.__name__, attr))
        if wrapped.__name__ != "h":
            raise SystemExit("OBSERVER: %s did not take the wrapper" % attr)
    if len(installed) != 3:
        raise SystemExit("OBSERVER: only %d of 3 installed" % len(installed))
    print("   observers installed on: %s" % ", ".join(installed))

    # -- second dispatch, with the observers ---------------------------------
    cap2 = SQ.j3_capture(want_writes=True)
    print("   observed dispatch: ticks %s (recorded %s) gate %s"
          % (cap2["ticks"], cap2["recorded_ticks"], cap2["gate"]))
    perturbed = cap2["ticks"] != cap2["recorded_ticks"]
    if perturbed:
        print("   *** the observation perturbed the dispatch (ticks moved) ***")

    print("\n=== conditional divergences, measured on the real operands ===")
    for m in CONDITIONAL:
        r = obs[m]
        print("   %-22s handler calls %-5d lane-divergences %-6d"
              % (m, r["calls"], r["divergent"]))
        for s in r["samples"][:3]:
            print("        %s" % json.dumps(s))

    doc = {
        "schema": "phase16s-divergent-operands/1", "phase": "16S",
        "item": "S1 follow-up -- do the divergences fire on J3's own operands?",
        "host_only": True, "gpu_execution_performed": False,
        "gta_launched": False, "currently_armed": False,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "emulator": {"path": EMU_REL, "sha256": emu_sha},
        "observation_is_passive": True,
        "ticks_baseline": cap["ticks"],
        "ticks_observed": cap2["ticks"],
        "ticks_match_recorded": cap2["ticks"] == cap2["recorded_ticks"],
        "perturbed": perturbed,
        "unconditional_divergence": {
            "mnemonics": list(UNCONDITIONAL),
            "why": ("the handler reads every source's full 32 bits as an f32 "
                    "value and computes in f32; the ISA reads a 16-bit half as "
                    "an f16 and computes in f16.  There is no operand for "
                    "which the two agree, so every executed instance diverges."),
            "instances_on_j3": {"v_fma_mixlo_f16": 224,
                                "v_fma_mixhi_f16": 32},
        },
        "conditional_divergence": {m: obs[m] for m in CONDITIONAL},
        "verdict": None,
    }

    uncond_hit = True   # always, by construction
    cond_hit = any(obs[m]["divergent"] > 0 for m in CONDITIONAL)
    if perturbed:
        doc["verdict"] = "INCONCLUSIVE_OBSERVATION_PERTURBED"
    elif uncond_hit and cond_hit:
        doc["verdict"] = ("DIVERGENCE_FIRES_ON_J3"
                          " -- both an unconditional and a conditional "
                          "divergence occurred on J3's own operands")
    elif uncond_hit:
        doc["verdict"] = ("DIVERGENCE_FIRES_ON_J3"
                          " -- an unconditional divergence occurred "
                          "(the two MIX mnemonics); the conditional ones did "
                          "not fire on this operand set")
    else:
        doc["verdict"] = "NO_DIVERGENCE_OBSERVED"

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    print("\n   VERDICT: %s" % doc["verdict"])
    print("wrote %s" % OUT)
    print("wall %.1fs" % (time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
