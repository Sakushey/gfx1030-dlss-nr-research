#!/usr/bin/env python3
"""Phase 16R / R9 -- observe the J3 dispatch's division sequence, and run the
end-to-end differential that decides whether the emulator's declared
structural approximation of `v_div_scale_f32` / `v_div_fmas_f32` /
`v_div_fixup_f32` can change any externally visible byte of this fixture.

HOST ONLY.  No GPU, no HIP call, no game launch, nothing armed.

WHAT IT DOES.  One process, one dispatch, one mode:

  baseline        the emulator's own handlers, wrapped only to RECORD what
                  they were called with.  These 144 + 72 + 72 parameter
                  tuples are the executed forms of the J3 trace.
  isa             the same dispatch with the three handlers REPLACED on
                  `GateCore` (the class the runner instantiates, i.e. the
                  MRO-resolved owner) by the independent RDNA2 reference in
                  `r9_isa_div.py`.  Same inputs, ISA semantics.
  always_scale64  a deliberately WRONG reference: every non-exceptional
                  `v_div_scale_f32` result is `ldexp(S0, 64)`.  A KNOWN-BAD
                  control.  If the differential cannot tell this apart from
                  the baseline, the differential proves nothing.

THE OBSERVABLE.  `externally visible bytes` = the ISA-visible bytes, read
through `core._mem_byte(addr) & 0xFF` -- the same observation layer
`phase16q/j3_v2/J3_CONFORMANCE_FINAL.json` pins (`reader: isa_bytes`) --
over exactly the declared regions this dispatch WROTE.  Read-only regions
are reported separately and excluded, because a byte the kernel never
writes is not an output.  A SHA-256 over those bytes is the digest.

Nothing under phase16p/, phase16q/, phase16h_candidate_f/ or any other
phase is modified; the emulator patch is applied in memory, to this
process's class object only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ISA = os.path.dirname(HERE)                     # phase16r/isa
ROOT = os.path.dirname(os.path.dirname(ISA))    # project root

sys.path.insert(0, HERE)
import r9_isa_div as REF                        # noqa: E402

P16P = os.path.join(ROOT, "phase16p", "j3_v2", "tools")
sys.path.insert(0, P16P)

import p16p_trace as T                          # noqa: E402  (unmodified)
import p16p_j3cfg as J3                         # noqa: E402  (unmodified)

# The trace these numbers must reproduce.  Read from the phase 16P artifact
# rather than typed, so a mismatch is a measurement and not a transcription
# error.
TRACE_SUMMARY = os.path.join(ROOT, "phase16p", "j3_v2", "out",
                             "J3_TRACE_SUMMARY.json")

# The extents the recorded trace was produced at.  Recovered from the
# recorded artifact's own `regions` block, not assumed.
def _recorded_extents():
    d = json.load(open(TRACE_SUMMARY, encoding="utf-8"))
    tensor = canvas = None
    for r in d["regions"]:
        if r["name"] == "slot_0xA0":
            canvas = r["size"]
        elif tensor is None:
            tensor = r["size"]
    return tensor, canvas, d


TENSOR_BYTES, CANVAS_BYTES, RECORDED = _recorded_extents()

DIV_MNEMS = ("v_div_scale_f32", "v_div_fmas_f32", "v_div_fixup_f32")

#: ISA operand roles, by printed operand index.  Derived from the ISA text's
#: S0/S1/S2 naming plus LLVM's operand list (see r9_isa_div.py header):
#:   v_div_scale_f32  vdst, SDST, SRC0=S0, SRC1=S1, SRC2=S2
#:   v_div_fmas_f32   vdst, SRC0=S0, SRC1=S1, SRC2=S2
#:   v_div_fixup_f32  vdst, SRC0=S0=Quotient, SRC1=S1=Denominator, SRC2=S2=Numerator
_ROLES = {
    "v_div_scale_f32": (2, 3, 4),
    "v_div_fmas_f32": (1, 2, 3),
    "v_div_fixup_f32": (1, 2, 3),
}


# ---------------------------------------------------------------------------
# the recorder
# ---------------------------------------------------------------------------
class DivTracer(T.Tracer):
    """The phase 16P tracer plus a per-instance record of the three div ops."""

    def __init__(self):
        super().__init__()
        self.div = []            # one row per executed div instruction
        self.div_hook_calls = {m: 0 for m in DIV_MNEMS}
        self.div_lane_calls = {m: 0 for m in DIV_MNEMS}


def _record(tr, self_, mnem, ops, ins):
    """Capture the ISA operands of one executed div instruction, per lane.

    VALIDATED.  The operands recorded here were checked against a direct dump
    of the VGPR file across one J3 division site (tools/r9_dbg_regs.py,
    logs/r9_dbg_regs.json): at 0x0B51C4 the recorder captured
    s0=0xC91814CC s1=0x3F000000 s2=0x3EE00000, and the register dump measured
    v8=0xC91814CC, v7=0x3F000000, v5=0x3EE00000 at the same instant.  That
    check exists because the recorded values initially looked inconsistent
    with a hand derivation of the disassembled sequence; the hand derivation
    was wrong, and the recorder was right.
    """
    i0, i1, i2 = _ROLES[mnem]
    row = {
        "pc": ins.get("address"),
        "mnem": mnem,
        "ops": ins.get("operands"),
        "wave": getattr(self_, "_p16p_wave", 0),
        "exec": self_.exec_l,
        "n_lanes": bin(self_.exec_l).count("1"),
        "vcc_l_before": self_.vcc_l,
        "lanes": [],
    }
    for lane in range(self_.lanes):
        if not ((self_.exec_l >> lane) & 1):
            continue
        try:
            s0 = self_.vget(lane, ops[i0], fp=True)
            s1 = self_.vget(lane, ops[i1], fp=True)
            s2 = self_.vget(lane, ops[i2], fp=True)
        except (IndexError, NotImplementedError):
            s0 = s1 = s2 = None
        if mnem == "v_div_scale_f32":
            s1 = s1 if len(ops) > i1 else None
        row["lanes"].append({"lane": lane,
                             "s0_bits": REF.bits(s0) if isinstance(s0, float) else None,
                             "s1_bits": REF.bits(s1) if isinstance(s1, float) else None,
                             "s2_bits": REF.bits(s2) if isinstance(s2, float) else None,
                             "s0": s0, "s1": s1, "s2": s2})
    tr.div.append(row)
    tr.div_lane_calls[mnem] += row["n_lanes"]


def _make_emulator_level(tr, mnem, original):
    """Wrap the MRO-resolved handler so it RECORDS, then delegates."""
    def handler(self, ins, ops):
        tr.div_hook_calls[mnem] += 1
        _record(tr, self, mnem, ops, ins)
        return original(self, ins, ops)
    return handler


def _make_isa_level(tr, mnem, mode):
    """The independent RDNA2 reference, installed in place of the handler.

    `mode` selects WHICH semantics are installed:
      "isa"             the independent RDNA2 reference
      "always_scale64"  a deliberately WRONG reference (known-bad control)
      "restated"        the emulator's own behaviour, re-implemented here
                        from the description in r9_isa_div.emulator_*
    The third is the control that isolates SEMANTICS from PLUMBING: if
    replacing a handler with a faithful restatement of itself moves the
    digest, then the digests below are measuring the harness, not the
    instruction.
    """
    if mnem == "v_div_scale_f32":
        def handler(self, ins, ops):
            tr.div_hook_calls[mnem] += 1
            _record(tr, self, mnem, ops, ins)
            sdst = ops[1]
            vcc_mask = 0
            for lane in range(self.lanes):
                if not ((self.exec_l >> lane) & 1):
                    continue
                s0 = self.vget(lane, ops[2], fp=True)
                s1 = self.vget(lane, ops[3], fp=True) if len(ops) > 3 else s0
                s2 = self.vget(lane, ops[4], fp=True) if len(ops) > 4 else s0
                if mode == "restated":
                    r = REF.emulator_scale_f32(s0, s1, s2)
                elif mode == "always_scale64":
                    if s2 == 0.0 or s1 == 0.0:
                        r = REF.scale_f32(s0, s1, s2)
                    else:
                        r = {"D": REF.ldexp32(s0, 64), "vcc": 0}
                else:
                    r = REF.scale_f32(
                        s0, s1, s2, mode="passthrough",
                        exp_mode=("unbiased" if mode == "isa_unbiased"
                                  else "biased"))
                    if mode == "u1_zero" and not r["branch_assigned"]:
                        # An ALTERNATIVE resolution of the ISA text's missing
                        # `else` (uncertainty U1): the unassigned branch
                        # yields +0.0.  Not claimed to be the hardware
                        # behaviour -- this exists to MEASURE whether the
                        # resolution of U1 is load-bearing on visible bytes.
                        r = {"D": 0.0, "vcc": r["vcc"],
                             "branch": "U1 resolved to +0.0"}
                self.vset(lane, ops[0], REF.bits(r["D"]))
                if r["vcc"]:
                    vcc_mask |= 1 << lane
            if sdst == "vcc_lo":
                self.vcc_l = vcc_mask
            elif sdst not in ("null", "off", None):
                self.sset(sdst, vcc_mask)
        return handler

    if mnem == "v_div_fmas_f32":
        def handler(self, ins, ops):
            tr.div_hook_calls[mnem] += 1
            _record(tr, self, mnem, ops, ins)
            for lane in range(self.lanes):
                if not ((self.exec_l >> lane) & 1):
                    continue
                s0 = self.vget(lane, ops[1], fp=True)
                s1 = self.vget(lane, ops[2], fp=True)
                s2 = self.vget(lane, ops[3], fp=True)
                vcc = (self.vcc_l >> lane) & 1
                if mode == "restated":
                    out = REF.emulator_fmas_f32(s0, s1, s2)
                else:
                    out = REF.fmas_f32(s0, s1, s2, vcc)
                self.vset(lane, ops[0], REF.bits(out))
        return handler

    # v_div_fixup_f32
    def handler(self, ins, ops):
        tr.div_hook_calls[mnem] += 1
        _record(tr, self, mnem, ops, ins)
        for lane in range(self.lanes):
            if not ((self.exec_l >> lane) & 1):
                continue
            s0 = self.vget(lane, ops[1], fp=True)
            s1 = self.vget(lane, ops[2], fp=True)
            s2 = self.vget(lane, ops[3], fp=True)
            if mode == "restated":
                out = REF.emulator_fixup_f32(s0, s1, s2)
            elif mode == "always_scale64":
                out = s0
            else:
                out = REF.fixup_f32(s0, s1, s2)["D"]
            self.vset(lane, ops[0], REF.bits(out))
    return handler


# ---------------------------------------------------------------------------
# the observable
# ---------------------------------------------------------------------------
def visible_digest(core, regions, tr):
    """SHA-256 over the ISA-visible bytes of every region this run WROTE."""
    h = hashlib.sha256()
    per_region = {}
    for lo, name, size in regions:
        d = tr.touch.get(name)
        if not d or d["wmax"] is None:
            per_region[name] = {"written": False}
            continue
        n = d["wmax"] - lo + 1
        h.update(name.encode("ascii"))
        h.update(b"\x00")
        h.update(n.to_bytes(8, "little"))
        buf = bytearray(n)
        for off in range(n):
            buf[off] = core._mem_byte(lo + off) & 0xFF
        h.update(buf)
        distinct = len(set(buf))
        per_region[name] = {
            "written": True, "bytes": n,
            "addr_lo": "0x%X" % lo, "addr_hi": "0x%X" % (lo + n - 1),
            "sha256": hashlib.sha256(bytes(buf)).hexdigest(),
            "distinct_byte_values": distinct,
        }
    return h.hexdigest(), per_region


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True,
                    choices=("baseline", "restated", "isa", "always_scale64",
                             "u1_zero", "isa_unbiased"))
    ap.add_argument("--fix-negate", action="store_true",
                    help="ALSO repair, in memory only, the emulator's "
                         "`-vN` operand bug (see the note in the header).")
    ap.add_argument("--only", default=None,
                    help="comma-separated subset of the three mnemonics to "
                         "replace; the rest get the restated emulator. "
                         "Default: all three.")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    targets = (tuple(a.only.split(",")) if a.only else DIV_MNEMS)
    for m in targets:
        if m not in DIV_MNEMS:
            raise SystemExit("R9: --only names an unknown mnemonic: %s" % m)

    if a.mode != "baseline":
        import p16h_global_gate as G
        core_cls = G.GateCore
    else:
        import p16h_global_gate as G
        core_cls = G.GateCore

    # ---- MEASURED, SEPARATE DEFECT, kept out of the div question ---------
    # `Core.vget` reads a negated vector operand as `(-bits) & 0xFFFFFFFF`
    # reinterpreted as f32 -- an INTEGER negate of the bit pattern, which is
    # the true negation only for +-0.0.  `-v8` with v8 = 0.5 therefore reads
    # as -8.0.  This is not one of R9's three instructions, but it sits on
    # the same sequence: the Newton-Raphson steps at 0x0B51A8 / 0x0B51B4 use
    # `-v8`, so the quotient handed to `v_div_fmas_f32` and
    # `v_div_fixup_f32` is not the quotient the ISA sequence would compute.
    # The wrapper below counts those reads always, and repairs them only
    # under --fix-negate, IN MEMORY, on this process's class object only.
    neg_reads = {"n": 0}
    _orig_vget = core_cls.vget

    def _r9_vget(self, lane, tok, fp=False):
        t = tok.strip()
        if t.startswith("-v"):
            neg_reads["n"] += 1
            v = _orig_vget(self, lane, t[1:], fp)
            if a.fix_negate:
                return (-v) if fp else ((-v) & 0xFFFFFFFF)
            return _orig_vget(self, lane, t, fp)
        return _orig_vget(self, lane, t, fp)

    _r9_vget.__r9_vget__ = True
    core_cls.vget = _r9_vget
    if not getattr(core_cls.vget, "__r9_vget__", False):
        raise SystemExit("R9: the vget wrapper did not take")

    vals, meta = J3.load_authentic_cell()
    regions = J3.j3_regions(vals, tensor_bytes=TENSOR_BYTES,
                            canvas_bytes=CANVAS_BYTES)

    tr = DivTracer()
    tr.regions = regions
    T.install(tr)

    # ---- install the three div hooks ON THE CLASS THE RUNNER INSTANTIATES
    import p16h_global_gate as G
    core_cls = G.GateCore
    mro_owner = {}
    for mnem in DIV_MNEMS:
        owner = None
        for k in core_cls.__mro__:
            if "op_" + mnem in k.__dict__:
                owner = k
                break
        mro_owner[mnem] = owner.__name__ if owner else None

    installed = {}
    for mnem in DIV_MNEMS:
        original = getattr(core_cls, "op_" + mnem)
        if a.mode == "baseline":
            fn = _make_emulator_level(tr, mnem, original)
        elif mnem in targets:
            fn = _make_isa_level(tr, mnem, a.mode)
        else:
            fn = _make_isa_level(tr, mnem, "restated")
        fn.__r9_hook__ = mnem
        setattr(core_cls, "op_" + mnem, fn)
        installed[mnem] = getattr(core_cls, "op_" + mnem).__r9_hook__
        # the hook must have landed: a patch that does not resolve is a
        # silent no-op and would make every number below a non-measurement.
        if installed[mnem] != mnem:
            raise SystemExit("R9: hook for %s did not take on %s"
                             % (mnem, core_cls.__name__))
    # and the unwrapped original must no longer be what runs
    for mnem in DIV_MNEMS:
        if not getattr(getattr(core_cls, "op_" + mnem), "__r9_hook__", None):
            raise SystemExit("R9: %s is not hooked after install" % mnem)

    res, ggate, hw = T.run_j3(vals, regions,
                              wave_count=J3.J3_WAVES, round_cap=2_000_000)
    g = ggate.summary()
    cores = res["_cores"]
    if not cores:
        raise SystemExit("R9: no cores returned; nothing to hash")
    core = cores[0]

    digest, per_region = visible_digest(core, regions, tr)

    # ---- the executed forms
    forms = {}
    for mnem in DIV_MNEMS:
        rows = [r for r in tr.div if r["mnem"] == mnem]
        pcs = sorted({r["pc"] for r in rows})
        per_pc = {}
        for pc in pcs:
            sub = [r for r in rows if r["pc"] == pc]
            per_pc["0x%06X" % pc] = {
                "instances": len(sub),
                "ops": sub[0]["ops"],
                "n_lanes_total": sum(r["n_lanes"] for r in sub),
                "exec_masks": sorted({r["exec"] for r in sub}),
            }
        forms[mnem] = {
            "instances": len(rows),
            "lane_instances": tr.div_lane_calls[mnem],
            "handler_calls": tr.div_hook_calls[mnem],
            "distinct_pcs": len(pcs),
            "sites": per_pc,
        }

    # ---- what the operands actually were, and whether ISA differs there
    divergence = {}
    if a.mode == "baseline":
        for mnem in DIV_MNEMS:
            diff = agree = 0
            branches = {}
            examples, examples_diff = [], []
            for r in tr.div:
                if r["mnem"] != mnem:
                    continue
                for L in r["lanes"]:
                    s0, s1, s2 = L["s0"], L["s1"], L["s2"]
                    if s0 is None:
                        continue
                    if mnem == "v_div_scale_f32":
                        isa = REF.scale_f32(s0, s1, s2, mode="passthrough")
                        emu = REF.emulator_scale_f32(s0, s1, s2)
                        branches[isa["branch"]] = branches.get(isa["branch"], 0) + 1
                        same = (REF.bits(isa["D"]) == REF.bits(emu["D"]))
                    elif mnem == "v_div_fmas_f32":
                        isa_v = REF.fmas_f32(s0, s1, s2, (r["vcc_l_before"] >> L["lane"]) & 1)
                        emu_v = REF.emulator_fmas_f32(s0, s1, s2)
                        branches["vcc_lane=%d" % ((r["vcc_l_before"] >> L["lane"]) & 1)] = \
                            branches.get("vcc_lane=%d" % ((r["vcc_l_before"] >> L["lane"]) & 1), 0) + 1
                        same = (REF.bits(isa_v) == REF.bits(emu_v))
                    else:
                        isa = REF.fixup_f32(s0, s1, s2)
                        emu_v = REF.emulator_fixup_f32(s0, s1, s2)
                        branches[isa["branch"]] = branches.get(isa["branch"], 0) + 1
                        same = (REF.bits(isa["D"]) == REF.bits(emu_v))
                    if same:
                        agree += 1
                    else:
                        diff += 1
                        if len(examples_diff) < 6:
                            examples_diff.append(
                                {"pc": "0x%06X" % r["pc"], "lane": L["lane"],
                                 "s0": "0x%08X" % REF.bits(s0),
                                 "s1": "0x%08X" % REF.bits(s1),
                                 "s2": "0x%08X" % REF.bits(s2)})
                    if len(examples) < 4:
                        examples.append(
                            {"pc": "0x%06X" % r["pc"], "lane": L["lane"],
                             "s0": "0x%08X" % REF.bits(s0),
                             "s1": "0x%08X" % REF.bits(s1),
                             "s2": "0x%08X" % REF.bits(s2), "agree": same})
            divergence[mnem] = {
                "lane_instances": agree + diff,
                "isa_equals_emulator": agree,
                "isa_differs_from_emulator": diff,
                "isa_branches_hit": branches,
                "examples": examples,
                "examples_that_differ": examples_diff,
            }

    doc = {
        "schema": "phase16r-r9-j3-div-run/1",
        "phase": "16R", "track": "R9",
        "host_only": True, "gpu_execution_performed": False,
        "gta_launched": False, "currently_armed": False,
        "mode": a.mode,
        "replaced_handlers": list(targets) if a.mode not in ("baseline",) else [],
        "geometry": {"kernel": J3.SYM, "grid": list(J3.J3_GRID),
                     "block": list(J3.J3_BLOCK), "waves": J3.J3_WAVES},
        "extents": {"tensor_bytes": TENSOR_BYTES, "canvas_bytes": CANVAS_BYTES,
                    "source": "phase16p/j3_v2/out/J3_TRACE_SUMMARY.json regions"},
        "recorded_trace": {
            "ticks": RECORDED["ticks"],
            "counts": RECORDED["counts"],
            "families_executed_div": {
                m: RECORDED["families_executed"].get(m)
                for m in DIV_MNEMS},
        },
        "reproduced": {
            "ticks": res["ticks"], "outcome": str(res["outcome"]),
            "faults": res["faults"], "natural_end": res["natural_end"],
            "nodes": len(tr.pc), "store_instances": len(tr.store_rows),
            "gate": g["gate"], "n_global_reads": g.get("n_global_reads"),
            "n_global_writes": g.get("n_global_writes"),
        },
        "ticks_match_recorded": res["ticks"] == RECORDED["ticks"],
        "handlers": {"instantiated_class": core_cls.__name__,
                     "mro_resolved_owner": mro_owner,
                     "hooked": installed},
        "vget_negate_probe": {
            "measured": "count of `-vN` vector-operand reads in this run",
            "neg_reads": neg_reads["n"],
            "repaired_in_this_run": bool(a.fix_negate),
            "defect": "vget('-vN') = f32((-bits(N)) & 0xFFFFFFFF); equals "
                      "-v only when v is +-0.0 (emu.py:460-461)",
        },
        "executed_forms": forms,
        "divergence_baseline": divergence,
        "visible_bytes": {
            "reader": "core._mem_byte(addr) & 0xFF",
            "digest_sha256": digest,
            "per_region": per_region,
        },
    }
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    print("mode=%s ticks=%s (recorded %s) stores=%d nodes=%d gate=%s"
          % (a.mode, res["ticks"], RECORDED["ticks"],
             len(tr.store_rows), len(tr.pc), g["gate"]))
    for m in DIV_MNEMS:
        print("  %-18s handler_calls=%-5d instances=%-5d lane_instances=%d"
              % (m, tr.div_hook_calls[m], forms[m]["instances"],
                 tr.div_lane_calls[m]))
    print("VISIBLE_BYTES_SHA256 %s" % digest)
    print("neg_operand_reads=%d fix_negate=%s"
          % (neg_reads["n"], bool(a.fix_negate)))
    print("wrote %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
