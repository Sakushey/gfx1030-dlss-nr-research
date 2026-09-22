#!/usr/bin/env python3
"""Phase 16Y / PART II / TARGETED ORACLE FOR THE LIVENESS-CRITICAL MNEMONICS
(brief S27).

WHY THIS EXISTS.  Phase 16T's J3 instruction conformance matrix classifies a
mnemonic by whether it contributes to the OUTPUT cone.  Queried for the five
instructions that decide the 0xBBE20 question it answers:

    s_and_saveexec_b32   VERIFIED_INDEPENDENTLY
    s_cbranch_scc1       NOT_OUTPUT_RELEVANT
    s_cbranch_execz      NOT_OUTPUT_RELEVANT
    s_endpgm             NOT_OUTPUT_RELEVANT
    s_barrier            NOT_OUTPUT_RELEVANT

"NOT_OUTPUT_RELEVANT" is a true statement about the output image and a false
comfort about liveness: these four are precisely the instructions that decide
whether a wave reaches the in-loop barrier, whether it leaves the loop, and
whether it retires at all.  Brief S27 says an unverified liveness-critical
mnemonic gets a targeted independent oracle now rather than an assumption.

WHAT THIS DOES.  It takes the REAL instruction dicts out of the frozen J3
disassembly (`PE.slice_program`, the same slicer the runner uses), builds
minimal micro-programs from them, executes them on the SAME INSTANTIATED core
class the J3 run uses, and compares the resulting architectural state against
an independent reference computed in plain Python.  It also asserts, via the
MRO, which class actually supplies each handler -- a subclass that overrode one
of these would otherwise be silently untested.

Each case carries a NEGATIVE CONTROL: the reference is deliberately broken in
the way the instruction is most plausibly mis-implemented (AND read as OR,
branch polarity inverted, ...) and the comparator must report a mismatch.  A
comparator that cannot fail is not a comparator.

Host-only.  No GPU, no HIP, no driver, no game, no harness executable.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
Y = os.path.dirname(HERE)
ROOT = os.path.dirname(Y)

REV_TREE = os.path.join(ROOT, "phase16t", "semantic", "revision_16t")
J3V2 = os.path.join(ROOT, "phase16r", "j3_v2")
DIS = os.path.join(ROOT, "phase16h_candidate_f", "disasm",
                   "candidate_f_gfx1030_disasm.txt")
SYM = "_Z10k_swin_varILi32ELb0EEv9VarParams"
OUT = os.path.join(Y, "audit", "J3_LIVENESS_SEMANTICS_ORACLE_16Y.json")

TREE_MODULES = ["emu", "p16j_input", "p14d8_core", "p14e_emu", "p14eh",
                "p16e_rec", "p16h_scratch_probe", "p16j_scratch_isa"]
PATHS = ["phase16k_pretest/k3_arena", "phase16j_pre_gta/tools",
         "phase16i_closure/tools", "phase16h_pcrel_fix/tools",
         "phase16e_candidate_e/tools", "phase14e_static/tools",
         "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
         "phase14d11_static/tools", "phase14d11_static",
         "phase14d_static/tools", "phase8_static/tools",
         "phase14d8_static/tools"]

#: the four PCs the liveness argument turns on, from the frozen 16X analysis
PCS = {"s_and_saveexec_b32": 0xBBE2C, "s_cbranch_scc1": 0xBA730,
       "s_cbranch_execz": 0xBBE30, "s_endpgm": 0xC36D8,
       "s_barrier": 0xBBE20, "s_branch": 0xBBF1C}

MASK32 = (1 << 32) - 1


def setup():
    sys.path.insert(0, os.path.join(ROOT, "phase16p", "j3_v2", "tools"))
    sys.path.insert(0, os.path.join(ROOT, "phase16j_pre_gta", "tools"))
    sys.path.insert(0, J3V2)
    sys.path.insert(0, os.path.join(ROOT, "phase16t", "j3"))
    for p in PATHS:
        pp = os.path.join(ROOT, p)
        if pp not in sys.path:
            sys.path.insert(0, pp)
    for name in TREE_MODULES:
        path = os.path.join(REV_TREE, name + ".py")
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)


def which_class_owns(cls, mnem):
    """Walk the MRO and name the class whose __dict__ holds the handler."""
    attr = "op_" + mnem
    for k in cls.__mro__:
        if attr in k.__dict__:
            return "%s.%s" % (k.__name__, attr)
    return None


def run_cases():
    import emu
    import p16h_global_gate as G
    prog_all, _rows, _i = G.PE.slice_program(DIS, SYM)
    by_addr = {}
    for ins in prog_all:
        by_addr.setdefault(ins.get("address"), ins)

    Core = G.GateCore
    G.GateCore.oob_sem = "u32"
    G.GateCore.alloc = 16384
    G.GateCore.lds_img = 0x10000
    if not hasattr(G.GateCore, "gate"):
        G.GateCore.gate = None

    cases = []

    def mk(ins, n_extra=1):
        """A micro-program: the instruction under test at index 0, then n_extra
        filler instructions.  `pc` is an INDEX into this list."""
        end = by_addr[PCS["s_endpgm"]]
        body = [dict(ins)]
        for _ in range(n_extra):
            body.append(dict(end))
        return body

    def new_core(prog):
        c = Core(prog, lanes=32, lds_size=0x10000, lds_fill=0,
                 wavebase=0, mem={})
        # `p14d11_emu.TraceCore.step` reads `self._prog_ref` before delegating;
        # the real runner sets it during set-up.  Without it every step raises
        # AttributeError('_prog_ref') before the handler under test is reached.
        c._prog_ref = prog
        return c

    def rec(name, mnem, vector, got, want, wrongs, note=""):
        """`wrongs` are genuinely plausible MIS-READINGS of the instruction.

        A control is only a control where the readings differ.  On the vector
        (EXEC=0xFFFFFFFF, s2=0xFFFFFFFF) AND and OR coincide, so NO wrong
        reading can be distinguished there -- that vector is positive-only, and
        calling it a control failure would be the mirror of the mistake this
        project keeps making (a check that cannot fire reported as evidence).
        Each case therefore reports which vectors discriminate, and needs at
        least one that does.
        """
        if not isinstance(wrongs, list):
            wrongs = [wrongs]
        agree = (got == want)
        disc = [w for w in wrongs if w != want]
        if disc:
            control_ok = all(got != w for w in disc)
            kind = "discriminating"
        else:
            control_ok = True
            kind = ("positive-only: every wrong reading coincides with the "
                    "right one on this vector")
        cases.append({
            "oracle": name, "mnemonic": mnem, "vector": vector,
            "handler_owner": which_class_owns(Core, mnem),
            "measured": got, "independent_reference": want,
            "agrees_with_reference": agree,
            "control_kind": kind,
            "negative_controls": [
                {"wrong_reference": w, "differs_from_reference": w != want,
                 "wrong_reference_matches_measurement": got == w}
                for w in wrongs],
            "note": note,
            "verdict": "PASS" if (agree and control_ok) else "FAIL",
        })

    # ---- 1. s_and_saveexec_b32 s8, s2 : EXEC := EXEC & s2 ; s8 := EXEC_old --
    ins = by_addr[PCS["s_and_saveexec_b32"]]
    ops = [t.strip() for t in (ins.get("operands") or "").split(",")]
    for i, (exec0, s2) in enumerate([(MASK32, MASK32), (MASK32, 0x5A5A5A5A),
                                     (0x0F0F0F0F, 0x00FF00FF), (0x0, 0xFFFF)]):
        p = mk(ins)
        c = new_core(p)
        c.exec_l = exec0
        c.s[2] = s2
        c.step()
        got = {"exec_after": c.exec_l, "saved_dst_s8": c.s[8]}
        want = {"exec_after": exec0 & s2, "saved_dst_s8": exec0}
        wrong = [
            # W1: AND read as OR -- the classic scalar-mask mis-implementation
            {"exec_after": exec0 | s2, "saved_dst_s8": exec0},
            # W2: the destination receives the NEW EXEC rather than the old one
            {"exec_after": exec0 & s2, "saved_dst_s8": exec0 & s2},
        ]
        rec("and_saveexec_semantics",
            "s_and_saveexec_b32",
            {"vector": i, "operands": ops, "exec_before": hex(exec0),
             "s2": hex(s2)},
            got, want, wrong,
            "EXEC = EXEC & s2 and the destination receives the OLD EXEC. "
            "The negative control reads the operation as OR, which is the "
            "plausible mis-implementation the ISA text rules out.")

    # ---- 2. s_cbranch_scc1 : pc = target iff SCC == 1 ---------------------
    # NOTE on the reference model: `Core.step()` advances pc by 1 on
    # fall-through, and a branch handler overrides pc with `ins["target"]`.
    # So "not taken" is pc_before + 1, not pc_before.  The first draft of this
    # oracle got that wrong and reported four false failures -- recorded here
    # because it is the same conflation of index and address that S19 warns
    # about.  Taken and not-taken are also placed on DIFFERENT indices, so a
    # branch that never fires cannot pass by landing where fall-through lands.
    ins = by_addr[PCS["s_cbranch_scc1"]]
    for i, scc in enumerate([0, 1]):
        p = mk(ins, 3)                      # 4 instructions: [ins, end, end, end]
        p[0] = dict(ins)
        p[0]["target"] = 2
        c = new_core(p)
        c.scc = scc
        c.step()
        got = {"pc": c.pc}
        want = {"pc": 2 if scc == 1 else 1}
        wrong = {"pc": 1 if scc == 1 else 2}
        rec("cbranch_scc1_semantics", "s_cbranch_scc1",
            {"vector": i, "scc": scc, "target_index": 2, "fallthrough_index": 1},
            got, want, wrong,
            "Branches on SCC == 1 and on nothing else.  Negative control "
            "inverts the polarity.")

    # ---- 3. s_cbranch_execz : pc = target iff EXEC == 0 ------------------
    ins = by_addr[PCS["s_cbranch_execz"]]
    end = dict(by_addr[PCS["s_endpgm"]])
    for i, ex in enumerate([0, MASK32, 1 << 7]):
        # target index 2 vs fall-through index 1: DIFFERENT, so "never branches"
        # and "always branches" cannot both score PASS.
        p = [dict(ins), dict(end), dict(end)]
        p[0]["target"] = 2
        c = new_core(p)
        c.exec_l = ex
        c.step()
        got = {"pc": c.pc}
        want = {"pc": 2 if ex == 0 else 1}
        wrong = {"pc": 1 if ex == 0 else 2}
        rec("cbranch_execz_semantics", "s_cbranch_execz",
            {"vector": i, "exec": hex(ex), "target_index": 2,
             "fallthrough_index": 1}, got, want, wrong,
            "Branches iff the whole EXEC mask is zero.  This is the backedge "
            "that would re-enter the loop header, so its polarity IS the "
            "liveness question.")

    # ---- 4. s_endpgm : terminates, by raising Halt -----------------------
    ins = by_addr[PCS["s_endpgm"]]
    c = new_core([dict(ins)])
    raised = None
    try:
        c.step()
    except emu.Halt as h:
        raised = getattr(h, "kind", str(h))
    except BaseException as e:                                  # noqa: BLE001
        raised = "OTHER:%s" % type(e).__name__
    got = {"halt_kind": raised, "terminated": bool(c.terminated)}
    want = {"halt_kind": "END", "terminated": True}
    wrong = {"halt_kind": None, "terminated": False}
    rec("endpgm_semantics", "s_endpgm", {}, got, want, wrong,
        "Retires by raising Halt('END') AND setting terminated.  Both matter: "
        "p14eh._run_wg_hw marks the wave ENDED on the raise, and the raise is "
        "why the scheduler's steps_done excludes this step.")

    # ---- 5. s_barrier : the CORE does not synchronise --------------------
    ins = by_addr[PCS["s_barrier"]]
    p = [dict(ins), dict(by_addr[PCS["s_endpgm"]])]
    c = new_core(p)
    before = {"exec": c.exec_l, "scc": c.scc, "s": list(c.s),
              "pc": c.pc, "terminated": c.terminated}
    c.step()
    after = {"exec": c.exec_l, "scc": c.scc, "s": list(c.s), "pc": c.pc,
             "terminated": c.terminated}
    got = {"state_unchanged": (before["exec"] == after["exec"]
                               and before["scc"] == after["scc"]
                               and before["s"] == after["s"]),
           "pc_advanced_by": after["pc"] - before["pc"],
           "terminated": after["terminated"]}
    want = {"state_unchanged": True, "pc_advanced_by": 1, "terminated": False}
    wrong = {"state_unchanged": True, "pc_advanced_by": 10,
             "terminated": False}
    rec("barrier_is_not_implemented_in_the_core", "s_barrier", {},
        got, want, wrong,
        "The core's s_barrier handler is _noop: executing it changes no "
        "architectural state.  Synchronisation therefore lives ENTIRELY in the "
        "scheduler (p14eh._run_wg_hw intercepts the barrier before core.step, "
        "holds the wave in WAITING, and only releases when every live wave is "
        "parked on the SAME site).  This is why the per-wave barrier trace is "
        "evidence about the scheduler, not about an instruction.")

    # ---- handler ownership: nothing may shadow these --------------------
    owners = {m: which_class_owns(Core, m) for m in
              ("s_and_saveexec_b32", "s_cbranch_scc1", "s_cbranch_execz",
               "s_endpgm", "s_barrier", "s_branch")}
    shadowed = sorted(m for m, o in owners.items()
                      if o is None or not o.startswith("Core."))
    return cases, owners, shadowed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()
    setup()
    cases, owners, shadowed = run_cases()
    bad = [c for c in cases if c["verdict"] != "PASS"]
    doc = {
        "schema": "phase16y-liveness-semantics-oracle/1",
        "phase": "16Y",
        "brief": "S27 -- targeted oracle for the liveness-critical mnemonics",
        "host_only": True, "gpu_execution_performed": False,
        "kernel_launch_count": 0,
        "why": "Phase 16T classifies a mnemonic by output-cone relevance. "
               "s_cbranch_scc1, s_cbranch_execz, s_endpgm and s_barrier are "
               "NOT_OUTPUT_RELEVANT and therefore carry no independent "
               "verification there, although they decide liveness.  S27 "
               "requires an oracle rather than an assumption.",
        "instructions_used_from": os.path.relpath(DIS, ROOT).replace("\\", "/"),
        "handler_owners_in_the_instantiated_class": owners,
        "handlers_shadowed_by_a_subclass": shadowed,
        "n_cases": len(cases), "n_failed": len(bad),
        "cases": cases,
        "verdict": "PASS" if not bad and not shadowed else "FAIL",
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    for c in cases:
        print("  %-46s %-8s %s" % (c["oracle"], c["mnemonic"][:22],
                                   c["verdict"]))
        print("       measured=%s" % json.dumps(c["measured"])[:110])
        print("       reference=%s" % json.dumps(c["independent_reference"])[:110])
    print("handler owners: %s" % json.dumps(owners))
    print("shadowed: %s" % (shadowed or "none"))
    print("cases=%d failed=%d" % (len(cases), len(bad)))
    print("LIVENESS SEMANTICS ORACLE VERDICT: %s" % doc["verdict"])
    return 0 if doc["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
