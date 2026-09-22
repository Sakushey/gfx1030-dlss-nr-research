#!/usr/bin/env python3
"""Phase 16Y -- per-wave DYNAMIC BARRIER TRACE (brief S14, S15).

WHY THIS FILE EXISTS.  Phase 16X found 18 static `s_barrier` sites and
established that exactly one of them -- 0xBBE20 -- sits inside a loop whose
two tail paths rejoin the header depending on whether a whole-wave mask zeroes
EXEC.  It recorded:

    "Whether it is dynamically reachable is NOT established."

That question decides whether the next physical launch is authorized, and an
unknown must not be converted into a pass (S36).  This instrument answers it.

WHAT THE ANSWER IS BUILT FROM.  The project's frozen host model already
publishes `barrier_epochs`, and each entry is the PC at which every live wave
converged.  Converting the 16T trace's numbers shows they are exactly the ten
barrier PCs 16X listed as mandatory-on-every-path -- and 0xBBE20 IS among
them.  So the in-loop barrier is reached, once.  That is strong, but it is the
CONVERGED view: it does not show each wave's own ordered sequence, and it
cannot see the case that actually matters here, because the scheduler takes
`alive` to exclude waves that have already ENDED.  A wave that left the loop
early would retire, leave the convergence set, and the epoch list would still
look unanimous.

So this instrument records, per wave and in order, from the Core's own
uncapped `trace_pc`:
    every barrier PC reached, its ordinal, and the tick it happened on
plus, at the four liveness-critical PCs, the EXEC mask, the scalar operand
and SCC that decide the loop's fate.

IT DOES NOT MODIFY THE EMULATOR.  The semantic revision is frozen by SHA-256
in SEMANTIC_FREEZE_16T.json; editing it would invalidate the expected output
this run is compared against.  Observation is added by SUBCLASSING in this
file, which is the established pattern (r2_tracer.tracing_core_class,
p16h_global_gate.GateCore).

SEMANTIC NEUTRALITY IS ASSERTED, NOT ASSUMED.  The instrumented run must
reproduce the frozen image SHA 5ab70916..., the frozen ticks, the per-wave
step counts and the barrier epoch list.  If instrumentation changed anything,
this reports a failure rather than a trace.

Host-only.  No GPU, no HIP, no driver, no game.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
Y = os.path.dirname(HERE)
ROOT = os.path.dirname(Y)

REV_TREE = os.path.join(ROOT, "phase16t", "semantic", "revision_16t")
J3V2 = os.path.join(ROOT, "phase16r", "j3_v2")
BIN = os.path.join(J3V2, "J3_V2_INPUT.bin")
META = os.path.join(J3V2, "J3_V2_INPUT.json")
REF_TRACE = os.path.join(ROOT, "phase16t", "j3", "out", "j3_revision.json")
EXPECTED_IMAGE_SHA = \
    "5ab70916b9c284dd24a1878afcd7b984928145442623909a275b0035743979e4"
OUT = os.path.join(Y, "audit", "J3_DYNAMIC_BARRIER_LIVENESS_16Y.json")

SYM = "_Z10k_swin_varILi32ELb0EEv9VarParams"

#: the 18 static barrier sites, from phase16x/audit/J3_CFG_BARRIER_ANALYSIS
BARRIERS = [0xAC608, 0xACB4C, 0xAD6F0, 0xAD744, 0xAEB1C, 0xAEE00, 0xAEEA4,
            0xB3A54, 0xB5B8C, 0xB780C, 0xB9384, 0xBA70C, 0xBBE20, 0xBBF24,
            0xBDB5C, 0xC06F0, 0xC0C4C, 0xC1660]
IN_LOOP_BARRIER = 0xBBE20
LOOP_HEADER = 0xBA71C
LOOP_EXIT_TEST = 0xBA730        # s_cbranch_scc1 -> 0xBBF20 : the only exit
SAVEEXEC = 0xBBE2C              # s_and_saveexec_b32 s8, s2
EXECZ_BACKEDGE = 0xBBE30        # s_cbranch_execz -> header
BRANCH_BACKEDGE = 0xBBF1C       # s_branch -> header
ENDPGM = 0xC36D8
#: the scalar register holding s2 at SAVEEXEC and s8 (saved EXEC) -- read by
#: name from the disassembly, never typed.  See operand_of().
WATCHED = sorted(set(BARRIERS + [LOOP_HEADER, LOOP_EXIT_TEST, SAVEEXEC,
                                 EXECZ_BACKEDGE, BRANCH_BACKEDGE, ENDPGM]))
WAVECOUNT = 8

PATHS = ["phase16k_pretest/k3_arena", "phase16j_pre_gta/tools",
         "phase16i_closure/tools", "phase16h_pcrel_fix/tools",
         "phase16e_candidate_e/tools", "phase14e_static/tools",
         "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
         "phase14d11_static/tools", "phase14d11_static",
         "phase14d_static/tools", "phase8_static/tools",
         "phase14d8_static/tools"]
TREE_MODULES = ["emu", "p16j_input", "p14d8_core", "p14e_emu", "p14eh",
                "p16e_rec", "p16h_scratch_probe", "p16j_scratch_isa"]


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def load_revision():
    """Same mechanism as phase16t/j3/t16_j3_run.py: register the frozen
    revision modules in sys.modules BEFORE anything imports them."""
    for name in TREE_MODULES:
        path = os.path.join(REV_TREE, name + ".py")
        if not os.path.exists(path):
            raise SystemExit("revision tree is missing %s" % path)
        import importlib.util
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)


def operand_of(prog, pc, want_idx):
    """Read the operand text of one instruction out of the loaded program, so
    `s2`/`s8` are MEASURED from the binary and not typed from a screenshot.

    16Y RECOVERY REPAIR: this read `ins.get("ops") or ins.get("ops_raw")`, and
    the sliced program's key is `operands`, so the field it fed
    (`operands_measured_from_the_binary`) reported null for every PC while
    looking like a measurement.  The key is now the real one, and a miss
    returns the sentinel "MISSING" rather than None so a reader cannot mistake
    "not found" for "not reported".
    """
    for ins in prog:
        if ins.get("address") == pc:
            return ins.get("mnemonic"), (ins.get("operands")
                                         if ins.get("operands") is not None
                                         else "MISSING")
    return "MISSING", "MISSING"


def new_ev():
    """One wave's event bucket.  A factory, so the three places that build a
    bucket cannot drift apart."""
    return {"barriers": [], "loop_header": 0, "endpgm": None, "steps": 0,
            "bbe20": [], "watched": defaultdict(int),
            #: steps that RETIRED by raising `emu.Halt` (i.e. `s_endpgm`).
            #: `p14eh._run_wg_hw` does `core.step(); steps_done += 1` inside a
            #: try, so a halting step is executed but never counted.  Keeping
            #: the two apart is what makes that off-by-one a stated,
            #: falsifiable fact instead of a fudge factor.
            "halting_steps": 0, "halt_pcs": []}


class Recorder:
    """Per-wave control events, collected from inside a Core subclass.

    Deliberately O(1) per instruction and only four watched PCs do any work,
    because the whole run is ~110k steps and an instrument that perturbs the
    schedule is worse than no instrument.
    """

    def __init__(self):
        self.ev = defaultdict(new_ev)
        self.n_captured = 0
        self.enabled = True
        # 16Y RECOVERY REPAIR.  The inherited version read the wave id off the
        # core as `getattr(self,"wid",0) if hasattr(self,"wid") else
        # getattr(self.w,"id",0)`.  Neither attribute exists: `emu.Core.__init__`
        # consumes `wavebase` to seed v[lane][0] and never stores it, and there
        # is no `self.w`.  The first of those two paths silently collapsed all
        # eight waves into bucket 0 (the T32 "wave always 0" defect); the second
        # raised AttributeError('w') and faulted every wave at tick 2.
        #
        # Waves are therefore identified by CORE IDENTITY and mapped through
        # `res["_cores"]` after the run -- construction order, which is wave
        # order, which is what phase16y/waitcnt/tools/p16y_pc_trace.py already
        # relies on.  Holding the core here keeps its id stable (ids can be
        # recycled once an object dies).
        self.cores = {}
        # 16Y RECOVERY REPAIR.  The mask register was read as `core.sget(2)`.
        # `emu.Core.sget(tok)` takes a register-NAME STRING -- its first
        # statement is `tok = tok.strip()` (revision_16t/emu.py:471) -- so
        # passing the int 2 raised "'int' object has no attribute 'strip'" the
        # first time the loop header was reached, and that exception faulted
        # all eight waves at tick 10525.  The name is now PARSED from the
        # s_and_saveexec_b32 instruction's own operand text, which is what
        # operand_of()/the module docstring always said it would be.
        self.mask_reg = None
        self.mask_reg_unparsed = 0

    @staticmethod
    def mask_register_of(ins):
        """The SOURCE register of `s_and_saveexec_b32 sDst, sSrc`.

        Returns the token string (e.g. "s2") or None.  Read from the
        instruction's operand text -- never typed from a screenshot.
        """
        ops = ins.get("operands") or ""
        toks = [t.strip() for t in ops.split(",") if t.strip()]
        if len(toks) < 2:
            return None
        src = toks[-1]
        ok = len(src) >= 2 and src[0] == "s" and src[1:].isdigit()
        return src if ok else None

    def note(self, core, ins, halting=False):
        if not self.enabled:
            return
        wid = id(core)
        self.cores[wid] = core
        pc = ins.get("address")
        mn = ins.get("mnemonic") or ""
        e = self.ev[wid]
        e["steps"] += 1
        if halting:
            e["halting_steps"] += 1
            e["halt_pcs"].append(pc)
        if pc in BARRIERS:
            e["barriers"].append({"ordinal": len(e["barriers"]) + 1,
                                  "pc": pc, "steps_at": e["steps"],
                                  "exec_before": core.exec_l,
                                  "scc_before": core.scc})
        if pc == LOOP_HEADER:
            e["loop_header"] += 1
        if pc in (LOOP_EXIT_TEST, SAVEEXEC, EXECZ_BACKEDGE, BRANCH_BACKEDGE,
                  ENDPGM):
            e["watched"][str(pc)] += 1
        if pc == SAVEEXEC:
            # EXEC := EXEC & s<src>   (the source operand named in the binary)
            if self.mask_reg is None:
                self.mask_reg = self.mask_register_of(ins)
                if self.mask_reg is None:
                    self.mask_reg_unparsed += 1
            e["bbe20"].append({"at_step": e["steps"],
                               "mask_reg": self.mask_reg,
                               "exec_before": core.exec_l,
                               "s2": (core.sget(self.mask_reg)
                                      if self.mask_reg else None)})
            self.n_captured += 1
        if pc == LOOP_EXIT_TEST:
            if e["bbe20"]:
                e["bbe20"][-1]["scc_at_exit_test"] = core.scc
                e["bbe20"][-1]["exit_taken"] = bool(core.scc)
        if pc == EXECZ_BACKEDGE and e["bbe20"]:
            e["bbe20"][-1]["exec_after_and"] = core.exec_l
            e["bbe20"][-1]["backedge_taken"] = (core.exec_l == 0)
        if pc == ENDPGM and e["endpgm"] is None:
            e["endpgm"] = {"at_step": e["steps"],
                           "barriers_seen": len(e["barriers"])}


def run(rev_tree=REV_TREE, save_trace=False):
    t0 = time.time()
    sys.path.insert(0, os.path.join(ROOT, "phase16p", "j3_v2", "tools"))
    sys.path.insert(0, os.path.join(ROOT, "phase16j_pre_gta", "tools"))
    sys.path.insert(0, J3V2)
    sys.path.insert(0, os.path.join(ROOT, "phase16t", "j3"))
    for p in PATHS:
        pp = os.path.join(ROOT, p)
        if pp not in sys.path:
            sys.path.insert(0, pp)
    load_revision()

    import p16p_j3cfg as J3                                        # noqa
    import r2_tracer as RT                                         # noqa
    import p16j_input as IN                                        # noqa

    rec = Recorder()

    vals, _meta = J3.load_authentic_cell()
    doc = json.load(open(META, encoding="utf-8"))
    blob = open(BIN, "rb").read()
    if hashlib.sha256(blob).hexdigest() != doc["bin_sha256"]:
        raise SystemExit("REFUSING: the input bin does not hash to its "
                         "declared value")
    schema = RT.RegionSchema(doc["regions"])
    images = {r["name"]: blob[r["payload_offset_in_bin"]:
                             r["payload_offset_in_bin"]
                             + r["allocation_extent"]]
              for r in doc["regions"]}
    fill = RT.material_fill(schema, images)
    trace = RT.Trace(schema, detail_cap=1)

    def core_cls():
        import p16h_global_gate as G
        return G.GateCore

    base = RT.tracing_core_class(core_cls(), trace)

    # ---- the liveness instrument: a subclass, not an edit ---------------
    prog_ref = {}

    class LivenessCore(base):
        def step(self):
            pc = self.pc
            ins = None
            prog = self._prog_ref if hasattr(self, "_prog_ref") else None
            if prog:
                prog_ref["p"] = prog
                if 0 <= pc < len(prog):
                    ins = prog[pc]
            # `s_endpgm` retires by RAISING `emu.Halt` (revision_16t/emu.py:829).
            # If the hapter is not recorded on that path the terminating
            # instruction is missing from the trace -- which is exactly how the
            # inherited instrument came to report endpgm_recorded=False on a run
            # that ended naturally.  The step is recorded, and labelled.
            try:
                r = super().step()
            except BaseException:
                if ins is not None:
                    rec.note(self, ins, halting=True)
                raise
            if ins is not None:
                rec.note(self, ins)
            return r

    # 16Y RECOVERY REPAIR.  This was `lambda *a, **k: LivenessCore(*a, **k)`.
    # `p16p_trace.run_j3` does `G.p14eh.HWCore = core_cls` and `run_workgroup_hw`
    # then reads CLASS attributes off it (`HWCore.agg_lds`, `HWCore.registry`,
    # `HWCore.alloc`).  A lambda is a function, so those reads die with
    # "'function' object has no attribute 'agg_lds'" and the trace never ran.
    # Every other runner in this project passes the class itself; calling the
    # class is what `LivenessCore(*a, **k)` did anyway.
    assert isinstance(LivenessCore, type), \
        "the core class handed to run_j3 must be a CLASS, not a callable"
    tc = LivenessCore
    regs = [(r["base"], r["name"], r["allocation_extent"])
            for r in doc["regions"]]
    res, ggate, _hw = RT.run_j3_once(vals, regs, traced_fill_wrap(fill, trace),
                                     core_cls=tc)

    # ---- core identity -> wave index, from the emulator's own data --------
    # `res["_cores"]` preserves construction order, which is wave order.  The
    # mapping is asserted to be a bijection over all eight cores: if any core
    # never reported, or two cores collided, the per-wave columns below would
    # be fiction and this must not be allowed to look like a result.
    cores = res.get("_cores") or []
    order = [id(c) for c in cores]
    mapped = [k for k in order if k in rec.cores]
    problems = []
    if len(cores) != WAVECOUNT:
        problems.append("expected %d cores, got %d" % (WAVECOUNT, len(cores)))
    if len(set(order)) != len(order):
        problems.append("core identity is not unique -- ids were recycled")
    if len(mapped) != len(order):
        problems.append("cores that never reported to the instrument: %d of %d"
                        % (len(order) - len(mapped), len(order)))
    if len(rec.cores) != len(order):
        problems.append("the instrument saw %d distinct cores, the emulator "
                        "built %d" % (len(rec.cores), len(order)))
    if problems:
        raise SystemExit("REFUSING: the per-wave mapping is not a bijection "
                         "over the eight waves -- %s" % "; ".join(problems))
    by_id = dict(rec.ev)
    rec.ev = defaultdict(new_ev,
                         {w: by_id[k] for w, k in enumerate(order)})
    rec.wave_mapping = {"method": "core identity via res['_cores'] construction "
                                  "order (wave order)",
                        "n_cores": len(order), "bijective": True}

    # ---- identity of the RESULT, not of the instrument -------------------
    mem = cores[0].mem if cores else {}
    out = bytearray()
    for r in doc["regions"]:
        base_va = r["base"]
        n = r["allocation_extent"]
        for i in range(n):
            v = mem.get(base_va + i)
            out.append((IN.pattern_at(i) if v is None else v) & 0xFF)
    image_sha = hashlib.sha256(bytes(out)).hexdigest()
    prog = prog_ref.get("p") or []
    operands = {hex(pc): operand_of(prog, pc, None)
                for pc in (SAVEEXEC, LOOP_EXIT_TEST, EXECZ_BACKEDGE)}
    return (rec, res, image_sha, operands, trace, time.time() - t0, prog,
            nonperturbation_facts(res, ggate, trace))


def nonperturbation_facts(res, ggate, trace):
    """The phase16t/j3/t16_j3_run.py observables, recomputed by the same
    formulas, so the instrumented run can be compared against the FROZEN
    artifact on every axis the brief S20 names -- not only ticks and image."""
    ts = trace.summary()
    cf = hashlib.sha256()
    for pc, d in sorted(ts["by_pc"].items(), key=lambda kv: str(kv[0])):
        cf.update(("%s=%d;" % (pc, d["n"])).encode())
    dig = RT_module().image_store_digest(res)
    return {
        "ticks": res.get("ticks"),
        "outcome": str(res.get("outcome")),
        "natural_end": res.get("natural_end"),
        "faults": res.get("faults"),
        "control_flow_signature": cf.hexdigest()[:32],
        "store_digest": {"single_pass": dig[0], "n_addrs": dig[1]},
        "store_addresses_sha256": hashlib.sha256(
            ",".join(str(x) for x in dig[2]).encode()).hexdigest(),
        "by_pc_n": len(ts["by_pc"]),
        "gate": RT_module().gate_counts(ggate),
    }


def RT_module():
    import r2_tracer
    return r2_tracer


def traced_fill_wrap(fill, trace):
    """Same wrapper t16_j3_run.py uses."""
    import r2_tracer as RT

    def f(mem):
        return RT.wrap_mem(fill(mem), trace)
    return f


# ------------------------------------------------------------------- verdict
def analyse(rec, res, image_sha, operands, wall, facts):
    ref = json.load(open(REF_TRACE, encoding="utf-8"))
    # 16Y RECOVERY REPAIR.  The inherited version compared the recording against
    # THIS RUN's own model output (`res["per_wave"]`).  When the instrument
    # faulted every wave at tick 2, both sides were 0 and G5/G6 passed on 0==0 --
    # a vacuous green.  The comparison is therefore against the FROZEN 16T
    # artifact, which is an independent object on disk and does not move when
    # this run is broken.
    ref_pw = {w["wave"]: w for w in ref["per_wave"]}
    ev = rec.ev
    waves = []
    for w in range(WAVECOUNT):
        e = ev.get(w) or new_ev()
        waves.append({
            "wave": w,
            "n_barriers_recorded": len(e["barriers"]),
            "n_barriers_frozen_16t": ref_pw[w]["barriers"],
            "n_barriers_reported_by_model": res["per_wave"][w]["barriers"],
            "barrier_pc_sequence": [b["pc"] for b in e["barriers"]],
            "barrier_ordinals_match_frozen_16t":
                len(e["barriers"]) == ref_pw[w]["barriers"],
            "barrier_ordinals_match_model":
                len(e["barriers"]) == res["per_wave"][w]["barriers"],
            "loop_header_entries": e["loop_header"],
            "in_loop_barrier_executions":
                sum(1 for b in e["barriers"] if b["pc"] == IN_LOOP_BARRIER),
            "in_loop_barrier_details": e["bbe20"],
            "endpgm_recorded": e["endpgm"],
            "state": res["per_wave"][w]["state"],
            "frozen_16t_state": ref_pw[w]["state"],
            "model_steps": res["per_wave"][w]["steps"],
            "frozen_16t_steps": ref_pw[w]["steps"],
            "instrument_steps": e["steps"],
            "halting_steps": e["halting_steps"],
            "halt_pcs": [hex(x) for x in e["halt_pcs"]],
            # the emulator's counter excludes the halting step (see new_ev);
            # comparing the same quantity to the same quantity is the point.
            "instrument_steps_counted": e["steps"] - e["halting_steps"],
            "steps_agree":
                (e["steps"] - e["halting_steps"]) == ref_pw[w]["steps"],
            "halt_is_endpgm": (e["halting_steps"] == 1
                               and e["halt_pcs"] == [ENDPGM]),
        })

    seqs = [tuple(x["barrier_pc_sequence"]) for x in waves]
    same_seq = all(s == seqs[0] for s in seqs)
    counts = [x["n_barriers_recorded"] for x in waves]
    hdrs = [x["loop_header_entries"] for x in waves]
    total_recorded_steps = sum(x["instrument_steps"] for x in waves)
    reached = any(IN_LOOP_BARRIER in s for s in seqs)
    all_reached = all(IN_LOOP_BARRIER in s for s in seqs)
    equal_iters = len(set(hdrs)) == 1

    gates = {
        "G1_image_identity": (image_sha == EXPECTED_IMAGE_SHA,
                              "the instrumented run produced the frozen "
                              "output: %s" % image_sha[:16]),
        "G2_ticks_match_reference": (res["ticks"] == ref["ticks"],
                                     "%s vs %s" % (res["ticks"],
                                                   ref["ticks"])),
        "G3_outcome_natural_end": (bool(res.get("natural_end")),
                                   str(res.get("outcome"))),
        "G4_no_faults": (not res.get("faults"), str(res.get("faults"))[:120]),
        "G5_barrier_count_agrees_with_frozen_16t":
            (all(x["barrier_ordinals_match_frozen_16t"] for x in waves),
             "recorded=%s frozen_16t=%s" % (counts,
                                            [x["n_barriers_frozen_16t"]
                                             for x in waves])),
        "G5b_barrier_count_agrees_with_this_run":
            (all(x["barrier_ordinals_match_model"] for x in waves),
             "recorded=%s this_run=%s" % (counts,
                                          [x["n_barriers_reported_by_model"]
                                           for x in waves])),
        "G6_instrument_step_count_agrees":
            (all(x["steps_agree"] for x in waves),
             "instrument_counted=%s frozen_16t=%s (halting steps excluded, "
             "see G6b)"
             % ([x["instrument_steps_counted"] for x in waves],
                [x["frozen_16t_steps"] for x in waves])),
        # The off-by-one is a CLAIM, so it is gated: every wave must retire by
        # raising exactly one Halt, and it must be s_endpgm.  If that is not so,
        # G6 is comparing the wrong pair of numbers and must not be trusted.
        "G6b_the_halting_step_is_exactly_one_s_endpgm_per_wave":
            (all(x["halt_is_endpgm"] for x in waves),
             "halting_steps=%s halt_pcs=%s"
             % ([x["halting_steps"] for x in waves],
                [x["halt_pcs"] for x in waves])),
        # A run in which the instrument reported nothing agrees with itself.
        # This gate makes that shape a FAILURE rather than a green.
        "G12_the_recording_is_not_vacuous":
            (all(x["n_barriers_recorded"] > 0 for x in waves)
             and all(x["loop_header_entries"] > 0 for x in waves)
             and all(x["endpgm_recorded"] for x in waves)
             and total_recorded_steps > 0,
             "barriers=%s loop_header_entries=%s endpgm_recorded=%s steps=%s"
             % (counts, hdrs,
                [bool(x["endpgm_recorded"]) for x in waves],
                total_recorded_steps)),
        "G7_all_waves_same_barrier_sequence":
            (same_seq, "8 sequences compared; identical=%s" % same_seq),
        "G8_in_loop_barrier_reachability_resolved":
            (reached or not reached,
             "reached=%s; reached_by_every_wave=%s" % (reached, all_reached)),
        "G9_equal_iteration_count_across_waves":
            (equal_iters and all_reached,
             "loop_header_entries=%s" % hdrs),
        "G10_no_wave_ends_while_a_peer_awaits_a_later_barrier":
            (endpgm_consistent(waves), ""),
        "G11_no_extra_barrier":
            (len(set(counts)) == 1, "distinct counts=%d" % len(set(counts))),
    }
    # ---- S20: non-perturbation on every named axis, not just two ----------
    # The brief names natural end, ticks, store digest, store address set,
    # barrier epoch sequence and memory-event counts.  Each is an independent
    # observable with its own formula, so a trace that perturbed only the
    # memory path (say) cannot hide behind a matching image.
    s20 = {
        "natural_end": ref.get("natural_end"),
        "ticks": ref.get("ticks"),
        "control_flow_signature": ref.get("control_flow_signature"),
        "store_digest": ref.get("store_digest"),
        "store_addresses_sha256": ref.get("store_addresses_sha256"),
        "barrier_epochs": ref.get("barrier_epochs"),
        "by_pc_n": ref.get("by_pc_n"),
        "gate": ref.get("gate"),
    }
    got = {
        "natural_end": res.get("natural_end"),
        "ticks": res.get("ticks"),
        "control_flow_signature": facts["control_flow_signature"],
        "store_digest": facts["store_digest"],
        "store_addresses_sha256": facts["store_addresses_sha256"],
        "barrier_epochs": res.get("barrier_epochs"),
        "by_pc_n": facts["by_pc_n"],
        "gate": facts["gate"],
    }
    for k in sorted(s20):
        same = (json.dumps(s20[k], sort_keys=True)
                == json.dumps(got[k], sort_keys=True))
        gates["N_%s_matches_frozen_16t" % k] = (
            same, "frozen=%s this=%s" % (json.dumps(s20[k])[:80],
                                         json.dumps(got[k])[:80]))
    gates["G10_no_wave_ends_while_a_peer_awaits_a_later_barrier"] = (
        (endpgm_consistent(waves), explain_endpgm(waves, seqs)))
    failed = [k for k, (ok, _) in gates.items() if not ok]
    verdict = ("PASS" if not failed and same_seq and all_reached and
               equal_iters else "FAIL")
    answer = ("B" if (reached and all_reached and equal_iters and same_seq)
              else "A" if not reached and not any(
                  x["in_loop_barrier_executions"] for x in waves)
              else "UNRESOLVED")
    return {
        "schema": "phase16y-dynamic-barrier-liveness/1",
        "phase": "16Y",
        "brief": "S14 dynamic barrier trace, S15 release gate",
        "host_only": True,
        "gpu_execution_performed": False,
        "kernel_launch_count": 0,
        "wall_s": round(wall, 1),
        "semantic_neutrality": "asserted by G1/G2/G6 -- the instrument must "
                               "reproduce the frozen output, ticks and "
                               "per-wave step counts exactly",
        "s14_answer": {
            "choice": answer,
            "meaning": {
                "A": "0xBBE20 is NOT dynamically reached by the frozen J3 "
                     "input",
                "B": "0xBBE20 IS reached and all 8 waves execute it the same "
                     "number of times in the same ordinal sequence",
                "UNRESOLVED": "neither could be proven -- NO PHYSICAL LAUNCH",
            }[answer],
        },
        "in_loop_barrier": {
            "pc": hex(IN_LOOP_BARRIER),
            "statically_inside_a_loop_per_16X": True,
            "dynamically_reached": reached,
            "reached_by_every_wave": all_reached,
            "executions_per_wave": [x["in_loop_barrier_executions"]
                                    for x in waves],
            "loop_header_entries_per_wave": hdrs,
            "operands_measured_from_the_binary": {
                k: {"mnemonic": v[0], "ops": v[1]} for k, v in operands.items()
            },
        },
        "barrier_epoch_list_from_model": res.get("barrier_epochs"),
        "barrier_epoch_list_decoded_as_pcs":
            ["0x%X" % x for x in (res.get("barrier_epochs") or [])],
        "identical_to_16T_reference_epochs":
            res.get("barrier_epochs") == ref.get("barrier_epochs"),
        "per_wave": waves,
        "gates": {k: {"pass": bool(v[0]), "evidence": v[1]}
                  for k, v in gates.items()},
        "gates_failed": failed,
        "verdict": verdict,
    }


def endpgm_consistent(waves):
    """No wave may retire before a barrier another wave later reaches."""
    n = max((len(x["barrier_pc_sequence"]) for x in waves), default=0)
    return all(len(x["barrier_pc_sequence"]) == n for x in waves)


def explain_endpgm(waves, seqs):
    n = max((len(s) for s in seqs), default=0)
    short = [x["wave"] for x in waves if len(x["barrier_pc_sequence"]) != n]
    return ("all 8 waves recorded %d barriers; short waves=%s"
            % (n, short or "none"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    rec, res, image_sha, operands, _trace, wall, _prog, facts = run()
    doc = analyse(rec, res, image_sha, operands, wall, facts)
    doc["nonperturbation_observables"] = facts
    doc["per_wave_mapping"] = getattr(rec, "wave_mapping", None)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    print("wrote %s" % OUT)
    print("wall %.1f s   ticks %s   image %s" % (wall, res["ticks"],
                                                 image_sha[:16]))
    for k, v in sorted(doc["gates"].items()):
        print("  %-56s %s" % (k, "PASS" if v["pass"] else "FAIL"))
        if not v["pass"]:
            print("       %s" % v["evidence"])
    print("S14 answer: %s -- %s" % (doc["s14_answer"]["choice"],
                                    doc["s14_answer"]["meaning"]))
    print("VERDICT: %s" % doc["verdict"])
    return 0 if doc["verdict"] == "PASS" else 1


# --------------------------------------------------------- checker controls
def self_test():
    """16Y RECOVERY REPAIR (brief S24, S26).

    The inherited suite had two defects, both recorded in
    phase16y/recovery/QWEN_PROGRESS_RECONCILIATION.md:

    1. It did not test this file's checker.  It re-implemented a condensed
       version of `analyse()`'s decision rule inside `check()` and tested THAT.
       The suite could pass while `analyse()` was wrong, and it is exactly the
       producer-grades-its-own-homework shape brief S26 forbids.

    2. Its last case, "nobody reaches 0xBBE20 (answer A is internally
       consistent)", was self-contradictory: it passed must_fail=False, while
       the `check()` it called always ANDs in `reached`. So the control asserted
       an expectation its own helper could not express, and the suite FAILED
       on its own contradiction.

    Rather than maintain a second, drifting copy of the decision logic, this
    now delegates to the canonical control suite in the INDEPENDENT verifier
    `p16y_barrier_verify.py`, which consumes the serialized trace only.  The
    tracer shares no conclusion logic with it, which is the point.
    """
    import subprocess
    verifier = os.path.join(HERE, "p16y_barrier_verify.py")
    print("delegating to the independent verifier's control suite:")
    print("  %s" % verifier)
    rc = subprocess.call([sys.executable, verifier, "--controls"])
    print("INDEPENDENT CONTROL VERDICT: %s"
          % ("PASS" if rc == 0 else "FAIL"))
    return rc


def _self_test_superseded():
    """The inherited, defective suite, kept verbatim for the record.  It is
    NOT called; phase16y/recovery/history/PART_II_SELFTEST_AS_INHERITED.txt
    holds its output."""
    import copy

    def build(seqs, hdrs=None):
        waves = []
        for w, s in enumerate(seqs):
            waves.append({"wave": w, "barrier_pc_sequence": list(s),
                          "n_barriers_recorded": len(s),
                          "loop_header_entries": (hdrs or [10] * len(seqs))[w],
                          "in_loop_barrier_executions":
                              sum(1 for p in s if p == IN_LOOP_BARRIER)})
        return waves

    base_seq = [0xAD744, 0xB3A54, 0xB5B8C, 0xB780C, 0xB9384, 0xBA70C,
                0xBBE20, 0xBBF24, 0xBDB5C, 0xC06F0]
    good = build([base_seq] * 8)
    cases = []

    def check(label, waves, must_fail):
        seqs = [tuple(x["barrier_pc_sequence"]) for x in waves]
        same = all(s == seqs[0] for s in seqs)
        hdrs = [x["loop_header_entries"] for x in waves]
        counts = [x["n_barriers_recorded"] for x in waves]
        reached = all(IN_LOOP_BARRIER in s for s in seqs)
        ok = (same and len(set(counts)) == 1 and len(set(hdrs)) == 1
              and reached and endpgm_consistent(waves))
        detected = not ok
        cases.append({"case": label, "checker_says_pass": ok,
                      "expected": "fail" if must_fail else "pass",
                      "detected": detected == must_fail if must_fail
                      else ok,
                      "verdict": "PASS" if (detected == must_fail) else "FAIL"})

    check("pristine: 8 identical 10-barrier sequences", good, False)
    w = copy.deepcopy(good)
    w[7]["barrier_pc_sequence"] = w[7]["barrier_pc_sequence"][:-1]
    w[7]["n_barriers_recorded"] -= 1
    check("wave 7 missing one barrier event", w, True)
    w = copy.deepcopy(good)
    w[3]["barrier_pc_sequence"] = (w[3]["barrier_pc_sequence"][:7]
                                   + [0xBBE20]
                                   + w[3]["barrier_pc_sequence"][7:])
    w[3]["n_barriers_recorded"] += 1
    check("wave 3 given one extra barrier event", w, True)
    w = copy.deepcopy(good)
    w[5]["loop_header_entries"] = 11
    check("wave 5 iterates the in-loop barrier once more", w, True)
    w = copy.deepcopy(good)
    w[0]["barrier_pc_sequence"] = [p for p in w[0]["barrier_pc_sequence"]
                                   if p != IN_LOOP_BARRIER]
    w[0]["n_barriers_recorded"] -= 1
    check("wave 0 never reaches 0xBBE20", w, True)
    w = copy.deepcopy(good)
    w[2]["barrier_pc_sequence"] = list(reversed(w[2]["barrier_pc_sequence"]))
    check("wave 2 reaches the same barriers in a different order", w, True)
    w = copy.deepcopy(good)
    for x in w:
        x["barrier_pc_sequence"] = [p for p in x["barrier_pc_sequence"]
                                    if p != IN_LOOP_BARRIER]
        x["in_loop_barrier_executions"] = 0
        x["n_barriers_recorded"] -= 1
    check("nobody reaches 0xBBE20 (answer A is internally consistent)", w,
          False)
    print("\nchecker negative controls (S16):")
    for c in cases:
        print("  %-58s %s" % (c["case"], c["verdict"]))
    bad = [c for c in cases if c["verdict"] != "PASS"]
    print("cases=%d failed=%d" % (len(cases), len(bad)))
    with open(os.path.join(Y, "audit",
                           "J3_DYNAMIC_BARRIER_CHECKER_CONTROLS_16Y.json"),
              "w", encoding="utf-8") as f:
        json.dump({"schema": "phase16y-barrier-checker-controls/1",
                   "note": "S16: the HOST trace is mutated here; Candidate F "
                           "is not.  A checker that rejects nothing is not a "
                           "checker.",
                   "cases": cases, "n_failed": len(bad),
                   "verdict": "PASS" if not bad else "FAIL"}, f, indent=1)
        f.write("\n")
    print("CHECKER CONTROL VERDICT: %s" % ("PASS" if not bad else "FAIL"))
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
