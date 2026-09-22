#!/usr/bin/env python3
"""Phase 16Y / WAITCNT / STEP 1 -- persist the DYNAMICALLY EXECUTED PC set.

Host-only.  No GPU, no HIP, no ROCm runtime import, no harness executable, no
`*launch*`/`*arm*`/`*go_no_go*` binary.  Nothing here touches a device.

WHAT THIS IS
    `phase16t/j3/t16_j3_run.py`'s flow, unchanged in every respect that
    affects what gets executed: same frozen `revision_16t` semantic tree
    imported by path, same `phase16r/j3_v2/J3_V2_INPUT.bin` read from disk and
    re-checked against its declared sha256, same RegionSchema / material_fill /
    Trace / run_j3_once, same 8 waves and round cap.

WHAT THIS ADDS
    One subclass of the already-tracing core class, installed in THIS process
    only, wrapping `step()` to record the program index of every instruction
    the wave retires.  The frozen tree under `phase16t/semantic/revision_16t/`
    is NOT edited.

WHY THE BRIEF'S `trace_pc` COULD NOT BE USED
    The brief states the emulator exposes `Core.trace_pc` as `List[int]` at
    `phase14d8_static/tools/p14d8_core.py:82`, appended per instruction at
    `:357`.  That attribute does not exist: a repository-wide search for
    `trace_pc` over `*.py` returns zero matches, and those two line numbers
    hold the tail of `expected_layout_str()` and the body of `_gst()`.  The
    recorder below substitutes for it, and is asserted against the frozen
    artifact's own per-wave `steps`, which is the check the brief asked for
    regardless of which mechanism produced the list.

    A second brief detail also does not hold and is corrected here: cores do
    NOT carry `self.wavebase` (`emu.Core.__init__` consumes the kwarg to seed
    `v[lane][0]` and never stores it), so waves are identified by core
    IDENTITY and mapped through `res["_cores"]`, whose order is construction
    order, which is wave order.

NON-PERTURBATION IS ASSERTED, NOT ASSUMED
    After the run, ticks, outcome, natural_end, capped, diverged,
    `barrier_epochs` and per-wave (state, steps, barriers, fault) are compared
    against `phase16t/j3/out/j3_revision.json`.  Any mismatch is a hard exit:
    a PC trace that changed the execution it measures is worthless.

Usage:
    python phase16y/waitcnt/tools/p16y_pc_trace.py ^
        --out phase16y/waitcnt/out/j3_executed_pcs.json
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WC = os.path.dirname(HERE)                    # phase16y/waitcnt
ROOT = os.path.dirname(os.path.dirname(WC))   # ...<PROJECT_ROOT>

T16 = os.path.join(ROOT, "phase16t")
REV_TREE = os.path.join(T16, "semantic", "revision_16t")
FROZEN_J3_JSON = os.path.join(T16, "j3", "out", "j3_revision.json")

TREE_MODULES = ["emu", "p16j_input", "p14d8_core", "p14e_emu", "p14eh",
                "p16e_rec", "p16h_scratch_probe", "p16j_scratch_isa"]
EDITED = ("emu", "p14d8_core")

#: identical to t16_j3_run.py's PATHS -- the composed emulator resolves most
#: modules from the live tree; only the edited ones come from the revision.
PATHS = ["phase16k_pretest/k3_arena", "phase16j_pre_gta/tools",
         "phase16i_closure/tools", "phase16h_pcrel_fix/tools",
         "phase16e_candidate_e/tools", "phase14e_static/tools",
         "phase14eh_tools", "phase14eg_tools", "phase14e_forensics/tools",
         "phase14d11_static/tools", "phase14d11_static",
         "phase14d_static/tools", "phase8_static/tools",
         "phase14d8_static/tools"]

J3V2 = os.path.join(ROOT, "phase16r", "j3_v2")
BIN = os.path.join(J3V2, "J3_V2_INPUT.bin")
META = os.path.join(J3V2, "J3_V2_INPUT.json")

CO = os.path.join(ROOT, "phase16h_candidate_f",
                  "gfx1030_dlssnr_candidate_f.co")
CO_SHA = "47b5d1d11041b034ac30eebac090ee922f415d8f08a0111e69641d7e0557524b"


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def load_revision(revdir):
    for name in TREE_MODULES:
        path = os.path.join(revdir, name + ".py")
        if not os.path.exists(path):
            raise SystemExit("revision tree is missing %s" % path)
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    # ---- frozen artifact identity first, before any work ------------------
    got = sha256_file(CO)
    if got != CO_SHA:
        raise SystemExit("REFUSING: candidate F .co sha256 is %s, brief "
                         "declares %s" % (got, CO_SHA))
    print("candidate .co sha256 verified:", got)

    t0 = time.time()
    sys.path.insert(0, HERE)
    sys.path.insert(0, J3V2)
    sys.path.insert(0, os.path.join(ROOT, "phase16p", "j3_v2", "tools"))
    sys.path.insert(0, os.path.join(ROOT, "phase16j_pre_gta", "tools"))
    for p in PATHS:
        pp = os.path.join(ROOT, p)
        if pp not in sys.path:
            sys.path.insert(0, pp)
    load_revision(REV_TREE)

    import p16j_input as IN                                        # noqa: E402
    import p16p_j3cfg as J3                                        # noqa: E402
    import r2_tracer as RT                                         # noqa: E402

    loaded = {}
    for mod in TREE_MODULES:
        m = sys.modules.get(mod)
        f = getattr(m, "__file__", None) if m else None
        loaded[mod] = {
            "file": os.path.relpath(f, ROOT).replace("\\", "/") if f else None,
            "sha256": sha256_file(f) if f and os.path.exists(f) else None,
            "from_revision_tree": bool(f and os.path.abspath(f).startswith(
                os.path.abspath(REV_TREE))),
        }
    if not all(loaded[m]["from_revision_tree"] for m in EDITED):
        raise SystemExit("PROVENANCE FAILURE: %s" % json.dumps(loaded, indent=1))

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

    tc = RT.tracing_core_class(core_cls(), trace)

    # ---- the recorder -----------------------------------------------------
    # One list per core INSTANCE.  Cores are created in wave order and
    # `res["_cores"]` preserves that order, so instance -> wave is resolved
    # after the run from data the emulator itself produces.
    # 16Y RECOVERY REPAIR.  The inherited recorder produced exactly one more
    # entry per wave than the emulator's own `steps_done`, and the script
    # refused on that disagreement -- correctly, and that refusal is the
    # background "failed" shell in the interrupted session.  The cause is
    # measured, not guessed: `op_s_endpgm` retires by RAISING `emu.Halt`
    # (revision_16t/emu.py:829), and the scheduler runs the step as
    #
    #     try:  core.step(); w["steps_done"] += 1
    #
    # so a halting step is executed but never counted.  One per wave.
    #
    # The step is still RECORDED here (it really executed, and the waitcnt
    # audit wants every executed instruction), but the halt is counted
    # separately so the assertion below can be exact instead of fudged:
    #     len(pcs) == declared + halts,  halts == 1,  and the extra PC is s_endpgm.
    class RecordingCore(tc):
        def step(self):
            if not hasattr(self, "_p16y_pcs"):
                self._p16y_pcs = []
                self._p16y_halts = 0
            self._p16y_pcs.append(self.pc)
            try:
                return super().step()
            except BaseException:
                self._p16y_halts += 1
                raise

    RecordingCore.__name__ = "Recording" + tc.__name__
    RecordingCore.__qualname__ = RecordingCore.__name__

    def traced_fill(mem):
        return RT.wrap_mem(fill(mem), trace)

    regs = [(r["base"], r["name"], r["allocation_extent"])
            for r in doc["regions"]]
    res, ggate, _hw = RT.run_j3_once(vals, regs, traced_fill,
                                     core_cls=RecordingCore)

    # ---- the executed program, exactly as the emulator sliced it ----------
    import p16h_global_gate as G
    prog, _rows, _i = G.PE.slice_program(os.path.join(ROOT, J3.CANDIDATE_DIS),
                                         J3.SYM)

    cores = res.get("_cores") or []
    if len(cores) != 8:
        raise SystemExit("REFUSING: expected 8 cores, got %d" % len(cores))
    per_wave = {w["wave"]: w for w in res["per_wave"]}
    traces = {}
    for i, c in enumerate(cores):
        pcs = getattr(c, "_p16y_pcs", None)
        if pcs is None:
            raise SystemExit("REFUSING: core for wave %d recorded nothing "
                             "(instrument never installed)" % i)
        traces[i] = pcs
    if not traces or sum(len(v) for v in traces.values()) == 0:
        raise SystemExit("REFUSING: the PC trace came out EMPTY -- the "
                         "instrument did not take effect")

    # ---- sanity: the trace length must equal the emulator's own counter ---
    problems = []
    halt_report = {}
    for w, pcs in traces.items():
        declared = per_wave[w]["steps"]
        halts = getattr(cores[w], "_p16y_halts", None)
        if halts is None:
            problems.append({"wave": w, "error": "halt counter absent -- the "
                             "instrument did not install"})
            continue
        last_mnem = prog[pcs[-1]].get("mnemonic") if pcs else None
        halt_report[w] = {"emulator_steps": declared,
                          "trace_len": len(pcs),
                          "halting_steps": halts,
                          "last_pc": pcs[-1] if pcs else None,
                          "last_mnemonic": last_mnem}
        if len(pcs) != declared + halts:
            problems.append({"wave": w, "emulator_steps": declared,
                             "trace_len": len(pcs), "halting_steps": halts,
                             "why": "trace_len must equal emulator steps plus "
                                    "the steps that retired by raising Halt"})
        if halts != 1:
            problems.append({"wave": w, "halting_steps": halts,
                             "why": "each wave must retire by raising Halt "
                                    "exactly once"})
        if last_mnem is None or not str(last_mnem).startswith("s_endpgm"):
            problems.append({"wave": w, "last_mnemonic": last_mnem,
                             "why": "the uncounted step must be the "
                                    "terminating s_endpgm"})
    if problems:
        raise SystemExit("REFUSING: recorded trace length disagrees with the "
                         "emulator's own steps_done: %s"
                         % json.dumps(problems))
    total = sum(len(v) for v in traces.values())

    # ---- non-perturbation assertion against the frozen artifact ----------
    frozen = json.load(open(FROZEN_J3_JSON, encoding="utf-8"))
    keys = ("wave", "state", "steps", "barriers", "fault")
    comparisons = {
        "ticks": (frozen["ticks"], res["ticks"]),
        "outcome": (frozen["outcome"], str(res["outcome"])),
        "natural_end": (frozen["natural_end"], res.get("natural_end")),
        "capped": (frozen["capped"], res.get("capped")),
        "diverged": (frozen["diverged"], res.get("diverged")),
        "barrier_epochs": (frozen["barrier_epochs"],
                           res.get("barrier_epochs")),
        "per_wave": ([{k: w[k] for k in keys} for w in frozen["per_wave"]],
                     [{k: w[k] for k in keys} for w in res["per_wave"]]),
    }
    for name, (exp, act) in comparisons.items():
        if json.dumps(exp, sort_keys=True) != json.dumps(act, sort_keys=True):
            problems.append({"field": name, "frozen": exp, "this": act})
    if problems:
        raise SystemExit("REFUSING: the instrumented run is NOT the frozen J3 "
                         "run -- %s" % json.dumps(problems)[:4000])
    print("non-perturbation OK: instrumented run reproduces the frozen J3 "
          "run exactly (ticks=%s outcome=%s, %d barrier epochs equal)"
          % (res["ticks"], comparisons["outcome"][1],
             len(res["barrier_epochs"])))

    # ---- cross-check the two independent views of executed PCs ------------
    # The memory tracer records a pc for every global access, on a path the
    # recorder does not touch.  Its PC keys must be a SUBSET of the executed
    # addrs the recorder saw -- a PC in by_pc that the recorder never stepped
    # would mean one of the two instruments is lying.
    tsum = trace.summary()
    acc_pcs = {int(k) for k in tsum["by_pc"] if k.isdigit()}
    exec_addrs = set()
    for w, pcs in traces.items():
        exec_addrs.update(prog[i]["address"] for i in pcs
                          if prog[i].get("address") is not None)
    orphans = sorted(acc_pcs - exec_addrs)
    print("executed addrs=%d ; global-access tracer pcs=%d ; tracer pcs not "
          "in executed set=%d" % (len(exec_addrs), len(acc_pcs), len(orphans)))
    if orphans:
        print("  first orphans:", [hex(x) for x in orphans[:10]])

    # ---- persist ----------------------------------------------------------
    ins_table = [{"n": n, "addr": ins.get("address"),
                  "mnem": ins.get("mnemonic"), "ops": ins.get("operands"),
                  "text": ins.get("text")} for n, ins in enumerate(prog)]
    out = {
        "schema": "phase16y-waitcnt-executed-pcs/1",
        "host_only": True, "gpu_execution_performed": False,
        "ta_launched": False, "currently_armed": False,
        "candidate_sha256": got,
        "input_sha256": hashlib.sha256(blob).hexdigest(),
        "sym": J3.SYM, "waves": 8,
        "ticks": res["ticks"], "outcome": str(res["outcome"]),
        "natural_end": res.get("natural_end"),
        "barrier_epochs": res.get("barrier_epochs"),
        "barrier_epoch_hex": ["0x%X" % x for x in res["barrier_epochs"]],
        "modules_loaded": loaded,
        "non_perturbation_verified_against": os.path.relpath(
            FROZEN_J3_JSON, ROOT).replace("\\", "/"),
        "per_wave_steps": {str(w): per_wave[w]["steps"] for w in traces},
        "per_wave_barriers": {str(w): per_wave[w]["barriers"] for w in traces},
        # the off-by-one, stated as measured fact rather than absorbed
        "per_wave_halting_steps": {str(w): halt_report[w]["halting_steps"]
                                   for w in sorted(halt_report)},
        "per_wave_trace_len": {str(w): halt_report[w]["trace_len"]
                               for w in sorted(halt_report)},
        "abort_reason": ("s_endpgm retires by raising emu.Halt, and "
                         "p14eh._run_wg_hw increments steps_done after "
                         "core.step() returns, so a halting step executes but "
                         "is not counted.  trace_len == steps + 1 per wave."),
        "n_executed_total": total,
        "n_distinct_executed_addrs": len(exec_addrs),
        "tracer_pc_orphans": [hex(x) for x in orphans],
        # The emulator's OWN record of which PCs performed a global access, and
        # whether it was a store.  The waitcnt audit cross-checks its own
        # memory-op classification against this, so a parser that mis-reads an
        # operand cannot quietly shrink the set of producers it audits.
        "tracer_by_pc": {str(k): v for k, v in tsum["by_pc"].items()},
        "tracer_totals": {k: tsum[k] for k in
                          ("n_read_ops", "n_write_ops", "n_read_bytes",
                           "n_write_bytes", "n_unmapped_read",
                           "n_unmapped_write", "counts_exact")},
        "instruction_table_len": len(ins_table),
        "instruction_table": ins_table,
        "executed_prog_index_by_wave": {str(k): v for k, v in
                                        sorted(traces.items())},
        "emulator_waitcnt_semantics": {
            "op_s_waitcnt": "bound to _noop in emu.py",
            "op_s_waitcnt_depctr": "bound to _noop in emu.py",
            "consequence": (
                "The host emulator executes every memory op synchronously, so "
                "it CANNOT exhibit a waitcnt-ordering hang and its clean "
                "natural_end is NOT evidence that Candidate F's waits are "
                "correct.  The dynamic PC set below is the right INPUT to a "
                "semantic ordering check, not the result of one."),
        },
        "wall_s": round(time.time() - t0, 1),
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(out, f)
    print("executed: waves=%d total=%d distinct_addr=%d -> %s (%.1f s)"
          % (len(traces), total, len(exec_addrs),
             os.path.relpath(a.out, ROOT), time.time() - t0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
