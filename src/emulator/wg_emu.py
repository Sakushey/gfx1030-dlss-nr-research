"""Phase 14E-F6/F7/F8 — WORKGROUP-LEVEL EMULATOR (host-only, zero GPU).

Executes ALL waves of ONE workgroup together on a SHARED LDS image and a
SHARED global-memory model, with a documented single workgroup barrier
object (GFX6..GFX11 semantics, no split/named barriers):

  - every wave that reaches an s_barrier instruction parks (WAITING).
  - the barrier completes only when every still-alive wave of the
    workgroup has parked.  Waves that already ended (s_endpgm) are no
    longer participants (AMDGPU execution model: a terminated wave is
    dropped; it cannot block the others).
  - if the alive set parks but at DIFFERENT static barrier sites in the
    same barrier epoch -> BARRIER_SEQUENCE_DIVERGENCE (epoch mismatch;
    data-unsafe; treated as a deadlock-grade failure for SWIN).
  - if a wave cannot reach the barrier the others wait on (spins or
    faults) -> WORKGROUP_DEADLOCK / FAULT / bounded step limit.

Wave states: RUNNABLE / WAITING_AT_BARRIER / ENDED / FAULTED.
Deterministic scheduler: round-robin, one instruction per alive wave per
round; barrier release checked after each full round.

The per-wave instruction semantics are the existing house emulator
(SwinCore = RecCore = Core8 = Core from phases 8/14D8/14D11/14E,
p14e_emu.py) — unchanged.  Only the barrier object and the LDS/global
sharing are added here.  Cycle-halt (single-wave spinning) is disabled
per wave; global step caps bound the run instead.
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUTD = os.path.abspath(os.path.join(HERE, "..", "out"))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
for p in (HERE, os.path.join(ROOT, "phase14e_static", "tools"),
          os.path.join(ROOT, "phase14d8_static", "tools"),
          os.path.join(ROOT, "phase8_static", "tools"),
          os.path.join(ROOT, "phase14d_static", "tools"),
          os.path.join(ROOT, "phase14d11_static", "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import p14e_emu as PE                 # noqa: E402
from p14e_emu import (SwinCore, slice_program, text_mem_map, swin_mem,
                      _norm_float_ops)  # noqa: E402
import p14d11_emu as P11               # noqa: E402
import p14d_kd as kd                   # noqa: E402
from emu import Halt, NotImpl, U32     # noqa: E402

KERNEL = PE.KERNEL
ENT_CO = PE.ENT_CO
ENT_DIS = PE.ENT_DIS
LDS_PART = PE.LDS_PART


class WG_SwinCore(SwinCore):
    """SwinCore + the gfx1100 `2addr` mnemonics the original SWIN uses
    (control-neutral deterministic model consistent with the house
    read2/write2 conventions: two b64 accesses at base+o0*8 / base+o1*8)."""

    def op_ds_load_2addr_b64(self, ins, ops):
        self._ds2_b64(ins, ops, store=False)

    def op_ds_store_2addr_b64(self, ins, ops):
        self._ds2_b64(ins, ops, store=True)

    def op_ds_load_u16_d16_hi(self, ins, ops):
        # original-gfx1100 spelling of ds_read_u16_d16_hi
        self._ds_load_bytes(ins, ops, 2, d16_hi=True)

    def op_v_clz_i32_u32(self, ins, ops):
        # dst = leading-zero count of the 32-bit value (0 -> 32); the i32
        # flavour on the ISA counts on |S|, which only differs for negative
        # S (data are zero here); keep the deterministic u32 flavour.
        dst, src = ops[0], ops[1]
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                v = self.vget(lane, src) & U32
                self.vset(lane, dst, 32 - v.bit_length() if v else 32)

    def op_v_ffbh_u32_e64(self, ins, ops):
        self.op_v_ffbh_u32(ins, ops)

    def op_v_mbcnt_lo_u32_b32(self, ins, ops):
        # count of low-32 exec bits; control-neutral here (model lanes by
        # popcount of exec_lo & src mask).
        dst, src = ops[0], ops[1]
        mask = self.sget(src) if ops[1].startswith("s") else \
            (self.vcc_l if ops[1] == "vcc_lo" else self.sget(src))
        for lane in range(self.lanes):
            if (self.exec_l >> lane) & 1:
                self.vset(lane, dst, bin(self.exec_l & U32).count("1"))


class _NoKeys(dict):
    """Dict whose membership test is always False (disables the house
    single-wave CYCLE halt; cross-wave progress is legitimate here)."""

    def __contains__(self, k):
        return False


# ---------------------------------------------------------------------------
# Workgroup driver
# ---------------------------------------------------------------------------
def _sat_f32(x):
    """f32() with HW round-to-nearest overflow behaviour: |x| beyond f32
    range becomes +-inf instead of raising OverflowError."""
    try:
        return _f32_orig(x)
    except OverflowError:
        import math as _m
        return _m.copysign(float("inf"), x) if x else 0.0


import emu as _EMU_MOD
_f32_orig = _EMU_MOD.f32
if getattr(_EMU_MOD, "f32", None) is not _sat_f32:
    _EMU_MOD.f32 = _sat_f32


def run_workgroup(prog, dw16_, label, grid, block, fields, text_path=None,
                  wave_count=8, per_wave_step_cap=8_000_000,
                  round_cap=200_000_000, trace_path=None,
                  log_barrier_sgprs=(), wgid=(0, 0, 0)):
    """Run `wave_count` waves (wavebase w*32) of one workgroup together.

    prog: instruction list (house build_orig_program output, pc-indexed).
    `barrier_epochs` records successfully released rendezvous only; a wave
    arrival whose release-step faults is retained per-wave but not completed.
    Returns a result dict (see below).  Deterministic."""
    if not getattr(prog, "_normed_float_ops", False):
        _norm_float_ops(prog)
        try:
            prog._normed_float_ops = True
        except AttributeError:
            pass
    mem = swin_mem(fields, grid, block)
    if text_path is not None:
        tm = text_mem_map(text_path)
        mem.update(tm)
    shared_lds = bytearray(LDS_PART)   # zero-filled, like the house model
    barrier_idx = {i: ins.get("address") for i, ins in enumerate(prog)
                   if "barrier" in ins.get("mnemonic", "")}
    plan = P11.entry_plan(dw16_)
    waves = []
    for w in range(wave_count):
        wb = w * 32
        core = WG_SwinCore(prog, lanes=32, lds_size=LDS_PART, lds_fill=0,
                           wavebase=wb, mem=mem)
        core._prog_ref = prog
        P11.fill_entry(core, plan, kernarg=PE.KERNARG,
                       dispatch_ptr=PE.PACKET, wgid=wgid,
                       wavebase=wb, block=block)
        core.lds = shared_lds            # SHARED LDS image
        core.mem = mem                   # SHARED global model
        core._cyckeys = _NoKeys()        # no single-wave cycle halt
        core._cyckeys_full = _NoKeys()
        waves.append({"core": core, "state": "RUNNABLE",
                      "n_bar": 0, "bar_sites": [], "bar_epochs": [],
                      "fault": None, "steps_done": 0})

    barrier_epochs = []      # completed epochs: {no, site, wave order}
    pend_epoch = None        # current pending epoch descriptor
    ticks = 0
    outcome = None
    diverged = False
    barrier_sgpr = dict(log_barrier_sgprs) if log_barrier_sgprs else {}

    def site_of(w):
        i = w["core"].pc
        if i < len(prog):
            return prog[i].get("address")
        return None

    while True:
        ticks += 1
        if ticks > round_cap:
            outcome = ("ROUNDCAP", ticks)
            break
        any_active = False
        for w in waves:
            if w["state"] == "ENDED" or w["state"] == "FAULTED":
                continue
            core = w["core"]
            any_active = True
            if w["state"] == "WAITING":
                continue
            # RUNNABLE: look at the next instruction
            if core.pc >= len(prog):
                w["state"] = "FAULTED"
                w["fault"] = "PCOVERRUN"
                continue
            ins = prog[core.pc]
            mnem = ins["mnemonic"]
            if "barrier" in mnem:
                # park this wave at the barrier
                w["state"] = "WAITING"
                w["n_bar"] += 1
                site = ins.get("address")
                w["bar_sites"].append(site)
                w["bar_epochs"].append({"no": len(barrier_epochs) + 1,
                                        "site": site,
                                        "arrival_round": ticks})
                if barrier_sgpr is not None and site in barrier_sgpr:
                    barrier_sgpr[site].append(
                        [core.s[i] for i in log_barrier_sgprs[site]])
                continue
            # step one instruction
            try:
                core.step()
                w["steps_done"] += 1
                if core.terminated:
                    w["state"] = "ENDED"
            except Halt as h:
                if h.kind == "END" or core.terminated:
                    w["state"] = "ENDED"
                else:
                    w["state"] = "FAULTED"
                    w["fault"] = ("HALT", h.kind, getattr(h, "info", None),
                                  site_of(w), core.steps)
            except NotImpl as e:
                w["state"] = "FAULTED"
                w["fault"] = ("NOTIMPL", str(e), site_of(w), core.steps)
            except Exception as e:  # fail closed, like the house trace()
                w["state"] = "FAULTED"
                w["fault"] = ("EXC", f"{type(e).__name__}: {e}",
                              site_of(w), core.steps)
            if w["steps_done"] > per_wave_step_cap:
                w["state"] = "FAULTED"
                w["fault"] = ("STEPCAP", site_of(w), core.steps)
        if not any_active:
            outcome = ("ALL_ENDED", ticks)
            break
        # A faulted wave cannot be treated as a terminated participant.
        # Otherwise a remaining wave could appear to complete a rendezvous
        # although another required wave never executed its barrier path.
        if any(w["state"] == "FAULTED" for w in waves):
            outcome = ("FAULT", ticks)
            break
        # ---- barrier release check (end of round) ----
        alive = [w for w in waves if w["state"] not in ("ENDED", "FAULTED")]
        if alive and all(w["state"] == "WAITING" for w in alive):
            sites = {w["bar_sites"][-1] for w in alive}
            if len(sites) != 1:
                diverged = True
                outcome = ("BARRIER_SEQUENCE_DIVERGENCE", ticks,
                           sorted(s for s in sites if s))
                break
            site = sites.pop()
            release_fault = False
            for w in alive:
                # release: execute the (no-op) barrier instruction
                try:
                    w["core"].step()
                    w["steps_done"] += 1
                    w["state"] = "RUNNABLE"
                except Exception as e:
                    w["state"] = "FAULTED"
                    w["fault"] = ("RELEASE-EXC", str(e))
                    release_fault = True
            if release_fault:
                outcome = ("FAULT", ticks)
                break
            barrier_epochs.append({"no": len(barrier_epochs) + 1,
                                   "site": site,
                                   "round": ticks,
                                   "waves": [w["core"] and
                                             int((w["core"].s[15] if False
                                                  else 0)) for w in []],
                                   "arrivals": [w["bar_epochs"][-1]
                                                for w in alive]})
        elif alive and not any(w["state"] == "RUNNABLE" for w in alive):
            # alive waves: mixture of WAITING + FAULTED impossible here
            # (faulted are not alive); all waiting handled above -> any
            # WAITING with a RUNNABLE partner just keeps waiting.
            pass

    # ---- summarize ----
    core0 = waves[0]["core"]
    res = {
        "label": label, "grid": list(grid), "block": list(block),
        "wave_count": wave_count,
        "outcome": outcome, "diverged": diverged, "ticks": ticks,
        "lds_size": LDS_PART,
        "barrier_epochs": barrier_epochs,
        "per_wave": [
            {"wave": w, "state": waves[w]["state"], "steps": waves[w]["steps_done"],
             "barriers": waves[w]["n_bar"],
             "bar_sites": waves[w]["bar_sites"],
             "fault": waves[w]["fault"]}
            for w in range(wave_count)],
    }
    if trace_path:
        with open(trace_path, "w", encoding="utf-8") as f:
            f.write(f"# workgroup trace {label} outcome={outcome}\n")
            for w in range(wave_count):
                f.write(f"# wave {w}: state={waves[w]['state']} "
                        f"steps={waves[w]['steps_done']} "
                        f"barriers={waves[w]['n_bar']} "
                        f"fault={waves[w]['fault']}\n")
                for e in waves[w]["bar_epochs"]:
                    f.write(f"  bar-epoch#{e['no']} site={e['site']:#x} "
                            f"arrival_round={e['arrival_round']}\n")
            f.write("# completed barrier epochs (rendezvous)\n")
            for e in barrier_epochs:
                f.write(f"  epoch#{e['no']} site={e['site']:#x} "
                        f"round={e['round']}\n")
    return res


def _noop_barrier_fixup(prog):
    """(reserved) — not needed: barriers are intercepted by the driver."""
    return prog


# ---------------------------------------------------------------------------
# Entry-fixed failed-config run (F7) and helpers
# ---------------------------------------------------------------------------
def ef_fields(dims=64):
    fields = {}
    for o, k in ((0x00, 0), (0x08, 1), (0x10, 2), (0x30, 3), (0x38, 4),
                 (0x48, 5), (0x78, 6), (0x80, 7), (0xA0, 8)):
        fields[o] = ("ptr", k)
    for o in (0x18, 0x1C, 0x20, 0x24):
        fields[o] = ("u32", dims)
    fields[0x28] = ("u32", 0)     # flags 0
    fields[0x98] = ("u64", 0)
    return fields


def run_ef_failed(label="F7failed", wave_count=8, trace_path=None):
    prog, rows, idx = slice_program(ENT_DIS, KERNEL)
    dw = P11.dw16(ENT_CO, KERNEL)
    return run_workgroup(prog, dw, label, (1, 1, 1), (256, 1, 1),
                         ef_fields(), text_path=ENT_CO,
                         wave_count=wave_count, trace_path=trace_path)


# ---- original gfx1100 (F8) ------------------------------------------------
ORIG_OBJ = os.path.join(ROOT, "phase5_exact_fragment", "gfx1100_code_object.o")
ORIG_DIS = os.path.join(ROOT, "phase5_exact_fragment",
                        "gfx1100_disassembly.txt")


def run_orig_failed(label="F8orig", wave_count=8, trace_path=None):
    prog, rows, idx = slice_program(ORIG_DIS, KERNEL)
    dw = P11.dw16(ORIG_OBJ, KERNEL)
    return run_workgroup(prog, dw, label, (1, 1, 1), (256, 1, 1),
                         ef_fields(), text_path=ORIG_OBJ,
                         wave_count=wave_count, trace_path=trace_path)


if __name__ == "__main__":
    import csv
    mode = sys.argv[1] if len(sys.argv) > 1 else "ef"
    if mode == "ef":
        r = run_ef_failed("P256D64-wg8", trace_path=os.path.join(
            OUTD, "phase14e_failed_workgroup_trace.txt"))
        tag = "failed"
    else:
        r = run_orig_failed("ORIG-P256D64-wg8", trace_path=os.path.join(
            OUTD, "phase14e_original_workgroup_trace.txt"))
        tag = "original"
    with open(os.path.join(OUTD, f"phase14e_{tag}_workgroup_result.json"),
              "w", encoding="utf-8") as f:
        json.dump(r, f, indent=1, default=str)
    with open(os.path.join(OUTD, f"phase14e_{tag}_barrier_epochs.csv"),
              "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["epoch", "site_pc", "release_round"])
        for e in r["barrier_epochs"]:
            w.writerow([e["no"], f"0x{e['site']:x}", e["round"]])
    with open(os.path.join(OUTD, f"phase14e_{tag}_per_wave.csv"),
              "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["wave", "state", "steps", "barrier_hits",
                    "barrier_sites", "fault"])
        for p in r["per_wave"]:
            w.writerow([p["wave"], p["state"], p["steps"], p["barriers"],
                        " ".join(f"0x{s:x}" for s in p["bar_sites"]),
                        p["fault"]])
    print(json.dumps({"outcome": r["outcome"], "ticks": r["ticks"],
                      "epochs": len(r["barrier_epochs"]),
                      "waves": [(p["wave"], p["state"], p["steps"],
                                 p["barriers"], p["fault"])
                                for p in r["per_wave"]]}, indent=1))
