"""Phase 16Z -- one host J3 dispatch, as a standalone process.

Invoked as:  python p16z_run.py <job.json>

The job spec is deliberately a file, not argv, so a job is reproducible from
the artefacts alone.  Each process gets its own bytecode cache prefix, its own
scratch directory and its own stdout, so N of them can run concurrently
without touching each other.

Two modes:
  control / layout : run under a base set (the physical 16Y addresses, or the
                     frozen control bases), optionally over a patched code
                     object + disassembly.
  The program the emulator executes is ALWAYS sliced from the disassembly of
  the very code object whose sha is recorded in the result, so a patched
  binary cannot be described by an unpatched program.
"""

import hashlib
import json
import os
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
Z = os.path.dirname(HERE)
ROOT = os.path.dirname(Z)

PHYS_BASES = {
    "slot_0x00": 0x0000000404000000,
    "slot_0x08": 0x0000000400040000,
    "slot_0x10": 0x0000000400020000,
    "slot_0xA0": 0x0000000400080000,
}
FROZEN_IMAGE_SHA = \
    "5ab70916b9c284dd24a1878afcd7b984928145442623909a275b0035743979e4"
FROZEN_TICKS = 13699
FROZEN_EPOCHS = [710468, 735828, 744332, 751628, 758660, 763660, 769568,
                 769828, 777052, 788208]
FROZEN_REL_STORE_DIGEST = \
    "38309375536bbb8b06946f674ed6fec5ae46d1bbed983da8571349fad92048eb"
FROZEN_REL_STORE_N = 6144


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


HALTS = []


def jsonable(o):
    """Make a measurement dict JSON-safe without silently dropping signal.

    Keys beginning with `_` are the runner's private bulk objects (raw images,
    per-byte maps) and are reported as digests elsewhere; tuple keys are the
    (region, offset) store keys and are rendered as "region@offset".
    """
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            if isinstance(k, str) and k.startswith("_"):
                continue
            if isinstance(k, tuple):
                k = "@".join(str(x) for x in k)
            out[str(k)] = jsonable(v)
        return out
    if isinstance(o, (list, tuple)):
        return [jsonable(v) for v in o]
    if isinstance(o, bytes):
        return {"__bytes_sha256__": sha256_bytes(o), "n": len(o)}
    if isinstance(o, (str, int, float, bool)) or o is None:
        return o
    return repr(o)


def build_observers(mods):
    """Add a per-wave halting-PC recorder.

    The halting PC is the address of the instruction whose execution raised
    `emu.Halt` -- the s_endpgm that actually retired THIS wave.

    This matters: `p14eh`'s barrier releases when every ALIVE wave is waiting,
    so a patch that terminates only some waves does NOT deadlock -- the
    survivors simply carry on to the next barrier, release among themselves
    and run to the normal end.  Such a run reports `n_ended == 8` and
    `ALL_ENDED`.  Counting ended waves therefore CANNOT detect an unsafe
    diagnostic; the per-wave halting PC is the only positive evidence of
    WHERE each wave stopped.
    """
    def wrap(base):
        class HaltObs(base):
            def step(self):
                pc = self.pc
                try:
                    r = super().step()
                except Exception as e:            # noqa: BLE001
                    if type(e).__name__ == "Halt":
                        # `self.pc` is an INDEX into the parsed program, not
                        # a code address.  Reporting it raw produced
                        # "0x443c" for a wave that retired at 0xC36D8.
                        prog = getattr(self, "_prog_ref", None)
                        a = None
                        if prog is not None and 0 <= pc < len(prog):
                            a = prog[pc].get("address")
                        HALTS.append(hex(a) if a is not None
                                     else "index:%d" % pc)
                    raise
                return r

        HaltObs.__name__ = "HaltObs" + base.__name__
        HaltObs.__qualname__ = HaltObs.__name__
        return HaltObs

    return wrap


def main(jobpath):
    with open(jobpath, encoding="utf-8") as f:
        J = json.load(f)
    out_path = J["out"]
    t0 = time.time()
    res = {"schema": "phase16z-host-run/1", "job": J["job"],
           "mode": J["mode"], "host_only": True,
           "gpu_execution_performed": False,
           "job_spec": J}
    try:
        sys.path.insert(0, os.path.join(ROOT, "phase16y", "addressing",
                                        "part4_scratch"))
        import p4_lib as P4

        mods = P4.boot()
        J3 = mods["J3"]

        co = J.get("co") or os.path.join(
            ROOT, "phase16h_candidate_f", "gfx1030_dlssnr_candidate_f.co")
        dis = J.get("dis")
        if dis:
            J3.CANDIDATE_DIS = dis
            J3.CANDIDATE_CO = os.path.relpath(co, ROOT).replace("\\", "/")
        res["co_path"] = os.path.relpath(co, ROOT).replace("\\", "/")
        res["co_sha256"] = sha_file(co)
        res["dis_path"] = os.path.relpath(J3.CANDIDATE_DIS, ROOT).replace(
            "\\", "/")
        res["dis_sha256"] = sha_file(J3.CANDIDATE_DIS)

        ctrl_regions = P4.control_regions(P4.input_doc_and_blob()[0])
        if J["mode"] == "layout":
            bases = {k: int(v, 0) for k, v in J["bases"].items()}
            if set(bases) != set(ctrl_regions):
                raise SystemExit("bases %s != regions %s"
                                 % (sorted(bases), sorted(ctrl_regions)))
            # p4_lib builds a layout-relative histograms with `addr - shift`,
            # so shift_D must be a NUMBER even when the layout is an explicit
            # base set rather than a rigid shift.  0 means "compare against
            # the control's own region table", which is what the region-
            # relative observables want.
            layout = {"id": J["job"], "kind": J.get("kind", "explicit"),
                      "shift_D": 0, "shift_D_hex": "n/a",
                      "note": J.get("note", ""), "bases": bases}
        elif J["mode"] == "control":
            layout = {"id": J["job"], "kind": "control", "shift_D": 0,
                      "shift_D_hex": "0x0", "note": "frozen control bases",
                      "bases": {n: r["base"] for n, r in ctrl_regions.items()}}
        else:
            raise SystemExit("unknown mode %r" % J["mode"])

        res["bases"] = {k: "0x%016X" % v for k, v in layout["bases"].items()}
        res["layout_id"] = layout["id"]

        hw = build_observers(mods)
        del HALTS[:]
        rec_bar = None
        if J.get("record_barriers"):
            # Reuse the frozen Phase-16Y wave-barrier instrument (read-only)
            # so the per-wave barrier PC sequence is measured the same way it
            # was for the 15-layout metamorphic family, and is therefore
            # directly comparable with it.
            import importlib.util
            lvp = os.path.join(ROOT, "phase16y", "liveness",
                               "p16y_barrier_trace.py")
            spec = importlib.util.spec_from_file_location(
                "p16z_wbi", lvp)
            WBI = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(WBI)
            import p4_run_wave_barriers as WBR
            bar_rec = WBI.Recorder()
            built = []
            inner = WBR.wave_wrap(bar_rec, built)
            outer = hw

            def hw(base, _i=inner, _o=outer):
                return _o(_i(base))
            rec_bar = (WBI, bar_rec, built)
        m = P4.run_layout(layout, core_wrap=hw)
        res["wall_s"] = round(time.time() - t0, 1)
        # `run_layout` returns the raw image and the non-pattern byte map as
        # bytes objects; they are reported as digests and dropped so the
        # result stays JSON.
        m.pop("_image", None)
        m.pop("_image_nonpattern", None)
        res["measured"] = jsonable(m)

        # ---- the frozen observables, compared ------------------------------
        img = m.get("image_sha256")
        res["image_sha256"] = img
        res["image_matches_frozen"] = (img == FROZEN_IMAGE_SHA)
        res["ticks"] = m.get("ticks")
        res["ticks_match_frozen"] = (m.get("ticks") == FROZEN_TICKS)
        res["natural_end"] = m.get("natural_end")
        res["outcome"] = m.get("outcome")
        res["faults"] = m.get("faults")
        res["faults_empty"] = (m.get("faults") == [] or m.get("faults") is None)
        res["barrier_epochs"] = m.get("barrier_epochs")
        res["barrier_epochs_match_frozen"] = \
            (m.get("barrier_epochs") == FROZEN_EPOCHS)
        res["rel_store_n"] = m.get("rel_store_n")
        # run_layout exposes the region-relative store digest as
        # `image_nonpattern_digest`; `rel_store_digest` is a different key
        # that only the comparison layer sets, so reading it here silently
        # compared None with None.
        res["rel_store_digest"] = m.get("image_nonpattern_digest")
        res["rel_store_region_relative_unchanged"] = (
            m.get("rel_store_n") == FROZEN_REL_STORE_N
            and m.get("rel_store_digest") == FROZEN_REL_STORE_DIGEST)
        res["exec_steps_total"] = m.get("exec_steps_total")
        res["exec_pc_n"] = m.get("exec_pc_n")
        res["per_wave_steps"] = [p.get("steps") for p in
                                 (m.get("per_wave") or [])]
        res["n_ended"] = m.get("n_ended")
        res["n_faulted"] = m.get("n_faulted")
        res["control_flow_signature"] = m.get("control_flow_signature")

        # ---- per-wave halting PC (positive proof of WHERE each wave ended) --
        # recorded in execution order; the driver runs waves 0..7 in order
        # within a tick, but a tie is impossible here because every wave
        # halts at most once.
        res["waves_that_halted"] = len(HALTS)
        res["halting_pcs_observed"] = HALTS
        res["halting_pcs_unique"] = sorted(set(HALTS))
        res["all_waves_share_one_halting_pc"] = (
            len(HALTS) == 8 and len(set(HALTS)) == 1)
        res["per_wave_state"] = [p.get("state") for p in
                                 (m.get("per_wave") or [])]
        if rec_bar is not None:
            WBI, bar_rec, built = rec_bar
            import p4_run_wave_barriers as WBR
            pw = WBR.per_wave(WBI, bar_rec, built, WBI.WAVECOUNT)
            pw["per_wave_barrier_pcs_hex"] = [
                ["0x%X" % p for p in s] for s in pw["per_wave_barrier_pcs"]]
            res["per_wave_barrier_pcs_hex"] = pw["per_wave_barrier_pcs_hex"]
            res["per_wave_barrier_steps_at"] = pw["per_wave_barrier_steps_at"]
            res["per_wave_barrier_counts"] = pw["per_wave_barrier_counts"]
            res["wave_mapping_bijective"] = pw["wave_mapping_bijective"]
            res["all_waves_share_one_barrier_pc_sequence"] = (
                len({tuple(s) for s in pw["per_wave_barrier_pcs_hex"]}) == 1)
        res["per_wave_barriers"] = [p.get("barriers") for p in
                                    (m.get("per_wave") or [])]
        res["verdict"] = ("OK" if res["image_matches_frozen"] else "RAN")
        res["wall_s"] = round(time.time() - t0, 1)
        res["measured_keys"] = sorted(m.keys())
    except Exception:                                 # noqa: BLE001
        res["verdict"] = "ERROR"
        res["traceback"] = traceback.format_exc()
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    print("[%s] verdict=%s image=%s ticks=%s"
          % (J["job"], res.get("verdict"), str(res.get("image_sha256"))[:16],
             res.get("ticks")))
    return 0 if res.get("verdict") != "ERROR" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
