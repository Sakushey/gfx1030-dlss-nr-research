from unittest.mock import patch
import unittest

import hostpath  # noqa: F401
import wg_emu


class _Core:
    def __init__(self, prog, *, wavebase=0, **_kwargs):
        self.pc = 0 if wavebase == 0 else len(prog)
        self.s = [0] * 128
        self.terminated = False
        self.steps = 0

    def step(self):
        self.steps += 1
        self.pc += 1


class _ReleaseFaultCore(_Core):
    def step(self):
        raise RuntimeError("synthetic barrier release failure")


class _EndedThenBarrierCore(_Core):
    """Wave 0 ends; wave 1 alone reaches and releases the next barrier."""
    def __init__(self, prog, *, wavebase=0, **kwargs):
        super().__init__(prog, wavebase=wavebase, **kwargs)
        self.prog = prog
        self.pc = 0 if wavebase == 0 else 1

    def step(self):
        self.steps += 1
        if self.prog[self.pc]["mnemonic"] == "s_endpgm":
            self.terminated = True
        self.pc += 1


class TestBarrierFaultParticipation(unittest.TestCase):
    def _run(self, core, prog, waves):
        with (
            patch.object(wg_emu, "WG_SwinCore", core),
            patch.object(wg_emu.P11, "entry_plan", lambda _dw: None),
            patch.object(wg_emu.P11, "fill_entry", lambda *_a, **_k: None),
            patch.object(wg_emu, "swin_mem", lambda *_a, **_k: {}),
        ):
            return wg_emu.run_workgroup(
                prog, None, "synthetic", (1, 1, 1), (64, 1, 1), {},
                wave_count=waves, round_cap=8,
            )

    def test_faulted_wave_prevents_barrier_success(self):
        result = self._run(_Core, [
            {"mnemonic": "s_barrier", "address": 0},
            {"mnemonic": "s_endpgm", "address": 4},
        ], 2)
        self.assertEqual(result["outcome"][0], "FAULT")
        self.assertEqual(result["per_wave"][1]["state"], "FAULTED")
        self.assertEqual(result["barrier_epochs"], [])

    def test_release_exception_stays_faulted(self):
        result = self._run(_ReleaseFaultCore,
                           [{"mnemonic": "s_barrier", "address": 0}], 1)
        self.assertEqual(result["outcome"][0], "FAULT")
        self.assertEqual(result["per_wave"][0]["state"], "FAULTED")
        self.assertEqual(result["per_wave"][0]["fault"][0], "RELEASE-EXC")
        self.assertEqual(result["barrier_epochs"], [])

    def test_ended_wave_is_not_a_faulted_barrier_participant(self):
        result = self._run(_EndedThenBarrierCore, [
            {"mnemonic": "s_endpgm", "address": 0},
            {"mnemonic": "s_barrier", "address": 4},
            {"mnemonic": "s_endpgm", "address": 8},
        ], 2)
        self.assertEqual(result["outcome"][0], "ALL_ENDED")
        self.assertEqual(result["per_wave"][0]["state"], "ENDED")
        self.assertEqual(result["per_wave"][1]["state"], "ENDED")
        self.assertEqual(len(result["barrier_epochs"]), 1)
        self.assertEqual(result["barrier_epochs"][0]["site"], 4)
