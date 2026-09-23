"""Adversarial VOPD tests: both halves read one architectural pre-state."""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401
import emu


class TestVopdAtomicPrestate(unittest.TestCase):
    def _core(self, operands, lanes=1):
        row = {"address": 0x100, "mnemonic": "v_dual_add_u32",
               "operands": operands, "text": ""}
        return emu.Core(emu.build_orig_program([row]), lanes=lanes)

    def test_partner_read_does_not_observe_partner_write(self):
        core = self._core(
            "v1, v0, 1 :: v_dual_add_u32 v2, v1, 1")
        core.v[0][0], core.v[0][1] = 10, 5
        core.step()
        self.assertEqual((core.v[0][1], core.v[0][2]), (11, 6))
        self.assertEqual(core.pc, 1)

    def test_partner_fmac_reads_prestate_not_partner_result(self):
        row = {"address": 0x100, "mnemonic": "v_dual_mov_b32",
               "operands": "v3, v0 :: v_dual_fmac_f32 v4, v3, v2",
               "text": ""}
        core = emu.Core(emu.build_orig_program([row]), lanes=1)
        core.v[0][0] = emu.f32_bits(4.0)
        core.v[0][3] = emu.f32_bits(2.0)
        core.v[0][2] = emu.f32_bits(3.0)
        core.v[0][4] = emu.f32_bits(1.0)
        core.step()
        self.assertEqual(emu.bits_f32(core.v[0][4]), 7.0)

    def test_overlapping_destinations_fail_closed(self):
        core = self._core(
            "v1, v0, 1 :: v_dual_add_u32 v1, v0, 1")
        with self.assertRaisesRegex(emu.NotImpl, "overlapping vector writes"):
            core.step()

    def test_idempotent_overlapping_destinations_still_fail_closed(self):
        core = self._core(
            "v1, v0, 1 :: v_dual_add_u32 v1, v0, 1")
        # Both halves write v1, but retain its old value (0 + 1 == 1).
        core.v[0][0], core.v[0][1] = 0, 1
        with self.assertRaisesRegex(emu.NotImpl, "overlapping vector writes"):
            core.step()

    def test_exec_mask_applies_to_both_halves(self):
        core = self._core(
            "v1, v0, 1 :: v_dual_add_u32 v2, v0, 2", lanes=2)
        core.exec_l = 0b01
        core.v[0][0], core.v[1][0] = 5, 7
        core.step()
        self.assertEqual((core.v[0][1], core.v[0][2]), (6, 7))
        self.assertEqual((core.v[1][1], core.v[1][2]), (0, 0))


if __name__ == "__main__":
    unittest.main()
