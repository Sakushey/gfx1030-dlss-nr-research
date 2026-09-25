"""Scalar and vector BFE use different control-field encodings."""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401  (sets up the import namespace)
import emu
import isa_oracle_scalar as oracle
from p14d8_core import Core8


class TestBfeWidthRules(unittest.TestCase):
    def setUp(self):
        self.core = emu.Core([], lanes=1, vgprs=8)

    def test_decoded_scalar_host_form_accepts_width_32(self):
        self.core.op_s_bfe_u32({}, ["s1", "0xDEADBEEF", "0", "32"])
        self.assertEqual(self.core.s[1], 0xDEADBEEF)

    def test_decoded_scalar_host_form_keeps_signed_width_32(self):
        self.core.op_s_bfe_i32({}, ["s1", "0x80000001", "0", "32"])
        self.assertEqual(self.core.s[1], 0x80000001)

    def test_vector_width_is_low_five_bits(self):
        expected_u = {0: 0, 31: 0x7FFFFFFF, 32: 0, 33: 1, 63: 0x7FFFFFFF}
        expected_i = {0: 0, 31: 0xFFFFFFFF, 32: 0, 33: 0xFFFFFFFF,
                      63: 0xFFFFFFFF}
        for width in (0, 31, 32, 33, 63):
            self.core.v[0][1] = 0xFFFFFFFF
            self.core.v[0][2] = 0
            self.core.v[0][3] = width
            self.core.op_v_bfe_u32({}, ["v4", "v1", "v2", "v3"])
            self.core.op_v_bfe_i32({}, ["v5", "v1", "v2", "v3"])
            self.assertEqual(self.core.v[0][4], expected_u[width], width)
            self.assertEqual(self.core.v[0][5], expected_i[width], width)

    def test_raw_scalar_packed_control_uses_offset_low6_width_22_16(self):
        scalar = Core8([], lanes=1, vgprs=4)
        scalar.op_s_bfe_u32({}, ["s1", "0xDEADBEEF", "0x00200000"])
        self.assertEqual(scalar.s[1], 0xDEADBEEF)
        # offset 33 / width 1: bit 33 is outside a 32-bit source.
        scalar.op_s_bfe_u32({}, ["s1", "0xDEADBEEF", "0x00010021"])
        self.assertEqual(scalar.s[1], 0)

    def test_raw_scalar_signed_width_32_and_oracle_agree_independently(self):
        scalar = Core8([], lanes=1, vgprs=4)
        scalar.op_s_bfe_i32({}, ["s1", "0x80000001", "0x00200000"])
        self.assertEqual(scalar.s[1], 0x80000001)
        vector = {"mnem": "s_bfe_i32", "setup": {"s0": 0x80000001},
                  "operands": ["s1", "s0", "0x00200000"]}
        self.assertEqual(oracle.eval_scalar(vector)["value"], 0x80000001)

    def test_decoded_scalar_host_form_width_zero_is_still_zero(self):
        self.core.op_s_bfe_u32({}, ["s1", "0xDEADBEEF", "0", "0"])
        self.assertEqual(self.core.s[1], 0)


if __name__ == "__main__":
    unittest.main()
