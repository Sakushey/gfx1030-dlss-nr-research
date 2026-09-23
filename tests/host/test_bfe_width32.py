"""BFE width is a six-bit field: 32 must not alias to zero."""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401  (sets up the import namespace)
import emu
import isa_oracle_scalar as oracle


class TestBfeWidth32(unittest.TestCase):
    def setUp(self):
        self.core = emu.Core([], lanes=1, vgprs=8)

    def test_scalar_unsigned_width_32_preserves_all_bits(self):
        self.core.op_s_bfe_u32({}, ["s1", "0xDEADBEEF", "0", "32"])
        self.assertEqual(self.core.s[1], 0xDEADBEEF)

    def test_scalar_signed_width_32_preserves_negative_bits(self):
        self.core.op_s_bfe_i32({}, ["s1", "0x80000001", "0", "32"])
        self.assertEqual(self.core.s[1], 0x80000001)

    def test_vector_unsigned_width_32_preserves_all_bits(self):
        self.core.v[0][1] = 0x12345678
        self.core.v[0][2] = 0
        self.core.v[0][3] = 32
        self.core.op_v_bfe_u32({}, ["v4", "v1", "v2", "v3"])
        self.assertEqual(self.core.v[0][4], 0x12345678)

    def test_vector_signed_width_32_preserves_negative_bits(self):
        self.core.v[0][1] = 0x80000001
        self.core.v[0][2] = 0
        self.core.v[0][3] = 32
        self.core.op_v_bfe_i32({}, ["v4", "v1", "v2", "v3"])
        self.assertEqual(self.core.v[0][4], 0x80000001)

    def test_oracle_width_32_matches_full_register(self):
        self.assertEqual(oracle.s_bfe_u32(0xDEADBEEF, 0, 32)["value"], 0xDEADBEEF)
        self.assertEqual(oracle.s_bfe_i32(0x80000001, 0, 32)["value"], 0x80000001)

    def test_negative_control_width_zero_is_still_zero(self):
        self.core.op_s_bfe_u32({}, ["s1", "0xDEADBEEF", "0", "0"])
        self.assertEqual(self.core.s[1], 0)


if __name__ == "__main__":
    unittest.main()
