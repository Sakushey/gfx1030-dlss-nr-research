"""Unmodelled value-producing WMMA instructions must fail closed."""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401  (sets up the import namespace)
import emu


class TestUnmodelledWmmaFailsClosed(unittest.TestCase):
    def setUp(self):
        self.core = emu.Core([], lanes=1, vgprs=4)
        self.core.v[0][1] = 0xDEADBEEF

    def test_named_wmma_does_not_silently_preserve_accumulator(self):
        with self.assertRaisesRegex(emu.NotImpl, "v_wmma_f32_16x16x16_f16"):
            self.core.op_v_wmma_f32_16x16x16_f16(
                {}, ["v1", "v2", "v3", "v1"])
        self.assertEqual(self.core.v[0][1], 0xDEADBEEF)

    def test_generic_wmma_stub_is_not_accepted_as_a_no_op(self):
        with self.assertRaisesRegex(emu.NotImpl, "v_wmma_stub"):
            self.core.op_v_wmma_stub({}, ["v1"])
        self.assertEqual(self.core.v[0][1], 0xDEADBEEF)


if __name__ == "__main__":
    unittest.main()
