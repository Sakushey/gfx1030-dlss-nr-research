"""Fail-closed checks for unmodelled memory instructions.

An instruction that produces a value must not be a silent no-op: retaining a
stale destination can turn a memory-dependency error into a false PASS.
"""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401  (sets up the flat source namespace)
import emu


class TestUnmodelledMemoryFailsClosed(unittest.TestCase):
    def test_global_byte_load_does_not_leave_stale_destination(self):
        core = emu.Core([], lanes=1, vgprs=4, mem={0x40: 0xAB})
        core.v[0][0] = 0x40
        core.v[0][1] = 0
        core.v[0][2] = 0xDEADBEEF

        with self.assertRaisesRegex(emu.NotImpl, "global_load_b8"):
            core.op_global_load_b8({}, ["v2", "v[0:1]"])

        # The old silent stub would return and leave this stale value behind.
        self.assertEqual(core.v[0][2], 0xDEADBEEF)


if __name__ == "__main__":
    unittest.main()
