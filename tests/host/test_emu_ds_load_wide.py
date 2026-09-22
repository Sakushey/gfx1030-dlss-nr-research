"""Independent LDS load-width and operand-position checks."""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401
import emu


class TestDsLoadWide(unittest.TestCase):
    def test_b64_uses_second_operand_as_address_and_splits_destination(self):
        core = emu.Core([], lanes=1, vgprs=8, lds_size=64)
        core.v[0][0] = 4
        core.lds[12:20] = bytes.fromhex("44 33 22 11 88 77 66 55")
        core.op_ds_load_b64(
            {"text": "ds_load_b64 v[1:2], v0 offset:8"},
            ["v[1:2]", "v0", "offset:8"],
        )
        self.assertEqual(core.v[0][1], 0x11223344)
        self.assertEqual(core.v[0][2], 0x55667788)

    def test_b128_load_writes_four_dwords(self):
        core = emu.Core([], lanes=1, vgprs=8, lds_size=64)
        core.lds[:16] = bytes.fromhex(
            "44 33 22 11 88 77 66 55 cc bb aa 99 00 ff ee dd"
        )
        core.op_ds_load_b128(
            {"text": "ds_load_b128 v[1:4], v0"},
            ["v[1:4]", "v0"],
        )
        self.assertEqual(core.v[0][1:5],
                         [0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00])


if __name__ == "__main__":
    unittest.main()
