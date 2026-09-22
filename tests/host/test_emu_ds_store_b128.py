"""Independent LDS store-width checks for DS_STORE_B128."""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401  (sets up the flat source namespace)
import emu


class TestDsStoreB128(unittest.TestCase):
    def test_four_dwords_are_written_little_endian_at_the_byte_offset(self):
        core = emu.Core([], lanes=1, vgprs=8, lds_size=64)
        core.v[0][0] = 4
        core.v[0][1:5] = [0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00]

        core.op_ds_store_b128(
            {"text": "ds_store_b128 v0, v[1:4] offset:8"},
            ["v0", "v[1:4]", "offset:8"],
        )

        self.assertEqual(
            bytes(core.lds[12:28]),
            bytes.fromhex("44 33 22 11 88 77 66 55 cc bb aa 99 00 ff ee dd"),
        )

    def test_inactive_lane_does_not_store(self):
        core = emu.Core([], lanes=1, vgprs=8, lds_size=64)
        core.exec_l = 0
        core.v[0][0] = 0
        core.v[0][1:5] = [1, 2, 3, 4]
        core.op_ds_store_b128(
            {"text": "ds_store_b128 v0, v[1:4]"},
            ["v0", "v[1:4]"],
        )
        self.assertEqual(bytes(core.lds[:16]), bytes(16))

    def test_data_range_parser_rejects_descending_range(self):
        self.assertEqual(
            emu.Core._ds_parts("ds_store_b128 v0, v[1:4]", 16),
            ("v0", ["v[1:4]"], 0),
        )
        with self.assertRaisesRegex(emu.NotImpl, "descending data range"):
            emu.Core._ds_parts("ds_store_b128 v0, v[4:1]", 16)


if __name__ == "__main__":
    unittest.main()
