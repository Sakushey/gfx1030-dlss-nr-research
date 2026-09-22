"""Independent unsigned scalar borrow checks."""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401
import emu


class TestScalarBorrow(unittest.TestCase):
    def setUp(self):
        self.core = emu.Core([], lanes=1)

    def _run(self, mnemonic, lhs, rhs, scc=0):
        self.core.sset("s1", lhs)
        self.core.sset("s2", rhs)
        self.core.scc = scc
        getattr(self.core, mnemonic)({}, ["s0", "s1", "s2"])
        return self.core.sget("s0"), self.core.scc

    def test_sub_reports_unsigned_borrow(self):
        self.assertEqual(self._run("op_s_sub_u32", 0, 1), (0xFFFFFFFF, 1))
        self.assertEqual(self._run("op_s_sub_u32", 8, 3), (5, 0))

    def test_subb_consumes_and_replaces_scc(self):
        self.assertEqual(self._run("op_s_subb_u32", 1, 0, scc=1), (0, 0))
        self.assertEqual(self._run("op_s_subb_u32", 0, 0, scc=1),
                         (0xFFFFFFFF, 1))


if __name__ == "__main__":
    unittest.main()
