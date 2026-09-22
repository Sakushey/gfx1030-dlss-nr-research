"""Independent EXEC/VCC def-use checks for V_CMPX."""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401  (sets up the flat source namespace)
import p16g_isa as isa


def analyse(text: str):
    ins = isa.Insn(0, 0, text, "00000000", text)
    isa._fill_defuse(ins)
    return ins


class TestCmpxDefUse(unittest.TestCase):
    def test_cmpx_reads_and_writes_exec_and_writes_vcc(self):
        ins = analyse("v_cmpx_ne_u32_e32 0, v5")
        self.assertIn("exec", ins.uses_special)
        self.assertIn("exec", ins.defs_special)
        self.assertIn("vcc", ins.defs_special)

    def test_plain_compare_does_not_write_exec(self):
        ins = analyse("v_cmp_ne_u32_e32 0, v5")
        self.assertNotIn("exec", ins.defs_special)
        self.assertIn("vcc", ins.defs_special)


if __name__ == "__main__":
    unittest.main()
