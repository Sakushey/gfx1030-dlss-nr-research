"""Independent def-use checks for VOP3B scalar-status destinations."""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401
import p16g_isa as isa


def analyse(text: str):
    ins = isa.Insn(0, 0, text, "00000000", text)
    isa._fill_defuse(ins)
    return ins


class TestVop3bStatusDestination(unittest.TestCase):
    def test_div_scale_vcc_status_operand_is_a_definition(self):
        ins = analyse("v_div_scale_f32 v6, vcc_lo, v5, v5, v3")
        self.assertIn(("vgpr", 6), ins.defs)
        self.assertIn("vcc", ins.defs_special)
        self.assertNotIn("vcc", ins.uses_special)

    def test_div_scale_null_status_has_no_register_edge(self):
        ins = analyse("v_div_scale_f32 v6, null, v5, v5, v3")
        self.assertEqual(ins.defs, [("vgpr", 6)])
        self.assertNotIn("vcc", ins.defs_special)
        self.assertNotIn("vcc", ins.uses_special)

    def test_ordinary_vector_alu_has_no_second_destination(self):
        ins = analyse("v_add_u32 v6, v5, v3")
        self.assertEqual(ins.defs, [("vgpr", 6)])
        self.assertNotIn("vcc", ins.defs_special)


if __name__ == "__main__":
    unittest.main()
