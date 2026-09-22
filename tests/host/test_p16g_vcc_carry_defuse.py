"""Independent VCC carry-chain def-use checks."""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401
import p16g_isa as isa


def analyse(text: str):
    ins = isa.Insn(0, 0, text, "00000000", text)
    isa._fill_defuse(ins)
    return ins


class TestVccCarryDefUse(unittest.TestCase):
    def test_carry_out_is_a_vcc_definition_not_a_stale_read(self):
        ins = analyse("v_add_co_u32 v0, vcc_lo, v1, v2")
        self.assertIn("vcc", ins.defs_special)
        self.assertNotIn("vcc", ins.uses_special)

    def test_carry_in_out_reads_and_writes_vcc(self):
        for text in ("v_add_co_ci_u32 v0, vcc_lo, v1, v2, vcc_lo",
                     "v_sub_co_ci_u32 v0, vcc_lo, v1, v2, vcc_lo"):
            with self.subTest(text=text):
                ins = analyse(text)
                self.assertIn("vcc", ins.uses_special)
                self.assertIn("vcc", ins.defs_special)

    def test_incomplete_carry_in_form_does_not_invent_a_vcc_source(self):
        ins = analyse("v_add_co_ci_u32 v0, vcc_lo, v1, v2")
        self.assertIn("vcc", ins.defs_special)
        self.assertNotIn("vcc", ins.uses_special)

    def test_noncarry_add_does_not_gain_a_vcc_dependency(self):
        ins = analyse("v_add_nc_u32 v0, v1, v2")
        self.assertNotIn("vcc", ins.uses_special)
        self.assertNotIn("vcc", ins.defs_special)


if __name__ == "__main__":
    unittest.main()
