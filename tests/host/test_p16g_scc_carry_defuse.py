"""Independent SCC carry/borrow def-use checks."""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401
import p16g_isa as isa


def analyse(text: str):
    ins = isa.Insn(0, 0, text, "00000000", text)
    isa._fill_defuse(ins)
    return ins


class TestSccCarryDefUse(unittest.TestCase):
    def test_addc_reads_prior_scc_as_carry_in(self):
        ins = analyse("s_addc_u32 s0, s1, s2")
        self.assertIn("scc", ins.uses_special)

    def test_subb_reads_prior_scc_as_borrow_in(self):
        ins = analyse("s_subb_u32 s0, s1, s2")
        self.assertIn("scc", ins.uses_special)

    def test_plain_add_and_sub_do_not_read_prior_scc(self):
        for text in ("s_add_u32 s0, s1, s2", "s_sub_u32 s0, s1, s2"):
            with self.subTest(text=text):
                self.assertNotIn("scc", analyse(text).uses_special)


if __name__ == "__main__":
    unittest.main()
