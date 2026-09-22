"""Independent def-use checks for saveexec instruction forms.

The expected EXEC effects come directly from the saveexec instruction
contract: each form consumes the old EXEC mask and produces a replacement
EXEC mask, regardless of its Boolean operator spelling.
"""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401  (sets up the flat source namespace)
import p16g_isa as isa


def analyse(text: str):
    ins = isa.Insn(0, 0, text, "00000000", text)
    isa._fill_defuse(ins)
    return ins


class TestSaveexecDefUse(unittest.TestCase):
    def test_all_modelled_saveexec_forms_read_and_write_exec(self):
        forms = (
            "s_and_saveexec_b32 s0, s1",
            "s_and_saveexec_b64 s[0:1], s[2:3]",
            "s_andn2_saveexec_b32 s0, s1",
            "s_andn2_saveexec_b64 s[0:1], s[2:3]",
            "s_and_not1_saveexec_b32 s0, s1",
            "s_and_not1_saveexec_b64 s[0:1], s[2:3]",
            "s_or_saveexec_b32 s0, s1",
            "s_or_saveexec_b64 s[0:1], s[2:3]",
            "s_xor_saveexec_b32 s0, s1",
            "s_xor_saveexec_b64 s[0:1], s[2:3]",
            "s_nand_saveexec_b32 s0, s1",
            "s_nand_saveexec_b64 s[0:1], s[2:3]",
            "s_nor_saveexec_b32 s0, s1",
            "s_nor_saveexec_b64 s[0:1], s[2:3]",
            "s_xnor_saveexec_b32 s0, s1",
            "s_xnor_saveexec_b64 s[0:1], s[2:3]",
        )
        for text in forms:
            with self.subTest(text=text):
                ins = analyse(text)
                self.assertIn("exec", ins.uses_special)
                self.assertIn("exec", ins.defs_special)

    def test_plain_scalar_and_is_not_a_saveexec_operation(self):
        ins = analyse("s_and_b32 s0, s1, s2")
        self.assertNotIn("exec", ins.uses_special)
        self.assertNotIn("exec", ins.defs_special)


if __name__ == "__main__":
    unittest.main()
