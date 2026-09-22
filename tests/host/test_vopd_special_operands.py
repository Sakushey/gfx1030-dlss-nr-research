"""Independent robustness checks for special-state VOPD operands.

The static dependency analyser promises to fail closed for unsupported input.
It must therefore not crash when a parsed operand denotes architectural state
rather than a numbered SGPR/VGPR.
"""
from __future__ import annotations

import pathlib
import sys
import unittest


VOPD_DIR = pathlib.Path(__file__).resolve().parents[2] / "src" / "vopd"
sys.path.insert(0, str(VOPD_DIR))

import p16aw_vopd_dependency as vopd


class TestVopdSpecialOperands(unittest.TestCase):
    def test_vcc_source_is_a_special_read_not_a_formatting_exception(self):
        result = vopd.analyse_op("v_dual_and_b32 v1, vcc_lo, v2")
        self.assertTrue(result["modelled"])
        self.assertIn("vcc_lo", result["reads"])
        self.assertIn("v2", result["reads"])
        self.assertEqual(result["writes"], {"v1"})

    def test_pair_classification_with_vcc_source_is_total(self):
        result = vopd.classify_pair(
            "v_dual_and_b32 v1, vcc_lo, v2",
            "v_dual_mov_b32 v3, v4",
        )
        self.assertEqual(result["class"], "INDEPENDENT")


if __name__ == "__main__":
    unittest.main()
