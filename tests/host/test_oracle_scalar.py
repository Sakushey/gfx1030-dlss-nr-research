"""Host-only tests for the independent scalar ISA oracle.

These pin the oracle's contract at the handful of points where a plausible
wrong implementation would still look reasonable: unsigned wraparound,
signed reinterpretation, sign extension, and the comparison-to-SCC
convention. Every group includes a negative control that separates the
correct behaviour from the wrong one.
"""
from __future__ import annotations

import unittest

import hostpath  # noqa: F401  (sets up the import namespace)
import isa_oracle_scalar as O

U32 = 0xFFFFFFFF


def val(r):
    return r["value"] if isinstance(r, dict) else r


class TestUnsignedWrap(unittest.TestCase):
    def test_add_wraps_and_sets_scc(self):
        self.assertEqual(val(O.s_add_u32(U32, 1)), 0)
        self.assertEqual(O.s_add_u32(U32, 1)["scc"], 1)

    def test_add_without_carry_clears_scc(self):
        self.assertEqual(val(O.s_add_u32(1, 2)), 3)
        self.assertEqual(O.s_add_u32(1, 2)["scc"], 0)

    def test_sub_borrow(self):
        self.assertEqual(val(O.s_sub_u32(0, 1)), U32)
        self.assertEqual(O.s_sub_u32(0, 1)["scc"], 1)

    def test_negative_control_not_infinite_precision(self):
        # A Python-int implementation without masking would return 2^32.
        self.assertNotEqual(val(O.s_add_u32(U32, 1)), U32 + 1)


class TestSignedReinterpretation(unittest.TestCase):
    def test_add_i32_wraps_into_sign_bit(self):
        self.assertEqual(val(O.s_add_i32(0x7FFFFFFF, 1)), 0x80000000)

    def test_abs_of_int32_min_is_itself(self):
        self.assertEqual(val(O.s_abs_i32(0x80000000)), 0x80000000)

    def test_sext_i8(self):
        self.assertEqual(val(O.s_sext_i32_i8(0x80)), 0xFFFFFF80)
        self.assertEqual(val(O.s_sext_i32_i8(0x7F)), 0x0000007F)

    def test_sext_i16(self):
        self.assertEqual(val(O.s_sext_i32_i16(0x8000)), 0xFFFF8000)

    def test_negative_control_sext_is_not_zero_extend(self):
        self.assertNotEqual(val(O.s_sext_i32_i8(0x80)), 0x00000080)


class TestMinMax(unittest.TestCase):
    def test_unsigned_min_max_respect_high_bit(self):
        # 0xFFFFFFFF is large unsigned, not -1.
        self.assertEqual(val(O.s_min_u32(1, U32)), 1)
        self.assertEqual(val(O.s_max_u32(1, U32)), U32)

    def test_signed_min_max_respect_high_bit(self):
        self.assertEqual(val(O.s_min_i32(1, U32)), U32)
        self.assertEqual(val(O.s_max_i32(1, U32)), 1)

    def test_negative_control_signed_and_unsigned_differ(self):
        # If both used the same comparison, these would agree.
        self.assertNotEqual(val(O.s_min_u32(1, U32)), val(O.s_min_i32(1, U32)))


class TestMulHi(unittest.TestCase):
    def test_mul_hi_u32_high_word(self):
        # (2^32-1)^2 = 2^64 - 2^33 + 1 -> high 32 bits = 2^32 - 2
        self.assertEqual(val(O.s_mul_hi_u32(U32, U32)), 0xFFFFFFFE)

    def test_negative_control_not_low_word(self):
        # s_mul_u32 (low word) of the same operands is 1; distinct from hi.
        self.assertNotEqual(val(O.s_mul_hi_u32(U32, U32)), 1)


class TestBitCompare(unittest.TestCase):
    def test_bitcmp1_reads_high_bit(self):
        self.assertEqual(O.s_bitcmp1_b32(0x80000000, 31)["scc"], 1)
        self.assertEqual(O.s_bitcmp1_b32(0x00000000, 31)["scc"], 0)

    def test_bitcmp0_is_the_complement(self):
        self.assertEqual(O.s_bitcmp0_b32(0x80000000, 31)["scc"], 0)
        self.assertEqual(O.s_bitcmp0_b32(0x00000000, 31)["scc"], 1)

    def test_negative_control_bitcmp0_and_bitcmp1_disagree(self):
        self.assertNotEqual(O.s_bitcmp1_b32(0x80000000, 31)["scc"],
                            O.s_bitcmp0_b32(0x80000000, 31)["scc"])


class TestComparisonWritesScc(unittest.TestCase):
    def test_unsigned_comparison_ignores_sign_bit(self):
        self.assertEqual(O.SCALAR["s_cmp_gt_u32"](U32, 1)["scc"], 1)

    def test_signed_comparison_honours_sign_bit(self):
        # As signed, 0xFFFFFFFF is -1, which is not > 1.
        self.assertEqual(O.SCALAR["s_cmp_gt_i32"](U32, 1)["scc"], 0)

    def test_negative_control_signed_unsigned_disagree(self):
        self.assertNotEqual(O.SCALAR["s_cmp_gt_u32"](U32, 1)["scc"],
                            O.SCALAR["s_cmp_gt_i32"](U32, 1)["scc"])


class TestNegativeHexImmediate(unittest.TestCase):
    def test_negative_hex_immediate_is_a_u32_word(self):
        result = O.eval_scalar({
            "mnem": "s_add_i32",
            "setup": {"s1": 0},
            "operands": ["s0", "s1", "-0x1"],
        })
        self.assertEqual(result["value"], U32)

    def test_negative_hex_is_not_rejected_as_an_unknown_token(self):
        try:
            O.eval_scalar({
                "mnem": "s_add_u32",
                "setup": {"s1": 1},
                "operands": ["s0", "s1", "-0x1"],
            })
        except KeyError as exc:
            self.fail("negative hexadecimal immediate was rejected: %s" % exc)


if __name__ == "__main__":
    unittest.main()
