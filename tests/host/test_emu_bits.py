"""Host-only tests for the emulator's bit-level conversions.

Every expectation here is a property predicted from the IEEE-754 definition
or from the ISA, not a value read back from the implementation. Each group
carries a negative control that must distinguish the case under test from a
plausible wrong implementation.
"""
from __future__ import annotations

import math
import unittest

import hostpath  # noqa: F401  (sets up the import namespace)
import emu


class TestF32Saturation(unittest.TestCase):
    def test_overflow_saturates_to_infinity(self):
        # IEEE-754: the rounded result of a finite real outside the
        # representable range is a signed infinity.
        self.assertEqual(emu.f32(1e40), math.inf)
        self.assertEqual(emu.f32(-1e40), -math.inf)

    def test_underflow_flushes_to_zero(self):
        self.assertEqual(emu.f32(1e-50), 0.0)

    def test_in_range_passthrough(self):
        self.assertEqual(emu.f32(1.0), 1.0)
        self.assertEqual(emu.f32(-2.0), -2.0)

    def test_negative_control_sign_is_not_lost(self):
        # A sign-blind implementation would return +inf for both.
        self.assertNotEqual(emu.f32(1e40), emu.f32(-1e40))


class TestF32Bits(unittest.TestCase):
    def test_bits_round_trip(self):
        self.assertEqual(emu.f32_bits(1.0), 0x3F800000)
        self.assertEqual(emu.bits_f32(0x3F800000), 1.0)

    def test_negative_zero_is_not_positive_zero(self):
        # Distinct bit patterns; a naive comparison would treat them as equal.
        self.assertEqual(emu.f32_bits(-0.0), 0x80000000)
        self.assertEqual(emu.f32_bits(0.0), 0x00000000)

    def test_negative_control_bit_width(self):
        # Guards against a 16-bit-truncating implementation.
        self.assertEqual(emu.f32_bits(-1.0) & 0xFF800000, 0xBF800000)


class TestF16(unittest.TestCase):
    def test_known_half_patterns(self):
        self.assertEqual(emu.f16_to_f32(0x3C00), 1.0)
        self.assertEqual(emu.f16_to_f32(0xBC00), -1.0)
        self.assertEqual(emu.f16_to_f32(0x0000), 0.0)

    def test_half_infinity(self):
        self.assertEqual(emu.f16_to_f32(0x7C00), math.inf)

    def test_f32_to_f16_round_trip_exact(self):
        self.assertEqual(emu.f32_to_f16_bits(1.0), 0x3C00)
        self.assertEqual(emu.f32_to_f16_bits(-1.0), 0xBC00)

    def test_negative_control_biased_exponent(self):
        # 2.0 in binary16 is exponent 16 -> 0x4000. A sign-blind or
        # unbiased-exponent implementation would not produce this.
        self.assertEqual(emu.f32_to_f16_bits(2.0), 0x4000)
        self.assertNotEqual(emu.f32_to_f16_bits(2.0),
                            emu.f32_to_f16_bits(-2.0))


class TestF32BitsToF16Rne(unittest.TestCase):
    """Hand-derived IEEE-754 binary32-to-binary16 boundary vectors."""

    def test_exact_midpoints_choose_even_half_significand(self):
        self.assertEqual(emu.f32_bits_to_f16(0x3F801000), 0x3C00)
        # Midpoint of odd 0x3C01 and even 0x3C02.
        self.assertEqual(emu.f32_bits_to_f16(0x3F803000), 0x3C02)

    def test_subnormal_normal_boundary_and_signed_zero(self):
        self.assertEqual(emu.f32_to_f16_bits(1023.5 * 2.0 ** -24), 0x0400)
        self.assertEqual(emu.f32_bits_to_f16(0x80000000), 0x8000)
        self.assertEqual(emu.f32_bits_to_f16(0x80000001), 0x8000)

    def test_overflow_tie_rounds_to_infinity(self):
        self.assertEqual(emu.f32_to_f16_bits(65519.0), 0x7BFF)
        self.assertEqual(emu.f32_to_f16_bits(65520.0), 0x7C00)


class TestF32ClassBits(unittest.TestCase):
    """f32_class_bit takes *bits*, matching the hardware class operand."""

    def _cls(self, value):
        return emu.f32_class_bit(emu.f32_bits(value))

    def test_positive_and_negative_differ(self):
        self.assertEqual(self._cls(1.0), 8)
        self.assertEqual(self._cls(-1.0), 3)

    def test_zero(self):
        self.assertEqual(self._cls(0.0), 6)

    def test_infinity(self):
        self.assertEqual(self._cls(emu.f32(1e40)), 9)

    def test_negative_control_classes_are_distinct(self):
        classes = {self._cls(1.0), self._cls(-1.0), self._cls(0.0),
                   self._cls(emu.f32(1e40))}
        self.assertEqual(len(classes), 4,
                         "class bits must distinguish sign, zero, and range")


if __name__ == "__main__":
    unittest.main()
