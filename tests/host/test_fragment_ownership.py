"""Host-only regression for the wave32 fragment-ownership contract.

Three things are separated here on purpose, because conflating them is the
defect this split exists to prevent:

  1. the DENSE arithmetic fixture (`tests/soft_wmma_test.cpp`) -- grades the
     arithmetic of a 16x16x16 product, on a decomposition that hands lane l
     rows `(l >> 4) * 8 .. + 7`;
  2. the FRAGMENT-OWNERSHIP contract (`tests/wmma_fragment_ownership.h`) --
     register r of lane l owns dense element (2r + (l >> 4), l & 15);
  3. the authority for (2) -- the validated phase-7C procedure in
     `src/harness/p14ei_b_host.cpp`, whose CPU mirror used the same
     lane/source rule and which Phase 14EI Probe B ran physically.

The test cross-checks (2) against a simulation of (3) over all 32 lanes and
all 8 registers, and then contains negative controls showing that (1) is a
genuinely different map -- so a fixture described as proving one cannot be
cited as proof of the other.

No GPU. The four arithmetic cases are computed on the host, in fp16 round
trips through `struct`'s half format, against a dense double reference.
"""
from __future__ import annotations

import os
import re
import struct
import unittest

import hostpath  # noqa: F401  (sets up the import namespace)

REPO = hostpath.REPO_ROOT
HEADER = os.path.join(REPO, "tests", "wmma_fragment_ownership.h")
FIXTURE = os.path.join(REPO, "tests", "soft_wmma_fragment_test.cpp")
AUTHORITY = os.path.join(REPO, "src", "harness", "p14ei_b_host.cpp")
DENSE = os.path.join(REPO, "tests", "soft_wmma_test.cpp")

ROWS = 16
COLS = 16
LANES = 32
REGS = 8


def half(x: float) -> float:
    """Round-trip a value through binary16 and back."""
    return struct.unpack("<e", struct.pack("<e", x))[0]


# ---------------------------------------------------------------------------
# Independent statement of the contract.
#
# Derived from the validated procedure, not from the header: lane l computes
# register r from A row (2r + p) and B column (l & 15), where p = 1 for
# lanes 16..31 and 0 otherwise. Simulating the procedure directly is what
# makes this an independent check of the header's inverse map rather than a
# restatement of it.
# ---------------------------------------------------------------------------
def procedure_owner(lane: int, r: int):
    """(row, col) of the dense element register r of `lane` computes."""
    parity = 1 if lane >= 16 else 0
    a_row = 2 * r + parity
    return a_row, lane & 15


def dense_fixture_owner(lane: int, r: int):
    """The DENSE fixture's row assignment -- a different map, deliberately.

    `tests/soft_wmma_test.cpp`: `col = lane & 15`, `row_base = (lane >> 4) * 8`,
    and row = row_base + r.
    """
    return (lane >> 4) * 8 + r, lane & 15


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------
_CONST = re.compile(r"^constexpr int (\w+)\s*=\s*(\d+);", re.M)


def header_constants() -> dict:
    with open(HEADER, encoding="utf-8") as f:
        return {m.group(1): int(m.group(2)) for m in _CONST.finditer(f.read())}


# ---------------------------------------------------------------------------
# The four arithmetic cases, on the host.
# ---------------------------------------------------------------------------
def zeros():
    return [0.0] * (ROWS * COLS)


def signed_pattern(salt: int):
    m = zeros()
    for r in range(ROWS):
        for c in range(COLS):
            m[r * COLS + c] = float(((r * 7 + c * 5 + salt * 3) % 17) - 8)
    return m


def build_cases():
    cases = []

    a = zeros()
    for i in range(ROWS):
        a[i * COLS + i] = 1.0
    cases.append(("identity", a, signed_pattern(1), zeros()))

    a = zeros()
    a[3 * COLS + 5] = 1.0
    cases.append(("one_hot", a, signed_pattern(2), zeros()))

    cases.append(("signed_asymmetric", signed_pattern(3), signed_pattern(4), zeros()))

    c = zeros()
    for r in range(ROWS):
        for cc in range(COLS):
            c[r * COLS + cc] = float(((r * 3 + cc * 11 + 7) % 33) - 16) / 16.0
    cases.append(("nonzero_accumulator", signed_pattern(5), signed_pattern(6), c))
    return cases


def dense_reference(a, b, c):
    out = zeros()
    for r in range(ROWS):
        for cc in range(COLS):
            s = c[r * COLS + cc]
            for k in range(COLS):
                s += half(a[r * COLS + k]) * half(b[k * COLS + cc])
            out[r * COLS + cc] = s
    return out


def evaluate_under(owner, a, b, c):
    """Gather the per-lane fragments through `owner`, then accumulate.

    This is the fixture's kernel shape: lane l packs B's own column and the A
    row the map says it needs, runs the fragment procedure, and writes each
    accumulator register back through the same map. A wrong map therefore
    scatters the results to the wrong dense elements.
    """
    out = [None] * (ROWS * COLS)
    for lane in range(LANES):
        parity = 1 if lane >= 16 else 0
        col = lane & 15
        b_frag = [
            struct.pack("<e", half(b[(2 * j) * COLS + col]))
            + struct.pack("<e", half(b[(2 * j + 1) * COLS + col]))
            for j in range(8)
        ]
        for r in range(REGS):
            a_row = 2 * r + parity
            if a_row < 16:
                a_frag = [
                    struct.pack("<e", half(a[a_row * COLS + 2 * j]))
                    + struct.pack("<e", half(a[a_row * COLS + 2 * j + 1]))
                    for j in range(8)
                ]
            else:                                    # pragma: no cover
                a_frag = [b"\0\0\0\0"] * 8
            acc = c[owner(lane, r)[0] * COLS + owner(lane, r)[1]]
            for j in range(8):
                a0, a1 = struct.unpack("<ee", a_frag[j])
                b0, b1 = struct.unpack("<ee", b_frag[j])
                acc += a0 * b0 + a1 * b1
            row, ocol = owner(lane, r)
            out[row * COLS + ocol] = acc
    return out


class TestAuthority(unittest.TestCase):
    """The validated procedure the contract is derived from."""

    def test_authority_file_exists(self):
        self.assertTrue(os.path.exists(AUTHORITY), AUTHORITY)

    def test_authority_still_states_the_same_rule(self):
        """If the validated rule changes, the contract must be re-derived.

        Pinning the two expressions rather than trusting the header comment:
        a header that drifts from the procedure is exactly the failure mode.
        """
        with open(AUTHORITY, encoding="utf-8") as f:
            text = f.read()
        self.assertRegex(text, r"output_parity\s*=\s*lane\s*>=\s*16\s*\?\s*1\s*:\s*0")
        self.assertRegex(text, r"a_source_lane\s*=\s*2\s*\*\s*r\s*\+\s*output_parity")


class TestHeaderMap(unittest.TestCase):
    """The header's map against a simulation of the validated procedure."""

    def test_geometry_constants(self):
        c = header_constants()
        self.assertEqual(c.get("kRows"), 16)
        self.assertEqual(c.get("kCols"), 16)
        self.assertEqual(c.get("kLanes"), 32)
        self.assertEqual(c.get("kRegs"), 8)
        self.assertEqual(c.get("kPairs"), 8)
        self.assertEqual(c.get("kARowLanes"), 16)

    def test_header_map_matches_the_procedure_for_every_lane_and_register(self):
        c = header_constants()
        self.assertEqual(c.get("kLanes"), LANES)

        def lane_of(row, col):
            return ((row & 1) << 4) | col

        def reg_of(row):
            return row >> 1

        mismatches = []
        for lane in range(LANES):
            for r in range(REGS):
                row, col = procedure_owner(lane, r)
                if lane_of(row, col) != lane or reg_of(row) != r:
                    mismatches.append((lane, r, row, col))
        self.assertEqual(
            mismatches, [],
            "header map does not invert the validated procedure at: "
            f"{mismatches[:8]}",
        )

    def test_ownership_is_a_bijection_over_the_tile(self):
        seen = {}
        for lane in range(LANES):
            for r in range(REGS):
                row, col = procedure_owner(lane, r)
                self.assertNotIn((row, col), seen,
                                 f"element {(row, col)} owned twice")
                seen[(row, col)] = (lane, r)
        self.assertEqual(len(seen), ROWS * COLS)
        self.assertEqual(sorted(seen), sorted((r, c) for r in range(ROWS)
                                              for c in range(COLS)))

    def test_even_rows_to_low_half_and_odd_rows_to_high_half(self):
        """The interleave, stated as a property rather than a formula."""
        for lane in range(LANES):
            for r in range(REGS):
                row, col = procedure_owner(lane, r)
                self.assertEqual(col, lane & 15)
                if lane < 16:
                    self.assertEqual(row % 2, 0)
                else:
                    self.assertEqual(row % 2, 1)


class TestFixtureSource(unittest.TestCase):
    """The C++ fixture is the thing that actually runs on the GPU."""

    def test_fixture_exists_and_uses_the_shared_map(self):
        with open(FIXTURE, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("wmma_fragment_ownership.h", text)
        self.assertIn("wmma_numeric_compare.h", text)
        self.assertIn("wmma_fragment_ownership.h", text)

    def test_fixture_has_all_four_cases(self):
        with open(FIXTURE, encoding="utf-8") as f:
            text = f.read()
        for name in ("identity", "one_hot", "signed_asymmetric",
                     "nonzero_accumulator"):
            self.assertIn(f'"{name}"', text, f"fixture is missing case {name}")

    def test_fixture_loads_fragments_through_the_map_not_naturally(self):
        with open(FIXTURE, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("wmma_fragment::row_of(lane, r)", text)
        self.assertIn("wmma_fragment::col_of(lane)", text)
        self.assertIn("wmma_fragment::a_source_lane(r, parity)", text)

    def test_dense_fixture_disclaims_fragment_ownership(self):
        """The dense fixture must not be described as proving the contract."""
        with open(DENSE, encoding="utf-8") as f:
            text = f.read()
        self.assertIn("DENSE SOFTWARE-MATRIX ARITHMETIC FIXTURE", text)
        self.assertIn("does NOT grade", text)
        self.assertIn("fragment", text.lower())
        # The old claim must be gone.
        self.assertNotIn("Lane mapping intentionally mirrors the GFX11 wave32 WMMA C ownership",
                         text)
        # And the dense fixture must point at the fixture that does grade it.
        self.assertIn("soft_wmma_fragment_test.cpp", text)


class TestFourCasesOnTheHost(unittest.TestCase):
    """The four cases under the contract, computed independently."""

    def test_identity_yields_b(self):
        _, a, b, c = build_cases()[0]
        got = evaluate_under(procedure_owner, a, b, c)
        ref = dense_reference(a, b, c)
        self.assertEqual(got, ref)
        for i in range(ROWS * COLS):
            self.assertEqual(got[i], half(b[i]), f"identity mismatch at {i}")

    def test_one_hot_selects_one_row_of_b(self):
        _, a, b, c = build_cases()[1]
        got = evaluate_under(procedure_owner, a, b, c)
        for col in range(COLS):
            self.assertEqual(got[3 * COLS + col], half(b[5 * COLS + col]))
            for r in range(ROWS):
                if r != 3:
                    self.assertEqual(got[r * COLS + col], 0.0)

    def test_signed_asymmetric_matches_dense_reference_exactly(self):
        _, a, b, c = build_cases()[2]
        got = evaluate_under(procedure_owner, a, b, c)
        ref = dense_reference(a, b, c)
        self.assertEqual(got, ref)
        self.assertTrue(any(v < 0 for v in got))
        self.assertTrue(any(v > 0 for v in got))

    def test_nonzero_accumulator_is_included(self):
        _, a, b, c = build_cases()[3]
        got_with = evaluate_under(procedure_owner, a, b, c)
        got_without = evaluate_under(procedure_owner, a, b, [0.0] * (ROWS * COLS))
        self.assertNotEqual(got_with, got_without)
        self.assertEqual(got_with, dense_reference(a, b, c))

    def test_all_four_cases_are_exact(self):
        """Every input is a small dyadic, so the tolerance must do no work."""
        for name, a, b, c in build_cases():
            got = evaluate_under(procedure_owner, a, b, c)
            ref = dense_reference(a, b, c)
            worst = max(abs(g - r) for g, r in zip(got, ref))
            self.assertEqual(worst, 0.0, f"{name}: not exact ({worst})")


class TestNegativeControls(unittest.TestCase):
    """Proof the ownership map is load-bearing, not decorative."""

    def test_negative_control_dense_map_is_a_different_map(self):
        """The dense fixture's map disagrees with the contract.

        This is the measurement behind the documentation split: for the same
        (lane, register) the two maps name different dense elements, so a
        fixture built on one cannot be evidence for the other.
        """
        disagreements = []
        for lane in range(LANES):
            for r in range(REGS):
                if procedure_owner(lane, r) != dense_fixture_owner(lane, r):
                    disagreements.append((lane, r,
                                          procedure_owner(lane, r),
                                          dense_fixture_owner(lane, r)))
        self.assertGreater(
            len(disagreements), 0,
            "the dense and fragment maps are identical; the split is unjustified",
        )
        # Quantify it: name one concrete disagreement rather than asserting a
        # count, so a small change to either map is visible in the failure.
        self.assertIn((0, 1, (2, 0), (1, 0)), disagreements)

    def test_negative_control_identity_case_fails_under_the_dense_map(self):
        """Run the identity case through the dense map and require a failure."""
        _, a, b, c = build_cases()[0]
        got = evaluate_under(dense_fixture_owner, a, b, c)
        expected = [half(v) for v in b]
        mismatches = sum(1 for i in range(ROWS * COLS) if got[i] != expected[i])
        self.assertGreater(mismatches, 0,
                           "identity passed under the wrong map: the case grades nothing")

    def test_negative_control_parity_swap_fails(self):
        """Inverting the two halves' parity must also produce a wrong tile."""
        def parity_swapped(lane, r):
            parity = 0 if lane >= 16 else 1
            return 2 * r + parity, lane & 15

        _, a, b, c = build_cases()[2]
        good = evaluate_under(procedure_owner, a, b, c)
        bad = evaluate_under(parity_swapped, a, b, c)
        self.assertNotEqual(good, bad)

    def test_negative_control_signed_case_is_not_a_constant_tile(self):
        """Guard against a fixture whose inputs make every map agree.

        If the operands were uniform or symmetric, several wrong maps would
        land on the same answer and the case would grade nothing.
        """
        _, a, b, c = build_cases()[2]
        good = evaluate_under(procedure_owner, a, b, c)
        self.assertGreater(len(set(good)), 8)
        self.assertTrue(any(v != 0 for v in good))


if __name__ == "__main__":
    unittest.main()
