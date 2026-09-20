"""Host-only regression for the shared finite-aware numerical comparator.

`tests/wmma_numeric_compare.h` is the one comparison utility used by the
dense arithmetic fixture, the bounded benchmark, and the wave32 fragment
fixture. This test compiles a host driver against it and requires every
rejection class to actually reject.

The negative controls here are of two kinds, and both matter:

  * data controls -- a real input of each kind the comparator claims to
    reject (NaN, +Inf, -Inf, an untouched sentinel, a short buffer, one
    element over tolerance, a corrupted out-of-range guard);
  * a control on the *comparator itself* -- the naive `max_abs <= tol` check
    is run over the same buffers, and the driver reports whether the naive
    form accepted them. On the NaN and sentinel inputs it does accept them
    with a reported max-abs of 0, which is exactly why the utility exists.

If the naive check ever stops accepting those inputs, the driver reports BAD
and this test fails: a negative control that has silently become a positive
one is worse than no control.
"""
from __future__ import annotations

import os
import re
import unittest

import cxxtoolchain
import hostpath  # noqa: F401  (sets up the import namespace)

REPO = hostpath.REPO_ROOT
HEADER = os.path.join(REPO, "tests", "wmma_numeric_compare.h")
DRIVER = os.path.join(REPO, "tests", "host", "compare_driver.cpp")

# The rejection classes the comparator promises, and the driver case that
# must produce each of them.
REQUIRED_CASES = {
    "known_good_exact": "PASS",
    "known_good_within_tolerance": "PASS",
    "nan_in_result": "NAN_MISMATCH",
    "pos_inf_in_result": "INF_MISMATCH",
    "neg_inf_in_result": "INF_MISMATCH",
    "nonfinite_reference_is_void": "NONFINITE_REFERENCE",
    "untouched_sentinel": "SENTINEL_UNTOUCHED",
    "wrong_length_got": "LENGTH_MISMATCH",
    "wrong_length_ref": "LENGTH_MISMATCH",
    "ref_shaped_like_got_is_length_mismatch": "LENGTH_MISMATCH",
    "empty_comparison_is_not_a_pass": "LENGTH_MISMATCH",
    "one_element_over_tolerance": "TOLERANCE_EXCEEDED",
    "tightened_tolerance_rejects": "TOLERANCE_EXCEEDED",
    "corrupted_guard": "GUARD_CORRUPTED",
}

# Inputs the naive comparator accepts. `nan_in_result` and `untouched_sentinel`
# are the load-bearing ones: for both, the naive form reports max-abs 0.0.
NAIVE_MUST_ACCEPT = ("nan_in_result", "untouched_sentinel", "corrupted_guard")

_CASE = re.compile(r"^CASE (\S+) EXPECT (\S+) GOT (\S+) INDEX (\d+) "
                   r"MAXABS (\S+) COMPARED (\d+) (OK|BAD)$", re.M)
_NAIVE = re.compile(r"^NAIVE (\S+) EXPECT_ACCEPTS (\d) GOT_ACCEPTS (\d) "
                    r"MAXABS (\S+) (OK|BAD)$", re.M)


class TestComparatorSource(unittest.TestCase):
    """Properties of the header that do not need a compiler."""

    def test_header_and_driver_exist(self):
        self.assertTrue(os.path.exists(HEADER), HEADER)
        self.assertTrue(os.path.exists(DRIVER), DRIVER)

    def test_header_declares_every_verdict(self):
        with open(HEADER, encoding="utf-8") as f:
            text = f.read()
        for v in set(REQUIRED_CASES.values()):
            self.assertIn(v, text, f"header does not declare {v}")

    def test_header_is_self_contained(self):
        """No project include, so a host driver can compile it standalone."""
        with open(HEADER, encoding="utf-8") as f:
            includes = re.findall(r"^#include\s+(.+)$", f.read(), re.M)
        for inc in includes:
            self.assertTrue(inc.startswith("<"), f"non-system include: {inc}")

    def test_every_consumer_includes_the_shared_header(self):
        """The utility must be shared, not reimplemented per fixture."""
        for rel in ("tests/soft_wmma_test.cpp", "tests/soft_wmma_bench.cpp",
                    "tests/soft_wmma_fragment_test.cpp"):
            path = os.path.join(REPO, rel.replace("/", os.sep))
            self.assertTrue(os.path.exists(path), f"{rel} missing")
            with open(path, encoding="utf-8") as f:
                text = f.read()
            self.assertIn('wmma_numeric_compare.h', text,
                          f"{rel} does not include the shared comparator")

    def test_consumers_do_not_hand_roll_a_tolerance_loop(self):
        """A per-consumer `max_abs <= tol` is the defect this replaced."""
        for rel in ("tests/soft_wmma_test.cpp", "tests/soft_wmma_bench.cpp",
                    "tests/soft_wmma_fragment_test.cpp"):
            path = os.path.join(REPO, rel.replace("/", os.sep))
            with open(path, encoding="utf-8") as f:
                text = f.read()
            self.assertNotIn("max_abs <=", text,
                             f"{rel} still contains an ad-hoc tolerance test")


class TestComparatorBehaviour(unittest.TestCase):
    """The compiled driver's actual verdicts."""

    @classmethod
    def setUpClass(cls):
        ok, detail, out = cxxtoolchain.compile_and_run(
            [DRIVER], include_dirs=[os.path.join(REPO, "tests")])
        cls.compiler_ok = ok
        cls.detail = detail
        cls.out = out or ""
        # Group 3 is the verdict the comparator produced, group 7 is the
        # driver's own OK/BAD flag. Reading group 3 for both silently marks
        # every case BAD, which is what a mis-indexed regex does here.
        cls.cases = {m.group(1): (m.group(2), m.group(7) == "OK", m.group(3))
                     for m in _CASE.finditer(cls.out)}
        cls.naive = {m.group(1): (m.group(2) == "1", m.group(3) == "1",
                                  m.group(5) == "OK")
                     for m in _NAIVE.finditer(cls.out)}

    def setUp(self):
        if self.compiler_ok is None:
            self.skipTest(self.detail)
        if not self.compiler_ok:
            self.fail("driver did not build/run: " + self.detail)

    def test_driver_reports_no_internal_failures(self):
        self.assertIn("DRIVER_FAILURES 0", self.out, self.out[-2000:])

    def test_every_required_case_ran(self):
        missing = sorted(set(REQUIRED_CASES) - set(self.cases))
        self.assertEqual(missing, [], f"cases missing from driver output: {missing}")

    def test_every_case_matches_its_expected_verdict(self):
        wrong = {name: (exp, self.cases[name][2])
                 for name, exp in REQUIRED_CASES.items()
                 if name in self.cases and self.cases[name][0] != exp}
        self.assertEqual(wrong, {}, f"verdict mismatch: {wrong}")

    def test_no_case_is_reported_bad(self):
        bad = sorted(n for n, v in self.cases.items() if not v[1])
        self.assertEqual(bad, [], f"driver flagged these cases BAD: {bad}")

    def test_known_good_case_is_accepted(self):
        """A checker that rejects the control is broken, not strict."""
        for name in ("known_good_exact", "known_good_within_tolerance"):
            self.assertIn(name, self.cases)
            self.assertEqual(self.cases[name][0], "PASS")

    def test_length_and_guard_verdicts_precede_tolerance(self):
        """An out-of-range write must be named as such.

        `corrupted_guard` also has a perfect graded region, so a comparator
        that graded only [0, count) would report PASS.
        """
        self.assertEqual(self.cases["corrupted_guard"][0], "GUARD_CORRUPTED")

    def test_reference_carries_the_graded_region_only(self):
        """The two buffers are not the same length, and the rule says so.

        `got` is `count + guards`; `ref` is `count`. A reference shaped like
        the result buffer -- the shape a caller reaches for by reflex, and the
        shape this comparator originally demanded -- must be rejected, not
        accepted. Both directions of a wrong reference length are covered:
        one shorter than `count`, one longer.
        """
        self.assertEqual(self.cases["ref_shaped_like_got_is_length_mismatch"][0],
                         "LENGTH_MISMATCH")
        self.assertEqual(self.cases["wrong_length_ref"][0], "LENGTH_MISMATCH")

    # ---------------------------------------------------------- negative control
    def test_negative_control_naive_check_accepts_the_rejected_inputs(self):
        """Prove the data cases discriminate.

        On these inputs the naive `max_abs <= tol` comparison reports a
        maximum error of zero and accepts. A comparator that passes these is
        not a stricter comparator, it is a vacuous one.
        """
        for name in NAIVE_MUST_ACCEPT:
            self.assertIn(name, self.naive, f"driver did not emit NAIVE {name}")
            expect_accepts, got_accepts, ok = self.naive[name]
            self.assertTrue(expect_accepts, f"control for {name} is mis-declared")
            self.assertTrue(got_accepts,
                            f"naive check rejected {name}; the control has gone stale")
            self.assertTrue(ok, f"driver flagged NAIVE {name} BAD")

    def test_negative_control_nan_is_invisible_to_a_max_abs_scan(self):
        """Name the mechanism, not just the outcome.

        `fabs(NaN - 1.0f) > m` is false for every m, so a NaN never raises the
        running maximum. The driver's reported MAXABS for that case must
        therefore be 0 -- if it is not, the naive helper is not the naive
        helper and the control above proves nothing.
        """
        self.assertIn("nan_in_result", self.naive)
        m = re.search(r"^NAIVE nan_in_result EXPECT_ACCEPTS \d GOT_ACCEPTS \d "
                      r"MAXABS (\S+)", self.out, re.M)
        self.assertIsNotNone(m, "no NAIVE nan_in_result line")
        self.assertEqual(float(m.group(1)), 0.0)


if __name__ == "__main__":
    unittest.main()
