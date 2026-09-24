"""Phase 16BK — F11 residual fix: malformed variant strings must be refused.

The canonical production resolver (``src.neural.resolver.resolve``) previously
allowed empty / whitespace-only variant strings to pass through
UNIQUE_FAMILY_FALLBACK.  This test verifies the repaired behaviour against the
required table:

  ""      -> MALFORMED -> REFUSE (status=MISSING, item=None)
  "   "   -> MALFORMED -> REFUSE
  "\\t"   -> MALFORMED -> REFUSE
  valid exact match            -> EXACT
  valid unique family fallback -> UNIQUE_FAMILY_FALLBACK
  multiple candidates          -> AMBIGUOUS -> REFUSE
  zero candidates              -> MISSING -> REFUSE

Host-only.  No pytest; asserts + printed observed values.
"""
import sys

sys.dont_write_bytecode = True

import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from src.neural.resolver import (
    AMBIGUOUS,
    EXACT,
    MISSING,
    RESOLVED,
    REFUSED,
    UNIQUE_FAMILY_FALLBACK,
    ResolutionRefused,
    resolve as production_resolve,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
FAILURES = []


def adapter_a(ctx=None):
    return "A"


def adapter_b(ctx=None):
    return "B"


def check(label, ok, detail=""):
    print("  [%s] %s%s" % ("PASS" if ok else "FAIL", label,
                           (" :: " + str(detail)) if detail else ""))
    if not ok:
        FAILURES.append(label + (" :: " + str(detail) if detail else ""))
    return ok


def note(label, value):
    print("  OBSERVED %-50s %s" % (label, value))


# ===========================================================================
# Malformed variant tests (F11 residual)
# ===========================================================================
def test_malformed_empty_string_refused():
    """Empty string variant must NOT reach UNIQUE_FAMILY_FALLBACK."""
    print("[M1] malformed: empty-string variant")
    entries = {("fam", "v1"): adapter_a}
    res = production_resolve("fam", "", entries)
    note("status", res.status)
    note("item", res.item)
    note("provenance", res.provenance)
    check("malformed_empty_is_missing_status", res.status == MISSING, res.status)
    check("malformed_empty_carries_no_item", res.item is None)
    check("malformed_empty_is_refused", res.is_refused)
    check("malformed_empty_provenance_mentions_malformed",
          "MALFORMED_VARIANT" in res.provenance, res.provenance)
    raised = None
    try:
        res.require()
    except ResolutionRefused as e:
        raised = str(e)
    check("malformed_empty_require_raises", raised is not None, raised)


def test_malformed_whitespace_only_refused():
    """Whitespace-only variant must NOT reach UNIQUE_FAMILY_FALLBACK."""
    print("[M2] malformed: whitespace-only variant")
    entries = {("fam", "v1"): adapter_a}
    res = production_resolve("fam", "   ", entries)
    note("status", res.status)
    note("item", res.item)
    check("malformed_ws_is_missing_status", res.status == MISSING, res.status)
    check("malformed_ws_carries_no_item", res.item is None)
    check("malformed_ws_is_refused", res.is_refused)


def test_malformed_tab_only_refused():
    """Tab-only variant must NOT reach UNIQUE_FAMILY_FALLBACK."""
    print("[M3] malformed: tab-only variant")
    entries = {("fam", "v1"): adapter_a}
    res = production_resolve("fam", "\t", entries)
    note("status", res.status)
    note("item", res.item)
    check("malformed_tab_is_missing_status", res.status == MISSING, res.status)
    check("malformed_tab_carries_no_item", res.item is None)
    check("malformed_tab_is_refused", res.is_refused)


def test_malformed_newline_only_refused():
    """Newline-only variant must NOT reach UNIQUE_FAMILY_FALLBACK."""
    print("[M4] malformed: newline-only variant")
    entries = {("fam", "v1"): adapter_a}
    res = production_resolve("fam", "\n", entries)
    note("status", res.status)
    check("malformed_newline_is_missing_status", res.status == MISSING, res.status)
    check("malformed_newline_is_refused", res.is_refused)


def test_malformed_empty_family_has_no_fallback():
    """Even when the family has exactly one candidate, an empty variant
    does NOT silently fall back — it is refused."""
    print("[M5] malformed: empty variant with single-candidate family")
    entries = {("fam", "v99"): adapter_a}
    res = production_resolve("fam", "", entries)
    check("empty_var_single_candidate_still_missing",
          res.status == MISSING, res.status)
    check("empty_var_single_candidate_no_item", res.item is None)
    # Before the fix this was UNIQUE_FAMILY_FALLBACK with item=v99.


# ===========================================================================
# Negative controls — valid cases must still work
# ===========================================================================
def test_positive_exact_match_still_works():
    """Exact registered variant resolves as EXACT."""
    print("[P1] positive control: exact match")
    entries = {("fam", "v1"): adapter_a}
    res = production_resolve("fam", "v1", entries)
    note("status", res.status)
    check("exact_status", res.status == EXACT, res.status)
    check("exact_item", res.item is adapter_a)
    check("exact_require_returns", res.require() is adapter_a)
    check("exact_is_resolved", res.is_resolved)


def test_positive_unique_family_fallback_still_works():
    """Unknown-but-valid variant with single family candidate falls back."""
    print("[P2] positive control: unique family fallback")
    entries = {("fam", "v1"): adapter_a}
    res = production_resolve("fam", "vUNKNOWN", entries)
    note("status", res.status)
    check("fallback_status", res.status == UNIQUE_FAMILY_FALLBACK, res.status)
    check("fallback_item", res.item is adapter_a)
    check("fallback_resolved_variant", res.resolved_variant == "v1")
    check("fallback_is_resolved", res.is_resolved)
    check("fallback_provenance_mentions_fallback",
          "UNIQUE_FAMILY_FALLBACK" in res.provenance)


def test_positive_ambiguous_still_refused():
    """Multiple candidates with unknown variant -> AMBIGUOUS, refused."""
    print("[P3] positive control: ambiguous")
    entries = {("fam", "vA"): adapter_a, ("fam", "vB"): adapter_b}
    res = production_resolve("fam", "vX", entries)
    note("status", res.status)
    check("ambiguous_status", res.status == AMBIGUOUS, res.status)
    check("ambiguous_no_item", res.item is None)
    check("ambiguous_is_refused", res.is_refused)
    raised = None
    try:
        res.require()
    except ResolutionRefused:
        raised = True
    check("ambiguous_require_raises", raised)


def test_positive_missing_still_refused():
    """Zero candidates -> MISSING, refused."""
    print("[P4] positive control: missing")
    res = production_resolve("fam", "v1", {})
    note("status", res.status)
    check("missing_status", res.status == MISSING, res.status)
    check("missing_no_item", res.item is None)
    check("missing_is_refused", res.is_refused)


def test_positive_non_empty_trailing_space_is_not_malformed():
    """A variant with trailing space is NOT empty-after-strip in the sense of
    being malformed — wait, it IS whitespace-insensitive? No. The contract does
    NOT normalise whitespace. So 'v1 ' is treated as the literal string 'v1 ',
    which is NOT registered -> goes to fallback/ambiguous/missing like any other
    unknown variant. It is NOT refused as malformed because it is non-empty
    before strip."""
    print("[P5] positive control: non-empty variant with trailing space")
    entries = {("fam", "v1"): adapter_a}
    res = production_resolve("fam", "v1 ", entries)
    note("status", res.status)
    # "v1 " is not registered, but the family has one candidate -> fallback
    check("trailing_space_is_not_malformed",
          res.status != MISSING or "MALFORMED_VARIANT" not in res.provenance,
          res.status + ": " + res.provenance)


# ===========================================================================
# Main
# ===========================================================================
def main():
    test_malformed_empty_string_refused()
    test_malformed_whitespace_only_refused()
    test_malformed_tab_only_refused()
    test_malformed_newline_only_refused()
    test_malformed_empty_family_has_no_fallback()
    test_positive_exact_match_still_works()
    test_positive_unique_family_fallback_still_works()
    test_positive_ambiguous_still_refused()
    test_positive_missing_still_refused()
    test_positive_non_empty_trailing_space_is_not_malformed()
    print()
    if FAILURES:
        print("RESULT: FAIL (%d)" % len(FAILURES))
        for f in FAILURES:
            print("  FAIL:", f)
        return 1
    print("RESULT: PASS -- all malformed-variant cases held")
    return 0


# ===========================================================================
# unittest discovery adapter  (added by the 16BK coordinator)
# ===========================================================================
# This file was written with plain `assert`-style functions plus a `main()`,
# which `python -m unittest discover` CANNOT see: discovery collected 0 tests
# from it, so the F11 fix was unprotected in the project's normal suite while
# its own direct run reported 30 passing checks.  That is the "verify
# artifacts, not exit codes" failure in miniature -- the tests passed but
# nothing would ever run them again.
#
# The adapter below registers each check as a real TestCase.  It does NOT
# re-implement any check: it calls the same functions, so the two runners
# cannot drift apart.  `main()` is retained unchanged for a direct run.
import unittest as _unittest


class TestResolverMalformedVariant(_unittest.TestCase):
    """Discoverable wrapper over the checks above."""

    def _run(self, fn):
        # The check functions raise AssertionError on failure; a non-empty
        # FAILURES list is also fatal, so a silently-appended failure cannot
        # be missed by the adapter.
        before = len(FAILURES)
        fn()
        self.assertEqual(len(FAILURES), before,
                         "check appended to FAILURES: %r" % (FAILURES[before:],))

    def test_00_no_preexisting_failures(self):
        self.assertEqual(list(FAILURES), [],
                         "a check failed at import time: %r" % (FAILURES,))

    def test_malformed_empty_string_refused(self):
        self._run(test_malformed_empty_string_refused)

    def test_malformed_whitespace_only_refused(self):
        self._run(test_malformed_whitespace_only_refused)

    def test_malformed_tab_only_refused(self):
        self._run(test_malformed_tab_only_refused)

    def test_malformed_newline_only_refused(self):
        self._run(test_malformed_newline_only_refused)

    def test_malformed_empty_family_has_no_fallback(self):
        self._run(test_malformed_empty_family_has_no_fallback)

    def test_positive_exact_match_still_works(self):
        self._run(test_positive_exact_match_still_works)

    def test_positive_unique_family_fallback_still_works(self):
        self._run(test_positive_unique_family_fallback_still_works)

    def test_positive_ambiguous_still_refused(self):
        self._run(test_positive_ambiguous_still_refused)

    def test_positive_missing_still_refused(self):
        self._run(test_positive_missing_still_refused)

    def test_positive_non_empty_trailing_space_is_not_malformed(self):
        self._run(test_positive_non_empty_trailing_space_is_not_malformed)


if __name__ == "__main__":
    sys.exit(main())
