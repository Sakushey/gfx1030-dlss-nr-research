"""Host-only tests for the immutable-action-reference check.

A workflow pinned to a movable tag such as `@v7` can be re-pointed upstream at
any time, so the tag no longer identifies the code that ran. These tests make
the check falsifiable: a tag reference must FAIL, a full commit SHA must PASS,
and the repository's own workflows must all be pinned.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

import hostpath

REPO = Path(hostpath.REPO_ROOT)
VERIFIER_SRC = REPO / "scripts" / "verify_publication.py"

PINNED_CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
PINNED_SETUP = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"


def _load_verifier():
    spec = importlib.util.spec_from_file_location("vp_under_test", VERIFIER_SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


VP = _load_verifier()


def problems_for(text: str) -> list[str]:
    return VP.action_ref_problems(".github/workflows/x.yml", text)


class TestActionRefPinning(unittest.TestCase):
    def test_movable_tag_is_rejected(self):
        # negative control: this is exactly the regression to prevent
        problems = problems_for("      - uses: actions/checkout@v7\n")
        self.assertEqual(1, len(problems))
        self.assertIn("not pinned", problems[0])

    def test_full_sha_is_accepted(self):
        # companion valid case
        self.assertEqual([], problems_for(f"      - uses: {PINNED_CHECKOUT}\n"))

    def test_sha_with_trailing_version_comment_is_accepted(self):
        self.assertEqual(
            [], problems_for(f"      - uses: {PINNED_CHECKOUT} # v7\n")
        )

    def test_local_action_is_exempt(self):
        self.assertEqual(
            [], problems_for("      - uses: ./.github/actions/build\n")
        )

    def test_branch_reference_is_rejected(self):
        self.assertEqual(1, len(problems_for("        uses: owner/repo@main\n")))

    def test_reference_with_no_ref_at_all_is_rejected(self):
        self.assertEqual(1, len(problems_for("        uses: owner/repo\n")))

    def test_check_actually_ran_over_the_real_workflows(self):
        """Guard against a vacuous pass: the real workflows must be inspected.

        If the workflow path filter were wrong, the check would report success
        while reading nothing.
        """
        workflows = sorted((REPO / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(workflows, "no workflows found to check")
        seen = 0
        for wf in workflows:
            text = wf.read_text(encoding="utf-8")
            seen += sum(1 for line in text.splitlines()
                        if VP.ACTION_REF_RX.match(line))
        self.assertGreater(seen, 0, "no `uses:` references were parsed")

    def test_every_real_workflow_action_is_pinned(self):
        for wf in sorted((REPO / ".github" / "workflows").glob("*.yml")):
            rel = f".github/workflows/{wf.name}"
            self.assertEqual(
                [], VP.action_ref_problems(rel, wf.read_text(encoding="utf-8")),
                f"{rel} has an unpinned action reference",
            )


if __name__ == "__main__":
    unittest.main()
