"""Regression tests for the publication privacy scanner."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

import hostpath

REPO = Path(hostpath.REPO_ROOT)
VERIFIER = REPO / "scripts" / "verify_publication.py"


def _load_verifier():
    spec = importlib.util.spec_from_file_location("verify_publication_under_test", VERIFIER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


AUDIT = _load_verifier()


class TestPublicationPrivacyPatterns(unittest.TestCase):
    def test_windows_user_path_catches_filesystem_and_escaped_source_forms(self):
        slash = bytes((92,))
        plain = b"C:" + slash + b"Users" + slash + b"alice" + slash + b"project"
        escaped = b"C:" + slash * 2 + b"Users" + slash * 2 + b"alice" + slash * 2 + b"project"
        rx = AUDIT.PERSONAL_PATTERNS["windows_user_path"]
        self.assertIsNotNone(rx.search(plain))
        self.assertIsNotNone(rx.search(escaped))

    def test_windows_user_path_keeps_placeholder_forms_allowed(self):
        slash = bytes((92,))
        placeholder = b"C:" + slash * 2 + b"Users" + slash * 2 + b"<user>" + slash * 2 + b"project"
        rx = AUDIT.PERSONAL_PATTERNS["windows_user_path"]
        self.assertIsNone(rx.search(placeholder))


if __name__ == "__main__":
    unittest.main()
