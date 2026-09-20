"""Every published host module must import cleanly.

The modules were developed as one flat import namespace. If a cross-module
import ever stops resolving, the published extraction has broken, and that
should fail loudly here rather than at the point a contributor tries to use
it.
"""
from __future__ import annotations

import importlib
import os
import pathlib
import unittest

import hostpath

REPO = pathlib.Path(hostpath.REPO_ROOT)
GROUPS = ("emulator", "oracle", "isa")


def published_modules():
    mods = []
    for g in GROUPS:
        for p in sorted((REPO / "src" / g).glob("*.py")):
            if p.stem.startswith("_"):
                continue
            mods.append(p.stem)
    return mods


class TestImportSmoke(unittest.TestCase):
    def test_src_groups_are_populated(self):
        for g in GROUPS:
            with self.subTest(group=g):
                n = len(list((REPO / "src" / g).glob("*.py")))
                self.assertGreater(n, 0, f"src/{g} has no modules")

    def test_every_published_module_imports(self):
        failures = []
        mods = published_modules()
        self.assertGreater(len(mods), 0)
        for m in mods:
            try:
                importlib.import_module(m)
            except Exception as e:  # noqa: BLE001
                failures.append(f"{m}: {type(e).__name__}: {e}")
        self.assertEqual(failures, [], "import failures: " + "; ".join(failures))

    def test_negative_control_import_check_can_fail(self):
        """The import check above must be able to fail."""
        with self.assertRaises(ImportError):
            importlib.import_module("this_module_does_not_exist_xyz")


if __name__ == "__main__":
    unittest.main()
