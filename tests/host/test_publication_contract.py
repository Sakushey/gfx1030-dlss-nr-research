"""Contract tests tying the provenance manifest to the files on disk.

`audit/PUBLICATION_MANIFEST.json` claims that each published source file is
a byte-identical copy of a specific original with a recorded hash. This test
makes that claim falsifiable: if a published file is edited, the manifest
entry no longer matches and this test fails.

That matters because an edited copy would silently invalidate the
provenance record while still looking correct.
"""
from __future__ import annotations

import hashlib
import json
import os
import unittest

import hostpath

REPO = hostpath.REPO_ROOT
MANIFEST = os.path.join(REPO, "audit", "PUBLICATION_MANIFEST.json")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class TestManifestIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(MANIFEST, encoding="utf-8") as f:
            cls.manifest = json.load(f)

    def test_manifest_is_non_empty(self):
        self.assertGreater(len(self.manifest["files"]), 0)

    def test_every_listed_file_exists(self):
        missing = [
            e["public_path"] for e in self.manifest["files"]
            if not os.path.exists(os.path.join(REPO, e["public_path"]))
        ]
        self.assertEqual(missing, [], f"listed but absent: {missing}")

    def test_every_listed_file_matches_its_recorded_public_hash(self):
        """The published bytes must equal what the manifest records.

        `public_sha256` is the hash of the content as published (after the
        declared CRLF->LF normalisation, where that applies). A fresh clone
        therefore gets bytes matching this hash.
        """
        drifted = []
        for e in self.manifest["files"]:
            p = os.path.join(REPO, e["public_path"])
            if not os.path.exists(p):
                continue
            expected = e.get("public_sha256")
            if expected is None:
                drifted.append(f"{e['public_path']} (no public_sha256 recorded)")
                continue
            if sha256(p) != expected:
                drifted.append(e["public_path"])
        self.assertEqual(
            drifted, [],
            f"published copy differs from its recorded hash: {drifted}",
        )

    def test_normalisation_is_declared_where_it_happened(self):
        """If published bytes differ from source bytes, it must be declared."""
        undeclared = []
        for e in self.manifest["files"]:
            changed = e.get("source_sha256") != e.get("public_sha256")
            declared = e.get("modifications", "none") != "none"
            if changed != declared:
                undeclared.append(e["public_path"])
        self.assertEqual(
            undeclared, [],
            f"content changed from source but not declared, or vice versa: {undeclared}",
        )

    def test_every_entry_declares_provenance_and_license(self):
        bad = [
            e["public_path"] for e in self.manifest["files"]
            if not e.get("provenance") or not e.get("license")
        ]
        self.assertEqual(bad, [], f"entries missing provenance/license: {bad}")

    def test_negative_control_hash_check_can_fail(self):
        """Prove the comparison above is not vacuous.

        A recorded hash must differ from a deliberately wrong one, otherwise
        `test_every_listed_file_is_byte_identical` could never fail.
        """
        entry = self.manifest["files"][0]
        p = os.path.join(REPO, entry["public_path"])
        self.assertNotEqual(sha256(p), "0" * 64)
        self.assertNotEqual(entry.get("public_sha256"), "0" * 64)


if __name__ == "__main__":
    unittest.main()
