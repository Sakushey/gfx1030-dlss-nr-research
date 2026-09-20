"""Host-only tests for the publication sync helper.

Every test drives a throwaway public repo and source root created under a
temporary directory. Nothing here reads or writes the real private research
tree, and nothing here uses the real publication manifest except the suffix
coverage check, which is meant to police the real one.

Each rejection-oriented case has a companion case that must be accepted, so a
helper that simply rejected everything would fail this suite rather than pass
it.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import hostpath

REPO = Path(hostpath.REPO_ROOT)
HELPER_SRC = REPO / "scripts" / "prepare_publication_sync.py"


def _load_helper():
    spec = importlib.util.spec_from_file_location("pps_under_test", HELPER_SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


HELPER = _load_helper()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entry(src_rel, src_bytes, dst_rel, pub_bytes,
          category="PUBLIC_ORIGINAL_TOOLING", modification="none"):
    return {
        "source_path": src_rel,
        "public_path": dst_rel,
        "source_sha256": sha(src_bytes),
        "public_sha256": sha(pub_bytes),
        "source_bytes": len(src_bytes),
        "bytes": len(pub_bytes),
        "publication_category": category,
        "modifications": modification,
    }


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


class Fixture:
    """An isolated public repo plus an isolated private source root."""

    def __init__(self, tmpdir, entries, pub_blobs, src_blobs,
                 verifier_rc=0, branch="publication-sync/test"):
        self.pub = Path(tmpdir) / "pub"
        self.src = Path(tmpdir) / "src"
        (self.pub / "audit").mkdir(parents=True)
        (self.pub / "scripts").mkdir(parents=True)
        for rel, data in pub_blobs.items():
            p = self.pub / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        for rel, data in src_blobs.items():
            p = self.src / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        (self.pub / "audit" / "PUBLICATION_MANIFEST.json").write_text(
            json.dumps({"files": entries}, indent=1), encoding="utf-8")
        shutil.copy(HELPER_SRC, self.pub / "scripts" / "prepare_publication_sync.py")
        (self.pub / "scripts" / "verify_publication.py").write_text(
            f"import sys\nsys.exit({verifier_rc})\n", encoding="utf-8")

        _git(self.pub, "init", "-b", "main")
        _git(self.pub, "config", "user.email", "test@example.invalid")
        _git(self.pub, "config", "user.name", "T")
        _git(self.pub, "add", "-A")
        _git(self.pub, "commit", "-m", "init")
        head = _git(self.pub, "rev-parse", "HEAD").stdout.strip()
        _git(self.pub, "update-ref", "refs/remotes/origin/main", head)
        if branch != "main":
            _git(self.pub, "checkout", "-b", branch)
        self.manifest_path = self.pub / "audit" / "PUBLICATION_MANIFEST.json"

    def run(self, *extra):
        return subprocess.run(
            [sys.executable,
             str(self.pub / "scripts" / "prepare_publication_sync.py"),
             "--source-root", str(self.src), *extra],
            cwd=self.pub, capture_output=True, text=True,
        )

    @staticmethod
    def parse(proc):
        return json.loads(proc.stdout[proc.stdout.index("{"):])


class SyncTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)

    def make(self, entries, pub_blobs, src_blobs, **kw):
        return Fixture(self._tmp.name, entries, pub_blobs, src_blobs, **kw)

    def simple(self, old_src=b"x = 1\n", new_src=None, pub_bytes=b"x = 1\n", **kw):
        """One mapped file.

        `old_src` is what the manifest records; `new_src` is what the source
        root actually contains now. They differ only when a change is wanted.
        """
        if new_src is None:
            new_src = old_src
        e = entry("phase/tool.py", old_src, "tools/tool.py", pub_bytes)
        return self.make([e], {"tools/tool.py": pub_bytes},
                         {"phase/tool.py": new_src}, **kw)


class TestBasicStates(SyncTestBase):
    def test_T01_unchanged_mapped_files_is_none(self):
        fx = self.simple()
        p = fx.run()
        self.assertEqual(0, p.returncode)
        out = Fixture.parse(p)
        self.assertEqual("PUBLICATION_SYNC_NONE", out["publication_state"])
        self.assertEqual(0, out["changed"])
        self.assertEqual([], out["blockers"])

    def test_T02_bat_mapping_is_accepted(self):
        body = b"@echo off\r\nrem build\r\n"
        e = entry("phase10/tools/build.bat", body, "src/tools/build.bat", body)
        fx = self.make([e], {"src/tools/build.bat": body},
                       {"phase10/tools/build.bat": body})
        out = Fixture.parse(fx.run())
        self.assertEqual([], out["blockers"])
        self.assertEqual("PUBLICATION_SYNC_NONE", out["publication_state"])

    def test_T03_safe_mapped_change_is_pending(self):
        fx = self.simple(new_src=b"x = 2\n")
        out = Fixture.parse(fx.run())
        self.assertEqual(1, out["changed"])
        self.assertEqual("PUBLICATION_SYNC_PENDING", out["publication_state"])
        self.assertEqual([], out["blockers"])

    def test_T04_secret_like_change_is_blocked(self):
        secret = b"token = \"" + b"ghp_" + b"A" * 36 + b"\"\n"
        fx = self.simple(new_src=secret)
        p = fx.run()
        self.assertEqual(2, p.returncode)
        out = Fixture.parse(p)
        self.assertEqual("PUBLICATION_SYNC_BLOCKED", out["publication_state"])
        self.assertTrue(any("secret-like" in b for b in out["blockers"]))
        # the matched value must not be echoed
        self.assertNotIn("ghp_", p.stdout)

    def test_T05_personal_absolute_path_is_blocked(self):
        body = b"see C:\\Users\\realperson\\notes.txt\n"
        fx = self.simple(new_src=body)
        out = Fixture.parse(fx.run())
        self.assertEqual("PUBLICATION_SYNC_BLOCKED", out["publication_state"])
        self.assertTrue(any("personal/machine" in b for b in out["blockers"]))

    def test_T05b_benign_placeholder_is_accepted(self):
        # companion valid case: the same shape with a placeholder must pass
        body = b"see C:/Users/<user>/notes.txt\n"
        fx = self.simple(new_src=body)
        out = Fixture.parse(fx.run())
        self.assertEqual([], out["blockers"])
        self.assertEqual("PUBLICATION_SYNC_PENDING", out["publication_state"])

    def test_T06_public_file_hash_drift_is_blocked(self):
        e = entry("phase/tool.py", b"x = 1\n", "tools/tool.py", b"x = 1\n")
        e["public_sha256"] = sha(b"something else entirely\n")
        fx = self.make([e], {"tools/tool.py": b"x = 1\n"},
                       {"phase/tool.py": b"x = 1\n"})
        out = Fixture.parse(fx.run())
        self.assertEqual("PUBLICATION_SYNC_BLOCKED", out["publication_state"])
        self.assertTrue(any("drifted" in b for b in out["blockers"]))

    def test_T08_unapproved_extension_is_blocked(self):
        e = entry("phase/tool.exe", b"MZ\n", "tools/tool.exe", b"MZ\n")
        fx = self.make([e], {"tools/tool.exe": b"MZ\n"},
                       {"phase/tool.exe": b"MZ\n"})
        out = Fixture.parse(fx.run())
        self.assertEqual("PUBLICATION_SYNC_BLOCKED", out["publication_state"])
        self.assertTrue(any("suffix is not eligible" in b for b in out["blockers"]))


class TestNewFilePolicy(SyncTestBase):
    def test_T07_unmapped_new_file_is_not_auto_published(self):
        fx = self.simple(new_src=b"x = 2\n")
        # a brand-new private file that is NOT in the manifest
        (fx.src / "phase" / "brand_new.py").write_bytes(b"NEW = True\n")
        p = fx.run("--apply")
        self.assertEqual(0, p.returncode)
        self.assertFalse((fx.pub / "phase" / "brand_new.py").exists())
        self.assertFalse((fx.pub / "brand_new.py").exists())
        # only the approved mapping was refreshed
        self.assertEqual(b"x = 2\n", (fx.pub / "tools" / "tool.py").read_bytes())


class TestStatusDrift(SyncTestBase):
    def _with_status(self):
        fx = self.simple()
        status = fx.src / "SESSION_REPORT.md"
        status.write_bytes(b"# report v1\n")
        return fx, status

    def test_T09_status_change_is_pending(self):
        fx, status = self._with_status()
        out = Fixture.parse(fx.run("--status-file", str(status)))
        self.assertTrue(out["status_drift"])
        self.assertEqual("PUBLICATION_SYNC_PENDING", out["publication_state"])
        # neither the hash nor the private path may appear
        p = fx.run("--status-file", str(status))
        self.assertNotIn("sha256", p.stdout.lower().replace("status_file", ""))
        self.assertNotIn(str(status), p.stdout)

    def test_T10_mark_reviewed_then_none(self):
        fx, status = self._with_status()
        m = fx.run("--status-file", str(status), "--mark-status-reviewed")
        self.assertEqual(0, m.returncode, m.stderr)
        self.assertNotIn(str(status), m.stdout)
        out = Fixture.parse(fx.run("--status-file", str(status)))
        self.assertFalse(out["status_drift"])
        self.assertEqual("PUBLICATION_SYNC_NONE", out["publication_state"])

    def test_T10b_edited_status_after_review_is_pending_again(self):
        fx, status = self._with_status()
        fx.run("--status-file", str(status), "--mark-status-reviewed")
        status.write_bytes(b"# report v2\n")
        out = Fixture.parse(fx.run("--status-file", str(status)))
        self.assertTrue(out["status_drift"])
        self.assertEqual("PUBLICATION_SYNC_PENDING", out["publication_state"])
        # the tracked tree is untouched by any of this
        self.assertEqual("", _git(fx.pub, "status", "--porcelain").stdout.strip())

    def test_T11_state_lives_only_under_git(self):
        fx, status = self._with_status()
        fx.run("--status-file", str(status), "--mark-status-reviewed")
        state = fx.pub / ".git" / "publication-sync-state.json"
        self.assertTrue(state.is_file())
        recorded = json.loads(state.read_text(encoding="utf-8"))["reviewed_status_sha256"]
        tracked = _git(fx.pub, "ls-files").stdout
        self.assertNotIn("publication-sync-state.json", tracked)
        # the recorded hash must not appear anywhere in the worktree
        for path in fx.pub.rglob("*"):
            if ".git" in path.parts or not path.is_file():
                continue
            self.assertNotIn(recorded, path.read_text(encoding="utf-8", errors="ignore"),
                             f"{path} leaked the status fingerprint")


class TestApplyHygiene(SyncTestBase):
    def test_T12_apply_on_main_is_refused(self):
        fx = self.simple(new_src=b"x = 2\n", branch="main")
        p = fx.run("--apply")
        self.assertEqual(4, p.returncode)
        self.assertIn("APPLY_REFUSED", p.stderr)
        # nothing was written
        self.assertEqual(b"x = 1\n", (fx.pub / "tools" / "tool.py").read_bytes())

    def test_T13_apply_on_publication_branch_is_allowed(self):
        fx = self.simple(new_src=b"x = 2\n")
        p = fx.run("--apply")
        self.assertEqual(0, p.returncode, p.stderr)
        self.assertEqual(b"x = 2\n", (fx.pub / "tools" / "tool.py").read_bytes())
        man = json.loads(fx.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(sha(b"x = 2\n"), man["files"][0]["public_sha256"])

    def test_T14_verifier_failure_rolls_back_completely(self):
        fx = self.simple(new_src=b"x = 2\n", verifier_rc=1)
        before_pub = (fx.pub / "tools" / "tool.py").read_bytes()
        before_man = fx.manifest_path.read_bytes()
        p = fx.run("--apply")
        self.assertEqual(3, p.returncode)
        self.assertIn("APPLY_ROLLED_BACK", p.stderr)
        self.assertEqual(before_pub, (fx.pub / "tools" / "tool.py").read_bytes())
        self.assertEqual(before_man, fx.manifest_path.read_bytes())
        self.assertEqual("", _git(fx.pub, "status", "--porcelain").stdout.strip())

    def test_T15_crlf_transform_reproduces_manifest_semantics(self):
        crlf = b"a = 1\r\nb = 2\r\n"
        lf = b"a = 1\nb = 2\n"
        e = entry("phase/tool.py", crlf, "tools/tool.py", lf,
                  modification="line endings normalised CRLF -> LF")
        fx = self.make([e], {"tools/tool.py": lf}, {"phase/tool.py": crlf})
        out = Fixture.parse(fx.run())
        self.assertEqual("PUBLICATION_SYNC_NONE", out["publication_state"])
        self.assertEqual(0, out["changed"])

    def test_T15b_crlf_transform_applies_the_declared_normalisation(self):
        crlf1 = b"a = 1\r\n"
        lf1 = b"a = 1\n"
        crlf2 = b"a = 2\r\n"
        e = entry("phase/tool.py", crlf1, "tools/tool.py", lf1,
                  modification="line endings normalised CRLF -> LF")
        fx = self.make([e], {"tools/tool.py": lf1}, {"phase/tool.py": crlf2})
        p = fx.run("--apply")
        self.assertEqual(0, p.returncode, p.stderr)
        self.assertEqual(b"a = 2\n", (fx.pub / "tools" / "tool.py").read_bytes())


class TestSuffixCoverage(unittest.TestCase):
    """The helper must never ship with an approved mapped type it refuses."""

    @staticmethod
    def uncovered(mapped, safe):
        return sorted(mapped - safe)

    def test_T16_every_mapped_suffix_is_auto_sync_eligible(self):
        man = json.loads(
            (REPO / "audit" / "PUBLICATION_MANIFEST.json").read_text(encoding="utf-8")
        )
        mapped = {os.path.splitext(e["public_path"])[1].lower()
                  for e in man["files"]}
        self.assertTrue(mapped, "manifest mapped no files")
        missing = self.uncovered(mapped, HELPER.SAFE_SUFFIXES)
        self.assertEqual(
            [], missing,
            f"mapped suffixes the helper would refuse: {missing}",
        )

    def test_T16b_coverage_check_can_actually_fail(self):
        # negative control: the same check must reject an unapproved extension
        self.assertEqual([".wat"], self.uncovered({".py", ".wat"},
                                                  HELPER.SAFE_SUFFIXES))


if __name__ == "__main__":
    unittest.main()
