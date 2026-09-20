"""Host-only regression for `scripts/run_test.ps1`.

The launcher had three defects, and each gets a check here:

  F1a  it resolved the fixture source next to *itself* -- `Join-Path $Here
       "soft_wmma_test.cpp"` -- while the source lives in `tests\\` and the
       script lives in `scripts\\`. The script therefore refused to run at all,
       reporting a missing file one directory away from the real one.
  F1b  the HIP root was a hardcoded literal with no override, so a second
       ROCm installation could not be selected and a moved/renamed install
       could not be addressed without editing the script.
  F1c  Visual Studio was discovered only through the `MSFT_VSInstance` WMI
       class. That class is not registered on every host -- it raises
       "Invalid class" on this one -- so the script concluded that no C++
       compiler was installed on a machine that has one.

A fourth requirement is layered on top: a `-BuildOnly` mode that resolves
dependencies, finds the toolchain and compiles, and then stops *before* any
device is enumerated or the produced executable is invoked.

The negative controls are real rather than narrated:

  * the pre-fix revision of the script is read back with `git show` and run
    against a scratch repository laid out the same way. It must fail, and it
    must fail at the source-path check -- which in that revision precedes
    every device call, so running it cannot reach the GPU. That ordering is
    asserted statically first, which is what makes the execution safe.
  * `Get-CimInstance MSFT_VSInstance` is attempted directly and its failure
    is recorded, which is the evidence that F1c could not have been fixed by
    keeping the WMI class as the only mechanism.

Nothing here launches a kernel. The only execution is `-BuildOnly`, whose
whole contract is that it stops before the device is touched.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest

import hostpath  # noqa: F401  (sets up the import namespace)

REPO = hostpath.REPO_ROOT
SCRIPT = os.path.join(REPO, "scripts", "run_test.ps1")
REL = "scripts/run_test.ps1"
DEFAULT_HIP_ROOT = os.path.join(
    os.environ.get("ProgramFiles", r"C:\Program Files"), "AMD", "ROCm", "6.4")
CLANG = os.path.join(DEFAULT_HIP_ROOT, "bin", "clang++.exe")

POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")


def read_script() -> str:
    with open(SCRIPT, encoding="utf-8") as f:
        return f.read()


def git_show(rev_path: str):
    """Return the file's content at `rev_path` (e.g. 'HEAD:scripts/run_test.ps1')."""
    try:
        p = subprocess.run(["git", "show", rev_path], cwd=REPO,
                           capture_output=True, text=True, timeout=60)
    except Exception as exc:                          # pragma: no cover
        return None, f"git show failed: {exc}"
    if p.returncode != 0:
        return None, p.stderr.strip()
    return p.stdout, "ok"


def ps(script_text: str, timeout: int = 300):
    """Run a PowerShell script from a scratch file; return (rc, output).

    Output is decoded with `errors="replace"` on purpose. PowerShell writes
    its diagnostics in the console codepage, which on a non-English host is
    not UTF-8, and a strict decode raises inside subprocess's reader thread --
    which silently truncates stdout at the offending byte rather than
    failing, so the caller sees a short string and a confusing assertion.
    Replacing the undecodable byte keeps the ASCII the assertions look for.
    """
    if POWERSHELL is None:                            # pragma: no cover
        return None, "no powershell on PATH"
    with tempfile.TemporaryDirectory(prefix="psrun-") as work:
        path = os.path.join(work, "run.ps1")
        with open(path, "w", encoding="utf-8", newline="\r\n") as f:
            f.write(script_text)
        p = subprocess.run(
            [POWERSHELL, "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", path],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")


def parse_check(path: str):
    """Parse a PowerShell file without executing it."""
    if POWERSHELL is None:                            # pragma: no cover
        return None, "no powershell on PATH"
    # $errs/$tokens must be declared first: [ref] on an undeclared variable
    # is itself an error, which would be misread as a parse failure.
    probe = ("$errs = $null; $tokens = $null; "
             "[System.Management.Automation.Language.Parser]::ParseFile("
             f"'{path}', [ref]$tokens, [ref]$errs) | Out-Null; "
             "if ($errs.Count -eq 0) { 'PARSE_OK' } else { "
             "$errs | ForEach-Object { $_.Message } }")
    return ps(probe, timeout=120)


class TestLauncherSource(unittest.TestCase):
    """Properties checkable without running anything."""

    def setUp(self):
        self.text = read_script()

    def test_script_exists(self):
        self.assertTrue(os.path.exists(SCRIPT), SCRIPT)

    def test_script_parses(self):
        """A parse error is a launcher that cannot start at all.

        This is the check that catches the `$candidate:` class of defect: a
        bare variable followed by a colon parses as a scoped reference and is
        a hard parse error, not a warning.
        """
        rc, out = parse_check(SCRIPT)
        if rc is None:                                # pragma: no cover
            self.skipTest(out)
        self.assertIn("PARSE_OK", out, out.strip()[:1500])

    # ------------------------------------------------------------------ F1a
    def test_source_resolves_under_tests_not_next_to_the_script(self):
        """The defect verbatim: source next to the script directory."""
        self.assertIn('Join-Path $Repo "tests\\soft_wmma_test.cpp"', self.text)
        self.assertNotIn('Join-Path $Here "soft_wmma_test.cpp"', self.text)

    def test_repo_root_is_the_parent_of_the_script_directory(self):
        self.assertIn("$Here    = Split-Path -Parent $MyInvocation.MyCommand.Path",
                      self.text)
        self.assertIn("$Repo    = Split-Path -Parent $Here", self.text)

    def test_default_source_exists_on_disk(self):
        """The default path the script computes must name a real file."""
        self.assertTrue(os.path.exists(os.path.join(REPO, "tests",
                                                    "soft_wmma_test.cpp")))

    # ------------------------------------------------------------------ F1b
    def test_hip_root_is_configurable(self):
        self.assertIn("[string]$HipRoot", self.text)
        self.assertIn("$env:GFX1030_HIP_ROOT", self.text)

    def test_hip_root_has_a_safe_default_and_no_path_inference(self):
        self.assertIn('$DefaultHipRoot = Join-Path ${env:ProgramFiles} '
                      '"AMD\\ROCm\\6.4"', self.text)
        # PATH must not be consulted for the root: two ROCm versions can be
        # installed at once, and clang++ on PATH is not necessarily the one
        # whose runtime the fixture loads.
        self.assertIsNone(re.search(r"HipRoot\s*=\s*\(?Get-Command", self.text))
        self.assertIsNone(re.search(r"HipRoot\s*=.*\bwhere\.exe\b", self.text))

    def test_default_hip_root_is_the_pinned_rocm_64(self):
        """Recorded because the project's runtime identity is ROCm 6.4."""
        self.assertIn("ROCm\\6.4", self.text)

    # ------------------------------------------------------------------ F1c
    def test_vs_discovery_has_all_three_layers(self):
        self.assertIn("function Get-VsInstallFromVswhere", self.text)
        self.assertIn("function Get-VsInstallFromWellKnownRoots", self.text)
        self.assertIn("function Get-VsInstallFromWmi", self.text)

    def test_wmi_is_the_last_resort_not_the_only_mechanism(self):
        m = re.search(r"\$strategies\s*=\s*\[ordered\]@\{(.*?)\n    \}",
                      self.text, re.S)
        self.assertIsNotNone(m, "strategy table not found")
        table = m.group(1)
        order = re.findall(r"'([^']+)'\s*=", table)
        self.assertEqual(order[-1], "MSFT_VSInstance",
                         f"MSFT_VSInstance is not last: {order}")
        self.assertIn("vswhere", order)
        self.assertIn("well-known-roots", order)

    def test_wmi_lookup_is_guarded_and_cannot_abort_the_script(self):
        """On this host the call raises; the script must survive that.

        An unguarded `Get-CimInstance MSFT_VSInstance` under
        `$ErrorActionPreference = "Stop"` terminates the script, which is the
        mechanism by which the original concluded 'no compiler installed'.
        """
        m = re.search(r"function Get-VsInstallFromWmi\s*\{(.*?)\n\}", self.text,
                      re.S)
        self.assertIsNotNone(m, "Get-VsInstallFromWmi not found")
        body = m.group(1)
        self.assertIn("try", body)
        self.assertIn("catch", body)
        self.assertIn("return @()", body)

    def test_vswhere_is_locatable_from_the_installer_directory(self):
        self.assertIn("Microsoft Visual Studio\\Installer\\vswhere.exe",
                      self.text)

    def test_all_strategies_failing_is_a_loud_exit(self):
        self.assertIn("exit 10", self.text)

    # --------------------------------------------------------------- F1 -BuildOnly
    def test_buildonly_switch_is_declared(self):
        self.assertIn("[switch]$BuildOnly", self.text)

    def test_hipinfo_is_gated_on_not_buildonly(self):
        self.assertIn("if (-not $BuildOnly -and -not (Test-Path $HipInfo))",
                      self.text)

    def test_buildonly_stop_precedes_every_device_call(self):
        """Ordering, asserted positionally rather than by narration.

        The stop must appear after the compile and before the first `$HipInfo`
        invocation and before the first `& $Exe` execution. A stop that merely
        sets a flag while device code still runs is not a stop.
        """
        stop = self.text.find('if ($BuildOnly) {\n    Write-Host ""\n'
                              '    Write-Host "BUILD-ONLY')
        self.assertNotEqual(stop, -1, "no -BuildOnly stop block found")
        self.assertIn("exit 0", self.text[stop:stop + 300])

        hipinfo = self.text.find("& $HipInfo")
        run = self.text.find("\n& $Exe")
        compile_call = self.text.find("& $Clang @CompileArgs")
        self.assertNotEqual(hipinfo, -1)
        self.assertNotEqual(run, -1)
        self.assertNotEqual(compile_call, -1)
        self.assertLess(compile_call, stop, "stop precedes the compile")
        self.assertLess(stop, hipinfo, "-BuildOnly stop is after hipInfo")
        self.assertLess(stop, run, "-BuildOnly stop is after running the fixture")


class TestLauncherExecution(unittest.TestCase):
    """The checks that need the script to actually run."""

    def setUp(self):
        self.have_toolchain = os.path.exists(CLANG)

    def test_buildonly_compiles_and_stops_before_the_device(self):
        """-BuildOnly must produce an executable and touch no device.

        The output path is redirected into a scratch directory so the build
        artifact never lands in the repository: `verify_publication.py` fails
        closed on an untracked `.exe`.
        """
        if not self.have_toolchain:
            self.skipTest(f"no HIP toolchain at {CLANG}")
        with tempfile.TemporaryDirectory(prefix="buildonly-") as work:
            exe = os.path.join(work, "soft_wmma_test.exe")
            rc, out = ps(
                f"& '{SCRIPT}' -BuildOnly -Exe '{exe}'; exit $LASTEXITCODE")
            self.assertEqual(rc, 0, out[-4000:])
            self.assertTrue(os.path.exists(exe),
                            "no executable produced by -BuildOnly")
            self.assertTrue(os.path.getsize(exe) > 0)
            self.assertIn("BUILD-ONLY", out)

    def test_buildonly_reports_no_device_enumeration(self):
        if not self.have_toolchain:
            self.skipTest(f"no HIP toolchain at {CLANG}")
        with tempfile.TemporaryDirectory(prefix="buildonly-") as work:
            exe = os.path.join(work, "soft_wmma_test.exe")
            rc, out = ps(
                f"& '{SCRIPT}' -BuildOnly -Exe '{exe}'; exit $LASTEXITCODE")
            self.assertEqual(rc, 0, out[-4000:])
            for banner in ("DEVICE CHECK", "RUN ONE TINY GPU TILE"):
                self.assertNotIn(banner, out,
                                 f"-BuildOnly reached the {banner} section")
            self.assertNotIn("gcnArchName", out)

    def test_buildonly_leaves_no_artifact_in_the_repository(self):
        """The repository must be byte-identical after a -BuildOnly run."""
        if not self.have_toolchain:
            self.skipTest(f"no HIP toolchain at {CLANG}")
        before = subprocess.run(["git", "status", "--porcelain"], cwd=REPO,
                                capture_output=True, text=True).stdout
        with tempfile.TemporaryDirectory(prefix="buildonly-") as work:
            exe = os.path.join(work, "soft_wmma_test.exe")
            rc, out = ps(
                f"& '{SCRIPT}' -BuildOnly -Exe '{exe}'; exit $LASTEXITCODE")
            self.assertEqual(rc, 0, out[-4000:])
        after = subprocess.run(["git", "status", "--porcelain"], cwd=REPO,
                               capture_output=True, text=True).stdout
        self.assertEqual(before, after,
                         "a -BuildOnly run changed the working tree")

    def test_a_missing_hip_root_is_reported_not_ignored(self):
        """A bad -HipRoot must fail, not silently fall back to the default."""
        rc, out = ps(f"& '{SCRIPT}' -BuildOnly "
                     f"-HipRoot 'C:\\no\\such\\rocm'; exit $LASTEXITCODE")
        self.assertNotEqual(rc, 0, out[-2000:])
        self.assertIn("HIP root not found", out)


class TestNegativeControls(unittest.TestCase):
    """The pre-fix revision must fail the checks that describe the fix."""

    @classmethod
    def setUpClass(cls):
        cls.old, cls.why = git_show("HEAD:" + REL)

    def test_original_revision_is_available_to_control_against(self):
        self.assertIsNotNone(self.old, f"cannot read HEAD:{REL}: {self.why}")

    def test_original_uses_the_script_directory_for_the_source(self):
        """The defect, measured on the real previous revision."""
        self.assertIn('Join-Path $Here "soft_wmma_test.cpp"', self.old)
        self.assertNotIn('Join-Path $Repo "tests\\soft_wmma_test.cpp"', self.old)

    def test_original_has_no_buildonly_switch(self):
        self.assertNotIn("BuildOnly", self.old)

    def test_original_hardcodes_the_hip_root(self):
        self.assertRegex(self.old, r'HipRoot\s*=\s*"C:\\Program Files\\AMD\\ROCm')

    def test_original_uses_wmi_as_the_only_vs_mechanism(self):
        self.assertIn("MSFT_VSInstance", self.old)
        self.assertNotIn("vswhere", self.old)
        # Unguarded, and this file sets $ErrorActionPreference = "Stop".
        self.assertIn('$ErrorActionPreference = "Stop"', self.old)

    def test_original_checks_the_source_before_any_device_call(self):
        """Why running the original here cannot reach the GPU.

        The control below executes the pre-fix script. That is only safe
        because in that revision the source-existence check precedes every
        device call -- asserted here so the safety argument is a check rather
        than a recollection, and so this control starts failing loudly if that
        ordering ever changes.

        The device calls are `& $HipInfo` and `& $Exe` -- the *invocations*.
        Matching the bare name `hipInfo` would hit the `Test-Path $HipInfo`
        guard instead, which is a file-existence check and not a device call.
        """
        src = self.old.find("Source file not found")
        first_device = min(x for x in (
            self.old.find("& $HipInfo"), self.old.find("\n& $Exe"),
        ) if x != -1)
        self.assertNotEqual(src, -1, "no source check in the original")
        self.assertLess(src, first_device,
                        "the original's source check is after a device call")

    def test_negative_control_the_original_script_fails_to_launch(self):
        """Run the original in a scratch repo laid out identically.

        `tests/soft_wmma_test.cpp` exists and `scripts/` holds only the old
        launcher, exactly as before the fix. The old launcher must fail -- and
        with the source-path error, not with anything else.
        """
        if self.old is None:                          # pragma: no cover
            self.skipTest(self.why)
        with tempfile.TemporaryDirectory(prefix="oldlaunch-") as work:
            os.makedirs(os.path.join(work, "scripts"))
            os.makedirs(os.path.join(work, "tests"))
            shutil.copy(os.path.join(REPO, "tests", "soft_wmma_test.cpp"),
                        os.path.join(work, "tests", "soft_wmma_test.cpp"))
            with open(os.path.join(work, "scripts", "run_test.ps1"), "w",
                      encoding="utf-8", newline="\r\n") as f:
                f.write(self.old)
            # No real HIP root is needed: in the original the source check
            # runs BEFORE the device phase, so the run never gets that far.
            rc, out = ps(f"& '{os.path.join(work, 'scripts', 'run_test.ps1')}'; "
                         "exit $LASTEXITCODE")
            self.assertNotEqual(rc, 0,
                                "the pre-fix launcher unexpectedly succeeded")
            self.assertIn("Source file not found", out)
            # It must have failed at the path check, having looked next to
            # itself rather than in tests\.
            self.assertIn(os.path.join(work, "scripts", "soft_wmma_test.cpp"), out)
            self.assertNotIn("DEVICE CHECK", out)
            self.assertNotIn("RUN ONE TINY GPU TILE", out)

    def test_negative_control_the_wmi_class_may_be_unavailable(self):
        """Measure the mechanism behind F1c rather than asserting it.

        The claim is that `MSFT_VSInstance` is not dependable. On a host where
        the class *is* registered this test reports the other outcome, which
        is itself information: it means the defect is latent here rather than
        active. Either way the class must not be the only mechanism, which is
        what the layering test above enforces.
        """
        if POWERSHELL is None:                        # pragma: no cover
            self.skipTest("no powershell on PATH")
        rc, out = ps("$ErrorActionPreference='Stop'; try { "
                     "$i = Get-CimInstance MSFT_VSInstance -ErrorAction Stop; "
                     "'WMI_OK ' + @($i).Count } catch { 'WMI_UNAVAILABLE' }",
                     timeout=120)
        if rc is None:                                # pragma: no cover
            self.skipTest(out)
        ok = "WMI_OK" in out
        print(f"[F1c] MSFT_VSInstance query outcome: "
              f"{'available' if ok else 'UNAVAILABLE'} ({out.strip()[:200]})")
        # Both outcomes are acceptable for this host; what is not acceptable
        # is the script depending on it alone, which is checked separately.
        self.assertIn("WMI_OK" if ok else "WMI_UNAVAILABLE", out)


if __name__ == "__main__":
    unittest.main()
