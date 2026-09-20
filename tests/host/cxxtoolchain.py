"""Locate a host C++ compiler and run a small compiled driver.

Host-only. No GPU, no HIP, no device enumeration: the fixtures under test
here are plain C++ translation units, and the point of running them on the
host is that the negative controls can execute on a machine with no GPU.

There is no build system in this repository, so the search is explicit and
ordered, and its failure mode is honest: if no compiler is found the caller
skips with the reason rather than reporting a pass.
"""
from __future__ import annotations

import glob
import os
import shutil
import subprocess
import tempfile

# Compilers tried in order. `clang++`/`g++` first: they need no environment
# setup, which is what makes them usable from a test runner. `cl` is last
# because it only works inside a Visual Studio developer shell.
_UNIX_CANDIDATES = ("clang++", "g++", "c++")
_WINDOWS_GLOBS = (
    r"C:\Program Files\AMD\ROCm\*\bin\clang++.exe",
    r"C:\Program Files\LLVM\bin\clang++.exe",
)


def find_cxx():
    """Return the argv prefix for a host C++ compiler, or None.

    A returned prefix is a list, so a caller can do `prefix + [src, "-o", out]`.
    """
    env = os.environ.get("CXX", "").strip()
    if env:
        parts = env.split()
        if shutil.which(parts[0]) or os.path.exists(parts[0]):
            return parts

    for name in _UNIX_CANDIDATES:
        found = shutil.which(name)
        if found:
            return [found]

    if os.name == "nt":
        for pattern in _WINDOWS_GLOBS:
            for hit in sorted(glob.glob(pattern)):
                if os.path.exists(hit):
                    return [hit]

    found = shutil.which("cl")
    if found:
        return [found]

    return None


def _flavour(prefix):
    """'msvc' only for the real `cl`, never for `clang++`.

    A prefix test on "cl" would classify `clang++.exe` as MSVC -- it starts
    with those two letters -- and then hand it `/nologo` and `/Fe:`, which it
    rejects as missing files. Compare the whole stem instead.
    """
    stem = os.path.basename(prefix[0]).lower()
    if stem.endswith(".exe"):
        stem = stem[:-4]
    return "msvc" if stem == "cl" else "gnu"


def compile_and_run(sources, include_dirs=(), timeout=120):
    """Compile `sources` and run the result.

    Returns (ok, detail, stdout) where `ok` is True only when the compile
    succeeded and the program exited 0. `detail` carries the compiler or
    runtime output so a failure is diagnosable without a rebuild.
    """
    prefix = find_cxx()
    if prefix is None:
        return None, "no host C++ compiler found on PATH, in $CXX, or in a known install root", ""

    with tempfile.TemporaryDirectory(prefix="wmma-cxx-") as work:
        exe = os.path.join(work, "driver.exe" if os.name == "nt" else "driver")
        argv = list(prefix)
        argv += ["-std=c++17"]
        if _flavour(prefix) == "gnu":
            argv += ["-O1", "-Wall", "-Wextra", "-Werror"]
            if os.name == "nt":
                argv += ["-D_CRT_SECURE_NO_WARNINGS"]
        argv += [f"-I{d}" for d in include_dirs]
        argv += list(sources)
        argv += ["-o", exe]
        if _flavour(prefix) == "msvc":
            # cl writes the .exe next to the sources; force it into the
            # scratch directory so nothing is left in the repository.
            argv += ["/Fe:" + exe, "/nologo", "/std:c++17", "/EHsc", "/W4"]

        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return False, "compiler timed out: " + " ".join(argv), ""
        if proc.returncode != 0:
            return False, ("compile failed ({}): {}".format(proc.returncode,
                                                           proc.stderr.strip()[-4000:] or
                                                           proc.stdout.strip()[-4000:])), ""
        if not os.path.exists(exe):
            return False, "compiler reported success but produced no executable", ""

        try:
            run = subprocess.run([exe], capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return False, "driver timed out", ""
        out = run.stdout
        if run.returncode != 0:
            return False, ("driver exited {}: {}".format(run.returncode,
                                                         run.stderr.strip()[-2000:])), out
        return True, "ok", out
