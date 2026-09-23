# Windows host-only reproduction — 2026-09-23

Evidence level: `HOST_VALIDATED`

This record reproduces the public host-only setup on an independent machine. No GPU,
ROCm runtime, C++ toolchain, or physical experiment was used.

## Environment

- OS: Windows 11, AMD64
- Python: 3.13.7
- Repository commit: `7215992065fef4eb9979b6cdcfe0ebdb1a518cf8`
- Checkout: fresh clone of the public repository

No hostname, username, absolute local path, credential, or machine identifier is
included in this record.

## Host test entry point

From the repository root:

```powershell
python -m unittest discover -s tests/host -t tests/host
```

Result:

```text
Ran 72 tests in 19.918s
OK
```

This passed without setting `PYTHONPATH`.

## Import namespace

### Direct imports from the repository root

With `PYTHONPATH` unset:

```powershell
python -c "import emu, p14d_kd, isa_oracle_scalar"
```

Result: failed with `ModuleNotFoundError: No module named 'emu'`.

This exposed a documentation mismatch: the root `conftest.py` is loaded by pytest,
but a plain Python process does not import `conftest.py` automatically. The setup
documentation and the `conftest.py` module docstring are corrected in the same
change.

### Direct imports with documented `PYTHONPATH`

Using the documented Windows path list:

```text
src/emulator;src/isa;src/oracle
```

the same direct import command succeeded.

## Publication audit

```powershell
python scripts/verify_publication.py
```

Result: `PUBLICATION VERIFY: PASS`.

The repository-provided audit reported clean secret/privacy scans, no prohibited
tracked artifacts, valid JSON/YAML, matching publication-manifest entries, resolving
README links, SHA-pinned Actions, and no tracked bytecode caches.

## Device-free `tools/` checks

All Python files under `tools/` compiled successfully with:

```powershell
python -m compileall -q tools
```

The following command-line utilities returned help successfully when the documented
`PYTHONPATH` was set:

- `p16j_determinism.py --help`
- `p16j_job_status.py --help`
- `p16j_throughput.py --help`

Two utilities failed before argument parsing, even with the documented `PYTHONPATH`:

- `c_freeze.py --help` — missing module `p16j_execcache`
- `p16j_differential.py --help` — missing module `p16j_j2_freeze`

Neither referenced module is present in the tracked public tree at the tested commit.
This is recorded as a host-only reproducibility deviation; no private or proprietary
artifact was used to work around it.

## Deviations found

1. Plain Python imports from the repository root do not inherit the path changes in
   `conftest.py`. Direct imports require the documented `PYTHONPATH`.
2. Two device-free utilities reference modules that are absent from the tracked public
   tree, so they cannot currently reach their CLI even with `PYTHONPATH` configured.

No physical-support claim is made from this reproduction.
