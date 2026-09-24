# Reproducibility

If a result cannot be reproduced from this repository plus locally supplied
inputs, it is not a result — it is an anecdote.

## Tiers of reproduction

| Tier | Requirements | What it can establish |
| --- | --- | --- |
| Host-only | Python 3.10+ | rungs 1–2 |
| Build-only | MSVC v143 + Windows SDK | that C++ components compile |
| Physical | + AMD ROCm with a gfx1030 device | rung 3+ |

Most of the project is reproducible at the host-only tier. That is
deliberate: it is the tier anyone can check.

## Host-only reproduction

```powershell
python -m unittest discover -s tests/host -t tests/host
```

The suite is stdlib `unittest` only, so it runs with no third-party
packages installed. `pytest` also collects it if you have pytest.
`tests/host/test_publication_contract.py` additionally re-checks the
provenance manifest against the files on disk.

The Python modules were developed as one flat import namespace spread
across directories. `conftest.py` at the repository root puts every `src/*`
directory on `sys.path`. If you drive a module from outside the repository
root, set the equivalent path explicitly:

```powershell
$env:PYTHONPATH = "src\emulator;src\isa;src\oracle"
```

```bash
export PYTHONPATH=src/emulator:src/isa:src/oracle
```

No GPU, no driver, and no Administrator rights are required.

## Physical reproduction

Physical experiments are bounded and one-shot. Read
[docs/hardware-testing-policy.md](docs/hardware-testing-policy.md) before
running anything on hardware.

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_test.ps1
```

This compiles and runs one small gfx1030 workload. It does not change
clocks, voltage, power limits, firmware, BIOS, registry, or drivers, and it
does not install anything.

## What you must supply yourself

Some harnesses embed a code object that is an artifact under study. That
artifact is **not** distributed here (see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)). You generate it locally
from your own inputs using the tooling in `src/isa/` and `src/emulator/`.
Where a harness cannot be built without such an artifact, the documentation
for that harness says so rather than shipping a placeholder that silently
changes what is being tested.

## Rules that make a result reproducible

1. **Record the artifact identity.** A code object is identified by its
   content hash, not by its filename. Two builds with the same name are
   different artifacts.
2. **Preserve raw evidence.** Summaries are derived; raw output is
   evidence. Keep the raw form.
3. **Compare per-record values, not totals.** Two runs with identical
   aggregate counts can hold entirely different values. Counting matches
   is not the same as checking equivalence.
4. **Read the artifact back.** A tool reporting success does not mean its
   output is correct. Read the produced artifact and check a property you
   can predict independently.
5. **Test the verifier against a known-bad case.** A check that cannot
   fail is not a check. A check that rejects the known-good case is
   broken, not strict.
6. **Say which tier produced the result.** Host evidence and physical
   evidence are labelled differently and are never merged.
7. **One variable per experiment.** A run that changes two things cannot
   attribute its outcome to either.

## Known environmental constraints

- The physical path targets AMD ROCm 6.4 on Windows, which enumerates
  gfx1030 on the reference machine. Other runtime versions may not
  enumerate this device at all, and a harness that initializes against a
  runtime that sees no GPU will fail before reaching the code under test.
- A GPU watchdog recovery can let a synchronization call return success
  even though the kernel never completed. **Sync success is not kernel
  success.** Corroborate with evidence that the kernel produced output.


## Phase 16BK host checks

The Phase 16BK neural tests are host-only. From a clean checkout with the
listed Python dependencies installed, run:

```text
python scripts/verify_publication.py
python -m unittest discover -s tests/host -t tests/host
python -m unittest tests.neural.test_connected_executor tests.neural.test_input_dependency_structured
python tests/neural/test_resolver_malformed_variant.py
```

These tests do not launch a GPU or promote host evidence to physical
qualification. Current status and claim limits are recorded in
[docs/current-state.md](docs/current-state.md).
