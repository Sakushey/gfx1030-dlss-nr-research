# Build and Setup

This page covers what is needed to work with the repository, how to run the
**host-only** checks (no GPU, always safe), and how to run the **single bounded GPU
experiment** (requires a `gfx1030` device and explicit intent).

No Administrator rights are required for anything described here. Nothing in this
repository persists environment variables, installs software, or modifies system
state.

## Toolchain requirements

### Host-only work (no GPU)

| Requirement | Version | Why |
| --- | --- | --- |
| Python | 3.10 or newer | The emulator, oracle, ISA tooling, and analysis utilities. |
| A POSIX-style shell or PowerShell | any recent | Running the host-side commands. |
| unittest (stdlib) | current | `python -m unittest discover -s tests/host -t tests/host` is the host-only entry point; pytest also collects the suite if installed. |

Host-only work needs no GPU, no HIP, no ROCm, and no C++ toolchain.

### The HIP path (C++ and physical experiments)

| Requirement | Version | Why |
| --- | --- | --- |
| AMD ROCm | **6.4** | Provides HIP and the `gfx1030`-capable runtime used by the physical path. Standard install location: `C:\Program Files\AMD\ROCm\6.4`. |
| MSVC build tools | **v143** (Visual Studio 2022 Build Tools, "Desktop development with C++") | AMD's HIP compiler on Windows needs the MSVC/Windows SDK host toolchain for linking. |
| Windows SDK | any version shipped with the above | Same reason. |

**ROCm 6.4 specifically.** In this environment, ROCm 6.4 is the runtime generation
that enumerates `gfx1030`. ROCm 7.1 does not enumerate this device here. The bridge
tooling fingerprints both generations (`abi_6_4_fingerprint.cpp`,
`abi_7_1_fingerprint.cpp`) precisely because "which runtime is loaded" has to be a
recorded fact rather than an assumption. See the [glossary](glossary.md) for
`fatbin`, `code object`, and related terms, and [architecture](architecture.md) for
the identity gate.

If `link.exe` is not already on `PATH`, the GPU run script attempts to enter the
Visual Studio developer shell automatically. If it cannot, it stops with a clear
message rather than failing obscurely.

### Constraints

- **No Administrator rights** are needed for host work or for the bounded GPU
  experiment.
- **Never** run a physical test with modified watchdog/TDR settings, and never change
  clocks, voltages, power limits, firmware, BIOS, registry, or drivers. See
  [hardware testing policy](hardware-testing-policy.md).

## The import namespace, and `PYTHONPATH`

The host-side Python modules were developed as **one flat import namespace** spread
across several directories, not as an installed package. They are imported by bare
module name — `import emu`, `import p14d_kd`, and so on.

A root-level `conftest.py` makes the flat namespace available to pytest by
putting every `src/*` directory on `sys.path`. Plain `python` does **not** load
`conftest.py` automatically, even when the repository root is the working directory.

**Two supported ways to run:**

1. **The documented host test command from the repository root** configures its own
   import path and runs without setting `PYTHONPATH`.
2. **Plain Python scripts or direct imports** need `PYTHONPATH` set to the three
   source directories explicitly:

   ```
   src/emulator;src/isa;src/oracle        (Windows)
   src/emulator:src/isa:src/oracle        (POSIX)
   ```

All 24 published modules import cleanly under this arrangement. If an import fails,
the usual cause is running from a directory outside the repository root without
`PYTHONPATH` set.

## Running the host-only checks

From the repository root:

```
python -m unittest discover -s tests/host -t tests/host
```

This is the **only** supported host test entry point. It executes host-side code
only: it must not touch a GPU, and it must not require ROCm. If a host-only test
appears to need a device, that is a bug worth reporting.

Host-only checks are the appropriate place for nearly all contribution work — see the
"no GPU required" section of [contribution areas](contribution-areas.md).

## Running the single bounded GPU experiment

This is the **one** supported physical entry point, and it is deliberately minimal:

```
powershell -ExecutionPolicy Bypass -File scripts\run_test.ps1
```

What it is: a bounded, one-shot experiment. In outline it

1. checks that the HIP 6.4 root, its compiler, and its device-info tool are present,
2. performs a **device preflight** and stops if the device does not report `gfx1030`,
3. sets **session-only** environment variables (this does not change Machine or User
   environment variables),
4. compiles the bounded soft-WMMA test program for `gfx1030`,
5. runs **one tiny tile** — a single small thread block and a single matrix tile —
   and exits.

No loop, no retry, no escalation. It is not a benchmark and it is not a stress test.

**Before running it:**

- Confirm you intend to run a physical experiment. The physical path is entered
  deliberately, not casually. See [current state](current-state.md) and
  [hardware testing policy](hardware-testing-policy.md).
- Do not modify watchdog/TDR settings, clocks, voltages, or power limits.
- Preserve the complete output. If the run does not pass, the instruction is to paste
  the complete output and *not* to change clocks, drivers, BIOS, or power settings.
- Treat a driver-recovery message as a report about the host, not as kernel output.

A physical run also requires the code object it embeds — see the next section.

### Note: harnesses that embed a code object

The C++ harnesses in `src/harness/` that embed a `gfx1030` code object do **not** ship
that artifact. You must generate it locally, from your own legally obtained
installation, using the tooling in this repository. This is intentional:

- The repository redistributes **no proprietary asset** — no code object, no fatbin,
  no vendor binary, no mod payload.
- A code object generated locally reflects the environment that produced it, which is
  also the only way an identity gate can mean anything.

Each harness directory has its own build script (`p14_build_host.ps1`,
`p14d10_build_host.ps1`, `p14d11_build_host.ps1`, `p14e_build_host.ps1`,
`p14ei_build.ps1`, `p16f_build_host.ps1`). Read the relevant script before building;
it records what it needs and where it expects to find it.

## Verification checklist for a clean setup

A setup is in a good state when all of the following hold:

- [ ] `python -m unittest discover -s tests/host -t tests/host` runs from the repository root and completes.
- [ ] Direct imports resolve (`import emu`, `import p14d_kd`, `import isa_oracle_scalar`)
      either from the repository root or with `PYTHONPATH` set as above.
- [ ] The `tools/` utilities run without a GPU.
- [ ] For the HIP path only: ROCm 6.4 is installed at its standard location,
      MSVC v143 and a Windows SDK are present, and the device preflight reports
      `gfx1030`.
- [ ] No environment variable was persisted and no system setting was changed.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `ModuleNotFoundError` for a bare module name | Running outside the repository root without `PYTHONPATH` set. Prefer running from the root. |
| The GPU script stops reporting the HIP root is missing | ROCm 6.4 is not installed at its standard location. |
| The GPU script stops reporting the device did not report `gfx1030` | The preflight failed. Do not work around it; this is the intended fail-closed behavior. |
| The GPU script stops reporting the C++ build tools are missing | MSVC v143 and/or a Windows SDK are not installed or not discoverable. |
| The device is not enumerated at all | Confirm which ROCm generation is active. In this environment ROCm 7.1 does not enumerate `gfx1030`; ROCm 6.4 does. |
| A harness will not build | Its embedded code object has not been generated locally. See the note above. |
