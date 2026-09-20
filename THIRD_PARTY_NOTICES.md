# Third-Party Notices

This repository contains no third-party source code, no third-party
binaries, and no rewritten or copied third-party implementation.

Everything tracked in `src/`, `tools/`, `tests/`, and `scripts/` is
original work produced for this project and is licensed under
Apache-2.0 unless stated otherwise in the file header.

## Components that are *referenced* but not *included*

The project studies and interoperates with components that are not
redistributed here. They are listed so that provenance is unambiguous.
Contributors must supply their own local copies where a workflow needs
them.

| Component | Role in the research | Redistributed here? |
| --- | --- | --- |
| AMD ROCm / HIP runtime (`amdhip64_6.dll`, ROCm 6.4) | Host runtime used by the physical harnesses | No — install from AMD |
| AMD HIP headers (`hip/hip_runtime.h`) | Compile-time dependency of the bounded test program | No — part of the ROCm install |
| NVIDIA-targeted DLSS-NR code objects and fatbins | The artifacts under study; supplied locally by the researcher | No |
| Third-party mod binaries (including `version.dll` shims) | Interoperability target; supplied locally | No |
| Game executables and assets | Not part of this research at this stage | No |

## Build-time toolchain

Compiling the C++ components requires a toolchain the user installs
themselves: an MSVC v143 / Windows SDK host toolchain and the AMD HIP
compiler shipped with ROCm. No toolchain binaries are vendored here.

## Why nothing third-party is vendored

Redistributing the artifacts under study would:

1. misrepresent this project as a distributor of proprietary software;
2. make the repository's license ambiguous; and
3. remove the need for a contributor to establish local provenance,
   which is the point of the research.

If a workflow in this repository needs a proprietary input, the
documentation says so explicitly and describes how to supply it
locally. See `docs/PROVENANCE.md`.
