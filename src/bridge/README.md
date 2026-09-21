# HIP bridge and ABI tooling

Original interoperability tooling. Host-only; no GPU required to build or
test the mock path.

## What is here

| File | Role |
| --- | --- |
| `amdhip64_7.cpp` | ABI-forwarding bridge: exports the HIP entry points the upstream runtime imports and forwards each to the versioned HIP runtime that actually enumerates gfx1030 on this platform |
| `mock_hip6.cpp` | Deterministic stand-in exporting the same symbol set, so the whole launch path can be exercised with no GPU and no real runtime |
| `registry_ident.cpp` / `.h` | Fail-closed payload identity: registration is gated on a content hash, so the wrong code object cannot be substituted silently |
| `hip_bridge_smoke.cpp` | Host-only smoke test of the bridge against the mock backend |
| `hip_bridge_reg_smoke.cpp` | Host-only test of the registration path |
| `abi_6_4_fingerprint.cpp`, `abi_7_1_fingerprint.cpp` | ABI probes comparing the two runtime versions at the declaration level |
| `bridge_config.h` | Compile-time backend path configuration |
| `kernel_policy_map.h` | Kernel identity → policy mapping |
| `exports.def` | Export list for the bridge DLL |
| `tools/` | ABI matrix generation and manifest utilities |

## Required local input — you must generate this yourself

`registry_ident.h` includes:

```c
#include "bridge_gfx1030_fatbin.h"
```

**`bridge_gfx1030_fatbin.h` is deliberately not published.** It embeds a
proprietary code-object payload that this project studies but does not
distribute. Without it, the bridge sources will not compile.

This is intentional rather than an oversight. Shipping a placeholder header
would silently change what the identity gate compares, which is worse than
an explicit missing dependency — the gate would appear to work while
verifying nothing.

To build the bridge you must generate the header locally from **your own**
code object. The last four steps of that chain run from this repository, with
`tools/p11_bundle_build.py` and `tools/p11_embed_header.py`; the five steps
before them do not, because the tooling that performed them lived in
historical phase directories this repository does not publish, and neither
does `../isa/` or `../emulator/` contain a payload builder.

The full chain, with every mandatory input and every gap named, is in
[`../../docs/bridge-payload-build-dag.md`](../../docs/bridge-payload-build-dag.md)
and in machine-readable form in `bridge_payload_dag.json`. The short version:

```powershell
python src/bridge/tools/p11_bundle_build.py --object <your translated .co> --out gfx1030_dlssnr.fatbin
python src/bridge/tools/p11_embed_header.py --bundle gfx1030_dlssnr.fatbin --out bridge_gfx1030_fatbin.h
```

```powershell
python src/bridge/tools/bridge_payload_dag.py   # check the DAG is still honest
```

If your build fails with a missing `bridge_gfx1030_fatbin.h`, that is the
documented behaviour, not a repository defect.

## Design properties worth preserving

- **Fail-closed backend load.** Every wrapper checks that the resolved
  backend export exists. A missing export produces a documented error —
  never a silent success. Silent success is the failure mode that makes a
  broken bridge look like a working one.
- **No PATH resolution.** The backend is loaded from an absolute
  compile-time path, never from `PATH` and never from an environment
  variable. Two builds of the same runtime version can otherwise produce
  different behaviour on different machines.
- **Identity before substitution.** Payload identity is a content hash, not
  a filename or version string.

## See also

- [../../docs/architecture.md](../../docs/architecture.md)
- [../../docs/PROVENANCE.md](../../docs/PROVENANCE.md)
- [../../THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)
