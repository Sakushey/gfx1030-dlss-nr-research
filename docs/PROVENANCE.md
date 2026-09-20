# Provenance

Where the published code came from, how it was selected, and what was
deliberately left out.

## Selection method

This repository is **not** a snapshot of a working tree. It was built by:

```
inventory  ->  classify  ->  explicit allowlist  ->  copy only allowlisted files
```

Every file in the source project received exactly one publication class.
Anything not on the explicit allowlist was excluded. The default for an
uncertain file was **exclude**.

The controls that make this meaningful:

- **No wholesale copy.** The source tree was never copied and pruned, and
  `.gitignore` was never the mechanism protecting the repository. The
  allowlist is the mechanism; `.gitignore` is defence in depth only.
- **Verbatim copies.** No included file was edited. Every copy is
  byte-identical to its source **apart from line-ending normalisation**,
  which is applied to exactly 10 files and recorded per-file in the
  manifest (`modifications: "line endings normalised CRLF -> LF"`).
  Normalisation is performed explicitly during the build rather than left
  to git's smudge/clean filters, so the bytes a fresh clone receives are
  the bytes the manifest records. The other 78 files are byte-identical
  with no transformation at all.
- **Two independent scans.** Secret and personal-path scanning ran against
  the completed tree *before* git was initialised, and again against the
  staged index and the committed snapshot.

## What is included

Everything under `src/`, `tools/`, `tests/`, and `scripts/` is original
work produced for this project:

| Path | Content |
| --- | --- |
| `src/emulator/` | host instruction emulator and LDS/DS semantic models |
| `src/oracle/` | independently written scalar ISA oracle |
| `src/isa/` | instruction decode, rebuild, and memory-model gates |
| `src/bridge/` | HIP ABI bridge, ABI probes, mock backend |
| `src/harness/` | bounded physical host harnesses |
| `tools/` | host-side analysis utilities |
| `tests/` | bounded gfx1030 test program |
| `scripts/` | run scripts |

Ownership: project-owned original work. Licence: Apache-2.0.

**Modifications to included files: none.** Every file under `src/`,
`tools/`, `tests/`, and `scripts/` is byte-identical to its source.

The only added files are new: documentation, community files, CI
configuration, the publication audit records, and `conftest.py` (which
establishes the shared Python import namespace these modules were
developed against, and which did not previously exist as a file because
the original tree used per-script `sys.path` edits).

## What is excluded, and why

Exclusions are grouped by reason in
[../audit/EXCLUSIONS.md](../audit/EXCLUSIONS.md). Category summary:

| Reason | Rationale |
| --- | --- |
| Proprietary binaries | code objects, fatbins, runtime DLLs, and other artifacts under study are not this project's to redistribute |
| Proprietary-derived material | translated proprietary kernels and raw proprietary disassembly are excluded |
| Generated internal evidence | traces and result files tied to a specific internal run |
| Local-machine artifacts | bytecode caches, logs, and machine-specific outputs |
| Personal-path content | files embedding local absolute paths |
| Large binaries | nothing near or above 100 MiB is published |
| Secret-like content | matched by pattern scan; every hit was a synthetic test literal or a pattern definition, not a credential |
| Ambiguous | not confidently classifiable as public-safe original work |

### One notable exclusion

A verifier that cross-checks the emulator against the frozen reference
layout is **not** published. It hard-asserts that the loaded emulator
module resolves to one specific internal path, which exists only in the
internal tree. A published copy could never satisfy its own identity
gate, so shipping it would mean shipping a verifier that always fails —
worse than shipping nothing, because it would look like coverage. The
independent oracle it drives is published in `src/oracle/`.

## Required inputs are not shipped

Some harnesses need a code object that is an artifact under study. The
project does not distribute such artifacts. Where a component needs one,
the documentation says so, and the expectation is that a researcher
generates it locally from their own inputs with the published tooling.

No placeholder artifact is shipped in place of a real one: a placeholder
would silently change what is being tested, which is worse than an
explicit missing dependency.

### A concrete case: the bridge identity header

`src/bridge/registry_ident.h` includes `bridge_gfx1030_fatbin.h`, which
embeds a proprietary code-object payload and is therefore excluded. Without
it the bridge sources will not compile.

This is deliberate. A placeholder would let the payload-identity gate
appear to work while comparing nothing, which defeats the gate's purpose.
The header must be generated locally from the researcher's own code object
using the published tooling — see [../src/bridge/README.md](../src/bridge/README.md).

## Reproducing the selection

The inventory, classification, and copy steps were scripted. The generated
records are:

- `audit/SOURCE_INVENTORY.json` — every source file with size and SHA-256
- `audit/SOURCE_CLASSIFICATION.json` — the class assigned to every file
- `audit/PUBLICATION_MANIFEST.json` — every included file with its source
  hash, published-content hash, public path, category, declared
  modifications, and reason for inclusion
- `audit/EXCLUSIONS.md` — exclusions grouped by reason
- `audit/PRE_GIT_PUBLICATION_GATE.json` — the result of each safety gate
- `audit/GITHUB_READINESS.json` — publication readiness record

These records allow the selection to be re-checked rather than taken on
trust.
