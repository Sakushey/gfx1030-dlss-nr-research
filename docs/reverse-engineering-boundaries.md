# Reverse-engineering boundaries

What this project does, what it deliberately does not do, and where the
line sits.

## What this project does

- Analyses publicly documented GPU instruction set architecture (AMD
  RDNA2 / GFX10, wave32 subset) to build original tooling.
- Reads artifacts the researcher already possesses locally, for the
  purpose of interoperability research.
- Writes original tools: an emulator, an independent oracle, decoders,
  a HIP ABI bridge, harnesses, and analysis utilities.
- Publishes methodology, results, and its own tooling.

## What this project does not do

- **Redistribute proprietary material.** No game assets, no NVIDIA
  binaries, no AMD runtime DLLs, no third-party mod binaries. See
  [../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
- **Publish translated proprietary kernels or raw proprietary
  disassembly.** Those are artifacts under study, not this project's
  output.
- **Circumvent anti-cheat.** This is not a goal, a side effect, or an
  acceptable outcome. Nothing here is designed to defeat integrity
  checks, and a contribution that would is rejected.
- **Enable piracy.** No tooling here acquires, decrypts, or unlocks
  commercial content.
- **Distribute a working game patch.** The project studies whether a
  workload can run; it does not ship a way to run a game.
- **Modify the host machine.** No clocks, voltage, power limits, firmware,
  BIOS, registry, or driver changes. See
  [hardware-testing-policy.md](hardware-testing-policy.md).

## Where the line sits

The distinction that matters:

> **Publishing original interoperability tooling and measured results is
> fine. Publishing, or shipping a way to obtain, someone else's
> implementation is not.**

Concretely:

| Action | Status |
| --- | --- |
| Publishing an original emulator for a documented ISA | allowed |
| Publishing a hash of an artifact under study | allowed |
| Publishing the artifact itself | **not allowed** |
| Publishing our own analysis of the artifact | allowed |
| Publishing extracted proprietary implementation | **not allowed** |
| Publishing a tool that operates on a user-supplied input | allowed |
| Publishing a tool that fetches that input for the user | **not allowed** |

## Why this is stated so plainly

Interoperability research legitimately involves examining artifacts you
were not given source for. That is normal and useful. What is not
legitimate is turning that research into a distribution channel for the
thing being studied, or into a tool for defeating protections.

Being explicit about the boundary keeps contributors from drifting across
it by accident, and keeps the project's licence and provenance
unambiguous.

## If you are unsure

Ask in an issue **before** opening a pull request that includes anything
you did not write yourself. The default is exclude.

If a contribution cannot be accepted without redistributing a third-party
artifact, the correct outcome is to document how a contributor supplies
their own local copy — not to vendor the artifact.
