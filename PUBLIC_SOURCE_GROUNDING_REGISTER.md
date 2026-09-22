# Public Source-Grounding Register

External sources this project reads, with the label each imported claim must carry.
The detailed, machine-readable register is published at
[`docs/sources/SOURCE_GROUNDING_REGISTER.md`](docs/sources/SOURCE_GROUNDING_REGISTER.md).

## Evidence hierarchy

```
exact local artifact
>
official architecture/runtime specification
>
locally reproduced external repo claim
>
unreproduced external repo claim
>
hypothesis
```

**No finding crosses repositories without a compatibility label.** An unlabelled
import is a defect, not an omission. The labels are:

`IDENTICAL_PRIMARY_ARTIFACT` · `COMPATIBLE_VERSION` · `DIFFERENT_VERSION_ANALOGUE` ·
`UNKNOWN_COMPATIBILITY`.

## Tier A — sources consulted every development phase

| id | repository | what is taken from it | what it cannot establish |
|---|---|---|---|
| A1 | `philippraschke75-spec/gfx1030-dlss-nr-translation-lab` | independent gfx1030 research and translation evidence | nothing about this project's own artefacts |
| A2 | `TripleZer000/gfx1032-dlss-nr-research` | adjacent-architecture comparative evidence | gfx1030 behaviour: a different die |
| A3 | `maanHimself/OpenDLSS-NR` | upstream model graph, operator and weight-table semantics | gfx1030 execution |
| A4 | `guentra/dlss5-amd-hip-linux` | a complete native HIP network: graph semantics, weight conversion, operator references | gfx1030 execution — its implementation targets gfx1200/gfx1201 |
| A5 | `Paimonshen/dlss-nr-reverse-engineering` | table mapping and reverse-engineering observations | this project's numerics |
| A6 | `heimeimei27/dlss5-zluda-amd` | runtime-interposition evidence | gfx1030 numerics |
| A7 | official AMD ROCm / LLVM / ISA documentation | instruction semantics, hazards, legal operand forms | this project's code |

## Tier B — consulted for integration lessons

| id | repository | concept taken | ceiling |
|---|---|---|---|
| B1 | `vladbogun1/dlss5-amd` | address-independent dispatch trace with pointer relocation | concept only where no explicit permissive licence is present |
| B2 | `Tagertswe/dlssnr-on-amd-linux` | cross-API external-memory sharing; the measured hazard of a GPU-side spin wait | Linux/Proton/RDNA4: no Windows/gfx1030 identity is claimed |
| B3 | `zmodelerlover/dlss5-neural-amd` | integration findings | informs route selection only |
| B4 | `GoldenNights/DLSSNR-OPTI-bridge-AMD` | DXGI wrapping and resource plumbing | informs design only |
| B5 | `3zwr1/AMD-NR---OptiScaler` | fallback/bypass UX | informs design only |

## Durable lesson carried forward

An optimisation that reused one A fragment across Q, K and V changed a complete
network's output image. **Optimisation equivalence must be validated at operator
AND graph output**, not at the operator alone: a mathematically tempting
shared-load optimisation can violate source publication, rounding or ordering
semantics.

## Refresh policy

Source heads are refreshed at the start of each development phase, and **only the
delta** is inspected. If the network is unavailable the register is marked
`SOURCE_REFRESH_STALE` — never "no changes".
