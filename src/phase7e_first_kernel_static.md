# Phase 7E — first translated gfx1030 kernel

Target: `_Z13k_conv_splitk12ConvParams1d`

The original gfx1100 object was read-only. A new target-only assembly was
generated from the Phase-6 census and assembled/linked as separate files:

- `k_conv_splitk_translated_gfx1030.s`
- `k_conv_splitk_translated_gfx1030.o`
- `k_conv_splitk_translated_gfx1030.co`

The original gfx1100 object and static DLSS-NR files were not modified.

## Translation audit

| item | result |
|---|---:|
| physical source sites | 1,754 |
| source operation tokens | 1,758 |
| direct-compatible tokens retained | 1,415 |
| target spellings regenerated | 81 |
| dual component tokens unbundled | 8 |
| GFX11 scheduling/resource tokens removed | 253 |
| WMMA sites replaced | 1 |
| unresolved sites | 0 |
| assembler exit | 0 |

The one WMMA site at static address `0x69C88` is the reviewed exact form
`D/C=v[1:8], A=v[9:16], B=v[17:24]`. It expands to 64
`v_dot2c_f32_f16` operations with 64 `ds_bpermute_b32` operations and
explicit reusable temporaries `v45`/`v46`. Their first later uses are
definitions, so the translator proves them dead at the replacement site.

## Linked code-object static checks

| check | result |
|---|---|
| ELF machine/target | AMDGPU, gfx1030 |
| code-object type | DYN shared code object |
| relocations after link | 0 |
| unresolved branch labels | 0 |
| unresolved symbols | 0 |
| WMMA/MFMA in translated assembly | none |
| GFX11 dual operations | none |
| wavefront | wave32 |
| kernarg segment | 304 bytes, 8-byte alignment |
| by-value user argument | 48 bytes |
| group/LDS segment | 4,096 bytes |
| private segment | 0 bytes |
| VGPR / SGPR metadata | 51 / 42 |
| spills | 0 |
| linked function code size | 9,260 bytes |
| AMDGPU metadata note | present and target gfx1030 |

The generated output agrees with the manually reviewed Phase-7D exact
replacement: same A-row source-lane remap, direct B-column source, in-place
accumulator aliasing, wave32, no LDS added by the replacement, and explicit
`lgkmcnt(0)` waits after each cross-lane read.

This artifact has passed HIP 6.4 module registration and symbol resolution.
It has not yet been launched.
