# Phase 7G — first-kernel no-work execution plan

## Static ABI reconstruction

The target metadata reports one 48-byte by-value user argument followed by
HIP hidden dispatch arguments. The safe harness models the user portion as:

| offset | size | harness meaning |
|---:|---:|---|
| 0 | 8 | guarded pointer slot 0 |
| 8 | 8 | guarded pointer slot 1 |
| 16 | 8 | guarded pointer slot 2 |
| 24 | 8 | guarded pointer slot 3 |
| 32 | 8 | guarded pointer slot 4 |
| 40 | 4 | `split_count` |

This is a size/layout model for the reconstructed kernel path; the original
host-side DLSS-NR structures remain untouched.

## Bounded no-work configuration

- `split_count = 0`.
- One grid block, one 256-thread workgroup, matching the target’s maximum
  workgroup contract and its 4,096-byte fixed LDS requirement.
- Five distinct allocations of 12 KiB each: 4 KiB leading guard, 4 KiB
  centered payload, and 4 KiB trailing guard. Total allocation is 60 KiB,
  far below the 64 MiB phase limit.
- All pointer slots reference the centered payload of a guarded allocation.
- No benchmark or repeated launch.

## Control-flow basis

The target first tests the signed field at offset `0x28`. With zero, the
bounded setup reaches the loop-equality path at `0x691B4`, which branches to
the post-work path at `0x6AFD4` before the WMMA site at `0x69C88`. The static
range `0x6AFD4..0x6B31C` contains no WMMA/MFMA and has only one global byte
store (`0x6B17C`) before the execution mask is cleared and the path ends.
The centered guarded buffers cover that bounded store and all pointer loads.

The next action is exactly one no-work launch, followed by synchronization,
buffer inspection, and a Windows Event ID 4101 check. A successful result is
an inspection stop; no real-output launch is included in this phase.
