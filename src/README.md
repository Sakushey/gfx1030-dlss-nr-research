# phase14eg_tools — corrected DS recorder + physical-LDS model overlay

Host-only. Zero GPU. Python 3.x (developed on 3.14). Run from the
project root:

    python phase14eg_tools/p14e_emu_g.py

Writes:
- `..\phase14eg_lds_model_matrix.csv` (project root)
- `out/p14e_emu_g_results.json` (per-case detail incl. per-site
  censuses)

## What it does

Imports the untouched Phase 14E emulator (`phase14e_static/tools/
p14e_emu.py`) and runs the exact failed SWIN dispatch (grid 1x1x1,
block 256, dims 64, flags 0; boundary waves 0 and 7) for the
entry-fixed translated gfx1030 stream AND the original gfx1100 stream
(original: partial — see matrix).

`GCore` subclasses `SwinCore` and replaces the DS recorder:

- value semantics untouched (ea = (vaddr+imm) & 0x3FFF over a 16-KiB
  image) — step counts reproduce `p14e_emulation.json` exactly
  (13,085 / 12,488);
- every ds event additionally recorded with kind (`rw` = real LDS
  read/write, `bp` = ds_bpermute lane routing, `oth`), the RAW
  (pre-mask) address `vaddr+imm`, width and site;
- bpermute uses the true address operand (last v-token; ISA order
  vdst, vdata, vaddr) instead of the legacy recorder's first-token
  misparse.

## Models (matrix verdicts)

- MODEL_A: raw 32-bit logical EA bounds-checked vs allocation
  (15,872 or 16,384). Yardstick, not a hardware candidate.
- MODEL_B: effective = raw & 0x3FFF (16-KiB working region) — the rule
  the code is compiled against; emulator END under it.
- MODEL_C: effective = raw & 0xFFFF (64-KiB bank view), carve 15,872;
  span beyond carve = OUT_OF_CARVE.

Address bands in the CSV bucket raw rw starts:
`lt_16k / 16k_32k / 32k_64k / ge_64k`.

## Limitations (read before citing numbers)

- `ds_*` addressing is vaddr-form throughout the translated slice;
  SGPR-addressed forms would not be recorded correctly (none present).
- Raw addresses are integer-exact but data-dependent; some lanes
  produce >= 0x10000 "absurd" producers (see
  `phase14eg_real_lds_requirement.md` §7).
- Original-stream dynamic runs stop at emulator op-model gaps
  (v_clz_i32_u32_e32, ds_load_2addr_b64) — that kernel's full-run
  evidence lives in the Phase 14E forensics workgroup emulator.
