# phase16s/isa — ISA_ORACLE_16

Phase 16S item S1. **Host only: no GPU, no HIP, no game, nothing armed or deployed.** Every number below was measured in the run whose command is in the artifact's `run` block; the JSON was read back afterwards and checked against properties fixed before the read-back.

## What this is

`phase16r/isa/J3_INSTRUCTION_CONFORMANCE.json` reports `J3_INSTRUCTION_SEMANTICS_BLOCKED = 19`, of which sixteen are blocked with `NO_INDEPENDENT_ORACLE_VECTOR_FOR_THIS_MNEMONIC`. This artifact supplies instruction-level oracle vectors for those sixteen, derives every expected value from the ISA mathematical definition through an independent model (`oracle16.py`, which imports nothing), and measures the live emulator against it. The three `v_div_*` mnemonics (R9) are **not** addressed here.

## Result

| | |
|---|---|
| verdict | **MEASURED_DISAGREEMENTS_IN_5_OF_16** |
| vectors | 146 |
| comparisons (field-level) | **198** |
| vectors disagreeing | 47 |
| status DISAGREES | 5 |
| status VERIFIED_INDEPENDENTLY | 11 |
| emulator loaded | `c6afc641be3ce734789ec505eb7f23ca876db8787cbccb9f00426064edb17205` |

## Per mnemonic

| mnemonic | status | vectors | comparisons | disagreements | unexplained | J3 execs | value-cone nodes |
|---|---|---|---|---|---|---|---|
| `s_mov_b64` | VERIFIED_INDEPENDENTLY | 6 | 8 | 0 | 0 | 8 | 8 |
| `v_add_co_u32` | VERIFIED_INDEPENDENTLY | 9 | 22 | 0 | 0 | 528 | 216 |
| `v_add_co_ci_u32_e64` | DISAGREES | 9 | 24 | 5 | 5 | 592 | 248 |
| `v_cmp_gt_i32_e64` | VERIFIED_INDEPENDENTLY | 7 | 13 | 0 | 0 | 16 | 16 |
| `v_cmp_gt_u32_e64` | VERIFIED_INDEPENDENTLY | 6 | 10 | 0 | 0 | 32 | 24 |
| `v_cmp_lt_i32_e64` | VERIFIED_INDEPENDENTLY | 6 | 11 | 0 | 0 | 16 | 16 |
| `v_lshlrev_b16` | VERIFIED_INDEPENDENTLY | 7 | 8 | 0 | 0 | 456 | 48 |
| `v_lshrrev_b16` | VERIFIED_INDEPENDENTLY | 7 | 8 | 0 | 0 | 64 | 40 |
| `v_min_u32_e32` | VERIFIED_INDEPENDENTLY | 7 | 9 | 0 | 0 | 16 | 16 |
| `v_mul_lo_u16` | VERIFIED_INDEPENDENTLY | 6 | 6 | 0 | 0 | 48 | 48 |
| `v_mul_u32_u24_e32` | VERIFIED_INDEPENDENTLY | 6 | 6 | 0 | 0 | 112 | 8 |
| `v_pack_b32_f16` | DISAGREES | 7 | 9 | 4 | 1 | 256 | 24 |
| `v_sub_nc_u16` | VERIFIED_INDEPENDENTLY | 7 | 8 | 0 | 0 | 24 | 24 |
| `v_cvt_f16_f32_e32` | DISAGREES | 24 | 24 | 8 | 8 | 1016 | 96 |
| `v_fma_mixlo_f16` | DISAGREES | 16 | 16 | 15 | 13 | 224 | 32 |
| `v_fma_mixhi_f16` | DISAGREES | 16 | 16 | 15 | 14 | 32 | 32 |

## Defect findings

Each entry states, for the mnemonic: the exact input vectors in hex, the oracle's expected destination, the live emulator's measured destination, **the reading each side implements**, and the J3 reachability of the disagreement. Nothing here is a paraphrase: the expected values come from `oracle16.py` and the measured values are read back from the emulator by the R11 tool's own `Harness.probe`.

### `v_add_co_ci_u32_e64`

**Reading each side implements.**

- The ISA form is VOP3B: `V_ADD_CO_CI_U32` stores the carry-out to the scalar destination the encoding names (rdna2_isa.txt:7275-7281, `In VOP3 the VCC destination may be an arbitrary SGPR-pair`). The live handler writes the carry-out only when the destination token is `vcc_lo`; any other destination is silently dropped.
- The ISA's carry-in is the per-lane VCC bit of the source the encoding names; the live handler reads it as bit `lane` of the named register, which this suite MEASURED to agree, so the carry-in side is not part of this finding.

**J3 operand forms (static, from the J3 kernel's own disassembly).** 231 distinct form(s); second-operand (scalar-destination) token counts: `{"null": 231}` -- 0 of them name a real scalar destination rather than `null` or `vcc_lo`.

**Can J3 reach this defect? — `NOT_REACHED_ON_THE_J3_PATH`**

The defect fires only when operand 2 (the VOP3B scalar destination) names a register other than `null`/`vcc_lo`. All 231 distinct operand strings this module prints for this mnemonic pass `null` (0 of them name a real scalar destination). The emulator's operand string IS this disassembly text, so no executable instance of this mnemonic in this module can trigger the drop: the defect is real, measured, and LATENT.

**J3 reachability (cone).** executions on the J3 path: `592`; value-cone nodes `248`; union-cone nodes `400`; contributes to written bytes: `True`.  The 16R cone record puts this mnemonic in the J3 output cone (248 value-cone node(s), 400 union-cone node(s)) and marks it as contributing to written bytes, so the disagreement is on the J3 output path as an upper bound. The cone is a lane-collapsed OVER-APPROXIMATION (16R's own INFERRED note), so this is 'cone-reachable', not a proof that a wrong value reached a store.

- **carry_out_to_sgpr** — `v_add_co_ci_u32_e64 v0, s0, v1, v2, s19`
  - setup (raw 32-bit register contents): `{"s19": "0x00000000", "v1": "0xFFFFFFFF x32", "v2": "0x00000002 x32"}`
  - oracle expected destination `v0`: `0x00000001`
  - live emulator measured: `0x00000001`
  - differing field `extra.s0`: oracle `4294967295`, emulator `3735928559`
  - source: ISA rdna2_isa.txt:7275-7284
  - note: DISCRIMINATING: the carry-out destination is an ordinary SGPR, which is the VOP3B form the document describes at :7277-7281. 0xFFFFFFFF + 2 + 0 = 0x100000001, so s0 must read all-ones. A handler that writes the carry only to VCC leaves s0 at the sentinel.

- **carry_in_zero_no_carry** — `v_add_co_ci_u32_e64 v0, s0, v1, v2, s19`
  - setup (raw 32-bit register contents): `{"s19": "0x00000000", "v1": "0x00000000 x32", "v2": "0x00000000 x32"}`
  - oracle expected destination `v0`: `0x00000000`
  - live emulator measured: `0x00000000`
  - differing field `extra.s0`: oracle `0`, emulator `3735928559`
  - source: ISA rdna2_isa.txt:7275-7284
  - note: Zero case with a zero carry-in: result 0, carry-out 0, and the carry-out SGPR written rather than left at the sentinel.

- **carry_boundary_with_zero_carry_in** — `v_add_co_ci_u32_e64 v0, s0, v1, v2, s19`
  - setup (raw 32-bit register contents): `{"s19": "0x00000000", "v1": "0xFFFFFFFF x32", "v2": "0x00000000 x32"}`
  - oracle expected destination `v0`: `0xFFFFFFFF`
  - live emulator measured: `0xFFFFFFFF`
  - differing field `extra.s0`: oracle `0`, emulator `3735928559`
  - source: ISA rdna2_isa.txt:7275-7284
  - note: 0xFFFFFFFF + 0 + 0: one below the boundary, carry 0.

- **carry_in_from_sgpr_bit_pattern** — `v_add_co_ci_u32_e64 v0, s0, v1, v2, s19`
  - setup (raw 32-bit register contents): `{"s19": "0xAAAA5555", "v1": "0x00000001 x32", "v2": "0x00000001 x32"}`
  - oracle expected destination `v0`: `0x00000003`
  - live emulator measured: `0x00000003`
  - differing field `extra.s0`: oracle `0`, emulator `3735928559`
  - source: ISA rdna2_isa.txt:7275-7284
  - note: Carry-in as a per-lane pattern: 1 + 1 + bit(lane, 0xAAAA5555), which is 1 in the odd lanes of the pattern. Lanes 1 and 2 are read back, so a single broadcast bit is separated from the architectural per-lane carry-in.

- **operand_order_not_observable** — `v_add_co_ci_u32_e64 v0, s0, v1, v2, s19`
  - setup (raw 32-bit register contents): `{"s19": "0x00000000", "v1": "0x00010000", "v2": "0x00000003"}`
  - oracle expected destination `v0`: `0x00010003`
  - live emulator measured: `0x00010003`
  - differing field `extra.s0`: oracle `0`, emulator `3735928559`
  - admissible alternate readings measured on the same vector: `src0_src1_swapped=0x00010003`
  - source: ISA rdna2_isa.txt:7275-7284
  - note: Stated plainly: addition is commutative, so NO vector can separate src0 from src1 here. The vector is kept so the non-discrimination is visible rather than implied.

### `v_pack_b32_f16`

**Reading each side implements.**

- The ISA takes the FIRST source (S0) into the LOW half and the SECOND (S1) into the HIGH half of the packed word (rdna2_isa.txt:10209-10210, `D[31:16].f16 = S1.f16; D[15:0].f16 = S0.f16.`); the live handler computes `((src0 & 0xFFFF) << 16) | (src1 & 0xFFFF)`, i.e. it puts src0 in the HIGH half and src1 in the LOW half -- the two operands are exchanged.
- The J3 site `v_pack_b32_f16 v11, v5, 1.0` passes a FLOAT LITERAL for the second source. The architectural operand is an FP16 value, so the literal means the bit pattern 0x3C00. The live handler is `Core8.op_v_pack_b32_f16` (phase14d8_static/tools/p14d8_core.py:685), which calls `self._vbin(ins, ops, ...)`; `_vbin` (phase8_static/tools/emu.py:789-790) reads each source with `self.vget(lane, ops[i])` and passes NO `fp` argument, so the operand is read with the default `fp=False`. That reaches the last two lines of `vget` (phase8_static/tools/emu.py:473-476):
        elif fp:
            return float(tok)
        else:
            return int(tok)
so a non-register token is decoded with `int(tok)` and `int('1.0')` raises. MEASURED, through this tool's own Harness.probe: `{'error': "ValueError: invalid literal for int() with base 10: '1.0'"}` for the token `1.0`, against `error: None` for the tokens `2` and `0x3C00`. The coordinator's correction describes the `fp=True` arm of that branch, which this mnemonic does not take -- the caller is the integer path, not `_vfp`. The defect is therefore an exception rather than a silently wrong value, and it is recorded with the measured error string.

**J3 operand forms (static, from the J3 kernel's own disassembly).** 33 distinct form(s); this mnemonic's printed operand 2 is its ordinary destination, not a VOP3B scalar destination, so no scalar-destination count is reported

**Can J3 reach this defect? — `NOT_ESTABLISHED (half-swap) / NOT_REACHED (float literal)`**

TWO sub-defects with different reachability. (a) HALF SWAP: fires when the two source halves differ in VALUE, which is run-time state; 29 of the 33 on-disk forms have differing source TOKENS, so the swap is not structurally excluded, but whether the values differed on J3 is not decidable from the recorded evidence -> NOT_ESTABLISHED. (b) FLOAT LITERAL: 1 on-disk form(s) pass a float literal. That form RAISES in the emulator, and the J3 run recorded outcome=('ALL_ENDED', 13590), faults=[], natural_end=True, gate=PASS -- a raised operand error would have appeared there. So that form did NOT execute on J3 -> NOT_REACHED (with the caveat that this project has measured the wave harness's ALL_ENDED to be fail-open, so the no-fault record is read together with `natural_end` and the empty fault list).

**J3 reachability (cone).** executions on the J3 path: `256`; value-cone nodes `24`; union-cone nodes `24`; contributes to written bytes: `True`.  The 16R cone record puts this mnemonic in the J3 output cone (24 value-cone node(s), 24 union-cone node(s)) and marks it as contributing to written bytes, so the disagreement is on the J3 output path as an upper bound. The cone is a lane-collapsed OVER-APPROXIMATION (16R's own INFERRED note), so this is 'cone-reachable', not a proof that a wrong value reached a store.

- **j3_v1_v2_half_mapping** — `v_pack_b32_f16 v1, v1, v2`
  - setup (raw 32-bit register contents): `{"v1": "0x00003C00 x32", "v2": "0x00004000 x32"}`
  - oracle expected destination `v1`: `0x40003C00`
  - live emulator measured: `0x3C004000`
  - differing field `value`: oracle `1073757184`, emulator `1006649344`
  - admissible alternate readings measured on the same vector: `src0_high_src1_low=0x3C004000`
  - the emulator's value matches the alternate reading(s): src0_high_src1_low
  - source: J3 sample 0x0000000B1948: v_pack_b32_f16 v17, v17, v20 | ISA rdna2_isa.txt:10207-10210
  - note: J3 operand shape, verbatim. S1 (0x4000) belongs in bits 31:16 and S0 (0x3C00) in bits 15:0, so the expected value is 0x40003C00; the alt reading is the half mapping reversed (0x3C004000). The two candidates differ in every bit of the packed value.

- **j3_float_literal_operand** — `v_pack_b32_f16 v11, v5, 1.0`
  - setup (raw 32-bit register contents): `{"v5": "0x0000BC00 x32"}`
  - oracle expected destination `v11`: `0x3C00BC00`
  - live emulator measured: `0x00000000`
  - differing field `error`: oracle `None`, emulator `ValueError: invalid literal for int() with base 10: '1.0'`
  - differing field `value`: oracle `1006681088`, emulator `0`
  - admissible alternate readings measured on the same vector: `src0_high_src1_low=0xBC003C00`
  - source: J3 sample 0x0000000ABA10: v_pack_b32_f16 v11, v5, 1.0 | ISA rdna2_isa.txt:10207-10210
  - note: J3 operand shape taken VERBATIM, including the float literal: `v_pack_b32_f16 v11, v5, 1.0`. The architectural operand is an FP16 value, so 1.0 is 0x3C00. Whether the emulator's operand parser accepts this printed form at all is part of the measurement.

- **high_bits_of_sources_ignored** — `v_pack_b32_f16 v0, v1, v2`
  - setup (raw 32-bit register contents): `{"v1": "0x1234ABCD x32", "v2": "0x5678EF01 x32"}`
  - oracle expected destination `v0`: `0xEF01ABCD`
  - live emulator measured: `0xABCDEF01`
  - differing field `value`: oracle `4009864141`, emulator `2882400001`
  - admissible alternate readings measured on the same vector: `src0_high_src1_low=0xABCDEF01`
  - the emulator's value matches the alternate reading(s): src0_high_src1_low
  - source: ISA rdna2_isa.txt:10207-10210
  - note: Only the low 16 bits of each source are packed: 0xEF01ABCD, with the half order still observable.

- **exec_partial** — `v_pack_b32_f16 v0, v1, v2`
  - setup (raw 32-bit register contents): `{"exec": "0x00000003", "v0": "0xAAAA5555 x32", "v1": "0x00003C00 x32", "v2": "0x00004000 x32"}`
  - oracle expected destination `v0`: `0x40003C00`
  - live emulator measured: `0x3C004000`
  - differing field `value`: oracle `1073757184`, emulator `1006649344`
  - admissible alternate readings measured on the same vector: `src0_high_src1_low=0x3C004000`
  - the emulator's value matches the alternate reading(s): src0_high_src1_low
  - source: ISA rdna2_isa.txt:10207-10210 + 3.3 EXECute Mask
  - note: EXEC = lanes 0,1; lanes 2 and 17 must keep 0xAAAA5555.

### `v_cvt_f16_f32_e32`

**Reading each side implements.**

- SIGN. The ISA takes the sign of the result from the sign of the f32 input (`D.f16 = flt32_to_flt16(S0.f)`, rdna2_isa.txt:7577). The live handler takes it from bit 16 of the f32 pattern (`s = (b >> 16) & 1` where `b` is the packed binary32 word), i.e. from the low mantissa bit of the second byte, so any input whose bit 16 is 1 -- 65504.0, the largest subnormal, every negative value with that mantissa bit clear -- comes back with the wrong sign.
- SUBNORMAL FLUSH. The ISA requires FP16 DENORMALS to be created when an f32 value rounds into the subnormal range (rdna2_isa.txt:7573-7575, `creates FP16 denormals when appropriate`). The live handler returns a signed zero whenever the biased exponent is below -24, so a magnitude that rounds UP to the smallest subnormal (2^-24) is flushed to zero.
- SUBNORMAL CLAMP AT THE TOP OF THE RANGE. Rounding a subnormal magnitude up to exactly 2^-14 must give the smallest NORMAL (0x0400). The live handler clamps the subnormal significand with `min(frac, 0x3FF)`, so 1024 is clamped back to 1023 and the result is 0x03FF, one quantum low.
- INPUT MODIFIER `-vN`. The ISA says this conversion `supports input modifiers`, i.e. the f32 VALUE is negated before conversion. The live operand reader negates the raw 32-bit pattern with two's-complement integer arithmetic and then reinterprets it as f32, so `-1.5` becomes the f32 value -3.0 (0x3FC00000 -> 0xC0400000).

**J3 operand forms (static, from the J3 kernel's own disassembly).** 116 distinct form(s); this mnemonic's printed operand 2 is its ordinary destination, not a VOP3B scalar destination, so no scalar-destination count is reported

**Can J3 reach this defect? — `NOT_ESTABLISHED (value-driven) / NOT_REACHED (input modifier)`**

The sign, subnormal-flush and clamp sub-defects are driven by the VALUE being converted, not by the operand shape: any input whose bit 16 is set or whose magnitude is subnormal triggers them. This mnemonic executes 1016 times on the J3 path over 116 distinct on-disk forms, so the trigger is structurally available, but the tree holds no per-instruction J3 VALUE trace that would show whether a triggering value occurred -> NOT_ESTABLISHED. The `-vN` input-modifier sub-defect IS shape-driven: 0 of the 116 on-disk forms carry an input modifier token, so on this evidence that sub-defect is NOT_REACHED on the J3 path.

**J3 reachability (cone).** executions on the J3 path: `1016`; value-cone nodes `96`; union-cone nodes `96`; contributes to written bytes: `True`.  The 16R cone record puts this mnemonic in the J3 output cone (96 value-cone node(s), 96 union-cone node(s)) and marks it as contributing to written bytes, so the disagreement is on the J3 output path as an upper bound. The cone is a lane-collapsed OVER-APPROXIMATION (16R's own INFERRED note), so this is 'cone-reachable', not a proof that a wrong value reached a store.

- **largest_f16_subnormal** — `v_cvt_f16_f32_e32 v1, v1`
  - setup (raw 32-bit register contents): `{"v1": "0x387FC000 x32"}`
  - oracle expected destination `v1`: `0x000003FF`
  - live emulator measured: `0x000083FF`
  - differing field `value`: oracle `1023`, emulator `33791`
  - admissible alternate readings measured on the same vector: `preserve_dst_high_half=0x387F03FF`
  - source: ISA rdna2_isa.txt:7571-7577 (D.f16 = flt32_to_flt16(S0.f))
  - note: Largest subnormal: 1023*2^-24 -> 0x03FF.

- **max_f16_finite** — `v_cvt_f16_f32_e32 v1, v1`
  - setup (raw 32-bit register contents): `{"v1": "0x477FE000 x32"}`
  - oracle expected destination `v1`: `0x00007BFF`
  - live emulator measured: `0x0000FBFF`
  - differing field `value`: oracle `31743`, emulator `64511`
  - admissible alternate readings measured on the same vector: `preserve_dst_high_half=0x477F7BFF`
  - source: ISA rdna2_isa.txt:7571-7577 (D.f16 = flt32_to_flt16(S0.f))
  - note: Largest finite: 65504 -> 0x7BFF.

- **overflow_just_above_max** — `v_cvt_f16_f32_e32 v1, v1`
  - setup (raw 32-bit register contents): `{"v1": "0x477FE100 x32"}`
  - oracle expected destination `v1`: `0x00007BFF`
  - live emulator measured: `0x0000FBFF`
  - differing field `value`: oracle `31743`, emulator `64511`
  - admissible alternate readings measured on the same vector: `preserve_dst_high_half=0x477F7BFF`
  - source: ISA rdna2_isa.txt:7571-7577 (D.f16 = flt32_to_flt16(S0.f))
  - note: OVERFLOW BOUNDARY just above the largest finite and below the tie: 65505 rounds DOWN to 65504, so 0x7BFF. A truncating or round-half-up reading would give infinity here.

- **overflow_tie_at_65520** — `v_cvt_f16_f32_e32 v1, v1`
  - setup (raw 32-bit register contents): `{"v1": "0x477FF000 x32"}`
  - oracle expected destination `v1`: `0x00007C00`
  - live emulator measured: `0x0000FC00`
  - differing field `value`: oracle `31744`, emulator `64512`
  - admissible alternate readings measured on the same vector: `preserve_dst_high_half=0x477F7C00`
  - source: ISA rdna2_isa.txt:7571-7577 (D.f16 = flt32_to_flt16(S0.f))
  - note: ROUNDING TIE AT OVERFLOW: 65520 is exactly half way between 65504 (significand LSB 1, odd) and 65536, which is infinity (LSB 0, even). Round-to-nearest-EVEN therefore gives infinity -> 0x7C00.

- **overflow_above_tie** — `v_cvt_f16_f32_e32 v1, v1`
  - setup (raw 32-bit register contents): `{"v1": "0x477FF100 x32"}`
  - oracle expected destination `v1`: `0x00007C00`
  - live emulator measured: `0x0000FC00`
  - differing field `value`: oracle `31744`, emulator `64512`
  - admissible alternate readings measured on the same vector: `preserve_dst_high_half=0x477F7C00`
  - source: ISA rdna2_isa.txt:7571-7577 (D.f16 = flt32_to_flt16(S0.f))
  - note: Above the tie -> infinity -> 0x7C00.

- **subnormal_round_up** — `v_cvt_f16_f32_e32 v1, v1`
  - setup (raw 32-bit register contents): `{"v1": "0x33400000 x32"}`
  - oracle expected destination `v1`: `0x00000001`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `1`, emulator `0`
  - admissible alternate readings measured on the same vector: `preserve_dst_high_half=0x33400001`
  - source: ISA rdna2_isa.txt:7571-7577 (D.f16 = flt32_to_flt16(S0.f))
  - note: SUBNORMAL ROUNDING: 3*2^-26 = 0.75 * 2^-24 lies between zero and the smallest subnormal and is more than half way up, so the correct RNE result is 0x0001. The value is BELOW 2^-24, which is the region a flush-to-zero reading would lose.

- **subnormal_just_below_normal** — `v_cvt_f16_f32_e32 v1, v1`
  - setup (raw 32-bit register contents): `{"v1": "0x387FF000 x32"}`
  - oracle expected destination `v1`: `0x00000400`
  - live emulator measured: `0x000083FF`
  - differing field `value`: oracle `1024`, emulator `33791`
  - admissible alternate readings measured on the same vector: `preserve_dst_high_half=0x387F0400`
  - source: ISA rdna2_isa.txt:7571-7577 (D.f16 = flt32_to_flt16(S0.f))
  - note: Top of the subnormal range: 4095*2^-26 = 1023.75*2^-24 rounds to 1024*2^-24, the smallest NORMAL -> 0x0400.

- **negate_input_modifier** — `v_cvt_f16_f32_e32 v1, -v1`
  - setup (raw 32-bit register contents): `{"v1": "0x3FC00000 x32"}`
  - oracle expected destination `v1`: `0x0000BE00`
  - live emulator measured: `0x00004200`
  - differing field `value`: oracle `48640`, emulator `16896`
  - admissible alternate readings measured on the same vector: `preserve_dst_high_half=0x3FC0BE00`
  - source: ISA rdna2_isa.txt:7571-7577 (D.f16 = flt32_to_flt16(S0.f))
  - note: INPUT MODIFIER: the document says this conversion `supports input modifiers`. `-v1` with v1 = 1.5 must give -1.5 = 0xBE00: the negate applies to the f32 value and RNE then converts.

### `v_fma_mixlo_f16`

**Reading each side implements.**

- The ISA computes a FP16 fused multiply-add on the FP16 operands and writes the 16-bit result into the LOW half of the destination (rdna2_isa.txt:9355-9361, `D.f[15:0] = S0.f * S1.f + S2.f.`). The live handler decodes each source's FULL 32-bit register as an f32 value, evaluates `a * b + c` in f32 and writes the 32-bit f32 result over the WHOLE destination, so neither the operand width nor the result placement is the ISA's.

**J3 operand forms (static, from the J3 kernel's own disassembly).** 26 distinct form(s); this mnemonic's printed operand 2 is its ordinary destination, not a VOP3B scalar destination, so no scalar-destination count is reported

**Can J3 reach this defect? — `REACHABLE_ON_THE_J3_PATH`**

The divergence is UNCONDITIONAL: on every execution the handler decodes each source's full 32-bit register as an f32 value, evaluates in f32, and writes the 32-bit f32 result over the whole destination. There is no operand shape or value for which this handler implements the ISA's FP16 operand width and half placement, so any one of the 224 J3 executions is a triggering execution -> REACHABLE.

**J3 reachability (cone).** executions on the J3 path: `224`; value-cone nodes `32`; union-cone nodes `32`; contributes to written bytes: `True`.  The 16R cone record puts this mnemonic in the J3 output cone (32 value-cone node(s), 32 union-cone node(s)) and marks it as contributing to written bytes, so the disagreement is on the J3 output path as an upper bound. The cone is a lane-collapsed OVER-APPROXIMATION (16R's own INFERRED note), so this is 'cone-reachable', not a proof that a wrong value reached a store.

- **j3_one_times_two_plus_zero** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00003C00 x32", "v2": "0x00004000 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0xAAAA4000`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2863284224`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x00004000, double_rounding_mul_then_add=0xAAAA4000`
  - source: J3 sample 0x0000000ABA08: v_fma_mixlo_f16 v1, v8, v16, 0 | ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: J3 operand shape, verbatim. 1.0 * 2.0 + 0 = 2.0, placed in the LOW half: destination bits 15:0 high. The declared reading PRESERVES the high half (dst pre-set 0xAAAA5555); the alt zeroes it.

- **hi_vs_lo_separator** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00003E00 x32", "v2": "0x00004000 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0xAAAA4200`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2863284736`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x00004200, double_rounding_mul_then_add=0xAAAA4200`
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: SEPARATOR for the MIX lo/hi distinction: 1.5 * 2 = 3.0 = 0x4200 in the LOW half. The high-half reading of the same arithmetic gives a value that differs in the whole written half.

- **neg_zero_product_and_addend** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00008000 x32", "v2": "0x00003C00 x32", "v3": "0x00008000 x32"}`
  - oracle expected destination `v1`: `0xAAAA8000`
  - live emulator measured: `0x00008000`
  - differing field `value`: oracle `2863300608`, emulator `32768`
  - admissible alternate readings measured on the same vector: `positive_zero=0x00000000, other_half_zeroed=0x00008000, double_rounding_mul_then_add=0xAAAA8000`
  - the emulator's value matches the alternate reading(s): other_half_zeroed
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: OPEN: -0 * 1 + (-0). IEEE 754 gives -0 only when both terms are -0, which holds here -> 0x8000 in the LOW half. The alt reading is +0.

- **mixed_sign_zero_sum** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00008000 x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0xAAAA0000`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2863267840`, emulator `0`
  - admissible alternate readings measured on the same vector: `negative_zero=0x00008000, other_half_zeroed=0x00000000, double_rounding_mul_then_add=0xAAAA0000`
  - the emulator's value matches the alternate reading(s): other_half_zeroed
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: OPEN: -0 * 1 + +0 -> +0 under RNE (mixed-sign zero sum). The alt reading is -0.

- **smallest_subnormal** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00000001 x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0xAAAA0001`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2863267841`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x00000001, double_rounding_mul_then_add=0xAAAA0001`
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: Smallest subnormal: 2^-24 * 1 + 0.

- **largest_subnormal** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x000003FF x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0xAAAA03FF`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2863268863`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x000003FF, double_rounding_mul_then_add=0xAAAA03FF`
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: Largest subnormal: 1023*2^-24.

- **smallest_normal** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00000400 x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0xAAAA0400`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2863268864`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x00000400, double_rounding_mul_then_add=0xAAAA0400`
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: Smallest normal: 2^-14.

- **max_finite** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00007BFF x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0xAAAA7BFF`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2863299583`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x00007BFF, double_rounding_mul_then_add=0xAAAA7BFF`
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: Largest finite: 65504 * 1 + 0 -> 0x7BFF.

- **overflow_to_infinity** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00007BFF x32", "v2": "0x00004000 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0xAAAA7C00`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2863299584`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x00007C00, double_rounding_mul_then_add=0xAAAA7C00`
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: OVERFLOW: 65504 * 2 = 131008 exceeds the f16 range -> infinity.

- **infinity_times_one** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00007C00 x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0xAAAA7C00`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2863299584`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x00007C00, double_rounding_mul_then_add=0xAAAA7C00`
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: Inf * 1 + 0 -> Inf.

- **infinity_times_zero** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00007C00 x32", "v2": "0x00000000 x32", "v3": "0x00003C00 x32"}`
  - oracle expected destination `v1`: `0xAAAA7E00`
  - live emulator measured: `0x00003C00`
  - differing field `value`: oracle `2863300096`, emulator `15360`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x00007E00, double_rounding_mul_then_add=0xAAAA7E00`
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: OPEN: Inf * 0 is the IEEE invalid operation -> quiet NaN. The document's expression `S0.f*S1.f+S2.f` gives no value for it; the declared reading is 0x7E00.

- **qnan_propagation** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00007E00 x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0xAAAA7E00`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2863300096`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x00007E00, double_rounding_mul_then_add=0xAAAA7E00`
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: OPEN: a NaN operand -> the declared reading is the quiet NaN 0x7E00.

- **fused_single_rounding** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00003C01 x32", "v2": "0x00003C01 x32", "v3": "0x0000BC00 x32"}`
  - oracle expected destination `v1`: `0xAAAA1800`
  - live emulator measured: `0x0000BC00`
  - differing field `value`: oracle `2863273984`, emulator `48128`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x00001800, double_rounding_mul_then_add=0xAAAA1800`
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: FUSED vs DOUBLE ROUNDING. a = b = 1 + 2^-10, c = -1. The exact product is 1 + 2^-9 + 2^-20; adding -1 leaves 2^-9 + 2^-20, which rounds (RNE, tie to even) to 2^-9. A multiply-round-then-add implementation rounds the product to 1 + 2^-9 first and then gets 0. The two readings differ and only one of them is 'fused'.

- **fused_tie_in_the_subnormal_grid** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00003C01 x32", "v2": "0x00003C01 x32", "v3": "0x0000BC01 x32"}`
  - oracle expected destination `v1`: `0xAAAA1401`
  - live emulator measured: `0x0000BC01`
  - differing field `value`: oracle `2863272961`, emulator `48129`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x00001401, double_rounding_mul_then_add=0xAAAA1400`
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: FUSED TIE: a = b = 1 + 2^-10, c = -(1 + 2^-10). The exact value is (1+2^-10)^2 - (1+2^-10) = 2^-10 + 2^-20, which is below the smallest normal, so the single rounding happens on the SUBNORMAL grid. Kept separate from the vector above because the rounding grid differs.

- **exact_cancellation_positive_zero** — `v_fma_mixlo_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x0000BC00 x32", "v2": "0x00004000 x32", "v3": "0x00004000 x32"}`
  - oracle expected destination `v1`: `0xAAAA0000`
  - live emulator measured: `0x00004000`
  - differing field `value`: oracle `2863267840`, emulator `16384`
  - admissible alternate readings measured on the same vector: `negative_zero=0x00008000, other_half_zeroed=0x00000000, double_rounding_mul_then_add=0xAAAA0000`
  - source: ISA rdna2_isa.txt:9355-9361 (D.f[15:0] = S0.f*S1.f+S2.f)
  - note: (-1) * 2 + 2 = 0: an exact cancellation, so the sign is +0 under RNE.

### `v_fma_mixhi_f16`

**Reading each side implements.**

- The ISA computes a FP16 fused multiply-add and writes the 16-bit result into the HIGH half of the destination (rdna2_isa.txt:9367-9374, `D.f[31:16] = S0.f * S1.f + S2.f.`). The live handler decodes each source's FULL 32-bit register as an f32 value, evaluates `a * b + c` in f32 and writes the 32-bit f32 result over the WHOLE destination -- the same reading as the MIXLO handler, with no HIGH-half placement at all.

**J3 operand forms (static, from the J3 kernel's own disassembly).** 8 distinct form(s); this mnemonic's printed operand 2 is its ordinary destination, not a VOP3B scalar destination, so no scalar-destination count is reported

**Can J3 reach this defect? — `REACHABLE_ON_THE_J3_PATH`**

The divergence is UNCONDITIONAL: on every execution the handler decodes each source's full 32-bit register as an f32 value, evaluates in f32, and writes the 32-bit f32 result over the whole destination. There is no operand shape or value for which this handler implements the ISA's FP16 operand width and half placement, so any one of the 32 J3 executions is a triggering execution -> REACHABLE.

**J3 reachability (cone).** executions on the J3 path: `32`; value-cone nodes `32`; union-cone nodes `32`; contributes to written bytes: `True`.  The 16R cone record puts this mnemonic in the J3 output cone (32 value-cone node(s), 32 union-cone node(s)) and marks it as contributing to written bytes, so the disagreement is on the J3 output path as an upper bound. The cone is a lane-collapsed OVER-APPROXIMATION (16R's own INFERRED note), so this is 'cone-reachable', not a proof that a wrong value reached a store.

- **j3_one_times_two_plus_zero** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00003C00 x32", "v2": "0x00004000 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0x40005555`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `1073763669`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x40000000, double_rounding_mul_then_add=0x40005555`
  - source: J3 sample 0x0000000ABA28: v_fma_mixhi_f16 v1, v8, v19, 0 | ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: J3 operand shape, verbatim. 1.0 * 2.0 + 0 = 2.0, placed in the HIGH half: destination bits 15:0 low. The declared reading PRESERVES the low half (dst pre-set 0xAAAA5555); the alt zeroes it.

- **hi_vs_lo_separator** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00003E00 x32", "v2": "0x00004000 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0x42005555`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `1107318101`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x42000000, double_rounding_mul_then_add=0x42005555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: SEPARATOR for the MIX lo/hi distinction: 1.5 * 2 = 3.0 = 0x4200 in the HIGH half. The low-half reading of the same arithmetic gives a value that differs in the whole written half.

- **neg_zero_product_and_addend** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00008000 x32", "v2": "0x00003C00 x32", "v3": "0x00008000 x32"}`
  - oracle expected destination `v1`: `0x80005555`
  - live emulator measured: `0x00008000`
  - differing field `value`: oracle `2147505493`, emulator `32768`
  - admissible alternate readings measured on the same vector: `positive_zero=0x00000000, other_half_zeroed=0x80000000, double_rounding_mul_then_add=0x80005555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: OPEN: -0 * 1 + (-0). IEEE 754 gives -0 only when both terms are -0, which holds here -> 0x8000 in the HIGH half. The alt reading is +0.

- **mixed_sign_zero_sum** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00008000 x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0x00005555`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `21845`, emulator `0`
  - admissible alternate readings measured on the same vector: `negative_zero=0x80000000, other_half_zeroed=0x00000000, double_rounding_mul_then_add=0x00005555`
  - the emulator's value matches the alternate reading(s): other_half_zeroed
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: OPEN: -0 * 1 + +0 -> +0 under RNE (mixed-sign zero sum). The alt reading is -0.

- **smallest_subnormal** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00000001 x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0x00015555`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `87381`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x00010000, double_rounding_mul_then_add=0x00015555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: Smallest subnormal: 2^-24 * 1 + 0.

- **largest_subnormal** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x000003FF x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0x03FF5555`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `67065173`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x03FF0000, double_rounding_mul_then_add=0x03FF5555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: Largest subnormal: 1023*2^-24.

- **smallest_normal** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00000400 x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0x04005555`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `67130709`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x04000000, double_rounding_mul_then_add=0x04005555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: Smallest normal: 2^-14.

- **max_finite** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00007BFF x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0x7BFF5555`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2080331093`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x7BFF0000, double_rounding_mul_then_add=0x7BFF5555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: Largest finite: 65504 * 1 + 0 -> 0x7BFF.

- **overflow_to_infinity** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00007BFF x32", "v2": "0x00004000 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0x7C005555`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2080396629`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x7C000000, double_rounding_mul_then_add=0x7C005555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: OVERFLOW: 65504 * 2 = 131008 exceeds the f16 range -> infinity.

- **infinity_times_one** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00007C00 x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0x7C005555`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2080396629`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x7C000000, double_rounding_mul_then_add=0x7C005555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: Inf * 1 + 0 -> Inf.

- **infinity_times_zero** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00007C00 x32", "v2": "0x00000000 x32", "v3": "0x00003C00 x32"}`
  - oracle expected destination `v1`: `0x7E005555`
  - live emulator measured: `0x00003C00`
  - differing field `value`: oracle `2113951061`, emulator `15360`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x7E000000, double_rounding_mul_then_add=0x7E005555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: OPEN: Inf * 0 is the IEEE invalid operation -> quiet NaN. The document's expression `S0.f*S1.f+S2.f` gives no value for it; the declared reading is 0x7E00.

- **qnan_propagation** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00007E00 x32", "v2": "0x00003C00 x32", "v3": "0x00000000 x32"}`
  - oracle expected destination `v1`: `0x7E005555`
  - live emulator measured: `0x00000000`
  - differing field `value`: oracle `2113951061`, emulator `0`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x7E000000, double_rounding_mul_then_add=0x7E005555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: OPEN: a NaN operand -> the declared reading is the quiet NaN 0x7E00.

- **fused_single_rounding** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00003C01 x32", "v2": "0x00003C01 x32", "v3": "0x0000BC00 x32"}`
  - oracle expected destination `v1`: `0x18005555`
  - live emulator measured: `0x0000BC00`
  - differing field `value`: oracle `402675029`, emulator `48128`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x18000000, double_rounding_mul_then_add=0x18005555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: FUSED vs DOUBLE ROUNDING. a = b = 1 + 2^-10, c = -1. The exact product is 1 + 2^-9 + 2^-20; adding -1 leaves 2^-9 + 2^-20, which rounds (RNE, tie to even) to 2^-9. A multiply-round-then-add implementation rounds the product to 1 + 2^-9 first and then gets 0. The two readings differ and only one of them is 'fused'.

- **fused_tie_in_the_subnormal_grid** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x00003C01 x32", "v2": "0x00003C01 x32", "v3": "0x0000BC01 x32"}`
  - oracle expected destination `v1`: `0x14015555`
  - live emulator measured: `0x0000BC01`
  - differing field `value`: oracle `335631701`, emulator `48129`
  - admissible alternate readings measured on the same vector: `other_half_zeroed=0x14010000, double_rounding_mul_then_add=0x14005555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: FUSED TIE: a = b = 1 + 2^-10, c = -(1 + 2^-10). The exact value is (1+2^-10)^2 - (1+2^-10) = 2^-10 + 2^-20, which is below the smallest normal, so the single rounding happens on the SUBNORMAL grid. Kept separate from the vector above because the rounding grid differs.

- **exact_cancellation_positive_zero** — `v_fma_mixhi_f16 v1, v1, v2, v3`
  - setup (raw 32-bit register contents): `{"v0": "0xAAAA5555 x32", "v1": "0x0000BC00 x32", "v2": "0x00004000 x32", "v3": "0x00004000 x32"}`
  - oracle expected destination `v1`: `0x00005555`
  - live emulator measured: `0x00004000`
  - differing field `value`: oracle `21845`, emulator `16384`
  - admissible alternate readings measured on the same vector: `negative_zero=0x80000000, other_half_zeroed=0x00000000, double_rounding_mul_then_add=0x00005555`
  - source: ISA rdna2_isa.txt:9367-9374 (D.f[31:16] = S0.f*S1.f+S2.f)
  - note: (-1) * 2 + 2 = 0: an exact cancellation, so the sign is +0 under RNE.

## Negative controls

- **NC_A** — the oracle's own self-test can fail: {"name": "NC_A_oracle_self_test_is_falsifiable", "break": "oracle16.BREAK = {'mul_lo_u16'}", "mnemonic": "v_mul_lo_u16", "disagreements_before": 0, "disagreements_after": 3, "changed": true, "n_vectors": 6, "examples": [{"vector": "j3_imm_0xab_vs_v9", "expect_clean": 1197, "expect_sabotaged": 683410605, "disagreement_fields": ["value"]}, {"vector": "j3_v17_times_6", "expect_clean": 65530, "expect_sabotaged": 393210, "disagreement_fields": ["value"]}, {"vector": "max_times_max_truncates", "expect_clean": 1, "expect_sabotaged": 4294836225, "disagreement_fields": ["value"]}, {"vector": "zero_case", "expect_clean": 0, "expect_sabotaged": 0, "disagreement_fields": []}], "other_mnemonics_unaffected": "not re-measured under the break"}
- **NC_B** — a mutation of the live emulator handler is detected: 16/16 mnemonics fired, 16/16 changed an observation.
- **NC_C** — a zero-comparison run is refused: n_comparisons = 198, refused = False
- **NC_D** — the comparator rejects an expectation with one bit flipped: 16/16 cases

### NC_B detail

| mnemonic | handler | owner | shape | fired | invocations | vectors changed | changed fields |
|---|---|---|---|---|---|---|---|
| `s_mov_b64` | `op_s_mov_b64` | Core | src1_src0_swapped | True | 7 | 6 | error,value |
| `v_add_co_u32` | `op_v_add_co_u32` | Core | src1_src0_swapped | True | 18 | 9 | error,extra.s0,extra.s2,extra.vcc,value |
| `v_add_co_ci_u32_e64` | `op_v_add_co_ci_u32` | Core | src1_src0_swapped | True | 18 | 9 | error,extra.v0@1,extra.v0@2,extra.v10@1,extra.v10@2,extra.v10@31,extra.vcc,value |
| `v_cmp_gt_i32_e64` | `_cmp_dispatch` | SwinCore | src1_src0_swapped | True | 11 | 7 | error,value |
| `v_cmp_gt_u32_e64` | `_cmp_dispatch` | SwinCore | src1_src0_swapped | True | 9 | 6 | error,value |
| `v_cmp_lt_i32_e64` | `_cmp_dispatch` | SwinCore | src1_src0_swapped | True | 9 | 6 | error,value |
| `v_lshlrev_b16` | `op_v_lshlrev_b16` | Core8 | src1_src0_swapped | True | 8 | 7 | error,value |
| `v_lshrrev_b16` | `op_v_lshrrev_b16` | Core | src1_src0_swapped | True | 8 | 7 | error,value |
| `v_min_u32_e32` | `op_v_min_u32` | Core8 | src1_src0_swapped | True | 8 | 7 | error,value |
| `v_mul_lo_u16` | `op_v_mul_lo_u16` | Core8 | src1_src0_swapped | True | 6 | 6 | error,value |
| `v_mul_u32_u24_e32` | `op_v_mul_u32_u24` | Core8 | src1_src0_swapped | True | 6 | 6 | error,value |
| `v_pack_b32_f16` | `op_v_pack_b32_f16` | Core8 | src1_src0_swapped | True | 8 | 6 | error,value |
| `v_sub_nc_u16` | `op_v_sub_nc_u16` | Core | src1_src0_swapped | True | 8 | 7 | error,value |
| `v_cvt_f16_f32_e32` | `op_v_cvt_f16_f32` | Core | src1_src0_swapped | True | 24 | 24 | error,value |
| `v_fma_mixlo_f16` | `op_v_fma_mixlo_f16` | Core | src1_src0_swapped | True | 16 | 16 | error,value |
| `v_fma_mixhi_f16` | `op_v_fma_mixhi_f16` | Core8 | src1_src0_swapped | True | 16 | 16 | error,value |

## What could not be established

- The OPSEL field mapping for V_FMA_MIXLO_F16 / V_FMA_MIXHI_F16: the text gives `0=src[31:0], 1=src[31:0], 2=src[15:0], 3=src[31:16]`, where entries 0 and 1 are identical. Every vector fixes OPSEL at the low half; the J3 sites that print `op_sel_hi:[...]` are NOT modelled.
- Whether bits [31:16] of a 16-bit-result destination are preserved or zeroed for the B16 ALU ops and V_CVT_F16_F32: the ISA states this for V_MAD_U16 only, and the measurement reports which reading the emulator implements rather than resolving the text.
- NaN sign and payload propagation for V_CVT_F16_F32 and the FMA_MIX mnemonics; only the declared readings are compared.
- Whether the carry-out register of the VOP3B forms is written in EXEC-clear lanes.
- Whether a wrong value from any of these instructions actually reaches a global store on the J3 path: the 16R cone is a lane-collapsed over-approximation, so 'in the cone' is an upper bound, not a trace of one value to one store.
- Anything about real hardware: this is a host-only measurement of a Python emulator and says nothing about gfx1030 silicon.

## Open questions recorded per mnemonic

- `s_mov_b64`: How a 32-bit SGPR source names a 64-bit operand is not stated; the declared reading is zero-extension of the named SGPR.
- `v_add_co_u32`: The value the carry-out register takes in lanes where EXEC is clear is not stated; two admissible readings are recorded on the EXEC vector.
- `v_add_co_ci_u32_e64`: Carry-in source: the text says `VCC` at :7283 and `the SGPR-pair at S2.u` at :7281; a per-lane bit of the named register is the declared reading. The value the carry-out register takes in EXEC-clear lanes is not stated.
- `v_lshlrev_b16`: Bits [31:16] of the destination: the text gives D.u[15:0] only. Declared reading is preservation, inferred from V_MAD_U16 (:10244-10248), which states the convention for itself; the zero-extending alternative is measured.
- `v_lshrrev_b16`: The expression line at :10150 is WRONG: it prints `D.u16 = S0.u16 * S1.u16.` under the caption `Logical shift right, count is in the first operand`. The reading used is the one V_LSHLREV_B16 (:10226) and V_ASHRREV_I16 (:10153) agree on. Bits [31:16] of the destination, as above.
- `v_mul_lo_u16`: The document gives no expression line for this mnemonic at all, only the prose 'Multiply two unsigned shorts.'; the 16-bit truncation is from the destination width. Bits [31:16] of the destination, as above.
- `v_pack_b32_f16`: The half-to-position mapping is stated explicitly; only how an out-of-range or float-literal operand token is spelled is unstated.
- `v_sub_nc_u16`: The block prints BOTH `D.u16 = S0.u16 + S1.u16.` (:10139) and `D.u16 = S0.u16 - S1.u16.` (:10145). The declared reading is the subtraction, which the mnemonic and the caption both say. Bits [31:16] of the destination, as above.
- `v_cvt_f16_f32_e32`: NaN handling is not stated at all: the text gives `D.f16 = flt32_to_flt16(S0.f)` with accuracy and denormal behaviour only. Declared readings: quiet NaN -> 0x7E00 with the sign cleared; both alternatives (sign preserved, payload preserved) are measured. Bits [31:16] of the destination: the text gives a 16-bit destination only. Declared reading: zero-extension.
- `v_fma_mixlo_f16`: The half of the destination NOT written is not stated (V_MAD_U16 states it for itself at :10244-10248; V_FMA_MIX* does not). Declared reading: preserved; the zero-extending alternative is measured. OPSEL: the text says `0=src[31:0], 1=src[31:0], 2=src[15:0], 3=src[31:16]`, in which entries 0 and 1 are identical -- one of them is wrong. Every vector here fixes OPSEL at the low half of each source and passes no `op_sel` token, so the OPSEL mapping is NOT measured. NaN / Inf / zero-sign rules are not stated; the declared readings are IEEE 754's defaults and are recorded on the affected vectors.
- `v_fma_mixhi_f16`: As V_FMA_MIXLO_F16: the untouched half, the OPSEL mapping and the NaN / Inf rules are all unstated. The J3 disassembly prints an `op_sel_hi:[...]` operand for several of these sites; that token is an assembler annotation and is deliberately not modelled here.

## Read-back checks

- `vector_count_matches`: True
- `comparison_count_nonzero`: True
- `per_mnemonic_covers_16`: True
- `every_vector_has_a_measurement`: True
- `nc_d_fired`: True
- `nc_c_ok`: True
- `emu_hash_pinned`: True
- `host_only`: True
- `gpu_execution_performed_false`: True
- `every_defect_has_a_stated_reading`: True
- `all_sixteen_have_a_j3_sample`: True
- `nc_b_at_least_6_rejected`: True
- `nc_a_changed`: True

## MEASURED vs INFERRED vs DECLARED

- **MEASURED** — every count, every comparison, every differing field, the emulator sha256 and module path, the mutation invocation counts and observation deltas, the NC results.
- **INFERRED** — that the J3 kernel's disassembly range covers the operand shapes J3 executed (the samples are the module's own text inside the kernel's address range, which also contains the recorded store-site PCs); and that cone membership bounds the output path.
- **DECLARED** — every reading the ISA text does not state: the untouched half of a 16-bit destination, NaN propagation, the sign of an exact-zero FMA result, the value of a mask register in EXEC-clear lanes, the carry-in source token. Each appears under Open questions and each carries an alternate reading in the JSON, so the measurement -- not the oracle -- decides which one the emulator implements.
- **NOT CLAIMED** — nothing about real gfx1030 hardware. A disagreement here is a disagreement between two host-side models.
