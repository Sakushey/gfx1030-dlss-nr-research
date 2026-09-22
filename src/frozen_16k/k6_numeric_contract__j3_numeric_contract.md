# J3 numeric contract (Phase 16K, work item K6)

**Status: FROZEN. No physical output has been observed.**

This contract was written before any GPU ran. No tolerance below was fitted to
a device result, because there is no device result: J3 has not been executed,
no GPU kernel has been launched in this phase, and the only bytes in this
directory came out of a host-side Python emulator of the gfx1030 ISA.

Frozen against:

| artefact | value |
|---|---|
| kernel | `_Z10k_swin_varILi32ELb0EEv9VarParams` (`k_swin_var<32,false>`) |
| geometry | grid(1,1,1) block(256,1,1) shared=0, 8 waves |
| VarParams | X=576, Y=960, pair=(0,0), flags=0x1 |
| input | `pattern_at(offset)` from 0 in every region, generator A |
| J3 harness bytes | `72335a20c96d734e26b757e29955c0ef58fe3fe32c72e89da79024e2ed3e13f3` |

---

## 1. Region classification

Every output region the kernel writes at the J3 geometry, classified into
exactly one of INTEGER/CONTROL, COPY/BITWISE, FP16, FP32, UNKNOWN.

| VarParams slot | written | writes | store widths | class |
|---|---|---|---|---|
| 0x00 | no | 0 | — | INTEGER/CONTROL |
| 0x08 | yes | 2048 | 1 byte | **UNKNOWN** |
| 0x10 | no | 0 | — | INTEGER/CONTROL |
| 0x30 | no | 0 | — | INTEGER/CONTROL |
| 0x38 | no | 0 | — | INTEGER/CONTROL |
| 0xA0 | yes | 4608 | 1 byte (4608), 4 bytes (1 site) | **UNKNOWN** |

**Tally: INTEGER/CONTROL 4, COPY/BITWISE 0, FP16 0, FP32 0, UNKNOWN 2.**

Four of the six slots are never written at this geometry and are listed as
INTEGER/CONTROL for one reason only: a region that is never written carries
no numeric result, so it is compared as unchanged input, bit-exactly. That is
the whole of the claim; it is not a statement that the kernel computes an
integer there.

Two slots are written, and **both are UNKNOWN. Neither is promoted to FP16 or
FP32 to make this table look complete.**

Why they are UNKNOWN, and not FP16:

* Both store **1-byte** values. FP16 is 2 bytes and FP32 is 4. A 1-byte datum
  cannot hold either, whatever arithmetic produced it.
* The arithmetic upstream of those 1-byte stores is float arithmetic — the
  canvas chain contains `v_cvt_f32_f16`, `v_log_f32`, `v_floor_f32`,
  `v_ldexp_f32`, `v_mul_f32`, `v_rndne_f32`, `v_cvt_i32_f32` — so the stored
  byte is a **float-derived code**, not a float value.
* The byte population agrees. Under the corrected emulator the canvas stores
  3184 bytes over 256 distinct values, and the four largest bins are `0x00`
  (624), `0xFE` (390), `0x7E` (172) and `0xFF` (85) — E4M3 ±0, ±max-finite and
  ±NaN. `0x7E` and `0xFF` are exactly the clamp (`v_min_i32 .., 0x7e`) and the
  NaN sentinel (`v_mov_b32_e32 v3, 0x7f`) the encoder is built around. That is
  a float code population, not the low byte of anything.
* The encoder's structure is an **E4M3 software encoder**: sign via
  `v_cmp_gt_f16` + `v_cndmask_b32_e64 v4, 0, 0xffffff80`; exponent via
  `v_log_f32`/`v_floor_f32`/`v_ldexp_f32`; 3-bit mantissa via `v_add_f32 -1.0`,
  `v_mul_f32 8.0`, `v_rndne_f32`; packing via `v_lshl_add_u32 .., 3, 56`
  (3 bits, bias 56 = 7<<3); clamp via `v_min_i32 .., 0x7e`; NaN sentinel
  `0x7f`. An 8-bit float is **neither of the two float classes this census is
  permitted to name**, so it is UNKNOWN by the contract's own definition.

`slot_0xA0` also carries one 4-byte `global_store_dword` at `0x000ACC24` whose
chain is integer/bitwise. The writing PCs do not agree on one class, which is
itself sufficient to make the region UNKNOWN.

---

## 2. Comparison rules

### 2.1 UNKNOWN — refuse-to-pass

**A region classified UNKNOWN is not compared numerically and cannot pass.**
It must be resolved before J3 is authorised.

Resolving it does not mean picking a tolerance. It means establishing what the
stored datum *is* — for `slot_0xA0`, by decoding the observed bytes against the
E4M3 encoder's own arithmetic, or by finding the mod's actual consumer of that
buffer and reading the format off it. Until then the region is compared only
as **raw bytes, bit-exactly**, and any mismatch is a hard failure with no
tolerance band. This is deliberate: an honest UNKNOWN that forces a region to
be checked as raw bytes is more useful than a wrong FP16 label, because the
raw-byte check is a real test and a wrong label is a false pass.

No tolerance is invented for `slot_0x08` or `slot_0xA0`. There is none in this
document.

### 2.2 INTEGER/CONTROL — bit-exact, tolerance 0

**Derived, not chosen.** The operations are integer and bitwise. Python
integers are exact and the emulator implements these ops with `& U32`, shifts
and masks — no rounding step exists anywhere in the chain, so there is no
error to bound. The only correct comparison is byte-identity; a tolerance
would be a bug.

In force at J3 for: `slot_0x00`, `slot_0x10`, `slot_0x30`, `slot_0x38`, each
compared against the pre-launch input pattern it was filled with.

### 2.3 COPY/BITWISE — bit-exact, tolerance 0

**Derived, not chosen**, by the same argument: a copy or a bitwise transform
has no rounding. **Not in force at J3** — no region is classified
COPY/BITWISE. Stated for completeness so a later phase inherits the rule
rather than re-deciding it.

### 2.4 FP16 — 0 ULP per operation; N·2⁻¹¹ relative for a chain of N

**Derived from the representation, not chosen.** binary16 is 1 sign bit, 5
exponent bits, **10 explicit mantissa bits**; the unit roundoff is
u = 2⁻¹¹ ≈ 4.88e-4.

* A single correctly-rounded fp16 operation on exactly-representable inputs
  is exact: tolerance 0 ULP.
* A chain of N correctly-rounded fp16 operations has a worst-case forward
  relative error of N·u. The bound grows with N; it is not a constant.

**Not in force at J3** — no region is FP16. Note explicitly that a *single
absolute* fp16 tolerance would be a judgement call, not a derivation: fp16's
normal range spans 2⁻¹⁴ to 2¹⁵, so one absolute number cannot be right at both
ends. Any future fp16 comparison must scale by the exponent, or compare ULP.

### 2.5 FP32 — N·2⁻²⁴ relative for a sum of N terms

**Derived from the representation, not chosen.** binary32 is 1 sign bit, 8
exponent bits, **23 explicit mantissa bits**; u = 2⁻²⁴ ≈ 5.96e-8.

* A single correctly-rounded fp32 operation on exactly-representable inputs is
  exact: tolerance 0 ULP.
* A sum or dot product of N terms has the standard forward bound
  |error| ≤ (N·u / (1 − N·u)) · Σ|xᵢ|. This grows with N and with the
  magnitude of the inputs — both known before any device ran, which is why it
  can be frozen now.

**Not in force at J3** — no region is FP32. And note: a flat "1e-6 relative"
or "1 ULP" fp32 tolerance would be a **judgement call, not a derivation**,
because neither follows from the format; the bound above does. If a later
phase wants a flat number, it must say it is a choice.

### 2.6 Judgement calls, declared

There are two, and neither is in force at J3:

1. **The decision to compare float-derived codes as raw bytes** rather than
   decode them. This is a choice, not a derivation: decoding them would
   require knowing the format for certain, which is the thing that is UNKNOWN.
2. **Any absolute floor** added to a float tolerance to stop a near-zero
   result demanding a zero tolerance. No such floor is defined here, because
   no float region is in force. A future phase that adds one must mark it as
   a judgement call.

---

## 3. Measured, inferred, and UNKNOWN

### Measured (reproducible, host-only, no GPU)

* **The census.** Which slots are written, by which PCs, at what width, over
  which logical offsets, and how many times. `j3_output_regions.json`.
* **The reach.** How far into each declared region the kernel actually goes,
  under three canvas declarations and on both emulator paths.
  `j3_reach_evidence.json`.
* **The byte populations.** Every stored byte, under both emulator paths,
  per region. `j3_expected_outputs.json`.
* **Four emulator defects**, each with a minimal reproduction that runs the
  real handler and compares against the ISA:
  * `p16k_k6_vcmpx_repro.py` — `Core._vcmpx` reads `vget(ops[1])` for *both*
    operands when `len(ops) < 3`. That is right for `v_cmp_*`, which carries a
    destination, and wrong for `v_cmpx_*`, which does not: the disassembler
    prints `v_cmpx_<c> src0, src1`, so `ops[0]` is src0. Every `v_cmpx_*` was
    evaluated as `fn(src0, src0)`. Measured consequence: the kernel's
    `v_cmpx_neq_f32_e32 0, v5` at `0x000B5124` yields EXEC=0 instead of
    EXEC=0xFFFFFFFF, so `s_cbranch_execz 63` skips the entire E4M3 magnitude
    encoder and the only bytes ever stored are `0x00`/`0x80`.
  * `p16k_k6_f32_arith_repro.py` — `Core._vfp` reads operands through
    `vget(..., fp=True)`, but `Core.vget` returns the **raw register** for a
    `vN` token; `fp` is honoured only for literals. Register operands
    therefore reach the arithmetic as f32 *bit patterns*, not values.
    Measured: 11 of 13 cases disagree with the ISA. `v_floor_f32` of 448.0
    returns `0x4E87C000` (f32(0x43E00000) = f32(1138753536)), which is exactly
    the raw-bits model and nothing else.
  * `_fp_cmp_cond` has no `v_cmp_ngt_f32` entry, so the encoder's
    `v_cmpx_ngt_f32_e32 0x3c800000, v5` raises `KeyError` once defect 1 stops
    masking it.
  * `op_v_lshl_add_u32` computes `(src1 << src0) + src2`; the ISA is
    `(src0 << src1) + src2`. Measured: `v_lshl_add_u32 v2, v1(=8), 3, 56`
    returns 824 = (3<<8)+56, not 120 = (8<<3)+56. This is on the encoder's
    critical path (`v_lshl_add_u32 v6, v6, 3, 56` at `0x000B51F4`).

  Defects 1 and 2 are repaired by a **K6-local monkey-patch**
  (`p16k_k6_run.install_vcmpx_correction()`); defects 3 and 4 are **not
  repaired**, and are reported instead. Nothing outside this directory was
  modified.

### Inferred

* **The region classification.** It is read off the disassembly — the store
  instruction's width and the arithmetic that produces its value operand —
  not off a pointer's name. It is an inference from static evidence, and it is
  labelled as one.
* **That the canvas byte code is E4M3.** Inferred from the encoder's
  structure (f16 input, log2/floor exponent extraction, ×8 + round-nearest
  mantissa, `<<3 + 56` pack, `min 0x7e` clamp, `0x7f` NaN sentinel) and from
  the byte population being dominated by `0x7E`/`0x7F`/`0xFE`/`0xFF`. It is
  **not** proven by decoding a known input end to end, and this document does
  not claim it is.

### UNKNOWN

* **The numeric value the hardware will write to the canvas.** The emulator
  cannot supply it: the encoder is f32 arithmetic (defects 3 and 4) and the
  format is not one of the four classes this census may name.
* **Whether the emulator's per-workgroup loop bound is faithful.** Measured
  under the corrected path at 4 MiB: grid(1,1,1) and grid(120,72,1) both give
  `('ALL_ENDED', 14398)`, 6656 stores, and for `slot_0xA0` the *same* 4608
  writes over the *same* offsets 0..657887 and the *same* 7296 reads reaching
  2621471. A tile-driven kernel given 120×72 tiles should not behave
  identically to one given a single tile, so the 2.6 MB read reach may be an
  emulator artefact of its single-workgroup model. This is the same class of
  question J1 raised about residual global reads, and it is unresolved.
* **Whether `slot_0x08`'s 1-byte stores belong to the same encoder family** as
  the canvas, or to a different float-derived code. Its bytes are also fp8
  sentinels (`0xFF`/`0xFE`/`0x7E`), which suggests the same family, but the
  chain walk reaches it through a different block and this is not established.

---

## 4. The reference bytes are not a certified prediction

`j3_expected_outputs.bin` contains **the emulator's** post-launch bytes, with
the K6-local correction applied and the canvas declared at 4 MiB. Every region
carries a `reference_trust` field in `j3_expected_outputs.json`, and for J3
**every written region reads `NOT CERTIFIED`** — both because their class is
UNKNOWN, and because their bytes differ between the frozen and corrected
emulator paths. The frozen path is the one the eleven host gates validate; the
corrected path is what the ISA specifies. Recording only one would make the
difference an assertion rather than a measurement.

The `.bin` is therefore a **regression fixture and a shape witness** — it fixes
what the emulator produces today so a future change to the emulator or the
kernel shows up as a diff — and it is explicitly **not** a prediction of what
the hardware will write.

---

## 5. Canvas size, and the frozen input

**Which size this contract used.** The region map and the reach evidence
declare the canvas at **three** sizes, each measured separately:

| key | bytes | what it is |
|---|---|---|
| `harness` | 1·1·8192 = 8192 | what the frozen J3 harness will actually `hipMalloc` |
| `recovered` | 1·1·32768 = 32768 | K3's shift-15 formula for block 256 |
| `over4mib` | 4·1024·1024 = 4194304 | an over-declaration, not a candidate size — the only declaration under which all eleven host gates pass |

**The reference is taken from `over4mib`**, because it is the only
declaration under which every global access the kernel makes lands inside a
declared region. The `harness` run is not usable as a reference, and
`j3_reach_evidence.json` measures why.

**Does the frozen input's hard-coded 8192 sit upstream of this?** No — for the
K6 tools. `p16j_j3_input_hash.py:35` carries `CANVAS = 1 * 1 * 8192` and that
constant does determine the frozen J3 **input hash**
(`592766ef55c9544d0f3da9b7d496d635d13799842ef5c97181a2f45308e7a2f8`), which is
the K3 finding. But K6 does not import that script. K6 imports `p16j_input.py`
for `pattern_at`, `PatternMem` and `regions_for` only, and passes its **own**
canvas size to `regions_for`. The frozen input generator was not modified.

The consequence is unchanged and is stated in `j3_reach_evidence.json`: under
the frozen 8192-byte declaration the canvas takes **1792 out-of-bounds reads
and 2048 out-of-bounds writes**, reaching offset 2,621,471 in reads and
657,887 in writes. At K3's 32,768 the result is **identical** — every one of
those accesses is still out of bounds — so the mis-sizing is not a factor of
four, it is far larger. The reach is the same on both emulator paths, so this
is a property of the address arithmetic, not of the value semantics.

**This contract does not authorise J3.** The frozen canvas is too small for
the kernel's own accesses, both written regions are UNKNOWN, and the reference
bytes are not certified. Those three must be resolved first.

---

## 6. How to check every claim here

```
python p16k_k6_vcmpx_repro.py        # emulator defect 1 (+2), minimal
python p16k_k6_f32_arith_repro.py    # emulator defect 3 (+4), minimal
python p16k_k6_trace_encoder.py --wave 1 --pass 0 --lane 0
python p16k_k6_trace_encoder.py --wave 1 --pass 0 --lane 0 --corrected
python p16k_k6_probe_values.py --waves 1
python p16k_k6_numeric.py            # regenerates all four artefacts
```

Host-only. No GPU, no HIP call, no GTA, no driver, registry, clock or
firmware change. Nothing outside `phase16k_pretest/k6_j3_numeric/` is written.
