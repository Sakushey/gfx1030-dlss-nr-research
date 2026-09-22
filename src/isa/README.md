# phase16r/isa — Phase 16R items R9, R10, R11

Host-only emulator qualification. **No GPU execution, no HIP call, nothing
armed or deployed.** Every number below comes from a run whose command is in
the artifact's own `sources` / `commands` block, and every artifact in this
folder was read back and checked after it was written.

Everything this stream wrote is under `phase16r/isa/`. The tools installed a
`sys.addaudithook` write-intent audit for each run: **1 write intent outside
`phase16r/isa`** (`os.mkdir` of the pre-existing
`phase16e_candidate_e/tools/../out`), **state-changing: 0**.

## Files

| path | what |
|---|---|
| `R9_DIVISION_SEMANTICS.json` | R9 artifact — the V_DIV sequence on the J3 path |
| `N7_RELEASE_GATE.json` | R10 artifact — the release gate, one top-level verdict |
| `J3_INSTRUCTION_CONFORMANCE.json` | R11 artifact — the instruction-level J3 conformance matrix |
| `tools/r9_*.py`, `tools/r10_n7_gate.py`, `tools/r11_j3_matrix.py` | the tools that produced them |
| `logs/` | raw tool output and the re-run oracle results |
| `ref/rdna2_isa.txt`, `ref/rdna2_isa_wayback.pdf`, `ref/llvm_asm_gfx8.rst` | the reference texts R9 and R11 read semantics out of |

Re-run (from the project root):

```
python phase16r/isa/tools/r9_j3_div.py
python phase16r/isa/tools/r10_n7_gate.py
python phase16r/isa/tools/r11_j3_matrix.py
```

## R9 — division semantics on the J3 path

**Verdict `BLOCKED_J3_DIVISION_SEMANTICS`.** The emulator implements none of
`V_DIV_SCALE_F32` / `V_DIV_FMAS_F32` / `V_DIV_FIXUP_F32`; it substitutes
structural approximations. Measured, not inferred: J3 executes 144
`v_div_scale_f32`, 72 `v_div_fmas_f32`, 72 `v_div_fixup_f32`.

Two independent reasons, both measured:

1. J3 reaches `V_DIV_SCALE_F32`'s missing `else` on **100%** of its 144
   executed scale instances (the ISA text assigns no value there), and
2. the `exponent(S2.f) <= 23` clause is textually ambiguous between the biased
   and unbiased exponent; the two readings select **different** branches on
   this fixture.

The fixture is sensitive exactly where the text is silent: three admissible
readings give three digests, `1a12d7d5926de60b` (biased / passthrough),
`8f38cbfa4bf1328c` (unbiased), `5881dae9a75f55ec` (`else -> 0.0`), with ticks
13590 / 14085 / 13305. No second independent source resolves the clause; the
corroborating LLVM file fixes only the mnemonic and operand list. The smallest
experiment that would close it: one hardware `v_div_scale_f32` with S0 = 0.5,
S1 = 0.5, S2 = 0.4375.

## R10 — the N7 release gate

**Verdict `PASS`**, 9 measured boolean gates, `blocking_gates: []`. The stale
mutation `f16c_sign_from_bit31` is classified `RETIRED_STALE_NEGATIVE_CONTROL`
with provenance (the `_f16c` defect it inverts was repaired in 16L, so it
rejects nothing), and is replaced in the ACTIVE set by
`f16c_sign_from_bit16_DEFECT_RESTORED`, which is detected. Replay of the
original frozen runner: **117 vectors / 24,355 comparisons / 0 disagreeing**,
sha256 pinned. The hash-pin gate accepts the clean input and refuses corrupt
and missing ones. G6: 14/14 active must-reject mutations detected.

`corrected_gate_record` keeps the first run's FALSE POSITIVE visible: G1 was
originally written over the whole project tree, returned FAIL on 258
created / 137 modified files belonging to other streams, and was re-scoped to
**this stream's own writes**; the top-level verdict is the corrected gate's.

## R11 — instruction-level J3 conformance matrix

`J3_INSTRUCTION_CONFORMANCE.json`, sha256 `90c2da19…`, one row per union-cone
mnemonic (146 rows from the J3 output-cone record), each carrying: mnemonic,
family, executed count, the four per-cone node counts, handler, handler
owner/MRO path resolved **live on the instantiated `BothCore`**, semantic
source, independent oracle, oracle vectors, comparisons, detecting mutation,
mutation effect observed, mutation rejected, status.

Statuses (only the four the brief allows):

```
VERIFIED_INDEPENDENTLY         61
VERIFIED_BY_EXACT_EQUIVALENCE   0
NOT_OUTPUT_RELEVANT            66
BLOCKED                        19
```

**`J3_INSTRUCTION_SEMANTICS_BLOCKED = 19` — the requirement is NOT met, so
the expected-output freeze must not proceed.** The blocked mnemonics:

* `ISA_DIVISION_SEQUENCE_NOT_IMPLEMENTED` (3) — `v_div_scale_f32` (144),
  `v_div_fmas_f32` (72), `v_div_fixup_f32` (72); see R9.
* `NO_INDEPENDENT_ORACLE_VECTOR_FOR_THIS_MNEMONIC` (16) — 16 named mnemonics
  no oracle vector observes at all: `s_mov_b64` (8), `v_add_co_ci_u32_e64`
  (592), `v_add_co_u32` (528), `v_cmp_gt_i32_e64` (16), `v_cmp_gt_u32_e64`
  (32), `v_cmp_lt_i32_e64` (16), `v_cvt_f16_f32_e32` (1016),
  `v_fma_mixhi_f16` (32), `v_fma_mixlo_f16` (224), `v_lshlrev_b16` (456),
  `v_lshrrev_b16` (64), `v_min_u32_e32` (16), `v_mul_lo_u16` (48),
  `v_mul_u32_u24_e32` (112), `v_pack_b32_f16` (256), `v_sub_nc_u16` (24)
  (counts = executions on the J3 path).

**Next step that would close it:** write instruction-level oracle vectors for
those 16 mnemonics (family coverage is not enough — several of them sit in
families that *are* covered, which is exactly the hole this matrix exists to
show).

### Oracles joined

* J3_CONFORMANCE (16Q): 169 vectors / 24,417 comparisons / 0 failures; the
  M2 suite is contained in it (117 of 117 names present, 52 extra) — measured.
* 16L vector oracle, **re-run here**: 97/97 agree.
* 16L scalar oracle, **re-run here**: 69 vectors, 61 agree / 8 disagree.
  The recorded 16L results are STALE: the live `phase8_static/tools/emu.py`
  sha256 is `c6afc641…`, not the recorded `597148aa…` / `77867252…`.

### Negative controls (each shown rejecting a known-bad)

* **NC1** — the classifier run over corrupted evidence flips 3 rows
  VERIFIED→BLOCKED, and stays bounded: corrupting every suite *except* the
  refuted one also flips the adjudicated row to BLOCKED.
* **NC3** — the pair-aware destination read-back is load-bearing:
  `s_lshl_b64`'s recorded disagreement is a harness read-back artifact
  (recomposed 8589934590 == oracle 8589934590).
* **NC4** — one oracle adjudicated. On the Q1 oracle's own vector
  `q1_andn2_saveexec_b32_operand_order` (old EXEC 15, S0 255) the two
  candidate readings differ in 4 bits: ISA `S0 & ~EXEC_old` = 240 vs legacy
  `EXEC_old & ~S0` = 0. The live emulator gives **240** (the ISA reading, dst
  15), the Q1 oracle model gives **240**, and the 16L scalar oracle gives
  **0** — it computes the reading the ISA document refutes
  (`ref/rdna2_isa.txt` line 6450, `EXEC_LO = S0.u32 & ~EXEC_LO;`, sha256
  `46fdab00…`). Patching that legacy reading into the live handler is rejected
  by this vector (EXEC 240→0) and survives a constructed probe whose inputs
  cannot separate the readings. Hence `s_andn2_saveexec_b32` is
  `VERIFIED_INDEPENDENTLY` (61, not 60), and `refuted_oracles` in the artifact
  records the refuted oracle and the measurement.

48 of 146 rows have a `mutation_rejected: true` column; 38 mutations were
measured in this run on the MRO-resolved handler with invocation counts and a
before/after observation delta.

## MEASURED vs INFERRED vs DESIGNED

* **MEASURED** — every count, digest, comparison, handler owner and mutation
  delta above; the oracle re-runs; the write-volume audit; the NC1/NC3/NC4
  rejection behaviour.
* **INFERRED** — cone membership is an upper bound (the cone is a
  lane-collapsed over-approximation, so a node does not prove the value
  reached a store); "no oracle observes this mnemonic" is an inference about
  what the joined suites observe.
* **DESIGNED** — the four-value status vocabulary (the brief's); the rule that
  a mutation counts as a control only when it changes an observation; NC4's
  nondiscriminating probe is constructed here to demonstrate that a vector
  which cannot separate two readings cannot reject the known-bad between them.
* **NOT CLAIMED** — no GPU, HIP or physical validation of any kind. `BLOCKED`
  means no independent observation was found; it is **not** a claim that the
  emulator is wrong.
