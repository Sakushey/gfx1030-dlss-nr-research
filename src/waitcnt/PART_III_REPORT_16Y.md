# Phase 16Y Part III — S_WAITCNT EXECUTED-PATH AUDIT

**Deliverable:** `phase16y/waitcnt/PART_III_WAITCNT_AUDIT_16Y.json` (schema
`phase16y-waitcnt-executed-path/1`, revision 3).
**Engine:** `phase16y/waitcnt/tools/p16y_waitcnt_audit.py`.
**Host-only:** `host_only: true`, `gpu_execution_performed: false`,
`kernel_launch_count: 0`, `llvm_objcopy_used: false`. No HIP call, no launch,
no frozen artefact written.

## Verdict

**PASS — 0 hazards, 0 unclassified instructions on the dynamic path**, over
107 649 dynamically executed instructions, 20 608 memory producers and 1 277
distinct executed waits. The liveness-relevant hazard count (a hazard whose
consumer feeds a branch or an address) is **0**, and **0** executed barriers
were crossed with memory outstanding.

## What changed in revision 3 (revision 1 and 2 numbers kept in `history`)

The coordinator raised one material residual: 784 dynamically executed
instructions reported as UNCLASSIFIED, on the theory that an unclassified
instruction cannot be recognised as a CONSUMER and could therefore hide a
hazard. That has now been measured instruction by instruction, and **the
premise is refuted**, but the exercise found a real and different defect.

### 1. Was the flagged class actually invisible? No — measured

The pre-fix classifier (raw-encoding-bit format detection, kept verbatim in the
engine as the "before" arm) flagged **240 of 17 478** static instructions
`ok=False`. Comparing the `(defs, uses)` **sets** — not the `ok` flags — the two
models agree on **17 260 / 17 478** statistically and on **9 103 / 9 199**
dynamically executed addresses:

| class | static | dynamically executed | consumer edge visible pre-fix? |
|---|---|---|---|
| flagged **but** `defs` AND `uses` filled | 133 | **98 (784 executions)** | **yes** |
| flagged and `defs` AND `uses` **empty** (genuine blind class) | 107 | **0** | no |
| total flagged | 240 | 98 | — |

For the flagged 4-operand VOP2-family forms, the pre-fix model computed
`defs = op0`, `uses = op[1:]` — **exactly the sets the fixed model computes**.
They were flagged, not invisible. Since the def-use walk consumes only
`defs`/`uses`, the 784 could not have hidden a consumer edge, and the hazard
count could not change: **0 before, 0 after**.

All 218 static disagreements are accounted for by only two classes: 111
`v_cmpx_*` (the real defect, below) and 107 VOP3 mnemonics absent from the
pre-fix operand table (the genuine blind class). No other instruction differs.

### 2. VOP2 / VALU operand forms actually observed (MEASURED, with counts)

Over all 17 478 static instructions, 124 VALU mnemonics, 10 786 VALU instances:

* **0 mnemonics print a single operand**, and **0 two-operand forms have
  `dst == src0` of the worked-on register — the hypothesised "implicit src0"
  VOP2-e32 form does not occur. (The rev-1 reason string claiming it did was a
  guess written into code, not a measurement; corrected in rev 2.)
* **28 mnemonics print two operands**: 19 unary VOP1-style `(dst, src0)`, e.g.
  `v_mov_b32_e32 v19, 0`, and **9 `v_cmpx_*_e32`** whose two printed operands
  are **both sources** (the destination is EXEC and is not printed).
* **26 mnemonics print four operands** (1 819 instances): ordinary
  `dst + 3 sources`. The flagged e32 members are
  `v_cndmask_b32_e32` (119 static / 784 executions), `v_fmaak_f32` (11),
  `v_fmamk_f32` (3). The much larger `v_cndmask_b32_e64` (564) was never
  flagged.
* The op1 role was decided **empirically** by rewriting op1 to `v1` and asking
  `llvm-mc`: a VGPR can never be an SDST, so rejection proves op1 is an SDST.
  **30 probed, 30 comparisons, 1 disagreement** (`v_mad_i64_i32` is an SDST
  mnemonic that my ISA prediction set had missed — the probe corrected it,
  which is evidence the probe can disagree with its own prediction).

### 3. The real defect found (and why it matters even though it is inert here)

`v_cmpx_*_e32` prints its two SOURCES and no destination. The pre-fix model
read printed op0 as a **destination** (`defs = op0`) and therefore dropped it
as a use. The fixed model uses `op0` and `op1` and defines EXEC. This is
confirmed against the frozen ISA text (*"All V_CMPX instructions write the
result of their comparison ... to the EXEC mask"*) and the 16t emulator handler.

MEASURED dynamic footprint: **96 executed addresses, all `v_cmpx_o_f16_e32`,
and every one has `op0 == op1`** — so the operand the pre-fix model drops is
the same register it keeps, and the defect is **inert on this trace**. The
residual model difference is a *spurious def* of op0 (`owner[v] := None`),
which can only **mask** a hazard, never create one; the fixed model has the
correct defs and still reports 0 hazards, so nothing is masked in the verdict.

### 4. Through-VALU hazard controls — and an honest correction

Revision 2's through-VOP2 control was **invalid** and reported 0/0. It walked
the executed set in address order and took the first `v_cndmask_b32_e32`, which
reads a *different* register than the producer it was paired with, so it could
not fire. Selection is now by **predicate** (the consumer must read a register
the producer defines), and both members of each pair are real, unmutated
instructions. Each arm's classification is recomputed from the exact text it is
given (rev 2 reused a stale classification for a mutated producer, which
confounded its `v_cmpx` control).

| control | produces | before the fix | after the fix | intent |
|---|---|---|---|---|
| (g) through a flagged 4-operand `v_cndmask_b32_e32` (the 784 class) | `global_load_ushort v26 …` → `v_cndmask_b32_e32 v26, 0x43e00000, v26, vcc_lo` | **HAZARD** | **HAZARD** | caught either way |
| (g2) through a VOP3 mnemonic the pre-fix model could not classify (empty defs *and* uses) | `s_load_dwordx8 s[16:23] …` → `v_add_f32_e64 v8, s16, s16` | **MISSED** | **HAZARD** | genuine pre-fix gap |
| (h) through `v_cmpx_o_f16_e32 v4, v7` (the role defect) | `global_load_ushort v4 …` | **MISSED** | **HAZARD** | genuine pre-fix gap |

**Plainly: the hazard planted through the 784-class instruction is caught
BEFORE the fix.** The coordinator's premise about that class is wrong; the
control cannot discriminate the two models, and it is recorded as such rather
than as a success. The real pre-fix gaps are (g2) and (h), both demonstrated
MISSED → HAZARD.

Controls (a) delete a required wait, (b) raise a wait's vmcnt, (c) move a wait
after its consumer each report HAZARD (8 hazards apiece); (d) an empty/decoy
executed-PC set reports **VACUOUS**, never PASS; (e) the `tracer_by_pc`
cross-check is shown to be able to fail (MISMATCH 1/0/0). The decoder carries
its own wrong-layout control, which fails on 44 of 44 entries.

### 5. Are any of the 784 on the liveness-critical region? No — 0

Definition: inside `[0xBA71C, 0xBA730]` (loop header → loop-exit test) **or**
within 64 bytes of the barrier at `0xBBE20` **or** within 64 bytes of the EXEC
manipulation at `0xBBE2C`.

**0 instructions and 0 executions** of the flagged class lie there — and 0 of
the genuine blind class too. The 98 flagged instances span `0xB0AC8`–`0xC03AC`
in 97 distinct 256-byte buckets, i.e. they are spread one-per-region across
most of the kernel rather than concentrated in the loop body. The three focus
areas are confirmed on the dynamic path, each executed 8 times (once per
wave): `0xBA730` = `s_cbranch_scc1 1531`, `0xBBE2C` = `s_and_saveexec_b32 s8, s2`,
`0xBBE20` = `s_barrier`.

## Audit results (unchanged by revision 3)

| check | result |
|---|---|
| STEP 1 decoder | 49 probe entries, 132 `s_waitcnt` field comparisons, **0 mismatches** |
| raw-word provenance | sha256 unchanged and equal to the J3 candidate sha; 17 478/17 478 addresses and texts match |
| STEP 2 dynamic waits | **1 277** distinct executed waits (not the ~1 882 static) |
| STEP 3 def-use walk | 107 649 steps, **20 608 producers, 0 hazards, 0 unclassified (was 784)** |
| producer outcome | 20 576 retired before their first consumer; 32 with no consumer seen |
| tracer cross-check | 1 908 comparisons, 0 mismatches — **MATCH** |
| barrier adjacency | 80 executed barriers, **0** crossed with vmem or lgkm outstanding; 0 without a wait in the 16 preceding instructions |
| sensitivities | depctr-as-full-fence, `gl0_inv` as VMEM, and two alternative op1-role models all give **0 hazards**, `verdict_unchanged: true` |

## MEASURED vs INFERRED

* **MEASURED:** every decoder field position (predicts all 49 probe words; the
  wrong-layout control fails 44/44); the operand-form inventory; the op1 role
  for all 30 probed mnemonics; the def/use agreement counts; the 96-instance
  dynamic footprint of the `v_cmpx` defect and the `op0 == op1` masking; the
  hazard count; the tracer agreement; the control outcomes.
* **INFERRED:** the counter semantics (FIFO "all but the newest N"), for which
  the supporting evidence is that the binary contains `s_waitcnt_vscnt`, which
  only exists if VMEM loads and stores use separate counters; and the
  cross-wave ordering through `s_barrier`, which one wave's trace cannot prove
  and which is covered only by the barrier-adjacency sub-audit.

## Limits (stated, not glossed)

1. First-CONSUMER register-level def-use only: a dependency reaching a branch
   through two or more further instructions is not followed.
2. Per-wave analysis; cross-wave ordering through `s_barrier` is not provable
   from one wave's trace.
3. The audited path is the one this emulator retires with waitcnt bound to
   `_noop`. Dropping a wait cannot change the path there; on hardware it could
   in principle change a register value and hence the path, so the audit covers
   THIS path — the path the values imply.
4. The `tracer_by_pc` per-PC `n` does not reconcile with `tracer_totals`
   (`<no-context>` is 246 880), so it is used only for set membership and
   flags, never for counts.
5. `S_WAITCNT_DEPCTR` is modelled as having no effect on the VMEM/LGKM
   counters; the `depctr_modelled_as_full_fence` sensitivity shows the verdict
   does not depend on that choice.
