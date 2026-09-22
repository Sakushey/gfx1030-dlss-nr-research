# SESSION_REPORT.md — Phase 16K

**PRE-TEST ALPHA HARDENING, ONE-SHOT RUNTIME, CONTROL CENTER, AND GFX10.3
ARCHITECTURE FREEZE**

Date 2026-09-19. Project `<PROJECT_ROOT>`. Host-only throughout.

> **NO GPU KERNEL WAS LAUNCHED. NO GAME WAS LAUNCHED. NOTHING IS ARMED.**
> No clock, voltage, power-limit, firmware, BIOS, registry, or driver change
> was made. No security control was weakened. No stress test was run.
> Candidate F, Candidate E, the frozen alpha bridge, and all Phase 16G/H/I/J
> evidence are byte-unchanged; the new bridge is a new artifact with a new
> identity in a new directory.

---

## FINAL VERDICT

# `BLOCKED_OTHER`

Of the brief's named blockers, **two are present** — global arena model and
LDS semantics. The third, **entry ABI, is answered and withdrawn** (item 3):
K2 measured the entry state of both modules and found them byte-identical,
and proved by CFG dominance that the two suspect sites do not read entry
state at all. The decisive blocker is one the list does not name:
**the host emulator is the instrument that produced every gate result
in this phase, and its address-formation instructions are wrong.** Both
`v_lshl_add_u32` and `v_lshl_or_b32` shift the wrong operand, and
`v_lshl_or_b32` is the instruction that forms the LDS tag. This session
re-derived and empirically confirmed that defect rather than accepting it
from a subagent (item 7). Until the instrument is repaired and every gate
re-run, no gate result here — including the one `CLEAN` row, and including
the measured `ea_max` — can be treated as authoritative.

Reporting a named blocker alone would imply the arena or the LDS semantics is
the problem, when the analysis of **both** rests on that instrument. K4's
static findings (no translation defect; do not build Candidate G) and K2's
entry-state result survive independently, because they are disassembly facts.

`FINAL_PRETEST_STATE.json`:

```json
{ "gpu_execution_performed": false,
  "gta_launched": false,
  "currently_armed": false }
```

All three are **checked, not asserted**: 25 phase-16K artifacts carry the
field and 0 violate it; `tasklist` shows no GTA process; and `\\.\pipe\`
shows 0 listening `DLSSNR_RDNA2_Control_*` pipes, so no supervisor is in a
state that could admit a launch.

---

## 1. K0 — Phase 16J frozen, evidence manifest recorded

The Phase 16J report was frozen under a phase-specific name
(`frozen/phase16j_SESSION_REPORT.md`); the live `SESSION_REPORT.md` was left
live, as the brief requires. `phase16k_pretest/evidence_manifest.json`
records exact SHA-256 + size for 16 artefacts and 13 emulator semantic
sources, and cross-checks its semantics list against
`p16j_execcache.SEMANTICS_SOURCES` (agrees: **True**). All three brief-stated
hashes match: Candidate F `47b5d1d1…0557524b`, alpha bridge `93484428…f3abfe0`,
J3 harness `72335a20…2ed3e13f3`.

**Module chain re-verified end to end** (see item 14): decoding all
1,259,728 `0xNN` tokens out of the bridge's embedded
`bridge_gfx1030_fatbin.h` yields a byte string hashing to
`ec9bffea…03f2eb57` — byte-for-byte the on-disk fatbin. The chain
`.co → fatbin → header → DLL` is intact.

## 2. K1 — bounded recorders; the `RecCore.g_ops` leak

`RecCore.__init__` set `self.g_ops = []` and `_gl_addr` appended one 4-tuple
per global lane-access with **nothing ever draining it** — and `RecCore` is
on the **production path** (confirmed from `BothCore.__mro__`, not inferred).
One `swin256f` 8-wave dispatch retained **8,370,176 live 4-tuples**.

Replaced with an explicit three-mode recorder (`AGGREGATE` default,
`TARGETED_TRACE`, `FULL_TRACE` with a printed cost and a hard budget that
raises rather than being quietly exceeded). List-compatible, so existing
readers keep working; a reader that needs every event must now declare it.

**Measured** (8 waves, AGGREGATE):

| | swin32f | swin256f |
|---|---|---|
| events counted | 20,128 | **1,054,976** |
| events retained | 467 | **664** |
| **peak RSS** | **197.3 MiB** | **244.1 MiB** |
| RSS across the run | flat | 198.4 → 244.1 (181 samples) |

The brief's "comfortably sub-GB" is met with ~4.2× headroom, and the peak is
**independent of the event count**.

**Differential validation against persisted PRE-change artifacts**, file to
file, recursively, no tolerance and no exclusion list: **0 differing fields**
on `swin32f`, `swin32t`, `swin64f`. All three references were verified
byte-identical to originals whose mtimes (12:44–12:46) pre-date the 13:43
edit, so this is not a run compared against itself. **Independently re-run at
the end of this session**: swin32f, 0 differing fields, `EQUIVALENT`.

K1B (operand-token memoization) was **skipped**; nothing depends on it.

## 3. K2 — entry SGPR state for `<32,true>` — **COMPLETE**

**The entry ABI is not the problem, and the two sites do not read entry state
at all.** The original gfx1100 module and Candidate F have identical
entry-relevant descriptors (d13 `0x0000019D`, d14 `0x00000408`,
`user_sgpr_count` 14, kernarg 424 B, private 24 B) and a **byte-identical
entry map**: `s0..s1` kernarg_segment_ptr, `s2..s13` UNKNOWN, `s14` wgid_x,
`s15` wgid_y, `s16` pswf.

The 128 reads at `0x000941FC` / `0x00094204` are **not** entry SGPRs.
`s_load_dwordx8 s[8:15], s[0:1], 0x30` (candidate `0x94048`) and
`s_load_b256 s[8:15], s[0:1], 0x30` (original `0xAFA5C`) each **strictly
dominate** the sites — a CFG dominance computation, persisted in
`k2_site_analysis.json` — and each is the **only** dominating writer of s12
(15 writers in the kernel, 1 dominates). Nothing writes `s0/s1` on the way to
the load (129 writers elsewhere, 0 dominating), so `s[0:1]` is the entry
kernarg pointer. The bases are therefore `VarParams[0x40]` / `[0x48]`,
kernarg fields the host **provably zeroes** (96 B at +0x40..+0x9F, five
zeroing runs). The gfx1100 module carries the byte-identical address sequence
`D6FE7C13 0031190C` / `D6FE7C15 0039190C` and the same loads, so **the
translation is faithful**. This **refutes** Phase 16J J1 §2's classification
(B) "emulator entry-SGPR state" — the correct classification is a
kernarg-field/predication question.

**UNKNOWN, deliberately:** `s2..s13`. `user_sgpr_count` declares 14 SGPRs but
only `kernarg_segment_ptr` is enabled, so s2..s13 are reserved and
unpopulated; the module does not say what the runtime puts there, so no value
is invented. No evidence ties them to the sites.

**Negative test:** 7 perturbations, **all detected** — each of the four
enabled entry SGPRs shifted by 1, `user_sgpr_count` + 1, wrong
`module_sha256`, and the declared-gap entry removed. Positive verify PASS on
both maps. Independently proven to fail: a map with wgid_x moved s14→s15 is
rejected with 3 failures, rc=1.

**Independent cross-checks:** the llvm-mc descriptor bit probe confirms every
bit of the decode, including `user_sgpr_count` at d13[4:1]; the compiler's
own `.note` YAML agrees on `wavefront_size` 32; and a behavioural proof in
the original module (`s_mul_i32 s4,s6,s15` / `s_add_u32 s6,s4,s14` is the
linear workgroup index) proves wgid_x@s14, wgid_y@s15. Neither M0 nor SCC is
a dispatch input: M0 is never mentioned in either kernel, and SCC is read
only by the 11 `s_cbranch_scc0/1`, each of which has a dominating
SCC-setting instruction (515/515 conditional branches checked).

This result is a **static disassembly fact**, so unlike the arena and LDS
measurements it does **not** depend on the defective emulator (see §14).

## 4. K3 — the real arena topology

The "64 MiB region per pointer" was a **harness convention**, not a model.
The arena is a small set of long-lived pool buffers plus **one grow-only
reused canvas** (`VarParams+0xA0`), allocated
`ceil((Y-a)/8)·ceil((X-b)/8)·(1<<shift)` — where `shift` is **selected by
block size**: 15 for block 256, which all five variants use. Phase 16J
hard-coded 8192, the **block-64** shift, declaring the canvas at exactly
**¼** of its real size in every variant.

Re-running all five variants under the corrected canvas:

| variant | baseline | explained | canvas_only |
|---|---|---|---|
| swin32f | 0 | 0 | **0** |
| swin32t | 152 | 16 | **136** |
| swin64f | 160 | 64 | **96** |
| swin128f | 512 | 128 | **384** |
| swin256f | 1664 | 1024 | **640** |
| **total** | **2488** | **1232 (49.5%)** | **1256** |

**1232 of 2488 counted violations — 49.5% — were false.** But **no variant
becomes clean**: the residual now bases on the canvas pointer **beyond the
mod's own real allocation**, so it is a *genuine* OOB rather than a harness
artefact. Verdict: **REDUCED, not explained.** Derived twice (predictively
and by measurement); all five agree, per-site offsets included.
`execution_signature` is bit-identical across all three region models, so
region size relabels and changes nothing else.

Aliases are modelled as aliases (`0x00`/`0x08` are two slots of one pool,
17/39 and 15/39 captured transitions being exact exchanges). Tensor sizes are
recorded as **UNKNOWN** — neither 64 MiB nor the 2 MiB bound is a measured
size. K3B (passive runtime capture) was **design-only and not executed**.

## 5. K4 — the `0xE077E` LDS source

All outside-bound LDS events are `ds_write_b16` writes from **8 sites**
(immediates 0…1792, stride 256) with `oob_read_zero = 0`. The original
gfx1100 module contains **the same eight sites at the same immediates with
zero masks**, and `ds_write_b16` counts are identical across modules for
every variant. H1–H6 were tested explicitly; H2/H3/H4/H6 are refuted by
measurement, H1 is supported only as "missing normalization".

**There is no translation defect, so Candidate G must not be built** and
Candidate F remains the final module. The `& 0x3FFF` mask that would "fix"
this is **refuted by the C1/C2 gfx1030 silicon measurements** as a hardware
model — applying it would change *which memory the kernel addresses*, folding
slice tags 7 and 14 onto one ring offset. Four of the six proofs K4C
requires are not established. **Decision: do NOT build Candidate G.**

## 6. K5 — the five-variant SWIN gate matrix

`phase16k_swin_matrix.csv`, generated by `tools/p16k_k5_matrix.py` from
measured JSON rather than retyped from prose.

| variant | cell | global OOB | of which `VarParams[0x40]/[0x48]` | canvas-family | LDS outside | verdict |
|---|---|---|---|---|---|---|
| swin32f | `<32,false>` | 0 | 0 | 0 | 0 | **CLEAN** |
| swin32t | `<32,true>` | 136 | 128 | 8 | 0 | **BLOCKED** |
| swin64f | `<64,false>` | 96 | 0 | 96 | 0 | **BLOCKED** |
| swin128f | `<128,false>` | 384 | 0 | 384 | 4096 | **BLOCKED** |
| swin256f | `<256,false>` | 640 | 0 | 640 | 8192 | **BLOCKED** |

**CLEAN 1, EXPLAINED_VALID 0, BLOCKED 4.** No AMBER is used and none was
available. The rule applied strictly: **an unexplained firing is BLOCKED,
never EXPLAINED_VALID** — knowing *which site* fires is not knowing the
access is *fine*.

The fourth column is labelled `VarParams[0x40]/[0x48]`, **not** "entry-SGPR"
as Phase 16J had it: K2 proved by CFG dominance that the 128 reads at
`0x941FC`/`0x94204` do not read entry state (§3). The relabel changes the
*attribution*, not the verdict — the reads are still outside every declared
region, and K2 explicitly did not claim they are valid.

The two blockers are **separate code** (the global sites are reads; the LDS
sites are `ds_write_b16` writes at different addresses), so this is two
problems, not one. The LDS count is read from **two independent sources**
(K3's `lds_counters` and K4's census) which agree — reported honestly as
**2 of 5 checked, 2 agree, 3 unchecked**, because counting an absent
comparison as a pass is a failure this project has hit before.

## 7. K6 — the J3 numerical reference

Every output region classified; **tolerances frozen before any physical
output existed** (none does — no GPU ran).

**Tally: INTEGER/CONTROL 4, COPY/BITWISE 0, FP16 0, FP32 0, UNKNOWN 2.**
Both *written* regions (`0x08`, `0xA0`) are **UNKNOWN**: they store **1-byte**
values produced by float arithmetic — an **E4M3 software encoder** (sign via
`v_cmp_gt_f16`+`v_cndmask`, exponent via `v_log_f32`/`v_floor_f32`/`v_ldexp_f32`,
3-bit mantissa via `v_rndne_f32`, pack `v_lshl_add_u32 ..,3,56`, clamp
`v_min_i32 ..,0x7e`, NaN sentinel `0x7f`). A 1-byte datum cannot hold FP16 or
FP32, and an 8-bit float is neither class the census may name. **Neither was
promoted to make the table look complete.** UNKNOWN means refuse-to-pass:
compared as raw bytes, bit-exactly, no invented tolerance.

Tolerance provenance is stated per class as **derived** (INTEGER/CONTROL and
COPY/BITWISE → 0, because no rounding step exists; FP16 → 0 ULP/op, N·2⁻¹¹
for a chain of N from 10 explicit mantissa bits; FP32 → N·2⁻²⁴·Σ|xᵢ| from 23
mantissa bits) versus **judgement call** (declared as such). No float
tolerance is actually in force at J3.

**Four emulator ISA defects**, each with a minimal reproduction that runs the
real handler against the ISA:

| defect | measured consequence |
|---|---|
| `Core._vcmpx` reads `vget(ops[1])` for both operands when `len(ops) < 3` | every `v_cmpx_*` evaluated as `fn(src0, src0)`; `v_cmpx_neq_f32_e32 0, v5` at `0x000B5124` yields `EXEC=0` instead of `0xFFFFFFFF`, **skipping the entire E4M3 magnitude encoder** |
| `Core._vfp` passes f32 *bit patterns* for register operands | 11 of 13 arithmetic cases disagree with the ISA |
| `_fp_cmp_cond` has no `v_cmp_ngt_f32` | `KeyError` once defect 1 stops masking it |
| `op_v_lshl_add_u32` computes `(src1 << src0) + src2` (ISA: `(src0 << src1) + src2`) | 824 instead of 120 — **on the encoder's critical path** |

Two are repaired by a **K6-local monkey-patch**; two are **not repaired and
are reported instead**. Nothing outside `k6_j3_numeric/` was modified.

**Independently re-verified by this session, not taken on trust.** Reading
`emu.py` directly: `_vbin3` passes `ops[1], ops[2], ops[3]` as
`src0, src1, src2`, and both shift-add/or ops compute `((b << (a & 31)) …)`
with `a = src0`, `b = src1` — i.e. they shift **src1 by src0** where the ISA
shifts **src0 by src1**. Empirically, `v_lshl_add_u32 v2, v1(=8), 3, 56`
returns **824** (`(3<<8)+56`) where the ISA gives **120** (`(8<<3)+56`).

**This matters more than the value-semantics defects, because
`op_v_lshl_or_b32` (`emu.py:669`) carries the identical swapped-operand bug**
— and `v_lshl_or_b32` is the instruction K4 identified as forming the LDS
ring **tag**. The disassembly confirms the ISA reading: every emitted site
puts the shift amount in the `src1` slot (`v_lshl_or_b32 v3, v40, 7, v37`,
`v_lshl_add_u32 v8, v8, 4, v9`), which is only meaningful if `src0` is the
value being shifted.

**Consequence:** the *addresses* in both residual analyses are produced by a
mis-evaluated instruction. K4's **static** findings survive — the same eight
sites at the same immediates in the original gfx1100 module, zero masks,
identical `ds_write_b16` counts are disassembly facts, independent of the
emulator — so "no translation defect, do not build Candidate G" still holds.
But the measured `ea_max = 0xE077E`, and the global OOB offsets in item 6, are
**not trustworthy as values** until the emulator is repaired and every gate
re-run.

**The frozen 8192-byte canvas takes 1792 OOB reads and 2048 OOB writes**,
reaching offset 2,621,471 — and the reach is **identical** at K3's 32,768, so
the mis-sizing is far larger than a factor of four. The reference `.bin` is a
**regression fixture and shape witness**, explicitly **not a prediction**;
every written region reads `NOT CERTIFIED`.

## 8. K7 — real one-shot job control

The frozen bridge had **two arming doors and no job limit**: arming started a
*continuous* run. The J6 `kOneShotCap = 200` launch counter is deliberately
**not carried forward** — it would fire *inside* a job, recreating the
blocked-job failure mode this phase exists to remove.

The state machine changes state only on a control command, a **job boundary
marker**, or a fault. The boundary is the **measured** one: `flag_wait`…
`flag_set`, i.e. **159 launches** for job 1, 160 for jobs 2–14
(`159 + 13×160 = 2239`). This also resolves a self-contradiction in
`j6_one_shot/DESIGN.md` §3, whose `Import`/`Export` boundary would have
refused job 1's own end marker.

**The property that matters: once a job is admitted, every kernel of it is
allowed.** No state and no event can refuse a kernel of an admitted job —
including `DISARM_NOW_IF_IDLE`, which refuses to cut a running job.

**Decisive result**, replaying the real 2239-launch sequence:

```
admitted = 159   refused = 2080   jobs_admitted_total = 1   final = DISARMED
```

Job 1 runs whole; refusal begins at job 2's **first** launch — at a boundary,
before job 2 was submitted.

## 9. K8 — the managed control plane

Named pipe `\\.\pipe\DLSSNR_RDNA2_Control_<gamepid>`, line-delimited JSON,
commands `STATUS` / `ARM_ONE_SHOT` / `DISARM_AFTER_JOB` / `DISARM_NOW_IF_IDLE`
/ `COLLECT_STATUS`. **The runtime owns the state; a client may read it and
request transitions, never set it.** A client disconnect changes nothing.
**There is no command that arms a continuous run.**

The pipe uses `PIPE_REJECT_REMOTE_CLIENTS` and an **owner-only DACL** built
from the process token (not a well-known SID), because otherwise any local
process could disarm the supervisor. A pipe that fails to come up is
**reported, not silent** (`CONTROL_PLANE_UNAVAILABLE stage=… code=…`), and
the supervisor enforces its own state regardless.

**Verified:** 15/15 scenarios; **per-launch** cross-check against an
independently written Python model — **0 differences, 0 acceptance failures**;
a 5-defect negative self-test, all detected; **25/25** protocol cases against
the *real* server (`k8_ctl_host.exe` links the shipping `control_plane.cpp`);
and the new bridge's **export set is 29/29 identical** to the frozen alpha
bridge. New bridge SHA-256
`39fa91b558f506da892b5b6926561ffc394bab5064b9f75252675ced67e049f7`.

## 10. K9/K10 — Control Center

`DLSSNR-RDNA2-ControlCenter.exe` (100,352 B, WinForms, built with in-box
`csc.exe` only — nothing installed) plus a smoke-test harness.
**20 passed, 0 failed**; GUI `--selftest` PASS. It was additionally
**cross-checked against the real server** (12 assertions, PASS), which caught
two defects a mock could never have found: `registered_kernels` is a *number*
in the real server but an array in the mock, and `ReadTimeout` throws on a
synchronous pipe.

`profiles/gta5_enhanced.json`: only `gta5_enhanced` enabled (two others
explicitly disabled), **Story Mode ONLY**, **BattlEye OFF**, AMD FSR 3
Quality, **Frame Generation OFF**, `arm_mode: ONE_SHOT`,
`max_jobs_per_arm: 1`, `continuous_arming_supported: false`, with eleven
load-bearing gate rules.

## 11. K11 — deployment sandbox

The whole flow was exercised against a mock GTA directory:
VANILLA→DEPLOY→VERIFY→ROLLBACK→exact VANILLA; PHASE16 OLD→DEPLOY
ALPHA→VERIFY→ROLLBACK→exact previous; interrupted deployment;
modified-after-deploy; missing backup; GUI against the mock profile.

**Two defects were found in the frozen alpha scripts and deliberately not
fixed** (fixing them changes frozen package bytes):
`rollback_alpha.ps1:64` removes `dlssnr16.cfg` unconditionally with no hash
check; `verify_alpha.ps1:52` asserts `$backups.Count -eq 1`, but the real
game folder already holds a 20260907 backup dir, so a *correct* deploy makes
two backups and verify reports FAIL. Also `deploy_alpha.ps1` writes its
manifest into `-CandidateDir`, mutating `phase16i_alpha/` itself.

## 12. K12/K13/K14 — harness set and plans (not executed)

Equivalent one-workgroup harness definitions for 32t / 64f / 128f / 256f
were written and **not executed**. The serial physical qualification plan and
the first GTA test plan were written and **not run**. This workstream
independently found the same `flag_wait`/`flag_set` boundary contradiction in
`j6_one_shot/DESIGN.md` §3 that item 8 resolved.

## 13. K15/K16 — TargetProfile / GFX1030Profile

`TargetProfile` / `GFX1030Profile` created; hidden assumptions were removed
from the generic translator logic rather than mechanically string-replaced.
`REFERENCE_EXACT` frozen; `OPT_GFX1030` defined but **not started**. **A
gfx1030 ELF is never relabelled as gfx1031/1032.** Candidate F byte-identity
re-verified.

## 14. K17 — adversarial validator policy

Policy: every gate that can authorize physical execution needs a positive
test, a deliberately malformed negative test, and an independent
cross-check. `tools/p16k_k17_validators.py` **runs** what can be run.

| gate | positive | negative | cross-check | verdict |
|---|---|---|---|---|
| module_hash | pass | pass | pass | **ALL THREE** |
| one_shot | pass | pass | pass | **ALL THREE** |
| scratch | pass | pass | pass | **ALL THREE** |
| global | pass | pass | pass | **ALL THREE** |
| lds | pass | pass | pass | **ALL THREE** |
| entry_state | pass | pass | pass | **ALL THREE** |

**6 of 6 gates have all three legs.** The `entry_state` gate was originally
an existence check — it reported `passes: true` because K2's JSON files were
present, which cannot distinguish a verifier that passed from one that was
never run. It now **re-runs K2's verifier** on both maps and reads the
recorded negative results, and it was shown to fail on a perturbed map
(wgid_x s14→s15 ⇒ 3 failures, rc=1).

The `scratch` gate is worth naming: it
reports **0 OOB in all five variants** — it had *never been observed firing*,
which is indistinguishable from a gate that cannot fire. A negative test was
therefore constructed: monkey-patching the declared private-segment bound
from 24 to 8 **in memory** (no modified module is ever written to disk) makes
the gate **fire**. The manifest gate's negative test is likewise
non-vacuous — a file carrying a *declared* supersession still reports
`EVIDENCE_MUTATED` when given a third value.

## 15. K18 — final pre-test state

`phase16k_pretest/FINAL_PRETEST_STATE.json`. The three required booleans are
**computed from live checks**: 25 artifacts carry `gpu_execution_performed`
and 0 violate it; `tasklist` shows no GTA process; `\\.\pipe\` shows 0
listening control pipes.

**Five blockers remain** — `GLOBAL_ARENA`, `LDS_SEMANTICS`, `EMULATOR_ISA`,
`J3_INPUT_CANVAS`, `J3_REGIONS_UNKNOWN` — and the verdict is
**`BLOCKED_OTHER`** for the reason stated at the top. `ENTRY_ABI` was
**removed** from the blocker list once K2 reported; it is kept in a
`resolved` section with its evidence rather than deleted, so a reader can see
which named blocker was answered and how. It was answered from static
disassembly, so it is the one blocker whose resolution does **not** depend on
the defective emulator.

---

## What would unblock this

In dependency order — **the first item gates the value of all the others**:

1. **Repair the emulator's ISA defects** (`_vcmpx` operand selection,
   `v_lshl_add_u32` operand order, `_vfp` register semantics, the missing
   `v_cmp_ngt_f32`), then **re-run every gate in this phase.** Until then the
   `CLEAN` row and both residual analyses are provisional.
2. ~~**K2** — finish the entry-SGPR reconstruction and its negative test.~~
   **DONE** (§3). It reclassified 128 of `swin32t`'s 136 residual reads: they
   are `VarParams[0x40]`/`[0x48]` reads, not entry SGPRs, so they belong to
   the global-residual question below, not to an entry-ABI question.
3. **Global residual** — explain the canvas-family reads beyond the mod's own
   allocation (8 / 96 / 384 / 640). Note the offsets carry tag-like high bits
   of the same shape K4 found for LDS; whether the root cause is shared is a
   **hypothesis, not a measurement**.
4. **LDS** — needs either a gfx1100 measurement of `ds_store_b16` at
   `EA = 0x70000` under a 15616-byte group segment (physical GPU work, not
   this phase), or a liveness proof that the ring offsets are never read back
   through a slice-tagged address. **Do not extend the mask to turn the gate
   green.**
5. **J3 input** — the frozen canvas constant (8192) is wrong for the J3
   geometry (32768), and the kernel reads far beyond even that. The frozen
   J3 input hash `592766ef…08e7a2f8` is built on the wrong constant.
6. **J3 regions** — resolve `0x08` and `0xA0` from UNKNOWN (decode the E4M3
   encoder, or find the mod's consumer of that buffer), and certify the
   reference bytes.

Then, and only then, is `PRETEST_READY_FOR_J3_AUTHORIZATION` a candidate.

## Not done, and deliberately so

No GPU execution; no GTA launch; no TDR/watchdog/registry timeout change; no
OC/UV/OV/power/fan/firmware/BIOS change; no PCIe hack; no driver replacement;
no Defender/security weakening; no kernel-mode or MMIO experiment; no
architecture spoofing. No long stress test. Candidate G was **not** built.
K3B was **not** executed. K12/K13/K14 harnesses were **not** executed. K1B
was **skipped**. `OPT_GFX1030` was **not** started.

## Artifact locations

| what | where |
|---|---|
| frozen 16J report | `phase16k_pretest/frozen/phase16j_SESSION_REPORT.md` |
| evidence manifest | `phase16k_pretest/evidence_manifest.json` |
| K1 report / measurements | `phase16k_pretest/K1_REPORT.md`, `out/k1_*` |
| K2 entry state | `phase16k_pretest/k2_entry_state/` — report, both maps, self-test, site analysis, llvm-mc probe |
| K3 arena | `phase16k_pretest/k3_arena/` |
| K4 LDS | `phase16k_pretest/k4_lds/` |
| **K5 matrix** | `phase16k_pretest/phase16k_swin_matrix.csv` |
| K6 J3 numeric | `phase16k_pretest/k6_j3_numeric/` |
| K7/K8 one-shot + control plane | `phase16k_pretest/k7_oneshot/` |
| K9/K10 Control Center | `phase16k_pretest/k9_control_center/` |
| K11 sandbox | `phase16k_pretest/k11_sandbox/` |
| K12/K13/K14 harness + plans | `phase16k_pretest/k12_harness_set/` |
| K15/K16 target profile | `phase16k_pretest/k15_target_profile/` |
| K17 validator policy | `phase16k_pretest/phase16k_validator_policy.json` |
| **K18 final state** | `phase16k_pretest/FINAL_PRETEST_STATE.json` |
