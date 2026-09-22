# Phase 16K — K4C: Candidate G decision

Date 2026-09-19. Host-only. **No module was built, modified, or rebuilt.
Candidate F is untouched. The 82 pcrel sites were not re-run because there is
no new module to run them against.**

**DECISION: do NOT build Candidate G. Candidate F remains the final module.
The `0xE077E` outside-bound LDS accesses remain an open LDS-semantics item.**

---

## 1. The gate, and whether it is met

K4C sets one entry condition:

> "Build Candidate G ONLY if K4 establishes a real Candidate-F translation
> defect."

K4 established the opposite. Measured (`p16k_lds_compare.md`):

* The original gfx1100 `<128,false>` and `<256,false>` contain the **same
  eight `ds_store_b16` / `ds_write_b16` sites at the same immediates**
  (0, 256, 512, 768, 1024, 1280, 1536, 1792) with the same address form and
  **zero** masks.
* The `v_lshl_or_b32 …, 7, …` producers that form the high tag are present in
  equal number in both modules — 18 total, 7 with shift 7 for `<128,false>`;
  18 / 4 for `<256,false>`.
* `ds_write_b16` counts are identical across modules for every variant
  (42 / 41 / 65 / 66 / 66).

The translation reproduced the original's address path faithfully. The only
difference between the two modules anywhere in this path is the presence of a
Candidate-E `& 0x3FFF` self-mask — and at the failing sites it is absent in
**both**. Per K4B's own rule — *"If original and Candidate agree and both form
huge addresses: the translation is not the source"* — the translation is not
the source.

H1–H6 (`p16k_lds_census.md` §5) leave no alternative:

| | hypothesis | verdict |
|---|---|---|
| H1 | missing Candidate-E normalization at a large-variant site | **supported** (missing normalization) / **refuted** ("newly reachable") |
| H2 | normalization applied before the final EA | **refuted** — the mask is always the instruction immediately preceding the access |
| H3 | soft-WMMA liveness polluted address bits | **refuted** — the high bits come from an explicit `v_lshl_or_b32` present identically in the original |
| H4 | emulator instruction semantic is wrong | **refuted** — the model matches the physically measured gfx1030 rule (C1/C2) |
| H5 | original creates the same high address | **supported** (measured) / **not-decidable** (the gfx1100 interpretation) |
| H6 | synthetic input enters an unreachable branch | **refuted** — two patterns differing in 65,269 / 65,536 bytes give byte-identical signatures and value-identical records |

So the anomaly is neither a translation defect, nor an emulator divergence,
nor an input artefact. It is **inherited GFX11 ring code that the Candidate-E
transform normalized in three variants and not in two.**

## 2. Why "the transform missed two variants" is not by itself a reason to build Candidate G

The tempting move is: extend the mask site list to `<128,false>` and
`<256,false>`, and the gate goes green. K4C forbids exactly that —
*"No 'mask until green'"* — and requires any new normalization to be
*independently justified*. It names six things to prove. Assessed against
what K4 actually measured:

| required proof | status |
|---|---|
| **exact logical ring size** | **NOT PROVEN.** The transform uses `0x3FFF` = 16383. Candidate F declares 16384 for `<128,false>`; the **original** declares 15616; `<256,false>` declares 19200. Three different numbers, and the mask's window matches only one of them — the one the transform itself chose. No measurement fixes the ring size. |
| **exact point where masking belongs** | **PARTIALLY KNOWN, NOT JUSTIFIED.** The transform's convention is measured: the mask is the instruction immediately preceding the access, on the address register (all 34 masked sites). But at these eight sites the DS immediates (0…1792) are added *after* the mask, so `(producer & 0x3FFF) + imm` is the real address — the transform does not bound the EA by construction. The same gap is visible at a masked site today: `0xBDC8C ds_read_u16 v5, v31 offset:15616` has a reachable range of `[15616, 31999]` against a 16384 bound. |
| **store/load twins** | **NOT SATISFIABLE from present evidence.** The octet's stores use offsets 0, 256, …, 1792. The twelve shift-7 load twins use offsets **0, 128, 512, 640** and a *different* producer (`v_or3_b32` three-way OR, versus the store's `v_or_b32` two-way OR). There is no matched store/load pair for this octet, so it cannot be shown that masking the stores keeps them paired with their readers. |
| **liveness** | **NOT PROVEN.** No liveness analysis was performed. The tag enters through `v63`, a live-in whose definition lies outside the block; a static search found 174 writers of `v63`/`v60` in the kernel range, and none could be resolved to the one feeding this block. |
| **barrier identity** | **NOT PROVEN.** No barrier analysis was performed for these sites. |
| **no unrelated CFG change, no scratch/global impact** | **SATISFIABLE but unproven.** Checked mechanically: `v7` is written once at `0x000F62A8` and consumed by exactly the eight stores and nothing else, so a mask on `v7` would be isolated to the LDS path. The same `v40` that feeds `v7` also feeds a **global** address at `0x000F4D00` (`v_lshl_or_b32 v3, v40, 7, v37` → `global_load_sbyte v4, v3, s[24:25]`) — masking `v7` would not touch that, but the interaction is a claim that has to be demonstrated, not assumed. |

Two of six are satisfiable in principle; four are not established.

## 3. The decisive objection: the mask is a semantic change, not a hardware model

This is the part that makes the decision, and it is a measurement, not a
preference.

`phase14ei_probeC1_14bit_alias.md` and `phase14ei_probeC2_highbits.md`
measured DS addressing on **real gfx1030 silicon**:

* **C1** — under a 32-KiB group segment, `0x0000` and `0x4000` hold distinct
  sentinels. The `EA & 0x3FFF` 16-KiB-ring model is **refuted**.
* **C2** — under a 64-KiB group segment, **46 of 46** high-composite DS reads
  returned **zero**, across `ds_read_b32/u16/b64/b128/read2_b64`. No low-16
  alias, no wrap, no truncation. `EA >= allocation ⇒ read returns zero,
  write discarded`.

So `& 0x3FFF` is **not** what the hardware does. Applying it does not make
the emulator more faithful — it changes **which memory location the kernel
addresses**, folding slice tag 7 and slice tag 14 onto the same ring offset.

That is a change in program semantics. Under K4C it would have to be an
*independently justified correction*, and the justification would have to be
that the slice tags carry no distinct live data — that the ring is genuinely
a 16-KiB window and the tags are cycle counters, as
`phase16_lds_ring_analysis.md` asserts. **That assertion has not been
measured.** The one instrument that could have tested it — whether the tags
are input-dependent — is H6, and H6 refuted input-dependence without
establishing semantic equivalence: an invariant tag is equally consistent
with "cycle counter over one live window" and with "distinct slice that the
authentic data happens to set to 7 and 14".

A change that folds two address spaces together, justified by an unmeasured
claim, applied until a gate turns green, is the precise thing K4C was written
to prevent.

## 4. What would change this decision

The decision is not "never"; it is "not on this evidence". It would change if
any of the following were measured:

1. **A gfx1100 measurement** of what `ds_store_b16` does with `EA = 0x70000`
   under a 15616-byte group segment. If gfx1100 aliases where gfx1030 does
   not, the mask becomes a *translation* correction rather than a semantic
   change. This requires physical GPU work, which this phase does not perform.
2. **A liveness/data-flow proof** that the ring offsets `[0, 0x7E]` written by
   the octet are never read back through a slice-tagged address — i.e. that
   the tags are not load-bearing. The twelve load twins are the place to look;
   they currently use a different offset set and a different producer.
3. **A capture of the authentic private-segment contents** at this block, to
   show what `v63` actually holds in a real game dispatch. The host-side
   pattern test cannot reach this, because `v63`'s producer is outside the
   modelled arena.
4. **A derivation of the ring size** from the kernel rather than from the
   transform — the three candidate numbers (15616, 16384, 19200) currently
   disagree, and the mask matches only the transform's own choice.

Absent (1)–(4), extending the mask is a hypothesis, not a correction.

## 5. Consequence for the phase

* **Candidate F remains the final module.** No Candidate G exists.
* The 82 pcrel relocations were **not** re-verified, because no new module was
  produced; they remain as verified for Candidate F.
* The two failing variants cannot be reported CLEAN. Under K5's vocabulary
  (CLEAN / EXPLAINED_VALID / BLOCKED, no vague AMBER) the honest label is
  **BLOCKED**: the accesses are fully *explained* (provenance is complete and
  reproduced in both variants) but they are **not shown to be valid**. Calling
  them EXPLAINED_VALID would require the semantic-equivalence proof of §3,
  which does not exist.
* This item is therefore the LDS-semantics blocker standing between the
  present state and a `PRETEST_READY_FOR_J3_AUTHORIZATION` verdict.

## 6. Artefacts

Written by this workstream, all under `phase16k_pretest/k4_lds/`:

| file | content |
|---|---|
| `p16k_lds_census.py` | per-event LDS census instrument (fixed: trailing `per_wave` key) |
| `p16k_lds_census_swin128f_w8.json` | `<128,false>`, 8 waves, pattern A — 4096 outside (pre-K1 semantics) |
| `p16k_lds_census_swin256f_w8.json` | `<256,false>`, 8 waves, pattern A — 8192 outside |
| `p16k_lds_census_swin128f_w8_genB.json` | `<128,false>`, 8 waves, pattern B — H6 |
| `p16k_lds_census_swin128f_w8_genA_postK1.json` | `<128,false>`, 8 waves, pattern A again, post-K1 — separates the K1 change from the H6 effect |
| `p16k_lds_producers.py` | per-site address-producer census, both modules |
| `p16k_lds_producers.json` | the census data |
| `p16k_lds_slice.py` | self-mask instruction census (chain walk now delegates to the producers tool) |
| `p16k_lds_slice.json` | the self-mask data |
| `p16k_lds_census.md` | census, slice, H1–H6 verdicts |
| `p16k_lds_compare.md` | original gfx1100 vs Candidate F |
| `p16k_lds_verdict.md` | this file |

No file outside `phase16k_pretest/k4_lds/` was created or modified, with one
exception stated for completeness: `phase16k_pretest/tools/p16k_manifest.py`
and `phase16k_pretest/evidence_manifest.json` were written by the K0
workstream earlier in this phase, not by this one. No frozen artefact was
touched; `p16k_manifest.py --verify` was not re-run here.
