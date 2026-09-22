# Phase 16O Track A — the Phase 16N regression, root-caused

**Host-only. No GPU execution, no GTA launch, nothing armed.**

---

## Verdict

| field | value |
|---|---|
| **root-cause classification** | **`CORRECT_REPAIR_EXPOSED_HARNESS_DEFECT`** |
| minimal causal source-change set | `phase8_static/tools/emu.py` — `Core._mem_byte` / `Core._read_u32` (Phase 16N defect **D9**) |
| necessary? | **yes** — reverting only D9 restores the pre-16N cell |
| sufficient? | **yes** — keeping D9 and reverting every other Phase 16N emulator repair still reproduces the regression |
| older defect fixed | `phase16j_pre_gta/tools/p16j_input.py` :: `regions_for` |
| Candidate F | **byte-unchanged**, `47b5d1d11041b034ac30eebac090ee922f415d8f08a0111e69641d7e0557524b` |
| Phase 16N repairs reverted? | **no — all 13 are kept**, as the brief requires |

---

## 1. The two endpoints (A1)

Two independent source trees, each run in a **fresh process** by
`tools/a_run_rev.py`, which prints source-root path, the SHA-256 of every
edited module **actually imported**, the composed MRO, the Candidate hash
and the fixture hash, and **aborts** if any edited module resolved outside
the revision tree.

| revision | contents | ticks | OOB r / w | signature | reproduces |
|---|---|---|---|---|---|
| `pre16n` | all Phase 16N repairs reverted | 13,590 | 0 / 0 | `8d37352c…` | the Phase 16M clean cell, **exactly** |
| `post16n` | as Phase 16N left it | **10,553** | **15,104 / 4,352** | `5cc9e6a6…` | the Phase 16N regression, **exactly** |

`post16n`'s signature `5cc9e6a66ee81c039686012ee9361c298bf7d7580795783045c0281008a2060e`
is byte-identical to the value Phase 16N recorded in
`phase16n_semantic_freeze/n8_matrix/SMOKE_swin32f.json`, and `pre16n`'s
`8d37352c20dbf9770385d9a582c057eb76455eb74662455ba7fc742a35472365` is
byte-identical to Phase 16M's clean cell.  Both endpoints reproduce their
reference cells, so the provenance question is settled before any semantics
are debugged.

> **No pre-16N source backup exists**, and that was *checked*, not assumed:
> the only pre-16N artefact on disk is the SHA-256 of
> `phase8_static/tools/emu.py` (`597148aa2f28bad7…`, 62,118 bytes) in
> `phase16m_final_host/m0_freeze/P16M_INITIAL_HASHES.json`, and no file of
> that size or digest exists anywhere in the tree.  **PRE16N is therefore a
> reconstruction** from the defects' own recorded descriptions, and it is
> validated **behaviourally** — it reproduces the reference cell exactly —
> rather than claimed byte-exact.  This is stated here rather than buried.

## 2. Source-level subset bisection (A2)

Runtime monkey-patching is retired; every arm below is a real source tree,
built by `tools/a_build_revs.py`, whose every substitution **fails loudly**
if its target text is absent or ambiguous.  All arms below run under the
**Phase 16N harness conditions** (the buggy `regions_for`), which is the
state the regression was measured in.

| arm | ticks | OOB r / w | verdict |
|---|---|---|---|
| `post16n` (baseline) | 10,553 | 15,104 / 4,352 | **regressed** |
| `minus_p14d8_core` | 10,553 | 15,104 / 4,352 | unchanged |
| `minus_p14e_emu` | 10,553 | 15,104 / 4,352 | unchanged |
| `minus_p14eh` | 10,553 | 15,104 / 4,352 | unchanged |
| `minus_p16e_rec` | 10,553 | 15,104 / 4,352 | unchanged |
| `minus_p16h_scratch_probe` | 10,553 | 15,104 / 4,352 | unchanged |
| `minus_p16j_scratch_isa` | 10,553 | 15,104 / 4,352 | unchanged |
| **`minus_emu_d9only`** | **13,590** | **0 / 0** | **restored** |
| `minus_emu` (every emu repair) | 13,590 | 0 / 0 | restored |
| **`minus_emu_other16n`** (D9 kept, every other emu repair reverted) | **10,553** | **15,104 / 4,352** | **still regressed** |

Six of the seven edited files are **individually inert** for this cell.
Inside `emu.py`, D9 is both **necessary** (`minus_emu_d9only` restores) and
**sufficient** (`minus_emu_other16n` does not).

**This supersedes Phase 16N's runtime bisect**, which reported that no
repair was causal.  That result was an artefact of the method: the
`class_mask` arm reassigned `SwinCore._cmp_dispatch` to a closure whose
fallback called `E.Core._cmp_dispatch` — the **base** method — so restoring
one repair silently replaced a *different* override for every non-class
compare.  A runtime patch is a claim about equivalence that nobody checked.

## 3. First semantic divergence (A3)

**Tick 2, wave 0, PC `0x000AB504`:**

```
s_load_dword s45, s[0:1], 0x28        ; s[0:1] = kernarg base 0x10000
    resolved byte address  0x10028
    PRE16N  ->  0x00000001            the real dword key
    16N     ->  0x8C1DEF01            one real byte + three pattern bytes
```

| byte | real dword key? | synthesised from region | PRE16N | 16N |
|---|---|---|---|---|
| `0x10028` | yes | — | `0x01` | `0x01` |
| `0x10029` | no | base `0x240` | `0x00` | `0xEF` |
| `0x1002A` | no | base `0x240` | `0x00` | `0x1D` |
| `0x1002B` | no | base `0x240` | `0x00` | `0x8C` |

`s45` is not an address; it selects a branch shortly afterwards.  That is
why the tick count moves as well as the addresses.

## 4. Provenance of the first bad global address (A4)

First bad site `0x000ACC24` — `global_store_dword v[1:2], v6, off`,
encoding `DC708000 007D0601`, 256 events, range
`0xEDD8F504AEFF2600`..`0xEDD8F504AEFF29FC`.  **All 4,352 global writes are
out of bounds**, at 68 sites, all addressed through this family.

The base pair `s[38:39]` is defined by

```
0x000AB53C   s_load_dwordx4 s[36:39], s[0:1], 0x98
```

| dword | bytes (16N) | 16N word | pre-16N word | dest |
|---|---|---|---|---|
| `0x10098` | `CD 20 10 6B` | `0x6B1020CD` | `0x000000CD` | s36 |
| `0x1009C` | `D9 16 12 FC` | `0xFC1216D9` | `0x000000D9` | s37 |
| **`0x100A0`** | `00 26 FF AE` | **`0xAEFF2600`** | `0x2B870000` | **s38** |
| **`0x100A4`** | `04 F5 D8 ED` | **`0xEDD8F504`** | `0x00000004` | **s39** |

Re-derived base **`0xEDD8F504AEFF2600`**; the gate measured
**`0xEDD8F504AEFF2600`**.  The correct value is the canvas pointer,
**`0x000000042B870000`**.

**Every register has a producer.**  No component is read before it is
defined, there is no uninitialised register, and there is no missing ABI
input.  The *value* is wrong, and it is wrong because three of the four
bytes at `0x100A0`/`0x100A4` were answered by a synthesised pattern byte
instead of by the real dword key beside them.

`gate/FIRST_DIVERGENCE.md` and `gate/FIRST_DIVERGENCE.json` re-derive every
number above and **check it against the measured value**; the script exits
non-zero on disagreement and refuses to pass if its negative control (both
readers agreeing) fires.

## 5. The mechanism (A5)

`phase16j_pre_gta/tools/p16j_input.py :: regions_for()` had a docstring that
said *"for every authentic POINTER field"* and a body that looped over
**every non-empty entry of `vals`** — including the **scalar** kernarg
fields — using each entry's **VALUE** as a region base:

| field | value | region declared at | what it actually is |
|---|---|---|---|
| `0x18` | `0x240` | **`0x240`** | X, a coordinate |
| `0x1C` | `0x3C0` | **`0x3C0`** | Y, a coordinate |
| `0x28` | `0x1` | **`0x1`** | flags |

Each is 64 MiB wide.  Together they claimed the entire low address space —
**including the kernarg segment at `0x10000`**.

`PatternMem.__contains__` answers `True` for **any** address inside a
declared region.  Phase 16N's D9 repair — *correct per the ISA* — made
`Core._mem_byte` ask `a in self.mem` to mean *"a real byte was stored
here"*.  For `PatternMem` that question returns `True` for synthesised
addresses too, so the pattern byte outranked the real dword key beside it
and the byte-addressed reader assembled the kernel's base pointers out of
pattern noise.

**The Phase 16N repair is right; the harness region declaration is wrong.**
`p16i_authentic_harness.run` had already been corrected the same way for the
**gate's** region declarations — its comment records the identical mistake
("inventing three large low-address windows in which a genuinely
out-of-bounds read was scored as legitimate") — but the same bug was left in
the **data** path.

### The fix

`regions_for` now declares synthetic regions **only at the authentic pointer
fields**, which is what its own docstring always said:

```python
POINTER_FIELD_OFFSETS = (0x00, 0x08, 0x10, 0x30, 0x38, 0xA0)
```

One second, independent change was made and is reported **separately,
because it is not load-bearing for this cell**: `Core._mem_byte`'s two
"does a real entry exist" tests are now `dict.__contains__` rather than
`in`.  The arm `harness_fixed_only` (16N reader, harness fixed) already
restores the clean cell, so the harness fix alone is sufficient; the
`_mem_byte` change closes a latent hole that no cell in this project
currently reaches (a dword stored *inside* a declared pattern region and
read back through the byte-addressed reader).

### End-to-end confirmation

With the harness fixed, the **Phase 16N** emulator reproduces the Phase 16M
clean cell **exactly** — 13,590 ticks, 0 OOB reads, 0 OOB writes, 209,152
global reads, 6,656 global writes, signature
`8d37352c20dbf9770385d9a582c057eb76455eb74662455ba7fc742a35472365`.

That is the strongest available statement that the 13 Phase 16N repairs are
correct and complete: nothing was reverted, and the pre-existing clean
result came back.

## 6. Disposition of Phase 16N's "ambiguous" readings

Phase 16N settled two readings the evidence had not.  Both are now
**validated by the fixed harness**, not merely asserted:

* `v_add_f16` writes the whole destination (upper half zeroed) — the
  corrected run reproduces the pre-16N cell exactly, and every `v_add_f16`
  in this kernel is bracketed by `ds_read_u16` above and `ds_write_b16`
  below, so the upper half is dead either way.
* `v_cmp_class_f32`'s class-mask bit order — the mask is now read; the
  corrected run reproduces the same cell, so no SWIN control-flow decision
  depends on the difference.

## 7. What is NOT claimed

* PRE16N is a **behavioural reconstruction**, not a byte-exact restore.
* The 128 residual reads on `swin<32,true>` are analysed separately
  (`../e_swin32t/E_RESIDUAL.md`) and are **not** attributed to this defect.
* No claim is made that the harness defect was the *only* thing wrong with
  the Phase 16N harness — only that it is the sole cause of this regression,
  measured from both sides.

## 8. Artifacts

| what | where |
|---|---|
| revision builder | `tools/a_build_revs.py` |
| revision runner (prints provenance) | `tools/a_run_rev.py` |
| revision manifest + per-file hashes | `REVISION_MANIFEST.json` |
| per-arm measurements | `out/REV_<rev>_<tag>.json` |
| first divergence + def-use provenance | `out/FIRST_DIVERGENCE.{md,json}` |
| measured scalar-load trace (both readers) | `tools/a_sload_probe.py`, `out/A_SLOAD_*.json` |
