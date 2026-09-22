# SOURCE_GROUNDING_REGISTER — Phase 16AW

Mirror of `SOURCE_GROUNDING_REGISTER.json` (brief PART XXV, sections 141–146).
Machine-readable fields are authoritative; this file is the concise human view.

- **Generated:** 2026-09-21T21:08:18Z · Phase 16AW · HOST-ONLY · GPU calls: 0
- **Write scope:** `p16aw/sources/` only. Read-only with respect to the GPU and
  to all pre-existing project artifacts.
- **Brief source:** `p16aw/audit/ASTRA_AUDIT4_2026-09-21.md`
  (`sha256 f4b882663490ab42834122bb56b87b2fe096f7445b0419502956eefc694ca36b`)
- **Refresh results:** `SOURCE_REFRESH_16AW.json`

---

## 1. The two-value rule

The supervisor's value and this phase's measured value are **different quantities in
different fields**, so they can never be confused:

| field | provenance |
|---|---|
| `supervisor_last_seen` | transcribed from the brief as supplied — **never measured here** |
| `last_seen_commit` | **measured by this phase**; method recorded in `SOURCE_REFRESH_16AW.json` |

A `null` measured field means *this phase did not measure it* — it never means "no change".

## 2. Evidence hierarchy (brief s144, verbatim)

```
exact local artifact
>
official architecture/runtime specification
>
locally reproduced external repo claim
>
unreproduced external repo claim
>
hypothesis
```

## 3. Compatibility labelling (brief s26)

Every imported claim carries exactly one label:
`IDENTICAL_PRIMARY_ARTIFACT` · `COMPATIBLE_VERSION` · `DIFFERENT_VERSION_ANALOGUE` · `UNKNOWN_COMPATIBILITY`.

> **NO finding crosses repositories without such a label.** An unlabelled import is a
> defect, not an omission.

## 4. Mandatory every supervisor session (brief s142)

Checked at the start of every serious supervisor session and before any physical or
roadmap decision. If changed: enumerate commits/files, extract project-relevant deltas,
update the claim register — and **do not automatically promote claims**. If the network
is unavailable, mark `SOURCE_REFRESH_STALE` — **never "no changes."**

| id | repo | branch | supervisor last-seen | **measured 16AW** | status |
|---|---|---|---|---|---|
| **SRC-A** | `philippraschke75-spec/gfx1030-dlss-nr-translation-lab` | main | `152fdfe` | `152fdfecf0d3b03f08628606b6458dd3cbd90e0c` | **SAME** |
| **SRC-B** | `TripleZer000/gfx1032-dlss-nr-research` | main | `be22541` | `be225412da5b05b33b279d0c0792ae65169992d9` | **SAME** |

Roles — **A:** independent gfx1030 translation/capture research · comparative physical
evidence · translation strategies · weight/launch-contract investigation.
**B:** related GFX10.3 host-gate/module-load research · integration questions ·
comparative architecture investigation.

## 5. Primary official sources (brief s143)

| id | repo | branch | supervisor last-seen | **measured 16AW** | status |
|---|---|---|---|---|---|
| SRC-C | `ROCm/llvm-project` | amd-staging | `4f26d79` | `4f26d79705247aaaeca97c2882361c5a40546d82` | SAME |
| SRC-D | `ROCm/clr` | develop | `1cb204b` | `1cb204b798a18936babb025406bfb588a84c1d6f` | SAME |
| SRC-E | `ROCm/hip` | develop | `2f3f4dc` | `2f3f4dc74d84acd5662e9f07d01048e6c81d013d` | SAME |
| SRC-F | `ROCm/composable_kernel` | develop | `735c465` | `735c4655078aac1cad86b8d198780e9f699c889d` | SAME |
| SRC-G | `GPUOpen-LibrariesAndSDKs/FidelityFX-SDK` | main | `60f4ea8` | `60f4ea81909200d8542eca14dccb2628b763a9a3` | SAME |
| SRC-H | `GPUOpen-Tools/radeon_gpu_analyzer` | master | `39688b0` | `39688b004af6993f7146dd8e26b52994ec020fe6` | SAME |
| SRC-I | `microsoft/DirectX-Graphics-Samples` | master | `213dd4f` | `213dd4fd4918ea009dd8f35adee1aff1f2ecaba4` | SAME |
| SRC-J | `TsudaKageyu/minhook` | master | `8af6b4a` | `8af6b4acae5a9388fd742b56fa79ece89d96f823` | SAME |
| SRC-K | `ROCm/rocprofiler-compute` | *(default — see note)* | `05fbfd4` | `05fbfd4c34f77d6a7f9ec95f180cf321a94b42b9` | SAME |

**SRC-K branch note.** The brief named no branch. The value lives on the repository's
**default** branch, measured as `refs/heads/develop_deprecated` (and as `HEAD`). The
branch now called `develop` is a *different* commit (`4ac6c9c5…`), as are `main`
(`8a11ea15…`) and `amd-staging` (`eba15d75…`). A future checker who assumed `develop`
would compare against a different lineage and could report a spurious `NEWER`. The
supervisor value is preserved unchanged; only the resolution is recorded.

## 6. Local clones already assimilated

| id | clone path | local HEAD | remote main | at pin? |
|---|---|---|---|---|
| **SRC-L** | `p16au/external/_clone/translation-lab` | `4a0ec6e03bd05f11cd991d3a6883891037c1b7c2` | `152fdfe…` | **NO — BEHIND** |
| **SRC-M** | `p16at/external/_clone/gfx1032-dlss-nr-research` | `be225412da5b05b33b279d0c0792ae65169992d9` | `be22541…` | yes |

**SRC-L is behind.** The clone is at `4a0ec6e` ("Merge initial repository README",
2026-09-21T16:05:44+02:00); its own `origin/main` tracking ref also holds `4a0ec6e`;
the remote main measured this phase is `152fdfe`. The pin is **absent from the clone**
(`git cat-file -t 152fdfe…` → `fatal: git cat-file: could not get object info`).

Why: the clone was made in phase 16AU, when the brief pinned `4a0ec6e`
(`p16au/external/translation_lab/SOURCE_MANIFEST.json`). The pin was later advanced;
the clone was never re-made. So the clone is a faithful copy of the **older** pin.

*Consequence for the 16AU claims: none.* Claims E1–E10 are correctly scoped to
`4a0ec6e` — the bytes actually read. What is stale is the clone, not the claims.

**Required action before any future comparative use:** re-clone at the pin, or record
explicitly that the comparison was made against `4a0ec6e` and *not* against `152fdfe`.
Using the stale clone while quoting the pin would attribute `4a0ec6e`'s content to `152fdfe`.

**Ancestry is not proven.** Whether `4a0ec6e` is an *ancestor* of `152fdfe` was not
established — that needs the missing objects and a fetch is forbidden here. Brief s24
records the supervisor's own finding ("TWO commits ahead"), which is consistent with
ancestry but is the supervisor's measurement, not this phase's. **"Behind" here means
"not at the pin and does not contain it" — not a proven first-parent ancestry claim.**

## 7. Discovered source (brief s146)

| id | repo | role | recorded | licence |
|---|---|---|---|---|
| SRC-N | `lmxxf/dlss5-on-amd-9070xt-porting` | the DLSS 5 (DLSSNR) 71-block Swin/ViT network description — the object this project researches | `79c1654f88e673b0f26fed201dd82bf80095b696` | **MIT — the only licence text actually on disk and hashed** (`p16as/_fetch/upstream/LICENSE`, sha256 `ab181e59…`) |

Two honest caveats. **No supervisor value exists for this source** — it was registered
under s146, and its absence from the supervisor's list is recorded rather than concealed.
Its commit is **read from phase 16AS's fetch manifest, not re-measured this phase**, so
its `last_checked_utc` is `null`.

## 8. Document sources (brief s144) — identity and role only

Not fetched; the brief does not require it. `availability` is stated honestly.

| id | document | compatibility default | availability |
|---|---|---|---|
| DOC-1 | AMD **RDNA2** ISA reference guide (70648) | `COMPATIBLE_VERSION` — the exact ISA family targeted | `NOT_FETCHED_THIS_PHASE` |
| DOC-2 | AMD **RDNA3** ISA reference guide (70650) | `DIFFERENT_VERSION_ANALOGUE` for gfx1030 (it is the **source** ISA) | `NOT_FETCHED_THIS_PHASE` |
| DOC-3 | ROCm LLVM **AMDGPUUsage** | `COMPATIBLE_VERSION` | `NOT_FETCHED_THIS_PHASE` |
| DOC-4 | ROCm **GFX1030 instruction syntax** | `COMPATIBLE_VERSION` | `NOT_FETCHED_THIS_PHASE` |
| DOC-5 | Microsoft **D3D12 resource barriers** | `COMPATIBLE_VERSION` | `NOT_FETCHED_THIS_PHASE` |
| DOC-6 | Microsoft **D3D12 fences / shared handles** | `COMPATIBLE_VERSION` | `NOT_FETCHED_THIS_PHASE` |
| DOC-7 | **NVIDIA DLSS 5 research description** | `UNKNOWN_COMPATIBILITY` | **`NOT_IDENTIFIED`** |

Two entries need a flag rather than a tick:

- **DOC-4** is the least crisply identified entry. The brief names it generically and no
  single canonical document of that title was located or fetched. It is registered as a
  **source class** (the AMDGPU backend's gfx1030 assembler/disassembler corpus plus its
  target tables). A future phase should bind it to a path and revision, or retire it.
- **DOC-7 is unresolved, not satisfied.** No first-party NVIDIA publication under that
  identity was located. What exists on disk is the *third-party* re-implementation
  `SRC-N`, whose README describes the network. That is a **different source with a
  different evidence ceiling**; registering it under the brief's name would be a
  substitution, so the two are registered **separately** and DOC-7 stays unresolved.

## 9. No-vendoring binding (s25 / s27 / s28)

- **s25/s27 — the Cyberpunk FSR3 capture is the translation-lab's OWN evidence ceiling.**
  It must **not** be treated as GTA V Enhanced's input contract. Input-contract identity
  between the two was never established and is not implied.
- **s28 — the VOPD temporary-result lowering is INDEPENDENT COMPARATIVE SUPPORT only**
  for the parallel-assignment strategy. Not adopted proof; not a source of code.
- **No source may be vendored or copied because no explicit license was observed.**
  Both local clones are reference-by-identity only:
  - `SRC-B` / `SRC-M`: `NO_LICENSE_FILE_FOUND`, vendoring **unconditionally** not permitted
    (`p16at/external/gfx1032/LICENSE_STATUS.json`, sha256 `0b913e24…`).
  - `SRC-A` / `SRC-L`: `NO_EXPLICIT_LICENSE_OBSERVED`, vendoring not permitted
    (`p16au/external/translation_lab/SOURCE_MANIFEST.json`, sha256 `6412bf74…`).

## 10. Refresh summary — 2026-09-21

```
outcome = ALL_LOOKUPS_SUCCEEDED      source_refresh_stale = false
11 queried · 11 SAME · 0 NEWER · 0 STALE
```

*Timestamp precision:* the instant of each lookup was not individually recorded.
`last_checked_utc` is `2026-09-21T21:08:18Z` — the clock reading taken on the command
immediately after the lookups, so an **upper bound**, not an interpolated midpoint. An
interpolated "plausible" time would be fabricated precision.

**Every one of the eleven remote HEAD values measured this phase equals the supervisor's
last-seen value exactly. No source has advanced. No lookup failed. `SOURCE_REFRESH_STALE`
is NOT set.**

Method: `GIT_TERMINAL_PROMPT=0 git ls-remote --heads <url> <branch>` (git 2.55.0.windows.3).
Read-only — a ref advertisement; no local repository, no objects, no files written.

The method was **shown able to discriminate, not merely asserted to**: on
`ROCm/llvm-project` the same call returned three refs with three *different* SHAs
(`amd-staging`, `archive/amd-staging`, `msearles/amd-staging`); likewise `develop` vs
`docs/develop` on clr and hip, and `develop` vs `zhimding/develop` on composable_kernel.
A tool returning a constant, or a call silently matching the wrong ref, could not have
produced that.

`SOURCE_REFRESH_STALE` would be set, **with the exact error text**, had any lookup failed
or the network been unavailable — and would never be reported as "no changes". That case
did not arise.

### Explicitly not measured this phase

- a fresh lookup for **SRC-N** (read from a prior phase's artifact; `last_checked_utc: null`)
- any network lookup for the seven **DOC-\*** sources
- the **licence text** of the official/third-party repos — the `license` field records the
  established upstream default with `license_verified_this_phase: false`; only SRC-N's
  licence text was actually read and hashed
- an **object-graph** ancestor proof for the translation-lab clone (needs a fetch)

---

## What this register is not

Not a copy or mirror of any source · not a licence grant · not a claim that any
registered source's claims are true · not a substitute for re-checking a source before
relying on it. A `SAME` result means the source did not move — it does **not** promote
any claim.
