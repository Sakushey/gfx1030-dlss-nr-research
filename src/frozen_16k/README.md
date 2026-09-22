# frozen_16k — Phase 16K evidence, frozen PRE-FIX

**Status: HISTORICAL / PRE-FIX REFERENCE. Read-only. Never a source of current truth.**

Phase 16L opened by freezing the Phase 16K report, its final state, and the
Phase 16K evidence the report explicitly references. The reason is stated in the
16L brief itself: Phase 16K found that **the host instrument is wrong**, so
everything it measured dynamically must be re-derived rather than reinterpreted.

The originals in the rest of the tree are **untouched**. This directory holds
hash-verified copies plus `FROZEN_16K_EVIDENCE.json`, which records path,
SHA-256, size, freeze time, and the re-hash verification of every copy.

## What "PRE-FIX" means here

`emulator_base__emu.py` (SHA-256 `4f4a64acabd5c1f8…`) is the **defective**
emulator exactly as Phase 16K used it. It is preserved deliberately: the Phase 16L
ISA-conformance oracle proves its defects against the ISA, and a defect cannot be
proven against a file that has been edited.

## Rule for Phase 16L and later

- Do **not** overwrite any file in this directory.
- Do **not** cite a number from here as a current measurement. Cite it only as
  "Phase 16K measured X, invalidated because Y" (see `../EVIDENCE_INVALIDATION.md`).
- The declared-supersession policy is applied in `../evidence_manifest_16l.json`;
  nothing was silently rebaselined.

## Contents

| key | what it is | why frozen |
|---|---|---|
| `session_report` | Phase 16K `SESSION_REPORT.md` | the report whose dynamic results are invalidated |
| `final_pretest_state` | `FINAL_PRETEST_STATE.json` | the `BLOCKED_OTHER` verdict record |
| `swin_matrix_csv` / `_json` | the five-variant gate matrix | re-derived in L5 as `phase16l_swin_matrix.csv` |
| `evidence_manifest` | 16K manifest | predecessor of `evidence_manifest_16l.json` |
| `validator_policy` | K17 3-leg audit | re-run in L23 |
| `k3_arena_rerun` | K3 dynamic arena rerun | dynamic half invalidated; static topology survives |
| `k4_lds_verdict` | K4 `0xE077E` verdict | static half survives; `ea_max` invalidated |
| `k6_numeric_contract` | J3 numeric contract | superseded by `J3_V2_NUMERIC_CONTRACT.md` |
| `k6_reach_evidence` | frozen-canvas reach | the 8192-B canvas is retired (L8) |
| `k7_oneshot_design` | one-shot design | admission placement re-decided in L11–L13 |
| `candidate_f_co` | **Candidate F** `47b5d1d1…` | **still the current candidate** — frozen as the baseline identity |
| `candidate_f_fatbin` | fatbin `ec9bffea…` | payload identity |
| `alpha_bridge` | frozen alpha bridge `93484428…` | still deployed; not mutated |
| `phase16k_bridge` | K7 bridge `39fa91b5…` | historical unless L11–L17 leave the bytes final |
| `j3_harness_exe` / `_cpp_source` | old J3 harness `72335a20…` | **RETIRED** — L10 builds a new harness |
| `emulator_base` | `phase8_static/tools/emu.py` PRE-fix | the defect evidence |

## The retired J3 input

The old J3 physical input hash

```
592766ef55c9544d0f3da9b7d496d635d13799842ef5c97181a2f45308e7a2f8
```

is **RETIRED** by Phase 16L (L8). It was built over an 8192-byte canvas for a
geometry whose recovered canvas is 32768 B/tile, and the kernel reads far past
both. Per the L8 instruction it must **never again** be called the current
physical input. `j3_input_candidate__p16j_j3_input_hash.json` is retained only as
the record of what that hash was.
