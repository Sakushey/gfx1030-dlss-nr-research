# Public Roadmap

Current position, at the granularity a reader outside the project can act on.
Machine-readable companion: [`PUBLIC_STATE.json`](PUBLIC_STATE.json).

**This is a limits statement first.** Nothing below is a compatibility claim, a
performance claim, or a statement that any game, mod or workload works on
`gfx1030`.

## Tracks

| track | verdict | blocker | next acceptance |
|---|---|---|---|
| `AUDITS` | AUDIT4_PRESERVED_CLAIMS_EXTRACTED -- PARTIALLY_DISPOSITIONED | 8 of 16 claims remain OPEN; 5 of them are launch-relevant | every launch-relevant finding carries a typed disposition |
| `CANDIDATE_F_TRANSLATION` | DEMONSTRATED_TRANSLATION_DEFECT -- VOPD sequentialization, one site proved | corrected artifact CANDIDATE_F_VOPD_CORRECTED_V1 is not built | a corrected translation bound to the actual parent, statically qualified, with no physical run |
| `CAPTURE` | BLOCKED_BY_MEASURED_DEPENDENCY, authorization valid and unspent | real-backend bridge equivalence is not established; RAW_DUMP argument and frame semantics are defective | bridge equivalence PASS, then one authorized story-mode cold + warm capture |
| `GAME_INTEGRATION` | NOT_REACHED | no complete offline job has run; the game resource contract is unwritten | one authenticated complete offline job with nontrivial output |
| `GRAPH_REFERENCE` | ADVANCED_NOT_ROBUST -- 520 / 535 first-frame fields | no instance-level authentic DAG; weight provenance is collapsed into one boolean | AUTHENTIC_JOB_DAG_V1 built from captured instances |
| `NATIVE_SLOT5` | PREPARE_PATH_QUALIFIED / EXECUTION_BACKEND_MISSING | no real execution backend; the loop-termination proof is unsound; the numerical contract has an unpinned parameter | execute backend + sound loop proof + repaired numerical oracle, all bound to the same experiment id |
| `PHYSICAL` | J3_TDR_CORRECT_INPUT -- the last non-game slot is 1 and is HELD | the final qualification program is not green; do not launch from the old 24/26 gate | a full SLOT5_QUALIFICATION_V3 pass with a demonstrated positive path |
| `PUBLICATION` | PENDING_DRIFT | none engineering; no draft PR can be opened from this environment | a coherent public-safe checkpoint pushed fast-forward |

## How to read a track

A track's `verdict` is what has been **measured**. A `blocker` is the specific,
named thing that stops the next acceptance. A track with a blocker is not
"nearly done" — the blocker is the work.

## What is deliberately not attempted here

* No schedule. A date would be a claim this project has no evidence for.
* No percentage complete. Progress here is a set of gates, and gates are reached
  or not reached.
* No roadmap item is closed by another item being closed.
