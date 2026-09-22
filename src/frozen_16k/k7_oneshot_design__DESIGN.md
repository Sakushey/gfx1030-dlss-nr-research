# Phase 16K K7/K8 — one-shot job control and the runtime control plane

**Status: IMPLEMENTED, BUILT, AND VERIFIED HOST-SIDE. NOT DEPLOYED. NO GPU
WORK HAS RUN. NO GAME HAS BEEN LAUNCHED.**

Artifact: `prod_build/amdhip64_7.dll`
SHA256 `39fa91b558f506da892b5b6926561ffc394bab5064b9f75252675ced67e049f7`

The frozen alpha bridge (`phase16i_alpha/runtime/amdhip64_7.dll`,
`93484428…`) is **untouched**. This is a new artifact with a new identity, in
a new directory, exactly as the brief requires. Candidate F's module is not
touched, so `47b5d1d1…7524b` is unaffected.

---

## 1. What was wrong

`phase16i_alpha/build/src/amdhip64_7.cpp` had **two arming doors and no job
limit**. The only launch-related counter in the file was `launch_ordinal`,
which exists to number log lines. Arming the deployment gate therefore
started a **continuous** run: every subsequent `hipLaunchKernel` reached the
backend until the process died. That is not a first-physical-test
configuration, and it is the single thing standing between this phase and
`PRETEST_READY_FOR_J3_AUTHORIZATION`.

## 2. Why this is not a launch counter

The brief forbids implementing one-shot as "allow N kernel launches then
block launch N+1", and the reason is concrete: at the moment launch N+1
arrives, the host has already committed to it. If N+1 is the first launch of
the next job, the host is now waiting on a job that will never run — the
blocked-job failure mode this phase exists to remove.

`phase16j_pre_gta/j6_one_shot/DESIGN.md` §3 had exactly that shape in its
`kOneShotCap = 200` belt-and-braces: if the `Import`/`Export` markers were
ever missed, the cap would fire **inside a job**. That cap is deliberately
**not** carried forward.

Instead the supervisor's state changes only on:

* a control-plane command,
* a **job boundary marker** observed in the launch stream,
* a fault.

`launches_allowed` and `launches_refused` exist for accounting and for the
log. Nothing reads them to decide anything.

### The job structure, measured rather than assumed

`phase16j_pre_gta/out/j6_launch_seq.txt` is a real session's launch
sequence: 2239 launches, every one of them blocked, so the whole stream is
recorded with no GPU work happening.

```
job 1        indices   0..158    159 launches
jobs 2..14   indices 159..2238   160 launches each
159 + 13*160 = 2239

job start marker : k_flag_waitPjjj   (the job's FIRST launch)
job end   marker : k_flag_setPjj     (the job's LAST launch)
```

`flag_set` at 158 and `flag_wait` at 159 are adjacent, so the boundary is
unambiguous.

> **A contradiction in the earlier design, resolved.** `j6_one_shot/DESIGN.md`
> §3 places the boundary at `Import`/`Export` (indices 1..156) while its own
> §5 asserts `allowed == 159`. Worse, moving to `SPENT` at `Export` (index
> 156) would refuse `flag_set` at index 158 — job 1's own end marker —
> truncating the job. `CONTROL_PROTOCOL.md` uses `flag_wait`..`flag_set`,
> which is the measured boundary, and the simulation confirms 159.
> (Independently found by the K12/K13/K14 workstream.)

### The property that matters

Once a job is admitted, **every kernel of it is allowed**. No state and no
event can refuse a kernel belonging to an admitted job. That includes
operator action: `DISARM_NOW_IF_IDLE` refuses to cut a running job
(`BUSY_JOB_RUNNING`), and `DISARM_AFTER_JOB` queues the disarm to the
boundary.

### The three bounds, and what each is for

| bound | fires when | can it truncate an admitted job? |
|---|---|---|
| `NESTED_JOB_START` fault | a second start marker arrives while a job is running | no — the job already ended without its end marker, so the stream is malformed |
| `UNEXPECTED_LAUNCH_SHAPE` fault | a non-start launch arrives where a start was required | no — no job is admitted in that state |
| `TAIL_WATCHDOG` (512 launches) | armed while a job was in flight, and its end marker never arrives | no — this bounds only the tolerated *tail of an un-admitted* job |

The watchdog is the only raw number in the design. It is a shape watchdog,
not the one-shot mechanism: 512 is >3× the measured 160-launch job, so a
legitimate tail can never reach it, and reaching it means the stream stopped
matching the shape we measured. Its failure action — refuse everything — is
the failure this game build already tolerates (2239/2239 refusals, measured,
§4 below).

## 3. The state machine

```
                 ARM_ONE_SHOT (gate open)
   DISARMED ─────────────────────────────► ARMED_ONE_SHOT
      ▲                                          │
      │                                          │ job start marker
      │                                          ▼
      │                                     JOB_RUNNING
      │                                          │
      │                                          │ job end marker
      │            JOB_COMPLETE ◄────────────────┘
      │                 │
      └─────────────────┘   (immediate; the one shot is spent)

   FALLBACK — recorded instead of JOB_COMPLETE when no whole job was
              admitted (disarmed while armed, or process teardown mid-job).
   FAULTED  — entered from any state on a fault.  Fail-closed: every launch
              refused until restart.
```

`ARM_ONE_SHOT` is accepted only when the state is `DISARMED`, the deployment
gate is open, **and** we have seen a job boundary at some point (arming
against a stream whose shape we have never recognised is refused with
`UNMEASURED_STREAM_SHAPE`). Arming at process start, before any launch, is
allowed and is the ordinary case.

If a job is in flight when ARM arrives, the supervisor enters
`TOLERATING_TAIL`: that job's remaining kernels are allowed, because
refusing them would be refusing inside a job. The next `JOB_START` after it
is the one shot.

### One judgement call, stated plainly

Re-arming after the one shot is spent **is permitted** (at a job boundary,
with the gate open, by a deliberate operator command). The brief's diagram
draws `DISARMED → ARMED_ONE_SHOT` and `JOB_COMPLETE → DISARMED`, so
re-arming is reachable; making it a permanent lockout would contradict the
diagram and make the tool useless for a second test. What is *not* permitted
is a continuous mode: every job requires its own deliberate arm, and
`jobs_admitted_total` is reported so the count is never invisible. **This is
flagged for review** — if the intent is a permanent single-shot lockout, the
change is one line in `Supervisor::arm_one_shot`.

## 4. The control plane

`CONTROL_PROTOCOL.md` in this directory is normative. Summary:

| | |
|---|---|
| pipe | `\\.\pipe\DLSSNR_RDNA2_Control_<gamepid>` |
| framing | one JSON request per line, one JSON response per line |
| commands | `STATUS`, `ARM_ONE_SHOT`, `DISARM_AFTER_JOB`, `DISARM_NOW_IF_IDLE`, `COLLECT_STATUS` |
| authority | the runtime owns the state; a client may read it and request transitions, never set it |
| disconnects | change nothing — losing the observer is not losing the decision |

There is **no** command that arms a continuous run.

**Security.** The pipe is created with `PIPE_REJECT_REMOTE_CLIENTS` and a
DACL granting access only to this process's user SID (plus SYSTEM and
Administrators), built from the process token rather than a well-known SID.
Without it, any local process could disarm the supervisor or read its state.
This adds `ADVAPI32` to the bridge's import set — a deliberate, reviewed
change; the alternative is an IPC surface any local process can drive.

A pipe that fails to come up is **reported, not silent**: the bridge logs
`CONTROL_PLANE_UNAVAILABLE stage=… code=…`, and the supervisor keeps
enforcing its own state regardless.

## 5. What was verified, and how

Everything below is host-only. No GPU, no game, no driver, no registry.

| check | tool | result |
|---|---|---|
| the state machine over 15 scenarios | `out/k7_sim.exe` (compiles the **same** `src/oneshot.h` the DLL does) | 15/15 |
| independent per-event cross-check | `tools/p16k_k7_crosscheck.py` (a second implementation written from `CONTROL_PROTOCOL.md`, compared **per launch**, not on totals) | 15/15, 0 differences |
| the validator can fail | `--self-test` injects 5 deliberate defects | all 5 detected |
| the real control plane over the wire | `out/k8_ctl_host.exe` (links the **same** `src/control_plane.cpp`) driven by `tools/p16k_k8_client.py` | 25/25 |
| export set unchanged | `dumpbin /exports` against the frozen alpha DLL | 29/29 identical |

### The decisive result

`frames123` replays the **real 2239-launch sequence** through the
supervisor:

```
admitted = 159   refused = 2080   jobs_admitted_total = 1   final = DISARMED
```

Job 1 runs whole (159 launches); all 2080 launches of jobs 2..14 are
refused, and the refusal begins at job 2's **first** launch — at a job
boundary, before job 2 was submitted.

### Why refusal is a safe fallback here

In the session that produced `j6_launch_seq.txt`, all 2239 launches were
refused and the process carried on (`hipDeviceSynchronize -> 0`,
`hipMemcpy -> 0`), with the DLSS-NR runtime logging
`frames 600 dispatches 0 submitted 0 ready -1 route backbuffer`. Refusing a
launch is a failure mode this exact build already tolerates 2239 times in a
row, and its own fallback is to route the raw backbuffer. `BLOCKED_KERNEL_LAUNCH_ONE_SHOT`
returns the **same** `kHipErrorLaunchFailure` as the existing disarmed gate
for that reason: a different error code would be a new failure mode with no
evidence behind it.

## 6. What is deliberately absent

* No launch counter in the decision path.
* No wait, sleep, frame counter, or timeout.
* No fake success: a refused launch returns a real error and the backend is
  not called.
* No writes to any device buffer, by the supervisor or the control plane.
* No persistence: the state lives in the DLL's memory and dies with the
  process.
* No new arming door: `ARM_ONE_SHOT` still requires the deployment gate.

## 7. What has NOT been done

* The bridge has **not** been deployed, loaded, or run. It has been built
  and its logic has been verified host-side.
* `deploy_alpha.ps1` / `verify_alpha.ps1` hard-code the **old** bridge hash
  and will reject this one. Updating them changes frozen package bytes and
  was not done (see the K11 findings).
* Nothing in this directory has been executed against a GPU.
