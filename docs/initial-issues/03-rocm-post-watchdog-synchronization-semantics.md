# Investigate ROCm post-watchdog synchronization semantics

> Draft for supervisor review. Do not open automatically.

**Title:** Investigate ROCm post-watchdog synchronization semantics

**Suggested labels:** `rocm`, `runtime`, `physical`, `correctness`, `documentation`

**Evidence level:** `PHYSICAL_DIAGNOSTIC`, with a host-side component that is
`HOST_STATIC`. The host-side part requires no GPU; the confirmation requires
`gfx1030` and explicit authorization.

---

## Context

When a GPU operation does not complete, the Windows GPU watchdog (TDR) recovers the
engine. Recovery is the platform's response to a **hang** — it means the operation did
**not** complete, and it is not a success of any kind.

The problem this issue addresses is what happens *next*, on the host side. After a
watchdog recovery, a HIP synchronization call can **return without reporting an
error**. Taken at face value, that return value says "the synchronization succeeded",
which is the opposite of what actually occurred.

This matters well beyond this project's immediate blocker. Any diagnostic workflow on
this platform that checks a synchronization return value as its completion signal will
be misled in exactly this case — it will read a hang as a pass. In this project the
consequence would be severe: it would silently turn a non-completion into an apparent
result and could lead the research to a completely wrong conclusion about which rung
has been reached. The project's own discipline is that a **synchronization return value
is not kernel output**, and that the correct liveness signal is the one the harness
produces itself, not the one the runtime returns after a fault.

## What is needed

Two things: a documented understanding, and a way for tooling to detect the situation.

**Understanding (host-side first):**

- What does the runtime actually report after a watchdog-triggered recovery? Which
  calls return, what status do they return, and what does that status mean?
- Does the behavior differ by runtime generation? This project targets **ROCm 6.4**,
  which is the generation that enumerates `gfx1030` here; ROCm 7.1 does not enumerate
  this device in this environment. The bridge already fingerprints both generations
  (`src/bridge/abi_6_4_fingerprint.cpp`, `src/bridge/abi_7_1_fingerprint.cpp`).
- Which observable host-side signals **do** distinguish "completed" from "the engine
  was recovered"? Candidate signals worth characterizing: the presence of a completion
  marker written by the harness itself, heartbeat-style evidence that the process was
  alive throughout, and platform-level recovery records.

**Detection:**

- A host-side check that a completion signal is **self-produced** — written by the
  harness or the kernel under test — rather than derived from a runtime return code.
- A check that a run's liveness evidence covers the whole interval, so that a gap is
  visible rather than inferred.

**Explicitly out of scope** (prohibited by the hardware safety policy, and
self-defeating regardless): modifying watchdog/TDR settings to observe the difference,
or deliberately inducing recoveries by lengthening or stressing the workload.

The host-side portion can be done entirely with the mock backend
(`src/bridge/mock_hip6.cpp`), which can simulate the *reporting shape* without a
device. Confirming against a real recovery requires a physical run under
authorization; the physical part of this issue may legitimately remain open.

## What a good resolution looks like

- A written characterization of post-recovery synchronization behavior on the targeted
  runtime generation, distinguishing what is observed, what is inferred, and what
  remains unknown.
- A clear, quotable statement for the documentation: what a synchronization return
  value does and does not establish after a recovery, and what the harness must rely on
  instead.
- Host-side checks that a completion signal is self-produced and that liveness evidence
  spans the run, both demonstrated against a known-bad case (a simulated missing
  completion marker must be rejected).
- Any remaining physical-only questions stated as open questions rather than filled in
  by assumption.

## Acceptance criteria

- [ ] The runtime generation under discussion is named explicitly (ROCm version, and
      which runtime identity actually loaded).
- [ ] The behavior is described with a distinction between **observed**, **inferred**,
      and **unknown** — no unknown is presented as known.
- [ ] At least one host-side check exists that a run's completion signal is
      self-produced, and that check is demonstrated **rejecting** a case where the
      completion marker is absent while a runtime call reports success.
- [ ] The check is also demonstrated **accepting** a known-good case, so that it is not
      merely rejecting everything.
- [ ] Documentation states unambiguously that a synchronization return value after a
      recovery is not kernel output.
- [ ] No watchdog/TDR setting was modified to obtain any observation, and this is
      stated explicitly.
- [ ] [Current state](../current-state.md) is updated if the characterization changes
      what the project can claim.

## Related

- `01-candidate-f-physical-j3-non-completion.md` — the run this semantics question
  arises from.
- [Current state](../current-state.md) — the physical problem in context.
- [Evidence and reproducibility](../evidence-and-reproducibility.md) — why an exit code
  or a success message is not proof its output is right.
- [Glossary](../glossary.md) — watchdog/TDR, host-valid vs. hardware-valid.
