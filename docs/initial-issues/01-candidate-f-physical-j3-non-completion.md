# Localize Candidate-F physical J3 non-completion

> Draft for supervisor review. Do not open automatically.

**Title:** Localize Candidate-F physical J3 non-completion

**Suggested labels:** `physical`, `gfx1030`, `needs-authorization`, `diagnostics`,
`blocked`

**Evidence level:** `PHYSICAL_DIAGNOSTIC` (current). Target on resolution:
`PHYSICAL_ONE_WORKGROUP` if the workgroup completes, or a documented negative result
with the eliminated space narrowed further — either outcome is a real result.

---

## Context

This is the project's live blocker.

A correctly parameterized **one-workgroup** ("Candidate F") `gfx1030` translation
reaches the physical HIP runtime. The dispatch is **accepted at launch** — the runtime
does not reject it — but the kernel **does not complete**. The Windows GPU watchdog
eventually recovers the engine.

Host-side validation has already eliminated a substantial space of candidate causes:

- descriptor layout,
- barrier placement,
- `waitcnt` placement,
- argument (kernarg) layout,
- address layout.

Those checks were performed host-side and are not currently the leading explanation.
The remaining problem has been narrowed to **physical kernel liveness**: something
about the kernel as it actually runs on the device, rather than about the host-side
description of it.

Two things make this task easy to get wrong:

1. **Non-completion is not a clear error.** The launch succeeds, so there is no
   rejection to read. The observable is the absence of completion plus a host-side
   recovery event.
2. **The post-recovery host signal is misleading.** A synchronization call can return
   *without reporting an error* after the recovery. That return value is not kernel
   output and not evidence of success. See issue 03.

## What is needed

A **bounded checkpoint** approach: instead of re-running the whole case, make partial
progress observable so the point of non-completion can be localized.

Concretely:

- Add bounded checkpoints to the existing harness so that identifiable progress
  markers are produced at defined points during execution, and the last marker
  observed is informative.
- Keep each run **one-shot and bounded**: one case per authorization, no loops, no
  automatic retries, no escalation.
- Design each diagnostic so it can fail, and demonstrate it against a case whose
  outcome is already known before trusting a "clean" result.
- Distinguish, for any observed stall, whether it is **synchronization-related** or
  **liveness-related**, and state the evidence for the distinction rather than the
  conclusion alone.
- Preserve raw output as produced. Keep the preflight record and the run record
  together.

Out of scope for this issue: any change to watchdog/TDR settings, clocks, voltages,
power limits, firmware, BIOS, registry, or drivers. Those are prohibited by the
project's hardware safety policy and would also invalidate the interpretation of any
result.

## What a good resolution looks like

One of the following, with raw evidence preserved:

1. **Localized.** A specific execution region or checkpoint boundary is identified as
   the point after which no progress is observed, with the evidence that localizes it
   and the reasoning that rules out the checkpoints before it.
2. **Completed.** The one-workgroup case completes, and the change that made it
   complete is understood — not merely observed to help. A change that reduces the
   symptom is not proof it has explained the cause.
3. **Narrowed further, with a documented negative.** Several additional hypotheses are
   eliminated with explicit negative evidence, leaving a smaller space. This is a
   legitimate outcome and should be recorded as such rather than treated as failure.

In all three cases, update [current state](../current-state.md) with the new evidence
level and label it at the level actually established.

## Acceptance criteria

- [ ] A bounded checkpoint mechanism exists in the harness, and each checkpoint's
      presence in the output is demonstrated on a case where it *is* reached.
- [ ] The diagnostic is shown **able to fail**: it produces a distinguishable outcome
      on a known-bad case.
- [ ] At least one bounded physical run has been performed **under explicit
      authorization**, one-shot, with no automatic retry.
- [ ] The raw output of that run is preserved and referenced from the issue, together
      with the preflight record for the same run.
- [ ] Any stall is classified as synchronization-related or liveness-related, with the
      evidence for the classification stated.
- [ ] Host evidence and physical evidence are kept distinct in the write-up; no host
      result is presented as bearing on device behavior.
- [ ] No watchdog/TDR, clock, voltage, power, firmware, BIOS, registry, or driver
      setting was changed; this is stated explicitly in the resolution.
- [ ] [Current state](../current-state.md) is updated with the outcome and an
      appropriate evidence label, at the level actually established.

## Related

- `03-rocm-post-watchdog-synchronization-semantics.md` — interpreting the host-side
  signal after recovery.
- `02-independent-review-executed-gfx1030-instruction-forms.md` — independent review of
  the instruction forms, which is the host-side complement to this work.
- [Current state](../current-state.md), [architecture](../architecture.md),
  [hardware testing policy](../hardware-testing-policy.md).
