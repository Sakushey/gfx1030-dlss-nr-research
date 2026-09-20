# Validate on a second Navi21/gfx1030 device

> Draft for supervisor review. Do not open automatically.

**Title:** Validate on a second Navi21/gfx1030 device

**Suggested labels:** `physical`, `gfx1030`, `needs-authorization`, `hardware-variance`

**Evidence level:** `PHYSICAL_DIAGNOSTIC` (current baseline is
`PHYSICAL_DIAGNOSTIC`). Target: confirm the bounded observation reproduces, or document
that it does not.

---

## Context

Every physical observation in this project so far comes from **one** device. That is a
real limitation, and it has a specific consequence for the current blocker: the project
cannot currently distinguish between

- a property of **this device** — its particular state, its driver installation, its
  thermal or power situation, its position on some manufacturing distribution, and
- a property of **`gfx1030` / Navi21** as a target.

Those lead to very different conclusions. If the one-workgroup non-completion is
specific to this device, then the research is chasing a local fault. If it reproduces
identically on a second device, the finding is about the target, and the project's
reasoning about host-side elimination becomes much better grounded.

There is a second reason this matters. "Navi21" is a hardware family, not a single
part, and the `gfx1030` target covers more than one SKU. Behaviors that hold on one
part are not automatically properties of the family. The honest way to say that is to
test it.

This issue is **bounded and one-shot**, exactly like every other physical experiment in
this project. It does not require the second device to succeed; a difference is a
finding, and so is an exact match.

## What is needed

- **A second Navi21 / `gfx1030` device** — a different physical card from the one used
  so far, ideally a different SKU or a different system.
- **The same bounded procedure**, run once, on that device:
  - the documented preflight (`scripts/run_test.ps1` performs a device preflight and
    refuses to continue if the device does not report `gfx1030`),
  - the bounded one-workgroup case, run one-shot with **no automatic retry**.
- **Record the differences that could matter**, without changing any of them: device
  SKU, driver version, runtime version and identity, OS build. Record them as observed
  facts rather than adjusting anything to match.
- **A comparison of the outcomes**, stated at the level of the *observation* — did the
  bounded case reach the same point, produce the same output, and fail to complete in
  the same way? Compare per observable, not by summary.
- **Environment caveat to check:** in this project's environment, ROCm **6.4**
  enumerates `gfx1030` and ROCm 7.1 does not. Confirm which runtime generation is
  active on the second machine before interpreting anything, and record it.

Out of scope, and prohibited: any change to watchdog/TDR settings, clocks, voltages,
power limits, firmware, BIOS, registry, or drivers — on either device, and in particular
any attempt to "make the second device behave like the first".

## What a good resolution looks like

One of:

1. **Reproduced.** The bounded case behaves the same on the second device, and this is
   recorded with the observed facts for both devices side by side. This strengthens the
   conclusion that the finding is about the target rather than the machine.
2. **Diverged.** The bounded case behaves differently, and the difference is described
   precisely: at which point, in what observable, and in what way. This is a valuable
   result — it means device-specific factors are in play and the earlier reasoning needs
   revisiting — and it should be recorded as a finding rather than a failure.
3. **Not run.** The device or authorization was unavailable, recorded as an open item
   rather than quietly dropped.

In all cases, raw output from the second device is preserved as produced, alongside the
recorded environment facts.

## Acceptance criteria

- [ ] A second, physically distinct Navi21 / `gfx1030` device was used, and the fact
      that it is a different card from the original is stated.
- [ ] The device preflight reported `gfx1030` on the second device, and its output is
      preserved.
- [ ] The runtime generation and identity in use on the second device is **recorded**
      (ROCm version, and which runtime identity loaded), not assumed to match.
- [ ] The bounded case was run **one-shot**, with no automatic retry and no escalation.
- [ ] Raw output from the second device is preserved as produced.
- [ ] The comparison between the two devices is stated per observable, not as a single
      summary verdict; any observables that differ are called out individually.
- [ ] Observed environment differences (SKU, driver, runtime, OS build) are recorded
      without modifying anything to align them.
- [ ] The outcome is classified as reproduced / diverged / not run, and the evidence
      label is set at the level actually established.
- [ ] No watchdog/TDR, clock, voltage, power, firmware, BIOS, registry, or driver
      setting was changed on either device, and this is stated explicitly.
- [ ] [Current state](../current-state.md) is updated to reflect either the second-device
      confirmation or the divergence.

## Related

- `01-candidate-f-physical-j3-non-completion.md` — the case being reproduced.
- `03-rocm-post-watchdog-synchronization-semantics.md` — interpreting the host-side
  signal after recovery, which applies identically here.
- [Current state](../current-state.md) — the current single-device basis for all
  physical claims.
- [Hardware testing policy](../hardware-testing-policy.md) — the rules this run must
  follow.
- [Glossary](../glossary.md) — gfx1030, Navi21, RDNA2, watchdog/TDR.
