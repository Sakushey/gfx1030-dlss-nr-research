# Hardware testing policy

This policy is not advisory. Physical experiments that do not follow it
are not accepted as evidence.

## Principles

- **Bounded one-shot experiments.** One question per run. A run that
  changes two things cannot attribute its outcome to either.
- **No automatic retries.** A retry after a GPU reset produces no new
  information and repeatedly resets the engine.
- **No watchdog or TDR modification.** Not by registry, not by registry
  policy, not by driver setting, not temporarily.
- **No clock, voltage, or power-limit changes.** Not as an experiment, not
  as a workaround.
- **No firmware, BIOS, registry, or driver modification.**
- **No installations.** Nothing on the target machine changes outside the
  project directory.
- **Preserve raw evidence.** Summaries are derived. Raw output is the
  evidence. Keep the raw form and record the artifact identity.
- **Preflight first.** Confirm the device, the runtime, and the artifact
  identity *before* dispatching anything.
- **Only run physical tests when explicitly authorized.** "It would be
  interesting to know" is not authorization.

## Hard rules

1. **Driver-reset output is not kernel output.**
   If the watchdog recovered the engine, the kernel did not complete.
   Output captured after a reset cannot be attributed to the workload.

2. **A synchronization call returning success is not kernel success.**
   A watchdog recovery can unblock a synchronization call and let it
   return "no error". Treat a post-reset success as uninformative unless
   corroborated by evidence that the kernel itself produced output.

3. **Host evidence is not physical qualification.**
   Agreement under the host model never promotes a claim to a physical
   rung. See [proof-model.md](proof-model.md).

4. **The authorization checkbox is real.**
   Hardware-result reports must answer explicitly whether watchdog/TDR
   settings were modified. A "yes" disqualifies the result — it is not a
   caveat.

## What a physical experiment looks like

```
preflight          device present, runtime enumerates the target,
                   artifact identity recorded by content hash
    |
    v
one dispatch       bounded geometry, single configuration
    |
    v
raw capture        unmodified output preserved, with timestamps
    |
    v
classification     labelled PHYSICAL_DIAGNOSTIC or higher,
                   or explicitly labelled as inconclusive
```

If the engine resets, the experiment **ends**. It is recorded as a reset,
not retried. The result is classified at most `PHYSICAL_DIAGNOSTIC`
unless a completion is independently corroborated.

## Reporting a hardware result

Use the hardware test result issue form. It asks for GPU, architecture,
driver and runtime versions, candidate and harness identity, geometry,
whether a watchdog reset occurred, whether watchdog/TDR settings were
modified, and the evidence level.

Results that do not state these are not actionable and will be closed
pending the missing information.

## Why this is strict

The failure mode this policy prevents is a project talking itself into a
result. A kernel that resets the engine, combined with a synchronization
call that returns success, looks exactly like a passing test to anyone who
checks only the return code. That is how a project reports progress it
does not have.


## Phase 16BK authorization and result fields

The current recorded physical-launch allowance is 5 authorized, 5 spent, and
0 remaining. Any further project-local GPU launch requires a new explicit
authorization tied to a bounded operation, target, completion event, and stop
condition. The current hardware claim remains limited to one source-built
 decoder-transition operation with narrow gfx1030 validation.

A hardware result must record the exact tested object SHA-256, target/device
architecture, public-safe authorization identity or reference, approved scope,
completion mechanism and event, sentinel result, written-set result, guard
result, immutability result, numerical comparison count, reset/device-loss
state, and architecture-override state. Use a role or public-safe authorization
reference rather than personal contact details. Do not attach proprietary
artifacts, captures, raw session reports, credentials, local settings, or
personal filesystem paths; identify restricted evidence only by a public-safe
reference when appropriate.
