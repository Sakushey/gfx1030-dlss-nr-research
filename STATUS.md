# Status

Authoritative current state of the project. If this file disagrees with any
other document, this file wins.

Last reviewed: 2026-09-20

---

## One-line summary

Host-side semantic validation of a gfx1030 DLSS-NR translation is
substantially developed; **physical kernel liveness on gfx1030 is the
current blocker**, and no end-to-end neural frame has been demonstrated.

## Ladder position

```
 1. Host static correctness ................. demonstrated
 2. Host dynamic / independent oracle ....... demonstrated (partial coverage)
 3. One-workgroup physical .................. LAUNCHES, DOES NOT COMPLETE
 4. Multi-workgroup ......................... not reached
 5. Authentic full dispatch ................. not reached
 6. Complete neural job ..................... not reached
 7. D3D12 / HIP interop ..................... not reached
 8. Presented frame ......................... not reached
 9. Temporal stability ...................... not reached
10. Sustained gameplay ...................... not reached
11. Performance ............................. not applicable yet
```

Rung 3 is where the project is stuck, and it is a *physical* rung. Nothing
above it can be claimed, and nothing at rung 1 or 2 substitutes for it.

## Component status

| Component | State | Evidence ceiling it can reach |
| --- | --- | --- |
| Host instruction emulator (`src/emulator/`) | advanced experimental | `HOST_VALIDATED` |
| Independent scalar ISA oracle (`src/oracle/`) | experimental, partial ISA coverage | `HOST_INDEPENDENT_ORACLE` |
| ISA decode / rebuild (`src/isa/`) | active development | `HOST_STATIC` |
| HIP bridge + ABI probes (`src/bridge/`) | works host-side against a mock backend | `HOST_VALIDATED` |
| Bounded physical harnesses (`src/harness/`) | reach the runtime; kernel does not complete | `PHYSICAL_DIAGNOSTIC` |
| Host analysis utilities (`tools/`) | usable | `HOST_STATIC` |
| Bounded gfx1030 test program (`tests/`) | the only GPU-touching code | `PHYSICAL_ONE_WORKGROUP` |

## The current physical problem

A correctly parameterized **one-workgroup** gfx1030 translation reaches the
physical HIP runtime but does not complete before the Windows GPU watchdog
recovers the engine.

Host-side descriptor, argument, address-layout, barrier, and waitcnt
checks pass on the modeled path. The failure is therefore being treated
as a **physical kernel-liveness** problem, without assuming those host
checks can rule out every hardware-specific synchronization or model-
fidelity defect.

The latest authorized midpoint checkpoint diagnostic also triggered a
watchdog recovery. It narrows the first physical failure to the **first
~55.6% of modeled one-workgroup execution**. No exact failing instruction
or mechanism has been established yet.

Work is focused on **bounded checkpoint diagnostics rather than blind
retries**. Retrying a watchdog-reset kernel without a new hypothesis
produces no information and repeatedly resets the engine.

### What "watchdog recovered the engine" implies

When the Windows GPU watchdog recovers the engine, a synchronization call
can return success even though the kernel never completed. **Sync success is
not kernel success.** Treat any post-reset "no error" result as
uninformative unless it is corroborated by evidence that the kernel itself
produced output.

## Explicit non-claims

The project does **not** claim, and must not be described as claiming:

- that DLSS-NR runs on gfx1030;
- that any game frame has been produced;
- that host-validated behaviour implies hardware-valid behaviour;
- that the host emulator is a complete or formally verified gfx1030 model;
- that the bridge makes any proprietary workload work.

## Immediate next steps

1. Continue bounded bisection of the one-workgroup non-completion
   ([issue #2](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/2)).
2. Independently review the dynamically executed gfx1030 instruction
   forms ([issue #3](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/3)).
3. Characterize post-watchdog ROCm synchronization semantics
   ([issue #4](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/4)).
4. Map D3D12/HIP interop requirements ahead of rung 7
   ([issue #7](https://github.com/Sakushey/gfx1030-dlss-nr-research/issues/7)).

See [ROADMAP.md](ROADMAP.md) for the milestone view and
[docs/current-state.md](docs/current-state.md) for detail.
