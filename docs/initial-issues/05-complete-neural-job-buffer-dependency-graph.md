# Build complete neural-job buffer dependency graph

> Draft for supervisor review. Do not open automatically.

**Title:** Build complete neural-job buffer dependency graph

**Suggested labels:** `host-only`, `analysis`, `neural-job`, `research`

**Evidence level:** targets `HOST_STATIC`. Host-only; no GPU required.

---

## Context

The project studies a neural-rendering workload, but the work so far has necessarily
been *local*: individual kernels, individual entry contracts, individual instruction
forms. What does not yet exist is a **complete picture of the job as a whole** — which
buffers exist, which kernels read and write which of them, and in what order the
dependencies force them to run.

That gap has a direct cost. Without a job-level dependency graph:

- The project cannot state what a "complete neural job" (proof-ladder rung 6) would
  even consist of, which makes rung 6 a label rather than a target.
- A local result cannot be placed: a kernel that validates in isolation may be
  irrelevant, or may be the one that matters, and there is no way to tell.
- Interoperability requirements (issue 06) cannot be scoped, because they depend on
  what memory must be shared and when.
- Any future attempt to assemble the job would be done blind, discovering the
  dependency structure by trial.

This is a **host-side static analysis task**. It requires no GPU and produces no
physical claim. It is one of the highest-value host-side tasks available, because it
converts an open-ended research area into a concrete structure that other work can
attach to.

## What is needed

- A **buffer inventory** for the job: each buffer identified (size, element type,
  alignment, and its role — input, intermediate, output, or persistent state), with how
  each identity was determined recorded.
- A **read/write map**: for each kernel in the job, which buffers it reads and which it
  writes. Sources for this are the kernarg layouts (`tools/p16g_kernarg.py`), the
  decoded instruction stream, and the descriptor/resource information already
  characterized host-side.
- A **dependency graph**: an ordering derived from the read/write map (a kernel that
  reads a buffer depends on whatever writes it), stated explicitly as edges rather than
  as a list.
- **Explicit unknowns.** Every place where the map is inferred rather than established
  must be marked as such, with what would settle it. A dependency graph with silent
  guesses is worse than one with visible gaps, because the guesses will be treated as
  facts by later work.
- **A checkable representation.** A machine-readable artifact (the project's `tools/`
  directory has precedent for structured outputs) so that later checks can be run
  against it — for example, verifying that a proposed execution order respects every
  edge.
- **A negative check.** A check over the graph that can fail: for instance, a proposed
  ordering that violates an edge must be rejected.

Out of scope: executing the job, assembling it on a device, or claiming completion.
This issue produces a *description* of the job, which is a rung-1/rung-2 artifact.

## What a good resolution looks like

- A buffer inventory and a read/write map covering the job, with the derivation of each
  entry traceable to a source (which tool, which artifact, which field).
- A dependency graph as explicit edges, with the acyclic structure either demonstrated
  or its cycles documented as findings.
- A machine-readable form of the graph, plus at least one check over it that has been
  shown to reject a violating input.
- An explicit list of what could not be determined host-side, framed as questions with
  a means of resolution rather than as assumptions.
- A bridge from the graph to the ladder: a concrete definition of what rung 6
  ("complete neural job") would mean for *this* job, expressed in terms of the graph.

## Acceptance criteria

- [ ] Every buffer in the inventory has an identified size and role, or is explicitly
      marked unknown with the reason.
- [ ] Every kernel in the job has a read set and a write set, or is explicitly marked
      incomplete.
- [ ] The dependency graph is expressed as edges, not as an implied order.
- [ ] Each edge is marked as **established** or **inferred**, and inferred edges state
      what would establish them.
- [ ] A machine-readable artifact of the graph exists, and its schema is documented.
- [ ] At least one check over the graph is demonstrated **rejecting** a deliberately
      violating ordering, and **accepting** a known-good ordering.
- [ ] The definition of rung 6 for this job is written in terms of the graph, so that
      "complete neural job" becomes falsifiable rather than aspirational.
- [ ] The write-up states that no device was used, and keeps all claims labelled as
      host evidence.
- [ ] [Current state](../current-state.md) is updated: at minimum, the "complete neural
      job: not qualified" row should reference this structure once it exists.

## Related

- `06-d3d12-hip-interoperability-requirements.md` — the interop requirements depend on
  what must be shared and when, which this graph supplies.
- `01-candidate-f-physical-j3-non-completion.md` — the physical problem; placing the
  Candidate-F case within the job graph is one way to judge how much it represents.
- [Architecture](../architecture.md) — the decode path and utilities this builds on.
- [Glossary](../glossary.md) — kernarg, descriptor, dispatch, rung.
