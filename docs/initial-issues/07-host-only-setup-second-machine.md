# Validate host-only setup on a second machine

> Draft for supervisor review. Do not open automatically.

**Title:** Validate host-only setup on a second machine

**Suggested labels:** `host-only`, `reproducibility`, `good-first-task`,
`documentation`

**Evidence level:** `HOST_STATIC`. Host-only; no GPU, no ROCm, no C++ toolchain
required.

---

## Context

The host-only tooling (emulator, oracle, ISA decode/rebuild, analysis utilities) is the
part of this project that is *supposed* to work anywhere. It should run on any machine
with a suitable Python, with no GPU, no ROCm, and no C++ toolchain.

That claim has never been tested on a machine other than the one it was developed on.
Until it is, several things are unknown:

- Whether the setup instructions are complete, or whether they silently assume
  something that happens to be true on the original machine.
- Whether the import arrangement actually works from a fresh checkout, or only from a
  tree with local artifacts present. The modules use a **flat import namespace** —
  `import emu`, `import p14d_kd` — resolved by a root-level `conftest.py` that puts every
  `src/*` directory on `sys.path`, or equivalently by setting `PYTHONPATH` to
  `src/emulator;src/isa;src/oracle` (Windows) or the colon-separated equivalent (POSIX).
  A fresh checkout is the only way to confirm that is sufficient.
- Whether the host tests pass from a clean checkout, or depend on something not
  committed.
- Whether the repository is actually free of anything machine-specific — a personal
  path, a local artifact, a cached file — which is both a reproducibility question and a
  publication question.

This is an excellent first contribution: it needs no GPU, it cannot damage anything, and
its success criterion is unambiguous.

## What is needed

- **A fresh checkout on a second machine** — a different machine from the one the
  project was developed on, ideally a different OS or Python minor version.
- **Run the documented host-only entry point:** `python -m unittest discover -s tests/host -t tests/host` from the
  repository root. Report the result exactly, including failures.
- **Verify the import namespace independently:** confirm that the bare-name imports
  resolve, both from the repository root and (separately) with `PYTHONPATH` set as
  documented. Test the two paths as distinct cases; the documented arrangement is
  supposed to support both.
- **Run the `tools/` utilities** that do not require a device, and report any that fail
  or that turn out to require something the documentation does not mention.
- **Report every deviation from the documentation**, however small: a missing
  prerequisite, a step that assumes a tool is present, a command whose behavior differs
  between shells, a version assumption.
- **Report anything that looks machine-specific** in the checkout — an absolute path,
  a personal detail, a binary artifact, a credential or token. This is a
  security-relevant finding, not just a tidiness issue; report it without quoting any
  sensitive value.

Out of scope: the HIP path, the physical experiment, and anything requiring a GPU. This
issue is specifically about proving the host-only claim on a machine that is not the
original.

## What a good resolution looks like

- Either the documented procedure works on a second machine, confirmed step by step —
  or it does not, and the specific deviations are recorded precisely enough to fix.
- Any documentation correction is made, or a precise correction is proposed (which
  prerequisite, which command, which expected-vs-actual).
- Any accidental machine-specific content found is reported, and if it is a credential
  or personal detail, reported privately rather than in a public issue comment.
- The result is recorded in a way that a *third* person could repeat, since the point is
  to establish that the setup is not machine-specific.

## Acceptance criteria

- [ ] A fresh checkout was performed on a machine that is not the original development
      machine, and this is stated (OS and Python version, without any personal or
      machine-identifying detail).
- [ ] `python -m unittest discover -s tests/host -t tests/host` was run from the repository root, with the outcome reported
      exactly — including any failures, with their output.
- [ ] The import namespace was verified **both** from the repository root and with
      `PYTHONPATH` set as documented, as two separate cases.
- [ ] Every deviation from the documentation is listed, with expected vs. actual
      behavior.
- [ ] The set of `tools/` utilities exercised without a device is listed, with outcomes.
- [ ] Any machine-specific, personal, or secret content found is reported without
      quoting the sensitive value itself.
- [ ] Documentation corrections are proposed or applied, and the result is reproducible
      by a third person from the record.
- [ ] No GPU was used, and no physical claim is made.

## Related

- [Build and setup](../build-and-setup.md) — the procedure under test.
- [Contribution areas](../contribution-areas.md) — the "Reproducibility / CI" and
  "Documentation" areas.
- [Evidence and reproducibility](../evidence-and-reproducibility.md) — why a reported
  success is not proof the output is right.
