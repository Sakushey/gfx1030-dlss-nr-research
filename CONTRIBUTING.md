# Contributing

Thanks for your interest. This is an independent, unofficial research project
investigating whether DLSS Neural Rendering (DLSS-NR) GPU workloads can be
translated from NVIDIA-targeted code objects to AMD RDNA2 / Navi21-class
gfx1030 hardware (e.g. RX 6950 XT), validated on the host, and executed on real
hardware under bounded conditions.

This project is not affiliated with, endorsed by, or supported by NVIDIA, AMD,
Rockstar Games, Take-Two Interactive, or any third-party mod or project
referenced by the research.

Because the project makes claims about hardware behaviour, contributions are
held to an evidence standard. The rules below are not bureaucracy; they exist
because a claim that outruns its evidence is the single most damaging thing that
can enter this repository.

## Every contribution must state

Open a pull request and fill in the template. At minimum, every contribution
must state:

1. **What changed.** The concrete change, in files and in behaviour.
2. **Why.** The reason for the change, and what problem it solves.
3. **Proof layer affected.** Which rung of the proof ladder (below) this change
   touches, and whether it moves a claim up a rung, holds it in place, or
   corrects a claim that was too high.
4. **Evidence.** The artifacts, logs, hashes, or reasoning that support the
   change. A claim without evidence is a proposal, not a result.
5. **Tests run.** Which tests were executed and what the outcome was. If no
   test was run, say so explicitly rather than leaving it implied.
6. **Negative controls where meaningful.** A check that cannot fail proves
   nothing. Where a change adds or alters a verifier, show that the verifier
   rejects a known-bad input, and that it accepts a known-good one.
7. **Host vs physical classification.** Say plainly whether the evidence is
   host-side or comes from physical hardware, and do not blur the two.

## The proof ladder

Each rung is stricter than the one before it. **Passing one rung never implies
the next.** A contribution that demonstrates a higher rung without the lower
ones being satisfied is not a valid result.

Host static correctness -> Host dynamic / independent oracle -> One-workgroup
physical -> Multi-workgroup -> Authentic full dispatch -> Complete neural job ->
D3D12/HIP interop -> Presented frame -> Temporal stability -> Sustained gameplay
-> Performance.

## Evidence labels

Contributors must classify every claim at the highest level **actually**
established. Do not round up.

* `PROPOSED` — an idea, design, or hypothesis. No execution.
* `HOST_STATIC` — static reasoning or analysis over artifacts; no execution.
* `HOST_VALIDATED` — executed on the host against the project's own model.
* `HOST_INDEPENDENT_ORACLE` — executed on the host and checked against an
  independent reference that was not derived from the thing under test.
* `PHYSICAL_DIAGNOSTIC` — physical hardware was exercised for diagnosis only;
  this is **not** kernel output and does not qualify a kernel.
* `PHYSICAL_ONE_WORKGROUP` — a single-workgroup kernel reached and completed on
  physical hardware.
* `PHYSICAL_MULTI_WORKGROUP` — a multi-workgroup kernel completed on physical
  hardware.
* `COMPLETE_JOB` — the authentic full dispatch completed.
* `INTEROP` — D3D12/HIP interop demonstrated.
* `PRESENTED_FRAME` — a frame was presented.
* `TEMPORAL` — behaviour holds across time (multiple frames / frames in
  sequence).
* `PERFORMANCE` — performance was measured meaningfully.

Note in particular that **driver-reset output is not kernel output**, and
**host evidence is not physical qualification**.

## Prohibited contributions

Do **not** submit any of the following. Pull requests containing them will be
closed, and the material will not be merged.

* **Proprietary game binaries**, in whole or in part, in any form.
* **NVIDIA binary assets** — code objects, fatbins, libraries, blobs, or
  extracted contents of the same, regardless of how they were obtained.
* **AMD runtime DLLs** or other redistributable-restricted vendor runtime
  binaries.
* **Copied commercial mod binaries** or the contents of third-party mod
  packages.
* **Credentials** — API keys, tokens, passwords, private keys, or anything of
  the kind.
* **Crash dumps containing personal or system data** — memory dumps, minidumps,
  WER reports, or logs that embed hostnames, usernames, filesystem paths,
  machine identifiers, or other system or personal information.

If a contribution needs to refer to such an artifact, refer to it by identity
(hash, size, structure) rather than including it.

## Hardware safety policy

The project enforces a bounded physical-experiment policy. Contributions must
not weaken it:

* bounded one-shot physical experiments;
* no automatic retries;
* no watchdog / TDR modification;
* no clock, voltage, or power tricks;
* preserve raw evidence;
* preflight first;
* driver-reset output is not kernel output;
* host evidence is not physical qualification;
* physical tests only when explicitly authorized.

A pull request that introduces automatic retry of a physical test, modifies
watchdog behaviour, or presents a recovered-from-reset run as a success will be
rejected.

## Pull request checkboxes

The pull request template asks you to confirm:

* No proprietary artifacts added
* No credentials or personal data added
* Evidence level is stated
* Tests were run
* Negative control added where appropriate
* No frozen reference was silently changed
* Physical-support claims do not exceed evidence

Do not check a box you cannot honestly stand behind.

## Legal and licensing

By contributing, you confirm you have the right to submit the material and that
it contains nothing you do not have the right to license. Do not claim copyright
ownership of anything third-party, and do not include third-party copyrighted
material that is not compatibly licensed.
