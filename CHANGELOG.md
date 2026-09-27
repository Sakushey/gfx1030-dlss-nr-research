# Changelog

## Unreleased — Phase 16BO / A8C6 state sync

- Canonical project state advanced through an authentic host core frame, representative gfx1030 family qualification, a complete standalone gfx1030 core frame, GTA source capture, captured-frame offline replay, and two distinct matched GTA neural-frame presentations.
- REAL implementation admission is treated as load-bearing for the production executor; unadmitted production resolution fails closed.
- Graph weights advanced to 73/73 applied, including the authenticated 263,168-byte `block30.layer3.layer` view for `t_w_conv_res_views`.
- C1024/ViT state now uses the locally established scale-first contract and an exact QKV record view/packing rather than the coarse aggregate.
- Decoder skips are fixed to authenticated transition outputs 4/8/14/22.
- Core TensorSpecs/addition semantics are separated from game-boundary/auxiliary semantics; the Rec.709 `mean` leaf no longer acts as a fake core blocker.
- The old Candidate-F/J3 watchdog-localization track remains preserved as historical evidence but is no longer the live project blocker.
- The first correctness transport deliberately uses explicit CPU staging between D3D12 and HIP; zero-copy is not claimed.
- Warm temporal correctness, sustained gameplay, direct zero-copy interop and performance remain separate future qualifications.
- Public documentation now distinguishes canonical project state from the subset of raw evidence that can be safely published.


All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

* **Citation metadata** — `CITATION.cff` (CFF 1.2.0) so the research software can
  be cited.
* **CI dependency manifest** — `requirements-ci.txt` pins the CI validation
  tooling, tracked by Dependabot for `pip` alongside the existing
  `github-actions` updates.

### Changed

* **Publication sync freshness is now two-dimensional** — the sync helper
  detects authoritative-status drift (an optional read-only fingerprint of the
  private session report) in addition to mapped-implementation drift, so
  "no mapped file changed" no longer reads as "the public project is current".
  The fingerprint is stored local-only under the public repository's `.git`.
* **Publication apply is branch-guarded and transactional** — `--apply` is
  refused outside a `publication-sync/*` branch, and a failing publication
  verifier now rolls the mirror back completely instead of leaving a
  half-applied tree.
* **GitHub Actions supply chain hardening** — workflow actions are pinned to
  full commit SHAs, checkouts that do not need to push use
  `persist-credentials: false`, and each workflow has a concurrency group and a
  job timeout.
* **Public research status refreshed** — the headline physical state now
  reflects the latest completed checkpoint diagnostic and its narrowed search
  interval.

### Fixed

* **Publication sync no longer reports a false blocker.** Three approved mapped
  `.bat` tooling files were published but the helper refused `.bat` as a
  sync-eligible suffix, which made every end-of-session check report a block
  with zero real drift. A host-only regression now asserts that every mapped
  suffix is sync-eligible, so the helper cannot ship that gap again.

## [0.0.1-dev-preview] - 2026-09-20

### Added

* **Host semantic emulator** — a host-side instruction emulator that executes
  translated kernel semantics without touching physical hardware.
* **Independent scalar ISA oracle** — a separate scalar reference model, built
  independently of the emulator, used to cross-check host results so that a
  failure of the emulator does not silently become the reference.
* **HIP bridge / interop tooling** — tooling that carries a translated candidate
  toward the HIP runtime.
* **Host harnesses** — harnesses that drive the emulator and oracle over the
  project's test corpus on the host.
* **Host-side analysis utilities** — utilities for inspecting translated code
  objects, kernel arguments, and the evidence produced by the above.
* **Bounded gfx1030 soft-WMMA test program** — a bounded one-shot physical test
  program exercising a soft-WMMA path on gfx1030-class hardware, run under the
  project's hardware safety policy.
* **Publication and audit scaffolding** — the tooling and structure used to
  publish artifacts and to audit what is published (allowlist-based publication
  control, evidence manifests, and the checks that guard them).
