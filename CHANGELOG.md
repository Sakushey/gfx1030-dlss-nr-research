# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1-dev-preview] - unreleased

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
