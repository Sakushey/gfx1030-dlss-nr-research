# Public Changelog

Changes that reached this public repository, newest first. This branch is
generated from a curated export of the private working tree; it is not a mirror of
it, and it does not carry the private tree's history.

## publication-sync/post-astra4-16az-clean-20260922

*Cut from `main` rather than from any earlier publication branch, so the branch's
tip carries no inherited identity.* See `PUBLIC_STATE.json` for the current
position and `PUBLIC_ROADMAP.md` for the track state.

* Added a machine-readable public state surface (`PUBLIC_STATE.json`) and its
  narrative companions (`PUBLIC_ROADMAP.md`, `PUBLIC_SOURCE_GROUNDING_REGISTER.md`,
  `PUBLIC_CHANGELOG.md`), so the current project position can be read from the
  public repository alone.
* Forward fix for a private path that was present in `src/bridge/bridge_config.h`
  in this branch's base. The file is the test-only branch of a compile-time
  constant; the fix substitutes a placeholder token. **This is a forward fix, not
  a history rewrite** — the bytes remain in already-pushed history, which is
  stated rather than hidden.
* Updated the published host-side tooling and documentation.

## What a changelog entry here does and does not mean

An entry means the change reached the public repository. It is not a claim that
the change is correct, complete, or that it establishes anything about `gfx1030`.
Evidence levels are in [`STATUS.md`](STATUS.md) and
[`docs/evidence-and-reproducibility.md`](docs/evidence-and-reproducibility.md).
