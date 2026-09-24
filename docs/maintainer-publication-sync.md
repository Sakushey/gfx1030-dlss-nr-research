# Maintainer publication sync

The private research tree and public repository are separate. The public
repository receives only reviewed files inside its publication scope; private
session reports, local state, raw captures, weights, binaries, credentials, and
machine-specific paths remain private.

## Session-end path

The project Claude Code Stop hook invokes the canonical publication
orchestrator. The hook does not run Git operations itself. The orchestrator
waits for source writers to become quiescent, takes the publication lock,
checks the current source fingerprint, and runs a publication dry-run. If the
gates pass, the canonical publisher prepares an isolated candidate from a
freshly fetched live `main` and verifies the exact base SHA before applying
reviewed additions. The additions record binds the sanitized current-state
review to the exact private report fingerprint and names the public summary
surfaces that were reviewed. The publisher copies that review state only into
the disposable candidate's local Git metadata; it never publishes the private
report or the review marker.

The publisher runs the phase-current manifest-v2 verifier and C1–C4 controls,
host tests and build checks, privacy/secrets scans, proprietary-artifact scans,
licensing/provenance checks, and a deterministic public render. It stages only
the explicit publication scope. The private working tree is never treated as
a Git repository or recursively copied to the public candidate.

If ready, the publisher creates one fresh phase branch, uses the maintainer's
GitHub noreply identity, pushes normally, creates a PR for that exact branch,
and verifies the remote SHA and the PR's GitHub Actions runs. It never force
pushes, revives PR #17, or merges. Issue #42 remains the final identity/privacy
review gate for controlled merge decisions.

The Stop hook itself records only the publisher's verified session result in
`PUBLICATION_SESSION_STATUS.json`. A substantive session is complete only
when that record matches the current source fingerprint. Outcomes are
`PUBLISHED`, `NO_PUBLIC_DELTA`, or `PUBLICATION_BLOCKED(<specific reason>)`.

## Publication boundaries

- Use freshly fetched live `main`; reject a candidate if its bound base SHA has
  moved.
- Copy only explicit project files with current provenance and license
  evidence. New files require an approved mapping; generated tree inventories
  must match the actual candidate in both directions.
- Keep workflows labelled **DEFINED_NOT_PROVEN** until real GitHub Actions
  runs are observed for the exact PR head SHA.
- Do not change repository rules, contributors, issues, or required checks as
  part of local publication.
- Stop after the branch, PR, remote SHA, and Actions verification. Review,
  issue management, contributor coordination, and merge decisions belong to
  the external Steward.
