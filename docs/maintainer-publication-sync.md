# Maintainer publication-sync protocol

The public repository is a curated mirror, not a checkout of the private research tree. Keeping it current must never weaken that separation.

Core rule: **detect automatically; publish deliberately.** A completed coding session must never itself imply a public push.

## Stage A — automatic end-of-session check

After a successful development session, the coding agent may run the sync helper in its default read-only mode:

    python C:\path\to\gfx1030-dlss-nr-research\scripts\prepare_publication_sync.py --source-root C:\path\to\private-project

This check reads only private files that already have an explicit source_path -> public_path mapping in audit/PUBLICATION_MANIFEST.json. It does not discover new files, copy anything, commit, push, create a PR, or change repository settings.

Summarize the result as one of:

- PUBLICATION_SYNC_NONE
- PUBLICATION_SYNC_PENDING
- PUBLICATION_SYNC_BLOCKED

Do not paste private absolute paths, secret-like values, crash dumps, raw session reports, or machine-specific evidence into model context.

## Stage B — explicit publication preparation

Run apply mode only after the user or supervisor explicitly asks to refresh the public repository, or when a standing project-specific instruction explicitly authorizes publication preparation.

Preconditions:

- the research session is at a stable checkpoint;
- no concurrent process is writing a mapped source file;
- the public checkout is clean and fast-forwarded to origin/main;
- the private source tree remains read-only.

Then run:

    python scripts\prepare_publication_sync.py --source-root C:\path\to\private-project --apply

Apply mode may update only files already approved in the manifest. It updates their recorded hashes/sizes and runs the publication verifier. It does not discover new files, edit status prose, commit, push, or merge.

## Stage C — curated status refresh

Implementation sync and project-state sync are separate. After mapped files are refreshed, update public status only from the latest authoritative completed evidence.

Normally review:

- README.md only when the headline state changed;
- STATUS.md;
- ROADMAP.md;
- docs/current-state.md;
- release notes only when a release is actually being prepared.

Never copy the raw private SESSION_REPORT.md. Summarize only supported claims at the correct proof-ladder rung. Exclude private paths, provider/API configuration, raw dumps, internal agent/supervisor material, and proprietary-derived evidence.

Use cautious language: a host check can weaken a hypothesis without eliminating every hardware-specific version of it.

## Stage D — branch, CI, PR, merge

1. Inspect git diff --stat and git diff.
2. Run python scripts/verify_publication.py.
3. Run python -m unittest discover -s tests/host -t tests/host.
4. Create a branch named publication-sync/YYYYMMDD-HHMM.
5. Commit with the repository-local no-reply identity.
6. Push the branch normally. Never force-push.
7. Open a PR to main.
8. Require both Host-only checks and Tracked-tree audit to pass.
9. Review the publication diff before merge.
10. Merge through the PR; never let an agent push directly to main.
11. Fast-forward the local public checkout to origin/main afterward.

## Existing mapped files vs. new files

An existing manifest mapping may be refreshed automatically by the helper if its publication category and transform remain approved.

A new private file is never automatically published. Before adding one:

1. classify it using the publication taxonomy;
2. establish ownership/provenance and license;
3. inspect for proprietary-derived content;
4. scan for secrets and personal/machine-specific data;
5. decide whether publishing it is actually useful;
6. add it to the manifest only after that review.

Default when uncertain: **exclude**.

## What may be automatic

Safe automatic behavior:

- the read-only mapped-file check;
- reporting that a public refresh is pending;
- writing a small status marker inside an already-approved project-private state location, if the local agent setup uses one.

Unsafe automatic behavior:

- copying newly discovered private files;
- committing;
- pushing;
- opening or merging a PR;
- changing repository visibility;
- creating a release.

Those remain explicit publication operations.

## Concurrency and history rules

- If research jobs are still writing mapped private files, apply mode waits.
- No force push.
- No ordinary rewrite of established public history.
- No direct push to main from an agent.
- If a secret or sensitive artifact ever reaches public history, stop and treat it as an incident; a normal deletion commit is not assumed to erase exposure.

## Minimal recurring gate

Before each publication PR require:

- public checkout synced and clean;
- mapped-source sync applied;
- new files explicitly reviewed;
- public state documents current;
- secret scan clean;
- privacy scan clean;
- provenance/license clean;
- host tests pass;
- publication audit passes;
- no proprietary binaries or raw private evidence;
- branch + PR only;
- CI green before merge.

The cost of missing one public update is small; the cost of automatically publishing a private artifact is not.