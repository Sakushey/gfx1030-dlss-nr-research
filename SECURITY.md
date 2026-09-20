# Security Policy

## Scope

This repository is an independent, unofficial research project. Security
reports are welcome and are handled in the open where that is safe, and
privately where it is not.

## Reporting a non-sensitive issue

For ordinary, non-sensitive defects that have a security dimension but do not
expose anything secret or exploitable on their own, open a regular GitHub issue
using the **Bug report** form. Examples: a tool that mishandles a malformed
input file, an unchecked bounds condition in a host-side parser, a missing
validation in the host harnesses.

## Reporting a sensitive finding

If a finding is sensitive — a credential or token exposed in the tree, a
vulnerability that is exploitable against users of the tooling, or anything
whose public disclosure would cause harm before a fix exists — use GitHub's
private vulnerability reporting route on this repository if it is enabled (the
**Security** tab, "Report a vulnerability").

If private vulnerability reporting is **not** available or not enabled, do not
publish secret material or exploitable details in a public issue, pull request,
or discussion. Wait until a private reporting route is available, or contact the
repository maintainers through GitHub in whatever private channel GitHub
provides, and keep the details out of public view until then.

**No email address is published for security reports.** Do not send reports to
any email address you believe belongs to a maintainer; the project does not
publish one and cannot guarantee receipt through an address it does not control.

## What the project will never ask of a reporter

Triaging a security report for this project never requires GPU kernel execution,
never requires running a game, and never requires modifying hardware, drivers,
firmware, registry settings, clocks, voltages, or power limits. If a report
appears to require any of those things, you are not obliged to perform them — a
description of the issue plus host-side evidence is sufficient. This mirrors the
project's hardware safety policy: physical experiments happen only when
explicitly authorized, are bounded, and are never a precondition for
participating in triage.

## Handling expectations

* Reports are reviewed as maintainer time allows; this is a volunteer research
  project without a response-time guarantee.
* Sensitive reports are not reproduced on hardware as part of triage.
* Please do not include personal data, credentials, crash dumps containing
  personal or system information, or proprietary third-party binaries in a
  report.

## Supported versions

This project does not publish supported release branches. Work happens on the
default branch, and only the current state of the default branch is considered.
See `CHANGELOG.md` for the current development status.
