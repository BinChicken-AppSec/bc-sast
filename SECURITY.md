# Security policy

## Reporting a vulnerability

Please report suspected security issues in `bc-sast` itself privately, not via
a public GitHub issue. Use
[GitHub Security Advisories](../../security/advisories/new) for this
repository ("Security" tab, then "Report a vulnerability"). This opens a
private discussion thread with maintainers before any public disclosure.

If you can't use GitHub Security Advisories, open a regular issue asking
for an alternate private contact. Don't include vulnerability details in
that issue itself.

Please include:
- A description of the issue and its potential impact.
- Steps to reproduce, or a minimal proof-of-concept.
- Affected version/commit.

## Scope

This covers vulnerabilities in `bc-sast`'s own code (the scanning/remediation
pipeline, the CLI, the GitHub Action integration, and the container build),
not vulnerabilities *found by* `bc-sast` in a scanned target repository.

Known, already-documented architecture-level security considerations
(e.g. the remediation policy gate being off by default, no per-diff human
approval) are tracked in `docs/compliance/AI_AGENT_SECURITY_REVIEW.md`
rather than needing a fresh report. Read that first.

## Supported versions

`1.0.0` is the current release. Only that tag and the latest commit on the
default branch are supported; there is no backport branch for anything
older.

## Response expectations

Best-effort: there is currently no formal SLA. A maintainer will
acknowledge new reports and follow up with next steps.
