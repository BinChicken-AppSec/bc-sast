# Deliver source fixes and reusable tests

`--remediation-delivery patch|branch|zip` selects how the combined proposal
leaves BC SAST. It does not select test depth or authorize test execution.
Generated tests, extensions to existing tests, approved supporting files,
and accepted production fixes travel together.

The default remains `patch`, preserving the existing review-and-apply
workflow. Explicit `branch` and `zip` delivery require a full scan followed
by non-interactive remediation. They reject diff-scoped scans, prior-report
remediation, resume, in-place remediation, dry runs, and `--stop-after`.
They work with or without `--target-tests`.

## Push a new branch

Add these options to your normal configured scan invocation:

```text
--repo /path/to/repository --remediate \
  --target-tests comprehensive --remediation-delivery branch \
  --delivery-remote origin --delivery-branch bc-sast/security-fixes-run-123
```

The input must be a clean, committed Git checkout. BC SAST creates an
isolated detached worktree. After the applicable remediation and test
assurance gates permit delivery, it commits the combined source and test
changes and pushes to the explicitly named new branch on the named remote.
Existing branches must not be overwritten. If there are no changes, the
receipt records `no_changes` and no commit or branch is created. This
is explicit publication authorization; omit this mode when you want a local proposal only.

The original checkout's files and active branch remain unchanged. Branch
mode requires Git, configured commit identity, an existing remote, and
credentials with appropriate push permission. Publication disables executable
credential helpers and interactive prompts; configure noninteractive
authentication such as an SSH agent or an appropriate HTTP header in the
trusted CI environment. The scanner does not create
or merge a pull request automatically. Developers can review the branch
and use their usual contribution workflow.

## Produce a ZIP for CI

Add these options to your normally configured scanner invocation:

```text
--repo /path/to/source --remediate \
  --target-tests comprehensive --remediation-delivery zip
```

Git is not required. BC SAST makes an isolated source snapshot and uses
that same copy for scanning, test preparation, and remediation. Source
fixes and accepted tests are added to the copy, leaving the original source
files unchanged. On permitted delivery, the resulting source tree is
written to:

```text
<target>/security-scan/remediated-source.zip
```

This contains source and test files, not merely patch instructions. Extract
it into a separate review directory and inspect the changes before using
it to replace or update a development checkout. The ZIP does not contain
Git history. Existing artifacts are not overwritten; use a fresh CI
workspace or deliberately archive the previous output before another run.

Configure your CI system's existing artifact upload mechanism to publish
`security-scan/remediated-source.zip`, together with the delivery receipt,
scan reports, and target-test assurance report where applicable. Writing a
local ZIP does not automatically upload it to a CI server. BC SAST has no
generic CI artifact server or upload credential integration.

The snapshot and ZIP omit `.git`, `security-scan`, symlinks, recognized
credential files (including `.env*`, private key extensions, and common
credential directories), and common dependency/build output directories.
These exclusions are not proof that arbitrary source contains no secrets.
They can also omit legitimate vendored code or configuration; review the
recorded omissions before treating the archive as a usable application.

The copy and archive are bounded to 256 MiB of file content, 30,000 entries,
and directory depth 32. Unsupported special files, unsafe or nonportable
filenames, and case-insensitive filename collisions cause an explicit
failure. The exported ZIP uses Unix mode 0644 so an uploader running
outside the scanner container can read it; restrict workspace access and CI artifact
download permissions appropriately. ZIP uses uncompressed STORE entries
and preserves executable bits where the host exposes them. Source copying requires a quiescent input
workspace; portable filesystem checks do not provide an atomic snapshot of
files that another process is actively changing. Native Windows operation
still requires platform validation.

## Assurance and results

Delivery does not weaken remediation gates. A blocked proposal is not
published as an approved result. Delivery failure returns a nonzero exit status after saving available
remediation evidence. A delivery receipt is written only after delivery
succeeds, so inspect the run status as well as any
`security-scan/delivery.json` before consuming artifacts.
The receipt records `status` (`pushed`, `no_changes`, or `created`), `mode`,
`destination`, `detail`, and `excluded_paths`. It also records the known
`scan_revision` and scoped `validation` information: whether model review
was enabled, its available results, target-test assurance status, and the
number of target command results. A null revision or target-test status
does not establish a verified baseline or test execution. Branch
`no_changes` means no commit or push; ZIP delivery can still create an
archive when remediation made no changes.

If publication or ZIP creation fails, the updated worktree or snapshot is
retained and its recovery path is printed. If delivery succeeds but saving
the receipt fails, the run fails and reports that distinction. Inspect the
destination before retrying to avoid repeating a completed publication.

Keep artifacts scoped to the current CI run so an earlier artifact cannot
be mistaken for the latest successful result.

Testing levels such as `unit`, `integration`, and `comprehensive` control
requested test scope. Existing suites are inspected before missing tests
are proposed. Shipped profiles generate and review tests but do not execute
target code. Execution requires a reviewed embedded container and command
policy; a generated suite or a pushed branch does not prove tests passed.
See [target testing](target-testing.md) for validation states and remaining
coverage gaps.

Tests delivered in a branch or ZIP are ordinary target-project files in
its established framework layout. Once incorporated into the development
repository, they can be reused by developers, CI, and future scans. The
project's test runner must actually collect them; storage alone does not
establish execution.

No live remote publication, CI upload, or native Windows delivery was
validated for this change. Local repository and synthetic archive checks
do not establish those outcomes.

## GitHub Actions artifact step

The Docker action exposes `remediation-delivery: zip` alongside
`remediate: "true"`. It remains a producer; the consumer workflow adds the
upload step after a successful scan. For example, using the artifact action
pin already present in this repository's CI:

```yaml
- name: Downloadable remediated source
  if: success()
  uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
  with:
    name: remediated-source
    path: |
      security-scan/remediated-source.zip
      security-scan/delivery.json
      security-scan/target-tests.json
    if-no-files-found: error
```

Use a fresh output directory for each run. Retention and download permissions
are controlled by the consuming CI project. Other CI systems should archive
the same paths using their native artifact mechanism. Branch mode is
available through the CLI with explicit destination flags; it does not
require an artifact upload step.
