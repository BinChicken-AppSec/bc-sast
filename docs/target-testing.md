# Target-repository testing during remediation

Target testing is opt-in and runs only after a full scan with isolated,
non-interactive remediation. It is separate from BC SAST's own Rust tests.
S8 produces the ranked typed report; S9 renders and publishes the scan
reports, followed by S10 remediation and S11 model review. S9 is
deterministic and does not call a model or reparse Markdown. Target-test
preparation runs before S10. Execution runs only with an execution-enabled
profile and a prepared local Docker environment. Postpatch execution, when
authorized, runs after S11 against the final combined proposal.

Add these options to your normally configured scanner invocation:

```text
--repo /path/to/clean/repository --remediate --target-tests comprehensive
```

`--target-tests` selects a policy embedded in the BC SAST binary. It accepts
a compiled profile name, not a JSON file path. `--target-tests` without a value
selects `comprehensive`; omitting the flag disables this workflow.
`--testing-level` is an alternate spelling.
Editing a runtime file cannot change these policies. Adding or changing a
profile requires reviewing the source policy and rebuilding the scanner.
This keeps repository contents, generated tests, and model output from
granting themselves new command or image permissions.

With default patch or explicit branch delivery, the target must be a clean
committed Git checkout and worktree creation must succeed. Explicit
`--remediation-delivery zip` instead uses an isolated source snapshot and
does not require Git. Scanning and remediation use that same copied tree. Any `--stop-after` setting, partial/diff scans,
prior-report remediation, resume, interactive remediation, in-place edits,
dry-run remediation, and the host `verify_command` are unsupported with this feature. These restrictions
bind discovery, baseline execution, and remediation to the same snapshot.
Existing scan-only and prior-report workflows do not perform target-test
planning, generation, or execution.

For a scan that only produces reports, use `--stop-after s9` without
`--target-tests`. That boundary prevents S10/S11 even when `--remediate`
is supplied. `--stop-after s8` stops before rendered report files.
Target testing requires continuing through remediation, so neither stop
boundary is compatible with `--target-tests`.

## Select testing depth

| Level | Requested scope |
|---|---|
| `discover` | Inspect the environment and record gaps without generating tests. |
| `unit` | Unit behavior and security regression tests. |
| `integration` | Unit scope plus component and integration contracts. |
| `comprehensive` | Relevant unit, integration, E2E, and security regression tests for core workflows and security-critical paths. |
| `e2e` | Alias for the cumulative comprehensive scope, including lower-level tests where appropriate. |
| `generate` | Compatible name for comprehensive generation. |
| `discovered-offline` | Comprehensive generation plus allowlisted discovered suites in ecosystem-specific Linux images, with the target's own lockfile-pinned dependencies installed first. |

These levels describe requested depth, not achieved coverage. The harness
rejects proposed test kinds outside the selected level; independent review
must assess whether the declared classification matches actual behavior.
All generation levels first discover existing tests and supply bounded
excerpts to both generator and reviewer. They should reuse suitable tests,
extend existing suites, and add missing meaningful coverage. Truncated,
inline, or undiscovered tests require further inspection and remain gaps.

A no-addition proposal can proceed only after independent model review of
existing test evidence. Test presence alone never establishes adequacy.
Generation without execution remains unverified. Levels choose test scope;
execution still requires a vetted compiled image/command policy. Only
`discovered-offline` ships execution authorization. `discover`, `unit`,
`integration`, `comprehensive`, `e2e`, and `generate` remain unauthorized
for execution, and none of them installs anything. `discovered-offline`
installs the target's declared dependencies from its lockfile, in a
separate container that is the only one with a network. See
[dependency provisioning](#dependency-provisioning).

## Discover and plan

The `discover` profile performs bounded static discovery for target testing;
S10/S11 remediation still runs because `--remediate` is required. The plan
records package manifests, native test layouts, framework hints,
workspaces, CI/service evidence, suggested commands, expectation sources,
and risk-based coverage obligations. Finding test files does not establish
adequate coverage. Discovery records unsupported and truncated inspection.

Select a generation level such as `--target-tests comprehensive` to request
a separate generation session and an independent read-only review session
before S10 edits production
code. Build-time `generator_model` and `reviewer_model` settings can route
these roles; otherwise both inherit the configured remediation model in
independent sessions. No particular model name is hardcoded.

The generator inspects existing tests and project contracts, then proposes
unit, integration, end-to-end, and security regression tests appropriate
to the target. Each proposal must cite an existing file, line, and exact
snippet supporting its expectations. These citations are checked locally;
the independent reviewer evaluates the behavioral interpretation. Models
can still make mistakes, and review is not executable proof.

The harness can extend existing test files or create tests in recognized
test layouts. Fixtures and setup files require exact paths in
the embedded policy's `allowed_support_paths`. Production source edits, Git
metadata, escaping paths, symlink aliases, and recognized credential-file
paths are rejected.
A reviewable batch is capped at 24 files, 64 KB per file, and 256 KB total.
Larger or underspecified applications retain explicit remaining gaps.
Inline Rust test modules inside production source are not automatically
rewritten by this test-generation path; integration tests under `tests/`
or a separately reviewed extension are appropriate alternatives.

### Generation batches and the findings budget

Generation is chunked across findings rather than refused when a report is
large. The findings evidence one generation request may carry is derived
from the generator model's context window, not written down as a fixed
byte count: the assumed window is 128,000 tokens, half of it is reserved
for the rest of the request (the role instructions, the discovery
inventory, the bounded existing-test excerpts, the read and search results
the generator collects across its turn budget, and its own reply), and the
remaining 64,000 tokens are estimated at four bytes per token. That is
256,000 bytes of findings evidence per batch today. The window is an
assumption because no per-model context limit is published anywhere in
this project; the price table carries token rates and long-context pricing
thresholds, which are not context limits. Assuming the smallest window the
generator role is routed to keeps the budget conservative.

Findings are grouped by the source file they are reported against, and a
source file's findings always stay in one batch. Tests for a source file
belong in one destination test file, so the source file is the smallest
unit that can move between batches without two batches proposing the same
destination. Groups are packed in sorted path order, so a directory's
files normally share a batch as well. Each batch is one generator session
that sees only its own findings and is told which source files it owns.

Generation is refused, never silently truncated, when:

- one source file's findings exceed a whole batch on their own, which no
  further splitting can fix;
- the report needs more than 8 batches, the ceiling on how many separate
  model calls one preparation will spend; or
- two batches propose the same destination test file. The two contents
  were written by sessions that never saw each other, so merging them
  would produce a file neither model wrote and neither reviewer would
  recognize, and keeping one would silently drop coverage the other batch
  reported as covered.

Independent review is a single session over the combined proposal from
every batch. The combined proposal is therefore bounded by the same caps
as one reviewable batch: 24 files, 64 KB per file, and 256 KB in total.
Batching bounds the evidence going in and does not buy room for more
reviewed output coming out. When more than one batch ran, the reviewer is
given each batch's source-file scope rather than every batch's findings
repeated, and the artifact records that as a remaining gap.

Generation is given the findings remediation is about to fix, which is the
same `--top N` CVSS selection S10 uses, not every finding in the report.

The remediation model receives the discovery plan. Reviewed generated
files and discovered existing tests are bound to their bytes: changing or
deleting them during remediation blocks patch export. This conservative
gate can reject an intentional compatibility change; review the contract
and tests separately rather than weaken assertions to accommodate a patch.

## Build and select an execution profile

Before `discovered-offline` was added, every shipped profile omitted
execution authorization. Generation and review could complete, but no
stock profile could run baseline or postpatch tests. That limitation was
not a successful validation outcome.

Select the new opt-in profile with:

```text
--repo /path/to/clean/repository --remediate --target-tests discovered-offline
```

Discovery provides package language, directory, manifest evidence, and
command suggestions. The build-owned profile authorizes exact argv
alternatives for each ecosystem. Matching is case-sensitive and covers
every argument; it permits no wildcard, prefix, shell-text substitution,
or additional arguments. The caller contains no language-specific branch.
Every resolved command also passes `ContainerPolicy::validate`, including
the original image pin, argument, path, and command-count checks. At most
64 commands are authorized across the whole target. Duplicate package
commands are deduplicated and ordering is stable.

| Detected ecosystem | Pinned upstream image family | Allowed discovered command |
|---|---|---|
| Rust | Docker Official `rust:1-bookworm` | `cargo test --locked --offline` |
| JavaScript/TypeScript | Docker Official `node:22-bookworm-slim` | `npm run` with exactly `test`, `test:unit`, `test:integration`, or `test:e2e` |
| Python | Docker Official `python:3.12-slim-bookworm` | `python -m pytest` |
| Go | Docker Official `golang:1-bookworm` | The exact Go test invocation emitted by discovery, including its recursive package selector |
| Java/Kotlin | Docker Official `maven:3-eclipse-temurin-21` | `mvn --offline test` |
| .NET | Microsoft `dotnet/sdk:8.0-bookworm-slim` | `dotnet test --no-restore` |

The policy contains immutable digest references, not these mutable tags.
The digests were checked against [Docker Hub tag metadata](https://hub.docker.com/v2/repositories/library/node/tags/22-bookworm-slim)
and the [Microsoft registry manifest](https://mcr.microsoft.com/v2/dotnet/sdk/manifests/8.0-bookworm-slim)
on 2026-09-10. The other Docker Official Images use the same tag metadata
endpoint with their image name and tag. These established upstream
families provide the relevant toolchains without adding target credentials
or application-specific bootstrap scripts. Digest pinning makes changes
reviewable; it is not a vulnerability assessment of the image.

Preload each required image by the exact reference in
`crates/bc-cli/src/target_testing/policies/discovered-offline.json` on the
local Docker engine before scanning. Image acquisition is a separate,
trusted operator task. The executor uses `--pull never` and never downloads
an image during testing.

These are base toolchain images, not universal application test images.
The Python image does not contain pytest, and the Node image does not
contain Jest. Neither contains the target's own dependencies, and the
execution snapshot deliberately excludes the host's `node_modules`,
`vendor`, `target`, and virtual environment directories. That is what the
provisioning phase below exists to fix. Unavailable services, incompatible
runtime versions, or an absent local image still produce failed or blocked
commands. A supported ecosystem means its commands can be authorized, not
that every project can run in that base image.

An unmatched suggestion is recorded in `remaining_gaps`, naming its
manifest and argv. A recognized package with no suggestion names the
package and ecosystem in its refusal. An ecosystem absent from the
catalog is refused explicitly. A package the build cannot install
dependencies for is refused before its tests are considered, and its
refusal names both the pins the ecosystem accepts and the pins that were
actually found. If no package ecosystem is recognized, the refusal
includes inspected-entry counts and available test/project evidence.
Refusals block verified export even if other packages pass. The current
discovery does not suggest Gradle, tox, or nox commands. Its pnpm, Yarn,
and Bun packages are refused by this profile because the Node image
provides npm only.

## Dependency provisioning

Running a project's test suite already executes that project's code, so
refusing to install that project's declared dependencies is not a coherent
security line: it only guarantees the suite fails for a reason that has
nothing to do with the target. The genuine marginal risks are network
access during the install and install-time hook scripts, and both are
addressed directly rather than avoided.

Provisioning is a separate phase with its own container invocation, run
once per package, before any baseline. That container is the only one in
the whole run that has a network. Every test phase keeps `--network none`,
and nothing about the test phases was relaxed to make provisioning
possible: an install and a test command are different command kinds, and
only the build-owned install kind selects the networked invocation.

| Detected ecosystem | Pin the build requires | Provisioning command | Install-time scripts |
|---|---|---|---|
| Rust | `Cargo.lock` | `cargo fetch --locked` | No control. Cargo build scripts do not run during a fetch, but they do run later during `cargo test`, as they would anywhere. |
| JavaScript/TypeScript | `package-lock.json` or `npm-shrinkwrap.json` | `npm ci --ignore-scripts --no-audit --no-fund` | Disabled. `--ignore-scripts` stops `preinstall`, `install`, and `postinstall` hooks. |
| Python | `requirements.txt` | `pip install --user --no-input --no-cache-dir --only-binary :all: -r requirements.txt` | Disabled in effect. `--only-binary :all:` installs wheels only, so no `setup.py` is executed during the install. A project with only source distributions fails the install rather than running one. |
| Go | `go.mod` | `go mod download` | None to disable. Downloading a module does not execute it. |
| Java/Kotlin | `pom.xml` | `mvn -B dependency:go-offline` | No control. Maven resolves and can execute plugin code during resolution, and offers no equivalent flag. |
| .NET | `packages.lock.json` | `dotnet restore --locked-mode` | No control. Restore evaluates the project's own MSBuild logic and any `.props` or `.targets` a restored package brings. |

Each command is the ecosystem's lockfile-respecting form, not its
resolving one, so the installed versions are the ones the target committed.
`npm ci` fails outright without a lockfile rather than writing one;
`cargo fetch --locked` refuses a stale or absent `Cargo.lock`;
`dotnet restore --locked-mode` fails if a restore would change
`packages.lock.json`. A package with none of the pins its ecosystem
accepts is refused: there is no resolve-from-the-internet fallback, and
because vendored dependency directories are stripped from the snapshot,
running its suite anyway could only produce a misleading failure. That
refusal is recorded before anything runs, and it blocks verified export.

Provisioning is per package, and a package is a manifest with a pin beside
it. That is a real limit for workspace layouts that keep one lockfile at
the repository root: an npm workspace member with no `package-lock.json`
of its own is refused, even though the root package it belongs to may
install and test fine. Workspace-aware installs are not implemented, and
guessing that an ancestor lockfile covers a member would be exactly the
kind of assumption this profile refuses to make.

Two ecosystems deserve their limits stated plainly. Maven has no lockfile
at all: a POM with exact versions is the only pin it has, and a POM using
version ranges is not reproducible. `dependency:go-offline` is also known
not to resolve every plugin dependency, so an offline `mvn test` can still
fail on a plugin it never fetched. For Python, `requirements.txt` is only
as pinned as the project made it; hashes are not required, because
requiring them would refuse nearly every real requirements file. Poetry,
uv, and Pipenv locks are recorded in the plan as discovered evidence and
then refused, because installing from them needs a tool the vetted image
does not carry. Gradle is refused for the same reason it has no test
command today.

The provisioning container is hardened exactly like the test containers:
digest-pinned image, `--pull never`, unprivileged UID, all capabilities
dropped, `no-new-privileges`, read-only container root, CPU, memory, and
process limits, bounded output, and a cleared host environment with a
private empty `DOCKER_CONFIG`. It inherits no scanner environment, no
credentials, and no registry logins, so an install reaches public package
registries as an anonymous client and cannot reach a private one. Its
deadline is 1,200 seconds rather than the 600 seconds a test command gets,
because a cold dependency tree takes longer to fetch than the suite it
enables takes to run.

It receives one writable mount, and it is not a path from the host
project: a private per-run dependency store in a fresh temporary
directory, narrowed to the host user, that is removed when the run ends.
The install writes there; every test phase mounts that same store
read-only and copies what it needs into its own throwaway working copy, so
target code can never modify what a later phase reads. The target's own
source stays read-only in every phase, provisioning included.

Two consequences are worth knowing. Each test command copies the
dependency tree into its container before running, so a large
`node_modules` or Maven repository costs time and temporary space per
command. And the current source is copied over the store's older copy at
the start of every phase, so a file the patch changed is the patched one,
while a file the patch deleted can still linger in the working copy.

Resolved suite commands are `Existing`: they run in `existing_baseline`
before generation and in `postpatch` after remediation. They do not run in
`generated_baseline`, and neither does the install, which runs once in
`provision` and is never repeated after the patch. Reinstalling afterwards
would replace the environment the baseline was measured against.
Discovery cannot supply a trustworthy security
failure signature, so it must not relabel an existing suite as a security
regression. Generated tests collected by the existing suite may run after
the patch, but their prepatch reproduction is unmeasured. Even when both
suite runs pass, the result remains
`functional_checks_passed_security_unverified`.

The resolved image/command list is recorded in
`resolved_execution_policies` in `security-scan/target-tests.json` and
supplied to generation and review. Resolution happens once before any
model edits. Later target changes cannot expand the approved command set.

Policies live under `crates/bc-cli/src/target_testing/policies/` and are
embedded with `include_str!` by `target_testing/builtin_profiles.rs`.
To add an execution profile:

1. Review the target's test commands and prepare a vetted local image.
2. Add a strict JSON policy to that source directory. For discovered
   execution, use `discovered_execution` entries with `language`, a
   digest-pinned `image`, `allowed_argv` arrays of exact alternatives, and
   a `provisioning` object carrying `pins`, `argv`, and `scripts_disabled`.
   Provisioning is required, not optional: an ecosystem whose dependencies
   the build cannot install is one whose suite cannot be believed. Follow
   `discovered-offline.json`. For a target-specific security reproduction
   with a reviewed failure marker, use the existing literal `execution`
   schema below; a literal policy that declares no provisioning command
   runs unprovisioned, against an image that must already carry what its
   commands need. Do not combine both forms. Approve any exact
   fixture/setup paths separately.
3. Register a unique name and version in `PROFILES`, using `include_str!`.
4. Run the policy and executor tests, then rebuild with
   `cargo build --release -p bc-cli`.
5. Select the compiled name with `--target-tests your-profile-name`.

Bump the profile version when its permissions or behavior change. The
assurance artifact records the selected name and version. A target file,
model output, or runtime JSON file cannot introduce commands or override
the compiled policy. Unknown names and paths fail closed. Existing
full-scan and isolation requirements apply to every profile.

For example, this is a **source policy template**, not a shipped profile
or runtime file. Adapt it to the actual pytest layout before registering:

```json
{
  "generate": true,
  "allowed_support_paths": ["tests/conftest.py"],
  "execution": {
    "image": "your-local-test-image@sha256:REPLACE_WITH_64_HEX_DIGEST",
    "commands": [
      {
        "id": "existing",
        "cwd": ".",
        "argv": ["python", "-m", "pytest", "tests/existing"],
        "kind": "existing"
      },
      {
        "id": "legitimate-workflows",
        "cwd": ".",
        "argv": ["python", "-m", "pytest", "tests/functional"],
        "kind": "functional"
      },
      {
        "id": "ownership-regression",
        "cwd": ".",
        "argv": ["python", "-m", "pytest", "tests/security/test_ownership.py"],
        "kind": "security_regression",
        "expected_failure_contains": "test_non_owner_cannot_read_record"
      }
    ]
  }
}
```

The placeholder digest is deliberately invalid. Prepare and vet the image
outside this workflow. A literal `execution` policy declares no
provisioning command, so its image must already carry the frameworks and
dependencies its commands need; the profile above is the one that installs
them. The harness never pulls an image or installs anything on the host.
Network-disabled test commands cannot fetch packages; external services
remain blockers.

The backend requires a local Docker engine running Linux containers. It
uses a bounded copied source snapshot, a read-only source mount, an
unprivileged user, dropped capabilities, a read-only container root,
bounded temporary storage, CPU/memory/process limits, bounded output, and
timeouts. Test commands additionally run with no network. It does not
mount the host target writable, the Docker socket, host home, or
credentials into the container. The one writable mount any container
receives is the private per-run dependency store described above, and only
the provisioning phase gets it writable. Target commands never fall back
to execution on the host. Recognized secret files, symlinks, dependency
and build directories are excluded from the execution snapshot; this can
block projects that need them and does not prove arbitrary source files
contain no secrets. Supply synthetic fixtures, not production credentials.

Test network isolation is enforced by Docker's `--network none`, not by a
prompt or an npm setting. Only a build-owned provisioning command runs
with a network, and it runs before any test phase. The executor clears the
host environment and uses a private, empty `DOCKER_CONFIG`. It does not
inherit registry logins or Docker contexts. It limits execution to 600
seconds per test command and 1,200 seconds per install, two CPUs, 4 GB
memory, 256 processes, and a 4 GB temporary filesystem. The temporary
filesystem holds the working copy of the target plus whatever provisioning
installed, which is why it and the memory limit are larger than the
512 MB and 2 GB used before dependencies were installed at all.

An allowlisted runner still executes untrusted target code. For example,
`npm run test` can invoke project lifecycle scripts. The Docker boundary
contains that code; argv matching cannot prevent it from opening another
container path, spawning a process, or attempting an installation. A test
command has no network to install over regardless, and no host dependency
installation is allowed in any phase. The working directory is a safe
initial directory, not an
in-container chroot. This design assumes a trusted, patched local Docker
engine and reviewed images without embedded credentials. Literal
confinement of every test process to its working directory is not provided
by this executor.

The fixed setup shell is inside the Linux image. A Windows host does not
need POSIX `sh`, but does need the supported local Linux-container backend.
This is not native Windows application testing. Windows-specific targets
and multi-service E2E environments require a separately supported executor;
they must not be represented as tested by this backend.

## Execution order and results

1. Install each provisionable package's declared dependencies, once, in
   the run's only networked container.
2. Run approved existing suites against the unpatched snapshot.
3. Generate and independently inspect proposed tests, if requested.
4. Run approved functional and security tests before the patch.
5. Run S10 remediation and S11 independent model review.
6. Confirm test bytes are unchanged, then rerun all approved test commands
   on the final combined patch. The install does not repeat.
7. Record scoped results and gate both patch-file and remediation-JSON
   exports. A blocked result never becomes a passing result.

The artifact is `security-scan/target-tests.json`; successful workflow runs
also annotate Markdown and SARIF with scoped assurance status. It distinguishes
the compiled policy name/version, static discovery,
generated/inspected/applied test artifacts, actual
execution results, baseline failures, missing security reproduction,
postpatch failures, and remaining gaps. Text is redacted for reporting;
proposed test and remediation patches still contain actual code and need
normal source-access controls.

### An environment failure is not a test failure

Each command result carries one state, and they mean different things:

| State | Meaning |
|---|---|
| `passed` | The command ran against a prepared environment and succeeded. |
| `failed` | The command ran against a prepared environment and the target's own code failed. This is the only state that is evidence about the target. |
| `environment_failed` | The environment could not be prepared. Either an install exited nonzero, or a test phase was refused because its dependencies were never installed. Nothing was learned about the target. |
| `blocked` | The command could not be started at all: invalid policy, unusable snapshot, or a container the engine refused to run. Docker's own reserved exit codes 125 to 127 land here. |
| `timed_out` | The command exceeded its deadline and its container was removed. |

A failed install never becomes `failed`, and a suite whose install failed
is not run at all: it is recorded as `environment_failed` with the install
command and its outcome named in the result. Before this distinction
existed, an unprovisioned suite exited 1 and was recorded as a failing
test, which then blocked the export of a fix that was never in question.
The gap text follows the same split, so a reader is told that an
environment could not be prepared rather than that a baseline failed. The
artifact also carries a top-level `environment_blocked` flag, repeated in
the Markdown and SARIF annotations, so an unusable environment is visible
without reading every result.

An environment failure still withholds export. Being unable to run the
tests is not permission to skip them; it is a different, and honestly
labeled, reason to stop.

A security command must fail before the patch with its configured failure
signature and pass afterwards to demonstrate that regression. A nonzero
exit alone is insufficient: a syntax error is not a reproduced
vulnerability, and neither is an `environment_failed` result, which cannot
satisfy the reproduction check at all. Even a matching failure signature
warrants human inspection of the test and its failure; it is not universal
proof of a fix. Baseline failures against a prepared environment are
reported as pre-existing pending investigation. Automatic flaky-test
classification is not implemented.

A command passing establishes only that command's observed result. This
feature does not claim comprehensive coverage for an arbitrary application,
that a model's proposed expectations are correct, or that passing tests
exclude other vulnerabilities and regressions. Budgeted generation,
unsupported frameworks, unavailable services, and unmet coverage obligations
remain explicit gaps.

Individual generated files remain `not_individually_verified`: runner
collection reports are not yet parsed to prove which cases actually ran.
The approved commands and observed exit statuses are recorded separately.
Rejected or incomplete requested generation withholds patch export. The
artifact records requested generator/reviewer models and usage returned by
completed sessions; usage lost when a model session errors is still unknown.

## Retain tests for future runs

Generation edits the detached remediation worktree, or the isolated source
snapshot for ZIP delivery, following the target's
existing test layout and package boundaries. Examples include Rust `tests/`,
Python `tests/`, and framework-native colocated JavaScript test files.
Fixtures and setup changes remain subject to the compiled profile's exact
support-path permissions. No universal directory is imposed on monorepos.

With default `--remediation-delivery patch`, the combined
`security-scan/remediation.patch` carries new test files,
extensions to existing tests, approved support files, and production fixes.
The separate `security-scan/target-tests.json` stores assurance metadata and
results; it is not the reusable test suite. Per-finding remediation JSON
must not be used as a substitute for the combined patch: tests generated
before S10 are not necessarily part of a per-finding diff.

After inspecting the combined patch and its validation gaps, apply it from
the original target repository root:

```sh
git apply --check security-scan/remediation.patch
git apply security-scan/remediation.patch
```

For default patch delivery, review and commit the resulting test and source
changes using the target's normal contribution process. This mode does not
automatically apply the patch to the original checkout, commit, or push it.
Once committed, the tests are ordinary target-project tests available to
developers, CI, and future BC SAST runs. The project's test commands/CI must collect them;
merely storing a file does not establish that it executes.

`--keep-remediation-worktree` retains the proposal checkout for inspection.
Normally it is removed after export. If writing a nonempty patch fails,
the worktree is retained and its recovery path is printed. Validation gates
can withhold export; a retained blocked proposal is not an approved fix.

Explicit `--remediation-delivery branch` commits and pushes the combined
changes to an explicitly named new remote branch. Explicit
`--remediation-delivery zip` packages the updated isolated source tree,
including accepted tests, at `security-scan/remediated-source.zip` without
requiring Git. CI must upload that file through its artifact mechanism.
See [remediation delivery](remediation-delivery.md) for flags, authorization,
exclusions, failure handling, and reuse. Delivery mode does not authorize
test execution or change the selected testing level.

Note the operational scope: the authorization, refusal and classification
paths are covered by tests, while the container execution path itself has
not yet been observed running against a live engine.
