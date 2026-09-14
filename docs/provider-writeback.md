# Provider assessment write-back

A full scan can publish its assessments back to the original findings in
Semgrep, Checkmarx One, Snyk Code, and Aikido. Use `--provider-writeback apply`
to run this automatically after S9 reporting and before S10 remediation,
when remediation is enabled. There is no per-finding human approval step
in this workflow. The flag selects the build-owned publication policy.

BC SAST updates native provider findings. It does not upload a replacement
SARIF report or assume that missing report entries are false positives.

## Run an automatic full scan

```sh
bc-sast --repo ./my-app \
  --provider-writeback apply
```

Add the existing provider ingestion configuration and credentials for the
provider being used. The write-back flag does not fetch findings by itself.
Credentials must have the provider's required triage permissions. They
remain in the harness publishing process, outside target test containers
and model tool environments.

| Mode | Behavior |
|---|---|
| `off` | Default. No provider publication. |
| `plan` | Write assessment proposals without changing provider findings. |
| `apply` | Generate the plan and automatically process eligible native updates after S9. |

Automatic publication requires a completed full scan. It does not use a
diff scan, a resumed scan, prior-report remediation, or a utility command
as evidence of a fresh full assessment. Remediation is optional: publishing
scan assessments does not require generating patches. A proposed or locally
tested patch does not mark a provider finding fixed.

`--diff-scope` is refused with `apply` at startup, and blocks publication
in `plan` mode too. A diff-scoped scan examines only the pull request's
changed files, so for every finding outside them it has no verdict at all,
and writing an assessment back for a finding this run never examined is
the same error as remediating one. Three independent checks enforce it:

1. `--provider-writeback apply` combined with `--diff-scope` is a startup
   error, before any scan runs.
2. The ledger's `full_scan` flag is `false` for the whole run, so every
   planned update carries the `full_scan_required` blocking reason and the
   automatic policy refuses every origin.
3. Each provider finding the run set aside as out of diff scope also
   carries that reason as its own assessment limitation, and an assessment
   with unresolved limitations is never published. The ledger still
   inventories those findings: they are unassessed, which is not the same
   as absent, and the receipt says so.

## Reports and local state

S9 writes `<out-dir>/provider-writeback-plan.json` alongside the normal
reports. In `apply` mode, publication also writes
`<out-dir>/provider-writeback-results.json`. Stopping before S9 does not
produce a new S9 plan or publication result.

The plan contains the pre-filter assessment ledger, provider origins,
ingestion results, source scan context, proposed actions, and limitations.
A plan is evidence, not an authorization file. Editing an `apply_enabled`
field in exported JSON does not enable publication. The automatic workflow
uses its in-memory scan results and build-owned policy.

Publication results record each origin's outcome and reason. Unsupported
actions are recorded as blocked with the capability limitation explained.
Failures, pending provider approval or retest, and read-back uncertainty
have explicit statuses. Repeated operations retain their recorded status
and include a no-replay reason and a warning that current provider state
was not revalidated. A successful operation does not turn the whole batch
into a success. `complete` means every origin was processed, not that every
update succeeded. Ingestion errors and analysis limitations remain visible
even when no provider findings were returned.

The journal location is built in: `provider-publications` beneath the
application state directory (`BC_STATE_DIR` when configured, otherwise
`$HOME/.bc-sast/state`). No separate publication directory flag or
persistent volume is required. Ephemeral containers use this local state
for the duration of the run, then discard it with the container.

Local journals prevent replay while retained. After container replacement,
the harness reads current provider state and applies the same conflict
checks, but cannot recover an earlier ambiguous write or guarantee that
append-only notes will not repeat. Cross-run replay protection requires
retaining the application state directory. Keep journals outside the target
checkout and do not upload them as unrestricted CI artifacts.

Journals retain the provider baseline and operation state needed to avoid
repeating mutations. They can contain sensitive provider metadata or
source-related information. Keep them access-controlled with appropriate
CI retention. Public reports and publication results are redacted
separately.

## Automatic assessment policy

The assessment ledger is captured before S7 deduplication and framework
filtering. Each imported origin retains its own evidence and disposition.
Merging preserves origins; it does not transfer a false-positive verdict
from one member to another.

| Assessment | Automatic handling |
|---|---|
| Supported false positive | Propose native false-positive closure or ignore, subject to evidence, identity, current state, and group-conflict checks. |
| Supported true positive | Retain the finding and publish supported notes, confirmation, or an evidence-based severity update. |
| Inconclusive, unassessed, failed, or conflicting | Leave provider disposition unchanged and record why. |
| Excluded by framework mapping | Use the underlying assessment. Exclusion does not establish a false positive or lower severity. |
| Merged into another finding | Preserve every origin and reconcile its recorded assessment. |

False-positive publication requires an explicit negative verdict, strong
recorded confidence, and supporting rationale. Known affected origins
with a true-positive, unresolved, or conflicting assessment block
false-positive updates for that group. The adapters preserve existing
triage and ignore policies identified by their baseline reads. These checks
run automatically; they do not require a person to approve each entry.

Severity is separate from confidence and framework relevance. Automatic
severity changes require a credible CVSS assessment associated with that
specific finding. Missing or ambiguous severity evidence does not produce
an arbitrary downgrade. In particular, PCI DSS or OWASP mapping exclusions
cannot lower severity.

## Native provider scope and capabilities

The build-owned policy explicitly uses provider-native mutation scope.
That scope can be broader than the branch analyzed by BC SAST. Reports
record the assessed scope, native propagation, and remaining gaps rather
than claiming branch isolation that an API does not provide.

| Provider | Automatic operations and limits |
|---|---|
| Semgrep | True-positive notes and native false-positive ignores using numeric issue IDs and fingerprints. No severity override. Matching findings can propagate across repository refs and future scans; returned affected IDs are checked and retained. |
| Checkmarx One | Native confirmation, false-positive `NOT_EXPLOITABLE`, comments, and supported severity fields. Similarity and Attack Vector grouping can affect project or application scope across branches. `scanId` is not a branch-isolation control. Conflicting states are not forcibly overridden. |
| Snyk Code | Exact asset-fingerprint ignore policies with type `not-vulnerable`. True-positive notes and severity updates are unsupported, so those entries produce no mutation. Existing matching policies are not duplicated. Policy approval and provider retest remain separate outcomes. |
| Aikido | Native issue ignore, credible supported severity adjustment, or group note when appropriate. A group note requires a known group ID and has group scope. Disabling container-tag propagation does not establish Git branch isolation. |

The current scan is bound to its local source revision. Where a provider
returns a source revision or ref, mismatches are rejected. Missing external
revision metadata remains an explicit coverage gap; the harness does not
invent a provider SHA or treat a scan timestamp as proof. Aikido's inspected
repository detail contract does not supply a commit SHA.

Known affected origins can be checked for conflicts. This is not an
exhaustive assessment of every historical or future branch affected by
provider-native propagation. Checkmarx tenant application scope and Snyk
asset-wide ignores are particularly important examples. An operator who
requires branch-only mutation should use `plan` where the vendor cannot
enforce that boundary.

Snyk publishing uses the reviewed `2026-03-25` REST policy contract and
keeps pending approval distinct from effective dashboard suppression.
Semgrep and Snyk inventories use bounded pagination. The shared transport
restricts provider origins, disables redirects, and bounds response sizes
and timeouts. These controls are enforced by code, not model instructions.

## Source revision binding

Automatic publication requires a clean, committed Git checkout. The
harness captures HEAD before the scan, checks any `--git-sha` override,
and verifies the index and tracked file bytes against committed Git
blobs. Before publication it checks the original source again and checks
any isolated delivery snapshot against the same content. A mismatch
blocks publication and produces a blocked results receipt.

These checks run local Git reads with hooks, filesystem monitoring,
external diff commands, lazy fetching, and network protocols disabled.
Content verification streams files without invoking Git content filters.
Known report artifacts and the scanner's built-in excluded directories
are exempt from untracked-file checks. Other uncommitted or ignored
source is refused. Tracked files remain checked even in excluded
directories.

The current binding does not support Git SHA-256 object stores, tracked
symlinks or submodules, or working files converted from their committed
bytes by line-ending or content filters. These cases fail automatically;
they do not request human approval. Native Windows behavior remains
unverified. Ordinary scans and remediation artifact delivery retain their
existing modes; these restrictions apply to automatic provider updates.

## Failures, retries, and concurrent changes

The publisher checks current provider state, records the operation before
sending, and sends the native mutation once. The adapter checks the
immediate pre-write baseline again and performs read-back afterward.

Safe failures before a mutation can be retried on a later run. Journals
prevent automatically resending a request whose outcome is ambiguous.
Already recorded operations are reported separately. Do not delete state
to force a retry after a lost response: reconcile provider state first.

An HTTP success is not proof of effective triage. Results distinguish
verified read-back, pending approval, awaiting retest, accepted but
unverified updates, and unknown outcomes. There is no automatic rollback
that could overwrite a later human decision.

The inspected APIs do not provide a common atomic compare-and-swap
contract. A human can still edit a finding between the final read and the
write. Automatic publication does not eliminate that race. OAuth tokens
can also expire during a long batch; errors remain recorded rather than
triggering blind mutation retries.

## Optional manual utility

The existing `--publish-provider-plan` utility remains available for a
separately selected operation. Its `--provider-publish-phase prepare` and
`apply` modes retain their explicit review, revision-attestation, scope,
and concurrent-edit flags. They are an optional compatibility workflow,
not a prerequisite for `--provider-writeback apply` during a full scan.

## Validation and remaining limits

The adapters and policy have local unit and mock HTTP contract tests.
No live provider account or vendor dashboard was used to validate this
implementation. Tenant permissions, feature availability, actual grouping
propagation, rescans, and eventual consistency remain unmeasured. Native
Windows behavior has not been established by these tests.

The automatic workflow passed the existing CI coverage gates on
September 10, 2026:

| Gate | Lines | Functions | Exit code |
|---|---:|---:|---:|
| Workspace, with the CI exclusion list | 100% | 100% | 0 |
| `bc-cli` | 99.38250% | 99.65191% | 0 |

Before removal of the separate state-directory flag, workspace verification
passed with 6,396 tests, zero failures and
zero ignored tests, excluding `bc-parity-tests`. These commands each exited
0:

```sh
cargo build --workspace --exclude bc-parity-tests --all-targets --offline
cargo test --workspace --exclude bc-parity-tests --offline
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo fmt --check
```

Each coverage run followed `cargo llvm-cov clean --workspace`, which exited 0.
Dependencies were used offline. These checks validate local control flow
and contract fixtures; they do not establish provider dashboard behavior
or model assessment accuracy.

After removal of the state-directory flag, all 864 CLI unit and integration
tests passed with zero failures or ignored tests. CLI Clippy, formatting,
and the CLI coverage gate exited 0. Coverage was 99.39496% of lines and
99.65191% of functions. The workspace gate above was not rerun for
this CLI-only adjustment.

External SARIF import remains a separate capability. It does not replace
native scan findings.
