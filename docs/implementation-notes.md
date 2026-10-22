# Implementation notes

How the current Rust stages, tools and renderers behave. This describes
implemented behavior, not a claim that the product has passed a full
production assessment.

## Scanning and reporting

S9 is an explicit deterministic reporting stage in
`crates/appsec-orchestrator/src/reporting.rs`. S8 produces the structured
analysis; S9 redacts it and renders Markdown and SARIF. The CLI publishes
those formats and CSV/JSON exports. An S8 stop does not publish reports;
an S9 stop publishes reports and prevents remediation. No additional
model is used for S9.

Framework guidance and requirement mappings are embedded in
`appsec-compliance`. `--scan-framework` selects them; `--compliance-preset`
remains a compatible spelling. Runtime compliance-policy files and CLI
configuration overrides for S0 source/sink rule files are rejected.
Changing the embedded YAML and rebuilding changes the rules. Framework
selection guides analysis and maps findings; it does not independently
verify every requirement or establish compliance.

## Target testing and remediation

`appsec-target-tests` provides bounded static discovery of target packages,
framework hints, test layouts, CI evidence, contracts and coverage gaps.
The CLI adds compiled testing profiles selected by `--target-tests [LEVEL]`
or `--testing-level LEVEL`. A bare flag selects `comprehensive`; omitting
it disables target-test orchestration. See [testing levels](target-testing.md).

Discovery precedes generation. Both generation and independent review
receive bounded existing-test excerpts and are instructed to reuse suitable
suites before adding missing coverage. Proposals need checked contract
citations, approved destinations and bounded content. An independently
reviewed existing suite can be reused without forcing new files. This is
model review, not evidence that the suite executes or covers every behavior.

A vetted compiled execution profile can run approved commands against
baseline and patched snapshots in restricted Linux containers. The
`discovered-offline` profile authorizes discovered suites through exact
ecosystem allowlists, and installs each package's lockfile-pinned
dependencies first in the run's only networked container. Other shipped
profiles do not authorize execution. Results distinguish generation,
review, actual command outcomes, baseline failures, environments that
could not be prepared, and remaining gaps.
Security regression evidence requires the configured baseline failure
signature and a passing patched run. Passing commands do not prove that
every generated case was collected or that the fix is complete.

Reviewed generated tests and discovered existing test bytes are protected
against later changes during remediation. Failure of those checks blocks
export. The combined patch includes tests created before S10; individual
finding diffs are not a substitute for that combined output.

## Delivery

Full-scan remediation, with or without target testing, supports:

- `patch`: the existing combined patch for review and manual application.
- `branch`: one commit containing accepted source and test changes on an
  explicitly selected new branch. The remote branch must not exist.
- `zip`: updated source and tests from an isolated copy, without requiring
  Git. The copy is used for both scanning and remediation. CI uploads the
  resulting ZIP using its own artifact mechanism.

Branch and ZIP delivery preserve the original source directory. They reject
partial scans and respect remediation and applicable validation gates.
Delivery errors return an unsuccessful CLI result; publication errors
retain the proposed changes for recovery. A completed delivery receipt
records the destination, scan revision where available, validation scope,
and ZIP exclusions. A branch run with no changes records a no-op.

The Docker action accepts ZIP delivery. The consumer's upload step is
shown in [remediation delivery](remediation-delivery.md).

## Harness corrections

| Code area | Correction |
|---|---|
| `appsec-llm-agentic/src/session.rs` | Tool dispatch rejects names outside the tools advertised for the session. A prompt restriction alone is not the boundary. |
| `appsec-sandbox-tools/src/control_path.rs`, `write.rs`, `edit.rs` | Write paths are checked for protected Git control data, including aliases, alongside path confinement. |
| `appsec-sandbox-tools/src/journal.rs` | The journal captures the actual resolved destination and original bytes before a write. Unreadable or ambiguous baselines fail rather than proceeding without rollback evidence. |
| `appsec-diffcapture/src/lib.rs` | Rollback handles resolved path identities and propagates Git checkout failures. |
| `appsec-stage-s10/src/lib.rs` | Actual touched files drive diff and rollback decisions. A claimed fix with no change is downgraded to review rather than accepted as fixed. |
| `appsec-cli/src/worktree.rs` | A failed write of a nonempty exported patch retains the worktree and prints its recovery path instead of deleting the proposed tests and fixes. |

These checks do not eliminate prompt injection, prove arbitrary source is
secret-free, or make every filesystem and process path safe. Known limits
include concurrent mutation during portable source copying, unmeasured
native Windows behavior, and best-effort cleanup of Git transport
subprocesses after cancellation or timeout.

## Checks and limits

Implementation checks used synthetic repositories, model stubs and local
bare Git remotes, so they qualify the strength of this verification rather
than standing in for a live one.

No full workspace coverage measurement, live model evaluation, external
SAST-provider run, live remote push, CI artifact upload, Docker target-test
execution, or native Windows run has been completed. No CI upload or remote
publication has been performed against a live service. The absence of
Semgrep, Checkmarx and other provider access is known. It is not a failure
of built-in framework selection or the core scan path.
