# Executive infographics

Six presentation images based on the local implementation reviewed on
September 14, 2026. The artwork uses the repository banner's charcoal,
white and red palette without product names, logos or mascots.

Each PNG is 1672 by 941 pixels, approximately 16:9. Insert it as a picture
on a widescreen PowerPoint, Keynote or Google Slides slide, preserving its
aspect ratio. Text is part of the image, not editable slide text.

| Image | Main message |
|---|---|
| [01. Scan options](01-scan-options.png) | Choose repository-wide, change-focused or repeated per-repository assessment. |
| [02. Full scan](02-full-scan.png) | Connect code context and vulnerability verification to prioritized reporting. |
| [03. PR diff scan](03-pr-diff-scan.png) | Bring evidence about changed files into developer review. |
| [04. Batch scan](04-batch-scan.png) | Apply independent assessments across a repository manifest. |
| [05. Remediation and testing](05-remediation-and-testing.png) | Discover and extend target tests, propose isolated fixes, and deliver reviewable changes. |
| [06. Provider verification](06-provider-verification.png) | Feed supported verification outcomes back through optional native provider updates. |

For a short executive presentation, use 01, 03 and 05. Add 06 for an
audience concerned with scanner triage; use 02 and 04 for scan coverage
and operating-model discussions. These are conceptual workflow pictures,
not measured performance claims or screenshots of a dashboard.

## Speaker notes and implementation references

- Full scan means the configured repository scope. Exclusions, language
  support, budgets and failed analysis still limit coverage. The diagram
  compresses S0 through S8 into context, discovery and verification; S9
  reporting is shown separately. See
  [orchestration](../../crates/bc-orchestrator/src/lib.rs) and
  [reporting](../../crates/bc-orchestrator/src/reporting.rs).
- PR diff scanning selects changed files while retaining wider code
  context. Comments and suggested fixes are optional. Developers retain
  review and merge control. See `Cli::diff_scope`, `Cli::pr_comments` in
  [CLI arguments](../../crates/bc-cli/src/args.rs), and
  `resolve_diff_scope` in [CLI orchestration](../../crates/bc-cli/src/lib.rs).
- Batch runs are sequential and independent, with failures recorded per
  repository. There is no combined cross-repository attack-path analysis.
  The summary icon is illustrative, not an implemented dashboard. See
  [batch execution](../../crates/bc-cli/src/batch.rs).
- Target testing requires full scan and isolated remediation. Existing
  tests are inspected first. Generation does not establish that tests
  ran or that coverage is complete. Only an execution-enabled profile
  with a prepared environment permits execution. The approved profile
  is build-owned, not a per-test human approval prompt. Delivery remains
  subject to its configured gates. See [target testing](../target-testing.md),
  [delivery](../remediation-delivery.md), and
  [target-test implementation](../../crates/bc-cli/src/target_testing.rs).
- Provider updates require runtime opt-in and run after S9, before
  optional remediation. Each provider supports different actions and
  mutation scopes, which can extend beyond one branch. Missing findings,
  framework exclusions and unresolved analysis never authorize closure.
  See [provider write-back](../provider-writeback.md) and
  [automatic policy](../../crates/bc-cli/src/provider_publish/automatic_policy.rs).
- Live provider accounts, live target-test container execution and remote
  delivery retain the validation limits recorded in
  [implementation notes](../implementation-notes.md). These illustrations
  do not establish end-to-end validation, complete security or compliance.

## Provenance

These six images are AI-generated, and each carries C2PA provenance
metadata recording that. They were reviewed by hand for accuracy against
the documentation they illustrate.

One review note worth keeping: the testing graphic deliberately omits the
explanatory text the generator added around it, which read as though
discovery executes target code. It does not. `--target-tests` is opt-in and
the profiles that ship authorize no execution at all, as
[target testing](../target-testing.md) sets out.
