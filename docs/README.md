# Docs

## Start here

- [Executive infographics](infographics/README.md): six presentation images
  covering scan modes, remediation, target testing and provider verification.
- [`solution-design.md`](solution-design.md): the high-level "what and
  why": purpose, goals/non-goals, context/component/deployment/trust-
  boundary diagrams (Mermaid, plus an editable
  [`diagrams/solution-design.drawio`](diagrams/solution-design.drawio)
  copy), and the key design decisions and trade-offs behind this port.

## Using `bc-sast`

- [`USER_GUIDE.md`](USER_GUIDE.md), the CLI reference: modes, the full
  flag list, dialects, output files, environment variables, the
  remediation policy gate.
- [`configuration.md`](configuration.md), the optional `--config` YAML
  file: merge/override order, `${VAR}` expansion, the config-trust
  boundary, the full key reference (including which keys are dead weight
  carried over from the Python original), `config.local.yaml`.
- [`outputs.md`](outputs.md), covering every file `bc-sast` writes:
  `report.md`'s and `report.sarif`'s exact shape,
  `findings.json`/`remediation.json`, and the S10 `--resume` checkpoint
  database.
- [`third-party-ingestion.md`](third-party-ingestion.md), on ingesting
  findings exported from Checkmarx, Snyk, Semgrep, Aikido, and Sonatype:
  supported formats, how ingested findings are re-verified through S6 and
  deduplicated through S7 alongside the LLM's own findings, and known
  per-vendor limitations. Also covers the **live vendor API fetch**
  flags (`--semgrep-token`/`--snyk-token`/`--sonatype-base-url`/
  `--aikido-client-id`/`--checkmarx-base-url` and their per-vendor
  siblings) that pull each vendor's latest scan of the same repo+branch
  directly over its own REST API, no manual export needed.

- [`provider-writeback.md`](provider-writeback.md): implemented S9 provider
  assessment proposals, automatic full-scan native API publishing,
  persistent state, provider scope, and validation limits.
  and empirical evaluation.

- [`built-in-policies.md`](built-in-policies.md): framework rules, testing
  profiles, source locations, and rebuilding after policy changes.
- [`target-testing.md`](target-testing.md): target test discovery, levels,
  generation, execution authorization, reuse, and validation limits.
- [`remediation-delivery.md`](remediation-delivery.md): combined patches,
  new branches, Git-free ZIP output, and CI artifact uploads.
- [`implementation-notes.md`](implementation-notes.md): current working-tree
  changes and the scope of checks performed on them.

## How it works

- [`comparison.md`](comparison.md), the measured head-to-head against the
  Python harness this port replaces: methodology, per-language results,
  cost, and what each side does better.
- [`diagrams/`](diagrams/README.md): Mermaid diagrams of the pipeline, the
  seed plane, the route guard gate, the finding lifecycle, the crate map
  and the recommended deployment model.
- [`architecture.md`](architecture.md): the crate-tier map, the S0-S9
  scan pipeline's data flow, the per-language knowledge in the S4 and S6
  prompts, and how S10 remediation and S11 validation hang off it.
- [`remediation.md`](remediation.md), stage S10: the agentic fix loop,
  finding selection, diff capture/revert, and the deterministic policy
  gate (`bc-policy-gate`).
- [`validation.md`](validation.md), stage S11: the validator panel (two
  personas always, an optional opt-in third) that grades an S10 fix, gate
  synthesis, and the deterministic scoring engine
  (`bc-validation-scoring`).

## Release

- [`../CHANGELOG.md`](../CHANGELOG.md): what changed, grouped by theme.
  `1.0.0` is the current release.

## Contributing

- [`../CONTRIBUTING.md`](../CONTRIBUTING.md): how to build and test, what a
  change has to clear before it merges (coverage, dependency vetting, a
  test that fails before the fix, documentation that matches the code),
  and the house style.
- [`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md): the behavioral
  expectations for this project's spaces, and how to report a problem.
- [`ISSUE_TEMPLATE.md`](ISSUE_TEMPLATE.md) and
  [`PULL_REQUEST_TEMPLATE.md`](PULL_REQUEST_TEMPLATE.md): what an issue or
  a pull request is expected to say. `../CODEOWNERS` names who reviews.

## Integrations and process

- [`deployment.md`](deployment.md). **Start here to roll this out**: build
  the image once, publish it to a registry you control, and pull it from
  each target repo's pull-request workflow. Self-hosted and hosted-runner
  variants, batch/scheduled scans, and exactly what the scanner needs
  network access to.
- [`github-action.md`](github-action.md): the GitHub Action (the
  no-registry alternative to the above), the fork-PR-safe two-workflow
  pattern, and how PR review comments and suggested-fix diffs get
  posted.
- [`supply-chain.md`](supply-chain.md): the dependency-vetting policy
  for anything added to `Cargo.toml`.
- [`parity-harness.md`](parity-harness.md): the Python cross-validation
  harness (`bc-parity-tests`, `parity/`) that checks this port's scoring
  logic against the real `vvaharness` source.
- [`coverage-exceptions.md`](coverage-exceptions.md): the full rationale
  behind every crate CI's 100%-coverage gate excepts, moved out of
  `ci.yml` itself so that file stays readable.

## Security posture

- [`compliance/CONTROL_MAPPING.md`](compliance/CONTROL_MAPPING.md):
  mapping against OWASP ASVS, NIST SSDF, PCI-DSS, and the PCI Secure
  Software Standard.
- [`compliance/AI_AGENT_SECURITY_REVIEW.md`](compliance/AI_AGENT_SECURITY_REVIEW.md):
  OWASP LLM Top 10, MITRE ATLAS, and AARM review, with a severity-ranked
  findings table and open recommendations. Read this before treating any
  configuration as production-hardened, especially before enabling
  `--remediate`.
- [`compliance/THREAT_MODEL_ATLAS.md`](compliance/THREAT_MODEL_ATLAS.md):
  a dedicated threat model built by walking all 16 MITRE ATLAS tactics in
  order against this system, with a risk register sorted by residual risk.
  Companion to the review above, not a duplicate of it.

See also the root [`README.md`](../README.md) for build/run basics and
[`SECURITY.md`](../SECURITY.md) for vulnerability reporting.
