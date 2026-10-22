# Changelog

All notable changes to this project are recorded here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-10-22

Documentation only. No change to detection, verification, remediation or
any output schema.

### Changed

- `docs/comparison.md`: the feature comparison against upstream v1.5.0 now
  opens each cell with a Yes / No / Partial / Both verdict before the
  prose, and leads with a table of where each project is ahead. Previously
  every cell was prose, so telling who led a row meant reading both sides
  of it. Partial is never rounded up to Yes: the text after it names what
  is missing. No row was added or removed, and no benchmark number changed.
- Two rows in that table were reworded. "A failed graph build aborts the
  scan" was phrased as a negative, which made its verdict read backwards,
  and is now "Scan survives a failed structural build".
  "`findings.json` versioned" is now "carries a schema version". Both keep
  their original verdicts.

### Note for anyone resuming a 1.0.0 run

S10 and S11 checkpoints are keyed by engine version, which comes from the
package version. A checkpoint written by 1.0.0 will not be resumed by
1.0.1; the affected stage re-runs from the start. This is the existing
checkpoint contract, not a change to it.

## [1.0.0] - 2026-10-22

First public release. A Rust port of
[`visa-vulnerability-agentic-harness`](https://github.com/visa/visa-vulnerability-agentic-harness)
("vvaharness"), Visa's Apache-2.0 Python agentic SAST harness, ported
behaviour-for-behaviour up to upstream **v1.4.0** and benchmarked against
**v1.5.0**.

The binary is `appsec-scan`. One invocation runs the whole pipeline; there
are no subcommands.

### The pipeline

Twelve stages, S0 to S11. S0 is a deterministic tree-sitter seed plane
that spends no tokens: it builds a call graph, matches a source/sink
corpus across 11 languages, and hands the deep-dive real taint paths to
start from. S1 surveys the repository, S2 threat-models it, S3 decomposes
it into analysis chunks, S4 deep-dives each chunk, S5 pre-filters, S6
adversarially verifies, S7 dedups, S8 analyses exploit chains, S9 reports.
`--remediate` adds S10 (propose a fix) and S11 (grade it with a second
model pass).

### What it produces

A Markdown report, SARIF 2.1.0 with stable fingerprints, a CSV export, and
a structured `findings.json` carrying source and sink references. A run
manifest records the model, the wire API each role actually used, token
counts and cost. Dropped findings are reported with a tagged reason rather
than discarded silently, so a candidate the verifier refuted is
distinguishable from one a budget never reached.

### Capabilities

- **Two provider dialects.** OpenAI (Chat Completions and the Responses
  API, with per-role pinning) and Anthropic Messages, with a per-model
  capability table covering sampling rules, reasoning-effort tiers, output
  ceilings and cache minimums.
- **Request-side prompt caching** on both dialects, with cache reads
  priced separately so a report's cost figure reflects what was billed.
- **Diff-scoped scans** that neither report nor edit a file the pull
  request never touched, and opt-in pull request comments scoped the same
  way.
- **Remediation** behind safety gates: worktree isolation, a cross-file
  change never applied automatically, reverts by default, and a kill-file.
- **Target testing**, optionally running the scanned project's own tests
  around a fix, with dependency provisioning and an API-specification step.
- **Third-party scan ingestion** from five vendors, re-verified through S6
  and deduplicated with native findings rather than appended.
- **Compliance presets** for ASVS, PCI-DSS, SSDF and SOC 2. Net-new; the
  Python original has no equivalent.
- **Batch scanning** over a repository list, checkpoint and resume, token
  and wall-clock budgets, and a `--doctor` preflight that reports what each
  configured model accepts.

### Security posture

Repository contents and model output are treated as untrusted throughout.
The report sanitiser prevents injected model prose from restructuring the
report, including via setext underlines and mismatched code fences. The
output directory and checkpoint state refuse symlinks, since a link
planted in a scanned repository would otherwise redirect every artifact a
reviewer trusts. Secrets are redacted from logs and manifests, and the
gateway host is recorded without its scheme, port, path or credentials.

Dependencies are pinned and audited by `cargo-deny` on every run and on a
weekly schedule. This release ships `rustls` 0.23.46, `rustls-webpki`
0.103.16 and `webpki-root-certs` 1.0.10, which carry the fixes for
RUSTSEC-2026-0346 through 0349, 0382 and 0383.

### Known limitations

- **Findings are LLM-generated triage candidates, not confirmed
  vulnerabilities.** Human review is required.
- **Runs are not reproducible.** `--temperature 0` is sent and accepted,
  but the OpenAI Responses API has no `seed` parameter, so temperature is
  the only determinism control available and it is not sufficient. Two
  scans of the same commit can differ, and on the project's own test bed
  the same scanner over identical source has varied by up to 47 points of
  precision between runs. `step4.runs` enables vote-across-samples, which
  trades cost for stability.
- **Upstream v1.5.0's live exploit verification is deliberately not
  ported.** It sends attack traffic at a running application, which is
  dynamic testing and outside this tool's scope.
- Benchmark numbers in `docs/comparison.md` are three runs per application
  on eight small applications. Read the pooled totals rather than any
  single row; the document states its own noise floor.

### Documentation

`docs/USER_GUIDE.md` for flags and workflows, `docs/configuration.md` for
every configuration key, `docs/outputs.md` for the output schemas,
`docs/architecture.md` for the stage design, `docs/llm-transport.md` for
provider behaviour, and `docs/comparison.md` for the measured comparison
against upstream, including what it does worse.
