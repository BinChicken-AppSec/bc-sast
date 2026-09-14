# Output Formats

## On-disk layout

Per scan, under the **out-dir** (`--out-dir`, default
`<repo>/security-scan/`, created if missing):

- `report.md`: the Markdown report
- `report.sarif`: the SARIF 2.1.0 report
- `report.csv`: a flat CSV findings export
- `findings.json`: a `{commit_sha, findings}` snapshot, consumed later by
  `--post-comments-from <path>` to post/update GitHub PR review comments
  without re-running the scan
- `remediation.patch`: a unified diff, **only** written by a
  worktree-isolated `--remediate` run that actually produced edits (see
  "Worktree-isolated remediation" below). Not overridable.

**No output flag is needed for the first four.** A scan reaching S9 writes
the three report formats and, when a Git SHA is known, `findings.json`, and `--out-md`/`--out-sarif`/`--out-csv`/`--out-findings-json`
only MOVE one of them: each overrides the path for its own format alone
and leaves the other three in the out-dir
(`bc-cli::resolve_output_paths`). `--out-dir` moves the whole set at once.

The out-dir is created before the scan starts, so a directory that cannot
be created fails the run in a second rather than after a full run's model
spend, with an error naming the directory. It defaults inside `--repo`,
not the working directory: the repo is the one location a scan is already
guaranteed to have (the packaged image is read-only and its working
directory is `/`), and it is what keeps `--repo-file` batch entries from
writing over each other.

S9 is the explicit reporting step. It redacts the typed S8 report and
renders Markdown and SARIF without a model call or Markdown reparsing;
the CLI publishes these alongside CSV and the eligible findings export.
`--stop-after s8` writes none of these report files. `--stop-after s9`
publishes them and prevents remediation, even if `--remediate` is supplied.
`findings.json` additionally requires a known Git SHA. This matters for
Git-free ZIP delivery, where that export may be absent. The run summary
names each file it actually wrote.

One JSON export stays opt-in (no default path; omit the flag and nothing
is written):

- `--out-remediation-json <path>` (`--remediate`): one record per
  remediated finding, written when remediation runs after S9
  (regardless of git-SHA availability). Consumed later by
  `--post-fixes-from <path>` to post fix-suggestion comments. Not forced,
  because it is only meaningful when remediation actually ran.

Modes that deliberately skip scanning write no reports and create no
out-dir at all: `--post-comments-from`, `--post-fixes-from`,
`--remediate-from` (which augments a PRIOR run's reports in place where
they already exist, and creates nothing), `--gc`/`--gc-run`, `--doctor`,
`--setup` and `--estimate`.

If `--remediate` runs at all, `report.md` and `report.sarif` are
**rewritten in place** a second time after remediation completes, with
remediation results folded in, and validation results too when S11
validation ran (`bc-cli::augment_report_outputs`). The first,
pre-remediation write always happens the moment the scan itself finishes;
the second write happens whenever there is at least one remediation record
OR at least one validation score, so a `--remediate` run with
`step_validate.enabled: false` still gets its `#### Remediation` blocks.
`report.csv` is NOT part of this second pass. Like `findings.json`, it's
written once, from the pre-remediation scan outcome, and never carries
remediation or validation data.

### Worktree-isolated remediation

With default patch delivery and a Git `--repo`, `--remediate` edits a throwaway detached worktree
rather than the user's checkout, and exports the result to
`<repo>/security-scan/remediation.patch`, which is applicable from the
repo root with `git apply security-scan/remediation.patch`. It is written
only when the agent actually changed something (an empty `.patch` would
look like a produced-but-broken artifact), and never at all under
`--remediate-in-place` or for a non-git target, where the edits are
already on disk. The file list it is built from is `git status` inside
the worktree, not the agents' self-reported `changes[]`. See
[remediation](remediation.md).

### Target tests and delivery artifacts

The following paths stay under `<repo>/security-scan/`; `--out-dir` does
not relocate them:

| Artifact | When written and what it means |
|---|---|
| `target-tests.json` | Target-test preparation and validation evidence when `--target-tests` is enabled during full-scan remediation. Records discovery, compiled policy identity, model review, generated-file metadata, command results, and gaps. |
| `remediation.patch` | Default worktree delivery, when accepted edits exist. Contains source fixes and generated or extended tests together. |
| `remediated-source.zip` | Successful explicit ZIP delivery. Contains the updated isolated source tree, including accepted tests, with recorded exclusions. Git is not required. |
| `delivery.json` | Successful explicit branch or ZIP delivery receipt, including destination, exclusions, known scan revision, and scoped validation state. A delivery failure may produce no receipt. |

`--remediation-delivery branch` commits and pushes the combined accepted
changes to one explicitly named new branch. ZIP mode leaves original
source files unchanged and requires the consumer CI to upload the archive.
Both modes require a full scan and remediation, with or without target
tests. Neither changes the testing level or authorizes target execution.
A branch, archive, or generated suite is not evidence that tests passed.

Default patch delivery retains tests only in the combined patch until a
developer applies and commits it. Per-finding remediation JSON need not
contain tests generated before S10 and cannot replace that combined
artifact. See [target testing](target-testing.md) and
[remediation delivery](remediation-delivery.md) for reuse, gates, failure
handling, and command examples.

Checkpoints live in a SQLite DB at `$BC_STATE_DIR/bc-sast.db`, or
`$HOME/.bc-sast/state/bc-sast.db` if `$BC_STATE_DIR` is unset. They are
written by both the scan pipeline (one row per stage, keys `s1`..`s7`)
and S10 remediation (one row per finding), and read back only under
`--resume`. See "Checkpoint database" below.

`--repo-file` batch mode is the one exception to the layout above: each
manifest entry writes its own `<entry-path>/security-scan/` output
exactly as a single-repo scan would, `findings.json` included. A
top-level `--out-dir`/`--out-*` is deliberately NOT applied per entry:
one shared directory would have every entry overwrite the last, and a
remote entry's redirected reports would be deleted along with its clone.
On top of the per-entry output there is one roll-up file,
`--out-batch-summary` (default `./batch_summary.md`), written once, at
the end of the whole batch. See "`batch_summary.md`" below.

## `report.md`: Markdown report

The Markdown examples below illustrate content and ordering. Punctuation
is simplified for documentation; they are not byte-for-byte output
fixtures. JSON keys and other machine-readable identifiers are unchanged.

Rendered by `bc_report_md::render_markdown` (`crates/bc-report-md/src/lib.rs`).
Sections, in order, each independently omitted when its underlying data is
empty:

1. `# Agentic SAST : <repo name or repo root>` (title)
2. `## Summary`: always present (free-text scan summary)
3. `## Executive Summary`: always present; see its own section below
4. `## Scan Metrics`: omitted if `report.metrics` is `None`; carries the
   token counts and what the run cost, see its own section below
5. `## Scan Health`: omitted on a fully clean run (no degraded flag, no
   failed chunks, no per-stage errors, no budget stop). A
   `**BUDGET REACHED**` bullet leads the section whenever `--max-tokens`
   or `--max-scan-seconds` ran out, rendered verbatim as
   `- ⚠️ **BUDGET REACHED**: {budget_stop}. The scan stopped starting new
   work at that point; findings from the work not done are absent, and any
   finding listed as not verified was never sent to the verifier.`, where
   `{budget_stop}` names the budget and how far the scan got (e.g.
   `S6: token budget of 3000000 reached (3012044 spent): 412 of 1881
   finding(s) verified, 1469 left unverified`); the findings it never
   verified appear as `[UNCONFIRMED]` bullets under `## Dropped Findings`
   and are not counted as true positives
6. `## Threat Model`: omitted if `report.threat_model` is `None`
7. `## Verification`: always present. Seven bullets: raw findings, true
   positives, false positives, verifier errors, duplicates collapsed,
   `- Not verified (budget/time cap reached): N`, and
   `- Verification precision (of findings examined): X%`. An eighth,
   `- Outside the PR diff (third-party findings retained, not analyzed,
   not remediated): N`, renders between those last two on a `--diff-scope`
   run that ingested third-party findings from files the pull request
   never touched, and is omitted entirely otherwise. Those are counted
   there and in no other bullet: the scan formed no verdict on them, so
   folding them into false positives, verifier errors or the precision
   denominator would claim a judgement it never made. That last figure
   is true positives over the findings the verifier actually **examined**
   (`tp / (tp + fp)`), not over `raw_findings_count`. A budget stop
   leaves candidates unexamined, and charging each one against precision
   as though it were a false positive read a capped scan at 33.8% where
   the honest number was 74.8%. This deliberately diverges from Python's
   `verification_precision_pct`, which divides by the raw count; Python
   has no in-stage budget, so the two agree there.
8. `## Findings (N)`: always present (heading renders even at N=0); one
   block per finding, see template below
9. `## Exploit Chains`: omitted only when there are no chains **and** the
   scan is degraded; otherwise always renders (either the chain list or a
   "No exploit chains were identified" message)
10. `## Dropped Findings`: always present (`_None._` when empty). One
    bullet per dropped finding, tagged with its reason: `[FP]`,
    `[DUP of #N]`, `[DUP (pre-verify)]`, `[UNCONFIRMED]`, `[VERIFY-ERR]`,
    `[EXCLUDED]`, `[GUARDRAIL]`, or `[OUT OF DIFF SCOPE]`. The last one is
    the only tag that is not a judgement about the finding: it means the
    file was outside a `--diff-scope` run's changed set, so this scan never
    examined it (see
    [`third-party-ingestion.md`](third-party-ingestion.md))
11. `## Appendix: Scan Scope`: omitted if `report.metrics` is `None`
12. `## Appendix: Files Not Sent for Catch-All Review (call-graph
    unreachable)`: rendered only when `output.emit_unreachable_appendix`
    was set **and** `step3.catchall_mode: reachable_only` actually dropped
    files

Two further sections are appended after the fact rather than rendered by
`render_markdown`: `## Baseline Comparison` (a `--baseline` run) and
`## Remediation Summary` (a `--remediate`/`--remediate-from` run).

A **provider quota/billing failure is a budget stop too**, not a transient
error to retry. OpenAI reports an account with no credits as an HTTP 429
(`insufficient_quota`, `credit_balance_exhausted`,
`{organization,project}_spend_limit_exceeded`,
`organization_usage_limit_exceeded`), the same status as an ordinary rate
limit, and Anthropic as an HTTP 400 whose message says the credit balance
is too low. Both are classified as `LlmError::QuotaExhausted`, which is
**never retried** (waiting does not put money back in the account) and
which trips the same budget gate `--max-tokens`/`--max-scan-seconds` use:
the first S4 chunk or S6 finding to hit it stops the stage from starting
any more work. It surfaces exactly where a token/time stop does: as
`**BUDGET REACHED**: S6: provider quota exhausted: You exceeded your
current quota ...: 0 of 250 finding(s) verified, 250 left unverified` in
`## Scan Health`, as `not verified : provider quota exhausted : ...` on the
`[UNCONFIRMED]` bullets under `## Dropped Findings`, and named in the
`## Executive Summary`'s **Not examined** line. Findings it never reached
are neither confirmed nor ruled out; the fix is to top up the provider
account and rerun, not to raise a budget.

Transient retries themselves (a real 429, a 5xx, a dropped connection)
are logged at `WARN`: the error, the attempt number and cap, and the
backoff delay. `--log-file` is the **only** place they go. Logging is
file-only and opt-in (`bc_cli::logging::init_logging`) because the
`--interactive` picker and the progress bar own the terminal during a
scan, so a run without `--log-file` shows nothing at all while it retries.
Pass one on any scan you may need to explain afterwards.

### `## Scan Metrics`: what the run spent, in tokens and in dollars

Rendered by `bc_report_md::render_metrics`
(`crates/bc-report-md/src/metrics.rs`). Alongside the coverage and chunk
counts it carries three token bullets (`prompt`, `completion`, `total`,
each `unavailable` when no backend reported usage at all) and, when the
run recorded any spend, the money:

```
- Tokens (total): 1284310
- Cost (USD): 3.207750
```

The per-phase `### Tokens by Phase` table gains a `Cost (USD)` column on
the same figures:

```
| Phase | Calls | Prompt | Completion | Total | % | Cache-read (excl.) | Cost (USD) |
|---|---:|---:|---:|---:|---:|---:|---:|
| s4 | 23 | 812,004 | 61,220 | 873,224 | 68.0 | 2,140,880 | 2.242610 |
| s6 | 14 | 301,455 | 18,900 | 320,355 | 24.9 | 903,110 | 0.842739 |
| s1 | 1 | 74,551 | 16,180 | 90,731 | 7.1 | 0 | 0.122401 |
```

Three things about that column are deliberate.

**Cost is summed one call at a time, never derived from a phase total.**
Several models charge a higher rate above a context threshold (Anthropic's
long-context tier doubles the rate above 200,000 prompt tokens), and a
single stage's calls routinely land on both sides of it. A phase's summed
tokens have no single correct rate, so pricing them as one notional call
would be wrong by the whole tier difference, not by rounding. Each call is
costed as it returns, while its own context size is still known, and only
the dollars are added up. `bc-pricing` has no function that accepts a
summed token count, which is what keeps this true.

**Cache reads count toward the cost even though they are excluded from
the token totals.** They are cheap, not free, and on a cache-heavy agentic
scan they outnumber billable tokens by an order of magnitude. Each token
class is charged at its own published rate; a cache read is never charged
at the input rate.

**A missing rate is reported as missing, never as zero.** The cell reads
`unpriced` for a phase that spent tokens nothing could price, and `-` for
a phase that never billed anything. The run total then reads:

```
- Cost (USD): unpriced
- Unpriced tokens: 1284310 across 38 call(s) with no published rate (openai/house-blend-9); the cost above is a lower bound
```

The `- Unpriced tokens:` line renders whenever anything went unpriced,
including on an otherwise-priced run, where it marks the cost as a floor.
The names in it are exactly the keys a `pricing.rates` override is written
under, so the line doubles as the fix. See `USER_GUIDE.md` §10 for how a
provider is identified and how to correct it.

The same figures reach `ScanMetrics` itself, and through it every consumer
of the serialized report: `cost_usd` (`null`, never `0`, when no figure
can honestly be given), `unpriced_tokens`, `unpriced_calls`,
`unpriced_models`, and per-phase `cost_usd`/`unpriced_tokens` keys inside
`tokens_by_phase`. The `bc-sast` run summary line prints the same total
beside the findings count.

Remediation (`--remediate`) and fix validation are **not** included in any
of this. They run after the report is built and have never appeared in
`tokens_by_phase` either; the cost figure covers the scan model calls in S0-S8. S9 uses no model.
S9 adds no model calls. Target-test generator and reviewer usage from
completed sessions is recorded separately in `target-tests.json`, together
with requested model names and the compiled policy identity. It is not
added to the main scan cost; usage from failed sessions may be unknown.

### `## Executive Summary`

Rendered by `bc_report_md::render_executive_summary`
(`crates/bc-report-md/src/executive.rs`). It is a compact,
non-technical-stakeholder-facing readout, always present (unlike every
other section here, it's never conditionally omitted). Not a port; the
Python original has no equivalent section.

```
## Executive Summary

- **Findings confirmed**: 7 (2 critical, 3 high, 1 medium, 1 low, 0 info)
- **Noise reduction**: 22 candidate finding(s) were automatically reviewed : 7 confirmed real, 12 ruled out as false positives (31.8% verification precision among those examined).
- **Not examined**: 3 candidate finding(s) were never sent to the verifier because the scan stopped early (S6: token budget of 3000000 reached) : they are neither confirmed nor ruled out and are listed under Dropped Findings.
- **Code scanned**: 48,204 lines of code across 6 language(s)
```

- **Findings confirmed**: a per-severity breakdown of `report.findings`.
- **Noise reduction**: `report.raw_findings_count` (pre-verification
  candidates) vs. confirmed-true-positive count vs.
  `report.dropped`-filtered false-positive count, plus a precision
  percentage over the findings actually examined
  (`confirmed / (confirmed + false positives) * 100`, `0.0` when nothing
  was examined).
- **Not examined**: rendered only when at least one candidate was left
  unverified by a budget or time stop. It names the recorded
  `budget_stop` when there is one ("because the scan stopped early
  (<reason>)") and stays generic otherwise. These are neither confirmed
  nor ruled out.
- **Code scanned**: only rendered when `report.metrics` is `Some` and
  the summed `loc_scanned_by_language` is non-zero: total LOC and
  language count.

**Deliberately excludes any time-saved or ROI claim**: flagged during
scoping as an unsubstantiated claim this pipeline has no basis to make,
and left out on purpose, not an oversight.

### Finding-block template

Ported from `crates/bc-report-md/src/findings.rs::render_one`. Exact
field/heading order for one finding (`i` = 1-based position in
`report.findings`, in report order; this position is also what
`bc_report_md::augment_markdown` later matches by, and what
`--out-remediation-json`'s `finding_index` refers to):

```
### N. [SEVERITY] Title
**Class:** <CWE-NNN: name, or the vuln-class string if no CWE resolves>
**CWE:** CWE-NNN: name - https://cwe.mitre.org/data/definitions/NNN.html   (only if a CWE resolved)
**Also flagged as:** CWE-NNN (name), ...   (only if s7 dedup merged other CWE lenses on the same code range; see `step7_dedup.merge_same_range_cwes`)
**Compliance:** <requirement id>, <requirement id>   (only if an active compliance policy matched this finding)
**File:** `path:line_start-line_end`
**CVSS 3.1:** **9.8** (Critical) : `CVSS:3.1/...`   (or just the backticked vector if only the vector parsed, or `_not computed_`)
**VulContextSeverity:** `env-vector` - **score (rating)**   (only if a vsvs_score is set)
**OffensivePriority:** **Pn** - label | *reason*   (only if offensive_priority is set)
**Confidence:** 0.NN (N run agreed)   (singular/plural chosen on the vote count, not a literal `run(s)`)
**Also at:** `file:line`, ...   (or `file:start-end` when the collapsed duplicate carries a distinct end line; only if s7 dedup collapsed other call sites)

*N additional call site(s) collapsed during dedup : same root cause; each location needs the same fix applied.*   (only if duplicates present)

#### Description
<description body, markdown headings demoted>

#### Impact
<only if non-empty>

#### Exploit scenario
<only if non-empty>

#### Preconditions
- <bullet per precondition>   (only if non-empty)

```
<code_snippet, verbatim, inside a fenced code block>
```

#### How to fix
<recommendation, only if non-empty>

**Exploitability:** <exploitability_notes>

#### Adversarial verification
**Verdict:** TRUE_POSITIVE (confidence: 8/10) : <verdict_reason>

<verifier_reasoning>
```

(the `#### Adversarial verification` block only renders if `f.verdict` is
`Some(_)`; `verdict` wire strings are the literal `TRUE_POSITIVE`/
`FALSE_POSITIVE`, uppercased directly, not humanized; see
`crates/bc-report-md/src/wire.rs::verdict_str`. `SEVERITY` is
`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`.)

**`## Baseline Comparison`** (only with `--baseline`): appended at the very
end of the report by `bc_report_md::append_baseline_section`, after
remediation/validation have finished rewriting everything above it. It
opens with four lines: the baseline path, and the `New`, `Unchanged` and
`Resolved (absent from this scan)` counts, spelled exactly that way. Those
are followed by a `### New findings` list and a `### Resolved findings`
list, each entry rendered as ``- `file:line` : title``. Both lists are
omitted when empty; the counts are always rendered, because "0 new, 0
resolved against `<baseline>`" is the result a PR gate wants and an
omitted section is indistinguishable from a run where the flag was
forgotten. `Unchanged` is a count only; those findings are already listed
in full immediately above.

**Post-remediation `#### Remediation` subsection**: when `--remediate` ran,
`bc_report_md::augment_markdown_with_remediation` appends this block to
each remediated finding's own section (matched to the `### N. [...]`
heading by *position*, resolved from the record's stable `finding_id`;
see `docs/remediation.md`):

```
#### Remediation

- **Status:** Fixed
- **Summary:** <agent's 2-4 sentence summary>
- **Approach:** Automated fix applied by the Remediation Agent ...
- **Patch:** unified diff produced
- **Validation:** Fixed
- **Root cause:** <agent's root-cause prose>
- **Files changed:**
  - `app/db.py`
- **Remaining risks:**
  - ...
- **Recommendations:**
  - ...
```

The report then gains a trailing `## Remediation Summary` section with
the true-positive count, how many findings were in scope for remediation,
how many produced a patch, and the success rate. The whole augmentation
fails closed (report left byte-identical) if any record's index is out of
range for the headings present, or two records claim the same finding.

**Post-remediation `#### Validation` subsection**: when `--remediate` ran
with S11 validation enabled, `bc_report_md::augment_markdown`
(`crates/bc-report-md/src/augment.rs`) appends this block to the end of the
matching finding's own section (matched by heading *position*, not
content: `validations[i]` corresponds to the `(i+1)`th `### N. [...]`
heading):

```
#### Validation

**Status:** Fixed (score: 0.92)

<justification, trimmed>
```

`Status` is `fix_status.as_str()` on `bc_validation_scoring::FixVerdict`.
The four possible values are `"Fixed"`, `"Partially Fixed"`, `"Not Fixed"`,
and `"UNVERIFIABLE"` (this last one deliberately not title-cased, matching
the Python original's own wire vocabulary). This augmentation is a no-op
(report left byte-identical) if the number of `### N. [...]` headings found
doesn't exactly match the number of validation-slot entries. It fails
closed rather than guessing.

## `report.sarif`: SARIF 2.1.0

Built by `bc_sarif::build_sarif`/`build_sarif_with_validations`
(`crates/bc-sarif/src/lib.rs`), driven directly off the typed `FinalReport`
(no Markdown round-trip, unlike the Python original). Top-level shape
(`SarifDocument`):

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": {
        "name": "Agentic SAST",
        "version": "<bc-sast's own CARGO_PKG_VERSION>",
        "rules": [ { "id": "<vuln-class, kebab-case>", "name": "...", "shortDescription": {"text": "..."} } ],
        "supportedTaxonomies": [ { "guid": "b7c8d9e0-1f2a-3b4c-5d6e-7f8090a1b2c3" } ]
      }},
      "results": [ /* one per finding, see below */ ],
      "taxonomies": [ /* CWE taxonomy, same fixed guid */ ],
      "invocations": [ { "executionSuccessful": true, "toolExecutionNotifications": [ /* omitted if empty */ ] } ],
      "properties": {
        "applicationId": "",
        "cmdbSource": null,
        "applicationName": null,
        "scanDegraded": false,
        "unrankedFallback": false
      }
    }
  ]
}
```

`CWE_TAXONOMY_GUID` (`b7c8d9e0-1f2a-3b4c-5d6e-7f8090a1b2c3`) is a fixed
constant, deliberately stable across runs. `executionSuccessful` is `false`
only when the exploit-chain pass falls back (`report.degraded`); per-stage
`errors_by_stage` entries and a nonzero `chunks_failed` each add a
`"warning"`-level `toolExecutionNotifications` entry but leave
`executionSuccessful: true`.

### One SARIF result per finding

```json
{
  "ruleId": "injection",
  "level": "error",
  "message": { "text": "SQL injection  [CVSS 9.8: CVSS:3.1/AV:N/...]" },
  "locations": [ { "physicalLocation": {
    "artifactLocation": { "uri": "app/login.py" },
    "region": { "startLine": 10, "endLine": 12 }
  }}],
  "relatedLocations": [ /* one per collapsed duplicate call site; omitted key entirely if empty */ ],
  "rank": 98.0,
  "taxa": [
    /* the primary CWE first, then one entry per `related_cwes` lens S7 merged in */
    { "toolComponent": { "name": "CWE", "guid": "b7c8d9e0-..." }, "id": "CWE-89" }
  ],
  "partialFingerprints": {
    "bc/findingId/v1": "<40-char hex SHA-1>",
    "bc/findingId/v2": "<40-char hex SHA-1>"
  },
  "properties": {
    "severity": "high",
    "security-severity": "9.8",
    "cvssRating": "Critical",
    "category": "injection",
    "cvssVector": "CVSS:3.1/AV:N/...",
    "cwe": "CWE-89: SQL Injection",
    "cweId": "CWE-89",
    "cweName": "SQL Injection",
    "cvssScore": 9.8,
    "vulContextSeverityVector": null,
    "vulContextSeverityScore": null,
    "vulContextSeverityRating": null,
    "offensivePriority": null,
    "offensivePriorityLabel": null,
    "offensivePriorityReason": null,
    "confidence": 0.9,
    "votes": 1,
    "description": "<markdown body, truncated at 4000 Unicode chars + an ellipsis>",
    "dedupRelatedLocationCount": null,
    "validationStatus": null,
    "validationScore": null,
    "validationJustification": null,
    "mergeReadiness": null,
    "remediationStatus": null
  }
}
```

Every `Option<T>` field is **omitted entirely** when unknown
(`skip_serializing_if = "Option::is_none"`), not emitted as JSON `null`.
The sample above shows `null` only to enumerate the possible keys; a real
document simply won't have that key. `rank` = `cvss_score * 10` (SARIF's
0-100 scale), present only for a genuine non-negative score. `level` is
`error` for CRITICAL/HIGH, `warning` for MEDIUM, `note` for LOW/INFO
(`crates/bc-sarif/src/severity.rs::sarif_level`).

**`partialFingerprints` mechanism** (`bc_sarif::finding_id`, net-new versus
the Python original, which emits no fingerprint at all): a hex SHA-1 over
`rule_id + '\0' + normalized_path + '\0' + normalized_snippet`
(`crates/bc-sarif/src/fingerprint.rs::finding_fingerprint`), keyed under the
versioned property name `bc/findingId/v1` (`FINGERPRINT_KEY`). The path
strips a leading `./`; the snippet has all whitespace runs collapsed to a
single space. Deliberately excludes the line number, so a force-push that
shifts lines doesn't mint a spurious duplicate Code Scanning alert.

**A second key, `bc/findingId/v2` (`FINGERPRINT_KEY_V2`), ships alongside
it.** v1 hashes the snippet the *model quoted*; v2 hashes the
whitespace-normalized text actually **on disk** for `line_start..=line_end`,
with the normalized path and **no** `rule_id`. That makes v2 the stronger
identity (it survives the model rewording its own quote, and it re-classes
a finding when the code changed), while v1 survives a code edit
the model still quotes the same way. Both are emitted so a baseline
comparison can try the strong key first and fall back. v2 is **omitted**
when the file or the line range cannot be read; v1 is always present. See
`--baseline`'s three-matcher description in `USER_GUIDE.md` §1g.

The v1 hash is exposed as `bc_sarif::finding_id(&finding)` for any other
consumer that needs to refer to "this exact finding" consistently. It is
also how `bc-cli::RemediationRecordExport.finding_id` and
`bc-cli::augment_report_outputs` correlate an S11 validation score back to
the finding it belongs to.

**Validation properties** (`validationStatus`/`validationScore`/
`validationJustification`/`mergeReadiness`, `crates/bc-sarif/src/types.rs`):
populated only in the second, post-remediation SARIF write, via
`build_sarif_with_validations(report, tool_version, &by_id)` where
`by_id: BTreeMap<String, ValidationScore>` is keyed by the same
`finding_id`. `validationStatus` is `fix_status.as_str()`; `mergeReadiness`
is `bc_validation_scoring::derive_merge_readiness(fix_status).as_str()`
(`"Ready"` / `"Ready with Conditions"` / `"Not Ready"`). `build_sarif`
(used for the first, pre-remediation write) is a thin wrapper that always
passes an empty map, so every validation property is simply absent on that
first write.

**`baselineState`** (only with `--baseline`) is SARIF 2.1.0's own field,
set to `"new"` or `"unchanged"` on each of this run's results, and
`"absent"` on each baseline finding this run no longer reports. Emitting
the absent results is what lets a Code Scanning consumer *close* a
resolved alert rather than leave it open indefinitely, so **both**
baseline formats produce them, by different routes:

- From a **`report.sarif` baseline**, the earlier run's own result is
  re-emitted verbatim, re-tagged `"absent"`. Nothing is recomputed: that
  document already holds the fingerprints and the severity that run
  assigned, including a v2 fingerprint taken against the code *as it
  was*, which can no longer be derived now the finding is gone.
- From a **`--out-findings-json` baseline**, the result is rebuilt from
  the exported `bc_model::Finding` through `bc_sarif::
  build_absent_result`, the same `build_result` a live finding's result
  comes from. The export is a full typed record (CVSS score and vector,
  CWE, confidence, votes), so `level`, `rank` and `security-severity`
  are derived rather than fabricated. The one thing it does
  not carry is the severity band S8 assigned, which is reconstructed
  with `bc_stage_s8::final_severity` from the CVSS bands it does carry:
  the same function S8 used, and the same reconstruction
  `--remediate-from` relies on. The v2 fingerprint is whatever the
  loader could compute against the *current* tree, and is simply omitted
  when the file is no longer readable.

An absent result may name a `ruleId` this run's own `driver.rules` does
not declare (the resolved finding's class may not occur in this scan at
all). That is true of both routes and is accepted by SARIF consumers:
`ruleId` needs no matching `reportingDescriptor` when no `ruleIndex` is
given.

The annotation is applied by re-parsing the SARIF this run already wrote
and stamping it, so it cannot drift from `build_sarif`'s output; any
misalignment between results and findings leaves the document untouched
rather than mislabelled.

**`remediationStatus`**: S10's own verdict for this finding (`"Fixed"`,
`"Not Fixed"`, `"Denied"` and so on, or the policy gate's capped
`final_verdict` when it overrode the agent's), stamped on by
`bc-cli::apply_remediation_status` in the same second write, keyed by
`finding_id` like the validation properties, and absent for any finding
remediation never reached. It is deliberately separate from
`validationStatus`: that one is S11's *independent grade of a fix*, this
one is what the remediator itself concluded. A consumer needs both to
tell "no fix was attempted" (a work item) from "a fix was attempted and
rejected" (a triage signal).

## In-place augmentation by `--remediate-from`

`--remediate-from` runs no scan, so it produces no `report.md`/
`report.sarif` of its own. Instead it augments the PRIOR run's copies
where they still are (`--out-md`/`--out-sarif`/`--out-dir` when given,
else the repo's `security-scan/` defaults), with exactly the sections and
properties documented above for `--remediate`: `#### Remediation`,
`#### Validation`, `## Remediation Summary`, `remediationStatus` and the
`validation*`/`mergeReadiness` keys.

How that differs mechanically from the `--remediate` path
(`bc-cli::augment_prior_reports`), and why:

- **`report.sarif` is stamped, not rebuilt.** `--remediate` re-runs
  `build_sarif_with_validations` over the report it just produced. Here
  the report was reconstructed from a findings export, which carries no
  app profile, metrics or degraded flag. Rebuilding from it would drop
  the `applicationId`, the invocation notifications and the run
  properties the earlier scan wrote. The prior document is read back and
  only the remediation/validation property keys are set on it (through
  the same `bc_sarif::apply_validation` the builder itself uses), so the
  rest survives byte-for-byte.
- **Results are matched by `bc/findingId/v1`, not by position.** A prior
  `--baseline` run appends `absent` results, which makes the results
  array longer than the export's finding list; a positional zip would
  shift every annotation onto the wrong result.
- **An already-augmented `report.md` is left untouched.** This path
  appends to what is on disk rather than re-rendering, so a second
  `--remediate-from` would otherwise stack a contradicting remediation
  block under every finding. A report already carrying a
  `## Remediation Summary` is refused; the SARIF has no such hazard and
  is re-stamped every time.
- **Both augmenters fail closed**, exactly as they do post-`--remediate`:
  a heading count that doesn't match the export, or a SARIF document
  that doesn't parse as this tool's own, leaves the file byte-for-byte
  unchanged. The run summary line distinguishes "augmented", "no prior
  report at `<path>`" and "left `<path>` unchanged", naming the path in
  every case.

## `report.csv`: flat findings export

Built by `bc_csv::build_csv` (`crates/bc-csv/src/lib.rs`), driven directly
off the typed `FinalReport`. Not a port: the Python original never emitted
CSV either. One row per finding, columns matching the conventions industry
SAST tools (Snyk, Semgrep, Checkmarx) use for their own CSV exports, so an
existing spreadsheet/BI/ticketing pipeline that already ingests one of
those can ingest this the same way:

```
id,severity,cwe,cwe_name,vuln_class,title,file,line_start,line_end,cvss_score,cvss_vector,cvss_rating,confidence,votes,verdict,offensive_priority,compliance_requirements,description,recommendation
```

- **`id`** reuses `bc-sarif`'s own stable per-finding fingerprint
  (`bc_sarif::finding_id`) rather than minting a second identity scheme.
  The same finding's `id` in `report.csv` and `partialFingerprints` in
  `report.sarif` are identical, so the two formats can be joined directly.
- **`cwe`/`cwe_name`** use the same explicit-CWE-first,
  vuln-class-fallback resolution (`bc_cwe::cwe_for`/`cwe_name`) as
  `report.md`'s own `**CWE:**` line. Both are blank only when the finding
  is `VulnClass::Other` with no explicit CWE token.
- **`compliance_requirements`** is semicolon-joined (commas are the CSV
  delimiter), and empty when no compliance policy was active or matched.
- Text fields (`title`/`description`/`recommendation`/etc.) are
  RFC4180-quoted whenever they contain a comma, quote, or line break; a
  hand-rolled writer (`crates/bc-csv/src/writer.rs`) is used rather than
  an external crate, matching this project's dependency-minimization
  convention (`bc-enrich`'s CMDB CSV *parser* uses the same approach).
- Published after S9 from the typed report. `--stop-after s8` writes no
  CSV, Markdown, SARIF, or findings export; `--stop-after s9` publishes
  them subject to the findings export's Git-SHA requirement.
- Empty findings still produce a header-only file (one line), matching
  how `report.sarif` always emits a valid `results: []` rather than
  omitting the file.

## `findings.json` (`--out-findings-json` / `--post-comments-from`)

Written by scans that reach S9 with a known Git SHA,
at `<out-dir>/findings.json` unless `--out-findings-json` moves it.

```rust
struct FindingsExport {
    commit_sha: String,
    findings: Vec<bc_model::Finding>,
}
```

```json
{
  "commit_sha": "<git HEAD SHA at scan time>",
  "findings": [
    {
      "chunk_id": "c1",
      "file": "app/login.py",
      "line_start": 10,
      "line_end": 12,
      "vuln_class": "injection",
      "cwe": "CWE-89",
      "related_cwes": [],
      "title": "SQL injection",
      "impact": "...",
      "description": "...",
      "exploit_scenario": "...",
      "preconditions": ["..."],
      "recommendation": "...",
      "code_snippet": "...",
      "source_ref": null,
      "sink_ref": null,
      "backfilled_refs": [],
      "reanchored": [],
      "confidence": 0.9,
      "votes": 1,
      "duplicates": [ { "file": "...", "line_start": 0, "line_end": 0, "vuln_class": "...", "title": "", "chunk_id": "", "source_ref": null, "sink_ref": null, "reasoning": "" } ],
      "verdict": "TRUE_POSITIVE",
      "verdict_confidence": 8,
      "verdict_reason": "...",
      "cvss_vector": "CVSS:3.1/AV:N/...",
      "cvss_score": 9.8,
      "cvss_rating": "Critical",
      "verifier_reasoning": "...",
      "vsvs_vector": null,
      "vsvs_score": null,
      "vsvs_rating": null,
      "offensive_priority": null,
      "offensive_reason": "",
      "compliance_requirements": []
    }
  ]
}
```

Two fields record where a value came from rather than what it is.
`backfilled_refs` names any `source_ref`/`sink_ref` S5 synthesized from the
AST because the model left it empty. `reanchored` names any of
`line_start`/`line_end` that S4 rewrote after parsing, which happens only
for a temporal C/C++ finding (use-after-free, double-free, a
time-of-check-to-time-of-use race) reported at the release or check site
rather than at the later unsafe use. Both are empty on a finding nothing
touched, so a non-empty value is the audit trail for a line the pipeline
chose rather than the model.

Field names are plain snake_case Rust identifiers. Enum wire values:
`vuln_class` is kebab-case (`"injection"`, `"heap-overflow"`, ...);
`verdict` is SCREAMING_SNAKE_CASE (`"TRUE_POSITIVE"`/`"FALSE_POSITIVE"`).
`--post-comments-from` reads this same file back
(`bc_cli::post_comments_only`) to post/update PR comments without touching
`--repo` or the pipeline at all.

## `remediation.json` (`--out-remediation-json` / `--post-fixes-from`)

Written when `--remediate` runs after the scan completes S9
(no git-SHA precondition, unlike `findings.json`). Top-level shape
(`bc-cli::RemediationExport`):

```rust
struct RemediationExport {
    refused: Option<String>,          // Some(reason) if the S10 staleness preflight refused to run at all
    results: Vec<RemediationOutcomeExport>,
}

#[serde(tag = "status", rename_all = "snake_case")]
enum RemediationOutcomeExport {
    Processed(Box<RemediationRecordExport>),
    Failed { finding_index: i64, error: String },
}
```

```json
{
  "refused": null,
  "results": [
    {
      "status": "processed",
      "finding_index": 1,
      "finding_id": "<same 40-char SHA-1 as report.sarif's partialFingerprints>",
      "verdict": "<RemediationVerdict::verdict.as_str()>",
      "policy_action": null,
      "policy_reason": null,
      "final_verdict": null,
      "changes": [ { "file": "app/login.py", "summary": "parameterized the query" } ],
      "summary": "...",
      "diff": "--- a/app/login.py\n+++ b/app/login.py\n@@ ...",
      "validation": {
        "raw_score": 0.9,
        "fix_status": "Fixed",
        "justification": "fix verified",
        "gate_results": [
          {
            "gate_name": "...",
            "status": "...",
            "summary": "...",
            "evidence": [ { "file": "app/login.py", "line": 12, "snippet": "..." } ],
            "details": "...",
            "confidence": "HIGH"
          }
        ],
        "has_critical_failure": false
      }
    },
    { "status": "failed", "finding_index": 2, "error": "agent run exceeded max turns" }
  ]
}
```

`RemediationOutcomeExport` is internally tagged on `"status"`
(`"processed"`/`"failed"`), so a `Processed` record's own fields sit
alongside `"status"` at the same JSON object level, not nested under a
`"Processed"` key. `validation` is `Some(_)` only when S11 ran for that
specific finding. The remediation export carries the full
`ValidationScoreExport` (score, fix status, justification, and every gate's
own evidence), not just a status string. `--post-fixes-from`
(`bc_cli::post_fixes_only`) only reads `finding_id` + `diff` back out of
each `Processed` record with a non-empty diff. It ignores `validation`,
`policy_*`, and `changes` entirely, so `remediation.json` on disk carries
strictly more detail than what actually gets posted to GitHub as a
fix-suggestion comment.

`confidence` is `"HIGH"` or `"FLAGGED"` for a gate the S11 persona panel
synthesized (`bc_validation_scoring::SynthesisConfidence`), so triage can
see which gate lacked consensus without parsing the justification prose.
It is *absent*, not `null`, for a gate that never went through synthesis,
and the reader defaults it, so a `remediation.json` written before this
key existed still loads. `--post-fixes-from` reads only `finding_id` and
`diff` either way.

## `batch_summary.md` (`--repo-file` / `--out-batch-summary`)

Written once, after every manifest entry has been scanned (`bc_cli::
batch::write_batch_summary`): a Markdown table, one row per entry, plus
an optional failures section:

```markdown
# Batch Scan Summary

| # | App ID | Repo | Status | Findings | New | Unchanged | Resolved | Report |
| - | ------ | ---- | ------ | -------- | --- | --------- | -------- | ------ |
| 1 | app-42 | payments-service | OK | 7 | 2 | 5 | 1 | /workspace/payments-service/security-scan/report.md |
| 2 | app-42 | payments-worker | FAILED: preflight failed: ... | - | - | - | - | - |

## Failures

- **payments-worker** (app-42): preflight failed: ...
```

- `Status` is `OK` for a completed entry or `FAILED: <error>` for one
  that failed (parse error, clone failure, or scan failure). A failed
  entry never aborts the rest of the batch.
- `New` / `Unchanged` / `Resolved` are that entry's own `--baseline`
  counts, from the manifest's optional per-entry baseline field/column
  (see USER_GUIDE §1d), the same three numbers the single-repo summary
  line prints. All three are `-` when the entry had no baseline: a dash,
  not a zero, because "0 new" and "no comparison was made" are
  materially different claims.
- `Report` is that entry's own `report.md` path, always its `<path>/
  security-scan/` default (a top-level `--out-dir`/`--out-md` is not
  applied per entry). It is `-` when the entry never reached a
  `FinalReport`.
- Table-cell text (app id, repo name, error text) has `|` escaped and
  newlines collapsed to spaces, since manifest content and scan error
  text both flow into a Markdown table cell untrusted.
- The `## Failures` section is present only when at least one entry
  failed, listing each failed entry's error message in full (not
  cell-truncated).

## Checkpoint database (`--resume`)

SQLite, at `$BC_STATE_DIR/bc-sast.db`, or `$HOME/.bc-sast/state/bc-sast.db`
when `$BC_STATE_DIR` is unset **or empty**
(`bc_checkpoint::default_db_path`, `crates/bc-checkpoint/src/
sqlite_store.rs`). Schema:

```sql
CREATE TABLE IF NOT EXISTS runs (
  run_id     TEXT PRIMARY KEY,
  repo_root  TEXT NOT NULL,
  repo_name  TEXT,
  app_id     TEXT,
  started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_runs_updated ON runs(updated_at);

CREATE TABLE IF NOT EXISTS checkpoints (
  run_id     TEXT    NOT NULL,
  step       TEXT    NOT NULL,
  payload    BLOB    NOT NULL,
  size       INTEGER NOT NULL CHECK (size <= 104857600),
  created_at TEXT    NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (run_id, step)
);
```

(`PRAGMA journal_mode = WAL`, `foreign_keys = ON`, `busy_timeout = 30000`,
`synchronous = NORMAL`.) `checkpoints` deliberately carries no foreign key
to `runs`; the cascade is done in application code, in `delete_run`. A 100
MiB payload cap is enforced both at save time and by the `CHECK`
constraint.

This store backs **both** halves of `--resume`: the S1-S7 scan-pipeline
stage checkpoints and S10 remediation's per-finding ones. The scan writes
its checkpoints unconditionally and only *reads* them under `--resume`.

- `run_id` = `bc_checkpoint::run_id_for(repo)`: hex SHA-1 of the
  canonicalised repo path, truncated to 32 chars. That is one `run_id` per
  repo path, stable across separate invocations. Falls back to hashing the raw
  (unresolved) path if the repo can't be canonicalised.
- `step` = `"s1"`..`"s7"` for the scan pipeline's stage checkpoints, and
  `format!("remediate_{finding_index}")` for remediation, one row per
  finding position there, not per pipeline stage.
- `payload` = a JSON-serialized snapshot of the finding's identity hash
  (a SHA-1 over NUL-separated finding index/title/file/rendered body) plus
  the `RemediationRecord` produced for that finding.

`--resume` skips re-remediating a finding only when a saved checkpoint's own
identity hash matches the finding being processed *now*: same position,
title, file, and rendered body. Checkpoints are always written when the
store opened successfully, regardless of `--resume`; `--resume` only
controls whether they're **consulted** before re-running a finding. If the
default-location store can't be opened (e.g. an unwritable `$HOME`),
remediation degrades to no persistence with a warning on stderr. This is a
resume convenience, not a correctness requirement, so it never blocks a
`--remediate` run.

### Pruning the checkpoint database (`--gc`)

The DB grows one `runs` row (plus its checkpoint blobs) per distinct repo
path ever scanned with a store available. `--gc` prunes it and never
touches any `security-scan/` output:

- `--gc` alone deletes every run older than `--gc-max-age-days` (default
  `5`) **or** beyond the `--gc-keep-runs` most-recently-touched (default
  `100`). Either condition is enough.
- `--gc-run <repo-path>` fully evicts that one repo's run, ignoring both
  limits. Implies `--gc`.
- `--gc-dry-run` reports what either would delete without touching the
  database.

Both modes skip scanning entirely; `--repo` is still a required argument
but is unused. See `USER_GUIDE.md` §1b.

## A note on step 0

Nothing in this document reflects step 0's cost, because in its default
`rules` mode the seed plane spends no tokens at all: it is pure
tree-sitter static analysis. It runs **by default** (`step0.enabled:
true`) and walks exactly step 1's scope, so it also never widens
`total_files_in_scope`. Its output reaches these files only indirectly:
the framework routes and auth guards it extracts are what let S5's route
gate drop a "missing authorization" finding on a guarded handler, and its
seed taint paths are what `ast_backfill_evidence` uses to fill in a
finding's `source_ref`. Switching it to `callgraph_detection: llm` makes
it a real spender, and it then appears in `## Scan Metrics`' tokens-by-
phase table under `s0` like any other stage.
