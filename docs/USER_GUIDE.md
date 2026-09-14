# BC Agentic SAST Harness: User Guide

An agentic SAST pipeline. It points an LLM at a repository, surveys it,
threat-models it, decomposes it into analysis chunks, deep-dives each chunk
for findings, adversarially verifies them, dedups, analyzes exploit chains,
and emits a Markdown report, a SARIF 2.1.0 file, and a flat CSV export.
Optionally, it can also
propose automated fixes for verified findings and grade those fixes with a
second LLM pass, and post both findings and fixes as GitHub PR comments.

`bc-sast` is a **single binary with flags**. There is no
`scan`/`remediate`/`validate` subcommand split. One invocation of
`bc-sast --repo <path>` runs the whole scan pipeline (stages S0-S9);
adding `--remediate` chains on remediation (S10) and fix-validation (S11)
against that same run's findings, in the same process.

Stage S0 is the deterministic, LLM-free tree-sitter seed plane and runs
**by default** (`step0.enabled: true`). It walks the same scope S1 walks
(the orchestrator copies `step1`'s `exclude_dirs`/`exclude_exts`/
`exclude_globs`/`max_file_kb` onto it), so exclusions are configured once,
under `step1`. `--stop-after` only accepts `s1`..`s9`; there is no `s0`
stop point, because S0 spends no tokens and produces no report.

> **Findings are LLM-generated triage candidates, not confirmed
> vulnerabilities.** Human review is required. Runs are non-deterministic:
> two scans of the same repo may produce different findings.

---

## Quick start

```bash
bc-sast --repo /path/to/target \
    --gateway-base-url https://api.openai.com/v1 \
    --gateway-api-key "$OPENAI_API_KEY" \
    --dialect openai \
    --model gpt-4o
```

Writes `/path/to/target/security-scan/report.md`, `report.sarif`,
`report.csv` and `findings.json`. No flag asks for them; a scan always
writes what it produced, and `--out-dir` moves the whole set.

Point at an Anthropic-shaped endpoint instead:

```bash
bc-sast --repo /path/to/target \
    --gateway-base-url https://api.anthropic.com/v1 \
    --gateway-api-key "$ANTHROPIC_API_KEY" \
    --dialect anthropic \
    --model claude-sonnet-4-6
```

Scan, then propose fixes for the top 10 findings, picking interactively:

```bash
bc-sast --repo /path/to/target \
    --gateway-base-url https://api.openai.com/v1 \
    --gateway-api-key "$OPENAI_API_KEY" \
    --remediate -i --top 10
```

`--gateway-base-url` and `--gateway-api-key` can also come from the
`BC_GATEWAY_BASE_URL` / `BC_GATEWAY_API_KEY` environment variables (both
flags are wired with clap environment bindings in clap, so an exported var is picked up
automatically without retyping it on every invocation).

---

## 1. Modes

`bc-sast` doesn't have subcommands; it has a handful of flag combinations
that change what one invocation does:

| Mode | Trigger | What happens |
|---|---|---|
| **Plain scan** | `--repo` alone (`--gateway-base-url` always required) | Runs S0-S9, writes `report.md` + `report.sarif` + `report.csv`. Nothing else. |
| **Scan + remediate** | add `--remediate` | After the scan reaches a `FinalReport`, walks its findings with the remediation agent (S10), applying a minimal diff per finding via `Read`/`Glob`/`Grep`/`Edit`/`Write` tools. **Your checkout is not modified**: for a git `--repo` the edits happen in a throwaway detached worktree and come back as `security-scan/remediation.patch` (see §1f). S11 fix-validation then runs automatically afterward for each remediated finding (see below) unless disabled via `--config`'s `step_validate.enabled: false`. A no-op when the scan does not produce a report or any `--stop-after` boundary is selected, including S8 and S9. |
| **Interactive remediation** | `--remediate -i` (`-i`/`--interactive`) | Same S10 remediation, but findings are chosen live from an arrow-key terminal menu (falls back to a numbered prompt on a non-TTY stream) instead of being walked automatically top-N. Shows **every** finding (a profile's `step_remediate.top_n_findings` default is ignored) unless `--top` is also given explicitly on the same invocation. |
| **Remediate only** | `--remediate-from <findings.json>` | Skips SCANNING but not remediation: reads a findings JSON written by a prior run's `--out-findings-json` and remediates those findings directly. Everything `--remediate` supports still applies (`--top`, `-i`, the safety gates, worktree isolation, S11 validation, `--out-remediation-json`). The export carries the commit it came from, so the same HEAD-staleness refusal applies; `--force` overrides it. The prior run's `report.md`/`report.sarif` ARE augmented in place when they exist. See §1h. Mutually exclusive with `--remediate`. |
| **Post comments only** | `--post-comments-from <findings.json>` | Skips scanning entirely. Reads a findings JSON file written by a prior run's `--out-findings-json`, and posts/updates GitHub PR review comments for it. Requires `--github-token`, `--github-repo`, and `--pr-number`; errors out otherwise. `--repo` is still required as an arg but is unused in this mode. |
| **Post fixes only** | `--post-fixes-from <remediation.json>` | Skips both scanning and remediation. Reads a remediation JSON file written by a prior run's `--out-remediation-json`, and posts/updates GitHub fix-suggestion PR comments for it. Same GitHub-flag requirement as above. |
| **Baseline comparison** | add `--baseline <prior-run>` (or, in batch mode, a per-entry baseline field/column in the manifest) | The scan runs at full coverage; every finding is then classified `new` or `unchanged` against a prior run, and every prior finding missing now is reported `resolved`. Adds `baselineState` to `report.sarif`, a `## Baseline Comparison` section to `report.md`, and counts to the summary line. See §1g below. |
| **Diff-scoped scan** | add `--diff-scope` | The scan itself only hunts for vulnerabilities in the PR's changed files. The rest of the repo stays available as call-graph/import context, but nothing outside the diff gets newly chunked, deep-dived, or reported. Requires `--github-token`/`--github-repo`/`--pr-number`; see §1a below. |
| **PR comments** | add `--pr-comments` (with `--diff-scope`) | The scan posts/updates one PR comment per finding as it finishes. Off unless asked for: GitHub credentials alone let a run read the PR's diff, never write to its review thread. Passing it without `--diff-scope` is a startup error; see §1a below. |
| **Compliance-scoped scan** | add `--scan-framework <NAME>` | The scan runs at full coverage; findings are tagged with (and, optionally via `--compliance-scope filter`, narrowed to) the compliance-framework requirements they satisfy. See §1c below. |
| **Checkpoint gc** | `--gc` or `--gc-run <path>` | Skips scanning and remediation entirely. Prunes or evicts run/checkpoint state from the SQLite state DB (`$BC_STATE_DIR/bc-sast.db`, see `--resume`). `--repo` is still required as an arg but is unused in this mode; `<repo>/security-scan/` output is never touched. See §1b below. |
| **Batch scan** | `--repo-file <manifest>` | Skips single-repo mode entirely (mutually exclusive with `--repo`). Scans every repo listed in a `.txt`/`.csv` manifest in sequence, one independent scan per entry, writing a `batch_summary.md` roll-up. Refuses `--diff-scope`: a manifest names many repositories and a diff belongs to one pull request on one of them, so there is no single scope to resolve. See §1d below. |
| **Doctor** | `--doctor` | Skips scanning. Runs the same readiness checks as `--setup`, then (only if none of them block) one live gateway probe, then exits. See §1e below. |
| **Setup** | `--setup` | Skips scanning. Runs read-only, no-network readiness checks (gateway client/credentials, `git` on PATH, `--config` load), then exits. See §1e below. |
| **Estimate** | `--estimate` | Skips scanning. Prints a rough, no-network scope preview for `--repo` (file count, bytes, an approximate input-token count) and exits. See §1e below. |

`--post-comments-from` and `--post-fixes-from` exist so a scan/remediation
job and the (more privileged) job that posts PR comments can be separate
CI workflow steps, the same split GitHub Actions already forces for SARIF
upload from a fork PR (see `docs/github-action.md`).

### S11 fix-validation

Whenever `--remediate` runs in **batch mode** (i.e. not `-i`), each
remediated finding is, by default, immediately graded by a second LLM pass
(S11) that scores whether the applied diff actually fixed the finding
(`Fixed` / `PartiallyFixed` / `NotFixed` / `Unverifiable`). This is
`step_validate.enabled: true` by default, overridable per-run in a
`--config` YAML. Validation results are folded back into `report.md` and
`report.sarif` in a second write pass after remediation completes, and into
`--out-remediation-json` if requested. **Validation is never blocking**.
See `docs/validation.md` and `docs/compliance/AI_AGENT_SECURITY_REVIEW.md`
for why this is a real, documented consideration, not an oversight.

There is no separate `--mode fix|report-only` flag. Every `--remediate`
run attempts to apply patches directly, subject to the policy gate if
`--enforce-remediation-policy` is set (see §6, and
`docs/remediation.md`).

### 1f. Worktree-isolated remediation (the default)

When `--repo` is a git worktree, `--remediate` does **not** edit it.
`bc-sast` checks the same commit out into a throwaway detached worktree
under `$BC_STATE_DIR/remediation-worktrees/` (or the system temp dir if
the state dir can't be resolved), roots the write-capable agent there,
runs S10 and S11 against it, exports a unified diff, and deletes the
checkout again.

The fix arrives as **`<repo>/security-scan/remediation.patch`**, next to
`report.md`/`report.sarif`/`report.csv`, and applies from the repo root:

```bash
git apply security-scan/remediation.patch
```

The run summary prints the path. `--out-remediation-json`'s per-finding
`diff` fields are unaffected, so `--post-fixes-from` still posts PR fix
suggestions exactly as before.

| Flag | Default | Effect |
|---|---|---|
| *(none)* | isolated, for a git `--repo` | The behavior above. |
| `--remediate-in-place` | `false` | Edit `--repo` itself. This is the pre-isolation behavior and prints a warning that source files will be edited. |
| `--keep-remediation-worktree` | `false` | Don't delete the checkout. Inspect it, then `git worktree remove --force <path>` yourself. |

For default patch delivery without target testing, a non-Git `--repo`
(or a failed `git worktree add`) falls back to in-place with a printed note. Every S10 safety
gate still runs either way. See `docs/remediation.md` for the full
list and the CLI flags that tune them (`--no-syntax-check`,
`--keep-unverified`, `--max-diff-lines`, `--max-files-touched`,
`--remediate-dry-run`, `--verify-command`, `--verify-timeout`).

### Full-scan target testing and delivery

Add `--target-tests [LEVEL]` (alias `--testing-level`) to a full scan with
`--remediate`. A bare flag selects `comprehensive`. The built-in levels are
`discover`, `unit`, `integration`, and `comprehensive`; `e2e` and the older
`generate` spelling select comprehensive scope. Discovery runs first and
existing tests are inspected before missing tests are proposed. Suitable
existing suites can be retained without creating unnecessary new files.

Those levels inspect, generate and review tests but do not execute code.
Select `discovered-offline` to authorize discovered suites through compiled
ecosystem image and argv allowlists. Local pinned images must be available;
the target's own dependencies are installed from its lockfile by that
profile, in the only container of the run that has a network. A package
with no such lockfile, and any refused suggestion, remains a reported gap.
Changing policy content requires a source
change and rebuild. Requested scope is not a claim of completed coverage.
The workflow rejects diff-scoped scans, prior-report remediation, resume,
in-place remediation and any `--stop-after` selection.

Choose how accepted source and test changes are delivered:

| Flags | Result |
|---|---|
| `--remediation-delivery patch` (default) | Combined `security-scan/remediation.patch` from a Git worktree. Review and apply it to retain source fixes and tests in the target repository. |
| `--remediation-delivery branch --delivery-remote origin --delivery-branch bc-sast/fixes-run-123` | One commit containing all accepted changes, pushed to a new branch on the named remote. Selecting this mode authorizes the commit and push; existing branches are not replaced. |
| `--remediation-delivery zip` | Updated source and tests in `security-scan/remediated-source.zip`, prepared from an isolated source snapshot. Works without Git; CI must upload the ZIP using its own artifact mechanism. |

Branch and ZIP delivery require full-scan, non-interactive isolated
remediation, with or without target testing. They do not fall back to
in-place edits. Branch delivery needs a clean Git checkout; ZIP delivery
uses a bounded source snapshot and records excluded paths. Default patch
mode with target testing also requires a clean Git checkout. Delivery
records its outcome in `security-scan/delivery.json`; it does not establish
that generated tests ran or passed. A failed combined-patch export retains
the remediation worktree for recovery rather than deleting accepted tests.

See [target testing](target-testing.md), [built-in policies](built-in-policies.md)
and [remediation delivery](remediation-delivery.md) for restrictions,
validation states, excluded files and CI examples.

### 1g. Baseline comparison (`--baseline`)

`--baseline <path>` answers "what did this change introduce?" without
narrowing the scan. Unlike `--diff-scope` (which reduces what is
*analyzed*), the scan is unchanged; only the report gains a
classification:

```bash
# First run: keep its findings as the baseline.
bc-sast --repo . --gateway-base-url "$GW" --out-findings-json baseline.json

# Later run: classify against it.
bc-sast --repo . --gateway-base-url "$GW" --baseline baseline.json
```

The flag accepts **either** a prior `--out-findings-json` export or a
prior `report.sarif`, sniffed by content rather than by extension. A
`report.sarif` is still the better baseline: it carries the fingerprints
the earlier run actually computed (including a v2 taken against the code
*as it was*), so a resolved finding is re-emitted into this run's SARIF
byte-for-byte as it was described then. A findings JSON carries no
fingerprints (both are recomputed against the current tree), but it does
carry the whole typed finding record, so resolved findings from one are
rebuilt into real `absent` SARIF results through the same builder a live
finding's result comes from: `level`, `rank` and `security-severity` are
derived from the exported CVSS data, never fabricated. Either
way, a resolved alert reaches Code Scanning as `absent` and can be
closed.

Three matchers run in decreasing strength, each as a full pass over
everything still unmatched, so an exact pairing is never lost to a fuzzy
one:

1. `bc/findingId/v2`: path + the on-disk text of the finding's line
   range. The strongest signal, and unavailable when the file cannot be
   read.
2. `bc/findingId/v1`: rule id + path + the model's own quoted snippet.
   Survives a code edit as long as the model quoted the same text, and
   therefore matches a finding whose line number moved.
3. Same file, same vulnerability class, and either overlapping line
   ranges or start lines within `step7_dedup.line_tolerance`. This is the
   same rule this pipeline already uses to collapse duplicates *within* a
   run.

Matching is one-to-one. Anything unclaimed on this run's side is `new`;
anything unclaimed on the baseline's side is `absent` in SARIF (appended
to this run's results as a resolved alert; see `docs/outputs.md` for how
each baseline format builds one), rendered as "resolved" in the
Markdown.

A missing or unparseable baseline is a **hard error, before the scan
starts**. Comparing against nothing would report every pre-existing
finding as newly introduced, which is the opposite of what the flag was
asked for.

**In batch mode the baseline is per entry, not per batch.** A baseline is
one repository's prior findings, so a single file cannot classify several
repositories' scans. Applied to a second repo it would call every one of
that repo's findings `new` and every one of the baseline's `resolved`, a
confidently wrong answer a PR gate would then act on. So:

- Passing the top-level `--baseline` flag alongside `--repo-file` is
  **refused** with an error naming the per-entry alternative.
- Each manifest entry declares its own baseline instead: an optional 4th
  comma field in a `.txt` manifest, an optional `baseline` column in a
  `.csv` one. See §1d.

### 1h. Report augmentation in `--remediate-from` mode

`--remediate-from <findings.json>` remediates a prior run's export
without rescanning. When that prior run's report artifacts are still
where a scan would have left them, they are **augmented in place** with
this remediation's results, the same output an ordinary `--remediate`
scan produces:

- `report.md` gains a `#### Remediation` block under each remediated
  finding, a `#### Validation` block under each one S11 graded, and a
  report-level `## Remediation Summary`.
- `report.sarif` gains `remediationStatus` on each remediated result and
  `validationStatus`/`validationScore`/`validationJustification`/
  `mergeReadiness` on each validated one.

Where it looks: `--out-md`/`--out-sarif`/`--out-dir` when given,
otherwise the repo's own `security-scan/report.md` and
`security-scan/report.sarif`.
The run summary line says what happened to each (augmented, not found,
or left unchanged), naming the exact path in every case. Nothing is ever
created that wasn't already there; a missing prior report is reported,
not an error.

Three behaviors worth knowing:

- **The SARIF is stamped, not rebuilt.** The report this mode works from
  is reconstructed out of a findings export, which carries findings and
  nothing else: no app profile, no scan metrics, no degraded flag.
  Rebuilding `report.sarif` from it would blank out the `applicationId`,
  the invocation notifications and the run properties the earlier scan
  actually computed. So the prior document is read back and only the
  remediation/validation keys are written onto it; everything else
  survives byte-for-byte. Results are matched by their own
  `bc/findingId/v1` fingerprint, not by position, so a document that
  already carries `absent` results from a `--baseline` run still gets
  every annotation on the right result.
- **An already-augmented `report.md` is left alone.** A `--remediate`
  scan re-renders its Markdown from the run that just produced it and is
  therefore naturally idempotent; this mode appends to whatever is on
  disk, so re-running it against a report that already has a
  `## Remediation Summary` would stack a second, contradicting
  remediation block under every finding. It refuses instead. (The SARIF
  side has no such hazard: stamping a property twice overwrites it, so
  it is re-stamped every time.)
- **The augmenters fail closed.** If the report's numbered finding finding
  headings don't line up with the export (a report from a different
  scan, say), `report.md` is left byte-for-byte unchanged rather than
  risking a fix filed under the wrong finding, and the summary line says
  that the report was left unchanged.

### 1a. Diff-scoped scanning (`--diff-scope`)

A Rust-only feature. There is no equivalent in the original Python
harness. Every PR scan today (without this flag) re-analyzes the entire
repository, including pre-existing issues in files the PR never touched.
`--diff-scope` fixes the cost and noise of that by scoping the *analysis
itself* to the PR's changed files, while still giving the LLM the full
codebase as context: if `api.js` changes and imports `utils.js`, the
scanner still sees `utils.js` to correctly reason about that call, but
won't newly chunk, deep-dive, or report a pre-existing issue that happens
to live in `utils.js` when nobody touched it.

- **Requires** `--github-token`, `--github-repo`, and `--pr-number`: the
  diff is fetched from the PR itself, the same GitHub REST call
  `--post-comments-from` mode already uses for comment-anchoring, just run
  *before* the scan starts instead of after. Passing `--diff-scope` without
  all three is a hard error (mirroring the same precondition
  `--post-comments-from`/`--post-fixes-from` already enforce), not a silent
  no-op.
- **Reading the diff is not permission to write to the PR.** The three
  credential flags say which pull request the run is about. `--pr-comments`
  says whether the run may comment on it, and it is off by default, so a
  diff-scoped scan with a token still posts nothing unless asked to.
- **Fails hard, not silently, on a fetch error.** If the diff can't be
  fetched, the whole run fails rather than quietly falling back to a
  full-repo scan. A silent fallback would burn exactly the LLM spend this
  flag exists to avoid, without telling you it happened.
- **A diff that matches nothing scopes to nothing, not to everything.** A
  PR of only renames, deletions, mode changes or binary files carries no
  changed lines, so the parsed set is empty. That is a legitimate state,
  not an error: the run completes, analyzes nothing, prints a warning
  naming the likely cause, and the report still carries its scope line as
  `- Scope: PR diff (0 of N files)`. CI stays green. Earlier versions
  treated an empty set as "the flag was never passed" and quietly scanned
  the whole repository. S1 and S3 still make one model call each before
  every chunk is trimmed away, so the run is cheap rather than free.
- **A merge commit's conflict resolution is in scope, deliberately.** Scope
  is the merge-base (three-dot) diff GitHub returns for the pull request,
  so base commits the branch has merged in are correctly excluded. Hunks a
  merge commit introduced while *resolving* a conflict are part
  of head-versus-merge-base, and they are scanned. That is the safe
  reading: a change introduced during conflict resolution is exactly the
  kind that gets past review unnoticed, and excluding it would mean
  diffing each non-merge commit separately and unioning the results, which
  would leave a hole a scanner should not have.
- **No local `git diff` fallback.** The diff always comes from the GitHub
  API, and `--diff-scope` without `--github-token`/`--github-repo`/
  `--pr-number` is a hard error rather than a silent fall back to a
  full-repo scan. This is a genuine gap rather than a consequence of the
  runtime image: the packaged image ships `git` now, so a local-git path
  would be usable, but none is implemented. The GitHub API is also the
  only source that knows the merge base the pull request is actually
  measured against, which a local shallow checkout typically does not
  have.
- **What actually gets scoped**: S3 (decompose) trims every chunk's file
  list down to its intersection with the PR's changed files after all its
  other passes run (so taint-chain chunking still sees the full call
  graph before anything narrows), dropping any chunk that becomes empty.
  S4 (deep-dive) then enforces that scope in code (a finding reported on
  any file outside the trimmed chunk is dropped, not just discouraged by
  the prompt), so a model that reports on a call-graph-adjacent file it
  was shown as read-only context can't leak that finding into the report.
- **Known limitation**: cross-file context for a trimmed-out file is
  one-hop only (whatever's directly call-graph-adjacent to a file still in
  scope). A taint chain running `A` (changed) to `B` to `C` to `D`
  (changed), where `B`/`C` are both unchanged and only ever adjacent to
  each other (never directly to `A` or `D`), loses visibility into the
  *interior* of that chain, even though the chunk's own hypothesis (built
  by the taint-merge pass before trimming) still describes the full path.
  Not blocking for most PRs; worth knowing about for a change deep inside
  a long, otherwise-untouched call chain.
- **Report output**: `report.md`'s `## Scan Metrics` section renders an
  explicit `- Scope: PR diff (N of M files)` line whenever diff-scope was
  active, so a small `analyzed_files_unique`/`total_files_in_scope` ratio
  reads as "intentional diff-scope" rather than "the scan silently
  failed." Omitted entirely on a full-repo scan.
- **Third-party ingested findings are scoped too.** A Checkmarx/Snyk/
  Semgrep/Aikido/Sonatype finding joins the pipeline after S5, past the S3
  and S4 scoping described above, so it gets its own boundary check at the
  merge point. One in a changed file is verified and reported normally; one
  in a file the pull request never touched is **retained but not reported**,
  recorded with the drop reason `OUT_OF_DIFF_SCOPE` and rendered in
  `report.md`'s `## Dropped Findings` section tagged `[OUT OF DIFF SCOPE]`,
  counted on its own `Outside the PR diff` line, and surfaced in
  `report.sarif` as a run-level note. It is deliberately not deleted: this
  scan never examined that file, so it has neither confirmed nor refuted
  the vendor's claim, and a silent omission would read as "resolved". It is
  also not a finding, so it never reaches `findings.json`, `--pr-comments`,
  or remediation. See
  [`third-party-ingestion.md`](third-party-ingestion.md).
- **Remediation is fenced to the diff as well.** With `--diff-scope`, S10
  refuses to patch any finding whose file is outside the changed set, and
  records the refusal rather than skipping it silently. The refusal is
  checked before the policy gate and before the agent is called, on every
  route into remediation: the batch `--top` walk, the `-i` picker, and
  `--remediate-from`. See [`remediation.md`](remediation.md).
- **`--provider-writeback apply` cannot be combined with `--diff-scope`**,
  and is refused at startup. Publishing an assessment back to a vendor for
  a finding the scan never examined is the same error in a different place.

```bash
bc-sast --repo /path/to/target \
    --gateway-base-url https://api.openai.com/v1 \
    --gateway-api-key "$OPENAI_API_KEY" \
    --diff-scope \
    --github-token "$GITHUB_TOKEN" \
    --github-repo owner/name \
    --pr-number 123
```

#### Posting the findings back (`--pr-comments`)

Add `--pr-comments` to the invocation above and the scan posts/updates one
comment per finding when it finishes. Two rules shape it:

- **It must be asked for.** Earlier versions posted whenever
  `--github-token`/`--github-repo`/`--pr-number` were all present, which
  meant any CI job holding a token published to the review thread whether
  or not that was the intent, including jobs that only wanted the flag
  trio so `--diff-scope` could fetch a diff. Without `--pr-comments` the
  scan still runs and still writes `report.md`, `report.sarif` and
  `report.csv`; it just leaves the PR alone.
- **It requires `--diff-scope`, and says so at startup.** A comment is
  only worth posting where a reviewer is already reading. A finding
  outside the diff has no line to anchor to, so GitHub demotes it to a
  conversation comment, and a fix suggestion for a line the diff never
  touched has no commit button at all. A full-repo scan with commenting on
  buries the handful of remarks about the change under a wall of remarks
  about everything else, which is why the combination is refused before
  the scan starts rather than after it.

The same opt-in governs batch mode (`--repo-file`). `--post-comments-from`
and `--post-fixes-from` are unaffected: each of those *is* the explicit
request to post, and neither runs a scan.

### 1b. Checkpoint garbage collection (`--gc`)

`--resume` checkpoints accumulate one `runs` row (plus its checkpoint
blobs) per distinct repo path ever scanned with a checkpoint store
available. `--gc` prunes that state; it never touches `<repo>/security-
scan/` output. Neither `--gateway-base-url` nor any LLM/GitHub
credentials are needed in this mode. It only opens the local SQLite
state DB.

Two independent ways to invoke it, matching `cli.py::_gc`'s own two
branches:

- **Age/count-based pruning** (`--gc` alone): deletes every run older
  than `--gc-max-age-days` (default `5`) **or** beyond the
  `--gc-keep-runs` most-recently-touched (default `100`). A run is
  pruned if it matches *either* condition.
- **Targeted eviction** (`--gc-run <repo-path>`): fully evicts the one
  run for that repo path, ignoring the age/count limits above. Implies
  `--gc`.

`--gc-dry-run` reports what would be deleted/evicted without touching the
database, for either branch.

```bash
# Prune anything untouched for 5+ days beyond the 100 most recent runs
bc-sast --repo /path/to/target --gc

# See what a prune would do, without deleting anything
bc-sast --repo /path/to/target --gc --gc-dry-run

# Fully evict one repo's run (e.g. after renaming/removing a scan target)
bc-sast --repo /path/to/target --gc-run /old/path/to/target
```

### 1c. Built-in security frameworks (`--scan-framework`)

Select a framework bundled into the executable with
`--scan-framework <NAME>`. No external policy file or network fetch is
required. `--compliance-preset` remains a compatible spelling of the
same selector. Runtime `--compliance-policy <PATH>` is no longer supported;
edit the source policy and rebuild to change its content.

The shipped names are `asvs`, `pci-dss` (aliases `pci_dss` and `pcidss`),
`ssdf`, and `soc2`. Their YAML sources live in
`crates/bc-compliance/presets/`; `crates/bc-compliance/src/presets.rs`
embeds and registers them. Each source file records its framework version,
source citations, mapping assumptions, and known gaps. These are claims
and mappings maintained with the source, not an assertion that a scan
establishes compliance with the entire framework.

Each policy supplies two things:

- `guidance`, incorporated into S1/S3/S4/S6/S8 model prompts to focus
  security analysis without reducing the repository analysis scope.
- `requirements`, a CWE/vulnerability-class crosswalk used to tag
  findings before S8. S9 renders the resulting requirement tags.

This is framework guidance and finding classification, not an independent
signature engine or a proof that every requirement was tested. The S0
source/sink corpus is a separate detection mechanism. Selecting a
framework does not enable or require unavailable third-party providers.

Repeat `--scan-framework` to combine frameworks. Guidance is combined
in selection order and matching requirement IDs are unioned. Unknown
names and malformed embedded policies fail closed.

`--compliance-scope annotate` retains findings regardless of mapping;
this is the shipped presets' default. `--compliance-scope filter` moves
findings that match none of the active filter policies into
`report.dropped` before S8 builds chains. Multiple filter policies use OR
semantics. An unmapped vulnerability can still matter to a framework:
filtering is a report-scope choice, not evidence that an issue is safe.
In particular, the SOC 2 mapping is intentionally sparse, so annotating
is preferable to filtering when seeking broad security coverage.

```bash
# Add these flags to your normal configured scan command.
bc-sast --repo /path/to/target --scan-framework asvs

# Tag against both frameworks and retain unmapped findings.
bc-sast --repo /path/to/target \
    --scan-framework asvs --scan-framework pci-dss \
    --compliance-scope annotate
```

For source changes, rebuild instructions, and the named target-testing
profiles used with full-scan remediation, see
[Built-in policies and rule sources](built-in-policies.md).

### 1d. Batch scanning (`--repo-file`)

A deliberately **scoped, minimal** port of the Python original's
`orchestrator/batch.py` (~688 lines), not a full port; see the caveats
below. Mutually exclusive with `--repo`.

`--repo-file <manifest>` scans every repo listed in a manifest file, one
independent scan per entry, in sequence: no shared findings or
call-graph context between entries, and one entry's failure is recorded
and skipped rather than aborting the rest of the batch. Every entry
reuses the same model/gateway/`--config`/compliance/`--remediate` flags
as a single-repo run (`entry_cli` is a full clone of the top-level
`Cli`, with only `--repo`/`--repo-name`/`--app-id` and the output paths
overridden per entry) and writes its own `<path>/security-scan/` output,
isolated from every other entry. A top-level `--out-dir`/`--out-*` is
deliberately not applied per entry: one shared directory would have each
entry overwrite the last.

Two manifest shapes, dispatched on file extension (case-insensitive
`.csv` vs anything else):

- **`.txt`**: one entry per line,
  `application_id,repository_name,path[,baseline]` (blank lines and
  `#`-prefixed comments skipped). The 4th `baseline` field is optional; a
  three-field line is exactly as valid as it has always been.
- **`.csv`**: a header row plus one data row per entry. The header is
  case-insensitively aliased, so any of these column names work:
  - App ID: `AppID` / `application_id` / `app_id` / `applicationid`
  - Repo name: `RepoName` / `repository_name` / `repo_name` / `repo`
  - Path/URL: `Path` / `url` / `repo_url` / `ref`
  - Baseline (**optional**): `baseline` / `baseline_path` /
    `baseline_file`

  A leading UTF-8 BOM is stripped automatically; blank rows between data
  rows are skipped.

**Per-entry `--baseline`.** The optional baseline field/column gives that
one entry the same treatment `--baseline` gives a single-repo run (see
§1g): a prior `--out-findings-json` export or a prior `report.sarif`,
sniffed by content. Details:

- A **relative** path resolves against the *manifest's own directory*,
  not the process's working directory. A manifest is a checked-in
  artifact naming files that sit beside it, and it must mean the same
  thing wherever the batch is launched from. An absolute path is used
  as-is.
- The file must **exist at parse time**: a bad baseline fails the whole
  batch before the first scan starts, rather than after N repos have
  already been scanned.
- A blank cell (or an absent column/4th field) means "no baseline for
  this entry"; it never inherits a neighbor's.
- A baseline that exists but turns out to be unloadable fails **that
  entry only**, recorded in the summary like any other entry failure.
- The top-level `--baseline` flag is refused in this mode (see §1g).

In both shapes, the `path`/`Path` cell is either an **existing local
directory** or a **git URL**. Anything starting with `http://`,
`https://`, `git@`, `ssh://`, or ending in `.git` is treated as remote
and cloned (`git clone --depth 1`, 600-second bound) into `--workspace`
(default `./batch-workspace`) before scanning:

| Flag | Type | Default | What it does |
|---|---|---|---|
| `--workspace <DIR>` | `PathBuf` | `./batch-workspace` | Directory remote manifest entries are cloned into. |
| `--keep-clones` | flag | `false` | Don't delete a cloned repo's source after scanning it (the `security-scan/` report output is always kept either way). A local-directory entry is never touched regardless of this flag. |
| `--git-token <TOKEN>` | `Option<String>` (env `BC_GIT_TOKEN`) | none | Token used to authenticate an `http(s)` clone URL that doesn't already carry its own credentials (SSH URLs use the local SSH agent/keys instead and ignore this). Never logged or written to the batch summary, and always scrubbed from clone-failure error text too. |
| `--out-batch-summary <PATH>` | `Option<PathBuf>` | `./batch_summary.md` | Where the batch roll-up (see below) is written. |

A re-cloned destination is verified via a stage marker written to the
**operator-private state dir** (`$BC_STATE_DIR`, not `--workspace`
itself), so a workspace an attacker only partially controls can't forge
a marker to pass off a stale or foreign checkout as freshly cloned.

`batch_summary.md` is a Markdown table: one row per manifest entry
(`# | App ID | Repo | Status | Findings | New | Unchanged | Resolved |
Report`), `Status` either `OK` or `FAILED: <error>`, plus a `## Failures`
section listing each failed entry's error in full when at least one entry
failed. `New`/`Unchanged`/`Resolved` are that entry's baseline counts, or
`-` when it had no baseline (a dash, not a zero: "0 new" and "no
comparison was made" are different claims).

**Deliberately not ported**, both with rationale recorded in `batch.rs`'s
own module doc comment:
- **`--group-by-app`**: Python's version is a genuine scan-*scope*
  change (every repo sharing an app id staged under one directory and
  scanned as a single combined tree, so cross-repo call-graph edges are
  visible), not just a reporting grouping. Approximating it by grouping
  separate per-repo reports afterward would misrepresent what the flag
  actually does, so it's left unimplemented rather than faked.
- **Deriving a clone URL from a blank `Path`/`url` cell** via Python's
  `batch.git_base_url` config key. This port's manifest parsers always
  require the Path/url column to be non-blank instead.

```bash
# .txt manifest: the 4th field (this entry's own baseline) is optional
# and resolves relative to repos.txt's own directory.
cat > repos.txt <<'EOF'
app-42,payments-service,https://github.com/acme/payments-service.git,baselines/payments-service.sarif
app-42,payments-worker,/local/checkout/payments-worker
EOF

bc-sast --repo-file repos.txt \
    --gateway-base-url https://api.openai.com/v1 \
    --gateway-api-key "$OPENAI_API_KEY" \
    --workspace ./batch-workspace \
    --git-token "$GITHUB_TOKEN"
```

### 1e. Environment diagnostics (`--doctor` / `--setup` / `--estimate`) and automatic preflight

Three standalone commands, each skipping scanning entirely, plus a gate
that runs automatically before every real scan:

- **`--setup`** runs read-only, no-network readiness checks: gateway
  client/credentials, `git` on PATH, and (if `--config` was also passed)
  that the config file loads and passes the trust gate. Never makes a
  network call or spends a token. Ported from `vvaharness setup`, but
  deliberately scoped down to this port's single-gateway architecture,
  with no profile recommendation, `.env` scaffolding, shell-rc gateway
  auto-discovery, or rulepack-generation hints, none of which apply here.
- **`--doctor`** runs the exact same static checks as `--setup`, and
  then, only if none of them are blocking, one minimal live request
  through the gateway (`--model`, 4 max tokens) to catch bad credentials,
  an unreachable base URL, a TLS/proxy misconfiguration, or an unknown
  model id before a real scan spends real tokens. Ported from
  `vvaharness doctor`.
- **`--estimate`** is a rough, no-network, no-LLM-call scope preview: it
  walks `--repo`, counts files matching a fixed source-code extension
  set, sums their bytes, and divides by 4 for a crude token estimate.
  Deliberately prints no dollar figure (cost is model-dependent; this
  only projects scope). Ported from `vvaharness estimate`.
- **`--skip-preflight`**: every *real* scan (not `--doctor`/`--setup`/
  `--estimate`/`--gc`/etc.) automatically runs the same static checks
  plus a live probe before starting S1, and aborts with a non-zero exit
  if anything blocks. Pass this flag to skip that gate, e.g. when the
  gateway is already known-good and the extra probe's latency/spend
  isn't wanted, or the environment can't support one (an isolated CI
  runner with a mocked gateway).

**The probe retries a transient failure before it means anything.** It
makes up to three attempts with a 1 s then 2 s backoff, so a burst 429
(eight scans starting at once all hitting the same gateway) does not
refuse to start a scan the retry loop would have sailed through seconds
later. A *persistent* rate limit is reported as a **warning**, not a
block: the gateway is up and the key works, and the scan's own retry loop
handles exactly that. Only a real failure (bad credentials, an
unreachable base URL, a TLS/proxy misconfiguration, an unknown model id)
blocks. Static checks are evaluated first, and a blocking one short-
circuits the probe entirely: a known-bad key never spends a token.

Blocking-ness is per check, not per warning: a missing `--gateway-api-key`
and a `git` binary absent from `PATH` are both warnings, since a gateway
may need no key and `--git-sha` can stand in for `git`.

Sample `--doctor` output (`--setup`'s is identical minus the `[probe]` line):

```
  ✓ gateway client                http://127.0.0.1:8080 (Openai dialect)
  ✓ gateway API key                set
  ✓ git                            found on PATH
  3 ok · 0 warning(s) · 0 blocking issue(s)
  [probe] ✓ gpt-4o reachable
```

A blocking check instead prints `[probe] skipped: fix the blocking
item(s) above first` in place of the `[probe]` line, never attempting
the live request.

A blocking failure (e.g. a malformed `--ca-cert`) exits non-zero from
both `--doctor` and `--setup`, and (via the automatic preflight gate)
from a real scan too, without a `--skip-preflight` override.

---

## 2. Flag reference

All flags are `--long-form`; only `-i`/`--interactive` and
`-v`/`--verbose` have short aliases. Types/defaults below are taken
directly from the `Cli` struct in `crates/bc-cli/src/args.rs` and
cross-checked against `bc-sast --help`.

| Flag | Type | Default | What it does |
|---|---|---|---|
| `--repo <PATH>` | `PathBuf` | *(required unless `--repo-file`)* | Path to the repository to scan. Unused (but still required) in `--post-comments-from`/`--post-fixes-from` mode. |
| `--repo-file <PATH>` | `Option<PathBuf>` | none | Batch mode: a `.txt`/`.csv` manifest listing repos to scan. See §1d. Mutually exclusive with `--repo`. |
| `--workspace <DIR>` | `PathBuf` | `./batch-workspace` | Batch mode only: directory remote manifest entries are cloned into. See §1d. |
| `--keep-clones` | flag | `false` | Batch mode only: don't delete a cloned repo's source after scanning it. See §1d. |
| `--git-token <TOKEN>` | `Option<String>` (env `BC_GIT_TOKEN`) | none | Batch mode only: token for authenticating an `http(s)` clone URL. See §1d. |
| `--out-batch-summary <PATH>` | `Option<PathBuf>` | `./batch_summary.md` | Batch mode only: where the batch roll-up summary is written. |
| `--repo-name <NAME>` | `Option<String>` | repo dir's own name | Human-readable name for the report title. Ignored in `--repo-file` mode, where each entry's manifest-declared repository name is used instead. |
| `--model <MODEL>` | `String` | `gpt-4o` | Model identifier passed to every pipeline stage. |
| `--gateway-base-url <URL>` | `String` (env `BC_GATEWAY_BASE_URL`) | *(required)* | AI-gateway base URL (OpenAI-compatible or Anthropic-compatible). |
| `--gateway-api-key <KEY>` | `Option<String>` (env `BC_GATEWAY_API_KEY`) | none | AI-gateway API key. |
| `--ca-cert <PATH>` | `Option<PathBuf>` | none | Custom CA certificate (PEM) to trust for the gateway's TLS connection, e.g. for a private/self-signed gateway deployment. |
| `--dialect <openai\|anthropic>` | enum | `openai` | Which wire dialect the gateway speaks. |
| `--pricing-provider <ID>` | `Option<String>` | inferred from `--gateway-base-url` | Price the run's tokens at this [models.dev](https://models.dev) provider's rates (`openai`, `anthropic`, `openrouter`, and others). Needed only when the gateway host does not identify a provider, where the run is otherwise reported as unpriced rather than guessed at. Wins over `pricing.provider` in `--config`. See §10. |
| `--stop-after <s1..s9>` | `String`, case-insensitive | `""` (not provided) | Stop the scan after this stage. Empty string means "not provided", a raw `String` field rather than `Option<T>`, since a custom clap `value_parser` on `Option<T>` can't express "empty means None." |
| `--app-id <ID>` | `String` | `""` (not provided) | CMDB application id, for environmental-CVSS/OffensivePriority enrichment. |
| `--cmdb-csv <PATH>` | `String` | `""` (not provided) | CMDB CSV export path. |
| `--checkmarx-xml <PATH>` | `Vec<PathBuf>`, repeatable | none | Checkmarx CxSAST classic `CxXMLResults` XML report(s) to ingest. See `docs/third-party-ingestion.md`. |
| `--snyk-json <PATH>` | `Vec<PathBuf>`, repeatable | none | Snyk CLI JSON report(s) (`snyk test --json`, Open Source/SCA shape) to ingest. |
| `--semgrep-json <PATH>` | `Vec<PathBuf>`, repeatable | none | Semgrep native JSON report(s) (`semgrep scan --json`, SAST `results[]` shape) to ingest. |
| `--aikido-json <PATH>` | `Vec<PathBuf>`, repeatable | none | Aikido Security "Export Issues" API JSON export(s) to ingest. |
| `--sonatype-json <PATH>` | `Vec<PathBuf>`, repeatable | none | Sonatype Lifecycle/IQ Server raw report JSON export(s) to ingest. |
| `--semgrep-token <TOKEN>` | `Option<String>` (env `SEMGREP_TOKEN`) | none | Semgrep API token for a **live** fetch of the latest scan. See `docs/third-party-ingestion.md#live-vendor-api-fetch`. Requires `--semgrep-deployment-slug`/`--semgrep-repo` too, or the live fetch is silently skipped. |
| `--semgrep-deployment-slug <SLUG>` | `Option<String>` | none | Semgrep deployment/org slug. |
| `--semgrep-repo <owner/name>` | `Option<String>` | none | Repo name exactly as Semgrep tracks it. |
| `--semgrep-branch <BRANCH>` | `Option<String>` | none | Optional branch filter. |
| `--semgrep-base-url <URL>` | `Option<String>` | Semgrep's default SaaS host | Optional API base URL override. |
| `--snyk-token <TOKEN>` | `Option<String>` (env `SNYK_TOKEN`) | none | Snyk API token for a live fetch. Requires `--snyk-org-id`/`--snyk-project-id` too. |
| `--snyk-org-id <ID>` | `Option<String>` | none | Snyk organization ID. |
| `--snyk-project-id <ID>` | `Option<String>` | none | Snyk project ID (Snyk's own data model ties this to a specific branch already). |
| `--sonatype-base-url <URL>` | `Option<String>` | none | Sonatype Lifecycle/IQ Server base URL for a live fetch. Requires `--sonatype-username`/`--sonatype-password`/`--sonatype-app-id` too. |
| `--sonatype-username <USER>` | `Option<String>` | none | Sonatype username, or a generated user-token `userCode`. |
| `--sonatype-password <PASS>` | `Option<String>` (env `SONATYPE_PASSWORD`) | none | Sonatype password, or a generated user-token `passCode`. |
| `--sonatype-app-id <ID>` | `Option<String>` | none | The application's Sonatype `publicId`. |
| `--sonatype-stage <STAGE>` | `Option<String>` | `"build"` | Sonatype has no branch concept. This stands in for one (see doc). |
| `--aikido-client-id <ID>` | `Option<String>` | none | Aikido OAuth2 client ID for a live fetch. Requires `--aikido-client-secret`/`--aikido-repo-id` too. |
| `--aikido-client-secret <SECRET>` | `Option<String>` (env `AIKIDO_CLIENT_SECRET`) | none | Aikido OAuth2 client secret. |
| `--aikido-repo-id <ID>` | `Option<i64>` | none | Aikido's internal integer ID for this connected code repository. |
| `--aikido-base-url <URL>` | `Option<String>` | Aikido's EU SaaS host | Optional API base URL override (US/ME regional hosts). |
| `--checkmarx-base-url <URL>` | `Option<String>` | none | Checkmarx One data-plane base URL for a live fetch. Requires `--checkmarx-iam-url`/`--checkmarx-tenant`/`--checkmarx-api-key`/`--checkmarx-project-id` too. |
| `--checkmarx-iam-url <URL>` | `Option<String>` | none | Checkmarx One IAM (Keycloak) host, separate from the data-plane host. |
| `--checkmarx-tenant <TENANT>` | `Option<String>` | none | Checkmarx One tenant name. |
| `--checkmarx-api-key <KEY>` | `Option<String>` (env `CHECKMARX_API_KEY`) | none | Checkmarx One long-lived API key ("refresh token" in Checkmarx's own terminology). |
| `--checkmarx-project-id <ID>` | `Option<String>` | none | Checkmarx One project ID. |
| `--checkmarx-branch <BRANCH>` | `Option<String>` | none | Optional branch filter. |
| `--git-sha <SHA>` | `String` | `""` (not provided) | Commit sha to record as this scan's `report.git_sha`, used verbatim instead of shelling out to `git rev-parse HEAD`. Left unset, the shell-out is the fallback everywhere, including inside the packaged image, which ships `git`. Still recommended in the GitHub Action: the workflow authoritatively knows which commit it checked out, and a shallow or detached checkout can leave `git rev-parse` disagreeing with it. |
| `--out-dir <PATH>` | `Option<PathBuf>` | `<repo>/security-scan` | Directory every report is written into: `report.md`, `report.sarif`, `report.csv` and `findings.json`. Created if absent, before the scan starts, so a directory that cannot be created fails the run in a second rather than after a full run's model spend. Defaults inside `--repo`, not the working directory: the repo is the one location a scan is already guaranteed to have (the packaged image is read-only, working directory `/`), and per-repo defaults are what keep `--repo-file` entries from writing over each other. The four flags below override this per format. |
| `--out-md <PATH>` | `Option<PathBuf>` | `<out-dir>/report.md` | Markdown report output path. Moves only the Markdown report; the other three stay in the out-dir. |
| `--out-sarif <PATH>` | `Option<PathBuf>` | `<out-dir>/report.sarif` | SARIF output path. Moves only the SARIF report. |
| `--out-csv <PATH>` | `Option<PathBuf>` | `<out-dir>/report.csv` | Flat CSV findings export path (Snyk/Semgrep/Checkmarx-style: one row per finding). Written after S9 reporting; `--stop-after s8` publishes no CSV or other report files. Not re-augmented with S11 validation data after `--remediate`, unlike `report.md`/`report.sarif`. |
| `--no-threat-model` | flag | `false` | Disable step 2 (threat modeling). |
| `--max-tokens <N>` | `Option<u64>` | none (uncapped) | Cap total LLM token spend (prompt + completion) for the run. Checked at the S4-S7 stage boundaries **and** before each individual deep-dive chunk, verification session and semantic-dedup call. Tripping it does not abort. See §9. |
| `--max-scan-seconds <N>` | `Option<u64>` | none (uncapped) | Cap total scan wall-clock time, measured from the start of the scan. Same trip behavior as `--max-tokens`. See §9. |
| `--auto-step1` | flag | `false` | After clone, AI-survey the repo to derive additional `step1` exclusions (directories/extensions/globs, `max_file_kb`, `config_dedup`) and apply them before S1 runs. Also settable as `step1.auto_exclude`; this flag forces it on. `--resume` reuses a previously-written overlay instead of re-surveying. |
| `--no-auto-step1` | flag | `false` | Hard-disable the auto-exclude survey for this run, whatever `step1.auto_exclude` or `--auto-step1` says. Mutually exclusive with `--auto-step1`. |
| `--github-token <TOKEN>` | `Option<String>` (env `GITHUB_TOKEN`) | none | GitHub token used to fetch the PR's diff for `--diff-scope` and, when `--pr-comments` is also passed, to post/update PR review comments. Credentials on their own never post anything. |
| `--github-repo <owner/name>` | `Option<String>` | none | Repository the pull request lives in. |
| `--pr-number <N>` | `Option<u64>` | none | Pull request number this run is about. |
| `--pr-comments` | flag | `false` | Post this scan's findings to the pull request as comments. Off by default: the three credential flags say which PR the run is about, this one says it may write to it. Requires `--diff-scope`; passing it without is a startup error. See §1a. |
| `--github-api-base-url <URL>` | `String` (env `GITHUB_API_URL`) | `https://api.github.com` | GitHub REST API base URL; override for GitHub Enterprise Server. GitHub Actions runners already export `GITHUB_API_URL` correctly. |
| `--diff-scope` | flag | `false` | Scope the scan itself to the PR's changed files. See §1a. Requires `--github-token`/`--github-repo`/`--pr-number`; errors out otherwise. Fetching the diff is read-only and posts nothing on its own. |
| `--target-tests [LEVEL]` | `Option<String>` | disabled; bare flag selects `comprehensive` | Built-in testing level: `discover`, `unit`, `integration`, `comprehensive`; `e2e` and `generate` are aliases for comprehensive scope. `--testing-level` is an alternative spelling. Full-scan isolated remediation only; see [target testing](target-testing.md). |
| `--remediation-delivery <patch\|branch\|zip>` | `DeliveryMode` | `patch` | Choose combined patch, one pushed branch, or updated source ZIP. Branch and ZIP modes require full-scan isolated remediation; see [delivery](remediation-delivery.md). |
| `--delivery-remote <NAME>` | `Option<String>` | none | Named Git remote, required with branch delivery; paired with `--delivery-branch`. |
| `--delivery-branch <NAME>` | `Option<String>` | none | New destination branch, required with branch delivery; paired with `--delivery-remote`. |
| `--scan-framework <NAME>` | `Vec<String>`, repeatable | none | Built-in framework preset(s); `--compliance-preset` is an alias. Names: `asvs`, `pci-dss`, `ssdf`, `soc2`; see §1c. |
| `--compliance-scope <annotate\|filter>` | `String`, case-insensitive | `""` (each policy's own mode) | Override every active compliance policy's `scope_mode` uniformly for this run. See §1c. |
| `--out-findings-json <PATH>` | `Option<PathBuf>` | `<out-dir>/findings.json` | Findings-and-commit-SHA snapshot for a later `--post-comments-from` run. Written by every scan, like the three reports above; this flag only moves it. Silently skipped if the scan doesn't reach a `FinalReport` or has no known git SHA, since the commit is half of what the export is for. |
| `--post-comments-from <PATH>` | `Option<PathBuf>` | none | See §1. |
| `--baseline <PATH>` | `Option<PathBuf>` | none | Classify this scan's findings against a prior run's, either a `--out-findings-json` export or a `report.sarif`. See §1g. Hard error if unreadable. Single-repo only. It is refused with `--repo-file`, which takes a per-entry baseline from the manifest instead (see §1d). |
| `--config <PATH>` | `Option<PathBuf>` | none | YAML config file with per-stage settings and per-role model overrides. See `docs/configuration.md`. |
| `--cve-file <PATH>` | `Option<PathBuf>` | none (or `inject.cve_file`) | JSON feed of CVEs already filed against this codebase (a bare array or an object with a `cves` array). Rendered into S1's "Known CVEs already filed" block, S2's "KNOWN PRIOR CVEs" evidence block, S3's "KNOWN CVEs: DO NOT REDISCOVER" block, and S8's "KNOWN CVEs" chain-combination block. A missing file injects nothing; a structurally broken one warns and injects nothing (it is prompt context, not a gate). |
| `--controls-file <PATH>` | `Option<PathBuf>` | none (or `inject.controls_file`) | YAML list of compensating design controls already in place (bare list or an object with a `controls` list), rendered into the `DESIGN CONTROLS` block of S2, S3 and S8, and into S6's "DESIGN CONTROLS IN EFFECT ON THIS PATH" block (where the verifier must demonstrate a bypass to return TRUE_POSITIVE). Same missing/broken-file rules as `--cve-file`. |
| `--temperature <F>` | `Option<f64>` | none (provider default, `1.0`) | Sampling temperature for every stage. A `--config`'s per-role `models.<role>.temperature` wins over it. `--temperature 0` is the main run-to-run stability lever. See `docs/configuration.md` § Reproducible runs. |
| `--seed <N>` | `Option<u64>` | none | Deterministic-sampling seed for every stage; per-role `models.<role>.seed` wins. **OpenAI dialect only**. The Anthropic Messages API has no seed parameter. |
| `--top-p <F>` | `Option<f64>` | none | Nucleus-sampling cutoff for every stage; per-role `models.<role>.top_p` wins. The Anthropic dialect drops it when `temperature` is also set. |
| `--step-timeout <SECS>` | `Option<u64>` | none | Per-LLM-call wall-clock deadline for every stage. Unlike the sampling flags this OVERRIDES any `stepN.timeout` in `--config`. Without it, each stage uses its own configured value (S3/S8 `3600`, S4 `1800`) or the gateway client's 300 s default. |
| `--remediate [true\|false]` | `bool`, explicit-value-capable | `false` | Bare `--remediate` = `true`; also accepts an explicit value (`--remediate false`) so a static CI `args:` array can pass it unconditionally. |
| `--top <N\|all\|*>` | `Option<String>`, parsed | none (profile default, or uncapped) | Cap remediation to the top N findings by CVSS score (highest first), or `all`/`*` for every finding. |
| `-i`, `--interactive` | flag | `false` | See §1. |
| `--force` | flag | `false` | Override the S10 git-HEAD-staleness safety refusal: by default, remediation refuses to run if the repo's HEAD has moved since the scan ran (stale line numbers would misplace the agent's file:line evidence). |
| `--resume` | flag | `false` | Skip re-remediating a finding whose previously-saved checkpoint still matches it exactly. Checkpoints are always written when a checkpoint store is available; this flag only controls whether they're *consulted* before re-running. |
| `--enforce-remediation-policy` | flag | `false` | Enable S10's deterministic policy gate. See §6. |
| `--remediation-policy <PATH>` | `Option<PathBuf>` | none | The remediation policy YAML. Only consulted when `--enforce-remediation-policy` is set. |
| `--remediation-playbook <PATH>` | `Option<PathBuf>` | none | Per-CWE fix-strategy YAML injected into the agent's prompt on the policy gate's allow path. Only consulted when `--enforce-remediation-policy` is set. Config-side equivalents of the two flags above: `step_remediate.policy_file` / `step_remediate.playbook_file`, resolved against the `--config` file's own directory. |
| `--remediate-in-place` | flag | `false` | Edit `--repo` directly instead of a throwaway detached worktree. See §1f. |
| `--keep-remediation-worktree` | flag | `false` | Keep the throwaway remediation worktree on disk for inspection. See §1f. |
| `--no-syntax-check` | flag | `false` | Turn OFF S10's post-patch tree-sitter parse gate (`step_remediate.syntax_check`). A file that no longer parses otherwise rolls the whole patch back. |
| `--keep-unverified` | flag | `false` | Leave a patch applied even when the run didn't end in a clean `Fixed` verdict (`step_remediate.keep_unverified`). |
| `--max-diff-lines <N>` | `Option<usize>` | `200` | Roll a patch back when it adds+removes more than N lines (`step_remediate.max_diff_lines`); `0` disables. |
| `--max-files-touched <N>` | `Option<usize>` | `1` | Roll a patch back when it touched more than N files (`step_remediate.max_files_touched`); `0` disables. At the shipped `1`, any fix reaching into a second file is refused and reverted: the finding is still reported, with the refusal and its reason rendered on the finding's `Patch` line. Raise it to allow wider patches. |
| `--remediate-dry-run` | flag | `false` | Run every gate, then roll everything back regardless, keeping the diff, so `--out-remediation-json`/`--post-fixes-from` still produce fix suggestions (`step_remediate.dry_run`). |
| `--verify-command <CMD>` | `Option<String>` | none | A build/lint/test command S10 runs through `sh -c` in the repo root after the syntax and policy gates; a non-zero exit or timeout rolls the patch back (`step_remediate.verify_command`). Operator-supplied only (nothing the model or the scanned repo influences reaches it), and nothing runs unless it is set. |
| `--verify-timeout <SECS>` | `Option<u64>` | `600` | Wall-clock cap for `--verify-command` (`step_remediate.verify_timeout_secs`). |
| `--out-remediation-json <PATH>` | `Option<PathBuf>` | none | After remediation completes, write its per-finding verdicts (diffs, policy decisions, validation scores) as JSON, for a later `--post-fixes-from` run. |
| `--post-fixes-from <PATH>` | `Option<PathBuf>` | none | See §1. |
| `--remediate-from <PATH>` | `Option<PathBuf>` | none | Remediate a prior run's `--out-findings-json` export without rescanning, augmenting that run's reports in place. See §1h. Mutually exclusive with `--remediate`. |
| `--gc` | flag | `false` | See §1b. |
| `--gc-keep-runs <N>` | `usize` | `100` | Retain the N most-recently-touched runs when `--gc` runs (ignored otherwise, and ignored by `--gc-run`). |
| `--gc-max-age-days <N>` | `i64` | `5` | Delete runs untouched for more than N days when `--gc` runs (ignored otherwise, and ignored by `--gc-run`). |
| `--gc-run <PATH>` | `Option<PathBuf>` | none | See §1b. Implies `--gc`. |
| `--gc-dry-run` | flag | `false` | Report what `--gc`/`--gc-run` would delete without touching the database. |
| `--estimate` | flag | `false` | Print a rough, no-network scope preview for `--repo` and exit. See §1e. |
| `--doctor` | flag | `false` | Run environment-readiness checks plus a live gateway probe, then exit. See §1e. |
| `--setup` | flag | `false` | Run the same read-only readiness checks as `--doctor` (no live probe), then exit. See §1e. |
| `--stream-large-responses` | flag | `false` | Send any model call asking for at least 21,333 output tokens as a server-sent-event stream, reassembled into exactly the response a single JSON body would have carried. Off by default; turn it on when a gateway/proxy in front of the provider drops connections that go quiet for minutes. Also settable as `llm.stream_large_responses` in `--config` (the flag can only turn it ON). See §8. |
| `--skip-preflight` | flag | `false` | Skip the automatic pre-scan readiness gate that otherwise runs before every real scan. See §1e. |
| `--log-file <PATH>` | `Option<PathBuf>` | none | Write structured logs (DEBUG/INFO/WARN/ERROR) to this file, and only to this file: passing it turns off the automatic stderr stream, so behavior is exactly what it always was. Add `--log-stderr` for both at once. See §7. |
| `--log-stderr` | flag | `false` | Stream logs to stderr even when stderr is a real terminal, and alongside `--log-file` when that is given too. Without it, streaming turns itself on whenever there is no `--log-file` and stderr is not a terminal, which is the CI case. See §7. |
| `-v`, `--verbose` | count (0-3+) | `0` | Raise the level above the default `WARN`: once for `INFO`, twice for `DEBUG`, 3+ for `TRACE`. Applies to whichever destinations are active. `RUST_LOG` (standard `tracing-subscriber` `EnvFilter` syntax) takes precedence when set. See §7. |
| `--no-progress` | flag | `false` | Disable the live terminal progress bar. Already auto-disabled when stdout isn't a real terminal. This flag opts out explicitly even in an interactive one. See §7. |
| `-h`, `--help` / `-V`, `--version` | *(n/a)* | *(n/a)* | Standard clap help/version. |

`--repo` and `--gateway-base-url` are the only two flags with no default:
clap requires both on every invocation, including
`--post-comments-from`/`--post-fixes-from`/`--gc` mode (where `--repo` is
parsed but not actually used, and `--gateway-base-url` need not point
anywhere real since no LLM call is ever made in these modes).

---

## 3. Dialects and the gateway

`bc-sast` doesn't call a specific vendor SDK. It speaks one of two wire
protocols to whatever URL `--gateway-base-url` points at:

| `--dialect` | Wire shape | Talks to |
|---|---|---|
| `openai` *(default)* | OpenAI Chat Completions request/response shape | `https://api.openai.com/v1`, or any OpenAI-compatible gateway (e.g. Bifrost, Portkey) |
| `anthropic` | Anthropic Messages API request/response shape | `https://api.anthropic.com/v1`, or any Anthropic-compatible gateway |

Both dialects implement the same internal `LlmClient` trait, so tool
availability for remediation (`Read`/`Glob`/`Grep`/`Edit`/`Write`) is a
property of `bc-sandbox-tools`, not of which dialect you pick.

- `--gateway-base-url` (required) and `--gateway-api-key` (optional)
  configure the HTTP client used for every stage; every stage shares the
  same model/gateway/dialect unless a `--config` YAML overrides
  `models.<role>`.
- TLS verification is always on; there is no flag to disable it.
  `--ca-cert <PEM path>` adds a custom trust anchor on top of that, for a
  private or self-signed gateway; it does not weaken verification.
- `--model` sets one model id for every stage; per-stage/per-role overrides
  (`models.deepdive`, `models.remediate`, and others) are only available via
  `--config`. The roles are named by function rather than by stage number,
  so
  [`configuration.md`'s role-to-stage map](configuration.md#role-to-stage-map)
  is the lookup: it gives every `models.<role>` key, the stage it drives,
  what that stage does, and what supplies the model id when the role is
  left unset.

---

## 4. Output files

Written under the out-dir (`--out-dir`, default `<repo>/security-scan/`)
unless a per-format `--out-md`/`--out-sarif`/`--out-csv`/
`--out-findings-json` moves one of them. The first four need no flag to
ask for them: every scan writes what it produced, and the run summary
names each file. See `docs/outputs.md` for the full format reference:

| File | Written when | Contents |
|---|---|---|
| `report.md` | scan completes S9 | Findings report in Markdown, including the `## Executive Summary` section (see `docs/outputs.md` for every section and its exact shape). Augmented after remediation when a finding was processed, including S11 results when available. |
| `report.sarif` | scan completes S9 | SARIF 2.1.0. Same in-place re-write behavior as `report.md`. |
| `report.csv` | scan completes S9 | Flat, one-row-per-finding CSV in the same shape Snyk/Semgrep/Checkmarx export. Written once, never re-augmented with S11 validation data. |
| `findings.json` | scan completes S9 with a known Git SHA | `{ commit_sha, findings }`. Consumed by `--post-comments-from`. |
| `--out-remediation-json <PATH>` | flag passed and `--remediate` ran | Per-finding remediation verdicts, diffs, policy decisions and validation scores. Consumed by `--post-fixes-from`. The one export still opt-in, because it is only meaningful when remediation actually ran. |
| `--out-batch-summary <PATH>` (default `./batch_summary.md`) | `--repo-file` batch mode only, always written at the end of the batch | One row per manifest entry (status, findings count, per-entry baseline new/unchanged/resolved counts, report path) plus a `## Failures` section if any entry failed. See §1d. |

None of the files above are written unless their own precondition is
met. A `--stop-after s8` run publishes no report files; `--stop-after s9`
publishes them and stops before remediation. A mode that deliberately skips scanning
(`--post-comments-from`, `--post-fixes-from`, `--remediate-from`,
`--gc`/`--gc-run`, `--doctor`, `--setup`, `--estimate`) writes none of
them and creates no out-dir at all.

---

## 5. Environment variables

| Variable | Consumed by | Effect |
|---|---|---|
| `BC_GATEWAY_BASE_URL` | `--gateway-base-url` | Supplies the gateway URL if the flag itself is omitted. |
| `BC_GATEWAY_API_KEY` | `--gateway-api-key` | Supplies the gateway API key if the flag itself is omitted. |
| `BC_STATE_DIR` | remediation checkpoint store, `--gc`/`--gc-run` | Root directory for the checkpoint SQLite DB (`$BC_STATE_DIR/bc-sast.db`). Falls back to `$HOME/.bc-sast/state/bc-sast.db` if unset. Opened automatically whenever `--remediate` is passed; if opening it fails there, the run continues with a warning and `--resume` has no effect that run. In `--gc`/`--gc-run` mode a failure to open it is a hard error instead. The operator explicitly asked to touch the state DB, so a silent no-op would hide exactly the failure they'd want to know about. |
| `BC_NO_LOCAL_CONFIG` | `--config` loading | If set to a non-empty value, skips merging a sibling `config.local.yaml` found next to a `--config` file. |
| `BC_ALLOW_CWD_CONFIG` | `--config` trust gate | A `--config` file that resolves *inside* `--repo` is refused by default (defends against a malicious `config.yaml` checked into the scan target). Set this (non-empty) to opt out for a target you trust. |
| `GITHUB_TOKEN` | `--github-token` | Supplies the GitHub token if the flag itself is omitted. |
| `GITHUB_API_URL` | `--github-api-base-url` | Supplies the GitHub REST API base URL if the flag itself is omitted; GitHub Actions runners export this automatically. |

The remediation policy's own kill-switch env var name is **not** one of
the above. See §6; it's caller-defined per policy file.

---

## 6. Remediation policy gate (`--enforce-remediation-policy`)

**Off by default.** Repository path confinement, Git control-path
protection, per-session tool allowlists and baseline journalling apply
without this flag. CWE/path policy rules require explicit opt-in. See
[remediation](remediation.md) for current controls and
[implementation notes](implementation-notes.md) for the recent changes.
The earlier security review's claim that path confinement was the only
control predates these guards.

When enabled, `--remediation-policy <PATH>` points at a YAML file
(deny/allow CWE lists, `deny_paths`, `forbid_patch_paths`, and a
`kill_switch` block) evaluated **before** any patch-generation LLM call.
**This project ships no example policy file of its own**. The only
richly-populated policy YAML in the repo
(`crates/bc-yaml/tests/fixtures/remediation_policy.yaml.example`) is a
deliberately-preserved, byte-for-byte copy of the Python original's own
example, used only to test this project's YAML parser against real-world
input, not a template meant for end users (its
`kill_switch.env_var: VVAHARNESS_REMEDIATE_DISABLE` is a leftover from that
original and not this project's own naming). Enabling the gate with
neither `--remediation-policy` nor `--remediation-playbook` set means
every finding fails closed to guidance-only. Write your own policy file:

```yaml
kill_switch:
  env_var: BC_REMEDIATE_DISABLE   # any name you choose
  file:    ./.bc-remediate-off    # presence of this file also disables
default_action: deny
allow:
  CWE-89: "SQL injection is safe to auto-patch with parameterized queries"
deny:
  CWE-284: "access control issues are too risky to auto-patch"
deny_paths:
  - "**/migrations/**"
```

At runtime, if `policy.kill_env` is set, the harness reads that
environment variable and treats `"1"`, `"true"`, `"yes"`, or `"on"`
(case-insensitive) as "disable remediation": every finding is forced to
guidance-only. The kill file check is a plain existence test, independent
of the env var.

---

## 7. Observability: structured logging & the progress bar

Both are new capability, not ports. The Python original's own
"observability" was ad-hoc `print` calls to `sys.stderr` diagnostics with
no real level scheme. They are designed to never collide, and the rule
that keeps them apart is described below.

### Structured logging (`--log-file` / `--log-stderr` / `-v` / `RUST_LOG`)

Logs go to a file, to stderr, to both, or nowhere. Which one you get
depends on `--log-file`, `--log-stderr`, and whether stderr is a real
terminal:

| | stderr is a terminal | stderr is not a terminal (CI, piped) |
|---|---|---|
| **no `--log-file`** | nothing installed, silent | **stderr**, live |
| **`--log-file <PATH>`** | file only | file only |

`--log-stderr` adds stderr to every one of those four cells, including
the two that already write a file.

**Why stderr is the discriminator.** Two pieces of UI redraw in place
while a scan runs, and both of them write to stderr: the progress bar
and the `--interactive` picker. A log line arriving mid-frame corrupts
the display, which is why logs were file-only to begin with. Neither can
redraw when stderr is not a terminal, though: the progress bar hides
itself and the picker falls back to a numbered prompt that only appends
lines. So when stderr is not a terminal there is nothing to corrupt, and
the logs stream. That is the CI case, and it is the difference between
watching a twenty-minute scan and waiting for it to finish so you can
download an artifact. Nothing here reads `CI` or `GITHUB_ACTIONS`; it is
the same `is_terminal()` check the progress bar and picker already make.

On your own terminal the default is still silence. `--log-stderr` is how
to ask for logs anyway, and it pairs naturally with `--no-progress`:

```bash
bc-sast --repo /path/to/target --log-stderr --no-progress -v
```

Passing `--log-file` keeps that file as the only destination, so any
existing invocation behaves exactly as it did:

```bash
bc-sast --repo /path/to/target \
    --gateway-base-url https://api.openai.com/v1 \
    --gateway-api-key "$OPENAI_API_KEY" \
    --log-file ./scan.log -vv
```

Add `--log-stderr` to that command to watch the run and keep the file.

- Default level is `WARN` for every destination, including the stderr
  stream. Every `tracing::warn!` in this codebase marks an exceptional
  path (a skipped third-party scan file, a clamped S4 vote threshold, a
  transient LLM error being retried), so a healthy scan prints nothing
  and a stuck one prints the line that explains why.
- `-v` raises it once per repeat: `-v` = `INFO` (per-stage summaries),
  `-vv` = `DEBUG`, `-vvv`+ = `TRACE`. It is no longer ignored without
  `--log-file`; it applies to whichever destinations are active.
- `RUST_LOG` (standard `tracing-subscriber` `EnvFilter` syntax, e.g.
  `RUST_LOG=bc_stage_s4=debug,warn`) takes precedence over `-v` when set,
  for per-module filtering a single global `-v` count can't express.
- Lines are plain text with a timestamp, no ANSI color, on both
  destinations. GitHub Actions prefixes its own timestamp column when it
  renders the console, but the raw log you download or pipe elsewhere
  does not have one, so the subscriber keeps writing its own. There are
  no `::group::` markers: collapsing the output is the opposite of what
  a live view is for.

### Progress bar (`--no-progress`)

On by default whenever stdout is a real terminal (auto-disabled the same
way `cargo`/`npm`'s own bars are when output is piped or run in CI, so no
ANSI control codes ever leak into a non-interactive log). Pass
`--no-progress` to opt out explicitly even in an interactive terminal.
Renders, live: the current stage name, S3/S4 chunk progress (e.g. "chunk
7 of 23"), a running findings-found counter, elapsed time, and token
spend so far.

### The underlying event stream

Both consumers above are built on the same internal
`bc_pipeline_core::ScanEvent` stream emitted at stage boundaries and at
each S3/S4 chunk. There is no separate CLI flag for the event stream
itself; it always fires during a scan; `--no-progress` controls only
whether the bar renders it. The log stream above is separate: it carries
`tracing` events from the stages themselves, not these.

## 8. Streaming large model calls (`--stream-large-responses`)

Off by default. When enabled, any model call asking for at least
**21,333** output tokens is sent as a server-sent-event stream instead of
one JSON response body; the pieces are reassembled into exactly the
response body a non-streaming call would have returned, and parsed by the
same parser. Text, tool calls, token usage and stop reason are identical
either way: no stage can tell which mode ran, and nothing downstream
(reports, spend accounting, the progress bar) changes.

```bash
bc-sast --repo . --gateway-base-url "$GW" --stream-large-responses
```

Or in a `--config`:

```yaml
llm:
  stream_large_responses: true
```

The flag can only turn streaming **on**: a bare boolean flag has no
"explicitly off" spelling, so a config that already enabled it wins over
the flag's absence.

**When to use it.** A 64,000-token generation sends nothing at all until
it finishes. A gateway or proxy sitting in front of the provider with its
own idle timeout can read that silence as a dead connection and drop it.
Streaming keeps bytes flowing for the whole call. This port's per-call
deadlines (`stepN.timeout` / `--step-timeout`) already handle the
*client's* own timeout, which is why streaming wasn't ported initially,
but they can do nothing about an intermediary's.

**Which calls it affects.** On default settings, the single-shot stages
whose `max_tokens` clears the threshold: S2, S3, S4 and S8 (all `64000`).
S1 stays on the single-response path (`16000`), and so do the agentic
stages S6, S10 and S11: an agentic *turn* is bounded by `AgenticConfig`'s
own 16,000-token ceiling, and `step6_verify` has no `max_tokens` key at
all. Raise or lower a stage's `max_tokens` in `--config` and it moves
accordingly.

**What is unaffected.** Per-call timeouts still bound the *whole* stream,
not just its first byte (the deadline is a total one, applied from
connect until the response body finishes). Retries, the transient-error
classification, and the same-call parameter corrections (`temperature`
drop, `max_tokens` rename/clamp) all behave exactly as they do without
streaming. A rejected request is answered with an ordinary JSON error
document regardless of what it asked for. A provider error delivered
*inside* an already-successful stream fails the call with the same
`LlmError` the equivalent HTTP status would have produced, so a truncated
answer is never returned as a complete one.

**Where 21,333 comes from.** It is the ceiling the official Anthropic SDK
itself refuses to send a non-streaming request above. The Python original
streams unconditionally (`backends/sdk.py:288-289`) and has no threshold
of its own; adopting the SDK's avoids streaming every small call for no
benefit.

## 9. Spend caps, and what happens when one trips

Two flags cap a run. Neither has a default: omit both and the scan is
unbounded.

| Flag | Caps |
|---|---|
| `--max-tokens <N>` | Total LLM token spend for the run, prompt + completion. |
| `--max-scan-seconds <N>` | Total wall-clock time, measured from the start of the scan. |

**Where they are checked.** At the S4-S7 stage boundaries *and* before
each individual unit of work inside those stages: one deep-dive chunk
(S4), one verification session (S6), one semantic-dedup call (S5/S7). A
stage boundary alone is not a budget: a live scan given
`--max-tokens 3000000` spent 4.9 million, because cumulative spend was
still under the cap when S6 *started* and S6 then ran 1,881 verification
sessions to completion with nothing left to consult. That is why the gate
is readable from inside the loops.

**Tripping one does not abort the scan.** It stops *starting* new
stage-4-through-7 work, lets in-flight work finish, and falls through to
build the best report available. What that costs is reported honestly
rather than hidden:

- `## Scan Health` leads with a `⚠️ **BUDGET REACHED**` line naming which
  budget ran out and how far the scan got.
- Every candidate the verifier never examined becomes an `[UNCONFIRMED]`
  entry under `## Dropped Findings`, with the budget reason as its
  detail, **never** a finding. A budget that trips before S6 leaves
  nothing "verified"; reporting the survivors as true positives at 100%
  precision is the one thing the report must not do.
- `## Verification` counts them on its own `- Not verified (budget/time
  cap reached): N` line, and its precision figure divides by the findings
  actually **examined**, so an unexamined candidate is not charged
  against precision as though it were a false positive.
- `## Executive Summary` carries a `**Not examined**` bullet naming the
  stop reason.
- Deep-dive chunks the gate stopped before they ran are recorded as
  `skipped`, not `failed`: nothing failed, and they are excluded from
  both `chunks_failed` and `chunks_attempted`.

### Provider quota exhaustion is a budget stop too

An account with no credits left is **not** a transient error to retry.
Waiting does not put money back in it. OpenAI signals it as an HTTP 429
(`insufficient_quota`, `credit_balance_exhausted`, spend/usage-limit
wording), the same status as an ordinary rate limit; Anthropic as an HTTP
400 whose message says the credit balance is too low. Both map to
`LlmError::QuotaExhausted`, which is never retried, and the first S4 chunk
or S6 session to hit it **trips the same budget gate** from inside the
stage, so every other session in the run stops rather than rediscovering
the same fact independently. Before this, a CI run against an empty
account spent 80 minutes doing ~250 verification sessions × 6 retries × a
10 s backoff and produced nothing but a timeout.

The quota reason appears in the budget warning under `## Scan Health`,
in the `[UNCONFIRMED]` bullets for unverified candidates, and in the
executive summary's **Not examined** line. The fix is to top up the account and rerun, not to
raise a budget.

Transient retries that *are* worth retrying (a real 429, a 5xx, a dropped
connection) are logged at `WARN` with the error, the attempt number and
cap, and the backoff delay. `WARN` is the default level everywhere, so
these lines reach a CI console on their own (see §7) and a stalled run
says so while it is still running. On your own terminal they need
`--log-stderr` or a `--log-file`, and a `--log-file` is worth passing on
any scan you may need to explain afterward.

`max_budget_usd`, which a config written for the Python original may set
under `step1`/`step6_verify`/`step_remediate`/`step_validate`, is **not**
a third budget. In Python it was forwarded to the Claude CLI and Claude
Agent SDK backends, which enforce it themselves and which this port does
not have; the two routes this port's dialects correspond to ignore it
there too. It is no longer shipped as a default here, and a config that
still sets it loads with a warning naming the two caps above. See
`docs/configuration.md`'s key reference.

## 10. What the run cost

Every scan reports its own spend in dollars, beside the token counts it
already reported. Three places say it:

- the run summary line: `Scan complete: 7 finding(s). Cost (USD): 3.207750. Markdown: security-scan/report.md`
- `report.md`'s `## Scan Metrics`: a `- Cost (USD):` bullet for the run,
  and a `Cost (USD)` column on the per-phase `### Tokens by Phase` table
- `ScanMetrics` itself, and so every consumer of the serialized report:
  `cost_usd`, `unpriced_tokens`, `unpriced_calls`, `unpriced_models`

Rates come from a vendored snapshot of [models.dev](https://models.dev)
committed in `crates/bc-pricing/data/`, so a price change arrives as a
reviewable diff rather than as a silent change in what yesterday's scan
would have cost.

**Cost is summed one call at a time.** Several models charge more above a
context threshold, and one stage's calls land on both sides of it, so a
phase's summed tokens have no single correct rate. Each call is priced as
it returns and only the dollars are added up. See `docs/outputs.md` for
what that means for reading the table.

### Which provider is billing

The same model id costs different amounts under different providers: 775
ids in the captured table are published by more than one, and
`claude-sonnet-4-5` is 3.00 USD per million input tokens direct from
Anthropic and 3.75 through a reseller. So a rate cannot be looked up
without a provider, and what this scanner has is a base URL, not a
provider name.

The provider is resolved in this order:

1. `--pricing-provider <ID>`, if given.
2. `pricing.provider` in `--config`, if set.
3. Inferred from `--gateway-base-url`'s host, when that host is a
   first-party API endpoint whose operator is not in doubt
   (`api.openai.com`, `api.anthropic.com`, `openrouter.ai`,
   `<name>.openai.azure.com`, and a few dozen more).
4. Otherwise nothing, and the run is reported as **unpriced**.

Step 4 is deliberate, and it is what a private deployment, a
pass-through proxy such as Helicone, and a Cloudflare AI Gateway all get:
their host says nothing about who is billing, and a guess there does not
produce an approximate invoice, it produces a confident wrong one. An
unpriced run still reports every token; it just declines to put a dollar
figure on them:

```
Scan complete: 7 finding(s). Cost (USD): unpriced (1284310 token(s) had no published rate).
```

and, in `report.md`:

```
- Cost (USD): unpriced
- Unpriced tokens: 1284310 across 38 call(s) with no published rate (unidentified-provider/gpt-4o); the cost above is a lower bound
```

Set `--pricing-provider` to the provider whose rates that endpoint
actually resells, and the same run prices normally. The same line appears
on a partly priced run too, with a real figure beside it, marking the
total as a floor rather than an answer.

### Correcting the rates

A public rate table is exactly wrong for the case it matters most in: a
gateway on negotiated terms. `pricing.rates` in `--config` replaces
published rates with real ones, in the vendored file's own shape, so an
entry copied out of `crates/bc-pricing/data/models-dev-prices.json` is a
valid correction as it stands:

```yaml
pricing:
  provider: acme-gateway
  rates:
    acme-gateway:
      claude-sonnet-4-5:
        input: 1500000        # picodollars per token: 1.50 USD
        output: 7500000       # per million tokens
        cache_read: 150000
        cache_write: 1875000
```

Rates are integer picodollars per token, which is the published USD per
million tokens times 10^6. A provider id of `*` matches any provider, for
a deployment that fronts everything through one endpoint at one price. A
`rates` block the price table cannot parse is refused as a whole, with a
`[config] WARN` naming the problem, and the run falls back to published
rates: a typo must never leave you believing a negotiated rate was
applied when it was not.
