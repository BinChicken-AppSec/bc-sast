//! `bc-sast`'s clap `Cli` argument struct and its small enum/conversion
//! satellites — split out of `lib.rs` (task #109, mechanical code-health
//! cleanup) purely for file size; nothing here changes behavior.

#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use bc_orchestrator::StopAfter;
use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Parser)]
#[command(name = "bc-sast", version, about = "Agentic SAST scanner")]
pub struct Cli {
    #[command(flatten)]
    pub provider_publish: crate::provider_publish::ProviderPublishArgs,
    /// Path to the repository to scan. Unused (but still required) in
    /// `--post-comments-from` mode. Mutually exclusive with `--repo-file`
    /// (exactly one of the two must be given).
    #[arg(long, required_unless_present = "repo_file")]
    pub repo: Option<PathBuf>,

    /// Batch mode (scoped stub — see `batch` module doc comment): a
    /// manifest file listing repos to scan, either a plain `.txt`
    /// (`application_id,repository_name,path[,baseline]` per line, blank
    /// lines and `#`-prefixed comments skipped) or a `.csv` with a header
    /// row (`AppID,RepoName,Path` plus an optional `baseline` column,
    /// case-insensitively aliased — see
    /// `batch::parse_manifest_csv`'s own doc comment for the accepted
    /// aliases). Each `path`/`Path` cell is either an EXISTING LOCAL
    /// DIRECTORY or a git URL (cloned into `--workspace`, see that
    /// flag's own doc comment). Every entry is scanned in sequence with
    /// the same model/gateway/`--config`/compliance flags as a
    /// single-repo run, each writing its own `<path>/security-scan/`
    /// output, isolated from the others (one entry's failure is recorded
    /// and skipped, not fatal to the batch). Mutually exclusive with
    /// `--repo`. Deliberately NOT ported from the Python original's
    /// `batch.py`: `--group-by-app` (a genuine scan-scope change — one
    /// combined multi-repo scan per application — not just a reporting
    /// grouping, so approximating it here would be misleading rather
    /// than merely incomplete).
    #[arg(long, conflicts_with = "repo")]
    pub repo_file: Option<PathBuf>,

    /// Batch mode only: directory to clone remote manifest entries into.
    /// Ported from `vvaharness --workspace`, same default.
    #[arg(long, default_value = "./batch-workspace")]
    pub workspace: PathBuf,

    /// Batch mode only: do not delete a cloned repo's source after
    /// scanning it (the `security-scan/` report output is always kept
    /// either way — see `clone::purge_clone`). A LOCAL-directory
    /// manifest entry is never touched regardless of this flag; only
    /// clones this run itself created under `--workspace` are affected.
    #[arg(long)]
    pub keep_clones: bool,

    /// Batch mode only: token used to authenticate an `http(s)` clone
    /// URL that doesn't already carry its own credentials (injected as
    /// `x-access-token:<TOKEN>@host`; SSH URLs authenticate via the
    /// local SSH agent/keys and ignore this). Never logged or written to
    /// the batch summary — see `clone::scrub_url_secrets`.
    #[arg(long, env = "BC_GIT_TOKEN")]
    pub git_token: Option<String>,

    /// Batch-mode summary output path (default: `./batch_summary.md`).
    /// Ignored outside `--repo-file` mode.
    #[arg(long)]
    pub out_batch_summary: Option<PathBuf>,

    /// Human-readable name for the report title (defaults to the repo
    /// directory's own name). Ignored in `--repo-file` mode, where each
    /// entry's manifest-declared repository name is used instead.
    #[arg(long)]
    pub repo_name: Option<String>,

    /// Model identifier passed to every pipeline stage.
    #[arg(long, default_value = "gpt-4o")]
    pub model: String,

    /// Sampling temperature for EVERY stage, unless a `--config` sets
    /// that stage's own `models.<role>.temperature` (which wins).
    ///
    /// Omitting this sends no `temperature` at all, leaving the
    /// provider's default — `1.0` for both dialects, i.e. maximally
    /// divergent between two scans of the same repo. `--temperature 0` is
    /// the single biggest lever on run-to-run stability; see
    /// `docs/configuration.md`'s reproducible profile for the rest, and
    /// note that S4 clamps `runs > 1` to `1` at temperature 0 (N
    /// identical samples cannot vote).
    #[arg(long)]
    pub temperature: Option<f64>,

    /// Deterministic-sampling seed for every stage, unless a `--config`
    /// sets that stage's own `models.<role>.seed`. Sent only on the
    /// OpenAI dialect — the Anthropic Messages API has no seed parameter,
    /// so this is silently inert under `--dialect anthropic`. Even with a
    /// seed, providers document sampling as best-effort reproducible, not
    /// guaranteed.
    #[arg(long)]
    pub seed: Option<u64>,

    /// Nucleus-sampling cutoff for every stage, unless a `--config` sets
    /// that stage's own `models.<role>.top_p`. The Anthropic dialect
    /// drops it whenever `temperature` is also set, since the Messages
    /// API rejects the pair — prefer one or the other, not both.
    #[arg(long)]
    pub top_p: Option<f64>,

    /// Per-LLM-call wall-clock deadline, in seconds, for every stage —
    /// an OVERRIDE of any `stepN.timeout` a `--config` sets (unlike the
    /// sampling flags above, where the config wins), because this exists
    /// for the operator whose gateway is slower than the profile's author
    /// assumed. Omitting it leaves each stage at its own configured
    /// value, or the shared gateway client's 300 s default where there
    /// isn't one.
    #[arg(long)]
    pub step_timeout: Option<u64>,

    /// AI-gateway base URL (OpenAI-compatible or Anthropic-compatible).
    #[arg(
        long,
        env = "BC_GATEWAY_BASE_URL",
        required = false,
        required_unless_present = "publish_provider_plan",
        default_value_if("publish_provider_plan", clap::builder::ArgPredicate::IsPresent, "")
    )]
    pub gateway_base_url: String,

    /// AI-gateway API key.
    #[arg(long, env = "BC_GATEWAY_API_KEY")]
    pub gateway_api_key: Option<String>,

    /// Custom CA certificate (PEM) to trust for the gateway's TLS
    /// connection, e.g. for a private/self-signed gateway deployment.
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,

    /// Which wire dialect the gateway speaks.
    #[arg(long, value_enum, default_value_t = Dialect::Openai)]
    pub dialect: Dialect,

    /// Price this run's tokens at this provider's published rates, using
    /// the provider ids from <https://models.dev> (`openai`, `anthropic`,
    /// `openrouter`, ...). The same model id costs different amounts
    /// under different providers, so a rate table cannot be consulted
    /// without one.
    ///
    /// Normally unnecessary: the provider is inferred from
    /// `--gateway-base-url`'s host when that host is a first-party API
    /// endpoint. Set it for a private deployment, a proxy, or any
    /// endpoint whose host does not say who is billing, where the run is
    /// otherwise reported as unpriced rather than guessed at. Wins over
    /// `pricing.provider` in `--config`, which in turn wins over the
    /// inferred value. See `docs/outputs.md`.
    #[arg(long)]
    pub pricing_provider: Option<String>,

    /// Stop the scan after this stage (`s1`..`s9`, case-insensitive).
    ///
    /// A raw `String`, not `Option<StopAfterArg>` — an empty string
    /// (`action.yml`'s own `stop-after` input, when unset, has no
    /// meaningful default the way `--model`/`--dialect` do) means "not
    /// provided," normalized by [`crate::parse_stop_after`] right where
    /// this is consumed. A custom `value_parser` on an `Option<T>` field
    /// can't do this through clap's own derive machinery: it must return
    /// `T`, not `Option<T>` (clap wraps `Some(...)` itself when a value
    /// is present), so there's no way to make an explicitly-empty value
    /// parse to `None` that way — this was tried and reverted once
    /// already (see `docs/github-action.md`'s own history of this).
    #[arg(long, default_value = "")]
    pub stop_after: String,

    /// Path to a known-CVE feed (JSON — either a bare `[...]` list or a
    /// `{"cves": [...]}` wrapper). Its entries are stamped into the
    /// context package and rendered into S1's "Known CVEs already filed"
    /// block and S3's "DO NOT REDISCOVER" block, so the model spends its
    /// budget on what isn't already tracked. Ported from Python's
    /// `inject.cve_file`, which is also readable from `--config` (this
    /// flag wins). A missing file is not an error — it simply injects
    /// nothing.
    #[arg(long)]
    pub cve_file: Option<PathBuf>,

    /// Path to a design-controls file (YAML — a bare list of mappings or
    /// a `{controls: [...]}` wrapper) describing compensating controls
    /// already in place, rendered into S3's `DESIGN CONTROLS` block.
    /// Ported from Python's `inject.controls_file`; same flag-wins-over-
    /// config and missing-file-is-fine rules as `--cve-file`.
    #[arg(long)]
    pub controls_file: Option<PathBuf>,

    /// CMDB application id, for environmental-CVSS/OffensivePriority
    /// enrichment. A raw `String` (empty means "not provided") for the
    /// same reason as `--stop-after` above.
    #[arg(long, default_value = "")]
    pub app_id: String,

    /// CMDB CSV export path. A raw `String` (empty means "not provided")
    /// for the same reason as `--stop-after` above.
    #[arg(long, default_value = "")]
    pub cmdb_csv: String,

    /// Path(s) to a Checkmarx CxSAST classic `CxXMLResults` XML report.
    /// Repeat the flag to ingest multiple files in one run. Each
    /// finding is converted into this pipeline's own shape, re-verified
    /// through S6 alongside LLM-discovered findings, and deduplicated
    /// against them through S7 — see `bc-thirdparty`'s own doc comments
    /// for the exact format and mapping. Not a port — the Python
    /// original has no third-party SAST/SCA ingestion of any kind.
    #[arg(long)]
    pub checkmarx_xml: Vec<PathBuf>,

    /// Path(s) to a Snyk CLI JSON report (`snyk test --json`, Open
    /// Source/SCA `vulnerabilities[]` shape). Repeat the flag to ingest
    /// multiple files. See `--checkmarx-xml`'s own doc comment for how
    /// ingested findings are re-verified and deduplicated.
    #[arg(long)]
    pub snyk_json: Vec<PathBuf>,

    /// Path(s) to a Semgrep native JSON report (`semgrep scan --json`,
    /// `results[]` shape — SAST only, not Semgrep Supply Chain's
    /// separately-shaped `vulns[]`). Repeat the flag to ingest multiple
    /// files. See `--checkmarx-xml`'s own doc comment for how ingested
    /// findings are re-verified and deduplicated.
    #[arg(long)]
    pub semgrep_json: Vec<PathBuf>,

    /// Path(s) to an Aikido Security "Export Issues" API JSON export (a
    /// plain JSON array of issue objects). Repeat the flag to ingest
    /// multiple files. See `--checkmarx-xml`'s own doc comment for how
    /// ingested findings are re-verified and deduplicated.
    #[arg(long)]
    pub aikido_json: Vec<PathBuf>,

    /// Path(s) to a Sonatype Lifecycle/IQ Server raw report JSON export
    /// (`components[].securityData.securityIssues[]` shape). Repeat the
    /// flag to ingest multiple files. See `--checkmarx-xml`'s own doc
    /// comment for how ingested findings are re-verified and
    /// deduplicated.
    #[arg(long)]
    pub sonatype_json: Vec<PathBuf>,

    /// Live vendor API fetch — pulls each configured vendor's *latest
    /// scan of this same repo+branch* directly over its own REST API,
    /// instead of requiring an operator to export a report file by hand
    /// first (the `--checkmarx-xml`/`--snyk-json`/etc flags above). Each
    /// vendor group below is all-or-nothing: every required flag in the
    /// group must be present (like `--github-token`/`--github-repo`/
    /// `--pr-number`) or that vendor's live fetch is silently skipped —
    /// this is purely additive alongside the file-based flags, both feed
    /// the same S6-verify/S7-dedup pipeline. Not a port — the Python
    /// original has no third-party SAST/SCA ingestion of any kind.
    /// Semgrep API token (`apidocs.semgrep.dev`'s own bearer token —
    /// never expires). Required, with `--semgrep-deployment-slug` and
    /// `--semgrep-repo`, for a live Semgrep fetch.
    #[arg(long, env = "SEMGREP_TOKEN")]
    pub semgrep_token: Option<String>,
    /// The Semgrep deployment/org slug (visible in the Semgrep AppSec
    /// Platform URL) findings are fetched from.
    #[arg(long)]
    pub semgrep_deployment_slug: Option<String>,
    /// The repo name exactly as Semgrep tracks it (`org/repo`), used to
    /// filter findings to this repo only.
    #[arg(long)]
    pub semgrep_repo: Option<String>,
    /// Branch to filter Semgrep findings to; omit to fetch across every
    /// branch Semgrep has scanned for this repo.
    #[arg(long)]
    pub semgrep_branch: Option<String>,
    /// Override the default Semgrep API base URL (self-hosted/regional
    /// deployments); leave unset for the standard SaaS endpoint.
    #[arg(long)]
    pub semgrep_base_url: Option<String>,

    /// Snyk API token (`snyk auth` / account settings — sent as
    /// `Authorization: token <value>`, not `Bearer`). Required, with
    /// `--snyk-org-id` and `--snyk-project-id`, for a live Snyk fetch.
    #[arg(long, env = "SNYK_TOKEN")]
    pub snyk_token: Option<String>,
    /// Regional Snyk API origin, used for ingestion and reviewed publication.
    #[arg(long)]
    pub snyk_base_url: Option<String>,
    /// The Snyk organization ID (a project's org, visible in its Snyk
    /// UI URL or via the Snyk API/CLI) findings are fetched from.
    #[arg(long)]
    pub snyk_org_id: Option<String>,
    /// The Snyk project ID — Snyk's own data model ties a project to a
    /// specific branch already, so there's no separate `--snyk-branch`.
    #[arg(long)]
    pub snyk_project_id: Option<String>,

    /// Sonatype Lifecycle/IQ Server base URL — always operator-supplied
    /// in full (this vendor is commonly self-hosted, no sensible public
    /// default exists). Required, with `--sonatype-username`,
    /// `--sonatype-password`, and `--sonatype-app-id`, for a live
    /// Sonatype fetch.
    #[arg(long)]
    pub sonatype_base_url: Option<String>,
    /// Sonatype username, or a generated user-token `userCode` used in
    /// its place (Sonatype's own recommended approach for service
    /// accounts).
    #[arg(long)]
    pub sonatype_username: Option<String>,
    /// Sonatype password, or a generated user-token `passCode`.
    #[arg(long, env = "SONATYPE_PASSWORD")]
    pub sonatype_password: Option<String>,
    /// The application's Sonatype `publicId` (not its internal ID —
    /// resolved automatically).
    #[arg(long)]
    pub sonatype_app_id: Option<String>,
    /// Sonatype "stage" to fetch the latest report for — Sonatype has no
    /// branch concept; whichever branch a CI job scanned just overwrites
    /// that stage's own report. Defaults to `"build"` (Sonatype's own
    /// default CI-scan stage) when unset.
    #[arg(long)]
    pub sonatype_stage: Option<String>,

    /// Aikido Security OAuth2 client ID (Settings → Integrations → REST
    /// API in the Aikido UI). Required, with `--aikido-client-secret`
    /// and `--aikido-repo-id`, for a live Aikido fetch.
    #[arg(long)]
    pub aikido_client_id: Option<String>,
    /// Aikido OAuth2 client secret.
    #[arg(long, env = "AIKIDO_CLIENT_SECRET")]
    pub aikido_client_secret: Option<String>,
    /// Aikido's own internal integer ID for this connected code
    /// repository (visible in the Aikido UI, or via its own
    /// `/repositories/code` API).
    #[arg(long)]
    pub aikido_repo_id: Option<i64>,
    /// Override the default Aikido API base URL (regional hosts — EU
    /// (`app.aikido.dev`) is the default, and `app.us.aikido.dev`,
    /// `app.au.aikido.dev` and `app.me.aikido.dev` exist for US,
    /// Australian and Middle-East tenants).
    #[arg(long)]
    pub aikido_base_url: Option<String>,

    /// Checkmarx One data-plane base URL (e.g.
    /// `https://ast.checkmarx.net`, region-specific). Required, with
    /// `--checkmarx-iam-url`, `--checkmarx-tenant`, `--checkmarx-api-key`,
    /// and `--checkmarx-project-id`, for a live Checkmarx fetch.
    #[arg(long)]
    pub checkmarx_base_url: Option<String>,
    /// Checkmarx One IAM (Keycloak) host — genuinely separate from the
    /// data-plane host (e.g. EU data is `eu.ast.checkmarx.net` but EU IAM
    /// is `eu.iam.checkmarx.net`, and the Germany region uses
    /// `deu.iam.checkmarx.net`), not derivable from
    /// `--checkmarx-base-url`.
    #[arg(long)]
    pub checkmarx_iam_url: Option<String>,
    /// The Checkmarx One tenant name (used in the IAM token-exchange URL).
    #[arg(long)]
    pub checkmarx_tenant: Option<String>,
    /// The long-lived Checkmarx One API key ("refresh token" in
    /// Checkmarx's own terminology) generated in its UI.
    #[arg(long, env = "CHECKMARX_API_KEY")]
    pub checkmarx_api_key: Option<String>,
    /// The Checkmarx One project ID findings are fetched from.
    #[arg(long)]
    pub checkmarx_project_id: Option<String>,
    /// Branch to filter Checkmarx scans to; omit to fetch the latest
    /// completed scan across any branch.
    #[arg(long)]
    pub checkmarx_branch: Option<String>,

    /// The commit sha to record as this scan's `git_sha`, used verbatim
    /// instead of shelling out to `git rev-parse HEAD`. Left unset, the
    /// shell-out is the fallback, and it works inside the packaged
    /// container now that the image ships `git` (the previous
    /// `distroless/cc` runtime had none, which made this flag mandatory
    /// in CI). A GitHub Actions caller should still pass its own
    /// already-known sha here
    /// (`github.event.pull_request.head.sha` for a PR trigger,
    /// `github.sha` otherwise): the workflow is authoritative about which
    /// commit it checked out, and a shallow or detached checkout can
    /// leave `git rev-parse` disagreeing with it. A raw `String` (empty
    /// means "not provided") for the same reason as `--stop-after` above.
    #[arg(long, default_value = "")]
    pub git_sha: String,

    /// Directory every one of this scan's reports is written into:
    /// `report.md`, `report.sarif`, `report.csv` and `findings.json`.
    /// Created if it does not exist; a directory that cannot be created
    /// or written fails the run up front, before any model spend, rather
    /// than after it. Defaults to `security-scan/` inside `--repo`, NOT
    /// the process's working directory: the repo is the one location a
    /// scan is already guaranteed to have (the container image itself is
    /// read-only, and its working directory is `/`), it is what
    /// `docs/outputs.md` has always documented, and it is the only
    /// default under which `--repo-file` batch entries write somewhere
    /// per-entry instead of clobbering each other. The four `--out-*`
    /// flags below override this per format, each independently.
    #[arg(long)]
    pub out_dir: Option<PathBuf>,

    /// Markdown report output path (default: `<out-dir>/report.md`).
    #[arg(long)]
    pub out_md: Option<PathBuf>,

    /// SARIF output path (default: `<out-dir>/report.sarif`).
    #[arg(long)]
    pub out_sarif: Option<PathBuf>,

    /// CSV findings-export output path (default:
    /// `<out-dir>/report.csv`). One row per finding, columns
    /// matching the conventions industry SAST tools (Snyk/Semgrep/
    /// Checkmarx) use for their own CSV exports. Written once, from the
    /// pre-remediation scan outcome — like `--out-findings-json`, not
    /// re-augmented with S11 validation data the way `report.md`/
    /// `report.sarif` are. Not a port — the Python original never
    /// emitted CSV either.
    #[arg(long)]
    pub out_csv: Option<PathBuf>,

    /// Provider updates: off, S9 proposals only (plan), or publish eligible assessments (apply).
    #[arg(long, default_value = "off", value_parser = ["off", "plan", "apply"])]
    pub provider_writeback: String,

    /// Disable step 2 (threat modeling).
    #[arg(long)]
    pub no_threat_model: bool,

    /// Cap total LLM token spend (prompt + completion). Checked at the
    /// S4-S7 stage boundaries AND before each individual deep-dive chunk
    /// (S4), verification session (S6) and semantic-dedup call (S5/S7) —
    /// a stage boundary alone is not a budget, since S4 and S6 each spend
    /// millions of tokens between two of them. Tripping it does not abort
    /// the scan: it stops starting new stage-4-through-7 work, lets
    /// in-flight work finish, and falls through to build the best report
    /// available, same as `--max-scan-seconds`. Chunks never analysed and
    /// findings never verified are reported as such — in the report's
    /// `## Scan Health` section and, for findings, as `UNCONFIRMED`
    /// entries under `## Dropped Findings`; an unverified finding is
    /// never counted as a true positive. Not a port — Python has no
    /// equivalent budget knob.
    #[arg(long)]
    pub max_tokens: Option<u64>,

    /// Cap total scan wall-clock time, in seconds, measured from the
    /// start of the scan. See `--max-tokens` for what tripping either cap
    /// actually does.
    #[arg(long)]
    pub max_scan_seconds: Option<u64>,

    /// GitHub token used to post/update PR review comments, and to fetch
    /// the PR's own diff for `--diff-scope`. Credentials alone no longer
    /// post anything: this, `--github-repo` and `--pr-number` say WHICH
    /// pull request the run is about, and `--pr-comments` says whether to
    /// write to it.
    #[arg(long, env = "GITHUB_TOKEN")]
    pub github_token: Option<String>,

    /// Repository the pull request lives in, as `owner/name`.
    #[arg(long)]
    pub github_repo: Option<String>,

    /// Pull request number this run is about.
    #[arg(long)]
    pub pr_number: Option<u64>,

    /// Post this scan's findings to the pull request as comments.
    ///
    /// Off by default, and deliberately separate from the three GitHub
    /// credential flags. Those say which PR the run is about, which a
    /// run needs to know for `--diff-scope` whether or not it is allowed
    /// to write anything back; treating their presence as consent to
    /// comment meant every CI job that had a token at all published to
    /// the review thread, which is a side effect nobody asked for.
    /// Without this flag the scan still runs and still writes its
    /// Markdown, SARIF and CSV reports; it just leaves the PR alone.
    ///
    /// Requires `--diff-scope`, and fails at startup without it. A
    /// comment is only worth posting where a reviewer is already
    /// reading, and a fix suggestion is only committable when its lines
    /// are part of the diff. Scanning the whole repository and then
    /// commenting on all of it buries the handful of remarks about the
    /// change under a wall of remarks about everything else.
    #[arg(long)]
    pub pr_comments: bool,

    /// Scope the scan itself to the PR's changed files: S3 only chunks
    /// (and S4 only reports on) files the diff actually touches, while
    /// the rest of the repo stays available as call-graph/import context
    /// for reasoning about those changes — not a post-scan comment
    /// filter, an up-front reduction in what gets analyzed at all.
    /// Requires `--github-token`/`--github-repo`/`--pr-number` (the diff
    /// is fetched from the PR itself); fails hard rather than silently
    /// falling back to a full-repo scan if the diff fetch fails, since
    /// that would burn the budget this flag exists to avoid. A diff that
    /// fetches fine but touches no source lines (only renames, deletions,
    /// mode changes or binary files) is not an error: it warns and scans
    /// nothing, so CI stays green without a surprise full-repo scan.
    #[arg(long)]
    pub diff_scope: bool,

    /// Removed runtime policy-file option, retained only to explain migration.
    #[arg(long, hide = true)]
    pub compliance_policy: Vec<PathBuf>,

    /// Select a security-framework ruleset embedded in this build:
    /// asvs, pci-dss, ssdf, or soc2. Repeat to combine frameworks.
    /// Changing guidance or mappings requires editing the bundled source
    /// policy and rebuilding. Unknown names fail closed.
    #[arg(long, visible_alias = "scan-framework", value_name = "NAME")]
    pub compliance_preset: Vec<String>,

    /// Override EVERY loaded policy's `scope_mode` uniformly for this run
    /// (`annotate` or `filter`), regardless of what each individual
    /// embedded preset itself declares — this is the "loosen or
    /// strengthen reporting" knob: the scan always runs at full
    /// coverage, but `filter` narrows the final REPORT down to only
    /// findings relevant to an active compliance policy.
    /// `--compliance-preset asvs --compliance-scope filter` surfaces
    /// only ASVS-relevant findings even though the shipped ASVS preset's
    /// own default is `annotate` (tag everything, drop nothing). Empty
    /// (the default) leaves each policy's own declared mode untouched.
    #[arg(long, default_value = "")]
    pub compliance_scope: String,

    /// GitHub REST API base URL. Defaults to github.com's own API;
    /// override for a GitHub Enterprise Server instance
    /// (`https://<host>/api/v3`). GitHub Actions runners already export
    /// `GITHUB_API_URL` set correctly for the environment they run in.
    #[arg(long, env = "GITHUB_API_URL", default_value = "https://api.github.com")]
    pub github_api_base_url: String,

    /// Findings-snapshot output path (default:
    /// `<out-dir>/findings.json`). A `{commit_sha, findings}` export for
    /// a later `--post-comments-from` run to post GitHub PR comments
    /// from a separate, privileged workflow job, the same way SARIF
    /// upload already happens in a separate job from the scan itself
    /// (see `docs/github-action.md`). Written by every scan, like the
    /// three reports above; this flag only moves it. Silently skipped
    /// if the scan doesn't reach a `FinalReport` or has no known git SHA
    /// (the same precondition `--github-token` posting itself checks):
    /// the commit is half of what the file is FOR, and an export
    /// carrying no commit would only fail later, in the privileged job
    /// that consumes it.
    #[arg(long)]
    pub out_findings_json: Option<PathBuf>,

    /// Skip scanning entirely; read a findings JSON file written by a
    /// prior `--out-findings-json` run and post/update GitHub PR comments
    /// for it. Requires `--github-token`/`--github-repo`/`--pr-number`.
    #[arg(long)]
    pub post_comments_from: Option<PathBuf>,

    /// Compare this scan against a prior run and classify every finding
    /// as `new` / `unchanged`, plus every prior finding missing now as
    /// `absent` (resolved).
    ///
    /// Accepts EITHER a prior `--out-findings-json` export or a prior
    /// `report.sarif` — sniffed by content, not by extension. A
    /// `report.sarif` is the better baseline: it carries the fingerprints
    /// the earlier run actually computed, so a resolved finding can be
    /// re-emitted into this run's SARIF exactly as it was described then.
    ///
    /// Adds `baselineState` to every SARIF result, a
    /// `## Baseline Comparison` section to `report.md`, and new/unchanged/
    /// resolved counts to the run summary. Fails hard on a missing or
    /// unreadable baseline — comparing against nothing would silently
    /// report every pre-existing finding as newly introduced, which is
    /// the opposite of what this flag was asked to do.
    ///
    /// Single-repo mode only. In `--repo-file` batch mode each entry
    /// carries its OWN baseline (a 4th comma field in a `.txt` manifest,
    /// a `baseline`/`baseline_path`/`baseline_file` column in a `.csv`
    /// one), because a baseline is one repository's prior findings —
    /// passing this flag alongside `--repo-file` is refused rather than
    /// silently comparing every repo against one repo's history. Not a
    /// port — the Python original has no baseline mode.
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// YAML config file with per-stage settings (`step1`, `step2`,
    /// `step5_prefilter`, ...) and per-stage-role model overrides
    /// (`models.preprocess`, `models.deepdive`, ...) layered on top of
    /// each stage's own shipped default. Omitting this flag leaves every
    /// stage exactly as `--model` alone configures it today. Refused if
    /// it resolves inside `--repo` itself, unless
    /// `BC_ALLOW_CWD_CONFIG` is set (see `bc-config`).
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Phase 2: after a scan completes, attempt an automated fix for each
    /// verified finding (or as many as `--top`/`step_remediate.
    /// top_n_findings` selects), using the same model/gateway as the scan
    /// itself unless `--config` sets `models.remediate`. A no-op if the
    /// scan doesn't reach a `FinalReport`.
    ///
    /// This flag is the ONLY thing that lets a run write to the code it
    /// is scanning, and it is off by default. Without it the pipeline
    /// reads the repository, writes its reports to `--out-md`/
    /// `--out-sarif`/`--out-csv`, and changes nothing else: S10 is never
    /// constructed, `step_validate.enabled` is likewise `false` so S11
    /// never runs either, and no tool the scan stages hold is
    /// write-capable. Adding it does not change that for the user's own
    /// checkout either, unless `--remediate-in-place` is also passed:
    /// a git `--repo` is remediated in a throwaway worktree and the
    /// result exported as a patch.
    ///
    /// Accepts an explicit `true`/`false` value (`--remediate false`) as
    /// well as the bare flag (`--remediate`, equivalent to `--remediate
    /// true`) — `action.yml`'s static `args:` array can't conditionally
    /// omit an element based on whether an input was supplied, so it
    /// always passes this flag with an explicit value driven by its own
    /// `remediate` input (default `"false"`).
    #[arg(
        long,
        num_args = 0..=1,
        default_value_t = false,
        default_missing_value = "true",
        action = clap::ArgAction::Set
    )]
    pub remediate: bool,

    /// Select a built-in testing level: discover, unit, integration, e2e,
    /// or comprehensive (the default when this flag has no value). Existing
    /// tests are inspected first. Requires full scan plus isolated remediation.
    /// Select discovered-offline to execute allowlisted discovered suites in
    /// preloaded, ecosystem-specific containers. Other levels do not execute.
    #[arg(long, visible_alias = "testing-level", value_name = "LEVEL", num_args = 0..=1, default_missing_value = "comprehensive", requires = "remediate", conflicts_with_all = ["remediate_from", "diff_scope", "stop_after", "interactive", "remediate_in_place", "resume"])]
    pub target_tests: Option<String>,

    /// Deliver full-scan remediation as a patch (default), a newly pushed
    /// branch containing one commit, or an updated source ZIP for CI upload.
    #[arg(long, value_enum, default_value = "patch")]
    pub remediation_delivery: crate::delivery::DeliveryMode,
    /// Named Git remote for explicit branch delivery (no URL argument).
    #[arg(long, requires = "delivery_branch")]
    pub delivery_remote: Option<String>,
    /// New branch for branch delivery. Existing branches are never replaced.
    #[arg(long, requires = "delivery_remote")]
    pub delivery_branch: Option<String>,

    /// Cap remediation to the top N findings by CVSS score (highest
    /// first), or `all`/`*` to remediate every finding — overriding a
    /// numeric `step_remediate.top_n_findings` profile default. Omitting
    /// this flag falls back to that profile default, or no cap if it's
    /// also absent. In `--interactive` mode, a profile default is
    /// ignored entirely unless this flag is also given explicitly (see
    /// `--interactive`'s own doc comment).
    #[arg(long)]
    pub top: Option<String>,

    /// Pick which findings to remediate from an arrow-key terminal menu
    /// (a numbered-prompt fallback on a non-TTY stream) instead of
    /// walking the top-N batch automatically — ported from the Python
    /// original's `-i`/`--interactive`. Shows every finding, ignoring any
    /// profile-configured `step_remediate.top_n_findings` default (an
    /// automatic cap would hide findings from a menu the user is
    /// choosing from by hand); an explicit `--top N` on this same
    /// invocation still applies.
    #[arg(long, short = 'i')]
    pub interactive: bool,

    /// Override the S10 git-HEAD-staleness safety refusal: by default,
    /// remediation refuses to run if the repository's current HEAD has
    /// moved since the scan itself ran (stale line numbers would make
    /// the agent's file:line evidence land on the wrong code).
    #[arg(long)]
    pub force: bool,

    /// Resume from previously-saved checkpoints instead of re-running
    /// from scratch. Applies to both parts of a run this flag can touch:
    /// a plain scan skips re-running any of S1-S7 whose checkpoint
    /// already matches (see `bc_orchestrator::ScanConfig::resume`), and
    /// `--remediate` skips re-remediating a finding whose previously-
    /// saved checkpoint still matches it exactly (same position, title,
    /// file, and rendered body) — ported from the Python original's
    /// `_finding_identity` check. Checkpoints are always written when a
    /// checkpoint store is available (see this crate's module doc
    /// comment), regardless of this flag; `--resume` only controls
    /// whether they're consulted before re-running a stage or a finding.
    #[arg(long)]
    pub resume: bool,

    /// After clone, AI-survey the repo to derive additional step1
    /// exclusions (directories/extensions/globs, `max_file_kb`,
    /// `config_dedup`) beyond what's already configured, and apply them
    /// before S1 runs. Also enabled via `step1.auto_exclude` in
    /// `--config` (this flag forces it on regardless); `--resume` reuses
    /// a previously-written overlay instead of re-surveying. Ported from
    /// the Python original's `--auto-step1`/`s1_autoexclude.py`.
    #[arg(long, conflicts_with = "no_auto_step1")]
    pub auto_step1: bool,

    /// Hard-disable AI auto-exclude for this run, irrespective of
    /// `step1.auto_exclude` in `--config` — wins over `--auto-step1` and
    /// any config default.
    #[arg(long)]
    pub no_auto_step1: bool,

    /// Enable S10's deterministic policy gate (deny-list-wins,
    /// fail-closed) — strictly opt-in, matching the Python original's own
    /// default-off posture. Requires `--remediation-policy` and/or
    /// `--remediation-playbook` to have any real effect; enabling this
    /// with neither set means EVERY finding fails closed to
    /// guidance-only (no patches at all), since a missing/unparseable
    /// policy is a fail-closed condition, not a permissive one.
    #[arg(long)]
    pub enforce_remediation_policy: bool,

    /// The remediation policy YAML (deny/allow CWE lists, sensitive
    /// `deny_paths`, kill-switch). Only consulted when
    /// `--enforce-remediation-policy` is set.
    #[arg(long)]
    pub remediation_policy: Option<PathBuf>,

    /// The remediation playbook YAML (per-CWE fix strategies injected
    /// into the agent's prompt on the policy gate's ALLOW path). Only
    /// consulted when `--enforce-remediation-policy` is set.
    #[arg(long)]
    pub remediation_playbook: Option<PathBuf>,

    /// Turn OFF S10's post-patch tree-sitter parse gate (on by default,
    /// also settable via `step_remediate.syntax_check`). With the gate
    /// on, any file the agent touched that no longer parses rolls the
    /// whole patch back; turning it off keeps a syntactically broken
    /// patch on disk, so this exists only for a language this workspace
    /// has no grammar for and where the false rollbacks cost more than
    /// the protection is worth.
    #[arg(long)]
    pub no_syntax_check: bool,

    /// Leave S10's patch applied even when the run did not end in a
    /// clean `Fixed` verdict (`step_remediate.keep_unverified`). Off by
    /// default — an unverified patch is rolled back so `--resume`
    /// re-attempts the finding instead of walking past a fix that isn't
    /// on disk.
    #[arg(long)]
    pub keep_unverified: bool,

    /// Roll an S10 patch back when it adds+removes more than this many
    /// lines (`step_remediate.max_diff_lines`, default 200). `0`
    /// disables the cap.
    #[arg(long)]
    pub max_diff_lines: Option<usize>,

    /// Roll an S10 patch back when it touched more than this many files
    /// (`step_remediate.max_files_touched`, default 3). `0` disables the
    /// cap.
    #[arg(long)]
    pub max_files_touched: Option<usize>,

    /// Let S10 edit and run every gate as normal, then roll everything
    /// back regardless of the outcome — while KEEPING each captured diff,
    /// so `--out-remediation-json`/`--post-fixes-from` still produce PR
    /// fix suggestions (`step_remediate.dry_run`). "Show me the patch you
    /// would apply, without applying it."
    #[arg(long)]
    pub remediate_dry_run: bool,

    /// A shell command (build, lint, test suite) S10 runs in the repo
    /// root after the syntax and policy gates
    /// (`step_remediate.verify_command`). A non-zero exit or a timeout
    /// rolls the patch back. Nothing runs unless this is set.
    ///
    /// **This executes an arbitrary shell command** — it is only ever the
    /// operator's own string, never anything the model or the scanned
    /// repository can influence.
    #[arg(long)]
    pub verify_command: Option<String>,

    /// Wall-clock cap for `--verify-command`, in seconds
    /// (`step_remediate.verify_timeout_secs`, default 600). The process
    /// is killed and the patch rolled back when it expires.
    #[arg(long)]
    pub verify_timeout: Option<u64>,

    /// Run `--remediate` against the user's own `--repo` checkout instead
    /// of a throwaway detached git worktree.
    ///
    /// The default (when `--repo` is a git worktree) is to check the same
    /// commit out into a temporary worktree, run S10 + S11 there, export
    /// a unified diff to `<repo>/security-scan/remediation.patch`, and
    /// throw the checkout away — the user's files are never modified at
    /// all. This flag opts back into editing them in place, which is what
    /// every S10 safety gate exists to make survivable; use it when you
    /// want the fix applied to your tree directly. A non-git `--repo` has
    /// no worktree to make, so it is always in-place regardless.
    #[arg(long)]
    pub remediate_in_place: bool,

    /// Keep the throwaway remediation worktree on disk (and registered in
    /// the parent repo's `.git/worktrees`) instead of removing it after
    /// the patch has been exported — for inspecting what the agent
    /// actually did. Remove it yourself afterwards with
    /// `git worktree remove --force <path>`; the path is printed in the
    /// run summary.
    #[arg(long)]
    pub keep_remediation_worktree: bool,

    /// After remediation completes, write its per-finding verdicts (and
    /// any policy-gate audit trail) as JSON to this path — a later
    /// `--post-fixes-from` run reads it to post fix-suggestion comments
    /// from a separate, privileged workflow job, the same way
    /// `--post-comments-from` already does for scan findings (see
    /// `docs/github-action.md`).
    #[arg(long)]
    pub out_remediation_json: Option<PathBuf>,

    /// Skip scanning and remediation entirely; read a remediation JSON
    /// file written by a prior `--out-remediation-json` run and
    /// post/update GitHub fix-suggestion comments for it. Requires
    /// `--github-token`/`--github-repo`/`--pr-number`.
    #[arg(long)]
    pub post_fixes_from: Option<PathBuf>,

    /// Skip SCANNING (but not remediation): read a findings JSON file
    /// written by a prior `--out-findings-json` run and remediate those
    /// findings directly. Everything `--remediate` supports applies —
    /// `--top`, `-i`, the safety gates, worktree isolation, S11
    /// validation, `--out-remediation-json`.
    ///
    /// The export carries the commit it was produced from, so the same
    /// HEAD-staleness refusal `--remediate` uses still applies: if the
    /// repository has moved on, the findings' line numbers no longer
    /// point at the code they describe, and remediation refuses rather
    /// than sending the agent to the wrong lines. `--force` overrides it.
    ///
    /// The prior run's `report.md`/`report.sarif` ARE augmented in place
    /// when they exist — the same `#### Remediation`/`#### Validation`
    /// sections, `## Remediation Summary`, and `remediationStatus`/
    /// `validationStatus` SARIF properties an ordinary `--remediate` scan
    /// adds. They are looked for at `--out-md`/`--out-sarif` when given,
    /// else the repo's own `security-scan/` defaults; a report that isn't
    /// there is reported on stdout, not an error. Unlike a `--remediate`
    /// scan (which re-renders both files from the run that just produced
    /// them), this appends to what is already on disk, so a `report.md`
    /// that already carries a remediation section is left alone rather
    /// than given a second, contradicting one.
    #[arg(long, conflicts_with = "remediate")]
    pub remediate_from: Option<PathBuf>,

    /// Prune old run/checkpoint state from the SQLite state DB
    /// (`$BC_STATE_DIR/bc-sast.db`, see `--resume`) — deletes runs older
    /// than `--gc-max-age-days` OR beyond the `--gc-keep-runs` most
    /// recent (by last-touched time). Skips scanning entirely, the same
    /// way `--post-comments-from` does; `--repo` is still required as an
    /// arg but unused in this mode. `<repo>/security-scan/` output is
    /// never touched — this only affects `--resume`'s own state.
    #[arg(long)]
    pub gc: bool,

    /// Retain the N most-recently-touched runs when `--gc` runs (ignored
    /// otherwise).
    #[arg(long, default_value_t = 100)]
    pub gc_keep_runs: usize,

    /// Delete runs untouched for more than N days when `--gc` runs
    /// (ignored otherwise).
    #[arg(long, default_value_t = 5)]
    pub gc_max_age_days: i64,

    /// Fully evict the run for this repo path (age/count limits above
    /// are ignored) instead of age/count-based pruning. Implies `--gc`.
    #[arg(long)]
    pub gc_run: Option<PathBuf>,

    /// Report what `--gc`/`--gc-run` would delete without touching the
    /// database.
    #[arg(long)]
    pub gc_dry_run: bool,

    /// Print a rough, no-network scope preview for `--repo` (file count,
    /// bytes, an approximate input-token count) and exit — makes no LLM
    /// calls and spends no tokens. Skips scanning entirely, the same way
    /// `--gc` does. Ported from `vvaharness estimate` (`cli.py:59-94`).
    #[arg(long)]
    pub estimate: bool,

    /// Write structured logs (DEBUG/INFO/WARN/ERROR) to this file.
    /// Passing it makes the file the only destination: the automatic
    /// stderr stream described under `--log-stderr` stays off, so a run
    /// that passes this flag behaves exactly as it always has. Pass
    /// `--log-stderr` alongside it to get both at once. Not a port. The
    /// Python original's own "observability" was ad-hoc
    /// `print(..., file=sys.stderr)` with no level scheme to gate on.
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Stream structured logs to stderr even when stderr is a real
    /// terminal, and stream them alongside `--log-file` when that is
    /// also given.
    ///
    /// Without this flag, streaming to stderr turns itself on whenever
    /// no `--log-file` was passed and stderr is NOT a terminal, which is
    /// the CI case: nothing there redraws in place, so a scan an
    /// operator could previously only read after downloading an artifact
    /// becomes watchable live. On a real terminal the default stays
    /// silent, because the progress bar and the `--interactive` picker
    /// both redraw on stderr and an interleaved log line corrupts the
    /// frame. This flag is how to ask for the logs anyway, usually
    /// together with `--no-progress`.
    #[arg(long)]
    pub log_stderr: bool,

    /// Raise the log level above the default (WARN): once for INFO,
    /// twice for DEBUG, three or more for TRACE. Applies to whichever
    /// destinations are active, `--log-file` or stderr or both, and has
    /// no effect only when none of them are (a terminal with neither
    /// `--log-file` nor `--log-stderr`). `RUST_LOG` (standard
    /// `tracing-subscriber` `EnvFilter` syntax, e.g.
    /// `RUST_LOG=bc_stage_s4=debug`) takes precedence over this flag when
    /// set, for per-module filtering `-v`'s single global level can't
    /// express.
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Disable the live terminal progress bar (stage name, S4 chunk
    /// progress, findings counter, elapsed time, token spend). The bar
    /// already auto-disables itself when stdout isn't a real terminal
    /// (piped output, CI logs) — this flag is for explicitly opting out
    /// even in an interactive terminal. Not a port — the Python original
    /// has no equivalent UI.
    #[arg(long)]
    pub no_progress: bool,

    /// Run environment-readiness diagnostics (gateway client/credentials,
    /// `git` on PATH, `--config` load) and, if none of those are
    /// blocking, one minimal live request through the gateway — then
    /// exit, without scanning. Skips scanning entirely, the same way
    /// `--gc` does. Ported from `vvaharness doctor` (`cli.py:29-56`),
    /// adapted to this port's own single-backend (gateway-mediated
    /// `LlmClient`) architecture rather than Python's four alternative
    /// backends — see `environment.rs`'s own module doc comment.
    #[arg(long)]
    pub doctor: bool,

    /// Send any model call asking for at least 21,333 output tokens as a
    /// server-sent-event STREAM, reassembled into exactly the response a
    /// single JSON body would have carried (same text, same tool calls,
    /// same usage, same stop reason — no caller can tell which mode ran).
    ///
    /// Off by default. Turn it on when a gateway or proxy in front of the
    /// provider drops a connection that goes quiet for minutes: a large
    /// generation sends nothing at all until it finishes, while a stream
    /// trickles bytes the whole time. This port's per-call timeouts
    /// (`step*.timeout`) already solve the same problem for the client's
    /// own deadline, which is why streaming was skipped originally — they
    /// do nothing about an intermediary's idle timer.
    ///
    /// 21,333 is the ceiling the official Anthropic SDK itself refuses to
    /// send a non-streaming request above. The Python original streams
    /// unconditionally (`backends/sdk.py:288-289`) and has no threshold of
    /// its own; adopting the SDK's avoids streaming every small call for
    /// no benefit.
    ///
    /// Also settable as `llm.stream_large_responses: true` in a
    /// `--config`. The flag can only turn streaming ON — it never
    /// overrides a config that enabled it.
    #[arg(long)]
    pub stream_large_responses: bool,

    /// Skip the automatic pre-scan readiness gate (the same checks
    /// `--doctor` runs, plus a live probe) that otherwise runs before
    /// every real scan. Ported from `vvaharness scan --skip-preflight`
    /// (`orchestrator/entry.py`); use this when the gateway is known-good
    /// but the extra probe call's latency/spend isn't wanted, or the
    /// environment can't support one (e.g. an isolated CI runner with a
    /// mocked gateway).
    #[arg(long)]
    pub skip_preflight: bool,

    /// Read-only readiness check: renders the SAME static checks
    /// `--doctor` does (gateway client/credentials, `git` on PATH,
    /// `--config` load), then exits — WITHOUT the live gateway probe, so
    /// it never spends a token or needs network access. Ported from
    /// `vvaharness setup`, but deliberately scoped down: Python's wizard
    /// also recommends among four alternative backend profiles,
    /// auto-discovers a gateway from shell rc files, scaffolds a `.env`,
    /// and prints rulepack-generation/agent-install hints — none of
    /// which apply to this port's single-backend architecture (one
    /// gateway, one API key, no profiles) or its already-embedded rule
    /// corpus (see task #31A-C). Use `--doctor` instead when you also
    /// want the live connectivity probe.
    #[arg(long)]
    pub setup: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Dialect {
    Openai,
    Anthropic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum StopAfterArg {
    S1,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
}

impl From<StopAfterArg> for StopAfter {
    fn from(a: StopAfterArg) -> Self {
        match a {
            StopAfterArg::S1 => StopAfter::S1,
            StopAfterArg::S2 => StopAfter::S2,
            StopAfterArg::S3 => StopAfter::S3,
            StopAfterArg::S4 => StopAfter::S4,
            StopAfterArg::S5 => StopAfter::S5,
            StopAfterArg::S6 => StopAfter::S6,
            StopAfterArg::S7 => StopAfter::S7,
            StopAfterArg::S8 => StopAfter::S8,
            StopAfterArg::S9 => StopAfter::S9,
        }
    }
}

/// A minimal `Cli` builder shared by `batch`'s own test module — this
/// crate's own `mod tests` below has its own, separately-maintained copy
/// of the same shape (matching this project's established
/// small-deliberate-duplication convention over forcing cross-module
/// coupling for a single test helper).
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn minimal_cli(repo: &Path) -> Cli {
        Cli {
            repo: Some(repo.to_path_buf()),
            repo_file: None,
            workspace: std::path::PathBuf::from("./batch-workspace"),
            keep_clones: false,
            git_token: None,
            out_batch_summary: None,
            repo_name: None,
            model: "m".to_string(),
            temperature: None,
            seed: None,
            top_p: None,
            step_timeout: None,
            gateway_base_url: "http://127.0.0.1:0".to_string(),
            gateway_api_key: None,
            ca_cert: None,
            dialect: Dialect::Openai,
            pricing_provider: None,
            stop_after: String::new(),
            cve_file: None,
            controls_file: None,
            app_id: String::new(),
            cmdb_csv: String::new(),
            checkmarx_xml: Vec::new(),
            snyk_json: Vec::new(),
            semgrep_json: Vec::new(),
            aikido_json: Vec::new(),
            sonatype_json: Vec::new(),
            semgrep_token: None,
            semgrep_deployment_slug: None,
            semgrep_repo: None,
            semgrep_branch: None,
            semgrep_base_url: None,
            snyk_token: None,
            snyk_base_url: None,
            snyk_org_id: None,
            snyk_project_id: None,
            sonatype_base_url: None,
            sonatype_username: None,
            sonatype_password: None,
            sonatype_app_id: None,
            sonatype_stage: None,
            aikido_client_id: None,
            aikido_client_secret: None,
            aikido_repo_id: None,
            aikido_base_url: None,
            checkmarx_base_url: None,
            checkmarx_iam_url: None,
            checkmarx_tenant: None,
            checkmarx_api_key: None,
            checkmarx_project_id: None,
            checkmarx_branch: None,
            git_sha: String::new(),
            out_dir: None,
            out_md: None,
            out_sarif: None,
            out_csv: None,
            provider_publish: Default::default(),
            provider_writeback: "off".into(),
            no_threat_model: false,
            max_tokens: None,
            max_scan_seconds: None,
            github_token: None,
            github_repo: None,
            pr_number: None,
            pr_comments: false,
            diff_scope: false,
            compliance_policy: Vec::new(),
            compliance_preset: Vec::new(),
            compliance_scope: String::new(),
            github_api_base_url: "https://api.github.com".to_string(),
            out_findings_json: None,
            post_comments_from: None,
            baseline: None,
            config: None,
            remediate: false,
            target_tests: None,
            top: None,
            interactive: false,
            force: false,
            resume: false,
            enforce_remediation_policy: false,
            remediation_policy: None,
            remediation_playbook: None,
            no_syntax_check: false,
            keep_unverified: false,
            max_diff_lines: None,
            max_files_touched: None,
            remediate_dry_run: false,
            verify_command: None,
            verify_timeout: None,
            remediate_in_place: false,
            remediation_delivery: crate::delivery::DeliveryMode::Patch,
            delivery_remote: None,
            delivery_branch: None,
            keep_remediation_worktree: false,
            out_remediation_json: None,
            post_fixes_from: None,
            remediate_from: None,
            gc: false,
            gc_keep_runs: 100,
            gc_max_age_days: 5,
            gc_run: None,
            gc_dry_run: false,
            estimate: false,
            log_file: None,
            log_stderr: false,
            verbose: 0,
            no_progress: true,
            doctor: false,
            stream_large_responses: false,
            skip_preflight: true,
            setup: false,
            auto_step1: false,
            no_auto_step1: false,
        }
    }
}
