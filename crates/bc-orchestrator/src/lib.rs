//! Sequences the S1-S8 detection pipeline into one scan, ported from
//! `orchestrator/scan.py::scan_repo`. Pure orchestration — every
//! regex/CVSS-math/prompt-text concern lives in the stage crates or
//! `bc-enrich`/`bc-cvss`/`bc-sarif`/`bc-report-md`; this crate only
//! knows the *order* stages run in, what to do when one degrades or is
//! skipped, and where the scan should stop early.
//!
//! S9 is deterministic reporting: redact the structured report and build
//! Markdown and SARIF using the existing formatters. It has its own progress
//! events and stop boundary, without model calls or Markdown reparsing.
//!
//! Step 10 (remediation) is wired via [`remediate`], a deliberately
//! separate entry point from [`run_scan`] rather than a tenth `StopAfter`
//! variant: remediation operates on an already-built [`FinalReport`] with
//! its own write-capable `ToolExecutor` (`SandboxTools::new_with_write`,
//! not the read-only one `run_scan` uses), matching how Python's own
//! `_run_remediation` is a distinct step consulted only after S8 + SARIF,
//! not part of the S1-S8 sequence itself. Step 11 (fix validation,
//! Phase 3's scoped port — see `bc-stage-s11`) is optionally chained
//! right after each finding's remediation inside [`remediate`] itself,
//! gated by an `Option<ValidateConfig>` — see that function's own doc
//! comment for exactly what's ported vs. adapted vs. dropped from the
//! Python original.
//!
//! `build_metrics` (below) assembles the report's "scan health"
//! `ScanMetrics`, ported from `util/metrics.py::build` — chunk-kind
//! counts, LOC totals, timing, and file coverage all come from data
//! already produced by S1 (`ctx`)/S3 (`manifest`)/S4-S7 (per-stage
//! counts captured as the scan proceeds). **Token usage** is real too:
//! [`UsageTrackingClient`] wraps the injected `LlmClient` once at the top
//! of [`run_scan`], so every stage's calls are captured without any
//! stage's `Output` type having to carry a `Usage` — `tracker.take()` at
//! each stage boundary attributes the spend to that phase. The arithmetic
//! follows `util/tokens.py:54-61` exactly: the headline prompt figure is
//! *billable* input (fresh + cache-write), with cache-reads reported in
//! their own per-phase bucket rather than folded in, and all four fields
//! report `None` ("unavailable") rather than a misleading `0` when no
//! backend ever reported usage. **Still deliberately unavailable**:
//! `errors_by_stage`/`errors_log_path`, since no Rust port of Python's
//! `util/errlog` module exists — those stay at their zero/empty defaults;
//! every other `ScanMetrics` field is real.
//!
//! **Deliberately not ported**: `_head_sha`'s subprocess `timeout=20` —
//! `git rev-parse HEAD` is a fast, local, no-network operation, so the
//! defensive timeout has negligible practical value; [`head_sha`] still
//! degrades to `None` on any failure (missing `git`, not a repo, non-zero
//! exit), matching the Python original's `except Exception: return None`.

/// Folds each stage's typed diagnostics into the report's
/// `ScanMetrics::pipeline_diagnostics`.
mod diagnostics;
/// External-context loaders for `ScanInput::known_cves` /
/// `ScanInput::design_controls` (Python: `injectors/`).
pub mod inject;
pub use diagnostics::autoexclude_counts;
/// Cooperative Ctrl-C: refused model calls and skipped-stage records.
mod cancellation;
pub use cancellation::cancel_aware_client;
/// The run manifest (`run_manifest.json`): what the whole invocation did,
/// stage by stage.
pub mod manifest;
mod provider_assessment;
pub mod reporting;
mod telemetry;
use bc_pipeline_core::StageStatus;
use reporting::Stage9;
use telemetry::StageRun;

/// What a scan cost: provider inference, operator rate overrides, and the
/// per-call money accumulator behind [`ScanMetrics::cost_usd`].
pub mod pricing;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bc_checkpoint::CheckpointStore;
use bc_llm_client::{ChatRequest, ChatResponse, LlmClient, LlmError, ToolExecutor, Usage};
use bc_model::{
    AppProfile, Chunk, ContextPackage, Control, Cve, DropReason, DroppedFinding, FinalReport,
    Finding, ScanMetrics, ScopeEntry, ScopeKind, TaskManifest,
};
use bc_pipeline_core::{PipelineStage, StageError};
use bc_stage_s0::{Stage0, Step0Config, Step0Input};
use bc_stage_s1::{Stage1, Step1Config, Step1Input};
use bc_stage_s2::{Stage2, Step2Config, Step2Input};
use bc_stage_s3::{Stage3, Step3Config, Step3Input};
use bc_stage_s4::{Stage4, Step4Config, Step4Input};
use bc_stage_s5::{Stage5, Step5Config, Step5Input};
use bc_stage_s6::{Stage6, Step6Config, Step6Input};
use bc_stage_s7::{Stage7, Step7Config, Step7Input};
use bc_stage_s8::{Stage8, Step8Config, Step8Input};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// The nine typed per-stage configs a scan needs, plus the tool-version
/// string stamped into SARIF's `tool.driver.version`. Owned (not
/// `Clone`d) into each stage as the scan proceeds — a scan runs each
/// stage exactly once, so there's no need for any `Step*Config` to
/// support cloning.
pub struct ScanConfig {
    /// Mirrors `cfg.step0.enabled` — `default.yaml`/`taint.yaml` enable
    /// it, `sdk.yaml`/`full.yaml` omit it. S0 is pure static analysis
    /// (zero tokens, never degrades) so unlike step2 there's no
    /// `Degraded` outcome to record when it runs — only "ran" vs
    /// "skipped".
    pub step0_enabled: bool,
    pub step0: Step0Config,
    pub step1: Step1Config,
    /// Mirrors `cfg.step2.enabled` (Python default `true`) — S2 is the
    /// one stage the Python original can skip entirely by config, not
    /// just degrade.
    pub step2_enabled: bool,
    pub step2: Step2Config,
    pub step3: Step3Config,
    pub step4: Step4Config,
    pub step5: Step5Config,
    pub step6: Step6Config,
    pub step7: Step7Config,
    pub step8: Step8Config,
    pub tool_version: String,
    /// Optional spend/time budget, checked both at S4-S7 stage
    /// boundaries and — through [`bc_pipeline_core::BudgetGate`] —
    /// before each individual deep-dive chunk (S4), verification session
    /// (S6) and semantic-dedup call (S5/S7), which is where the money
    /// actually goes. `None` (the default) is fully unbounded,
    /// matching every scan's behavior before this field existed. Not a
    /// port — Python has no equivalent; a Rust-only hardening addition.
    /// Tripping the cap does **not** behave like `stop_after` (which
    /// returns `report: None`): it instead falls through to the
    /// existing S8 + redact + SARIF tail with whatever findings/state
    /// are on hand at the trip point, so a capped scan still produces a
    /// real, if partial, report — see [`SpendCap`].
    pub spend_cap: Option<SpendCap>,
    /// Optional persistent store for per-stage (S1-S7) checkpoints,
    /// mirroring `orchestrator/scan.py`'s checkpoint-per-stage-boundary
    /// behavior. `None` is fully unbounded/unchanged from every scan's
    /// behavior before this field existed. Deliberately a `ScanConfig`
    /// field rather than a separate `run_scan` parameter (unlike
    /// [`remediate`]'s own `checkpoint` argument) — `ScanConfig` is
    /// already the single struct every test/CLI call site constructs
    /// once, so adding a field here touches a handful of struct
    /// literals instead of every one of `run_scan`'s ~30 call sites.
    /// Checkpoints are always WRITTEN whenever a store is present,
    /// regardless of [`Self::resume`] — matching [`RemediateConfig`]'s
    /// own "always save, resume only controls whether they're
    /// consulted" contract exactly, and Python's own always-checkpoint
    /// behavior.
    pub checkpoint: Option<Arc<dyn bc_checkpoint::CheckpointStore>>,
    /// When `true` and [`Self::checkpoint`] is present, each of S1-S7
    /// consults its own cached checkpoint first and skips re-running
    /// (and re-spending LLM tokens on) a stage whose checkpoint is
    /// already there. `false` (the default) never consults a checkpoint
    /// even if one exists — a fresh, non-resuming run — matching
    /// [`RemediateConfig::resume`]'s own semantics for the analogous
    /// per-finding case.
    pub resume: bool,
    /// Mirrors `output.emit_unreachable_appendix` (Python default
    /// `false`, only ever set in `taint.yaml`) — copies
    /// `TaskManifest.unreachable_files` (populated only under
    /// `step3.catchall_mode: reachable_only`) onto the final report so
    /// the "Files Not Sent for Catch-All Review" appendix renders.
    /// Leaving both this and `catchall_mode` at their defaults keeps
    /// `FinalReport.unreachable_files` empty and the appendix absent,
    /// matching `default.yaml` exactly.
    pub emit_unreachable_appendix: bool,
    /// Optional observer for [`bc_pipeline_core::ScanEvent`]s (stage
    /// start/finish, S4's per-chunk progress, running findings counts,
    /// per-stage token usage) — consumed by `bc-cli`'s progress bar (task
    /// #75) or any other external observer. `None` (the default) is a
    /// full no-op, matching every scan's behavior before this field
    /// existed. Not a port — the Python original has no equivalent event
    /// stream.
    pub progress: Option<bc_pipeline_core::ProgressSink>,
    /// Which provider's rates this run's tokens are priced at, plus any
    /// operator supplied corrections to them. The [`Default`] prices
    /// nothing and reports every token as unpriced, which is the honest
    /// answer for a caller that has not said which endpoint it is talking
    /// to. See [`pricing`] for why a guess would be worse than that.
    /// Set by `bc-cli` from `--pricing-provider`, `--config`'s `pricing`
    /// section, and [`pricing::infer_provider`] on the gateway base URL,
    /// in that order of precedence. Not a port: the Python original
    /// reports tokens and no money at all.
    pub pricing: pricing::PricingConfig,
    /// What the `--auto-step1` survey's overlay guards decided, when that
    /// pre-pass ran (`bc-cli` runs it before the scan, see
    /// [`autoexclude_counts`]). Carried here only so it can reach
    /// `ScanMetrics::pipeline_diagnostics`; the default (`ran: false`) is
    /// "no survey ran".
    pub autoexclude: bc_model::AutoExcludeCounts,
    /// The run's cooperative cancellation (Ctrl-C), or `None` for a run
    /// nothing can cancel (every library caller, and every test that does
    /// not exercise it). Once tripped, every stage gate stops starting new
    /// work, the stages that have not started are skipped, S8 builds the
    /// report without a model call, and the partial report comes back
    /// with `ScanMetrics::canceled` set. See [`cancellation`].
    pub cancel: Option<bc_pipeline_core::CancelTokenRef>,
}

/// A budget on total scan cost (see [`ScanConfig::spend_cap`]). Both
/// fields are independent triggers — either one exceeding its limit trips
/// the cap; leaving both `None` (the `Default`) never trips.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpendCap {
    /// Total tokens (prompt + completion, summed across every phase
    /// completed so far) — the same prompt/completion split
    /// `build_metrics` uses for `ScanMetrics::total_tokens`.
    pub max_total_tokens: Option<u64>,
    /// Wall-clock elapsed since `run_scan` started.
    pub max_wall_clock: Option<std::time::Duration>,
}

pub struct ScanInput {
    pub repo_root: PathBuf,
    pub repo_name: String,
    pub known_cves: Vec<Cve>,
    pub design_controls: Vec<Control>,
    /// CMDB application id (`--app-id`); `None` skips CMDB enrichment
    /// entirely (OffensivePriority is still computed — it degrades
    /// gracefully with `app: None` — only the environmental CVSS score
    /// is skipped), matching the Python original.
    pub application_id: Option<String>,
    pub cmdb_path: Option<PathBuf>,
    /// Caller-supplied HEAD sha (`--git-sha`), used verbatim instead of
    /// shelling out to `git rev-parse HEAD` when present. `None` falls
    /// back to [`head_sha`], which works in the packaged container image
    /// now that it ships `git` (Wolfi, see the `Dockerfile`; the previous
    /// `distroless/cc` runtime had no `git` binary and no shell to add
    /// one, which made this override mandatory in CI). It stays the
    /// recommended input all the same: a GitHub Actions caller already
    /// authoritatively knows the right sha itself
    /// (`github.event.pull_request.head.sha`, or `github.sha` for a
    /// non-PR trigger), and a shallow or detached checkout can still
    /// leave `git rev-parse` reporting something other than the sha the
    /// workflow means.
    pub git_sha_override: Option<String>,
    /// `--diff-scope`'s changed-file map (repo-relative path -> changed
    /// line numbers), fetched via `bc_github::GithubClient::fetch_diff`
    /// before the scan starts. Legitimately empty for a PR whose diff
    /// carries no line-level changes (renames, deletions, mode changes,
    /// binary files), so it is `diff_scope_active` — not `is_empty()` —
    /// that says whether scoping is in effect.
    pub changed_files: BTreeMap<String, BTreeSet<i64>>,
    /// Whether `--diff-scope` was requested. `false` (the default for
    /// every existing caller) means a full-repo scan, byte-for-byte as
    /// before this field existed; `true` scopes the scan to
    /// `changed_files`, including the zero-file case.
    pub diff_scope_active: bool,
    /// Active framework policies. The CLI selects embedded presets via
    /// `--scan-framework` (also `--compliance-preset`). Each policy's
    /// `guidance` is stamped into
    /// `ContextPackage` for S1/S3/S4/S6/S8's prompts the same way
    /// `known_cves`/`changed_files` are (see
    /// `bc_compliance::combined_guidance`); every policy's `requirements`
    /// are matched against `canonical` findings just before S8 runs, with
    /// OR-across-`Filter`-mode-policies semantics (see
    /// `bc_compliance::apply_to_findings`). An empty `Vec` is a full
    /// no-op — every downstream pass behaves exactly like today. Not a
    /// port — this tool's own feature, with no Python-original
    /// counterpart.
    pub compliance: Vec<bc_compliance::CompliancePolicy>,
    /// Third-party scan-report files to ingest (`--checkmarx-xml`/
    /// `--snyk-json`/`--semgrep-json`/`--aikido-json`/`--sonatype-json`).
    /// Each file is parsed (`bc_thirdparty`), converted into this
    /// pipeline's own `Finding` shape, and re-verified through S6
    /// alongside LLM-discovered findings before being deduplicated
    /// against them through S7 — see [`load_third_party_findings`]'s own
    /// doc comment for exactly where this happens and why (bypassing S4/
    /// S5, which are tuned for this pipeline's own noisy first-pass LLM
    /// output, not vendor-scanner output). Empty `Vec`s are a full no-op.
    /// Not a port — the Python original has no third-party SAST/SCA
    /// ingestion of any kind.
    pub checkmarx_xml: Vec<PathBuf>,
    pub snyk_json: Vec<PathBuf>,
    pub semgrep_json: Vec<PathBuf>,
    pub aikido_json: Vec<PathBuf>,
    pub sonatype_json: Vec<PathBuf>,
    /// Live vendor API credentials/identifiers (`bc-cli`'s `--semgrep-*`/
    /// `--snyk-*`/`--sonatype-*`/`--aikido-*`/`--checkmarx-*` flag groups)
    /// for fetching each vendor's *latest scan of this same repo+branch*
    /// directly over its own REST API, rather than requiring an operator
    /// to export a report file by hand first. `None` (the default, when
    /// a vendor's required flags aren't all present) is a full no-op for
    /// that vendor — this is purely additive alongside the file-based
    /// `_xml`/`_json` fields above; both paths feed the exact same
    /// `load_third_party_findings` merge point and downstream S6/S7
    /// treatment. Not a port — the Python original has no third-party
    /// SAST/SCA ingestion of any kind (live or file-based).
    pub semgrep_live: Option<bc_thirdparty_api::semgrep::SemgrepConfig>,
    pub snyk_live: Option<bc_thirdparty_api::snyk::SnykConfig>,
    pub sonatype_live: Option<bc_thirdparty_api::sonatype::SonatypeConfig>,
    pub aikido_live: Option<bc_thirdparty_api::aikido::AikidoConfig>,
    pub checkmarx_live: Option<bc_thirdparty_api::checkmarx::CheckmarxConfig>,
}

/// Where a scan can stop early. S8 finishes analysis; S9 generates the
/// reports. Every explicit stop boundary prevents remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopAfter {
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

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ScanOutcome {
    /// S9 proposal artifact. Never authorizes remote updates.
    pub provider_writeback_plan: Option<String>,
    pub stopped_after: Option<StopAfter>,
    /// Redacted (`bc_redact::redact_tree`, applied once via a JSON
    /// round-trip right after S8 assembles the report) before this
    /// struct is ever returned — "redact before write" happens here, not
    /// at whatever call site eventually serializes it. Every downstream
    /// format (Markdown, SARIF, CSV, `--out-findings-json`,
    /// `--out-remediation-json`) is built from this SAME already-
    /// redacted value, so none of them need their own redaction pass.
    pub report: Option<FinalReport>,
    pub markdown: Option<String>,
    /// Pretty-printed SARIF 2.1.0 JSON text. `None` until the scan runs
    /// past `StopAfter::S8`.
    pub sarif: Option<String>,
}

/// A budget that trips before S6 leaves every surviving candidate
/// UNVERIFIED. Reporting them as findings — which is what happened on a
/// 2026-09-07 Juice Shop run: 160 S4 candidates rendered as 160 true
/// positives at "100% precision" — is the one thing this report must
/// never do. They become `Unconfirmed` drops with the budget reason, the
/// same shape S6 gives a finding whose session never started, so the
/// Verification section's "Not verified" line and the executive
/// summary's "Not examined" bullet count them honestly.
fn unverified_by_budget(candidates: &mut Vec<Finding>, reason: &str) -> Vec<DroppedFinding> {
    let detail = format!("not verified — {reason}");
    candidates
        .drain(..)
        .map(|f| DroppedFinding {
            file: f.file,
            line: f.line_start,
            vuln_class: f.vuln_class,
            title: f.title,
            chunk_id: f.chunk_id,
            reason: DropReason::Unconfirmed,
            detail: detail.clone(),
            canonical_idx: None,
            provider_origins: f.provider_origins,
            verification: None,
        })
        .collect()
}

fn stopped(stop_after: StopAfter) -> ScanOutcome {
    ScanOutcome {
        provider_writeback_plan: None,
        stopped_after: Some(stop_after),
        report: None,
        markdown: None,
        sarif: None,
    }
}

/// CMDB lookup → `(AppProfile` threaded into `ctx` for S1-S8, raw
/// `AppInfo` for post-S7 enrichment)`. `application_id` absent/empty, or
/// no `cmdb_path`, or the CSV failing to load, or the id not resolving —
/// all degrade to `(None, None)`, matching
/// `orchestrator/cmdb.py::_load_app_profile`'s broad
/// `except Exception: return None, None`.
fn resolve_app_profile(
    application_id: Option<&str>,
    cmdb_path: Option<&Path>,
) -> (Option<AppProfile>, Option<bc_enrich::AppInfo>) {
    let (Some(app_id), Some(cmdb_path)) = (application_id, cmdb_path) else {
        return (None, None);
    };
    if app_id.is_empty() {
        return (None, None);
    }
    let Ok(cmdb) = bc_enrich::load_cmdb_csv(cmdb_path) else {
        return (None, None);
    };
    let Some(info) = bc_enrich::lookup_app(app_id, &cmdb) else {
        return (None, None);
    };
    let profile = AppProfile {
        application_id: app_id.to_string(),
        name: info.name.clone(),
        externally_facing: info.externally_facing,
        pci_scoped: info.pci_scoped,
        processes_pan: info.processes_pan,
        pii: info.pii,
        source: info.source.clone(),
    };
    (Some(profile), Some(info))
}

/// Reads and parses every third-party scan-report file supplied via
/// `ScanInput.{checkmarx_xml, snyk_json, semgrep_json, aikido_json,
/// sonatype_json}` into this pipeline's own `Finding` shape
/// (`bc_thirdparty::to_finding`). A malformed or unreadable file is a
/// WARN to stderr, not a hard scan failure — third-party ingestion is a
/// best-effort enrichment layered on top of the LLM-driven scan, never
/// something that should abort a scan the operator otherwise wanted to
/// run, matching every other optional-input degrade policy in this
/// crate (CMDB above, `--auto-step1` in `bc-cli`).
///
/// Findings returned here are merged into `prefiltered_findings` in
/// `run_scan`, AFTER S5 completes and BEFORE S6 runs — never through S4
/// (chunk-scoped re-discovery; a vendor already found these) or S5 (its
/// confidence-threshold/evidence-requirement gates are tuned for this
/// pipeline's own noisy first-pass LLM output, not vendor-scanner
/// output). They still get real S6 adversarial re-verification and real
/// S7 cross-origin dedup against the LLM's own findings, exactly like
/// the user's confirmed design.
///
/// `async` (and each live vendor call below is `.await`ed one at a time,
/// not fanned out concurrently) purely because the live-API fetches
/// (`ScanInput.{semgrep,snyk,sonatype,aikido,checkmarx}_live`) need it —
/// the 5 file-based reads above stay synchronous `std::fs` calls. A
/// vendor API failure is the same WARN-and-skip degrade as a bad file:
/// live ingestion is best-effort on top of the LLM-driven scan, never a
/// reason to abort a scan the operator otherwise wanted to run.
struct LoadedProviderFindings {
    findings: Vec<Finding>,
    ingestion: Vec<bc_model::ProviderIngestionRecord>,
}

impl std::ops::Deref for LoadedProviderFindings {
    type Target = [Finding];
    fn deref(&self) -> &Self::Target {
        &self.findings
    }
}

async fn load_third_party_findings(input: &ScanInput) -> LoadedProviderFindings {
    let mut findings = Vec::new();
    let mut ingestion = Vec::new();
    ingestion.extend(load_vendor_findings(
        &input.checkmarx_xml,
        bc_thirdparty::checkmarx::parse,
        "checkmarx",
        &mut findings,
    ));
    ingestion.extend(load_vendor_findings(
        &input.snyk_json,
        bc_thirdparty::snyk::parse,
        "snyk",
        &mut findings,
    ));
    ingestion.extend(load_vendor_findings(
        &input.semgrep_json,
        bc_thirdparty::semgrep::parse,
        "semgrep",
        &mut findings,
    ));
    ingestion.extend(load_vendor_findings(
        &input.aikido_json,
        bc_thirdparty::aikido::parse,
        "aikido",
        &mut findings,
    ));
    ingestion.extend(load_vendor_findings(
        &input.sonatype_json,
        bc_thirdparty::sonatype::parse,
        "sonatype",
        &mut findings,
    ));

    if let Some(config) = &input.semgrep_live {
        let client =
            bc_thirdparty_api::semgrep::SemgrepClient::new(live_http_client(), config.clone());
        let result = client.fetch_findings().await.map_err(|e| e.to_string());
        ingestion.push(push_live_findings(result, "semgrep-live", &mut findings));
    }
    if let Some(config) = &input.snyk_live {
        let client = bc_thirdparty_api::snyk::SnykClient::new(live_http_client(), config.clone());
        let result = client.fetch_findings().await.map_err(|e| e.to_string());
        ingestion.push(push_live_findings(result, "snyk-live", &mut findings));
    }
    if let Some(config) = &input.sonatype_live {
        let client =
            bc_thirdparty_api::sonatype::SonatypeClient::new(live_http_client(), config.clone());
        let result = client.fetch_findings().await.map_err(|e| e.to_string());
        ingestion.push(push_live_findings(result, "sonatype-live", &mut findings));
    }
    if let Some(config) = &input.aikido_live {
        let client =
            bc_thirdparty_api::aikido::AikidoClient::new(live_http_client(), config.clone());
        let result = client.fetch_findings().await.map_err(|e| e.to_string());
        ingestion.push(push_live_findings(result, "aikido-live", &mut findings));
    }
    if let Some(config) = &input.checkmarx_live {
        let client =
            bc_thirdparty_api::checkmarx::CheckmarxClient::new(live_http_client(), config.clone());
        let result = client.fetch_findings().await.map_err(|e| e.to_string());
        ingestion.push(push_live_findings(result, "checkmarx-live", &mut findings));
    }

    LoadedProviderFindings {
        findings,
        ingestion,
    }
}

/// Split freshly-ingested third-party findings at the `--diff-scope`
/// boundary: the ones this run may treat as its own, and the ones it must
/// only RETAIN.
///
/// **Why this exists.** `load_third_party_findings`' output joins the
/// pipeline after S5, which is after the only two places diff scope was
/// ever enforced (S3 trims chunks, S4 drops a finding reported outside its
/// trimmed chunk). Both of those govern the LLM's own analysis and neither
/// can see a vendor finding, so a diff-scoped pull-request scan ingesting
/// Checkmarx/Snyk/Semgrep/Aikido/Sonatype output was re-verifying,
/// reporting, PR-commenting and REMEDIATING pre-existing issues in files
/// the pull request never touched.
///
/// **Retained, never discarded.** A vendor's pre-existing finding is real
/// information about the repository; silently dropping it would be the
/// absence-as-evidence failure this codebase has repeatedly had to fix.
/// Each one becomes a [`DropReason::OutOfDiffScope`] entry in
/// `FinalReport::dropped` carrying its own provider origins, so it is
/// still visible in `report.md`, still in the provider ledger, and still
/// attributable to the vendor that reported it — while being, explicitly,
/// none of this pull request's business.
///
/// A no-op when scoping is inactive: every finding comes back in the first
/// half and the second is empty, so a full-repo scan ingests exactly what
/// it always did.
fn split_provider_findings_by_diff_scope(
    findings: Vec<Finding>,
    scope: &bc_model::DiffScope,
) -> (Vec<Finding>, Vec<DroppedFinding>) {
    let mut in_scope = Vec::new();
    let mut retained = Vec::new();
    for finding in findings {
        match scope.refusal(&finding.file) {
            None => in_scope.push(finding),
            Some(reason) => retained.push(DroppedFinding {
                provider_origins: finding.provider_origins,
                // Deliberately `None`: this run ran no verification on it,
                // and an empty evidence block is the honest way to say so.
                verification: None,
                file: finding.file,
                line: finding.line_start,
                vuln_class: finding.vuln_class,
                title: finding.title,
                chunk_id: finding.chunk_id,
                reason: DropReason::OutOfDiffScope,
                detail: reason,
                canonical_idx: None,
            }),
        }
    }
    (in_scope, retained)
}

/// A short-timeout (30s — a single REST call, never the minutes-long
/// generations the LLM gateway client's own default accounts for), no
/// custom-CA plain `reqwest::Client` — matches `bc-cli::build_github_client`'s
/// own reasoning for reaching a public, standard-trust-store vendor API.
/// Built fresh per call rather than threaded through `ScanInput`/`run_scan`,
/// same as every other one-shot HTTP client already in this crate.
fn live_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("a plain reqwest client with only a timeout set always builds")
}

/// Shared WARN-and-skip degrade for every live-vendor `fetch_findings()`
/// call in [`load_third_party_findings`] — same policy as
/// [`load_vendor_findings`]'s per-file degrade. Takes a plain
/// `Result<_, String>`, not a generic `Result<_, E: Display>` bound —
/// each call site's own vendor-specific `thiserror` error is turned into
/// a `String` via `.map_err(|e| e.to_string())` right at the call site,
/// so this function (like `load_vendor_findings` above) compiles once,
/// not once per vendor error type — see that function's own doc comment
/// for why a generic version is deliberately avoided here.
fn push_live_findings(
    result: Result<Vec<bc_thirdparty::ThirdPartyFinding>, String>,
    vendor: &str,
    out: &mut Vec<Finding>,
) -> bc_model::ProviderIngestionRecord {
    let mut record = bc_model::ProviderIngestionRecord {
        source: vendor.to_string(),
        limitations: vec![
            "Provider-side filtering and skipped items are not exhaustively inventoried".into(),
        ],
        ..Default::default()
    };
    match result {
        Ok(parsed) => {
            record.imported_count = parsed.len();
            record.completed = true;
            tracing::info!("[{vendor}] ingested {} finding(s)", parsed.len());
            out.extend(parsed.iter().map(bc_thirdparty::to_finding));
        }
        Err(e) => {
            record
                .limitations
                .push(format!("Live ingestion failed: {}", bc_redact::redact(&e)));
            tracing::warn!("[{vendor}] failed to fetch live findings; recorded as incomplete");
        }
    }
    record
}

/// Largest vendor export file read into memory (256 MiB). A report is
/// operator-supplied, but a security tool should not be taken down by one:
/// without a cap a multi-gigabyte file was read whole before any parser
/// limit applied. Parsers may enforce tighter limits of their own
/// (`bc_thirdparty::checkmarx::MAX_REPORT_BYTES`).
const MAX_VENDOR_EXPORT_BYTES: u64 = 256 * 1024 * 1024;

/// Reads `path` as UTF-8, refusing anything over `max` bytes without
/// reading past the cap (the metadata length is checked first, and the
/// read itself is bounded in case the file grows meanwhile).
fn read_bounded_export(path: &Path, max: u64) -> Result<String, String> {
    use std::io::Read;
    // One named converter rather than a closure per call: the metadata and
    // read failures cannot be provoked portably in a test, and each closure
    // would be a function the coverage gate counts as never run.
    fn message(e: impl std::fmt::Display) -> String {
        e.to_string()
    }
    let too_large = || format!("larger than the {max}-byte limit for a vendor export");
    let file = std::fs::File::open(path).map_err(message)?;
    let len = file.metadata().map_err(message)?.len();
    if len > max {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(message)?;
    if bytes.len() as u64 > max {
        return Err(too_large());
    }
    String::from_utf8(bytes).map_err(message)
}

/// `parse` is a plain function pointer (`fn(&str) -> ...`), not a
/// generic `impl Fn`/`F: Fn` bound — every one of the 5 vendor `parse`
/// functions this is called with shares an identical signature and
/// coerces to the same concrete pointer type, so this function compiles
/// once, not once per call site (avoiding the coverage-attribution
/// pitfalls a generic version would risk for no real benefit here).
fn load_vendor_findings(
    paths: &[PathBuf],
    parse: fn(&str) -> Result<Vec<bc_thirdparty::ThirdPartyFinding>, String>,
    vendor: &str,
    out: &mut Vec<Finding>,
) -> Vec<bc_model::ProviderIngestionRecord> {
    let mut records = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let mut record = bc_model::ProviderIngestionRecord {
            source: format!("{vendor}-file-{index}"),
            limitations: vec![
                "File export completeness and source revision are not authenticated".into(),
            ],
            ..Default::default()
        };
        // Every message here is formatted eagerly into a `String` before
        // being handed to `tracing`: the macros only evaluate their
        // arguments when a subscriber has the callsite enabled, and no
        // test installs one, so an inlined `path.display()`/`parsed.len()`
        // is invisible to both the test suite and to coverage. Same fix,
        // same reason, as `inject`'s own skipped-record summary.
        let text = match read_bounded_export(path, MAX_VENDOR_EXPORT_BYTES) {
            Ok(text) => text,
            Err(e) => {
                let msg = format!(
                    "[{vendor}] failed to read {} ({e}); skipping",
                    path.display()
                );
                tracing::warn!("{msg}");
                record.limitations.push("Could not read export".into());
                records.push(record);
                continue;
            }
        };
        match parse(&text) {
            Ok(parsed) => {
                record.completed = true;
                record.imported_count = parsed.len();
                let msg = format!(
                    "[{vendor}] ingested {} finding(s) from {}",
                    parsed.len(),
                    path.display()
                );
                tracing::info!("{msg}");
                out.extend(parsed.iter().map(bc_thirdparty::to_finding));
            }
            Err(e) => {
                record.limitations.push("Could not parse export".into());
                let msg = format!(
                    "[{vendor}] failed to parse {} ({e}); skipping",
                    path.display()
                );
                tracing::warn!("{msg}");
            }
        }
        records.push(record);
    }
    records
}

/// The scanned repo's current git HEAD SHA, or `None` for a non-git
/// target / git failure. Ported from `_head_sha` — including its exact
/// leniency: a successful `git rev-parse` is trusted as-is (Python
/// returns `r.stdout.strip()` unconditionally on `returncode == 0`, with
/// no separate "but what if it's empty" case, since that combination
/// doesn't occur in practice).
pub fn head_sha(repo: &Path) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Wraps an `LlmClient` to accumulate every `ChatResponse::usage` it
/// sees — the mechanism `run_scan` uses to populate `ScanMetrics`'
/// `prompt_tokens`/`completion_tokens`/`total_tokens`/`tokens_by_phase`
/// WITHOUT touching any stage crate's own `Output` type or its already-
/// 100%-covered test suite: every `Stage*::new` call already takes an
/// `Arc<dyn LlmClient>` by dependency injection, so wrapping the client
/// ONCE at the top of `run_scan` transparently captures every call S1-S7
/// make (single-shot or agentic — `bc_llm_agentic::run_agentic` itself
/// calls `chat` through whatever client it's given, so multi-turn usage
/// still flows through this one interception point) — no stage crate
/// needs to know this exists.
///
/// It is also where a call is COSTED, for the reason
/// [`crate::pricing`] sets out at length: a long-context rate switches on
/// one call's own prompt size, so a phase's summed tokens cannot be
/// priced afterwards, and this is the last point at which an individual
/// call's context size still exists. `request.model` is read here too,
/// because the pipeline routes a different model to each of its twelve
/// roles, and a phase total with no model attached is not a number
/// anything can price.
struct UsageTrackingClient {
    inner: Arc<dyn LlmClient>,
    total: Mutex<PhaseUsage>,
    /// Resolved once per scan from [`ScanConfig::pricing`]; holds the
    /// vendored table plus any operator overrides.
    pricer: bc_pricing::Pricer<'static>,
    /// The provider every call is priced under, or `None` when the
    /// endpoint could not be attributed to one. See
    /// [`crate::pricing::infer_provider`].
    provider: Option<String>,
    /// The run's Anthropic cache lifetime, which decides the write rate
    /// (see [`crate::pricing::PricingConfig::cache_ttl`]).
    cache_ttl: bc_llm_client::CacheTtl,
    /// Every `provider/model` this run failed to price, kept outside
    /// [`PhaseUsage`] so that stays `Copy` and so the report can name the
    /// gap once for the whole run rather than per phase.
    unpriced_models: pricing::UnpricedModels,
}

/// One pipeline phase's token accounting — the Rust shape of Python's
/// per-phase bucket (`util/tokens.py::_bucket`, which carries
/// `prompt`/`completion`/`cache_read`/`cache_write`/`calls`).
///
/// `calls_with_usage` is the counter behind `build_metrics`' "report
/// `None`, not `0`" decision (`util/tokens.py:70`, read at
/// `util/metrics.py:93`): a scan whose backend never reported usage must
/// say *unavailable* in the report, not claim a truthful-looking zero.
/// Python knows a call carried usage because the backend either passed a
/// `dict` or `None`; `ChatResponse::usage` is a plain (non-`Option`)
/// `Usage`, so the equivalent signal here is "the dialect filled in
/// something" — any non-zero field. A real call that genuinely billed
/// zero tokens in every category is indistinguishable from no usage at
/// all, and is counted as no usage; that only ever moves the report from
/// a meaningless `0` to an honest `unavailable`.
///
/// `cost` is the money half of the same bucket. It is deliberately not
/// derivable from the other three fields: see [`crate::pricing`] for why
/// a phase's totals cannot be priced after the fact, and why this is
/// accumulated one call at a time instead.
///
/// `truncated_replies` counts `LlmClient::note_truncated_reply` calls.
/// It lives in this bucket, behind the same lock as the token counts,
/// rather than in a free-standing `AtomicU64`, so `take` attributes a
/// truncation to exactly the phase whose tokens it is reset with: an
/// atomic read at a stage boundary could straddle a concurrent S4 chunk's
/// increment and charge it to the wrong stage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PhaseUsage {
    usage: Usage,
    calls: i64,
    calls_with_usage: i64,
    cost: pricing::PhaseCost,
    truncated_replies: u64,
}

impl UsageTrackingClient {
    fn new(inner: Arc<dyn LlmClient>, pricing: &pricing::PricingConfig) -> Self {
        UsageTrackingClient {
            inner,
            total: Mutex::new(PhaseUsage::default()),
            pricer: pricing.pricer(),
            provider: pricing.provider.clone(),
            cache_ttl: pricing.cache_ttl,
            unpriced_models: pricing::UnpricedModels::default(),
        }
    }

    /// Snapshots the usage accumulated since construction (or the last
    /// `take`) and resets it to zero — used to attribute usage to
    /// exactly the pipeline phase that was running when it accrued,
    /// rather than one grand total with no per-stage breakdown.
    fn take(&self) -> PhaseUsage {
        std::mem::take(&mut self.total.lock().unwrap())
    }

    /// The same snapshot WITHOUT the reset — what a mid-stage
    /// [`SpendGate`] needs, since `take` is owned by the stage-boundary
    /// accounting and calling it from a gate would silently steal the
    /// running stage's usage out of `tokens_by_phase`.
    fn peek(&self) -> PhaseUsage {
        *self.total.lock().unwrap()
    }
}

#[async_trait::async_trait]
impl LlmClient for UsageTrackingClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let response = self.inner.chat(request).await?;
        let mut total = self.total.lock().unwrap();
        total.calls += 1;
        // Only a call that reported usage is costed. A call that reported
        // none has nothing to price, and counting it as unpriced would
        // invent a gap where there is only silence from the backend,
        // which is exactly the distinction `calls_with_usage` already draws.
        let mut unpriced = None;
        if response.usage != Usage::default() {
            total.calls_with_usage += 1;
            unpriced = total.cost.record_call(
                &self.pricer,
                self.provider.as_deref(),
                &request.model,
                response.usage,
                self.cache_ttl,
            );
        }
        total.usage.input_tokens += response.usage.input_tokens;
        total.usage.output_tokens += response.usage.output_tokens;
        total.usage.cache_creation_input_tokens += response.usage.cache_creation_input_tokens;
        total.usage.cache_read_input_tokens += response.usage.cache_read_input_tokens;
        drop(total);
        if let Some(label) = unpriced {
            self.unpriced_models.add(label);
        }
        Ok(response)
    }

    /// Counted here (see [`PhaseUsage::truncated_replies`]) and forwarded,
    /// as the trait requires of any decorator, so a client further in
    /// still hears about it.
    fn note_truncated_reply(&self) {
        self.total.lock().unwrap().truncated_replies += 1;
        self.inner.note_truncated_reply();
    }
}

/// One phase's spend in the shape [`bc_pipeline_core::ScanEvent::UsageUpdate`]
/// carries, using the same billable-prompt arithmetic ([`prompt_tokens`])
/// and "priced nothing is `None`, not `0`" rule `build_metrics` applies
/// to `tokens_by_phase`, so the live stream and the report agree.
fn stage_usage(phase: PhaseUsage) -> bc_pipeline_core::StageUsage {
    bc_pipeline_core::StageUsage {
        prompt_tokens: prompt_tokens(phase.usage),
        completion_tokens: phase.usage.output_tokens as i64,
        cache_read_tokens: phase.usage.cache_read_input_tokens as i64,
        cache_write_tokens: phase.usage.cache_creation_input_tokens as i64,
        calls: phase.calls,
        cost_usd: (phase.cost.priced_calls() > 0).then(|| phase.cost.total().dollars_f64()),
        unpriced_tokens: phase.cost.unpriced_tokens() as i64,
        truncated_replies: phase.truncated_replies,
    }
}

/// The headline "prompt" figure: **billable input only** — fresh
/// `input_tokens` plus `cache_creation_input_tokens` (cache *writes*).
///
/// Ported from `util/tokens.py:54-61`, whose comment states the rule
/// outright: *"Headline `prompt` = billable input (fresh + cache-write).
/// cache-read is ~10% cost and tracked separately so it doesn't inflate
/// the total."* This port previously folded `cache_read_input_tokens`
/// into the same sum, which silently inflated `prompt_tokens` and
/// `total_tokens` in every report — and by a lot, since prompt caching
/// means cache reads dominate a multi-turn agentic scan. Cache reads are
/// still reported, in each phase's own `cache_read` bucket, exactly as
/// Python does (and as `bc_report_md`'s "Cache-read (excl.)" column
/// already expected).
fn prompt_tokens(usage: Usage) -> i64 {
    (usage.input_tokens + usage.cache_creation_input_tokens) as i64
}

/// Every chunk's outcome, in the plain-string shape
/// `bc_metrics::count_failed_chunks` expects (matching Python's own
/// `dict[str, str]` `chunk_outcomes`).
fn outcome_str(outcome: bc_stage_s4::ChunkOutcome) -> &'static str {
    match outcome {
        bc_stage_s4::ChunkOutcome::Completed => "completed",
        bc_stage_s4::ChunkOutcome::Error => "error",
        bc_stage_s4::ChunkOutcome::Guardrail => "guardrail",
        bc_stage_s4::ChunkOutcome::Skipped => SKIPPED_CHUNK,
    }
}

/// The one `outcome_str` value that is NOT a failure: a chunk the budget
/// gate stopped before it ever ran. `build_metrics` filters these out of
/// `chunks_failed` (nothing failed) and out of `chunks_attempted`
/// (nothing was attempted), leaving the budget itself to account for
/// them in `ScanMetrics::budget_stop`.
const SKIPPED_CHUNK: &str = "skipped";

/// The prefix `bc_stage_s7::run_dedup` puts on the one degrade reason
/// that is a budget stop rather than a call failure — S5 and S7 both
/// report degradation through the same `StageOutcome::Degraded` channel,
/// and only this one belongs in `ScanMetrics::budget_stop`.
const BUDGET_SKIP: &str = "semantic dedup skipped:";

/// `Some(stage-prefixed reason)` when a degraded S5/S7 outcome degraded
/// *because the budget ran out* rather than because its semantic-dedup
/// call failed. Everything else about a degraded stage is already
/// reported through `errors_by_stage`; only a budget stop also belongs in
/// `ScanMetrics::budget_stop`.
fn budget_skip_reason(stage: &str, outcome_reason: Option<&str>) -> Option<String> {
    let reason = outcome_reason?;
    reason
        .contains(BUDGET_SKIP)
        .then(|| format!("{stage}: {reason}"))
}

/// Assembles the report's "scan health" `ScanMetrics`, ported from
/// `util/metrics.py::build`. Every field is derived from data already
/// produced by S1 (`ctx`)/S3 (`manifest`)/S4-S7 (the caller's own
/// captured counts/`tokens_by_phase`/`errors_by_stage`) — no new stage
/// crate plumbing needed for any of it (see [`UsageTrackingClient`] for
/// how `tokens_by_phase` is captured without touching a single stage
/// crate's own `Output` type).
///
/// `errors_by_stage` is deliberately coarser than Python's own
/// `util/errlog`-backed tally: Python logs one JSONL record per
/// transient failure (a stage can log several for one eventually-
/// successful run, e.g. a retried guardrail hit), re-read and counted at
/// report time. This port has no file-backed error log (there's still no
/// other consumer for one — see `bc-stage-s8`'s own doc comment on why
/// that's deliberately not built), so this is a coarser, honestly-scoped
/// signal instead: 1 if S1/S2/S3/S5/S7 degraded to a fallback result at
/// all this scan (or S2's LLM call failed outright), or S4's own
/// `chunks_failed` count when nonzero — never a fine-grained per-retry
/// tally. S6 is deliberately excluded: its only drop reason today is
/// `DropReason::FalsePositive`, a normal successful verdict, not an
/// error — counting it here would mislabel legitimate S6 output as a
/// failure. S8 is excluded for a structural reason, not a scope choice:
/// this function's own result is embedded in `Step8Input` *before* S8
/// runs, so S8's own outcome can never be known yet at this point (it
/// already has a more direct signal anyway — `FinalReport::degraded`/
/// `degraded_reason`, set after S8 completes).
#[allow(clippy::too_many_arguments)]
fn build_metrics(
    ctx: &ContextPackage,
    manifest: &TaskManifest,
    repo_root: &Path,
    repo_name: &str,
    start_ts: &str,
    end_ts: &str,
    raw_findings_count: i64,
    true_positive_count: i64,
    false_positive_count: i64,
    duplicate_count: i64,
    chunk_outcomes: &BTreeMap<String, bc_stage_s4::ChunkOutcome>,
    tokens_by_phase: &BTreeMap<String, PhaseUsage>,
    unpriced_models: Vec<String>,
    mut errors_by_stage: BTreeMap<String, i64>,
    budget_stop: Option<String>,
) -> ScanMetrics {
    let mut analyzed: BTreeSet<String> = BTreeSet::new();
    let (mut chunks_risk, mut chunks_catchall, mut chunks_specialist) = (0i64, 0i64, 0i64);
    let mut scope = Vec::with_capacity(manifest.chunks.len());
    for chunk in &manifest.chunks {
        analyzed.extend(chunk.files.iter().cloned());
        let kind = bc_metrics::chunk_kind(&chunk.id, chunk.specialist.is_some());
        match kind {
            bc_metrics::ChunkKind::Risk => chunks_risk += 1,
            bc_metrics::ChunkKind::Catchall => chunks_catchall += 1,
            bc_metrics::ChunkKind::Specialist => chunks_specialist += 1,
        }
        let mut files = chunk.files.clone();
        files.sort();
        scope.push(ScopeEntry {
            name: chunk.id.clone(),
            kind: match kind {
                bc_metrics::ChunkKind::Risk => ScopeKind::Risk,
                bc_metrics::ChunkKind::Catchall => ScopeKind::Catchall,
                bc_metrics::ChunkKind::Specialist => ScopeKind::Specialist,
            },
            files,
        });
    }

    let folders_scanned = bc_metrics::folders_scanned(analyzed.iter().map(String::as_str));

    let mut loc_in_scope_by_language: BTreeMap<String, i64> = BTreeMap::new();
    let mut loc_scanned_by_language: BTreeMap<String, i64> = BTreeMap::new();
    for file in &ctx.all_files {
        let ext = Path::new(file)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
            .unwrap_or_default();
        let lang = bc_repo_analysis::ext_to_lang(&ext)
            .unwrap_or("other")
            .to_string();
        let loc = bc_pathjail::confine(repo_root, file)
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|content| bc_metrics::count_nonblank_lines(&content) as i64)
            .unwrap_or(0);
        *loc_in_scope_by_language.entry(lang.clone()).or_insert(0) += loc;
        if analyzed.contains(file) {
            *loc_scanned_by_language.entry(lang).or_insert(0) += loc;
        }
    }

    let outcome_strs: Vec<&str> = chunk_outcomes.values().copied().map(outcome_str).collect();
    // Budget-skipped chunks are excluded from BOTH counts: they did not
    // fail (so `chunks_failed` — and through it `errors_by_stage["s4"]`
    // — must not call them errors), and they were never attempted (so
    // the report's "N/M chunks failed" ratio must not pretend they
    // were). `ScanMetrics::budget_stop` is where they are accounted for.
    let chunks_skipped = outcome_strs.iter().filter(|&&v| v == SKIPPED_CHUNK).count() as i64;
    let chunks_failed = bc_metrics::count_failed_chunks(
        outcome_strs.iter().copied().filter(|&v| v != SKIPPED_CHUNK),
    ) as i64;
    if chunks_failed > 0 {
        errors_by_stage.insert("s4".to_string(), chunks_failed);
    }

    // Per-phase buckets use Python's own key names
    // (`util/tokens.py::_bucket`: `prompt`/`completion`/`cache_read`/
    // `cache_write`/`calls`) — which is also exactly what
    // `bc_report_md::metrics`' "Tokens by Phase" table already reads. The
    // previous `prompt_tokens`/`completion_tokens`/`total_tokens` keys
    // matched neither, so that table rendered every phase as all-zeros in
    // every report.
    //
    // `cost_usd` rides along in the same per-phase bucket, and is
    // deliberately absent rather than `0` for a phase that priced
    // nothing: a zero there reads as "this phase was free", which is a
    // claim about a model whose rates are simply unknown. See
    // `crate::pricing` for why the money is accumulated per call and only
    // summed here.
    let mut prompt_total = 0i64;
    let mut completion_total = 0i64;
    let mut cache_read_total = 0i64;
    let mut cache_write_total = 0i64;
    let mut truncated_total = 0u64;
    let mut usage_recorded = false;
    let mut run_cost = pricing::PhaseCost::default();
    let tokens_by_phase_json: BTreeMap<String, serde_json::Value> = tokens_by_phase
        .iter()
        .map(|(phase, phase_usage)| {
            let usage = phase_usage.usage;
            let prompt = prompt_tokens(usage);
            let completion = usage.output_tokens as i64;
            prompt_total += prompt;
            completion_total += completion;
            cache_read_total += usage.cache_read_input_tokens as i64;
            cache_write_total += usage.cache_creation_input_tokens as i64;
            truncated_total += phase_usage.truncated_replies;
            usage_recorded |= phase_usage.calls_with_usage > 0;
            run_cost.merge(phase_usage.cost);
            let cost = phase_usage.cost;
            (
                phase.clone(),
                serde_json::json!({
                    "calls": phase_usage.calls,
                    "prompt": prompt,
                    "completion": completion,
                    "cache_read": usage.cache_read_input_tokens as i64,
                    "cache_write": usage.cache_creation_input_tokens as i64,
                    "cost_usd": (cost.priced_calls() > 0).then(|| cost.total().dollars_f64()),
                    "unpriced_tokens": cost.unpriced_tokens() as i64,
                }),
            )
        })
        .collect();

    ScanMetrics {
        scan_id: format!("{start_ts}__{repo_name}"),
        module_name: repo_name.to_string(),
        start_ts: start_ts.to_string(),
        end_ts: end_ts.to_string(),
        duration_sec: bc_metrics::duration_seconds(start_ts, end_ts),
        total_files_in_scope: ctx.all_files.len() as i64,
        analyzed_files_unique: ctx
            .all_files
            .iter()
            .filter(|f| analyzed.contains(*f))
            .count() as i64,
        chunks_total: manifest.chunks.len() as i64,
        chunks_risk,
        chunks_catchall,
        chunks_specialist,
        chunks_attempted: manifest.chunks.len() as i64 - chunks_skipped,
        chunks_failed,
        errors_by_stage,
        errors_log_path: String::new(),
        budget_stop: budget_stop.unwrap_or_default(),
        // Both set by `run_scan` after this returns: the diagnostics are
        // accumulated stage by stage, and a cancellation is read once, at
        // the point the report is assembled.
        canceled: false,
        pipeline_diagnostics: bc_model::PipelineDiagnostics::default(),
        loc_in_scope_by_language,
        loc_scanned_by_language,
        raw_findings_count,
        true_positive_count,
        false_positive_count,
        duplicate_count,
        // `None`, not `Some(0)`, when nothing ever reported usage —
        // Python's `tok_avail` gate (`util/metrics.py:93,124-127`), which
        // `bc_report_md` renders as "unavailable". A hard `0` in the Scan
        // Metrics block reads as "this scan was free", which is a
        // materially wrong claim to make about a run whose backend simply
        // didn't return usage.
        prompt_tokens: usage_recorded.then_some(prompt_total),
        completion_tokens: usage_recorded.then_some(completion_total),
        total_tokens: usage_recorded.then_some(prompt_total + completion_total),
        cache_read_tokens: usage_recorded.then_some(cache_read_total),
        cache_write_tokens: usage_recorded.then_some(cache_write_total),
        tokens_by_phase: usage_recorded.then_some(tokens_by_phase_json),
        // Counted whether or not the backend reported usage: a truncation
        // is a lost result, which is a fact about the run regardless of
        // what the provider said it cost.
        llm_truncated_replies: truncated_total as i64,
        // Filled in by `run_scan` once the report exists; this function
        // only sees the stages up to S7.
        stage_timings: BTreeMap::new(),
        // Same "`None`, not `Some(0)`" rule as the token fields above,
        // and for a sharper reason: a run whose model this build has no
        // rate for did not cost nothing, it cost an amount nobody here
        // can state. `Some(0.0)` is reserved for a run that really was
        // priced and really was free.
        cost_usd: (usage_recorded && run_cost.priced_calls() > 0)
            .then(|| run_cost.total().dollars_f64()),
        unpriced_tokens: usage_recorded.then_some(run_cost.unpriced_tokens() as i64),
        unpriced_calls: usage_recorded.then_some(run_cost.unpriced_calls() as i64),
        unpriced_models,
        folders_scanned,
        scope,
        excluded: ctx.excluded.clone(),
        changed_files_count: ctx.changed_files.len() as i64,
        diff_scope_active: ctx.diff_scope_active,
    }
}

/// Billable tokens recorded so far, across every phase that has already
/// reached a stage boundary. Reuses [`prompt_tokens`]'s own
/// prompt/completion split so budget arithmetic stays in lockstep with
/// `build_metrics`'s `total_tokens` math.
fn recorded_tokens(tokens_by_phase: &BTreeMap<String, PhaseUsage>) -> u64 {
    tokens_by_phase.values().copied().map(phase_tokens).sum()
}

/// One phase's billable tokens — the per-bucket half of
/// [`recorded_tokens`], split out so [`SpendGate`] can apply it to the
/// tracker's live (not-yet-recorded) bucket too.
fn phase_tokens(phase: PhaseUsage) -> u64 {
    prompt_tokens(phase.usage) as u64 + phase.usage.output_tokens
}

/// Which of `cap`'s two limits `spent`/`elapsed` has reached, or `None`
/// when neither has. The single place the budget predicate lives, shared
/// by the stage-boundary check ([`spend_cap_exceeded`]) and the
/// mid-stage [`SpendGate`], so the two can never disagree about whether
/// a scan is over budget.
fn cap_tripped_by(cap: &SpendCap, spent: u64, elapsed: std::time::Duration) -> Option<String> {
    if let Some(max_tokens) = cap.max_total_tokens {
        if spent >= max_tokens {
            return Some(format!(
                "token budget of {max_tokens} reached ({spent} spent)"
            ));
        }
    }
    if let Some(max_wall_clock) = cap.max_wall_clock {
        if elapsed >= max_wall_clock {
            return Some(format!(
                "time budget of {}s reached ({}s elapsed)",
                max_wall_clock.as_secs(),
                elapsed.as_secs()
            ));
        }
    }
    None
}

/// Why the scan must stop at an S4-S7 stage boundary: an operator's
/// cancellation first (it explains the stop whatever else is true), then
/// the spend cap.
fn boundary_stop(
    cancel: Option<&bc_pipeline_core::CancelTokenRef>,
    cap: Option<&SpendCap>,
    tokens_by_phase: &BTreeMap<String, PhaseUsage>,
    scan_start: std::time::Instant,
) -> Option<String> {
    bc_pipeline_core::canceled(cancel)
        .or_else(|| spend_cap_exceeded(cap, tokens_by_phase, scan_start))
}

/// Checked at S4-S7 stage boundaries — see [`ScanConfig::spend_cap`].
/// `cap: None` never trips (the default, fully-unbounded scan).
fn spend_cap_exceeded(
    cap: Option<&SpendCap>,
    tokens_by_phase: &BTreeMap<String, PhaseUsage>,
    scan_start: std::time::Instant,
) -> Option<String> {
    cap_tripped_by(cap?, recorded_tokens(tokens_by_phase), scan_start.elapsed())
}

/// The mid-stage half of the same budget: a [`bc_pipeline_core::BudgetGate`]
/// a stage consults before each unit of work.
///
/// `tokens_by_phase` is only folded in at stage boundaries, so the
/// running total a gate needs is "everything recorded before this stage
/// started" plus "whatever the tracker has accumulated since" — hence
/// `baseline_tokens`, snapshotted when the gate is built, plus a
/// non-destructive [`UsageTrackingClient::peek`]. Reading `take` here
/// instead would steal the running stage's usage out from under
/// `record_usage` and silently zero its row in the report.
///
/// Two independent ways to stop, hence `cap: Option<SpendCap>` alongside
/// `external`:
///
/// * **A cap the gate computes for itself** (`--max-tokens` /
///   `--max-scan-seconds`), absent on the default unbounded scan.
/// * **Something a stage learned by making a call** — today only
///   `bc_llm_client::LlmError::QuotaExhausted`, the provider saying the
///   account has no credits left. Nothing here can predict that, so
///   [`bc_pipeline_core::BudgetGate::trip`] pushes it in from the stage,
///   and it stops a scan that has no cap at all just as well as one that
///   does.
struct SpendGate {
    cap: Option<SpendCap>,
    tracker: Arc<UsageTrackingClient>,
    baseline_tokens: u64,
    scan_start: std::time::Instant,
    /// The first externally-supplied stop reason, or `None` while the
    /// gate has only its own counters to go on. `Mutex` rather than
    /// `OnceLock` so the "first reason wins" rule is expressed by the
    /// write itself; a `Mutex<Option<String>>` is also what the stage
    /// crates' own trippable test gates use.
    external: std::sync::Mutex<Option<String>>,
    /// The run-wide cancellation, shared by every stage's gate (unlike
    /// `external`, which belongs to this one stage's gate).
    cancel: Option<bc_pipeline_core::CancelTokenRef>,
}

impl SpendGate {
    /// Why the scan should stop, or `None` to keep going. The external
    /// reason is consulted first: it is a hard fact from the provider
    /// (no more work can be paid for at all), whereas a cap is a policy
    /// the operator set — and when both apply, the provider's is the one
    /// that explains what actually happened.
    fn tripped(&self) -> Option<String> {
        // An operator's cancellation outranks everything: it is the reason
        // the run is stopping, whatever else is also true.
        if let Some(reason) = bc_pipeline_core::canceled(self.cancel.as_ref()) {
            return Some(reason);
        }
        // `unwrap`, matching `UsageTrackingClient`'s own locking: the only
        // code this mutex ever guards is a `clone` and a `get_or_insert`,
        // neither of which can panic, so the lock cannot become poisoned.
        if let Some(reason) = self.external.lock().unwrap().clone() {
            return Some(reason);
        }
        cap_tripped_by(
            self.cap.as_ref()?,
            self.baseline_tokens + phase_tokens(self.tracker.peek()),
            self.scan_start.elapsed(),
        )
    }
}

/// `SpendGate`'s own `Debug`, hand-written because `UsageTrackingClient`
/// holds an `Arc<dyn LlmClient>` that cannot derive one — and
/// `bc_pipeline_core::BudgetGate` requires `Debug` so a `Step*Config`
/// holding a gate can still derive it.
impl std::fmt::Debug for SpendGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpendGate")
            .field("cap", &self.cap)
            .field("baseline_tokens", &self.baseline_tokens)
            .field("external", &self.external)
            .field("cancel", &self.cancel)
            .finish_non_exhaustive()
    }
}

impl bc_pipeline_core::BudgetGate for SpendGate {
    fn should_stop(&self) -> bool {
        self.tripped().is_some()
    }

    fn stop_reason(&self) -> String {
        self.tripped()
            .unwrap_or_else(|| "spend cap reached".to_string())
    }

    /// First reason wins. Under `parallel` concurrency several tasks can
    /// discover the same exhausted account within milliseconds of each
    /// other; the one that got there first is the one that explains the
    /// stop, and the rest must not rewrite the report's account of it.
    fn trip(&self, reason: String) {
        self.external.lock().unwrap().get_or_insert(reason);
    }
}

/// A gate over the scan's remaining budget — **always** one, even with no
/// cap set.
///
/// It used to return `None` for an uncapped scan, on the reasoning that
/// the default should pay nothing, not even an `Arc` clone per chunk.
/// That was wrong in a way the 2026-09 quota failure made expensive: a
/// gate is not only about a cap the operator set, it is also the one
/// channel a stage has for saying "the provider just told me nothing else
/// can be funded" (see [`SpendGate`]'s own docs and
/// [`bc_pipeline_core::BudgetGate::trip`]). An unbounded scan is exactly
/// the scan with no other stopping condition, so it is the one that most
/// needs to hear that. An idle gate — no cap, nothing tripped — answers
/// `should_stop() == false` on two cheap loads, which is what that per-
/// chunk `Arc` clone buys.
fn budget_gate(
    cap: Option<&SpendCap>,
    tracker: &Arc<UsageTrackingClient>,
    tokens_by_phase: &BTreeMap<String, PhaseUsage>,
    scan_start: std::time::Instant,
    cancel: Option<&bc_pipeline_core::CancelTokenRef>,
) -> Option<bc_pipeline_core::BudgetGateRef> {
    Some(Arc::new(SpendGate {
        cap: cap.copied(),
        tracker: tracker.clone(),
        baseline_tokens: recorded_tokens(tokens_by_phase),
        scan_start,
        external: std::sync::Mutex::new(None),
        cancel: cancel.cloned(),
    }))
}

/// Deserializes a `(run_id, step)` checkpoint, when [`ScanConfig::resume`]
/// is set and a store is present — `resume: false` never even attempts a
/// load (a fresh run always re-runs every stage), matching
/// `RemediateConfig::resume`'s own "resume only controls whether a
/// checkpoint is consulted" contract. Every failure mode (no store, no
/// row, corrupt JSON) collapses to `None`, exactly like
/// `CheckpointStore::load` itself.
fn load_checkpoint<T: DeserializeOwned>(
    checkpoint: Option<&dyn CheckpointStore>,
    resume: bool,
    run_id: &str,
    step: &str,
) -> Option<T> {
    if !resume {
        return None;
    }
    let bytes = checkpoint?.load(run_id, step)?;
    serde_json::from_slice(&bytes).ok()
}

/// Serializes and saves a `(run_id, step)` checkpoint whenever a store is
/// present — called unconditionally after a stage actually runs (never
/// after a cache hit), regardless of [`ScanConfig::resume`], matching how
/// remediate's own checkpoints are "always written ... regardless of this
/// flag". A `None` store or a serialize/save failure is silently a no-op,
/// same "never fatal to the overall scan" contract `CheckpointStore::save`
/// itself documents.
fn save_checkpoint<T: Serialize>(
    checkpoint: Option<&dyn CheckpointStore>,
    run_id: &str,
    step: &str,
    value: &T,
) {
    let Some(store) = checkpoint else {
        return;
    };
    if let Ok(bytes) = serde_json::to_vec(value) {
        let _ = store.save(run_id, step, &bytes);
    }
}

/// Records `usage` into `tokens_by_phase` (same key `build_metrics` reads)
/// and, if a progress sink is present, emits the matching
/// [`bc_pipeline_core::ScanEvent::UsageUpdate`] — the one call every
/// stage boundary makes right after `tracker.take()`, so token spend
/// stays in sync between the final report's metrics and the live
/// progress stream. The emitted `prompt_tokens` goes through
/// [`prompt_tokens`] for exactly that reason — reading `input_tokens`
/// alone made the live stream under-report by the whole cache-write
/// share, disagreeing with the very report it is previewing.
fn record_usage(
    tokens_by_phase: &mut BTreeMap<String, PhaseUsage>,
    progress: Option<&bc_pipeline_core::ProgressSink>,
    checkpoint_key: &str,
    stage: &'static str,
    usage: PhaseUsage,
) {
    tokens_by_phase.insert(checkpoint_key.to_string(), usage);
    bc_pipeline_core::emit(
        progress,
        bc_pipeline_core::ScanEvent::UsageUpdate {
            stage,
            usage: stage_usage(usage),
        },
    );
}

/// S1's checkpoint payload — everything downstream stages need from S1's
/// output, without needing the `Stage1::run` call itself to have
/// happened this invocation. `degraded` is carried alongside so a cache
/// hit still records the same `errors_by_stage["s1"]` entry a live,
/// degraded run would have.
#[derive(Serialize, Deserialize)]
struct Step1Checkpoint {
    ctx: ContextPackage,
    degraded: bool,
}

#[derive(Serialize, Deserialize)]
struct Step2Checkpoint {
    threat_model: Option<bc_model::ThreatModel>,
    degraded: bool,
}

/// Whether a threat model says anything at all, Python's
/// `tm.threats or tm.assets or tm.trust_boundaries` save gate.
fn threat_model_has_content(tm: &bc_model::ThreatModel) -> bool {
    !(tm.threats.is_empty() && tm.assets.is_empty() && tm.trust_boundaries.is_empty())
}

/// S2's stage-done counters (`scan.py`: `assets= boundaries= threats=`);
/// none at all when there is no model.
fn threat_model_counts(tm: Option<&bc_model::ThreatModel>) -> Vec<(&'static str, u64)> {
    tm.map(|tm| {
        vec![
            ("assets", telemetry::count(tm.assets.len())),
            ("boundaries", telemetry::count(tm.trust_boundaries.len())),
            ("threats", telemetry::count(tm.threats.len())),
        ]
    })
    .unwrap_or_default()
}

#[derive(Serialize, Deserialize)]
struct Step3Checkpoint {
    manifest: TaskManifest,
    degraded: bool,
}

/// S4's checkpoint carries the per-chunk outcomes alongside the findings,
/// as Python's does (`scan.py`: "Bundle the per-chunk outcomes with the
/// findings so a --resume that rebuilds metrics still sees the coverage
/// tally"). It used to drop them, so a resumed scan reported zero failed
/// chunks and a clean `errors_by_stage` for an S4 that had in fact lost
/// chunks: the one run a reader most needs to be told about.
///
/// `#[serde(default)]` keeps an older, findings-only row loadable; like
/// Python's legacy bare-list checkpoint, it resumes with no outcomes.
#[derive(Serialize, Deserialize)]
struct Step4Checkpoint {
    findings: Vec<Finding>,
    #[serde(default)]
    outcomes: BTreeMap<String, CheckpointChunkOutcome>,
}

/// A serde-able mirror of [`bc_stage_s4::ChunkOutcome`], which derives no
/// `serde` of its own; the stage crate owns the type, this crate owns the
/// checkpoint format. Spelled exactly as [`outcome_str`] spells the same
/// values, which is Python's own checkpoint vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CheckpointChunkOutcome {
    Completed,
    Error,
    Guardrail,
    Skipped,
}

impl From<bc_stage_s4::ChunkOutcome> for CheckpointChunkOutcome {
    fn from(outcome: bc_stage_s4::ChunkOutcome) -> Self {
        match outcome {
            bc_stage_s4::ChunkOutcome::Completed => CheckpointChunkOutcome::Completed,
            bc_stage_s4::ChunkOutcome::Error => CheckpointChunkOutcome::Error,
            bc_stage_s4::ChunkOutcome::Guardrail => CheckpointChunkOutcome::Guardrail,
            bc_stage_s4::ChunkOutcome::Skipped => CheckpointChunkOutcome::Skipped,
        }
    }
}

impl From<CheckpointChunkOutcome> for bc_stage_s4::ChunkOutcome {
    fn from(outcome: CheckpointChunkOutcome) -> Self {
        match outcome {
            CheckpointChunkOutcome::Completed => bc_stage_s4::ChunkOutcome::Completed,
            CheckpointChunkOutcome::Error => bc_stage_s4::ChunkOutcome::Error,
            CheckpointChunkOutcome::Guardrail => bc_stage_s4::ChunkOutcome::Guardrail,
            CheckpointChunkOutcome::Skipped => bc_stage_s4::ChunkOutcome::Skipped,
        }
    }
}

/// S4's stage-done counters and status from its per-chunk outcomes, the
/// same whether the outcomes came from a live run or a checkpoint:
/// `findings`, plus how many chunks there were and how many failed or were
/// skipped by the budget. Failed chunks or a budget stop close S4 as
/// `CompletedWithErrors`, the Python original's rule for a stage that
/// returned but logged unrecovered errors.
fn s4_counts(
    findings: usize,
    outcomes: &BTreeMap<String, bc_stage_s4::ChunkOutcome>,
) -> Vec<(&'static str, u64)> {
    let failed = outcomes
        .values()
        .filter(|o| {
            !matches!(
                o,
                bc_stage_s4::ChunkOutcome::Completed | bc_stage_s4::ChunkOutcome::Skipped
            )
        })
        .count();
    let skipped = outcomes
        .values()
        .filter(|o| **o == bc_stage_s4::ChunkOutcome::Skipped)
        .count();
    vec![
        ("findings", telemetry::count(findings)),
        ("chunks", telemetry::count(outcomes.len())),
        ("chunks_failed", telemetry::count(failed)),
        ("chunks_skipped", telemetry::count(skipped)),
    ]
}

#[derive(Serialize, Deserialize)]
struct Step5Checkpoint {
    findings: Vec<Finding>,
    dropped: Vec<DroppedFinding>,
    degraded: bool,
}

/// The `kept=`/`verified=`/`canonical=` plus `dropped=` pair S5, S6 and
/// S7 report on their stage-done line (`scan.py`'s `_sp_done` details).
fn kept_dropped_counts(
    kept_name: &'static str,
    kept: &[Finding],
    dropped: &[DroppedFinding],
) -> Vec<(&'static str, u64)> {
    vec![
        (kept_name, telemetry::count(kept.len())),
        ("dropped", telemetry::count(dropped.len())),
    ]
}

/// S6 has no degrade concept of its own (see the original, unchecked-
/// pointed code: `stage6.run(...).await?` either fully succeeds or
/// propagates a hard `Err`), so unlike its neighbors this payload carries
/// no `degraded` flag.
#[derive(Serialize, Deserialize)]
struct Step6Checkpoint {
    verified: Vec<Finding>,
    dropped: Vec<DroppedFinding>,
}

#[derive(Serialize, Deserialize)]
struct Step7Checkpoint {
    findings: Vec<Finding>,
    dropped: Vec<DroppedFinding>,
    degraded: bool,
}

/// Run the full S1-S8 pipeline against one local checkout, stopping
/// early if `stop_after` is reached. `Err` propagates a genuinely fatal
/// stage failure (S1/S3's LLM call, S4/S6's guardrail-abort gate, S7's
/// LLM call — every failure mode a stage crate itself treats as
/// `Err(StageError)`); every other stage-level policy (S2's
/// catch-and-continue-without-a-threat-model, S1/S3/S8's internal
/// degrade-to-fallback) is handled here or already inside the stage
/// crate, and never surfaces as an `Err` from this function.
pub async fn run_scan(
    llm: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    input: ScanInput,
    config: ScanConfig,
    stop_after: Option<StopAfter>,
) -> Result<ScanOutcome, StageError> {
    let start_ts = bc_metrics::now_iso();
    let scan_start = std::time::Instant::now();
    let (app_profile, app_info) =
        resolve_app_profile(input.application_id.as_deref(), input.cmdb_path.as_deref());

    // Wraps `llm` once so every stage's own `Arc<dyn LlmClient>` calls
    // are transparently metered — see `UsageTrackingClient`'s own doc
    // comment. `tracker` stays available (the concrete type, not the
    // trait object) to read `.take()` after each stage; `llm` itself is
    // shadowed so every `Stage*::new(llm.clone(), ...)` call below is
    // unchanged syntactically.
    let tracker = Arc::new(UsageTrackingClient::new(llm, &config.pricing));
    let llm: Arc<dyn LlmClient> = tracker.clone();
    let mut tokens_by_phase: BTreeMap<String, PhaseUsage> = BTreeMap::new();
    let mut errors_by_stage: BTreeMap<String, i64> = BTreeMap::new();

    // Mirrors `remediate`'s own checkpoint wiring exactly (see that
    // function's doc comment): `register_run` unconditionally whenever a
    // store is present, `reset_run` only for a fresh (non-`--resume`)
    // run so a LATER `--resume` can never see stale rows from an earlier,
    // intentionally-discarded run of the same repo.
    let run_id = bc_checkpoint::run_id_for(&input.repo_root);
    if let Some(cp) = &config.checkpoint {
        cp.register_run(
            &run_id,
            &input.repo_root.to_string_lossy(),
            Some(input.repo_name.as_str()),
            input.application_id.as_deref(),
        );
        if !config.resume {
            cp.reset_run(&run_id);
        }
    }
    let checkpoint = config.checkpoint.as_deref();
    let progress = config.progress.as_ref();
    let mut stage_timings = telemetry::StageTimings::new();
    // One accumulator per scan, filled as each stage returns its own typed
    // counters. A stage restored from a checkpoint did not run this time
    // and contributes nothing.
    let mut pipeline_diag = diagnostics::seeded(&config.autoexclude);
    // Checked at every stage boundary: a canceled run starts no further
    // stage, and saves no checkpoint for a gated stage (S4-S7) it may have
    // cut short, so a later `--resume` re-runs that stage in full rather
    // than inheriting its partial result.
    let cancel = config.cancel.clone();
    let canceled_now = || bc_pipeline_core::canceled(cancel.as_ref());
    let live_checkpoint = || checkpoint.filter(|_| canceled_now().is_none());

    // ── Step 0 — Static seed (profile-controlled) ────────────────────
    // `rules` mode is pure static analysis (zero tokens); `llm` mode
    // makes real single-shot classification calls, so it shares the
    // same metered client every other LLM-calling stage uses.
    // `Stage0::run` never degrades (an empty seed on any failure is
    // itself a valid, non-degraded outcome — see `bc_stage_s0::
    // SeedPackage::has_content`), so nothing to add to `errors_by_stage`.
    let s0_skip = canceled_now()
        .or_else(|| (!config.step0_enabled).then(|| "disabled in config".to_string()));
    let seed = if s0_skip.is_none() {
        let s0_run = StageRun::start(progress, Stage0::NAME);
        // The seed plane walks the SAME scope the survey does: S1 reuses
        // the seed's file inventory when one is present, so a step-0 walk
        // that ignored `step1.exclude_dirs` would silently widen the whole
        // scan — a 2026-09-07 Juice Shop run went from 199 files to 744
        // that way and spent its entire budget before verification.
        let mut step0 = config.step0;
        step0.walk = config.step1.walk.clone();
        let stage0 = Stage0::new(step0, Some(llm.clone()));
        let s0_input = Step0Input {
            repo_root: input.repo_root.clone(),
        };
        let outcome = stage0.run(s0_input).await?.into_value();
        record_usage(
            &mut tokens_by_phase,
            progress,
            "s0",
            Stage0::NAME,
            tracker.take(),
        );
        s0_run.finish(
            progress,
            &mut stage_timings,
            StageStatus::Completed,
            vec![
                ("entry_points", telemetry::count(outcome.entry_points.len())),
                ("sinks", telemetry::count(outcome.unsafe_sinks.len())),
            ],
            None,
        );
        Some(outcome)
    } else {
        telemetry::record_unstarted(
            progress,
            &mut stage_timings,
            Stage0::NAME,
            StageStatus::Skipped,
            s0_skip,
        );
        None
    };

    // ── Step 1 — Pre-process ────────────────────────────────────────
    let mut ctx = if let Some(reason) = canceled_now() {
        cancellation::skip_stages(progress, &mut stage_timings, &[Stage1::NAME], &reason);
        cancellation::empty_context(&input.repo_root)
    } else {
        let s1_run = StageRun::start(progress, Stage1::NAME);
        if let Some(cached) =
            load_checkpoint::<Step1Checkpoint>(checkpoint, config.resume, &run_id, "s1")
        {
            if cached.degraded {
                errors_by_stage.insert("s1".to_string(), 1);
            }
            s1_run.finish(
                progress,
                &mut stage_timings,
                StageStatus::Cached,
                vec![("files", telemetry::count(cached.ctx.all_files.len()))],
                None,
            );
            cached.ctx
        } else {
            let stage1 = Stage1::new(llm.clone(), tools.clone(), config.step1);
            let s1_input = Step1Input {
                repo_root: input.repo_root.clone(),
                known_cves: input.known_cves.clone(),
                design_controls: input.design_controls.clone(),
                changed_files: input.changed_files.clone(),
                diff_scope_active: input.diff_scope_active,
                compliance_guidance: bc_compliance::combined_guidance(&input.compliance),
                seed,
            };
            let s1_outcome = stage1.run(s1_input).await?;
            let degraded = s1_outcome.is_degraded();
            if degraded {
                errors_by_stage.insert("s1".to_string(), 1);
            }
            let ctx = s1_outcome.into_value();
            save_checkpoint(
                checkpoint,
                &run_id,
                "s1",
                &Step1Checkpoint {
                    ctx: ctx.clone(),
                    degraded,
                },
            );
            s1_run.finish(
                progress,
                &mut stage_timings,
                StageStatus::from_degraded(degraded),
                vec![("files", telemetry::count(ctx.all_files.len()))],
                None,
            );
            ctx
        }
    };
    ctx.app_profile = app_profile.clone();
    record_usage(
        &mut tokens_by_phase,
        progress,
        "s1",
        Stage1::NAME,
        tracker.take(),
    );
    if stop_after == Some(StopAfter::S1) {
        return Ok(stopped(StopAfter::S1));
    }

    // ── Step 2 — Threat model (optional; catch-and-continue) ────────
    let threat_model = if let Some(reason) = canceled_now() {
        cancellation::skip_stages(progress, &mut stage_timings, &[Stage2::NAME], &reason);
        None
    } else if !config.step2_enabled {
        telemetry::record_unstarted(
            progress,
            &mut stage_timings,
            Stage2::NAME,
            StageStatus::Skipped,
            Some("disabled in config".to_string()),
        );
        None
    } else {
        let s2_run = StageRun::start(progress, Stage2::NAME);
        if let Some(cached) =
            load_checkpoint::<Step2Checkpoint>(checkpoint, config.resume, &run_id, "s2")
        {
            if cached.degraded {
                errors_by_stage.insert("s2".to_string(), 1);
            }
            s2_run.finish(
                progress,
                &mut stage_timings,
                StageStatus::Cached,
                threat_model_counts(cached.threat_model.as_ref()),
                None,
            );
            cached.threat_model
        } else {
            // `with_tools` is what lets `step2.agentic: true` run its
            // read-only, repo-jailed session; without it S2 is always
            // single-shot.
            let stage2 = Stage2::new(llm.clone(), config.step2).with_tools(tools.clone());
            let s2_input = Step2Input {
                repo_root: input.repo_root.clone(),
                repo_name: input.repo_name.clone(),
                known_cves: input.known_cves.clone(),
                design_controls: input.design_controls.clone(),
                ctx: ctx.clone(),
                app_profile: app_profile.clone(),
            };
            // `run_detailed` rather than `PipelineStage::run`: the same
            // stage, but it hands back the counters `run` drops. S2 has no
            // degraded-`Ok` outcome of its own, so `Err` is the only way it
            // degrades, exactly as before.
            let s2_result = stage2.run_detailed(s2_input).await;
            let degraded = s2_result.is_err();
            if degraded {
                errors_by_stage.insert("s2".to_string(), 1);
            }
            // An `Err` is Python's `outcome="error"` branch: the stage
            // failed and the scan continues with no threat model at all.
            let (status, detail) = match &s2_result {
                Ok(_) => (StageStatus::Completed, None),
                Err(e) => (StageStatus::Error, Some(bc_redact::redact(&e.to_string()))),
            };
            let (threat_model, s2_diag) = match s2_result {
                Ok((tm, diag)) => (Some(tm), diag),
                Err(_) => (None, bc_stage_s2::ThreatModelDiagnostics::default()),
            };
            pipeline_diag.threat_model = diagnostics::threat_model_counts(
                &s2_diag,
                threat_model.as_ref().is_none_or(|tm| tm.threats.is_empty()),
            );
            // Only a real, non-degraded model is worth resuming from
            // (`scan.py`: checkpointing an empty model "would make
            // `--resume` inherit it forever and s2 would never re-run").
            // A degraded or failed S2 is left for the next run to retry.
            if !degraded && threat_model.as_ref().is_some_and(threat_model_has_content) {
                save_checkpoint(
                    checkpoint,
                    &run_id,
                    "s2",
                    &Step2Checkpoint {
                        threat_model: threat_model.clone(),
                        degraded,
                    },
                );
            }
            s2_run.finish(
                progress,
                &mut stage_timings,
                status,
                threat_model_counts(threat_model.as_ref()),
                detail,
            );
            threat_model
        }
    };
    ctx.threat_model = threat_model.clone();
    record_usage(
        &mut tokens_by_phase,
        progress,
        "s2",
        Stage2::NAME,
        tracker.take(),
    );
    if stop_after == Some(StopAfter::S2) {
        return Ok(stopped(StopAfter::S2));
    }

    // ── Step 3 — Decompose ───────────────────────────────────────────
    let manifest = if let Some(reason) = canceled_now() {
        cancellation::skip_stages(progress, &mut stage_timings, &[Stage3::NAME], &reason);
        cancellation::empty_manifest()
    } else {
        let s3_run = StageRun::start(progress, Stage3::NAME);
        if let Some(cached) =
            load_checkpoint::<Step3Checkpoint>(checkpoint, config.resume, &run_id, "s3")
        {
            if cached.degraded {
                errors_by_stage.insert("s3".to_string(), 1);
            }
            s3_run.finish(
                progress,
                &mut stage_timings,
                StageStatus::Cached,
                vec![("chunks", telemetry::count(cached.manifest.chunks.len()))],
                None,
            );
            cached.manifest
        } else {
            let stage3 = Stage3::new(llm.clone(), config.step3);
            let (s3_outcome, s3_diag) = stage3
                .run_with_diagnostics(Step3Input { ctx: ctx.clone() })
                .await?;
            pipeline_diag.decompose = diagnostics::decompose_counts(&s3_diag);
            let degraded = s3_outcome.is_degraded();
            if degraded {
                errors_by_stage.insert("s3".to_string(), 1);
            }
            let manifest = s3_outcome.into_value();
            save_checkpoint(
                checkpoint,
                &run_id,
                "s3",
                &Step3Checkpoint {
                    manifest: manifest.clone(),
                    degraded,
                },
            );
            s3_run.finish(
                progress,
                &mut stage_timings,
                StageStatus::from_degraded(degraded),
                vec![("chunks", telemetry::count(manifest.chunks.len()))],
                None,
            );
            manifest
        }
    };
    record_usage(
        &mut tokens_by_phase,
        progress,
        "s3",
        Stage3::NAME,
        tracker.take(),
    );
    if stop_after == Some(StopAfter::S3) {
        return Ok(stopped(StopAfter::S3));
    }

    // ── Steps 4-7 — deep-dive, pre-filter, verify, dedup ─────────────
    // Wrapped in a labeled block (not a real loop — it always runs
    // exactly once) so an exceeded `spend_cap` can `break 'pipeline`
    // straight into the existing S8 + redact + SARIF tail below with
    // whatever partial state exists at the trip point, instead of either
    // ignoring the cap or returning `stop_after`'s bare `report: None`
    // outcome — see `ScanConfig::spend_cap`'s own doc comment.
    // `raw_findings_count`/`chunk_outcomes`/`canonical` are always set by
    // Step 4 before any break/return past this point can occur, so they
    // have no meaningful "unset" value and are left uninitialized until
    // then; `true_positive_count`/`false_positive_count`/
    // `duplicate_count`/`all_dropped` genuinely can stay at their zero/
    // empty default when the cap trips before the stage that would set
    // them runs. `stop_after`'s own early `return`s are untouched by this
    // restructuring — same checks, same place, same behavior.
    let raw_findings_count: i64;
    let chunk_outcomes: BTreeMap<String, bc_stage_s4::ChunkOutcome>;
    let mut true_positive_count: i64 = 0;
    let mut false_positive_count: i64 = 0;
    let mut duplicate_count: i64 = 0;
    let mut canonical: Vec<Finding>;
    let mut all_dropped: Vec<DroppedFinding> = Vec::new();
    let mut provider_ledger = bc_model::ProviderLedger {
        full_scan: !input.diff_scope_active,
        resumed: config.resume,
        ..Default::default()
    };
    // The pull request's changed-file boundary in the shape the
    // provider-ingestion merge point below needs it. Built from
    // `diff_scope_active`, never from `changed_files.is_empty()`: a
    // rename-only diff is legitimately active with zero changed files and
    // must scope to nothing rather than to everything — see `ScanInput`'s
    // own doc comments on both fields.
    let diff_scope = bc_model::DiffScope::new(input.diff_scope_active, input.changed_files.keys());
    // What tripped the spend cap, if anything — whether at a stage
    // boundary here or inside S4/S5/S6/S7 via their `BudgetGate`. Ends up
    // in `ScanMetrics::budget_stop` and so in the report's
    // `## Scan Health` section: a scan that silently produced a third of
    // the analysis it was asked for is worse than one that says so.
    let mut budget_stop: Option<String> = None;

    'pipeline: {
        // ── Step 4 — Deep-dive ───────────────────────────────────────
        let s4_run = StageRun::start(progress, Stage4::NAME);
        let s4_checkpoint =
            load_checkpoint::<Step4Checkpoint>(checkpoint, config.resume, &run_id, "s4");
        // Resume chaining (`scan.py`: "A valid S5 row can only be reused
        // when its S4 prerequisite was also restored"): a downstream
        // checkpoint is only consulted when the stage feeding it was
        // itself restored. Once any stage re-runs, every later row
        // describes inputs this run no longer has and is stale.
        let s4_resumed = s4_checkpoint.is_some();
        let deepdive_findings: Vec<Finding> = if let Some(cached) = s4_checkpoint {
            chunk_outcomes = cached
                .outcomes
                .into_iter()
                .map(|(id, outcome)| (id, outcome.into()))
                .collect();
            s4_run.finish(
                progress,
                &mut stage_timings,
                StageStatus::Cached,
                s4_counts(cached.findings.len(), &chunk_outcomes),
                None,
            );
            cached.findings
        } else {
            let mut step4 = config.step4;
            step4.budget_gate = budget_gate(
                config.spend_cap.as_ref(),
                &tracker,
                &tokens_by_phase,
                scan_start,
                cancel.as_ref(),
            );
            let stage4 = Stage4::new(llm.clone(), step4).with_progress(progress.cloned());
            let chunks: Vec<Chunk> = manifest.sorted_chunks().into_iter().cloned().collect();
            let deepdive = stage4
                .run(Step4Input {
                    chunks,
                    ctx: ctx.clone(),
                })
                .await?
                .into_value();
            if let Some(reason) = deepdive.budget_stop.clone() {
                budget_stop.get_or_insert(format!("S4: {reason}"));
            }
            pipeline_diag.deepdive = diagnostics::deepdive_counts(&deepdive.diagnostics);
            chunk_outcomes = deepdive.outcomes.clone();
            save_checkpoint(
                live_checkpoint(),
                &run_id,
                "s4",
                &Step4Checkpoint {
                    findings: deepdive.findings.clone(),
                    outcomes: chunk_outcomes
                        .iter()
                        .map(|(id, outcome)| (id.clone(), (*outcome).into()))
                        .collect(),
                },
            );
            let counts = s4_counts(deepdive.findings.len(), &chunk_outcomes);
            let lost_chunks = counts
                .iter()
                .any(|(name, n)| *name == "chunks_failed" && *n > 0);
            s4_run.finish(
                progress,
                &mut stage_timings,
                StageStatus::from_degraded(lost_chunks || deepdive.budget_stop.is_some()),
                counts,
                deepdive.budget_stop.as_deref().map(bc_redact::redact),
            );
            deepdive.findings
        };
        raw_findings_count = deepdive_findings.len() as i64;
        canonical = deepdive_findings.clone();
        record_usage(
            &mut tokens_by_phase,
            progress,
            "s4",
            Stage4::NAME,
            tracker.take(),
        );
        bc_pipeline_core::emit(
            progress,
            bc_pipeline_core::ScanEvent::FindingsCount {
                stage: Stage4::NAME,
                count: deepdive_findings.len(),
            },
        );
        if stop_after == Some(StopAfter::S4) {
            return Ok(stopped(StopAfter::S4));
        }
        if let Some(reason) = boundary_stop(
            cancel.as_ref(),
            config.spend_cap.as_ref(),
            &tokens_by_phase,
            scan_start,
        ) {
            budget_stop.get_or_insert(format!("{reason}; stopped before S5"));
            all_dropped.extend(unverified_by_budget(&mut canonical, &reason));
            cancellation::skip_stages(
                progress,
                &mut stage_timings,
                &[Stage5::NAME, Stage6::NAME, Stage7::NAME],
                &reason,
            );
            break 'pipeline;
        }

        // ── Step 5 — Pre-filter ──────────────────────────────────────
        let s5_run = StageRun::start(progress, Stage5::NAME);
        let s5_checkpoint = load_checkpoint::<Step5Checkpoint>(
            checkpoint, // `s4_resumed` already implies `config.resume`.
            s4_resumed, &run_id, "s5",
        );
        let s5_resumed = s5_checkpoint.is_some();
        let (mut prefiltered_findings, prefiltered_dropped): (Vec<Finding>, Vec<DroppedFinding>) =
            if let Some(cached) = s5_checkpoint {
                if cached.degraded {
                    errors_by_stage.insert("s5".to_string(), 1);
                }
                s5_run.finish(
                    progress,
                    &mut stage_timings,
                    StageStatus::Cached,
                    kept_dropped_counts("kept", &cached.findings, &cached.dropped),
                    None,
                );
                (cached.findings, cached.dropped)
            } else {
                let mut step5 = config.step5;
                // S5's one LLM call is S7's semantic dedup, run inline
                // through this shared config — mid-stage relative to the
                // S4 boundary check above.
                step5.dedup.budget_gate = budget_gate(
                    config.spend_cap.as_ref(),
                    &tracker,
                    &tokens_by_phase,
                    scan_start,
                    cancel.as_ref(),
                );
                let s5_input = Step5Input {
                    findings: deepdive_findings,
                    ctx: ctx.clone(),
                };
                // The free function behind `Stage5::run`, called directly
                // for the counters `run` drops; its degrade reason is the
                // one `run` would have wrapped in `StageOutcome::Degraded`.
                let (prefiltered, s5_reason, s5_diag) =
                    bc_stage_s5::run_prefilter_with_diagnostics(llm.as_ref(), &s5_input, &step5)
                        .await;
                pipeline_diag.prefilter = diagnostics::prefilter_counts(&s5_diag);
                let degraded = s5_reason.is_some();
                if degraded {
                    errors_by_stage.insert("s5".to_string(), 1);
                    budget_stop = budget_stop
                        .take()
                        .or_else(|| budget_skip_reason("S5", s5_reason.as_deref()));
                }
                save_checkpoint(
                    live_checkpoint(),
                    &run_id,
                    "s5",
                    &Step5Checkpoint {
                        findings: prefiltered.findings.clone(),
                        dropped: prefiltered.dropped.clone(),
                        degraded,
                    },
                );
                s5_run.finish(
                    progress,
                    &mut stage_timings,
                    StageStatus::from_degraded(degraded),
                    kept_dropped_counts("kept", &prefiltered.findings, &prefiltered.dropped),
                    None,
                );
                (prefiltered.findings, prefiltered.dropped)
            };
        // Third-party-ingested findings join here — after S5, never
        // through S4/S5 themselves — so they still get real S6/S7
        // treatment; see `load_third_party_findings`'s own doc comment.
        let imported = load_third_party_findings(&input).await;
        provider_ledger.ingestion = imported.ingestion;
        // Built from EVERY imported finding, in-scope or not: the ledger is
        // the inventory of what each vendor reported, and an inventory that
        // silently omits what this run declined to look at is the same
        // absence-as-evidence problem in a different file.
        provider_ledger.assessments = provider_assessment::unassessed(&imported.findings);
        let (in_scope, out_of_diff_scope) =
            split_provider_findings_by_diff_scope(imported.findings, &diff_scope);
        // `len()` is read here rather than inside the macro's own argument
        // list: a `tracing` macro evaluates its arguments lazily, behind
        // the subscriber check, so an expression written there is a region
        // no test can reach.
        let set_aside = out_of_diff_scope.len();
        if set_aside != 0 {
            tracing::info!("[s5] {set_aside} third-party finding(s) are outside the --diff-scope changed-file set; retained in the report as out of scope, not verified and not remediated");
        }
        provider_assessment::mark_out_of_diff_scope(&mut provider_ledger, &out_of_diff_scope);
        // Cloned into the report's audit trail here (so a budget stop
        // between this point and S8 still carries them) while the list
        // itself stays alive for the second `mark_out_of_diff_scope` call
        // after S6 — see that function's own doc comment for why there are
        // two.
        all_dropped.extend(out_of_diff_scope.iter().cloned());
        prefiltered_findings.extend(in_scope);
        canonical = prefiltered_findings.clone();
        record_usage(
            &mut tokens_by_phase,
            progress,
            "s5",
            Stage5::NAME,
            tracker.take(),
        );
        if stop_after == Some(StopAfter::S5) {
            return Ok(stopped(StopAfter::S5));
        }
        if let Some(reason) = boundary_stop(
            cancel.as_ref(),
            config.spend_cap.as_ref(),
            &tokens_by_phase,
            scan_start,
        ) {
            budget_stop.get_or_insert(format!("{reason}; stopped before S6"));
            all_dropped.extend(prefiltered_dropped);
            all_dropped.extend(unverified_by_budget(&mut canonical, &reason));
            cancellation::skip_stages(
                progress,
                &mut stage_timings,
                &[Stage6::NAME, Stage7::NAME],
                &reason,
            );
            break 'pipeline;
        }

        // ── Step 6 — Verify ────────────────────────────────────────────
        let s6_run = StageRun::start(progress, Stage6::NAME);
        let s6_checkpoint =
            load_checkpoint::<Step6Checkpoint>(checkpoint, s5_resumed, &run_id, "s6");
        let s6_resumed = s6_checkpoint.is_some();
        // S6's status: cached, or a budget stop inside it (the one way it
        // returns having done less than it was asked).
        let mut s6_status = StageStatus::Cached;
        let mut s6_detail = None;
        let (verified_findings, verified_dropped): (Vec<Finding>, Vec<DroppedFinding>) =
            if let Some(cached) = s6_checkpoint {
                (cached.verified, cached.dropped)
            } else {
                let mut step6 = config.step6;
                step6.budget_gate = budget_gate(
                    config.spend_cap.as_ref(),
                    &tracker,
                    &tokens_by_phase,
                    scan_start,
                    cancel.as_ref(),
                );
                let stage6 =
                    Stage6::new(llm.clone(), tools.clone(), step6).with_progress(progress.cloned());
                let s6_input = Step6Input {
                    findings: prefiltered_findings,
                    ctx: ctx.clone(),
                };
                let verified = stage6.run(s6_input).await?.into_value();
                s6_status = StageStatus::from_degraded(verified.budget_stop.is_some());
                s6_detail = verified.budget_stop.as_deref().map(bc_redact::redact);
                if let Some(reason) = verified.budget_stop.clone() {
                    budget_stop.get_or_insert(format!("S6: {reason}"));
                }
                pipeline_diag.verify = diagnostics::verify_counts(&verified.diagnostics);
                save_checkpoint(
                    live_checkpoint(),
                    &run_id,
                    "s6",
                    &Step6Checkpoint {
                        verified: verified.verified.clone(),
                        dropped: verified.dropped.clone(),
                    },
                );
                (verified.verified, verified.dropped)
            };
        provider_assessment::record_verification(
            &mut provider_ledger,
            &verified_findings,
            &verified_dropped,
        );
        // `record_verification` rewrites `limitations` on every record it
        // walks, including the ones it could not associate with a verdict —
        // which is exactly what an out-of-diff-scope finding looks like to
        // it, since it never reached S6. Re-assert the real reason.
        provider_assessment::mark_out_of_diff_scope(&mut provider_ledger, &out_of_diff_scope);
        s6_run.finish(
            progress,
            &mut stage_timings,
            s6_status,
            kept_dropped_counts("verified", &verified_findings, &verified_dropped),
            s6_detail,
        );
        bc_pipeline_core::emit(
            progress,
            bc_pipeline_core::ScanEvent::FindingsCount {
                stage: Stage6::NAME,
                count: verified_findings.len(),
            },
        );
        record_usage(
            &mut tokens_by_phase,
            progress,
            "s6",
            Stage6::NAME,
            tracker.take(),
        );
        if stop_after == Some(StopAfter::S6) {
            return Ok(stopped(StopAfter::S6));
        }

        // Captured before their respective moves below — `verified_dropped`'s
        // false-positive count and `deduped_dropped`'s duplicate count each
        // come from exactly one stage's own drop list (matching
        // `scan.py`'s `fp`/`duplicates` provenance), not the post-merge
        // `all_dropped`, since `DropReason::FalsePositive` is produced only by
        // S6 and `DropReason::Duplicate` only by S7 — merging first would lose
        // which stage a given drop came from.
        true_positive_count = verified_findings.len() as i64;
        false_positive_count = verified_dropped
            .iter()
            .filter(|d| d.reason == DropReason::FalsePositive)
            .count() as i64;
        canonical = verified_findings.clone();
        if let Some(reason) = boundary_stop(
            cancel.as_ref(),
            config.spend_cap.as_ref(),
            &tokens_by_phase,
            scan_start,
        ) {
            budget_stop.get_or_insert(format!("{reason}; stopped before S7"));
            all_dropped.extend(prefiltered_dropped);
            all_dropped.extend(verified_dropped);
            cancellation::skip_stages(progress, &mut stage_timings, &[Stage7::NAME], &reason);
            break 'pipeline;
        }

        // ── Step 7 — Dedup ─────────────────────────────────────────────
        let s7_run = StageRun::start(progress, Stage7::NAME);
        let s7_counts = |kept: &[Finding], dropped: &[DroppedFinding]| {
            vec![
                ("canonical", telemetry::count(kept.len())),
                ("dup_dropped", telemetry::count(dropped.len())),
            ]
        };
        let (deduped_findings, deduped_dropped): (Vec<Finding>, Vec<DroppedFinding>) =
            if let Some(cached) =
                load_checkpoint::<Step7Checkpoint>(checkpoint, s6_resumed, &run_id, "s7")
            {
                if cached.degraded {
                    errors_by_stage.insert("s7".to_string(), 1);
                }
                s7_run.finish(
                    progress,
                    &mut stage_timings,
                    StageStatus::Cached,
                    s7_counts(&cached.findings, &cached.dropped),
                    None,
                );
                (cached.findings, cached.dropped)
            } else {
                let mut step7 = config.step7;
                step7.budget_gate = budget_gate(
                    config.spend_cap.as_ref(),
                    &tracker,
                    &tokens_by_phase,
                    scan_start,
                    cancel.as_ref(),
                );
                let stage7 = Stage7::new(llm.clone(), step7);
                let s7_outcome = stage7
                    .run(Step7Input {
                        findings: verified_findings,
                        ctx: ctx.clone(),
                    })
                    .await?;
                let degraded = s7_outcome.is_degraded();
                if degraded {
                    errors_by_stage.insert("s7".to_string(), 1);
                    budget_stop = budget_stop
                        .take()
                        .or_else(|| budget_skip_reason("S7", s7_outcome.reason()));
                }
                let deduped = s7_outcome.into_value();
                save_checkpoint(
                    live_checkpoint(),
                    &run_id,
                    "s7",
                    &Step7Checkpoint {
                        findings: deduped.findings.clone(),
                        dropped: deduped.dropped.clone(),
                        degraded,
                    },
                );
                s7_run.finish(
                    progress,
                    &mut stage_timings,
                    StageStatus::from_degraded(degraded),
                    s7_counts(&deduped.findings, &deduped.dropped),
                    None,
                );
                (deduped.findings, deduped.dropped)
            };
        duplicate_count = deduped_dropped.len() as i64;
        bc_pipeline_core::emit(
            progress,
            bc_pipeline_core::ScanEvent::FindingsCount {
                stage: Stage7::NAME,
                count: deduped_findings.len(),
            },
        );
        record_usage(
            &mut tokens_by_phase,
            progress,
            "s7",
            Stage7::NAME,
            tracker.take(),
        );

        all_dropped.extend(prefiltered_dropped);
        all_dropped.extend(verified_dropped);
        all_dropped.extend(deduped_dropped);
        canonical = deduped_findings;

        // Post-S7 enrichment (VulContextSeverity + OffensivePriority) — runs
        // before the S7 stop-point check, matching `scan.py`'s own ordering
        // (`_enrich_findings` is called before its `stop_after == "s7"`
        // check). Takes the raw `bc_enrich::AppInfo` (not the coerced
        // `AppProfile` threaded through `ContextPackage`/`FinalReport`) since
        // that's what carries the CR/IR/AR/MAV math `vsvs_score` needs.
        bc_enrich::enrich_findings(&mut canonical, app_info.as_ref());

        // Compliance-scope tag/filter — deliberately runs on this plain
        // `Vec<Finding>`, before S8 builds any chain (`Chain.steps` indexes
        // into `FinalReport.findings`; filtering after S8 would desync those
        // indices). A no-op when no policy is active or every active policy
        // is pure-guidance (empty `requirements`); combines multiple active
        // policies with OR-across-`Filter`-mode semantics. Not a port — this
        // tool's own feature.
        bc_compliance::apply_to_findings(&input.compliance, &mut canonical, &mut all_dropped);

        if stop_after == Some(StopAfter::S7) {
            return Ok(stopped(StopAfter::S7));
        }
    }

    // `end_ts` captured here (post-enrichment, pre-Step-8), matching
    // `scan.py`'s own capture point exactly.
    let end_ts = bc_metrics::now_iso();
    let mut metrics = build_metrics(
        &ctx,
        &manifest,
        &input.repo_root,
        &input.repo_name,
        &start_ts,
        &end_ts,
        raw_findings_count,
        true_positive_count,
        false_positive_count,
        duplicate_count,
        &chunk_outcomes,
        &tokens_by_phase,
        tracker.unpriced_models.snapshot(),
        errors_by_stage,
        budget_stop,
    );
    metrics.pipeline_diagnostics = pipeline_diag;
    // Read once, here: a cancellation that lands during S8 or later finds
    // a report that already holds everything the pipeline set out to do,
    // so it is not marked partial (the run itself still exits 130).
    cancellation::mark_canceled(&mut metrics, canceled_now());

    // ── Step 8 — Chain ───────────────────────────────────────────────
    let s8_run = StageRun::start(progress, Stage8::NAME);
    // Refuses the chain call once canceled, so S8 falls back to its own
    // unranked report and the tail needs no model after a Ctrl-C.
    let stage8 = Stage8::new(
        cancellation::CancelAwareClient::wrap(llm.clone(), cancel.clone()),
        config.step8,
    );
    let s8_input = Step8Input {
        findings: canonical,
        ctx: ctx.clone(),
        dropped: all_dropped,
        raw_findings_count,
        metrics: Some(metrics),
    };
    let s8_outcome = stage8.run(s8_input).await?;
    let s8_degraded = s8_outcome.is_degraded();
    let mut report = s8_outcome.into_value();
    // S8's own spend reaches the event stream (and so the run manifest)
    // but not `report.metrics.tokens_by_phase`: those metrics are an
    // input to S8, built before it runs. Its truncations are added below
    // because a lost S8 reply explains a gap in this very report.
    let s8_usage = tracker.take();
    record_usage(&mut tokens_by_phase, progress, "s8", Stage8::NAME, s8_usage);
    s8_run.finish(
        progress,
        &mut stage_timings,
        StageStatus::from_degraded(s8_degraded),
        vec![
            ("findings", telemetry::count(report.findings.len())),
            ("chains", telemetry::count(report.chains.len())),
        ],
        None,
    );
    if let Some(metrics) = report.metrics.as_mut() {
        metrics.llm_truncated_replies += s8_usage.truncated_replies as i64;
        metrics.stage_timings = stage_timings;
    }
    bc_pipeline_core::emit(
        progress,
        bc_pipeline_core::ScanEvent::FindingsCount {
            stage: Stage8::NAME,
            count: report.findings.len(),
        },
    );
    provider_ledger.analysis_complete = !report.degraded
        && report
            .metrics
            .as_ref()
            .is_some_and(|m| m.errors_by_stage.is_empty() && m.budget_stop.is_empty());
    report.provider_ledger = provider_ledger;
    report.repo_name = Some(input.repo_name.clone());
    report.threat_model = threat_model;
    report.app_profile = app_profile;
    if config.emit_unreachable_appendix {
        report.unreachable_files = manifest.unreachable_files.clone();
    }
    report.git_sha = input
        .git_sha_override
        .clone()
        .or_else(|| head_sha(&input.repo_root));

    if stop_after == Some(StopAfter::S8) {
        return Ok(ScanOutcome {
            provider_writeback_plan: None,
            stopped_after: Some(StopAfter::S8),
            report: Some(reporting::redact_report(&report)?),
            markdown: None,
            sarif: None,
        });
    }

    // S9 is a distinct deterministic pipeline stage; it spends no model
    // tokens. Its timing goes to the event stream only: the report it
    // renders cannot contain its own duration.
    let s9_run = StageRun::start(progress, Stage9::NAME);
    let rendered = Stage9 {
        tool_version: config.tool_version.clone(),
    }
    .run(report)
    .await?
    .into_value();
    s9_run.finish(
        progress,
        &mut telemetry::StageTimings::new(),
        StageStatus::Completed,
        vec![("findings", telemetry::count(rendered.report.findings.len()))],
        None,
    );
    Ok(ScanOutcome {
        provider_writeback_plan: Some(rendered.provider_writeback_plan),
        stopped_after: (stop_after == Some(StopAfter::S9)).then_some(StopAfter::S9),
        report: Some(rendered.report),
        markdown: Some(rendered.markdown),
        sarif: Some(rendered.sarif),
    })
}

/// Everything one remediation run needs beyond the report/repo
/// themselves.
pub struct RemediateConfig {
    pub step10: bc_stage_s10::Step10Config,
    /// `--top` cap; `None` means "no CLI override — use whatever
    /// [`resolve_top`](bc_stage_s10::resolve_top) computes from the
    /// profile default, if any."
    pub top: Option<bc_stage_s10::TopSpec>,
    /// Profile-configured default cap (`step_remediate.top_n_findings`);
    /// `None` when the config doesn't set one.
    pub top_default: Option<bc_stage_s10::TopSpec>,
    /// Bypasses the git-SHA staleness refusal below.
    pub force: bool,
    /// `--resume`: consult `checkpoint` (see [`remediate`]) before
    /// re-running each finding, skipping any whose stored
    /// [`bc_stage_s10::finding_identity`] still matches. Has no effect
    /// when `checkpoint` is `None`.
    pub resume: bool,
    /// Whether `repo` (the path [`remediate`] is given) is a throwaway
    /// detached worktree rather than the user's own checkout — set by the
    /// CLI layer, which is the only thing that knows how the executor was
    /// rooted.
    ///
    /// Purely a message-shaping flag: it decides which pre-remediation
    /// stderr warning is printed. The in-place wording ("about to EDIT
    /// source files in <path>") is ported from `orchestrator/scan.py:
    /// 604-611` and exists so a user who did not realize `--remediate`
    /// writes to their working tree gets one chance to see that before it
    /// happens. Printing it for an isolated run would be a lie — nothing
    /// under `--repo` is written at all — and a warning that cries wolf is
    /// a warning nobody reads on the run that matters.
    pub isolated: bool,
}

/// The outcome of [`remediate`]: either the preflight refused to run at
/// all (`refused`, ported from `orchestrator/scan.py::
/// _remediate_preflight` — remediation is disabled for this run, but the
/// scan itself already completed and its own output is unaffected), or a
/// per-finding [`bc_stage_s10::RemediationOutcome`] for every finding
/// selected.
#[derive(Debug, Default)]
pub struct RemediateOutcome {
    pub refused: Option<String>,
    pub outcomes: Vec<bc_stage_s10::RemediationOutcome>,
    /// One entry per `outcomes[i]` when S11 validation ran (`validate`
    /// was `Some` in the [`remediate`] call) — `Some(score)` for a
    /// `Processed` outcome with something to validate, `None` for a
    /// `Failed` outcome or a `Processed` one with no actual diff. Empty
    /// (not one `None` per outcome) when validation didn't run at all,
    /// so callers can distinguish "validation disabled" from "nothing
    /// was validatable."
    pub validations: Vec<Option<bc_validation_scoring::ValidationScore>>,
    /// How many `validate_finding` calls returned `Err` (an actual
    /// validation attempt failing — LLM call error, malformed response —
    /// not "wasn't selected for validation"). These findings ALSO show up
    /// as `None` in `validations` since there's no score to report, but
    /// this count keeps that failure from being silently indistinguishable
    /// from "not selected"; each one is also `eprintln!`'d at the point of
    /// failure, matching Python's own `FAILED: {id} — {reason}` line
    /// (`validation/cli/_run.py::_run_reports`).
    pub validation_failures: usize,
}

/// Redacts every string a [`RemediateOutcome`] carries that could echo
/// secret material an agent quoted from source — diffs (the diff of a
/// hardcoded-secret fix can itself contain the secret), agent-authored
/// summaries/root-cause text, and S11 validation justifications —
/// applied once here so both the batch ([`remediate`]) and interactive
/// (`bc-cli::remediate_interactively`) paths get the same "redact before
/// write" guarantee [`run_scan`]'s own report redaction already
/// provides. Callers apply this to the outcome they're about to return,
/// mirroring `run_scan`'s own placement (redact once, right before the
/// value is handed back) rather than requiring every downstream
/// serializer (`--out-remediation-json`, the S11 report-augmentation
/// SARIF/Markdown re-write) to redact for itself.
pub fn redact_remediate_outcome(mut outcome: RemediateOutcome) -> RemediateOutcome {
    for o in &mut outcome.outcomes {
        match o {
            bc_stage_s10::RemediationOutcome::Processed(record) => {
                **record = redact_remediation_record(record);
            }
            bc_stage_s10::RemediationOutcome::Failed { error, .. } => {
                *error = bc_redact::redact(error);
            }
        }
    }
    for score in outcome.validations.iter_mut().flatten() {
        redact_validation_score(score);
    }
    outcome
}

/// [`bc_stage_s10::RemediationRecord`] already derives `Serialize`/
/// `Deserialize` (for checkpoint round-tripping), so the same JSON-
/// round-trip technique `run_scan` uses for `FinalReport` applies here
/// unchanged — a future field addition is covered for free rather than
/// silently bypassing redaction if a hand-rolled per-field pass forgot it.
///
/// The diff is the one exception: `redact_tree` would redact it as plain
/// text, and a multi-line match (a PEM block) collapses hunk lines and
/// breaks the patch framing that `--post-fixes-from`, `git apply` and
/// S11's diff tools all parse. It is redacted structure-aware instead.
fn redact_remediation_record(
    record: &bc_stage_s10::RemediationRecord,
) -> bc_stage_s10::RemediationRecord {
    let json = serde_json::to_value(record).expect("RemediationRecord always serializes");
    let mut redacted: bc_stage_s10::RemediationRecord =
        serde_json::from_value(bc_redact::redact_tree(&json))
            .expect("redact_tree preserves JSON shape, so RemediationRecord deserializes back");
    redacted.diff = record.diff.as_deref().map(bc_redact::redact_diff);
    redacted
}

/// `bc_validation_scoring::ValidationScore` deliberately has no
/// `serde`/I/O dependency at all (its own module doc: "Pure logic, no
/// I/O") — a per-field pass here, rather than pulling `serde` into that
/// crate just for this, keeps that boundary intact.
fn redact_validation_score(score: &mut bc_validation_scoring::ValidationScore) {
    score.justification = bc_redact::redact(&score.justification);
    for gate in &mut score.gate_results {
        gate.summary = bc_redact::redact(&gate.summary);
        gate.details = bc_redact::redact(&gate.details);
        for evidence in &mut gate.evidence {
            evidence.snippet = bc_redact::redact(&evidence.snippet);
        }
    }
}

/// The band label [`bc_stage_s10::select_top_by_cvss`] falls back to
/// when a finding has no numeric CVSS score. `pub` (not just used
/// internally by [`remediate`]) so `bc-cli`'s `-i`/`--interactive`
/// dispatch can reuse the exact same CVSS/severity-band selection logic
/// for an explicit `--top N` in interactive mode, rather than
/// duplicating this mapping a second time.
pub fn severity_str(s: bc_model::Severity) -> &'static str {
    match s {
        bc_model::Severity::Critical => "CRITICAL",
        bc_model::Severity::High => "HIGH",
        bc_model::Severity::Medium => "MEDIUM",
        bc_model::Severity::Low => "LOW",
        bc_model::Severity::Info => "INFO",
    }
}

/// Ported from `orchestrator/scan.py::_remediate_preflight`: `Some(reason)`
/// if the repo's current git HEAD has moved since `report` was built and
/// `force` wasn't set — a stale line number would make the agent's
/// file:line evidence land on the wrong code. Shared by [`remediate`]
/// (the `--top` batch path) and `bc-cli`'s `-i`/`--interactive` picker
/// dispatch, so both paths refuse identically rather than risking the
/// staleness check drifting out of sync between them.
pub fn stale_refusal(report: &FinalReport, repo: &Path, force: bool) -> Option<String> {
    let (Some(report_sha), Some(current_sha)) = (&report.git_sha, head_sha(repo)) else {
        return None;
    };
    if report_sha == &current_sha || force {
        return None;
    }
    Some(format!(
        "HEAD moved since scan ({} -> {}); pass --force to override",
        &report_sha[..report_sha.len().min(8)],
        &current_sha[..current_sha.len().min(8)],
    ))
}

/// Rolls a remediation back once S11 has independently graded it `Not
/// Fixed` or `UNVERIFIABLE`.
///
/// The gap this closes: S11 is the only thing in the pipeline that looks at
/// a fix adversarially, and until now it only ever *recorded* its verdict.
/// A patch S11 graded `Not Fixed` stayed on disk, went into the report, and
/// was posted to a PR exactly like one graded `Fixed` — an unverified edit
/// to the user's working tree that looks like a fix and is not one.
///
/// **`baseline` is what makes this work without a VCS.** S10 hands each
/// finding's own pre-remediation bytes forward
/// (`bc_stage_s10::RemediationRun::baselines`), so the rollback is the same
/// byte-exact, VCS-free restore S10's in-loop gates perform. Only when
/// there is no baseline, which means a `--resume`d record whose snapshot
/// lived in the process that first ran it, does this fall back to
/// [`bc_stage_s10::revert_record`]'s git path. That fallback is a no-op
/// against a target that is not a git worktree, and it was a no-op
/// unconditionally under the old `distroless/cc` runtime, which shipped no
/// `git`: the field failure this replaces was `[s11] WARNING: cannot roll
/// back finding 4: /scan/repo is not a git repository ... the patch is
/// still applied` on a path-traversal fix S11 had just graded `Not Fixed`
/// (GitHub Actions run 34021176323). The packaged image ships `git` now,
/// so the fallback can actually fire there, but the baseline stays the
/// primary path because it needs no repository at all.
///
/// **`protected` is why a rollback can be partial.** S10 remediates every
/// selected finding before S11 validates any of them, so a LATER finding
/// may have edited one of these files and been kept. This finding's
/// baseline predates that edit, so restoring the file would destroy a good
/// fix to undo a bad one. Those files are left applied and each one is
/// warned about by name.
///
/// Every failure here is a loud warning rather than an error: the run's
/// other output is still valid, and what the operator must not be left
/// guessing about is whether the tree was modified. `keep_unverified` opts
/// out entirely.
fn revert_if_validation_failed(
    repo: &Path,
    record: &mut bc_stage_s10::RemediationRecord,
    baseline: Option<&bc_stage_s10::Baseline>,
    protected: &BTreeMap<String, i64>,
    score: &bc_validation_scoring::ValidationScore,
    step10: &bc_stage_s10::Step10Config,
) {
    use bc_validation_scoring::FixVerdict;
    if step10.keep_unverified
        || !matches!(
            score.fix_status,
            FixVerdict::NotFixed | FixVerdict::Unverifiable
        )
    {
        return;
    }
    let report = bc_stage_s10::revert_after_failed_validation(
        repo,
        record,
        baseline,
        protected,
        score.fix_status.as_str(),
    );
    for warning in &report.warnings {
        eprintln!("  [s11] WARNING: {warning}");
    }
    if let Some(line) = &report.restored {
        eprintln!("  [s11] {line}");
    }
}

/// Everything [`remediate`] needs to additionally run S11 fix validation
/// right after remediation — a separate, optional bundle (rather than
/// folding into [`RemediateConfig`]) so a caller that never enables
/// validation doesn't need to construct a `Step11Config` or a read-only
/// `ToolExecutor` it won't use. `None` disables validation entirely
/// (`RemediateOutcome.validations` stays empty in that case).
pub struct ValidateConfig<'a> {
    pub step11: &'a bc_stage_s11::Step11Config,
    /// MUST be read-only — never the write-capable executor `remediate`
    /// itself uses. Validation never mutates source, matching the Python
    /// original's own trust-model guarantee.
    pub tools: &'a dyn ToolExecutor,
}

/// Runs S10 remediation against an already-built `report`'s findings,
/// optionally chaining Phase 3's scoped S11 fix validation right after
/// each remediated finding. Ported from `orchestrator/scan.py::
/// _run_remediation` + `_remediate_preflight`: refuses (returns
/// `refused: Some(reason)`, no findings touched) if the repo's current
/// git HEAD has moved since `report` was built and `config.force` wasn't
/// set — a stale line number would make the agent's file:line evidence
/// land on the wrong code. Otherwise selects the top-N findings by CVSS
/// (highest first, [`bc_stage_s10::select_top_by_cvss`]) and remediates
/// them sequentially via [`bc_stage_s10::run_remediation`].
///
/// `tools` MUST be write-capable (`SandboxTools::new_with_write`) —
/// unlike `run_scan`'s read-only `tools`, this is a deliberately separate
/// executor instance the caller constructs.
///
/// `checkpoint` (when given) enables `--resume`'s skip check
/// (`config.resume`) and always receives a save for every successfully
/// processed finding, regardless of `config.resume` — see
/// [`bc_stage_s10::run_remediation`]'s own doc comment for the exact
/// semantics. Its `run_id` is [`bc_checkpoint::run_id_for(repo)`],
/// deliberately the SAME construction the (not-yet-checkpointed) S1-S9
/// scan pipeline would use, so remediation and scan checkpoints share
/// one run namespace, disambiguated by step key
/// (`remediate_<finding_index>` vs. `s1`..`s9`).
///
/// `validate`, when `Some`, runs [`bc_stage_s11::validate_finding`] for
/// every `Processed` outcome that actually changed something on disk
/// (`record.diff.is_some()`) — reusing the SAME `selected` findings list
/// this function already built for `run_remediation`, so there's no
/// re-derivation of the CVSS-selected subset and no risk of the two
/// walks drifting apart. Sequential per finding, matching
/// `run_remediation`'s own per-finding walk (each finding's own
/// architect+pentester calls run concurrently internally — see
/// `bc_stage_s11::validate_finding`'s own doc comment for why that's
/// safe here but remediation itself stays sequential). A validation
/// [`bc_llm_client::LlmError`] is treated the same way a missing diff
/// is (`None` for that finding) — a transient validation failure must
/// never take down the whole remediation run's own, already-real,
/// output.
#[allow(clippy::too_many_arguments)]
pub async fn remediate(
    llm: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    repo: &Path,
    report: &FinalReport,
    config: &RemediateConfig,
    policy: Option<&bc_stage_s10::PolicyContext>,
    checkpoint: Option<Arc<dyn bc_checkpoint::CheckpointStore>>,
    validate: Option<ValidateConfig<'_>>,
) -> RemediateOutcome {
    remediate_observed(
        llm,
        tools,
        repo,
        report,
        config,
        policy,
        checkpoint,
        validate,
        &RemediateTelemetry::default(),
    )
    .await
}

/// The S10/S11 stage names on the [`bc_pipeline_core::ScanEvent`] stream,
/// shaped like the S1-S8 stage crates' own `NAME`s.
pub const S10_STAGE: &str = "s10-remediate";
pub const S11_STAGE: &str = "s11-validate";

/// Where [`remediate_observed`] reports S10/S11 telemetry, and how it
/// prices their model calls. A separate bundle rather than more
/// [`RemediateConfig`] fields because it is the scan's (the same sink and
/// pricing [`ScanConfig`] carried), not remediation's own settings. The
/// [`Default`] observes nothing and prices nothing, which is exactly what
/// [`remediate`] passes.
#[derive(Debug, Clone, Default)]
pub struct RemediateTelemetry {
    pub progress: Option<bc_pipeline_core::ProgressSink>,
    pub pricing: pricing::PricingConfig,
    /// The run's cooperative cancellation (the scan's own token). Once it
    /// trips, remediation does not start, S10 starts no further finding
    /// and refuses the running agent's next model call (its own error
    /// path then rolls the partial patch back), the verify command is
    /// killed, and S11 is skipped.
    pub cancel: Option<bc_pipeline_core::CancelTokenRef>,
}

/// Closes S10 and S11 as skipped because the run was canceled before
/// remediation could start: the caller's counterpart of
/// [`remediation_not_requested`], so the manifest still accounts for both.
pub fn remediation_canceled(progress: Option<&bc_pipeline_core::ProgressSink>, reason: &str) {
    cancellation::skip_stages(
        progress,
        &mut telemetry::StageTimings::new(),
        &[S10_STAGE, S11_STAGE],
        reason,
    );
}

/// Closes S10 and S11 as `disabled` for a scan that reached S9 and was not
/// asked to remediate: Python's `_sp_done("s10", outcome="disabled")` when
/// `--remediate` is off, so the stage list and the run manifest account
/// for all twelve stages rather than silently stopping at S9.
pub fn remediation_not_requested(progress: Option<&bc_pipeline_core::ProgressSink>) {
    let mut timings = telemetry::StageTimings::new();
    for stage in [S10_STAGE, S11_STAGE] {
        telemetry::record_unstarted(
            progress,
            &mut timings,
            stage,
            StageStatus::Disabled,
            Some("remediation not requested".to_string()),
        );
    }
}

/// Emits one remediation stage's spend. `record_usage` without the
/// `tokens_by_phase` map: S10/S11 run after the report's metrics exist,
/// so there is no map to fold them into, only the event stream (and
/// through it the run manifest, the one output that sees the whole run).
fn emit_usage(
    progress: Option<&bc_pipeline_core::ProgressSink>,
    stage: &'static str,
    usage: PhaseUsage,
) {
    bc_pipeline_core::emit(
        progress,
        bc_pipeline_core::ScanEvent::UsageUpdate {
            stage,
            usage: stage_usage(usage),
        },
    );
}

/// [`remediate`], additionally reporting S10 and S11 as stages on
/// `telemetry.progress`: start/finish events with Python's stage-done
/// counters (`orchestrator/scan.py:846-902`: S10 `attempted`/`fixed`/
/// `not_fixed`, plus `failed` here; S11 `validated`/`passed`/`failed`)
/// and per-stage token spend. The remediation client is wrapped in the
/// same [`UsageTrackingClient`] the scan uses, so S10 and S11 are metered
/// and priced as their own phases instead of going unrecorded.
///
/// A refused run (stale HEAD) reports both stages `disabled` with the
/// reason, and a report with nothing to remediate does too, matching
/// Python's `_sp_done("s10", outcome="disabled")`; S11 is `disabled`
/// whenever `validate` is `None`.
#[allow(clippy::too_many_arguments)]
pub async fn remediate_observed(
    llm: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    repo: &Path,
    report: &FinalReport,
    config: &RemediateConfig,
    policy: Option<&bc_stage_s10::PolicyContext>,
    checkpoint: Option<Arc<dyn bc_checkpoint::CheckpointStore>>,
    validate: Option<ValidateConfig<'_>>,
    telemetry: &RemediateTelemetry,
) -> RemediateOutcome {
    let progress = telemetry.progress.as_ref();
    // S10/S11 finish after the report was built, so their timings have no
    // `ScanMetrics` to land in; the events carry them instead.
    let mut timings = telemetry::StageTimings::new();
    let disable_both = |timings: &mut telemetry::StageTimings, reason: &str| {
        telemetry::record_unstarted(
            progress,
            timings,
            S10_STAGE,
            StageStatus::Disabled,
            Some(bc_redact::redact(reason)),
        );
        telemetry::record_unstarted(
            progress,
            timings,
            S11_STAGE,
            StageStatus::Disabled,
            Some("remediation did not run".to_string()),
        );
    };
    // Before anything else, the staleness check included: remediation must
    // never START after a cancellation.
    if let Some(reason) = bc_pipeline_core::canceled(telemetry.cancel.as_ref()) {
        remediation_canceled(progress, &reason);
        return RemediateOutcome {
            refused: Some(reason),
            ..RemediateOutcome::default()
        };
    }
    if let Some(reason) = stale_refusal(report, repo, config.force) {
        disable_both(&mut timings, &reason);
        return RemediateOutcome {
            refused: Some(reason),
            outcomes: Vec::new(),
            validations: Vec::new(),
            validation_failures: 0,
        };
    }

    let top = bc_stage_s10::resolve_top(config.top, config.top_default);
    let positions = bc_stage_s10::select_top_by_cvss(
        report.findings.len(),
        top,
        |i| report.findings[i].finding.cvss_score,
        |i| severity_str(report.findings[i].severity),
    );
    let selected: Vec<(i64, bc_model::RankedFinding)> = positions
        .into_iter()
        .map(|pos| ((pos + 1) as i64, report.findings[pos].clone()))
        .collect();
    // Nothing to remediate is Python's `not (rem_on and report.findings)`
    // branch: both stages close `disabled`. The walk below still runs (a
    // no-op) so checkpoint registration behaves exactly as before.
    let nothing_selected = selected.is_empty();
    if nothing_selected {
        disable_both(&mut timings, "no findings selected for remediation");
    }

    // Ported from `orchestrator/scan.py`'s own pre-remediation warning: the
    // one place a scan stops being read-only. It goes to stderr, before any
    // agent runs, and names the directory about to be edited — a user who
    // did not realize `--remediate` writes to their working tree gets one
    // chance to see that before it happens.
    //
    // `isolated` runs get a plain informational line instead: the agent
    // edits a throwaway checkout and the user's own files are never
    // touched, so there is nothing to warn about — see
    // `RemediateConfig::isolated`.
    if !selected.is_empty() {
        if config.isolated {
            eprintln!(
                "  [s10] remediating in an isolated worktree at {}; your \
                 checkout is not modified",
                repo.display()
            );
        } else {
            let mode = if config.step10.dry_run {
                "DRY RUN — will edit and then roll back every change in"
            } else {
                "FIX MODE — about to EDIT source files in"
            };
            eprintln!(
                "  [s10] ⚠ {mode} {}; rerun with --stop-after s9 to scan without \
                 modifying the target",
                repo.display()
            );
        }
    }

    let run_id = bc_checkpoint::run_id_for(repo);
    if let Some(cp) = &checkpoint {
        // Upsert the run's metadata row so a later `gc` pass can rank it
        // by recency — ported from `scan.py`'s own `register_run` call,
        // done once per invocation that uses checkpoints at all.
        cp.register_run(
            &run_id,
            &report.repo_root,
            report.repo_name.as_deref(),
            report
                .app_profile
                .as_ref()
                .map(|ap| ap.application_id.as_str()),
        );
        // Fresh (non-`--resume`) run == start over: purge this run_id's
        // prior checkpoints now, so the only state a later `--resume`
        // can see is from THIS run — ported from `scan.py`'s own
        // `reset_run` call, gated the same way on `not args.resume`.
        if !config.resume {
            cp.reset_run(&run_id);
        }
    }
    // `baselines` is aligned 1:1 with `outcomes` and never leaves this
    // function: it holds each finding's pre-remediation file bytes purely
    // so `revert_if_validation_failed` below can undo a patch without git.
    //
    // Metered like the scan's own client (see `UsageTrackingClient`), so
    // S10 and S11 are attributed as phases of their own; `llm` is shadowed
    // so both stages' calls below go through it unchanged.
    let tracker = Arc::new(UsageTrackingClient::new(llm, &telemetry.pricing));
    let llm = cancel_aware_client(tracker.clone(), telemetry.cancel.clone());
    // S10 checks the same token between findings and while its verify
    // command runs; see `Step10Config::cancel`.
    let mut step10 = config.step10.clone();
    step10.cancel = telemetry.cancel.clone();
    let s10_run = (!nothing_selected).then(|| StageRun::start(progress, S10_STAGE));
    let bc_stage_s10::RemediationRun {
        mut outcomes,
        baselines,
    } = bc_stage_s10::run_remediation(
        llm.as_ref(),
        tools.as_ref(),
        repo,
        &selected,
        &step10,
        policy,
        checkpoint.as_deref(),
        &run_id,
        config.resume,
    )
    .await;
    if let Some(run) = s10_run {
        emit_usage(progress, S10_STAGE, tracker.take());
        let counts = telemetry::remediation_counts(&outcomes);
        // An agent session that errored is lost work, Python's
        // `completed_with_errors`; a finding the agent looked at and did
        // not fix is a verdict, not an error.
        let failed = outcomes
            .iter()
            .any(|o| matches!(o, bc_stage_s10::RemediationOutcome::Failed { .. }));
        run.finish(
            progress,
            &mut timings,
            StageStatus::from_degraded(failed),
            counts,
            None,
        );
    }

    // A cancellation during S10 skips S11 outright: validating patches the
    // operator has just asked the run to stop producing is new work.
    let s11_cancel = bc_pipeline_core::canceled(telemetry.cancel.as_ref())
        .filter(|_| validate.is_some() && !nothing_selected);
    let validate = validate.filter(|_| s11_cancel.is_none());
    if let Some(reason) = &s11_cancel {
        cancellation::skip_stages(progress, &mut timings, &[S11_STAGE], reason);
    }
    // S11's own stage: only when S10 had something to hand it (otherwise
    // `disable_both` already closed it) and validation was asked for.
    let s11_run = match (&validate, nothing_selected || s11_cancel.is_some()) {
        (Some(_), false) => Some(StageRun::start(progress, S11_STAGE)),
        (None, false) => {
            telemetry::record_unstarted(
                progress,
                &mut timings,
                S11_STAGE,
                StageStatus::Disabled,
                Some("validation disabled".to_string()),
            );
            None
        }
        (_, true) => None,
    };
    let mut validations = Vec::new();
    let mut validation_failures = 0usize;
    if let Some(v) = validate {
        validations = vec![None; outcomes.len()];
        // `step_validate.max_findings` caps validation to the top-N of
        // these by CVSS (highest first) — reusing the SAME
        // `select_top_by_cvss` helper S10's own `--top` selection above
        // uses, matching `dto_loader.py::select_reports`/`_top_by_cvss`'s
        // "trim the validatable pool, don't touch anything else" scope.
        //
        // Owned clones rather than borrows into `outcomes`: the loop below
        // MUTATES `outcomes[i]` to mark a record S11 just rolled back, and
        // a live `&` into the same vector would forbid that. A record is a
        // handful of strings; the alternative — collect decisions now,
        // apply them in a second pass — separates the rollback from the
        // reason for it across two loops for no real gain.
        let validatable: Vec<(usize, bc_stage_s10::RemediationRecord)> = outcomes
            .iter()
            .enumerate()
            .filter_map(|(i, outcome)| {
                let bc_stage_s10::RemediationOutcome::Processed(record) = outcome else {
                    return None;
                };
                record.diff.is_some().then(|| (i, record.as_ref().clone()))
            })
            .collect();
        let chosen_positions: BTreeSet<usize> = bc_stage_s10::select_top_by_cvss(
            validatable.len(),
            v.step11.max_findings,
            |pos| selected[validatable[pos].0].1.finding.cvss_score,
            |pos| severity_str(selected[validatable[pos].0].1.severity),
        )
        .into_iter()
        .collect();

        for (pos, (i, record)) in validatable.iter().enumerate() {
            // Stop starting validation sessions once canceled; the ones
            // not reached stay `None`, "not validated".
            let canceled = bc_pipeline_core::canceled(telemetry.cancel.as_ref()).is_some();
            if canceled || !chosen_positions.contains(&pos) {
                continue;
            }
            let i = *i;
            let finding = &selected[i].1;
            // Checkpointed per (finding, redacted diff, persona models), so
            // `--resume` reuses a panel's score instead of re-running it
            // (vvaharness v1.3 `validate_` steps).
            match bc_stage_s11::validate_finding_checkpointed(
                llm.as_ref(),
                v.tools,
                repo,
                finding,
                record,
                v.step11,
                checkpoint.as_deref(),
                &run_id,
                config.resume,
            )
            .await
            {
                Ok(score) => {
                    // Computed against the CURRENT `outcomes`, immediately
                    // before the rollback that consumes it: a finding
                    // processed later in S10's walk may hold a kept patch
                    // on one of these same files, and that patch must
                    // survive undoing this one.
                    let protected =
                        bc_stage_s10::files_kept_by_later_findings(&outcomes, &baselines, i);
                    // The rollback marks the record (see
                    // `bc_stage_s10::note_record_reverted`), so the updated
                    // copy has to replace the one in `outcomes` — that is
                    // what every downstream consumer reads. Writing the
                    // whole variant back, rather than reaching into the one
                    // in place, keeps this total: nothing here has to
                    // re-assert that `outcomes[i]` is still `Processed`.
                    let mut updated = record.clone();
                    revert_if_validation_failed(
                        repo,
                        &mut updated,
                        baselines[i].as_ref(),
                        &protected,
                        &score,
                        &config.step10,
                    );
                    outcomes[i] = bc_stage_s10::RemediationOutcome::Processed(Box::new(updated));
                    validations[i] = Some(score);
                }
                Err(e) => {
                    // Surfaced loudly rather than silently folded into
                    // "not selected for validation" — matches Python's
                    // own `FAILED: {id} — {reason}` line
                    // (`validation/cli/_run.py::_run_reports`).
                    eprintln!(
                        "  [s11] FAILED: validation error for finding {}: {e}",
                        record.finding_id
                    );
                    validation_failures += 1;
                }
            }
        }
    }
    if let Some(run) = s11_run {
        emit_usage(progress, S11_STAGE, tracker.take());
        run.finish(
            progress,
            &mut timings,
            StageStatus::from_degraded(validation_failures > 0),
            telemetry::validation_counts(&validations, validation_failures),
            (validation_failures > 0)
                .then(|| format!("{validation_failures} validation session(s) errored")),
        );
    }

    redact_remediate_outcome(RemediateOutcome {
        refused: None,
        outcomes,
        validations,
        validation_failures,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use bc_llm_client::{
        ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, ToolSpec, Usage,
    };
    use serde_json::{json, Value};

    use super::*;

    /// Cooperative Ctrl-C through the pipeline, and the pipeline
    /// diagnostics' path into the report.
    mod cancel_scan;
    /// Resume chaining, stage telemetry and S10/S11 metering, kept in
    /// their own file (`src/tests/run_telemetry.rs`) rather than grown
    /// onto this one; as a child module it reuses every fixture here.
    mod run_telemetry;

    // Boxed trait object (not a generic type param) so every test's
    // routing closure shares one compiled `chat` body — see
    // `feedback_coverage_tool_gotchas.md` on generic-fixture coverage
    // splitting.
    type Router = Box<dyn Fn(&str) -> Result<String, LlmError> + Send + Sync>;

    struct RoutedClient {
        router: Router,
    }

    impl RoutedClient {
        fn new(router: impl Fn(&str) -> Result<String, LlmError> + Send + Sync + 'static) -> Self {
            RoutedClient {
                router: Box::new(router),
            }
        }
    }

    #[async_trait]
    impl LlmClient for RoutedClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let system = request.system.as_deref().unwrap_or("");
            let text = (self.router)(system)?;
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(text)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    struct NoTools;
    impl ToolExecutor for NoTools {
        fn available_tools(&self) -> Vec<ToolSpec> {
            ["Read", "Glob", "Grep"]
                .iter()
                .map(|name| ToolSpec {
                    name: name.to_string(),
                    description: String::new(),
                    parameters: json!({}),
                })
                .collect()
        }
        fn execute(&self, _name: &str, _args: &Value) -> String {
            String::new()
        }
    }

    /// One phase's worth of usage from a single call that DID report
    /// usage — the shape `UsageTrackingClient::take` hands `record_usage`
    /// after a stage that made one billable request.
    fn phase_usage(usage: Usage) -> PhaseUsage {
        PhaseUsage {
            usage,
            calls: 1,
            calls_with_usage: 1,
            cost: pricing::PhaseCost::default(),
            truncated_replies: 0,
        }
    }

    /// [`phase_usage`] with that one call actually costed, the way
    /// [`UsageTrackingClient::chat`] costs it as it returns.
    fn priced_phase(provider: Option<&str>, model: &str, usage: Usage) -> PhaseUsage {
        let mut phase = phase_usage(usage);
        let config = pricing::PricingConfig::for_provider(provider);
        phase
            .cost
            .record_call(&config.pricer(), provider, model, usage, config.cache_ttl);
        phase
    }

    /// [`scan_config`] pointed at a real provider, with every stage's
    /// model set to `model`. `"gpt-4o"` is the CLI's own default and a
    /// real vendored entry: 2.50 USD per million input tokens, 10.00 per
    /// million output, 1.25 per million cache reads, and deliberately NO
    /// published cache-write rate, which is what makes it useful for the
    /// partially-rated case too.
    fn priced_scan_config(provider: Option<&str>, model: &str) -> ScanConfig {
        let mut config = scan_config();
        config.pricing = pricing::PricingConfig::for_provider(provider);
        config.step1.model = model.to_string();
        config.step2.model = model.to_string();
        config.step3.model = model.to_string();
        config.step4.model = model.to_string();
        config.step5.dedup.model = model.to_string();
        config.step6.model = model.to_string();
        config.step7.model = model.to_string();
        config.step8.model = model.to_string();
        config
    }

    const S1_SYSTEM_MARK: &str = "security-focused codebase mapper";
    const S2_SYSTEM_MARK: &str = "application-security threat modeler";
    const S3_SYSTEM_MARK: &str = "vulnerability research strategist";
    const S4_SYSTEM_MARK: &str = "security researcher performing deep code analysis";
    const S6_SYSTEM_MARK: &str = "second-opinion reviewer";
    const S8_SYSTEM_MARK: &str = "exploit development strategist";

    const S1_JSON: &str = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
    const S2_JSON: &str = r#"{"system_context":"ctx","assets":[{"name":"user records"}],"trust_boundaries":[],"threats":[],"open_questions":[]}"#;
    const S3_GARBAGE: &str = "not valid json at all, deliberately garbage so s3 degrades to its deterministic catchall sweep";
    const S4_EMPTY: &str = r#"{"findings": []}"#;
    const GOOD_CVSS: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";

    /// One shared, non-generic dispatch function used by every test's
    /// router closure below (not an inline per-test `if`/`else` chain) —
    /// a plain function has exactly one compiled body regardless of how
    /// many different `table` slices call sites pass it, so its "no mark
    /// matched" fallback is a single instance, covered once by
    /// `route_panics_on_an_unrecognized_system_prompt` below, rather than
    /// N copies each only reachable from a bug in that one test's own
    /// mark set.
    fn route(system: &str, table: &[(&str, &str)]) -> String {
        for (mark, reply) in table {
            if system.contains(mark) {
                return (*reply).to_string();
            }
        }
        panic!("unrecognized system prompt in test router: {system}");
    }

    #[test]
    #[should_panic(expected = "unrecognized system prompt")]
    fn route_panics_on_an_unrecognized_system_prompt() {
        route("zzz-totally-unmatched-zzz", &[("xyz-mark-xyz", "reply")]);
    }

    #[test]
    fn no_tools_execute_returns_an_empty_string() {
        assert_eq!(NoTools.execute("Read", &json!({})), "");
    }

    fn s4_one_finding_json() -> String {
        json!({"findings": [{
            "file": "app.py", "line_start": 10, "line_end": 12,
            "vuln_class": "injection", "title": "SQL injection", "description": "user input reaches a raw query",
            "code_snippet": "cur.execute(q)", "confidence": 0.9,
            "source_ref": "app.py:10", "sink_ref": "app.py:12",
        }]})
        .to_string()
    }

    fn s4_finding_on(file: &str) -> String {
        json!({"findings": [{
            "file": file, "line_start": 10, "line_end": 12,
            "vuln_class": "injection", "title": "SQL injection", "description": "user input reaches a raw query",
            "code_snippet": "cur.execute(q)", "confidence": 0.9,
            "source_ref": format!("{file}:10"), "sink_ref": format!("{file}:12"),
        }]})
        .to_string()
    }

    fn s6_true_positive_text() -> String {
        format!(
            "traced it\nVERDICT: TRUE_POSITIVE (confidence: 9/10) — reachable\nCVSS: {GOOD_CVSS}\n"
        )
    }

    fn s8_ranked_json() -> String {
        json!({
            "summary": "One SQL injection finding.",
            "ranked_findings": [{"index": 0, "severity": "high", "exploitability_notes": "reachable from an external request"}],
            "chains": [],
        })
        .to_string()
    }

    /// Client whose router recognizes only the marks in `table` — S1/S2
    /// always succeed, S3 always degrades (exercising its deterministic
    /// catchall sweep instead of needing a well-formed `TaskManifest`),
    /// and S4/S6/S8's replies are supplied by the caller. Omitting a
    /// later stage's mark from `table` is itself the "this stage must not
    /// be called" assertion for `stop_after` tests — `route`'s shared
    /// panic fires if the scan proceeds further than expected.
    fn client_with(table: Vec<(&'static str, String)>) -> Arc<dyn LlmClient> {
        Arc::new(RoutedClient::new(move |system: &str| {
            let owned: Vec<(&str, &str)> = table.iter().map(|(m, r)| (*m, r.as_str())).collect();
            Ok(route(system, &owned))
        }))
    }

    fn full_table(s4: &str, s6: &str, s8: &str) -> Vec<(&'static str, String)> {
        vec![
            (S1_SYSTEM_MARK, S1_JSON.to_string()),
            (S2_SYSTEM_MARK, S2_JSON.to_string()),
            (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
            (S4_SYSTEM_MARK, s4.to_string()),
            (S6_SYSTEM_MARK, s6.to_string()),
            (S8_SYSTEM_MARK, s8.to_string()),
        ]
    }

    fn empty_findings_client() -> Arc<dyn LlmClient> {
        client_with(full_table(S4_EMPTY, "", ""))
    }

    fn one_finding_client() -> Arc<dyn LlmClient> {
        let s6 = s6_true_positive_text();
        let s8 = s8_ranked_json();
        client_with(full_table(&s4_one_finding_json(), &s6, &s8))
    }

    /// Wraps an inner client, overwriting every response's `usage` with a
    /// fixed value — `RoutedClient` always reports `Usage::default()`
    /// (zero), which makes it impossible to drive `spend_cap`'s token
    /// check via the standard fixtures without this.
    struct UsageInjectingClient {
        inner: Arc<dyn LlmClient>,
        usage: Usage,
    }

    #[async_trait]
    impl LlmClient for UsageInjectingClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let mut response = self.inner.chat(request).await?;
            response.usage = self.usage;
            Ok(response)
        }
    }

    /// Like [`UsageInjectingClient`], but only overwrites `usage` for the
    /// one call whose system prompt contains `mark` — every other call
    /// keeps the inner client's own (zero, for `RoutedClient`) usage.
    /// Lets a test push the cumulative token total over budget at
    /// exactly one specific stage boundary, to prove `spend_cap` trips
    /// there and not earlier.
    struct MarkedUsageClient {
        inner: Arc<dyn LlmClient>,
        mark: &'static str,
        usage: Usage,
    }

    #[async_trait]
    impl LlmClient for MarkedUsageClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let mut response = self.inner.chat(request).await?;
            if request.system.as_deref().unwrap_or("").contains(self.mark) {
                response.usage = self.usage;
            }
            Ok(response)
        }
    }

    fn setup_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.py"),
            "def handler(request):\n    q = request.GET['q']\n    cur.execute(q)\n",
        )
        .unwrap();
        dir
    }

    fn scan_input(dir: &std::path::Path) -> ScanInput {
        ScanInput {
            repo_root: dir.to_path_buf(),
            repo_name: "demo".to_string(),
            known_cves: Vec::new(),
            design_controls: Vec::new(),
            application_id: None,
            cmdb_path: None,
            git_sha_override: None,
            changed_files: BTreeMap::new(),
            diff_scope_active: false,
            compliance: Vec::new(),
            checkmarx_xml: Vec::new(),
            snyk_json: Vec::new(),
            semgrep_json: Vec::new(),
            aikido_json: Vec::new(),
            sonatype_json: Vec::new(),
            semgrep_live: None,
            snyk_live: None,
            sonatype_live: None,
            aikido_live: None,
            checkmarx_live: None,
        }
    }

    fn scan_config() -> ScanConfig {
        let mut step7 = Step7Config::new("m");
        step7.semantic = false; // avoid needing a canned semantic-dedup reply; 1 finding trivially dedups alone.
        step7.retry_backoff_base = std::time::Duration::ZERO; // keep a ConnectionError test fast (default backoff starts at 10s).
        let mut step1 = Step1Config::new("m");
        step1.retry_backoff_base = std::time::Duration::ZERO; // keep a ConnectionError test fast (default backoff starts at 10s).
        let mut step2 = Step2Config::new("m");
        step2.retry_backoff_base = std::time::Duration::ZERO;
        let mut step3 = Step3Config::new("m");
        step3.retry_backoff_base = std::time::Duration::ZERO;
        let mut step4 = Step4Config::new("m");
        step4.retry_backoff_base = std::time::Duration::ZERO;
        let mut step5 = Step5Config::new("m");
        step5.dedup.retry_backoff_base = std::time::Duration::ZERO;
        let mut step8 = Step8Config::new("m");
        step8.retry_backoff_base = std::time::Duration::ZERO;
        ScanConfig {
            autoexclude: Default::default(),
            cancel: None,
            step0_enabled: false,
            step0: Step0Config::new(),
            step1,
            step2_enabled: true,
            step2,
            step3,
            step4,
            step5,
            step6: Step6Config::new("m"),
            step7,
            step8,
            tool_version: "0.1.0-test".to_string(),
            spend_cap: None,
            checkpoint: None,
            resume: false,
            emit_unreachable_appendix: false,
            progress: None,
            pricing: pricing::PricingConfig::default(),
        }
    }

    #[tokio::test]
    async fn a_full_run_with_zero_findings_reaches_sarif() {
        let dir = setup_repo();
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, None);
        let report = outcome.report.unwrap();
        assert!(report.findings.is_empty());
        assert!(!outcome.markdown.unwrap().is_empty());
        assert!(outcome.sarif.unwrap().contains("\"version\": \"2.1.0\""));
    }

    #[tokio::test]
    async fn imported_negative_assessment_survives_the_real_pipeline_into_s9() {
        let dir = setup_repo();
        let export = dir.path().join("vendor.json");
        std::fs::write(&export, r#"{"results":[{"check_id":"rule","path":"app.py","start":{"line":1},"end":{"line":1},"extra":{"message":"candidate","severity":"ERROR"}}]}"#).unwrap();
        let mut input = scan_input(dir.path());
        input.semgrep_json.push(export);
        let outcome = run_scan(
            client_with(full_table(S4_EMPTY,
                "Traced the input guard.\nVERDICT: FALSE_POSITIVE (confidence: 9/10) - bounded input\n", "")),
            Arc::new(NoTools), input, scan_config(), None,
        ).await.unwrap();
        let report = outcome.report.unwrap();
        assert!(report.findings.is_empty());
        assert_eq!(report.provider_ledger.assessments.len(), 1);
        let record = &report.provider_ledger.assessments[0];
        assert_eq!(record.drop_reason, Some(DropReason::FalsePositive));
        assert_eq!(record.verification.as_ref().unwrap().confidence, 9);
        let plan: serde_json::Value =
            serde_json::from_str(&outcome.provider_writeback_plan.unwrap()).unwrap();
        assert_eq!(plan["plan"]["entries"][0]["outcome"], "false_positive");
        assert_eq!(plan["plan"]["apply_enabled"], false);
        assert_eq!(plan["ingestion"][0]["imported_count"], 1);
        assert_eq!(plan["assessments"].as_array().unwrap().len(), 1);
    }

    /// Two vendor findings, one in the pull request's changed file and
    /// one in a file it never touched. The out-of-scope one must not
    /// become a finding, must not be verified, and must still be visible.
    #[tokio::test]
    async fn a_diff_scoped_run_retains_an_out_of_scope_provider_finding_instead_of_reporting_it() {
        let dir = setup_repo();
        let export = dir.path().join("vendor.json");
        std::fs::write(
            &export,
            r#"{"results":[
                {"check_id":"rule-a","path":"app.py","start":{"line":1},"end":{"line":1},
                 "extra":{"message":"in the PR","severity":"ERROR"}},
                {"check_id":"rule-b","path":"vendor/old.py","start":{"line":7},"end":{"line":7},
                 "extra":{"message":"pre-existing","severity":"ERROR"}}]}"#,
        )
        .unwrap();
        let mut input = scan_input(dir.path());
        input.semgrep_json.push(export);
        input.diff_scope_active = true;
        input.changed_files =
            BTreeMap::from([("app.py".to_string(), BTreeSet::from([1i64, 2, 3]))]);

        let outcome = run_scan(
            client_with(full_table(
                S4_EMPTY,
                &s6_true_positive_text(),
                &s8_ranked_json(),
            )),
            Arc::new(NoTools),
            input,
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let report = outcome.report.unwrap();

        // The in-scope vendor finding got real S6 verification and IS
        // reported; the out-of-scope one is not a finding at all, so it
        // also never reaches `findings.json` or a PR comment, both of
        // which read `report.findings` and nothing else.
        assert_eq!(report.findings.len(), 1);
        assert!(report
            .findings
            .iter()
            .all(|f| f.finding.file != "vendor/old.py"));

        // Retained, with a reason that says which rule set it aside.
        let retained: Vec<_> = report
            .dropped
            .iter()
            .filter(|d| d.reason == DropReason::OutOfDiffScope)
            .collect();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].file, "vendor/old.py");
        assert_eq!(retained[0].line, 7);
        assert!(retained[0].detail.contains("--diff-scope"));
        assert!(retained[0].verification.is_none());
        assert!(!retained[0].provider_origins.is_empty());

        assert_eq!(report.findings[0].finding.file, "app.py");
        assert_eq!(
            report.findings[0].finding.verdict,
            Some(bc_model::Verdict::TruePositive)
        );

        // Both are still inventoried; only the out-of-scope one carries
        // the scope reason, and neither invents a verdict.
        assert_eq!(report.provider_ledger.assessments.len(), 2);
        let set_aside = report
            .provider_ledger
            .assessments
            .iter()
            .find(|a| a.file == "vendor/old.py")
            .unwrap();
        assert_eq!(set_aside.drop_reason, Some(DropReason::OutOfDiffScope));
        assert!(set_aside.verification.is_none());
        assert_eq!(set_aside.limitations.len(), 1);
        assert!(set_aside.limitations[0].contains("--diff-scope"));

        // Write-back stays refused for the whole run, and says so.
        assert!(!report.provider_ledger.full_scan);
        let plan: serde_json::Value =
            serde_json::from_str(&outcome.provider_writeback_plan.unwrap()).unwrap();
        assert_eq!(plan["plan"]["apply_enabled"], false);
        let blocked = plan["plan"]["entries"][0]["blocking_reasons"].to_string();
        assert!(blocked.contains("full_scan_required"), "{blocked}");

        // Surfaced in SARIF as a run-level note rather than a result: the
        // scan did not examine that file, so it has no result to report,
        // but a consumer reading only `report.sarif` must not read the
        // silence as "the vendor finding is resolved".
        let sarif: serde_json::Value = serde_json::from_str(&outcome.sarif.unwrap()).unwrap();
        let notes = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"].to_string();
        assert!(notes.contains("outside this pull request"), "{notes}");
        assert!(sarif["runs"][0]["results"]
            .to_string()
            .find("vendor/old.py")
            .is_none());

        // Visible in the rendered report, tagged and counted separately.
        let markdown = outcome.markdown.unwrap();
        assert!(markdown.contains("**[OUT OF DIFF SCOPE]**"), "{markdown}");
        assert!(markdown.contains("vendor/old.py"));
        assert!(markdown.contains(
            "- Outside the PR diff (third-party findings retained, not analyzed, not remediated): 1"
        ));
    }

    /// The behavioral pin for a run WITHOUT `--diff-scope`: both vendor
    /// findings are ingested and verified exactly as before, and nothing
    /// is set aside.
    #[tokio::test]
    async fn without_a_diff_scope_every_provider_finding_is_still_ingested_and_verified() {
        let dir = setup_repo();
        let export = dir.path().join("vendor.json");
        std::fs::write(
            &export,
            r#"{"results":[
                {"check_id":"rule-a","path":"app.py","start":{"line":1},"end":{"line":1},
                 "extra":{"message":"in the PR","severity":"ERROR"}},
                {"check_id":"rule-b","path":"vendor/old.py","start":{"line":7},"end":{"line":7},
                 "extra":{"message":"pre-existing","severity":"ERROR"}}]}"#,
        )
        .unwrap();
        let mut input = scan_input(dir.path());
        input.semgrep_json.push(export);

        let outcome = run_scan(
            client_with(full_table(
                S4_EMPTY,
                "Traced the input guard.\nVERDICT: FALSE_POSITIVE (confidence: 9/10) - bounded input\n",
                "",
            )),
            Arc::new(NoTools),
            input,
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let report = outcome.report.unwrap();

        assert!(report
            .dropped
            .iter()
            .all(|d| d.reason != DropReason::OutOfDiffScope));
        // Both reached S6 and came back with a real verdict.
        assert_eq!(
            report
                .dropped
                .iter()
                .filter(|d| d.reason == DropReason::FalsePositive)
                .count(),
            2
        );
        assert!(report.provider_ledger.full_scan);
        assert!(!outcome.markdown.unwrap().contains("Outside the PR diff"));
    }

    #[tokio::test]
    async fn a_full_run_with_step0_enabled_reaches_sarif() {
        // S0's own rules-mode ships with no source/sink YAML by default
        // (see `bc_stage_s0`'s module doc comment), so it's expected to
        // produce an empty seed here — this test's job is proving the
        // *wiring* (Stage0 runs before Stage1 and its output threads
        // into `Step1Input.seed` without erroring), not exercising a
        // non-empty seed's own effects, which `bc-stage-s0`/`bc-stage-s1`
        // already cover directly.
        let dir = setup_repo();
        let mut config = scan_config();
        config.step0_enabled = true;
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, None);
        assert!(outcome.report.is_some());
    }

    #[tokio::test]
    async fn git_sha_override_is_used_verbatim_instead_of_shelling_out_to_git() {
        // setup_repo()'s tempdir is deliberately NOT a real git repo (no
        // `git init`), so `head_sha` on it would return `None` on its
        // own — proving this isn't just "happens to match a real sha,"
        // the override is genuinely what populates report.git_sha here.
        let dir = setup_repo();
        let mut input = scan_input(dir.path());
        input.git_sha_override = Some("override-sha".to_string());
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            input,
            scan_config(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            outcome.report.unwrap().git_sha,
            Some("override-sha".to_string())
        );
    }

    #[tokio::test]
    async fn without_an_override_git_sha_falls_back_to_the_shell_out_and_is_none_for_a_non_git_dir()
    {
        let dir = setup_repo();
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.report.unwrap().git_sha, None);
    }

    #[tokio::test]
    async fn a_real_finding_survives_s4_through_s8_and_appears_in_the_report_and_sarif() {
        let dir = setup_repo();
        let outcome = run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let report = outcome.report.unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].finding.file, "app.py");
        let md = outcome.markdown.unwrap();
        assert!(md.contains("SQL injection"));
        let sarif = outcome.sarif.unwrap();
        assert!(sarif.contains("app.py"));
    }

    #[tokio::test]
    async fn a_secret_in_a_finding_is_redacted_from_the_report_sarif_and_markdown_alike() {
        // Regression: redaction used to happen only on the rendered
        // Markdown string, leaving `outcome.report` (and therefore SARIF,
        // built from the same struct) unredacted. A real Visa test PAN
        // (Luhn-valid, so `bc_redact` actually flags it) embedded in a
        // finding's code_snippet must now come out clean everywhere.
        let dir = setup_repo();
        let s4 = json!({"findings": [{
            "file": "app.py", "line_start": 10, "line_end": 12,
            "vuln_class": "injection", "title": "SQL injection",
            "description": "user input reaches a raw query",
            "code_snippet": "cur.execute(q)  # 4111111111111111", "confidence": 0.9,
            "source_ref": "app.py:10", "sink_ref": "app.py:12",
        }]})
        .to_string();
        let client = client_with(full_table(&s4, &s6_true_positive_text(), &s8_ranked_json()));
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            None,
        )
        .await
        .unwrap();

        let report = outcome.report.unwrap();
        assert_eq!(report.findings.len(), 1);
        assert!(!report.findings[0]
            .finding
            .code_snippet
            .contains("4111111111111111"));

        assert!(!outcome.markdown.unwrap().contains("4111111111111111"));
        assert!(!outcome.sarif.unwrap().contains("4111111111111111"));
    }

    #[tokio::test]
    async fn diff_scope_excludes_off_diff_findings_end_to_end_and_is_a_no_op_when_unset() {
        // Two unrelated files; S3 degrades (S3_GARBAGE) to its
        // deterministic catchall sweep, so both land in scope purely from
        // `ctx.all_files` regardless of the LLM. The one canned S4 reply
        // names "unchanged.py" — the file NOT in the diff — simulating a
        // model that reports on a file outside what the PR touched (S3's
        // trim pass removes it from every chunk; S4's own file-scope
        // filter, task #25, is the backstop if it somehow survived that).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("changed.py"),
            "def handler(request):\n    q = request.GET['q']\n    cur.execute(q)\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("unchanged.py"),
            "def other(request):\n    q2 = request.GET['q2']\n    cur.execute(q2)\n",
        )
        .unwrap();

        let client = client_with(full_table(
            &s4_finding_on("unchanged.py"),
            &s6_true_positive_text(),
            &s8_ranked_json(),
        ));

        let mut input_on = scan_input(dir.path());
        input_on.diff_scope_active = true;
        input_on.changed_files =
            BTreeMap::from([("changed.py".to_string(), BTreeSet::from([1i64]))]);
        let outcome_on = run_scan(
            client.clone(),
            Arc::new(NoTools),
            input_on,
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let report_on = outcome_on.report.unwrap();
        assert!(
            report_on.findings.is_empty(),
            "an off-diff finding must never reach the report when diff-scope is active"
        );

        // Off: byte-for-byte today's behavior — the same finding is
        // in-scope and reported normally.
        let outcome_off = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let report_off = outcome_off.report.unwrap();
        assert_eq!(report_off.findings.len(), 1);
        assert_eq!(report_off.findings[0].finding.file, "unchanged.py");
    }

    #[tokio::test]
    async fn diff_scope_with_an_empty_changed_set_scans_nothing_and_says_so_in_the_report() {
        // The fail-open regression, end to end. `--diff-scope` was asked
        // for and the PR's diff parsed to zero changed lines (renames,
        // deletions, mode changes, binary files all do this). Pre-fix,
        // that empty map was indistinguishable from "no diff scope": the
        // whole repo was chunked and analyzed at full LLM spend, and the
        // report's scope line — gated on a non-zero count — vanished, so
        // nothing anywhere said a scope had been requested.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("changed.py"),
            "def handler(request):\n    q = request.GET['q']\n    cur.execute(q)\n",
        )
        .unwrap();

        let client = client_with(full_table(
            &s4_finding_on("changed.py"),
            &s6_true_positive_text(),
            &s8_ranked_json(),
        ));

        let mut input = scan_input(dir.path());
        input.diff_scope_active = true;
        assert!(input.changed_files.is_empty());
        let outcome = run_scan(client, Arc::new(NoTools), input, scan_config(), None)
            .await
            .unwrap();

        let report = outcome.report.unwrap();
        assert!(
            report.findings.is_empty(),
            "a diff-scoped scan of zero files must analyze nothing, not everything"
        );
        let metrics = report.metrics.unwrap();
        assert!(metrics.diff_scope_active);
        assert_eq!(metrics.changed_files_count, 0);
        assert_eq!(metrics.analyzed_files_unique, 0);
        assert!(outcome
            .markdown
            .unwrap()
            .contains("- Scope: PR diff (0 of "));
    }

    fn compliance_policy(
        name: &str,
        req_id: &str,
        scope_mode: bc_compliance::ScopeMode,
        vuln_classes: &[&str],
    ) -> bc_compliance::CompliancePolicy {
        bc_compliance::CompliancePolicy {
            name: name.to_string(),
            guidance: String::new(),
            scope_mode,
            requirements: vec![bc_compliance::Requirement {
                id: req_id.to_string(),
                title: "Injection controls".to_string(),
                cwes: Vec::new(),
                vuln_classes: vuln_classes.iter().map(|s| s.to_string()).collect(),
            }],
        }
    }

    #[tokio::test]
    async fn compliance_annotate_mode_tags_matching_findings_and_is_a_no_op_when_unset() {
        let dir = setup_repo();

        let mut input_with = scan_input(dir.path());
        input_with.compliance = vec![compliance_policy(
            "TEST-FRAMEWORK",
            "REQ-1",
            bc_compliance::ScopeMode::Annotate,
            &["injection"],
        )];
        let outcome_with = run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            input_with,
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let report_with = outcome_with.report.unwrap();
        assert_eq!(report_with.findings.len(), 1);
        assert_eq!(
            report_with.findings[0].finding.compliance_requirements,
            vec!["REQ-1".to_string()]
        );

        // Unset: byte-for-byte today's behavior — no tagging happens.
        let outcome_without = run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let report_without = outcome_without.report.unwrap();
        assert_eq!(report_without.findings.len(), 1);
        assert!(report_without.findings[0]
            .finding
            .compliance_requirements
            .is_empty());
    }

    #[tokio::test]
    async fn compliance_filter_mode_drops_non_matching_findings_out_of_the_report() {
        let dir = setup_repo();
        let mut input = scan_input(dir.path());
        input.compliance = vec![compliance_policy(
            "TEST-FRAMEWORK",
            "REQ-1",
            bc_compliance::ScopeMode::Filter,
            &["xss"],
        )];
        let outcome = run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            input,
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let report = outcome.report.unwrap();
        assert!(
            report.findings.is_empty(),
            "a finding matching no requirement must be dropped in Filter mode"
        );
        assert_eq!(report.dropped.len(), 1);
        assert_eq!(report.dropped[0].reason, DropReason::Excluded);
    }

    #[tokio::test]
    async fn compliance_combines_a_preset_and_a_custom_policy_with_or_across_filters() {
        // Two Filter-mode policies: only the second matches the one real
        // finding ("injection"). Combining them must still keep it (OR
        // semantics across frameworks), tagged with both policies' own
        // matching requirement ids where applicable.
        let dir = setup_repo();
        let mut input = scan_input(dir.path());
        input.compliance = vec![
            compliance_policy("ASVS", "V5.3.2", bc_compliance::ScopeMode::Filter, &["xss"]),
            compliance_policy(
                "Custom-PCI",
                "6.2.4",
                bc_compliance::ScopeMode::Filter,
                &["injection"],
            ),
        ];
        let outcome = run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            input,
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let report = outcome.report.unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].finding.compliance_requirements,
            vec!["6.2.4".to_string()]
        );
        assert!(report.dropped.is_empty());
    }

    const SEMANTIC_DEDUP_MARK: &str = "collapsing overlapping SAST findings";

    fn s4_two_findings_json() -> String {
        json!({"findings": [
            {
                "file": "app.py", "line_start": 10, "line_end": 12,
                "vuln_class": "injection", "title": "SQL injection A", "description": "user input reaches a raw query",
                "code_snippet": "cur.execute(q)", "confidence": 0.9,
                "source_ref": "app.py:10", "sink_ref": "app.py:12",
            },
            {
                "file": "other.py", "line_start": 20, "line_end": 22,
                "vuln_class": "injection", "title": "SQL injection B", "description": "a second, unrelated raw query",
                "code_snippet": "cur2.execute(q2)", "confidence": 0.9,
                "source_ref": "other.py:20", "sink_ref": "other.py:22",
            },
        ]})
        .to_string()
    }

    fn s8_two_ranked_json() -> String {
        json!({
            "summary": "Two SQL injection findings.",
            "ranked_findings": [
                {"index": 0, "severity": "high", "exploitability_notes": "reachable"},
                {"index": 1, "severity": "high", "exploitability_notes": "reachable"},
            ],
            "chains": [],
        })
        .to_string()
    }

    /// Drives a real S1 degrade (garbage mapper output — unparseable text
    /// degrades that stage's own JSON assembly directly) and a real S5/S7
    /// semantic-dedup degrade (the underlying LLM *call* failing — S5's
    /// own pre-verify pass and S7's final dedup pass both call the exact
    /// same `bc_stage_s7::run_dedup`/`semantic_dedup` code with the exact
    /// same system prompt, so ONE failing mark degrades both) all the way
    /// through to a real `FinalReport`, proving `run_scan` actually
    /// records each in `errors_by_stage` — not just that `build_metrics`'s
    /// own merge-in logic works in isolation (already covered above).
    /// Note `parse_dedup_output` is a lenient regex scan that returns an
    /// empty (not `Err`) result for unparseable text — unlike S1/S3's own
    /// degrade trigger, S5/S7 only degrade when the LLM *call itself*
    /// fails, never on a merely-garbled-but-successful reply.
    #[tokio::test]
    async fn run_scan_records_real_stage_degrades_in_errors_by_stage() {
        let dir = setup_repo();
        std::fs::write(dir.path().join("other.py"), "cur2.execute(q2)\n").unwrap();

        let s6 = s6_true_positive_text();
        let s8 = s8_two_ranked_json();
        let table: Vec<(&'static str, String)> = vec![
            (S1_SYSTEM_MARK, S3_GARBAGE.to_string()), // any non-JSON-object text degrades S1 too
            (S2_SYSTEM_MARK, S2_JSON.to_string()),
            (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
            (S4_SYSTEM_MARK, s4_two_findings_json()),
            (S6_SYSTEM_MARK, s6),
            (S8_SYSTEM_MARK, s8),
        ];
        let client = Arc::new(RoutedClient::new(move |system: &str| {
            if system.contains(SEMANTIC_DEDUP_MARK) {
                return Err(LlmError::ConnectionError {
                    message: "provider down".to_string(),
                });
            }
            let owned: Vec<(&str, &str)> = table.iter().map(|(m, r)| (*m, r.as_str())).collect();
            Ok(route(system, &owned))
        }));

        let mut config = scan_config();
        config.step5.pre_verify_threshold = 2; // low enough that 2 survivors trigger S5's own semantic pass
        config.step5.dedup.semantic = true;
        config.step7.semantic = true; // scan_config()'s own default already, kept explicit here

        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        let report = outcome.report.unwrap();
        assert_eq!(report.findings.len(), 2);
        let metrics = report.metrics.unwrap();
        assert_eq!(metrics.errors_by_stage.get("s1"), Some(&1));
        assert_eq!(metrics.errors_by_stage.get("s5"), Some(&1));
        assert_eq!(metrics.errors_by_stage.get("s7"), Some(&1));
        // s3 degrades too here — every other test in this file feeds it
        // `S3_GARBAGE` as its own established baseline (S3 always
        // degrades to its deterministic catchall sweep unless a test
        // specifically supplies a well-formed `TaskManifest`, none do),
        // so this isn't specific to this test's own scenario. s2
        // answered a well-formed reply and s4 has no failed chunks —
        // neither should show up.
        assert_eq!(metrics.errors_by_stage.get("s3"), Some(&1));
        assert!(!metrics.errors_by_stage.contains_key("s2"));
        assert!(!metrics.errors_by_stage.contains_key("s4"));
    }

    #[tokio::test]
    async fn a_false_positive_verdict_is_dropped_and_counted_in_metrics() {
        let dir = setup_repo();
        let s6_false_positive = format!(
            "traced it\nVERDICT: FALSE_POSITIVE (confidence: 9/10) — input is sanitized\nCVSS: {GOOD_CVSS}\n"
        );
        let s8_no_findings = json!({
            "summary": "No confirmed findings.",
            "ranked_findings": [],
            "chains": [],
        })
        .to_string();
        let client = client_with(full_table(
            &s4_one_finding_json(),
            &s6_false_positive,
            &s8_no_findings,
        ));
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let report = outcome.report.unwrap();
        assert!(report.findings.is_empty()); // the false positive never survives to the report
        let metrics = report.metrics.unwrap();
        assert_eq!(metrics.raw_findings_count, 1);
        assert_eq!(metrics.true_positive_count, 0);
        assert_eq!(metrics.false_positive_count, 1);
        assert_eq!(metrics.duplicate_count, 0);
    }

    #[tokio::test]
    async fn stage2_llm_failure_is_caught_and_the_scan_continues_without_a_threat_model() {
        let dir = setup_repo();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(move |system: &str| {
            if system.contains(S2_SYSTEM_MARK) {
                Err(LlmError::ConnectionError {
                    message: "s2 down".to_string(),
                })
            } else {
                Ok(route(
                    system,
                    &[
                        (S1_SYSTEM_MARK, S1_JSON),
                        (S3_SYSTEM_MARK, S3_GARBAGE),
                        (S4_SYSTEM_MARK, S4_EMPTY),
                    ],
                ))
            }
        }));
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let report = outcome.report.unwrap();
        assert!(report.threat_model.is_none());
    }

    #[tokio::test]
    async fn step2_disabled_by_config_skips_the_llm_call_entirely() {
        let dir = setup_repo();
        // S2's mark is deliberately absent from the table: if S2 were
        // called anyway (a real bug), `route`'s shared fallback panics.
        let client = client_with(vec![
            (S1_SYSTEM_MARK, S1_JSON.to_string()),
            (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
            (S4_SYSTEM_MARK, S4_EMPTY.to_string()),
        ]);
        let mut cfg = scan_config();
        cfg.step2_enabled = false;
        let outcome = run_scan(client, Arc::new(NoTools), scan_input(dir.path()), cfg, None)
            .await
            .unwrap();
        assert!(outcome.report.unwrap().threat_model.is_none());
    }

    #[tokio::test]
    async fn stop_after_s1_returns_early_with_no_report() {
        let dir = setup_repo();
        let client = client_with(vec![(S1_SYSTEM_MARK, S1_JSON.to_string())]);
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            Some(StopAfter::S1),
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, Some(StopAfter::S1));
        assert!(outcome.report.is_none());
    }

    #[tokio::test]
    async fn stop_after_s2_returns_early() {
        let dir = setup_repo();
        let client = client_with(vec![
            (S1_SYSTEM_MARK, S1_JSON.to_string()),
            (S2_SYSTEM_MARK, S2_JSON.to_string()),
        ]);
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            Some(StopAfter::S2),
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, Some(StopAfter::S2));
    }

    #[tokio::test]
    async fn stop_after_s3_returns_early() {
        let dir = setup_repo();
        let client = client_with(vec![
            (S1_SYSTEM_MARK, S1_JSON.to_string()),
            (S2_SYSTEM_MARK, S2_JSON.to_string()),
            (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
        ]);
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            Some(StopAfter::S3),
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, Some(StopAfter::S3));
    }

    #[tokio::test]
    async fn stop_after_s4_returns_early() {
        let dir = setup_repo();
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            Some(StopAfter::S4),
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, Some(StopAfter::S4));
    }

    #[tokio::test]
    async fn stop_after_s5_returns_early() {
        let dir = setup_repo();
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            Some(StopAfter::S5),
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, Some(StopAfter::S5));
    }

    #[tokio::test]
    async fn stop_after_s6_returns_early() {
        let dir = setup_repo();
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            Some(StopAfter::S6),
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, Some(StopAfter::S6));
    }

    #[tokio::test]
    async fn stop_after_s7_returns_early() {
        let dir = setup_repo();
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            Some(StopAfter::S7),
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, Some(StopAfter::S7));
    }

    #[tokio::test]
    async fn stop_after_s9_renders_reports_and_emits_its_own_stage_events() {
        let dir = setup_repo();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut config = scan_config();
        config.progress = Some(tx);
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            Some(StopAfter::S9),
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, Some(StopAfter::S9));
        assert!(outcome.report.is_some());
        assert!(outcome.markdown.is_some());
        let sarif: serde_json::Value =
            serde_json::from_str(outcome.sarif.as_ref().unwrap()).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        let events: Vec<_> = rx.try_iter().collect();
        assert_eq!(
            events[events.len() - 2],
            bc_pipeline_core::ScanEvent::StageStarted { stage: "s9" }
        );
        assert!(matches!(
            &events[events.len() - 1],
            bc_pipeline_core::ScanEvent::StageFinished {
                stage: "s9",
                status: StageStatus::Completed,
                duration: Some(_),
                ..
            }
        ));
    }

    /// Every stage's `(name, status)` from a run's `StageFinished` events,
    /// in order, for asserting the whole lifecycle at once.
    fn finished_stages(events: &[bc_pipeline_core::ScanEvent]) -> Vec<(&'static str, StageStatus)> {
        events
            .iter()
            .filter_map(|e| match e {
                bc_pipeline_core::ScanEvent::StageFinished { stage, status, .. } => {
                    Some((*stage, *status))
                }
                _ => None,
            })
            .collect()
    }

    /// The counters one stage reported on its `StageFinished` event.
    fn finished_counts(
        events: &[bc_pipeline_core::ScanEvent],
        wanted: &str,
    ) -> Vec<(&'static str, u64)> {
        let missing = format!("no StageFinished for {wanted}");
        events
            .iter()
            .find_map(|e| match e {
                bc_pipeline_core::ScanEvent::StageFinished { stage, counts, .. }
                    if *stage == wanted =>
                {
                    Some(counts.clone())
                }
                _ => None,
            })
            .expect(&missing)
    }

    #[tokio::test]
    async fn a_full_scan_closes_every_stage_with_a_status_and_its_counters() {
        let dir = setup_repo();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut config = scan_config();
        config.progress = Some(tx);
        let outcome = run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        let events: Vec<_> = rx.try_iter().collect();
        let stages: Vec<&str> = finished_stages(&events).iter().map(|(s, _)| *s).collect();
        assert_eq!(
            stages,
            [
                "s0-seed",
                "s1-preprocess",
                "s2-threatmodel",
                "s3-decompose",
                "s4-deepdive",
                "s5-prefilter",
                "s6-verify",
                "s7-dedup",
                "s8-chain",
                "s9"
            ]
        );
        assert_eq!(
            finished_counts(&events, "s6-verify"),
            vec![("verified", 1), ("dropped", 0)]
        );
        assert_eq!(finished_counts(&events, "s8-chain")[0], ("findings", 1));
        // Timings for everything the report could know about (S0-S8),
        // recorded in the report itself.
        let timings = outcome.report.unwrap().metrics.unwrap().stage_timings;
        assert_eq!(
            timings.keys().map(String::as_str).collect::<Vec<_>>(),
            ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"]
        );
        // `scan_config` switches S0 off: skipped, so no duration.
        assert_eq!(timings["s0"].outcome, "skipped");
        assert_eq!(timings["s0"].duration_sec, None);
        assert!(timings
            .iter()
            .filter(|(id, _)| *id != "s0")
            .all(|(_, t)| t.duration_sec.is_some()));
        // S8's spend now reaches the stream too.
        assert!(events.iter().any(|e| matches!(
            e,
            bc_pipeline_core::ScanEvent::UsageUpdate {
                stage: "s8-chain",
                ..
            }
        )));
    }

    #[tokio::test]
    async fn switched_off_stages_close_as_skipped_without_starting() {
        let dir = setup_repo();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut config = scan_config();
        config.progress = Some(tx);
        config.step0_enabled = false;
        config.step2_enabled = false;
        run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            Some(StopAfter::S2),
        )
        .await
        .unwrap();
        let events: Vec<_> = rx.try_iter().collect();
        assert_eq!(
            finished_stages(&events),
            [
                ("s0-seed", StageStatus::Skipped),
                ("s1-preprocess", StageStatus::Completed),
                ("s2-threatmodel", StageStatus::Skipped),
            ]
        );
        assert!(
            !events.contains(&bc_pipeline_core::ScanEvent::StageStarted {
                stage: "s2-threatmodel"
            })
        );
    }

    #[tokio::test]
    async fn stop_after_s8_returns_analysis_without_rendered_reports() {
        let dir = setup_repo();
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            Some(StopAfter::S8),
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, Some(StopAfter::S8));
        assert!(outcome.report.is_some());
        assert!(outcome.markdown.is_none());
        assert!(outcome.sarif.is_none());
    }

    #[tokio::test]
    async fn unreachable_files_never_reach_the_report_when_emit_unreachable_appendix_is_off() {
        let dir = setup_repo();
        let mut config = scan_config();
        config.step3.catchall_mode = "reachable_only".to_string();
        // Deliberately left at its default `false` — even if S3's catchall
        // gate populated `manifest.unreachable_files`, it must never reach
        // the final report unless this flag is explicitly on.
        assert!(!config.emit_unreachable_appendix);
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        assert!(outcome.report.unwrap().unreachable_files.is_empty());
    }

    #[tokio::test]
    async fn unreachable_files_reach_the_report_when_emit_unreachable_appendix_is_on() {
        // Seeds a checkpoint carrying a pre-populated
        // `manifest.unreachable_files` directly, bypassing S1/S3's real
        // detection entirely — this test is only proving the orchestrator
        // wiring (does `config.emit_unreachable_appendix` copy
        // `manifest.unreachable_files` onto the final report), not
        // `catchall_mode: reachable_only`'s own gating logic, which
        // `bc-stage-s3::catchall`'s own tests already cover directly.
        let dir = setup_repo();
        let ckpt_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = Arc::new(
            bc_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
        );
        let run_id = bc_checkpoint::run_id_for(dir.path());

        let ctx = ContextPackage {
            all_files: vec!["app.py".to_string()],
            ..ContextPackage::default()
        };
        store
            .save(
                &run_id,
                "s1",
                &serde_json::to_vec(&Step1Checkpoint {
                    ctx,
                    degraded: false,
                })
                .unwrap(),
            )
            .unwrap();
        store
            .save(
                &run_id,
                "s2",
                &serde_json::to_vec(&Step2Checkpoint {
                    threat_model: None,
                    degraded: false,
                })
                .unwrap(),
            )
            .unwrap();
        store
            .save(
                &run_id,
                "s3",
                &serde_json::to_vec(&Step3Checkpoint {
                    manifest: TaskManifest {
                        chunks: Vec::new(),
                        rationale: String::new(),
                        unreachable_files: vec!["orphan.py".to_string()],
                    },
                    degraded: false,
                })
                .unwrap(),
            )
            .unwrap();
        store
            .save(
                &run_id,
                "s4",
                &serde_json::to_vec(&Step4Checkpoint {
                    findings: Vec::new(),
                    outcomes: BTreeMap::new(),
                })
                .unwrap(),
            )
            .unwrap();
        store
            .save(
                &run_id,
                "s5",
                &serde_json::to_vec(&Step5Checkpoint {
                    findings: Vec::new(),
                    dropped: Vec::new(),
                    degraded: false,
                })
                .unwrap(),
            )
            .unwrap();
        store
            .save(
                &run_id,
                "s6",
                &serde_json::to_vec(&Step6Checkpoint {
                    verified: Vec::new(),
                    dropped: Vec::new(),
                })
                .unwrap(),
            )
            .unwrap();
        store
            .save(
                &run_id,
                "s7",
                &serde_json::to_vec(&Step7Checkpoint {
                    findings: Vec::new(),
                    dropped: Vec::new(),
                    degraded: false,
                })
                .unwrap(),
            )
            .unwrap();

        let mut config = scan_config();
        config.checkpoint = Some(store);
        config.resume = true;
        config.emit_unreachable_appendix = true;

        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        let report = outcome.report.unwrap();
        assert_eq!(report.unreachable_files, vec!["orphan.py".to_string()]);
    }

    /// The one degrade reason among S5's and S7's that means "the budget
    /// ran out", told apart from the semantic call simply failing.
    #[test]
    fn budget_skip_reason_recognizes_only_a_budget_stop() {
        assert_eq!(
            budget_skip_reason(
                "S7",
                Some("semantic dedup skipped: token budget of 100 reached (120 spent)")
            ),
            Some("S7: semantic dedup skipped: token budget of 100 reached (120 spent)".to_string())
        );
        // A genuine call failure degrades too, but is not a budget stop.
        assert_eq!(
            budget_skip_reason("S5", Some("semantic dedup call failed (non-fatal): boom")),
            None
        );
        // And a stage that did not degrade at all has no reason to give.
        assert_eq!(budget_skip_reason("S5", None), None);
    }

    /// `SpendGate` reads the LIVE total — everything recorded at earlier
    /// stage boundaries plus what the tracker has accumulated since — so
    /// it can trip part-way through a stage, which is the whole point.
    #[test]
    fn spend_gate_adds_the_running_stage_s_spend_to_the_recorded_baseline() {
        let tracker = Arc::new(UsageTrackingClient::new(
            client_with(Vec::new()),
            &pricing::PricingConfig::default(),
        ));
        let mut tokens_by_phase = BTreeMap::new();
        tokens_by_phase.insert(
            "s1".to_string(),
            phase_usage(Usage {
                input_tokens: 40,
                ..Usage::default()
            }),
        );
        let cap = SpendCap {
            max_total_tokens: Some(100),
            max_wall_clock: None,
        };
        let gate = budget_gate(
            Some(&cap),
            &tracker,
            &tokens_by_phase,
            std::time::Instant::now(),
            None,
        )
        .unwrap();
        assert!(!gate.should_stop(), "40 of 100 recorded, nothing live yet");

        // 60 more tokens spent inside the running stage — invisible to
        // `tokens_by_phase` until the next boundary, but not to the gate.
        {
            let mut total = tracker.total.lock().unwrap();
            total.usage.input_tokens += 60;
        }
        assert!(gate.should_stop());
        assert_eq!(
            gate.stop_reason(),
            "token budget of 100 reached (100 spent)"
        );
        // And `peek` did not consume it, so the stage boundary still
        // attributes all 60 to the running stage.
        assert_eq!(tracker.take().usage.input_tokens, 60);
    }

    #[test]
    fn spend_gate_also_trips_on_wall_clock_and_debug_prints_its_cap() {
        let tracker = Arc::new(UsageTrackingClient::new(
            client_with(Vec::new()),
            &pricing::PricingConfig::default(),
        ));
        let cap = SpendCap {
            max_total_tokens: None,
            max_wall_clock: Some(std::time::Duration::ZERO),
        };
        let gate = budget_gate(
            Some(&cap),
            &tracker,
            &BTreeMap::new(),
            std::time::Instant::now(),
            None,
        )
        .unwrap();
        assert!(gate.should_stop());
        assert!(gate.stop_reason().starts_with("time budget of 0s reached"));
        // `BudgetGate` requires `Debug` so a `Step*Config` holding one can
        // still derive it — and `UsageTrackingClient` cannot derive one,
        // so this impl is hand-written and needs exercising.
        let rendered = format!("{gate:?}");
        assert!(rendered.starts_with("SpendGate"), "{rendered}");
        assert!(rendered.contains("baseline_tokens: 0"), "{rendered}");
    }

    /// A capless scan still gets a gate — an idle one, which only an
    /// external trip can ever shut. Before the 2026-09 quota fix this
    /// returned `None`, which meant the one scan shape with no other
    /// stopping condition was also the one that could not be told the
    /// provider had stopped funding it.
    #[test]
    fn a_scan_with_no_cap_builds_an_idle_gate_that_only_an_external_trip_can_stop() {
        let tracker = Arc::new(UsageTrackingClient::new(
            client_with(Vec::new()),
            &pricing::PricingConfig::default(),
        ));
        let gate = budget_gate(
            None,
            &tracker,
            &BTreeMap::new(),
            std::time::Instant::now(),
            None,
        )
        .expect("an uncapped scan still gets a gate");
        assert!(
            !gate.should_stop(),
            "nothing caps it and nothing tripped it"
        );
        assert_eq!(gate.stop_reason(), "spend cap reached");

        gate.trip("provider quota exhausted — no credits left".to_string());
        assert!(gate.should_stop());
        assert_eq!(
            gate.stop_reason(),
            "provider quota exhausted — no credits left"
        );
    }

    /// Under `parallel` concurrency several tasks discover the same
    /// exhausted account at once; the first account of it is the one the
    /// report keeps.
    #[test]
    fn a_second_trip_does_not_overwrite_the_first_reason() {
        let tracker = Arc::new(UsageTrackingClient::new(
            client_with(Vec::new()),
            &pricing::PricingConfig::default(),
        ));
        let gate = budget_gate(
            None,
            &tracker,
            &BTreeMap::new(),
            std::time::Instant::now(),
            None,
        )
        .unwrap();
        gate.trip("provider quota exhausted — first".to_string());
        gate.trip("provider quota exhausted — second".to_string());
        assert_eq!(gate.stop_reason(), "provider quota exhausted — first");
        // And it shows up in the hand-written `Debug`, which a stage
        // config carrying the gate renders.
        assert!(
            format!("{gate:?}").contains("provider quota exhausted — first"),
            "{gate:?}"
        );
    }

    /// The external reason wins over a cap that has also been reached:
    /// "the provider stopped funding this" explains the stop, where "the
    /// token cap was hit" would merely be true.
    #[test]
    fn an_external_trip_outranks_a_cap_that_has_also_been_reached() {
        let tracker = Arc::new(UsageTrackingClient::new(
            client_with(Vec::new()),
            &pricing::PricingConfig::default(),
        ));
        let cap = SpendCap {
            max_total_tokens: None,
            max_wall_clock: Some(std::time::Duration::ZERO),
        };
        let gate = budget_gate(
            Some(&cap),
            &tracker,
            &BTreeMap::new(),
            std::time::Instant::now(),
            None,
        )
        .unwrap();
        assert!(gate.stop_reason().starts_with("time budget of 0s reached"));
        gate.trip("provider quota exhausted — no credits left".to_string());
        assert!(gate.should_stop());
        assert_eq!(
            gate.stop_reason(),
            "provider quota exhausted — no credits left"
        );
    }

    /// The fallback in `stop_reason` for a gate asked why it stopped when
    /// it has not, in fact, stopped — not reachable through a stage (they
    /// only ask after `should_stop` said yes), but a `BudgetGate` impl
    /// must still answer something rather than panic.
    #[test]
    fn an_untripped_spend_gate_still_answers_the_reason_question() {
        let tracker = Arc::new(UsageTrackingClient::new(
            client_with(Vec::new()),
            &pricing::PricingConfig::default(),
        ));
        let cap = SpendCap {
            max_total_tokens: Some(100),
            max_wall_clock: None,
        };
        let gate = budget_gate(
            Some(&cap),
            &tracker,
            &BTreeMap::new(),
            std::time::Instant::now(),
            None,
        )
        .unwrap();
        assert!(!gate.should_stop());
        assert_eq!(gate.stop_reason(), "spend cap reached");
    }

    #[test]
    fn spend_cap_exceeded_is_none_when_no_cap_is_set() {
        assert!(spend_cap_exceeded(None, &BTreeMap::new(), std::time::Instant::now()).is_none());
    }

    #[test]
    fn spend_cap_exceeded_trips_when_total_tokens_reach_the_limit() {
        let cap = SpendCap {
            max_total_tokens: Some(100),
            max_wall_clock: None,
        };
        let mut tokens_by_phase = BTreeMap::new();
        tokens_by_phase.insert(
            "s4".to_string(),
            phase_usage(Usage {
                input_tokens: 60,
                output_tokens: 40,
                ..Usage::default()
            }),
        );
        let reason =
            spend_cap_exceeded(Some(&cap), &tokens_by_phase, std::time::Instant::now()).unwrap();
        assert_eq!(reason, "token budget of 100 reached (100 spent)");
    }

    #[test]
    fn spend_cap_exceeded_is_none_when_under_the_token_limit() {
        let cap = SpendCap {
            max_total_tokens: Some(100),
            max_wall_clock: None,
        };
        let mut tokens_by_phase = BTreeMap::new();
        tokens_by_phase.insert(
            "s4".to_string(),
            phase_usage(Usage {
                input_tokens: 10,
                output_tokens: 10,
                ..Usage::default()
            }),
        );
        assert!(
            spend_cap_exceeded(Some(&cap), &tokens_by_phase, std::time::Instant::now()).is_none()
        );
    }

    #[test]
    fn spend_cap_exceeded_trips_when_wall_clock_is_exceeded() {
        let cap = SpendCap {
            max_total_tokens: None,
            max_wall_clock: Some(std::time::Duration::ZERO),
        };
        let reason =
            spend_cap_exceeded(Some(&cap), &BTreeMap::new(), std::time::Instant::now()).unwrap();
        assert!(reason.starts_with("time budget of 0s reached"), "{reason}");
    }

    /// A cap already spent by the time S4 starts now stops S4 itself —
    /// its `BudgetGate` declines every chunk rather than analyzing all of
    /// them and only noticing at the boundary afterwards. The scan still
    /// falls through to the S8 + redact + SARIF tail and produces a real
    /// report, rather than returning `stop_after`'s bare `report: None`;
    /// it just has nothing in it, and says so.
    /// `step1.exclude_dirs` must bound the seed plane's walk too: S1
    /// reuses the seed's inventory, so a wider step-0 walk widens the scan.
    #[tokio::test]
    async fn the_seed_plane_walks_the_survey_scope_not_the_whole_repo() {
        let dir = setup_repo();
        std::fs::create_dir_all(dir.path().join("vendor")).unwrap();
        std::fs::write(
            dir.path().join("vendor/lib.py"),
            "def helper(x):\n    return x\n\n\ndef other(y):\n    return y\n",
        )
        .unwrap();
        let mut config = scan_config();
        config.step0_enabled = true;
        config.step1.walk.exclude_dirs.push("vendor".to_string());
        let outcome = run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        let metrics = outcome.report.unwrap().metrics.unwrap();
        // Only app.py (3 lines) is in scope; vendor/lib.py's 5 lines are not.
        assert_eq!(metrics.loc_in_scope_by_language.get("python"), Some(&3));
    }

    #[tokio::test]
    async fn a_token_cap_already_spent_before_s4_skips_every_chunk_and_still_reports() {
        let dir = setup_repo();
        let client = Arc::new(UsageInjectingClient {
            inner: one_finding_client(),
            usage: Usage {
                input_tokens: 1000,
                ..Usage::default()
            },
        });
        let mut config = scan_config();
        config.spend_cap = Some(SpendCap {
            max_total_tokens: Some(1),
            max_wall_clock: None,
        });
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, None);
        let report = outcome.report.unwrap();
        assert!(report.findings.is_empty());
        let metrics = report.metrics.clone().unwrap();
        assert_eq!(metrics.raw_findings_count, 0);
        assert_eq!(metrics.true_positive_count, 0);
        assert_eq!(metrics.false_positive_count, 0);
        assert_eq!(metrics.duplicate_count, 0);
        // Skipped is neither "attempted" nor "failed" — the budget line
        // is where those chunks are accounted for.
        assert_eq!(metrics.chunks_attempted, 0);
        assert_eq!(metrics.chunks_failed, 0);
        assert!(!metrics.errors_by_stage.contains_key("s4"));
        assert!(
            metrics
                .budget_stop
                .starts_with("S4: token budget of 1 reached"),
            "{}",
            metrics.budget_stop
        );
        assert!(
            metrics
                .budget_stop
                // The two original chunks plus the v1.3 `injection` specialist
                // chunk that the `.execute(` sink gates in.
                .contains("0 of 3 deep-dive chunk(s) analyzed, 3 skipped"),
            "{}",
            metrics.budget_stop
        );
        // And the reader is told, in the report itself.
        let md = bc_report_md::render_markdown(&report);
        assert!(md.contains("## Scan Health"), "{md}");
        assert!(md.contains("**BUDGET REACHED**"), "{md}");
    }

    /// Same trip point as the token-cap test above, but via
    /// `max_wall_clock: Duration::ZERO` (trips immediately) with an
    /// otherwise-unbounded token budget — proves the wall-clock trigger
    /// alone is wired all the way through, not just the token one.
    #[tokio::test]
    async fn a_zero_wall_clock_cap_skips_every_chunk_and_still_produces_a_report() {
        let dir = setup_repo();
        let mut config = scan_config();
        config.spend_cap = Some(SpendCap {
            max_total_tokens: None,
            max_wall_clock: Some(std::time::Duration::ZERO),
        });
        let outcome = run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, None);
        let report = outcome.report.unwrap();
        assert!(report.findings.is_empty());
        let metrics = report.metrics.unwrap();
        assert_eq!(metrics.true_positive_count, 0);
        assert!(
            metrics
                .budget_stop
                .starts_with("S4: time budget of 0s reached"),
            "{}",
            metrics.budget_stop
        );
    }

    /// Forces S5's own semantic pre-verify pass to make a real LLM call
    /// (`pre_verify_threshold` met by 2 findings) and gives *only* that
    /// call enough usage to trip a token cap that S1-S4's zero-usage
    /// calls didn't — proving the cap check after S5 (not just S4) is
    /// really wired, and that a trip there snapshots `prefiltered.findings`
    /// (S5's own output, unverified/undeduped) rather than S4's raw set.
    #[tokio::test]
    async fn a_token_cap_tripped_by_s5_s_own_semantic_pass_stops_the_scan_after_s5() {
        let dir = setup_repo();
        std::fs::write(dir.path().join("other.py"), "cur2.execute(q2)\n").unwrap();
        let client = Arc::new(MarkedUsageClient {
            inner: client_with(vec![
                (S1_SYSTEM_MARK, S1_JSON.to_string()),
                (S2_SYSTEM_MARK, S2_JSON.to_string()),
                (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
                (S4_SYSTEM_MARK, s4_two_findings_json()),
                (SEMANTIC_DEDUP_MARK, S3_GARBAGE.to_string()),
                (S8_SYSTEM_MARK, s8_two_ranked_json()),
            ]),
            mark: SEMANTIC_DEDUP_MARK,
            usage: Usage {
                input_tokens: 1000,
                ..Usage::default()
            },
        });
        let mut config = scan_config();
        config.step5.pre_verify_threshold = 2;
        config.step5.dedup.semantic = true;
        config.spend_cap = Some(SpendCap {
            max_total_tokens: Some(1),
            max_wall_clock: None,
        });
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, None);
        let report = outcome.report.unwrap();
        // The scan stopped before S6, so nothing was verified: the two
        // candidates are reported as NOT verified, never as findings.
        assert!(report.findings.is_empty());
        let metrics = report.metrics.clone().unwrap();
        assert_eq!(metrics.raw_findings_count, 2);
        assert_eq!(metrics.true_positive_count, 0);
        assert_eq!(metrics.duplicate_count, 0);
        let unverified: Vec<_> = report
            .dropped
            .iter()
            .filter(|d| d.reason == DropReason::Unconfirmed && d.detail.starts_with("not verified"))
            .collect();
        // Message args live in locals: an `assert!` argument on its own
        // line is never evaluated and shows up as an uncovered line.
        let dropped_dbg = format!("{:?}", report.dropped);
        assert_eq!(unverified.len(), 2, "{dropped_dbg}");
        let detail = unverified[0].detail.clone();
        assert!(detail.contains("token budget"), "{detail}");
    }

    /// The 2026-09-06 Juice Shop failure end to end, in miniature: the
    /// cap is reached by the FIRST unit of work inside S4, and the stage
    /// must stop starting chunks then and there instead of finishing all
    /// of them and only noticing at the boundary afterwards. Uses the
    /// real `SpendGate`, so it also proves `baseline_tokens` + the
    /// tracker's non-destructive `peek` add up to the live running total
    /// mid-stage — the thing `tokens_by_phase` alone cannot see.
    #[tokio::test]
    async fn a_token_cap_reached_inside_s4_stops_starting_new_chunks() {
        let dir = setup_repo();
        std::fs::write(dir.path().join("other.py"), "cur2.execute(q2)\n").unwrap();
        let client = Arc::new(MarkedUsageClient {
            inner: client_with(full_table(
                &s4_two_findings_json(),
                &s6_true_positive_text(),
                &s8_two_ranked_json(),
            )),
            mark: S4_SYSTEM_MARK,
            usage: Usage {
                input_tokens: 1000,
                ..Usage::default()
            },
        });
        let mut config = scan_config();
        // One chunk at a time, so the first chunk's spend is definitely
        // visible to the gate before the second chunk consults it.
        config.step4.parallel = 1;
        config.spend_cap = Some(SpendCap {
            max_total_tokens: Some(500),
            max_wall_clock: None,
        });
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();

        assert_eq!(outcome.stopped_after, None);
        let report = outcome.report.unwrap();
        let metrics = report.metrics.clone().unwrap();
        assert!(
            metrics
                .budget_stop
                .starts_with("S4: token budget of 500 reached"),
            "{}",
            metrics.budget_stop
        );
        assert!(
            metrics
                .budget_stop
                // The two original chunks plus the v1.3 `injection` specialist
                // chunk that the `.execute(` sinks gate in.
                .ends_with("1 of 3 deep-dive chunk(s) analyzed, 2 skipped"),
            "{}",
            metrics.budget_stop
        );
        assert_eq!(
            metrics.chunks_attempted, 1,
            "the skipped chunk was never attempted"
        );
        assert_eq!(metrics.chunks_failed, 0, "and it did not fail");
        assert!(bc_report_md::render_markdown(&report).contains("**BUDGET REACHED**"));
    }

    /// The same failure at the stage that actually caused it: S6 was 69%
    /// of the Juice Shop scan's whole spend, over 1,881 sessions, none of
    /// which could see the budget. A finding whose session never runs
    /// must be reported as unverified — not counted as a true positive,
    /// and not silently missing from the report.
    #[tokio::test]
    async fn a_token_cap_reached_inside_s6_leaves_the_rest_unverified_and_says_so() {
        let dir = setup_repo();
        std::fs::write(dir.path().join("other.py"), "cur2.execute(q2)\n").unwrap();
        let client = Arc::new(MarkedUsageClient {
            inner: client_with(full_table(
                &s4_two_findings_json(),
                &s6_true_positive_text(),
                &s8_ranked_json(),
            )),
            mark: S6_SYSTEM_MARK,
            usage: Usage {
                input_tokens: 1000,
                ..Usage::default()
            },
        });
        let mut config = scan_config();
        config.step6.parallel = 1;
        config.spend_cap = Some(SpendCap {
            max_total_tokens: Some(500),
            max_wall_clock: None,
        });
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();

        let report = outcome.report.unwrap();
        let metrics = report.metrics.clone().unwrap();
        assert!(
            metrics
                .budget_stop
                .starts_with("S6: token budget of 500 reached"),
            "{}",
            metrics.budget_stop
        );
        assert!(
            metrics
                .budget_stop
                .ends_with("1 of 2 finding(s) verified, 1 left unverified"),
            "{}",
            metrics.budget_stop
        );
        // Exactly one finding was actually confirmed; the other is
        // present, and honestly labeled.
        assert_eq!(metrics.true_positive_count, 1);
        assert_eq!(metrics.raw_findings_count, 2);
        let unverified: Vec<&DroppedFinding> = report
            .dropped
            .iter()
            .filter(|d| d.reason == DropReason::Unconfirmed)
            .collect();
        assert_eq!(unverified.len(), 1);
        let detail = unverified[0].detail.clone();
        assert!(
            detail.starts_with("not verified — token budget of 500 reached"),
            "{detail}"
        );
        let md = bc_report_md::render_markdown(&report);
        assert!(md.contains("**BUDGET REACHED**"), "{md}");
        assert!(md.contains("[UNCONFIRMED]"), "{md}");
    }

    /// Gives only S6's own verify call enough usage to trip the cap —
    /// S1-S5 all stay under budget with a single finding (S5's semantic
    /// pass doesn't engage at the default `pre_verify_threshold`) — so
    /// the trip happens right after S6, snapshotting `verified.verified`
    /// (S6's true-positive survivor) with `true_positive_count` already
    /// set, but before S7's dedup ever runs.
    #[tokio::test]
    async fn a_token_cap_tripped_by_s6_s_own_verify_call_stops_the_scan_after_s6() {
        let dir = setup_repo();
        let client = Arc::new(MarkedUsageClient {
            inner: one_finding_client(),
            mark: S6_SYSTEM_MARK,
            usage: Usage {
                input_tokens: 1000,
                ..Usage::default()
            },
        });
        let mut config = scan_config();
        config.spend_cap = Some(SpendCap {
            max_total_tokens: Some(1),
            max_wall_clock: None,
        });
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, None);
        let report = outcome.report.unwrap();
        assert_eq!(report.findings.len(), 1);
        let metrics = report.metrics.unwrap();
        assert_eq!(metrics.true_positive_count, 1);
        assert_eq!(metrics.false_positive_count, 0);
        assert_eq!(metrics.duplicate_count, 0);
    }

    /// A generous cap that's never actually reached behaves identically
    /// to `spend_cap: None` — the scan runs S4 through S7 to completion
    /// exactly as it would unbounded.
    #[tokio::test]
    async fn a_generous_spend_cap_lets_the_scan_complete_normally() {
        let dir = setup_repo();
        let mut config = scan_config();
        config.spend_cap = Some(SpendCap {
            max_total_tokens: Some(u64::MAX),
            max_wall_clock: Some(std::time::Duration::from_secs(3600)),
        });
        let outcome = run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.stopped_after, None);
        let report = outcome.report.unwrap();
        assert_eq!(report.findings.len(), 1);
        let metrics = report.metrics.unwrap();
        assert_eq!(metrics.true_positive_count, 1);
        assert_eq!(metrics.false_positive_count, 0);
        assert!(outcome.sarif.is_some());
    }

    #[tokio::test]
    async fn run_scan_registers_the_run_with_a_checkpoint_store() {
        let dir = setup_repo();
        let ckpt_dir = tempfile::tempdir().unwrap();
        let db_path = ckpt_dir.path().join("state.db");
        let store: Arc<dyn bc_checkpoint::CheckpointStore> =
            Arc::new(bc_checkpoint::SqliteCheckpointStore::new(&db_path).unwrap());
        let mut config = scan_config();
        config.checkpoint = Some(store);
        run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();

        // A separate connection to the same file — proves `register_run`
        // actually persisted a `runs` row, mirroring `remediate`'s own
        // identical test.
        let inspector = bc_checkpoint::SqliteCheckpointStore::new(&db_path).unwrap();
        let report = inspector.prune(100, 5, true).unwrap();
        assert_eq!(report.kept, 1);
        assert!(report.deleted.is_empty());
    }

    #[tokio::test]
    async fn run_scan_saves_a_checkpoint_for_every_stage_that_actually_ran() {
        let dir = setup_repo();
        let ckpt_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = Arc::new(
            bc_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
        );
        let mut config = scan_config();
        config.checkpoint = Some(store.clone());
        run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();

        let run_id = bc_checkpoint::run_id_for(dir.path());
        for step in ["s1", "s2", "s3", "s4", "s5", "s6", "s7"] {
            assert!(
                store.load(&run_id, step).is_some(),
                "missing checkpoint for {step}"
            );
        }
        // S8 is deliberately not checkpointed — see `Step4Checkpoint`'s
        // sibling doc comments on what S1-S7 checkpointing covers.
        assert!(store.load(&run_id, "s8").is_none());
    }

    #[tokio::test]
    async fn run_scan_without_resume_clears_every_stale_checkpoint_before_running() {
        let dir = setup_repo();
        let ckpt_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = Arc::new(
            bc_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
        );
        let run_id = bc_checkpoint::run_id_for(dir.path());
        // A leftover key from an earlier, unrelated run of this same
        // repo — not one `run_scan` would ever itself write or read, so
        // its removal can only be `reset_run`'s doing, not incidental
        // overwriting by this run's own S1-S7 saves.
        store
            .save(&run_id, "stale_leftover", b"from a discarded prior run")
            .unwrap();

        let mut config = scan_config();
        config.checkpoint = Some(store.clone());
        // config.resume stays false (the default) — a fresh run.
        let outcome = run_scan(
            empty_findings_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();

        assert!(outcome.report.is_some());
        assert_eq!(store.load(&run_id, "stale_leftover"), None);
    }

    #[tokio::test]
    async fn run_scan_with_resume_uses_a_cached_ctx_and_skips_s1_s_llm_call() {
        let dir = setup_repo();
        let ckpt_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = Arc::new(
            bc_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
        );
        let run_id = bc_checkpoint::run_id_for(dir.path());
        // Three files that don't exist in `setup_repo()`'s real fixture
        // (which only creates `app.py`) — `total_files_in_scope == 3`
        // afterward can only come from this cached `ctx`, not a real S1
        // walk of the repo.
        let cached_ctx = ContextPackage {
            language: "python".to_string(),
            all_files: vec!["a.py".to_string(), "b.py".to_string(), "c.py".to_string()],
            ..ContextPackage::default()
        };
        store
            .save(
                &run_id,
                "s1",
                &serde_json::to_vec(&Step1Checkpoint {
                    ctx: cached_ctx,
                    degraded: false,
                })
                .unwrap(),
            )
            .unwrap();

        // S1's mark is deliberately absent from the table: if S1 were
        // called anyway (a real bug), `route`'s shared fallback panics.
        let client = client_with(vec![
            (S2_SYSTEM_MARK, S2_JSON.to_string()),
            (S3_SYSTEM_MARK, S3_GARBAGE.to_string()),
            (S4_SYSTEM_MARK, S4_EMPTY.to_string()),
        ]);
        let mut config = scan_config();
        config.checkpoint = Some(store);
        config.resume = true;

        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();

        let metrics = outcome.report.unwrap().metrics.unwrap();
        assert_eq!(metrics.total_files_in_scope, 3);
    }

    #[tokio::test]
    async fn run_scan_with_resume_falls_back_to_a_live_run_when_the_cached_checkpoint_is_corrupt() {
        let dir = setup_repo();
        let ckpt_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = Arc::new(
            bc_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
        );
        let run_id = bc_checkpoint::run_id_for(dir.path());
        store.save(&run_id, "s1", b"not valid json").unwrap();

        let mut config = scan_config();
        config.checkpoint = Some(store);
        config.resume = true;
        let outcome = run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        // Falls back to a genuine live S1 run (`one_finding_client` has
        // S1's mark) rather than erroring on the unparseable payload.
        assert_eq!(outcome.report.unwrap().findings.len(), 1);
    }

    #[tokio::test]
    async fn run_scan_resume_without_a_checkpoint_store_behaves_like_a_normal_scan() {
        let dir = setup_repo();
        let mut config = scan_config();
        config.resume = true; // no checkpoint store at all
        let outcome = run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        assert_eq!(outcome.report.unwrap().findings.len(), 1);
    }

    /// The end-to-end resume story: a first, unbounded pass populates a
    /// checkpoint for every one of S1-S7; a second `--resume` pass, given
    /// a client whose router recognizes ONLY S8's mark (S8 is
    /// deliberately never checkpointed — see `Step4Checkpoint`'s sibling
    /// doc comments), reaches the exact same report without ever calling
    /// the LLM for S1-S7 — if it had, `route`'s shared panic would fire.
    #[tokio::test]
    async fn run_scan_with_resume_serves_every_stage_from_a_fully_populated_cache() {
        let dir = setup_repo();
        let ckpt_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = Arc::new(
            bc_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
        );

        let mut first_config = scan_config();
        first_config.checkpoint = Some(store.clone());
        let first = run_scan(
            one_finding_client(),
            Arc::new(NoTools),
            scan_input(dir.path()),
            first_config,
            None,
        )
        .await
        .unwrap();
        let first_report = first.report.unwrap();

        let second_client = client_with(vec![(S8_SYSTEM_MARK, s8_ranked_json())]);
        let mut second_config = scan_config();
        second_config.checkpoint = Some(store);
        second_config.resume = true;
        let second = run_scan(
            second_client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            second_config,
            None,
        )
        .await
        .unwrap();
        let second_report = second.report.unwrap();

        assert_eq!(second_report.findings.len(), first_report.findings.len());
        assert_eq!(
            second_report.metrics.unwrap().true_positive_count,
            first_report.metrics.unwrap().true_positive_count
        );
    }

    /// A hand-seeded checkpoint whose OWN `degraded` flag is `true` for
    /// S1/S2/S5/S7 (the four stages whose checkpoint carries one) must
    /// still record the matching `errors_by_stage` entry on a cache hit —
    /// a live degraded run and a cached-as-degraded run should look
    /// identical to `build_metrics`, not silently lose the signal just
    /// because the expensive part (the LLM call) didn't happen this time.
    #[tokio::test]
    async fn run_scan_with_resume_records_errors_by_stage_from_a_degraded_cached_checkpoint() {
        let dir = setup_repo();
        let ckpt_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = Arc::new(
            bc_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
        );
        let run_id = bc_checkpoint::run_id_for(dir.path());

        let ctx = ContextPackage {
            all_files: vec!["app.py".to_string()],
            ..ContextPackage::default()
        };
        store
            .save(
                &run_id,
                "s1",
                &serde_json::to_vec(&Step1Checkpoint {
                    ctx,
                    degraded: true,
                })
                .unwrap(),
            )
            .unwrap();
        store
            .save(
                &run_id,
                "s2",
                &serde_json::to_vec(&Step2Checkpoint {
                    threat_model: None,
                    degraded: true,
                })
                .unwrap(),
            )
            .unwrap();
        store
            .save(
                &run_id,
                "s3",
                &serde_json::to_vec(&Step3Checkpoint {
                    manifest: TaskManifest {
                        chunks: Vec::new(),
                        rationale: String::new(),
                        unreachable_files: Vec::new(),
                    },
                    degraded: false,
                })
                .unwrap(),
            )
            .unwrap();
        let finding = s10_finding(Some(7.0));
        store
            .save(
                &run_id,
                "s4",
                &serde_json::to_vec(&Step4Checkpoint {
                    findings: vec![finding.clone()],
                    outcomes: BTreeMap::new(),
                })
                .unwrap(),
            )
            .unwrap();
        store
            .save(
                &run_id,
                "s5",
                &serde_json::to_vec(&Step5Checkpoint {
                    findings: vec![finding.clone()],
                    dropped: Vec::new(),
                    degraded: true,
                })
                .unwrap(),
            )
            .unwrap();
        store
            .save(
                &run_id,
                "s6",
                &serde_json::to_vec(&Step6Checkpoint {
                    verified: vec![finding.clone()],
                    dropped: Vec::new(),
                })
                .unwrap(),
            )
            .unwrap();
        store
            .save(
                &run_id,
                "s7",
                &serde_json::to_vec(&Step7Checkpoint {
                    findings: vec![finding],
                    dropped: Vec::new(),
                    degraded: true,
                })
                .unwrap(),
            )
            .unwrap();

        let client = client_with(vec![(S8_SYSTEM_MARK, s8_ranked_json())]);
        let mut config = scan_config();
        config.checkpoint = Some(store);
        config.resume = true;

        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();

        let metrics = outcome.report.unwrap().metrics.unwrap();
        assert_eq!(metrics.errors_by_stage.get("s1"), Some(&1));
        assert_eq!(metrics.errors_by_stage.get("s2"), Some(&1));
        assert_eq!(metrics.errors_by_stage.get("s5"), Some(&1));
        assert_eq!(metrics.errors_by_stage.get("s7"), Some(&1));
    }

    #[tokio::test]
    async fn a_stage1_llm_failure_propagates_as_err() {
        let dir = setup_repo();
        let client: Arc<dyn LlmClient> = Arc::new(RoutedClient::new(|_| {
            Err(LlmError::ConnectionError {
                message: "down".to_string(),
            })
        }));
        let result = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn head_sha_is_none_for_a_non_git_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(head_sha(dir.path()), None);
    }

    #[test]
    fn head_sha_returns_the_commit_hash_for_a_real_repo() {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .output()
                .unwrap()
        };
        run(&["init", "-q"]);
        run(&[
            "-c",
            "user.email=test@test.com",
            "-c",
            "user.name=test",
            "commit",
            "--allow-empty",
            "-q",
            "-m",
            "x",
        ]);
        let sha = head_sha(dir.path());
        assert_eq!(sha.as_ref().map(String::len), Some(40));
    }

    #[test]
    fn resolve_app_profile_with_no_application_id_is_none() {
        assert_eq!(resolve_app_profile(None, None), (None, None));
    }

    #[test]
    fn resolve_app_profile_with_an_empty_application_id_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_app_profile(Some(""), Some(dir.path())),
            (None, None)
        );
    }

    #[test]
    fn resolve_app_profile_with_no_cmdb_path_is_none() {
        assert_eq!(resolve_app_profile(Some("42"), None), (None, None));
    }

    #[test]
    fn resolve_app_profile_with_a_directory_cmdb_path_is_none() {
        // `load_cmdb_csv` treats a non-file path as "no CMDB configured"
        // (`Ok(empty map)`), not an error — this exercises that branch,
        // distinct from a genuine read failure (see the next test).
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve_app_profile(Some("42"), Some(dir.path())),
            (None, None)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_app_profile_with_an_unreadable_cmdb_file_is_none() {
        // The same id resolves from a readable CMDB, so the `None` below
        // is the read failure's doing, not a missing row.
        let dir = tempfile::tempdir().unwrap();
        let readable = dir.path().join("cmdb.csv");
        std::fs::write(
            &readable,
            "id,name,externally_facing,pci,pan,pii,parent_id\n1,Acme,yes,no,no,no,\n",
        )
        .unwrap();
        assert!(resolve_app_profile(Some("1"), Some(&readable)).0.is_some());
        // A regular file no user can read: the kernel refuses reads of this
        // write-only sysctl even for root, unlike a chmod-000 file.
        let unreadable = std::path::Path::new("/proc/sys/vm/drop_caches");
        assert_eq!(
            resolve_app_profile(Some("1"), Some(unreadable)),
            (None, None)
        );
    }

    #[test]
    fn resolve_app_profile_with_an_id_not_in_the_cmdb_is_none() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("cmdb.csv"),
            "id,name,externally_facing,pci,pan,pii,parent_id\n1,Acme,yes,no,no,no,\n",
        )
        .unwrap();
        let (profile, info) = resolve_app_profile(Some("999"), Some(&dir.path().join("cmdb.csv")));
        assert_eq!(profile, None);
        assert_eq!(info, None);
    }

    #[test]
    fn resolve_app_profile_with_a_matching_id_builds_an_app_profile() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("cmdb.csv"),
            "id,name,externally_facing,pci,pan,pii,parent_id\n42,Acme,yes,yes,no,no,\n",
        )
        .unwrap();
        let (profile, info) = resolve_app_profile(Some("42"), Some(&dir.path().join("cmdb.csv")));
        let profile = profile.unwrap();
        assert_eq!(profile.application_id, "42");
        assert_eq!(profile.name, "Acme");
        assert!(profile.externally_facing);
        assert!(profile.pci_scoped);
        assert!(info.is_some());
    }

    // ── `load_third_party_findings` / `load_vendor_findings` ────────

    fn third_party_input(set: impl FnOnce(&mut ScanInput)) -> ScanInput {
        let mut input = scan_input(Path::new("/unused"));
        set(&mut input);
        input
    }

    #[tokio::test]
    async fn load_third_party_findings_is_empty_when_nothing_is_configured() {
        let input = scan_input(Path::new("/unused"));
        assert!(load_third_party_findings(&input).await.is_empty());
    }

    #[tokio::test]
    async fn load_third_party_findings_ingests_a_checkmarx_xml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkmarx.xml");
        std::fs::write(
            &path,
            r#"<CxXMLResults><Query cweId="89" name="SQLi"><Result FileName="app.py" Line="1"/></Query></CxXMLResults>"#,
        )
        .unwrap();
        let input = third_party_input(|i| i.checkmarx_xml = vec![path]);
        let findings = load_third_party_findings(&input).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].chunk_id.starts_with("external:checkmarx:"));
    }

    #[tokio::test]
    async fn load_third_party_findings_ingests_a_snyk_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snyk.json");
        std::fs::write(
            &path,
            r#"{"vulnerabilities": [{"id": "SNYK-1", "packageName": "lodash", "version": "1.0"}]}"#,
        )
        .unwrap();
        let input = third_party_input(|i| i.snyk_json = vec![path]);
        let findings = load_third_party_findings(&input).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].chunk_id.starts_with("external:snyk:"));
    }

    #[tokio::test]
    async fn load_third_party_findings_ingests_a_semgrep_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("semgrep.json");
        std::fs::write(&path, r#"{"results": [{"check_id": "x", "path": "a.py"}]}"#).unwrap();
        let input = third_party_input(|i| i.semgrep_json = vec![path]);
        let findings = load_third_party_findings(&input).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].chunk_id.starts_with("external:semgrep:"));
    }

    #[tokio::test]
    async fn load_third_party_findings_ingests_an_aikido_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("aikido.json");
        std::fs::write(&path, r#"[{"id": 1, "rule": "x", "severity": "low"}]"#).unwrap();
        let input = third_party_input(|i| i.aikido_json = vec![path]);
        let findings = load_third_party_findings(&input).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].chunk_id.starts_with("external:aikido:"));
    }

    #[tokio::test]
    async fn load_third_party_findings_ingests_a_sonatype_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sonatype.json");
        std::fs::write(
            &path,
            r#"{"components": [{"packageUrl": "pkg:npm/x@1", "securityData": {"securityIssues": [{"reference": "CVE-1", "severity": 5.0}]}}]}"#,
        )
        .unwrap();
        let input = third_party_input(|i| i.sonatype_json = vec![path]);
        let findings = load_third_party_findings(&input).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].chunk_id.starts_with("external:sonatype:"));
    }

    #[tokio::test]
    async fn load_third_party_findings_combines_multiple_vendors_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let checkmarx_path = dir.path().join("cx.xml");
        std::fs::write(
            &checkmarx_path,
            r#"<CxXMLResults><Query cweId="89" name="SQLi"><Result FileName="app.py" Line="1"/></Query></CxXMLResults>"#,
        )
        .unwrap();
        let snyk_path = dir.path().join("snyk.json");
        std::fs::write(&snyk_path, r#"{"vulnerabilities": [{"id": "S-1"}]}"#).unwrap();
        let mut input = scan_input(Path::new("/unused"));
        input.checkmarx_xml = vec![checkmarx_path];
        input.snyk_json = vec![snyk_path];
        assert_eq!(load_third_party_findings(&input).await.len(), 2);
    }

    /// The read itself is capped, not just the size check before it:
    /// `/proc/self/status` reports a length of 0 but reads as hundreds of
    /// bytes, as a file growing after the check would.
    #[cfg(target_os = "linux")]
    #[test]
    fn read_bounded_export_caps_the_read_when_the_size_check_underreports() {
        let refused =
            read_bounded_export(std::path::Path::new("/proc/self/status"), 16).unwrap_err();
        assert_eq!(refused, "larger than the 16-byte limit for a vendor export");
    }

    #[test]
    fn read_bounded_export_refuses_a_file_over_the_limit_and_non_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.json");
        std::fs::write(&path, "0123456789").unwrap();
        assert_eq!(read_bounded_export(&path, 10).unwrap(), "0123456789");
        let refused = read_bounded_export(&path, 9).unwrap_err();
        assert_eq!(refused, "larger than the 9-byte limit for a vendor export");
        std::fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(read_bounded_export(&path, 10).is_err());
        let missing = dir.path().join("missing.json");
        assert!(read_bounded_export(&missing, 10).is_err());
    }

    #[tokio::test]
    async fn load_vendor_findings_warns_and_skips_a_nonexistent_file() {
        let input =
            third_party_input(|i| i.checkmarx_xml = vec![PathBuf::from("/does/not/exist.xml")]);
        let loaded = load_third_party_findings(&input).await;
        assert!(loaded.is_empty());
        assert_eq!(loaded.ingestion.len(), 1);
        assert!(!loaded.ingestion[0].completed);
        assert!(!loaded.ingestion[0].limitations.is_empty());
    }

    #[tokio::test]
    async fn load_vendor_findings_warns_and_skips_a_malformed_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.xml");
        std::fs::write(&path, "not xml at all").unwrap();
        let input = third_party_input(|i| i.checkmarx_xml = vec![path]);
        assert!(load_third_party_findings(&input).await.is_empty());
    }

    // ── live-vendor fetch path ───────────────────────────────────────

    #[tokio::test]
    async fn load_third_party_findings_fetches_from_a_configured_live_semgrep_client() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(
                // The v1 findings operation's own inline 200 body — a
                // top-level `findings` array with snake_case fields, per
                // `semgrep.dev/api/v1/public_v1.openapi.yaml`. This
                // fixture previously used the `{"sastFindings": {...}}`
                // envelope and camelCase field names taken from a
                // different (internal) endpoint's schema, so it decoded
                // to zero findings and asserted against `len() == 1`.
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "findings": [{
                        "id": 1,
                        "state": "unresolved",
                        "status": "open",
                        "rule": {"name": "x", "message": "m", "cwe_names": []},
                        "severity": "high",
                        "location": {"file_path": "a.py", "line": 1, "end_line": 1}
                    }]
                })),
            )
            .mount(&server)
            .await;
        let mut config =
            bc_thirdparty_api::semgrep::SemgrepConfig::new("tok", "deploy", "org/repo");
        config.base_url = server.uri();
        let input = third_party_input(|i| i.semgrep_live = Some(config));

        let findings = load_third_party_findings(&input).await;

        assert_eq!(findings.len(), 1);
        assert!(findings[0].chunk_id.starts_with("external:semgrep:"));
    }

    #[tokio::test]
    async fn load_third_party_findings_warns_and_skips_a_failed_live_fetch() {
        let mut config =
            bc_thirdparty_api::semgrep::SemgrepConfig::new("tok", "deploy", "org/repo");
        config.base_url = "http://127.0.0.1:1".to_string();
        let input = third_party_input(|i| i.semgrep_live = Some(config));

        assert!(load_third_party_findings(&input).await.is_empty());
    }

    #[tokio::test]
    async fn load_third_party_findings_warns_and_skips_a_failed_live_snyk_fetch() {
        let mut config = bc_thirdparty_api::snyk::SnykConfig::new("tok", "org-1", "proj-1");
        config.base_url = "http://127.0.0.1:1".to_string();
        let input = third_party_input(|i| i.snyk_live = Some(config));

        assert!(load_third_party_findings(&input).await.is_empty());
    }

    #[tokio::test]
    async fn load_third_party_findings_warns_and_skips_a_failed_live_sonatype_fetch() {
        let config = bc_thirdparty_api::sonatype::SonatypeConfig::new(
            "http://127.0.0.1:1",
            "user",
            "pass",
            "my-app",
        );
        let input = third_party_input(|i| i.sonatype_live = Some(config));

        assert!(load_third_party_findings(&input).await.is_empty());
    }

    #[tokio::test]
    async fn load_third_party_findings_warns_and_skips_a_failed_live_aikido_fetch() {
        let mut config = bc_thirdparty_api::aikido::AikidoConfig::new("id", "secret", 42);
        config.base_url = "http://127.0.0.1:1".to_string();
        let input = third_party_input(|i| i.aikido_live = Some(config));

        assert!(load_third_party_findings(&input).await.is_empty());
    }

    #[tokio::test]
    async fn load_third_party_findings_warns_and_skips_a_failed_live_checkmarx_fetch() {
        let config = bc_thirdparty_api::checkmarx::CheckmarxConfig::new(
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            "acme",
            "key",
            "proj-1",
        );
        let input = third_party_input(|i| i.checkmarx_live = Some(config));

        assert!(load_third_party_findings(&input).await.is_empty());
    }

    fn third_party_only_client() -> Arc<dyn LlmClient> {
        let s6 = s6_true_positive_text();
        let s8 = s8_ranked_json();
        client_with(full_table(S4_EMPTY, &s6, &s8))
    }

    #[tokio::test]
    async fn run_scan_merges_a_third_party_finding_into_the_final_report() {
        // S4 (`S4_EMPTY`) discovers nothing on its own — the only finding
        // in this scan comes from the ingested Checkmarx report, proving
        // it really is re-verified through S6 (using `s6_true_positive_
        // text`, the same real verdict grammar `one_finding_client`
        // uses) and survives S7/S8 through to the final report, not just
        // parsed and dropped somewhere along the way.
        let dir = setup_repo();
        let checkmarx_path = dir.path().join("checkmarx.xml");
        std::fs::write(
            &checkmarx_path,
            r#"<CxXMLResults><Query cweId="89" name="SQLi from Checkmarx"><Result FileName="app.py" Line="2"/></Query></CxXMLResults>"#,
        )
        .unwrap();
        let mut input = scan_input(dir.path());
        input.checkmarx_xml = vec![checkmarx_path];

        let outcome = run_scan(
            third_party_only_client(),
            Arc::new(NoTools),
            input,
            scan_config(),
            None,
        )
        .await
        .unwrap();

        let report = outcome.report.unwrap();
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].finding.title, "SQLi from Checkmarx");
        assert!(report.findings[0]
            .finding
            .chunk_id
            .starts_with("external:checkmarx:"));
    }

    // ── `build_metrics` / `outcome_str` ─────────────────────────────

    fn chunk(id: &str, files: &[&str], specialist: Option<&str>) -> Chunk {
        Chunk {
            id: id.to_string(),
            size: bc_model::ChunkSize::Medium,
            risk_rank: 1,
            files: files.iter().map(|f| f.to_string()).collect(),
            focus_entry_points: Vec::new(),
            hypothesis: String::new(),
            related_cves: Vec::new(),
            threat_id: None,
            languages: Vec::new(),
            specialist: specialist.map(str::to_string),
            path_funcs: Vec::new(),
            source_ref: String::new(),
            sink_ref: String::new(),
            sink_cwe: Vec::new(),
            shard_id: String::new(),
        }
    }

    #[test]
    fn outcome_str_maps_every_variant() {
        assert_eq!(
            outcome_str(bc_stage_s4::ChunkOutcome::Completed),
            "completed"
        );
        assert_eq!(outcome_str(bc_stage_s4::ChunkOutcome::Error), "error");
        assert_eq!(
            outcome_str(bc_stage_s4::ChunkOutcome::Guardrail),
            "guardrail"
        );
    }

    #[test]
    fn build_metrics_classifies_every_chunk_kind_and_aggregates_loc_by_language() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "a\nb\n\nc\n").unwrap(); // 3 non-blank
        std::fs::write(dir.path().join("unscanned.py"), "x\ny\n").unwrap(); // in scope, not analyzed
        std::fs::write(dir.path().join("app.rs"), "fn main() {}\n").unwrap();

        let ctx = ContextPackage {
            all_files: vec![
                "app.py".to_string(),
                "unscanned.py".to_string(),
                "app.rs".to_string(),
            ],
            ..Default::default()
        };
        let manifest = TaskManifest {
            chunks: vec![
                chunk("risk-001", &["app.py"], None),
                chunk("catchall-002", &["app.rs"], None),
                chunk("specialist-003", &["app.py"], Some("iac")),
            ],
            rationale: String::new(),
            unreachable_files: Vec::new(),
        };
        let mut chunk_outcomes = BTreeMap::new();
        chunk_outcomes.insert("risk-001".to_string(), bc_stage_s4::ChunkOutcome::Completed);
        chunk_outcomes.insert("catchall-002".to_string(), bc_stage_s4::ChunkOutcome::Error);
        chunk_outcomes.insert(
            "specialist-003".to_string(),
            bc_stage_s4::ChunkOutcome::Guardrail,
        );

        let mut tokens_by_phase = BTreeMap::new();
        tokens_by_phase.insert(
            "s1".to_string(),
            phase_usage(Usage {
                input_tokens: 100,
                output_tokens: 20,
                cache_creation_input_tokens: 5,
                cache_read_input_tokens: 3,
            }),
        );
        tokens_by_phase.insert(
            "s3".to_string(),
            phase_usage(Usage {
                input_tokens: 50,
                output_tokens: 10,
                ..Usage::default()
            }),
        );
        let metrics = build_metrics(
            &ctx,
            &manifest,
            dir.path(),
            "demo",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:10Z",
            5,
            3,
            1,
            1,
            &chunk_outcomes,
            &tokens_by_phase,
            Vec::new(),
            BTreeMap::new(),
            None,
        );

        assert_eq!(metrics.scan_id, "2024-01-01T00:00:00Z__demo");
        assert_eq!(metrics.module_name, "demo");
        assert_eq!(metrics.duration_sec, 10.0);
        assert_eq!(metrics.total_files_in_scope, 3);
        assert_eq!(metrics.analyzed_files_unique, 2); // app.py + app.rs; unscanned.py excluded
        assert_eq!(metrics.chunks_total, 3);
        assert_eq!(metrics.chunks_risk, 1);
        assert_eq!(metrics.chunks_catchall, 1);
        assert_eq!(metrics.chunks_specialist, 1);
        assert_eq!(metrics.chunks_attempted, 3);
        assert_eq!(metrics.chunks_failed, 2); // error + guardrail, not completed
        assert_eq!(metrics.raw_findings_count, 5);
        assert_eq!(metrics.true_positive_count, 3);
        assert_eq!(metrics.false_positive_count, 1);
        assert_eq!(metrics.duplicate_count, 1);
        // Python's arithmetic (`util/tokens.py:54-61`): prompt = fresh +
        // cache-write, with cache-read tracked separately and NOT summed
        // into the total.
        // s1: 100 + 5 = 105 prompt, 20 completion, 3 cache-read.
        // s3: 50 prompt, 10 completion.
        assert_eq!(metrics.prompt_tokens, Some(155));
        assert_eq!(metrics.completion_tokens, Some(30));
        assert_eq!(metrics.total_tokens, Some(185));
        let phases = metrics.tokens_by_phase.as_ref().unwrap();
        assert_eq!(phases["s1"]["prompt"], 105);
        assert_eq!(phases["s1"]["completion"], 20);
        assert_eq!(phases["s1"]["cache_read"], 3);
        assert_eq!(phases["s1"]["cache_write"], 5);
        assert_eq!(phases["s1"]["calls"], 1);
        assert_eq!(phases["s3"]["prompt"], 50);
        // s4's own chunk-failure count (error + guardrail) is folded into
        // `errors_by_stage` automatically, even though the caller passed
        // an empty map in — this is the one stage whose per-stage error
        // count is always derived here, not supplied by the caller.
        assert_eq!(metrics.errors_by_stage.get("s4"), Some(&2));
        assert_eq!(metrics.errors_by_stage.len(), 1);
        // python: app.py (3 non-blank) + unscanned.py (2 non-blank) = 5 in scope,
        // but only app.py is analyzed (via a chunk) => 3 scanned.
        assert_eq!(metrics.loc_in_scope_by_language.get("python"), Some(&5));
        assert_eq!(metrics.loc_scanned_by_language.get("python"), Some(&3));
        // rust: app.rs (1 non-blank), analyzed via catchall-002 => counted in both.
        assert_eq!(metrics.loc_in_scope_by_language.get("rust"), Some(&1));
        assert_eq!(metrics.loc_scanned_by_language.get("rust"), Some(&1));
        assert_eq!(metrics.folders_scanned, vec!["."]);
        assert_eq!(metrics.scope.len(), 3);
        let risk_entry = metrics.scope.iter().find(|s| s.name == "risk-001").unwrap();
        assert_eq!(risk_entry.kind, ScopeKind::Risk);
        let catchall_entry = metrics
            .scope
            .iter()
            .find(|s| s.name == "catchall-002")
            .unwrap();
        assert_eq!(catchall_entry.kind, ScopeKind::Catchall);
        let specialist_entry = metrics
            .scope
            .iter()
            .find(|s| s.name == "specialist-003")
            .unwrap();
        assert_eq!(specialist_entry.kind, ScopeKind::Specialist);
    }

    #[test]
    fn build_metrics_reports_token_usage_as_unavailable_when_no_call_carried_any() {
        // Python's `tok_avail` gate (`util/metrics.py:93`): a scan whose
        // backend never reported usage must render "unavailable", not a
        // zero that reads as "this scan was free". Every phase here has
        // real calls but no usage — exactly what a `RoutedClient`-style
        // backend that omits the usage block produces.
        let dir = tempfile::tempdir().unwrap();
        let ctx = ContextPackage::default();
        let manifest = TaskManifest {
            chunks: Vec::new(),
            rationale: String::new(),
            unreachable_files: Vec::new(),
        };
        let mut tokens_by_phase = BTreeMap::new();
        tokens_by_phase.insert(
            "s1".to_string(),
            PhaseUsage {
                usage: Usage::default(),
                calls: 3,
                calls_with_usage: 0,
                cost: pricing::PhaseCost::default(),
                truncated_replies: 0,
            },
        );
        let metrics = build_metrics(
            &ctx,
            &manifest,
            dir.path(),
            "demo",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:10Z",
            0,
            0,
            0,
            0,
            &BTreeMap::new(),
            &tokens_by_phase,
            Vec::new(),
            BTreeMap::new(),
            None,
        );
        assert_eq!(metrics.prompt_tokens, None);
        assert_eq!(metrics.completion_tokens, None);
        assert_eq!(metrics.total_tokens, None);
        assert_eq!(metrics.tokens_by_phase, None);
        // Nothing was spent, so there is nothing to say about the cost
        // either, including that it was zero.
        assert_eq!(metrics.cost_usd, None);
        assert_eq!(metrics.unpriced_tokens, None);
        assert_eq!(metrics.unpriced_calls, None);
        assert!(metrics.unpriced_models.is_empty());
    }

    /// The token counts for a call that costs exactly 1.00 USD under
    /// `openai`/`gpt-4o`: 200,000 input at 2.50 per million is 0.50, and
    /// 50,000 output at 10.00 per million is another 0.50.
    fn one_dollar_of_gpt_4o() -> Usage {
        Usage {
            input_tokens: 200_000,
            output_tokens: 50_000,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 0,
        }
    }

    fn empty_metrics_inputs() -> (ContextPackage, TaskManifest) {
        (
            ContextPackage::default(),
            TaskManifest {
                chunks: Vec::new(),
                rationale: String::new(),
                unreachable_files: Vec::new(),
            },
        )
    }

    /// `build_metrics` with only the cost-relevant arguments varying.
    fn cost_metrics(
        repo_root: &Path,
        tokens_by_phase: &BTreeMap<String, PhaseUsage>,
        unpriced_models: Vec<String>,
    ) -> ScanMetrics {
        let (ctx, manifest) = empty_metrics_inputs();
        build_metrics(
            &ctx,
            &manifest,
            repo_root,
            "demo",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:10Z",
            0,
            0,
            0,
            0,
            &BTreeMap::new(),
            tokens_by_phase,
            unpriced_models,
            BTreeMap::new(),
            None,
        )
    }

    #[test]
    fn build_metrics_sums_every_phase_cost_into_one_run_total() {
        let dir = tempfile::tempdir().unwrap();
        let tokens_by_phase = BTreeMap::from([
            (
                "s1".to_string(),
                priced_phase(Some("openai"), "gpt-4o", one_dollar_of_gpt_4o()),
            ),
            (
                "s4".to_string(),
                priced_phase(Some("openai"), "gpt-4o", one_dollar_of_gpt_4o()),
            ),
        ]);
        let metrics = cost_metrics(dir.path(), &tokens_by_phase, Vec::new());

        assert_eq!(metrics.cost_usd, Some(2.0));
        assert_eq!(metrics.unpriced_tokens, Some(0));
        assert_eq!(metrics.unpriced_calls, Some(0));
        assert!(metrics.unpriced_models.is_empty());
        let phases = metrics.tokens_by_phase.as_ref().unwrap();
        assert_eq!(phases["s1"]["cost_usd"], 1.0);
        assert_eq!(phases["s4"]["cost_usd"], 1.0);
        assert_eq!(phases["s1"]["unpriced_tokens"], 0);
    }

    #[test]
    fn build_metrics_reports_an_unpriceable_run_as_unpriced_not_free() {
        // The whole point of the `Option`: a run whose model has no
        // published rate must not read as a run that cost nothing.
        let dir = tempfile::tempdir().unwrap();
        let tokens_by_phase = BTreeMap::from([(
            "s1".to_string(),
            priced_phase(Some("openai"), "house-blend-9", one_dollar_of_gpt_4o()),
        )]);
        let metrics = cost_metrics(
            dir.path(),
            &tokens_by_phase,
            vec!["openai/house-blend-9".to_string()],
        );

        assert_eq!(metrics.cost_usd, None);
        assert_ne!(metrics.cost_usd, Some(0.0));
        assert_eq!(metrics.unpriced_tokens, Some(250_000));
        assert_eq!(metrics.unpriced_calls, Some(1));
        assert_eq!(metrics.unpriced_models, ["openai/house-blend-9"]);
        // Tokens are still reported in full; only the money is missing.
        assert_eq!(metrics.total_tokens, Some(250_000));
        let phases = metrics.tokens_by_phase.as_ref().unwrap();
        assert_eq!(phases["s1"]["cost_usd"], serde_json::Value::Null);
        assert_eq!(phases["s1"]["unpriced_tokens"], 250_000);
    }

    #[test]
    fn build_metrics_reports_a_mixed_run_as_a_lower_bound() {
        let dir = tempfile::tempdir().unwrap();
        let tokens_by_phase = BTreeMap::from([
            (
                "s1".to_string(),
                priced_phase(Some("openai"), "gpt-4o", one_dollar_of_gpt_4o()),
            ),
            (
                "s4".to_string(),
                priced_phase(Some("openai"), "house-blend-9", one_dollar_of_gpt_4o()),
            ),
        ]);
        let metrics = cost_metrics(
            dir.path(),
            &tokens_by_phase,
            vec!["openai/house-blend-9".to_string()],
        );

        // The priced half is exact; the unpriced half is counted, not
        // guessed at, so the figure is a floor with a stated gap.
        assert_eq!(metrics.cost_usd, Some(1.0));
        assert_eq!(metrics.unpriced_tokens, Some(250_000));
        assert_eq!(metrics.unpriced_calls, Some(1));
        let phases = metrics.tokens_by_phase.as_ref().unwrap();
        assert_eq!(phases["s1"]["cost_usd"], 1.0);
        assert_eq!(phases["s4"]["cost_usd"], serde_json::Value::Null);
    }

    #[test]
    fn build_metrics_counts_a_model_with_no_cache_write_rate_as_partly_unpriced() {
        // `gpt-4o` publishes no cache-write rate at all, so a cached call
        // prices its other three classes exactly and reports the rest as
        // a hole rather than charging them at the input rate.
        let dir = tempfile::tempdir().unwrap();
        let usage = Usage {
            input_tokens: 200_000,
            output_tokens: 50_000,
            cache_creation_input_tokens: 1_000,
            cache_read_input_tokens: 800_000,
        };
        let tokens_by_phase = BTreeMap::from([(
            "s1".to_string(),
            priced_phase(Some("openai"), "gpt-4o", usage),
        )]);
        let metrics = cost_metrics(dir.path(), &tokens_by_phase, Vec::new());

        // 1.00 for input and output, plus 800,000 cache reads at 1.25
        // per million.
        assert_eq!(metrics.cost_usd, Some(2.0));
        assert_eq!(metrics.unpriced_tokens, Some(1_000));
        assert_eq!(metrics.unpriced_calls, Some(0));
        assert!(metrics.unpriced_models.is_empty());
    }

    #[tokio::test]
    async fn a_scan_on_a_priced_model_reports_what_it_cost() {
        let dir = setup_repo();
        let client = Arc::new(UsageInjectingClient {
            inner: empty_findings_client(),
            usage: one_dollar_of_gpt_4o(),
        });
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            priced_scan_config(Some("openai"), "gpt-4o"),
            None,
        )
        .await
        .unwrap();
        let metrics = outcome.report.unwrap().metrics.unwrap();
        let phases = metrics.tokens_by_phase.as_ref().unwrap();
        // Every call is one dollar, and the run total is exactly the sum
        // of the calls rather than a re-derivation from the token totals.
        let calls: i64 = phases.values().map(|b| b["calls"].as_i64().unwrap()).sum();
        assert!(calls > 1, "the fixture scan makes several calls");
        assert_eq!(metrics.cost_usd, Some(calls as f64));
        assert_eq!(metrics.unpriced_tokens, Some(0));
        assert!(metrics.unpriced_models.is_empty());
        assert_eq!(phases["s1"]["cost_usd"], 1.0);
    }

    #[tokio::test]
    async fn a_scan_on_a_model_no_table_knows_reports_unpriced_and_names_it() {
        // The default fixture model is `m`, which no provider publishes.
        let dir = setup_repo();
        let client = Arc::new(UsageInjectingClient {
            inner: empty_findings_client(),
            usage: one_dollar_of_gpt_4o(),
        });
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            priced_scan_config(Some("openai"), "m"),
            None,
        )
        .await
        .unwrap();
        let metrics = outcome.report.unwrap().metrics.unwrap();
        assert_eq!(metrics.cost_usd, None);
        assert!(metrics.total_tokens.unwrap() > 0, "tokens were still spent");
        assert!(metrics.unpriced_tokens.unwrap() > 0);
        // Named once for the whole run, however many phases hit it, and
        // spelled as the exact key a `pricing.rates` override needs.
        assert_eq!(metrics.unpriced_models, ["openai/m"]);
    }

    #[tokio::test]
    async fn a_scan_with_no_identified_provider_prices_nothing_and_says_so() {
        // No `--pricing-provider`, and a base URL whose host settled
        // nothing: the run is unpriced, and the report names the model
        // under a placeholder provider rather than picking one.
        let dir = setup_repo();
        let client = Arc::new(UsageInjectingClient {
            inner: empty_findings_client(),
            usage: one_dollar_of_gpt_4o(),
        });
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            priced_scan_config(None, "gpt-4o"),
            None,
        )
        .await
        .unwrap();
        let metrics = outcome.report.unwrap().metrics.unwrap();
        assert_eq!(metrics.cost_usd, None);
        assert_eq!(
            metrics.unpriced_models,
            [format!("{}/gpt-4o", pricing::UNKNOWN_PROVIDER)]
        );
    }

    #[tokio::test]
    async fn a_scan_whose_gateway_is_on_negotiated_rates_uses_the_override() {
        // The case the public table gets wrong. Same run, same tokens,
        // priced at a tenth of the list rate because the operator said so.
        let dir = setup_repo();
        let client = Arc::new(UsageInjectingClient {
            inner: empty_findings_client(),
            usage: one_dollar_of_gpt_4o(),
        });
        let mut config = priced_scan_config(Some("openai"), "gpt-4o");
        let mut overrides = bc_pricing::PriceTable::default();
        overrides.insert(
            "openai",
            "gpt-4o",
            bc_pricing::ModelPrice::flat(250_000, 1_000_000),
        );
        config.pricing.overrides = overrides;
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            config,
            None,
        )
        .await
        .unwrap();
        let metrics = outcome.report.unwrap().metrics.unwrap();
        let phases = metrics.tokens_by_phase.as_ref().unwrap();
        let calls: i64 = phases.values().map(|b| b["calls"].as_i64().unwrap()).sum();
        assert_eq!(metrics.cost_usd, Some(calls as f64 / 10.0));
    }

    #[tokio::test]
    async fn a_scan_whose_backend_reports_usage_records_calls_and_bills_cache_writes_only() {
        // End-to-end through `UsageTrackingClient`: proves `calls`/
        // `calls_with_usage` are captured per phase and that a cache-read
        // never inflates the headline prompt figure.
        let dir = setup_repo();
        let client = Arc::new(UsageInjectingClient {
            inner: empty_findings_client(),
            usage: Usage {
                input_tokens: 10,
                output_tokens: 2,
                cache_creation_input_tokens: 4,
                cache_read_input_tokens: 1_000,
            },
        });
        let outcome = run_scan(
            client,
            Arc::new(NoTools),
            scan_input(dir.path()),
            scan_config(),
            None,
        )
        .await
        .unwrap();
        let metrics = outcome.report.unwrap().metrics.unwrap();
        let phases = metrics.tokens_by_phase.as_ref().unwrap();
        let s1 = &phases["s1"];
        assert_eq!(s1["calls"], 1);
        assert_eq!(s1["prompt"], 14); // 10 fresh + 4 cache-write, NOT +1000 cache-read
        assert_eq!(s1["completion"], 2);
        assert_eq!(s1["cache_read"], 1_000);
        assert_eq!(s1["cache_write"], 4);
        // The grand totals are exactly the sum of the per-phase buckets,
        // and never include cache-reads — which here outnumber the
        // billable tokens 1000:14 per call, so folding them in would be
        // glaringly visible.
        let sum = |key: &str| -> i64 {
            phases
                .values()
                .map(|b| b[key].as_i64().unwrap())
                .sum::<i64>()
        };
        assert_eq!(metrics.prompt_tokens, Some(sum("prompt")));
        assert_eq!(metrics.completion_tokens, Some(sum("completion")));
        assert_eq!(
            metrics.total_tokens,
            Some(sum("prompt") + sum("completion"))
        );
        assert!(sum("cache_read") > metrics.total_tokens.unwrap());
        assert_eq!(sum("prompt"), 14 * sum("calls"));
    }

    #[test]
    fn build_metrics_threads_the_diff_scope_changed_file_count() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ContextPackage {
            all_files: vec!["a.py".to_string(), "b.py".to_string()],
            diff_scope_active: true,
            changed_files: BTreeMap::from([("a.py".to_string(), BTreeSet::from([1]))]),
            ..Default::default()
        };
        let manifest = TaskManifest {
            chunks: Vec::new(),
            rationale: String::new(),
            unreachable_files: Vec::new(),
        };
        let metrics = build_metrics(
            &ctx,
            &manifest,
            dir.path(),
            "demo",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:10Z",
            0,
            0,
            0,
            0,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
            None,
        );
        assert_eq!(metrics.changed_files_count, 1);
        assert!(metrics.diff_scope_active);
    }

    #[test]
    fn build_metrics_reports_diff_scope_active_with_a_zero_changed_file_count() {
        // A rename-only PR. `changed_files_count: 0` alone is
        // indistinguishable from a full-repo scan, which is exactly how
        // the report's scope line used to go missing.
        let dir = tempfile::tempdir().unwrap();
        let ctx = ContextPackage {
            all_files: vec!["a.py".to_string(), "b.py".to_string()],
            diff_scope_active: true,
            ..Default::default()
        };
        let manifest = TaskManifest {
            chunks: Vec::new(),
            rationale: String::new(),
            unreachable_files: Vec::new(),
        };
        let metrics = build_metrics(
            &ctx,
            &manifest,
            dir.path(),
            "demo",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:10Z",
            0,
            0,
            0,
            0,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
            None,
        );
        assert_eq!(metrics.changed_files_count, 0);
        assert!(metrics.diff_scope_active);
    }

    #[test]
    fn build_metrics_changed_file_count_is_zero_without_diff_scope() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ContextPackage {
            all_files: vec!["a.py".to_string()],
            ..Default::default()
        };
        let manifest = TaskManifest {
            chunks: Vec::new(),
            rationale: String::new(),
            unreachable_files: Vec::new(),
        };
        let metrics = build_metrics(
            &ctx,
            &manifest,
            dir.path(),
            "demo",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:10Z",
            0,
            0,
            0,
            0,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
            None,
        );
        assert_eq!(metrics.changed_files_count, 0);
        assert!(!metrics.diff_scope_active);
    }

    #[test]
    fn build_metrics_treats_an_unreadable_file_as_zero_loc() {
        let dir = tempfile::tempdir().unwrap();
        // Deliberately no file written at this path — read fails, LOC == 0.
        let ctx = ContextPackage {
            all_files: vec!["missing.py".to_string()],
            ..Default::default()
        };
        let manifest = TaskManifest {
            chunks: Vec::new(),
            rationale: String::new(),
            unreachable_files: Vec::new(),
        };
        let metrics = build_metrics(
            &ctx,
            &manifest,
            dir.path(),
            "demo",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z",
            0,
            0,
            0,
            0,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
            None,
        );
        assert_eq!(metrics.loc_in_scope_by_language.get("python"), Some(&0));
        assert_eq!(metrics.chunks_total, 0);
        assert_eq!(metrics.chunks_failed, 0);
        // No chunk failures and an empty tokens map: no call ever
        // reported usage, so every token field is `None` ("unavailable")
        // rather than a `Some(0)` that would read as a genuinely free
        // scan — Python's `tok_avail` gate (`util/metrics.py:93`).
        // `errors_by_stage` stays genuinely empty (s4's own
        // chunks_failed==0 never gets inserted).
        assert_eq!(metrics.prompt_tokens, None);
        assert_eq!(metrics.completion_tokens, None);
        assert_eq!(metrics.total_tokens, None);
        assert_eq!(metrics.tokens_by_phase, None);
        assert!(metrics.errors_by_stage.is_empty());
    }

    #[test]
    fn build_metrics_treats_a_path_that_escapes_the_repo_root_as_zero_loc() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ContextPackage {
            all_files: vec!["../outside.py".to_string()],
            ..Default::default()
        };
        let manifest = TaskManifest {
            chunks: Vec::new(),
            rationale: String::new(),
            unreachable_files: Vec::new(),
        };
        let metrics = build_metrics(
            &ctx,
            &manifest,
            dir.path(),
            "demo",
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z",
            0,
            0,
            0,
            0,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Vec::new(),
            BTreeMap::new(),
            None,
        );
        assert_eq!(metrics.loc_in_scope_by_language.get("python"), Some(&0));
    }

    use bc_model::{Finding, RankedFinding as RF, Severity, VulnClass};
    use bc_sandbox_tools::SandboxTools;

    fn s10_finding(cvss: Option<f64>) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "chunk-01".to_string(),
            file: "app.py".to_string(),
            line_start: 1,
            line_end: 2,
            vuln_class: VulnClass::Injection,
            cwe: Some("CWE-89".to_string()),
            title: "SQLi".to_string(),
            impact: String::new(),
            description: "desc".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "x = 1".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.9,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: cvss,
            cvss_rating: None,
            verifier_reasoning: String::new(),
            vsvs_vector: None,
            vsvs_score: None,
            vsvs_rating: None,
            offensive_priority: None,
            offensive_reason: String::new(),
            related_cwes: Vec::new(),
        }
    }

    fn s10_ranked(cvss: Option<f64>) -> RF {
        RF {
            finding: s10_finding(cvss),
            severity: Severity::High,
            exploitability_notes: String::new(),
        }
    }

    fn s10_report(repo: &Path, findings: Vec<RF>, git_sha: Option<String>) -> FinalReport {
        FinalReport {
            provider_ledger: Default::default(),
            repo_root: repo.display().to_string(),
            repo_name: None,
            git_sha,
            findings,
            chains: Vec::new(),
            dropped: Vec::new(),
            raw_findings_count: 0,
            metrics: None,
            threat_model: None,
            app_profile: None,
            summary: String::new(),
            degraded: false,
            degraded_reason: String::new(),
            unreachable_files: Vec::new(),
        }
    }

    fn s10_verdict_json() -> String {
        json!({
            "finding_index": 1, "verdict": "Fixed",
            "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
            "root_cause": "x", "changes": [], "remaining_risks": [],
            "recommendations": [], "summary": "s",
        })
        .to_string()
    }

    struct S10Client;
    #[async_trait]
    impl LlmClient for S10Client {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(s10_verdict_json())],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    struct FailingClient;
    #[async_trait]
    impl LlmClient for FailingClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Err(LlmError::ConnectionError {
                message: "provider down".to_string(),
            })
        }
    }

    fn s10_config() -> RemediateConfig {
        let mut step10 = bc_stage_s10::Step10Config::new("test-model");
        step10.max_transient_retries = 0;
        step10.retry_backoff_base = std::time::Duration::ZERO;
        RemediateConfig {
            step10,
            top: None,
            top_default: None,
            force: false,
            resume: false,
            isolated: false,
        }
    }

    /// Shared by every test below that expects a
    /// `RemediationOutcome::Processed` — a single named function (rather
    /// than each call site writing its own `match`-with-panic-fallback)
    /// so there's exactly one compiled instance.
    fn expect_processed(o: &bc_stage_s10::RemediationOutcome) -> &bc_stage_s10::RemediationRecord {
        match o {
            bc_stage_s10::RemediationOutcome::Processed(r) => r,
            other => panic!("expected Processed, got {other:?}"),
        }
    }

    /// The `Failed`-outcome mirror of [`expect_processed`], same rationale.
    fn expect_failed(o: &bc_stage_s10::RemediationOutcome) -> &str {
        match o {
            bc_stage_s10::RemediationOutcome::Failed { error, .. } => error,
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    #[should_panic(expected = "expected Failed")]
    fn expect_failed_panics_on_a_processed_outcome() {
        expect_failed(&bc_stage_s10::RemediationOutcome::Processed(Box::new(
            bc_stage_s10::RemediationRecord {
                finding_index: 1,
                finding_id: "x".to_string(),
                verdict: bc_stage_s10::RemediationVerdict {
                    finding_index: 1,
                    verdict: bc_stage_s10::Verdict::Fixed,
                    gates: bc_stage_s10::Gates::default(),
                    root_cause: String::new(),
                    changes: Vec::new(),
                    remaining_risks: Vec::new(),
                    recommendations: Vec::new(),
                    summary: String::new(),
                },
                policy_action: None,
                policy_reason: None,
                final_verdict: None,
                policy_reverted: Vec::new(),
                policy_matched_globs: Vec::new(),
                diff: None,
            },
        )));
    }

    #[test]
    #[should_panic(expected = "expected Processed")]
    fn expect_processed_panics_on_a_failed_outcome() {
        expect_processed(&bc_stage_s10::RemediationOutcome::Failed {
            finding_index: 1,
            error: "x".to_string(),
        });
    }

    #[tokio::test]
    async fn remediate_processes_every_finding_when_the_repo_is_not_a_git_target() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));

        let outcome = remediate(
            llm,
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            None,
            None,
        )
        .await;

        assert!(outcome.refused.is_none());
        assert_eq!(outcome.outcomes.len(), 1);
        let _ = expect_processed(&outcome.outcomes[0]);
        // No `validate` config was passed — S11 never ran at all.
        assert!(outcome.validations.is_empty());
    }

    #[tokio::test]
    async fn remediate_announces_a_dry_run_differently_from_fix_mode() {
        // The pre-remediation stderr warning is the one chance a user has
        // to notice that `--remediate` is about to write to their working
        // tree — so it must not claim files are being edited when
        // `dry_run` means every change is rolled back again.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let mut config = s10_config();
        config.step10.dry_run = true;

        let outcome = remediate(llm, tools, dir.path(), &report, &config, None, None, None).await;

        assert!(outcome.refused.is_none());
        assert_eq!(outcome.outcomes.len(), 1);
    }

    #[tokio::test]
    async fn remediate_announces_an_isolated_run_without_the_fix_mode_warning() {
        // The FIX MODE warning says "about to EDIT source files in
        // <path>". In worktree-isolated mode nothing under the user's
        // `--repo` is written at all, so printing it would be false — and
        // a warning that fires on runs it does not apply to is a warning
        // nobody reads on the run where it does.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let mut config = s10_config();
        config.isolated = true;

        let outcome = remediate(llm, tools, dir.path(), &report, &config, None, None, None).await;

        assert!(outcome.refused.is_none());
        assert_eq!(outcome.outcomes.len(), 1);
    }

    #[tokio::test]
    async fn remediate_of_a_report_with_no_findings_warns_about_nothing() {
        // Nothing is going to be edited, so the "about to EDIT source
        // files" warning must not fire — an unconditional one would cry
        // wolf on every clean scan run with `--remediate`.
        let dir = tempfile::tempdir().unwrap();
        let report = s10_report(dir.path(), Vec::new(), None);
        let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));

        let outcome = remediate(
            llm,
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            None,
            None,
        )
        .await;

        assert!(outcome.refused.is_none());
        assert!(outcome.outcomes.is_empty());
    }

    /// Answers BOTH S10's remediation system prompt (a real `Write` tool
    /// call on the first turn, then a `Fixed` verdict with a non-empty
    /// `changes` list on the second, so `record.diff` ends up `Some(_)`
    /// and S11 actually has something to validate) and S11's two persona
    /// system prompts (an immediate all-pass gate JSON, no tool call
    /// needed) — routed by system-prompt substring, same precedent as
    /// this file's own `S10Client`/`route`.
    struct S10AndS11Client {
        remediate_turn: Mutex<u32>,
    }

    impl S10AndS11Client {
        fn new() -> Self {
            S10AndS11Client {
                remediate_turn: Mutex::new(0),
            }
        }
    }

    fn s11_all_pass_gates_json() -> String {
        json!({
            "gates": [
                {"gate_name": "root_cause", "status": "pass", "summary": "ok"},
                {"gate_name": "instance_coverage", "status": "pass", "summary": "ok"},
                {"gate_name": "no_new_vulnerabilities", "status": "pass", "summary": "ok"},
                {"gate_name": "security_best_practices", "status": "pass", "summary": "ok"},
            ]
        })
        .to_string()
    }

    #[async_trait]
    impl LlmClient for S10AndS11Client {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let system = request.system.as_deref().unwrap_or("");
            if system.contains("REMEDIATION agent") {
                let mut turn = self.remediate_turn.lock().unwrap();
                *turn += 1;
                if *turn == 1 {
                    return Ok(ChatResponse {
                        content: vec![ContentBlock::ToolUse {
                            id: "1".to_string(),
                            name: "Write".to_string(),
                            input: json!({"path": "app.py", "content": "print('fixed')\n"}),
                        }],
                        stop_reason: StopReason::ToolUse,
                        usage: Usage::default(),
                    });
                }
                let verdict = json!({
                    "finding_index": 1, "verdict": "Fixed",
                    "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
                    "root_cause": "x",
                    "changes": [{"file": "app.py", "summary": "fixed it"}],
                    "remaining_risks": [], "recommendations": [], "summary": "s",
                })
                .to_string();
                return Ok(ChatResponse {
                    content: vec![ContentBlock::Text(verdict)],
                    stop_reason: StopReason::EndTurn,
                    usage: Usage::default(),
                });
            }
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(s11_all_pass_gates_json())],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    /// Same remediation behavior as [`S10AndS11Client`], but S11 fails
    /// every gate, so the fix is graded `Not Fixed` — the shape the
    /// post-validation rollback exists for.
    struct S10SucceedsS11GradesNotFixedClient {
        remediate_turn: Mutex<u32>,
    }

    #[async_trait]
    impl LlmClient for S10SucceedsS11GradesNotFixedClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let system = request.system.as_deref().unwrap_or("");
            if system.contains("REMEDIATION agent") {
                let mut turn = self.remediate_turn.lock().unwrap();
                *turn += 1;
                if *turn == 1 {
                    return Ok(ChatResponse {
                        content: vec![ContentBlock::ToolUse {
                            id: "1".to_string(),
                            name: "Write".to_string(),
                            input: json!({"path": "app.py", "content": "print('bad fix')\n"}),
                        }],
                        stop_reason: StopReason::ToolUse,
                        usage: Usage::default(),
                    });
                }
                let verdict = json!({
                    "finding_index": 1, "verdict": "Fixed",
                    "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
                    "root_cause": "x",
                    "changes": [{"file": "app.py", "summary": "fixed it"}],
                    "remaining_risks": [], "recommendations": [], "summary": "s",
                })
                .to_string();
                return Ok(ChatResponse {
                    content: vec![ContentBlock::Text(verdict)],
                    stop_reason: StopReason::EndTurn,
                    usage: Usage::default(),
                });
            }
            let failed = json!({
                "gates": [
                    {"gate_name": "root_cause", "status": "fail", "summary": "not addressed"},
                    {"gate_name": "instance_coverage", "status": "fail", "summary": "missed"},
                    {"gate_name": "no_new_vulnerabilities", "status": "fail", "summary": "worse"},
                    {"gate_name": "security_best_practices", "status": "fail", "summary": "no"},
                ]
            })
            .to_string();
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(failed)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    #[tokio::test]
    async fn remediate_rolls_a_failed_validation_back_end_to_end_without_git() {
        // The whole Item-1 path in one test, on a NON-git tempdir: S10
        // applies a fix, S11 grades it `Not Fixed`, and the file goes back
        // byte-for-byte with no `git` anywhere. Before the per-finding
        // baseline was carried out of S10, this could only print
        // `[s11] WARNING: ... is not a git repository ... the patch is
        // still applied` and leave the bad fix on disk, which is exactly
        // what the old distroless container did in the field.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        assert!(!is_git_worktree(dir.path()));
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let llm: Arc<dyn LlmClient> = Arc::new(S10SucceedsS11GradesNotFixedClient {
            remediate_turn: Mutex::new(0),
        });
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
        let step11 = s11_config();

        let outcome = remediate(
            llm,
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            None,
            Some(ValidateConfig {
                step11: &step11,
                tools: read_only_tools.as_ref(),
            }),
        )
        .await;

        assert_eq!(
            outcome.validations[0].as_ref().map(|v| v.fix_status),
            Some(bc_validation_scoring::FixVerdict::NotFixed)
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
            "print(1)\n"
        );
        let record = expect_processed(&outcome.outcomes[0]);
        assert!(bc_stage_s10::was_reverted(record));
        // The contract `--out-remediation-json` / `--post-fixes-from`
        // depend on: a record with no diff yields no fix suggestion, so a
        // patch that is no longer on disk is never posted to a PR.
        assert_eq!(record.diff, None);
    }

    /// `bc_diffcapture::is_git_worktree` is not reachable from this crate
    /// (it depends on `bc-stage-s10`, not `bc-diffcapture`), so the
    /// "genuinely not a git repo" precondition is asserted by asking git
    /// itself — a tempdir that merely lacks a `.git` entry could still sit
    /// inside someone's checkout, which would make the test prove nothing.
    fn is_git_worktree(root: &Path) -> bool {
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "--is-inside-work-tree"])
            .output()
            .is_ok_and(|out| out.status.success())
    }

    /// Same remediation behavior as [`S10AndS11Client`], but the S11
    /// validation call always errors — for proving a genuine validation
    /// failure is counted/surfaced rather than silently indistinguishable
    /// from "not selected for validation".
    struct S10SucceedsS11FailsClient {
        remediate_turn: Mutex<u32>,
    }

    impl S10SucceedsS11FailsClient {
        fn new() -> Self {
            S10SucceedsS11FailsClient {
                remediate_turn: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl LlmClient for S10SucceedsS11FailsClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let system = request.system.as_deref().unwrap_or("");
            if system.contains("REMEDIATION agent") {
                let mut turn = self.remediate_turn.lock().unwrap();
                *turn += 1;
                if *turn == 1 {
                    return Ok(ChatResponse {
                        content: vec![ContentBlock::ToolUse {
                            id: "1".to_string(),
                            name: "Write".to_string(),
                            input: json!({"path": "app.py", "content": "print('fixed')\n"}),
                        }],
                        stop_reason: StopReason::ToolUse,
                        usage: Usage::default(),
                    });
                }
                let verdict = json!({
                    "finding_index": 1, "verdict": "Fixed",
                    "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
                    "root_cause": "x",
                    "changes": [{"file": "app.py", "summary": "fixed it"}],
                    "remaining_risks": [], "recommendations": [], "summary": "s",
                })
                .to_string();
                return Ok(ChatResponse {
                    content: vec![ContentBlock::Text(verdict)],
                    stop_reason: StopReason::EndTurn,
                    usage: Usage::default(),
                });
            }
            Err(LlmError::ConnectionError {
                message: "s11 down".to_string(),
            })
        }
    }

    fn s11_config() -> bc_stage_s11::Step11Config {
        let mut cfg = bc_stage_s11::Step11Config::new("test-model");
        cfg.max_transient_retries = 0;
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        cfg
    }

    /// Answers S10's remediation prompt for ANY number of findings (unlike
    /// `S10AndS11Client`, which only tracks a single global turn counter
    /// and so only works for exactly one finding): "already wrote?" is
    /// read straight off THIS finding's own message history (a fresh
    /// `run_agentic` session per finding, so a `ToolResult` block only
    /// ever appears once this finding's own Write has round-tripped —
    /// no shared state needed to tell findings apart). Every Write
    /// targets `app.py` (matching `s10_finding`'s own hardcoded `file`,
    /// which is what `remediate_finding`'s pre-agent snapshot is scoped
    /// to) with unique content per write (`write_count`) so each
    /// finding's own before/after diff is genuinely non-empty even
    /// though they share a path. Also answers both S11 persona prompts
    /// with an all-pass gate JSON.
    struct MultiFindingClient {
        write_count: Mutex<u32>,
    }

    impl MultiFindingClient {
        fn new() -> Self {
            MultiFindingClient {
                write_count: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl LlmClient for MultiFindingClient {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let system = request.system.as_deref().unwrap_or("");
            if system.contains("REMEDIATION agent") {
                let already_wrote = request.messages.iter().any(|m| {
                    m.content
                        .iter()
                        .any(|c| matches!(c, ContentBlock::ToolResult { .. }))
                });
                if !already_wrote {
                    let mut n = self.write_count.lock().unwrap();
                    *n += 1;
                    return Ok(ChatResponse {
                        content: vec![ContentBlock::ToolUse {
                            id: "1".to_string(),
                            name: "Write".to_string(),
                            input: json!({
                                "path": "app.py",
                                "content": format!("print({n})\n"),
                            }),
                        }],
                        stop_reason: StopReason::ToolUse,
                        usage: Usage::default(),
                    });
                }
                let verdict = json!({
                    "finding_index": 1, "verdict": "Fixed",
                    "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
                    "root_cause": "x",
                    "changes": [{"file": "app.py", "summary": "fixed it"}],
                    "remaining_risks": [], "recommendations": [], "summary": "s",
                })
                .to_string();
                return Ok(ChatResponse {
                    content: vec![ContentBlock::Text(verdict)],
                    stop_reason: StopReason::EndTurn,
                    usage: Usage::default(),
                });
            }
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(s11_all_pass_gates_json())],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    #[tokio::test]
    async fn remediate_with_validation_enabled_caps_to_max_findings_by_cvss() {
        let dir = tempfile::tempdir().unwrap();
        let report = s10_report(
            dir.path(),
            vec![
                s10_ranked(Some(1.0)),
                s10_ranked(Some(9.0)),
                s10_ranked(Some(5.0)),
            ],
            None,
        );
        let llm: Arc<dyn LlmClient> = Arc::new(MultiFindingClient::new());
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
        let mut step11 = s11_config();
        step11.max_findings = Some(2);

        let outcome = remediate(
            llm,
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            None,
            Some(ValidateConfig {
                step11: &step11,
                tools: read_only_tools.as_ref(),
            }),
        )
        .await;

        assert_eq!(outcome.outcomes.len(), 3);
        for o in &outcome.outcomes {
            assert!(expect_processed(o).diff.is_some());
        }
        assert_eq!(outcome.validations.len(), 3);
        // Lowest CVSS (1.0, original position 0) is validatable but
        // capped out — the two higher-CVSS findings (9.0, 5.0) win.
        assert!(outcome.validations[0].is_none());
        assert!(outcome.validations[1].is_some());
        assert!(outcome.validations[2].is_some());
    }

    #[tokio::test]
    async fn remediate_with_validation_enabled_and_no_cap_validates_every_validatable_finding() {
        let dir = tempfile::tempdir().unwrap();
        let report = s10_report(
            dir.path(),
            vec![s10_ranked(Some(1.0)), s10_ranked(Some(9.0))],
            None,
        );
        let llm: Arc<dyn LlmClient> = Arc::new(MultiFindingClient::new());
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
        let mut step11 = s11_config();
        step11.max_findings = None;

        let outcome = remediate(
            llm,
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            None,
            Some(ValidateConfig {
                step11: &step11,
                tools: read_only_tools.as_ref(),
            }),
        )
        .await;

        assert_eq!(outcome.validations.len(), 2);
        assert!(outcome.validations[0].is_some());
        assert!(outcome.validations[1].is_some());
    }

    #[tokio::test]
    async fn remediate_with_validation_enabled_caps_falls_back_to_the_severity_band_when_a_finding_has_no_numeric_cvss_score(
    ) {
        let dir = tempfile::tempdir().unwrap();
        // s10_ranked always sets severity: High -> band_score 7.0, so the
        // no-CVSS finding (0) loses the cap comparison to the explicit
        // 9.0 finding (1) — proving the severity-band fallback path in
        // `select_top_by_cvss`'s `severity_of` closure actually ran, not
        // just that a score was compared.
        let report = s10_report(
            dir.path(),
            vec![s10_ranked(None), s10_ranked(Some(9.0))],
            None,
        );
        let llm: Arc<dyn LlmClient> = Arc::new(MultiFindingClient::new());
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
        let mut step11 = s11_config();
        step11.max_findings = Some(1);

        let outcome = remediate(
            llm,
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            None,
            Some(ValidateConfig {
                step11: &step11,
                tools: read_only_tools.as_ref(),
            }),
        )
        .await;

        assert_eq!(outcome.validations.len(), 2);
        assert!(outcome.validations[0].is_none());
        assert!(outcome.validations[1].is_some());
    }

    #[test]
    fn redact_remediate_outcome_scrubs_every_string_a_remediation_carries() {
        const PAN: &str = "4111111111111111";
        let record = bc_stage_s10::RemediationRecord {
            finding_index: 1,
            finding_id: "abc123".to_string(),
            verdict: bc_stage_s10::RemediationVerdict {
                finding_index: 1,
                verdict: bc_stage_s10::Verdict::Fixed,
                gates: bc_stage_s10::Gates::default(),
                root_cause: format!("hardcoded secret {PAN} removed"),
                changes: vec![bc_stage_s10::Change {
                    file: "app.py".to_string(),
                    summary: format!("replaced {PAN} with an env var"),
                }],
                remaining_risks: vec![format!("audit log may still show {PAN}")],
                recommendations: vec![format!("rotate {PAN}")],
                summary: format!("fixed; old value was {PAN}"),
            },
            policy_action: None,
            policy_reason: Some(format!("matched deny rule near {PAN}")),
            final_verdict: None,
            policy_reverted: Vec::new(),
            policy_matched_globs: Vec::new(),
            diff: Some(format!("-KEY = \"{PAN}\"\n+KEY = os.environ[\"KEY\"]\n")),
        };
        let outcome = bc_orchestrator_remediate_outcome_fixture(record, PAN);

        let redacted = redact_remediate_outcome(outcome);

        let record = expect_processed(&redacted.outcomes[0]);
        let record_json = serde_json::to_string(record).unwrap();
        assert!(!record_json.contains(PAN), "record still contains PAN");

        assert!(!expect_failed(&redacted.outcomes[1]).contains(PAN));

        let score = redacted.validations[0].as_ref().unwrap();
        assert!(!score.justification.contains(PAN));
        assert!(!score.gate_results[0].summary.contains(PAN));
        assert!(!score.gate_results[0].details.contains(PAN));
        assert!(!score.gate_results[0].evidence[0].snippet.contains(PAN));
    }

    fn bc_orchestrator_remediate_outcome_fixture(
        record: bc_stage_s10::RemediationRecord,
        pan: &str,
    ) -> RemediateOutcome {
        RemediateOutcome {
            refused: None,
            outcomes: vec![
                bc_stage_s10::RemediationOutcome::Processed(Box::new(record)),
                bc_stage_s10::RemediationOutcome::Failed {
                    finding_index: 2,
                    error: format!("tool output leaked {pan}"),
                },
            ],
            validations: vec![Some(bc_validation_scoring::ValidationScore {
                raw_score: 1.0,
                fix_status: bc_validation_scoring::FixVerdict::Fixed,
                justification: format!("confirmed fix; saw {pan} in the old diff"),
                gate_results: vec![bc_validation_scoring::GateResult {
                    gate_name: bc_validation_scoring::GateName::RootCause,
                    status: bc_validation_scoring::GateStatus::Pass,
                    summary: format!("root cause addressed, old value {pan}"),
                    details: format!("full detail mentioning {pan}"),
                    evidence: vec![bc_validation_scoring::Evidence {
                        file: "app.py".to_string(),
                        line: Some(10),
                        snippet: format!("KEY = \"{pan}\""),
                    }],
                    confidence: Some(bc_validation_scoring::SynthesisConfidence::High),
                }],
                has_critical_failure: false,
            })],
            validation_failures: 0,
        }
    }

    #[tokio::test]
    async fn remediate_with_validation_enabled_populates_the_validations_vector() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let llm: Arc<dyn LlmClient> = Arc::new(S10AndS11Client::new());
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
        let step11 = s11_config();

        let outcome = remediate(
            llm,
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            None,
            Some(ValidateConfig {
                step11: &step11,
                tools: read_only_tools.as_ref(),
            }),
        )
        .await;

        assert_eq!(outcome.outcomes.len(), 1);
        let record = expect_processed(&outcome.outcomes[0]);
        assert!(record.diff.is_some());
        assert_eq!(outcome.validations.len(), 1);
        let score = outcome.validations[0]
            .as_ref()
            .expect("a diffed Processed finding should have been validated");
        assert_eq!(score.fix_status, bc_validation_scoring::FixVerdict::Fixed);
    }

    #[tokio::test]
    async fn remediate_counts_and_surfaces_a_genuine_validation_error() {
        // Regression: a validation attempt that genuinely errors (an
        // `LlmError`, not "wasn't selected") must not be silently
        // indistinguishable from a finding that was never validated at
        // all — it shows up as `None` in `validations` either way, but
        // `validation_failures` must count it.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let llm: Arc<dyn LlmClient> = Arc::new(S10SucceedsS11FailsClient::new());
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
        let step11 = s11_config();

        let outcome = remediate(
            llm,
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            None,
            Some(ValidateConfig {
                step11: &step11,
                tools: read_only_tools.as_ref(),
            }),
        )
        .await;

        let record = expect_processed(&outcome.outcomes[0]);
        assert!(record.diff.is_some());
        assert_eq!(outcome.validations, vec![None]);
        assert_eq!(outcome.validation_failures, 1);
    }

    #[tokio::test]
    async fn remediate_with_validation_enabled_skips_a_failed_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let llm: Arc<dyn LlmClient> = Arc::new(FailingClient);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
        let step11 = s11_config();

        let outcome = remediate(
            llm,
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            None,
            Some(ValidateConfig {
                step11: &step11,
                tools: read_only_tools.as_ref(),
            }),
        )
        .await;

        assert_eq!(outcome.outcomes.len(), 1);
        assert!(matches!(
            outcome.outcomes[0],
            bc_stage_s10::RemediationOutcome::Failed { .. }
        ));
        assert_eq!(outcome.validations, vec![None]);
    }

    #[tokio::test]
    async fn remediate_with_validation_enabled_skips_a_processed_finding_with_no_diff() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        // `S10Client`'s canned verdict has an empty `changes` list, so
        // remediation succeeds but leaves nothing for S11 to validate.
        let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let read_only_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new(dir.path()));
        let step11 = s11_config();

        let outcome = remediate(
            llm,
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            None,
            Some(ValidateConfig {
                step11: &step11,
                tools: read_only_tools.as_ref(),
            }),
        )
        .await;

        let record = expect_processed(&outcome.outcomes[0]);
        assert!(record.diff.is_none());
        assert_eq!(outcome.validations, vec![None]);
    }

    #[tokio::test]
    async fn remediate_refuses_when_head_has_moved_since_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["init", "-q"])
            .output()
            .unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["add", "-A"])
            .output()
            .unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args([
                "-c",
                "user.email=test@test.com",
                "-c",
                "user.name=test",
                "commit",
                "-q",
                "-m",
                "x",
            ])
            .output()
            .unwrap();
        let report = s10_report(
            dir.path(),
            vec![s10_ranked(Some(7.0))],
            Some("stale0000000000000000000000000000000000".to_string()),
        );
        let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));

        let outcome = remediate(
            llm,
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            None,
            None,
        )
        .await;

        assert!(outcome.refused.unwrap().contains("HEAD moved since scan"));
        assert!(outcome.outcomes.is_empty());
    }

    #[tokio::test]
    async fn remediate_force_overrides_the_git_sha_staleness_refusal() {
        let dir = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["init", "-q"])
            .output()
            .unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["add", "-A"])
            .output()
            .unwrap();
        std::process::Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args([
                "-c",
                "user.email=test@test.com",
                "-c",
                "user.name=test",
                "commit",
                "-q",
                "-m",
                "x",
            ])
            .output()
            .unwrap();
        let report = s10_report(
            dir.path(),
            vec![s10_ranked(Some(7.0))],
            Some("stale0000000000000000000000000000000000".to_string()),
        );
        let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let mut cfg = s10_config();
        cfg.force = true;

        let outcome = remediate(llm, tools, dir.path(), &report, &cfg, None, None, None).await;

        assert!(outcome.refused.is_none());
        assert_eq!(outcome.outcomes.len(), 1);
    }

    #[test]
    fn severity_str_maps_every_variant() {
        assert_eq!(severity_str(Severity::Critical), "CRITICAL");
        assert_eq!(severity_str(Severity::High), "HIGH");
        assert_eq!(severity_str(Severity::Medium), "MEDIUM");
        assert_eq!(severity_str(Severity::Low), "LOW");
        assert_eq!(severity_str(Severity::Info), "INFO");
    }

    #[tokio::test]
    async fn remediate_falls_back_to_the_severity_band_when_a_finding_has_no_numeric_cvss_score() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(None)], None);
        let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let mut cfg = s10_config();
        cfg.top = Some(bc_stage_s10::TopSpec::N(1));

        let outcome = remediate(llm, tools, dir.path(), &report, &cfg, None, None, None).await;

        assert_eq!(outcome.outcomes.len(), 1);
    }

    #[tokio::test]
    async fn remediate_selects_only_the_top_n_findings_by_cvss() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(
            dir.path(),
            vec![
                s10_ranked(Some(1.0)),
                s10_ranked(Some(9.0)),
                s10_ranked(Some(5.0)),
            ],
            None,
        );
        let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let mut cfg = s10_config();
        cfg.top = Some(bc_stage_s10::TopSpec::N(1));

        let outcome = remediate(llm, tools, dir.path(), &report, &cfg, None, None, None).await;

        assert_eq!(outcome.outcomes.len(), 1);
        // The highest-CVSS finding (9.0) is at original position 1, so its
        // 1-based finding_index is 2.
        assert_eq!(expect_processed(&outcome.outcomes[0]).finding_index, 2);
    }

    struct S10AltClient;
    #[async_trait]
    impl LlmClient for S10AltClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let verdict = json!({
                "finding_index": 1, "verdict": "Not Fixed",
                "gates": {"source": "fail", "sink": "fail", "missing_control": "fail"},
                "root_cause": "x", "changes": [], "remaining_risks": [],
                "recommendations": [], "summary": "s",
            })
            .to_string();
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(verdict)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    /// A remediation agent that actually WRITES its fix before claiming
    /// it: one `Write` turn, then the `Fixed` verdict naming the file.
    ///
    /// [`S10Client`] deliberately narrates a fix it never applies, which
    /// S10's `reconcile_verdict_with_diff` downgrades to `Needs Review`
    /// on the strength of the empty on-disk diff. That is the correct
    /// outcome for an unapplied fix, but it makes `S10Client` unusable
    /// for seeding a checkpoint that is supposed to hold a genuine
    /// `Fixed` — hence this one.
    struct S10EditingClient {
        turn: Mutex<u32>,
    }

    impl S10EditingClient {
        fn new() -> Self {
            S10EditingClient {
                turn: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl LlmClient for S10EditingClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let mut turn = self.turn.lock().unwrap();
            *turn += 1;
            if *turn == 1 {
                return Ok(ChatResponse {
                    content: vec![ContentBlock::ToolUse {
                        id: "1".to_string(),
                        name: "Write".to_string(),
                        input: json!({"path": "app.py", "content": "print('fixed')\n"}),
                    }],
                    stop_reason: StopReason::ToolUse,
                    usage: Usage::default(),
                });
            }
            let verdict = json!({
                "finding_index": 1, "verdict": "Fixed",
                "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
                "root_cause": "x",
                "changes": [{"file": "app.py", "summary": "fixed it"}],
                "remaining_risks": [], "recommendations": [], "summary": "s",
            })
            .to_string();
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(verdict)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    #[tokio::test]
    async fn remediate_with_a_checkpoint_store_saves_a_checkpoint_for_each_processed_finding() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let llm: Arc<dyn LlmClient> = Arc::new(S10Client);
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let ckpt_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = Arc::new(
            bc_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
        );

        let outcome = remediate(
            llm,
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            Some(store.clone()),
            None,
        )
        .await;

        assert_eq!(outcome.outcomes.len(), 1);
        let run_id = bc_checkpoint::run_id_for(dir.path());
        let step = bc_stage_s10::remediation_step_key(&s10_config().step10, 1, &report.findings[0]);
        assert!(store.load(&run_id, &step).is_some());
    }

    #[tokio::test]
    async fn remediate_with_resume_serves_a_cached_verdict_instead_of_the_fresh_client_response() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let ckpt_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = Arc::new(
            bc_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
        );
        let mut cfg = s10_config();
        cfg.resume = true;

        // The seeding run must leave a genuine `Fixed` in the checkpoint,
        // so its agent really writes the fix. A narrated-but-unwritten one
        // would be downgraded to `Needs Review` before it was ever stored,
        // and the resume this test is about would then have nothing worth
        // serving.
        let first_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let first = remediate(
            Arc::new(S10EditingClient::new()),
            first_tools,
            dir.path(),
            &report,
            &cfg,
            None,
            Some(store.clone()),
            None,
        )
        .await;
        assert_eq!(
            expect_processed(&first.outcomes[0]).verdict.verdict,
            bc_stage_s10::Verdict::Fixed
        );

        // Same finding, same run — a fresh client that would answer
        // differently must never be consulted; `--resume` serves the
        // cached "Fixed" verdict instead of this client's "Not Fixed".
        let second_tools: Arc<dyn ToolExecutor> =
            Arc::new(SandboxTools::new_with_write(dir.path()));
        let second = remediate(
            Arc::new(S10AltClient),
            second_tools,
            dir.path(),
            &report,
            &cfg,
            None,
            Some(store),
            None,
        )
        .await;

        assert_eq!(
            expect_processed(&second.outcomes[0]).verdict.verdict,
            bc_stage_s10::Verdict::Fixed
        );
    }

    #[tokio::test]
    async fn remediate_without_resume_ignores_an_existing_matching_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let ckpt_dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = Arc::new(
            bc_checkpoint::SqliteCheckpointStore::new(ckpt_dir.path().join("state.db")).unwrap(),
        );
        let mut cfg = s10_config();
        cfg.resume = true;

        let first_tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        remediate(
            Arc::new(S10Client),
            first_tools,
            dir.path(),
            &report,
            &cfg,
            None,
            Some(store.clone()),
            None,
        )
        .await;

        // `resume: false` this time — even though the checkpoint's
        // identity would still match, it must never be consulted; the
        // second client's fresh "Not Fixed" response is what comes back.
        cfg.resume = false;
        let second_tools: Arc<dyn ToolExecutor> =
            Arc::new(SandboxTools::new_with_write(dir.path()));
        let second = remediate(
            Arc::new(S10AltClient),
            second_tools,
            dir.path(),
            &report,
            &cfg,
            None,
            Some(store),
            None,
        )
        .await;

        assert_eq!(
            expect_processed(&second.outcomes[0]).verdict.verdict,
            bc_stage_s10::Verdict::NotFixed
        );
    }

    #[tokio::test]
    async fn remediate_registers_the_run_with_a_checkpoint_store() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let ckpt_dir = tempfile::tempdir().unwrap();
        let db_path = ckpt_dir.path().join("state.db");
        let store: Arc<dyn bc_checkpoint::CheckpointStore> =
            Arc::new(bc_checkpoint::SqliteCheckpointStore::new(&db_path).unwrap());
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));

        remediate(
            Arc::new(S10Client),
            tools,
            dir.path(),
            &report,
            &s10_config(),
            None,
            Some(store),
            None,
        )
        .await;

        // A separate connection to the same file — proves `register_run`
        // actually persisted a `runs` row, not just that `remediate`
        // itself still behaves as before.
        let inspector = bc_checkpoint::SqliteCheckpointStore::new(&db_path).unwrap();
        let report = inspector.prune(100, 5, true).unwrap();
        assert_eq!(report.kept, 1);
        assert!(report.deleted.is_empty());
    }

    // Captures exactly what `remediate` passed to `register_run`, so a
    // test can assert on the `app_id` argument without needing a second
    // SQLite connection into `SqliteCheckpointStore`'s own private
    // schema. `save`/`load` are trivial (always-miss) implementations
    // exercised via `resume: true` below — `bc_stage_s10::run_remediation`
    // only calls `load` on that path.
    #[derive(Default)]
    struct SpyCheckpointStore {
        registered_app_id: Mutex<Option<Option<String>>>,
    }

    impl bc_checkpoint::CheckpointStore for SpyCheckpointStore {
        fn save(
            &self,
            _run_id: &str,
            _step: &str,
            _payload: &[u8],
        ) -> Result<(), bc_checkpoint::CheckpointError> {
            Ok(())
        }

        fn load(&self, _run_id: &str, _step: &str) -> Option<Vec<u8>> {
            None
        }

        fn register_run(
            &self,
            _run_id: &str,
            _repo_root: &str,
            _repo_name: Option<&str>,
            app_id: Option<&str>,
        ) {
            *self.registered_app_id.lock().unwrap() = Some(app_id.map(str::to_string));
        }
    }

    #[tokio::test]
    async fn remediate_registers_the_report_s_application_id_when_an_app_profile_is_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let mut report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        report.app_profile = Some(AppProfile {
            application_id: "42".to_string(),
            name: String::new(),
            externally_facing: false,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: String::new(),
        });
        let spy = Arc::new(SpyCheckpointStore::default());
        let store: Arc<dyn bc_checkpoint::CheckpointStore> = spy.clone();
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        let mut config = s10_config();
        config.resume = true;

        remediate(
            Arc::new(S10Client),
            tools,
            dir.path(),
            &report,
            &config,
            None,
            Some(store),
            None,
        )
        .await;

        assert_eq!(
            *spy.registered_app_id.lock().unwrap(),
            Some(Some("42".to_string()))
        );
    }

    #[tokio::test]
    async fn remediate_without_resume_clears_stale_checkpoints_via_reset_run() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let ckpt_dir = tempfile::tempdir().unwrap();
        let db_path = ckpt_dir.path().join("state.db");
        let store: Arc<dyn bc_checkpoint::CheckpointStore> =
            Arc::new(bc_checkpoint::SqliteCheckpointStore::new(&db_path).unwrap());
        let run_id = bc_checkpoint::run_id_for(dir.path());
        // A checkpoint under a key no real remediation of THIS report
        // would ever write — simulating a leftover row from an earlier,
        // now-irrelevant finding set (e.g. `remediate_99`).
        store.save(&run_id, "remediate_99", b"stale").unwrap();

        let mut cfg = s10_config();
        cfg.resume = false;
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        remediate(
            Arc::new(S10Client),
            tools,
            dir.path(),
            &report,
            &cfg,
            None,
            Some(store.clone()),
            None,
        )
        .await;

        assert_eq!(store.load(&run_id, "remediate_99"), None);
    }

    #[tokio::test]
    async fn remediate_with_resume_does_not_clear_stale_checkpoints() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print(1)\n").unwrap();
        let report = s10_report(dir.path(), vec![s10_ranked(Some(7.0))], None);
        let ckpt_dir = tempfile::tempdir().unwrap();
        let db_path = ckpt_dir.path().join("state.db");
        let store: Arc<dyn bc_checkpoint::CheckpointStore> =
            Arc::new(bc_checkpoint::SqliteCheckpointStore::new(&db_path).unwrap());
        let run_id = bc_checkpoint::run_id_for(dir.path());
        // A stage checkpoint, not a `remediate_*` row: S10 itself prunes
        // `remediate_*` rows no live finding claims (engine-keyed steps,
        // see `bc_stage_s10::remediation_step_key`), which is a different
        // thing from the whole-run reset this test pins.
        store.save(&run_id, "s1", b"stale").unwrap();

        let mut cfg = s10_config();
        cfg.resume = true;
        let tools: Arc<dyn ToolExecutor> = Arc::new(SandboxTools::new_with_write(dir.path()));
        remediate(
            Arc::new(S10Client),
            tools,
            dir.path(),
            &report,
            &cfg,
            None,
            Some(store.clone()),
            None,
        )
        .await;

        assert_eq!(store.load(&run_id, "s1"), Some(b"stale".to_vec()));
    }

    // ---- S11's post-validation rollback -------------------------------

    /// A git repo with `app.py` committed, then modified as a remediation
    /// would have modified it — the state `revert_if_validation_failed`
    /// exists to undo.
    fn patched_git_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(args)
                .output()
                .unwrap()
        };
        run(&["init", "-q"]);
        std::fs::write(dir.path().join("app.py"), "print('original')\n").unwrap();
        run(&["add", "-A"]);
        run(&[
            "-c",
            "user.email=test@test.com",
            "-c",
            "user.name=test",
            "commit",
            "-q",
            "-m",
            "x",
        ]);
        std::fs::write(dir.path().join("app.py"), "print('a bad fix')\n").unwrap();
        dir
    }

    fn validated_record(files: &[&str]) -> bc_stage_s10::RemediationRecord {
        bc_stage_s10::RemediationRecord {
            finding_index: 1,
            finding_id: "abc123".to_string(),
            verdict: bc_stage_s10::RemediationVerdict {
                finding_index: 1,
                verdict: bc_stage_s10::Verdict::Fixed,
                gates: bc_stage_s10::Gates::default(),
                root_cause: String::new(),
                changes: files
                    .iter()
                    .map(|f| bc_stage_s10::Change {
                        file: (*f).to_string(),
                        summary: "s".to_string(),
                    })
                    .collect(),
                remaining_risks: Vec::new(),
                recommendations: Vec::new(),
                summary: String::new(),
            },
            policy_action: None,
            policy_reason: None,
            final_verdict: None,
            policy_reverted: Vec::new(),
            policy_matched_globs: Vec::new(),
            diff: Some("d".to_string()),
        }
    }

    fn score_of(
        status: bc_validation_scoring::FixVerdict,
    ) -> bc_validation_scoring::ValidationScore {
        bc_validation_scoring::ValidationScore {
            raw_score: 0.0,
            fix_status: status,
            justification: String::new(),
            gate_results: Vec::new(),
            has_critical_failure: false,
        }
    }

    /// One finding's pre-remediation baseline, shaped the way
    /// `bc_stage_s10::remediate_finding_with_baseline` hands one back.
    fn baseline_of(file: &str, content: &str) -> bc_stage_s10::Baseline {
        let mut baseline = bc_stage_s10::Baseline::default();
        baseline.merge_originals([(file.to_string(), Some(content.as_bytes().to_vec()))]);
        baseline
    }

    /// Runs the post-validation rollback for a record claiming `files`,
    /// returning the record so a caller can assert on what was recorded.
    fn run_rollback(
        repo: &Path,
        files: &[&str],
        baseline: Option<&bc_stage_s10::Baseline>,
        status: bc_validation_scoring::FixVerdict,
        step10: &bc_stage_s10::Step10Config,
    ) -> bc_stage_s10::RemediationRecord {
        let mut record = validated_record(files);
        revert_if_validation_failed(
            repo,
            &mut record,
            baseline,
            &BTreeMap::new(),
            &score_of(status),
            step10,
        );
        record
    }

    #[test]
    fn a_not_fixed_validation_rolls_the_patch_back() {
        for status in [
            bc_validation_scoring::FixVerdict::NotFixed,
            bc_validation_scoring::FixVerdict::Unverifiable,
        ] {
            let dir = patched_git_repo();
            let record = run_rollback(
                dir.path(),
                &["app.py"],
                None,
                status,
                &bc_stage_s10::Step10Config::new("m"),
            );
            assert_eq!(
                std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
                "print('original')\n"
            );
            // The record has to say so too, or `--post-fixes-from` posts a
            // "Suggested fix" for a patch that is no longer on disk.
            assert!(bc_stage_s10::was_reverted(&record));
            assert_eq!(record.diff, None);
        }
    }

    #[test]
    fn a_not_fixed_validation_rolls_back_from_the_baseline_with_no_git_at_all() {
        // The field failure this closes (GitHub Actions run 34021176323,
        // the old distroless container, no `git` binary): the git-only
        // backstop could do nothing, so a fix S11 graded `Not Fixed`
        // stayed applied behind a warning. The baseline needs no VCS,
        // which still matters on any target that is not a checkout.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print('a bad fix')\n").unwrap();
        let baseline = baseline_of("app.py", "print('original')\n");
        let record = run_rollback(
            dir.path(),
            &["app.py"],
            Some(&baseline),
            bc_validation_scoring::FixVerdict::NotFixed,
            &bc_stage_s10::Step10Config::new("m"),
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
            "print('original')\n"
        );
        assert!(bc_stage_s10::was_reverted(&record));
        assert_eq!(record.diff, None);
    }

    #[test]
    fn a_baseline_rollback_restores_a_file_the_record_never_claimed() {
        // The baseline is keyed on what the agent actually TOUCHED, not on
        // its self-reported `changes[]` — a helper module it rewrote
        // without mentioning is restored too, which the git backstop (which
        // only ever looked at `changes[]`) could never do.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "bad\n").unwrap();
        std::fs::write(dir.path().join("helper.py"), "also bad\n").unwrap();
        let mut baseline = baseline_of("app.py", "good\n");
        baseline.merge_originals([("helper.py".to_string(), Some(b"also good\n".to_vec()))]);
        run_rollback(
            dir.path(),
            &["app.py"],
            Some(&baseline),
            bc_validation_scoring::FixVerdict::NotFixed,
            &bc_stage_s10::Step10Config::new("m"),
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("helper.py")).unwrap(),
            "also good\n"
        );
    }

    #[test]
    fn a_baseline_rollback_will_not_destroy_a_later_findings_kept_fix() {
        // S10 remediates every finding before S11 validates any of them, so
        // a later finding may have edited this same file and been KEPT.
        // This finding's baseline predates that edit, so restoring it would
        // delete a good fix to undo a bad one.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "finding 7's good fix\n").unwrap();
        let baseline = baseline_of("app.py", "before finding 1\n");
        let mut record = validated_record(&["app.py"]);
        let protected = BTreeMap::from([("app.py".to_string(), 7i64)]);
        revert_if_validation_failed(
            dir.path(),
            &mut record,
            Some(&baseline),
            &protected,
            &score_of(bc_validation_scoring::FixVerdict::NotFixed),
            &bc_stage_s10::Step10Config::new("m"),
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
            "finding 7's good fix\n"
        );
        // Nothing was restored, so the diff stays: the patch really is
        // still on disk and blanking it would erase the only record of it.
        assert_eq!(record.diff.as_deref(), Some("d"));
        assert!(record.verdict.summary.contains("LEFT APPLIED"));
        assert!(record.verdict.summary.contains("app.py (finding 7)"));
    }

    #[test]
    fn a_passing_validation_leaves_the_patch_alone() {
        let dir = patched_git_repo();
        for status in [
            bc_validation_scoring::FixVerdict::Fixed,
            bc_validation_scoring::FixVerdict::PartiallyFixed,
        ] {
            let baseline = baseline_of("app.py", "print('original')\n");
            let record = run_rollback(
                dir.path(),
                &["app.py"],
                Some(&baseline),
                status,
                &bc_stage_s10::Step10Config::new("m"),
            );
            assert_eq!(
                std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
                "print('a bad fix')\n"
            );
            assert!(!bc_stage_s10::was_reverted(&record));
        }
    }

    #[test]
    fn keep_unverified_opts_out_of_the_post_validation_rollback() {
        let dir = patched_git_repo();
        let mut step10 = bc_stage_s10::Step10Config::new("m");
        step10.keep_unverified = true;
        let baseline = baseline_of("app.py", "print('original')\n");
        run_rollback(
            dir.path(),
            &["app.py"],
            Some(&baseline),
            bc_validation_scoring::FixVerdict::NotFixed,
            &step10,
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
            "print('a bad fix')\n"
        );
    }

    #[test]
    fn a_record_claiming_nothing_needs_no_rollback() {
        let dir = patched_git_repo();
        let record = run_rollback(
            dir.path(),
            &[],
            None,
            bc_validation_scoring::FixVerdict::NotFixed,
            &bc_stage_s10::Step10Config::new("m"),
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
            "print('a bad fix')\n"
        );
        assert!(!bc_stage_s10::was_reverted(&record));
    }

    #[test]
    fn a_non_git_target_without_a_baseline_warns_instead_of_rolling_back() {
        // The remaining honest gap: a `--resume`d record's baseline lives
        // only in the process that first ran it, so this path really does
        // have nothing to restore from. The operator has to be told the
        // patch is still applied rather than the run pretending otherwise.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "print('a bad fix')\n").unwrap();
        let record = run_rollback(
            dir.path(),
            &["app.py"],
            None,
            bc_validation_scoring::FixVerdict::NotFixed,
            &bc_stage_s10::Step10Config::new("m"),
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("app.py")).unwrap(),
            "print('a bad fix')\n"
        );
        assert!(!bc_stage_s10::was_reverted(&record));
        assert_eq!(record.diff.as_deref(), Some("d"));
    }
}
