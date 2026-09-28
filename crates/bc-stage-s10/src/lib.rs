//! Phase 2's S10 remediation stage: the per-finding agentic loop that
//! attempts an actual code fix, gated by [`bc_policy_gate`]'s
//! deny-list-wins policy gate and playbook, ported from
//! `remediation_agent/{runner,plugin_runner/*,policy/*}.py`.
//!
//! **Deliberate scope decisions vs. the Python original** (see the
//! project's architecture notes for the full research trail):
//! - Only the in-pipeline entry point is ported (a `FinalReport` already
//!   in memory) — the Python original's standalone `vvaharness remediate`
//!   CLI re-parses a prior scan's rendered Markdown report; this port
//!   never renders-then-reparses findings, so there is no such report to
//!   re-parse and no reason to build that machinery.
//! - Strictly sequential, one finding at a time (matching the Python
//!   original) — concurrent agents with Edit/Write on the same working
//!   tree would race on file contents/git state/diff capture.
//! - `--resume` checkpoint/skip support, ported from
//!   `remediation_agent/runner.py::remediate_one`'s `_finding_identity`
//!   pattern: [`run_remediation`] accepts an optional
//!   [`bc_checkpoint::CheckpointStore`] + `run_id`. A checkpoint is only
//!   treated as "already done" when its stored [`finding_identity`] hash
//!   matches the CURRENT finding at that position — a stale/reordered
//!   checkpoint under the same position-keyed step never causes a wrong
//!   finding to be silently skipped. Saving happens whenever a store is
//!   given, regardless of `resume` (so a *later* `--resume` run has
//!   something to load); only the read/skip check is gated by `resume`,
//!   exactly matching `opts.resume`'s role in the Python original.
//!
//! **Safety gates (no Python equivalent — added here deliberately).**
//! Every `Edit`/`Write` the model emits executes immediately, mid-loop,
//! against a real working tree. The Python original left whatever landed
//! there in place no matter how the run ended: a `Not Fixed` verdict, an
//! LLM error, an exhausted turn budget and a syntactically mangled file
//! all finished with the patch still applied, and `--resume` then skipped
//! the finding because a checkpoint had been saved for it. That is the
//! "remediation broke my codebase" report. This port therefore treats the
//! agent's edits as a proposal that must earn the right to stay:
//!
//! 0. Everything the agent writes is journalled with its pre-edit bytes
//!    (`bc_sandbox_tools::WriteJournal`), so a rollback is exact and works
//!    on a non-git target and for files nobody predicted.
//! 1. The pre-existing deny-list policy post-gate.
//! 2. A tree-sitter parse gate ([`bc_repo_analysis::syntax_check`]).
//! 3. An optional operator-configured verify command.
//! 4. A diff-size / files-touched cap.
//! 5. `dry_run` rolls back unconditionally while keeping the diff.
//! 6. Anything but a clean `Fixed` verdict rolls the patch back.
//!
//! A rolled-back finding is never checkpointed, so `--resume` re-attempts
//! it rather than skipping past a fix that is not on disk. `keep_unverified`
//! restores the old leave-it-applied behavior for gate 6 for an operator
//! who wants it.
//!
//! Each finding's baseline also travels OUT of the loop
//! ([`remediate_finding_with_baseline`] -> [`RemediationRun::baselines`]),
//! so Phase 3's S11 rollback can undo a fix it grades `Not Fixed` with the
//! same byte-exact, VCS-free mechanism instead of the git-only
//! [`revert_record`] backstop, which does nothing at all on a target that
//! is not a git worktree. In memory only: it never enters a
//! [`RemediationRecord`], a checkpoint, or any output file.
//!
//! One further net-new behavior sits *before* the gates rather than among
//! them: [`Step10Config::retry_unapplied_fix`] gives the agent exactly one
//! more session when it answers `Fixed` while the write journal and the
//! computed diff both say it wrote nothing. That is the stage's most
//! common live failure, and today's (correct) downgrade leaves the finding
//! simply unfixed.

mod checkpoint;
mod prompts;
mod select;
mod verdict;
mod verify_process;
mod workflow_gate;
mod worktree_walk;

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use bc_checkpoint::CheckpointStore;
use bc_llm_agentic::{run_agentic, AgenticConfig};
use bc_llm_client::{LlmClient, LlmError, ToolExecutor};
use bc_model::RankedFinding;
use bc_policy_gate::{Decision, Playbook, RemediationGate, Strategy};
use serde::{Deserialize, Serialize};

use checkpoint::{load_cached_record, save_checkpoint};

pub use checkpoint::{
    checkpoint_done, finding_identity, remediation_step_key, REMEDIATE_STEP_PREFIX,
};
pub use select::{band_score, parse_top_spec, resolve_top, select_top_by_cvss, TopSpec};
pub use verdict::{Change, GateStatus, Gates, RemediationVerdict, Verdict};
pub use workflow_gate::UNSAFE_WORKFLOW_REFERENCE;

/// One finding's pre-remediation baseline: the on-disk bytes of exactly
/// the files its agent touched, captured before it ran.
///
/// Re-exported (rather than re-implemented, or forcing every consumer to
/// depend on `bc-diffcapture` for one type) under the name that says what
/// it MEANS here — `bc_diffcapture::Snapshot` is the general
/// pre-edit-content container; a `Baseline` is specifically "the state
/// this finding's patch should be undone to". Undoing a finding is the
/// only thing `bc-orchestrator` and `bc-interactive` ever do with one.
pub use bc_diffcapture::Snapshot as Baseline;

/// Everything one S10 run needs beyond the repo/findings themselves —
/// the model-role config plus the loop's own tunables, mirroring
/// `step_remediate`'s Python schema.
#[derive(Debug, Clone)]
pub struct Step10Config {
    pub model: String,
    pub max_turns: u32,
    pub allowed_tools: Vec<String>,
    /// `fix` mode applies edits; `report-only` describes them without
    /// touching disk.
    pub fix_mode: bool,
    /// How many times a single agentic turn retries after a retryable
    /// [`LlmError`] before giving up — forwarded to
    /// [`bc_llm_agentic::AgenticConfig`]. A Rust-only test-speed knob
    /// (no Python equivalent), same precedent as `bc-stage-s1`'s own
    /// `retry_backoff_base` field.
    pub max_transient_retries: u32,
    /// How many times a single agentic turn retries after a context-
    /// overflow by evicting oldest tool results — forwarded to
    /// [`bc_llm_agentic::AgenticConfig::max_context_shrinks`].
    pub max_context_shrinks: u32,
    pub retry_backoff_base: std::time::Duration,
    /// Sampling temperature for this stage's agentic turns. `None` (the
    /// default) sends no `temperature` at all, leaving the provider's own
    /// — which for both dialects is `1.0`, i.e. maximally divergent
    /// between two runs. Ported from the Python original's per-role
    /// `models.<role>.temperature` (`backends/llm.py::resolve`).
    pub temperature: Option<f64>,
    /// Nucleus-sampling cutoff, forwarded to
    /// [`bc_llm_client::ChatRequest::top_p`]. `None` (the default) sends
    /// none — net-new versus Python. The Anthropic dialect drops it when
    /// `temperature` is also set, as the Messages API rejects the pair.
    pub top_p: Option<f64>,
    /// Deterministic-sampling seed, forwarded to
    /// [`bc_llm_client::ChatRequest::seed`] (OpenAI dialect only). `None`
    /// (the default) sends no seed.
    pub seed: Option<u64>,
    /// Reasoning-effort tier for this stage's calls (the Python
    /// original's `models.<role>.effort`, else `--reasoning-effort`),
    /// forwarded to [`bc_llm_client::ChatRequest::reasoning_effort`].
    /// `None` (the default) sends none, leaving the provider's default.
    pub reasoning_effort: Option<bc_llm_client::ReasoningEffort>,
    /// Per-role OpenAI transport pin (Python's
    /// `models.<role>.use_responses_api`), forwarded to
    /// [`bc_llm_client::ChatRequest::openai_api`]. `None` (the default)
    /// keeps the client-wide `--openai-api` choice.
    pub openai_api: Option<bc_llm_client::OpenAiApi>,
    /// Per-turn wall-clock deadline in seconds, overriding the shared
    /// gateway client's own 300 s default. `None` (the default) keeps it.
    pub timeout_secs: Option<u64>,

    // ---- safety gates (see the crate doc comment) ----
    /// Parse every file the agent touched with tree-sitter afterwards and
    /// roll the whole patch back if any of them no longer parses. On by
    /// default: an unparseable file is unambiguous damage, and the check
    /// costs one parse per touched file with no network and no LLM.
    pub syntax_check: bool,
    /// Leave the patch applied even when the run did not end in a clean
    /// `Fixed` verdict — the pre-gate behavior of this stage, kept as an
    /// escape hatch for an operator who would rather inspect a bad patch
    /// than lose it. Off by default.
    pub keep_unverified: bool,
    /// Roll the patch back if it adds+removes more than this many lines.
    /// `0` disables the check. A remediation is a targeted fix for one
    /// finding; a 2,000-line diff is a refactor nobody asked for, and is
    /// the shape of a run that went wrong rather than one that went big.
    pub max_diff_lines: usize,
    /// Roll the patch back if it touched more than this many files. `0`
    /// disables the check.
    ///
    /// Ships at `1`: a fix that reaches into a second file is no longer a
    /// targeted change to the code the finding names, it is a design
    /// decision about how two parts of the system talk to each other, and
    /// that is a judgment a human reviewer has to make. The finding is
    /// still reported in full; only the automated patch is declined. An
    /// operator who wants the wider blast radius can raise the cap.
    pub max_files_touched: usize,
    /// Let the agent edit and run every gate as normal, then roll
    /// everything back regardless of the outcome — while KEEPING the
    /// captured diff in the record, so `--out-remediation-json` /
    /// `--post-fixes-from` still produce PR fix suggestions. "Show me the
    /// patch you would apply, without applying it."
    pub dry_run: bool,
    /// An operator-supplied shell command (build, lint, test suite) run in
    /// the repo root after the syntax and policy gates. A non-zero exit or
    /// a timeout rolls the patch back. `None` (the default) runs nothing.
    ///
    /// **This executes an arbitrary shell command.** It is only ever the
    /// operator's own configured string — never anything the model, the
    /// scanned repository, or a finding can influence — and there is no
    /// default value, so nothing runs unless someone explicitly set it.
    pub verify_command: Option<String>,
    /// Wall-clock cap for [`Self::verify_command`]; the process is killed
    /// and the patch rolled back when it expires.
    pub verify_timeout_secs: u64,
    /// Give the agent ONE more attempt when it answers `Fixed`/`Partially
    /// Fixed`, names specific files in `changes[]`, and yet left no
    /// corresponding change on disk — i.e. exactly when
    /// [`reconcile_verdict_with_diff`] is about to downgrade it.
    ///
    /// On by default because this is the single most common live failure
    /// mode this stage has: 3 of ~12 real remediations across four field
    /// runs ended with a record reading "…was fixed by changing the query
    /// to use parameterized queries. Downgraded from the agent's own
    /// reported verdict: it described a fix, but no corresponding on-disk
    /// change was found." The downgrade is correct and the gate is doing
    /// its job — but the finding is then simply left unfixed, having spent
    /// a full agentic session. The retry costs one extra session only in
    /// the case that already produced nothing, is capped at exactly one
    /// (never a loop), and changes no verdict on its own: if the second
    /// attempt also writes nothing, the same downgrade lands as before.
    pub retry_unapplied_fix: bool,
    /// The write-capable executor's copy-on-first-write ledger
    /// (`bc_sandbox_tools::SandboxTools::journal`), so the gates can roll
    /// back files nobody predicted the agent would touch — and can do so
    /// on a target with no VCS at all.
    ///
    /// `None` (the default) is a degraded but still-safe mode: on a git
    /// target the gates fall back to `git status` for "what changed" and
    /// `git checkout` for "put it back", which covers everything except a
    /// file the user already had uncommitted edits in. Supply it whenever
    /// the executor is a `SandboxTools` — it costs nothing and removes
    /// that gap.
    pub journal: Option<bc_sandbox_tools::WriteJournal>,
    /// Static target-test plan and baseline facts, supplied only by full-scan
    /// remediation. Repository-derived text is untrusted evidence.
    pub target_test_context: Option<String>,
    /// The `--diff-scope` boundary this run must not edit outside of.
    ///
    /// [`bc_model::DiffScope::inactive`] by default, which allows every
    /// file — so a full-repo run behaves exactly as it did before this
    /// field existed. When it is ACTIVE,
    /// [`remediate_finding_with_baseline`] refuses any finding whose file
    /// is not in the changed set, before the agent is called and before
    /// anything is snapshotted.
    ///
    /// **Why it lives on the config rather than in a parameter.** Every
    /// route into this stage's loop — the batch `--top` walk
    /// ([`run_remediation`]), the interactive picker
    /// (`bc_interactive::run_interactive`), prior-report remediation
    /// (`bc-cli`'s `--remediate-from`), and a direct
    /// [`remediate_finding`] call — has to build a `Step10Config` first.
    /// Putting the boundary here means a future caller that assembles its
    /// own candidate set cannot route around the gate by not passing it;
    /// the worst it can do is leave it inactive, which is the same thing
    /// as not being diff-scoped.
    ///
    /// Net-new versus Python, which has no diff scoping and no remediation
    /// scope gate at all.
    pub diff_scope: bc_model::DiffScope,
    /// The API dialect (`openai`/`anthropic`) the model is reached
    /// through, and the gateway host serving it: together with
    /// [`Self::model`] and this crate's version they make up the
    /// [`bc_checkpoint::EngineKey`] every `--resume` checkpoint is keyed
    /// by, so a record produced by one model or endpoint is never served
    /// as another's. Empty by default, which still keys by model and
    /// version; the CLI fills both from the resolved gateway settings.
    pub dialect: String,
    pub base_host: String,
    /// The run's cooperative cancellation (Ctrl-C). Once tripped,
    /// [`run_remediation`] starts no further finding and a running
    /// [`Self::verify_command`] is killed together with everything it
    /// started (the patch is then rolled back like any failed verify).
    /// `None` (the default) is a run nothing can cancel.
    pub cancel: Option<bc_pipeline_core::CancelTokenRef>,
}

impl Step10Config {
    /// Sensible defaults matching every shipped Python profile:
    /// `max_turns=40`, tools `[Read, Glob, Grep, Edit, Write]`, fix mode.
    ///
    /// The safety-gate defaults have no Python counterpart (the original
    /// has no gates at all); they are mirrored in
    /// `bc_config::step_defaults()`'s `step_remediate` section, and
    /// `step_defaults_agree_with_step10_config_new` pins the two together.
    pub fn new(model: impl Into<String>) -> Self {
        Step10Config {
            model: model.into(),
            max_turns: 40,
            allowed_tools: vec![
                "Read".to_string(),
                "Glob".to_string(),
                "Grep".to_string(),
                "Edit".to_string(),
                "Write".to_string(),
            ],
            fix_mode: true,
            max_transient_retries: 4,
            max_context_shrinks: 16,
            retry_backoff_base: std::time::Duration::from_secs(10),
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: None,
            openai_api: None,
            timeout_secs: None,
            syntax_check: true,
            keep_unverified: false,
            max_diff_lines: 200,
            max_files_touched: 1,
            dry_run: false,
            verify_command: None,
            verify_timeout_secs: 600,
            retry_unapplied_fix: true,
            journal: None,
            target_test_context: None,
            diff_scope: bc_model::DiffScope::inactive(),
            dialect: String::new(),
            base_host: String::new(),
            cancel: None,
        }
    }
}

/// The deterministic gate + playbook + detected repo frameworks, built
/// once per run. Loaded from disk by the caller (`bc-config`/CLI layer
/// resolves the actual file paths); `None` gate/playbook data fails
/// closed on every decision, matching [`bc_policy_gate::RemediationGate`]'s
/// own documented posture.
pub struct PolicyContext {
    pub gate: RemediationGate,
    pub playbook: Playbook,
    pub frameworks: BTreeSet<String>,
}

impl PolicyContext {
    pub fn new(gate: RemediationGate, playbook: Playbook, frameworks: BTreeSet<String>) -> Self {
        PolicyContext {
            gate,
            playbook,
            frameworks,
        }
    }
}

/// The per-finding result: the coerced verdict plus (when policy
/// enforcement ran) the gate's own audit trail.
///
/// `policy_action`/`final_verdict` are owned `String`s (not `&'static
/// str`, despite [`action_label`]/`bc_policy_gate::cap_verdict` only
/// ever producing a handful of literal values) specifically so this
/// whole type can derive `Deserialize` — a checkpoint payload loaded
/// back from SQLite is an owned byte buffer, and deserializing a
/// borrowed `&'static str` out of it is not possible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationRecord {
    pub finding_index: i64,
    /// A stable, content-based identity for the finding this record is
    /// about — [`bc_sarif::finding_id`], the SAME id used for SARIF
    /// `partialFingerprints` and the existing GitHub finding-comment
    /// marker, so a remediation can be correlated back to "the same
    /// finding" everywhere it's surfaced. Deliberately not just
    /// `finding_index` (the scan-ordinal position), which isn't stable
    /// across rescans.
    pub finding_id: String,
    pub verdict: RemediationVerdict,
    pub policy_action: Option<String>,
    pub policy_reason: Option<String>,
    pub final_verdict: Option<String>,
    pub policy_reverted: Vec<String>,
    pub policy_matched_globs: Vec<String>,
    /// The unified diff of whatever `verdict.changes` ended up being,
    /// captured regardless of whether policy enforcement is on — `None`
    /// when the agent never ran (pre-gate deny) or made no changes.
    pub diff: Option<String>,
}

/// One finding's outcome from [`run_remediation`]'s sequential walk: a
/// bad finding never aborts the run, it's just recorded as failed.
#[derive(Debug, Clone)]
pub enum RemediationOutcome {
    Processed(Box<RemediationRecord>),
    Failed { finding_index: i64, error: String },
}

fn getenv(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// Renders one finding's Markdown section text for the prompt, reusing
/// the exact same renderer the scan report itself uses (rather than a
/// second finding-to-text formatter).
fn render_finding_body(finding: &RankedFinding) -> String {
    bc_report_md::render_findings(std::slice::from_ref(finding)).join("\n")
}

/// Ported from `policy.decide.pre_decision`: decide whether `cwe`/`file`
/// may be patched and, if so, resolve its playbook strategy. The
/// playbook is supplementary prompt context, not a second gate — a CWE
/// with no playbook entry still gets the full agent run.
fn pre_decision(
    policy: &PolicyContext,
    cwe: Option<&str>,
    file: &str,
) -> (Decision, Option<Strategy>) {
    let decision = policy.gate.decide(cwe.unwrap_or(""), file, &getenv);
    let strategy = if decision.may_generate_patch() {
        let lang = bc_policy_gate::language_for(file);
        let frameworks: Vec<String> = policy.frameworks.iter().cloned().collect();
        cwe.and_then(|c| policy.playbook.resolve(c, lang, &frameworks))
    } else {
        None
    };
    (decision, strategy)
}

use worktree_walk::worktree_forbidden_matches;

fn dedup_preserve_order(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

/// The audit record for a finding the `--diff-scope` boundary refused:
/// no agent call, no snapshot, no patch, and a `policy_action` of
/// [`OUT_OF_DIFF_SCOPE_ACTION`] that no other outcome uses.
///
/// Deliberately shaped like the pre-gate DENY record just below it (same
/// `REJECT` final verdict, same empty `policy_reverted`/
/// `policy_matched_globs`, same `diff: None`), because downstream
/// consumers already handle that shape correctly — a scope refusal is a
/// refusal, it just has a different reason on it.
fn out_of_diff_scope_record(
    finding_index: i64,
    finding_id: String,
    reason: &str,
) -> RemediationRecord {
    RemediationRecord {
        finding_index,
        finding_id,
        verdict: RemediationVerdict::out_of_diff_scope(finding_index, reason),
        policy_action: Some(OUT_OF_DIFF_SCOPE_ACTION.to_string()),
        policy_reason: Some(reason.to_string()),
        final_verdict: Some("REJECT".to_string()),
        policy_reverted: Vec::new(),
        policy_matched_globs: Vec::new(),
        diff: None,
    }
}

/// [`RemediationRecord::policy_action`] for a scope refusal. Distinct from
/// `bc_policy_gate`'s own `"patch"`/`"guidance_only"` labels (see
/// [`action_label`]) precisely so `--out-remediation-json` can be filtered
/// on it: "the tool declined because the file is not in the pull request"
/// is a different fact from "the tool's policy declined this CWE", and an
/// operator auditing a run has to be able to tell them apart.
pub const OUT_OF_DIFF_SCOPE_ACTION: &str = "out_of_diff_scope";

/// `true` when `record` is a diff-scope refusal — the boolean form of
/// [`OUT_OF_DIFF_SCOPE_ACTION`], so callers reasoning about a run's
/// outcomes never have to compare the literal themselves.
pub fn was_out_of_diff_scope(record: &RemediationRecord) -> bool {
    record.policy_action.as_deref() == Some(OUT_OF_DIFF_SCOPE_ACTION)
}

/// Runs the remediation agent for one finding and returns its verdict +
/// (when policy enforcement is on) the gate's audit trail. `finding_index`
/// is the finding's 1-based ordinal position in the scan report.
///
/// Propagates an [`LlmError`] only when the agentic call itself fails
/// (network/rate-limit/etc.) — an unparseable-but-successful response
/// still yields a `Needs Review` verdict, never an error, matching the
/// Python original's lenient JSON-salvage coercion.
pub async fn remediate_finding(
    client: &dyn LlmClient,
    tools: &dyn ToolExecutor,
    repo: &Path,
    finding: &RankedFinding,
    finding_index: i64,
    config: &Step10Config,
    policy: Option<&PolicyContext>,
) -> Result<RemediationRecord, LlmError> {
    remediate_finding_with_baseline(client, tools, repo, finding, finding_index, config, policy)
        .await
        .map(|(record, _)| record)
}

/// [`remediate_finding`], additionally handing back the finding's own
/// pre-remediation **baseline**: the bytes of exactly the files this
/// finding's agent touched, as of the moment before it ran (which, in a
/// sequential walk, is *after* every earlier finding's kept fix).
///
/// **Why this exists.** S10's own gates roll back byte-exactly because
/// they still hold this snapshot; every later consumer used to get
/// nothing, so Phase 3's S11 rollback fell through to
/// [`revert_record`]'s git-only path. On a target that is not a git
/// worktree that path is a no-op, so a fix S11 graded `Not Fixed` stayed
/// on disk with only a warning (observed under the old `distroless/cc`
/// runtime, which shipped no `git` at all: GitHub Actions run
/// 34021176323, `[s11] WARNING: cannot roll back finding 4: /scan/repo is
/// not a git repository...`). The packaged image ships `git` now, but a
/// scanned tree that simply is not a checkout still lands in the same
/// place, so carrying the baseline out remains the primary mechanism and
/// the one the in-loop gates already trust.
///
/// **In memory only.** The baseline holds raw pre-edit file contents; it
/// is deliberately not part of [`RemediationRecord`] and therefore never
/// reaches a `--resume` checkpoint, `--out-remediation-json`, or a PR
/// comment. A resumed record consequently has no baseline, which is
/// exactly why [`revert_record`] survives as the fallback.
#[allow(clippy::too_many_arguments)]
pub async fn remediate_finding_with_baseline(
    client: &dyn LlmClient,
    tools: &dyn ToolExecutor,
    repo: &Path,
    finding: &RankedFinding,
    finding_index: i64,
    config: &Step10Config,
    policy: Option<&PolicyContext>,
) -> Result<(RemediationRecord, Baseline), LlmError> {
    let file = finding.finding.file.clone();
    let cwe = finding.finding.cwe.clone();
    let finding_id = bc_sarif::finding_id(&finding.finding);

    // The diff-scope boundary, checked FIRST: before the policy gate,
    // before the pre-agent snapshot, before a single token is spent. A
    // finding in a file the pull request never touched is not a finding
    // this run may edit, whatever the policy says about its CWE.
    if let Some(reason) = config.diff_scope.refusal(&file) {
        return Ok((
            out_of_diff_scope_record(finding_index, finding_id, &reason),
            Baseline::default(),
        ));
    }

    let pre = policy.map(|p| pre_decision(p, cwe.as_deref(), &file));

    // Pre-gate DENY: skip the agent entirely, zero tokens spent.
    if let Some((decision, _)) = &pre {
        if !decision.may_generate_patch() {
            return Ok((
                RemediationRecord {
                    finding_index,
                    finding_id,
                    verdict: RemediationVerdict::denied(finding_index, &decision.reason),
                    policy_action: Some("guidance_only".to_string()),
                    policy_reason: Some(decision.reason.clone()),
                    final_verdict: Some("REJECT".to_string()),
                    policy_reverted: Vec::new(),
                    policy_matched_globs: Vec::new(),
                    diff: None,
                },
                Baseline::default(),
            ));
        }
    }

    // Each finding's gates must only ever see its OWN writes — the
    // executor (and therefore its journal) is shared across the whole
    // sequential walk.
    if let Some(journal) = &config.journal {
        journal.clear();
    }

    // Snapshot the finding's file (plus, under enforcement, every
    // worktree file matching a forbidden/sensitive glob) BEFORE the
    // agent edits anything.
    let mut snap_targets: Vec<String> = if file.is_empty() {
        Vec::new()
    } else {
        vec![file.clone()]
    };
    // Every workflow file, policy or not: the workflow-pin gate below
    // needs the pre-edit text to tell an introduced ref from an existing
    // one (and to find the pins the repository already trusts), and a
    // rollback needs a baseline for a workflow the model edited without
    // listing it in `changes`.
    for f in workflow_gate::workflow_snapshot_paths(repo) {
        if !snap_targets.contains(&f) {
            snap_targets.push(f);
        }
    }
    if let Some(p) = policy {
        let patterns = dedup_preserve_order(
            p.gate
                .forbid_patch_paths()
                .iter()
                .chain(p.gate.deny_paths().iter())
                .cloned(),
        );
        for f in worktree_forbidden_matches(repo, &patterns) {
            if !snap_targets.contains(&f) {
                snap_targets.push(f);
            }
        }
    }
    let mut before = bc_diffcapture::snapshot_files(repo, &snap_targets);
    // Whatever was already dirty is the USER's uncommitted work, not the
    // agent's. Recording it now is what lets the gates below roll back
    // "everything that changed" without ever destroying it — see
    // [`agent_touched_files`].
    let dirty_before: BTreeSet<String> = bc_diffcapture::changed_files_whole_tree(repo)
        .into_iter()
        .collect();

    let strategy = pre.as_ref().and_then(|(_, s)| s.clone());
    let (deny_paths, forbid_paths): (Vec<String>, Vec<String>) = policy
        .map(|p| {
            (
                p.gate.deny_paths().to_vec(),
                p.gate.forbid_patch_paths().to_vec(),
            )
        })
        .unwrap_or_default();
    let body = render_finding_body(finding);
    let repo_display = repo.display().to_string();
    let mut user = prompts::build_user(&prompts::FindingPrompt {
        finding_index,
        file: &file,
        body: &body,
        repo: &repo_display,
        fix_mode: config.fix_mode,
        strategy: strategy.as_ref(),
        deny_paths: &deny_paths,
        forbid_paths: &forbid_paths,
    });

    if let Some(context) = &config.target_test_context {
        user.push_str("\nTARGET TEST ASSURANCE CONTEXT (untrusted repository evidence):\n");
        user.push_str(context);
        user.push_str("\nPreserve independently reviewed tests and assertions. Test generation is not execution or verification. Fix the underlying vulnerability; do not accommodate an incorrect patch by changing tests.\n");
    }

    let mut agentic_config = AgenticConfig::new(config.model.clone());
    agentic_config.system_prompt = Some(prompts::build_system());
    agentic_config.allowed_tools = effective_tools(config);
    agentic_config.max_turns = config.max_turns;
    agentic_config.max_transient_retries = config.max_transient_retries;
    agentic_config.max_context_shrinks = config.max_context_shrinks;
    agentic_config.retry_backoff_base = config.retry_backoff_base;
    agentic_config.temperature = config.temperature;
    agentic_config.top_p = config.top_p;
    agentic_config.seed = config.seed;
    agentic_config.reasoning_effort = config.reasoning_effort;
    agentic_config.openai_api = config.openai_api;
    agentic_config.timeout_secs = config.timeout_secs;

    let first_answer = match run_agentic(client, tools, &user, &agentic_config).await {
        Ok(outcome) => outcome.final_text,
        Err(e) => {
            // The loop died mid-flight (network, rate limit, a provider
            // 500). Whatever the agent had already written is a partial
            // edit nobody will ever verify, and the caller turns this into
            // a `Failed` outcome that carries no diff — so leaving it on
            // disk would be an invisible, unattributable change.
            let touched = agent_touched_files(repo, config, &mut before, &dirty_before, &[]);
            bc_diffcapture::revert_all(repo, &touched, &before);
            return Err(e);
        }
    };
    let mut verdict = coerce_answer(&first_answer, finding_index);

    // ---- The one bounded retry: "you described a fix but never wrote it."
    //
    // See [`Step10Config::retry_unapplied_fix`] for the field evidence.
    // Deliberately placed BEFORE every gate, so a second attempt that does
    // write is judged by the policy, syntax, verify and size gates exactly
    // like a first-attempt fix — a retry that bypassed the gates would be a
    // hole, not a feature. Capped at exactly one extra session: the failure
    // it addresses is a model that narrated instead of calling a tool, and
    // if a pointed "you did not call Edit, call it now" does not fix that,
    // a third identical ask will not either.
    let mut carried_over: Vec<String> = Vec::new();
    if config.retry_unapplied_fix {
        let claimed_files = claimed_files(&verdict);
        if !claimed_files.is_empty()
            && describes_an_unwritten_fix(repo, config, &mut before, &verdict)
        {
            // Fold attempt 1's copy-on-first-write baselines into `before`
            // (which never lets a later capture displace an earlier one)
            // and remember what it wrote, THEN clear the ledger so attempt
            // 2 gets a window of its own. Without the fold first, clearing
            // would let attempt 2's first write record already-modified
            // bytes as that file's "original", and a rollback would then
            // restore attempt 1's half-patched code as if it were pristine.
            if let Some(journal) = &config.journal {
                before.merge_originals(journal.originals());
                carried_over = journal.touched();
                journal.clear();
            }
            let retry_prompt = prompts::build_retry(&user, &first_answer, &claimed_files);
            let second_answer =
                match run_agentic(client, tools, &retry_prompt, &agentic_config).await {
                    Ok(outcome) => outcome.final_text,
                    Err(e) => {
                        // Identical posture to a first-attempt mid-flight
                        // failure above: an errored session's writes are a
                        // partial edit nobody will ever verify, and the caller
                        // turns this into a `Failed` outcome carrying no diff.
                        // Keeping attempt 1's verdict instead would be worse,
                        // not better — attempt 2 may have written something,
                        // and attempt 1's verdict says nothing about it.
                        let touched = dedup_preserve_order(carried_over.into_iter().chain(
                            agent_touched_files(repo, config, &mut before, &dirty_before, &[]),
                        ));
                        bc_diffcapture::revert_all(repo, &touched, &before);
                        return Err(e);
                    }
                };
            verdict = coerce_answer(&second_answer, finding_index);
            note_retry(&mut verdict, &claimed_files);
        }
    }

    // Everything the agent ACTUALLY changed, and a baseline good enough to
    // put every one of those files back. `carried_over` re-adds whatever
    // the pre-retry journal window held, which `clear()` dropped from the
    // ledger but which is still the agent's own edit and still needs to be
    // in every gate's rollback scope.
    let claimed = claimed_files(&verdict);
    let whole_tree = bc_diffcapture::changed_files_whole_tree(repo);
    let touched = dedup_preserve_order(carried_over.iter().cloned().chain(agent_touched_files(
        repo,
        config,
        &mut before,
        &dirty_before,
        &claimed,
    )));
    // The value this function hands forward for S11's own rollback —
    // captured here, before any gate runs, so it describes the tree as the
    // agent found it rather than as a gate left it.
    let baseline = before.subset(&touched);

    // The record's audit fields, filled in as the gates below run. A
    // `final_verdict` only exists when a policy context was supplied at
    // all (it is the gate's own ACCEPT/REJECT label, not the agent's).
    let mut policy_action = None;
    let mut policy_reason = None;
    let mut final_verdict: Option<String> = None;
    let mut policy_reverted: Vec<String> = Vec::new();
    let mut policy_matched_globs: Vec<String> = Vec::new();
    if let Some((decision, _)) = &pre {
        policy_action = Some(action_label(decision.action).to_string());
        policy_reason = Some(decision.reason.clone());
    }

    // ---- Gate 1: the deterministic deny-list post-gate (policy only).
    // Inspects what ACTUALLY changed on disk — the union of the diff's own
    // file list, the agent's self-reported `changes`, and `git status` —
    // and reverts anything that hit a forbidden/sensitive path.
    if let Some(p) = policy {
        let (decision, _) = pre.as_ref().expect("policy is Some, so pre_decision ran");
        let worktree_forbidden = if whole_tree.is_empty() {
            let patterns = dedup_preserve_order(
                p.gate
                    .forbid_patch_paths()
                    .iter()
                    .chain(p.gate.deny_paths().iter())
                    .cloned(),
            );
            worktree_forbidden_matches(repo, &patterns)
        } else {
            Vec::new()
        };
        let diff_scope = dedup_preserve_order(
            claimed
                .iter()
                .cloned()
                .chain(whole_tree.iter().cloned())
                .chain(touched.iter().cloned()),
        );
        let diff = bc_diffcapture::capture_git_diff(repo, &diff_scope)
            .or_else(|| bc_diffcapture::synth_unified_diff(repo, &before, &diff_scope));
        let diff_files = bc_policy_gate::inspect_diff(diff.as_deref());
        let candidates = dedup_preserve_order(
            diff_files
                .into_iter()
                .chain(claimed.iter().cloned())
                .chain(whole_tree.iter().cloned())
                .chain(touched.iter().cloned())
                .chain(worktree_forbidden),
        );
        let bad = p.gate.forbidden_files(&candidates);

        if bad.is_empty() {
            // A policy allow is only PERMISSION to patch, never evidence
            // that a patch happened: ACCEPT additionally needs a real
            // on-disk change and a verdict that claims one (ported from
            // `postgate.py::enforce_post`'s `patch_applied` and verdict
            // checks). The agent's own evidence gates are necessary, not
            // sufficient; a no-op `Not Fixed` with three passing gates
            // used to be labeled ACCEPT.
            let gates_passed =
                verdict.gates.all_pass() && claims_a_fix(&verdict) && diff_has_content(&diff);
            final_verdict =
                Some(bc_policy_gate::cap_verdict(decision.action, gates_passed).to_string());
        } else {
            let mut matched = BTreeSet::new();
            for f in &bad {
                if let Some(g) = p
                    .gate
                    .patch_touches_forbidden(std::slice::from_ref(f))
                    .or_else(|| p.gate.changed_paths_hit_deny(std::slice::from_ref(f)))
                {
                    matched.insert(g);
                }
                if let Ok(rolled) = bc_diffcapture::revert(repo, std::slice::from_ref(f), &before) {
                    policy_reverted.extend(rolled);
                }
            }
            let bad_set: BTreeSet<&str> = bad.iter().map(String::as_str).collect();
            verdict
                .changes
                .retain(|c| !bad_set.contains(c.file.as_str()));
            let note = format!(
                "Policy post-gate reverted {} file(s) that touched forbidden/sensitive paths \
                 ({}): {}. These edits were rolled back on disk; route to a human.",
                policy_reverted.len(),
                matched.iter().cloned().collect::<Vec<_>>().join(", "),
                policy_reverted.join(", "),
            );
            verdict.remaining_risks.push(note.clone());
            if matches!(verdict.verdict, Verdict::Fixed | Verdict::PartiallyFixed) {
                verdict.verdict = Verdict::NeedsReview;
            }
            verdict.summary = if verdict.summary.is_empty() {
                note
            } else {
                format!("{} {}", verdict.summary, note)
            };
            policy_matched_globs = matched.into_iter().collect();
            final_verdict = Some("REJECT".to_string());
        }
    }

    // ---- Gate 1b: reusable-workflow pins. Always on, with or without a
    // policy context (see `workflow_gate`'s module doc comment). A remote
    // reusable workflow may only be pinned to a commit the repository
    // already pins it to; anything else is an invented SHA or a mutable
    // ref, and the whole patch goes back. Python reverts only the
    // offending workflow file here and relies on the verdict alone; this
    // port's gate 6 would roll the rest back for a `Not Fixed` anyway, so
    // doing it here in one step keeps the note and the tree in agreement.
    let unsafe_refs = workflow_gate::unsafe_workflow_refs(repo, &before, &touched);
    if !unsafe_refs.is_empty() {
        let rolled_back = bc_diffcapture::revert_all(repo, &touched, &before);
        note_revert(
            &mut verdict,
            &format!(
                "workflow-pin gate: the edit introduced unverified reusable-workflow refs \
                 ({}). S10 must pin a remote reusable workflow only to a commit the \
                 repository already establishes, or decline the fix; it must never invent \
                 a SHA. All {} file(s) the agent touched were rolled back.",
                workflow_gate::describe(&unsafe_refs),
                rolled_back.len()
            ),
        );
        verdict.verdict = Verdict::NotFixed;
        verdict
            .changes
            .retain(|c| !unsafe_refs.contains_key(&bc_diffcapture::norm_path(&c.file)));
        policy_reverted.extend(rolled_back);
        policy_reason = Some(UNSAFE_WORKFLOW_REFERENCE.to_string());
        return Ok((
            RemediationRecord {
                finding_index,
                finding_id,
                verdict,
                policy_action,
                policy_reason,
                final_verdict: Some("REJECT".to_string()),
                policy_reverted,
                policy_matched_globs,
                diff: None,
            },
            baseline,
        ));
    }

    // ---- Gate 2: the agent must not have left unparseable source behind.
    //
    // Deliberately AFTER the policy post-gate, not before it. Junk written
    // into a deny-listed path is both a policy violation and a syntax
    // error; running this first would roll the file back and report only
    // the syntax problem, silently dropping the compliance audit trail
    // (`policy_reverted`/`policy_matched_globs`/REJECT) for the more
    // serious of the two. Running it second also means it judges the tree
    // as it will actually be left — after the policy gate has already
    // undone whatever it refuses to allow.
    if config.syntax_check {
        if let Some(broken) = first_unparseable(repo, &touched) {
            let rolled_back = bc_diffcapture::revert_all(repo, &touched, &before);
            note_revert(
                &mut verdict,
                &format!(
                    "syntax gate: {broken} no longer parses after the agent's edits. \
                     All {} file(s) it touched were rolled back.",
                    rolled_back.len()
                ),
            );
            verdict.verdict = Verdict::NeedsReview;
            if pre.is_some() {
                final_verdict = Some("REJECT".to_string());
            }
            return Ok((
                RemediationRecord {
                    finding_index,
                    finding_id,
                    verdict,
                    policy_action,
                    policy_reason,
                    final_verdict,
                    policy_reverted,
                    policy_matched_globs,
                    diff: None,
                },
                baseline,
            ));
        }
    }

    // ---- Gate 3: the operator's own build/lint/test command.
    if let Some(command) = &config.verify_command {
        if let Err(detail) = run_verify_command(
            repo,
            command,
            config.verify_timeout_secs,
            config.cancel.as_ref(),
        )
        .await
        {
            let rolled_back = bc_diffcapture::revert_all(repo, &touched, &before);
            note_revert(
                &mut verdict,
                &format!(
                    "verify command failed, so all {} file(s) the agent touched were rolled \
                     back. Last output:\n{detail}",
                    rolled_back.len()
                ),
            );
            verdict.verdict = Verdict::NeedsReview;
            if pre.is_some() {
                final_verdict = Some("REJECT".to_string());
            }
            return Ok((
                RemediationRecord {
                    finding_index,
                    finding_id,
                    verdict,
                    policy_action,
                    policy_reason,
                    final_verdict,
                    policy_reverted,
                    policy_matched_globs,
                    diff: None,
                },
                baseline,
            ));
        }
    }

    // ---- The record's own diff, plus the "you said Fixed but nothing
    // changed" reconciliation.
    // The model's `changes` array is an annotation, not a source of truth.
    // A tool call can mutate a helper and the model can omit it (including
    // returning `Fixed` with an empty array); using the actual touched set
    // ensures S11 receives the patch that is really on disk.
    let mut record_diff = capture_diff(repo, &before, &touched);
    let asserted_fix = claims_a_fix(&verdict);
    reconcile_verdict_with_diff(&mut verdict, &record_diff);
    if asserted_fix && verdict.verdict == Verdict::NeedsReview && pre.is_some() {
        final_verdict = Some("REJECT".to_string());
    }

    // ---- Gate 4: size caps. A remediation is a targeted fix for one
    // finding; a sprawling one is a run that went wrong, not one that went
    // big. Measured over everything the agent touched (not just what it
    // admitted to), so an under-reported rewrite cannot slip the cap.
    if let Some(reason) = over_size_cap(repo, &before, &touched, config) {
        let rolled_back = bc_diffcapture::revert_all(repo, &touched, &before);
        note_revert(
            &mut verdict,
            &format!(
                "{reason}, so all {} file(s) the agent touched were rolled back.",
                rolled_back.len()
            ),
        );
        verdict.verdict = Verdict::NeedsReview;
        if pre.is_some() {
            final_verdict = Some("REJECT".to_string());
        }
        record_diff = None;
    } else if config.dry_run {
        // ---- Gate 5: dry run. Roll back unconditionally, but KEEP the
        // diff so the record still yields a PR fix suggestion.
        let rolled_back = bc_diffcapture::revert_all(repo, &touched, &before);
        note_revert(
            &mut verdict,
            &format!(
                "dry run: the patch was captured and then rolled back \
                 ({} file(s) restored); nothing was left applied.",
                rolled_back.len()
            ),
        );
    } else if !matches!(verdict.verdict, Verdict::Fixed) && !config.keep_unverified {
        // ---- Gate 6: anything but a clean `Fixed` goes back. `Not Fixed`,
        // `Partially Fixed`, `Needs Review` and `False Positive` all mean
        // "this patch was never confirmed to work", and a half-applied fix
        // for a vulnerability is strictly worse than the vulnerability
        // alone: it looks addressed. Only fires when there was actually
        // something on disk to undo, so a verdict reached without any edit
        // is left exactly as it was (and still checkpoints).
        let rolled_back = bc_diffcapture::revert_all(repo, &touched, &before);
        if !rolled_back.is_empty() {
            let reported = verdict.verdict.as_str();
            note_revert(
                &mut verdict,
                &format!(
                    "the agent's verdict was '{reported}', not 'Fixed', so its patch was rolled \
                     back ({} file(s) restored). Set keep_unverified to leave it applied.",
                    rolled_back.len()
                ),
            );
            record_diff = None;
        }
    }

    // The post-gate ran before the later gates could still roll the patch
    // back, so its provisional ACCEPT is reconciled against the diff the
    // record actually ends up with (`plugin_runner/run.py::
    // _reconcile_post_meta`): an ACCEPT with no captured diff is a label
    // contradicting the evidence, and becomes REJECT/`no_diff_captured`.
    if final_verdict.as_deref() == Some("ACCEPT") && !diff_has_content(&record_diff) {
        final_verdict = Some("REJECT".to_string());
        policy_reason = Some(NO_DIFF_CAPTURED.to_string());
    }

    Ok((
        RemediationRecord {
            finding_index,
            finding_id,
            verdict,
            policy_action,
            policy_reason,
            final_verdict,
            policy_reverted,
            policy_matched_globs,
            diff: record_diff,
        },
        baseline,
    ))
}

/// [`RemediationRecord::policy_reason`] when the policy allowed a patch,
/// every gate passed, and yet no diff survived to the record, matching
/// Python's reconciled `policy_reason`.
pub const NO_DIFF_CAPTURED: &str = "no_diff_captured";

/// The agent's answer text turned into a verdict — the lenient
/// JSON-salvage coercion, with an unparseable response becoming a
/// `Needs Review` verdict that quotes (redacted, truncated) what it
/// actually said. Factored out because the retry above needs the exact
/// same treatment for its second answer; two copies would be two places
/// for the diagnostic to drift.
fn coerce_answer(answer: &str, finding_index: i64) -> RemediationVerdict {
    match bc_json_repair::extract_json(answer) {
        Ok(data) => RemediationVerdict::coerce(&data, finding_index),
        Err(e) => RemediationVerdict {
            finding_index,
            verdict: Verdict::NeedsReview,
            gates: Gates::default(),
            root_cause: String::new(),
            changes: Vec::new(),
            remaining_risks: Vec::new(),
            recommendations: Vec::new(),
            summary: format!(
                "could not parse agent response as JSON: {e} | response began: {}",
                unparseable_excerpt(answer)
            ),
        },
    }
}

/// The non-empty repo-relative paths a verdict claims it changed.
fn claimed_files(verdict: &RemediationVerdict) -> Vec<String> {
    verdict
        .changes
        .iter()
        .map(|c| c.file.clone())
        .filter(|f| !f.is_empty())
        .collect()
}

/// `true` when this answer is the "described a fix, wrote nothing" shape:
/// a `Fixed`/`Partially Fixed` verdict naming specific files whose diff
/// is empty. Deliberately the SAME predicate
/// [`reconcile_verdict_with_diff`] downgrades on (both go through
/// [`claims_a_fix`] and [`diff_has_content`]) so the retry fires exactly
/// when — and only when — the downgrade otherwise would: "before I mark
/// your answer as unapplied, here is one more chance to apply it."
///
/// The journal's originals are folded into `before` first so the
/// non-git synthesized-diff fallback can see a file the agent wrote that
/// nobody predicted; without that, a real edit on a target with no `git`
/// would look like no edit and the retry would fire against a fix that
/// had in fact landed.
fn describes_an_unwritten_fix(
    repo: &Path,
    config: &Step10Config,
    before: &mut bc_diffcapture::Snapshot,
    verdict: &RemediationVerdict,
) -> bool {
    if !claims_a_fix(verdict) {
        return false;
    }
    if let Some(journal) = &config.journal {
        before.merge_originals(journal.originals());
    }
    !diff_has_content(&capture_diff(repo, before, &claimed_files(verdict)))
}

/// The note recording that a retry happened, appended to `summary` so it
/// reaches the report, `--out-remediation-json` and any PR comment — a
/// remediation that took two sessions is a fact a reviewer wants, and the
/// per-run cost is a fact an operator wants.
pub const RETRY_NOTE_PREFIX: &str = "Retried once after an unapplied fix:";

fn note_retry(verdict: &mut RemediationVerdict, claimed: &[String]) {
    let note = format!(
        "{RETRY_NOTE_PREFIX} the first answer claimed a change to {} but wrote nothing to \
         disk, so the session was re-run once with an explicit instruction to apply the \
         edit. Retries used: 1.",
        claimed.join(", ")
    );
    verdict.summary = if verdict.summary.is_empty() {
        note
    } else {
        format!("{} {note}", verdict.summary)
    };
}

/// The tool names actually offered to the agent. In `report-only` mode the
/// mutating tools are dropped from the request itself rather than only
/// being discouraged by the prompt — a prompt that says "do NOT edit
/// files" while `Edit` is still on the wire is a request, not a control,
/// and the whole point of report-only is that nothing can be written.
fn effective_tools(config: &Step10Config) -> Vec<String> {
    if config.fix_mode {
        return config.allowed_tools.clone();
    }
    config
        .allowed_tools
        .iter()
        .filter(|t| !matches!(t.as_str(), "Write" | "Edit"))
        .cloned()
        .collect()
}

/// Every repo-relative path the agent actually wrote to this run, folding
/// its captured pre-edit bytes into `before` so a rollback of any of them
/// is exact. Three sources, deliberately combined:
///
/// 1. **The executor's journal** (`config.journal`) — exact, and the only
///    source that works on a target with no VCS at all.
/// 2. **`git status` minus whatever was ALREADY dirty before the agent
///    ran.** The subtraction is the safety-critical half: a blanket
///    "revert everything git reports as changed" would `git checkout` the
///    user's own uncommitted work, which is precisely the "remediation
///    broke my codebase" outcome these gates exist to prevent. Files that
///    became dirty during the run are the agent's; files that were dirty
///    beforehand are the user's and are never touched.
/// 3. **The agent's self-reported `changes[]`, but only those already in
///    the snapshot.** A claimed file with a real captured baseline can be
///    restored byte-exactly; a claimed file WITHOUT one could only be
///    "restored" by `git checkout`, which for a file the agent never
///    actually modified would silently destroy the user's edits to it — so
///    an unbacked claim is deliberately dropped rather than trusted.
fn agent_touched_files(
    repo: &Path,
    config: &Step10Config,
    before: &mut bc_diffcapture::Snapshot,
    dirty_before: &BTreeSet<String>,
    claimed: &[String],
) -> Vec<String> {
    let journalled = match &config.journal {
        Some(journal) => {
            before.merge_originals(journal.originals());
            journal.touched()
        }
        None => Vec::new(),
    };
    let newly_dirty: Vec<String> = bc_diffcapture::changed_files_whole_tree(repo)
        .into_iter()
        .filter(|f| !dirty_before.contains(f))
        .collect();
    let backed: Vec<String> = claimed
        .iter()
        .map(|f| bc_diffcapture::norm_path(f))
        .filter(|f| before.get(f).is_some())
        .collect();
    dedup_preserve_order(journalled.into_iter().chain(newly_dirty).chain(backed))
}

/// The marker every gate-driven rollback note starts with, and the reason
/// [`revert_reason`] can be answered from a `RemediationRecord` alone.
pub const REVERT_NOTE_PREFIX: &str = "Rolled back by an S10 safety gate:";

/// Which gate rolled this record's patch back, and why, in the gate's own
/// words. `None` when nothing was rolled back.
///
/// Read off the recorded note rather than a dedicated struct field:
/// `RemediationRecord` round-trips through checkpoints and
/// `--out-remediation-json` and is built by literal in several other
/// crates' fixtures, so a new required field would be a breaking change
/// across the workspace for a fact the record already states in full. The
/// note is written by [`note_revert`] and by nothing else.
///
/// The reason is what stops a declined fix from reading as "the tool had
/// nothing to say": the report renders it against the finding (see
/// `bc_report_md::RemediationView::rollback_reason`), so a reader can tell
/// a patch that was attempted and refused apart from one that was never
/// attempted at all.
pub fn revert_reason(record: &RemediationRecord) -> Option<&str> {
    record
        .verdict
        .remaining_risks
        .iter()
        .find_map(|r| r.strip_prefix(REVERT_NOTE_PREFIX))
        .map(str::trim)
}

/// `true` when this record's patch was rolled back by one of S10's safety
/// gates and is therefore NOT on disk. The boolean half of
/// [`revert_reason`], for callers that only need to know that it happened.
pub fn was_reverted(record: &RemediationRecord) -> bool {
    revert_reason(record).is_some()
}

/// Records `reason` on `verdict` — in `remaining_risks` (machine-readable,
/// via [`was_reverted`]) and appended to `summary` (what a human reading
/// the report actually sees).
fn note_revert(verdict: &mut RemediationVerdict, reason: &str) {
    let note = format!("{REVERT_NOTE_PREFIX} {reason}");
    verdict.remaining_risks.push(note.clone());
    verdict.summary = if verdict.summary.is_empty() {
        note
    } else {
        format!("{} {note}", verdict.summary)
    };
}

/// The first file in `touched` that no longer parses as its own language,
/// if any. A file that has been deleted, cannot be read, or is written in
/// a language this workspace has no grammar for yields no opinion and is
/// skipped — [`bc_repo_analysis::syntax_check`]'s `None` means "not
/// checked", never "checked and fine".
fn first_unparseable(repo: &Path, touched: &[String]) -> Option<String> {
    touched.iter().find_map(|rel| {
        let resolved = bc_pathjail::confine(repo, rel)?;
        let bytes = std::fs::read(&resolved).ok()?;
        (bc_repo_analysis::syntax_check(Path::new(rel.as_str()), &bytes) == Some(true))
            .then(|| rel.clone())
    })
}

/// `Some(reason)` when the patch is too big to be a targeted fix for one
/// finding, per `max_diff_lines` / `max_files_touched` (either at `0`
/// disables that half). Measured against the diff of everything the agent
/// touched, so an under-reported rewrite cannot slip the cap.
fn over_size_cap(
    repo: &Path,
    before: &bc_diffcapture::Snapshot,
    touched: &[String],
    config: &Step10Config,
) -> Option<String> {
    if config.max_files_touched > 0 && touched.len() > config.max_files_touched {
        return Some(format!(
            "the patch touched {} file(s), over the max_files_touched limit of {}",
            touched.len(),
            config.max_files_touched
        ));
    }
    if config.max_diff_lines == 0 || touched.is_empty() {
        return None;
    }
    let diff = bc_diffcapture::capture_git_diff(repo, touched)
        .or_else(|| bc_diffcapture::synth_unified_diff(repo, before, touched))
        .unwrap_or_default();
    let changed = changed_line_count(&diff);
    (changed > config.max_diff_lines).then(|| {
        format!(
            "the patch changed {changed} line(s), over the max_diff_lines limit of {}",
            config.max_diff_lines
        )
    })
}

/// Added + removed lines in a unified diff. `+++`/`---` are file headers,
/// not content, so they are excluded — counting them would charge every
/// patch two extra lines per file and make a small cap unusable.
fn changed_line_count(diff: &str) -> usize {
    diff.lines()
        .filter(|l| {
            (l.starts_with('+') && !l.starts_with("+++"))
                || (l.starts_with('-') && !l.starts_with("---"))
        })
        .count()
}

/// Runs the operator's `command` under `sh -c` in `repo`, capped at
/// `timeout_secs`. `Ok(())` only on a zero exit; otherwise `Err` carries
/// the tail of the command's own output for the rollback note.
///
/// `sh -c` is deliberate: an operator writing a verify command wants
/// `cargo build && cargo test`, not an argv array. Nothing model-,
/// repository-, or finding-derived reaches this string — it comes from
/// config only, and there is no default, so absent explicit operator
/// intent no process is ever spawned. `kill_on_drop` means a timeout
/// actually kills the child rather than orphaning a build that then races
/// the rollback for the same files.
async fn run_verify_command(
    repo: &Path,
    command: &str,
    timeout_secs: u64,
    cancel: Option<&bc_pipeline_core::CancelTokenRef>,
) -> Result<(), String> {
    run_verify_command_with_shell(repo, VERIFY_SHELL, command, timeout_secs, cancel).await
}

/// The interpreter [`run_verify_command`] spawns. A parameter on the
/// inner function purely so the "there is no shell on this system" branch
/// is reachable from a test. That branch decides whether the gate fails
/// OPEN or CLOSED, so it has to be asserted rather than assumed. The
/// packaged runtime image does ship a `sh` (Wolfi, see the `Dockerfile`),
/// which is what makes this gate usable at all, but nothing stops an
/// operator running the same binary on a hand-built minimal base that has
/// no shell, and that is the run least able to notice a gate quietly
/// passing everything. Asserting it by deleting `sh` from the test
/// machine is not an option; asserting it by asking for an interpreter
/// that is definitely not installed exercises byte-for-byte the same code
/// path.
const VERIFY_SHELL: &str = "sh";

/// [`run_verify_command`] against an explicit interpreter — see
/// [`VERIFY_SHELL`].
///
/// **Fails CLOSED when the interpreter is missing.** A host with no `sh`
/// cannot run the operator's build/test command, and "could not check" is
/// not "checked and fine": returning `Ok(())` there would let an
/// unverified patch through under a gate the operator explicitly turned
/// on, silently, in exactly the environment least able to notice.
/// The `Err` puts the patch back, downgrades the verdict to `Needs
/// Review`, and says plainly which of the two it was.
async fn run_verify_command_with_shell(
    repo: &Path,
    shell: &str,
    command: &str,
    timeout_secs: u64,
    cancel: Option<&bc_pipeline_core::CancelTokenRef>,
) -> Result<(), String> {
    use verify_process::GroupRun;
    // Its own process group, killed as a whole on timeout or cancellation:
    // see `verify_process` for why killing `sh` alone is not enough.
    match verify_process::run_in_group(
        repo,
        shell,
        command,
        Duration::from_secs(timeout_secs),
        cancel,
    )
    .await
    {
        GroupRun::Finished(Ok(out)) if out.status.success() => Ok(()),
        GroupRun::Finished(Ok(out)) => Err(tail_lines(
            &format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
            VERIFY_OUTPUT_LINES,
        )),
        // `repo.is_dir()` disambiguates: on Unix a spawn reports the SAME
        // `NotFound` whether the program or the working directory is the
        // thing that is missing, and blaming a missing shell for a missing
        // repo path would send an operator hunting the wrong problem.
        GroupRun::Finished(Err(e)) if e.kind() == std::io::ErrorKind::NotFound && repo.is_dir() => {
            Err(format!(
                "verify_command could not run: no shell. '{shell}' is not present on this \
             system, so the operator's build or test command could not be started. The \
             gate fails closed rather than passing a patch it could not verify; unset \
             step_remediate.verify_command to run without it."
            ))
        }
        GroupRun::Finished(Err(e)) => Err(format!("the verify command could not be started: {e}")),
        GroupRun::TimedOut => Err(format!(
            "the verify command did not finish within {timeout_secs}s and was killed"
        )),
        GroupRun::Canceled(reason) => Err(format!(
            "the verify command was stopped ({reason}) and killed before it finished"
        )),
    }
}

/// How much of a failed verify command's output ends up in the note — the
/// tail, since a build failure's actual error is at the end.
const VERIFY_OUTPUT_LINES: usize = 40;

fn tail_lines(text: &str, max: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(max)..].join("\n")
}

/// One S11-driven rollback's outcome, split so the caller can report both
/// halves honestly: a fix can be partly put back and partly left applied,
/// and saying only "rolled back" would be a lie in that case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rollback {
    /// Repo-relative paths actually restored to this finding's baseline.
    pub restored: Vec<String>,
    /// Paths deliberately LEFT ALONE because a later finding's kept fix
    /// also edited them, paired with that later finding's index. See
    /// [`revert_record_with_baseline`] for why restoring these would
    /// destroy a good fix to undo a bad one.
    pub skipped: Vec<(String, i64)>,
}

/// Rolls this finding's patch back from ITS OWN pre-remediation baseline
/// — the snapshot [`remediate_finding_with_baseline`] carried out of the
/// agentic loop — with no VCS involvement whatsoever.
///
/// **Why this is the primary path and [`revert_record`] the fallback.**
/// `revert_record` restores through `git checkout`, so it can do nothing
/// at all unless the target is a git worktree AND a `git` binary is on
/// PATH. The old `distroless/cc` runtime satisfied neither: a
/// path-traversal fix that S11 graded `Not Fixed` stayed on disk with
/// only `[s11] WARNING: ... is not a git repository ... the patch is
/// still applied` to show for it (GitHub Actions run 34021176323). The
/// packaged image ships `git` now, but a scanned tree with no `.git` at
/// all reaches the same dead end. The S10 gates in that same run *did*
/// roll back, because they use exactly this byte-level baseline. This
/// function gives S11 the same mechanism.
///
/// **`protected` is the correctness-critical argument.** S10 remediates
/// every selected finding first, and S11 validates afterwards — so by the
/// time this runs, a LATER finding may have edited one of these files and
/// been KEPT. This finding's baseline predates that edit, so restoring
/// the file would silently delete a good fix in order to undo a bad one.
/// Any file in `protected` (file -> the later finding's index, from
/// [`files_kept_by_later_findings`]) is therefore left exactly as it is
/// and reported in [`Rollback::skipped`] for the caller to warn about.
/// Leaving a bad patch applied and saying so is recoverable; silently
/// destroying a good one is not.
pub fn revert_record_with_baseline(
    repo: &Path,
    baseline: &Baseline,
    protected: &std::collections::BTreeMap<String, i64>,
) -> Rollback {
    let mut restorable = Vec::new();
    let mut skipped = Vec::new();
    for file in baseline.keys() {
        match protected.get(file) {
            Some(kept_by) => skipped.push((file.clone(), *kept_by)),
            None => restorable.push(file.clone()),
        }
    }
    Rollback {
        restored: bc_diffcapture::revert_all(repo, &restorable, baseline),
        skipped,
    }
}

/// Every file a finding at `position` must NOT have restored, because a
/// finding processed LATER in the same sequential S10 walk also touched it
/// and that later patch is still applied — mapped to the later finding's
/// index so the warning can name it.
///
/// "Later" is by position in `outcomes` (S10's own processing order),
/// deliberately not by `finding_index` (the report ordinal), because
/// `--top` selects by CVSS and the two orders differ. "Still applied" is
/// `diff.is_some() && !was_reverted(..)` — the same two facts everything
/// else in this crate reads a kept patch off.
///
/// `baselines` is [`RemediationRun::baselines`], aligned 1:1 with
/// `outcomes`; an entry with no baseline (a `--resume`d record, a failed
/// finding) contributes nothing, which is the safe direction: it can only
/// cause a rollback to proceed that a baseline might have blocked, and
/// such a record has no *kept* on-disk patch of its own to protect.
pub fn files_kept_by_later_findings(
    outcomes: &[RemediationOutcome],
    baselines: &[Option<Baseline>],
    position: usize,
) -> std::collections::BTreeMap<String, i64> {
    let mut protected = std::collections::BTreeMap::new();
    for (i, outcome) in outcomes.iter().enumerate().skip(position + 1) {
        let RemediationOutcome::Processed(record) = outcome else {
            continue;
        };
        if record.diff.is_none() || was_reverted(record) {
            continue;
        }
        let Some(Some(baseline)) = baselines.get(i) else {
            continue;
        };
        for file in baseline.keys() {
            protected
                .entry(file.clone())
                .or_insert(record.finding_index);
        }
    }
    protected
}

/// The operator-facing account of one rollback, for a caller to print.
/// Split into warnings and a plain line because the two mean opposite
/// things: a warning says the tree is still modified in a way nobody
/// asked for, and must not be buried in routine output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RollbackReport {
    pub warnings: Vec<String>,
    /// `Some(_)` only when files were genuinely restored.
    pub restored: Option<String>,
}

/// The whole "S11 graded this fix bad, undo it" action in one place:
/// restore from the finding's own baseline where that is safe, fall back
/// to git where there is no baseline, record what happened on `record`,
/// and hand back the lines the caller should print.
///
/// Shared by `bc_orchestrator::remediate` (the `--top` batch walk) and
/// `bc_interactive`'s picker so a fix chosen by hand is held to exactly
/// the same standard as one chosen by CVSS — and, more importantly, so
/// the two cannot drift on the one question that matters here: whether a
/// bad patch is actually off the disk. The `keep_unverified` opt-out and
/// the `Not Fixed`/`UNVERIFIABLE` test stay with the callers, which are
/// the ones that depend on `bc-validation-scoring`; this function is
/// reached only once that decision is made. `status` is the grade, quoted
/// verbatim in the note.
///
/// See [`revert_record_with_baseline`] for what `protected` is for, and
/// [`note_record_reverted`] for why the diff is cleared only when
/// something was really restored.
pub fn revert_after_failed_validation(
    repo: &Path,
    record: &mut RemediationRecord,
    baseline: Option<&Baseline>,
    protected: &std::collections::BTreeMap<String, i64>,
    status: &str,
) -> RollbackReport {
    let mut report = RollbackReport::default();
    // An empty baseline means "the agent touched nothing", not "no
    // baseline was carried" — either way there is nothing to restore, and
    // the git fallback would find nothing to do either.
    let Some(baseline) = baseline.filter(|b| !b.is_empty()) else {
        match revert_record(repo, record) {
            Ok(reverted) if reverted.is_empty() => {}
            Ok(reverted) => {
                report.restored = Some(format!(
                    "rolled back finding {} ({status}) via git: {}",
                    record.finding_id,
                    reverted.join(", ")
                ));
                note_record_reverted(
                    record,
                    &format!(
                        "S11 validation graded this fix '{status}', so its {} file(s) were \
                         restored from git.",
                        reverted.len()
                    ),
                    true,
                );
            }
            Err(e) => report.warnings.push(e),
        }
        return report;
    };

    let rollback = revert_record_with_baseline(repo, baseline, protected);
    for (file, kept_by) in &rollback.skipped {
        report.warnings.push(format!(
            "not rolling back {file} for finding {}: finding {kept_by}'s kept fix also touched \
             it — that patch is still applied",
            record.finding_index
        ));
    }
    if rollback.restored.is_empty() && rollback.skipped.is_empty() {
        return report;
    }
    if !rollback.restored.is_empty() {
        report.restored = Some(format!(
            "rolled back finding {} ({status}): {}",
            record.finding_id,
            rollback.restored.join(", ")
        ));
    }
    note_record_reverted(
        record,
        &rollback_note(status, &rollback),
        !rollback.restored.is_empty(),
    );
    report
}

/// The human-readable half of an S11 rollback, recorded on the record so
/// the report, `--out-remediation-json` and any PR comment all say the
/// same thing about what is actually on disk — including the awkward case
/// where part of the patch had to be left applied.
fn rollback_note(status: &str, rollback: &Rollback) -> String {
    let mut note = format!(
        "S11 validation graded this fix '{status}', so {} file(s) were restored from this \
         finding's own pre-remediation baseline.",
        rollback.restored.len()
    );
    if !rollback.skipped.is_empty() {
        let held: Vec<String> = rollback
            .skipped
            .iter()
            .map(|(file, kept_by)| format!("{file} (finding {kept_by})"))
            .collect();
        note.push_str(&format!(
            " {} file(s) were deliberately LEFT APPLIED because a later finding's kept fix also \
             edited them and restoring would have destroyed it: {}. Review those by hand.",
            rollback.skipped.len(),
            held.join(", ")
        ));
    }
    note
}

/// Marks `record` as rolled back after the fact: the same
/// [`REVERT_NOTE_PREFIX`] note S10's own gates leave (so
/// [`was_reverted`] answers `true` for it downstream) plus, when
/// something was genuinely restored, `diff = None`.
///
/// Clearing the diff is what stops `--out-remediation-json` /
/// `--post-fixes-from` from posting a "Suggested fix" comment for a patch
/// that is no longer on disk — precisely what S10's own gates already do
/// at every rollback point (`record_diff = None`), so a fix undone by S11
/// and a fix undone by the syntax gate look the same to every consumer.
///
/// `restored_any` is deliberately a parameter rather than assumed: when
/// every file was held back by a later finding's kept fix, the patch IS
/// still applied, and blanking the diff would erase the only record of a
/// real on-disk change. In that case the note explains what happened and
/// the diff stays.
pub fn note_record_reverted(record: &mut RemediationRecord, reason: &str, restored_any: bool) {
    note_revert(&mut record.verdict, reason);
    if restored_any {
        record.diff = None;
    }
}

/// Rolls back the files a `RemediationRecord` says it changed, for a
/// caller that has no per-finding baseline to work from — a `--resume`d
/// record loaded straight out of a checkpoint (its baseline lives only in
/// the process that created it) or a record read back off disk.
///
/// The FALLBACK, not the primary path: prefer
/// [`revert_record_with_baseline`], which is byte-exact and needs no VCS.
/// Git-only, necessarily — with no snapshot there is no other baseline to
/// restore from. Tracked files are `git checkout --`'d back to HEAD;
/// untracked ones the agent created are deleted. On a non-git target this
/// is an `Err` the caller should surface as a warning rather than a
/// failure — there is genuinely nothing that can be done, and the run's
/// other output is still valid.
///
/// Reverting to HEAD (not to a pre-agent snapshot) means a file the user
/// already had uncommitted edits in would lose them. Callers reach this
/// only for a finding S11 graded `Not Fixed`/`UNVERIFIABLE`, i.e. one
/// whose patch is known bad, and only for the files that finding's own
/// record claims — but the difference from `bc_diffcapture::revert_all`'s exact
/// rollback is real, and it is why S10's in-loop gates are the primary
/// mechanism and this is the backstop.
pub fn revert_record(repo: &Path, record: &RemediationRecord) -> Result<Vec<String>, String> {
    let files: Vec<String> = record
        .verdict
        .changes
        .iter()
        .map(|c| c.file.clone())
        .filter(|f| !f.is_empty())
        .collect();
    if files.is_empty() {
        return Ok(Vec::new());
    }
    if !bc_diffcapture::is_git_worktree(repo) {
        return Err(format!(
            "cannot roll back finding {}: {} is not a git repository, so there is no baseline \
             to restore from — the patch is still applied",
            record.finding_index,
            repo.display()
        ));
    }
    bc_diffcapture::revert(repo, &files, &bc_diffcapture::Snapshot::default())
}

/// The unified diff for the actual files THIS finding's fix touched —
/// distinct from the post-gate's own, more
/// broadly-scoped `diff`/`diff_scope` above (which also sweeps in
/// incidental worktree changes purely to police forbidden-path
/// touches). Computed fresh at each `RemediationRecord` return point so
/// it always reflects the observed write set as it stands at that point.
/// The write journal and the post-agent worktree delta supply that set;
/// `RemediationVerdict::changes` is deliberately not trusted for it.
fn capture_diff(
    repo: &Path,
    before: &bc_diffcapture::Snapshot,
    files: &[String],
) -> Option<String> {
    if files.is_empty() {
        return None;
    }
    bc_diffcapture::capture_git_diff(repo, files)
        .or_else(|| bc_diffcapture::synth_unified_diff(repo, before, files))
}

/// How much of an unparseable agent response to quote back in the
/// verdict summary.
const UNPARSEABLE_EXCERPT_CHARS: usize = 200;

/// A short, single-lined, secret-scrubbed opening of a response that
/// would not parse, for the verdict summary.
///
/// Without this, a parse failure is undiagnosable after the fact: the
/// 2026-09-03 field failure recorded only serde's "key must be a string
/// at line 1 column 2", which says the response was malformed but not
/// how, and the text itself was never written anywhere. This summary
/// reaches `remediation.json` and can reach a PR comment, and the
/// response may quote source code — a `secret_exposure` finding's answer
/// would quote the credential — so it goes through [`bc_redact::redact`]
/// before being truncated.
fn unparseable_excerpt(text: &str) -> String {
    let scrubbed = bc_redact::redact(text.trim());
    let flattened = scrubbed.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.is_empty() {
        return "<empty response>".to_string();
    }
    let kept: String = flattened.chars().take(UNPARSEABLE_EXCERPT_CHARS).collect();
    if flattened.chars().count() > UNPARSEABLE_EXCERPT_CHARS {
        format!("{kept}… (truncated)")
    } else {
        kept
    }
}

/// The agent asserted a fix. Its file list is an annotation and can be
/// absent or incomplete, so it does not determine whether an asserted fix
/// requires independent on-disk evidence.
fn claims_a_fix(verdict: &RemediationVerdict) -> bool {
    matches!(verdict.verdict, Verdict::Fixed | Verdict::PartiallyFixed)
}

/// `true` when `diff` describes a real on-disk change. Checks the
/// CONTENT, not just `Some`: `capture_git_diff` legitimately returns
/// `Some("")` when the claimed files produce a real, empty `git diff`,
/// which is precisely the "claimed a fix but wrote nothing" signal.
fn diff_has_content(diff: &Option<String>) -> bool {
    diff.as_deref().is_some_and(|d| !d.trim().is_empty())
}

/// Deterministic ground truth overriding the agent's own self-report: if
/// `verdict` claims `Fixed`/`PartiallyFixed`, but `diff` shows no actual
/// on-disk change, the agent
/// narrated success without a tool call that actually persisted — found
/// live (gpt-4o, real remediation runs against real findings): a "Fixed"
/// verdict naming a specific file+summary, for a file that was never
/// modified on disk. The system prompt now also tells the agent to read
/// its own edit back before claiming success, but an LLM's own
/// confirmation is never unimpeachable the way a real computed diff is —
/// matching this project's established "trust but verify" precedent
/// elsewhere (S1's deterministic repo walk validating the LLM's own
/// output, S6's adversarial verification), the computed diff here is the
/// actual backstop, not the prompt text alone.
///
/// This remains the LAST word even with
/// [`Step10Config::retry_unapplied_fix`] on: the retry gets the agent one
/// more chance to actually write the fix it described, and if that second
/// attempt also writes nothing, this downgrade lands exactly as it did
/// before the retry existed.
fn reconcile_verdict_with_diff(verdict: &mut RemediationVerdict, diff: &Option<String>) {
    if diff_has_content(diff) || !claims_a_fix(verdict) {
        return;
    }
    let note = "Downgraded from the agent's own reported verdict: it described a \
                fix, but no corresponding on-disk change was found, so it was \
                never actually applied."
        .to_string();
    verdict.verdict = Verdict::NeedsReview;
    verdict.remaining_risks.push(note.clone());
    verdict.summary = if verdict.summary.is_empty() {
        note
    } else {
        format!("{} {note}", verdict.summary)
    };
}

fn action_label(action: bc_policy_gate::Action) -> &'static str {
    match action {
        bc_policy_gate::Action::Patch => "patch",
        bc_policy_gate::Action::GuidanceOnly => "guidance_only",
    }
}

/// One finding's checkpoint-aware remediation, ported from
/// `remediation_agent/runner.py::remediate_one` (shared by both the
/// sequential `--top` walk in [`run_remediation`] and the `-i`/
/// `--interactive` picker, which needs to remediate exactly one
/// user-selected finding at a time): when `resume` is true and a
/// checkpoint's stored [`finding_identity`] matches the current finding
/// at that position, the finding is skipped (no agent call) and the
/// cached record is returned as-is. A successfully-processed finding is
/// always saved to `checkpoint` (if given) regardless of `resume`, so a
/// *later* run (or a later pick, in the interactive picker) can resume
/// from it.
#[allow(clippy::too_many_arguments)]
pub async fn remediate_one_checkpointed(
    client: &dyn LlmClient,
    tools: &dyn ToolExecutor,
    repo: &Path,
    finding_index: i64,
    finding: &RankedFinding,
    config: &Step10Config,
    policy: Option<&PolicyContext>,
    checkpoint: Option<&dyn CheckpointStore>,
    run_id: &str,
    resume: bool,
) -> (RemediationOutcome, Option<Baseline>) {
    // Ahead of BOTH the checkpoint read and the agent call, so a record
    // saved by an earlier, differently-scoped run can never resurrect a
    // fix for a file this run is fenced off from — and so nothing is
    // saved for a finding this run declined to touch. The same gate lives
    // inside `remediate_finding_with_baseline` for callers that reach it
    // directly; neither is redundant, since `--resume` short-circuits
    // before that one is ever consulted.
    if let Some(reason) = config.diff_scope.refusal(&finding.finding.file) {
        let record = out_of_diff_scope_record(
            finding_index,
            bc_sarif::finding_id(&finding.finding),
            &reason,
        );
        return (RemediationOutcome::Processed(Box::new(record)), None);
    }

    let step = remediation_step_key(config, finding_index, finding);
    let fid = finding_identity(finding_index, finding);

    if resume {
        if let Some(cached) =
            checkpoint.and_then(|s| load_cached_record(s, run_id, &step, &fid, config))
        {
            // No baseline: the snapshot lives in memory only and belongs to
            // whichever process originally ran this finding. A caller that
            // later needs to undo this record falls back to
            // `revert_record`'s git path — see
            // `remediate_finding_with_baseline`.
            return (RemediationOutcome::Processed(Box::new(cached)), None);
        }
    }

    let result = remediate_finding_with_baseline(
        client,
        tools,
        repo,
        finding,
        finding_index,
        config,
        policy,
    )
    .await;
    match result {
        Ok((record, baseline)) => {
            // A rolled-back record is deliberately NOT checkpointed. The
            // checkpoint means "this finding is done"; `--resume` skips
            // anything it can load. Saving one for a patch that a safety
            // gate just removed from disk would make the next `--resume`
            // run walk straight past a finding that is still unfixed — the
            // exact way a bad fix used to become a permanently skipped one.
            if let Some(store) = checkpoint {
                if !was_reverted(&record) {
                    save_checkpoint(store, run_id, &step, &fid, config, &record);
                }
            }
            (
                RemediationOutcome::Processed(Box::new(record)),
                Some(baseline),
            )
        }
        Err(e) => (
            RemediationOutcome::Failed {
                finding_index,
                error: e.to_string(),
            },
            // The agentic loop's own error path already rolled everything
            // it had written back, so there is nothing left for a caller to
            // undo and no baseline to undo it from.
            None,
        ),
    }
}

/// Walks `findings` sequentially, remediating each one — a bad finding
/// never aborts the run, it's just recorded as [`RemediationOutcome::Failed`].
/// `findings` should already reflect whatever `--top`/CVSS-based
/// selection the caller wants; this function processes exactly the
/// slice it's given, in order.
///
/// See [`remediate_one_checkpointed`] for `checkpoint`/`run_id`/`resume`'s
/// exact semantics — this is just that function called once per finding.
#[allow(clippy::too_many_arguments)]
pub async fn run_remediation(
    client: &dyn LlmClient,
    tools: &dyn ToolExecutor,
    repo: &Path,
    findings: &[(i64, RankedFinding)],
    config: &Step10Config,
    policy: Option<&PolicyContext>,
    checkpoint: Option<&dyn CheckpointStore>,
    run_id: &str,
    resume: bool,
) -> RemediationRun {
    let mut run = RemediationRun {
        outcomes: Vec::with_capacity(findings.len()),
        baselines: Vec::with_capacity(findings.len()),
    };
    // Engine-keyed rows are never overwritten by a run under another
    // model; they stop being found. Clear the ones no finding of THIS run
    // claims, so they neither pile up nor come back if the operator later
    // switches to the old model again (`prune_stale_steps` in Python).
    // Batch walk only: the interactive picker remediates one finding at a
    // time and cannot know the live set.
    if let Some(store) = checkpoint {
        let live: Vec<String> = findings
            .iter()
            .map(|(index, finding)| remediation_step_key(config, *index, finding))
            .collect();
        let pruned = store
            .prune_stale(run_id, REMEDIATE_STEP_PREFIX, &live)
            .len();
        if pruned > 0 {
            tracing::info!(
                "[ckpt] pruned {pruned} stale {REMEDIATE_STEP_PREFIX}* checkpoint row(s), \
                 written by an earlier engine, model or finding set"
            );
        }
    }
    for (finding_index, finding) in findings {
        // A canceled run starts no further finding. Each one not reached
        // is still recorded, as a failure naming the cancellation, so the
        // outcomes stay one per selected finding and nothing reads as fixed.
        if let Some(reason) = bc_pipeline_core::canceled(config.cancel.as_ref()) {
            run.outcomes.push(RemediationOutcome::Failed {
                finding_index: *finding_index,
                error: format!("not attempted: {reason}"),
            });
            run.baselines.push(None);
            continue;
        }
        let (outcome, baseline) = remediate_one_checkpointed(
            client,
            tools,
            repo,
            *finding_index,
            finding,
            config,
            policy,
            checkpoint,
            run_id,
            resume,
        )
        .await;
        run.outcomes.push(outcome);
        run.baselines.push(baseline);
    }
    run
}

/// How one S10 walk turned out, in the terms a progress line or an exit
/// code needs. Computed from outcomes, so it reflects every later rollback
/// (an S11 revert marks the record, and the fix stops counting).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RemediationCounts {
    /// Every finding the walk was given.
    pub attempted: usize,
    /// Processed, verdict `Fixed`, a non-empty diff, and not rolled back:
    /// a fix that is actually on disk (or, in a dry run, captured).
    pub fixed: usize,
    /// Processed but not [`Self::fixed`]: declined, denied, out of scope,
    /// rolled back, or answered with anything but `Fixed`.
    pub not_fixed: usize,
    /// The agentic call itself failed ([`RemediationOutcome::Failed`]).
    pub failed: usize,
}

impl RemediationCounts {
    pub fn from_outcomes(outcomes: &[RemediationOutcome]) -> Self {
        let mut counts = RemediationCounts {
            attempted: outcomes.len(),
            ..RemediationCounts::default()
        };
        for outcome in outcomes {
            match outcome {
                RemediationOutcome::Processed(record) if is_kept_fix(record) => counts.fixed += 1,
                RemediationOutcome::Processed(_) => counts.not_fixed += 1,
                RemediationOutcome::Failed { .. } => counts.failed += 1,
            }
        }
        counts
    }
}

/// `true` when `record` is a fix that stands: verdict `Fixed`, a diff
/// with content, and no rollback note.
pub fn is_kept_fix(record: &RemediationRecord) -> bool {
    record.verdict.verdict == Verdict::Fixed
        && diff_has_content(&record.diff)
        && !was_reverted(record)
}

/// [`run_remediation`]'s full result: one outcome per finding, plus each
/// finding's own pre-remediation baseline aligned 1:1 with it.
///
/// The two are parallel vectors rather than a baseline field on
/// [`RemediationOutcome`] for one reason: `RemediationOutcome`'s
/// `Processed` payload is a [`RemediationRecord`], which is `Serialize` +
/// `Deserialize` and travels into `--resume` checkpoints,
/// `--out-remediation-json` and PR comments. A baseline is raw pre-edit
/// file content — a process-lifetime rollback aid, not an artifact — and
/// must never be written anywhere. Keeping it structurally outside the
/// serialized type makes that impossible to get wrong by accident, and
/// index alignment (not `finding_index` keying) is what preserves S10's
/// processing ORDER, which [`files_kept_by_later_findings`] depends on.
#[derive(Debug, Default)]
pub struct RemediationRun {
    pub outcomes: Vec<RemediationOutcome>,
    pub baselines: Vec<Option<Baseline>>,
}

#[cfg(test)]
mod tests;
