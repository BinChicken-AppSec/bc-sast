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

use appsec_checkpoint::CheckpointStore;
use appsec_llm_agentic::{run_agentic, AgenticConfig};
use appsec_llm_client::{LlmClient, LlmError, ToolExecutor};
use appsec_model::RankedFinding;
use appsec_policy_gate::{Decision, Playbook, RemediationGate, Strategy};
use serde::{Deserialize, Serialize};

use checkpoint::{load_cached_record, save_checkpoint};

pub use checkpoint::{
    checkpoint_done, finding_identity, remediation_step_key, REMEDIATE_STEP_PREFIX,
};
pub use select::{band_score, parse_top_spec, resolve_top, select_top_by_cvss, TopSpec};
pub use verdict::{Change, GateStatus, Gates, RemediationVerdict, Verdict};
pub use workflow_gate::UNSAFE_WORKFLOW_REFERENCE;

pub use appsec_diffcapture::Snapshot as Baseline;

#[derive(Debug, Clone)]
pub struct Step10Config {
    pub model: String,
    pub max_turns: u32,
    pub allowed_tools: Vec<String>,
    pub fix_mode: bool,
    pub max_transient_retries: u32,
    pub max_context_shrinks: u32,
    pub retry_backoff_base: std::time::Duration,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
    pub reasoning_effort: Option<appsec_llm_client::ReasoningEffort>,
    pub openai_api: Option<appsec_llm_client::OpenAiApi>,
    pub timeout_secs: Option<u64>,

    pub syntax_check: bool,
    pub keep_unverified: bool,
    pub max_diff_lines: usize,
    pub max_files_touched: usize,
    pub dry_run: bool,
    pub verify_command: Option<String>,
    pub verify_timeout_secs: u64,
    pub retry_unapplied_fix: bool,
    pub journal: Option<appsec_sandbox_tools::WriteJournal>,
    pub target_test_context: Option<String>,
    pub diff_scope: appsec_model::DiffScope,
    pub dialect: String,
    pub base_host: String,
    pub cancel: Option<appsec_pipeline_core::CancelTokenRef>,
}

impl Step10Config {
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
            diff_scope: appsec_model::DiffScope::inactive(),
            dialect: String::new(),
            base_host: String::new(),
            cancel: None,
        }
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationRecord {
    pub finding_index: i64,
    pub finding_id: String,
    pub verdict: RemediationVerdict,
    pub policy_action: Option<String>,
    pub policy_reason: Option<String>,
    pub final_verdict: Option<String>,
    pub policy_reverted: Vec<String>,
    pub policy_matched_globs: Vec<String>,
    pub diff: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RemediationOutcome {
    Processed(Box<RemediationRecord>),
    Failed { finding_index: i64, error: String },
}

fn getenv(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn render_finding_body(finding: &RankedFinding) -> String {
    appsec_report_md::render_findings(std::slice::from_ref(finding)).join("\n")
}

fn pre_decision(
    policy: &PolicyContext,
    cwe: Option<&str>,
    file: &str,
) -> (Decision, Option<Strategy>) {
    let decision = policy.gate.decide(cwe.unwrap_or(""), file, &getenv);
    let strategy = if decision.may_generate_patch() {
        let lang = appsec_policy_gate::language_for(file);
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

pub const OUT_OF_DIFF_SCOPE_ACTION: &str = "out_of_diff_scope";

pub fn was_out_of_diff_scope(record: &RemediationRecord) -> bool {
    record.policy_action.as_deref() == Some(OUT_OF_DIFF_SCOPE_ACTION)
}

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
    let finding_id = appsec_sarif::finding_id(&finding.finding);

    if let Some(reason) = config.diff_scope.refusal(&file) {
        return Ok((
            out_of_diff_scope_record(finding_index, finding_id, &reason),
            Baseline::default(),
        ));
    }

    let pre = policy.map(|p| pre_decision(p, cwe.as_deref(), &file));

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

    if let Some(journal) = &config.journal {
        journal.clear();
    }

    let mut snap_targets: Vec<String> = if file.is_empty() {
        Vec::new()
    } else {
        vec![file.clone()]
    };
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
    let mut before = appsec_diffcapture::snapshot_files(repo, &snap_targets);
    let dirty_before: BTreeSet<String> = appsec_diffcapture::changed_files_whole_tree(repo)
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
            let touched = agent_touched_files(repo, config, &mut before, &dirty_before, &[]);
            appsec_diffcapture::revert_all(repo, &touched, &before);
            return Err(e);
        }
    };
    let mut verdict = coerce_answer(&first_answer, finding_index);

    let mut carried_over: Vec<String> = Vec::new();
    if config.retry_unapplied_fix {
        let claimed_files = claimed_files(&verdict);
        if !claimed_files.is_empty()
            && describes_an_unwritten_fix(repo, config, &mut before, &verdict)
        {
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
                        let touched = dedup_preserve_order(carried_over.into_iter().chain(
                            agent_touched_files(repo, config, &mut before, &dirty_before, &[]),
                        ));
                        appsec_diffcapture::revert_all(repo, &touched, &before);
                        return Err(e);
                    }
                };
            verdict = coerce_answer(&second_answer, finding_index);
            note_retry(&mut verdict, &claimed_files);
        }
    }

    let claimed = claimed_files(&verdict);
    let whole_tree = appsec_diffcapture::changed_files_whole_tree(repo);
    let touched = dedup_preserve_order(carried_over.iter().cloned().chain(agent_touched_files(
        repo,
        config,
        &mut before,
        &dirty_before,
        &claimed,
    )));
    let baseline = before.subset(&touched);

    let mut policy_action = None;
    let mut policy_reason = None;
    let mut final_verdict: Option<String> = None;
    let mut policy_reverted: Vec<String> = Vec::new();
    let mut policy_matched_globs: Vec<String> = Vec::new();
    if let Some((decision, _)) = &pre {
        policy_action = Some(action_label(decision.action).to_string());
        policy_reason = Some(decision.reason.clone());
    }

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
        let diff = appsec_diffcapture::capture_git_diff(repo, &diff_scope)
            .or_else(|| appsec_diffcapture::synth_unified_diff(repo, &before, &diff_scope));
        let diff_files = appsec_policy_gate::inspect_diff(diff.as_deref());
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
            let gates_passed =
                verdict.gates.all_pass() && claims_a_fix(&verdict) && diff_has_content(&diff);
            final_verdict =
                Some(appsec_policy_gate::cap_verdict(decision.action, gates_passed).to_string());
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
                if let Ok(rolled) =
                    appsec_diffcapture::revert(repo, std::slice::from_ref(f), &before)
                {
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

    let unsafe_refs = workflow_gate::unsafe_workflow_refs(repo, &before, &touched);
    if !unsafe_refs.is_empty() {
        let rolled_back = appsec_diffcapture::revert_all(repo, &touched, &before);
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
            .retain(|c| !unsafe_refs.contains_key(&appsec_diffcapture::norm_path(&c.file)));
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

    if config.syntax_check {
        if let Some(broken) = first_unparseable(repo, &touched) {
            let rolled_back = appsec_diffcapture::revert_all(repo, &touched, &before);
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

    if let Some(command) = &config.verify_command {
        if let Err(detail) = run_verify_command(
            repo,
            command,
            config.verify_timeout_secs,
            config.cancel.as_ref(),
        )
        .await
        {
            let rolled_back = appsec_diffcapture::revert_all(repo, &touched, &before);
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

    let mut record_diff = capture_diff(repo, &before, &touched);
    let asserted_fix = claims_a_fix(&verdict);
    reconcile_verdict_with_diff(&mut verdict, &record_diff);
    if asserted_fix && verdict.verdict == Verdict::NeedsReview && pre.is_some() {
        final_verdict = Some("REJECT".to_string());
    }

    if let Some(reason) = over_size_cap(repo, &before, &touched, config) {
        let rolled_back = appsec_diffcapture::revert_all(repo, &touched, &before);
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
        let rolled_back = appsec_diffcapture::revert_all(repo, &touched, &before);
        note_revert(
            &mut verdict,
            &format!(
                "dry run: the patch was captured and then rolled back \
                 ({} file(s) restored); nothing was left applied.",
                rolled_back.len()
            ),
        );
    } else if !matches!(verdict.verdict, Verdict::Fixed) && !config.keep_unverified {
        let rolled_back = appsec_diffcapture::revert_all(repo, &touched, &before);
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

pub const NO_DIFF_CAPTURED: &str = "no_diff_captured";

fn coerce_answer(answer: &str, finding_index: i64) -> RemediationVerdict {
    match appsec_json_repair::extract_json(answer) {
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

fn claimed_files(verdict: &RemediationVerdict) -> Vec<String> {
    verdict
        .changes
        .iter()
        .map(|c| c.file.clone())
        .filter(|f| !f.is_empty())
        .collect()
}

fn describes_an_unwritten_fix(
    repo: &Path,
    config: &Step10Config,
    before: &mut appsec_diffcapture::Snapshot,
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

fn agent_touched_files(
    repo: &Path,
    config: &Step10Config,
    before: &mut appsec_diffcapture::Snapshot,
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
    let newly_dirty: Vec<String> = appsec_diffcapture::changed_files_whole_tree(repo)
        .into_iter()
        .filter(|f| !dirty_before.contains(f))
        .collect();
    let backed: Vec<String> = claimed
        .iter()
        .map(|f| appsec_diffcapture::norm_path(f))
        .filter(|f| before.get(f).is_some())
        .collect();
    dedup_preserve_order(journalled.into_iter().chain(newly_dirty).chain(backed))
}

pub const REVERT_NOTE_PREFIX: &str = "Rolled back by an S10 safety gate:";

pub fn revert_reason(record: &RemediationRecord) -> Option<&str> {
    record
        .verdict
        .remaining_risks
        .iter()
        .find_map(|r| r.strip_prefix(REVERT_NOTE_PREFIX))
        .map(str::trim)
}

pub fn was_reverted(record: &RemediationRecord) -> bool {
    revert_reason(record).is_some()
}

fn note_revert(verdict: &mut RemediationVerdict, reason: &str) {
    let note = format!("{REVERT_NOTE_PREFIX} {reason}");
    verdict.remaining_risks.push(note.clone());
    verdict.summary = if verdict.summary.is_empty() {
        note
    } else {
        format!("{} {note}", verdict.summary)
    };
}

fn first_unparseable(repo: &Path, touched: &[String]) -> Option<String> {
    touched.iter().find_map(|rel| {
        let resolved = appsec_pathjail::confine(repo, rel)?;
        let bytes = std::fs::read(&resolved).ok()?;
        (appsec_repo_analysis::syntax_check(Path::new(rel.as_str()), &bytes) == Some(true))
            .then(|| rel.clone())
    })
}

fn over_size_cap(
    repo: &Path,
    before: &appsec_diffcapture::Snapshot,
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
    let diff = appsec_diffcapture::capture_git_diff(repo, touched)
        .or_else(|| appsec_diffcapture::synth_unified_diff(repo, before, touched))
        .unwrap_or_default();
    let changed = changed_line_count(&diff);
    (changed > config.max_diff_lines).then(|| {
        format!(
            "the patch changed {changed} line(s), over the max_diff_lines limit of {}",
            config.max_diff_lines
        )
    })
}

fn changed_line_count(diff: &str) -> usize {
    diff.lines()
        .filter(|l| {
            (l.starts_with('+') && !l.starts_with("+++"))
                || (l.starts_with('-') && !l.starts_with("---"))
        })
        .count()
}

async fn run_verify_command(
    repo: &Path,
    command: &str,
    timeout_secs: u64,
    cancel: Option<&appsec_pipeline_core::CancelTokenRef>,
) -> Result<(), String> {
    run_verify_command_with_shell(repo, VERIFY_SHELL, command, timeout_secs, cancel).await
}

const VERIFY_SHELL: &str = "sh";

async fn run_verify_command_with_shell(
    repo: &Path,
    shell: &str,
    command: &str,
    timeout_secs: u64,
    cancel: Option<&appsec_pipeline_core::CancelTokenRef>,
) -> Result<(), String> {
    use verify_process::GroupRun;
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

const VERIFY_OUTPUT_LINES: usize = 40;

fn tail_lines(text: &str, max: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(max)..].join("\n")
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rollback {
    pub restored: Vec<String>,
    pub skipped: Vec<(String, i64)>,
}

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
        restored: appsec_diffcapture::revert_all(repo, &restorable, baseline),
        skipped,
    }
}

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RollbackReport {
    pub warnings: Vec<String>,
    pub restored: Option<String>,
}

pub fn revert_after_failed_validation(
    repo: &Path,
    record: &mut RemediationRecord,
    baseline: Option<&Baseline>,
    protected: &std::collections::BTreeMap<String, i64>,
    status: &str,
) -> RollbackReport {
    let mut report = RollbackReport::default();
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

pub fn note_record_reverted(record: &mut RemediationRecord, reason: &str, restored_any: bool) {
    note_revert(&mut record.verdict, reason);
    if restored_any {
        record.diff = None;
    }
}

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
    if !appsec_diffcapture::is_git_worktree(repo) {
        return Err(format!(
            "cannot roll back finding {}: {} is not a git repository, so there is no baseline \
             to restore from — the patch is still applied",
            record.finding_index,
            repo.display()
        ));
    }
    appsec_diffcapture::revert(repo, &files, &appsec_diffcapture::Snapshot::default())
}

fn capture_diff(
    repo: &Path,
    before: &appsec_diffcapture::Snapshot,
    files: &[String],
) -> Option<String> {
    if files.is_empty() {
        return None;
    }
    appsec_diffcapture::capture_git_diff(repo, files)
        .or_else(|| appsec_diffcapture::synth_unified_diff(repo, before, files))
}

const UNPARSEABLE_EXCERPT_CHARS: usize = 200;

fn unparseable_excerpt(text: &str) -> String {
    let scrubbed = appsec_redact::redact(text.trim());
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

fn claims_a_fix(verdict: &RemediationVerdict) -> bool {
    matches!(verdict.verdict, Verdict::Fixed | Verdict::PartiallyFixed)
}

fn diff_has_content(diff: &Option<String>) -> bool {
    diff.as_deref().is_some_and(|d| !d.trim().is_empty())
}

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

fn action_label(action: appsec_policy_gate::Action) -> &'static str {
    match action {
        appsec_policy_gate::Action::Patch => "patch",
        appsec_policy_gate::Action::GuidanceOnly => "guidance_only",
    }
}

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
    if let Some(reason) = config.diff_scope.refusal(&finding.finding.file) {
        let record = out_of_diff_scope_record(
            finding_index,
            appsec_sarif::finding_id(&finding.finding),
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
            None,
        ),
    }
}

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
        if let Some(reason) = appsec_pipeline_core::canceled(config.cancel.as_ref()) {
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RemediationCounts {
    pub attempted: usize,
    pub fixed: usize,
    pub not_fixed: usize,
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

pub fn is_kept_fix(record: &RemediationRecord) -> bool {
    record.verdict.verdict == Verdict::Fixed
        && diff_has_content(&record.diff)
        && !was_reverted(record)
}

#[derive(Debug, Default)]
pub struct RemediationRun {
    pub outcomes: Vec<RemediationOutcome>,
    pub baselines: Vec<Option<Baseline>>,
}

#[cfg(test)]
mod tests;
