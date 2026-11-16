mod checkpoint;
mod evidence;
mod hints;
mod prompts;

pub use checkpoint::{validation_step_key, VALIDATE_STEP_PREFIX};
pub use hints::hints_path;

use appsec_checkpoint::CheckpointStore;
use appsec_llm_agentic::{run_agentic, AgenticConfig};
use appsec_llm_client::{LlmClient, LlmError, ToolExecutor};
use appsec_model::RankedFinding;
use appsec_stage_s10::RemediationRecord;
use appsec_validation_scoring::{
    score_fix, GateName, GateResult, GateStatus, SynthesisConfidence, ValidationScore,
};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Step11Config {
    pub model: String,
    pub max_turns: u32,
    pub allowed_tools: Vec<String>,
    pub max_transient_retries: u32,
    pub max_context_shrinks: u32,
    pub retry_backoff_base: std::time::Duration,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
    pub reasoning_effort: Option<appsec_llm_client::ReasoningEffort>,
    pub openai_api: Option<appsec_llm_client::OpenAiApi>,
    pub timeout_secs: Option<u64>,
    pub max_findings: Option<usize>,
    pub allow_repo_hints: bool,
    pub security_architect_model: Option<String>,
    pub penetration_tester_model: Option<String>,
    pub cross_repo_analyzer_model: Option<String>,
    pub cross_repo_analyzer: bool,
    pub fact_tools: bool,
    pub split_ties_score: bool,
    pub dialect: String,
    pub base_host: String,
}

impl Step11Config {
    pub fn new(model: impl Into<String>) -> Self {
        Step11Config {
            model: model.into(),
            max_turns: 50,
            allowed_tools: ["Read", "Glob", "Grep"]
                .into_iter()
                .chain(appsec_sandbox_tools::FACT_TOOL_NAMES)
                .map(String::from)
                .collect(),
            max_transient_retries: 4,
            max_context_shrinks: 16,
            retry_backoff_base: std::time::Duration::from_secs(10),
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: Some(appsec_llm_client::ReasoningEffort::High),
            openai_api: None,
            timeout_secs: None,
            max_findings: Some(20),
            allow_repo_hints: false,
            security_architect_model: None,
            penetration_tester_model: None,
            cross_repo_analyzer_model: None,
            cross_repo_analyzer: false,
            fact_tools: true,
            split_ties_score: true,
            dialect: String::new(),
            base_host: String::new(),
        }
    }
}

fn effective_allowed_tools(config: &Step11Config) -> Vec<String> {
    if config.fact_tools {
        return config.allowed_tools.clone();
    }
    config
        .allowed_tools
        .iter()
        .filter(|name| !appsec_sandbox_tools::FACT_TOOL_NAMES.contains(&name.as_str()))
        .cloned()
        .collect()
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn coerce_gates(data: &Value) -> Vec<GateResult> {
    let Some(gates) = data.get("gates").and_then(Value::as_array) else {
        return Vec::new();
    };
    gates
        .iter()
        .filter_map(|g| {
            let name = GateName::parse(&str_field(g, "gate_name"))?;
            Some(GateResult {
                gate_name: name,
                status: GateStatus::parse(&str_field(g, "status")),
                summary: str_field(g, "summary"),
                evidence: evidence::parse_evidence(g),
                details: str_field(g, "details"),
                confidence: None,
            })
        })
        .collect()
}

fn severity_rank(status: GateStatus) -> u8 {
    match status {
        GateStatus::Fail => 0,
        GateStatus::Partial => 1,
        GateStatus::Pass => 2,
        GateStatus::Skip => 3,
        GateStatus::Invalid => 4,
    }
}

fn persona_vote(gates: &[GateResult], name: GateName) -> Option<&GateResult> {
    gates
        .iter()
        .filter(|g| g.gate_name == name)
        .min_by_key(|g| severity_rank(g.status))
}

const MIN_CONSENSUS_VOTES: usize = 2;

const SECURITY_ARCHITECT: &str = "security-architect";
const PENETRATION_TESTER: &str = "penetration-tester";
const CROSS_REPO_ANALYZER: &str = "cross-repo-analyzer";

fn with_confidence(gate: &GateResult, confidence: SynthesisConfidence) -> GateResult {
    GateResult {
        confidence: Some(confidence),
        ..gate.clone()
    }
}

fn synthesize_one_gate(reports: &[&GateResult]) -> GateResult {
    let voting: Vec<&GateResult> = reports
        .iter()
        .copied()
        .filter(|r| r.status != GateStatus::Skip)
        .collect();
    if voting.is_empty() {
        return with_confidence(reports[0], SynthesisConfidence::Flagged);
    }
    let mut tally: Vec<(GateStatus, usize)> = Vec::new();
    for r in &voting {
        match tally.iter_mut().find(|(status, _)| *status == r.status) {
            Some((_, votes)) => *votes += 1,
            None => tally.push((r.status, 1)),
        }
    }
    tally.sort_by_key(|(status, _)| severity_rank(*status));
    let top_votes = tally
        .iter()
        .map(|(_, votes)| *votes)
        .max()
        .expect("tally is non-empty because voting is");
    let tied: Vec<GateStatus> = tally
        .iter()
        .filter(|(_, votes)| *votes == top_votes)
        .map(|(status, _)| *status)
        .collect();
    let chosen = *tied
        .first()
        .expect("at least one status carries the top vote count");
    let confidence = match tied.as_slice() {
        [_] if top_votes >= MIN_CONSENSUS_VOTES => SynthesisConfidence::High,
        [_] => SynthesisConfidence::Flagged,
        [GateStatus::Partial, GateStatus::Pass] | [GateStatus::Fail, GateStatus::Partial] => {
            SynthesisConfidence::Split
        }
        _ => SynthesisConfidence::Flagged,
    };
    let winner = voting
        .iter()
        .find(|r| r.status == chosen)
        .expect("`chosen` was tallied from `voting` itself");
    with_confidence(winner, confidence)
}

fn synthesize_n(persona_gates: &[Vec<GateResult>]) -> Vec<GateResult> {
    let mut names: Vec<GateName> = Vec::new();
    for gates in persona_gates {
        for g in gates {
            if !names.contains(&g.gate_name) {
                names.push(g.gate_name);
            }
        }
    }
    names
        .into_iter()
        .map(|name| {
            let reports: Vec<&GateResult> = persona_gates
                .iter()
                .filter_map(|gates| persona_vote(gates, name))
                .collect();
            synthesize_one_gate(&reports)
        })
        .collect()
}

fn apply_tie_policy(gates: Vec<GateResult>, split_ties_score: bool) -> Vec<GateResult> {
    if split_ties_score {
        return gates;
    }
    gates
        .into_iter()
        .map(|g| match g.confidence {
            Some(SynthesisConfidence::Split) => with_confidence(&g, SynthesisConfidence::Flagged),
            _ => g,
        })
        .collect()
}

fn vote_lines(
    persona_names: &[&str],
    persona_gates: &[Vec<GateResult>],
    synthesized: &[GateResult],
) -> Vec<String> {
    synthesized
        .iter()
        .map(|merged| {
            let votes: Vec<String> = persona_names
                .iter()
                .zip(persona_gates)
                .map(|(persona, gates)| {
                    let status = persona_vote(gates, merged.gate_name)
                        .map_or("absent", |g| g.status.as_str());
                    format!("{persona}={status}")
                })
                .collect();
            format!(
                "[s11] {}: {} -> {} ({})",
                merged.gate_name.as_str(),
                votes.join(" "),
                merged.status.as_str(),
                merged.confidence.map_or("?", SynthesisConfidence::as_str),
            )
        })
        .collect()
}

fn lacks_consensus(gate: &GateResult) -> bool {
    gate.confidence != Some(SynthesisConfidence::High)
}

fn agentic_config(
    config: &Step11Config,
    system_prompt: String,
    persona_model: Option<&str>,
) -> AgenticConfig {
    let model = persona_model.unwrap_or(&config.model);
    let mut cfg = AgenticConfig::new(model.to_string());
    cfg.system_prompt = Some(system_prompt);
    cfg.allowed_tools = effective_allowed_tools(config);
    cfg.max_turns = config.max_turns;
    cfg.max_transient_retries = config.max_transient_retries;
    cfg.max_context_shrinks = config.max_context_shrinks;
    cfg.retry_backoff_base = config.retry_backoff_base;
    cfg.temperature = config.temperature;
    cfg.top_p = config.top_p;
    cfg.seed = config.seed;
    cfg.reasoning_effort = config.reasoning_effort;
    cfg.openai_api = config.openai_api;
    cfg.timeout_secs = config.timeout_secs;
    cfg
}

fn gates_from(outcome: &appsec_llm_agentic::AgenticOutcome) -> Vec<GateResult> {
    appsec_json_repair::extract_json(&outcome.final_text)
        .map(|v| coerce_gates(&v))
        .unwrap_or_default()
}

async fn run_persona(
    client: &dyn LlmClient,
    tools: &dyn ToolExecutor,
    user_prompt: &str,
    config: &AgenticConfig,
    persona: &str,
) -> Result<Vec<GateResult>, LlmError> {
    let gates = gates_from(&run_agentic(client, tools, user_prompt, config).await?);
    if !gates.is_empty() {
        return Ok(gates);
    }
    tracing::warn!(
        "[s11] {persona} returned no usable gates (unparseable or gateless response); \
         retrying the persona once."
    );
    let gates = gates_from(&run_agentic(client, tools, user_prompt, config).await?);
    if gates.is_empty() {
        tracing::warn!(
            "[s11] {persona} returned no usable gates on retry either; the panel \
             continues without its opinion, which alone can force UNVERIFIABLE."
        );
    }
    Ok(gates)
}

pub async fn validate_finding(
    client: &dyn LlmClient,
    tools: &dyn ToolExecutor,
    repo: &std::path::Path,
    finding: &RankedFinding,
    record: &RemediationRecord,
    config: &Step11Config,
) -> Result<ValidationScore, LlmError> {
    let redacted_diff = appsec_redact::redact_diff(record.diff.as_deref().unwrap_or(""));
    let diff = redacted_diff.as_str();
    let cvss_rating = finding.finding.cvss_rating.as_deref();
    let hints = hints::load_hints(repo, config.allow_repo_hints);
    let affected_files: Vec<String> = {
        let mut files: Vec<String> = record
            .verdict
            .changes
            .iter()
            .map(|c| c.file.clone())
            .collect();
        files.dedup();
        files
    };
    let base_prompt = prompts::ValidationPrompt {
        title: &finding.finding.title,
        file: &finding.finding.file,
        line: finding.finding.line_start,
        description: &finding.finding.description,
        cwe: finding.finding.cwe.as_deref(),
        cvss_rating,
        cvss_score: finding.finding.cvss_score,
        cvss_vector: finding.finding.cvss_vector.as_deref(),
        impact: &finding.finding.impact,
        exploit_scenario: &finding.finding.exploit_scenario,
        preconditions: &finding.finding.preconditions,
        recommendation: &finding.finding.recommendation,
        affected_files: &affected_files,
        diff,
        remediation_root_cause: &record.verdict.root_cause,
        remediation_remaining_risks: &record.verdict.remaining_risks,
        include_hints: false,
        hints: &hints,
    };
    let architect_user = prompts::build_user(&base_prompt);
    let pentester_user = prompts::build_user(&prompts::ValidationPrompt {
        include_hints: true,
        ..base_prompt
    });

    let architect_config = agentic_config(
        config,
        prompts::security_architect_system(config.fact_tools),
        config.security_architect_model.as_deref(),
    );
    let pentester_config = agentic_config(
        config,
        prompts::penetration_tester_system(config.fact_tools),
        config.penetration_tester_model.as_deref(),
    );

    let with_facts = appsec_sandbox_tools::FactTools::new(tools, repo, diff);
    let tools: &dyn ToolExecutor = if config.fact_tools {
        &with_facts
    } else {
        tools
    };

    let persona_names: &[&str] = if config.cross_repo_analyzer {
        &[SECURITY_ARCHITECT, PENETRATION_TESTER, CROSS_REPO_ANALYZER]
    } else {
        &[SECURITY_ARCHITECT, PENETRATION_TESTER]
    };
    let persona_gates: Vec<Vec<GateResult>> = if config.cross_repo_analyzer {
        let cross_repo_user = prompts::build_user(&base_prompt);
        let cross_repo_config = agentic_config(
            config,
            prompts::cross_repo_analyzer_system(config.fact_tools),
            config.cross_repo_analyzer_model.as_deref(),
        );
        let (architect_gates, pentester_gates, cross_repo_gates) = tokio::join!(
            run_persona(
                client,
                tools,
                &architect_user,
                &architect_config,
                SECURITY_ARCHITECT
            ),
            run_persona(
                client,
                tools,
                &pentester_user,
                &pentester_config,
                PENETRATION_TESTER
            ),
            run_persona(
                client,
                tools,
                &cross_repo_user,
                &cross_repo_config,
                CROSS_REPO_ANALYZER
            ),
        );
        vec![architect_gates?, pentester_gates?, cross_repo_gates?]
    } else {
        let (architect_gates, pentester_gates) = tokio::join!(
            run_persona(
                client,
                tools,
                &architect_user,
                &architect_config,
                SECURITY_ARCHITECT
            ),
            run_persona(
                client,
                tools,
                &pentester_user,
                &pentester_config,
                PENETRATION_TESTER
            ),
        );
        vec![architect_gates?, pentester_gates?]
    };

    let synthesized = apply_tie_policy(synthesize_n(&persona_gates), config.split_ties_score);
    let lines = vote_lines(persona_names, &persona_gates, &synthesized);
    for (gate, line) in synthesized.iter().zip(lines) {
        if lacks_consensus(gate) {
            tracing::warn!("{line}");
        } else {
            tracing::info!("{line}");
        }
    }
    Ok(score_fix(&synthesized))
}

#[allow(clippy::too_many_arguments)]
pub async fn validate_finding_checkpointed(
    client: &dyn LlmClient,
    tools: &dyn ToolExecutor,
    repo: &std::path::Path,
    finding: &RankedFinding,
    record: &RemediationRecord,
    config: &Step11Config,
    checkpoint: Option<&dyn CheckpointStore>,
    run_id: &str,
    resume: bool,
) -> Result<ValidationScore, LlmError> {
    let step = validation_step_key(config, record);
    if resume {
        if let Some(cached) = checkpoint.and_then(|s| checkpoint::load_score(s, run_id, &step)) {
            return Ok(cached);
        }
    }
    let score = validate_finding(client, tools, repo, finding, record, config).await?;
    if let Some(store) = checkpoint {
        checkpoint::save_score(store, run_id, &step, &score);
    }
    Ok(score)
}

#[cfg(test)]
mod tests;
