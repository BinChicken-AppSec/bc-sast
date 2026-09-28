//! Phase 3's S11 fix-validation stage: grades an S10 remediation against
//! 4 weighted gates via a 2-or-3-persona LLM panel, ported (scoped) from
//! `vvaharness/validation/`.
//!
//! **Deliberate scope decisions vs. the Python original** (see the
//! project's architecture plan/memory for the full research trail):
//! - The Python original is a full multi-persona **Claude Agent SDK
//!   subagent** panel (3 personas), an on-disk DTO-file staging/workspace
//!   model, and its own standalone CLI/backends registry — none of which
//!   fits this port's dialect-agnostic, gateway-mediated, in-process
//!   architecture. Only the deterministic scoring engine
//!   ([`bc_validation_scoring`]) is ported faithfully; the panel itself
//!   is adapted to run as calls through this port's existing
//!   [`bc_llm_agentic::run_agentic`] loop.
//! - **`cross-repo-analyzer` is opt-in (`Step11Config::cross_repo_analyzer`,
//!   default `false`), not auto-triggered.** Python spawns it "only when
//!   a fix spans 2+ repositories" — a pure LLM-judgment call the
//!   orchestrator makes itself, reading the diff at runtime; there is no
//!   host-side Python code anywhere that computes a repo count. This port
//!   has no per-scan orchestrator LLM making that call and no multi-repo
//!   concept in its data model (`bc-sast --repo <path>` is always exactly
//!   one repo, and a remediation diff never spans repo boundaries), so
//!   there's no signal to auto-trigger on. Rather than leave the persona
//!   permanently unreachable, it's exposed as an explicit operator
//!   opt-in (`step_validate.cross_repo_analyzer: true`) for repos an
//!   operator knows are logically multi-component (e.g. a monorepo with
//!   independently-versioned services) — when on, it runs on every
//!   finding rather than conditionally per-diff.
//! - **N-way gate synthesis** (see [`synthesize_n`]): generalizes the
//!   Python original's "2+ agree / 1 only / contradiction → most
//!   conservative" rule to however many personas actually reported a
//!   given gate name — 2 when `cross_repo_analyzer` is off (collapsing
//!   to "same status → that status; different → the more conservative
//!   one", byte-identical to this crate's pre-3rd-persona behavior), 3
//!   when it's on. Each merged gate also carries a
//!   [`SynthesisConfidence`]: `High` when 2+ personas agreed, `Split`
//!   when they tied one step apart on the severity scale (a
//!   `pass`/`partial` or `partial`/`fail` disagreement about how
//!   complete the fix is), and `Flagged` for a `pass`-against-`fail`
//!   contradiction, a garbled report, a three-way tie, a lone vote, or
//!   a gate the whole panel skipped. A single `Flagged` gate makes the
//!   whole fix score `Unverifiable` — the panel's opinion is still
//!   reported in full, but it is not allowed to stand in for a verdict.
//!   `Split` scores exactly as `High` does: the conservative status
//!   stands, and the scoring engine's own half credit and critical-gate
//!   cap are what express the doubt.
//! - **No staged workspace copy.** The Python original stages an
//!   ephemeral per-finding repo copy specifically so a separately
//!   invoked `vvaharness validate` command has an isolated snapshot. This
//!   port validates immediately, in-process, right after S10 applies a
//!   fix — the real, already-fixed working tree is used directly via a
//!   **read-only** tool executor (never the write-capable one S10 uses),
//!   matching the persona's `[Read, Grep, Glob]`-only enforcement and the
//!   trust-model guarantee that validation never mutates source.
//! - **The five deterministic fact tools ARE ported.** Python grants its
//!   personas `DiffTouched`/`ChangedLines`/`DiffImpactMap`/`PatternScan`/
//!   `TestInventory` alongside the three readers
//!   (`validation/tools/deep_tools.py`,
//!   `validation/constants/tools.py::DEFAULT_FACT_TOOLS`). They live here
//!   as [`bc_sandbox_tools::FactTools`], wrapped around the caller's
//!   read-only executor per finding so the diff they answer from is that
//!   finding's own; `step_validate.fact_tools` turns them off for a model
//!   that copes badly with eight tools.
//! - **`effort` is ported, `max_budget_usd` is not**: the panel's
//!   reasoning effort is [`Step11Config::reasoning_effort`] (`high` by
//!   default, Python's `DEFAULT_EFFORT`, from `step_validate.effort`),
//!   while `max_budget_usd` was already decided as a dropped no-op knob
//!   back at S6's port, whose module comment records why Python's own
//!   analogous backends never enforced it either.

mod checkpoint;
mod evidence;
mod hints;
mod prompts;

pub use checkpoint::{validation_step_key, VALIDATE_STEP_PREFIX};
pub use hints::hints_path;

use bc_checkpoint::CheckpointStore;
use bc_llm_agentic::{run_agentic, AgenticConfig};
use bc_llm_client::{LlmClient, LlmError, ToolExecutor};
use bc_model::RankedFinding;
use bc_stage_s10::RemediationRecord;
use bc_validation_scoring::{
    score_fix, GateName, GateResult, GateStatus, SynthesisConfidence, ValidationScore,
};
use serde_json::Value;

/// Everything one S11 validation run needs beyond the finding/record
/// themselves.
#[derive(Debug, Clone)]
pub struct Step11Config {
    /// The panel's shared/default model — every persona uses this unless
    /// its own `*_model` override below is set. Plays the role Python's
    /// `models.validate.orchestrator` does.
    pub model: String,
    pub max_turns: u32,
    pub allowed_tools: Vec<String>,
    pub max_transient_retries: u32,
    /// How many times a single agentic turn retries after a context-
    /// overflow by evicting oldest tool results — forwarded to
    /// [`bc_llm_agentic::AgenticConfig::max_context_shrinks`].
    pub max_context_shrinks: u32,
    pub retry_backoff_base: std::time::Duration,
    /// Sampling temperature for every persona call. `None` (the default)
    /// sends no `temperature` at all, leaving the provider's own — which
    /// for both dialects is `1.0`, i.e. maximally divergent between two
    /// runs. Ported from the Python original's per-role
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
    /// Reasoning-effort tier for every persona's turns, forwarded to
    /// [`bc_llm_client::ChatRequest::reasoning_effort`]. Defaults to
    /// `high`, the Python original's `DEFAULT_EFFORT` for the validation
    /// agent (`validation/constants/artifacts.py`) and the shipped
    /// `step_validate.effort`; `bc-cli` layers `step_validate.effort`,
    /// `--reasoning-effort` and `models.validate.orchestrator.effort`
    /// over it, in that order. A model that takes no effort parameter
    /// has it dropped by the capability table, so this is inert there.
    pub reasoning_effort: Option<bc_llm_client::ReasoningEffort>,
    /// Per-role OpenAI transport pin (Python's
    /// `models.<role>.use_responses_api`), forwarded to
    /// [`bc_llm_client::ChatRequest::openai_api`]. `None` (the default)
    /// keeps the client-wide `--openai-api` choice.
    pub openai_api: Option<bc_llm_client::OpenAiApi>,
    /// Per-turn wall-clock deadline in seconds, overriding the shared
    /// gateway client's own 300 s default. `None` (the default) keeps it.
    pub timeout_secs: Option<u64>,
    /// Caps in-scan validation to the top-N validatable findings by CVSS
    /// score (highest first) — ported from `step_validate.max_findings`
    /// (`dto_loader.py::select_reports`/`_top_by_cvss`). `None` or
    /// `Some(0)` validates every validatable finding, matching the
    /// Python original's `--all`/absent-cap behavior. The caller
    /// (`bc_orchestrator::remediate`) is responsible for applying this —
    /// this stage's own `validate_finding` has no concept of "which
    /// findings," only "validate this one."
    pub max_findings: Option<usize>,
    /// Whether `<repo>/inputs/validator_hints.yaml` — a file living
    /// inside the *scanned* repo itself — is trusted enough to REPLACE
    /// the bundled per-CWE hint set. Defaults to `false` (fail-closed):
    /// see [`hints::load_hints`]'s own doc comment for the threat model.
    /// The CLI computes this once via `bc_config::check_config_trust`
    /// against the same `BC_ALLOW_CWD_CONFIG` opt-in that already governs
    /// trusting a scan target's own `config.yaml`.
    ///
    /// This gates the *override* only — the bundled 10-CWE hint set ships
    /// with the binary and is always available, so `false` is a complete,
    /// hint-carrying configuration rather than a degraded one.
    pub allow_repo_hints: bool,
    /// Per-persona model override for `security-architect` — `None`
    /// inherits `model`. Ported from Python's `AgentConfig.
    /// security_architect_model` / `models.validate.security_architect.id`
    /// inheritance semantics (`validation/cli/_model.py`).
    pub security_architect_model: Option<String>,
    /// Per-persona model override for `penetration-tester` — `None`
    /// inherits `model`. Same inheritance semantics as
    /// `security_architect_model`.
    pub penetration_tester_model: Option<String>,
    /// Per-persona model override for `cross-repo-analyzer` — `None`
    /// inherits `model`. Only consulted when `cross_repo_analyzer` below
    /// is `true`.
    pub cross_repo_analyzer_model: Option<String>,
    /// Whether the `cross-repo-analyzer` persona runs alongside
    /// security-architect/penetration-tester. Defaults to `false` — see
    /// this crate's module doc comment for why it's operator opt-in here
    /// rather than auto-triggered like the Python original.
    pub cross_repo_analyzer: bool,
    /// Whether each persona additionally gets the five deterministic
    /// **fact tools** ([`bc_sandbox_tools::FACT_TOOL_NAMES`]) on top of
    /// `Read`/`Glob`/`Grep`. Defaults to `true`, matching Python's own
    /// unconditional `fact_tools=DEFAULT_FACT_TOOLS`
    /// (`validation/session/launcher.py:259`) — there is no Python knob
    /// to port here; `step_validate.fact_tools` exists purely as an
    /// operator escape hatch for a model that copes badly with a
    /// 8-tool schema.
    ///
    /// Turning it OFF also strips the five names out of
    /// [`Self::allowed_tools`] before the panel runs (see
    /// [`effective_allowed_tools`]), because
    /// [`bc_llm_agentic::run_agentic`] rejects an allow-list naming a tool
    /// the executor does not advertise — so the toggle stays a one-line
    /// change rather than a two-key ritual.
    pub fact_tools: bool,
    /// Whether a two-way tie one step apart on the severity scale
    /// (`pass`/`partial`, `partial`/`fail`) is scored as
    /// [`SynthesisConfidence::Split`] (`true`, the default and this port's
    /// long-standing behavior: the conservative status stands and scores
    /// normally) or, as vvaharness does for every tie, marked
    /// [`SynthesisConfidence::Flagged`] so the whole fix is inconclusive
    /// (`false`). `step_validate.split_ties_score`. See
    /// [`synthesize_one_gate`] for why this port scores such ties.
    pub split_ties_score: bool,
    /// The API dialect and gateway host the panel is reached through,
    /// folded into the `--resume` checkpoint key (see
    /// [`Step11Config::engine_key`]) together with every persona model.
    /// Empty by default; the CLI fills both from the resolved gateway.
    pub dialect: String,
    pub base_host: String,
}

impl Step11Config {
    /// Sensible defaults matching the shipped Python profile's
    /// `step_validate` block (`max_turns: 50`, `max_findings: 20`), plus
    /// this port's own read-only tool set (`allowed_tools`, matching the
    /// persona's actually-enforced `[Read, Grep, Glob]` — Bash/Write/Edit
    /// are never offered at all here, structurally, rather than denied
    /// by a separate permission policy the way the Python original's SDK
    /// sandbox does) followed by the five deterministic fact tools, which
    /// together reproduce Python's `DEFAULT_FACT_TOOLS`
    /// (`validation/constants/tools.py:22-31`) exactly — only the order of
    /// the three readers differs, and `allowed_tools` is a set in every
    /// consumer.
    ///
    /// Setting `allowed_tools` explicitly (`step_validate.allowed_tools`)
    /// REPLACES this list wholesale rather than merging with it, so an
    /// operator asking for `[Read]` gets `[Read]` — Python's
    /// `_fact_tools(options, allowed)` filters the same way.
    pub fn new(model: impl Into<String>) -> Self {
        Step11Config {
            model: model.into(),
            max_turns: 50,
            allowed_tools: ["Read", "Glob", "Grep"]
                .into_iter()
                .chain(bc_sandbox_tools::FACT_TOOL_NAMES)
                .map(String::from)
                .collect(),
            max_transient_retries: 4,
            max_context_shrinks: 16,
            retry_backoff_base: std::time::Duration::from_secs(10),
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: Some(bc_llm_client::ReasoningEffort::High),
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

/// The tool allow-list the panel actually runs with: `allowed_tools` as
/// configured, minus the five fact-tool names when
/// [`Step11Config::fact_tools`] is off.
///
/// The subtraction is not cosmetic. [`bc_llm_agentic::run_agentic`] fails
/// the whole call with `InvalidRequest` when the allow-list names a tool
/// the executor does not advertise, and the executor only advertises the
/// five when it is wrapped in [`bc_sandbox_tools::FactTools`] — which
/// happens on exactly the same condition. Without this, flipping
/// `step_validate.fact_tools: false` would turn every validation into an
/// error instead of a smaller tool set.
fn effective_allowed_tools(config: &Step11Config) -> Vec<String> {
    if config.fact_tools {
        return config.allowed_tools.clone();
    }
    config
        .allowed_tools
        .iter()
        .filter(|name| !bc_sandbox_tools::FACT_TOOL_NAMES.contains(&name.as_str()))
        .cloned()
        .collect()
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Parses one persona's raw JSON response into a set of [`GateResult`]s.
/// An entry whose `gate_name` doesn't match one of the 4 known names is
/// DROPPED (not passed through as a placeholder) — this naturally shows
/// up as a *missing* gate to [`score_fix`]'s shape check (fail-closed to
/// `Unverifiable`) rather than ever needing an "unknown gate" variant.
/// Never fails: a non-object response, or one missing `gates` entirely,
/// yields an empty list (which `score_fix` also resolves to
/// `Unverifiable`, via the same shape check).
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
                // One persona's own opinion, pre-synthesis: there is no
                // panel to be confident about yet. Python's
                // `PersonaGateEntry` likewise carries no confidence
                // field; only the synthesized gate does.
                confidence: None,
            })
        })
        .collect()
}

/// Ranks how conservative a status is (lower wins), mirroring Python's
/// `enums/gates.py::_STATUS_CONSERVATIVE_RANK`. Used to pick the most
/// conservative among DIFFERING statuses — never as a general-purpose
/// ordering — in the panel's tie-break ([`synthesize_one_gate`]) and in
/// one persona's own duplicate fold ([`persona_vote`]).
///
/// `Skip` and `Invalid` sit at the permissive end, and their order
/// relative to each other matters only to `persona_vote`: the panel
/// tie-break never sees a `Skip` (abstentions are filtered out first).
fn severity_rank(status: GateStatus) -> u8 {
    match status {
        GateStatus::Fail => 0,
        GateStatus::Partial => 1,
        GateStatus::Pass => 2,
        GateStatus::Skip => 3,
        GateStatus::Invalid => 4,
    }
}

/// One persona's single vote on one gate name: the most conservative
/// entry it reported for that name, or `None` if it did not report the
/// gate at all.
///
/// A persona's response can name the same gate more than once — nothing
/// in the schema stops it, and [`coerce_gates`] faithfully keeps every
/// entry. Folding those to one vote is Python's rule (`_consensus.py`
/// builds `votes: dict[str, str]` keyed by persona, combining a repeat
/// through `_most_conservative_status`), and it is load-bearing rather
/// than cosmetic here: [`MIN_CONSENSUS_VOTES`] is 2 and the usual panel
/// is 2 personas, so silently dropping one persona's own contradicting
/// entry is exactly what turns a tie into the "2 agreeing votes" that
/// [`SynthesisConfidence::High`] — and therefore any score at all —
/// requires.
///
/// Ties (the same status listed twice) keep the earliest entry, so the
/// summary and evidence carried forward stay deterministic; otherwise
/// the surviving entry is the conservative one, which keeps the
/// reported evidence consistent with the reported status.
fn persona_vote(gates: &[GateResult], name: GateName) -> Option<&GateResult> {
    gates
        .iter()
        .filter(|g| g.gate_name == name)
        .min_by_key(|g| severity_rank(g.status))
}

/// How many agreeing non-skip votes a status needs to win with
/// [`SynthesisConfidence::High`]. Ported from Python's
/// `validation/constants/synthesis.py::MIN_CONSENSUS_VOTES`.
const MIN_CONSENSUS_VOTES: usize = 2;

/// The panel's persona names, as they appear in every log line this
/// module emits. Named constants rather than repeated literals so the
/// name a vote is attributed to in [`vote_lines`] cannot drift from the
/// one [`run_persona`] logs a parse failure against.
const SECURITY_ARCHITECT: &str = "security-architect";
const PENETRATION_TESTER: &str = "penetration-tester";
const CROSS_REPO_ANALYZER: &str = "cross-repo-analyzer";

/// Re-labels one persona report as the panel's synthesized answer.
fn with_confidence(gate: &GateResult, confidence: SynthesisConfidence) -> GateResult {
    GateResult {
        confidence: Some(confidence),
        ..gate.clone()
    }
}

/// Merges every persona's report of ONE gate name into a single result,
/// carrying both the chosen status and how strongly the panel agreed on
/// it ([`SynthesisConfidence`]).
///
/// `skip` is an abstention (matching `cross-repo-analyzer`'s own
/// instructions to always skip 2 of the 4 gates) and is excluded from
/// the vote. The most conservative of the top-voted statuses always
/// wins, carrying its own summary and evidence; what varies is the
/// confidence label attached to it:
/// - a single most-voted status with [`MIN_CONSENSUS_VOTES`] or more
///   votes wins outright, at `High`;
/// - a single most-voted status BELOW that threshold — one lone
///   non-skip vote — is `Flagged`;
/// - a two-way tie one step apart on the severity scale
///   (`partial`/`pass`, or `fail`/`partial`) is `Split`: the personas
///   disagree about how complete the fix is, not about whether it
///   works, and `Split` scores exactly as `High` does;
/// - every other tie is `Flagged` — `pass` against `fail`, which IS a
///   contradiction about whether the fix works; anything tied with
///   `Invalid`, where one persona's report is garbled rather than
///   dissenting; and a three-way tie, where there is no coherent pair
///   to read as a matter of degree;
/// - if every reporting persona skipped, the merged result is `skip`,
///   `Flagged` — a gate nobody evaluated is not a consensus either.
///
/// The line sits at contradiction rather than at any disagreement
/// because of what the panel actually disagrees about in practice.
/// Across fourteen runs and all 96 synthesized gates, not one gate was
/// flagged for the lone-vote or all-abstained cases the rule was
/// written for; every flag was a genuine `pass`-against-`partial` split
/// over completeness ("no tests to verify the fix", "retains an unused
/// block of code"), and each one discarded the fix. Those two cases
/// still fail closed here, and the scoring engine already knows how to
/// express a partial fix: half credit, and no `Fixed` label for a
/// partial critical gate.
///
/// Ported from the Python original's
/// `_consensus.py::synthesize_gates_for_finding`, generalized from its
/// fixed 3-persona panel to however many personas actually reported this
/// gate name here. The *status* half of the rule is unchanged for any
/// panel of 3 or fewer (all this port ever runs): what is new is the
/// confidence label, which [`bc_validation_scoring::score_fix`] fails
/// closed on. Tallying by frequency rather than scanning a conservative
/// order also fixes a latent divergence that only a 4+-persona panel
/// could have reached, where a 3-vs-2 majority lost to the 2 because the
/// more conservative status was checked first.
fn synthesize_one_gate(reports: &[&GateResult]) -> GateResult {
    let voting: Vec<&GateResult> = reports
        .iter()
        .copied()
        .filter(|r| r.status != GateStatus::Skip)
        .collect();
    if voting.is_empty() {
        return with_confidence(reports[0], SynthesisConfidence::Flagged);
    }
    // One entry per distinct non-skip status, most conservative first —
    // so "the most conservative of the tied statuses" below is just the
    // head of the tie.
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
    // `tally` was sorted by `severity_rank` before `tied` was filtered
    // out of it, so a tied pair is always in ascending-rank order and
    // the two `Split` patterns below are exact — there is no reversed
    // arm to write. `Skip` cannot appear: abstentions were filtered out
    // of `voting` above.
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

/// Synthesizes every persona's independent gate set into one, gate name
/// by gate name, via [`synthesize_one_gate`]. A gate name present in
/// only SOME personas' responses — including the extreme case of a
/// whole persona's response failing to parse at all, leaving it with
/// zero gates — still synthesizes from whichever personas did report
/// it, and that lone opinion is still reported with its own status and
/// evidence; but it comes back [`SynthesisConfidence::Flagged`], which
/// [`score_fix`] then fails closed to `Unverifiable` rather than letting
/// one persona decide a fix by itself. Only when NO persona reports a
/// given gate does the merged set end up incomplete for it, which fails
/// closed through [`score_fix`]'s shape check instead.
///
/// Each persona contributes at most ONE vote per gate name, however many
/// times its response named that gate — see [`persona_vote`], which is
/// what makes the vote counts [`synthesize_one_gate`] tallies mean "how
/// many personas", the unit [`MIN_CONSENSUS_VOTES`] is denominated in.
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

/// Applies [`Step11Config::split_ties_score`]: with it off, every
/// [`SynthesisConfidence::Split`] gate is relabeled
/// [`SynthesisConfidence::Flagged`], which [`score_fix`] resolves to
/// `UNVERIFIABLE`, matching vvaharness's "any tie is inconclusive".
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

/// One line per synthesized gate, naming every persona's own vote, the
/// status the panel settled on, and the confidence label that decides
/// whether the fix can be scored at all — e.g.
/// `[s11] root_cause: security-architect=pass penetration-tester=partial
/// -> partial (SPLIT)`.
///
/// `remediation.json` records only the merged status and its label, and
/// that is not enough to tell a lone unseconded vote from two personas
/// contradicting each other: both arrive as `FLAGGED`, on a gate whose
/// reported status looks perfectly ordinary. Recovering the difference
/// meant inferring it statistically across many runs' artifacts. These
/// lines make each panel's actual votes a fact of the run log instead,
/// which is also the only way to see a `Split` for what it is rather
/// than as an unexplained `partial`.
///
/// `persona_names` is positional against `persona_gates`, the same
/// order [`validate_finding`] builds both in. A persona that reported
/// nothing for a gate is recorded as `absent`, deliberately not the
/// same word as the `skip` it would have written to abstain: a persona
/// whose reply failed to parse twice contributes no report at all, and
/// that is a different thing from one that answered "I did not assess
/// this".
///
/// The lines come back as plain strings rather than being logged here,
/// because they do not all belong at the same level: see
/// [`lacks_consensus`].
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

/// Whether this gate's [`vote_lines`] entry is something an operator
/// needs to see without having asked for it, which is what picks the
/// level it is logged at.
///
/// The two cases have different audiences. A `Split` or `Flagged` gate
/// is the explanation for the score the fix received, and on a
/// `Flagged` gate it is the explanation for why the patch was reverted;
/// that has to reach an operator reading a default run, so it goes to
/// `warn`. A `High` gate explains nothing on its own: it is only useful
/// to someone tabulating every gate to characterize how the panel
/// behaves, which is what `-v` is for, so it goes to `info`.
///
/// Splitting it here also keeps `warn` honest, since every vote line
/// that reaches that level then marks a gate the panel did not agree
/// on. And the volume falls as the underlying problem does: a run whose
/// panel agrees everywhere prints nothing at default verbosity.
///
/// An unlabeled gate (`None`) counts as lacking consensus. Synthesis
/// always labels what it merges, so this is unreachable from
/// [`validate_finding`], but a gate whose agreement is unknown is not a
/// gate to quieten.
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

fn gates_from(outcome: &bc_llm_agentic::AgenticOutcome) -> Vec<GateResult> {
    bc_json_repair::extract_json(&outcome.final_text)
        .map(|v| coerce_gates(&v))
        .unwrap_or_default()
}

/// Runs ONE persona and returns the gates it reported, re-running it
/// exactly once if the first reply yielded none.
///
/// "No gates" covers both halves of the same mechanical failure: no JSON
/// could be extracted from the reply at all, and JSON that parsed but
/// named no recognizable gate ([`coerce_gates`] drops unknown names). A
/// persona that reported zero gates is equally useless either way — its
/// prompt demands a verdict on all four criteria — so both are worth one
/// more attempt rather than a silent abstention.
///
/// This exists because an empty gate list is indistinguishable, further
/// down the pipeline, from a persona that genuinely had no opinion: the
/// surviving persona's gates then carry a lone vote,
/// [`synthesize_one_gate`] marks them [`SynthesisConfidence::Flagged`],
/// [`score_fix`] returns `Unverifiable`, and
/// [`bc_stage_s10`]'s revert-on-anything-but-`Fixed` rule then rolls back
/// a fix that may have been perfectly good. One malformed reply from one
/// model should not read as a lack of panel consensus, which is a
/// different thing entirely. (Upstream vvaharness v1.3.0 applied exactly
/// this principle at S6, retrying an unparseable verdict rather than
/// silently dropping the finding; it has not applied it here.)
///
/// Exactly one retry, deliberately not a loop and not configurable:
/// [`bc_json_repair::extract_json`] has already repaired malformed JSON
/// before this point, so reaching here at all is the rare residual case,
/// and a second failure is far more likely to be a model that cannot
/// answer this prompt than a transient formatting slip. Both outcomes are
/// logged, because the pre-existing silence was the larger half of the
/// bug: an operator could not tell a discarded fix caused by panel
/// disagreement from one caused by a model emitting bad JSON.
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

/// Runs the validator panel against one already-remediated finding and
/// scores the synthesized result — security-architect and
/// penetration-tester always; cross-repo-analyzer additionally when
/// `config.cross_repo_analyzer` is set. `tools` MUST be read-only (a
/// plain `SandboxTools::new(repo)`, never the write-capable instance S10
/// uses) — validation never mutates source, matching the Python
/// original's own trust-model guarantee.
///
/// Every persona call runs CONCURRENTLY (`tokio::join!`): all are
/// read-only and genuinely independent, unlike S10's remediation loop
/// (deliberately sequential there, since Edit/Write mutate a shared
/// working tree — no such constraint applies here). Each arm goes
/// through [`run_persona`], so a persona whose reply carried no usable
/// gates is retried once, concurrently with the rest of the panel and
/// without serializing it.
///
/// Once the panel has answered, every gate's individual votes are
/// logged via [`vote_lines`] — one line per gate, whatever the outcome,
/// so a run log always says how the panel actually voted rather than
/// only what the merge concluded. A gate that did not reach consensus
/// logs at `warn` and an agreed one at `info`, per
/// [`lacks_consensus`].
///
/// Propagates an [`LlmError`] only when an agentic call itself fails
/// (network/rate-limit/etc.) — an unparseable-but-successful response
/// from any persona degrades to an empty gate list for that persona,
/// never an error, matching [`bc_stage_s10::remediate_finding`]'s own
/// "content-level issues never error" precedent.
///
/// A persona only reaches that degraded state after [`run_persona`]
/// has re-run it once and the retry ALSO produced nothing, and both the
/// retry and its failure are logged at `warn` naming the persona. What
/// survives to synthesis is therefore a genuine failure to answer rather
/// than a one-off formatting slip. `score_fix` still resolves such a
/// panel closed to `Unverifiable`: via its shape check if no persona
/// parsed, or via the consensus check if only one did, since a surviving
/// persona's gates then carry only its own single vote. That is the
/// intended fail-closed behavior for a panel that really did not reach
/// consensus, and the retry is only about not reaching it mechanically.
pub async fn validate_finding(
    client: &dyn LlmClient,
    tools: &dyn ToolExecutor,
    // `tools` is already jailed to the repo root at construction time
    // (mirroring `SandboxTools`'s own design). `repo` resolves
    // `<repo>/inputs/validator_hints.yaml` for the penetration-tester's
    // per-CWE bypass hints (see `hints::load_hints`), and is the jailed
    // root the `PatternScan`/`TestInventory` fact tools walk.
    repo: &std::path::Path,
    finding: &RankedFinding,
    record: &RemediationRecord,
    config: &Step11Config,
) -> Result<ValidationScore, LlmError> {
    // The panel only ever sees the REDACTED diff, as in Python, where the
    // validator reads the persisted (already redacted) `diff.patch`. The
    // diff of a hardcoded-secret fix contains the secret it removed; the
    // persona needs to see that the literal went away, not what it was
    // (the secret-exposure prompt rule tells it exactly that). Redacted
    // structure-aware, so `DiffTouched`/`ChangedLines` still parse it.
    let redacted_diff = bc_redact::redact_diff(record.diff.as_deref().unwrap_or(""));
    let diff = redacted_diff.as_str();
    let cvss_rating = finding.finding.cvss_rating.as_deref();
    let hints = hints::load_hints(repo, config.allow_repo_hints);
    // Python's `affected_files` comes from the PATCH's own
    // `files_touched` (`manifest_builder.py:41`), not from the finding —
    // it is the ground truth the `instance_coverage` gate is measured
    // against, so it must describe what the fix actually changed. The
    // typed equivalent here is the verdict's own `changes` list.
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

    // The five deterministic fact tools are layered on top of whatever
    // read-only executor the caller supplied, for the duration of this
    // one finding's panel — the diff they answer from is THIS
    // remediation's, so the wrapper cannot be built once by the
    // orchestrator and shared. See `bc_sandbox_tools::FactTools` for why
    // it is a decorator rather than a `SandboxTools` constructor flag.
    let with_facts = bc_sandbox_tools::FactTools::new(tools, repo, diff);
    let tools: &dyn ToolExecutor = if config.fact_tools {
        &with_facts
    } else {
        tools
    };

    // Positional against `persona_gates` below, and consumed only by
    // `vote_lines` — the synthesis itself is deliberately blind to which
    // persona cast which vote, since no persona's opinion outranks
    // another's.
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

/// [`validate_finding`] behind a `--resume` checkpoint, the S11
/// counterpart of `bc_stage_s10::remediate_one_checkpointed`.
///
/// With `resume` set, a score saved under this finding's
/// [`validation_step_key`] (same finding, same redacted diff, same panel
/// and models) is returned without running a single persona. A freshly
/// computed score is saved whenever a store is given, whether or not this
/// run resumed, so a later `--resume` has it. A failed validation saves
/// nothing.
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
