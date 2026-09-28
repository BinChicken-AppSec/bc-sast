//! S1 — Pre-process: one agentic Read/Glob/Grep exploration call builds a
//! rough structural map (language, modules, entry points, unsafe sinks,
//! a seed call graph), which is then validated and filled out against
//! ground truth by the deterministic passes in `bc-repo-analysis`.
//! Ported from `vvaharness/pipeline/stages/s1_preprocess.py::run`.
//!
//! Two things the Python original does are deliberately **not** this
//! stage's job (confirmed by reading `orchestrator/scan.py`): CMDB
//! `AppProfile` lookup and `ThreatModel` generation are both attached to
//! the `ContextPackage` by the orchestrator *after* this stage returns,
//! not produced here.

mod autoexclude;
mod prompts;
mod pure;

pub use autoexclude::{
    run_autoexclude, run_autoexclude_with_diagnostics, AutoExcludeConfig, AutoExcludeDiagnostics,
    AutoExcludeOverlay,
};

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{json, Value};

use bc_llm_agentic::{run_agentic, AgenticConfig};
use bc_llm_client::{LlmClient, ToolExecutor};
use bc_model::{ContextPackage, Control, Cve};
use bc_pipeline_core::{PipelineStage, StageError, StageOutcome};
use bc_repo_analysis::{CallGraphConfig, DedupConfig, WalkConfig};
use bc_stage_s0::SeedPackage;

/// `step1.mode`: `Full` always runs S1's own agentic Read/Glob/Grep
/// exploration; `GapFill` skips it when the S0 seed is strong enough
/// (see `pure::should_escalate_gap_fill`), falling back to `Full`'s
/// behavior on sparse coverage for a large, service-shaped repo. A
/// `GapFill` request with no seed present (or an empty one) behaves
/// exactly like `Full` — an absent/empty seed is "falsy" the same way
/// Python's own `if mode == "gap_fill" and seed:` guard treats it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Step1Mode {
    #[default]
    Full,
    GapFill,
}

/// `step1.call_graph` (a STRING config key in the Python original — not
/// to be confused with this crate's own `Step1Config.call_graph` field,
/// which is the max-targets/rounds/etc. knobs BOTH backends share).
/// `TreeSitter` (the real shipped default) gives exact def end-lines/
/// byte-ranges via `bc_repo_analysis::ts_graph_build` — precise
/// enclosing-caller resolution and real `def_spans` for downstream
/// function slicing. `Regex` uses `bc_repo_analysis::supplement_call_graph`
/// instead — no AST, no `def_spans`, but doesn't require these 14
/// grammar crates to parse anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CallGraphMode {
    #[default]
    TreeSitter,
    Regex,
}

pub struct Step1Config {
    pub model: String,
    pub allowed_tools: Vec<String>,
    pub max_turns: u32,
    pub max_tokens: u32,
    pub max_transient_retries: u32,
    pub max_context_shrinks: u32,
    pub retry_backoff_base: std::time::Duration,
    pub walk: WalkConfig,
    pub dedup: DedupConfig,
    pub call_graph: CallGraphConfig,
    pub call_graph_mode: CallGraphMode,
    pub mode: Step1Mode,
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
}

impl Step1Config {
    pub fn new(model: impl Into<String>) -> Self {
        Step1Config {
            model: model.into(),
            allowed_tools: vec!["Read".to_string(), "Glob".to_string(), "Grep".to_string()],
            // Matches `step1.max_turns`'s real shipped default
            // (`config/__init__.py:105`, `40` — also already correctly
            // mirrored in `bc-config/src/step_defaults.rs`'s config
            // schema for `--config`-driven runs). `25` here previously
            // had no basis in any real profile's step1 turn cap.
            max_turns: 40,
            max_tokens: 16_000,
            max_transient_retries: 4,
            max_context_shrinks: 16,
            retry_backoff_base: std::time::Duration::from_secs(10),
            walk: WalkConfig::new(),
            dedup: DedupConfig::new(),
            call_graph: CallGraphConfig::new(),
            call_graph_mode: CallGraphMode::TreeSitter,
            mode: Step1Mode::Full,
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: None,
            openai_api: None,
            timeout_secs: None,
        }
    }
}

pub struct Step1Input {
    pub repo_root: PathBuf,
    pub known_cves: Vec<Cve>,
    pub design_controls: Vec<Control>,
    /// `--diff-scope`'s changed-file map, stamped into `ContextPackage`
    /// verbatim the same way `known_cves`/`design_controls` are — never
    /// touched by S1's own agentic call. Legitimately empty for a diff of
    /// only renames/deletions/mode changes/binary files, which is why
    /// `diff_scope_active` travels alongside it rather than being
    /// inferred from `is_empty()`.
    pub changed_files: BTreeMap<String, BTreeSet<i64>>,
    /// Whether `--diff-scope` was requested, stamped into
    /// `ContextPackage` alongside `changed_files` so downstream passes can
    /// tell "no scoping" from "scoping that matched nothing." `false`
    /// when diff-scope isn't active.
    pub diff_scope_active: bool,
    /// Free-text guidance from the active `bc-compliance` policy, stamped
    /// into `ContextPackage` verbatim the same way `known_cves`/
    /// `design_controls` are — never touched by S1's own agentic call.
    /// Empty when no compliance policy is active. Not a port — this
    /// tool's own feature.
    pub compliance_guidance: String,
    /// S0's static seed, when the profile enables it. `None`/an empty
    /// seed is a full no-op — walk, mode, and entry_points/sinks/
    /// call_graph all behave exactly as when S0 never ran.
    pub seed: Option<SeedPackage>,
}

pub struct Stage1 {
    client: Arc<dyn LlmClient>,
    tools: Arc<dyn ToolExecutor>,
    config: Step1Config,
}

impl Stage1 {
    pub fn new(
        client: Arc<dyn LlmClient>,
        tools: Arc<dyn ToolExecutor>,
        config: Step1Config,
    ) -> Self {
        Stage1 {
            client,
            tools,
            config,
        }
    }
}

fn json_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// `ContextPackage.excluded`'s untyped JSON shape, converted from
/// `bc-repo-analysis`'s typed exclusion/dedup reports. This is exactly
/// the shape `bc-report-md`'s scope appendix expects to consume —
/// `DedupReport.dropped`/`.promoted` are lists on the Rust side, but the
/// rendered shape needs their *counts* (matching the Python dict's own
/// `dropped`/`promoted` integer fields, distinct from the `promoted_files`
/// list key).
fn build_excluded_value(
    exclusion: &bc_repo_analysis::ExclusionReport,
    dedup: &bc_repo_analysis::DedupReport,
) -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    map.insert("dirs".to_string(), json!(exclusion.dirs));
    map.insert("exts".to_string(), json!(exclusion.exts));
    map.insert("globs".to_string(), json!(exclusion.globs));
    map.insert("oversize".to_string(), json!(exclusion.oversize));
    map.insert(
        "oversize_files".to_string(),
        json!(exclusion.oversize_files),
    );
    map.insert("symlinks".to_string(), json!(exclusion.symlinks));

    let top_clusters: Vec<Value> = dedup
        .top_clusters
        .iter()
        .map(|c| json!({"sample": c.sample, "size": c.size, "reps": c.reps, "dropped": c.dropped}))
        .collect();
    let promoted_files: Vec<Value> = dedup
        .promoted
        .iter()
        .map(|(p, why)| json!([p, why]))
        .collect();
    map.insert(
        "config_dedup".to_string(),
        json!({
            "candidates": dedup.candidates,
            "clusters": dedup.clusters,
            "kept_reps": dedup.kept_reps,
            "promoted": dedup.promoted.len(),
            "dropped": dedup.dropped.len(),
            "top_clusters": top_clusters,
            "promoted_files": promoted_files,
        }),
    );
    map
}

impl PipelineStage for Stage1 {
    type Input = Step1Input;
    type Output = ContextPackage;
    const NAME: &'static str = "s1-preprocess";

    async fn run(&self, input: Step1Input) -> Result<StageOutcome<ContextPackage>, StageError> {
        let skip_dirs = pure::advisory_skip_dirs(&self.config.walk.exclude_dirs);
        let user_prompt = prompts::build_user_prompt(&input.known_cves, &skip_dirs);

        // Reuse S0's own walk when it ran and found something, rather
        // than walking the repo a second time — the file list and
        // exclusion report both travel on the seed. Falls back to S1's
        // own walk when S0 was disabled or produced no walk.
        let (all_files, exclusion_report) = match &input.seed {
            Some(seed) if !seed.all_files.is_empty() => {
                (seed.all_files.clone(), seed.excluded.clone())
            }
            _ => bc_repo_analysis::walk_repo(&input.repo_root, &self.config.walk),
        };
        let (all_files, dedup_report) =
            bc_repo_analysis::dedup_configs(&all_files, &input.repo_root, &self.config.dedup);
        let excluded_value = build_excluded_value(&exclusion_report, &dedup_report);

        // `step1.mode: gap_fill` skips S1's own agentic exploration when
        // the S0 seed is strong enough; sparse coverage on a large,
        // service-shaped repo escalates back to `Full`. An absent or
        // empty seed always behaves like `Full` — matching Python's own
        // `if mode == "gap_fill" and seed:` guard, where a falsy seed
        // takes the agentic path regardless of the configured mode.
        let run_agentic_exploration = match (self.config.mode, &input.seed) {
            (Step1Mode::GapFill, Some(seed)) if seed.has_content() => {
                pure::should_escalate_gap_fill(seed, &all_files).0
            }
            _ => true,
        };

        let final_text = if run_agentic_exploration {
            let mut agentic_config = AgenticConfig::new(self.config.model.clone());
            agentic_config.system_prompt = Some(prompts::SYSTEM.to_string());
            agentic_config.allowed_tools = self.config.allowed_tools.clone();
            agentic_config.max_tokens = self.config.max_tokens;
            agentic_config.max_turns = self.config.max_turns;
            agentic_config.max_transient_retries = self.config.max_transient_retries;
            agentic_config.max_context_shrinks = self.config.max_context_shrinks;
            agentic_config.retry_backoff_base = self.config.retry_backoff_base;
            agentic_config.temperature = self.config.temperature;
            agentic_config.top_p = self.config.top_p;
            agentic_config.seed = self.config.seed;
            agentic_config.reasoning_effort = self.config.reasoning_effort;
            agentic_config.openai_api = self.config.openai_api;
            agentic_config.timeout_secs = self.config.timeout_secs;

            let outcome = run_agentic(
                self.client.as_ref(),
                self.tools.as_ref(),
                &user_prompt,
                &agentic_config,
            )
            .await
            .map_err(|e| {
                StageError::new(Self::NAME, format!("agentic mapping call failed: {e}"))
            })?;
            outcome.final_text
        } else {
            // Mirrors Python's `raw = "{}"` gap_fill short-circuit: an
            // empty object is valid JSON, so it flows through the exact
            // same degrade/parse path below as any other model output —
            // never a `Degraded` outcome on its own, since parsing "{}"
            // always succeeds.
            "{}".to_string()
        };

        // Degrade — don't abort the whole scan — when the mapper emits
        // empty or non-JSON output, mirroring the Python original: the
        // ground-truth walk and call-graph supplement below repopulate
        // file inventory and edges either way, so an empty agent map
        // still yields a usable `ContextPackage` (just without the LLM's
        // sink/entry-point guesses).
        let (mut data, degraded_reason): (Value, Option<String>) =
            match bc_json_repair::extract_json(&final_text) {
                Ok(Value::Object(map)) => (Value::Object(map), None),
                Ok(other) => {
                    let reason = format!(
                        "mapper response was valid JSON but not an object (got a {})",
                        json_kind(&other)
                    );
                    (json!({}), Some(reason))
                }
                Err(e) => {
                    let head: String = final_text.chars().take(500).collect();
                    let reason = format!("mapper response not parseable ({e}); raw[:500]={head:?}");
                    (json!({}), Some(reason))
                }
            };

        data = pure::unwrap_container(data);

        pure::scope_filter(&mut data, &input.repo_root, &all_files);

        // Merge S0's seed after the agent's own output has already been
        // scope-filtered: seed entry_points/sinks go through the exact
        // same in-scope path resolution, then S0's own AST-derived call
        // graph (when non-empty) is adopted directly — preferred over
        // the regex-based supplement below, which is skipped entirely in
        // that case (see `run_agentic_exploration`-adjacent
        // `skip_call_graph_supplement`).
        if let Some(seed) = &input.seed {
            pure::merge_seed_into_data(&mut data, &input.repo_root, &all_files, seed);
            pure::apply_seed_call_graph(&mut data, seed);
        }

        // `data` is always an object here: `extract_json`'s degrade path
        // uses `json!({})` and `unwrap_container` only ever substitutes
        // one object for another (or leaves it untouched) — never
        // produces a non-object from an object input. `.expect()` (a
        // std-library call, not a branch of this crate's own) converts
        // that invariant into straight-line code instead of an
        // unreachable `else` arm.
        let map = data
            .as_object_mut()
            .expect("data is always a JSON object at this point");
        map.insert(
            "repo_root".to_string(),
            json!(input.repo_root.to_string_lossy()),
        );
        let has_language = matches!(map.get("language"), Some(Value::String(s)) if !s.is_empty());
        if !has_language {
            map.insert(
                "language".to_string(),
                json!(pure::language_fallback(&all_files)),
            );
        }
        map.insert("all_files".to_string(), json!(all_files));
        map.insert(
            "excluded".to_string(),
            Value::Object(excluded_value.into_iter().collect()),
        );
        map.insert(
            "known_cves".to_string(),
            serde_json::to_value(&input.known_cves).expect("Cve serialization is infallible"),
        );
        map.insert(
            "design_controls".to_string(),
            serde_json::to_value(&input.design_controls)
                .expect("Control serialization is infallible"),
        );
        map.insert(
            "changed_files".to_string(),
            serde_json::to_value(&input.changed_files)
                .expect("changed_files serialization is infallible"),
        );
        map.insert(
            "diff_scope_active".to_string(),
            json!(input.diff_scope_active),
        );
        map.insert(
            "compliance_guidance".to_string(),
            json!(input.compliance_guidance),
        );

        // Call-graph backend dispatch, ported from `run()`'s `cg_mode`
        // block. `TreeSitter` (the default) gives exact def end-lines/
        // byte-ranges -> precise enclosing-caller resolution and real
        // `def_spans` for downstream function slicing.
        let has_seed_cg = data
            .get("call_graph")
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty());
        let has_seed_cg_files = data
            .get("call_graph_files")
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty());
        let has_seed_spans = data
            .get("def_spans")
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty());
        let has_full_seed_graph = has_seed_cg && has_seed_cg_files && has_seed_spans;

        match self.config.call_graph_mode {
            CallGraphMode::TreeSitter if has_full_seed_graph => {
                // S0's graph is authoritative but only covers the
                // languages its engine has plugins for. Reusing it
                // wholesale would mark every file in every OTHER
                // language structurally unreachable — gate reuse on
                // LANGUAGE COVERAGE, not artifact non-emptiness: keep
                // S0 as the primary graph, but back the residual-
                // language file set with a tree-sitter rebuild and
                // merge per language so no language is silently
                // dropped from reachability.
                let covered = pure::seed_covered_languages(&data);
                let residual: Vec<String> = all_files
                    .iter()
                    .filter(|f| pure::is_residual_language_file(f, &covered))
                    .cloned()
                    .collect();
                if !residual.is_empty() {
                    let seed_cg = pure::parse_call_graph(&data);
                    let seed_cgf = pure::parse_call_graph_files(&data);
                    let seed_spans = pure::parse_def_spans(&data);
                    let result = bc_repo_analysis::ts_graph_build(
                        &residual,
                        &input.repo_root,
                        self.config.call_graph.max_targets,
                        &BTreeMap::new(),
                    );
                    pure::apply_ts_graph_result(&mut data, &result);
                    pure::merge_graph_artifacts(&mut data, seed_cg, seed_cgf, seed_spans);
                }
            }
            CallGraphMode::TreeSitter => {
                // No usable S0 seed graph (or only a partial one) —
                // full tree-sitter build over every in-scope file,
                // regrafting whatever's currently in `data` (a partial
                // seed, or the agent's own raw output) as prior edges.
                let prior = pure::parse_call_graph(&data);
                let result = bc_repo_analysis::ts_graph_build(
                    &all_files,
                    &input.repo_root,
                    self.config.call_graph.max_targets,
                    &prior,
                );
                pure::apply_ts_graph_result(&mut data, &result);
            }
            CallGraphMode::Regex if has_full_seed_graph => {}
            CallGraphMode::Regex => {
                let entry_point_functions = pure::extract_function_names(&data, "entry_points");
                let sink_functions = pure::extract_function_names(&data, "unsafe_sinks");
                let raw_call_graph = pure::parse_call_graph(&data);
                let cg_result = bc_repo_analysis::supplement_call_graph(
                    &raw_call_graph,
                    &entry_point_functions,
                    &sink_functions,
                    &all_files,
                    &input.repo_root,
                    &self.config.call_graph,
                );
                let map = data
                    .as_object_mut()
                    .expect("data is always a JSON object at this point");
                map.insert(
                    "call_graph".to_string(),
                    serde_json::to_value(&cg_result.call_graph)
                        .expect("call graph serialization is infallible"),
                );
                map.insert(
                    "call_graph_files".to_string(),
                    serde_json::to_value(&cg_result.call_graph_files)
                        .expect("call graph files serialization is infallible"),
                );
            }
        }

        let pkg: ContextPackage = serde_json::from_value(data).map_err(|e| {
            StageError::new(Self::NAME, format!("ContextPackage assembly failed: {e}"))
        })?;

        match degraded_reason {
            Some(reason) => Ok(StageOutcome::Degraded { value: pkg, reason }),
            None => Ok(StageOutcome::Ok(pkg)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bc_llm_client::{ChatRequest, ChatResponse, LlmError, StopReason, ToolSpec, Usage};
    use std::sync::Mutex;

    struct ScriptedClient {
        replies: Mutex<Vec<String>>,
    }

    impl ScriptedClient {
        fn new(replies: Vec<&str>) -> Self {
            ScriptedClient {
                replies: Mutex::new(replies.into_iter().rev().map(str::to_string).collect()),
            }
        }
    }

    #[async_trait]
    impl LlmClient for ScriptedClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let text = self.replies.lock().unwrap().pop().unwrap_or_default();
            Ok(ChatResponse {
                content: vec![bc_llm_client::ContentBlock::Text(text)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    /// Requests one tool call on its first turn, then finishes with the
    /// final JSON on its second — exercises the injected `ToolExecutor`
    /// for real, unlike `ScriptedClient` (which always finishes on turn
    /// one and never actually calls `execute`).
    struct ToolCallThenFinishClient {
        turn: Mutex<u32>,
    }

    #[async_trait]
    impl LlmClient for ToolCallThenFinishClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let mut turn = self.turn.lock().unwrap();
            *turn += 1;
            if *turn == 1 {
                Ok(ChatResponse {
                    content: vec![bc_llm_client::ContentBlock::ToolUse {
                        id: "1".to_string(),
                        name: "Read".to_string(),
                        input: json!({"path": "app.py"}),
                    }],
                    stop_reason: StopReason::ToolUse,
                    usage: Usage::default(),
                })
            } else {
                let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
                Ok(ChatResponse {
                    content: vec![bc_llm_client::ContentBlock::Text(json.to_string())],
                    stop_reason: StopReason::EndTurn,
                    usage: Usage::default(),
                })
            }
        }
    }

    /// Declares support for the stage's default `allowed_tools` (so
    /// `run_agentic`'s tool-support check passes) but is never actually
    /// invoked by these tests — the scripted client always stops on its
    /// first turn without requesting a tool call.
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

    fn write(dir: &std::path::Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn stage(replies: Vec<&str>) -> Stage1 {
        Stage1::new(
            Arc::new(ScriptedClient::new(replies)),
            Arc::new(NoTools),
            Step1Config::new("test-model"),
        )
    }

    fn input(repo_root: &std::path::Path) -> Step1Input {
        Step1Input {
            repo_root: repo_root.to_path_buf(),
            known_cves: Vec::new(),
            design_controls: Vec::new(),
            changed_files: BTreeMap::new(),
            diff_scope_active: false,
            compliance_guidance: String::new(),
            seed: None,
        }
    }

    #[tokio::test]
    async fn well_formed_agent_output_produces_ok_not_degraded() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app.py", "def handle():\n    run_query()\n");

        let json = r#"{"language":"python","modules":[],"entry_points":[{"file":"app.py","function":"handle","kind":"network","reachable_from_unauth":true}],"unsafe_sinks":[],"call_graph":{},"notes":"n"}"#;
        let s1 = stage(vec![json]);
        let outcome = s1.run(input(dir.path())).await.unwrap();
        assert!(!outcome.is_degraded());
        let pkg = outcome.into_value();
        assert_eq!(pkg.language, "python");
        assert_eq!(pkg.entry_points.len(), 1);
        assert_eq!(pkg.repo_root, dir.path().to_string_lossy());
    }

    #[tokio::test]
    async fn malformed_agent_output_degrades_but_still_yields_a_usable_package() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app.py", "print('hi')\n");

        let s1 = stage(vec!["not json at all, sorry"]);
        let outcome = s1.run(input(dir.path())).await.unwrap();
        assert!(outcome.is_degraded());
        assert!(outcome.reason().unwrap().contains("not parseable"));
        let pkg = outcome.into_value();
        assert_eq!(pkg.language, "python"); // language fallback from all_files
        assert!(pkg.all_files.contains(&"app.py".to_string()));
    }

    #[tokio::test]
    async fn non_object_json_output_degrades() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.txt", "x");
        let s1 = stage(vec!["[1, 2, 3]"]);
        let outcome = s1.run(input(dir.path())).await.unwrap();
        assert!(outcome.is_degraded());
        assert!(outcome.reason().unwrap().contains("not an object"));
    }

    #[tokio::test]
    async fn container_wrapped_output_is_unwrapped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app.py", "x");
        let json = r#"{"context_package": {"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}}"#;
        let s1 = stage(vec![json]);
        let outcome = s1.run(input(dir.path())).await.unwrap();
        assert!(!outcome.is_degraded());
        assert_eq!(outcome.into_value().language, "python");
    }

    #[tokio::test]
    async fn entry_points_outside_ground_truth_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app.py", "x");
        let json = r#"{"language":"python","modules":[],"entry_points":[{"file":"app.py","function":"h","kind":"network","reachable_from_unauth":true},{"file":"nonexistent.py","function":"i","kind":"network","reachable_from_unauth":true}],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let outcome = s1.run(input(dir.path())).await.unwrap();
        let pkg = outcome.into_value();
        assert_eq!(pkg.entry_points.len(), 1);
        assert_eq!(pkg.entry_points[0].file, "app.py");
    }

    #[tokio::test]
    async fn missing_required_field_on_a_typed_item_is_a_fatal_error_not_a_degrade() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app.py", "x");
        // "function" is required on EntryPoint with no default — a
        // present-but-incomplete item must fail the whole assembly, not
        // silently degrade (matches the Python original's uncaught
        // `pydantic.ValidationError` from `ContextPackage.model_validate`).
        let json = r#"{"language":"python","modules":[],"entry_points":[{"file":"app.py","kind":"network"}],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let result = s1.run(input(dir.path())).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn known_cves_and_controls_are_carried_through_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "x");
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let mut inp = input(dir.path());
        inp.known_cves = vec![Cve {
            id: "CVE-1".to_string(),
            summary: "s".to_string(),
            affected_files: Vec::new(),
            cvss: None,
            patched: false,
        }];
        inp.changed_files = BTreeMap::from([("a.py".to_string(), BTreeSet::from([1, 2]))]);
        inp.diff_scope_active = true;
        inp.compliance_guidance = "Prioritize PCI-DSS Req 6 findings.".to_string();
        let outcome = s1.run(inp).await.unwrap();
        let pkg = outcome.into_value();
        assert_eq!(pkg.known_cves.len(), 1);
        assert_eq!(pkg.known_cves[0].id, "CVE-1");
        assert_eq!(pkg.changed_files.get("a.py"), Some(&BTreeSet::from([1, 2])));
        assert!(pkg.diff_scope_active);
        assert_eq!(
            pkg.compliance_guidance,
            "Prioritize PCI-DSS Req 6 findings."
        );
    }

    #[tokio::test]
    async fn diff_scope_active_survives_an_empty_changed_file_map() {
        // The rename-only PR: `changed_files` is legitimately empty, and
        // the flag is the only thing telling S3/S4 that scoping applies.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "x");
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let mut inp = input(dir.path());
        inp.diff_scope_active = true;
        let pkg = s1.run(inp).await.unwrap().into_value();
        assert!(pkg.diff_scope_active);
        assert!(pkg.changed_files.is_empty());
    }

    #[tokio::test]
    async fn diff_scope_inactive_is_carried_through_as_false() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "x");
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let pkg = s1.run(input(dir.path())).await.unwrap().into_value();
        assert!(!pkg.diff_scope_active);
    }

    #[tokio::test]
    async fn compliance_guidance_defaults_to_empty_when_unset() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "x");
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let outcome = s1.run(input(dir.path())).await.unwrap();
        let pkg = outcome.into_value();
        assert_eq!(pkg.compliance_guidance, "");
    }

    // ── S0 seed integration ──────────────────────────────────────────

    /// Proves the agentic call was never invoked — used to verify the
    /// `gap_fill` skip path actually skips, not just that its output
    /// happens to look the same as if it ran.
    struct PanicsIfCalledClient;
    #[async_trait]
    impl LlmClient for PanicsIfCalledClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            panic!("agentic call should have been skipped in gap_fill mode");
        }
    }

    #[tokio::test]
    #[should_panic(expected = "agentic call should have been skipped")]
    async fn panics_if_called_client_actually_panics() {
        let request = ChatRequest::new("m", Vec::new(), 1);
        let _ = PanicsIfCalledClient.chat(&request).await;
    }

    fn seed_ep(
        file: &str,
        kind: bc_model::EntryPointKind,
        reachable: bool,
    ) -> bc_model::EntryPoint {
        bc_model::EntryPoint {
            file: file.to_string(),
            function: "handler".to_string(),
            kind,
            reachable_from_unauth: reachable,
        }
    }

    fn seed_sink(file: &str, cwe: &[&str]) -> bc_model::Sink {
        bc_model::Sink {
            file: file.to_string(),
            line: 3,
            function: "system".to_string(),
            snippet: "os.system(cmd)".to_string(),
            cwe: cwe.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn seed_all_files_is_reused_instead_of_re_walking() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "x");
        write(dir.path(), "b.py", "x"); // present on disk but NOT in the seed's walk
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let mut inp = input(dir.path());
        inp.seed = Some(SeedPackage {
            all_files: vec!["a.py".to_string()],
            ..Default::default()
        });
        let outcome = s1.run(inp).await.unwrap();
        let pkg = outcome.into_value();
        assert_eq!(pkg.all_files, vec!["a.py".to_string()]);
    }

    #[tokio::test]
    async fn seed_with_empty_all_files_falls_back_to_a_real_walk() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "c.py", "x");
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let mut inp = input(dir.path());
        inp.seed = Some(SeedPackage::default()); // all_files empty
        let outcome = s1.run(inp).await.unwrap();
        assert!(outcome.into_value().all_files.contains(&"c.py".to_string()));
    }

    #[tokio::test]
    async fn gap_fill_mode_skips_the_agentic_call_on_a_small_repo() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Step1Config::new("test-model");
        cfg.mode = Step1Mode::GapFill;
        let s1 = Stage1::new(Arc::new(PanicsIfCalledClient), Arc::new(NoTools), cfg);
        let mut inp = input(dir.path());
        inp.seed = Some(SeedPackage {
            all_files: vec!["a.py".to_string()],
            entry_points: vec![seed_ep("a.py", bc_model::EntryPointKind::Network, false)],
            ..Default::default()
        });
        // Doesn't panic => the agentic call was genuinely skipped.
        let outcome = s1.run(inp).await.unwrap();
        assert!(!outcome.is_degraded());
    }

    #[tokio::test]
    async fn gap_fill_mode_with_no_seed_content_still_runs_the_agentic_call() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "x");
        let json = r#"{"language":"rust","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let mut cfg = Step1Config::new("test-model");
        cfg.mode = Step1Mode::GapFill;
        let s1 = Stage1::new(
            Arc::new(ScriptedClient::new(vec![json])),
            Arc::new(NoTools),
            cfg,
        );
        let mut inp = input(dir.path());
        inp.seed = Some(SeedPackage::default()); // has_content() == false
        let outcome = s1.run(inp).await.unwrap();
        // "rust" could only have come from the agent's own output, not
        // from the extension-majority fallback (the file is a.py).
        assert_eq!(outcome.into_value().language, "rust");
    }

    #[tokio::test]
    async fn gap_fill_mode_escalates_to_full_on_a_large_service_shaped_repo_with_sparse_seed() {
        let dir = tempfile::tempdir().unwrap();
        let all_files: Vec<String> = (0..501).map(|i| format!("src/f{i}.py")).collect();
        let json = r#"{"language":"rust","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let mut cfg = Step1Config::new("test-model");
        cfg.mode = Step1Mode::GapFill;
        let s1 = Stage1::new(
            Arc::new(ScriptedClient::new(vec![json])),
            Arc::new(NoTools),
            cfg,
        );
        let mut inp = input(dir.path());
        let entry_points = (0..10)
            .map(|i| {
                seed_ep(
                    &format!("src/f{i}.py"),
                    bc_model::EntryPointKind::Network,
                    false,
                )
            })
            .collect();
        inp.seed = Some(SeedPackage {
            all_files: all_files.clone(),
            entry_points,
            unsafe_sinks: Vec::new(), // < 5, satisfies the escalation predicate
            ..Default::default()
        });
        let outcome = s1.run(inp).await.unwrap();
        // Escalated to Full => the agentic call ran and its output won.
        assert_eq!(outcome.into_value().language, "rust");
    }

    #[tokio::test]
    async fn seed_entry_points_and_sinks_are_merged_after_agent_output() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "x");
        let json = r#"{"language":"python","modules":[],"entry_points":[{"file":"a.py","function":"agent_ep","kind":"cli","reachable_from_unauth":false}],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let mut inp = input(dir.path());
        inp.seed = Some(SeedPackage {
            all_files: vec!["a.py".to_string()],
            entry_points: vec![seed_ep("a.py", bc_model::EntryPointKind::Network, true)],
            unsafe_sinks: vec![seed_sink("a.py", &["CWE-78"])],
            ..Default::default()
        });
        let outcome = s1.run(inp).await.unwrap();
        let pkg = outcome.into_value();
        assert_eq!(pkg.entry_points.len(), 2);
        assert!(pkg.entry_points.iter().any(|e| e.function == "agent_ep"));
        assert!(pkg.entry_points.iter().any(|e| e.function == "handler"
            && e.kind == bc_model::EntryPointKind::Network
            && e.reachable_from_unauth));
        assert_eq!(pkg.unsafe_sinks.len(), 1);
        assert_eq!(pkg.unsafe_sinks[0].cwe, vec!["CWE-78".to_string()]);
    }

    #[tokio::test]
    async fn seed_entry_points_outside_ground_truth_are_dropped_same_as_agent_output() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "x");
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let mut inp = input(dir.path());
        inp.seed = Some(SeedPackage {
            all_files: vec!["a.py".to_string()],
            entry_points: vec![seed_ep(
                "outside.py",
                bc_model::EntryPointKind::Network,
                false,
            )],
            ..Default::default()
        });
        let outcome = s1.run(inp).await.unwrap();
        assert!(outcome.into_value().entry_points.is_empty());
    }

    #[tokio::test]
    async fn seed_call_graph_is_adopted_and_supplement_is_skipped() {
        // A COMPLETE seed (call_graph + call_graph_files + def_spans, all
        // qualified `"file::name"` qnodes, matching real production
        // shape) whose only in-scope file's language ("python") is
        // therefore already fully covered — `ts_graph`'s residual-file
        // set is empty, so it never runs at all and the seed's graph
        // passes through untouched. A partial (2-of-3-field) seed is
        // exercised separately by
        // `partial_seed_call_graph_is_backed_by_a_tree_sitter_rebuild`.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def f():\n    g()\n");
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{"agent_only":["nope"]},"notes":""}"#;
        let s1 = stage(vec![json]);
        let mut inp = input(dir.path());
        inp.seed = Some(SeedPackage {
            all_files: vec!["a.py".to_string()],
            call_graph: BTreeMap::from([("a.py::f".to_string(), vec!["a.py::g".to_string()])]),
            call_graph_files: BTreeMap::from([("f".to_string(), vec!["a.py:1".to_string()])]),
            def_spans: BTreeMap::from([("a.py::f".to_string(), (1, 2))]),
            ..Default::default()
        });
        let outcome = s1.run(inp).await.unwrap();
        let pkg = outcome.into_value();
        // Seed's call graph wins outright; the agent's own `call_graph`
        // key never survives, proving the regex supplement (which would
        // have parsed `raw_call_graph` from the agent's JSON) was
        // skipped rather than merged.
        assert_eq!(
            pkg.call_graph.get("a.py::f"),
            Some(&vec!["a.py::g".to_string()])
        );
        assert!(!pkg.call_graph.contains_key("agent_only"));
        assert_eq!(
            pkg.call_graph_files.get("f"),
            Some(&vec!["a.py:1".to_string()])
        );
        assert_eq!(pkg.def_spans.get("a.py::f"), Some(&(1, 2)));
    }

    #[tokio::test]
    async fn partial_seed_call_graph_is_backed_by_a_tree_sitter_rebuild() {
        // A seed with call_graph/call_graph_files but NO def_spans is
        // "partial" — `has_full_seed_graph` is false, so this takes the
        // full-rebuild dispatch branch (not the residual-language one),
        // regrafting the seed's own (qualified) edges as prior edges.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a.py",
            "def f():\n    g()\n\n\ndef g():\n    pass\n",
        );
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let mut inp = input(dir.path());
        inp.seed = Some(SeedPackage {
            all_files: vec!["a.py".to_string()],
            call_graph: BTreeMap::from([("a.py::f".to_string(), vec!["a.py::g".to_string()])]),
            call_graph_files: BTreeMap::from([("f".to_string(), vec!["a.py:1".to_string()])]),
            ..Default::default()
        });
        let outcome = s1.run(inp).await.unwrap();
        let pkg = outcome.into_value();
        // The real tree-sitter rebuild finds the same edge (a.py's `g`
        // really is defined and really is called from `f`) AND now has
        // real def_spans, which the partial seed alone never carried.
        assert_eq!(
            pkg.call_graph.get("a.py::f"),
            Some(&vec!["a.py::g".to_string()])
        );
        assert!(pkg.def_spans.contains_key("a.py::f"));
        assert!(pkg.def_spans.contains_key("a.py::g"));
    }

    #[tokio::test]
    async fn residual_language_files_are_backed_by_tree_sitter_and_merged_with_the_seed() {
        // The seed's graph only names a python file — javascript is
        // "residual" (a language `all_files` has but the seed's
        // artifacts never mention). `ts_graph` should scan ONLY the
        // residual file, and its result should be UNIONED with the
        // seed's python graph, not replace it.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def f():\n    pass\n");
        write(
            dir.path(),
            "b.js",
            "function jscaller() { jscallee(); }\nfunction jscallee() {}\n",
        );
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let mut inp = input(dir.path());
        inp.seed = Some(SeedPackage {
            all_files: vec!["a.py".to_string(), "b.js".to_string()],
            // A synthetic edge to a name that doesn't actually exist in
            // `a.py`'s real content — this can ONLY survive via the
            // seed-merge path (`merge_graph_artifacts`), never by
            // coincidentally being rediscovered by a real scan, making
            // this assertion airtight proof the merge ran (not just a
            // full rebuild that happened to agree with the seed).
            call_graph: BTreeMap::from([(
                "a.py::f".to_string(),
                vec!["a.py::seed_only_edge".to_string()],
            )]),
            call_graph_files: BTreeMap::from([("f".to_string(), vec!["a.py:1".to_string()])]),
            def_spans: BTreeMap::from([("a.py::f".to_string(), (1, 2))]),
            ..Default::default()
        });
        let outcome = s1.run(inp).await.unwrap();
        let pkg = outcome.into_value();
        // The seed's own (otherwise unrediscoverable) edge survived...
        assert_eq!(
            pkg.call_graph.get("a.py::f"),
            Some(&vec!["a.py::seed_only_edge".to_string()])
        );
        // ...alongside the residual JS scan's own, independently
        // discovered real edge.
        assert_eq!(
            pkg.call_graph.get("b.js::jscaller"),
            Some(&vec!["b.js::jscallee".to_string()])
        );
        // ...merged alongside (not instead of) the seed's own def_spans.
        assert_eq!(pkg.def_spans.get("a.py::f"), Some(&(1, 2)));
        assert!(pkg.def_spans.contains_key("b.js::jscaller"));
    }

    #[tokio::test]
    async fn regex_mode_uses_the_regex_supplement_instead_of_tree_sitter() {
        let dir = tempfile::tempdir().unwrap();
        // `CALL_TOKEN_RX` (the regex path's call-site scanner) requires
        // 3+ character names — unlike `ts_graph`'s query-driven callee
        // extraction, which accepts 2+.
        write(
            dir.path(),
            "a.py",
            "def caller():\n    callee()\n\n\ndef callee():\n    pass\n",
        );
        // `supplement_call_graph`'s BFS runs BACKWARD from a seed name —
        // it looks for CALL SITES of that name to discover callers, not
        // for the seed's own outgoing calls. Seeding with `callee` (the
        // sink) lets it find the `callee()` call site inside `caller`'s
        // body and discover the `caller -> callee` edge; seeding with
        // `caller` itself would find nothing (nothing calls `caller`).
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[{"file":"a.py","function":"callee"}],"call_graph":{},"notes":""}"#;
        let mut config = Step1Config::new("test-model");
        config.call_graph_mode = CallGraphMode::Regex;
        let s1 = Stage1::new(
            Arc::new(ScriptedClient::new(vec![json])),
            Arc::new(NoTools),
            config,
        );
        let outcome = s1.run(input(dir.path())).await.unwrap();
        let pkg = outcome.into_value();
        // `supplement_call_graph` qualifies edges the same way
        // `ts_graph` does (`q_join`) — what distinguishes this from the
        // default `TreeSitter` mode's output is that it never populates
        // `def_spans` at all (no AST, no byte ranges to record).
        assert_eq!(
            pkg.call_graph.get("a.py::caller"),
            Some(&vec!["a.py::callee".to_string()])
        );
        assert!(pkg.def_spans.is_empty());
    }

    #[tokio::test]
    async fn regex_mode_skips_the_supplement_when_a_full_seed_graph_is_present() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def f():\n    g()\n");
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{"agent_only":["nope"]},"notes":""}"#;
        let mut config = Step1Config::new("test-model");
        config.call_graph_mode = CallGraphMode::Regex;
        let s1 = Stage1::new(
            Arc::new(ScriptedClient::new(vec![json])),
            Arc::new(NoTools),
            config,
        );
        let mut inp = input(dir.path());
        inp.seed = Some(SeedPackage {
            all_files: vec!["a.py".to_string()],
            call_graph: BTreeMap::from([("a.py::f".to_string(), vec!["a.py::g".to_string()])]),
            call_graph_files: BTreeMap::from([("f".to_string(), vec!["a.py:1".to_string()])]),
            def_spans: BTreeMap::from([("a.py::f".to_string(), (1, 2))]),
            ..Default::default()
        });
        let outcome = s1.run(inp).await.unwrap();
        let pkg = outcome.into_value();
        assert_eq!(
            pkg.call_graph.get("a.py::f"),
            Some(&vec!["a.py::g".to_string()])
        );
        assert!(!pkg.call_graph.contains_key("agent_only"));
    }

    #[tokio::test]
    async fn empty_seed_call_graph_still_runs_the_normal_call_graph_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def f():\n    g()\n");
        let json = r#"{"language":"python","modules":[],"entry_points":[],"unsafe_sinks":[],"call_graph":{},"notes":""}"#;
        let s1 = stage(vec![json]);
        let mut inp = input(dir.path());
        inp.seed = Some(SeedPackage {
            all_files: vec!["a.py".to_string()],
            ..Default::default()
        });
        let outcome = s1.run(inp).await.unwrap();
        // No assertion tied to backend internals here — this just proves
        // the presence of a (content-empty) seed doesn't panic or
        // otherwise short-circuit the ordinary call-graph dispatch
        // (`CallGraphMode::TreeSitter` by default — see the dedicated
        // dispatch tests above for its actual per-mode behavior).
        assert!(!outcome.is_degraded());
    }

    #[tokio::test]
    async fn agentic_call_failure_is_fatal() {
        struct FailingClient;
        #[async_trait]
        impl LlmClient for FailingClient {
            async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
                Err(LlmError::ConnectionError {
                    message: "boom".to_string(),
                })
            }
        }
        let dir = tempfile::tempdir().unwrap();
        // Zero retries/backoff so a retryable error still fails immediately
        // rather than looping through `max_transient_retries` real
        // attempts in this test.
        let mut cfg = Step1Config::new("test-model");
        cfg.max_transient_retries = 0;
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let s1 = Stage1::new(Arc::new(FailingClient), Arc::new(NoTools), cfg);
        let result = s1.run(input(dir.path())).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("agentic mapping call failed"));
    }

    #[test]
    fn json_kind_covers_every_variant() {
        assert_eq!(json_kind(&Value::Null), "null");
        assert_eq!(json_kind(&json!(true)), "boolean");
        assert_eq!(json_kind(&json!(1)), "number");
        assert_eq!(json_kind(&json!("s")), "string");
        assert_eq!(json_kind(&json!([1])), "array");
        assert_eq!(json_kind(&json!({"a": 1})), "object");
    }

    #[tokio::test]
    async fn tool_call_round_trip_exercises_the_injected_tool_executor() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "app.py", "x");
        let s1 = Stage1::new(
            Arc::new(ToolCallThenFinishClient {
                turn: Mutex::new(0),
            }),
            Arc::new(NoTools),
            Step1Config::new("test-model"),
        );
        let outcome = s1.run(input(dir.path())).await.unwrap();
        assert!(!outcome.is_degraded());
        assert_eq!(outcome.into_value().language, "python");
    }

    #[test]
    fn build_excluded_value_shapes_config_dedup_counts_not_lists() {
        let exclusion = bc_repo_analysis::ExclusionReport::default();
        let dedup = bc_repo_analysis::DedupReport {
            dropped: vec!["a.yaml".to_string(), "b.yaml".to_string()],
            promoted: vec![("c.yaml".to_string(), "secret".to_string())],
            top_clusters: vec![bc_repo_analysis::ClusterSummary {
                shape: "abc123".to_string(),
                size: 5,
                reps: vec!["rep.yaml".to_string()],
                dropped: 4,
                sample: "rep.yaml".to_string(),
            }],
            ..Default::default()
        };
        let value = build_excluded_value(&exclusion, &dedup);
        let cd = &value["config_dedup"];
        assert_eq!(cd["dropped"], json!(2));
        assert_eq!(cd["promoted"], json!(1));
        assert_eq!(cd["promoted_files"], json!([["c.yaml", "secret"]]));
        assert_eq!(
            cd["top_clusters"],
            json!([{"sample": "rep.yaml", "size": 5, "reps": ["rep.yaml"], "dropped": 4}])
        );
    }
}
