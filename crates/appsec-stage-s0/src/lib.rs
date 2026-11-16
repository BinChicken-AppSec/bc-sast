mod engine;
mod llm_detect;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use appsec_llm_client::LlmClient;
use appsec_model::{
    EntryPoint, EntryPointKind, Sink, TaintEvidencePath, TaintSymbolRef, TaintTransferEdge,
};
use appsec_pipeline_core::{PipelineStage, StageError, StageOutcome};
use appsec_repo_analysis::{ExclusionReport, WalkConfig};

pub use engine::{run_callgraph_engine, scan_repo, EngineConfig};
pub use llm_detect::{detect_specs, Step0LlmConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetectionMode {
    #[default]
    Rules,
    Llm,
}

impl DetectionMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "rules" => Some(DetectionMode::Rules),
            "llm" => Some(DetectionMode::Llm),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DetectionMode::Rules => "rules",
            DetectionMode::Llm => "llm",
        }
    }
}

pub struct Step0Config {
    pub enabled: bool,
    pub detection_mode: DetectionMode,
    pub languages: Vec<String>,
    pub sources_yaml: Option<PathBuf>,
    pub sinks_yaml: Option<PathBuf>,
    pub call_graph_max_targets: usize,
    pub walk: WalkConfig,
    pub llm: Option<Step0LlmConfig>,
}

impl Step0Config {
    pub fn new() -> Self {
        Step0Config {
            enabled: true,
            detection_mode: DetectionMode::Rules,
            languages: Vec::new(),
            sources_yaml: None,
            sinks_yaml: None,
            call_graph_max_targets: appsec_callgraph::graph::DEFAULT_MAX_TARGETS_PER_CALL,
            walk: WalkConfig::new(),
            llm: None,
        }
    }
}

impl Default for Step0Config {
    fn default() -> Self {
        Step0Config::new()
    }
}

pub struct Step0Input {
    pub repo_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SeedPackage {
    pub entry_points: Vec<EntryPoint>,
    pub framework_entry_points: Vec<EntryPoint>,
    pub unsafe_sinks: Vec<Sink>,
    pub taint_paths: Vec<Vec<String>>,
    pub taint_evidence: Vec<TaintEvidencePath>,
    pub rule_cwe: BTreeMap<String, Vec<String>>,
    pub call_graph: BTreeMap<String, Vec<String>>,
    pub call_graph_files: BTreeMap<String, Vec<String>>,
    pub def_spans: BTreeMap<String, (usize, usize)>,
    pub call_graph_confidence: BTreeMap<(String, String), f64>,
    pub engine: String,
    pub languages: Vec<String>,
    pub all_files: Vec<String>,
    pub excluded: ExclusionReport,
}

impl SeedPackage {
    fn empty(engine: &str, languages: Vec<String>) -> Self {
        SeedPackage {
            entry_points: Vec::new(),
            framework_entry_points: Vec::new(),
            unsafe_sinks: Vec::new(),
            taint_paths: Vec::new(),
            taint_evidence: Vec::new(),
            rule_cwe: BTreeMap::new(),
            call_graph: BTreeMap::new(),
            call_graph_files: BTreeMap::new(),
            def_spans: BTreeMap::new(),
            call_graph_confidence: BTreeMap::new(),
            engine: engine.to_string(),
            languages,
            all_files: Vec::new(),
            excluded: ExclusionReport::default(),
        }
    }

    pub fn has_content(&self) -> bool {
        !self.entry_points.is_empty()
            || !self.unsafe_sinks.is_empty()
            || !self.taint_paths.is_empty()
            || !self.taint_evidence.is_empty()
            || !self.call_graph.is_empty()
            || !self.call_graph_files.is_empty()
            || !self.def_spans.is_empty()
            || !self.framework_entry_points.is_empty()
    }
}

impl Default for SeedPackage {
    fn default() -> Self {
        SeedPackage::empty("callgraph", Vec::new())
    }
}

fn convert_symbol_ref(r: appsec_callgraph::TaintSymbolRef) -> TaintSymbolRef {
    TaintSymbolRef {
        qnode: r.qnode,
        symbol: r.symbol,
        kind: r.kind,
    }
}

fn convert_edge(e: appsec_callgraph::TaintTransferEdge) -> TaintTransferEdge {
    TaintTransferEdge {
        file: e.file,
        line: e.line as i64,
        function_qnode: e.function_qnode,
        src: convert_symbol_ref(e.src),
        dst: convert_symbol_ref(e.dst),
        transfer_kind: e.transfer_kind,
        condition_text: None,
        is_tainted_condition: None,
        confidence: e.confidence,
        call_type: None,
        reflected_targets: (!e.reflected_targets.is_empty()).then_some(e.reflected_targets),
        is_speculative: e.is_speculative,
        framework: None,
        marker_type: None,
    }
}

fn convert_evidence(p: appsec_callgraph::TaintEvidencePath) -> TaintEvidencePath {
    TaintEvidencePath {
        source_ref: p.source_ref,
        sink_ref: p.sink_ref,
        path_funcs: p.path_funcs,
        edges: p.edges.into_iter().map(convert_edge).collect(),
        sink_cwe: p.sink_cwe,
        sanitized: p.sanitized,
    }
}

fn convert_entry_point(ep: appsec_callgraph::EntryPoint) -> EntryPoint {
    EntryPoint {
        file: ep.file,
        function: ep.function,
        kind: EntryPointKind::parse(&ep.kind),
        reachable_from_unauth: ep.reachable_from_unauth,
    }
}

fn convert_sink(s: appsec_callgraph::Sink) -> Sink {
    Sink {
        file: s.file,
        line: s.line as i64,
        function: s.function,
        snippet: s.snippet,
        cwe: s.cwe,
    }
}

fn convert_taint_seed(
    seed: appsec_callgraph::TaintSeed,
    engine: &str,
    languages: Vec<String>,
) -> SeedPackage {
    SeedPackage {
        entry_points: seed
            .entry_points
            .into_iter()
            .map(convert_entry_point)
            .collect(),
        framework_entry_points: seed
            .framework_entry_points
            .into_iter()
            .map(convert_entry_point)
            .collect(),
        unsafe_sinks: seed.unsafe_sinks.into_iter().map(convert_sink).collect(),
        taint_paths: seed.taint_paths,
        taint_evidence: seed
            .taint_evidence
            .into_iter()
            .map(convert_evidence)
            .collect(),
        rule_cwe: seed.rule_cwe,
        call_graph: seed.call_graph,
        call_graph_files: seed.call_graph_files,
        def_spans: seed.def_spans,
        call_graph_confidence: seed.call_graph_confidence,
        engine: engine.to_string(),
        languages,
        all_files: Vec::new(),
        excluded: ExclusionReport::default(),
    }
}

pub async fn run_seed(
    repo_root: &std::path::Path,
    config: &Step0Config,
    client: Option<&dyn LlmClient>,
) -> SeedPackage {
    if !config.enabled {
        return SeedPackage::default();
    }

    let (all_files, excluded) = appsec_repo_analysis::walk_repo(repo_root, &config.walk);
    let in_scope: std::collections::BTreeSet<String> = all_files.iter().cloned().collect();
    let detected = appsec_repo_analysis::detect_languages(&all_files, Some(repo_root));
    let langs = engine::filter_step0_languages(&detected, &config.languages);

    let engine_config = EngineConfig {
        detection_mode: config.detection_mode,
        sources_yaml: config.sources_yaml.clone(),
        sinks_yaml: config.sinks_yaml.clone(),
        call_graph_max_targets: config.call_graph_max_targets,
        llm: config.llm.as_ref().map(|c| Step0LlmConfig {
            model: c.model.clone(),
            max_candidates: c.max_candidates,
            max_batch_candidates: c.max_batch_candidates,
            min_source_confidence: c.min_source_confidence,
            min_sink_confidence: c.min_sink_confidence,
            max_tokens: c.max_tokens,
            heuristic_supplement: c.heuristic_supplement,
            min_sources: c.min_sources,
            min_sinks: c.min_sinks,
            max_heuristic_specs: c.max_heuristic_specs,
            temperature: c.temperature,
            top_p: c.top_p,
            seed: c.seed,
            reasoning_effort: c.reasoning_effort,
            openai_api: c.openai_api,
            timeout_secs: c.timeout_secs,
        }),
    };
    let mut seed = run_callgraph_engine(repo_root, &in_scope, &langs, &engine_config, client).await;
    seed.all_files = all_files;
    seed.excluded = excluded;
    seed
}

pub struct Stage0 {
    config: Step0Config,
    llm_client: Option<Arc<dyn LlmClient>>,
}

impl Stage0 {
    pub fn new(config: Step0Config, llm_client: Option<Arc<dyn LlmClient>>) -> Self {
        Stage0 { config, llm_client }
    }
}

impl PipelineStage for Stage0 {
    type Input = Step0Input;
    type Output = SeedPackage;
    const NAME: &'static str = "s0-seed";

    async fn run(&self, input: Step0Input) -> Result<StageOutcome<SeedPackage>, StageError> {
        let client = self.llm_client.as_deref();
        let seed = run_seed(&input.repo_root, &self.config, client).await;
        Ok(StageOutcome::Ok(seed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_llm_client::{ChatRequest, ChatResponse, LlmError};
    use async_trait::async_trait;

    #[test]
    fn detection_mode_parses_both_config_spellings_case_insensitively() {
        assert_eq!(DetectionMode::parse("rules"), Some(DetectionMode::Rules));
        assert_eq!(DetectionMode::parse("llm"), Some(DetectionMode::Llm));
        assert_eq!(DetectionMode::parse("  LLM \n"), Some(DetectionMode::Llm));
    }

    #[test]
    fn detection_mode_refuses_an_unrecognized_value_rather_than_defaulting() {
        assert_eq!(DetectionMode::parse(""), None);
        assert_eq!(DetectionMode::parse("rule"), None);
        assert_eq!(DetectionMode::parse("LLMs"), None);
    }

    #[test]
    fn detection_mode_round_trips_through_as_str() {
        for mode in [DetectionMode::Rules, DetectionMode::Llm] {
            assert_eq!(DetectionMode::parse(mode.as_str()), Some(mode));
        }
    }

    #[test]
    fn step0_config_new_defaults_to_rules_mode_enabled() {
        let cfg = Step0Config::new();
        assert!(cfg.enabled);
        assert_eq!(cfg.detection_mode, DetectionMode::Rules);
        assert!(cfg.languages.is_empty());
        assert_eq!(
            cfg.call_graph_max_targets,
            appsec_callgraph::graph::DEFAULT_MAX_TARGETS_PER_CALL
        );
    }

    #[test]
    fn step0_config_default_matches_new() {
        let a = Step0Config::default();
        let b = Step0Config::new();
        assert_eq!(a.enabled, b.enabled);
        assert_eq!(a.detection_mode, b.detection_mode);
    }

    #[test]
    fn seed_package_default_is_engine_callgraph_with_no_content() {
        let seed = SeedPackage::default();
        assert_eq!(seed.engine, "callgraph");
        assert!(!seed.has_content());
    }

    #[test]
    fn has_content_true_when_entry_points_present() {
        let mut seed = SeedPackage::default();
        seed.entry_points.push(EntryPoint {
            file: "a.py".to_string(),
            function: "f".to_string(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        });
        assert!(seed.has_content());
    }

    #[test]
    fn has_content_true_when_unsafe_sinks_present() {
        let mut seed = SeedPackage::default();
        seed.unsafe_sinks.push(Sink {
            file: "a.py".to_string(),
            line: 1,
            function: "sink".to_string(),
            snippet: String::new(),
            cwe: Vec::new(),
        });
        assert!(seed.has_content());
    }

    #[test]
    fn has_content_true_when_taint_paths_present() {
        let mut seed = SeedPackage::default();
        seed.taint_paths.push(vec!["a.py:1".to_string()]);
        assert!(seed.has_content());
    }

    #[test]
    fn has_content_true_when_call_graph_present() {
        let mut seed = SeedPackage::default();
        seed.call_graph
            .insert("f".to_string(), vec!["g".to_string()]);
        assert!(seed.has_content());
    }

    #[test]
    fn has_content_true_when_call_graph_files_present() {
        let mut seed = SeedPackage::default();
        seed.call_graph_files
            .insert("f".to_string(), vec!["a.py".to_string()]);
        assert!(seed.has_content());
    }

    #[test]
    fn has_content_true_when_def_spans_present() {
        let mut seed = SeedPackage::default();
        seed.def_spans.insert("f".to_string(), (1, 2));
        assert!(seed.has_content());
    }

    #[test]
    fn has_content_true_when_framework_entry_points_present() {
        let mut seed = SeedPackage::default();
        seed.framework_entry_points.push(EntryPoint {
            file: "a.py".to_string(),
            function: "f".to_string(),
            kind: EntryPointKind::Other,
            reachable_from_unauth: false,
        });
        assert!(seed.has_content());
    }

    #[test]
    fn convert_entry_point_resolves_the_kinds_the_corpus_writes() {
        let kind_of = |kind: &str| {
            convert_entry_point(appsec_callgraph::EntryPoint {
                file: "a.py".to_string(),
                function: "f".to_string(),
                kind: kind.to_string(),
                reachable_from_unauth: false,
            })
            .kind
        };
        assert_eq!(kind_of("network"), EntryPointKind::Network);
        assert_eq!(kind_of("ipc"), EntryPointKind::Ipc);
        assert_eq!(kind_of("file"), EntryPointKind::File);
        assert_eq!(kind_of("cli"), EntryPointKind::Cli);
        assert_eq!(kind_of("deserialization"), EntryPointKind::Deserialization);
        assert_eq!(kind_of("framework"), EntryPointKind::Framework);
        assert_eq!(kind_of("http"), EntryPointKind::Network);
        assert_eq!(kind_of("stdin"), EntryPointKind::Cli);
        assert_eq!(kind_of("env"), EntryPointKind::File);
        assert_eq!(kind_of("other"), EntryPointKind::Other);
        assert_eq!(kind_of("bogus"), EntryPointKind::Other);
    }

    #[test]
    fn has_content_true_when_taint_evidence_present() {
        let mut seed = SeedPackage::default();
        seed.taint_evidence.push(TaintEvidencePath {
            source_ref: "a.py:1".to_string(),
            sink_ref: "a.py:2".to_string(),
            path_funcs: Vec::new(),
            edges: Vec::new(),
            sink_cwe: Vec::new(),
            sanitized: false,
        });
        assert!(seed.has_content());
    }

    #[test]
    fn convert_evidence_carries_every_edge_field_the_engine_can_set() {
        let path = appsec_callgraph::TaintEvidencePath {
            source_ref: "a.py:1".to_string(),
            sink_ref: "a.py:9".to_string(),
            path_funcs: vec!["a.py::f".to_string()],
            edges: vec![
                appsec_callgraph::TaintTransferEdge {
                    file: "a.py".to_string(),
                    line: 3,
                    function_qnode: "a.py::f".to_string(),
                    src: appsec_callgraph::TaintSymbolRef {
                        qnode: "a.py::f".to_string(),
                        symbol: "raw".to_string(),
                        kind: "local".to_string(),
                    },
                    dst: appsec_callgraph::TaintSymbolRef {
                        qnode: "a.py::f".to_string(),
                        symbol: "arg0".to_string(),
                        kind: "arg".to_string(),
                    },
                    transfer_kind: "local_to_sink".to_string(),
                    reflected_targets: Vec::new(),
                    confidence: None,
                    is_speculative: None,
                },
                appsec_callgraph::TaintTransferEdge {
                    file: "a.py".to_string(),
                    line: 4,
                    function_qnode: "a.py::f".to_string(),
                    src: appsec_callgraph::TaintSymbolRef::default(),
                    dst: appsec_callgraph::TaintSymbolRef::default(),
                    transfer_kind: "reflect".to_string(),
                    reflected_targets: vec!["a.py::g".to_string()],
                    confidence: Some("medium".to_string()),
                    is_speculative: Some(true),
                },
            ],
            sink_cwe: vec!["CWE-78".to_string()],
            sanitized: true,
        };
        let out = convert_evidence(path);
        assert_eq!(out.source_ref, "a.py:1");
        assert_eq!(out.path_funcs, vec!["a.py::f".to_string()]);
        assert!(out.sanitized);
        assert_eq!(out.edges[0].line, 3);
        assert_eq!(out.edges[0].src.symbol, "raw");
        assert_eq!(out.edges[0].transfer_kind, "local_to_sink");
        assert_eq!(out.edges[0].reflected_targets, None);
        assert_eq!(out.edges[0].confidence, None);
        assert_eq!(out.edges[0].condition_text, None);
        assert_eq!(out.edges[0].is_tainted_condition, None);
        assert_eq!(out.edges[0].call_type, None);
        assert_eq!(out.edges[0].framework, None);
        assert_eq!(out.edges[0].marker_type, None);
        assert_eq!(
            out.edges[1].reflected_targets,
            Some(vec!["a.py::g".to_string()])
        );
        assert_eq!(out.edges[1].confidence, Some("medium".to_string()));
        assert_eq!(out.edges[1].is_speculative, Some(true));
    }

    #[test]
    fn convert_taint_seed_carries_the_framework_entry_points_and_evidence() {
        let seed = appsec_callgraph::TaintSeed {
            framework_entry_points: vec![appsec_callgraph::EntryPoint {
                file: "a.py".to_string(),
                function: "show".to_string(),
                kind: "framework".to_string(),
                reachable_from_unauth: true,
            }],
            taint_evidence: vec![appsec_callgraph::TaintEvidencePath {
                source_ref: "a.py:1".to_string(),
                sink_ref: "a.py:9".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let pkg = convert_taint_seed(seed, "callgraph", vec!["python".to_string()]);
        assert_eq!(pkg.framework_entry_points.len(), 1);
        assert_eq!(
            pkg.framework_entry_points[0].kind,
            EntryPointKind::Framework
        );
        assert_eq!(pkg.taint_evidence.len(), 1);
        assert_eq!(pkg.taint_evidence[0].sink_ref, "a.py:9");
    }

    #[test]
    fn convert_entry_point_carries_reachable_from_unauth_through() {
        let ep = appsec_callgraph::EntryPoint {
            file: "a.py".to_string(),
            function: "handler".to_string(),
            kind: "network".to_string(),
            reachable_from_unauth: false,
        };
        let out = convert_entry_point(ep);
        assert_eq!(out.file, "a.py");
        assert_eq!(out.function, "handler");
        assert_eq!(out.kind, EntryPointKind::Network);
        assert!(!out.reachable_from_unauth);

        let framework = appsec_callgraph::EntryPoint {
            file: "a.py".to_string(),
            function: "handler".to_string(),
            kind: "framework".to_string(),
            reachable_from_unauth: true,
        };
        assert!(convert_entry_point(framework).reachable_from_unauth);
    }

    #[test]
    fn convert_sink_carries_cwe_through() {
        let s = appsec_callgraph::Sink {
            file: "a.py".to_string(),
            line: 5,
            function: "system".to_string(),
            snippet: "os.system(cmd)".to_string(),
            cwe: vec!["CWE-78".to_string()],
        };
        let out = convert_sink(s);
        assert_eq!(out.line, 5);
        assert_eq!(out.cwe, vec!["CWE-78".to_string()]);
    }

    #[tokio::test]
    async fn run_seed_returns_default_when_disabled() {
        let mut cfg = Step0Config::new();
        cfg.enabled = false;
        let dir = tempfile::tempdir().unwrap();
        let seed = run_seed(dir.path(), &cfg, None).await;
        assert!(!seed.has_content());
        assert!(seed.all_files.is_empty());
    }

    #[tokio::test]
    async fn run_seed_attaches_walk_results_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.py"), "import os\nos.system('x')\n").unwrap();
        let cfg = Step0Config::new();
        let seed = run_seed(dir.path(), &cfg, None).await;
        assert_eq!(seed.all_files, vec!["main.py".to_string()]);
    }

    #[tokio::test]
    async fn stage0_run_wraps_run_seed_as_ok() {
        let dir = tempfile::tempdir().unwrap();
        let stage = Stage0::new(Step0Config::new(), None);
        let outcome = stage
            .run(Step0Input {
                repo_root: dir.path().to_path_buf(),
            })
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
    }

    struct ScriptedClient {
        reply: String,
    }

    #[async_trait]
    impl LlmClient for ScriptedClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Ok(ChatResponse {
                content: vec![appsec_llm_client::ContentBlock::Text(self.reply.clone())],
                stop_reason: appsec_llm_client::StopReason::EndTurn,
                usage: appsec_llm_client::Usage::default(),
            })
        }
    }

    #[tokio::test]
    async fn run_seed_forwards_the_llm_config_through_to_the_engine() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.py"),
            "def handler():\n    cmd = request.args.get('cmd')\n    os.system(cmd)\n",
        )
        .unwrap();
        let mut cfg = Step0Config::new();
        cfg.detection_mode = DetectionMode::Llm;
        cfg.llm = Some(Step0LlmConfig::new("test-model"));
        let client = ScriptedClient {
            reply: "[]".to_string(),
        };
        let seed = run_seed(dir.path(), &cfg, Some(&client as &dyn LlmClient)).await;
        assert!(seed.has_content());
    }
}
