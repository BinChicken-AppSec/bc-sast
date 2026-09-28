//! Tree-sitter-native call-graph seed engine wrapper. Ported from
//! `vvaharness/pipeline/stages/callgraph_engine/__init__.py`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use bc_callgraph::families::{canonical_lang, VVAH_LANGUAGES};
use bc_callgraph::rules::{load_rulepacks, parse_rulepacks_text};
use bc_callgraph::scan::{build_spec_index, scan_file, supported_languages};
use bc_callgraph::{build_taint_paths, FileIndex, MatchSpec};
use bc_llm_client::LlmClient;

use crate::llm_detect::{detect_specs, Specs, Step0LlmConfig};
use crate::{convert_taint_seed, DetectionMode, SeedPackage};

/// S0's bundled default rule corpus — see `crates/bc-stage-s0/corpus/`
/// for the full scope/rigor notes. Used by [`load_rules_mode_specs`]
/// only when the operator hasn't configured their own
/// `sources_yaml`/`sinks_yaml`, so `step0.enabled: true` produces real
/// rule content out of the box rather than an empty seed.
const EMBEDDED_SOURCES_YAML: &str = include_str!("../corpus/sources.yaml");
const EMBEDDED_SINKS_YAML: &str = include_str!("../corpus/sinks.yaml");

pub struct EngineConfig {
    pub detection_mode: DetectionMode,
    pub sources_yaml: Option<PathBuf>,
    pub sinks_yaml: Option<PathBuf>,
    pub call_graph_max_targets: usize,
    /// `step0.callgraph.llm.*` — required for `detection_mode: Llm` to
    /// actually attempt an LLM call; `None` behaves as Python's own "no
    /// model configured" branch (falls back to `rules` immediately).
    pub llm: Option<Step0LlmConfig>,
}

/// Port of `_filter_step0_languages`: an empty/absent allowlist is a
/// no-op; otherwise every entry is resolved through the shared
/// language-alias table and unrecognized entries are reported (not
/// silently dropped) rather than just producing no matches.
pub fn filter_step0_languages(langs: &[&'static str], allow_raw: &[String]) -> Vec<&'static str> {
    if allow_raw.is_empty() {
        return langs.to_vec();
    }
    let mut allow: BTreeSet<String> = BTreeSet::new();
    for x in allow_raw {
        if x.trim().is_empty() {
            continue;
        }
        let canon = canonical_lang(x);
        if !VVAH_LANGUAGES.contains(&canon.as_str()) {
            tracing::warn!(
                "[s0] step0.languages entry {x:?} is not a recognized \
                 language or alias; it will not match any file"
            );
        }
        allow.insert(canon);
    }
    langs
        .iter()
        .copied()
        .filter(|l| allow.contains(*l))
        .collect()
}

/// Port of `_scan_repo`: scan every in-scope file whose extension maps
/// to a language `bc_callgraph::scan` actually has a plugin for, keeping
/// only indices `keep` selects. Per-file scan failures are already
/// folded into `scan_file`'s `None` return (see its own doc comment) —
/// there is nothing further to catch here, matching how the Python
/// original's `try/except` around `scan_file` only ever logs and moves
/// on, never aborting the whole scan.
pub fn scan_repo(
    repo_root: &Path,
    in_scope: &BTreeSet<String>,
    source_specs: &[MatchSpec],
    sink_specs: &[MatchSpec],
    collect_observed: bool,
    keep: &dyn Fn(&FileIndex) -> bool,
) -> Vec<FileIndex> {
    let source_index = build_spec_index(source_specs);
    let sink_index = build_spec_index(sink_specs);
    let supported = supported_languages();

    let mut out = Vec::new();
    for rel in in_scope {
        let abs = repo_root.join(rel);
        if !abs.is_file() {
            continue;
        }
        let ext = bc_repo_analysis::suffix_lower(rel);
        let Some(lang) = bc_repo_analysis::ext_to_lang(&ext) else {
            continue;
        };
        if !supported.contains(&lang) {
            continue;
        }
        let scanned = scan_file(
            &abs,
            rel,
            lang,
            source_specs,
            sink_specs,
            collect_observed,
            Some(&source_index),
            Some(&sink_index),
        )
        .filter(|idx| keep(idx));
        if let Some(idx) = scanned {
            out.push(idx);
        }
    }
    out
}

/// Loads and returns `(source_specs, sink_specs, rule_cwe)` from
/// configured YAML, or from the bundled starter corpus
/// (`crates/bc-stage-s0/corpus/*.yaml`) when neither `sources_yaml` nor
/// `sinks_yaml` is configured — an explicit config path always wins over
/// the embedded default. Returns `None` only on an actual load failure,
/// in which case the caller returns an empty seed; a load failure logs
/// its own message first.
fn load_rules_mode_specs(config: &EngineConfig, active_langs: &[String]) -> Option<Specs> {
    let have_sources = config.sources_yaml.as_deref().is_some_and(Path::is_file);
    let have_sinks = config.sinks_yaml.as_deref().is_some_and(Path::is_file);
    if !have_sources && !have_sinks {
        tracing::info!(
            "[s0/callgraph] no source/sink rule YAML configured — falling back to the \
             bundled starter corpus"
        );
        return match parse_rulepacks_text(
            Some(EMBEDDED_SOURCES_YAML),
            Some(EMBEDDED_SINKS_YAML),
            active_langs,
        ) {
            Ok(loaded) => Some(loaded),
            Err(e) => {
                tracing::warn!(
                    "[s0/callgraph] bundled starter corpus load failed: {e} — returning \
                     empty seed"
                );
                None
            }
        };
    }
    match load_rulepacks(
        config.sources_yaml.as_deref().filter(|_| have_sources),
        config.sinks_yaml.as_deref().filter(|_| have_sinks),
        active_langs,
    ) {
        Ok(loaded) => Some(loaded),
        Err(e) => {
            tracing::warn!("[s0/callgraph] rule load failed: {e} — returning empty seed");
            None
        }
    }
}

/// Public entry point invoked by `run_seed` — port of
/// `callgraph_engine.run`. Never fails — degrades to an empty
/// [`SeedPackage`] on any condition that would otherwise abort.
pub async fn run_callgraph_engine(
    repo_root: &Path,
    in_scope: &BTreeSet<String>,
    langs: &[&'static str],
    config: &EngineConfig,
    client: Option<&dyn LlmClient>,
) -> SeedPackage {
    let supported = supported_languages();
    let active_langs: Vec<String> = langs
        .iter()
        .filter(|l| supported.contains(l))
        .map(|l| l.to_string())
        .collect();

    if active_langs.is_empty() {
        tracing::warn!(
            "[s0/callgraph] no language plugins for {langs:?} (supported: \
             {supported:?}) — returning empty seed"
        );
        return SeedPackage::empty("callgraph", langs.iter().map(|s| s.to_string()).collect());
    }

    let mut detection_mode = config.detection_mode;
    let mut used_llm_specs = false;
    let mut source_specs = Vec::new();
    let mut sink_specs = Vec::new();
    let mut rule_cwe = std::collections::BTreeMap::new();

    if detection_mode == DetectionMode::Llm {
        match (client, &config.llm) {
            (Some(client), Some(llm_config)) => {
                let observed = scan_repo(repo_root, in_scope, &[], &[], true, &|idx| {
                    !idx.functions.is_empty() || !idx.observed_calls.is_empty()
                });
                if observed.is_empty() {
                    tracing::warn!(
                        "[s0/callgraph] llm detection found no parseable files; \
                         falling back to configured rules YAML."
                    );
                    detection_mode = DetectionMode::Rules;
                } else {
                    let (s, k, c) =
                        detect_specs(client, &observed, &active_langs, llm_config).await;
                    used_llm_specs = !s.is_empty() || !k.is_empty();
                    if used_llm_specs {
                        source_specs = s;
                        sink_specs = k;
                        rule_cwe = c;
                    } else {
                        tracing::warn!(
                            "[s0/callgraph] llm detection produced 0 specs; \
                             falling back to configured rules YAML."
                        );
                        detection_mode = DetectionMode::Rules;
                    }
                }
            }
            _ => {
                // No client/`step0.callgraph.llm` config supplied — the
                // same outcome Python reaches when `cfg.models.*` has no
                // usable model role resolved for this stage.
                tracing::warn!(
                    "[s0/callgraph] step0.callgraph_detection=llm requested but no \
                     model is configured; falling back to configured rules YAML."
                );
                detection_mode = DetectionMode::Rules;
            }
        }
    }

    if detection_mode == DetectionMode::Rules {
        match load_rules_mode_specs(config, &active_langs) {
            Some((s, k, c)) => {
                source_specs = s;
                sink_specs = k;
                rule_cwe = c;
            }
            None => return SeedPackage::empty("callgraph", active_langs),
        }
    }

    if source_specs.is_empty() && sink_specs.is_empty() {
        // No corpus for these languages — a route-only language such as
        // PHP, Ruby, Kotlin or Rust today. The framework entry-point
        // plane does not need rules, so keep going: the scan below still
        // records functions, calls and routes; only taint seeding is
        // empty. Returning early here silently zeroed every entry point
        // on a single-language repo of those languages (2026-09-07).
        tracing::info!(
            "[s0/callgraph] 0 taint rules applicable to {active_langs:?} — \
             entry points only"
        );
    }

    // Formatted eagerly rather than through `info!`'s own arguments:
    // `tracing`'s macros only evaluate their args when a subscriber has
    // the callsite enabled, so inlining them would make these four
    // expressions invisible to both the test suite and to coverage —
    // the same reason `bc_orchestrator::inject` formats its own summary
    // line up front.
    let spec_summary = format!(
        "[s0/callgraph] {} source specs, {} sink specs, {} langs ({})",
        source_specs.len(),
        sink_specs.len(),
        active_langs.len(),
        active_langs.join(", ")
    );
    tracing::info!("{spec_summary}");

    let file_indices = scan_repo(
        repo_root,
        in_scope,
        &source_specs,
        &sink_specs,
        false,
        &|idx| {
            !idx.source_hits.is_empty()
                || !idx.sink_hits.is_empty()
                || !idx.functions.is_empty()
                // A route table (`config/routes.rb`, `routes/web.php`)
                // declares handlers without defining a function of its
                // own, so it would otherwise be dropped along with
                // every framework entry point in it.
                || !idx.framework_markers.is_empty()
        },
    );

    if file_indices.is_empty() {
        // `used_llm_specs=true` reaching this branch is believed
        // unreachable in practice (empirically probed, not proven):
        // every spec `append_spec` builds is derived directly from an
        // observed call site in one of these same in-scope files, and
        // this second `scan_repo` pass re-parses that exact file with
        // that exact spec — so the spec always matches at least the one
        // site it came from, keeping `file_indices` non-empty. Kept as
        // real, reachable-by-construction code (not deleted) since a
        // future match-logic change could break that guarantee.
        if used_llm_specs {
            tracing::warn!(
                "[s0/callgraph] llm specs produced 0 matched files — returning empty seed"
            );
        } else {
            tracing::warn!(
                "[s0/callgraph] 0 files with source/sink matches — returning empty seed"
            );
        }
        let mut seed = SeedPackage::empty("callgraph", active_langs);
        seed.rule_cwe = rule_cwe;
        return seed;
    }

    let taint_seed = build_taint_paths(&file_indices, &rule_cwe, config.call_graph_max_targets);
    let seed = convert_taint_seed(taint_seed, "callgraph", active_langs);
    // Eagerly formatted for the same reason as `spec_summary` above.
    let seed_summary = format!(
        "[s0/callgraph] seed: {} entry-points, {} sinks, {} taint paths ({} rules CWE-tagged)",
        seed.entry_points.len(),
        seed.unsafe_sinks.len(),
        seed.taint_paths.len(),
        rule_cwe.len()
    );
    tracing::info!("{seed_summary}");
    seed
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bc_llm_client::{ChatRequest, ChatResponse, LlmError};

    #[test]
    fn filter_step0_languages_no_filter_when_allowlist_empty() {
        let langs = &["python", "java"];
        assert_eq!(filter_step0_languages(langs, &[]), vec!["python", "java"]);
    }

    #[test]
    fn filter_step0_languages_narrows_to_allowlist_via_alias() {
        let langs = &["python", "java", "csharp"];
        let allow = vec!["dotnet".to_string()];
        assert_eq!(filter_step0_languages(langs, &allow), vec!["csharp"]);
    }

    #[test]
    fn filter_step0_languages_skips_blank_entries() {
        let langs = &["python"];
        let allow = vec!["  ".to_string(), "python".to_string()];
        assert_eq!(filter_step0_languages(langs, &allow), vec!["python"]);
    }

    #[test]
    fn filter_step0_languages_unrecognized_entry_matches_nothing() {
        let langs = &["python"];
        let allow = vec!["not-a-real-language".to_string()];
        assert!(filter_step0_languages(langs, &allow).is_empty());
    }

    #[test]
    fn scan_repo_skips_a_file_missing_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "import os\nos.system('x')\n").unwrap();
        let mut in_scope = BTreeSet::new();
        in_scope.insert("a.py".to_string());
        in_scope.insert("missing.py".to_string());
        let out = scan_repo(dir.path(), &in_scope, &[], &[], false, &|_| true);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].file, "a.py");
    }

    #[test]
    fn scan_repo_skips_a_file_with_no_recognized_extension() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("c.zzqx"), "whatever").unwrap();
        let mut in_scope = BTreeSet::new();
        in_scope.insert("c.zzqx".to_string());
        let out = scan_repo(dir.path(), &in_scope, &[], &[], false, &|_| true);
        assert!(out.is_empty());
    }

    #[test]
    fn scan_repo_skips_a_recognized_but_unsupported_language() {
        // `.swift` maps to a real language via `ext_to_lang`, but
        // `bc_callgraph::scan` has no plugin for it — this must be
        // dropped at the plugin-support check, not the extension check.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.swift"), "print(\"hi\")").unwrap();
        let mut in_scope = BTreeSet::new();
        in_scope.insert("b.swift".to_string());
        let out = scan_repo(dir.path(), &in_scope, &[], &[], false, &|_| true);
        assert!(out.is_empty());
    }

    #[test]
    fn scan_repo_keep_predicate_filters_results() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "import os\nos.system('x')\n").unwrap();
        let mut in_scope = BTreeSet::new();
        in_scope.insert("a.py".to_string());
        let out = scan_repo(dir.path(), &in_scope, &[], &[], false, &|_| false);
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn run_callgraph_engine_empty_when_no_supported_language() {
        // "swift" — not one of `bc_callgraph::scan::supported_languages()`'s
        // ten wired languages.
        let dir = tempfile::tempdir().unwrap();
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: None,
            sinks_yaml: None,
            call_graph_max_targets: 3,
            llm: None,
        };
        let seed =
            run_callgraph_engine(dir.path(), &BTreeSet::new(), &["swift"], &config, None).await;
        assert!(!seed.has_content());
        assert_eq!(seed.languages, vec!["swift".to_string()]);
    }

    #[tokio::test]
    async fn run_callgraph_engine_llm_mode_falls_back_to_rules_and_returns_empty_without_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let config = EngineConfig {
            detection_mode: DetectionMode::Llm,
            sources_yaml: None,
            sinks_yaml: None,
            call_graph_max_targets: 3,
            llm: None,
        };
        let seed =
            run_callgraph_engine(dir.path(), &BTreeSet::new(), &["python"], &config, None).await;
        assert!(!seed.has_content());
        assert_eq!(seed.engine, "callgraph");
    }

    struct ScriptedClient {
        reply: String,
    }

    #[async_trait]
    impl LlmClient for ScriptedClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Ok(ChatResponse {
                content: vec![bc_llm_client::ContentBlock::Text(self.reply.clone())],
                stop_reason: bc_llm_client::StopReason::EndTurn,
                usage: bc_llm_client::Usage::default(),
            })
        }
    }

    fn llm_only_config(model: &str) -> EngineConfig {
        EngineConfig {
            detection_mode: DetectionMode::Llm,
            sources_yaml: None,
            sinks_yaml: None,
            call_graph_max_targets: 3,
            llm: Some(Step0LlmConfig::new(model)),
        }
    }

    #[tokio::test]
    async fn run_callgraph_engine_llm_mode_builds_a_real_seed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.py"),
            "def handler():\n    cmd = request.args.get('cmd')\n    os.system(cmd)\n",
        )
        .unwrap();
        let mut in_scope = BTreeSet::new();
        in_scope.insert("app.py".to_string());
        // `os.system` is heuristically classified as a sink even with no
        // real LLM reply matching any candidate id — proves the LLM
        // pass ran (an empty response never reaches `by_id`) and its
        // `heuristic_supplement` fallback topped up the sink side.
        let client = ScriptedClient {
            reply: "[]".to_string(),
        };
        let config = llm_only_config("test-model");
        let seed = run_callgraph_engine(
            dir.path(),
            &in_scope,
            &["python"],
            &config,
            Some(&client as &dyn LlmClient),
        )
        .await;
        assert!(seed.has_content());
        assert_eq!(seed.engine, "callgraph");
    }

    #[tokio::test]
    async fn run_callgraph_engine_llm_mode_falls_back_when_no_parseable_files() {
        let dir = tempfile::tempdir().unwrap();
        let client = ScriptedClient {
            reply: "[]".to_string(),
        };
        let config = llm_only_config("test-model");
        let seed = run_callgraph_engine(
            dir.path(),
            &BTreeSet::new(),
            &["python"],
            &config,
            Some(&client as &dyn LlmClient),
        )
        .await;
        assert!(!seed.has_content());
    }

    #[tokio::test]
    async fn run_callgraph_engine_llm_mode_falls_back_when_the_call_fails() {
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
        // A DOTTED call, so `collect_candidates` actually produces a
        // candidate and `detect_specs` actually reaches the client. With
        // a bare `g()` there are no candidates, `detect_specs` returns
        // early, and this test passed without the failing call ever
        // happening — it proved nothing about a failed call.
        std::fs::write(
            dir.path().join("app.py"),
            "def handler():\n    cmd = request.args.get('cmd')\n    os.system(cmd)\n",
        )
        .unwrap();
        let mut in_scope = BTreeSet::new();
        in_scope.insert("app.py".to_string());
        let client = FailingClient;
        let mut config = llm_only_config("test-model");
        // `os.system` is heuristically classified as a sink, which would
        // rescue the run from the failed call and hide the fallback.
        config
            .llm
            .as_mut()
            .expect("llm_only_config sets it")
            .heuristic_supplement = false;
        let seed = run_callgraph_engine(
            dir.path(),
            &in_scope,
            &["python"],
            &config,
            Some(&client as &dyn LlmClient),
        )
        .await;
        // The failed call degrades to `rules`, which — with no rules YAML
        // configured — falls back to the bundled starter corpus, and that
        // corpus knows `request.args.get`/`os.system`. A populated seed is
        // therefore the proof that the failure was absorbed rather than
        // aborting the run or hanging.
        assert!(seed.has_content());
        assert!(!seed.unsafe_sinks.is_empty());
    }

    #[tokio::test]
    async fn run_callgraph_engine_llm_mode_falls_back_to_rules_yaml_on_zero_specs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), "def f():\n    g()\n").unwrap();
        let mut in_scope = BTreeSet::new();
        in_scope.insert("app.py".to_string());
        // Well-formed JSON but every row's role is neither source nor
        // sink, and heuristic_supplement is off — genuinely 0 specs.
        let client = ScriptedClient {
            reply: r#"[{"id":"c1","role":"none","confidence":0.9}]"#.to_string(),
        };
        let mut llm = Step0LlmConfig::new("test-model");
        llm.heuristic_supplement = false;
        let sources = write_source_yaml(dir.path());
        let sinks = write_sink_yaml(dir.path());
        let config = EngineConfig {
            detection_mode: DetectionMode::Llm,
            sources_yaml: Some(sources),
            sinks_yaml: Some(sinks),
            call_graph_max_targets: 3,
            llm: Some(llm),
        };
        let seed = run_callgraph_engine(
            dir.path(),
            &in_scope,
            &["python"],
            &config,
            Some(&client as &dyn LlmClient),
        )
        .await;
        // Rules YAML targets a different call shape (request.args.get /
        // os.system) than this fixture (`f()`/`g()`), so the fallback
        // itself lands on "0 files with source/sink matches" — still
        // proof the llm->rules fallback path executed rather than
        // erroring.
        assert!(!seed.has_content());
    }

    #[tokio::test]
    async fn run_callgraph_engine_emits_structured_evidence_and_framework_entry_points() {
        // End-to-end proof that the whole S0 seed plane now produces what
        // S1/S3/S4/S5 have been waiting on: a real Flask handler whose
        // request parameter reaches `os.system` through a local alias.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.py"),
            "from flask import request\n\
             import os\n\
             \n\
             @app.route(\"/run/<int:job_id>\")\n\
             def run(job_id):\n\
             \x20   raw = request.args.get(\"cmd\")\n\
             \x20   cmd = raw\n\
             \x20   os.system(cmd)\n",
        )
        .unwrap();
        let mut in_scope = BTreeSet::new();
        in_scope.insert("app.py".to_string());
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: Some(write_source_yaml(dir.path())),
            sinks_yaml: Some(write_sink_yaml(dir.path())),
            call_graph_max_targets: 3,
            llm: None,
        };
        let seed = run_callgraph_engine(dir.path(), &in_scope, &["python"], &config, None).await;

        assert_eq!(seed.taint_paths, vec![vec!["app.py:6", "app.py:8"]]);
        assert_eq!(seed.taint_evidence.len(), 1);
        let ev = &seed.taint_evidence[0];
        assert_eq!(ev.source_ref, "app.py:6");
        assert_eq!(ev.sink_ref, "app.py:8");
        assert_eq!(ev.path_funcs, vec!["app.py::run".to_string()]);
        let kinds: Vec<&str> = ev.edges.iter().map(|e| e.transfer_kind.as_str()).collect();
        assert_eq!(kinds, vec!["source", "assign", "local_to_sink"]);
        assert_eq!(ev.edges[1].src.symbol, "raw");
        assert_eq!(ev.edges[1].dst.symbol, "cmd");
        assert!(!ev.sanitized);

        assert_eq!(seed.framework_entry_points.len(), 1);
        let fep = &seed.framework_entry_points[0];
        assert_eq!(fep.file, "app.py");
        assert_eq!(fep.function, "run");
        assert_eq!(fep.kind, bc_model::EntryPointKind::Framework);
    }

    #[tokio::test]
    async fn run_callgraph_engine_empty_when_no_rule_yaml_configured() {
        let dir = tempfile::tempdir().unwrap();
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: None,
            sinks_yaml: None,
            call_graph_max_targets: 3,
            llm: None,
        };
        // No files in scope, so even though this now falls back to the
        // bundled starter corpus (which has real python specs), there's
        // nothing for `scan_repo` to match against — still empty.
        let seed =
            run_callgraph_engine(dir.path(), &BTreeSet::new(), &["python"], &config, None).await;
        assert!(!seed.has_content());
        assert_eq!(seed.languages, vec!["python".to_string()]);
    }

    #[test]
    fn load_rules_mode_specs_falls_back_to_the_bundled_corpus_when_unconfigured() {
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: None,
            sinks_yaml: None,
            call_graph_max_targets: 3,
            llm: None,
        };
        let langs = vec!["python".to_string()];
        let (sources, sinks, _cwe) =
            load_rules_mode_specs(&config, &langs).expect("bundled corpus should parse");
        assert!(!sources.is_empty());
        assert!(!sinks.is_empty());
    }

    #[test]
    fn the_java_corpus_also_answers_for_kotlin() {
        // Kotlin calls the same JVM APIs by the same names, and
        // `MatchSpec.languages` is a set the matcher tests with
        // `contains(language)` — so the Java rules cover Kotlin the
        // moment an extractor for it is wired, with no second corpus to
        // keep in step. Nothing here depends on Kotlin being
        // *extractable* yet; rules are filtered against the operator's
        // active languages long before any file is parsed.
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: None,
            sinks_yaml: None,
            call_graph_max_targets: 3,
            llm: None,
        };
        let langs = vec!["kotlin".to_string()];
        let (sources, sinks, _cwe) =
            load_rules_mode_specs(&config, &langs).expect("bundled corpus should parse");
        assert!(sources.iter().any(|s| s.languages.contains("kotlin")));
        assert!(sinks.iter().any(|s| s.languages.contains("kotlin")));
        // And every Kotlin rule is a Java rule — the point is that they
        // are the same rules, not a parallel set.
        assert!(sinks
            .iter()
            .filter(|s| s.languages.contains("kotlin"))
            .all(|s| s.languages.contains("java")));
    }

    #[test]
    fn the_bundled_corpus_carries_both_roles_for_every_supported_language() {
        // C# shipped with one sink rule and NO source rule at all, and
        // Go/JavaScript with a handful of each, so three of the six
        // languages had extractors that nothing could ever match. This
        // is the guard against that regressing.
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: None,
            sinks_yaml: None,
            call_graph_max_targets: 3,
            llm: None,
        };
        // All ten languages, with no exemption: PHP, Ruby and Rust
        // gained their own rules on 2026-09-07 and Kotlin rides the
        // Java block, so "wired for routes but with nothing to match"
        // is no longer a state any language is in.
        for lang in bc_callgraph::families::VVAH_LANGUAGES.iter() {
            let langs = vec![(*lang).to_string()];
            let (sources, sinks, _cwe) =
                load_rules_mode_specs(&config, &langs).expect("bundled corpus should parse");
            assert!(
                sources.iter().any(|s| s.languages.contains(*lang)),
                "no source rule for {lang}"
            );
            assert!(
                sinks.iter().any(|s| s.languages.contains(*lang)),
                "no sink rule for {lang}"
            );
        }
    }

    #[test]
    fn every_ep_kind_in_the_bundled_source_corpus_resolves_to_a_known_kind() {
        // 20 of the 21 shipped source rules said `http`, `stdin` or
        // `env`, none of which the seed's kind conversion recognized, so
        // the corpus quietly produced `Other` for everything but one C
        // rule. Every kind the corpus writes has to resolve, and every
        // rule has to survive the language filter to be checked at all.
        let langs: Vec<String> = bc_callgraph::families::VVAH_LANGUAGES
            .iter()
            .map(|l| (*l).to_string())
            .collect();
        let (sources, _sinks, _cwe) =
            parse_rulepacks_text(Some(EMBEDDED_SOURCES_YAML), None, &langs)
                .expect("bundled corpus should parse");
        let rule_ids: BTreeSet<&str> = sources.iter().map(|s| s.rule_id.as_str()).collect();
        assert_eq!(
            rule_ids.len(),
            EMBEDDED_SOURCES_YAML.matches("\n  - id: ").count(),
            "a source rule was dropped by the language filter"
        );
        for spec in &sources {
            assert_ne!(
                bc_model::EntryPointKind::parse(&spec.kind),
                bc_model::EntryPointKind::Other,
                "{}: ep_kind {:?} is not a kind the seed recognizes",
                spec.rule_id,
                spec.kind
            );
        }
    }

    #[tokio::test]
    async fn e2e_a_request_source_reaching_a_weak_hash_sink_is_still_paired() {
        // The trap in switching the taint compatibility filter on:
        // `crypto` sinks are `semantic_family: other`, so no protected
        // family keeps them, and they appeared in no allowed-sink row.
        // This pair was reported before only because `http` had no row
        // of its own and admitted everything.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("main.go"),
            "package main\n\nfunc handler(w http.ResponseWriter, r *http.Request) {\n\
             \tq := r.FormValue(\"q\")\n\tsum := md5.Sum([]byte(q))\n\t_ = sum\n}\n",
        )
        .unwrap();
        let mut in_scope = BTreeSet::new();
        in_scope.insert("main.go".to_string());
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: None,
            sinks_yaml: None,
            call_graph_max_targets: 3,
            llm: None,
        };
        let seed = run_callgraph_engine(dir.path(), &in_scope, &["go"], &config, None).await;
        assert!(
            seed.entry_points
                .iter()
                .any(|e| e.function == "handler" && e.kind == bc_model::EntryPointKind::Network),
            "{:?}",
            seed.entry_points
        );
        assert!(
            seed.unsafe_sinks
                .iter()
                .any(|s| s.cwe.iter().any(|c| c == "CWE-327")),
            "{:?}",
            seed.unsafe_sinks
        );
        assert!(
            seed.taint_evidence
                .iter()
                .any(|p| p.sink_cwe.iter().any(|c| c == "CWE-327")),
            "{:?}",
            seed.taint_evidence
        );
        assert_eq!(seed.taint_paths.len(), 1, "{:?}", seed.taint_paths);
    }

    #[tokio::test]
    async fn run_callgraph_engine_rules_mode_falls_back_to_bundled_corpus_and_builds_a_real_seed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.py"),
            "def handler():\n    cmd = request.args.get('cmd')\n    os.system(cmd)\n",
        )
        .unwrap();
        let mut in_scope = BTreeSet::new();
        in_scope.insert("app.py".to_string());
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: None,
            sinks_yaml: None,
            call_graph_max_targets: 3,
            llm: None,
        };
        let seed = run_callgraph_engine(dir.path(), &in_scope, &["python"], &config, None).await;
        assert!(seed.has_content());
        assert_eq!(seed.engine, "callgraph");
        assert!(!seed.unsafe_sinks.is_empty());
    }

    #[tokio::test]
    async fn run_callgraph_engine_explicit_config_wins_over_the_bundled_corpus() {
        let dir = tempfile::tempdir().unwrap();
        // Both sides explicitly configured, but scoped to java only — 0
        // rules applicable to the active python language. The bundled
        // corpus's own `os.system` sink rule *would* match this file, so
        // a non-empty seed here would prove the embedded fallback ran
        // despite explicit config being present.
        let java_only = r#"
rules:
  - id: java-only-source
    languages: [java]
    metadata:
      vvah-role: source
      vvah-ep-kind: network
      cwe: "CWE-20"
    patterns:
      - pattern: request.getParameter(...)
"#;
        let sources = dir.path().join("sources.yaml");
        let sinks = dir.path().join("sinks.yaml");
        std::fs::write(&sources, java_only).unwrap();
        std::fs::write(&sinks, java_only).unwrap();
        std::fs::write(dir.path().join("app.py"), "os.system(cmd)\n").unwrap();
        let mut in_scope = BTreeSet::new();
        in_scope.insert("app.py".to_string());
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: Some(sources),
            sinks_yaml: Some(sinks),
            call_graph_max_targets: 3,
            llm: None,
        };
        let seed = run_callgraph_engine(dir.path(), &in_scope, &["python"], &config, None).await;
        assert!(!seed.has_content());
    }

    // ── end-to-end, through the real tree-sitter extractor ───────────
    //
    // Every `arg_to_param` test that existed before this block built its
    // `FileIndex` by hand, and the only test on real source was one
    // function doing `raw = request.args.get(..); cmd = raw;
    // os.system(cmd)` — a bare local handed straight to a sink. That is
    // why the seed plane shipped with ~140 green tests and still
    // produced `taint_paths = 0` on a real five-file Flask app
    // (2026-09-06): nothing exercised composed sink arguments, a
    // cross-file `arg_to_param`, or an instance-method sink. These
    // write real files and run the whole engine over them.

    /// Run S0 over `files` in a fresh tempdir, against the BUNDLED
    /// corpus unless `rules` overrides it. Returns the `SeedPackage`.
    async fn e2e(
        files: &[(&str, &str)],
        languages: &'static [&'static str],
        rules: Option<(&str, &str)>,
    ) -> (tempfile::TempDir, crate::SeedPackage) {
        let dir = tempfile::tempdir().unwrap();
        let mut in_scope = BTreeSet::new();
        for (name, body) in files {
            let path = dir.path().join(name);
            // Next.js routes ARE their paths, so those fixtures are
            // nested (`pages/api/…`) rather than flat.
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
            in_scope.insert((*name).to_string());
        }
        let (sources_yaml, sinks_yaml) = match rules {
            Some((src, snk)) => {
                let sp = dir.path().join("_sources.yaml");
                let kp = dir.path().join("_sinks.yaml");
                std::fs::write(&sp, src).unwrap();
                std::fs::write(&kp, snk).unwrap();
                (Some(sp), Some(kp))
            }
            None => (None, None),
        };
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml,
            sinks_yaml,
            call_graph_max_targets: 3,
            llm: None,
        };
        let seed = run_callgraph_engine(dir.path(), &in_scope, languages, &config, None).await;
        (dir, seed)
    }

    fn transfer_kinds(seed: &crate::SeedPackage, idx: usize) -> Vec<&str> {
        seed.taint_evidence[idx]
            .edges
            .iter()
            .map(|e| e.transfer_kind.as_str())
            .collect()
    }

    const PY_HANDLER_PRELUDE: &str = "from flask import request\nimport os\n\n";

    #[tokio::test]
    async fn e2e_python_an_f_string_sink_argument_grounds_a_path() {
        let (_d, seed) = e2e(
            &[(
                "app.py",
                "from flask import request\n\
                 import subprocess\n\
                 \n\
                 def ping():\n\
                 \x20   host = request.args.get(\"host\")\n\
                 \x20   subprocess.check_output(f\"ping -c 1 {host}\", shell=True)\n",
            )],
            &["python"],
            None,
        )
        .await;
        assert_eq!(seed.taint_paths, vec![vec!["app.py:5", "app.py:6"]]);
        assert_eq!(transfer_kinds(&seed, 0), vec!["source", "local_to_sink"]);
    }

    #[tokio::test]
    async fn e2e_python_a_concatenated_sink_argument_grounds_a_path() {
        let body = format!(
            "{PY_HANDLER_PRELUDE}def run():\n\
             \x20   raw = request.args.get(\"c\")\n\
             \x20   os.system(\"echo \" + raw + \" >/dev/null\")\n"
        );
        let (_d, seed) = e2e(&[("app.py", &body)], &["python"], None).await;
        assert_eq!(seed.taint_paths.len(), 1);
        assert_eq!(transfer_kinds(&seed, 0), vec!["source", "local_to_sink"]);
    }

    #[tokio::test]
    async fn e2e_python_a_format_call_sink_argument_grounds_a_path() {
        let body = format!(
            "{PY_HANDLER_PRELUDE}def run():\n\
             \x20   raw = request.args.get(\"c\")\n\
             \x20   os.system(\"echo {{}}\".format(raw))\n"
        );
        let (_d, seed) = e2e(&[("app.py", &body)], &["python"], None).await;
        assert_eq!(seed.taint_paths.len(), 1);
        assert_eq!(transfer_kinds(&seed, 0), vec!["source", "local_to_sink"]);
    }

    #[tokio::test]
    async fn e2e_python_a_percent_format_sink_argument_grounds_a_path() {
        let body = format!(
            "{PY_HANDLER_PRELUDE}def run():\n\
             \x20   raw = request.args.get(\"c\")\n\
             \x20   os.system(\"echo %s\" % raw)\n"
        );
        let (_d, seed) = e2e(&[("app.py", &body)], &["python"], None).await;
        assert_eq!(seed.taint_paths.len(), 1);
    }

    #[tokio::test]
    async fn e2e_python_a_cross_file_call_grounds_an_arg_to_param_edge() {
        let (_d, seed) = e2e(
            &[
                (
                    "app.py",
                    "from flask import request\n\
                     import helper\n\
                     \n\
                     def handle():\n\
                     \x20   raw = request.args.get(\"c\")\n\
                     \x20   helper.run_cmd(raw)\n",
                ),
                (
                    "helper.py",
                    "import os\n\
                     \n\
                     def run_cmd(c):\n\
                     \x20   os.system(\"sh -c \" + c)\n",
                ),
            ],
            &["python"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["app.py:5", "helper.py:3", "helper.py:4"]]
        );
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
    }

    #[tokio::test]
    async fn e2e_python_a_literal_before_the_tainted_argument_grounds_the_right_slot() {
        // `helper.run_cmd("-v", raw)`: the tainted value is argument 1.
        // Mapping `raw` to slot 0 — the `flag` parameter — would leave
        // the sink's read of `c` ungrounded.
        let (_d, seed) = e2e(
            &[
                (
                    "app.py",
                    "from flask import request\n\
                     import helper\n\
                     \n\
                     def handle():\n\
                     \x20   raw = request.args.get(\"c\")\n\
                     \x20   helper.run_cmd(\"-v\", raw)\n",
                ),
                (
                    "helper.py",
                    "import os\n\
                     \n\
                     def run_cmd(flag, c):\n\
                     \x20   os.system(\"sh -c \" + c)\n",
                ),
            ],
            &["python"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["app.py:5", "helper.py:3", "helper.py:4"]]
        );
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
    }

    #[tokio::test]
    async fn e2e_python_a_two_hop_passthrough_grounds_both_boundaries() {
        let (_d, seed) = e2e(
            &[
                (
                    "app.py",
                    "from flask import request\n\
                     import mid\n\
                     \n\
                     def handle():\n\
                     \x20   raw = request.args.get(\"c\")\n\
                     \x20   mid.step(raw)\n",
                ),
                (
                    "mid.py",
                    "import tail\n\
                     \n\
                     def step(v):\n\
                     \x20   tail.finish(v)\n",
                ),
                (
                    "tail.py",
                    "import os\n\
                     \n\
                     def finish(w):\n\
                     \x20   os.system(w)\n",
                ),
            ],
            &["python"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["app.py:5", "mid.py:3", "tail.py:3", "tail.py:4"]]
        );
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "arg_to_param", "local_to_sink"]
        );
    }

    #[tokio::test]
    async fn e2e_python_a_sanitized_cross_file_path_is_evidence_but_not_a_taint_path() {
        // `quote` is in the built-in sanitizer set, and it neutralizes
        // the value one hop BEFORE the sink function — the case the
        // symbolic walk used to collapse into a bare `None`, which the
        // soft gate would then have re-emitted as an unsanitized path.
        let (_d, seed) = e2e(
            &[
                (
                    "app.py",
                    "from flask import request\n\
                     import shlex\n\
                     import helper\n\
                     \n\
                     def handle():\n\
                     \x20   raw = request.args.get(\"c\")\n\
                     \x20   safe = shlex.quote(raw)\n\
                     \x20   helper.run_cmd(safe)\n",
                ),
                (
                    "helper.py",
                    "import os\n\
                     \n\
                     def run_cmd(c):\n\
                     \x20   os.system(\"sh -c \" + c)\n",
                ),
            ],
            &["python"],
            None,
        )
        .await;
        assert!(seed.taint_paths.is_empty());
        assert_eq!(seed.taint_evidence.len(), 1);
        assert!(seed.taint_evidence[0].sanitized);
        assert!(transfer_kinds(&seed, 0).contains(&"sanitize"));
    }

    #[tokio::test]
    async fn e2e_python_a_built_cursor_execute_is_a_sql_sink() {
        let (_d, seed) = e2e(
            &[
                (
                    "app.py",
                    "from flask import request\n\
                     import db\n\
                     \n\
                     def handle():\n\
                     \x20   name = request.args.get(\"n\")\n\
                     \x20   db.find(name)\n",
                ),
                (
                    "db.py",
                    "import sqlite3\n\
                     \n\
                     def find(n):\n\
                     \x20   cur = sqlite3.connect(\"a.db\").cursor()\n\
                     \x20   cur.execute(\"SELECT * FROM t WHERE n = '\" + n + \"'\")\n",
                ),
            ],
            &["python"],
            None,
        )
        .await;
        assert_eq!(seed.unsafe_sinks.len(), 1);
        assert_eq!(seed.unsafe_sinks[0].line, 5);
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-89".to_string()]);
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
    }

    #[tokio::test]
    async fn e2e_python_a_bound_cursor_execute_is_not_a_sql_sink() {
        // The regression guard for the whole `requires_dynamic_arg`
        // design: a parameterized query must not become a taint path
        // just because the soft gate keeps ungrounded ones.
        let (_d, seed) = e2e(
            &[
                (
                    "app.py",
                    "from flask import request\n\
                     import db\n\
                     \n\
                     def handle():\n\
                     \x20   name = request.args.get(\"n\")\n\
                     \x20   db.find(name)\n",
                ),
                (
                    "db.py",
                    "import sqlite3\n\
                     \n\
                     def find(n):\n\
                     \x20   cur = sqlite3.connect(\"a.db\").cursor()\n\
                     \x20   cur.execute(\"SELECT * FROM t WHERE n = ?\", (n,))\n",
                ),
            ],
            &["python"],
            None,
        )
        .await;
        assert!(seed.unsafe_sinks.is_empty());
        assert!(seed.taint_paths.is_empty());
    }

    #[tokio::test]
    async fn e2e_python_an_unguarded_route_is_reachable_from_unauth_and_a_guarded_one_is_not() {
        let (_d, seed) = e2e(
            &[(
                "app.py",
                "from flask import request\n\
                 from auth import login_required\n\
                 \n\
                 @app.route(\"/open\")\n\
                 def open_page():\n\
                 \x20   return \"ok\"\n\
                 \n\
                 @app.route(\"/closed\")\n\
                 @login_required\n\
                 def closed_page():\n\
                 \x20   return \"ok\"\n",
            )],
            &["python"],
            None,
        )
        .await;
        let by = |f: &str| {
            seed.framework_entry_points
                .iter()
                .find(|e| e.function == f)
                .unwrap()
                .reachable_from_unauth
        };
        assert!(by("open_page"));
        assert!(!by("closed_page"));
    }

    #[tokio::test]
    async fn e2e_java_a_concatenated_query_grounds_a_cross_file_path() {
        let (_d, seed) = e2e(
            &[
                (
                    "Handler.java",
                    "public class Handler {\n\
                     \x20 public void handle(HttpServletRequest request) {\n\
                     \x20   String q = request.getParameter(\"q\");\n\
                     \x20   Helper.run(q);\n\
                     \x20 }\n\
                     }\n",
                ),
                (
                    "Helper.java",
                    "public class Helper {\n\
                     \x20 static void run(String q) {\n\
                     \x20   st.executeQuery(\"SELECT * FROM t WHERE a = '\" + q + \"'\");\n\
                     \x20 }\n\
                     }\n",
                ),
            ],
            &["java"],
            None,
        )
        .await;
        assert_eq!(seed.unsafe_sinks.len(), 1);
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-89".to_string()]);
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
    }

    #[tokio::test]
    async fn e2e_csharp_an_interpolated_query_grounds_a_cross_file_path() {
        // The bundled corpus has no C# source rule (ASP.NET request
        // input is an indexer, not a call), so this supplies one — the
        // extractor and evidence plane are what's under test.
        let sources = r#"
rules:
  - id: cs.console-readline
    languages: [csharp]
    pattern: Console.ReadLine(...)
    metadata:
      cwe: CWE-20
      ep_kind: stdin
"#;
        let sinks = r#"
rules:
  - id: cs.dbcommand-execute
    languages: [csharp]
    pattern: $CMD.ExecuteReader(...)
    metadata:
      cwe: CWE-89
      sink_kind: sql
      requires_dynamic_arg: true
"#;
        let (_d, seed) = e2e(
            &[
                (
                    "Handler.cs",
                    "class Handler {\n\
                     \x20 void Handle() {\n\
                     \x20   var q = Console.ReadLine();\n\
                     \x20   Helper.Run(q);\n\
                     \x20 }\n\
                     }\n",
                ),
                (
                    "Helper.cs",
                    "class Helper {\n\
                     \x20 static void Run(string q) {\n\
                     \x20   cmd.ExecuteReader($\"SELECT * FROM t WHERE a = '{q}'\");\n\
                     \x20 }\n\
                     }\n",
                ),
            ],
            &["csharp"],
            Some((sources, sinks)),
        )
        .await;
        assert_eq!(seed.unsafe_sinks.len(), 1);
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
    }

    // ── Go, JavaScript, TypeScript and C#, end to end ────────────────
    //
    // Go and JS/TS carried no intra-procedural facts at all and C# no
    // source rule, so before the 2026-09-07 seed-plane work none of the
    // four could produce a single grounded path. Every test below runs
    // the REAL extractor over real files against the BUNDLED corpus —
    // the lesson of 2026-09-06, when ~140 green hand-built-fixture
    // tests coexisted with `taint_paths = 0` on a live repo.

    /// `reachable_from_unauth` of the framework entry point for `f`.
    /// `expect` rather than `unwrap_or_else(|| panic!(…))`: a panic
    /// closure is a function coverage never executes, and this crate's
    /// gate is 100% of them.
    fn unauth(seed: &crate::SeedPackage, f: &str) -> bool {
        seed.framework_entry_points
            .iter()
            .find(|e| e.function == f)
            .expect("no framework entry point for that handler")
            .reachable_from_unauth
    }

    #[tokio::test]
    async fn e2e_go_a_cross_file_call_grounds_an_arg_to_param_edge() {
        let (_d, seed) = e2e(
            &[
                (
                    "app.go",
                    "package main\n\
                     \n\
                     import \"helper\"\n\
                     \n\
                     func Handle(w http.ResponseWriter, r *http.Request) {\n\
                     \tname := r.FormValue(\"name\")\n\
                     \thelper.RunCmd(name)\n\
                     }\n",
                ),
                (
                    "helper.go",
                    "package helper\n\
                     \n\
                     import \"os/exec\"\n\
                     \n\
                     func RunCmd(c string) {\n\
                     \texec.Command(\"sh\", \"-c\", \"echo \"+c)\n\
                     }\n",
                ),
            ],
            &["go"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["app.go:6", "helper.go:5", "helper.go:6"]]
        );
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-78".to_string()]);
    }

    #[tokio::test]
    async fn e2e_go_a_literal_before_the_tainted_argument_grounds_the_right_slot() {
        let (_d, seed) = e2e(
            &[
                (
                    "app.go",
                    "package main\n\
                     \n\
                     import \"helper\"\n\
                     \n\
                     func Handle(w http.ResponseWriter, r *http.Request) {\n\
                     \tname := r.FormValue(\"name\")\n\
                     \thelper.RunCmd(\"-v\", name)\n\
                     }\n",
                ),
                (
                    "helper.go",
                    "package helper\n\
                     \n\
                     import \"os/exec\"\n\
                     \n\
                     func RunCmd(flag string, c string) {\n\
                     \texec.Command(\"sh\", \"-c\", \"echo \"+c)\n\
                     }\n",
                ),
            ],
            &["go"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["app.go:6", "helper.go:5", "helper.go:6"]]
        );
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
    }

    #[tokio::test]
    async fn e2e_go_a_returned_value_grounds_a_return_to_local_edge() {
        let (_d, seed) = e2e(
            &[
                (
                    "app.go",
                    "package main\n\
                     \n\
                     import \"helper\"\n\
                     \n\
                     func Handle(w http.ResponseWriter, r *http.Request) {\n\
                     \traw := r.FormValue(\"q\")\n\
                     \tq := helper.Build(raw)\n\
                     \tdb.Query(q)\n\
                     }\n",
                ),
                (
                    "helper.go",
                    "package helper\n\
                     \n\
                     func Build(v string) string {\n\
                     \treturn \"SELECT \" + v\n\
                     }\n",
                ),
            ],
            &["go"],
            None,
        )
        .await;
        assert_eq!(seed.taint_paths.len(), 1);
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "return_to_local", "return_to_sink"]
        );
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-89".to_string()]);
    }

    #[tokio::test]
    async fn e2e_go_a_parameterized_query_is_not_a_sql_sink() {
        let (_d, seed) = e2e(
            &[(
                "app.go",
                "package main\n\
                 \n\
                 func Handle(w http.ResponseWriter, r *http.Request) {\n\
                 \tname := r.FormValue(\"name\")\n\
                 \tdb.Query(\"SELECT * FROM t WHERE n = ?\", name)\n\
                 }\n",
            )],
            &["go"],
            None,
        )
        .await;
        assert!(seed.unsafe_sinks.is_empty());
        assert!(seed.taint_paths.is_empty());
    }

    #[tokio::test]
    async fn e2e_go_routes_are_entry_points_with_auth_computed() {
        let (_d, seed) = e2e(
            &[(
                "routes.go",
                "package main\n\
                 \n\
                 func Mount() {\n\
                 \tr.GET(\"/open/:id\", openPage)\n\
                 \tr.GET(\"/closed\", JWTMiddleware, closedPage)\n\
                 \thttp.HandleFunc(\"/plain\", plainPage)\n\
                 }\n\
                 \n\
                 func openPage(c *gin.Context)  {}\n\
                 func closedPage(c *gin.Context) {}\n\
                 func plainPage(w http.ResponseWriter, r *http.Request) {}\n",
            )],
            &["go"],
            None,
        )
        .await;
        assert!(unauth(&seed, "openPage"));
        assert!(unauth(&seed, "plainPage"));
        assert!(!unauth(&seed, "closedPage"));
    }

    /// A two-file Express app: `handle` reads `req.query.name` and hands
    /// it to `helper.runCmd`, which shells out. `ext` picks `.js` vs
    /// `.ts` so the identical flow is proven through both grammars.
    fn express_pair(ext: &str) -> [(String, String); 2] {
        [
            (
                format!("app.{ext}"),
                "const helper = require('./helper');\n\
                 \n\
                 function handle(req, res) {\n\
                 \x20 const name = req.query.name;\n\
                 \x20 helper.runCmd(name);\n\
                 }\n"
                .to_string(),
            ),
            (
                format!("helper.{ext}"),
                "const child_process = require('child_process');\n\
                 \n\
                 function runCmd(c) {\n\
                 \x20 child_process.exec(`echo ${c}`);\n\
                 }\n"
                .to_string(),
            ),
        ]
    }

    /// `express_pair` as the borrowed shape `e2e` takes.
    fn as_files(pair: &[(String, String); 2]) -> Vec<(&str, &str)> {
        pair.iter().map(|(n, b)| (n.as_str(), b.as_str())).collect()
    }

    #[tokio::test]
    async fn e2e_javascript_a_cross_file_call_grounds_an_arg_to_param_edge() {
        let pair = express_pair("js");
        let (_d, seed) = e2e(&as_files(&pair), &["javascript"], None).await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["app.js:4", "helper.js:3", "helper.js:4"]]
        );
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-78".to_string()]);
    }

    #[tokio::test]
    async fn e2e_typescript_a_cross_file_call_grounds_an_arg_to_param_edge() {
        // The same flow through the TypeScript grammar, whose parameter
        // lists are `required_parameter` wrappers rather than bare
        // identifiers — the shape that made `FuncDef::params` empty and
        // every `arg_to_param` edge unresolvable by name.
        let (_d, seed) = e2e(
            &[
                (
                    "app.ts",
                    "import * as helper from './helper';\n\
                     \n\
                     export function handle(req: Request, res: Response): void {\n\
                     \x20 const name: string = req.query.name;\n\
                     \x20 helper.runCmd(name);\n\
                     }\n",
                ),
                (
                    "helper.ts",
                    "import * as child_process from 'child_process';\n\
                     \n\
                     export function runCmd(c: string): void {\n\
                     \x20 child_process.exec(`echo ${c}`);\n\
                     }\n",
                ),
            ],
            &["typescript"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["app.ts:4", "helper.ts:3", "helper.ts:4"]]
        );
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
    }

    #[tokio::test]
    async fn e2e_javascript_a_literal_before_the_tainted_argument_grounds_the_right_slot() {
        let (_d, seed) = e2e(
            &[
                (
                    "app.js",
                    "const helper = require('./helper');\n\
                     \n\
                     function handle(req, res) {\n\
                     \x20 const name = req.query.name;\n\
                     \x20 helper.runCmd('-v', name);\n\
                     }\n",
                ),
                (
                    "helper.js",
                    "const child_process = require('child_process');\n\
                     \n\
                     function runCmd(flag, c) {\n\
                     \x20 child_process.exec('echo ' + c);\n\
                     }\n",
                ),
            ],
            &["javascript"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["app.js:4", "helper.js:3", "helper.js:4"]]
        );
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
    }

    #[tokio::test]
    async fn e2e_typescript_an_arrow_handler_grounds_a_return_to_local_edge() {
        // The handler is an arrow bound to a `const`, which is where
        // most Express/Next code puts one — and which carried no
        // `FuncDef` at all before.
        let (_d, seed) = e2e(
            &[
                (
                    "app.ts",
                    "import * as helper from './helper';\n\
                     \n\
                     export const handle = (req: Request): void => {\n\
                     \x20 const raw = req.query.q;\n\
                     \x20 const sql = helper.build(raw);\n\
                     \x20 db.query(sql);\n\
                     };\n",
                ),
                (
                    "helper.ts",
                    "export function build(v: string): string {\n\
                     \x20 return `SELECT ${v}`;\n\
                     }\n",
                ),
            ],
            &["typescript"],
            None,
        )
        .await;
        assert_eq!(seed.taint_paths.len(), 1);
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "return_to_local", "return_to_sink"]
        );
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-89".to_string()]);
    }

    #[tokio::test]
    async fn e2e_javascript_a_parameterized_query_is_not_a_sql_sink() {
        let (_d, seed) = e2e(
            &[(
                "app.js",
                "function handle(req, res) {\n\
                 \x20 const id = req.query.id;\n\
                 \x20 db.query('SELECT * FROM t WHERE id = ?', [id]);\n\
                 }\n",
            )],
            &["javascript"],
            None,
        )
        .await;
        assert!(seed.unsafe_sinks.is_empty());
        assert!(seed.taint_paths.is_empty());
    }

    #[tokio::test]
    async fn e2e_javascript_an_ungrounded_reachable_pair_still_keeps_its_path() {
        // The soft gate, now that JavaScript reaches it at all: this
        // pair IS call-graph reachable and the walk cannot ground it
        // (the sink argument is a call to a function that is not in the
        // repo), so it keeps its place in `taint_paths` carrying the
        // bare fallback evidence. Nothing that grounded before the
        // extractor learned to emit facts may disappear now that it
        // does.
        let (_d, seed) = e2e(
            &[(
                "app.js",
                "function handle(req, res) {\n\
                 \x20 const name = req.query.name;\n\
                 \x20 child_process.exec(buildCommand());\n\
                 }\n",
            )],
            &["javascript"],
            None,
        )
        .await;
        assert_eq!(seed.taint_paths, vec![vec!["app.js:2", "app.js:3"]]);
        assert_eq!(seed.taint_evidence.len(), 1);
        assert!(seed.taint_evidence[0].edges.is_empty());
        assert!(!seed.taint_evidence[0].sanitized);
    }

    #[tokio::test]
    async fn e2e_javascript_koa_and_fastify_routes_are_entry_points_with_auth_computed() {
        let (_d, seed) = e2e(
            &[(
                "routes.js",
                "function showKoa(ctx) { return ctx.query; }\n\
                 function showFastify(request) { return request.query; }\n\
                 function createThing(request) { return request.body; }\n\
                 router.get('/koa/:id', showKoa);\n\
                 fastify.get('/f/:id', { preHandler: verifyToken }, showFastify);\n\
                 fastify.post('/open', createThing);\n",
            )],
            &["javascript"],
            None,
        )
        .await;
        assert!(unauth(&seed, "showKoa"));
        assert!(unauth(&seed, "createThing"));
        assert!(!unauth(&seed, "showFastify"));
    }

    #[tokio::test]
    async fn e2e_javascript_a_hapi_route_is_an_entry_point() {
        let (_d, seed) = e2e(
            &[(
                "routes.js",
                "function showUser(request, h) { return request.params; }\n\
                 server.route({ method: 'GET', path: '/u/{id}', handler: showUser });\n",
            )],
            &["javascript"],
            None,
        )
        .await;
        assert!(unauth(&seed, "showUser"));
    }

    #[tokio::test]
    async fn e2e_typescript_nestjs_controller_routes_are_entry_points_with_auth_computed() {
        let (_d, seed) = e2e(
            &[(
                "users.controller.ts",
                "@Controller('users')\n\
                 export class UsersController {\n\
                 \x20 @Get(':id')\n\
                 \x20 findOne(@Param('id') id: string): string { return id; }\n\
                 \n\
                 \x20 @UseGuards(AuthGuard)\n\
                 \x20 @Post()\n\
                 \x20 create(@Body() dto: any): any { return dto; }\n\
                 }\n",
            )],
            &["typescript"],
            None,
        )
        .await;
        assert!(unauth(&seed, "findOne"));
        assert!(!unauth(&seed, "create"));
    }

    // ── framework entry points: PHP / Ruby / Kotlin / Rust ──────────
    //
    // These four languages carry framework routes and auth guards but
    // no source/sink rules in the bundled corpus, and
    // `run_callgraph_engine` short-circuits to an empty seed when zero
    // specs apply to the active languages — so every test below
    // supplies one nominal rule pair. Nothing in a fixture has to match
    // it; the framework plane is what is under test.

    const ROUTE_SOURCES: &str = r#"
rules:
  - id: ext.request-read
    languages: [php, ruby, kotlin, rust]
    pattern: request.param(...)
    metadata:
      cwe: CWE-20
      ep_kind: network
"#;
    const ROUTE_SINKS: &str = r#"
rules:
  - id: ext.exec
    languages: [php, ruby, kotlin, rust]
    pattern: $X.exec(...)
    metadata:
      cwe: CWE-78
      sink_kind: command
"#;

    /// [`e2e`] with the nominal rule pair above.
    async fn e2e_routes(
        files: &[(&str, &str)],
        languages: &'static [&'static str],
    ) -> (tempfile::TempDir, crate::SeedPackage) {
        e2e(files, languages, Some((ROUTE_SOURCES, ROUTE_SINKS))).await
    }

    /// `"<METHOD> <path> -> <handler> @<line>"` per route the framework
    /// plane recorded for one file of an [`e2e_routes`] repo, read back
    /// through the same `scan_file` the engine itself runs.
    fn routes_in(dir: &tempfile::TempDir, rel: &str, language: &str) -> Vec<String> {
        let idx = scan_file(
            &dir.path().join(rel),
            rel,
            language,
            &[],
            &[],
            false,
            None,
            None,
        )
        .unwrap();
        idx.framework_markers
            .iter()
            .map(|m| format!("{} -> {} @{}", m.marker_name, m.function_qnode, m.line))
            .collect()
    }

    /// A language with routes but no taint corpus must still surface its
    /// entry points: the engine used to return an empty seed the moment
    /// zero rules applied, which zeroed every route on a single-language
    /// PHP/Ruby/Kotlin/Rust repo while the per-file scan was finding them.
    #[tokio::test]
    async fn e2e_a_route_only_language_with_no_corpus_still_yields_entry_points() {
        let (_d, seed) = e2e(
            &[(
                "src/main.rs",
                "use axum::{routing::get, Router};\n\
                 async fn search() -> &'static str { \"ok\" }\n\
                 fn app() -> Router { Router::new().route(\"/search\", get(search)) }\n",
            )],
            &["rust"],
            None,
        )
        .await;
        assert_eq!(seed.framework_entry_points.len(), 1);
        assert_eq!(seed.framework_entry_points[0].function, "search");
        assert!(seed.taint_paths.is_empty());
    }

    #[tokio::test]
    async fn e2e_php_laravel_routes_carry_their_method_path_handler_and_guard() {
        let (dir, seed) = e2e_routes(
            &[(
                "web.php",
                "<?php\n\
                 Route::get('/open', [PublicController::class, 'index']);\n\
                 Route::group(['middleware' => 'auth', 'prefix' => 'admin'], function () {\n\
                 \x20   Route::get('/users/{id}', [AdminController::class, 'show']);\n\
                 });\n",
            )],
            &["php"],
        )
        .await;
        assert_eq!(
            routes_in(&dir, "web.php", "php"),
            vec![
                "GET /open -> PublicController@index @2".to_string(),
                "GET /admin/users/{id} -> AdminController@show @4".to_string(),
            ]
        );
        assert!(unauth(&seed, "PublicController@index"));
        assert!(!unauth(&seed, "AdminController@show"));
    }

    #[tokio::test]
    async fn e2e_php_symfony_attribute_routes_carry_their_method_path_handler_and_guard() {
        let (dir, seed) = e2e_routes(
            &[(
                "UserController.php",
                "<?php\n\
                 #[Route('/api')]\n\
                 class UserController {\n\
                 \x20   #[Route('/users/{id}', methods: ['GET'])]\n\
                 \x20   public function show(int $id) { return $id; }\n\
                 \n\
                 \x20   #[Route('/users', methods: ['POST'])]\n\
                 \x20   #[IsGranted('ROLE_ADMIN')]\n\
                 \x20   public function create() { return 1; }\n\
                 }\n",
            )],
            &["php"],
        )
        .await;
        assert_eq!(
            routes_in(&dir, "UserController.php", "php"),
            vec![
                "GET /api/users/{id} -> show @4".to_string(),
                "POST /api/users -> create @7".to_string(),
            ]
        );
        assert!(unauth(&seed, "show"));
        assert!(!unauth(&seed, "create"));
    }

    #[tokio::test]
    async fn e2e_php_a_script_reading_a_superglobal_is_an_entry_point() {
        let (_d, seed) = e2e_routes(&[("index.php", "<?php\necho $_GET['q'];\n")], &["php"]).await;
        assert!(unauth(&seed, "__main__"));
    }

    #[tokio::test]
    async fn e2e_ruby_rails_routes_carry_their_method_path_handler_and_controller_guard() {
        let (dir, seed) = e2e_routes(
            &[
                (
                    "routes.rb",
                    "Rails.application.routes.draw do\n\
                     \x20 get '/users/:id', to: 'users#show'\n\
                     \x20 get '/about', to: 'pages#about'\n\
                     end\n",
                ),
                (
                    "users_controller.rb",
                    "class UsersController < ApplicationController\n\
                     \x20 before_action :authenticate_user!\n\
                     \x20 def show\n\
                     \x20   render json: {}\n\
                     \x20 end\n\
                     end\n",
                ),
            ],
            &["ruby"],
        )
        .await;
        assert_eq!(
            routes_in(&dir, "routes.rb", "ruby"),
            vec![
                "GET /users/:id -> users#show @2".to_string(),
                "GET /about -> pages#about @3".to_string(),
            ]
        );
        // The guard is declared in the controller, the route in the
        // routes table — two files, one handler id.
        assert!(!unauth(&seed, "users#show"));
        assert!(unauth(&seed, "pages#about"));
    }

    /// The spelling real Rails route tables are written in: the path is
    /// a hash *key*, not a positional argument. A probe over a real
    /// Rails app found zero entry points until this was read.
    #[tokio::test]
    async fn e2e_ruby_rails_hash_rocket_routes_carry_their_method_path_and_controller_guard() {
        let (dir, seed) = e2e_routes(
            &[
                (
                    "routes.rb",
                    "Rails.application.routes.draw do\n\
                     \x20 get '/reports/search' => 'reports#search', as: :report_search\n\
                     \x20 get '/reports/:id/download' => 'reports#download', as: :report_download\n\
                     \x20 post '/ops/reindex' => 'ops#reindex'\n\
                     \x20 match '/ops/ping' => 'ops#ping', via: [:get, :post]\n\
                     end\n",
                ),
                (
                    "reports_controller.rb",
                    "class ReportsController < ApplicationController\n\
                     \x20 before_action :authenticate_user!, except: [:search]\n\
                     \x20 def search\n\
                     \x20 end\n\
                     \x20 def download\n\
                     \x20 end\n\
                     end\n",
                ),
                (
                    "ops_controller.rb",
                    "class OpsController < ApplicationController\n\
                     \x20 before_action :require_admin!\n\
                     \x20 def reindex\n\
                     \x20 end\n\
                     \x20 def ping\n\
                     \x20 end\n\
                     end\n",
                ),
            ],
            &["ruby"],
        )
        .await;
        assert_eq!(
            routes_in(&dir, "routes.rb", "ruby"),
            vec![
                "GET /reports/search -> reports#search @2".to_string(),
                "GET /reports/:id/download -> reports#download @3".to_string(),
                "POST /ops/reindex -> ops#reindex @4".to_string(),
                // `match … via:` binds one route per verb it names.
                "GET /ops/ping -> ops#ping @5".to_string(),
                "POST /ops/ping -> ops#ping @5".to_string(),
            ]
        );
        assert!(unauth(&seed, "reports#search"));
        assert!(!unauth(&seed, "reports#download"));
        // `require_admin!` is the project's own guard name, not one any
        // framework ships.
        assert!(!unauth(&seed, "ops#reindex"));
        assert!(!unauth(&seed, "ops#ping"));
    }

    #[tokio::test]
    async fn e2e_ruby_rails_resources_expands_to_the_seven_conventional_actions() {
        let (dir, seed) = e2e_routes(
            &[(
                "routes.rb",
                "Rails.application.routes.draw do\n\
                 \x20 namespace :admin do\n\
                 \x20   resources :users\n\
                 \x20 end\n\
                 end\n",
            )],
            &["ruby"],
        )
        .await;
        assert_eq!(
            routes_in(&dir, "routes.rb", "ruby"),
            vec![
                "GET /admin/users -> admin/users#index @3".to_string(),
                "POST /admin/users -> admin/users#create @3".to_string(),
                "GET /admin/users/:id -> admin/users#show @3".to_string(),
                "PATCH /admin/users/:id -> admin/users#update @3".to_string(),
                "DELETE /admin/users/:id -> admin/users#destroy @3".to_string(),
                "GET /admin/users/:id/edit -> admin/users#edit @3".to_string(),
                "GET /admin/users/new -> admin/users#new @3".to_string(),
            ]
        );
        assert_eq!(seed.framework_entry_points.len(), 7);
        assert!(unauth(&seed, "admin/users#destroy"));
    }

    #[tokio::test]
    async fn e2e_ruby_a_sinatra_route_is_guarded_only_by_a_before_filter() {
        let (dir, seed) =
            e2e_routes(&[("open.rb", "get '/open' do\n  \"ok\"\nend\n")], &["ruby"]).await;
        assert_eq!(
            routes_in(&dir, "open.rb", "ruby"),
            vec!["GET /open -> get_open @1".to_string()]
        );
        assert!(unauth(&seed, "get_open"));

        let (_d, guarded) = e2e_routes(
            &[(
                "closed.rb",
                "before do\n  authenticate!\nend\n\nget '/closed' do\n  \"ok\"\nend\n",
            )],
            &["ruby"],
        )
        .await;
        assert!(!unauth(&guarded, "get_closed"));
    }

    #[tokio::test]
    async fn e2e_kotlin_ktor_nested_routes_carry_their_method_path_handler_and_guard() {
        let (dir, seed) = e2e_routes(
            &[(
                "App.kt",
                "fun Application.module() {\n\
                 \x20   routing {\n\
                 \x20       route(\"/api\") {\n\
                 \x20           get(\"/health\") { call.respond(1) }\n\
                 \x20           authenticate(\"jwt\") {\n\
                 \x20               get(\"/me/{id}\") { call.respond(2) }\n\
                 \x20           }\n\
                 \x20       }\n\
                 \x20   }\n\
                 }\n",
            )],
            &["kotlin"],
        )
        .await;
        assert_eq!(
            routes_in(&dir, "App.kt", "kotlin"),
            vec![
                "GET /api/health -> get_api_health @4".to_string(),
                "GET /api/me/{id} -> get_api_me_id @6".to_string(),
            ]
        );
        assert!(unauth(&seed, "get_api_health"));
        assert!(!unauth(&seed, "get_api_me_id"));
    }

    #[tokio::test]
    async fn e2e_kotlin_spring_mappings_carry_their_method_path_handler_and_guard() {
        let (dir, seed) = e2e_routes(
            &[(
                "UserController.kt",
                "@RestController\n\
                 @RequestMapping(\"/api\")\n\
                 class UserController {\n\
                 \x20   @GetMapping(\"/users/{id}\")\n\
                 \x20   fun show(@PathVariable id: String): String = id\n\
                 \n\
                 \x20   @PostMapping(\"/users\")\n\
                 \x20   @PreAuthorize(\"hasRole('ADMIN')\")\n\
                 \x20   fun create(): String = \"\"\n\
                 }\n",
            )],
            &["kotlin"],
        )
        .await;
        assert_eq!(
            routes_in(&dir, "UserController.kt", "kotlin"),
            vec![
                "GET /api/users/{id} -> show @4".to_string(),
                "POST /api/users -> create @7".to_string(),
            ]
        );
        assert!(unauth(&seed, "show"));
        assert!(!unauth(&seed, "create"));
    }

    #[tokio::test]
    async fn e2e_typescript_nextjs_file_based_routes_are_entry_points() {
        let (_d, seed) = e2e(
            &[
                (
                    "pages/api/users/[id].ts",
                    "export default function handler(req, res) { return res.json(req.query); }\n",
                ),
                (
                    "app/api/items/route.ts",
                    "export async function GET(request) { return new Response('ok'); }\n",
                ),
            ],
            &["typescript"],
            None,
        )
        .await;
        assert!(unauth(&seed, "handler"));
        assert!(unauth(&seed, "GET"));
    }

    #[tokio::test]
    async fn e2e_csharp_an_aspnet_request_property_grounds_a_cross_file_path() {
        // `Request.Query["id"]` is an indexer on a property, which is
        // why C# shipped with no source rule at all until the extractor
        // learned to record a property read as a call site.
        let (_d, seed) = e2e(
            &[
                (
                    "Handler.cs",
                    "class Handler {\n\
                     \x20 void Handle() {\n\
                     \x20   var q = Request.Query[\"id\"];\n\
                     \x20   Helper.Run(q);\n\
                     \x20 }\n\
                     }\n",
                ),
                (
                    "Helper.cs",
                    "class Helper {\n\
                     \x20 static void Run(string q) {\n\
                     \x20   cmd.ExecuteReader($\"SELECT * FROM t WHERE a = '{q}'\");\n\
                     \x20 }\n\
                     }\n",
                ),
            ],
            &["csharp"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["Handler.cs:3", "Helper.cs:2", "Helper.cs:3"]]
        );
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-89".to_string()]);
    }

    #[tokio::test]
    async fn e2e_csharp_a_literal_before_the_tainted_argument_grounds_the_right_slot() {
        let (_d, seed) = e2e(
            &[
                (
                    "Handler.cs",
                    "class Handler {\n\
                     \x20 void Handle() {\n\
                     \x20   var q = Request.Form[\"n\"];\n\
                     \x20   Helper.Run(\"-v\", q);\n\
                     \x20 }\n\
                     }\n",
                ),
                (
                    "Helper.cs",
                    "class Helper {\n\
                     \x20 static void Run(string flag, string q) {\n\
                     \x20   Process.Start(\"sh\", \"-c \" + q);\n\
                     \x20 }\n\
                     }\n",
                ),
            ],
            &["csharp"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["Handler.cs:3", "Helper.cs:2", "Helper.cs:3"]]
        );
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-78".to_string()]);
    }

    #[tokio::test]
    async fn e2e_csharp_a_returned_value_grounds_a_return_to_local_edge() {
        let (_d, seed) = e2e(
            &[
                (
                    "Handler.cs",
                    "class Handler {\n\
                     \x20 void Handle() {\n\
                     \x20   var raw = Request.Query[\"id\"];\n\
                     \x20   var sql = Helper.Build(raw);\n\
                     \x20   cmd.ExecuteReader(sql);\n\
                     \x20 }\n\
                     }\n",
                ),
                (
                    "Helper.cs",
                    "class Helper {\n\
                     \x20 static string Build(string v) {\n\
                     \x20   return \"SELECT \" + v;\n\
                     \x20 }\n\
                     }\n",
                ),
            ],
            &["csharp"],
            None,
        )
        .await;
        assert_eq!(seed.taint_paths.len(), 1);
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "return_to_local", "return_to_sink"]
        );
    }

    #[tokio::test]
    async fn e2e_csharp_a_parameterized_sqlcommand_is_not_a_sql_sink() {
        let (_d, seed) = e2e(
            &[(
                "Handler.cs",
                "class Handler {\n\
                 \x20 void Handle() {\n\
                 \x20   var q = Request.Query[\"id\"];\n\
                 \x20   var cmd = new SqlCommand(\"SELECT * FROM t WHERE a = @a\", conn);\n\
                 \x20 }\n\
                 }\n",
            )],
            &["csharp"],
            None,
        )
        .await;
        assert!(seed.unsafe_sinks.is_empty());
        assert!(seed.taint_paths.is_empty());
    }

    // ── Go route tables that import their handlers ───────────────────

    #[tokio::test]
    async fn e2e_go_an_imported_handler_is_an_entry_point_on_the_file_that_defines_it() {
        // The gin/echo/chi idiom: `main.go` registers handlers it
        // imports from a `handlers` package, and guards them with a
        // group-level middleware. Naming the entry point after the
        // route table invents a function `main.go` does not have, and
        // recording the guard only where the route is written leaves
        // every grouped handler looking anonymously reachable.
        let (_d, seed) = e2e(
            &[
                (
                    "main.go",
                    "package main\n\
                     \n\
                     import \"example.com/app/handlers\"\n\
                     \n\
                     func RequireAdmin() gin.HandlerFunc { return nil }\n\
                     \n\
                     func mount() {\n\
                     \tr := gin.New()\n\
                     \tr.Use(gin.Logger())\n\
                     \tr.GET(\"/reports\", handlers.SearchReports)\n\
                     \tadmin := r.Group(\"/admin\")\n\
                     \tadmin.Use(RequireAdmin())\n\
                     \tadmin.GET(\"/export/:id\", handlers.ExportReport)\n\
                     \tmux := http.NewServeMux()\n\
                     \tmux.Handle(\"/probe\", requireServiceToken(http.HandlerFunc(probeHandler)))\n\
                     \tmux.Handle(\"/\", r)\n\
                     }\n\
                     \n\
                     func probeHandler(w http.ResponseWriter, r *http.Request) {}\n",
                ),
                (
                    "handlers/handlers.go",
                    "package handlers\n\
                     \n\
                     func SearchReports(c *gin.Context) {}\n\
                     \n\
                     func ExportReport(c *gin.Context) {}\n",
                ),
            ],
            &["go"],
            None,
        )
        .await;
        let mut seen: Vec<(&str, &str, bool)> = seed
            .framework_entry_points
            .iter()
            .map(|e| {
                (
                    e.file.as_str(),
                    e.function.as_str(),
                    e.reachable_from_unauth,
                )
            })
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                // Resolved through the import to the file that defines
                // it, and guarded by the group's own middleware.
                ("handlers/handlers.go", "ExportReport", false),
                ("handlers/handlers.go", "SearchReports", true),
                // A wrapped handler is found inside its wrapper, and
                // the wrapper is the guard.
                ("main.go", "probeHandler", false),
            ]
        );
        // `mux.Handle("/", r)` mounts a router; `r` is not a handler
        // and must not become an entry point.
        assert!(!seed
            .framework_entry_points
            .iter()
            .any(|e| e.function == "r"));
    }

    // ── Java: the sink families, and annotation-bound sources ────────

    /// A Spring-shaped two-file app: the controller reads one request
    /// parameter and hands it to `Helper.run`, whose body is `sink`.
    fn java_pair(sink: &str) -> [(String, String); 2] {
        [
            (
                "Portal.java".to_string(),
                "public class Portal {\n\
                 \x20 public void handle(HttpServletRequest request) throws Exception {\n\
                 \x20   String v = request.getParameter(\"v\");\n\
                 \x20   Helper.run(v);\n\
                 \x20 }\n\
                 }\n"
                .to_string(),
            ),
            (
                "Helper.java".to_string(),
                format!(
                    "public class Helper {{\n\
                     \x20 static void run(String v) throws Exception {{\n\
                     \x20   {sink}\n\
                     \x20 }}\n\
                     }}\n"
                ),
            ),
        ]
    }

    /// The `(cwe, line)` of every sink the Java pair produced.
    async fn java_sink_cwes(sink: &str) -> Vec<String> {
        let pair = java_pair(sink);
        let files: Vec<(&str, &str)> = pair.iter().map(|(n, b)| (n.as_str(), b.as_str())).collect();
        let (_d, seed) = e2e(&files, &["java"], None).await;
        assert!(
            !seed.taint_paths.is_empty(),
            "the seeded flow produced no taint path"
        );
        let mut out: Vec<String> = seed
            .unsafe_sinks
            .iter()
            .flat_map(|s| s.cwe.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    #[tokio::test]
    async fn e2e_java_command_execution_sinks_ground_a_path() {
        // `Runtime.getRuntime().exec(cmd)` reduces to an `exec` call on
        // `Runtime`; the pre-existing codeql-qualified rule could never
        // match it, because `java.lang` is implicitly imported and so
        // the receiver never resolves.
        assert_eq!(
            java_sink_cwes("Runtime.getRuntime().exec(\"sh -c \" + v);").await,
            vec!["CWE-78".to_string()]
        );
        assert_eq!(
            java_sink_cwes("new ProcessBuilder(\"/bin/sh\", \"-c\", v).start();").await,
            vec!["CWE-78".to_string()]
        );
    }

    #[tokio::test]
    async fn e2e_java_path_traversal_sinks_ground_a_path() {
        assert_eq!(
            java_sink_cwes("Files.readAllBytes(ROOT.resolve(v));").await,
            vec!["CWE-22".to_string()]
        );
        assert_eq!(
            java_sink_cwes("new FileInputStream(new File(v)).close();").await,
            vec!["CWE-22".to_string()]
        );
    }

    #[tokio::test]
    async fn e2e_java_deserialization_and_xxe_sinks_ground_a_path() {
        assert_eq!(
            java_sink_cwes("new ObjectInputStream(open(v)).readObject();").await,
            vec!["CWE-502".to_string()]
        );
        assert_eq!(
            java_sink_cwes("DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(v);")
                .await,
            vec!["CWE-611".to_string()]
        );
    }

    #[tokio::test]
    async fn e2e_java_ssrf_redirect_and_ldap_sinks_ground_a_path() {
        assert_eq!(
            java_sink_cwes("new URL(v).openConnection().connect();").await,
            vec!["CWE-918".to_string()]
        );
        assert_eq!(
            java_sink_cwes("response.sendRedirect(v);").await,
            vec!["CWE-601".to_string()]
        );
        assert_eq!(
            java_sink_cwes("ctx.search(\"ou=people\", \"(uid=\" + v + \")\", controls);").await,
            vec!["CWE-90".to_string()]
        );
    }

    #[tokio::test]
    async fn e2e_java_spel_and_weak_crypto_sinks_ground_a_path() {
        assert_eq!(
            java_sink_cwes("parser.parseExpression(v).getValue();").await,
            vec!["CWE-95".to_string()]
        );
        assert_eq!(
            java_sink_cwes("MessageDigest.getInstance(\"MD5\").digest(v.getBytes());").await,
            vec!["CWE-327".to_string()]
        );
    }

    #[tokio::test]
    async fn e2e_java_an_annotation_bound_parameter_is_a_source() {
        // `@RequestParam("file") String name` is how most Spring code
        // reads its input. The marker plane recorded it and used it
        // only to emit an entry point, so the parameter it names was
        // never tainted and no sink it reached had a source to pair
        // with — two of the four seeded flows in the polyglot Spring
        // app were invisible for exactly this reason.
        let (_d, seed) = e2e(
            &[
                (
                    "Portal.java",
                    "public class Portal {\n\
                     \x20 @GetMapping(\"/read\")\n\
                     \x20 public byte[] read(@RequestParam(\"file\") String name) throws Exception {\n\
                     \x20   return Archive.load(name);\n\
                     \x20 }\n\
                     }\n",
                ),
                (
                    "Archive.java",
                    "public class Archive {\n\
                     \x20 static byte[] load(String name) throws Exception {\n\
                     \x20   return Files.readAllBytes(ROOT.resolve(name));\n\
                     \x20 }\n\
                     }\n",
                ),
            ],
            &["java"],
            None,
        )
        .await;
        assert!(!seed.taint_paths.is_empty());
        assert_eq!(seed.taint_paths[0][0], "Portal.java:3");
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-22".to_string()]);
    }

    #[tokio::test]
    async fn e2e_java_a_delegating_controller_reaches_the_service_it_shadows() {
        // `exportReport` calling `service.exportReport(...)` is the
        // commonest service-layer shape there is, and the same-file
        // shortcut in call resolution used to answer it with the
        // CALLER, whose self-edge is then dropped — leaving the method
        // with no outgoing edge and everything downstream of it
        // unreachable.
        let (_d, seed) = e2e(
            &[
                (
                    "Portal.java",
                    "public class Portal {\n\
                     \x20 public void exportReport(HttpServletRequest request) throws Exception {\n\
                     \x20   String v = request.getParameter(\"report\");\n\
                     \x20   service.exportReport(v);\n\
                     \x20 }\n\
                     }\n",
                ),
                (
                    "Ops.java",
                    "public class Ops {\n\
                     \x20 public void exportReport(String v) throws Exception {\n\
                     \x20   Runtime.getRuntime().exec(\"sh -c \" + v);\n\
                     \x20 }\n\
                     }\n",
                ),
            ],
            &["java"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["Portal.java:3", "Ops.java:2", "Ops.java:3"]]
        );
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
    }

    #[tokio::test]
    async fn e2e_a_recursive_call_still_resolves_to_itself() {
        // The counterpart guard: a bare (receiver-less) self-call is
        // genuine recursion and must keep resolving to the caller, so
        // the sink inside the recursive function stays reachable.
        let (_d, seed) = e2e(
            &[(
                "Portal.java",
                "public class Portal {\n\
                 \x20 public void walk(HttpServletRequest request, int n) throws Exception {\n\
                 \x20   String v = request.getParameter(\"v\");\n\
                 \x20   walk(request, n - 1);\n\
                 \x20   Runtime.getRuntime().exec(\"sh -c \" + v);\n\
                 \x20 }\n\
                 }\n",
            )],
            &["java"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["Portal.java:3", "Portal.java:5"]]
        );
    }

    #[tokio::test]
    async fn e2e_rust_axum_routes_carry_their_method_path_handler_and_nested_guard() {
        let (dir, seed) = e2e_routes(
            &[(
                "app.rs",
                "fn app() -> Router {\n\
                 \x20   Router::new()\n\
                 \x20       .route(\"/health\", get(health))\n\
                 \x20       .nest(\n\
                 \x20           \"/api\",\n\
                 \x20           Router::new()\n\
                 \x20               .route(\"/me/{id}\", get(me))\n\
                 \x20               .route_layer(middleware::from_fn(auth)),\n\
                 \x20       )\n\
                 }\n\
                 \n\
                 async fn health() -> String { String::new() }\n\
                 async fn me() -> String { String::new() }\n",
            )],
            &["rust"],
        )
        .await;
        assert_eq!(
            routes_in(&dir, "app.rs", "rust"),
            vec![
                "GET /api/me/{id} -> me @7".to_string(),
                "GET /health -> health @3".to_string(),
            ]
        );
        assert!(unauth(&seed, "health"));
        assert!(!unauth(&seed, "me"));
    }

    /// The shape a real axum app is written in: the guarded section is
    /// built in a local and merged into the parent router. A probe over
    /// one reported all four routes anonymously reachable until the
    /// binding was followed.
    #[tokio::test]
    async fn e2e_rust_axum_a_merged_local_router_keeps_its_own_route_layer_guard() {
        let (dir, seed) = e2e_routes(
            &[(
                "main.rs",
                "fn build_router(state: AppState) -> Router {\n\
                 \x20   let operator_routes = Router::new()\n\
                 \x20       .route(\"/admin/reports/:slug/export\", get(handlers::export_report))\n\
                 \x20       .route(\"/admin/jobs/rebuild\", post(handlers::rebuild_index))\n\
                 \x20       .route_layer(middleware::from_fn(require_operator_token));\n\
                 \n\
                 \x20   Router::new()\n\
                 \x20       .route(\"/reports/search\", get(handlers::search_reports))\n\
                 \x20       .merge(operator_routes)\n\
                 \x20       .with_state(state)\n\
                 }\n",
            )],
            &["rust"],
        )
        .await;
        // Each route once, at its own path, with the handler's bare
        // name rather than the `handlers::` path it is referenced by.
        assert_eq!(
            routes_in(&dir, "main.rs", "rust"),
            vec![
                "POST /admin/jobs/rebuild -> rebuild_index @4".to_string(),
                "GET /admin/reports/:slug/export -> export_report @3".to_string(),
                "GET /reports/search -> search_reports @8".to_string(),
            ]
        );
        assert!(unauth(&seed, "search_reports"));
        assert!(!unauth(&seed, "export_report"));
        assert!(!unauth(&seed, "rebuild_index"));
    }

    /// `.nest("/admin", local)` mounts the local router's routes under
    /// the nest prefix, and a guard the *parent* applies after the nest
    /// reaches them.
    #[tokio::test]
    async fn e2e_rust_axum_a_nested_local_router_takes_the_prefix_and_the_parent_guard() {
        let (dir, seed) = e2e_routes(
            &[(
                "main.rs",
                "fn app() -> Router {\n\
                 \x20   let console = Router::new().route(\"/jobs\", get(jobs));\n\
                 \n\
                 \x20   Router::new()\n\
                 \x20       .route(\"/health\", get(health))\n\
                 \x20       .nest(\"/admin\", console)\n\
                 \x20       .route_layer(middleware::from_fn(require_admin_token))\n\
                 }\n",
            )],
            &["rust"],
        )
        .await;
        assert_eq!(
            routes_in(&dir, "main.rs", "rust"),
            vec![
                "GET /admin/jobs -> jobs @2".to_string(),
                "GET /health -> health @5".to_string(),
            ]
        );
        assert!(!unauth(&seed, "jobs"));
        assert!(!unauth(&seed, "health"));
    }

    #[tokio::test]
    async fn e2e_rust_actix_and_rocket_attribute_handlers_carry_their_method_path_and_guard() {
        let (dir, seed) = e2e_routes(
            &[
                (
                    "api.rs",
                    "use actix_web::{get, post, HttpResponse};\n\
                     \n\
                     #[get(\"/items/{id}\")]\n\
                     async fn item(id: u32) -> HttpResponse { HttpResponse::Ok().finish() }\n\
                     \n\
                     #[post(\"/items\")]\n\
                     async fn create(claims: Claims) -> HttpResponse { HttpResponse::Ok().finish() }\n",
                ),
                (
                    "launch.rs",
                    "use rocket::get;\n\
                     \n\
                     #[get(\"/ping/<id>\")]\n\
                     fn ping(id: u32) -> String { String::new() }\n",
                ),
            ],
            &["rust"],
        )
        .await;
        assert_eq!(
            routes_in(&dir, "api.rs", "rust"),
            vec![
                "GET /items/{id} -> item @4".to_string(),
                "POST /items -> create @7".to_string(),
            ]
        );
        assert_eq!(
            routes_in(&dir, "launch.rs", "rust"),
            vec!["GET /ping/<id> -> ping @4".to_string()]
        );
        assert!(unauth(&seed, "item"));
        assert!(!unauth(&seed, "create"));
        assert!(unauth(&seed, "ping"));
    }

    #[tokio::test]
    async fn e2e_rust_an_actix_resource_route_is_an_entry_point() {
        let (dir, seed) = e2e_routes(
            &[(
                "cfg.rs",
                "fn cfg(c: &mut ServiceConfig) {\n\
                 \x20   c.service(web::resource(\"/p\").route(web::get().to(handler)));\n\
                 }\n\
                 \n\
                 async fn handler() -> String { String::new() }\n",
            )],
            &["rust"],
        )
        .await;
        assert_eq!(
            routes_in(&dir, "cfg.rs", "rust"),
            vec!["GET /p -> handler @2".to_string()]
        );
        assert!(unauth(&seed, "handler"));
    }

    // ── a query assembled from literals into a local is bound ────────
    //
    // `requires_dynamic_arg` asks whether the query argument is a
    // literal AT THE CALL SITE, which answers "no" for the
    // parameterized query every tutorial teaches — `String sql = "…
    // WHERE a = ?"; st.prepareStatement(sql)`. The polyglot bed carries
    // exactly that shape as its negative control in five languages, and
    // the seed reported a taint path onto it in each. One test per
    // language, each pairing the safe local with a genuinely composed
    // query so the fix cannot be "stop matching".

    /// `(cwe, line)` per sink the two-file app produced.
    async fn sink_lines(files: &[(&str, &str)], lang: &'static [&'static str]) -> Vec<i64> {
        let (_d, seed) = e2e(files, lang, None).await;
        seed.unsafe_sinks.iter().map(|s| s.line).collect()
    }

    #[tokio::test]
    async fn e2e_java_a_query_built_from_literals_into_a_local_is_bound() {
        let lines = sink_lines(
            &[(
                "Repo.java",
                "public class Repo {\n\
                 \x20 void safe(String owner) throws Exception {\n\
                 \x20   String sql = \"SELECT * FROM t\" + \" WHERE a = ?\";\n\
                 \x20   PreparedStatement st = c.prepareStatement(sql);\n\
                 \x20   st.executeQuery();\n\
                 \x20 }\n\
                 \x20 void unsafe(String owner) throws Exception {\n\
                 \x20   String sql = \"SELECT * FROM t WHERE a = '\" + owner + \"'\";\n\
                 \x20   c.prepareStatement(sql);\n\
                 \x20 }\n\
                 }\n",
            )],
            &["java"],
        )
        .await;
        // Only the composed query is a sink: the bound `prepareStatement`
        // is filtered by the literal-only local, and the zero-argument
        // `executeQuery()` by `requires_any_arg`.
        assert_eq!(lines, vec![9]);
    }

    #[tokio::test]
    async fn e2e_csharp_a_command_built_from_a_literal_local_is_bound() {
        let lines = sink_lines(
            &[(
                "Repo.cs",
                "class Repo {\n\
                 \x20 void Safe(string owner) {\n\
                 \x20   string sql = \"SELECT * FROM t\" + \" WHERE a = @p0\";\n\
                 \x20   var cmd = new SqlCommand(sql, conn);\n\
                 \x20   cmd.ExecuteReader();\n\
                 \x20 }\n\
                 \x20 void Unsafe(string owner) {\n\
                 \x20   var cmd = new SqlCommand(\"SELECT * FROM t WHERE a = '\" + owner + \"'\", conn);\n\
                 \x20   cmd.ExecuteReader();\n\
                 \x20 }\n\
                 }\n",
            )],
            &["csharp"],
        )
        .await;
        // ADO.NET's execute carries no argument at all, so it is judged
        // by the command it was built from — line 5's command came from
        // a literal-only local, line 9's from a composed string.
        assert_eq!(lines, vec![8, 9]);
    }

    #[tokio::test]
    async fn e2e_python_a_query_built_from_literals_into_a_local_is_bound() {
        let lines = sink_lines(
            &[(
                "db.py",
                "def safe(cur, owner):\n\
                 \x20   sql = \"SELECT * FROM t\" \" WHERE a = ?\"\n\
                 \x20   cur.execute(sql, (owner,))\n\
                 \n\
                 def unsafe(cur, owner):\n\
                 \x20   sql = \"SELECT * FROM t WHERE a = '\" + owner + \"'\"\n\
                 \x20   cur.execute(sql)\n",
            )],
            &["python"],
        )
        .await;
        assert_eq!(lines, vec![7]);
    }

    #[tokio::test]
    async fn e2e_go_a_query_built_from_literals_into_a_local_is_bound() {
        let lines = sink_lines(
            &[(
                "store.go",
                "package store\n\
                 \n\
                 func Safe(owner string) {\n\
                 \tsql := \"SELECT * FROM t\" + \" WHERE a = $1\"\n\
                 \tdb.Query(sql, owner)\n\
                 }\n\
                 \n\
                 func Unsafe(owner string) {\n\
                 \tsql := \"SELECT * FROM t WHERE a = '\" + owner + \"'\"\n\
                 \tdb.Query(sql)\n\
                 }\n",
            )],
            &["go"],
        )
        .await;
        assert_eq!(lines, vec![10]);
    }

    #[tokio::test]
    async fn e2e_javascript_a_query_built_from_literals_into_a_local_is_bound() {
        let lines = sink_lines(
            &[(
                "db.js",
                "function safe(owner) {\n\
                 \x20 const sql = 'SELECT * FROM t' + ' WHERE a = ?';\n\
                 \x20 db.query(sql, [owner]);\n\
                 }\n\
                 function unsafe(owner) {\n\
                 \x20 const sql = 'SELECT * FROM t WHERE a = ' + owner;\n\
                 \x20 db.query(sql);\n\
                 }\n",
            )],
            &["javascript"],
        )
        .await;
        assert_eq!(lines, vec![7]);
    }

    #[tokio::test]
    async fn e2e_csharp_a_command_built_empty_keeps_its_execute_dynamic() {
        // `new SqlCommand()` sets its text later through `CommandText`,
        // which this extractor cannot see — so both the argument-less
        // constructor and the zero-argument execute stay sinks, which
        // is the case those two rules exist for.
        let lines = sink_lines(
            &[(
                "Repo.cs",
                "class Repo {\n\
                 \x20 void Run(string owner) {\n\
                 \x20   var cmd = new SqlCommand();\n\
                 \x20   cmd.CommandText = \"SELECT * FROM t WHERE a = '\" + owner + \"'\";\n\
                 \x20   cmd.ExecuteReader();\n\
                 \x20 }\n\
                 }\n",
            )],
            &["csharp"],
        )
        .await;
        assert_eq!(lines, vec![3, 5]);
    }

    // ── PHP / Ruby / Rust, end to end ────────────────────────────────
    //
    // These three were wired for framework routes only: every handler
    // the route plane found led nowhere, because no sink rule existed
    // for them at all. `scan::lite` carries no assign/return/call-arg
    // facts, so nothing here can ground — every path is the soft gate's
    // reachability shape — but a reachable source/sink pair is exactly
    // what the seed owes the stages downstream.

    /// `"file:line"` of each taint path's last hop.
    fn path_sinks(seed: &crate::SeedPackage) -> Vec<String> {
        seed.taint_paths
            .iter()
            .filter_map(|p| p.last().cloned())
            .collect()
    }

    #[tokio::test]
    async fn e2e_php_a_superglobal_reaches_a_shell_across_files() {
        let (_d, seed) = e2e(
            &[
                (
                    "index.php",
                    "<?php\n\
                     function handle() {\n\
                     \x20   $target = $_GET['target'];\n\
                     \x20   return Ops::runHousekeeping($target);\n\
                     }\n",
                ),
                (
                    "Ops.php",
                    "<?php\n\
                     class Ops {\n\
                     \x20   public static function runHousekeeping(string $c): string {\n\
                     \x20       return shell_exec($c.' 2>&1');\n\
                     \x20   }\n\
                     }\n",
                ),
            ],
            &["php"],
            None,
        )
        .await;
        assert_eq!(path_sinks(&seed), vec!["Ops.php:4".to_string()]);
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-78".to_string()]);
    }

    #[tokio::test]
    async fn e2e_php_a_laravel_request_reaches_an_interpolated_query() {
        let (_d, seed) = e2e(
            &[
                (
                    "Controller.php",
                    "<?php\n\
                     class C {\n\
                     \x20   public function search($request) {\n\
                     \x20       $q = $request->query('q');\n\
                     \x20       return Gateway::searchIndex($q);\n\
                     \x20   }\n\
                     }\n",
                ),
                (
                    "Gateway.php",
                    "<?php\n\
                     class Gateway {\n\
                     \x20   public static function searchIndex(string $f): array {\n\
                     \x20       return DB::select(\"select * from t where a like '%{$f}%'\");\n\
                     \x20   }\n\
                     \x20   public static function byEmail(string $e): array {\n\
                     \x20       return DB::select('select * from t where e = ?', [$e]);\n\
                     \x20   }\n\
                     }\n",
                ),
            ],
            &["php"],
            None,
        )
        .await;
        // Only the interpolated query is a sink: the bound one on line 7
        // passes its value as a parameter, which `requires_dynamic_arg`
        // can finally see now that `scan::lite` answers it.
        assert_eq!(path_sinks(&seed), vec!["Gateway.php:4".to_string()]);
        assert_eq!(seed.unsafe_sinks.len(), 1);
    }

    #[tokio::test]
    async fn e2e_php_a_fixed_include_path_is_not_a_file_inclusion_sink() {
        let (_d, seed) = e2e(
            &[(
                "boot.php",
                "<?php\n\
                 function boot() {\n\
                 \x20   require __DIR__.'/vendor/autoload.php';\n\
                 }\n\
                 function render($name) {\n\
                 \x20   require '/srv/layouts/'.$name.'.phtml';\n\
                 }\n",
            )],
            &["php"],
            None,
        )
        .await;
        // A path built without a single variable in it is fixed, however
        // many literals it concatenates.
        let lines: Vec<i64> = seed.unsafe_sinks.iter().map(|s| s.line).collect();
        assert_eq!(lines, vec![6]);
    }

    #[tokio::test]
    async fn e2e_ruby_params_reach_an_interpolated_find_by_sql() {
        let (_d, seed) = e2e(
            &[
                (
                    "app/controllers/reports_controller.rb",
                    "class ReportsController < ApplicationController\n\
                     \x20 def search\n\
                     \x20   owner = params[:owner].to_s\n\
                     \x20   Report.matching_owner(owner)\n\
                     \x20 end\n\
                     end\n",
                ),
                (
                    "app/models/report.rb",
                    "class Report < ApplicationRecord\n\
                     \x20 def self.matching_owner(fragment)\n\
                     \x20   find_by_sql(\"SELECT * FROM reports WHERE owner LIKE '%#{fragment}%'\")\n\
                     \x20 end\n\
                     \x20 def self.owned_by(email)\n\
                     \x20   where('owner_email = ?', email)\n\
                     \x20 end\n\
                     end\n",
                ),
            ],
            &["ruby"],
            None,
        )
        .await;
        // `where('owner_email = ?', email)` on line 6 is the bound form
        // and must stay out of the sink set entirely.
        assert_eq!(
            path_sinks(&seed),
            vec!["app/models/report.rb:3".to_string()]
        );
        assert_eq!(seed.unsafe_sinks.len(), 1);
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-89".to_string()]);
    }

    #[tokio::test]
    async fn e2e_ruby_a_params_driven_public_send_is_a_dynamic_dispatch_sink() {
        let (_d, seed) = e2e(
            &[
                (
                    "app/controllers/ops_controller.rb",
                    "class OpsController < ApplicationController\n\
                     \x20 def summary\n\
                     \x20   metric = params[:metric].to_s\n\
                     \x20   Report.metric_value(metric)\n\
                     \x20 end\n\
                     end\n",
                ),
                (
                    "app/models/report.rb",
                    "class Report < ApplicationRecord\n\
                     \x20 def self.metric_value(name)\n\
                     \x20   public_send(name)\n\
                     \x20 end\n\
                     end\n",
                ),
            ],
            &["ruby"],
            None,
        )
        .await;
        assert_eq!(
            path_sinks(&seed),
            vec!["app/models/report.rb:3".to_string()]
        );
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-470".to_string()]);
    }

    #[tokio::test]
    async fn e2e_rust_an_axum_extractor_parameter_reaches_a_command() {
        // axum binds request input by destructuring an extractor in the
        // handler's own signature, so the source is a parameter pattern
        // rather than a call — the only place that binding is visible.
        let (_d, seed) = e2e(
            &[
                (
                    "handlers.rs",
                    "pub async fn rebuild(State(state): State<App>, Json(body): Json<Req>) -> Resp {\n\
                     \x20   let dataset = body.dataset.clone();\n\
                     \x20   service::queue_rebuild(&state, &dataset)\n\
                     }\n",
                ),
                (
                    "store.rs",
                    "pub fn queue_rebuild(state: &App, invocation: &str) -> Result<String, E> {\n\
                     \x20   let output = Command::new(\"sh\").arg(\"-c\").arg(invocation).output()?;\n\
                     \x20   Ok(String::from_utf8_lossy(&output.stdout).into_owned())\n\
                     }\n",
                ),
            ],
            &["rust"],
            None,
        )
        .await;
        assert_eq!(path_sinks(&seed), vec!["store.rs:2".to_string()]);
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-78".to_string()]);
        // `State` carries application state, not request input.
        assert_eq!(seed.entry_points.len(), 1);
    }

    #[tokio::test]
    async fn e2e_rust_a_bound_query_is_not_a_sql_sink() {
        let (_d, seed) = e2e(
            &[(
                "store.rs",
                "impl Db {\n\
                 \x20   pub fn unsafe_search(&self, team: &str) -> R {\n\
                 \x20       let sql = format!(\"SELECT * FROM t WHERE team = '{}'\", team);\n\
                 \x20       self.execute(&sql)\n\
                 \x20   }\n\
                 \x20   pub fn bound_lookup(&self, owner: &str) -> R {\n\
                 \x20       let sql = \"SELECT * FROM t WHERE owner = $1\";\n\
                 \x20       self.query_params(sql, &[owner])\n\
                 \x20   }\n\
                 }\n",
            )],
            &["rust"],
            None,
        )
        .await;
        let lines: Vec<i64> = seed.unsafe_sinks.iter().map(|s| s.line).collect();
        assert_eq!(lines, vec![4]);
    }

    // ── a script's top level is a caller too ─────────────────────────
    //
    // A statement at the top level of a file belongs to no function, so
    // it has no `FuncDef` and used to have no `fn_meta` entry — and the
    // inter-procedural walk gates on exactly that. A top-level source
    // could only ever pair with a sink in its own file, which is the
    // wrong answer for every script-shaped program there is.

    #[tokio::test]
    async fn e2e_php_a_top_level_superglobal_reaches_a_sink_two_files_away() {
        // The php-laravel app's own file-inclusion RCE: `$_GET` read by
        // a bare script, `require $path` two files away.
        let (_d, seed) = e2e(
            &[
                (
                    "legacy-export.php",
                    "<?php\n\
                     require __DIR__.'/vendor/autoload.php';\n\
                     $layout = $_GET['layout'];\n\
                     $reporting = new ReportingService();\n\
                     echo $reporting->renderLegacyLayout($layout);\n",
                ),
                (
                    "ReportingService.php",
                    "<?php\n\
                     class ReportingService {\n\
                     \x20   public function renderLegacyLayout(string $name): string {\n\
                     \x20       $path = self::ROOT.'/'.$name.'.phtml';\n\
                     \x20       require $path;\n\
                     \x20       return '';\n\
                     \x20   }\n\
                     }\n",
                ),
            ],
            &["php"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec![
                "legacy-export.php:3",
                "ReportingService.php:3",
                "ReportingService.php:5",
            ]]
        );
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-98".to_string()]);
        // The fixed `require __DIR__.'/vendor/autoload.php'` on line 2
        // is a constant path and must not be a sink at all.
        assert_eq!(seed.unsafe_sinks.len(), 1);
    }

    #[tokio::test]
    async fn e2e_python_a_top_level_script_reaches_a_helper_in_another_file() {
        let (_d, seed) = e2e(
            &[
                (
                    "run.py",
                    "from flask import request\n\
                     import helper\n\
                     \n\
                     target = request.args.get(\"t\")\n\
                     helper.run_cmd(target)\n",
                ),
                (
                    "helper.py",
                    "import os\n\
                     \n\
                     def run_cmd(c):\n\
                     \x20   os.system(\"sh -c \" + c)\n",
                ),
            ],
            &["python"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["run.py:4", "helper.py:3", "helper.py:4"]]
        );
        // The module scope grounds like any other caller: it has assign
        // and call-argument facts of its own.
        assert_eq!(
            transfer_kinds(&seed, 0),
            vec!["source", "arg_to_param", "local_to_sink"]
        );
        // A module is not a function, so it claims no definition span.
        assert!(seed.def_spans.keys().all(|k| !k.ends_with("::<module>")));
        assert!(seed.def_spans.contains_key("helper.py::run_cmd"));
    }

    // ── Kotlin / C / C++, end to end ─────────────────────────────────

    #[tokio::test]
    async fn e2e_kotlin_a_ktor_request_read_reaches_a_jvm_sink() {
        // Kotlin's sinks ARE the Java corpus's — same JVM APIs, same
        // names — but its request surface is Ktor's, which Java shares
        // nothing with. Kotlin also has no `new`, so `ProcessBuilder(…)`
        // is a bare call rather than a constructor.
        let (_d, seed) = e2e(
            &[
                (
                    "Routes.kt",
                    "suspend fun rebuild(call: ApplicationCall, service: ReportService) {\n\
                     \x20   val scope = call.request.queryParameters[\"scope\"] ?: \"all\"\n\
                     \x20   service.rebuildIndex(scope)\n\
                     }\n",
                ),
                (
                    "Repo.kt",
                    "class Repo {\n\
                     \x20   fun rebuildIndex(scope: String): String {\n\
                     \x20       val command = INDEXER_BIN + \" --scope=\" + scope\n\
                     \x20       return ProcessBuilder(\"sh\", \"-c\", command).start().toString()\n\
                     \x20   }\n\
                     }\n",
                ),
            ],
            &["kotlin"],
            None,
        )
        .await;
        assert_eq!(
            seed.taint_paths,
            vec![vec!["Routes.kt:2", "Repo.kt:2", "Repo.kt:4"]]
        );
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-78".to_string()]);
    }

    #[tokio::test]
    async fn e2e_kotlin_a_constant_template_query_is_bound() {
        // `"… LIMIT $PAGE_LIMIT"` is a template but not a composed
        // value: every hole is a `const val`, so the query is as fixed
        // as the literal it compiles to. Reading it as dynamic reports
        // the bound, parameterized query every JDBC tutorial teaches.
        let (_d, seed) = e2e(
            &[(
                "Repo.kt",
                "class Repo {\n\
                 \x20   fun bound(email: String) {\n\
                 \x20       val stmt = conn.prepareStatement(\"SELECT id FROM t WHERE e = ? LIMIT $PAGE_LIMIT\")\n\
                 \x20       stmt.setString(1, email)\n\
                 \x20       stmt.executeQuery()\n\
                 \x20   }\n\
                 \x20   fun built(fragment: String) {\n\
                 \x20       conn.createStatement().executeQuery(\"SELECT id FROM t WHERE e LIKE '%$fragment%'\")\n\
                 \x20   }\n\
                 }\n",
            )],
            &["kotlin"],
            None,
        )
        .await;
        // Only the interpolated query: the bound template is filtered by
        // its constant holes, and the argument-less `executeQuery()` by
        // `requires_any_arg`.
        let lines: Vec<i64> = seed.unsafe_sinks.iter().map(|s| s.line).collect();
        assert_eq!(lines, vec![8]);
    }

    #[tokio::test]
    async fn e2e_c_argv_reaches_a_shell_across_files() {
        let (_d, seed) = e2e(
            &[
                (
                    "main.c",
                    "int main(int argc, char **argv)\n\
                     {\n\
                     \x20   const char *target = argv[1];\n\
                     \x20   return util_run_archive(\"/srv/spool\", target);\n\
                     }\n",
                ),
                (
                    "util.c",
                    "int util_run_archive(const char *spool_dir, const char *target)\n\
                     {\n\
                     \x20   char command[512];\n\
                     \x20   snprintf(command, sizeof(command), \"/usr/bin/tar -C %s \", spool_dir);\n\
                     \x20   strcat(command, target);\n\
                     \x20   return system(command);\n\
                     }\n",
                ),
            ],
            &["c-cpp"],
            None,
        )
        .await;
        let sinks: Vec<(&str, i64)> = seed
            .unsafe_sinks
            .iter()
            .map(|s| (s.file.as_str(), s.line))
            .collect();
        // The bounded `snprintf` on line 4 is the SAFE alternative to
        // `sprintf` and is not an overflow sink; its format argument is
        // a literal, so it is not a format-string sink either.
        assert_eq!(sinks, vec![("util.c", 5), ("util.c", 6)]);
        let ends: Vec<&str> = seed
            .taint_paths
            .iter()
            .filter_map(|p| p.last().map(String::as_str))
            .collect();
        assert!(ends.contains(&"util.c:6"));
        assert!(ends.contains(&"util.c:5"));
    }

    #[tokio::test]
    async fn e2e_c_a_literal_format_is_not_a_format_string_sink() {
        // CWE-134 is about a format argument an attacker controls, and
        // the family puts it in a different position per function —
        // first for `printf`, second for `fprintf`, third for
        // `snprintf`. Without `dynamic_arg_index` every logging line in
        // a C program reports.
        let (_d, seed) = e2e(
            &[(
                "report.c",
                "void emit(struct report *rep, const char *message)\n\
                 {\n\
                 \x20   fprintf(rep->stream, message);\n\
                 \x20   fprintf(stderr, \"reportd: fixed notice\\n\");\n\
                 \x20   printf(\"%s\\n\", message);\n\
                 \x20   printf(message);\n\
                 }\n",
            )],
            &["c-cpp"],
            None,
        )
        .await;
        let lines: Vec<i64> = seed.unsafe_sinks.iter().map(|s| s.line).collect();
        assert_eq!(lines, vec![3, 6]);
    }

    #[tokio::test]
    async fn e2e_c_only_a_computed_allocation_size_is_an_overflow_sink() {
        // CWE-190: the corpus's `c.alloc-size-overflow` may name
        // `malloc` at all only because `requires_arithmetic_arg` can
        // tell a size that is COMPUTED at the call site from one that
        // is simply passed. Without it the rule would report every
        // allocation in the program, which is why `malloc` was absent
        // from the corpus before 2026-09-07.
        let (_d, seed) = e2e(
            &[(
                "alloc.c",
                "void *build(size_t count, size_t width, size_t len)\n\
                 {\n\
                 \x20   void *plain = malloc(len);\n\
                 \x20   void *fixed = malloc(sizeof(struct hdr));\n\
                 \x20   void *safe = calloc(count, width);\n\
                 \x20   void *grown = realloc(plain, len);\n\
                 \x20   void *wrapped = malloc(count * width);\n\
                 \x20   void *regrown = realloc(plain, count * width);\n\
                 \x20   return wrapped;\n\
                 }\n",
            )],
            &["c-cpp"],
            None,
        )
        .await;
        let hits: Vec<(i64, &str, &str)> = seed
            .unsafe_sinks
            .iter()
            .map(|s| {
                (
                    s.line,
                    s.snippet.as_str(),
                    s.cwe.first().map(String::as_str).unwrap_or(""),
                )
            })
            .collect();
        // `malloc(len)`, `malloc(sizeof(…))` and `realloc(p, len)` each
        // allocate exactly what they were asked for and cannot wrap.
        // `calloc(count, width)` is the SAFE idiom the corpus comment
        // explains: it multiplies internally under its own overflow
        // check, and flagging it would flag the recommended fix.
        assert_eq!(
            hits,
            vec![
                (7, "void *wrapped = malloc(count * width);", "CWE-190"),
                (
                    8,
                    "void *regrown = realloc(plain, count * width);",
                    "CWE-190"
                ),
            ]
        );
    }

    #[tokio::test]
    async fn e2e_cpp_only_a_computed_array_new_is_an_overflow_sink() {
        // C++'s `new T[n]` is a `new_expression`, not a call, and has
        // no argument list at all — the extractor reads the array
        // length as argument 0 under the name `operator_new_array`, so
        // the corpus's existing `c.alloc-size-overflow` predicate
        // covers it with no index of its own. The non-array forms
        // allocate exactly one object and are not allocations with a
        // size to wrap.
        let (_d, seed) = e2e(
            &[(
                "buf.cpp",
                "char *build(size_t count, size_t width)\n\
                 {\n\
                 \x20   int *plain = new int[count];\n\
                 \x20   Buffer *one = new Buffer(count * width);\n\
                 \x20   Buffer *bare = new Buffer;\n\
                 \x20   char *wrapped = new char[count * width];\n\
                 \x20   return wrapped;\n\
                 }\n",
            )],
            &["c-cpp"],
            None,
        )
        .await;
        let hits: Vec<(i64, &str, &str)> = seed
            .unsafe_sinks
            .iter()
            .map(|s| {
                (
                    s.line,
                    s.snippet.as_str(),
                    s.cwe.first().map(String::as_str).unwrap_or(""),
                )
            })
            .collect();
        assert_eq!(
            hits,
            vec![(6, "char *wrapped = new char[count * width];", "CWE-190")]
        );
    }

    #[tokio::test]
    async fn e2e_c_only_a_hand_multiplied_calloc_is_an_overflow_sink() {
        // `calloc` is out of `c.alloc-size-overflow` because
        // `calloc(n, size)` is the fix a reviewer recommends. The one
        // shape that throws that protection away — the caller does the
        // multiply and passes an element size of `1`, so `calloc`'s own
        // overflow check multiplies by one — has its own rule, which
        // states BOTH halves as argument predicates and so stays narrow
        // enough to leave every idiomatic call alone.
        let (_d, seed) = e2e(
            &[(
                "zero.c",
                "void *build(size_t count, size_t width, size_t len)\n\
                 {\n\
                 \x20   void *safe = calloc(count, width);\n\
                 \x20   void *str = calloc(len + 1, sizeof(char));\n\
                 \x20   void *one = calloc(1, sizeof(struct hdr));\n\
                 \x20   void *bytes = calloc(count, 1);\n\
                 \x20   void *defeated = calloc(count * width, 1);\n\
                 \x20   return defeated;\n\
                 }\n",
            )],
            &["c-cpp"],
            None,
        )
        .await;
        let hits: Vec<(i64, &str, &str)> = seed
            .unsafe_sinks
            .iter()
            .map(|s| {
                (
                    s.line,
                    s.snippet.as_str(),
                    s.cwe.first().map(String::as_str).unwrap_or(""),
                )
            })
            .collect();
        assert_eq!(
            hits,
            vec![(7, "void *defeated = calloc(count * width, 1);", "CWE-190")]
        );
    }

    #[tokio::test]
    async fn e2e_c_an_arithmetic_alloca_keeps_the_more_precise_cwe() {
        // `alloca` is named by BOTH `c.alloc-size-overflow` (CWE-190)
        // and `c.unbounded-copy` (CWE-787), and first match wins. The
        // corpus orders the arithmetic rule first on purpose: a
        // computed `alloca` size is an integer overflow, while a bare
        // one is an unbounded stack allocation, and each keeps its own
        // class.
        let (_d, seed) = e2e(
            &[(
                "stack.c",
                "void f(size_t n, size_t m, size_t len)\n\
                 {\n\
                 \x20   char *a = alloca(n * m);\n\
                 \x20   char *b = alloca(len);\n\
                 }\n",
            )],
            &["c-cpp"],
            None,
        )
        .await;
        let hits: Vec<(i64, &str)> = seed
            .unsafe_sinks
            .iter()
            .map(|s| (s.line, s.cwe.first().map(String::as_str).unwrap_or("")))
            .collect();
        assert_eq!(hits, vec![(3, "CWE-190"), (4, "CWE-787")]);
    }

    #[tokio::test]
    async fn e2e_cpp_a_method_and_a_namespaced_call_are_call_sites() {
        // C++ shares C's language key and grammar. `obj.method(x)`,
        // `ptr->method(y)` and `ns::fn(z)` are the three shapes C does
        // not have.
        let (_d, seed) = e2e(
            &[(
                "app.cpp",
                "int run(int argc, char **argv)\n\
                 {\n\
                 \x20   const char *cmd = argv[1];\n\
                 \x20   std::system(cmd);\n\
                 \x20   logger.write(cmd);\n\
                 \x20   sink->consume(cmd);\n\
                 \x20   return 0;\n\
                 }\n",
            )],
            &["c-cpp"],
            None,
        )
        .await;
        assert_eq!(seed.unsafe_sinks.len(), 1);
        assert_eq!(seed.unsafe_sinks[0].line, 4);
        assert_eq!(seed.unsafe_sinks[0].cwe, vec!["CWE-78".to_string()]);
        assert_eq!(seed.taint_paths, vec![vec!["app.cpp:3", "app.cpp:4"]]);
    }

    fn write_source_yaml(dir: &Path) -> PathBuf {
        let path = dir.join("sources.yaml");
        std::fs::write(
            &path,
            r#"
rules:
  - id: py-net-source
    languages: [python]
    metadata:
      vvah-role: source
      vvah-ep-kind: network
      cwe: "CWE-20"
    patterns:
      - pattern: request.args.get(...)
"#,
        )
        .unwrap();
        path
    }

    fn write_sink_yaml(dir: &Path) -> PathBuf {
        let path = dir.join("sinks.yaml");
        std::fs::write(
            &path,
            r#"
rules:
  - id: py-cmd-sink
    languages: [python]
    metadata:
      vvah-role: sink
      vvah-sink-kind: command
      cwe: "CWE-78"
    patterns:
      - pattern: os.system(...)
"#,
        )
        .unwrap();
        path
    }

    #[tokio::test]
    async fn run_callgraph_engine_empty_when_zero_rules_apply_to_active_langs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sources.yaml");
        // The only rule here targets java; the only plugin-supported
        // language is python, so `load_rulepacks` succeeds but filters
        // this rule out entirely, leaving 0 applicable specs.
        std::fs::write(
            &path,
            r#"
rules:
  - id: java-net-source
    languages: [java]
    metadata:
      vvah-role: source
      vvah-ep-kind: network
      cwe: "CWE-20"
    patterns:
      - pattern: request.getParameter(...)
"#,
        )
        .unwrap();
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: Some(path),
            sinks_yaml: None,
            call_graph_max_targets: 3,
            llm: None,
        };
        let seed =
            run_callgraph_engine(dir.path(), &BTreeSet::new(), &["python"], &config, None).await;
        assert!(!seed.has_content());
        assert_eq!(seed.languages, vec!["python".to_string()]);
    }

    #[tokio::test]
    async fn run_callgraph_engine_rules_mode_builds_a_real_seed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.py"),
            "def handler():\n    cmd = request.args.get('cmd')\n    os.system(cmd)\n",
        )
        .unwrap();
        let sources = write_source_yaml(dir.path());
        let sinks = write_sink_yaml(dir.path());
        let mut in_scope = BTreeSet::new();
        in_scope.insert("app.py".to_string());
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: Some(sources),
            sinks_yaml: Some(sinks),
            call_graph_max_targets: 3,
            llm: None,
        };
        let seed = run_callgraph_engine(dir.path(), &in_scope, &["python"], &config, None).await;
        assert!(seed.has_content());
        assert_eq!(seed.engine, "callgraph");
        assert_eq!(seed.languages, vec!["python".to_string()]);
        assert!(!seed.unsafe_sinks.is_empty());
    }

    #[tokio::test]
    async fn run_callgraph_engine_empty_when_no_files_in_scope_match() {
        let dir = tempfile::tempdir().unwrap();
        let sources = write_source_yaml(dir.path());
        let sinks = write_sink_yaml(dir.path());
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: Some(sources),
            sinks_yaml: Some(sinks),
            call_graph_max_targets: 3,
            llm: None,
        };
        // Applicable rules exist, but nothing is in scope to scan.
        let seed =
            run_callgraph_engine(dir.path(), &BTreeSet::new(), &["python"], &config, None).await;
        assert!(!seed.has_content());
        assert_eq!(seed.engine, "callgraph");
    }

    #[tokio::test]
    async fn run_callgraph_engine_rule_load_failure_returns_empty_seed() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("sources.yaml");
        // `load_rulepacks` only errors when the YAML document's top level
        // isn't a mapping (a `rules:` key with the wrong value shape is
        // tolerated as "no rules", not an error) — a bare top-level list
        // is what actually triggers `RulesError`.
        std::fs::write(&bad, "- 1\n- 2\n").unwrap();
        let config = EngineConfig {
            detection_mode: DetectionMode::Rules,
            sources_yaml: Some(bad),
            sinks_yaml: None,
            call_graph_max_targets: 3,
            llm: None,
        };
        let seed =
            run_callgraph_engine(dir.path(), &BTreeSet::new(), &["python"], &config, None).await;
        assert!(!seed.has_content());
    }
}
