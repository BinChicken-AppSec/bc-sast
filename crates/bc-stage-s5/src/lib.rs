//! S5 — Deterministic pre-filter, run between S4 deep-dive and S6 verify.
//! Cuts obvious false-positives (test/mock paths, hallucinated file paths,
//! low-confidence findings, missing source/sink evidence) mechanically so
//! the expensive adversarial verifier isn't burned on findings that can be
//! rejected without a model call, then applies S7's deterministic trivial-
//! dup pre-filter, then — only once survivors reach
//! `config.pre_verify_threshold` — S7's full semantic dedup pass. Ported
//! from `vvaharness/pipeline/stages/s5_prefilter.py`.
//!
//! Depends directly on `bc-stage-s7` rather than duplicating its dedup
//! logic, mirroring the Python original's own `from . import s7_dedup`.
//!
//! This stage has no *direct* internal degrade policy of its own — but it
//! inherits one transitively: when `run_prefilter` reaches the semantic
//! pre-verify pass, it calls straight into `bc_stage_s7::run_dedup`, whose
//! own non-fatal LLM-failure handling (see that crate's docs) surfaces
//! here as `StageOutcome::Degraded` too, exactly as it does for S7 itself.

mod backfill;
mod gates;
/// Public only so `bc-stage-s6` can hold its LANGUAGE FACTS prompt block
/// and these gates to the same claims: the two halves of the JS-race and
/// template-escaping rules must not disagree, and the test that proves it
/// has to run one of them. Nothing in the pipeline calls into it from
/// outside this crate.
pub mod lang_gates;
/// Public for the same reason as [`lang_gates`]: `bc-stage-s6`'s
/// LANGUAGE FACTS state in prose what this gate decides mechanically —
/// a route the framework guards HAS an authorization check — and the
/// test that holds the two to the same claim has to run the gate.
pub mod route_gates;

use std::collections::HashSet;

use bc_llm_client::LlmClient;
use bc_model::{ContextPackage, Finding};
use bc_pipeline_core::{PipelineStage, StageError, StageOutcome};
use bc_stage_s7::{DedupOutput, Step7Config};

pub struct Step5Config {
    pub min_pre_confidence: f64,
    pub require_evidence: bool,
    /// `0` disables the semantic pre-verify pass entirely, matching the
    /// Python original's falsy-threshold check.
    pub pre_verify_threshold: usize,
    /// `false` disables the AST/call-graph evidence backfill pass
    /// entirely, matching Python's `step5_prefilter.ast_backfill_evidence`
    /// (default `true`).
    pub ast_backfill: bool,
    /// Shared with S7 (`step7_dedup` in the Python config) — `dedup.model`
    /// is the model role S5's own semantic pre-verify call uses too.
    pub dedup: Step7Config,
}

impl Step5Config {
    pub fn new(dedup_model: impl Into<String>) -> Self {
        Step5Config {
            min_pre_confidence: 0.6,
            require_evidence: true,
            pre_verify_threshold: 25,
            ast_backfill: true,
            dedup: Step7Config::new(dedup_model),
        }
    }
}

pub struct Step5Input {
    pub findings: Vec<Finding>,
    pub ctx: ContextPackage,
}

/// The full S5 sequence: deterministic gates, then AST/call-graph evidence
/// backfill on the survivors, then S7's deterministic pre-filter, then —
/// only above `config.pre_verify_threshold` survivors — S7's full semantic
/// dedup. A semantic-dedup dropped finding's `canonical_idx` is cleared
/// and its `detail` prefixed with `"pre-verify semantic: "`, matching the
/// Python original: the index would point into this pre-verify list,
/// which goes stale once S6 drops false positives and S7 re-dedups for
/// real, so only the reasoning survives.
pub async fn run_prefilter(
    client: &dyn LlmClient,
    input: &Step5Input,
    config: &Step5Config,
) -> (DedupOutput, Option<String>) {
    let valid_files: Option<HashSet<&str>> = if input.ctx.all_files.is_empty() {
        None
    } else {
        Some(input.ctx.all_files.iter().map(String::as_str).collect())
    };

    let routes = route_gates::RouteIndex::new(&input.ctx.entry_points);
    {
        // Diagnostics for the live pipeline: how many framework routes the
        // gate can see, and how many of them are guarded. A 2026-09-07 run
        // showed zero route-gate drops while the same code fired offline.
        let total = input.ctx.entry_points.len();
        let (framework, guarded) = routes.counts();
        tracing::info!(
            total,
            framework,
            guarded,
            "[s5] route gate index built from the context's entry points"
        );
    }
    let gate_result = gates::apply_gates(
        &input.findings,
        valid_files.as_ref(),
        config.min_pre_confidence,
        config.require_evidence,
        // The language gates read the finding's real lines when they can;
        // an empty `repo_root` (every non-repo test fixture) falls back to
        // the model's own snippet.
        (!input.ctx.repo_root.is_empty())
            .then(|| std::path::Path::new(input.ctx.repo_root.as_str())),
        &routes,
    );
    let mut dropped = gate_result.dropped;
    let mut survivors = gate_result.keep;

    if config.ast_backfill {
        let index = backfill::BackfillIndex::new(&input.ctx);
        backfill::backfill_all(&mut survivors, &index);
    }

    // Deliberately runs the same-range CWE merge here and not only in S7:
    // every lens this collapses pre-verify is a whole S6 verification
    // session (a multi-turn agentic run) that never has to happen.
    let (mut keep, dup_dropped) = bc_stage_s7::prefilter(
        &survivors,
        config.dedup.line_tolerance,
        config.dedup.merge_same_range_cwes,
        config.dedup.merge_same_sink,
    );
    dropped.extend(dup_dropped);

    let mut degraded_reason = None;
    if config.pre_verify_threshold > 0
        && keep.len() >= config.pre_verify_threshold
        && config.dedup.semantic
    {
        let (sem_output, reason) =
            bc_stage_s7::run_dedup(client, &keep, &config.dedup, &input.ctx).await;
        keep = sem_output.findings;
        for mut d in sem_output.dropped {
            d.canonical_idx = None;
            d.detail = format!("pre-verify semantic: {}", d.detail);
            dropped.push(d);
        }
        degraded_reason = reason;
    }

    (
        DedupOutput {
            findings: keep,
            dropped,
        },
        degraded_reason,
    )
}

pub struct Stage5 {
    client: std::sync::Arc<dyn LlmClient>,
    config: Step5Config,
}

impl Stage5 {
    pub fn new(client: std::sync::Arc<dyn LlmClient>, config: Step5Config) -> Self {
        Stage5 { client, config }
    }
}

impl PipelineStage for Stage5 {
    type Input = Step5Input;
    type Output = DedupOutput;
    const NAME: &'static str = "s5-prefilter";

    async fn run(&self, input: Step5Input) -> Result<StageOutcome<DedupOutput>, StageError> {
        let (output, degraded_reason) =
            run_prefilter(self.client.as_ref(), &input, &self.config).await;
        match degraded_reason {
            Some(reason) => Ok(StageOutcome::Degraded {
                value: output,
                reason,
            }),
            None => Ok(StageOutcome::Ok(output)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bc_llm_client::{ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, Usage};
    use bc_model::VulnClass;

    struct ScriptedClient {
        reply: String,
    }

    #[async_trait]
    impl LlmClient for ScriptedClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(self.reply.clone())],
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
                message: "boom".to_string(),
            })
        }
    }

    fn finding(file: &str, line: i64, confidence: f64) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            chunk_id: "c".to_string(),
            file: file.to_string(),
            line_start: line,
            line_end: line,
            vuln_class: VulnClass::Injection,
            cwe: None,
            title: "t".to_string(),
            impact: String::new(),
            description: "d".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "x".to_string(),
            // Real `file:line` refs, not placeholders: the trivial dedup
            // this stage runs now has a flow-identity tier
            // (`bc_dedup_core::collapse_trivial`), so two findings sharing
            // one literal `"src"`/`"sink"` pair would be the same flow and
            // collapse — which is correct behaviour, and exactly what a
            // fixture must not accidentally trigger.
            source_ref: Some(format!("{file}:{line}")),
            sink_ref: Some(format!("{file}:{line}")),
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence,
            votes: 1,
            duplicates: Vec::new(),
            verdict: None,
            verdict_confidence: None,
            verdict_reason: String::new(),
            cvss_vector: None,
            cvss_score: None,
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

    #[tokio::test]
    async fn gates_and_trivial_dedup_run_without_any_llm_call_below_threshold() {
        let findings = vec![
            finding("a.rs", 10, 0.9),
            finding("a.rs", 11, 0.9),
            finding("tests/x.py", 1, 0.9),
        ];
        let input = Step5Input {
            findings,
            ctx: ContextPackage::default(),
        };
        let (out, reason) = run_prefilter(&FailingClient, &input, &Step5Config::new("m")).await;
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.dropped.len(), 2);
        assert!(reason.is_none());
    }

    /// The 2026-09-06 Juice Shop `routes/captcha.ts:11` false positive,
    /// end to end and read from a real file rather than the model's
    /// snippet — the path `run_prefilter` takes whenever `ctx.repo_root`
    /// points at an actual checkout.
    #[tokio::test]
    async fn a_synchronous_typescript_race_is_gated_out_using_the_real_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("routes")).unwrap();
        std::fs::write(
            dir.path().join("routes/captcha.ts"),
            "module.exports = function captcha () {\n             \x20 return (req, res) => {\n             \x20   const captchaId = req.app.locals.captchaId++\n             \x20   res.json({ captchaId })\n             \x20 }\n             }\n",
        )
        .unwrap();

        let mut race = finding("routes/captcha.ts", 3, 0.9);
        race.vuln_class = VulnClass::RaceCondition;
        race.cwe = Some("CWE-362".to_string());
        // Deliberately blank, so only the real file read can settle this.
        race.code_snippet = String::new();
        let unrelated = finding("routes/order.ts", 42, 0.9);

        let input = Step5Input {
            findings: vec![race, unrelated],
            ctx: ContextPackage {
                repo_root: dir.path().to_string_lossy().to_string(),
                ..Default::default()
            },
        };
        let (out, _) = run_prefilter(&FailingClient, &input, &Step5Config::new("m")).await;
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].file, "routes/order.ts");
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].reason, bc_model::DropReason::Excluded);
        assert_eq!(out.dropped[0].detail, "synchronous JS/TS code cannot race");
    }

    #[tokio::test]
    async fn ast_backfill_fills_a_missing_sink_ref_before_trivial_dedup_runs() {
        // `require_evidence: false` so this finding survives the gate chain
        // despite a missing sink_ref — matching Python's own comment that
        // the evidence gate judges a finding's OWN refs; backfill only
        // decorates survivors, it never satisfies that gate itself.
        let mut f = finding("a.rs", 10, 0.9);
        f.sink_ref = None;
        let mut cfg = Step5Config::new("m");
        cfg.require_evidence = false;
        let input = Step5Input {
            findings: vec![f],
            ctx: ContextPackage::default(),
        };
        let (out, _) = run_prefilter(&FailingClient, &input, &cfg).await;
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].sink_ref, Some("a.rs:10".to_string()));
        assert_eq!(
            out.findings[0].backfilled_refs,
            vec!["sink_ref".to_string()]
        );
    }

    #[tokio::test]
    async fn ast_backfill_disabled_leaves_missing_refs_untouched() {
        let mut f = finding("a.rs", 10, 0.9);
        f.sink_ref = None;
        let mut cfg = Step5Config::new("m");
        cfg.require_evidence = false;
        cfg.ast_backfill = false;
        let input = Step5Input {
            findings: vec![f],
            ctx: ContextPackage::default(),
        };
        let (out, _) = run_prefilter(&FailingClient, &input, &cfg).await;
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].sink_ref, None);
        assert!(out.findings[0].backfilled_refs.is_empty());
    }

    #[tokio::test]
    async fn semantic_pre_verify_fires_once_survivors_reach_the_threshold() {
        let findings: Vec<Finding> = (0..3)
            .map(|i| finding(&format!("f{i}.rs"), i * 100, 0.9))
            .collect();
        let mut cfg = Step5Config::new("m");
        cfg.pre_verify_threshold = 3;
        let reply = "index=0 is_duplicate=false canonical=-1 reasoning=\"a\"\n\
                     index=1 is_duplicate=true canonical=0 reasoning=\"shared\"\n\
                     index=2 is_duplicate=false canonical=-1 reasoning=\"b\"\n";
        let input = Step5Input {
            findings,
            ctx: ContextPackage::default(),
        };
        let (out, reason) = run_prefilter(
            &ScriptedClient {
                reply: reply.to_string(),
            },
            &input,
            &cfg,
        )
        .await;
        assert_eq!(out.findings.len(), 2);
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].canonical_idx, None);
        assert_eq!(out.dropped[0].detail, "pre-verify semantic: shared");
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn below_threshold_never_calls_the_semantic_pass() {
        let findings: Vec<Finding> = (0..3)
            .map(|i| finding(&format!("f{i}.rs"), i * 100, 0.9))
            .collect();
        let mut cfg = Step5Config::new("m");
        cfg.pre_verify_threshold = 10;
        let input = Step5Input {
            findings,
            ctx: ContextPackage::default(),
        };
        let (out, reason) = run_prefilter(&FailingClient, &input, &cfg).await;
        assert_eq!(out.findings.len(), 3);
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn zero_threshold_disables_the_semantic_pass_even_with_many_survivors() {
        let findings: Vec<Finding> = (0..30)
            .map(|i| finding(&format!("f{i}.rs"), i * 100, 0.9))
            .collect();
        let mut cfg = Step5Config::new("m");
        cfg.pre_verify_threshold = 0;
        let input = Step5Input {
            findings,
            ctx: ContextPackage::default(),
        };
        let (out, reason) = run_prefilter(&FailingClient, &input, &cfg).await;
        assert_eq!(out.findings.len(), 30);
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn semantic_disabled_in_dedup_config_skips_the_pass() {
        let findings: Vec<Finding> = (0..3)
            .map(|i| finding(&format!("f{i}.rs"), i * 100, 0.9))
            .collect();
        let mut cfg = Step5Config::new("m");
        cfg.pre_verify_threshold = 3;
        cfg.dedup.semantic = false;
        let input = Step5Input {
            findings,
            ctx: ContextPackage::default(),
        };
        let (out, reason) = run_prefilter(&FailingClient, &input, &cfg).await;
        assert_eq!(out.findings.len(), 3);
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn semantic_pass_failure_degrades_but_keeps_deterministic_results() {
        let findings: Vec<Finding> = (0..3)
            .map(|i| finding(&format!("f{i}.rs"), i * 100, 0.9))
            .collect();
        let mut cfg = Step5Config::new("m");
        cfg.pre_verify_threshold = 3;
        cfg.dedup.retry_backoff_base = std::time::Duration::ZERO;
        let input = Step5Input {
            findings,
            ctx: ContextPackage::default(),
        };
        let (out, reason) = run_prefilter(&FailingClient, &input, &cfg).await;
        assert_eq!(out.findings.len(), 3);
        assert!(reason.unwrap().contains("semantic dedup call failed"));
    }

    #[tokio::test]
    async fn file_inventory_gate_uses_the_supplied_all_files_list() {
        let findings = vec![finding("known.rs", 1, 0.9), finding("unknown.rs", 2, 0.9)];
        let input = Step5Input {
            findings,
            ctx: ContextPackage {
                all_files: vec!["known.rs".to_string()],
                ..Default::default()
            },
        };
        let (out, _) = run_prefilter(&FailingClient, &input, &Step5Config::new("m")).await;
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].file, "known.rs");
    }

    #[tokio::test]
    async fn stage5_run_wraps_a_successful_prefilter_as_ok() {
        let findings = vec![finding("a.rs", 10, 0.9)];
        let stage = Stage5::new(std::sync::Arc::new(FailingClient), Step5Config::new("m"));
        let outcome = stage
            .run(Step5Input {
                findings,
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
        assert_eq!(outcome.into_value().findings.len(), 1);
    }

    #[tokio::test]
    async fn stage5_run_wraps_a_semantic_failure_as_degraded() {
        let findings: Vec<Finding> = (0..3)
            .map(|i| finding(&format!("f{i}.rs"), i * 100, 0.9))
            .collect();
        let mut cfg = Step5Config::new("m");
        cfg.pre_verify_threshold = 3;
        cfg.dedup.retry_backoff_base = std::time::Duration::ZERO;
        let stage = Stage5::new(std::sync::Arc::new(FailingClient), cfg);
        let outcome = stage
            .run(Step5Input {
                findings,
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert!(outcome.is_degraded());
    }
}
