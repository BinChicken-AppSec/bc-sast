mod clustering;
mod parse;
mod semantic;

use std::collections::HashMap;

use appsec_dedup_core::CanonicalOf;
use appsec_llm_client::LlmClient;
use appsec_model::{ContextPackage, DropReason, DroppedFinding, Finding};
use appsec_pipeline_core::{PipelineStage, StageError, StageOutcome};

pub use clustering::prefilter;

pub struct Step7Input {
    pub findings: Vec<Finding>,
    pub ctx: ContextPackage,
}

pub struct Step7Config {
    pub model: String,
    pub line_tolerance: i64,
    pub semantic: bool,
    pub merge_same_range_cwes: bool,
    pub merge_same_sink: bool,
    pub max_tokens: u32,
    pub max_transient_retries: u32,
    pub retry_backoff_base: std::time::Duration,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
    pub reasoning_effort: Option<appsec_llm_client::ReasoningEffort>,
    pub openai_api: Option<appsec_llm_client::OpenAiApi>,
    pub timeout_secs: Option<u64>,
    pub budget_gate: Option<appsec_pipeline_core::BudgetGateRef>,
}

impl Step7Config {
    pub fn new(model: impl Into<String>) -> Self {
        Step7Config {
            model: model.into(),
            line_tolerance: 3,
            semantic: true,
            merge_same_range_cwes: true,
            merge_same_sink: true,
            max_tokens: 64_000,
            max_transient_retries: 4,
            retry_backoff_base: std::time::Duration::from_secs(10),
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: None,
            openai_api: None,
            timeout_secs: None,
            budget_gate: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct DedupOutput {
    pub findings: Vec<Finding>,
    pub dropped: Vec<DroppedFinding>,
}

pub(crate) fn sort_for_stable_canonical(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        sink_anchor_rank(a)
            .cmp(&sink_anchor_rank(b))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line_start.cmp(&b.line_start))
            .then_with(|| severity_key(b).cmp(&severity_key(a)))
            .then_with(|| a.vuln_class.as_str().cmp(b.vuln_class.as_str()))
            .then_with(|| cwe_rank(a).cmp(&cwe_rank(b)))
            .then_with(|| b.verdict_confidence.cmp(&a.verdict_confidence))
            .then_with(|| b.confidence.total_cmp(&a.confidence))
            .then_with(|| a.title.cmp(&b.title))
    });
}

const GENERIC_CWES: &[u32] = &[
    20, 74, 200, 284, 285, 664, 682, 691, 693, 697, 703, 707, 710,
];

fn cwe_rank(f: &Finding) -> (u8, u32) {
    match appsec_dedup_core::cwe_number(f.cwe.as_deref()) {
        Some(n) => (u8::from(GENERIC_CWES.contains(&n)), n),
        None => (2, u32::MAX),
    }
}

fn sink_anchor_rank(f: &Finding) -> u8 {
    let (Some(_), Some(sink)) = (
        appsec_dedup_core::normalize_ref(f.source_ref.as_deref()),
        appsec_dedup_core::normalize_ref(f.sink_ref.as_deref()),
    ) else {
        return 1;
    };
    let sink_file = sink.rsplit_once(':').map_or(sink.as_str(), |(p, _)| p);
    match appsec_dedup_core::normalize_ref(Some(sink_file)) {
        Some(sink_file)
            if Some(&sink_file) == appsec_dedup_core::normalize_ref(Some(&f.file)).as_ref() =>
        {
            0
        }
        _ => 1,
    }
}

fn severity_key(f: &Finding) -> Option<i64> {
    f.cvss_score.map(|s| (s * 100.0).round() as i64)
}

pub async fn run_dedup(
    client: &dyn LlmClient,
    verified: &[Finding],
    config: &Step7Config,
    ctx: &ContextPackage,
) -> (DedupOutput, Option<String>) {
    if verified.len() <= 1 {
        return (
            DedupOutput {
                findings: verified.to_vec(),
                dropped: Vec::new(),
            },
            None,
        );
    }

    let mut findings = verified.to_vec();
    sort_for_stable_canonical(&mut findings);
    let (mut canonical_of, mut reasoning): (CanonicalOf, HashMap<usize, String>) =
        clustering::deterministic_passes(
            &findings,
            config.line_tolerance,
            config.merge_same_range_cwes,
            config.merge_same_sink,
        );

    let unresolved: Vec<usize> = (0..findings.len())
        .filter(|i| !canonical_of.contains_key(i))
        .collect();
    let mut degraded_reason = None;

    let budget_stop = config
        .budget_gate
        .as_ref()
        .filter(|gate| gate.should_stop())
        .map(|gate| gate.stop_reason());

    if unresolved.len() >= 2 && config.semantic && budget_stop.is_none() {
        let view = appsec_repo_analysis::GraphView::new(ctx);
        match semantic::semantic_dedup(client, &findings, &unresolved, config, ctx, &view).await {
            Ok(merges) => {
                for (local_idx, local_canon, why) in merges {
                    let g_idx = unresolved[local_idx];
                    let g_canon = unresolved[local_canon];
                    if !canonical_of.contains_key(&g_idx) && g_canon < g_idx {
                        canonical_of.insert(g_idx, g_canon);
                        reasoning.insert(g_idx, why);
                    }
                }
            }
            Err(e) => {
                degraded_reason = Some(format!("semantic dedup call failed (non-fatal): {e}"));
            }
        }
    } else if let Some(reason) = budget_stop {
        if unresolved.len() >= 2 && config.semantic {
            degraded_reason = Some(format!("semantic dedup skipped: {reason}"));
        }
    }

    clustering::promote_anchored_representatives(&mut findings, &canonical_of);
    clustering::attach_duplicates(&mut findings, &canonical_of, &reasoning);

    let partition = appsec_dedup_core::partition(findings.len(), &canonical_of);
    let canonical: Vec<Finding> = partition
        .kept_indices
        .iter()
        .map(|&i| findings[i].clone())
        .collect();
    let dropped: Vec<DroppedFinding> = partition
        .dropped_indices
        .iter()
        .map(|&i| {
            let r = appsec_dedup_core::root(&canonical_of, i);
            DroppedFinding {
                file: findings[i].file.clone(),
                line: findings[i].line_start,
                vuln_class: findings[i].vuln_class,
                title: findings[i].title.clone(),
                chunk_id: findings[i].chunk_id.clone(),
                reason: DropReason::Duplicate,
                detail: reasoning[&i].clone(),
                canonical_idx: partition.new_index_of.get(&r).map(|&x| x as i64),
                provider_origins: findings[i].provider_origins.clone(),
                verification: appsec_model::VerificationEvidence::from_finding(&findings[i]),
            }
        })
        .collect();

    (
        DedupOutput {
            findings: canonical,
            dropped,
        },
        degraded_reason,
    )
}

pub struct Stage7 {
    client: std::sync::Arc<dyn LlmClient>,
    config: Step7Config,
}

impl Stage7 {
    pub fn new(client: std::sync::Arc<dyn LlmClient>, config: Step7Config) -> Self {
        Stage7 { client, config }
    }
}

impl PipelineStage for Stage7 {
    type Input = Step7Input;
    type Output = DedupOutput;
    const NAME: &'static str = "s7-dedup";

    async fn run(&self, input: Step7Input) -> Result<StageOutcome<DedupOutput>, StageError> {
        let (output, degraded_reason) = run_dedup(
            self.client.as_ref(),
            &input.findings,
            &self.config,
            &input.ctx,
        )
        .await;
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
    use appsec_llm_client::{ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, Usage};
    use appsec_model::VulnClass;
    use async_trait::async_trait;

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

    struct RetryingClient {
        fail_times: std::sync::atomic::AtomicU32,
    }

    impl RetryingClient {
        fn new(fail_times: u32) -> Self {
            RetryingClient {
                fail_times: std::sync::atomic::AtomicU32::new(fail_times),
            }
        }
    }

    #[async_trait]
    impl LlmClient for RetryingClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            if self.fail_times.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                self.fail_times
                    .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                return Err(LlmError::ServerError {
                    status: 503,
                    message: "down".to_string(),
                });
            }
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(String::new())],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    fn finding(file: &str, line: i64, vc: VulnClass, title: &str) -> Finding {
        Finding {
            provider_origins: Vec::new(),
            component: None,
            chunk_id: "c".to_string(),
            file: file.to_string(),
            line_start: line,
            line_end: line,
            vuln_class: vc,
            cwe: None,
            title: title.to_string(),
            impact: String::new(),
            description: "d".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "x".to_string(),
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
    async fn one_range_under_several_cwes_becomes_one_finding_carrying_the_others() {
        let mut hardcoded = finding(
            "routes/continueCode.ts",
            13,
            VulnClass::Other,
            "Hardcoded salt",
        );
        hardcoded.line_end = 13;
        hardcoded.cwe = Some("CWE-798".to_string());
        let mut inconsistent = finding(
            "routes/continueCode.ts",
            12,
            VulnClass::Other,
            "Inconsistent salt",
        );
        inconsistent.line_end = 21;
        inconsistent.cwe = Some("CWE-345".to_string());
        let mut authz = finding(
            "routes/continueCode.ts",
            12,
            VulnClass::Other,
            "Missing authorization",
        );
        authz.line_end = 21;
        authz.cwe = Some("CWE-284".to_string());
        let mut exposure = finding(
            "routes/continueCode.ts",
            12,
            VulnClass::InfoLeak,
            "Information exposure",
        );
        exposure.line_end = 21;
        exposure.cwe = Some("CWE-200".to_string());
        exposure.cvss_score = Some(7.5);

        let mut cfg = Step7Config::new("m");
        cfg.semantic = false;
        let (out, _) = run_dedup(
            &FailingClient,
            &[hardcoded, inconsistent, authz, exposure],
            &cfg,
            &ContextPackage::default(),
        )
        .await;

        assert_eq!(out.findings.len(), 2, "4 findings become 2");
        let merged = out
            .findings
            .iter()
            .find(|f| f.line_end == 21)
            .expect("the 12-21 cluster survives");
        assert_eq!(merged.cwe.as_deref(), Some("CWE-200"));
        assert_eq!(merged.title, "Information exposure");
        assert_eq!(merged.vuln_class, VulnClass::InfoLeak);
        assert_eq!(
            merged.related_cwes,
            vec!["CWE-345".to_string(), "CWE-284".to_string()],
            "no lens is lost"
        );
        assert!(out
            .findings
            .iter()
            .any(|f| f.cwe.as_deref() == Some("CWE-798") && f.related_cwes.is_empty()));
        assert_eq!(out.dropped.len(), 2);
        assert!(out
            .dropped
            .iter()
            .all(|d| d.detail == clustering::SAME_RANGE_CWE_REASON));
    }

    #[tokio::test]
    async fn the_same_range_cwe_merge_can_be_switched_off() {
        let mut a = finding("routes/continueCode.ts", 12, VulnClass::Other, "a");
        a.line_end = 21;
        a.cwe = Some("CWE-345".to_string());
        let mut b = finding("routes/continueCode.ts", 12, VulnClass::Other, "b");
        b.line_end = 21;
        b.cwe = Some("CWE-284".to_string());

        let mut cfg = Step7Config::new("m");
        cfg.semantic = false;
        cfg.merge_same_range_cwes = false;
        let (out, _) = run_dedup(&FailingClient, &[a, b], &cfg, &ContextPackage::default()).await;
        assert_eq!(out.findings.len(), 2);
        assert!(out.findings.iter().all(|f| f.related_cwes.is_empty()));
    }

    #[tokio::test]
    async fn one_flow_reported_from_both_ends_collapses_onto_the_sink_anchored_copy() {
        let mut source_end = finding("handlers.py", 37, VulnClass::Injection, "cmdi at source");
        source_end.line_end = 39;
        source_end.cwe = Some("CWE-78".to_string());
        source_end.source_ref = Some("handlers.py:38".to_string());
        source_end.sink_ref = Some("shell.py:6".to_string());
        let mut sink_end = finding("shell.py", 5, VulnClass::Injection, "cmdi at sink");
        sink_end.line_end = 6;
        sink_end.cwe = Some("CWE-78".to_string());
        sink_end.source_ref = Some("handlers.py:38".to_string());
        sink_end.sink_ref = Some("shell.py:6".to_string());

        let mut cfg = Step7Config::new("m");
        cfg.semantic = false;

        for input in [
            vec![source_end.clone(), sink_end.clone()],
            vec![sink_end.clone(), source_end.clone()],
        ] {
            let (out, _) =
                run_dedup(&FailingClient, &input, &cfg, &ContextPackage::default()).await;
            assert_eq!(out.findings.len(), 1, "one flow, one finding");
            assert_eq!(out.findings[0].file, "shell.py", "the sink end survives");
            assert_eq!(out.dropped.len(), 1);
            assert_eq!(out.dropped[0].file, "handlers.py");
            assert_eq!(out.dropped[0].detail, clustering::FLOW_REASON);
            assert_eq!(out.findings[0].duplicates.len(), 1);
            assert_eq!(out.findings[0].duplicates[0].file, "handlers.py");
        }
    }

    #[test]
    fn sink_anchor_rank_needs_both_refs_and_a_matching_anchor_file() {
        let mut f = finding("shell.py", 5, VulnClass::Injection, "t");
        assert_eq!(sink_anchor_rank(&f), 1, "no refs at all");
        f.sink_ref = Some("shell.py:6".to_string());
        assert_eq!(sink_anchor_rank(&f), 1, "sink alone is not a flow");
        f.source_ref = Some("handlers.py:38".to_string());
        assert_eq!(sink_anchor_rank(&f), 0);
        f.sink_ref = Some("./shell.py:6".to_string());
        assert_eq!(sink_anchor_rank(&f), 0);
        f.file = "./shell.py".to_string();
        assert_eq!(sink_anchor_rank(&f), 0);
        f.sink_ref = Some("shell.py".to_string());
        assert_eq!(sink_anchor_rank(&f), 0);
        f.sink_ref = Some("other.py:6".to_string());
        assert_eq!(sink_anchor_rank(&f), 1);
        f.sink_ref = Some("   ".to_string());
        assert_eq!(sink_anchor_rank(&f), 1);
    }

    #[test]
    fn severity_key_scales_the_cvss_score_to_an_orderable_integer() {
        let mut f = finding("a.rs", 1, VulnClass::Injection, "t");
        assert_eq!(severity_key(&f), None);
        f.cvss_score = Some(9.85);
        assert_eq!(severity_key(&f), Some(985));
        f.cvss_score = Some(0.0);
        assert_eq!(severity_key(&f), Some(0));
        assert!(severity_key(&f) > None);
    }

    #[test]
    fn stable_canonical_sort_puts_the_most_severe_of_one_range_first() {
        let mut low = finding("a.rs", 10, VulnClass::Injection, "low");
        low.cvss_score = Some(4.0);
        let mut high = finding("a.rs", 10, VulnClass::Other, "high");
        high.cvss_score = Some(9.1);
        let unscored = finding("a.rs", 10, VulnClass::HeapOverflow, "unscored");

        let mut findings = vec![unscored, low, high];
        sort_for_stable_canonical(&mut findings);
        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, vec!["high", "low", "unscored"]);
    }

    #[test]
    fn stable_canonical_sort_orders_by_file_then_line_then_class() {
        let mut findings = vec![
            finding("b.rs", 1, VulnClass::Injection, "t"),
            finding("a.rs", 50, VulnClass::Injection, "t"),
            finding("a.rs", 5, VulnClass::Other, "t"),
            finding("a.rs", 5, VulnClass::Injection, "t"),
        ];
        sort_for_stable_canonical(&mut findings);
        let key: Vec<(&str, i64, &str)> = findings
            .iter()
            .map(|f| (f.file.as_str(), f.line_start, f.vuln_class.as_str()))
            .collect();
        assert_eq!(
            key,
            vec![
                ("a.rs", 5, VulnClass::Injection.as_str()),
                ("a.rs", 5, VulnClass::Other.as_str()),
                ("a.rs", 50, VulnClass::Injection.as_str()),
                ("b.rs", 1, VulnClass::Injection.as_str()),
            ]
        );
    }

    #[test]
    fn stable_canonical_sort_puts_the_best_evidenced_duplicate_first() {
        let mut weak = finding("a.rs", 10, VulnClass::Injection, "weak");
        weak.verdict_confidence = Some(6);
        let mut strong = finding("a.rs", 10, VulnClass::Injection, "strong");
        strong.verdict_confidence = Some(9);
        let mut unverified = finding("a.rs", 10, VulnClass::Injection, "unverified");
        unverified.verdict_confidence = None;

        let mut findings = vec![unverified, weak, strong];
        sort_for_stable_canonical(&mut findings);
        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, vec!["strong", "weak", "unverified"]);
    }

    #[test]
    fn stable_canonical_sort_prefers_the_specific_then_lower_cwe_lens() {
        let mut umbrella = finding("a.py", 28, VulnClass::Injection, "input validation");
        umbrella.cwe = Some("CWE-20".to_string());
        umbrella.confidence = 0.95;
        let mut sqli = finding("a.py", 28, VulnClass::Injection, "sqli");
        sqli.cwe = Some("CWE-89".to_string());
        sqli.confidence = 0.5;
        let mut idor = finding("a.py", 28, VulnClass::Injection, "idor");
        idor.cwe = Some("CWE-639".to_string());
        idor.confidence = 0.9;
        let mut traversal = finding("a.py", 28, VulnClass::Injection, "traversal");
        traversal.cwe = Some("CWE-22".to_string());
        traversal.confidence = 0.6;
        let mut unclassed = finding("a.py", 28, VulnClass::Injection, "no cwe");
        unclassed.confidence = 0.99;

        for order in [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0], [2, 4, 0, 3, 1]] {
            let pool = [&umbrella, &sqli, &idor, &traversal, &unclassed];
            let mut findings: Vec<Finding> = order.iter().map(|&i| pool[i].clone()).collect();
            sort_for_stable_canonical(&mut findings);
            let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
            assert_eq!(
                titles,
                vec!["traversal", "sqli", "idor", "input validation", "no cwe"]
            );
        }
    }

    #[test]
    fn stable_canonical_sort_breaks_a_full_tie_on_confidence_then_title() {
        let mut low = finding("a.rs", 10, VulnClass::Injection, "zzz");
        low.confidence = 0.2;
        let mut high_b = finding("a.rs", 10, VulnClass::Injection, "bbb");
        high_b.confidence = 0.8;
        let mut high_a = finding("a.rs", 10, VulnClass::Injection, "aaa");
        high_a.confidence = 0.8;

        let mut findings = vec![low, high_b, high_a];
        sort_for_stable_canonical(&mut findings);
        let titles: Vec<&str> = findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, vec!["aaa", "bbb", "zzz"]);
    }

    #[tokio::test]
    async fn two_permutations_of_the_same_input_dedup_identically() {
        let mut early = finding("a.rs", 10, VulnClass::Injection, "early");
        early.verdict_confidence = Some(9);
        early.code_snippet = "the canonical snippet".to_string();
        let mut late = finding("a.rs", 12, VulnClass::Injection, "late");
        late.verdict_confidence = Some(8);
        late.code_snippet = "the duplicate snippet".to_string();
        let other = finding("z.rs", 99, VulnClass::Other, "unrelated");

        let mut cfg = Step7Config::new("m");
        cfg.line_tolerance = 3;
        cfg.semantic = false;

        let forward = vec![early.clone(), late.clone(), other.clone()];
        let reversed = vec![other, late, early];

        let (out_a, _) =
            run_dedup(&FailingClient, &forward, &cfg, &ContextPackage::default()).await;
        let (out_b, _) =
            run_dedup(&FailingClient, &reversed, &cfg, &ContextPackage::default()).await;

        assert_eq!(out_a, out_b);
        assert_eq!(out_a.findings.len(), 2);
        assert_eq!(out_a.findings[0].title, "early");
        assert_eq!(out_a.findings[0].code_snippet, "the canonical snippet");
        assert_eq!(out_a.dropped.len(), 1);
        assert_eq!(out_a.dropped[0].title, "late");
    }

    #[tokio::test]
    async fn single_finding_short_circuits_with_no_dedup() {
        let findings = vec![finding("a.rs", 10, VulnClass::Injection, "t")];
        let (out, reason) = run_dedup(
            &ScriptedClient {
                reply: String::new(),
            },
            &findings,
            &Step7Config::new("m"),
            &ContextPackage::default(),
        )
        .await;
        assert_eq!(out.findings.len(), 1);
        assert!(out.dropped.is_empty());
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn trivial_duplicates_collapse_without_any_llm_call() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("a.rs", 11, VulnClass::Injection, "t2"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.line_tolerance = 3;
        let (out, reason) =
            run_dedup(&FailingClient, &findings, &cfg, &ContextPackage::default()).await;
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].reason, DropReason::Duplicate);
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn semantic_pass_merges_distinct_findings_the_prefilter_missed() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let reply = "index=0 is_duplicate=false canonical=-1 reasoning=\"x\"\n\
                     index=1 is_duplicate=true canonical=0 reasoning=\"shared helper\"\n\
                     index=2 is_duplicate=false canonical=-1 reasoning=\"y\"\n";
        let (out, reason) = run_dedup(
            &ScriptedClient {
                reply: reply.to_string(),
            },
            &findings,
            &Step7Config::new("m"),
            &ContextPackage::default(),
        )
        .await;
        assert_eq!(out.findings.len(), 2);
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].detail, "shared helper");
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn a_semantic_merge_also_ends_up_on_the_sink_anchored_member() {
        let mut away = finding("a.rs", 10, VulnClass::Injection, "entry point");
        away.line_end = 12;
        let mut at_sink = finding("b.rs", 500, VulnClass::Injection, "the sink");
        at_sink.line_end = 510;
        at_sink.sink_ref = Some("b.rs:505".to_string());
        let findings = vec![
            away,
            at_sink,
            finding("c.rs", 900, VulnClass::Other, "unrelated"),
        ];
        let reply = "index=0 is_duplicate=false canonical=-1 reasoning=\"x\"\n\
                     index=1 is_duplicate=true canonical=0 reasoning=\"shared helper\"\n\
                     index=2 is_duplicate=false canonical=-1 reasoning=\"y\"\n";
        let (out, reason) = run_dedup(
            &ScriptedClient {
                reply: reply.to_string(),
            },
            &findings,
            &Step7Config::new("m"),
            &ContextPackage::default(),
        )
        .await;
        assert!(reason.is_none());
        assert_eq!(out.findings.len(), 2);
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.findings[0].file, "b.rs");
        assert_eq!(out.dropped[0].file, "a.rs");
        assert_eq!(out.dropped[0].detail, "shared helper");
        assert_eq!(out.dropped[0].canonical_idx, Some(0));
        assert_eq!(out.findings[0].duplicates.len(), 1);
        assert_eq!(out.findings[0].duplicates[0].file, "a.rs");
    }

    #[tokio::test]
    async fn semantic_call_failure_degrades_to_deterministic_only_results() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let (out, reason) =
            run_dedup(&FailingClient, &findings, &cfg, &ContextPackage::default()).await;
        assert_eq!(out.findings.len(), 3);
        assert!(out.dropped.is_empty());
        assert!(reason.unwrap().contains("semantic dedup call failed"));
    }

    #[tokio::test]
    async fn semantic_call_retries_a_transient_failure_then_succeeds() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let client = RetryingClient::new(2);
        let (out, reason) = run_dedup(&client, &findings, &cfg, &ContextPackage::default()).await;
        assert_eq!(out.findings.len(), 3);
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn a_second_semantic_merge_targeting_an_already_resolved_index_is_ignored() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let reply = "index=2 is_duplicate=true canonical=0 reasoning=\"first\"\n\
                     index=2 is_duplicate=true canonical=1 reasoning=\"second\"\n";
        let (out, _) = run_dedup(
            &ScriptedClient {
                reply: reply.to_string(),
            },
            &findings,
            &Step7Config::new("m"),
            &ContextPackage::default(),
        )
        .await;
        assert_eq!(out.dropped.len(), 1);
        assert_eq!(out.dropped[0].detail, "first");
        assert_eq!(out.dropped[0].canonical_idx, Some(0));
    }

    #[derive(Debug)]
    struct FixedGate(bool);

    impl appsec_pipeline_core::BudgetGate for FixedGate {
        fn should_stop(&self) -> bool {
            self.0
        }
        fn stop_reason(&self) -> String {
            "token budget of 3000000 reached (3012044 spent)".to_string()
        }
    }

    #[tokio::test]
    async fn a_tripped_budget_gate_skips_the_semantic_call_and_degrades() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.budget_gate = Some(std::sync::Arc::new(FixedGate(true)));
        let (out, reason) =
            run_dedup(&FailingClient, &findings, &cfg, &ContextPackage::default()).await;
        assert_eq!(out.findings.len(), 3);
        assert_eq!(
            reason.unwrap(),
            "semantic dedup skipped: token budget of 3000000 reached (3012044 spent)"
        );
    }

    #[tokio::test]
    async fn an_untripped_budget_gate_lets_the_semantic_call_happen() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.budget_gate = Some(std::sync::Arc::new(FixedGate(false)));
        let reply = "index=1 is_duplicate=true canonical=0 reasoning=\"shared helper\"\n";
        let (out, reason) = run_dedup(
            &ScriptedClient {
                reply: reply.to_string(),
            },
            &findings,
            &cfg,
            &ContextPackage::default(),
        )
        .await;
        assert_eq!(out.findings.len(), 2);
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn a_tripped_gate_says_nothing_when_the_call_would_not_have_happened_anyway() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.semantic = false;
        cfg.budget_gate = Some(std::sync::Arc::new(FixedGate(true)));
        let (_, reason) =
            run_dedup(&FailingClient, &findings, &cfg, &ContextPackage::default()).await;
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn semantic_disabled_skips_the_llm_call_entirely() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.semantic = false;
        let (out, reason) =
            run_dedup(&FailingClient, &findings, &cfg, &ContextPackage::default()).await;
        assert_eq!(out.findings.len(), 3);
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn stage7_run_wraps_a_successful_dedup_as_ok() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("a.rs", 11, VulnClass::Injection, "t2"),
        ];
        let stage = Stage7::new(
            std::sync::Arc::new(ScriptedClient {
                reply: String::new(),
            }),
            Step7Config::new("m"),
        );
        let outcome = stage
            .run(Step7Input {
                findings,
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert!(!outcome.is_degraded());
        assert_eq!(outcome.into_value().findings.len(), 1);
    }

    #[tokio::test]
    async fn stage7_run_wraps_a_semantic_failure_as_degraded() {
        let findings = vec![
            finding("a.rs", 10, VulnClass::Injection, "t1"),
            finding("b.rs", 500, VulnClass::Injection, "t2"),
            finding("c.rs", 900, VulnClass::Other, "t3"),
        ];
        let mut cfg = Step7Config::new("m");
        cfg.retry_backoff_base = std::time::Duration::ZERO;
        let stage = Stage7::new(std::sync::Arc::new(FailingClient), cfg);
        let outcome = stage
            .run(Step7Input {
                findings,
                ctx: ContextPackage::default(),
            })
            .await
            .unwrap();
        assert!(outcome.is_degraded());
        assert!(outcome
            .reason()
            .unwrap()
            .contains("semantic dedup call failed"));
    }
}
