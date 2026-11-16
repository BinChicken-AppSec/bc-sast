use std::collections::{BTreeMap, BTreeSet};

use appsec_callgraph::annotator::{
    append_spec, build_prompt_batch, collect_candidates, norm_cwe_for_role, parse_results,
    supplement_with_heuristics, SYSTEM_PROMPT,
};
use appsec_callgraph::{Candidate, FileIndex, MatchSpec};
use appsec_llm_client::{ChatRequest, LlmClient, LlmError, Message};
use serde_json::Value;

pub struct Step0LlmConfig {
    pub model: String,
    pub max_candidates: usize,
    pub max_batch_candidates: usize,
    pub min_source_confidence: f64,
    pub min_sink_confidence: f64,
    pub max_tokens: u32,
    pub heuristic_supplement: bool,
    pub min_sources: usize,
    pub min_sinks: usize,
    pub max_heuristic_specs: usize,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
    pub reasoning_effort: Option<appsec_llm_client::ReasoningEffort>,
    pub openai_api: Option<appsec_llm_client::OpenAiApi>,
    pub timeout_secs: Option<u64>,
}

impl Step0LlmConfig {
    pub fn new(model: impl Into<String>) -> Self {
        Step0LlmConfig {
            model: model.into(),
            max_candidates: 400,
            max_batch_candidates: 150,
            min_source_confidence: 0.75,
            min_sink_confidence: 0.75,
            max_tokens: 16_000,
            heuristic_supplement: true,
            min_sources: 1,
            min_sinks: 1,
            max_heuristic_specs: 10,
            temperature: None,
            top_p: None,
            seed: None,
            reasoning_effort: None,
            openai_api: None,
            timeout_secs: None,
        }
    }
}

pub(crate) type Specs = (
    Vec<MatchSpec>,
    Vec<MatchSpec>,
    BTreeMap<String, Vec<String>>,
);

fn empty_specs() -> Specs {
    (Vec::new(), Vec::new(), BTreeMap::new())
}

fn accept_row(
    row: &serde_json::Map<String, Value>,
    by_id: &BTreeMap<String, &Candidate>,
    config: &Step0LlmConfig,
    source_specs: &mut Vec<MatchSpec>,
    sink_specs: &mut Vec<MatchSpec>,
    rule_cwe: &mut BTreeMap<String, Vec<String>>,
    seen_sig: &mut BTreeSet<(String, String, String, String)>,
) {
    let cid = row.get("id").and_then(Value::as_str).unwrap_or("").trim();
    let Some(cand) = by_id.get(cid) else {
        return;
    };
    let role = row
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("none")
        .trim()
        .to_lowercase();
    let conf = row.get("confidence").and_then(Value::as_f64).unwrap_or(0.0);
    if role == "source" && conf < config.min_source_confidence {
        return;
    }
    if role == "sink" && conf < config.min_sink_confidence {
        return;
    }
    if role != "source" && role != "sink" {
        return;
    }
    let cwe_raw = row.get("cwe").and_then(Value::as_str).unwrap_or("");
    let cwe = norm_cwe_for_role(cwe_raw, &role);
    let kind = row
        .get("kind")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(if role == "source" { "other" } else { "unsafe" })
        .to_string();
    append_spec(
        &role,
        cand,
        &kind,
        &cwe,
        source_specs,
        sink_specs,
        rule_cwe,
        seen_sig,
        "",
    );
}

pub async fn detect_specs(
    client: &dyn LlmClient,
    file_indices: &[FileIndex],
    active_langs: &[String],
    config: &Step0LlmConfig,
) -> Specs {
    let active_set: BTreeSet<String> = active_langs.iter().cloned().collect();
    let candidates = collect_candidates(file_indices, &active_set, config.max_candidates);
    if candidates.is_empty() {
        return empty_specs();
    }
    let by_id: BTreeMap<String, &Candidate> =
        candidates.iter().map(|c| (c.cid.clone(), c)).collect();

    let mut source_specs = Vec::new();
    let mut sink_specs = Vec::new();
    let mut rule_cwe = BTreeMap::new();
    let mut seen_sig = BTreeSet::new();

    for batch in candidates.chunks(config.max_batch_candidates.max(1)) {
        let user = build_prompt_batch(batch);
        let request = ChatRequest {
            model: config.model.clone(),
            system: Some(SYSTEM_PROMPT.to_string()),
            messages: vec![Message::user_text(&user)],
            tools: Vec::new(),
            max_tokens: config.max_tokens,
            temperature: config.temperature,
            top_p: config.top_p,
            seed: config.seed,
            reasoning_effort: config.reasoning_effort,
            openai_api: config.openai_api,
            thinking_budget: None,
            betas: Vec::new(),
            json_mode: false,
            timeout: config.timeout_secs.map(std::time::Duration::from_secs),
            stream: false,
            ..ChatRequest::default()
        };
        let response = match client.chat(&request).await {
            Ok(r) => r,
            Err(e) => {
                let fatal = e.halts_scan() || matches!(e, LlmError::GuardrailBlocked { .. });
                if fatal {
                    tracing::warn!(
                        "[s0/callgraph] llm detection batch failed: {e}; not sending the \
                         remaining batches"
                    );
                    break;
                }
                tracing::warn!(
                    "[s0/callgraph] llm detection batch failed: {e}; skipping this batch \
                     and keeping the others"
                );
                continue;
            }
        };
        for row in parse_results(&response.text()) {
            accept_row(
                &row,
                &by_id,
                config,
                &mut source_specs,
                &mut sink_specs,
                &mut rule_cwe,
                &mut seen_sig,
            );
        }
    }

    if config.heuristic_supplement {
        let need_src = config.min_sources.saturating_sub(source_specs.len());
        let need_snk = config.min_sinks.saturating_sub(sink_specs.len());
        if need_src > 0 || need_snk > 0 {
            let (s, k, c) = supplement_with_heuristics(
                file_indices,
                active_langs,
                source_specs,
                sink_specs,
                rule_cwe,
                need_src,
                need_snk,
                config.max_heuristic_specs,
            );
            source_specs = s;
            sink_specs = k;
            rule_cwe = c;
        }
    }

    (source_specs, sink_specs, rule_cwe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_callgraph::ObservedCall;
    use appsec_llm_client::{ChatRequest, ChatResponse, ContentBlock, LlmError, StopReason, Usage};
    use async_trait::async_trait;

    struct ScriptedClient {
        replies: std::sync::Mutex<Vec<String>>,
    }

    impl ScriptedClient {
        fn new(replies: Vec<&str>) -> Self {
            ScriptedClient {
                replies: std::sync::Mutex::new(
                    replies.into_iter().rev().map(str::to_string).collect(),
                ),
            }
        }
    }

    #[async_trait]
    impl LlmClient for ScriptedClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            let text = self.replies.lock().unwrap().pop().unwrap_or_default();
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(text)],
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

    fn observed_call(language: &str, module: &str, method: &str) -> FileIndex {
        FileIndex {
            file: "a.py".to_string(),
            language: language.to_string(),
            observed_calls: vec![ObservedCall {
                file: "a.py".to_string(),
                language: language.to_string(),
                line: 1,
                receiver: module.to_string(),
                method: method.to_string(),
                snippet: format!("{module}.{method}()"),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn detect_specs_empty_when_no_candidates() {
        let client = ScriptedClient::new(vec!["[]"]);
        let config = Step0LlmConfig::new("m");
        let (s, k, c) = detect_specs(&client, &[], &["python".to_string()], &config).await;
        assert!(s.is_empty() && k.is_empty() && c.is_empty());
    }

    #[tokio::test]
    async fn detect_specs_classifies_a_source_above_confidence_threshold() {
        let idx = observed_call("python", "request", "args_get");
        let client = ScriptedClient::new(vec![
            r#"[{"id":"c1","role":"source","confidence":0.9,"cwe":"CWE-20","kind":"network"}]"#,
        ]);
        let mut config = Step0LlmConfig::new("m");
        config.heuristic_supplement = false;
        let (source_specs, sink_specs, rule_cwe) =
            detect_specs(&client, &[idx], &["python".to_string()], &config).await;
        assert_eq!(source_specs.len(), 1);
        assert!(sink_specs.is_empty());
        assert_eq!(source_specs[0].cwe, "CWE-20");
        assert_eq!(rule_cwe.len(), 1);
    }

    #[tokio::test]
    async fn detect_specs_classifies_a_sink_and_defaults_missing_kind_to_unsafe() {
        let idx = observed_call("python", "os", "system");
        let client = ScriptedClient::new(vec![
            r#"[{"id":"c1","role":"sink","confidence":0.9,"cwe":"CWE-78"}]"#,
        ]);
        let mut config = Step0LlmConfig::new("m");
        config.heuristic_supplement = false;
        let (source_specs, sink_specs, _) =
            detect_specs(&client, &[idx], &["python".to_string()], &config).await;
        assert!(source_specs.is_empty());
        assert_eq!(sink_specs.len(), 1);
        assert_eq!(sink_specs[0].kind, "unsafe");
    }

    #[tokio::test]
    async fn detect_specs_drops_a_source_row_below_the_confidence_threshold() {
        let idx = observed_call("python", "request", "args_get");
        let client = ScriptedClient::new(vec![
            r#"[{"id":"c1","role":"source","confidence":0.1,"cwe":"CWE-20"}]"#,
        ]);
        let mut config = Step0LlmConfig::new("m");
        config.heuristic_supplement = false;
        let (source_specs, sink_specs, _) =
            detect_specs(&client, &[idx], &["python".to_string()], &config).await;
        assert!(source_specs.is_empty() && sink_specs.is_empty());
    }

    #[tokio::test]
    async fn detect_specs_drops_a_sink_row_below_the_confidence_threshold() {
        let idx = observed_call("python", "os", "system");
        let client = ScriptedClient::new(vec![
            r#"[{"id":"c1","role":"sink","confidence":0.1,"cwe":"CWE-78"}]"#,
        ]);
        let mut config = Step0LlmConfig::new("m");
        config.heuristic_supplement = false;
        let (source_specs, sink_specs, _) =
            detect_specs(&client, &[idx], &["python".to_string()], &config).await;
        assert!(source_specs.is_empty() && sink_specs.is_empty());
    }

    #[tokio::test]
    async fn detect_specs_ignores_a_row_with_an_unknown_candidate_id() {
        let idx = observed_call("python", "request", "args_get");
        let client =
            ScriptedClient::new(vec![r#"[{"id":"c999","role":"source","confidence":0.9}]"#]);
        let mut config = Step0LlmConfig::new("m");
        config.heuristic_supplement = false;
        let (source_specs, sink_specs, _) =
            detect_specs(&client, &[idx], &["python".to_string()], &config).await;
        assert!(source_specs.is_empty() && sink_specs.is_empty());
    }

    #[tokio::test]
    async fn detect_specs_ignores_a_row_with_role_none() {
        let idx = observed_call("python", "request", "args_get");
        let client = ScriptedClient::new(vec![r#"[{"id":"c1","role":"none","confidence":0.9}]"#]);
        let mut config = Step0LlmConfig::new("m");
        config.heuristic_supplement = false;
        let (source_specs, sink_specs, _) =
            detect_specs(&client, &[idx], &["python".to_string()], &config).await;
        assert!(source_specs.is_empty() && sink_specs.is_empty());
    }

    #[tokio::test]
    async fn detect_specs_empty_on_call_failure() {
        let idx = observed_call("python", "request", "args_get");
        let client = FailingClient;
        let mut config = Step0LlmConfig::new("m");
        config.heuristic_supplement = false;
        let (s, k, c) = detect_specs(&client, &[idx], &["python".to_string()], &config).await;
        assert!(s.is_empty() && k.is_empty() && c.is_empty());
    }

    struct SequenceClient {
        outcomes: std::sync::Mutex<Vec<Result<String, LlmError>>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl LlmClient for SequenceClient {
        async fn chat(&self, _request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let text = self.outcomes.lock().unwrap().remove(0)?;
            Ok(ChatResponse {
                content: vec![ContentBlock::Text(text)],
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    fn two_candidates() -> FileIndex {
        let call = |line: usize, receiver: &str, method: &str| ObservedCall {
            file: "a.py".to_string(),
            language: "python".to_string(),
            line,
            receiver: receiver.to_string(),
            method: method.to_string(),
            snippet: format!("{receiver}.{method}()"),
            ..Default::default()
        };
        FileIndex {
            file: "a.py".to_string(),
            language: "python".to_string(),
            observed_calls: vec![call(1, "request", "args_get"), call(2, "os", "system")],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn one_failed_batch_no_longer_discards_the_others() {
        let client = SequenceClient {
            outcomes: std::sync::Mutex::new(vec![
                Err(LlmError::ServerError {
                    status: 503,
                    message: "down".to_string(),
                }),
                Ok(r#"[{"id":"c2","role":"sink","confidence":0.9,"cwe":"CWE-78"}]"#.to_string()),
            ]),
            calls: Default::default(),
        };
        let mut config = Step0LlmConfig::new("m");
        config.max_batch_candidates = 1;
        config.heuristic_supplement = false;
        let (source_specs, sink_specs, _) = detect_specs(
            &client,
            &[two_candidates()],
            &["python".to_string()],
            &config,
        )
        .await;
        assert!(source_specs.is_empty());
        assert_eq!(sink_specs.len(), 1);
    }

    #[tokio::test]
    async fn an_account_level_failure_stops_the_remaining_batches() {
        for err in [
            LlmError::QuotaExhausted {
                message: "no credit".to_string(),
            },
            LlmError::GuardrailBlocked {
                message: "refused".to_string(),
            },
            LlmError::Authentication {
                status: Some(401),
                message: "bad key".to_string(),
            },
        ] {
            let client = SequenceClient {
                outcomes: std::sync::Mutex::new(vec![
                    Err(err),
                    Ok(r#"[{"id":"c2","role":"sink","confidence":0.9}]"#.to_string()),
                ]),
                calls: Default::default(),
            };
            let mut config = Step0LlmConfig::new("m");
            config.max_batch_candidates = 1;
            config.heuristic_supplement = false;
            let (s, k, _) = detect_specs(
                &client,
                &[two_candidates()],
                &["python".to_string()],
                &config,
            )
            .await;
            assert!(s.is_empty() && k.is_empty());
            assert_eq!(client.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn detect_specs_batches_across_max_batch_candidates() {
        let idx = FileIndex {
            file: "a.py".to_string(),
            language: "python".to_string(),
            observed_calls: vec![
                ObservedCall {
                    file: "a.py".to_string(),
                    language: "python".to_string(),
                    line: 1,
                    receiver: "request".to_string(),
                    method: "args_get".to_string(),
                    snippet: "request.args_get()".to_string(),
                    ..Default::default()
                },
                ObservedCall {
                    file: "a.py".to_string(),
                    language: "python".to_string(),
                    line: 2,
                    receiver: "os".to_string(),
                    method: "system".to_string(),
                    snippet: "os.system()".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let client = ScriptedClient::new(vec![
            r#"[{"id":"c1","role":"source","confidence":0.9,"cwe":"CWE-20"}]"#,
            r#"[{"id":"c2","role":"sink","confidence":0.9,"cwe":"CWE-78"}]"#,
        ]);
        let mut config = Step0LlmConfig::new("m");
        config.max_batch_candidates = 1;
        config.heuristic_supplement = false;
        let (source_specs, sink_specs, _) =
            detect_specs(&client, &[idx], &["python".to_string()], &config).await;
        assert_eq!(source_specs.len(), 1);
        assert_eq!(sink_specs.len(), 1);
    }

    #[tokio::test]
    async fn detect_specs_heuristic_supplement_tops_up_when_below_minimums() {
        let idx = observed_call("python", "os", "system");
        let client = ScriptedClient::new(vec!["[]"]);
        let mut config = Step0LlmConfig::new("m");
        config.min_sinks = 1;
        config.max_heuristic_specs = 10;
        let (_, sink_specs, _) =
            detect_specs(&client, &[idx], &["python".to_string()], &config).await;
        assert!(!sink_specs.is_empty());
    }
}
