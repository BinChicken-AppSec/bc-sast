//! `--doctor --cache-probe`: the live half of the prompt-cache
//! diagnostic whose pure half is `bc_llm_client::classify_cache_probe`.
//! Ported from the Python original's `orchestrator/preflight.py::
//! run_cache_probe`, reduced to what this port has: one configured
//! client and one `--model`, rather than Python's matrix of backends,
//! filler shapes and thinking arms.
//!
//! Both calls go through the REAL configured client, cache-policy
//! wrapper included, for the reason Python gives: a separate client
//! would test a request the scan never sends. Only `--doctor` calls this,
//! and only after the ordinary live probe reached the model.

use bc_llm_client::{
    cache_probe_filler, classify_cache_probe, estimate_tokens, CacheDialect, CachePolicy,
    CacheProbeVerdict, ChatRequest, LlmClient, Message, Usage, CACHE_PROBE_FILLER_MIN_TOKENS,
    CACHE_PROBE_USER_A, CACHE_PROBE_USER_B,
};

/// Each probe call's output budget: Python's `_PROBE_MAX_TOKENS`. Only
/// the usage matters, but the budget still has to clear a one-word reply
/// from a model that thinks first.
const PROBE_MAX_TOKENS: u32 = 256;

/// What the probe found, rendered by [`std::fmt::Display`].
#[derive(Debug, Clone, PartialEq)]
pub struct CacheProbeOutcome {
    pub model: String,
    /// How many of the two calls were sent, for the spend line.
    pub calls_sent: u8,
    /// Estimated prompt tokens per call, for the spend line.
    pub estimated_prompt_tokens: u64,
    pub result: Result<CacheProbeReading, String>,
}

/// A completed probe: both calls' cache accounting and the verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct CacheProbeReading {
    pub first: Usage,
    pub second: Usage,
    pub verdict: CacheProbeVerdict,
}

impl CacheProbeOutcome {
    /// A probe that was asked for but not run, because the ordinary live
    /// probe had not reached the model first (Python runs it only after
    /// that probe passed: there is nothing to diagnose otherwise).
    pub(crate) fn skipped(model: &str) -> Self {
        CacheProbeOutcome {
            model: model.to_string(),
            calls_sent: 0,
            estimated_prompt_tokens: 0,
            result: Err("skipped: the live probe did not reach the model".to_string()),
        }
    }

    /// Whether the probe ran to a verdict. Any verdict counts: a cache
    /// that does not work is a finding, not a broken diagnostic.
    pub fn completed(&self) -> bool {
        self.result.is_ok()
    }
}

/// Send Call A then, straight after, Call B through `client`, and
/// classify the pair. `policy` is the cache policy the client stamps on
/// every request, needed to tell "the gateway ignored our marker" from
/// "we never sent one".
pub(crate) async fn run(
    client: &dyn LlmClient,
    model: &str,
    dialect: CacheDialect,
    policy: &CachePolicy,
) -> CacheProbeOutcome {
    let system = cache_probe_filler(CACHE_PROBE_FILLER_MIN_TOKENS);
    let estimated = estimate_tokens(&system) + estimate_tokens(CACHE_PROBE_USER_A);
    let request = |user: &str| ChatRequest {
        system: Some(system.clone()),
        ..ChatRequest::new(model, vec![Message::user_text(user)], PROBE_MAX_TOKENS)
    };
    let mut calls_sent = 1;
    let result = async {
        let first = client
            .chat(&request(CACHE_PROBE_USER_A))
            .await
            .map_err(|e| format!("call A failed: {e}"))?;
        calls_sent = 2;
        let second = client
            .chat(&request(CACHE_PROBE_USER_B))
            .await
            .map_err(|e| format!("call B failed: {e}"))?;
        let mut verdict = classify_cache_probe(&first.usage, &second.usage, dialect);
        // Python's post-classification override: a zero-write, zero-read
        // pair has two causes, and only our own gate can tell them apart.
        // When it says no marker went out, the gateway is not to blame.
        if verdict == CacheProbeVerdict::MarkerNotHonored
            && dialect == CacheDialect::Anthropic
            && !policy.anthropic_marker_worth_placing(model, estimate_tokens(&system))
        {
            verdict = CacheProbeVerdict::MarkerWithheld;
        }
        Ok(CacheProbeReading {
            first: first.usage,
            second: second.usage,
            verdict,
        })
    }
    .await;
    CacheProbeOutcome {
        model: model.to_string(),
        calls_sent,
        estimated_prompt_tokens: estimated,
        result: result.map_err(|e: String| bc_redact::redact(&e)),
    }
}

impl std::fmt::Display for CacheProbeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut lines = Vec::new();
        if self.calls_sent > 0 {
            lines.push(format!(
                "  [cache-probe] {}: {} live call(s) of about {} prompt tokens each \
                 (real tokens were spent)",
                self.model, self.calls_sent, self.estimated_prompt_tokens
            ));
        }
        match &self.result {
            Err(e) => lines.push(format!("  [cache-probe] \u{2717} {e}")),
            Ok(reading) => {
                lines.push(format!(
                    "  [cache-probe] call A wrote {} read {}; call B wrote {} read {}",
                    reading.first.cache_creation_input_tokens,
                    reading.first.cache_read_input_tokens,
                    reading.second.cache_creation_input_tokens,
                    reading.second.cache_read_input_tokens,
                ));
                lines.push(format!(
                    "  [cache-probe] verdict {}: {}",
                    reading.verdict.code(),
                    reading.verdict.explanation()
                ));
            }
        }
        f.write_str(&lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::{ChatResponse, ContentBlock, LlmError, StopReason};
    use std::sync::Mutex;

    /// Answers each call with the next scripted usage (or error), and
    /// records every request.
    struct Scripted {
        replies: Mutex<Vec<Result<Usage, LlmError>>>,
        seen: Mutex<Vec<ChatRequest>>,
    }

    impl Scripted {
        fn new(replies: Vec<Result<Usage, LlmError>>) -> Self {
            Scripted {
                replies: Mutex::new(replies.into_iter().rev().collect()),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl LlmClient for Scripted {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            self.seen.lock().unwrap().push(request.clone());
            let usage = self.replies.lock().unwrap().pop().unwrap()?;
            Ok(ChatResponse {
                content: vec![ContentBlock::text("PONG")],
                stop_reason: StopReason::EndTurn,
                usage,
            })
        }
    }

    fn user_turn_is(request: &ChatRequest, want: &str) -> bool {
        matches!(&request.messages[0].content[0], ContentBlock::Text(t) if t == want)
    }

    fn usage(write: u64, read: u64) -> Usage {
        Usage {
            input_tokens: 10,
            output_tokens: 1,
            cache_creation_input_tokens: write,
            cache_read_input_tokens: read,
        }
    }

    async fn probe(
        a: Usage,
        b: Usage,
        dialect: CacheDialect,
        policy: CachePolicy,
    ) -> (CacheProbeOutcome, Vec<ChatRequest>) {
        let client = Scripted::new(vec![Ok(a), Ok(b)]);
        let outcome = run(&client, "claude-opus-5", dialect, &policy).await;
        let seen = client.seen.into_inner().unwrap();
        (outcome, seen)
    }

    #[tokio::test]
    async fn the_two_calls_share_the_filler_and_differ_only_in_the_user_turn() {
        let (outcome, seen) = probe(
            usage(9000, 0),
            usage(0, 9000),
            CacheDialect::Anthropic,
            CachePolicy::default(),
        )
        .await;
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].system, seen[1].system);
        assert!(seen[0]
            .system
            .as_deref()
            .unwrap()
            .starts_with("CACHE-PROBE-FILLER-LINE-000000"));
        assert!(user_turn_is(&seen[0], CACHE_PROBE_USER_A));
        assert!(user_turn_is(&seen[1], CACHE_PROBE_USER_B));
        assert!(seen.iter().all(|r| r.max_tokens == PROBE_MAX_TOKENS));
        assert!(seen.iter().all(|r| r.model == "claude-opus-5"));
        assert!(outcome.completed());
        assert!(outcome.estimated_prompt_tokens > u64::from(CACHE_PROBE_FILLER_MIN_TOKENS));
        let reading = outcome.result.as_ref().unwrap();
        assert_eq!(reading.verdict, CacheProbeVerdict::AnthropicWorks);
        let text = outcome.to_string();
        assert!(
            text.contains("claude-opus-5: 2 live call(s) of about"),
            "{text}"
        );
        assert!(text.contains("real tokens were spent"), "{text}");
        assert!(text.contains("call A wrote 9000 read 0; call B wrote 0 read 9000"));
        assert!(text.contains("verdict anthropic_works: cache markers are honored"));
    }

    /// Every verdict the classifier can reach through this CLI, and the
    /// explanation it prints.
    #[tokio::test]
    async fn each_verdict_is_classified_and_explained() {
        use CacheDialect::{Anthropic, OpenAi};
        use CacheProbeVerdict::*;
        let cases = [
            (usage(500, 0), usage(0, 0), Anthropic, WriteOkReadFails),
            (usage(0, 900), usage(0, 900), Anthropic, AlreadyWarm),
            (usage(0, 0), usage(0, 0), Anthropic, MarkerNotHonored),
            (usage(0, 0), usage(0, 4000), OpenAi, OpenAiImplicitWorking),
            (usage(0, 0), usage(0, 0), OpenAi, BelowMinimum),
            (usage(700, 0), usage(0, 700), OpenAi, AnthropicWorks),
        ];
        for (a, b, dialect, want) in cases {
            let (outcome, _) = probe(a, b, dialect, CachePolicy::default()).await;
            let reading = outcome.result.as_ref().unwrap();
            assert_eq!(reading.verdict, want, "{a:?} {b:?} {dialect:?}");
            let text = outcome.to_string();
            assert!(text.contains(want.code()), "{text}");
            assert!(text.contains(want.explanation()), "{text}");
        }
    }

    #[tokio::test]
    async fn a_marker_our_own_gate_withheld_is_not_blamed_on_the_gateway() {
        let off = CachePolicy {
            markers: false,
            ..CachePolicy::default()
        };
        let (outcome, _) = probe(usage(0, 0), usage(0, 0), CacheDialect::Anthropic, off).await;
        let verdict = outcome.result.unwrap().verdict;
        assert_eq!(verdict, CacheProbeVerdict::MarkerWithheld);

        // A minimum no probe filler clears withholds the marker too.
        let huge_minimum = CachePolicy {
            min_block_tokens: Some(1_000_000),
            ..CachePolicy::default()
        };
        let (outcome, _) = probe(
            usage(0, 0),
            usage(0, 0),
            CacheDialect::Anthropic,
            huge_minimum,
        )
        .await;
        assert_eq!(
            outcome.result.unwrap().verdict,
            CacheProbeVerdict::MarkerWithheld
        );

        // OpenAI has no marker to withhold: its zero/zero stays as is.
        let (outcome, _) = probe(usage(0, 0), usage(0, 0), CacheDialect::OpenAi, off).await;
        assert_eq!(
            outcome.result.unwrap().verdict,
            CacheProbeVerdict::BelowMinimum
        );
    }

    #[tokio::test]
    async fn a_failed_call_is_reported_redacted_and_stops_the_probe() {
        let secret = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let client = Scripted::new(vec![Err(LlmError::ConnectionError {
            message: format!("refused for key {secret}"),
        })]);
        let outcome = run(&client, "m", CacheDialect::OpenAi, &CachePolicy::default()).await;
        assert!(!outcome.completed());
        assert_eq!(client.seen.lock().unwrap().len(), 1, "B is never sent");
        assert_eq!(outcome.calls_sent, 1);
        let text = outcome.to_string();
        assert!(text.contains("\u{2717} call A failed"), "{text}");
        assert!(!text.contains(secret), "{text}");

        let client = Scripted::new(vec![
            Ok(usage(1, 0)),
            Err(LlmError::RateLimited {
                retry_after_secs: None,
            }),
        ]);
        let outcome = run(&client, "m", CacheDialect::OpenAi, &CachePolicy::default()).await;
        assert_eq!(outcome.calls_sent, 2);
        assert!(outcome.result.unwrap_err().starts_with("call B failed"));
    }

    #[test]
    fn a_skipped_probe_spent_nothing_and_says_why() {
        let outcome = CacheProbeOutcome::skipped("m");
        assert!(!outcome.completed());
        assert_eq!(
            outcome.to_string(),
            "  [cache-probe] \u{2717} skipped: the live probe did not reach the model"
        );
    }
}
