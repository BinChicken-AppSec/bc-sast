use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use regex::Regex;
use serde_json::{json, Value};

use crate::chat::{ChatRequest, ChatResponse};
use crate::client::LlmClient;
use crate::error::LlmError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CacheTtl {
    #[default]
    FiveMinutes,
    OneHour,
}

impl CacheTtl {
    pub fn as_str(self) -> &'static str {
        match self {
            CacheTtl::FiveMinutes => "5m",
            CacheTtl::OneHour => "1h",
        }
    }

    pub fn cache_control(self) -> Value {
        match self {
            CacheTtl::FiveMinutes => json!({"type": "ephemeral"}),
            CacheTtl::OneHour => json!({"type": "ephemeral", "ttl": "1h"}),
        }
    }
}

impl fmt::Display for CacheTtl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CacheTtl {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "5m" => Ok(CacheTtl::FiveMinutes),
            "1h" => Ok(CacheTtl::OneHour),
            other => Err(format!("unknown cache TTL {other:?} (expected 5m or 1h)")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    pub markers: bool,
    pub min_block_tokens: Option<u32>,
    pub ttl: CacheTtl,
}

impl Default for CachePolicy {
    fn default() -> Self {
        CachePolicy {
            markers: true,
            min_block_tokens: None,
            ttl: CacheTtl::FiveMinutes,
        }
    }
}

impl CachePolicy {
    pub fn min_tokens_for(&self, model: &str) -> u32 {
        self.min_block_tokens
            .filter(|n| *n > 0)
            .unwrap_or_else(|| anthropic_min_cacheable_tokens(model))
    }

    pub fn anthropic_marker_worth_placing(
        &self,
        model: &str,
        cumulative_estimated_tokens: u64,
    ) -> bool {
        self.markers
            && clears_floor(
                cumulative_estimated_tokens,
                u64::from(self.min_tokens_for(model)),
            )
    }

    pub fn openai_cache_key_worth_sending(&self, estimated_prompt_tokens: u64) -> bool {
        self.markers
            && clears_floor(
                estimated_prompt_tokens,
                u64::from(OPENAI_MIN_CACHEABLE_PROMPT_TOKENS),
            )
    }
}

pub const CACHE_EST_MARGIN_PERCENT: u64 = 135;

pub const OPENAI_MIN_CACHEABLE_PROMPT_TOKENS: u32 = 1024;

fn clears_floor(estimated_tokens: u64, floor: u64) -> bool {
    estimated_tokens.saturating_mul(CACHE_EST_MARGIN_PERCENT) >= floor.saturating_mul(100)
}

pub fn estimate_tokens(text: &str) -> u64 {
    (text.chars().count() as u64).div_ceil(4)
}

static ANTHROPIC_MIN_TOKENS_TABLE: LazyLock<Vec<(Regex, u32)>> = LazyLock::new(|| {
    [
        (r"(?i)opus-5|fable-5", 512),
        (r"(?i)opus-4[-.]?[56]|haiku-4[-.]?5", 4096),
        (r"(?i)opus-4[-.]?7|haiku-3[-.]?5", 2048),
        (r"(?i)opus-4|sonnet-[45]", 1024),
    ]
    .into_iter()
    .map(|(pattern, floor)| (Regex::new(pattern).expect("static pattern"), floor))
    .collect()
});

pub const ANTHROPIC_MIN_TOKENS_FALLBACK: u32 = 4096;

pub fn anthropic_min_cacheable_tokens(model: &str) -> u32 {
    if let Some(floor) = crate::capabilities::capabilities(model).cache_min_tokens {
        return floor;
    }
    ANTHROPIC_MIN_TOKENS_TABLE
        .iter()
        .find(|(rx, _)| rx.is_match(model))
        .map_or(ANTHROPIC_MIN_TOKENS_FALLBACK, |(_, floor)| *floor)
}

pub struct ApplyCachePolicy {
    inner: Arc<dyn LlmClient>,
    policy: CachePolicy,
}

impl ApplyCachePolicy {
    pub fn new(inner: Arc<dyn LlmClient>, policy: CachePolicy) -> Self {
        ApplyCachePolicy { inner, policy }
    }
}

#[async_trait]
impl LlmClient for ApplyCachePolicy {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        if request.cache == self.policy {
            return self.inner.chat(request).await;
        }
        let mut stamped = request.clone();
        stamped.cache = self.policy;
        self.inner.chat(&stamped).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::{StopReason, Usage};
    use crate::message::Message;

    #[test]
    fn ttl_spellings_round_trip_and_reject_unknowns() {
        for ttl in [CacheTtl::FiveMinutes, CacheTtl::OneHour] {
            assert_eq!(ttl.as_str().parse::<CacheTtl>(), Ok(ttl));
            assert_eq!(ttl.to_string(), ttl.as_str());
        }
        assert_eq!(" 1H ".parse(), Ok(CacheTtl::OneHour));
        assert!("2h".parse::<CacheTtl>().is_err());
        assert_eq!(CacheTtl::default(), CacheTtl::FiveMinutes);
    }

    #[test]
    fn the_five_minute_marker_is_byte_identical_to_the_historical_one() {
        assert_eq!(
            CacheTtl::FiveMinutes.cache_control(),
            json!({"type": "ephemeral"})
        );
        assert_eq!(
            CacheTtl::OneHour.cache_control(),
            json!({"type": "ephemeral", "ttl": "1h"})
        );
    }

    #[test]
    fn default_policy_matches_the_python_defaults() {
        let p = CachePolicy::default();
        assert!(p.markers);
        assert_eq!(p.min_block_tokens, None);
        assert_eq!(p.ttl, CacheTtl::FiveMinutes);
    }

    #[test]
    fn the_minimum_table_matches_the_python_original() {
        let cases = [
            ("claude-opus-5", 512),
            ("claude-fable-5-1", 512),
            ("claude-opus-4-5", 4096),
            ("claude-opus-4.6", 4096),
            ("claude-haiku-4-5", 4096),
            ("claude-opus-4-7", 2048),
            ("claude-3-haiku-3.5", 2048),
            ("claude-opus-4-8", 1024),
            ("claude-opus-4-1", 1024),
            ("claude-sonnet-4-5", 1024),
            ("CLAUDE-SONNET-5", 1024),
            ("some-unknown-model", 4096),
            ("my-opus-4-7-deploy", 2048),
            ("gateway-sonnet-4-5-alias", 1024),
        ];
        for (model, floor) in cases {
            assert_eq!(anthropic_min_cacheable_tokens(model), floor, "{model}");
        }
    }

    #[test]
    fn an_operator_override_replaces_the_table_but_zero_does_not() {
        let mut p = CachePolicy::default();
        assert_eq!(p.min_tokens_for("claude-sonnet-4-5"), 1024);
        p.min_block_tokens = Some(64);
        assert_eq!(p.min_tokens_for("claude-sonnet-4-5"), 64);
        p.min_block_tokens = Some(0);
        assert_eq!(p.min_tokens_for("claude-sonnet-4-5"), 1024);
    }

    #[test]
    fn the_estimate_is_chars_over_four_rounded_up() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("abc"), 1);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcde"), 2);
        assert_eq!(estimate_tokens("🙂🙂🙂🙂"), 1);
    }

    #[test]
    fn the_marker_gate_applies_the_margin_and_the_kill_switch() {
        let p = CachePolicy::default();
        assert!(p.anthropic_marker_worth_placing("claude-sonnet-4-5", 759));
        assert!(!p.anthropic_marker_worth_placing("claude-sonnet-4-5", 758));
        let off = CachePolicy {
            markers: false,
            ..CachePolicy::default()
        };
        assert!(!off.anthropic_marker_worth_placing("claude-sonnet-4-5", 1_000_000));
    }

    #[test]
    fn the_openai_key_gate_uses_the_flat_floor_and_the_kill_switch() {
        let p = CachePolicy::default();
        assert!(p.openai_cache_key_worth_sending(759));
        assert!(!p.openai_cache_key_worth_sending(758));
        let off = CachePolicy {
            markers: false,
            ..CachePolicy::default()
        };
        assert!(!off.openai_cache_key_worth_sending(1_000_000));
    }

    struct PolicyProbe(std::sync::Mutex<Option<CachePolicy>>);

    #[async_trait]
    impl LlmClient for PolicyProbe {
        async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
            *self.0.lock().unwrap() = Some(request.cache);
            Ok(ChatResponse {
                content: Vec::new(),
                stop_reason: StopReason::EndTurn,
                usage: Usage::default(),
            })
        }
    }

    fn seen_policy(stamp: CachePolicy, sent: CachePolicy) -> CachePolicy {
        let probe = Arc::new(PolicyProbe(std::sync::Mutex::new(None)));
        let client = ApplyCachePolicy::new(probe.clone(), stamp);
        let mut req = ChatRequest::new("m", vec![Message::user_text("hi")], 1);
        req.cache = sent;
        crate::client::tests::block_on(client.chat(&req)).unwrap();
        let seen = *probe.0.lock().unwrap();
        seen.unwrap()
    }

    #[test]
    fn the_layer_stamps_the_operator_policy_over_whatever_the_request_carried() {
        let operator = CachePolicy {
            markers: false,
            min_block_tokens: Some(10),
            ttl: CacheTtl::OneHour,
        };
        assert_eq!(seen_policy(operator, CachePolicy::default()), operator);
        assert_eq!(seen_policy(operator, operator), operator);
    }
}
