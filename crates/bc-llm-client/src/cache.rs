//! Prompt-cache policy shared by both dialects, so neither can disagree
//! with the other about when a cache hint is worth sending. Ported from
//! the Python original's `backends/llm/cache.py` (the `cache_markers`
//! kill switch and `CACHE_EST_MARGIN`), `backends/llm/sdk.py:346-371`
//! (the per-model minimum cacheable prefix table) and
//! `backends/llm/openai.py:294-310` (the flat 1,024-token OpenAI floor).
//!
//! Everything here is pure: the dialect crates decide *where* a marker or
//! key goes, this module decides *whether* one is worth placing.
//!
//! **Divergence from Python, deliberate**: `sdk.py` also gates every
//! Anthropic marker on a route classification sniffed from the base URL
//! host (`_cache_route`: Anthropic, Vertex, Bedrock or unknown, failing
//! closed on unknown). This port has no such gate: the operator already
//! states the wire dialect explicitly (`--dialect anthropic`), which is
//! the claim the host sniff exists to infer, and a gateway that is not in
//! fact Messages-compatible fails on far more than a cache marker. The
//! [`CachePolicy::markers`] kill switch covers the remaining case of a
//! strict gateway that rejects `cache_control` specifically.

use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use regex::Regex;
use serde_json::{json, Value};

use crate::chat::{ChatRequest, ChatResponse};
use crate::client::LlmClient;
use crate::error::LlmError;

/// How long an Anthropic cache entry lives after its last read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CacheTtl {
    /// The provider default. Writes bill at 1.25x the base input rate.
    #[default]
    FiveMinutes,
    /// The extended lifetime. Writes bill at 2x the base input rate, so
    /// it pays off only when the same prefix is re-read after a gap of
    /// more than five minutes (a long S6 verification queue, say).
    OneHour,
}

impl CacheTtl {
    /// The config and wire spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            CacheTtl::FiveMinutes => "5m",
            CacheTtl::OneHour => "1h",
        }
    }

    /// The Anthropic `cache_control` object for this lifetime. The
    /// five-minute form omits `ttl` entirely, byte-identical to what this
    /// port has always sent, so the default changes nothing on the wire.
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

/// The operator's prompt-cache policy. Rides on every
/// [`ChatRequest::cache`], stamped there by [`ApplyCachePolicy`] at the
/// one point the client is built, the same way `stream` is stamped by
/// [`crate::StreamLargeResponses`]: whether and how to cache is a
/// transport question no stage has a view on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    /// The kill switch (Python's `cache_markers: off`). `false` sends no
    /// Anthropic `cache_control` marker and no OpenAI `prompt_cache_key`
    /// at all. A cache prefix is still placed first in the prompt, since
    /// a stable leading prefix costs nothing and still lets an implicit
    /// cache hit.
    pub markers: bool,
    /// An operator-forced minimum cacheable block size in real tokens
    /// (Python's `cache_min_block_tokens`), replacing the per-model table
    /// for the Anthropic dialect. `None` uses the table.
    pub min_block_tokens: Option<u32>,
    /// The Anthropic cache lifetime every marker is sent with.
    pub ttl: CacheTtl,
}

impl Default for CachePolicy {
    /// Markers on, per-model minimums, five-minute lifetime: the Python
    /// original's defaults.
    fn default() -> Self {
        CachePolicy {
            markers: true,
            min_block_tokens: None,
            ttl: CacheTtl::FiveMinutes,
        }
    }
}

impl CachePolicy {
    /// The minimum cacheable prefix, in real tokens, a breakpoint on
    /// `model` must clear on the Anthropic dialect: the operator override
    /// when one is set, else [`anthropic_min_cacheable_tokens`].
    pub fn min_tokens_for(&self, model: &str) -> u32 {
        self.min_block_tokens
            .filter(|n| *n > 0)
            .unwrap_or_else(|| anthropic_min_cacheable_tokens(model))
    }

    /// Whether an Anthropic breakpoint ending a prefix of
    /// `cumulative_estimated_tokens` (estimated with [`estimate_tokens`],
    /// counted from the start of the rendered request: tools, then
    /// system, then messages) is worth placing on `model`.
    ///
    /// Below the minimum the API silently caches nothing while the marker
    /// still spends one of the request's four breakpoint slots, so a
    /// sub-minimum marker is pure waste. The estimate is scaled by
    /// [`CACHE_EST_MARGIN_PERCENT`] first, resolving a borderline
    /// estimate toward marking, since refusing a cacheable block re-sends
    /// its whole prefix at full price on every later call.
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

    /// Whether an OpenAI `prompt_cache_key` is worth sending for a prompt
    /// of `estimated_prompt_tokens`: the kill switch is on and the prompt
    /// clears [`OPENAI_MIN_CACHEABLE_PROMPT_TOKENS`]. Below that floor
    /// OpenAI caches nothing, so a key would only add a field a strict
    /// gateway might reject.
    pub fn openai_cache_key_worth_sending(&self, estimated_prompt_tokens: u64) -> bool {
        self.markers
            && clears_floor(
                estimated_prompt_tokens,
                u64::from(OPENAI_MIN_CACHEABLE_PROMPT_TOKENS),
            )
    }
}

/// Boundary margin applied to an [`estimate_tokens`] figure before it is
/// compared with a provider's minimum, as a percentage. Python's
/// `CACHE_EST_MARGIN = 1.35`: the offline estimate under-counts against
/// the real tokenizer by up to about that factor, and the cost of the
/// error is asymmetric (an inert marker wastes a free slot, a refused
/// cacheable block re-bills its whole prefix), so a block whose estimate
/// is within its own error of the floor is marked.
pub const CACHE_EST_MARGIN_PERCENT: u64 = 135;

/// OpenAI's documented minimum cacheable prompt, in real tokens, counted
/// cumulatively from the start of the request. One flat floor, as in
/// `openai.py::_CACHE_MIN_PROMPT_TOKENS`: OpenAI documents a single
/// minimum for every model.
pub const OPENAI_MIN_CACHEABLE_PROMPT_TOKENS: u32 = 1024;

fn clears_floor(estimated_tokens: u64, floor: u64) -> bool {
    estimated_tokens.saturating_mul(CACHE_EST_MARGIN_PERCENT) >= floor.saturating_mul(100)
}

/// A cheap, deterministic token estimate: one token per four characters,
/// rounded up.
///
/// Four characters per token is the long-standing rule of thumb for
/// English prose under both providers' tokenizers; source code tokenizes
/// denser (closer to three), which this under-counts, and which
/// [`CACHE_EST_MARGIN_PERCENT`] absorbs. The Python original uses a
/// content-aware estimator (`util/tokens.py::estimate_tokens`); a plain
/// character count is used here because the estimate only ever decides
/// whether a cache hint is worth sending, never a budget, and a
/// dependency-free rule is easier to reason about when it is wrong.
/// Counted in Unicode scalars, not bytes, so non-ASCII text is not
/// inflated three- or four-fold.
pub fn estimate_tokens(text: &str) -> u64 {
    (text.chars().count() as u64).div_ceil(4)
}

/// The Anthropic per-model minimum cacheable prefix table, in real
/// tokens, ported verbatim from `sdk.py::_CACHE_MIN_TOKENS_TABLE`. First
/// match wins, so specific minors precede their bare-family catch-alls.
/// The sequence is NOT monotonic across releases (opus-4-5/4-6 need more
/// than 4-7, which needs more than 4-8), so no version-ordering heuristic
/// is safe.
static ANTHROPIC_MIN_TOKENS_TABLE: LazyLock<Vec<(Regex, u32)>> = LazyLock::new(|| {
    [
        (r"(?i)opus-5|fable-5", 512),
        (r"(?i)opus-4[-.]?[56]|haiku-4[-.]?5", 4096),
        (r"(?i)opus-4[-.]?7|haiku-3[-.]?5", 2048),
        // opus-4, opus-4-1, opus-4-8 and every sonnet-4* / sonnet-5*.
        (r"(?i)opus-4|sonnet-[45]", 1024),
    ]
    .into_iter()
    .map(|(pattern, floor)| (Regex::new(pattern).expect("static pattern"), floor))
    .collect()
});

/// An unseen model gets the largest published minimum
/// (`_CACHE_MIN_TOKENS_FALLBACK`): marking below a real minimum wastes a
/// slot, so an unknown model is assumed to need the most.
pub const ANTHROPIC_MIN_TOKENS_FALLBACK: u32 = 4096;

/// The minimum cacheable prefix, in real tokens, Anthropic publishes for
/// `model`: the [`crate::capabilities`] row when the model is known
/// there, else the first matching pattern of the Python original's
/// table (which also catches gateway aliases that merely CONTAIN a family
/// name, `my-opus-4-7-deploy` say), else
/// [`ANTHROPIC_MIN_TOKENS_FALLBACK`].
pub fn anthropic_min_cacheable_tokens(model: &str) -> u32 {
    if let Some(floor) = crate::capabilities::capabilities(model).cache_min_tokens {
        return floor;
    }
    ANTHROPIC_MIN_TOKENS_TABLE
        .iter()
        .find(|(rx, _)| rx.is_match(model))
        .map_or(ANTHROPIC_MIN_TOKENS_FALLBACK, |(_, floor)| *floor)
}

/// Stamps an operator [`CachePolicy`] onto every request passing through,
/// so the dialect crates see the policy without any stage threading it.
/// Built once, in `bc-cli::build_llm_client`, beside
/// [`crate::StreamLargeResponses`].
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

    /// Table-tested against `sdk.py::_CACHE_MIN_TOKENS_TABLE`, including
    /// its non-monotonic ordering and the separator variants.
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
            // Unknown to the capability table, caught by the patterns.
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
        // Scalars, not bytes: four 4-byte characters are one token.
        assert_eq!(estimate_tokens("🙂🙂🙂🙂"), 1);
    }

    #[test]
    fn the_marker_gate_applies_the_margin_and_the_kill_switch() {
        let p = CachePolicy::default();
        // sonnet floor 1024: 1024 / 1.35 = 758.5, so 759 clears, 758 not.
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
        // Already equal: passed through untouched.
        assert_eq!(seen_policy(operator, operator), operator);
    }
}
