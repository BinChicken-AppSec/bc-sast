//! The single-turn request/response shape `LlmClient::chat` speaks, common
//! to both the OpenAI-compatible chat-completions dialect and the
//! Anthropic-compatible Messages dialect.

use crate::cache::CachePolicy;
use crate::effort::ReasoningEffort;
use crate::message::{ContentBlock, Message};
use crate::openai_api::OpenAiApi;
use crate::tool::ToolSpec;

/// One model call. `thinking_budget` and `betas` are Anthropic-specific
/// extras that the OpenAI dialect silently ignores if set — same
/// accept-and-drop-if-unsupported behavior `backends/oai.py`'s `prompt()`/
/// `agentic()` already have for `thinking_budget`/`betas`, so callers don't
/// need to know which dialect they're talking to when building a request.
///
/// `Default` exists so a caller building one with struct-literal syntax
/// can end it with `..Default::default()` and keep compiling when a
/// transport field is added; its empty `model` and zero `max_tokens` are
/// placeholders every real caller overrides.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ChatRequest {
    pub model: String,
    pub system: Option<String>,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
    pub max_tokens: u32,
    /// `f64`, not `f32`: JSON has no native 32-bit float type, so a dialect
    /// crate serializing this straight into a request body via
    /// `serde_json` would otherwise widen it to `f64` at send time (e.g.
    /// `0.2f32 as f64` == `0.20000000298023224`) — every dialect crate
    /// sends this over JSON, so the field itself stays JSON-precision-safe.
    pub temperature: Option<f64>,
    /// Nucleus sampling. `f64` for the same JSON-precision reason as
    /// [`Self::temperature`]. Both dialects accept it, but the Anthropic
    /// Messages API rejects `temperature` and `top_p` in the same request
    /// — `bc-llm-anthropic` resolves that by sending `temperature` only
    /// when both are set, so a caller can set both without knowing which
    /// dialect it is talking to.
    pub top_p: Option<f64>,
    /// Deterministic-sampling seed. Emitted by the OpenAI dialect only
    /// (`seed`, best-effort reproducibility for a fixed
    /// `system_fingerprint`); the Anthropic Messages API has no seed
    /// parameter at all and silently drops this, same accept-and-drop
    /// handling every other dialect-specific extra on this struct gets.
    ///
    /// Net-new versus the Python original, which exposes only
    /// `models.<role>.temperature` (`backends/llm.py::resolve`) — a seed
    /// is the other half of making two back-to-back scans of the same
    /// repo agree, and costs nothing when the provider ignores it.
    pub seed: Option<u64>,
    pub thinking_budget: Option<u32>,
    pub betas: Vec<String>,
    /// Forces a structured-JSON response (OpenAI `response_format:
    /// json_object`); the Anthropic dialect has no equivalent wire flag and
    /// ignores this.
    pub json_mode: bool,
    /// Send this call as a server-sent-event STREAM and reassemble the
    /// pieces into the same [`ChatResponse`] a non-streamed call would
    /// have returned. `false` (the default everywhere) keeps the single
    /// JSON response body this port has always used.
    ///
    /// **Why it exists.** The Python original streams unconditionally
    /// (`backends/sdk.py:288-289`, "Stream so large max_tokens (64k)
    /// doesn't trip the HTTP timeout" — it only ever reads
    /// `stream.get_final_message()`, so streaming buys it nothing but
    /// the absence of one long silent socket). This port skipped it in
    /// favor of per-call timeouts ([`Self::timeout`]), which solves the
    /// same problem for a client that controls its own deadline — but
    /// not for a gateway or proxy in front of the provider that imposes
    /// its own idle timeout, which only a stream's steady trickle of
    /// bytes keeps alive.
    ///
    /// **Nothing else changes.** The dialect crates assemble the stream
    /// into exactly the response body a non-streaming call would have
    /// returned and parse THAT with the same parser, so text, tool_use
    /// blocks, usage and stop reason are identical either way and no
    /// caller can tell which mode ran. Retries and the same-call
    /// parameter corrections apply unchanged, and [`Self::timeout`]
    /// bounds the whole stream, not just its first byte.
    ///
    /// Set by `bc-cli`'s opt-in `--stream-large-responses` /
    /// `llm.stream_large_responses` (see
    /// [`crate::StreamLargeResponses`]), never by a stage — which
    /// request is large enough to be worth streaming is a transport
    /// question, not one a stage has any view on.
    pub stream: bool,
    /// Per-request wall-clock deadline, applied by the dialect crate on
    /// top of whichever default the shared `reqwest::Client` was built
    /// with (`bc_gateway_http::GatewayConfig::timeout`, 300 s). `None`
    /// keeps that client-wide default.
    ///
    /// Ported from the Python original's per-step `timeout` config keys,
    /// which both real backends honor per call rather than per client
    /// (`backends/sdk.py:274` and `backends/oai.py:278`, both
    /// `client.with_options(timeout=float(timeout))`). Without it, a
    /// stage asking for 64k output tokens over a 300 s client default
    /// fails on the clock rather than on the model.
    pub timeout: Option<std::time::Duration>,
    /// Reasoning-effort tier for a reasoning-class model (the Python
    /// original's `models.<role>.effort`). OpenAI dialect only: sent as
    /// `reasoning_effort` on Chat Completions and `reasoning.effort` on
    /// the Responses API; a model that rejects the tier is remembered and
    /// the call retried without it. The Anthropic dialect ignores it.
    pub reasoning_effort: Option<ReasoningEffort>,
    /// Per-request OpenAI transport pin (the Python original's per-role
    /// `use_responses_api`), overriding the OpenAI client's configured
    /// default. A request field rather than client configuration because
    /// one client serves every role. `None` keeps the client default;
    /// the Anthropic dialect ignores it.
    pub openai_api: Option<OpenAiApi>,
    /// A large, stable leading prefix shared by many calls (S4's shared
    /// context plus one shard's source, say), kept separate from the rest
    /// of the first user turn so each dialect can place it where its
    /// cache works best. The Anthropic dialect sends it as its own
    /// leading text block, marked as a cache breakpoint when the
    /// [`CachePolicy`] gate allows; the OpenAI dialect prepends it to the
    /// first user text, since its implicit prefix cache needs the stable
    /// part first. `None` sends the request byte-identical to one built
    /// before this field existed.
    pub cache_prefix: Option<String>,
    /// Caller-supplied, stable routing material for OpenAI's
    /// `prompt_cache_key` (stage and repository name, say). Never sent
    /// raw: the OpenAI dialect SHA-256s it together with the model (and a
    /// digest of [`Self::cache_prefix`], when present) and sends only the
    /// hash, and only when the prompt is estimated to clear OpenAI's
    /// 1,024-token caching floor. Must not carry secrets regardless. The
    /// Anthropic dialect ignores it.
    pub cache_key: Option<String>,
    /// The operator's prompt-cache policy. Stamped on every request by
    /// [`crate::ApplyCachePolicy`] where the client is built, like
    /// [`Self::stream`]; stages leave it at its default.
    pub cache: CachePolicy,
}

impl ChatRequest {
    /// A request with no tools, no system prompt, and no dialect extras —
    /// the common case for a single-shot `prompt()`-style call.
    pub fn new(model: impl Into<String>, messages: Vec<Message>, max_tokens: u32) -> Self {
        ChatRequest {
            model: model.into(),
            system: None,
            messages,
            tools: Vec::new(),
            max_tokens,
            temperature: None,
            top_p: None,
            seed: None,
            thinking_budget: None,
            betas: Vec::new(),
            json_mode: false,
            timeout: None,
            stream: false,
            reasoning_effort: None,
            openai_api: None,
            cache_prefix: None,
            cache_key: None,
            cache: CachePolicy::default(),
        }
    }
}

/// Normalizes OpenAI's `finish_reason` (`"stop"`/`"length"`/`"tool_calls"`/
/// `"content_filter"`) and Anthropic's `stop_reason` (`"end_turn"`/
/// `"max_tokens"`/`"tool_use"`/`"stop_sequence"`) onto one shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
    Other(String),
}

/// Token accounting, field names normalized to the Anthropic vocabulary —
/// matching `backends/oai.py`'s own comment that it normalizes OpenAI's
/// `prompt_tokens`/`completion_tokens`/cached-tokens onto these names "so
/// `util/tokens.py` sees one unified total across all three backends".
///
/// **The contract every dialect honors** (and `bc-pricing` relies on):
/// the three input fields are DISJOINT slices of one prompt, and add up
/// to its full size.
///
/// - `input_tokens`: the fresh, uncached remainder, billed at the base
///   input rate. Anthropic reports exactly this. OpenAI reports the whole
///   prompt (`prompt_tokens` on Chat Completions, `input_tokens` on the
///   Responses API), so its dialect subtracts both cache slices out.
/// - `cache_read_input_tokens`: served from cache, billed at the cache
///   read rate (Anthropic `cache_read_input_tokens`; OpenAI
///   `prompt_tokens_details.cached_tokens` /
///   `input_tokens_details.cached_tokens`).
/// - `cache_creation_input_tokens`: written to cache, billed at the cache
///   write rate. Anthropic `cache_creation_input_tokens` (the sum of both
///   lifetimes; which lifetime was used is the [`CachePolicy::ttl`] the
///   request carried, since every marker in one request uses the same
///   one). OpenAI reports a write only on models that bill one
///   (`cache_write_tokens`); everywhere else it is `0`, which is correct
///   data, not a gap.
/// - `output_tokens`: generated tokens, reasoning included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: u64,
    pub cache_read_input_tokens: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChatResponse {
    pub content: Vec<ContentBlock>,
    pub stop_reason: StopReason,
    pub usage: Usage,
}

impl ChatResponse {
    /// Concatenate every [`ContentBlock::Text`] block, matching the
    /// repeated `"".join(b.text for b in msg.content if type=="text")`
    /// pattern in both `backends/oai.py` and `backends/sdk.py`.
    pub fn text(&self) -> String {
        self.content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Every `(id, name, input)` tool call in this response, in order.
    pub fn tool_uses(&self) -> Vec<(&str, &str, &serde_json::Value)> {
        self.content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::ToolUse { id, name, input } => {
                    Some((id.as_str(), name.as_str(), input))
                }
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;

    #[test]
    fn chat_request_new_has_no_tools_or_extras() {
        let req = ChatRequest::new("gpt-4o", vec![Message::user_text("hi")], 1024);
        assert_eq!(req.model, "gpt-4o");
        assert!(req.system.is_none());
        assert!(req.tools.is_empty());
        assert_eq!(req.max_tokens, 1024);
        assert!(req.temperature.is_none());
        assert!(req.top_p.is_none());
        assert!(req.seed.is_none());
        assert!(req.thinking_budget.is_none());
        assert!(req.betas.is_empty());
        assert!(!req.json_mode);
        assert!(req.timeout.is_none());
        assert!(
            !req.stream,
            "streaming is opt-in — every existing caller keeps the single-response path"
        );
        assert!(req.reasoning_effort.is_none());
        assert!(req.openai_api.is_none());
        assert!(req.cache_prefix.is_none());
        assert!(req.cache_key.is_none());
        assert_eq!(req.cache, CachePolicy::default());
    }

    #[test]
    fn default_matches_new_apart_from_the_placeholders() {
        let from_default = ChatRequest {
            model: "m".to_string(),
            max_tokens: 7,
            ..ChatRequest::default()
        };
        assert_eq!(from_default, ChatRequest::new("m", Vec::new(), 7));
    }

    #[test]
    fn text_and_tool_uses_ignore_opaque_blocks() {
        let resp = ChatResponse {
            content: vec![
                ContentBlock::Opaque {
                    dialect: crate::message::OpaqueDialect::OpenAiResponses,
                    payload: serde_json::json!({"type": "reasoning"}),
                },
                ContentBlock::text("answer"),
            ],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        };
        assert_eq!(resp.text(), "answer");
        assert!(resp.tool_uses().is_empty());
    }

    #[test]
    fn stop_reason_equality() {
        assert_eq!(StopReason::EndTurn, StopReason::EndTurn);
        assert_eq!(
            StopReason::Other("x".to_string()),
            StopReason::Other("x".to_string())
        );
        assert_ne!(StopReason::EndTurn, StopReason::ToolUse);
    }

    #[test]
    fn usage_defaults_to_zero() {
        assert_eq!(
            Usage::default(),
            Usage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
            }
        );
    }

    #[test]
    fn chat_response_text_concatenates_text_blocks_and_skips_others() {
        let resp = ChatResponse {
            content: vec![
                ContentBlock::text("part one "),
                ContentBlock::ToolUse {
                    id: "1".to_string(),
                    name: "Read".to_string(),
                    input: serde_json::json!({}),
                },
                ContentBlock::text("part two"),
            ],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        };
        assert_eq!(resp.text(), "part one part two");
    }

    #[test]
    fn chat_response_text_is_empty_when_there_is_no_text_block() {
        let resp = ChatResponse {
            content: vec![ContentBlock::ToolUse {
                id: "1".to_string(),
                name: "Read".to_string(),
                input: serde_json::json!({}),
            }],
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        };
        assert_eq!(resp.text(), "");
    }

    #[test]
    fn chat_response_tool_uses_extracts_all_tool_calls_in_order() {
        let resp = ChatResponse {
            content: vec![
                ContentBlock::text("calling tools"),
                ContentBlock::ToolUse {
                    id: "1".to_string(),
                    name: "Read".to_string(),
                    input: serde_json::json!({"path": "a"}),
                },
                ContentBlock::ToolUse {
                    id: "2".to_string(),
                    name: "Glob".to_string(),
                    input: serde_json::json!({"pattern": "*.rs"}),
                },
            ],
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        };
        let calls = resp.tool_uses();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "1");
        assert_eq!(calls[0].1, "Read");
        assert_eq!(calls[0].2, &serde_json::json!({"path": "a"}));
        assert_eq!(calls[1].1, "Glob");
    }

    #[test]
    fn chat_response_tool_uses_is_empty_when_there_are_no_tool_calls() {
        let resp = ChatResponse {
            content: vec![ContentBlock::text("just text")],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        };
        assert!(resp.tool_uses().is_empty());
    }
}
