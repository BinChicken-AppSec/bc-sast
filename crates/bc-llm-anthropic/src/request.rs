//! `ChatRequest` -> Anthropic Messages API JSON request body, ported from
//! the request-shape half of `backends/sdk.py`'s `agentic()`.
//!
//! What each model accepts comes from `bc_llm_client::capabilities`:
//! sampling parameters, the thinking form and effort tiers
//! ([`crate::thinking`]), and the output ceiling are all settled before
//! anything is sent. Cache breakpoints are placed by
//! [`crate::cache_markers`]. Whatever the table gets wrong is corrected
//! and remembered by [`crate::corrections`].

use bc_llm_client::capabilities::{capabilities, warn_param_once, Sampling};
use bc_llm_client::{ChatRequest, ContentBlock, Message, OpaqueDialect, Role, ToolSpec};
use serde_json::{json, Value};

use crate::cache_markers::{markable, Breakpoints};
use crate::thinking;

/// The body to send: [`build_body`], with everything already learned
/// about the model applied.
pub fn build_request_body(request: &ChatRequest) -> Value {
    let mut body = build_body(request);
    crate::corrections::apply_learned(&request.model, &mut body);
    body
}

/// The body the capability table and cache policy alone produce.
pub fn build_body(request: &ChatRequest) -> Value {
    let model = request.model.as_str();
    let caps = capabilities(model);
    let max_tokens = caps.clamp_max_tokens(request.max_tokens);
    if max_tokens < request.max_tokens {
        warn_param_once(
            model,
            "max_tokens",
            &format!("capped at the model's {max_tokens}-token output ceiling"),
        );
    }
    let plan = thinking::plan(
        model,
        &caps,
        request.thinking_budget,
        request.reasoning_effort,
        max_tokens,
    );
    let mut breakpoints = Breakpoints::new(&request.cache, model);

    let mut tools: Vec<Value> = request.tools.iter().map(to_anthropic_tool).collect();
    for tool in &tools {
        breakpoints.add(&tool.to_string());
    }
    if let Some(last) = tools.last_mut() {
        breakpoints.place(last);
    }

    let system = request.system.as_ref().map(|system| {
        breakpoints.add(system);
        // Prompt-cache the system block: S4 fires the same large system
        // prompt N x runs x chunks, and S6/S3/S8 similarly repeat theirs.
        // Ported from `sdk.py::_build_system_content`, gate included.
        let mut block = json!({"type": "text", "text": system});
        breakpoints.place(&mut block);
        Value::Array(vec![block])
    });

    let mut messages = to_anthropic_messages(&request.messages);
    if let Some(prefix) = request.cache_prefix.as_deref().filter(|p| !p.is_empty()) {
        insert_cache_prefix(&mut messages, prefix, &mut breakpoints);
    }
    for block in request.messages.iter().flat_map(|m| &m.content) {
        breakpoints.add(&estimate_text(block));
    }
    // Only a multi-turn request gets the per-turn marker; see
    // `mark_latest_turn_for_caching`.
    if request.messages.len() > 1 {
        mark_latest_turn_for_caching(&mut messages, &mut breakpoints);
    }

    let mut body = json!({
        "model": request.model,
        "max_tokens": max_tokens,
        "messages": messages,
    });
    if let Some(system) = system {
        body["system"] = system;
    }
    if !tools.is_empty() {
        body["tools"] = Value::Array(tools);
    }
    apply_sampling(&mut body, request, caps.sampling, plan.thinking_active);
    // `request.seed` is deliberately not emitted: the Messages API has no
    // seed parameter, and sending an unknown top-level key is a 400.
    if let Some(thinking) = plan.thinking {
        body["thinking"] = thinking;
    }
    if let Some(effort) = plan.effort {
        body["output_config"] = json!({"effort": effort.as_str()});
    }
    if request.stream {
        // No `stream_options` counterpart here: the Messages API always
        // reports usage over a stream (input side on `message_start`,
        // output side on `message_delta`), so unlike the
        // chat-completions dialect nothing extra has to be asked for.
        body["stream"] = json!(true);
    }
    body
}

/// `temperature`/`top_p`, as far as the model and this request allow.
///
/// Both are dropped (with a once-per-model warning) when the model
/// rejects sampling, or when it will think on this request: the Messages
/// API rejects a non-default value alongside extended thinking.
///
/// Otherwise the Messages API still rejects `temperature` and `top_p` in
/// the same request, so one has to win. `temperature` does: it's the knob
/// the Python original exposes per model role (`backends/llm.py::resolve`
/// reads only `models.<role>.temperature`), so a config that sets both is
/// near-certainly carrying `top_p` for an OpenAI-dialect role.
fn apply_sampling(body: &mut Value, request: &ChatRequest, sampling: Sampling, thinking: bool) {
    let model = request.model.as_str();
    if sampling == Sampling::Rejected || thinking {
        let why = if thinking {
            "extended thinking is on for this request; not sent"
        } else {
            "the model rejects it; not sent"
        };
        for (param, value) in [
            ("temperature", request.temperature),
            ("top_p", request.top_p),
        ] {
            if value.is_some() {
                warn_param_once(model, param, why);
            }
        }
        return;
    }
    match (request.temperature, request.top_p) {
        (Some(temperature), Some(top_p)) => {
            tracing::debug!(
                "[anthropic] both temperature ({temperature}) and top_p ({top_p}) were set; \
                 the Messages API accepts only one — sending temperature and dropping top_p."
            );
            body["temperature"] = json!(temperature);
        }
        (Some(temperature), None) => body["temperature"] = json!(temperature),
        (None, Some(top_p)) => body["top_p"] = json!(top_p),
        (None, None) => {}
    }
}

/// Put the cache prefix in front of the first user turn as its own text
/// block, marked as a breakpoint when the gate allows and something
/// follows it (a breakpoint with an empty remainder buys nothing). Ported
/// from `sdk.py::_build_cache_prefix_content`.
fn insert_cache_prefix(messages: &mut [Value], prefix: &str, breakpoints: &mut Breakpoints) {
    let Some(content) = messages
        .iter_mut()
        .find(|m| m["role"] == "user")
        .and_then(|m| m["content"].as_array_mut())
    else {
        return;
    };
    breakpoints.add(prefix);
    let mut block = json!({"type": "text", "text": prefix});
    if !content.is_empty() {
        breakpoints.place(&mut block);
    }
    content.insert(0, block);
}

/// The text a block contributes to the cumulative cache estimate: what
/// this dialect actually sends for it (nothing, for a foreign opaque
/// block).
fn estimate_text(block: &ContentBlock) -> String {
    match block {
        ContentBlock::Text(text) => text.clone(),
        ContentBlock::ToolUse { input, .. } => input.to_string(),
        ContentBlock::ToolResult { content, .. } => content.clone(),
        other => other
            .opaque_for(OpaqueDialect::Anthropic)
            .map(Value::to_string)
            .unwrap_or_default(),
    }
}

/// Anthropic's Messages API requires strict user/assistant role
/// alternation, so consecutive [`Role::Tool`] messages (one per tool call
/// `bc-llm-agentic` executed from a single assistant turn — see
/// [`Message::tool_result`]) must be folded into a single `user`-role
/// message with multiple `tool_result` blocks, matching
/// `backends/sdk.py`'s `messages.append({"role": "user", "content":
/// results})` after a turn's tool calls all run.
fn to_anthropic_messages(messages: &[Message]) -> Vec<Value> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < messages.len() {
        if messages[i].role == Role::Tool {
            let mut blocks = Vec::new();
            while i < messages.len() && messages[i].role == Role::Tool {
                blocks.extend(messages[i].content.iter().filter_map(to_anthropic_block));
                i += 1;
            }
            out.push(json!({"role": "user", "content": blocks}));
        } else {
            let role = if messages[i].role == Role::User {
                "user"
            } else {
                "assistant"
            };
            let blocks: Vec<Value> = messages[i]
                .content
                .iter()
                .filter_map(to_anthropic_block)
                .collect();
            out.push(json!({"role": role, "content": blocks}));
            i += 1;
        }
    }
    out
}

/// Put ONE `cache_control` marker on the last markable content block of
/// the most recent user/tool-result message, extending the cached prefix
/// past the system prompt to cover the whole conversation so far. Ported
/// from `backends/sdk.py::_with_cache_marker`, which `agentic()` applies
/// to `messages` on every turn (sdk.py:410-432, 495, 568).
///
/// Returns whether a marker was actually placed (the cache gate can
/// refuse it).
///
/// **Divergence from Python, deliberate**: `_with_cache_marker` is applied
/// by `agentic()` only, never by `prompt()`; the caller here gates on
/// `messages.len() > 1` instead of on the presence of tools, because this
/// port's forced-final agentic turn sends an EMPTY tool list (see
/// `bc_llm_agentic::session::run_agentic`) while carrying the longest
/// history of the whole session — exactly the call that most needs the
/// marker. A single-shot stage call is left unmarked: its user prompt is
/// unique per call, so a cache write nobody ever reads back would be a
/// flat ~25% surcharge on it.
fn mark_latest_turn_for_caching(messages: &mut [Value], breakpoints: &mut Breakpoints) -> bool {
    let Some(last_user) = messages.iter_mut().rfind(|m| m["role"] == "user") else {
        return false;
    };
    let Some(block) = last_user["content"]
        .as_array_mut()
        .and_then(|c| c.iter_mut().rfind(|b| markable(b)))
    else {
        return false;
    };
    breakpoints.place(block)
}

/// One neutral block in this dialect's shape, or `None` for an opaque
/// block that belongs to another dialect (never replayable here).
/// Anthropic's own opaque blocks (`thinking`, `redacted_thinking`) are
/// replayed verbatim, signature included: the API verifies it when
/// extended thinking and tool use are combined.
fn to_anthropic_block(block: &ContentBlock) -> Option<Value> {
    Some(match block {
        ContentBlock::Text(text) => json!({"type": "text", "text": text}),
        ContentBlock::ToolUse { id, name, input } => {
            json!({"type": "tool_use", "id": id, "name": name, "input": input})
        }
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } => {
            let mut value = json!({
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": content,
            });
            if *is_error {
                value["is_error"] = json!(true);
            }
            value
        }
        other => other.opaque_for(OpaqueDialect::Anthropic)?.clone(),
    })
}

fn to_anthropic_tool(spec: &ToolSpec) -> Value {
    json!({
        "name": spec.name,
        "description": spec.description,
        "input_schema": spec.parameters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::{CachePolicy, CacheTtl, ReasoningEffort};

    /// A policy whose minimum every test prompt clears, for tests about
    /// WHERE markers go rather than whether the gate allows them.
    fn markable_policy() -> CachePolicy {
        CachePolicy {
            min_block_tokens: Some(1),
            ..CachePolicy::default()
        }
    }

    fn marked(mut req: ChatRequest) -> ChatRequest {
        req.cache = markable_policy();
        req
    }

    fn marker_count(body: &Value) -> usize {
        body.to_string().matches("cache_control").count()
    }

    fn read_tool() -> ToolSpec {
        ToolSpec {
            name: "Read".to_string(),
            description: "read a file".to_string(),
            parameters: json!({"type": "object"}),
        }
    }

    #[test]
    fn minimal_request_has_model_max_tokens_and_messages_only() {
        let req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        let body = build_request_body(&req);
        assert_eq!(
            body,
            json!({
                "model": "claude-opus-4-6",
                "max_tokens": 512,
                "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
            })
        );
    }

    #[test]
    fn a_non_streaming_request_carries_no_stream_key() {
        let body = build_request_body(&ChatRequest::new("claude", vec![], 512));
        assert!(body.get("stream").is_none());
    }

    #[test]
    fn a_streaming_request_sets_stream_and_nothing_else() {
        let mut req = ChatRequest::new("claude", vec![Message::user_text("hi")], 512);
        req.stream = true;
        let body = build_request_body(&req);
        assert_eq!(body["stream"], true);
        // No `stream_options` counterpart: an unknown key is a 400.
        assert!(body.get("stream_options").is_none());
        assert_eq!(body["max_tokens"], 512);
    }

    #[test]
    fn a_seed_is_never_sent_because_the_messages_api_has_no_such_parameter() {
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.seed = Some(42);
        assert!(build_request_body(&req).get("seed").is_none());
    }

    #[test]
    fn top_p_is_sent_when_temperature_is_unset() {
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.top_p = Some(0.1);
        let body = build_request_body(&req);
        assert_eq!(body["top_p"], 0.1);
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn temperature_wins_and_top_p_is_dropped_when_both_are_set() {
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.temperature = Some(0.0);
        req.top_p = Some(0.1);
        let body = build_request_body(&req);
        assert_eq!(body["temperature"], 0.0);
        assert!(body.get("top_p").is_none());
    }

    /// `--temperature 0` against Opus 4.7 or later was a guaranteed 400.
    #[test]
    fn a_model_that_rejects_sampling_gets_none_of_it() {
        for model in ["claude-opus-4-7", "claude-opus-5", "claude-fable-5-1"] {
            let mut req = ChatRequest::new(model, vec![Message::user_text("hi")], 512);
            req.temperature = Some(0.0);
            req.top_p = Some(0.1);
            let body = build_request_body(&req);
            assert!(body.get("temperature").is_none(), "{model}");
            assert!(body.get("top_p").is_none(), "{model}");
        }
    }

    #[test]
    fn sampling_is_dropped_when_thinking_is_on() {
        let mut req = ChatRequest::new("claude-sonnet-4-5", vec![Message::user_text("hi")], 8000);
        req.temperature = Some(0.2);
        req.top_p = Some(0.9);
        req.thinking_budget = Some(4000);
        let body = build_request_body(&req);
        assert_eq!(
            body["thinking"],
            json!({"type": "enabled", "budget_tokens": 4000})
        );
        assert!(body.get("temperature").is_none());
        assert!(body.get("top_p").is_none());
    }

    #[test]
    fn adaptive_models_get_adaptive_thinking_and_output_config_effort() {
        let mut req = ChatRequest::new("claude-opus-4-7", vec![Message::user_text("hi")], 512);
        req.thinking_budget = Some(4000);
        req.reasoning_effort = Some(ReasoningEffort::XHigh);
        let body = build_request_body(&req);
        assert_eq!(body["thinking"], json!({"type": "adaptive"}));
        assert_eq!(body["output_config"], json!({"effort": "xhigh"}));
    }

    #[test]
    fn max_tokens_is_capped_at_the_model_ceiling() {
        let req = ChatRequest::new("claude-sonnet-4-5", vec![Message::user_text("hi")], 200_000);
        assert_eq!(build_request_body(&req)["max_tokens"], 64_000);
    }

    #[test]
    fn a_small_system_prompt_is_not_marked_below_the_model_minimum() {
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.system = Some("be helpful".to_string());
        let body = build_request_body(&req);
        assert_eq!(
            body["system"],
            json!([{"type": "text", "text": "be helpful"}])
        );
        assert_eq!(marker_count(&body), 0);
    }

    #[test]
    fn a_system_prompt_over_the_minimum_is_marked_with_the_default_policy() {
        let big = "rule ".repeat(4_000);
        let mut req = ChatRequest::new("claude-sonnet-4-5", vec![Message::user_text("hi")], 512);
        req.system = Some(big.clone());
        let body = build_request_body(&req);
        assert_eq!(
            body["system"],
            json!([{"type": "text", "text": big, "cache_control": {"type": "ephemeral"}}])
        );
    }

    #[test]
    fn the_kill_switch_removes_every_marker() {
        let mut req = marked(ChatRequest::new(
            "claude-opus-4-6",
            vec![
                Message::user_text("q"),
                Message::assistant(vec![ContentBlock::text("a")]),
                Message::tool_result("1", "r", false),
            ],
            512,
        ));
        req.system = Some("s".into());
        req.tools.push(read_tool());
        req.cache_prefix = Some("p".into());
        req.cache.markers = false;
        assert_eq!(marker_count(&build_request_body(&req)), 0);
    }

    #[test]
    fn a_one_hour_ttl_is_sent_on_every_marker() {
        let mut req = marked(ChatRequest::new(
            "claude-opus-4-6",
            vec![Message::user_text("hi")],
            512,
        ));
        req.system = Some("be helpful".into());
        req.cache.ttl = CacheTtl::OneHour;
        let body = build_request_body(&req);
        assert_eq!(
            body["system"][0]["cache_control"],
            json!({"type": "ephemeral", "ttl": "1h"})
        );
    }

    #[test]
    fn a_single_shot_request_carries_no_per_turn_cache_marker() {
        let mut req = marked(ChatRequest::new(
            "claude-opus-4-6",
            vec![Message::user_text("hi")],
            512,
        ));
        req.system = Some("be helpful".to_string());
        let body = build_request_body(&req);
        assert!(body["messages"][0]["content"][0]
            .get("cache_control")
            .is_none());
        assert_eq!(
            body["system"][0]["cache_control"],
            json!({"type": "ephemeral"})
        );
    }

    #[test]
    fn a_multi_turn_request_marks_the_latest_tool_result_block_for_caching() {
        let mut req = marked(ChatRequest::new(
            "claude-opus-4-6",
            vec![
                Message::user_text("find the bug"),
                Message::assistant(vec![ContentBlock::ToolUse {
                    id: "1".to_string(),
                    name: "Read".to_string(),
                    input: json!({}),
                }]),
                Message::tool_result("1", "first result", false),
                Message::tool_result("2", "second result", false),
            ],
            512,
        ));
        req.system = Some("be helpful".to_string());
        let body = build_request_body(&req);
        let messages = body["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3);
        assert!(messages[0]["content"][0].get("cache_control").is_none());
        assert!(messages[2]["content"][0].get("cache_control").is_none());
        assert_eq!(
            messages[2]["content"][1]["cache_control"],
            json!({"type": "ephemeral"})
        );
    }

    #[test]
    fn at_most_two_markers_without_tools_or_a_prefix_however_long_the_session() {
        let mut messages = vec![Message::user_text("start")];
        for i in 0..10 {
            messages.push(Message::assistant(vec![ContentBlock::ToolUse {
                id: i.to_string(),
                name: "Read".to_string(),
                input: json!({}),
            }]));
            messages.push(Message::tool_result(i.to_string(), "result", false));
        }
        let mut req = marked(ChatRequest::new("claude-opus-4-6", messages, 512));
        req.system = Some("be helpful".to_string());
        assert_eq!(marker_count(&build_request_body(&req)), 2);
    }

    /// All four kinds at once: tools, system, prefix, tail. Never five.
    #[test]
    fn tools_system_prefix_and_tail_spend_exactly_the_four_breakpoints() {
        let mut req = marked(ChatRequest::new(
            "claude-opus-4-6",
            vec![
                Message::user_text("question"),
                Message::assistant(vec![ContentBlock::ToolUse {
                    id: "1".into(),
                    name: "Read".into(),
                    input: json!({}),
                }]),
                Message::tool_result("1", "result", false),
            ],
            512,
        ));
        req.system = Some("be helpful".into());
        req.tools = vec![read_tool(), read_tool()];
        req.cache_prefix = Some("SHARED CONTEXT".into());
        let body = build_request_body(&req);
        assert_eq!(marker_count(&body), 4);
        // The LAST tool carries the marker, not the first.
        assert!(body["tools"][0].get("cache_control").is_none());
        assert_eq!(
            body["tools"][1]["cache_control"],
            json!({"type": "ephemeral"})
        );
        assert_eq!(
            body["messages"][0]["content"],
            json!([
                {"type": "text", "text": "SHARED CONTEXT", "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": "question"},
            ])
        );
        assert_eq!(
            body["messages"][2]["content"][0]["cache_control"],
            json!({"type": "ephemeral"})
        );
    }

    #[test]
    fn the_tool_marker_needs_the_tools_alone_to_clear_the_minimum() {
        // Default policy: one short tool is far below any minimum.
        let mut req = ChatRequest::new("claude-sonnet-4-5", vec![Message::user_text("q")], 512);
        req.tools.push(read_tool());
        let body = build_request_body(&req);
        assert_eq!(marker_count(&body), 0);
        assert_eq!(
            body["tools"],
            json!([{"name": "Read", "description": "read a file", "input_schema": {"type": "object"}}])
        );
    }

    #[test]
    fn a_prefix_with_nothing_after_it_is_sent_unmarked() {
        let mut req = marked(ChatRequest::new(
            "claude-opus-4-6",
            vec![Message {
                role: Role::User,
                content: vec![],
            }],
            512,
        ));
        req.cache_prefix = Some("P".into());
        let body = build_request_body(&req);
        assert_eq!(
            body["messages"][0]["content"],
            json!([{"type": "text", "text": "P"}])
        );
    }

    #[test]
    fn a_prefix_without_a_user_turn_or_empty_is_not_sent() {
        let mut req = marked(ChatRequest::new(
            "claude-opus-4-6",
            vec![Message::assistant(vec![ContentBlock::text("a")])],
            512,
        ));
        req.cache_prefix = Some("P".into());
        let body = build_request_body(&req);
        assert!(!body.to_string().contains("\"P\""));
        req.messages = vec![Message::user_text("q")];
        req.cache_prefix = Some(String::new());
        let body = build_request_body(&req);
        assert_eq!(body["messages"][0]["content"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn the_marker_lands_on_the_last_user_turn_even_when_an_assistant_turn_follows() {
        let req = marked(ChatRequest::new(
            "claude-opus-4-6",
            vec![
                Message::user_text("question"),
                Message::assistant(vec![ContentBlock::text("partial answer")]),
            ],
            512,
        ));
        let body = build_request_body(&req);
        assert_eq!(
            body["messages"][0]["content"][0]["cache_control"],
            json!({"type": "ephemeral"})
        );
        assert!(body["messages"][1]["content"][0]
            .get("cache_control")
            .is_none());
    }

    #[test]
    fn marking_a_message_list_with_no_user_turn_is_a_no_op() {
        let policy = markable_policy();
        let mut bp = Breakpoints::new(&policy, "m");
        let mut messages =
            vec![json!({"role": "assistant", "content": [{"type": "text", "text": "x"}]})];
        assert!(!mark_latest_turn_for_caching(&mut messages, &mut bp));
    }

    #[test]
    fn marking_a_user_turn_with_nothing_markable_is_a_no_op() {
        let policy = markable_policy();
        let mut bp = Breakpoints::new(&policy, "m");
        bp.add("abcd");
        let mut messages = vec![json!({"role": "user", "content": []})];
        assert!(!mark_latest_turn_for_caching(&mut messages, &mut bp));
        let mut thinking_only =
            vec![json!({"role": "user", "content": [{"type": "thinking", "thinking": "t"}]})];
        assert!(!mark_latest_turn_for_caching(&mut thinking_only, &mut bp));
    }

    #[test]
    fn system_prompt_is_a_top_level_field_not_a_message() {
        let mut req = ChatRequest::new("claude-opus-4-6", vec![Message::user_text("hi")], 512);
        req.system = Some("be helpful".to_string());
        let body = build_request_body(&req);
        assert_eq!(body["system"][0]["text"], "be helpful");
        assert_eq!(body["messages"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn assistant_message_with_text_and_tool_use() {
        let messages = vec![Message::assistant(vec![
            ContentBlock::text("looking it up"),
            ContentBlock::ToolUse {
                id: "1".to_string(),
                name: "Glob".to_string(),
                input: json!({}),
            },
        ])];
        let out = to_anthropic_messages(&messages);
        assert_eq!(
            Value::Array(out),
            json!([{
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "looking it up"},
                    {"type": "tool_use", "id": "1", "name": "Glob", "input": {}},
                ],
            }])
        );
    }

    /// Thinking blocks go back verbatim, signature and all, ahead of the
    /// tool call they led to; another dialect's opaque blocks never do.
    #[test]
    fn thinking_blocks_are_replayed_verbatim_and_foreign_ones_dropped() {
        let thinking = json!({"type": "thinking", "thinking": "hmm", "signature": "sig=="});
        let redacted = json!({"type": "redacted_thinking", "data": "cipher"});
        let messages = vec![
            Message::assistant(vec![
                ContentBlock::Opaque {
                    dialect: OpaqueDialect::Anthropic,
                    payload: thinking.clone(),
                },
                ContentBlock::Opaque {
                    dialect: OpaqueDialect::Anthropic,
                    payload: redacted.clone(),
                },
                ContentBlock::Opaque {
                    dialect: OpaqueDialect::OpenAiResponses,
                    payload: json!({"type": "reasoning"}),
                },
                ContentBlock::ToolUse {
                    id: "t1".into(),
                    name: "Read".into(),
                    input: json!({}),
                },
            ]),
            Message {
                role: Role::Tool,
                content: vec![ContentBlock::Opaque {
                    dialect: OpaqueDialect::OpenAiResponses,
                    payload: json!(1),
                }],
            },
        ];
        let out = to_anthropic_messages(&messages);
        assert_eq!(
            out[0]["content"],
            json!([thinking, redacted, {"type": "tool_use", "id": "t1", "name": "Read", "input": {}}])
        );
        assert_eq!(out[1]["content"], json!([]));
    }

    #[test]
    fn a_single_tool_result_message_becomes_a_user_message_with_one_block() {
        let messages = vec![Message::tool_result("call_1", "contents", false)];
        let out = to_anthropic_messages(&messages);
        assert_eq!(
            Value::Array(out),
            json!([{
                "role": "user",
                "content": [{"type": "tool_result", "tool_use_id": "call_1", "content": "contents"}],
            }])
        );
    }

    #[test]
    fn an_error_tool_result_sets_is_error() {
        let messages = vec![Message::tool_result("call_1", "boom", true)];
        let out = to_anthropic_messages(&messages);
        assert_eq!(out[0]["content"][0]["is_error"], true);
    }

    #[test]
    fn consecutive_tool_messages_are_folded_into_one_user_message() {
        let messages = vec![
            Message::assistant(vec![ContentBlock::text("using two tools")]),
            Message::tool_result("call_1", "result one", false),
            Message::tool_result("call_2", "result two", false),
            Message::user_text("thanks"),
        ];
        let out = to_anthropic_messages(&messages);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0]["role"], "assistant");
        assert_eq!(out[1]["role"], "user");
        assert_eq!(out[1]["content"].as_array().unwrap().len(), 2);
        assert_eq!(out[1]["content"][0]["tool_use_id"], "call_1");
        assert_eq!(out[1]["content"][1]["tool_use_id"], "call_2");
        assert_eq!(out[2]["role"], "user");
        assert_eq!(out[2]["content"][0]["text"], "thanks");
    }

    #[test]
    fn the_estimate_counts_only_what_this_dialect_sends() {
        assert_eq!(estimate_text(&ContentBlock::text("t")), "t");
        assert_eq!(
            estimate_text(&ContentBlock::ToolUse {
                id: "1".into(),
                name: "n".into(),
                input: json!({"a": 1}),
            }),
            "{\"a\":1}"
        );
        assert_eq!(
            estimate_text(&Message::tool_result("1", "r", false).content[0]),
            "r"
        );
        let own = ContentBlock::Opaque {
            dialect: OpaqueDialect::Anthropic,
            payload: json!("x"),
        };
        assert_eq!(estimate_text(&own), "\"x\"");
        let foreign = ContentBlock::Opaque {
            dialect: OpaqueDialect::OpenAiResponses,
            payload: json!("x"),
        };
        assert_eq!(estimate_text(&foreign), "");
    }

    #[test]
    fn a_learned_correction_is_applied_to_the_built_body() {
        let model = "request-rs-learned-top-p";
        let mut first = json!({"top_p": 1});
        assert!(crate::corrections::correct(
            model,
            &mut first,
            "top_p rejected"
        ));
        let mut req = ChatRequest::new(model, vec![Message::user_text("hi")], 512);
        req.top_p = Some(0.3);
        assert!(build_body(&req).get("top_p").is_some());
        assert!(build_request_body(&req).get("top_p").is_none());
    }
}
