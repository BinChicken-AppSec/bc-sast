//! OpenAI prompt-cache support shared by both request shapes: the
//! `prompt_cache_key` routing hint and the `cache_prefix` placement.
//! Ported from `backends/llm/openai.py:294-364` (`_prompt_cache_key`,
//! `_prefix_meets_cache_minimum`).
//!
//! OpenAI caches implicitly: any prompt of 1,024 tokens or more whose
//! leading bytes match a recent request's may be served from cache. The
//! key only biases load-balancing toward a server already holding the
//! prefix, so a miss costs nothing but the discount. Two rules follow:
//! the stable prefix must come FIRST (hence the prefix placement), and
//! the key must group exactly the calls that can hit each other's cache.
//!
//! **Security.** The key is a SHA-256 digest of the caller's routing
//! material, the model and (when present) a digest of the cache prefix.
//! No repository path, prompt content or credential ever reaches the
//! wire through it.
//!
//! **Divergence from Python, deliberate**: `_prompt_cache_key` derives
//! its material itself (stage tag, tracker repo name) and spreads a
//! prefix-less stage over an 8-way shard ring to stay under OpenAI's
//! ~15 requests/minute per-key guidance. Here the caller supplies the
//! material ([`bc_llm_client::ChatRequest::cache_key`]), so a fan-out
//! stage that wants sharding appends its own shard suffix; this module
//! only hashes.

use bc_llm_client::{estimate_tokens, ChatRequest, ContentBlock};
use sha2::{Digest, Sha256};

fn sha256_hex(data: &str) -> String {
    Sha256::digest(data.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A cheap estimate of the whole rendered prompt, in tokens: system,
/// cache prefix, every message's text, tool call arguments and results,
/// and the tool schemas. See [`bc_llm_client::estimate_tokens`].
pub fn estimate_prompt_tokens(request: &ChatRequest) -> u64 {
    let mut total = request.system.as_deref().map_or(0, estimate_tokens)
        + request.cache_prefix.as_deref().map_or(0, estimate_tokens);
    for message in &request.messages {
        for block in &message.content {
            total += match block {
                ContentBlock::Text(t) => estimate_tokens(t),
                ContentBlock::ToolUse { input, .. } => estimate_tokens(&input.to_string()),
                ContentBlock::ToolResult { content, .. } => estimate_tokens(content),
                ContentBlock::Opaque { payload, .. } => estimate_tokens(&payload.to_string()),
            };
        }
    }
    for tool in &request.tools {
        total += estimate_tokens(&tool.description) + estimate_tokens(&tool.parameters.to_string());
    }
    total
}

/// The `prompt_cache_key` to send, or `None`: no caller material, the
/// cache kill switch is off, or the prompt is estimated below OpenAI's
/// caching floor (where a key buys nothing and is one more field a
/// strict gateway could reject).
pub fn prompt_cache_key(request: &ChatRequest) -> Option<String> {
    let material = request.cache_key.as_deref().filter(|m| !m.is_empty())?;
    if !request
        .cache
        .openai_cache_key_worth_sending(estimate_prompt_tokens(request))
    {
        return None;
    }
    // Calls sharing a prefix share a key; different prefixes (S4 shards)
    // get different keys, so each lands on the server holding its own.
    let bucket = request
        .cache_prefix
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(|p| sha256_hex(p)[..12].to_string())
        .unwrap_or_default();
    // NUL separators: no field can smuggle a delimiter into another.
    let raw = format!("{material}\0{}\0{bucket}", request.model);
    Some(sha256_hex(&raw)[..32].to_string())
}

/// `text` with the request's cache prefix in front of it, when this is
/// the first user turn and there is a prefix. The prefix is concatenated
/// as given (the caller owns any separator), exactly as
/// `sdk.py::_build_cache_prefix_content` does for a route without
/// breakpoints.
pub fn with_prefix(request: &ChatRequest, first_user_turn: bool, text: String) -> String {
    match request.cache_prefix.as_deref() {
        Some(prefix) if first_user_turn && !prefix.is_empty() => format!("{prefix}{text}"),
        _ => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::{CachePolicy, Message, OpaqueDialect, ToolSpec};
    use serde_json::json;

    fn big_request() -> ChatRequest {
        let mut r = ChatRequest::new("gpt-5.1", vec![Message::user_text("x".repeat(4_000))], 10);
        r.cache_key = Some("s4:my-repo".to_string());
        r
    }

    #[test]
    fn sha256_matches_the_published_test_vector() {
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_estimate_counts_every_part_of_the_prompt() {
        let mut r = ChatRequest::new(
            "m",
            vec![
                Message::user_text("aaaa"),
                Message::assistant(vec![
                    ContentBlock::ToolUse {
                        id: "1".into(),
                        name: "Read".into(),
                        input: json!({}),
                    },
                    ContentBlock::Opaque {
                        dialect: OpaqueDialect::OpenAiResponses,
                        payload: json!(1),
                    },
                ]),
                Message::tool_result("1", "bbbb", false),
            ],
            1,
        );
        r.system = Some("cccc".into());
        r.cache_prefix = Some("dddd".into());
        r.tools.push(ToolSpec {
            name: "Read".into(),
            description: "eeee".into(),
            parameters: json!({}),
        });
        // 4 chars each = 1 token each: system, prefix, user, `{}`, `1`,
        // tool result, description, `{}` schema.
        assert_eq!(estimate_prompt_tokens(&r), 8);
    }

    #[test]
    fn the_key_is_a_32_hex_char_hash_never_the_raw_material() {
        let key = prompt_cache_key(&big_request()).unwrap();
        assert_eq!(key.len(), 32);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!key.contains("my-repo"));
        // Deterministic across calls.
        assert_eq!(prompt_cache_key(&big_request()).unwrap(), key);
    }

    #[test]
    fn the_key_varies_with_model_and_prefix() {
        let base = prompt_cache_key(&big_request()).unwrap();
        let mut other_model = big_request();
        other_model.model = "gpt-5.2".into();
        assert_ne!(prompt_cache_key(&other_model).unwrap(), base);
        let mut shard_a = big_request();
        shard_a.cache_prefix = Some("shard A source".into());
        let mut shard_b = big_request();
        shard_b.cache_prefix = Some("shard B source".into());
        let a = prompt_cache_key(&shard_a).unwrap();
        assert_ne!(a, base);
        assert_ne!(a, prompt_cache_key(&shard_b).unwrap());
        // An empty prefix is no prefix.
        let mut empty = big_request();
        empty.cache_prefix = Some(String::new());
        assert_eq!(prompt_cache_key(&empty).unwrap(), base);
    }

    #[test]
    fn no_key_without_material_below_the_floor_or_with_the_kill_switch_off() {
        let mut none = big_request();
        none.cache_key = None;
        assert_eq!(prompt_cache_key(&none), None);
        let mut empty = big_request();
        empty.cache_key = Some(String::new());
        assert_eq!(prompt_cache_key(&empty), None);
        let mut small = big_request();
        small.messages = vec![Message::user_text("short")];
        assert_eq!(prompt_cache_key(&small), None);
        let mut off = big_request();
        off.cache = CachePolicy {
            markers: false,
            ..CachePolicy::default()
        };
        assert_eq!(prompt_cache_key(&off), None);
    }

    #[test]
    fn the_prefix_goes_first_on_the_first_user_turn_only() {
        let mut r = ChatRequest::new("m", Vec::new(), 1);
        assert_eq!(with_prefix(&r, true, "q".into()), "q");
        r.cache_prefix = Some("P:".into());
        assert_eq!(with_prefix(&r, true, "q".into()), "P:q");
        assert_eq!(with_prefix(&r, false, "q".into()), "q");
        r.cache_prefix = Some(String::new());
        assert_eq!(with_prefix(&r, true, "q".into()), "q");
    }
}
