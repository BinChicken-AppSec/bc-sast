use appsec_llm_client::{estimate_tokens, ChatRequest, ContentBlock};
use sha2::{Digest, Sha256};

fn sha256_hex(data: &str) -> String {
    Sha256::digest(data.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

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

pub fn prompt_cache_key(request: &ChatRequest) -> Option<String> {
    let material = request.cache_key.as_deref().filter(|m| !m.is_empty())?;
    if !request
        .cache
        .openai_cache_key_worth_sending(estimate_prompt_tokens(request))
    {
        return None;
    }
    let bucket = request
        .cache_prefix
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(|p| sha256_hex(p)[..12].to_string())
        .unwrap_or_default();
    let raw = format!("{material}\0{}\0{bucket}", request.model);
    Some(sha256_hex(&raw)[..32].to_string())
}

pub fn with_prefix(request: &ChatRequest, first_user_turn: bool, text: String) -> String {
    match request.cache_prefix.as_deref() {
        Some(prefix) if first_user_turn && !prefix.is_empty() => format!("{prefix}{text}"),
        _ => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_llm_client::{CachePolicy, Message, OpaqueDialect, ToolSpec};
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
        assert_eq!(estimate_prompt_tokens(&r), 8);
    }

    #[test]
    fn the_key_is_a_32_hex_char_hash_never_the_raw_material() {
        let key = prompt_cache_key(&big_request()).unwrap();
        assert_eq!(key.len(), 32);
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!key.contains("my-repo"));
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
