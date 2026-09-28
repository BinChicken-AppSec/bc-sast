//! Same-call corrections for request parameters a specific model rejects,
//! REMEMBERED per model for the life of the process so a 400 is paid once
//! per model rather than once per call.
//!
//! Ported from `backends/llm/openai.py`'s retry-and-drop handler
//! (`:560-600`) and its module-level memories: `_NO_TEMP_MODELS`,
//! `_USE_LEGACY_MAXTOK`, `_NO_CACHE_KEY_MODELS`, and the DeepAgents
//! route's `_NO_REASONING_EFFORT` (`model_building.py`). The initial Rust
//! port corrected the same rejections but forgot them after each call,
//! so a stage making 400 calls to a model that rejects `temperature` sent
//! 800 requests.
//!
//! This is the backstop behind `bc_llm_client::capabilities`: the request
//! builders already leave out what the capability table says a model
//! rejects, and this catches whatever the table gets wrong (an unknown
//! gateway alias, a model whose rules changed).
//!
//! Net-new versus Python: `top_p` and `seed` are learned too, the
//! completion-token ceiling a model reports is remembered, and a rejected
//! effort tier steps DOWN one tier instead of being dropped outright, so
//! `max` on a model that tops out at `xhigh` still runs at `xhigh` rather
//! than at the provider default.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use bc_llm_client::ReasoningEffort;
use serde_json::{Map, Value};

/// Which request shape a body is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    Chat,
    Responses,
}

#[derive(Debug, Default)]
struct Learned {
    no_temperature: HashSet<String>,
    no_top_p: HashSet<String>,
    no_seed: HashSet<String>,
    legacy_max_tokens: HashSet<String>,
    no_cache_key: HashSet<String>,
    no_effort: HashSet<(String, String)>,
    ceiling: HashMap<String, u64>,
}

/// Per-model learned rejections, shared by every call through one client.
#[derive(Debug, Default)]
pub struct QuirkMemory {
    learned: Mutex<Learned>,
}

/// The effort tier one below `effort` worth retrying at, or `None` to drop
/// the parameter. `none` and `minimal` are never stepped INTO: a model
/// that rejected `low` is not going to be rescued by an even rarer tier.
fn lower_tier(effort: &str) -> Option<&'static str> {
    let parsed: ReasoningEffort = effort.parse().ok()?;
    let next = match parsed {
        ReasoningEffort::Max => ReasoningEffort::XHigh,
        ReasoningEffort::XHigh => ReasoningEffort::High,
        ReasoningEffort::High => ReasoningEffort::Medium,
        ReasoningEffort::Medium => ReasoningEffort::Low,
        _ => return None,
    };
    Some(next.as_str())
}

fn token_keys(shape: Shape) -> &'static [&'static str] {
    match shape {
        Shape::Chat => &["max_completion_tokens", "max_tokens"],
        Shape::Responses => &["max_output_tokens"],
    }
}

/// The effort tier `body` carries, wherever this shape puts it.
fn effort_of(body: &Map<String, Value>, shape: Shape) -> Option<String> {
    let value = match shape {
        Shape::Chat => body.get("reasoning_effort"),
        Shape::Responses => body.get("reasoning").and_then(|r| r.get("effort")),
    };
    value.and_then(Value::as_str).map(str::to_string)
}

fn set_effort(body: &mut Map<String, Value>, shape: Shape, effort: Option<&str>) {
    let (key, value) = match shape {
        Shape::Chat => ("reasoning_effort", effort.map(Value::from)),
        Shape::Responses => (
            "reasoning",
            effort.map(|e| serde_json::json!({"effort": e})),
        ),
    };
    match value {
        Some(v) => {
            body.insert(key.to_string(), v);
        }
        None => {
            body.remove(key);
        }
    }
}

/// Extracts `N` from an OpenAI rejection naming the model's actual
/// completion-token ceiling (`"...supports at most N completion
/// tokens..."`). `lower_error_text` is expected already lowercased.
pub fn parse_completion_token_limit(lower_error_text: &str) -> Option<u64> {
    let marker = "supports at most ";
    let idx = lower_error_text.find(marker)?;
    let rest = &lower_error_text[idx + marker.len()..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

impl QuirkMemory {
    fn lock(&self) -> std::sync::MutexGuard<'_, Learned> {
        self.learned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Apply everything already learned about `model` to a freshly built
    /// `body`, before it is sent.
    pub fn apply_learned(&self, body: &mut Value, shape: Shape, model: &str) {
        let Some(map) = body.as_object_mut() else {
            return;
        };
        let learned = self.lock();
        for (set, key) in [
            (&learned.no_temperature, "temperature"),
            (&learned.no_top_p, "top_p"),
            (&learned.no_seed, "seed"),
            (&learned.no_cache_key, "prompt_cache_key"),
        ] {
            if set.contains(model) {
                map.remove(key);
            }
        }
        if shape == Shape::Chat && learned.legacy_max_tokens.contains(model) {
            swap_key(map, "max_completion_tokens", "max_tokens");
        }
        if let Some(limit) = learned.ceiling.get(model) {
            clamp_token_key(map, shape, *limit);
        }
        // Step down through every tier already learned unsupported.
        while let Some(effort) = effort_of(map, shape) {
            if !learned
                .no_effort
                .contains(&(model.to_string(), effort.clone()))
            {
                break;
            }
            set_effort(map, shape, lower_tier(&effort));
        }
    }

    /// Correct `body` in place for a 400 whose `error_text` names one
    /// known, self-correctable rejection, learning it for `model`.
    /// Returns `true` (resend the corrected body) when one applied, and
    /// `false` (propagate the original error) otherwise, including when
    /// the error names a parameter `body` does not actually carry:
    /// nothing to fix, so nothing to gain by resending.
    ///
    /// Each correction removes, moves or lowers the very key it acts on,
    /// so the same one cannot fire twice on one body except the effort
    /// step-down, which is bounded by the number of tiers. The caller
    /// bounds the total regardless.
    pub fn correct(&self, body: &mut Value, shape: Shape, model: &str, error_text: &str) -> bool {
        let lower = error_text.to_ascii_lowercase();
        let Some(map) = body.as_object_mut() else {
            return false;
        };
        let mut guard = self.lock();
        let learned = &mut *guard;

        if shape == Shape::Chat && lower.contains("max_completion_tokens") {
            if swap_key(map, "max_completion_tokens", "max_tokens") {
                learned.legacy_max_tokens.insert(model.to_string());
                warn(
                    model,
                    "max_completion_tokens",
                    "retrying with legacy `max_tokens`",
                );
                return true;
            }
            if swap_key(map, "max_tokens", "max_completion_tokens") {
                learned.legacy_max_tokens.remove(model);
                warn(model, "max_tokens", "retrying with `max_completion_tokens`");
                return true;
            }
        }
        for (key, set) in [
            ("temperature", &mut learned.no_temperature),
            ("top_p", &mut learned.no_top_p),
            ("seed", &mut learned.no_seed),
            ("prompt_cache_key", &mut learned.no_cache_key),
        ] {
            if lower.contains(key) && map.remove(key).is_some() {
                set.insert(model.to_string());
                warn(model, key, "retrying without it");
                return true;
            }
        }
        if let Some(limit) = parse_completion_token_limit(&lower) {
            if clamp_token_key(map, shape, limit) {
                learned.ceiling.insert(model.to_string(), limit);
                warn(
                    model,
                    "max tokens",
                    "clamped to the model's reported ceiling",
                );
                return true;
            }
        }
        let names_effort = lower.contains("reasoning_effort")
            || lower.contains("reasoning.effort")
            || (lower.contains("reasoning") && lower.contains("effort"));
        if names_effort {
            if let Some(effort) = effort_of(map, shape).filter(|e| e != "none") {
                set_effort(map, shape, lower_tier(&effort));
                learned.no_effort.insert((model.to_string(), effort));
                warn(
                    model,
                    "reasoning effort",
                    "retrying one tier lower (or without it)",
                );
                return true;
            }
        }
        false
    }
}

/// The pinned-Chat-Completions answer to "function tools with
/// reasoning_effort are not supported ... set reasoning_effort to 'none'":
/// set it to `none` (tools keep working, reasoning is lost for the call).
/// `false` when it already was `none`, since setting it cannot help twice.
/// In `Auto` mode the client moves the model to the Responses API
/// instead, which keeps both.
pub fn degrade_reasoning_to_none(body: &mut Value, model: &str) -> bool {
    let Some(map) = body.as_object_mut() else {
        return false;
    };
    if map.get("reasoning_effort").and_then(Value::as_str) == Some("none") {
        return false;
    }
    map.insert("reasoning_effort".to_string(), Value::from("none"));
    warn(
        model,
        "reasoning_effort",
        "Chat Completions rejects function tools with reasoning on this model; running this \
         call with reasoning_effort=none. Use --openai-api auto or responses to keep reasoning.",
    );
    true
}

fn warn(model: &str, param: &str, what: &str) {
    tracing::warn!(model, param, "[openai] {model} rejected `{param}`: {what}");
}

/// Moves `map[from]` to `map[to]` if present, returning whether it did.
fn swap_key(map: &mut Map<String, Value>, from: &str, to: &str) -> bool {
    match map.remove(from) {
        Some(v) => {
            map.insert(to.to_string(), v);
            true
        }
        None => false,
    }
}

/// Lowers whichever output-budget key `map` carries to `limit`, returning
/// whether it changed anything. A value already at or under the limit is
/// left alone, so a server that keeps quoting the same ceiling cannot
/// drive a retry loop.
fn clamp_token_key(map: &mut Map<String, Value>, shape: Shape, limit: u64) -> bool {
    for key in token_keys(shape) {
        if let Some(current) = map.get(*key).and_then(Value::as_u64) {
            if current > limit {
                map.insert((*key).to_string(), Value::from(limit));
                return true;
            }
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_rejected_temperature_is_dropped_and_remembered() {
        let q = QuirkMemory::default();
        let mut body = json!({"temperature": 0.2, "max_completion_tokens": 10});
        assert!(q.correct(
            &mut body,
            Shape::Chat,
            "m",
            "Unsupported value: 'temperature'"
        ));
        assert!(body.get("temperature").is_none());
        let mut next = json!({"temperature": 0.2});
        q.apply_learned(&mut next, Shape::Responses, "m");
        assert!(next.get("temperature").is_none(), "learned across shapes");
        let mut other = json!({"temperature": 0.2});
        q.apply_learned(&mut other, Shape::Chat, "other-model");
        assert_eq!(other["temperature"], 0.2, "learned per model");
    }

    #[test]
    fn top_p_seed_and_prompt_cache_key_are_learned_the_same_way() {
        let q = QuirkMemory::default();
        for key in ["top_p", "seed", "prompt_cache_key"] {
            let mut body = json!({key: 1});
            assert!(q.correct(
                &mut body,
                Shape::Chat,
                "m",
                &format!("unknown parameter {key}")
            ));
            assert!(body.get(key).is_none());
        }
        let mut next = json!({"top_p": 1, "seed": 1, "prompt_cache_key": "k", "x": 1});
        q.apply_learned(&mut next, Shape::Chat, "m");
        assert_eq!(next, json!({"x": 1}));
    }

    #[test]
    fn the_legacy_max_tokens_swap_is_learned_and_unlearned() {
        let q = QuirkMemory::default();
        let mut body = json!({"max_completion_tokens": 100});
        assert!(q.correct(
            &mut body,
            Shape::Chat,
            "m",
            "'max_completion_tokens' is not supported with this model. Use 'max_tokens'"
        ));
        assert_eq!(body, json!({"max_tokens": 100}));
        let mut next = json!({"max_completion_tokens": 7});
        q.apply_learned(&mut next, Shape::Chat, "m");
        assert_eq!(next, json!({"max_tokens": 7}));
        // The Responses shape has no such key to swap.
        let mut resp = json!({"max_output_tokens": 7});
        q.apply_learned(&mut resp, Shape::Responses, "m");
        assert_eq!(resp, json!({"max_output_tokens": 7}));
        // The reverse direction un-learns it.
        let mut back = json!({"max_tokens": 100});
        assert!(q.correct(
            &mut back,
            Shape::Chat,
            "m",
            "Use 'max_completion_tokens' instead"
        ));
        assert_eq!(back, json!({"max_completion_tokens": 100}));
        let mut after = json!({"max_completion_tokens": 7});
        q.apply_learned(&mut after, Shape::Chat, "m");
        assert_eq!(after, json!({"max_completion_tokens": 7}));
    }

    #[test]
    fn naming_max_completion_tokens_with_neither_key_present_is_not_a_swap() {
        let q = QuirkMemory::default();
        let mut body = json!({"model": "m"});
        assert!(!q.correct(&mut body, Shape::Chat, "m", "max_completion_tokens"));
    }

    #[test]
    fn the_max_completion_tokens_text_on_the_responses_shape_is_not_a_swap() {
        let q = QuirkMemory::default();
        let mut body = json!({"max_output_tokens": 100});
        assert!(!q.correct(&mut body, Shape::Responses, "m", "max_completion_tokens"));
    }

    #[test]
    fn a_reported_ceiling_is_clamped_and_remembered_for_both_shapes() {
        let q = QuirkMemory::default();
        let text = "max_tokens is too large: 64000. This model supports at most 16384 \
                    completion tokens, whereas you provided 64000.";
        let mut body = json!({"max_completion_tokens": 64000});
        assert!(q.correct(&mut body, Shape::Chat, "m", text));
        assert_eq!(body["max_completion_tokens"], 16384);
        // Already at the ceiling: no further correction, no loop.
        assert!(!q.correct(&mut body, Shape::Chat, "m", text));
        let mut resp = json!({"max_output_tokens": 64000});
        q.apply_learned(&mut resp, Shape::Responses, "m");
        assert_eq!(resp["max_output_tokens"], 16384);
        let mut legacy = json!({"max_tokens": 64000});
        q.apply_learned(&mut legacy, Shape::Chat, "m");
        assert_eq!(legacy["max_tokens"], 16384);
        let mut none = json!({});
        assert!(!clamp_token_key(
            none.as_object_mut().unwrap(),
            Shape::Chat,
            1
        ));
    }

    #[test]
    fn parse_completion_token_limit_needs_the_phrase_and_digits() {
        assert_eq!(
            parse_completion_token_limit("this model supports at most 16384 completion tokens"),
            Some(16384)
        );
        assert_eq!(parse_completion_token_limit("rate limit exceeded"), None);
        assert_eq!(parse_completion_token_limit("supports at most a lot"), None);
    }

    #[test]
    fn a_rejected_effort_steps_down_a_tier_and_is_remembered() {
        let q = QuirkMemory::default();
        let mut body = json!({"reasoning": {"effort": "max"}});
        assert!(q.correct(
            &mut body,
            Shape::Responses,
            "m",
            "Unsupported value: 'reasoning.effort' does not support 'max'"
        ));
        assert_eq!(body, json!({"reasoning": {"effort": "xhigh"}}));
        let mut next = json!({"reasoning": {"effort": "max"}});
        q.apply_learned(&mut next, Shape::Responses, "m");
        assert_eq!(next, json!({"reasoning": {"effort": "xhigh"}}));
        // Chat shape, lowest tier: dropped entirely.
        let mut chat = json!({"reasoning_effort": "low"});
        assert!(q.correct(
            &mut chat,
            Shape::Chat,
            "m",
            "reasoning_effort is not supported"
        ));
        assert!(chat.get("reasoning_effort").is_none());
        let mut chat_next = json!({"reasoning_effort": "low"});
        q.apply_learned(&mut chat_next, Shape::Chat, "m");
        assert!(chat_next.get("reasoning_effort").is_none());
    }

    #[test]
    fn a_none_effort_or_a_missing_one_is_not_corrected() {
        let q = QuirkMemory::default();
        let mut none = json!({"reasoning_effort": "none"});
        assert!(!q.correct(&mut none, Shape::Chat, "m", "reasoning_effort bad"));
        let mut absent = json!({});
        assert!(!q.correct(&mut absent, Shape::Chat, "m", "reasoning_effort bad"));
    }

    #[test]
    fn lower_tier_walks_down_and_stops_at_low() {
        assert_eq!(lower_tier("max"), Some("xhigh"));
        assert_eq!(lower_tier("xhigh"), Some("high"));
        assert_eq!(lower_tier("high"), Some("medium"));
        assert_eq!(lower_tier("medium"), Some("low"));
        assert_eq!(lower_tier("low"), None);
        assert_eq!(lower_tier("minimal"), None);
        assert_eq!(lower_tier("bogus"), None);
    }

    #[test]
    fn an_unrecognized_400_or_a_non_object_body_is_not_corrected() {
        let q = QuirkMemory::default();
        let mut body = json!({"temperature": 1});
        assert!(!q.correct(&mut body, Shape::Chat, "m", "model not found"));
        let mut array = json!([1]);
        assert!(!q.correct(&mut array, Shape::Chat, "m", "temperature"));
        q.apply_learned(&mut array, Shape::Chat, "m");
        assert_eq!(array, json!([1]));
    }

    #[test]
    fn degrading_to_none_is_one_shot() {
        let mut body = json!({"reasoning_effort": "high"});
        assert!(degrade_reasoning_to_none(&mut body, "m"));
        assert_eq!(body["reasoning_effort"], "none");
        assert!(!degrade_reasoning_to_none(&mut body, "m"));
        assert!(!degrade_reasoning_to_none(&mut json!([]), "m"));
    }
}
