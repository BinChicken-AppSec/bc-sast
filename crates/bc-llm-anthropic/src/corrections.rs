//! Learned, per-model corrections for Messages API parameters the
//! capability table got wrong: the backstop behind
//! `bc_llm_client::capabilities`, mirroring `bc_llm_openai::quirks`.
//!
//! Covers what `AnthropicClient`'s own `temperature` memo does not:
//! `top_p`, `output_config` (effort) and `thinking`. A 400 naming one of
//! them is corrected and resent once, and the correction applied to every
//! later request for that model, so the rejection is paid once per model
//! per process.
//!
//! The memory is process-wide rather than per client because the client
//! struct is owned by a separate change (authentication); in practice
//! `bc-cli` builds one Anthropic client per process, so the scope is the
//! same.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};

use serde_json::{json, Value};

#[derive(Debug, Default)]
struct Learned {
    no_top_p: HashSet<String>,
    no_effort: HashSet<String>,
    /// What to do with `thinking` for a model that rejected the form it
    /// was sent: switch a budget to adaptive, or drop it.
    thinking: HashMap<String, ThinkingFix>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThinkingFix {
    Adaptive,
    Drop,
}

static LEARNED: LazyLock<Mutex<Learned>> = LazyLock::new(|| Mutex::new(Learned::default()));

fn learned() -> std::sync::MutexGuard<'static, Learned> {
    LEARNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn is_budget_form(thinking: &Value) -> bool {
    thinking["type"] == "enabled"
}

fn apply_thinking_fix(map: &mut serde_json::Map<String, Value>, fix: ThinkingFix) -> bool {
    match (fix, map.get("thinking")) {
        (ThinkingFix::Adaptive, Some(t)) if is_budget_form(t) => {
            map.insert("thinking".to_string(), json!({"type": "adaptive"}));
            true
        }
        (ThinkingFix::Drop, Some(_)) => {
            map.remove("thinking");
            true
        }
        _ => false,
    }
}

/// Apply everything learned about `model` to a freshly built body.
pub fn apply_learned(model: &str, body: &mut Value) {
    let Some(map) = body.as_object_mut() else {
        return;
    };
    let learned = learned();
    if learned.no_top_p.contains(model) {
        map.remove("top_p");
    }
    if learned.no_effort.contains(model) {
        map.remove("output_config");
    }
    if let Some(fix) = learned.thinking.get(model) {
        apply_thinking_fix(map, *fix);
    }
}

/// Correct `body` for a 400 naming `top_p`, `output_config`/`effort` or
/// `thinking`, learning the correction for `model`. `false` when the
/// error names none of them, or names one `body` does not carry.
pub fn correct(model: &str, body: &mut Value, error_text: &str) -> bool {
    let lower = error_text.to_ascii_lowercase();
    let Some(map) = body.as_object_mut() else {
        return false;
    };
    let mut learned = learned();
    if lower.contains("top_p") && map.remove("top_p").is_some() {
        learned.no_top_p.insert(model.to_string());
        warn(model, "top_p", "retrying without it");
        return true;
    }
    if (lower.contains("output_config") || lower.contains("effort"))
        && map.remove("output_config").is_some()
    {
        learned.no_effort.insert(model.to_string());
        warn(model, "output_config.effort", "retrying without it");
        return true;
    }
    if lower.contains("thinking") {
        // A budget rejected by an adaptive-only model becomes adaptive;
        // anything else rejected about thinking is dropped.
        let fix = match map.get("thinking") {
            Some(t) if is_budget_form(t) && lower.contains("adaptive") => ThinkingFix::Adaptive,
            _ => ThinkingFix::Drop,
        };
        if apply_thinking_fix(map, fix) {
            learned.thinking.insert(model.to_string(), fix);
            warn(model, "thinking", "retrying with it corrected");
            return true;
        }
    }
    false
}

fn warn(model: &str, param: &str, what: &str) {
    tracing::warn!(
        model,
        param,
        "[anthropic] {model} rejected `{param}`: {what}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rejected_top_p_is_dropped_and_remembered() {
        let mut body = json!({"top_p": 0.5});
        assert!(correct("corr-top-p", &mut body, "top_p is not supported"));
        assert_eq!(body, json!({}));
        let mut next = json!({"top_p": 0.5, "x": 1});
        apply_learned("corr-top-p", &mut next);
        assert_eq!(next, json!({"x": 1}));
    }

    #[test]
    fn a_rejected_effort_is_dropped_and_remembered() {
        let mut body = json!({"output_config": {"effort": "high"}});
        assert!(correct(
            "corr-effort",
            &mut body,
            "output_config: Extra inputs"
        ));
        assert_eq!(body, json!({}));
        let mut next = json!({"output_config": {"effort": "low"}});
        apply_learned("corr-effort", &mut next);
        assert_eq!(next, json!({}));
    }

    #[test]
    fn a_rejected_budget_becomes_adaptive_when_the_error_says_so() {
        let budget = json!({"thinking": {"type": "enabled", "budget_tokens": 2000}});
        let mut body = budget.clone();
        assert!(correct(
            "corr-adaptive",
            &mut body,
            "thinking.type.enabled is not supported for this model. Use thinking.type.adaptive"
        ));
        assert_eq!(body, json!({"thinking": {"type": "adaptive"}}));
        let mut next = budget.clone();
        apply_learned("corr-adaptive", &mut next);
        assert_eq!(next, json!({"thinking": {"type": "adaptive"}}));
        // An adaptive body is left alone by the adaptive fix.
        let mut already = json!({"thinking": {"type": "adaptive"}});
        apply_learned("corr-adaptive", &mut already);
        assert_eq!(already, json!({"thinking": {"type": "adaptive"}}));
    }

    #[test]
    fn any_other_thinking_rejection_drops_it() {
        let mut body = json!({"thinking": {"type": "adaptive"}});
        assert!(correct("corr-drop", &mut body, "thinking is not supported"));
        assert_eq!(body, json!({}));
        let mut next = json!({"thinking": {"type": "enabled", "budget_tokens": 1}});
        apply_learned("corr-drop", &mut next);
        assert_eq!(next, json!({}));
    }

    #[test]
    fn nothing_to_fix_means_no_retry() {
        let mut body = json!({"temperature": 1});
        assert!(!correct(
            "corr-none",
            &mut body,
            "top_p output_config thinking"
        ));
        assert!(!correct("corr-none", &mut body, "model not found"));
        let mut array = json!([1]);
        assert!(!correct("corr-none", &mut array, "top_p"));
        apply_learned("corr-none", &mut array);
        assert_eq!(array, json!([1]));
    }
}
