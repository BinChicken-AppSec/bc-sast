//! How a request's thinking budget and reasoning effort become the
//! Messages API's `thinking` and `output_config.effort` fields for one
//! specific model, per `bc_llm_client::capabilities`.
//!
//! The wire forms changed across Claude generations, and the wrong one is
//! a 400, not a warning:
//!
//! - up to the 4.5 generation, extended thinking is
//!   `{"type": "enabled", "budget_tokens": N}` (N at least 1,024 and
//!   below `max_tokens`);
//! - from 4.6 it is `{"type": "adaptive"}` with the depth set by
//!   `output_config: {"effort": ...}`, and from 4.7 the budget form is
//!   rejected outright;
//! - from Opus 5 / Sonnet 5 thinking is on by default, and some models
//!   (Fable 5.x, Mythos 5.x, Opus 5.5) cannot turn it off at all.
//!
//! Net-new versus the Python original, which sends only the budget form
//! (`backends/sdk.py`'s `kw["thinking"]`).

use bc_llm_client::capabilities::{warn_param_once, ModelCapabilities, Thinking};
use bc_llm_client::ReasoningEffort;
use serde_json::{json, Value};

/// The smallest `budget_tokens` the Messages API accepts.
pub const MIN_THINKING_BUDGET: u32 = 1024;

/// What to send for thinking and effort.
#[derive(Debug, Clone, PartialEq)]
pub struct ThinkingPlan {
    /// The `thinking` object, or `None` to omit it.
    pub thinking: Option<Value>,
    /// The `output_config.effort` tier, or `None` to omit it.
    pub effort: Option<ReasoningEffort>,
    /// Whether the model will think on this request, sent or by default.
    /// Sampling parameters must then be left out: the Messages API
    /// rejects a non-default `temperature` or `top_p` alongside thinking.
    pub thinking_active: bool,
}

/// Decide the plan for `model` given the caller's `budget`, `effort` and
/// (already clamped) `max_tokens`.
pub fn plan(
    model: &str,
    caps: &ModelCapabilities,
    budget: Option<u32>,
    effort: Option<ReasoningEffort>,
    max_tokens: u32,
) -> ThinkingPlan {
    // `none`/`minimal` are OpenAI tiers: on Claude they mean "don't
    // think", which only some models can honor.
    let wants_off = matches!(
        effort,
        Some(ReasoningEffort::None | ReasoningEffort::Minimal)
    );
    let effort = effort.filter(|_| !wants_off);
    match caps.thinking {
        Thinking::Unknown | Thinking::None | Thinking::BudgetTokens => {
            let effort = effort.and_then(|asked| clamp(model, caps, asked));
            let thinking = budget.and_then(|b| budget_form(model, b, max_tokens));
            ThinkingPlan {
                thinking_active: thinking.is_some(),
                thinking,
                effort,
            }
        }
        Thinking::AdaptivePreferred if effort.is_none() => {
            // The deprecated budget form still works here, and is the
            // only way to honor a budget without an effort.
            let thinking = budget.and_then(|b| budget_form(model, b, max_tokens));
            ThinkingPlan {
                thinking_active: thinking.is_some(),
                thinking,
                effort: None,
            }
        }
        Thinking::AdaptivePreferred | Thinking::Adaptive => {
            if effort.is_none() && budget.is_none() {
                return ThinkingPlan {
                    thinking: None,
                    effort: None,
                    thinking_active: false,
                };
            }
            if budget.is_some() && caps.thinking == Thinking::Adaptive {
                warn_param_once(
                    model,
                    "thinking_budget",
                    "the model takes adaptive thinking only; sent as adaptive, budget ignored",
                );
            }
            ThinkingPlan {
                thinking: Some(json!({"type": "adaptive"})),
                effort: effort.and_then(|asked| clamp(model, caps, asked)),
                thinking_active: true,
            }
        }
        Thinking::AdaptiveDefaultOn | Thinking::AdaptiveAlwaysOn => {
            // Thinking cannot be switched off here (or only at some
            // tiers), so "off" is honored as the lowest tier instead.
            let effort = if wants_off {
                warn_param_once(
                    model,
                    "reasoning_effort",
                    "the model cannot turn thinking off; sent as low",
                );
                Some(ReasoningEffort::Low)
            } else {
                effort
            };
            if budget.is_some() {
                warn_param_once(
                    model,
                    "thinking_budget",
                    "the model takes adaptive thinking only; budget ignored",
                );
            }
            let explicit = effort.is_some() || budget.is_some();
            ThinkingPlan {
                thinking: explicit.then(|| json!({"type": "adaptive"})),
                effort: effort.and_then(|asked| clamp(model, caps, asked)),
                thinking_active: true,
            }
        }
    }
}

fn clamp(model: &str, caps: &ModelCapabilities, asked: ReasoningEffort) -> Option<ReasoningEffort> {
    let sent = caps.clamp_effort(asked);
    match sent {
        None => {
            warn_param_once(
                model,
                "reasoning_effort",
                "the model takes no effort parameter; not sent",
            );
        }
        Some(tier) if tier != asked => {
            warn_param_once(
                model,
                "reasoning_effort",
                &format!("{asked} is not supported; sent as {tier}"),
            );
        }
        Some(_) => {}
    }
    sent
}

/// The legacy budget form, with the budget brought inside the API's
/// bounds (at least [`MIN_THINKING_BUDGET`], below `max_tokens`), or
/// `None` when `max_tokens` leaves no room for any budget at all.
fn budget_form(model: &str, budget: u32, max_tokens: u32) -> Option<Value> {
    if max_tokens <= MIN_THINKING_BUDGET {
        warn_param_once(
            model,
            "thinking_budget",
            "max_tokens leaves no room for the 1024-token minimum thinking budget; not sent",
        );
        return None;
    }
    let clamped = budget.clamp(MIN_THINKING_BUDGET, max_tokens - 1);
    if clamped != budget {
        warn_param_once(
            model,
            "thinking_budget",
            &format!("brought inside the API's bounds as {clamped}"),
        );
    }
    Some(json!({"type": "enabled", "budget_tokens": clamped}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::capabilities::capabilities;
    use ReasoningEffort::{High, Low, Max, Minimal, XHigh};

    fn p(model: &str, budget: Option<u32>, effort: Option<ReasoningEffort>) -> ThinkingPlan {
        plan(model, &capabilities(model), budget, effort, 32_000)
    }

    fn adaptive() -> Option<Value> {
        Some(json!({"type": "adaptive"}))
    }

    #[test]
    fn budget_models_keep_the_budget_form_and_clamp_effort() {
        let plan = p("claude-sonnet-4-5", Some(4000), Some(High));
        assert_eq!(
            plan.thinking,
            Some(json!({"type": "enabled", "budget_tokens": 4000}))
        );
        assert_eq!(plan.effort, None, "sonnet 4.5 takes no effort");
        assert!(plan.thinking_active);
        let opus45 = p("claude-opus-4-5", None, Some(Max));
        assert_eq!(opus45.effort, Some(High));
        assert_eq!(opus45.thinking, None);
        assert!(!opus45.thinking_active);
    }

    #[test]
    fn an_unknown_model_gets_exactly_what_was_asked() {
        let plan = p("my-claude-alias", Some(2048), Some(XHigh));
        assert_eq!(
            plan.thinking,
            Some(json!({"type": "enabled", "budget_tokens": 2048}))
        );
        assert_eq!(plan.effort, Some(XHigh));
    }

    #[test]
    fn the_budget_is_brought_inside_the_api_bounds() {
        let caps = capabilities("claude-sonnet-4-5");
        let small = plan("claude-sonnet-4-5", &caps, Some(10), None, 8000);
        assert_eq!(small.thinking.unwrap()["budget_tokens"], 1024);
        let big = plan("claude-sonnet-4-5", &caps, Some(50_000), None, 8000);
        assert_eq!(big.thinking.unwrap()["budget_tokens"], 7999);
        let no_room = plan("claude-sonnet-4-5", &caps, Some(4000), None, 1024);
        assert_eq!(no_room.thinking, None);
        assert!(!no_room.thinking_active);
    }

    #[test]
    fn opus_4_6_prefers_adaptive_but_honors_a_bare_budget() {
        let with_effort = p("claude-opus-4-6", Some(4000), Some(XHigh));
        assert_eq!(with_effort.thinking, adaptive());
        assert_eq!(with_effort.effort, Some(High), "no xhigh on 4.6");
        let bare_budget = p("claude-opus-4-6", Some(4000), None);
        assert_eq!(
            bare_budget.thinking,
            Some(json!({"type": "enabled", "budget_tokens": 4000}))
        );
        let nothing = p("claude-opus-4-6", None, None);
        assert_eq!(nothing.thinking, None);
        assert!(!nothing.thinking_active);
        // "Off" is honored: 4.6 can disable thinking.
        let off = p("claude-opus-4-6", None, Some(ReasoningEffort::None));
        assert_eq!((off.thinking, off.effort), (Option::None, Option::None));
    }

    #[test]
    fn opus_4_7_is_adaptive_only() {
        let budget = p("claude-opus-4-7", Some(4000), None);
        assert_eq!(budget.thinking, adaptive());
        assert_eq!(budget.effort, None);
        assert!(budget.thinking_active);
        let effort = p("claude-opus-4-7", None, Some(XHigh));
        assert_eq!((effort.thinking, effort.effort), (adaptive(), Some(XHigh)));
        let nothing = p("claude-opus-4-7", None, None);
        assert!(!nothing.thinking_active);
        let off = p("claude-opus-4-7", None, Some(Minimal));
        assert!(!off.thinking_active);
    }

    #[test]
    fn always_on_models_never_get_a_budget_and_clamp_off_to_low() {
        for model in [
            "claude-opus-5-5",
            "claude-fable-5-1",
            "claude-opus-5",
            "claude-sonnet-5",
        ] {
            let off = p(model, None, Some(ReasoningEffort::None));
            assert_eq!(
                (off.thinking, off.effort),
                (adaptive(), Some(Low)),
                "{model}"
            );
            let budget = p(model, Some(4000), None);
            assert_eq!(
                (budget.thinking, budget.effort),
                (adaptive(), None),
                "{model}"
            );
            let nothing = p(model, None, None);
            assert_eq!(nothing.thinking, None, "{model}: on by default");
            assert!(nothing.thinking_active, "{model}");
        }
    }
}
