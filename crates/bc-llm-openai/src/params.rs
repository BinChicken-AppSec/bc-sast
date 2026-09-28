//! The parameter decisions both OpenAI request shapes share: what the
//! capability table (`bc_llm_client::capabilities`) says this model
//! accepts, applied to what the caller asked for BEFORE anything is
//! sent. Every change is logged once per model and parameter, naming the
//! reason, so an operator who set `temperature: 0` on a reasoning model
//! finds out why it had no effect.

use bc_llm_client::capabilities::{capabilities, warn_param_once, ModelCapabilities, Sampling};
use bc_llm_client::{ChatRequest, ReasoningEffort};

/// The caller's knobs after the capability table has had its say.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Resolved {
    pub caps: ModelCapabilities,
    pub max_tokens: u32,
    pub effort: Option<ReasoningEffort>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
}

pub fn resolve(request: &ChatRequest) -> Resolved {
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

    let effort = request.reasoning_effort.and_then(|asked| {
        let sent = caps.clamp_effort(asked);
        match sent {
            None => {
                warn_param_once(
                    model,
                    "reasoning_effort",
                    "the model takes no reasoning effort; not sent",
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
    });

    let sampling_ok = caps.sampling_allowed(effort);
    let why_not = match caps.sampling {
        Sampling::OnlyWhenEffortNone => {
            "the model accepts it only when reasoning effort is none; not sent"
        }
        _ => "the model rejects it; not sent",
    };
    let keep = |value: Option<f64>, param: &str| -> Option<f64> {
        if value.is_some() && !sampling_ok {
            warn_param_once(model, param, why_not);
            return None;
        }
        value
    };
    let temperature = keep(request.temperature, "temperature");
    let mut top_p = keep(request.top_p, "top_p");
    if caps.sampling == Sampling::OneOfTemperatureOrTopP && temperature.is_some() && top_p.is_some()
    {
        warn_param_once(
            model,
            "top_p",
            "the model accepts temperature or top_p, not both; sent temperature only",
        );
        top_p = None;
    }
    let seed = request.seed.filter(|_| {
        let ok = caps.seed_allowed(effort);
        if !ok {
            warn_param_once(model, "seed", why_not);
        }
        ok
    });

    Resolved {
        caps,
        max_tokens,
        effort,
        temperature,
        top_p,
        seed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_llm_client::Message;

    fn req(model: &str) -> ChatRequest {
        let mut r = ChatRequest::new(model, vec![Message::user_text("hi")], 1000);
        r.temperature = Some(0.0);
        r.top_p = Some(0.5);
        r.seed = Some(7);
        r
    }

    /// The operator-facing case the CLI default makes common: a reasoning
    /// model with `temperature: 0` and no effort. GPT-5.6's default effort
    /// is medium, so sampling is dropped...
    #[test]
    fn gpt_5_6_luna_drops_sampling_at_its_default_effort() {
        let r = resolve(&req("gpt-5.6-luna"));
        assert_eq!(r.effort, None);
        assert_eq!((r.temperature, r.top_p, r.seed), (None, None, None));
    }

    /// ...and kept when the caller explicitly turns reasoning off.
    #[test]
    fn gpt_5_6_luna_keeps_sampling_with_effort_none() {
        let mut request = req("gpt-5.6-luna");
        request.reasoning_effort = Some(ReasoningEffort::None);
        let r = resolve(&request);
        assert_eq!(r.effort, Some(ReasoningEffort::None));
        assert_eq!(r.temperature, Some(0.0));
        assert_eq!(r.top_p, Some(0.5));
        assert_eq!(r.seed, Some(7));
    }

    #[test]
    fn effort_is_clamped_or_dropped_per_model() {
        let mut request = req("gpt-5.5");
        request.reasoning_effort = Some(ReasoningEffort::Max);
        assert_eq!(resolve(&request).effort, Some(ReasoningEffort::XHigh));
        request.model = "gpt-4o".to_string();
        assert_eq!(resolve(&request).effort, None);
        request.model = "o3".to_string();
        request.reasoning_effort = Some(ReasoningEffort::High);
        assert_eq!(resolve(&request).effort, Some(ReasoningEffort::High));
    }

    #[test]
    fn a_non_reasoning_model_keeps_every_sampling_knob() {
        let r = resolve(&req("gpt-4o"));
        assert_eq!(
            (r.temperature, r.top_p, r.seed),
            (Some(0.0), Some(0.5), Some(7))
        );
        assert_eq!(r.max_tokens, 1000);
    }

    #[test]
    fn a_rejecting_model_drops_sampling_with_the_plain_reason() {
        let r = resolve(&req("o3"));
        assert_eq!((r.temperature, r.top_p, r.seed), (None, None, None));
    }

    #[test]
    fn one_of_temperature_or_top_p_keeps_temperature() {
        // Only Claude rows use this rule today, but the resolver applies
        // it whichever dialect asks.
        let r = resolve(&req("claude-opus-4-6"));
        assert_eq!(r.temperature, Some(0.0));
        assert_eq!(r.top_p, None);
        let mut only_top_p = req("claude-opus-4-6");
        only_top_p.temperature = None;
        assert_eq!(resolve(&only_top_p).top_p, Some(0.5));
    }

    #[test]
    fn max_tokens_is_capped_at_the_published_ceiling() {
        let mut request = req("gpt-5.6-luna");
        request.max_tokens = 500_000;
        assert_eq!(resolve(&request).max_tokens, 128_000);
    }

    #[test]
    fn nothing_requested_means_nothing_sent() {
        let r = resolve(&ChatRequest::new("gpt-5.6-luna", Vec::new(), 10));
        assert_eq!(
            (r.effort, r.temperature, r.top_p, r.seed),
            (None, None, None, None)
        );
    }
}
