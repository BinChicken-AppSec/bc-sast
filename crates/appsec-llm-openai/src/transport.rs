use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use appsec_llm_client::OpenAiApi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelTransport {
    Unknown,
    Proven,
    ChatOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeRejection {
    NoRoute,
    UnknownParameter,
    NoOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Chat { auto: bool },
    Responses { may_fall_back: bool },
}

pub fn route(
    configured: OpenAiApi,
    per_request: Option<OpenAiApi>,
    state: ModelTransport,
    reasoning_family: bool,
) -> Route {
    match per_request.unwrap_or(configured) {
        OpenAiApi::Chat => Route::Chat { auto: false },
        OpenAiApi::Responses => Route::Responses {
            may_fall_back: false,
        },
        OpenAiApi::Auto => match state {
            ModelTransport::ChatOnly => Route::Chat { auto: true },
            ModelTransport::Proven => Route::Responses {
                may_fall_back: true,
            },
            ModelTransport::Unknown if reasoning_family => Route::Responses {
                may_fall_back: true,
            },
            ModelTransport::Unknown => Route::Chat { auto: true },
        },
    }
}

impl ModelTransport {
    pub fn endpoint(self) -> &'static str {
        match self {
            ModelTransport::Proven => "responses",
            ModelTransport::ChatOnly | ModelTransport::Unknown => "chat",
        }
    }

    pub fn fell_back(self) -> bool {
        self == ModelTransport::ChatOnly
    }
}

const UNKNOWN_PARAM_MARKERS: &[&str] = &[
    "unknown parameter",
    "unsupported parameter",
    "unrecognized parameter",
    "unrecognised parameter",
    "unrecognized request argument",
    "unknown field",
    "unrecognized field",
    "extra inputs are not permitted",
];

const RESPONSES_ONLY_PARAMS: &[&str] = &[
    "input",
    "instructions",
    "store",
    "include",
    "max_output_tokens",
];

pub fn responses_shape_rejection(status: u16, body: &str) -> Option<ShapeRejection> {
    match status {
        404 | 405 | 501 => Some(ShapeRejection::NoRoute),
        400 => {
            let lower = body.to_ascii_lowercase();
            let unknown = UNKNOWN_PARAM_MARKERS.iter().any(|m| lower.contains(m));
            let names_ours = RESPONSES_ONLY_PARAMS.iter().any(|p| lower.contains(p));
            (unknown && names_ours).then_some(ShapeRejection::UnknownParameter)
        }
        _ => None,
    }
}

pub fn wants_responses_api(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("/v1/responses") || lower.contains("responses api")
}

#[derive(Debug, Default)]
pub struct TransportMemory {
    states: Mutex<HashMap<String, ModelTransport>>,
    fallbacks: AtomicU64,
    warned: Mutex<HashSet<String>>,
}

impl TransportMemory {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, ModelTransport>> {
        self.states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn state(&self, model: &str) -> ModelTransport {
        self.lock()
            .get(model)
            .copied()
            .unwrap_or(ModelTransport::Unknown)
    }

    pub fn may_fall_back(&self, model: &str, kind: ShapeRejection) -> bool {
        self.state(model) != ModelTransport::Proven || kind != ShapeRejection::NoOutput
    }

    pub(crate) fn mark_proven(&self, model: &str) {
        self.lock()
            .insert(model.to_string(), ModelTransport::Proven);
    }

    pub(crate) fn learn_chat_only(&self, model: &str, why: ShapeRejection) {
        self.lock()
            .insert(model.to_string(), ModelTransport::ChatOnly);
        self.fallbacks.fetch_add(1, Ordering::Relaxed);
        let first = self
            .warned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(model.to_string());
        if first {
            tracing::warn!(
                model,
                reason = ?why,
                "[openai] {model}: the endpoint rejected the Responses API request shape; \
                 retrying on Chat Completions and using it for this model from now on"
            );
        }
    }

    pub(crate) fn forget(&self, model: &str) {
        self.lock().remove(model);
    }

    pub(crate) fn restore(&self, model: &str, state: ModelTransport) {
        match state {
            ModelTransport::Unknown => self.forget(model),
            known => {
                self.lock().insert(model.to_string(), known);
            }
        }
    }

    pub fn fallbacks(&self) -> u64 {
        self.fallbacks.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoint_label_reads_unknown_as_chat() {
        assert_eq!(ModelTransport::Proven.endpoint(), "responses");
        assert_eq!(ModelTransport::ChatOnly.endpoint(), "chat");
        assert_eq!(ModelTransport::Unknown.endpoint(), "chat");
        assert!(ModelTransport::ChatOnly.fell_back());
        assert!(!ModelTransport::Proven.fell_back());
        assert!(
            !ModelTransport::Unknown.fell_back(),
            "started on chat, never rejected from responses"
        );
    }

    #[test]
    fn the_per_request_pin_wins_over_the_configured_api() {
        let unknown = ModelTransport::Unknown;
        assert_eq!(
            route(OpenAiApi::Chat, Some(OpenAiApi::Responses), unknown, false),
            Route::Responses {
                may_fall_back: false
            }
        );
        assert_eq!(
            route(OpenAiApi::Auto, Some(OpenAiApi::Chat), unknown, true),
            Route::Chat { auto: false }
        );
        assert_eq!(
            route(OpenAiApi::Chat, None, unknown, true),
            Route::Chat { auto: false }
        );
    }

    #[test]
    fn auto_starts_reasoning_families_on_responses_and_the_rest_on_chat() {
        let responses = Route::Responses {
            may_fall_back: true,
        };
        assert_eq!(
            route(OpenAiApi::Auto, None, ModelTransport::Unknown, true),
            responses
        );
        assert_eq!(
            route(OpenAiApi::Auto, None, ModelTransport::Unknown, false),
            Route::Chat { auto: true }
        );
        assert_eq!(
            route(OpenAiApi::Auto, None, ModelTransport::Proven, false),
            responses
        );
        assert_eq!(
            route(OpenAiApi::Auto, None, ModelTransport::ChatOnly, true),
            Route::Chat { auto: true }
        );
        assert_eq!(
            route(OpenAiApi::Responses, None, ModelTransport::ChatOnly, false),
            Route::Responses {
                may_fall_back: false
            }
        );
    }

    #[test]
    fn only_shape_evidence_counts_as_a_rejection() {
        for status in [404, 405, 501] {
            assert_eq!(
                responses_shape_rejection(status, ""),
                Some(ShapeRejection::NoRoute)
            );
        }
        assert_eq!(
            responses_shape_rejection(400, "Unrecognized request argument supplied: input"),
            Some(ShapeRejection::UnknownParameter)
        );
        assert_eq!(
            responses_shape_rejection(400, r#"{"error":"Unknown parameter: 'store'"}"#),
            Some(ShapeRejection::UnknownParameter)
        );
        assert_eq!(
            responses_shape_rejection(400, "Unknown parameter: 'foo'"),
            None
        );
        assert_eq!(responses_shape_rejection(400, "input is too long"), None);
        for status in [401, 403, 429, 500, 502, 503] {
            assert_eq!(
                responses_shape_rejection(status, "Unknown parameter: input"),
                None
            );
        }
    }

    #[test]
    fn the_chat_rejection_pointing_at_responses_is_recognized() {
        assert!(wants_responses_api(
            "Function tools with reasoning_effort are not supported for gpt-5.6-luna in \
             /v1/chat/completions. To use function tools, use /v1/responses or set \
             reasoning_effort to 'none'."
        ));
        assert!(wants_responses_api("please use the Responses API"));
        assert!(!wants_responses_api("temperature is not supported"));
    }

    #[test]
    fn memory_learns_proves_and_forgets() {
        let m = TransportMemory::default();
        assert_eq!(m.state("gpt-x"), ModelTransport::Unknown);
        m.learn_chat_only("gpt-x", ShapeRejection::NoRoute);
        m.learn_chat_only("gpt-x", ShapeRejection::NoRoute);
        assert_eq!(m.state("gpt-x"), ModelTransport::ChatOnly);
        assert_eq!(m.fallbacks(), 2);
        m.forget("gpt-x");
        assert_eq!(m.state("gpt-x"), ModelTransport::Unknown);
        m.mark_proven("gpt-x");
        assert_eq!(m.state("gpt-x"), ModelTransport::Proven);
        m.restore("gpt-x", ModelTransport::ChatOnly);
        assert_eq!(m.state("gpt-x"), ModelTransport::ChatOnly);
        m.restore("gpt-x", ModelTransport::Unknown);
        assert_eq!(m.state("gpt-x"), ModelTransport::Unknown);
        assert_eq!(m.fallbacks(), 2, "a restore is not a fallback");
    }

    #[test]
    fn a_proven_model_does_not_fall_back_on_a_missing_output_alone() {
        let m = TransportMemory::default();
        assert!(m.may_fall_back("gpt-x", ShapeRejection::NoOutput));
        m.mark_proven("gpt-x");
        assert!(!m.may_fall_back("gpt-x", ShapeRejection::NoOutput));
        assert!(m.may_fall_back("gpt-x", ShapeRejection::NoRoute));
        assert!(m.may_fall_back("gpt-x", ShapeRejection::UnknownParameter));
    }
}
