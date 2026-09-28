//! Which OpenAI API shape a call goes out on, and what this process has
//! learned about each model's support for the Responses API. Ported from
//! the Python original's transport resolution
//! (`deepagents/options/model_building.py::resolve_use_responses_api`)
//! and its learned fallback (`deepagents/client.py::_should_fall_back`,
//! `_learn_chat_completions_only`, `_RESPONSES_PROVEN_MODELS`).
//!
//! **Divergence from Python, deliberate.** Python falls back to Chat
//! Completions on ANY error from a model's first, unproven Responses
//! call, treating that call as the capability probe. A 429, a 5xx or a
//! timeout on that one call would then flip the model to Chat Completions
//! for the rest of the process, silently running a reasoning model
//! without its reasoning replay, on a transient fault that says nothing
//! about the endpoint's shape. Here the retry layer sits ABOVE the client
//! (`bc-llm-agentic`), so a transient error must reach it unchanged:
//! only a response that is evidence about the request SHAPE triggers a
//! fallback (see [`responses_shape_rejection`]).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use bc_llm_client::OpenAiApi;

/// What this process knows about one model's Responses API support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelTransport {
    /// Never tried, or un-learned after both transports failed.
    Unknown,
    /// At least one Responses API call succeeded.
    Proven,
    /// The endpoint rejected the Responses request shape for this model
    /// and Chat Completions then worked.
    ChatOnly,
}

/// Why a Responses call is evidence the endpoint does not speak the
/// Responses API for this model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeRejection {
    /// HTTP 404, 405 or 501: no `/responses` route at all.
    NoRoute,
    /// A 400 naming a Responses-only parameter as unknown.
    UnknownParameter,
    /// A 2xx whose body has no `output` array: something answered, but
    /// not with a Responses document.
    NoOutput,
}

/// Where one call goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Chat Completions. `auto` is whether the effective API was
    /// [`OpenAiApi::Auto`], which lets a Chat Completions rejection that
    /// says "use /v1/responses" switch this call to the Responses API.
    Chat { auto: bool },
    /// The Responses API. `may_fall_back` is whether a shape rejection
    /// may retry on Chat Completions (only in [`OpenAiApi::Auto`]).
    Responses { may_fall_back: bool },
}

/// The route for one call: the per-request pin wins over the client's
/// configured API, and `Auto` resolves through the learned state first
/// and the model's family second.
///
/// `reasoning_family` is whether `bc_llm_client::capabilities` knows the
/// model as a reasoning model (GPT-5.x, GPT-6, the o-series). Those start
/// on the Responses API, the only OpenAI endpoint that carries reasoning
/// across tool calls. Everything else, including a name the table does
/// not know, starts on Chat Completions; a Chat Completions rejection
/// pointing at `/v1/responses` then moves the model over (see
/// [`wants_responses_api`]), so a reasoning model hiding behind a gateway
/// alias still ends up on the right endpoint after one rejected call.
///
/// **Divergence from Python, deliberate**: Python's resolution sends
/// every non-Anthropic model to the Responses API first and falls back
/// on any error. Starting a known non-reasoning model (gpt-4o, gpt-4.1)
/// on Chat Completions avoids a guaranteed wasted call through gateways
/// that do not route `/responses` at all.
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

/// Phrases an endpoint uses to reject a parameter it does not know.
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

/// Parameters only the Responses API has. A rejection naming one of
/// these as unknown means the endpoint is not a Responses endpoint.
const RESPONSES_ONLY_PARAMS: &[&str] = &[
    "input",
    "instructions",
    "store",
    "include",
    "max_output_tokens",
];

/// Whether a non-2xx from `/responses` is evidence about the request
/// SHAPE (never about load or the network): a missing route, or a 400
/// naming a Responses-only parameter as unknown. 429, 5xx, and every
/// other 4xx are not.
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

/// Whether a Chat Completions 400 is the "function tools with
/// reasoning_effort are not supported ... use /v1/responses" rejection
/// newer reasoning models give on that endpoint.
pub fn wants_responses_api(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("/v1/responses") || lower.contains("responses api")
}

/// Per-model transport state, shared by every call through one client
/// (and by every client handed the same `Arc`).
#[derive(Debug, Default)]
pub struct TransportMemory {
    states: Mutex<HashMap<String, ModelTransport>>,
    fallbacks: AtomicU64,
    warned: Mutex<HashSet<String>>,
}

impl TransportMemory {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, ModelTransport>> {
        // A poisoned lock only means another call panicked mid-insert;
        // the map itself is still a valid map.
        self.states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// What is known about `model`.
    pub fn state(&self, model: &str) -> ModelTransport {
        self.lock()
            .get(model)
            .copied()
            .unwrap_or(ModelTransport::Unknown)
    }

    /// Whether a shape rejection of `kind` may send `model` back to Chat
    /// Completions. A model already proven on the Responses API falls
    /// back only on a missing route or an unknown-parameter rejection: a
    /// 2xx without `output` from an endpoint that has answered properly
    /// before is a bad response, not a different endpoint.
    pub fn may_fall_back(&self, model: &str, kind: ShapeRejection) -> bool {
        self.state(model) != ModelTransport::Proven || kind != ShapeRejection::NoOutput
    }

    pub(crate) fn mark_proven(&self, model: &str) {
        self.lock()
            .insert(model.to_string(), ModelTransport::Proven);
    }

    /// Record `model` as Chat-Completions-only, count the fallback, and
    /// warn the first time this model falls back.
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

    /// Forget whatever was learned about `model`: both transports failed
    /// (so the rejection proved nothing), or Chat Completions itself
    /// pointed back at the Responses API.
    pub(crate) fn forget(&self, model: &str) {
        self.lock().remove(model);
    }

    /// Put `model` back to a state read earlier, without counting or
    /// warning: an attempt to move it that failed changes nothing.
    pub(crate) fn restore(&self, model: &str, state: ModelTransport) {
        match state {
            ModelTransport::Unknown => self.forget(model),
            known => {
                self.lock().insert(model.to_string(), known);
            }
        }
    }

    /// How many times any model fell back from the Responses API to Chat
    /// Completions, for the run manifest (Python's
    /// `deepagents_responses_fallback` counter).
    pub fn fallbacks(&self) -> u64 {
        self.fallbacks.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Learned state outranks the family either way.
        assert_eq!(
            route(OpenAiApi::Auto, None, ModelTransport::Proven, false),
            responses
        );
        assert_eq!(
            route(OpenAiApi::Auto, None, ModelTransport::ChatOnly, true),
            Route::Chat { auto: true }
        );
        // A pinned Responses ignores the learned state entirely.
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
        // An unknown parameter that is not one of ours: some other bug.
        assert_eq!(
            responses_shape_rejection(400, "Unknown parameter: 'foo'"),
            None
        );
        // Naming ours without saying it is unknown: an ordinary 400.
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
