//! [`OpenAiApi`]: which OpenAI HTTP API shape a request should use.
//!
//! Lives here rather than in `bc-llm-openai` because a per-role transport
//! pin (the Python original's `models.<role>.use_responses_api`) has to
//! ride on the [`crate::ChatRequest`] itself: `bc-cli` builds ONE client
//! for every stage, so a per-role choice cannot be client configuration.
//! `bc-llm-openai` re-exports it, and the Anthropic dialect ignores it.

use std::fmt;
use std::str::FromStr;

/// The OpenAI API shape to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OpenAiApi {
    /// `POST {base}/chat/completions`. The default, so an upgrade changes
    /// nothing on the wire until an operator opts in.
    #[default]
    Chat,
    /// `POST {base}/responses`, pinned: never falls back.
    Responses,
    /// The Responses API first, falling back to Chat Completions (and
    /// remembering that for the model) only when the endpoint rejects the
    /// Responses request SHAPE. Mirrors the Python original's default
    /// transport resolution
    /// (`deepagents/options/model_building.py::resolve_use_responses_api`).
    Auto,
}

impl OpenAiApi {
    /// The config spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            OpenAiApi::Chat => "chat",
            OpenAiApi::Responses => "responses",
            OpenAiApi::Auto => "auto",
        }
    }

    /// The per-role override the Python original spells as
    /// `use_responses_api: bool`: `true` pins Responses, `false` pins
    /// Chat Completions.
    pub fn from_use_responses_api(use_responses_api: bool) -> Self {
        if use_responses_api {
            OpenAiApi::Responses
        } else {
            OpenAiApi::Chat
        }
    }
}

impl fmt::Display for OpenAiApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parses `chat`, `responses` or `auto`, ignoring case and surrounding
/// whitespace. Anything else is an error, so a typo in
/// `--openai-api`/`BC_OPENAI_API`/`llm.openai_api` fails the run instead
/// of silently selecting a transport.
impl FromStr for OpenAiApi {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "chat" => Ok(OpenAiApi::Chat),
            "responses" => Ok(OpenAiApi::Responses),
            "auto" => Ok(OpenAiApi::Auto),
            other => Err(format!(
                "unknown OpenAI API {other:?} (expected chat, responses or auto)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_chat_completions() {
        assert_eq!(OpenAiApi::default(), OpenAiApi::Chat);
    }

    #[test]
    fn every_variant_round_trips_through_its_config_spelling() {
        for api in [OpenAiApi::Chat, OpenAiApi::Responses, OpenAiApi::Auto] {
            assert_eq!(api.as_str().parse::<OpenAiApi>(), Ok(api));
            assert_eq!(api.to_string(), api.as_str());
        }
        assert_eq!(" AUTO ".parse(), Ok(OpenAiApi::Auto));
    }

    #[test]
    fn an_unknown_value_is_an_error() {
        assert!("completions".parse::<OpenAiApi>().is_err());
    }

    #[test]
    fn use_responses_api_maps_to_a_pinned_transport() {
        assert_eq!(
            OpenAiApi::from_use_responses_api(true),
            OpenAiApi::Responses
        );
        assert_eq!(OpenAiApi::from_use_responses_api(false), OpenAiApi::Chat);
    }
}
