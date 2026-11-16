use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OpenAiApi {
    #[default]
    Chat,
    Responses,
    Auto,
}

impl OpenAiApi {
    pub fn as_str(self) -> &'static str {
        match self {
            OpenAiApi::Chat => "chat",
            OpenAiApi::Responses => "responses",
            OpenAiApi::Auto => "auto",
        }
    }

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
