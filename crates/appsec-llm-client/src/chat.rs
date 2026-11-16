use crate::cache::CachePolicy;
use crate::effort::ReasoningEffort;
use crate::message::{ContentBlock, Message};
use crate::openai_api::OpenAiApi;
use crate::tool::ToolSpec;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ChatRequest {
    pub model: String,
    pub system: Option<String>,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
    pub max_tokens: u32,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
    pub thinking_budget: Option<u32>,
    pub betas: Vec<String>,
    pub json_mode: bool,
    pub stream: bool,
    pub timeout: Option<std::time::Duration>,
    pub reasoning_effort: Option<ReasoningEffort>,
    pub openai_api: Option<OpenAiApi>,
    pub cache_prefix: Option<String>,
    pub cache_key: Option<String>,
    pub cache: CachePolicy,
}

impl ChatRequest {
    pub fn new(model: impl Into<String>, messages: Vec<Message>, max_tokens: u32) -> Self {
        ChatRequest {
            model: model.into(),
            system: None,
            messages,
            tools: Vec::new(),
            max_tokens,
            temperature: None,
            top_p: None,
            seed: None,
            thinking_budget: None,
            betas: Vec::new(),
            json_mode: false,
            timeout: None,
            stream: false,
            reasoning_effort: None,
            openai_api: None,
            cache_prefix: None,
            cache_key: None,
            cache: CachePolicy::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation_input_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub reasoning_output_tokens: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChatResponse {
    pub content: Vec<ContentBlock>,
    pub stop_reason: StopReason,
    pub usage: Usage,
}

impl ChatResponse {
    pub fn text(&self) -> String {
        self.content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect()
    }

    pub fn tool_uses(&self) -> Vec<(&str, &str, &serde_json::Value)> {
        self.content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::ToolUse { id, name, input } => {
                    Some((id.as_str(), name.as_str(), input))
                }
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;

    #[test]
    fn chat_request_new_has_no_tools_or_extras() {
        let req = ChatRequest::new("gpt-4o", vec![Message::user_text("hi")], 1024);
        assert_eq!(req.model, "gpt-4o");
        assert!(req.system.is_none());
        assert!(req.tools.is_empty());
        assert_eq!(req.max_tokens, 1024);
        assert!(req.temperature.is_none());
        assert!(req.top_p.is_none());
        assert!(req.seed.is_none());
        assert!(req.thinking_budget.is_none());
        assert!(req.betas.is_empty());
        assert!(!req.json_mode);
        assert!(req.timeout.is_none());
        assert!(
            !req.stream,
            "streaming is opt-in — every existing caller keeps the single-response path"
        );
        assert!(req.reasoning_effort.is_none());
        assert!(req.openai_api.is_none());
        assert!(req.cache_prefix.is_none());
        assert!(req.cache_key.is_none());
        assert_eq!(req.cache, CachePolicy::default());
    }

    #[test]
    fn default_matches_new_apart_from_the_placeholders() {
        let from_default = ChatRequest {
            model: "m".to_string(),
            max_tokens: 7,
            ..ChatRequest::default()
        };
        assert_eq!(from_default, ChatRequest::new("m", Vec::new(), 7));
    }

    #[test]
    fn text_and_tool_uses_ignore_opaque_blocks() {
        let resp = ChatResponse {
            content: vec![
                ContentBlock::Opaque {
                    dialect: crate::message::OpaqueDialect::OpenAiResponses,
                    payload: serde_json::json!({"type": "reasoning"}),
                },
                ContentBlock::text("answer"),
            ],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        };
        assert_eq!(resp.text(), "answer");
        assert!(resp.tool_uses().is_empty());
    }

    #[test]
    fn stop_reason_equality() {
        assert_eq!(StopReason::EndTurn, StopReason::EndTurn);
        assert_eq!(
            StopReason::Other("x".to_string()),
            StopReason::Other("x".to_string())
        );
        assert_ne!(StopReason::EndTurn, StopReason::ToolUse);
    }

    #[test]
    fn usage_defaults_to_zero() {
        assert_eq!(
            Usage::default(),
            Usage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: 0,
                cache_read_input_tokens: 0,
                reasoning_output_tokens: 0,
            }
        );
    }

    #[test]
    fn chat_response_text_concatenates_text_blocks_and_skips_others() {
        let resp = ChatResponse {
            content: vec![
                ContentBlock::text("part one "),
                ContentBlock::ToolUse {
                    id: "1".to_string(),
                    name: "Read".to_string(),
                    input: serde_json::json!({}),
                },
                ContentBlock::text("part two"),
            ],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        };
        assert_eq!(resp.text(), "part one part two");
    }

    #[test]
    fn chat_response_text_is_empty_when_there_is_no_text_block() {
        let resp = ChatResponse {
            content: vec![ContentBlock::ToolUse {
                id: "1".to_string(),
                name: "Read".to_string(),
                input: serde_json::json!({}),
            }],
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        };
        assert_eq!(resp.text(), "");
    }

    #[test]
    fn chat_response_tool_uses_extracts_all_tool_calls_in_order() {
        let resp = ChatResponse {
            content: vec![
                ContentBlock::text("calling tools"),
                ContentBlock::ToolUse {
                    id: "1".to_string(),
                    name: "Read".to_string(),
                    input: serde_json::json!({"path": "a"}),
                },
                ContentBlock::ToolUse {
                    id: "2".to_string(),
                    name: "Glob".to_string(),
                    input: serde_json::json!({"pattern": "*.rs"}),
                },
            ],
            stop_reason: StopReason::ToolUse,
            usage: Usage::default(),
        };
        let calls = resp.tool_uses();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "1");
        assert_eq!(calls[0].1, "Read");
        assert_eq!(calls[0].2, &serde_json::json!({"path": "a"}));
        assert_eq!(calls[1].1, "Glob");
    }

    #[test]
    fn chat_response_tool_uses_is_empty_when_there_are_no_tool_calls() {
        let resp = ChatResponse {
            content: vec![ContentBlock::text("just text")],
            stop_reason: StopReason::EndTurn,
            usage: Usage::default(),
        };
        assert!(resp.tool_uses().is_empty());
    }
}
