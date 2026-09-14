//! The dialect-agnostic chat message shape every `LlmClient` implementation
//! converts to and from its own wire format (OpenAI's `messages: [...]`
//! array with a separate `tool` role, Anthropic's `messages: [...]` array
//! that folds tool results into a `user`-role message's content blocks).

use serde_json::Value;

/// Who a [`Message`] is attributed to. `Tool` exists as a distinct role
/// (rather than folding tool results into `User`) because that is the
/// OpenAI-dialect convention (one `role: "tool"` message per result,
/// addressed by `tool_call_id`); the Anthropic dialect instead groups
/// consecutive `Tool` messages into a single `user`-role message with
/// multiple `tool_result` content blocks when it serializes a request —
/// that grouping is a dialect-implementation detail, not part of this
/// neutral shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
    Tool,
}

/// One piece of a [`Message`]'s content. A single message can carry more
/// than one block (e.g. an assistant turn that emits explanatory text
/// alongside a tool call).
#[derive(Debug, Clone, PartialEq)]
pub enum ContentBlock {
    Text(String),
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
}

impl ContentBlock {
    pub fn text(s: impl Into<String>) -> Self {
        ContentBlock::Text(s.into())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

impl Message {
    pub fn user_text(text: impl Into<String>) -> Self {
        Message {
            role: Role::User,
            content: vec![ContentBlock::text(text)],
        }
    }

    pub fn assistant(content: Vec<ContentBlock>) -> Self {
        Message {
            role: Role::Assistant,
            content,
        }
    }

    pub fn tool_result(
        tool_use_id: impl Into<String>,
        content: impl Into<String>,
        is_error: bool,
    ) -> Self {
        Message {
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: tool_use_id.into(),
                content: content.into(),
                is_error,
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_block_text_helper() {
        assert_eq!(
            ContentBlock::text("hi"),
            ContentBlock::Text("hi".to_string())
        );
    }

    #[test]
    fn message_user_text_wraps_a_single_text_block() {
        let m = Message::user_text("hello");
        assert_eq!(m.role, Role::User);
        assert_eq!(m.content, vec![ContentBlock::Text("hello".to_string())]);
    }

    #[test]
    fn message_assistant_carries_arbitrary_content() {
        let blocks = vec![
            ContentBlock::text("thinking out loud"),
            ContentBlock::ToolUse {
                id: "call_1".to_string(),
                name: "Read".to_string(),
                input: serde_json::json!({"path": "a.rs"}),
            },
        ];
        let m = Message::assistant(blocks.clone());
        assert_eq!(m.role, Role::Assistant);
        assert_eq!(m.content, blocks);
    }

    #[test]
    fn message_tool_result_wraps_a_single_tool_result_block() {
        let m = Message::tool_result("call_1", "file contents", false);
        assert_eq!(m.role, Role::Tool);
        assert_eq!(
            m.content,
            vec![ContentBlock::ToolResult {
                tool_use_id: "call_1".to_string(),
                content: "file contents".to_string(),
                is_error: false,
            }]
        );
    }

    #[test]
    fn role_and_content_block_are_comparable_and_cloneable() {
        assert_eq!(Role::User, Role::User);
        assert_ne!(Role::User, Role::Assistant);
        let block = ContentBlock::text("x");
        assert_eq!(block.clone(), block);
    }

    #[test]
    fn debug_impls_do_not_panic() {
        let _ = format!("{:?}", Role::Tool);
        let _ = format!("{:?}", ContentBlock::text("x"));
        let _ = format!("{:?}", Message::user_text("x"));
    }
}
