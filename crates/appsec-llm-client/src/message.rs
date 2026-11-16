use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
    Tool,
}

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
    Opaque {
        dialect: OpaqueDialect,
        payload: Value,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpaqueDialect {
    OpenAiResponses,
    Anthropic,
}

impl ContentBlock {
    pub fn text(s: impl Into<String>) -> Self {
        ContentBlock::Text(s.into())
    }

    pub fn opaque_for(&self, dialect: OpaqueDialect) -> Option<&Value> {
        match self {
            ContentBlock::Opaque {
                dialect: d,
                payload,
            } if *d == dialect => Some(payload),
            _ => None,
        }
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
    fn opaque_for_returns_the_payload_only_to_its_own_dialect() {
        let block = ContentBlock::Opaque {
            dialect: OpaqueDialect::Anthropic,
            payload: serde_json::json!({"type": "thinking"}),
        };
        assert_eq!(
            block.opaque_for(OpaqueDialect::Anthropic),
            Some(&serde_json::json!({"type": "thinking"}))
        );
        assert_eq!(block.opaque_for(OpaqueDialect::OpenAiResponses), None);
        assert_eq!(
            ContentBlock::text("x").opaque_for(OpaqueDialect::Anthropic),
            None
        );
    }

    #[test]
    fn debug_impls_do_not_panic() {
        let _ = format!("{:?}", Role::Tool);
        let _ = format!("{:?}", ContentBlock::text("x"));
        let _ = format!("{:?}", Message::user_text("x"));
    }
}
