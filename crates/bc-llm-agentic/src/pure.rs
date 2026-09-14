//! Pure, deterministic pieces of the agentic loop — no I/O, no async —
//! ported from the identical logic duplicated across `backends/oai.py`
//! (`_cap_tool_result`, `_shrink_history`) and mirrored by
//! `backends/sdk.py`'s own context-overflow handling.

use bc_llm_client::{ContentBlock, Message, Role};

/// Per-tool-result cap kept in the message history (~12K tokens). A single
/// large tool result would otherwise accumulate across turns and blow past
/// the model's input limit on its own.
pub const TOOL_RESULT_CAP: usize = 48_000;

const SHRINK_THRESHOLD: usize = 1_200;
const SHRINK_KEEP: usize = 800;
const EVICTED_MARK: &str = "[evicted to fit context]";

/// Truncate a single tool result to [`TOOL_RESULT_CAP`] characters, applied
/// proactively to every tool result before it's appended to history.
pub fn cap_tool_result(result: &str) -> String {
    let char_count = result.chars().count();
    if char_count <= TOOL_RESULT_CAP {
        return result.to_string();
    }
    let truncated: String = result.chars().take(TOOL_RESULT_CAP).collect();
    let extra = char_count - TOOL_RESULT_CAP;
    format!(
        "{truncated}\n\n…[truncated {extra} chars to fit context — re-read a specific line \
         range with Read offset/limit if you need more]"
    )
}

/// Evict the OLDEST not-yet-evicted oversized tool result (replace with a
/// short stub) to claw back context after a [`bc_llm_client::LlmError::ContextOverflow`].
/// Returns `true` if it shrank something, `false` once every oversized tool
/// result has already been evicted — so repeated calls advance through all
/// large reads instead of re-picking the first one, and the caller stops
/// cleanly when there is nothing left to free.
pub fn shrink_history(messages: &mut [Message]) -> bool {
    for message in messages.iter_mut() {
        if message.role != Role::Tool {
            continue;
        }
        if let Some(ContentBlock::ToolResult { content, .. }) = message.content.first_mut() {
            if content.chars().count() > SHRINK_THRESHOLD && !content.ends_with(EVICTED_MARK) {
                let kept: String = content.chars().take(SHRINK_KEEP).collect();
                *content = format!("{kept}\n…{EVICTED_MARK}");
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_result_content(message: &Message) -> &str {
        match message.content.first() {
            Some(ContentBlock::ToolResult { content, .. }) => content,
            _ => "",
        }
    }

    #[test]
    fn cap_tool_result_leaves_short_results_untouched() {
        assert_eq!(cap_tool_result("short"), "short");
    }

    #[test]
    fn cap_tool_result_truncates_and_reports_the_overflow() {
        let long = "a".repeat(TOOL_RESULT_CAP + 100);
        let capped = cap_tool_result(&long);
        assert!(capped.starts_with(&"a".repeat(TOOL_RESULT_CAP)));
        assert!(capped.contains("truncated 100 chars"));
    }

    #[test]
    fn cap_tool_result_boundary_exactly_at_cap_is_untouched() {
        let exact = "a".repeat(TOOL_RESULT_CAP);
        assert_eq!(cap_tool_result(&exact), exact);
    }

    #[test]
    fn shrink_history_evicts_the_oldest_oversized_tool_result() {
        let mut messages = vec![
            Message::user_text("hi"),
            Message::tool_result("1", "x".repeat(SHRINK_THRESHOLD + 1), false),
            Message::tool_result("2", "y".repeat(SHRINK_THRESHOLD + 1), false),
        ];
        assert!(shrink_history(&mut messages));
        let content = tool_result_content(&messages[1]);
        assert!(content.ends_with(EVICTED_MARK));
        // kept + '\n' + '…' + EVICTED_MARK
        assert_eq!(
            content.chars().count(),
            SHRINK_KEEP + 2 + EVICTED_MARK.chars().count()
        );
        // The second oversized result is untouched by this call.
        assert!(!tool_result_content(&messages[2]).ends_with(EVICTED_MARK));
    }

    #[test]
    fn shrink_history_advances_past_an_already_evicted_result() {
        let mut messages = vec![
            Message::tool_result("1", "x".repeat(SHRINK_THRESHOLD + 1), false),
            Message::tool_result("2", "y".repeat(SHRINK_THRESHOLD + 1), false),
        ];
        assert!(shrink_history(&mut messages));
        assert!(shrink_history(&mut messages));
        assert!(tool_result_content(&messages[0]).ends_with(EVICTED_MARK));
        assert!(tool_result_content(&messages[1]).ends_with(EVICTED_MARK));
    }

    #[test]
    fn shrink_history_returns_false_once_nothing_is_left_to_shrink() {
        let mut messages = vec![Message::tool_result("1", "short", false)];
        assert!(!shrink_history(&mut messages));
    }

    #[test]
    fn shrink_history_ignores_non_tool_messages() {
        let mut messages = vec![Message::user_text("x".repeat(SHRINK_THRESHOLD + 1))];
        assert!(!shrink_history(&mut messages));
    }

    #[test]
    fn shrink_history_ignores_a_tool_result_at_or_under_the_threshold() {
        let mut messages = vec![Message::tool_result(
            "1",
            "x".repeat(SHRINK_THRESHOLD),
            false,
        )];
        assert!(!shrink_history(&mut messages));
    }

    #[test]
    fn shrink_history_ignores_a_tool_role_message_without_a_tool_result_block() {
        // `Message`'s fields are public, so a `Role::Tool` message that
        // doesn't wrap a `ToolResult` block (never produced by
        // `Message::tool_result` itself) is reachable through direct
        // construction, just like the analogous case in
        // `bc-llm-openai`/`bc-llm-anthropic`'s request builders.
        let mut messages = vec![Message {
            role: Role::Tool,
            content: vec![ContentBlock::text("x".repeat(SHRINK_THRESHOLD + 1))],
        }];
        assert!(!shrink_history(&mut messages));
        assert_eq!(tool_result_content(&messages[0]), "");
    }
}
