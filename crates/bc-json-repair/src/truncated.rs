//! Recovering the complete prefix of a JSON document that was cut off
//! mid-value, for a model reply that stopped at its output-token budget
//! (VVAH-E005).
//!
//! Not a port: the Python original re-asks the model for a truncated
//! reply and otherwise drops it. Keeping the values that DID arrive whole
//! (the first ninety findings of a hundred, say) loses less than dropping
//! the reply, so this cuts the text back to the end of the last value
//! that closed and closes every bracket still open above it.
//!
//! Callers use it only for a reply known to be truncated. On a complete
//! but malformed reply it would quietly discard the malformed tail, which
//! is the job of the syntax-repair re-ask, not of this.

use serde_json::Value;

use crate::{extract_json, ExtractError};

/// The first JSON document in `text`, closed if it was cut off.
///
/// The closing pass runs FIRST: on a cut-off document, [`extract_json`]'s
/// balanced-span search finds the first nested value that did close (one
/// finding object, say) and returns that instead of the document, which
/// only turns a truncation into a shape error downstream. When the closed
/// prefix still does not parse, that is reported as invalid rather than
/// hidden behind an inner fragment. Text with no bracket at all falls
/// through to [`extract_json`] for its ordinary error.
pub fn extract_truncated_json(text: &str) -> Result<Value, ExtractError> {
    match close_truncated(text) {
        Some(closed) => serde_json::from_str(&closed).map_err(ExtractError::from),
        None => extract_json(text),
    }
}

/// The first JSON document in `text` cut back to the end of its last
/// complete nested value, with every still-open bracket closed. `None`
/// when there is no opening bracket or no nested value ever completed.
pub fn close_truncated(text: &str) -> Option<String> {
    let start = text.find(['{', '['])?;
    let body = &text[start..];
    let mut stack: Vec<char> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    // (byte offset just past a closing bracket, brackets still open there)
    let mut last_cut: Option<(usize, Vec<char>)> = None;
    for (i, c) in body.char_indices() {
        if in_string {
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' | '[' => stack.push(c),
            '}' | ']' => {
                stack.pop();
                if stack.is_empty() {
                    // The document closed after all: nothing was cut off.
                    return Some(body[..=i].to_string());
                }
                last_cut = Some((i + 1, stack.clone()));
            }
            _ => {}
        }
    }
    let (end, open) = last_cut?;
    let mut closed = body[..end].to_string();
    for bracket in open.iter().rev() {
        closed.push(if *bracket == '{' { '}' } else { ']' });
    }
    Some(closed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_findings_list_cut_mid_element_keeps_the_complete_elements() {
        let cut = r#"{"findings": [{"file": "a.py", "line": 1}, {"file": "b.py", "li"#;
        assert_eq!(
            extract_truncated_json(cut).unwrap(),
            json!({"findings": [{"file": "a.py", "line": 1}]})
        );
    }

    #[test]
    fn brackets_and_escaped_quotes_inside_strings_are_not_structure() {
        let cut = r#"prose {"a": [{"s": "x ] } \" ["}, {"s": "unfinished"#;
        assert_eq!(
            extract_truncated_json(cut).unwrap(),
            json!({"a": [{"s": "x ] } \" ["}]})
        );
    }

    #[test]
    fn a_nested_array_cut_off_closes_every_level() {
        let cut = "[[1, 2], [3, [4, 5], [6";
        assert_eq!(close_truncated(cut).unwrap(), "[[1, 2], [3, [4, 5]]]");
    }

    #[test]
    fn a_complete_document_is_returned_unchanged() {
        assert_eq!(
            extract_truncated_json(r#"{"a": 1}"#).unwrap(),
            json!({"a": 1})
        );
        assert_eq!(
            close_truncated(r#"x {"a": [1]} y"#).unwrap(),
            r#"{"a": [1]}"#
        );
    }

    #[test]
    fn nothing_recoverable_keeps_the_original_error() {
        assert!(close_truncated("no json here").is_none());
        assert!(close_truncated(r#"{"only": "a scalar"#).is_none());
        assert!(matches!(
            extract_truncated_json("no json here"),
            Err(ExtractError::NotFound)
        ));
    }

    #[test]
    fn a_closed_prefix_that_still_does_not_parse_is_an_invalid_error() {
        // The closed prefix `{"a" 1, "b": [2]}` is not JSON: reported,
        // not hidden.
        assert!(matches!(
            extract_truncated_json(r#"{"a" 1, "b": [2], "c": [3"#),
            Err(ExtractError::Invalid(_))
        ));
    }
}
