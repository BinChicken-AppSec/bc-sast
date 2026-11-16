use serde_json::Value;

use crate::{extract_json, ExtractError};

pub fn extract_truncated_json(text: &str) -> Result<Value, ExtractError> {
    match close_truncated(text) {
        Some(closed) => serde_json::from_str(&closed).map_err(ExtractError::from),
        None => extract_json(text),
    }
}

pub fn close_truncated(text: &str) -> Option<String> {
    let start = text.find(['{', '['])?;
    let body = &text[start..];
    let mut stack: Vec<char> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
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
        assert!(matches!(
            extract_truncated_json(r#"{"a" 1, "b": [2], "c": [3"#),
            Err(ExtractError::Invalid(_))
        ));
    }
}
