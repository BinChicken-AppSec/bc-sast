// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! Parse a deep-dive reply into its findings list, with one bounded repair
//! re-ask on failure. Ported from the v1.4.0 `s4_deepdive.py::_single_run`
//! parse block and `_repair_json_prompt`.
//!
//! Two different failures reach the repair and they need opposite
//! instructions. A syntax failure means the text is not valid JSON: fix
//! the syntax. A shape failure ([`crate::findings_shape::findings_list`])
//! means the text parsed perfectly and the SHAPE is wrong, so "fix the
//! JSON syntax only" would tell the model to correct something already
//! correct; it would return the same object, the shape check would refuse
//! it again, and the chunk would fail after paying twice for the same
//! (uncached, up to 64k-token) reply. So the prompt branches on the kind.

use serde_json::Value;

use crate::findings_shape::findings_list;

/// Output cap on the repair call. A repair restates findings the primary
/// reply already described, so it never needs the primary's full budget
/// (upstream: `min(step4.max_tokens, 12000)`).
pub(crate) const REPAIR_MAX_TOKENS: u32 = 12_000;

/// Why a reply could not be read as a findings list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseFailure {
    /// No JSON value could be extracted from the text at all.
    Syntax(String),
    /// Valid JSON, but not carrying a usable `findings` list.
    Shape(String),
}

impl std::fmt::Display for ParseFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseFailure::Syntax(m) => write!(f, "invalid JSON: {m}"),
            ParseFailure::Shape(m) => write!(f, "wrong shape: {m}"),
        }
    }
}

/// Extract JSON from `raw` and return its findings list.
///
/// `truncated` is whether the reply stopped at its output budget
/// (VVAH-E005): its cut-off document is closed back to the last complete
/// finding rather than searched for the first balanced fragment, which
/// would find one finding object and call it the wrong shape.
pub(crate) fn parse_findings(raw: &str, truncated: bool) -> Result<Vec<Value>, ParseFailure> {
    let extracted = if truncated {
        bc_json_repair::extract_truncated_json(raw)
    } else {
        bc_json_repair::extract_json(raw)
    };
    let data = extracted.map_err(|e| ParseFailure::Syntax(e.to_string()))?;
    findings_list(&data).map_err(ParseFailure::Shape)
}

/// The repair prompt for `raw`, worded for the kind of `failure`.
pub(crate) fn repair_json_prompt(raw: &str, failure: &ParseFailure) -> String {
    let task = match failure {
        ParseFailure::Shape(_) => {
            "The previous s4 response was VALID JSON but the wrong shape: it carried no usable \
             `findings` list.\nReturn ONLY a JSON object of the form {\"findings\": [...]}, \
             preserving every finding the response already describes. If it genuinely found \
             nothing, return exactly {\"findings\": []}. Do not rename the key and do not use \
             null for the list."
        }
        ParseFailure::Syntax(_) => {
            "The previous s4 response was intended to be JSON but failed to parse.\nFix the \
             JSON syntax only and return ONLY a valid JSON object that preserves the same \
             findings content as much as possible."
        }
    };
    format!("REPAIR TASK:\n{task}\n\nFAILURE:\n{failure}\n\nPREVIOUS RESPONSE:\n{raw}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_findings_distinguishes_syntax_from_shape() {
        assert!(matches!(
            parse_findings("not json", false),
            Err(ParseFailure::Syntax(_))
        ));
        assert!(matches!(
            parse_findings(r#"{"findings": null}"#, false),
            Err(ParseFailure::Shape(_))
        ));
        assert_eq!(
            parse_findings(r#"{"findings": []}"#, false).unwrap(),
            Vec::<Value>::new()
        );
    }

    #[test]
    fn the_shape_prompt_asks_for_the_key_not_a_syntax_fix() {
        let p = repair_json_prompt("{}", &ParseFailure::Shape("no list".into()));
        assert!(p.starts_with("REPAIR TASK:\nThe previous s4 response was VALID JSON"));
        assert!(p.contains("return exactly {\"findings\": []}"));
        assert!(p.contains("FAILURE:\nwrong shape: no list\n"));
        assert!(p.ends_with("PREVIOUS RESPONSE:\n{}\n"));
    }

    #[test]
    fn the_syntax_prompt_asks_for_a_syntax_fix_only() {
        let p = repair_json_prompt("{oops", &ParseFailure::Syntax("eof".into()));
        assert!(p.contains("Fix the JSON syntax only"));
        assert!(!p.contains("wrong shape"));
        assert!(p.contains("FAILURE:\ninvalid JSON: eof\n"));
    }
}
