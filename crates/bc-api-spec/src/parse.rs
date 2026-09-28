//! Parsing specification text into a `serde_json::Value`.
//!
//! JSON goes through `serde_json`. YAML goes through `bc_yaml::parse_strict`,
//! the only YAML reader this workspace has: `docs/supply-chain.md` rules
//! out a full YAML library. The strict parser refuses anything outside its
//! subset rather than approximating it, and that refusal is reported as
//! [`ParseFailure::Unverifiable`], never as malformed. A valid YAML file
//! that uses anchors or multi-line plain scalars is somebody's working
//! specification, and a parser limitation must never become a reason to
//! overwrite it.

use std::borrow::Cow;

use serde_json::Value;

use crate::format::Syntax;

/// Why text could not be read as a document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseFailure {
    /// The text is definitely not valid in its format.
    Malformed(String),
    /// The text may be valid but cannot be verified by the built-in parser.
    Unverifiable(String),
}

/// Parse `text` in `format`.
pub fn parse(text: &str, syntax: Syntax) -> Result<Value, ParseFailure> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    match syntax {
        Syntax::Json => serde_json::from_str(text).map_err(|error| {
            let message = error.to_string();
            // serde_json refuses nesting deeper than 128 levels. That is a
            // limit of this reader, not proof the document is invalid.
            if message.contains("recursion limit") {
                ParseFailure::Unverifiable(format!(
                    "nested deeper than the built-in JSON parser reads ({message})"
                ))
            } else {
                ParseFailure::Malformed(format!("invalid JSON: {message}"))
            }
        }),
        Syntax::Yaml => bc_yaml::parse_strict(&without_document_start(text)).map_err(|error| {
            ParseFailure::Unverifiable(format!(
                "could not be verified by the built-in YAML parser ({error})"
            ))
        }),
        other => Err(ParseFailure::Unverifiable(format!(
            "{other:?} is parsed by its standard, not as a JSON or YAML tree"
        ))),
    }
}

/// A single leading `---` marker is common and harmless; blank it (keeping
/// line numbers) so the strict parser, which reads one document and has no
/// markers, accepts it. Any other marker still reaches the parser and is
/// refused there.
fn without_document_start(text: &str) -> Cow<'_, str> {
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            offset += line.len();
            continue;
        }
        if trimmed == "---" && line.starts_with("---") {
            let mut owned = String::with_capacity(text.len());
            owned.push_str(&text[..offset]);
            owned.push_str(&text[offset + 3..]);
            return Cow::Owned(owned);
        }
        break;
    }
    Cow::Borrowed(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_errors_are_malformed_unless_only_too_deep() {
        assert_eq!(parse("{\"a\":1}", Syntax::Json).unwrap(), json!({"a": 1}));
        assert!(matches!(
            parse("{\"a\":", Syntax::Json),
            Err(ParseFailure::Malformed(_))
        ));
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        assert!(matches!(
            parse(&deep, Syntax::Json),
            Err(ParseFailure::Unverifiable(_))
        ));
        assert_eq!(parse("\u{feff}{}", Syntax::Json).unwrap(), json!({}));
    }

    #[test]
    fn yaml_outside_the_subset_is_unverifiable() {
        assert_eq!(parse("a: 1\n", Syntax::Yaml).unwrap(), json!({"a": 1}));
        let error = parse("a: &x 1\n", Syntax::Yaml).unwrap_err();
        assert!(
            matches!(&error, ParseFailure::Unverifiable(m) if m.contains("could not be verified"))
        );
    }

    #[test]
    fn text_syntaxes_are_not_trees() {
        assert!(matches!(
            parse("type Query { a: Int }", Syntax::Graphql),
            Err(ParseFailure::Unverifiable(m)) if m.contains("parsed by its standard")
        ));
    }

    #[test]
    fn one_leading_document_marker_is_accepted() {
        assert_eq!(
            parse("# spec\n\n---\nopenapi: 3.1.0\n", Syntax::Yaml).unwrap(),
            json!({"openapi": "3.1.0"})
        );
        assert!(parse("---\na: 1\n---\nb: 2\n", Syntax::Yaml).is_err());
        assert!(parse(" ---\na: 1\n", Syntax::Yaml).is_err());
        assert_eq!(without_document_start("a: 1\n"), "a: 1\n");
        assert_eq!(without_document_start("\n"), "\n");
    }
}
