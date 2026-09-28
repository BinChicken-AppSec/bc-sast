//! A purpose-built YAML parser for this project's own config files —
//! **not** a full YAML 1.1/1.2 implementation.
//!
//! The entire actively-maintained `serde_yaml`-compatible ecosystem is
//! stalled as of this writing (the canonical crate is deprecated by its
//! author with no successor; the two community forks we found have not
//! released in over a year either — see `docs/supply-chain.md`). Rather
//! than depend on an unmaintained third-party YAML engine for a security
//! tool's own config loading, this crate implements exactly the YAML
//! subset this project's config/profile/input files actually use,
//! verified against the real fixtures in the Python reference
//! implementation:
//!
//! - Comments (`#`, only when preceded by whitespace or at line start —
//!   never inside a quoted scalar).
//! - Block mappings and sequences (indentation-driven), including a
//!   mapping's first key starting on the same line as a sequence dash
//!   (`- name: foo` followed by sibling keys aligned under `name`).
//! - Flow-style mappings/sequences (`{a: 1, b: [2, 3]}`).
//! - Plain, single-quoted, and double-quoted scalars, with PyYAML-
//!   compatible implicit typing (bool/null/int/float — see
//!   `scalar::resolve_plain`'s doc comment for exactly what's covered).
//! - Literal (`|`) and folded (`>`) block scalars with chomping
//!   indicators (`-`/`+`/clip).
//!
//! Explicitly **out of scope** (none of this project's own YAML uses
//! them): anchors/aliases (`&`/`*`), custom tags (`!!foo`), multi-document
//! streams (`---`/`...`), complex mapping keys (`? key`), hex/octal/
//! sexagesimal integer literals, and multi-line plain-scalar folding.
//! Any of these appearing in a config file will either produce a parse
//! error or (for the numeric literal forms) silently resolve as a string
//! rather than the intended number — both documented in the relevant
//! function's doc comment rather than silently mis-parsing something a
//! reader would expect to work.
//!
//! Parses directly into `serde_json::Value` (object keys always
//! alphabetically ordered, since that's how `serde_json`'s default
//! `Map` — a `BTreeMap` — behaves without the `preserve_order` feature;
//! this doesn't affect deep-merge/lookup correctness, only iteration/
//! debug-print order) so every downstream consumer in this workspace
//! works with the exact same value type already used everywhere else.

mod block;
mod error;
mod flow;
mod scalar;

pub use error::YamlError;

/// Parse a YAML document into a `serde_json::Value`. An empty (or
/// all-comments/all-blank) document parses to `Value::Null`, matching
/// PyYAML's `safe_load` behavior for an empty file.
pub fn parse(input: &str) -> Result<serde_json::Value, YamlError> {
    block::Parser::new(input).parse_document()
}

/// Parse a YAML document, refusing anything the subset above cannot
/// represent exactly instead of approximating it.
///
/// [`parse`] is tuned for this project's own config files and stays
/// lenient: text after the first line it cannot place is dropped, an
/// anchor or tag becomes part of a plain string, and a repeated key keeps
/// its last value. That is tolerable for files this project writes and
/// dangerous for a file someone else wrote, where a silently different
/// value could be mistaken for the author's intent. `parse_strict`
/// returns an error for each of those cases (unplaced trailing content,
/// tab indentation, document markers, anchors, aliases, tags, directives,
/// reserved indicators, block-scalar indentation indicators, complex and
/// merge keys, unterminated or trailing-text quoted scalars, `: ` inside a
/// plain scalar, text after a flow collection, and duplicate keys), so a
/// successful parse means every line was read under rules this crate
/// implements. It does not make the parser more capable: an error means
/// "not verifiable here", not "invalid YAML".
pub fn parse_strict(input: &str) -> Result<serde_json::Value, YamlError> {
    block::Parser::new_strict(input).parse_document()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_document_is_null() {
        assert_eq!(parse("").unwrap(), serde_json::Value::Null);
        assert_eq!(
            parse("   \n\n# just a comment\n").unwrap(),
            serde_json::Value::Null
        );
    }

    #[test]
    fn simple_mapping() {
        let v = parse("name: test\nenabled: true\ncount: 3\n").unwrap();
        assert_eq!(v, json!({"name": "test", "enabled": true, "count": 3}));
    }

    #[test]
    fn nested_mapping_and_sequence() {
        let yaml = "\
step1:
  allowed_tools:
    - Read
    - Glob
    - Grep
  max_budget_usd: 25.0
";
        let v = parse(yaml).unwrap();
        assert_eq!(
            v,
            json!({"step1": {"allowed_tools": ["Read", "Glob", "Grep"], "max_budget_usd": 25.0}})
        );
    }

    #[test]
    fn flow_mapping_value() {
        let v = parse("autoexclude: {id: claude-sonnet-4-6, via: cli}\n").unwrap();
        assert_eq!(
            v,
            json!({"autoexclude": {"id": "claude-sonnet-4-6", "via": "cli"}})
        );
    }

    #[test]
    fn sequence_of_flow_style_mappings_on_the_dash_line() {
        // Regression: `parse_sequence` used to check for a block-mapping
        // colon before checking for a leading `{`/`[`, so a flow mapping
        // right after the dash (`- { id: CWE-89 }`) got misread as a
        // block mapping split on the *first* colon it found — key `"{
        // id"`, value `"CWE-89 }"` — instead of being routed to the flow
        // parser. Config files that use this exact shorthand (a common,
        // real-world style for short single-line sequence entries) would
        // silently parse to garbage keys/values rather than erroring.
        let v = parse("allow:\n  - { id: CWE-89 }\n  - { id: CWE-78 }\n").unwrap();
        assert_eq!(v, json!({"allow": [{"id": "CWE-89"}, {"id": "CWE-78"}]}));
    }

    #[test]
    fn sequence_of_flow_style_sequences_on_the_dash_line() {
        let v = parse("pairs:\n  - [1, 2]\n  - [3, 4]\n").unwrap();
        assert_eq!(v, json!({"pairs": [[1, 2], [3, 4]]}));
    }

    #[test]
    fn sequence_of_mappings_with_key_on_dash_line() {
        let yaml = "\
controls:
  - name: api-gateway-auth
    kind: auth
    protects:
      - \"src/handlers/**\"
    notes: All handler entry points sit behind JWT validation.
  - name: seccomp-sandbox
    kind: sandbox
";
        let v = parse(yaml).unwrap();
        assert_eq!(
            v,
            json!({"controls": [
                {"name": "api-gateway-auth", "kind": "auth", "protects": ["src/handlers/**"],
                 "notes": "All handler entry points sit behind JWT validation."},
                {"name": "seccomp-sandbox", "kind": "sandbox"}
            ]})
        );
    }

    #[test]
    fn comments_are_ignored() {
        let yaml = "\
# a full-line comment
key: value  # an inline comment
";
        let v = parse(yaml).unwrap();
        assert_eq!(v, json!({"key": "value"}));
    }

    #[test]
    fn quoted_scalar_hash_is_not_a_comment() {
        let v = parse(r#"pattern: "not a #comment""#).unwrap();
        assert_eq!(v, json!({"pattern": "not a #comment"}));
    }

    #[test]
    fn env_placeholder_passes_through_as_plain_string() {
        // ${VAR:-default} is not a YAML construct at all in this scope —
        // it's just ordinary scalar text; env-expansion is bc-config's job.
        let v = parse("api_key: ${ANTHROPIC_SDK_API_KEY}\n").unwrap();
        assert_eq!(v, json!({"api_key": "${ANTHROPIC_SDK_API_KEY}"}));
    }

    #[test]
    fn folded_block_scalar() {
        let yaml = "\
instruction: >
  Use a parameterized
  query instead.
notes: after
";
        let v = parse(yaml).unwrap();
        assert_eq!(v["instruction"], "Use a parameterized query instead.\n");
        assert_eq!(v["notes"], "after");
    }

    #[test]
    fn literal_block_scalar_preserves_newlines() {
        let yaml = "\
example: |
  line one
  line two
after: x
";
        let v = parse(yaml).unwrap();
        assert_eq!(v["example"], "line one\nline two\n");
        assert_eq!(v["after"], "x");
    }

    #[test]
    fn literal_block_scalar_strip_chomp() {
        let yaml = "\
example: |-
  no trailing newline
after: x
";
        let v = parse(yaml).unwrap();
        assert_eq!(v["example"], "no trailing newline");
    }

    #[test]
    fn null_value_forms() {
        let v = parse("a:\nb: ~\nc: null\n").unwrap();
        assert_eq!(v, json!({"a": null, "b": null, "c": null}));
    }

    #[test]
    fn document_root_is_a_plain_scalar() {
        assert_eq!(parse("just text\n").unwrap(), json!("just text"));
    }

    #[test]
    fn document_root_is_a_sequence() {
        assert_eq!(parse("- a\n- b\n").unwrap(), json!(["a", "b"]));
    }

    #[test]
    fn key_with_nothing_after_it_at_all_is_null() {
        // No trailing newline, no following line at all — parse_node must
        // handle "input exhausted" while looking for this key's value,
        // not just "next line is dedented".
        assert_eq!(
            parse("trailing_key:").unwrap(),
            json!({"trailing_key": null})
        );
    }

    #[test]
    fn block_scalar_nested_under_a_key_rather_than_inline() {
        // The content must be indented DEEPER than the standalone ">"
        // line itself (column 2 here), not merely deeper than "key:".
        let yaml = "\
key:
  >
    folded content
after: x
";
        let v = parse(yaml).unwrap();
        assert_eq!(v["key"], "folded content\n");
        assert_eq!(v["after"], "x");
    }

    #[test]
    fn bare_dash_sequence_item_with_nested_mapping() {
        let yaml = "\
items:
  -
    nested: value
";
        let v = parse(yaml).unwrap();
        assert_eq!(v, json!({"items": [{"nested": "value"}]}));
    }

    #[test]
    fn sequence_item_that_is_itself_a_literal_block_scalar() {
        let yaml = "\
lines:
  - |
      line one
      line two
";
        let v = parse(yaml).unwrap();
        assert_eq!(v["lines"][0], "line one\nline two\n");
    }

    #[test]
    fn multi_line_flow_mapping_folds_the_continuation_line() {
        let yaml = "a: {b: 1,\n    c: 2}\nafter: x\n";
        let v = parse(yaml).unwrap();
        assert_eq!(v, json!({"a": {"b": 1, "c": 2}, "after": "x"}));
    }

    #[test]
    fn flow_collection_with_quoted_strings_at_block_level() {
        // Exercises flow_is_balanced's quote-skipping (both quote kinds),
        // which only matters via the block-level collect_flow_text path,
        // not flow.rs's own directly-tested parser.
        let v = parse("tags: ['a b', \"c, d\"]\n").unwrap();
        assert_eq!(v, json!({"tags": ["a b", "c, d"]}));
    }

    #[test]
    fn double_quoted_key() {
        let v = parse("\"quoted key\": value\n").unwrap();
        assert_eq!(v, json!({"quoted key": "value"}));
    }

    #[test]
    fn single_quoted_key() {
        let v = parse("'quoted key': value\n").unwrap();
        assert_eq!(v, json!({"quoted key": "value"}));
    }

    #[test]
    fn single_quoted_key_with_doubled_quote_escape() {
        let v = parse("'it''s a key': value\n").unwrap();
        assert_eq!(v, json!({"it's a key": "value"}));
    }

    #[test]
    fn double_quoted_key_with_escaped_quote() {
        let v = parse(r#""a \"b\" key": value"#).unwrap();
        assert_eq!(v, json!({"a \"b\" key": "value"}));
    }

    #[test]
    fn single_quoted_value_at_block_level() {
        let v = parse("key: 'a value'\n").unwrap();
        assert_eq!(v, json!({"key": "a value"}));
    }

    #[test]
    fn unterminated_single_quoted_value_at_block_level_falls_back_gracefully() {
        let result = parse("key: 'unterminated\n");
        assert!(result.is_ok());
    }

    #[test]
    fn quoted_key_with_colon_at_absolute_end_of_line() {
        // No space (or anything) after the colon at all -- exercises the
        // "next is None" arm of find_mapping_colon's quoted-key branch.
        assert_eq!(
            parse("\"lonely key\":").unwrap(),
            json!({"lonely key": null})
        );
    }

    #[test]
    fn double_quoted_value_with_escaped_quote_at_block_level() {
        let v = parse(r#"key: "with \"escaped\" quote""#).unwrap();
        assert_eq!(v, json!({"key": "with \"escaped\" quote"}));
    }

    #[test]
    fn multi_line_flow_mapping_with_escaped_quote_in_first_line() {
        // Exercises flow_is_balanced's escaped-double-quote skip, which
        // only matters when the balance check runs on a not-yet-closed
        // first line (i.e. via the multi-line collect_flow_text path).
        let yaml = "a: {b: \"esc\\\"aped\",\n    c: 2}\n";
        let v = parse(yaml).unwrap();
        assert_eq!(v, json!({"a": {"b": "esc\"aped", "c": 2}}));
    }

    #[test]
    fn document_root_bare_quoted_scalar_with_no_colon_is_a_string() {
        // Exercises find_mapping_colon's quoted-prefix branch reaching the
        // "no colon follows the closing quote" None case.
        assert_eq!(parse("\"just a value\"\n").unwrap(), json!("just a value"));
    }

    #[test]
    fn unterminated_quote_at_block_level_falls_back_gracefully() {
        // Must not panic; the exact fallback text isn't the point.
        let result = parse("key: \"unterminated\n");
        assert!(result.is_ok());
    }

    #[test]
    fn folded_block_scalar_keep_chomp_preserves_trailing_blank_lines() {
        let yaml = "\
key: >+
  keep me


after: x
";
        let v = parse(yaml).unwrap();
        assert!(v["key"].as_str().unwrap().ends_with("\n\n\n"));
        assert_eq!(v["after"], "x");
    }

    #[test]
    fn block_scalar_indicator_glued_to_other_text_is_not_an_indicator() {
        // "|extra" is not `|` followed only by an optional chomp mark and
        // a comment, so it must resolve as the plain string "|extra"
        // rather than being (mis)treated as a literal block scalar.
        let v = parse("weird: |extra\n").unwrap();
        assert_eq!(v["weird"], "|extra");
    }

    #[test]
    fn empty_block_scalar_with_no_content_lines_is_an_empty_string() {
        let yaml = "key: |\nafter: x\n";
        let v = parse(yaml).unwrap();
        assert_eq!(v["key"], "");
        assert_eq!(v["after"], "x");
    }

    #[test]
    fn crlf_line_endings_are_normalized() {
        let v = parse("a: 1\r\nb: 2\r\n").unwrap();
        assert_eq!(v, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn deny_paths_style_sequence_of_globs() {
        let yaml = "\
deny_paths:
  - \"**/auth/**\"
  - \"**/*crypto*\"
";
        let v = parse(yaml).unwrap();
        assert_eq!(v, json!({"deny_paths": ["**/auth/**", "**/*crypto*"]}));
    }

    #[test]
    fn malformed_flow_collection_is_an_error() {
        assert!(parse("a: {unclosed\n").is_err());
    }

    #[test]
    fn error_display_includes_line_number() {
        let err = parse("a: {unclosed\n").unwrap_err();
        assert!(err.to_string().contains("line"));
    }

    /// A pathological input a few KB in size (250 levels of `- ` nesting)
    /// must return a clean [`YamlError`], not overflow the stack — the
    /// exact DoS shape a crafted repo-controlled file (e.g.
    /// `inputs/validator_hints.yaml`) could otherwise use against an
    /// unattended CI scan.
    #[test]
    fn deeply_nested_block_sequence_is_a_clean_error_not_a_crash() {
        let mut yaml = String::new();
        for i in 0..250 {
            yaml.push_str(&"  ".repeat(i));
            yaml.push_str("-\n");
        }
        let err = parse(&yaml).unwrap_err();
        assert!(err.to_string().contains("maximum nesting depth"));
    }

    #[test]
    fn deeply_nested_block_mapping_is_a_clean_error_not_a_crash() {
        let mut yaml = String::new();
        for i in 0..250 {
            yaml.push_str(&"  ".repeat(i));
            yaml.push_str(&format!("k{i}:\n"));
        }
        let err = parse(&yaml).unwrap_err();
        assert!(err.to_string().contains("maximum nesting depth"));
    }

    #[test]
    fn deeply_nested_flow_sequence_is_a_clean_error_not_a_crash() {
        let yaml = format!("a: {}{}\n", "[".repeat(250), "]".repeat(250));
        let err = parse(&yaml).unwrap_err();
        assert!(err.to_string().contains("maximum nesting depth"));
    }

    #[test]
    fn block_mapping_nested_just_under_the_depth_cap_still_parses() {
        let mut yaml = String::new();
        for i in 0..50 {
            yaml.push_str(&"  ".repeat(i));
            yaml.push_str(&format!("k{i}:\n"));
        }
        yaml.push_str(&"  ".repeat(50));
        yaml.push_str("leaf: value\n");
        let v = parse(&yaml).unwrap();
        // Walk the 51 nested keys down to the leaf scalar.
        let mut cur = &v;
        for i in 0..50 {
            cur = &cur[format!("k{i}")];
        }
        assert_eq!(cur["leaf"], "value");
    }

    #[test]
    fn a_sequence_at_its_keys_own_indentation_is_the_keys_value() {
        let yaml = "tags:\n- users\n- admin\nname: api\n";
        let expected = json!({"tags": ["users", "admin"], "name": "api"});
        assert_eq!(parse(yaml).unwrap(), expected);
        assert_eq!(parse_strict(yaml).unwrap(), expected);
        // The same shape under a mapping that starts on a dash line.
        assert_eq!(
            parse_strict("- name: a\n  items:\n  - 1\n").unwrap(),
            json!([{"name": "a", "items": [1]}])
        );
    }

    #[test]
    fn strict_parsing_accepts_what_the_subset_represents_exactly() {
        let yaml = "\
# comment
openapi: 3.1.0
info:
  title: \"Pets # not a comment\"
  version: '1.0'
  description: |
    Line one.
    Line two.
paths:
  /pets/{id}:
    get:
      tags: [pets, 'read']
      parameters: []
      responses: {\"200\": {description: ok}} # trailing comment
empty:
";
        let value = parse_strict(yaml).unwrap();
        assert_eq!(value["info"]["title"], "Pets # not a comment");
        assert_eq!(value["info"]["description"], "Line one.\nLine two.\n");
        assert_eq!(
            value["paths"]["/pets/{id}"]["get"]["tags"],
            json!(["pets", "read"])
        );
        assert_eq!(value["empty"], serde_json::Value::Null);
        assert_eq!(parse_strict("").unwrap(), serde_json::Value::Null);
        assert_eq!(
            parse_strict("a: \"x\" # note\n").unwrap(),
            json!({"a": "x"})
        );
        assert_eq!(
            parse_strict("a: [1, 2] # note\n").unwrap(),
            json!({"a": [1, 2]})
        );
        assert_eq!(parse_strict("a: -5\nb: - \n").unwrap_err().line, 2);
    }

    #[test]
    fn strict_parsing_refuses_what_the_lenient_parser_would_approximate() {
        for (yaml, fragment) in [
            ("a: 1\n  b: 2\nc: 3\n", "cannot place"),
            ("a: one\n  two\nb: 3\n", "cannot place"),
            ("- a\nb: 1\n", "cannot place"),
            ("a:\n\tb: 1\n", "tab character"),
            ("a: 1\n---\nb: 2\n", "document markers"),
            ("--- x\n", "document markers"),
            ("a: 1\n...\n", "document markers"),
            ("a: &x 1\n", "outside the supported subset"),
            ("a: *x\n", "outside the supported subset"),
            ("a: !!str 1\n", "outside the supported subset"),
            ("a: |2\n   x\n", "outside the supported subset"),
            ("? a\n", "outside the supported subset"),
            ("<<: {a: 1}\n", "mapping key"),
            ("&a key: 1\n", "mapping key"),
            ("{a: 1}\nb: 2\n", "mapping key"),
            ("a: b: c\n", "unquoted ': '"),
            ("a: b:\n", "unquoted ': '"),
            ("a: \"open\n  close\"\n", "unterminated"),
            ("a: \"x\" y\n", "text after a quoted scalar"),
            ("a: [1, 2] x\n", "text after a flow collection"),
            ("a: [&x 1]\n", "outside the supported subset"),
            ("a: {&k 1: 2}\n", "outside the supported subset"),
            ("a: {k: 1, k: 2}\n", "duplicate flow-mapping key"),
            ("a: 1\na: 2\n", "duplicate mapping key"),
            ("- ?\n", "outside the supported subset"),
        ] {
            let error = parse_strict(yaml).unwrap_err();
            assert!(
                error.to_string().contains(fragment),
                "{yaml:?} gave {error}, expected {fragment:?}"
            );
        }
        // Lenient parsing of the same inputs is unchanged.
        assert_eq!(parse("a: &x 1\n").unwrap(), json!({"a": "&x 1"}));
        assert_eq!(parse("a: {k: 1, k: 2}\n").unwrap(), json!({"a": {"k": 2}}));
        assert_eq!(parse("a: 1\na: 2\n").unwrap(), json!({"a": 2}));
        assert_eq!(parse("a: [1] x\n").unwrap(), json!({"a": [1]}));
    }

    #[test]
    fn strict_duplicate_key_errors_name_the_repeated_line() {
        let error = parse_strict("a: 1\nb:\n  c: 1\na:\n  d: 2\n").unwrap_err();
        assert_eq!(error.line, 4);
    }

    #[test]
    fn a_tab_inside_content_is_not_indentation() {
        assert_eq!(parse_strict("a: \"x\ty\"\n").unwrap(), json!({"a": "x\ty"}));
        assert_eq!(
            parse_strict("a: 1\n\t\nb: 2\n").unwrap(),
            json!({"a": 1, "b": 2})
        );
    }
}
