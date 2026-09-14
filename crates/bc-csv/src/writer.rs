//! Minimal RFC4180-ish CSV writer — no external crate, matching this
//! project's dependency-minimization policy (the same rationale
//! `bc-enrich`'s CSV *parser* already uses for its CMDB-input reader): a
//! narrowly-scoped, well-tested primitive is preferable to a fresh
//! supply-chain dependency for a single, bounded writing task.

/// Quotes `field` (doubling any embedded `"`) only when it contains a
/// comma, quote, or line break — otherwise returns it unescaped, matching
/// how spreadsheet tools round-trip a plain field without adding quotes
/// that would otherwise show up literally when the file is opened.
fn escape_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// One CSV row: every field escaped and comma-joined, terminated with a
/// CRLF line ending per RFC4180 (Excel-friendly; most modern tools accept
/// a bare LF too, but CRLF is the spec's own recommendation).
pub(crate) fn write_row(fields: &[String]) -> String {
    let joined: String = fields
        .iter()
        .map(|f| escape_field(f))
        .collect::<Vec<_>>()
        .join(",");
    format!("{joined}\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_field_is_unescaped() {
        assert_eq!(escape_field("hello"), "hello");
    }

    #[test]
    fn empty_field_is_unescaped() {
        assert_eq!(escape_field(""), "");
    }

    #[test]
    fn field_with_a_comma_is_quoted() {
        assert_eq!(escape_field("a,b"), "\"a,b\"");
    }

    #[test]
    fn field_with_an_embedded_quote_is_quoted_and_doubled() {
        assert_eq!(escape_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn field_with_a_newline_is_quoted() {
        assert_eq!(escape_field("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn field_with_a_carriage_return_is_quoted() {
        assert_eq!(escape_field("line1\rline2"), "\"line1\rline2\"");
    }

    #[test]
    fn write_row_joins_fields_with_commas_and_a_crlf_terminator() {
        let row = write_row(&["a".to_string(), "b".to_string(), "c".to_string()]);
        assert_eq!(row, "a,b,c\r\n");
    }

    #[test]
    fn write_row_escapes_fields_that_need_it() {
        let row = write_row(&["a,b".to_string(), "plain".to_string()]);
        assert_eq!(row, "\"a,b\",plain\r\n");
    }

    #[test]
    fn write_row_of_empty_slice_is_just_the_terminator() {
        assert_eq!(write_row(&[]), "\r\n");
    }
}
