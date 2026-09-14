//! Minimal RFC4180-ish CSV parser — no external crate, since this
//! project's dependency-minimization policy prefers a narrowly-scoped,
//! well-tested primitive over a fresh supply-chain dependency for a
//! single, bounded parsing task (a batch manifest: quoted fields with
//! embedded commas, `""`-escaped quotes, `\r\n`/`\r`/`\n` line endings).
//! A deliberate duplicate of `bc-enrich`'s own copy (`csv_parse.rs`,
//! used for `--cmdb-csv`) — pulling in the whole `bc-enrich` crate for
//! one small, self-contained function would run against the same
//! dependency-minimization policy this parser itself exists to serve.

/// Split `text` into rows of fields. A blank line yields a one-element
/// row containing an empty string rather than Python `csv.reader`'s
/// genuinely empty `[]` — harmless here, since every caller already
/// treats "every field blank" the same as "no row at all".
pub(crate) fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut rows = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = normalized.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => row.push(std::mem::take(&mut field)),
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                _ => field.push(c),
            }
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_yields_no_rows() {
        assert_eq!(parse_csv(""), Vec::<Vec<String>>::new());
    }

    #[test]
    fn simple_comma_separated_fields() {
        assert_eq!(parse_csv("a,b,c\n"), vec![vec!["a", "b", "c"]]);
    }

    #[test]
    fn multiple_rows() {
        assert_eq!(
            parse_csv("a,b\nc,d\n"),
            vec![vec!["a", "b"], vec!["c", "d"]]
        );
    }

    #[test]
    fn a_row_with_no_trailing_newline_is_still_flushed() {
        assert_eq!(parse_csv("a,b"), vec![vec!["a", "b"]]);
    }

    #[test]
    fn quoted_field_with_an_embedded_comma() {
        assert_eq!(
            parse_csv("\"Acme, Inc.\",yes\n"),
            vec![vec!["Acme, Inc.", "yes"]]
        );
    }

    #[test]
    fn escaped_double_quote_inside_a_quoted_field() {
        assert_eq!(
            parse_csv("\"say \"\"hi\"\"\",b\n"),
            vec![vec!["say \"hi\"", "b"]]
        );
    }

    #[test]
    fn quoted_field_with_an_embedded_newline() {
        assert_eq!(
            parse_csv("\"line1\nline2\",b\n"),
            vec![vec!["line1\nline2", "b"]]
        );
    }

    #[test]
    fn crlf_and_bare_cr_line_endings_are_normalized() {
        assert_eq!(
            parse_csv("a,b\r\nc,d\r"),
            vec![vec!["a", "b"], vec!["c", "d"]]
        );
    }

    #[test]
    fn a_blank_line_yields_a_single_empty_field_row() {
        assert_eq!(
            parse_csv("a,b\n\nc,d\n"),
            vec![vec!["a", "b"], vec![""], vec!["c", "d"]]
        );
    }

    #[test]
    fn empty_fields_between_commas_are_preserved() {
        assert_eq!(parse_csv("a,,c\n"), vec![vec!["a", "", "c"]]);
    }
}
