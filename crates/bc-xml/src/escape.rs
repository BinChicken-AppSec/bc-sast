//! Escaping for output and reference decoding for input.
//!
//! The two directions are kept side by side because they must agree
//! exactly: whatever [`escape_text`] or [`escape_attribute`] produces has
//! to decode back to the same string, including the carriage returns and
//! attribute whitespace that XML's line-end and attribute-value
//! normalization would otherwise rewrite.

use crate::chars::{is_name, is_xml_char};
use crate::error::ErrorKind;

/// Escape `text` for use as element content: `&`, `<` and `>` become
/// entity references, and a carriage return becomes `&#13;` so line-end
/// normalization does not turn it into a newline on the way back in.
///
/// Characters XML 1.0 does not allow at all pass through unchanged; the
/// writer rejects them before calling this.
pub fn escape_text(text: &str) -> String {
    escape(text, false)
}

/// Escape `value` for use inside a double-quoted attribute value. On top
/// of what [`escape_text`] does, `"` becomes `&quot;` and tab, newline and
/// carriage return become character references, because attribute-value
/// normalization would otherwise turn each of them into a space.
pub fn escape_attribute(value: &str) -> String {
    escape(value, true)
}

fn escape(input: &str, attribute: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            '"' if attribute => out.push_str("&quot;"),
            '\n' if attribute => out.push_str("&#10;"),
            '\t' if attribute => out.push_str("&#9;"),
            _ => out.push(c),
        }
    }
    out
}

/// Decode references in `src[start..end]` and apply line-end
/// normalization; for an attribute value, also apply attribute-value
/// normalization (each literal whitespace character becomes a space; with
/// no DTD every attribute is CDATA-typed, so nothing is collapsed). An
/// error carries the byte offset in `src` of the offending `&`.
pub(crate) fn decode(
    src: &str,
    start: usize,
    end: usize,
    attribute: bool,
) -> Result<String, (usize, ErrorKind)> {
    let raw = &src[start..end];
    let mut out = String::with_capacity(raw.len());
    let mut index = 0;
    while let Some(c) = raw[index..].chars().next() {
        index += c.len_utf8();
        match c {
            '&' => {
                let at = start + index - 1;
                let body_len = raw[index..]
                    .find(';')
                    .ok_or((at, ErrorKind::InvalidReference))?;
                let body = &raw[index..index + body_len];
                out.push(resolve_reference(body).map_err(|kind| (at, kind))?);
                index += body_len + 1;
            }
            '\r' => {
                if raw[index..].starts_with('\n') {
                    index += 1;
                }
                out.push(if attribute { ' ' } else { '\n' });
            }
            '\n' | '\t' if attribute => out.push(' '),
            _ => out.push(c),
        }
    }
    Ok(out)
}

/// Resolve the text between `&` and `;`. Only the five predefined entities
/// exist: there is no DTD to declare more, so any other name is an
/// undefined entity rather than something to look up or fetch.
fn resolve_reference(body: &str) -> Result<char, ErrorKind> {
    if let Some(number) = body.strip_prefix('#') {
        let (digits, radix) = match number.strip_prefix('x') {
            Some(hex) => (hex, 16),
            None => (number, 10),
        };
        // `from_str_radix` alone would accept a leading `+`, and it reports
        // overflow as an error, so no length cap is needed on top.
        let well_formed = !digits.is_empty() && digits.chars().all(|c| c.is_digit(radix));
        return well_formed
            .then(|| u32::from_str_radix(digits, radix).ok())
            .flatten()
            .and_then(char::from_u32)
            .filter(|&c| is_xml_char(c))
            .ok_or_else(|| ErrorKind::InvalidCharReference(body.to_string()));
    }
    match body {
        "amp" => Ok('&'),
        "lt" => Ok('<'),
        "gt" => Ok('>'),
        "apos" => Ok('\''),
        "quot" => Ok('"'),
        _ if is_name(body) => Err(ErrorKind::UndefinedEntity(body.to_string())),
        _ => Err(ErrorKind::InvalidReference),
    }
}

/// Line-end normalization for text that has no references to decode
/// (comments, CDATA sections, processing instructions, and whitespace
/// outside the root element).
pub(crate) fn normalize_newlines(raw: &str) -> String {
    raw.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(raw: &str, attribute: bool) -> Result<String, (usize, ErrorKind)> {
        decode(raw, 0, raw.len(), attribute)
    }

    #[test]
    fn escaping_covers_markup_quotes_and_normalized_whitespace() {
        assert_eq!(escape_text("a<b>&c\r\n\t\""), "a&lt;b&gt;&amp;c&#13;\n\t\"");
        assert_eq!(
            escape_attribute("a<b>&c\r\n\t\"'"),
            "a&lt;b&gt;&amp;c&#13;&#10;&#9;&quot;'"
        );
    }

    #[test]
    fn predefined_entities_and_character_references_decode() {
        assert_eq!(
            decode_all("&lt;&gt;&amp;&apos;&quot;&#65;&#x42;&#x1F600;", false).unwrap(),
            "<>&'\"AB\u{1F600}"
        );
        assert_eq!(decode_all("&#0000000065;", false).unwrap(), "A");
    }

    #[test]
    fn line_ends_normalize_in_text_and_whitespace_normalizes_in_attributes() {
        assert_eq!(
            decode_all("a\r\nb\rc\nd\te", false).unwrap(),
            "a\nb\nc\nd\te"
        );
        assert_eq!(decode_all("a\r\nb\rc\nd\te", true).unwrap(), "a b c d e");
        assert_eq!(decode_all("&#13;&#10;&#9;", true).unwrap(), "\r\n\t");
        assert_eq!(normalize_newlines("a\r\nb\rc"), "a\nb\nc");
    }

    #[test]
    fn bad_references_report_the_offset_of_their_ampersand() {
        assert_eq!(
            decode("xx&nbsp;", 1, 8, false),
            Err((2, ErrorKind::UndefinedEntity("nbsp".into())))
        );
        assert_eq!(
            decode_all("a & b", false),
            Err((2, ErrorKind::InvalidReference))
        );
        assert_eq!(
            decode_all("a &1; b", false),
            Err((2, ErrorKind::InvalidReference))
        );
        assert_eq!(
            decode_all("&;", false),
            Err((0, ErrorKind::InvalidReference))
        );
        for body in [
            "#0",
            "#x0",
            "#",
            "#x",
            "#+65",
            "#X41",
            "#xFFFE",
            "#xD800",
            "#99999999999",
            "#1a",
        ] {
            let raw = format!("&{body};");
            assert_eq!(
                decode_all(&raw, false),
                Err((0, ErrorKind::InvalidCharReference(body.into()))),
                "{body}"
            );
        }
    }
}
