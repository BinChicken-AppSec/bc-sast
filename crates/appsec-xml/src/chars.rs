//! XML 1.0 (Fifth Edition) character classes, productions 2, 3, 4, 4a and
//! 5, plus the NCName production from Namespaces in XML 1.0.

/// `Char`: the characters an XML 1.0 document may contain at all.
pub(crate) fn is_xml_char(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
    )
}

/// `S`: the four whitespace characters. Nothing else counts, in particular
/// not the Unicode spaces `char::is_whitespace` accepts.
pub(crate) fn is_whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

/// `NameStartChar`.
pub(crate) fn is_name_start_char(c: char) -> bool {
    matches!(
        c,
        ':' | 'A'..='Z'
            | '_'
            | 'a'..='z'
            | '\u{C0}'..='\u{D6}'
            | '\u{D8}'..='\u{F6}'
            | '\u{F8}'..='\u{2FF}'
            | '\u{370}'..='\u{37D}'
            | '\u{37F}'..='\u{1FFF}'
            | '\u{200C}'..='\u{200D}'
            | '\u{2070}'..='\u{218F}'
            | '\u{2C00}'..='\u{2FEF}'
            | '\u{3001}'..='\u{D7FF}'
            | '\u{F900}'..='\u{FDCF}'
            | '\u{FDF0}'..='\u{FFFD}'
            | '\u{10000}'..='\u{EFFFF}'
    )
}

/// `NameChar`.
pub(crate) fn is_name_char(c: char) -> bool {
    is_name_start_char(c)
        || matches!(
            c,
            '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}'
        )
}

/// Whether `s` is an XML 1.0 `Name` (colons allowed).
pub(crate) fn is_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(is_name_start_char) && chars.all(is_name_char)
}

/// Whether `s` is an `NCName`: a name with no colon, the form every
/// prefix, local name, processing-instruction target and most WSDL/XSD
/// `name` attribute values must take.
pub fn is_ncname(s: &str) -> bool {
    !s.contains(':') && is_name(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_chars_exclude_controls_and_non_characters() {
        for c in [
            '\t',
            '\n',
            '\r',
            ' ',
            'a',
            '\u{D7FF}',
            '\u{E000}',
            '\u{FFFD}',
            '\u{10000}',
        ] {
            assert!(is_xml_char(c), "{c:?}");
        }
        for c in [
            '\0', '\u{1}', '\u{B}', '\u{C}', '\u{1F}', '\u{FFFE}', '\u{FFFF}',
        ] {
            assert!(!is_xml_char(c), "{c:?}");
        }
    }

    #[test]
    fn whitespace_is_only_the_four_xml_spaces() {
        for c in [' ', '\t', '\n', '\r'] {
            assert!(is_whitespace(c));
        }
        for c in ['\u{A0}', '\u{2003}', 'x', '\u{C}'] {
            assert!(!is_whitespace(c));
        }
    }

    #[test]
    fn names_follow_the_start_and_continuation_classes() {
        for name in [
            "a",
            "_x",
            ":y",
            "a-b.c1",
            "\u{C0}\u{B7}",
            "\u{10000}x",
            "a\u{300}",
        ] {
            assert!(is_name(name), "{name}");
        }
        for name in ["", "1a", "-a", ".a", "a b", "a\u{D7}", "\u{B7}"] {
            assert!(!is_name(name), "{name}");
        }
    }

    #[test]
    fn ncnames_are_names_without_colons() {
        assert!(is_ncname("definitions"));
        assert!(is_ncname("tns-1.x"));
        assert!(!is_ncname("wsdl:definitions"));
        assert!(!is_ncname(":a"));
        assert!(!is_ncname(""));
        assert!(!is_ncname("9lives"));
    }
}
