use std::sync::LazyLock;

use regex::Regex;

static PAN_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:\d[\s\-]?){13,19}\b").unwrap());

static CARD_CTX_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(pan|card(?:[\s_-]*(?:no|num|number))?|cc(?:[\s_-]*(?:no|num|number))?|credit[\s_-]*card|acct|account(?:[\s_-]*(?:no|num|number))?)\b")
        .unwrap()
});

fn chars_before(text: &str, byte_pos: usize, n_chars: usize) -> usize {
    if n_chars == 0 {
        return byte_pos;
    }
    text[..byte_pos]
        .char_indices()
        .rev()
        .nth(n_chars - 1)
        .map(|(i, _)| i)
        .unwrap_or(0)
}

fn mask_pan(matched: &str, preceding_window: &str) -> String {
    let digits: String = matched.chars().filter(char::is_ascii_digit).collect();
    if digits.len() < 13 {
        return matched.to_string();
    }
    if !(appsec_redact::luhn(&digits) || CARD_CTX_RX.is_match(preceding_window)) {
        return matched.to_string();
    }
    let mut kept = 0;
    let mut out = String::with_capacity(matched.len());
    for c in matched.chars() {
        if c.is_ascii_digit() {
            out.push(if kept < 4 { c } else { 'X' });
            kept += 1;
        } else {
            out.push(c);
        }
    }
    out
}

pub fn redact_source(text: &str, rel: &str) -> String {
    let text = crate::packed_text::sanitize_packed_text(text, rel);
    let text = text.as_str();
    let mut out = String::with_capacity(text.len());
    let mut last_end = 0;
    for m in PAN_RX.find_iter(text) {
        out.push_str(&text[last_end..m.start()]);
        let window_start = chars_before(text, m.start(), 48);
        let window = &text[window_start..m.start()];
        out.push_str(&mask_pan(m.as_str(), window));
        last_end = m.end();
    }
    out.push_str(&text[last_end..]);
    appsec_redact::redact_counts(&out).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digit_run_under_13_is_never_touched() {
        let input = "port = 123456789012";
        assert_eq!(redact_source(input, "f"), input);
    }

    #[test]
    fn chars_before_with_zero_n_chars_returns_the_position_unchanged() {
        assert_eq!(chars_before("hello world", 5, 0), 5);
    }

    #[test]
    fn mask_pan_called_directly_with_fewer_than_13_digits_is_left_unchanged() {
        assert_eq!(mask_pan("1234567890", ""), "1234567890");
    }

    #[test]
    fn luhn_valid_card_is_masked_regardless_of_context() {
        let input = "x = 4111111111111111";
        let out = redact_source(input, "f");
        assert!(out.contains("4111XXXXXXXXXXXX"));
        assert!(!out.contains("4111111111111111"));
    }

    #[test]
    fn non_luhn_digit_run_with_card_context_keyword_is_masked() {
        let input = "cardNumber = 1234567890123456";
        assert!(!appsec_redact::luhn("1234567890123456"));
        let out = redact_source(input, "f");
        assert!(out.contains("1234XXXXXXXXXXXX"));
    }

    #[test]
    fn non_luhn_digit_run_without_context_is_left_unchanged() {
        let input = "timestamp = 1699999999999999";
        assert!(!appsec_redact::luhn("1699999999999999"));
        let out = redact_source(input, "f");
        assert_eq!(out, input);
    }

    #[test]
    fn separators_within_the_digit_run_are_preserved_verbatim() {
        let input = "4111-1111-1111-1111";
        let out = redact_source(input, "f");
        assert!(out.contains("4111-XXXX-XXXX-XXXX") || out.contains("4111-XXXXXXXXXXXXXXX"));
    }

    #[test]
    fn layer_two_still_redacts_things_layer_one_does_not_touch() {
        let input = "ssn = 123-45-6789";
        let out = redact_source(input, "f");
        assert_ne!(out, input);
    }

    #[test]
    fn no_newlines_are_added_or_removed() {
        let input = "line one\nline two 4111111111111111\nline three\n";
        let out = redact_source(input, "f");
        assert_eq!(out.matches('\n').count(), input.matches('\n').count());
    }

    #[test]
    fn context_window_is_char_boundary_safe_with_multibyte_text_preceding_a_match() {
        let input = "café☕️ résumé naïve 日本語のテキストがここにあります 4111111111111111";
        let out = redact_source(input, "f");
        assert!(out.contains("4111XXXXXXXXXXXX"));
    }

    #[test]
    fn context_keyword_immediately_preceding_a_short_multibyte_prefix_is_detected() {
        let input = "café pan: 1234567890123456";
        let out = redact_source(input, "f");
        assert!(out.contains("1234XXXXXXXXXXXX"));
    }

    #[test]
    fn binary_text_and_data_uris_are_elided_before_redaction() {
        assert_eq!(
            redact_source("\0\0\0 4111111111111111", "img.bin"),
            "[binary content elided: img.bin is not text]"
        );
        assert_eq!(
            redact_source("x = \"data:image/gif;base64,R0lGOD==\"", "t.js"),
            "x = \"[data-uri image/gif elided: 8 chars]\""
        );
    }

    #[test]
    fn empty_input_is_unchanged() {
        assert_eq!(redact_source("", "f"), "");
    }

    #[test]
    fn multiple_matches_in_one_string_are_each_handled_independently() {
        let input = "a=4111111111111111 b=1699999999999999";
        let out = redact_source(input, "f");
        assert!(out.contains("4111XXXXXXXXXXXX"));
        assert!(out.contains("1699999999999999"));
    }
}
