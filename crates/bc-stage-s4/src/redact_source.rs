//! Two-layer source redaction applied before a chunk's code enters the
//! prompt, ported from `s4_deepdive.py`'s `_PAN_RX`/`_CARD_CTX`/
//! `_mask_pan`/`_redact_source`.
//!
//! Layer 1 (this module's own logic) keeps the BIN prefix + length of any
//! card-shaped digit run so a researcher can still flag "test PAN in
//! source" findings, masking only when the run is Luhn-valid (any prefix)
//! or a card-context keyword sits just before it — this is what keeps an
//! ordinary 13-19 digit literal (a timestamp, a Snowflake/DB id) from
//! being needlessly mangled. Layer 2 is the shared full-blot redactor
//! (`bc_redact::redact_counts` — SSNs, credentials, keys, JWTs, and any
//! Luhn/IIN-valid card layer 1 didn't already catch). `redact_counts` is
//! used (not `redact`) because S4 runs chunks concurrently and must not
//! race on a shared mutable count side-channel — this crate's own
//! function is pure and stateless so the same property holds throughout.
//!
//! **Deliberately not ported**: the Python original's per-file
//! `print(..., file=sys.stderr)` summary of how many PAN/other tokens were
//! masked — a pure diagnostic with no other side effect, dropped per this
//! project's established convention.

use std::sync::LazyLock;

use regex::Regex;

static PAN_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(?:\d[\s\-]?){13,19}\b").unwrap());

/// A card-context keyword sitting just before the digit run (e.g. `pan =`,
/// `cardNumber:`, `acct_no`, `credit_card`) — matched in a short window
/// preceding the match so a labelled-but-non-Luhn test PAN is still
/// caught.
static CARD_CTX_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(pan|card(?:[\s_-]*(?:no|num|number))?|cc(?:[\s_-]*(?:no|num|number))?|credit[\s_-]*card|acct|account(?:[\s_-]*(?:no|num|number))?)\b")
        .unwrap()
});

/// The byte position `n_chars` Unicode scalar values before `byte_pos` in
/// `text` (clamped to the start of the string) — a char-boundary-safe
/// equivalent of Python's character-index slicing (`m.start() - 48`),
/// since `regex::Match` boundaries in Rust are byte offsets and an
/// arbitrary `byte_pos - 48` could otherwise land inside a multi-byte
/// UTF-8 character.
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
    if !(bc_redact::luhn(&digits) || CARD_CTX_RX.is_match(preceding_window)) {
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

/// Mask sensitive data before `text` (the contents of `rel`, only used by
/// the Python original for its dropped stderr log) is packed into the
/// prompt. Preserves line structure (no newlines added/removed) so
/// finding line numbers stay accurate.
pub fn redact_source(text: &str) -> String {
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
    bc_redact::redact_counts(&out).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digit_run_under_13_is_never_touched() {
        let input = "port = 123456789012"; // 12 digits
        assert_eq!(redact_source(input), input);
    }

    #[test]
    fn chars_before_with_zero_n_chars_returns_the_position_unchanged() {
        assert_eq!(chars_before("hello world", 5, 0), 5);
    }

    #[test]
    fn mask_pan_called_directly_with_fewer_than_13_digits_is_left_unchanged() {
        // PAN_RX itself guarantees >=13 digits in any match it hands to
        // `mask_pan` (`(?:\d[\s\-]?){13,19}` consumes exactly one digit per
        // repetition), so this branch is unreachable via `redact_source`'s
        // own call path — whitebox-tested directly as a defensive guard
        // against a future change to PAN_RX's lower bound.
        assert_eq!(mask_pan("1234567890", ""), "1234567890");
    }

    #[test]
    fn luhn_valid_card_is_masked_regardless_of_context() {
        let input = "x = 4111111111111111"; // Visa test PAN, Luhn-valid
        let out = redact_source(input);
        assert!(out.contains("4111XXXXXXXXXXXX"));
        assert!(!out.contains("4111111111111111"));
    }

    #[test]
    fn non_luhn_digit_run_with_card_context_keyword_is_masked() {
        let input = "cardNumber = 1234567890123456"; // 16 digits, not Luhn-valid
        assert!(!bc_redact::luhn("1234567890123456"));
        let out = redact_source(input);
        assert!(out.contains("1234XXXXXXXXXXXX"));
    }

    #[test]
    fn non_luhn_digit_run_without_context_is_left_unchanged() {
        let input = "timestamp = 1699999999999999"; // 16 digits, not Luhn-valid, no context keyword
        assert!(!bc_redact::luhn("1699999999999999"));
        let out = redact_source(input);
        assert_eq!(out, input);
    }

    #[test]
    fn separators_within_the_digit_run_are_preserved_verbatim() {
        let input = "4111-1111-1111-1111"; // Luhn-valid with hyphen separators
        let out = redact_source(input);
        assert!(out.contains("4111-XXXX-XXXX-XXXX") || out.contains("4111-XXXXXXXXXXXXXXX"));
    }

    #[test]
    fn layer_two_still_redacts_things_layer_one_does_not_touch() {
        // An SSN is not a 13-19 digit run at all, so layer 1 leaves it
        // alone; layer 2 (the shared redactor) must still catch it.
        let input = "ssn = 123-45-6789";
        let out = redact_source(input);
        assert_ne!(out, input);
    }

    #[test]
    fn no_newlines_are_added_or_removed() {
        let input = "line one\nline two 4111111111111111\nline three\n";
        let out = redact_source(input);
        assert_eq!(out.matches('\n').count(), input.matches('\n').count());
    }

    #[test]
    fn context_window_is_char_boundary_safe_with_multibyte_text_preceding_a_match() {
        // A run of multi-byte characters immediately before a Luhn-valid
        // digit run must not panic when computing the 48-char lookback
        // window (this is exactly the case a byte-offset slice would break
        // on for arbitrary text).
        let input = "café☕️ résumé naïve 日本語のテキストがここにあります 4111111111111111";
        let out = redact_source(input);
        assert!(out.contains("4111XXXXXXXXXXXX"));
    }

    #[test]
    fn context_keyword_immediately_preceding_a_short_multibyte_prefix_is_detected() {
        let input = "café pan: 1234567890123456";
        let out = redact_source(input);
        assert!(out.contains("1234XXXXXXXXXXXX"));
    }

    #[test]
    fn empty_input_is_unchanged() {
        assert_eq!(redact_source(""), "");
    }

    #[test]
    fn multiple_matches_in_one_string_are_each_handled_independently() {
        let input = "a=4111111111111111 b=1699999999999999";
        let out = redact_source(input);
        assert!(out.contains("4111XXXXXXXXXXXX"));
        assert!(out.contains("1699999999999999")); // untouched, no context/luhn
    }
}
