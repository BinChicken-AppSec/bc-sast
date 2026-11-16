pub const MAX_ERROR_BODY_CHARS: usize = 2000;

pub fn sanitize_error_body(body: &str) -> String {
    let redacted = appsec_redact::redact(body);
    if redacted.chars().count() <= MAX_ERROR_BODY_CHARS {
        return redacted;
    }
    let mut out: String = redacted.chars().take(MAX_ERROR_BODY_CHARS).collect();
    out.push_str("… [truncated]");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ordinary_short_body_passes_through_unchanged() {
        assert_eq!(sanitize_error_body("model not found"), "model not found");
    }

    #[test]
    fn an_empty_body_stays_empty() {
        assert_eq!(sanitize_error_body(""), "");
    }

    #[test]
    fn a_reflected_bearer_token_is_redacted() {
        let scrubbed =
            sanitize_error_body("upstream rejected: Authorization: Bearer sk-abcd1234efgh5678");
        assert!(
            !scrubbed.contains("sk-abcd1234efgh5678"),
            "token survived redaction: {scrubbed}"
        );
    }

    #[test]
    fn an_oversized_body_is_capped_and_marked() {
        let body = "x".repeat(MAX_ERROR_BODY_CHARS + 500);
        let scrubbed = sanitize_error_body(&body);
        assert!(scrubbed.ends_with("… [truncated]"));
        assert_eq!(
            scrubbed.chars().count(),
            MAX_ERROR_BODY_CHARS + "… [truncated]".chars().count()
        );
    }

    #[test]
    fn a_body_exactly_at_the_cap_is_not_truncated() {
        let body = "y".repeat(MAX_ERROR_BODY_CHARS);
        let scrubbed = sanitize_error_body(&body);
        assert_eq!(scrubbed, body);
    }

    #[test]
    fn truncation_never_splits_a_multi_byte_character() {
        let body = "🙂".repeat(MAX_ERROR_BODY_CHARS + 10);
        let scrubbed = sanitize_error_body(&body);
        assert!(scrubbed.starts_with('🙂'));
        assert!(scrubbed.ends_with("… [truncated]"));
    }
}
