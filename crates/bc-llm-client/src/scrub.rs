//! Error-body hygiene shared by both dialect crates.
//!
//! A gateway or reverse proxy sitting between this tool and the model
//! provider routinely reflects request material back in a 4xx/5xx body —
//! an `Authorization` header, an API key it failed to forward, a cookie,
//! or (worse, for a SAST tool) a slice of the source snippet that was in
//! the prompt. That body ends up inside an `LlmError`, then inside a
//! `StageError` message, then in `report.md`/`errors.json`. Ported from
//! `backends/sdk.py:320-346`, which wraps the provider body in `redact()`
//! for exactly this reason ("a gateway/proxy can reflect Authorization
//! headers, keys, or cookies in an error body") before it lands in the
//! raised exception's text.
//!
//! The length cap is net-new: Python's `redact(body)` is unbounded, and a
//! gateway that echoes the whole request back turns one failed call into
//! a multi-megabyte error string carried through checkpoints and reports.
//! Truncating to [`MAX_ERROR_BODY_CHARS`] keeps the diagnostic (provider
//! error bodies put the useful part first) without the payload.

/// Scalar-count cap on a retained provider error body, applied after
/// redaction.
pub const MAX_ERROR_BODY_CHARS: usize = 2000;

/// Redact credential/PII material out of a provider error body, then cap
/// it. Truncation is by Unicode scalar (never mid-codepoint) and appends
/// an explicit marker so a truncated body can't be mistaken for a
/// complete one.
pub fn sanitize_error_body(body: &str) -> String {
    let redacted = bc_redact::redact(body);
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
        // Every char is 4 bytes, so a byte-based cap would land mid-scalar.
        let body = "🙂".repeat(MAX_ERROR_BODY_CHARS + 10);
        let scrubbed = sanitize_error_body(&body);
        assert!(scrubbed.starts_with('🙂'));
        assert!(scrubbed.ends_with("… [truncated]"));
    }
}
