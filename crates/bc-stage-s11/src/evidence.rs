//! Bounds on the evidence a persona reports. Every `file`/`snippet`
//! string here is model output, and it flows into `files_needing_fixes`,
//! the justification, `remediation.json`, the Markdown report and SARIF.
//! A persona that pastes a whole file into `snippet`, or reports a
//! thousand evidence entries, used to carry all of it through to every
//! one of those.
//!
//! Each value is redacted BEFORE it is truncated: truncating first could
//! cut a secret in half, leaving a prefix too short for a pattern to
//! recognize but long enough to matter.

use bc_validation_scoring::{Evidence, TRUNCATION_MARKER};
use serde_json::Value;

/// Most evidence entries kept per gate.
pub(crate) const MAX_EVIDENCE_PER_GATE: usize = 20;
/// Longest `file` kept, in characters.
pub(crate) const MAX_EVIDENCE_FILE_CHARS: usize = 512;
/// Longest `snippet` kept, in characters.
pub(crate) const MAX_EVIDENCE_SNIPPET_CHARS: usize = 2048;

/// `raw` redacted, then cut to `max` characters plus
/// [`TRUNCATION_MARKER`], warning (with the field name and the limit,
/// never the value) when it had to be cut.
fn bounded(field: &str, raw: &str, max: usize) -> String {
    let redacted = bc_redact::redact(raw);
    if redacted.chars().count() <= max {
        return redacted;
    }
    tracing::warn!("[s11] persona evidence {field} exceeds {max} characters; truncated");
    let kept: String = redacted.chars().take(max).collect();
    format!("{kept}{TRUNCATION_MARKER}")
}

/// One gate's `evidence` array, parsed and bounded. Non-object entries
/// are dropped, as before.
pub(crate) fn parse_evidence(gate: &Value) -> Vec<Evidence> {
    let Some(entries) = gate.get("evidence").and_then(Value::as_array) else {
        return Vec::new();
    };
    let objects: Vec<&serde_json::Map<String, Value>> =
        entries.iter().filter_map(Value::as_object).collect();
    let count = objects.len();
    if count > MAX_EVIDENCE_PER_GATE {
        tracing::warn!(
            "[s11] persona evidence list has {count} entries, over the \
             {MAX_EVIDENCE_PER_GATE} per-gate limit; the rest were dropped"
        );
    }
    objects
        .into_iter()
        .take(MAX_EVIDENCE_PER_GATE)
        .map(|e| {
            let text = |key: &str| e.get(key).and_then(Value::as_str).unwrap_or_default();
            Evidence {
                file: bounded("file", text("file"), MAX_EVIDENCE_FILE_CHARS),
                line: e.get("line").and_then(Value::as_i64),
                snippet: bounded("snippet", text("snippet"), MAX_EVIDENCE_SNIPPET_CHARS),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn well_formed_evidence_passes_through_unchanged() {
        let gate = json!({"evidence": [
            {"file": "src/app.py", "line": 12, "snippet": "query(sql, params)"},
            "not an object",
            {"line": "twelve"},
        ]});
        assert_eq!(
            parse_evidence(&gate),
            vec![
                Evidence {
                    file: "src/app.py".to_string(),
                    line: Some(12),
                    snippet: "query(sql, params)".to_string(),
                },
                Evidence::default(),
            ]
        );
        assert!(parse_evidence(&json!({})).is_empty());
    }

    #[test]
    fn the_entry_count_is_capped_per_gate() {
        let entries: Vec<Value> = (0..MAX_EVIDENCE_PER_GATE + 5)
            .map(|i| json!({"file": format!("f{i}.py")}))
            .collect();
        let parsed = parse_evidence(&json!({ "evidence": entries }));
        assert_eq!(parsed.len(), MAX_EVIDENCE_PER_GATE);
        assert_eq!(parsed[0].file, "f0.py");
    }

    #[test]
    fn long_fields_are_truncated_with_a_marker() {
        let gate = json!({"evidence": [{
            "file": "d/".repeat(MAX_EVIDENCE_FILE_CHARS),
            "snippet": "x".repeat(MAX_EVIDENCE_SNIPPET_CHARS + 1),
        }]});
        let parsed = parse_evidence(&gate);
        assert_eq!(
            parsed[0].file.chars().count(),
            MAX_EVIDENCE_FILE_CHARS + TRUNCATION_MARKER.len()
        );
        assert!(parsed[0].file.ends_with(TRUNCATION_MARKER));
        assert!(parsed[0].snippet.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn a_secret_is_redacted_before_truncation_so_no_fragment_survives() {
        // The key sits right at the cut: truncating first would keep
        // `AKIA` plus a few characters, too short for the AWS pattern.
        let padding = "y".repeat(MAX_EVIDENCE_SNIPPET_CHARS - 10);
        let gate = json!({"evidence": [{
            "snippet": format!("{padding} AKIAIOSFODNN7EXAMPLE tail"),
        }]});
        let snippet = &parse_evidence(&gate)[0].snippet;
        assert!(!snippet.contains("AKIAIOSF"), "{snippet}");
        assert!(snippet.contains("[REDACTED"), "{snippet}");
    }
}
