//! The per-finding `RemediationVerdict` contract, ported from
//! `remediation_agent/models/{verdict,gates,change}.py`. Its JSON schema
//! is embedded in the SYSTEM prompt (see [`crate::prompts`]) so every
//! backend is told the exact output shape; [`RemediationVerdict::coerce`]
//! validates the agent's response the same lenient way the scan
//! pipeline's own ThreatModel/TaskManifest/Finding parsing does.
//!
//! `Serialize`/`Deserialize` derives exist purely so `crate::lib`'s
//! `--resume` checkpoint payload can round-trip a whole
//! [`RemediationVerdict`] through JSON — an internal storage format, not
//! a public API contract, so the derives use serde's plain default
//! representation rather than matching `Verdict::as_str`'s
//! space-separated display form.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Fixed,
    PartiallyFixed,
    NotFixed,
    FalsePositive,
    NeedsReview,
    Denied,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Fixed => "Fixed",
            Verdict::PartiallyFixed => "Partially Fixed",
            Verdict::NotFixed => "Not Fixed",
            Verdict::FalsePositive => "False Positive",
            Verdict::NeedsReview => "Needs Review",
            Verdict::Denied => "Denied",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "Fixed" => Some(Verdict::Fixed),
            "Partially Fixed" => Some(Verdict::PartiallyFixed),
            "Not Fixed" => Some(Verdict::NotFixed),
            "False Positive" => Some(Verdict::FalsePositive),
            "Needs Review" => Some(Verdict::NeedsReview),
            "Denied" => Some(Verdict::Denied),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateStatus {
    Pass,
    Partial,
    Fail,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            GateStatus::Pass => "pass",
            GateStatus::Partial => "partial",
            GateStatus::Fail => "fail",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pass" => Some(GateStatus::Pass),
            "partial" => Some(GateStatus::Partial),
            "fail" => Some(GateStatus::Fail),
            _ => None,
        }
    }
}

/// The 3-gate evidence status block: Gate A (source), Gate B (sink), Gate
/// C (missing control). Each defaults to `Fail` (conservative) so a
/// verdict that omits a gate still validates rather than being discarded
/// wholesale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gates {
    pub source: GateStatus,
    pub sink: GateStatus,
    pub missing_control: GateStatus,
}

impl Default for Gates {
    fn default() -> Self {
        Gates {
            source: GateStatus::Fail,
            sink: GateStatus::Fail,
            missing_control: GateStatus::Fail,
        }
    }
}

impl Gates {
    /// True iff all three evidence gates read `Pass` — the post-gate's
    /// clean-path ACCEPT/REJECT audit label depends on this.
    pub fn all_pass(&self) -> bool {
        self.source == GateStatus::Pass
            && self.sink == GateStatus::Pass
            && self.missing_control == GateStatus::Pass
    }

    fn from_value(v: &Value) -> Self {
        let field = |key: &str| {
            v.get(key)
                .and_then(Value::as_str)
                .and_then(GateStatus::parse)
                .unwrap_or(GateStatus::Fail)
        };
        Gates {
            source: field("source"),
            sink: field("sink"),
            missing_control: field("missing_control"),
        }
    }
}

/// One edited-file record in a remediation verdict.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Change {
    pub file: String,
    pub summary: String,
}

impl Change {
    fn from_value(v: &Value) -> Self {
        Change {
            file: str_field(v, "file"),
            summary: str_field(v, "summary"),
        }
    }
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn str_list_field(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Structured result the remediation agent must return for one finding.
/// Only `verdict` is strictly required by [`RemediationVerdict::coerce`]
/// — every other field has a safe zero-value default so a near-complete
/// agent response (e.g. one that omits `summary`) is preserved rather
/// than thrown away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationVerdict {
    pub finding_index: i64,
    pub verdict: Verdict,
    pub gates: Gates,
    pub root_cause: String,
    pub changes: Vec<Change>,
    pub remaining_risks: Vec<String>,
    pub recommendations: Vec<String>,
    pub summary: String,
}

/// A short human name for a JSON value's shape, for the diagnostic when
/// an agent returns something other than the verdict object it was asked
/// for. Naming the shape is what makes the next such failure actionable:
/// the field case reported only "was not a JSON object", which does not
/// say whether the model wrapped it, stringified it, or gave up.
fn describe_shape(value: &Value) -> String {
    match value {
        Value::Array(items) => format!("a {}-element array", items.len()),
        Value::String(_) => "a string".to_string(),
        Value::Number(_) => "a number".to_string(),
        Value::Bool(_) => "a boolean".to_string(),
        Value::Null => "null".to_string(),
        Value::Object(_) => "an object".to_string(),
    }
}

impl RemediationVerdict {
    /// Builds a verdict from a (possibly imperfect) agent payload,
    /// preserving as much real content as possible. Never fails: an
    /// unparseable/non-object payload, or one with an unrecognized
    /// `verdict` field, still produces a `Needs Review` verdict rather
    /// than being dropped. `finding_index` is always pinned to the
    /// caller's known value regardless of what the model returned.
    pub fn coerce(data: &Value, finding_index: i64) -> Self {
        // A model asked for one object sometimes wraps it in a list, or
        // emits a single-element list of the object. `[{...}]` carries
        // exactly the verdict that was asked for, so unwrap it rather
        // than discarding a real fix over a bracket — a live run on
        // 2026-09-04 lost one finding's remediation to precisely this
        // ("agent response was not a JSON object"). Only a single
        // element is unwrapped: two or more is a genuinely different
        // answer to the question, and guessing which one to keep would
        // be inventing a verdict.
        let unwrapped = data
            .as_array()
            .filter(|items| items.len() == 1)
            .map(|items| &items[0])
            .unwrap_or(data);
        let data = unwrapped;
        let Some(obj) = data.as_object() else {
            return RemediationVerdict {
                finding_index,
                verdict: Verdict::NeedsReview,
                gates: Gates::default(),
                root_cause: String::new(),
                changes: Vec::new(),
                remaining_risks: Vec::new(),
                recommendations: Vec::new(),
                summary: format!(
                    "agent response was not a JSON object (got {})",
                    describe_shape(data)
                ),
            };
        };
        let verdict = obj
            .get("verdict")
            .and_then(Value::as_str)
            .and_then(Verdict::parse)
            .unwrap_or(Verdict::NeedsReview);
        RemediationVerdict {
            finding_index,
            verdict,
            gates: obj.get("gates").map(Gates::from_value).unwrap_or_default(),
            root_cause: str_field(data, "root_cause"),
            changes: obj
                .get("changes")
                .and_then(Value::as_array)
                .map(|arr| arr.iter().map(Change::from_value).collect())
                .unwrap_or_default(),
            remaining_risks: str_list_field(data, "remaining_risks"),
            recommendations: str_list_field(data, "recommendations"),
            summary: str_field(data, "summary"),
        }
    }

    /// A bare "denied by policy" verdict for a finding the pre-gate
    /// refused to send to the model at all — no patch, no prose advice.
    /// Ported from `policy.decide.guidance_verdict`.
    pub fn denied(finding_index: i64, reason: &str) -> Self {
        RemediationVerdict {
            finding_index,
            verdict: Verdict::Denied,
            gates: Gates::default(),
            root_cause: String::new(),
            changes: Vec::new(),
            remaining_risks: Vec::new(),
            recommendations: Vec::new(),
            summary: format!("Denied by policy ({reason}). No patch generated."),
        }
    }

    /// A bare "outside the diff scope" verdict for a finding
    /// [`crate::remediate_finding_with_baseline`]'s scope gate refused to
    /// send to the model — the `--diff-scope` counterpart of
    /// [`RemediationVerdict::denied`], and deliberately NOT that function:
    /// a reader must be able to tell "your policy forbids patching this"
    /// from "this file is not part of the pull request", and a shared
    /// `Denied by policy (...)` sentence would blur exactly that.
    ///
    /// Reuses [`Verdict::Denied`] for the verdict itself so every existing
    /// consumer (report rendering, `--out-remediation-json`, S11's
    /// "nothing to validate" check) treats it as the no-patch outcome it
    /// is, without a new variant each of them would have to learn.
    ///
    /// Net-new versus Python, which has no diff scoping at all.
    pub fn out_of_diff_scope(finding_index: i64, reason: &str) -> Self {
        RemediationVerdict {
            finding_index,
            verdict: Verdict::Denied,
            gates: Gates::default(),
            root_cause: String::new(),
            changes: Vec::new(),
            remaining_risks: Vec::new(),
            recommendations: Vec::new(),
            summary: format!("Out of diff scope ({reason}). No patch generated."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_round_trips_through_as_str_and_parse() {
        for v in [
            Verdict::Fixed,
            Verdict::PartiallyFixed,
            Verdict::NotFixed,
            Verdict::FalsePositive,
            Verdict::NeedsReview,
            Verdict::Denied,
        ] {
            assert_eq!(Verdict::parse(v.as_str()), Some(v));
        }
    }

    #[test]
    fn verdict_parse_rejects_an_unrecognized_string() {
        assert_eq!(Verdict::parse("Fixed!"), None);
    }

    #[test]
    fn gate_status_round_trips_through_as_str_and_parse() {
        for g in [GateStatus::Pass, GateStatus::Partial, GateStatus::Fail] {
            assert_eq!(GateStatus::parse(g.as_str()), Some(g));
        }
    }

    #[test]
    fn gate_status_parse_rejects_an_unrecognized_string() {
        assert_eq!(GateStatus::parse("PASS"), None);
    }

    #[test]
    fn gates_default_to_fail() {
        let g = Gates::default();
        assert_eq!(g.source, GateStatus::Fail);
        assert_eq!(g.sink, GateStatus::Fail);
        assert_eq!(g.missing_control, GateStatus::Fail);
        assert!(!g.all_pass());
    }

    #[test]
    fn gates_all_pass_is_true_only_when_every_gate_passes() {
        let g = Gates {
            source: GateStatus::Pass,
            sink: GateStatus::Pass,
            missing_control: GateStatus::Pass,
        };
        assert!(g.all_pass());
        let partial = Gates {
            missing_control: GateStatus::Partial,
            ..g
        };
        assert!(!partial.all_pass());
    }

    #[test]
    fn coerce_of_a_non_object_is_needs_review() {
        let v = RemediationVerdict::coerce(&Value::String("oops".to_string()), 3);
        assert_eq!(v.finding_index, 3);
        assert_eq!(v.verdict, Verdict::NeedsReview);
        assert!(v.summary.contains("not a JSON object"));
    }

    #[test]
    fn coerce_of_a_full_valid_payload_preserves_every_field() {
        let data = serde_json::json!({
            "finding_index": 99,
            "verdict": "Fixed",
            "gates": {"source": "pass", "sink": "pass", "missing_control": "pass"},
            "root_cause": "unsanitized input reaches the sink",
            "changes": [{"file": "app.py", "summary": "parameterized the query"}],
            "remaining_risks": ["none"],
            "recommendations": ["add a regression test"],
            "summary": "Fixed the SQL injection.",
        });
        let v = RemediationVerdict::coerce(&data, 1);
        // finding_index is pinned to the caller's value, not the payload's.
        assert_eq!(v.finding_index, 1);
        assert_eq!(v.verdict, Verdict::Fixed);
        assert!(v.gates.all_pass());
        assert_eq!(v.root_cause, "unsanitized input reaches the sink");
        assert_eq!(
            v.changes,
            vec![Change {
                file: "app.py".to_string(),
                summary: "parameterized the query".to_string()
            }]
        );
        assert_eq!(v.remaining_risks, vec!["none".to_string()]);
        assert_eq!(v.recommendations, vec!["add a regression test".to_string()]);
        assert_eq!(v.summary, "Fixed the SQL injection.");
    }

    #[test]
    fn coerce_of_an_unrecognized_verdict_string_falls_back_to_needs_review() {
        let data = serde_json::json!({"verdict": "Kinda Fixed?"});
        let v = RemediationVerdict::coerce(&data, 1);
        assert_eq!(v.verdict, Verdict::NeedsReview);
    }

    #[test]
    fn coerce_of_a_missing_verdict_field_falls_back_to_needs_review() {
        let v = RemediationVerdict::coerce(&serde_json::json!({}), 1);
        assert_eq!(v.verdict, Verdict::NeedsReview);
    }

    #[test]
    fn coerce_missing_gates_defaults_to_all_fail() {
        let data = serde_json::json!({"verdict": "Fixed"});
        let v = RemediationVerdict::coerce(&data, 1);
        assert_eq!(v.gates, Gates::default());
    }

    #[test]
    fn coerce_missing_optional_fields_defaults_to_empty() {
        let data = serde_json::json!({"verdict": "Not Fixed"});
        let v = RemediationVerdict::coerce(&data, 1);
        assert_eq!(v.root_cause, "");
        assert!(v.changes.is_empty());
        assert!(v.remaining_risks.is_empty());
        assert!(v.recommendations.is_empty());
        assert_eq!(v.summary, "");
    }

    #[test]
    fn coerce_a_change_missing_its_own_fields_defaults_to_empty_strings() {
        let data = serde_json::json!({"verdict": "Fixed", "changes": [{}]});
        let v = RemediationVerdict::coerce(&data, 1);
        assert_eq!(v.changes, vec![Change::default()]);
    }

    #[test]
    fn coerce_ignores_non_string_entries_in_a_string_list_field() {
        let data = serde_json::json!({
            "verdict": "Fixed",
            "remaining_risks": ["ok", 5, null, "another"],
        });
        let v = RemediationVerdict::coerce(&data, 1);
        assert_eq!(
            v.remaining_risks,
            vec!["ok".to_string(), "another".to_string()]
        );
    }

    #[test]
    fn denied_builds_a_bare_verdict_with_no_advice() {
        let v = RemediationVerdict::denied(7, "deny:CWE-284");
        assert_eq!(v.finding_index, 7);
        assert_eq!(v.verdict, Verdict::Denied);
        assert!(v.changes.is_empty());
        assert!(v.recommendations.is_empty());
        assert_eq!(
            v.summary,
            "Denied by policy (deny:CWE-284). No patch generated."
        );
    }

    #[test]
    fn out_of_diff_scope_is_distinguishable_from_a_policy_denial() {
        let v = RemediationVerdict::out_of_diff_scope(3, "vendor/lib.py is outside");
        assert_eq!(v.finding_index, 3);
        assert_eq!(v.verdict, Verdict::Denied);
        assert!(v.changes.is_empty());
        assert!(v.recommendations.is_empty());
        assert_eq!(
            v.summary,
            "Out of diff scope (vendor/lib.py is outside). No patch generated."
        );
        assert!(!v.summary.contains("Denied by policy"));
    }
}

#[cfg(test)]
mod unwrap_tests {
    use super::*;

    #[test]
    fn a_single_element_array_wrapping_the_verdict_is_unwrapped() {
        // The 2026-09-04 field shape: the model returned the right
        // object inside a list, and the whole remediation was discarded.
        let data = serde_json::json!([{
            "verdict": "Fixed",
            "summary": "parameterized the query",
            "changes": [{"file": "app.py", "summary": "used ?"}]
        }]);
        let v = RemediationVerdict::coerce(&data, 7);
        assert_eq!(v.verdict, Verdict::Fixed);
        assert_eq!(v.summary, "parameterized the query");
        assert_eq!(v.changes.len(), 1);
        assert_eq!(v.finding_index, 7, "index is always the caller's");
    }

    #[test]
    fn a_multi_element_array_is_not_guessed_at() {
        let data = serde_json::json!([{"verdict": "Fixed"}, {"verdict": "Not Fixed"}]);
        let v = RemediationVerdict::coerce(&data, 1);
        assert_eq!(v.verdict, Verdict::NeedsReview);
        assert!(v.summary.contains("2-element array"), "{}", v.summary);
    }

    #[test]
    fn a_non_object_response_names_the_shape_it_got() {
        for (data, want) in [
            (serde_json::json!("Fixed"), "a string"),
            (serde_json::json!(3), "a number"),
            (serde_json::json!(true), "a boolean"),
            (serde_json::Value::Null, "null"),
            (serde_json::json!([]), "a 0-element array"),
        ] {
            let v = RemediationVerdict::coerce(&data, 1);
            assert_eq!(v.verdict, Verdict::NeedsReview);
            assert!(v.summary.contains(want), "{} lacked {want}", v.summary);
        }
    }

    #[test]
    fn describe_shape_names_an_object_too() {
        // Not reachable through `coerce` (an object takes the happy
        // path), but the arm exists so the helper is total.
        assert_eq!(describe_shape(&serde_json::json!({})), "an object");
    }

    #[test]
    fn a_single_element_array_of_a_non_object_still_reports_that_element() {
        let v = RemediationVerdict::coerce(&serde_json::json!(["nope"]), 1);
        assert_eq!(v.verdict, Verdict::NeedsReview);
        assert!(v.summary.contains("a string"), "{}", v.summary);
    }
}
