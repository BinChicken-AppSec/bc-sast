use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::coerce;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VulnClass {
    UseAfterFree,
    HeapOverflow,
    StackOverflow,
    FormatString,
    IntegerOverflow,
    TypeConfusion,
    RaceCondition,
    Injection,
    UnsafeDeserialization,
    LogicFlaw,
    InfoLeak,
    Other,
}

impl VulnClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UseAfterFree => "use-after-free",
            Self::HeapOverflow => "heap-overflow",
            Self::StackOverflow => "stack-overflow",
            Self::FormatString => "format-string",
            Self::IntegerOverflow => "integer-overflow",
            Self::TypeConfusion => "type-confusion",
            Self::RaceCondition => "race-condition",
            Self::Injection => "injection",
            Self::UnsafeDeserialization => "unsafe-deserialization",
            Self::LogicFlaw => "logic-flaw",
            Self::InfoLeak => "info-leak",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DupLocation {
    pub file: String,
    pub line_start: i64,
    #[serde(default)]
    pub line_end: i64,
    pub vuln_class: VulnClass,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub chunk_id: String,
    #[serde(default)]
    pub source_ref: Option<String>,
    #[serde(default)]
    pub sink_ref: Option<String>,
    #[serde(default)]
    pub reasoning: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    TruePositive,
    FalsePositive,
}

fn deserialize_confidence<'de, D>(d: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    let v = Value::deserialize(d)?;
    Ok(coerce::coerce_confidence(&v, 0.5))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    #[serde(default)]
    pub provider_origins: Vec<crate::ProviderOrigin>,
    #[serde(default)]
    pub component: Option<crate::ComponentRef>,
    pub chunk_id: String,
    pub file: String,
    pub line_start: i64,
    pub line_end: i64,
    pub vuln_class: VulnClass,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub related_cwes: Vec<String>,
    pub title: String,
    #[serde(default)]
    pub impact: String,
    pub description: String,
    #[serde(default)]
    pub exploit_scenario: String,
    #[serde(default)]
    pub preconditions: Vec<String>,
    #[serde(default)]
    pub recommendation: String,
    pub code_snippet: String,
    #[serde(default)]
    pub source_ref: Option<String>,
    #[serde(default)]
    pub sink_ref: Option<String>,
    #[serde(default)]
    pub backfilled_refs: Vec<String>,
    #[serde(default)]
    pub reanchored: Vec<String>,
    #[serde(default)]
    pub compliance_requirements: Vec<String>,
    #[serde(deserialize_with = "deserialize_confidence")]
    pub confidence: f64,
    #[serde(default = "default_votes")]
    pub votes: i64,
    #[serde(default)]
    pub duplicates: Vec<DupLocation>,

    #[serde(default)]
    pub verdict: Option<Verdict>,
    #[serde(default)]
    pub verdict_confidence: Option<i64>,
    #[serde(default)]
    pub verdict_reason: String,
    #[serde(default)]
    pub cvss_vector: Option<String>,
    #[serde(default)]
    pub cvss_score: Option<f64>,
    #[serde(default)]
    pub cvss_rating: Option<String>,
    #[serde(default)]
    pub verifier_reasoning: String,

    #[serde(default)]
    pub vsvs_vector: Option<String>,
    #[serde(default)]
    pub vsvs_score: Option<f64>,
    #[serde(default)]
    pub vsvs_rating: Option<String>,
    #[serde(default)]
    pub offensive_priority: Option<String>,
    #[serde(default)]
    pub offensive_reason: String,
}

fn default_votes() -> i64 {
    1
}

impl Finding {
    pub fn canonical_key(&self, line_bucket: i64) -> (String, i64, VulnClass) {
        let bucket = if line_bucket == 0 {
            self.line_start
        } else {
            self.line_start.div_euclid(line_bucket)
        };
        (self.file.clone(), bucket, self.vuln_class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn minimal_finding_json() -> serde_json::Value {
        serde_json::json!({
            "chunk_id": "c1",
            "file": "a.py",
            "line_start": 10,
            "line_end": 12,
            "vuln_class": "injection",
            "title": "SQLi",
            "description": "desc",
            "code_snippet": "query(x)",
            "confidence": 0.9,
        })
    }

    #[test]
    fn finding_deserializes_with_defaults() {
        let f: Finding = serde_json::from_value(minimal_finding_json()).unwrap();
        assert_eq!(f.votes, 1);
        assert!(f.duplicates.is_empty());
        assert!(f.backfilled_refs.is_empty());
        assert!(f.reanchored.is_empty());
        assert_eq!(f.verdict, None);
        assert_eq!(f.confidence, 0.9);
        assert_eq!(f.vuln_class, VulnClass::Injection);
    }

    #[test]
    fn finding_backfilled_refs_round_trips_when_populated() {
        let mut json = minimal_finding_json();
        json["backfilled_refs"] = serde_json::json!(["source_ref", "sink_ref"]);
        let f: Finding = serde_json::from_value(json).unwrap();
        assert_eq!(
            f.backfilled_refs,
            vec!["source_ref".to_string(), "sink_ref".to_string()]
        );
    }

    #[test]
    fn finding_reanchored_round_trips_when_populated() {
        let mut json = minimal_finding_json();
        json["reanchored"] = serde_json::json!(["line_start", "line_end"]);
        let f: Finding = serde_json::from_value(json).unwrap();
        assert_eq!(
            f.reanchored,
            vec!["line_start".to_string(), "line_end".to_string()]
        );
        let back = serde_json::to_value(&f).unwrap();
        assert_eq!(
            back["reanchored"],
            serde_json::json!(["line_start", "line_end"])
        );
    }

    #[test]
    fn finding_confidence_is_coerced_not_strict() {
        let mut json = minimal_finding_json();
        json["confidence"] = serde_json::json!("high");
        let f: Finding = serde_json::from_value(json).unwrap();
        assert_eq!(f.confidence, 0.5);
    }

    #[test]
    fn finding_confidence_missing_entirely_is_a_hard_error() {
        let mut json = minimal_finding_json();
        json.as_object_mut().unwrap().remove("confidence");
        let result: Result<Finding, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn finding_vuln_class_has_no_leniency_and_rejects_unknown_values() {
        let mut json = minimal_finding_json();
        json["vuln_class"] = serde_json::json!("not-a-real-class");
        let result: Result<Finding, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[rstest]
    #[case(VulnClass::UseAfterFree, "use-after-free")]
    #[case(VulnClass::HeapOverflow, "heap-overflow")]
    #[case(VulnClass::StackOverflow, "stack-overflow")]
    #[case(VulnClass::FormatString, "format-string")]
    #[case(VulnClass::IntegerOverflow, "integer-overflow")]
    #[case(VulnClass::TypeConfusion, "type-confusion")]
    #[case(VulnClass::RaceCondition, "race-condition")]
    #[case(VulnClass::Injection, "injection")]
    #[case(VulnClass::UnsafeDeserialization, "unsafe-deserialization")]
    #[case(VulnClass::LogicFlaw, "logic-flaw")]
    #[case(VulnClass::InfoLeak, "info-leak")]
    #[case(VulnClass::Other, "other")]
    fn vuln_class_as_str_and_round_trip(#[case] vc: VulnClass, #[case] wire: &str) {
        assert_eq!(vc.as_str(), wire);
        let v = serde_json::to_value(vc).unwrap();
        assert_eq!(v, serde_json::json!(wire));
        let back: VulnClass = serde_json::from_value(v).unwrap();
        assert_eq!(back, vc);
    }

    #[test]
    fn canonical_key_buckets_line_start() {
        let mut f: Finding = serde_json::from_value(minimal_finding_json()).unwrap();
        f.line_start = 142;
        let k1 = f.canonical_key(10);
        f.line_start = 145;
        let k2 = f.canonical_key(10);
        assert_eq!(k1, k2);
        f.line_start = 200;
        let k3 = f.canonical_key(10);
        assert_ne!(k1, k3);
    }

    #[test]
    fn canonical_key_zero_bucket_falls_back_to_exact_line() {
        let mut f: Finding = serde_json::from_value(minimal_finding_json()).unwrap();
        f.line_start = 142;
        assert_eq!(
            f.canonical_key(0),
            ("a.py".to_string(), 142, VulnClass::Injection)
        );
    }

    #[rstest]
    #[case("TRUE_POSITIVE", Verdict::TruePositive)]
    #[case("FALSE_POSITIVE", Verdict::FalsePositive)]
    fn verdict_wire_format(#[case] wire: &str, #[case] expected: Verdict) {
        let v: Verdict = serde_json::from_value(serde_json::json!(wire)).unwrap();
        assert_eq!(v, expected);
        assert_eq!(
            serde_json::to_value(expected).unwrap(),
            serde_json::json!(wire)
        );
    }

    #[test]
    fn dup_location_defaults() {
        let d: DupLocation = serde_json::from_value(serde_json::json!({
            "file": "a.py", "line_start": 1, "vuln_class": "other"
        }))
        .unwrap();
        assert_eq!(d.line_end, 0);
        assert_eq!(d.title, "");
        assert_eq!(d.source_ref, None);
    }
}
