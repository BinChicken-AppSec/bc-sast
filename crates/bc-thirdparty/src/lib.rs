//! Third-party SAST/SCA scan ingestion: parses vendor-exported findings
//! (Checkmarx, Snyk, Semgrep, Aikido, Sonatype) into this pipeline's own
//! `bc_model::Finding` shape, so they can be re-verified through S6 and
//! deduplicated against LLM-discovered findings through S7. This is a
//! new feature with no Python precedent — the original tool has no
//! third-party SAST/SCA ingestion of any kind (confirmed by exhaustive
//! grep of the Python source: zero references to any of these 5 vendor
//! names outside this port's own outbound `--out-csv` format, which is
//! only loosely styled after what such tools produce, not an inbound
//! parser).
//!
//! Each vendor module exposes `parse(text: &str) -> Result<Vec<ThirdPartyFinding>, String>`
//! for its own canonical export format (see each module's own doc
//! comment for which format/shape was chosen and why real vendor export
//! shapes disagree enough that only ONE per vendor is supported, not
//! every historical variant). [`to_finding`] converts the shared
//! normalized IR into a `bc_model::Finding` ready to flow through S6/S7
//! exactly like any LLM-discovered finding.

pub mod aikido;
pub mod checkmarx;
pub mod semgrep;
pub mod snyk;
pub mod sonatype;

use bc_model::{Finding, VulnClass};

/// A vendor's own severity rating, normalized to one shared 5-point
/// scale — every vendor uses a different word/number scale (see each
/// vendor module's own doc comment) — the common currency [`to_finding`]
/// preserves independently from verification confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// One finding, normalized from a vendor's own export shape into a
/// common intermediate representation every vendor module produces —
/// [`to_finding`] is the single place that turns this into a real
/// `bc_model::Finding`, so the CWE/severity/vuln-class mapping logic
/// lives in exactly one place regardless of which of the 5 vendor
/// parsers produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct ThirdPartyFinding {
    pub provider_origins: Vec<bc_model::ProviderOrigin>,
    /// Short vendor tag stamped into the synthesized `chunk_id` and used
    /// in diagnostics — `"checkmarx"`/`"snyk"`/`"semgrep"`/`"aikido"`/
    /// `"sonatype"`.
    pub vendor: &'static str,
    /// The vendor's own stable finding/vulnerability identifier (e.g.
    /// Checkmarx's `SimilarityId`, Snyk's `SNYK-JS-...` id, Semgrep's
    /// `fingerprint`) — used for the synthesized `chunk_id` so repeat
    /// ingestion of the same export is traceable in the report; not
    /// otherwise a lookup key anywhere downstream (`chunk_id` is
    /// audit-trail-only, never matched on by S6/S7 — see [`to_finding`]'s
    /// own doc comment).
    pub external_id: String,
    pub title: String,
    /// Repo-relative source file (SAST) or manifest/dependency file
    /// (SCA) the finding is attributed to. SCA vendors (Snyk, Sonatype)
    /// often have no real line number for this — those modules default
    /// `line_start`/`line_end` to `1` rather than fabricating one; S6's
    /// verifier degrades gracefully when a line doesn't obviously relate
    /// to the claimed issue, since the finding's title/description still
    /// carries the real package/version evidence.
    pub file: String,
    pub line_start: i64,
    pub line_end: i64,
    /// Canonical `"CWE-NNN"` if the vendor supplied one, already
    /// normalized (see each module's own CWE-format handling — vendors
    /// disagree on bare-number vs `CWE-`-prefixed vs full descriptive-
    /// string formats).
    pub cwe: Option<String>,
    pub severity: Severity,
    pub description: String,
    /// Vendor-supplied remediation/fix guidance, when available — folded
    /// into `Finding.recommendation`. Empty when the vendor's export
    /// doesn't carry prose remediation text (e.g. Aikido's structured-
    /// only export).
    pub recommendation: String,
}

/// Maps a CWE id to this pipeline's closed [`VulnClass`] enum — a small,
/// deliberately approximate classifier with no Python-side precedent
/// (`VulnClass` was never applied to third-party findings there, since
/// none existed). Unknown/absent CWEs fall back to `Other`, which is
/// always a safe, harmless classification: `VulnClass` only gates a
/// handful of report-grouping/compliance-tag paths downstream, never a
/// hard filter that could silently drop a finding.
fn classify_vuln_class(cwe: Option<&str>) -> VulnClass {
    let Some(cwe) = cwe else {
        return VulnClass::Other;
    };
    match cwe.trim().to_ascii_uppercase().as_str() {
        "CWE-416" => VulnClass::UseAfterFree,
        "CWE-122" => VulnClass::HeapOverflow,
        "CWE-121" => VulnClass::StackOverflow,
        "CWE-134" => VulnClass::FormatString,
        "CWE-190" | "CWE-191" => VulnClass::IntegerOverflow,
        "CWE-843" => VulnClass::TypeConfusion,
        "CWE-362" | "CWE-367" => VulnClass::RaceCondition,
        "CWE-74" | "CWE-77" | "CWE-78" | "CWE-79" | "CWE-89" | "CWE-90" | "CWE-94" | "CWE-95"
        | "CWE-643" | "CWE-611" | "CWE-918" | "CWE-22" | "CWE-434" => VulnClass::Injection,
        "CWE-502" => VulnClass::UnsafeDeserialization,
        "CWE-840" | "CWE-841" | "CWE-862" | "CWE-863" | "CWE-284" | "CWE-285" | "CWE-287" => {
            VulnClass::LogicFlaw
        }
        "CWE-200" | "CWE-209" | "CWE-311" | "CWE-312" | "CWE-319" | "CWE-532" => {
            VulnClass::InfoLeak
        }
        _ => VulnClass::Other,
    }
}

/// Converts one normalized third-party finding into a `bc_model::Finding`
/// ready to be re-verified through S6 and deduplicated through S7
/// alongside this pipeline's own LLM-discovered findings.
///
/// `chunk_id` is synthesized as `"external:<vendor>:<external_id>"` —
/// audit-trail-only (rendered in the "Dropped Findings" table if S6/S7
/// drops it), never a lookup key anywhere in this codebase; `votes` is
/// always `1` (one vendor scanner made one detection — the honest value,
/// not a fabricated consensus count); `code_snippet` is left empty since
/// S6's verifier always re-reads the real source itself via its own
/// Read/Grep/Glob tools rather than trusting a caller-supplied snippet.
pub fn to_finding(tpf: &ThirdPartyFinding) -> Finding {
    Finding {
        provider_origins: tpf
            .provider_origins
            .iter()
            .cloned()
            .map(|mut origin| {
                if origin.severity.is_none() {
                    origin.severity = Some(format!("{:?}", tpf.severity).to_ascii_lowercase());
                }
                origin
            })
            .collect(),
        chunk_id: format!("external:{}:{}", tpf.vendor, tpf.external_id),
        file: tpf.file.clone(),
        line_start: tpf.line_start,
        line_end: tpf.line_end,
        vuln_class: classify_vuln_class(tpf.cwe.as_deref()),
        cwe: tpf.cwe.clone(),
        title: tpf.title.clone(),
        impact: String::new(),
        description: tpf.description.clone(),
        exploit_scenario: String::new(),
        preconditions: Vec::new(),
        recommendation: tpf.recommendation.clone(),
        code_snippet: String::new(),
        source_ref: None,
        sink_ref: None,
        backfilled_refs: Vec::new(),
        reanchored: Vec::new(),
        compliance_requirements: Vec::new(),
        // Severity describes impact, not evidence that the allegation is true.
        confidence: 0.5,
        votes: 1,
        duplicates: Vec::new(),
        verdict: None,
        verdict_confidence: None,
        verdict_reason: String::new(),
        cvss_vector: None,
        cvss_score: None,
        cvss_rating: None,
        verifier_reasoning: String::new(),
        vsvs_vector: None,
        vsvs_score: None,
        vsvs_rating: None,
        offensive_priority: None,
        offensive_reason: String::new(),
        related_cwes: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(cwe: Option<&str>, severity: Severity) -> ThirdPartyFinding {
        ThirdPartyFinding {
            provider_origins: Vec::new(),
            vendor: "snyk",
            external_id: "SNYK-JS-LODASH-1".to_string(),
            title: "Prototype Pollution".to_string(),
            file: "package.json".to_string(),
            line_start: 1,
            line_end: 1,
            cwe: cwe.map(str::to_string),
            severity,
            description: "desc".to_string(),
            recommendation: "upgrade lodash".to_string(),
        }
    }

    #[test]
    fn to_finding_synthesizes_a_vendor_scoped_chunk_id() {
        let f = to_finding(&sample(None, Severity::High));
        assert_eq!(f.chunk_id, "external:snyk:SNYK-JS-LODASH-1");
    }

    #[test]
    fn to_finding_always_sets_votes_to_one() {
        let f = to_finding(&sample(None, Severity::High));
        assert_eq!(f.votes, 1);
    }

    #[test]
    fn to_finding_leaves_code_snippet_empty() {
        let f = to_finding(&sample(None, Severity::High));
        assert_eq!(f.code_snippet, "");
    }

    #[test]
    fn to_finding_carries_title_description_and_recommendation() {
        let f = to_finding(&sample(None, Severity::Medium));
        assert_eq!(f.title, "Prototype Pollution");
        assert_eq!(f.description, "desc");
        assert_eq!(f.recommendation, "upgrade lodash");
    }

    #[test]
    fn to_finding_carries_file_and_line_span() {
        let mut tpf = sample(None, Severity::Low);
        tpf.file = "src/app.py".to_string();
        tpf.line_start = 10;
        tpf.line_end = 12;
        let f = to_finding(&tpf);
        assert_eq!(f.file, "src/app.py");
        assert_eq!(f.line_start, 10);
        assert_eq!(f.line_end, 12);
    }

    #[test]
    fn to_finding_leaves_step6_and_post_step7_fields_at_their_defaults() {
        let f = to_finding(&sample(None, Severity::Critical));
        assert_eq!(f.verdict, None);
        assert_eq!(f.cvss_score, None);
        assert_eq!(f.vsvs_score, None);
        assert_eq!(f.offensive_priority, None);
        assert!(f.duplicates.is_empty());
        assert!(f.compliance_requirements.is_empty());
    }

    #[rstest::rstest]
    #[case(Severity::Critical, 0.5)]
    #[case(Severity::High, 0.5)]
    #[case(Severity::Medium, 0.5)]
    #[case(Severity::Low, 0.5)]
    #[case(Severity::Info, 0.5)]
    fn severity_does_not_determine_verification_confidence(
        #[case] sev: Severity,
        #[case] expected: f64,
    ) {
        let f = to_finding(&sample(None, sev));
        assert_eq!(f.confidence, expected);
    }

    #[test]
    fn file_origin_keeps_severity_without_inventing_mutation_identity() {
        let mut input = sample(None, Severity::Critical);
        input.provider_origins.push(bc_model::ProviderOrigin {
            source: bc_model::ProviderSource::File,
            provider: bc_model::ProviderKind::Semgrep,
            ..Default::default()
        });
        let finding = to_finding(&input);
        assert_eq!(
            finding.provider_origins[0].severity.as_deref(),
            Some("critical")
        );
        assert!(finding.provider_origins[0].native_ids.issue_id.is_none());
        assert_eq!(finding.confidence, 0.5);
        let roundtrip: Finding =
            serde_json::from_value(serde_json::to_value(&finding).unwrap()).unwrap();
        assert_eq!(roundtrip.provider_origins, finding.provider_origins);
    }

    #[test]
    fn to_finding_carries_the_cwe_through_unchanged() {
        let f = to_finding(&sample(Some("CWE-89"), Severity::High));
        assert_eq!(f.cwe, Some("CWE-89".to_string()));
    }

    #[rstest::rstest]
    #[case("CWE-416", VulnClass::UseAfterFree)]
    #[case("CWE-122", VulnClass::HeapOverflow)]
    #[case("CWE-121", VulnClass::StackOverflow)]
    #[case("CWE-134", VulnClass::FormatString)]
    #[case("CWE-190", VulnClass::IntegerOverflow)]
    #[case("CWE-191", VulnClass::IntegerOverflow)]
    #[case("CWE-843", VulnClass::TypeConfusion)]
    #[case("CWE-362", VulnClass::RaceCondition)]
    #[case("CWE-367", VulnClass::RaceCondition)]
    #[case("CWE-79", VulnClass::Injection)]
    #[case("CWE-89", VulnClass::Injection)]
    #[case("CWE-78", VulnClass::Injection)]
    #[case("CWE-77", VulnClass::Injection)]
    #[case("CWE-74", VulnClass::Injection)]
    #[case("CWE-90", VulnClass::Injection)]
    #[case("CWE-94", VulnClass::Injection)]
    #[case("CWE-95", VulnClass::Injection)]
    #[case("CWE-643", VulnClass::Injection)]
    #[case("CWE-611", VulnClass::Injection)]
    #[case("CWE-918", VulnClass::Injection)]
    #[case("CWE-22", VulnClass::Injection)]
    #[case("CWE-434", VulnClass::Injection)]
    #[case("CWE-502", VulnClass::UnsafeDeserialization)]
    #[case("CWE-840", VulnClass::LogicFlaw)]
    #[case("CWE-841", VulnClass::LogicFlaw)]
    #[case("CWE-862", VulnClass::LogicFlaw)]
    #[case("CWE-863", VulnClass::LogicFlaw)]
    #[case("CWE-284", VulnClass::LogicFlaw)]
    #[case("CWE-285", VulnClass::LogicFlaw)]
    #[case("CWE-287", VulnClass::LogicFlaw)]
    #[case("CWE-200", VulnClass::InfoLeak)]
    #[case("CWE-209", VulnClass::InfoLeak)]
    #[case("CWE-311", VulnClass::InfoLeak)]
    #[case("CWE-312", VulnClass::InfoLeak)]
    #[case("CWE-319", VulnClass::InfoLeak)]
    #[case("CWE-532", VulnClass::InfoLeak)]
    #[case("CWE-9999", VulnClass::Other)]
    fn classify_vuln_class_mapping(#[case] cwe: &str, #[case] expected: VulnClass) {
        assert_eq!(classify_vuln_class(Some(cwe)), expected);
    }

    #[test]
    fn classify_vuln_class_absent_cwe_is_other() {
        assert_eq!(classify_vuln_class(None), VulnClass::Other);
    }

    #[test]
    fn classify_vuln_class_is_case_and_whitespace_insensitive() {
        assert_eq!(classify_vuln_class(Some(" cwe-89 ")), VulnClass::Injection);
    }
}
