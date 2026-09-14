//! Built-in, verified compliance-framework presets — bundled at compile
//! time via `include_str!`, so `--compliance-preset asvs` works with no
//! network access at scan time. Each preset's own YAML file carries its
//! primary-source citation and verification date in a header comment,
//! matching this repo's `docs/compliance/CONTROL_MAPPING.md` rigor bar: a
//! wrong control ID is worse than none, so gaps are left out rather than
//! guessed.
//!
//! `presets/asvs.yaml` ships a primary-source-verified CWE-to-ASVS-
//! v5.0.0-requirement crosswalk (see that file's own header comment for
//! the exact chapters consulted, explicit no-match CWEs, and the few
//! general/imperfect-fit mappings flagged in-line). Defaults to
//! `scope_mode: annotate` — tag every matching finding, drop nothing —
//! matching this crate's own safer-default philosophy; a caller who
//! wants ASVS-only reporting can override every loaded policy's scope
//! uniformly (`bc-cli`'s `--compliance-scope filter`).
//!
//! `presets/soc2.yaml` is deliberately much smaller: the AICPA Trust
//! Services Criteria are principle-based and auditor-interpreted, not a
//! prescriptive technical control list, so only 3 of the 77 recognized
//! CWEs have a genuinely specific (not "everything funnels into one
//! broad bucket") textual match — see that file's own header comment.
//! Guidance-text prioritization carries the rest of the signal.
//!
//! `presets/ssdf.yaml` maps to NIST SP 800-218 (SSDF) v1.1 + SP 800-218A.
//! SSDF sits between asvs.yaml's near-total per-CWE granularity and
//! soc2.yaml's near-total sparseness: it's a small set of broad,
//! process-level tasks (not ~350 fine-grained technical requirements),
//! so most of the 77 recognized CWEs converge on the same handful of IDs
//! (PW.5.1 "secure coding practices" and PW.7.2 "code review/analysis"
//! above all) rather than each getting a distinct ID the way ASVS's do —
//! see that file's own header comment for exactly which primary-source
//! text each task ID is grounded in, and for the 5 CWEs SSDF's text
//! never addresses at all.
//!
//! `presets/pci-dss.yaml` ships a primary-source-verified CWE-to-
//! PCI-DSS-v4.0.1-requirement crosswalk. Its scope deliberately differs
//! from `docs/compliance/CONTROL_MAPPING.md`'s own PCI-DSS row (which
//! scopes PCI-DSS to "Requirement 6 only" because that document maps
//! this TOOL's own posture as a stateless CI scanner never itself in a
//! cardholder-data environment): this preset maps CWEs found in a
//! *scanned customer repo*, which may well be part of a CDE, so it maps
//! across the whole standard (Requirements 2/3/4/6/7/8 and Appendix
//! A1) — see that file's own header comment for the exact sections
//! read, why 6.2.4 is unusually broad by design of the primary text
//! itself, and the full no-match CWE list with reasons.

use crate::loader::parse_policy;
use crate::types::CompliancePolicy;

const ASVS: &str = include_str!("../presets/asvs.yaml");
const SOC2: &str = include_str!("../presets/soc2.yaml");
const SSDF: &str = include_str!("../presets/ssdf.yaml");
const PCI_DSS: &str = include_str!("../presets/pci-dss.yaml");

/// Looks up a built-in preset by name (case-insensitive). Fails closed on
/// an unknown name or on malformed embedded YAML — the latter would be a
/// packaging bug caught immediately by this crate's own tests, not a
/// runtime data problem, but still surfaced as an error rather than
/// silently ignored.
pub fn preset(name: &str) -> Result<CompliancePolicy, String> {
    match name.to_ascii_lowercase().as_str() {
        "asvs" => preset_from(name, ASVS),
        "soc2" => preset_from(name, SOC2),
        "ssdf" => preset_from(name, SSDF),
        "pci-dss" | "pci_dss" | "pcidss" => preset_from(name, PCI_DSS),
        other => Err(format!("unknown compliance preset: {other:?}")),
    }
}

/// Split out from [`preset`] so the malformed-embedded-YAML error path is
/// directly testable with a deliberately bad `yaml` argument — the real
/// shipped presets are always well-formed, so this arm is otherwise a
/// packaging-bug backstop no real input ever reaches.
fn preset_from(name: &str, yaml: &str) -> Result<CompliancePolicy, String> {
    parse_policy(yaml).map_err(|e| format!("built-in preset {name:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asvs_preset_resolves_and_parses() {
        let policy = preset("asvs").unwrap();
        assert_eq!(policy.name, "OWASP ASVS v5.0.0");
    }

    #[test]
    fn preset_lookup_is_case_insensitive() {
        assert!(preset("ASVS").is_ok());
        assert!(preset("AsVs").is_ok());
    }

    #[test]
    fn unknown_preset_name_is_a_fail_closed_error() {
        let err = preset("nonexistent-framework").unwrap_err();
        assert!(err.contains("unknown compliance preset"));
        assert!(err.contains("nonexistent-framework"));
    }

    #[test]
    fn preset_from_wraps_a_malformed_yaml_parse_error_naming_the_preset() {
        let err = preset_from("asvs", "not: [a, valid\n").unwrap_err();
        assert!(err.contains("asvs"));
    }

    #[test]
    fn asvs_preset_defaults_to_annotate_scope() {
        let policy = preset("asvs").unwrap();
        assert_eq!(policy.scope_mode, crate::types::ScopeMode::Annotate);
    }

    #[test]
    fn asvs_preset_maps_known_cwes_to_the_expected_requirement_ids() {
        use crate::matching::matching_requirement_ids;
        let policy = preset("asvs").unwrap();
        assert_eq!(
            matching_requirement_ids(&policy, Some("CWE-89"), "other"),
            vec!["V1.2.4".to_string()]
        );
        // A CWE cited under more than one ASVS id matches every one of
        // them, not just the first.
        assert_eq!(
            matching_requirement_ids(&policy, Some("CWE-918"), "other"),
            vec!["V1.3.6".to_string(), "V1.5.3".to_string()]
        );
    }

    #[test]
    fn asvs_preset_has_no_entry_for_a_documented_no_match_cwe() {
        let policy = preset("asvs").unwrap();
        for cwe in ["CWE-276", "CWE-426", "CWE-476", "CWE-732"] {
            assert!(
                policy.requirements.iter().all(|r| !r.cwes.contains(&cwe.to_string())),
                "{cwe} is documented as a no-match in asvs.yaml's header but appears in a requirement"
            );
        }
    }

    /// Every CWE `bc-cwe` recognizes by name should be either mapped to
    /// at least one ASVS requirement here, or be one of the four CWEs
    /// `asvs.yaml`'s own header comment documents as a deliberate,
    /// explicit no-match — this is a regression guard against a CWE
    /// silently falling through the cracks (neither mapped nor
    /// documented as excluded) if `bc-cwe`'s table changes later. The
    /// list is duplicated here rather than importing `bc-cwe` to avoid
    /// adding a cross-crate dependency for a single test; it must be
    /// kept in sync with `crates/bc-cwe/src/lib.rs::lookup_name` by
    /// hand.
    #[test]
    fn every_known_cwe_is_either_mapped_or_a_documented_gap() {
        const KNOWN_CWES: &[&str] = &[
            "CWE-20", "CWE-22", "CWE-73", "CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89",
            "CWE-90", "CWE-94", "CWE-95", "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125",
            "CWE-134", "CWE-190", "CWE-200", "CWE-209", "CWE-269", "CWE-276", "CWE-284", "CWE-285",
            "CWE-287", "CWE-294", "CWE-295", "CWE-306", "CWE-311", "CWE-312", "CWE-319", "CWE-326",
            "CWE-327", "CWE-330", "CWE-345", "CWE-347", "CWE-352", "CWE-362", "CWE-367", "CWE-384",
            "CWE-400", "CWE-416", "CWE-426", "CWE-434", "CWE-444", "CWE-476", "CWE-489", "CWE-502",
            "CWE-522", "CWE-532", "CWE-552", "CWE-601", "CWE-611", "CWE-639", "CWE-640", "CWE-643",
            "CWE-668", "CWE-693", "CWE-732", "CWE-770", "CWE-787", "CWE-798", "CWE-829", "CWE-840",
            "CWE-841", "CWE-843", "CWE-862", "CWE-863", "CWE-915", "CWE-918", "CWE-923",
            "CWE-1021", "CWE-1104", "CWE-1188", "CWE-1236", "CWE-1333", "CWE-1390",
        ];
        const DOCUMENTED_NO_MATCH: &[&str] = &["CWE-276", "CWE-426", "CWE-476", "CWE-732"];

        let policy = preset("asvs").unwrap();
        let mapped: std::collections::HashSet<&str> = policy
            .requirements
            .iter()
            .flat_map(|r| r.cwes.iter().map(String::as_str))
            .collect();

        for cwe in KNOWN_CWES {
            let is_mapped = mapped.contains(cwe);
            let is_documented_gap = DOCUMENTED_NO_MATCH.contains(cwe);
            assert!(
                is_mapped || is_documented_gap,
                "{cwe} is neither mapped to an ASVS requirement nor listed as a documented no-match gap"
            );
            assert!(
                !(is_mapped && is_documented_gap),
                "{cwe} is both mapped AND listed as a no-match gap — inconsistent"
            );
        }
    }

    // ── soc2 ──────────────────────────────────────────────────────────

    #[test]
    fn soc2_preset_resolves_and_parses() {
        let policy = preset("soc2").unwrap();
        assert_eq!(policy.name, "SOC 2 (AICPA Trust Services Criteria)");
    }

    #[test]
    fn soc2_preset_defaults_to_annotate_scope() {
        let policy = preset("soc2").unwrap();
        assert_eq!(policy.scope_mode, crate::types::ScopeMode::Annotate);
    }

    #[test]
    fn soc2_preset_has_a_non_empty_guidance_text() {
        let policy = preset("soc2").unwrap();
        assert!(!policy.guidance.is_empty());
    }

    #[test]
    fn soc2_preset_maps_its_three_genuinely_specific_cwes() {
        use crate::matching::matching_requirement_ids;
        let policy = preset("soc2").unwrap();
        assert_eq!(
            matching_requirement_ids(&policy, Some("CWE-269"), "other"),
            vec!["CC6.3".to_string()]
        );
        assert_eq!(
            matching_requirement_ids(&policy, Some("CWE-319"), "other"),
            vec!["CC6.7".to_string()]
        );
        assert_eq!(
            matching_requirement_ids(&policy, Some("CWE-829"), "other"),
            vec!["CC6.8".to_string()]
        );
    }

    #[test]
    fn soc2_preset_deliberately_leaves_most_cwes_unmapped() {
        // Confirms this preset is genuinely minimal, not accidentally
        // truncated — matching asvs.yaml's near-total coverage would be
        // a sign something regressed, since soc2.yaml's own header
        // explains why only 3 CWEs have a defensible textual match.
        let policy = preset("soc2").unwrap();
        let mapped_count: usize = policy.requirements.iter().map(|r| r.cwes.len()).sum();
        assert_eq!(mapped_count, 3);
    }

    // ── ssdf ──────────────────────────────────────────────────────────

    #[test]
    fn ssdf_preset_resolves_and_parses() {
        let policy = preset("ssdf").unwrap();
        assert_eq!(policy.name, "NIST SP 800-218 (SSDF) v1.1");
    }

    #[test]
    fn ssdf_preset_lookup_is_case_insensitive() {
        assert!(preset("SSDF").is_ok());
        assert!(preset("SsDf").is_ok());
    }

    #[test]
    fn ssdf_preset_defaults_to_annotate_scope() {
        let policy = preset("ssdf").unwrap();
        assert_eq!(policy.scope_mode, crate::types::ScopeMode::Annotate);
    }

    #[test]
    fn ssdf_preset_has_a_non_empty_guidance_text() {
        let policy = preset("ssdf").unwrap();
        assert!(!policy.guidance.is_empty());
    }

    #[test]
    fn ssdf_preset_maps_known_cwes_to_the_expected_task_ids() {
        use crate::matching::matching_requirement_ids;
        let policy = preset("ssdf").unwrap();
        // CWE-1104 (unmaintained third-party component) is deliberately
        // narrow: only PW.4.4, not the broad PW.5.1/PW.7.2 pair, since
        // it's a component-lifecycle gap, not a coding-practice defect.
        assert_eq!(
            matching_requirement_ids(&policy, Some("CWE-1104"), "other"),
            vec!["PW.4.4".to_string()]
        );
        // CWE-89 (SQL injection) is a coding-practice defect: it should
        // hit both the general "prevent" task and the general "detect"
        // task, in task-number order.
        assert_eq!(
            matching_requirement_ids(&policy, Some("CWE-89"), "other"),
            vec!["PW.5.1".to_string(), "PW.7.2".to_string()]
        );
    }

    #[test]
    fn ssdf_preset_has_no_entry_for_a_documented_no_match_cwe() {
        let policy = preset("ssdf").unwrap();
        for cwe in ["CWE-400", "CWE-426", "CWE-732", "CWE-770", "CWE-923"] {
            assert!(
                policy.requirements.iter().all(|r| !r.cwes.contains(&cwe.to_string())),
                "{cwe} is documented as a no-match in ssdf.yaml's header but appears in a requirement"
            );
        }
    }

    /// Every CWE `bc-cwe` recognizes by name should be either mapped to
    /// at least one SSDF task here, or be one of the five CWEs
    /// `ssdf.yaml`'s own header comment documents as a deliberate,
    /// explicit no-match — mirrors
    /// `every_known_cwe_is_either_mapped_or_a_documented_gap` above for
    /// asvs.yaml. The list is duplicated here rather than importing
    /// `bc-cwe` to avoid a cross-crate dependency for a single test; it
    /// must be kept in sync with `crates/bc-cwe/src/lib.rs::lookup_name`
    /// by hand.
    #[test]
    fn every_known_cwe_is_either_ssdf_mapped_or_a_documented_gap() {
        const KNOWN_CWES: &[&str] = &[
            "CWE-20", "CWE-22", "CWE-73", "CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89",
            "CWE-90", "CWE-94", "CWE-95", "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125",
            "CWE-134", "CWE-190", "CWE-200", "CWE-209", "CWE-269", "CWE-276", "CWE-284", "CWE-285",
            "CWE-287", "CWE-294", "CWE-295", "CWE-306", "CWE-311", "CWE-312", "CWE-319", "CWE-326",
            "CWE-327", "CWE-330", "CWE-345", "CWE-347", "CWE-352", "CWE-362", "CWE-367", "CWE-384",
            "CWE-400", "CWE-416", "CWE-426", "CWE-434", "CWE-444", "CWE-476", "CWE-489", "CWE-502",
            "CWE-522", "CWE-532", "CWE-552", "CWE-601", "CWE-611", "CWE-639", "CWE-640", "CWE-643",
            "CWE-668", "CWE-693", "CWE-732", "CWE-770", "CWE-787", "CWE-798", "CWE-829", "CWE-840",
            "CWE-841", "CWE-843", "CWE-862", "CWE-863", "CWE-915", "CWE-918", "CWE-923",
            "CWE-1021", "CWE-1104", "CWE-1188", "CWE-1236", "CWE-1333", "CWE-1390",
        ];
        const DOCUMENTED_NO_MATCH: &[&str] =
            &["CWE-400", "CWE-426", "CWE-732", "CWE-770", "CWE-923"];

        let policy = preset("ssdf").unwrap();
        let mapped: std::collections::HashSet<&str> = policy
            .requirements
            .iter()
            .flat_map(|r| r.cwes.iter().map(String::as_str))
            .collect();

        for cwe in KNOWN_CWES {
            let is_mapped = mapped.contains(cwe);
            let is_documented_gap = DOCUMENTED_NO_MATCH.contains(cwe);
            assert!(
                is_mapped || is_documented_gap,
                "{cwe} is neither mapped to an SSDF task nor listed as a documented no-match gap"
            );
            assert!(
                !(is_mapped && is_documented_gap),
                "{cwe} is both mapped AND listed as a no-match gap — inconsistent"
            );
        }
    }

    // ── pci-dss ───────────────────────────────────────────────────────

    #[test]
    fn pci_dss_preset_resolves_and_parses() {
        let policy = preset("pci-dss").unwrap();
        assert_eq!(policy.name, "PCI-DSS v4.0.1");
    }

    #[test]
    fn pci_dss_preset_lookup_accepts_name_variants() {
        assert!(preset("PCI-DSS").is_ok());
        assert!(preset("pci_dss").is_ok());
        assert!(preset("PciDss").is_ok());
    }

    #[test]
    fn pci_dss_preset_defaults_to_annotate_scope() {
        let policy = preset("pci-dss").unwrap();
        assert_eq!(policy.scope_mode, crate::types::ScopeMode::Annotate);
    }

    #[test]
    fn pci_dss_preset_has_a_non_empty_guidance_text() {
        let policy = preset("pci-dss").unwrap();
        assert!(!policy.guidance.is_empty());
    }

    #[test]
    fn pci_dss_preset_maps_known_cwes_to_the_expected_requirement_ids() {
        use crate::matching::matching_requirement_ids;
        let policy = preset("pci-dss").unwrap();
        // CWE-798 (hard-coded credentials) has a literal, single primary
        // match: Requirement 8.6.2's "not hard coded in scripts,
        // configuration/property files, or bespoke and custom source
        // code" text.
        assert_eq!(
            matching_requirement_ids(&policy, Some("CWE-798"), "other"),
            vec!["8.6.2".to_string()]
        );
        // CWE-306 (missing authentication for a critical function) is
        // cited under both the general secure-coding requirement and
        // the specific authentication requirement.
        assert_eq!(
            matching_requirement_ids(&policy, Some("CWE-306"), "other"),
            vec!["6.2.4".to_string(), "8.3.1".to_string()]
        );
    }

    #[test]
    fn pci_dss_preset_has_no_entry_for_a_documented_no_match_cwe() {
        let policy = preset("pci-dss").unwrap();
        for cwe in [
            "CWE-209", "CWE-276", "CWE-362", "CWE-367", "CWE-384", "CWE-400", "CWE-426", "CWE-434",
            "CWE-476", "CWE-489", "CWE-502", "CWE-552", "CWE-601", "CWE-611", "CWE-693", "CWE-732",
            "CWE-770", "CWE-843", "CWE-918", "CWE-923", "CWE-1021", "CWE-1236", "CWE-1333",
        ] {
            assert!(
                policy.requirements.iter().all(|r| !r.cwes.contains(&cwe.to_string())),
                "{cwe} is documented as a no-match in pci-dss.yaml's header but appears in a requirement"
            );
        }
    }

    /// Every CWE `bc-cwe` recognizes by name should be either mapped to
    /// at least one PCI-DSS requirement here, or be one of the 23 CWEs
    /// `pci-dss.yaml`'s own header comment documents as a deliberate,
    /// explicit no-match — mirrors
    /// `every_known_cwe_is_either_mapped_or_a_documented_gap` above for
    /// asvs.yaml. The list is duplicated here rather than importing
    /// `bc-cwe` to avoid a cross-crate dependency for a single test; it
    /// must be kept in sync with `crates/bc-cwe/src/lib.rs::lookup_name`
    /// by hand.
    #[test]
    fn every_known_cwe_is_either_pci_dss_mapped_or_a_documented_gap() {
        const KNOWN_CWES: &[&str] = &[
            "CWE-20", "CWE-22", "CWE-73", "CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89",
            "CWE-90", "CWE-94", "CWE-95", "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125",
            "CWE-134", "CWE-190", "CWE-200", "CWE-209", "CWE-269", "CWE-276", "CWE-284", "CWE-285",
            "CWE-287", "CWE-294", "CWE-295", "CWE-306", "CWE-311", "CWE-312", "CWE-319", "CWE-326",
            "CWE-327", "CWE-330", "CWE-345", "CWE-347", "CWE-352", "CWE-362", "CWE-367", "CWE-384",
            "CWE-400", "CWE-416", "CWE-426", "CWE-434", "CWE-444", "CWE-476", "CWE-489", "CWE-502",
            "CWE-522", "CWE-532", "CWE-552", "CWE-601", "CWE-611", "CWE-639", "CWE-640", "CWE-643",
            "CWE-668", "CWE-693", "CWE-732", "CWE-770", "CWE-787", "CWE-798", "CWE-829", "CWE-840",
            "CWE-841", "CWE-843", "CWE-862", "CWE-863", "CWE-915", "CWE-918", "CWE-923",
            "CWE-1021", "CWE-1104", "CWE-1188", "CWE-1236", "CWE-1333", "CWE-1390",
        ];
        const DOCUMENTED_NO_MATCH: &[&str] = &[
            "CWE-209", "CWE-276", "CWE-362", "CWE-367", "CWE-384", "CWE-400", "CWE-426", "CWE-434",
            "CWE-476", "CWE-489", "CWE-502", "CWE-552", "CWE-601", "CWE-611", "CWE-693", "CWE-732",
            "CWE-770", "CWE-843", "CWE-918", "CWE-923", "CWE-1021", "CWE-1236", "CWE-1333",
        ];

        let policy = preset("pci-dss").unwrap();
        let mapped: std::collections::HashSet<&str> = policy
            .requirements
            .iter()
            .flat_map(|r| r.cwes.iter().map(String::as_str))
            .collect();

        for cwe in KNOWN_CWES {
            let is_mapped = mapped.contains(cwe);
            let is_documented_gap = DOCUMENTED_NO_MATCH.contains(cwe);
            assert!(
                is_mapped || is_documented_gap,
                "{cwe} is neither mapped to a PCI-DSS requirement nor listed as a documented no-match gap"
            );
            assert!(
                !(is_mapped && is_documented_gap),
                "{cwe} is both mapped AND listed as a no-match gap — inconsistent"
            );
        }
    }
}
