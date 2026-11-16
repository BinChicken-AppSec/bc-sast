mod fingerprint;
mod invocation;
mod result;
mod rules;
mod severity;
mod types;
mod wire;

use appsec_model::FinalReport;

pub use fingerprint::{
    finding_fingerprint, finding_fingerprint_v2, finding_fingerprint_v3, finding_id_v2,
    finding_id_v3, line_range_text, FINGERPRINT_KEY, FINGERPRINT_KEY_V2, FINGERPRINT_KEY_V3,
};
pub use result::{apply_validation, build_absent_result, rule_id_for, Fingerprints};
pub use types::{
    ArtifactLocation, Driver, Invocation, Location, MessageText, Notification, PhysicalLocation,
    Region, RelatedLocation, ResultProperties, Rule, Run, RunProperties, SarifDocument,
    SarifResult, Taxon, TaxonRef, Taxonomy, TaxonomyRef, Tool, ToolComponentRef,
};

pub fn finding_id(finding: &appsec_model::Finding) -> String {
    finding_fingerprint(rule_id_for(finding), &finding.file, &finding.code_snippet)
}

pub const CWE_TAXONOMY_GUID: &str = "b7c8d9e0-1f2a-3b4c-5d6e-7f8090a1b2c3";

pub fn build_sarif(report: &FinalReport, tool_version: &str) -> SarifDocument {
    build_sarif_with_validations(report, tool_version, &std::collections::BTreeMap::new())
}

fn reported_repo_root(report: &FinalReport) -> Option<&std::path::Path> {
    (!report.repo_root.is_empty()).then(|| std::path::Path::new(&report.repo_root))
}

pub fn build_sarif_with_validations(
    report: &FinalReport,
    tool_version: &str,
    validations: &std::collections::BTreeMap<String, appsec_validation_scoring::ValidationScore>,
) -> SarifDocument {
    build_sarif_in(
        reported_repo_root(report),
        report,
        tool_version,
        validations,
    )
}

pub fn build_sarif_in(
    repo_root: Option<&std::path::Path>,
    report: &FinalReport,
    tool_version: &str,
    validations: &std::collections::BTreeMap<String, appsec_validation_scoring::ValidationScore>,
) -> SarifDocument {
    let driver = Driver {
        name: "Agentic SAST".to_string(),
        version: tool_version.to_string(),
        rules: rules::build_rules(&report.findings),
        supported_taxonomies: vec![types::TaxonomyRef {
            guid: CWE_TAXONOMY_GUID.to_string(),
        }],
    };

    let results = report
        .findings
        .iter()
        .map(|rf| {
            let validation = validations.get(&finding_id(&rf.finding));
            let fingerprints = result::Fingerprints {
                v2: repo_root.and_then(|root| finding_id_v2(root, &rf.finding)),
                v3: repo_root.and_then(|root| finding_id_v3(root, &rf.finding)),
            };
            result::build_result(rf, validation, fingerprints)
        })
        .collect();
    let taxonomies = vec![rules::build_taxonomy(&report.findings)];
    let invocation = invocation::build_invocation(
        report.degraded,
        report.metrics.as_ref(),
        invocation::out_of_diff_scope_count(report),
    );
    let properties = invocation::build_run_properties(report);

    let run = Run {
        tool: Tool { driver },
        results,
        taxonomies,
        invocations: Some(vec![invocation]),
        properties,
    };

    SarifDocument {
        schema: "https://json.schemastore.org/sarif-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![run],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use appsec_model::{DupLocation, Finding, RankedFinding, ScanMetrics, Severity, VulnClass};

    fn minimal_report() -> FinalReport {
        FinalReport {
            repo_identity: None,
            provider_ledger: Default::default(),
            repo_root: "/repo".to_string(),
            repo_name: None,
            git_sha: None,
            findings: Vec::new(),
            chains: Vec::new(),
            dropped: Vec::new(),
            raw_findings_count: 0,
            metrics: None,
            threat_model: None,
            app_profile: None,
            summary: "clean scan".to_string(),
            degraded: false,
            degraded_reason: String::new(),
            unreachable_files: Vec::new(),
        }
    }

    fn finding(overrides: impl FnOnce(&mut Finding)) -> Finding {
        let mut f = Finding {
            provider_origins: Vec::new(),
            component: None,
            chunk_id: "c1".to_string(),
            file: "app/login.py".to_string(),
            line_start: 10,
            line_end: 10,
            vuln_class: VulnClass::Injection,
            cwe: None,
            title: "SQL injection".to_string(),
            impact: String::new(),
            description: "desc".to_string(),
            exploit_scenario: String::new(),
            preconditions: Vec::new(),
            recommendation: String::new(),
            code_snippet: "query(x)".to_string(),
            source_ref: None,
            sink_ref: None,
            backfilled_refs: Vec::new(),
            reanchored: Vec::new(),
            compliance_requirements: Vec::new(),
            confidence: 0.9,
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
        };
        overrides(&mut f);
        f
    }

    fn ranked(f: Finding, severity: Severity) -> RankedFinding {
        RankedFinding {
            finding: f,
            severity,
            exploitability_notes: String::new(),
        }
    }

    #[test]
    fn finding_id_matches_the_fingerprint_embedded_in_the_built_sarif() {
        let f = finding(|f| f.vuln_class = VulnClass::Injection);
        let id = finding_id(&f);
        let mut r = minimal_report();
        r.findings = vec![ranked(f, Severity::High)];
        let doc = build_sarif(&r, "1.0.0");
        let result = &doc.runs[0].results[0];
        assert_eq!(result.partial_fingerprints.get(FINGERPRINT_KEY), Some(&id));
    }

    #[test]
    fn build_sarif_emits_both_fingerprints_when_the_repo_is_readable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("login.py"), "a\nb\nc\n").unwrap();
        let f = finding(|f| {
            f.file = "login.py".to_string();
            f.line_start = 2;
            f.line_end = 2;
        });
        let mut r = minimal_report();
        r.repo_root = dir.path().to_string_lossy().to_string();
        r.findings = vec![ranked(f.clone(), Severity::High)];

        let doc = build_sarif(&r, "1.0.0");
        let fps = &doc.runs[0].results[0].partial_fingerprints;
        assert_eq!(fps.get(FINGERPRINT_KEY), Some(&finding_id(&f)));
        assert_eq!(
            fps.get(FINGERPRINT_KEY_V2),
            finding_id_v2(dir.path(), &f).as_ref()
        );
    }

    #[test]
    fn build_sarif_emits_v1_only_when_the_repo_is_not_readable() {
        let f = finding(|f| f.vuln_class = VulnClass::Injection);
        let mut r = minimal_report();
        r.findings = vec![ranked(f, Severity::High)];
        let fps = &build_sarif(&r, "1.0.0").runs[0].results[0].partial_fingerprints;
        assert!(fps.contains_key(FINGERPRINT_KEY));
        assert!(!fps.contains_key(FINGERPRINT_KEY_V2));
    }

    #[test]
    fn build_sarif_emits_v1_only_when_the_report_has_no_repo_root() {
        let f = finding(|f| f.vuln_class = VulnClass::Injection);
        let mut r = minimal_report();
        r.repo_root = String::new();
        r.findings = vec![ranked(f, Severity::High)];
        let fps = &build_sarif(&r, "1.0.0").runs[0].results[0].partial_fingerprints;
        assert!(fps.contains_key(FINGERPRINT_KEY));
        assert!(!fps.contains_key(FINGERPRINT_KEY_V2));
    }

    #[test]
    fn build_sarif_in_reads_sources_from_the_caller_supplied_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("login.py"), "a\nb\nc\n").unwrap();
        let f = finding(|f| {
            f.file = "login.py".to_string();
            f.line_start = 1;
            f.line_end = 1;
        });
        let mut r = minimal_report();
        r.repo_root = "/does/not/exist".to_string();
        r.findings = vec![ranked(f.clone(), Severity::High)];

        let doc = build_sarif_in(
            Some(dir.path()),
            &r,
            "1.0.0",
            &std::collections::BTreeMap::new(),
        );
        assert_eq!(
            doc.runs[0].results[0]
                .partial_fingerprints
                .get(FINGERPRINT_KEY_V2),
            finding_id_v2(dir.path(), &f).as_ref()
        );
    }

    #[test]
    fn build_sarif_in_with_no_root_skips_the_v2_fingerprint_entirely() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("login.py"), "a\n").unwrap();
        let f = finding(|f| {
            f.file = "login.py".to_string();
            f.line_start = 1;
            f.line_end = 1;
        });
        let mut r = minimal_report();
        r.repo_root = dir.path().to_string_lossy().to_string();
        r.findings = vec![ranked(f, Severity::High)];

        let doc = build_sarif_in(None, &r, "1.0.0", &std::collections::BTreeMap::new());
        let fps = &doc.runs[0].results[0].partial_fingerprints;
        assert!(fps.contains_key(FINGERPRINT_KEY));
        assert!(!fps.contains_key(FINGERPRINT_KEY_V2));
    }

    #[test]
    fn a_built_result_has_no_baseline_state_and_omits_the_key_when_serialized() {
        let f = finding(|f| f.vuln_class = VulnClass::Injection);
        let mut r = minimal_report();
        r.findings = vec![ranked(f, Severity::High)];
        let doc = build_sarif(&r, "1.0.0");
        assert!(doc.runs[0].results[0].baseline_state.is_none());
        let json = serde_json::to_string(&doc).unwrap();
        assert!(!json.contains("baselineState"));
    }

    #[test]
    fn with_baseline_state_sets_the_field_and_serializes_it() {
        let f = finding(|f| f.vuln_class = VulnClass::Injection);
        let mut r = minimal_report();
        r.findings = vec![ranked(f, Severity::High)];
        let doc = build_sarif(&r, "1.0.0");
        let tagged = doc.runs[0].results[0].clone().with_baseline_state("new");
        assert_eq!(tagged.baseline_state.as_deref(), Some("new"));
        let json = serde_json::to_string(&tagged).unwrap();
        assert!(json.contains("\"baselineState\":\"new\""));
    }

    #[test]
    fn build_sarif_with_validations_folds_a_matched_score_into_its_result_properties() {
        let f = finding(|f| f.vuln_class = VulnClass::Injection);
        let id = finding_id(&f);
        let mut r = minimal_report();
        r.findings = vec![ranked(f, Severity::High)];
        let mut validations = std::collections::BTreeMap::new();
        validations.insert(
            id,
            appsec_validation_scoring::ValidationScore {
                raw_score: 0.9,
                fix_status: appsec_validation_scoring::FixVerdict::Fixed,
                justification: "fix verified".to_string(),
                gate_results: Vec::new(),
                has_critical_failure: false,
            },
        );
        let doc = build_sarif_with_validations(&r, "1.0.0", &validations);
        let props = &doc.runs[0].results[0].properties;
        assert_eq!(props.validation_status.as_deref(), Some("Fixed"));
        assert_eq!(props.merge_readiness.as_deref(), Some("Ready"));
    }

    #[test]
    fn build_sarif_with_validations_leaves_an_unmatched_findings_properties_untouched() {
        let f = finding(|f| f.vuln_class = VulnClass::Injection);
        let mut r = minimal_report();
        r.findings = vec![ranked(f, Severity::High)];
        let mut validations = std::collections::BTreeMap::new();
        validations.insert(
            "some-other-finding".to_string(),
            appsec_validation_scoring::ValidationScore {
                raw_score: 0.9,
                fix_status: appsec_validation_scoring::FixVerdict::Fixed,
                justification: "fix verified".to_string(),
                gate_results: Vec::new(),
                has_critical_failure: false,
            },
        );
        let doc = build_sarif_with_validations(&r, "1.0.0", &validations);
        assert!(doc.runs[0].results[0]
            .properties
            .validation_status
            .is_none());
    }

    #[test]
    fn build_sarif_delegates_to_build_sarif_with_validations_with_no_scores() {
        let f = finding(|f| f.vuln_class = VulnClass::Injection);
        let mut r = minimal_report();
        r.findings = vec![ranked(f, Severity::High)];
        let doc = build_sarif(&r, "1.0.0");
        assert!(doc.runs[0].results[0]
            .properties
            .validation_status
            .is_none());
    }

    #[test]
    fn schema_and_version_are_exact() {
        let doc = build_sarif(&minimal_report(), "1.0.0");
        assert_eq!(doc.schema, "https://json.schemastore.org/sarif-2.1.0.json");
        assert_eq!(doc.version, "2.1.0");
        assert_eq!(doc.runs.len(), 1);
    }

    #[test]
    fn driver_name_and_version() {
        let doc = build_sarif(&minimal_report(), "9.9.9");
        let driver = &doc.runs[0].tool.driver;
        assert_eq!(driver.name, "Agentic SAST");
        assert_eq!(driver.version, "9.9.9");
    }

    #[test]
    fn driver_has_no_information_uri() {
        let doc = build_sarif(&minimal_report(), "1.0.0");
        let json = serde_json::to_value(&doc.runs[0].tool.driver).unwrap();
        assert!(json.get("informationUri").is_none());
    }

    #[test]
    fn supported_taxonomies_guid_matches_taxonomy_and_result_taxa() {
        let mut r = minimal_report();
        r.findings = vec![ranked(
            finding(|f| f.vuln_class = VulnClass::UseAfterFree),
            Severity::High,
        )];
        let doc = build_sarif(&r, "1.0.0");
        let run = &doc.runs[0];
        assert_eq!(
            run.tool.driver.supported_taxonomies[0].guid,
            CWE_TAXONOMY_GUID
        );
        assert_eq!(run.taxonomies[0].guid, CWE_TAXONOMY_GUID);
        assert_eq!(
            run.results[0].taxa.as_ref().unwrap()[0].tool_component.guid,
            CWE_TAXONOMY_GUID
        );
    }

    #[test]
    fn every_result_rule_id_resolves_in_the_driver_rules_catalog() {
        let mut r = minimal_report();
        r.findings = vec![
            ranked(
                finding(|f| f.vuln_class = VulnClass::Injection),
                Severity::High,
            ),
            ranked(
                finding(|f| f.vuln_class = VulnClass::UseAfterFree),
                Severity::Critical,
            ),
        ];
        let doc = build_sarif(&r, "1.0.0");
        let run = &doc.runs[0];
        let rule_ids: Vec<&str> = run
            .tool
            .driver
            .rules
            .iter()
            .map(|r| r.id.as_str())
            .collect();
        for result in &run.results {
            assert!(rule_ids.contains(&result.rule_id.as_str()));
        }
    }

    #[test]
    fn results_preserve_findings_order_unsorted() {
        let mut r = minimal_report();
        r.findings = vec![
            ranked(
                finding(|f| f.title = "Z finding".to_string()),
                Severity::Low,
            ),
            ranked(
                finding(|f| f.title = "A finding".to_string()),
                Severity::Critical,
            ),
        ];
        let doc = build_sarif(&r, "1.0.0");
        let titles: Vec<&str> = doc.runs[0]
            .results
            .iter()
            .map(|res| res.message.text.as_str())
            .collect();
        assert_eq!(titles, vec!["Z finding", "A finding"]);
    }

    #[test]
    fn result_locations_and_related_locations_wired_through() {
        let mut r = minimal_report();
        r.findings = vec![ranked(
            finding(|f| {
                f.file = "app.py".to_string();
                f.line_start = 5;
                f.line_end = 8;
                f.duplicates = vec![DupLocation {
                    file: "b.py".to_string(),
                    line_start: 10,
                    line_end: 20,
                    vuln_class: VulnClass::Injection,
                    title: String::new(),
                    chunk_id: String::new(),
                    source_ref: None,
                    sink_ref: None,
                    reasoning: String::new(),
                }];
            }),
            Severity::High,
        )];
        let doc = build_sarif(&r, "1.0.0");
        let result = &doc.runs[0].results[0];
        assert_eq!(
            result.locations[0].physical_location.artifact_location.uri,
            "app.py"
        );
        assert_eq!(result.locations[0].physical_location.region.start_line, 5);
        assert_eq!(
            result.locations[0].physical_location.region.end_line,
            Some(8)
        );
        assert_eq!(result.related_locations.len(), 1);
        assert_eq!(result.properties.dedup_related_location_count, Some(1));
    }

    #[test]
    fn invocation_and_run_properties_reflect_degraded_state() {
        let mut r = minimal_report();
        r.degraded = true;
        r.metrics = Some(ScanMetrics {
            chunks_failed: 1,
            ..Default::default()
        });
        let doc = build_sarif(&r, "1.0.0");
        let run = &doc.runs[0];
        assert!(!run.invocations.as_ref().unwrap()[0].execution_successful);
        assert!(run.properties.scan_degraded);
        assert!(run.properties.unranked_fallback);
    }

    #[test]
    fn empty_report_round_trips_through_serde_json() {
        let doc = build_sarif(&minimal_report(), "1.0.0");
        let json = serde_json::to_string(&doc).unwrap();
        let back: SarifDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, back);
    }

    #[test]
    fn populated_report_round_trips_through_serde_json() {
        let mut r = minimal_report();
        r.app_profile = Some(appsec_model::AppProfile {
            exposure: String::new(),
            reaches: Vec::new(),
            reached_by: Vec::new(),
            application_id: "APP1".to_string(),
            name: "App".to_string(),
            externally_facing: true,
            pci_scoped: true,
            processes_pan: false,
            pii: false,
            source: "cmdb".to_string(),
        });
        r.findings = vec![ranked(
            finding(|f| {
                f.cvss_score = Some(9.8);
                f.cvss_vector = Some("CVSS:3.1/AV:N".to_string());
                f.cvss_rating = Some("Critical".to_string());
            }),
            Severity::Critical,
        )];
        let doc = build_sarif(&r, "1.0.0");
        let json = serde_json::to_string(&doc).unwrap();
        let back: SarifDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(doc, back);
    }
}
