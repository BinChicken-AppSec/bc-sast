//! A realistic CxSAST 9.5 `CxXMLResults` export, parsed end to end.
//!
//! The expected findings were captured from the importer's previous,
//! hand-written XML reader before it was replaced by `bc-xml`, so this
//! test pins that the switch changed nothing a valid report produces:
//! same findings, same order, same descriptions.

use bc_model::{ProviderKind, ProviderOrigin, ProviderProduct, ProviderSource};
use bc_thirdparty::{checkmarx, Severity, ThirdPartyFinding};

const REPORT: &str = include_str!("fixtures/checkmarx-cxsast-report.xml");

fn expected(
    external_id: &str,
    title: &str,
    file: &str,
    line: i64,
    cwe: &str,
    severity: Severity,
    evidence: &str,
) -> ThirdPartyFinding {
    ThirdPartyFinding {
        provider_origins: vec![ProviderOrigin {
            provider: ProviderKind::Checkmarx,
            source: ProviderSource::File,
            product: ProviderProduct::Sast,
            ..Default::default()
        }],
        vendor: "checkmarx",
        external_id: external_id.to_string(),
        title: title.to_string(),
        file: file.to_string(),
        line_start: line,
        line_end: line,
        cwe: Some(cwe.to_string()),
        severity,
        description: format!(
            "Checkmarx SAST detected a potential {title} at {file}:{line}. {evidence} \
             Classic CxSAST XML exports carry no free-text description \u{2014} verify \
             against the actual source."
        ),
        recommendation: String::new(),
    }
}

#[test]
fn a_realistic_export_produces_the_same_findings_as_before() {
    let findings = checkmarx::parse(REPORT).unwrap();
    let want = vec![
        expected(
            "-1487230613",
            "SQL_Injection",
            "src/payments/repository.py",
            88,
            "CWE-89",
            Severity::High,
            "Data flow: src/payments/views.py:31 (order_id) -> \
             src/payments/repository.py:88 (execute). Status: New.",
        ),
        expected(
            "-339118802",
            "Reflected_XSS",
            "src/web/templates.py",
            54,
            "CWE-79",
            Severity::Medium,
            "Location: src/web/templates.py:54 (Response). Status: Recurrent.",
        ),
        expected(
            "778120014",
            "Use_Of_Hardcoded_Password",
            "config/settings_\u{fc}nicode.py",
            7,
            "CWE-0",
            Severity::Low,
            "Location: config/settings_\u{fc}nicode.py:7 (DB_PASSWORD). Status: New.",
        ),
    ];
    assert_eq!(findings, want);
}

#[test]
fn the_export_still_parses_with_a_byte_order_mark() {
    // .NET writes one by default; the old reader rejected it.
    let with_bom = format!("\u{FEFF}{REPORT}");
    assert_eq!(
        checkmarx::parse(&with_bom).unwrap(),
        checkmarx::parse(REPORT).unwrap()
    );
}
