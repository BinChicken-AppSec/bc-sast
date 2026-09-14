//! Checkmarx CxSAST classic (on-prem) report ingestion — the
//! `CxXMLResults` XML format (`Query`/`Result`/`Path`, attribute-based
//! schema), not Checkmarx One's newer SARIF/JSON export. Classic XML is
//! the stable, versioned, well-documented format across CxSAST releases;
//! there is no fixed public schema for its CSV UI-table export (columns
//! are user-configurable in the Checkmarx Results Viewer), so XML is the
//! only format this parser targets.
//!
//! Findings marked `FalsePositive="True"` by an operator inside
//! Checkmarx's own UI are skipped — an operator's explicit triage
//! decision shouldn't be silently reintroduced here as a fresh,
//! unreviewed finding.
//!
//! Classic CxSAST XML carries no free-text description field (that's a
//! UI/database-only thing, not part of the report) — `description`
//! below is synthesized from the rule name, the location, the
//! `Result@Status` (`New`/`Recurrent`, i.e. whether this is a regression
//! or a long-standing finding) and, crucially, the **dataflow**.
//!
//! The dataflow lives in `<Path><PathNode>` element *text*
//! (`<FileName>`/`<Line>`/`<Name>`), which the crate's own XML reader
//! used to discard outright — so the single most useful piece of
//! evidence Checkmarx supplies, the source→sink pair, never reached S6's
//! verifier. It does now; the verifier still re-reads the actual source
//! before judging the claim either way, exactly as it does for every
//! other finding.

use crate::xml::{self, XmlNode};
use crate::{Severity, ThirdPartyFinding};

pub fn parse(text: &str) -> Result<Vec<ThirdPartyFinding>, String> {
    let root = xml::parse(text)?;
    if root.tag != "CxXMLResults" {
        return Err(format!(
            "expected a <CxXMLResults> root element, got <{}>",
            root.tag
        ));
    }

    let mut findings = Vec::new();
    for query in root.child_elements("Query") {
        let cwe = normalize_cwe_id(query.attr("cweId"));
        let name = query.attr("name").unwrap_or("Checkmarx finding");
        let query_severity = query.attr("Severity");

        for result in query.child_elements("Result") {
            if result
                .attr("FalsePositive")
                .is_some_and(|v| v.eq_ignore_ascii_case("true"))
            {
                continue;
            }
            let Some(file) = result.attr("FileName") else {
                continue;
            };
            let line = result
                .attr("Line")
                .and_then(|l| l.parse::<i64>().ok())
                .unwrap_or(1);
            let severity = parse_severity(result.attr("Severity").or(query_severity));
            let path = result.child_elements("Path").next();
            let external_id = path
                .and_then(|p| p.attr("SimilarityId"))
                .map(str::to_string)
                .or_else(|| result.attr("NodeId").map(str::to_string))
                .unwrap_or_else(|| format!("{file}:{line}"));

            let mut description =
                format!("Checkmarx SAST detected a potential {name} at {file}:{line}.");
            if let Some(flow) = describe_dataflow(path) {
                description.push_str(&format!(" {flow}"));
            }
            if let Some(status) = result.attr("Status").filter(|s| !s.trim().is_empty()) {
                description.push_str(&format!(" Status: {status}."));
            }
            description.push_str(
                " Classic CxSAST XML exports carry no free-text description — \
                 verify against the actual source.",
            );

            findings.push(ThirdPartyFinding {
                provider_origins: vec![bc_model::ProviderOrigin {
                    provider: bc_model::ProviderKind::Checkmarx,
                    source: bc_model::ProviderSource::File,
                    product: bc_model::ProviderProduct::Sast,
                    ..Default::default()
                }],
                vendor: "checkmarx",
                external_id,
                title: name.to_string(),
                file: file.to_string(),
                line_start: line,
                line_end: line,
                cwe: cwe.clone(),
                severity,
                description,
                recommendation: String::new(),
            });
        }
    }
    Ok(findings)
}

/// Renders the first and last `<PathNode>` of a `<Path>` as the taint
/// source and sink. Returns `None` when the result carries no path nodes
/// at all (Checkmarx omits them for some query types) rather than
/// emitting a half-empty "flow".
fn describe_dataflow(path: Option<&XmlNode>) -> Option<String> {
    let nodes: Vec<&XmlNode> = path?.child_elements("PathNode").collect();
    let source = describe_node(nodes.first().copied()?)?;
    // A single-node path is its own source and sink; rendering it once is
    // more honest than pretending there are two ends.
    let sink = describe_node(nodes.last().copied()?)?;
    if source == sink {
        return Some(format!("Location: {source}."));
    }
    Some(format!("Data flow: {source} -> {sink}."))
}

/// `src/app.py:42 (execute)`, with the trailing name omitted when the
/// node has none.
fn describe_node(node: &XmlNode) -> Option<String> {
    let file = node.child_text("FileName")?;
    let line = node.child_text("Line").unwrap_or("?");
    match node.child_text("Name") {
        Some(name) => Some(format!("{file}:{line} ({name})")),
        None => Some(format!("{file}:{line}")),
    }
}

fn normalize_cwe_id(raw: Option<&str>) -> Option<String> {
    let id = raw.map(str::trim).filter(|s| !s.is_empty())?;
    let stripped = id
        .strip_prefix("CWE-")
        .or_else(|| id.strip_prefix("cwe-"))
        .unwrap_or(id);
    Some(format!("CWE-{stripped}"))
}

fn parse_severity(raw: Option<&str>) -> Severity {
    match raw.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_xml() -> &'static str {
        r#"<?xml version="1.0" encoding="UTF-8"?>
        <CxXMLResults ScanId="1">
          <Query id="1" cweId="89" name="SQL_Injection" Severity="High">
            <Result FileName="src/app.py" Line="42" Severity="High" FalsePositive="False" Status="New">
              <Path ResultId="r1" PathId="1" SimilarityId="abc123">
                <PathNode><FileName>src/handler.py</FileName><Line>7</Line><Column>13</Column><NodeId>1</NodeId><Name>request</Name><Type>ParamDecl</Type><Length>7</Length></PathNode>
                <PathNode><FileName>src/app.py</FileName><Line>42</Line><Column>9</Column><NodeId>2</NodeId><Name>execute</Name><Type>MethodInvoke</Type><Length>7</Length></PathNode>
              </Path>
            </Result>
            <Result FileName="src/other.py" Line="7" Severity="Medium" FalsePositive="True">
              <Path ResultId="r2" PathId="1" SimilarityId="def456"/>
            </Result>
          </Query>
          <Query id="2" cweId="79" name="Stored_XSS" Severity="Medium">
            <Result FileName="src/view.py" Line="10" FalsePositive="False"/>
          </Query>
        </CxXMLResults>"#
    }

    #[test]
    fn parses_every_non_false_positive_result_across_queries() {
        let findings = parse(sample_xml()).unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn maps_file_line_cwe_and_severity() {
        let findings = parse(sample_xml()).unwrap();
        let f = &findings[0];
        assert_eq!(f.file, "src/app.py");
        assert_eq!(f.line_start, 42);
        assert_eq!(f.line_end, 42);
        assert_eq!(f.cwe, Some("CWE-89".to_string()));
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.title, "SQL_Injection");
    }

    #[test]
    fn false_positive_results_are_skipped() {
        let findings = parse(sample_xml()).unwrap();
        assert!(!findings.iter().any(|f| f.file == "src/other.py"));
    }

    #[test]
    fn uses_the_path_similarity_id_as_the_external_id() {
        let findings = parse(sample_xml()).unwrap();
        assert_eq!(findings[0].external_id, "abc123");
    }

    #[test]
    fn falls_back_to_file_line_when_no_path_element_is_present() {
        let findings = parse(sample_xml()).unwrap();
        assert_eq!(findings[1].external_id, "src/view.py:10");
    }

    #[test]
    fn result_without_a_severity_falls_back_to_the_query_severity() {
        let findings = parse(sample_xml()).unwrap();
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    #[test]
    fn the_description_carries_the_path_node_dataflow() {
        let findings = parse(sample_xml()).unwrap();
        assert!(findings[0]
            .description
            .contains("Data flow: src/handler.py:7 (request) -> src/app.py:42 (execute)."));
    }

    #[test]
    fn the_description_carries_the_result_status() {
        let findings = parse(sample_xml()).unwrap();
        assert!(findings[0].description.contains("Status: New."));
    }

    #[test]
    fn a_result_with_no_status_attribute_omits_it_from_the_description() {
        let findings = parse(sample_xml()).unwrap();
        assert!(!findings[1].description.contains("Status:"));
    }

    #[test]
    fn a_blank_status_attribute_is_omitted_from_the_description() {
        let xml = r#"<CxXMLResults><Query cweId="89" name="X">
            <Result FileName="a.py" Line="1" Status="  "/></Query></CxXMLResults>"#;
        assert!(!parse(xml).unwrap()[0].description.contains("Status:"));
    }

    #[test]
    fn a_result_with_no_path_omits_the_dataflow() {
        let findings = parse(sample_xml()).unwrap();
        assert!(!findings[1].description.contains("Data flow"));
        assert!(!findings[1].description.contains("Location:"));
    }

    #[test]
    fn a_single_node_path_is_rendered_as_one_location_not_a_flow() {
        let xml = r#"<CxXMLResults><Query cweId="89" name="X">
            <Result FileName="a.py" Line="1">
              <Path SimilarityId="s1">
                <PathNode><FileName>a.py</FileName><Line>1</Line><Name>eval</Name></PathNode>
              </Path>
            </Result></Query></CxXMLResults>"#;
        let findings = parse(xml).unwrap();
        assert!(findings[0].description.contains("Location: a.py:1 (eval)."));
        assert!(!findings[0].description.contains("Data flow"));
    }

    #[test]
    fn a_path_node_with_no_name_is_rendered_without_one() {
        let xml = r#"<CxXMLResults><Query cweId="89" name="X">
            <Result FileName="a.py" Line="1">
              <Path SimilarityId="s1">
                <PathNode><FileName>a.py</FileName><Line>1</Line></PathNode>
                <PathNode><FileName>b.py</FileName><Line>2</Line></PathNode>
              </Path>
            </Result></Query></CxXMLResults>"#;
        let findings = parse(xml).unwrap();
        assert!(findings[0]
            .description
            .contains("Data flow: a.py:1 -> b.py:2."));
    }

    #[test]
    fn a_path_node_with_no_line_renders_an_unknown_line() {
        let xml = r#"<CxXMLResults><Query cweId="89" name="X">
            <Result FileName="a.py" Line="1">
              <Path SimilarityId="s1">
                <PathNode><FileName>a.py</FileName></PathNode>
                <PathNode><FileName>b.py</FileName><Line>2</Line></PathNode>
              </Path>
            </Result></Query></CxXMLResults>"#;
        let findings = parse(xml).unwrap();
        assert!(findings[0].description.contains("a.py:? -> b.py:2."));
    }

    #[test]
    fn a_path_node_with_no_file_name_omits_the_dataflow_entirely() {
        let xml = r#"<CxXMLResults><Query cweId="89" name="X">
            <Result FileName="a.py" Line="1">
              <Path SimilarityId="s1">
                <PathNode><Line>1</Line><Name>n</Name></PathNode>
              </Path>
            </Result></Query></CxXMLResults>"#;
        let findings = parse(xml).unwrap();
        assert!(!findings[0].description.contains("Data flow"));
        assert!(!findings[0].description.contains("Location:"));
    }

    #[test]
    fn an_empty_path_element_omits_the_dataflow() {
        let xml = r#"<CxXMLResults><Query cweId="89" name="X">
            <Result FileName="a.py" Line="1"><Path SimilarityId="s1"></Path></Result>
            </Query></CxXMLResults>"#;
        let findings = parse(xml).unwrap();
        assert!(!findings[0].description.contains("Data flow"));
    }

    #[test]
    fn a_result_missing_filename_is_skipped() {
        let xml =
            r#"<CxXMLResults><Query cweId="89" name="X"><Result Line="1"/></Query></CxXMLResults>"#;
        assert!(parse(xml).unwrap().is_empty());
    }

    #[test]
    fn missing_or_unparseable_line_defaults_to_one() {
        let xml = r#"<CxXMLResults><Query cweId="89" name="X"><Result FileName="a.py" Line="not-a-number"/></Query></CxXMLResults>"#;
        let findings = parse(xml).unwrap();
        assert_eq!(findings[0].line_start, 1);
    }

    #[test]
    fn missing_cwe_id_yields_no_cwe() {
        let xml = r#"<CxXMLResults><Query name="X"><Result FileName="a.py" Line="1"/></Query></CxXMLResults>"#;
        let findings = parse(xml).unwrap();
        assert_eq!(findings[0].cwe, None);
    }

    #[test]
    fn a_cwe_id_already_prefixed_is_not_double_prefixed() {
        let xml = r#"<CxXMLResults><Query cweId="CWE-89" name="X"><Result FileName="a.py" Line="1"/></Query></CxXMLResults>"#;
        let findings = parse(xml).unwrap();
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
    }

    #[test]
    fn unrecognized_severity_falls_back_to_info() {
        let xml = r#"<CxXMLResults><Query cweId="89" name="X"><Result FileName="a.py" Line="1" Severity="Weird"/></Query></CxXMLResults>"#;
        let findings = parse(xml).unwrap();
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn a_wrong_root_element_is_a_hard_error() {
        let err = parse("<NotCheckmarx/>").unwrap_err();
        assert!(err.contains("CxXMLResults"));
    }

    #[test]
    fn malformed_xml_propagates_the_parse_error() {
        assert!(parse("not xml").is_err());
    }

    #[test]
    fn no_queries_yields_no_findings() {
        assert!(parse("<CxXMLResults/>").unwrap().is_empty());
    }
}
