//! Checkmarx CxSAST classic (on-prem) report ingestion: the
//! `CxXMLResults` XML format (`Query`/`Result`/`Path`, attribute-based
//! schema), not Checkmarx One's newer SARIF/JSON export. Classic XML is
//! the stable, versioned, well-documented format across CxSAST releases;
//! there is no fixed public schema for its CSV UI-table export (columns
//! are user-configurable in the Checkmarx Results Viewer), so XML is the
//! only format this parser targets.
//!
//! Findings marked `FalsePositive="True"` by an operator inside
//! Checkmarx's own UI are skipped: an operator's explicit triage
//! decision shouldn't be silently reintroduced here as a fresh,
//! unreviewed finding.
//!
//! Classic CxSAST XML carries no free-text description field (that's a
//! UI/database-only thing, not part of the report), so `description`
//! below is synthesized from the rule name, the location, the
//! `Result@Status` (`New`/`Recurrent`, i.e. whether this is a regression
//! or a long-standing finding) and, crucially, the **dataflow**.
//!
//! The dataflow lives in `<Path><PathNode>` element *text*
//! (`<FileName>`/`<Line>`/`<Name>`), which the crate's first XML reader
//! discarded outright, so the single most useful piece of evidence
//! Checkmarx supplies, the source-to-sink pair, never reached S6's
//! verifier. It does now; the verifier still re-reads the actual source
//! before judging the claim either way, exactly as it does for every
//! other finding.
//!
//! # Reading the XML
//!
//! A report is untrusted input (anyone who can hand the operator a file,
//! or commit one a CI job picks up, controls it), so it is read with
//! `bc-xml`, the workspace's bounded reader, under `REPORT_LIMITS`.
//! This replaced a private recursive-descent parser that had no depth or
//! size bound: 200,000 nested elements overflowed the stack and aborted
//! the whole scan, and it expanded the input into a `Vec<char>` (four
//! bytes per character) before looking at it. `bc-xml` reads iteratively,
//! refuses any `<!DOCTYPE` (so no external or nested entities), and
//! turns every limit into an ordinary error, which the orchestrator
//! reports as a WARN naming the file and skips like any other malformed
//! export.
//!
//! What the importer sees of the tree is unchanged: elements are matched
//! by their tag as written (CxXML uses no namespaces), attribute values
//! and text have the predefined entities and character references
//! decoded, and an element's text is every text run directly inside it,
//! concatenated and trimmed. `bc-xml` is stricter than the old parser
//! about malformed input (an undefined entity such as `&nbsp;`, a stray
//! `&`, or content after the root element is now an error instead of
//! being passed through or ignored); real CxSAST exports are written by
//! .NET's `XmlWriter`, which never produces any of those. It also reads
//! CDATA sections and a leading byte order mark, which the old parser
//! rejected.

use bc_xml::{Element, ErrorKind, Limits, XmlError};

use crate::{Severity, ThirdPartyFinding};

/// Largest Checkmarx XML report accepted, in bytes (64 MiB).
///
/// Sized from the parsed tree's cost, not the file's: a typical indented
/// CxSAST export (measured on a synthetic 10-node-path report) takes
/// about 36 bytes of memory per input byte once parsed, so 64 MiB peaks
/// at roughly 2.3 GB, while even a very large real scan (tens of
/// thousands of results) stays well under it. Public so a caller that
/// reads the file can refuse an oversize one before reading it all.
pub const MAX_REPORT_BYTES: usize = 64 * 1024 * 1024;

/// Deepest element nesting accepted. A CxXML report nests eight levels
/// (`CxXMLResults/Query/Result/Path/PathNode/Snippet/Line/Code`); the
/// headroom is for fields a future CxSAST release might add.
const MAX_DEPTH: usize = 32;

/// Most nodes (elements, text runs, comments) accepted. A realistic
/// 64 MiB export has about 5.2 million, so this only trips on input that
/// is denser than any real report, where it keeps the tree at a size
/// comparable to the one [`MAX_REPORT_BYTES`] allows.
const MAX_NODES: usize = 10_000_000;

/// The bounds a Checkmarx report is parsed under; `bc-xml`'s defaults for
/// attributes per element and namespaces in scope.
const REPORT_LIMITS: Limits = Limits {
    max_input_bytes: MAX_REPORT_BYTES,
    max_depth: MAX_DEPTH,
    max_nodes: MAX_NODES,
    ..Limits::new(MAX_REPORT_BYTES)
};

pub fn parse(text: &str) -> Result<Vec<ThirdPartyFinding>, String> {
    let document = bc_xml::parse_str(text, &REPORT_LIMITS).map_err(|e| describe_xml_error(&e))?;
    let root = &document.root;
    if !root.name.matches("CxXMLResults") {
        return Err(format!(
            "expected a <CxXMLResults> root element, got <{}>",
            root.name
        ));
    }

    let mut findings = Vec::new();
    for query in children(root, "Query") {
        let cwe = normalize_cwe_id(query.attribute("cweId"));
        let name = query.attribute("name").unwrap_or("Checkmarx finding");
        let query_severity = query.attribute("Severity");

        for result in children(query, "Result") {
            if result
                .attribute("FalsePositive")
                .is_some_and(|v| v.eq_ignore_ascii_case("true"))
            {
                continue;
            }
            let Some(file) = result.attribute("FileName") else {
                continue;
            };
            let line = result
                .attribute("Line")
                .and_then(|l| l.parse::<i64>().ok())
                .unwrap_or(1);
            let severity = parse_severity(result.attribute("Severity").or(query_severity));
            let path = children(result, "Path").next();
            let external_id = path
                .and_then(|p| p.attribute("SimilarityId"))
                .map(str::to_string)
                .or_else(|| result.attribute("NodeId").map(str::to_string))
                .unwrap_or_else(|| format!("{file}:{line}"));

            let mut description =
                format!("Checkmarx SAST detected a potential {name} at {file}:{line}.");
            if let Some(flow) = describe_dataflow(path) {
                description.push_str(&format!(" {flow}"));
            }
            if let Some(status) = result.attribute("Status").filter(|s| !s.trim().is_empty()) {
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

/// Turns a `bc-xml` refusal into the message the orchestrator logs next
/// to the file's path. A limit or a DOCTYPE says which safeguard fired,
/// so an operator with a genuine report knows it was refused on purpose
/// and not because the export is corrupt.
fn describe_xml_error(error: &XmlError) -> String {
    match error.kind {
        ErrorKind::InputTooLarge { .. }
        | ErrorKind::DepthLimitExceeded { .. }
        | ErrorKind::AttributeLimitExceeded { .. }
        | ErrorKind::NodeLimitExceeded { .. }
        | ErrorKind::NamespaceLimitExceeded { .. } => format!(
            "Checkmarx XML report refused by a safety limit: {error} (reports are capped at \
             {} MiB, {MAX_DEPTH} levels of nesting and {MAX_NODES} nodes)",
            MAX_REPORT_BYTES / (1024 * 1024)
        ),
        ErrorKind::DoctypeForbidden => format!(
            "Checkmarx XML report refused: {error} (CxSAST exports have none, and a DOCTYPE \
             can declare external entities)"
        ),
        _ => format!("malformed Checkmarx XML report: {error}"),
    }
}

/// The child elements of `element` whose tag is `tag` as written. CxXML
/// declares no namespaces, so the tag is compared as a plain name, which
/// is what the old reader did too.
fn children<'a>(element: &'a Element, tag: &'a str) -> impl Iterator<Item = &'a Element> {
    element
        .child_elements()
        .filter(move |child| child.name.matches(tag))
}

/// The trimmed text of the first `<tag>` child, or `None` when there is
/// no such child or its text is empty.
fn child_text(element: &Element, tag: &str) -> Option<String> {
    let text = children(element, tag).next()?.text();
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// Renders the first and last `<PathNode>` of a `<Path>` as the taint
/// source and sink. Returns `None` when the result carries no path nodes
/// at all (Checkmarx omits them for some query types) rather than
/// emitting a half-empty "flow".
fn describe_dataflow(path: Option<&Element>) -> Option<String> {
    let nodes: Vec<&Element> = children(path?, "PathNode").collect();
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
fn describe_node(node: &Element) -> Option<String> {
    let file = child_text(node, "FileName")?;
    let line = child_text(node, "Line").unwrap_or_else(|| "?".to_string());
    match child_text(node, "Name") {
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
        let err = parse("not xml").unwrap_err();
        assert!(
            err.starts_with("malformed Checkmarx XML report: line 1, column 1:"),
            "{err}"
        );
    }

    #[test]
    fn deep_nesting_is_an_error_instead_of_a_stack_overflow() {
        // The old recursive reader overflowed the stack on this input and
        // aborted the whole process, not just this import.
        let depth = 200_000;
        let xml = format!(
            "<CxXMLResults>{}{}</CxXMLResults>",
            "<a>".repeat(depth),
            "</a>".repeat(depth)
        );
        let err = parse(&xml).unwrap_err();
        assert!(err.contains("refused by a safety limit"), "{err}");
        assert!(
            err.contains("elements nest deeper than the limit of 32"),
            "{err}"
        );
    }

    #[test]
    fn nesting_up_to_the_depth_limit_is_accepted() {
        let inner = MAX_DEPTH - 1;
        let xml = format!(
            "<CxXMLResults>{}{}</CxXMLResults>",
            "<a>".repeat(inner),
            "</a>".repeat(inner)
        );
        assert!(parse(&xml).unwrap().is_empty());
    }

    #[test]
    fn a_doctype_with_an_external_entity_is_refused() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE CxXMLResults [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<CxXMLResults><Query name="&xxe;"><Result FileName="a.py" Line="1"/></Query></CxXMLResults>"#;
        let err = parse(xml).unwrap_err();
        assert!(
            err.starts_with("Checkmarx XML report refused: line 2, column 1:"),
            "{err}"
        );
        assert!(
            err.contains("DOCTYPE declarations are not accepted"),
            "{err}"
        );
    }

    #[test]
    fn an_oversize_report_is_refused_before_it_is_parsed() {
        // Whitespace, so the only thing that can refuse it is the size
        // check: parsed, it would fail for having no root element instead.
        let xml = " ".repeat(MAX_REPORT_BYTES + 1);
        let err = parse(&xml).unwrap_err();
        assert!(err.contains("refused by a safety limit"), "{err}");
        assert!(
            err.contains("input is 67108865 bytes, over the 67108864-byte limit"),
            "{err}"
        );
        assert!(err.contains("capped at 64 MiB"), "{err}");
    }

    #[test]
    fn an_undefined_entity_is_now_an_error_rather_than_passed_through() {
        let xml = r#"<CxXMLResults><Query name="a&nbsp;b"/></CxXMLResults>"#;
        let err = parse(xml).unwrap_err();
        assert!(err.contains("undefined entity &nbsp;"), "{err}");
    }

    #[test]
    fn a_byte_order_mark_cdata_and_comments_are_read() {
        let xml = "\u{FEFF}<?xml version=\"1.0\" encoding=\"utf-8\"?>\
            <CxXMLResults><Query cweId=\"89\" name=\"X\"><!-- note -->\
            <Result FileName=\"a.py\" Line=\"1\"><Path SimilarityId=\"s1\"><PathNode>\
            <FileName><![CDATA[a<b>.py]]></FileName><Line> 3 <!-- c --></Line>\
            </PathNode></Path></Result></Query></CxXMLResults>";
        let description = &parse(xml).unwrap()[0].description;
        assert!(
            description.contains("Location: a<b>.py:3."),
            "{description}"
        );
    }

    #[test]
    fn a_prefixed_tag_is_not_mistaken_for_the_unprefixed_one() {
        let xml = r#"<CxXMLResults xmlns:x="urn:x"><x:Query name="X">
            <Result FileName="a.py" Line="1"/></x:Query></CxXMLResults>"#;
        assert!(parse(xml).unwrap().is_empty());
        let err = parse(r#"<x:CxXMLResults xmlns:x="urn:x"/>"#).unwrap_err();
        assert!(err.contains("got <x:CxXMLResults>"), "{err}");
    }

    #[test]
    fn no_queries_yields_no_findings() {
        assert!(parse("<CxXMLResults/>").unwrap().is_empty());
    }
}
