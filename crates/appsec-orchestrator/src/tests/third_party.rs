use super::*;
#[tokio::test]
async fn load_third_party_findings_is_empty_when_nothing_is_configured() {
    let input = scan_input(Path::new("/unused"));
    assert!(load_third_party_findings(&input).await.is_empty());
}
#[tokio::test]
async fn load_third_party_findings_ingests_a_checkmarx_xml_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkmarx.xml");
    std::fs::write(
        &path,
        r#"<CxXMLResults><Query cweId="89" name="SQLi"><Result FileName="app.py" Line="1"/></Query></CxXMLResults>"#,
    )
    .unwrap();
    let input = third_party_input(|i| i.checkmarx_xml = vec![path]);
    let findings = load_third_party_findings(&input).await;
    assert_eq!(findings.len(), 1);
    assert!(findings[0].chunk_id.starts_with("external:checkmarx:"));
}
#[tokio::test]
async fn load_third_party_findings_ingests_a_snyk_json_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snyk.json");
    std::fs::write(
        &path,
        r#"{"vulnerabilities": [{"id": "SNYK-1", "packageName": "lodash", "version": "1.0"}]}"#,
    )
    .unwrap();
    let input = third_party_input(|i| i.snyk_json = vec![path]);
    let findings = load_third_party_findings(&input).await;
    assert_eq!(findings.len(), 1);
    assert!(findings[0].chunk_id.starts_with("external:snyk:"));
}
#[tokio::test]
async fn load_third_party_findings_ingests_a_semgrep_json_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("semgrep.json");
    std::fs::write(&path, r#"{"results": [{"check_id": "x", "path": "a.py"}]}"#).unwrap();
    let input = third_party_input(|i| i.semgrep_json = vec![path]);
    let findings = load_third_party_findings(&input).await;
    assert_eq!(findings.len(), 1);
    assert!(findings[0].chunk_id.starts_with("external:semgrep:"));
}
#[tokio::test]
async fn load_third_party_findings_ingests_an_aikido_json_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("aikido.json");
    std::fs::write(&path, r#"[{"id": 1, "rule": "x", "severity": "low"}]"#).unwrap();
    let input = third_party_input(|i| i.aikido_json = vec![path]);
    let findings = load_third_party_findings(&input).await;
    assert_eq!(findings.len(), 1);
    assert!(findings[0].chunk_id.starts_with("external:aikido:"));
}
#[tokio::test]
async fn load_third_party_findings_ingests_a_sonatype_json_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sonatype.json");
    std::fs::write(
        &path,
        r#"{"components": [{"packageUrl": "pkg:npm/x@1", "securityData": {"securityIssues": [{"reference": "CVE-1", "severity": 5.0}]}}]}"#,
    )
    .unwrap();
    let input = third_party_input(|i| i.sonatype_json = vec![path]);
    let findings = load_third_party_findings(&input).await;
    assert_eq!(findings.len(), 1);
    assert!(findings[0].chunk_id.starts_with("external:sonatype:"));
}
#[tokio::test]
async fn load_third_party_findings_combines_multiple_vendors_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let checkmarx_path = dir.path().join("cx.xml");
    std::fs::write(
        &checkmarx_path,
        r#"<CxXMLResults><Query cweId="89" name="SQLi"><Result FileName="app.py" Line="1"/></Query></CxXMLResults>"#,
    )
    .unwrap();
    let snyk_path = dir.path().join("snyk.json");
    std::fs::write(&snyk_path, r#"{"vulnerabilities": [{"id": "S-1"}]}"#).unwrap();
    let mut input = scan_input(Path::new("/unused"));
    input.checkmarx_xml = vec![checkmarx_path];
    input.snyk_json = vec![snyk_path];
    assert_eq!(load_third_party_findings(&input).await.len(), 2);
}
#[cfg(target_os = "linux")]
#[test]
fn read_bounded_export_caps_the_read_when_the_size_check_underreports() {
    let refused = read_bounded_export(std::path::Path::new("/proc/self/status"), 16).unwrap_err();
    assert_eq!(refused, "larger than the 16-byte limit for a vendor export");
}
#[test]
fn read_bounded_export_refuses_a_file_over_the_limit_and_non_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("export.json");
    std::fs::write(&path, "0123456789").unwrap();
    assert_eq!(read_bounded_export(&path, 10).unwrap(), "0123456789");
    let refused = read_bounded_export(&path, 9).unwrap_err();
    assert_eq!(refused, "larger than the 9-byte limit for a vendor export");
    std::fs::write(&path, [0xff, 0xfe]).unwrap();
    assert!(read_bounded_export(&path, 10).is_err());
    let missing = dir.path().join("missing.json");
    assert!(read_bounded_export(&missing, 10).is_err());
}
#[tokio::test]
async fn load_vendor_findings_warns_and_skips_a_nonexistent_file() {
    let input = third_party_input(|i| i.checkmarx_xml = vec![PathBuf::from("/does/not/exist.xml")]);
    let loaded = load_third_party_findings(&input).await;
    assert!(loaded.is_empty());
    assert_eq!(loaded.ingestion.len(), 1);
    assert!(!loaded.ingestion[0].completed);
    assert!(!loaded.ingestion[0].limitations.is_empty());
}
#[tokio::test]
async fn load_vendor_findings_warns_and_skips_a_malformed_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.xml");
    std::fs::write(&path, "not xml at all").unwrap();
    let input = third_party_input(|i| i.checkmarx_xml = vec![path]);
    assert!(load_third_party_findings(&input).await.is_empty());
}

#[tokio::test]
async fn load_third_party_findings_fetches_from_a_configured_live_semgrep_client() {
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "findings": [{
                    "id": 1,
                    "state": "unresolved",
                    "status": "open",
                    "rule": {"name": "x", "message": "m", "cwe_names": []},
                    "severity": "high",
                    "location": {"file_path": "a.py", "line": 1, "end_line": 1}
                }]
            })),
        )
        .mount(&server)
        .await;
    let mut config =
        appsec_thirdparty_api::semgrep::SemgrepConfig::new("tok", "deploy", "org/repo");
    config.base_url = server.uri();
    let input = third_party_input(|i| i.semgrep_live = Some(config));

    let findings = load_third_party_findings(&input).await;

    assert_eq!(findings.len(), 1);
    assert!(findings[0].chunk_id.starts_with("external:semgrep:"));
}
#[tokio::test]
async fn load_third_party_findings_warns_and_skips_a_failed_live_fetch() {
    let mut config =
        appsec_thirdparty_api::semgrep::SemgrepConfig::new("tok", "deploy", "org/repo");
    config.base_url = "http://127.0.0.1:1".to_string();
    let input = third_party_input(|i| i.semgrep_live = Some(config));

    assert!(load_third_party_findings(&input).await.is_empty());
}
#[tokio::test]
async fn load_third_party_findings_warns_and_skips_a_failed_live_snyk_fetch() {
    let mut config = appsec_thirdparty_api::snyk::SnykConfig::new("tok", "org-1", "proj-1");
    config.base_url = "http://127.0.0.1:1".to_string();
    let input = third_party_input(|i| i.snyk_live = Some(config));

    assert!(load_third_party_findings(&input).await.is_empty());
}
#[tokio::test]
async fn load_third_party_findings_warns_and_skips_a_failed_live_sonatype_fetch() {
    let config = appsec_thirdparty_api::sonatype::SonatypeConfig::new(
        "http://127.0.0.1:1",
        "user",
        "pass",
        "my-app",
    );
    let input = third_party_input(|i| i.sonatype_live = Some(config));

    assert!(load_third_party_findings(&input).await.is_empty());
}
#[tokio::test]
async fn load_third_party_findings_warns_and_skips_a_failed_live_aikido_fetch() {
    let mut config = appsec_thirdparty_api::aikido::AikidoConfig::new("id", "secret", 42);
    config.base_url = "http://127.0.0.1:1".to_string();
    let input = third_party_input(|i| i.aikido_live = Some(config));

    assert!(load_third_party_findings(&input).await.is_empty());
}
#[tokio::test]
async fn load_third_party_findings_warns_and_skips_a_failed_live_checkmarx_fetch() {
    let config = appsec_thirdparty_api::checkmarx::CheckmarxConfig::new(
        "http://127.0.0.1:1",
        "http://127.0.0.1:1",
        "acme",
        "key",
        "proj-1",
    );
    let input = third_party_input(|i| i.checkmarx_live = Some(config));

    assert!(load_third_party_findings(&input).await.is_empty());
}

struct PromptCapturingClient {
    inner: Arc<dyn LlmClient>,
    seen: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl LlmClient for PromptCapturingClient {
    async fn chat(&self, request: &ChatRequest) -> Result<ChatResponse, LlmError> {
        let mut text = String::new();
        for message in &request.messages {
            for block in &message.content {
                if let ContentBlock::Text(t) = block {
                    text.push_str(t);
                }
            }
        }
        self.seen.lock().unwrap().push(text);
        self.inner.chat(request).await
    }
}

async fn threat_model_prompt_for(set: impl FnOnce(&mut ScanInput)) -> String {
    let dir = setup_repo();
    let mut input = scan_input(dir.path());
    set(&mut input);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let client = Arc::new(PromptCapturingClient {
        inner: third_party_only_client(),
        seen: seen.clone(),
    });
    run_scan(client, Arc::new(NoTools), input, scan_config(), None)
        .await
        .expect("the scan runs");
    let prompts = seen.lock().unwrap();
    prompts
        .iter()
        .find(|p| p.contains("PRIOR SCANNER FINDINGS"))
        .expect("the threat-model prompt carries the provider section")
        .clone()
}

#[tokio::test]
async fn a_dependency_alert_reaches_the_threat_model_prompt() {
    let dir = tempfile::tempdir().unwrap();
    let export = dir.path().join("snyk.json");
    std::fs::write(
        &export,
        r#"{"vulnerabilities":[{"id":"SNYK-1","packageName":"lodash","version":"4.17.15","title":"Prototype Pollution","severity":"critical"}]}"#,
    )
    .unwrap();
    let prompt = threat_model_prompt_for(|i| i.snyk_json.push(export)).await;
    assert!(prompt.contains("TOTAL: 1 finding(s)"), "{prompt}");
    assert!(
        prompt.contains("[critical] lodash@4.17.15 — Prototype Pollution (snyk)"),
        "the component, not just a count, reaches the threat model: {prompt}"
    );
    assert!(prompt.contains("snyk=1"), "{prompt}");
}

#[tokio::test]
async fn a_sast_finding_reaches_the_threat_model_prompt_as_a_hotspot() {
    let dir = tempfile::tempdir().unwrap();
    let export = dir.path().join("semgrep.json");
    std::fs::write(
        &export,
        r#"{"results":[{"check_id":"rule","path":"src/app.py","start":{"line":1},"end":{"line":1},"extra":{"message":"candidate","severity":"ERROR"}}]}"#,
    )
    .unwrap();
    let prompt = threat_model_prompt_for(|i| i.semgrep_json.push(export)).await;
    assert!(prompt.contains("semgrep=1"), "{prompt}");
    assert!(prompt.contains("sast=1"), "{prompt}");
    assert!(
        prompt.contains("CONCENTRATED IN: src (1)"),
        "the directory the other scanner already flagged is named: {prompt}"
    );
}

#[tokio::test]
async fn a_scan_with_no_vendor_exports_says_so_in_the_threat_model_prompt() {
    let prompt = threat_model_prompt_for(|_| {}).await;
    assert!(
        prompt.contains("no third-party scanner results supplied"),
        "{prompt}"
    );
}
