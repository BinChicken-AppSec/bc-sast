use super::*;
pub(super) fn app_profile_and_info(
    input: &ScanInput,
) -> Result<(Option<AppProfile>, Option<appsec_enrich::AppInfo>), StageError> {
    resolve_app_profile(
        input.application_id.as_deref(),
        input.cmdb_path.as_deref(),
        input.context_dir.as_deref(),
        &input.repo_root,
    )
    .map_err(|e| StageError::new("context", e))
}

pub(super) fn resolve_app_profile(
    application_id: Option<&str>,
    cmdb_path: Option<&Path>,
    context_dir: Option<&Path>,
    input_root: &Path,
) -> Result<(Option<AppProfile>, Option<appsec_enrich::AppInfo>), String> {
    if let (Some(p), Some(i)) = resolve_from_cmdb(application_id, cmdb_path) {
        return Ok((Some(p), Some(i)));
    }
    let Some(dir) = context_dir else {
        return Ok((None, None));
    };
    match appsec_context::load(dir, input_root, &|k| std::env::var(k).ok()) {
        Ok(None) => Ok((None, None)),
        Ok(Some(c)) => Ok((Some(c.profile), Some(c.app))),
        Err(e) => Err(format!("deployment context: {e}")),
    }
}

fn resolve_from_cmdb(
    application_id: Option<&str>,
    cmdb_path: Option<&Path>,
) -> (Option<AppProfile>, Option<appsec_enrich::AppInfo>) {
    let (Some(app_id), Some(cmdb_path)) = (application_id, cmdb_path) else {
        return (None, None);
    };
    if app_id.is_empty() {
        return (None, None);
    }
    let Ok(cmdb) = appsec_enrich::load_cmdb_csv(cmdb_path) else {
        return (None, None);
    };
    let Some(info) = appsec_enrich::lookup_app(app_id, &cmdb) else {
        return (None, None);
    };
    let profile = AppProfile {
        exposure: String::new(),
        reaches: Vec::new(),
        reached_by: Vec::new(),
        application_id: app_id.to_string(),
        name: info.name.clone(),
        externally_facing: info.externally_facing,
        pci_scoped: info.pci_scoped,
        processes_pan: info.processes_pan,
        pii: info.pii,
        source: info.source.clone(),
    };
    (Some(profile), Some(info))
}

pub(super) struct LoadedProviderFindings {
    pub(super) findings: Vec<Finding>,
    pub(super) ingestion: Vec<appsec_model::ProviderIngestionRecord>,
    pub(super) digest: appsec_model::ProviderDigest,
}

impl std::ops::Deref for LoadedProviderFindings {
    type Target = [Finding];
    fn deref(&self) -> &Self::Target {
        &self.findings
    }
}

pub(super) async fn load_third_party_findings(input: &ScanInput) -> LoadedProviderFindings {
    let mut findings = Vec::new();
    let mut ingestion = Vec::new();
    ingestion.extend(load_vendor_findings(
        &input.checkmarx_xml,
        appsec_thirdparty::checkmarx::parse,
        "checkmarx",
        &mut findings,
    ));
    ingestion.extend(load_vendor_findings(
        &input.snyk_json,
        appsec_thirdparty::snyk::parse,
        "snyk",
        &mut findings,
    ));
    ingestion.extend(load_vendor_findings(
        &input.semgrep_json,
        appsec_thirdparty::semgrep::parse,
        "semgrep",
        &mut findings,
    ));
    ingestion.extend(load_vendor_findings(
        &input.aikido_json,
        appsec_thirdparty::aikido::parse,
        "aikido",
        &mut findings,
    ));
    ingestion.extend(load_vendor_findings(
        &input.sonatype_json,
        appsec_thirdparty::sonatype::parse,
        "sonatype",
        &mut findings,
    ));

    if let Some(config) = &input.semgrep_live {
        let client =
            appsec_thirdparty_api::semgrep::SemgrepClient::new(live_http_client(), config.clone());
        let result = client.fetch_findings().await.map_err(|e| e.to_string());
        ingestion.push(push_live_findings(result, "semgrep-live", &mut findings));
    }
    if let Some(config) = &input.snyk_live {
        let client =
            appsec_thirdparty_api::snyk::SnykClient::new(live_http_client(), config.clone());
        let result = client.fetch_findings().await.map_err(|e| e.to_string());
        ingestion.push(push_live_findings(result, "snyk-live", &mut findings));
    }
    if let Some(config) = &input.sonatype_live {
        let client = appsec_thirdparty_api::sonatype::SonatypeClient::new(
            live_http_client(),
            config.clone(),
        );
        let result = client.fetch_findings().await.map_err(|e| e.to_string());
        ingestion.push(push_live_findings(result, "sonatype-live", &mut findings));
    }
    if let Some(config) = &input.aikido_live {
        let client =
            appsec_thirdparty_api::aikido::AikidoClient::new(live_http_client(), config.clone());
        let result = client.fetch_findings().await.map_err(|e| e.to_string());
        ingestion.push(push_live_findings(result, "aikido-live", &mut findings));
    }
    if let Some(config) = &input.checkmarx_live {
        let client = appsec_thirdparty_api::checkmarx::CheckmarxClient::new(
            live_http_client(),
            config.clone(),
        );
        let result = client.fetch_findings().await.map_err(|e| e.to_string());
        ingestion.push(push_live_findings(result, "checkmarx-live", &mut findings));
    }

    let digest = appsec_model::ProviderDigest::of(&findings);
    LoadedProviderFindings {
        findings,
        ingestion,
        digest,
    }
}

pub(super) struct Gathered {
    pub(super) app_profile: Option<AppProfile>,
    pub(super) app_info: Option<appsec_enrich::AppInfo>,
    pub(super) design_controls: Vec<Control>,
    pub(super) imported: LoadedProviderFindings,
}

pub(super) async fn gather_all(
    llm: &dyn appsec_llm_client::LlmClient,
    input: &mut ScanInput,
) -> Result<Gathered, StageError> {
    let (mut app_profile, app_info) = app_profile_and_info(input)?;
    let mut design_controls = Vec::new();
    gather_typed_context(llm, input, &mut app_profile, &mut design_controls).await;
    let imported = load_third_party_findings(input).await;
    Ok(Gathered {
        app_profile,
        app_info,
        design_controls,
        imported,
    })
}

pub(super) fn attach_gathered_context(ctx: &mut appsec_model::ContextPackage, gathered: &Gathered) {
    ctx.app_profile = gathered.app_profile.clone();
    ctx.design_controls = gathered.design_controls.clone();
    let digest = &gathered.imported.digest;
    ctx.provider_digest = (!digest.is_empty()).then(|| digest.clone());
}

pub(super) fn split_provider_findings_by_diff_scope(
    findings: Vec<Finding>,
    scope: &appsec_model::DiffScope,
) -> (Vec<Finding>, Vec<DroppedFinding>) {
    let mut in_scope = Vec::new();
    let mut retained = Vec::new();
    for finding in findings {
        match scope.refusal(&finding.file) {
            None => in_scope.push(finding),
            Some(reason) => retained.push(DroppedFinding {
                provider_origins: finding.provider_origins,
                verification: None,
                file: finding.file,
                line: finding.line_start,
                vuln_class: finding.vuln_class,
                title: finding.title,
                chunk_id: finding.chunk_id,
                reason: DropReason::OutOfDiffScope,
                detail: reason,
                canonical_idx: None,
            }),
        }
    }
    (in_scope, retained)
}

pub(super) fn document_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("a reqwest client with a timeout and no redirects always builds")
}

pub(super) fn document_name_of(url: &str) -> String {
    url.split(['?', '#'])
        .next()
        .unwrap_or(url)
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("document")
        .to_string()
}

#[async_trait::async_trait]
pub(super) trait DocumentFetch: Send + Sync {
    async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), String>;
}

pub(super) struct HttpFetch(pub(super) reqwest::Client);

fn redacted(e: reqwest::Error) -> String {
    appsec_redact::redact(&e.to_string())
}

#[async_trait::async_trait]
impl DocumentFetch for HttpFetch {
    async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), String> {
        let response = self.0.get(url).send().await.map_err(redacted)?;
        let status = response.status().as_u16();
        let bytes = response.bytes().await.map_err(redacted)?;
        Ok((status, bytes.to_vec()))
    }
}

pub(super) async fn fetch_documents(
    urls: &[String],
) -> (Vec<appsec_context::extract::SourceDocument>, Vec<String>) {
    if urls.is_empty() {
        return (Vec::new(), Vec::new());
    }
    fetch_documents_with(&HttpFetch(document_http_client()), urls).await
}

pub(super) async fn fetch_documents_with(
    fetch: &dyn DocumentFetch,
    urls: &[String],
) -> (Vec<appsec_context::extract::SourceDocument>, Vec<String>) {
    let mut documents = Vec::new();
    let mut problems = Vec::new();
    for url in urls {
        if let Err(e) = appsec_context::supplied::check_url(url) {
            problems.push(e);
            continue;
        }
        let (status, bytes) = match fetch.get(url).await {
            Ok(pair) => pair,
            Err(e) => {
                problems.push(format!("{url}: {e}"));
                continue;
            }
        };
        if !(200..300).contains(&status) {
            problems.push(format!("{url}: HTTP {status}"));
            continue;
        }
        match appsec_context::supplied::decode(&document_name_of(url), &bytes, url) {
            Ok(document) => documents.push(document),
            Err(e) => problems.push(e),
        }
    }
    (documents, problems)
}

pub(super) fn live_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("a plain reqwest client with only a timeout set always builds")
}

pub(super) fn push_live_findings(
    result: Result<Vec<appsec_thirdparty::ThirdPartyFinding>, String>,
    vendor: &str,
    out: &mut Vec<Finding>,
) -> appsec_model::ProviderIngestionRecord {
    let mut record = appsec_model::ProviderIngestionRecord {
        source: vendor.to_string(),
        limitations: vec![
            "Provider-side filtering and skipped items are not exhaustively inventoried".into(),
        ],
        ..Default::default()
    };
    match result {
        Ok(parsed) => {
            record.imported_count = parsed.len();
            record.completed = true;
            tracing::info!("[{vendor}] ingested {} finding(s)", parsed.len());
            out.extend(parsed.iter().map(appsec_thirdparty::to_finding));
        }
        Err(e) => {
            record.limitations.push(format!(
                "Live ingestion failed: {}",
                appsec_redact::redact(&e)
            ));
            tracing::warn!("[{vendor}] failed to fetch live findings; recorded as incomplete");
        }
    }
    record
}

pub(super) const MAX_VENDOR_EXPORT_BYTES: u64 = 256 * 1024 * 1024;

pub(super) fn read_bounded_export(path: &Path, max: u64) -> Result<String, String> {
    use std::io::Read;
    fn message(e: impl std::fmt::Display) -> String {
        e.to_string()
    }
    let too_large = || format!("larger than the {max}-byte limit for a vendor export");
    let file = std::fs::File::open(path).map_err(message)?;
    let len = file.metadata().map_err(message)?.len();
    if len > max {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(message)?;
    if bytes.len() as u64 > max {
        return Err(too_large());
    }
    String::from_utf8(bytes).map_err(message)
}

pub(super) fn load_vendor_findings(
    paths: &[PathBuf],
    parse: fn(&str) -> Result<Vec<appsec_thirdparty::ThirdPartyFinding>, String>,
    vendor: &str,
    out: &mut Vec<Finding>,
) -> Vec<appsec_model::ProviderIngestionRecord> {
    let mut records = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let mut record = appsec_model::ProviderIngestionRecord {
            source: format!("{vendor}-file-{index}"),
            limitations: vec![
                "File export completeness and source revision are not authenticated".into(),
            ],
            ..Default::default()
        };
        let text = match read_bounded_export(path, MAX_VENDOR_EXPORT_BYTES) {
            Ok(text) => text,
            Err(e) => {
                let msg = format!(
                    "[{vendor}] failed to read {} ({e}); skipping",
                    path.display()
                );
                tracing::warn!("{msg}");
                record.limitations.push("Could not read export".into());
                records.push(record);
                continue;
            }
        };
        match parse(&text) {
            Ok(parsed) => {
                record.completed = true;
                record.imported_count = parsed.len();
                let msg = format!(
                    "[{vendor}] ingested {} finding(s) from {}",
                    parsed.len(),
                    path.display()
                );
                tracing::info!("{msg}");
                out.extend(parsed.iter().map(appsec_thirdparty::to_finding));
            }
            Err(e) => {
                record.limitations.push("Could not parse export".into());
                let msg = format!(
                    "[{vendor}] failed to parse {} ({e}); skipping",
                    path.display()
                );
                tracing::warn!("{msg}");
            }
        }
        records.push(record);
    }
    records
}

pub(super) async fn gather_typed_context(
    llm: &dyn appsec_llm_client::LlmClient,
    input: &mut ScanInput,
    profile: &mut Option<AppProfile>,
    controls: &mut Vec<Control>,
) -> Vec<String> {
    let query = search_query_for(input, profile.as_ref());
    let (mut documents, mut problems) = gather_documents(
        input.context_mcp_server.as_deref(),
        &input.context_mcp_spaces,
        &query,
    );
    let (supplied, supplied_problems) = appsec_context::supplied::read_paths(&input.context_files);
    documents.extend(supplied);
    problems.extend(supplied_problems);
    let (fetched, fetch_problems) = fetch_documents(&input.context_urls).await;
    documents.extend(fetched);
    problems.extend(fetch_problems);
    if documents.is_empty() {
        log_context(0, 0, &problems);
        return problems;
    }

    let (extra, admitted) = extract_and_merge(llm, &documents, input, profile, controls).await;
    problems.extend(extra);
    log_context(documents.len(), admitted, &problems);
    problems
}

pub(super) async fn extract_and_merge(
    llm: &dyn appsec_llm_client::LlmClient,
    documents: &[appsec_context::extract::SourceDocument],
    input: &mut ScanInput,
    profile: &mut Option<AppProfile>,
    controls: &mut Vec<Control>,
) -> (Vec<String>, usize) {
    let mut problems = Vec::new();
    let subject = subject_of(input, profile.as_ref());
    let raw = match extraction_call(llm, &subject, documents).await {
        Ok(text) => text,
        Err(e) => {
            problems.push(format!("extracting facts from the documents failed: {e}"));
            return (problems, 0);
        }
    };
    let (facts, rejected) = appsec_context::extract::parse_facts(&raw, documents);
    problems.extend(rejected);

    let admitted = facts.sources.len();
    if !facts.is_empty() {
        let target = profile.get_or_insert_with(|| AppProfile {
            application_id: input.application_id.clone().unwrap_or_default(),
            name: String::new(),
            externally_facing: false,
            pci_scoped: false,
            processes_pan: false,
            pii: false,
            source: "gathered-context".into(),
            exposure: String::new(),
            reaches: Vec::new(),
            reached_by: Vec::new(),
        });
        appsec_context::extract::merge_into(&facts, target);
        controls.extend(facts.controls.iter().cloned());
    }
    (problems, admitted)
}

pub(super) fn subject_of(
    input: &ScanInput,
    profile: Option<&AppProfile>,
) -> appsec_context::extract::Subject {
    appsec_context::extract::Subject {
        repo_name: input.repo_name.clone(),
        application_id: input
            .application_id
            .clone()
            .filter(|id| !id.trim().is_empty()),
        application_name: profile
            .map(|p| p.name.clone())
            .filter(|n| !n.trim().is_empty()),
    }
}

pub(super) fn search_query_for(
    input: &ScanInput,
    profile: Option<&AppProfile>,
) -> appsec_mcp::SearchQuery {
    appsec_mcp::SearchQuery {
        label: input
            .context_mcp_label
            .clone()
            .filter(|l| !l.trim().is_empty()),
        terms: subject_of(input, profile)
            .terms()
            .into_iter()
            .map(str::to_owned)
            .collect(),
    }
}

async fn extraction_call(
    llm: &dyn appsec_llm_client::LlmClient,
    subject: &appsec_context::extract::Subject,
    documents: &[appsec_context::extract::SourceDocument],
) -> Result<String, String> {
    let request = appsec_llm_client::ChatRequest {
        messages: vec![appsec_llm_client::Message::user_text(
            appsec_context::extract::extraction_prompt(subject, documents),
        )],
        system: Some(appsec_context::extract::EXTRACTION_SYSTEM.to_string()),
        ..appsec_llm_client::ChatRequest::default()
    };
    llm.chat(&request)
        .await
        .map(|r| r.text())
        .map_err(|e| e.to_string())
}

pub(super) fn gather_documents(
    server: Option<&Path>,
    spaces: &[String],
    query: &appsec_mcp::SearchQuery,
) -> (Vec<appsec_context::extract::SourceDocument>, Vec<String>) {
    let Some(server) = server else {
        return (Vec::new(), Vec::new());
    };
    if spaces.is_empty() {
        return (
            Vec::new(),
            vec![
                "a context MCP server was configured but no spaces were listed, \
                 so nothing was gathered"
                    .to_string(),
            ],
        );
    }
    let mut session = match appsec_mcp::client::Session::spawn_with_inherited_env(server) {
        Ok(s) => s,
        Err(e) => return (Vec::new(), vec![e]),
    };
    let (gathering, mut problems) = drive(&mut session.client, spaces, query);
    if let Err(e) = session.shutdown() {
        problems.push(e);
    }
    (gathering, problems)
}

pub(super) fn drive<R: std::io::BufRead, W: std::io::Write>(
    client: &mut appsec_mcp::client::Client<R, W>,
    spaces: &[String],
    query: &appsec_mcp::SearchQuery,
) -> (Vec<appsec_context::extract::SourceDocument>, Vec<String>) {
    if let Err(e) = client.initialize() {
        return (
            Vec::new(),
            vec![format!("the context server did not start: {e}")],
        );
    }
    let gathered = appsec_mcp::gather::gather(
        client,
        spaces,
        query,
        &appsec_mcp::gather::Budget::default(),
    );
    let documents = gathered
        .documents
        .iter()
        .map(|d| appsec_context::extract::SourceDocument {
            title: d.doc.title.clone(),
            space: d.doc.space.clone(),
            url: d.url.clone(),
            modified: d.doc.modified.clone(),
            truncated: d.truncated,
            text: d.text.clone(),
        })
        .collect();
    (documents, gathered.problems)
}

pub(super) fn log_context(fetched: usize, admitted: usize, problems: &[String]) {
    for problem in problems {
        tracing::warn!(target: "appsec::context", problem = %problem,
            "gathering deployment context was incomplete");
    }
    if fetched > 0 {
        tracing::info!(target: "appsec::context", fetched, admitted,
            "read deployment documents and admitted typed facts from them");
    }
}
