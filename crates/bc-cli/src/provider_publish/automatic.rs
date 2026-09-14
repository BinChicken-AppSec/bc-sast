//! Full-scan publication driven by a compiled policy, without interactive approval.
use super::{
    automatic_policy, client, error_message, operation_lock, save, Journal, LockedJournal,
    Publisher, Request,
};
use bc_model::{FinalReport, ProviderOrigin};
use bc_thirdparty_api::publish::{ApprovedAction, PublishClient, WriteStatus};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const POLICY: &str = "automatic-native-scope-v1";

pub struct Run {
    cli: crate::Cli,
    state: PathBuf,
    source: super::source_binding::SourceBinding,
}

/// Configuration authorizes the batch once. Model output cannot select endpoints,
/// commands, credentials, policy versions, or journal locations.
pub fn configure(cli: &crate::Cli) -> Result<Option<Run>, String> {
    if cli.provider_writeback != "apply" {
        return Ok(None);
    }
    let state = bc_checkpoint::default_db_path()
        .map_err(error_message)?
        .with_file_name("provider-publications");
    configure_at(cli, state)
}

pub(crate) fn configure_at(cli: &crate::Cli, state: PathBuf) -> Result<Option<Run>, String> {
    if cli.provider_writeback != "apply" {
        return Ok(None);
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&state).map_err(error_message)?;
    let state = state.canonicalize().map_err(error_message)?;
    let repo = crate::repo_path(cli)
        .canonicalize()
        .map_err(error_message)?;
    if state.starts_with(repo) {
        return Err("Automatic provider state must be outside the untrusted repository".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(&state)
            .map_err(error_message)?
            .permissions()
            .mode()
            & 0o022
            != 0
        {
            return Err("Automatic provider state must not be writable by other users".into());
        }
    }
    let source = super::source_binding::capture(cli)?;
    Ok(Some(Run {
        cli: cli.clone(),
        state,
        source,
    }))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Entry {
    origin: ProviderOrigin,
    action: Option<ApprovedAction>,
    operation_id: Option<String>,
    status: String,
    reason: String,
    mutation_scope: String,
    scope_limitations: Vec<String>,
}
#[derive(Serialize, Deserialize)]
struct Receipt {
    schema_version: u32,
    policy_version: String,
    scan_revision: Option<String>,
    analysis_complete: bool,
    ingestion: Vec<bc_model::ProviderIngestionRecord>,
    limitations: Vec<String>,
    complete: bool,
    entries: Vec<Entry>,
}

trait Clients {
    type Client: Publisher;
    async fn connect(
        &mut self,
        origin: &ProviderOrigin,
    ) -> Result<(String, Arc<Self::Client>), String>;
}
struct NativeClients<'a> {
    cli: &'a crate::Cli,
    cache: BTreeMap<String, Result<Arc<PublishClient>, String>>,
}
impl Clients for NativeClients<'_> {
    type Client = PublishClient;
    async fn connect(
        &mut self,
        origin: &ProviderOrigin,
    ) -> Result<(String, Arc<PublishClient>), String> {
        let key = json!([
            origin.provider,
            origin.tenant_id,
            origin.project_id,
            origin.repository_id,
            origin.repository_name
        ])
        .to_string();
        if !self.cache.contains_key(&key) {
            self.cache
                .insert(key.clone(), client(self.cli, origin).await.map(Arc::new));
        }
        let client = self.cache[&key].clone()?;
        Ok((client.endpoint_origin(), client))
    }
}
impl Run {
    pub async fn publish(
        &self,
        report: &FinalReport,
        results_path: &Path,
    ) -> Result<String, String> {
        if let Err(reason) = self.source.verify(report) {
            let receipt = Receipt {
                schema_version: 1,
                policy_version: POLICY.into(),
                scan_revision: report.git_sha.clone(),
                analysis_complete: false,
                ingestion: report.provider_ledger.ingestion.clone(),
                limitations: vec![reason.clone()],
                complete: true,
                entries: report
                    .provider_ledger
                    .assessments
                    .iter()
                    .map(|record| Entry {
                        origin: record.origin.clone(),
                        action: None,
                        operation_id: None,
                        status: "blocked".into(),
                        reason: reason.clone(),
                        mutation_scope: automatic_policy::scope_description(record.origin.provider)
                            .into(),
                        scope_limitations: Vec::new(),
                    })
                    .collect(),
            };
            write_receipt(results_path, &receipt)?;
            return Err(reason);
        }
        let mut clients = NativeClients {
            cli: &self.cli,
            cache: BTreeMap::new(),
        };
        batch(&mut clients, report, &self.state, results_path).await
    }
}

fn write_receipt(path: &Path, receipt: &Receipt) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(error_message)?;
    let value = bc_redact::redact_tree(&serde_json::to_value(receipt).map_err(error_message)?);
    file.write_all(&serde_json::to_vec_pretty(&value).map_err(error_message)?)
        .map_err(error_message)?;
    file.as_file().sync_all().map_err(error_message)?;
    file.persist(path).map_err(error_message)?;
    Ok(())
}

async fn batch(
    clients: &mut impl Clients,
    report: &FinalReport,
    state: &Path,
    results_path: &Path,
) -> Result<String, String> {
    let mut receipt = Receipt {
        schema_version: 1,
        policy_version: POLICY.into(),
        scan_revision: report.git_sha.clone(),
        analysis_complete: report.provider_ledger.analysis_complete && !report.degraded,
        ingestion: report.provider_ledger.ingestion.clone(),
        limitations: if report.degraded || !report.provider_ledger.analysis_complete {
            vec!["Scan analysis was incomplete; provider findings remain unchanged".into()]
        } else {
            Vec::new()
        },
        complete: false,
        entries: Vec::new(),
    };
    // Check artifact storage before sending anything and checkpoint each outcome.
    write_receipt(results_path, &receipt)?;
    let mut records: Vec<_> = report.provider_ledger.assessments.iter().collect();
    records.sort_by(|a, b| a.origin.cmp(&b.origin));
    records.dedup_by(|a, b| a.origin == b.origin);
    let mut processed: BTreeMap<String, Entry> = BTreeMap::new();
    for record in records {
        let mut entry = Entry {
            origin: record.origin.clone(),
            action: None,
            operation_id: None,
            status: "blocked".into(),
            reason: String::new(),
            mutation_scope: automatic_policy::scope_description(record.origin.provider).into(),
            scope_limitations: Vec::new(),
        };
        match automatic_policy::select(report, record) {
            Err(reason) => {
                entry.reason = reason;
            }
            Ok(action) => {
                entry.action = Some(action.clone());
                let scope = automatic_policy::scope_key(&record.origin);
                let conflict = report.provider_ledger.assessments.iter().any(|other| {
                    automatic_policy::scope_key(&other.origin) == scope
                        && automatic_policy::select(report, other)
                            .is_ok_and(|other_action| !same_effect(Some(&action), &other_action))
                });
                // Coalesce only compatible actions. A severity or verdict conflict
                // must not disappear merely because another instance ran first.
                if conflict {
                    entry.reason = "Conflicting actions share a native mutation identity".into();
                } else {
                    match processed.entry(scope.clone()) {
                        std::collections::btree_map::Entry::Occupied(previous) => {
                            let previous = previous.get();
                            entry.operation_id = previous.operation_id.clone();
                            entry.status = previous.status.clone();
                            entry.reason = format!("Shared native operation: {}", previous.reason);
                            entry.scope_limitations = previous.scope_limitations.clone();
                        }
                        std::collections::btree_map::Entry::Vacant(slot) => {
                            match clients.connect(&record.origin).await {
                                Err(error) => {
                                    entry.status = "failed".into();
                                    entry.reason = error;
                                }
                                Ok((endpoint, client)) => {
                                    let approved = Request {
                                        origin: record.origin.clone(),
                                        endpoint_origin: endpoint.clone(),
                                        assessment: record.clone(),
                                        revision: report.git_sha.clone().unwrap_or_default(),
                                        action,
                                        policy: POLICY.into(),
                                    };
                                    let operation: String = Sha1::digest(
                                        json!([POLICY, endpoint, scope, report.git_sha])
                                            .to_string()
                                            .as_bytes(),
                                    )
                                    .iter()
                                    .map(|byte| format!("{byte:02x}"))
                                    .collect();
                                    entry.operation_id = Some(operation.clone());
                                    let path = state.join(format!("{operation}.json"));
                                    match transact(client.as_ref(), approved, &path).await {
                                        Ok((status, reason, gaps)) => {
                                            entry.status = status;
                                            entry.reason = reason;
                                            entry.scope_limitations = gaps;
                                        }
                                        Err(error) => {
                                            entry.status = "blocked".into();
                                            entry.reason = error;
                                        }
                                    }
                                }
                            }
                            slot.insert(entry.clone());
                        }
                    }
                }
            }
        }
        receipt.entries.push(entry);
        write_receipt(results_path, &receipt)?;
    }
    if receipt
        .ingestion
        .iter()
        .any(|source| !source.completed || !source.limitations.is_empty())
    {
        receipt.limitations.push("Provider ingestion has errors or coverage limitations; absence never implies false positive".into());
    }
    receipt.complete = true;
    write_receipt(results_path, &receipt)?;
    let mut statuses = BTreeMap::<String, usize>::new();
    for entry in &receipt.entries {
        *statuses.entry(entry.status.clone()).or_default() += 1;
    }
    Ok(format!(
        "Provider publication: {}; coverage limitations: {}; results: {}",
        serde_json::to_string(&statuses).map_err(error_message)?,
        receipt.limitations.len(),
        results_path.display()
    ))
}

fn same_effect(previous: Option<&ApprovedAction>, action: &ApprovedAction) -> bool {
    match (previous, action) {
        (Some(ApprovedAction::FalsePositive { .. }), ApprovedAction::FalsePositive { .. })
        | (Some(ApprovedAction::Note { .. }), ApprovedAction::Note { .. }) => true,
        (
            Some(ApprovedAction::Confirmed { severity: a, .. }),
            ApprovedAction::Confirmed { severity: b, .. },
        ) => a == b,
        _ => false,
    }
}

fn read_journal(file: &mut File) -> Result<Journal, String> {
    let mut bytes = Vec::new();
    file.take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(error_message)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("Publication journal exceeds 8 MiB".into());
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| "Malformed publication journal; no mutation replay".into())
}

async fn transact(
    client: &impl Publisher,
    approved: Request,
    path: &Path,
) -> Result<(String, String, Vec<String>), String> {
    let _lock = operation_lock(path)?;
    let existing = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => true,
        Ok(_) => return Err("Publication journal must be a regular file".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error_message(error)),
    };
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(!existing);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = LockedJournal::acquire(options.open(path).map_err(error_message)?)?;
    let mut journal = if existing {
        let previous = read_journal(&mut file)?;
        if previous.version != 1 || previous.request != approved {
            return Err(
                "Existing operation has different assessment or binding; retained without replay"
                    .into(),
            );
        }
        if !["preparing", "prepared"].contains(&previous.status.as_str()) {
            return Ok((
                previous.status,
                "Previously recorded operation; no mutation replay".into(),
                vec!["Provider state was not revalidated during this repeated operation".into()],
            ));
        }
        previous
    } else {
        let journal = Journal {
            version: 1,
            request: approved,
            baseline: Value::Null,
            status: "preparing".into(),
            result: Value::Null,
        };
        save(&mut file, &journal)?;
        journal
    };
    let baseline = match client.read(&journal.request.origin).await {
        Ok(value) => value,
        Err(error) => {
            return Ok((
                "failed".into(),
                error.message,
                vec!["Baseline unavailable; no mutation sent; preparation can retry".into()],
            ))
        }
    };
    super::check_revision(&baseline, &journal.request.revision)?;
    if journal.status == "prepared" && baseline != journal.baseline {
        journal.status = "conflict".into();
        save(&mut file, &journal)?;
        return Ok((
            "conflict".into(),
            "Provider baseline changed before publication".into(),
            Vec::new(),
        ));
    }
    protect_existing_triage(&journal.request, &baseline)?;
    check_ingestion_state(&journal.request, &baseline)?;
    let mut gaps = vec!["Provider-native propagation may affect other branches or projects; those sources were not scanned by this operation".into()];
    if baseline["source_revision"].as_str().is_none() {
        gaps.push("Provider API did not supply a source revision; binding uses configured ingestion identity and the scanned revision".into());
    }
    journal.baseline = baseline;
    journal.status = "sending".into();
    save(&mut file, &journal)?;
    match client
        .write(
            &journal.request.origin,
            &journal.request.action,
            &journal.baseline,
        )
        .await
    {
        Ok(result) => {
            journal.status = match result.status {
                WriteStatus::Verified => "verified",
                WriteStatus::AwaitingRetest => "awaiting_retest",
                WriteStatus::PendingApproval => "pending_approval",
                WriteStatus::AcceptedUnverified => "accepted_unverified",
            }
            .into();
            journal.result =
                bc_redact::redact_tree(&serde_json::to_value(result).map_err(error_message)?);
        }
        Err(error) => {
            journal.status = if error.uncertain {
                "outcome_unknown"
            } else {
                "failed"
            }
            .into();
            journal.result = json!({"error": error.message});
        }
    }
    save(&mut file, &journal)?;
    let reason = journal.result["error"]
        .as_str()
        .unwrap_or("Native API outcome recorded; no automatic mutation retry")
        .to_string();
    Ok((journal.status, reason, gaps))
}

fn protect_existing_triage(request: &Request, baseline: &Value) -> Result<(), String> {
    if !matches!(request.action, ApprovedAction::Confirmed { .. }) {
        return Ok(());
    }
    let protected = match request.origin.provider {
        bc_model::ProviderKind::Checkmarx => baseline["results"].as_array().is_none_or(|rows| {
            rows.is_empty()
                || rows
                    .iter()
                    .any(|row| !matches!(row["state"].as_str(), Some("TO_VERIFY" | "CONFIRMED")))
        }),
        bc_model::ProviderKind::Aikido => baseline["issue"]["status"] != "open",
        _ => false,
    };
    if protected {
        Err(
            "Existing provider triage is protected from automatic confirmation or severity changes"
                .into(),
        )
    } else {
        Ok(())
    }
}

fn check_ingestion_state(request: &Request, baseline: &Value) -> Result<(), String> {
    // Append-only annotations do not reverse an existing decision. Native state
    // changes must not overwrite a state/severity edit made while models scanned.
    if matches!(request.action, ApprovedAction::Note { .. }) {
        return Ok(());
    }
    let origin = &request.origin;
    let (rows, state_field, severity_field): (Vec<&Value>, &str, &str) = match origin.provider {
        bc_model::ProviderKind::Semgrep => (
            baseline["members"]
                .as_array()
                .map(|rs| rs.iter().collect())
                .unwrap_or_default(),
            "triage_state",
            "severity",
        ),
        bc_model::ProviderKind::Checkmarx => (
            baseline["results"]
                .as_array()
                .map(|rs| rs.iter().collect())
                .unwrap_or_default(),
            "state",
            "severity",
        ),
        bc_model::ProviderKind::Aikido => (vec![&baseline["issue"]], "status", "severity"),
        bc_model::ProviderKind::Snyk => (
            vec![&baseline["issue"]["attributes"]],
            "status",
            "effective_severity_level",
        ),
        _ => return Err("Unsupported provider state binding".into()),
    };
    for (expected, field) in [
        (&origin.state, state_field),
        (&origin.severity, severity_field),
    ] {
        if let Some(expected) = expected {
            if rows.is_empty()
                || rows.iter().any(|row| {
                    row[field]
                        .as_str()
                        .is_none_or(|actual| !actual.eq_ignore_ascii_case(expected))
                })
            {
                return Err("Provider state or severity changed since ingestion; automatic mutation refused".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "automatic_tests.rs"]
mod tests;
