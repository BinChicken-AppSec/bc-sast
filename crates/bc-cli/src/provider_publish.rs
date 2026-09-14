//! Provider publication from compiled automatic policy or an explicit manual operation.
pub mod automatic;
mod automatic_policy;
mod source_binding;
use bc_model::{
    DropReason, ProviderAssessmentRecord, ProviderKind, ProviderOrigin, ProviderProduct,
    ProviderSource, Verdict,
};
use bc_thirdparty_api::publish::{self, ApprovedAction, Auth, PublishClient};
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum Phase {
    #[default]
    Prepare,
    Apply,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum Action {
    #[default]
    FalsePositive,
    Confirmed,
    Note,
}
#[derive(Debug, Clone, Default, Args)]
pub struct ProviderPublishArgs {
    /// Publish one reviewed S9 plan entry without running models or target code.
    #[arg(long)]
    pub publish_provider_plan: Option<PathBuf>,
    /// Zero-based entry in the plan, explicitly selected for review.
    #[arg(long, requires = "publish_provider_plan")]
    pub provider_publish_entry: Option<usize>,
    /// Prepare a provider baseline first; apply only the unchanged reviewed journal.
    #[arg(long, value_enum, default_value = "prepare")]
    pub provider_publish_phase: Phase,
    #[arg(long, value_enum, default_value = "false-positive")]
    pub provider_publish_action: Action,
    /// Bounded human rationale, stored with the decision and sent to the provider.
    #[arg(long)]
    pub provider_publish_reason: Option<String>,
    /// Explicitly attest the selected vendor finding was assessed at this source revision.
    #[arg(long)]
    pub provider_publish_revision: Option<String>,
    /// Optional evidence-backed severity for a confirmed finding, never framework filtering.
    #[arg(long,value_parser=["low","medium","high","critical"])]
    pub provider_publish_severity: Option<String>,
    /// Durable operation journal, outside the untrusted target checkout.
    #[arg(long)]
    pub provider_publish_journal: Option<PathBuf>,
    /// Human reviewed the selected assessment and prepared provider baseline.
    #[arg(long)]
    pub provider_publish_reviewed: bool,
    /// Accept documented provider propagation beyond this branch and future rescans.
    #[arg(long)]
    pub provider_publish_accept_scope: bool,
    /// Accept the residual race with human edits where the API has no conditional write.
    #[arg(long)]
    pub provider_publish_accept_concurrent_edits: bool,
}

impl ProviderPublishArgs {
    pub(crate) fn requires_plan(&self) -> bool {
        self.provider_publish_entry.is_some()
            || self.provider_publish_reason.is_some()
            || self.provider_publish_revision.is_some()
            || self.provider_publish_severity.is_some()
            || self.provider_publish_journal.is_some()
            || self.provider_publish_reviewed
            || self.provider_publish_accept_scope
            || self.provider_publish_accept_concurrent_edits
            || self.provider_publish_phase != Phase::Prepare
            || self.provider_publish_action != Action::FalsePositive
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Request {
    origin: ProviderOrigin,
    endpoint_origin: String,
    assessment: ProviderAssessmentRecord,
    revision: String,
    action: ApprovedAction,
    policy: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct Journal {
    version: u32,
    request: Request,
    baseline: Value,
    status: String,
    result: Value,
}

fn error_message(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn bounded_read(path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| format!("Cannot read publication artifact: {e}"))?
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(error_message)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("Publication artifact exceeds 8 MiB".into());
    }
    Ok(bytes)
}
fn request(args: &ProviderPublishArgs, artifact: &Value) -> Result<Request, String> {
    if artifact["plan"]["schema_version"] != 1 {
        return Err("Unsupported provider plan version".into());
    }
    if artifact["scan"]["full_scan"] != true
        || artifact["scan"]["resumed"] != false
        || artifact["scan"]["analysis_complete"] != true
    {
        return Err(
            "Publication requires a completed full scan with no degraded analysis or resume".into(),
        );
    }
    let revision = args
        .provider_publish_revision
        .as_deref()
        .filter(|r| !r.trim().is_empty())
        .ok_or("Explicit reviewed source revision is required")?;
    if artifact["scan"]["git_sha"].as_str() != Some(revision) {
        return Err("Reviewed source revision does not match scan".into());
    }
    let index = args
        .provider_publish_entry
        .ok_or("Select --provider-publish-entry")?;
    let origin: ProviderOrigin =
        serde_json::from_value(artifact["plan"]["entries"][index]["origin"].clone())
            .map_err(|_| "Selected plan entry has no valid origin")?;
    if origin.source != ProviderSource::Api || origin.product != ProviderProduct::Sast {
        return Err("Publication requires a native API SAST identity".into());
    }
    let assessments: Vec<ProviderAssessmentRecord> =
        serde_json::from_value(artifact["assessments"].clone())
            .map_err(|_| "Provider assessment ledger is missing")?;
    if args.provider_publish_action == Action::FalsePositive
        && assessments.iter().any(|other| {
            shares_scope(&origin, &other.origin)
                && other
                    .verification
                    .as_ref()
                    .is_some_and(|v| v.verdict == Verdict::TruePositive)
        })
    {
        return Err("An affected provider group contains a true positive; false-positive publication is blocked".into());
    }
    let matches: Vec<_> = assessments
        .into_iter()
        .filter(|a| a.origin == origin)
        .collect();
    let assessment = matches
        .first()
        .ok_or("Selected origin was not assessed")?
        .clone();
    if matches.iter().any(|a| a != &assessment) || !assessment.limitations.is_empty() {
        return Err("Conflicting or incomplete assessment".into());
    }
    let evidence = assessment
        .verification
        .as_ref()
        .ok_or("Selected origin was not verified")?;
    if !(0..=10).contains(&evidence.confidence) {
        return Err("Verification confidence is outside its valid range".into());
    }
    if evidence.reason.trim().is_empty() || evidence.reasoning.trim().is_empty() {
        return Err("Verification evidence is incomplete".into());
    }
    let reason = args
        .provider_publish_reason
        .as_deref()
        .filter(|r| !r.trim().is_empty() && r.len() <= 900 && !r.chars().any(char::is_control))
        .ok_or("A human reason of 1 to 900 bytes is required")?;
    if bc_redact::redact(reason) != reason {
        return Err("Publication reason contains sensitive data; use an evidence reference".into());
    }
    let action = match args.provider_publish_action {
        Action::FalsePositive
            if evidence.verdict == Verdict::FalsePositive
                && evidence.confidence >= 9
                && assessment.drop_reason == Some(DropReason::FalsePositive) =>
        {
            ApprovedAction::FalsePositive {
                reason: reason.into(),
            }
        }
        Action::Confirmed
            if evidence.verdict == Verdict::TruePositive
                && evidence.confidence >= 6
                && assessment.drop_reason.is_none() =>
        {
            ApprovedAction::Confirmed {
                reason: reason.into(),
                severity: args.provider_publish_severity.clone(),
            }
        }
        Action::Note
            if evidence.verdict == Verdict::TruePositive
                && evidence.confidence >= 6
                && assessment.drop_reason.is_none() =>
        {
            ApprovedAction::Note {
                reason: reason.into(),
            }
        }
        _ => return Err(
            "Requested action does not match a supported assessment; unresolved findings stay open"
                .into(),
        ),
    };
    if args.provider_publish_severity.is_some() && args.provider_publish_action != Action::Confirmed
    {
        return Err("Severity requires a confirmed assessment".into());
    }
    Ok(Request {
        endpoint_origin: String::new(),
        origin,
        assessment,
        revision: revision.into(),
        action,
        policy: "human-reviewed-v1".into(),
    })
}
fn shares_scope(a: &ProviderOrigin, b: &ProviderOrigin) -> bool {
    fn same(a: &Option<String>, b: &Option<String>) -> bool {
        a.as_ref()
            .zip(b.as_ref())
            .is_some_and(|(a, b)| !a.is_empty() && a == b)
    }
    if a.provider != b.provider {
        return false;
    }
    match a.provider {
        ProviderKind::Semgrep => {
            same(&a.tenant_id, &b.tenant_id)
                && same(&a.native_ids.match_based_id, &b.native_ids.match_based_id)
        }
        ProviderKind::Snyk => {
            same(&a.tenant_id, &b.tenant_id)
                && same(
                    &a.native_ids.asset_finding_id,
                    &b.native_ids.asset_finding_id,
                )
        }
        ProviderKind::Checkmarx => {
            same(&a.tenant_id, &b.tenant_id)
                && (same(&a.native_ids.similarity_id, &b.native_ids.similarity_id)
                    || same(
                        &a.native_ids.attack_vector_id,
                        &b.native_ids.attack_vector_id,
                    ))
        }
        ProviderKind::Aikido => {
            same(&a.repository_id, &b.repository_id)
                && same(&a.native_ids.issue_id, &b.native_ids.issue_id)
        }
        _ => false,
    }
}

fn save(file: &mut File, journal: &Journal) -> Result<(), String> {
    // The prepared snapshot is private, byte-preserving provider evidence.
    // Redacting before comparison can conceal two distinct human edits.
    let data = serde_json::to_vec_pretty(journal).map_err(error_message)?;
    if data.len() > 8 * 1024 * 1024 {
        return Err("Publication journal exceeds 8 MiB".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(error_message)?;
    file.write_all(&data).map_err(error_message)?;
    file.set_len(data.len() as u64).map_err(error_message)?;
    file.sync_all().map_err(error_message)
}
async fn client(cli: &crate::Cli, origin: &ProviderOrigin) -> Result<PublishClient, String> {
    match origin.provider {
        ProviderKind::Semgrep => {
            let c = crate::build_semgrep_live_config(cli)
                .ok_or("Semgrep publishing credentials and repository binding are required")?;
            if origin.tenant_id.as_deref() != Some(&c.deployment_slug)
                || origin.repository_name.as_deref() != Some(&c.repo)
            {
                return Err("Semgrep credential target binding differs from plan".into());
            }
            PublishClient::new(origin.provider, &c.base_url, Auth::Bearer(c.token))
                .map_err(|e| e.message)
        }
        ProviderKind::Snyk => {
            let c = crate::build_snyk_live_config(cli)
                .ok_or("Snyk publishing credentials and project binding are required")?;
            if origin.tenant_id.as_deref() != Some(&c.org_id)
                || origin.project_id.as_deref() != Some(&c.project_id)
            {
                return Err("Snyk credential target binding differs from plan".into());
            }
            PublishClient::new(origin.provider, &c.base_url, Auth::Token(c.token))
                .map_err(|e| e.message)
        }
        ProviderKind::Checkmarx => {
            let c = crate::build_checkmarx_live_config(cli)
                .ok_or("Checkmarx publishing credentials and project binding are required")?;
            if origin.tenant_id.as_deref() != Some(&c.tenant)
                || origin.project_id.as_deref() != Some(&c.project_id)
            {
                return Err("Checkmarx credential target binding differs from plan".into());
            }
            publish::checkmarx_client(c).await.map_err(|e| e.message)
        }
        ProviderKind::Aikido => {
            let c = crate::build_aikido_live_config(cli)
                .ok_or("Aikido publishing credentials and repository binding are required")?;
            if origin.repository_id.as_deref() != Some(c.code_repo_id.to_string().as_str()) {
                return Err("Aikido credential target binding differs from plan".into());
            }
            publish::aikido_client(c).await.map_err(|e| e.message)
        }
        _ => Err("Provider publishing is unsupported".into()),
    }
}

pub async fn run(cli: &crate::Cli) -> Result<String, String> {
    let args = &cli.provider_publish;
    let path = args
        .publish_provider_plan
        .as_ref()
        .ok_or("Provider plan is required")?;
    let artifact: Value =
        serde_json::from_slice(&bounded_read(path)?).map_err(|_| "Malformed provider plan")?;
    let mut approved = request(args, &artifact)?;
    let journal_path = args
        .provider_publish_journal
        .as_ref()
        .ok_or("A durable --provider-publish-journal is required")?;
    if journal_path == path {
        return Err("Journal must differ from source plan".into());
    }
    if args.provider_publish_phase == Phase::Apply
        && !(args.provider_publish_reviewed
            && args.provider_publish_accept_scope
            && args.provider_publish_accept_concurrent_edits)
    {
        return Err("Apply requires explicit human review, scope acceptance, and concurrent-edit risk acceptance".into());
    }
    let journal_path = validate_journal_path(journal_path, crate::repo_path(cli), path)?;
    let client = client(cli, &approved.origin).await?;
    approved.endpoint_origin = client.endpoint_origin();
    execute(&client, args, approved, &journal_path).await
}

fn validate_journal_path(path: &Path, repo: &Path, plan: &Path) -> Result<PathBuf, String> {
    let repo = repo
        .canonicalize()
        .map_err(|_| "Repository path cannot be resolved for journal isolation")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .map_err(|_| "Journal parent must already exist")?;
    if parent.starts_with(&repo) {
        return Err("Publication journal must be outside the untrusted repository".into());
    }
    let path = parent.join(path.file_name().ok_or("Journal filename is required")?);
    if path
        == plan
            .canonicalize()
            .map_err(|_| "Provider plan cannot be resolved")?
    {
        return Err("Journal must differ from source plan".into());
    }
    if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("Journal symlinks are refused".into());
    }
    Ok(path)
}

trait Publisher {
    async fn read(&self, origin: &ProviderOrigin) -> Result<Value, publish::PublishError>;
    async fn write(
        &self,
        origin: &ProviderOrigin,
        action: &ApprovedAction,
        expected: &Value,
    ) -> Result<publish::WriteResult, publish::PublishError>;
}
impl Publisher for PublishClient {
    async fn read(&self, origin: &ProviderOrigin) -> Result<Value, publish::PublishError> {
        publish::read(self, origin).await
    }
    async fn write(
        &self,
        origin: &ProviderOrigin,
        action: &ApprovedAction,
        expected: &Value,
    ) -> Result<publish::WriteResult, publish::PublishError> {
        publish::write(self, origin, action, expected).await
    }
}

// Explicit unlocking also releases a lock briefly inherited by a concurrently
// spawned child process. Closing the parent descriptor alone can leave that
// inherited lock held until the child executes its new program.
struct LockedJournal(File);
impl LockedJournal {
    fn acquire(file: File) -> Result<Self, String> {
        file.try_lock().map_err(|_| "Journal is already locked")?;
        Ok(Self(file))
    }
}
impl std::ops::Deref for LockedJournal {
    type Target = File;
    fn deref(&self) -> &File {
        &self.0
    }
}
impl std::ops::DerefMut for LockedJournal {
    fn deref_mut(&mut self) -> &mut File {
        &mut self.0
    }
}
impl Drop for LockedJournal {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

struct OperationLock {
    file: File,
    path: PathBuf,
}
impl Drop for OperationLock {
    fn drop(&mut self) {
        let _ = self.file.sync_all();
        let _ = std::fs::remove_file(&self.path);
    }
}
fn operation_lock(path: &Path) -> Result<OperationLock, String> {
    let path = path.with_extension("publication-lock");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| "Publication journal is locked or its directory is unavailable")?;
    Ok(OperationLock { file, path })
}

async fn execute(
    client: &impl Publisher,
    args: &ProviderPublishArgs,
    approved: Request,
    path: &Path,
) -> Result<String, String> {
    let _lock = operation_lock(path)?;
    if args.provider_publish_phase == Phase::Prepare {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|_| "Journal already exists or cannot be created")?;
        let mut file = LockedJournal::acquire(file)?;
        let mut journal = Journal {
            version: 1,
            request: approved,
            baseline: Value::Null,
            status: "preparing".into(),
            result: Value::Null,
        };
        save(&mut file, &journal)?;
        let baseline = client
            .read(&journal.request.origin)
            .await
            .map_err(|e| e.message)?;
        check_revision(&baseline, &journal.request.revision)?;
        journal.baseline = baseline;
        journal.status = "prepared".into();
        save(&mut file, &journal)?;
        return Ok(format!(
            "Prepared provider baseline for review: {}",
            path.display()
        ));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(error_message)?;
    if !metadata.is_file() {
        return Err("Journal must be a regular file".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(error_message)?;
    let mut file = LockedJournal::acquire(file)?;
    let mut bytes = Vec::new();
    (&mut *file)
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(error_message)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err("Journal exceeds 8 MiB".into());
    }
    let journal: Journal = serde_json::from_slice(&bytes)
        .map_err(|_| "Invalid journal; reconcile manually before any further write")?;
    if journal.version != 1 || journal.request != approved {
        return Err("Approval differs from prepared journal".into());
    }
    if journal.status != "prepared" {
        return Err(format!(
            "Journal state is {}; operation is never automatically replayed",
            journal.status
        ));
    }
    let mut journal = journal;
    let baseline = client.read(&approved.origin).await.map_err(|e| e.message)?;
    check_revision(&baseline, &approved.revision)?;
    if baseline != journal.baseline {
        journal.status = "conflict".into();
        save(&mut file, &journal)?;
        return Err("Provider baseline changed after preparation; review a new operation".into());
    }
    journal.status = "sending".into();
    save(&mut file, &journal)?;
    match client
        .write(&approved.origin, &approved.action, &baseline)
        .await
    {
        Ok(result) => {
            journal.status = match result.status {
                publish::WriteStatus::Verified => "verified",
                publish::WriteStatus::AwaitingRetest => "awaiting_retest",
                publish::WriteStatus::PendingApproval => "pending_approval",
                publish::WriteStatus::AcceptedUnverified => "accepted_unverified",
            }
            .into();
            journal.result =
                bc_redact::redact_tree(&serde_json::to_value(result).map_err(error_message)?);
            save(&mut file, &journal)?;
            Ok(format!(
                "Provider publication status: {}; journal: {}",
                journal.status,
                path.display()
            ))
        }
        Err(error) => {
            journal.status = if error.uncertain {
                "outcome_unknown"
            } else {
                "failed"
            }
            .into();
            journal.result = json!({"error":error.message});
            save(&mut file, &journal)?;
            Err(format!(
                "Provider publication {}; inspect {} before another operation",
                journal.status,
                path.display()
            ))
        }
    }
}

fn check_revision(baseline: &Value, revision: &str) -> Result<(), String> {
    if baseline["source_revision"]
        .as_str()
        .is_some_and(|actual| actual != revision)
    {
        return Err("Provider source revision differs from reviewed revision".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::VerificationEvidence;
    use std::sync::Mutex;
    struct Fake {
        baseline: Value,
        reads: Mutex<usize>,
        writes: Mutex<usize>,
        read_failure: bool,
        result: Result<publish::WriteStatus, bool>,
    }
    impl Publisher for Fake {
        async fn read(&self, _: &ProviderOrigin) -> Result<Value, publish::PublishError> {
            *self.reads.lock().unwrap() += 1;
            if self.read_failure {
                Err(publish::PublishError::new("provider unavailable"))
            } else {
                Ok(self.baseline.clone())
            }
        }
        async fn write(
            &self,
            _: &ProviderOrigin,
            _: &ApprovedAction,
            _: &Value,
        ) -> Result<publish::WriteResult, publish::PublishError> {
            *self.writes.lock().unwrap() += 1;
            match self.result {
                Ok(status) => Ok(publish::WriteResult {
                    status,
                    response: json!({"ok":true}),
                }),
                Err(uncertain) => Err(publish::PublishError {
                    message: "request failed".into(),
                    uncertain,
                }),
            }
        }
    }
    fn args() -> ProviderPublishArgs {
        ProviderPublishArgs {
            provider_publish_entry: Some(0),
            provider_publish_revision: Some("abc".into()),
            provider_publish_reason: Some(
                "Independent review confirmed the input is bounded".into(),
            ),
            ..Default::default()
        }
    }
    fn artifact() -> Value {
        let origin = ProviderOrigin {
            provider: ProviderKind::Semgrep,
            product: ProviderProduct::Sast,
            source: ProviderSource::Api,
            ..Default::default()
        };
        let record = ProviderAssessmentRecord {
            origin: origin.clone(),
            file: "app.rs".into(),
            line: 1,
            title: "candidate".into(),
            verification: Some(VerificationEvidence {
                verdict: Verdict::FalsePositive,
                confidence: 9,
                reason: "bound checked".into(),
                reasoning: "independent code reference".into(),
                cvss_vector: None,
            }),
            drop_reason: Some(DropReason::FalsePositive),
            limitations: vec![],
        };
        json!({"plan":{"schema_version":1,"entries":[{"origin":origin}]},"assessments":[record],"scan":{"full_scan":true,"resumed":false,"analysis_complete":true,"git_sha":"abc"}})
    }
    #[test]
    fn policy_rejects_unassessed_filtered_failed_and_wrong_revision() {
        let a = args();
        let value = artifact();
        assert!(request(&a, &value).is_ok());
        for path in ["full_scan", "analysis_complete"] {
            let mut v = value.clone();
            v["scan"][path] = json!(false);
            assert!(request(&a, &v).is_err());
        }
        let mut v = value.clone();
        v["scan"]["resumed"] = json!(true);
        assert!(request(&a, &v).is_err());
        let mut v = value.clone();
        v["scan"]["git_sha"] = json!("other");
        assert!(request(&a, &v).is_err());
        let mut v = value.clone();
        v["assessments"][0]["verification"] = Value::Null;
        assert!(request(&a, &v).is_err());
        let mut v = value.clone();
        v["assessments"][0]["verification"]["confidence"] = json!(3);
        assert!(request(&a, &v).is_err());
        let mut v = value.clone();
        v["assessments"][0]["drop_reason"] = json!("EXCLUDED");
        assert!(request(&a, &v).is_err());
        let mut v = value.clone();
        v["assessments"][0]["limitations"] = json!(["failed"]);
        assert!(request(&a, &v).is_err());
        let mut a = args();
        a.provider_publish_reason = None;
        assert!(request(&a, &value).is_err());
        assert!(check_revision(&json!({"source_revision":"other"}), "abc").is_err());
        assert!(check_revision(&json!({"source_revision":"abc"}), "abc").is_ok());
    }
    #[tokio::test]
    async fn journal_requires_prepare_and_no_replay_after_any_send() {
        for result in [
            Ok(publish::WriteStatus::Verified),
            Ok(publish::WriteStatus::AwaitingRetest),
            Ok(publish::WriteStatus::PendingApproval),
            Ok(publish::WriteStatus::AcceptedUnverified),
            Err(true),
            Err(false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("journal.json");
            let mut a = args();
            let req = request(&a, &artifact()).unwrap();
            let fake = Fake {
                baseline: json!({"state":"open"}),
                writes: Mutex::new(0),
                reads: Mutex::new(0),
                read_failure: false,
                result,
            };
            execute(&fake, &a, req.clone(), &path).await.unwrap();
            assert_eq!(*fake.writes.lock().unwrap(), 0);
            assert!(execute(&fake, &a, req.clone(), &path).await.is_err());
            a.provider_publish_phase = Phase::Apply;
            let outcome = execute(&fake, &a, req.clone(), &path).await;
            assert_eq!(outcome.is_ok(), result.is_ok(), "{outcome:?}");
            assert_eq!(*fake.writes.lock().unwrap(), 1, "{outcome:?}");
            assert!(execute(&fake, &a, req, &path)
                .await
                .unwrap_err()
                .contains("never automatically replayed"));
            assert_eq!(*fake.writes.lock().unwrap(), 1);
            let journal: Journal = serde_json::from_slice(&bounded_read(&path).unwrap()).unwrap();
            assert_ne!(journal.status, "sending");
            if let Ok(status) = result {
                assert_eq!(
                    serde_json::to_value(status).unwrap().as_str(),
                    Some(journal.status.as_str())
                );
            }
        }
    }
    #[tokio::test]
    async fn changed_provider_state_or_approval_cannot_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut a = args();
        let req = request(&a, &artifact()).unwrap();
        let mut fake = Fake {
            baseline: json!({"state":"open"}),
            writes: Mutex::new(0),
            reads: Mutex::new(0),
            read_failure: false,
            result: Ok(publish::WriteStatus::Verified),
        };
        execute(&fake, &a, req.clone(), &path).await.unwrap();
        a.provider_publish_phase = Phase::Apply;
        let mut changed = req.clone();
        changed.revision = "different".into();
        assert!(execute(&fake, &a, changed, &path)
            .await
            .unwrap_err()
            .contains("Approval differs"));
        fake.baseline = json!({"state":"human ignored"});
        assert!(execute(&fake, &a, req, &path)
            .await
            .unwrap_err()
            .contains("baseline changed"));
        assert_eq!(*fake.writes.lock().unwrap(), 0);
    }
    #[test]
    fn artifact_reads_are_bounded_and_missing_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("artifact");
        assert!(bounded_read(&path).is_err());
        std::fs::write(&path, vec![b' '; 8 * 1024 * 1024 + 1]).unwrap();
        assert!(bounded_read(&path).is_err());
    }

    #[test]
    fn request_requires_native_identity_complete_evidence_and_an_explicit_bounded_reason() {
        for (pointer, replacement) in [
            ("/plan/schema_version", json!(2)),
            ("/plan/entries/0/origin/source", json!("file")),
            ("/plan/entries/0/origin/product", json!("dependency")),
            ("/assessments", Value::Null),
            ("/assessments", json!([])),
            ("/assessments/0/verification/confidence", json!(-1)),
            ("/assessments/0/verification/confidence", json!(11)),
            ("/assessments/0/verification/reason", json!(" ")),
            ("/assessments/0/verification/reasoning", json!("")),
        ] {
            let mut value = artifact();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(request(&args(), &value).is_err(), "{pointer}");
        }
        let mut a = args();
        a.provider_publish_entry = None;
        assert!(request(&a, &artifact()).is_err());
        a.provider_publish_entry = Some(99);
        assert!(request(&a, &artifact()).is_err());
        a = args();
        for revision in [None, Some(" ".into())] {
            a.provider_publish_revision = revision;
            assert!(request(&a, &artifact()).is_err());
        }
        for reason in [
            None,
            Some(" ".into()),
            Some("x".repeat(901)),
            Some("line\nbreak".into()),
            Some("Credential AKIAIOSFODNN7EXAMPLE".into()),
        ] {
            let mut a = args();
            a.provider_publish_reason = reason;
            assert!(request(&a, &artifact()).is_err());
        }
        let mut value = artifact();
        let mut duplicate = value["assessments"][0].clone();
        duplicate["verification"]["reason"] = json!("conflicting review");
        value["assessments"].as_array_mut().unwrap().push(duplicate);
        assert!(request(&args(), &value)
            .unwrap_err()
            .contains("Conflicting"));
    }

    #[test]
    fn confirmed_and_note_actions_need_a_confirmed_assessment_and_severity_stays_scoped() {
        let mut value = artifact();
        value["assessments"][0]["verification"]["verdict"] = json!("TRUE_POSITIVE");
        value["assessments"][0]["drop_reason"] = Value::Null;
        for action in [Action::Confirmed, Action::Note] {
            let mut a = args();
            a.provider_publish_action = action;
            assert!(request(&a, &value).is_ok());
            value["assessments"][0]["verification"]["confidence"] = json!(5);
            assert!(request(&a, &value).is_err());
            value["assessments"][0]["verification"]["confidence"] = json!(9);
        }
        let mut a = args();
        a.provider_publish_action = Action::Confirmed;
        a.provider_publish_severity = Some("high".into());
        assert!(matches!(
            request(&a, &value).unwrap().action,
            ApprovedAction::Confirmed {
                severity: Some(_),
                ..
            }
        ));
        a.provider_publish_action = Action::Note;
        assert!(request(&a, &value).unwrap_err().contains("Severity"));
        a.provider_publish_action = Action::FalsePositive;
        assert!(request(&a, &artifact()).unwrap_err().contains("Severity"));
    }

    fn scoped_origin(provider: ProviderKind) -> ProviderOrigin {
        ProviderOrigin {
            provider,
            tenant_id: Some("tenant".into()),
            repository_id: Some("repo".into()),
            native_ids: bc_model::ProviderNativeIds {
                issue_id: Some("1".into()),
                match_based_id: Some("match".into()),
                similarity_id: Some("similar".into()),
                attack_vector_id: Some("attack".into()),
                asset_finding_id: Some("asset".into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn provider_scope_identity_is_specific_and_shared_true_positives_block_false_positive_actions()
    {
        for provider in [
            ProviderKind::Semgrep,
            ProviderKind::Snyk,
            ProviderKind::Checkmarx,
            ProviderKind::Aikido,
        ] {
            let origin = scoped_origin(provider);
            assert!(shares_scope(&origin, &origin));
            assert!(!shares_scope(&origin, &ProviderOrigin::default()));
            let mut other = origin.clone();
            other.native_ids = Default::default();
            assert!(!shares_scope(&origin, &other));
        }
        assert!(!shares_scope(
            &ProviderOrigin::default(),
            &ProviderOrigin::default()
        ));
        let mut checkmarx = scoped_origin(ProviderKind::Checkmarx);
        let other = checkmarx.clone();
        checkmarx.native_ids.similarity_id = None;
        assert!(shares_scope(&checkmarx, &other));
        let mut value = artifact();
        let mut origin = scoped_origin(ProviderKind::Semgrep);
        origin.source = ProviderSource::Api;
        origin.product = ProviderProduct::Sast;
        value["plan"]["entries"][0]["origin"] = serde_json::to_value(&origin).unwrap();
        value["assessments"][0]["origin"] = serde_json::to_value(&origin).unwrap();
        let mut positive = value["assessments"][0].clone();
        positive["origin"]["native_ids"]["issue_id"] = json!("2");
        positive["verification"]["verdict"] = json!("TRUE_POSITIVE");
        value["assessments"].as_array_mut().unwrap().push(positive);
        assert!(request(&args(), &value)
            .unwrap_err()
            .contains("contains a true positive"));
    }

    #[test]
    fn journal_paths_must_be_resolvable_external_and_distinct_from_the_plan() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let plan = dir.path().join("plan.json");
        std::fs::write(&plan, "{}").unwrap();
        let external = dir.path().join("journal.json");
        assert_eq!(
            validate_journal_path(&external, &repo, &plan).unwrap(),
            dir.path().canonicalize().unwrap().join("journal.json")
        );
        assert!(validate_journal_path(&repo.join("journal"), &repo, &plan).is_err());
        assert!(validate_journal_path(&plan, &repo, &plan).is_err());
        assert!(validate_journal_path(&dir.path().join("missing/journal"), &repo, &plan).is_err());
        assert!(validate_journal_path(&external, &dir.path().join("missing"), &plan).is_err());
        assert!(validate_journal_path(&external, &repo, &dir.path().join("missing-plan")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn journal_symlink_aliases_cannot_escape_path_policy() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let plan = dir.path().join("plan");
        std::fs::write(&plan, "{}").unwrap();
        symlink(&repo, dir.path().join("alias")).unwrap();
        assert!(validate_journal_path(&dir.path().join("alias/journal"), &repo, &plan).is_err());
        symlink(&plan, dir.path().join("journal")).unwrap();
        assert!(validate_journal_path(&dir.path().join("journal"), &repo, &plan).is_err());
    }

    fn fake() -> Fake {
        Fake {
            baseline: json!({"state":"open"}),
            writes: Mutex::new(0),
            reads: Mutex::new(0),
            read_failure: false,
            result: Ok(publish::WriteStatus::Verified),
        }
    }

    #[tokio::test]
    async fn pending_crash_states_malformed_journals_and_old_versions_never_send() {
        for state in [
            "preparing",
            "sending",
            "outcome_unknown",
            "failed",
            "conflict",
            "pending_approval",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("journal");
            let mut a = args();
            a.provider_publish_phase = Phase::Apply;
            let req = request(&a, &artifact()).unwrap();
            let journal = Journal {
                version: 1,
                request: req.clone(),
                baseline: json!({"state":"open"}),
                status: state.into(),
                result: Value::Null,
            };
            std::fs::write(&path, serde_json::to_vec(&journal).unwrap()).unwrap();
            let fake = fake();
            assert!(execute(&fake, &a, req, &path)
                .await
                .unwrap_err()
                .contains("never automatically replayed"));
            assert_eq!(*fake.writes.lock().unwrap(), 0);
            assert!(!path.with_extension("publication-lock").exists());
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut a = args();
        a.provider_publish_phase = Phase::Apply;
        let req = request(&a, &artifact()).unwrap();
        for contents in ["invalid".to_owned(), " ".repeat(8 * 1024 * 1024 + 1)] {
            std::fs::write(&path, contents).unwrap();
            assert!(execute(&fake(), &a, req.clone(), &path).await.is_err());
        }
        std::fs::remove_file(&path).unwrap();
        let old = Journal {
            version: 99,
            request: req.clone(),
            baseline: Value::Null,
            status: "prepared".into(),
            result: Value::Null,
        };
        std::fs::write(&path, serde_json::to_vec(&old).unwrap()).unwrap();
        assert!(execute(&fake(), &a, req.clone(), &path)
            .await
            .unwrap_err()
            .contains("Approval differs"));
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(execute(&fake(), &a, req, &path)
            .await
            .unwrap_err()
            .contains("regular file"));
    }

    #[tokio::test]
    async fn lock_files_and_advisory_file_locks_prevent_overlapping_operations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut a = args();
        let req = request(&a, &artifact()).unwrap();
        std::fs::write(path.with_extension("publication-lock"), "held").unwrap();
        assert!(execute(&fake(), &a, req.clone(), &path)
            .await
            .unwrap_err()
            .contains("locked"));
        std::fs::remove_file(path.with_extension("publication-lock")).unwrap();
        execute(&fake(), &a, req.clone(), &path).await.unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.try_lock().unwrap();
        a.provider_publish_phase = Phase::Apply;
        assert!(execute(&fake(), &a, req, &path)
            .await
            .unwrap_err()
            .contains("already locked"));
        assert!(!path.with_extension("publication-lock").exists());
    }

    #[tokio::test]
    async fn failed_baseline_read_preserves_nonpublishable_prepare_state_and_apply_is_not_sent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut a = args();
        let req = request(&a, &artifact()).unwrap();
        let provider = Fake {
            read_failure: true,
            ..fake()
        };
        assert!(execute(&provider, &a, req.clone(), &path)
            .await
            .unwrap_err()
            .contains("provider unavailable"));
        let journal: Journal = serde_json::from_slice(&bounded_read(&path).unwrap()).unwrap();
        assert_eq!(journal.status, "preparing");
        std::fs::remove_file(&path).unwrap();
        execute(&fake(), &a, req.clone(), &path).await.unwrap();
        a.provider_publish_phase = Phase::Apply;
        assert!(execute(&provider, &a, req, &path)
            .await
            .unwrap_err()
            .contains("provider unavailable"));
        let journal: Journal = serde_json::from_slice(&bounded_read(&path).unwrap()).unwrap();
        assert_eq!(journal.status, "prepared");
        assert_eq!(*provider.reads.lock().unwrap(), 2);
        assert_eq!(*provider.writes.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn private_baseline_preserves_exact_bytes_for_comparison() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let a = args();
        let req = request(&a, &artifact()).unwrap();
        let fake = Fake {
            baseline: json!({"note":"AKIAIOSFODNN7EXAMPLE"}),
            ..fake()
        };
        execute(&fake, &a, req, &path).await.unwrap();
        let journal: Journal = serde_json::from_slice(&bounded_read(&path).unwrap()).unwrap();
        assert_eq!(journal.baseline, fake.baseline);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[tokio::test]
    async fn credential_binding_and_untrusted_endpoints_fail_before_any_oauth_request() {
        let dir = tempfile::tempdir().unwrap();
        let mut cli = crate::args::test_support::minimal_cli(dir.path());
        for provider in [
            ProviderKind::Semgrep,
            ProviderKind::Snyk,
            ProviderKind::Checkmarx,
            ProviderKind::Aikido,
            ProviderKind::Unknown,
        ] {
            assert!(client(
                &cli,
                &ProviderOrigin {
                    provider,
                    ..Default::default()
                }
            )
            .await
            .is_err());
        }
        cli.semgrep_token = Some("synthetic-token".into());
        cli.semgrep_deployment_slug = Some("deployment".into());
        cli.semgrep_repo = Some("repo".into());
        cli.snyk_token = Some("synthetic-token".into());
        cli.snyk_org_id = Some("org".into());
        cli.snyk_project_id = Some("project".into());
        cli.checkmarx_base_url = Some("https://evil.invalid".into());
        cli.checkmarx_iam_url = Some("https://evil.invalid".into());
        cli.checkmarx_tenant = Some("tenant".into());
        cli.checkmarx_api_key = Some("synthetic-token".into());
        cli.checkmarx_project_id = Some("project".into());
        cli.aikido_client_id = Some("synthetic-id".into());
        cli.aikido_client_secret = Some("synthetic-secret".into());
        cli.aikido_repo_id = Some(12);
        cli.aikido_base_url = Some("https://evil.invalid".into());
        for provider in [
            ProviderKind::Semgrep,
            ProviderKind::Snyk,
            ProviderKind::Checkmarx,
            ProviderKind::Aikido,
        ] {
            assert!(client(
                &cli,
                &ProviderOrigin {
                    provider,
                    ..Default::default()
                }
            )
            .await
            .err()
            .unwrap()
            .contains("binding"));
        }
        let semgrep = ProviderOrigin {
            provider: ProviderKind::Semgrep,
            tenant_id: Some("deployment".into()),
            repository_name: Some("repo".into()),
            ..Default::default()
        };
        let snyk = ProviderOrigin {
            provider: ProviderKind::Snyk,
            tenant_id: Some("org".into()),
            project_id: Some("project".into()),
            ..Default::default()
        };
        // Constructing these bearer/token clients performs no HTTP requests.
        assert!(client(&cli, &semgrep).await.is_ok());
        assert!(client(&cli, &snyk).await.is_ok());
        let bound = client(&cli, &semgrep).await.unwrap();
        let invalid = ProviderOrigin {
            provider: ProviderKind::Semgrep,
            ..Default::default()
        };
        // Exercise the production trait bridge with metadata rejected by the
        // adapter before it can construct an HTTP request.
        assert!(Publisher::read(&bound, &invalid).await.is_err());
        assert!(Publisher::write(
            &bound,
            &invalid,
            &ApprovedAction::FalsePositive {
                reason: "reviewed".into()
            },
            &Value::Null
        )
        .await
        .is_err());
        cli.semgrep_base_url = Some("https://evil.invalid".into());
        cli.snyk_base_url = Some("https://evil.invalid".into());
        for origin in [
            semgrep,
            snyk,
            ProviderOrigin {
                provider: ProviderKind::Checkmarx,
                tenant_id: Some("tenant".into()),
                project_id: Some("project".into()),
                ..Default::default()
            },
            ProviderOrigin {
                provider: ProviderKind::Aikido,
                repository_id: Some("12".into()),
                ..Default::default()
            },
        ] {
            assert!(client(&cli, &origin)
                .await
                .err()
                .unwrap()
                .contains("approved HTTPS"));
        }
    }

    #[tokio::test]
    async fn run_rejects_missing_artifacts_journals_and_each_missing_approval_before_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let mut cli = crate::args::test_support::minimal_cli(&repo);
        assert!(run(&cli).await.unwrap_err().contains("plan is required"));
        let plan = dir.path().join("plan.json");
        cli.provider_publish = args();
        cli.provider_publish.publish_provider_plan = Some(plan.clone());
        std::fs::write(&plan, "malformed").unwrap();
        assert!(run(&cli).await.unwrap_err().contains("Malformed"));
        std::fs::write(&plan, serde_json::to_vec(&artifact()).unwrap()).unwrap();
        assert!(run(&cli).await.unwrap_err().contains("journal"));
        cli.provider_publish.provider_publish_journal = Some(plan.clone());
        assert!(run(&cli).await.unwrap_err().contains("differ"));
        cli.provider_publish.provider_publish_journal = Some(dir.path().join("journal"));
        cli.provider_publish.provider_publish_phase = Phase::Apply;
        for missing in 0..3 {
            cli.provider_publish.provider_publish_reviewed = missing != 0;
            cli.provider_publish.provider_publish_accept_scope = missing != 1;
            cli.provider_publish
                .provider_publish_accept_concurrent_edits = missing != 2;
            assert!(run(&cli)
                .await
                .unwrap_err()
                .contains("explicit human review"));
        }
        cli.provider_publish
            .provider_publish_accept_concurrent_edits = true;
        assert!(run(&cli).await.unwrap_err().contains("credentials"));
        assert!(!dir.path().join("journal").exists());
    }

    #[tokio::test]
    async fn main_rejects_combined_publication_modes_before_loading_providers_or_models() {
        let base = crate::args::test_support::minimal_cli(Path::new("."));
        for mode in 0..12 {
            let mut cli = base.clone();
            cli.provider_publish.publish_provider_plan = Some("unused-plan".into());
            match mode {
                0 => cli.remediate = true,
                1 => cli.remediate_from = Some("report".into()),
                2 => cli.repo_file = Some("repos".into()),
                3 => cli.post_comments_from = Some("report".into()),
                4 => cli.post_fixes_from = Some("report".into()),
                5 => cli.gc = true,
                6 => cli.gc_run = Some("run".into()),
                7 => cli.estimate = true,
                8 => cli.doctor = true,
                9 => cli.setup = true,
                10 => cli.provider_writeback = "plan".into(),
                11 => cli.stop_after = "s8".into(),
                _ => unreachable!(),
            }
            assert!(crate::main_impl(cli)
                .await
                .unwrap_err()
                .contains("separate operation"));
        }
        let summary = crate::ScanSummary {
            provider_publication: Some("prepared; no mutation".into()),
            ..Default::default()
        };
        assert!(summary.to_string().contains("prepared; no mutation"));
    }

    #[test]
    fn saves_truncate_old_bytes_and_read_only_handles_report_write_failures() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        std::fs::write(&path, vec![b'x'; 10000]).unwrap();
        let journal = Journal {
            version: 1,
            request: request(&args(), &artifact()).unwrap(),
            baseline: Value::Null,
            status: "prepared".into(),
            result: Value::Null,
        };
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        save(&mut file, &journal).unwrap();
        drop(file);
        let decoded: Journal = serde_json::from_slice(&bounded_read(&path).unwrap()).unwrap();
        assert_eq!(decoded.status, "prepared");
        let mut read_only = File::open(&path).unwrap();
        assert!(save(&mut read_only, &journal).is_err());
    }

    #[tokio::test]
    async fn publication_flags_without_a_plan_are_rejected_before_scan_dispatch() {
        for flag in 0..10 {
            let mut cli = crate::args::test_support::minimal_cli(Path::new("."));
            match flag {
                0 => cli.provider_publish.provider_publish_phase = Phase::Apply,
                1 => cli.provider_publish.provider_publish_action = Action::Note,
                2 => cli.provider_publish.provider_publish_entry = Some(0),
                3 => cli.provider_publish.provider_publish_reason = Some("reviewed".into()),
                4 => cli.provider_publish.provider_publish_revision = Some("abc".into()),
                5 => cli.provider_publish.provider_publish_severity = Some("high".into()),
                6 => cli.provider_publish.provider_publish_journal = Some("journal".into()),
                7 => cli.provider_publish.provider_publish_reviewed = true,
                8 => cli.provider_publish.provider_publish_accept_scope = true,
                9 => {
                    cli.provider_publish
                        .provider_publish_accept_concurrent_edits = true
                }
                _ => unreachable!(),
            }
            assert!(crate::main_impl(cli)
                .await
                .unwrap_err()
                .contains("publish-provider-plan"));
        }
    }

    #[tokio::test]
    async fn provider_revision_mismatch_prevents_both_preparation_and_apply() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut a = args();
        let req = request(&a, &artifact()).unwrap();
        let mut provider = fake();
        provider.baseline = json!({"source_revision":"wrong"});
        assert!(execute(&provider, &a, req.clone(), &path)
            .await
            .unwrap_err()
            .contains("revision differs"));
        assert_eq!(*provider.writes.lock().unwrap(), 0);
        std::fs::remove_file(&path).unwrap();
        provider.baseline = json!({"source_revision":"abc"});
        execute(&provider, &a, req.clone(), &path).await.unwrap();
        a.provider_publish_phase = Phase::Apply;
        provider.baseline = json!({"source_revision":"changed"});
        assert!(execute(&provider, &a, req, &path)
            .await
            .unwrap_err()
            .contains("revision differs"));
        assert_eq!(*provider.writes.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn parsed_publication_arguments_reach_local_artifact_validation_without_scanning() {
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let plan = dir.path().join("plan.json");
        let cli = crate::Cli::try_parse_from([
            "bc-sast",
            "--repo",
            dir.path().to_str().unwrap(),
            "--publish-provider-plan",
            plan.to_str().unwrap(),
            "--provider-publish-entry",
            "0",
        ])
        .unwrap();
        assert_eq!(cli.provider_publish.provider_publish_phase, Phase::Prepare);
        assert!(crate::main_impl(cli.clone())
            .await
            .unwrap_err()
            .contains("Cannot read publication artifact"));
        std::fs::write(&plan, "not json").unwrap();
        assert!(crate::main_impl(cli)
            .await
            .unwrap_err()
            .contains("Malformed provider plan"));
        assert!(crate::Cli::try_parse_from(["bc-sast", "--provider-publish-entry", "0"]).is_err());
        assert!(crate::Cli::try_parse_from([
            "bc-sast",
            "--publish-provider-plan",
            "plan",
            "--provider-publish-phase",
            "invalid"
        ])
        .is_err());
        assert!(crate::Cli::try_parse_from([
            "bc-sast",
            "--publish-provider-plan",
            "plan",
            "--provider-publish-severity",
            "invalid"
        ])
        .is_err());
    }

    #[test]
    fn explicit_journal_unlock_releases_the_lock_while_a_cloned_descriptor_remains_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let journal = LockedJournal::acquire(file).unwrap();
        // A duplicate descriptor models the shared open-file description held
        // across a concurrent fork, without launching a process or target code.
        let inherited = journal.try_clone().unwrap();
        let competitor = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(competitor.try_lock().is_err());

        drop(journal);

        // Merely closing journal's descriptor would leave the Unix flock held
        // by inherited. The explicit unlock must allow an independent opener.
        competitor
            .try_lock()
            .expect("RAII drop must explicitly release the shared lock");
        assert!(
            inherited.metadata().is_ok(),
            "The cloned descriptor is still open"
        );
        competitor.unlock().unwrap();
        drop(inherited);
    }

    #[test]
    fn ordinary_scan_still_requires_a_gateway_while_publishing_does_not() {
        use clap::{CommandFactory, FromArgMatches};
        // Disable only this parser instance's env fallback. Do not mutate the
        // process environment shared with concurrent credential-related tests.
        let command =
            crate::Cli::command().mut_arg("gateway_base_url", |arg| arg.env(None::<&str>));
        let error = command
            .clone()
            .try_get_matches_from(["bc-sast", "--repo", "."])
            .unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
        assert!(error.to_string().contains("--gateway-base-url"));
        assert!(command
            .clone()
            .try_get_matches_from([
                "bc-sast",
                "--repo",
                ".",
                "--gateway-base-url",
                "http://127.0.0.1:0"
            ])
            .is_ok());
        let matches = command
            .try_get_matches_from([
                "bc-sast",
                "--repo",
                ".",
                "--publish-provider-plan",
                "plan.json",
            ])
            .unwrap();
        let cli = crate::Cli::from_arg_matches(&matches).unwrap();
        assert!(cli.gateway_base_url.is_empty());
        assert_eq!(
            cli.provider_publish.publish_provider_plan,
            Some(PathBuf::from("plan.json"))
        );
    }

    #[tokio::test]
    async fn changed_endpoint_origin_invalidates_prepared_approval_before_provider_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut a = args();
        let mut approved = request(&a, &artifact()).unwrap();
        approved.endpoint_origin = "https://api.snyk.io".into();
        execute(&fake(), &a, approved.clone(), &path).await.unwrap();
        let original = bounded_read(&path).unwrap();

        a.provider_publish_phase = Phase::Apply;
        approved.endpoint_origin = "https://api.eu.snyk.io".into();
        let provider = fake();
        let error = execute(&provider, &a, approved, &path).await.unwrap_err();

        assert!(error.contains("Approval differs"));
        assert_eq!(*provider.reads.lock().unwrap(), 0);
        assert_eq!(*provider.writes.lock().unwrap(), 0);
        assert_eq!(bounded_read(&path).unwrap(), original);
        assert!(!path.with_extension("publication-lock").exists());
    }

    #[test]
    fn oversized_journal_save_preserves_previous_durable_record_and_file_position() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let mut journal = Journal {
            version: 1,
            request: request(&args(), &artifact()).unwrap(),
            baseline: json!({"state":"open"}),
            status: "prepared".into(),
            result: Value::Null,
        };
        save(&mut file, &journal).unwrap();
        let original = bounded_read(&path).unwrap();
        let position = file.stream_position().unwrap();
        journal.baseline = Value::String("x".repeat(8 * 1024 * 1024));

        assert!(save(&mut file, &journal)
            .unwrap_err()
            .contains("exceeds 8 MiB"));

        assert_eq!(file.stream_position().unwrap(), position);
        assert_eq!(bounded_read(&path).unwrap(), original);
        let retained: Journal = serde_json::from_slice(&original).unwrap();
        assert_eq!(retained.status, "prepared");
    }

    #[tokio::test]
    async fn production_run_binds_endpoint_and_journals_preparation_before_local_identity_rejection(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir(&repo).unwrap();
        let plan_path = dir.path().join("plan.json");
        let journal_path = dir.path().join("journal.json");
        let mut value = artifact();
        // The credential configuration matches the selected tenant, but its
        // unsafe native slug is rejected by the adapter before any HTTP call.
        value["plan"]["entries"][0]["origin"]["tenant_id"] = json!("invalid/deployment");
        value["plan"]["entries"][0]["origin"]["repository_name"] = json!("repo");
        value["assessments"][0]["origin"] = value["plan"]["entries"][0]["origin"].clone();
        std::fs::write(&plan_path, serde_json::to_vec(&value).unwrap()).unwrap();
        let mut cli = crate::args::test_support::minimal_cli(&repo);
        cli.provider_publish = args();
        cli.provider_publish.publish_provider_plan = Some(plan_path);
        cli.provider_publish.provider_publish_journal = Some(journal_path.clone());
        cli.semgrep_token = Some("synthetic-token".into());
        cli.semgrep_deployment_slug = Some("invalid/deployment".into());
        cli.semgrep_repo = Some("repo".into());

        assert!(run(&cli)
            .await
            .unwrap_err()
            .contains("invalid Semgrep deployment"));

        let journal: Journal =
            serde_json::from_slice(&bounded_read(&journal_path).unwrap()).unwrap();
        assert_eq!(journal.request.endpoint_origin, "https://semgrep.dev");
        assert_eq!(journal.status, "preparing");
        assert!(journal.baseline.is_null());
        assert!(!journal_path.with_extension("publication-lock").exists());
    }
}
