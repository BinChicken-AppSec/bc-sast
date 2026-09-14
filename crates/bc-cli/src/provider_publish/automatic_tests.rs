use super::*;
use bc_model::{
    DropReason, ProviderAssessmentRecord, ProviderKind, ProviderNativeIds, ProviderProduct,
    ProviderSource, Verdict, VerificationEvidence,
};
use bc_thirdparty_api::publish::{PublishError, WriteResult};
use std::sync::Mutex;

struct Fake {
    baseline: Mutex<Result<Value, PublishError>>,
    result: Mutex<Result<WriteStatus, bool>>,
    reads: Mutex<usize>,
    writes: Mutex<usize>,
}
impl Fake {
    fn new() -> Self {
        Self {
            baseline: Mutex::new(Ok(json!({"source_revision":"revision","state":"open"}))),
            result: Mutex::new(Ok(WriteStatus::Verified)),
            reads: Mutex::new(0),
            writes: Mutex::new(0),
        }
    }
}
impl Publisher for Fake {
    async fn read(&self, _: &ProviderOrigin) -> Result<Value, PublishError> {
        *self.reads.lock().unwrap() += 1;
        self.baseline.lock().unwrap().clone()
    }
    async fn write(
        &self,
        _: &ProviderOrigin,
        _: &ApprovedAction,
        expected: &Value,
    ) -> Result<WriteResult, PublishError> {
        assert_eq!(expected, self.baseline.lock().unwrap().as_ref().unwrap());
        *self.writes.lock().unwrap() += 1;
        match *self.result.lock().unwrap() {
            Ok(status) => Ok(WriteResult {
                status,
                response: json!({"status":"recorded"}),
            }),
            Err(uncertain) => Err(PublishError {
                message: "injected provider failure".into(),
                uncertain,
            }),
        }
    }
}
struct FakeClients {
    client: Arc<Fake>,
    connects: usize,
    fail: Option<ProviderKind>,
}
impl Clients for FakeClients {
    type Client = Fake;
    async fn connect(&mut self, origin: &ProviderOrigin) -> Result<(String, Arc<Fake>), String> {
        self.connects += 1;
        if self.fail == Some(origin.provider) {
            Err("provider credentials unavailable".into())
        } else {
            Ok(("https://trusted.invalid".into(), self.client.clone()))
        }
    }
}
fn clients() -> FakeClients {
    FakeClients {
        client: Arc::new(Fake::new()),
        connects: 0,
        fail: None,
    }
}
fn clean_git_fixture(repo: &Path) -> String {
    for argv in [
        vec!["init", "-b", "main"],
        vec![
            "-c",
            "user.name=BC Test",
            "-c",
            "user.email=bc-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-m",
            "Synthetic fixture",
        ],
    ] {
        let output = std::process::Command::new("git")
            .current_dir(repo)
            .args(argv)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = std::process::Command::new("git")
        .current_dir(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn record(provider: ProviderKind) -> ProviderAssessmentRecord {
    ProviderAssessmentRecord {
        origin: ProviderOrigin {
            provider,
            product: ProviderProduct::Sast,
            source: ProviderSource::Api,
            tenant_id: Some("tenant".into()),
            project_id: Some("project".into()),
            repository_id: Some("repo".into()),
            repository_name: Some("owner/repo".into()),
            git_ref: Some("refs/heads/main".into()),
            scan_id: Some("scan".into()),
            native_ids: ProviderNativeIds {
                issue_id: Some("1".into()),
                match_based_id: Some("fingerprint".into()),
                similarity_id: Some("similarity".into()),
                asset_finding_id: Some("asset".into()),
                group_id: Some("group".into()),
                ..Default::default()
            },
            ..Default::default()
        },
        file: "app.rs".into(),
        line: 1,
        title: "candidate".into(),
        verification: Some(VerificationEvidence {
            verdict: Verdict::FalsePositive,
            confidence: 9,
            reason: "bound is checked".into(),
            reasoning: "source evidence inspected".into(),
            cvss_vector: None,
        }),
        drop_reason: Some(DropReason::FalsePositive),
        limitations: vec![],
    }
}
fn report(records: Vec<ProviderAssessmentRecord>) -> FinalReport {
    let mut r: FinalReport = serde_json::from_value(
        json!({"repo_root":"/repo","git_sha":"revision","findings":[],"chains":[],"summary":""}),
    )
    .unwrap();
    r.provider_ledger.full_scan = true;
    r.provider_ledger.analysis_complete = true;
    r.provider_ledger.assessments = records;
    r
}
fn request() -> Request {
    let assessment = record(ProviderKind::Semgrep);
    Request {
        origin: assessment.origin.clone(),
        assessment,
        endpoint_origin: "https://trusted.invalid".into(),
        revision: "revision".into(),
        action: ApprovedAction::FalsePositive {
            reason: "checked".into(),
        },
        policy: POLICY.into(),
    }
}
fn journal(path: &Path, status: &str, request: Request, baseline: Value) {
    let j = Journal {
        version: 1,
        request,
        baseline,
        status: status.into(),
        result: Value::Null,
    };
    std::fs::write(path, serde_json::to_vec(&j).unwrap()).unwrap();
}
fn receipt(path: &Path) -> Receipt {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

#[tokio::test]
async fn every_native_outcome_is_durable_and_never_replayed() {
    for (result, status) in [
        (Ok(WriteStatus::Verified), "verified"),
        (Ok(WriteStatus::AwaitingRetest), "awaiting_retest"),
        (Ok(WriteStatus::PendingApproval), "pending_approval"),
        (Ok(WriteStatus::AcceptedUnverified), "accepted_unverified"),
        (Err(false), "failed"),
        (Err(true), "outcome_unknown"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operation.json");
        let fake = Fake::new();
        *fake.result.lock().unwrap() = result;
        let outcome = transact(&fake, request(), &path).await.unwrap();
        assert_eq!(outcome.0, status);
        assert_eq!(*fake.writes.lock().unwrap(), 1);
        let saved: Journal = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved.status, status);
        let repeated = transact(&fake, request(), &path).await.unwrap();
        assert_eq!(repeated.0, status);
        assert!(repeated.1.contains("no mutation replay"));
        assert_eq!(*fake.reads.lock().unwrap(), 1);
        assert_eq!(*fake.writes.lock().unwrap(), 1);
    }
}
#[tokio::test]
async fn preparing_can_retry_baseline_failure_but_sending_cannot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operation.json");
    let fake = Fake::new();
    *fake.baseline.lock().unwrap() = Err(PublishError::new("read unavailable"));
    let failed = transact(&fake, request(), &path).await.unwrap();
    assert_eq!(failed.0, "failed");
    assert!(failed.2.iter().any(|g| g.contains("can retry")));
    assert_eq!(*fake.writes.lock().unwrap(), 0);
    let saved: Journal = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(saved.status, "preparing");
    *fake.baseline.lock().unwrap() = Ok(json!({"state":"open"}));
    let resumed = transact(&fake, request(), &path).await.unwrap();
    assert_eq!(resumed.0, "verified");
    assert!(resumed
        .2
        .iter()
        .any(|g| g.contains("did not supply a source revision")));
    assert_eq!(*fake.writes.lock().unwrap(), 1);
    for status in ["sending", "conflict", "accepted_unverified"] {
        let other = dir.path().join(format!("{status}.json"));
        journal(&other, status, request(), Value::Null);
        assert_eq!(transact(&fake, request(), &other).await.unwrap().0, status);
    }
    assert_eq!(*fake.writes.lock().unwrap(), 1);
}
#[tokio::test]
async fn prepared_baseline_requires_exact_state_and_revision() {
    for variant in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operation.json");
        let fake = Fake::new();
        let baseline = json!({"source_revision":"revision","state":"open"});
        journal(&path, "prepared", request(), baseline);
        if variant == 1 {
            *fake.baseline.lock().unwrap() =
                Ok(json!({"source_revision":"revision","state":"human changed"}));
        }
        if variant == 2 {
            *fake.baseline.lock().unwrap() = Ok(json!({"source_revision":"other"}));
        }
        let result = transact(&fake, request(), &path).await;
        match variant {
            0 => assert_eq!(result.unwrap().0, "verified"),
            1 => assert_eq!(result.unwrap().0, "conflict"),
            _ => assert!(result.unwrap_err().contains("revision differs")),
        }
        assert_eq!(*fake.writes.lock().unwrap(), usize::from(variant == 0));
    }
}
#[tokio::test]
async fn malformed_oversized_and_changed_journals_refuse_without_provider_calls() {
    for variant in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operation.json");
        let fake = Fake::new();
        match variant {
            0 => std::fs::write(&path, b"{truncated").unwrap(),
            1 => std::fs::write(&path, vec![b'x'; 8 * 1024 * 1024 + 1]).unwrap(),
            2 => {
                let mut req = request();
                req.endpoint_origin = "https://other.invalid".into();
                journal(&path, "prepared", req, Value::Null);
            }
            3 => {
                journal(&path, "prepared", request(), Value::Null);
                let mut value: Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                value["version"] = json!(99);
                std::fs::write(&path, value.to_string()).unwrap();
            }
            _ => std::fs::create_dir(&path).unwrap(),
        }
        assert!(transact(&fake, request(), &path).await.is_err());
        assert_eq!(*fake.reads.lock().unwrap(), 0);
        assert_eq!(*fake.writes.lock().unwrap(), 0);
    }
}
#[cfg(unix)]
#[tokio::test]
async fn symlink_and_locked_journals_never_mutate() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.json");
    journal(&target, "prepared", request(), Value::Null);
    let link = dir.path().join("link.json");
    symlink(&target, &link).unwrap();
    let fake = Fake::new();
    assert!(transact(&fake, request(), &link).await.is_err());
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&target)
        .unwrap();
    lock.try_lock().unwrap();
    assert!(transact(&fake, request(), &target).await.is_err());
    File::unlock(&lock).unwrap();
    assert_eq!(*fake.reads.lock().unwrap(), 0);
    assert_eq!(*fake.writes.lock().unwrap(), 0);
}
#[tokio::test]
async fn initial_receipt_failure_prevents_every_provider_call() {
    let dir = tempfile::tempdir().unwrap();
    let mut clients = clients();
    let r = report(vec![record(ProviderKind::Semgrep)]);
    assert!(batch(
        &mut clients,
        &r,
        dir.path(),
        &dir.path().join("missing/results.json")
    )
    .await
    .is_err());
    assert_eq!(clients.connects, 0);
    assert_eq!(*clients.client.writes.lock().unwrap(), 0);
}
#[tokio::test]
async fn grouped_origins_share_one_operation_and_each_receives_a_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("results.json");
    let mut clients = clients();
    let first = record(ProviderKind::Semgrep);
    let mut second = first.clone();
    second.origin.git_ref = Some("refs/heads/develop".into());
    let r = report(vec![first.clone(), second, first]);
    batch(&mut clients, &r, dir.path(), &path).await.unwrap();
    let receipt = receipt(&path);
    assert!(receipt.complete);
    assert_eq!(receipt.entries.len(), 2);
    assert_eq!(clients.connects, 1);
    assert_eq!(*clients.client.writes.lock().unwrap(), 1);
    assert_eq!(
        receipt.entries[0].operation_id,
        receipt.entries[1].operation_id
    );
    assert!(receipt.entries.iter().all(|e| e.status == "verified"));
    assert!(receipt.entries[1]
        .reason
        .contains("Shared native operation"));
}
#[tokio::test]
async fn failed_provider_does_not_stop_other_providers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("results.json");
    let mut clients = clients();
    clients.fail = Some(ProviderKind::Semgrep);
    let r = report(vec![
        record(ProviderKind::Semgrep),
        record(ProviderKind::Checkmarx),
    ]);
    let summary = batch(&mut clients, &r, dir.path(), &path).await.unwrap();
    let result = receipt(&path);
    assert!(summary.contains("failed"));
    assert_eq!(result.entries.len(), 2);
    assert!(result.entries.iter().any(|e| e.status == "failed"));
    assert!(result.entries.iter().any(|e| e.status == "verified"));
    assert_eq!(*clients.client.writes.lock().unwrap(), 1);
}
#[tokio::test]
async fn incomplete_scan_and_unresolved_findings_do_not_connect() {
    for variant in 0..3 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("results.json");
        let mut clients = clients();
        let mut record = record(ProviderKind::Semgrep);
        if variant == 1 {
            record.verification = None;
        }
        if variant == 2 {
            record.drop_reason = Some(DropReason::Excluded);
        }
        let mut r = report(vec![record]);
        if variant == 0 {
            r.degraded = true;
        }
        batch(&mut clients, &r, dir.path(), &path).await.unwrap();
        assert_eq!(clients.connects, 0);
        assert_eq!(receipt(&path).entries[0].status, "blocked");
    }
}
#[test]
fn action_coalescing_requires_compatible_native_effects() {
    let fp = ApprovedAction::FalsePositive {
        reason: "one".into(),
    };
    let fp2 = ApprovedAction::FalsePositive {
        reason: "two".into(),
    };
    let note = ApprovedAction::Note {
        reason: "note".into(),
    };
    let confirmed = ApprovedAction::Confirmed {
        reason: "confirmed".into(),
        severity: Some("high".into()),
    };
    let lower = ApprovedAction::Confirmed {
        reason: "confirmed".into(),
        severity: Some("low".into()),
    };
    assert!(same_effect(Some(&fp), &fp2));
    assert!(same_effect(Some(&note), &note));
    assert!(same_effect(Some(&confirmed), &confirmed));
    assert!(!same_effect(Some(&confirmed), &lower));
    assert!(!same_effect(Some(&fp), &note));
    assert!(!same_effect(None, &note));
}
#[tokio::test]
async fn state_failures_are_recorded_per_entry_and_no_mutation_occurs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("results.json");
    let mut clients = clients();
    let r = report(vec![record(ProviderKind::Semgrep)]);
    batch(&mut clients, &r, &dir.path().join("missing-state"), &path)
        .await
        .unwrap();
    assert_eq!(receipt(&path).entries[0].status, "blocked");
    assert_eq!(*clients.client.writes.lock().unwrap(), 0);
}
#[test]
fn configuration_requires_apply_and_private_state_outside_target() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    clean_git_fixture(&repo);
    let state = dir.path().join("state");
    let mut cli = crate::args::test_support::minimal_cli(&repo);
    assert!(configure(&cli).unwrap().is_none());
    assert!(configure_at(&cli, state.clone()).unwrap().is_none());
    cli.provider_writeback = "apply".into();
    assert_eq!(
        configure_at(&cli, state.clone()).unwrap().unwrap().state,
        state.canonicalize().unwrap()
    );
    assert!(configure_at(&cli, repo.join("unsafe"))
        .err()
        .unwrap()
        .contains("outside"));
    let file = dir.path().join("file");
    std::fs::write(&file, "not a directory").unwrap();
    assert!(configure_at(&cli, file.join("state")).is_err());
}
#[test]
fn configuration_uses_application_state_without_a_publication_flag() {
    let _guard = crate::tests::ENV_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    clean_git_fixture(&repo);
    let state = dir.path().join("application-state");
    let prior = std::env::var("BC_STATE_DIR").ok();
    unsafe { std::env::set_var("BC_STATE_DIR", &state) };
    let mut cli = crate::args::test_support::minimal_cli(&repo);
    assert!(configure(&cli).unwrap().is_none());
    cli.provider_writeback = "plan".into();
    assert!(configure(&cli).unwrap().is_none());
    assert!(!state.exists());
    cli.provider_writeback = "apply".into();
    let result = configure(&cli);
    crate::tests::restore_env("BC_STATE_DIR", prior);
    assert_eq!(
        result.unwrap().unwrap().state,
        state.join("provider-publications").canonicalize().unwrap()
    );
}

#[cfg(unix)]
#[test]
fn configuration_rejects_shared_writable_state() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let state = dir.path().join("state");
    std::fs::create_dir(&repo).unwrap();
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o777)).unwrap();
    let mut cli = crate::args::test_support::minimal_cli(&repo);
    cli.provider_writeback = "apply".into();
    assert!(configure_at(&cli, state)
        .err()
        .unwrap()
        .contains("writable"));
}
#[tokio::test]
async fn native_client_failures_are_cached_without_network() {
    let dir = tempfile::tempdir().unwrap();
    let cli = crate::args::test_support::minimal_cli(dir.path());
    let mut native = NativeClients {
        cli: &cli,
        cache: BTreeMap::new(),
    };
    let o = record(ProviderKind::Semgrep).origin;
    assert!(native.connect(&o).await.is_err());
    assert!(native.connect(&o).await.is_err());
    assert_eq!(native.cache.len(), 1);
    let mut cli = cli.clone();
    cli.semgrep_token = Some("synthetic-token".into());
    cli.semgrep_deployment_slug = Some("other-deployment".into());
    cli.semgrep_repo = Some("owner/repo".into());
    let mut native = NativeClients {
        cli: &cli,
        cache: BTreeMap::new(),
    };
    assert!(native.connect(&o).await.is_err());
}
#[tokio::test]
async fn run_without_credentials_emits_failure_receipt_without_scanning() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let revision = clean_git_fixture(&repo);
    let mut cli = crate::args::test_support::minimal_cli(&repo);
    cli.provider_writeback = "apply".into();
    let run = configure_at(&cli, dir.path().join("state"))
        .unwrap()
        .unwrap();
    let path = dir.path().join("results.json");
    let mut r = report(vec![record(ProviderKind::Semgrep)]);
    r.repo_root = repo.to_string_lossy().into_owned();
    r.git_sha = Some(revision);
    let result = run.publish(&r, &path).await.unwrap();
    assert!(result.contains("failed"));
    assert_eq!(receipt(&path).entries[0].status, "failed");
}

#[tokio::test]
async fn native_client_success_is_cached_without_sending_http() {
    let dir = tempfile::tempdir().unwrap();
    let mut cli = crate::args::test_support::minimal_cli(dir.path());
    cli.semgrep_token = Some("synthetic-token".into());
    cli.semgrep_deployment_slug = Some("tenant".into());
    cli.semgrep_repo = Some("owner/repo".into());
    let mut native = NativeClients {
        cli: &cli,
        cache: BTreeMap::new(),
    };
    let o = record(ProviderKind::Semgrep).origin;
    let first = native.connect(&o).await.unwrap();
    let second = native.connect(&o).await.unwrap();
    assert!(Arc::ptr_eq(&first.1, &second.1));
    assert_eq!(first.0, "https://semgrep.dev");
    assert_eq!(native.cache.len(), 1);
}

#[test]
fn automatic_confirmation_preserves_existing_human_triage() {
    let mut req = request();
    req.action = ApprovedAction::Confirmed {
        reason: "verified".into(),
        severity: None,
    };
    req.origin.provider = ProviderKind::Checkmarx;
    for baseline in [
        json!({}),
        json!({"results":[]}),
        json!({"results":[{"state":"NOT_EXPLOITABLE"}]}),
        json!({"results":[{"state":"TO_VERIFY"},{"state":"URGENT"}]}),
    ] {
        assert!(protect_existing_triage(&req, &baseline)
            .unwrap_err()
            .contains("triage"));
    }
    assert!(protect_existing_triage(
        &req,
        &json!({"results":[{"state":"TO_VERIFY"},{"state":"CONFIRMED"}]})
    )
    .is_ok());
    req.origin.provider = ProviderKind::Aikido;
    assert!(protect_existing_triage(&req, &json!({"issue":{"status":"open"}})).is_ok());
    assert!(protect_existing_triage(&req, &json!({"issue":{"status":"ignored"}})).is_err());
    req.origin.provider = ProviderKind::Semgrep;
    assert!(protect_existing_triage(&req, &json!({})).is_ok());
    req.action = ApprovedAction::Note {
        reason: "append evidence".into(),
    };
    req.origin.provider = ProviderKind::Aikido;
    assert!(protect_existing_triage(&req, &json!({"issue":{"status":"ignored"}})).is_ok());
}

#[test]
fn ingestion_bindings_check_every_native_member_and_preserve_case_insensitive_values() {
    for (provider, baseline) in [
        (
            ProviderKind::Semgrep,
            json!({"members":[{"triage_state":"OPEN","severity":"HIGH"}]}),
        ),
        (
            ProviderKind::Checkmarx,
            json!({"results":[{"state":"OPEN","severity":"HIGH"}]}),
        ),
        (
            ProviderKind::Aikido,
            json!({"issue":{"status":"OPEN","severity":"HIGH"}}),
        ),
        (
            ProviderKind::Snyk,
            json!({"issue":{"attributes":{"status":"OPEN","effective_severity_level":"HIGH"}}}),
        ),
    ] {
        let mut req = request();
        req.origin.provider = provider;
        req.origin.state = Some("open".into());
        req.origin.severity = Some("high".into());
        assert!(check_ingestion_state(&req, &baseline).is_ok());
        req.origin.state = Some("changed".into());
        assert!(check_ingestion_state(&req, &baseline).is_err());
        req.origin.state = Some("open".into());
        req.origin.severity = Some("low".into());
        assert!(check_ingestion_state(&req, &baseline).is_err());
        assert!(check_ingestion_state(&req, &json!({})).is_err());
        req.origin.state = None;
        req.origin.severity = None;
        assert!(check_ingestion_state(&req, &json!({})).is_ok());
    }
    let mut req = request();
    req.origin.state = Some("open".into());
    assert!(check_ingestion_state(
        &req,
        &json!({"members":[{"triage_state":"open"},{"triage_state":"ignored"}]})
    )
    .is_err());
    req.origin.provider = ProviderKind::Unknown;
    assert!(check_ingestion_state(&req, &json!({}))
        .unwrap_err()
        .contains("Unsupported"));
    req.action = ApprovedAction::Note {
        reason: "append only".into(),
    };
    assert!(check_ingestion_state(&req, &json!({})).is_ok());
}

#[tokio::test]
async fn conflicting_native_severity_actions_block_the_whole_group_before_connecting() {
    const VECTOR: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    let mut first = record(ProviderKind::Checkmarx);
    first.drop_reason = None;
    first.verification.as_mut().unwrap().verdict = Verdict::TruePositive;
    first.verification.as_mut().unwrap().cvss_vector = Some(VECTOR.into());
    let mut second = first.clone();
    second.origin.git_ref = Some("refs/heads/develop".into());
    second.origin.native_ids.issue_id = Some("2".into());
    second.verification.as_mut().unwrap().cvss_vector = None;
    let mut r = report(vec![first.clone(), second]);
    let mut finding:bc_model::Finding=serde_json::from_value(json!({"chunk_id":"external","file":first.file,"line_start":first.line,"line_end":first.line,"vuln_class":"other","title":first.title,"description":"claim","code_snippet":"","confidence":0.5})).unwrap();
    finding.provider_origins = vec![first.origin];
    finding.cvss_vector = Some(VECTOR.into());
    finding.cvss_rating = Some("Critical".into());
    r.findings.push(bc_model::RankedFinding {
        finding,
        severity: bc_model::Severity::Low,
        exploitability_notes: String::new(),
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.json");
    let mut c = clients();
    batch(&mut c, &r, dir.path(), &path).await.unwrap();
    let result = receipt(&path);
    assert_eq!(result.entries.len(), 2);
    assert!(result
        .entries
        .iter()
        .all(|e| e.status == "blocked" && e.reason.contains("Conflicting actions")));
    assert_eq!(c.connects, 0);
    assert_eq!(*c.client.writes.lock().unwrap(), 0);
}

#[tokio::test]
async fn native_triage_changes_stop_before_the_durable_sending_boundary() {
    let dir = tempfile::tempdir().unwrap();
    for (index, mut req, baseline) in [
        (
            0,
            request(),
            json!({"source_revision":"revision","members":[{"triage_state":"ignored"}]}),
        ),
        (
            1,
            request(),
            json!({"source_revision":"revision","results":[{"state":"NOT_EXPLOITABLE"}]}),
        ),
    ] {
        if index == 0 {
            req.origin.state = Some("untriaged".into());
        } else {
            req.origin.provider = ProviderKind::Checkmarx;
            req.action = ApprovedAction::Confirmed {
                reason: "verified".into(),
                severity: None,
            };
        }
        let fake = Fake::new();
        *fake.baseline.lock().unwrap() = Ok(baseline);
        let path = dir.path().join(format!("{index}.json"));
        assert!(transact(&fake, req, &path).await.is_err());
        assert_eq!(*fake.reads.lock().unwrap(), 1);
        assert_eq!(*fake.writes.lock().unwrap(), 0);
        let saved: Journal = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(saved.status, "preparing");
    }
}

#[tokio::test]
async fn empty_assessment_receipt_preserves_failed_and_limited_ingestion() {
    for completed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt.json");
        let mut r = report(vec![]);
        r.provider_ledger.analysis_complete = false;
        r.provider_ledger
            .ingestion
            .push(bc_model::ProviderIngestionRecord {
                source: "semgrep".into(),
                imported_count: 0,
                completed,
                limitations: vec!["Pagination unavailable for this repository".into()],
            });
        let mut c = clients();
        batch(&mut c, &r, dir.path(), &path).await.unwrap();
        let saved = receipt(&path);
        assert!(saved.complete);
        assert!(!saved.analysis_complete);
        assert!(saved.entries.is_empty());
        assert_eq!(saved.ingestion, r.provider_ledger.ingestion);
        assert!(saved
            .limitations
            .iter()
            .any(|gap| gap.contains("absence never implies false positive")));
        assert_eq!(c.connects, 0);
        assert_eq!(*c.client.writes.lock().unwrap(), 0);
    }
}

#[tokio::test]
async fn changed_source_produces_blocked_receipt_before_any_provider_operation() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    let revision = clean_git_fixture(&repo);
    let mut cli = crate::args::test_support::minimal_cli(&repo);
    cli.provider_writeback = "apply".into();
    let state = dir.path().join("state");
    let run = configure_at(&cli, state.clone()).unwrap().unwrap();
    let mut r = report(vec![record(ProviderKind::Semgrep)]);
    r.git_sha = Some(revision);
    r.repo_root = repo.to_string_lossy().into_owned();
    std::fs::write(repo.join("new_source.rs"), "uncommitted fix").unwrap();
    let path = dir.path().join("result.json");
    assert!(run.publish(&r, &path).await.is_err());
    let result = receipt(&path);
    assert!(!result.analysis_complete);
    assert_eq!(result.entries[0].status, "blocked");
    assert!(!result.limitations.is_empty());
    assert_eq!(std::fs::read_dir(state).unwrap().count(), 0);
}
