use std::ffi::OsString;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

const MAX_COMMANDS: usize = 64;
const MAX_ARGV_ITEMS: usize = 64;
const MAX_ARG_BYTES: usize = 16 * 1024;
const MAX_SNAPSHOT_ENTRIES: usize = 30_000;
const MAX_SNAPSHOT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SNAPSHOT_DEPTH: usize = 32;
const OUTPUT_BYTES_PER_STREAM: usize = 64 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
const PROVISION_TIMEOUT: Duration = Duration::from_secs(1_200);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);
pub const PROVISION_PHASE: &str = "provision";
static CONTAINER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    Provision,
    Existing,
    Functional,
    SecurityRegression,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TestCommand {
    pub id: String,
    pub cwd: String,
    pub argv: Vec<String>,
    pub kind: CommandKind,
    #[serde(default)]
    pub expected_failure_contains: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContainerPolicy {
    pub image: String,
    pub commands: Vec<TestCommand>,
}

impl ContainerPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if !is_digest_pinned_image(&self.image) {
            return Err("target-test image must be pinned with a sha256 digest".into());
        }
        if self.commands.is_empty() || self.commands.len() > MAX_COMMANDS {
            return Err(format!(
                "target-test policy must contain 1 to {MAX_COMMANDS} commands"
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for command in &self.commands {
            validate_command(command)?;
            if !ids.insert(&command.id) {
                return Err(format!("duplicate target-test command id: {}", command.id));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Passed,
    Failed,
    EnvironmentFailed,
    Blocked,
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CleanupState {
    Automatic,
    NotNeeded,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionResult {
    pub phase: String,
    pub command_id: String,
    pub kind: CommandKind,
    pub state: ExecutionState,
    pub exit_code: Option<i32>,
    pub output: String,
    pub cleanup: CleanupState,
}

#[derive(Debug)]
pub struct DependencyStore {
    _root: tempfile::TempDir,
    store: std::path::PathBuf,
}

impl DependencyStore {
    pub fn create() -> Result<Self, String> {
        Self::create_in(&std::env::temp_dir())
    }

    fn create_in(parent: &Path) -> Result<Self, String> {
        let root = tempfile::Builder::new()
            .prefix("bc-sast-target-deps-")
            .tempdir_in(parent)
            .map_err(crate::context("cannot create dependency store"))?;
        set_store_mode(root.path(), 0o700)?;
        let store = root.path().join("store");
        std::fs::create_dir(&store).map_err(crate::context("cannot create dependency store"))?;
        set_store_mode(&store, 0o777)?;
        Ok(Self { _root: root, store })
    }

    fn path(&self) -> &Path {
        &self.store
    }
}

#[cfg(unix)]
fn set_store_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(crate::context(
        "cannot prepare dependency store permissions",
    ))
}

#[cfg(not(unix))]
fn set_store_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

pub async fn execute(
    root: &Path,
    policy: &ContainerPolicy,
    phase: &str,
    dependencies: &DependencyStore,
) -> Vec<ExecutionResult> {
    if let Err(error) = policy.validate() {
        return policy
            .commands
            .iter()
            .map(|command| blocked_result(phase, command, error.clone()))
            .collect();
    }

    let commands = match commands_for_phase(&policy.commands, phase) {
        Ok(commands) if commands.is_empty() => return Vec::new(),
        Ok(commands) => commands,
        Err(error) => {
            return policy
                .commands
                .iter()
                .map(|command| blocked_result(phase, command, error.clone()))
                .collect()
        }
    };
    let snapshot = match create_snapshot(root) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return commands
                .iter()
                .map(|command| blocked_result(phase, command, error.clone()))
                .collect();
        }
    };
    let mut results = Vec::with_capacity(commands.len());
    for command in commands {
        results.push(
            run_command(
                docker_program(),
                timeout_for(command),
                &snapshot,
                dependencies,
                &policy.image,
                phase,
                command,
            )
            .await,
        );
    }
    results
}

pub fn not_provisioned(
    policy: &ContainerPolicy,
    phase: &str,
    reason: &str,
) -> Vec<ExecutionResult> {
    let commands = match commands_for_phase(&policy.commands, phase) {
        Ok(commands) => commands,
        Err(error) => {
            return policy
                .commands
                .iter()
                .map(|command| blocked_result(phase, command, error.clone()))
                .collect()
        }
    };
    commands
        .into_iter()
        .map(|command| ExecutionResult {
            phase: phase.to_string(),
            command_id: command.id.clone(),
            kind: command.kind.clone(),
            state: ExecutionState::EnvironmentFailed,
            exit_code: None,
            output: redact_and_cap(&format!("not run: {reason}")),
            cleanup: CleanupState::NotNeeded,
        })
        .collect()
}

fn timeout_for(command: &TestCommand) -> Duration {
    match command.kind {
        CommandKind::Provision => PROVISION_TIMEOUT,
        _ => COMMAND_TIMEOUT,
    }
}

fn blocked_result(phase: &str, command: &TestCommand, error: String) -> ExecutionResult {
    ExecutionResult {
        phase: phase.to_string(),
        command_id: command.id.clone(),
        kind: command.kind.clone(),
        state: ExecutionState::Blocked,
        exit_code: None,
        output: redact_and_cap(&format!("blocked: {error}")),
        cleanup: CleanupState::NotNeeded,
    }
}

fn validate_command(command: &TestCommand) -> Result<(), String> {
    if !safe_id(&command.id) {
        return Err(format!("invalid target-test command id: {}", command.id));
    }
    if !safe_relative_dir(&command.cwd) {
        return Err(format!("invalid target-test command cwd: {}", command.cwd));
    }
    if command.argv.is_empty() || command.argv.len() > MAX_ARGV_ITEMS {
        return Err(format!(
            "target-test command {} has invalid argv length",
            command.id
        ));
    }
    if command.argv.iter().any(|argument| {
        argument.is_empty() || argument.len() > MAX_ARG_BYTES || argument.contains('\0')
    }) {
        return Err(format!(
            "target-test command {} has an invalid argv item",
            command.id
        ));
    }
    if is_interpreter(&command.argv[0]) {
        return Err(format!(
            "target-test command {} must name a test runner, not a shell interpreter",
            command.id
        ));
    }
    if command.kind != CommandKind::Provision && requests_dependency_install(&command.argv) {
        return Err(format!(
            "target-test command {} requests dependency installation, which is forbidden",
            command.id
        ));
    }
    match (&command.kind, &command.expected_failure_contains) {
        (CommandKind::SecurityRegression, Some(marker))
            if !marker.trim().is_empty() && marker.len() <= 1_024 => {}
        (CommandKind::SecurityRegression, _) => {
            return Err(format!(
                "security-regression command {} requires expected_failure_contains",
                command.id
            ))
        }
        (_, Some(_)) => {
            return Err(format!(
                "only security-regression command {} may set expected_failure_contains",
                command.id
            ))
        }
        (_, None) => {}
    }
    Ok(())
}

fn commands_for_phase<'a>(
    commands: &'a [TestCommand],
    phase: &str,
) -> Result<Vec<&'a TestCommand>, String> {
    let selected = match phase {
        PROVISION_PHASE => commands
            .iter()
            .filter(|command| command.kind == CommandKind::Provision)
            .collect(),
        "existing_baseline" => commands
            .iter()
            .filter(|command| command.kind == CommandKind::Existing)
            .collect(),
        "generated_baseline" => commands
            .iter()
            .filter(|command| {
                matches!(
                    command.kind,
                    CommandKind::Functional | CommandKind::SecurityRegression
                )
            })
            .collect(),
        "postpatch" => commands
            .iter()
            .filter(|command| command.kind != CommandKind::Provision)
            .collect(),
        _ => return Err(format!("unknown target-test execution phase: {phase}")),
    };
    Ok(selected)
}

fn is_digest_pinned_image(image: &str) -> bool {
    let Some((name, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    !name.is_empty() && digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 100
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn safe_relative_dir(path: &str) -> bool {
    if path == "." || path.is_empty() {
        return true;
    }
    !path.contains('\\')
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !path.split('/').any(|part| {
            part.starts_with('.') || matches!(part, "node_modules" | "target" | "vendor")
        })
}

fn is_interpreter(program: &str) -> bool {
    matches!(
        program
            .rsplit('/')
            .next()
            .unwrap_or(program)
            .to_ascii_lowercase()
            .as_str(),
        "sh" | "bash" | "zsh" | "fish" | "cmd" | "cmd.exe" | "powershell" | "pwsh"
    )
}

fn requests_dependency_install(argv: &[String]) -> bool {
    let program = argv[0]
        .rsplit('/')
        .next()
        .unwrap_or(&argv[0])
        .to_ascii_lowercase();
    let subcommand = argv.get(1).map(|value| value.as_str()).unwrap_or_default();
    matches!(
        (program.as_str(), subcommand),
        (
            "npm" | "pnpm" | "yarn" | "bun",
            "install" | "add" | "upgrade" | "ci"
        ) | ("pip" | "pip3" | "poetry" | "uv", "install" | "add" | "sync")
            | ("cargo", "install" | "add" | "fetch" | "vendor")
            | ("go", "get" | "install")
            | (
                "mvn" | "mvnw",
                "dependency:get" | "dependency:go-offline" | "dependency:resolve"
            )
            | ("dotnet", "restore" | "add")
    ) || (program == "go"
        && subcommand == "mod"
        && argv.get(2).is_some_and(|value| value == "download"))
}

struct Snapshot {
    tempdir: tempfile::TempDir,
    source: std::path::PathBuf,
}

impl Snapshot {
    fn path(&self) -> &Path {
        &self.source
    }
    fn docker_config(&self) -> &Path {
        self.tempdir.path()
    }
}

fn create_snapshot(root: &Path) -> Result<Snapshot, String> {
    let root = root
        .canonicalize()
        .map_err(crate::context("cannot resolve target root"))?;
    if !root.is_dir() {
        return Err("target root is not a directory".into());
    }
    let snapshot = tempfile::Builder::new()
        .prefix("bc-sast-target-test-")
        .tempdir()
        .map_err(crate::context("cannot create isolated target snapshot"))?;
    let source = snapshot.path().join("source");
    std::fs::create_dir(&source).map_err(crate::context("cannot create target snapshot"))?;
    make_snapshot_directory_readable(&source)?;
    let mut budget = SnapshotBudget::default();
    copy_sanitized(&root, &source, 0, &mut budget)?;
    Ok(Snapshot {
        tempdir: snapshot,
        source,
    })
}

#[derive(Default)]
struct SnapshotBudget {
    entries: usize,
    bytes: u64,
}

fn copy_sanitized(
    source: &Path,
    destination: &Path,
    depth: usize,
    budget: &mut SnapshotBudget,
) -> Result<(), String> {
    if depth > MAX_SNAPSHOT_DEPTH {
        return Err(format!(
            "target snapshot exceeds depth limit {MAX_SNAPSHOT_DEPTH}"
        ));
    }
    for entry in std::fs::read_dir(source).map_err(crate::context("cannot read target snapshot"))? {
        let entry = entry.map_err(crate::context("cannot enumerate target snapshot"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if excluded_snapshot_name(&name) {
            continue;
        }
        budget.entries += 1;
        if budget.entries > MAX_SNAPSHOT_ENTRIES {
            return Err(format!(
                "target snapshot exceeds entry limit {MAX_SNAPSHOT_ENTRIES}"
            ));
        }
        let source_path = entry.path();
        let metadata = std::fs::symlink_metadata(&source_path)
            .map_err(crate::context("cannot inspect target snapshot"))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        let destination_path = destination.join(name.as_ref());
        if metadata.is_dir() {
            std::fs::create_dir(&destination_path)
                .map_err(crate::context("cannot create snapshot directory"))?;
            make_snapshot_directory_readable(&destination_path)?;
            copy_sanitized(&source_path, &destination_path, depth + 1, budget)?;
        } else if metadata.is_file() {
            let remaining = MAX_SNAPSHOT_BYTES.saturating_sub(budget.bytes);
            let copied = copy_file_bounded(&source_path, &destination_path, remaining)?;
            budget.bytes = budget.bytes.saturating_add(copied);
            restrict_snapshot_permissions(&destination_path, &metadata)?;
        }
    }
    Ok(())
}

fn copy_file_bounded(source: &Path, destination: &Path, remaining: u64) -> Result<u64, String> {
    use std::io::{Read, Write};
    let mut source =
        std::fs::File::open(source).map_err(crate::context("cannot open target snapshot file"))?;
    let mut destination = std::fs::File::create(destination)
        .map_err(crate::context("cannot create target snapshot file"))?;
    let copied = std::io::copy(
        &mut std::io::Read::by_ref(&mut source).take(remaining.saturating_add(1)),
        &mut destination,
    )
    .map_err(crate::context("cannot copy target snapshot file"))?;
    destination
        .flush()
        .map_err(crate::context("cannot finish target snapshot file"))?;
    if copied > remaining {
        return Err(format!(
            "target snapshot exceeds byte limit {MAX_SNAPSHOT_BYTES}"
        ));
    }
    Ok(copied)
}

fn excluded_snapshot_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == ".git"
        || lower.starts_with(".env")
        || matches!(
            lower.as_str(),
            "credentials"
                | "credentials.json"
                | "secrets.json"
                | "secrets.yaml"
                | "secrets.yml"
                | "id_rsa"
                | "id_ed25519"
                | ".aws"
                | ".ssh"
                | ".azure"
                | ".kube"
                | ".npmrc"
                | ".pypirc"
                | "node_modules"
                | "target"
                | "vendor"
                | ".venv"
                | "venv"
                | ".tox"
                | "dist"
                | "build"
                | ".next"
                | "coverage"
        )
        || [".pem", ".key", ".p12", ".pfx", ".kdbx"]
            .iter()
            .any(|extension| lower.ends_with(extension))
}

#[cfg(unix)]
fn restrict_snapshot_permissions(path: &Path, metadata: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mode = if metadata.permissions().mode() & 0o111 == 0 {
        0o644
    } else {
        0o755
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(crate::context("cannot set snapshot permissions"))
}

#[cfg(unix)]
fn make_snapshot_directory_readable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(crate::context("cannot set snapshot directory permissions"))
}

#[cfg(not(unix))]
fn make_snapshot_directory_readable(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(not(unix))]
fn restrict_snapshot_permissions(
    _path: &Path,
    _metadata: &std::fs::Metadata,
) -> Result<(), String> {
    Ok(())
}

async fn run_command(
    program: &str,
    timeout: Duration,
    snapshot: &Snapshot,
    dependencies: &DependencyStore,
    image: &str,
    phase: &str,
    command: &TestCommand,
) -> ExecutionResult {
    let name = container_name();
    let mut guard = ContainerCleanup::new(name.clone());
    let arguments = docker_arguments(snapshot.path(), dependencies.path(), image, &name, command);
    let mut docker = Command::new(program);
    docker
        .args(&arguments)
        .env_clear()
        .env("PATH", safe_host_path())
        .env("DOCKER_CONFIG", snapshot.docker_config())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = match docker.spawn() {
        Ok(child) => child,
        Err(error) => {
            guard.disarm();
            return ExecutionResult {
                phase: phase.to_string(),
                command_id: command.id.clone(),
                kind: command.kind.clone(),
                state: ExecutionState::Blocked,
                exit_code: None,
                output: redact_and_cap(&format!("blocked: Docker could not start: {error}")),
                cleanup: CleanupState::NotNeeded,
            };
        }
    };
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let completed = async {
        let (stdout, stderr, status) =
            tokio::join!(read_capped(stdout), read_capped(stderr), child.wait(),);
        (stdout, stderr, status)
    };
    match tokio::time::timeout(timeout, completed).await {
        Ok((stdout, stderr, Ok(status))) => {
            guard.disarm();
            let (output, truncated) = combine_output(stdout, stderr);
            ExecutionResult {
                phase: phase.to_string(),
                command_id: command.id.clone(),
                kind: command.kind.clone(),
                state: if status.success() {
                    ExecutionState::Passed
                } else if matches!(status.code(), Some(125..=127)) {
                    ExecutionState::Blocked
                } else if command.kind == CommandKind::Provision {
                    ExecutionState::EnvironmentFailed
                } else {
                    ExecutionState::Failed
                },
                exit_code: status.code(),
                output: redact_and_cap(&output_with_truncation(output, truncated)),
                cleanup: CleanupState::Automatic,
            }
        }
        Ok((_stdout, _stderr, Err(error))) => {
            guard.disarm();
            ExecutionResult {
                phase: phase.to_string(),
                command_id: command.id.clone(),
                kind: command.kind.clone(),
                state: ExecutionState::Blocked,
                exit_code: None,
                output: redact_and_cap(&format!("blocked: Docker did not complete: {error}")),
                cleanup: CleanupState::Automatic,
            }
        }
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            let cleanup = cleanup_container(&name).await;
            guard.disarm();
            ExecutionResult {
                phase: phase.to_string(),
                command_id: command.id.clone(),
                kind: command.kind.clone(),
                state: ExecutionState::TimedOut,
                exit_code: None,
                output: format!("timed out after {} seconds", timeout.as_secs()),
                cleanup,
            }
        }
    }
}

const TEST_SETUP: &str = "set -eu; mkdir -p /tmp/repo /tmp/home; \
    if [ -d /deps/repo ]; then cp -R /deps/repo/. /tmp/repo/; fi; \
    if [ -d /deps/home ]; then cp -R /deps/home/. /tmp/home/; fi; \
    cp -R /source/. /tmp/repo/; cd /tmp/repo; cd -- \"$1\"; shift; exec \"$@\"";

const PROVISION_SETUP: &str = "set -eu; umask 000; mkdir -p /deps/repo /deps/home; \
    cp -R /source/. /deps/repo/; cd /deps/repo; cd -- \"$1\"; shift; \
    \"$@\"; chmod -R a+rwX /deps 2>/dev/null || true";

fn docker_arguments(
    snapshot: &Path,
    dependencies: &Path,
    image: &str,
    name: &str,
    command: &TestCommand,
) -> Vec<OsString> {
    let provisioning = command.kind == CommandKind::Provision;
    let source = format!(
        "type=bind,src={},dst=/source,readonly",
        snapshot.to_string_lossy()
    );
    let store = format!(
        "type=bind,src={},dst=/deps{}",
        dependencies.to_string_lossy(),
        if provisioning { "" } else { ",readonly" }
    );
    let network = if provisioning { "bridge" } else { "none" };
    let home = if provisioning {
        "HOME=/deps/home"
    } else {
        "HOME=/tmp/home"
    };
    let setup = if provisioning {
        PROVISION_SETUP
    } else {
        TEST_SETUP
    };
    let cwd = if command.cwd.is_empty() {
        "."
    } else {
        command.cwd.as_str()
    };
    let mut arguments = vec![
        "--host".into(),
        docker_endpoint().into(),
        "run".into(),
        "--rm".into(),
        "--name".into(),
        name.into(),
        "--pull".into(),
        "never".into(),
        "--network".into(),
        network.into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges:true".into(),
        "--pids-limit".into(),
        "256".into(),
        "--cpus".into(),
        "2".into(),
        "--memory".into(),
        "4g".into(),
        "--tmpfs".into(),
        "/tmp:rw,nosuid,nodev,size=4g".into(),
        "--user".into(),
        "65532:65532".into(),
        "--env".into(),
        home.into(),
    ];
    if provisioning {
        arguments.extend([
            "--env".into(),
            OsString::from("DOTNET_CLI_TELEMETRY_OPTOUT=1"),
            "--env".into(),
            OsString::from("DOTNET_NOLOGO=1"),
        ]);
    }
    arguments.extend([
        "--mount".into(),
        source.into(),
        "--mount".into(),
        store.into(),
        "--workdir".into(),
        "/tmp".into(),
        "--entrypoint".into(),
        "/bin/sh".into(),
        image.into(),
        "-c".into(),
        setup.into(),
        "bc-sast-target-executor".into(),
        cwd.into(),
    ]);
    arguments.extend(command.argv.iter().map(OsString::from));
    arguments
}

async fn read_capped<R: AsyncRead + Unpin>(mut reader: R) -> (String, bool) {
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        let count = match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        let remaining = OUTPUT_BYTES_PER_STREAM.saturating_sub(output.len());
        let keep = remaining.min(count);
        output.extend_from_slice(&buffer[..keep]);
        truncated |= keep < count;
    }
    (String::from_utf8_lossy(&output).into_owned(), truncated)
}

fn combine_output(stdout: (String, bool), stderr: (String, bool)) -> (String, bool) {
    let output = match (stdout.0.trim(), stderr.0.trim()) {
        ("", "") => String::new(),
        (stdout, "") => stdout.to_string(),
        ("", stderr) => stderr.to_string(),
        (stdout, stderr) => format!("stdout:\n{stdout}\nstderr:\n{stderr}"),
    };
    (output, stdout.1 || stderr.1)
}

fn output_with_truncation(mut output: String, truncated: bool) -> String {
    if truncated {
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str("[output truncated]");
    }
    output
}

fn redact_and_cap(output: &str) -> String {
    let mut end = output.len().min(OUTPUT_BYTES_PER_STREAM * 2);
    while end > 0 && !output.is_char_boundary(end) {
        end -= 1;
    }
    appsec_redact::redact(&output[..end])
}

#[cfg(unix)]
fn docker_endpoint() -> &'static str {
    "unix:///var/run/docker.sock"
}

#[cfg(windows)]
fn docker_endpoint() -> &'static str {
    "npipe:////./pipe/docker_engine"
}

#[cfg(not(any(unix, windows)))]
fn docker_endpoint() -> &'static str {
    "unix:///var/run/docker.sock"
}

fn docker_program() -> &'static str {
    if cfg!(windows) {
        r"C:\Program Files\Docker\Docker\resources\bin\docker.exe"
    } else {
        "docker"
    }
}

fn safe_host_path() -> &'static str {
    if cfg!(windows) {
        r"C:\Windows\System32;C:\Windows"
    } else {
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
    }
}

fn container_name() -> String {
    let sequence = CONTAINER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("bc-sast-target-test-{}-{sequence}", std::process::id())
}

struct ContainerCleanup {
    name: String,
    armed: bool,
}

impl ContainerCleanup {
    fn new(name: String) -> Self {
        Self { name, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ContainerCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let name = self.name.clone();
            handle.spawn(async move {
                let _ = cleanup_container(&name).await;
            });
        }
    }
}

async fn cleanup_container(name: &str) -> CleanupState {
    let mut docker = Command::new(docker_program());
    docker
        .args(["--host", docker_endpoint(), "rm", "-f", "--", name])
        .env_clear()
        .env("PATH", safe_host_path())
        .kill_on_drop(true);
    match tokio::time::timeout(CLEANUP_TIMEOUT, docker.status()).await {
        Ok(Ok(status)) if status.success() => CleanupState::Succeeded,
        _ => CleanupState::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned_image() -> String {
        format!("example.test/test@sha256:{}", "a".repeat(64))
    }

    fn command() -> TestCommand {
        TestCommand {
            id: "existing-tests".into(),
            cwd: "crate".into(),
            argv: vec!["cargo".into(), "test".into(), "--offline".into()],
            kind: CommandKind::Existing,
            expected_failure_contains: None,
        }
    }

    fn provision() -> TestCommand {
        TestCommand {
            id: "provision-0".into(),
            cwd: "crate".into(),
            argv: vec!["cargo".into(), "fetch".into(), "--locked".into()],
            kind: CommandKind::Provision,
            expected_failure_contains: None,
        }
    }

    fn store() -> DependencyStore {
        DependencyStore::create().unwrap()
    }

    #[tokio::test]
    async fn invalid_policy_and_missing_snapshot_are_blocked_before_process_creation() {
        let policy = ContainerPolicy {
            image: "unpinned:latest".into(),
            commands: vec![command()],
        };
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing");
        let store = store();
        let invalid = execute(&missing, &policy, "existing_baseline", &store).await;
        assert_eq!(invalid[0].state, ExecutionState::Blocked);
        assert_eq!(invalid[0].cleanup, CleanupState::NotNeeded);
        let policy = ContainerPolicy {
            image: pinned_image(),
            commands: vec![command()],
        };
        let missing_snapshot = execute(&missing, &policy, "existing_baseline", &store).await;
        assert_eq!(missing_snapshot[0].state, ExecutionState::Blocked);
        assert_eq!(missing_snapshot[0].cleanup, CleanupState::NotNeeded);
    }

    #[tokio::test]
    async fn output_reader_drains_but_retains_only_its_bound() {
        use tokio::io::AsyncWriteExt;
        let (mut writer, reader) = tokio::io::duplex(1024);
        let send = tokio::spawn(async move {
            writer
                .write_all(&vec![b'x'; OUTPUT_BYTES_PER_STREAM * 3])
                .await
                .unwrap();
        });
        let (text, truncated) = read_capped(reader).await;
        send.await.unwrap();
        assert_eq!(text.len(), OUTPUT_BYTES_PER_STREAM);
        assert!(truncated);
    }

    #[test]
    fn root_cwd_is_supported_and_utf8_output_is_bounded_without_panicking() {
        let mut command = command();
        command.cwd = ".".into();
        assert!(validate_command(&command).is_ok());
        assert!(!safe_relative_dir("../outside"));
        let output = "€".repeat(100_000);
        let capped = redact_and_cap(&output);
        assert!(capped.len() <= OUTPUT_BYTES_PER_STREAM * 2);
    }

    #[test]
    fn policy_requires_a_digest_pinned_image_and_safe_explicit_commands() {
        let policy = ContainerPolicy {
            image: pinned_image(),
            commands: vec![command()],
        };
        assert!(policy.validate().is_ok());
        let mut unpinned = policy.clone();
        unpinned.image = "example.test/test:latest".into();
        assert!(unpinned.validate().is_err());
        let mut shell = policy.clone();
        shell.commands[0].argv = vec!["sh".into(), "-c".into(), "test".into()];
        assert!(shell.validate().is_err());
        let mut install = policy;
        install.commands[0].argv = vec!["npm".into(), "install".into()];
        assert!(install.validate().is_err());
    }

    #[test]
    fn phases_only_run_commands_that_produce_relevant_evidence() {
        let existing = command();
        let functional = TestCommand {
            id: "functional".into(),
            cwd: "".into(),
            argv: vec!["cargo".into(), "test".into()],
            kind: CommandKind::Functional,
            expected_failure_contains: None,
        };
        let security = TestCommand {
            id: "security".into(),
            cwd: "".into(),
            argv: vec!["cargo".into(), "test".into()],
            kind: CommandKind::SecurityRegression,
            expected_failure_contains: Some("vulnerability reproduced".into()),
        };
        let commands = vec![provision(), existing, functional, security];
        let selected = |phase| {
            commands_for_phase(&commands, phase)
                .unwrap()
                .into_iter()
                .map(|command| command.id.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(selected(PROVISION_PHASE), ["provision-0"]);
        assert_eq!(selected("existing_baseline"), ["existing-tests"]);
        assert_eq!(selected("generated_baseline"), ["functional", "security"]);
        assert_eq!(
            selected("postpatch"),
            ["existing-tests", "functional", "security"]
        );
        assert!(commands_for_phase(&commands, "unknown").is_err());
    }

    #[test]
    fn only_a_provisioning_command_may_install_and_it_still_passes_every_other_check() {
        let mut installing = command();
        installing.argv = vec!["npm".into(), "ci".into()];
        assert!(validate_command(&installing)
            .unwrap_err()
            .contains("requests dependency installation"));
        installing.kind = CommandKind::Provision;
        validate_command(&installing).unwrap();
        let mut fetching = command();
        fetching.argv = vec!["go".into(), "mod".into(), "download".into()];
        assert!(validate_command(&fetching)
            .unwrap_err()
            .contains("requests dependency installation"));
        fetching.argv = vec!["go".into(), "mod".into(), "verify".into()];
        validate_command(&fetching).unwrap();
        let rejected = |change: fn(&mut TestCommand)| {
            let mut candidate = provision();
            change(&mut candidate);
            validate_command(&candidate).unwrap_err()
        };
        assert!(
            rejected(|c| c.argv = vec!["sh".into(), "-c".into(), "npm ci".into()])
                .contains("must name a test runner, not a shell interpreter")
        );
        assert!(
            rejected(|c| c.cwd = "../outside".into()).contains("invalid target-test command cwd")
        );
        assert!(rejected(|c| c.id = "../escape".into()).contains("invalid target-test command id"));
        assert!(rejected(|c| c.argv.clear()).contains("has invalid argv length"));
        assert!(
            rejected(|c| c.expected_failure_contains = Some("boom".into()))
                .contains("only security-regression command")
        );
    }

    #[test]
    fn an_install_gets_a_longer_deadline_than_the_suite_it_prepares() {
        assert_eq!(timeout_for(&provision()), PROVISION_TIMEOUT);
        assert_eq!(timeout_for(&command()), COMMAND_TIMEOUT);
        assert!(PROVISION_TIMEOUT > COMMAND_TIMEOUT);
    }

    #[test]
    fn a_dependency_store_is_private_writable_and_reports_a_root_it_cannot_create() {
        let store = store();
        assert!(store.path().is_dir());
        let private_root = store.path().parent().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(store.path()), 0o777);
            assert_eq!(mode(private_root), 0o700);
        }
        let missing = private_root.join("missing");
        assert!(DependencyStore::create_in(&missing)
            .unwrap_err()
            .contains("cannot create dependency store"));
        #[cfg(unix)]
        assert!(set_store_mode(&missing, 0o700)
            .unwrap_err()
            .contains("cannot prepare dependency store permissions"));
    }

    #[tokio::test]
    async fn a_phase_that_cannot_be_provisioned_is_refused_rather_than_run_and_misread() {
        let policy = policy_with(vec![provision(), command()]);
        let results = not_provisioned(&policy, "postpatch", "npm ci ended EnvironmentFailed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].command_id, "existing-tests");
        assert_eq!(results[0].state, ExecutionState::EnvironmentFailed);
        assert_ne!(results[0].state, ExecutionState::Failed);
        assert_eq!(results[0].exit_code, None);
        assert_eq!(results[0].cleanup, CleanupState::NotNeeded);
        assert!(results[0]
            .output
            .contains("not run: npm ci ended EnvironmentFailed"));
        let unknown = not_provisioned(&policy, "audit", "unused");
        assert_eq!(unknown.len(), 2);
        assert!(unknown
            .iter()
            .all(|result| result.state == ExecutionState::Blocked));
    }

    #[test]
    fn docker_invocation_is_local_pinned_and_hardened_without_command_interpolation() {
        let command = command();
        let arguments = docker_arguments(
            Path::new("/snapshot"),
            Path::new("/store"),
            &pinned_image(),
            "bc-sast-target-test-1-0",
            &command,
        );
        let arguments: Vec<String> = arguments
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        for required in [
            "--host",
            docker_endpoint(),
            "--pull",
            "never",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "no-new-privileges:true",
            "--pids-limit",
            "256",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=4g",
        ] {
            assert!(
                arguments.iter().any(|value| value == required),
                "missing {required}"
            );
        }
        assert!(arguments
            .iter()
            .any(|value| value == "type=bind,src=/snapshot,dst=/source,readonly"));
        assert!(arguments
            .iter()
            .any(|value| value == "type=bind,src=/store,dst=/deps,readonly"));
        assert!(arguments
            .iter()
            .any(|value| value == "exec \"$@\"" || value.contains("exec \"$@\"")));
        assert!(arguments.iter().any(|value| value == "cargo"));
        assert!(!arguments
            .iter()
            .any(|value| value.contains("cargo test --offline")));
    }

    #[test]
    fn only_the_provisioning_phase_reaches_the_network_or_writes_to_the_store() {
        let rendered = |command: &TestCommand| {
            docker_arguments(
                Path::new("/snapshot"),
                Path::new("/store"),
                &pinned_image(),
                "bc-sast-target-test-1-0",
                command,
            )
            .into_iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
        };
        let after = |arguments: &[String], flag: &str| {
            arguments
                .iter()
                .position(|value| value == flag)
                .map(|index| arguments[index + 1].clone())
                .unwrap()
        };
        let installing = rendered(&provision());
        let testing = rendered(&command());
        assert_eq!(after(&installing, "--network"), "bridge");
        assert_eq!(after(&testing, "--network"), "none");
        assert!(installing
            .iter()
            .any(|value| value == "type=bind,src=/store,dst=/deps"));
        assert!(testing
            .iter()
            .any(|value| value == "type=bind,src=/store,dst=/deps,readonly"));
        for arguments in [&installing, &testing] {
            assert!(arguments
                .iter()
                .any(|value| value == "type=bind,src=/snapshot,dst=/source,readonly"));
            for required in [
                "--read-only",
                "--cap-drop",
                "ALL",
                "no-new-privileges:true",
                "65532:65532",
                "never",
            ] {
                assert!(
                    arguments.iter().any(|value| value == required),
                    "{required}"
                );
            }
            assert!(!arguments.iter().any(|value| value.contains("secret")));
        }
        assert!(installing.iter().any(|value| value == "HOME=/deps/home"));
        assert!(testing.iter().any(|value| value == "HOME=/tmp/home"));
        assert!(installing
            .iter()
            .any(|value| value == "DOTNET_CLI_TELEMETRY_OPTOUT=1"));
        assert!(!testing
            .iter()
            .any(|value| value.starts_with("DOTNET_CLI_TELEMETRY")));
        assert!(installing.iter().any(|value| value == PROVISION_SETUP));
        assert!(testing.iter().any(|value| value == TEST_SETUP));
        assert!(PROVISION_SETUP.contains("cd /deps/repo"));
        assert!(TEST_SETUP.contains("cd /tmp/repo"));
        assert!(installing.iter().any(|value| value == "--locked"));
        let mut rooted = command();
        rooted.cwd = String::new();
        let arguments = rendered(&rooted);
        let label = arguments
            .iter()
            .position(|value| value == "bc-sast-target-executor")
            .unwrap();
        assert_eq!(arguments[label + 1], ".");
    }

    #[test]
    fn sanitized_snapshot_excludes_metadata_secrets_dependencies_outputs_and_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".git")).unwrap();
        std::fs::write(root.path().join(".git/config"), "secret").unwrap();
        std::fs::write(root.path().join(".env"), "TOKEN=secret").unwrap();
        std::fs::create_dir(root.path().join("node_modules")).unwrap();
        std::fs::write(root.path().join("node_modules/pkg"), "dependency").unwrap();
        std::fs::write(root.path().join("app.rs"), "fn main() {}\n").unwrap();
        let snapshot = create_snapshot(root.path()).unwrap();
        assert!(snapshot.path().join("app.rs").is_file());
        assert!(!snapshot.path().join(".git").exists());
        assert!(!snapshot.path().join(".env").exists());
        assert!(!snapshot.path().join("node_modules").exists());
    }

    #[cfg(unix)]
    #[test]
    fn sanitized_snapshot_skips_symlink_aliases() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.rs"), "fn main() {}\n").unwrap();
        symlink(root.path().join("app.rs"), root.path().join("alias.rs")).unwrap();
        let snapshot = create_snapshot(root.path()).unwrap();
        assert!(!snapshot.path().join("alias.rs").exists());
    }

    fn policy_with(commands: Vec<TestCommand>) -> ContainerPolicy {
        ContainerPolicy {
            image: pinned_image(),
            commands,
        }
    }

    #[test]
    fn a_policy_must_carry_between_one_and_sixty_four_uniquely_named_commands() {
        let empty = policy_with(Vec::new());
        assert!(empty
            .validate()
            .unwrap_err()
            .contains("must contain 1 to 64 commands"));
        let crowded = policy_with(
            (0..=MAX_COMMANDS)
                .map(|index| TestCommand {
                    id: format!("command-{index}"),
                    ..command()
                })
                .collect(),
        );
        assert!(crowded
            .validate()
            .unwrap_err()
            .contains("must contain 1 to 64 commands"));
        let duplicated = policy_with(vec![command(), command()]);
        assert_eq!(
            duplicated.validate().unwrap_err(),
            "duplicate target-test command id: existing-tests"
        );
    }

    #[test]
    fn every_unsafe_command_shape_is_rejected_with_its_own_reason() {
        let rejected = |change: fn(&mut TestCommand)| {
            let mut candidate = command();
            change(&mut candidate);
            validate_command(&candidate).unwrap_err()
        };
        assert!(rejected(|c| c.id = "../escape".into()).contains("invalid target-test command id"));
        assert!(rejected(|c| c.id = "a".repeat(101)).contains("invalid target-test command id"));
        assert!(
            rejected(|c| c.cwd = "../outside".into()).contains("invalid target-test command cwd")
        );
        assert!(rejected(|c| c.cwd = "node_modules/pkg".into())
            .contains("invalid target-test command cwd"));
        assert!(rejected(|c| c.argv.clear()).contains("has invalid argv length"));
        assert!(
            rejected(|c| c.argv = vec!["cargo".into(); MAX_ARGV_ITEMS + 1])
                .contains("has invalid argv length")
        );
        assert!(rejected(|c| c.argv[1] = String::new()).contains("has an invalid argv item"));
        assert!(rejected(|c| c.argv[1] = "x".repeat(MAX_ARG_BYTES + 1))
            .contains("has an invalid argv item"));
        assert!(
            rejected(|c| c.argv[1] = "test\0--offline".into()).contains("has an invalid argv item")
        );
        assert!(
            rejected(|c| c.expected_failure_contains = Some("boom".into()))
                .contains("only security-regression command")
        );
        assert!(rejected(|c| c.kind = CommandKind::SecurityRegression)
            .contains("requires expected_failure_contains"));
        assert!(rejected(|c| {
            c.kind = CommandKind::SecurityRegression;
            c.expected_failure_contains = Some("   ".into());
        })
        .contains("requires expected_failure_contains"));
        assert!(rejected(|c| {
            c.kind = CommandKind::SecurityRegression;
            c.expected_failure_contains = Some("x".repeat(1_025));
        })
        .contains("requires expected_failure_contains"));

        let mut reproduces = command();
        reproduces.kind = CommandKind::SecurityRegression;
        reproduces.expected_failure_contains = Some("ownership assertion failed".into());
        assert!(validate_command(&reproduces).is_ok());
    }

    #[tokio::test]
    async fn an_unknown_phase_blocks_every_command_even_when_the_snapshot_is_usable() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.rs"), "fn main() {}\n").unwrap();
        let results = execute(
            root.path(),
            &policy_with(vec![command()]),
            "audit",
            &store(),
        )
        .await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, ExecutionState::Blocked);
        assert_eq!(results[0].cleanup, CleanupState::NotNeeded);
        assert_eq!(results[0].exit_code, None);
        assert!(results[0]
            .output
            .contains("unknown target-test execution phase: audit"));
    }

    #[tokio::test]
    async fn a_phase_with_no_matching_command_records_nothing_and_starts_no_container() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.rs"), "fn main() {}\n").unwrap();
        let functional = TestCommand {
            id: "functional".into(),
            kind: CommandKind::Functional,
            ..command()
        };
        assert!(execute(
            root.path(),
            &policy_with(vec![functional]),
            "existing_baseline",
            &store()
        )
        .await
        .is_empty());
    }

    #[tokio::test]
    async fn an_unavailable_pinned_image_never_falls_back_to_running_on_the_host() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.rs"), "fn main() {}\n").unwrap();
        let marker = root.path().join("host-marker");
        let probe = TestCommand {
            id: "host-escape-probe".into(),
            cwd: ".".into(),
            argv: vec!["touch".into(), marker.to_string_lossy().into_owned()],
            kind: CommandKind::Existing,
            expected_failure_contains: None,
        };
        let results = execute(
            root.path(),
            &policy_with(vec![probe]),
            "existing_baseline",
            &store(),
        )
        .await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].phase, "existing_baseline");
        assert_eq!(results[0].command_id, "host-escape-probe");
        assert_eq!(results[0].kind, CommandKind::Existing);
        assert_ne!(results[0].state, ExecutionState::Passed);
        assert!(
            !marker.exists(),
            "a target command must never execute on the host"
        );
        assert!(
            !root.path().join("host-marker").exists(),
            "a target command must never execute on the host"
        );
    }

    #[test]
    fn the_production_call_site_uses_the_real_client_and_deadline() {
        assert_eq!(COMMAND_TIMEOUT, Duration::from_secs(600));
        assert_eq!(CLEANUP_TIMEOUT, Duration::from_secs(15));
        #[cfg(not(windows))]
        assert_eq!(docker_program(), "docker");
        #[cfg(windows)]
        assert!(docker_program().ends_with(r"\\docker.exe"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_container_client_exit_status_decides_passed_failed_and_blocked() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.rs"), "fn main() {}\n").unwrap();
        let snapshot = create_snapshot(root.path()).unwrap();
        let clients = tempfile::tempdir().unwrap();
        let store = store();
        for (code, kind, expected) in [
            (0, CommandKind::Existing, ExecutionState::Passed),
            (1, CommandKind::Existing, ExecutionState::Failed),
            (125, CommandKind::Existing, ExecutionState::Blocked),
            (127, CommandKind::Existing, ExecutionState::Blocked),
            (0, CommandKind::Provision, ExecutionState::Passed),
            (1, CommandKind::Provision, ExecutionState::EnvironmentFailed),
            (125, CommandKind::Provision, ExecutionState::Blocked),
        ] {
            let client = clients.path().join(format!("exit-{code}"));
            std::fs::write(&client, format!("#!/bin/sh\nexit {code}\n")).unwrap();
            std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o755)).unwrap();
            let provisioning = kind == CommandKind::Provision;
            let result = run_command(
                client.to_str().unwrap(),
                COMMAND_TIMEOUT,
                &snapshot,
                &store,
                &pinned_image(),
                if provisioning {
                    PROVISION_PHASE
                } else {
                    "generated_baseline"
                },
                &if provisioning { provision() } else { command() },
            )
            .await;
            assert_eq!(result.state, expected, "exit {code} {kind:?}");
            assert_eq!(result.exit_code, Some(code), "exit {code} {kind:?}");
            assert_eq!(result.cleanup, CleanupState::Automatic, "exit {code}");
            assert!(result.output.is_empty(), "exit {code}: {}", result.output);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_container_that_outlives_its_deadline_is_killed_and_reported_as_a_timeout() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.rs"), "fn main() {}\n").unwrap();
        let snapshot = create_snapshot(root.path()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let clients = tempfile::tempdir().unwrap();
        let client = clients.path().join("never-returns");
        std::fs::write(&client, "#!/bin/sh\nexec sleep 300\n").unwrap();
        std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o755)).unwrap();
        let result = run_command(
            client.to_str().unwrap(),
            Duration::ZERO,
            &snapshot,
            &store(),
            &pinned_image(),
            "postpatch",
            &command(),
        )
        .await;
        assert_eq!(result.state, ExecutionState::TimedOut);
        assert_eq!(result.exit_code, None);
        assert_eq!(result.output, "timed out after 0 seconds");
        assert_eq!(result.phase, "postpatch");
        assert!(
            matches!(
                result.cleanup,
                CleanupState::Succeeded | CleanupState::Failed
            ),
            "{:?}",
            result.cleanup
        );
    }

    #[tokio::test]
    async fn a_container_client_that_cannot_be_started_is_blocked_never_run_on_the_host() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.rs"), "fn main() {}\n").unwrap();
        let snapshot = create_snapshot(root.path()).unwrap();
        let result = run_command(
            "bc-sast-not-a-real-container-client",
            COMMAND_TIMEOUT,
            &snapshot,
            &store(),
            &pinned_image(),
            "existing_baseline",
            &command(),
        )
        .await;
        assert_eq!(result.state, ExecutionState::Blocked);
        assert_eq!(result.exit_code, None);
        assert_eq!(result.cleanup, CleanupState::NotNeeded);
        assert!(
            result
                .output
                .starts_with("blocked: Docker could not start:"),
            "{}",
            result.output
        );
    }

    #[test]
    fn a_snapshot_root_must_resolve_to_a_directory() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("app.rs");
        std::fs::write(&file, "fn main() {}\n").unwrap();
        assert!(create_snapshot(&file)
            .err()
            .unwrap()
            .contains("target root is not a directory"));
        assert!(create_snapshot(&root.path().join("missing"))
            .err()
            .unwrap()
            .contains("cannot resolve target root"));
    }

    #[test]
    fn a_snapshot_copies_nested_directories_and_isolates_the_docker_configuration() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("src/nested")).unwrap();
        std::fs::write(root.path().join("src/nested/app.rs"), "fn main() {}\n").unwrap();
        let snapshot = create_snapshot(root.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(snapshot.path().join("src/nested/app.rs")).unwrap(),
            "fn main() {}\n"
        );
        assert_ne!(snapshot.docker_config(), snapshot.path());
        assert_eq!(snapshot.path().parent(), Some(snapshot.docker_config()));
        assert!(!snapshot.docker_config().join("config.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_snapshot_keeps_the_executable_bit_and_drops_every_other_permission() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let script = root.path().join("run-tests");
        std::fs::write(&script, "true\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let plain = root.path().join("app.rs");
        std::fs::write(&plain, "fn main() {}\n").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o600)).unwrap();
        let snapshot = create_snapshot(root.path()).unwrap();
        let mode = |name: &str| {
            std::fs::metadata(snapshot.path().join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("run-tests"), 0o755);
        assert_eq!(mode("app.rs"), 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn a_snapshot_skips_special_files_it_cannot_copy() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.rs"), "fn main() {}\n").unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(root.path().join("pipe"))
            .status()
            .expect("mkfifo is a POSIX utility");
        assert!(status.success());
        let snapshot = create_snapshot(root.path()).unwrap();
        assert!(snapshot.path().join("app.rs").is_file());
        assert!(!snapshot.path().join("pipe").exists());
    }

    #[test]
    fn a_snapshot_stops_at_its_depth_entry_and_byte_bounds() {
        let root = tempfile::tempdir().unwrap();
        let mut deep = root.path().to_path_buf();
        for _ in 0..=MAX_SNAPSHOT_DEPTH {
            deep.push("nested");
        }
        std::fs::create_dir_all(&deep).unwrap();
        assert!(create_snapshot(root.path())
            .err()
            .unwrap()
            .contains("exceeds depth limit 32"));

        let source = tempfile::tempdir().unwrap();
        std::fs::write(source.path().join("app.rs"), "fn main() {}\n").unwrap();
        let destination = tempfile::tempdir().unwrap();
        let mut counted_out = SnapshotBudget {
            entries: MAX_SNAPSHOT_ENTRIES,
            bytes: 0,
        };
        assert!(
            copy_sanitized(source.path(), destination.path(), 0, &mut counted_out)
                .unwrap_err()
                .contains("exceeds entry limit 30000")
        );
        assert!(!destination.path().join("app.rs").exists());
        let mut spent = SnapshotBudget {
            entries: 0,
            bytes: MAX_SNAPSHOT_BYTES,
        };
        assert!(
            copy_sanitized(source.path(), destination.path(), 0, &mut spent)
                .unwrap_err()
                .contains("exceeds byte limit")
        );
    }

    #[test]
    fn a_bounded_file_copy_reports_which_side_failed_and_refuses_to_overrun() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("app.rs");
        std::fs::write(&source, "fn main() {}\n").unwrap();
        assert!(
            copy_file_bounded(&root.path().join("missing"), &root.path().join("out"), 1024)
                .unwrap_err()
                .contains("cannot open target snapshot file")
        );
        assert!(
            copy_file_bounded(&source, &root.path().join("no-such-dir/out"), 1024)
                .unwrap_err()
                .contains("cannot create target snapshot file")
        );
        assert!(copy_file_bounded(&source, &root.path().join("clipped"), 4)
            .unwrap_err()
            .contains("exceeds byte limit"));
        assert!(
            copy_file_bounded(root.path(), &root.path().join("from-a-directory"), 1024)
                .unwrap_err()
                .contains("cannot copy target snapshot file")
        );
        assert_eq!(
            copy_file_bounded(&source, &root.path().join("out"), 1024).unwrap(),
            13
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("out")).unwrap(),
            "fn main() {}\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_source_directory_blocks_the_snapshot_rather_than_silently_skipping_it() {
        use std::os::unix::fs::PermissionsExt;
        if crate::test_support::permissions_enforced(
            "an_unreadable_source_directory_blocks_the_snapshot_rather_than_silently_skipping_it",
        ) {
            let root = tempfile::tempdir().unwrap();
            let locked = root.path().join("locked");
            std::fs::create_dir(&locked).unwrap();
            std::fs::write(locked.join("app.rs"), "fn main() {}\n").unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            let outcome = create_snapshot(root.path());
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(outcome
                .err()
                .unwrap()
                .contains("cannot read target snapshot"));
        }
    }

    #[test]
    fn a_source_directory_that_cannot_be_listed_blocks_the_copy() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.rs"), "fn main() {}\n").unwrap();
        let destination = tempfile::tempdir().unwrap();
        let mut budget = SnapshotBudget::default();
        let outcome = copy_sanitized(
            &root.path().join("app.rs/src"),
            destination.path(),
            1,
            &mut budget,
        );
        assert!(outcome.unwrap_err().contains("cannot read target snapshot"));
        assert_eq!(budget.entries, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_source_entry_that_cannot_be_inspected_blocks_the_snapshot() {
        let base = tempfile::tempdir().unwrap();
        let staged = base.path().join("staged");
        let listed = staged.join("l".repeat(200));
        std::fs::create_dir_all(&listed).unwrap();
        std::fs::write(listed.join("app.rs"), "fn main() {}\n").unwrap();
        let root = crate::test_support::bury_near_path_max(&staged);
        let outcome = create_snapshot(&root).err();
        assert!(outcome.unwrap().contains("cannot inspect target snapshot"));
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_permission_failures_are_reported_rather_than_ignored() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let metadata = std::fs::metadata(root.path()).unwrap();
        assert!(restrict_snapshot_permissions(&missing, &metadata)
            .unwrap_err()
            .contains("cannot set snapshot permissions"));
        assert!(make_snapshot_directory_readable(&missing)
            .unwrap_err()
            .contains("cannot set snapshot directory permissions"));
    }

    #[test]
    fn combined_output_labels_both_streams_and_records_truncation_once() {
        let quiet = combine_output((String::new(), false), ("  \n".into(), false));
        assert_eq!(quiet, (String::new(), false));
        assert_eq!(
            combine_output(("pass\n".into(), false), (String::new(), false)),
            ("pass".to_string(), false)
        );
        assert_eq!(
            combine_output((String::new(), false), ("boom\n".into(), true)),
            ("boom".to_string(), true)
        );
        assert_eq!(
            combine_output(("pass".into(), true), ("boom".into(), false)),
            ("stdout:\npass\nstderr:\nboom".to_string(), true)
        );
        assert_eq!(output_with_truncation("kept".into(), false), "kept");
        assert_eq!(
            output_with_truncation("kept".into(), true),
            "kept\n[output truncated]"
        );
        assert_eq!(
            output_with_truncation(String::new(), true),
            "[output truncated]"
        );
    }

    #[test]
    fn container_names_are_unique_safe_identifiers_scoped_to_this_process() {
        let first = container_name();
        let second = container_name();
        assert_ne!(first, second);
        let prefix = format!("bc-sast-target-test-{}-", std::process::id());
        for name in [&first, &second] {
            assert!(safe_id(name), "{name} must be usable as a --name argument");
            assert!(name.starts_with(&prefix), "{name}");
        }
    }

    #[test]
    fn the_executor_reaches_only_a_local_daemon_through_an_absolute_host_path() {
        let separator = if cfg!(windows) { ';' } else { ':' };
        let path = safe_host_path();
        assert!(!path.is_empty());
        for entry in path.split(separator) {
            assert!(
                Path::new(entry).is_absolute(),
                "{entry} would resolve relative to the working directory"
            );
        }
        assert!(Path::new(docker_program()).is_absolute() || docker_program() == "docker");
        let endpoint = docker_endpoint();
        assert!(
            endpoint.starts_with("unix://") || endpoint.starts_with("npipe:"),
            "{endpoint} must be a local engine, never a remote TCP daemon"
        );
    }

    #[tokio::test]
    async fn explicit_container_removal_always_reports_its_own_outcome() {
        let state = cleanup_container(&container_name()).await;
        assert!(
            matches!(state, CleanupState::Succeeded | CleanupState::Failed),
            "{state:?}"
        );
        assert_eq!(cleanup_container("").await, CleanupState::Failed);
    }

    #[test]
    fn a_cleanup_guard_dropped_outside_a_runtime_cannot_schedule_anything() {
        drop(ContainerCleanup::new(container_name()));
    }

    #[tokio::test]
    async fn a_disarmed_cleanup_guard_leaves_a_completed_container_alone() {
        let mut disarmed = ContainerCleanup::new(container_name());
        disarmed.disarm();
        assert!(!disarmed.armed);
        drop(disarmed);
        let armed = ContainerCleanup::new(container_name());
        assert!(armed.armed);
        drop(armed);
        tokio::task::yield_now().await;
    }
}
