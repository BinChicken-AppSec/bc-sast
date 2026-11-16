use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct PyEnv {
    python: PathBuf,
    repo: PathBuf,
}

pub fn resolve() -> Option<PyEnv> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let python = env::var_os("BC_PARITY_PYTHON")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("../../parity/.venv/bin/python3"));
    let repo = env::var_os("BC_PARITY_REPO")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("../../../visa-vulnerability-agentic-harness"));
    if !python.is_file() {
        eprintln!(
            "SKIPPED: parity python not found at {} -- run parity/setup.sh (see parity/README.md)",
            python.display()
        );
        return None;
    }
    if !repo.is_dir() {
        eprintln!(
            "SKIPPED: vvaharness checkout not found at {} -- set BC_PARITY_REPO",
            repo.display()
        );
        return None;
    }
    Some(PyEnv { python, repo })
}

fn run(mut cmd: Command, input: &serde_json::Value, label: &str) -> Option<serde_json::Value> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {label}: {e}"));
    let wrote = child.stdin.take().expect("piped stdin").write_all(
        serde_json::to_string(input)
            .expect("input serializes")
            .as_bytes(),
    );
    let output = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("failed waiting on {label}: {e}"));
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success()
        && (stderr.contains("ModuleNotFoundError") || stderr.contains("ImportError"))
    {
        let line = stderr
            .lines()
            .rev()
            .find(|l| l.contains("Error"))
            .unwrap_or("import failed");
        eprintln!(
            "SKIPPED: {label} cannot import from this vvaharness checkout -- {} \
             (run parity/setup.sh, see parity/README.md)",
            line.trim()
        );
        return None;
    }
    if let Err(e) = wrote {
        panic!("failed writing stdin to {label}: {e}\nstderr: {stderr}");
    }
    assert!(
        output.status.success(),
        "{label} exited {:?}\nstderr: {stderr}",
        output.status.code(),
    );
    Some(serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "{label} produced invalid JSON: {e}\nstdout: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    }))
}

impl PyEnv {
    pub fn run_oracle(&self, name: &str, input: &serde_json::Value) -> Option<serde_json::Value> {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let script = manifest_dir.join("../../parity/oracles").join(name);
        let mut cmd = Command::new(&self.python);
        cmd.arg(&script).env("PYTHONPATH", &self.repo);
        run(cmd, input, name)
    }
}
