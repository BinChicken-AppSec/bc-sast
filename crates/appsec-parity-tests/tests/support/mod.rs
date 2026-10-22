//! Shared plumbing for every parity test file: locate the parity venv +
//! the vvaharness checkout, and shell out to an oracle script under
//! `parity/oracles/` with JSON on stdin/stdout.
//!
//! `tests/*.rs` files are each compiled as a separate crate, so this
//! module is recompiled into every one of them via `mod support;` — a
//! given test file only calls `run_oracle` with its own oracle name.

use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct PyEnv {
    python: PathBuf,
    repo: PathBuf,
}

/// Resolves the parity Python venv + harness checkout, honoring
/// `BC_PARITY_PYTHON` / `BC_PARITY_REPO` overrides, falling back to the
/// conventional sibling-checkout layout described in `parity/README.md`.
/// Returns `None` (after printing an explanatory note to stderr) when
/// either doesn't actually exist, so callers can skip rather than fail —
/// `cargo test --workspace` must stay green on a machine that hasn't run
/// `parity/setup.sh`.
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

fn run(mut cmd: Command, input: &serde_json::Value, label: &str) -> serde_json::Value {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {label}: {e}"));
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(
            serde_json::to_string(input)
                .expect("input serializes")
                .as_bytes(),
        )
        .unwrap_or_else(|e| panic!("failed writing stdin to {label}: {e}"));
    let output = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("failed waiting on {label}: {e}"));
    assert!(
        output.status.success(),
        "{label} exited {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "{label} produced invalid JSON: {e}\nstdout: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

impl PyEnv {
    /// Runs one of the oracle scripts under `parity/oracles/<name>` with
    /// `input` as its JSON stdin, returning its parsed JSON stdout.
    pub fn run_oracle(&self, name: &str, input: &serde_json::Value) -> serde_json::Value {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let script = manifest_dir.join("../../parity/oracles").join(name);
        let mut cmd = Command::new(&self.python);
        cmd.arg(&script).env("PYTHONPATH", &self.repo);
        run(cmd, input, name)
    }
}
