//! File-system side of the API specification step: bounded, jailed reads
//! that never follow symlinks, the reference scan for a relocation, and a
//! transactional apply that rolls every change back if any one fails.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use bc_api_spec::references::{scan, Reference};
use bc_llm_client::ToolExecutor;
use bc_sandbox_tools::SandboxTools;

/// Directories the reference scan does not enter: dependency and build
/// output, which a relocation neither owns nor updates.
const SKIPPED_DIRECTORIES: [&str; 13] = [
    ".git",
    "node_modules",
    "target",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "bin",
    "obj",
    ".next",
    ".tox",
];
const MAX_SCAN_DEPTH: usize = 32;
const MAX_SCAN_ENTRIES: usize = 20_000;
const MAX_SCAN_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SCAN_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Blocking references named in a refusal; the rest are counted.
const MAX_NAMED_BLOCKERS: usize = 20;

/// Whether any existing component of repository path `path` is a symlink.
pub(super) fn has_symlink(root: &Path, path: &str) -> bool {
    let mut current = root.to_path_buf();
    path.split('/').any(|part| {
        current.push(part);
        std::fs::symlink_metadata(&current).is_ok_and(|meta| meta.file_type().is_symlink())
    })
}

/// Whether anything (file, directory or link) exists at `path`.
pub(super) fn occupied(root: &Path, path: &str) -> bool {
    std::fs::symlink_metadata(root.join(path)).is_ok()
}

/// At most `limit + 1` bytes of repository file `path`, so a caller can tell
/// an oversized file from one exactly at the limit. Symlinks, escaping
/// paths and anything but a regular file are refused.
pub(super) fn read_bounded(root: &Path, path: &str, limit: usize) -> Result<Vec<u8>, String> {
    if has_symlink(root, path) {
        return Err("a symlink is involved; symlinks are never followed".into());
    }
    let full = bc_pathjail::confine(root, path).ok_or("the path escapes the repository")?;
    let file = std::fs::File::open(&full).map_err(cannot_read)?;
    if !file.metadata().is_ok_and(|meta| meta.is_file()) {
        return Err("not a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(cannot_read)?;
    Ok(bytes)
}

fn cannot_read(error: std::io::Error) -> String {
    format!("cannot be read ({})", error.kind())
}

/// A file whose references to the relocated specification are rewritten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Rewrite {
    pub path: String,
    pub before: String,
    pub after: String,
}

/// What a relocation will change besides the specification itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct RelocationScan {
    pub references: Vec<Reference>,
    pub rewrites: Vec<Rewrite>,
}

/// Decide whether the specification at `old` can move to `new`, and which
/// references move with it. Every text file in the repository (bounded) is
/// scanned; `editable` says which files the step may change. Any reference
/// that cannot be rewritten, or any doubt the scan could not resolve,
/// refuses the move with the reasons.
pub(super) fn prepare_relocation(
    root: &Path,
    old: &str,
    new: &str,
    editable: &dyn Fn(&str) -> bool,
) -> Result<RelocationScan, Vec<String>> {
    if has_symlink(root, old) || has_symlink(root, new) {
        return Err(vec!["a symlink is involved in the old or new path".into()]);
    }
    if occupied(root, new) {
        return Err(vec![format!("{new} already exists")]);
    }
    let basename = old.rsplit('/').next().unwrap_or(old);
    let mut walk = Walk::default();
    walk.visit(root, root, 0).map_err(|reason| vec![reason])?;
    let mut result = RelocationScan::default();
    let mut blocking = Vec::new();
    for (path, bytes) in walk.files {
        if path == old || !contains(&bytes, basename.as_bytes()) {
            continue;
        }
        let Ok(text) = String::from_utf8(bytes) else {
            blocking.push(format!("{path}: a non-UTF-8 file mentions {basename}"));
            continue;
        };
        // A file the redactor would change cannot be published by branch
        // delivery once modified, so it is never edited here.
        let allowed = editable(&path) && bc_redact::redact(&text) == text;
        let found = scan(&path, &text, old, new, allowed);
        blocking.extend(
            found
                .blocking
                .iter()
                .map(|(line, reason)| format!("{path}:{line}: {reason}")),
        );
        if let Some(after) = found.rewritten {
            result.references.extend(found.rewritable);
            result.rewrites.push(Rewrite {
                path,
                before: text,
                after,
            });
        }
    }
    if blocking.is_empty() {
        return Ok(result);
    }
    let extra = blocking.len().saturating_sub(MAX_NAMED_BLOCKERS);
    blocking.truncate(MAX_NAMED_BLOCKERS);
    if extra > 0 {
        blocking.push(format!("and {extra} more"));
    }
    Err(blocking)
}

/// The UTF-8 text of every repository file `keep` selects, read with the
/// reference scan's bounds (which apply to the whole walk).
pub(super) fn texts(
    root: &Path,
    keep: &dyn Fn(&str) -> bool,
) -> Result<Vec<(String, String)>, String> {
    let mut walk = Walk::default();
    walk.visit(root, root, 0)?;
    Ok(walk
        .files
        .into_iter()
        .filter(|(path, _)| keep(path))
        .filter_map(|(path, bytes)| Some((path, String::from_utf8(bytes).ok()?)))
        .collect())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[derive(Default)]
struct Walk {
    files: Vec<(String, Vec<u8>)>,
    entries: usize,
    bytes: u64,
}

impl Walk {
    /// Collect regular files under `directory`, refusing (rather than
    /// silently narrowing) a scan that would exceed its bounds.
    fn visit(&mut self, root: &Path, directory: &Path, depth: usize) -> Result<(), String> {
        if depth > MAX_SCAN_DEPTH {
            return Err("the reference scan exceeded its directory depth limit".into());
        }
        let mut entries: Vec<_> = std::fs::read_dir(directory)
            .and_then(Iterator::collect::<Result<_, _>>)
            .map_err(cannot_read)?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            self.entries += 1;
            if self.entries > MAX_SCAN_ENTRIES {
                return Err("the reference scan exceeded its entry limit".into());
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let file_type = entry.file_type().map_err(cannot_read)?;
            let path = entry.path();
            if file_type.is_dir() && !SKIPPED_DIRECTORIES.contains(&name.as_str()) {
                self.visit(root, &path, depth + 1)?;
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let mut bytes = Vec::new();
                if let Err(error) = std::fs::File::open(&path)
                    .and_then(|file| file.take(MAX_SCAN_FILE_BYTES + 1).read_to_end(&mut bytes))
                {
                    return Err(format!("{relative} {}", cannot_read(error)));
                }
                self.bytes += bytes.len() as u64;
                if bytes.len() as u64 > MAX_SCAN_FILE_BYTES || self.bytes > MAX_SCAN_TOTAL_BYTES {
                    return Err(format!(
                        "{relative} exceeded the reference scan's byte limits"
                    ));
                }
                self.files.push((relative, bytes));
            }
            // Symlinks are never followed, and a link cannot be edited
            // safely, so it is neither scanned nor a reference.
        }
        Ok(())
    }
}

/// One change to apply: new contents, or removal when `contents` is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Change {
    pub path: String,
    pub contents: Option<String>,
}

/// Apply `changes` in order after confirming each path still holds what
/// the proposal was reviewed against (`expected`: the bytes, or `None` for
/// "must not exist"). Any failure restores every earlier change. An `Err`
/// means nothing was changed; a rollback that itself fails is reported
/// distinctly so the caller can stop.
pub(super) fn apply(
    root: &Path,
    changes: &[Change],
    expected: &BTreeMap<String, Option<Vec<u8>>>,
) -> Result<(), ApplyError> {
    for (path, bytes) in expected {
        let current = match std::fs::read(root.join(path)) {
            Ok(current) => Some(current),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(ApplyError::NotApplied(format!(
                    "{path} could not be re-read ({})",
                    e.kind()
                )))
            }
        };
        if has_symlink(root, path) || current.as_ref() != bytes.as_ref() {
            return Err(ApplyError::NotApplied(format!(
                "{path} changed after the proposal was reviewed"
            )));
        }
    }
    let writer = SandboxTools::new_with_write(root.to_path_buf());
    let mut done: Vec<&Change> = Vec::new();
    for change in changes {
        let applied = match &change.contents {
            Some(contents) => {
                writer.execute(
                    "Write",
                    &serde_json::json!({"path": change.path, "content": contents}),
                );
                std::fs::read(root.join(&change.path)).ok().as_deref() == Some(contents.as_bytes())
            }
            None => std::fs::remove_file(root.join(&change.path)).is_ok(),
        };
        if !applied {
            rollback(root, &done, expected).map_err(ApplyError::RollbackFailed)?;
            return Err(ApplyError::NotApplied(format!(
                "{} could not be written",
                change.path
            )));
        }
        done.push(change);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ApplyError {
    NotApplied(String),
    RollbackFailed(String),
}

fn rollback(
    root: &Path,
    done: &[&Change],
    expected: &BTreeMap<String, Option<Vec<u8>>>,
) -> Result<(), String> {
    for change in done.iter().rev() {
        let full = root.join(&change.path);
        let restored = match expected.get(&change.path).cloned().flatten() {
            Some(bytes) => std::fs::write(&full, bytes),
            None => std::fs::remove_file(&full),
        };
        restored.map_err(|e| {
            format!(
                "an API specification change to {} could not be rolled back ({})",
                change.path,
                e.kind()
            )
        })?;
    }
    Ok(())
}
