//! The I/O half of the reusable-workflow pin gate: which workflow files to
//! snapshot before the agent runs, and which of them it left holding an
//! unverifiable `uses: owner/repo/.github/workflows/x.yml@ref` afterwards.
//! The decision itself is [`bc_policy_gate::introduced_unsafe_workflow_refs`];
//! this module only gathers its inputs, with every read confined to the
//! repository and bounded, since the files are untrusted content.
//!
//! Ported from `remediation_agent/policy/workflow_refs.py::
//! workflow_snapshot_paths` and the gate's call site in
//! `remediation_agent/policy/postgate.py::enforce_post` (vvaharness
//! v1.3.0). **Deliberate divergence:** Python runs the check only when the
//! policy gate is enforced. Here it runs on every remediation, because an
//! invented commit SHA breaks the target's CI whether or not the operator
//! also asked for a CWE policy, and the check costs a directory listing.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

use bc_policy_gate::{is_workflow_path, WORKFLOW_PREFIX};

/// [`crate::RemediationRecord::policy_reason`] when this gate rejects an
/// edit, matching Python's `PostResult.reason`.
pub const UNSAFE_WORKFLOW_REFERENCE: &str = "unsafe_workflow_reference";

/// Most workflow files listed for the snapshot. A real repository has a
/// handful; a directory holding thousands is hostile or broken, and this
/// only bounds the pre-edit listing. A file the agent itself touched is
/// always checked, cap or not (see [`unsafe_workflow_refs`]).
const MAX_WORKFLOW_FILES: usize = 1_000;

/// Largest workflow file read for the check. A larger one cannot be
/// verified, so it is reported as unsafe rather than skipped: the gate
/// fails closed.
const MAX_WORKFLOW_BYTES: u64 = 1024 * 1024;

/// Most problems quoted per file, and the longest quoted problem, in the
/// rollback note. The note reaches `remediation.json` and PR comments, and
/// both the file and the ref text in it are model-written.
const MAX_ISSUES_QUOTED: usize = 10;
const MAX_ISSUE_CHARS: usize = 256;

/// Every `.github/workflows/*.yml`/`*.yaml` file directly under the repo,
/// sorted, as repo-relative paths: the files S10 must snapshot so the gate
/// can compare before with after, and so a rollback has a baseline even
/// for a workflow the model edited without listing it in `changes`.
pub(crate) fn workflow_snapshot_paths(repo: &Path) -> Vec<String> {
    let Some(dir) = bc_pathjail::confine(repo, WORKFLOW_PREFIX.trim_end_matches('/')) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| format!("{WORKFLOW_PREFIX}{}", e.file_name().to_string_lossy()))
        .filter(|rel| is_workflow_path(rel))
        .collect();
    out.sort();
    out.truncate(MAX_WORKFLOW_FILES);
    out
}

/// What reading one workflow file for the gate produced.
#[derive(Debug, PartialEq)]
enum Current {
    Text(String),
    TooLarge,
}

/// The file's current text: empty when it is gone, is not a regular file,
/// or resolves outside the repository; [`Current::TooLarge`] past
/// [`MAX_WORKFLOW_BYTES`].
fn read_current(repo: &Path, rel: &str) -> Current {
    let Some(file) = bc_pathjail::confine(repo, rel)
        .filter(|p| p.is_file())
        .and_then(|p| std::fs::File::open(p).ok())
    else {
        return Current::Text(String::new());
    };
    let mut bytes = Vec::new();
    // A read error mid-file leaves what was read so far, which can only
    // hide a ref by truncating it; the size check below cannot catch that,
    // but a file that errors part-way through a read on a local checkout
    // is not a realistic attack surface for an S10 edit.
    let _ = file.take(MAX_WORKFLOW_BYTES + 1).read_to_end(&mut bytes);
    if bytes.len() as u64 > MAX_WORKFLOW_BYTES {
        return Current::TooLarge;
    }
    Current::Text(String::from_utf8_lossy(&bytes).into_owned())
}

/// Unsafe reusable-workflow refs the agent's edit introduced, keyed by
/// repo-relative path. Checked: every workflow file listed now, every
/// workflow file in the pre-edit snapshot, and every workflow file the
/// agent touched (which may be one it created past the listing cap).
pub(crate) fn unsafe_workflow_refs(
    repo: &Path,
    before: &bc_diffcapture::Snapshot,
    touched: &[String],
) -> BTreeMap<String, Vec<String>> {
    let prior: BTreeMap<String, Option<String>> = before
        .keys()
        .filter(|k| is_workflow_path(k))
        .map(|k| {
            let text = before
                .get(k)
                .and_then(Option::as_ref)
                .map(|b| String::from_utf8_lossy(b).into_owned());
            (k.clone(), text)
        })
        .collect();
    let paths: BTreeSet<String> = workflow_snapshot_paths(repo)
        .into_iter()
        .chain(prior.keys().cloned())
        .chain(touched.iter().filter(|t| is_workflow_path(t)).cloned())
        .collect();

    let mut current = BTreeMap::new();
    let mut oversized = BTreeMap::new();
    for path in paths {
        match read_current(repo, &path) {
            Current::Text(text) => {
                current.insert(path, text);
            }
            Current::TooLarge => {
                oversized.insert(
                    path,
                    vec![format!(
                        "file exceeds {MAX_WORKFLOW_BYTES} bytes and cannot be verified"
                    )],
                );
            }
        }
    }
    let mut issues = bc_policy_gate::introduced_unsafe_workflow_refs(&prior, &current);
    issues.extend(oversized);
    issues
}

/// The rollback note's description of `issues`, bounded (see
/// [`MAX_ISSUES_QUOTED`]).
pub(crate) fn describe(issues: &BTreeMap<String, Vec<String>>) -> String {
    issues
        .iter()
        .map(|(path, refs)| {
            let mut quoted: Vec<String> = refs
                .iter()
                .take(MAX_ISSUES_QUOTED)
                .map(|r| truncate_chars(r, MAX_ISSUE_CHARS))
                .collect();
            if refs.len() > MAX_ISSUES_QUOTED {
                quoted.push(format!("and {} more", refs.len() - MAX_ISSUES_QUOTED));
            }
            format!("{path}: {}", quoted.join(", "))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max).collect();
    format!("{kept}...[truncated]")
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKFLOW: &str = ".github/workflows/ci.yml";

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn uses(reference: &str) -> String {
        format!("jobs:\n  a:\n    uses: org/repo/.github/workflows/sec.yml@{reference}\n")
    }

    #[test]
    fn snapshot_paths_list_only_top_level_workflow_files_sorted() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), ".github/workflows/b.yaml", "");
        write(dir.path(), ".github/workflows/a.yml", "");
        write(dir.path(), ".github/workflows/readme.md", "");
        write(dir.path(), ".github/workflows/nested/c.yml", "");
        write(dir.path(), ".github/other.yml", "");
        assert_eq!(
            workflow_snapshot_paths(dir.path()),
            vec![
                ".github/workflows/a.yml".to_string(),
                ".github/workflows/b.yaml".to_string()
            ]
        );
    }

    #[test]
    fn snapshot_paths_without_a_workflow_directory_are_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(workflow_snapshot_paths(dir.path()).is_empty());
        std::fs::create_dir_all(dir.path().join(".github")).unwrap();
        std::fs::write(dir.path().join(".github/workflows"), "not a dir").unwrap();
        assert!(workflow_snapshot_paths(dir.path()).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_workflow_directory_symlinked_out_of_the_repo_is_not_listed() {
        let base = tempfile::tempdir().unwrap();
        let repo = base.path().join("repo");
        write(base.path(), "outside/x.yml", "");
        std::fs::create_dir_all(repo.join(".github")).unwrap();
        std::os::unix::fs::symlink(base.path().join("outside"), repo.join(".github/workflows"))
            .unwrap();
        assert!(workflow_snapshot_paths(&repo).is_empty());
    }

    #[test]
    fn the_listing_is_capped() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..=MAX_WORKFLOW_FILES {
            write(dir.path(), &format!(".github/workflows/w{i:05}.yml"), "");
        }
        assert_eq!(
            workflow_snapshot_paths(dir.path()).len(),
            MAX_WORKFLOW_FILES
        );
    }

    #[test]
    fn read_current_distinguishes_missing_present_and_oversized() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read_current(dir.path(), WORKFLOW),
            Current::Text(String::new())
        );
        write(dir.path(), WORKFLOW, "name: CI\n");
        assert_eq!(
            read_current(dir.path(), WORKFLOW),
            Current::Text("name: CI\n".to_string())
        );
        let big = "#".repeat(MAX_WORKFLOW_BYTES as usize + 1);
        write(dir.path(), WORKFLOW, &big);
        assert_eq!(read_current(dir.path(), WORKFLOW), Current::TooLarge);
    }

    #[test]
    fn an_introduced_mutable_ref_is_reported_and_an_untouched_repo_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), WORKFLOW, &uses("develop"));
        let before = bc_diffcapture::snapshot_files(dir.path(), &[WORKFLOW.to_string()]);
        assert!(unsafe_workflow_refs(dir.path(), &before, &[]).is_empty());

        write(dir.path(), WORKFLOW, &uses(&"0".repeat(40)));
        let issues = unsafe_workflow_refs(dir.path(), &before, &[]);
        assert!(issues[WORKFLOW][0].contains("placeholder commit SHA"));
    }

    #[test]
    fn a_touched_workflow_outside_the_listing_is_still_checked() {
        let dir = tempfile::tempdir().unwrap();
        let nested = ".github/workflows/nested/new.yml";
        write(dir.path(), nested, &uses("main"));
        let issues = unsafe_workflow_refs(
            dir.path(),
            &bc_diffcapture::Snapshot::default(),
            &[nested.to_string(), "src/app.py".to_string()],
        );
        assert!(issues.contains_key(nested));
    }

    #[test]
    fn an_oversized_workflow_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            WORKFLOW,
            &"#".repeat(MAX_WORKFLOW_BYTES as usize + 1),
        );
        let issues = unsafe_workflow_refs(dir.path(), &bc_diffcapture::Snapshot::default(), &[]);
        assert!(issues[WORKFLOW][0].contains("cannot be verified"));
    }

    #[test]
    fn describe_bounds_the_count_and_length_of_quoted_problems() {
        let mut issues = BTreeMap::new();
        let long = "x".repeat(MAX_ISSUE_CHARS + 5);
        let mut refs = vec![long];
        refs.extend((0..MAX_ISSUES_QUOTED).map(|i| format!("r{i}")));
        issues.insert(WORKFLOW.to_string(), refs);
        issues.insert("b.yml".to_string(), vec!["short".to_string()]);
        let text = describe(&issues);
        assert!(text.starts_with(".github/workflows/ci.yml: "));
        assert!(text.contains("...[truncated]"));
        assert!(text.ends_with("and 1 more; b.yml: short"));
    }
}
