//! Fail-closed validation of reusable-workflow references an S10 edit
//! introduces, ported from
//! `remediation_agent/policy/workflow_refs.py` (new in vvaharness v1.3.0).
//!
//! **Why.** A finding such as "privileged workflow delegates to
//! `org/repo/.github/workflows/security.yml@develop`" invites the model to
//! "pin" the call. With no network access it cannot know any real commit,
//! so it invents one: an all-zero SHA, or a plausible-looking hash that
//! names no commit at all. Either breaks the pipeline, and a guessed SHA
//! that happens to exist in a fork is worse than the mutable ref it
//! replaced. The only commit this stage can vouch for is one the
//! repository itself already pins the same workflow to, so that is the
//! only one accepted.
//!
//! Pure functions only: the caller supplies the pre-edit snapshot and the
//! current file contents, and gets back per-file problems.
//!
//! **Scope, as in Python.** Only a *remote reusable workflow*
//! (`owner/repo/.github/workflows/<name>.yml@<ref>`) is gated. An action
//! (`uses: actions/checkout@v4`) is not a workflow call and is left
//! alone, and a local call (`uses: ./.github/workflows/x.yml`) carries no
//! `@ref`, so it never matches either.
//!
//! **One deliberate divergence: placeholder detection is stricter.**
//! Python treats a SHA as a placeholder only when every character is the
//! same (`0000...`). This port also rejects any 40-hex string that
//! repeats with a period of [`MAX_PLACEHOLDER_PERIOD`] characters or fewer
//! (`deadbeef` five times, `0123456789abcdef` repeated). A real SHA-1 has
//! that shape with probability around 20 in 16^20, so nothing genuine is
//! lost, and a copied placeholder that Python would have trusted because
//! it already appeared elsewhere in the repository is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;

/// Where GitHub looks for workflow files, repo-relative.
pub const WORKFLOW_PREFIX: &str = ".github/workflows/";

/// A placeholder is any 40-hex string periodic with a period at most this
/// long. See the module doc comment.
pub const MAX_PLACEHOLDER_PERIOD: usize = 20;

/// Python's `_USES`, verbatim (`(?im)`: case-insensitive, multi-line).
static USES_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r##"(?im)^\s*(?:-\s*)?uses\s*:\s*['"]?(?P<workflow>[^@\s'"#]+/\.github/workflows/[^@\s'"#]+\.ya?ml)@(?P<ref>[^\s'"#]+)"##,
    )
    .expect("USES_RE is a compile-time-constant valid regex")
});

/// `true` for a repo-relative path GitHub would run as a workflow:
/// `.github/workflows/**.yml`/`.yaml`, compared case-insensitively as
/// Python's `casefold` does.
pub fn is_workflow_path(path: &str) -> bool {
    let folded = path.to_lowercase();
    folded.starts_with(WORKFLOW_PREFIX) && (folded.ends_with(".yml") || folded.ends_with(".yaml"))
}

/// Every `(workflow, ref)` pair a remote reusable-workflow `uses:` line in
/// `text` names, in document order.
pub fn workflow_references(text: &str) -> Vec<(String, String)> {
    USES_RE
        .captures_iter(text)
        .map(|c| (c["workflow"].to_string(), c["ref"].to_string()))
        .collect()
}

/// `true` for exactly 40 hex digits.
pub fn is_full_sha(reference: &str) -> bool {
    reference.len() == 40 && reference.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `true` for a full SHA that is not a placeholder (see the module doc
/// comment for what counts as one).
pub fn is_nonplaceholder_sha(reference: &str) -> bool {
    if !is_full_sha(reference) {
        return false;
    }
    let bytes = reference.to_ascii_lowercase().into_bytes();
    let periodic =
        (1..=MAX_PLACEHOLDER_PERIOD).any(|p| bytes.iter().zip(&bytes[p..]).all(|(a, b)| a == b));
    !periodic
}

/// Why `reference` may not be introduced for `workflow`, or `None` when it
/// is a non-placeholder SHA the pre-edit repository already pins that same
/// workflow to. `trusted` maps a lowercased workflow to its established
/// lowercased SHAs.
pub fn unsafe_reason(
    workflow: &str,
    reference: &str,
    trusted: &BTreeMap<String, BTreeSet<String>>,
) -> Option<&'static str> {
    if !is_full_sha(reference) {
        return Some("not an immutable 40-character commit SHA");
    }
    if !is_nonplaceholder_sha(reference) {
        return Some("placeholder commit SHA");
    }
    let established = trusted
        .get(&workflow.to_lowercase())
        .is_some_and(|shas| shas.contains(&reference.to_lowercase()));
    (!established).then_some("commit SHA is not established by the pre-edit repository")
}

/// Unsafe reusable-workflow refs the current attempt introduced, keyed by
/// repo-relative workflow path, each entry reading `workflow@ref (reason)`.
///
/// - `before` is the pre-edit snapshot: path to its text, `None` when the
///   file did not exist. Non-workflow paths are ignored.
/// - `current` is every workflow path worth checking now, with its current
///   text (an empty string for a file that is gone).
///
/// An occurrence counts as introduced only beyond the number of identical
/// `(workflow, ref)` pairs the same file already had, so a pre-existing
/// mutable ref is never blamed on an unrelated edit to the same file: the
/// gate stops S10 making things worse, it does not reinterpret the
/// repository's existing debt.
pub fn introduced_unsafe_workflow_refs(
    before: &BTreeMap<String, Option<String>>,
    current: &BTreeMap<String, String>,
) -> BTreeMap<String, Vec<String>> {
    let mut trusted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut prior: BTreeMap<&str, BTreeMap<(String, String), usize>> = BTreeMap::new();
    for (path, text) in before {
        let Some(text) = text.as_deref().filter(|_| is_workflow_path(path)) else {
            continue;
        };
        let counts = prior.entry(path.as_str()).or_default();
        for (workflow, reference) in workflow_references(text) {
            if is_nonplaceholder_sha(&reference) {
                trusted
                    .entry(workflow.to_lowercase())
                    .or_default()
                    .insert(reference.to_lowercase());
            }
            *counts.entry((workflow, reference)).or_default() += 1;
        }
    }

    let empty = BTreeMap::new();
    let mut issues: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (path, text) in current {
        let previous = prior.get(path.as_str()).unwrap_or(&empty);
        let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
        for pair in workflow_references(text) {
            let count = seen.entry(pair.clone()).or_default();
            *count += 1;
            if *count <= previous.get(&pair).copied().unwrap_or(0) {
                continue;
            }
            let (workflow, reference) = pair;
            if let Some(reason) = unsafe_reason(&workflow, &reference, &trusted) {
                issues
                    .entry(path.clone())
                    .or_default()
                    .push(format!("{workflow}@{reference} ({reason})"));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKFLOW: &str = ".github/workflows/cicd_pipeline.yaml";
    const CALLEE: &str = "visa/reusable/.github/workflows/security.yml";
    /// Looks random: no short period, so it is not a placeholder.
    const REAL_SHA: &str = "8f14e45fceea167a5a36dedd4bea2543c1f2b9d0";
    const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

    fn workflow(reference: &str) -> String {
        format!(
            "name: CI\njobs:\n  security:\n    uses: {CALLEE}@{reference}\n    secrets: inherit\n"
        )
    }

    fn before(entries: &[(&str, Option<String>)]) -> BTreeMap<String, Option<String>> {
        entries
            .iter()
            .map(|(p, t)| (p.to_string(), t.clone()))
            .collect()
    }

    fn current(entries: &[(&str, String)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(p, t)| (p.to_string(), t.clone()))
            .collect()
    }

    #[test]
    fn workflow_paths_are_recognized_case_insensitively() {
        assert!(is_workflow_path(".github/workflows/ci.yml"));
        assert!(is_workflow_path(".GitHub/Workflows/CI.YAML"));
        assert!(!is_workflow_path(".github/not-a-workflow.yml"));
        assert!(!is_workflow_path(".github/workflows/readme.md"));
    }

    #[test]
    fn only_remote_reusable_workflow_calls_are_parsed() {
        let text = "\
jobs:
  a:
    uses: org/repo/.github/workflows/build.yml@main
  b:
    - uses: 'org/repo/.github/workflows/x.yaml@v1' # trailing comment
  c:
    uses: ./.github/workflows/local.yml
  d:
    steps:
      - uses: actions/checkout@v4
  e:
    USES: Org/Repo/.GITHUB/workflows/y.YML@abc
";
        assert_eq!(
            workflow_references(text),
            vec![
                (
                    "org/repo/.github/workflows/build.yml".to_string(),
                    "main".to_string()
                ),
                (
                    "org/repo/.github/workflows/x.yaml".to_string(),
                    "v1".to_string()
                ),
                (
                    "Org/Repo/.GITHUB/workflows/y.YML".to_string(),
                    "abc".to_string()
                ),
            ]
        );
    }

    #[test]
    fn sha_shape_and_placeholders() {
        assert!(is_full_sha(REAL_SHA));
        assert!(!is_full_sha("v1.2.3"));
        assert!(!is_full_sha(&"g".repeat(40)));
        assert!(!is_full_sha(&REAL_SHA[..39]));
        assert!(is_nonplaceholder_sha(REAL_SHA));
        assert!(is_nonplaceholder_sha(&REAL_SHA.to_uppercase()));
        assert!(!is_nonplaceholder_sha(ZERO_SHA));
        assert!(!is_nonplaceholder_sha(&"deadbeef".repeat(5)));
        assert!(!is_nonplaceholder_sha(
            "0123456789abcdef0123456789abcdef01234567"
        ));
        assert!(!is_nonplaceholder_sha("main"));
    }

    #[test]
    fn unsafe_reason_covers_every_case() {
        let mut trusted = BTreeMap::new();
        trusted.insert(
            CALLEE.to_lowercase(),
            BTreeSet::from([REAL_SHA.to_string()]),
        );
        assert_eq!(
            unsafe_reason(CALLEE, "develop", &trusted),
            Some("not an immutable 40-character commit SHA")
        );
        assert_eq!(
            unsafe_reason(CALLEE, ZERO_SHA, &trusted),
            Some("placeholder commit SHA")
        );
        assert_eq!(
            unsafe_reason(CALLEE, "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0c", &trusted),
            Some("commit SHA is not established by the pre-edit repository")
        );
        assert_eq!(unsafe_reason(CALLEE, REAL_SHA, &trusted), None);
        assert_eq!(
            unsafe_reason(&CALLEE.to_uppercase(), &REAL_SHA.to_uppercase(), &trusted),
            None
        );
        assert_eq!(
            unsafe_reason(
                "other/repo/.github/workflows/security.yml",
                REAL_SHA,
                &trusted
            ),
            Some("commit SHA is not established by the pre-edit repository")
        );
    }

    #[test]
    fn an_all_zero_pin_is_unsafe() {
        let issues = introduced_unsafe_workflow_refs(
            &before(&[(WORKFLOW, Some(workflow("develop")))]),
            &current(&[(WORKFLOW, workflow(ZERO_SHA))]),
        );
        assert_eq!(issues.keys().collect::<Vec<_>>(), vec![WORKFLOW]);
        assert!(issues[WORKFLOW][0].contains(ZERO_SHA));
        assert!(issues[WORKFLOW][0].contains("placeholder commit SHA"));
    }

    #[test]
    fn an_unverified_realistic_sha_is_unsafe() {
        let issues = introduced_unsafe_workflow_refs(
            &before(&[(WORKFLOW, Some(workflow("develop")))]),
            &current(&[(WORKFLOW, workflow(REAL_SHA))]),
        );
        assert!(issues[WORKFLOW][0].contains("not established by the pre-edit repository"));
    }

    #[test]
    fn a_new_branch_or_tag_ref_is_unsafe() {
        let issues = introduced_unsafe_workflow_refs(
            &before(&[(WORKFLOW, Some("name: CI\n".to_string()))]),
            &current(&[(WORKFLOW, workflow("v2"))]),
        );
        assert!(issues[WORKFLOW][0].contains("not an immutable 40-character commit SHA"));
    }

    #[test]
    fn a_sha_the_repository_already_pins_is_allowed() {
        let locked = ".github/workflows/locked.yml";
        let issues = introduced_unsafe_workflow_refs(
            &before(&[
                (WORKFLOW, Some(workflow("develop"))),
                (locked, Some(workflow(REAL_SHA))),
            ]),
            &current(&[(WORKFLOW, workflow(REAL_SHA)), (locked, workflow(REAL_SHA))]),
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn a_placeholder_already_in_the_repository_is_not_trusted() {
        let locked = ".github/workflows/locked.yml";
        let issues = introduced_unsafe_workflow_refs(
            &before(&[
                (WORKFLOW, Some(workflow("develop"))),
                (locked, Some(workflow(ZERO_SHA))),
            ]),
            &current(&[(WORKFLOW, workflow(ZERO_SHA)), (locked, workflow(ZERO_SHA))]),
        );
        assert_eq!(issues.keys().collect::<Vec<_>>(), vec![WORKFLOW]);
    }

    #[test]
    fn an_unchanged_mutable_ref_does_not_block_an_unrelated_edit() {
        let issues = introduced_unsafe_workflow_refs(
            &before(&[(WORKFLOW, Some(workflow("develop")))]),
            &current(&[(WORKFLOW, workflow("develop").replace("CI", "Renamed"))]),
        );
        assert!(issues.is_empty());
    }

    #[test]
    fn a_second_copy_of_a_pre_existing_mutable_ref_is_new() {
        let doubled = format!("{}{}", workflow("develop"), workflow("develop"));
        let issues = introduced_unsafe_workflow_refs(
            &before(&[(WORKFLOW, Some(workflow("develop")))]),
            &current(&[(WORKFLOW, doubled)]),
        );
        assert_eq!(issues[WORKFLOW].len(), 1);
    }

    #[test]
    fn a_newly_created_workflow_file_is_checked() {
        let created = ".github/workflows/new.yml";
        let issues = introduced_unsafe_workflow_refs(
            &before(&[(created, None)]),
            &current(&[(created, workflow("main"))]),
        );
        assert!(issues.contains_key(created));
    }

    #[test]
    fn non_workflow_snapshot_entries_neither_trust_nor_count() {
        // A SHA pinned only in a non-workflow file is not evidence.
        let issues = introduced_unsafe_workflow_refs(
            &before(&[
                ("docs/ci.yml", Some(workflow(REAL_SHA))),
                (WORKFLOW, Some(String::new())),
            ]),
            &current(&[(WORKFLOW, workflow(REAL_SHA))]),
        );
        assert!(issues.contains_key(WORKFLOW));
    }

    #[test]
    fn a_deleted_workflow_introduces_nothing() {
        let issues = introduced_unsafe_workflow_refs(
            &before(&[(WORKFLOW, Some(workflow("develop")))]),
            &current(&[(WORKFLOW, String::new())]),
        );
        assert!(issues.is_empty());
    }
}
