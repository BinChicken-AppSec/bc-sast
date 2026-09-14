//! Diff inspection + verdict capping, ported from
//! `remediation_agent/policy_gate/diffscan.py`. `inspect_diff` extracts
//! the changed-file set from a unified diff (git or a synthesized
//! non-git diff) so the S10 post-gate can enforce path policy on what
//! actually changed; `cap_verdict` maps the binary policy decision + gate
//! status to a clean ACCEPT/REJECT audit label.

use crate::Action;

/// Extracts the changed-file set (repo-relative paths) from a unified
/// diff — works for real git diffs and this project's own synthesized
/// non-git diffs (same headers). `/dev/null` (the added/deleted side) is
/// ignored. Returns a de-duplicated, order-preserving list.
pub fn inspect_diff(diff_text: Option<&str>) -> Vec<String> {
    let Some(text) = diff_text else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut add = |p: &str| {
        let p = p.trim();
        if p.is_empty() || p == "/dev/null" {
            return;
        }
        if seen.insert(p.to_string()) {
            out.push(p.to_string());
        }
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("diff --git a/") {
            // A single fluent chain (not a nested `if let`) — this
            // project's established fix for a recurring `cargo-llvm-cov`
            // phantom-brace quirk where a nested `if let`'s own closing
            // brace shows spurious 0 coverage.
            rest.split_once(" b/")
                .into_iter()
                .for_each(|(_, b)| add(b.trim_end()));
            continue;
        }
        if let Some(rest) = line.strip_prefix("+++ ") {
            add(rest.strip_prefix("b/").unwrap_or(rest));
            continue;
        }
        if let Some(rest) = line.strip_prefix("--- ") {
            add(rest.strip_prefix("a/").unwrap_or(rest));
        }
    }
    out
}

/// Maps the binary policy decision + gate status to a clean ACCEPT/REJECT
/// verdict. `Action::Patch` with every evidence gate passed -> `"ACCEPT"`;
/// anything else (a denied finding routed to guidance, or a patch with a
/// failed/skipped gate) -> `"REJECT"`.
pub fn cap_verdict(action: Action, all_gates_passed: bool) -> &'static str {
    if action == Action::GuidanceOnly {
        return "REJECT";
    }
    if all_gates_passed {
        "ACCEPT"
    } else {
        "REJECT"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_diff_of_none_is_empty() {
        assert!(inspect_diff(None).is_empty());
    }

    #[test]
    fn inspect_diff_of_an_empty_string_is_empty() {
        assert!(inspect_diff(Some("")).is_empty());
    }

    #[test]
    fn inspect_diff_extracts_the_file_from_a_diff_git_header() {
        let diff = "diff --git a/src/app.py b/src/app.py\nindex 123..456 100644\n";
        assert_eq!(inspect_diff(Some(diff)), vec!["src/app.py".to_string()]);
    }

    #[test]
    fn inspect_diff_extracts_files_from_plus_and_minus_headers() {
        let diff = "--- a/old.py\n+++ b/new.py\n";
        assert_eq!(
            inspect_diff(Some(diff)),
            vec!["old.py".to_string(), "new.py".to_string()]
        );
    }

    #[test]
    fn inspect_diff_ignores_dev_null_on_either_side() {
        let diff = "--- /dev/null\n+++ b/new.py\n";
        assert_eq!(inspect_diff(Some(diff)), vec!["new.py".to_string()]);
    }

    #[test]
    fn inspect_diff_deduplicates_while_preserving_first_seen_order() {
        let diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n";
        assert_eq!(inspect_diff(Some(diff)), vec!["app.py".to_string()]);
    }

    #[test]
    fn inspect_diff_handles_multiple_files_in_one_diff() {
        let diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n\
                     diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n";
        assert_eq!(
            inspect_diff(Some(diff)),
            vec!["a.py".to_string(), "b.py".to_string()]
        );
    }

    #[test]
    fn cap_verdict_guidance_only_is_always_reject() {
        assert_eq!(cap_verdict(Action::GuidanceOnly, true), "REJECT");
        assert_eq!(cap_verdict(Action::GuidanceOnly, false), "REJECT");
    }

    #[test]
    fn cap_verdict_patch_with_all_gates_passed_is_accept() {
        assert_eq!(cap_verdict(Action::Patch, true), "ACCEPT");
    }

    #[test]
    fn cap_verdict_patch_with_a_failed_gate_is_reject() {
        assert_eq!(cap_verdict(Action::Patch, false), "REJECT");
    }
}
