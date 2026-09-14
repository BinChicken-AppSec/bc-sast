//! The deterministic, no-LLM eligibility gate, ported from
//! `policy_gate/gate.py::RemediationGate.decide`. Evaluated in a fixed
//! order where an earlier rule always wins over a later one:
//!
//! 1. Missing/unparseable policy -> fail-closed to `GuidanceOnly`.
//! 2. Kill switch (env var or file) active -> `GuidanceOnly`, checked on
//!    every call, not cached.
//! 3. An unrecognized/unmapped CWE id -> `GuidanceOnly`.
//! 4. The CWE (or one of its declared descendants) is deny-listed ->
//!    `GuidanceOnly` — wins over everything below, including an
//!    otherwise-allowed CWE.
//! 5. The file path matches a `deny_paths` glob -> `GuidanceOnly` — a
//!    sensitive-subsystem guard that blocks even an allow-listed CWE.
//! 6. The CWE is allow-listed -> `Patch`.
//! 7. Otherwise, the policy's own `default_action`.

use std::path::Path;

use crate::cwe::norm_cwe;
use crate::loader::parse_policy;
use crate::matching::{first_match, glob_match};
use crate::types::{Decision, PolicyData};
use crate::Action;

pub struct RemediationGate {
    policy: Option<PolicyData>,
}

impl RemediationGate {
    /// Builds a gate from already-parsed policy data (e.g. for
    /// programmatic construction in tests, or a caller that loaded the
    /// file itself). `None` behaves exactly like a missing/unparseable
    /// file — fail-closed to `GuidanceOnly` on every decision.
    pub fn new(policy: Option<PolicyData>) -> Self {
        RemediationGate { policy }
    }

    /// Loads and parses a policy file from disk. A missing file, a
    /// network (UNC/`\\host\share`) path, or a parse failure all silently
    /// resolve to `Self::new(None)` — the gate's own
    /// fail-closed-on-every-decision behavior is the visible consequence,
    /// matching the Python original's "missing/unparseable policy" rule
    /// rather than surfacing a separate load-time error. The network-path
    /// check runs before any filesystem touch, since even a failed read
    /// would trigger Windows' SMB handshake and leak the caller's NTLMv2
    /// hash to a malicious UNC host.
    pub fn load(path: &Path) -> Self {
        if bc_pathjail::is_network_path(&path.to_string_lossy()) {
            return RemediationGate::new(None);
        }
        let policy = std::fs::read_to_string(path)
            .ok()
            .and_then(|text| parse_policy(&text).ok());
        RemediationGate::new(policy)
    }

    pub fn decide(
        &self,
        cwe_id: &str,
        file_path: &str,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Decision {
        let Some(policy) = &self.policy else {
            return Decision {
                action: Action::GuidanceOnly,
                reason: "no_policy_loaded".to_string(),
                matched_rule: None,
            };
        };

        if kill_switch_active(policy, getenv) {
            return Decision {
                action: Action::GuidanceOnly,
                reason: "kill_switch".to_string(),
                matched_rule: None,
            };
        }

        let Some(cwe) = norm_cwe(cwe_id) else {
            return Decision {
                action: Action::GuidanceOnly,
                reason: "unmapped_cwe".to_string(),
                matched_rule: None,
            };
        };

        if let Some(reason) = policy.deny.get(&cwe) {
            return Decision {
                action: Action::GuidanceOnly,
                reason: reason.clone(),
                matched_rule: Some(format!("deny:{cwe}")),
            };
        }

        let norm_path = file_path.replace('\\', "/");
        for pattern in &policy.deny_paths {
            if glob_match(&norm_path, pattern) {
                return Decision {
                    action: Action::GuidanceOnly,
                    reason: format!("sensitive_path:{pattern}"),
                    matched_rule: Some(format!("deny_path:{pattern}")),
                };
            }
        }

        if policy.allow.contains(&cwe) {
            return Decision {
                action: Action::Patch,
                reason: "allow_list".to_string(),
                matched_rule: Some(format!("allow:{cwe}")),
            };
        }

        Decision {
            action: policy.default_action,
            reason: "default_action".to_string(),
            matched_rule: None,
        }
    }

    pub fn deny_paths(&self) -> &[String] {
        self.policy
            .as_ref()
            .map(|p| p.deny_paths.as_slice())
            .unwrap_or(&[])
    }

    pub fn forbid_patch_paths(&self) -> &[String] {
        self.policy
            .as_ref()
            .map(|p| p.forbid_patch_paths.as_slice())
            .unwrap_or(&[])
    }

    /// The `forbid_patch_paths` glob a changed file hits, ported from
    /// `RemediationGate.patch_touches_forbidden`. The caller MUST revert
    /// the candidate — running build/test against an LLM-modified build
    /// script is arbitrary code execution on the scanner host.
    pub fn patch_touches_forbidden(&self, changed_files: &[String]) -> Option<String> {
        first_match(changed_files, self.forbid_patch_paths())
    }

    /// The `deny_paths` glob a changed file hits, ported from
    /// `RemediationGate.changed_paths_hit_deny`. The caller should revert
    /// that file and downgrade the verdict to guidance.
    pub fn changed_paths_hit_deny(&self, changed_files: &[String]) -> Option<String> {
        first_match(changed_files, self.deny_paths())
    }

    /// The subset of `changed_files` that hit `forbid_patch_paths` OR
    /// `deny_paths` — every file that must be reverted from disk, ported
    /// from `RemediationGate.forbidden_files`.
    pub fn forbidden_files(&self, changed_files: &[String]) -> Vec<String> {
        changed_files
            .iter()
            .filter(|f| !f.is_empty())
            .filter(|f| {
                let nf = f.replace('\\', "/");
                glob_match_any(&nf, self.forbid_patch_paths())
                    || glob_match_any(&nf, self.deny_paths())
            })
            .cloned()
            .collect()
    }
}

fn glob_match_any(path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| glob_match(path, p))
}

fn kill_switch_active(policy: &PolicyData, getenv: &dyn Fn(&str) -> Option<String>) -> bool {
    if let Some(env_name) = &policy.kill_env {
        let truthy = getenv(env_name)
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        if truthy {
            return true;
        }
    }
    policy.kill_file.as_deref().is_some_and(Path::exists)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn policy(mutate: impl FnOnce(&mut PolicyData)) -> PolicyData {
        let mut p = PolicyData {
            deny: BTreeMap::new(),
            allow: BTreeSet::new(),
            deny_paths: Vec::new(),
            forbid_patch_paths: Vec::new(),
            kill_env: None,
            kill_file: None,
            default_action: Action::GuidanceOnly,
        };
        mutate(&mut p);
        p
    }

    #[test]
    fn missing_policy_fails_closed() {
        let gate = RemediationGate::new(None);
        let d = gate.decide("CWE-89", "app.py", &no_env);
        assert_eq!(d.action, Action::GuidanceOnly);
        assert_eq!(d.reason, "no_policy_loaded");
    }

    #[test]
    fn no_env_helper_returns_none_when_called_directly() {
        // A direct, non-`&dyn Fn`-coerced call — `decide`'s own tests
        // above only ever reference `&no_env`, which some `cargo-llvm-cov`
        // builds don't reliably attribute back to this function's own
        // compiled body (the same class of coverage-attribution quirk
        // documented for identical trivial closures elsewhere in this
        // workspace).
        assert_eq!(no_env("ANYTHING"), None);
    }

    #[test]
    fn load_of_a_missing_file_fails_closed() {
        let gate = RemediationGate::load(Path::new("/does/not/exist.yaml"));
        let d = gate.decide("CWE-89", "app.py", &no_env);
        assert_eq!(d.action, Action::GuidanceOnly);
        assert_eq!(d.reason, "no_policy_loaded");
    }

    #[test]
    fn load_of_a_network_path_fails_closed_without_touching_the_filesystem() {
        let gate = RemediationGate::load(Path::new(r"\\attacker\share\policy.yaml"));
        let d = gate.decide("CWE-89", "app.py", &no_env);
        assert_eq!(d.action, Action::GuidanceOnly);
        assert_eq!(d.reason, "no_policy_loaded");
    }

    #[test]
    fn load_of_a_malformed_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "not: [a, valid\n").unwrap();
        let gate = RemediationGate::load(&path);
        let d = gate.decide("CWE-89", "app.py", &no_env);
        assert_eq!(d.reason, "no_policy_loaded");
    }

    #[test]
    fn load_of_a_real_file_parses_and_decides() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "default_action: allow\nallow:\n  - {id: CWE-89}\n").unwrap();
        let gate = RemediationGate::load(&path);
        let d = gate.decide("CWE-89", "app.py", &no_env);
        assert_eq!(d.action, Action::Patch);
        assert_eq!(d.matched_rule.as_deref(), Some("allow:CWE-89"));
    }

    #[test]
    fn kill_switch_env_var_truthy_wins_over_everything() {
        let p = policy(|p| {
            p.kill_env = Some("BC_KILL".to_string());
            p.allow.insert("CWE-89".to_string());
        });
        let gate = RemediationGate::new(Some(p));
        let getenv = |k: &str| (k == "BC_KILL").then(|| "true".to_string());
        let d = gate.decide("CWE-89", "app.py", &getenv);
        assert_eq!(d.action, Action::GuidanceOnly);
        assert_eq!(d.reason, "kill_switch");
    }

    #[test]
    fn kill_switch_env_var_falsy_value_does_not_trigger() {
        let p = policy(|p| {
            p.kill_env = Some("BC_KILL".to_string());
            p.allow.insert("CWE-89".to_string());
        });
        let gate = RemediationGate::new(Some(p));
        let getenv = |k: &str| (k == "BC_KILL").then(|| "0".to_string());
        let d = gate.decide("CWE-89", "app.py", &getenv);
        assert_eq!(d.action, Action::Patch);
    }

    #[test]
    fn kill_switch_file_presence_wins() {
        let dir = tempfile::tempdir().unwrap();
        let kill_file = dir.path().join("off");
        std::fs::write(&kill_file, "").unwrap();
        let p = policy(|p| {
            p.kill_file = Some(kill_file);
            p.allow.insert("CWE-89".to_string());
        });
        let gate = RemediationGate::new(Some(p));
        let d = gate.decide("CWE-89", "app.py", &no_env);
        assert_eq!(d.action, Action::GuidanceOnly);
        assert_eq!(d.reason, "kill_switch");
    }

    #[test]
    fn kill_switch_file_absent_does_not_trigger() {
        let dir = tempfile::tempdir().unwrap();
        let p = policy(|p| {
            p.kill_file = Some(dir.path().join("off"));
            p.allow.insert("CWE-89".to_string());
        });
        let gate = RemediationGate::new(Some(p));
        let d = gate.decide("CWE-89", "app.py", &no_env);
        assert_eq!(d.action, Action::Patch);
    }

    #[test]
    fn an_unmapped_cwe_fails_closed() {
        let p = policy(|p| p.default_action = Action::Patch);
        let gate = RemediationGate::new(Some(p));
        let d = gate.decide("not-a-cwe", "app.py", &no_env);
        assert_eq!(d.action, Action::GuidanceOnly);
        assert_eq!(d.reason, "unmapped_cwe");
    }

    #[test]
    fn deny_list_wins_over_an_allow_list_entry_for_the_same_cwe() {
        let p = policy(|p| {
            p.deny.insert("CWE-89".to_string(), "too risky".to_string());
            p.allow.insert("CWE-89".to_string());
        });
        let gate = RemediationGate::new(Some(p));
        let d = gate.decide("CWE-89", "app.py", &no_env);
        assert_eq!(d.action, Action::GuidanceOnly);
        assert_eq!(d.reason, "too risky");
        assert_eq!(d.matched_rule.as_deref(), Some("deny:CWE-89"));
    }

    #[test]
    fn a_sensitive_path_blocks_an_otherwise_allowed_cwe() {
        let p = policy(|p| {
            p.allow.insert("CWE-89".to_string());
            p.deny_paths = vec!["**/auth/**".to_string()];
        });
        let gate = RemediationGate::new(Some(p));
        let d = gate.decide("CWE-89", "src/auth/login.py", &no_env);
        assert_eq!(d.action, Action::GuidanceOnly);
        assert!(d.reason.starts_with("sensitive_path:"));
    }

    #[test]
    fn a_sensitive_path_pattern_also_matches_a_root_level_path() {
        // "**/auth/**" requires a literal '/' before "auth" once
        // translated by fnmatch — a root-level `auth/login.py` (nothing
        // before "auth" at all) must still match a pattern clearly meant
        // to catch it, matching the same root-level concern `glob_hit`
        // handles for exclude-globs elsewhere in this workspace.
        let p = policy(|p| {
            p.allow.insert("CWE-89".to_string());
            p.deny_paths = vec!["**/auth/**".to_string()];
        });
        let gate = RemediationGate::new(Some(p));
        let d = gate.decide("CWE-89", "auth/login.py", &no_env);
        assert_eq!(d.action, Action::GuidanceOnly);
    }

    #[test]
    fn an_allow_listed_cwe_on_a_non_sensitive_path_is_patchable() {
        let p = policy(|p| {
            p.allow.insert("CWE-89".to_string());
            p.deny_paths = vec!["**/auth/**".to_string()];
        });
        let gate = RemediationGate::new(Some(p));
        let d = gate.decide("CWE-89", "src/db/query.py", &no_env);
        assert_eq!(d.action, Action::Patch);
        assert_eq!(d.matched_rule.as_deref(), Some("allow:CWE-89"));
    }

    #[test]
    fn a_cwe_matching_neither_list_falls_through_to_the_default_action() {
        let p = policy(|p| p.default_action = Action::Patch);
        let gate = RemediationGate::new(Some(p));
        let d = gate.decide("CWE-999", "app.py", &no_env);
        assert_eq!(d.action, Action::Patch);
        assert_eq!(d.reason, "default_action");
        assert_eq!(d.matched_rule, None);
    }

    #[test]
    fn backslash_paths_are_normalized_before_glob_matching() {
        let p = policy(|p| {
            p.allow.insert("CWE-89".to_string());
            p.deny_paths = vec!["*auth*".to_string()];
        });
        let gate = RemediationGate::new(Some(p));
        let d = gate.decide("CWE-89", r"src\auth\login.py", &no_env);
        assert_eq!(d.action, Action::GuidanceOnly);
    }

    #[test]
    fn deny_paths_and_forbid_patch_paths_accessors_expose_the_loaded_policy() {
        let p = policy(|p| {
            p.deny_paths = vec!["**/auth/**".to_string()];
            p.forbid_patch_paths = vec!["**/ci/**".to_string()];
        });
        let gate = RemediationGate::new(Some(p));
        assert_eq!(gate.deny_paths(), &["**/auth/**".to_string()]);
        assert_eq!(gate.forbid_patch_paths(), &["**/ci/**".to_string()]);
    }

    #[test]
    fn deny_paths_and_forbid_patch_paths_are_empty_without_a_loaded_policy() {
        let gate = RemediationGate::new(None);
        assert!(gate.deny_paths().is_empty());
        assert!(gate.forbid_patch_paths().is_empty());
    }

    #[test]
    fn patch_touches_forbidden_returns_the_matching_glob() {
        let p = policy(|p| p.forbid_patch_paths = vec!["**/ci/**".to_string()]);
        let gate = RemediationGate::new(Some(p));
        assert_eq!(
            gate.patch_touches_forbidden(&[".github/ci/build.yml".to_string()]),
            Some("**/ci/**".to_string())
        );
        assert_eq!(gate.patch_touches_forbidden(&["app.py".to_string()]), None);
    }

    #[test]
    fn changed_paths_hit_deny_returns_the_matching_glob() {
        let p = policy(|p| p.deny_paths = vec!["**/auth/**".to_string()]);
        let gate = RemediationGate::new(Some(p));
        assert_eq!(
            gate.changed_paths_hit_deny(&["auth/login.py".to_string()]),
            Some("**/auth/**".to_string())
        );
        assert_eq!(gate.changed_paths_hit_deny(&["app.py".to_string()]), None);
    }

    #[test]
    fn forbidden_files_unions_forbid_and_deny_matches_and_normalizes_backslashes() {
        let p = policy(|p| {
            p.deny_paths = vec!["**/auth/**".to_string()];
            p.forbid_patch_paths = vec!["**/ci/**".to_string()];
        });
        let gate = RemediationGate::new(Some(p));
        let bad = gate.forbidden_files(&[
            "auth/login.py".to_string(),
            r"ci\build.yml".to_string(),
            "app.py".to_string(),
            "".to_string(),
        ]);
        assert_eq!(
            bad,
            vec!["auth/login.py".to_string(), r"ci\build.yml".to_string()]
        );
    }

    #[test]
    fn forbidden_files_is_empty_when_nothing_matches() {
        let gate = RemediationGate::new(Some(policy(|_| {})));
        assert!(gate.forbidden_files(&["app.py".to_string()]).is_empty());
    }

    #[test]
    fn may_generate_patch_is_true_only_for_the_patch_action() {
        assert!(Decision {
            action: Action::Patch,
            reason: String::new(),
            matched_rule: None,
        }
        .may_generate_patch());
        assert!(!Decision {
            action: Action::GuidanceOnly,
            reason: String::new(),
            matched_rule: None,
        }
        .may_generate_patch());
    }
}
