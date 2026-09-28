//! Representative configuration files and their redacted contents, ported
//! from upstream v1.4.0 `s2_threatmodel.py::_select_config_reps`/
//! `_config_rep_contents`.
//!
//! This block is the one place S2 sends raw configuration content to the
//! model, and configuration files are the files most likely to carry
//! credentials. So every body is read through the containment check,
//! redacted in FULL, and only then cut to `max_config_rep_chars`: capping
//! first could bisect a secret straddling the cap so that its surviving
//! prefix matches no redaction pattern and a partial credential egresses
//! under a header that advertises the content as redacted.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use crate::repo_read::{cap_text, read_contained};

const CONFIG_EXTS: &[&str] = &[
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".properties",
    ".conf",
    ".cfg",
    ".env",
];

/// Well-known security-relevant descriptor and configuration file names
/// (lower-case). Mirrors upstream `lang/hints.py::SECURITY_CONFIG_NAMES`,
/// the same list `bc-stage-s3` keeps privately in `source.rs`; keep the
/// two in step.
const SECURITY_CONFIG_NAMES: &[&str] = &[
    "web.xml",
    "struts.xml",
    "struts-config.xml",
    "applicationcontext.xml",
    "spring-security.xml",
    "beans.xml",
    "faces-config.xml",
    "shiro.ini",
    "security.xml",
    "ejb-jar.xml",
    "jboss-web.xml",
    "weblogic.xml",
    "androidmanifest.xml",
    "info.plist",
    "application.properties",
    "application.yml",
    "application.yaml",
    "appsettings.json",
    "web.config",
    "app.config",
];

/// Raw read ceiling for a body: far above the useful cap, and floored at
/// four times an operator-raised cap because redaction can lengthen text.
/// A file over it goes path-only rather than being cut before redaction.
const CONFIG_REP_RAW_CEILING: usize = 500_000;

fn base_name_lower(rel: &str) -> String {
    rel.rsplit('/').next().unwrap_or(rel).to_lowercase()
}

fn is_security_name(rel: &str) -> bool {
    SECURITY_CONFIG_NAMES.contains(&base_name_lower(rel).as_str())
}

/// Representative configuration files, one per IMMEDIATE parent directory
/// per round, breadth-first, capped at `max_reps`.
///
/// Deduplicating by top-level directory (the previous behavior) collapsed
/// a whole monorepo to one representative, because every
/// `services/<n>/config.yml` shares the top-level `services`. Within a
/// directory a security-relevant name is preferred. A name in
/// [`SECURITY_CONFIG_NAMES`] is selectable even when its extension
/// (`.xml`, `.config`, `.plist`) is not a config extension, or the
/// canonical TLS and authorization config of Java, .NET and mobile stacks
/// could never be chosen.
pub(crate) fn select_config_reps(full_files: &[String], max_reps: usize) -> Vec<String> {
    let mut by_dir: BTreeMap<&str, Vec<&String>> = BTreeMap::new();
    for rel in full_files {
        let ext = bc_repo_analysis::suffix_lower(rel);
        let name = base_name_lower(rel);
        if CONFIG_EXTS.contains(&ext.as_str())
            || CONFIG_EXTS.contains(&name.as_str())
            || SECURITY_CONFIG_NAMES.contains(&name.as_str())
        {
            let parent = rel.rsplit_once('/').map_or("", |(dir, _)| dir);
            by_dir.entry(parent).or_default().push(rel);
        }
    }
    for files in by_dir.values_mut() {
        files.sort_by_key(|f| (!is_security_name(f), (*f).clone()));
    }
    let mut reps = Vec::new();
    let mut round = 0;
    while reps.len() < max_reps {
        let mut added = false;
        for files in by_dir.values() {
            if let Some(f) = files.get(round) {
                reps.push((*f).clone());
                added = true;
                if reps.len() >= max_reps {
                    break;
                }
            }
        }
        if !added {
            break;
        }
        round += 1;
    }
    reps
}

/// Pair each representative with a redacted, capped body. Bodies go to
/// the first `max_bodies` paths ranked security-relevant names first (a
/// stable sort, so breadth order holds within each group); the rest stay
/// path-only with an empty body, keeping the full breadth of the selection
/// visible. `cap_chars == 0` means path-only throughout. Output order is
/// `rel_paths` order.
pub(crate) fn config_rep_contents(
    root: &Path,
    rel_paths: &[String],
    cap_chars: usize,
    max_bodies: usize,
) -> Vec<(String, String)> {
    let read_ceiling = CONFIG_REP_RAW_CEILING.max(cap_chars.saturating_mul(4));
    let mut ranked: Vec<&String> = rel_paths.iter().collect();
    ranked.sort_by_key(|r| !is_security_name(r));
    let with_bodies: HashSet<&String> = ranked.into_iter().take(max_bodies).collect();
    rel_paths
        .iter()
        .map(|rel| {
            let mut body = String::new();
            if cap_chars > 0 && with_bodies.contains(rel) {
                // Whole or nothing: `redact` must see the intact file.
                let raw = read_contained(root, rel, read_ceiling, true);
                if !raw.is_empty() {
                    body = cap_text(&bc_redact::redact(&raw), cap_chars);
                }
            }
            (rel.clone(), body)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn files(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn each_immediate_parent_directory_gets_its_own_slot_breadth_first() {
        let all = files(&[
            "services/a/config.yml",
            "services/a/extra.yml",
            "services/b/config.yml",
            ".env",
            "src/app.py",
        ]);
        assert_eq!(
            select_config_reps(&all, 10),
            files(&[
                ".env",
                "services/a/config.yml",
                "services/b/config.yml",
                "services/a/extra.yml",
            ])
        );
        assert_eq!(select_config_reps(&all, 2).len(), 2);
        assert!(select_config_reps(&all, 0).is_empty());
    }

    #[test]
    fn security_names_are_preferred_and_selectable_without_a_config_extension() {
        let all = files(&[
            "WEB-INF/aaa.yml",
            "WEB-INF/web.xml",
            "ios/Info.plist",
            "src/Main.java",
        ]);
        let reps = select_config_reps(&all, 10);
        assert_eq!(
            reps,
            files(&["WEB-INF/web.xml", "ios/Info.plist", "WEB-INF/aaa.yml"])
        );
    }

    #[test]
    fn bodies_are_redacted_before_they_are_capped() {
        let dir = tempfile::tempdir().unwrap();
        // The AWS key straddles the 30-char cap: capping first would leave
        // "AKIAABCD..." unrecognizable and so unredacted.
        let key = format!("AKIA{}", "ABCDEFGHIJKLMNOP");
        write(
            dir.path(),
            "conf/app.yml",
            &format!("aws_access_key: {key}\n"),
        );
        let out = config_rep_contents(dir.path(), &files(&["conf/app.yml"]), 30, 12);
        let body = &out[0].1;
        assert!(!body.contains("AKIA"), "{body}");
        assert!(body.contains("…(truncated,"), "{body}");
    }

    #[test]
    fn a_zero_cap_is_path_only_and_bodies_are_limited_to_max_bodies() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a/x.yml", "a: 1");
        write(dir.path(), "b/web.xml", "<web/>");
        let reps = files(&["a/x.yml", "b/web.xml"]);
        let none = config_rep_contents(dir.path(), &reps, 0, 12);
        assert!(none.iter().all(|(_, b)| b.is_empty()));

        let one = config_rep_contents(dir.path(), &reps, 100, 1);
        // The security-relevant name wins the single body slot, and the
        // output keeps the caller's order.
        assert_eq!(one[0], ("a/x.yml".to_string(), String::new()));
        assert_eq!(one[1], ("b/web.xml".to_string(), "<web/>".to_string()));
    }

    #[test]
    fn unreadable_escaping_or_oversized_bodies_stay_path_only() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "big.yml",
            &"x".repeat(CONFIG_REP_RAW_CEILING + 1),
        );
        let reps = files(&["missing.yml", "../escape.yml", "big.yml"]);
        let out = config_rep_contents(dir.path(), &reps, 2000, 12);
        assert!(out.iter().all(|(_, b)| b.is_empty()), "{out:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_config_symlink_escaping_the_repo_is_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(outside.path(), "shadow.yml", "password: hunter2");
        std::os::unix::fs::symlink(
            outside.path().join("shadow.yml"),
            dir.path().join("app.yml"),
        )
        .unwrap();
        let out = config_rep_contents(dir.path(), &files(&["app.yml"]), 2000, 12);
        assert_eq!(out, vec![("app.yml".to_string(), String::new())]);
    }
}
