use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use crate::repo_read::{cap_text, read_contained};

pub(crate) const MANIFEST_CANDIDATES: &[&str] = &[
    "package.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "setup.py",
    "pyproject.toml",
    "requirements.txt",
    "go.mod",
    "Cargo.toml",
    "Gemfile",
    "composer.json",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".csproj",
];

const MANIFEST_RAW_CEILING: usize = 500_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ManifestCaps {
    pub per_file_chars: usize,
    pub total_chars: usize,
    pub max_depth: usize,
    pub max_total: usize,
    pub max_per_kind: usize,
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}

fn rel_of(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|r| r.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default()
}

fn manifests_in(root: &Path, dir: &Path) -> Vec<(&'static str, String)> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    let mut out = Vec::new();
    for kind in MANIFEST_CANDIDATES {
        for name in names.iter().filter(|n| match kind.strip_prefix('.') {
            Some(_) => n.ends_with(kind),
            None => n == kind,
        }) {
            let rel = rel_of(root, &dir.join(name));
            let contained = appsec_pathjail::confine(root, &rel).is_some_and(|p| p.is_file());
            if contained {
                out.push((*kind, rel));
            }
        }
    }
    out
}

fn walk(
    root: &Path,
    dir: &Path,
    depth: usize,
    max_depth: usize,
    hits: &mut BTreeMap<&'static str, Vec<String>>,
) {
    for (kind, rel) in manifests_in(root, dir) {
        hits.entry(kind).or_default().push(rel);
    }
    if depth >= max_depth {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut children: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| is_real_dir(p))
        .collect();
    children.sort();
    for child in children {
        let name = child
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if appsec_repo_analysis::DEFAULT_EXCLUDE_DIRS.contains(&name.as_str()) {
            continue;
        }
        walk(root, &child, depth + 1, max_depth, hits);
    }
}

pub(crate) fn find_manifests(
    root: &Path,
    max_depth: usize,
    max_total: usize,
    max_per_kind: usize,
) -> Vec<(&'static str, String)> {
    let mut hits: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    walk(root, root, 0, max_depth, &mut hits);
    let ordered: Vec<(&'static str, Vec<String>)> = MANIFEST_CANDIDATES
        .iter()
        .filter_map(|k| {
            hits.remove(k)
                .map(|v| (*k, v.into_iter().take(max_per_kind).collect()))
        })
        .collect();
    let mut selected = Vec::new();
    let mut round = 0;
    while selected.len() < max_total {
        let mut added = false;
        for (kind, paths) in &ordered {
            if let Some(rel) = paths.get(round) {
                selected.push((*kind, rel.clone()));
                added = true;
                if selected.len() >= max_total {
                    break;
                }
            }
        }
        if !added {
            break;
        }
        round += 1;
    }
    selected
}

fn json_keep(raw: &str, keys: &[&str]) -> Option<String> {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(raw) else {
        return None;
    };
    let keep: BTreeMap<&String, &Value> = map
        .iter()
        .filter(|(k, _)| keys.contains(&k.as_str()))
        .collect();
    if keep.is_empty() {
        return None;
    }
    serde_json::to_string_pretty(&keep).ok()
}

fn toml_header(line: &str) -> Option<&str> {
    let t = line.trim();
    if t.starts_with("[[") {
        return Some("");
    }
    let inner = t.strip_prefix('[')?.split(']').next()?;
    Some(inner.trim())
}

fn bracket_delta(line: &str) -> i64 {
    let mut depth = 0i64;
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => quote = Some(c),
            (None, '#') => break,
            (None, '[' | '{') => depth += 1,
            (None, ']' | '}') => depth -= 1,
            _ => {}
        }
    }
    depth
}

fn pyproject_keep(raw: &str) -> Option<String> {
    const PROJECT_KEYS: &[&str] = &["name", "version", "dependencies", "optional-dependencies"];
    const WHOLE_TABLES: &[&str] = &["project.optional-dependencies", "tool.poetry.dependencies"];
    let mut out: Vec<&str> = Vec::new();
    let mut table = String::new();
    let mut in_value = 0i64;
    for line in raw.lines() {
        if in_value > 0 {
            out.push(line);
            in_value += bracket_delta(line);
            continue;
        }
        if let Some(header) = toml_header(line) {
            table = header.to_string();
            if WHOLE_TABLES.contains(&header) || header == "project" {
                out.push(line);
            }
            continue;
        }
        if WHOLE_TABLES.contains(&table.as_str()) {
            out.push(line);
        } else if table == "project" {
            let key = line.split('=').next().unwrap_or("").trim();
            if line.contains('=') && PROJECT_KEYS.contains(&key) {
                out.push(line);
                in_value = bracket_delta(line).max(0);
            }
        }
    }
    let kept: Vec<&str> = out.into_iter().filter(|l| !l.trim().is_empty()).collect();
    let has_body = kept.iter().any(|l| toml_header(l).is_none());
    has_body.then(|| kept.join("\n"))
}

pub(crate) fn structural_truncate(kind: &str, raw: &str, cap: usize) -> String {
    let kept = match kind {
        "package.json" | "composer.json" => json_keep(
            raw,
            &[
                "name",
                "version",
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "require",
                "require-dev",
                "scripts",
            ],
        ),
        "pyproject.toml" => pyproject_keep(raw),
        _ => None,
    };
    cap_text(kept.as_deref().unwrap_or(raw), cap)
}

pub(crate) fn apply_total_cap(
    manifests: Vec<(String, String)>,
    total: usize,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut remaining = total as i64;
    for (name, mut text) in manifests {
        if remaining <= 0 {
            break;
        }
        let len = text.chars().count() as i64;
        if len > remaining {
            text = cap_text(&text, remaining as usize);
        }
        remaining -= text.chars().count() as i64;
        out.push((name, text));
    }
    out
}

pub(crate) fn gather_manifests(root: &Path, caps: ManifestCaps) -> Vec<(String, String)> {
    let per_kind = caps.max_per_kind.max(1);
    let found = find_manifests(root, caps.max_depth, caps.max_total, per_kind);
    let mut bodies = Vec::new();
    for (kind, rel) in found {
        let raw = read_contained(root, &rel, MANIFEST_RAW_CEILING, false);
        if raw.is_empty() {
            continue;
        }
        bodies.push((rel, structural_truncate(kind, &raw, caps.per_file_chars)));
    }
    apply_total_cap(bodies, caps.total_chars)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn caps() -> ManifestCaps {
        ManifestCaps {
            per_file_chars: 4000,
            total_chars: 24_000,
            max_depth: 3,
            max_total: 12,
            max_per_kind: 2,
        }
    }

    #[test]
    fn manifests_are_found_below_the_root_up_to_the_depth_limit() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "package.json", "{}");
        write(dir.path(), "services/a/pom.xml", "<p/>");
        write(dir.path(), "a/b/c/go.mod", "module x");
        write(dir.path(), "a/b/c/d/Gemfile", "gem 'rails'");
        let found = find_manifests(dir.path(), 3, 12, 2);
        assert_eq!(
            found,
            vec![
                ("package.json", "package.json".to_string()),
                ("pom.xml", "services/a/pom.xml".to_string()),
                ("go.mod", "a/b/c/go.mod".to_string()),
            ]
        );
    }

    #[test]
    fn excluded_directories_are_not_searched() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "node_modules/pkg/package.json", "{}");
        write(dir.path(), "vendor/x/go.mod", "module x");
        assert!(find_manifests(dir.path(), 3, 12, 2).is_empty());
    }

    #[test]
    fn kinds_are_capped_then_taken_round_robin() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..4 {
            write(dir.path(), &format!("p{i}/package.json"), "{}");
        }
        write(dir.path(), "svc/pom.xml", "<p/>");
        write(dir.path(), "a.csproj", "<P/>");
        write(dir.path(), "b.csproj", "<P/>");
        let found = find_manifests(dir.path(), 3, 12, 2);
        let kinds: Vec<&str> = found.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            kinds,
            vec![
                "package.json",
                "pom.xml",
                ".csproj",
                "package.json",
                ".csproj"
            ]
        );
        assert_eq!(found[0].1, "p0/package.json");
        assert_eq!(found[3].1, "p1/package.json");

        let capped = find_manifests(dir.path(), 3, 2, 2);
        assert_eq!(capped.len(), 2);
        assert_eq!(capped[1].0, "pom.xml");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_directories_and_escaping_files_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(outside.path(), "evil.csproj", "<P/>");
        write(outside.path(), "go.mod", "module evil");
        std::os::unix::fs::symlink(outside.path(), dir.path().join("linked")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("go.mod"), dir.path().join("go.mod"))
            .unwrap();
        assert!(find_manifests(dir.path(), 3, 12, 2).is_empty());
        assert!(gather_manifests(dir.path(), caps()).is_empty());
    }

    #[test]
    fn a_directory_named_like_a_manifest_is_not_a_hit() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("x.csproj")).unwrap();
        assert!(find_manifests(dir.path(), 0, 12, 2).is_empty());
    }

    #[test]
    fn a_missing_root_finds_nothing() {
        assert!(find_manifests(Path::new("/nonexistent/bc-s2-root"), 3, 12, 2).is_empty());
    }

    #[test]
    fn package_json_keeps_only_dependency_sections() {
        let raw = r#"{"description": "long prose", "name": "app", "dependencies": {"express": "^4"}, "private": true}"#;
        let out = structural_truncate("package.json", raw, 4000);
        assert!(out.contains("\"express\""));
        assert!(out.contains("\"name\": \"app\""));
        assert!(!out.contains("long prose"));
        assert!(
            out.find("dependencies").unwrap() < out.find("name").unwrap(),
            "sorted keys"
        );
    }

    #[test]
    fn json_without_kept_keys_or_unparseable_falls_back_to_a_prefix_cap() {
        assert_eq!(
            structural_truncate("package.json", r#"{"a": 1}"#, 100),
            r#"{"a": 1}"#
        );
        assert_eq!(
            structural_truncate("composer.json", "[1, 2]", 100),
            "[1, 2]"
        );
        assert_eq!(
            structural_truncate("package.json", "{broken", 3),
            "{br\n…(truncated, 7 chars total)"
        );
        assert_eq!(structural_truncate("pom.xml", "<x/>", 100), "<x/>");
    }

    #[test]
    fn pyproject_keeps_project_dependencies_and_poetry_tables() {
        let raw = "\
[build-system]
requires = [\"setuptools\"]

[project]
name = \"app\"
description = \"skip me\"
dependencies = [
  \"django>=4\",  # web framework [pinned]
  \"requests\",
]
readme = \"README.md\"

[project.optional-dependencies]
dev = [\"pytest\"]

[tool.black]
line-length = 88

[tool.poetry.dependencies]
flask = \"^2\"

[[tool.mypy.overrides]]
module = \"x\"
";
        let out = structural_truncate("pyproject.toml", raw, 4000);
        assert_eq!(
            out,
            "\
[project]
name = \"app\"
dependencies = [
  \"django>=4\",  # web framework [pinned]
  \"requests\",
]
[project.optional-dependencies]
dev = [\"pytest\"]
[tool.poetry.dependencies]
flask = \"^2\""
        );
    }

    #[test]
    fn pyproject_with_nothing_recognized_falls_back_to_the_raw_prefix() {
        let raw = "[tool.black]\nline-length = 88\n[project]\n";
        assert_eq!(structural_truncate("pyproject.toml", raw, 1000), raw);
    }

    #[test]
    fn bracket_delta_ignores_quoted_and_commented_brackets() {
        assert_eq!(bracket_delta("x = [ \"a]\", 'b[' # ]]"), 1);
        assert_eq!(bracket_delta("]"), -1);
        assert_eq!(bracket_delta("{ a = 1 }"), 0);
    }

    #[test]
    fn toml_header_recognizes_tables_and_array_tables() {
        assert_eq!(toml_header("[project]"), Some("project"));
        assert_eq!(toml_header("  [ tool.poetry ]  "), Some("tool.poetry"));
        assert_eq!(toml_header("[[x]]"), Some(""));
        assert_eq!(toml_header("name = 1"), None);
    }

    #[test]
    fn the_total_cap_truncates_the_straddling_manifest_and_drops_the_rest() {
        let bodies = vec![
            ("a".to_string(), "x".repeat(6)),
            ("b".to_string(), "y".repeat(6)),
            ("c".to_string(), "z".repeat(6)),
        ];
        let out = apply_total_cap(bodies, 10);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].1, "xxxxxx");
        assert_eq!(out[1].1, "yyyy\n…(truncated, 6 chars total)");
        assert!(apply_total_cap(vec![("a".into(), "x".into())], 0).is_empty());
    }

    #[test]
    fn gather_manifests_reads_truncates_and_caps() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"name": "app", "readme": "long", "dependencies": {"koa": "2"}}"#,
        );
        write(dir.path(), "svc/requirements.txt", "flask==2\n");
        write(dir.path(), "empty/go.mod", "");
        let out = gather_manifests(dir.path(), caps());
        assert_eq!(out.len(), 2, "an empty manifest is skipped: {out:?}");
        assert_eq!(out[0].0, "package.json");
        assert!(out[0].1.contains("koa") && !out[0].1.contains("readme"));
        assert_eq!(
            out[1],
            ("svc/requirements.txt".to_string(), "flask==2\n".to_string())
        );
    }
}
