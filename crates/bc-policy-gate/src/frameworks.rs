//! Per-file language + per-repo framework detection, ported from
//! `remediation_agent/frameworks.py`. The playbook resolves a fix strategy
//! on (CWE, language, framework); the language must come from the
//! *finding's file extension* (a repo's primary language is wrong for a
//! polyglot repo), and frameworks are inferred once per repo from
//! manifest files. Both are cheap, deterministic, and dependency-light —
//! deliberately a separate, coarser table from `bc-repo-analysis`'s own
//! language detection, which serves S3's different purpose.

use std::path::Path;

const EXT_LANG: &[(&str, &str)] = &[
    (".py", "python"),
    (".pyi", "python"),
    (".java", "java"),
    (".kt", "java"),
    (".scala", "java"),
    (".groovy", "java"),
    (".js", "javascript"),
    (".jsx", "javascript"),
    (".mjs", "javascript"),
    (".ts", "javascript"),
    (".tsx", "javascript"),
    (".cs", "csharp"),
    (".go", "go"),
    (".rb", "ruby"),
    (".php", "php"),
    (".c", "c"),
    (".h", "c"),
    (".cc", "cpp"),
    (".cpp", "cpp"),
    (".cxx", "cpp"),
    (".hpp", "cpp"),
    (".rs", "rust"),
];

/// Manifest file -> marker substring -> framework key (matches playbook
/// keys). Markers are matched lower-cased against the file's own
/// lower-cased content.
const MANIFESTS: &[(&str, &[(&str, &str)])] = &[
    (
        "requirements.txt",
        &[
            ("django", "django"),
            ("flask", "flask"),
            ("sqlalchemy", "sqlalchemy"),
            ("fastapi", "fastapi"),
        ],
    ),
    (
        "pyproject.toml",
        &[
            ("django", "django"),
            ("flask", "flask"),
            ("sqlalchemy", "sqlalchemy"),
            ("fastapi", "fastapi"),
        ],
    ),
    (
        "Pipfile",
        &[
            ("django", "django"),
            ("flask", "flask"),
            ("sqlalchemy", "sqlalchemy"),
        ],
    ),
    (
        "package.json",
        &[
            ("\"react\"", "react"),
            ("\"next\"", "react"),
            ("\"express\"", "express"),
            ("\"vue\"", "vue"),
            ("\"angular\"", "angular"),
        ],
    ),
    (
        "pom.xml",
        &[
            ("spring-boot", "spring"),
            ("<groupid>org.springframework", "spring"),
            ("hibernate", "hibernate"),
        ],
    ),
    (
        "build.gradle",
        &[("org.springframework", "spring"), ("spring-boot", "spring")],
    ),
    ("Gemfile", &[("rails", "rails"), ("sinatra", "sinatra")]),
    (
        "go.mod",
        &[("gin-gonic", "gin"), ("gorilla/mux", "gorilla")],
    ),
];

/// Playbook language key for `file_path`, or `"default"` if unrecognized.
pub fn language_for(file_path: &str) -> &'static str {
    let ext = Path::new(file_path)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()));
    ext.and_then(|e| {
        EXT_LANG
            .iter()
            .find(|(k, _)| *k == e)
            .map(|(_, lang)| *lang)
    })
    .unwrap_or("default")
}

/// Cheap manifest grep over the repo root and its immediate children. The
/// caller should cache the result for the run (it never changes mid-run).
pub fn detect_frameworks(repo_root: &Path) -> std::collections::BTreeSet<String> {
    let mut found = std::collections::BTreeSet::new();
    for (fname, markers) in MANIFESTS {
        for candidate in manifest_candidates(repo_root, fname) {
            let Ok(text) = std::fs::read_to_string(&candidate) else {
                continue;
            };
            let lower = text.to_lowercase();
            for (needle, fw) in *markers {
                if lower.contains(needle) {
                    found.insert((*fw).to_string());
                }
            }
        }
    }
    found
}

/// `repo_root/fname` plus every immediate child directory's `fname` —
/// mirrors Python's `root.glob(fname) + root.glob(f"*/{fname}")`.
fn manifest_candidates(repo_root: &Path, fname: &str) -> Vec<std::path::PathBuf> {
    let mut out = vec![repo_root.join(fname)];
    let Ok(entries) = std::fs::read_dir(repo_root) else {
        return out;
    };
    for entry in entries.flatten() {
        if entry.path().is_dir() {
            out.push(entry.path().join(fname));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_extensions_map_to_their_playbook_language() {
        assert_eq!(language_for("app.py"), "python");
        assert_eq!(language_for("Main.java"), "java");
        assert_eq!(language_for("Main.kt"), "java");
        assert_eq!(language_for("index.tsx"), "javascript");
        assert_eq!(language_for("Program.cs"), "csharp");
        assert_eq!(language_for("main.go"), "go");
        assert_eq!(language_for("app.rb"), "ruby");
        assert_eq!(language_for("index.php"), "php");
        assert_eq!(language_for("lib.c"), "c");
        assert_eq!(language_for("lib.cpp"), "cpp");
        assert_eq!(language_for("main.rs"), "rust");
    }

    #[test]
    fn extension_matching_is_case_insensitive() {
        assert_eq!(language_for("APP.PY"), "python");
    }

    #[test]
    fn an_unrecognized_extension_is_default() {
        assert_eq!(language_for("notes.txt"), "default");
    }

    #[test]
    fn no_extension_at_all_is_default() {
        assert_eq!(language_for("Makefile"), "default");
    }

    #[test]
    fn detect_frameworks_finds_a_root_level_manifest_marker() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "Django==4.2\n").unwrap();
        let fw = detect_frameworks(dir.path());
        assert!(fw.contains("django"));
    }

    #[test]
    fn detect_frameworks_finds_a_manifest_one_level_down() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("backend")).unwrap();
        std::fs::write(
            dir.path().join("backend/package.json"),
            r#"{"dependencies": {"express": "^4"}}"#,
        )
        .unwrap();
        let fw = detect_frameworks(dir.path());
        assert!(fw.contains("express"));
    }

    #[test]
    fn detect_frameworks_matches_are_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Gemfile"), "gem 'RAILS'\n").unwrap();
        let fw = detect_frameworks(dir.path());
        assert!(fw.contains("rails"));
    }

    #[test]
    fn detect_frameworks_returns_empty_for_a_repo_with_no_manifests() {
        let dir = tempfile::tempdir().unwrap();
        assert!(detect_frameworks(dir.path()).is_empty());
    }

    #[test]
    fn detect_frameworks_is_a_no_op_when_the_repo_root_does_not_exist() {
        let fw = detect_frameworks(Path::new("/does/not/exist"));
        assert!(fw.is_empty());
    }
}
