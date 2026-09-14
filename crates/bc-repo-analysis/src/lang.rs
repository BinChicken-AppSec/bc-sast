//! Extension-to-language classification, ported from
//! `vvaharness/lang/hints.py::EXT_TO_LANG`/`LANG_DISPLAY`/`is_iac_file`/
//! `_sniff_lang`/`detect_languages`. Shared by S1 (language-fallback vote),
//! S2 (evidence language breakdown), and S3 (chunk language tagging + the
//! `iac`/`batch-etl` specialist gates) — kept here rather than in any one
//! stage crate since it's a leaf fact about file extensions/paths/content,
//! not stage-specific business logic.

/// `EXT_TO_LANG`, transcribed 1:1 (132 entries, keyed on the dot-prefixed
/// lowercase extension). Returns the internal language key (e.g.
/// `"c-cpp"`), not a human-readable name — see [`lang_display`] for that.
pub fn ext_to_lang(ext: &str) -> Option<&'static str> {
    Some(match ext {
        ".aba" | ".abap" => "abap",
        ".ascx" | ".aspx" | ".cshtml" | ".ejs" | ".erb" | ".ftl" | ".ftlh" | ".haml"
        | ".handlebars" | ".hbs" | ".htm" | ".html" | ".j2" | ".jade" | ".jinja" | ".jinja2"
        | ".jsp" | ".jspf" | ".jspx" | ".liquid" | ".mako" | ".master" | ".mustache" | ".njk"
        | ".phtml" | ".pug" | ".rhtml" | ".slim" | ".svelte" | ".tag" | ".tagx" | ".twig"
        | ".vbhtml" | ".vm" | ".vtl" | ".vue" => "web-template",
        ".asm" | ".s" => "assembly",
        ".bas" | ".cls" | ".frm" | ".vb" | ".vbs" => "vbnet",
        ".bash" | ".sh" | ".zsh" => "shell",
        ".bat" | ".cmd" => "batch",
        ".bicep" => "bicep",
        ".c" | ".cc" | ".cpp" | ".cxx" | ".h" | ".hpp" => "c-cpp",
        ".cbl" | ".cob" | ".cpy" => "cobol",
        ".cjs" | ".js" | ".jsx" | ".mjs" => "javascript",
        ".clj" | ".cljc" | ".cljs" | ".edn" => "clojure",
        ".cr" => "crystal",
        ".cs" => "csharp",
        ".cts" | ".mts" | ".ts" | ".tsx" => "typescript",
        ".dart" => "dart",
        ".ddl" | ".dml" | ".fnc" | ".pkb" | ".pks" | ".plb" | ".pls" | ".plsql" | ".prc"
        | ".sql" | ".trg" | ".tsql" | ".vw" => "sql",
        ".erl" | ".hrl" => "erlang",
        ".ex" | ".exs" => "elixir",
        ".fs" | ".fsi" | ".fsx" => "fsharp",
        ".go" => "go",
        ".groovy" | ".gsh" | ".gvy" | ".gy" => "groovy",
        ".hcl" | ".tf" | ".tfvars" => "terraform",
        ".hs" | ".lhs" => "haskell",
        ".java" => "java",
        ".jcl" => "jcl",
        ".jl" => "julia",
        ".kt" | ".kts" => "kotlin",
        ".lua" => "lua",
        ".m" | ".mm" => "objective-c",
        ".ml" | ".mli" => "ocaml",
        ".nim" | ".nims" => "nim",
        ".php" => "php",
        ".pl" | ".pm" => "perl",
        ".ps1" | ".psd1" | ".psm1" => "powershell",
        ".py" => "python",
        ".r" => "r",
        ".rb" => "ruby",
        ".rs" => "rust",
        ".sc" | ".scala" => "scala",
        ".sol" => "solidity",
        ".swift" => "swift",
        ".zig" => "zig",
        _ => return None,
    })
}

/// `LANG_DISPLAY`, transcribed 1:1: human-readable name for an
/// [`ext_to_lang`] internal key (e.g. `"c-cpp"` -> `"C/C++"`). Falls back
/// to the raw key itself when unmapped (matching Python's
/// `LANG_DISPLAY.get(key, key)`) — every key `ext_to_lang` can produce has
/// an entry here, so that fallback is defensive, not exercised via the
/// extension-classification path.
///
/// `"c"` and `"cpp"` are the one addition to the Python table: they are
/// not `ext_to_lang` outputs, but `bc_stage_s4::hints::hint_key_for_path`
/// splits `"c-cpp"` into them per file to pick a research lens, and that
/// lens is labelled with this function.
pub fn lang_display(key: &str) -> &str {
    match key {
        "c-cpp" => "C/C++",
        "c" => "C",
        "cpp" => "C++",
        "rust" => "Rust",
        "go" => "Go",
        "python" => "Python",
        "java" => "Java",
        "javascript" => "JavaScript",
        "php" => "PHP",
        "ruby" => "Ruby",
        "objective-c" => "Objective-C",
        "kotlin" => "Kotlin",
        "csharp" => "C#/.NET",
        "perl" => "Perl",
        "swift" => "Swift",
        "scala" => "Scala",
        "cobol" => "COBOL",
        "jcl" => "JCL (z/OS)",
        "dart" => "Dart/Flutter",
        "elixir" => "Elixir",
        "erlang" => "Erlang",
        "groovy" => "Groovy",
        "lua" => "Lua",
        "r" => "R",
        "powershell" => "PowerShell",
        "shell" => "Shell (bash/sh)",
        "batch" => "Windows Batch (.cmd/.bat)",
        "web-template" => "Web Templates",
        "ansible" => "Ansible",
        "terraform" => "Terraform / HCL",
        "bicep" => "Azure Bicep",
        "dockerfile" => "Dockerfile",
        "jenkins" => "Jenkinsfile",
        "github-actions" => "GitHub Actions",
        "kubernetes" => "Kubernetes / Helm",
        "typescript" => "TypeScript",
        "sql" => "SQL / PL-SQL / T-SQL",
        "vbnet" => "Visual Basic / VB.NET",
        "abap" => "ABAP (SAP)",
        "clojure" => "Clojure",
        "haskell" => "Haskell",
        "ocaml" => "OCaml",
        "fsharp" => "F#",
        "julia" => "Julia",
        "solidity" => "Solidity",
        "assembly" => "Assembly",
        "zig" => "Zig",
        "nim" => "Nim",
        "crystal" => "Crystal",
        other => other,
    }
}

use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

/// `Path(f).suffix.lower()` equivalent: the last dot-extension including
/// the leading dot, or `""` for an extensionless/dotfile path — ported
/// from `callgraph_engine/__init__.py::_lang_of`'s `Path(rel).suffix.lower()`
/// call. The canonical, single copy of this helper: `bc-stage-s0`/`-s1`/
/// `-s2`/`-s3` all depend on this crate already and call this instead of
/// keeping their own copy, since a naive `rsplit_once('.')`-style
/// reimplementation (once present in `bc-stage-s0`) silently mishandles a
/// dotfile like `.gitignore` — treating the whole name as its own
/// extension instead of matching `Path::extension()`'s (and Python's
/// `pathlib.Path.suffix`'s) "no extension" answer.
pub fn suffix_lower(f: &str) -> String {
    Path::new(f)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default()
}

static ANSIBLE_PATH_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|/)(?:ansible|playbooks?|roles|inventories|group_vars|host_vars)(?:/|$)")
        .unwrap()
});
static ANSIBLE_BODY_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\s*-?\s*(hosts|tasks|handlers|become|gather_facts|ansible\.[\w.]+)\s*:")
        .unwrap()
});
static COBOL_BODY_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)IDENTIFICATION\s+DIVISION|PROCEDURE\s+DIVISION|WORKING-STORAGE\s+SECTION|^.{0,7}\d{2}\s+\S+.*\bPIC(?:TURE)?\s+[X9SVA]|^.{0,7}\d{2}\s+FILLER\b|\bCOPY\s+\w+\s*\.",
    )
    .unwrap()
});
static JCL_BODY_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^//\S*\s+(JOB|EXEC|DD|PROC)\b|^//\s*SYSIN\b").unwrap());
static MAINFRAME_PATH_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|/)(?:mvs[_-]?code|jcl|cntl|proclib|cobol|copybooks?|jobs)(?:/|$)")
        .unwrap()
});
static DOCKERFILE_NAME_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|/)(?:Dockerfile|Containerfile)(?:\.[\w.-]+)?$").unwrap()
});
static JENKINSFILE_NAME_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|/)Jenkinsfile(?:\.[\w.-]+)?$").unwrap());
static GHACTIONS_PATH_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$").unwrap());
static K8S_PATH_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|/)(?:k8s|kubernetes|helm|charts?|manifests?|deploy(?:ments?)?)/.+\.(?:ya?ml|tpl)$").unwrap()
});
static K8S_BODY_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^apiVersion:\s+\S+").unwrap());
static IAC_PATH_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|/)(?:Dockerfile|Containerfile|Jenkinsfile)(?:\.[\w.-]+)?$|(?:^|/)(?:docker-compose(?:[\w.-]*)?|Chart|kustomization|\.gitlab-ci|cloudbuild|azure-pipelines|buildspec|appspec|serverless)\.ya?ml$|\.(?:tf|tfvars|hcl|bicep)$|(?:^|/)\.github/workflows/[^/]+\.ya?ml$|(?:^|/)(?:k8s|kubernetes|helm|charts?|manifests?|deploy(?:ments?)?|cloudformation|cfn)/.+\.(?:ya?ml|tpl|json)$|(?:^|/)(?:ansible|playbooks?|roles|group_vars|host_vars)/.+\.ya?ml$",
    )
    .unwrap()
});

/// Path/filename-only check for Infrastructure-as-Code, CI, and container
/// config. No file I/O — safe to call per file from `_is_source`-equivalent
/// callers and from specialist gates. Ported from `hints.py::is_iac_file`.
pub fn is_iac_file(rel: &str) -> bool {
    IAC_PATH_RX.is_match(rel)
}

/// Read up to `n` bytes of `repo_root/rel`, lossily decoded — a byte-count
/// (not Python's character-count) cap, since this only feeds structural
/// header regexes (JCL/COBOL/Ansible/K8s markers) that appear reliably
/// within the first few hundred *bytes* of a well-formed file; unlike a
/// user-visible prompt excerpt, an off-by-a-few-bytes boundary here can't
/// change whether the regex matches. Empty string (not an error) on any
/// I/O failure, matching Python's own `except OSError: return ""`.
fn read_head(repo_root: &Path, rel: &str, n: usize) -> String {
    match std::fs::read(repo_root.join(rel)) {
        Ok(bytes) => String::from_utf8_lossy(&bytes[..bytes.len().min(n)]).into_owned(),
        Err(_) => String::new(),
    }
}

/// Classify files the extension map missed (or mis-bucketed as plain
/// config). Path-based first; falls back to a head-of-file content probe
/// when `repo_root` is supplied. Ported from `hints.py::_sniff_lang`.
fn sniff_lang(rel: &str, repo_root: Option<&Path>) -> Option<&'static str> {
    if DOCKERFILE_NAME_RX.is_match(rel) {
        return Some("dockerfile");
    }
    if JENKINSFILE_NAME_RX.is_match(rel) {
        return Some("jenkins");
    }
    if GHACTIONS_PATH_RX.is_match(rel) {
        return Some("github-actions");
    }

    let suffix = suffix_lower(rel);

    if suffix == ".yml" || suffix == ".yaml" {
        if ANSIBLE_PATH_RX.is_match(rel) {
            return Some("ansible");
        }
        if K8S_PATH_RX.is_match(rel) {
            return Some("kubernetes");
        }
        if let Some(root) = repo_root {
            let head = read_head(root, rel, 4096);
            if ANSIBLE_BODY_RX.is_match(&head) {
                return Some("ansible");
            }
            if K8S_BODY_RX.is_match(&head) {
                return Some("kubernetes");
            }
        }
        return None;
    }

    if !suffix.is_empty() {
        return None;
    }

    // Extension-less: mainframe sources commonly ship as PDS-member dumps.
    let head = if MAINFRAME_PATH_RX.is_match(rel) {
        repo_root.map(|root| read_head(root, rel, 4096))
    } else {
        repo_root.map(|root| read_head(root, rel, 1024))
    }?;
    if JCL_BODY_RX.is_match(&head) {
        return Some("jcl");
    }
    if COBOL_BODY_RX.is_match(&head) {
        return Some("cobol");
    }
    None
}

/// Ordered list of language keys present in `files`, most common first
/// (ties broken by first-occurrence order across `files` — a stable sort
/// over insertion order, matching Python's stable `sorted()` over
/// dict-insertion order). If `repo_root` is given, extension-less and
/// `.yml`/`.yaml` files are additionally content-sniffed (COBOL/JCL/
/// Ansible/Kubernetes). Ported from `hints.py::detect_languages`.
pub fn detect_languages(files: &[String], repo_root: Option<&Path>) -> Vec<&'static str> {
    let mut order: Vec<&'static str> = Vec::new();
    let mut counts: HashMap<&'static str, i64> = HashMap::new();
    for f in files {
        let suffix = suffix_lower(f);
        let mut lang = ext_to_lang(&suffix);
        if lang.is_none() || suffix == ".yml" || suffix == ".yaml" {
            lang = sniff_lang(f, repo_root).or(lang);
        }
        if let Some(lang) = lang {
            if !counts.contains_key(lang) {
                order.push(lang);
            }
            *counts.entry(lang).or_insert(0) += 1;
        }
    }
    let mut result: Vec<(&'static str, i64)> = order.into_iter().map(|k| (k, counts[k])).collect();
    result.sort_by_key(|&(_, c)| std::cmp::Reverse(c));
    result.into_iter().map(|(k, _)| k).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn suffix_lower_extracts_lowercase_dotted_extension() {
        assert_eq!(suffix_lower("src/Main.PY"), ".py");
        assert_eq!(suffix_lower("a/b.c/d.py"), ".py");
    }

    #[test]
    fn suffix_lower_is_empty_for_an_extensionless_file() {
        assert_eq!(suffix_lower("README"), "");
    }

    #[test]
    fn suffix_lower_is_empty_for_a_dotfile_not_a_self_referential_extension() {
        // The bug this consolidation fixed: a naive `rsplit_once('.')`
        // split treats the leading dot itself as a separator, returning
        // ".gitignore" as the "extension". `Path::extension()` (and
        // Python's `pathlib.Path.suffix`) correctly treat a leading-dot-
        // only filename as having no extension at all.
        assert_eq!(suffix_lower(".gitignore"), "");
        assert_eq!(suffix_lower(".env"), "");
    }

    #[rstest]
    #[case(".py", "python")]
    #[case(".rs", "rust")]
    #[case(".js", "javascript")]
    #[case(".ts", "typescript")]
    #[case(".java", "java")]
    #[case(".go", "go")]
    #[case(".c", "c-cpp")]
    #[case(".sql", "sql")]
    #[case(".html", "web-template")]
    fn ext_to_lang_known(#[case] ext: &str, #[case] expected: &str) {
        assert_eq!(ext_to_lang(ext), Some(expected));
    }

    #[test]
    fn ext_to_lang_unknown_is_none() {
        assert_eq!(ext_to_lang(".xyz123"), None);
        assert_eq!(ext_to_lang(""), None);
    }

    #[test]
    fn ext_to_lang_covers_every_table_entry() {
        let table: &[(&str, &str)] = &[
            (".aba", "abap"),
            (".abap", "abap"),
            (".ascx", "web-template"),
            (".asm", "assembly"),
            (".aspx", "web-template"),
            (".bas", "vbnet"),
            (".bash", "shell"),
            (".bat", "batch"),
            (".bicep", "bicep"),
            (".c", "c-cpp"),
            (".cbl", "cobol"),
            (".cc", "c-cpp"),
            (".cjs", "javascript"),
            (".clj", "clojure"),
            (".cljc", "clojure"),
            (".cljs", "clojure"),
            (".cls", "vbnet"),
            (".cmd", "batch"),
            (".cob", "cobol"),
            (".cpp", "c-cpp"),
            (".cpy", "cobol"),
            (".cr", "crystal"),
            (".cs", "csharp"),
            (".cshtml", "web-template"),
            (".cts", "typescript"),
            (".cxx", "c-cpp"),
            (".dart", "dart"),
            (".ddl", "sql"),
            (".dml", "sql"),
            (".edn", "clojure"),
            (".ejs", "web-template"),
            (".erb", "web-template"),
            (".erl", "erlang"),
            (".ex", "elixir"),
            (".exs", "elixir"),
            (".fnc", "sql"),
            (".frm", "vbnet"),
            (".fs", "fsharp"),
            (".fsi", "fsharp"),
            (".fsx", "fsharp"),
            (".ftl", "web-template"),
            (".ftlh", "web-template"),
            (".go", "go"),
            (".groovy", "groovy"),
            (".gsh", "groovy"),
            (".gvy", "groovy"),
            (".gy", "groovy"),
            (".h", "c-cpp"),
            (".haml", "web-template"),
            (".handlebars", "web-template"),
            (".hbs", "web-template"),
            (".hcl", "terraform"),
            (".hpp", "c-cpp"),
            (".hrl", "erlang"),
            (".hs", "haskell"),
            (".htm", "web-template"),
            (".html", "web-template"),
            (".j2", "web-template"),
            (".jade", "web-template"),
            (".java", "java"),
            (".jcl", "jcl"),
            (".jinja", "web-template"),
            (".jinja2", "web-template"),
            (".jl", "julia"),
            (".js", "javascript"),
            (".jsp", "web-template"),
            (".jspf", "web-template"),
            (".jspx", "web-template"),
            (".jsx", "javascript"),
            (".kt", "kotlin"),
            (".kts", "kotlin"),
            (".lhs", "haskell"),
            (".liquid", "web-template"),
            (".lua", "lua"),
            (".m", "objective-c"),
            (".mako", "web-template"),
            (".master", "web-template"),
            (".mjs", "javascript"),
            (".ml", "ocaml"),
            (".mli", "ocaml"),
            (".mm", "objective-c"),
            (".mts", "typescript"),
            (".mustache", "web-template"),
            (".nim", "nim"),
            (".nims", "nim"),
            (".njk", "web-template"),
            (".php", "php"),
            (".phtml", "web-template"),
            (".pkb", "sql"),
            (".pks", "sql"),
            (".pl", "perl"),
            (".plb", "sql"),
            (".pls", "sql"),
            (".plsql", "sql"),
            (".pm", "perl"),
            (".prc", "sql"),
            (".ps1", "powershell"),
            (".psd1", "powershell"),
            (".psm1", "powershell"),
            (".pug", "web-template"),
            (".py", "python"),
            (".r", "r"),
            (".rb", "ruby"),
            (".rhtml", "web-template"),
            (".rs", "rust"),
            (".s", "assembly"),
            (".sc", "scala"),
            (".scala", "scala"),
            (".sh", "shell"),
            (".slim", "web-template"),
            (".sol", "solidity"),
            (".sql", "sql"),
            (".svelte", "web-template"),
            (".swift", "swift"),
            (".tag", "web-template"),
            (".tagx", "web-template"),
            (".tf", "terraform"),
            (".tfvars", "terraform"),
            (".trg", "sql"),
            (".ts", "typescript"),
            (".tsql", "sql"),
            (".tsx", "typescript"),
            (".twig", "web-template"),
            (".vb", "vbnet"),
            (".vbhtml", "web-template"),
            (".vbs", "vbnet"),
            (".vm", "web-template"),
            (".vtl", "web-template"),
            (".vue", "web-template"),
            (".vw", "sql"),
            (".zig", "zig"),
            (".zsh", "shell"),
        ];
        assert_eq!(table.len(), 132);
        for (ext, expected) in table {
            assert_eq!(ext_to_lang(ext), Some(*expected), "mismatch for {ext}");
        }
    }

    #[test]
    fn lang_display_known_keys() {
        assert_eq!(lang_display("c-cpp"), "C/C++");
        assert_eq!(lang_display("python"), "Python");
        assert_eq!(lang_display("csharp"), "C#/.NET");
        // Not `ext_to_lang` outputs — the per-file split
        // `bc_stage_s4::hints::hint_key_for_path` makes of `"c-cpp"`.
        assert_eq!(lang_display("c"), "C");
        assert_eq!(lang_display("cpp"), "C++");
    }

    #[test]
    fn lang_display_falls_back_to_the_raw_key_when_unmapped() {
        assert_eq!(lang_display("totally-unknown-key"), "totally-unknown-key");
    }

    #[test]
    fn lang_display_covers_every_ext_to_lang_output_value() {
        let keys = [
            "abap",
            "web-template",
            "assembly",
            "vbnet",
            "shell",
            "batch",
            "bicep",
            "c-cpp",
            "cobol",
            "javascript",
            "clojure",
            "crystal",
            "csharp",
            "typescript",
            "dart",
            "sql",
            "erlang",
            "elixir",
            "fsharp",
            "go",
            "groovy",
            "terraform",
            "haskell",
            "java",
            "jcl",
            "julia",
            "kotlin",
            "lua",
            "objective-c",
            "ocaml",
            "nim",
            "php",
            "perl",
            "powershell",
            "python",
            "r",
            "ruby",
            "rust",
            "scala",
            "solidity",
            "swift",
            "zig",
        ];
        for key in keys {
            assert_ne!(lang_display(key), "", "missing display name for {key}");
        }
    }

    #[test]
    fn is_iac_file_matches_dockerfile_jenkinsfile_and_terraform() {
        assert!(is_iac_file("Dockerfile"));
        assert!(is_iac_file("docker/Dockerfile.prod"));
        assert!(is_iac_file("Jenkinsfile"));
        assert!(is_iac_file("infra/main.tf"));
        assert!(is_iac_file(".github/workflows/ci.yml"));
        assert!(is_iac_file("k8s/deployment.yaml"));
        assert!(is_iac_file("ansible/playbook.yml"));
        assert!(is_iac_file("docker-compose.yml"));
    }

    #[test]
    fn is_iac_file_rejects_unrelated_paths() {
        assert!(!is_iac_file("src/main.rs"));
        assert!(!is_iac_file("README.md"));
        assert!(!is_iac_file("data/values.yaml"));
    }

    #[test]
    fn sniff_lang_classifies_dockerfile_jenkinsfile_and_github_actions_by_path_only() {
        assert_eq!(sniff_lang("Dockerfile", None), Some("dockerfile"));
        assert_eq!(
            sniff_lang("build/Containerfile.ci", None),
            Some("dockerfile")
        );
        assert_eq!(sniff_lang("Jenkinsfile", None), Some("jenkins"));
        assert_eq!(
            sniff_lang(".github/workflows/ci.yml", None),
            Some("github-actions")
        );
    }

    #[test]
    fn sniff_lang_classifies_yaml_by_path_without_repo_root() {
        assert_eq!(sniff_lang("ansible/site.yml", None), Some("ansible"));
        assert_eq!(sniff_lang("k8s/deployment.yaml", None), Some("kubernetes"));
        assert_eq!(sniff_lang("config/values.yaml", None), None);
    }

    #[test]
    fn sniff_lang_yaml_falls_back_to_body_sniff_with_repo_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("misc.yml"),
            "hosts: all\ntasks:\n  - name: x\n",
        )
        .unwrap();
        assert_eq!(sniff_lang("misc.yml", Some(dir.path())), Some("ansible"));

        std::fs::write(dir.path().join("other.yml"), "apiVersion: v1\nkind: Pod\n").unwrap();
        assert_eq!(
            sniff_lang("other.yml", Some(dir.path())),
            Some("kubernetes")
        );

        std::fs::write(dir.path().join("plain.yml"), "key: value\n").unwrap();
        assert_eq!(sniff_lang("plain.yml", Some(dir.path())), None);
    }

    #[test]
    fn sniff_lang_returns_none_for_a_known_non_yaml_suffix() {
        assert_eq!(sniff_lang("src/main.rs", None), None);
    }

    #[test]
    fn sniff_lang_extensionless_without_repo_root_is_none() {
        assert_eq!(sniff_lang("makefile_helper", None), None);
    }

    #[test]
    fn sniff_lang_extensionless_mainframe_path_sniffs_jcl_and_cobol() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("jcl")).unwrap();
        std::fs::write(
            dir.path().join("jcl/RUNJOB"),
            "//RUNJOB JOB (ACCT),'x'\n//STEP1 EXEC PGM=IEFBR14\n",
        )
        .unwrap();
        assert_eq!(sniff_lang("jcl/RUNJOB", Some(dir.path())), Some("jcl"));

        std::fs::create_dir_all(dir.path().join("cobol")).unwrap();
        std::fs::write(
            dir.path().join("cobol/PROG"),
            "       IDENTIFICATION DIVISION.\n       PROGRAM-ID. PROG.\n",
        )
        .unwrap();
        assert_eq!(sniff_lang("cobol/PROG", Some(dir.path())), Some("cobol"));
    }

    #[test]
    fn sniff_lang_extensionless_non_mainframe_path_still_sniffs_via_broader_fallback() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("SOMEPROG"),
            "       IDENTIFICATION DIVISION.\n",
        )
        .unwrap();
        assert_eq!(sniff_lang("SOMEPROG", Some(dir.path())), Some("cobol"));
    }

    #[test]
    fn sniff_lang_extensionless_unreadable_file_yields_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(sniff_lang("does-not-exist", Some(dir.path())), None);
    }

    #[test]
    fn detect_languages_counts_and_sorts_descending_with_first_seen_tiebreak() {
        let files = vec![
            "a.rs".to_string(),
            "b.py".to_string(),
            "c.rs".to_string(),
            "d.py".to_string(),
            "e.rs".to_string(),
        ];
        assert_eq!(detect_languages(&files, None), vec!["rust", "python"]);
    }

    #[test]
    fn detect_languages_content_sniffs_yaml_when_repo_root_given() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("site.yml"),
            "hosts: all\ntasks:\n  - name: x\n",
        )
        .unwrap();
        let files = vec!["site.yml".to_string()];
        assert_eq!(detect_languages(&files, Some(dir.path())), vec!["ansible"]);
    }

    #[test]
    fn detect_languages_ignores_files_with_no_recognized_language() {
        let files = vec!["README".to_string(), "LICENSE".to_string()];
        assert!(detect_languages(&files, None).is_empty());
    }
}
