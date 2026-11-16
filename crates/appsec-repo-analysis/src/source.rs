use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::lang::{ext_to_lang, is_iac_file, suffix_lower};

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

const SECURITY_CONFIG_EXTS: &[&str] = &[".xml", ".properties"];
const SECURITY_CONFIG_DIR_SEGMENTS: &[&str] =
    &["web-inf", "meta-inf", "resources", "conf", "config"];

fn file_name_lower(f: &str) -> String {
    Path::new(f)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(f)
        .to_lowercase()
}

pub fn is_source(f: &str) -> bool {
    let name = file_name_lower(f);
    if name.ends_with(".d.ts") {
        return false;
    }
    let ext = suffix_lower(f);
    if ext_to_lang(&ext).is_some() {
        return true;
    }
    if SECURITY_CONFIG_NAMES.contains(&name.as_str()) {
        return true;
    }
    if SECURITY_CONFIG_EXTS.contains(&ext.as_str()) {
        let lower = f.to_lowercase();
        return lower
            .split('/')
            .any(|seg| SECURITY_CONFIG_DIR_SEGMENTS.contains(&seg));
    }
    is_iac_file(f)
}

const BASENAME_LANG: &[(&str, &str)] = &[
    ("makefile", "make"),
    ("dockerfile", "docker"),
    ("jenkinsfile", "groovy"),
    ("procfile", "shell"),
    ("gemfile", "ruby"),
    ("rakefile", "ruby"),
    ("cmakelists.txt", "cmake"),
];

static SHEBANG_LANG_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^#!\S*/(?:env\s+)?(python\d?|bash|sh|zsh|ruby|perl|node)\b").unwrap()
});

fn shebang_lang(interp: &str) -> &'static str {
    match interp {
        "python" | "python2" | "python3" => "python",
        "bash" | "sh" | "zsh" => "shell",
        "ruby" => "ruby",
        "perl" => "perl",
        _ => "javascript",
    }
}

const SHEBANG_PROBE_BYTES: u64 = 256;

fn first_line(repo_root: &Path, rel: &str) -> String {
    let Some(path) = appsec_pathjail::confine(repo_root, rel) else {
        return String::new();
    };
    let Ok(file) = std::fs::File::open(path) else {
        return String::new();
    };
    let mut line = Vec::new();
    let _ = BufReader::new(file.take(SHEBANG_PROBE_BYTES)).read_until(b'\n', &mut line);
    String::from_utf8_lossy(&line).into_owned()
}

pub fn lang_of_file(f: &str, repo_root: Option<&Path>) -> Option<&'static str> {
    if let Some(lang) = ext_to_lang(&suffix_lower(f)) {
        return Some(lang);
    }
    let name = file_name_lower(f);
    if let Some((_, lang)) = BASENAME_LANG.iter().find(|(n, _)| *n == name) {
        return Some(lang);
    }
    if name.starts_with(".env") {
        return Some("dotenv");
    }
    let root = repo_root?;
    let line = first_line(root, f);
    SHEBANG_LANG_RX
        .captures(&line)
        .map(|caps| shebang_lang(&caps[1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognized_extension_is_source() {
        assert!(is_source("src/app.py"));
        assert!(is_source("src/app.rs"));
        assert!(is_source("src/app.ts"));
    }

    #[test]
    fn a_typescript_declaration_file_is_not_source() {
        assert!(!is_source("types/index.d.ts"));
        assert!(!is_source("node_modules/@types/x/INDEX.D.TS"));
    }

    #[test]
    fn known_security_config_name_is_source() {
        assert!(is_source("web.xml"));
        assert!(is_source("WEB.XML"));
        assert!(is_source("config/applicationContext.xml"));
    }

    #[test]
    fn xml_under_a_canonical_config_root_is_source() {
        assert!(is_source("src/main/webapp/WEB-INF/custom.xml"));
        assert!(is_source("app/META-INF/persistence.xml"));
        assert!(is_source("conf/settings.properties"));
    }

    #[test]
    fn xml_outside_a_config_root_is_not_source() {
        assert!(!is_source("data/catalog.xml"));
    }

    #[test]
    fn iac_file_is_source() {
        assert!(is_source("Dockerfile"));
        assert!(is_source("infra/main.tf"));
    }

    #[test]
    fn unrelated_file_is_not_source() {
        assert!(!is_source("README.md"));
        assert!(!is_source("assets/logo.png"));
    }

    #[test]
    fn lang_of_file_uses_the_extension_table_first() {
        assert_eq!(lang_of_file("src/a.py", None), Some("python"));
    }

    #[test]
    fn lang_of_file_knows_extensionless_convention_names_and_dotenv() {
        assert_eq!(lang_of_file("Makefile", None), Some("make"));
        assert_eq!(lang_of_file("build/CMakeLists.txt", None), Some("cmake"));
        assert_eq!(lang_of_file(".env.production", None), Some("dotenv"));
    }

    #[test]
    fn lang_of_file_without_a_repo_root_never_reads() {
        assert_eq!(lang_of_file("bin/tool", None), None);
    }

    #[test]
    fn lang_of_file_reads_a_shebang_for_an_unclassified_file() {
        let dir = tempfile::tempdir().unwrap();
        let cases = [
            ("py", "#!/usr/bin/env python3\n", Some("python")),
            ("sh", "#!/bin/bash\nset -e\n", Some("shell")),
            ("rb", "#!/usr/bin/ruby\n", Some("ruby")),
            ("pl", "#!/usr/bin/perl -w\n", Some("perl")),
            ("js", "#!/usr/bin/env node\n", Some("javascript")),
            ("none", "plain text\n", None),
        ];
        for (name, body, want) in cases {
            std::fs::write(dir.path().join(name), body).unwrap();
            assert_eq!(lang_of_file(name, Some(dir.path())), want, "{name}");
        }
    }

    #[test]
    fn lang_of_file_is_unknown_for_a_missing_or_escaping_path() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(lang_of_file("gone", Some(dir.path())), None);
        assert_eq!(lang_of_file("../../etc/passwd", Some(dir.path())), None);
    }
}
