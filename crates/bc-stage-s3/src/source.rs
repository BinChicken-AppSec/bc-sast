//! "Is this a source file worth a specialist sweep?" heuristic, ported
//! from `s3_decompose.py::_is_source`.

use std::path::Path;

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

/// True for files worth a repo-wide specialist sweep: recognized source
/// extensions, well-known security-relevant descriptor/config files,
/// XML/`.properties` under a canonical config root (not generic data XML),
/// or Infrastructure-as-Code.
pub fn is_source(f: &str) -> bool {
    let ext = bc_repo_analysis::suffix_lower(f);
    if bc_repo_analysis::ext_to_lang(&ext).is_some() {
        return true;
    }
    let name = Path::new(f)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(f)
        .to_lowercase();
    if SECURITY_CONFIG_NAMES.contains(&name.as_str()) {
        return true;
    }
    if SECURITY_CONFIG_EXTS.contains(&ext.as_str()) {
        let lower = f.to_lowercase();
        let parts: std::collections::HashSet<&str> = lower.split('/').collect();
        if SECURITY_CONFIG_DIR_SEGMENTS
            .iter()
            .any(|seg| parts.contains(seg))
        {
            return true;
        }
    }
    bc_repo_analysis::is_iac_file(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognized_extension_is_source() {
        assert!(is_source("src/app.py"));
        assert!(is_source("src/app.rs"));
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
}
