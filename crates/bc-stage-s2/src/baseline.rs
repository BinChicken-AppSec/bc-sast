// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! Repo-kind classifier and minimum-baseline checklist, ported from
//! `s2_threatmodel.py`'s `_repo_kind`/`_baseline_block`/`_BASELINES`.

use std::collections::{BTreeSet, HashSet};
use std::sync::LazyLock;

use regex::Regex;

use crate::evidence::Evidence;

const NATIVE_LANGS: &[&str] = &[
    "c",
    "cpp",
    "c++",
    "c-cpp",
    "c/c++",
    "rust",
    "objective-c",
    "objc",
];

static WEB_FW_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(spring|express|fastify|koa|hapi|nest|next|nuxt|django|flask|fastapi|tornado|rails|sinatra|laravel|symfony|gin-gonic|echo|fiber|actix|axum|asp\.net|ktor|micronaut|quarkus|vertx|play-framework)\b",
    )
    .unwrap()
});

static ANDROID_PACKAGE_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bcom\.android\b").unwrap());

const BASELINES: &[(&str, &[&str])] = &[
    (
        "web-api",
        &[
            "OWASP A01 Broken Access Control (IDOR, path traversal, forced browsing, privilege escalation)",
            "OWASP A02 Cryptographic Failures (weak/missing crypto, plaintext secrets/transport)",
            "OWASP A03 Injection (SQL/NoSQL/OS/LDAP/template/header)",
            "OWASP A04 Insecure Design (missing rate-limit, trust-boundary assumptions)",
            "OWASP A05 Security Misconfiguration (default creds, debug on, permissive CORS)",
            "OWASP A07 Identification & Authentication Failures (weak session, missing MFA, JWT flaws)",
            "OWASP A08 Software & Data Integrity Failures (unsafe deserialization, unsigned updates)",
            "OWASP A10 Server-Side Request Forgery",
            "XSS (reflected / stored / DOM)",
            "CSRF / state-changing GET",
        ],
    ),
    (
        "mobile",
        &[
            "OWASP M1 Improper Credential Usage (hardcoded keys, token leakage)",
            "OWASP M3 Insecure Authentication/Authorization",
            "OWASP M5 Insecure Communication (no cert pinning, cleartext traffic)",
            "OWASP M8 Security Misconfiguration (exported components, debuggable build)",
            "OWASP M9 Insecure Data Storage (world-readable prefs, unencrypted DB)",
        ],
    ),
    (
        "native",
        &[
            "CWE-119/787 Buffer overflow (stack/heap write OOB)",
            "CWE-416 Use-after-free / double-free",
            "CWE-190 Integer overflow leading to undersized allocation",
            "CWE-134 Format-string",
            "CWE-362 TOCTOU / race condition",
            "CWE-78 OS command injection via system()/exec()",
        ],
    ),
    (
        "iac",
        &[
            "Over-permissive IAM / RBAC (wildcard actions, cluster-admin bindings)",
            "Public network exposure (0.0.0.0/0 ingress, hostNetwork, public S3/bucket)",
            "Secrets committed in plaintext / env",
            "Privileged or root containers, missing securityContext",
            "Disabled TLS / unencrypted storage classes",
        ],
    ),
    (
        "library",
        &[
            "Injection via untrusted caller input (SQL/OS/path)",
            "Unsafe deserialization (pickle/yaml.load/XMLDecoder/ObjectInputStream)",
            "Path traversal in file-handling APIs",
            "ReDoS / algorithmic-complexity DoS",
        ],
    ),
];

pub fn repo_kind(ev: &Evidence, all_files: &[String]) -> BTreeSet<String> {
    let mut kinds = BTreeSet::new();
    let all_files_lower: Vec<String> = all_files.iter().map(|f| f.to_lowercase()).collect();
    let manifest_text = ev
        .manifests
        .iter()
        .map(|(_, body)| body.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    let has_network_ep = ev.entry_points.iter().any(|(kind, ..)| kind == "network");
    if has_network_ep || !ev.api_artefacts.is_empty() || WEB_FW_RX.is_match(&manifest_text) {
        kinds.insert("web-api".to_string());
    }

    if all_files_lower.iter().any(|f| {
        f.ends_with("androidmanifest.xml") || f.ends_with("info.plist") || f.ends_with("podfile")
    }) || ANDROID_PACKAGE_RX.is_match(&manifest_text)
    {
        kinds.insert("mobile".to_string());
    }

    if all_files_lower.iter().any(|f| {
        f.ends_with(".tf")
            || f.ends_with(".hcl")
            || f.ends_with("chart.yaml")
            || f.ends_with("values.yaml")
            || f.ends_with("kustomization.yaml")
            || f.ends_with("kustomization.yml")
    }) {
        kinds.insert("iac".to_string());
    }

    let mut langs: HashSet<String> = HashSet::new();
    langs.insert(ev.primary_language.to_lowercase());
    langs.extend(ev.languages.iter().map(|(l, _)| l.to_lowercase()));
    if NATIVE_LANGS.iter().any(|nl| langs.contains(*nl)) {
        kinds.insert("native".to_string());
    }

    if kinds.is_empty() {
        kinds.insert("library".to_string());
    }
    kinds
}

/// Checklist items for every kind in `kinds`, in `kinds`-then-table order,
/// deduplicated across kinds. Extracted as its own function so the "kind
/// has no entry in `BASELINES`" arm — unreachable via [`baseline_block`]'s
/// only real inputs (`repo_kind`'s outputs and the hardcoded `"owasp"` ->
/// `web-api`, both always a `BASELINES` key) — is still directly
/// whitebox-testable with a synthetic unknown kind.
fn collect_baseline_items(kinds: &BTreeSet<String>) -> Vec<&'static str> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut items: Vec<&str> = Vec::new();
    for k in kinds {
        if let Some((_, checklist)) = BASELINES.iter().find(|(name, _)| *name == k) {
            for it in *checklist {
                if seen.insert(it) {
                    items.push(it);
                }
            }
        }
    }
    items
}

/// `(kinds, block_text)` — `block_text` is `""` when `mode == "none"`.
/// `collect_baseline_items(&kinds)` is never empty here: `kinds` is either
/// the hardcoded `{"web-api"}` (`mode == "owasp"`) or `repo_kind`'s output,
/// and every value either can produce is a `BASELINES` key with a non-empty
/// checklist — so, unlike the Python original, no separate "no items
/// survived" guard is needed (or reachable) here.
pub fn baseline_block(
    ev: &Evidence,
    all_files: &[String],
    mode: &str,
) -> (BTreeSet<String>, String) {
    if mode == "none" {
        return (BTreeSet::new(), String::new());
    }
    let kinds = if mode == "owasp" {
        BTreeSet::from(["web-api".to_string()])
    } else {
        repo_kind(ev, all_files)
    };

    let items = collect_baseline_items(&kinds);
    let body: String = items
        .iter()
        .map(|it| format!("  - {it}"))
        .collect::<Vec<_>>()
        .join("\n");
    let kinds_joined: Vec<&str> = kinds.iter().map(|s| s.as_str()).collect();
    let block = format!(
        "\nMINIMUM BASELINE for repo kind {{{}}} — rank each against THIS codebase; emit a threat ONLY if a matching surface exists in the evidence above, otherwise omit silently:\n{body}\n",
        kinds_joined.join(", ")
    );
    (kinds, block)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_evidence() -> Evidence {
        Evidence::default()
    }

    #[test]
    fn repo_kind_defaults_to_library_with_no_signals() {
        let ev = empty_evidence();
        assert_eq!(repo_kind(&ev, &[]), BTreeSet::from(["library".to_string()]));
    }

    #[test]
    fn repo_kind_web_api_from_network_entry_point() {
        let mut ev = empty_evidence();
        ev.entry_points = vec![(
            "network".to_string(),
            true,
            "app.py".to_string(),
            "handle".to_string(),
        )];
        assert!(repo_kind(&ev, &[]).contains("web-api"));
    }

    #[test]
    fn repo_kind_web_api_from_api_artefacts() {
        let mut ev = empty_evidence();
        ev.api_artefacts = vec!["openapi.yaml".to_string()];
        assert!(repo_kind(&ev, &[]).contains("web-api"));
    }

    #[test]
    fn repo_kind_web_api_from_framework_manifest_text() {
        let mut ev = empty_evidence();
        ev.manifests = vec![(
            "package.json".to_string(),
            "{\"dependencies\": {\"express\": \"^4\"}}".to_string(),
        )];
        assert!(repo_kind(&ev, &[]).contains("web-api"));
    }

    #[test]
    fn repo_kind_mobile_from_android_manifest_file() {
        let ev = empty_evidence();
        let files = vec!["app/src/main/AndroidManifest.xml".to_string()];
        assert!(repo_kind(&ev, &files).contains("mobile"));
    }

    #[test]
    fn repo_kind_mobile_from_ios_info_plist() {
        let ev = empty_evidence();
        let files = vec!["ios/App/Info.plist".to_string()];
        assert!(repo_kind(&ev, &files).contains("mobile"));
    }

    #[test]
    fn repo_kind_mobile_from_android_package_in_manifest_text() {
        let mut ev = empty_evidence();
        ev.manifests = vec![(
            "build.gradle".to_string(),
            "applicationId 'com.android.example'".to_string(),
        )];
        assert!(repo_kind(&ev, &[]).contains("mobile"));
    }

    #[test]
    fn repo_kind_iac_from_terraform_file() {
        let ev = empty_evidence();
        let files = vec!["infra/main.tf".to_string()];
        assert!(repo_kind(&ev, &files).contains("iac"));
    }

    #[test]
    fn repo_kind_native_from_primary_language() {
        let mut ev = empty_evidence();
        ev.primary_language = "rust".to_string();
        assert!(repo_kind(&ev, &[]).contains("native"));
    }

    #[test]
    fn repo_kind_native_from_detected_languages_list() {
        let mut ev = empty_evidence();
        ev.languages = vec![("C/C++".to_string(), 5)];
        assert!(repo_kind(&ev, &[]).contains("native"));
    }

    #[test]
    fn repo_kind_can_combine_multiple_kinds() {
        let mut ev = empty_evidence();
        ev.entry_points = vec![(
            "network".to_string(),
            true,
            "app.py".to_string(),
            "h".to_string(),
        )];
        ev.primary_language = "rust".to_string();
        let kinds = repo_kind(&ev, &[]);
        assert!(kinds.contains("web-api"));
        assert!(kinds.contains("native"));
    }

    #[test]
    fn collect_baseline_items_unknown_kind_contributes_nothing() {
        let kinds = BTreeSet::from(["totally-unknown-kind".to_string()]);
        assert!(collect_baseline_items(&kinds).is_empty());
    }

    #[test]
    fn collect_baseline_items_dedupes_across_kinds_preserving_order() {
        let kinds = BTreeSet::from(["library".to_string(), "web-api".to_string()]);
        let items = collect_baseline_items(&kinds);
        // "library" sorts before "web-api" in a BTreeSet, so its items lead.
        assert_eq!(
            items[0],
            "Injection via untrusted caller input (SQL/OS/path)"
        );
        assert!(items.contains(&"OWASP A01 Broken Access Control (IDOR, path traversal, forced browsing, privilege escalation)"));
    }

    #[test]
    fn baseline_block_none_mode_is_empty() {
        let ev = empty_evidence();
        let (kinds, block) = baseline_block(&ev, &[], "none");
        assert!(kinds.is_empty());
        assert_eq!(block, "");
    }

    #[test]
    fn baseline_block_owasp_mode_forces_web_api() {
        let ev = empty_evidence();
        let (kinds, block) = baseline_block(&ev, &[], "owasp");
        assert_eq!(kinds, BTreeSet::from(["web-api".to_string()]));
        assert!(block.contains("MINIMUM BASELINE for repo kind {web-api}"));
        assert!(block.contains("OWASP A01"));
    }

    #[test]
    fn baseline_block_auto_mode_uses_repo_kind() {
        let ev = empty_evidence();
        let (kinds, block) = baseline_block(&ev, &[], "auto");
        assert_eq!(kinds, BTreeSet::from(["library".to_string()]));
        assert!(block.contains("Injection via untrusted caller input"));
    }

    #[test]
    fn baseline_block_dedupes_items_shared_across_kinds() {
        // web-api and native share no items in this table, but combining
        // two kinds must not duplicate an item that appears in both of
        // their lists (none do here, so this just exercises the `seen`
        // gate over two kinds without any actual collision — still worth
        // confirming multi-kind concatenation preserves per-kind order).
        let mut ev = empty_evidence();
        ev.entry_points = vec![(
            "network".to_string(),
            true,
            "app.py".to_string(),
            "h".to_string(),
        )];
        ev.primary_language = "rust".to_string();
        let (_, block) = baseline_block(&ev, &[], "auto");
        assert!(block.contains("OWASP A01"));
        assert!(block.contains("CWE-119/787"));
    }
}
