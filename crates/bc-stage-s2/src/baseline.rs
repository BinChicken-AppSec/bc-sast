// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! Repo-kind classifier and minimum-baseline checklist, ported from
//! `s2_threatmodel.py`'s `_repo_kind`/`_baseline_block`/`_BASELINES`/
//! `_baseline_audit` (v1.4.0).
//!
//! Every baseline item carries a stable id (`BL-<kind>-<suffix>`), so the
//! model's disposition of it (a threat whose evidence starts
//! `baseline: <ID>`, or an `open_questions` entry starting `<ID>:`) is
//! machine-checkable by matching the id rather than fuzzy-matching prose.

use std::collections::{BTreeSet, HashSet};
use std::sync::LazyLock;

use regex::Regex;

use bc_model::ThreatModel;

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

/// `(kind, [(id, text)])`.
type Checklist = &'static [(&'static str, &'static str)];

const BASELINES: &[(&str, Checklist)] = &[
    (
        "web-api",
        &[
            ("BL-WEB-A01", "OWASP A01 Broken Access Control (IDOR, path traversal, forced browsing, privilege escalation)"),
            ("BL-WEB-A02", "OWASP A02 Cryptographic Failures (weak/missing crypto, plaintext secrets/transport)"),
            ("BL-WEB-A03", "OWASP A03 Injection (SQL/NoSQL/OS/LDAP/template/header)"),
            ("BL-WEB-A04", "OWASP A04 Insecure Design (missing rate-limit, trust-boundary assumptions)"),
            ("BL-WEB-A05", "OWASP A05 Security Misconfiguration (default creds, debug on, permissive CORS)"),
            ("BL-WEB-A07", "OWASP A07 Identification & Authentication Failures (weak session, missing MFA, JWT flaws)"),
            ("BL-WEB-A08", "OWASP A08 Software & Data Integrity Failures (unsafe deserialization, unsigned updates)"),
            ("BL-WEB-A10", "OWASP A10 Server-Side Request Forgery"),
            ("BL-WEB-XSS", "XSS (reflected / stored / DOM)"),
            ("BL-WEB-CSRF", "CSRF / state-changing GET"),
        ],
    ),
    (
        "mobile",
        &[
            ("BL-MOB-M1", "OWASP M1 Improper Credential Usage (hardcoded keys, token leakage)"),
            ("BL-MOB-M3", "OWASP M3 Insecure Authentication/Authorization"),
            ("BL-MOB-M5", "OWASP M5 Insecure Communication (no cert pinning, cleartext traffic)"),
            ("BL-MOB-M8", "OWASP M8 Security Misconfiguration (exported components, debuggable build)"),
            ("BL-MOB-M9", "OWASP M9 Insecure Data Storage (world-readable prefs, unencrypted DB)"),
        ],
    ),
    (
        "native",
        &[
            ("BL-NAT-119", "CWE-119/787 Buffer overflow (stack/heap write OOB)"),
            ("BL-NAT-416", "CWE-416 Use-after-free / double-free"),
            ("BL-NAT-190", "CWE-190 Integer overflow leading to undersized allocation"),
            ("BL-NAT-134", "CWE-134 Format-string"),
            ("BL-NAT-362", "CWE-362 TOCTOU / race condition"),
            ("BL-NAT-78", "CWE-78 OS command injection via system()/exec()"),
        ],
    ),
    (
        "iac",
        &[
            ("BL-IAC-IAM", "Over-permissive IAM / RBAC (wildcard actions, cluster-admin bindings)"),
            ("BL-IAC-NET", "Public network exposure (0.0.0.0/0 ingress, hostNetwork, public S3/bucket)"),
            ("BL-IAC-SECRETS", "Secrets committed in plaintext / env"),
            ("BL-IAC-PRIV", "Privileged or root containers, missing securityContext"),
            ("BL-IAC-TLS", "Disabled TLS / unencrypted storage classes"),
        ],
    ),
    (
        "library",
        &[
            ("BL-LIB-INJ", "Injection via untrusted caller input (SQL/OS/path)"),
            ("BL-LIB-DESER", "Unsafe deserialization (pickle/yaml.load/XMLDecoder/ObjectInputStream)"),
            ("BL-LIB-PATH", "Path traversal in file-handling APIs"),
            ("BL-LIB-REDOS", "ReDoS / algorithmic-complexity DoS"),
        ],
    ),
];

static BASELINE_EVIDENCE_RX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^baseline:\s*(BL-[A-Z]+-\w+)").unwrap());

pub fn repo_kind(ev: &Evidence, all_files: &[String]) -> BTreeSet<String> {
    let mut kinds = BTreeSet::new();
    let all_files_lower: Vec<String> = all_files.iter().map(|f| f.to_lowercase()).collect();
    let manifest_text = ev
        .manifests
        .iter()
        .map(|(_, body)| body.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    // A framework-routed handler faces the same surface as "network", of
    // which it is a specialization (upstream v1.4.0).
    let has_network_ep = ev
        .entry_points
        .iter()
        .any(|(kind, ..)| kind == "network" || kind == "framework");
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
/// deduplicated across kinds by id. Extracted as its own function so the
/// "kind has no entry in `BASELINES`" arm — unreachable via
/// [`baseline_block`]'s only real inputs (`repo_kind`'s outputs and the
/// hardcoded `"owasp"` -> `web-api`, both always a `BASELINES` key) — is
/// still directly whitebox-testable with a synthetic unknown kind.
fn collect_baseline_items(kinds: &BTreeSet<String>) -> Vec<(&'static str, &'static str)> {
    let mut seen: HashSet<&str> = HashSet::new();
    let mut items = Vec::new();
    for k in kinds {
        if let Some((_, checklist)) = BASELINES.iter().find(|(name, _)| *name == k) {
            for (id, text) in *checklist {
                if seen.insert(id) {
                    items.push((*id, *text));
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
///
/// The block requires a disposition for every item (upstream v1.4.0): the
/// previous "emit a threat ONLY if a matching surface exists, otherwise
/// omit silently" let a model drop a whole checklist category without a
/// trace. The prompt text is transcribed verbatim.
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

    let body: String = collect_baseline_items(&kinds)
        .iter()
        .map(|(id, text)| format!("  - [{id}] {text}"))
        .collect::<Vec<_>>()
        .join("\n");
    let kinds_joined: Vec<&str> = kinds.iter().map(|s| s.as_str()).collect();
    let block = format!(
        "\nMINIMUM BASELINE for repo kind {{{}}} — this is a coverage floor, not a checklist \
         to tick. A disposition is REQUIRED for EVERY item; silent omission is a contract \
         violation. For each item, do exactly one of:\n  (a) emit a threat whose \"evidence\" \
         starts with \"baseline: <ID>\", setting likelihood to reflect how strongly this \
         snapshot supports it (\"rare\" is a perfectly good answer for a plausible-but-\
         unconfirmed surface). Continue the string after the id with the concrete evidence for \
         THIS repo — e.g. \"baseline: BL-WEB-A03; routes/search.ts builds SQL by string \
         concatenation\" — and give \"surface\" a real path when one exists. Write the bare id \
         alone only when this snapshot genuinely offers nothing; a threat pinned to no file \
         forfeits its guaranteed review chunk in a later stage;\n  (b) add an open_questions \
         entry starting \"<ID>: \" with a one-clause reason no matching surface exists in the \
         evidence above.\nYou are looking at STRUCTURE, not source code, so you usually cannot \
         rule an item out — when in doubt, choose (a) with a low likelihood. A later stage \
         re-checks every threat against the real code.\n{body}\n",
        kinds_joined.join(", ")
    );
    (kinds, block)
}

/// Which required baseline ids for `kinds` received neither disposition:
/// no threat whose `evidence` starts `baseline: <ID>` and no
/// `open_questions` entry naming the id before a colon. Deterministic and
/// model-free. Run it BEFORE capping: baseline dispositions are
/// deliberately low-likelihood, rank last and are the first thing the cap
/// removes, so auditing afterwards would blame the model for the
/// harness's own truncation.
pub fn baseline_audit(tm: &ThreatModel, kinds: &BTreeSet<String>) -> BTreeSet<String> {
    let mut required: BTreeSet<String> = collect_baseline_items(kinds)
        .into_iter()
        .map(|(id, _)| id.to_string())
        .collect();
    for t in &tm.threats {
        if let Some(c) = BASELINE_EVIDENCE_RX.captures(&t.evidence) {
            required.remove(&c[1]);
        }
    }
    for q in tm.open_questions.iter().filter(|q| q.starts_with("BL-")) {
        let id = q.split(':').next().unwrap_or("").trim();
        required.remove(id);
    }
    required
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
            (
                "BL-LIB-INJ",
                "Injection via untrusted caller input (SQL/OS/path)"
            )
        );
        assert!(items.iter().any(|(id, _)| *id == "BL-WEB-A01"));
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
        assert!(
            block.contains("MINIMUM BASELINE for repo kind {web-api} — this is a coverage floor")
        );
        assert!(block.contains("  - [BL-WEB-A01] OWASP A01"));
        assert!(block.contains("A disposition is REQUIRED for EVERY item"));
        assert!(!block.contains("omit silently"));
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
    #[test]
    fn repo_kind_web_api_from_a_framework_entry_point() {
        let mut ev = empty_evidence();
        ev.entry_points = vec![(
            "framework".to_string(),
            false,
            "Ctl.java".to_string(),
            "get".to_string(),
        )];
        assert!(repo_kind(&ev, &[]).contains("web-api"));
    }

    fn threat_with_evidence(evidence: &str) -> bc_model::Threat {
        bc_model::Threat {
            id: "T1".to_string(),
            threat: "t".to_string(),
            actor: bc_model::Actor::RemoteUnauth,
            surface: "s".to_string(),
            asset: "a".to_string(),
            impact: bc_model::Impact::Low,
            likelihood: bc_model::Likelihood::Rare,
            controls: String::new(),
            evidence: evidence.to_string(),
        }
    }

    #[test]
    fn baseline_audit_reports_only_undisposed_ids() {
        let kinds = BTreeSet::from(["library".to_string()]);
        let tm = ThreatModel {
            threats: vec![
                threat_with_evidence("baseline: BL-LIB-INJ; db.py builds SQL"),
                threat_with_evidence("baseline:BL-LIB-PATH"),
                // Not at the start: not a disposition.
                threat_with_evidence("see baseline: BL-LIB-REDOS"),
            ],
            open_questions: vec![
                "BL-LIB-DESER : no deserialization in scope".to_string(),
                "What is BL-LIB-REDOS?".to_string(),
            ],
            ..ThreatModel::default()
        };
        assert_eq!(
            baseline_audit(&tm, &kinds),
            BTreeSet::from(["BL-LIB-REDOS".to_string()])
        );
        assert!(baseline_audit(&tm, &BTreeSet::new()).is_empty());
    }
}
