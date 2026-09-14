//! OffensivePriority (P1-P4) heuristic classification, ported verbatim
//! from `report/enrich.py`'s `KW_*` keyword tables and
//! `offensive_priority_for`. Model-agnostic and pure — every finding gets
//! a priority regardless of whether CMDB context is available (`app:
//! None` degrades gracefully via the `exposure_unknown` branch), unlike
//! [`crate::vsvs`], which is CMDB-gated entirely.

use std::collections::HashMap;

use crate::cmdb::AppInfo;

const KW_CODE_KNOWLEDGE: &[&str] = &[
    "source code is accessible",
    "access to the source",
    "access to the repo",
    "read access to the repo",
    "decompil",
    "reverse engineer",
    "if the attacker knows",
    "knowing the function",
    "knowledge of the source",
    "internal function name",
    "would need to know",
    "hardcoded credential",
    "hardcoded password",
    "hardcoded secret",
    "hardcoded token",
    "hard-coded credential",
    "hard-coded password",
    "hard-coded secret",
    "credential in source",
    "secret in source",
    "test credential",
    "qa credential",
    "qa password",
    "test password",
    "encryption key in source",
    "key hardcoded",
];

const KW_INTERNAL: &[&str] = &[
    "internal network",
    "intranet",
    "corporate network",
    "internal-only",
    "internal only",
    "back-office",
    "corporate sso",
    "enterprise sso",
    "enterprise idp",
    "behind sso",
    "behind the idp",
    "loopback",
    "127.0.0.1",
    "localhost",
    "local listener",
    "local user",
    "local access",
    "same host",
    "on the host",
    "service-to-service",
    "mtls",
    "behind api gateway",
    "behind the gateway",
    "vpn",
    "external partner",
    "third-party provisioned",
    "log access",
    "db access",
    "database access",
    "mitm",
    "man-in-the-middle",
    "man in the middle",
    "compromised server",
    "compromise of",
    "control of the",
    "physical access",
    "adjacent network",
];

const KW_HIGH_PRIV: &[&str] = &[
    "super_admin",
    "super admin",
    "system_admin",
    "dist_admin",
    "with admin",
    "as an admin",
    "an admin user",
    "admin role",
    "privileged user",
    "privileged account",
    "requires admin",
    "admin-only",
    "admin privileges",
];

const KW_OBTAINABLE_AUTH: &[&str] = &[
    "self-registration",
    "self-registered",
    "self registration",
    "free signup",
    "sign up for",
    "any registered user",
    "any authenticated user",
    "any user account",
    "any valid user",
    "developer account",
    "portal user",
    "merchant account",
    "low-privilege user",
    "low privilege user",
    "lowest role",
];

const KW_NO_AUTH: &[&str] = &[
    "unauthenticated",
    "no authentication",
    "without authentication",
    "no auth required",
    "without auth",
    "pre-auth",
    "anonymous",
    "no credentials",
    "without credentials",
    "[allowanonymous]",
    "allowanonymous",
    "publicly accessible",
    "public endpoint",
];

/// Human-readable label for a `P1`-`P4` priority code — `""` (not
/// `Option::None`) for an unrecognized code, matching this function's own
/// pre-consolidation return type; delegates to the canonical
/// `bc_model::offensive_label` (identical P1-P4 text) rather than keeping
/// a second copy, since this crate already depends on `bc-model`.
pub fn offensive_label(priority: &str) -> &'static str {
    bc_model::offensive_label(priority).unwrap_or("")
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// Lenient `KEY:VALUE` extraction from a CVSS-like vector string — unlike
/// `bc_cvss::parse` (which requires all eight base metrics present, in
/// the fixed CVSS order, behind a `CVSS:3.x/` header), this tolerates a
/// partial or malformed vector (e.g. a verifier LLM emitting a near-miss
/// format) by splitting on `/` then `:` and keeping whatever pairs parse
/// — matching the Python original's own forgiving `parse_vector`.
fn parse_vector_loose(vector: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for part in vector.split('/') {
        if let Some((k, v)) = part.split_once(':') {
            m.insert(k.trim().to_uppercase(), v.trim().to_uppercase());
        }
    }
    m
}

/// Pure `(priority, reason)` classification — model-agnostic, called for
/// every finding post-S7 regardless of whether CMDB context (`app`) is
/// available.
pub fn offensive_priority_for(
    title: &str,
    category: &str,
    description: &str,
    cvss_vector: Option<&str>,
    app: Option<&AppInfo>,
) -> (String, String) {
    let body = format!("{title} {category} {description}").to_lowercase();
    let v = cvss_vector.map(parse_vector_loose).unwrap_or_default();
    let av = v.get("AV").map(String::as_str).unwrap_or("N");
    let pr = v.get("PR").map(String::as_str).unwrap_or("L");
    let pr_explicit = v.contains_key("PR");
    let ac = v.get("AC").map(String::as_str).unwrap_or("L");

    let cmdb_external = app.is_some_and(|a| a.externally_facing);
    let cmdb_internal = app.is_some_and(|a| !a.externally_facing);

    let code_knowledge =
        contains_any(&body, KW_CODE_KNOWLEDGE) || category.to_lowercase().contains("hardcoded");
    let internal_net =
        cmdb_internal || matches!(av, "A" | "L" | "P") || contains_any(&body, KW_INTERNAL);
    let high_priv = pr == "H" || contains_any(&body, KW_HIGH_PRIV);
    let obtainable_auth = pr == "L" || contains_any(&body, KW_OBTAINABLE_AUTH);
    // An explicit PR:L/PR:H in the vector means auth IS required — it
    // vetoes a stray "unauthenticated"/"public" keyword in the prose
    // (which usually describes the endpoint class, not the privilege the
    // verifier scored), so a PR:L finding is never mislabeled as the top
    // unauthenticated tier.
    let pr_requires_auth = pr_explicit && matches!(pr, "L" | "H");
    let no_auth = !pr_requires_auth
        && (contains_any(&body, KW_NO_AUTH) || (pr == "N" && !obtainable_auth && !high_priv));
    let internet_reachable = av == "N" && !internal_net && cmdb_external;
    let exposure_unknown = app.is_none() && av == "N" && !internal_net;

    let mut why: Vec<String> = Vec::new();
    let prio;
    if code_knowledge {
        prio = "P4";
        why.push("requires source-code / insider knowledge".to_string());
        if cmdb_internal {
            why.push("app not externally facing (CMDB)".to_string());
        } else if av != "N" {
            why.push(format!("AV:{av}"));
        }
    } else if exposure_unknown && !high_priv {
        prio = "P3";
        why.push("exposure unverified — no CMDB context".to_string());
        why.push(format!(
            "AV:{av} (network-routable; internet exposure unconfirmed)"
        ));
    } else if !internet_reachable || high_priv {
        prio = "P3";
        if cmdb_internal {
            why.push("app not externally facing (CMDB)".to_string());
        } else if av != "N" {
            why.push(format!("AV:{av} (non-network)"));
        } else if internal_net {
            why.push("internal-network position required".to_string());
        }
        if high_priv {
            why.push(
                (if pr == "H" {
                    "PR:H - high-privilege auth required"
                } else {
                    "admin/privileged role required"
                })
                .to_string(),
            );
        }
        // The Python original has a defensive `if not why: why.append(...)`
        // fallback here — provably unreachable given this branch's own
        // entry condition (`not internet_reachable or high_priv`) and the
        // three `if`/`elif`/`elif` above it: reaching this branch with
        // every one of those four checks false requires `high_priv` false
        // (else the block just above fires) and entry via
        // `not internet_reachable`, which — given `av == "N"` and
        // `!internal_net` (both required for the first three checks to
        // stay silent) — reduces to `not cmdb_external`; but `cmdb_external
        // == false` with `cmdb_internal == false` (also required) only
        // holds when `app` is `None`, and an `app`-less `av == "N"`
        // `!internal_net` case is exactly `exposure_unknown`, which the
        // `elif` above this one already claims first. Confirmed by
        // brute-forcing every AV/AC/PR/app combination against the Python
        // original directly. Not ported.
    } else if no_auth {
        prio = "P1";
        why.push(format!(
            "internet-facing{}",
            if cmdb_external { " (CMDB)" } else { "" }
        ));
        why.push(format!(
            "AV:{av} - unauthenticated{}",
            if pr_explicit {
                format!(" (PR:{pr})")
            } else {
                String::new()
            }
        ));
    } else {
        prio = "P2";
        why.push(format!(
            "internet-facing{}",
            if cmdb_external { " (CMDB)" } else { "" }
        ));
        why.push(format!("PR:{pr} - auth required but obtainable"));
    }

    if ac == "H" && matches!(prio, "P1" | "P2") {
        why.push("AC:H - complex preconditions".to_string());
    }

    (prio.to_string(), why.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(externally_facing: bool) -> AppInfo {
        AppInfo {
            externally_facing,
            ..Default::default()
        }
    }

    #[test]
    fn code_knowledge_keyword_wins_p4_regardless_of_vector() {
        let (p, why) = offensive_priority_for(
            "leak",
            "other",
            "exploitable only if the attacker knows the internal function name",
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None,
        );
        assert_eq!(p, "P4");
        assert!(why.contains("source-code"));
    }

    #[test]
    fn hardcoded_category_alone_triggers_code_knowledge() {
        let (p, _) = offensive_priority_for("t", "Hardcoded Secret", "d", None, None);
        assert_eq!(p, "P4");
    }

    #[test]
    fn code_knowledge_with_internal_cmdb_app_notes_cmdb_in_reason() {
        let (_, why) = offensive_priority_for(
            "t",
            "other",
            "hardcoded password found",
            None,
            Some(&app(false)),
        );
        assert!(why.contains("CMDB"));
    }

    #[test]
    fn code_knowledge_with_non_network_av_notes_the_vector() {
        let (_, why) = offensive_priority_for(
            "t",
            "other",
            "hardcoded password found",
            Some("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None,
        );
        assert!(why.contains("AV:L"));
    }

    #[test]
    fn no_cmdb_and_network_vector_and_no_internal_keyword_is_exposure_unknown() {
        let (p, why) = offensive_priority_for(
            "t",
            "other",
            "plain finding, no privilege keywords",
            Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
            None,
        );
        assert_eq!(p, "P3");
        assert!(why.contains("no CMDB context"));
    }

    #[test]
    fn internal_network_vector_is_p3_and_notes_non_network() {
        let (p, why) = offensive_priority_for(
            "t",
            "other",
            "d",
            Some("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(&app(true)),
        );
        assert_eq!(p, "P3");
        assert!(why.contains("AV:L (non-network)"));
    }

    #[test]
    fn internal_cmdb_app_is_p3_and_notes_cmdb() {
        let (p, why) = offensive_priority_for(
            "t",
            "other",
            "d",
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(&app(false)),
        );
        assert_eq!(p, "P3");
        assert!(why.contains("app not externally facing"));
    }

    #[test]
    fn internal_keyword_in_prose_with_no_cmdb_is_p3() {
        let (p, why) = offensive_priority_for(
            "t",
            "other",
            "reachable only from the internal network",
            None,
            None,
        );
        assert_eq!(p, "P3");
        assert!(why.contains("internal-network position"));
    }

    #[test]
    fn high_privilege_required_is_p3_even_when_internet_reachable() {
        let (p, why) = offensive_priority_for(
            "t",
            "other",
            "requires admin",
            Some("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"),
            Some(&app(true)),
        );
        assert_eq!(p, "P3");
        assert!(why.contains("PR:H - high-privilege"));
    }

    #[test]
    fn high_privilege_keyword_without_pr_h_still_notes_admin_role_required() {
        let (p, why) = offensive_priority_for(
            "t",
            "other",
            "requires admin privileges",
            Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
            Some(&app(true)),
        );
        assert_eq!(p, "P3");
        assert!(why.contains("admin/privileged role required"));
    }

    #[test]
    fn unauthenticated_internet_facing_cmdb_app_is_p1() {
        let (p, why) = offensive_priority_for(
            "t",
            "other",
            "unauthenticated access to the endpoint",
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(&app(true)),
        );
        assert_eq!(p, "P1");
        assert!(why.contains("(CMDB)"));
        assert!(why.contains("unauthenticated"));
    }

    #[test]
    fn implicit_pr_n_with_no_high_priv_or_obtainable_auth_keywords_is_p1() {
        let (p, _) = offensive_priority_for(
            "t",
            "other",
            "plain description",
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(&app(true)),
        );
        assert_eq!(p, "P1");
    }

    #[test]
    fn explicit_pr_l_vetoes_a_stray_unauthenticated_keyword() {
        let (p, _) = offensive_priority_for(
            "t",
            "other",
            "endpoint is described as unauthenticated in some docs but the vector says otherwise",
            Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
            Some(&app(true)),
        );
        assert_eq!(p, "P2");
    }

    #[test]
    fn obtainable_auth_via_pr_l_is_p2_with_explicit_pr_note() {
        let (p, why) = offensive_priority_for(
            "t",
            "other",
            "d",
            Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
            Some(&app(true)),
        );
        assert_eq!(p, "P2");
        assert!(why.contains("PR:L - auth required but obtainable"));
    }

    #[test]
    fn ac_high_appends_a_complex_precondition_note_only_for_p1_p2() {
        let (_, why) = offensive_priority_for(
            "t",
            "other",
            "unauthenticated",
            Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            Some(&app(true)),
        );
        assert!(why.contains("AC:H"));
    }

    #[test]
    fn ac_high_is_not_appended_for_p3() {
        let (p, why) = offensive_priority_for(
            "t",
            "other",
            "requires admin",
            Some("CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H"),
            Some(&app(true)),
        );
        assert_eq!(p, "P3");
        assert!(!why.contains("AC:H"));
    }

    #[test]
    fn no_cvss_vector_at_all_defaults_av_n_pr_l_ac_l() {
        let (p, _) = offensive_priority_for(
            "t",
            "other",
            "plain description, no keywords",
            None,
            Some(&app(true)),
        );
        assert_eq!(p, "P2");
    }

    #[test]
    fn malformed_vector_falls_back_to_defaults_without_panicking() {
        let (p, _) = offensive_priority_for(
            "t",
            "other",
            "d",
            Some("garbage not a vector"),
            Some(&app(true)),
        );
        assert_eq!(p, "P2");
    }

    #[test]
    fn offensive_label_covers_every_priority_and_falls_back_to_empty() {
        assert_eq!(offensive_label("P1"), "Externally Exploitable, No Auth");
        assert_eq!(
            offensive_label("P2"),
            "Externally Exploitable, Obtainable Auth"
        );
        assert_eq!(
            offensive_label("P3"),
            "Internal Network / Privileged Position"
        );
        assert_eq!(offensive_label("P4"), "Code-Knowledge / Insider Dependent");
        assert_eq!(offensive_label("bogus"), "");
    }
}
