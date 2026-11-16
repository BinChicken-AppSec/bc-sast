use appsec_model::{ContextPackage, Control, ControlKind, Reach};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Support {
    Corroborated { evidence: Vec<String> },
    Unsupported,
}

impl Support {
    pub fn is_corroborated(&self) -> bool {
        matches!(self, Self::Corroborated { .. })
    }
}

const MAX_EVIDENCE: usize = 3;

fn hints(kind: ControlKind) -> &'static [&'static str] {
    match kind {
        ControlKind::Auth => &[
            "auth",
            "login",
            "session",
            "token",
            "jwt",
            "oauth",
            "permission",
            "rbac",
        ],
        ControlKind::InputValidation => &[
            "valid",
            "sanitiz",
            "sanitis",
            "escape",
            "schema",
            "allowlist",
            "whitelist",
        ],
        ControlKind::Sandbox => &["sandbox", "jail", "seccomp", "container", "isolat"],
        ControlKind::Aslr => &["aslr", "pie", "relro"],
        ControlKind::Cfi => &["cfi", "safestack", "fortify"],
        ControlKind::Other => &[],
    }
}

pub fn support_for_control(control: &Control, ctx: &ContextPackage) -> Support {
    let mut evidence = Vec::new();

    for path in &control.protects {
        if let Some(found) = entry_point_for(path, ctx) {
            evidence.push(found);
            break;
        }
    }

    let words = hints(control.kind);
    if !words.is_empty() {
        if let Some(found) = symbol_matching(words, ctx) {
            evidence.push(found);
        }
    }

    evidence.truncate(MAX_EVIDENCE);
    if evidence.is_empty() {
        Support::Unsupported
    } else {
        Support::Corroborated { evidence }
    }
}

pub fn support_for_reach(reach: &Reach, ctx: &ContextPackage) -> Support {
    let mut words: Vec<String> = vec![reach.kind.to_ascii_lowercase()];
    words.extend(
        reach
            .name
            .to_ascii_lowercase()
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|w| w.len() >= 3)
            .map(str::to_owned),
    );
    match reach.kind.as_str() {
        "database" => {
            words.extend(["sql", "postgres", "mysql", "mongo", "repository"].map(String::from))
        }
        "queue" => words.extend(["queue", "kafka", "rabbit", "sqs", "topic"].map(String::from)),
        "metadata" => words.extend(["metadata", "169.254"].map(String::from)),
        "filesystem" => words.extend(["file", "path", "fs"].map(String::from)),
        _ => {}
    }
    let refs: Vec<&str> = words.iter().map(String::as_str).collect();
    match symbol_matching(&refs, ctx) {
        Some(found) => Support::Corroborated {
            evidence: vec![found],
        },
        None => Support::Unsupported,
    }
}

fn entry_point_for(path: &str, ctx: &ContextPackage) -> Option<String> {
    let segments: Vec<&str> = path
        .split('/')
        .filter(|s| !s.is_empty() && s.len() >= 3 && !s.starts_with('{') && !s.starts_with(':'))
        .collect();
    if segments.is_empty() {
        return None;
    }
    ctx.entry_points.iter().find_map(|e| {
        let haystack = format!(
            "{} {}",
            e.function.to_ascii_lowercase(),
            e.file.to_ascii_lowercase()
        );
        segments
            .iter()
            .any(|s| haystack.contains(&s.to_ascii_lowercase()))
            .then(|| format!("entry point {} in {}", e.function, e.file))
    })
}

fn symbol_matching(words: &[&str], ctx: &ContextPackage) -> Option<String> {
    let matches = |text: &str| -> bool {
        let lower = text.to_ascii_lowercase();
        words.iter().any(|w| !w.is_empty() && lower.contains(w))
    };
    if let Some(symbol) = ctx.call_graph.keys().find(|s| matches(s)) {
        return Some(format!("call-graph symbol {symbol}"));
    }
    ctx.all_files
        .iter()
        .find(|f| matches(f))
        .map(|f| format!("file {f}"))
}

pub fn render(ctx: &ContextPackage) -> String {
    let gathered = ctx
        .app_profile
        .as_ref()
        .is_some_and(|p| p.source.starts_with("gathered"));
    if !gathered || (ctx.design_controls.is_empty() && !has_edges(ctx)) {
        return String::new();
    }

    let mut out = String::from(
        "\
CLAIMED CONTROLS AND TOPOLOGY, CHECKED AGAINST THIS CODE:
  Each line is a claim taken from the organisation's own documentation,
  followed by what this repository shows about it. \"Corroborated\" means
  something here is consistent with the claim -- not that the control
  works. \"Not corroborated\" means this repository shows nothing either
  way, which is NOT evidence the control is absent: a gateway or WAF in
  front of this service leaves no trace inside it.

  Weigh a corroborated claim more heavily than an uncorroborated one.
  Never treat an uncorroborated claim as proof that a finding is
  exploitable, and never let a corroborated one talk you out of
  reporting what the code shows.
",
    );

    for control in &ctx.design_controls {
        let protects = if control.protects.is_empty() {
            "global".to_string()
        } else {
            control.protects.join(", ")
        };
        out.push_str(&format!(
            "  - control {:?} ({}, protects {protects}): {}\n",
            control.name,
            kind_name(control.kind),
            describe(&support_for_control(control, ctx))
        ));
    }

    if let Some(profile) = ctx.app_profile.as_ref() {
        for (label, edges) in [
            ("reaches", &profile.reaches),
            ("reached by", &profile.reached_by),
        ] {
            for edge in edges {
                out.push_str(&format!(
                    "  - {label} {:?} ({}): {}\n",
                    edge.name,
                    edge.kind,
                    describe(&support_for_reach(edge, ctx))
                ));
            }
        }
    }
    out
}

fn has_edges(ctx: &ContextPackage) -> bool {
    ctx.app_profile
        .as_ref()
        .is_some_and(|p| !p.reaches.is_empty() || !p.reached_by.is_empty())
}

fn describe(support: &Support) -> String {
    match support {
        Support::Corroborated { evidence } => {
            format!("corroborated by {}", evidence.join("; "))
        }
        Support::Unsupported => {
            "not corroborated -- this repository shows nothing either way".to_string()
        }
    }
}

fn kind_name(kind: ControlKind) -> &'static str {
    match kind {
        ControlKind::Auth => "auth",
        ControlKind::Sandbox => "sandbox",
        ControlKind::InputValidation => "input-validation",
        ControlKind::Aslr => "aslr",
        ControlKind::Cfi => "cfi",
        ControlKind::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use appsec_model::{AppProfile, EntryPoint, EntryPointKind};

    use super::*;

    fn control(name: &str, kind: ControlKind, protects: &[&str]) -> Control {
        Control {
            name: name.into(),
            kind,
            protects: protects.iter().map(|s| s.to_string()).collect(),
            notes: String::new(),
        }
    }

    fn reach(name: &str, kind: &str) -> Reach {
        Reach {
            name: name.into(),
            kind: kind.into(),
            authenticated: None,
        }
    }

    fn gathered_profile() -> AppProfile {
        AppProfile {
            application_id: "APP-1".into(),
            name: "payments".into(),
            externally_facing: true,
            pci_scoped: true,
            processes_pan: true,
            pii: false,
            source: "gathered-context".into(),
            exposure: "internet".into(),
            reaches: Vec::new(),
            reached_by: Vec::new(),
        }
    }

    fn ctx() -> ContextPackage {
        ContextPackage {
            app_profile: Some(gathered_profile()),
            ..ContextPackage::default()
        }
    }

    #[test]
    fn a_control_naming_a_route_is_corroborated_by_a_matching_entry_point() {
        let mut c = ctx();
        c.entry_points.push(EntryPoint {
            file: "src/routes/payments.rs".into(),
            function: "post_payments".into(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: true,
        });
        let support = support_for_control(
            &control("Edge WAF", ControlKind::InputValidation, &["/payments"]),
            &c,
        );
        let Support::Corroborated { evidence } = support else {
            panic!("expected corroboration, got {support:?}");
        };
        assert!(
            evidence.iter().any(|e| e.contains("post_payments")),
            "{evidence:?}"
        );
    }

    #[test]
    fn an_auth_control_is_corroborated_by_an_auth_shaped_symbol() {
        let mut c = ctx();
        c.call_graph
            .insert("middleware::require_session".into(), Vec::new());
        let support = support_for_control(&control("SSO", ControlKind::Auth, &[]), &c);
        let Support::Corroborated { evidence } = support else {
            panic!("expected corroboration, got {support:?}");
        };
        assert!(evidence[0].contains("require_session"), "{evidence:?}");
    }

    #[test]
    fn a_control_with_nothing_matching_is_unsupported() {
        let c = ctx();
        assert_eq!(
            support_for_control(&control("Edge WAF", ControlKind::Auth, &["/nothing"]), &c),
            Support::Unsupported
        );
    }

    #[test]
    fn a_control_of_unknown_kind_is_never_corroborated_by_a_symbol() {
        let mut c = ctx();
        c.call_graph.insert("anything::at_all".into(), Vec::new());
        assert_eq!(
            support_for_control(&control("Mystery", ControlKind::Other, &[]), &c),
            Support::Unsupported
        );
    }

    #[test]
    fn a_route_claim_of_only_short_or_templated_segments_matches_nothing() {
        let mut c = ctx();
        c.entry_points.push(EntryPoint {
            file: "src/x.rs".into(),
            function: "handler".into(),
            kind: EntryPointKind::Network,
            reachable_from_unauth: false,
        });
        for path in ["/", "/a/{id}", "/{id}", "/:id"] {
            assert_eq!(
                support_for_control(&control("WAF", ControlKind::Other, &[path]), &c),
                Support::Unsupported,
                "{path} should not match"
            );
        }
    }

    #[test]
    fn a_file_counts_as_evidence_when_no_symbol_does() {
        let mut c = ctx();
        c.all_files.push("src/auth/session.rs".into());
        let support = support_for_control(&control("SSO", ControlKind::Auth, &[]), &c);
        let Support::Corroborated { evidence } = support else {
            panic!("expected corroboration, got {support:?}");
        };
        assert!(evidence[0].contains("src/auth/session.rs"), "{evidence:?}");
    }

    #[test]
    fn a_claimed_database_is_corroborated_by_a_database_shaped_symbol() {
        let mut c = ctx();
        c.call_graph
            .insert("store::postgres_connect".into(), Vec::new());
        let support = support_for_reach(&reach("cards-db", "database"), &c);
        assert!(support.is_corroborated(), "{support:?}");
    }

    #[test]
    fn a_claimed_edge_is_corroborated_by_its_own_name() {
        let mut c = ctx();
        c.all_files.push("src/clients/cards.rs".into());
        assert!(support_for_reach(&reach("cards-db", "service"), &c).is_corroborated());
    }

    #[test]
    fn a_claimed_edge_with_no_trace_is_unsupported() {
        let c = ctx();
        assert_eq!(
            support_for_reach(&reach("mainframe", "service"), &c),
            Support::Unsupported
        );
    }

    #[test]
    fn a_very_short_edge_name_does_not_match_on_its_own() {
        let mut c = ctx();
        c.all_files.push("src/zz.rs".into());
        assert_eq!(
            support_for_reach(&reach("zz", "other"), &c),
            Support::Unsupported
        );
    }

    #[test]
    fn nothing_gathered_renders_nothing() {
        assert!(render(&ContextPackage::default()).is_empty());
        let mut c = ctx();
        c.app_profile.as_mut().expect("profile").source = "cmdb".into();
        c.design_controls
            .push(control("WAF", ControlKind::Auth, &[]));
        assert!(
            render(&c).is_empty(),
            "an operator's own control is their statement, not a claim to check"
        );
        assert!(render(&ctx()).is_empty());
    }

    #[test]
    fn the_block_states_both_verdicts_and_what_each_means() {
        let mut c = ctx();
        c.call_graph
            .insert("middleware::require_session".into(), Vec::new());
        c.design_controls
            .push(control("SSO", ControlKind::Auth, &[]));
        c.design_controls.push(control(
            "Edge WAF",
            ControlKind::InputValidation,
            &["/nothing"],
        ));
        c.app_profile.as_mut().expect("profile").reaches = vec![reach("mainframe", "service")];

        let out = render(&c);
        assert!(out.contains("corroborated by call-graph symbol"), "{out}");
        assert!(out.contains("not corroborated"), "{out}");
        assert!(out.contains("nothing either way"), "{out}");
        assert!(out.contains("NOT evidence the control is absent"), "{out}");
        assert!(
            out.contains("never let a corroborated one talk you out of"),
            "{out}"
        );
        assert!(out.contains("\"SSO\""), "{out}");
        assert!(out.contains("\"Edge WAF\""), "{out}");
        assert!(out.contains("reaches \"mainframe\""), "{out}");
    }

    #[test]
    fn a_global_control_says_global_rather_than_an_empty_list() {
        let mut c = ctx();
        c.design_controls
            .push(control("SSO", ControlKind::Auth, &[]));
        assert!(render(&c).contains("protects global"));
    }

    #[test]
    fn reached_by_edges_are_rendered_too() {
        let mut c = ctx();
        c.app_profile.as_mut().expect("profile").reached_by =
            vec![reach("partner gateway", "service")];
        let out = render(&c);
        assert!(out.contains("reached by \"partner gateway\""), "{out}");
    }

    #[test]
    fn every_control_kind_renders_its_canonical_name() {
        for (kind, name) in [
            (ControlKind::Auth, "auth"),
            (ControlKind::Sandbox, "sandbox"),
            (ControlKind::InputValidation, "input-validation"),
            (ControlKind::Aslr, "aslr"),
            (ControlKind::Cfi, "cfi"),
            (ControlKind::Other, "other"),
        ] {
            assert_eq!(kind_name(kind), name);
            let _ = hints(kind);
        }
    }

    #[test]
    fn sandbox_aslr_and_cfi_claims_are_corroborated_by_their_own_words() {
        for (kind, symbol) in [
            (ControlKind::Sandbox, "run::seccomp_apply"),
            (ControlKind::Aslr, "build::enable_pie"),
            (ControlKind::Cfi, "build::fortify_source"),
        ] {
            let mut c = ctx();
            c.call_graph.insert(symbol.into(), Vec::new());
            assert!(
                support_for_control(&control("X", kind, &[]), &c).is_corroborated(),
                "{symbol} should corroborate {kind:?}"
            );
        }
    }

    #[test]
    fn queue_metadata_and_filesystem_edges_use_their_own_words() {
        for (kind, symbol) in [
            ("queue", "bus::kafka_publish"),
            ("metadata", "cloud::metadata_lookup"),
            ("filesystem", "io::path_join"),
        ] {
            let mut c = ctx();
            c.call_graph.insert(symbol.into(), Vec::new());
            assert!(
                support_for_reach(&reach("thing", kind), &c).is_corroborated(),
                "{symbol} should corroborate a {kind} edge"
            );
        }
    }
}
