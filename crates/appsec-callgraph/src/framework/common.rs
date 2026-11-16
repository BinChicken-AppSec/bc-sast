use tree_sitter::Node;

use super::{normalize_guard_name, route_params, ANGLE_PARAM, BRACE_PARAM, COLON_PARAM};
use crate::scan::{named_kids, py_text, AuthGuardFact, FrameworkMarkerFact, RouteTaintFact};

pub(super) const ANY_METHOD: &str = "ANY";

pub(super) struct Facts<'a> {
    pub markers: &'a mut Vec<FrameworkMarkerFact>,
    pub routes: &'a mut Vec<RouteTaintFact>,
    pub guards: &'a mut Vec<AuthGuardFact>,
}

pub(super) struct Route<'a> {
    pub method: &'a str,
    pub path: String,
    pub handler: String,
    pub line: usize,
    pub framework: &'a str,
}

impl Facts<'_> {
    pub(super) fn push_route(&mut self, r: &Route, guard_names: &[String]) {
        if r.handler.is_empty() {
            return;
        }
        let params = path_params(&r.path);
        self.markers.push(FrameworkMarkerFact {
            function_qnode: r.handler.clone(),
            line: r.line,
            marker_type: format!("{}_route", r.framework),
            marker_name: format!("{} {}", r.method, r.path),
            parameter_names: params.clone(),
            framework: r.framework.to_string(),
            confidence: "high".to_string(),
        });
        for p in params {
            self.routes.push(RouteTaintFact {
                function_qnode: r.handler.clone(),
                line: r.line,
                route_pattern: r.path.clone(),
                parameter_name: p,
                is_tainted: true,
                framework: r.framework.to_string(),
            });
        }
        self.push_guard(&r.handler, r.line, r.framework, guard_names);
    }

    pub(super) fn push_guard(
        &mut self,
        handler: &str,
        line: usize,
        framework: &str,
        names: &[String],
    ) {
        let Some(name) = names.iter().find(|n| requires_auth(n)) else {
            return;
        };
        self.guards.push(AuthGuardFact {
            function_qnode: handler.to_string(),
            line,
            marker_name: name.clone(),
            requires_auth: true,
            framework: framework.to_string(),
        });
    }
}

pub(super) fn join_path(prefix: &str, path: &str) -> String {
    let joined = format!(
        "{}/{}",
        prefix.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let trimmed = joined.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(super) fn anon_handler(method: &str, path: &str) -> String {
    let slug = path
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
        .to_ascii_lowercase();
    let slug = if slug.is_empty() { "root" } else { &slug };
    format!("{}_{}", method.to_ascii_lowercase(), slug)
}

pub(super) fn path_params(path: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for rx in [&*BRACE_PARAM, &*ANGLE_PARAM, &*COLON_PARAM] {
        for p in route_params(rx, path) {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

const EXTRA_AUTH_NAMES: &[&str] = &[
    "auth",
    "auth.basic",
    "authenticateuser",
    "authsession",
    "claims",
    "httpauthentication",
    "isgranted",
    "sanctum",
    "security",
];

const DEMAND_VERBS: &[&str] = &["require", "ensure"];
const CREDENTIAL_NOUNS: &[&str] = &[
    "admin",
    "apikey",
    "auth",
    "credential",
    "jwt",
    "login",
    "permission",
    "role",
    "session",
    "signin",
    "token",
    "user",
];

pub(super) fn requires_auth(name: &str) -> bool {
    let leaf = name.rsplit('\\').next().unwrap_or(name);
    let leaf = leaf.rsplit("::").next().unwrap_or(leaf);
    let base = leaf
        .split(':')
        .next()
        .unwrap_or(leaf)
        .trim_end_matches(['!', '?']);
    if super::auth_guard_kind(base) == Some(true) {
        return true;
    }
    let norm = normalize_guard_name(base);
    EXTRA_AUTH_NAMES.contains(&norm.as_str()) || is_demand_phrase(&norm)
}

fn is_demand_phrase(norm: &str) -> bool {
    DEMAND_VERBS.iter().any(|v| norm.starts_with(v))
        && CREDENTIAL_NOUNS.iter().any(|n| norm.contains(n))
}

pub(super) fn string_text(node: Node, src: &[u8]) -> String {
    match named_kids(node).find(|c| c.kind() == "string_content") {
        Some(c) => py_text(c, src),
        None => super::strip_quotes(&py_text(node, src)).to_string(),
    }
}

pub(super) const REST_ACTIONS: &[(&str, &str, &str)] = &[
    ("index", "GET", ""),
    ("create", "POST", ""),
    ("show", "GET", "/{id}"),
    ("update", "PATCH", "/{id}"),
    ("destroy", "DELETE", "/{id}"),
    ("edit", "GET", "/{id}/edit"),
    ("new", "GET", "/new"),
];

#[cfg(test)]
pub(super) mod testing {
    use crate::scan::{AuthGuardFact, FrameworkMarkerFact, RouteTaintFact};

    #[allow(clippy::type_complexity)]
    pub(in crate::framework) fn facts_for(
        language: &str,
        src: &str,
    ) -> (
        Vec<FrameworkMarkerFact>,
        Vec<RouteTaintFact>,
        Vec<AuthGuardFact>,
    ) {
        let lang = crate::scan::ts_language(language).unwrap();
        let mut p = tree_sitter::Parser::new();
        p.set_language(&lang).unwrap();
        let tree = p.parse(src, None).unwrap();
        super::super::extract_framework_facts(language, "", src.as_bytes(), tree.root_node())
    }

    pub(in crate::framework) fn marker_names(m: &[FrameworkMarkerFact]) -> Vec<String> {
        m.iter().map(|f| f.marker_name.clone()).collect()
    }

    pub(in crate::framework) fn route_patterns(r: &[RouteTaintFact]) -> Vec<String> {
        r.iter()
            .map(|f| format!("{}:{}", f.route_pattern, f.parameter_name))
            .collect()
    }

    pub(in crate::framework) fn guard_names(g: &[AuthGuardFact]) -> Vec<(String, String)> {
        g.iter()
            .map(|f| (f.function_qnode.clone(), f.marker_name.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_path_concatenates_prefix_and_path() {
        assert_eq!(join_path("/admin", "/stats"), "/admin/stats");
        assert_eq!(join_path("/admin/", "stats"), "/admin/stats");
        assert_eq!(join_path("", "/users"), "/users");
    }

    #[test]
    fn join_path_keeps_the_root_path_a_single_slash() {
        assert_eq!(join_path("", ""), "/");
        assert_eq!(join_path("", "/"), "/");
        assert_eq!(join_path("/api", "/"), "/api");
    }

    #[test]
    fn anon_handler_slugifies_the_path() {
        assert_eq!(anon_handler("GET", "/admin/stats"), "get_admin_stats");
        assert_eq!(anon_handler("POST", "/users/{id}"), "post_users_id");
    }

    #[test]
    fn anon_handler_names_the_root_path() {
        assert_eq!(anon_handler("GET", "/"), "get_root");
    }

    #[test]
    fn path_params_reads_all_three_template_dialects() {
        assert_eq!(path_params("/u/{id}"), vec!["id".to_string()]);
        assert_eq!(path_params("/u/<uuid:id>"), vec!["id".to_string()]);
        assert_eq!(path_params("/u/:id"), vec!["id".to_string()]);
        assert!(path_params("/u").is_empty());
    }

    #[test]
    fn path_params_dedups_across_dialects() {
        assert_eq!(path_params("/u/{id}/v/<id>"), vec!["id".to_string()]);
    }

    #[test]
    fn requires_auth_accepts_the_shared_table() {
        assert!(requires_auth("PreAuthorize"));
        assert!(requires_auth("authenticate"));
    }

    #[test]
    fn requires_auth_accepts_the_ecosystem_specific_spellings() {
        assert!(requires_auth("auth"));
        assert!(requires_auth("auth:api"));
        assert!(requires_auth("auth.basic"));
        assert!(requires_auth("authenticate_user!"));
        assert!(requires_auth("AuthSession"));
        assert!(requires_auth("IsGranted"));
        assert!(requires_auth(r"Illuminate\Auth\Middleware\Authenticate"));
        assert!(requires_auth("middleware::RequireAuth"));
    }

    #[test]
    fn requires_auth_accepts_an_applications_own_demand_phrase() {
        assert!(requires_auth("require_operator_token"));
        assert!(requires_auth("require_admin!"));
        assert!(requires_auth("ensure_signin"));
        assert!(requires_auth("requireApiKey"));
    }

    #[test]
    fn requires_auth_rejects_a_demand_phrase_with_no_credential_in_it() {
        assert!(!requires_auth("require_json_body"));
        assert!(!requires_auth("ensure_https"));
        assert!(!requires_auth("admin_dashboard"));
    }

    #[test]
    fn requires_auth_rejects_unrelated_names() {
        assert!(!requires_auth("throttle"));
        assert!(!requires_auth("author"));
        assert!(!requires_auth(""));
    }

    #[test]
    fn push_route_drops_a_nameless_handler() {
        let (mut m, mut r, mut g) = (Vec::new(), Vec::new(), Vec::new());
        let mut facts = Facts {
            markers: &mut m,
            routes: &mut r,
            guards: &mut g,
        };
        facts.push_route(
            &Route {
                method: "GET",
                path: "/x".to_string(),
                handler: String::new(),
                line: 1,
                framework: "laravel",
            },
            &[],
        );
        assert!(m.is_empty() && r.is_empty() && g.is_empty());
    }

    #[test]
    fn push_route_emits_a_marker_a_route_fact_and_a_guard() {
        let (mut m, mut r, mut g) = (Vec::new(), Vec::new(), Vec::new());
        let mut facts = Facts {
            markers: &mut m,
            routes: &mut r,
            guards: &mut g,
        };
        facts.push_route(
            &Route {
                method: "GET",
                path: "/u/{id}".to_string(),
                handler: "show".to_string(),
                line: 7,
                framework: "laravel",
            },
            &["throttle".to_string(), "auth".to_string()],
        );
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].marker_type, "laravel_route");
        assert_eq!(m[0].marker_name, "GET /u/{id}");
        assert_eq!(m[0].parameter_names, vec!["id".to_string()]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].route_pattern, "/u/{id}");
        assert_eq!(r[0].parameter_name, "id");
        assert!(r[0].is_tainted);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].marker_name, "auth");
        assert!(g[0].requires_auth);
    }

    #[test]
    fn push_guard_is_silent_without_an_authentication_name() {
        let (mut m, mut r, mut g) = (Vec::new(), Vec::new(), Vec::new());
        let mut facts = Facts {
            markers: &mut m,
            routes: &mut r,
            guards: &mut g,
        };
        facts.push_guard("show", 1, "laravel", &["throttle".to_string()]);
        assert!(g.is_empty());
    }

    #[test]
    fn string_text_unwraps_a_literal_and_survives_an_empty_one() {
        let mut p = tree_sitter::Parser::new();
        p.set_language(&tree_sitter_ruby::LANGUAGE.into()).unwrap();
        let src = "x = 'abc'\ny = ''\n";
        let tree = p.parse(src, None).unwrap();
        let mut found = Vec::new();
        collect_strings(tree.root_node(), src.as_bytes(), &mut found);
        assert_eq!(found, vec!["abc".to_string(), String::new()]);
    }

    fn collect_strings(node: Node, src: &[u8], out: &mut Vec<String>) {
        if node.kind() == "string" {
            out.push(string_text(node, src));
            return;
        }
        for c in crate::scan::kids(node) {
            collect_strings(c, src, out);
        }
    }

    #[test]
    fn rest_actions_covers_the_seven_conventional_routes() {
        assert_eq!(REST_ACTIONS.len(), 7);
        assert!(REST_ACTIONS
            .iter()
            .any(|(a, m, _)| *a == "destroy" && *m == "DELETE"));
    }
}
