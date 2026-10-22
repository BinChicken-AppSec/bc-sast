//! Shared plumbing for the PHP, Ruby, Kotlin and Rust entry-point
//! detectors.
//!
//! The four sibling modules all answer the same question — "what HTTP
//! routes does this file register, and is any of them behind an
//! authentication guard?" — so the fact-emission shape, the path
//! concatenation, the synthetic name an anonymous handler gets and the
//! guard-name test all live here rather than four times over.
//!
//! **What a route fact looks like for these languages.** The existing
//! Python/Java/C#/Express sections carry no HTTP *method*: a
//! `@GetMapping` and a `@PostMapping` both become
//! `marker_type = "spring_route"` with the bare path as the
//! `marker_name`, so the verb is lost. There is no field for it on
//! [`FrameworkMarkerFact`], and adding one would touch every
//! construction site in `framework.rs`. These detectors therefore spell
//! the marker name `"<METHOD> <path>"` (`"GET /admin/users/{id}"`) and
//! leave [`RouteTaintFact::route_pattern`] the bare path, so both the
//! verb and the group/controller-prefixed path survive into the fact
//! plane. Nothing outside this crate reads either field (S4 renders
//! `marker_type` only), so the convention is free to be the more
//! informative one.

use tree_sitter::Node;

use super::{normalize_guard_name, route_params, ANGLE_PARAM, BRACE_PARAM, COLON_PARAM};
use crate::scan::{named_kids, py_text, AuthGuardFact, FrameworkMarkerFact, RouteTaintFact};

/// The method name used when a registration binds every HTTP verb —
/// Laravel's `Route::any`, a Symfony `#[Route]` with no `methods:`
/// list, and Spring's bare `@RequestMapping`.
pub(super) const ANY_METHOD: &str = "ANY";

/// The three fact vectors a detector fills, bundled so the per-route
/// emission below needs one parameter instead of three.
pub(super) struct Facts<'a> {
    pub markers: &'a mut Vec<FrameworkMarkerFact>,
    pub routes: &'a mut Vec<RouteTaintFact>,
    pub guards: &'a mut Vec<AuthGuardFact>,
}

/// One recognized route registration.
pub(super) struct Route<'a> {
    /// `GET`/`POST`/… or [`ANY_METHOD`].
    pub method: &'a str,
    /// Already concatenated with every enclosing group/controller prefix.
    pub path: String,
    /// The handler's qnode — a real function/method name where one
    /// exists, else [`anon_handler`].
    pub handler: String,
    pub line: usize,
    pub framework: &'a str,
}

impl Facts<'_> {
    /// Emit the marker, one [`RouteTaintFact`] per path parameter, and
    /// an [`AuthGuardFact`] when any of `guard_names` demands
    /// authentication. A route with no handler name is dropped: an
    /// entry point keyed by an empty qnode is skipped downstream
    /// anyway.
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

    /// Record the first of `names` that demands authentication.
    /// Emitting nothing is what makes a handler reachable-from-unauth,
    /// so a name list with no guard in it is not an error.
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

/// Concatenate a group/controller prefix with a route path, normalizing
/// the slashes either side may or may not carry. The root path stays
/// `"/"` rather than collapsing to the empty string.
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

/// A stable qnode for a closure/lambda handler that has no name of its
/// own — `("GET", "/admin/stats")` -> `"get_admin_stats"`. Falling back
/// to the enclosing function (what the Express section does) would
/// collapse every route registered in one `routing { … }` block into a
/// single entry point, losing the per-route guard verdict that is the
/// whole point of the plane.
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

/// Path parameters in any of the three template dialects these
/// frameworks use: `{id}` (Laravel/Symfony/Ktor/Spring/axum/actix),
/// `<id>`/`<uuid:id>` (rocket) and `:id` (Rails/Sinatra/axum).
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

/// Guard spellings only these four ecosystems use, normalized the same
/// way [`normalize_guard_name`] normalizes the shared table. Kept
/// separate from `super::AUTH_REQUIRED_NAMES` so that adding, say, the
/// bare name `auth` for Laravel middleware cannot change what an
/// Express or Django decorator means.
const EXTRA_AUTH_NAMES: &[&str] = &[
    // Laravel `->middleware('auth')` / `'auth:api'`, axum
    // `from_fn(auth)`.
    "auth",
    // Laravel's HTTP-basic middleware alias.
    "auth.basic",
    // Devise's `before_action :authenticate_user!`.
    "authenticateuser",
    // axum-login's session extractor.
    "authsession",
    // The conventional JWT-claims extractor across axum/actix/rocket.
    "claims",
    // actix-web-httpauth's middleware.
    "httpauthentication",
    // Symfony's `#[IsGranted]`.
    "isgranted",
    // Laravel Sanctum's API guard.
    "sanctum",
    // Symfony's `#[Security("...")]` attribute and the `security`
    // option on `#[Route]`.
    "security",
];

/// The verbs an application's *own* guard function is named with. A
/// project writes its middleware as `require_operator_token` or
/// `require_admin!` far more often than it reuses one of the framework
/// names above, so a demand verb applied to a credential noun counts
/// too.
const DEMAND_VERBS: &[&str] = &["require", "ensure"];
/// …and the nouns that make such a name a *credential* demand rather
/// than a validation filter: `require_admin` is a guard,
/// `require_json_body` and `ensure_https` are not.
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

/// Whether `name` — a middleware, attribute, annotation, filter or
/// extractor name — says the handler requires authentication.
pub(super) fn requires_auth(name: &str) -> bool {
    // `Illuminate\Auth\Middleware\Authenticate`, `middleware::from_fn`,
    // `auth:api`, `authenticate_user!` — reduce each to the bare name
    // the tables are written against.
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

/// `require_operator_token` / `require_admin!` — a demand verb followed
/// somewhere by a credential noun.
fn is_demand_phrase(norm: &str) -> bool {
    DEMAND_VERBS.iter().any(|v| norm.starts_with(v))
        && CREDENTIAL_NOUNS.iter().any(|n| norm.contains(n))
}

/// The text a string-literal node carries, without its quotes. Every
/// one of these four grammars exposes the body as a `string_content`
/// child; an empty literal has none, hence the strip-the-quotes
/// fallback.
pub(super) fn string_text(node: Node, src: &[u8]) -> String {
    match named_kids(node).find(|c| c.kind() == "string_content") {
        Some(c) => py_text(c, src),
        None => super::strip_quotes(&py_text(node, src)).to_string(),
    }
}

/// The 7 actions a conventional REST resource routes to, as
/// `(action, method, path suffix)` against the resource's own base
/// path. Shared by Rails' `resources :users` and Laravel's
/// `Route::resource`, which generate the same table (Rails also maps
/// `PUT` onto `update`, a duplicate of the `PATCH` row that would add
/// no new entry point).
pub(super) const REST_ACTIONS: &[(&str, &str, &str)] = &[
    ("index", "GET", ""),
    ("create", "POST", ""),
    ("show", "GET", "/{id}"),
    ("update", "PATCH", "/{id}"),
    ("destroy", "DELETE", "/{id}"),
    ("edit", "GET", "/{id}/edit"),
    ("new", "GET", "/new"),
];

/// Shared fixtures for the four sibling modules' own unit tests.
#[cfg(test)]
pub(super) mod testing {
    use crate::scan::{AuthGuardFact, FrameworkMarkerFact, RouteTaintFact};

    /// Parse `src` as `language` and run the whole framework plane over
    /// it, exactly as `scan_file` does.
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

    /// `"<METHOD> <path>"` per marker, in emission order.
    pub(in crate::framework) fn marker_names(m: &[FrameworkMarkerFact]) -> Vec<String> {
        m.iter().map(|f| f.marker_name.clone()).collect()
    }

    /// `"<pattern>:<parameter>"` per route fact, in emission order.
    pub(in crate::framework) fn route_patterns(r: &[RouteTaintFact]) -> Vec<String> {
        r.iter()
            .map(|f| format!("{}:{}", f.route_pattern, f.parameter_name))
            .collect()
    }

    /// `(handler, guard name)` per recorded guard.
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
        // `<id>` matches the angle dialect and `{id}` the brace one;
        // the same name must not be reported twice.
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
        // The names real projects give their own middleware, which no
        // framework table can enumerate.
        assert!(requires_auth("require_operator_token"));
        assert!(requires_auth("require_admin!"));
        assert!(requires_auth("ensure_signin"));
        assert!(requires_auth("requireApiKey"));
    }

    #[test]
    fn requires_auth_rejects_a_demand_phrase_with_no_credential_in_it() {
        assert!(!requires_auth("require_json_body"));
        assert!(!requires_auth("ensure_https"));
        // A credential noun on its own is not a demand.
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
