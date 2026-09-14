//! Rust entry points: axum's `Router` builder, actix-web's attribute
//! macros and `web::resource(...).route(...)` form, and rocket's
//! attribute macros.
//!
//! **Which framework an attribute belongs to.** `#[get("/p")]` is
//! spelled identically by actix-web and rocket, and nothing in the
//! attribute itself distinguishes them, so the file's own `use`
//! declarations decide: a file that imports `rocket` is rocket's,
//! everything else is attributed to actix-web.
//!
//! **Guards.** A router-level `.route_layer(middleware::from_fn(auth))`
//! or `.layer(HttpAuthentication::bearer(...))` guards every route in
//! the chain it wraps. A handler that takes an `AuthSession`, `Claims`
//! or `RequireAuth` extractor guards itself: in all three frameworks
//! such an extractor rejects the request before the body runs, which is
//! exactly what a middleware guard does.
//!
//! **Routers built in a local.** The idiomatic way to write a guarded
//! section of an axum app is to build it in a `let` and merge it in:
//!
//! This executable example scans source text through the public API. The
//! target snippet is parsed, not compiled or executed, so this crate does not
//! need axum or implementations of the target's handlers and middleware.
//!
//! ```rust
//! let source = r#"
//! fn app() -> Router {
//!     let operator_routes = Router::new()
//!         .route("/admin/jobs/rebuild", post(rebuild_index))
//!         .route_layer(middleware::from_fn(require_operator_token));
//!     Router::new().route("/search", get(search)).merge(operator_routes)
//! }
//! "#;
//! let file = tempfile::NamedTempFile::new()?;
//! std::fs::write(file.path(), source)?;
//! let facts = bc_callgraph::scan_file(
//!     file.path(), "app.rs", "rust", &[], &[], false, None, None,
//! ).expect("Rust source should be parsed");
//! assert_eq!(facts.framework_markers.len(), 2);
//! assert!(facts.framework_markers.iter().any(|route|
//!     route.marker_name == "POST /admin/jobs/rebuild"
//!         && route.function_qnode == "rebuild_index"));
//! assert!(facts.framework_markers.iter().any(|route|
//!     route.marker_name == "GET /search" && route.function_qnode == "search"));
//! assert_eq!(facts.auth_guards.len(), 1);
//! assert_eq!(facts.auth_guards[0].function_qnode, "rebuild_index");
//! assert_eq!(facts.auth_guards[0].marker_name, "require_operator_token");
//! assert!(facts.auth_guards[0].requires_auth);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! so a walk that only followed receiver chains would report the merged
//! routes without the parent's prefix, and would miss a guard the
//! parent applies *after* the merge. Every `let` binding in the file is
//! therefore resolved at its `.merge(...)`/`.nest("/p", ...)` call site
//! and walked there with that site's prefix and guards; a binding
//! consumed that way is skipped where it is declared, so its routes are
//! emitted exactly once.
//!
//! **Not attempted.** `.nest("/api", api_routes())` where the nested
//! router is returned by a *function* — binding that needs the
//! cross-file resolution this per-file plane does not have, so only an
//! inline `Router` or a local holding one picks up the prefix.

use std::collections::{BTreeMap, BTreeSet};

use tree_sitter::Node;

use super::common::{self, Facts, Route};
use crate::scan::{kids, named_kids, py_text, AuthGuardFact, FrameworkMarkerFact, RouteTaintFact};

fn verb_method(name: &str) -> Option<&'static str> {
    Some(match name {
        "get" => "GET",
        "post" => "POST",
        "put" => "PUT",
        "delete" => "DELETE",
        "patch" => "PATCH",
        "head" => "HEAD",
        "options" => "OPTIONS",
        _ => return None,
    })
}

/// Path prefix and guards in force in one `Router` builder chain.
#[derive(Clone, Default)]
struct Ctx {
    prefix: String,
    guards: Vec<String>,
}

pub(super) fn visit(
    root: Node,
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) {
    let mut facts = Facts {
        markers,
        routes,
        guards,
    };
    let env = Env::build(root, src);
    walk(root, src, &Ctx::default(), &env, &mut facts);
    let framework = if uses_rocket(root, src) {
        "rocket"
    } else {
        "actix"
    };
    attribute_routes(root, src, framework, &env.signatures, &mut facts);
}

/// The whole-file lookups the walk needs.
struct Env<'a> {
    /// Parameter type names per function, so a route naming its handler
    /// can see the extractors that handler takes.
    signatures: BTreeMap<String, Vec<String>>,
    /// `let name = <expr>;` bindings in source order, so a shadowed
    /// name still resolves to the binding actually in scope at a use.
    bindings: Vec<(String, Node<'a>)>,
    /// [`Node::id`] of every binding value a `merge`/`nest` consumes:
    /// the ordinary walk leaves those to that call site so their routes
    /// are emitted once, with the merging chain's prefix and guards.
    consumed: BTreeSet<usize>,
}

impl<'a> Env<'a> {
    fn build(root: Node<'a>, src: &[u8]) -> Self {
        let mut signatures = BTreeMap::new();
        collect_signatures(root, src, &mut signatures);
        let mut bindings = Vec::new();
        collect_bindings(root, src, &mut bindings);
        let mut env = Env {
            signatures,
            bindings,
            consumed: BTreeSet::new(),
        };
        env.consumed = consumed_bindings(root, src, &env);
        env
    }

    /// The binding `name` refers to at byte offset `before` — the last
    /// one declared ahead of it, since Rust requires a local to be
    /// declared before use and shadowing rebinds the name.
    fn resolve(&self, name: &str, before: usize) -> Option<Node<'a>> {
        self.bindings
            .iter()
            .rev()
            .find(|(n, value)| n == name && value.start_byte() < before)
            .map(|(_, value)| *value)
    }
}

fn collect_bindings<'a>(node: Node<'a>, src: &[u8], out: &mut Vec<(String, Node<'a>)>) {
    if node.kind() == "let_declaration" {
        if let (Some(pattern), Some(value)) = (
            node.child_by_field_name("pattern"),
            node.child_by_field_name("value"),
        ) {
            if pattern.kind() == "identifier" {
                out.push((py_text(pattern, src), value));
            }
        }
    }
    for c in kids(node) {
        collect_bindings(c, src, out);
    }
}

/// Which binding values are named as an argument to a `merge`/`nest`.
fn consumed_bindings(node: Node, src: &[u8], env: &Env) -> BTreeSet<usize> {
    let mut out = BTreeSet::new();
    collect_consumed(node, src, env, &mut out);
    out
}

fn collect_consumed(node: Node, src: &[u8], env: &Env, out: &mut BTreeSet<usize>) {
    if node.kind() == "call_expression" {
        if let Some((name, _, args)) = method_call(node, src) {
            if is_composition(&name) {
                for a in args.iter().filter(|a| a.kind() == "identifier") {
                    let bound = env.resolve(&py_text(*a, src), node.start_byte());
                    out.extend(bound.map(|b| b.id()));
                }
            }
        }
    }
    for c in kids(node) {
        collect_consumed(c, src, env, out);
    }
}

fn is_composition(name: &str) -> bool {
    matches!(name, "merge" | "nest" | "nest_service")
}

fn collect_signatures(node: Node, src: &[u8], out: &mut BTreeMap<String, Vec<String>>) {
    if node.kind() == "function_item" {
        if let Some(name) = node.child_by_field_name("name") {
            let params = node
                .child_by_field_name("parameters")
                .map(|p| {
                    named_kids(p)
                        .filter_map(|param| param.child_by_field_name("type"))
                        .map(|t| py_text(t, src))
                        .collect()
                })
                .unwrap_or_default();
            out.insert(py_text(name, src), params);
        }
    }
    for c in kids(node) {
        collect_signatures(c, src, out);
    }
}

fn uses_rocket(node: Node, src: &[u8]) -> bool {
    if node.kind() == "use_declaration" && py_text(node, src).contains("rocket") {
        return true;
    }
    kids(node).any(|c| uses_rocket(c, src))
}

// ── axum / actix builder chains ──────────────────────────────────────────

/// `(method name, receiver, argument values)` for `recv.method(args)`.
fn method_call<'a>(node: Node<'a>, src: &[u8]) -> Option<(String, Node<'a>, Vec<Node<'a>>)> {
    let func = node
        .child_by_field_name("function")
        .filter(|f| f.kind() == "field_expression")?;
    let name = py_text(func.child_by_field_name("field")?, src);
    let receiver = func.child_by_field_name("value")?;
    let args = node
        .child_by_field_name("arguments")
        .map(|a| named_kids(a).collect())
        .unwrap_or_default();
    Some((name, receiver, args))
}

fn walk(node: Node, src: &[u8], ctx: &Ctx, env: &Env, facts: &mut Facts) {
    match node.kind() {
        // Walked at the `merge`/`nest` that consumes it instead.
        "let_declaration"
            if node
                .child_by_field_name("value")
                .is_some_and(|v| env.consumed.contains(&v.id())) =>
        {
            return;
        }
        "call_expression" => {
            if let Some((name, receiver, args)) = method_call(node, src) {
                if builder_call(&name, node, receiver, &args, src, ctx, env, facts) {
                    return;
                }
            }
        }
        _ => {}
    }
    for c in kids(node) {
        walk(c, src, ctx, env, facts);
    }
}

/// `true` when this was a router-builder call whose receiver (and any
/// composed router) has already been walked.
#[allow(clippy::too_many_arguments)]
fn builder_call(
    name: &str,
    node: Node,
    receiver: Node,
    args: &[Node],
    src: &[u8],
    ctx: &Ctx,
    env: &Env,
    facts: &mut Facts,
) -> bool {
    match name {
        "route" => {
            route_call(receiver, args, src, ctx, env, facts);
        }
        n if is_composition(n) => {
            let mut inner = ctx.clone();
            // `.merge(r)` composes at the current prefix;
            // `.nest("/api", r)` mounts underneath its own.
            let composed = match args.first().filter(|a| is_string(**a)) {
                Some(prefix) => {
                    inner.prefix =
                        common::join_path(&ctx.prefix, &common::string_text(*prefix, src));
                    &args[1..]
                }
                None if n == "merge" => args,
                // A `nest` whose prefix is not a literal: its routes
                // would be reported at the wrong path, so leave them.
                None => &[],
            };
            for a in composed {
                walk(composed_router(*a, node, src, env), src, &inner, env, facts);
            }
        }
        "route_layer" | "layer" | "wrap" => {
            let mut inner = ctx.clone();
            for a in args {
                identifiers(*a, src, &mut inner.guards);
            }
            walk(receiver, src, &inner, env, facts);
            return true;
        }
        _ => return false,
    }
    walk(receiver, src, ctx, env, facts);
    true
}

/// The router expression a composition argument stands for: the value
/// of the `let` binding it names, or the argument itself when it is an
/// inline `Router::new()...` chain.
fn composed_router<'a>(arg: Node<'a>, call: Node, src: &[u8], env: &Env<'a>) -> Node<'a> {
    if arg.kind() != "identifier" {
        return arg;
    }
    env.resolve(&py_text(arg, src), call.start_byte())
        .unwrap_or(arg)
}

fn is_string(node: Node) -> bool {
    matches!(node.kind(), "string_literal" | "raw_string_literal")
}

/// `.route("/p", get(h))` (axum) or `web::resource("/p").route(web::get().to(h))`
/// (actix): the path comes from the call's own first argument in the
/// first form and from the receiver's `resource`/`scope` in the second,
/// which is also what tells the two frameworks apart.
fn route_call(receiver: Node, args: &[Node], src: &[u8], ctx: &Ctx, env: &Env, facts: &mut Facts) {
    let (framework, raw) = match args.first().filter(|a| is_string(**a)) {
        Some(a) => ("axum", common::string_text(*a, src)),
        None => match resource_path(receiver, src) {
            Some(p) => ("actix", p),
            None => return,
        },
    };
    let path = common::join_path(&ctx.prefix, &raw);
    let mut bindings = Vec::new();
    for a in args {
        method_routes(*a, src, &mut bindings);
    }
    for (method, handler, line) in bindings {
        let mut guards = ctx.guards.clone();
        guards.extend(env.signatures.get(&handler).cloned().unwrap_or_default());
        facts.push_route(
            &Route {
                method: &method,
                path: path.clone(),
                handler,
                line,
                framework,
            },
            &guards,
        );
    }
}

/// The path an actix `web::resource("/p")` / `web::scope("/api")` call
/// in `node`'s receiver chain declares.
fn resource_path(node: Node, src: &[u8]) -> Option<String> {
    if node.kind() == "call_expression" {
        let name = node
            .child_by_field_name("function")
            .map(|f| py_text(f, src))
            .unwrap_or_default();
        let leaf = name.rsplit("::").next().unwrap_or(&name);
        if matches!(leaf, "resource" | "scope") {
            return node
                .child_by_field_name("arguments")
                .and_then(|a| named_kids(a).find(|v| is_string(*v)))
                .map(|v| common::string_text(v, src));
        }
    }
    kids(node).find_map(|c| resource_path(c, src))
}

/// Every `(METHOD, handler, line)` binding under `node`: axum's
/// `get(show)` and `get(show).post(create)`, and actix's
/// `web::get().to(show)`.
fn method_routes(node: Node, src: &[u8], out: &mut Vec<(String, String, usize)>) {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            let line = node.start_position().row + 1;
            if func.kind() == "identifier" {
                if let Some(m) = verb_method(&py_text(func, src)) {
                    out.extend(first_ident_arg(node, src).map(|h| (m.to_string(), h, line)));
                }
            } else if func.kind() == "field_expression" {
                let field = func
                    .child_by_field_name("field")
                    .map(|f| py_text(f, src))
                    .unwrap_or_default();
                let method = if field == "to" {
                    func.child_by_field_name("value")
                        .and_then(|v| receiver_verb(v, src))
                } else {
                    verb_method(&field).map(str::to_string)
                };
                if let Some(m) = method {
                    out.extend(first_ident_arg(node, src).map(|h| (m, h, line)));
                }
            }
        }
    }
    for c in kids(node) {
        method_routes(c, src, out);
    }
}

/// The verb `web::get()` names, for actix's `web::get().to(handler)`.
fn receiver_verb(node: Node, src: &[u8]) -> Option<String> {
    let func = node
        .child_by_field_name("function")
        .filter(|_| node.kind() == "call_expression")?;
    let text = py_text(func, src);
    let leaf = text.rsplit("::").next().unwrap_or(&text);
    verb_method(leaf).map(str::to_string)
}

/// The first argument that names a function, by its leaf path segment.
fn first_ident_arg(call: Node, src: &[u8]) -> Option<String> {
    let args = call.child_by_field_name("arguments")?;
    named_kids(args)
        .find(|a| matches!(a.kind(), "identifier" | "scoped_identifier"))
        .map(|a| {
            let text = py_text(a, src);
            text.rsplit("::").next().unwrap_or(&text).to_string()
        })
}

/// Every identifier under `node` — a `.layer(...)` argument names its
/// middleware somewhere in there, whatever wrapper it is written with.
fn identifiers(node: Node, src: &[u8], out: &mut Vec<String>) {
    if matches!(node.kind(), "identifier" | "type_identifier") {
        out.push(py_text(node, src));
    }
    for c in kids(node) {
        identifiers(c, src, out);
    }
}

// ── attribute-macro handlers ─────────────────────────────────────────────

fn attribute_routes(
    node: Node,
    src: &[u8],
    framework: &str,
    signatures: &BTreeMap<String, Vec<String>>,
    facts: &mut Facts,
) {
    if node.kind() == "function_item" {
        attribute_handler(node, src, framework, signatures, facts);
    }
    for c in kids(node) {
        attribute_routes(c, src, framework, signatures, facts);
    }
}

fn attribute_handler(
    node: Node,
    src: &[u8],
    framework: &str,
    signatures: &BTreeMap<String, Vec<String>>,
    facts: &mut Facts,
) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let handler = py_text(name_node, src);
    let guards = signatures.get(&handler).cloned().unwrap_or_default();
    let mut prev = node.prev_named_sibling();
    while let Some(attr) = prev.filter(|p| p.kind() == "attribute_item") {
        if let Some((method, path)) = attribute_route(attr, src) {
            facts.push_route(
                &Route {
                    method,
                    path,
                    handler: handler.clone(),
                    line: node.start_position().row + 1,
                    framework,
                },
                &guards,
            );
        }
        prev = attr.prev_named_sibling();
    }
}

/// `#[get("/p")]` / `#[actix_web::post("/p")]` -> `("GET", "/p")`.
fn attribute_route(item: Node, src: &[u8]) -> Option<(&'static str, String)> {
    let attr = named_kids(item).find(|c| c.kind() == "attribute")?;
    let name = named_kids(attr)
        .find(|c| matches!(c.kind(), "identifier" | "scoped_identifier"))
        .map(|n| py_text(n, src))?;
    let leaf = name.rsplit("::").next().unwrap_or(&name);
    let method = verb_method(leaf)?;
    let tokens = attr.child_by_field_name("arguments")?;
    let path = named_kids(tokens).find(|t| is_string(*t))?;
    Some((method, common::string_text(path, src)))
}

#[cfg(test)]
mod tests {
    use super::common::testing::{facts_for, guard_names, marker_names, route_patterns};
    use super::*;

    #[allow(clippy::type_complexity)]
    fn rust(
        src: &str,
    ) -> (
        Vec<FrameworkMarkerFact>,
        Vec<RouteTaintFact>,
        Vec<AuthGuardFact>,
    ) {
        facts_for("rust", src)
    }

    #[test]
    fn an_axum_route_reports_its_method_path_and_handler() {
        let (m, r, g) = rust(
            "fn app() -> Router {\n\
             \x20   Router::new().route(\"/users/{id}\", get(show))\n}\n\
             async fn show() -> String { String::new() }\n",
        );
        assert_eq!(marker_names(&m), vec!["GET /users/{id}".to_string()]);
        assert_eq!(m[0].function_qnode, "show");
        assert_eq!(m[0].marker_type, "axum_route");
        assert_eq!(m[0].line, 2);
        assert_eq!(route_patterns(&r), vec!["/users/{id}:id".to_string()]);
        assert!(g.is_empty());
    }

    #[test]
    fn an_axum_method_router_chain_binds_every_verb_it_names() {
        let (m, _, _) = rust(
            "fn app() -> Router {\n\
             \x20   Router::new().route(\"/users\", get(list).post(create))\n}\n",
        );
        // The outermost `.post(create)` call is reached first; both
        // bindings are on the same `.route(...)`.
        let mut names = marker_names(&m);
        names.sort();
        assert_eq!(
            names,
            vec!["GET /users".to_string(), "POST /users".to_string()]
        );
    }

    #[test]
    fn an_axum_nest_prefixes_the_routes_inside_it() {
        let (m, _, _) = rust(
            "fn app() -> Router {\n\
             \x20   Router::new().nest(\"/api\", Router::new().route(\"/ping\", get(ping)))\n}\n",
        );
        assert_eq!(marker_names(&m), vec!["GET /api/ping".to_string()]);
    }

    #[test]
    fn an_axum_nest_without_a_literal_prefix_is_ignored() {
        let (m, _, _) = rust(
            "fn app() -> Router {\n\
             \x20   Router::new().nest(prefix, Router::new().route(\"/ping\", get(ping)))\n}\n",
        );
        // A route reported at the wrong path is worse than one not
        // reported at all, so the nested router is left alone.
        assert!(m.is_empty());
    }

    #[test]
    fn a_merged_local_router_keeps_the_guard_its_own_chain_applies() {
        let (m, _, g) = rust(
            "fn app() -> Router {\n\
             \x20   let operator = Router::new()\n\
             \x20       .route(\"/admin/jobs\", post(rebuild))\n\
             \x20       .route_layer(middleware::from_fn(require_operator_token));\n\
             \n\
             \x20   Router::new().route(\"/search\", get(search)).merge(operator)\n}\n",
        );
        // Each route exactly once: the binding is walked where it is
        // merged, not where it is declared.
        assert_eq!(m.len(), 2);
        assert_eq!(
            guard_names(&g),
            vec![("rebuild".to_string(), "require_operator_token".to_string())]
        );
        assert_eq!(
            marker_names(&m),
            vec!["POST /admin/jobs".to_string(), "GET /search".to_string()]
        );
    }

    #[test]
    fn a_nested_local_router_takes_the_nest_prefix_and_the_parent_guard() {
        let (m, _, g) = rust(
            "fn app() -> Router {\n\
             \x20   let console = Router::new().route(\"/jobs\", get(jobs));\n\
             \x20   Router::new()\n\
             \x20       .nest(\"/admin\", console)\n\
             \x20       .route_layer(middleware::from_fn(require_admin_token))\n}\n",
        );
        assert_eq!(marker_names(&m), vec!["GET /admin/jobs".to_string()]);
        assert_eq!(
            guard_names(&g),
            vec![("jobs".to_string(), "require_admin_token".to_string())]
        );
    }

    #[test]
    fn a_merged_inline_router_needs_no_binding() {
        let (m, _, _) = rust(
            "fn app() -> Router {\n\
             \x20   Router::new().merge(Router::new().route(\"/ping\", get(ping)))\n}\n",
        );
        assert_eq!(marker_names(&m), vec!["GET /ping".to_string()]);
    }

    #[test]
    fn a_merge_of_an_unbound_name_declares_nothing() {
        let (m, _, _) = rust("fn app() -> Router {\n    Router::new().merge(elsewhere())\n}\n");
        assert!(m.is_empty());
    }

    #[test]
    fn a_binding_declared_after_its_use_is_not_resolved() {
        // Rust could not compile this; the ordering rule is what keeps
        // a shadowed name from resolving forwards into a cycle.
        let (m, _, _) = rust(
            "fn app() -> Router {\n\
             \x20   Router::new().merge(later);\n\
             \x20   let later = Router::new().route(\"/ping\", get(ping));\n}\n",
        );
        // The binding is still walked where it is declared.
        assert_eq!(marker_names(&m), vec!["GET /ping".to_string()]);
    }

    #[test]
    fn a_shadowed_binding_resolves_to_the_one_in_scope() {
        let (m, _, _) = rust(
            "fn app() -> Router {\n\
             \x20   let part = Router::new().route(\"/first\", get(first));\n\
             \x20   let app = Router::new().nest(\"/a\", part);\n\
             \x20   let part = Router::new().route(\"/second\", get(second));\n\
             \x20   app.nest(\"/b\", part)\n}\n",
        );
        assert_eq!(
            marker_names(&m),
            vec!["GET /a/first".to_string(), "GET /b/second".to_string()]
        );
    }

    #[test]
    fn an_axum_route_layer_guards_the_chain_it_wraps() {
        let (m, _, g) = rust(
            "fn app() -> Router {\n\
             \x20   Router::new()\n\
             \x20       .route(\"/closed\", get(closed))\n\
             \x20       .route_layer(middleware::from_fn(auth))\n}\n",
        );
        assert_eq!(m.len(), 1);
        assert_eq!(
            guard_names(&g),
            vec![("closed".to_string(), "auth".to_string())]
        );
    }

    #[test]
    fn an_axum_layer_of_unrelated_middleware_guards_nothing() {
        let (_, _, g) = rust(
            "fn app() -> Router {\n\
             \x20   Router::new()\n\
             \x20       .route(\"/open\", get(open))\n\
             \x20       .layer(TraceLayer::new_for_http())\n}\n",
        );
        assert!(g.is_empty());
    }

    #[test]
    fn an_extractor_in_the_handler_signature_guards_the_route() {
        let (_, _, g) = rust(
            "fn app() -> Router {\n\
             \x20   Router::new().route(\"/me\", get(me))\n}\n\
             async fn me(session: AuthSession) -> String { String::new() }\n",
        );
        assert_eq!(
            guard_names(&g),
            vec![("me".to_string(), "AuthSession".to_string())]
        );
    }

    #[test]
    fn a_route_call_naming_no_handler_declares_nothing() {
        let (m, _, _) = rust("fn app() -> Router {\n    Router::new().route(\"/x\", 1)\n}\n");
        assert!(m.is_empty());
    }

    #[test]
    fn a_route_call_with_neither_a_literal_nor_a_resource_is_ignored() {
        let (m, _, _) = rust("fn app() -> Router {\n    r.route(path, get(h))\n}\n");
        assert!(m.is_empty());
    }

    #[test]
    fn an_unrelated_method_call_is_not_a_router_builder() {
        let (m, _, _) = rust("fn f() {\n    map.insert(\"/x\", 1);\n}\n");
        assert!(m.is_empty());
    }

    #[test]
    fn an_actix_resource_route_reports_its_method_path_and_handler() {
        let (m, _, _) = rust(
            "fn cfg(c: &mut ServiceConfig) {\n\
             \x20   c.service(web::resource(\"/p\").route(web::get().to(handler)));\n}\n",
        );
        assert_eq!(marker_names(&m), vec!["GET /p".to_string()]);
        assert_eq!(m[0].function_qnode, "handler");
        assert_eq!(m[0].marker_type, "actix_route");
    }

    #[test]
    fn an_actix_scope_route_reports_its_path() {
        let (m, _, _) = rust(
            "fn cfg(c: &mut ServiceConfig) {\n\
             \x20   c.service(web::scope(\"/api\").route(web::post().to(create)));\n}\n",
        );
        assert_eq!(marker_names(&m), vec!["POST /api".to_string()]);
    }

    #[test]
    fn an_actix_wrap_of_http_authentication_guards_the_chain_it_wraps() {
        let (m, _, g) = rust(
            "fn cfg(c: &mut ServiceConfig) {\n\
             \x20   c.service(\n\
             \x20       web::resource(\"/p\")\n\
             \x20           .route(web::get().to(handler))\n\
             \x20           .wrap(HttpAuthentication::bearer(validator)),\n\
             \x20   );\n}\n",
        );
        assert_eq!(m.len(), 1);
        assert_eq!(
            guard_names(&g),
            vec![("handler".to_string(), "HttpAuthentication".to_string())]
        );
    }

    #[test]
    fn an_actix_attribute_handler_reports_its_method_path_and_handler() {
        let (m, r, g) = rust(
            "#[actix_web::get(\"/items/{id}\")]\n\
             async fn item(id: web::Path<u32>) -> HttpResponse { HttpResponse::Ok().finish() }\n",
        );
        assert_eq!(marker_names(&m), vec!["GET /items/{id}".to_string()]);
        assert_eq!(m[0].function_qnode, "item");
        assert_eq!(m[0].framework, "actix");
        assert_eq!(route_patterns(&r), vec!["/items/{id}:id".to_string()]);
        assert!(g.is_empty());
    }

    #[test]
    fn an_attribute_handler_taking_a_claims_extractor_is_guarded() {
        let (_, _, g) = rust(
            "#[post(\"/p\")]\nasync fn p(claims: Claims) -> HttpResponse { HttpResponse::Ok().finish() }\n",
        );
        assert_eq!(
            guard_names(&g),
            vec![("p".to_string(), "Claims".to_string())]
        );
    }

    #[test]
    fn a_rocket_attribute_handler_is_attributed_to_rocket() {
        let (m, r, _) = rust(
            "use rocket::get;\n\n#[get(\"/items/<id>\")]\nfn item(id: u32) -> String { String::new() }\n",
        );
        assert_eq!(marker_names(&m), vec!["GET /items/<id>".to_string()]);
        assert_eq!(m[0].framework, "rocket");
        assert_eq!(route_patterns(&r), vec!["/items/<id>:id".to_string()]);
    }

    #[test]
    fn a_non_route_attribute_declares_nothing() {
        let (m, _, _) = rust("#[derive(Debug)]\nstruct S;\n\n#[test]\nfn t() {}\n");
        assert!(m.is_empty());
    }

    #[test]
    fn a_route_attribute_without_a_path_declares_nothing() {
        let (m, _, _) = rust("#[get]\nfn t() {}\n");
        assert!(m.is_empty());
    }

    #[test]
    fn a_route_attribute_with_no_string_argument_declares_nothing() {
        let (m, _, _) = rust("#[get(index)]\nfn t() {}\n");
        assert!(m.is_empty());
    }

    #[test]
    fn every_attribute_verb_maps_to_its_own_method() {
        for (verb, method) in [
            ("put", "PUT"),
            ("delete", "DELETE"),
            ("patch", "PATCH"),
            ("head", "HEAD"),
            ("options", "OPTIONS"),
        ] {
            let (m, _, _) = rust(&format!("#[{verb}(\"/u\")]\nfn t() {{}}\n"));
            assert_eq!(m[0].marker_name, format!("{method} /u"));
        }
    }
}
