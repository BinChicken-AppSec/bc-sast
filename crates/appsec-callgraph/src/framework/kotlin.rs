//! Kotlin entry points: Ktor's `routing { … }` DSL and the Spring
//! annotations a Kotlin controller shares with its Java counterpart.
//!
//! **Handler naming.** A Ktor handler is a lambda with no name, and the
//! enclosing `Application.module` function is no substitute: one module
//! routinely registers a guarded and an unguarded route side by side,
//! and naming both after the module would collapse them into one entry
//! point whose guard verdict is whichever was recorded first. So the
//! name comes from the lambda itself where the lambda names one —
//! `post("/ops/snapshot/restore") { restoreConsoleSnapshot(call, svc) }`
//! is a pure delegation, and `restoreConsoleSnapshot` is the function a
//! later stage will actually be reading when it asks whether this route
//! is guarded (see [`delegate_handler`]). Anything less clear-cut, and
//! any name two routes in the file share (see [`ambiguous_delegates`]),
//! falls back to [`common::anon_handler`]'s path-derived
//! `post_ops_snapshot_restore`. A Spring handler is a named function and
//! keeps its own name, exactly as the Java section does.
//!
//! **Not attempted.** `@RequestMapping(method = [RequestMethod.GET])` —
//! the verb reads as `ANY` rather than `GET`, which is what the Java
//! section does with the same annotation.

use std::collections::{BTreeMap, BTreeSet};

use tree_sitter::Node;

use super::common::{self, Facts, Route, ANY_METHOD};
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

/// The Spring mapping annotations, shared with `framework.rs`'s Java
/// section.
fn mapping_method(name: &str) -> Option<&'static str> {
    Some(match name {
        "GetMapping" => "GET",
        "PostMapping" => "POST",
        "PutMapping" => "PUT",
        "DeleteMapping" => "DELETE",
        "PatchMapping" => "PATCH",
        "RequestMapping" => ANY_METHOD,
        _ => return None,
    })
}

/// Path prefix and guards in force — a Ktor `route("/api") { … }` or a
/// Spring `@RequestMapping` on the enclosing class — plus the one
/// file-wide fact the walk needs, computed once before it starts.
#[derive(Clone)]
struct Ctx<'a> {
    prefix: String,
    guards: Vec<String>,
    /// Delegate names that more than one route in this file resolves
    /// to; see [`ambiguous_delegates`].
    ambiguous: &'a BTreeSet<String>,
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
    let ambiguous = ambiguous_delegates(root, src);
    let ctx = Ctx {
        prefix: String::new(),
        guards: Vec::new(),
        ambiguous: &ambiguous,
    };
    walk(root, src, &ctx, &mut facts);
}

fn walk(node: Node, src: &[u8], ctx: &Ctx, facts: &mut Facts) {
    match node.kind() {
        "class_declaration" => {
            spring_class(node, src, ctx, facts);
            return;
        }
        "function_declaration" => spring_function(node, src, ctx, facts),
        // A recognized Ktor DSL call has already walked its own lambda.
        "call_expression" if ktor_call(node, src, ctx, facts) => return,
        _ => {}
    }
    for c in kids(node) {
        walk(c, src, ctx, facts);
    }
}

// ── Ktor ─────────────────────────────────────────────────────────────────

/// `(callee, first string argument, trailing lambda)` for a Ktor DSL
/// call. tree-sitter-kotlin-ng spells `get("/p") { … }` as a
/// `call_expression` wrapping the `get("/p")` `call_expression` plus an
/// `annotated_lambda`, and the argument-less `routing { … }` as the
/// callee identifier plus the lambda, so both shapes are unwrapped here.
fn dsl_call<'a>(node: Node<'a>, src: &[u8]) -> Option<(String, Option<String>, Option<Node<'a>>)> {
    let lambda = named_kids(node).find(|c| c.kind() == "annotated_lambda");
    let first = named_kids(node).next()?;
    let (callee, args) = match first.kind() {
        "identifier" => (
            first,
            named_kids(node).find(|c| c.kind() == "value_arguments"),
        ),
        "call_expression" => {
            let inner = named_kids(first).next()?;
            (
                inner,
                named_kids(first).find(|c| c.kind() == "value_arguments"),
            )
        }
        _ => return None,
    };
    if callee.kind() != "identifier" {
        return None;
    }
    Some((
        py_text(callee, src),
        args.and_then(|a| first_string(a, src)),
        lambda,
    ))
}

/// The first string literal among a `value_arguments` node's arguments.
fn first_string(args: Node, src: &[u8]) -> Option<String> {
    named_kids(args)
        .filter_map(|a| named_kids(a).next())
        .find(|v| v.kind() == "string_literal")
        .map(|v| common::string_text(v, src))
}

/// The trailing lambda of a Ktor *verb* call — `get("/x") { … }`, the
/// one shape [`ktor_call`] turns into a route. `None` for `routing`,
/// `route`, `authenticate`, a call with no trailing lambda and anything
/// that is not a call at all.
fn verb_lambda<'a>(node: Node<'a>, src: &[u8]) -> Option<Node<'a>> {
    if node.kind() != "call_expression" {
        return None;
    }
    let (name, _, lambda) = dsl_call(node, src)?;
    verb_method(&name)?;
    lambda
}

/// The function a route lambda merely hands the request to —
/// `post("/x") { restoreConsoleSnapshot(call, service) }` ->
/// `restoreConsoleSnapshot`.
///
/// tree-sitter-kotlin-ng nests the body's statements directly under the
/// `annotated_lambda`'s `lambda_literal` (the braces are anonymous
/// children), so a pure delegation is a `lambda_literal` whose only
/// named child is a `call_expression` whose own first named child is a
/// bare `identifier`.
///
/// Only that shape counts, because only that shape says the lambda has
/// no code of its own:
/// - an empty body has no statement to name;
/// - an inline body (`{ call.respond(1) }`) reaches its callee through a
///   `navigation_expression`, not a bare identifier, and its code is
///   right there in the lambda;
/// - a body with a second statement of any kind — `{ audit(); handle() }`,
///   `{ val id = …; handle(id) }` — does work the delegate does not see;
/// - a higher-order call carrying its own trailing lambda
///   (`{ withContext { … } }`) names the *combinator*, not the handler.
///
/// Every one of those returns `None` and leaves the route with its
/// synthetic path-derived name, which is exactly what the whole file
/// used to get.
fn delegate_handler(lambda: Node, src: &[u8]) -> Option<String> {
    let body = named_kids(lambda).find(|c| c.kind() == "lambda_literal")?;
    let mut stmts = named_kids(body);
    let only = stmts.next()?;
    if stmts.next().is_some() || only.kind() != "call_expression" {
        return None;
    }
    let callee = named_kids(only).next()?;
    if callee.kind() != "identifier" || named_kids(only).any(|c| c.kind() == "annotated_lambda") {
        return None;
    }
    Some(py_text(callee, src))
}

/// Delegate names that more than one route in this file resolves to.
///
/// **Load-bearing, in the direction of a false negative.**
/// [`crate::evidence::emit_framework_entry_points`] dedups entry points
/// by `(file, function name)` and folds every `AuthGuardFact` for a name
/// together with `*e = *e && g.requires_auth` — an unguarded route
/// contributes no fact at all, so it cannot pull the flag back down.
/// Two routes in one file delegating to the same function would
/// therefore collapse into ONE entry point carrying the guarded route's
/// verdict, and a real finding on the open one would be silently
/// suppressed. Sharing a name is rare and unnameable; the whole point of
/// this module is to be honest about what is reachable, so both routes
/// give the name up and take their synthetic ones back.
///
/// The count spans the whole file rather than one `routing { … }` block,
/// because the dedup it defends against is per file.
fn ambiguous_delegates(root: Node, src: &[u8]) -> BTreeSet<String> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    count_delegates(root, src, &mut seen);
    seen.into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(name, _)| name)
        .collect()
}

fn count_delegates(node: Node, src: &[u8], seen: &mut BTreeMap<String, usize>) {
    if let Some(lambda) = verb_lambda(node, src) {
        if let Some(name) = delegate_handler(lambda, src) {
            *seen.entry(name).or_default() += 1;
        }
        // `walk` stops at a verb call rather than descending into its
        // handler, so a route registered inside another route's body is
        // never emitted — and must not be counted here either.
        return;
    }
    for c in kids(node) {
        count_delegates(c, src, seen);
    }
}

/// `true` when this call was a Ktor DSL statement and its own lambda has
/// already been walked.
fn ktor_call(node: Node, src: &[u8], ctx: &Ctx, facts: &mut Facts) -> bool {
    let Some((name, arg, lambda)) = dsl_call(node, src) else {
        return false;
    };
    let Some(lambda) = lambda else {
        return false;
    };
    let mut inner = ctx.clone();
    match name.as_str() {
        "routing" => {}
        "route" => inner.prefix = common::join_path(&ctx.prefix, &arg.unwrap_or_default()),
        "authenticate" => inner.guards.push(name.clone()),
        verb => {
            let Some(method) = verb_method(verb) else {
                return false;
            };
            let path = common::join_path(&ctx.prefix, &arg.unwrap_or_default());
            // The uniqueness guard is applied here rather than inside
            // [`delegate_handler`], which stays a pure reading of one
            // lambda; whether that reading is SAFE to use is a
            // whole-file question.
            let handler = delegate_handler(lambda, src)
                .filter(|name| !ctx.ambiguous.contains(name))
                .unwrap_or_else(|| common::anon_handler(method, &path));
            facts.push_route(
                &Route {
                    method,
                    path,
                    handler,
                    line: node.start_position().row + 1,
                    framework: "ktor",
                },
                &ctx.guards,
            );
            return true;
        }
    }
    walk(lambda, src, &inner, facts);
    true
}

// ── Spring ───────────────────────────────────────────────────────────────

/// Every annotation on `node`, as `(name, arguments)`.
fn annotations<'a>(node: Node<'a>, src: &[u8]) -> Vec<(String, Option<Node<'a>>)> {
    let mut out = Vec::new();
    for m in named_kids(node).filter(|c| c.kind() == "modifiers") {
        for a in named_kids(m).filter(|c| c.kind() == "annotation") {
            let Some(first) = named_kids(a).next() else {
                continue;
            };
            let (type_node, args) = if first.kind() == "constructor_invocation" {
                let Some(t) = named_kids(first).next() else {
                    continue;
                };
                (t, named_kids(first).find(|c| c.kind() == "value_arguments"))
            } else {
                (first, None)
            };
            let text = py_text(type_node, src);
            out.push((text.rsplit('.').next().unwrap_or(&text).to_string(), args));
        }
    }
    out
}

/// A `@RestController` class carrying `@RequestMapping("/api")`
/// prefixes every mapping its functions declare, and a class-level
/// `@PreAuthorize` guards every one of them — the same semantics the
/// Java section gives a Spring controller.
fn spring_class(node: Node, src: &[u8], ctx: &Ctx, facts: &mut Facts) {
    let mut inner = ctx.clone();
    for (name, args) in annotations(node, src) {
        if mapping_method(&name).is_some() {
            let path = args.and_then(|a| first_string(a, src)).unwrap_or_default();
            inner.prefix = common::join_path(&ctx.prefix, &path);
        }
        inner.guards.push(name);
    }
    for c in kids(node) {
        walk(c, src, &inner, facts);
    }
}

fn spring_function(node: Node, src: &[u8], ctx: &Ctx, facts: &mut Facts) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let handler = py_text(name_node, src);
    let line = node.start_position().row + 1;
    let annos = annotations(node, src);
    let mut guards = ctx.guards.clone();
    guards.extend(annos.iter().map(|(n, _)| n.clone()));

    for (name, args) in &annos {
        let Some(method) = mapping_method(name) else {
            continue;
        };
        let path = args.and_then(|a| first_string(a, src)).unwrap_or_default();
        facts.push_route(
            &Route {
                method,
                path: common::join_path(&ctx.prefix, &path),
                handler: handler.clone(),
                line,
                framework: "spring",
            },
            &guards,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::common::testing::{facts_for, guard_names, marker_names, route_patterns};
    use super::*;

    #[allow(clippy::type_complexity)]
    fn kotlin(
        src: &str,
    ) -> (
        Vec<FrameworkMarkerFact>,
        Vec<RouteTaintFact>,
        Vec<AuthGuardFact>,
    ) {
        facts_for("kotlin", src)
    }

    #[test]
    fn a_ktor_route_reports_its_method_path_and_handler() {
        let (m, r, g) = kotlin(
            "fun Application.module() {\n\
             \x20   routing {\n\
             \x20       get(\"/users/{id}\") { call.respond(1) }\n\
             \x20   }\n}\n",
        );
        assert_eq!(marker_names(&m), vec!["GET /users/{id}".to_string()]);
        assert_eq!(m[0].function_qnode, "get_users_id");
        assert_eq!(m[0].marker_type, "ktor_route");
        assert_eq!(m[0].line, 3);
        assert_eq!(route_patterns(&r), vec!["/users/{id}:id".to_string()]);
        assert!(g.is_empty());
    }

    #[test]
    fn ktor_route_blocks_nest_their_prefixes() {
        let (m, _, _) = kotlin(
            "fun Application.module() {\n\
             \x20   routing {\n\
             \x20       route(\"/api\") {\n\
             \x20           route(\"/v1\") {\n\
             \x20               post(\"/users\") { call.respond(1) }\n\
             \x20           }\n\
             \x20       }\n\
             \x20   }\n}\n",
        );
        assert_eq!(marker_names(&m), vec!["POST /api/v1/users".to_string()]);
        assert_eq!(m[0].function_qnode, "post_api_v1_users");
    }

    #[test]
    fn a_ktor_verb_without_a_path_inherits_the_route_prefix() {
        let (m, _, _) = kotlin(
            "fun Application.module() {\n\
             \x20   routing {\n\
             \x20       route(\"/health\") {\n\
             \x20           get { call.respond(1) }\n\
             \x20       }\n\
             \x20   }\n}\n",
        );
        assert_eq!(marker_names(&m), vec!["GET /health".to_string()]);
    }

    /// The shape the whole delegate rule exists for: the lambda is a
    /// pure hand-off, so the route is named after the function whose
    /// body a later stage will be reading.
    #[test]
    fn a_ktor_route_that_only_delegates_takes_its_handlers_name() {
        let (m, r, g) = kotlin(
            "fun Route.opsRoutes(service: ReportService) {\n\
             \x20   authenticate(\"auth-session\") {\n\
             \x20       post(\"/ops/snapshot/{id}\") {\n\
             \x20           restoreConsoleSnapshot(call, service)\n\
             \x20       }\n\
             \x20   }\n}\n",
        );
        assert_eq!(
            marker_names(&m),
            vec!["POST /ops/snapshot/{id}".to_string()]
        );
        assert_eq!(m[0].function_qnode, "restoreConsoleSnapshot");
        assert_eq!(
            route_patterns(&r),
            vec!["/ops/snapshot/{id}:id".to_string()]
        );
        assert_eq!(
            guard_names(&g),
            vec![(
                "restoreConsoleSnapshot".to_string(),
                "authenticate".to_string()
            )]
        );
    }

    /// An inline body does its own work, so there is nothing to name it
    /// after — and `call.respond` is a navigation expression, not the
    /// bare identifier the rule demands.
    #[test]
    fn an_inline_ktor_body_keeps_the_synthetic_name() {
        let (m, _, _) =
            kotlin("fun Route.r() {\n    get(\"/reports\") { call.respond(listAll()) }\n}\n");
        assert_eq!(m[0].function_qnode, "get_reports");
    }

    /// Two statements means the lambda has code of its own, and naming
    /// it after either call would hide the other.
    #[test]
    fn a_ktor_lambda_with_two_calls_keeps_the_synthetic_name() {
        let (m, _, _) =
            kotlin("fun Route.r() {\n    get(\"/reports\") { audit(call); listOwned(call) }\n}\n");
        assert_eq!(m[0].function_qnode, "get_reports");
    }

    #[test]
    fn an_empty_ktor_lambda_keeps_the_synthetic_name() {
        let (m, _, _) = kotlin("fun Route.r() {\n    get(\"/reports\") { }\n}\n");
        assert_eq!(m[0].function_qnode, "get_reports");
    }

    /// `withContext { … }` names the combinator, not the handler.
    #[test]
    fn a_ktor_lambda_around_another_lambda_keeps_the_synthetic_name() {
        let (m, _, _) = kotlin(
            "fun Route.r() {\n    get(\"/reports\") { withContext(IO) { listOwned(call) } }\n}\n",
        );
        assert_eq!(m[0].function_qnode, "get_reports");
    }

    /// The false-negative guard. `emit_framework_entry_points` dedups by
    /// `(file, function)` and ANDs the guard flags, so letting an open
    /// and a guarded route share one name would fold the open one into
    /// the guarded verdict and suppress a real finding. Both give the
    /// name up, and the guard fact stays on the closed route alone.
    #[test]
    fn two_ktor_routes_sharing_a_delegate_both_keep_their_synthetic_names() {
        let (m, _, g) = kotlin(
            "fun Route.r(service: ReportService) {\n\
             \x20   get(\"/reports/search\") {\n\
             \x20       renderReports(call, service)\n\
             \x20   }\n\
             \x20   authenticate(\"auth-session\") {\n\
             \x20       get(\"/reports\") {\n\
             \x20           renderReports(call, service)\n\
             \x20       }\n\
             \x20   }\n}\n",
        );
        assert_eq!(
            m.iter()
                .map(|f| f.function_qnode.clone())
                .collect::<Vec<_>>(),
            vec!["get_reports_search".to_string(), "get_reports".to_string()]
        );
        assert_eq!(
            guard_names(&g),
            vec![("get_reports".to_string(), "authenticate".to_string())]
        );
    }

    /// A route registered inside another route's handler is never
    /// emitted (the walk stops at the outer verb), so it must not make
    /// its delegate look shared either.
    #[test]
    fn a_delegate_inside_an_unemitted_nested_route_is_not_counted_as_shared() {
        let (m, _, _) = kotlin(
            "fun Route.r() {\n\
             \x20   get(\"/a\") {\n\
             \x20       handleIt(call)\n\
             \x20   }\n\
             \x20   post(\"/b\") {\n\
             \x20       get(\"/c\") { handleIt(call) }\n\
             \x20   }\n}\n",
        );
        assert_eq!(
            m.iter()
                .map(|f| f.function_qnode.clone())
                .collect::<Vec<_>>(),
            vec!["handleIt".to_string(), "post_b".to_string()]
        );
    }

    #[test]
    fn a_ktor_authenticate_block_guards_the_routes_inside_it() {
        let (m, _, g) = kotlin(
            "fun Application.module() {\n\
             \x20   routing {\n\
             \x20       get(\"/open\") { call.respond(1) }\n\
             \x20       authenticate(\"jwt\") {\n\
             \x20           get(\"/closed\") { call.respond(2) }\n\
             \x20       }\n\
             \x20   }\n}\n",
        );
        assert_eq!(m.len(), 2);
        assert_eq!(
            guard_names(&g),
            vec![("get_closed".to_string(), "authenticate".to_string())]
        );
    }

    #[test]
    fn every_ktor_verb_maps_to_its_own_method() {
        for (verb, method) in [
            ("put", "PUT"),
            ("delete", "DELETE"),
            ("patch", "PATCH"),
            ("head", "HEAD"),
            ("options", "OPTIONS"),
        ] {
            let (m, _, _) = kotlin(&format!(
                "fun Application.module() {{\n    routing {{\n\
                 \x20       {verb}(\"/u\") {{ call.respond(1) }}\n    }}\n}}\n"
            ));
            assert_eq!(m[0].marker_name, format!("{method} /u"));
        }
    }

    #[test]
    fn a_dsl_call_that_names_no_verb_is_not_a_route() {
        let (m, _, _) = kotlin(
            "fun Application.module() {\n\
             \x20   routing {\n\
             \x20       install(\"/x\") { nothing() }\n\
             \x20   }\n}\n",
        );
        assert!(m.is_empty());
    }

    #[test]
    fn a_call_without_a_trailing_lambda_is_not_a_ktor_route() {
        let (m, _, _) = kotlin("fun f() {\n    get(\"/users\")\n}\n");
        assert!(m.is_empty());
    }

    #[test]
    fn a_call_on_a_receiver_is_not_a_ktor_route() {
        let (m, _, _) = kotlin("fun f() {\n    client.get(\"/users\") { retry() }\n}\n");
        assert!(m.is_empty());
    }

    #[test]
    fn a_spring_kotlin_mapping_reports_its_method_path_and_handler() {
        let (m, r, g) = kotlin(
            "@RestController\n@RequestMapping(\"/api\")\nclass UserController {\n\
             \x20   @GetMapping(\"/users/{id}\")\n\
             \x20   fun show(@PathVariable id: String): String = id\n}\n",
        );
        assert_eq!(marker_names(&m), vec!["GET /api/users/{id}".to_string()]);
        assert_eq!(m[0].function_qnode, "show");
        assert_eq!(m[0].marker_type, "spring_route");
        assert_eq!(route_patterns(&r), vec!["/api/users/{id}:id".to_string()]);
        assert!(g.is_empty());
    }

    #[test]
    fn a_spring_kotlin_pre_authorize_guards_its_function() {
        let (_, _, g) = kotlin(
            "class UserController {\n\
             \x20   @GetMapping(\"/users\")\n\
             \x20   @PreAuthorize(\"hasRole('ADMIN')\")\n\
             \x20   fun list(): String = \"\"\n}\n",
        );
        assert_eq!(
            guard_names(&g),
            vec![("list".to_string(), "PreAuthorize".to_string())]
        );
    }

    #[test]
    fn a_class_level_pre_authorize_guards_every_mapping() {
        let (m, _, g) = kotlin(
            "@PreAuthorize(\"hasRole('ADMIN')\")\nclass AdminController {\n\
             \x20   @PostMapping(\"/purge\")\n\
             \x20   fun purge(): String = \"\"\n}\n",
        );
        assert_eq!(marker_names(&m), vec!["POST /purge".to_string()]);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].marker_name, "PreAuthorize");
    }

    #[test]
    fn a_bare_request_mapping_binds_every_verb() {
        let (m, _, _) = kotlin("class C {\n    @RequestMapping\n    fun all(): String = \"\"\n}\n");
        assert_eq!(marker_names(&m), vec!["ANY /".to_string()]);
    }

    #[test]
    fn every_spring_mapping_annotation_maps_to_its_own_method() {
        for (anno, method) in [
            ("PutMapping", "PUT"),
            ("DeleteMapping", "DELETE"),
            ("PatchMapping", "PATCH"),
        ] {
            let (m, _, _) = kotlin(&format!(
                "class C {{\n    @{anno}(\"/u\")\n    fun f(): String = \"\"\n}}\n"
            ));
            assert_eq!(m[0].marker_name, format!("{method} /u"));
        }
    }

    #[test]
    fn a_fully_qualified_mapping_annotation_is_read_by_its_leaf_name() {
        let (m, _, _) = kotlin(
            "class C {\n\
             \x20   @org.springframework.web.bind.annotation.GetMapping(\"/u\")\n\
             \x20   fun f(): String = \"\"\n}\n",
        );
        assert_eq!(marker_names(&m), vec!["GET /u".to_string()]);
    }

    #[test]
    fn a_function_with_no_mapping_annotation_declares_nothing() {
        let (m, _, _) = kotlin("class C {\n    fun helper(): String = \"\"\n}\n");
        assert!(m.is_empty());
    }
}
