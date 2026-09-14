//! PHP entry points: Laravel's `Route::` facade, Symfony's `#[Route]`
//! attributes and `@Route` annotations, and the request superglobals a
//! framework-free script reads directly.
//!
//! **Handler naming.** A Laravel registration names its handler in one
//! of three ways, and each keeps the spelling Laravel itself uses so
//! two controllers sharing an action name stay distinct entry points:
//! `[UserController::class, 'show']` and `'UserController@show'` both
//! become `UserController@show`, and a closure becomes
//! [`common::anon_handler`]'s `get_admin_stats`. A Symfony route is
//! attributed to the method it annotates, which is the same file its
//! `#[IsGranted]` guard lives in, so the two join.
//!
//! **Not attempted.** `Route::match(['get','post'], …)` (a verb list
//! rather than a verb), route-model binding, and resolving a controller
//! named only by a `::class` constant in another file — the first is
//! rare, the rest need the cross-file resolution this per-file plane
//! does not have (the same reason the module doc gives for Django's
//! `urlpatterns`).

use std::sync::LazyLock;

use regex::Regex;
use tree_sitter::Node;

use super::common::{self, Facts, Route, ANY_METHOD, REST_ACTIONS};
use crate::scan::{
    collect_fn_ranges, kids, named_kids, py_text, scope_for, AuthGuardFact, FrameworkMarkerFact,
    RouteTaintFact,
};

/// `@Route("/legacy/{id}", …)` in a docblock — the annotation form
/// Symfony used before PHP 8 attributes existed.
static ANNOTATION_ROUTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"@Route\s*\(\s*(?:path\s*=\s*)?["']([^"']*)["']"#).unwrap());
/// The `methods={"GET","POST"}` option of the same annotation.
static ANNOTATION_METHODS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"methods\s*=\s*\{([^}]*)\}").unwrap());

/// PHP's top-level script body has no function name of its own; this
/// names it, so a framework-free `index.php` reading `$_GET` still
/// becomes an entry point.
const FILE_SCOPE: &str = "__main__";

/// The request superglobals that make a plain script an entry point.
/// `$_SERVER` is deliberately absent: every script touches it, mostly
/// for `REQUEST_URI` bookkeeping rather than to read user input.
const SUPERGLOBALS: &[&str] = &["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"];

/// Both spellings of a PHP string literal — single-quoted (`string`)
/// and double-quoted (`encapsed_string`).
fn is_string(node: Node) -> bool {
    matches!(node.kind(), "string" | "encapsed_string")
}

/// Laravel verbs that register exactly one HTTP method, plus `any`.
fn verb_method(name: &str) -> Option<&'static str> {
    Some(match name {
        "get" => "GET",
        "post" => "POST",
        "put" => "PUT",
        "patch" => "PATCH",
        "delete" => "DELETE",
        "options" => "OPTIONS",
        "head" => "HEAD",
        "any" => ANY_METHOD,
        _ => return None,
    })
}

/// Group/controller prefix and middleware in force at one point in the
/// route table.
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
    walk(root, src, &Ctx::default(), &mut facts);
    superglobals(root, src, &mut facts);
}

fn walk(node: Node, src: &[u8], ctx: &Ctx, facts: &mut Facts) {
    match node.kind() {
        "scoped_call_expression" | "member_call_expression" => {
            if let Some((root, segs)) = chain(node, src) {
                if root.rsplit('\\').next() == Some("Route") {
                    laravel_chain(&segs, src, ctx, facts);
                    return;
                }
            }
        }
        "class_declaration" => {
            symfony_class(node, src, ctx, facts);
            return;
        }
        "method_declaration" | "function_definition" => symfony_handler(node, src, ctx, facts),
        _ => {}
    }
    for c in kids(node) {
        walk(c, src, ctx, facts);
    }
}

// ── Laravel ──────────────────────────────────────────────────────────────

/// Flatten `Route::prefix('a')->middleware('b')->group($fn)` into its
/// root name (`Route`) and its `(method, arguments)` segments, base
/// first. `None` for any call expression that is not such a chain.
fn chain<'a>(node: Node<'a>, src: &[u8]) -> Option<(String, Vec<(String, Node<'a>)>)> {
    let name = py_text(node.child_by_field_name("name")?, src);
    let args = node.child_by_field_name("arguments")?;
    if node.kind() == "scoped_call_expression" {
        let scope = py_text(node.child_by_field_name("scope")?, src);
        return Some((scope, vec![(name, args)]));
    }
    let (root, mut segs) = chain(node.child_by_field_name("object")?, src)?;
    segs.push((name, args));
    Some((root, segs))
}

/// The value an `argument` node wraps, skipping the `name:` label a
/// named argument carries.
fn arg_value<'a>(arg: Node<'a>) -> Option<Node<'a>> {
    if arg.kind() != "argument" {
        return Some(arg);
    }
    match arg.child_by_field_name("name") {
        Some(_) => named_kids(arg).nth(1),
        None => named_kids(arg).next(),
    }
}

/// `(label, value)` per argument; the label is `None` for a positional
/// one.
fn arg_pairs<'a>(args: Node<'a>, src: &[u8]) -> Vec<(Option<String>, Node<'a>)> {
    named_kids(args)
        .filter_map(|a| {
            let label = a
                .child_by_field_name("name")
                .filter(|_| a.kind() == "argument")
                .map(|n| py_text(n, src));
            arg_value(a).map(|v| (label, v))
        })
        .collect()
}

/// Every string literal in `node`, which is either a literal itself or
/// an array of them — `'auth'` and `['auth', 'verified']` are both
/// valid Laravel middleware spellings.
fn string_values(node: Node, src: &[u8], out: &mut Vec<String>) {
    if is_string(node) {
        out.push(common::string_text(node, src));
    } else if node.kind() == "array_creation_expression" {
        for el in named_kids(node) {
            for v in named_kids(el) {
                string_values(v, src, out);
            }
        }
    }
}

/// The leading argument, when it is a string literal — the slot every
/// `Route::` verb, `prefix` and `resource` call puts its path in. A
/// *later* string argument is the handler (`'UserController@show'`),
/// never the path, so scanning past the first argument would read a
/// `Route::get($path, 'C@s')` as bound to the path `C@s`.
fn first_string(args: Node, src: &[u8]) -> Option<String> {
    let (_, value) = arg_pairs(args, src).into_iter().next()?;
    is_string(value).then(|| common::string_text(value, src))
}

/// `['middleware' => 'auth', 'prefix' => 'admin']` — a `Route::group`
/// options array, folded into `ctx`.
fn group_options(array: Node, src: &[u8], ctx: &mut Ctx) {
    for el in named_kids(array) {
        let parts: Vec<Node> = named_kids(el).collect();
        let [key, value] = parts[..] else { continue };
        let mut values = Vec::new();
        string_values(value, src, &mut values);
        match common::string_text(key, src).as_str() {
            "middleware" => ctx.guards.extend(values),
            "prefix" => {
                if let Some(p) = values.first() {
                    ctx.prefix = common::join_path(&ctx.prefix, p);
                }
            }
            _ => {}
        }
    }
}

/// The handler a Laravel registration binds, as a qnode.
fn laravel_handler(args: Node, src: &[u8], method: &str, path: &str) -> String {
    for (_, value) in arg_pairs(args, src).into_iter().skip(1) {
        // `[UserController::class, 'show']`
        if value.kind() == "array_creation_expression" {
            let mut parts = Vec::new();
            for el in named_kids(value) {
                for v in named_kids(el) {
                    if v.kind() == "class_constant_access_expression" {
                        parts.extend(named_kids(v).next().map(|n| py_text(n, src)));
                    } else if is_string(v) {
                        parts.push(common::string_text(v, src));
                    }
                }
            }
            if let [class, action] = &parts[..] {
                return format!("{class}@{action}");
            }
        } else if is_string(value) {
            // `'UserController@show'`
            return common::string_text(value, src);
        }
    }
    common::anon_handler(method, path)
}

/// The controller class a `Route::resource` binds — `Ctl::class` or the
/// legacy `'Ctl'` string form.
fn resource_controller(value: Node, src: &[u8]) -> Option<String> {
    if value.kind() == "class_constant_access_expression" {
        return named_kids(value).next().map(|n| py_text(n, src));
    }
    is_string(value).then(|| common::string_text(value, src))
}

fn laravel_chain(segs: &[(String, Node)], src: &[u8], ctx: &Ctx, facts: &mut Facts) {
    let mut ctx = ctx.clone();
    let mut verb: Option<(&'static str, Node)> = None;
    let mut resource: Option<Node> = None;
    let mut bodies: Vec<Node> = Vec::new();

    for (name, args) in segs {
        match name.to_ascii_lowercase().as_str() {
            "prefix" => {
                if let Some(p) = first_string(*args, src) {
                    ctx.prefix = common::join_path(&ctx.prefix, &p);
                }
            }
            "middleware" => {
                for (_, v) in arg_pairs(*args, src) {
                    string_values(v, src, &mut ctx.guards);
                }
            }
            "group" => {
                for (_, v) in arg_pairs(*args, src) {
                    if v.kind() == "array_creation_expression" {
                        group_options(v, src, &mut ctx);
                    } else if matches!(v.kind(), "anonymous_function" | "arrow_function") {
                        bodies.push(v);
                    }
                }
            }
            "resource" | "apiresource" => resource = Some(*args),
            lower => verb = verb_method(lower).map(|m| (m, *args)).or(verb),
        }
    }

    if let Some((method, args)) = verb {
        if let Some(raw) = first_string(args, src) {
            let path = common::join_path(&ctx.prefix, &raw);
            let handler = laravel_handler(args, src, method, &path);
            facts.push_route(
                &Route {
                    method,
                    path,
                    handler,
                    line: args.start_position().row + 1,
                    framework: "laravel",
                },
                &ctx.guards,
            );
        }
    }
    if let Some(args) = resource {
        laravel_resource(args, src, &ctx, facts);
    }
    for body in bodies {
        walk(body, src, &ctx, facts);
    }
}

/// `Route::resource('photos', PhotoController::class)` — the same seven
/// conventional actions Rails generates, with Laravel's own singular
/// path parameter (`/photos/{photo}`).
fn laravel_resource(args: Node, src: &[u8], ctx: &Ctx, facts: &mut Facts) {
    let values: Vec<Node> = arg_pairs(args, src).into_iter().map(|(_, v)| v).collect();
    let (Some(name_node), Some(controller_node)) = (values.first(), values.get(1)) else {
        return;
    };
    let Some(controller) = resource_controller(*controller_node, src) else {
        return;
    };
    let name = common::string_text(*name_node, src);
    // Laravel names the parameter after the singular resource; the
    // trailing-`s` rule is what its own `Str::singular` does for the
    // regular nouns route tables are written with.
    let param = name.strip_suffix('s').unwrap_or(&name);
    let base = common::join_path(&ctx.prefix, &name);
    let line = args.start_position().row + 1;
    for (action, method, suffix) in REST_ACTIONS {
        let path = common::join_path(&base, &suffix.replace("{id}", &format!("{{{param}}}")));
        facts.push_route(
            &Route {
                method,
                path,
                handler: format!("{controller}@{action}"),
                line,
                framework: "laravel",
            },
            &ctx.guards,
        );
    }
}

// ── Symfony ──────────────────────────────────────────────────────────────

/// Every `#[Attribute(...)]` on `node`, as `(name, arguments)`; the
/// arguments node is `None` for a bare marker attribute.
fn attributes<'a>(node: Node<'a>, src: &[u8]) -> Vec<(String, Option<Node<'a>>)> {
    let mut out = Vec::new();
    let Some(list) = node.child_by_field_name("attributes") else {
        return out;
    };
    for group in named_kids(list) {
        for attr in named_kids(group) {
            let Some(name) =
                named_kids(attr).find(|c| matches!(c.kind(), "name" | "qualified_name"))
            else {
                continue;
            };
            let text = py_text(name, src);
            out.push((
                text.rsplit('\\').next().unwrap_or(&text).to_string(),
                attr.child_by_field_name("parameters"),
            ));
        }
    }
    out
}

/// `(path, methods)` from a `#[Route]` attribute's arguments. The path
/// is the first positional argument or the `path:` named one; an
/// absent `methods:` list means every verb.
fn route_attribute(args: Option<Node>, src: &[u8]) -> (String, Vec<String>) {
    let Some(args) = args else {
        return (String::new(), Vec::new());
    };
    let mut path = String::new();
    let mut methods = Vec::new();
    for (label, value) in arg_pairs(args, src) {
        match label.as_deref() {
            Some("methods") => string_values(value, src, &mut methods),
            Some("path") | None if path.is_empty() && is_string(value) => {
                path = common::string_text(value, src);
            }
            _ => {}
        }
    }
    (path, methods)
}

/// A class carrying `#[Route('/api')]` prefixes every route its methods
/// declare, and a class-level `#[IsGranted]` guards every one of them.
fn symfony_class(node: Node, src: &[u8], ctx: &Ctx, facts: &mut Facts) {
    let mut ctx = ctx.clone();
    for (name, args) in attributes(node, src) {
        if name == "Route" {
            let (path, _) = route_attribute(args, src);
            ctx.prefix = common::join_path(&ctx.prefix, &path);
        }
        ctx.guards.push(name);
    }
    for c in kids(node) {
        walk(c, src, &ctx, facts);
    }
}

/// `@Route("/legacy/{id}", methods={"GET","POST"})` in the docblock
/// immediately above a handler.
fn annotation_route(node: Node, src: &[u8]) -> Option<(String, Vec<String>)> {
    let comment = node
        .prev_named_sibling()
        .filter(|c| c.kind() == "comment")?;
    let text = py_text(comment, src);
    let path = ANNOTATION_ROUTE.captures(&text)?[1].to_string();
    let methods = ANNOTATION_METHODS
        .captures(&text)
        .map(|m| {
            m[1].split(',')
                .map(|s| s.trim().trim_matches(['"', '\'']).to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    Some((path, methods))
}

fn symfony_handler(node: Node, src: &[u8], ctx: &Ctx, facts: &mut Facts) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let handler = py_text(name_node, src);
    let line = node.start_position().row + 1;
    let attrs = attributes(node, src);
    let mut guards = ctx.guards.clone();
    guards.extend(attrs.iter().map(|(n, _)| n.clone()));

    let mut declared: Vec<(String, Vec<String>)> = attrs
        .iter()
        .filter(|(n, _)| n == "Route")
        .map(|(_, args)| route_attribute(*args, src))
        .collect();
    if declared.is_empty() {
        declared.extend(annotation_route(node, src));
    }
    for (path, methods) in declared {
        let path = common::join_path(&ctx.prefix, &path);
        let methods = if methods.is_empty() {
            vec![ANY_METHOD.to_string()]
        } else {
            methods
        };
        for method in methods {
            facts.push_route(
                &Route {
                    method: &method,
                    path: path.clone(),
                    handler: handler.clone(),
                    line,
                    framework: "symfony",
                },
                &guards,
            );
        }
    }
}

// ── framework-free scripts ───────────────────────────────────────────────

/// `$_GET`/`$_POST`/… anywhere in the file. A script reading a request
/// superglobal is network-reachable whether or not a router bound it,
/// so it is an entry point in its own right — attributed to the
/// enclosing function, or to [`FILE_SCOPE`] at top level.
fn superglobals(root: Node, src: &[u8], facts: &mut Facts) {
    let mut ranges = Vec::new();
    collect_fn_ranges(
        root,
        src,
        &["function_definition", "method_declaration"],
        &mut ranges,
    );
    let mut seen: Vec<(String, String)> = Vec::new();
    superglobal_visit(root, src, &ranges, &mut seen, facts);
}

fn superglobal_visit(
    node: Node,
    src: &[u8],
    ranges: &[(usize, usize, String)],
    seen: &mut Vec<(String, String)>,
    facts: &mut Facts,
) {
    if node.kind() == "variable_name" {
        let name = py_text(node, src);
        if SUPERGLOBALS.contains(&name.as_str()) {
            let mut qnode = scope_for(node.start_byte(), ranges);
            if qnode.is_empty() {
                qnode = FILE_SCOPE.to_string();
            }
            let key = (qnode.clone(), name.clone());
            if !seen.contains(&key) {
                seen.push(key);
                facts.markers.push(FrameworkMarkerFact {
                    function_qnode: qnode,
                    line: node.start_position().row + 1,
                    marker_type: "php_superglobal".to_string(),
                    marker_name: name,
                    parameter_names: vec!["result".to_string()],
                    framework: "php".to_string(),
                    confidence: "high".to_string(),
                });
            }
        }
        return;
    }
    for c in kids(node) {
        superglobal_visit(c, src, ranges, seen, facts);
    }
}

#[cfg(test)]
mod tests {
    use super::common::testing::{facts_for, guard_names, marker_names, route_patterns};
    use super::*;

    #[allow(clippy::type_complexity)]
    fn php(
        src: &str,
    ) -> (
        Vec<FrameworkMarkerFact>,
        Vec<RouteTaintFact>,
        Vec<AuthGuardFact>,
    ) {
        facts_for("php", src)
    }

    #[test]
    fn laravel_array_controller_route_is_a_get_with_its_path_and_handler() {
        let (m, r, g) = php("<?php\nRoute::get('/users/{id}', [UserController::class, 'show']);\n");
        assert_eq!(marker_names(&m), vec!["GET /users/{id}".to_string()]);
        assert_eq!(m[0].function_qnode, "UserController@show");
        assert_eq!(m[0].marker_type, "laravel_route");
        assert_eq!(m[0].line, 2);
        assert_eq!(route_patterns(&r), vec!["/users/{id}:id".to_string()]);
        assert!(g.is_empty());
    }

    #[test]
    fn laravel_string_controller_route_keeps_the_at_spelling() {
        let (m, _, _) = php("<?php\nRoute::post('/users', 'UserController@store');\n");
        assert_eq!(m[0].function_qnode, "UserController@store");
        assert_eq!(m[0].marker_name, "POST /users");
    }

    #[test]
    fn laravel_closure_route_gets_a_synthetic_handler_name() {
        let (m, _, _) = php("<?php\nRoute::get('/stats', function () { return 1; });\n");
        assert_eq!(m[0].function_qnode, "get_stats");
    }

    #[test]
    fn laravel_arrow_closure_route_gets_a_synthetic_handler_name() {
        let (m, _, _) = php("<?php\nRoute::get(\"/ping\", fn () => 1);\n");
        assert_eq!(m[0].function_qnode, "get_ping");
    }

    #[test]
    fn laravel_verbs_each_map_to_their_own_method() {
        for (verb, method) in [
            ("put", "PUT"),
            ("patch", "PATCH"),
            ("delete", "DELETE"),
            ("options", "OPTIONS"),
            ("head", "HEAD"),
            ("any", "ANY"),
        ] {
            let (m, _, _) = php(&format!("<?php\nRoute::{verb}('/hook', 'H@go');\n"));
            assert_eq!(m[0].marker_name, format!("{method} /hook"));
        }
    }

    #[test]
    fn laravel_middleware_on_the_chain_is_a_guard() {
        let (_, _, g) = php("<?php\nRoute::post('/u', 'C@s')->middleware('auth');\n");
        assert_eq!(
            guard_names(&g),
            vec![("C@s".to_string(), "auth".to_string())]
        );
    }

    #[test]
    fn laravel_middleware_array_is_a_guard() {
        let (_, _, g) = php("<?php\nRoute::post('/u', 'C@s')->middleware(['throttle', 'auth']);\n");
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].marker_name, "auth");
    }

    #[test]
    fn laravel_group_options_supply_both_prefix_and_guard() {
        let (m, _, g) = php(
            "<?php\nRoute::group(['middleware' => 'auth', 'prefix' => 'admin'], function () {\n\
             \x20   Route::get('/stats', [S::class, 'index']);\n});\n",
        );
        assert_eq!(m[0].marker_name, "GET /admin/stats");
        assert_eq!(g[0].function_qnode, "S@index");
    }

    #[test]
    fn laravel_group_options_ignore_unrelated_keys_and_bare_elements() {
        let (m, _, g) = php(
            "<?php\nRoute::group(['as' => 'admin.', 'auth'], function () {\n\
             \x20   Route::get('/stats', 'S@index');\n});\n",
        );
        assert_eq!(m[0].marker_name, "GET /stats");
        assert!(g.is_empty());
    }

    #[test]
    fn laravel_prefix_calls_nest() {
        let (m, _, _) = php("<?php\nRoute::prefix('api')->group(function () {\n\
             \x20   Route::prefix('v1')->group(function () {\n\
             \x20       Route::get('/ping', 'P@go');\n\
             \x20   });\n});\n");
        assert_eq!(m[0].marker_name, "GET /api/v1/ping");
    }

    #[test]
    fn laravel_prefix_without_a_string_argument_is_ignored() {
        let (m, _, _) = php("<?php\nRoute::prefix($p)->group(function () {\n\
             \x20   Route::get('/ping', 'P@go');\n});\n");
        assert_eq!(m[0].marker_name, "GET /ping");
    }

    #[test]
    fn laravel_group_without_options_still_recurses() {
        let (m, _, _) =
            php("<?php\nRoute::group(function () {\n    Route::get('/a', 'A@b');\n});\n");
        assert_eq!(m[0].marker_name, "GET /a");
    }

    #[test]
    fn laravel_resource_expands_to_the_seven_conventional_actions() {
        let (m, _, _) = php("<?php\nRoute::resource('photos', PhotoController::class);\n");
        assert_eq!(m.len(), 7);
        let names = marker_names(&m);
        assert!(names.contains(&"GET /photos".to_string()));
        assert!(names.contains(&"POST /photos".to_string()));
        assert!(names.contains(&"GET /photos/{photo}".to_string()));
        assert!(names.contains(&"PATCH /photos/{photo}".to_string()));
        assert!(names.contains(&"DELETE /photos/{photo}".to_string()));
        assert!(names.contains(&"GET /photos/{photo}/edit".to_string()));
        assert!(names.contains(&"GET /photos/new".to_string()));
        assert_eq!(m[0].function_qnode, "PhotoController@index");
    }

    #[test]
    fn laravel_api_resource_accepts_the_legacy_string_controller() {
        let (m, _, _) = php("<?php\nRoute::apiResource('tag', 'TagController');\n");
        assert_eq!(m.len(), 7);
        assert_eq!(m[0].function_qnode, "TagController@index");
        // No trailing `s` to strip — the parameter keeps the raw name.
        assert!(marker_names(&m).contains(&"GET /tag/{tag}".to_string()));
    }

    #[test]
    fn laravel_resource_without_a_controller_argument_is_ignored() {
        let (m, _, _) = php("<?php\nRoute::resource('photos');\n");
        assert!(m.is_empty());
    }

    #[test]
    fn laravel_resource_with_an_unreadable_controller_is_ignored() {
        let (m, _, _) = php("<?php\nRoute::resource('photos', $ctl);\n");
        assert!(m.is_empty());
    }

    #[test]
    fn laravel_route_without_a_path_argument_is_ignored() {
        let (m, _, _) = php("<?php\nRoute::get($path, 'C@s');\n");
        assert!(m.is_empty());
    }

    #[test]
    fn laravel_route_with_an_unreadable_handler_falls_back_to_the_path_name() {
        let (m, _, _) = php("<?php\nRoute::get('/a', $handler);\n");
        assert_eq!(m[0].function_qnode, "get_a");
    }

    #[test]
    fn a_non_route_facade_chain_is_left_alone() {
        let (m, _, _) = php("<?php\nCache::get('/users/{id}');\n");
        assert!(m.is_empty());
    }

    #[test]
    fn an_instance_method_call_is_not_a_route_chain() {
        let (m, _, _) = php("<?php\n$svc->get('/users');\n");
        assert!(m.is_empty());
    }

    #[test]
    fn a_namespaced_route_facade_is_still_recognised() {
        let (m, _, _) = php("<?php\n\\Illuminate\\Support\\Facades\\Route::get('/a', 'A@b');\n");
        assert_eq!(m[0].marker_name, "GET /a");
    }

    #[test]
    fn symfony_attribute_route_reports_its_method_path_and_guard() {
        let (m, r, g) = php("<?php\nclass C {\n\
             \x20   #[Route('/api/u/{id}', methods: ['GET'])]\n\
             \x20   #[IsGranted('ROLE_USER')]\n\
             \x20   public function show(int $id) { return 1; }\n}\n");
        assert_eq!(marker_names(&m), vec!["GET /api/u/{id}".to_string()]);
        assert_eq!(m[0].function_qnode, "show");
        assert_eq!(m[0].framework, "symfony");
        assert_eq!(route_patterns(&r), vec!["/api/u/{id}:id".to_string()]);
        assert_eq!(
            guard_names(&g),
            vec![("show".to_string(), "IsGranted".to_string())]
        );
    }

    #[test]
    fn symfony_class_route_prefixes_its_methods() {
        let (m, _, _) = php("<?php\n#[Route('/api')]\nclass C {\n\
             \x20   #[Route(path: '/u', methods: ['GET', 'POST'])]\n\
             \x20   public function u() { return 1; }\n}\n");
        assert_eq!(
            marker_names(&m),
            vec!["GET /api/u".to_string(), "POST /api/u".to_string()]
        );
    }

    #[test]
    fn symfony_class_level_guard_covers_every_method() {
        let (_, _, g) = php("<?php\n#[IsGranted('ROLE_ADMIN')]\nclass C {\n\
             \x20   #[Route('/u')]\n\
             \x20   public function u() { return 1; }\n}\n");
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].marker_name, "IsGranted");
    }

    #[test]
    fn symfony_route_without_methods_binds_every_verb() {
        let (m, _, _) = php("<?php\n#[Route('/u')]\nfunction u() { return 1; }\n");
        assert_eq!(marker_names(&m), vec!["ANY /u".to_string()]);
    }

    #[test]
    fn symfony_bare_route_attribute_without_arguments_is_the_root_path() {
        let (m, _, _) = php("<?php\n#[Route]\nfunction u() { return 1; }\n");
        assert_eq!(marker_names(&m), vec!["ANY /".to_string()]);
    }

    #[test]
    fn symfony_route_with_an_unrecognised_named_argument_still_reads_the_path() {
        let (m, _, _) =
            php("<?php\n#[Route('/u', name: 'app_u', methods: ['GET'])]\nfunction u() { }\n");
        assert_eq!(marker_names(&m), vec!["GET /u".to_string()]);
    }

    #[test]
    fn symfony_security_attribute_is_a_guard_too() {
        let (_, _, g) = php(
            "<?php\n#[Route('/u')]\n#[Security(\"is_granted('ROLE_USER')\")]\n\
             function u() { return 1; }\n",
        );
        assert_eq!(
            guard_names(&g),
            vec![("u".to_string(), "Security".to_string())]
        );
    }

    #[test]
    fn symfony_annotation_route_is_read_out_of_the_docblock() {
        let (m, _, _) = php(
            "<?php\n/**\n * @Route(\"/legacy/{id}\", methods={\"GET\",\"POST\"})\n */\n\
             function legacy($id) { return $id; }\n",
        );
        assert_eq!(
            marker_names(&m),
            vec![
                "GET /legacy/{id}".to_string(),
                "POST /legacy/{id}".to_string()
            ]
        );
    }

    #[test]
    fn symfony_annotation_without_methods_binds_every_verb() {
        let (m, _, _) =
            php("<?php\n/**\n * @Route(\"/legacy\")\n */\nfunction legacy() { return 1; }\n");
        assert_eq!(marker_names(&m), vec!["ANY /legacy".to_string()]);
    }

    #[test]
    fn a_docblock_without_a_route_annotation_declares_nothing() {
        let (m, _, _) = php("<?php\n/** just a comment */\nfunction plain() { return 1; }\n");
        assert!(m.is_empty());
    }

    #[test]
    fn a_function_with_no_docblock_declares_nothing() {
        let (m, _, _) = php("<?php\nfunction plain() { return 1; }\n");
        assert!(m.is_empty());
    }

    #[test]
    fn a_superglobal_read_makes_the_enclosing_function_an_entry_point() {
        let (m, _, _) = php("<?php\nfunction handle() { echo $_GET['q']; }\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].marker_type, "php_superglobal");
        assert_eq!(m[0].function_qnode, "handle");
        assert_eq!(m[0].marker_name, "$_GET");
        assert_eq!(m[0].line, 2);
    }

    #[test]
    fn a_top_level_superglobal_read_is_a_file_scope_entry_point() {
        let (m, _, _) = php("<?php\necho $_POST['x'];\necho $_POST['y'];\necho $_COOKIE['c'];\n");
        // Deduped per (scope, superglobal): two `$_POST` reads, one fact.
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].function_qnode, FILE_SCOPE);
        assert_eq!(m[0].marker_name, "$_POST");
        assert_eq!(m[1].marker_name, "$_COOKIE");
    }

    #[test]
    fn an_ordinary_variable_is_not_a_superglobal() {
        let (m, _, _) = php("<?php\n$get = 1;\n");
        assert!(m.is_empty());
    }
}
