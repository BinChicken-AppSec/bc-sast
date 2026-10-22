//! Ruby entry points: the Rails routes DSL, Rails controller
//! `before_action` guards, and Sinatra's route blocks.
//!
//! **Why a Rails handler is named `users#show`.** Rails splits a route
//! from its guard across two files by design — the path lives in
//! `config/routes.rb`, the `before_action :authenticate_user!` in
//! `app/controllers/users_controller.rb` — so a per-file guard join
//! would report every Rails route as anonymously reachable. Both sides
//! therefore key on Rails' own canonical handler id, `controller#action`,
//! and [`crate::evidence::emit_framework_entry_points`] joins guards
//! carrying that spelling across files. It is also what keeps
//! `UsersController#show` and `PhotosController#show` distinct entry
//! points, which a bare `show` would not.
//!
//! **Both route spellings are read.** `get '/p', to: 'c#a'` and
//! `get '/p' => 'c#a'` bind the same route; the second — the path as a
//! hash *key* — is what the Rails guides use and what real route tables
//! are overwhelmingly written in, so reading only the first missed
//! entire applications. `match '/p' => 'c#a', via: [:get, :post]`
//! expands to one route per verb.
//!
//! **Not attempted.** Singular `resource`, and the `/:user_id` segment
//! a *nested* `resources` block adds — a nested block is walked with
//! its parent's collection path, so its own routes keep the outer
//! prefix but not the parent's id parameter.

use tree_sitter::Node;

use super::common::{self, Facts, Route, ANY_METHOD, REST_ACTIONS};
use crate::scan::{kids, named_kids, py_text, AuthGuardFact, FrameworkMarkerFact, RouteTaintFact};

/// The `before_action` spellings Rails accepts, old and new.
const BEFORE_FILTERS: &[&str] = &[
    "before_action",
    "prepend_before_action",
    "append_before_action",
    "before_filter",
];
/// …and the ones that take a filter back off.
const SKIP_FILTERS: &[&str] = &["skip_before_action", "skip_before_filter"];

fn http_method(name: &str) -> Option<&'static str> {
    Some(match name {
        "get" => "GET",
        "post" => "POST",
        "put" => "PUT",
        "patch" => "PATCH",
        "delete" => "DELETE",
        "options" => "OPTIONS",
        "head" => "HEAD",
        _ => return None,
    })
}

/// Path prefix and controller module in force at one point in the route
/// table. `namespace :admin` sets both; `scope '/v1'` only the path.
#[derive(Clone, Default)]
struct Ctx {
    prefix: String,
    module: String,
}

impl Ctx {
    /// `users#show` under `namespace :admin` is `admin/users#show`.
    fn qualify(&self, target: &str) -> String {
        if self.module.is_empty() {
            target.to_string()
        } else {
            format!("{}/{}", self.module, target)
        }
    }
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
    // Sinatra's `before do … end` filter runs for every route in the
    // file regardless of where it is written, so it is collected before
    // the routes it guards are walked.
    let mut filters = Vec::new();
    sinatra_filter(root, src, &mut filters);
    walk(root, src, &Ctx::default(), &filters, &mut facts);
    controllers(root, src, &mut facts);
}

// ── route tables ─────────────────────────────────────────────────────────

fn walk(node: Node, src: &[u8], ctx: &Ctx, filters: &[String], facts: &mut Facts) {
    if node.kind() == "call" && route_call(node, src, ctx, filters, facts) {
        return;
    }
    for c in kids(node) {
        walk(c, src, ctx, filters, facts);
    }
}

/// `true` when this call was a route-table statement and its own block
/// (if any) has already been walked.
fn route_call(node: Node, src: &[u8], ctx: &Ctx, filters: &[String], facts: &mut Facts) -> bool {
    // Every routes-DSL call is a bare method call; `redis.get("k")` is
    // not a route just because it spells a verb.
    if node.child_by_field_name("receiver").is_some() {
        return false;
    }
    let Some(method_node) = node.child_by_field_name("method") else {
        return false;
    };
    let name = py_text(method_node, src);
    let args = node.child_by_field_name("arguments");
    let block = node.child_by_field_name("block");
    let line = node.start_position().row + 1;

    match name.as_str() {
        "namespace" | "scope" => {
            let Some(args) = args else { return false };
            let Some(segment) = first_symbol(args, src).or_else(|| first_string(args, src)) else {
                return false;
            };
            let mut inner = ctx.clone();
            inner.prefix = common::join_path(&ctx.prefix, &segment);
            if name == "namespace" {
                inner.module = inner.qualify(&segment);
            }
            if let Some(b) = block {
                walk(b, src, &inner, filters, facts);
            }
            true
        }
        "resources" => {
            let Some(args) = args else { return false };
            let Some(resource) = first_symbol(args, src) else {
                return false;
            };
            let base = common::join_path(&ctx.prefix, &resource);
            resource_routes(&base, &ctx.qualify(&resource), line, facts);
            if let Some(b) = block {
                let inner = Ctx {
                    prefix: base.clone(),
                    module: ctx.module.clone(),
                };
                walk(b, src, &inner, filters, facts);
            }
            true
        }
        "root" => {
            let Some(args) = args else { return false };
            let Some(target) = pair_string(args, src, "to").or_else(|| first_string(args, src))
            else {
                return false;
            };
            facts.push_route(
                &Route {
                    method: "GET",
                    path: common::join_path(&ctx.prefix, "/"),
                    handler: ctx.qualify(&target),
                    line,
                    framework: "rails",
                },
                &[],
            );
            true
        }
        // `match '/p' => 'c#a', via: [:get, :post]` — one route per
        // verb the `via:` list names.
        "match" => {
            let Some(args) = args else { return false };
            let Some((path, target)) = rails_binding(args, src) else {
                return false;
            };
            for method in via_methods(args, src) {
                rails_route(&method, &path, &target, line, ctx, facts);
            }
            true
        }
        _ => {
            let Some(method) = http_method(&name) else {
                return false;
            };
            verb_route(method, node, src, ctx, filters, facts)
        }
    }
}

/// The `(path, controller#action)` a Rails route binds, in either
/// spelling the routes DSL accepts: `get '/p', to: 'c#a'` (positional
/// path, `to:` target) or `get '/p' => 'c#a'` (a hash pair whose *key*
/// is the path — the form the Rails guides themselves use, and by far
/// the more common one in real route tables).
fn rails_binding(args: Node, src: &[u8]) -> Option<(String, String)> {
    if let Some(target) = pair_string(args, src, "to") {
        return Some((first_string(args, src).unwrap_or_default(), target));
    }
    let pair = named_kids(args).filter(|n| n.kind() == "pair").find(|p| {
        p.child_by_field_name("key")
            .is_some_and(|k| k.kind() == "string")
    })?;
    let key = pair.child_by_field_name("key")?;
    let value = pair
        .child_by_field_name("value")
        .filter(|v| v.kind() == "string")?;
    Some((
        common::string_text(key, src),
        common::string_text(value, src),
    ))
}

/// The verbs a `match ... via:` option names, or [`ANY_METHOD`] when it
/// names none this walk recognizes.
fn via_methods(args: Node, src: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(value) = pair_value(args, src, "via") {
        symbol_list(value, src, &mut names);
    }
    let mut out: Vec<String> = names
        .iter()
        .filter_map(|n| http_method(n))
        .map(str::to_string)
        .collect();
    if out.is_empty() {
        out.push(ANY_METHOD.to_string());
    }
    out
}

fn rails_route(method: &str, path: &str, target: &str, line: usize, ctx: &Ctx, facts: &mut Facts) {
    facts.push_route(
        &Route {
            method,
            path: common::join_path(&ctx.prefix, path),
            handler: ctx.qualify(target),
            line,
            framework: "rails",
        },
        &[],
    );
}

fn verb_route(
    method: &str,
    node: Node,
    src: &[u8],
    ctx: &Ctx,
    filters: &[String],
    facts: &mut Facts,
) -> bool {
    let Some(args) = node.child_by_field_name("arguments") else {
        return false;
    };
    let line = node.start_position().row + 1;
    if let Some((path, target)) = rails_binding(args, src) {
        rails_route(method, &path, &target, line, ctx, facts);
        return true;
    }
    let path = first_string(args, src);
    // `get '/hi' do … end` — Sinatra.
    let (Some(path), Some(_)) = (path, node.child_by_field_name("block")) else {
        return false;
    };
    let path = common::join_path(&ctx.prefix, &path);
    facts.push_route(
        &Route {
            method,
            path: path.clone(),
            handler: common::anon_handler(method, &path),
            line,
            framework: "sinatra",
        },
        filters,
    );
    true
}

/// The seven conventional actions `resources :users` generates, against
/// `base` (`/users`) and its controller (`users`).
fn resource_routes(base: &str, controller: &str, line: usize, facts: &mut Facts) {
    for (action, method, suffix) in REST_ACTIONS {
        facts.push_route(
            &Route {
                method,
                path: common::join_path(base, &suffix.replace("{id}", ":id")),
                handler: format!("{controller}#{action}"),
                line,
                framework: "rails",
            },
            &[],
        );
    }
}

// ── Sinatra filters ──────────────────────────────────────────────────────

/// Method names called inside a top-level `before do … end`, which
/// Sinatra runs ahead of every route in the file.
fn sinatra_filter(node: Node, src: &[u8], out: &mut Vec<String>) {
    if node.kind() == "call"
        && node.child_by_field_name("receiver").is_none()
        && node
            .child_by_field_name("method")
            .is_some_and(|m| py_text(m, src) == "before")
    {
        if let Some(b) = node.child_by_field_name("block") {
            called_names(b, src, out);
        }
        return;
    }
    for c in kids(node) {
        sinatra_filter(c, src, out);
    }
}

/// Every bare method name invoked under `node` — a Sinatra filter body
/// is a sequence of helper calls, and `authenticate!` is one of them.
fn called_names(node: Node, src: &[u8], out: &mut Vec<String>) {
    if matches!(node.kind(), "identifier" | "call") {
        let name = match node.child_by_field_name("method") {
            Some(m) => py_text(m, src),
            None => py_text(node, src),
        };
        out.push(name);
    }
    for c in kids(node) {
        called_names(c, src, out);
    }
}

// ── controllers ──────────────────────────────────────────────────────────

/// One `before_action`/`skip_before_action` declaration.
struct Filter {
    name: String,
    only: Vec<String>,
    except: Vec<String>,
}

impl Filter {
    fn applies(&self, action: &str) -> bool {
        (self.only.is_empty() || self.only.iter().any(|a| a == action))
            && !self.except.iter().any(|a| a == action)
    }
}

fn controllers(node: Node, src: &[u8], facts: &mut Facts) {
    if node.kind() == "class" {
        controller_class(node, src, facts);
        return;
    }
    for c in kids(node) {
        controllers(c, src, facts);
    }
}

/// `UsersController` -> `users`, `Admin::UsersController` ->
/// `admin/users` — the controller half of Rails' `controller#action`
/// handler id.
fn controller_resource(class_name: &str) -> Option<String> {
    let base = class_name.strip_suffix("Controller")?;
    let mut out = String::new();
    for c in base.replace("::", "/").chars() {
        if c.is_ascii_uppercase() {
            if !out.is_empty() && !out.ends_with('/') {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    Some(out).filter(|s| !s.is_empty())
}

fn controller_class(node: Node, src: &[u8], facts: &mut Facts) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(resource) = controller_resource(&py_text(name_node, src)) else {
        return;
    };
    let Some(body) = node.child_by_field_name("body") else {
        return;
    };

    let mut filters: Vec<Filter> = Vec::new();
    let mut skips: Vec<Filter> = Vec::new();
    let mut actions: Vec<(String, usize)> = Vec::new();
    for stmt in named_kids(body) {
        match stmt.kind() {
            "call" => {
                let Some(method) = stmt.child_by_field_name("method") else {
                    continue;
                };
                let name = py_text(method, src);
                let target = if BEFORE_FILTERS.contains(&name.as_str()) {
                    &mut filters
                } else if SKIP_FILTERS.contains(&name.as_str()) {
                    &mut skips
                } else {
                    continue;
                };
                if let Some(args) = stmt.child_by_field_name("arguments") {
                    target.extend(parse_filter(args, src));
                }
            }
            "method" => {
                if let Some(name) = stmt.child_by_field_name("name") {
                    actions.push((py_text(name, src), stmt.start_position().row + 1));
                }
            }
            _ => {}
        }
    }

    for (action, line) in actions {
        let names: Vec<String> = filters
            .iter()
            .filter(|f| f.applies(&action))
            .filter(|f| !skips.iter().any(|s| s.name == f.name && s.applies(&action)))
            .map(|f| f.name.clone())
            .collect();
        facts.push_guard(&format!("{resource}#{action}"), line, "rails", &names);
    }
}

/// `:authenticate_user!, only: [:show, :edit]` — one [`Filter`] per
/// filter name the declaration lists.
fn parse_filter(args: Node, src: &[u8]) -> Vec<Filter> {
    let mut names = Vec::new();
    for arg in named_kids(args) {
        if arg.kind() != "pair" {
            symbol_list(arg, src, &mut names);
        }
    }
    let mut only = Vec::new();
    let mut except = Vec::new();
    for (key, target) in [("only", &mut only), ("except", &mut except)] {
        if let Some(value) = pair_value(args, src, key) {
            symbol_list(value, src, target);
        }
    }
    names
        .into_iter()
        .map(|name| Filter {
            name,
            only: only.clone(),
            except: except.clone(),
        })
        .collect()
}

// ── argument helpers ─────────────────────────────────────────────────────

/// Every symbol or string named by `node`, which is one of them or an
/// array of them.
fn symbol_list(node: Node, src: &[u8], out: &mut Vec<String>) {
    match node.kind() {
        "simple_symbol" => out.push(py_text(node, src).trim_start_matches(':').to_string()),
        "string" => out.push(common::string_text(node, src)),
        "array" => {
            for c in named_kids(node) {
                symbol_list(c, src, out);
            }
        }
        _ => {}
    }
}

fn first_symbol(args: Node, src: &[u8]) -> Option<String> {
    named_kids(args)
        .find(|a| a.kind() == "simple_symbol")
        .map(|a| py_text(a, src).trim_start_matches(':').to_string())
}

fn first_string(args: Node, src: &[u8]) -> Option<String> {
    named_kids(args)
        .find(|a| a.kind() == "string")
        .map(|a| common::string_text(a, src))
}

/// The value of the `key:` keyword argument, whatever node kind it is.
fn pair_value<'a>(args: Node<'a>, src: &[u8], key: &str) -> Option<Node<'a>> {
    named_kids(args)
        .filter(|n| n.kind() == "pair")
        .find(|p| {
            p.child_by_field_name("key")
                .is_some_and(|k| py_text(k, src).trim_matches(':') == key)
        })
        .and_then(|p| p.child_by_field_name("value"))
}

fn pair_string(args: Node, src: &[u8], key: &str) -> Option<String> {
    pair_value(args, src, key)
        .filter(|v| v.kind() == "string")
        .map(|v| common::string_text(v, src))
}

#[cfg(test)]
mod tests {
    use super::common::testing::{facts_for, guard_names, marker_names, route_patterns};
    use super::*;

    #[allow(clippy::type_complexity)]
    fn ruby(
        src: &str,
    ) -> (
        Vec<FrameworkMarkerFact>,
        Vec<RouteTaintFact>,
        Vec<AuthGuardFact>,
    ) {
        facts_for("ruby", src)
    }

    const DRAW: &str = "Rails.application.routes.draw do\n";

    #[test]
    fn a_rails_get_route_reports_its_method_path_and_handler() {
        let (m, r, g) = ruby(&format!(
            "{DRAW}  get '/users/:id', to: 'users#show'\nend\n"
        ));
        assert_eq!(marker_names(&m), vec!["GET /users/:id".to_string()]);
        assert_eq!(m[0].function_qnode, "users#show");
        assert_eq!(m[0].marker_type, "rails_route");
        assert_eq!(m[0].line, 2);
        assert_eq!(route_patterns(&r), vec!["/users/:id:id".to_string()]);
        assert!(g.is_empty());
    }

    #[test]
    fn every_rails_verb_maps_to_its_own_method() {
        for (verb, method) in [
            ("post", "POST"),
            ("put", "PUT"),
            ("patch", "PATCH"),
            ("delete", "DELETE"),
            ("options", "OPTIONS"),
            ("head", "HEAD"),
        ] {
            let (m, _, _) = ruby(&format!("{DRAW}  {verb} '/u', to: 'u#a'\nend\n"));
            assert_eq!(m[0].marker_name, format!("{method} /u"));
        }
    }

    #[test]
    fn root_binds_the_root_path() {
        let (m, _, _) = ruby(&format!("{DRAW}  root to: 'home#index'\nend\n"));
        assert_eq!(marker_names(&m), vec!["GET /".to_string()]);
        assert_eq!(m[0].function_qnode, "home#index");
    }

    #[test]
    fn root_accepts_the_positional_target_spelling() {
        let (m, _, _) = ruby(&format!("{DRAW}  root 'home#index'\nend\n"));
        assert_eq!(m[0].function_qnode, "home#index");
    }

    #[test]
    fn root_without_a_target_declares_nothing() {
        let (m, _, _) = ruby(&format!("{DRAW}  root\nend\n"));
        assert!(m.is_empty());
    }

    #[test]
    fn resources_expands_to_the_seven_conventional_actions() {
        let (m, _, _) = ruby(&format!("{DRAW}  resources :users\nend\n"));
        assert_eq!(m.len(), 7);
        let names = marker_names(&m);
        assert!(names.contains(&"GET /users".to_string()));
        assert!(names.contains(&"POST /users".to_string()));
        assert!(names.contains(&"GET /users/:id".to_string()));
        assert!(names.contains(&"PATCH /users/:id".to_string()));
        assert!(names.contains(&"DELETE /users/:id".to_string()));
        assert!(names.contains(&"GET /users/:id/edit".to_string()));
        assert!(names.contains(&"GET /users/new".to_string()));
        let handlers: Vec<&str> = m.iter().map(|f| f.function_qnode.as_str()).collect();
        assert!(handlers.contains(&"users#index"));
        assert!(handlers.contains(&"users#destroy"));
    }

    #[test]
    fn resources_without_a_symbol_declares_nothing() {
        let (m, _, _) = ruby(&format!("{DRAW}  resources\nend\n"));
        assert!(m.is_empty());
    }

    #[test]
    fn resources_named_by_a_variable_declares_nothing() {
        let (m, _, _) = ruby(&format!("{DRAW}  resources model\nend\n"));
        assert!(m.is_empty());
    }

    #[test]
    fn namespace_named_by_a_variable_keeps_the_outer_prefix() {
        let (m, _, _) = ruby(&format!(
            "{DRAW}  namespace model do\n    get '/ping', to: 'ping#show'\n  end\nend\n"
        ));
        // Unreadable segment: the block is still walked, as any
        // unrecognized call's children are.
        assert_eq!(marker_names(&m), vec!["GET /ping".to_string()]);
    }

    #[test]
    fn root_with_a_non_string_target_declares_nothing() {
        let (m, _, _) = ruby(&format!("{DRAW}  root to: :home\nend\n"));
        assert!(m.is_empty());
    }

    #[test]
    fn a_verb_call_without_arguments_is_not_a_route() {
        let (m, _, _) = ruby("get do\n  \"hi\"\nend\n");
        assert!(m.is_empty());
    }

    #[test]
    fn a_nested_resources_block_keeps_the_collection_prefix() {
        let (m, _, _) = ruby(&format!(
            "{DRAW}  resources :users do\n    get '/audit', to: 'audits#index'\n  end\nend\n"
        ));
        assert!(marker_names(&m).contains(&"GET /users/audit".to_string()));
    }

    #[test]
    fn namespace_prefixes_both_the_path_and_the_controller() {
        let (m, _, _) = ruby(&format!(
            "{DRAW}  namespace :admin do\n    get '/stats', to: 'stats#index'\n  end\nend\n"
        ));
        assert_eq!(marker_names(&m), vec!["GET /admin/stats".to_string()]);
        assert_eq!(m[0].function_qnode, "admin/stats#index");
    }

    #[test]
    fn scope_prefixes_only_the_path() {
        let (m, _, _) = ruby(&format!(
            "{DRAW}  scope '/v1' do\n    get '/ping', to: 'ping#show'\n  end\nend\n"
        ));
        assert_eq!(marker_names(&m), vec!["GET /v1/ping".to_string()]);
        assert_eq!(m[0].function_qnode, "ping#show");
    }

    #[test]
    fn namespaces_nest() {
        let (m, _, _) = ruby(&format!(
            "{DRAW}  namespace :api do\n    namespace :v2 do\n\
             \x20     get '/ping', to: 'ping#show'\n    end\n  end\nend\n"
        ));
        assert_eq!(marker_names(&m), vec!["GET /api/v2/ping".to_string()]);
        assert_eq!(m[0].function_qnode, "api/v2/ping#show");
    }

    #[test]
    fn namespace_without_a_segment_declares_nothing() {
        let (m, _, _) = ruby(&format!(
            "{DRAW}  namespace do\n    get '/ping', to: 'ping#show'\n  end\nend\n"
        ));
        // The block is still walked as an unrecognized call's children.
        assert_eq!(marker_names(&m), vec!["GET /ping".to_string()]);
    }

    #[test]
    fn a_verb_call_with_a_receiver_is_not_a_route() {
        let (m, _, _) = ruby("cache.get('/users')\n");
        assert!(m.is_empty());
    }

    #[test]
    fn a_verb_call_with_neither_target_nor_block_is_not_a_route() {
        let (m, _, _) = ruby(&format!("{DRAW}  get '/users'\nend\n"));
        assert!(m.is_empty());
    }

    #[test]
    fn the_hash_rocket_spelling_binds_the_same_route() {
        let (m, r, _) = ruby(&format!(
            "{DRAW}  get '/reports/:id/download' => 'reports#download', as: :report_download\nend\n"
        ));
        assert_eq!(
            marker_names(&m),
            vec!["GET /reports/:id/download".to_string()]
        );
        assert_eq!(m[0].function_qnode, "reports#download");
        assert_eq!(
            route_patterns(&r),
            vec!["/reports/:id/download:id".to_string()]
        );
    }

    #[test]
    fn the_hash_rocket_spelling_picks_up_the_enclosing_prefix() {
        let (m, _, _) = ruby(&format!(
            "{DRAW}  namespace :admin do\n    post '/reindex' => 'ops#reindex'\n  end\nend\n"
        ));
        assert_eq!(marker_names(&m), vec!["POST /admin/reindex".to_string()]);
        assert_eq!(m[0].function_qnode, "admin/ops#reindex");
    }

    #[test]
    fn a_hash_rocket_pair_whose_target_is_not_a_string_binds_nothing() {
        let (m, _, _) = ruby(&format!("{DRAW}  get '/p' => SomeEngine\nend\n"));
        assert!(m.is_empty());
    }

    #[test]
    fn match_via_binds_one_route_per_verb() {
        let (m, _, _) = ruby(&format!(
            "{DRAW}  match '/ops/ping' => 'ops#ping', via: [:get, :post]\nend\n"
        ));
        assert_eq!(
            marker_names(&m),
            vec!["GET /ops/ping".to_string(), "POST /ops/ping".to_string()]
        );
        assert_eq!(m[0].function_qnode, "ops#ping");
    }

    #[test]
    fn match_without_a_readable_via_binds_every_verb() {
        let (m, _, _) = ruby(&format!("{DRAW}  match '/p' => 'c#a'\nend\n"));
        assert_eq!(marker_names(&m), vec!["ANY /p".to_string()]);
        let (m, _, _) = ruby(&format!("{DRAW}  match '/p' => 'c#a', via: [:link]\nend\n"));
        assert_eq!(marker_names(&m), vec!["ANY /p".to_string()]);
    }

    #[test]
    fn match_accepts_the_to_spelling_too() {
        let (m, _, _) = ruby(&format!(
            "{DRAW}  match '/p', to: 'c#a', via: [:put]\nend\n"
        ));
        assert_eq!(marker_names(&m), vec!["PUT /p".to_string()]);
    }

    #[test]
    fn match_without_a_binding_declares_nothing() {
        let (m, _, _) = ruby(&format!("{DRAW}  match '/p'\nend\n"));
        assert!(m.is_empty());
        let (m, _, _) = ruby(&format!("{DRAW}  match\nend\n"));
        assert!(m.is_empty());
    }

    #[test]
    fn a_bare_call_that_names_no_verb_is_not_a_route() {
        let (m, _, _) = ruby("puts 'hello'\n");
        assert!(m.is_empty());
    }

    #[test]
    fn a_sinatra_route_block_is_an_unguarded_entry_point() {
        let (m, _, g) = ruby("get '/hi' do\n  \"hi\"\nend\n");
        assert_eq!(marker_names(&m), vec!["GET /hi".to_string()]);
        assert_eq!(m[0].function_qnode, "get_hi");
        assert_eq!(m[0].framework, "sinatra");
        assert!(g.is_empty());
    }

    #[test]
    fn a_sinatra_before_filter_guards_every_route_in_the_file() {
        let (m, _, g) = ruby("before do\n  authenticate!\nend\n\nget '/hi' do\n  \"hi\"\nend\n");
        assert_eq!(m.len(), 1);
        assert_eq!(
            guard_names(&g),
            vec![("get_hi".to_string(), "authenticate!".to_string())]
        );
    }

    #[test]
    fn a_sinatra_before_filter_of_unrelated_helpers_guards_nothing() {
        let (_, _, g) = ruby("before do\n  log_request\nend\n\nget '/hi' do\n  \"hi\"\nend\n");
        assert!(g.is_empty());
    }

    #[test]
    fn a_controller_before_action_guards_its_actions() {
        let (_, _, g) = ruby(
            "class UsersController < ApplicationController\n\
             \x20 before_action :authenticate_user!\n\
             \x20 def show\n  end\n\
             \x20 def index\n  end\n\
             end\n",
        );
        assert_eq!(
            guard_names(&g),
            vec![
                ("users#show".to_string(), "authenticate_user!".to_string()),
                ("users#index".to_string(), "authenticate_user!".to_string()),
            ]
        );
    }

    #[test]
    fn a_before_action_only_list_limits_the_actions_it_guards() {
        let (_, _, g) = ruby(
            "class UsersController < ApplicationController\n\
             \x20 before_action :require_login, only: [:show]\n\
             \x20 def show\n  end\n\
             \x20 def index\n  end\n\
             end\n",
        );
        assert_eq!(
            guard_names(&g),
            vec![("users#show".to_string(), "require_login".to_string())]
        );
    }

    #[test]
    fn a_before_action_except_list_exempts_an_action() {
        let (_, _, g) = ruby(
            "class UsersController < ApplicationController\n\
             \x20 before_filter :require_login, except: [:index]\n\
             \x20 def show\n  end\n\
             \x20 def index\n  end\n\
             end\n",
        );
        assert_eq!(
            guard_names(&g),
            vec![("users#show".to_string(), "require_login".to_string())]
        );
    }

    #[test]
    fn skip_before_action_removes_the_guard_it_names() {
        let (_, _, g) = ruby(
            "class UsersController < ApplicationController\n\
             \x20 before_action :authenticate_user!\n\
             \x20 skip_before_action :authenticate_user!, only: [:index]\n\
             \x20 def show\n  end\n\
             \x20 def index\n  end\n\
             end\n",
        );
        assert_eq!(
            guard_names(&g),
            vec![("users#show".to_string(), "authenticate_user!".to_string())]
        );
    }

    #[test]
    fn an_unrelated_controller_statement_is_not_a_filter() {
        let (_, _, g) = ruby(
            "class UsersController < ApplicationController\n\
             \x20 layout 'application'\n\
             \x20 before_action :authenticate_user!, only: SHOW_ACTIONS\n\
             \x20 def show\n  end\n\
             end\n",
        );
        // `layout` is not a filter; an `only:` list this walk cannot
        // read leaves the filter unconstrained rather than dropping it.
        assert_eq!(
            guard_names(&g),
            vec![("users#show".to_string(), "authenticate_user!".to_string())]
        );
    }

    #[test]
    fn a_controller_guard_that_demands_nothing_is_not_recorded() {
        let (_, _, g) = ruby(
            "class UsersController < ApplicationController\n\
             \x20 before_action :set_user\n\
             \x20 def show\n  end\n\
             end\n",
        );
        assert!(g.is_empty());
    }

    #[test]
    fn a_namespaced_controller_keeps_its_module_in_the_handler_id() {
        let (_, _, g) = ruby(
            "class Admin::UserProfilesController < ApplicationController\n\
             \x20 before_action :authenticate_user!\n\
             \x20 def show\n  end\n\
             end\n",
        );
        assert_eq!(g[0].function_qnode, "admin/user_profiles#show");
    }

    #[test]
    fn a_class_that_is_not_a_controller_declares_no_guards() {
        let (_, _, g) =
            ruby("class UserMailer\n  before_action :authenticate_user!\n  def show\n  end\nend\n");
        assert!(g.is_empty());
    }

    #[test]
    fn controller_resource_rejects_a_bare_controller_class() {
        assert_eq!(controller_resource("Controller"), None);
        assert_eq!(controller_resource("UserMailer"), None);
    }

    #[test]
    fn a_controller_with_an_empty_body_declares_no_guards() {
        let (_, _, g) = ruby("class UsersController < ApplicationController\nend\n");
        assert!(g.is_empty());
    }

    #[test]
    fn a_before_action_without_arguments_guards_nothing() {
        let (_, _, g) = ruby(
            "class UsersController < ApplicationController\n\
             \x20 before_action\n\
             \x20 def show\n  end\n\
             end\n",
        );
        assert!(g.is_empty());
    }
}
