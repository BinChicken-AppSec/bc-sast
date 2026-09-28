//! Framework route/marker and response-dataflow extraction. Ported from
//! `_scan.py`'s `_py_extract_framework_markers` (L662-744),
//! `_java_extract_framework_markers` (L747-864),
//! `_cs_extract_framework_markers` (L867-968) and the three
//! `_*_extract_response_dataflow` functions (L971-1211), plus the
//! `_FRAMEWORK_MARKER_EXTRACTORS`/`_RESPONSE_DATAFLOW_EXTRACTORS`
//! dispatch tables `scan_file` drives them from (L2831-2837).
//!
//! These facts are what `_graph.py::_emit_framework_entry_points`
//! (L1494-1554) turns into `kind="framework"` entry points, and what
//! `_apply_response_dataflow` (L1556-1616) uses to widen a taint-evidence
//! path's CWE set.
//!
//! **Deliberate divergences from the Python original**, each a fix rather
//! than a replication (see the repo's "fix Python bugs, don't preserve
//! them" rule):
//!
//! 1. **C# route facts are actually emitted.** Python reaches an
//!    `[HttpGet("...")]` attribute's arguments with
//!    `attr_node.child_by_field_name("arguments")`, but the
//!    `attribute` node in tree-sitter-c-sharp exposes its
//!    `attribute_argument_list` as an *unnamed* child, so that lookup is
//!    always `None` and `_cs_extract_framework_markers` never appends a
//!    single `RouteTaintFact`. This port walks to the
//!    `attribute_argument_list` (and through the `attribute_argument`
//!    wrapper) by node kind instead.
//! 2. **A route mapping is itself a marker.** Python only emits
//!    `FrameworkMarkerFact`s for *parameter* annotations
//!    (`@RequestParam`, `[FromQuery]`, …) and for the Django `request`
//!    parameter — and `_emit_framework_entry_points` reads *only*
//!    markers — so a `@GetMapping("/health")` handler with no annotated
//!    parameter yields no entry point at all, even though the route is
//!    exactly the implicit source the function's own docstring describes
//!    ("route bindings"). Python's `route_facts` are, correspondingly,
//!    dead: `_build_framework_symbol_table` reads them into a local that
//!    `build_taint_paths` then never uses. Here every recognized route
//!    mapping also emits a `<framework>_route` marker, so the handler
//!    becomes an entry point with or without annotated parameters.
//! 3. **Frameworks Python never covered are wired.** `_scan.py`'s marker
//!    table has three keys (python/java/csharp), so Go produced no
//!    framework entry points at all and JavaScript none either. Added
//!    here: Flask (`@app.route`/`@bp.route`), FastAPI
//!    (`@app.get`/`@router.post`/…), JAX-RS (`@Path` + `@GET`/… +
//!    `@QueryParam`/`@PathParam`/…), ASP.NET `[Route(...)]`; for
//!    JavaScript/TypeScript, Express and Koa (`app.get(...)`/
//!    `router.post(...)`), Fastify, hapi (`server.route({…})`), NestJS
//!    (`@Controller` + verb decorators + `@UseGuards` + parameter
//!    binding decorators) and Next.js file-based routes; and for Go,
//!    net/http, gin, echo, chi, gorilla mux and fiber. Django's
//!    `urlpatterns`/`path()`/`re_path()` table is **not** ported: binding
//!    a URL pattern to its view needs cross-module resolution of the view
//!    reference, which no fact in this crate carries (Python does not
//!    attempt it either).
//! 4. **Python handler parameters are read out of typed/defaulted
//!    parameters too.** Python's own extractor only recognizes a bare
//!    `identifier` parameter (its `param.type in ("identifier",
//!    "parameter")` test can never match `"parameter"` — no such node
//!    kind exists in tree-sitter-python), so `def view(request:
//!    HttpRequest)` is missed despite the comment right above it saying
//!    every function taking `request` should be treated as a view.
//! 5. **Four languages Python has no plugin for carry entry points**:
//!    PHP (Laravel, Symfony, and scripts reading `$_GET`/`$_POST`
//!    directly), Ruby (Rails and Sinatra), Kotlin (Ktor and Spring) and
//!    Rust (axum, actix-web and rocket). Their detectors live in
//!    `framework/{php,ruby,kotlin,rust}.rs` and share
//!    `framework/common.rs`, which also explains why their route
//!    markers name the HTTP method the sections below drop.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use tree_sitter::Node;

use crate::scan::{
    collect_fn_ranges, kids, named_kids, py_leftmost_identifier, py_text, scope_for, AuthGuardFact,
    FrameworkMarkerFact, ResponseDataflowFact, RouteTaintFact,
};

// Languages whose detectors landed after the sections below, kept in
// their own files so this one stays the Python-derived plane. See
// `framework/common.rs` for what they share.
mod common;
mod kotlin;
mod php;
mod ruby;
mod rust;

/// `{id}` — Spring, JAX-RS, ASP.NET and FastAPI path templates. Ported
/// from `_scan.py`'s inline `re_module.findall(r'\{(\w+)\}', route_path)`.
static BRACE_PARAM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\{(\w+)\}").unwrap());
/// `<id>` / `<int:id>` — Flask and Django path converters.
static ANGLE_PARAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<(?:[^<>:]+:)?(\w+)>").unwrap());
/// `:id` — Express path parameters.
static COLON_PARAM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r":(\w+)").unwrap());

/// Strip the quote characters tree-sitter keeps inside a string-literal
/// node's own text span, matching Python's `.strip("\"")` / `.strip("\"'")`.
fn strip_quotes(s: &str) -> &str {
    s.trim_matches(['"', '\''])
}

/// Capture-group-1 matches of `rx` in `pattern`, in order, deduped.
fn route_params(rx: &Regex, pattern: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in rx.captures_iter(pattern) {
        let name = c[1].to_string();
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// One recognized route mapping: a `<framework>_route` marker for the
/// handler plus one [`RouteTaintFact`] per path parameter.
#[allow(clippy::too_many_arguments)]
fn push_route(
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    function_qnode: &str,
    line: usize,
    pattern: &str,
    params: Vec<String>,
    framework: &str,
    marker_type: &str,
) {
    markers.push(FrameworkMarkerFact {
        function_qnode: function_qnode.to_string(),
        line,
        marker_type: marker_type.to_string(),
        marker_name: pattern.to_string(),
        parameter_names: params.clone(),
        framework: framework.to_string(),
        confidence: "high".to_string(),
    });
    for p in params {
        routes.push(RouteTaintFact {
            function_qnode: function_qnode.to_string(),
            line,
            route_pattern: pattern.to_string(),
            parameter_name: p,
            is_tainted: true,
            framework: framework.to_string(),
        });
    }
}

// ── authentication guards (no Python counterpart) ────────────────────────
//
// See [`crate::scan::AuthGuardFact`] for why this exists at all: nothing
// upstream ever sets `reachable_from_unauth`, so every seed entry point
// claims to be behind authentication regardless of the code.

/// Lowercased with `_` and `-` removed, so one table covers
/// `login_required`, `loginRequired` and `LoginRequired` alike.
fn normalize_guard_name(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

/// Names that demand authentication: Flask-Login/Flask-JWT/Django/DRF
/// decorators, Spring Security and Shiro and JSR-250 annotations, ASP.NET
/// `[Authorize]`, and the conventional Express middleware names.
/// Curated rather than heuristic — a substring match on "auth" would
/// catch `author_id` and every OAuth *client* helper.
const AUTH_REQUIRED_NAMES: &[&str] = &[
    "adminrequired",
    "authenticate",
    "authenticated",
    "authenticator",
    "authguard",
    "authmiddleware",
    "authorize",
    "authrequired",
    "checkauth",
    "ensureauthenticated",
    "freshloginrequired",
    "isauthenticated",
    // Go and Node router middleware conventions.
    "jwtauth",
    "jwtmiddleware",
    "jwtrequired",
    "loginrequired",
    "permissionclasses",
    "permissionrequired",
    "postauthorize",
    "preauthorize",
    "requireauth",
    "requirelogin",
    "requiresauth",
    "requiresauthentication",
    "requirespermissions",
    "requiresession",
    "requiresroles",
    "requiresuser",
    "rolesaccepted",
    "rolesallowed",
    "rolesrequired",
    "secured",
    "sessionmiddleware",
    "sessionrequired",
    "staffmemberrequired",
    "superuserrequired",
    "tokenrequired",
    "userpassestest",
    "verifytoken",
];

/// Explicit opt-outs. These are evidence the handler *is* anonymously
/// reachable, and they override an enclosing class's guard.
const ANONYMOUS_NAMES: &[&str] = &["allowanonymous", "anonymousallowed", "permitall"];

/// Guard-name *shapes*, for the middleware [`AUTH_REQUIRED_NAMES`]
/// cannot enumerate: a project spells its own router middleware
/// `requireServiceToken`, `ensureSession`, `withJWT`, and no curated
/// list will ever have all of them. Both halves stay curated — a
/// `require`/`ensure`/`verify`/`check`/`must`/`with` prefix over an
/// authentication noun — so `requireFields` and `authorId` are still
/// misses, which is the property the substring match this file rejects
/// would have thrown away.
const GUARD_PREFIXES: &[&str] = &["require", "ensure", "verify", "check", "must", "with"];
const GUARD_NOUNS: &[&str] = &[
    "admin",
    "auth",
    "credential",
    "identity",
    "jwt",
    "login",
    "permission",
    "role",
    "session",
    "token",
    "user",
];

/// `Some(requires_auth)` when `name` says something about authentication.
fn auth_guard_kind(name: &str) -> Option<bool> {
    // A dotted/qualified spelling (`auth.login_required`,
    // `org.springframework.security.access.prepost.PreAuthorize`) is
    // decided by its final segment.
    let leaf = name.rsplit('.').next().unwrap_or(name);
    let norm = normalize_guard_name(leaf);
    if ANONYMOUS_NAMES.contains(&norm.as_str()) {
        return Some(false);
    }
    if AUTH_REQUIRED_NAMES.contains(&norm.as_str()) {
        return Some(true);
    }
    let shaped = GUARD_PREFIXES.iter().any(|p| {
        norm.strip_prefix(p)
            .is_some_and(|rest| GUARD_NOUNS.iter().any(|n| rest.contains(n)))
    });
    shaped.then_some(true)
}

/// Record the strongest verdict among `names` for one handler. A
/// method-level opt-out beats a method-level guard (that is what
/// `[AllowAnonymous]` on an `[Authorize]` controller means), and any
/// method-level verdict beats the enclosing class's. Emits nothing when
/// nothing is known — absence of evidence is what makes an entry point
/// reachable-from-unauth.
fn push_auth_guard(
    out: &mut Vec<AuthGuardFact>,
    function_qnode: &str,
    line: usize,
    framework: &str,
    own_names: &[String],
    enclosing_names: &[String],
    decorate: fn(&str) -> String,
) {
    for (names, _own) in [(own_names, true), (enclosing_names, false)] {
        let verdicts: Vec<(&String, bool)> = names
            .iter()
            .filter_map(|n| auth_guard_kind(n).map(|k| (n, k)))
            .collect();
        if verdicts.is_empty() {
            continue;
        }
        let (name, requires_auth) = verdicts
            .iter()
            .find(|(_, k)| !*k)
            .copied()
            .unwrap_or(verdicts[0]);
        out.push(AuthGuardFact {
            function_qnode: function_qnode.to_string(),
            line,
            marker_name: decorate(name),
            requires_auth,
            framework: framework.to_string(),
        });
        return;
    }
}

fn at_name(n: &str) -> String {
    format!("@{n}")
}

fn bracket_name(n: &str) -> String {
    format!("[{n}]")
}

fn plain_name(n: &str) -> String {
    n.to_string()
}

/// Per-language dispatch, mirroring `_scan.py::_FRAMEWORK_MARKER_EXTRACTORS`.
/// `rel` is the repo-relative path, which only Next.js's file-based
/// routing needs — there the route *is* the path.
pub(crate) fn extract_framework_facts(
    language: &str,
    rel: &str,
    src: &[u8],
    root: Node,
) -> (
    Vec<FrameworkMarkerFact>,
    Vec<RouteTaintFact>,
    Vec<AuthGuardFact>,
) {
    let mut markers = Vec::new();
    let mut routes = Vec::new();
    let mut guards = Vec::new();
    match language {
        "python" => py_visit(root, src, &mut markers, &mut routes, &mut guards),
        "java" => java_visit(root, src, &mut markers, &mut routes, &mut guards),
        "csharp" => cs_visit(root, src, &mut markers, &mut routes, &mut guards),
        "javascript" | "typescript" => {
            js_visit(root, rel, src, &mut markers, &mut routes, &mut guards)
        }
        "go" => go_visit(root, src, &mut markers, &mut routes, &mut guards),
        "php" => php::visit(root, src, &mut markers, &mut routes, &mut guards),
        "ruby" => ruby::visit(root, src, &mut markers, &mut routes, &mut guards),
        "kotlin" => kotlin::visit(root, src, &mut markers, &mut routes, &mut guards),
        "rust" => rust::visit(root, src, &mut markers, &mut routes, &mut guards),
        _ => {}
    }
    (markers, routes, guards)
}

/// Per-language dispatch, mirroring `_scan.py::_RESPONSE_DATAFLOW_EXTRACTORS`.
pub(crate) fn extract_response_dataflow(
    language: &str,
    src: &[u8],
    root: Node,
) -> Vec<ResponseDataflowFact> {
    let mut out = Vec::new();
    match language {
        "python" => {
            let mut ranges = Vec::new();
            collect_fn_ranges(root, src, &["function_definition"], &mut ranges);
            py_response_visit(root, src, &ranges, &mut out);
        }
        "java" => {
            let mut ranges = Vec::new();
            collect_fn_ranges(root, src, &["method_declaration"], &mut ranges);
            java_response_visit(root, src, &ranges, &mut out);
        }
        "csharp" => {
            let mut ranges = Vec::new();
            collect_fn_ranges(root, src, &["method_declaration"], &mut ranges);
            cs_response_visit(root, src, &ranges, &mut out);
        }
        _ => {}
    }
    out
}

// ── Python ───────────────────────────────────────────────────────────────

/// Handler parameter names. Python's own extractor reads only bare
/// `identifier` parameters; this also unwraps the typed/defaulted forms
/// (see divergence 4 in the module doc).
fn py_param_names(params_node: Node, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for param in named_kids(params_node) {
        let name = match param.kind() {
            "identifier" => py_text(param, src),
            "typed_parameter" | "default_parameter" | "typed_default_parameter" => param
                .child_by_field_name("name")
                .or_else(|| param.child(0))
                .filter(|n| n.kind() == "identifier")
                .map(|n| py_text(n, src))
                .unwrap_or_default(),
            _ => String::new(),
        };
        if !name.is_empty() {
            out.push(name);
        }
    }
    out
}

/// `request.GET` / `.POST` / `.META` / `.FILES` reads anywhere under
/// `node`. Ported from `_py_extract_framework_markers::_check_request_access`.
fn py_request_access(
    node: Node,
    src: &[u8],
    fn_name: &str,
    markers: &mut Vec<FrameworkMarkerFact>,
) {
    if node.kind() == "attribute" {
        let obj = node.child_by_field_name("object");
        // The Python grammar's field is `attribute`; the `attr` fallback
        // mirrors the original's own compatibility branch for older
        // grammars.
        let attr = node
            .child_by_field_name("attribute")
            .or_else(|| node.child_by_field_name("attr"));
        if let (Some(obj), Some(attr)) = (obj, attr) {
            let obj_text = py_text(obj, src);
            let attr_text = py_text(attr, src);
            if obj_text == "request"
                && matches!(attr_text.as_str(), "GET" | "POST" | "META" | "FILES")
            {
                markers.push(FrameworkMarkerFact {
                    function_qnode: fn_name.to_string(),
                    line: node.start_position().row + 1,
                    marker_type: "django_dict_access".to_string(),
                    marker_name: format!("request.{attr_text}"),
                    parameter_names: vec!["result".to_string()],
                    framework: "django".to_string(),
                    confidence: "high".to_string(),
                });
            }
        }
    }
    for c in kids(node) {
        py_request_access(c, src, fn_name, markers);
    }
}

/// `(framework, marker_type)` for a `@<receiver>.<method>(...)`
/// decorator, or `None` when it names no route-registering call.
fn py_route_decorator_kind(method: &str) -> Option<(&'static str, &'static str)> {
    match method {
        "route" => Some(("flask", "flask_route")),
        "get" | "post" | "put" | "delete" | "patch" | "head" | "options" | "trace" => {
            Some(("fastapi", "fastapi_route"))
        }
        _ => None,
    }
}

/// First positional string argument of a `call` node, unquoted.
fn py_first_string_arg(call: Node, src: &[u8]) -> Option<String> {
    let args = call.child_by_field_name("arguments")?;
    named_kids(args)
        .find(|a| a.kind() == "string")
        .map(|a| strip_quotes(&py_text(a, src)).to_string())
}

/// Flask/FastAPI decorators on a `decorated_definition`. The decorated
/// function's own name is the qnode, matching how Python attributes a
/// Spring mapping to its method name.
/// Returns `None` for a decorated definition that is not a function —
/// the `?`s below are structural lookups tree-sitter always satisfies
/// for the node kinds reached here.
fn py_decorated(
    node: Node,
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) -> Option<()> {
    let def = node.child_by_field_name("definition")?;
    if def.kind() != "function_definition" {
        return None;
    }
    let fn_name = py_text(def.child_by_field_name("name")?, src);
    let decorator_names: Vec<String> = kids(node)
        .filter(|d| d.kind() == "decorator")
        .filter_map(|d| py_decorator_name(d, src))
        .collect();
    push_auth_guard(
        guards,
        &fn_name,
        def.start_position().row + 1,
        "python",
        &decorator_names,
        &[],
        at_name,
    );
    for dec in kids(node) {
        if dec.kind() != "decorator" {
            continue;
        }
        let Some(call) = named_kids(dec).find(|c| c.kind() == "call") else {
            continue;
        };
        let Some(func) = call
            .child_by_field_name("function")
            .filter(|f| f.kind() == "attribute")
        else {
            continue;
        };
        let method = func
            .child_by_field_name("attribute")
            .map(|n| py_text(n, src))
            .unwrap_or_default();
        let Some((framework, marker_type)) = py_route_decorator_kind(&method) else {
            continue;
        };
        // `app`/`bp`/`router`/`api` — anything else is some unrelated
        // decorator that happens to share a verb name.
        let receiver = py_leftmost_identifier(func, src);
        if receiver.is_empty() {
            continue;
        }
        let Some(pattern) = py_first_string_arg(call, src) else {
            continue;
        };
        let mut params = route_params(&ANGLE_PARAM, &pattern);
        params.extend(route_params(&BRACE_PARAM, &pattern));
        push_route(
            markers,
            routes,
            &fn_name,
            def.start_position().row + 1,
            &pattern,
            params,
            framework,
            marker_type,
        );
    }
    Some(())
}

/// A decorator's name, as written: `@login_required` (`identifier`),
/// `@auth.login_required` (`attribute`) and `@jwt_required()` (`call`)
/// are all reduced to their dotted source text.
fn py_decorator_name(dec: Node, src: &[u8]) -> Option<String> {
    let mut node = named_kids(dec).next()?;
    if node.kind() == "call" {
        node = node.child_by_field_name("function")?;
    }
    match node.kind() {
        "identifier" | "attribute" => Some(py_text(node, src)),
        _ => None,
    }
}

fn py_visit(
    node: Node,
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) {
    match node.kind() {
        "decorated_definition" => {
            py_decorated(node, src, markers, routes, guards);
        }
        "function_definition" => {
            let name_node = node.child_by_field_name("name");
            let params_node = node.child_by_field_name("parameters");
            if let (Some(name_node), Some(params_node)) = (name_node, params_node) {
                let fn_name = py_text(name_node, src);
                // Any function taking `request` is treated as a Django
                // view: naming heuristics miss common handlers such as
                // `profile(request)` (the original's own comment).
                if py_param_names(params_node, src)
                    .iter()
                    .any(|p| p == "request")
                {
                    markers.push(FrameworkMarkerFact {
                        function_qnode: fn_name.clone(),
                        line: node.start_position().row + 1,
                        marker_type: "django_view".to_string(),
                        marker_name: "request".to_string(),
                        parameter_names: vec!["request".to_string()],
                        framework: "django".to_string(),
                        confidence: "high".to_string(),
                    });
                }
                for c in kids(node) {
                    py_request_access(c, src, &fn_name, markers);
                }
            }
        }
        _ => {}
    }
    for c in kids(node) {
        py_visit(c, src, markers, routes, guards);
    }
}

// ── Java ─────────────────────────────────────────────────────────────────

/// `(framework, marker_type)` for a route-mapping annotation.
fn java_mapping_kind(name: &str) -> Option<(&'static str, &'static str)> {
    match name {
        "GetMapping" | "PostMapping" | "PutMapping" | "DeleteMapping" | "PatchMapping"
        | "RequestMapping" => Some(("spring", "spring_route")),
        // JAX-RS: `@Path` carries the template, the verb annotations
        // carry none but still mark the method as a resource method.
        "Path" | "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" => {
            Some(("jaxrs", "jaxrs_route"))
        }
        _ => None,
    }
}

/// Every annotation directly on `node`'s `modifiers` child.
fn java_annotations<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    for child in kids(node) {
        if child.kind() != "modifiers" {
            continue;
        }
        for m in kids(child) {
            if matches!(m.kind(), "annotation" | "marker_annotation") {
                out.push(m);
            }
        }
    }
    out
}

/// First `string_literal` in an annotation's `arguments` list, unquoted.
fn java_annotation_string(annotation: Node, src: &[u8]) -> Option<String> {
    let args = annotation.child_by_field_name("arguments")?;
    named_kids(args)
        .find(|a| a.kind() == "string_literal")
        .map(|a| strip_quotes(&py_text(a, src)).to_string())
}

/// Every annotation directly on `node`'s `modifiers` child, paired with
/// its name text. The `name` field is structural — tree-sitter-java
/// always provides one for both annotation node kinds — so pairing here
/// keeps the callers free of an unreachable guard.
fn java_named_annotations<'a>(node: Node<'a>, src: &[u8]) -> Vec<(Node<'a>, String)> {
    java_annotations(node)
        .into_iter()
        .filter_map(|a| a.child_by_field_name("name").map(|n| (a, py_text(n, src))))
        .collect()
}

/// Annotation/attribute names on the nearest enclosing type
/// declaration. A Spring `@PreAuthorize` or an ASP.NET `[Authorize]` on
/// the controller guards every handler in it, so a method-level lookup
/// alone would report those handlers as anonymously reachable.
fn enclosing_type_annotations(
    node: Node,
    src: &[u8],
    kinds: &[&str],
    // Java and C# share the `class_declaration` node kind, so the
    // extractor has to be chosen by the caller, not sniffed from it.
    extract: fn(Node, &[u8]) -> Vec<String>,
) -> Vec<String> {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if kinds.contains(&n.kind()) {
            return extract(n, src);
        }
        cur = n.parent();
    }
    Vec::new()
}

fn java_annotation_names(node: Node, src: &[u8]) -> Vec<String> {
    java_named_annotations(node, src)
        .into_iter()
        .map(|(_, name)| name)
        .collect()
}

fn cs_attribute_names(node: Node, src: &[u8]) -> Vec<String> {
    cs_named_attributes(node, src)
        .into_iter()
        .map(|(_, name)| name)
        .collect()
}

fn java_method(
    node: Node,
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) -> Option<()> {
    let method_name = py_text(node.child_by_field_name("name")?, src);
    let line = node.start_position().row + 1;

    let own = java_annotation_names(node, src);
    let enclosing = enclosing_type_annotations(
        node,
        src,
        &[
            "class_declaration",
            "record_declaration",
            "interface_declaration",
        ],
        java_annotation_names,
    );
    push_auth_guard(
        guards,
        &method_name,
        line,
        "java",
        &own,
        &enclosing,
        at_name,
    );

    for (ann, ann_name) in java_named_annotations(node, src) {
        let Some((framework, marker_type)) = java_mapping_kind(&ann_name) else {
            continue;
        };
        let pattern = java_annotation_string(ann, src).unwrap_or_default();
        let params = route_params(&BRACE_PARAM, &pattern);
        push_route(
            markers,
            routes,
            &method_name,
            line,
            &pattern,
            params,
            framework,
            marker_type,
        );
    }

    for param in named_kids(node.child_by_field_name("parameters")?) {
        if param.kind() == "formal_parameter" {
            java_parameter(param, src, &method_name, markers);
        }
    }
    Some(())
}

fn java_parameter(
    param: Node,
    src: &[u8],
    method_name: &str,
    markers: &mut Vec<FrameworkMarkerFact>,
) -> Option<()> {
    let param_name = py_text(param.child_by_field_name("name")?, src);
    let line = param.start_position().row + 1;

    for (_ann, ann_name) in java_named_annotations(param, src) {
        let (framework, marker_type) = match ann_name.as_str() {
            "RequestParam" | "PathVariable" | "RequestBody" | "RequestHeader" => {
                ("spring", "spring_annotation")
            }
            "QueryParam" | "PathParam" | "HeaderParam" | "FormParam" | "CookieParam"
            | "MatrixParam" | "BeanParam" => ("jaxrs", "jaxrs_annotation"),
            _ => continue,
        };
        markers.push(FrameworkMarkerFact {
            function_qnode: method_name.to_string(),
            line,
            marker_type: marker_type.to_string(),
            marker_name: format!("@{ann_name}"),
            parameter_names: vec![param_name.clone()],
            framework: framework.to_string(),
            confidence: "high".to_string(),
        });
    }

    if let Some(type_node) = param.child_by_field_name("type") {
        let type_text = py_text(type_node, src);
        if type_text.contains("ServletRequest") {
            markers.push(FrameworkMarkerFact {
                function_qnode: method_name.to_string(),
                line,
                marker_type: "spring_implicit".to_string(),
                marker_name: type_text,
                parameter_names: vec![param_name],
                framework: "spring".to_string(),
                confidence: "medium".to_string(),
            });
        }
    }
    Some(())
}

fn java_visit(
    node: Node,
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) {
    if node.kind() == "method_declaration" {
        java_method(node, src, markers, routes, guards);
    }
    for c in kids(node) {
        java_visit(c, src, markers, routes, guards);
    }
}

// ── C# ───────────────────────────────────────────────────────────────────

/// Every `attribute` inside `node`'s own `attribute_list` children.
fn cs_attributes<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let mut out = Vec::new();
    for child in kids(node) {
        if child.kind() != "attribute_list" {
            continue;
        }
        for a in kids(child) {
            if a.kind() == "attribute" {
                out.push(a);
            }
        }
    }
    out
}

/// First string argument of a C# attribute, unquoted. Walks to the
/// `attribute_argument_list` by kind and unwraps the
/// `attribute_argument` node — see divergence 1 in the module doc for
/// why the original's `child_by_field_name("arguments")` finds nothing.
fn cs_attribute_string(attribute: Node, src: &[u8]) -> Option<String> {
    let args = kids(attribute).find(|c| c.kind() == "attribute_argument_list")?;
    for arg in named_kids(args) {
        let lit = if arg.kind() == "attribute_argument" {
            named_kids(arg).next()
        } else {
            Some(arg)
        };
        if let Some(lit) = lit {
            if matches!(lit.kind(), "string_literal" | "string") {
                return Some(strip_quotes(&py_text(lit, src)).to_string());
            }
        }
    }
    None
}

/// Every attribute inside `node`'s own `attribute_list` children, paired
/// with its name text — the C# counterpart of [`java_named_annotations`].
fn cs_named_attributes<'a>(node: Node<'a>, src: &[u8]) -> Vec<(Node<'a>, String)> {
    cs_attributes(node)
        .into_iter()
        .filter_map(|a| a.child_by_field_name("name").map(|n| (a, py_text(n, src))))
        .collect()
}

fn cs_method(
    node: Node,
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) -> Option<()> {
    let method_name = py_text(node.child_by_field_name("name")?, src);
    let line = node.start_position().row + 1;

    let own = cs_attribute_names(node, src);
    let enclosing = enclosing_type_annotations(
        node,
        src,
        &["class_declaration", "record_declaration"],
        cs_attribute_names,
    );
    push_auth_guard(
        guards,
        &method_name,
        line,
        "aspnet",
        &own,
        &enclosing,
        bracket_name,
    );

    for (attr, attr_name) in cs_named_attributes(node, src) {
        if !matches!(
            attr_name.as_str(),
            "HttpGet" | "HttpPost" | "HttpPut" | "HttpDelete" | "HttpPatch" | "Route"
        ) {
            continue;
        }
        let pattern = cs_attribute_string(attr, src).unwrap_or_default();
        let params = route_params(&BRACE_PARAM, &pattern);
        push_route(
            markers,
            routes,
            &method_name,
            line,
            &pattern,
            params,
            "aspnet",
            "aspnet_route",
        );
    }

    for param in named_kids(node.child_by_field_name("parameters")?) {
        if param.kind() == "parameter" {
            cs_parameter(param, src, &method_name, markers);
        }
    }
    Some(())
}

fn cs_parameter(
    param: Node,
    src: &[u8],
    method_name: &str,
    markers: &mut Vec<FrameworkMarkerFact>,
) -> Option<()> {
    let param_name = py_text(param.child_by_field_name("name")?, src);
    for (_attr, attr_name) in cs_named_attributes(param, src) {
        if !matches!(
            attr_name.as_str(),
            "FromQuery" | "FromRoute" | "FromBody" | "FromHeader" | "FromForm"
        ) {
            continue;
        }
        markers.push(FrameworkMarkerFact {
            function_qnode: method_name.to_string(),
            line: param.start_position().row + 1,
            marker_type: "aspnet_annotation".to_string(),
            marker_name: format!("[{attr_name}]"),
            parameter_names: vec![param_name.clone()],
            framework: "aspnet".to_string(),
            confidence: "high".to_string(),
        });
    }
    Some(())
}

fn cs_visit(
    node: Node,
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) {
    if node.kind() == "method_declaration" {
        cs_method(node, src, markers, routes, guards);
    }
    for c in kids(node) {
        cs_visit(c, src, markers, routes, guards);
    }
}

// ── Go (net/http, gin, echo, chi, gorilla mux, fiber) ────────────────────
//
// No Python counterpart at all: `_scan.py`'s marker table has three
// keys (python/java/csharp), so a Go repo produced zero framework entry
// points and every Go handler looked unreachable to S1/S3.

/// `(framework, marker_type)` for a Go route-registration method name.
/// The three families are told apart by spelling, which is stable: `net
/// /http` and gorilla register with `HandleFunc`/`Handle`, gin and echo
/// use SHOUTING verbs, chi and fiber use TitleCase ones.
fn go_route_kind(method: &str) -> Option<(&'static str, &'static str)> {
    match method {
        "HandleFunc" | "Handle" => Some(("nethttp", "nethttp_route")),
        "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" | "Any" => {
            Some(("gin", "gin_route"))
        }
        "Get" | "Post" | "Put" | "Delete" | "Patch" | "Head" | "Options" => {
            Some(("chi", "chi_route"))
        }
        _ => None,
    }
}

/// First argument of a Go call, unquoted, when it is a string literal.
fn go_first_string_arg(call: Node, src: &[u8]) -> Option<String> {
    let args = call.child_by_field_name("arguments")?;
    let first = named_kids(args).next()?;
    matches!(
        first.kind(),
        "interpreted_string_literal" | "raw_string_literal"
    )
    .then(|| strip_quotes(&py_text(first, src)).to_string())
}

/// One route-registration argument, classified. Go's signature is
/// `(path, ...middleware, handler)`, so the LAST handler-shaped argument
/// is the handler and everything else is middleware.
enum GoArg {
    /// A handler: a local `showUser`, an imported `handlers.ShowUser`
    /// (the gin/echo/chi idiom — the whole point of a `handlers`
    /// package), or an inline `func(w, r) {…}` literal, which has no
    /// name of its own and borrows the enclosing scope's.
    Handler(String),
    /// Middleware, or the wrapper a handler is passed through:
    /// `requireServiceToken(http.HandlerFunc(probeHandler))` names two
    /// wrappers and one handler.
    Middleware(String),
}

/// Classify one route-registration argument, descending into a wrapper
/// call to find the handler it wraps.
fn go_route_arg(arg: Node, src: &[u8], fallback: &str, out: &mut Vec<GoArg>) {
    match arg.kind() {
        "identifier" => out.push(GoArg::Handler(py_text(arg, src))),
        // `handlers.SearchReports` — the handler is the selected name;
        // the package qualifier is resolved by the entry-point emitter,
        // which knows which file defines it.
        "selector_expression" => {
            if let Some(field) = arg.child_by_field_name("field") {
                out.push(GoArg::Handler(py_text(field, src)));
            }
        }
        "func_literal" => out.push(GoArg::Handler(fallback.to_string())),
        "call_expression" => {
            if let Some(f) = arg.child_by_field_name("function") {
                out.push(GoArg::Middleware(py_text(f, src)));
            }
            if let Some(args) = arg.child_by_field_name("arguments") {
                for inner in named_kids(args) {
                    go_route_arg(inner, src, fallback, out);
                }
            }
        }
        _ => {}
    }
}

/// `(handler, middleware)` for a route registration's argument list.
fn go_route_args(args: Node, src: &[u8], fallback: &str) -> (String, Vec<String>) {
    let mut parts = Vec::new();
    for arg in named_kids(args) {
        go_route_arg(arg, src, fallback, &mut parts);
    }
    let handler_at = parts
        .iter()
        .rposition(|p| matches!(p, GoArg::Handler(_)))
        .unwrap_or(usize::MAX);
    let mut handler = fallback.to_string();
    let mut middleware = Vec::new();
    for (i, part) in parts.into_iter().enumerate() {
        match part {
            GoArg::Handler(n) if i == handler_at => handler = n,
            GoArg::Handler(n) | GoArg::Middleware(n) => middleware.push(n),
        }
    }
    (handler, middleware)
}

/// Every name a `X.Use(a, b())` call registers as router middleware —
/// here every argument is a guard, not just the ones before the last.
fn go_use_names(args: Node, src: &[u8]) -> Vec<String> {
    let mut parts = Vec::new();
    for arg in named_kids(args) {
        go_route_arg(arg, src, "", &mut parts);
    }
    parts
        .into_iter()
        .map(|p| match p {
            GoArg::Handler(n) | GoArg::Middleware(n) => n,
        })
        .collect()
}

/// What a router handle (`r`, `admin`, `mux`) carries into the routes
/// registered on it.
#[derive(Default, Clone)]
struct GoHandle {
    /// The group's path prefix, `""` for a top-level router.
    prefix: String,
    /// Middleware registered on the handle itself, by `Group`'s trailing
    /// arguments or by a later `Use` call.
    guards: Vec<String>,
}

/// A `grp := router.Group("/api", mw...)` binding, so the routes
/// registered on `grp` carry both the group's prefix and its
/// middleware. gin and echo both spell it `Group`; a nested group
/// resolves against its own parent, which works because Go source is
/// written before it is used and this is a pre-order walk.
fn go_record_group(node: Node, src: &[u8], handles: &mut BTreeMap<String, GoHandle>) -> Option<()> {
    let call = named_kids(node.child_by_field_name("right")?).next()?;
    if call.kind() != "call_expression" {
        return None;
    }
    let func = call
        .child_by_field_name("function")
        .filter(|f| f.kind() == "selector_expression")?;
    if func.child_by_field_name("field").map(|f| py_text(f, src))? != "Group" {
        return None;
    }
    let parent = py_leftmost_identifier(func, src);
    let suffix = go_first_string_arg(call, src)?;
    let name = named_kids(node.child_by_field_name("left")?)
        .next()
        .filter(|n| n.kind() == "identifier")
        .map(|n| py_text(n, src))?;
    let base = handles.get(&parent).cloned().unwrap_or_default();
    let mut guards = base.guards;
    if let Some(args) = call.child_by_field_name("arguments") {
        // Everything after the prefix string is middleware.
        guards.extend(go_use_names(args, src));
    }
    handles.insert(
        name,
        GoHandle {
            prefix: format!("{}{suffix}", base.prefix),
            guards,
        },
    );
    Some(())
}

/// An `r.Use(auth())` / `admin.Use(RequireAdmin())` registration: every
/// route later registered on that handle is behind it.
fn go_record_use(node: Node, src: &[u8], handles: &mut BTreeMap<String, GoHandle>) -> Option<()> {
    let func = node
        .child_by_field_name("function")
        .filter(|f| f.kind() == "selector_expression")?;
    if py_text(func.child_by_field_name("field")?, src) != "Use" {
        return None;
    }
    let name = py_leftmost_identifier(func, src);
    if name.is_empty() {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    handles
        .entry(name)
        .or_default()
        .guards
        .extend(go_use_names(args, src));
    Some(())
}

fn go_visit(
    node: Node,
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) {
    let mut ranges = Vec::new();
    collect_fn_ranges(
        node,
        src,
        &["function_declaration", "method_declaration"],
        &mut ranges,
    );
    let mut handles = BTreeMap::new();
    go_route_visit(node, src, &ranges, &mut handles, markers, routes, guards);
}

#[allow(clippy::too_many_arguments)]
fn go_route_visit(
    node: Node,
    src: &[u8],
    ranges: &[(usize, usize, String)],
    handles: &mut BTreeMap<String, GoHandle>,
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) {
    if node.kind() == "short_var_declaration" {
        go_record_group(node, src, handles);
    }
    if node.kind() == "call_expression" {
        go_record_use(node, src, handles);
        go_route_call(node, src, ranges, handles, markers, routes, guards);
    }
    for c in kids(node) {
        go_route_visit(c, src, ranges, handles, markers, routes, guards);
    }
}

#[allow(clippy::too_many_arguments)]
fn go_route_call(
    node: Node,
    src: &[u8],
    ranges: &[(usize, usize, String)],
    handles: &BTreeMap<String, GoHandle>,
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) -> Option<()> {
    let func = node
        .child_by_field_name("function")
        .filter(|f| f.kind() == "selector_expression")?;
    let method = py_text(func.child_by_field_name("field")?, src);
    let (framework, marker_type) = go_route_kind(&method)?;
    // A route path is a string literal starting with `/`. Requiring it
    // is what keeps `cache.Get("k")` and `w.Header().Set(...)` out —
    // the TitleCase verb set is otherwise far too common a spelling to
    // claim on its own.
    let suffix = go_first_string_arg(node, src).filter(|p| p.starts_with('/'))?;
    let receiver = py_leftmost_identifier(func, src);
    let handle = handles.get(&receiver).cloned().unwrap_or_default();
    let pattern = format!("{}{suffix}", handle.prefix);
    let args = node.child_by_field_name("arguments")?;
    let fallback = scope_for(node.start_byte(), ranges);
    let (qnode, middleware) = go_route_args(args, src, &fallback);
    if qnode.is_empty() {
        return None;
    }
    // `mux.Handle("/", r)` mounts one router inside another; `r` is a
    // router handle, not a handler, and naming an entry point after it
    // would invent a function that does not exist.
    if handles.contains_key(&qnode) {
        return None;
    }
    let line = node.start_position().row + 1;
    push_auth_guard(
        guards,
        &qnode,
        line,
        framework,
        &middleware,
        &handle.guards,
        plain_name,
    );
    // gin/echo/fiber write `:id`, chi/gorilla/net-http-1.22 write
    // `{id}`; a router's own style is not worth branching on.
    let mut params = route_params(&COLON_PARAM, &pattern);
    params.extend(route_params(&BRACE_PARAM, &pattern));
    push_route(
        markers,
        routes,
        &qnode,
        line,
        &pattern,
        params,
        framework,
        marker_type,
    );
    Some(())
}

// ── JavaScript / TypeScript (Express, Koa, Fastify, hapi, NestJS, Next) ──

/// The handler function a route registration binds, as a qnode name: a
/// bare `identifier` argument names an existing function definition, a
/// named `function_expression` names itself, and an inline anonymous
/// handler falls back to the enclosing scope.
fn js_handler_name(args: Node, src: &[u8], fallback: &str) -> String {
    // Express's signature is `(path, ...middleware, handler)`, so the
    // LAST callable argument is the handler; every earlier identifier is
    // middleware. Taking the first would name
    // `app.get("/x", requireAuth, show)` after its auth middleware.
    let mut out = None;
    for arg in named_kids(args) {
        match arg.kind() {
            "identifier" => out = Some(py_text(arg, src)),
            "function_expression" | "function_declaration" => {
                out = Some(match arg.child_by_field_name("name") {
                    Some(n) => py_text(n, src),
                    None => fallback.to_string(),
                });
            }
            "arrow_function" => out = Some(fallback.to_string()),
            _ => {}
        }
    }
    out.unwrap_or_else(|| fallback.to_string())
}

/// Route-registration arguments that name a guard rather than the
/// handler — Express/Koa middleware, and the middleware *factories*
/// (`passport.authenticate('jwt')`, `requireAuth()`) that are far more
/// common in practice than a bare identifier. The handler is the LAST
/// identifier argument, so that one entry is dropped.
fn js_middleware_names(args: Node, src: &[u8]) -> Vec<String> {
    let mut names: Vec<(bool, String)> = Vec::new();
    for a in named_kids(args) {
        match a.kind() {
            "identifier" => names.push((true, py_text(a, src))),
            "call_expression" => {
                if let Some(f) = a.child_by_field_name("function") {
                    names.push((false, py_text(f, src)));
                }
            }
            _ => {}
        }
    }
    if let Some(pos) = names.iter().rposition(|(is_ident, _)| *is_ident) {
        names.remove(pos);
    }
    names.into_iter().map(|(_, n)| n).collect()
}

/// Route-registration handles. `fastify` joins Express's and Koa's set
/// because `fastify.get('/p', handler)` is the identical shape.
const JS_ROUTE_HANDLES: &[&str] = &["app", "router", "server", "api", "fastify"];

/// Object keys a Fastify route-options argument hangs its pre-handler
/// hooks off, where an auth guard lives.
const JS_HOOK_KEYS: &[&str] = &["preHandler", "onRequest", "preValidation", "beforeHandle"];

/// The first object-literal argument of a call — Fastify's route
/// options and hapi's whole route descriptor.
fn js_object_arg<'a>(args: Node<'a>) -> Option<Node<'a>> {
    named_kids(args).find(|a| a.kind() == "object")
}

/// The value node of `obj`'s `key` property.
fn js_object_value<'a>(obj: Node<'a>, key: &str, src: &[u8]) -> Option<Node<'a>> {
    named_kids(obj)
        .filter(|p| p.kind() == "pair")
        .find(|p| {
            p.child_by_field_name("key")
                .map(|k| strip_quotes(&py_text(k, src)) == key)
                .unwrap_or(false)
        })
        .and_then(|p| p.child_by_field_name("value"))
}

/// Guard names named by a route-options object's hook keys, an array of
/// them included (`{ preHandler: [verifyToken] }`).
fn js_hook_names(args: Node, src: &[u8]) -> Vec<String> {
    let Some(obj) = js_object_arg(args) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in JS_HOOK_KEYS {
        let Some(value) = js_object_value(obj, key, src) else {
            continue;
        };
        match value.kind() {
            "array" => out.extend(
                named_kids(value)
                    .filter(|e| e.kind() == "identifier")
                    .map(|e| py_text(e, src)),
            ),
            _ => out.push(py_text(value, src)),
        }
    }
    out
}

/// A hapi `server.route({ method, path, handler })` descriptor.
fn js_hapi_route(
    node: Node,
    src: &[u8],
    ranges: &[(usize, usize, String)],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) -> Option<()> {
    let args = node.child_by_field_name("arguments")?;
    let obj = js_object_arg(args)?;
    let pattern = strip_quotes(&py_text(js_object_value(obj, "path", src)?, src)).to_string();
    let handler = js_object_value(obj, "handler", src)?;
    let fallback = scope_for(node.start_byte(), ranges);
    let qnode = match handler.kind() {
        "identifier" => py_text(handler, src),
        _ => fallback,
    };
    if qnode.is_empty() {
        return None;
    }
    let line = node.start_position().row + 1;
    push_auth_guard(
        guards,
        &qnode,
        line,
        "hapi",
        &js_hook_names(args, src),
        &[],
        plain_name,
    );
    // hapi templates path parameters as `{id}`.
    push_route(
        markers,
        routes,
        &qnode,
        line,
        &pattern,
        route_params(&BRACE_PARAM, &pattern),
        "hapi",
        "hapi_route",
    );
    Some(())
}

fn js_visit(
    node: Node,
    rel: &str,
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) {
    let mut ranges = Vec::new();
    collect_fn_ranges(
        node,
        src,
        &["function_declaration", "method_definition"],
        &mut ranges,
    );
    js_route_visit(node, src, &ranges, markers, routes, guards);
    js_nest_visit(node, src, markers, routes, guards);
    js_next_visit(node, rel, src, markers, routes);
}

fn js_route_visit(
    node: Node,
    src: &[u8],
    ranges: &[(usize, usize, String)],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) {
    if node.kind() == "call_expression" {
        js_route_call(node, src, ranges, markers, routes, guards);
    }
    for c in kids(node) {
        js_route_visit(c, src, ranges, markers, routes, guards);
    }
}

fn js_route_call(
    node: Node,
    src: &[u8],
    ranges: &[(usize, usize, String)],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) -> Option<()> {
    let func = node
        .child_by_field_name("function")
        .filter(|f| f.kind() == "member_expression")?;
    let receiver = py_text(func.child_by_field_name("object")?, src);
    let method = py_text(func.child_by_field_name("property")?, src);
    // Only the conventional handles — anything else named `.get(...)` is
    // far more likely a map/cache read.
    if !JS_ROUTE_HANDLES.contains(&receiver.as_str()) {
        return None;
    }
    if method == "route" {
        return js_hapi_route(node, src, ranges, markers, routes, guards);
    }
    if !matches!(
        method.as_str(),
        "get" | "post" | "put" | "delete" | "patch" | "head" | "options" | "all" | "use"
    ) {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let pattern = named_kids(args)
        .find(|a| a.kind() == "string" || a.kind() == "template_string")
        .map(|a| strip_quotes(&py_text(a, src)).to_string())?;
    let fallback = scope_for(node.start_byte(), ranges);
    let qnode = js_handler_name(args, src, &fallback);
    if qnode.is_empty() {
        return None;
    }
    let line = node.start_position().row + 1;
    let mut middleware = js_middleware_names(args, src);
    middleware.extend(js_hook_names(args, src));
    let framework = if receiver == "fastify" {
        "fastify"
    } else {
        "express"
    };
    push_auth_guard(
        guards,
        &qnode,
        line,
        framework,
        &middleware,
        &[],
        plain_name,
    );
    push_route(
        markers,
        routes,
        &qnode,
        line,
        &pattern,
        route_params(&COLON_PARAM, &pattern),
        framework,
        "express_route",
    );
    Some(())
}

// ── NestJS decorators ────────────────────────────────────────────────────

/// A decorator's `(name, call_node)`: `@Get(':id')` and a bare `@Get`
/// both reduce to `"Get"`, with the call node present only for the
/// former.
fn js_decorator_parts<'a>(dec: Node<'a>, src: &[u8]) -> Option<(String, Option<Node<'a>>)> {
    let inner = named_kids(dec).next()?;
    match inner.kind() {
        "call_expression" => {
            let f = inner.child_by_field_name("function")?;
            Some((py_text(f, src), Some(inner)))
        }
        "identifier" | "member_expression" => Some((py_text(inner, src), None)),
        _ => None,
    }
}

/// Every `decorator` child of `node`, plus — for an exported class —
/// those of the enclosing `export_statement`, which is where
/// tree-sitter hangs `@Controller('x')` on `export class C {}`.
fn js_decorators<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    let mut out: Vec<Node<'a>> = kids(node).filter(|c| c.kind() == "decorator").collect();
    if let Some(p) = node.parent().filter(|p| p.kind() == "export_statement") {
        out.extend(kids(p).filter(|c| c.kind() == "decorator"));
    }
    out
}

/// First string argument of a decorator's call, unquoted.
fn js_decorator_string(call: Node, src: &[u8]) -> Option<String> {
    let args = call.child_by_field_name("arguments")?;
    named_kids(args)
        .find(|a| a.kind() == "string" || a.kind() == "template_string")
        .map(|a| strip_quotes(&py_text(a, src)).to_string())
}

/// Join a `@Controller('users')` prefix to a `@Get(':id')` suffix, with
/// exactly one separator: `/users/:id`.
fn js_join_route(prefix: &str, suffix: &str) -> String {
    let p = prefix.trim_matches('/');
    let s = suffix.trim_matches('/');
    match (p.is_empty(), s.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{s}"),
        (false, true) => format!("/{p}"),
        (false, false) => format!("/{p}/{s}"),
    }
}

fn js_nest_visit(
    node: Node,
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) {
    if node.kind() == "class_declaration" {
        js_nest_class(node, src, markers, routes, guards);
    }
    for c in kids(node) {
        js_nest_visit(c, src, markers, routes, guards);
    }
}

fn js_nest_class(
    node: Node,
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) -> Option<()> {
    let mut prefix = None;
    let mut class_guards: Vec<String> = Vec::new();
    for dec in js_decorators(node) {
        let Some((name, call)) = js_decorator_parts(dec, src) else {
            continue;
        };
        match name.as_str() {
            "Controller" => {
                prefix = Some(
                    call.and_then(|c| js_decorator_string(c, src))
                        .unwrap_or_default(),
                )
            }
            "UseGuards" => {
                class_guards.extend(call.into_iter().flat_map(|c| js_guard_args(c, src)))
            }
            _ => {}
        }
    }
    // Only a `@Controller`-decorated class is a Nest controller;
    // anything else is a plain class whose `@Get` would be something
    // else entirely.
    let prefix = prefix?;
    let body = node.child_by_field_name("body")?;
    let mut pending: Vec<Node> = Vec::new();
    for child in kids(body) {
        if child.kind() == "decorator" {
            pending.push(child);
            continue;
        }
        if child.kind() == "method_definition" {
            js_nest_method(
                child,
                &pending,
                &prefix,
                &class_guards,
                src,
                markers,
                routes,
                guards,
            );
        }
        pending.clear();
    }
    Some(())
}

/// Identifier arguments of `@UseGuards(AuthGuard, RolesGuard)`.
fn js_guard_args(call: Node, src: &[u8]) -> Vec<String> {
    call.child_by_field_name("arguments")
        .map(|args| {
            named_kids(args)
                .filter(|a| a.kind() == "identifier")
                .map(|a| py_text(a, src))
                .collect()
        })
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn js_nest_method(
    method: Node,
    decorators: &[Node],
    prefix: &str,
    class_guards: &[String],
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
    guards: &mut Vec<AuthGuardFact>,
) -> Option<()> {
    let name = py_text(method.child_by_field_name("name")?, src);
    let line = method.start_position().row + 1;
    let mut own_guards: Vec<String> = Vec::new();
    let mut mappings: Vec<String> = Vec::new();
    for dec in decorators {
        let Some((dname, call)) = js_decorator_parts(*dec, src) else {
            continue;
        };
        match dname.as_str() {
            "Get" | "Post" | "Put" | "Delete" | "Patch" | "Head" | "Options" | "All" => mappings
                .push(
                    call.and_then(|c| js_decorator_string(c, src))
                        .unwrap_or_default(),
                ),
            "UseGuards" => own_guards.extend(call.into_iter().flat_map(|c| js_guard_args(c, src))),
            _ => {}
        }
    }
    push_auth_guard(
        guards,
        &name,
        line,
        "nestjs",
        &own_guards,
        class_guards,
        at_name,
    );
    for suffix in mappings {
        let pattern = js_join_route(prefix, &suffix);
        push_route(
            markers,
            routes,
            &name,
            line,
            &pattern,
            route_params(&COLON_PARAM, &pattern),
            "nestjs",
            "nestjs_route",
        );
    }
    for param in named_kids(method.child_by_field_name("parameters")?) {
        js_nest_parameter(param, src, &name, markers);
    }
    Some(())
}

/// `@Query() q` / `@Body() dto` / `@Param('id') id` — Nest's parameter
/// binding decorators, the JavaScript counterpart of Spring's
/// `@RequestParam` and ASP.NET's `[FromQuery]`. They are not a call
/// shape any rule can name, which is why they live here.
fn js_nest_parameter(
    param: Node,
    src: &[u8],
    method_name: &str,
    markers: &mut Vec<FrameworkMarkerFact>,
) -> Option<()> {
    let name = py_text(param.child_by_field_name("pattern")?, src);
    for dec in kids(param).filter(|c| c.kind() == "decorator") {
        let Some((dname, _call)) = js_decorator_parts(dec, src) else {
            continue;
        };
        if !matches!(
            dname.as_str(),
            "Query" | "Body" | "Param" | "Headers" | "Req" | "Request" | "Session"
        ) {
            continue;
        }
        markers.push(FrameworkMarkerFact {
            function_qnode: method_name.to_string(),
            line: param.start_position().row + 1,
            marker_type: "nestjs_annotation".to_string(),
            marker_name: format!("@{dname}"),
            parameter_names: vec![name.clone()],
            framework: "nestjs".to_string(),
            confidence: "high".to_string(),
        });
    }
    Some(())
}

// ── Next.js file-based routes ────────────────────────────────────────────

/// `[id]` / `[...slug]` — Next.js dynamic segments.
static BRACKET_PARAM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[\.{0,3}(\w+)\]").unwrap());

/// `marker`'s byte offset in `rel`, but only as a whole path segment, so
/// `myapp/api/` does not read as `app/api/`.
fn path_segment_at(rel: &str, marker: &str) -> Option<usize> {
    if rel.starts_with(marker) {
        return Some(0);
    }
    rel.find(&format!("/{marker}")).map(|i| i + 1)
}

/// `(url, is_app_router)` for a Next.js API route file:
/// `pages/api/users/[id].ts` -> `/api/users/[id]`, and
/// `app/api/users/[id]/route.ts` -> the same. `None` for anything else.
fn next_route_path(rel: &str) -> Option<(String, bool)> {
    let (start, app_router) = match (
        path_segment_at(rel, "pages/api/"),
        path_segment_at(rel, "app/api/"),
    ) {
        (Some(i), _) => (i + "pages/".len(), false),
        (None, Some(i)) => (i + "app/".len(), true),
        (None, None) => return None,
    };
    let tail = &rel[start..];
    let stem = tail.rsplit_once('.').map(|(a, _)| a).unwrap_or(tail);
    let stem = if app_router {
        stem.strip_suffix("/route")?
    } else {
        stem.strip_suffix("/index").unwrap_or(stem)
    };
    Some((format!("/{stem}"), app_router))
}

/// Every `export_statement` under `node`.
fn js_exports<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
    if node.kind() == "export_statement" {
        out.push(node);
    }
    for c in kids(node) {
        js_exports(c, out);
    }
}

fn js_next_visit(
    node: Node,
    rel: &str,
    src: &[u8],
    markers: &mut Vec<FrameworkMarkerFact>,
    routes: &mut Vec<RouteTaintFact>,
) {
    let Some((pattern, app_router)) = next_route_path(rel) else {
        return;
    };
    let mut exports = Vec::new();
    js_exports(node, &mut exports);
    let params = route_params(&BRACKET_PARAM, &pattern);
    for ex in exports {
        let Some(decl) = ex
            .child_by_field_name("declaration")
            .filter(|d| d.kind() == "function_declaration")
        else {
            continue;
        };
        let Some(name) = decl.child_by_field_name("name").map(|n| py_text(n, src)) else {
            continue;
        };
        // App Router exports one function per HTTP verb; the Pages
        // Router exports a single default handler.
        let is_route = if app_router {
            matches!(
                name.as_str(),
                "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS"
            )
        } else {
            kids(ex).any(|c| c.kind() == "default")
        };
        if !is_route {
            continue;
        }
        push_route(
            markers,
            routes,
            &name,
            decl.start_position().row + 1,
            &pattern,
            params.clone(),
            "nextjs",
            "nextjs_route",
        );
    }
}

// ── response dataflow ────────────────────────────────────────────────────

fn py_response_visit(
    node: Node,
    src: &[u8],
    ranges: &[(usize, usize, String)],
    out: &mut Vec<ResponseDataflowFact>,
) {
    if node.kind() == "call" {
        if let Some(fn_node) = node.child_by_field_name("function") {
            if fn_node.kind() == "identifier" {
                let fname = py_text(fn_node, src);
                if matches!(fname.as_str(), "JsonResponse" | "HttpResponse" | "render") {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        for (i, arg) in named_kids(args).enumerate() {
                            // `render(request, template, context=...)` —
                            // the third argument carries the data.
                            if fname == "render" && i == 2 {
                                if arg.kind() == "keyword_argument" {
                                    if let Some(val) = arg.child_by_field_name("value") {
                                        out.push(ResponseDataflowFact {
                                            function_qnode: scope_for(node.start_byte(), ranges),
                                            line: node.start_position().row + 1,
                                            from_symbol: py_text(val, src),
                                            to_sink: "render".to_string(),
                                            framework: "django".to_string(),
                                            response_type: "html".to_string(),
                                        });
                                    }
                                }
                            } else if i == 0 && fname != "render" {
                                out.push(ResponseDataflowFact {
                                    function_qnode: scope_for(node.start_byte(), ranges),
                                    line: node.start_position().row + 1,
                                    from_symbol: py_text(arg, src),
                                    to_sink: fname.clone(),
                                    framework: "django".to_string(),
                                    response_type: if fname == "JsonResponse" {
                                        "json".to_string()
                                    } else {
                                        "html".to_string()
                                    },
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    for c in kids(node) {
        py_response_visit(c, src, ranges, out);
    }
}

fn java_response_visit(
    node: Node,
    src: &[u8],
    ranges: &[(usize, usize, String)],
    out: &mut Vec<ResponseDataflowFact>,
) {
    if node.kind() == "object_creation_expression" {
        if let Some(type_node) = node.child_by_field_name("type") {
            if py_text(type_node, src).contains("ResponseEntity") {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if let Some(first) = named_kids(args).next() {
                        out.push(ResponseDataflowFact {
                            function_qnode: scope_for(node.start_byte(), ranges),
                            line: node.start_position().row + 1,
                            from_symbol: py_text(first, src),
                            to_sink: "ResponseEntity".to_string(),
                            framework: "spring".to_string(),
                            response_type: "json".to_string(),
                        });
                    }
                }
            }
        }
    }
    if node.kind() == "method_invocation" {
        if let Some(name_node) = node.child_by_field_name("name") {
            if py_text(name_node, src) == "addAttribute" {
                if let Some(args) = node.child_by_field_name("arguments") {
                    let children: Vec<Node> = named_kids(args).collect();
                    if children.len() >= 2 {
                        out.push(ResponseDataflowFact {
                            function_qnode: scope_for(node.start_byte(), ranges),
                            line: node.start_position().row + 1,
                            from_symbol: py_text(children[1], src),
                            to_sink: "addAttribute".to_string(),
                            framework: "spring".to_string(),
                            response_type: "html".to_string(),
                        });
                    }
                }
            }
        }
    }
    for c in kids(node) {
        java_response_visit(c, src, ranges, out);
    }
}

fn cs_response_visit(
    node: Node,
    src: &[u8],
    ranges: &[(usize, usize, String)],
    out: &mut Vec<ResponseDataflowFact>,
) {
    if node.kind() == "invocation_expression" {
        if let Some(fn_node) = node.child_by_field_name("function") {
            if fn_node.kind() == "identifier" {
                let method = py_text(fn_node, src);
                if matches!(method.as_str(), "Ok" | "BadRequest" | "Created" | "Json") {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        for (i, arg) in named_kids(args).enumerate() {
                            // `Created(location, resource)` — the first
                            // argument is the location header, not data.
                            if method == "Created" && i == 0 {
                                continue;
                            }
                            out.push(ResponseDataflowFact {
                                function_qnode: scope_for(node.start_byte(), ranges),
                                line: node.start_position().row + 1,
                                from_symbol: py_text(arg, src),
                                to_sink: method.clone(),
                                framework: "aspnet".to_string(),
                                response_type: "json".to_string(),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }
    for c in kids(node) {
        cs_response_visit(c, src, ranges, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Parser, Tree};

    /// Parse `src` with the grammar `scan_file` itself would pick for a
    /// file at `rel` labeled `language` — one grammar table, not a
    /// test-only copy that could drift from it.
    fn parse(language: &str, rel: &str, src: &str) -> Tree {
        let lang =
            crate::scan::ts_language(&crate::scan::normalize_lang_for_grammar(rel, language))
                .unwrap();
        let mut p = Parser::new();
        p.set_language(&lang).unwrap();
        p.parse(src, None).unwrap()
    }

    fn facts(language: &str, src: &str) -> (Vec<FrameworkMarkerFact>, Vec<RouteTaintFact>) {
        let (markers, routes, _guards) = all_facts(language, src);
        (markers, routes)
    }

    #[allow(clippy::type_complexity)]
    fn all_facts(
        language: &str,
        src: &str,
    ) -> (
        Vec<FrameworkMarkerFact>,
        Vec<RouteTaintFact>,
        Vec<AuthGuardFact>,
    ) {
        facts_at(language, "app.src", src)
    }

    /// [`all_facts`] with the repo-relative path spelled out, for the
    /// Next.js routes that read it.
    #[allow(clippy::type_complexity)]
    fn facts_at(
        language: &str,
        rel: &str,
        src: &str,
    ) -> (
        Vec<FrameworkMarkerFact>,
        Vec<RouteTaintFact>,
        Vec<AuthGuardFact>,
    ) {
        let tree = parse(language, rel, src);
        extract_framework_facts(language, rel, src.as_bytes(), tree.root_node())
    }

    /// `(function, requires_auth)` per recorded guard.
    fn guards(language: &str, src: &str) -> Vec<(String, bool)> {
        all_facts(language, src)
            .2
            .into_iter()
            .map(|g| (g.function_qnode, g.requires_auth))
            .collect()
    }

    fn responses(language: &str, src: &str) -> Vec<ResponseDataflowFact> {
        let tree = parse(language, "app.src", src);
        extract_response_dataflow(language, src.as_bytes(), tree.root_node())
    }

    // ── helpers ─────────────────────────────────────────────────────

    #[test]
    fn strip_quotes_removes_both_quote_styles() {
        assert_eq!(strip_quotes("\"/a\""), "/a");
        assert_eq!(strip_quotes("'/b'"), "/b");
    }

    #[test]
    fn route_params_dedupes_repeated_captures() {
        assert_eq!(
            route_params(&BRACE_PARAM, "/a/{id}/b/{id}/c/{name}"),
            vec!["id".to_string(), "name".to_string()]
        );
    }

    // ── Python ──────────────────────────────────────────────────────

    #[test]
    fn python_bare_request_parameter_is_a_django_view() {
        let (markers, routes) = facts("python", "def profile(request):\n    pass\n");
        assert!(routes.is_empty());
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].marker_type, "django_view");
        assert_eq!(markers[0].framework, "django");
        assert_eq!(markers[0].function_qnode, "profile");
        assert_eq!(markers[0].line, 1);
    }

    #[test]
    fn python_typed_and_defaulted_request_parameters_are_django_views_too() {
        let (typed, _) = facts("python", "def a(request: HttpRequest):\n    pass\n");
        assert_eq!(typed.len(), 1);
        let (defaulted, _) = facts("python", "def b(request=None):\n    pass\n");
        assert_eq!(defaulted.len(), 1);
        let (typed_default, _) = facts("python", "def c(request: Any = None):\n    pass\n");
        assert_eq!(typed_default.len(), 1);
    }

    #[test]
    fn python_non_identifier_parameter_forms_are_skipped() {
        let (markers, _) = facts("python", "def a(*args, **kwargs):\n    pass\n");
        assert!(markers.is_empty());
    }

    #[test]
    fn python_request_dict_access_is_its_own_marker() {
        let (markers, _) = facts(
            "python",
            "def v(req):\n    x = request.GET\n    y = request.other\n",
        );
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].marker_type, "django_dict_access");
        assert_eq!(markers[0].marker_name, "request.GET");
        assert_eq!(markers[0].parameter_names, vec!["result".to_string()]);
        assert_eq!(markers[0].line, 2);
    }

    #[test]
    fn python_attribute_on_another_object_is_not_a_request_access() {
        let (markers, _) = facts("python", "def v(req):\n    x = other.GET\n");
        assert!(markers.is_empty());
    }

    #[test]
    fn python_flask_route_decorator_emits_a_route_and_a_marker() {
        let (markers, routes) = facts(
            "python",
            "@app.route(\"/u/<int:uid>\")\ndef show(uid):\n    pass\n",
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].parameter_name, "uid");
        assert_eq!(routes[0].route_pattern, "/u/<int:uid>");
        assert_eq!(routes[0].framework, "flask");
        assert!(routes[0].is_tainted);
        assert_eq!(routes[0].function_qnode, "show");
        assert_eq!(markers[0].marker_type, "flask_route");
        // The route line is the decorated function's, not the decorator's.
        assert_eq!(markers[0].line, 2);
    }

    #[test]
    fn python_fastapi_verb_decorator_reads_brace_parameters() {
        let (markers, routes) = facts(
            "python",
            "@router.get(\"/f/{item_id}\")\nasync def f(item_id):\n    pass\n",
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].parameter_name, "item_id");
        assert_eq!(markers[0].framework, "fastapi");
    }

    #[test]
    fn python_route_with_no_path_parameters_still_marks_the_handler() {
        let (markers, routes) = facts("python", "@app.route(\"/health\")\ndef h():\n    pass\n");
        assert!(routes.is_empty());
        assert_eq!(markers.len(), 1);
        assert!(markers[0].parameter_names.is_empty());
    }

    #[test]
    fn python_unrelated_decorators_are_ignored() {
        // Not a route verb, not a call, not an attribute, and a
        // decorated class rather than a function.
        let src = "@lru_cache()\n@staticmethod\n@a.b.route\ndef f():\n    pass\n\n@app.route(\"/x\")\nclass C:\n    pass\n";
        let (markers, routes) = facts("python", src);
        assert!(markers.is_empty());
        assert!(routes.is_empty());
    }

    #[test]
    fn python_decorator_naming_an_unrecognized_verb_is_ignored() {
        let (markers, _) = facts("python", "@app.middleware(\"/x\")\ndef f():\n    pass\n");
        assert!(markers.is_empty());
    }

    #[test]
    fn python_route_decorator_without_a_string_argument_is_skipped() {
        let (markers, _) = facts("python", "@app.route(path)\ndef f():\n    pass\n");
        assert!(markers.is_empty());
    }

    #[test]
    fn python_route_decorator_with_no_receiver_identifier_is_skipped() {
        // `(lambda: x)().route(...)` walks to no leftmost identifier.
        let (markers, _) = facts("python", "@(1).route(\"/x\")\ndef f():\n    pass\n");
        assert!(markers.is_empty());
    }

    // ── Java ────────────────────────────────────────────────────────

    #[test]
    fn java_spring_mapping_emits_route_facts_per_path_parameter() {
        let src = "class C {\n  @GetMapping(\"/u/{id}/p/{pid}\")\n  public String get() { return \"\"; }\n}\n";
        let (markers, routes) = facts("java", src);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].parameter_name, "id");
        assert_eq!(routes[1].parameter_name, "pid");
        assert_eq!(routes[0].framework, "spring");
        assert_eq!(markers[0].marker_type, "spring_route");
        assert_eq!(markers[0].function_qnode, "get");
    }

    #[test]
    fn java_jaxrs_path_and_verb_annotations_are_routes() {
        let src =
            "class C {\n  @Path(\"/p/{id}\")\n  @GET\n  public String r() { return \"\"; }\n}\n";
        let (markers, routes) = facts("java", src);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].framework, "jaxrs");
        // `@Path` carries a template, `@GET` carries none — both mark.
        assert_eq!(markers.len(), 2);
        assert_eq!(markers[1].marker_name, "");
    }

    #[test]
    fn java_parameter_annotations_and_servlet_types_are_markers() {
        let src = "class C {\n  public String h(@RequestParam String q, @QueryParam(\"x\") String x, HttpServletRequest req, @Other String o) { return q; }\n}\n";
        let (markers, routes) = facts("java", src);
        assert!(routes.is_empty());
        assert_eq!(markers.len(), 3);
        assert_eq!(markers[0].marker_name, "@RequestParam");
        assert_eq!(markers[0].framework, "spring");
        assert_eq!(markers[1].marker_name, "@QueryParam");
        assert_eq!(markers[1].framework, "jaxrs");
        assert_eq!(markers[2].marker_type, "spring_implicit");
        assert_eq!(markers[2].confidence, "medium");
        assert_eq!(markers[2].parameter_names, vec!["req".to_string()]);
    }

    #[test]
    fn java_unrecognized_method_annotations_are_ignored() {
        let src = "class C {\n  @Override\n  public String h() { return \"\"; }\n}\n";
        let (markers, routes) = facts("java", src);
        assert!(markers.is_empty());
        assert!(routes.is_empty());
    }

    // ── C# ──────────────────────────────────────────────────────────

    #[test]
    fn csharp_http_attribute_route_parameters_are_extracted() {
        let src = "class C {\n  [HttpGet(\"users/{id}\")]\n  public IActionResult G([FromQuery] string q, string plain) { return null; }\n}\n";
        let (markers, routes) = facts("csharp", src);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].parameter_name, "id");
        assert_eq!(routes[0].framework, "aspnet");
        assert_eq!(markers.len(), 2);
        assert_eq!(markers[0].marker_type, "aspnet_route");
        assert_eq!(markers[1].marker_name, "[FromQuery]");
        assert_eq!(markers[1].parameter_names, vec!["q".to_string()]);
    }

    #[test]
    fn csharp_route_attribute_without_parameters_still_marks_the_action() {
        let src = "class C {\n  [Route(\"api/[controller]\")]\n  [Ignored]\n  public IActionResult G() { return null; }\n}\n";
        let (markers, routes) = facts("csharp", src);
        assert!(routes.is_empty());
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].marker_name, "api/[controller]");
    }

    #[test]
    fn csharp_attribute_with_no_arguments_yields_an_empty_pattern() {
        let src = "class C {\n  [HttpGet]\n  public IActionResult G() { return null; }\n}\n";
        let (markers, _) = facts("csharp", src);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].marker_name, "");
    }

    #[test]
    fn csharp_attribute_whose_only_argument_is_not_a_string_yields_no_pattern() {
        let src = "class C {\n  [HttpGet(Name = nameof(G))]\n  public IActionResult G() { return null; }\n}\n";
        let (markers, _) = facts("csharp", src);
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].marker_name, "");
    }

    // ── JavaScript / TypeScript ─────────────────────────────────────

    #[test]
    fn csharp_parameter_attribute_that_is_not_a_binding_is_ignored() {
        let src = "class C {\n  public IActionResult G([Required] string q) { return null; }\n}\n";
        let (markers, _) = facts("csharp", src);
        assert!(markers.is_empty());
    }

    #[test]
    fn express_route_with_no_handler_argument_falls_back_to_the_enclosing_scope() {
        let (markers, _) = facts("javascript", "function m() { app.get('/x'); }\n");
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].function_qnode, "m");
    }

    #[test]
    fn express_route_with_an_inline_handler_falls_back_to_the_enclosing_scope() {
        let src =
            "function mount() {\n  app.get('/u/:id', (req, res) => res.send(req.params.id));\n}\n";
        let (markers, routes) = facts("javascript", src);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].parameter_name, "id");
        assert_eq!(routes[0].framework, "express");
        assert_eq!(markers[0].function_qnode, "mount");
    }

    // ── authentication guards ────────────────────────────────────────

    #[test]
    fn a_python_route_with_no_decorator_guard_records_nothing() {
        assert!(guards("python", "@app.route(\"/x\")\ndef show():\n    pass\n").is_empty());
    }

    #[test]
    fn a_python_login_required_decorator_is_an_auth_guard() {
        assert_eq!(
            guards(
                "python",
                "@app.route(\"/x\")\n@login_required\ndef show():\n    pass\n"
            ),
            vec![("show".to_string(), true)]
        );
    }

    #[test]
    fn a_python_auth_decorator_is_recognized_qualified_and_called() {
        // `@auth.login_required` (attribute) and `@jwt_required()`
        // (call) reach the same table as a bare identifier.
        assert_eq!(
            guards("python", "@auth.login_required\ndef a():\n    pass\n"),
            vec![("a".to_string(), true)]
        );
        assert_eq!(
            guards("python", "@jwt_required()\ndef b():\n    pass\n"),
            vec![("b".to_string(), true)]
        );
    }

    #[test]
    fn an_unrelated_python_decorator_is_not_an_auth_guard() {
        // A substring match on "auth" would catch this.
        assert!(guards("python", "@author_only\ndef a():\n    pass\n").is_empty());
    }

    #[test]
    fn a_java_class_level_preauthorize_guards_its_methods() {
        assert_eq!(
            guards(
                "java",
                "@PreAuthorize(\"hasRole('ADMIN')\")\nclass C {\n  @GetMapping(\"/x\")\n  void show() {}\n}\n"
            ),
            vec![("show".to_string(), true)]
        );
    }

    #[test]
    fn a_java_method_level_permitall_overrides_the_class_guard() {
        assert_eq!(
            guards(
                "java",
                "@RolesAllowed(\"ADMIN\")\nclass C {\n  @PermitAll\n  @GetMapping(\"/x\")\n  void show() {}\n}\n"
            ),
            vec![("show".to_string(), false)]
        );
    }

    #[test]
    fn a_csharp_controller_authorize_guards_its_actions_unless_allowanonymous() {
        assert_eq!(
            guards(
                "csharp",
                "[Authorize]\nclass C {\n  [HttpGet(\"/a\")]\n  void A() {}\n  [AllowAnonymous]\n  [HttpGet(\"/b\")]\n  void B() {}\n}\n"
            ),
            vec![("A".to_string(), true), ("B".to_string(), false)]
        );
    }

    #[test]
    fn express_middleware_before_the_handler_is_an_auth_guard() {
        assert_eq!(
            guards("javascript", "router.post(\"/x\", requireAuth, handleX);\n"),
            vec![("handleX".to_string(), true)]
        );
    }

    #[test]
    fn express_route_binds_the_last_callable_argument_not_the_first() {
        // Express is `(path, ...middleware, handler)`. Naming the route
        // after its first identifier attributes it to the middleware.
        let (markers, _) = facts("javascript", "router.post(\"/x\", requireAuth, handleX);\n");
        assert_eq!(markers[0].function_qnode, "handleX");
    }

    #[test]
    fn express_route_binds_a_named_handler_argument() {
        let (markers, _) = facts("javascript", "router.post(\"/x\", handleX);\n");
        assert_eq!(markers[0].function_qnode, "handleX");
    }

    #[test]
    fn express_route_binds_a_named_function_expression() {
        let (markers, _) = facts(
            "javascript",
            "app.put(\"/x\", function named(req, res) {});\n",
        );
        assert_eq!(markers[0].function_qnode, "named");
    }

    #[test]
    fn express_anonymous_handler_at_module_scope_is_dropped() {
        // No enclosing named function, so there is no qnode to hang an
        // entry point on.
        let (markers, _) = facts("javascript", "app.use(\"/x\", function (req, res) {});\n");
        assert!(markers.is_empty());
    }

    #[test]
    fn express_route_with_no_string_path_is_skipped() {
        let (markers, _) = facts("javascript", "function m() { app.get(routePath, h); }\n");
        assert!(markers.is_empty());
    }

    #[test]
    fn a_map_get_is_not_an_express_route() {
        let (markers, _) = facts("javascript", "function m() { cache.get(\"k\"); }\n");
        assert!(markers.is_empty());
    }

    #[test]
    fn typescript_uses_the_same_express_detection() {
        let (markers, routes) = facts("typescript", "function m() { app.get('/a/:b', h); }\n");
        assert_eq!(routes.len(), 1);
        assert_eq!(markers[0].framework, "express");
    }

    #[test]
    fn a_language_with_no_framework_extractor_yields_nothing() {
        let tree = parse("python", "a.py", "def f():\n    pass\n");
        let (markers, routes, _guards) =
            extract_framework_facts("ruby", "a.rb", b"", tree.root_node());
        assert!(markers.is_empty());
        assert!(routes.is_empty());
    }

    // ── Go ──────────────────────────────────────────────────────────

    /// `(framework, pattern, handler)` per recognized Go route.
    fn go_routes(src: &str) -> Vec<(String, String, String)> {
        facts("go", src)
            .0
            .into_iter()
            .map(|m| (m.framework, m.marker_name, m.function_qnode))
            .collect()
    }

    fn go_body(stmts: &str) -> String {
        format!("package main\nfunc mount() {{\n{stmts}}}\n")
    }

    #[test]
    fn go_net_http_gin_echo_chi_gorilla_and_fiber_routes_are_all_recognized() {
        let (markers, routes) = facts(
            "go",
            &go_body(
                "\thttp.HandleFunc(\"/p\", plainHandler)\n\
                 \tmux.Handle(\"/s\", muxHandler)\n\
                 \tr.GET(\"/gin/:id\", ginHandler)\n\
                 \te.GET(\"/echo/:name\", echoHandler)\n\
                 \trt.Get(\"/chi/{cid}\", chiHandler)\n\
                 \tm.HandleFunc(\"/gor/{gid}\", gorHandler).Methods(\"GET\")\n\
                 \tapp.Get(\"/fiber/:fid\", fiberHandler)\n",
            ),
        );
        let seen: Vec<(&str, &str, &str)> = markers
            .iter()
            .map(|m| {
                (
                    m.framework.as_str(),
                    m.marker_name.as_str(),
                    m.function_qnode.as_str(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                ("nethttp", "/p", "plainHandler"),
                ("nethttp", "/s", "muxHandler"),
                ("gin", "/gin/:id", "ginHandler"),
                ("gin", "/echo/:name", "echoHandler"),
                ("chi", "/chi/{cid}", "chiHandler"),
                ("nethttp", "/gor/{gid}", "gorHandler"),
                ("chi", "/fiber/:fid", "fiberHandler"),
            ]
        );
        // Both templating styles read out of one pass.
        let params: Vec<&str> = routes.iter().map(|r| r.parameter_name.as_str()).collect();
        assert_eq!(params, vec!["id", "name", "cid", "gid", "fid"]);
        assert!(routes.iter().all(|r| r.is_tainted));
    }

    #[test]
    fn a_go_route_group_prefixes_the_routes_registered_on_it() {
        let (markers, _) = facts(
            "go",
            &go_body(
                "\tapi := r.Group(\"/api\")\n\
                 \tv1 := api.Group(\"/v1\")\n\
                 \tv1.POST(\"/users/:uid\", createUser)\n",
            ),
        );
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].marker_name, "/api/v1/users/:uid");
        assert_eq!(markers[0].parameter_names, vec!["uid".to_string()]);
    }

    #[test]
    fn a_go_group_binding_that_is_not_one_is_ignored() {
        // Not a `Group` call, no string argument, and a non-identifier
        // target — each falls out of `go_record_group` at a different
        // point, and none may leave a stray prefix behind.
        let (markers, _) = facts(
            "go",
            &go_body(
                "\ta := r.Other(\"/x\")\n\
                 \tb := r.Group(prefix)\n\
                 \tc, d := r.Group(\"/y\")\n\
                 \te := plain()\n\
                 \ta.GET(\"/one\", h1)\n\
                 \tb.GET(\"/two\", h2)\n",
            ),
        );
        let names: Vec<&str> = markers.iter().map(|m| m.marker_name.as_str()).collect();
        assert_eq!(names, vec!["/one", "/two"]);
        // `c, d := …` binds `c`, which registers nothing here.
        assert_eq!(markers.len(), 2);
    }

    #[test]
    fn a_go_route_call_that_is_not_one_is_skipped() {
        // A non-selector callee, an unrecognized verb, a `Get` whose
        // first argument is not a path, and a bare-call verb — none is
        // a route.
        let (markers, _) = facts(
            "go",
            &go_body(
                "\tplain(\"/x\", h)\n\
                 \tr.Middleware(\"/x\", h)\n\
                 \tcache.Get(\"key\")\n\
                 \tw.Header().Set(\"X\", v)\n\
                 \tr.GET(path, h)\n",
            ),
        );
        assert!(markers.is_empty());
    }

    #[test]
    fn a_go_inline_handler_falls_back_to_the_enclosing_function() {
        assert_eq!(
            go_routes(&go_body(
                "\thttp.HandleFunc(\"/p\", func(w http.ResponseWriter, r *http.Request) {})\n"
            )),
            vec![("nethttp".to_string(), "/p".to_string(), "mount".to_string())]
        );
    }

    #[test]
    fn a_go_route_at_module_scope_with_no_handler_is_dropped() {
        // No enclosing named function and no handler argument, so there
        // is no qnode to hang an entry point on.
        let (markers, _) = facts("go", "package main\nvar _ = http.HandleFunc(\"/p\")\n");
        assert!(markers.is_empty());
    }

    #[test]
    fn go_route_middleware_named_for_auth_is_a_guard() {
        assert_eq!(
            guards("go", &go_body("\tr.GET(\"/x\", JWTMiddleware, show)\n")),
            vec![("show".to_string(), true)]
        );
        assert!(guards("go", &go_body("\tr.GET(\"/x\", logging, show)\n")).is_empty());
    }

    #[test]
    fn a_go_handler_imported_from_another_package_is_named_by_its_own_name() {
        // `r.GET("/x", handlers.SearchReports)` — the gin/echo/chi
        // idiom. Taking the enclosing scope instead names every route
        // in the table after `mount`.
        assert_eq!(
            go_routes(&go_body("\tr.GET(\"/x\", handlers.SearchReports)\n")),
            vec![(
                "gin".to_string(),
                "/x".to_string(),
                "SearchReports".to_string()
            )]
        );
    }

    #[test]
    fn a_go_handler_inside_a_wrapper_is_found_and_the_wrapper_is_the_guard() {
        let src = go_body(
            "\tmux.Handle(\"/probe\", requireServiceToken(http.HandlerFunc(probeHandler)))\n",
        );
        assert_eq!(
            go_routes(&src),
            vec![(
                "nethttp".to_string(),
                "/probe".to_string(),
                "probeHandler".to_string()
            )]
        );
        assert_eq!(guards("go", &src), vec![("probeHandler".to_string(), true)]);
    }

    #[test]
    fn go_group_middleware_guards_every_route_registered_on_the_group() {
        // Both spellings: middleware as a trailing `Group` argument,
        // and a separate `Use` on the group handle.
        let src = go_body(
            "\tadmin := r.Group(\"/admin\")\n\
             \tadmin.Use(RequireAdmin())\n\
             \tadmin.GET(\"/export\", exportReport)\n\
             \tops := r.Group(\"/ops\", authRequired)\n\
             \tops.GET(\"/run\", runJob)\n\
             \tr.GET(\"/open\", openPage)\n",
        );
        let mut got = guards("go", &src);
        got.sort();
        assert_eq!(
            got,
            vec![
                ("exportReport".to_string(), true),
                ("runJob".to_string(), true)
            ]
        );
        let names: Vec<String> = go_routes(&src).into_iter().map(|(_, p, _)| p).collect();
        assert_eq!(names, vec!["/admin/export", "/ops/run", "/open"]);
    }

    #[test]
    fn a_go_router_mounted_inside_another_is_not_a_handler() {
        // `mux.Handle("/", r)` mounts a router. Naming an entry point
        // after `r` invents a function that does not exist.
        let src = go_body("\tr.Use(gin.Logger())\n\tmux.Handle(\"/\", r)\n");
        assert!(go_routes(&src).is_empty());
    }

    #[test]
    fn a_go_use_that_is_not_router_middleware_registers_nothing() {
        // Not a `Use` call, and a `Use` with no leftmost identifier to
        // hang the handle on.
        let src = go_body("\tr.Other(mw)\n\t(1).Use(mw)\n\tr.GET(\"/x\", show)\n");
        assert!(guards("go", &src).is_empty());
        assert_eq!(go_routes(&src).len(), 1);
    }

    // ── guard-name shapes ───────────────────────────────────────────

    #[test]
    fn a_require_prefixed_middleware_over_an_auth_noun_is_a_guard() {
        // The names no curated list will ever have: every project
        // spells its own router middleware differently.
        for name in [
            "requireServiceToken",
            "ensureSession",
            "verifyJWT",
            "withAuth",
            "mustHaveRole",
            "checkUserIdentity",
        ] {
            assert_eq!(auth_guard_kind(name), Some(true), "{name}");
        }
    }

    #[test]
    fn a_shaped_name_over_a_non_auth_noun_is_not_a_guard() {
        // Both halves stay curated: a bare substring match on "auth"
        // would catch `authorId`, and a bare prefix match would catch
        // `requireFields`.
        for name in ["requireFields", "ensureCapacity", "authorId", "withTimeout"] {
            assert_eq!(auth_guard_kind(name), None, "{name}");
        }
    }

    // ── Koa / Fastify / hapi ────────────────────────────────────────

    #[test]
    fn a_koa_router_registration_is_a_route() {
        let (markers, routes) = facts("javascript", "router.get('/u/:id', showUser);\n");
        assert_eq!(markers[0].function_qnode, "showUser");
        assert_eq!(routes[0].parameter_name, "id");
    }

    #[test]
    fn a_fastify_route_reads_its_handler_past_an_options_object() {
        let (markers, _, guards) = all_facts(
            "javascript",
            "fastify.get('/f/:id', { preHandler: verifyToken }, fastifyHandler);\n",
        );
        assert_eq!(markers[0].framework, "fastify");
        assert_eq!(markers[0].function_qnode, "fastifyHandler");
        assert_eq!(guards.len(), 1);
        assert!(guards[0].requires_auth);
    }

    #[test]
    fn a_fastify_hook_array_and_an_unhooked_route_are_both_read() {
        let guarded = guards(
            "javascript",
            "fastify.post('/a', { onRequest: [requireAuth] }, createA);\n",
        );
        assert_eq!(guarded, vec![("createA".to_string(), true)]);
        assert!(guards("javascript", "fastify.post('/a', {}, createA);\n").is_empty());
    }

    #[test]
    fn a_passport_middleware_factory_is_an_auth_guard() {
        assert_eq!(
            guards(
                "javascript",
                "router.get('/x', passport.authenticate('jwt'), showX);\n"
            ),
            vec![("showX".to_string(), true)]
        );
    }

    #[test]
    fn a_hapi_server_route_descriptor_is_a_route() {
        let (markers, routes) = facts(
            "javascript",
            "server.route({ method: 'GET', path: '/u/{id}', handler: showUser });\n",
        );
        assert_eq!(markers[0].framework, "hapi");
        assert_eq!(markers[0].marker_name, "/u/{id}");
        assert_eq!(markers[0].function_qnode, "showUser");
        assert_eq!(routes[0].parameter_name, "id");
    }

    #[test]
    fn a_hapi_route_with_an_inline_handler_falls_back_to_the_enclosing_scope() {
        let (markers, _) = facts(
            "javascript",
            "function mount() {\n  server.route({ path: '/u', handler: (req, h) => 1 });\n}\n",
        );
        assert_eq!(markers[0].function_qnode, "mount");
    }

    #[test]
    fn a_hapi_route_missing_a_path_or_handler_is_skipped() {
        assert!(facts(
            "javascript",
            "server.route({ method: 'GET', handler: h });\nserver.route({ path: '/u' });\nserver.route(config);\n"
        )
        .0
        .is_empty());
    }

    #[test]
    fn a_hapi_style_route_at_module_scope_with_an_inline_handler_is_dropped() {
        assert!(facts(
            "javascript",
            "server.route({ path: '/u', handler: () => 1 });\n"
        )
        .0
        .is_empty());
    }

    // ── NestJS ──────────────────────────────────────────────────────

    #[test]
    fn a_nest_controller_joins_its_prefix_to_each_method_route() {
        let (markers, routes) = facts(
            "typescript",
            "@Controller('users')\n\
             export class UsersController {\n\
             \x20 @Get(':id')\n\
             \x20 findOne(@Param('id') id: string, @Query() q: any, plain: string) { return id; }\n\
             \x20 @Post()\n\
             \x20 create(@Body() dto: any) { return dto; }\n\
             }\n",
        );
        let routes_seen: Vec<(&str, &str)> = markers
            .iter()
            .filter(|m| m.marker_type == "nestjs_route")
            .map(|m| (m.marker_name.as_str(), m.function_qnode.as_str()))
            .collect();
        assert_eq!(
            routes_seen,
            vec![("/users/:id", "findOne"), ("/users", "create")]
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].parameter_name, "id");
        let params: Vec<(&str, &str)> = markers
            .iter()
            .filter(|m| m.marker_type == "nestjs_annotation")
            .map(|m| (m.marker_name.as_str(), m.parameter_names[0].as_str()))
            .collect();
        assert_eq!(
            params,
            vec![("@Param", "id"), ("@Query", "q"), ("@Body", "dto")]
        );
    }

    #[test]
    fn a_bare_nest_controller_and_an_empty_prefix_both_work() {
        let (markers, _) = facts(
            "typescript",
            "@Controller()\nclass Root {\n  @Get()\n  all() { return 1; }\n}\n",
        );
        assert_eq!(markers[0].marker_name, "/");
    }

    #[test]
    fn a_class_without_a_controller_decorator_registers_no_nest_route() {
        let (markers, _) = facts(
            "typescript",
            "@Injectable()\nclass Svc {\n  @Get(':id')\n  find(id: string) { return id; }\n}\n",
        );
        assert!(markers.is_empty());
    }

    #[test]
    fn nest_use_guards_at_class_and_method_level_are_auth_guards() {
        assert_eq!(
            guards(
                "typescript",
                "@Controller('a')\n@UseGuards(AuthGuard)\nclass A {\n  @Get()\n  one() {}\n}\n"
            ),
            vec![("one".to_string(), true)]
        );
        assert_eq!(
            guards(
                "typescript",
                "@Controller('a')\nclass A {\n  @UseGuards(AuthGuard)\n  @Get()\n  one() {}\n  @Get('two')\n  two() {}\n}\n"
            ),
            vec![("one".to_string(), true)]
        );
    }

    #[test]
    fn a_nest_decorator_that_is_neither_a_call_nor_a_name_is_ignored() {
        // `@(expr)` parses to a decorator whose inner node is neither an
        // identifier nor a call — at class level, at method level, and
        // on a parameter — and an unrecognized method or parameter
        // decorator marks nothing either.
        let (markers, _) = facts(
            "typescript",
            "@(mk())\n\
             @Controller('a')\n\
             class A {\n\
             \x20 @(mk())\n\
             \x20 @HttpCode(204)\n\
             \x20 @Get()\n\
             \x20 one(@Ignored() p: string, @(mk()) q: string) {}\n\
             }\n",
        );
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].marker_type, "nestjs_route");
    }

    #[test]
    fn a_nest_route_under_an_empty_controller_prefix_keeps_its_own_path() {
        let (markers, _) = facts(
            "typescript",
            "@Controller()\nclass A {\n  @Get('me')\n  me() {}\n}\n",
        );
        assert_eq!(markers[0].marker_name, "/me");
    }

    #[test]
    fn a_non_verb_method_on_a_route_handle_is_not_a_route() {
        assert!(facts("javascript", "app.listen(3000);\n").0.is_empty());
    }

    #[test]
    fn a_next_anonymous_default_export_names_no_handler() {
        assert!(facts_at(
            "javascript",
            "pages/api/x.js",
            "export default function (req, res) { return res; }\n",
        )
        .0
        .is_empty());
    }

    // ── Next.js ─────────────────────────────────────────────────────

    #[test]
    fn next_pages_api_default_export_is_a_route() {
        let (markers, routes, _g) = facts_at(
            "typescript",
            "src/pages/api/users/[id].ts",
            "export default function handler(req, res) { return res; }\n",
        );
        assert_eq!(markers.len(), 1);
        assert_eq!(markers[0].framework, "nextjs");
        assert_eq!(markers[0].marker_name, "/api/users/[id]");
        assert_eq!(markers[0].function_qnode, "handler");
        assert_eq!(routes[0].parameter_name, "id");
    }

    #[test]
    fn next_pages_api_index_collapses_to_its_directory() {
        let (markers, _, _g) = facts_at(
            "javascript",
            "pages/api/users/index.js",
            "export default function handler(req, res) { return res; }\n",
        );
        assert_eq!(markers[0].marker_name, "/api/users");
    }

    #[test]
    fn next_app_router_exports_one_route_per_verb() {
        let (markers, _, _g) = facts_at(
            "typescript",
            "app/api/items/[...slug]/route.ts",
            "export async function GET(request) { return request; }\n\
             export async function POST(request) { return request; }\n\
             export function helper(x) { return x; }\n",
        );
        let seen: Vec<(&str, &str)> = markers
            .iter()
            .map(|m| (m.marker_name.as_str(), m.function_qnode.as_str()))
            .collect();
        assert_eq!(
            seen,
            vec![
                ("/api/items/[...slug]", "GET"),
                ("/api/items/[...slug]", "POST"),
            ]
        );
    }

    #[test]
    fn a_non_default_pages_export_and_a_non_route_app_file_are_not_routes() {
        assert!(facts_at(
            "javascript",
            "pages/api/x.js",
            "export function named(req, res) { return res; }\nexport const k = 1;\n",
        )
        .0
        .is_empty());
        assert!(facts_at(
            "typescript",
            "app/api/x/page.ts",
            "export async function GET(r) { return r; }\n",
        )
        .0
        .is_empty());
    }

    #[test]
    fn a_file_outside_the_next_conventions_has_no_file_based_route() {
        assert!(facts_at(
            "javascript",
            "myapp/api/x.js",
            "export default function handler(req, res) { return res; }\n",
        )
        .0
        .is_empty());
        assert!(facts_at(
            "javascript",
            "lib/util.js",
            "export default function handler(req, res) { return res; }\n",
        )
        .0
        .is_empty());
    }

    // ── response dataflow ───────────────────────────────────────────

    #[test]
    fn python_response_helpers_are_tracked_with_their_body_type() {
        let src = "def v(request):\n    return JsonResponse(data)\n\ndef w(request):\n    return HttpResponse(body)\n\ndef x(request):\n    return render(request, \"t.html\", context=ctx)\n";
        let facts = responses("python", src);
        assert_eq!(facts.len(), 3);
        assert_eq!(facts[0].to_sink, "JsonResponse");
        assert_eq!(facts[0].response_type, "json");
        assert_eq!(facts[0].from_symbol, "data");
        assert_eq!(facts[0].function_qnode, "v");
        assert_eq!(facts[1].response_type, "html");
        assert_eq!(facts[2].to_sink, "render");
        assert_eq!(facts[2].from_symbol, "ctx");
    }

    #[test]
    fn python_render_without_a_keyword_context_yields_nothing() {
        let facts = responses(
            "python",
            "def v(r):\n    return render(r, \"t.html\", ctx)\n",
        );
        assert!(facts.is_empty());
    }

    #[test]
    fn python_response_call_with_no_arguments_yields_nothing() {
        let facts = responses("python", "def v(r):\n    return HttpResponse()\n");
        assert!(facts.is_empty());
    }

    #[test]
    fn python_non_response_calls_are_ignored() {
        let facts = responses(
            "python",
            "def v(r):\n    return other(x)\n    return o.m(y)\n",
        );
        assert!(facts.is_empty());
    }

    #[test]
    fn java_response_entity_and_add_attribute_are_tracked() {
        let src = "class C {\n  String m(Model model) {\n    model.addAttribute(\"k\", value);\n    return new ResponseEntity<String>(body, status);\n  }\n}\n";
        let facts = responses("java", src);
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[0].to_sink, "addAttribute");
        assert_eq!(facts[0].from_symbol, "value");
        assert_eq!(facts[0].response_type, "html");
        assert_eq!(facts[1].to_sink, "ResponseEntity");
        assert_eq!(facts[1].from_symbol, "body");
        assert_eq!(facts[1].function_qnode, "m");
    }

    #[test]
    fn java_response_shapes_that_carry_no_value_are_skipped() {
        let src = "class C {\n  String m(Model model) {\n    model.addAttribute(\"k\");\n    other.m();\n    return new ResponseEntity<String>();\n  }\n}\n";
        assert!(responses("java", src).is_empty());
    }

    #[test]
    fn java_object_creation_of_another_type_is_not_a_response() {
        assert!(responses("java", "class C { void m() { new Other(x); } }\n").is_empty());
    }

    #[test]
    fn csharp_action_results_are_tracked_and_created_skips_its_location() {
        let src = "class C {\n  IActionResult M() {\n    Ok(model);\n    Created(uri, resource);\n    Json(payload);\n    return BadRequest(err);\n  }\n}\n";
        let facts = responses("csharp", src);
        assert_eq!(facts.len(), 4);
        assert_eq!(facts[0].from_symbol, "model");
        assert_eq!(facts[1].to_sink, "Created");
        assert_eq!(facts[1].from_symbol, "resource");
        assert_eq!(facts[2].to_sink, "Json");
        assert_eq!(facts[3].to_sink, "BadRequest");
    }

    #[test]
    fn csharp_non_action_invocations_are_ignored() {
        let src = "class C {\n  void M() {\n    Other(x);\n    o.Ok(y);\n    Ok();\n  }\n}\n";
        assert!(responses("csharp", src).is_empty());
    }

    #[test]
    fn a_language_with_no_response_extractor_yields_nothing() {
        let tree = parse("javascript", "app.js", "app.get('/a', h);\n");
        assert!(extract_response_dataflow("javascript", b"", tree.root_node()).is_empty());
    }
}
