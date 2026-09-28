//! Per-file tree-sitter scanner. Ported from
//! `vvaharness/pipeline/stages/callgraph_engine/_scan.py`.
//!
//! **Scope: all six of `LANG_PLUGINS`' languages are wired** — Python,
//! JavaScript, TypeScript, Go, Java, and C# — plus four the Python
//! original has no plugin for at all (PHP, Ruby, Kotlin and Rust),
//! which carry function defs and call edges only so that the framework
//! entry points in [`crate::framework`] have a graph to sit on; see
//! `scan/lite.rs`. [`scan_file`]'s full
//! source/sink matching pipeline, the shared [`FileIndex`]/[`CallSite`]
//! types, and the language-plugin dispatch cover all six, ported
//! incrementally, matching this port's established "one language at a
//! time" pattern. JavaScript and TypeScript share one extractor
//! (`js_extract`) against three different tree-sitter grammars —
//! JavaScript, TypeScript, and TSX for `.tsx` files, picked by suffix in
//! [`normalize_lang_for_grammar`] — mirroring `LANG_PLUGINS`'s own
//! `"typescript": LangPlugin(... extract=_js_extract)` in the Python
//! original.
//!
//! **All six languages track `assigns`/`returns`/`call_args` and
//! `FuncDef::params`.** `_js_extract`/`_go_extract` return empty lists
//! for all three upstream (verified by reading both directly), which
//! left JavaScript, TypeScript and Go with no intra-procedural taint
//! plane at all — see the divergence notes above `js_leftmost_identifier`
//! and `go_leftmost_identifier`. Java additionally does
//! declared/narrowed-type resolution (`java_resolve_type`/`local_types`)
//! that C# never attempts — see the comment above `cs_leftmost_identifier`
//! for why.
//!
//! [`scan_file`] additionally drives four secondary tree walks, exactly
//! as `_scan.py::scan_file` (L2813-2837) does, populating the rest of
//! [`FileIndex`]: field/container facts ([`crate::facts`], Python/Java/C#
//! only), reflection facts ([`crate::reflection`], same three), and
//! framework markers/route facts plus response dataflow
//! ([`crate::framework`], those three plus JavaScript/TypeScript and Go).
//!
//! **Not carried over: `FileIndex.cfgs`.** CFG construction is
//! dead/unused code in the Python original — its own `scan_file` calls
//! `_build_cfg_for_function` with a `None` node on every function and
//! that helper returns `None` for a `None` node, so `FileIndex.cfgs` is
//! always empty there too. A permanently-empty field is not worth
//! carrying; nothing downstream can read anything out of it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use tree_sitter::{Node, Parser, Tree};

use crate::rules::MatchSpec;

// Function/call extraction for the four languages wired for their
// framework entry points only — see `scan/lite.rs`.
mod lite;

// ── record types ─────────────────────────────────────────────────────────

/// A call site tree-sitter observed that matched a source or sink
/// [`MatchSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallSite {
    /// Repo-relative path.
    pub file: String,
    /// 1-based.
    pub line: usize,
    /// Leftmost identifier of the call expression.
    pub receiver: String,
    /// Attribute name (or bare function name).
    pub method: String,
    /// Nearest enclosing function name (`""` = module scope).
    pub containing_fn: String,
    /// ~120 chars.
    pub snippet: String,
    /// [`MatchSpec::rule_id`].
    pub matched_rule: String,
    /// From [`MatchSpec::cwe`].
    pub cwe: String,
    /// `"source"` | `"sink"`.
    pub role: String,
    /// `ep_kind` / `sink_kind`.
    pub kind: String,
    pub semantic_family: String,
    pub owasp_top10_2025: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FuncDef {
    /// Bare function name (no class scope for MVP).
    pub name: String,
    /// 1-based.
    pub start_line: usize,
    pub end_line: usize,
    /// Enclosing class name for methods.
    pub class_name: String,
    /// Parameter names in the slot order a caller counts them — a Python
    /// method's leading `self`/`cls` is dropped because `obj.m(x)` passes
    /// `x` in slot 0. Lets the evidence walk turn "parameter 1 is
    /// tainted" into "`c` is tainted" inside the callee. Empty for
    /// hand-built fixtures, where the walk falls back to the positional
    /// coincidence upstream relied on.
    pub params: Vec<String>,
}

/// A call site observed by tree-sitter, regardless of rule matches.
///
/// Used by LLM annotator mode to derive source/sink specs from actual
/// repository call fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObservedCall {
    pub file: String,
    pub language: String,
    pub line: usize,
    pub receiver: String,
    pub resolved_receiver: String,
    pub method: String,
    pub containing_fn: String,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VarAssignFact {
    pub function_qnode: String,
    pub line: usize,
    pub dst_symbol: String,
    pub src_symbol: Option<String>,
    pub src_call: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReturnFact {
    pub function_qnode: String,
    pub line: usize,
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallArgFact {
    pub function_qnode: String,
    pub line: usize,
    pub callee_name: String,
    pub receiver: String,
    pub arg_symbols: Vec<String>,
    /// The argument slot each `arg_symbols` entry came from, parallel to
    /// it. `f("-v", x)` reports `["x"]` / `[1]`: a literal-only argument
    /// occupies a slot without contributing a symbol, and a composed one
    /// (`"a" + b + c`) contributes several to the same slot, so a symbol's
    /// index in the flat list is not its slot. Empty means "identity" —
    /// the pre-2026-09-07 shape hand-built fixtures still use.
    pub arg_slots: Vec<usize>,
    pub target_symbol: Option<String>,
}

/// `receiver.field = src_symbol`. Ported from
/// `_scan.py::FieldWriteFact` (L137-143).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FieldWriteFact {
    pub function_qnode: String,
    pub line: usize,
    /// `"self"`, `"this"`, or a variable name.
    pub receiver: String,
    /// Attribute/property/field name.
    pub field: String,
    /// RHS identifier, when the assignment is a simple one.
    pub src_symbol: Option<String>,
}

/// `dst_symbol = receiver.field`. Ported from
/// `_scan.py::FieldReadFact` (L146-152).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FieldReadFact {
    pub function_qnode: String,
    pub line: usize,
    pub receiver: String,
    pub field: String,
    /// LHS identifier, when the read is assigned.
    pub dst_symbol: Option<String>,
}

/// `container[k] = element` / `container.append(element)`. Ported from
/// `_scan.py::ContainerWriteFact` (L155-160).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerWriteFact {
    pub function_qnode: String,
    pub line: usize,
    /// The list/dict/array variable.
    pub container_symbol: String,
    /// The value being written.
    pub element_symbol: Option<String>,
}

/// A reflective/dynamic-dispatch call site. Ported from
/// `models.py::ReflectionFact` (L510-537). `call_type` is one of
/// `getmethod` | `invoke` | `getattr` | `construct` | `delegate` and
/// `language` one of `python` | `java` | `csharp`; both stay plain
/// `String`s to match this crate's existing `CallSite::kind`/`role`
/// convention rather than introducing enums with a single producer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReflectionFact {
    pub function_qnode: String,
    pub line: usize,
    pub call_type: String,
    /// Symbols passed to `getMethod`/`getattr`/… — a string literal's
    /// contents, or an identifier's name.
    pub target_symbols: Vec<String>,
    /// Object the reflective call is made on.
    pub receiver: String,
    pub language: String,
}

/// A framework annotation/decorator/implicit-type marker naming
/// parameters a web framework binds from user input. Ported from
/// `models.py::FrameworkMarkerFact` (L563-580).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FrameworkMarkerFact {
    pub function_qnode: String,
    pub line: usize,
    /// `spring_annotation` | `django_view` | `aspnet_annotation` |
    /// `spring_implicit` | `django_dict_access` | `aspnet_implicit` |
    /// `flask_route` | `fastapi_route` | `jaxrs_annotation` |
    /// `express_route` (the last four have no Python counterpart — see
    /// [`crate::framework`]'s module doc).
    pub marker_type: String,
    /// e.g. `"@RequestParam"`, `"request.GET"`, `"@FromQuery"`.
    pub marker_name: String,
    /// Which parameters this marker taints.
    pub parameter_names: Vec<String>,
    /// `spring` | `django` | `aspnet` | `flask` | `fastapi` | `jaxrs` |
    /// `express`.
    pub framework: String,
    /// `high` for an explicit annotation, `medium` for an implicit
    /// type-based match.
    pub confidence: String,
}

/// An authentication guard in evidence on a handler — a decorator,
/// annotation, attribute or route middleware.
///
/// **No Python counterpart.** `_scan.py`'s framework extractors carry no
/// auth field at all, and `_graph.py::_emit_framework_entry_points`
/// (L1533-1552) constructs `EntryPoint(file=, function=, kind=)` with
/// three keyword arguments, so `reachable_from_unauth` is left at the
/// pydantic model's `False` default for *every* entry point the seed
/// emits. Nothing in the pipeline ever sets it true except the S1
/// agent's own JSON. The field means "this handler is reachable without
/// authenticating" wherever it is read downstream — S3's decompose sort
/// and prompt rendering, S6's "reachable without authentication"
/// reasoning — so a blanket `false` tells those stages that every route
/// in a repo with no auth at all is *behind* auth, which is backwards
/// and unsafe. Recording what auth evidence exists lets the seed answer
/// the question honestly; see [`crate::evidence::emit_framework_entry_points`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthGuardFact {
    pub function_qnode: String,
    pub line: usize,
    /// e.g. `"@login_required"`, `"@PreAuthorize"`, `"[AllowAnonymous]"`.
    pub marker_name: String,
    /// `true` for a guard that demands authentication, `false` for an
    /// explicit opt-out (`[AllowAnonymous]`, `@PermitAll`) — which is
    /// evidence the handler *is* anonymously reachable, not evidence of
    /// a guard.
    pub requires_auth: bool,
    pub framework: String,
}

/// A route pattern's path parameter, bound to a handler argument.
/// Ported from `models.py::RouteTaintFact` (L614-627).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouteTaintFact {
    pub function_qnode: String,
    pub line: usize,
    /// e.g. `"/user/{id}"`, `"/user/<int:id>"`.
    pub route_pattern: String,
    /// e.g. `"id"`.
    pub parameter_name: String,
    /// URL parameters are always user-controlled.
    pub is_tainted: bool,
    pub framework: String,
}

/// Data flowing from a local into a framework response sink. Ported from
/// `models.py::ResponseDataflowFact` (L641-654).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResponseDataflowFact {
    pub function_qnode: String,
    pub line: usize,
    /// Variable flowing into the response.
    pub from_symbol: String,
    /// e.g. `"JsonResponse"`, `"ResponseEntity"`, `"Ok"`.
    pub to_sink: String,
    pub framework: String,
    /// `json` | `html` | `text` | `xml`.
    pub response_type: String,
}

/// One scan target's full extracted index.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileIndex {
    pub file: String,
    pub language: String,
    /// Local-name -> fully-qualified module/class name.
    pub imports: BTreeMap<String, String>,
    pub functions: Vec<FuncDef>,
    pub source_hits: Vec<CallSite>,
    pub sink_hits: Vec<CallSite>,
    /// All call edges in the file, whether or not they matched a rule —
    /// `(containing_fn_name, receiver_name, called_method_name)`. Used
    /// by the graph module to build true reachability.
    pub call_edges: Vec<(String, String, String)>,
    /// All observed calls with snippets, for LLM-based spec derivation.
    pub observed_calls: Vec<ObservedCall>,
    /// Lightweight intra-procedural facts for interprocedural taint.
    pub assigns: Vec<VarAssignFact>,
    pub returns: Vec<ReturnFact>,
    pub call_args: Vec<CallArgFact>,
    /// Field/container propagation facts — Python, Java and C# only
    /// (`_scan.py::_FIELD_FACT_EXTRACTORS` has exactly those three keys).
    pub field_writes: Vec<FieldWriteFact>,
    pub field_reads: Vec<FieldReadFact>,
    pub container_writes: Vec<ContainerWriteFact>,
    /// Reflection facts — same three languages
    /// (`_scan.py::_REFLECTION_FACT_EXTRACTORS`).
    pub reflection_facts: Vec<ReflectionFact>,
    /// Framework detection facts. `_scan.py`'s own extractor tables cover
    /// Python/Java/C#; this port additionally wires JavaScript/TypeScript
    /// (Express) — see [`crate::framework`].
    pub framework_markers: Vec<FrameworkMarkerFact>,
    pub auth_guards: Vec<AuthGuardFact>,
    pub route_facts: Vec<RouteTaintFact>,
    pub response_dataflow: Vec<ResponseDataflowFact>,
}

// ── per-call-site raw extraction shape ──────────────────────────────────

/// A raw call site as walked out of the tree, before source/sink
/// matching — `(line, receiver, method, containing_fn, snippet)` in the
/// Python original.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawCall {
    line: usize,
    receiver: String,
    method: String,
    containing_fn: String,
    snippet: String,
    /// Which positional arguments are *static* string literals, for
    /// [`crate::rules::MatchSpec::requires_dynamic_arg`] read at
    /// [`crate::rules::MatchSpec::dynamic_arg_index`]. A per-argument
    /// answer rather than a single flag because the C `printf` family
    /// puts its format string second or third. Empty for an extractor
    /// that does not compute it, so such a rule keeps matching there
    /// rather than silently going dark.
    static_args: Vec<bool>,
    /// Which positional arguments are *arithmetic* expressions (a `*`
    /// or `+` of two or more operands), for
    /// [`crate::rules::MatchSpec::requires_arithmetic_arg`] read at
    /// [`crate::rules::MatchSpec::arithmetic_arg_index`]. This is the
    /// predicate an allocation rule needs: `malloc(count * size)`
    /// computes a size that can wrap (CWE-190) where `malloc(len)`
    /// cannot. Empty for an extractor that does not compute it, which
    /// — unlike [`RawCall::static_args`] — leaves such a rule DARK
    /// rather than over-matching, since asking for arithmetic is a
    /// positive requirement and not a veto. Only C/C++ computes it
    /// today, and the corpus's only rules that ask are C/C++-only.
    arithmetic_args: Vec<bool>,
    /// Which positional arguments are the integer literal `1`, for
    /// [`crate::rules::MatchSpec::requires_unit_arg`] read at
    /// [`crate::rules::MatchSpec::unit_arg_index`]. Empty, and so DARK,
    /// for an extractor that does not compute it, exactly as
    /// [`RawCall::arithmetic_args`] is. It exists so a rule can require
    /// a shape at a SECOND argument as well as the first:
    /// `calloc(n * size, 1)` hand-multiplies its way past `calloc`'s
    /// own overflow check, and only the pair of predicates tells it
    /// from the idiomatic `calloc(n, size)`.
    unit_args: Vec<bool>,
    /// How many arguments the call passes, for
    /// [`crate::rules::MatchSpec::requires_any_arg`]. `None` for an
    /// extractor that does not compute it ([`lite`]), so such a rule
    /// keeps matching there rather than silently going dark.
    arg_count: Option<usize>,
    /// The bare identifier the first positional argument names, when it
    /// is one — the local a query was assembled into. Lets
    /// `requires_dynamic_arg` look through `String sql = "…" + "…";
    /// st.executeQuery(sql)`, which is how essentially all real code
    /// writes a query and which the literal-at-the-call-site test alone
    /// reads as dynamic. See [`literal_only_symbols`].
    first_arg_symbol: Option<String>,
    /// This "call" is really a property read (`req.query`,
    /// `Request.Headers`) that the extractor synthesized so a rule can
    /// name it — see [`RawCall::property_read`]'s own users in
    /// [`scan_file`]. Property reads match **source** specs only, and
    /// stay out of `call_edges`/`observed_calls`: a bare read is a read
    /// of data, never an execution, and a property name colliding with a
    /// function name would otherwise fabricate a call-graph edge.
    property_read: bool,
}

/// What a language plugin's tree-walk produces — the Python original's
/// `LangPlugin.extract`'s 6-tuple return, as a named struct instead (a
/// tuple this wide reads worse in Rust, and clippy's `type_complexity`
/// lint would flag it in every signature that threads it through).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ExtractResult {
    imports: BTreeMap<String, String>,
    functions: Vec<FuncDef>,
    calls: Vec<RawCall>,
    assigns: Vec<VarAssignFact>,
    returns: Vec<ReturnFact>,
    call_args: Vec<CallArgFact>,
}

/// Languages with a wired extractor. See the module doc comment.
pub fn supported_languages() -> &'static [&'static str] {
    &[
        "python",
        "javascript",
        "typescript",
        "go",
        "java",
        "csharp",
        "php",
        "ruby",
        "kotlin",
        "rust",
        // C and C++ share one language key (`ext_to_lang` maps `.c`,
        // `.h`, `.cpp` and friends to it) and one grammar: C++'s is a
        // superset of C's and parses both.
        "c-cpp",
    ]
}

fn extract(language: &str, src: &[u8], root: Node) -> Option<ExtractResult> {
    match language {
        "python" => Some(py_extract(src, root)),
        "javascript" | "typescript" => Some(js_extract(src, root)),
        "go" => Some(go_extract(src, root)),
        "java" => Some(java_extract(src, root)),
        "csharp" => Some(cs_extract(src, root)),
        "php" => Some(lite::extract(&lite::PHP, src, root)),
        "ruby" => Some(lite::extract(&lite::RUBY, src, root)),
        "kotlin" => Some(lite::extract(&lite::KOTLIN, src, root)),
        "rust" => Some(lite::extract(&lite::RUST, src, root)),
        "c-cpp" => Some(lite::extract(&lite::C_CPP, src, root)),
        _ => None,
    }
}

/// `ext_to_lang` labels `.tsx` as plain `"typescript"`, and that label is
/// what everything downstream keys on: [`FileIndex::language`], the
/// extractor dispatch in [`extract`], `MatchSpec::languages`, lens
/// selection and hint lookup. tree-sitter, though, ships two grammars for
/// TypeScript, because the TypeScript one reads `<div>` as a type
/// assertion and errors on JSX; error recovery then drops the subtrees
/// holding a component's handlers and calls, and S10's syntax gate reads
/// the resulting parse error as the fix having broken the file. So the
/// *grammar* is picked by suffix here while the label stays untouched,
/// the same reconciliation `bc_repo_analysis`'s call-graph backend does
/// for C against C++.
pub(crate) fn normalize_lang_for_grammar(rel: &str, language: &str) -> String {
    let is_tsx = Path::new(rel)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("tsx"));
    if language == "typescript" && is_tsx {
        "tsx".to_string()
    } else {
        language.to_string()
    }
}

/// Grammar per [`supported_languages`] key, plus `"tsx"`, which is a
/// grammar key and never a language label: only
/// [`normalize_lang_for_grammar`] produces it, and [`extract`] must never
/// see it.
pub(crate) fn ts_language(language: &str) -> Option<tree_sitter::Language> {
    match language {
        "python" => Some(tree_sitter_python::LANGUAGE.into()),
        "javascript" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "typescript" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "csharp" => Some(tree_sitter_c_sharp::LANGUAGE.into()),
        "php" => Some(tree_sitter_php::LANGUAGE_PHP.into()),
        "ruby" => Some(tree_sitter_ruby::LANGUAGE.into()),
        "kotlin" => Some(tree_sitter_kotlin_ng::LANGUAGE.into()),
        "rust" => Some(tree_sitter_rust::LANGUAGE.into()),
        "c-cpp" => Some(tree_sitter_cpp::LANGUAGE.into()),
        _ => None,
    }
}

// ── Python plugin ────────────────────────────────────────────────────────

pub(crate) fn py_text(node: Node, src: &[u8]) -> String {
    String::from_utf8_lossy(&src[node.start_byte()..node.end_byte()]).into_owned()
}

/// Walk a call/attribute expression to its leftmost identifier — that's
/// treated as the receiver root for import resolution.
pub(crate) fn py_leftmost_identifier(node: Node, src: &[u8]) -> String {
    let mut cur = node;
    loop {
        match cur.kind() {
            "identifier" => return py_text(cur, src),
            // `attribute` has children [object, ".", attribute]; recurse
            // into `object`.
            "attribute" => {
                let Some(next) = cur.child_by_field_name("object").or_else(|| cur.child(0)) else {
                    return String::new();
                };
                cur = next;
            }
            "call" => {
                let Some(next) = cur.child_by_field_name("function") else {
                    return String::new();
                };
                cur = next;
            }
            // subscript, parenthesized, etc. — take first child and keep
            // walking.
            _ => {
                let Some(next) = cur.child(0) else {
                    return String::new();
                };
                cur = next;
            }
        }
    }
}

/// Grab a compact single-line snippet at the call site.
fn py_snippet(src: &[u8], node: Node) -> String {
    let line_start = src[..node.start_byte()]
        .iter()
        .rposition(|&b| b == b'\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let line_end = src[node.end_byte()..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|i| node.end_byte() + i)
        .unwrap_or(src.len());
    let line = String::from_utf8_lossy(&src[line_start..line_end]);
    let trimmed = line.trim();
    trimmed.chars().take(120).collect()
}

/// Innermost enclosing function name for a byte offset, `""` if
/// module-level. `ranges` is `(start_byte, end_byte, name)` per function,
/// walked in reverse so a nested def overrides its outer one.
pub(crate) fn scope_for(offset: usize, ranges: &[(usize, usize, String)]) -> String {
    ranges
        .iter()
        .rev()
        .find(|(s, e, _)| *s <= offset && offset < *e)
        .map(|(_, _, name)| name.clone())
        .unwrap_or_default()
}

/// All named children of `node`, materialized. tree-sitter's own
/// `named_children` iterator borrows a `TreeCursor`, which makes it
/// unusable in tail position or as a function's return value; every
/// fact extractor in this crate wants the plain list.
pub(crate) fn named_kids<'a>(node: Node<'a>) -> std::vec::IntoIter<Node<'a>> {
    let mut cursor = node.walk();
    let out: Vec<Node<'a>> = node.named_children(&mut cursor).collect();
    out.into_iter()
}

/// [`named_kids`]'s all-children counterpart.
pub(crate) fn kids<'a>(node: Node<'a>) -> std::vec::IntoIter<Node<'a>> {
    let mut cursor = node.walk();
    let out: Vec<Node<'a>> = node.children(&mut cursor).collect();
    out.into_iter()
}

// ── composed-value symbols (divergence: fixes a Python blind spot) ───────
//
// **The defect this fixes.** Every one of the Python original's argument
// /RHS symbol collectors reads a *direct* `identifier` node and nothing
// else: `_py_identifier_args` (`_scan.py:1273-1285`) accepts an
// `identifier` argument or a `keyword_argument` whose `value` is an
// `identifier`; `_java_identifier_args` (`_scan.py:1518-1526`) and
// `_cs_identifier_args` (`_scan.py:1968-1980`) are flatter still. The
// assignment-RHS branches (`_scan.py:1364-1368` python, `1611-1619` /
// `1639-1647` java, `2015-2031` / `2135-2143` c#) and the three
// `_*_return_identifier` helpers gate on the same bare `identifier`.
//
// The consequence is that **string composition hides its operands from
// the taint plane entirely**. The node kinds `interpolation`,
// `concatenated_string`, `interpolated_string_expression` and
// `binary_expression` appear nowhere in `_scan.py`, and its single
// `binary_operator` mention (L268) is CFG condition text. So
// `subprocess.check_output(f"ping -c 1 {host}", shell=True)`,
// `cur.execute("… LIKE '" + pattern + "'")`, `"…".format(x)` and
// `"…%s" % x` all yield `arg_symbols == []`, which makes
// `_build_taint_evidence_for_path` return `None` and — under the
// original's hard evidence gate — drops the whole path. Field evidence
// (2026-09-06): a five-file Flask app whose handlers reach a
// command-injection, a SQL-injection and a path-traversal sink produced
// `taint_paths = 0` and `taint_evidence = 0`.
//
// Per the repo's "fix genuine Python bugs, don't replicate them" rule
// these collectors descend into the composition instead. Collection
// literals (`tuple`/`list`/`dict`/`set`) are deliberately **not**
// descended into: a collection argument is a container of values, not a
// composed string, and reading one as a string operand is exactly the
// bind-parameter false positive this change exists to avoid —
// `cur.execute("SELECT … WHERE email LIKE ?", (email,))` is a
// parameterized query, not an injection.

/// Depth cap for the composed-value walkers below. Deep enough for any
/// realistic concatenation/format chain, shallow enough that a
/// pathological expression can't drive the scanner into a long walk.
const COMPOSED_VALUE_MAX_DEPTH: usize = 8;

/// Append `sym` unless `out` already ends with the symbols collected for
/// the same argument. Duplicate operands (`f"{x} and {x}"`) add nothing.
fn push_symbol(out: &mut Vec<String>, sym: String) {
    if !out.contains(&sym) {
        out.push(sym);
    }
}

/// The `arg_symbols` / `arg_slots` pair of a [`CallArgFact`]: every
/// symbol of every argument, each tagged with the argument it came from.
/// [`push_symbol`] deduplicates within one argument; the same symbol
/// passed in two arguments is two entries, because both parameters
/// receive it. Slots count `named_kids` of the argument list, so a Python
/// keyword argument is numbered positionally — parameter binding by name
/// is not modeled, upstream or here.
fn slotted_arg_symbols(
    args_node: Option<Node>,
    src: &[u8],
    walk: fn(Node, &[u8], usize, &mut Vec<String>),
) -> (Vec<String>, Vec<usize>) {
    let mut symbols = Vec::new();
    let mut slots = Vec::new();
    let Some(args_node) = args_node else {
        return (symbols, slots);
    };
    for (slot, arg) in named_kids(args_node).enumerate() {
        let mut here = Vec::new();
        walk(arg, src, 0, &mut here);
        slots.extend(here.iter().map(|_| slot));
        symbols.extend(here);
    }
    (symbols, slots)
}

/// `(argument count, first positional argument's bare identifier)` for
/// one call — the two things [`crate::rules::MatchSpec`]'s
/// `requires_any_arg` and `requires_dynamic_arg` need beyond the
/// call-site literal test. C#'s one-level `argument` wrapper is
/// unwrapped, and Python's keyword arguments are skipped when looking
/// for the *first positional* one (they still count toward the total,
/// since a keyword argument is still an argument).
type ArgShape = (Option<usize>, Option<String>, Vec<bool>);

fn arg_shape(args_node: Option<Node>, src: &[u8], is_static: fn(Node) -> bool) -> ArgShape {
    let Some(args) = args_node else {
        return (Some(0), None, Vec::new());
    };
    let count = named_kids(args).count();
    let first = named_kids(args)
        .find(|a| a.kind() != "keyword_argument")
        .map(|a| {
            if a.kind() == "argument" {
                cs_argument_value(a).unwrap_or(a)
            } else {
                a
            }
        })
        .filter(|v| v.kind() == "identifier")
        .map(|v| py_text(v, src));
    let statics = named_kids(args).map(is_static).collect();
    (Some(count), first, statics)
}

/// Whether the argument at `index` is a static string literal — the
/// question `requires_dynamic_arg` asks. An index past the end of the
/// list is not static: there is no literal there to vouch for the call.
pub(crate) fn static_arg_at(statics: &[bool], index: usize) -> bool {
    statics.get(index).copied().unwrap_or(false)
}

/// Locals whose every assignment in their own function came from
/// literals alone — no other symbol, no call — keyed by
/// `(function_qnode, symbol)`.
///
/// **What this fixes.** `requires_dynamic_arg` asks whether the query
/// argument is a *literal at the call site*, which answers "no" for
/// `String sql = "SELECT … WHERE owner = ?"; st.prepareStatement(sql)`
/// — a bound, parameterized query assembled into a local, which is how
/// essentially all real code writes one. Field evidence (2026-09-07):
/// the java-spring and csharp-aspnet apps in the polyglot bed each
/// carry a deliberately-safe parameterized query as their negative
/// control, and the seed reported a taint path onto both. A local
/// assembled from literals alone carries no attacker input by
/// construction, so it is treated exactly like the literal it is.
fn literal_only_symbols(
    assigns: &[VarAssignFact],
    call_args: &[CallArgFact],
) -> BTreeSet<(String, String)> {
    let mut literal: BTreeSet<(String, String)> = BTreeSet::new();
    let mut built: BTreeSet<(String, String)> = BTreeSet::new();
    let mut composed: BTreeSet<(String, String)> = BTreeSet::new();
    for a in assigns {
        let key = (a.function_qnode.clone(), a.dst_symbol.clone());
        if a.src_symbol.is_some() {
            composed.insert(key);
        } else if a.src_call.is_some() {
            built.insert(key);
        } else {
            literal.insert(key);
        }
    }
    // Anything bound to a call's result is BUILT, whatever its
    // assignment fact says. A property read (`var raw =
    // Request.Query["id"]`) is a call site here but composes no
    // symbols, so its assignment looks literal — and it is the exact
    // opposite: it is a source. Reading the call-argument facts is what
    // tells the two apart.
    for cf in call_args {
        if let Some(t) = cf.target_symbol.as_ref().filter(|t| !t.is_empty()) {
            built.insert((cf.function_qnode.clone(), t.clone()));
        }
    }
    // Assigned two different ways is not "assigned from literals".
    let mut out: BTreeSet<(String, String)> = literal
        .iter()
        .filter(|k| !composed.contains(*k) && !built.contains(*k))
        .cloned()
        .collect();

    // One more relation, to a fixpoint: an object BUILT from a constant
    // query text carries a constant query. `SqlCommand cmd = new
    // SqlCommand(sql, conn); cmd.ExecuteReader()` is ADO.NET's own
    // parameterized idiom, and the execute call carries no argument at
    // all to judge — the query is whatever the command was built with.
    // Only argument slot 0 counts, and only when it names a symbol: a
    // `new SqlCommand()` built empty has its text set later through
    // `CommandText`, which this extractor cannot see, so it stays
    // dynamic — which is the case the zero-argument execute rule
    // exists for.
    let candidates: Vec<(String, String)> = built
        .iter()
        .filter(|k| !composed.contains(*k) && !literal.contains(*k))
        .cloned()
        .collect();
    loop {
        let mut grew = false;
        for cand in &candidates {
            if out.contains(cand) {
                continue;
            }
            let from_constant_text = call_args.iter().any(|cf| {
                cf.function_qnode == cand.0
                    && cf.target_symbol.as_deref() == Some(cand.1.as_str())
                    && cf.arg_slots.first() == Some(&0)
                    && cf
                        .arg_symbols
                        .first()
                        .is_some_and(|sym| out.contains(&(cand.0.clone(), sym.clone())))
            });
            if from_constant_text {
                out.insert(cand.clone());
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    out
}

/// Every identifier that flows into the value `node` denotes, descending
/// through Python's four string-composition shapes: f-strings
/// (`string` → `interpolation`), adjacent-literal and `+`
/// concatenation (`concatenated_string` / `binary_operator`),
/// `%`-formatting (also `binary_operator`) and `.format(...)`/any other
/// nested call (whose *arguments* carry the symbols — a `.format`
/// receiver is the literal template itself, so it never does).
fn py_value_symbols(node: Node, src: &[u8], depth: usize, out: &mut Vec<String>) {
    if depth > COMPOSED_VALUE_MAX_DEPTH {
        return;
    }
    match node.kind() {
        "identifier" => push_symbol(out, py_text(node, src)),
        "string"
        | "concatenated_string"
        | "interpolation"
        | "binary_operator"
        | "parenthesized_expression"
        | "conditional_expression"
        | "unary_operator" => {
            for c in named_kids(node) {
                py_value_symbols(c, src, depth + 1, out);
            }
        }
        "call" => {
            if let Some(args) = node.child_by_field_name("arguments") {
                for c in named_kids(args) {
                    py_value_symbols(c, src, depth + 1, out);
                }
            }
        }
        "keyword_argument" => {
            if let Some(v) = node.child_by_field_name("value") {
                py_value_symbols(v, src, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// True when `node` is a *static* string literal — a quoted string with
/// no `interpolation` child, or an adjacent-literal concatenation of
/// such strings. Used by the `requires_dynamic_arg` sink rules (see
/// [`crate::rules::MatchSpec::requires_dynamic_arg`]) to keep a
/// parameterized `cur.execute("… ?", (v,))` out of the SQL sink set
/// while still flagging `cur.execute("…" + v)` and `cur.execute(q)`.
fn py_is_static_string(node: Node) -> bool {
    match node.kind() {
        "string" => !named_kids(node).any(|c| c.kind() == "interpolation"),
        "concatenated_string" => named_kids(node).all(py_is_static_string),
        _ => false,
    }
}

/// The value inside a C# `argument` wrapper node. tree-sitter-c-sharp
/// exposes it as an unnamed child, not the `expression` field the Python
/// original reaches for (`_scan.py` L558/L640, `_cs_extract_field_facts`
/// L2752) — which is why every one of those `child_by_field_name(
/// "expression")` lookups silently finds nothing there.
pub(crate) fn cs_argument_value<'a>(arg: Node<'a>) -> Option<Node<'a>> {
    arg.child_by_field_name("expression")
        .or_else(|| named_kids(arg).next())
}

/// Pre-pass collecting `(start_byte, end_byte, name)` for every node
/// whose kind is in `kinds` and which has a `name` field — the shared
/// shape of `_scan.py`'s six near-identical `_collect_fn_ranges` inner
/// helpers (one per fact extractor), which each walk the whole tree
/// before the fact walk so [`scope_for`] can attribute a fact to its
/// enclosing function.
pub(crate) fn collect_fn_ranges(
    node: Node,
    src: &[u8],
    kinds: &[&str],
    out: &mut Vec<(usize, usize, String)>,
) {
    if kinds.contains(&node.kind()) {
        if let Some(n) = node.child_by_field_name("name") {
            out.push((node.start_byte(), node.end_byte(), py_text(n, src)));
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_fn_ranges(child, src, kinds, out);
    }
}

fn py_call_parts(call_node: Node, src: &[u8]) -> (String, String) {
    let Some(fn_node) = call_node.child_by_field_name("function") else {
        return (String::new(), String::new());
    };
    match fn_node.kind() {
        "attribute" => {
            let method = fn_node
                .child_by_field_name("attribute")
                .map(|n| py_text(n, src))
                .unwrap_or_default();
            let receiver = py_leftmost_identifier(fn_node, src);
            (receiver, method)
        }
        "identifier" => (String::new(), py_text(fn_node, src)),
        _ => (String::new(), String::new()),
    }
}

fn py_assignment_target_for_call(call_node: Node, src: &[u8]) -> Option<String> {
    let parent = call_node.parent()?;
    if parent.kind() != "assignment" {
        return None;
    }
    let right = parent.child_by_field_name("right")?;
    let left = parent.child_by_field_name("left")?;
    if right == call_node && left.kind() == "identifier" {
        Some(py_text(left, src))
    } else {
        None
    }
}

/// Parameter names of a Python `function_definition` in caller slot
/// order: `self`/`cls` dropped, `*args`/`**kw` by their bare names, the
/// `*` and `/` separators skipped. See [`FuncDef::params`].
fn py_param_names(fn_node: Node, src: &[u8]) -> Vec<String> {
    let Some(params) = fn_node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut out: Vec<String> = named_kids(params)
        .filter_map(|p| match p.kind() {
            "identifier" => Some(py_text(p, src)),
            "default_parameter"
            | "typed_default_parameter"
            | "typed_parameter"
            | "list_splat_pattern"
            | "dictionary_splat_pattern" => p
                .child_by_field_name("name")
                .or_else(|| named_kids(p).find(|c| c.kind() == "identifier"))
                .map(|n| py_text(n, src)),
            _ => None,
        })
        .collect();
    if matches!(out.first().map(String::as_str), Some("self" | "cls")) {
        out.remove(0);
    }
    out
}

/// Argument symbols for one call. Unlike Python's own
/// `_py_identifier_args` this descends through string composition — see
/// the "composed-value symbols" section above for the defect and the
/// field evidence.
fn py_identifier_args(call_node: Node, src: &[u8]) -> (Vec<String>, Vec<usize>) {
    slotted_arg_symbols(
        call_node.child_by_field_name("arguments"),
        src,
        py_value_symbols,
    )
}

/// Symbols a `return` hands back. Python's `_py_return_identifier`
/// (`_scan.py:1287-1296`) gates on a bare `identifier`, so
/// `return "%" + value + "%"` reports nothing and
/// `_callee_may_return_tainted` then refuses to propagate taint through
/// any string-building helper. Returns an empty vec when the returned
/// expression carries no symbols (or there is no value at all).
fn py_return_symbols(ret_node: Node, src: &[u8]) -> Vec<String> {
    let val = ret_node
        .child_by_field_name("value")
        .or_else(|| named_kids(ret_node).find(|c| c.kind() != "return"));
    let mut out = Vec::new();
    if let Some(val) = val {
        py_value_symbols(val, src, 0, &mut out);
    }
    out
}

/// [`py_extract`]'s accumulator, bundled into one struct (rather than
/// six separate `&mut` params to `visit`) to stay under clippy's
/// `too_many_arguments` threshold.
#[derive(Default)]
struct PyExtractState {
    imports: BTreeMap<String, String>,
    functions: Vec<FuncDef>,
    /// Precomputed function ranges so each call can be attributed to a
    /// scope — `(start_byte, end_byte, name)`.
    fn_ranges: Vec<(usize, usize, String)>,
    calls: Vec<RawCall>,
    assigns: Vec<VarAssignFact>,
    returns: Vec<ReturnFact>,
    call_args: Vec<CallArgFact>,
}

fn py_visit(node: Node, src: &[u8], state: &mut PyExtractState) {
    match node.kind() {
        "import_statement" => {
            // import foo   |   import foo.bar   |   import foo as f, baz
            let mut cursor = node.walk();
            for name_node in node.children(&mut cursor) {
                match name_node.kind() {
                    "aliased_import" => {
                        let mod_node = name_node.child_by_field_name("name");
                        let alias_node = name_node.child_by_field_name("alias");
                        if let (Some(m), Some(a)) = (mod_node, alias_node) {
                            state.imports.insert(py_text(a, src), py_text(m, src));
                        }
                    }
                    "dotted_name" => {
                        let modname = py_text(name_node, src);
                        let top = modname.split('.').next().unwrap_or("").to_string();
                        state.imports.insert(top, modname);
                    }
                    _ => {}
                }
            }
        }
        "import_from_statement" => {
            let mod_node = node.child_by_field_name("module_name");
            let modname = mod_node.map(|n| py_text(n, src)).unwrap_or_default();
            let mut cursor = node.walk();
            for c in node.children(&mut cursor) {
                if Some(c) == mod_node {
                    continue;
                }
                match c.kind() {
                    "aliased_import" => {
                        let name_node = c.child_by_field_name("name");
                        let alias_node = c.child_by_field_name("alias");
                        if let (Some(n), Some(a)) = (name_node, alias_node) {
                            let sym = py_text(n, src);
                            let fq = if modname.is_empty() {
                                sym
                            } else {
                                format!("{modname}.{sym}")
                            };
                            state.imports.insert(py_text(a, src), fq);
                        }
                    }
                    "dotted_name" => {
                        let sym = py_text(c, src);
                        let fq = if modname.is_empty() {
                            sym.clone()
                        } else {
                            format!("{modname}.{sym}")
                        };
                        state.imports.insert(sym, fq);
                    }
                    _ => {}
                }
            }
        }
        "function_definition" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let fname = py_text(name_node, src);
                state.functions.push(FuncDef {
                    name: fname.clone(),
                    start_line: node.start_position().row + 1,
                    end_line: node.end_position().row + 1,
                    class_name: String::new(),
                    params: py_param_names(node, src),
                });
                state
                    .fn_ranges
                    .push((node.start_byte(), node.end_byte(), fname));
            }
        }
        "call" => {
            // No separate `function` field presence check: `py_call_parts`
            // already returns `("", "")` when the field is absent, which
            // `!method.is_empty()` below already gates on — the guard this
            // replaced was provably redundant with that contract.
            let (receiver, method) = py_call_parts(node, src);
            if !method.is_empty() {
                let line = node.start_position().row + 1;
                let scope = scope_for(node.start_byte(), &state.fn_ranges);
                let snippet = py_snippet(src, node);
                let shape = arg_shape(
                    node.child_by_field_name("arguments"),
                    src,
                    py_is_static_string,
                );
                state.calls.push(RawCall {
                    line,
                    receiver: receiver.clone(),
                    method: method.clone(),
                    containing_fn: scope.clone(),
                    snippet,
                    static_args: shape.2.clone(),
                    arithmetic_args: Vec::new(),
                    unit_args: Vec::new(),
                    arg_count: shape.0,
                    first_arg_symbol: shape.1.clone(),
                    property_read: false,
                });
                let (arg_symbols, arg_slots) = py_identifier_args(node, src);
                state.call_args.push(CallArgFact {
                    function_qnode: scope,
                    line,
                    callee_name: method,
                    receiver,
                    arg_symbols,
                    arg_slots,
                    target_symbol: py_assignment_target_for_call(node, src),
                });
            }
        }
        "assignment" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            if let (Some(left), Some(right)) = (left, right) {
                if left.kind() == "identifier" {
                    let dst = py_text(left, src);
                    let fid_scope = scope_for(node.start_byte(), &state.fn_ranges);
                    let line = node.start_position().row + 1;
                    // `dst = <identifier>` is Python's only non-call RHS
                    // shape; every composition (`"%" + v + "%"`,
                    // `f"…{v}…"`, `"…".format(v)`, `"…%s" % v`) now
                    // reports one alias fact per operand instead of
                    // silently producing none. `_apply_local_aliases` is
                    // a per-symbol fixpoint, so N facts for one
                    // assignment is exactly the right shape.
                    let (syms, call) = if right.kind() == "call" {
                        let (_r, m) = py_call_parts(right, src);
                        (Vec::new(), (!m.is_empty()).then_some(m))
                    } else {
                        let mut syms = Vec::new();
                        py_value_symbols(right, src, 0, &mut syms);
                        (syms, None)
                    };
                    push_assign_facts(&mut state.assigns, &fid_scope, line, &dst, syms, call);
                }
            }
        }
        "return_statement" => {
            push_return_facts(
                &mut state.returns,
                &scope_for(node.start_byte(), &state.fn_ranges),
                node.start_position().row + 1,
                py_return_symbols(node, src),
            );
        }
        _ => {}
    }
    // Recurse into children (function_definition scopes contain calls
    // too).
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        py_visit(child, src, state);
    }
}

fn py_extract(src: &[u8], root: Node) -> ExtractResult {
    let mut state = PyExtractState::default();
    py_visit(root, src, &mut state);
    ExtractResult {
        imports: state.imports,
        functions: state.functions,
        calls: state.calls,
        assigns: state.assigns,
        returns: state.returns,
        call_args: state.call_args,
    }
}

// ── JavaScript / TypeScript plugin ───────────────────────────────────────
// tree-sitter-javascript / tree-sitter-typescript node types:
// import_statement (import_clause, source), variable_declarator (fields:
// name, value), function_declaration / method_definition /
// generator_function_declaration, arrow_function / function_expression
// (field: parameters — `formal_parameters`, whose TypeScript entries are
// `required_parameter`/`optional_parameter` wrappers around a `pattern`),
// call_expression (fields: function, arguments), member_expression
// (fields: object, property), template_string (`template_substitution`
// children), assignment_expression, return_statement.
//
// **Divergence: JS/TS now carries the same fact set Python/Java/C# do**,
// for the reason spelled out above the Go extractor — `_js_extract`
// returns empty assign/return/call-arg lists, so no JavaScript path
// could ever ground in taint evidence.
//
// **Divergence: property reads are call sites too.** Every JavaScript
// request-input API is a *property*, not a call: `req.query`,
// `req.body`, `req.params`, `ctx.request.body`, `request.payload`. The
// bundled corpus says so itself ("`req.query`/`req.body`/`req.params`
// are property access, not calls, and can't be expressed by this
// extractor") and carries exactly one call-shaped Express source in
// their place, so the entire JavaScript source plane was one rule wide.
// A `member_expression` that is not a call's callee is therefore
// recorded as a [`RawCall`] with `property_read: true`, which a
// `req.query(...)`-shaped rule matches. Property reads match SOURCE
// specs only and stay out of `call_edges`/`observed_calls` — see
// [`RawCall::property_read`].

fn js_leftmost_identifier(node: Node, src: &[u8]) -> String {
    let mut cur = node;
    loop {
        match cur.kind() {
            "identifier" | "property_identifier" => return py_text(cur, src),
            "member_expression" => {
                let Some(next) = cur.child_by_field_name("object").or_else(|| cur.child(0)) else {
                    return String::new();
                };
                cur = next;
            }
            "call_expression" => {
                let Some(next) = cur.child_by_field_name("function") else {
                    return String::new();
                };
                cur = next;
            }
            _ => {
                let Some(next) = cur.child(0) else {
                    return String::new();
                };
                cur = next;
            }
        }
    }
}

/// JavaScript's counterpart to [`py_value_symbols`]: template literals
/// (`template_string` → `template_substitution`), `+` concatenation, and
/// any nested call — which covers `.concat(...)`, `[...].join(...)` and
/// every wrapper helper, since a call's *arguments* are what carry the
/// symbols. Array/object literals are deliberately not descended into,
/// for the reason the "composed-value symbols" section above gives.
fn js_value_symbols(node: Node, src: &[u8], depth: usize, out: &mut Vec<String>) {
    if depth > COMPOSED_VALUE_MAX_DEPTH {
        return;
    }
    match node.kind() {
        "identifier" | "shorthand_property_identifier" => push_symbol(out, py_text(node, src)),
        "template_string"
        | "template_substitution"
        | "binary_expression"
        | "parenthesized_expression"
        | "ternary_expression"
        | "unary_expression"
        | "as_expression"
        | "non_null_expression" => {
            for c in named_kids(node) {
                js_value_symbols(c, src, depth + 1, out);
            }
        }
        "call_expression" => {
            if let Some(args) = node.child_by_field_name("arguments") {
                for c in named_kids(args) {
                    js_value_symbols(c, src, depth + 1, out);
                }
            }
            // `"a".concat(b).concat(c)` nests each call in the next
            // one's member `object`, as Java's `StringBuilder` chain
            // does — walk it, but only through chained calls, never a
            // plain receiver variable.
            if let Some(obj) = node
                .child_by_field_name("function")
                .and_then(|f| f.child_by_field_name("object"))
                .filter(|o| o.kind() == "call_expression")
            {
                js_value_symbols(obj, src, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// `(receiver, method)` for a JavaScript call expression.
fn js_call_parts(node: Node, src: &[u8]) -> (String, String) {
    let Some(fn_node) = node.child_by_field_name("function") else {
        return (String::new(), String::new());
    };
    match fn_node.kind() {
        "member_expression" => {
            let method = fn_node
                .child_by_field_name("property")
                .map(|p| py_text(p, src))
                .unwrap_or_default();
            (js_leftmost_identifier(fn_node, src), method)
        }
        "identifier" => (String::new(), py_text(fn_node, src)),
        _ => (String::new(), String::new()),
    }
}

/// One parameter's bound name, `""` for a destructured (`{ id }`) or
/// otherwise unnamed one. An empty placeholder rather than a dropped
/// entry: [`FuncDef::params`] is read *by slot*, so skipping a
/// destructured parameter would renumber every parameter after it, and
/// an empty name matches no symbol so it stays inert.
fn js_param_name(param: Node, src: &[u8]) -> String {
    match param.kind() {
        "identifier" => py_text(param, src),
        "required_parameter" | "optional_parameter" => param
            .child_by_field_name("pattern")
            .map(|p| js_param_name(p, src))
            .unwrap_or_default(),
        "assignment_pattern" => param
            .child_by_field_name("left")
            .map(|p| js_param_name(p, src))
            .unwrap_or_default(),
        "rest_pattern" => named_kids(param)
            .next()
            .map(|p| js_param_name(p, src))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

/// Parameter names of a JavaScript/TypeScript function, method, function
/// expression or arrow function. See [`FuncDef::params`].
fn js_param_names(fn_node: Node, src: &[u8]) -> Vec<String> {
    let Some(params) = fn_node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_kids(params).map(|p| js_param_name(p, src)).collect()
}

fn js_identifier_args(call_node: Node, src: &[u8]) -> (Vec<String>, Vec<usize>) {
    slotted_arg_symbols(
        call_node.child_by_field_name("arguments"),
        src,
        js_value_symbols,
    )
}

/// See [`py_first_arg_is_static_string`]. A template literal counts only
/// when it interpolates nothing.
fn js_is_static_string(node: Node) -> bool {
    match node.kind() {
        "string" => true,
        "template_string" => !named_kids(node).any(|c| c.kind() == "template_substitution"),
        _ => false,
    }
}

/// Walk out of the wrappers a bound value sits inside — `await`, and the
/// `object` position of a longer property chain (`req.query` inside
/// `req.query.id`) — to the node an assignment actually binds. Without
/// the chain step, `const id = req.query.id` would report no assignment
/// target for the `req.query` read, and every JavaScript source bound to
/// a local would be inert.
fn js_bound_value(node: Node) -> Node {
    let mut cur = node;
    while let Some(p) = cur.parent() {
        let wraps = match p.kind() {
            "await_expression" | "parenthesized_expression" | "non_null_expression" => true,
            "member_expression" => p.child_by_field_name("object") == Some(cur),
            _ => false,
        };
        if !wraps {
            break;
        }
        cur = p;
    }
    cur
}

fn js_call_target(node: Node, src: &[u8]) -> Option<String> {
    let value = js_bound_value(node);
    let parent = value.parent()?;
    let name = match parent.kind() {
        "variable_declarator" => (parent.child_by_field_name("value") == Some(value))
            .then(|| parent.child_by_field_name("name")),
        "assignment_expression" => (parent.child_by_field_name("right") == Some(value))
            .then(|| parent.child_by_field_name("left")),
        _ => None,
    };
    name.flatten()
        .filter(|n| n.kind() == "identifier")
        .map(|n| py_text(n, src))
}

/// `(src_symbols, src_call)` for a JavaScript RHS — the JS analogue of
/// [`java_value_source`].
fn js_value_source(value_node: Node, src: &[u8]) -> (Vec<String>, Option<String>) {
    match value_node.kind() {
        "call_expression" => {
            let (_recv, method) = js_call_parts(value_node, src);
            (Vec::new(), (!method.is_empty()).then_some(method))
        }
        "await_expression" => named_kids(value_node)
            .next()
            .map(|inner| js_value_source(inner, src))
            .unwrap_or_default(),
        _ => {
            let mut out = Vec::new();
            js_value_symbols(value_node, src, 0, &mut out);
            (out, None)
        }
    }
}

/// Symbols a JavaScript `return` hands back — see [`py_return_symbols`].
fn js_return_symbols(ret_node: Node, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(val) = named_kids(ret_node).next() {
        js_value_symbols(val, src, 0, &mut out);
    }
    out
}

/// A `member_expression` that is being *read*: not the callee of a call
/// (that is already a call site) and not the target of an assignment
/// (that is a write).
fn js_is_property_read(node: Node) -> bool {
    let Some(parent) = node.parent() else {
        return true;
    };
    match parent.kind() {
        // Arguments live under an `arguments` node, so a
        // `call_expression` parent can only be the callee position.
        "call_expression" | "new_expression" => false,
        "assignment_expression" | "augmented_assignment_expression" => {
            parent.child_by_field_name("left") != Some(node)
        }
        _ => true,
    }
}

#[derive(Default)]
struct JsExtractState {
    imports: BTreeMap<String, String>,
    functions: Vec<FuncDef>,
    fn_ranges: Vec<(usize, usize, String)>,
    calls: Vec<RawCall>,
    assigns: Vec<VarAssignFact>,
    returns: Vec<ReturnFact>,
    call_args: Vec<CallArgFact>,
    class_stack: Vec<String>,
}

impl JsExtractState {
    /// Record a `FuncDef` plus its byte range, so [`scope_for`] can
    /// attribute the calls inside it. `body_node` is the span the range
    /// covers — the whole declaration for a named function, the arrow
    /// itself for one bound to a `const`.
    fn push_function(&mut self, name: String, body_node: Node, params: Vec<String>) {
        self.functions.push(FuncDef {
            name: name.clone(),
            class_name: self.class_stack.last().cloned().unwrap_or_default(),
            start_line: body_node.start_position().row + 1,
            end_line: body_node.end_position().row + 1,
            params,
        });
        self.fn_ranges
            .push((body_node.start_byte(), body_node.end_byte(), name));
    }
}

/// An `arrow_function`/`function_expression` bound to a name — `const h =
/// (req, res) => {…}`, or `{ handler: (req) => {…} }`. Recorded under the
/// bound name so a route registration naming `h` finds a function
/// definition, and so its parameters can be resolved by slot.
fn js_bound_function<'a>(node: Node<'a>, src: &[u8]) -> Option<(String, Node<'a>)> {
    let (name_field, value_field) = match node.kind() {
        "variable_declarator" => ("name", "value"),
        "pair" => ("key", "value"),
        _ => return None,
    };
    let value = node.child_by_field_name(value_field)?;
    if !matches!(value.kind(), "arrow_function" | "function_expression") {
        return None;
    }
    let name = node.child_by_field_name(name_field)?;
    if !matches!(name.kind(), "identifier" | "property_identifier") {
        return None;
    }
    Some((py_text(name, src), value))
}

fn js_visit_import_clause(
    clause: Node,
    src_txt: &str,
    src: &[u8],
    imports: &mut BTreeMap<String, String>,
) {
    let mut cursor = clause.walk();
    for gc in clause.children(&mut cursor) {
        match gc.kind() {
            "identifier" => {
                imports.insert(py_text(gc, src), src_txt.to_string());
            }
            "namespace_import" => {
                let mut ggc_cursor = gc.walk();
                for ggc in gc.children(&mut ggc_cursor) {
                    if ggc.kind() == "identifier" {
                        imports.insert(py_text(ggc, src), src_txt.to_string());
                    }
                }
            }
            "named_imports" => {
                let mut spec_cursor = gc.walk();
                for spec in gc.children(&mut spec_cursor) {
                    if spec.kind() != "import_specifier" {
                        continue;
                    }
                    let Some(n) = spec.child_by_field_name("name") else {
                        continue;
                    };
                    let a = spec.child_by_field_name("alias");
                    let local = a
                        .map(|a| py_text(a, src))
                        .unwrap_or_else(|| py_text(n, src));
                    let n_text = py_text(n, src);
                    let fq = if src_txt.is_empty() {
                        n_text
                    } else {
                        format!("{src_txt}.{n_text}")
                    };
                    imports.insert(local, fq);
                }
            }
            _ => {}
        }
    }
}

fn js_visit(node: Node, src: &[u8], state: &mut JsExtractState) {
    match node.kind() {
        "import_statement" => {
            let src_node = node.child_by_field_name("source");
            let src_txt = src_node
                .map(|n| py_text(n, src).trim_matches(['"', '\'']).to_string())
                .unwrap_or_default();
            let mut cursor = node.walk();
            for c in node.children(&mut cursor) {
                if c.kind() == "import_clause" {
                    js_visit_import_clause(c, &src_txt, src, &mut state.imports);
                }
            }
        }
        "variable_declarator" | "pair" => {
            // const x = require('y') — CommonJS shape.
            let n = node.child_by_field_name("name");
            let v = node.child_by_field_name("value");
            if let (Some(n), Some(v)) = (n, v) {
                if v.kind() == "call_expression" {
                    let is_require = v.child_by_field_name("function").is_some_and(|fn_node| {
                        fn_node.kind() == "identifier" && py_text(fn_node, src) == "require"
                    });
                    if is_require {
                        if let Some(args) = v.child_by_field_name("arguments") {
                            let mut cursor = args.walk();
                            for arg in args.children(&mut cursor) {
                                if arg.kind() == "string" {
                                    state.imports.insert(
                                        py_text(n, src),
                                        py_text(arg, src).trim_matches(['"', '\'']).to_string(),
                                    );
                                }
                            }
                        }
                    }
                }
                if n.kind() == "identifier" {
                    let (src_symbols, src_call) = js_value_source(v, src);
                    push_assign_facts(
                        &mut state.assigns,
                        &scope_for(node.start_byte(), &state.fn_ranges),
                        node.start_position().row + 1,
                        &py_text(n, src),
                        src_symbols,
                        src_call,
                    );
                }
            }
            if let Some((name, value)) = js_bound_function(node, src) {
                state.push_function(name, value, js_param_names(value, src));
            }
        }
        "assignment_expression" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            if let (Some(left), Some(right)) = (left, right) {
                if left.kind() == "identifier" {
                    let (src_symbols, src_call) = js_value_source(right, src);
                    push_assign_facts(
                        &mut state.assigns,
                        &scope_for(node.start_byte(), &state.fn_ranges),
                        node.start_position().row + 1,
                        &py_text(left, src),
                        src_symbols,
                        src_call,
                    );
                }
            }
        }
        "return_statement" => {
            push_return_facts(
                &mut state.returns,
                &scope_for(node.start_byte(), &state.fn_ranges),
                node.start_position().row + 1,
                js_return_symbols(node, src),
            );
        }
        "class_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let cls = py_text(name_node, src);
                if !cls.is_empty() {
                    state.class_stack.push(cls);
                    let mut cursor = node.walk();
                    for c in node.children(&mut cursor) {
                        js_visit(c, src, state);
                    }
                    state.class_stack.pop();
                    return;
                }
            }
        }
        "function_declaration" | "method_definition" | "generator_function_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                state.push_function(py_text(name_node, src), node, js_param_names(node, src));
            }
        }
        "call_expression" => {
            let (receiver, method) = js_call_parts(node, src);
            if !method.is_empty() {
                let line = node.start_position().row + 1;
                let scope = scope_for(node.start_byte(), &state.fn_ranges);
                let shape = arg_shape(
                    node.child_by_field_name("arguments"),
                    src,
                    js_is_static_string,
                );
                state.calls.push(RawCall {
                    line,
                    receiver: receiver.clone(),
                    method: method.clone(),
                    containing_fn: scope.clone(),
                    snippet: py_snippet(src, node),
                    static_args: shape.2.clone(),
                    arithmetic_args: Vec::new(),
                    unit_args: Vec::new(),
                    arg_count: shape.0,
                    first_arg_symbol: shape.1.clone(),
                    property_read: false,
                });
                let (arg_symbols, arg_slots) = js_identifier_args(node, src);
                state.call_args.push(CallArgFact {
                    function_qnode: scope,
                    line,
                    callee_name: method,
                    receiver,
                    arg_symbols,
                    arg_slots,
                    target_symbol: js_call_target(node, src),
                });
            }
        }
        "member_expression" => {
            let property = node
                .child_by_field_name("property")
                .map(|p| py_text(p, src))
                .unwrap_or_default();
            let receiver = js_leftmost_identifier(node, src);
            if !property.is_empty() && !receiver.is_empty() && js_is_property_read(node) {
                let line = node.start_position().row + 1;
                let scope = scope_for(node.start_byte(), &state.fn_ranges);
                state.calls.push(RawCall {
                    line,
                    receiver: receiver.clone(),
                    method: property.clone(),
                    containing_fn: scope.clone(),
                    snippet: py_snippet(src, node),
                    static_args: Vec::new(),
                    arithmetic_args: Vec::new(),
                    unit_args: Vec::new(),
                    arg_count: Some(0),
                    first_arg_symbol: None,
                    property_read: true,
                });
                state.call_args.push(CallArgFact {
                    function_qnode: scope,
                    line,
                    callee_name: property,
                    receiver,
                    arg_symbols: Vec::new(),
                    arg_slots: Vec::new(),
                    target_symbol: js_call_target(node, src),
                });
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        js_visit(child, src, state);
    }
}

fn js_extract(src: &[u8], root: Node) -> ExtractResult {
    let mut state = JsExtractState::default();
    js_visit(root, src, &mut state);
    ExtractResult {
        imports: state.imports,
        functions: state.functions,
        calls: state.calls,
        assigns: state.assigns,
        returns: state.returns,
        call_args: state.call_args,
    }
}

// ── Java plugin ───────────────────────────────────────────────────────────
// tree-sitter-java node types: import_declaration, scoped_identifier,
// method_declaration, constructor_declaration, class_declaration,
// method_invocation (fields: object?, name), object_creation_expression
// (field: type), field_access (field: object, field).

pub(crate) fn java_leftmost_identifier(node: Node, src: &[u8]) -> String {
    let mut cur = node;
    loop {
        match cur.kind() {
            "identifier" => return py_text(cur, src),
            "field_access" => {
                let Some(next) = cur.child_by_field_name("object").or_else(|| cur.child(0)) else {
                    return String::new();
                };
                cur = next;
            }
            // Unlike `field_access`, a missing `object` field here is a
            // dead end, not a fall through to the first child — matches
            // `_java_leftmost`'s own asymmetric handling exactly.
            "method_invocation" => {
                let Some(next) = cur.child_by_field_name("object") else {
                    return String::new();
                };
                cur = next;
            }
            _ => {
                let Some(next) = cur.child(0) else {
                    return String::new();
                };
                cur = next;
            }
        }
    }
}

static GENERICS_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]*>").unwrap());

/// Strip generics/arrays/annotations so type lookups stay stable.
fn java_normalize_type_name(raw: &str) -> String {
    let t = GENERICS_RX.replace_all(raw, "");
    let t = t.replace("[]", "");
    t.split_whitespace().next_back().unwrap_or("").to_string()
}

fn java_resolve_type(raw: &str, imports: &BTreeMap<String, String>, package_name: &str) -> String {
    let t = java_normalize_type_name(raw);
    if t.is_empty() {
        return String::new();
    }
    if t.contains('.') {
        return t;
    }
    if let Some(v) = imports.get(&t) {
        return v.clone();
    }
    if !package_name.is_empty() {
        return format!("{package_name}.{t}");
    }
    t
}

/// Best-effort concrete type extraction from Java expressions: `new
/// Foo(...)` or a cast expression like `(Foo) value`.
fn java_ctor_type_from_node(
    node: Option<Node>,
    src: &[u8],
    imports: &BTreeMap<String, String>,
    package_name: &str,
) -> String {
    let Some(node) = node else {
        return String::new();
    };
    match node.kind() {
        "object_creation_expression" | "cast_expression" => node
            .child_by_field_name("type")
            .map(|t| java_resolve_type(&py_text(t, src), imports, package_name))
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn java_invocation_parts(node: Node, src: &[u8]) -> (String, String) {
    let method = node
        .child_by_field_name("name")
        .map(|n| py_text(n, src))
        .unwrap_or_default();
    let receiver = node
        .child_by_field_name("object")
        .map(|o| java_leftmost_identifier(o, src))
        .unwrap_or_default();
    (receiver, method)
}

/// Java's counterpart to [`py_value_symbols`]: `+` concatenation,
/// `String.format(...)`/`String.join(...)` and `StringBuilder` chains.
/// Java has no interpolated string literal, so `binary_expression` and
/// nested invocations are the whole composition surface.
fn java_value_symbols(node: Node, src: &[u8], depth: usize, out: &mut Vec<String>) {
    if depth > COMPOSED_VALUE_MAX_DEPTH {
        return;
    }
    match node.kind() {
        "identifier" => push_symbol(out, py_text(node, src)),
        "binary_expression"
        | "parenthesized_expression"
        | "ternary_expression"
        | "cast_expression"
        | "unary_expression" => {
            for c in named_kids(node) {
                java_value_symbols(c, src, depth + 1, out);
            }
        }
        "method_invocation" => {
            if let Some(args) = node.child_by_field_name("arguments") {
                for c in named_kids(args) {
                    java_value_symbols(c, src, depth + 1, out);
                }
            }
            // A fluent builder nests each call in the next one's
            // `object` (`sb.append(a).append(b).toString()`), so the
            // chain has to be walked for `StringBuilder` composition to
            // reach the taint plane at all. Only chained invocations —
            // never a plain receiver variable, which is the builder
            // itself and not a value flowing into the result.
            if let Some(obj) = node
                .child_by_field_name("object")
                .filter(|o| o.kind() == "method_invocation")
            {
                java_value_symbols(obj, src, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// Parameter names of a Java method or constructor, a varargs
/// `int... rest` included. See [`FuncDef::params`].
fn java_param_names(fn_node: Node, src: &[u8]) -> Vec<String> {
    let Some(params) = fn_node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_kids(params)
        .filter_map(|p| match p.kind() {
            "formal_parameter" => p.child_by_field_name("name"),
            "spread_parameter" => named_kids(p)
                .find(|c| c.kind() == "variable_declarator")
                .and_then(|d| d.child_by_field_name("name")),
            _ => None,
        })
        .map(|n| py_text(n, src))
        .collect()
}

fn java_identifier_args(call_node: Node, src: &[u8]) -> (Vec<String>, Vec<usize>) {
    slotted_arg_symbols(
        call_node.child_by_field_name("arguments"),
        src,
        java_value_symbols,
    )
}

/// See [`py_first_arg_is_static_string`]. Java string literals cannot
/// interpolate, so being a literal at all is enough.
/// Java string literals cannot interpolate, so being a literal at all
/// is enough. See [`py_is_static_string`].
fn java_is_static_string(node: Node) -> bool {
    node.kind() == "string_literal"
}

fn java_call_target(node: Node, src: &[u8]) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() == "assignment_expression" {
        let left = parent.child_by_field_name("left");
        let right = parent.child_by_field_name("right");
        if let (Some(left), Some(right)) = (left, right) {
            if right == node && left.kind() == "identifier" {
                return Some(py_text(left, src));
            }
        }
    }
    if parent.kind() == "variable_declarator" {
        let val = parent.child_by_field_name("value");
        let name = parent.child_by_field_name("name");
        if let (Some(val), Some(name)) = (val, name) {
            if val == node && name.kind() == "identifier" {
                return Some(py_text(name, src));
            }
        }
    }
    None
}

/// Symbols a Java `return` hands back — see [`py_return_symbols`] for
/// why the original's single-`identifier` gate is a defect.
fn java_return_symbols(ret_node: Node, src: &[u8]) -> Vec<String> {
    let val = ret_node
        .child_by_field_name("value")
        .or_else(|| named_kids(ret_node).next());
    let mut out = Vec::new();
    if let Some(val) = val {
        java_value_symbols(val, src, 0, &mut out);
    }
    out
}

/// `(src_symbols, src_call)` for an assignment/declaration's RHS —
/// shared by `local_variable_declaration` and `assignment_expression`
/// handling, which the Python original duplicates inline identically
/// (`_java_extract`'s two near-verbatim `if val_node.type == ...` /
/// `if right.type == ...` blocks). Python reports at most one symbol; a
/// `"…" + a + b` RHS has several operands, each of which is its own
/// alias fact.
fn java_value_source(value_node: Node, src: &[u8]) -> (Vec<String>, Option<String>) {
    match value_node.kind() {
        "method_invocation" => {
            let (_recv, method) = java_invocation_parts(value_node, src);
            (Vec::new(), (!method.is_empty()).then_some(method))
        }
        "object_creation_expression" => {
            let src_call = value_node.child_by_field_name("type").and_then(|t| {
                let text = py_text(t, src);
                let tail = text.rsplit('.').next().unwrap_or("").trim().to_string();
                (!tail.is_empty()).then_some(tail)
            });
            (Vec::new(), src_call)
        }
        _ => {
            let mut out = Vec::new();
            java_value_symbols(value_node, src, 0, &mut out);
            (out, None)
        }
    }
}

/// One [`VarAssignFact`] per composed-value operand, or one carrying
/// `src_call` when the RHS is a call/constructor. Shared by the Java and
/// C# assignment handlers, which are structurally identical here.
fn push_assign_facts(
    out: &mut Vec<VarAssignFact>,
    function_qnode: &str,
    line: usize,
    dst_symbol: &str,
    src_symbols: Vec<String>,
    src_call: Option<String>,
) {
    if let Some(call) = src_call {
        out.push(VarAssignFact {
            function_qnode: function_qnode.to_string(),
            line,
            dst_symbol: dst_symbol.to_string(),
            src_symbol: None,
            src_call: Some(call),
        });
        return;
    }
    if src_symbols.is_empty() {
        // "Assigned from literals alone" is a fact worth recording, not
        // an absence: it is what tells `requires_dynamic_arg` that a
        // query assembled into this local is bound rather than built.
        // `push_return_facts` already carries the same symbol-less
        // shape for the same kind of reason.
        out.push(VarAssignFact {
            function_qnode: function_qnode.to_string(),
            line,
            dst_symbol: dst_symbol.to_string(),
            src_symbol: None,
            src_call: None,
        });
        return;
    }
    for sym in src_symbols {
        out.push(VarAssignFact {
            function_qnode: function_qnode.to_string(),
            line,
            dst_symbol: dst_symbol.to_string(),
            src_symbol: Some(sym),
            src_call: None,
        });
    }
}

/// One [`ReturnFact`] per returned symbol, or a single symbol-less fact
/// when the returned expression carries none — Python always records
/// exactly one fact per `return`, and the symbol-less shape is what
/// `_callee_may_return_tainted` reads as "returns nothing tainted".
fn push_return_facts(
    out: &mut Vec<ReturnFact>,
    function_qnode: &str,
    line: usize,
    symbols: Vec<String>,
) {
    if symbols.is_empty() {
        out.push(ReturnFact {
            function_qnode: function_qnode.to_string(),
            line,
            symbol: None,
        });
        return;
    }
    for sym in symbols {
        out.push(ReturnFact {
            function_qnode: function_qnode.to_string(),
            line,
            symbol: Some(sym),
        });
    }
}

#[derive(Default)]
struct JavaExtractState {
    imports: BTreeMap<String, String>,
    functions: Vec<FuncDef>,
    fn_ranges: Vec<(usize, usize, String)>,
    calls: Vec<RawCall>,
    assigns: Vec<VarAssignFact>,
    returns: Vec<ReturnFact>,
    call_args: Vec<CallArgFact>,
    class_stack: Vec<String>,
    package_name: String,
    local_types: BTreeMap<String, String>,
}

fn java_visit_local_variable_declaration(node: Node, src: &[u8], state: &mut JavaExtractState) {
    let Some(type_node) = node.child_by_field_name("type") else {
        return;
    };
    let resolved_type = java_resolve_type(
        &py_text(type_node, src),
        &state.imports,
        &state.package_name,
    );
    if resolved_type.is_empty() {
        return;
    }
    let mut cursor = node.walk();
    for c in node.children(&mut cursor) {
        if c.kind() != "variable_declarator" {
            continue;
        }
        let Some(n) = c.child_by_field_name("name") else {
            continue;
        };
        let name = py_text(n, src);
        let init = c.child_by_field_name("value");
        let narrowed = java_ctor_type_from_node(init, src, &state.imports, &state.package_name);
        state.local_types.insert(
            name.clone(),
            if narrowed.is_empty() {
                resolved_type.clone()
            } else {
                narrowed
            },
        );
        let Some(val_node) = init else {
            continue;
        };
        let (src_symbols, src_call) = java_value_source(val_node, src);
        push_assign_facts(
            &mut state.assigns,
            &scope_for(node.start_byte(), &state.fn_ranges),
            node.start_position().row + 1,
            &name,
            src_symbols,
            src_call,
        );
    }
}

fn java_visit_assignment_expression(node: Node, src: &[u8], state: &mut JavaExtractState) {
    let left = node.child_by_field_name("left");
    let right = node.child_by_field_name("right");
    let (Some(left), Some(right)) = (left, right) else {
        return;
    };
    if left.kind() != "identifier" {
        return;
    }
    let narrowed = java_ctor_type_from_node(Some(right), src, &state.imports, &state.package_name);
    if !narrowed.is_empty() {
        state.local_types.insert(py_text(left, src), narrowed);
    }
    let (src_symbols, src_call) = java_value_source(right, src);
    push_assign_facts(
        &mut state.assigns,
        &scope_for(node.start_byte(), &state.fn_ranges),
        node.start_position().row + 1,
        &py_text(left, src),
        src_symbols,
        src_call,
    );
}

fn java_visit(node: Node, src: &[u8], state: &mut JavaExtractState) {
    match node.kind() {
        "package_declaration" => {
            let mut cursor = node.walk();
            let found = node
                .children(&mut cursor)
                .find(|c| c.kind() == "scoped_identifier");
            if let Some(c) = found {
                state.package_name = py_text(c, src);
            }
        }
        "import_declaration" => {
            let mut qname = String::new();
            let mut is_wildcard = false;
            let mut cursor = node.walk();
            for c in node.children(&mut cursor) {
                match c.kind() {
                    "scoped_identifier" => qname = py_text(c, src),
                    "asterisk" => is_wildcard = true,
                    _ => {}
                }
            }
            if !qname.is_empty() && !is_wildcard {
                let top = qname.rsplit('.').next().unwrap_or("").to_string();
                state.imports.insert(top, qname);
            }
        }
        "class_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let cls = py_text(name_node, src);
                if !cls.is_empty() {
                    let fq = if state.package_name.is_empty() {
                        cls.clone()
                    } else {
                        format!("{}.{cls}", state.package_name)
                    };
                    state.imports.insert(cls.clone(), fq);
                    state.class_stack.push(cls);
                    let mut cursor = node.walk();
                    for c in node.children(&mut cursor) {
                        java_visit(c, src, state);
                    }
                    state.class_stack.pop();
                    return;
                }
            }
        }
        "method_declaration" | "constructor_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let fname = py_text(name_node, src);
                state.functions.push(FuncDef {
                    name: fname.clone(),
                    class_name: state.class_stack.last().cloned().unwrap_or_default(),
                    start_line: node.start_position().row + 1,
                    end_line: node.end_position().row + 1,
                    params: java_param_names(node, src),
                });
                state
                    .fn_ranges
                    .push((node.start_byte(), node.end_byte(), fname));
            }
        }
        "formal_parameter" | "catch_formal_parameter" => {
            let name_node = node.child_by_field_name("name");
            let type_node = node.child_by_field_name("type");
            if let (Some(n), Some(t)) = (name_node, type_node) {
                let resolved =
                    java_resolve_type(&py_text(t, src), &state.imports, &state.package_name);
                state.local_types.insert(py_text(n, src), resolved);
            }
        }
        "local_variable_declaration" => java_visit_local_variable_declaration(node, src, state),
        "assignment_expression" => java_visit_assignment_expression(node, src, state),
        "method_invocation" => {
            let (receiver, method) = java_invocation_parts(node, src);
            if !method.is_empty() {
                let line = node.start_position().row + 1;
                let scope = scope_for(node.start_byte(), &state.fn_ranges);
                let snippet = py_snippet(src, node);
                let shape = arg_shape(
                    node.child_by_field_name("arguments"),
                    src,
                    java_is_static_string,
                );
                state.calls.push(RawCall {
                    line,
                    receiver: receiver.clone(),
                    method: method.clone(),
                    containing_fn: scope.clone(),
                    snippet,
                    static_args: shape.2.clone(),
                    arithmetic_args: Vec::new(),
                    unit_args: Vec::new(),
                    arg_count: shape.0,
                    first_arg_symbol: shape.1.clone(),
                    property_read: false,
                });
                let (arg_symbols, arg_slots) = java_identifier_args(node, src);
                state.call_args.push(CallArgFact {
                    function_qnode: scope,
                    line,
                    callee_name: method,
                    receiver,
                    arg_symbols,
                    arg_slots,
                    target_symbol: java_call_target(node, src),
                });
            }
        }
        "object_creation_expression" => {
            if let Some(type_node) = node.child_by_field_name("type") {
                let cls = py_text(type_node, src)
                    .rsplit('.')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !cls.is_empty() {
                    let line = node.start_position().row + 1;
                    let scope = scope_for(node.start_byte(), &state.fn_ranges);
                    let snippet = py_snippet(src, node);
                    let shape = arg_shape(
                        node.child_by_field_name("arguments"),
                        src,
                        java_is_static_string,
                    );
                    state.calls.push(RawCall {
                        line,
                        receiver: String::new(),
                        method: cls.clone(),
                        containing_fn: scope.clone(),
                        snippet,
                        static_args: shape.2.clone(),
                        arithmetic_args: Vec::new(),
                        unit_args: Vec::new(),
                        arg_count: shape.0,
                        first_arg_symbol: shape.1.clone(),
                        property_read: false,
                    });
                    let (arg_symbols, arg_slots) = java_identifier_args(node, src);
                    state.call_args.push(CallArgFact {
                        function_qnode: scope,
                        line,
                        callee_name: cls,
                        receiver: String::new(),
                        arg_symbols,
                        arg_slots,
                        target_symbol: java_call_target(node, src),
                    });
                }
            }
        }
        "return_statement" => {
            push_return_facts(
                &mut state.returns,
                &scope_for(node.start_byte(), &state.fn_ranges),
                node.start_position().row + 1,
                java_return_symbols(node, src),
            );
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        java_visit(child, src, state);
    }
}

fn java_extract(src: &[u8], root: Node) -> ExtractResult {
    let mut state = JavaExtractState::default();
    java_visit(root, src, &mut state);
    // Lightweight type hints for variable receivers: let matcher resolve
    // receiver variables through inferred declaration/parameter types.
    for (k, v) in state.local_types {
        if !v.is_empty() {
            state.imports.insert(k, v);
        }
    }
    ExtractResult {
        imports: state.imports,
        functions: state.functions,
        calls: state.calls,
        assigns: state.assigns,
        returns: state.returns,
        call_args: state.call_args,
    }
}

// ── Go plugin ─────────────────────────────────────────────────────────────
// tree-sitter-go node types: import_declaration, import_spec_list,
// import_spec (fields: name?, path), function_declaration,
// method_declaration, call_expression (fields: function, arguments),
// selector_expression (fields: operand, field), short_var_declaration /
// assignment_statement (fields: left, right — both `expression_list`),
// var_spec (repeated `name` fields + `value`), return_statement.
//
// **Divergence: Go now carries the same fact set Python/Java/C# do.**
// `_go_extract` returns empty `assigns`/`returns`/`call_args` lists and
// no `FuncDef.params`, which meant every Go source→sink pair reached
// `_build_taint_evidence_for_path` with nothing to walk: no local was
// ever tainted, no `arg_to_param` boundary could be crossed, and the
// only evidence a Go repo could produce was the bare `edges: []`
// fallback. That is the same blind spot the composed-value section
// above documents for Python, one level worse — not "the operands are
// invisible" but "the whole intra-procedural plane is". The extractor
// below emits them, so Go grounds exactly like Python does.

fn go_leftmost_identifier(node: Node, src: &[u8]) -> String {
    let mut cur = node;
    loop {
        match cur.kind() {
            "identifier" => return py_text(cur, src),
            "selector_expression" => {
                let Some(next) = cur.child_by_field_name("operand").or_else(|| cur.child(0)) else {
                    return String::new();
                };
                cur = next;
            }
            "call_expression" => {
                let Some(next) = cur.child_by_field_name("function") else {
                    return String::new();
                };
                cur = next;
            }
            _ => {
                let Some(next) = cur.child(0) else {
                    return String::new();
                };
                cur = next;
            }
        }
    }
}

fn go_import_spec(spec: Node, src: &[u8], imports: &mut BTreeMap<String, String>) {
    let Some(path_node) = spec.child_by_field_name("path") else {
        return;
    };
    let name_node = spec.child_by_field_name("name");
    let path = py_text(path_node, src).trim_matches(['"', '`']).to_string();
    let alias = name_node
        .map(|n| py_text(n, src))
        .unwrap_or_else(|| path.rsplit('/').next().unwrap_or("").to_string());
    if !alias.is_empty() && alias != "." && alias != "_" {
        imports.insert(alias, path);
    }
}

/// Go's counterpart to [`py_value_symbols`]: `+` concatenation,
/// `fmt.Sprintf`/`fmt.Sprint`/`strings.Join` and any other nested call
/// (whose *arguments* carry the symbols), plus fluent chains such as
/// `exec.Command(...).Output()`. Go has no interpolated string literal,
/// so `binary_expression` and nested calls are the whole composition
/// surface. A `composite_literal` (`[]string{a, b}`) is deliberately not
/// descended into, exactly as Python's collection literals are not — see
/// the "composed-value symbols" section above.
fn go_value_symbols(node: Node, src: &[u8], depth: usize, out: &mut Vec<String>) {
    if depth > COMPOSED_VALUE_MAX_DEPTH {
        return;
    }
    match node.kind() {
        "identifier" => push_symbol(out, py_text(node, src)),
        "binary_expression"
        | "parenthesized_expression"
        | "unary_expression"
        | "type_conversion_expression"
        | "expression_list" => {
            for c in named_kids(node) {
                go_value_symbols(c, src, depth + 1, out);
            }
        }
        "call_expression" => {
            if let Some(args) = node.child_by_field_name("arguments") {
                for c in named_kids(args) {
                    go_value_symbols(c, src, depth + 1, out);
                }
            }
            // `exec.Command(a).Output()` nests the inner call in the
            // outer selector's `operand`, so the chain has to be walked
            // for the composed value to reach the taint plane — the same
            // shape `java_value_symbols` walks for `StringBuilder`.
            if let Some(op) = node
                .child_by_field_name("function")
                .and_then(|f| f.child_by_field_name("operand"))
                .filter(|o| o.kind() == "call_expression")
            {
                go_value_symbols(op, src, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// `(receiver, method)` for a Go call expression.
fn go_call_parts(node: Node, src: &[u8]) -> (String, String) {
    let Some(fn_node) = node.child_by_field_name("function") else {
        return (String::new(), String::new());
    };
    match fn_node.kind() {
        "selector_expression" => {
            let method = fn_node
                .child_by_field_name("field")
                .map(|f| py_text(f, src))
                .unwrap_or_default();
            (go_leftmost_identifier(fn_node, src), method)
        }
        "identifier" => (String::new(), py_text(fn_node, src)),
        _ => (String::new(), String::new()),
    }
}

/// Parameter names of a Go function or method in caller slot order. A
/// `parameter_declaration` may name several parameters of one type
/// (`func f(a, b string)`), so every `name` field is read, not just the
/// first; `variadic_parameter_declaration` (`rest ...string`) names one.
/// A method's receiver lives in its own `receiver` field, never in
/// `parameters`, so it is excluded by construction. See [`FuncDef::params`].
fn go_param_names(fn_node: Node, src: &[u8]) -> Vec<String> {
    let Some(params) = fn_node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for p in named_kids(params) {
        if !matches!(
            p.kind(),
            "parameter_declaration" | "variadic_parameter_declaration"
        ) {
            continue;
        }
        let mut cursor = p.walk();
        for n in p.children_by_field_name("name", &mut cursor) {
            out.push(py_text(n, src));
        }
    }
    out
}

fn go_identifier_args(call_node: Node, src: &[u8]) -> (Vec<String>, Vec<usize>) {
    slotted_arg_symbols(
        call_node.child_by_field_name("arguments"),
        src,
        go_value_symbols,
    )
}

/// See [`py_first_arg_is_static_string`]. Go string literals cannot
/// interpolate, so being a literal at all is enough.
/// Go string literals cannot interpolate. See [`py_is_static_string`].
fn go_is_static_string(node: Node) -> bool {
    matches!(
        node.kind(),
        "interpreted_string_literal" | "raw_string_literal"
    )
}

/// Symbols a Go `return` hands back — see [`py_return_symbols`]. A Go
/// `return` wraps its values in an `expression_list`, which
/// [`go_value_symbols`] descends.
fn go_return_symbols(ret_node: Node, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for c in named_kids(ret_node) {
        go_value_symbols(c, src, 0, &mut out);
    }
    out
}

/// `(src_symbols, src_call)` for one Go RHS expression — the Go
/// analogue of [`java_value_source`].
fn go_value_source(value_node: Node, src: &[u8]) -> (Vec<String>, Option<String>) {
    if value_node.kind() == "call_expression" {
        let (_recv, method) = go_call_parts(value_node, src);
        return (Vec::new(), (!method.is_empty()).then_some(method));
    }
    let mut out = Vec::new();
    go_value_symbols(value_node, src, 0, &mut out);
    (out, None)
}

/// Pair each assignment target with the RHS expression it takes its
/// value from. Go assigns list-to-list (`a, b = x, y`) and also spreads
/// one multi-valued call across every target (`rows, err := db.Query(q)`),
/// so a single RHS element speaks for every target.
fn go_assign_pairs<'a>(lefts: Vec<Node<'a>>, right: Node<'a>) -> Vec<(Node<'a>, Node<'a>)> {
    let rights: Vec<Node<'a>> = named_kids(right).collect();
    let Some(first) = rights.first().copied() else {
        return Vec::new();
    };
    lefts
        .into_iter()
        .enumerate()
        .map(|(i, l)| (l, rights.get(i).copied().unwrap_or(first)))
        .collect()
}

/// `(assignment targets, RHS list)` for the statement `node` is the
/// right-hand side of, when there is one: `x, y := f()`, `x = v`, and
/// `var x = f()` all reach here. `None` for a call in any other
/// position.
fn go_enclosing_assignment<'a>(node: Node<'a>) -> Option<(Vec<Node<'a>>, Node<'a>)> {
    let list = node.parent().filter(|p| p.kind() == "expression_list")?;
    let stmt = list.parent()?;
    match stmt.kind() {
        "short_var_declaration" | "assignment_statement" => {
            let right = stmt.child_by_field_name("right")?;
            if right != list {
                return None;
            }
            let left = stmt.child_by_field_name("left")?;
            Some((named_kids(left).collect(), list))
        }
        "var_spec" => {
            let mut cursor = stmt.walk();
            let names = stmt.children_by_field_name("name", &mut cursor).collect();
            Some((names, list))
        }
        _ => None,
    }
}

/// The local a Go call's result is bound to, if any. `_` (the blank
/// identifier) is not a symbol anything can read back, so it never
/// becomes a taint target.
fn go_call_target(node: Node, src: &[u8]) -> Option<String> {
    let (lefts, right) = go_enclosing_assignment(node)?;
    let name = go_assign_pairs(lefts, right)
        .into_iter()
        .find(|(_, r)| *r == node)
        .map(|(l, _)| l)
        .filter(|l| l.kind() == "identifier")?;
    let text = py_text(name, src);
    (text != "_").then_some(text)
}

/// Method names on a `strings.Builder`/`bytes.Buffer` that append their
/// argument to the receiver. Go's builders are statement-driven
/// (`sb.WriteString(v)`), not fluent like Java's, so the composed-value
/// walker cannot see them; each write is recorded as an alias from the
/// written value into the builder variable instead, which is exactly
/// what `_apply_local_aliases` needs to carry taint into the later
/// `sb.String()`.
const GO_BUILDER_WRITES: &[&str] = &["Write", "WriteByte", "WriteRune", "WriteString"];

#[derive(Default)]
struct GoExtractState {
    imports: BTreeMap<String, String>,
    functions: Vec<FuncDef>,
    fn_ranges: Vec<(usize, usize, String)>,
    calls: Vec<RawCall>,
    assigns: Vec<VarAssignFact>,
    returns: Vec<ReturnFact>,
    call_args: Vec<CallArgFact>,
}

/// One `x, y := …` / `x = …` / `var x = …` statement's alias facts.
fn go_visit_assignment(
    lefts: Vec<Node>,
    right: Node,
    src: &[u8],
    line: usize,
    scope: &str,
    out: &mut Vec<VarAssignFact>,
) {
    for (l, r) in go_assign_pairs(lefts, right) {
        if l.kind() != "identifier" {
            continue;
        }
        let dst = py_text(l, src);
        if dst == "_" {
            continue;
        }
        let (src_symbols, src_call) = go_value_source(r, src);
        push_assign_facts(out, scope, line, &dst, src_symbols, src_call);
    }
}

fn go_visit(node: Node, src: &[u8], state: &mut GoExtractState) {
    match node.kind() {
        "import_declaration" => {
            let mut cursor = node.walk();
            for c in node.children(&mut cursor) {
                match c.kind() {
                    "import_spec" => go_import_spec(c, src, &mut state.imports),
                    "import_spec_list" => {
                        let mut gc_cursor = c.walk();
                        for gc in c.children(&mut gc_cursor) {
                            if gc.kind() == "import_spec" {
                                go_import_spec(gc, src, &mut state.imports);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        "function_declaration" | "method_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let fname = py_text(name_node, src);
                state.functions.push(FuncDef {
                    name: fname.clone(),
                    class_name: String::new(),
                    start_line: node.start_position().row + 1,
                    end_line: node.end_position().row + 1,
                    params: go_param_names(node, src),
                });
                state
                    .fn_ranges
                    .push((node.start_byte(), node.end_byte(), fname));
            }
        }
        "call_expression" => {
            let (receiver, method) = go_call_parts(node, src);
            if !method.is_empty() {
                let line = node.start_position().row + 1;
                let scope = scope_for(node.start_byte(), &state.fn_ranges);
                let shape = arg_shape(
                    node.child_by_field_name("arguments"),
                    src,
                    go_is_static_string,
                );
                state.calls.push(RawCall {
                    line,
                    receiver: receiver.clone(),
                    method: method.clone(),
                    containing_fn: scope.clone(),
                    snippet: py_snippet(src, node),
                    static_args: shape.2.clone(),
                    arithmetic_args: Vec::new(),
                    unit_args: Vec::new(),
                    arg_count: shape.0,
                    first_arg_symbol: shape.1.clone(),
                    property_read: false,
                });
                let (arg_symbols, arg_slots) = go_identifier_args(node, src);
                if !receiver.is_empty() && GO_BUILDER_WRITES.contains(&method.as_str()) {
                    for sym in &arg_symbols {
                        push_assign_facts(
                            &mut state.assigns,
                            &scope,
                            line,
                            &receiver,
                            vec![sym.clone()],
                            None,
                        );
                    }
                }
                state.call_args.push(CallArgFact {
                    function_qnode: scope,
                    line,
                    callee_name: method,
                    receiver,
                    arg_symbols,
                    arg_slots,
                    target_symbol: go_call_target(node, src),
                });
            }
        }
        "short_var_declaration" | "assignment_statement" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            if let (Some(left), Some(right)) = (left, right) {
                go_visit_assignment(
                    named_kids(left).collect(),
                    right,
                    src,
                    node.start_position().row + 1,
                    &scope_for(node.start_byte(), &state.fn_ranges),
                    &mut state.assigns,
                );
            }
        }
        "var_spec" => {
            if let Some(value) = node.child_by_field_name("value") {
                let mut cursor = node.walk();
                let names = node.children_by_field_name("name", &mut cursor).collect();
                go_visit_assignment(
                    names,
                    value,
                    src,
                    node.start_position().row + 1,
                    &scope_for(node.start_byte(), &state.fn_ranges),
                    &mut state.assigns,
                );
            }
        }
        "return_statement" => {
            push_return_facts(
                &mut state.returns,
                &scope_for(node.start_byte(), &state.fn_ranges),
                node.start_position().row + 1,
                go_return_symbols(node, src),
            );
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        go_visit(child, src, state);
    }
}

fn go_extract(src: &[u8], root: Node) -> ExtractResult {
    let mut state = GoExtractState::default();
    go_visit(root, src, &mut state);
    ExtractResult {
        imports: state.imports,
        functions: state.functions,
        calls: state.calls,
        assigns: state.assigns,
        returns: state.returns,
        call_args: state.call_args,
    }
}

// ── C# plugin ─────────────────────────────────────────────────────────────
// tree-sitter-c-sharp node types: using_directive (field: name),
// method_declaration, constructor_declaration, local_function_statement,
// invocation_expression (fields: function, arguments),
// member_access_expression (fields: expression, name),
// object_creation_expression (field: type). Unlike Java, C# does no
// declared/narrowed-type resolution at all (no `local_types`/
// `_resolve_type` equivalent — `_cs_extract` never has one either);
// receiver/method extraction is purely structural.

pub(crate) fn cs_leftmost_identifier(node: Node, src: &[u8]) -> String {
    let mut cur = node;
    loop {
        match cur.kind() {
            "identifier" => return py_text(cur, src),
            "member_access_expression" => {
                let Some(next) = cur
                    .child_by_field_name("expression")
                    .or_else(|| cur.child(0))
                else {
                    return String::new();
                };
                cur = next;
            }
            // Unlike Java's `method_invocation` (which dead-ends on a
            // missing `function` field), C#'s own `_cs_leftmost` falls
            // back to the first child here too — matches the Python
            // original's asymmetry with Java exactly.
            "invocation_expression" | "element_access_expression" => {
                let Some(next) = cur.child_by_field_name("function").or_else(|| cur.child(0))
                else {
                    return String::new();
                };
                cur = next;
            }
            _ => {
                let Some(next) = cur.child(0) else {
                    return String::new();
                };
                cur = next;
            }
        }
    }
}

fn cs_invocation_parts(node: Node, src: &[u8]) -> (String, String) {
    let fn_node = node
        .child_by_field_name("function")
        .or_else(|| node.child(0));
    let mut method = String::new();
    let mut receiver = String::new();
    if let Some(fn_node) = fn_node {
        match fn_node.kind() {
            "member_access_expression" => {
                method = fn_node
                    .child_by_field_name("name")
                    .map(|n| py_text(n, src))
                    .unwrap_or_default();
                receiver = cs_leftmost_identifier(fn_node, src);
            }
            "identifier" => method = py_text(fn_node, src),
            _ => {}
        }
    }
    (receiver, method)
}

/// C#'s counterpart to [`py_value_symbols`]: `$"…{x}…"` interpolated
/// strings, `+` concatenation and `string.Format(...)`/`.Append(...)`
/// chains. `argument` is C#'s own one-level wrapper around each
/// argument expression, which the original already unwrapped.
fn cs_value_symbols(node: Node, src: &[u8], depth: usize, out: &mut Vec<String>) {
    if depth > COMPOSED_VALUE_MAX_DEPTH {
        return;
    }
    match node.kind() {
        "identifier" => push_symbol(out, py_text(node, src)),
        "interpolated_string_expression"
        | "interpolation"
        | "binary_expression"
        | "parenthesized_expression"
        | "conditional_expression"
        | "cast_expression"
        | "prefix_unary_expression"
        | "postfix_unary_expression"
        | "argument" => {
            for c in named_kids(node) {
                cs_value_symbols(c, src, depth + 1, out);
            }
        }
        "invocation_expression" => {
            if let Some(args) = node.child_by_field_name("arguments") {
                for c in named_kids(args) {
                    cs_value_symbols(c, src, depth + 1, out);
                }
            }
            // Fluent `sb.Append(a).Append(b)` chains, as in Java.
            if let Some(func) = node.child_by_field_name("function") {
                if let Some(recv) = func
                    .child_by_field_name("expression")
                    .filter(|e| e.kind() == "invocation_expression")
                {
                    cs_value_symbols(recv, src, depth + 1, out);
                }
            }
        }
        _ => {}
    }
}

/// Parameter names of a C# method, constructor or local function. See
/// [`FuncDef::params`].
fn cs_param_names(fn_node: Node, src: &[u8]) -> Vec<String> {
    let Some(params) = fn_node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_kids(params)
        .filter(|p| p.kind() == "parameter")
        .filter_map(|p| p.child_by_field_name("name"))
        .map(|n| py_text(n, src))
        .collect()
}

fn cs_identifier_args(call_node: Node, src: &[u8]) -> (Vec<String>, Vec<usize>) {
    slotted_arg_symbols(
        call_node.child_by_field_name("arguments"),
        src,
        cs_value_symbols,
    )
}

/// See [`py_first_arg_is_static_string`]. C# wraps each argument in an
/// `argument` node; a verbatim/raw literal is as static as a plain one,
/// and an interpolated literal only counts when it interpolates
/// nothing.
fn cs_is_static_string(node: Node) -> bool {
    match node.kind() {
        "argument" => named_kids(node).next().is_some_and(cs_is_static_string),
        "string_literal" | "verbatim_string_literal" | "raw_string_literal" => true,
        "interpolated_string_expression" => !named_kids(node).any(|c| c.kind() == "interpolation"),
        _ => false,
    }
}

/// Walk out of the wrappers a bound value sits inside — `await`, and the
/// `expression` position of an indexer or a longer member chain
/// (`Request.Query` inside `Request.Query["id"]`) — to the node a
/// declaration actually binds. Without it, an ASP.NET request read would
/// report no assignment target and every C# property source would be
/// inert, exactly as `var q = Console.ReadLine();` was before the
/// `variable_declarator` fallback below.
fn cs_bound_value(node: Node) -> Node {
    let mut cur = node;
    while let Some(p) = cur.parent() {
        let wraps = match p.kind() {
            "await_expression" | "parenthesized_expression" => true,
            "element_access_expression" | "member_access_expression" => {
                p.child_by_field_name("expression") == Some(cur)
            }
            _ => false,
        };
        if !wraps {
            break;
        }
        cur = p;
    }
    cur
}

/// A `member_access_expression` that is being *read*: not the callee of
/// an invocation (that is already a call site) and not the target of an
/// assignment (that is a write).
fn cs_is_property_read(node: Node) -> bool {
    let Some(parent) = node.parent() else {
        return true;
    };
    match parent.kind() {
        // C# wraps each argument in an `argument` node, so an
        // `invocation_expression` parent can only be the callee.
        "invocation_expression" => false,
        "assignment_expression" | "simple_assignment_expression" => {
            parent.child_by_field_name("left") != Some(node)
        }
        _ => true,
    }
}

fn cs_call_target(node: Node, src: &[u8]) -> Option<String> {
    let node = cs_bound_value(node);
    let parent = node.parent()?;
    if matches!(
        parent.kind(),
        "assignment_expression" | "simple_assignment_expression"
    ) {
        let left = parent.child_by_field_name("left");
        let right = parent.child_by_field_name("right");
        if let (Some(left), Some(right)) = (left, right) {
            if right == node && left.kind() == "identifier" {
                return Some(py_text(left, src));
            }
        }
    }
    if parent.kind() == "equals_value_clause" {
        if let Some(gp) = parent.parent() {
            if gp.kind() == "variable_declarator" {
                if let Some(name) = gp.child_by_field_name("name") {
                    if name.kind() == "identifier" {
                        return Some(py_text(name, src));
                    }
                }
            }
        }
    }
    if parent.kind() == "variable_declarator" {
        let name = parent.child_by_field_name("name");
        // tree-sitter-c-sharp's `variable_declarator` has a `name` field
        // but NO `value` field — the initializer is an unnamed child
        // after `=` (the same grammar quirk `cs_visit_variable_declarator`
        // already works around). Requiring a `value` field here made
        // `var q = Console.ReadLine();` report no assignment target at
        // all, so `_seed_source_taint` had nothing to taint and *every*
        // C# source bound to a local was inert.
        let value = parent
            .child_by_field_name("value")
            .or_else(|| named_kids(parent).find(|vc| Some(*vc) != name));
        if let (Some(name), Some(value)) = (name, value) {
            if value == node && name.kind() == "identifier" {
                return Some(py_text(name, src));
            }
        }
    }
    None
}

/// Symbols a C# `return` hands back — see [`py_return_symbols`].
fn cs_return_symbols(ret_node: Node, src: &[u8]) -> Vec<String> {
    let expr = ret_node
        .child_by_field_name("expression")
        .or_else(|| named_kids(ret_node).next());
    let mut out = Vec::new();
    if let Some(expr) = expr {
        cs_value_symbols(expr, src, 0, &mut out);
    }
    out
}

/// `(src_symbols, src_call)` for an assignment/declarator's RHS — the C#
/// analogue of `java_value_source`, over `invocation_expression` instead
/// of `method_invocation`.
fn cs_value_source(value_node: Node, src: &[u8]) -> (Vec<String>, Option<String>) {
    match value_node.kind() {
        "invocation_expression" => {
            let (_recv, method) = cs_invocation_parts(value_node, src);
            (Vec::new(), (!method.is_empty()).then_some(method))
        }
        "object_creation_expression" => {
            let src_call = value_node.child_by_field_name("type").and_then(|t| {
                let text = py_text(t, src);
                let tail = text.rsplit('.').next().unwrap_or("").trim().to_string();
                (!tail.is_empty()).then_some(tail)
            });
            (Vec::new(), src_call)
        }
        _ => {
            let mut out = Vec::new();
            cs_value_symbols(value_node, src, 0, &mut out);
            (out, None)
        }
    }
}

fn cs_assignment_parts(node: Node, src: &[u8]) -> (Option<String>, Vec<String>, Option<String>) {
    let left = node.child_by_field_name("left");
    let right = node.child_by_field_name("right");
    let (Some(left), Some(right)) = (left, right) else {
        return (None, Vec::new(), None);
    };
    if left.kind() != "identifier" {
        return (None, Vec::new(), None);
    }
    let (src_symbols, src_call) = cs_value_source(right, src);
    (Some(py_text(left, src)), src_symbols, src_call)
}

#[derive(Default)]
struct CsExtractState {
    imports: BTreeMap<String, String>,
    functions: Vec<FuncDef>,
    fn_ranges: Vec<(usize, usize, String)>,
    calls: Vec<RawCall>,
    assigns: Vec<VarAssignFact>,
    returns: Vec<ReturnFact>,
    call_args: Vec<CallArgFact>,
    class_stack: Vec<String>,
}

fn cs_visit_variable_declarator(node: Node, src: &[u8], state: &mut CsExtractState) {
    let name_node = node.child_by_field_name("name");
    // C# grammar: `variable_declarator` has a `name` field but no
    // `value` field — the initializer is an unnamed child after `=`.
    // Walk named_children to find the first child that isn't the name.
    let value_node = node.child_by_field_name("value").or_else(|| {
        let mut cursor = node.walk();
        let found = node
            .named_children(&mut cursor)
            .find(|vc| Some(*vc) != name_node);
        found
    });
    let (Some(name_node), Some(value_node)) = (name_node, value_node) else {
        return;
    };
    if name_node.kind() != "identifier" {
        return;
    }
    let (src_symbols, src_call) = cs_value_source(value_node, src);
    push_assign_facts(
        &mut state.assigns,
        &scope_for(node.start_byte(), &state.fn_ranges),
        node.start_position().row + 1,
        &py_text(name_node, src),
        src_symbols,
        src_call,
    );
}

fn cs_visit(node: Node, src: &[u8], state: &mut CsExtractState) {
    match node.kind() {
        "using_directive" => {
            let name_node = node.child_by_field_name("name").or_else(|| {
                let mut cursor = node.walk();
                let found = node
                    .children(&mut cursor)
                    .find(|c| matches!(c.kind(), "qualified_name" | "identifier"));
                found
            });
            if let Some(name_node) = name_node {
                let qname = py_text(name_node, src);
                let top = qname.rsplit('.').next().unwrap_or("").to_string();
                state.imports.insert(top, qname);
            }
        }
        "class_declaration" | "struct_declaration" | "interface_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let cls = py_text(name_node, src);
                if !cls.is_empty() {
                    state.class_stack.push(cls);
                    let mut cursor = node.walk();
                    for c in node.children(&mut cursor) {
                        cs_visit(c, src, state);
                    }
                    state.class_stack.pop();
                    return;
                }
            }
        }
        "method_declaration" | "constructor_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let fname = py_text(name_node, src);
                state.functions.push(FuncDef {
                    name: fname.clone(),
                    class_name: state.class_stack.last().cloned().unwrap_or_default(),
                    start_line: node.start_position().row + 1,
                    end_line: node.end_position().row + 1,
                    params: cs_param_names(node, src),
                });
                state
                    .fn_ranges
                    .push((node.start_byte(), node.end_byte(), fname));
            }
        }
        "local_function_statement" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let fname = py_text(name_node, src);
                state.functions.push(FuncDef {
                    name: fname.clone(),
                    class_name: String::new(),
                    start_line: node.start_position().row + 1,
                    end_line: node.end_position().row + 1,
                    params: cs_param_names(node, src),
                });
                state
                    .fn_ranges
                    .push((node.start_byte(), node.end_byte(), fname));
            }
        }
        "invocation_expression" => {
            let (receiver, method) = cs_invocation_parts(node, src);
            if !method.is_empty() {
                let line = node.start_position().row + 1;
                let scope = scope_for(node.start_byte(), &state.fn_ranges);
                let snippet = py_snippet(src, node);
                let shape = arg_shape(
                    node.child_by_field_name("arguments"),
                    src,
                    cs_is_static_string,
                );
                state.calls.push(RawCall {
                    line,
                    receiver: receiver.clone(),
                    method: method.clone(),
                    containing_fn: scope.clone(),
                    snippet,
                    static_args: shape.2.clone(),
                    arithmetic_args: Vec::new(),
                    unit_args: Vec::new(),
                    arg_count: shape.0,
                    first_arg_symbol: shape.1.clone(),
                    property_read: false,
                });
                let (arg_symbols, arg_slots) = cs_identifier_args(node, src);
                state.call_args.push(CallArgFact {
                    function_qnode: scope,
                    line,
                    callee_name: method,
                    receiver,
                    arg_symbols,
                    arg_slots,
                    target_symbol: cs_call_target(node, src),
                });
            }
        }
        "object_creation_expression" => {
            let cls = node.child_by_field_name("type").and_then(|type_node| {
                let cls = py_text(type_node, src)
                    .rsplit('.')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                (!cls.is_empty()).then_some(cls)
            });
            if let Some(cls) = cls {
                let line = node.start_position().row + 1;
                let scope = scope_for(node.start_byte(), &state.fn_ranges);
                let snippet = py_snippet(src, node);
                let shape = arg_shape(
                    node.child_by_field_name("arguments"),
                    src,
                    cs_is_static_string,
                );
                state.calls.push(RawCall {
                    line,
                    receiver: String::new(),
                    method: cls.clone(),
                    containing_fn: scope.clone(),
                    snippet,
                    static_args: shape.2.clone(),
                    arithmetic_args: Vec::new(),
                    unit_args: Vec::new(),
                    arg_count: shape.0,
                    first_arg_symbol: shape.1.clone(),
                    property_read: false,
                });
                let (arg_symbols, arg_slots) = cs_identifier_args(node, src);
                state.call_args.push(CallArgFact {
                    function_qnode: scope,
                    line,
                    callee_name: cls,
                    receiver: String::new(),
                    arg_symbols,
                    arg_slots,
                    target_symbol: cs_call_target(node, src),
                });
            }
        }
        "member_access_expression" => {
            let name = node
                .child_by_field_name("name")
                .map(|n| py_text(n, src))
                .unwrap_or_default();
            let receiver = cs_leftmost_identifier(node, src);
            if !name.is_empty() && !receiver.is_empty() && cs_is_property_read(node) {
                let line = node.start_position().row + 1;
                let scope = scope_for(node.start_byte(), &state.fn_ranges);
                state.calls.push(RawCall {
                    line,
                    receiver: receiver.clone(),
                    method: name.clone(),
                    containing_fn: scope.clone(),
                    snippet: py_snippet(src, node),
                    static_args: Vec::new(),
                    arithmetic_args: Vec::new(),
                    unit_args: Vec::new(),
                    arg_count: Some(0),
                    first_arg_symbol: None,
                    property_read: true,
                });
                state.call_args.push(CallArgFact {
                    function_qnode: scope,
                    line,
                    callee_name: name,
                    receiver,
                    arg_symbols: Vec::new(),
                    arg_slots: Vec::new(),
                    target_symbol: cs_call_target(node, src),
                });
            }
        }
        "assignment_expression" | "simple_assignment_expression" => {
            let (dst, src_symbols, src_call) = cs_assignment_parts(node, src);
            if let Some(dst) = dst {
                push_assign_facts(
                    &mut state.assigns,
                    &scope_for(node.start_byte(), &state.fn_ranges),
                    node.start_position().row + 1,
                    &dst,
                    src_symbols,
                    src_call,
                );
            }
        }
        "variable_declarator" => cs_visit_variable_declarator(node, src, state),
        "return_statement" => {
            push_return_facts(
                &mut state.returns,
                &scope_for(node.start_byte(), &state.fn_ranges),
                node.start_position().row + 1,
                cs_return_symbols(node, src),
            );
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        cs_visit(child, src, state);
    }
}

fn cs_extract(src: &[u8], root: Node) -> ExtractResult {
    let mut state = CsExtractState::default();
    cs_visit(root, src, &mut state);
    ExtractResult {
        imports: state.imports,
        functions: state.functions,
        calls: state.calls,
        assigns: state.assigns,
        returns: state.returns,
        call_args: state.call_args,
    }
}

// ── framework parameter bindings as sources ──────────────────────────────

/// Marker types that name a parameter *bound from request input* —
/// Spring's `@RequestParam`/`@PathVariable`/`@RequestBody`/…, JAX-RS's
/// `@QueryParam`/…, ASP.NET's `[FromQuery]`/… and NestJS's
/// `@Query()`/`@Body()`/`@Param()`. Route markers and the implicit
/// type-based ones are deliberately absent: those say "this handler is
/// reachable from the network", which is an entry point, not "this
/// symbol holds attacker input", which is a source.
const BINDING_MARKER_TYPES: &[&str] = &[
    "aspnet_annotation",
    "jaxrs_annotation",
    "nestjs_annotation",
    // A PHP superglobal read is the one binding marker that names no
    // parameter: `$_GET['q']` reads request input straight into an
    // expression. It still marks the function as a place attacker input
    // enters, which is what a source is.
    "php_superglobal",
    "spring_annotation",
];

/// The rule id [`framework_binding_sources`] reports for a source that
/// is an annotation rather than a call.
pub const FRAMEWORK_BINDING_RULE: &str = "vvah.framework.binding";

/// Source hits and call-argument facts for the parameters a web
/// framework binds from request input.
///
/// **No Python counterpart, and it is why the whole annotation plane was
/// inert.** `_scan.py` records these markers and `_graph.py` reads them
/// only to emit entry points, so `@RequestParam("file") String name`
/// marks a handler as network-reachable and then contributes *nothing*
/// to the taint plane: the parameter it names is never tainted, and any
/// sink that parameter reaches has no source to pair with. Field
/// evidence (2026-09-07): a five-file Spring app produced taint paths
/// for the one flow that happened to read `request.getParameter(...)` —
/// a call — and none for the two that bind their input by annotation,
/// which is how most Spring, JAX-RS, ASP.NET and NestJS code is
/// written. A binding annotation *is* a source, and is spelled as one
/// here in exactly the `CallSite` + [`CallArgFact`] pair
/// `_seed_source_taint` already consumes: the fact's `target_symbol` is
/// the bound parameter, so the walk taints it by name on entry.
fn framework_binding_sources(
    rel: &str,
    markers: &[FrameworkMarkerFact],
) -> (Vec<CallSite>, Vec<CallArgFact>) {
    let mut hits = Vec::new();
    let mut facts = Vec::new();
    for m in markers {
        if !BINDING_MARKER_TYPES.contains(&m.marker_type.as_str()) {
            continue;
        }
        let bound: Vec<&String> = m.parameter_names.iter().filter(|p| !p.is_empty()).collect();
        hits.push(CallSite {
            file: rel.to_string(),
            line: m.line,
            receiver: String::new(),
            method: m.marker_name.clone(),
            containing_fn: m.function_qnode.clone(),
            snippet: format!("{} {}", m.marker_name, m.parameter_names.join(", ")),
            matched_rule: FRAMEWORK_BINDING_RULE.to_string(),
            cwe: "CWE-20".to_string(),
            role: "source".to_string(),
            kind: "http".to_string(),
            semantic_family: "other".to_string(),
            owasp_top10_2025: crate::families::owasp_labels("other")
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        });
        for p in bound {
            facts.push(CallArgFact {
                function_qnode: m.function_qnode.clone(),
                line: m.line,
                callee_name: m.marker_name.clone(),
                receiver: String::new(),
                arg_symbols: Vec::new(),
                arg_slots: Vec::new(),
                target_symbol: Some(p.clone()),
            });
        }
    }
    (hits, facts)
}

/// Axum's request extractors. A handler binds request input by
/// destructuring one in its own signature — `Query(params):
/// Query<SearchParams>` — so the binding is a *parameter pattern*,
/// neither an annotation nor a call. `State` is deliberately absent: it
/// carries application state, not request input.
const AXUM_EXTRACTORS: &[&str] = &[
    "Form",
    "Json",
    "Multipart",
    "Path",
    "Query",
    "RawQuery",
    "TypedHeader",
];

/// Source hits and call-argument facts for a Rust handler's axum
/// extractor parameters — the [`framework_binding_sources`] of a
/// language whose bindings are patterns.
///
/// [`lite`] records a parameter's pattern verbatim, which is the only
/// place an axum binding is visible: actix and rocket spell the same
/// thing as a parameter *type* (`id: web::Path<u32>`), which that
/// extractor does not record, so those two frameworks are a documented
/// gap rather than an oversight.
fn extractor_binding_sources(
    rel: &str,
    functions: &[FuncDef],
) -> (Vec<CallSite>, Vec<CallArgFact>) {
    let mut hits = Vec::new();
    let mut facts = Vec::new();
    for f in functions {
        for p in &f.params {
            let Some((wrapper, bound)) = p.split_once('(') else {
                continue;
            };
            let Some(bound) = bound.strip_suffix(')') else {
                continue;
            };
            if !AXUM_EXTRACTORS.contains(&wrapper) || bound.is_empty() {
                continue;
            }
            hits.push(CallSite {
                file: rel.to_string(),
                line: f.start_line,
                receiver: String::new(),
                method: wrapper.to_string(),
                containing_fn: f.name.clone(),
                snippet: p.clone(),
                matched_rule: FRAMEWORK_BINDING_RULE.to_string(),
                cwe: "CWE-20".to_string(),
                role: "source".to_string(),
                kind: "http".to_string(),
                semantic_family: "other".to_string(),
                owasp_top10_2025: crate::families::owasp_labels("other")
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            });
            facts.push(CallArgFact {
                function_qnode: f.name.clone(),
                line: f.start_line,
                callee_name: wrapper.to_string(),
                receiver: String::new(),
                arg_symbols: Vec::new(),
                arg_slots: Vec::new(),
                target_symbol: Some(bound.to_string()),
            });
        }
    }
    (hits, facts)
}

// ── semantic sink fallback (Iteration B) ─────────────────────────────────

struct SemanticSink {
    kind: &'static str,
    cwe: &'static str,
    family: &'static str,
    owasp: &'static [&'static str],
}

/// Repo-agnostic semantic sink detection: covers framework
/// response-render paths that aren't always captured by API-call
/// signature rules.
fn semantic_sink_override(
    language: &str,
    receiver: &str,
    method: &str,
    snippet: &str,
) -> Option<SemanticSink> {
    let low = snippet.to_lowercase();
    let m = method.to_lowercase();
    let r = receiver.to_lowercase();

    if language == "python"
        && matches!(
            m.as_str(),
            "response" | "htmlresponse" | "httpresponse" | "render_template" | "templateresponse"
        )
    {
        if low.contains("html")
            && (snippet.contains('{') || low.contains(".format(") || snippet.contains('+'))
        {
            return Some(SemanticSink {
                kind: "xss",
                cwe: "CWE-79",
                family: "html-response",
                owasp: &["A03:2025-Injection"],
            });
        }
        if matches!(m.as_str(), "render_template" | "templateresponse") {
            return Some(SemanticSink {
                kind: "xss",
                cwe: "CWE-79",
                family: "html-response",
                owasp: &["A03:2025-Injection"],
            });
        }
    }

    if language == "java"
        && matches!(m.as_str(), "print" | "println" | "write")
        && (matches!(r.as_str(), "response" | "writer" | "out")
            || low.contains("httpservletresponse"))
        && (snippet.contains('<') || low.contains("format(") || snippet.contains('+'))
    {
        return Some(SemanticSink {
            kind: "xss",
            cwe: "CWE-79",
            family: "html-response",
            owasp: &["A03:2025-Injection"],
        });
    }

    None
}

// ── matching ─────────────────────────────────────────────────────────────

/// `language -> method -> specs`, built once per scan (not per file).
/// Includes fallback buckets: language `"*"` for specs that don't
/// declare languages, method `"*"` for specs that don't declare
/// methods.
pub type SpecIndex<'a> = BTreeMap<String, BTreeMap<String, Vec<&'a MatchSpec>>>;

pub fn build_spec_index(specs: &[MatchSpec]) -> SpecIndex<'_> {
    let mut idx: SpecIndex = BTreeMap::new();
    for spec in specs {
        let langs: Vec<String> = if spec.languages.is_empty() {
            vec!["*".to_string()]
        } else {
            spec.languages.iter().cloned().collect()
        };
        let methods: Vec<String> = if !spec.methods.is_empty() {
            spec.methods.iter().cloned().collect()
        } else if !spec.module_attr_names.is_empty() {
            spec.module_attr_names.iter().cloned().collect()
        } else if !spec.receiver_method_names.is_empty() {
            spec.receiver_method_names.iter().cloned().collect()
        } else if !spec.bare_call_names.is_empty() {
            spec.bare_call_names.iter().cloned().collect()
        } else {
            vec!["*".to_string()]
        };
        for lang in &langs {
            for method in &methods {
                idx.entry(lang.clone())
                    .or_default()
                    .entry(method.clone())
                    .or_default()
                    .push(spec);
            }
        }
    }
    idx
}

/// Return the first spec whose fingerprint matches this call. `receiver`
/// is `""` for bare-name calls. `static_args` reports which of the
/// call's positional arguments are static string literals, which
/// [`MatchSpec::requires_dynamic_arg`] rules reject; `arithmetic_args`
/// reports which are `*`/`+` expressions, which
/// [`MatchSpec::requires_arithmetic_arg`] rules REQUIRE; `unit_args`
/// reports which are the integer literal `1`, which
/// [`MatchSpec::requires_unit_arg`] rules REQUIRE.
///
/// Every predicate a spec carries has to hold, each at its own index,
/// so a spec naming two of them expresses a CONJUNCTION across two
/// arguments — which is how the corpus asks for `calloc`'s
/// hand-multiplied shape (arithmetic at 0 *and* a unit size at 1)
/// without this function knowing that `calloc` exists.
#[allow(clippy::too_many_arguments)]
fn match_call<'a>(
    receiver: &str,
    method: &str,
    imports: &BTreeMap<String, String>,
    specs: &[&'a MatchSpec],
    language: &str,
    static_args: &[bool],
    arithmetic_args: &[bool],
    unit_args: &[bool],
    arg_count: Option<usize>,
) -> Option<&'a MatchSpec> {
    // PHP writes every variable with a `$` sigil, so its receivers
    // arrive as `$request`/`$pdo`. The sigil is part of the token, not
    // of the name a rule spells, and no other language can start a
    // receiver with one.
    let receiver = receiver.trim_start_matches('$');
    let resolved = if receiver.is_empty() {
        ""
    } else {
        imports.get(receiver).map(String::as_str).unwrap_or("")
    };
    for &spec in specs {
        if !spec.languages.contains(language) {
            continue;
        }
        // A query built entirely out of a literal is bound, not
        // injected: `cur.execute("… LIKE ?", (email,))` is the shape
        // this keeps out of the SQL sink set.
        if spec.requires_dynamic_arg && static_arg_at(static_args, spec.dynamic_arg_index) {
            continue;
        }
        // An allocation whose size is a bare name cannot wrap at this
        // call site: `malloc(len)` allocates exactly what `len` says,
        // while `malloc(count * size)` allocates whatever the product
        // truncates to. Absent per-argument shapes read as "not
        // arithmetic", so a rule asking this simply does not fire for
        // an extractor that cannot answer — see
        // [`MatchSpec::requires_arithmetic_arg`] on why that polarity
        // is the only honest one here.
        if spec.requires_arithmetic_arg
            && !arithmetic_args
                .get(spec.arithmetic_arg_index)
                .copied()
                .unwrap_or(false)
        {
            continue;
        }
        // An element size of literally `1` is what tells `calloc(n *
        // size, 1)` — which did the multiply by hand and defeated
        // `calloc`'s own overflow check — from the idiomatic
        // `calloc(n, size)` that did not. Same polarity as
        // `requires_arithmetic_arg`, and paired WITH it on the one rule
        // that asks: two predicates on one spec are ANDed, so the
        // corpus gets its two-argument condition without a special case
        // here. See [`MatchSpec::requires_unit_arg`].
        if spec.requires_unit_arg && !unit_args.get(spec.unit_arg_index).copied().unwrap_or(false) {
            continue;
        }
        // A JDBC `statement.executeQuery()` with no argument is the
        // prepared form; the SQL was fixed when the statement was
        // prepared, so there is nothing here to inject into.
        if spec.requires_any_arg && arg_count == Some(0) {
            continue;
        }
        // ── qualified match (codeql / fsb) ──────────────────────────
        if spec.has_qualified() {
            if spec.is_constructor {
                if receiver.is_empty() && spec.methods.contains(method) {
                    let ctor_import = imports.get(method).map(String::as_str).unwrap_or("");
                    if ctor_import.starts_with(&spec.package) {
                        return Some(spec);
                    }
                }
                continue;
            }
            if !spec.methods.contains(method) {
                continue;
            }
            if resolved.is_empty() {
                continue;
            }
            if resolved == spec.package || resolved.starts_with(&format!("{}.", spec.package)) {
                return Some(spec);
            }
            // Gap 1 recall guard: when only a narrowed class tail is
            // available, accept `...<ClassName>` for JVM-style
            // qualified rules.
            if matches!(language, "java" | "csharp" | "kotlin" | "scala") {
                let cls_tail = spec.class_name.rsplit('.').next().unwrap_or("");
                if !cls_tail.is_empty()
                    && (resolved == cls_tail || resolved.ends_with(&format!(".{cls_tail}")))
                {
                    return Some(spec);
                }
            }
            // `from java.sql import Statement; s = Statement();
            // s.executeQuery(...)` — the receiver is a variable, not an
            // import. Skipped for MVP (requires type inference).
            continue;
        }
        // ── module_attr match (semgrep-lifted) ──────────────────────
        if spec.has_module_attr() {
            if !spec.module_attr_names.contains(method) {
                continue;
            }
            if receiver == spec.module_attr_module {
                return Some(spec);
            }
            if resolved == spec.module_attr_module
                || resolved.starts_with(&format!("{}.", spec.module_attr_module))
                || resolved.ends_with(&format!(".{}", spec.module_attr_module))
            {
                return Some(spec);
            }
        }
        // ── bare-call match (`open(...)`) ───────────────────────────
        // Receiver-less by construction: `from flask import send_file`
        // then `send_file(p)`, or a builtin. A qualified
        // `flask.send_file(p)` is the module_attr shape instead, and
        // rule packs that want both spell both.
        if spec.has_bare_call() && receiver.is_empty() && spec.bare_call_names.contains(method) {
            return Some(spec);
        }
        // ── receiver-method match (`$CUR.execute(...)`) ─────────────
        // Deliberately receiver-agnostic: the whole point is the
        // instance-method sink whose receiver is a local variable no
        // import table can resolve.
        if spec.has_receiver_method()
            && !receiver.is_empty()
            && spec.receiver_method_names.contains(method)
        {
            return Some(spec);
        }
    }
    None
}

fn specs_for<'a>(
    index: Option<&SpecIndex<'a>>,
    fallback: &[&'a MatchSpec],
    language: &str,
    method: &str,
) -> Vec<&'a MatchSpec> {
    let Some(index) = index else {
        return fallback.to_vec();
    };
    let by_lang = index.get(language);
    let by_any = index.get("*");
    let mut out = Vec::new();
    for bucket in [by_lang, by_any] {
        let Some(bucket) = bucket else { continue };
        if let Some(v) = bucket.get(method) {
            out.extend(v.iter().copied());
        }
        if let Some(v) = bucket.get("*") {
            out.extend(v.iter().copied());
        }
    }
    out
}

// ── entry point ──────────────────────────────────────────────────────────

/// Parses `abs_path` (a `rel`-relative file already confirmed to be
/// `language`) with tree-sitter, matches source/sink call sites, and
/// returns the resulting [`FileIndex`]. `None` when the file can't be
/// scanned at all (unsupported language, unreadable, or empty) — not an
/// error, matching the Python original's own degrade-not-raise
/// contract.
#[allow(clippy::too_many_arguments)]
pub fn scan_file(
    abs_path: &Path,
    rel: &str,
    language: &str,
    source_specs: &[MatchSpec],
    sink_specs: &[MatchSpec],
    collect_observed: bool,
    source_index: Option<&SpecIndex>,
    sink_index: Option<&SpecIndex>,
) -> Option<FileIndex> {
    let ts_lang = ts_language(&normalize_lang_for_grammar(rel, language))?;
    let src = std::fs::read(abs_path).ok()?;
    if src.is_empty() {
        return None;
    }
    let mut parser = Parser::new();
    parser.set_language(&ts_lang).ok()?;
    let tree: Tree = parser.parse(&src, None)?;
    let extracted = extract(language, &src, tree.root_node())?;

    let literal_only = literal_only_symbols(&extracted.assigns, &extracted.call_args);
    let source_fallback: Vec<&MatchSpec> = source_specs.iter().collect();
    let sink_fallback: Vec<&MatchSpec> = sink_specs.iter().collect();

    let root = tree.root_node();
    // Field/container, reflection, framework and response facts each do
    // their own tree walk, exactly as `_scan.py::scan_file` (L2813-2837)
    // does, so the language plugin's own extract signature stays
    // unchanged. `FileIndex.cfgs` has no counterpart here: Python's
    // `scan_file` calls `_build_cfg_for_function(None, ...)` on every
    // function, and that helper returns `None` for a `None` node, so the
    // field is unconditionally empty there too.
    let (field_writes, field_reads, container_writes) =
        crate::facts::extract_field_facts(language, &src, root);
    let (framework_markers, route_facts, auth_guards) =
        crate::framework::extract_framework_facts(language, rel, &src, root);
    // A parameter a framework binds from request input is a source in
    // its own right — see [`framework_binding_sources`].
    let (mut binding_sources, mut binding_call_args) =
        framework_binding_sources(rel, &framework_markers);
    if language == "rust" {
        let (hits, facts) = extractor_binding_sources(rel, &extracted.functions);
        binding_sources.extend(hits);
        binding_call_args.extend(facts);
    }

    let mut idx = FileIndex {
        file: rel.to_string(),
        language: language.to_string(),
        imports: extracted.imports.clone(),
        functions: extracted.functions,
        assigns: extracted.assigns,
        returns: extracted.returns,
        call_args: extracted.call_args,
        field_writes,
        field_reads,
        container_writes,
        reflection_facts: crate::reflection::extract_reflection_facts(language, &src, root),
        framework_markers,
        auth_guards,
        route_facts,
        response_dataflow: crate::framework::extract_response_dataflow(language, &src, root),
        source_hits: binding_sources,
        ..Default::default()
    };
    idx.call_args.extend(binding_call_args);

    for RawCall {
        line,
        receiver,
        method,
        containing_fn: scope,
        snippet,
        static_args,
        arithmetic_args,
        unit_args,
        arg_count,
        first_arg_symbol,
        property_read,
    } in extracted.calls
    {
        // A query assembled from literals into a local is bound, not
        // built — see [`literal_only_symbols`]. A call with no argument
        // at all is judged by its receiver instead: `cmd.ExecuteReader()`
        // executes whatever `cmd` was built with.
        let mut static_args = static_args;
        let bound_locally = first_arg_symbol
            .map(|sym| (scope.clone(), sym))
            .is_some_and(|key| literal_only.contains(&key))
            || (arg_count == Some(0)
                && !receiver.is_empty()
                && literal_only.contains(&(scope.clone(), receiver.clone())));
        if bound_locally {
            if static_args.is_empty() {
                static_args.push(true);
            } else {
                static_args[0] = true;
            }
        }
        let src_specs_lang = specs_for(source_index, &source_fallback, language, &method);
        let snk_specs_lang = specs_for(sink_index, &sink_fallback, language, &method);

        // Record the edge for BFS regardless of match status — but never
        // for a synthesized property read, which is not a call and whose
        // property name colliding with some function's would fabricate a
        // call-graph edge. See [`RawCall::property_read`].
        if !property_read {
            idx.call_edges
                .push((scope.clone(), receiver.clone(), method.clone()));
        }
        // Record the full call fingerprint for annotator-style LLM mode.
        if collect_observed && !property_read {
            idx.observed_calls.push(ObservedCall {
                file: rel.to_string(),
                language: language.to_string(),
                line,
                receiver: receiver.clone(),
                resolved_receiver: extracted
                    .imports
                    .get(&receiver)
                    .cloned()
                    .unwrap_or_default(),
                method: method.clone(),
                containing_fn: scope.clone(),
                snippet: snippet.clone(),
            });
        }

        if let Some(src_spec) = match_call(
            &receiver,
            &method,
            &extracted.imports,
            &src_specs_lang,
            language,
            &static_args,
            &arithmetic_args,
            &unit_args,
            arg_count,
        ) {
            idx.source_hits.push(CallSite {
                file: rel.to_string(),
                line,
                receiver: receiver.clone(),
                method: method.clone(),
                containing_fn: scope.clone(),
                snippet: snippet.clone(),
                matched_rule: src_spec.rule_id.clone(),
                cwe: src_spec.cwe.clone(),
                role: "source".to_string(),
                kind: src_spec.kind.clone(),
                semantic_family: src_spec.semantic_family.clone(),
                owasp_top10_2025: src_spec.owasp_top10_2025.iter().cloned().collect(),
            });
            // A call can be BOTH a source and a sink (rare but valid).
        }
        // A property read is a read of data, never an execution: it can
        // be a source, but letting one match a sink spec would turn
        // every `foo.query` mention into a SQL sink, since the
        // receiver-method shape matches any receiver at all.
        if property_read {
            continue;
        }
        if let Some(snk_spec) = match_call(
            &receiver,
            &method,
            &extracted.imports,
            &snk_specs_lang,
            language,
            &static_args,
            &arithmetic_args,
            &unit_args,
            arg_count,
        ) {
            idx.sink_hits.push(CallSite {
                file: rel.to_string(),
                line,
                receiver: receiver.clone(),
                method: method.clone(),
                containing_fn: scope.clone(),
                snippet: snippet.clone(),
                matched_rule: snk_spec.rule_id.clone(),
                cwe: snk_spec.cwe.clone(),
                role: "sink".to_string(),
                kind: snk_spec.kind.clone(),
                semantic_family: snk_spec.semantic_family.clone(),
                owasp_top10_2025: snk_spec.owasp_top10_2025.iter().cloned().collect(),
            });
            continue;
        }

        // Iteration B semantic fallback: keep framework response sinks
        // even if the rule isn't representable as a module.attr
        // signature.
        if let Some(sem) = semantic_sink_override(language, &receiver, &method, &snippet) {
            idx.sink_hits.push(CallSite {
                file: rel.to_string(),
                line,
                receiver,
                method,
                containing_fn: scope,
                snippet,
                matched_rule: "vvah.semantic.sink".to_string(),
                cwe: sem.cwe.to_string(),
                role: "sink".to_string(),
                kind: sem.kind.to_string(),
                semantic_family: sem.family.to_string(),
                owasp_top10_2025: sem.owasp.iter().map(|s| s.to_string()).collect(),
            });
        }
    }

    Some(idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn write_py(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn parse(src: &[u8]) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        parser.parse(src, None).unwrap()
    }

    fn find_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(f) = find_kind(child, kind) {
                return Some(f);
            }
        }
        None
    }

    #[test]
    fn find_kind_none_when_no_node_of_that_kind_exists() {
        let tree = parse(b"x = 1\n");
        assert!(find_kind(tree.root_node(), "nonexistent_node_kind").is_none());
    }

    // ── composed-value symbols ───────────────────────────────────────
    //
    // Each of these shapes reported `arg_symbols == []` before, in this
    // port and in `_scan.py` alike, which is what stopped every real
    // Python taint path from grounding. See the "composed-value symbols"
    // section for the defect write-up.

    fn py_args(body: &str) -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", body);
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        idx.call_args
            .into_iter()
            .find(|c| c.callee_name == "system")
            .expect("no os.system call fact")
            .arg_symbols
    }

    #[test]
    fn py_arg_symbols_read_through_an_f_string() {
        assert_eq!(
            py_args("def f(host):\n    os.system(f\"ping -c 1 {host}\")\n"),
            vec!["host".to_string()]
        );
    }

    #[test]
    fn py_arg_symbols_read_through_a_concatenation_chain() {
        assert_eq!(
            py_args("def f(a, b):\n    os.system(\"x\" + a + \"y\" + b)\n"),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn py_arg_symbols_read_through_a_format_call() {
        // The `.format` receiver is the literal template, so only the
        // arguments contribute symbols.
        assert_eq!(
            py_args("def f(a):\n    os.system(\"ping {}\".format(a))\n"),
            vec!["a".to_string()]
        );
    }

    #[test]
    fn py_arg_symbols_read_through_percent_formatting() {
        assert_eq!(
            py_args("def f(a):\n    os.system(\"ping %s\" % a)\n"),
            vec!["a".to_string()]
        );
    }

    #[test]
    fn py_arg_symbols_read_through_a_nested_call() {
        // `send_file(report_path(name))` — the value the sink receives
        // is composed from `name`, one call deep.
        assert_eq!(
            py_args("def f(name):\n    os.system(shlex.quote(name))\n"),
            vec!["name".to_string()]
        );
    }

    #[test]
    fn py_arg_symbols_read_through_an_adjacent_literal_concatenation() {
        assert_eq!(
            py_args("def f(a):\n    os.system(\"x\" \"y\" + a)\n"),
            vec!["a".to_string()]
        );
    }

    #[test]
    fn py_arg_symbols_deduplicate_a_repeated_operand() {
        assert_eq!(
            py_args("def f(a):\n    os.system(f\"{a} and {a}\")\n"),
            vec!["a".to_string()]
        );
    }

    #[test]
    fn py_arg_symbols_do_not_descend_into_a_collection_literal() {
        // A bind-parameter tuple is a container of values, not a
        // composed string. Reading it as one is precisely the
        // parameterized-query false positive this must not produce.
        assert!(py_args("def f(a):\n    os.system(\"q\", (a,))\n").is_empty());
    }

    #[test]
    fn py_arg_symbols_carry_the_argument_slot_they_came_from() {
        // A literal-only first argument occupies slot 0 and contributes
        // nothing; the composed second argument and the bare third one
        // are slots 1 and 2 — not indices 0 and 1 of a flat list.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.py",
            "def f(a, b):\n    os.system(\"lit\", \"-v \" + a, b)\n",
        );
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        let fact = idx
            .call_args
            .into_iter()
            .find(|c| c.callee_name == "system")
            .expect("no os.system call fact");
        assert_eq!(fact.arg_symbols, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(fact.arg_slots, vec![1, 2]);
    }

    #[test]
    fn py_param_names_follow_caller_slots() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.py",
            "class A:\n    def m(self, a, b=1, *args, c: int = 2, **kw):\n        pass\n\n\
             def g(a, /, b: str, *, c):\n    pass\n",
        );
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        let params = |name: &str| {
            idx.functions
                .iter()
                .find(|f| f.name == name)
                .unwrap()
                .params
                .clone()
        };
        assert_eq!(params("m"), vec!["a", "b", "args", "c", "kw"]);
        assert_eq!(params("g"), vec!["a", "b", "c"]);
    }

    #[test]
    fn java_and_csharp_param_names_follow_caller_slots() {
        let dir = tempfile::tempdir().unwrap();
        let j = dir.path().join("A.java");
        std::fs::write(&j, "class A { void m(String a, int... rest) {} }\n").unwrap();
        let idx = scan_file(&j, "A.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.functions[0].params, vec!["a", "rest"]);
        let c = dir.path().join("A.cs");
        std::fs::write(&c, "class A { void M(string a, int b) { } }\n").unwrap();
        let idx = scan_file(&c, "A.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.functions[0].params, vec!["a", "b"]);
    }

    #[test]
    fn param_names_are_empty_when_the_node_has_no_parameters_field() {
        let src = b"x = 1\n";
        let tree = parse(src);
        let ident = find_kind(tree.root_node(), "identifier").unwrap();
        assert!(py_param_names(ident, src).is_empty());
        assert!(java_param_names(ident, src).is_empty());
        assert!(cs_param_names(ident, src).is_empty());
    }

    #[test]
    fn py_composite_assignment_records_one_alias_fact_per_operand() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.py",
            "def f(a, b):\n    v = \"%\" + a + b\n",
        );
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.assigns.len(), 2);
        assert!(idx.assigns.iter().all(|x| x.dst_symbol == "v"));
        let srcs: Vec<Option<&str>> = idx
            .assigns
            .iter()
            .map(|x| x.src_symbol.as_deref())
            .collect();
        assert_eq!(srcs, vec![Some("a"), Some("b")]);
    }

    #[test]
    fn py_composite_return_records_one_fact_per_operand() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.py",
            "def f(v):\n    return \"%\" + v + \"%\"\n",
        );
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        // `_callee_may_return_tainted` reads exactly this: without it a
        // string-building helper never hands taint back to its caller.
        assert_eq!(idx.returns.len(), 1);
        assert_eq!(idx.returns[0].symbol, Some("v".to_string()));
    }

    #[test]
    fn py_first_arg_is_static_string_distinguishes_bound_from_built_queries() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.py",
            "def f(p, q):\n    cur.execute(\"S ?\", (p,))\n    cur.execute(\"S \" + p)\n    cur.execute(q)\n    cur.execute(f\"S {p}\")\n",
        );
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        let src = std::fs::read(&path).unwrap();
        let tree = parse(&src);
        let mut statics = Vec::new();
        fn walk(n: Node, src: &[u8], out: &mut Vec<bool>) {
            if n.kind() == "call" {
                out.push(static_arg_at(
                    &arg_shape(n.child_by_field_name("arguments"), src, py_is_static_string).2,
                    0,
                ));
            }
            for c in kids(n) {
                walk(c, src, out);
            }
        }
        walk(tree.root_node(), &src, &mut statics);
        assert_eq!(statics, vec![true, false, false, false]);
        assert_eq!(idx.call_args.len(), 4);
    }

    #[test]
    fn py_first_arg_is_static_string_false_without_an_arguments_field() {
        // Defensive: every tree-sitter-python `call` has an `arguments`
        // field, but the helper is reachable from any node kind.
        let src = b"x = 1\n";
        let tree = parse(src);
        let ident = find_kind(tree.root_node(), "identifier").unwrap();
        assert!(!static_arg_at(
            &arg_shape(
                ident.child_by_field_name("arguments"),
                src,
                py_is_static_string
            )
            .2,
            0,
        ));
    }

    #[test]
    fn cs_arg_symbols_walk_a_fluent_append_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "A.cs",
            "class A {\n  void F(string a, string b) {\n    Run(sb.Append(a).Append(b).ToString());\n  }\n}\n",
        );
        let idx = scan_file(&path, "A.cs", "csharp", &[], &[], false, None, None).unwrap();
        let run = idx
            .call_args
            .iter()
            .find(|c| c.callee_name == "Run")
            .unwrap();
        assert_eq!(run.arg_symbols, vec!["b".to_string(), "a".to_string()]);
    }

    #[test]
    fn java_arg_symbols_read_through_concatenation_and_format_and_builders() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "A.java",
            "class A {\n  void f(String p) {\n    st.executeQuery(\"S \" + p);\n    st.executeUpdate(String.format(\"S %s\", p));\n    st.execute(sb.append(p).toString());\n  }\n}\n",
        );
        let idx = scan_file(&path, "A.java", "java", &[], &[], false, None, None).unwrap();
        let by = |name: &str| {
            idx.call_args
                .iter()
                .find(|c| c.callee_name == name)
                .unwrap()
                .arg_symbols
                .clone()
        };
        assert_eq!(by("executeQuery"), vec!["p".to_string()]);
        assert_eq!(by("executeUpdate"), vec!["p".to_string()]);
        // The builder chain is walked through `object`, which is the
        // only way `StringBuilder` composition reaches the taint plane.
        assert_eq!(by("execute"), vec!["p".to_string()]);
    }

    #[test]
    fn java_composite_rhs_and_return_record_every_operand() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "A.java",
            "class A {\n  String f(String a, String b) {\n    String q = \"x\" + a + b;\n    return \"y\" + q;\n  }\n}\n",
        );
        let idx = scan_file(&path, "A.java", "java", &[], &[], false, None, None).unwrap();
        let srcs: Vec<Option<&str>> = idx
            .assigns
            .iter()
            .map(|x| x.src_symbol.as_deref())
            .collect();
        assert_eq!(srcs, vec![Some("a"), Some("b")]);
        assert_eq!(idx.returns.len(), 1);
        assert_eq!(idx.returns[0].symbol, Some("q".to_string()));
    }

    #[test]
    fn cs_arg_symbols_read_through_interpolation_concatenation_and_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "A.cs",
            "class A {\n  void F(string p) {\n    Alpha($\"S {p}\");\n    Beta(\"S \" + p);\n    Gamma(string.Format(\"S {0}\", p));\n  }\n}\n",
        );
        let idx = scan_file(&path, "A.cs", "csharp", &[], &[], false, None, None).unwrap();
        let by = |name: &str| {
            idx.call_args
                .iter()
                .find(|c| c.callee_name == name)
                .unwrap()
                .arg_symbols
                .clone()
        };
        assert_eq!(by("Alpha"), vec!["p".to_string()]);
        assert_eq!(by("Beta"), vec!["p".to_string()]);
        assert_eq!(by("Gamma"), vec!["p".to_string()]);
    }

    #[test]
    fn cs_composite_rhs_and_return_record_every_operand() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "A.cs",
            "class A {\n  string F(string a, string b) {\n    var q = $\"{a}{b}\";\n    return q;\n  }\n}\n",
        );
        let idx = scan_file(&path, "A.cs", "csharp", &[], &[], false, None, None).unwrap();
        let srcs: Vec<Option<&str>> = idx
            .assigns
            .iter()
            .map(|x| x.src_symbol.as_deref())
            .collect();
        assert_eq!(srcs, vec![Some("a"), Some("b")]);
        assert_eq!(idx.returns[0].symbol, Some("q".to_string()));
    }

    #[test]
    fn cs_first_arg_is_static_string_accepts_a_zero_interpolation_literal() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "A.cs",
            "class A {\n  void F(string p) {\n    Alpha($\"plain\");\n    Beta($\"S {p}\");\n  }\n}\n",
        );
        let src = std::fs::read(&path).unwrap();
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&src, None).unwrap();
        let mut statics = Vec::new();
        fn walk(n: Node, src: &[u8], out: &mut Vec<bool>) {
            if n.kind() == "invocation_expression" {
                out.push(static_arg_at(
                    &arg_shape(n.child_by_field_name("arguments"), src, cs_is_static_string).2,
                    0,
                ));
            }
            for c in kids(n) {
                walk(c, src, out);
            }
        }
        walk(tree.root_node(), &src, &mut statics);
        assert_eq!(statics, vec![true, false]);
    }

    // ── Go composed-value symbols ────────────────────────────────────
    //
    // `_go_extract` emitted no call-argument facts at all, so every one
    // of these shapes reported nothing and no Go path could ground.

    /// `arg_symbols` of the `sink(...)` call in a Go file.
    fn go_args(body: &str) -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "main.go", body);
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        idx.call_args
            .into_iter()
            .find(|c| c.callee_name == "sink")
            .expect("no sink call fact")
            .arg_symbols
    }

    /// Wrap `stmts` in a Go function whose parameters are `a`/`b`.
    fn go_fn(stmts: &str) -> String {
        format!("package main\nfunc f(a string, b string) {{\n{stmts}}}\n")
    }

    #[test]
    fn go_arg_symbols_read_through_a_sprintf_call() {
        assert_eq!(
            go_args(&go_fn("\tsink(fmt.Sprintf(\"ping %s\", a))\n")),
            vec!["a".to_string()]
        );
    }

    #[test]
    fn go_arg_symbols_read_through_a_concatenation_chain() {
        assert_eq!(
            go_args(&go_fn("\tsink(\"echo \" + a + b)\n")),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn go_arg_symbols_read_through_strings_join_and_a_conversion() {
        assert_eq!(
            go_args(&go_fn("\tsink(strings.Join(a, \",\"), string(b))\n")),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn go_arg_symbols_walk_a_fluent_call_chain() {
        // `exec.Command(a).Output()` hides `a` inside the inner call's
        // arguments, reachable only through the selector's operand.
        assert_eq!(
            go_args(&go_fn("\tsink(exec.Command(a).Output())\n")),
            vec!["a".to_string()]
        );
    }

    #[test]
    fn go_arg_symbols_carry_the_argument_slot_they_came_from() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            &go_fn("\tsink(\"lit\", \"-v \"+a, b)\n"),
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        let fact = idx
            .call_args
            .into_iter()
            .find(|c| c.callee_name == "sink")
            .expect("no sink call fact");
        assert_eq!(fact.arg_symbols, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(fact.arg_slots, vec![1, 2]);
    }

    #[test]
    fn go_arg_symbols_do_not_descend_into_a_composite_literal() {
        assert!(go_args(&go_fn("\tsink([]string{a})\n")).is_empty());
    }

    #[test]
    fn go_param_names_cover_shared_types_variadics_and_exclude_the_receiver() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            "package main\n\
             func f(a, b string, c int, rest ...string) {}\n\
             func (h *H) M(x string) {}\n\
             func g() {}\n",
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        let params = |name: &str| {
            idx.functions
                .iter()
                .find(|f| f.name == name)
                .unwrap()
                .params
                .clone()
        };
        assert_eq!(params("f"), vec!["a", "b", "c", "rest"]);
        // The receiver `h` lives in its own field, never in `parameters`.
        assert_eq!(params("M"), vec!["x"]);
        assert!(params("g").is_empty());
    }

    #[test]
    fn go_composite_assignment_and_return_record_every_operand() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            &go_fn("\tq := \"x\" + a + b\n\treturn q, a\n"),
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        let srcs: Vec<Option<&str>> = idx
            .assigns
            .iter()
            .map(|x| x.src_symbol.as_deref())
            .collect();
        assert_eq!(srcs, vec![Some("a"), Some("b")]);
        let rets: Vec<Option<&str>> = idx.returns.iter().map(|r| r.symbol.as_deref()).collect();
        assert_eq!(rets, vec![Some("q"), Some("a")]);
    }

    #[test]
    fn go_multi_value_assignment_spreads_one_call_across_every_target() {
        // `rows, err := db.Query(q)` — one RHS, two targets; and the
        // blank identifier is never a taint target.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            &go_fn("\trows, err := db.Query(a)\n\t_, keep := split(b)\n\tx, y := a, b\n"),
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        let pairs: Vec<(&str, Option<&str>, Option<&str>)> = idx
            .assigns
            .iter()
            .map(|a| {
                (
                    a.dst_symbol.as_str(),
                    a.src_symbol.as_deref(),
                    a.src_call.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("rows", None, Some("Query")),
                ("err", None, Some("Query")),
                ("keep", None, Some("split")),
                ("x", Some("a"), None),
                ("y", Some("b"), None),
            ]
        );
    }

    #[test]
    fn go_var_declaration_with_an_initializer_records_an_alias() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            &go_fn("\tvar q = a\n\tvar u, v = a, b\n\tvar bare string\n"),
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        let pairs: Vec<(&str, Option<&str>)> = idx
            .assigns
            .iter()
            .map(|a| (a.dst_symbol.as_str(), a.src_symbol.as_deref()))
            .collect();
        assert_eq!(
            pairs,
            vec![("q", Some("a")), ("u", Some("a")), ("v", Some("b"))]
        );
    }

    #[test]
    fn go_call_target_is_recorded_for_a_short_declaration_and_an_assignment() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            &go_fn(
                "\tq := build(a)\n\tq = rebuild(b)\n\tvar v = declare(a)\n\
                 \t_ = drop(a)\n\tbare(a)\n\tm[a] = keyed(b)\n",
            ),
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        let targets: Vec<(&str, Option<&str>)> = idx
            .call_args
            .iter()
            .map(|c| (c.callee_name.as_str(), c.target_symbol.as_deref()))
            .collect();
        assert_eq!(
            targets,
            vec![
                ("build", Some("q")),
                ("rebuild", Some("q")),
                // `var v = …` binds through a `var_spec`, not an
                // expression list pair.
                ("declare", Some("v")),
                // The blank identifier is no symbol, a bare call binds
                // nothing, and an indexed target is not a plain local.
                ("drop", None),
                ("bare", None),
                ("keyed", None),
            ]
        );
        // The indexed assignment records no alias either.
        assert!(!idx.assigns.iter().any(|a| a.dst_symbol.contains('[')));
    }

    #[test]
    fn a_go_call_outside_an_assignment_binds_nothing() {
        // A call inside a `return`'s expression list reaches
        // `go_enclosing_assignment` but is not an assignment's RHS.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            "package main\nfunc f(a string) string {\n\treturn build(a)\n}\n",
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.call_args[0].callee_name, "build");
        assert_eq!(idx.call_args[0].target_symbol, None);
    }

    #[test]
    fn go_param_names_skip_a_comment_in_the_parameter_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            "package main\nfunc f(/* c */ a string) {}\n",
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.functions[0].params, vec!["a".to_string()]);
    }

    #[test]
    fn go_composed_value_walk_stops_at_the_depth_cap() {
        let deep = "(".repeat(COMPOSED_VALUE_MAX_DEPTH + 2)
            + "a"
            + &")".repeat(COMPOSED_VALUE_MAX_DEPTH + 2);
        assert!(go_args(&go_fn(&format!("\tsink({deep})\n"))).is_empty());
    }

    #[test]
    fn js_composed_value_walk_stops_at_the_depth_cap() {
        let deep = "(".repeat(COMPOSED_VALUE_MAX_DEPTH + 2)
            + "a"
            + &")".repeat(COMPOSED_VALUE_MAX_DEPTH + 2);
        assert!(js_args(&js_fn(&format!("  sink({deep});\n"))).is_empty());
    }

    #[test]
    fn go_builder_writes_alias_the_written_value_into_the_builder() {
        // `sb.WriteString(a)` is a statement, not a fluent chain, so the
        // composed-value walker cannot see it — the alias fact is what
        // carries taint into the later `sb.String()`.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            &go_fn("\tsb.WriteString(a)\n\tother.Compute(b)\n"),
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        let pairs: Vec<(&str, Option<&str>)> = idx
            .assigns
            .iter()
            .map(|a| (a.dst_symbol.as_str(), a.src_symbol.as_deref()))
            .collect();
        assert_eq!(pairs, vec![("sb", Some("a"))]);
    }

    #[test]
    fn go_first_arg_is_static_string_distinguishes_bound_from_built_queries() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            &go_fn("\tdb.Query(\"SELECT 1 WHERE x = ?\", a)\n\tdb.Query(`raw`)\n\tdb.Query(a)\n"),
        );
        let src = std::fs::read(&path).unwrap();
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&src, None).unwrap();
        let mut statics = Vec::new();
        fn walk(n: Node, src: &[u8], out: &mut Vec<bool>) {
            if n.kind() == "call_expression" {
                out.push(static_arg_at(
                    &arg_shape(n.child_by_field_name("arguments"), src, go_is_static_string).2,
                    0,
                ));
            }
            for c in kids(n) {
                walk(c, src, out);
            }
        }
        walk(tree.root_node(), &src, &mut statics);
        assert_eq!(statics, vec![true, true, false]);
    }

    // ── JavaScript / TypeScript composed-value symbols ───────────────

    /// `arg_symbols` of the `sink(...)` call in a JS/TS file.
    fn js_args_in(language: &str, name: &str, body: &str) -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), name, body);
        let idx = scan_file(&path, name, language, &[], &[], false, None, None).unwrap();
        idx.call_args
            .into_iter()
            .find(|c| c.callee_name == "sink")
            .expect("no sink call fact")
            .arg_symbols
    }

    fn js_args(body: &str) -> Vec<String> {
        js_args_in("javascript", "app.js", body)
    }

    /// Wrap `stmts` in a JavaScript function whose parameters are `a`/`b`.
    fn js_fn(stmts: &str) -> String {
        format!("function f(a, b) {{\n{stmts}}}\n")
    }

    #[test]
    fn js_arg_symbols_read_through_a_template_literal() {
        assert_eq!(
            js_args(&js_fn("  sink(`ping -c 1 ${a} ${b}`);\n")),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn js_arg_symbols_read_through_a_concatenation_chain() {
        assert_eq!(
            js_args(&js_fn("  sink(\"echo \" + a + b);\n")),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn js_arg_symbols_walk_a_concat_chain_and_a_nested_call() {
        assert_eq!(
            js_args(&js_fn("  sink(\"x\".concat(a).concat(b));\n")),
            vec!["b".to_string(), "a".to_string()]
        );
        assert_eq!(
            js_args(&js_fn("  sink(escape(a));\n")),
            vec!["a".to_string()]
        );
    }

    #[test]
    fn js_arg_symbols_read_through_a_ternary_and_a_typescript_cast() {
        assert_eq!(
            js_args(&js_fn("  sink(a ? a : b);\n")),
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            js_args_in(
                "typescript",
                "app.ts",
                "function f(a: string) {\n  sink((a as string)!);\n}\n"
            ),
            vec!["a".to_string()]
        );
    }

    #[test]
    fn js_arg_symbols_do_not_descend_into_an_array_literal() {
        assert!(js_args(&js_fn("  sink([a, b]);\n")).is_empty());
    }

    #[test]
    fn js_arg_symbols_carry_the_argument_slot_they_came_from() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            &js_fn("  sink(\"lit\", `-v ${a}`, b);\n"),
        );
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        let fact = idx
            .call_args
            .into_iter()
            .find(|c| c.callee_name == "sink")
            .expect("no sink call fact");
        assert_eq!(fact.arg_symbols, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(fact.arg_slots, vec![1, 2]);
    }

    #[test]
    fn js_param_names_cover_declarations_methods_arrows_and_destructuring() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            "function decl(a, b = 1, ...rest) {}\n\
             class K { m(x) {} }\n\
             const arrow = (req, res) => {};\n\
             const fexpr = function (c) {};\n\
             const api = { handler: (p) => {} };\n\
             function destructured({ id }, tail) {}\n",
        );
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        let params = |name: &str| {
            idx.functions
                .iter()
                .find(|f| f.name == name)
                .expect("no function of that name")
                .params
                .clone()
        };
        assert_eq!(params("decl"), vec!["a", "b", "rest"]);
        assert_eq!(params("m"), vec!["x"]);
        assert_eq!(params("arrow"), vec!["req", "res"]);
        assert_eq!(params("fexpr"), vec!["c"]);
        assert_eq!(params("handler"), vec!["p"]);
        // A destructured parameter keeps its slot under an empty name,
        // so `tail` stays parameter 1.
        assert_eq!(params("destructured"), vec!["", "tail"]);
    }

    #[test]
    fn typescript_parameter_wrappers_are_unwrapped_to_their_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.ts",
            "function f(a: string, b?: number, ...rest: string[]) {}\n",
        );
        let idx = scan_file(&path, "app.ts", "typescript", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.functions[0].params, vec!["a", "b", "rest"]);
    }

    #[test]
    fn js_arrow_bodies_are_attributed_to_the_name_they_are_bound_to() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            "const handle = (a) => { sink(a); };\nconst notAFunction = 1;\n",
        );
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        let fact = idx
            .call_args
            .iter()
            .find(|c| c.callee_name == "sink")
            .unwrap();
        assert_eq!(fact.function_qnode, "handle");
        assert_eq!(idx.functions.len(), 1);
    }

    #[test]
    fn js_composite_assignment_and_return_record_every_operand() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            &js_fn("  const q = `${a}-${b}`;\n  let r;\n  r = q;\n  return r + a;\n"),
        );
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        let pairs: Vec<(&str, Option<&str>)> = idx
            .assigns
            .iter()
            .map(|x| (x.dst_symbol.as_str(), x.src_symbol.as_deref()))
            .collect();
        assert_eq!(
            pairs,
            vec![("q", Some("a")), ("q", Some("b")), ("r", Some("q"))]
        );
        let rets: Vec<Option<&str>> = idx.returns.iter().map(|r| r.symbol.as_deref()).collect();
        assert_eq!(rets, vec![Some("r"), Some("a")]);
    }

    #[test]
    fn js_call_target_reads_through_await_and_an_assignment() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            "async function f(u) {\n  const rows = await load(u);\n  let g;\n  g = build(u);\n  drop(u);\n}\n",
        );
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        let targets: Vec<(&str, Option<&str>)> = idx
            .call_args
            .iter()
            .map(|c| (c.callee_name.as_str(), c.target_symbol.as_deref()))
            .collect();
        assert_eq!(
            targets,
            vec![("load", Some("rows")), ("build", Some("g")), ("drop", None)]
        );
        // The awaited call is the alias source, not the `await` wrapper.
        assert_eq!(idx.assigns[0].src_call, Some("load".to_string()));
    }

    #[test]
    fn js_first_arg_is_static_string_distinguishes_bound_from_built_queries() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            &js_fn("  db.query(\"SELECT 1 WHERE x = ?\", a);\n  db.query(`plain`);\n  db.query(`x ${a}`);\n  db.query(a);\n"),
        );
        let src = std::fs::read(&path).unwrap();
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(&src, None).unwrap();
        let mut statics = Vec::new();
        fn walk(n: Node, src: &[u8], out: &mut Vec<bool>) {
            if n.kind() == "call_expression" {
                out.push(static_arg_at(
                    &arg_shape(n.child_by_field_name("arguments"), src, js_is_static_string).2,
                    0,
                ));
            }
            for c in kids(n) {
                walk(c, src, out);
            }
        }
        walk(tree.root_node(), &src, &mut statics);
        assert_eq!(statics, vec![true, true, false, false]);
    }

    // ── property reads as source call sites ──────────────────────────

    #[test]
    fn js_property_reads_are_call_sites_bound_to_their_assignment_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            "function h(req) {\n  const id = req.query.id;\n  const all = req.body;\n  req.locals.x = 1;\n  this.svc.go();\n}\n",
        );
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        let reads: Vec<(&str, &str, Option<&str>)> = idx
            .call_args
            .iter()
            .map(|c| {
                (
                    c.receiver.as_str(),
                    c.callee_name.as_str(),
                    c.target_symbol.as_deref(),
                )
            })
            .collect();
        assert!(reads.contains(&("req", "query", Some("id"))));
        assert!(reads.contains(&("req", "id", Some("id"))));
        assert!(reads.contains(&("req", "body", Some("all"))));
        // A write target is not a read, and `this.svc` walks to no
        // leftmost identifier so it names no receiver.
        assert!(!reads.iter().any(|(_, m, _)| *m == "x"));
        assert!(!reads.iter().any(|(_, m, _)| *m == "svc"));
    }

    #[test]
    fn js_property_reads_stay_out_of_the_call_graph_and_observed_calls() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            "function h(req) {\n  const id = req.query;\n  go(id);\n}\n",
        );
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], true, None, None).unwrap();
        assert_eq!(
            idx.call_edges,
            vec![("h".to_string(), String::new(), "go".to_string())]
        );
        assert_eq!(idx.observed_calls.len(), 1);
        assert_eq!(idx.observed_calls[0].method, "go");
    }

    #[test]
    fn cs_property_reads_are_call_sites_bound_through_an_indexer() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "A.cs",
            "class A {\n  void M() {\n    var q = Request.Query[\"id\"];\n    var b = Request.Body;\n    Log.Level = 1;\n    Helper.Run(q);\n  }\n}\n",
        );
        let idx = scan_file(&path, "A.cs", "csharp", &[], &[], true, None, None).unwrap();
        let reads: Vec<(&str, &str, Option<&str>)> = idx
            .call_args
            .iter()
            .map(|c| {
                (
                    c.receiver.as_str(),
                    c.callee_name.as_str(),
                    c.target_symbol.as_deref(),
                )
            })
            .collect();
        assert!(reads.contains(&("Request", "Query", Some("q"))));
        assert!(reads.contains(&("Request", "Body", Some("b"))));
        // An assignment target is a write, and `Helper.Run` is already a
        // call.
        assert!(!reads.iter().any(|(_, m, _)| *m == "Level"));
        assert_eq!(
            idx.call_edges,
            vec![("M".to_string(), "Helper".to_string(), "Run".to_string())]
        );
        assert_eq!(idx.observed_calls.len(), 1);
    }

    #[test]
    fn a_property_read_can_be_a_source_but_never_a_sink() {
        // The receiver-method sink shape matches any receiver at all, so
        // letting a bare `x.query` read match one would make every
        // property mention a SQL sink.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            "function h(req) {\n  const q = req.query;\n}\n",
        );
        let source = MatchSpec {
            rule_id: "js.req-query".to_string(),
            role: "source".to_string(),
            languages: BTreeSet::from(["javascript".to_string()]),
            module_attr_module: "req".to_string(),
            module_attr_names: BTreeSet::from(["query".to_string()]),
            ..Default::default()
        };
        let sink = MatchSpec {
            rule_id: "js.any-query".to_string(),
            role: "sink".to_string(),
            languages: BTreeSet::from(["javascript".to_string()]),
            receiver_method_names: BTreeSet::from(["query".to_string()]),
            ..Default::default()
        };
        let idx = scan_file(
            &path,
            "app.js",
            "javascript",
            &[source],
            &[sink],
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(idx.source_hits.len(), 1);
        assert_eq!(idx.source_hits[0].matched_rule, "js.req-query");
        assert!(idx.sink_hits.is_empty());
    }

    // ── framework parameter bindings as sources ──────────────────────

    fn marker(marker_type: &str, name: &str, params: &[&str]) -> FrameworkMarkerFact {
        FrameworkMarkerFact {
            function_qnode: "handle".to_string(),
            line: 7,
            marker_type: marker_type.to_string(),
            marker_name: name.to_string(),
            parameter_names: params.iter().map(|p| (*p).to_string()).collect(),
            framework: "spring".to_string(),
            confidence: "high".to_string(),
        }
    }

    #[test]
    fn a_binding_annotation_becomes_a_source_hit_and_a_call_arg_fact() {
        let (hits, facts) = framework_binding_sources(
            "A.java",
            &[marker("spring_annotation", "@RequestParam", &["name"])],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].file, "A.java");
        assert_eq!(hits[0].line, 7);
        assert_eq!(hits[0].method, "@RequestParam");
        assert_eq!(hits[0].containing_fn, "handle");
        assert_eq!(hits[0].role, "source");
        assert_eq!(hits[0].kind, "http");
        assert_eq!(hits[0].matched_rule, FRAMEWORK_BINDING_RULE);
        assert!(!hits[0].owasp_top10_2025.is_empty());
        // The fact is what `_seed_source_taint` reads: it must name the
        // bound parameter as the target, at the same line and callee.
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].function_qnode, "handle");
        assert_eq!(facts[0].line, 7);
        assert_eq!(facts[0].callee_name, "@RequestParam");
        assert_eq!(facts[0].target_symbol, Some("name".to_string()));
    }

    #[test]
    fn every_binding_marker_type_is_a_source_and_nothing_else_is() {
        let markers: Vec<FrameworkMarkerFact> = BINDING_MARKER_TYPES
            .iter()
            .map(|t| marker(t, "@Bind", &["p"]))
            .chain([
                // A route says "reachable from the network", not "holds
                // attacker input"; an implicit type match is a guess at
                // the former too.
                marker("spring_route", "/x/{id}", &["id"]),
                marker("spring_implicit", "HttpServletRequest", &["request"]),
                marker("django_view", "request", &["request"]),
                // A binding that names no parameter still marks the
                // place input enters — a PHP superglobal read has no
                // parameter at all — so it is a source hit with no
                // seeding fact.
                marker("spring_annotation", "@RequestParam", &[]),
                marker("spring_annotation", "@RequestParam", &[""]),
            ])
            .collect();
        let (hits, facts) = framework_binding_sources("A.java", &markers);
        assert_eq!(hits.len(), BINDING_MARKER_TYPES.len() + 2);
        assert_eq!(facts.len(), BINDING_MARKER_TYPES.len());
    }

    #[test]
    fn a_binding_that_names_two_parameters_taints_both() {
        let (hits, facts) = framework_binding_sources(
            "A.java",
            &[marker("jaxrs_annotation", "@BeanParam", &["a", "b"])],
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(
            facts
                .iter()
                .map(|f| f.target_symbol.clone().unwrap())
                .collect::<Vec<_>>(),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn an_axum_extractor_parameter_is_a_source_and_state_is_not() {
        let f = |params: &[&str]| FuncDef {
            name: "handler".to_string(),
            start_line: 12,
            end_line: 20,
            class_name: String::new(),
            params: params.iter().map(|p| (*p).to_string()).collect(),
        };
        let (hits, facts) = extractor_binding_sources(
            "handlers.rs",
            &[f(&[
                // Request input, in every spelling axum offers.
                "Query(params)",
                "Path(slug)",
                "Json(body)",
                // Application state, not request input.
                "State(state)",
                // Not an extractor pattern at all.
                "plain",
                "Query(",
                "Unknown(x)",
                "Query()",
            ])],
        );
        assert_eq!(
            hits.iter().map(|h| h.method.as_str()).collect::<Vec<_>>(),
            vec!["Query", "Path", "Json"]
        );
        assert_eq!(hits[0].file, "handlers.rs");
        assert_eq!(hits[0].line, 12);
        assert_eq!(hits[0].containing_fn, "handler");
        assert_eq!(hits[0].matched_rule, FRAMEWORK_BINDING_RULE);
        assert_eq!(
            facts
                .iter()
                .map(|c| c.target_symbol.clone().unwrap())
                .collect::<Vec<_>>(),
            vec!["params", "slug", "body"]
        );
    }

    #[test]
    fn scan_file_reports_an_axum_extractor_parameter_as_a_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "h.rs",
            "pub async fn show(State(s): State<App>, Path(slug): Path<String>) -> R {\n    render(slug)\n}\n",
        );
        let idx = scan_file(&path, "h.rs", "rust", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.source_hits.len(), 1);
        assert_eq!(idx.source_hits[0].method, "Path");
        assert_eq!(idx.source_hits[0].containing_fn, "show");
    }

    #[test]
    fn a_php_receiver_matches_a_rule_without_its_sigil() {
        // PHP writes every variable with a `$`; the sigil is part of the
        // token, not of the name the corpus spells.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "c.php",
            "<?php\nfunction h($request) { return $request->query('q'); }\n",
        );
        let spec = MatchSpec {
            rule_id: "php.request".to_string(),
            role: "source".to_string(),
            languages: BTreeSet::from(["php".to_string()]),
            module_attr_module: "request".to_string(),
            module_attr_names: BTreeSet::from(["query".to_string()]),
            ..Default::default()
        };
        let idx = scan_file(&path, "c.php", "php", &[spec], &[], false, None, None).unwrap();
        assert_eq!(idx.source_hits.len(), 1);
        assert_eq!(idx.source_hits[0].receiver, "$request");
    }

    #[test]
    fn a_zero_argument_rule_skips_a_call_that_passes_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "A.java",
            "class C {\n  void m() {\n    st.executeQuery();\n    st.executeQuery(q);\n  }\n}\n",
        );
        let spec = MatchSpec {
            rule_id: "java.jdbc".to_string(),
            role: "sink".to_string(),
            languages: BTreeSet::from(["java".to_string()]),
            receiver_method_names: BTreeSet::from(["executeQuery".to_string()]),
            requires_any_arg: true,
            ..Default::default()
        };
        let idx = scan_file(&path, "A.java", "java", &[], &[spec], false, None, None).unwrap();
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].line, 4);
    }

    #[test]
    fn literal_only_symbols_reads_the_base_case_and_one_propagation_step() {
        let assign = |func: &str, dst: &str, sym: Option<&str>, call: Option<&str>| VarAssignFact {
            function_qnode: func.to_string(),
            line: 1,
            dst_symbol: dst.to_string(),
            src_symbol: sym.map(str::to_string),
            src_call: call.map(str::to_string),
        };
        let call = |func: &str, callee: &str, target: &str, args: &[&str]| CallArgFact {
            function_qnode: func.to_string(),
            line: 2,
            callee_name: callee.to_string(),
            receiver: String::new(),
            arg_symbols: args.iter().map(|a| (*a).to_string()).collect(),
            arg_slots: (0..args.len()).collect(),
            target_symbol: Some(target.to_string()),
        };
        let assigns = vec![
            // Built from literals alone.
            assign("f", "sql", None, None),
            // Composed with another symbol.
            assign("f", "built", Some("user"), None),
            // Built by a call from the constant text.
            assign("f", "cmd", None, Some("SqlCommand")),
            // Built by a call from the composed text.
            assign("f", "bad", None, Some("SqlCommand")),
            // Built by a call whose first slot names nothing.
            assign("f", "empty", None, Some("SqlCommand")),
            // Same name in another function stays separate.
            assign("g", "sql", Some("user"), None),
        ];
        let calls = vec![
            call("f", "SqlCommand", "cmd", &["sql", "conn"]),
            call("f", "SqlCommand", "bad", &["built"]),
            call("f", "SqlCommand", "empty", &[]),
        ];
        let out = literal_only_symbols(&assigns, &calls);
        assert!(out.contains(&("f".to_string(), "sql".to_string())));
        assert!(out.contains(&("f".to_string(), "cmd".to_string())));
        assert!(!out.contains(&("f".to_string(), "built".to_string())));
        assert!(!out.contains(&("f".to_string(), "bad".to_string())));
        assert!(!out.contains(&("f".to_string(), "empty".to_string())));
        assert!(!out.contains(&("g".to_string(), "sql".to_string())));
    }

    #[test]
    fn scan_file_reports_an_annotation_bound_parameter_as_a_source() {
        // Through the real extractor: the marker plane and the source
        // plane have to agree on line and callee name, or
        // `_seed_source_taint` finds no fact to seed from.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "A.java",
            "class C {\n  @GetMapping(\"/r\")\n  public byte[] r(@RequestParam(\"f\") String name) { return null; }\n}\n",
        );
        let idx = scan_file(&path, "A.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.source_hits.len(), 1);
        assert_eq!(idx.source_hits[0].matched_rule, FRAMEWORK_BINDING_RULE);
        let seeded = idx
            .call_args
            .iter()
            .find(|c| c.callee_name == "@RequestParam")
            .expect("no seeding fact for the bound parameter");
        assert_eq!(seeded.line, idx.source_hits[0].line);
        assert_eq!(seeded.target_symbol, Some("name".to_string()));
    }

    #[test]
    fn composed_value_walk_stops_at_the_depth_cap() {
        // A concatenation nested past `COMPOSED_VALUE_MAX_DEPTH` stops
        // contributing symbols rather than driving an unbounded walk.
        let deep = "(".repeat(COMPOSED_VALUE_MAX_DEPTH + 2)
            + "a"
            + &")".repeat(COMPOSED_VALUE_MAX_DEPTH + 2);
        let body = format!("def f(a):\n    os.system({deep})\n");
        assert!(py_args(&body).is_empty());
    }

    // ── bare-call / receiver-method / requires_dynamic_arg ───────────

    fn bare_open_sink() -> MatchSpec {
        MatchSpec {
            rule_id: "py.open-file".to_string(),
            role: "sink".to_string(),
            origin: "semgrep".to_string(),
            cwe: "CWE-22".to_string(),
            kind: "path".to_string(),
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            semantic_family: "file-io".to_string(),
            bare_call_names: std::collections::BTreeSet::from(["open".to_string()]),
            ..Default::default()
        }
    }

    fn cursor_execute_sink(requires_dynamic_arg: bool) -> MatchSpec {
        MatchSpec {
            rule_id: "py.dbapi-cursor-execute".to_string(),
            role: "sink".to_string(),
            origin: "semgrep".to_string(),
            cwe: "CWE-89".to_string(),
            kind: "sql".to_string(),
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            semantic_family: "sql-exec".to_string(),
            receiver_method_names: std::collections::BTreeSet::from(["execute".to_string()]),
            requires_dynamic_arg,
            ..Default::default()
        }
    }

    #[test]
    fn scan_file_matches_a_bare_call_sink() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "def f(p):\n    open(p)\n");
        let sinks = vec![bare_open_sink()];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].method, "open");
    }

    #[test]
    fn scan_file_bare_call_sink_does_not_match_a_method_of_the_same_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "def f(p):\n    zipf.open(p)\n");
        let sinks = vec![bare_open_sink()];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert!(idx.sink_hits.is_empty());
    }

    #[test]
    fn scan_file_matches_a_receiver_method_sink_on_any_receiver() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "def f(q):\n    cur.execute(q)\n");
        let sinks = vec![cursor_execute_sink(true)];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].receiver, "cur");
    }

    #[test]
    fn scan_file_receiver_method_sink_needs_a_receiver() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "def f(q):\n    execute(q)\n");
        let sinks = vec![cursor_execute_sink(true)];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert!(idx.sink_hits.is_empty());
    }

    #[test]
    fn scan_file_requires_dynamic_arg_skips_a_parameterized_query() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.py",
            "def f(p):\n    cur.execute(\"SELECT 1 WHERE a = ?\", (p,))\n    cur.execute(\"SELECT \" + p)\n",
        );
        let sinks = vec![cursor_execute_sink(true)];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].line, 3);
    }

    #[test]
    fn scan_file_without_requires_dynamic_arg_a_static_query_still_matches() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.py",
            "def f(p):\n    cur.execute(\"SELECT 1 WHERE a = ?\", (p,))\n",
        );
        let sinks = vec![cursor_execute_sink(false)];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert_eq!(idx.sink_hits.len(), 1);
    }

    // ── requires_arithmetic_arg ──────────────────────────────────────

    fn alloc_size_sink(names: &[&str], arithmetic_arg_index: usize) -> MatchSpec {
        MatchSpec {
            rule_id: "c.alloc-size-overflow".to_string(),
            role: "sink".to_string(),
            origin: "semgrep".to_string(),
            cwe: "CWE-190".to_string(),
            kind: "memory".to_string(),
            languages: std::collections::BTreeSet::from(["c-cpp".to_string()]),
            semantic_family: "other".to_string(),
            bare_call_names: names.iter().map(|n| (*n).to_string()).collect(),
            requires_arithmetic_arg: true,
            arithmetic_arg_index,
            ..Default::default()
        }
    }

    #[test]
    fn scan_file_requires_arithmetic_arg_matches_only_a_computed_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "a.c",
            "void f(size_t n, size_t m) {\n\
             \x20   a = malloc(len);\n\
             \x20   b = malloc(sizeof(struct hdr));\n\
             \x20   c = malloc(64);\n\
             \x20   d = malloc(n * m);\n\
             }\n",
        );
        let sinks = vec![alloc_size_sink(&["malloc"], 0)];
        let idx = scan_file(&path, "a.c", "c-cpp", &[], &sinks, false, None, None).unwrap();
        // Only the multiply can wrap; a name, a `sizeof` and a literal
        // each allocate exactly what they say.
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].line, 5);
        assert_eq!(idx.sink_hits[0].cwe, "CWE-190");
    }

    #[test]
    fn scan_file_requires_arithmetic_arg_reads_the_configured_index() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "a.c",
            "void f(size_t n, size_t m) {\n\
             \x20   p = realloc(p, n);\n\
             \x20   q = realloc(p, n * m);\n\
             }\n",
        );
        // `realloc` puts the size second; at index 0 the pointer
        // argument is a bare name and nothing would ever match.
        let idx = scan_file(
            &path,
            "a.c",
            "c-cpp",
            &[],
            &[alloc_size_sink(&["realloc"], 1)],
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].line, 3);
        let idx0 = scan_file(
            &path,
            "a.c",
            "c-cpp",
            &[],
            &[alloc_size_sink(&["realloc"], 0)],
            false,
            None,
            None,
        )
        .unwrap();
        assert!(idx0.sink_hits.is_empty());
    }

    #[test]
    fn scan_file_requires_arithmetic_arg_goes_dark_where_shapes_are_unknown() {
        // Python's extractor computes no arithmetic shapes, so the
        // predicate cannot be answered and the rule does not fire —
        // the opposite polarity to `requires_dynamic_arg`, and the
        // reason such a rule may only name languages that answer it.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "def f(n, m):\n    open(n * m)\n");
        let sinks = vec![MatchSpec {
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            ..alloc_size_sink(&["open"], 0)
        }];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert!(idx.sink_hits.is_empty());
    }

    #[test]
    fn scan_file_requires_arithmetic_arg_reaches_a_cpp_array_new() {
        // `new T[n]` is a `new_expression`, not a call, and carries no
        // argument list — the extractor reads its size as argument 0
        // and records it under `operator_new_array`, so the SAME
        // predicate that covers `malloc(n * m)` covers it.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "a.cpp",
            "void f(size_t n, size_t m) {\n\
             \x20   int *a = new int[n];\n\
             \x20   int *b = new int[n * m];\n\
             \x20   Foo *c = new Foo(n * m);\n\
             \x20   Foo *d = new Foo;\n\
             }\n",
        );
        let sinks = vec![alloc_size_sink(&["operator_new_array"], 0)];
        let idx = scan_file(&path, "a.cpp", "c-cpp", &[], &sinks, false, None, None).unwrap();
        // Only the computed array length can wrap; a bare `new int[n]`
        // cannot, and the two non-array forms allocate one object each
        // and are not allocations with a size at all.
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].line, 3);
        assert_eq!(idx.sink_hits[0].cwe, "CWE-190");
        assert_eq!(idx.sink_hits[0].method, "operator_new_array");
    }

    // ── requires_unit_arg, and the two-argument conjunction ──────────

    /// The corpus's `c.calloc-hand-multiplied-size`: arithmetic at 0
    /// AND the literal `1` at 1, which is the ONE unsafe `calloc`.
    fn calloc_hand_multiplied_sink() -> MatchSpec {
        MatchSpec {
            rule_id: "c.calloc-hand-multiplied-size".to_string(),
            requires_unit_arg: true,
            unit_arg_index: 1,
            ..alloc_size_sink(&["calloc"], 0)
        }
    }

    #[test]
    fn scan_file_two_argument_conjunction_matches_only_a_hand_multiplied_calloc() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "a.c",
            "void f(size_t n, size_t size, size_t len) {\n\
             \x20   a = calloc(n, size);\n\
             \x20   b = calloc(len + 1, sizeof(char));\n\
             \x20   c = calloc(1, sizeof(struct hdr));\n\
             \x20   d = calloc(n * size, size);\n\
             \x20   e = calloc(n, 1);\n\
             \x20   g = calloc(n * size, 1);\n\
             }\n",
        );
        let sinks = vec![calloc_hand_multiplied_sink()];
        let idx = scan_file(&path, "a.c", "c-cpp", &[], &sinks, false, None, None).unwrap();
        // Every safe idiom fails one half or the other: a bare count is
        // not arithmetic, and `sizeof(char)`/a real element size is not
        // the literal `1`. Only line 7 satisfies both.
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].line, 7);
        assert_eq!(idx.sink_hits[0].cwe, "CWE-190");
    }

    #[test]
    fn scan_file_dropping_either_half_of_the_conjunction_widens_the_rule() {
        // The point of ANDing two predicates: each one alone reports
        // calls the pair does not, and the `calloc` family is only safe
        // to name because both hold at once.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "a.c",
            "void f(size_t n, size_t size, size_t len) {\n\
             \x20   a = calloc(len + 1, sizeof(char));\n\
             \x20   b = calloc(n, 1);\n\
             \x20   c = calloc(n * size, 1);\n\
             }\n",
        );
        // Arithmetic alone also reports the textbook string allocation.
        let arithmetic_only = scan_file(
            &path,
            "a.c",
            "c-cpp",
            &[],
            &[alloc_size_sink(&["calloc"], 0)],
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            arithmetic_only
                .sink_hits
                .iter()
                .map(|h| h.line)
                .collect::<Vec<_>>(),
            vec![2, 4]
        );
        // The unit predicate alone reports the perfectly safe
        // `calloc(n, 1)`.
        let unit_only = scan_file(
            &path,
            "a.c",
            "c-cpp",
            &[],
            &[MatchSpec {
                requires_arithmetic_arg: false,
                ..calloc_hand_multiplied_sink()
            }],
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            unit_only
                .sink_hits
                .iter()
                .map(|h| h.line)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn scan_file_requires_unit_arg_goes_dark_where_shapes_are_unknown() {
        // Same polarity as `requires_arithmetic_arg`: Python computes
        // no unit shapes, so the predicate cannot be answered and the
        // rule does not fire rather than matching everything.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "def f(n):\n    open(n, 1)\n");
        let sinks = vec![MatchSpec {
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            requires_arithmetic_arg: false,
            requires_unit_arg: true,
            unit_arg_index: 1,
            ..alloc_size_sink(&["open"], 0)
        }];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert!(idx.sink_hits.is_empty());
    }

    #[test]
    fn build_spec_index_buckets_bare_call_and_receiver_method_names() {
        let specs = vec![bare_open_sink(), cursor_execute_sink(true)];
        let index = build_spec_index(&specs);
        let python = index.get("python").unwrap();
        assert_eq!(python.get("open").map(Vec::len), Some(1));
        assert_eq!(python.get("execute").map(Vec::len), Some(1));
        assert!(!python.contains_key("*"));
    }

    fn os_system_sink() -> MatchSpec {
        MatchSpec {
            rule_id: "py.os.system".to_string(),
            role: "sink".to_string(),
            origin: "semgrep".to_string(),
            cwe: "CWE-78".to_string(),
            kind: "command_injection".to_string(),
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            semantic_family: "command-exec".to_string(),
            owasp_top10_2025: std::collections::BTreeSet::from(["A03:2025-Injection".to_string()]),
            module_attr_module: "os".to_string(),
            module_attr_names: std::collections::BTreeSet::from(["system".to_string()]),
            ..Default::default()
        }
    }

    fn request_args_source() -> MatchSpec {
        MatchSpec {
            rule_id: "py.flask.request-args".to_string(),
            role: "source".to_string(),
            origin: "semgrep".to_string(),
            cwe: "CWE-20".to_string(),
            kind: "network".to_string(),
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            semantic_family: "other".to_string(),
            module_attr_module: "request".to_string(),
            module_attr_names: std::collections::BTreeSet::from(["get".to_string()]),
            ..Default::default()
        }
    }

    fn runtime_exec_sink_qualified() -> MatchSpec {
        MatchSpec {
            rule_id: "java.codeql.runtime-exec".to_string(),
            role: "sink".to_string(),
            origin: "codeql".to_string(),
            cwe: "CWE-78".to_string(),
            kind: "cmd".to_string(),
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            package: "subprocess".to_string(),
            class_name: "Popen".to_string(),
            top_class: "Popen".to_string(),
            methods: std::collections::BTreeSet::from(["communicate".to_string()]),
            ..Default::default()
        }
    }

    // ── supported_languages / extract / ts_language ─────────────────

    #[test]
    fn supported_languages_lists_every_wired_language() {
        assert_eq!(
            supported_languages(),
            &[
                "python",
                "javascript",
                "typescript",
                "go",
                "java",
                "csharp",
                "php",
                "ruby",
                "kotlin",
                "rust",
                "c-cpp"
            ]
        );
    }

    #[test]
    fn scan_file_returns_none_for_an_unsupported_language() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "a.swift", "func main() {}\n");
        assert!(scan_file(&path, "a.swift", "swift", &[], &[], false, None, None).is_none());
    }

    // ── scan_file: basic structure ───────────────────────────────────

    #[test]
    fn scan_file_returns_none_for_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.py");
        assert!(scan_file(
            &path,
            "does-not-exist.py",
            "python",
            &[],
            &[],
            false,
            None,
            None
        )
        .is_none());
    }

    #[test]
    fn scan_file_returns_none_for_an_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "empty.py", "");
        assert!(scan_file(&path, "empty.py", "python", &[], &[], false, None, None).is_none());
    }

    #[test]
    fn scan_file_extracts_imports_functions_and_calls() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.py",
            "import os\nfrom foo import bar as baz\n\ndef handler(req):\n    os.system(req)\n",
        );
        let sinks = vec![os_system_sink()];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert_eq!(idx.file, "app.py");
        assert_eq!(idx.language, "python");
        assert_eq!(idx.imports.get("os"), Some(&"os".to_string()));
        assert_eq!(idx.imports.get("baz"), Some(&"foo.bar".to_string()));
        assert_eq!(idx.functions.len(), 1);
        assert_eq!(idx.functions[0].name, "handler");
        assert_eq!(idx.call_edges.len(), 1);
        assert_eq!(
            idx.call_edges[0],
            (
                "handler".to_string(),
                "os".to_string(),
                "system".to_string()
            )
        );
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].matched_rule, "py.os.system");
        assert_eq!(idx.sink_hits[0].role, "sink");
        assert_eq!(idx.sink_hits[0].containing_fn, "handler");
        assert!(idx.source_hits.is_empty());
    }

    #[test]
    fn scan_file_matches_a_module_attr_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "import flask\nrequest.get('x')\n");
        let sources = vec![request_args_source()];
        let idx = scan_file(&path, "app.py", "python", &sources, &[], false, None, None).unwrap();
        assert_eq!(idx.source_hits.len(), 1);
        assert_eq!(idx.source_hits[0].role, "source");
        assert_eq!(idx.source_hits[0].matched_rule, "py.flask.request-args");
    }

    #[test]
    fn scan_file_matches_a_module_attr_sink_via_the_resolved_import_not_the_raw_receiver() {
        // `sp` (an aliased import) doesn't literally equal the spec's
        // `module_attr_module` ("subprocess") — only the raw receiver's
        // *resolved* import path does — exercising `match_call`'s
        // `resolved == spec.module_attr_module` disjunct distinctly from
        // the exact-receiver check just above it.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.py",
            "import subprocess as sp\nsp.check_call(cmd)\n",
        );
        let sinks = vec![MatchSpec {
            rule_id: "py.subprocess.check_call".to_string(),
            role: "sink".to_string(),
            origin: "semgrep".to_string(),
            cwe: "CWE-78".to_string(),
            kind: "command_injection".to_string(),
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            semantic_family: "command-exec".to_string(),
            module_attr_module: "subprocess".to_string(),
            module_attr_names: std::collections::BTreeSet::from(["check_call".to_string()]),
            ..Default::default()
        }];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].matched_rule, "py.subprocess.check_call");
    }

    #[test]
    fn scan_file_matches_a_qualified_import_resolved_receiver() {
        // Qualified (codeql/fsb) matching only resolves a receiver via
        // its own `import` statement, not via assignment-based type
        // inference (`p = Popen(cmd); p.communicate()` is a documented
        // MVP limitation in the Python original — see `match_call`'s
        // own comment) — so the receiver here is the imported module
        // name itself, not a locally-assigned variable.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.py",
            "import subprocess\nsubprocess.communicate()\n",
        );
        let sinks = vec![runtime_exec_sink_qualified()];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].matched_rule, "java.codeql.runtime-exec");
    }

    #[test]
    fn scan_file_a_call_can_be_both_a_source_and_a_sink() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "os.system(x)\n");
        let sources = vec![MatchSpec {
            module_attr_module: "os".to_string(),
            module_attr_names: std::collections::BTreeSet::from(["system".to_string()]),
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            role: "source".to_string(),
            rule_id: "src".to_string(),
            ..Default::default()
        }];
        let sinks = vec![os_system_sink()];
        let idx = scan_file(
            &path, "app.py", "python", &sources, &sinks, false, None, None,
        )
        .unwrap();
        assert_eq!(idx.source_hits.len(), 1);
        assert_eq!(idx.sink_hits.len(), 1);
    }

    #[test]
    fn scan_file_falls_back_to_the_semantic_sink_override() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "render_template(x)\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].matched_rule, "vvah.semantic.sink");
        assert_eq!(idx.sink_hits[0].cwe, "CWE-79");
    }

    #[test]
    fn scan_file_semantic_override_html_response_via_braces() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "response(f'<html>{x}</html>')\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].semantic_family, "html-response");
    }

    #[test]
    fn scan_file_no_semantic_override_when_response_has_no_html_markers() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "response(x)\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert!(idx.sink_hits.is_empty());
    }

    #[test]
    fn scan_file_collects_observed_calls_when_requested() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "import os\nos.system(x)\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], true, None, None).unwrap();
        assert_eq!(idx.observed_calls.len(), 1);
        assert_eq!(idx.observed_calls[0].resolved_receiver, "os");
        assert_eq!(idx.observed_calls[0].method, "system");
    }

    #[test]
    fn scan_file_does_not_collect_observed_calls_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "os.system(x)\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert!(idx.observed_calls.is_empty());
    }

    #[test]
    fn scan_file_uses_a_prebuilt_spec_index_when_given() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "os.system(x)\n");
        let sinks = vec![os_system_sink()];
        let sink_index = build_spec_index(&sinks);
        let idx = scan_file(
            &path,
            "app.py",
            "python",
            &[],
            &sinks,
            false,
            None,
            Some(&sink_index),
        )
        .unwrap();
        assert_eq!(idx.sink_hits.len(), 1);
    }

    #[test]
    fn scan_file_populates_assigns_returns_and_call_args() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.py",
            "def f(a):\n    x = a\n    y = os.system(a)\n    return x\n",
        );
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.assigns.len(), 2);
        assert_eq!(idx.assigns[0].dst_symbol, "x");
        assert_eq!(idx.assigns[0].src_symbol, Some("a".to_string()));
        assert_eq!(idx.assigns[1].dst_symbol, "y");
        assert_eq!(idx.assigns[1].src_call, Some("system".to_string()));
        assert_eq!(idx.returns.len(), 1);
        assert_eq!(idx.returns[0].symbol, Some("x".to_string()));
        assert_eq!(idx.call_args.len(), 1);
        assert_eq!(idx.call_args[0].callee_name, "system");
        assert_eq!(idx.call_args[0].arg_symbols, vec!["a".to_string()]);
    }

    #[test]
    fn an_rhs_that_is_neither_a_symbol_nor_a_call_records_a_literal_only_assignment() {
        // Not "no fact": "assigned from literals alone" is what tells
        // `requires_dynamic_arg` that a query built into this local is
        // bound rather than composed. See `literal_only_symbols`.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "z = 5\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.assigns.len(), 1);
        assert_eq!(idx.assigns[0].dst_symbol, "z");
        assert_eq!(idx.assigns[0].src_symbol, None);
        assert_eq!(idx.assigns[0].src_call, None);
    }

    #[test]
    fn scan_file_no_assign_fact_when_the_lhs_is_not_a_bare_identifier() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "obj.attr = x\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert!(idx.assigns.is_empty());
    }

    #[test]
    fn scan_file_captures_keyword_argument_identifier_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "foo(bar, baz=qux)\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(
            idx.call_args[0].arg_symbols,
            vec!["bar".to_string(), "qux".to_string()]
        );
    }

    #[test]
    fn scan_file_ignores_a_keyword_argument_with_a_non_identifier_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "foo(baz=5)\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert!(idx.call_args[0].arg_symbols.is_empty());
    }

    #[test]
    fn py_identifier_args_empty_when_the_node_has_no_arguments_field() {
        let src = b"x = 1\n";
        let tree = parse(src);
        let ident = find_kind(tree.root_node(), "identifier").unwrap();
        assert!(py_identifier_args(ident, src).0.is_empty());
    }

    #[test]
    fn py_return_symbols_reads_a_direct_value_field_when_present() {
        // `py_return_symbols` doesn't check its argument's own kind —
        // it just looks for a "value" field. `return_statement` never
        // defines one in this tree-sitter-python grammar (confirmed by
        // exhaustive testing against real return-statement shapes), so
        // this exercises that first branch directly against a different
        // real node kind (`keyword_argument`) that does define one,
        // rather than via `return_statement`'s own (grammar-guaranteed
        // absent) field.
        let src = b"foo(baz=qux)\n";
        let tree = parse(src);
        let kwarg = find_kind(tree.root_node(), "keyword_argument").unwrap();
        assert_eq!(py_return_symbols(kwarg, src), vec!["qux".to_string()]);
    }

    #[test]
    fn scan_file_records_the_assignment_target_symbol_for_a_call() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "result = os.system(x)\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.call_args[0].target_symbol, Some("result".to_string()));
    }

    #[test]
    fn scan_file_no_assignment_target_when_the_call_is_not_assigned() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "os.system(x)\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.call_args[0].target_symbol, None);
    }

    #[test]
    fn scan_file_no_assignment_target_when_the_call_is_assigned_to_a_non_identifier() {
        // `obj.attr = foo()`: the call's parent IS an assignment with
        // this call as its RHS, but the LHS isn't a bare identifier —
        // a distinct "no match" path from the call simply having no
        // assignment parent at all.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "obj.attr = foo()\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.call_args[0].target_symbol, None);
    }

    #[test]
    fn scan_file_return_with_no_identifier_has_no_symbol() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "def f():\n    return 1 + 2\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.returns[0].symbol, None);
    }

    #[test]
    fn scan_file_bare_return_has_no_symbol() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "def f():\n    return\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.returns[0].symbol, None);
    }

    #[test]
    fn scan_file_module_level_call_has_no_containing_fn() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "os.system(x)\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.call_edges[0].0, "");
    }

    #[test]
    fn scan_file_bare_function_call_has_empty_receiver() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "eval(x)\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.call_edges[0].1, "");
        assert_eq!(idx.call_edges[0].2, "eval");
    }

    #[test]
    fn scan_file_constructor_match_requires_the_import_to_start_with_the_package() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.py",
            "from javax.xml.parsers import DocumentBuilderFactory\nDocumentBuilderFactory()\n",
        );
        let sinks = vec![MatchSpec {
            rule_id: "ctor".to_string(),
            role: "sink".to_string(),
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            package: "javax.xml.parsers".to_string(),
            class_name: "DocumentBuilderFactory".to_string(),
            top_class: "DocumentBuilderFactory".to_string(),
            methods: std::collections::BTreeSet::from(["DocumentBuilderFactory".to_string()]),
            is_constructor: true,
            ..Default::default()
        }];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert_eq!(idx.sink_hits.len(), 1);
    }

    #[test]
    fn scan_file_no_match_when_receiver_import_is_unresolved() {
        let dir = tempfile::tempdir().unwrap();
        // `unknown` is never imported, so its resolved import is "".
        let path = write_py(dir.path(), "app.py", "unknown.system(x)\n");
        let sinks = vec![runtime_exec_sink_qualified()];
        let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
        assert!(idx.sink_hits.is_empty());
    }

    // ── build_spec_index / match_call (via scan_file, both index paths) ─

    #[test]
    fn build_spec_index_falls_back_to_wildcard_buckets() {
        let spec = MatchSpec {
            rule_id: "r1".to_string(),
            role: "sink".to_string(),
            package: "os".to_string(),
            class_name: "System".to_string(),
            top_class: "System".to_string(),
            methods: std::collections::BTreeSet::new(),
            module_attr_module: String::new(),
            module_attr_names: std::collections::BTreeSet::new(),
            languages: std::collections::BTreeSet::new(),
            ..Default::default()
        };
        let idx = build_spec_index(std::slice::from_ref(&spec));
        assert!(idx.contains_key("*"));
        assert!(idx["*"].contains_key("*"));
    }

    #[test]
    fn build_spec_index_uses_the_methods_set_when_present() {
        let spec = qualified_spec("java.lang", "Runtime", "exec", false);
        let idx = build_spec_index(std::slice::from_ref(&spec));
        assert!(idx["python"].contains_key("exec"));
        assert!(idx["java"].contains_key("exec"));
    }

    // ── semantic_sink_override direct tests (java branch, not yet
    // reachable through scan_file since only python is wired) ───────

    #[test]
    fn semantic_sink_override_java_response_write() {
        let got =
            semantic_sink_override("java", "response", "write", "response.write(\"<b>\" + x)");
        assert!(got.is_some());
        assert_eq!(got.unwrap().cwe, "CWE-79");
    }

    #[test]
    fn semantic_sink_override_java_matches_via_httpservletresponse_snippet_text() {
        // `receiver` alone doesn't satisfy the `r in {response,writer,out}`
        // half of the OR — only the `HttpServletResponse` snippet text
        // does, exercising that branch independently.
        let got = semantic_sink_override(
            "java",
            "resp",
            "println",
            "((HttpServletResponse) resp).println(\"<b>\" + x)",
        );
        assert!(got.is_some());
    }

    #[test]
    fn semantic_sink_override_java_no_match_without_html_markers() {
        assert!(semantic_sink_override("java", "response", "write", "response.write(x)").is_none());
    }

    #[test]
    fn semantic_sink_override_none_for_an_unhandled_language() {
        assert!(semantic_sink_override("go", "w", "write", "w.write(x)").is_none());
    }

    #[test]
    fn semantic_sink_override_python_render_template_without_html_markers_still_matches() {
        // `render_template`/`templateresponse` match unconditionally,
        // independent of the `snippet` markers the `response(...)`
        // branch requires.
        let got = semantic_sink_override("python", "", "render_template", "render_template(x)");
        assert!(got.is_some());
    }

    // ── extract() / ts_language() dispatch, direct ────────────────────
    //
    // `scan_file` itself short-circuits on `ts_language(language)?`
    // before ever reaching `extract`, so a full-pipeline test can't
    // exercise `extract`'s own unsupported-language arm — tested
    // directly instead, on its own merits (same pattern as
    // `rules::value_kind_name`).

    #[test]
    fn extract_none_for_an_unsupported_language() {
        let tree = parse(b"x = 1\n");
        assert!(extract("swift", b"x = 1\n", tree.root_node()).is_none());
    }

    #[test]
    fn ts_language_none_for_an_unsupported_language() {
        assert!(ts_language("swift").is_none());
    }

    // ── import_statement: bare `import x as y` ────────────────────────

    #[test]
    fn scan_file_bare_import_with_an_alias() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.py", "import os as o\no.system(x)\n");
        let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.imports.get("o"), Some(&"os".to_string()));
    }

    // ── py_call_parts, direct ──────────────────────────────────────────

    #[test]
    fn py_call_parts_empty_when_the_node_has_no_function_field() {
        let src = b"x = 1\n";
        let tree = parse(src);
        let ident = find_kind(tree.root_node(), "identifier").unwrap();
        assert_eq!(py_call_parts(ident, src), (String::new(), String::new()));
    }

    #[test]
    fn py_call_parts_empty_for_an_unrecognized_function_node_kind() {
        // `()()`: the outer call's `function` field is a `tuple` node —
        // neither `attribute` nor `identifier`.
        let src = b"()()\n";
        let tree = parse(src);
        let call = find_kind(tree.root_node(), "call").unwrap();
        assert_eq!(py_call_parts(call, src), (String::new(), String::new()));
    }

    // ── py_leftmost_identifier, direct ─────────────────────────────────

    #[test]
    fn py_leftmost_identifier_empty_when_walking_through_a_childless_token() {
        // `(x).foo`: the attribute's `object` is a
        // `parenthesized_expression` whose first child is the anonymous
        // `(` token, which itself has no children — the generic
        // `child(0)` fallback walks down to a dead end.
        let src = b"(x).foo\n";
        let tree = parse(src);
        let attr = find_kind(tree.root_node(), "attribute").unwrap();
        assert_eq!(py_leftmost_identifier(attr, src), "");
    }

    // ── match_call, direct (covers branches scan_file's python-only
    // wiring can't reach on its own: cross-language filtering, the
    // java/csharp class-tail recall guard, constructor mismatches, and
    // module_attr prefix/suffix resolution) ───────────────────────────

    fn qualified_spec(package: &str, class_name: &str, method: &str, is_ctor: bool) -> MatchSpec {
        MatchSpec {
            rule_id: "q".to_string(),
            role: "sink".to_string(),
            languages: std::collections::BTreeSet::from(["python".to_string(), "java".to_string()]),
            package: package.to_string(),
            class_name: class_name.to_string(),
            top_class: class_name.split('.').next().unwrap_or("").to_string(),
            methods: std::collections::BTreeSet::from([method.to_string()]),
            is_constructor: is_ctor,
            ..Default::default()
        }
    }

    #[test]
    fn match_call_skips_a_spec_for_a_different_language() {
        let spec = qualified_spec("os", "System", "exec", false);
        let other_lang_spec = MatchSpec {
            languages: std::collections::BTreeSet::from(["go".to_string()]),
            ..spec.clone()
        };
        let imports = BTreeMap::from([("os".to_string(), "os".to_string())]);
        let specs: Vec<&MatchSpec> = vec![&other_lang_spec, &spec];
        assert!(match_call(
            "os",
            "exec",
            &imports,
            &specs,
            "python",
            &[],
            &[],
            &[],
            None
        )
        .is_some());
    }

    #[test]
    fn match_call_constructor_does_not_match_a_non_empty_receiver() {
        let spec = qualified_spec("os", "System", "System", true);
        let imports = BTreeMap::from([("System".to_string(), "os.System".to_string())]);
        let specs = vec![&spec];
        // A constructor call always has an empty receiver (`System()`,
        // not `x.System()`) — matches `_match_call`'s own Python-side
        // MVP scope.
        assert!(match_call(
            "x",
            "System",
            &imports,
            &specs,
            "python",
            &[],
            &[],
            &[],
            None
        )
        .is_none());
    }

    #[test]
    fn match_call_constructor_does_not_match_when_the_import_does_not_start_with_the_package() {
        let spec = qualified_spec("os", "System", "System", true);
        let imports = BTreeMap::from([("System".to_string(), "somewhere.else.System".to_string())]);
        let specs = vec![&spec];
        assert!(match_call(
            "",
            "System",
            &imports,
            &specs,
            "python",
            &[],
            &[],
            &[],
            None
        )
        .is_none());
    }

    #[test]
    fn match_call_qualified_no_match_when_receiver_is_unresolved() {
        let spec = qualified_spec("os", "System", "exec", false);
        let specs = vec![&spec];
        assert!(match_call(
            "os",
            "exec",
            &BTreeMap::new(),
            &specs,
            "python",
            &[],
            &[],
            &[],
            None
        )
        .is_none());
    }

    #[test]
    fn match_call_java_class_tail_recall_guard_matches_a_narrowed_import() {
        let spec = qualified_spec("java.lang", "Runtime", "exec", false);
        // Only a narrowed class tail is known (no full package path) —
        // still recognized for JVM-style languages.
        let imports = BTreeMap::from([("rt".to_string(), "Runtime".to_string())]);
        let specs = vec![&spec];
        assert!(match_call("rt", "exec", &imports, &specs, "java", &[], &[], &[], None).is_some());
    }

    #[test]
    fn match_call_java_class_tail_recall_guard_matches_a_dotted_suffix() {
        let spec = qualified_spec("java.lang", "Runtime", "exec", false);
        let imports = BTreeMap::from([("rt".to_string(), "com.acme.Runtime".to_string())]);
        let specs = vec![&spec];
        assert!(match_call("rt", "exec", &imports, &specs, "java", &[], &[], &[], None).is_some());
    }

    #[test]
    fn match_call_class_tail_recall_guard_is_not_applied_outside_jvm_languages() {
        let spec = qualified_spec("java.lang", "Runtime", "exec", false);
        let imports = BTreeMap::from([("rt".to_string(), "Runtime".to_string())]);
        let specs = vec![&spec];
        assert!(match_call(
            "rt",
            "exec",
            &imports,
            &specs,
            "python",
            &[],
            &[],
            &[],
            None
        )
        .is_none());
    }

    #[test]
    fn match_call_qualified_falls_through_to_no_match_when_nothing_lines_up() {
        let spec = qualified_spec("java.lang", "Runtime", "exec", false);
        let imports =
            BTreeMap::from([("rt".to_string(), "completely.unrelated.Thing".to_string())]);
        let specs = vec![&spec];
        assert!(match_call("rt", "exec", &imports, &specs, "java", &[], &[], &[], None).is_none());
    }

    #[test]
    fn match_call_module_attr_skips_a_spec_with_a_different_method() {
        let spec = MatchSpec {
            module_attr_module: "os".to_string(),
            module_attr_names: std::collections::BTreeSet::from(["system".to_string()]),
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            ..Default::default()
        };
        let specs = vec![&spec];
        assert!(match_call(
            "os",
            "popen",
            &BTreeMap::new(),
            &specs,
            "python",
            &[],
            &[],
            &[],
            None
        )
        .is_none());
    }

    #[test]
    fn match_call_module_attr_matches_via_resolved_prefix() {
        let spec = MatchSpec {
            module_attr_module: "os".to_string(),
            module_attr_names: std::collections::BTreeSet::from(["system".to_string()]),
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            ..Default::default()
        };
        let imports = BTreeMap::from([("o".to_string(), "os.path".to_string())]);
        let specs = vec![&spec];
        assert!(match_call(
            "o",
            "system",
            &imports,
            &specs,
            "python",
            &[],
            &[],
            &[],
            None
        )
        .is_some());
    }

    #[test]
    fn match_call_module_attr_matches_via_resolved_suffix() {
        let spec = MatchSpec {
            module_attr_module: "os".to_string(),
            module_attr_names: std::collections::BTreeSet::from(["system".to_string()]),
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            ..Default::default()
        };
        let imports = BTreeMap::from([("o".to_string(), "compat.os".to_string())]);
        let specs = vec![&spec];
        assert!(match_call(
            "o",
            "system",
            &imports,
            &specs,
            "python",
            &[],
            &[],
            &[],
            None
        )
        .is_some());
    }

    // ── specs_for, direct ───────────────────────────────────────────

    #[test]
    fn specs_for_falls_back_to_the_raw_list_without_an_index() {
        let spec = os_system_sink();
        let fallback = vec![&spec];
        let got = specs_for(None, &fallback, "python", "system");
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn specs_for_collects_the_wildcard_method_bucket_alongside_a_named_match() {
        let named = os_system_sink();
        let wildcard = MatchSpec {
            rule_id: "wild".to_string(),
            languages: std::collections::BTreeSet::from(["python".to_string()]),
            ..Default::default()
        };
        let specs = [named.clone(), wildcard.clone()];
        let index = build_spec_index(&specs);
        let got = specs_for(Some(&index), &[], "python", "system");
        let ids: std::collections::BTreeSet<&str> =
            got.iter().map(|s| s.rule_id.as_str()).collect();
        assert!(ids.contains("py.os.system"));
        assert!(ids.contains("wild"));
    }

    // ── JavaScript / TypeScript extractor ────────────────────────────

    fn js_exec_sink() -> MatchSpec {
        MatchSpec {
            rule_id: "js.child_process.exec".to_string(),
            role: "sink".to_string(),
            origin: "semgrep".to_string(),
            cwe: "CWE-78".to_string(),
            kind: "command_injection".to_string(),
            languages: std::collections::BTreeSet::from(["javascript".to_string()]),
            semantic_family: "command-exec".to_string(),
            module_attr_module: "cp".to_string(),
            module_attr_names: std::collections::BTreeSet::from(["exec".to_string()]),
            ..Default::default()
        }
    }

    #[test]
    fn js_extract_es_import_named_and_namespace_and_aliased() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            "import fs from 'fs';\nimport { readFile as rf } from 'fs-extra';\nimport * as cp from 'child_process';\n",
        );
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.imports.get("fs"), Some(&"fs".to_string()));
        assert_eq!(
            idx.imports.get("rf"),
            Some(&"fs-extra.readFile".to_string())
        );
        assert_eq!(idx.imports.get("cp"), Some(&"child_process".to_string()));
    }

    #[test]
    fn js_extract_commonjs_require() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            "const cp = require('child_process');\n",
        );
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.imports.get("cp"), Some(&"child_process".to_string()));
    }

    #[test]
    fn js_extract_function_declaration_and_method_in_class() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            "function handler(req) {}\nclass Server {\n  listen() {}\n}\n",
        );
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.functions.len(), 2);
        let handler = idx.functions.iter().find(|f| f.name == "handler").unwrap();
        assert_eq!(handler.class_name, "");
        let listen = idx.functions.iter().find(|f| f.name == "listen").unwrap();
        assert_eq!(listen.class_name, "Server");
    }

    #[test]
    fn js_extract_member_call_and_bare_call() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            "function handler(cmd) {\n  cp.exec(cmd);\n  doThing();\n}\n",
        );
        let sinks = vec![js_exec_sink()];
        let idx = scan_file(
            &path,
            "app.js",
            "javascript",
            &[],
            &sinks,
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(idx.call_edges.len(), 2);
        assert!(idx.call_edges.contains(&(
            "handler".to_string(),
            "cp".to_string(),
            "exec".to_string()
        )));
        assert!(idx.call_edges.contains(&(
            "handler".to_string(),
            String::new(),
            "doThing".to_string()
        )));
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].matched_rule, "js.child_process.exec");
    }

    #[test]
    fn js_extract_assigns_returns_and_call_args_are_populated_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            "function f(x) {\n  const y = x;\n  run(y);\n  return y;\n}\n",
        );
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.functions[0].params, vec!["x".to_string()]);
        assert_eq!(idx.assigns.len(), 1);
        assert_eq!(idx.assigns[0].dst_symbol, "y");
        assert_eq!(idx.assigns[0].src_symbol, Some("x".to_string()));
        assert_eq!(idx.assigns[0].function_qnode, "f");
        assert_eq!(idx.returns.len(), 1);
        assert_eq!(idx.returns[0].symbol, Some("y".to_string()));
        assert_eq!(idx.call_args.len(), 1);
        assert_eq!(idx.call_args[0].callee_name, "run");
        assert_eq!(idx.call_args[0].arg_symbols, vec!["y".to_string()]);
        assert_eq!(idx.call_args[0].arg_slots, vec![0]);
    }

    #[test]
    fn js_leftmost_identifier_walks_a_chained_member_call() {
        let tree = {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_javascript::LANGUAGE.into())
                .unwrap();
            parser.parse(b"a.b.c();", None).unwrap()
        };
        let call = find_kind(tree.root_node(), "call_expression").unwrap();
        let fn_node = call.child_by_field_name("function").unwrap();
        assert_eq!(js_leftmost_identifier(fn_node, b"a.b.c();"), "a");
    }

    #[test]
    fn js_leftmost_identifier_walks_through_a_call_expression_object() {
        // `getFoo().bar()`: the outer call's function is a member_expression
        // whose object is itself a call_expression — exercises the
        // "call_expression" arm of the leftmost walk, not just
        // "member_expression".
        let src: &[u8] = b"getFoo().bar();";
        let tree = {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_javascript::LANGUAGE.into())
                .unwrap();
            parser.parse(src, None).unwrap()
        };
        let call = find_kind(tree.root_node(), "call_expression").unwrap();
        let fn_node = call.child_by_field_name("function").unwrap();
        assert_eq!(js_leftmost_identifier(fn_node, src), "getFoo");
    }

    #[test]
    fn js_leftmost_identifier_wildcard_arm_walks_then_dead_ends() {
        // `(a || b).c()`: the member_expression's object is a
        // parenthesized_expression — neither identifier, member_expression,
        // nor call_expression — hits the wildcard arm, which walks its
        // literal `(` token child; that token itself has no children,
        // hitting the wildcard's own fallback on the next iteration. One
        // test exercises both the wildcard's success path and its
        // fallback.
        let src: &[u8] = b"(a || b).c();";
        let tree = {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_javascript::LANGUAGE.into())
                .unwrap();
            parser.parse(src, None).unwrap()
        };
        let call = find_kind(tree.root_node(), "call_expression").unwrap();
        let fn_node = call.child_by_field_name("function").unwrap();
        assert_eq!(js_leftmost_identifier(fn_node, src), "");
    }

    #[test]
    fn js_extract_ignores_a_call_whose_function_is_neither_member_nor_identifier() {
        // `(a || b)()`: the call's function is a parenthesized_expression —
        // neither "member_expression" nor "identifier" — so no call is
        // recorded at all.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.js", "(a || b)();\n");
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        assert!(idx.call_edges.is_empty());
    }

    #[test]
    fn js_extract_mixed_default_and_named_import() {
        // The comma between `Default` and `{ named }` is an anonymous
        // token child of `import_clause` — exercises the wildcard arm of
        // `js_visit_import_clause`'s match.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.js",
            "import Default, { named } from 'x';\n",
        );
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.imports.get("Default"), Some(&"x".to_string()));
        assert_eq!(idx.imports.get("named"), Some(&"x.named".to_string()));
    }

    #[test]
    fn js_extract_named_import_with_an_empty_source_string() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "app.js", "import { x } from '';\n");
        let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.imports.get("x"), Some(&"x".to_string()));
    }

    #[test]
    fn typescript_uses_the_same_extractor_as_javascript() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "app.ts",
            "function handler(cmd: string) {\n  cp.exec(cmd);\n}\n",
        );
        let sinks = vec![MatchSpec {
            languages: std::collections::BTreeSet::from(["typescript".to_string()]),
            ..js_exec_sink()
        }];
        let idx = scan_file(
            &path,
            "app.ts",
            "typescript",
            &[],
            &sinks,
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(idx.language, "typescript");
        assert_eq!(idx.sink_hits.len(), 1);
    }

    #[test]
    fn a_tsx_component_is_parsed_with_the_tsx_grammar_under_the_typescript_label() {
        // `ext_to_lang` labels `.tsx` as `typescript`, and that label is
        // what lens selection, hint lookup and `MatchSpec::languages` key
        // on; only the grammar differs. With the TypeScript grammar,
        // `<div className="x">` is a type assertion followed by garbage,
        // and error recovery drops the subtree holding `onSubmit`, so the
        // handler and the sink call inside it both vanish.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "Form.tsx",
            "export const Form = () => {\n\
               const banner = <div className=\"x\">hi</div>;\n\
               const onSubmit = (cmd: string) => { cp.exec(cmd); };\n\
               return <form onSubmit={onSubmit}>{banner}</form>;\n\
             };\n",
        );
        let sinks = vec![MatchSpec {
            languages: std::collections::BTreeSet::from(["typescript".to_string()]),
            ..js_exec_sink()
        }];
        let idx = scan_file(
            &path,
            "Form.tsx",
            "typescript",
            &[],
            &sinks,
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(idx.language, "typescript");
        let names: Vec<&str> = idx.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.contains(&"Form") && names.contains(&"onSubmit"),
            "{names:?}"
        );
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].containing_fn, "onSubmit");
    }

    #[test]
    fn a_jsx_component_still_parses_with_the_javascript_grammar() {
        // The twin of the `.tsx` case: the JavaScript grammar has always
        // accepted JSX, and `.jsx` must not have been re-routed anywhere.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "Form.jsx",
            "export const Form = () => {\n\
               const onSubmit = (cmd) => { cp.exec(cmd); };\n\
               return <form onSubmit={onSubmit}><div className=\"x\">hi</div></form>;\n\
             };\n",
        );
        let sinks = vec![js_exec_sink()];
        let idx = scan_file(
            &path,
            "Form.jsx",
            "javascript",
            &[],
            &sinks,
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(idx.language, "javascript");
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].containing_fn, "onSubmit");
    }

    #[test]
    fn normalize_lang_for_grammar_rewrites_only_typescript_under_a_tsx_suffix() {
        assert_eq!(
            normalize_lang_for_grammar("src/Form.tsx", "typescript"),
            "tsx"
        );
        assert_eq!(normalize_lang_for_grammar("FORM.TSX", "typescript"), "tsx");
        assert_eq!(
            normalize_lang_for_grammar("src/api.ts", "typescript"),
            "typescript"
        );
        assert_eq!(
            normalize_lang_for_grammar("src/api.mts", "typescript"),
            "typescript"
        );
        assert_eq!(
            normalize_lang_for_grammar("Form.jsx", "javascript"),
            "javascript"
        );
        // The label owns dispatch: a `.tsx` suffix under another label is
        // left alone.
        assert_eq!(
            normalize_lang_for_grammar("Form.tsx", "javascript"),
            "javascript"
        );
    }

    #[test]
    fn tsx_is_a_grammar_key_not_a_language() {
        // Nothing may hand `"tsx"` to the label-keyed tables: it is not a
        // supported language and has no extractor of its own.
        assert!(ts_language("tsx").is_some());
        assert!(!supported_languages().contains(&"tsx"));
        let tree = parse(b"x = 1\n");
        assert!(extract("tsx", b"x = 1\n", tree.root_node()).is_none());
    }

    // ── Go extractor ──────────────────────────────────────────────────

    fn go_exec_sink() -> MatchSpec {
        MatchSpec {
            rule_id: "go.os_exec.command".to_string(),
            role: "sink".to_string(),
            origin: "semgrep".to_string(),
            cwe: "CWE-78".to_string(),
            kind: "command_injection".to_string(),
            languages: std::collections::BTreeSet::from(["go".to_string()]),
            semantic_family: "command-exec".to_string(),
            module_attr_module: "exec".to_string(),
            module_attr_names: std::collections::BTreeSet::from(["Command".to_string()]),
            ..Default::default()
        }
    }

    #[test]
    fn go_extract_single_import_spec_and_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            "package main\nimport \"fmt\"\nimport (\n\t\"os/exec\"\n\tosx \"os\"\n)\nfunc main() {}\n",
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.imports.get("fmt"), Some(&"fmt".to_string()));
        assert_eq!(idx.imports.get("exec"), Some(&"os/exec".to_string()));
        assert_eq!(idx.imports.get("osx"), Some(&"os".to_string()));
    }

    #[test]
    fn go_extract_blank_and_dot_import_aliases_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            "package main\nimport (\n\t_ \"os\"\n\t. \"fmt\"\n)\nfunc main() {}\n",
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        assert!(idx.imports.is_empty());
    }

    #[test]
    fn go_extract_function_and_method_declaration() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            "package main\ntype T struct{}\nfunc main() {}\nfunc (t T) Run() {}\n",
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.functions.len(), 2);
        assert!(idx.functions.iter().any(|f| f.name == "main"));
        assert!(idx.functions.iter().any(|f| f.name == "Run"));
    }

    #[test]
    fn go_extract_selector_call_and_bare_call() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            "package main\nimport \"os/exec\"\nfunc run(cmd string) {\n\texec.Command(cmd)\n\tdoThing()\n}\n",
        );
        let sinks = vec![go_exec_sink()];
        let idx = scan_file(&path, "main.go", "go", &[], &sinks, false, None, None).unwrap();
        assert_eq!(idx.call_edges.len(), 2);
        assert!(idx.call_edges.contains(&(
            "run".to_string(),
            "exec".to_string(),
            "Command".to_string()
        )));
        assert!(idx.call_edges.contains(&(
            "run".to_string(),
            String::new(),
            "doThing".to_string()
        )));
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].matched_rule, "go.os_exec.command");
    }

    #[test]
    fn go_extract_assigns_returns_and_call_args_are_populated_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            "package main\nfunc f(x string) string {\n\ty := x\n\trun(y)\n\treturn y\n}\n",
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.functions[0].params, vec!["x".to_string()]);
        assert_eq!(idx.assigns.len(), 1);
        assert_eq!(idx.assigns[0].dst_symbol, "y");
        assert_eq!(idx.assigns[0].src_symbol, Some("x".to_string()));
        assert_eq!(idx.assigns[0].function_qnode, "f");
        assert_eq!(idx.returns.len(), 1);
        assert_eq!(idx.returns[0].symbol, Some("y".to_string()));
        assert_eq!(idx.call_args.len(), 1);
        assert_eq!(idx.call_args[0].callee_name, "run");
        assert_eq!(idx.call_args[0].arg_symbols, vec!["y".to_string()]);
        assert_eq!(idx.call_args[0].arg_slots, vec![0]);
    }

    #[test]
    fn go_leftmost_identifier_walks_a_chained_selector_call() {
        let tree = {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_go::LANGUAGE.into())
                .unwrap();
            parser
                .parse(b"package main\nfunc f() { a.b.c() }\n", None)
                .unwrap()
        };
        let call = find_kind(tree.root_node(), "call_expression").unwrap();
        let fn_node = call.child_by_field_name("function").unwrap();
        assert_eq!(
            go_leftmost_identifier(fn_node, b"package main\nfunc f() { a.b.c() }\n"),
            "a"
        );
    }

    #[test]
    fn go_leftmost_identifier_walks_through_a_call_expression_operand() {
        // `getFoo().Bar()`: the outer call's function is a
        // selector_expression whose operand is itself a call_expression —
        // exercises the "call_expression" arm of the leftmost walk.
        let src: &[u8] = b"package main\nfunc f() { getFoo().Bar() }\n";
        let tree = {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_go::LANGUAGE.into())
                .unwrap();
            parser.parse(src, None).unwrap()
        };
        let call = find_kind(tree.root_node(), "call_expression").unwrap();
        let fn_node = call.child_by_field_name("function").unwrap();
        assert_eq!(go_leftmost_identifier(fn_node, src), "getFoo");
    }

    #[test]
    fn go_leftmost_identifier_wildcard_arm_walks_then_dead_ends() {
        // `(x).Foo()`: the selector_expression's operand is a
        // parenthesized_expression — neither identifier, selector_expression,
        // nor call_expression — hits the wildcard arm, which walks its
        // literal `(` token child; that token itself has no children,
        // hitting the wildcard's own fallback on the next iteration.
        let src: &[u8] = b"package main\nfunc f() { (x).Foo() }\n";
        let tree = {
            let mut parser = Parser::new();
            parser
                .set_language(&tree_sitter_go::LANGUAGE.into())
                .unwrap();
            parser.parse(src, None).unwrap()
        };
        let call = find_kind(tree.root_node(), "call_expression").unwrap();
        let fn_node = call.child_by_field_name("function").unwrap();
        assert_eq!(go_leftmost_identifier(fn_node, src), "");
    }

    #[test]
    fn go_extract_ignores_a_call_whose_function_is_neither_selector_nor_identifier() {
        // `(fn)()`: the call's function is a parenthesized_expression —
        // neither "selector_expression" nor "identifier" — so no call is
        // recorded at all.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "main.go",
            "package main\nvar fn func()\nfunc f() {\n\t(fn)()\n}\n",
        );
        let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
        assert!(idx.call_edges.is_empty());
    }

    // ── Java extractor ────────────────────────────────────────────────

    fn java_exec_sink() -> MatchSpec {
        MatchSpec {
            rule_id: "java.runtime.exec".to_string(),
            role: "sink".to_string(),
            origin: "semgrep".to_string(),
            cwe: "CWE-78".to_string(),
            kind: "command_injection".to_string(),
            languages: std::collections::BTreeSet::from(["java".to_string()]),
            semantic_family: "command-exec".to_string(),
            module_attr_module: "rt".to_string(),
            module_attr_names: std::collections::BTreeSet::from(["exec".to_string()]),
            ..Default::default()
        }
    }

    fn parse_java(src: &[u8]) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn java_extract_import_declaration_simple_and_wildcard() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "import java.util.List;\nimport java.io.*;\nclass App {}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.imports.get("List"), Some(&"java.util.List".to_string()));
        // The wildcard import contributes no binding at all.
        assert!(!idx.imports.values().any(|v| v == "java.io"));
    }

    #[test]
    fn java_extract_class_declaration_registers_a_package_qualified_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "package com.example;\nclass App {}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.imports.get("App"), Some(&"com.example.App".to_string()));
    }

    #[test]
    fn java_extract_class_declaration_without_a_package_uses_the_bare_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "App.java", "class App {}\n");
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.imports.get("App"), Some(&"App".to_string()));
    }

    #[test]
    fn java_extract_method_and_constructor_carry_the_enclosing_class_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    App() {}\n    void run() {}\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.functions.len(), 2);
        assert!(idx.functions.iter().all(|f| f.class_name == "App"));
        assert!(idx.functions.iter().any(|f| f.name == "App"));
        assert!(idx.functions.iter().any(|f| f.name == "run"));
    }

    #[test]
    fn java_extract_method_invocation_and_object_creation() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run(String cmd) {\n        rt.exec(cmd);\n        new Foo();\n    }\n}\n",
        );
        let sinks = vec![java_exec_sink()];
        let idx = scan_file(&path, "App.java", "java", &[], &sinks, false, None, None).unwrap();
        assert!(idx.call_edges.contains(&(
            "run".to_string(),
            "rt".to_string(),
            "exec".to_string()
        )));
        assert!(idx
            .call_edges
            .contains(&("run".to_string(), String::new(), "Foo".to_string())));
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].matched_rule, "java.runtime.exec");
    }

    #[test]
    fn java_extract_object_creation_with_a_qualified_type_uses_the_short_class_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run() {\n        new java.util.ArrayList();\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert!(idx.call_edges.contains(&(
            "run".to_string(),
            String::new(),
            "ArrayList".to_string()
        )));
    }

    #[test]
    fn java_extract_local_variable_declaration_narrows_the_type_via_constructor() {
        // `Iface x = new Impl();` should resolve `x` to `Impl` (the
        // constructor's concrete type), not just the declared `Iface`
        // type — matching `_java_extract`'s own narrowing comment.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run() {\n        Runnable x = new Impl();\n        x.run();\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.imports.get("x"), Some(&"Impl".to_string()));
        assert_eq!(idx.assigns.len(), 1);
        assert_eq!(idx.assigns[0].dst_symbol, "x");
        assert_eq!(idx.assigns[0].src_call, Some("Impl".to_string()));
    }

    #[test]
    fn java_extract_local_variable_declaration_with_an_identifier_initializer() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run(String cmd) {\n        String y = cmd;\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.assigns.len(), 1);
        assert_eq!(idx.assigns[0].src_symbol, Some("cmd".to_string()));
    }

    #[test]
    fn java_extract_local_variable_declaration_with_a_method_call_initializer() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run() {\n        String z = getName();\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.assigns.len(), 1);
        assert_eq!(idx.assigns[0].src_call, Some("getName".to_string()));
    }

    #[test]
    fn java_extract_local_variable_declaration_with_no_initializer_records_no_assign() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run() {\n        String s;\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert!(idx.assigns.is_empty());
    }

    #[test]
    fn java_extract_a_type_that_normalizes_to_empty_records_no_local_types() {
        // `<>` (a bare diamond type argument list with no leading type
        // name) is real, parseable tree-sitter-java input — its
        // `type_identifier` is an empty string, and stripping the
        // `<...>` generic-argument text leaves nothing at all, so
        // `java_resolve_type` normalizes to "". Exercises
        // `java_visit_local_variable_declaration`'s own early return for
        // that case, distinct from a missing type field entirely.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run() {\n        <> x;\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert!(!idx.imports.contains_key("x"));
    }

    #[test]
    fn java_extract_assignment_expression_various_rhs_kinds() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run(String cmd) {\n        String a;\n        String b;\n        String c;\n        a = cmd;\n        b = getName();\n        c = new Foo();\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.assigns.len(), 3);
        assert!(idx
            .assigns
            .iter()
            .any(|a| a.dst_symbol == "a" && a.src_symbol == Some("cmd".to_string())));
        assert!(idx
            .assigns
            .iter()
            .any(|a| a.dst_symbol == "b" && a.src_call == Some("getName".to_string())));
        assert!(idx
            .assigns
            .iter()
            .any(|a| a.dst_symbol == "c" && a.src_call == Some("Foo".to_string())));
    }

    #[test]
    fn java_extract_assignment_expression_narrows_a_cast_type() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run(Object o) {\n        Foo f;\n        f = (Foo) o;\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.imports.get("f"), Some(&"Foo".to_string()));
    }

    #[test]
    fn java_extract_assignment_to_a_non_identifier_lhs_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run(String cmd) {\n        this.field = cmd;\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert!(idx.assigns.is_empty());
    }

    #[test]
    fn java_extract_return_statement_with_and_without_an_identifier() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    String run(String cmd) {\n        if (cmd == null) {\n            return null;\n        }\n        return cmd;\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.returns.len(), 2);
        assert!(idx.returns.iter().any(|r| r.symbol.is_none()));
        assert!(idx
            .returns
            .iter()
            .any(|r| r.symbol == Some("cmd".to_string())));
    }

    #[test]
    fn java_extract_formal_parameter_type_hint() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run(Foo foo) {}\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.imports.get("foo"), Some(&"Foo".to_string()));
    }

    #[test]
    fn java_extract_catch_formal_parameter_has_no_type_field_to_resolve() {
        // tree-sitter-java wraps a caught exception's type in a
        // `catch_type` node with no `"type"` field of its own (unlike
        // `formal_parameter`, which exposes one directly) — so
        // `node.child_by_field_name("type")` genuinely returns `None`
        // here, matching `_java_extract`'s own `"formal_parameter" |
        // "catch_formal_parameter"` branch exactly: it reuses the same
        // lookup for both kinds, so a caught exception's type is never
        // captured in the Python original either. Faithfully replicated,
        // not a gap this port introduces.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run() {\n        try {\n        } catch (Bar bar) {\n        }\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert!(!idx.imports.contains_key("bar"));
    }

    #[test]
    fn java_extract_call_args_captures_identifier_arguments_and_target_symbol() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    void run(String cmd) {\n        String out = helper(cmd);\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.call_args.len(), 1);
        assert_eq!(idx.call_args[0].arg_symbols, vec!["cmd".to_string()]);
        assert_eq!(idx.call_args[0].target_symbol, Some("out".to_string()));
    }

    #[test]
    fn java_leftmost_identifier_walks_field_access_and_a_dead_end() {
        let src: &[u8] = b"class App { void run() { a.b.c(); } }";
        let tree = parse_java(src);
        // The outermost call's object is `a.b`, a field_access.
        let obj = find_kind(tree.root_node(), "field_access").unwrap();
        assert_eq!(java_leftmost_identifier(obj, src), "a");
    }

    #[test]
    fn java_invocation_parts_receiver_is_empty_when_the_object_is_itself_a_call() {
        // `_java_leftmost`'s asymmetric handling: a `method_invocation`
        // object with no further `object` field is a dead end (empty),
        // unlike `field_access`'s fallback-to-first-child.
        let src: &[u8] = b"class App { void run() { getFoo().bar(); } }";
        let tree = parse_java(src);
        // `find_kind` walks pre-order, so it returns the OUTER
        // `getFoo().bar()` call before descending into its `getFoo()`
        // object.
        let outer = find_kind(tree.root_node(), "method_invocation").unwrap();
        let (receiver, method) = java_invocation_parts(outer, src);
        assert_eq!(method, "bar");
        assert_eq!(receiver, "");
    }

    #[test]
    fn java_extract_ignores_a_method_invocation_with_no_name() {
        // Directly probes `java_invocation_parts` with a node that has
        // neither a `name` nor `object` field — matching the module's
        // established pattern of testing a helper directly with a
        // differently-shaped real node when the helper itself doesn't
        // validate its argument's kind.
        let src: &[u8] = b"class App {}";
        let tree = parse_java(src);
        let (receiver, method) = java_invocation_parts(tree.root_node(), src);
        assert_eq!(receiver, "");
        assert_eq!(method, "");
    }

    #[test]
    fn java_extract_assigns_returns_and_call_args_are_populated_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.java",
            "class App {\n    String run(String cmd) {\n        String out = helper(cmd);\n        return out;\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
        assert!(!idx.assigns.is_empty());
        assert!(!idx.returns.is_empty());
        assert!(!idx.call_args.is_empty());
    }

    // ── C# extractor ─────────────────────────────────────────────────

    fn cs_exec_sink() -> MatchSpec {
        MatchSpec {
            rule_id: "cs.process.start".to_string(),
            role: "sink".to_string(),
            origin: "semgrep".to_string(),
            cwe: "CWE-78".to_string(),
            kind: "command_injection".to_string(),
            languages: std::collections::BTreeSet::from(["csharp".to_string()]),
            semantic_family: "command-exec".to_string(),
            module_attr_module: "Process".to_string(),
            module_attr_names: std::collections::BTreeSet::from(["Start".to_string()]),
            ..Default::default()
        }
    }

    fn parse_cs(src: &[u8]) -> Tree {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn cs_extract_using_directive_registers_the_top_level_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "using System.Diagnostics;\nclass App {}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert_eq!(
            idx.imports.get("Diagnostics"),
            Some(&"System.Diagnostics".to_string())
        );
    }

    #[test]
    fn cs_extract_class_struct_and_interface_all_scope_their_methods() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class C {\n    void M() {}\n}\nstruct S {\n    void N() {}\n}\ninterface I {\n    void O();\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert!(idx
            .functions
            .iter()
            .any(|f| f.name == "M" && f.class_name == "C"));
        assert!(idx
            .functions
            .iter()
            .any(|f| f.name == "N" && f.class_name == "S"));
        assert!(idx
            .functions
            .iter()
            .any(|f| f.name == "O" && f.class_name == "I"));
    }

    #[test]
    fn cs_extract_local_function_statement_has_no_class_scope() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    void Run() {\n        void Local() {}\n        Local();\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert!(idx
            .functions
            .iter()
            .any(|f| f.name == "Local" && f.class_name.is_empty()));
    }

    #[test]
    fn cs_extract_invocation_and_object_creation() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    void Run(string cmd) {\n        Process.Start(cmd);\n        var f = new Foo();\n    }\n}\n",
        );
        let sinks = vec![cs_exec_sink()];
        let idx = scan_file(&path, "App.cs", "csharp", &[], &sinks, false, None, None).unwrap();
        assert!(idx.call_edges.contains(&(
            "Run".to_string(),
            "Process".to_string(),
            "Start".to_string()
        )));
        assert!(idx
            .call_edges
            .contains(&("Run".to_string(), String::new(), "Foo".to_string())));
        assert_eq!(idx.sink_hits.len(), 1);
        assert_eq!(idx.sink_hits[0].matched_rule, "cs.process.start");
    }

    #[test]
    fn cs_extract_object_creation_with_a_qualified_type_uses_the_short_class_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    void Run() {\n        var l = new System.Collections.ArrayList();\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert!(idx.call_edges.contains(&(
            "Run".to_string(),
            String::new(),
            "ArrayList".to_string()
        )));
    }

    #[test]
    fn cs_extract_variable_declarator_with_an_identifier_initializer() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    void Run(string cmd) {\n        string y = cmd;\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.assigns.len(), 1);
        assert_eq!(idx.assigns[0].dst_symbol, "y");
        assert_eq!(idx.assigns[0].src_symbol, Some("cmd".to_string()));
    }

    #[test]
    fn cs_extract_variable_declarator_with_a_method_call_initializer() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    void Run() {\n        string z = GetName();\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.assigns.len(), 1);
        assert_eq!(idx.assigns[0].src_call, Some("GetName".to_string()));
    }

    #[test]
    fn cs_extract_variable_declarator_with_a_constructor_initializer() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    void Run() {\n        var f = new Foo();\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert!(idx
            .assigns
            .iter()
            .any(|a| a.dst_symbol == "f" && a.src_call == Some("Foo".to_string())));
    }

    #[test]
    fn cs_extract_variable_declarator_with_no_initializer_records_no_assign() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(dir.path(), "App.cs", "class App {\n    string s;\n}\n");
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert!(idx.assigns.is_empty());
    }

    #[test]
    fn cs_extract_assignment_expression_various_rhs_kinds() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    void Run(string cmd) {\n        string a;\n        string b;\n        string c;\n        a = cmd;\n        b = GetName();\n        c = new Foo();\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert!(idx
            .assigns
            .iter()
            .any(|a| a.dst_symbol == "a" && a.src_symbol == Some("cmd".to_string())));
        assert!(idx
            .assigns
            .iter()
            .any(|a| a.dst_symbol == "b" && a.src_call == Some("GetName".to_string())));
        assert!(idx
            .assigns
            .iter()
            .any(|a| a.dst_symbol == "c" && a.src_call == Some("Foo".to_string())));
    }

    #[test]
    fn cs_extract_assignment_to_a_non_identifier_lhs_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    string field;\n    void Run(string cmd) {\n        this.field = cmd;\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert!(idx.assigns.is_empty());
    }

    #[test]
    fn cs_extract_return_statement_with_and_without_an_identifier() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    string Run(string cmd) {\n        if (cmd == null) {\n            return null;\n        }\n        return cmd;\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.returns.len(), 2);
        assert!(idx.returns.iter().any(|r| r.symbol.is_none()));
        assert!(idx
            .returns
            .iter()
            .any(|r| r.symbol == Some("cmd".to_string())));
    }

    #[test]
    fn cs_extract_call_args_captures_the_assignment_target_symbol() {
        // `cs_call_target`'s `assignment_expression` check (a plain
        // `outp = Helper(cmd);`, not a `var outp = Helper(cmd);`
        // declaration): tree-sitter-c-sharp 0.23.5 genuinely produces
        // that node kind here, with real `left`/`right` fields — unlike
        // the declaration-initializer path documented in the next test.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    void Run(string cmd) {\n        string outp;\n        outp = Helper(cmd);\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.call_args.len(), 1);
        assert_eq!(idx.call_args[0].target_symbol, Some("outp".to_string()));
    }

    #[test]
    fn cs_extract_call_args_target_symbol_for_a_declaration_initializer() {
        // `cs_call_target`'s `equals_value_clause`/`variable_declarator.
        // value`-field checks both assume grammar shapes tree-sitter-
        // c-sharp 0.23.5 doesn't actually produce: verified directly
        // that `var outp = Helper(cmd);`'s `variable_declarator` has no
        // `equals_value_clause` wrapper and no `"value"` field at all
        // (its initializer is an unnamed-field child after `=`, matching
        // `cs_visit_variable_declarator`'s own documented workaround for
        // exactly this). The consequence was that no C# source bound to
        // a local — `var q = Console.ReadLine();` — ever seeded taint,
        // since `_seed_source_taint` keys entirely on `target_symbol`,
        // so `cs_call_target` now falls back to the same positional
        // read its sibling already used.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    void Run(string cmd) {\n        var outp = Helper(cmd);\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.call_args.len(), 1);
        assert_eq!(idx.call_args[0].target_symbol, Some("outp".to_string()));
    }

    #[test]
    fn cs_extract_call_args_unwrap_the_argument_node_positionally() {
        // `_cs_identifier_args`'s `"argument"` branch reads an
        // `"expression"` field Python's original expects every
        // `argument` node to carry — but tree-sitter-c-sharp 0.23.5 (the
        // version this workspace pins) never actually populates one:
        // verified directly (`argument.child_by_field_name("expression")`
        // is `None` even for a bare identifier argument like
        // `Helper(cmd)`, whose sole child is an unnamed-field
        // `identifier`). The upshot upstream is that **every C# call's
        // `arg_symbols` is empty**, so no C# path can ever ground in
        // taint evidence — a total blind spot, not a corner case.
        // `cs_value_symbols` walks the `argument` wrapper's named
        // children instead, which is what the original meant to do.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    void Run(string cmd) {\n        Helper(cmd);\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.call_args.len(), 1);
        assert_eq!(idx.call_args[0].arg_symbols, vec!["cmd".to_string()]);
    }

    #[test]
    fn cs_extract_call_args_object_creation_with_no_arguments_field_yields_no_arg_symbols() {
        // `new Foo { X = 1 }` (an object-initializer with no parens) has
        // a `type` and an `initializer` field but, confirmed via a live
        // probe, NO `arguments` field at all — unlike `new Foo()`, which
        // always carries an (possibly empty) `argument_list`. Exercises
        // `_cs_identifier_args`'s `args_node is None` fallback.
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    void Run() {\n        var f = new Foo { X = 1 };\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert_eq!(idx.call_args.len(), 1);
        assert!(idx.call_args[0].arg_symbols.is_empty());
    }

    #[test]
    fn cs_leftmost_identifier_walks_member_access_and_a_dead_end() {
        let src: &[u8] = b"class App { void Run() { a.b.c(); } }";
        let tree = parse_cs(src);
        let obj = find_kind(tree.root_node(), "member_access_expression").unwrap();
        assert_eq!(cs_leftmost_identifier(obj, src), "a");
    }

    #[test]
    fn cs_leftmost_identifier_wildcard_arm_walks_then_dead_ends() {
        // `(a || b).c()`'s callee is a `member_access_expression` whose
        // `expression` field is a `parenthesized_expression` — neither an
        // identifier nor one of the two explicitly-handled node kinds, so
        // the walk falls into the wildcard arm, descends into the `(`
        // token via `child(0)`, then dead-ends (a token has no children).
        // Mirrors the equivalent JS/Go wildcard-arm tests.
        let src: &[u8] = b"class App { void Run() { (a || b).c(); } }";
        let tree = parse_cs(src);
        let obj = find_kind(tree.root_node(), "member_access_expression").unwrap();
        assert_eq!(cs_leftmost_identifier(obj, src), "");
    }

    #[test]
    fn cs_leftmost_identifier_falls_back_to_the_first_child_on_a_bare_invocation() {
        // Unlike Java's `method_invocation` (a dead end when `object` is
        // missing), C#'s `_cs_leftmost` falls back to the invocation's
        // own first child when it has no `function` field to walk into.
        let src: &[u8] = b"class App { void Run() { Local(); } }";
        let tree = parse_cs(src);
        let call = find_kind(tree.root_node(), "invocation_expression").unwrap();
        assert_eq!(cs_leftmost_identifier(call, src), "Local");
    }

    #[test]
    fn cs_extract_ignores_an_invocation_with_no_function_or_name() {
        let src: &[u8] = b"class App {}";
        let tree = parse_cs(src);
        let (receiver, method) = cs_invocation_parts(tree.root_node(), src);
        assert_eq!(receiver, "");
        assert_eq!(method, "");
    }

    #[test]
    fn cs_extract_assigns_returns_and_call_args_are_populated_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_py(
            dir.path(),
            "App.cs",
            "class App {\n    string Run(string cmd) {\n        var outp = Helper(cmd);\n        return outp;\n    }\n}\n",
        );
        let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
        assert!(!idx.assigns.is_empty());
        assert!(!idx.returns.is_empty());
        assert!(!idx.call_args.is_empty());
    }
}
