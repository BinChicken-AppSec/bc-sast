use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use tree_sitter::{Node, Parser, Tree};

use crate::rules::MatchSpec;

mod csharp;
mod go;
mod java;
mod javascript;
mod lite;
mod python;

pub(crate) use csharp::*;
use go::*;
pub(crate) use java::*;
use javascript::*;
pub(crate) use python::*;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallSite {
    pub file: String,
    pub line: usize,
    pub receiver: String,
    pub method: String,
    pub containing_fn: String,
    pub snippet: String,
    pub matched_rule: String,
    pub cwe: String,
    pub role: String,
    pub kind: String,
    pub semantic_family: String,
    pub owasp_top10_2025: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FuncDef {
    pub name: String,
    pub start_line: usize,
    pub end_line: usize,
    pub class_name: String,
    pub params: Vec<String>,
}

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
    pub arg_slots: Vec<usize>,
    pub target_symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FieldWriteFact {
    pub function_qnode: String,
    pub line: usize,
    pub receiver: String,
    pub field: String,
    pub src_symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FieldReadFact {
    pub function_qnode: String,
    pub line: usize,
    pub receiver: String,
    pub field: String,
    pub dst_symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerWriteFact {
    pub function_qnode: String,
    pub line: usize,
    pub container_symbol: String,
    pub element_symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReflectionFact {
    pub function_qnode: String,
    pub line: usize,
    pub call_type: String,
    pub target_symbols: Vec<String>,
    pub receiver: String,
    pub language: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FrameworkMarkerFact {
    pub function_qnode: String,
    pub line: usize,
    pub marker_type: String,
    pub marker_name: String,
    pub parameter_names: Vec<String>,
    pub framework: String,
    pub confidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthGuardFact {
    pub function_qnode: String,
    pub line: usize,
    pub marker_name: String,
    pub requires_auth: bool,
    pub framework: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RouteTaintFact {
    pub function_qnode: String,
    pub line: usize,
    pub route_pattern: String,
    pub parameter_name: String,
    pub is_tainted: bool,
    pub framework: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResponseDataflowFact {
    pub function_qnode: String,
    pub line: usize,
    pub from_symbol: String,
    pub to_sink: String,
    pub framework: String,
    pub response_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileIndex {
    pub file: String,
    pub language: String,
    pub imports: BTreeMap<String, String>,
    pub functions: Vec<FuncDef>,
    pub source_hits: Vec<CallSite>,
    pub sink_hits: Vec<CallSite>,
    pub call_edges: Vec<(String, String, String)>,
    pub observed_calls: Vec<ObservedCall>,
    pub assigns: Vec<VarAssignFact>,
    pub returns: Vec<ReturnFact>,
    pub call_args: Vec<CallArgFact>,
    pub field_writes: Vec<FieldWriteFact>,
    pub field_reads: Vec<FieldReadFact>,
    pub container_writes: Vec<ContainerWriteFact>,
    pub reflection_facts: Vec<ReflectionFact>,
    pub framework_markers: Vec<FrameworkMarkerFact>,
    pub auth_guards: Vec<AuthGuardFact>,
    pub route_facts: Vec<RouteTaintFact>,
    pub response_dataflow: Vec<ResponseDataflowFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RawCall {
    line: usize,
    receiver: String,
    method: String,
    containing_fn: String,
    snippet: String,
    static_args: Vec<bool>,
    arithmetic_args: Vec<bool>,
    unit_args: Vec<bool>,
    arg_count: Option<usize>,
    first_arg_symbol: Option<String>,
    property_read: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ExtractResult {
    imports: BTreeMap<String, String>,
    functions: Vec<FuncDef>,
    calls: Vec<RawCall>,
    assigns: Vec<VarAssignFact>,
    returns: Vec<ReturnFact>,
    call_args: Vec<CallArgFact>,
}

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

pub(crate) fn py_text(node: Node, src: &[u8]) -> String {
    String::from_utf8_lossy(&src[node.start_byte()..node.end_byte()]).into_owned()
}

pub(crate) fn scope_for(offset: usize, ranges: &[(usize, usize, String)]) -> String {
    ranges
        .iter()
        .rev()
        .find(|(s, e, _)| *s <= offset && offset < *e)
        .map(|(_, _, name)| name.clone())
        .unwrap_or_default()
}

pub(crate) fn named_kids<'a>(node: Node<'a>) -> std::vec::IntoIter<Node<'a>> {
    let mut cursor = node.walk();
    let out: Vec<Node<'a>> = node.named_children(&mut cursor).collect();
    out.into_iter()
}

pub(crate) fn kids<'a>(node: Node<'a>) -> std::vec::IntoIter<Node<'a>> {
    let mut cursor = node.walk();
    let out: Vec<Node<'a>> = node.children(&mut cursor).collect();
    out.into_iter()
}

const COMPOSED_VALUE_MAX_DEPTH: usize = 8;

fn push_symbol(out: &mut Vec<String>, sym: String) {
    if !out.contains(&sym) {
        out.push(sym);
    }
}

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

pub(crate) fn static_arg_at(statics: &[bool], index: usize) -> bool {
    statics.get(index).copied().unwrap_or(false)
}

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
    for cf in call_args {
        if let Some(t) = cf.target_symbol.as_ref().filter(|t| !t.is_empty()) {
            built.insert((cf.function_qnode.clone(), t.clone()));
        }
    }
    let mut out: BTreeSet<(String, String)> = literal
        .iter()
        .filter(|k| !composed.contains(*k) && !built.contains(*k))
        .cloned()
        .collect();

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

const BINDING_MARKER_TYPES: &[&str] = &[
    "aspnet_annotation",
    "jaxrs_annotation",
    "nestjs_annotation",
    "php_superglobal",
    "spring_annotation",
];

pub const FRAMEWORK_BINDING_RULE: &str = "vvah.framework.binding";

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

const AXUM_EXTRACTORS: &[&str] = &[
    "Form",
    "Json",
    "Multipart",
    "Path",
    "Query",
    "RawQuery",
    "TypedHeader",
];

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

struct SemanticSink {
    kind: &'static str,
    cwe: &'static str,
    family: &'static str,
    owasp: &'static [&'static str],
}

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
        if spec.requires_dynamic_arg && static_arg_at(static_args, spec.dynamic_arg_index) {
            continue;
        }
        if spec.requires_arithmetic_arg
            && !arithmetic_args
                .get(spec.arithmetic_arg_index)
                .copied()
                .unwrap_or(false)
        {
            continue;
        }
        if spec.requires_unit_arg && !unit_args.get(spec.unit_arg_index).copied().unwrap_or(false) {
            continue;
        }
        if spec.requires_any_arg && arg_count == Some(0) {
            continue;
        }
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
            if matches!(language, "java" | "csharp" | "kotlin" | "scala") {
                let cls_tail = spec.class_name.rsplit('.').next().unwrap_or("");
                if !cls_tail.is_empty()
                    && (resolved == cls_tail || resolved.ends_with(&format!(".{cls_tail}")))
                {
                    return Some(spec);
                }
            }
            continue;
        }
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
        if spec.has_bare_call() && receiver.is_empty() && spec.bare_call_names.contains(method) {
            return Some(spec);
        }
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
    let (field_writes, field_reads, container_writes) =
        crate::facts::extract_field_facts(language, &src, root);
    let (framework_markers, route_facts, auth_guards) =
        crate::framework::extract_framework_facts(language, rel, &src, root);
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

        if !property_read {
            idx.call_edges
                .push((scope.clone(), receiver.clone(), method.clone()));
        }
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
        }
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
mod tests;
