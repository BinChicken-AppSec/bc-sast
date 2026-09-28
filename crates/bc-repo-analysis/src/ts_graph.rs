// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! tree-sitter call-graph backend for `step1.call_graph: tree_sitter`,
//! ported from `vvaharness/lang/ts_graph.py`. Drop-in alternative to
//! [`crate::supplement_call_graph`] with the same output contract:
//! qualified caller -> qualified callees, bare-name -> def-site
//! `"file:line"` locations, and (new here) qualified-name -> `[start_line,
//! end_line]` def spans for downstream function slicing.
//!
//! **Per-language queries** live in [`QUERIES`] — one `defs` query
//! capturing `@name` (the identifier) and `@def` (the whole function
//! node, for span/byte-range), and one `calls` query capturing `@callee`.
//! Unlike Python's own `_captures()` shim (needed there because
//! `tree_sitter_language_pack` sits across three tree-sitter API
//! generations), this port pins one exact `tree-sitter` version and uses
//! `QueryCursor::matches` directly for `defs` — since a single query
//! match already groups its own `@name`+`@def` captures together (a live
//! probe confirmed this holds even for multi-alternative-pattern queries
//! like Java's `method_declaration`/`constructor_declaration`), the
//! Python original's separate name-node/def-node collection + byte-range
//! reconciliation is unnecessary here.
//!
//! **Enclosing-def resolution** is byte-range based: each call site maps
//! to the innermost def whose `[start_byte, end_byte)` contains it —
//! exact for AST-derived ranges (regex can't do this — no end-of-def).
//!
//! **Cross-file callee resolution** reuses [`crate::resolve_callee_files`]
//! so polymorphic-name handling stays identical to the regex path.
//!
//! **Graceful degrade, two levels** (Python has a third — "the whole
//! `tree-sitter-language-pack` runtime dependency is missing" — that
//! cannot occur here: this port statically links all 14 grammar crates,
//! so the backend is always available): (1) a language has no [`QUERIES`]
//! entry — falls back to regex [`crate::scan_defs`]/[`crate::CALL_TOKEN_RX`]
//! for those files; (2) a query fails to compile against the linked
//! grammar — same regex fallback, logged once. Level 2 is dead for all 14
//! languages against the exact grammar versions this workspace pins
//! (verified via a live probe compiling every query), but kept as real
//! code rather than assumed away — a future grammar-crate version bump
//! could change that.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use tree_sitter::{Language, Node, Parser, Query, QueryCursor, StreamingIterator};

use crate::callgraph::{
    q_join, q_split, resolve_callee_files, scan_defs, CALL_TOKEN_RX, MODULE_SCOPE, NOT_A_DEF,
};
use crate::lang::ext_to_lang;

struct LangQuery {
    lang_id: &'static str,
    defs: &'static str,
    calls: &'static str,
}

/// Shared by JavaScript, TypeScript and TSX: tree-sitter-typescript's two
/// grammars keep JavaScript's node names for every construct these
/// queries touch.
const JS_FAMILY_DEFS: &str = "(function_declaration name: (identifier) @name) @def\n\
               (method_definition name: (property_identifier) @name) @def\n\
               (variable_declarator name: (identifier) @name \
                   value: [(arrow_function) (function_expression)]) @def";
const JS_FAMILY_CALLS: &str = "(call_expression function: [\
              (identifier) @callee \
              (member_expression property: (property_identifier) @callee)\
            ])";

/// Keys are `bc_repo_analysis::lang::ext_to_lang` language ids, after
/// [`normalize_lang_for_queries`] has resolved a family key to the
/// concrete grammar (`c`/`cpp`, `typescript`/`tsx`). Queries are
/// intentionally permissive — false-positive callees are pruned by the
/// def-site lookup, same as the regex path.
const QUERIES: &[LangQuery] = &[
    LangQuery {
        lang_id: "python",
        defs: "(function_definition name: (identifier) @name) @def",
        calls: "(call function: [\
              (identifier) @callee \
              (attribute attribute: (identifier) @callee)\
            ])",
    },
    // Upstream v1.3 adds class declarations as defs and `new T(...)` as a
    // call to `T` (`@ctor_type`, normalized to its simple name), so a
    // handler that instantiates a service class reaches it. Method
    // references (`Foo::bar`) and signature-qualified qnodes are NOT
    // ported: the latter would change the qnode shape every consumer of
    // the graph (S3 taint BFS, S4 slicing, S5 backfill) matches on.
    LangQuery {
        lang_id: "java",
        defs: "(class_declaration name: (identifier) @name) @def\n\
               (method_declaration name: (identifier) @name) @def\n\
               (constructor_declaration name: (identifier) @name) @def",
        calls: "(method_invocation name: (identifier) @callee)\n\
               (object_creation_expression type: (type_identifier) @ctor_type)\n\
               (object_creation_expression type: (scoped_type_identifier) @ctor_type)\n\
               (object_creation_expression type: (generic_type (type_identifier) @ctor_type))",
    },
    // tree-sitter-kotlin-ng's grammar (the actively-maintained
    // tree-sitter-grammars/tree-sitter-kotlin successor this port pins —
    // see its Cargo.toml comment) differs from the older fwcd grammar
    // Python's tree-sitter-language-pack wraps: function/parameter names
    // are plain `identifier` nodes (not `simple_identifier`), and a
    // qualified call's `navigation_expression` has two unnamed-field
    // `identifier` children (receiver, then member) with no
    // `navigation_suffix` wrapper at all — confirmed via a live parse-tree
    // probe (`(navigation_expression (identifier) (identifier))`, no
    // field names). The query below is written against that real shape,
    // not transliterated from Python's.
    LangQuery {
        lang_id: "kotlin",
        defs: "(function_declaration name: (identifier) @name) @def",
        calls: "(call_expression [\
              (identifier) @callee \
              (navigation_expression (identifier) (identifier) @callee)\
            ])",
    },
    LangQuery {
        lang_id: "javascript",
        defs: JS_FAMILY_DEFS,
        calls: JS_FAMILY_CALLS,
    },
    LangQuery {
        lang_id: "typescript",
        defs: JS_FAMILY_DEFS,
        calls: JS_FAMILY_CALLS,
    },
    LangQuery {
        lang_id: "tsx",
        defs: JS_FAMILY_DEFS,
        calls: JS_FAMILY_CALLS,
    },
    LangQuery {
        lang_id: "go",
        defs: "(function_declaration name: (identifier) @name) @def\n\
               (method_declaration name: (field_identifier) @name) @def",
        calls: "(call_expression function: [\
              (identifier) @callee \
              (selector_expression field: (field_identifier) @callee)\
            ])",
    },
    LangQuery {
        lang_id: "c",
        defs: "(function_definition declarator: \
              (function_declarator declarator: (identifier) @name)) @def",
        calls: "(call_expression function: (identifier) @callee)",
    },
    LangQuery {
        lang_id: "cpp",
        defs: "(function_definition declarator: \
              (function_declarator declarator: [\
                (identifier) @name \
                (qualified_identifier name: (identifier) @name) \
                (field_identifier) @name])) @def",
        calls: "(call_expression function: [\
              (identifier) @callee \
              (field_expression field: (field_identifier) @callee) \
              (qualified_identifier name: (identifier) @callee)\
            ])",
    },
    // Same upstream v1.3 additions as Java: type declarations as defs and
    // `new T(...)` as a call to `T`. The LINQ pseudo-calls upstream also
    // synthesizes (`From`/`Where`/`Select` edges) are not ported: they only
    // resolve when the repository itself defines a method of that name.
    LangQuery {
        lang_id: "csharp",
        defs: "(class_declaration name: (identifier) @name) @def\n\
               (struct_declaration name: (identifier) @name) @def\n\
               (interface_declaration name: (identifier) @name) @def\n\
               (method_declaration name: (identifier) @name) @def\n\
               (constructor_declaration name: (identifier) @name) @def\n\
               (local_function_statement name: (identifier) @name) @def",
        calls: "(invocation_expression function: [\
              (identifier) @callee \
              (member_access_expression name: (identifier) @callee)\
            ])\n\
            (object_creation_expression type: (identifier) @ctor_type)\n\
            (object_creation_expression type: (qualified_name) @ctor_type)\n\
            (object_creation_expression type: (generic_name (identifier) @ctor_type))",
    },
    LangQuery {
        lang_id: "ruby",
        defs: "(method name: (identifier) @name) @def\n\
               (singleton_method name: (identifier) @name) @def",
        calls: "(call method: (identifier) @callee)",
    },
    LangQuery {
        lang_id: "php",
        defs: "(function_definition name: (name) @name) @def\n\
               (method_declaration name: (name) @name) @def",
        calls: "(function_call_expression function: (name) @callee)\n\
               (member_call_expression name: (name) @callee)\n\
               (scoped_call_expression name: (name) @callee)",
    },
    LangQuery {
        lang_id: "rust",
        defs: "(function_item name: (identifier) @name) @def",
        calls: "(call_expression function: [\
              (identifier) @callee \
              (field_expression field: (field_identifier) @callee) \
              (scoped_identifier name: (identifier) @callee)\
            ])",
    },
    LangQuery {
        lang_id: "swift",
        defs: "(function_declaration name: (simple_identifier) @name) @def",
        calls: "(call_expression [\
              (simple_identifier) @callee \
              (navigation_expression suffix: \
                (navigation_suffix suffix: (simple_identifier) @callee))\
            ])",
    },
    LangQuery {
        lang_id: "scala",
        defs: "(function_definition name: (identifier) @name) @def",
        calls: "(call_expression function: [\
              (identifier) @callee \
              (field_expression field: (identifier) @callee)\
            ])",
    },
];

pub(crate) fn language_for(lang_id: &str) -> Option<Language> {
    Some(match lang_id {
        "python" => tree_sitter_python::LANGUAGE.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        "kotlin" => tree_sitter_kotlin_ng::LANGUAGE.into(),
        "javascript" => tree_sitter_javascript::LANGUAGE.into(),
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "c" => tree_sitter_c::LANGUAGE.into(),
        "cpp" => tree_sitter_cpp::LANGUAGE.into(),
        "csharp" => tree_sitter_c_sharp::LANGUAGE.into(),
        "ruby" => tree_sitter_ruby::LANGUAGE.into(),
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        "swift" => tree_sitter_swift::LANGUAGE.into(),
        "scala" => tree_sitter_scala::LANGUAGE.into(),
        _ => return None,
    })
}

/// `EXT_TO_LANG` groups C and C++ under `"c-cpp"` for family-level
/// behavior, and labels `.tsx` as plain `"typescript"`. The query table
/// is keyed by concrete grammars (`c`/`cpp`, `typescript`/`tsx`), so
/// resolve by file suffix before lookup.
///
/// TSX needs its own grammar and not merely its own key: tree-sitter
/// ships `LANGUAGE_TSX` separately because the TypeScript grammar reads
/// `<div>` as a type assertion and errors on JSX, and error recovery then
/// drops the subtrees holding a component's handlers and calls. The
/// language *label* is untouched by this — it is what language reporting,
/// lens selection and hint lookup key on — only the parser changes.
pub(crate) fn normalize_lang_for_queries(rel: &str, lang: &str) -> String {
    if lang != "c-cpp" && lang != "typescript" {
        return lang.to_string();
    }
    let suf = Path::new(rel)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    let concrete = match lang {
        "typescript" if suf == ".tsx" => "tsx",
        "typescript" => "typescript",
        _ if matches!(suf.as_str(), ".cc" | ".cpp" | ".cxx" | ".hpp") => "cpp",
        _ => "c",
    };
    concrete.to_string()
}

struct Bundle {
    language: Language,
    defs: Query,
    calls: Query,
}

/// One compiled `(parser, defs_query, calls_query)` per grammar, built
/// once per [`build`] call and reused across every file of that language —
/// the Rust equivalent of Python's process-global `_cache` dict, just
/// scoped to a single call instead of the whole process (this backend is
/// invoked once per S1 run, so there is nothing to amortize across calls).
fn compile_all() -> HashMap<&'static str, Option<Bundle>> {
    let mut out = HashMap::new();
    for lq in QUERIES {
        let bundle = language_for(lq.lang_id).and_then(|language| {
            match (
                Query::new(&language, lq.defs),
                Query::new(&language, lq.calls),
            ) {
                (Ok(defs), Ok(calls)) => Some(Bundle {
                    language,
                    defs,
                    calls,
                }),
                (Err(e), _) | (_, Err(e)) => {
                    tracing::warn!(
                        "[s1] tree-sitter: disabling {:?} (query compile failed: {e}); \
                         regex fallback for those files",
                        lq.lang_id
                    );
                    None
                }
            }
        });
        out.insert(lq.lang_id, bundle);
    }
    out
}

/// `(name, start_line, end_line, byte_range)` — `byte_range` is `None` for
/// regex-derived defs (no end-of-function span available), which
/// [`enclosing`] then never selects as a caller.
struct DefEntry {
    name: String,
    start_line: usize,
    end_line: usize,
    byte_range: Option<(usize, usize)>,
}

/// `(callee name, byte offset of the call)`.
type CallEntry = (String, usize);

fn parse_file(
    text: &str,
    lang: &str,
    bundles: &HashMap<&'static str, Option<Bundle>>,
) -> (Vec<DefEntry>, Vec<CallEntry>) {
    let Some(Some(bundle)) = bundles.get(lang) else {
        let lines: Vec<&str> = text.lines().collect();
        let defs = scan_defs(&lines)
            .into_iter()
            .map(|(ln, name)| DefEntry {
                name,
                start_line: ln,
                end_line: ln,
                byte_range: None,
            })
            .collect();
        let calls = CALL_TOKEN_RX
            .captures_iter(text)
            .filter_map(|c| {
                let m = c.get(1)?;
                Some((m.as_str().to_string(), m.start()))
            })
            .collect();
        return (defs, calls);
    };

    let mut parser = Parser::new();
    parser
        .set_language(&bundle.language)
        .expect("compiled Query already proved this Language loads");
    let Some(tree) = parser.parse(text, None) else {
        return (Vec::new(), Vec::new());
    };
    let root = tree.root_node();

    let mut defs = Vec::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&bundle.defs, root, text.as_bytes());
    while let Some(m) = matches.next() {
        let mut name_node: Option<Node> = None;
        let mut def_node: Option<Node> = None;
        for cap in m.captures {
            match bundle.defs.capture_names()[cap.index as usize] {
                "name" => name_node = Some(cap.node),
                "def" => def_node = Some(cap.node),
                _ => {}
            }
        }
        let (Some(nn), Some(dn)) = (name_node, def_node) else {
            continue;
        };
        let name = &text[nn.byte_range()];
        if name.is_empty() || NOT_A_DEF.contains(name) {
            continue;
        }
        defs.push(DefEntry {
            name: name.to_string(),
            start_line: dn.start_position().row + 1,
            end_line: dn.end_position().row + 1,
            byte_range: Some((dn.start_byte(), dn.end_byte())),
        });
    }

    let mut calls = Vec::new();
    let mut cursor2 = QueryCursor::new();
    let mut caps = cursor2.captures(&bundle.calls, root, text.as_bytes());
    while let Some((m, idx)) = caps.next() {
        let cap = m.captures[*idx];
        let raw = &text[cap.node.byte_range()];
        match bundle.calls.capture_names()[cap.index as usize] {
            "callee" if !raw.is_empty() && !NOT_A_DEF.contains(raw) && raw.len() >= 2 => {
                calls.push((raw.to_string(), cap.node.start_byte()));
            }
            "ctor_type" => {
                let name = normalize_type(raw);
                if !name.is_empty() {
                    calls.push((name, cap.node.start_byte()));
                }
            }
            _ => {}
        }
    }
    (defs, calls)
}

/// A type reference reduced to its simple name: generic arguments and
/// array brackets removed, then the last `.`-separated segment and the
/// last whitespace-separated token (`java.util.List<String>` -> `List`,
/// `Outer.Inner` -> `Inner`). Ported from upstream v1.3 `_normalize_type`.
fn normalize_type(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut depth = 0usize;
    for ch in raw.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    let out = out.replace("[]", "");
    out.trim()
        .rsplit('.')
        .next()
        .and_then(|seg| seg.split_whitespace().last())
        .unwrap_or_default()
        .to_string()
}

/// Merge a same-name def's span into the span already recorded for it in
/// one file. Adjacent overloads (gap of at most 50 lines) union, as before;
/// a far-apart one no longer engulfs all the unrelated code between the
/// two, and instead replaces the recorded span only when its own body is
/// larger. Ported from upstream v1.3 `ts_graph.build`.
fn merge_overload_span(prev: (usize, usize), next: (usize, usize)) -> (usize, usize) {
    let (ps, pe) = prev;
    let (ns, ne) = next;
    let gap = if ns > pe {
        ns - pe
    } else {
        ps.saturating_sub(ne)
    };
    if gap <= OVERLOAD_MERGE_GAP {
        (ps.min(ns), pe.max(ne))
    } else if ne - ns > pe - ps {
        next
    } else {
        prev
    }
}

/// Largest line gap across which two same-name defs in one file are still
/// treated as one slice.
const OVERLOAD_MERGE_GAP: usize = 50;

/// Innermost def containing `byte_off` (`defs_sorted` ordered by span
/// width ascending, narrowest first).
fn enclosing(defs_sorted: &[DefEntry], byte_off: usize) -> Option<&str> {
    defs_sorted.iter().find_map(|d| {
        let (sb, eb) = d.byte_range?;
        (sb <= byte_off && byte_off < eb).then_some(d.name.as_str())
    })
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TsGraphResult {
    /// Qualified caller -> qualified callees, sorted.
    pub call_graph: BTreeMap<String, Vec<String>>,
    /// Bare function name -> sorted `"file:line"` def-sites (every
    /// scanned def, not just ones on a retained edge — S4's specialist
    /// chunks may focus functions off the call-graph edge frontier).
    pub call_graph_files: BTreeMap<String, Vec<String>>,
    /// Qualified name -> `[start_line, end_line]`, union-spanned across
    /// ADJACENT same-name defs in one file (e.g. Java/C# overloads) so
    /// downstream slicing doesn't lose one overload's body; see
    /// `merge_overload_span` for far-apart ones.
    pub def_spans: BTreeMap<String, (usize, usize)>,
}

/// Builds a call graph over `files` via tree-sitter, keeping `prior_edges`
/// (a previously-seeded graph, e.g. from S0 or a resumed agent run) only
/// where BOTH qnode endpoints still resolve to a real def in their
/// original file — this avoids name-only re-grafting after code
/// movement/renames on `--resume`, matching Python's own re-graft pass.
/// Pass an empty `prior_edges` when there is nothing to preserve.
pub fn build(
    files: &[String],
    repo_root: &Path,
    max_targets: usize,
    prior_edges: &BTreeMap<String, Vec<String>>,
) -> TsGraphResult {
    let bundles = compile_all();

    let mut fn_locs: HashMap<String, HashSet<String>> = HashMap::new();
    let mut def_files: HashMap<String, HashSet<String>> = HashMap::new();
    let mut def_spans: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut parsed: Vec<(String, Vec<DefEntry>, Vec<CallEntry>)> = Vec::new();

    for rel in files {
        let ext = Path::new(rel)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()));
        let Some(lang) = ext.as_deref().and_then(ext_to_lang) else {
            continue;
        };
        let lang = normalize_lang_for_queries(rel, lang);
        let Ok(text) = std::fs::read_to_string(repo_root.join(rel)) else {
            continue;
        };
        let (defs, calls) = parse_file(&text, &lang, &bundles);
        for d in &defs {
            fn_locs
                .entry(d.name.clone())
                .or_default()
                .insert(format!("{rel}:{}", d.start_line));
            def_files
                .entry(d.name.clone())
                .or_default()
                .insert(rel.clone());
            let qn = q_join(rel, &d.name);
            let span = (d.start_line, d.end_line);
            def_spans
                .entry(qn)
                .and_modify(|prev| *prev = merge_overload_span(*prev, span))
                .or_insert(span);
        }
        let mut defs_sorted = defs;
        defs_sorted.sort_by_key(|d| d.byte_range.map(|(s, e)| e - s).unwrap_or(usize::MAX));
        parsed.push((rel.clone(), defs_sorted, calls));
    }

    let mut cg: BTreeMap<String, BTreeMap<String, ()>> = BTreeMap::new();
    for (rel, defs_sorted, calls) in &parsed {
        for (callee, off) in calls {
            if !def_files.contains_key(callee) {
                continue;
            }
            let caller = enclosing(defs_sorted, *off).unwrap_or(MODULE_SCOPE);
            if caller == callee {
                continue;
            }
            let qcaller = q_join(rel, caller);
            for tf in resolve_callee_files(callee, rel, &def_files, max_targets) {
                let qcallee = q_join(&tf, callee);
                cg.entry(qcaller.clone()).or_default().insert(qcallee, ());
            }
        }
    }

    for (k, vs) in prior_edges {
        let (kf, kn) = q_split(k);
        if kf.is_empty() || !def_files.get(&kn).is_some_and(|fs| fs.contains(&kf)) {
            continue;
        }
        for v in vs {
            let (vf, vn) = q_split(v);
            if vf.is_empty() || !def_files.get(&vn).is_some_and(|fs| fs.contains(&vf)) {
                continue;
            }
            let qcaller = q_join(&kf, &kn);
            let qcallee = q_join(&vf, &vn);
            cg.entry(qcaller).or_default().insert(qcallee, ());
        }
    }

    let call_graph: BTreeMap<String, Vec<String>> = cg
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| (k, v.into_keys().collect()))
        .collect();
    let call_graph_files: BTreeMap<String, Vec<String>> = fn_locs
        .into_iter()
        .map(|(k, v)| {
            let mut v: Vec<String> = v.into_iter().collect();
            v.sort();
            (k, v)
        })
        .collect();

    TsGraphResult {
        call_graph,
        call_graph_files,
        def_spans,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    // Each source defines `callee` then a `caller` that calls it once —
    // exercises real end-to-end extension dispatch + parse + query-match
    // + same-file edge resolution for every one of the 14 wired
    // languages, against the exact grammar versions this workspace pins.
    #[rstest]
    #[case(
        "caller.py",
        "def callee():\n    pass\n\n\ndef caller():\n    callee()\n",
        "callee",
        "caller"
    )]
    #[case(
        "Caller.java",
        "class C {\n    void callee() {}\n    void caller() { callee(); }\n}\n",
        "callee",
        "caller"
    )]
    #[case(
        "caller.kt",
        "fun callee() {}\nfun caller() {\n    callee()\n}\n",
        "callee",
        "caller"
    )]
    #[case(
        "caller.js",
        "function callee() {}\nfunction caller() { callee(); }\n",
        "callee",
        "caller"
    )]
    #[case(
        "caller.ts",
        "function callee(): void {}\nfunction caller(): void { callee(); }\n",
        "callee",
        "caller"
    )]
    #[case(
        "caller.go",
        "package main\nfunc callee() {}\nfunc caller() {\n callee()\n}\n",
        "callee",
        "caller"
    )]
    #[case(
        "caller.c",
        "void callee() {}\nvoid caller() {\n callee();\n}\n",
        "callee",
        "caller"
    )]
    #[case(
        "caller.cpp",
        "void callee() {}\nvoid caller() {\n callee();\n}\n",
        "callee",
        "caller"
    )]
    #[case(
        "Caller.cs",
        "class C { void Callee() {} void Caller() { Callee(); } }",
        "Callee",
        "Caller"
    )]
    #[case(
        "caller.rb",
        "def callee\nend\n\ndef caller\n  callee()\nend\n",
        "callee",
        "caller"
    )]
    #[case(
        "caller.php",
        "<?php\nfunction callee() {}\nfunction caller() {\n  callee();\n}\n",
        "callee",
        "caller"
    )]
    #[case(
        "caller.rs",
        "fn callee() {}\nfn caller() {\n callee();\n}\n",
        "callee",
        "caller"
    )]
    #[case(
        "caller.swift",
        "func callee() {}\nfunc caller() {\n  callee()\n}\n",
        "callee",
        "caller"
    )]
    #[case(
        "caller.scala",
        "def callee() = {}\ndef caller() = {\n  callee()\n}\n",
        "callee",
        "caller"
    )]
    fn build_extracts_a_same_file_edge_for_every_wired_language(
        #[case] rel: &str,
        #[case] src: &str,
        #[case] callee: &str,
        #[case] caller: &str,
    ) {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), rel, src);
        let files = vec![rel.to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        let qcaller = q_join(rel, caller);
        let qcallee = q_join(rel, callee);
        assert!(
            result
                .call_graph
                .get(&qcaller)
                .is_some_and(|v| v.contains(&qcallee)),
            "expected {qcaller} -> {qcallee} in {:?}",
            result.call_graph
        );
        assert!(result.call_graph_files.contains_key(callee));
        assert!(result.call_graph_files.contains_key(caller));
        assert!(result.def_spans.contains_key(&qcallee));
        assert!(result.def_spans.contains_key(&qcaller));
    }

    #[test]
    fn build_a_def_named_a_not_a_def_token_is_not_recorded() {
        // `print` is a real, valid Python 3 function name (a builtin, not
        // a reserved keyword) — `def print(): ...` parses to a genuine
        // `function_definition` whose captured `@name` text is "print",
        // exercising the `NOT_A_DEF` filter on a query-derived name for a
        // realistic, not merely hand-contrived, case.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def print():\n    pass\n");
        let files = vec!["a.py".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        assert!(!result.call_graph_files.contains_key("print"));
        assert!(!result.def_spans.contains_key(&q_join("a.py", "print")));
    }

    #[test]
    fn build_ignores_a_file_with_no_recognized_extension() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "notes.zzqx", "whatever, doesn't matter");
        let files = vec!["notes.zzqx".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        assert!(result.call_graph.is_empty());
        assert!(result.call_graph_files.is_empty());
        assert!(result.def_spans.is_empty());
    }

    #[test]
    fn build_skips_a_file_missing_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let files = vec!["missing.py".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        assert!(result.def_spans.is_empty());
    }

    #[test]
    fn build_falls_back_to_regex_for_a_language_with_no_query_entry() {
        // "vbnet" has no `QUERIES` entry at all — every `.vb` file must
        // go through `scan_defs`/`CALL_TOKEN_RX` instead of a tree-sitter
        // query, exactly like Python's own level-2 graceful degrade.
        // `sub name(` (lowercase — `scan_defs`'s pattern is
        // case-sensitive) is one of `scan_defs`'s recognized patterns.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "caller.vb",
            "sub callee()\nend sub\n\nsub caller()\n    callee()\nend sub\n",
        );
        let files = vec!["caller.vb".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        // Regex-derived defs have no byte range, so `enclosing()` can
        // never attribute a call to one — the call is attributed to
        // `MODULE_SCOPE` instead, exactly matching Python's own
        // documented "no end-of-function span" limitation for the
        // regex-fallback path.
        let qmodule = q_join("caller.vb", MODULE_SCOPE);
        let qcallee = q_join("caller.vb", "callee");
        assert!(result
            .call_graph
            .get(&qmodule)
            .is_some_and(|v| v.contains(&qcallee)));
        let span = result.def_spans[&qcallee];
        assert_eq!(span.0, span.1);
    }

    #[test]
    fn normalize_lang_for_queries_splits_c_and_cpp_by_extension() {
        assert_eq!(normalize_lang_for_queries("a.c", "c-cpp"), "c");
        assert_eq!(normalize_lang_for_queries("a.h", "c-cpp"), "c");
        assert_eq!(normalize_lang_for_queries("a.cc", "c-cpp"), "cpp");
        assert_eq!(normalize_lang_for_queries("a.cpp", "c-cpp"), "cpp");
        assert_eq!(normalize_lang_for_queries("a.cxx", "c-cpp"), "cpp");
        assert_eq!(normalize_lang_for_queries("a.hpp", "c-cpp"), "cpp");
        assert_eq!(normalize_lang_for_queries("a.py", "python"), "python");
    }

    #[test]
    fn normalize_lang_for_queries_routes_tsx_to_its_own_grammar() {
        assert_eq!(normalize_lang_for_queries("a.tsx", "typescript"), "tsx");
        assert_eq!(normalize_lang_for_queries("A.TSX", "typescript"), "tsx");
        assert_eq!(
            normalize_lang_for_queries("a.ts", "typescript"),
            "typescript"
        );
        assert_eq!(
            normalize_lang_for_queries("a.mts", "typescript"),
            "typescript"
        );
        // The label owns dispatch: a `.tsx` suffix under another label
        // is left alone.
        assert_eq!(
            normalize_lang_for_queries("a.tsx", "javascript"),
            "javascript"
        );
    }

    #[test]
    fn build_dispatches_c_and_cpp_files_to_their_own_grammar() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a.c",
            "void callee() {}\nvoid caller() {\n callee();\n}\n",
        );
        write(
            dir.path(),
            "b.cpp",
            "void callee() {}\nvoid caller() {\n  callee();\n}\n",
        );
        let files = vec!["a.c".to_string(), "b.cpp".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        assert!(result
            .call_graph
            .get(&q_join("a.c", "caller"))
            .is_some_and(|v| v.contains(&q_join("a.c", "callee"))));
        assert!(result
            .call_graph
            .get(&q_join("b.cpp", "caller"))
            .is_some_and(|v| v.contains(&q_join("b.cpp", "callee"))));
    }

    #[test]
    fn build_discovers_a_handler_declared_inside_a_tsx_component() {
        // With the TypeScript grammar, `<div className="x">` is a type
        // assertion followed by garbage; error recovery drops the subtree
        // holding `onSubmit`, so the def and its edge both vanish.
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "Form.tsx",
            "function callee(): void {}\n\
             export const Form = () => {\n\
               const banner = <div className=\"x\">hi</div>;\n\
               const onSubmit = (e: Event) => { callee(); };\n\
               return <form onSubmit={onSubmit}>{banner}</form>;\n\
             };\n",
        );
        let files = vec!["Form.tsx".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        assert!(
            result.call_graph_files.contains_key("onSubmit"),
            "{:?}",
            result.call_graph_files
        );
        assert!(
            result
                .call_graph
                .get(&q_join("Form.tsx", "onSubmit"))
                .is_some_and(|v| v.contains(&q_join("Form.tsx", "callee"))),
            "{:?}",
            result.call_graph
        );
    }

    #[test]
    fn build_resolves_a_call_to_the_innermost_enclosing_def_not_the_outer_one() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a.py",
            "def callee():\n    pass\n\n\ndef outer():\n    def inner():\n        callee()\n    inner()\n",
        );
        let files = vec!["a.py".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        assert!(result
            .call_graph
            .get(&q_join("a.py", "inner"))
            .is_some_and(|v| v.contains(&q_join("a.py", "callee"))));
        assert!(!result
            .call_graph
            .get(&q_join("a.py", "outer"))
            .is_some_and(|v| v.contains(&q_join("a.py", "callee"))));
    }

    #[test]
    fn build_drops_a_self_recursive_call_as_a_self_loop() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def fact(n):\n    return fact(n - 1)\n");
        let files = vec!["a.py".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        assert!(!result.call_graph.contains_key(&q_join("a.py", "fact")));
    }

    #[test]
    fn build_drops_a_call_with_no_known_def_site_anywhere_scanned() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def caller():\n    unknown_helper()\n");
        let files = vec!["a.py".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        assert!(result.call_graph.is_empty());
        assert!(result.call_graph_files.contains_key("caller"));
    }

    #[test]
    fn build_call_graph_files_includes_defs_with_no_incoming_or_outgoing_edges() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "a.py", "def lonely():\n    pass\n");
        let files = vec!["a.py".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        assert!(result.call_graph.is_empty());
        assert_eq!(
            result.call_graph_files["lonely"],
            vec!["a.py:1".to_string()]
        );
    }

    #[test]
    fn build_def_spans_union_across_overloaded_defs_in_one_file() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "C.java",
            "class C {\n    void m() {\n        int x = 1;\n    }\n    void m(int a) {\n        int y = 2;\n        int z = 3;\n    }\n}\n",
        );
        let files = vec!["C.java".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        let span = result.def_spans[&q_join("C.java", "m")];
        // First overload: lines 2-4; second: lines 5-8. Union: 2-8.
        assert_eq!(span, (2, 8));
    }

    #[test]
    fn far_apart_overloads_do_not_engulf_the_code_between_them() {
        // Adjacent: union, either order.
        assert_eq!(merge_overload_span((2, 4), (5, 8)), (2, 8));
        assert_eq!(merge_overload_span((5, 8), (2, 4)), (2, 8));
        // Overlapping (a class and its constructor): union.
        assert_eq!(merge_overload_span((1, 100), (10, 20)), (1, 100));
        // Far apart: keep the larger body alone.
        assert_eq!(merge_overload_span((2, 4), (200, 260)), (200, 260));
        assert_eq!(merge_overload_span((200, 260), (2, 4)), (200, 260));
        assert_eq!(merge_overload_span((2, 40), (300, 301)), (2, 40));
    }

    #[test]
    fn normalize_type_reduces_a_type_reference_to_its_simple_name() {
        assert_eq!(normalize_type("Foo"), "Foo");
        assert_eq!(normalize_type("com.acme.Foo"), "Foo");
        assert_eq!(normalize_type("List<Map<String, Foo>>"), "List");
        assert_eq!(normalize_type("Foo[]"), "Foo");
        assert_eq!(normalize_type("  "), "");
        assert_eq!(normalize_type("<T>"), "");
    }

    #[test]
    fn a_java_constructor_call_reaches_the_class_it_instantiates() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "Svc.java",
            "class Svc {\n    Svc() {}\n    void run() {}\n}\n",
        );
        write(
            dir.path(),
            "Api.java",
            "class Api {\n    void handle() {\n        Svc a = new Svc();\n        \
             java.util.List<Svc> b = new java.util.ArrayList<Svc>();\n        \
             Box<Svc> c = new Box<Svc>();\n    }\n}\nclass Box<T> {}\n",
        );
        let files = vec!["Api.java".to_string(), "Svc.java".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        let edges = &result.call_graph[&q_join("Api.java", "handle")];
        assert!(edges.contains(&q_join("Svc.java", "Svc")), "{edges:?}");
        assert!(edges.contains(&q_join("Api.java", "Box")), "{edges:?}");
        // The class def spans its whole body; the ctor inside it is merged.
        assert_eq!(result.def_spans[&q_join("Svc.java", "Svc")], (1, 4));
    }

    #[test]
    fn a_one_letter_callee_is_ignored_like_upstream() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "A.java",
            "class A {\n    void f() {}\n    void g() {\n        f();\n    }\n}\n",
        );
        let files = vec!["A.java".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        assert!(!result.call_graph.contains_key(&q_join("A.java", "g")));
    }

    #[test]
    fn a_csharp_object_creation_reaches_the_type_it_instantiates() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "Svc.cs",
            "class Svc { public void Run() {} }\nstruct Point {}\ninterface IRepo {}\n",
        );
        write(
            dir.path(),
            "Api.cs",
            "class Api {\n  void Handle() {\n    var a = new Svc();\n    \
             var b = new Acme.Point();\n    var c = new Wrap<Svc>();\n  }\n}\n\
             class Wrap<T> {}\n",
        );
        let files = vec!["Api.cs".to_string(), "Svc.cs".to_string()];
        let result = build(&files, dir.path(), 3, &BTreeMap::new());
        let edges = &result.call_graph[&q_join("Api.cs", "Handle")];
        assert!(edges.contains(&q_join("Svc.cs", "Svc")), "{edges:?}");
        assert!(edges.contains(&q_join("Svc.cs", "Point")), "{edges:?}");
        assert!(edges.contains(&q_join("Api.cs", "Wrap")), "{edges:?}");
        assert!(result.call_graph_files.contains_key("IRepo"));
    }

    #[test]
    fn build_regrafts_a_prior_edge_when_both_endpoints_still_resolve() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a.py",
            "def callee():\n    pass\ndef caller():\n    pass\n",
        );
        let files = vec!["a.py".to_string()];
        let mut prior = BTreeMap::new();
        prior.insert(q_join("a.py", "caller"), vec![q_join("a.py", "callee")]);
        let result = build(&files, dir.path(), 3, &prior);
        assert!(result
            .call_graph
            .get(&q_join("a.py", "caller"))
            .is_some_and(|v| v.contains(&q_join("a.py", "callee"))));
    }

    #[rstest]
    #[case(q_join("moved.py", "caller"), q_join("a.py", "callee"))]
    #[case(q_join("a.py", "caller"), q_join("moved.py", "callee"))]
    fn build_drops_a_prior_edge_when_an_endpoint_no_longer_resolves(
        #[case] key: String,
        #[case] value: String,
    ) {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "a.py",
            "def callee():\n    pass\ndef caller():\n    pass\n",
        );
        let files = vec!["a.py".to_string()];
        let mut prior = BTreeMap::new();
        prior.insert(key, vec![value]);
        let result = build(&files, dir.path(), 3, &prior);
        assert!(result.call_graph.is_empty());
    }

    #[test]
    fn language_for_unknown_lang_id_is_none() {
        assert!(language_for("cobol").is_none());
    }

    #[test]
    fn enclosing_none_when_byte_offset_is_outside_every_def() {
        let defs = vec![DefEntry {
            name: "f".to_string(),
            start_line: 1,
            end_line: 2,
            byte_range: Some((10, 20)),
        }];
        assert_eq!(enclosing(&defs, 5), None);
    }

    #[test]
    fn enclosing_skips_regex_derived_defs_with_no_byte_range() {
        let defs = vec![DefEntry {
            name: "f".to_string(),
            start_line: 1,
            end_line: 1,
            byte_range: None,
        }];
        assert_eq!(enclosing(&defs, 0), None);
    }
}
