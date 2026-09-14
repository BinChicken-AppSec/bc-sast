// Portions of this file are transcribed from vvaharness, Visa's agentic
// SAST harness: Copyright 2026 Visa, Inc., licensed under the Apache
// License, Version 2.0. Reimplemented in Rust and modified; see the module
// documentation below, and NOTICE for the full attribution.
//! Field and container propagation facts. Ported from `_scan.py`'s
//! `_py_extract_field_facts` (L2323-2456), `_java_extract_field_facts`
//! (L2459-2615) and `_cs_extract_field_facts` (L2618-2769), dispatched
//! through `_FIELD_FACT_EXTRACTORS` (L2772-2779) — which has exactly
//! three keys, so JavaScript/TypeScript/Go files carry no field or
//! container facts here either.
//!
//! These feed `_graph.py`'s `_apply_field_writes`/`_apply_field_reads`/
//! `_apply_container_writes` (L543-637), which is the only thing that
//! reads them.

use std::sync::LazyLock;

use regex::Regex;
use tree_sitter::Node;

use crate::scan::{
    collect_fn_ranges, cs_argument_value, cs_leftmost_identifier, java_leftmost_identifier, kids,
    named_kids, py_text, scope_for, ContainerWriteFact, FieldReadFact, FieldWriteFact,
};

/// Java `setFoo`/`getFoo` bean conventions, ported from the original's
/// `re.match(r"^set[A-Z]", method)` / `r"^get[A-Z]"` tests.
static SETTER_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^set[A-Z]").unwrap());
static GETTER_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^get[A-Z]").unwrap());

/// `setFoo` -> `foo` (the original's `method[3].lower() + method[4:]`).
fn bean_field_name(method: &str) -> String {
    let rest = &method[3..];
    let mut chars = rest.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

type FieldFacts = (
    Vec<FieldWriteFact>,
    Vec<FieldReadFact>,
    Vec<ContainerWriteFact>,
);

/// Per-language dispatch, mirroring `_scan.py::_FIELD_FACT_EXTRACTORS`.
pub(crate) fn extract_field_facts(language: &str, src: &[u8], root: Node) -> FieldFacts {
    let mut st = FactState::default();
    match language {
        "python" => {
            collect_fn_ranges(root, src, &["function_definition"], &mut st.ranges);
            py_visit(root, src, &mut st);
        }
        "java" => {
            collect_fn_ranges(
                root,
                src,
                &["method_declaration", "constructor_declaration"],
                &mut st.ranges,
            );
            java_visit(root, src, &mut st);
        }
        "csharp" => {
            collect_fn_ranges(
                root,
                src,
                &[
                    "method_declaration",
                    "constructor_declaration",
                    "local_function_statement",
                ],
                &mut st.ranges,
            );
            cs_visit(root, src, &mut st);
        }
        _ => {}
    }
    (st.field_writes, st.field_reads, st.container_writes)
}

/// The three output lists plus the function ranges [`scope_for`] needs,
/// bundled so each `visit` takes one `&mut` instead of four.
#[derive(Default)]
struct FactState {
    ranges: Vec<(usize, usize, String)>,
    field_writes: Vec<FieldWriteFact>,
    field_reads: Vec<FieldReadFact>,
    container_writes: Vec<ContainerWriteFact>,
}

/// `Some(text)` when `node` is an `identifier`, else `None` — the
/// original's repeated `_text(n) if n is not None and n.type ==
/// "identifier" else None`.
fn identifier_text(node: Option<Node>, src: &[u8]) -> Option<String> {
    node.filter(|n| n.kind() == "identifier")
        .map(|n| py_text(n, src))
}

/// First `identifier` among a call's named arguments, unwrapping C#'s
/// `argument` node when present.
fn first_identifier_arg(args: Option<Node>, src: &[u8], unwrap_argument: bool) -> Option<String> {
    let args = args?;
    for a in named_kids(args) {
        if a.kind() == "identifier" {
            return Some(py_text(a, src));
        }
        if unwrap_argument && a.kind() == "argument" {
            return identifier_text(cs_argument_value(a), src);
        }
        // Python and Java both stop at the first argument regardless of
        // its kind (`break` after the first iteration), so a non-symbol
        // first argument yields no element symbol.
        if !unwrap_argument {
            return None;
        }
    }
    None
}

// ── Python ───────────────────────────────────────────────────────────────

fn py_visit(node: Node, src: &[u8], st: &mut FactState) {
    match node.kind() {
        "assignment" | "augmented_assignment" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            let line = node.start_position().row + 1;
            let scope = scope_for(node.start_byte(), &st.ranges);

            // `self.x = val` / `self.x += val`.
            if let Some(left) = left.filter(|l| l.kind() == "attribute") {
                let recv = left
                    .child_by_field_name("object")
                    .map(|n| py_text(n, src))
                    .unwrap_or_default();
                let fname = left
                    .child_by_field_name("attribute")
                    .map(|n| py_text(n, src))
                    .unwrap_or_default();
                if !recv.is_empty() && !fname.is_empty() {
                    st.field_writes.push(FieldWriteFact {
                        function_qnode: scope.clone(),
                        line,
                        receiver: recv,
                        field: fname,
                        src_symbol: identifier_text(right, src),
                    });
                }
            // `d[k] = x` — only a plain `=`, matching the original's
            // `elif` chain (an augmented subscript assign is not a
            // container write there).
            } else if node.kind() == "assignment" {
                if let Some(left) = left.filter(|l| l.kind() == "subscript") {
                    if let Some(container) = identifier_text(left.child_by_field_name("value"), src)
                    {
                        st.container_writes.push(ContainerWriteFact {
                            function_qnode: scope.clone(),
                            line,
                            container_symbol: container,
                            element_symbol: identifier_text(right, src),
                        });
                    }
                }
            }

            // `x = self.y` — a plain `=` only, again matching the
            // original (the field-read block sits inside its
            // `if t == "assignment"` arm).
            if node.kind() == "assignment" {
                if let Some(right) = right.filter(|r| r.kind() == "attribute") {
                    let recv = right
                        .child_by_field_name("object")
                        .map(|n| py_text(n, src))
                        .unwrap_or_default();
                    let fname = right
                        .child_by_field_name("attribute")
                        .map(|n| py_text(n, src))
                        .unwrap_or_default();
                    if !recv.is_empty() && !fname.is_empty() {
                        st.field_reads.push(FieldReadFact {
                            function_qnode: scope,
                            line,
                            receiver: recv,
                            field: fname,
                            dst_symbol: identifier_text(left, src),
                        });
                    }
                }
            }
        }
        "call" => {
            // `container.append(x)` / `container.add(x)`.
            if let Some(fn_node) = node.child_by_field_name("function") {
                if fn_node.kind() == "attribute" {
                    let method = fn_node
                        .child_by_field_name("attribute")
                        .map(|n| py_text(n, src))
                        .unwrap_or_default();
                    let obj_node = fn_node.child_by_field_name("object");
                    if matches!(method.as_str(), "append" | "add") {
                        if let Some(obj) = obj_node.filter(|o| o.kind() == "identifier") {
                            st.container_writes.push(ContainerWriteFact {
                                function_qnode: scope_for(node.start_byte(), &st.ranges),
                                line: node.start_position().row + 1,
                                container_symbol: py_text(obj, src),
                                element_symbol: first_identifier_arg(
                                    node.child_by_field_name("arguments"),
                                    src,
                                    false,
                                ),
                            });
                        }
                    }
                }
            }
        }
        _ => {}
    }
    for c in kids(node) {
        py_visit(c, src, st);
    }
}

// ── Java ─────────────────────────────────────────────────────────────────

/// LHS identifier when `node` is the RHS of an assignment or the
/// initialiser of a declarator. Ported from
/// `_java_extract_field_facts::_assign_target_of`.
fn java_assign_target_of(node: Node, src: &[u8]) -> Option<String> {
    let parent = node.parent()?;
    if parent.kind() == "assignment_expression" {
        let left = parent.child_by_field_name("left");
        let right = parent.child_by_field_name("right");
        if right == Some(node) {
            return identifier_text(left, src);
        }
    }
    if parent.kind() == "variable_declarator" {
        let val = parent.child_by_field_name("value");
        let name = parent.child_by_field_name("name");
        if val == Some(node) {
            return identifier_text(name, src);
        }
    }
    None
}

fn java_visit(node: Node, src: &[u8], st: &mut FactState) {
    match node.kind() {
        "assignment_expression" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            let line = node.start_position().row + 1;
            let scope = scope_for(node.start_byte(), &st.ranges);

            if let Some(left) = left.filter(|l| l.kind() == "field_access") {
                let (recv, fname) = java_field_access_parts(left, src);
                if !recv.is_empty() && !fname.is_empty() {
                    st.field_writes.push(FieldWriteFact {
                        function_qnode: scope.clone(),
                        line,
                        receiver: recv,
                        field: fname,
                        src_symbol: identifier_text(right, src),
                    });
                }
            }
            if let Some(right) = right.filter(|r| r.kind() == "field_access") {
                let (recv, fname) = java_field_access_parts(right, src);
                if !recv.is_empty() && !fname.is_empty() {
                    st.field_reads.push(FieldReadFact {
                        function_qnode: scope,
                        line,
                        receiver: recv,
                        field: fname,
                        dst_symbol: identifier_text(left, src),
                    });
                }
            }
        }
        "local_variable_declaration" => {
            // `Type x = obj.field;`
            let scope = scope_for(node.start_byte(), &st.ranges);
            let line = node.start_position().row + 1;
            for c in kids(node) {
                if c.kind() != "variable_declarator" {
                    continue;
                }
                let name_n = c.child_by_field_name("name");
                let val_n = c.child_by_field_name("value");
                if let (Some(name_n), Some(val_n)) =
                    (name_n, val_n.filter(|v| v.kind() == "field_access"))
                {
                    let (recv, fname) = java_field_access_parts(val_n, src);
                    if !recv.is_empty() && !fname.is_empty() {
                        st.field_reads.push(FieldReadFact {
                            function_qnode: scope.clone(),
                            line,
                            receiver: recv,
                            field: fname,
                            dst_symbol: Some(py_text(name_n, src)),
                        });
                    }
                }
            }
        }
        // Every arm below needs a receiver: the original guards each of
        // its three cases with `obj_n is not None`, so a receiverless
        // call contributes nothing.
        "method_invocation" if node.child_by_field_name("object").is_some() => {
            let method = node
                .child_by_field_name("name")
                .map(|n| py_text(n, src))
                .unwrap_or_default();
            let obj_n = node
                .child_by_field_name("object")
                .expect("guarded by the match arm");
            let line = node.start_position().row + 1;
            let scope = scope_for(node.start_byte(), &st.ranges);
            let recv = java_leftmost_identifier(obj_n, src);
            let args_n = node.child_by_field_name("arguments");
            if matches!(method.as_str(), "add" | "put") {
                if !recv.is_empty() {
                    st.container_writes.push(ContainerWriteFact {
                        function_qnode: scope,
                        line,
                        container_symbol: recv,
                        element_symbol: java_first_identifier_arg(args_n, src),
                    });
                }
            } else if SETTER_RX.is_match(&method) {
                let fname = bean_field_name(&method);
                if !recv.is_empty() && !fname.is_empty() {
                    st.field_writes.push(FieldWriteFact {
                        function_qnode: scope,
                        line,
                        receiver: recv,
                        field: fname,
                        src_symbol: java_first_identifier_arg(args_n, src),
                    });
                }
            } else if GETTER_RX.is_match(&method) {
                let fname = bean_field_name(&method);
                let zero_args = match args_n {
                    None => true,
                    Some(a) => named_kids(a).next().is_none(),
                };
                if !recv.is_empty() && !fname.is_empty() && zero_args {
                    st.field_reads.push(FieldReadFact {
                        function_qnode: scope,
                        line,
                        receiver: recv,
                        field: fname,
                        dst_symbol: java_assign_target_of(node, src),
                    });
                }
            }
        }
        _ => {}
    }
    for c in kids(node) {
        java_visit(c, src, st);
    }
}

fn java_field_access_parts(node: Node, src: &[u8]) -> (String, String) {
    let recv = node
        .child_by_field_name("object")
        .map(|n| py_text(n, src))
        .unwrap_or_default();
    let fname = node
        .child_by_field_name("field")
        .map(|n| py_text(n, src))
        .unwrap_or_default();
    (recv, fname)
}

/// First `identifier` among the arguments, skipping non-identifiers —
/// Java's own loop `break`s only once it finds one.
fn java_first_identifier_arg(args: Option<Node>, src: &[u8]) -> Option<String> {
    let args = args?;
    named_kids(args)
        .find(|a| a.kind() == "identifier")
        .map(|a| py_text(a, src))
}

// ── C# ───────────────────────────────────────────────────────────────────

/// `(receiver, field_name)` from a `member_access_expression`. Ported
/// from `_cs_extract_field_facts::_mae_parts`.
fn cs_mae_parts(node: Node, src: &[u8]) -> (String, String) {
    let recv = node
        .child_by_field_name("expression")
        .map(|n| cs_leftmost_identifier(n, src))
        .unwrap_or_default();
    let fname = node
        .child_by_field_name("name")
        .map(|n| py_text(n, src))
        .unwrap_or_default();
    (recv, fname)
}

fn cs_visit(node: Node, src: &[u8], st: &mut FactState) {
    match node.kind() {
        "assignment_expression" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            let line = node.start_position().row + 1;
            let scope = scope_for(node.start_byte(), &st.ranges);

            if let Some(left) = left.filter(|l| l.kind() == "member_access_expression") {
                let (recv, fname) = cs_mae_parts(left, src);
                if !recv.is_empty() && !fname.is_empty() {
                    st.field_writes.push(FieldWriteFact {
                        function_qnode: scope.clone(),
                        line,
                        receiver: recv,
                        field: fname,
                        src_symbol: identifier_text(right, src),
                    });
                }
            } else if let Some(left) = left.filter(|l| l.kind() == "element_access_expression") {
                if let Some(container) =
                    identifier_text(left.child_by_field_name("expression"), src)
                {
                    st.container_writes.push(ContainerWriteFact {
                        function_qnode: scope.clone(),
                        line,
                        container_symbol: container,
                        element_symbol: identifier_text(right, src),
                    });
                }
            }
            if let Some(right) = right.filter(|r| r.kind() == "member_access_expression") {
                let (recv, fname) = cs_mae_parts(right, src);
                if !recv.is_empty() && !fname.is_empty() {
                    st.field_reads.push(FieldReadFact {
                        function_qnode: scope,
                        line,
                        receiver: recv,
                        field: fname,
                        dst_symbol: identifier_text(left, src),
                    });
                }
            }
        }
        "variable_declarator" => {
            // `Type x = obj.Field;` — the initialiser may sit inside an
            // `equals_value_clause`.
            let name_n = node.child_by_field_name("name");
            let val_n = named_kids(node).find(|c| Some(*c) != name_n).and_then(|c| {
                if c.kind() == "equals_value_clause" {
                    named_kids(c).next()
                } else {
                    Some(c)
                }
            });
            if let (Some(name_n), Some(val_n)) = (
                name_n,
                val_n.filter(|v| v.kind() == "member_access_expression"),
            ) {
                let (recv, fname) = cs_mae_parts(val_n, src);
                if !recv.is_empty() && !fname.is_empty() {
                    st.field_reads.push(FieldReadFact {
                        function_qnode: scope_for(node.start_byte(), &st.ranges),
                        line: node.start_position().row + 1,
                        receiver: recv,
                        field: fname,
                        dst_symbol: identifier_text(Some(name_n), src),
                    });
                }
            }
        }
        "invocation_expression" => {
            if let Some(fn_n) = node
                .child_by_field_name("function")
                .filter(|f| f.kind() == "member_access_expression")
            {
                let method = fn_n
                    .child_by_field_name("name")
                    .map(|n| py_text(n, src))
                    .unwrap_or_default();
                if method == "Add" {
                    let container = fn_n
                        .child_by_field_name("expression")
                        .map(|e| cs_leftmost_identifier(e, src))
                        .unwrap_or_default();
                    if !container.is_empty() {
                        st.container_writes.push(ContainerWriteFact {
                            function_qnode: scope_for(node.start_byte(), &st.ranges),
                            line: node.start_position().row + 1,
                            container_symbol: container,
                            element_symbol: first_identifier_arg(
                                node.child_by_field_name("arguments"),
                                src,
                                true,
                            ),
                        });
                    }
                }
            }
        }
        _ => {}
    }
    for c in kids(node) {
        cs_visit(c, src, st);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Parser, Tree};

    fn parse(language: &str, src: &str) -> Tree {
        let lang: tree_sitter::Language = match language {
            "java" => tree_sitter_java::LANGUAGE.into(),
            "csharp" => tree_sitter_c_sharp::LANGUAGE.into(),
            _ => tree_sitter_python::LANGUAGE.into(),
        };
        let mut p = Parser::new();
        p.set_language(&lang).unwrap();
        p.parse(src, None).unwrap()
    }

    fn extract(language: &str, src: &str) -> FieldFacts {
        let tree = parse(language, src);
        extract_field_facts(language, src.as_bytes(), tree.root_node())
    }

    #[test]
    fn bean_field_name_lowercases_the_first_character_after_the_prefix() {
        assert_eq!(bean_field_name("setName"), "name");
        assert_eq!(bean_field_name("getURL"), "uRL");
        assert_eq!(bean_field_name("set"), "");
    }

    // ── Python ──────────────────────────────────────────────────────

    #[test]
    fn python_attribute_assignment_is_a_field_write() {
        let (fw, fr, cw) = extract("python", "def f(v):\n    self.name = v\n");
        assert!(fr.is_empty() && cw.is_empty());
        assert_eq!(fw.len(), 1);
        assert_eq!(fw[0].receiver, "self");
        assert_eq!(fw[0].field, "name");
        assert_eq!(fw[0].src_symbol, Some("v".to_string()));
        assert_eq!(fw[0].function_qnode, "f");
        assert_eq!(fw[0].line, 2);
    }

    #[test]
    fn python_augmented_attribute_assignment_is_a_field_write_too() {
        let (fw, _, _) = extract("python", "def f(v):\n    self.buf += v\n");
        assert_eq!(fw.len(), 1);
        assert_eq!(fw[0].field, "buf");
    }

    #[test]
    fn python_non_identifier_right_hand_side_leaves_no_source_symbol() {
        let (fw, _, _) = extract("python", "def f():\n    self.name = compute()\n");
        assert_eq!(fw[0].src_symbol, None);
    }

    #[test]
    fn python_subscript_assignment_is_a_container_write() {
        let (_, _, cw) = extract("python", "def f(v):\n    bag[k] = v\n");
        assert_eq!(cw.len(), 1);
        assert_eq!(cw[0].container_symbol, "bag");
        assert_eq!(cw[0].element_symbol, Some("v".to_string()));
    }

    #[test]
    fn python_subscript_assignment_on_a_non_identifier_container_is_skipped() {
        let (_, _, cw) = extract("python", "def f(v):\n    a.b[k] = v\n");
        assert!(cw.is_empty());
    }

    #[test]
    fn python_attribute_read_is_a_field_read() {
        let (_, fr, _) = extract("python", "def f():\n    x = self.name\n");
        assert_eq!(fr.len(), 1);
        assert_eq!(fr[0].receiver, "self");
        assert_eq!(fr[0].field, "name");
        assert_eq!(fr[0].dst_symbol, Some("x".to_string()));
    }

    #[test]
    fn python_append_and_add_are_container_writes() {
        let (_, _, cw) = extract(
            "python",
            "def f(v):\n    items.append(v)\n    seen.add(v)\n",
        );
        assert_eq!(cw.len(), 2);
        assert_eq!(cw[0].container_symbol, "items");
        assert_eq!(cw[1].container_symbol, "seen");
    }

    #[test]
    fn python_append_with_a_non_identifier_argument_carries_no_element() {
        let (_, _, cw) = extract("python", "def f():\n    items.append(1)\n");
        assert_eq!(cw.len(), 1);
        assert_eq!(cw[0].element_symbol, None);
    }

    #[test]
    fn python_append_with_no_arguments_carries_no_element() {
        let (_, _, cw) = extract("python", "def f():\n    items.append()\n");
        assert_eq!(cw[0].element_symbol, None);
    }

    #[test]
    fn python_calls_that_are_not_container_writes_are_ignored() {
        let (_, _, cw) = extract("python", "def f(v):\n    other(v)\n    a.b.append(v)\n");
        assert!(cw.is_empty());
    }

    // ── Java ────────────────────────────────────────────────────────

    #[test]
    fn java_field_access_assignment_is_a_field_write_and_read() {
        let src = "class C {\n  void m(String v) {\n    o.name = v;\n    x = o.other;\n  }\n}\n";
        let (fw, fr, _) = extract("java", src);
        assert_eq!(fw.len(), 1);
        assert_eq!(fw[0].receiver, "o");
        assert_eq!(fw[0].field, "name");
        assert_eq!(fw[0].src_symbol, Some("v".to_string()));
        assert_eq!(fr.len(), 1);
        assert_eq!(fr[0].field, "other");
        assert_eq!(fr[0].dst_symbol, Some("x".to_string()));
        assert_eq!(fr[0].function_qnode, "m");
    }

    #[test]
    fn java_local_variable_initialised_from_a_field_is_a_field_read() {
        let src =
            "class C {\n  void m() {\n    String s = o.name;\n    String t = compute();\n  }\n}\n";
        let (_, fr, _) = extract("java", src);
        assert_eq!(fr.len(), 1);
        assert_eq!(fr[0].dst_symbol, Some("s".to_string()));
    }

    #[test]
    fn java_add_and_put_are_container_writes() {
        let src =
            "class C {\n  void m(String v) {\n    list.add(v);\n    map.put(\"k\", v);\n  }\n}\n";
        let (_, _, cw) = extract("java", src);
        assert_eq!(cw.len(), 2);
        assert_eq!(cw[0].container_symbol, "list");
        assert_eq!(cw[1].container_symbol, "map");
        assert_eq!(cw[1].element_symbol, Some("v".to_string()));
    }

    #[test]
    fn java_setter_and_getter_conventions_become_field_facts() {
        let src = "class C {\n  void m(String v) {\n    o.setName(v);\n    String s = o.getName();\n    o.getThing(arg);\n  }\n}\n";
        let (fw, fr, _) = extract("java", src);
        assert_eq!(fw.len(), 1);
        assert_eq!(fw[0].field, "name");
        assert_eq!(fw[0].src_symbol, Some("v".to_string()));
        // The one-argument `getThing(arg)` is not a getter.
        assert_eq!(fr.len(), 1);
        assert_eq!(fr[0].field, "name");
        assert_eq!(fr[0].dst_symbol, Some("s".to_string()));
    }

    #[test]
    fn java_getter_assigned_by_an_expression_assignment_records_its_target() {
        let src = "class C {\n  void m() {\n    s = o.getName();\n    o.getName();\n  }\n}\n";
        let (_, fr, _) = extract("java", src);
        assert_eq!(fr.len(), 2);
        assert_eq!(fr[0].dst_symbol, Some("s".to_string()));
        assert_eq!(fr[1].dst_symbol, None);
    }

    #[test]
    fn java_receiverless_calls_produce_no_facts() {
        let (fw, fr, cw) = extract("java", "class C {\n  void m() {\n    setName(v);\n  }\n}\n");
        assert!(fw.is_empty() && fr.is_empty() && cw.is_empty());
    }

    // ── C# ──────────────────────────────────────────────────────────

    #[test]
    fn csharp_member_access_assignment_is_a_field_write_and_read() {
        let src = "class C {\n  void M(string v) {\n    o.Name = v;\n    x = o.Other;\n  }\n}\n";
        let (fw, fr, _) = extract("csharp", src);
        assert_eq!(fw.len(), 1);
        assert_eq!(fw[0].receiver, "o");
        assert_eq!(fw[0].field, "Name");
        assert_eq!(fr.len(), 1);
        assert_eq!(fr[0].field, "Other");
        assert_eq!(fr[0].dst_symbol, Some("x".to_string()));
    }

    #[test]
    fn csharp_element_access_assignment_is_a_container_write() {
        let src = "class C {\n  void M(string v) {\n    bag[k] = v;\n    o.bag[k] = v;\n  }\n}\n";
        let (_, _, cw) = extract("csharp", src);
        assert_eq!(cw.len(), 1);
        assert_eq!(cw[0].container_symbol, "bag");
        assert_eq!(cw[0].element_symbol, Some("v".to_string()));
    }

    #[test]
    fn csharp_declarator_initialised_from_a_property_is_a_field_read() {
        let src = "class C {\n  void M() {\n    var s = o.Name;\n    var t = Compute();\n  }\n}\n";
        let (_, fr, _) = extract("csharp", src);
        assert_eq!(fr.len(), 1);
        assert_eq!(fr[0].dst_symbol, Some("s".to_string()));
        assert_eq!(fr[0].function_qnode, "M");
    }

    #[test]
    fn csharp_add_is_a_container_write_unwrapping_the_argument_node() {
        let src =
            "class C {\n  void M(string v) {\n    list.Add(v);\n    other.Remove(v);\n  }\n}\n";
        let (_, _, cw) = extract("csharp", src);
        assert_eq!(cw.len(), 1);
        assert_eq!(cw[0].container_symbol, "list");
        assert_eq!(cw[0].element_symbol, Some("v".to_string()));
    }

    #[test]
    fn csharp_add_with_a_literal_argument_carries_no_element() {
        let (_, _, cw) = extract("csharp", "class C { void M() { list.Add(1); } }\n");
        assert_eq!(cw.len(), 1);
        assert_eq!(cw[0].element_symbol, None);
    }

    #[test]
    fn csharp_bare_invocation_is_not_a_container_write() {
        let (_, _, cw) = extract("csharp", "class C { void M() { Add(x); } }\n");
        assert!(cw.is_empty());
    }

    #[test]
    fn a_language_with_no_field_fact_extractor_yields_nothing() {
        let tree = parse("python", "x = 1\n");
        let (fw, fr, cw) = extract_field_facts("go", b"", tree.root_node());
        assert!(fw.is_empty() && fr.is_empty() && cw.is_empty());
    }
}
