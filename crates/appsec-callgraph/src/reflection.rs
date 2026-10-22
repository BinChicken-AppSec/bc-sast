//! Reflective / dynamic-dispatch call-site extraction. Ported from
//! `_scan.py`'s `_py_extract_reflection_facts` (L284-388),
//! `_java_extract_reflection_facts` (L391-500) and
//! `_cs_extract_reflection_facts` (L503-659), dispatched through
//! `_REFLECTION_FACT_EXTRACTORS` — Python, Java and C# only.
//!
//! Consumed by `_graph.py`'s `_apply_reflection_to_taint` (L1373-1424),
//! which turns a fact whose target symbol is already tainted into
//! speculative `reflect` edges on the evidence path.

use tree_sitter::Node;

use crate::scan::{
    collect_fn_ranges, cs_argument_value, cs_leftmost_identifier, java_leftmost_identifier, kids,
    named_kids, py_leftmost_identifier, py_text, scope_for, ReflectionFact,
};

/// Per-language dispatch, mirroring `_scan.py::_REFLECTION_FACT_EXTRACTORS`.
pub(crate) fn extract_reflection_facts(
    language: &str,
    src: &[u8],
    root: Node,
) -> Vec<ReflectionFact> {
    let mut ranges = Vec::new();
    let mut out = Vec::new();
    match language {
        "python" => {
            collect_fn_ranges(root, src, &["function_definition"], &mut ranges);
            py_visit(root, src, &ranges, &mut out);
        }
        "java" => {
            collect_fn_ranges(
                root,
                src,
                &["method_declaration", "constructor_declaration"],
                &mut ranges,
            );
            java_visit(root, src, &ranges, &mut out);
        }
        "csharp" => {
            collect_fn_ranges(
                root,
                src,
                &["method_declaration", "constructor_declaration"],
                &mut ranges,
            );
            cs_visit(root, src, &ranges, &mut out);
        }
        _ => {}
    }
    out
}

/// A string literal's contents or an identifier's name — the shape every
/// extractor's `target_symbols` entries take.
fn literal_or_identifier(node: Node, src: &[u8], string_kinds: &[&str]) -> Option<String> {
    if string_kinds.contains(&node.kind()) {
        return Some(py_text(node, src).trim_matches(['"', '\'']).to_string());
    }
    if node.kind() == "identifier" {
        return Some(py_text(node, src));
    }
    None
}

// ── Python ───────────────────────────────────────────────────────────────

/// `getattr`/`setattr` read their *second* argument as the member name;
/// everything else reads its first. Ported from the index tests inside
/// `_py_extract_reflection_facts`.
fn py_target_arg_index(fname: &str) -> usize {
    match fname {
        "getattr" | "setattr" => 1,
        _ => 0,
    }
}

fn py_call_type(fname: &str) -> &'static str {
    match fname {
        "getattr" | "vars" => "getattr",
        "eval" | "exec" => "invoke",
        _ => "construct",
    }
}

fn py_visit(
    node: Node,
    src: &[u8],
    ranges: &[(usize, usize, String)],
    out: &mut Vec<ReflectionFact>,
) {
    if node.kind() == "call" {
        if let Some(fn_node) = node.child_by_field_name("function") {
            match fn_node.kind() {
                "identifier" => {
                    let fname = py_text(fn_node, src);
                    if matches!(
                        fname.as_str(),
                        "getattr"
                            | "setattr"
                            | "__import__"
                            | "vars"
                            | "type"
                            | "eval"
                            | "exec"
                            | "compile"
                    ) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let want = py_target_arg_index(&fname);
                            let target = named_kids(args)
                                .nth(want)
                                .and_then(|a| literal_or_identifier(a, src, &["string"]));
                            if let Some(target) = target {
                                out.push(ReflectionFact {
                                    function_qnode: scope_for(node.start_byte(), ranges),
                                    line: node.start_position().row + 1,
                                    call_type: py_call_type(&fname).to_string(),
                                    target_symbols: vec![target],
                                    receiver: String::new(),
                                    language: "python".to_string(),
                                });
                            }
                        }
                    }
                }
                "attribute" => {
                    let method = fn_node
                        .child_by_field_name("attribute")
                        .map(|n| py_text(n, src))
                        .unwrap_or_default();
                    if method == "import_module"
                        && py_leftmost_identifier(fn_node, src) == "importlib"
                    {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            if let Some(target) = named_kids(args)
                                .find(|a| a.kind() == "string")
                                .map(|a| py_text(a, src).trim_matches(['"', '\'']).to_string())
                            {
                                out.push(ReflectionFact {
                                    function_qnode: scope_for(node.start_byte(), ranges),
                                    line: node.start_position().row + 1,
                                    call_type: "construct".to_string(),
                                    target_symbols: vec![target],
                                    receiver: "importlib".to_string(),
                                    language: "python".to_string(),
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    for c in kids(node) {
        py_visit(c, src, ranges, out);
    }
}

// ── Java ─────────────────────────────────────────────────────────────────

fn java_visit(
    node: Node,
    src: &[u8],
    ranges: &[(usize, usize, String)],
    out: &mut Vec<ReflectionFact>,
) {
    if node.kind() == "method_invocation" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let method = py_text(name_node, src);
            let receiver = node
                .child_by_field_name("object")
                .map(|o| java_leftmost_identifier(o, src))
                .unwrap_or_default();
            let mut push = |call_type: &str, target_symbols: Vec<String>| {
                out.push(ReflectionFact {
                    function_qnode: scope_for(node.start_byte(), ranges),
                    line: node.start_position().row + 1,
                    call_type: call_type.to_string(),
                    target_symbols,
                    receiver: receiver.clone(),
                    language: "java".to_string(),
                });
            };
            match method.as_str() {
                "getMethod" | "forName" | "getDeclaredMethod" | "getDeclaredField" | "getField" => {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let targets: Vec<String> = named_kids(args)
                            .filter_map(|a| literal_or_identifier(a, src, &["string_literal"]))
                            .collect();
                        if !targets.is_empty() {
                            push("getmethod", targets);
                        }
                    }
                }
                "invoke" => push("invoke", Vec::new()),
                "newInstance" | "getDeclaredConstructor" | "getConstructor" => {
                    push("construct", Vec::new())
                }
                "lookup" if receiver.contains("MethodHandles") => push("getmethod", Vec::new()),
                _ if receiver == "Activator" => push("construct", Vec::new()),
                _ => {}
            }
        }
    }
    for c in kids(node) {
        java_visit(c, src, ranges, out);
    }
}

// ── C# ───────────────────────────────────────────────────────────────────

/// C# arguments arrive wrapped in an `argument` node; the original
/// checks the bare literal/identifier form first and then unwraps.
fn cs_arg_symbol(arg: Node, src: &[u8]) -> Option<String> {
    if let Some(s) = literal_or_identifier(arg, src, &["string", "string_literal"]) {
        return Some(s);
    }
    if arg.kind() == "argument" {
        let e = cs_argument_value(arg)?;
        return literal_or_identifier(e, src, &["string", "string_literal"]);
    }
    None
}

fn cs_visit(
    node: Node,
    src: &[u8],
    ranges: &[(usize, usize, String)],
    out: &mut Vec<ReflectionFact>,
) {
    if node.kind() == "invocation_expression" {
        if let Some(fn_node) = node
            .child_by_field_name("function")
            .filter(|f| f.kind() == "member_access_expression")
        {
            if let Some(name_node) = fn_node.child_by_field_name("name") {
                let method = py_text(name_node, src);
                let receiver = fn_node
                    .child_by_field_name("expression")
                    .map(|e| cs_leftmost_identifier(e, src))
                    .unwrap_or_default();
                let mut push = |call_type: &str, target_symbols: Vec<String>| {
                    out.push(ReflectionFact {
                        function_qnode: scope_for(node.start_byte(), ranges),
                        line: node.start_position().row + 1,
                        call_type: call_type.to_string(),
                        target_symbols,
                        receiver: receiver.clone(),
                        language: "csharp".to_string(),
                    });
                };
                match method.as_str() {
                    "GetMethod" | "GetType" | "GetMethods" | "GetConstructor"
                    | "GetConstructors" => {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let targets: Vec<String> = named_kids(args)
                                .filter_map(|a| cs_arg_symbol(a, src))
                                .collect();
                            if !targets.is_empty() {
                                push("getmethod", targets);
                            } else if matches!(
                                method.as_str(),
                                "GetMethods" | "GetConstructor" | "GetConstructors"
                            ) {
                                // These need no string argument to be a
                                // reflective read.
                                push("getmethod", Vec::new());
                            }
                        }
                    }
                    "CreateDelegate" => push("delegate", Vec::new()),
                    "Invoke" => push("invoke", Vec::new()),
                    "LoadFrom" | "Load" | "LoadFile" | "CreateInstance" => {
                        push("construct", Vec::new())
                    }
                    "InvokeMember" => {
                        let targets = node
                            .child_by_field_name("arguments")
                            .and_then(|args| named_kids(args).next())
                            // Only the first argument (the member name),
                            // and only when it is a literal.
                            .and_then(|a| cs_member_name_literal(a, src))
                            .map(|s| vec![s])
                            .unwrap_or_default();
                        push("invoke", targets);
                    }
                    _ => {}
                }
            }
        }
    }
    for c in kids(node) {
        cs_visit(c, src, ranges, out);
    }
}

/// `InvokeMember`'s first argument, string literals only (the original
/// deliberately drops an identifier here, unlike `GetMethod`).
fn cs_member_name_literal(arg: Node, src: &[u8]) -> Option<String> {
    let lit = if arg.kind() == "argument" {
        cs_argument_value(arg)?
    } else {
        arg
    };
    if matches!(lit.kind(), "string" | "string_literal") {
        return Some(py_text(lit, src).trim_matches('"').to_string());
    }
    None
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

    fn facts(language: &str, src: &str) -> Vec<ReflectionFact> {
        let tree = parse(language, src);
        extract_reflection_facts(language, src.as_bytes(), tree.root_node())
    }

    // ── Python ──────────────────────────────────────────────────────

    #[test]
    fn python_getattr_reads_its_second_argument() {
        let out = facts(
            "python",
            "def f(obj, name):\n    return getattr(obj, name)\n",
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].call_type, "getattr");
        assert_eq!(out[0].target_symbols, vec!["name".to_string()]);
        assert_eq!(out[0].function_qnode, "f");
        assert_eq!(out[0].language, "python");
        assert_eq!(out[0].line, 2);
    }

    #[test]
    fn python_setattr_string_literal_target_is_unquoted() {
        let out = facts("python", "def f(o, v):\n    setattr(o, \"attr\", v)\n");
        assert_eq!(out[0].target_symbols, vec!["attr".to_string()]);
        assert_eq!(out[0].call_type, "construct");
    }

    #[test]
    fn python_first_argument_builtins_classify_by_name() {
        let out = facts(
            "python",
            "def f(x):\n    eval(x)\n    vars(x)\n    __import__(\"os\")\n    compile(x)\n",
        );
        let kinds: Vec<&str> = out.iter().map(|f| f.call_type.as_str()).collect();
        assert_eq!(kinds, vec!["invoke", "getattr", "construct", "construct"]);
    }

    #[test]
    fn python_reflective_call_with_a_non_symbol_target_is_skipped() {
        let out = facts("python", "def f(o):\n    getattr(o, 1)\n    getattr(o)\n");
        assert!(out.is_empty());
    }

    #[test]
    fn python_importlib_import_module_is_a_construct_fact() {
        let out = facts(
            "python",
            "def f():\n    importlib.import_module(\"os.path\")\n",
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].receiver, "importlib");
        assert_eq!(out[0].target_symbols, vec!["os.path".to_string()]);
    }

    #[test]
    fn python_import_module_on_another_receiver_is_ignored() {
        let out = facts(
            "python",
            "def f():\n    other.import_module(\"os\")\n    importlib.import_module(name)\n    o.m()\n",
        );
        assert!(out.is_empty());
    }

    // ── Java ────────────────────────────────────────────────────────

    #[test]
    fn java_get_method_family_collects_literal_and_identifier_targets() {
        let src = "class C {\n  void m(String n) {\n    c.getMethod(\"run\", n);\n  }\n}\n";
        let out = facts("java", src);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].call_type, "getmethod");
        assert_eq!(
            out[0].target_symbols,
            vec!["run".to_string(), "n".to_string()]
        );
        assert_eq!(out[0].receiver, "c");
        assert_eq!(out[0].language, "java");
    }

    #[test]
    fn java_get_method_without_symbol_arguments_emits_nothing() {
        let out = facts("java", "class C { void m() { c.getMethod(); } }\n");
        assert!(out.is_empty());
    }

    #[test]
    fn java_invoke_construct_and_handle_lookups_are_recorded() {
        let src = "class C {\n  void m() {\n    meth.invoke(o);\n    k.newInstance();\n    MethodHandles.lookup();\n    Activator.anything();\n    plain.other();\n  }\n}\n";
        let kinds: Vec<String> = facts("java", src)
            .into_iter()
            .map(|f| f.call_type)
            .collect();
        assert_eq!(
            kinds,
            vec!["invoke", "construct", "getmethod", "construct"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn java_lookup_on_a_non_handle_receiver_falls_through_to_the_activator_rule() {
        let out = facts("java", "class C { void m() { Activator.lookup(); } }\n");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].call_type, "construct");
    }

    // ── C# ──────────────────────────────────────────────────────────

    #[test]
    fn csharp_get_method_collects_its_wrapped_arguments() {
        let src = "class C {\n  void M(string n) {\n    t.GetMethod(\"Run\", n);\n  }\n}\n";
        let out = facts("csharp", src);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].call_type, "getmethod");
        assert_eq!(
            out[0].target_symbols,
            vec!["Run".to_string(), "n".to_string()]
        );
        assert_eq!(out[0].receiver, "t");
        assert_eq!(out[0].language, "csharp");
    }

    #[test]
    fn csharp_argument_free_reflection_reads_still_emit_a_fact() {
        let out = facts(
            "csharp",
            "class C { void M() { t.GetMethods(); t.GetType(); } }\n",
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].call_type, "getmethod");
        assert!(out[0].target_symbols.is_empty());
    }

    #[test]
    fn csharp_delegate_invoke_and_load_families_are_classified() {
        let src = "class C {\n  void M() {\n    d.CreateDelegate();\n    d.Invoke();\n    a.LoadFrom(p);\n    Activator.CreateInstance(t);\n    o.Other();\n  }\n}\n";
        let kinds: Vec<String> = facts("csharp", src)
            .into_iter()
            .map(|f| f.call_type)
            .collect();
        assert_eq!(
            kinds,
            vec!["delegate", "invoke", "construct", "construct"]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn csharp_invoke_member_keeps_only_a_literal_first_argument() {
        let literal = facts(
            "csharp",
            "class C { void M() { t.InvokeMember(\"Run\", x); } }\n",
        );
        assert_eq!(literal[0].call_type, "invoke");
        assert_eq!(literal[0].target_symbols, vec!["Run".to_string()]);
        let variable = facts("csharp", "class C { void M() { t.InvokeMember(name); } }\n");
        assert!(variable[0].target_symbols.is_empty());
        let empty = facts("csharp", "class C { void M() { t.InvokeMember(); } }\n");
        assert!(empty[0].target_symbols.is_empty());
    }

    #[test]
    fn csharp_bare_invocations_are_not_reflection() {
        assert!(facts("csharp", "class C { void M() { GetMethod(\"x\"); } }\n").is_empty());
    }

    #[test]
    fn a_language_with_no_reflection_extractor_yields_nothing() {
        let tree = parse("python", "x = 1\n");
        assert!(extract_reflection_facts("go", b"", tree.root_node()).is_empty());
    }
}
