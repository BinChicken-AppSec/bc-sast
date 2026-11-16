use std::collections::BTreeMap;

use tree_sitter::Node;

use super::{kids, named_kids, py_snippet, py_text, scope_for, ExtractResult, FuncDef, RawCall};

type ReadName = fn(Node, &[u8]) -> (String, String);

type ArgShapes = fn(Node, &[u8]) -> Vec<bool>;

pub(super) struct Shape {
    functions: &'static [&'static str],
    classes: &'static [&'static str],
    class_field: &'static str,
    calls: &'static [&'static str],
    call_parts: fn(Node, &[u8]) -> (String, String),
    params: fn(Node, &[u8]) -> Vec<String>,
    static_args: ArgShapes,
    arithmetic_args: Option<ArgShapes>,
    unit_args: Option<ArgShapes>,
    read_name: Option<ReadName>,
    arg_count: fn(Node) -> Option<usize>,
    fn_name: Option<fn(Node, &[u8]) -> String>,
}

pub(super) const PHP: Shape = Shape {
    functions: &["function_definition", "method_declaration"],
    classes: &[
        "class_declaration",
        "trait_declaration",
        "interface_declaration",
    ],
    class_field: "name",
    calls: &[
        "function_call_expression",
        "member_call_expression",
        "scoped_call_expression",
        "include_expression",
        "include_once_expression",
        "require_expression",
        "require_once_expression",
    ],
    call_parts: php_call_parts,
    params: php_params,
    static_args: php_static_args,
    arithmetic_args: None,
    unit_args: None,
    arg_count: field_arg_count,
    read_name: Some(php_read_name),
    fn_name: None,
};

pub(super) const RUBY: Shape = Shape {
    functions: &["method", "singleton_method"],
    classes: &["class", "module"],
    class_field: "name",
    calls: &["call"],
    call_parts: ruby_call_parts,
    params: ruby_params,
    static_args: ruby_static_args,
    arithmetic_args: None,
    unit_args: None,
    arg_count: field_arg_count,
    read_name: Some(ruby_read_name),
    fn_name: None,
};

pub(super) const KOTLIN: Shape = Shape {
    functions: &["function_declaration"],
    classes: &["class_declaration", "object_declaration"],
    class_field: "name",
    calls: &["call_expression"],
    call_parts: kotlin_call_parts,
    params: kotlin_params,
    static_args: kotlin_static_args,
    arithmetic_args: None,
    unit_args: None,
    arg_count: kotlin_arg_count,
    read_name: Some(kotlin_read_name),
    fn_name: None,
};

pub(super) const RUST: Shape = Shape {
    functions: &["function_item"],
    classes: &["impl_item"],
    class_field: "type",
    calls: &["call_expression"],
    call_parts: rust_call_parts,
    params: rust_params,
    static_args: rust_static_args,
    arithmetic_args: None,
    unit_args: None,
    arg_count: field_arg_count,
    read_name: None,
    fn_name: None,
};

pub(super) const C_CPP: Shape = Shape {
    functions: &["function_definition"],
    classes: &[
        "class_specifier",
        "struct_specifier",
        "namespace_definition",
    ],
    class_field: "name",
    calls: &["call_expression", "new_expression"],
    call_parts: c_call_parts,
    params: c_params,
    static_args: c_static_args,
    arithmetic_args: Some(c_arithmetic_args),
    unit_args: Some(c_unit_args),
    arg_count: c_arg_count,
    read_name: Some(c_read_name),
    fn_name: Some(c_fn_name),
};

pub(super) fn extract(shape: &Shape, src: &[u8], root: Node) -> ExtractResult {
    let mut classes = Vec::new();
    collect_ranges(root, src, shape.classes, shape.class_field, &mut classes);
    let mut fns = Vec::new();
    match shape.fn_name {
        Some(f) => collect_fn_ranges_by(root, src, shape.functions, f, &mut fns),
        None => collect_ranges(root, src, shape.functions, "name", &mut fns),
    }
    let mut state = State::default();
    visit(root, src, shape, &classes, &fns, &mut state);
    ExtractResult {
        imports: BTreeMap::new(),
        functions: state.functions,
        calls: state.calls,
        assigns: Vec::new(),
        returns: Vec::new(),
        call_args: Vec::new(),
    }
}

#[derive(Default)]
struct State {
    functions: Vec<FuncDef>,
    calls: Vec<RawCall>,
}

fn collect_fn_ranges_by(
    node: Node,
    src: &[u8],
    kinds: &[&str],
    name_of: fn(Node, &[u8]) -> String,
    out: &mut Vec<(usize, usize, String)>,
) {
    if kinds.contains(&node.kind()) {
        let name = name_of(node, src);
        if !name.is_empty() {
            out.push((node.start_byte(), node.end_byte(), name));
        }
    }
    for c in kids(node) {
        collect_fn_ranges_by(c, src, kinds, name_of, out);
    }
}

fn collect_ranges(
    node: Node,
    src: &[u8],
    kinds: &[&str],
    field: &str,
    out: &mut Vec<(usize, usize, String)>,
) {
    if kinds.contains(&node.kind()) {
        if let Some(n) = node.child_by_field_name(field) {
            out.push((node.start_byte(), node.end_byte(), py_text(n, src)));
        }
    }
    for c in kids(node) {
        collect_ranges(c, src, kinds, field, out);
    }
}

fn visit(
    node: Node,
    src: &[u8],
    shape: &Shape,
    classes: &[(usize, usize, String)],
    fns: &[(usize, usize, String)],
    state: &mut State,
) {
    if shape.functions.contains(&node.kind()) {
        let declared = match shape.fn_name {
            Some(f) => Some(f(node, src)).filter(|n| !n.is_empty()),
            None => node.child_by_field_name("name").map(|n| py_text(n, src)),
        };
        if let Some(name) = declared {
            state.functions.push(FuncDef {
                name,
                start_line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
                class_name: scope_for(node.start_byte(), classes),
                params: (shape.params)(node, src),
            });
        }
    } else if shape.calls.contains(&node.kind()) {
        let (receiver, method) = (shape.call_parts)(node, src);
        if !method.is_empty() {
            state.calls.push(RawCall {
                line: node.start_position().row + 1,
                receiver,
                method,
                containing_fn: scope_for(node.start_byte(), fns),
                snippet: py_snippet(src, node),
                static_args: (shape.static_args)(node, src),
                arithmetic_args: shape
                    .arithmetic_args
                    .map(|f| f(node, src))
                    .unwrap_or_default(),
                unit_args: shape.unit_args.map(|f| f(node, src)).unwrap_or_default(),
                arg_count: (shape.arg_count)(node),
                first_arg_symbol: None,
                property_read: false,
            });
        }
    } else if let Some((receiver, container)) = shape
        .read_name
        .map(|f| f(node, src))
        .filter(|(_, n)| !n.is_empty())
    {
        state.calls.push(RawCall {
            line: node.start_position().row + 1,
            receiver,
            method: container,
            containing_fn: scope_for(node.start_byte(), fns),
            snippet: py_snippet(src, node),
            static_args: Vec::new(),
            arithmetic_args: Vec::new(),
            unit_args: Vec::new(),
            arg_count: Some(0),
            first_arg_symbol: None,
            property_read: true,
        });
    }
    for c in kids(node) {
        visit(c, src, shape, classes, fns, state);
    }
}

fn leaf<'a>(text: &'a str, sep: &str) -> &'a str {
    text.rsplit(sep).next().unwrap_or(text)
}

fn leftmost(node: Node, src: &[u8], leaves: &[&str], fields: &[&str]) -> String {
    let mut cur = node;
    loop {
        if leaves.contains(&cur.kind()) {
            return py_text(cur, src);
        }
        let next = fields
            .iter()
            .find_map(|f| cur.child_by_field_name(f))
            .or_else(|| named_kids(cur).next());
        match next {
            Some(n) => cur = n,
            None => return String::new(),
        }
    }
}

fn field_text(node: Node, src: &[u8], field: &str) -> String {
    node.child_by_field_name(field)
        .map(|n| py_text(n, src))
        .unwrap_or_default()
}

fn php_call_parts(node: Node, src: &[u8]) -> (String, String) {
    match node.kind() {
        "include_expression"
        | "include_once_expression"
        | "require_expression"
        | "require_once_expression" => (String::new(), "include".to_string()),
        "function_call_expression" => {
            let text = field_text(node, src, "function");
            (String::new(), leaf(&text, "\\").to_string())
        }
        "scoped_call_expression" => {
            let scope = field_text(node, src, "scope");
            (
                leaf(&scope, "\\").to_string(),
                field_text(node, src, "name"),
            )
        }
        _ => {
            let receiver = node
                .child_by_field_name("object")
                .map(|o| {
                    leftmost(
                        o,
                        src,
                        &["variable_name", "name", "qualified_name"],
                        &["object", "scope"],
                    )
                })
                .unwrap_or_default();
            (receiver, field_text(node, src, "name"))
        }
    }
}

fn php_params(node: Node, src: &[u8]) -> Vec<String> {
    let Some(params) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_kids(params)
        .filter_map(|p| p.child_by_field_name("name"))
        .map(|n| py_text(n, src).trim_start_matches('$').to_string())
        .collect()
}

fn ruby_call_parts(node: Node, src: &[u8]) -> (String, String) {
    let receiver = node
        .child_by_field_name("receiver")
        .map(|r| leftmost(r, src, &["identifier", "constant", "self"], &["receiver"]))
        .unwrap_or_default();
    (receiver, field_text(node, src, "method"))
}

fn ruby_params(node: Node, src: &[u8]) -> Vec<String> {
    let Some(params) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_kids(params)
        .map(|p| {
            if p.kind() == "identifier" {
                py_text(p, src)
            } else {
                field_text(p, src, "name")
            }
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn kotlin_call_parts(node: Node, src: &[u8]) -> (String, String) {
    let Some(callee) = named_kids(node).next() else {
        return (String::new(), String::new());
    };
    match callee.kind() {
        "identifier" => (String::new(), py_text(callee, src)),
        "navigation_expression" => {
            let parts: Vec<Node> = named_kids(callee).collect();
            let method = parts.last().map(|n| py_text(*n, src)).unwrap_or_default();
            let receiver = parts
                .first()
                .map(|n| leftmost(*n, src, &["identifier"], &[]))
                .unwrap_or_default();
            if parts.len() < 2 {
                return (String::new(), String::new());
            }
            (receiver, method)
        }
        _ => (String::new(), String::new()),
    }
}

fn kotlin_params(node: Node, src: &[u8]) -> Vec<String> {
    let Some(params) = named_kids(node).find(|c| c.kind() == "function_value_parameters") else {
        return Vec::new();
    };
    named_kids(params)
        .filter(|p| p.kind() == "parameter")
        .filter_map(|p| named_kids(p).next())
        .filter(|n| n.kind() == "identifier")
        .map(|n| py_text(n, src))
        .collect()
}

fn rust_call_parts(node: Node, src: &[u8]) -> (String, String) {
    let Some(func) = node.child_by_field_name("function") else {
        return (String::new(), String::new());
    };
    match func.kind() {
        "identifier" => (String::new(), py_text(func, src)),
        "scoped_identifier" => {
            let path = field_text(func, src, "path");
            (leaf(&path, "::").to_string(), field_text(func, src, "name"))
        }
        "field_expression" => (
            leftmost(
                func,
                src,
                &["identifier", "self", "crate"],
                &["value", "function", "path"],
            ),
            field_text(func, src, "field"),
        ),
        _ => (String::new(), String::new()),
    }
}

fn rust_params(node: Node, src: &[u8]) -> Vec<String> {
    let Some(params) = node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_kids(params)
        .filter_map(|p| p.child_by_field_name("pattern"))
        .map(|n| py_text(n, src))
        .collect()
}

const PHP_SUPERGLOBALS: &[&str] = &["_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER", "_FILES"];

const RUBY_REQUEST_CONTAINERS: &[&str] = &["params", "cookies", "session"];

fn arguments_of<'a>(args: Option<Node<'a>>, wrapper: &str) -> Vec<Node<'a>> {
    let Some(args) = args else {
        return Vec::new();
    };
    named_kids(args)
        .map(|a| {
            if a.kind() == wrapper {
                named_kids(a).next().unwrap_or(a)
            } else {
                a
            }
        })
        .collect()
}

fn field_arguments<'a>(node: Node<'a>, wrapper: &str) -> Vec<Node<'a>> {
    arguments_of(node.child_by_field_name("arguments"), wrapper)
}

fn field_arg_count(node: Node) -> Option<usize> {
    node.child_by_field_name("arguments")
        .map(|a| named_kids(a).count())
}

fn kotlin_arg_count(node: Node) -> Option<usize> {
    kotlin_value_arguments(node).map(|a| named_kids(a).count())
}

fn php_static_args(node: Node, _src: &[u8]) -> Vec<bool> {
    if node.kind().ends_with("_expression") && !node.kind().ends_with("call_expression") {
        return named_kids(node)
            .next()
            .map(|v| vec![!has_variable(v)])
            .unwrap_or_default();
    }
    field_arguments(node, "argument")
        .into_iter()
        .map(|v| match v.kind() {
            "string" => true,
            "encapsed_string" => !kids(v).any(|c| c.kind() == "variable_name"),
            _ => false,
        })
        .collect()
}

fn has_variable(node: Node) -> bool {
    node.kind() == "variable_name" || kids(node).any(has_variable)
}

fn php_read_name(node: Node, src: &[u8]) -> (String, String) {
    if node.kind() != "subscript_expression" {
        return (String::new(), String::new());
    }
    let Some(obj) = named_kids(node)
        .next()
        .filter(|o| o.kind() == "variable_name")
    else {
        return (String::new(), String::new());
    };
    let bare = py_text(obj, src).trim_start_matches('$').to_string();
    if PHP_SUPERGLOBALS.contains(&bare.as_str()) {
        (String::new(), bare)
    } else {
        (String::new(), String::new())
    }
}

fn ruby_static_args(node: Node, _src: &[u8]) -> Vec<bool> {
    field_arguments(node, "\0")
        .into_iter()
        .map(|v| v.kind() == "string" && !named_kids(v).any(|c| c.kind() == "interpolation"))
        .collect()
}

fn ruby_read_name(node: Node, src: &[u8]) -> (String, String) {
    if node.kind() != "element_reference" {
        return (String::new(), String::new());
    }
    let Some(obj) = node
        .child_by_field_name("object")
        .filter(|o| o.kind() == "identifier")
    else {
        return (String::new(), String::new());
    };
    let name = py_text(obj, src);
    if RUBY_REQUEST_CONTAINERS.contains(&name.as_str()) {
        (String::new(), name)
    } else {
        (String::new(), String::new())
    }
}

fn rust_static_args(node: Node, _src: &[u8]) -> Vec<bool> {
    field_arguments(node, "\0")
        .into_iter()
        .map(|v| matches!(v.kind(), "string_literal" | "raw_string_literal"))
        .collect()
}

fn kotlin_value_arguments<'a>(node: Node<'a>) -> Option<Node<'a>> {
    named_kids(node).find(|c| c.kind() == "value_arguments")
}

fn kotlin_template_is_constant(literal: Node, src: &[u8]) -> bool {
    let is_const_name = |t: &str| {
        !t.is_empty()
            && t.chars()
                .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
    };
    let parts: Vec<Node> = named_kids(literal).collect();
    for (i, part) in parts.iter().enumerate() {
        match part.kind() {
            "interpolation" => {
                let inner: String = named_kids(*part).map(|n| py_text(n, src)).collect();
                if !is_const_name(&inner) {
                    return false;
                }
            }
            "string_content" if py_text(*part, src) == "$" => {
                let name = parts
                    .get(i + 1)
                    .map(|n| py_text(*n, src))
                    .unwrap_or_default();
                if !is_const_name(&name) {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

fn kotlin_static_args(node: Node, src: &[u8]) -> Vec<bool> {
    arguments_of(kotlin_value_arguments(node), "value_argument")
        .into_iter()
        .map(|v| v.kind() == "string_literal" && kotlin_template_is_constant(v, src))
        .collect()
}

fn kotlin_read_name(node: Node, src: &[u8]) -> (String, String) {
    if node.kind() != "index_expression" {
        return (String::new(), String::new());
    }
    let Some(target) = named_kids(node)
        .next()
        .filter(|t| t.kind() == "navigation_expression")
    else {
        return (String::new(), String::new());
    };
    let parts: Vec<Node> = named_kids(target).collect();
    if parts.len() < 2 {
        return (String::new(), String::new());
    }
    let container = py_text(parts[parts.len() - 1], src);
    let receiver = leftmost(parts[0], src, &["identifier"], &[]);
    (receiver, container)
}

fn c_declarator_name(node: Node, src: &[u8]) -> String {
    let mut cur = node;
    loop {
        if cur.kind() == "identifier" || cur.kind() == "field_identifier" {
            return py_text(cur, src);
        }
        match cur.child_by_field_name("declarator") {
            Some(next) => cur = next,
            None => return String::new(),
        }
    }
}

fn c_fn_name(node: Node, src: &[u8]) -> String {
    node.child_by_field_name("declarator")
        .map(|d| c_declarator_name(d, src))
        .unwrap_or_default()
}

const C_ARRAY_NEW: &str = "operator_new_array";

fn c_call_parts(node: Node, src: &[u8]) -> (String, String) {
    if node.kind() == "new_expression" {
        return match c_new_array_length(node) {
            Some(_) => (String::new(), C_ARRAY_NEW.to_string()),
            None => (String::new(), String::new()),
        };
    }
    let Some(func) = node.child_by_field_name("function") else {
        return (String::new(), String::new());
    };
    match func.kind() {
        "identifier" => (String::new(), py_text(func, src)),
        "field_expression" => (
            leftmost(func, src, &["identifier"], &["argument"]),
            field_text(func, src, "field"),
        ),
        "qualified_identifier" => (
            field_text(func, src, "scope"),
            field_text(func, src, "name"),
        ),
        _ => (String::new(), String::new()),
    }
}

fn c_params(node: Node, src: &[u8]) -> Vec<String> {
    let Some(decl) = node.child_by_field_name("declarator") else {
        return Vec::new();
    };
    let Some(params) = decl.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_kids(params)
        .filter(|p| p.kind() == "parameter_declaration")
        .map(|p| {
            p.child_by_field_name("declarator")
                .map(|d| c_declarator_name(d, src))
                .unwrap_or_default()
        })
        .collect()
}

fn c_new_array_length<'a>(node: Node<'a>) -> Option<Node<'a>> {
    if node.kind() != "new_expression" {
        return None;
    }
    node.child_by_field_name("declarator")
        .filter(|d| d.kind() == "new_declarator")
        .and_then(|d| d.child_by_field_name("length"))
}

fn c_arguments<'a>(node: Node<'a>) -> Vec<Node<'a>> {
    match c_new_array_length(node) {
        Some(length) => vec![length],
        None => field_arguments(node, "\0"),
    }
}

fn c_arg_count(node: Node) -> Option<usize> {
    match c_new_array_length(node) {
        Some(_) => Some(1),
        None => field_arg_count(node),
    }
}

fn c_static_args(node: Node, _src: &[u8]) -> Vec<bool> {
    c_arguments(node)
        .into_iter()
        .map(|v| v.kind() == "string_literal" || v.kind() == "concatenated_string")
        .collect()
}

const C_OVERFLOWING_OPERATORS: &[&str] = &["*", "+"];

fn c_arithmetic_args(node: Node, _src: &[u8]) -> Vec<bool> {
    c_arguments(node).into_iter().map(c_is_arithmetic).collect()
}

fn c_unparenthesized<'a>(node: Node<'a>) -> Node<'a> {
    let mut cur = node;
    while cur.kind() == "parenthesized_expression" {
        match named_kids(cur).next() {
            Some(inner) => cur = inner,
            None => break,
        }
    }
    cur
}

fn c_is_arithmetic(node: Node) -> bool {
    let cur = c_unparenthesized(node);
    cur.kind() == "binary_expression"
        && cur
            .child_by_field_name("operator")
            .is_some_and(|op| C_OVERFLOWING_OPERATORS.contains(&op.kind()))
}

fn c_unit_args(node: Node, src: &[u8]) -> Vec<bool> {
    c_arguments(node)
        .into_iter()
        .map(|a| c_is_unit_literal(a, src))
        .collect()
}

fn c_is_unit_literal(node: Node, src: &[u8]) -> bool {
    let cur = c_unparenthesized(node);
    cur.kind() == "number_literal" && py_text(cur, src) == "1"
}

fn c_read_name(node: Node, src: &[u8]) -> (String, String) {
    if node.kind() != "subscript_expression" {
        return (String::new(), String::new());
    }
    let name = node
        .child_by_field_name("argument")
        .filter(|a| a.kind() == "identifier")
        .map(|a| py_text(a, src))
        .unwrap_or_default();
    if C_ARGUMENT_VECTORS.contains(&name.as_str()) {
        (String::new(), name)
    } else {
        (String::new(), String::new())
    }
}

const C_ARGUMENT_VECTORS: &[&str] = &["argv", "envp"];

#[cfg(test)]
mod tests {
    use super::*;

    fn run(language: &str, src: &str) -> ExtractResult {
        let lang = super::super::ts_language(language).unwrap();
        let mut p = tree_sitter::Parser::new();
        p.set_language(&lang).unwrap();
        let tree = p.parse(src, None).unwrap();
        super::super::extract(language, src.as_bytes(), tree.root_node()).unwrap()
    }

    fn calls(res: &ExtractResult) -> Vec<String> {
        res.calls
            .iter()
            .map(|c| format!("{}.{}", c.receiver, c.method))
            .collect()
    }

    #[test]
    fn php_functions_methods_and_calls_are_extracted() {
        let res = run(
            "php",
            "<?php\nnamespace App;\nclass Svc {\n\
             \x20   public function run($a, $b) { return $this->helper($a); }\n}\n\
             function top($x) { return Svc::make($x) + strlen($x); }\n",
        );
        assert_eq!(res.functions.len(), 2);
        assert_eq!(res.functions[0].name, "run");
        assert_eq!(res.functions[0].class_name, "Svc");
        assert_eq!(
            res.functions[0].params,
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(res.functions[1].name, "top");
        assert_eq!(res.functions[1].class_name, "");
        assert_eq!(
            calls(&res),
            vec![
                "$this.helper".to_string(),
                "Svc.make".to_string(),
                ".strlen".to_string()
            ]
        );
        assert_eq!(res.calls[0].containing_fn, "run");
        assert_eq!(res.calls[1].containing_fn, "top");
    }

    fn static_calls(res: &ExtractResult) -> Vec<String> {
        res.calls
            .iter()
            .map(|c| {
                format!(
                    "{}@{}",
                    c.method,
                    c.static_args.first().copied().unwrap_or(false)
                )
            })
            .collect()
    }

    #[test]
    fn php_tells_a_bound_query_from_an_interpolated_one() {
        let res = run(
            "php",
            "<?php\nDB::select('select a where b = ?', [$e]);\nDB::select(\"select a where b = '{$x}'\");\nDB::select($sql);\n",
        );
        assert_eq!(
            static_calls(&res),
            vec![
                "select@true".to_string(),
                "select@false".to_string(),
                "select@false".to_string()
            ]
        );
    }

    #[test]
    fn php_superglobal_reads_are_receiver_less_call_sites() {
        let res = run(
            "php",
            "<?php\nfunction h() { $a = $_GET['q']; $b = $_POST['p']; $c = $rows['k']; }\n",
        );
        assert_eq!(calls(&res), vec!["._GET".to_string(), "._POST".to_string()]);
        assert!(res.calls.iter().all(|c| c.containing_fn == "h"));
        assert!(res.calls.iter().all(|c| c.property_read));
    }

    #[test]
    fn php_inclusion_is_a_call_and_a_fixed_path_is_static() {
        let res = run(
            "php",
            "<?php\nrequire __DIR__.'/vendor/autoload.php';\ninclude $layout;\nrequire_once 'a.php';\ninclude_once BASE.$n;\n",
        );
        assert_eq!(
            static_calls(&res),
            vec![
                "include@true".to_string(),
                "include@false".to_string(),
                "include@true".to_string(),
                "include@false".to_string()
            ]
        );
    }

    #[test]
    fn ruby_tells_a_bound_where_from_an_interpolated_one() {
        let res = run(
            "ruby",
            "where('owner = ?', o)\nfind_by_sql(\"SELECT #{x}\")\nwhere(cond)\n",
        );
        assert_eq!(
            static_calls(&res),
            vec![
                "where@true".to_string(),
                "find_by_sql@false".to_string(),
                "where@false".to_string()
            ]
        );
    }

    #[test]
    fn ruby_request_container_reads_are_receiver_less_call_sites() {
        let res = run(
            "ruby",
            "def h\n  a = params[:x]\n  b = cookies[:y]\n  c = rows[:z]\nend\n",
        );
        assert_eq!(
            calls(&res),
            vec![".params".to_string(), ".cookies".to_string()]
        );
    }

    #[test]
    fn rust_tells_a_literal_query_from_a_formatted_one() {
        let res = run(
            "rust",
            "fn f() {\n    sqlx::query(\"SELECT 1\");\n    sqlx::query(&fmt(\"SELECT {}\", x));\n    sqlx::query(r#\"SELECT 2\"#);\n}\n",
        );
        assert_eq!(
            static_calls(&res),
            vec![
                "query@true".to_string(),
                "query@false".to_string(),
                "fmt@true".to_string(),
                "query@true".to_string()
            ]
        );
    }

    #[test]
    fn kotlin_tells_a_bound_query_from_a_templated_one() {
        let res = run(
            "kotlin",
            "fun f() {\n  st.executeQuery(\"SELECT 1 WHERE a = ?\")\n  st.executeQuery(\"SELECT $x\")\n  st.executeQuery(\"SELECT ${a.b}\")\n  st.executeQuery(sql)\n  st.executeQuery()\n}\n",
        );
        assert_eq!(
            static_calls(&res),
            vec![
                "executeQuery@true".to_string(),
                "executeQuery@false".to_string(),
                "executeQuery@false".to_string(),
                "executeQuery@false".to_string(),
                "executeQuery@false".to_string()
            ]
        );
        assert_eq!(res.calls[4].arg_count, Some(0));
        assert_eq!(res.calls[0].arg_count, Some(1));
    }

    #[test]
    fn kotlin_ktor_request_reads_name_their_container_and_receiver() {
        let res = run(
            "kotlin",
            "fun h(call: ApplicationCall) {\n  val a = call.request.queryParameters[\"owner\"]\n  val b = call.parameters[\"id\"]\n  val c = rows[\"k\"]\n}\n",
        );
        assert_eq!(
            calls(&res),
            vec![
                "call.queryParameters".to_string(),
                "call.parameters".to_string()
            ]
        );
        assert!(res.calls.iter().all(|c| c.property_read));
    }

    #[test]
    fn c_functions_calls_and_argv_reads_are_extracted() {
        let res = run(
            "c-cpp",
            "struct report *report_open(const char *path, const char *tenant)\n{\n    return calloc(1, 8);\n}\nint main(int argc, char **argv)\n{\n    const char *t = argv[1];\n    const char *o = other[2];\n    report_open(\"/spool\", t);\n    return 0;\n}\n",
        );
        assert_eq!(
            res.functions
                .iter()
                .map(|f| f.name.as_str())
                .collect::<Vec<_>>(),
            vec!["report_open", "main"]
        );
        assert_eq!(
            res.functions[1].params,
            vec!["argc".to_string(), "argv".to_string()]
        );
        assert_eq!(
            calls(&res),
            vec![
                ".calloc".to_string(),
                "._argv".replace("_argv", "argv"),
                ".report_open".to_string()
            ]
        );
        assert_eq!(res.calls[1].containing_fn, "main");
        assert!(res.calls[1].property_read);
    }

    #[test]
    fn cpp_method_and_namespaced_calls_carry_their_receiver() {
        let res = run(
            "c-cpp",
            "int run() {\n    obj.method(x);\n    ptr->method(y);\n    ns::fn(z);\n    bare(w);\n    return 0;\n}\n",
        );
        assert_eq!(
            calls(&res),
            vec![
                "obj.method".to_string(),
                "ptr.method".to_string(),
                "ns.fn".to_string(),
                ".bare".to_string()
            ]
        );
    }

    #[test]
    fn c_tells_a_literal_format_from_a_variable_one() {
        let res = run(
            "c-cpp",
            "void f(const char *m) {\n    fprintf(s, m);\n    fprintf(s, \"fixed\");\n    snprintf(d, n, \"%s\", m);\n}\n",
        );
        let flags: Vec<Vec<bool>> = res.calls.iter().map(|c| c.static_args.clone()).collect();
        assert_eq!(
            flags,
            vec![
                vec![false, false],
                vec![false, true],
                vec![false, false, true, false]
            ]
        );
        assert_eq!(res.calls[2].arg_count, Some(4));
    }

    #[test]
    fn c_tells_a_computed_allocation_size_from_a_plain_one() {
        let res = run(
            "c-cpp",
            "void f(size_t n, size_t m) {\n\
             \x20   a = malloc(n * m);\n\
             \x20   b = malloc(len);\n\
             \x20   c = malloc(16);\n\
             \x20   d = malloc(sizeof(struct hdr));\n\
             \x20   e = malloc(n * sizeof(int));\n\
             \x20   g = malloc(len + 1);\n\
             \x20   h = realloc(p, n * m);\n\
             \x20   i = calloc(n, m);\n\
             \x20   j = malloc((n));\n\
             \x20   k = malloc((n * m));\n\
             \x20   l = malloc(-n);\n\
             \x20   o = malloc(n << 2);\n\
             }\n",
        );
        let flags: Vec<(&str, Vec<bool>)> = res
            .calls
            .iter()
            .map(|c| (c.method.as_str(), c.arithmetic_args.clone()))
            .collect();
        assert_eq!(
            flags,
            vec![
                ("malloc", vec![true]),
                ("malloc", vec![false]),
                ("malloc", vec![false]),
                ("malloc", vec![false]),
                ("malloc", vec![true]),
                ("malloc", vec![true]),
                ("realloc", vec![false, true]),
                ("calloc", vec![false, false]),
                ("malloc", vec![false]),
                ("malloc", vec![true]),
                ("malloc", vec![false]),
                ("malloc", vec![false]),
            ]
        );
    }

    #[test]
    fn cpp_an_array_new_is_a_call_whose_size_is_argument_zero() {
        let res = run(
            "c-cpp",
            "void f(size_t n, size_t m) {\n\
             \x20   int *a = new int[n * m];\n\
             \x20   int *b = new int[n];\n\
             \x20   char *c = new char[(n + 1) * m];\n\
             \x20   auto *d = new std::vector<int>[n * m];\n\
             \x20   int *e = new int[n * m]();\n\
             }\n",
        );
        let flags: Vec<(&str, Vec<bool>, Option<usize>)> = res
            .calls
            .iter()
            .map(|c| (c.method.as_str(), c.arithmetic_args.clone(), c.arg_count))
            .collect();
        assert_eq!(
            flags,
            vec![
                ("operator_new_array", vec![true], Some(1)),
                ("operator_new_array", vec![false], Some(1)),
                ("operator_new_array", vec![true], Some(1)),
                ("operator_new_array", vec![true], Some(1)),
                ("operator_new_array", vec![true], Some(1)),
            ]
        );
        assert!(res.calls.iter().all(|c| c.receiver.is_empty()));
        assert!(res.calls.iter().all(|c| !c.property_read));
    }

    #[test]
    fn cpp_a_non_array_new_is_not_recorded_at_all() {
        let res = run(
            "c-cpp",
            "void f(size_t n, size_t m) {\n\
             \x20   Foo *a = new Foo;\n\
             \x20   Foo *b = new Foo(n * m);\n\
             \x20   bare(n);\n\
             }\n",
        );
        assert_eq!(calls(&res), vec![".bare".to_string()]);
    }

    #[test]
    fn c_tells_a_hand_multiplied_calloc_from_the_safe_idiom() {
        let res = run(
            "c-cpp",
            "void f(size_t n, size_t size, size_t len) {\n\
             \x20   a = calloc(n * size, 1);\n\
             \x20   b = calloc(n, size);\n\
             \x20   c = calloc(len + 1, sizeof(char));\n\
             \x20   d = calloc(1, sizeof(struct hdr));\n\
             \x20   e = calloc(n * size, size);\n\
             \x20   g = calloc(n, 1);\n\
             \x20   h = calloc(n * size, (1));\n\
             \x20   i = calloc(n * size, 1u);\n\
             }\n",
        );
        let flags: Vec<(Vec<bool>, Vec<bool>)> = res
            .calls
            .iter()
            .map(|c| (c.arithmetic_args.clone(), c.unit_args.clone()))
            .collect();
        assert_eq!(
            flags,
            vec![
                (vec![true, false], vec![false, true]),
                (vec![false, false], vec![false, false]),
                (vec![true, false], vec![false, false]),
                (vec![false, false], vec![true, false]),
                (vec![true, false], vec![false, false]),
                (vec![false, false], vec![false, true]),
                (vec![true, false], vec![false, true]),
                (vec![true, false], vec![false, false]),
            ]
        );
    }

    #[test]
    fn a_language_that_computes_no_arithmetic_shapes_reports_none() {
        let res = run("rust", "fn f() {\n    alloc(n * m, 1);\n}\n");
        assert_eq!(res.calls.len(), 1);
        assert!(res.calls[0].arithmetic_args.is_empty());
        assert!(res.calls[0].unit_args.is_empty());
    }

    #[test]
    fn php_namespaced_names_are_read_by_their_leaf() {
        let res = run("php", "<?php\n\\App\\Svc::make();\n\\App\\helper();\n");
        assert_eq!(
            calls(&res),
            vec!["Svc.make".to_string(), ".helper".to_string()]
        );
    }

    #[test]
    fn php_chained_member_calls_root_on_the_leftmost_variable() {
        let res = run("php", "<?php\n$a->b()->c();\n");
        assert_eq!(calls(&res), vec!["$a.c".to_string(), "$a.b".to_string()]);
    }

    #[test]
    fn php_a_function_without_parameters_has_none() {
        let res = run("php", "<?php\nfunction f() { return 1; }\n");
        assert!(res.functions[0].params.is_empty());
    }

    #[test]
    fn ruby_methods_and_calls_are_extracted() {
        let res = run(
            "ruby",
            "class C\n  def run(a, b = 1)\n    helper(a)\n    Svc.make(a)\n  end\nend\n",
        );
        assert_eq!(res.functions.len(), 1);
        assert_eq!(res.functions[0].name, "run");
        assert_eq!(res.functions[0].class_name, "C");
        assert_eq!(
            res.functions[0].params,
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            calls(&res),
            vec![".helper".to_string(), "Svc.make".to_string()]
        );
        assert_eq!(res.calls[0].containing_fn, "run");
    }

    #[test]
    fn ruby_a_chained_receiver_roots_on_its_leftmost_identifier() {
        let res = run("ruby", "svc.build.run\n");
        assert_eq!(
            calls(&res),
            vec!["svc.run".to_string(), "svc.build".to_string()]
        );
    }

    #[test]
    fn ruby_a_method_without_parameters_has_none() {
        let res = run("ruby", "def f\n  1\nend\n");
        assert!(res.functions[0].params.is_empty());
    }

    #[test]
    fn kotlin_functions_and_calls_are_extracted() {
        let res = run(
            "kotlin",
            "class Svc {\n    fun run(a: String, b: Int): String {\n\
             \x20       helper(a)\n        return repo.find(a)\n    }\n}\n",
        );
        assert_eq!(res.functions.len(), 1);
        assert_eq!(res.functions[0].name, "run");
        assert_eq!(res.functions[0].class_name, "Svc");
        assert_eq!(
            res.functions[0].params,
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(
            calls(&res),
            vec![".helper".to_string(), "repo.find".to_string()]
        );
    }

    #[test]
    fn kotlin_a_chained_navigation_roots_on_its_leftmost_identifier() {
        let res = run("kotlin", "fun f() {\n    a.b.c(1)\n}\n");
        assert_eq!(calls(&res), vec!["a.c".to_string()]);
    }

    #[test]
    fn kotlin_a_call_on_a_non_identifier_callee_is_dropped() {
        let res = run("kotlin", "fun f() {\n    (1 + 2)(3)\n}\n");
        assert!(res.calls.is_empty());
    }

    #[test]
    fn kotlin_a_function_without_a_parameter_list_has_none() {
        let res = run("kotlin", "val x = 1\nfun f() = x\n");
        assert!(res.functions[0].params.is_empty());
    }

    #[test]
    fn rust_functions_impl_blocks_and_calls_are_extracted() {
        let res = run(
            "rust",
            "impl Handler {\n    fn run(&self, a: u32) -> u32 {\n\
             \x20       helper(a);\n        std::cmp::max(a, 1);\n        self.inner(a)\n    }\n}\n",
        );
        assert_eq!(res.functions.len(), 1);
        assert_eq!(res.functions[0].name, "run");
        assert_eq!(res.functions[0].class_name, "Handler");
        assert_eq!(res.functions[0].params, vec!["a".to_string()]);
        assert_eq!(
            calls(&res),
            vec![
                ".helper".to_string(),
                "cmp.max".to_string(),
                "self.inner".to_string()
            ]
        );
        assert_eq!(res.calls[0].containing_fn, "run");
    }

    #[test]
    fn rust_a_chained_method_call_roots_on_its_leftmost_identifier() {
        let res = run("rust", "fn f(a: A) {\n    a.b().c();\n}\n");
        assert_eq!(calls(&res), vec!["a.c".to_string(), "a.b".to_string()]);
    }

    #[test]
    fn rust_a_call_through_a_non_path_expression_is_dropped() {
        let res = run("rust", "fn f() {\n    (make())(1);\n}\n");
        assert_eq!(calls(&res), vec![".make".to_string()]);
    }

    #[test]
    fn rust_a_function_span_covers_its_whole_body() {
        let res = run("rust", "fn f() {\n    let x = 1;\n}\n");
        assert_eq!(res.functions[0].start_line, 1);
        assert_eq!(res.functions[0].end_line, 3);
        assert!(res.functions[0].params.is_empty());
    }

    #[test]
    fn the_lite_plane_emits_no_taint_facts() {
        let res = run("rust", "fn f(a: u32) -> u32 {\n    let b = a;\n    b\n}\n");
        assert!(res.imports.is_empty());
        assert!(res.assigns.is_empty());
        assert!(res.returns.is_empty());
        assert!(res.call_args.is_empty());
    }
}
