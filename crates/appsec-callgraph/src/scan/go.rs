use super::*;

pub(super) fn go_leftmost_identifier(node: Node, src: &[u8]) -> String {
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

pub(super) fn go_import_spec(spec: Node, src: &[u8], imports: &mut BTreeMap<String, String>) {
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

pub(super) fn go_value_symbols(node: Node, src: &[u8], depth: usize, out: &mut Vec<String>) {
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

pub(super) fn go_call_parts(node: Node, src: &[u8]) -> (String, String) {
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

pub(super) fn go_param_names(fn_node: Node, src: &[u8]) -> Vec<String> {
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

pub(super) fn go_identifier_args(call_node: Node, src: &[u8]) -> (Vec<String>, Vec<usize>) {
    slotted_arg_symbols(
        call_node.child_by_field_name("arguments"),
        src,
        go_value_symbols,
    )
}

pub(super) fn go_is_static_string(node: Node) -> bool {
    matches!(
        node.kind(),
        "interpreted_string_literal" | "raw_string_literal"
    )
}

pub(super) fn go_return_symbols(ret_node: Node, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for c in named_kids(ret_node) {
        go_value_symbols(c, src, 0, &mut out);
    }
    out
}

pub(super) fn go_value_source(value_node: Node, src: &[u8]) -> (Vec<String>, Option<String>) {
    if value_node.kind() == "call_expression" {
        let (_recv, method) = go_call_parts(value_node, src);
        return (Vec::new(), (!method.is_empty()).then_some(method));
    }
    let mut out = Vec::new();
    go_value_symbols(value_node, src, 0, &mut out);
    (out, None)
}

pub(super) fn go_assign_pairs<'a>(
    lefts: Vec<Node<'a>>,
    right: Node<'a>,
) -> Vec<(Node<'a>, Node<'a>)> {
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

pub(super) fn go_enclosing_assignment<'a>(node: Node<'a>) -> Option<(Vec<Node<'a>>, Node<'a>)> {
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

pub(super) fn go_call_target(node: Node, src: &[u8]) -> Option<String> {
    let (lefts, right) = go_enclosing_assignment(node)?;
    let name = go_assign_pairs(lefts, right)
        .into_iter()
        .find(|(_, r)| *r == node)
        .map(|(l, _)| l)
        .filter(|l| l.kind() == "identifier")?;
    let text = py_text(name, src);
    (text != "_").then_some(text)
}

pub(super) const GO_BUILDER_WRITES: &[&str] = &["Write", "WriteByte", "WriteRune", "WriteString"];

#[derive(Default)]
pub(super) struct GoExtractState {
    imports: BTreeMap<String, String>,
    functions: Vec<FuncDef>,
    fn_ranges: Vec<(usize, usize, String)>,
    calls: Vec<RawCall>,
    assigns: Vec<VarAssignFact>,
    returns: Vec<ReturnFact>,
    call_args: Vec<CallArgFact>,
}

pub(super) fn go_visit_assignment(
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

pub(super) fn go_visit(node: Node, src: &[u8], state: &mut GoExtractState) {
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

pub(super) fn go_extract(src: &[u8], root: Node) -> ExtractResult {
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
