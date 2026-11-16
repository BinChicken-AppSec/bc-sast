use super::*;

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

pub(super) static GENERICS_RX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^>]*>").unwrap());

pub(super) fn java_normalize_type_name(raw: &str) -> String {
    let t = GENERICS_RX.replace_all(raw, "");
    let t = t.replace("[]", "");
    t.split_whitespace().next_back().unwrap_or("").to_string()
}

pub(super) fn java_resolve_type(
    raw: &str,
    imports: &BTreeMap<String, String>,
    package_name: &str,
) -> String {
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

pub(super) fn java_ctor_type_from_node(
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

pub(super) fn java_invocation_parts(node: Node, src: &[u8]) -> (String, String) {
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

pub(super) fn java_value_symbols(node: Node, src: &[u8], depth: usize, out: &mut Vec<String>) {
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

pub(super) fn java_param_names(fn_node: Node, src: &[u8]) -> Vec<String> {
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

pub(super) fn java_identifier_args(call_node: Node, src: &[u8]) -> (Vec<String>, Vec<usize>) {
    slotted_arg_symbols(
        call_node.child_by_field_name("arguments"),
        src,
        java_value_symbols,
    )
}

pub(super) fn java_is_static_string(node: Node) -> bool {
    node.kind() == "string_literal"
}

pub(super) fn java_call_target(node: Node, src: &[u8]) -> Option<String> {
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

pub(super) fn java_return_symbols(ret_node: Node, src: &[u8]) -> Vec<String> {
    let val = ret_node
        .child_by_field_name("value")
        .or_else(|| named_kids(ret_node).next());
    let mut out = Vec::new();
    if let Some(val) = val {
        java_value_symbols(val, src, 0, &mut out);
    }
    out
}

pub(super) fn java_value_source(value_node: Node, src: &[u8]) -> (Vec<String>, Option<String>) {
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

#[derive(Default)]
pub(super) struct JavaExtractState {
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

pub(super) fn java_visit_local_variable_declaration(
    node: Node,
    src: &[u8],
    state: &mut JavaExtractState,
) {
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

pub(super) fn java_visit_assignment_expression(
    node: Node,
    src: &[u8],
    state: &mut JavaExtractState,
) {
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

pub(super) fn java_visit(node: Node, src: &[u8], state: &mut JavaExtractState) {
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

pub(super) fn java_extract(src: &[u8], root: Node) -> ExtractResult {
    let mut state = JavaExtractState::default();
    java_visit(root, src, &mut state);
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
