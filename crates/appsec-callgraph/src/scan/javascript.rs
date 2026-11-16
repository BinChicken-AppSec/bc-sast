use super::*;

pub(super) fn js_leftmost_identifier(node: Node, src: &[u8]) -> String {
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

pub(super) fn js_value_symbols(node: Node, src: &[u8], depth: usize, out: &mut Vec<String>) {
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

pub(super) fn js_call_parts(node: Node, src: &[u8]) -> (String, String) {
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

pub(super) fn js_param_name(param: Node, src: &[u8]) -> String {
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

pub(super) fn js_param_names(fn_node: Node, src: &[u8]) -> Vec<String> {
    let Some(params) = fn_node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_kids(params).map(|p| js_param_name(p, src)).collect()
}

pub(super) fn js_identifier_args(call_node: Node, src: &[u8]) -> (Vec<String>, Vec<usize>) {
    slotted_arg_symbols(
        call_node.child_by_field_name("arguments"),
        src,
        js_value_symbols,
    )
}

pub(super) fn js_is_static_string(node: Node) -> bool {
    match node.kind() {
        "string" => true,
        "template_string" => !named_kids(node).any(|c| c.kind() == "template_substitution"),
        _ => false,
    }
}

pub(super) fn js_bound_value(node: Node) -> Node {
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

pub(super) fn js_call_target(node: Node, src: &[u8]) -> Option<String> {
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

pub(super) fn js_value_source(value_node: Node, src: &[u8]) -> (Vec<String>, Option<String>) {
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

pub(super) fn js_return_symbols(ret_node: Node, src: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(val) = named_kids(ret_node).next() {
        js_value_symbols(val, src, 0, &mut out);
    }
    out
}

pub(super) fn js_is_property_read(node: Node) -> bool {
    let Some(parent) = node.parent() else {
        return true;
    };
    match parent.kind() {
        "call_expression" | "new_expression" => false,
        "assignment_expression" | "augmented_assignment_expression" => {
            parent.child_by_field_name("left") != Some(node)
        }
        _ => true,
    }
}

#[derive(Default)]
pub(super) struct JsExtractState {
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

pub(super) fn js_bound_function<'a>(node: Node<'a>, src: &[u8]) -> Option<(String, Node<'a>)> {
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

pub(super) fn js_visit_import_clause(
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

pub(super) fn js_visit(node: Node, src: &[u8], state: &mut JsExtractState) {
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

pub(super) fn js_extract(src: &[u8], root: Node) -> ExtractResult {
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
