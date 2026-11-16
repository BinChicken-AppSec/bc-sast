use super::*;

pub(crate) fn cs_argument_value<'a>(arg: Node<'a>) -> Option<Node<'a>> {
    arg.child_by_field_name("expression")
        .or_else(|| named_kids(arg).next())
}

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

pub(super) fn cs_invocation_parts(node: Node, src: &[u8]) -> (String, String) {
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

pub(super) fn cs_value_symbols(node: Node, src: &[u8], depth: usize, out: &mut Vec<String>) {
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

pub(super) fn cs_param_names(fn_node: Node, src: &[u8]) -> Vec<String> {
    let Some(params) = fn_node.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named_kids(params)
        .filter(|p| p.kind() == "parameter")
        .filter_map(|p| p.child_by_field_name("name"))
        .map(|n| py_text(n, src))
        .collect()
}

pub(super) fn cs_identifier_args(call_node: Node, src: &[u8]) -> (Vec<String>, Vec<usize>) {
    slotted_arg_symbols(
        call_node.child_by_field_name("arguments"),
        src,
        cs_value_symbols,
    )
}

pub(super) fn cs_is_static_string(node: Node) -> bool {
    match node.kind() {
        "argument" => named_kids(node).next().is_some_and(cs_is_static_string),
        "string_literal" | "verbatim_string_literal" | "raw_string_literal" => true,
        "interpolated_string_expression" => !named_kids(node).any(|c| c.kind() == "interpolation"),
        _ => false,
    }
}

pub(super) fn cs_bound_value(node: Node) -> Node {
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

pub(super) fn cs_is_property_read(node: Node) -> bool {
    let Some(parent) = node.parent() else {
        return true;
    };
    match parent.kind() {
        "invocation_expression" => false,
        "assignment_expression" | "simple_assignment_expression" => {
            parent.child_by_field_name("left") != Some(node)
        }
        _ => true,
    }
}

pub(super) fn cs_call_target(node: Node, src: &[u8]) -> Option<String> {
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

pub(super) fn cs_return_symbols(ret_node: Node, src: &[u8]) -> Vec<String> {
    let expr = ret_node
        .child_by_field_name("expression")
        .or_else(|| named_kids(ret_node).next());
    let mut out = Vec::new();
    if let Some(expr) = expr {
        cs_value_symbols(expr, src, 0, &mut out);
    }
    out
}

pub(super) fn cs_value_source(value_node: Node, src: &[u8]) -> (Vec<String>, Option<String>) {
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

pub(super) fn cs_assignment_parts(
    node: Node,
    src: &[u8],
) -> (Option<String>, Vec<String>, Option<String>) {
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
pub(super) struct CsExtractState {
    imports: BTreeMap<String, String>,
    functions: Vec<FuncDef>,
    fn_ranges: Vec<(usize, usize, String)>,
    calls: Vec<RawCall>,
    assigns: Vec<VarAssignFact>,
    returns: Vec<ReturnFact>,
    call_args: Vec<CallArgFact>,
    class_stack: Vec<String>,
}

pub(super) fn cs_visit_variable_declarator(node: Node, src: &[u8], state: &mut CsExtractState) {
    let name_node = node.child_by_field_name("name");
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

pub(super) fn cs_visit(node: Node, src: &[u8], state: &mut CsExtractState) {
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

pub(super) fn cs_extract(src: &[u8], root: Node) -> ExtractResult {
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
