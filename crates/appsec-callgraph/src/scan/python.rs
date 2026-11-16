use super::*;

pub(crate) fn py_leftmost_identifier(node: Node, src: &[u8]) -> String {
    let mut cur = node;
    loop {
        match cur.kind() {
            "identifier" => return py_text(cur, src),
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
            _ => {
                let Some(next) = cur.child(0) else {
                    return String::new();
                };
                cur = next;
            }
        }
    }
}

pub(super) fn py_snippet(src: &[u8], node: Node) -> String {
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

pub(super) fn py_value_symbols(node: Node, src: &[u8], depth: usize, out: &mut Vec<String>) {
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

pub(super) fn py_is_static_string(node: Node) -> bool {
    match node.kind() {
        "string" => !named_kids(node).any(|c| c.kind() == "interpolation"),
        "concatenated_string" => named_kids(node).all(py_is_static_string),
        _ => false,
    }
}

pub(super) fn py_call_parts(call_node: Node, src: &[u8]) -> (String, String) {
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

pub(super) fn py_assignment_target_for_call(call_node: Node, src: &[u8]) -> Option<String> {
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

pub(super) fn py_param_names(fn_node: Node, src: &[u8]) -> Vec<String> {
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

pub(super) fn py_identifier_args(call_node: Node, src: &[u8]) -> (Vec<String>, Vec<usize>) {
    slotted_arg_symbols(
        call_node.child_by_field_name("arguments"),
        src,
        py_value_symbols,
    )
}

pub(super) fn py_return_symbols(ret_node: Node, src: &[u8]) -> Vec<String> {
    let val = ret_node
        .child_by_field_name("value")
        .or_else(|| named_kids(ret_node).find(|c| c.kind() != "return"));
    let mut out = Vec::new();
    if let Some(val) = val {
        py_value_symbols(val, src, 0, &mut out);
    }
    out
}

#[derive(Default)]
pub(super) struct PyExtractState {
    imports: BTreeMap<String, String>,
    functions: Vec<FuncDef>,
    fn_ranges: Vec<(usize, usize, String)>,
    calls: Vec<RawCall>,
    assigns: Vec<VarAssignFact>,
    returns: Vec<ReturnFact>,
    call_args: Vec<CallArgFact>,
}

pub(super) fn py_visit(node: Node, src: &[u8], state: &mut PyExtractState) {
    match node.kind() {
        "import_statement" => {
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
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        py_visit(child, src, state);
    }
}

pub(super) fn py_extract(src: &[u8], root: Node) -> ExtractResult {
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
