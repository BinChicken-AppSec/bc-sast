use super::*;
use std::collections::BTreeSet;
use std::path::PathBuf;

fn write_py(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

fn parse(src: &[u8]) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .unwrap();
    parser.parse(src, None).unwrap()
}

fn find_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(f) = find_kind(child, kind) {
            return Some(f);
        }
    }
    None
}

#[test]
fn find_kind_none_when_no_node_of_that_kind_exists() {
    let tree = parse(b"x = 1\n");
    assert!(find_kind(tree.root_node(), "nonexistent_node_kind").is_none());
}

fn py_args(body: &str) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", body);
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    idx.call_args
        .into_iter()
        .find(|c| c.callee_name == "system")
        .expect("no os.system call fact")
        .arg_symbols
}

#[test]
fn py_arg_symbols_read_through_an_f_string() {
    assert_eq!(
        py_args("def f(host):\n    os.system(f\"ping -c 1 {host}\")\n"),
        vec!["host".to_string()]
    );
}

#[test]
fn py_arg_symbols_read_through_a_concatenation_chain() {
    assert_eq!(
        py_args("def f(a, b):\n    os.system(\"x\" + a + \"y\" + b)\n"),
        vec!["a".to_string(), "b".to_string()]
    );
}

#[test]
fn py_arg_symbols_read_through_a_format_call() {
    assert_eq!(
        py_args("def f(a):\n    os.system(\"ping {}\".format(a))\n"),
        vec!["a".to_string()]
    );
}

#[test]
fn py_arg_symbols_read_through_percent_formatting() {
    assert_eq!(
        py_args("def f(a):\n    os.system(\"ping %s\" % a)\n"),
        vec!["a".to_string()]
    );
}

#[test]
fn py_arg_symbols_read_through_a_nested_call() {
    assert_eq!(
        py_args("def f(name):\n    os.system(shlex.quote(name))\n"),
        vec!["name".to_string()]
    );
}

#[test]
fn py_arg_symbols_read_through_an_adjacent_literal_concatenation() {
    assert_eq!(
        py_args("def f(a):\n    os.system(\"x\" \"y\" + a)\n"),
        vec!["a".to_string()]
    );
}

#[test]
fn py_arg_symbols_deduplicate_a_repeated_operand() {
    assert_eq!(
        py_args("def f(a):\n    os.system(f\"{a} and {a}\")\n"),
        vec!["a".to_string()]
    );
}

#[test]
fn py_arg_symbols_do_not_descend_into_a_collection_literal() {
    assert!(py_args("def f(a):\n    os.system(\"q\", (a,))\n").is_empty());
}

#[test]
fn py_arg_symbols_carry_the_argument_slot_they_came_from() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.py",
        "def f(a, b):\n    os.system(\"lit\", \"-v \" + a, b)\n",
    );
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    let fact = idx
        .call_args
        .into_iter()
        .find(|c| c.callee_name == "system")
        .expect("no os.system call fact");
    assert_eq!(fact.arg_symbols, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(fact.arg_slots, vec![1, 2]);
}

#[test]
fn py_param_names_follow_caller_slots() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.py",
        "class A:\n    def m(self, a, b=1, *args, c: int = 2, **kw):\n        pass\n\n\
         def g(a, /, b: str, *, c):\n    pass\n",
    );
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    let params = |name: &str| {
        idx.functions
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .params
            .clone()
    };
    assert_eq!(params("m"), vec!["a", "b", "args", "c", "kw"]);
    assert_eq!(params("g"), vec!["a", "b", "c"]);
}

#[test]
fn java_and_csharp_param_names_follow_caller_slots() {
    let dir = tempfile::tempdir().unwrap();
    let j = dir.path().join("A.java");
    std::fs::write(&j, "class A { void m(String a, int... rest) {} }\n").unwrap();
    let idx = scan_file(&j, "A.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.functions[0].params, vec!["a", "rest"]);
    let c = dir.path().join("A.cs");
    std::fs::write(&c, "class A { void M(string a, int b) { } }\n").unwrap();
    let idx = scan_file(&c, "A.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.functions[0].params, vec!["a", "b"]);
}

#[test]
fn param_names_are_empty_when_the_node_has_no_parameters_field() {
    let src = b"x = 1\n";
    let tree = parse(src);
    let ident = find_kind(tree.root_node(), "identifier").unwrap();
    assert!(py_param_names(ident, src).is_empty());
    assert!(java_param_names(ident, src).is_empty());
    assert!(cs_param_names(ident, src).is_empty());
}

#[test]
fn py_composite_assignment_records_one_alias_fact_per_operand() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.py",
        "def f(a, b):\n    v = \"%\" + a + b\n",
    );
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.assigns.len(), 2);
    assert!(idx.assigns.iter().all(|x| x.dst_symbol == "v"));
    let srcs: Vec<Option<&str>> = idx
        .assigns
        .iter()
        .map(|x| x.src_symbol.as_deref())
        .collect();
    assert_eq!(srcs, vec![Some("a"), Some("b")]);
}

#[test]
fn py_composite_return_records_one_fact_per_operand() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.py",
        "def f(v):\n    return \"%\" + v + \"%\"\n",
    );
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.returns.len(), 1);
    assert_eq!(idx.returns[0].symbol, Some("v".to_string()));
}

#[test]
fn py_first_arg_is_static_string_distinguishes_bound_from_built_queries() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.py",
        "def f(p, q):\n    cur.execute(\"S ?\", (p,))\n    cur.execute(\"S \" + p)\n    cur.execute(q)\n    cur.execute(f\"S {p}\")\n",
    );
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    let src = std::fs::read(&path).unwrap();
    let tree = parse(&src);
    let mut statics = Vec::new();
    fn walk(n: Node, src: &[u8], out: &mut Vec<bool>) {
        if n.kind() == "call" {
            out.push(static_arg_at(
                &arg_shape(n.child_by_field_name("arguments"), src, py_is_static_string).2,
                0,
            ));
        }
        for c in kids(n) {
            walk(c, src, out);
        }
    }
    walk(tree.root_node(), &src, &mut statics);
    assert_eq!(statics, vec![true, false, false, false]);
    assert_eq!(idx.call_args.len(), 4);
}

#[test]
fn py_first_arg_is_static_string_false_without_an_arguments_field() {
    let src = b"x = 1\n";
    let tree = parse(src);
    let ident = find_kind(tree.root_node(), "identifier").unwrap();
    assert!(!static_arg_at(
        &arg_shape(
            ident.child_by_field_name("arguments"),
            src,
            py_is_static_string
        )
        .2,
        0,
    ));
}

#[test]
fn cs_arg_symbols_walk_a_fluent_append_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "A.cs",
        "class A {\n  void F(string a, string b) {\n    Run(sb.Append(a).Append(b).ToString());\n  }\n}\n",
    );
    let idx = scan_file(&path, "A.cs", "csharp", &[], &[], false, None, None).unwrap();
    let run = idx
        .call_args
        .iter()
        .find(|c| c.callee_name == "Run")
        .unwrap();
    assert_eq!(run.arg_symbols, vec!["b".to_string(), "a".to_string()]);
}

#[test]
fn java_arg_symbols_read_through_concatenation_and_format_and_builders() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "A.java",
        "class A {\n  void f(String p) {\n    st.executeQuery(\"S \" + p);\n    st.executeUpdate(String.format(\"S %s\", p));\n    st.execute(sb.append(p).toString());\n  }\n}\n",
    );
    let idx = scan_file(&path, "A.java", "java", &[], &[], false, None, None).unwrap();
    let by = |name: &str| {
        idx.call_args
            .iter()
            .find(|c| c.callee_name == name)
            .unwrap()
            .arg_symbols
            .clone()
    };
    assert_eq!(by("executeQuery"), vec!["p".to_string()]);
    assert_eq!(by("executeUpdate"), vec!["p".to_string()]);
    assert_eq!(by("execute"), vec!["p".to_string()]);
}

#[test]
fn java_composite_rhs_and_return_record_every_operand() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "A.java",
        "class A {\n  String f(String a, String b) {\n    String q = \"x\" + a + b;\n    return \"y\" + q;\n  }\n}\n",
    );
    let idx = scan_file(&path, "A.java", "java", &[], &[], false, None, None).unwrap();
    let srcs: Vec<Option<&str>> = idx
        .assigns
        .iter()
        .map(|x| x.src_symbol.as_deref())
        .collect();
    assert_eq!(srcs, vec![Some("a"), Some("b")]);
    assert_eq!(idx.returns.len(), 1);
    assert_eq!(idx.returns[0].symbol, Some("q".to_string()));
}

#[test]
fn cs_arg_symbols_read_through_interpolation_concatenation_and_format() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "A.cs",
        "class A {\n  void F(string p) {\n    Alpha($\"S {p}\");\n    Beta(\"S \" + p);\n    Gamma(string.Format(\"S {0}\", p));\n  }\n}\n",
    );
    let idx = scan_file(&path, "A.cs", "csharp", &[], &[], false, None, None).unwrap();
    let by = |name: &str| {
        idx.call_args
            .iter()
            .find(|c| c.callee_name == name)
            .unwrap()
            .arg_symbols
            .clone()
    };
    assert_eq!(by("Alpha"), vec!["p".to_string()]);
    assert_eq!(by("Beta"), vec!["p".to_string()]);
    assert_eq!(by("Gamma"), vec!["p".to_string()]);
}

#[test]
fn cs_composite_rhs_and_return_record_every_operand() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "A.cs",
        "class A {\n  string F(string a, string b) {\n    var q = $\"{a}{b}\";\n    return q;\n  }\n}\n",
    );
    let idx = scan_file(&path, "A.cs", "csharp", &[], &[], false, None, None).unwrap();
    let srcs: Vec<Option<&str>> = idx
        .assigns
        .iter()
        .map(|x| x.src_symbol.as_deref())
        .collect();
    assert_eq!(srcs, vec![Some("a"), Some("b")]);
    assert_eq!(idx.returns[0].symbol, Some("q".to_string()));
}

#[test]
fn cs_first_arg_is_static_string_accepts_a_zero_interpolation_literal() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "A.cs",
        "class A {\n  void F(string p) {\n    Alpha($\"plain\");\n    Beta($\"S {p}\");\n  }\n}\n",
    );
    let src = std::fs::read(&path).unwrap();
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(&src, None).unwrap();
    let mut statics = Vec::new();
    fn walk(n: Node, src: &[u8], out: &mut Vec<bool>) {
        if n.kind() == "invocation_expression" {
            out.push(static_arg_at(
                &arg_shape(n.child_by_field_name("arguments"), src, cs_is_static_string).2,
                0,
            ));
        }
        for c in kids(n) {
            walk(c, src, out);
        }
    }
    walk(tree.root_node(), &src, &mut statics);
    assert_eq!(statics, vec![true, false]);
}

fn go_args(body: &str) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "main.go", body);
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    idx.call_args
        .into_iter()
        .find(|c| c.callee_name == "sink")
        .expect("no sink call fact")
        .arg_symbols
}

fn go_fn(stmts: &str) -> String {
    format!("package main\nfunc f(a string, b string) {{\n{stmts}}}\n")
}

#[test]
fn go_arg_symbols_read_through_a_sprintf_call() {
    assert_eq!(
        go_args(&go_fn("\tsink(fmt.Sprintf(\"ping %s\", a))\n")),
        vec!["a".to_string()]
    );
}

#[test]
fn go_arg_symbols_read_through_a_concatenation_chain() {
    assert_eq!(
        go_args(&go_fn("\tsink(\"echo \" + a + b)\n")),
        vec!["a".to_string(), "b".to_string()]
    );
}

#[test]
fn go_arg_symbols_read_through_strings_join_and_a_conversion() {
    assert_eq!(
        go_args(&go_fn("\tsink(strings.Join(a, \",\"), string(b))\n")),
        vec!["a".to_string(), "b".to_string()]
    );
}

#[test]
fn go_arg_symbols_walk_a_fluent_call_chain() {
    assert_eq!(
        go_args(&go_fn("\tsink(exec.Command(a).Output())\n")),
        vec!["a".to_string()]
    );
}

#[test]
fn go_arg_symbols_carry_the_argument_slot_they_came_from() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        &go_fn("\tsink(\"lit\", \"-v \"+a, b)\n"),
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    let fact = idx
        .call_args
        .into_iter()
        .find(|c| c.callee_name == "sink")
        .expect("no sink call fact");
    assert_eq!(fact.arg_symbols, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(fact.arg_slots, vec![1, 2]);
}

#[test]
fn go_arg_symbols_do_not_descend_into_a_composite_literal() {
    assert!(go_args(&go_fn("\tsink([]string{a})\n")).is_empty());
}

#[test]
fn go_param_names_cover_shared_types_variadics_and_exclude_the_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        "package main\n\
         func f(a, b string, c int, rest ...string) {}\n\
         func (h *H) M(x string) {}\n\
         func g() {}\n",
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    let params = |name: &str| {
        idx.functions
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .params
            .clone()
    };
    assert_eq!(params("f"), vec!["a", "b", "c", "rest"]);
    assert_eq!(params("M"), vec!["x"]);
    assert!(params("g").is_empty());
}

#[test]
fn go_composite_assignment_and_return_record_every_operand() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        &go_fn("\tq := \"x\" + a + b\n\treturn q, a\n"),
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    let srcs: Vec<Option<&str>> = idx
        .assigns
        .iter()
        .map(|x| x.src_symbol.as_deref())
        .collect();
    assert_eq!(srcs, vec![Some("a"), Some("b")]);
    let rets: Vec<Option<&str>> = idx.returns.iter().map(|r| r.symbol.as_deref()).collect();
    assert_eq!(rets, vec![Some("q"), Some("a")]);
}

#[test]
fn go_multi_value_assignment_spreads_one_call_across_every_target() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        &go_fn("\trows, err := db.Query(a)\n\t_, keep := split(b)\n\tx, y := a, b\n"),
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    let pairs: Vec<(&str, Option<&str>, Option<&str>)> = idx
        .assigns
        .iter()
        .map(|a| {
            (
                a.dst_symbol.as_str(),
                a.src_symbol.as_deref(),
                a.src_call.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        pairs,
        vec![
            ("rows", None, Some("Query")),
            ("err", None, Some("Query")),
            ("keep", None, Some("split")),
            ("x", Some("a"), None),
            ("y", Some("b"), None),
        ]
    );
}

#[test]
fn go_var_declaration_with_an_initializer_records_an_alias() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        &go_fn("\tvar q = a\n\tvar u, v = a, b\n\tvar bare string\n"),
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    let pairs: Vec<(&str, Option<&str>)> = idx
        .assigns
        .iter()
        .map(|a| (a.dst_symbol.as_str(), a.src_symbol.as_deref()))
        .collect();
    assert_eq!(
        pairs,
        vec![("q", Some("a")), ("u", Some("a")), ("v", Some("b"))]
    );
}

#[test]
fn go_call_target_is_recorded_for_a_short_declaration_and_an_assignment() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        &go_fn(
            "\tq := build(a)\n\tq = rebuild(b)\n\tvar v = declare(a)\n\
             \t_ = drop(a)\n\tbare(a)\n\tm[a] = keyed(b)\n",
        ),
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    let targets: Vec<(&str, Option<&str>)> = idx
        .call_args
        .iter()
        .map(|c| (c.callee_name.as_str(), c.target_symbol.as_deref()))
        .collect();
    assert_eq!(
        targets,
        vec![
            ("build", Some("q")),
            ("rebuild", Some("q")),
            ("declare", Some("v")),
            ("drop", None),
            ("bare", None),
            ("keyed", None),
        ]
    );
    assert!(!idx.assigns.iter().any(|a| a.dst_symbol.contains('[')));
}

#[test]
fn a_go_call_outside_an_assignment_binds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        "package main\nfunc f(a string) string {\n\treturn build(a)\n}\n",
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.call_args[0].callee_name, "build");
    assert_eq!(idx.call_args[0].target_symbol, None);
}

#[test]
fn go_param_names_skip_a_comment_in_the_parameter_list() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        "package main\nfunc f(/* c */ a string) {}\n",
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.functions[0].params, vec!["a".to_string()]);
}

#[test]
fn go_composed_value_walk_stops_at_the_depth_cap() {
    let deep =
        "(".repeat(COMPOSED_VALUE_MAX_DEPTH + 2) + "a" + &")".repeat(COMPOSED_VALUE_MAX_DEPTH + 2);
    assert!(go_args(&go_fn(&format!("\tsink({deep})\n"))).is_empty());
}

#[test]
fn js_composed_value_walk_stops_at_the_depth_cap() {
    let deep =
        "(".repeat(COMPOSED_VALUE_MAX_DEPTH + 2) + "a" + &")".repeat(COMPOSED_VALUE_MAX_DEPTH + 2);
    assert!(js_args(&js_fn(&format!("  sink({deep});\n"))).is_empty());
}

#[test]
fn go_builder_writes_alias_the_written_value_into_the_builder() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        &go_fn("\tsb.WriteString(a)\n\tother.Compute(b)\n"),
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    let pairs: Vec<(&str, Option<&str>)> = idx
        .assigns
        .iter()
        .map(|a| (a.dst_symbol.as_str(), a.src_symbol.as_deref()))
        .collect();
    assert_eq!(pairs, vec![("sb", Some("a"))]);
}

#[test]
fn go_first_arg_is_static_string_distinguishes_bound_from_built_queries() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        &go_fn("\tdb.Query(\"SELECT 1 WHERE x = ?\", a)\n\tdb.Query(`raw`)\n\tdb.Query(a)\n"),
    );
    let src = std::fs::read(&path).unwrap();
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(&src, None).unwrap();
    let mut statics = Vec::new();
    fn walk(n: Node, src: &[u8], out: &mut Vec<bool>) {
        if n.kind() == "call_expression" {
            out.push(static_arg_at(
                &arg_shape(n.child_by_field_name("arguments"), src, go_is_static_string).2,
                0,
            ));
        }
        for c in kids(n) {
            walk(c, src, out);
        }
    }
    walk(tree.root_node(), &src, &mut statics);
    assert_eq!(statics, vec![true, true, false]);
}

fn js_args_in(language: &str, name: &str, body: &str) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), name, body);
    let idx = scan_file(&path, name, language, &[], &[], false, None, None).unwrap();
    idx.call_args
        .into_iter()
        .find(|c| c.callee_name == "sink")
        .expect("no sink call fact")
        .arg_symbols
}

fn js_args(body: &str) -> Vec<String> {
    js_args_in("javascript", "app.js", body)
}

fn js_fn(stmts: &str) -> String {
    format!("function f(a, b) {{\n{stmts}}}\n")
}

#[test]
fn js_arg_symbols_read_through_a_template_literal() {
    assert_eq!(
        js_args(&js_fn("  sink(`ping -c 1 ${a} ${b}`);\n")),
        vec!["a".to_string(), "b".to_string()]
    );
}

#[test]
fn js_arg_symbols_read_through_a_concatenation_chain() {
    assert_eq!(
        js_args(&js_fn("  sink(\"echo \" + a + b);\n")),
        vec!["a".to_string(), "b".to_string()]
    );
}

#[test]
fn js_arg_symbols_walk_a_concat_chain_and_a_nested_call() {
    assert_eq!(
        js_args(&js_fn("  sink(\"x\".concat(a).concat(b));\n")),
        vec!["b".to_string(), "a".to_string()]
    );
    assert_eq!(
        js_args(&js_fn("  sink(escape(a));\n")),
        vec!["a".to_string()]
    );
}

#[test]
fn js_arg_symbols_read_through_a_ternary_and_a_typescript_cast() {
    assert_eq!(
        js_args(&js_fn("  sink(a ? a : b);\n")),
        vec!["a".to_string(), "b".to_string()]
    );
    assert_eq!(
        js_args_in(
            "typescript",
            "app.ts",
            "function f(a: string) {\n  sink((a as string)!);\n}\n"
        ),
        vec!["a".to_string()]
    );
}

#[test]
fn js_arg_symbols_do_not_descend_into_an_array_literal() {
    assert!(js_args(&js_fn("  sink([a, b]);\n")).is_empty());
}

#[test]
fn js_arg_symbols_carry_the_argument_slot_they_came_from() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        &js_fn("  sink(\"lit\", `-v ${a}`, b);\n"),
    );
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    let fact = idx
        .call_args
        .into_iter()
        .find(|c| c.callee_name == "sink")
        .expect("no sink call fact");
    assert_eq!(fact.arg_symbols, vec!["a".to_string(), "b".to_string()]);
    assert_eq!(fact.arg_slots, vec![1, 2]);
}

#[test]
fn js_param_names_cover_declarations_methods_arrows_and_destructuring() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        "function decl(a, b = 1, ...rest) {}\n\
         class K { m(x) {} }\n\
         const arrow = (req, res) => {};\n\
         const fexpr = function (c) {};\n\
         const api = { handler: (p) => {} };\n\
         function destructured({ id }, tail) {}\n",
    );
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    let params = |name: &str| {
        idx.functions
            .iter()
            .find(|f| f.name == name)
            .expect("no function of that name")
            .params
            .clone()
    };
    assert_eq!(params("decl"), vec!["a", "b", "rest"]);
    assert_eq!(params("m"), vec!["x"]);
    assert_eq!(params("arrow"), vec!["req", "res"]);
    assert_eq!(params("fexpr"), vec!["c"]);
    assert_eq!(params("handler"), vec!["p"]);
    assert_eq!(params("destructured"), vec!["", "tail"]);
}

#[test]
fn typescript_parameter_wrappers_are_unwrapped_to_their_pattern() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.ts",
        "function f(a: string, b?: number, ...rest: string[]) {}\n",
    );
    let idx = scan_file(&path, "app.ts", "typescript", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.functions[0].params, vec!["a", "b", "rest"]);
}

#[test]
fn js_arrow_bodies_are_attributed_to_the_name_they_are_bound_to() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        "const handle = (a) => { sink(a); };\nconst notAFunction = 1;\n",
    );
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    let fact = idx
        .call_args
        .iter()
        .find(|c| c.callee_name == "sink")
        .unwrap();
    assert_eq!(fact.function_qnode, "handle");
    assert_eq!(idx.functions.len(), 1);
}

#[test]
fn js_composite_assignment_and_return_record_every_operand() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        &js_fn("  const q = `${a}-${b}`;\n  let r;\n  r = q;\n  return r + a;\n"),
    );
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    let pairs: Vec<(&str, Option<&str>)> = idx
        .assigns
        .iter()
        .map(|x| (x.dst_symbol.as_str(), x.src_symbol.as_deref()))
        .collect();
    assert_eq!(
        pairs,
        vec![("q", Some("a")), ("q", Some("b")), ("r", Some("q"))]
    );
    let rets: Vec<Option<&str>> = idx.returns.iter().map(|r| r.symbol.as_deref()).collect();
    assert_eq!(rets, vec![Some("r"), Some("a")]);
}

#[test]
fn js_call_target_reads_through_await_and_an_assignment() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        "async function f(u) {\n  const rows = await load(u);\n  let g;\n  g = build(u);\n  drop(u);\n}\n",
    );
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    let targets: Vec<(&str, Option<&str>)> = idx
        .call_args
        .iter()
        .map(|c| (c.callee_name.as_str(), c.target_symbol.as_deref()))
        .collect();
    assert_eq!(
        targets,
        vec![("load", Some("rows")), ("build", Some("g")), ("drop", None)]
    );
    assert_eq!(idx.assigns[0].src_call, Some("load".to_string()));
}

#[test]
fn js_first_arg_is_static_string_distinguishes_bound_from_built_queries() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        &js_fn("  db.query(\"SELECT 1 WHERE x = ?\", a);\n  db.query(`plain`);\n  db.query(`x ${a}`);\n  db.query(a);\n"),
    );
    let src = std::fs::read(&path).unwrap();
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(&src, None).unwrap();
    let mut statics = Vec::new();
    fn walk(n: Node, src: &[u8], out: &mut Vec<bool>) {
        if n.kind() == "call_expression" {
            out.push(static_arg_at(
                &arg_shape(n.child_by_field_name("arguments"), src, js_is_static_string).2,
                0,
            ));
        }
        for c in kids(n) {
            walk(c, src, out);
        }
    }
    walk(tree.root_node(), &src, &mut statics);
    assert_eq!(statics, vec![true, true, false, false]);
}

#[test]
fn js_property_reads_are_call_sites_bound_to_their_assignment_target() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        "function h(req) {\n  const id = req.query.id;\n  const all = req.body;\n  req.locals.x = 1;\n  this.svc.go();\n}\n",
    );
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    let reads: Vec<(&str, &str, Option<&str>)> = idx
        .call_args
        .iter()
        .map(|c| {
            (
                c.receiver.as_str(),
                c.callee_name.as_str(),
                c.target_symbol.as_deref(),
            )
        })
        .collect();
    assert!(reads.contains(&("req", "query", Some("id"))));
    assert!(reads.contains(&("req", "id", Some("id"))));
    assert!(reads.contains(&("req", "body", Some("all"))));
    assert!(!reads.iter().any(|(_, m, _)| *m == "x"));
    assert!(!reads.iter().any(|(_, m, _)| *m == "svc"));
}

#[test]
fn js_property_reads_stay_out_of_the_call_graph_and_observed_calls() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        "function h(req) {\n  const id = req.query;\n  go(id);\n}\n",
    );
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], true, None, None).unwrap();
    assert_eq!(
        idx.call_edges,
        vec![("h".to_string(), String::new(), "go".to_string())]
    );
    assert_eq!(idx.observed_calls.len(), 1);
    assert_eq!(idx.observed_calls[0].method, "go");
}

#[test]
fn cs_property_reads_are_call_sites_bound_through_an_indexer() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "A.cs",
        "class A {\n  void M() {\n    var q = Request.Query[\"id\"];\n    var b = Request.Body;\n    Log.Level = 1;\n    Helper.Run(q);\n  }\n}\n",
    );
    let idx = scan_file(&path, "A.cs", "csharp", &[], &[], true, None, None).unwrap();
    let reads: Vec<(&str, &str, Option<&str>)> = idx
        .call_args
        .iter()
        .map(|c| {
            (
                c.receiver.as_str(),
                c.callee_name.as_str(),
                c.target_symbol.as_deref(),
            )
        })
        .collect();
    assert!(reads.contains(&("Request", "Query", Some("q"))));
    assert!(reads.contains(&("Request", "Body", Some("b"))));
    assert!(!reads.iter().any(|(_, m, _)| *m == "Level"));
    assert_eq!(
        idx.call_edges,
        vec![("M".to_string(), "Helper".to_string(), "Run".to_string())]
    );
    assert_eq!(idx.observed_calls.len(), 1);
}

#[test]
fn a_property_read_can_be_a_source_but_never_a_sink() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        "function h(req) {\n  const q = req.query;\n}\n",
    );
    let source = MatchSpec {
        rule_id: "js.req-query".to_string(),
        role: "source".to_string(),
        languages: BTreeSet::from(["javascript".to_string()]),
        module_attr_module: "req".to_string(),
        module_attr_names: BTreeSet::from(["query".to_string()]),
        ..Default::default()
    };
    let sink = MatchSpec {
        rule_id: "js.any-query".to_string(),
        role: "sink".to_string(),
        languages: BTreeSet::from(["javascript".to_string()]),
        receiver_method_names: BTreeSet::from(["query".to_string()]),
        ..Default::default()
    };
    let idx = scan_file(
        &path,
        "app.js",
        "javascript",
        &[source],
        &[sink],
        false,
        None,
        None,
    )
    .unwrap();
    assert_eq!(idx.source_hits.len(), 1);
    assert_eq!(idx.source_hits[0].matched_rule, "js.req-query");
    assert!(idx.sink_hits.is_empty());
}

fn marker(marker_type: &str, name: &str, params: &[&str]) -> FrameworkMarkerFact {
    FrameworkMarkerFact {
        function_qnode: "handle".to_string(),
        line: 7,
        marker_type: marker_type.to_string(),
        marker_name: name.to_string(),
        parameter_names: params.iter().map(|p| (*p).to_string()).collect(),
        framework: "spring".to_string(),
        confidence: "high".to_string(),
    }
}

#[test]
fn a_binding_annotation_becomes_a_source_hit_and_a_call_arg_fact() {
    let (hits, facts) = framework_binding_sources(
        "A.java",
        &[marker("spring_annotation", "@RequestParam", &["name"])],
    );
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].file, "A.java");
    assert_eq!(hits[0].line, 7);
    assert_eq!(hits[0].method, "@RequestParam");
    assert_eq!(hits[0].containing_fn, "handle");
    assert_eq!(hits[0].role, "source");
    assert_eq!(hits[0].kind, "http");
    assert_eq!(hits[0].matched_rule, FRAMEWORK_BINDING_RULE);
    assert!(!hits[0].owasp_top10_2025.is_empty());
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].function_qnode, "handle");
    assert_eq!(facts[0].line, 7);
    assert_eq!(facts[0].callee_name, "@RequestParam");
    assert_eq!(facts[0].target_symbol, Some("name".to_string()));
}

#[test]
fn every_binding_marker_type_is_a_source_and_nothing_else_is() {
    let markers: Vec<FrameworkMarkerFact> = BINDING_MARKER_TYPES
        .iter()
        .map(|t| marker(t, "@Bind", &["p"]))
        .chain([
            marker("spring_route", "/x/{id}", &["id"]),
            marker("spring_implicit", "HttpServletRequest", &["request"]),
            marker("django_view", "request", &["request"]),
            marker("spring_annotation", "@RequestParam", &[]),
            marker("spring_annotation", "@RequestParam", &[""]),
        ])
        .collect();
    let (hits, facts) = framework_binding_sources("A.java", &markers);
    assert_eq!(hits.len(), BINDING_MARKER_TYPES.len() + 2);
    assert_eq!(facts.len(), BINDING_MARKER_TYPES.len());
}

#[test]
fn a_binding_that_names_two_parameters_taints_both() {
    let (hits, facts) = framework_binding_sources(
        "A.java",
        &[marker("jaxrs_annotation", "@BeanParam", &["a", "b"])],
    );
    assert_eq!(hits.len(), 1);
    assert_eq!(
        facts
            .iter()
            .map(|f| f.target_symbol.clone().unwrap())
            .collect::<Vec<_>>(),
        vec!["a".to_string(), "b".to_string()]
    );
}

#[test]
fn an_axum_extractor_parameter_is_a_source_and_state_is_not() {
    let f = |params: &[&str]| FuncDef {
        name: "handler".to_string(),
        start_line: 12,
        end_line: 20,
        class_name: String::new(),
        params: params.iter().map(|p| (*p).to_string()).collect(),
    };
    let (hits, facts) = extractor_binding_sources(
        "handlers.rs",
        &[f(&[
            "Query(params)",
            "Path(slug)",
            "Json(body)",
            "State(state)",
            "plain",
            "Query(",
            "Unknown(x)",
            "Query()",
        ])],
    );
    assert_eq!(
        hits.iter().map(|h| h.method.as_str()).collect::<Vec<_>>(),
        vec!["Query", "Path", "Json"]
    );
    assert_eq!(hits[0].file, "handlers.rs");
    assert_eq!(hits[0].line, 12);
    assert_eq!(hits[0].containing_fn, "handler");
    assert_eq!(hits[0].matched_rule, FRAMEWORK_BINDING_RULE);
    assert_eq!(
        facts
            .iter()
            .map(|c| c.target_symbol.clone().unwrap())
            .collect::<Vec<_>>(),
        vec!["params", "slug", "body"]
    );
}

#[test]
fn scan_file_reports_an_axum_extractor_parameter_as_a_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "h.rs",
        "pub async fn show(State(s): State<App>, Path(slug): Path<String>) -> R {\n    render(slug)\n}\n",
    );
    let idx = scan_file(&path, "h.rs", "rust", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.source_hits.len(), 1);
    assert_eq!(idx.source_hits[0].method, "Path");
    assert_eq!(idx.source_hits[0].containing_fn, "show");
}

#[test]
fn a_php_receiver_matches_a_rule_without_its_sigil() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "c.php",
        "<?php\nfunction h($request) { return $request->query('q'); }\n",
    );
    let spec = MatchSpec {
        rule_id: "php.request".to_string(),
        role: "source".to_string(),
        languages: BTreeSet::from(["php".to_string()]),
        module_attr_module: "request".to_string(),
        module_attr_names: BTreeSet::from(["query".to_string()]),
        ..Default::default()
    };
    let idx = scan_file(&path, "c.php", "php", &[spec], &[], false, None, None).unwrap();
    assert_eq!(idx.source_hits.len(), 1);
    assert_eq!(idx.source_hits[0].receiver, "$request");
}

#[test]
fn a_zero_argument_rule_skips_a_call_that_passes_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "A.java",
        "class C {\n  void m() {\n    st.executeQuery();\n    st.executeQuery(q);\n  }\n}\n",
    );
    let spec = MatchSpec {
        rule_id: "java.jdbc".to_string(),
        role: "sink".to_string(),
        languages: BTreeSet::from(["java".to_string()]),
        receiver_method_names: BTreeSet::from(["executeQuery".to_string()]),
        requires_any_arg: true,
        ..Default::default()
    };
    let idx = scan_file(&path, "A.java", "java", &[], &[spec], false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].line, 4);
}

#[test]
fn literal_only_symbols_reads_the_base_case_and_one_propagation_step() {
    let assign = |func: &str, dst: &str, sym: Option<&str>, call: Option<&str>| VarAssignFact {
        function_qnode: func.to_string(),
        line: 1,
        dst_symbol: dst.to_string(),
        src_symbol: sym.map(str::to_string),
        src_call: call.map(str::to_string),
    };
    let call = |func: &str, callee: &str, target: &str, args: &[&str]| CallArgFact {
        function_qnode: func.to_string(),
        line: 2,
        callee_name: callee.to_string(),
        receiver: String::new(),
        arg_symbols: args.iter().map(|a| (*a).to_string()).collect(),
        arg_slots: (0..args.len()).collect(),
        target_symbol: Some(target.to_string()),
    };
    let assigns = vec![
        assign("f", "sql", None, None),
        assign("f", "built", Some("user"), None),
        assign("f", "cmd", None, Some("SqlCommand")),
        assign("f", "bad", None, Some("SqlCommand")),
        assign("f", "empty", None, Some("SqlCommand")),
        assign("g", "sql", Some("user"), None),
    ];
    let calls = vec![
        call("f", "SqlCommand", "cmd", &["sql", "conn"]),
        call("f", "SqlCommand", "bad", &["built"]),
        call("f", "SqlCommand", "empty", &[]),
    ];
    let out = literal_only_symbols(&assigns, &calls);
    assert!(out.contains(&("f".to_string(), "sql".to_string())));
    assert!(out.contains(&("f".to_string(), "cmd".to_string())));
    assert!(!out.contains(&("f".to_string(), "built".to_string())));
    assert!(!out.contains(&("f".to_string(), "bad".to_string())));
    assert!(!out.contains(&("f".to_string(), "empty".to_string())));
    assert!(!out.contains(&("g".to_string(), "sql".to_string())));
}

#[test]
fn scan_file_reports_an_annotation_bound_parameter_as_a_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "A.java",
        "class C {\n  @GetMapping(\"/r\")\n  public byte[] r(@RequestParam(\"f\") String name) { return null; }\n}\n",
    );
    let idx = scan_file(&path, "A.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.source_hits.len(), 1);
    assert_eq!(idx.source_hits[0].matched_rule, FRAMEWORK_BINDING_RULE);
    let seeded = idx
        .call_args
        .iter()
        .find(|c| c.callee_name == "@RequestParam")
        .expect("no seeding fact for the bound parameter");
    assert_eq!(seeded.line, idx.source_hits[0].line);
    assert_eq!(seeded.target_symbol, Some("name".to_string()));
}

#[test]
fn composed_value_walk_stops_at_the_depth_cap() {
    let deep =
        "(".repeat(COMPOSED_VALUE_MAX_DEPTH + 2) + "a" + &")".repeat(COMPOSED_VALUE_MAX_DEPTH + 2);
    let body = format!("def f(a):\n    os.system({deep})\n");
    assert!(py_args(&body).is_empty());
}

fn bare_open_sink() -> MatchSpec {
    MatchSpec {
        rule_id: "py.open-file".to_string(),
        role: "sink".to_string(),
        origin: "semgrep".to_string(),
        cwe: "CWE-22".to_string(),
        kind: "path".to_string(),
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        semantic_family: "file-io".to_string(),
        bare_call_names: std::collections::BTreeSet::from(["open".to_string()]),
        ..Default::default()
    }
}

fn cursor_execute_sink(requires_dynamic_arg: bool) -> MatchSpec {
    MatchSpec {
        rule_id: "py.dbapi-cursor-execute".to_string(),
        role: "sink".to_string(),
        origin: "semgrep".to_string(),
        cwe: "CWE-89".to_string(),
        kind: "sql".to_string(),
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        semantic_family: "sql-exec".to_string(),
        receiver_method_names: std::collections::BTreeSet::from(["execute".to_string()]),
        requires_dynamic_arg,
        ..Default::default()
    }
}

#[test]
fn scan_file_matches_a_bare_call_sink() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "def f(p):\n    open(p)\n");
    let sinks = vec![bare_open_sink()];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].method, "open");
}

#[test]
fn scan_file_bare_call_sink_does_not_match_a_method_of_the_same_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "def f(p):\n    zipf.open(p)\n");
    let sinks = vec![bare_open_sink()];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert!(idx.sink_hits.is_empty());
}

#[test]
fn scan_file_matches_a_receiver_method_sink_on_any_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "def f(q):\n    cur.execute(q)\n");
    let sinks = vec![cursor_execute_sink(true)];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].receiver, "cur");
}

#[test]
fn scan_file_receiver_method_sink_needs_a_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "def f(q):\n    execute(q)\n");
    let sinks = vec![cursor_execute_sink(true)];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert!(idx.sink_hits.is_empty());
}

#[test]
fn scan_file_requires_dynamic_arg_skips_a_parameterized_query() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.py",
        "def f(p):\n    cur.execute(\"SELECT 1 WHERE a = ?\", (p,))\n    cur.execute(\"SELECT \" + p)\n",
    );
    let sinks = vec![cursor_execute_sink(true)];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].line, 3);
}

#[test]
fn scan_file_without_requires_dynamic_arg_a_static_query_still_matches() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.py",
        "def f(p):\n    cur.execute(\"SELECT 1 WHERE a = ?\", (p,))\n",
    );
    let sinks = vec![cursor_execute_sink(false)];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
}

fn alloc_size_sink(names: &[&str], arithmetic_arg_index: usize) -> MatchSpec {
    MatchSpec {
        rule_id: "c.alloc-size-overflow".to_string(),
        role: "sink".to_string(),
        origin: "semgrep".to_string(),
        cwe: "CWE-190".to_string(),
        kind: "memory".to_string(),
        languages: std::collections::BTreeSet::from(["c-cpp".to_string()]),
        semantic_family: "other".to_string(),
        bare_call_names: names.iter().map(|n| (*n).to_string()).collect(),
        requires_arithmetic_arg: true,
        arithmetic_arg_index,
        ..Default::default()
    }
}

#[test]
fn scan_file_requires_arithmetic_arg_matches_only_a_computed_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "a.c",
        "void f(size_t n, size_t m) {\n\
         \x20   a = malloc(len);\n\
         \x20   b = malloc(sizeof(struct hdr));\n\
         \x20   c = malloc(64);\n\
         \x20   d = malloc(n * m);\n\
         }\n",
    );
    let sinks = vec![alloc_size_sink(&["malloc"], 0)];
    let idx = scan_file(&path, "a.c", "c-cpp", &[], &sinks, false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].line, 5);
    assert_eq!(idx.sink_hits[0].cwe, "CWE-190");
}

#[test]
fn scan_file_requires_arithmetic_arg_reads_the_configured_index() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "a.c",
        "void f(size_t n, size_t m) {\n\
         \x20   p = realloc(p, n);\n\
         \x20   q = realloc(p, n * m);\n\
         }\n",
    );
    let idx = scan_file(
        &path,
        "a.c",
        "c-cpp",
        &[],
        &[alloc_size_sink(&["realloc"], 1)],
        false,
        None,
        None,
    )
    .unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].line, 3);
    let idx0 = scan_file(
        &path,
        "a.c",
        "c-cpp",
        &[],
        &[alloc_size_sink(&["realloc"], 0)],
        false,
        None,
        None,
    )
    .unwrap();
    assert!(idx0.sink_hits.is_empty());
}

#[test]
fn scan_file_requires_arithmetic_arg_goes_dark_where_shapes_are_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "def f(n, m):\n    open(n * m)\n");
    let sinks = vec![MatchSpec {
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        ..alloc_size_sink(&["open"], 0)
    }];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert!(idx.sink_hits.is_empty());
}

#[test]
fn scan_file_requires_arithmetic_arg_reaches_a_cpp_array_new() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "a.cpp",
        "void f(size_t n, size_t m) {\n\
         \x20   int *a = new int[n];\n\
         \x20   int *b = new int[n * m];\n\
         \x20   Foo *c = new Foo(n * m);\n\
         \x20   Foo *d = new Foo;\n\
         }\n",
    );
    let sinks = vec![alloc_size_sink(&["operator_new_array"], 0)];
    let idx = scan_file(&path, "a.cpp", "c-cpp", &[], &sinks, false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].line, 3);
    assert_eq!(idx.sink_hits[0].cwe, "CWE-190");
    assert_eq!(idx.sink_hits[0].method, "operator_new_array");
}

fn calloc_hand_multiplied_sink() -> MatchSpec {
    MatchSpec {
        rule_id: "c.calloc-hand-multiplied-size".to_string(),
        requires_unit_arg: true,
        unit_arg_index: 1,
        ..alloc_size_sink(&["calloc"], 0)
    }
}

#[test]
fn scan_file_two_argument_conjunction_matches_only_a_hand_multiplied_calloc() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "a.c",
        "void f(size_t n, size_t size, size_t len) {\n\
         \x20   a = calloc(n, size);\n\
         \x20   b = calloc(len + 1, sizeof(char));\n\
         \x20   c = calloc(1, sizeof(struct hdr));\n\
         \x20   d = calloc(n * size, size);\n\
         \x20   e = calloc(n, 1);\n\
         \x20   g = calloc(n * size, 1);\n\
         }\n",
    );
    let sinks = vec![calloc_hand_multiplied_sink()];
    let idx = scan_file(&path, "a.c", "c-cpp", &[], &sinks, false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].line, 7);
    assert_eq!(idx.sink_hits[0].cwe, "CWE-190");
}

#[test]
fn scan_file_dropping_either_half_of_the_conjunction_widens_the_rule() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "a.c",
        "void f(size_t n, size_t size, size_t len) {\n\
         \x20   a = calloc(len + 1, sizeof(char));\n\
         \x20   b = calloc(n, 1);\n\
         \x20   c = calloc(n * size, 1);\n\
         }\n",
    );
    let arithmetic_only = scan_file(
        &path,
        "a.c",
        "c-cpp",
        &[],
        &[alloc_size_sink(&["calloc"], 0)],
        false,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        arithmetic_only
            .sink_hits
            .iter()
            .map(|h| h.line)
            .collect::<Vec<_>>(),
        vec![2, 4]
    );
    let unit_only = scan_file(
        &path,
        "a.c",
        "c-cpp",
        &[],
        &[MatchSpec {
            requires_arithmetic_arg: false,
            ..calloc_hand_multiplied_sink()
        }],
        false,
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        unit_only
            .sink_hits
            .iter()
            .map(|h| h.line)
            .collect::<Vec<_>>(),
        vec![3, 4]
    );
}

#[test]
fn scan_file_requires_unit_arg_goes_dark_where_shapes_are_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "def f(n):\n    open(n, 1)\n");
    let sinks = vec![MatchSpec {
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        requires_arithmetic_arg: false,
        requires_unit_arg: true,
        unit_arg_index: 1,
        ..alloc_size_sink(&["open"], 0)
    }];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert!(idx.sink_hits.is_empty());
}

#[test]
fn build_spec_index_buckets_bare_call_and_receiver_method_names() {
    let specs = vec![bare_open_sink(), cursor_execute_sink(true)];
    let index = build_spec_index(&specs);
    let python = index.get("python").unwrap();
    assert_eq!(python.get("open").map(Vec::len), Some(1));
    assert_eq!(python.get("execute").map(Vec::len), Some(1));
    assert!(!python.contains_key("*"));
}

fn os_system_sink() -> MatchSpec {
    MatchSpec {
        rule_id: "py.os.system".to_string(),
        role: "sink".to_string(),
        origin: "semgrep".to_string(),
        cwe: "CWE-78".to_string(),
        kind: "command_injection".to_string(),
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        semantic_family: "command-exec".to_string(),
        owasp_top10_2025: std::collections::BTreeSet::from(["A03:2025-Injection".to_string()]),
        module_attr_module: "os".to_string(),
        module_attr_names: std::collections::BTreeSet::from(["system".to_string()]),
        ..Default::default()
    }
}

fn request_args_source() -> MatchSpec {
    MatchSpec {
        rule_id: "py.flask.request-args".to_string(),
        role: "source".to_string(),
        origin: "semgrep".to_string(),
        cwe: "CWE-20".to_string(),
        kind: "network".to_string(),
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        semantic_family: "other".to_string(),
        module_attr_module: "request".to_string(),
        module_attr_names: std::collections::BTreeSet::from(["get".to_string()]),
        ..Default::default()
    }
}

fn runtime_exec_sink_qualified() -> MatchSpec {
    MatchSpec {
        rule_id: "java.codeql.runtime-exec".to_string(),
        role: "sink".to_string(),
        origin: "codeql".to_string(),
        cwe: "CWE-78".to_string(),
        kind: "cmd".to_string(),
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        package: "subprocess".to_string(),
        class_name: "Popen".to_string(),
        top_class: "Popen".to_string(),
        methods: std::collections::BTreeSet::from(["communicate".to_string()]),
        ..Default::default()
    }
}

#[test]
fn supported_languages_lists_every_wired_language() {
    assert_eq!(
        supported_languages(),
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
            "c-cpp"
        ]
    );
}

#[test]
fn scan_file_returns_none_for_an_unsupported_language() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "a.swift", "func main() {}\n");
    assert!(scan_file(&path, "a.swift", "swift", &[], &[], false, None, None).is_none());
}

#[test]
fn scan_file_returns_none_for_a_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("does-not-exist.py");
    assert!(scan_file(
        &path,
        "does-not-exist.py",
        "python",
        &[],
        &[],
        false,
        None,
        None
    )
    .is_none());
}

#[test]
fn scan_file_returns_none_for_an_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "empty.py", "");
    assert!(scan_file(&path, "empty.py", "python", &[], &[], false, None, None).is_none());
}

#[test]
fn scan_file_extracts_imports_functions_and_calls() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.py",
        "import os\nfrom foo import bar as baz\n\ndef handler(req):\n    os.system(req)\n",
    );
    let sinks = vec![os_system_sink()];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert_eq!(idx.file, "app.py");
    assert_eq!(idx.language, "python");
    assert_eq!(idx.imports.get("os"), Some(&"os".to_string()));
    assert_eq!(idx.imports.get("baz"), Some(&"foo.bar".to_string()));
    assert_eq!(idx.functions.len(), 1);
    assert_eq!(idx.functions[0].name, "handler");
    assert_eq!(idx.call_edges.len(), 1);
    assert_eq!(
        idx.call_edges[0],
        (
            "handler".to_string(),
            "os".to_string(),
            "system".to_string()
        )
    );
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].matched_rule, "py.os.system");
    assert_eq!(idx.sink_hits[0].role, "sink");
    assert_eq!(idx.sink_hits[0].containing_fn, "handler");
    assert!(idx.source_hits.is_empty());
}

#[test]
fn scan_file_matches_a_module_attr_source() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "import flask\nrequest.get('x')\n");
    let sources = vec![request_args_source()];
    let idx = scan_file(&path, "app.py", "python", &sources, &[], false, None, None).unwrap();
    assert_eq!(idx.source_hits.len(), 1);
    assert_eq!(idx.source_hits[0].role, "source");
    assert_eq!(idx.source_hits[0].matched_rule, "py.flask.request-args");
}

#[test]
fn scan_file_matches_a_module_attr_sink_via_the_resolved_import_not_the_raw_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.py",
        "import subprocess as sp\nsp.check_call(cmd)\n",
    );
    let sinks = vec![MatchSpec {
        rule_id: "py.subprocess.check_call".to_string(),
        role: "sink".to_string(),
        origin: "semgrep".to_string(),
        cwe: "CWE-78".to_string(),
        kind: "command_injection".to_string(),
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        semantic_family: "command-exec".to_string(),
        module_attr_module: "subprocess".to_string(),
        module_attr_names: std::collections::BTreeSet::from(["check_call".to_string()]),
        ..Default::default()
    }];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].matched_rule, "py.subprocess.check_call");
}

#[test]
fn scan_file_matches_a_qualified_import_resolved_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.py",
        "import subprocess\nsubprocess.communicate()\n",
    );
    let sinks = vec![runtime_exec_sink_qualified()];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].matched_rule, "java.codeql.runtime-exec");
}

#[test]
fn scan_file_a_call_can_be_both_a_source_and_a_sink() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "os.system(x)\n");
    let sources = vec![MatchSpec {
        module_attr_module: "os".to_string(),
        module_attr_names: std::collections::BTreeSet::from(["system".to_string()]),
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        role: "source".to_string(),
        rule_id: "src".to_string(),
        ..Default::default()
    }];
    let sinks = vec![os_system_sink()];
    let idx = scan_file(
        &path, "app.py", "python", &sources, &sinks, false, None, None,
    )
    .unwrap();
    assert_eq!(idx.source_hits.len(), 1);
    assert_eq!(idx.sink_hits.len(), 1);
}

#[test]
fn scan_file_falls_back_to_the_semantic_sink_override() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "render_template(x)\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].matched_rule, "vvah.semantic.sink");
    assert_eq!(idx.sink_hits[0].cwe, "CWE-79");
}

#[test]
fn scan_file_semantic_override_html_response_via_braces() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "response(f'<html>{x}</html>')\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].semantic_family, "html-response");
}

#[test]
fn scan_file_no_semantic_override_when_response_has_no_html_markers() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "response(x)\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert!(idx.sink_hits.is_empty());
}

#[test]
fn scan_file_collects_observed_calls_when_requested() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "import os\nos.system(x)\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], true, None, None).unwrap();
    assert_eq!(idx.observed_calls.len(), 1);
    assert_eq!(idx.observed_calls[0].resolved_receiver, "os");
    assert_eq!(idx.observed_calls[0].method, "system");
}

#[test]
fn scan_file_does_not_collect_observed_calls_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "os.system(x)\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert!(idx.observed_calls.is_empty());
}

#[test]
fn scan_file_uses_a_prebuilt_spec_index_when_given() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "os.system(x)\n");
    let sinks = vec![os_system_sink()];
    let sink_index = build_spec_index(&sinks);
    let idx = scan_file(
        &path,
        "app.py",
        "python",
        &[],
        &sinks,
        false,
        None,
        Some(&sink_index),
    )
    .unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
}

#[test]
fn scan_file_populates_assigns_returns_and_call_args() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.py",
        "def f(a):\n    x = a\n    y = os.system(a)\n    return x\n",
    );
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.assigns.len(), 2);
    assert_eq!(idx.assigns[0].dst_symbol, "x");
    assert_eq!(idx.assigns[0].src_symbol, Some("a".to_string()));
    assert_eq!(idx.assigns[1].dst_symbol, "y");
    assert_eq!(idx.assigns[1].src_call, Some("system".to_string()));
    assert_eq!(idx.returns.len(), 1);
    assert_eq!(idx.returns[0].symbol, Some("x".to_string()));
    assert_eq!(idx.call_args.len(), 1);
    assert_eq!(idx.call_args[0].callee_name, "system");
    assert_eq!(idx.call_args[0].arg_symbols, vec!["a".to_string()]);
}

#[test]
fn an_rhs_that_is_neither_a_symbol_nor_a_call_records_a_literal_only_assignment() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "z = 5\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.assigns.len(), 1);
    assert_eq!(idx.assigns[0].dst_symbol, "z");
    assert_eq!(idx.assigns[0].src_symbol, None);
    assert_eq!(idx.assigns[0].src_call, None);
}

#[test]
fn scan_file_no_assign_fact_when_the_lhs_is_not_a_bare_identifier() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "obj.attr = x\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert!(idx.assigns.is_empty());
}

#[test]
fn scan_file_captures_keyword_argument_identifier_values() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "foo(bar, baz=qux)\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(
        idx.call_args[0].arg_symbols,
        vec!["bar".to_string(), "qux".to_string()]
    );
}

#[test]
fn scan_file_ignores_a_keyword_argument_with_a_non_identifier_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "foo(baz=5)\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert!(idx.call_args[0].arg_symbols.is_empty());
}

#[test]
fn py_identifier_args_empty_when_the_node_has_no_arguments_field() {
    let src = b"x = 1\n";
    let tree = parse(src);
    let ident = find_kind(tree.root_node(), "identifier").unwrap();
    assert!(py_identifier_args(ident, src).0.is_empty());
}

#[test]
fn py_return_symbols_reads_a_direct_value_field_when_present() {
    let src = b"foo(baz=qux)\n";
    let tree = parse(src);
    let kwarg = find_kind(tree.root_node(), "keyword_argument").unwrap();
    assert_eq!(py_return_symbols(kwarg, src), vec!["qux".to_string()]);
}

#[test]
fn scan_file_records_the_assignment_target_symbol_for_a_call() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "result = os.system(x)\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.call_args[0].target_symbol, Some("result".to_string()));
}

#[test]
fn scan_file_no_assignment_target_when_the_call_is_not_assigned() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "os.system(x)\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.call_args[0].target_symbol, None);
}

#[test]
fn scan_file_no_assignment_target_when_the_call_is_assigned_to_a_non_identifier() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "obj.attr = foo()\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.call_args[0].target_symbol, None);
}

#[test]
fn scan_file_return_with_no_identifier_has_no_symbol() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "def f():\n    return 1 + 2\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.returns[0].symbol, None);
}

#[test]
fn scan_file_bare_return_has_no_symbol() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "def f():\n    return\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.returns[0].symbol, None);
}

#[test]
fn scan_file_module_level_call_has_no_containing_fn() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "os.system(x)\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.call_edges[0].0, "");
}

#[test]
fn scan_file_bare_function_call_has_empty_receiver() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "eval(x)\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.call_edges[0].1, "");
    assert_eq!(idx.call_edges[0].2, "eval");
}

#[test]
fn scan_file_constructor_match_requires_the_import_to_start_with_the_package() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.py",
        "from javax.xml.parsers import DocumentBuilderFactory\nDocumentBuilderFactory()\n",
    );
    let sinks = vec![MatchSpec {
        rule_id: "ctor".to_string(),
        role: "sink".to_string(),
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        package: "javax.xml.parsers".to_string(),
        class_name: "DocumentBuilderFactory".to_string(),
        top_class: "DocumentBuilderFactory".to_string(),
        methods: std::collections::BTreeSet::from(["DocumentBuilderFactory".to_string()]),
        is_constructor: true,
        ..Default::default()
    }];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert_eq!(idx.sink_hits.len(), 1);
}

#[test]
fn scan_file_no_match_when_receiver_import_is_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "unknown.system(x)\n");
    let sinks = vec![runtime_exec_sink_qualified()];
    let idx = scan_file(&path, "app.py", "python", &[], &sinks, false, None, None).unwrap();
    assert!(idx.sink_hits.is_empty());
}

#[test]
fn build_spec_index_falls_back_to_wildcard_buckets() {
    let spec = MatchSpec {
        rule_id: "r1".to_string(),
        role: "sink".to_string(),
        package: "os".to_string(),
        class_name: "System".to_string(),
        top_class: "System".to_string(),
        methods: std::collections::BTreeSet::new(),
        module_attr_module: String::new(),
        module_attr_names: std::collections::BTreeSet::new(),
        languages: std::collections::BTreeSet::new(),
        ..Default::default()
    };
    let idx = build_spec_index(std::slice::from_ref(&spec));
    assert!(idx.contains_key("*"));
    assert!(idx["*"].contains_key("*"));
}

#[test]
fn build_spec_index_uses_the_methods_set_when_present() {
    let spec = qualified_spec("java.lang", "Runtime", "exec", false);
    let idx = build_spec_index(std::slice::from_ref(&spec));
    assert!(idx["python"].contains_key("exec"));
    assert!(idx["java"].contains_key("exec"));
}

#[test]
fn semantic_sink_override_java_response_write() {
    let got = semantic_sink_override("java", "response", "write", "response.write(\"<b>\" + x)");
    assert!(got.is_some());
    assert_eq!(got.unwrap().cwe, "CWE-79");
}

#[test]
fn semantic_sink_override_java_matches_via_httpservletresponse_snippet_text() {
    let got = semantic_sink_override(
        "java",
        "resp",
        "println",
        "((HttpServletResponse) resp).println(\"<b>\" + x)",
    );
    assert!(got.is_some());
}

#[test]
fn semantic_sink_override_java_no_match_without_html_markers() {
    assert!(semantic_sink_override("java", "response", "write", "response.write(x)").is_none());
}

#[test]
fn semantic_sink_override_none_for_an_unhandled_language() {
    assert!(semantic_sink_override("go", "w", "write", "w.write(x)").is_none());
}

#[test]
fn semantic_sink_override_python_render_template_without_html_markers_still_matches() {
    let got = semantic_sink_override("python", "", "render_template", "render_template(x)");
    assert!(got.is_some());
}

#[test]
fn extract_none_for_an_unsupported_language() {
    let tree = parse(b"x = 1\n");
    assert!(extract("swift", b"x = 1\n", tree.root_node()).is_none());
}

#[test]
fn ts_language_none_for_an_unsupported_language() {
    assert!(ts_language("swift").is_none());
}

#[test]
fn scan_file_bare_import_with_an_alias() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.py", "import os as o\no.system(x)\n");
    let idx = scan_file(&path, "app.py", "python", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.imports.get("o"), Some(&"os".to_string()));
}

#[test]
fn py_call_parts_empty_when_the_node_has_no_function_field() {
    let src = b"x = 1\n";
    let tree = parse(src);
    let ident = find_kind(tree.root_node(), "identifier").unwrap();
    assert_eq!(py_call_parts(ident, src), (String::new(), String::new()));
}

#[test]
fn py_call_parts_empty_for_an_unrecognized_function_node_kind() {
    let src = b"()()\n";
    let tree = parse(src);
    let call = find_kind(tree.root_node(), "call").unwrap();
    assert_eq!(py_call_parts(call, src), (String::new(), String::new()));
}

#[test]
fn py_leftmost_identifier_empty_when_walking_through_a_childless_token() {
    let src = b"(x).foo\n";
    let tree = parse(src);
    let attr = find_kind(tree.root_node(), "attribute").unwrap();
    assert_eq!(py_leftmost_identifier(attr, src), "");
}

fn qualified_spec(package: &str, class_name: &str, method: &str, is_ctor: bool) -> MatchSpec {
    MatchSpec {
        rule_id: "q".to_string(),
        role: "sink".to_string(),
        languages: std::collections::BTreeSet::from(["python".to_string(), "java".to_string()]),
        package: package.to_string(),
        class_name: class_name.to_string(),
        top_class: class_name.split('.').next().unwrap_or("").to_string(),
        methods: std::collections::BTreeSet::from([method.to_string()]),
        is_constructor: is_ctor,
        ..Default::default()
    }
}

#[test]
fn match_call_skips_a_spec_for_a_different_language() {
    let spec = qualified_spec("os", "System", "exec", false);
    let other_lang_spec = MatchSpec {
        languages: std::collections::BTreeSet::from(["go".to_string()]),
        ..spec.clone()
    };
    let imports = BTreeMap::from([("os".to_string(), "os".to_string())]);
    let specs: Vec<&MatchSpec> = vec![&other_lang_spec, &spec];
    assert!(match_call(
        "os",
        "exec",
        &imports,
        &specs,
        "python",
        &[],
        &[],
        &[],
        None
    )
    .is_some());
}

#[test]
fn match_call_constructor_does_not_match_a_non_empty_receiver() {
    let spec = qualified_spec("os", "System", "System", true);
    let imports = BTreeMap::from([("System".to_string(), "os.System".to_string())]);
    let specs = vec![&spec];
    assert!(match_call(
        "x",
        "System",
        &imports,
        &specs,
        "python",
        &[],
        &[],
        &[],
        None
    )
    .is_none());
}

#[test]
fn match_call_constructor_does_not_match_when_the_import_does_not_start_with_the_package() {
    let spec = qualified_spec("os", "System", "System", true);
    let imports = BTreeMap::from([("System".to_string(), "somewhere.else.System".to_string())]);
    let specs = vec![&spec];
    assert!(match_call(
        "",
        "System",
        &imports,
        &specs,
        "python",
        &[],
        &[],
        &[],
        None
    )
    .is_none());
}

#[test]
fn match_call_qualified_no_match_when_receiver_is_unresolved() {
    let spec = qualified_spec("os", "System", "exec", false);
    let specs = vec![&spec];
    assert!(match_call(
        "os",
        "exec",
        &BTreeMap::new(),
        &specs,
        "python",
        &[],
        &[],
        &[],
        None
    )
    .is_none());
}

#[test]
fn match_call_java_class_tail_recall_guard_matches_a_narrowed_import() {
    let spec = qualified_spec("java.lang", "Runtime", "exec", false);
    let imports = BTreeMap::from([("rt".to_string(), "Runtime".to_string())]);
    let specs = vec![&spec];
    assert!(match_call("rt", "exec", &imports, &specs, "java", &[], &[], &[], None).is_some());
}

#[test]
fn match_call_java_class_tail_recall_guard_matches_a_dotted_suffix() {
    let spec = qualified_spec("java.lang", "Runtime", "exec", false);
    let imports = BTreeMap::from([("rt".to_string(), "com.acme.Runtime".to_string())]);
    let specs = vec![&spec];
    assert!(match_call("rt", "exec", &imports, &specs, "java", &[], &[], &[], None).is_some());
}

#[test]
fn match_call_class_tail_recall_guard_is_not_applied_outside_jvm_languages() {
    let spec = qualified_spec("java.lang", "Runtime", "exec", false);
    let imports = BTreeMap::from([("rt".to_string(), "Runtime".to_string())]);
    let specs = vec![&spec];
    assert!(match_call(
        "rt",
        "exec",
        &imports,
        &specs,
        "python",
        &[],
        &[],
        &[],
        None
    )
    .is_none());
}

#[test]
fn match_call_qualified_falls_through_to_no_match_when_nothing_lines_up() {
    let spec = qualified_spec("java.lang", "Runtime", "exec", false);
    let imports = BTreeMap::from([("rt".to_string(), "completely.unrelated.Thing".to_string())]);
    let specs = vec![&spec];
    assert!(match_call("rt", "exec", &imports, &specs, "java", &[], &[], &[], None).is_none());
}

#[test]
fn match_call_module_attr_skips_a_spec_with_a_different_method() {
    let spec = MatchSpec {
        module_attr_module: "os".to_string(),
        module_attr_names: std::collections::BTreeSet::from(["system".to_string()]),
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        ..Default::default()
    };
    let specs = vec![&spec];
    assert!(match_call(
        "os",
        "popen",
        &BTreeMap::new(),
        &specs,
        "python",
        &[],
        &[],
        &[],
        None
    )
    .is_none());
}

#[test]
fn match_call_module_attr_matches_via_resolved_prefix() {
    let spec = MatchSpec {
        module_attr_module: "os".to_string(),
        module_attr_names: std::collections::BTreeSet::from(["system".to_string()]),
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        ..Default::default()
    };
    let imports = BTreeMap::from([("o".to_string(), "os.path".to_string())]);
    let specs = vec![&spec];
    assert!(match_call(
        "o",
        "system",
        &imports,
        &specs,
        "python",
        &[],
        &[],
        &[],
        None
    )
    .is_some());
}

#[test]
fn match_call_module_attr_matches_via_resolved_suffix() {
    let spec = MatchSpec {
        module_attr_module: "os".to_string(),
        module_attr_names: std::collections::BTreeSet::from(["system".to_string()]),
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        ..Default::default()
    };
    let imports = BTreeMap::from([("o".to_string(), "compat.os".to_string())]);
    let specs = vec![&spec];
    assert!(match_call(
        "o",
        "system",
        &imports,
        &specs,
        "python",
        &[],
        &[],
        &[],
        None
    )
    .is_some());
}

#[test]
fn specs_for_falls_back_to_the_raw_list_without_an_index() {
    let spec = os_system_sink();
    let fallback = vec![&spec];
    let got = specs_for(None, &fallback, "python", "system");
    assert_eq!(got.len(), 1);
}

#[test]
fn specs_for_collects_the_wildcard_method_bucket_alongside_a_named_match() {
    let named = os_system_sink();
    let wildcard = MatchSpec {
        rule_id: "wild".to_string(),
        languages: std::collections::BTreeSet::from(["python".to_string()]),
        ..Default::default()
    };
    let specs = [named.clone(), wildcard.clone()];
    let index = build_spec_index(&specs);
    let got = specs_for(Some(&index), &[], "python", "system");
    let ids: std::collections::BTreeSet<&str> = got.iter().map(|s| s.rule_id.as_str()).collect();
    assert!(ids.contains("py.os.system"));
    assert!(ids.contains("wild"));
}

fn js_exec_sink() -> MatchSpec {
    MatchSpec {
        rule_id: "js.child_process.exec".to_string(),
        role: "sink".to_string(),
        origin: "semgrep".to_string(),
        cwe: "CWE-78".to_string(),
        kind: "command_injection".to_string(),
        languages: std::collections::BTreeSet::from(["javascript".to_string()]),
        semantic_family: "command-exec".to_string(),
        module_attr_module: "cp".to_string(),
        module_attr_names: std::collections::BTreeSet::from(["exec".to_string()]),
        ..Default::default()
    }
}

#[test]
fn js_extract_es_import_named_and_namespace_and_aliased() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        "import fs from 'fs';\nimport { readFile as rf } from 'fs-extra';\nimport * as cp from 'child_process';\n",
    );
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.imports.get("fs"), Some(&"fs".to_string()));
    assert_eq!(
        idx.imports.get("rf"),
        Some(&"fs-extra.readFile".to_string())
    );
    assert_eq!(idx.imports.get("cp"), Some(&"child_process".to_string()));
}

#[test]
fn js_extract_commonjs_require() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        "const cp = require('child_process');\n",
    );
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.imports.get("cp"), Some(&"child_process".to_string()));
}

#[test]
fn js_extract_function_declaration_and_method_in_class() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        "function handler(req) {}\nclass Server {\n  listen() {}\n}\n",
    );
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.functions.len(), 2);
    let handler = idx.functions.iter().find(|f| f.name == "handler").unwrap();
    assert_eq!(handler.class_name, "");
    let listen = idx.functions.iter().find(|f| f.name == "listen").unwrap();
    assert_eq!(listen.class_name, "Server");
}

#[test]
fn js_extract_member_call_and_bare_call() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        "function handler(cmd) {\n  cp.exec(cmd);\n  doThing();\n}\n",
    );
    let sinks = vec![js_exec_sink()];
    let idx = scan_file(
        &path,
        "app.js",
        "javascript",
        &[],
        &sinks,
        false,
        None,
        None,
    )
    .unwrap();
    assert_eq!(idx.call_edges.len(), 2);
    assert!(idx.call_edges.contains(&(
        "handler".to_string(),
        "cp".to_string(),
        "exec".to_string()
    )));
    assert!(idx.call_edges.contains(&(
        "handler".to_string(),
        String::new(),
        "doThing".to_string()
    )));
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].matched_rule, "js.child_process.exec");
}

#[test]
fn js_extract_assigns_returns_and_call_args_are_populated_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        "function f(x) {\n  const y = x;\n  run(y);\n  return y;\n}\n",
    );
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.functions[0].params, vec!["x".to_string()]);
    assert_eq!(idx.assigns.len(), 1);
    assert_eq!(idx.assigns[0].dst_symbol, "y");
    assert_eq!(idx.assigns[0].src_symbol, Some("x".to_string()));
    assert_eq!(idx.assigns[0].function_qnode, "f");
    assert_eq!(idx.returns.len(), 1);
    assert_eq!(idx.returns[0].symbol, Some("y".to_string()));
    assert_eq!(idx.call_args.len(), 1);
    assert_eq!(idx.call_args[0].callee_name, "run");
    assert_eq!(idx.call_args[0].arg_symbols, vec!["y".to_string()]);
    assert_eq!(idx.call_args[0].arg_slots, vec![0]);
}

#[test]
fn js_leftmost_identifier_walks_a_chained_member_call() {
    let tree = {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        parser.parse(b"a.b.c();", None).unwrap()
    };
    let call = find_kind(tree.root_node(), "call_expression").unwrap();
    let fn_node = call.child_by_field_name("function").unwrap();
    assert_eq!(js_leftmost_identifier(fn_node, b"a.b.c();"), "a");
}

#[test]
fn js_leftmost_identifier_walks_through_a_call_expression_object() {
    let src: &[u8] = b"getFoo().bar();";
    let tree = {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        parser.parse(src, None).unwrap()
    };
    let call = find_kind(tree.root_node(), "call_expression").unwrap();
    let fn_node = call.child_by_field_name("function").unwrap();
    assert_eq!(js_leftmost_identifier(fn_node, src), "getFoo");
}

#[test]
fn js_leftmost_identifier_wildcard_arm_walks_then_dead_ends() {
    let src: &[u8] = b"(a || b).c();";
    let tree = {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .unwrap();
        parser.parse(src, None).unwrap()
    };
    let call = find_kind(tree.root_node(), "call_expression").unwrap();
    let fn_node = call.child_by_field_name("function").unwrap();
    assert_eq!(js_leftmost_identifier(fn_node, src), "");
}

#[test]
fn js_extract_ignores_a_call_whose_function_is_neither_member_nor_identifier() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.js", "(a || b)();\n");
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    assert!(idx.call_edges.is_empty());
}

#[test]
fn js_extract_mixed_default_and_named_import() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.js",
        "import Default, { named } from 'x';\n",
    );
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.imports.get("Default"), Some(&"x".to_string()));
    assert_eq!(idx.imports.get("named"), Some(&"x.named".to_string()));
}

#[test]
fn js_extract_named_import_with_an_empty_source_string() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "app.js", "import { x } from '';\n");
    let idx = scan_file(&path, "app.js", "javascript", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.imports.get("x"), Some(&"x".to_string()));
}

#[test]
fn typescript_uses_the_same_extractor_as_javascript() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "app.ts",
        "function handler(cmd: string) {\n  cp.exec(cmd);\n}\n",
    );
    let sinks = vec![MatchSpec {
        languages: std::collections::BTreeSet::from(["typescript".to_string()]),
        ..js_exec_sink()
    }];
    let idx = scan_file(
        &path,
        "app.ts",
        "typescript",
        &[],
        &sinks,
        false,
        None,
        None,
    )
    .unwrap();
    assert_eq!(idx.language, "typescript");
    assert_eq!(idx.sink_hits.len(), 1);
}

#[test]
fn a_tsx_component_is_parsed_with_the_tsx_grammar_under_the_typescript_label() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "Form.tsx",
        "export const Form = () => {\n\
           const banner = <div className=\"x\">hi</div>;\n\
           const onSubmit = (cmd: string) => { cp.exec(cmd); };\n\
           return <form onSubmit={onSubmit}>{banner}</form>;\n\
         };\n",
    );
    let sinks = vec![MatchSpec {
        languages: std::collections::BTreeSet::from(["typescript".to_string()]),
        ..js_exec_sink()
    }];
    let idx = scan_file(
        &path,
        "Form.tsx",
        "typescript",
        &[],
        &sinks,
        false,
        None,
        None,
    )
    .unwrap();
    assert_eq!(idx.language, "typescript");
    let names: Vec<&str> = idx.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(
        names.contains(&"Form") && names.contains(&"onSubmit"),
        "{names:?}"
    );
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].containing_fn, "onSubmit");
}

#[test]
fn a_jsx_component_still_parses_with_the_javascript_grammar() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "Form.jsx",
        "export const Form = () => {\n\
           const onSubmit = (cmd) => { cp.exec(cmd); };\n\
           return <form onSubmit={onSubmit}><div className=\"x\">hi</div></form>;\n\
         };\n",
    );
    let sinks = vec![js_exec_sink()];
    let idx = scan_file(
        &path,
        "Form.jsx",
        "javascript",
        &[],
        &sinks,
        false,
        None,
        None,
    )
    .unwrap();
    assert_eq!(idx.language, "javascript");
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].containing_fn, "onSubmit");
}

#[test]
fn normalize_lang_for_grammar_rewrites_only_typescript_under_a_tsx_suffix() {
    assert_eq!(
        normalize_lang_for_grammar("src/Form.tsx", "typescript"),
        "tsx"
    );
    assert_eq!(normalize_lang_for_grammar("FORM.TSX", "typescript"), "tsx");
    assert_eq!(
        normalize_lang_for_grammar("src/api.ts", "typescript"),
        "typescript"
    );
    assert_eq!(
        normalize_lang_for_grammar("src/api.mts", "typescript"),
        "typescript"
    );
    assert_eq!(
        normalize_lang_for_grammar("Form.jsx", "javascript"),
        "javascript"
    );
    assert_eq!(
        normalize_lang_for_grammar("Form.tsx", "javascript"),
        "javascript"
    );
}

#[test]
fn tsx_is_a_grammar_key_not_a_language() {
    assert!(ts_language("tsx").is_some());
    assert!(!supported_languages().contains(&"tsx"));
    let tree = parse(b"x = 1\n");
    assert!(extract("tsx", b"x = 1\n", tree.root_node()).is_none());
}

fn go_exec_sink() -> MatchSpec {
    MatchSpec {
        rule_id: "go.os_exec.command".to_string(),
        role: "sink".to_string(),
        origin: "semgrep".to_string(),
        cwe: "CWE-78".to_string(),
        kind: "command_injection".to_string(),
        languages: std::collections::BTreeSet::from(["go".to_string()]),
        semantic_family: "command-exec".to_string(),
        module_attr_module: "exec".to_string(),
        module_attr_names: std::collections::BTreeSet::from(["Command".to_string()]),
        ..Default::default()
    }
}

#[test]
fn go_extract_single_import_spec_and_group() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        "package main\nimport \"fmt\"\nimport (\n\t\"os/exec\"\n\tosx \"os\"\n)\nfunc main() {}\n",
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.imports.get("fmt"), Some(&"fmt".to_string()));
    assert_eq!(idx.imports.get("exec"), Some(&"os/exec".to_string()));
    assert_eq!(idx.imports.get("osx"), Some(&"os".to_string()));
}

#[test]
fn go_extract_blank_and_dot_import_aliases_are_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        "package main\nimport (\n\t_ \"os\"\n\t. \"fmt\"\n)\nfunc main() {}\n",
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    assert!(idx.imports.is_empty());
}

#[test]
fn go_extract_function_and_method_declaration() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        "package main\ntype T struct{}\nfunc main() {}\nfunc (t T) Run() {}\n",
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.functions.len(), 2);
    assert!(idx.functions.iter().any(|f| f.name == "main"));
    assert!(idx.functions.iter().any(|f| f.name == "Run"));
}

#[test]
fn go_extract_selector_call_and_bare_call() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        "package main\nimport \"os/exec\"\nfunc run(cmd string) {\n\texec.Command(cmd)\n\tdoThing()\n}\n",
    );
    let sinks = vec![go_exec_sink()];
    let idx = scan_file(&path, "main.go", "go", &[], &sinks, false, None, None).unwrap();
    assert_eq!(idx.call_edges.len(), 2);
    assert!(idx.call_edges.contains(&(
        "run".to_string(),
        "exec".to_string(),
        "Command".to_string()
    )));
    assert!(idx
        .call_edges
        .contains(&("run".to_string(), String::new(), "doThing".to_string())));
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].matched_rule, "go.os_exec.command");
}

#[test]
fn go_extract_assigns_returns_and_call_args_are_populated_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        "package main\nfunc f(x string) string {\n\ty := x\n\trun(y)\n\treturn y\n}\n",
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.functions[0].params, vec!["x".to_string()]);
    assert_eq!(idx.assigns.len(), 1);
    assert_eq!(idx.assigns[0].dst_symbol, "y");
    assert_eq!(idx.assigns[0].src_symbol, Some("x".to_string()));
    assert_eq!(idx.assigns[0].function_qnode, "f");
    assert_eq!(idx.returns.len(), 1);
    assert_eq!(idx.returns[0].symbol, Some("y".to_string()));
    assert_eq!(idx.call_args.len(), 1);
    assert_eq!(idx.call_args[0].callee_name, "run");
    assert_eq!(idx.call_args[0].arg_symbols, vec!["y".to_string()]);
    assert_eq!(idx.call_args[0].arg_slots, vec![0]);
}

#[test]
fn go_leftmost_identifier_walks_a_chained_selector_call() {
    let tree = {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .unwrap();
        parser
            .parse(b"package main\nfunc f() { a.b.c() }\n", None)
            .unwrap()
    };
    let call = find_kind(tree.root_node(), "call_expression").unwrap();
    let fn_node = call.child_by_field_name("function").unwrap();
    assert_eq!(
        go_leftmost_identifier(fn_node, b"package main\nfunc f() { a.b.c() }\n"),
        "a"
    );
}

#[test]
fn go_leftmost_identifier_walks_through_a_call_expression_operand() {
    let src: &[u8] = b"package main\nfunc f() { getFoo().Bar() }\n";
    let tree = {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .unwrap();
        parser.parse(src, None).unwrap()
    };
    let call = find_kind(tree.root_node(), "call_expression").unwrap();
    let fn_node = call.child_by_field_name("function").unwrap();
    assert_eq!(go_leftmost_identifier(fn_node, src), "getFoo");
}

#[test]
fn go_leftmost_identifier_wildcard_arm_walks_then_dead_ends() {
    let src: &[u8] = b"package main\nfunc f() { (x).Foo() }\n";
    let tree = {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .unwrap();
        parser.parse(src, None).unwrap()
    };
    let call = find_kind(tree.root_node(), "call_expression").unwrap();
    let fn_node = call.child_by_field_name("function").unwrap();
    assert_eq!(go_leftmost_identifier(fn_node, src), "");
}

#[test]
fn go_extract_ignores_a_call_whose_function_is_neither_selector_nor_identifier() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "main.go",
        "package main\nvar fn func()\nfunc f() {\n\t(fn)()\n}\n",
    );
    let idx = scan_file(&path, "main.go", "go", &[], &[], false, None, None).unwrap();
    assert!(idx.call_edges.is_empty());
}

fn java_exec_sink() -> MatchSpec {
    MatchSpec {
        rule_id: "java.runtime.exec".to_string(),
        role: "sink".to_string(),
        origin: "semgrep".to_string(),
        cwe: "CWE-78".to_string(),
        kind: "command_injection".to_string(),
        languages: std::collections::BTreeSet::from(["java".to_string()]),
        semantic_family: "command-exec".to_string(),
        module_attr_module: "rt".to_string(),
        module_attr_names: std::collections::BTreeSet::from(["exec".to_string()]),
        ..Default::default()
    }
}

fn parse_java(src: &[u8]) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_java::LANGUAGE.into())
        .unwrap();
    parser.parse(src, None).unwrap()
}

#[test]
fn java_extract_import_declaration_simple_and_wildcard() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "import java.util.List;\nimport java.io.*;\nclass App {}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.imports.get("List"), Some(&"java.util.List".to_string()));
    assert!(!idx.imports.values().any(|v| v == "java.io"));
}

#[test]
fn java_extract_class_declaration_registers_a_package_qualified_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "package com.example;\nclass App {}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.imports.get("App"), Some(&"com.example.App".to_string()));
}

#[test]
fn java_extract_class_declaration_without_a_package_uses_the_bare_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "App.java", "class App {}\n");
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.imports.get("App"), Some(&"App".to_string()));
}

#[test]
fn java_extract_method_and_constructor_carry_the_enclosing_class_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    App() {}\n    void run() {}\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.functions.len(), 2);
    assert!(idx.functions.iter().all(|f| f.class_name == "App"));
    assert!(idx.functions.iter().any(|f| f.name == "App"));
    assert!(idx.functions.iter().any(|f| f.name == "run"));
}

#[test]
fn java_extract_method_invocation_and_object_creation() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run(String cmd) {\n        rt.exec(cmd);\n        new Foo();\n    }\n}\n",
    );
    let sinks = vec![java_exec_sink()];
    let idx = scan_file(&path, "App.java", "java", &[], &sinks, false, None, None).unwrap();
    assert!(idx
        .call_edges
        .contains(&("run".to_string(), "rt".to_string(), "exec".to_string())));
    assert!(idx
        .call_edges
        .contains(&("run".to_string(), String::new(), "Foo".to_string())));
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].matched_rule, "java.runtime.exec");
}

#[test]
fn java_extract_object_creation_with_a_qualified_type_uses_the_short_class_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run() {\n        new java.util.ArrayList();\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert!(idx
        .call_edges
        .contains(&("run".to_string(), String::new(), "ArrayList".to_string())));
}

#[test]
fn java_extract_local_variable_declaration_narrows_the_type_via_constructor() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run() {\n        Runnable x = new Impl();\n        x.run();\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.imports.get("x"), Some(&"Impl".to_string()));
    assert_eq!(idx.assigns.len(), 1);
    assert_eq!(idx.assigns[0].dst_symbol, "x");
    assert_eq!(idx.assigns[0].src_call, Some("Impl".to_string()));
}

#[test]
fn java_extract_local_variable_declaration_with_an_identifier_initializer() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run(String cmd) {\n        String y = cmd;\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.assigns.len(), 1);
    assert_eq!(idx.assigns[0].src_symbol, Some("cmd".to_string()));
}

#[test]
fn java_extract_local_variable_declaration_with_a_method_call_initializer() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run() {\n        String z = getName();\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.assigns.len(), 1);
    assert_eq!(idx.assigns[0].src_call, Some("getName".to_string()));
}

#[test]
fn java_extract_local_variable_declaration_with_no_initializer_records_no_assign() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run() {\n        String s;\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert!(idx.assigns.is_empty());
}

#[test]
fn java_extract_a_type_that_normalizes_to_empty_records_no_local_types() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run() {\n        <> x;\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert!(!idx.imports.contains_key("x"));
}

#[test]
fn java_extract_assignment_expression_various_rhs_kinds() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run(String cmd) {\n        String a;\n        String b;\n        String c;\n        a = cmd;\n        b = getName();\n        c = new Foo();\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.assigns.len(), 3);
    assert!(idx
        .assigns
        .iter()
        .any(|a| a.dst_symbol == "a" && a.src_symbol == Some("cmd".to_string())));
    assert!(idx
        .assigns
        .iter()
        .any(|a| a.dst_symbol == "b" && a.src_call == Some("getName".to_string())));
    assert!(idx
        .assigns
        .iter()
        .any(|a| a.dst_symbol == "c" && a.src_call == Some("Foo".to_string())));
}

#[test]
fn java_extract_assignment_expression_narrows_a_cast_type() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run(Object o) {\n        Foo f;\n        f = (Foo) o;\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.imports.get("f"), Some(&"Foo".to_string()));
}

#[test]
fn java_extract_assignment_to_a_non_identifier_lhs_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run(String cmd) {\n        this.field = cmd;\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert!(idx.assigns.is_empty());
}

#[test]
fn java_extract_return_statement_with_and_without_an_identifier() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    String run(String cmd) {\n        if (cmd == null) {\n            return null;\n        }\n        return cmd;\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.returns.len(), 2);
    assert!(idx.returns.iter().any(|r| r.symbol.is_none()));
    assert!(idx
        .returns
        .iter()
        .any(|r| r.symbol == Some("cmd".to_string())));
}

#[test]
fn java_extract_formal_parameter_type_hint() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run(Foo foo) {}\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.imports.get("foo"), Some(&"Foo".to_string()));
}

#[test]
fn java_extract_catch_formal_parameter_has_no_type_field_to_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run() {\n        try {\n        } catch (Bar bar) {\n        }\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert!(!idx.imports.contains_key("bar"));
}

#[test]
fn java_extract_call_args_captures_identifier_arguments_and_target_symbol() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    void run(String cmd) {\n        String out = helper(cmd);\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.call_args.len(), 1);
    assert_eq!(idx.call_args[0].arg_symbols, vec!["cmd".to_string()]);
    assert_eq!(idx.call_args[0].target_symbol, Some("out".to_string()));
}

#[test]
fn java_leftmost_identifier_walks_field_access_and_a_dead_end() {
    let src: &[u8] = b"class App { void run() { a.b.c(); } }";
    let tree = parse_java(src);
    let obj = find_kind(tree.root_node(), "field_access").unwrap();
    assert_eq!(java_leftmost_identifier(obj, src), "a");
}

#[test]
fn java_invocation_parts_receiver_is_empty_when_the_object_is_itself_a_call() {
    let src: &[u8] = b"class App { void run() { getFoo().bar(); } }";
    let tree = parse_java(src);
    let outer = find_kind(tree.root_node(), "method_invocation").unwrap();
    let (receiver, method) = java_invocation_parts(outer, src);
    assert_eq!(method, "bar");
    assert_eq!(receiver, "");
}

#[test]
fn java_extract_ignores_a_method_invocation_with_no_name() {
    let src: &[u8] = b"class App {}";
    let tree = parse_java(src);
    let (receiver, method) = java_invocation_parts(tree.root_node(), src);
    assert_eq!(receiver, "");
    assert_eq!(method, "");
}

#[test]
fn java_extract_assigns_returns_and_call_args_are_populated_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.java",
        "class App {\n    String run(String cmd) {\n        String out = helper(cmd);\n        return out;\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.java", "java", &[], &[], false, None, None).unwrap();
    assert!(!idx.assigns.is_empty());
    assert!(!idx.returns.is_empty());
    assert!(!idx.call_args.is_empty());
}

fn cs_exec_sink() -> MatchSpec {
    MatchSpec {
        rule_id: "cs.process.start".to_string(),
        role: "sink".to_string(),
        origin: "semgrep".to_string(),
        cwe: "CWE-78".to_string(),
        kind: "command_injection".to_string(),
        languages: std::collections::BTreeSet::from(["csharp".to_string()]),
        semantic_family: "command-exec".to_string(),
        module_attr_module: "Process".to_string(),
        module_attr_names: std::collections::BTreeSet::from(["Start".to_string()]),
        ..Default::default()
    }
}

fn parse_cs(src: &[u8]) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
        .unwrap();
    parser.parse(src, None).unwrap()
}

#[test]
fn cs_extract_using_directive_registers_the_top_level_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "using System.Diagnostics;\nclass App {}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert_eq!(
        idx.imports.get("Diagnostics"),
        Some(&"System.Diagnostics".to_string())
    );
}

#[test]
fn cs_extract_class_struct_and_interface_all_scope_their_methods() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class C {\n    void M() {}\n}\nstruct S {\n    void N() {}\n}\ninterface I {\n    void O();\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert!(idx
        .functions
        .iter()
        .any(|f| f.name == "M" && f.class_name == "C"));
    assert!(idx
        .functions
        .iter()
        .any(|f| f.name == "N" && f.class_name == "S"));
    assert!(idx
        .functions
        .iter()
        .any(|f| f.name == "O" && f.class_name == "I"));
}

#[test]
fn cs_extract_local_function_statement_has_no_class_scope() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    void Run() {\n        void Local() {}\n        Local();\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert!(idx
        .functions
        .iter()
        .any(|f| f.name == "Local" && f.class_name.is_empty()));
}

#[test]
fn cs_extract_invocation_and_object_creation() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    void Run(string cmd) {\n        Process.Start(cmd);\n        var f = new Foo();\n    }\n}\n",
    );
    let sinks = vec![cs_exec_sink()];
    let idx = scan_file(&path, "App.cs", "csharp", &[], &sinks, false, None, None).unwrap();
    assert!(idx.call_edges.contains(&(
        "Run".to_string(),
        "Process".to_string(),
        "Start".to_string()
    )));
    assert!(idx
        .call_edges
        .contains(&("Run".to_string(), String::new(), "Foo".to_string())));
    assert_eq!(idx.sink_hits.len(), 1);
    assert_eq!(idx.sink_hits[0].matched_rule, "cs.process.start");
}

#[test]
fn cs_extract_object_creation_with_a_qualified_type_uses_the_short_class_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    void Run() {\n        var l = new System.Collections.ArrayList();\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert!(idx
        .call_edges
        .contains(&("Run".to_string(), String::new(), "ArrayList".to_string())));
}

#[test]
fn cs_extract_variable_declarator_with_an_identifier_initializer() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    void Run(string cmd) {\n        string y = cmd;\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.assigns.len(), 1);
    assert_eq!(idx.assigns[0].dst_symbol, "y");
    assert_eq!(idx.assigns[0].src_symbol, Some("cmd".to_string()));
}

#[test]
fn cs_extract_variable_declarator_with_a_method_call_initializer() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    void Run() {\n        string z = GetName();\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.assigns.len(), 1);
    assert_eq!(idx.assigns[0].src_call, Some("GetName".to_string()));
}

#[test]
fn cs_extract_variable_declarator_with_a_constructor_initializer() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    void Run() {\n        var f = new Foo();\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert!(idx
        .assigns
        .iter()
        .any(|a| a.dst_symbol == "f" && a.src_call == Some("Foo".to_string())));
}

#[test]
fn cs_extract_variable_declarator_with_no_initializer_records_no_assign() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(dir.path(), "App.cs", "class App {\n    string s;\n}\n");
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert!(idx.assigns.is_empty());
}

#[test]
fn cs_extract_assignment_expression_various_rhs_kinds() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    void Run(string cmd) {\n        string a;\n        string b;\n        string c;\n        a = cmd;\n        b = GetName();\n        c = new Foo();\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert!(idx
        .assigns
        .iter()
        .any(|a| a.dst_symbol == "a" && a.src_symbol == Some("cmd".to_string())));
    assert!(idx
        .assigns
        .iter()
        .any(|a| a.dst_symbol == "b" && a.src_call == Some("GetName".to_string())));
    assert!(idx
        .assigns
        .iter()
        .any(|a| a.dst_symbol == "c" && a.src_call == Some("Foo".to_string())));
}

#[test]
fn cs_extract_assignment_to_a_non_identifier_lhs_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    string field;\n    void Run(string cmd) {\n        this.field = cmd;\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert!(idx.assigns.is_empty());
}

#[test]
fn cs_extract_return_statement_with_and_without_an_identifier() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    string Run(string cmd) {\n        if (cmd == null) {\n            return null;\n        }\n        return cmd;\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.returns.len(), 2);
    assert!(idx.returns.iter().any(|r| r.symbol.is_none()));
    assert!(idx
        .returns
        .iter()
        .any(|r| r.symbol == Some("cmd".to_string())));
}

#[test]
fn cs_extract_call_args_captures_the_assignment_target_symbol() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    void Run(string cmd) {\n        string outp;\n        outp = Helper(cmd);\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.call_args.len(), 1);
    assert_eq!(idx.call_args[0].target_symbol, Some("outp".to_string()));
}

#[test]
fn cs_extract_call_args_target_symbol_for_a_declaration_initializer() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    void Run(string cmd) {\n        var outp = Helper(cmd);\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.call_args.len(), 1);
    assert_eq!(idx.call_args[0].target_symbol, Some("outp".to_string()));
}

#[test]
fn cs_extract_call_args_unwrap_the_argument_node_positionally() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    void Run(string cmd) {\n        Helper(cmd);\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.call_args.len(), 1);
    assert_eq!(idx.call_args[0].arg_symbols, vec!["cmd".to_string()]);
}

#[test]
fn cs_extract_call_args_object_creation_with_no_arguments_field_yields_no_arg_symbols() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    void Run() {\n        var f = new Foo { X = 1 };\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert_eq!(idx.call_args.len(), 1);
    assert!(idx.call_args[0].arg_symbols.is_empty());
}

#[test]
fn cs_leftmost_identifier_walks_member_access_and_a_dead_end() {
    let src: &[u8] = b"class App { void Run() { a.b.c(); } }";
    let tree = parse_cs(src);
    let obj = find_kind(tree.root_node(), "member_access_expression").unwrap();
    assert_eq!(cs_leftmost_identifier(obj, src), "a");
}

#[test]
fn cs_leftmost_identifier_wildcard_arm_walks_then_dead_ends() {
    let src: &[u8] = b"class App { void Run() { (a || b).c(); } }";
    let tree = parse_cs(src);
    let obj = find_kind(tree.root_node(), "member_access_expression").unwrap();
    assert_eq!(cs_leftmost_identifier(obj, src), "");
}

#[test]
fn cs_leftmost_identifier_falls_back_to_the_first_child_on_a_bare_invocation() {
    let src: &[u8] = b"class App { void Run() { Local(); } }";
    let tree = parse_cs(src);
    let call = find_kind(tree.root_node(), "invocation_expression").unwrap();
    assert_eq!(cs_leftmost_identifier(call, src), "Local");
}

#[test]
fn cs_extract_ignores_an_invocation_with_no_function_or_name() {
    let src: &[u8] = b"class App {}";
    let tree = parse_cs(src);
    let (receiver, method) = cs_invocation_parts(tree.root_node(), src);
    assert_eq!(receiver, "");
    assert_eq!(method, "");
}

#[test]
fn cs_extract_assigns_returns_and_call_args_are_populated_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_py(
        dir.path(),
        "App.cs",
        "class App {\n    string Run(string cmd) {\n        var outp = Helper(cmd);\n        return outp;\n    }\n}\n",
    );
    let idx = scan_file(&path, "App.cs", "csharp", &[], &[], false, None, None).unwrap();
    assert!(!idx.assigns.is_empty());
    assert!(!idx.returns.is_empty());
    assert!(!idx.call_args.is_empty());
}
