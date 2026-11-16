use std::path::Path;

use crate::lang::{ext_to_lang, suffix_lower};
use crate::ts_graph::{language_for, normalize_lang_for_queries};

pub fn syntax_check(path: &Path, bytes: &[u8]) -> Option<bool> {
    let rel = path.to_string_lossy();
    let lang = ext_to_lang(&suffix_lower(&rel))?;
    let concrete = normalize_lang_for_queries(&rel, lang);
    let language = language_for(&concrete)?;
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(bytes, None)?;
    Some(tree.root_node().has_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_python_parses_cleanly() {
        assert_eq!(
            syntax_check(Path::new("app.py"), b"def f(x):\n    return x + 1\n"),
            Some(false)
        );
    }

    #[test]
    fn a_stray_token_is_reported_as_broken() {
        assert_eq!(
            syntax_check(Path::new("app.py"), b"def f(x):\n    return x ) )\n"),
            Some(true)
        );
    }

    #[test]
    fn a_missing_statement_terminator_is_reported_as_broken() {
        assert_eq!(
            syntax_check(Path::new("A.java"), b"class A { void f() { int x = 1 } }"),
            Some(true)
        );
    }

    #[test]
    fn a_grammar_accepted_but_language_invalid_suite_is_not_caught() {
        assert_eq!(
            syntax_check(Path::new("app.py"), b"def f(x):\n    if x:\n"),
            Some(false)
        );
    }

    #[test]
    fn an_unbalanced_brace_is_reported_as_broken() {
        assert_eq!(
            syntax_check(Path::new("Main.java"), b"class A { void f() { }"),
            Some(true)
        );
    }

    #[test]
    fn well_formed_java_parses_cleanly() {
        assert_eq!(
            syntax_check(Path::new("Main.java"), b"class A { void f() { } }"),
            Some(false)
        );
    }

    #[test]
    fn a_c_header_uses_the_c_grammar_and_a_cpp_source_the_cpp_one() {
        assert_eq!(
            syntax_check(Path::new("a.h"), b"int f(void);\n"),
            Some(false)
        );
        assert_eq!(
            syntax_check(
                Path::new("a.cpp"),
                b"template <typename T> T f(T x) { return x; }\n"
            ),
            Some(false)
        );
    }

    #[test]
    fn an_unknown_suffix_has_no_verdict() {
        assert_eq!(syntax_check(Path::new("notes.xyzzy"), b"anything"), None);
        assert_eq!(syntax_check(Path::new("Makefile"), b"all:\n"), None);
    }

    #[test]
    fn a_known_language_with_no_linked_grammar_has_no_verdict() {
        assert_eq!(syntax_check(Path::new("q.sql"), b"SELECT ((("), None);
        assert_eq!(syntax_check(Path::new("main.tf"), b"resource {"), None);
    }

    #[test]
    fn an_empty_file_parses_cleanly() {
        assert_eq!(syntax_check(Path::new("app.py"), b""), Some(false));
    }

    #[test]
    fn non_utf8_bytes_in_a_supported_language_are_reported_as_broken() {
        assert_eq!(
            syntax_check(Path::new("app.py"), &[0x00, 0xff, 0xfe, 0x41]),
            Some(true)
        );
    }

    #[test]
    fn a_tsx_component_parses_with_the_tsx_grammar() {
        const JSX: &[u8] = b"export const A = () => <div className=\"x\">hi</div>;\n";
        assert_eq!(syntax_check(Path::new("a.tsx"), JSX), Some(false));
        assert_eq!(syntax_check(Path::new("a.jsx"), JSX), Some(false));
    }

    #[test]
    fn a_broken_tsx_file_is_still_reported_as_broken() {
        assert_eq!(
            syntax_check(Path::new("a.tsx"), b"export const A = () => <div>hi;\n"),
            Some(true)
        );
        assert_eq!(
            syntax_check(
                Path::new("a.tsx"),
                b"export const A = () => { return <div>hi</div>; } }\n"
            ),
            Some(true)
        );
    }

    #[test]
    fn a_plain_ts_file_keeps_the_typescript_grammar() {
        const ASSERTION: &[u8] = b"const n = <number>x;\n";
        assert_eq!(syntax_check(Path::new("a.ts"), ASSERTION), Some(false));
        assert_eq!(syntax_check(Path::new("a.tsx"), ASSERTION), Some(true));
    }
}
