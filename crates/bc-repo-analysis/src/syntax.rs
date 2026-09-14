//! [`syntax_check`]: "does this file still parse?", for S10's remediation
//! syntax gate.
//!
//! **Why this lives here.** A remediation agent's most common way of
//! breaking a codebase is not a subtly wrong fix — it is a `Write` that
//! drops a closing brace, or an `Edit` whose `new_string` leaves a dangling
//! `except:`. Nothing in the pipeline noticed: the verdict said "Fixed",
//! `git diff` showed a real change, and the file was left on disk
//! unparseable. This crate already statically links all 14 tree-sitter
//! grammars and already maps file suffix -> language ([`crate::ext_to_lang`],
//! [`crate::ts_graph_build`]'s own dispatch), so the check costs one extra
//! parse and no new dependency; putting it anywhere else would mean a
//! second copy of that dispatch.
//!
//! No Python equivalent — the Python original has no syntax gate at all.
//! This is a Rust-side addition, deliberately, because the failure it
//! catches is the one users actually report.

use std::path::Path;

use crate::lang::{ext_to_lang, suffix_lower};
use crate::ts_graph::{language_for, normalize_lang_for_queries};

/// `Some(true)` if `bytes` fail to parse cleanly as `path`'s language
/// (tree-sitter surfaced an `ERROR` or `MISSING` node anywhere in the
/// tree), `Some(false)` if they parse cleanly, and `None` when no verdict
/// is possible — an unknown suffix, or a language this workspace has no
/// grammar for (SQL, Terraform, shell, ... — [`crate::ext_to_lang`] knows
/// 132 extensions; only 14 languages have a linked grammar).
///
/// `None` is the important case for a caller: it means "not checked",
/// never "checked and fine". A gate built on this must treat `None` as a
/// file it has no opinion about rather than as a pass, or it would silently
/// bless every `.sql`/`.tf`/`.sh` edit as syntactically sound.
///
/// Takes bytes rather than reading `path` itself so the caller decides
/// what it is checking — the on-disk file, or a candidate buffer it has
/// not written yet — and so a file read once is not read twice. `path` is
/// used only for its extension; it need not exist.
///
/// Deliberately NOT a semantic check, and not even a complete syntactic
/// one. `Node::has_error()` covers both ERROR subtrees and the MISSING
/// nodes error recovery invents (probed directly against the grammar
/// versions this workspace pins: across Java/JavaScript/Go/Rust/C, every
/// input that produced a MISSING node also had `has_error()` set, so the
/// O(1) check needs no second tree walk beside it). What it does NOT catch
/// is source a *grammar* accepts but the *language* rejects — most
/// visibly, tree-sitter-python's `block` may be empty, so a truncated
/// `if x:` with no suite parses clean. The gate this feeds is a floor
/// ("the agent did not leave unparseable text on disk"), never a compiler.
pub fn syntax_check(path: &Path, bytes: &[u8]) -> Option<bool> {
    let rel = path.to_string_lossy();
    let lang = ext_to_lang(&suffix_lower(&rel))?;
    // `EXT_TO_LANG` groups C and C++ under one `c-cpp` family key and
    // labels `.tsx` as plain `typescript`; the grammars are separate, so
    // resolve back to a concrete one by suffix — the same reconciliation
    // the call-graph backend does. Getting TSX wrong here is not a
    // missed edge but a false verdict: the TypeScript grammar errors on
    // JSX, and S10 reads that as the fix having broken the file.
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
        // Exactly the shape a bad `Edit` leaves behind.
        assert_eq!(
            syntax_check(Path::new("app.py"), b"def f(x):\n    return x ) )\n"),
            Some(true)
        );
    }

    #[test]
    fn a_missing_statement_terminator_is_reported_as_broken() {
        // A MISSING-node case rather than a pure ERROR-subtree one; both
        // set `has_error()`, which is why one check covers both.
        assert_eq!(
            syntax_check(Path::new("A.java"), b"class A { void f() { int x = 1 } }"),
            Some(true)
        );
    }

    #[test]
    fn a_grammar_accepted_but_language_invalid_suite_is_not_caught() {
        // Pins the documented limitation rather than pretending it away:
        // tree-sitter-python allows an empty `block`, so a truncated
        // `if x:` parses clean even though Python itself rejects it. The
        // gate is a floor, not a compiler.
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
        // `EXT_TO_LANG` returns the shared `c-cpp` family key for both;
        // this pins the concrete-grammar reconciliation.
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
        // `ext_to_lang` maps 132 extensions; only 14 languages have a
        // grammar crate. A `None` here must never be read as "parsed fine".
        assert_eq!(syntax_check(Path::new("q.sql"), b"SELECT ((("), None);
        assert_eq!(syntax_check(Path::new("main.tf"), b"resource {"), None);
    }

    #[test]
    fn an_empty_file_parses_cleanly() {
        assert_eq!(syntax_check(Path::new("app.py"), b""), Some(false));
    }

    #[test]
    fn non_utf8_bytes_in_a_supported_language_are_reported_as_broken() {
        // Not a crash and not a silent pass: a source file the agent
        // filled with binary garbage is exactly what the gate should stop.
        assert_eq!(
            syntax_check(Path::new("app.py"), &[0x00, 0xff, 0xfe, 0x41]),
            Some(true)
        );
    }

    #[test]
    fn a_tsx_component_parses_with_the_tsx_grammar() {
        // tree-sitter ships a separate TSX grammar because the TypeScript
        // one reads `<div>` as a type assertion and errors on JSX. Parsing
        // `.tsx` with the TypeScript grammar made S10's gate read every
        // fix that touched a React component as having left unparseable
        // text on disk, and revert it.
        const JSX: &[u8] = b"export const A = () => <div className=\"x\">hi</div>;\n";
        assert_eq!(syntax_check(Path::new("a.tsx"), JSX), Some(false));
        // The JavaScript grammar has always accepted JSX; the twin pins
        // that `.jsx` was not re-routed anywhere.
        assert_eq!(syntax_check(Path::new("a.jsx"), JSX), Some(false));
    }

    #[test]
    fn a_broken_tsx_file_is_still_reported_as_broken() {
        // The TSX grammar must not defang the gate: an unclosed element
        // and a stray brace are both still errors.
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
        // An angle-bracket type assertion is legal TypeScript and illegal
        // TSX, so this pins that the suffix picks the grammar in both
        // directions rather than TSX simply replacing TypeScript.
        const ASSERTION: &[u8] = b"const n = <number>x;\n";
        assert_eq!(syntax_check(Path::new("a.ts"), ASSERTION), Some(false));
        assert_eq!(syntax_check(Path::new("a.tsx"), ASSERTION), Some(true));
    }
}
