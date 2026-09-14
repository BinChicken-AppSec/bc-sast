//! Deterministic re-anchoring of temporal C/C++ findings, run on every
//! `Finding` parsed out of a deep-dive reply before it is voted on.
//!
//! S4's reply schema (see [`crate::prompts`]'s `OUTPUT_SCHEMA`) tells the
//! model that a use-after-free / double-free / TOCTOU finding must be
//! anchored at the LATER unsafe use, spanning the release site when both
//! are visible. That instruction is advisory: a run that ignores it
//! reports the `free`/`delete` line and nothing downstream notices. The
//! anchor is not cosmetic — `bc_sarif`'s v2 fingerprint hashes the source
//! at the reported range (so the finding's identity drifts between runs
//! that disagree about the anchor), `bc_github`'s review comments are
//! silently demoted to conversation comments when the line is not in the
//! diff, and both [`crate::vote`] and S7's dedup key on the line.
//!
//! So this module enforces the rule instead of asking for it: parse the
//! reported file with the tree-sitter C++ grammar, and when the reported
//! `line_start` really does sit on a `free(p)`/`delete p` whose released
//! pointer is unambiguously used again later in the same function, rewrite
//! the range to span release → use.
//!
//! **This pass rewrites what the model said, so every ambiguity declines.**
//! A false re-anchor moves a *correct* finding onto a wrong line, which is
//! strictly worse than leaving a mis-anchored one alone. Every predicate
//! below is therefore written to bail rather than guess: the release call
//! must take a single bare identifier (no cast, no `s->buf`, no expression),
//! exactly one release site may cover the reported line, the enclosing
//! function must parse cleanly, anything that could have re-pointed the
//! pointer between the release and the next mention (an assignment, `++`,
//! a redeclaration, or having its address taken) abandons the finding
//! untouched rather than anchoring at a use that may no longer be a use,
//! and a "use" the release provably cannot reach — the mention that
//! follows a `free(p); return -1;` error branch — is not one.
//!
//! Note what this deliberately does NOT do: it never *invents* an anchor
//! for a finding reported somewhere else entirely (no release site on the
//! reported line means no rewrite, not a file-wide hunt), and it never
//! touches `sink_ref` — S5's backfill owns the refs, and a ref the model
//! wrote is evidence about its own reasoning that this pass has no
//! business editing.

use std::path::Path;

use bc_model::{Finding, VulnClass};
use tree_sitter::Node;

use crate::code_loading::read_confined;

/// The file extensions this pass will parse. The tree-sitter C++ grammar
/// handles both dialects, and a `.h` is routinely either one.
const C_CPP_EXTENSIONS: &[&str] = &[
    "c", "h", "cc", "cpp", "cxx", "c++", "hpp", "hh", "hxx", "h++",
];

/// Release functions recognised as a release site. Deliberately just the
/// libc pair: a project-specific `xfree`/`g_free`/`my_release` wrapper
/// cannot be told apart from an ordinary one-argument call without
/// knowing the project, and guessing wrong re-anchors a good finding.
const RELEASE_FUNCTIONS: &[&str] = &["free", "cfree"];

/// CWEs whose findings are temporal even when the model picked a
/// `vuln_class` that isn't: double-free (CWE-415) has no class of its own
/// in [`VulnClass`], so it arrives as `other`/`use-after-free` + CWE-415.
const TEMPORAL_CWES: &[&str] = &["CWE-415", "CWE-416", "CWE-367"];

/// Where a temporal finding should have been anchored: the release site,
/// the first later use of the released pointer, and which pointer that is
/// (carried only so the `info` log can name it).
struct Anchor {
    line_start: i64,
    line_end: i64,
    released: String,
}

/// Whether this finding is a temporal one. Both halves matter: the class
/// alone misses a double-free the model labelled `other`, and the CWE
/// alone misses the (common) finding that carries no CWE at all.
fn is_temporal(finding: &Finding) -> bool {
    if matches!(
        finding.vuln_class,
        VulnClass::UseAfterFree | VulnClass::RaceCondition
    ) {
        return true;
    }
    let cwe = finding.cwe.as_deref().unwrap_or_default().trim();
    TEMPORAL_CWES.iter().any(|c| c.eq_ignore_ascii_case(cwe))
}

fn is_c_or_cpp(file: &str) -> bool {
    let ext = Path::new(file)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    C_CPP_EXTENSIONS.iter().any(|e| e.eq_ignore_ascii_case(ext))
}

fn text(node: Node, src: &[u8]) -> String {
    String::from_utf8_lossy(&src[node.start_byte()..node.end_byte()]).into_owned()
}

/// The anonymous operator token of a `binary`/`unary`/`pointer`
/// expression — `&` and `*` share the `pointer_expression` kind, so the
/// token is the only thing that separates "address taken" from
/// "dereferenced".
fn operator_text(node: Node, src: &[u8]) -> String {
    node.child_by_field_name("operator")
        .map(|op| text(op, src))
        .unwrap_or_default()
}

/// 1-based line of a node's first character, in `Finding`'s numbering.
fn line_of(node: Node) -> i64 {
    node.start_position().row as i64 + 1
}

fn covers_line(node: Node, line: i64) -> bool {
    line_of(node) <= line && line <= node.end_position().row as i64 + 1
}

/// Pre-order (document-order) visit of `node` and every descendant.
/// `&mut dyn` rather than a generic so the two call sites share one
/// instantiation.
fn walk<'t>(node: Node<'t>, visit: &mut dyn FnMut(Node<'t>)) {
    visit(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk(child, visit);
    }
}

/// The name released by `node` if it is a release site releasing a single
/// bare identifier: `free(p)`/`cfree(p)`, `delete p`, `delete[] p`.
///
/// Everything else is `None` on purpose. `free(s->buf)` and
/// `free((void *)p)` are real releases, but their released *object* is an
/// expression whose later mentions this module cannot compare for
/// identity, and a wrong identity means a wrong anchor.
fn released_name(node: Node, src: &[u8]) -> Option<String> {
    match node.kind() {
        "call_expression" => {
            let callee = node.child_by_field_name("function")?;
            if callee.kind() != "identifier" {
                return None;
            }
            if !RELEASE_FUNCTIONS.contains(&text(callee, src).as_str()) {
                return None;
            }
            let args = node.child_by_field_name("arguments")?;
            if args.named_child_count() != 1 {
                return None;
            }
            let arg = args.named_child(0)?;
            if arg.kind() != "identifier" {
                return None;
            }
            Some(text(arg, src))
        }
        "delete_expression" => {
            let operand = node.named_child(0)?;
            if operand.kind() != "identifier" {
                return None;
            }
            Some(text(operand, src))
        }
        _ => None,
    }
}

/// The innermost function-shaped ancestor, whose body bounds the search
/// for a later use. A lambda counts: a `free` inside one must not find
/// its "use" in the enclosing function's code that follows the lambda.
fn enclosing_scope(node: Node) -> Option<Node> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if matches!(parent.kind(), "function_definition" | "lambda_expression") {
            return Some(parent);
        }
        current = parent;
    }
    None
}

/// Whether this mention re-points the pointer (or might): the left of an
/// assignment, an `++`/`--`, a redeclaration shadowing the name, or `&p`,
/// which hands a callee the means to overwrite it. Any of these means the
/// pointer may no longer be the freed one, so the finding is abandoned
/// rather than anchored past them.
fn is_reassignment(id: Node, src: &[u8]) -> bool {
    id.parent().is_some_and(|parent| match parent.kind() {
        "assignment_expression" => parent.child_by_field_name("left") == Some(id),
        "update_expression" => true,
        "init_declarator" | "pointer_declarator" => {
            parent.child_by_field_name("declarator") == Some(id)
        }
        "pointer_expression" => operator_text(parent, src) == "&",
        _ => false,
    })
}

fn is_null_literal(node: Node, src: &[u8]) -> bool {
    // `NULL` and `nullptr` both parse to the grammar's `null` node.
    node.kind() == "null" || (node.kind() == "number_literal" && text(node, src) == "0")
}

/// Whether this mention is only a null test — `p == NULL`, `NULL != p`,
/// `!p`, or a bare `if (p)`. Checking a dangling pointer is not a use of
/// it (it is, in fact, the thing a fixed version does), so these are
/// skipped over rather than reported as the unsafe use.
fn is_null_check(id: Node, src: &[u8]) -> bool {
    id.parent().is_some_and(|parent| match parent.kind() {
        "binary_expression" => {
            let operands = [
                parent.child_by_field_name("left"),
                parent.child_by_field_name("right"),
            ];
            matches!(operator_text(parent, src).as_str(), "==" | "!=")
                && operands.iter().flatten().any(|n| is_null_literal(*n, src))
        }
        "unary_expression" => operator_text(parent, src) == "!",
        "condition_clause" => true,
        _ => false,
    })
}

/// The nearest enclosing `{ ... }` block, which is what a `return` in the
/// middle of a function escapes from.
fn enclosing_block(node: Node) -> Option<Node> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "compound_statement" {
            return Some(parent);
        }
        current = parent;
    }
    None
}

/// Whether `block` unconditionally leaves itself after `after_byte` — a
/// `return`/`break`/`continue`/`goto`/`throw` that is a direct statement
/// of the block, not one buried in a nested branch that may fall through.
fn jumps_after(block: Node, after_byte: usize) -> bool {
    let mut cursor = block.walk();
    let mut children = block.named_children(&mut cursor);
    children.any(|child| {
        child.start_byte() >= after_byte
            && matches!(
                child.kind(),
                "return_statement"
                    | "break_statement"
                    | "continue_statement"
                    | "goto_statement"
                    | "throw_statement"
            )
    })
}

/// Whether some block between the release and `use_site` jumps away
/// before the use can be reached. `free(p); return -1;` inside an error
/// branch is the single most common shape in C, and the next textual
/// mention of `p` after such a branch is code the release can never
/// reach.
///
/// The converse (a use the release *can* reach, from a block that merely
/// ends) stays in scope: `if (err) { free(p); } use(p);` is a real
/// use-after-free and gets re-anchored.
fn jumps_between(release: Node, use_site: Node) -> bool {
    std::iter::successors(enclosing_block(release), |block| enclosing_block(*block))
        .take_while(|block| use_site.start_byte() >= block.end_byte())
        .any(|block| jumps_after(block, release.end_byte()))
}

fn ancestors<'t>(node: Node<'t>) -> impl Iterator<Item = Node<'t>> {
    std::iter::successors(Some(node), |n| n.parent())
}

/// The innermost node containing both — always `Some` for two nodes of
/// the same tree, which share at least its root.
fn lowest_common_ancestor<'t>(a: Node<'t>, b: Node<'t>) -> Option<Node<'t>> {
    let a_ancestors: Vec<Node<'t>> = ancestors(a).collect();
    ancestors(b).find(|n| a_ancestors.contains(n))
}

/// Constructs whose arms are alternatives: reaching one means not
/// reaching the others. A `switch`'s arms are the `case`s inside its
/// body block, so the block itself is the fork.
const BRANCHING_KINDS: &[&str] = &[
    "if_statement",
    "conditional_expression",
    "try_statement",
    "switch_statement",
];

/// Whether the release and the use sit in two different arms of the same
/// branch — `if (e) { free(p); } else { use(p); }`, or two `case`s of one
/// `switch`. Sequential-looking in the text, mutually exclusive in fact.
fn branches_apart(release: Node, use_site: Node) -> bool {
    lowest_common_ancestor(release, use_site).is_some_and(|lca| {
        BRANCHING_KINDS.contains(&lca.kind())
            || (lca.kind() == "compound_statement"
                && lca.parent().is_some_and(|p| p.kind() == "switch_statement"))
    })
}

/// Whether control provably cannot get from the release to `use_site`,
/// which makes the "use" a wrong anchor however plainly it reads.
fn use_is_unreachable(release: Node, use_site: Node) -> bool {
    branches_apart(release, use_site) || jumps_between(release, use_site)
}

/// The first mention of `name` inside `body` that starts after
/// `after_byte` and is a genuine use. `None` when there is no later
/// mention at all, or when the first one re-points the pointer.
fn first_use<'t>(body: Node<'t>, src: &[u8], name: &str, after_byte: usize) -> Option<Node<'t>> {
    let mut mentions: Vec<Node<'t>> = Vec::new();
    walk(body, &mut |node| {
        if node.kind() == "identifier" && node.start_byte() >= after_byte && text(node, src) == name
        {
            mentions.push(node);
        }
    });
    for id in mentions {
        if is_reassignment(id, src) {
            return None;
        }
        if is_null_check(id, src) {
            continue;
        }
        return Some(id);
    }
    None
}

/// The pure core: given a whole C/C++ source file and the line the model
/// anchored a temporal finding at, the range that finding should carry.
///
/// `None` — leave the finding exactly as reported — whenever the file
/// does not parse, the reported line carries no release site or more than
/// one, the release is not inside a function, that function does not
/// parse cleanly, the released pointer has no unambiguous later use, or
/// the use it does have is unreachable from the release.
fn temporal_anchor(source: &str, reported_line: i64) -> Option<Anchor> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_cpp::LANGUAGE.into())
        .ok()?;
    let tree = parser.parse(source, None)?;
    let src = source.as_bytes();

    let mut releases: Vec<(Node, String)> = Vec::new();
    walk(tree.root_node(), &mut |node| {
        if covers_line(node, reported_line) {
            if let Some(name) = released_name(node, src) {
                releases.push((node, name));
            }
        }
    });
    // Zero: the model anchored somewhere this pass has no opinion about.
    // Two or more (`free(a); free(b);` on one line): no way to tell which
    // one the finding is about.
    if releases.len() != 1 {
        return None;
    }
    let (release, released) = releases.remove(0);

    let scope = enclosing_scope(release)?;
    // A function whose body has a parse error (an unexpanded macro, a
    // dialect the grammar does not cover) can hide or invent mentions, so
    // its forward scan is not trustworthy.
    if scope.has_error() {
        return None;
    }
    let body = scope.child_by_field_name("body")?;

    // `release.end_byte()` is the end of the `free(p)`/`delete p`
    // expression, i.e. everything strictly after the release statement
    // bar its own semicolon — and it correctly excludes the released
    // pointer's mention *inside* the release itself.
    let use_site = first_use(body, src, &released, release.end_byte())?;
    if use_is_unreachable(release, use_site) {
        return None;
    }
    Some(Anchor {
        line_start: line_of(release),
        line_end: line_of(use_site),
        released,
    })
}

/// Re-anchor `finding` in place if it is a temporal C/C++ finding whose
/// reported line sits on a release site with an unambiguous later use.
/// Silent and side-effect-free in every other case.
pub(crate) fn reanchor_temporal(finding: &mut Finding, repo_root: &Path) {
    if !is_temporal(finding) || !is_c_or_cpp(&finding.file) {
        return;
    }
    // Confined read: `finding.file` is LLM-authored, so a `../../etc`
    // shaped path has to degrade to "no source" exactly like a missing
    // file does (CWE-22) — same rule as `code_loading::read_confined`'s
    // other callers.
    let Ok(source) = read_confined(repo_root, &finding.file) else {
        return;
    };
    let Some(anchor) = temporal_anchor(&source, finding.line_start) else {
        return;
    };

    let mut rewritten: Vec<String> = Vec::new();
    if anchor.line_start != finding.line_start {
        rewritten.push("line_start".to_string());
    }
    if anchor.line_end != finding.line_end {
        rewritten.push("line_end".to_string());
    }
    // The model already anchored it the way the schema asks. Nothing to
    // say, and nothing to record.
    if rewritten.is_empty() {
        return;
    }

    // Every interpolation is a plain binding captured inline, not an
    // expression: a `tracing` macro only evaluates its arguments when a
    // subscriber is listening, so an expression here would be a line no
    // test can execute.
    let Anchor {
        line_start,
        line_end,
        released,
    } = anchor;
    let class = finding.vuln_class.as_str();
    let file = &finding.file;
    let (was_start, was_end) = (finding.line_start, finding.line_end);
    tracing::info!(
        "[s4] re-anchored {class} finding in {file} from {was_start}-{was_end} to \
         {line_start}-{line_end}: the model reported the release of `{released}`, whose \
         first later use is line {line_end}."
    );
    finding.line_start = line_start;
    finding.line_end = line_end;
    finding.reanchored = rewritten;
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// A one-function C program whose line numbers are fixed and easy to
    /// reason about: line 1 is the signature, line 2 the allocation, and
    /// `body`'s first line is line 3.
    fn program(body: &str) -> String {
        format!("void handle(char *q) {{\n    char *p = malloc(16);\n{body}}}\n")
    }

    /// The first body line, i.e. where every fixture below puts its
    /// release site (and therefore the line the model is pretending to
    /// have reported).
    const FIRST_BODY_LINE: i64 = 3;

    fn body_anchor(body: &str, reported_line: i64) -> Option<Anchor> {
        temporal_anchor(&program(body), reported_line)
    }

    /// The range only — `Anchor` has no `PartialEq` of its own, and every
    /// test but one cares about exactly these two numbers.
    fn range(anchor: Option<Anchor>) -> Option<(i64, i64)> {
        anchor.map(|a| (a.line_start, a.line_end))
    }

    // ── the analysis: what it re-anchors ──────────────────────────────

    #[test]
    fn a_use_after_free_reported_at_the_free_spans_the_free_and_the_later_use() {
        let anchor = body_anchor("    free(p);\n    printf(\"%s\", p);\n", FIRST_BODY_LINE)
            .expect("the free and its later deref are both plainly there");
        assert_eq!((anchor.line_start, anchor.line_end), (3, 4));
        assert_eq!(anchor.released, "p");
    }

    #[test]
    fn a_double_free_anchors_at_the_second_free() {
        // The second `free(p)` mentions `p` like any other use would, so
        // the same forward scan lands on it — which is exactly the anchor
        // CWE-415 wants.
        assert_eq!(
            range(body_anchor(
                "    free(p);\n    log_it();\n    free(p);\n",
                FIRST_BODY_LINE
            )),
            Some((3, 5))
        );
    }

    #[test]
    fn cfree_is_a_release_site_too() {
        assert_eq!(
            range(body_anchor(
                "    cfree(p);\n    printf(\"%s\", p);\n",
                FIRST_BODY_LINE
            )),
            Some((3, 4))
        );
    }

    #[test]
    fn delete_and_delete_array_are_release_sites() {
        assert_eq!(
            range(body_anchor(
                "    delete p;\n    printf(\"%s\", p);\n",
                FIRST_BODY_LINE
            )),
            Some((3, 4))
        );
        assert_eq!(
            range(body_anchor(
                "    delete[] p;\n    printf(\"%s\", p);\n",
                FIRST_BODY_LINE
            )),
            Some((3, 4))
        );
    }

    #[test]
    fn a_dereference_a_field_access_and_a_subscript_all_count_as_the_use() {
        for use_line in ["    *p = 1;\n", "    q = p->next;\n", "    q = p[2];\n"] {
            assert_eq!(
                range(body_anchor(
                    &format!("    free(p);\n{use_line}"),
                    FIRST_BODY_LINE
                )),
                Some((3, 4)),
                "{use_line}"
            );
        }
    }

    #[test]
    fn a_later_declaration_initialised_from_the_freed_pointer_is_a_use() {
        // `char *r = p;` — the mention is the init_declarator's VALUE,
        // not its declarator, so it is a read of the dangling pointer.
        assert_eq!(
            range(body_anchor(
                "    free(p);\n    char *r = p;\n",
                FIRST_BODY_LINE
            )),
            Some((3, 4))
        );
    }

    #[test]
    fn a_comparison_that_is_not_against_null_is_a_use() {
        assert_eq!(
            range(body_anchor(
                "    free(p);\n    if (p == q) return;\n",
                FIRST_BODY_LINE
            )),
            Some((3, 4))
        );
    }

    #[test]
    fn a_release_spanning_several_lines_anchors_at_the_line_the_release_starts_on() {
        // The model reported line 4 (`p);`), which is inside the call but
        // not where it starts: `line_start` moves BACK to the release.
        assert_eq!(
            range(body_anchor(
                "    free(\n        p);\n    printf(\"%s\", p);\n",
                4
            )),
            Some((3, 5))
        );
    }

    // ── the null checks it steps over ─────────────────────────────────

    #[test]
    fn a_null_comparison_after_the_release_is_not_the_use() {
        for check in [
            "    if (p == NULL) return;\n",
            "    if (p != nullptr) return;\n",
            "    if (NULL == p) return;\n",
            "    if (p == 0) return;\n",
            "    if (!p) return;\n",
            "    if (p) return;\n",
        ] {
            assert_eq!(
                range(body_anchor(
                    &format!("    free(p);\n{check}    printf(\"%s\", p);\n"),
                    FIRST_BODY_LINE
                )),
                Some((3, 5)),
                "{check}"
            );
        }
    }

    #[test]
    fn a_null_check_with_no_real_use_after_it_re_anchors_nothing() {
        assert_eq!(
            range(body_anchor(
                "    free(p);\n    if (p == NULL) return;\n",
                FIRST_BODY_LINE
            )),
            None
        );
    }

    // ── the negatives: everything that must be left alone ─────────────

    #[test]
    fn a_finding_already_anchored_at_the_use_is_left_alone() {
        // Reported at line 4, the deref. No release site covers line 4,
        // so the pass has no opinion — it must NOT drag the anchor back
        // to the free.
        assert_eq!(
            range(body_anchor("    free(p);\n    printf(\"%s\", p);\n", 4)),
            None
        );
    }

    #[test]
    fn a_release_with_no_later_mention_at_all_is_left_alone() {
        assert_eq!(range(body_anchor("    free(p);\n", FIRST_BODY_LINE)), None);
    }

    #[test]
    fn a_pointer_reassigned_between_the_release_and_the_next_use_is_left_alone() {
        for reassignment in [
            "    p = NULL;\n",
            "    p = malloc(8);\n",
            "    p++;\n",
            "    char *p = q;\n",
            "    save(&p);\n",
        ] {
            assert_eq!(
                range(body_anchor(
                    &format!("    free(p);\n{reassignment}    printf(\"%s\", p);\n"),
                    FIRST_BODY_LINE
                )),
                None,
                "{reassignment}"
            );
        }
    }

    #[test]
    fn a_use_in_a_different_function_does_not_count() {
        let src = "void handle(void) {\n    char *p = malloc(16);\n    free(p);\n}\n\
                   void other(char *p) {\n    printf(\"%s\", p);\n}\n";
        assert_eq!(range(temporal_anchor(src, 3)), None);
    }

    #[test]
    fn a_use_the_release_can_never_reach_is_left_alone() {
        // The `free` is in an error branch that returns; the next textual
        // mention of `p` is code that branch never reaches, so anchoring
        // there would be confidently wrong.
        for escape in ["    return;\n", "    goto done;\n", "    throw 1;\n"] {
            let src = format!(
                "void handle(char *q) {{\n    char *p = malloc(16);\n    if (q) {{\n\
                 \x20       free(p);\n{escape}    }}\n    printf(\"%s\", p);\n}}\n"
            );
            assert_eq!(range(temporal_anchor(&src, 4)), None, "{escape}");
        }
    }

    #[test]
    fn a_use_in_a_sibling_branch_of_the_release_is_left_alone() {
        // The `else` arm is not reached from the `if` arm, so its mention
        // of `p` is not a use-after-free however sequential it looks.
        let src = "void handle(char *q) {\n    char *p = malloc(16);\n    if (q) {\n\
                   \x20       free(p);\n    } else {\n        printf(\"%s\", p);\n    }\n}\n";
        assert_eq!(range(temporal_anchor(src, 4)), None);

        // Same story for two arms of one `switch`.
        let src = "void handle(int k, char *p) {\n    switch (k) {\n    case 1:\n\
                   \x20       free(p);\n        break;\n    case 2:\n\
                   \x20       printf(\"%s\", p);\n        break;\n    }\n}\n";
        assert_eq!(range(temporal_anchor(src, 4)), None);
    }

    #[test]
    fn a_use_after_the_block_the_release_sits_in_is_still_a_use() {
        // Same shape without the jump: control does reach the `printf`,
        // and this really is a use-after-free.
        let src = "void handle(char *q) {\n    char *p = malloc(16);\n    if (q) {\n\
                   \x20       free(p);\n    }\n    printf(\"%s\", p);\n}\n";
        assert_eq!(range(temporal_anchor(src, 4)), Some((4, 6)));

        // Nor does an ordinary statement after the release close the
        // block off — only a jump does.
        let src = "void handle(char *q) {\n    char *p = malloc(16);\n    if (q) {\n\
                   \x20       free(p);\n        log_it();\n    }\n    printf(\"%s\", p);\n}\n";
        assert_eq!(range(temporal_anchor(src, 4)), Some((4, 7)));
    }

    #[test]
    fn a_release_whose_argument_is_not_a_bare_identifier_is_left_alone() {
        for release in [
            "    free((void *)p);\n",
            "    free(s->buf);\n",
            "    free();\n",
            "    free(p, q);\n",
            "    delete s->buf;\n",
            "    delete this;\n",
        ] {
            assert_eq!(
                range(body_anchor(
                    &format!("{release}    printf(\"%s\", p);\n"),
                    FIRST_BODY_LINE
                )),
                None,
                "{release}"
            );
        }
    }

    #[test]
    fn a_line_that_carries_no_release_at_all_is_left_alone() {
        for line in [
            "    printf(\"%s\", p);\n",
            "    obj->cb(p);\n",
            "    q = p;\n",
        ] {
            assert_eq!(
                range(body_anchor(
                    &format!("{line}    printf(\"%s\", p);\n"),
                    FIRST_BODY_LINE
                )),
                None,
                "{line}"
            );
        }
    }

    #[test]
    fn two_releases_on_the_reported_line_are_ambiguous_and_left_alone() {
        assert_eq!(
            range(body_anchor(
                "    free(p); free(q);\n    printf(\"%s%s\", p, q);\n",
                FIRST_BODY_LINE
            )),
            None
        );
    }

    #[test]
    fn a_release_outside_any_function_body_is_left_alone() {
        assert_eq!(range(temporal_anchor("int g = free(p);\n", 1)), None);
    }

    #[test]
    fn a_function_that_does_not_parse_cleanly_is_left_alone() {
        let src = "void handle(void) {\n    char *p = malloc(16);\n    free(p);\n\
                       @@@ not c @@@\n    printf(\"%s\", p);\n}\n";
        assert_eq!(range(temporal_anchor(src, 3)), None);
    }

    #[test]
    fn a_file_that_is_not_code_at_all_is_left_alone() {
        assert_eq!(
            range(temporal_anchor("just some prose, not code\n", 1)),
            None
        );
        assert_eq!(range(temporal_anchor("", 1)), None);
    }

    #[test]
    fn a_line_number_outside_the_file_is_left_alone() {
        assert_eq!(
            range(body_anchor("    free(p);\n    printf(\"%s\", p);\n", 0)),
            None
        );
        assert_eq!(
            range(body_anchor("    free(p);\n    printf(\"%s\", p);\n", 9999)),
            None
        );
    }

    // ── the gate around the analysis, and what it records ─────────────

    fn finding(file: &str, vuln_class: &str, cwe: Option<&str>, line: i64) -> Finding {
        serde_json::from_value(serde_json::json!({
            "chunk_id": "c1",
            "file": file,
            "line_start": line,
            "line_end": line,
            "vuln_class": vuln_class,
            "cwe": cwe,
            "title": "t",
            "description": "d",
            "code_snippet": "s",
            "confidence": 0.9,
        }))
        .unwrap()
    }

    /// A repo holding one file with a use-after-free: `free` on line 3,
    /// the dangling `printf` on line 4.
    fn repo_with(name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(name),
            program("    free(p);\n    printf(\"%s\", p);\n"),
        )
        .unwrap();
        let root = dir.path().to_path_buf();
        (dir, root)
    }

    #[test]
    fn a_mis_anchored_use_after_free_is_rewritten_and_the_rewrite_recorded() {
        let (_dir, root) = repo_with("bug.c");
        let mut f = finding("bug.c", "use-after-free", None, 3);
        reanchor_temporal(&mut f, &root);
        assert_eq!((f.line_start, f.line_end), (3, 4));
        assert_eq!(f.reanchored, vec!["line_end".to_string()]);
    }

    #[test]
    fn a_release_spanning_lines_records_both_ends_as_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("bug.c"),
            program("    free(\n        p);\n    printf(\"%s\", p);\n"),
        )
        .unwrap();
        let mut f = finding("bug.c", "use-after-free", None, 4);
        reanchor_temporal(&mut f, dir.path());
        assert_eq!((f.line_start, f.line_end), (3, 5));
        assert_eq!(
            f.reanchored,
            vec!["line_start".to_string(), "line_end".to_string()]
        );
    }

    #[test]
    fn a_finding_the_model_already_anchored_correctly_records_nothing() {
        let (_dir, root) = repo_with("bug.c");
        let mut f = finding("bug.c", "use-after-free", None, 3);
        f.line_end = 4;
        reanchor_temporal(&mut f, &root);
        assert_eq!((f.line_start, f.line_end), (3, 4));
        assert!(f.reanchored.is_empty());
    }

    #[test]
    fn a_double_free_reaches_the_pass_through_its_cwe_not_its_class() {
        // No `double-free` member in `VulnClass`, so this is how a real
        // one arrives.
        let (_dir, root) = repo_with("bug.c");
        let mut f = finding("bug.c", "other", Some("CWE-415"), 3);
        reanchor_temporal(&mut f, &root);
        assert_eq!((f.line_start, f.line_end), (3, 4));
    }

    #[test]
    fn a_toctou_race_reaches_the_pass_through_its_class() {
        // `race-condition` is how this codebase spells TOCTOU; such a
        // finding is in scope even though the fixture's release/use pair
        // is what actually decides the anchor.
        let (_dir, root) = repo_with("bug.c");
        let mut f = finding("bug.c", "race-condition", Some("CWE-367"), 3);
        reanchor_temporal(&mut f, &root);
        assert_eq!((f.line_start, f.line_end), (3, 4));
    }

    #[test]
    fn a_non_temporal_class_in_the_same_file_is_untouched() {
        let (_dir, root) = repo_with("bug.c");
        let mut f = finding("bug.c", "heap-overflow", Some("CWE-122"), 3);
        reanchor_temporal(&mut f, &root);
        assert_eq!((f.line_start, f.line_end), (3, 3));
        assert!(f.reanchored.is_empty());
    }

    #[test]
    fn a_file_that_is_not_c_or_cpp_is_untouched() {
        // Same bytes, different extension: nothing but the extension
        // decides, and a `.py` never reaches the C++ grammar.
        let (_dir, root) = repo_with("bug.py");
        let mut f = finding("bug.py", "use-after-free", None, 3);
        reanchor_temporal(&mut f, &root);
        assert_eq!((f.line_start, f.line_end), (3, 3));
        assert!(f.reanchored.is_empty());
    }

    #[test]
    fn every_c_and_cpp_extension_is_in_scope_and_nothing_else_is() {
        for ext in [
            "c", "h", "cc", "cpp", "cxx", "c++", "hpp", "hh", "hxx", "h++", "C",
        ] {
            assert!(is_c_or_cpp(&format!("a.{ext}")), "{ext}");
        }
        for ext in ["py", "java", "rs", "go", "ts", "md"] {
            assert!(!is_c_or_cpp(&format!("a.{ext}")), "{ext}");
        }
        assert!(!is_c_or_cpp("Makefile"));
    }

    #[test]
    fn a_file_that_cannot_be_read_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = finding("gone.c", "use-after-free", None, 3);
        reanchor_temporal(&mut f, dir.path());
        assert_eq!((f.line_start, f.line_end), (3, 3));
        assert!(f.reanchored.is_empty());
    }

    #[test]
    fn a_path_that_escapes_the_repo_root_is_untouched() {
        // `file` is LLM-authored; confinement must degrade to "no
        // source" rather than reading (and re-anchoring against) a file
        // outside the scan.
        let (dir, root) = repo_with("bug.c");
        let inner = root.join("sub");
        std::fs::create_dir(&inner).unwrap();
        let mut f = finding("../bug.c", "use-after-free", None, 3);
        reanchor_temporal(&mut f, &inner);
        assert_eq!((f.line_start, f.line_end), (3, 3));
        assert!(f.reanchored.is_empty());
        drop(dir);
    }

    #[test]
    fn a_c_file_whose_reported_line_holds_no_release_is_untouched() {
        let (_dir, root) = repo_with("bug.c");
        let mut f = finding("bug.c", "use-after-free", None, 2);
        reanchor_temporal(&mut f, &root);
        assert_eq!((f.line_start, f.line_end), (2, 2));
        assert!(f.reanchored.is_empty());
    }
}
