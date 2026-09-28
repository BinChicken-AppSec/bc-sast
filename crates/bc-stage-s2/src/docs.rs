//! Documentation evidence under one character budget, ported from the
//! documents pass of upstream v1.4.0 `s2_threatmodel.py::_gather_evidence`.
//!
//! Fixed-name documents are ordered by relevance to threat modeling, not
//! alphabetically: the first three are written about security properties,
//! the README for users, and the changelog is the weakest signal per byte.
//! Pass one gives every present document a fair share (a third of what
//! remains), so one large README can no longer exhaust the budget before
//! `THREAT_MODEL.md` is even opened. Pass two spends what is left growing
//! the documents pass one truncated, so a repository with a single README
//! still gets the whole allowance. Design documents found anywhere in the
//! file list are read last with what remains. Every read is
//! containment-checked.

use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::repo_read::read_contained;

pub(crate) const DOC_CANDIDATES: &[&str] = &[
    "THREAT_MODEL.md",
    "SECURITY.md",
    "ARCHITECTURE.md",
    "README.md",
    "README.rst",
    "README.txt",
    "README",
    "CHANGELOG.md",
    "CHANGELOG",
];

/// How many design documents beyond the fixed names are read.
pub(crate) const DOC_EXTRA_MAX: usize = 8;

/// Design and analysis documents not named README/ARCHITECTURE that still
/// describe the data flows a threat model needs. Matched against the stem.
static DOC_NAME_RX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(analysis|architecture|design|migration|specification|spec|threat|security|dataflow|data[_-]?flow|interface)",
    )
    .unwrap()
});

fn chars(s: &str) -> i64 {
    s.chars().count() as i64
}

fn stem(rel: &str) -> &str {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    match name.rfind('.') {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    }
}

/// `(name, body)` for every document read, fixed names first then extras.
pub(crate) fn gather_docs(
    root: &Path,
    full_files: &[String],
    doc_cap: usize,
) -> Vec<(String, String)> {
    let mut budget = doc_cap as i64;
    let mut docs: Vec<(String, String)> = Vec::new();

    // Pass one buys breadth.
    for name in DOC_CANDIDATES {
        if budget <= 0 {
            break;
        }
        let sub_cap = (budget / 3).max(1000).min(doc_cap as i64) as usize;
        let body = read_contained(root, name, sub_cap, false);
        if !body.is_empty() {
            budget -= chars(&body);
            docs.push((name.to_string(), body));
        }
    }

    // Pass two only ever grows a document pass one truncated, in the same
    // relevance order; it never displaces one. Bounded by the document
    // count, and stops early once nothing grows.
    let fixed = docs.len();
    for _ in 0..fixed {
        if budget <= 0 {
            break;
        }
        let mut grew = false;
        for (name, body) in docs.iter_mut() {
            if budget <= 0 {
                break;
            }
            let cap = (chars(body) + budget).min(doc_cap as i64) as usize;
            let bigger = read_contained(root, name, cap, false);
            let gain = chars(&bigger) - chars(body);
            if gain > 0 {
                budget -= gain;
                *body = bigger;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }

    let seen: HashSet<String> = docs.iter().map(|(n, _)| n.clone()).collect();
    let mut extras: Vec<&String> = full_files
        .iter()
        .filter(|rel| {
            let ext = bc_repo_analysis::suffix_lower(rel);
            (ext == ".md" || ext == ".rst")
                && !seen.contains(rel.as_str())
                && DOC_NAME_RX.is_match(stem(rel))
        })
        .collect();
    extras.sort();
    extras.truncate(DOC_EXTRA_MAX);
    if !extras.is_empty() && budget > 0 {
        let per_cap = (budget / extras.len() as i64).max(1000);
        for rel in extras {
            if budget <= 0 {
                break;
            }
            let body = read_contained(root, rel, budget.min(per_cap) as usize, false);
            if !body.is_empty() {
                budget -= chars(&body);
                docs.push((rel.clone(), body));
            }
        }
    }
    docs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, contents: &str) {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn documents_come_in_relevance_order() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "README.md", "readme");
        write(dir.path(), "THREAT_MODEL.md", "threats");
        write(dir.path(), "CHANGELOG", "changes");
        let docs = gather_docs(dir.path(), &[], 20_000);
        let names: Vec<&str> = docs.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["THREAT_MODEL.md", "README.md", "CHANGELOG"]);
    }

    #[test]
    fn a_large_readme_cannot_starve_the_threat_model() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "README.md", &"r".repeat(9000));
        write(dir.path(), "THREAT_MODEL.md", &"t".repeat(2000));
        write(dir.path(), "CHANGELOG", &"c".repeat(9000));
        let docs = gather_docs(dir.path(), &[], 6000);
        assert_eq!(docs[0], ("THREAT_MODEL.md".to_string(), "t".repeat(2000)));
        assert!(docs[1].1.starts_with("rrr"));
        // Pass two grows the README first (relevance order) and runs out
        // before it reaches the changelog.
        assert!(chars(&docs[1].1) > chars(&docs[2].1));
        let total: i64 = docs.iter().map(|(_, b)| chars(b)).sum();
        assert!(
            total <= 6000 + 80,
            "the budget holds (plus notices): {total}"
        );
    }

    #[test]
    fn a_single_readme_grows_into_the_whole_budget_in_pass_two() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "README.md", &"r".repeat(20_000));
        let docs = gather_docs(dir.path(), &[], 9000);
        // Pass one alone would stop at max(1000, 9000 / 3) = 3000.
        let kept = docs[0].1.chars().take_while(|c| *c == 'r').count();
        assert!(kept > 8000, "grew to {kept}");
    }

    #[test]
    fn a_zero_budget_reads_nothing() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "README.md", "x");
        assert!(gather_docs(dir.path(), &["docs/design.md".into()], 0).is_empty());
    }

    #[test]
    fn extras_are_matched_by_stem_sorted_capped_and_contained() {
        let dir = tempfile::tempdir().unwrap();
        let mut all = Vec::new();
        for i in 0..10 {
            let rel = format!("docs/architecture-{i}.md");
            write(dir.path(), &rel, "extra");
            all.push(rel);
        }
        write(dir.path(), "docs/random.md", "no");
        all.push("docs/random.md".into());
        all.push("../threat.md".into());
        all.push("docs/security.txt".into());
        let docs = gather_docs(dir.path(), &all, 20_000);
        // "../threat.md" sorts first and takes one of the eight slots, but
        // the containment check refuses to read it.
        assert_eq!(docs.len(), DOC_EXTRA_MAX - 1);
        assert_eq!(docs[0].0, "docs/architecture-0.md");
        assert!(docs
            .iter()
            .all(|(n, _)| n.starts_with("docs/architecture-")));
    }

    #[test]
    fn extras_stop_once_the_budget_is_spent() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "README.md", &"r".repeat(50));
        write(dir.path(), "docs/design.md", "design notes");
        write(dir.path(), "docs/spec.md", "spec notes");
        let all = vec!["docs/design.md".to_string(), "docs/spec.md".to_string()];
        // Budget 10: the README alone overruns it (with its notice).
        let docs = gather_docs(dir.path(), &all, 10);
        assert_eq!(docs.len(), 1);
        // A budget the README leaves room in funds the extras, which then
        // stop the moment it runs out: 5 chars remain, the first extra
        // overruns them, and the second is never read.
        write(dir.path(), "README.md", "r");
        let docs = gather_docs(dir.path(), &all, 6);
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[1].0, "docs/design.md");
    }

    #[test]
    fn a_root_document_already_read_is_not_read_again_as_an_extra() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "SECURITY.md", "policy");
        let docs = gather_docs(dir.path(), &["SECURITY.md".into()], 20_000);
        assert_eq!(docs.len(), 1);
    }

    #[test]
    fn stem_handles_dotfiles_and_nested_paths() {
        assert_eq!(stem("docs/design.v2.md"), "design.v2");
        assert_eq!(stem(".threat"), ".threat");
        assert_eq!(stem("NOTES"), "NOTES");
    }
}
