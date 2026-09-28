//! The strategist's grounding inventory: deterministic `F###`/`E###`/`K###`
//! ids for every file, entry point and sink the prompt shows, rendered as
//! the authoritative FILE INVENTORY block and resolved back after the call.
//! Ported from upstream v1.3 `ContextPackage.id_inventory` and
//! `_file_inventory_block`.
//!
//! Without an authoritative file list the strategist invented paths that
//! shared a basename with a real file elsewhere in the tree, and the old
//! basename resolver then "relocated" them onto the wrong file. With ids
//! there is no path to mis-match: an id either names a file in this exact
//! inventory or it is dropped.
//!
//! Ids come from SORTED order, not insertion order, so a prompt rendered
//! from them is byte-identical across runs (prompt-prefix caching depends
//! on it). They must be resolved against the SAME context the prompt was
//! rendered from: `sorted(view.all_files)[k]` and `sorted(full.all_files)[k]`
//! name different files whenever the lists differ. `run_decompose` builds
//! one [`IdInventory`] from the narrowed prompt context and uses that one
//! value for both rendering and resolution, so the two cannot diverge.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::Path;

use bc_model::ContextPackage;

use crate::wire::ep_kind_str;

/// One entry point as the inventory shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct InventoryEntryPoint {
    pub file_id: String,
    pub function: String,
    pub kind: &'static str,
    pub unauth: bool,
}

/// One sink as the inventory shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct InventorySink {
    pub file_id: String,
    pub function: String,
    pub cwe: Vec<String>,
}

/// `id -> item` maps, each keyed by a zero-padded id so lexical order is
/// numeric order.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct IdInventory {
    pub files: BTreeMap<String, String>,
    pub entry_points: BTreeMap<String, InventoryEntryPoint>,
    pub sinks: BTreeMap<String, InventorySink>,
}

/// `n` ids `"{prefix}{i:0width}"`, width at least three digits.
fn ids_for(n: usize, prefix: &str) -> Vec<String> {
    let width = n.to_string().len().max(3);
    (1..=n).map(|i| format!("{prefix}{i:0width$}")).collect()
}

impl IdInventory {
    /// Build the inventory for `ctx`. Paths are de-duplicated before
    /// numbering: a repeated path would otherwise take a second id and
    /// leave a gap when the reverse map is built.
    pub fn build(ctx: &ContextPackage) -> Self {
        let files_sorted: Vec<&String> = ctx
            .all_files
            .iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let file_id_of: BTreeMap<&str, String> = files_sorted
            .iter()
            .map(|f| f.as_str())
            .zip(ids_for(files_sorted.len(), "F"))
            .collect();
        let files = file_id_of
            .iter()
            .map(|(path, fid)| (fid.clone(), path.to_string()))
            .collect();
        let file_id = |f: &str| file_id_of.get(f).cloned().unwrap_or_default();

        let mut eps: Vec<_> = ctx.entry_points.iter().collect();
        eps.sort_by(|a, b| (&a.file, &a.function).cmp(&(&b.file, &b.function)));
        let entry_points = ids_for(eps.len(), "E")
            .into_iter()
            .zip(eps)
            .map(|(eid, e)| {
                (
                    eid,
                    InventoryEntryPoint {
                        file_id: file_id(&e.file),
                        function: e.function.clone(),
                        kind: ep_kind_str(e.kind),
                        unauth: e.reachable_from_unauth,
                    },
                )
            })
            .collect();

        let mut sinks: Vec<_> = ctx.unsafe_sinks.iter().collect();
        sinks.sort_by(|a, b| (&a.file, a.line, &a.function).cmp(&(&b.file, b.line, &b.function)));
        let sinks = ids_for(sinks.len(), "K")
            .into_iter()
            .zip(sinks)
            .map(|(kid, s)| {
                (
                    kid,
                    InventorySink {
                        file_id: file_id(&s.file),
                        function: s.function.clone(),
                        cwe: s.cwe.clone(),
                    },
                )
            })
            .collect();

        IdInventory {
            files,
            entry_points,
            sinks,
        }
    }

    /// The FILE INVENTORY block: the only block that binds an id to a real
    /// path. Every other prompt block keeps readable paths, because the
    /// directory and file name carry risk signal a bare id would strip.
    pub fn render(&self, repo_root: &Path) -> Vec<String> {
        let mut out =
            vec!["FILE INVENTORY (authoritative — the ONLY files that exist):".to_string()];
        for (fid, path) in &self.files {
            out.push(format!(
                "  {fid}  {path}  ({} LOC)",
                nonblank_loc(repo_root, path)
            ));
        }
        if !self.entry_points.is_empty() {
            out.push("ENTRY POINTS:".to_string());
            for (eid, e) in &self.entry_points {
                let unauth = if e.unauth { ", UNAUTH" } else { "" };
                out.push(format!(
                    "  {eid}  {}::{}  [{}{unauth}]",
                    e.file_id, e.function, e.kind
                ));
            }
        }
        if !self.sinks.is_empty() {
            out.push("SINKS:".to_string());
            for (kid, s) in &self.sinks {
                let cwe = if s.cwe.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", s.cwe.join(", "))
                };
                out.push(format!("  {kid}  {}::{}{cwe}", s.file_id, s.function));
            }
        }
        out.push(
            "Every chunk file reference MUST resolve to one of the F### ids above — this is \
             the complete set; nothing outside it exists in this repository."
                .to_string(),
        );
        out
    }
}

/// Non-blank line count of one inventory file, confined to `repo_root`
/// (the list is repo-derived, but a `../` entry must never be read). `0`
/// for anything unreadable, as upstream's `except OSError`.
fn nonblank_loc(repo_root: &Path, rel: &str) -> usize {
    let Some(path) = bc_pathjail::confine(repo_root, rel) else {
        return 0;
    };
    let Ok(file) = std::fs::File::open(path) else {
        return 0;
    };
    BufReader::new(file)
        .split(b'\n')
        .map_while(Result::ok)
        .filter(|line| line.iter().any(|b| !b.is_ascii_whitespace()))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_model::{EntryPoint, EntryPointKind, Sink};

    fn ctx() -> ContextPackage {
        ContextPackage::default()
    }

    #[test]
    fn ids_are_zero_padded_to_at_least_three_digits() {
        assert_eq!(ids_for(2, "F"), vec!["F001", "F002"]);
        assert_eq!(ids_for(1000, "F")[999], "F1000");
        assert_eq!(ids_for(1000, "F")[0], "F0001");
        assert!(ids_for(0, "F").is_empty());
    }

    #[test]
    fn files_are_numbered_in_sorted_order_after_deduplication() {
        let mut c = ctx();
        c.all_files = vec!["b.py".into(), "a.py".into(), "b.py".into()];
        let inv = IdInventory::build(&c);
        assert_eq!(inv.files.len(), 2);
        assert_eq!(inv.files["F001"], "a.py");
        assert_eq!(inv.files["F002"], "b.py");
    }

    #[test]
    fn entry_points_and_sinks_are_sorted_and_point_at_file_ids() {
        let mut c = ctx();
        c.all_files = vec!["a.py".into(), "b.py".into()];
        c.entry_points = vec![
            EntryPoint {
                file: "b.py".into(),
                function: "z".into(),
                kind: EntryPointKind::Cli,
                reachable_from_unauth: false,
            },
            EntryPoint {
                file: "a.py".into(),
                function: "y".into(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: true,
            },
            EntryPoint {
                file: "outside.py".into(),
                function: "w".into(),
                kind: EntryPointKind::Network,
                reachable_from_unauth: false,
            },
        ];
        c.unsafe_sinks = vec![
            Sink {
                file: "b.py".into(),
                line: 9,
                function: "exec".into(),
                snippet: String::new(),
                cwe: vec!["CWE-78".into()],
            },
            Sink {
                file: "b.py".into(),
                line: 3,
                function: "query".into(),
                snippet: String::new(),
                cwe: Vec::new(),
            },
        ];
        let inv = IdInventory::build(&c);
        assert_eq!(inv.entry_points["E001"].function, "y");
        assert_eq!(inv.entry_points["E001"].file_id, "F001");
        assert_eq!(inv.entry_points["E002"].function, "z");
        assert_eq!(inv.entry_points["E002"].file_id, "F002");
        // An entry point outside the inventory keeps an empty file id.
        assert_eq!(inv.entry_points["E003"].function, "w");
        assert_eq!(inv.entry_points["E003"].file_id, "");
        assert_eq!(inv.sinks["K001"].function, "query");
        assert_eq!(inv.sinks["K002"].cwe, vec!["CWE-78".to_string()]);

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "x = 1\n\n   \ny = 2\n").unwrap();
        let text = inv.render(dir.path()).join("\n");
        assert!(text.starts_with("FILE INVENTORY (authoritative"));
        assert!(text.contains("  F001  a.py  (2 LOC)"));
        assert!(text.contains("  F002  b.py  (0 LOC)"));
        assert!(text.contains("  E001  F001::y  [network, UNAUTH]"));
        assert!(text.contains("  E002  F002::z  [cli]"));
        assert!(text.contains("  K001  F002::query\n"));
        assert!(text.contains("  K002  F002::exec  [CWE-78]"));
        assert!(text.ends_with("nothing outside it exists in this repository."));
    }

    #[test]
    fn an_empty_context_renders_only_the_frame() {
        let text = IdInventory::build(&ctx()).render(Path::new("/nonexistent"));
        assert_eq!(text.len(), 2);
        assert!(!text.join("\n").contains("ENTRY POINTS:"));
        assert!(!text.join("\n").contains("SINKS:"));
    }

    #[test]
    fn a_path_escaping_the_repo_counts_zero_lines() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(nonblank_loc(dir.path(), "../../etc/passwd"), 0);
        assert_eq!(nonblank_loc(dir.path(), "missing.py"), 0);
    }
}
