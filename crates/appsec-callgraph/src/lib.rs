//! S0 — Static seed: tree-sitter-native source→sink call-graph seeding.
//! Ported from `vvaharness/pipeline/stages/callgraph_engine/` and
//! `vvaharness/rules/families.py`.
//!
//! Scans in-scope source with tree-sitter, matches source/sink call
//! sites against configured or LLM-derived [`MatchSpec`]s, and builds a
//! static call graph the S0 pipeline stage turns into a seed package for
//! S1 (skipping or narrowing its own agentic exploration) and S3
//! (taint-chunk construction).

pub mod annotator;
pub mod evidence;
pub mod facts;
pub mod families;
pub mod framework;
pub mod graph;
pub mod reflection;
pub mod rules;
pub mod scan;

pub use annotator::{collect_candidates, supplement_with_heuristics, Candidate};
pub use evidence::{TaintEvidencePath, TaintSymbolRef, TaintTransferEdge};
pub use graph::{build_taint_paths, TaintSeed};
pub use rules::{load_rulepacks, MatchSpec};
pub use scan::{
    scan_file, CallSite, ContainerWriteFact, FieldReadFact, FieldWriteFact, FileIndex,
    FrameworkMarkerFact, FuncDef, ObservedCall, ReflectionFact, ResponseDataflowFact,
    RouteTaintFact,
};

/// A source-of-taint call site, deduped by `(file, containing_fn)`.
/// Ported from the fields `_graph.py::build_taint_paths` actually
/// populates on `vvaharness.models.EntryPoint`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntryPoint {
    pub file: String,
    pub function: String,
    pub kind: String,
    /// Whether this handler can be reached without authenticating.
    ///
    /// Always `false` upstream — `_graph.py`'s two `EntryPoint(...)`
    /// construction sites pass `file`/`function`/`kind` only, so the
    /// pydantic `= False` default stands for every seed entry point and
    /// nothing but the S1 agent's own JSON can change it. That is
    /// backwards for the field's meaning: a repo with no authentication
    /// anywhere reports every route as authenticated. Framework entry
    /// points get the honest answer here, from the auth evidence
    /// [`crate::scan::AuthGuardFact`] records; reachability-derived
    /// entry points keep `false`, since a call site says nothing about
    /// the route that reaches it. See
    /// [`crate::evidence::emit_framework_entry_points`].
    pub reachable_from_unauth: bool,
}

/// An unsafe sink call site, deduped by `(file, line, function)`.
/// Ported from the fields `_graph.py::build_taint_paths` actually
/// populates on `vvaharness.models.Sink`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sink {
    pub file: String,
    pub line: usize,
    pub function: String,
    pub snippet: String,
    pub cwe: Vec<String>,
}
