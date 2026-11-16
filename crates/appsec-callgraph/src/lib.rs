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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EntryPoint {
    pub file: String,
    pub function: String,
    pub kind: String,
    pub reachable_from_unauth: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Sink {
    pub file: String,
    pub line: usize,
    pub function: String,
    pub snippet: String,
    pub cwe: Vec<String>,
}
