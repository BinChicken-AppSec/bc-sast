//! Deterministic, LLM-free repo analysis shared by S1 (preprocess) and S3
//! (decompose): repo walk, config-file structural dedup, call-graph
//! validation/supplementation, and BFS taint-path chunking. Ported from
//! `vvaharness/pipeline/stages/s1_preprocess.py` and `s3_decompose.py`.

mod callgraph;
mod dedup;
mod fnmatch;
mod frontier;
mod graph_view;
mod lang;
mod reachability;
mod source;
mod syntax;
mod taint;
mod ts_graph;
mod walk;

pub use callgraph::{
    q_file, q_join, q_name, q_split, resolve_callee_files, scan_defs, supplement_call_graph,
    CallGraphConfig, CallGraphReport, CallGraphResult, SOURCE_EXTENSIONS,
};
pub use dedup::{dedup_configs, ClusterSummary, DedupConfig, DedupReport};
pub use fnmatch::{default_exclude_globs, fnmatch, glob_hit};
pub use frontier::{ast_context_view, FrontierConfig};
pub use graph_view::{
    best_source_from_seed, entry_anchor_lines, neighborhood, parse_hop, qnodes_at,
    seed_paths_by_file, seed_reachable_files, GraphView, Neighbors,
};
pub use lang::{detect_languages, ext_to_lang, is_iac_file, lang_display, suffix_lower};
pub use reachability::{reachable_files, reachable_only_too_sparse};
pub use source::{is_source, lang_of_file};
pub use syntax::syntax_check;
pub use taint::{
    add_taint_chunks, bfs_to_sinks, pick_hop_files, size_for, threat_for, TaintChunkConfig,
    TaintChunkResult,
};
pub use ts_graph::{build as ts_graph_build, TsGraphResult};
pub use walk::{
    walk_repo, ExclusionReport, WalkConfig, DEFAULT_EXCLUDE_DIRS, DEFAULT_EXCLUDE_EXTS,
};
