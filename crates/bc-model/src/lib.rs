//! Cross-stage domain model, ported from the Python reference's
//! `models.py` — the pipeline's pydantic DTO spine, minus its Markdown
//! rendering (`FinalReport::to_markdown`, a 900+ line method living on
//! the model in the Python original) and its prompt-assembly methods
//! (`to_prompt_block` and friends), which either do real filesystem I/O
//! (`ContextPackage._signatures_block` reads source excerpts) or are
//! stage-specific text assembly rather than data-model concerns. Those
//! belong to `bc-report-md` and to whichever stage crate consumes this
//! data, respectively — this crate is pure data + the lenient
//! LLM-JSON-coercion deserializers.

mod coerce;
mod context;
mod diagnostics;
mod diff_scope;
mod finding;
mod manifest;
mod provider_report;
mod report;
pub use provider_report::{ProviderAssessmentRecord, ProviderIngestionRecord, ProviderLedger};
mod provider;
pub use provider::{
    ProviderKind, ProviderNativeIds, ProviderOrigin, ProviderProduct, ProviderSource,
};

pub use context::{
    Actor, AppProfile, Asset, ContextPackage, Control, ControlKind, Cve, EntryPoint,
    EntryPointKind, Impact, Likelihood, ModuleInfo, Sensitivity, Sink, TaintEvidencePath,
    TaintSymbolRef, TaintTransferEdge, Threat, ThreatModel, TrustBoundary,
};
pub use diagnostics::{
    AutoExcludeCounts, DecomposeCounts, DeepdiveCounts, PipelineDiagnostics, PrefilterCounts,
    ThreatModelCounts, VerifyCounts,
};
pub use diff_scope::DiffScope;
pub use finding::{DupLocation, Finding, Verdict, VulnClass};
pub use manifest::{Chunk, ChunkSize, TaskManifest};
pub use report::{
    offensive_label, Chain, DropReason, DroppedFinding, FinalReport, RankedFinding, ScanMetrics,
    ScopeEntry, ScopeKind, Severity, StageTiming, VerificationEvidence,
};
