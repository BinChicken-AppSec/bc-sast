mod coerce;
mod context;
mod diagnostics;
mod diff_scope;
mod digest;
mod finding;
mod identity;
mod manifest;
mod provider_report;
mod report;
pub use provider_report::{ProviderAssessmentRecord, ProviderIngestionRecord, ProviderLedger};
mod provider;
pub use provider::{
    ComponentRef, ProviderKind, ProviderNativeIds, ProviderOrigin, ProviderProduct, ProviderSource,
};

pub use context::{
    Actor, AppProfile, Asset, ContextPackage, Control, ControlKind, EntryPoint, EntryPointKind,
    Impact, Likelihood, ModuleInfo, Reach, Sensitivity, Sink, TaintEvidencePath, TaintSymbolRef,
    TaintTransferEdge, Threat, ThreatModel, TrustBoundary,
};
pub use diagnostics::{
    AutoExcludeCounts, DecomposeCounts, DeepdiveCounts, PipelineDiagnostics, PrefilterCounts,
    ThreatModelCounts, VerifyCounts,
};
pub use diff_scope::DiffScope;
pub use digest::{
    product_name, severity_rank, vendor_name, ProviderDependencyAlert, ProviderDigest,
    ProviderHotspot, MAX_DIGEST_DEPENDENCIES, MAX_DIGEST_HOTSPOTS,
};
pub use finding::{DupLocation, Finding, Verdict, VulnClass};
pub use identity::{FileDisposition, RepoIdentity, RepoKey, RepoKeySource};
pub use manifest::{Chunk, ChunkSize, TaskManifest};
pub use report::{
    offensive_label, Chain, DropReason, DroppedFinding, FinalReport, RankedFinding, ScanMetrics,
    ScopeEntry, ScopeKind, Severity, StageTiming, VerificationEvidence,
};
