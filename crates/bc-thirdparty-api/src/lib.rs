//! Live vendor SAST/SCA API clients — a companion to `bc-thirdparty`'s
//! file-based ingestion parsers, for operators who want the latest scan
//! for a given project (and branch, where the vendor's API supports it)
//! fetched directly rather than exported by hand. Each vendor module
//! converts its own API response into `bc_thirdparty::ThirdPartyFinding`,
//! the same normalized shape the file-based parsers produce, so callers
//! don't need to care which path a finding came from.
//!
//! Confidence differs materially per vendor — see each module's own doc
//! comment for exactly what was confirmed against a live OpenAPI spec
//! versus inferred from documentation prose, and which items are
//! flagged as genuinely uncertain pending real-account validation.
//! Semgrep, Snyk and Aikido all publish machine-readable OpenAPI specs
//! (Aikido's is embedded in its docs site rather than served standalone);
//! Checkmarx One is the weakest, with only JS-rendered docs plus the
//! OpenAPI documents vendored in its own SDK/CLI repositories.
//!
//! Every client routes its requests through [`retry`], so a transient
//! `429`/`502`/`503`/`504` costs a short backoff instead of the vendor's
//! entire finding set (a live-fetch error is only a WARN in
//! `bc-orchestrator`, never a scan failure).

mod oauth2;
mod retry;
mod timestamp;

pub mod aikido;
pub mod checkmarx;
pub mod semgrep;
pub mod snyk;
pub mod sonatype;
pub mod writeback;

pub mod publish;
