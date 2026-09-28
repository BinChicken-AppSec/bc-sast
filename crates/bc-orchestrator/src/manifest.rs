//! The run manifest: one JSON record of what a whole invocation did,
//! ported from the Python original's `manifest.py` (`capture`,
//! `_scrub_argv`) and `util/stage_telemetry.py` (`compose_stage_section`).
//!
//! It is the one output that sees the FULL run. The Markdown and SARIF
//! reports are rendered at S9, before remediation, so S10/S11's timing
//! and spend appear here and nowhere else.
//!
//! This module is pure: [`StageTelemetry`] folds the scan's own
//! [`ScanEvent`] stream into per-stage records, and [`compose`] turns
//! those plus the caller's run facts into a [`RunManifest`]. Reading
//! files, hashing them and writing the result are `bc-cli`'s job.
//!
//! **Deliberate divergences from Python.**
//! - Stage records come from the event stream, not a process-wide
//!   singleton, so a batch run's repositories cannot bleed into each
//!   other's records.
//! - Costs are the per-call exact figures this port already computes
//!   (see [`crate::pricing`]), not Python's per-phase role-mapped
//!   estimate, so `cost_estimated` means something narrower here: the
//!   stage's cost is a lower bound because some of its tokens had no
//!   published rate.
//! - Model calls made outside any stage (the startup credential probe,
//!   `--auto-step1`) are not metered at all, so there is no
//!   `unattributed` bucket.
//! - The serialized manifest is redacted as a whole
//!   ([`RunManifest::to_json`]), not only its argv: stage details carry
//!   error text, and a manifest is exactly the kind of artifact that
//!   outlives the process and lands in shared logs.

use std::collections::BTreeMap;

use bc_pipeline_core::{stage_id, stage_label, ScanEvent, StageStatus, StageUsage, STAGE_IDS};
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Bumped whenever a field changes meaning or disappears. Adding a field
/// does not bump it.
pub const RUN_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// What one stage did, folded from its events. `None` fields mean the
/// stream never said (a stage with spend but no finish, say).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StageRecord {
    pub started: bool,
    pub status: Option<StageStatus>,
    pub duration_sec: Option<f64>,
    pub counts: Vec<(&'static str, u64)>,
    pub detail: Option<String>,
    pub usage: Option<StageUsage>,
}

/// Every stage's [`StageRecord`], keyed by short stage id. Built by
/// feeding it the scan's events in order ([`StageTelemetry::record`]);
/// the Rust counterpart of Python's `STAGES` recorder plus the per-phase
/// `TOKENS` buckets.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StageTelemetry {
    stages: BTreeMap<String, StageRecord>,
}

impl StageTelemetry {
    /// Folds one event in. Events that describe no stage lifecycle or
    /// spend (chunk progress, running findings counts) are ignored.
    pub fn record(&mut self, event: &ScanEvent) {
        match event {
            ScanEvent::StageStarted { stage } => {
                self.entry(stage).started = true;
            }
            ScanEvent::StageFinished {
                stage,
                status,
                duration,
                counts,
                detail,
            } => {
                let record = self.entry(stage);
                record.status = Some(*status);
                record.duration_sec = duration.map(|d| d.as_secs_f64());
                record.counts = counts.clone();
                record.detail = detail.clone();
            }
            ScanEvent::UsageUpdate { stage, usage } => {
                let record = self.entry(stage);
                record.usage = Some(match record.usage {
                    Some(prior) => add_usage(prior, *usage),
                    None => *usage,
                });
            }
            ScanEvent::ChunkProgress { .. }
            | ScanEvent::VerifyProgress { .. }
            | ScanEvent::FindingsCount { .. } => {}
        }
    }

    /// One stage's record by short id (`"s4"`), if the stream mentioned it.
    pub fn get(&self, id: &str) -> Option<&StageRecord> {
        self.stages.get(id)
    }

    /// Every recorded stage in pipeline order (`s0`..`s11`), with any id
    /// outside that list after them, the order Python's
    /// `_ordered_stage_ids` gives.
    pub fn ordered(&self) -> Vec<(&str, &StageRecord)> {
        let known = STAGE_IDS
            .iter()
            .filter_map(|id| self.stages.get_key_value(*id));
        let extra = self
            .stages
            .iter()
            .filter(|(id, _)| !STAGE_IDS.contains(&id.as_str()));
        known
            .chain(extra)
            .map(|(id, record)| (id.as_str(), record))
            .collect()
    }

    fn entry(&mut self, stage: &str) -> &mut StageRecord {
        self.stages.entry(stage_id(stage).to_string()).or_default()
    }
}

/// Two usage updates for one stage, summed. The cost stays `None` only
/// when neither half priced anything.
fn add_usage(a: StageUsage, b: StageUsage) -> StageUsage {
    StageUsage {
        prompt_tokens: a.prompt_tokens + b.prompt_tokens,
        completion_tokens: a.completion_tokens + b.completion_tokens,
        cache_read_tokens: a.cache_read_tokens + b.cache_read_tokens,
        cache_write_tokens: a.cache_write_tokens + b.cache_write_tokens,
        calls: a.calls + b.calls,
        cost_usd: add_cost(a.cost_usd, b.cost_usd),
        unpriced_tokens: a.unpriced_tokens + b.unpriced_tokens,
        truncated_replies: a.truncated_replies + b.truncated_replies,
    }
}

fn add_cost(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0.0) + b.unwrap_or(0.0)),
    }
}

/// One stage's (or the run's) tokens. `input` is billable input, fresh
/// plus cache writes, the same figure the report calls "prompt"; cache
/// reads are kept out of it and reported on their own, and
/// `cache_write` is broken out although it is already inside `input`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenCounts {
    pub input: i64,
    pub output: i64,
    pub cache_read: i64,
    pub cache_write: i64,
    pub calls: i64,
}

impl TokenCounts {
    fn from_usage(usage: &StageUsage) -> Self {
        TokenCounts {
            input: usage.prompt_tokens,
            output: usage.completion_tokens,
            cache_read: usage.cache_read_tokens,
            cache_write: usage.cache_write_tokens,
            calls: usage.calls,
        }
    }

    fn add(&mut self, other: TokenCounts) {
        self.input += other.input;
        self.output += other.output;
        self.cache_read += other.cache_read;
        self.cache_write += other.cache_write;
        self.calls += other.calls;
    }
}

/// One `stages.<id>` object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestStage {
    pub label: String,
    /// A [`StageStatus`] spelling, or `error` for a stage that started and
    /// never finished (the scan aborted inside it).
    pub outcome: String,
    pub duration_sec: Option<f64>,
    pub tokens: TokenCounts,
    /// `None` when no call this stage made could be priced.
    pub cost_usd: Option<f64>,
    /// `true` when `cost_usd` is a lower bound: some of this stage's
    /// tokens had no published rate.
    pub cost_estimated: bool,
    #[serde(default)]
    pub counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub detail: Option<String>,
}

/// The `stages` map, serialized in pipeline order rather than a
/// `BTreeMap`'s lexical one (which would put `s10` before `s2`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ManifestStages(pub Vec<(String, ManifestStage)>);

impl Serialize for ManifestStages {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (id, stage) in &self.0 {
            map.serialize_entry(id, stage)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ManifestStages {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StagesVisitor;
        impl<'de> Visitor<'de> for StagesVisitor {
            type Value = ManifestStages;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a map of stage id to stage entry")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut stages = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    stages.push(entry);
                }
                Ok(ManifestStages(stages))
            }
        }
        deserializer.deserialize_map(StagesVisitor)
    }
}

/// The manifest's `totals`: every stage summed. The Python identity
/// `sum(stages) = totals` holds for every token key, since there is no
/// unattributed bucket here.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ManifestTotals {
    pub tokens: TokenCounts,
    /// Sum of every priced stage; `None` when nothing was priced. A lower
    /// bound whenever `unpriced_tokens` is non-zero.
    pub cost_usd: Option<f64>,
    pub unpriced_tokens: i64,
}

/// One model role's routing, never its credentials. `gateway_host` is
/// the host alone: no scheme, port, path, query or userinfo, any of which
/// can carry a tenant id or a token.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ModelEntry {
    pub id: String,
    pub dialect: String,
    pub gateway_host: Option<String>,
    pub pricing_provider: Option<String>,
    /// Which wire API the role's calls use: `chat`, `responses` or
    /// `auto` on the OpenAI dialect (the role's pin, else the client's
    /// `--openai-api`), `messages` on the Anthropic one. Filled by
    /// `bc-cli`; `None` only in a manifest written before it was.
    #[serde(default)]
    pub transport: Option<String>,
}

/// A hashed input file. `sha256` is `None` when the file could not be
/// read: a manifest records what it could, it never fails the run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InputHash {
    pub path: String,
    pub sha256: Option<String>,
}

/// What was scanned.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ManifestTarget {
    pub repo_name: Option<String>,
    pub git_sha: Option<String>,
}

/// S10/S11's counters, lifted out of their stage entries into one
/// summary (Python's `remediation` rollup). Present only when S10 ran;
/// the validation half only when S11 did, since a validation rollup with
/// no validation is unknown rather than clean.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RemediationRollup {
    pub attempted: u64,
    pub fixed: u64,
    pub not_fixed: u64,
    pub failed: u64,
    pub validated: Option<u64>,
    pub validation_passed: Option<u64>,
    pub validation_failed: Option<u64>,
}

/// The run manifest itself.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunManifest {
    pub schema_version: u32,
    pub tool: String,
    pub tool_version: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_sec: f64,
    pub exit_code: i32,
    /// `true` when the operator canceled the run (Ctrl-C): the stages it
    /// no longer reached are recorded as skipped, and `exit_code` is 130.
    #[serde(default)]
    pub canceled: bool,
    /// The command line, with every secret-bearing flag's value replaced
    /// and the rest shape-redacted ([`scrub_argv`]).
    pub argv: Vec<String>,
    pub config_path: Option<String>,
    pub config_sha256: Option<String>,
    /// The `config.local.yaml` overlay that was actually applied, hashed
    /// so the manifest records the effective configuration.
    pub local_overlay_sha256: Option<String>,
    pub input_hashes: BTreeMap<String, InputHash>,
    pub target: ManifestTarget,
    pub models: BTreeMap<String, ModelEntry>,
    pub stages: ManifestStages,
    pub totals: ManifestTotals,
    pub errors_by_stage: BTreeMap<String, u64>,
    pub remediation: Option<RemediationRollup>,
    pub counters: BTreeMap<String, u64>,
}

impl RunManifest {
    /// The manifest as pretty JSON, redacted as a whole
    /// (`bc_redact::redact_tree`) so no string field, argv or otherwise,
    /// can carry a secret-shaped value to disk.
    ///
    /// The redaction round-trips through `serde_json::Value`, whose maps
    /// are sorted, so the stages are put back in pipeline order before the
    /// struct itself (not the `Value`) is written.
    pub fn to_json(&self) -> String {
        let value = serde_json::to_value(self).expect("RunManifest always serializes");
        let mut redacted: RunManifest = serde_json::from_value(bc_redact::redact_tree(&value))
            .expect("redact_tree preserves JSON shape, so RunManifest deserializes back");
        redacted
            .stages
            .0
            .sort_by_key(|(id, _)| pipeline_position(id));
        serde_json::to_string_pretty(&redacted).expect("RunManifest always serializes")
    }
}

/// Where a stage id sorts: its place in [`STAGE_IDS`], or after all of
/// them.
fn pipeline_position(id: &str) -> usize {
    STAGE_IDS
        .iter()
        .position(|s| *s == id)
        .unwrap_or(STAGE_IDS.len())
}

/// Everything about the run the event stream does not know, supplied by
/// the caller.
#[derive(Debug, Clone, Default)]
pub struct RunFacts {
    pub tool_version: String,
    pub started_at: String,
    pub finished_at: String,
    pub duration_sec: f64,
    pub exit_code: i32,
    pub canceled: bool,
    /// Raw; [`compose`] scrubs it.
    pub argv: Vec<String>,
    pub config_path: Option<String>,
    pub config_sha256: Option<String>,
    pub local_overlay_sha256: Option<String>,
    pub input_hashes: BTreeMap<String, InputHash>,
    pub target: ManifestTarget,
    pub models: BTreeMap<String, ModelEntry>,
}

/// Builds the manifest from the run's facts and its stage telemetry.
pub fn compose(facts: RunFacts, telemetry: &StageTelemetry) -> RunManifest {
    let mut totals = ManifestTotals::default();
    let mut truncated = 0u64;
    let mut stages = Vec::new();
    for (id, record) in telemetry.ordered() {
        let usage = record.usage.unwrap_or_default();
        let tokens = TokenCounts::from_usage(&usage);
        totals.tokens.add(tokens);
        totals.cost_usd = add_cost(totals.cost_usd, usage.cost_usd);
        totals.unpriced_tokens += usage.unpriced_tokens;
        truncated += usage.truncated_replies;
        stages.push((
            id.to_string(),
            ManifestStage {
                label: stage_label(id).unwrap_or(id).to_string(),
                outcome: stage_outcome(record).to_string(),
                duration_sec: record.duration_sec,
                tokens,
                cost_usd: usage.cost_usd,
                cost_estimated: usage.cost_usd.is_some() && usage.unpriced_tokens > 0,
                counts: record
                    .counts
                    .iter()
                    .map(|(name, n)| (name.to_string(), *n))
                    .collect(),
                detail: record.detail.clone(),
            },
        ));
    }
    RunManifest {
        schema_version: RUN_MANIFEST_SCHEMA_VERSION,
        tool: "bc-sast".to_string(),
        tool_version: facts.tool_version,
        started_at: facts.started_at,
        finished_at: facts.finished_at,
        duration_sec: facts.duration_sec,
        exit_code: facts.exit_code,
        canceled: facts.canceled,
        argv: scrub_argv(&facts.argv),
        config_path: facts.config_path,
        config_sha256: facts.config_sha256,
        local_overlay_sha256: facts.local_overlay_sha256,
        input_hashes: facts.input_hashes,
        target: facts.target,
        models: facts.models,
        errors_by_stage: errors_by_stage(telemetry),
        remediation: remediation_rollup(telemetry),
        counters: BTreeMap::from([("llm_truncated_replies".to_string(), truncated)]),
        stages: ManifestStages(stages),
        totals,
    }
}

/// A finished stage's status; `error` for one that started and never
/// finished, which only an aborted scan leaves behind; `not_run` for a
/// stage the stream only reported spend for.
fn stage_outcome(record: &StageRecord) -> &'static str {
    match (record.status, record.started) {
        (Some(status), _) => status.as_str(),
        (None, true) => StageStatus::Error.as_str(),
        (None, false) => "not_run",
    }
}

fn count_of(record: &StageRecord, name: &str) -> Option<u64> {
    record
        .counts
        .iter()
        .find_map(|(n, value)| (*n == name).then_some(*value))
}

/// Per-stage error counts, the manifest's view of scan health. Coarser
/// than Python's `errlog`-backed tally, for the same reason
/// `ScanMetrics::errors_by_stage` is: S4 counts its failed chunks and S10
/// its failed sessions; every other stage that closed with errors (or
/// never closed) counts once.
fn errors_by_stage(telemetry: &StageTelemetry) -> BTreeMap<String, u64> {
    telemetry
        .ordered()
        .into_iter()
        .filter_map(|(id, record)| {
            let specific = match id {
                "s4" => count_of(record, "chunks_failed"),
                "s10" => count_of(record, "failed"),
                _ => None,
            };
            let erred = matches!(stage_outcome(record), "error" | "completed_with_errors");
            let n = match specific {
                Some(n) if n > 0 => n,
                _ => u64::from(erred),
            };
            (n > 0).then(|| (id.to_string(), n))
        })
        .collect()
}

/// The remediation rollup, present only when S10 actually ran.
fn remediation_rollup(telemetry: &StageTelemetry) -> Option<RemediationRollup> {
    let s10 = telemetry
        .get("s10")
        .filter(|r| r.status.is_some_and(|s| s != StageStatus::Disabled))?;
    let s11 = telemetry
        .get("s11")
        .filter(|r| r.status.is_some_and(|s| s != StageStatus::Disabled));
    let s10_count = |name| count_of(s10, name).unwrap_or(0);
    let s11_count = |name| s11.and_then(|r| count_of(r, name));
    Some(RemediationRollup {
        attempted: s10_count("attempted"),
        fixed: s10_count("fixed"),
        not_fixed: s10_count("not_fixed"),
        failed: s10_count("failed"),
        validated: s11_count("validated"),
        validation_passed: s11_count("passed"),
        validation_failed: s11_count("failed"),
    })
}

/// Whether a command-line flag's value is likely a secret: Python's
/// `_SECRET_FLAG_RX` substrings (`token`, `password`, `secret`,
/// `api-key`, `auth`, `credential`, `bearer`, ...), plus any flag with a
/// whole `key` word in it (`--client-key`), which Python leaves out only
/// because a bare `key` substring would also catch `--keep-clones`.
/// Matching `key` as a word catches the key flags without that false
/// positive. Over-matching is the safe direction: scrubbing a harmless
/// value costs a manifest reader nothing.
fn is_secret_flag(flag: &str) -> bool {
    const SECRET_PARTS: [&str; 12] = [
        "token",
        "password",
        "passwd",
        "pwd",
        "secret",
        "apikey",
        "api-key",
        "api_key",
        "access-key",
        "auth",
        "credential",
        "bearer",
    ];
    let name = flag.trim_start_matches('-').to_ascii_lowercase();
    SECRET_PARTS.iter().any(|part| name.contains(part))
        || name.split(['-', '_']).any(|word| word == "key")
}

/// Ported from Python's `manifest._scrub_argv`: the value of every
/// secret-bearing flag is replaced with `***`, in both the `--flag VALUE`
/// and `--flag=VALUE` forms, then every element is shape-redacted
/// (`bc_redact::redact`) so a secret passed under an innocent flag (a
/// URL with userinfo, a token in a path) is caught too.
pub fn scrub_argv(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut i = 0;
    while i < argv.len() {
        let token = &argv[i];
        if token.starts_with('-') {
            if let Some((flag, value)) = token.split_once('=') {
                if !value.is_empty() && is_secret_flag(flag) {
                    out.push(format!("{flag}=***"));
                    i += 1;
                    continue;
                }
            } else if is_secret_flag(token)
                && argv.get(i + 1).is_some_and(|next| !next.starts_with('-'))
            {
                out.push(token.clone());
                out.push("***".to_string());
                i += 2;
                continue;
            }
        }
        out.push(token.clone());
        i += 1;
    }
    out.iter().map(|arg| bc_redact::redact(arg)).collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn scrub_argv_replaces_secret_flag_values_in_both_forms() {
        let argv = strings(&[
            "bc-sast",
            "--repo",
            "/src/app",
            "--gateway-api-key",
            "sk-live-value",
            "--git-token=ghtoken-value",
            "--client-key",
            "/keys/client.pem",
            "--sonatype-password",
            "hunter2hunter2",
            "--aikido-client-secret",
            "shh-value",
            "--keep-clones",
            "--model",
            "opus",
        ]);
        let scrubbed = scrub_argv(&argv);
        assert_eq!(
            scrubbed,
            strings(&[
                "bc-sast",
                "--repo",
                "/src/app",
                "--gateway-api-key",
                "***",
                "--git-token=***",
                "--client-key",
                "***",
                "--sonatype-password",
                "***",
                "--aikido-client-secret",
                "***",
                "--keep-clones",
                "--model",
                "opus",
            ])
        );
    }

    #[test]
    fn scrub_argv_leaves_a_valueless_or_flag_followed_secret_flag_alone() {
        // `--github-token` followed by another flag took no value; an
        // empty `--x-token=` carries nothing to hide.
        let argv = strings(&["--github-token", "--resume", "--snyk-token=", "--git-token"]);
        assert_eq!(scrub_argv(&argv), argv);
    }

    #[test]
    fn scrub_argv_shape_redacts_a_secret_under_an_innocent_flag() {
        let argv = strings(&[
            "--gateway-base-url",
            "https://user:s3cretpass@gw.example.com/v1",
        ]);
        let scrubbed = scrub_argv(&argv);
        assert_eq!(scrubbed[0], "--gateway-base-url");
        assert!(!scrubbed[1].contains("s3cretpass"), "{}", scrubbed[1]);
    }

    #[test]
    fn secret_flag_matching_is_by_substring_or_whole_key_word() {
        for flag in [
            "--gateway-api-key",
            "--checkmarx-api-key",
            "--git-token",
            "--auth-header",
            "--client-key",
            "--db_pwd",
            "--private_key",
        ] {
            assert!(is_secret_flag(flag), "{flag}");
        }
        for flag in ["--keep-clones", "--keyboard", "--repo", "--model"] {
            assert!(!is_secret_flag(flag), "{flag}");
        }
    }

    fn finished(
        stage: &'static str,
        status: StageStatus,
        secs: Option<f64>,
        counts: Vec<(&'static str, u64)>,
    ) -> ScanEvent {
        ScanEvent::StageFinished {
            stage,
            status,
            duration: secs.map(Duration::from_secs_f64),
            counts,
            detail: None,
        }
    }

    fn usage(prompt: i64, cost: Option<f64>, unpriced: i64) -> StageUsage {
        StageUsage {
            prompt_tokens: prompt,
            completion_tokens: 1,
            cache_read_tokens: 2,
            cache_write_tokens: 3,
            calls: 1,
            cost_usd: cost,
            unpriced_tokens: unpriced,
            truncated_replies: 1,
        }
    }

    fn sample_telemetry() -> StageTelemetry {
        let mut t = StageTelemetry::default();
        let events = [
            ScanEvent::StageStarted {
                stage: "s1-preprocess",
            },
            ScanEvent::UsageUpdate {
                stage: "s1-preprocess",
                usage: usage(10, Some(0.5), 0),
            },
            finished(
                "s1-preprocess",
                StageStatus::Completed,
                Some(1.5),
                vec![("files", 3)],
            ),
            ScanEvent::ChunkProgress {
                stage: "s4-deepdive",
                completed: 1,
                total: 2,
            },
            ScanEvent::FindingsCount {
                stage: "s4-deepdive",
                count: 1,
            },
            ScanEvent::StageStarted {
                stage: "s4-deepdive",
            },
            ScanEvent::UsageUpdate {
                stage: "s4-deepdive",
                usage: usage(100, Some(1.0), 7),
            },
            finished(
                "s4-deepdive",
                StageStatus::CompletedWithErrors,
                Some(3.0),
                vec![("findings", 1), ("chunks_failed", 2)],
            ),
            finished("s2-threatmodel", StageStatus::Skipped, None, Vec::new()),
            ScanEvent::StageStarted {
                stage: "s10-remediate",
            },
            ScanEvent::UsageUpdate {
                stage: "s10-remediate",
                usage: usage(50, None, 50),
            },
            finished(
                "s10-remediate",
                StageStatus::CompletedWithErrors,
                Some(9.0),
                vec![
                    ("attempted", 2),
                    ("fixed", 1),
                    ("not_fixed", 1),
                    ("failed", 1),
                ],
            ),
            finished("s11-validate", StageStatus::Disabled, None, Vec::new()),
        ];
        for e in &events {
            t.record(e);
        }
        t
    }

    fn facts() -> RunFacts {
        RunFacts {
            tool_version: "1.0.0".to_string(),
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: "2026-01-01T00:01:00Z".to_string(),
            duration_sec: 60.0,
            exit_code: 0,
            argv: strings(&["bc-sast", "--git-token", "abc"]),
            ..RunFacts::default()
        }
    }

    #[test]
    fn a_canceled_run_says_so_in_the_manifest() {
        let mut canceled = facts();
        canceled.canceled = true;
        canceled.exit_code = 130;
        let manifest = compose(canceled, &sample_telemetry());
        assert!(manifest.canceled);
        let json: serde_json::Value = serde_json::from_str(&manifest.to_json()).unwrap();
        assert_eq!(json["canceled"], true);
        assert_eq!(json["exit_code"], 130);
        assert!(!compose(facts(), &sample_telemetry()).canceled);
    }

    #[test]
    fn compose_orders_stages_by_pipeline_position_and_sums_totals() {
        let manifest = compose(facts(), &sample_telemetry());
        let ids: Vec<&str> = manifest
            .stages
            .0
            .iter()
            .map(|(id, _)| id.as_str())
            .collect();
        assert_eq!(ids, ["s1", "s2", "s4", "s10", "s11"]);
        let s4 = &manifest.stages.0[2].1;
        assert_eq!(s4.label, "deep-dive");
        assert_eq!(s4.outcome, "completed_with_errors");
        assert_eq!(s4.duration_sec, Some(3.0));
        assert_eq!(s4.tokens.input, 100);
        // Priced, but with unrated tokens: a lower bound.
        assert!(s4.cost_estimated);
        assert_eq!(s4.counts["chunks_failed"], 2);
        let s2 = &manifest.stages.0[1].1;
        assert_eq!(s2.outcome, "skipped");
        assert_eq!(s2.duration_sec, None);
        assert_eq!(s2.cost_usd, None);
        assert!(!s2.cost_estimated);
        // Unpriced S10: no cost, and so not "estimated" either.
        assert!(!manifest.stages.0[3].1.cost_estimated);

        assert_eq!(manifest.totals.tokens.input, 160);
        assert_eq!(manifest.totals.tokens.calls, 3);
        assert_eq!(manifest.totals.cost_usd, Some(1.5));
        assert_eq!(manifest.totals.unpriced_tokens, 57);
        assert_eq!(manifest.counters["llm_truncated_replies"], 3);
        assert_eq!(manifest.argv, strings(&["bc-sast", "--git-token", "***"]));
        assert_eq!(manifest.schema_version, RUN_MANIFEST_SCHEMA_VERSION);
    }

    #[test]
    fn compose_derives_errors_by_stage_and_the_remediation_rollup() {
        let manifest = compose(facts(), &sample_telemetry());
        assert_eq!(
            manifest.errors_by_stage,
            BTreeMap::from([("s4".to_string(), 2), ("s10".to_string(), 1)])
        );
        let rollup = manifest.remediation.unwrap();
        assert_eq!(rollup.attempted, 2);
        assert_eq!(rollup.fixed, 1);
        assert_eq!(rollup.failed, 1);
        // S11 was disabled: unknown, not zero.
        assert_eq!(rollup.validated, None);
    }

    #[test]
    fn a_rollup_carries_validation_counts_when_s11_ran() {
        let mut t = sample_telemetry();
        t.record(&finished(
            "s11-validate",
            StageStatus::Completed,
            Some(2.0),
            vec![("validated", 1), ("passed", 1), ("failed", 0)],
        ));
        let rollup = compose(facts(), &t).remediation.unwrap();
        assert_eq!(rollup.validated, Some(1));
        assert_eq!(rollup.validation_passed, Some(1));
        assert_eq!(rollup.validation_failed, Some(0));
    }

    #[test]
    fn no_rollup_when_remediation_did_not_run() {
        let mut t = StageTelemetry::default();
        t.record(&finished(
            "s10-remediate",
            StageStatus::Disabled,
            None,
            Vec::new(),
        ));
        assert_eq!(compose(facts(), &t).remediation, None);
        assert_eq!(
            compose(facts(), &StageTelemetry::default()).remediation,
            None
        );
    }

    #[test]
    fn an_unfinished_stage_is_an_error_and_spend_alone_is_not_run() {
        let mut t = StageTelemetry::default();
        t.record(&ScanEvent::StageStarted { stage: "s6-verify" });
        t.record(&ScanEvent::UsageUpdate {
            stage: "s8-chain",
            usage: usage(1, None, 0),
        });
        t.record(&finished(
            "s3-decompose",
            StageStatus::Error,
            Some(0.1),
            Vec::new(),
        ));
        let manifest = compose(facts(), &t);
        let outcome = |id: &str| {
            manifest
                .stages
                .0
                .iter()
                .find(|(s, _)| s == id)
                .map(|(_, e)| e.outcome.clone())
                .unwrap()
        };
        assert_eq!(outcome("s6"), "error");
        assert_eq!(outcome("s8"), "not_run");
        assert_eq!(
            manifest.errors_by_stage,
            BTreeMap::from([("s3".to_string(), 1), ("s6".to_string(), 1)])
        );
    }

    #[test]
    fn repeated_usage_for_one_stage_is_summed() {
        let mut t = StageTelemetry::default();
        for cost in [None, Some(0.25), Some(0.5)] {
            t.record(&ScanEvent::UsageUpdate {
                stage: "s4-deepdive",
                usage: usage(10, cost, 0),
            });
        }
        let usage = t.get("s4").unwrap().usage.unwrap();
        assert_eq!(usage.prompt_tokens, 30);
        assert_eq!(usage.cost_usd, Some(0.75));
        assert_eq!(add_cost(None, None), None);
    }

    #[test]
    fn a_stage_outside_the_pipeline_list_sorts_after_it() {
        let mut t = StageTelemetry::default();
        t.record(&finished(
            "zz-custom",
            StageStatus::Completed,
            None,
            Vec::new(),
        ));
        t.record(&finished(
            "s0-seed",
            StageStatus::Completed,
            None,
            Vec::new(),
        ));
        let ids: Vec<&str> = t.ordered().into_iter().map(|(id, _)| id).collect();
        assert_eq!(ids, ["s0", "zz"]);
        // An unknown id is its own label.
        assert_eq!(compose(facts(), &t).stages.0[1].1.label, "zz");
    }

    #[test]
    fn the_json_keeps_pipeline_order_redacts_and_round_trips() {
        let mut f = facts();
        f.models.insert(
            "deepdive".to_string(),
            ModelEntry {
                id: "claude-opus".to_string(),
                dialect: "anthropic".to_string(),
                gateway_host: Some("gw.example.com".to_string()),
                pricing_provider: Some("anthropic".to_string()),
                transport: None,
            },
        );
        f.input_hashes.insert(
            "cve_file".to_string(),
            InputHash {
                path: "/in/cves.json".to_string(),
                sha256: None,
            },
        );
        let mut t = sample_telemetry();
        t.record(&ScanEvent::StageFinished {
            stage: "s2-threatmodel",
            status: StageStatus::Error,
            duration: Some(Duration::from_secs(1)),
            counts: Vec::new(),
            detail: Some("gateway said password=hunter2hunter2".to_string()),
        });
        let manifest = compose(f, &t);
        let json = manifest.to_json();
        let s10 = json.find("\"s10\"").unwrap();
        let s2 = json.find("\"s2\"").unwrap();
        assert!(s2 < s10, "stages must be in pipeline order: {json}");
        assert!(!json.contains("hunter2hunter2"), "{json}");
        let back: RunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.stages.0.len(), manifest.stages.0.len());
        assert_eq!(
            back.models["deepdive"].gateway_host.as_deref(),
            Some("gw.example.com")
        );
        assert_eq!(back.input_hashes["cve_file"].sha256, None);
    }

    #[test]
    fn stages_must_deserialize_from_a_map() {
        let err = serde_json::from_str::<ManifestStages>("[1, 2]").unwrap_err();
        assert!(err.to_string().contains("a map of stage id"), "{err}");
    }
}
