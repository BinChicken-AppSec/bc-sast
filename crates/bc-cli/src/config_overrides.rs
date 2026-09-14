//! Projects a `bc_config::load`-merged YAML tree onto the typed
//! `Step*Config` structs, ported key-for-key from the Python original's
//! per-stage config sections. Three of the eight sections use an
//! irregular name — `step5_prefilter`/`step6_verify`/`step7_dedup`
//! instead of `step5`/`step6`/`step7` — matching `bc_config::step_defaults`'s
//! own naming exactly.
//!
//! Every `Step*Config` field the Python config schema has an equivalent
//! for is overridden here. Two classes of field are deliberately NOT
//! exposed because they have no Python equivalent at all — Rust-only
//! additions to this port, not omissions:
//! - `retry_backoff_base` on every agentic stage that has it
//!   (`Step1Config`/`Step6Config`/`Step10Config`/`Step11Config` — a
//!   test/production transient-retry timing knob; the Python original
//!   has no exponential-backoff schedule configured via YAML at all).
//! - Per-stage `via` (backend selection) inside `models.<role>` — this
//!   port's `--dialect` is a single global flag, not a per-stage choice;
//!   only `models.<role>.id` (the model identifier) is applied.
//!
//! `max_transient_retries`/`max_context_shrinks` — the other two
//! `bc_llm_agentic::AgenticConfig` retry/shrink knobs each agentic stage
//! forwards — ARE exposed here for every stage that has them, same as
//! `max_turns`; there's nothing Rust-only about how many times a turn
//! retries or shrinks its context, only about the timing between
//! attempts.
//!
//! Each `apply_stepN` function reads every field it knows about
//! unconditionally when the section is present — `bc_config::load`
//! always deep-merges `step_defaults()` underneath any user YAML, so
//! every key below is normally populated with at least the Python
//! shipped default, not just user-supplied overrides. A field that's
//! missing or the wrong JSON type is left at whatever the caller's
//! `Step*Config::new()` already set, rather than erroring — config
//! loading itself is fail-closed (a malformed *file* is a hard error via
//! `bc_config::load`), but one malformed *field* silently keeping its
//! constructed default is the same leniency `bc-config`'s own coercion
//! layer already applies elsewhere.

use serde::de::DeserializeOwned;
use serde_json::Value;

use bc_orchestrator::ScanConfig;
use bc_repo_analysis::{CallGraphConfig, DedupConfig, WalkConfig};
use bc_stage_s0::Step0Config;
use bc_stage_s1::Step1Config;
use bc_stage_s2::Step2Config;
use bc_stage_s3::Step3Config;
use bc_stage_s4::Step4Config;
use bc_stage_s5::Step5Config;
use bc_stage_s6::Step6Config;
use bc_stage_s7::Step7Config;
use bc_stage_s8::Step8Config;

fn get<T: DeserializeOwned>(section: &Value, key: &str) -> Option<T> {
    serde_json::from_value(section.get(key)?.clone()).ok()
}

fn set<T: DeserializeOwned>(section: &Value, key: &str, target: &mut T) {
    if let Some(v) = get(section, key) {
        *target = v;
    }
}

/// One resolved `models.<role>` entry: the model id plus the three
/// sampling knobs Python resolves per role in `backends/llm.py::resolve`.
///
/// Every field is independently optional — a config may set
/// `models.deepdive.temperature` without an `id`, and a role that isn't
/// mentioned at all yields an all-`None` value rather than `None`, so
/// callers never have to distinguish "no section" from "section with no
/// id". `via`/`provider` are deliberately not read: this port's
/// `--dialect` is one global flag, not a per-stage choice (see the module
/// doc comment).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ModelRole {
    pub id: Option<String>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
}

impl ModelRole {
    fn from_section(section: &Value) -> Self {
        ModelRole {
            id: section
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string),
            temperature: get(section, "temperature"),
            top_p: get(section, "top_p"),
            seed: get(section, "seed"),
        }
    }
}

/// `models.<role>` — the id and sampling knobs for one stage's role.
///
/// `aliases` are additional spellings tried in order after `role` itself,
/// for a key Python renamed but still accepts: `models.graph_annotate`
/// falls back to `models.callgraph_creation`
/// (`callgraph_engine/_annotator.py:375-379`), which `taint.yaml` still
/// ships. The FIRST spelling present wins outright rather than being
/// merged field-by-field — a profile that sets both means one of them,
/// and silently taking `id` from one and `temperature` from the other
/// would produce a configuration neither spelling describes.
pub(crate) fn model_role_with_aliases(data: &Value, role: &str, aliases: &[&str]) -> ModelRole {
    let Some(models) = data.get("models") else {
        return ModelRole::default();
    };
    std::iter::once(role)
        .chain(aliases.iter().copied())
        .find_map(|name| models.get(name))
        .map(ModelRole::from_section)
        .unwrap_or_default()
}

pub(crate) fn model_role(data: &Value, role: &str) -> ModelRole {
    model_role_with_aliases(data, role, &[])
}

/// S11's shared/default role, which Python spells
/// `models.validate.orchestrator` — a nested object beside the three
/// per-persona sibling keys, not a flat `models.validate.id`
/// (`validation/cli/_model.py:39-47`; every shipped profile uses this
/// shape). The flat spelling is still accepted as a fallback, since this
/// port documented it before the nested one was wired and a config using
/// it must not silently start ignoring the model it names.
fn validate_role(data: &Value) -> ModelRole {
    let orchestrator = data
        .get("models")
        .and_then(|m| m.get("validate"))
        .and_then(|v| v.get("orchestrator"))
        .map(ModelRole::from_section);
    match orchestrator {
        Some(role) => role,
        None => model_role(data, "validate"),
    }
}

/// Like [`model_role`] but one level deeper — `data.models.<parent_role>.
/// <persona>.id`. Used for S11's per-persona model overrides
/// (`models.validate.security_architect.id` etc.), which nest under the
/// existing flat `models.validate.id` shared/default role rather than
/// replacing it — mirroring Python's `models.validate.orchestrator` (the
/// shared default) plus per-persona sibling keys.
fn nested_model_role(data: &Value, parent_role: &str, persona: &str) -> Option<String> {
    data.get("models")?
        .get(parent_role)?
        .get(persona)?
        .get("id")?
        .as_str()
        .map(str::to_string)
}

/// The global `--temperature`/`--top-p`/`--seed`/`--step-timeout` flags.
///
/// Sampling flags are a BASE: a per-role `models.<role>.temperature` in
/// the config file wins over them, matching how a profile is meant to be
/// the precise description of a run and a flag the coarse "make this run
/// stable" switch. `--step-timeout` is the opposite — an OVERRIDE,
/// replacing whatever `stepN.timeout` set — because it exists for the
/// operator whose gateway is slower than the profile's author assumed,
/// and a per-stage value winning would defeat exactly that.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct GlobalSampling {
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub seed: Option<u64>,
    pub step_timeout_secs: Option<u64>,
}

/// Applies one role's sampling knobs (config) beneath the global flags
/// (CLI) onto a stage's own three fields — see [`GlobalSampling`] for
/// which side wins.
macro_rules! apply_sampling {
    ($cfg:expr, $role:expr, $global:expr) => {{
        $cfg.temperature = $role.temperature.or($global.temperature);
        $cfg.top_p = $role.top_p.or($global.top_p);
        $cfg.seed = $role.seed.or($global.seed);
        if let Some(secs) = $global.step_timeout_secs {
            $cfg.timeout_secs = Some(secs);
        }
    }};
}

fn apply_walk(cfg: &mut WalkConfig, section: &Value) {
    set(section, "exclude_dirs", &mut cfg.exclude_dirs);
    set(section, "exclude_exts", &mut cfg.exclude_exts);
    set(section, "exclude_globs", &mut cfg.exclude_globs);
    set(section, "max_file_kb", &mut cfg.max_file_kb);
}

fn apply_dedup(cfg: &mut DedupConfig, section: &Value) {
    set(section, "enabled", &mut cfg.enabled);
    set(section, "exts", &mut cfg.exts);
    set(section, "min_cluster_size", &mut cfg.min_cluster_size);
    set(section, "keep_per_top_dir", &mut cfg.keep_per_top_dir);
    set(
        section,
        "promote_on_secret_hit",
        &mut cfg.promote_on_secret_hit,
    );
    set(
        section,
        "promote_on_insecure_value",
        &mut cfg.promote_on_insecure_value,
    );
    set(section, "max_file_kb", &mut cfg.max_file_kb);
}

fn apply_call_graph(cfg: &mut CallGraphConfig, section: &Value) {
    set(section, "validate", &mut cfg.validate);
    set(section, "supplement", &mut cfg.supplement);
    set(section, "rounds", &mut cfg.rounds);
    set(section, "max_targets", &mut cfg.max_targets);
}

/// The whole `step0` namespace.
///
/// Python DOES have this namespace (`_STEP_DEFAULTS["step0"]`:
/// `enabled`, `callgraph_detection`, `sources_yaml`, `sinks_yaml`,
/// `languages`) — an earlier version of this comment said it did not,
/// which is why only three of those five were ever read here.
///
/// `enabled` is `Step0Config`'s OWN internal gate (checked inside
/// `Stage0::run`); the SEPARATE orchestrator-level gate
/// (`ScanConfig.step0_enabled`, whether S0 runs at all) is set from the
/// same `step0.enabled` key by `step0_enabled_override` below, called
/// directly from `build_scan_config` the same way
/// `step2_enabled_override` already is — matching that existing
/// two-flag precedent rather than inventing a new pattern for this one
/// stage.
///
/// An unrecognized `callgraph_detection` value leaves the mode at its
/// constructed default rather than silently resolving to `rules`
/// (`DetectionMode::parse` returns `None`, deliberately) — a typo must
/// not turn into a permanently, invisibly cheaper scan. The mismatch is
/// warned about at the one place that can see both the value and the
/// fallback.
///
/// `model` is the caller's already-resolved fallback (`models.
/// graph_annotate`, else `models.preprocess`, else `--model`) — Python
/// resolves the annotator's model through the same kind of chain
/// (`_annotator.py:375-379`).
fn apply_step0(cfg: &mut Step0Config, section: &Value, model: &str) {
    set(section, "enabled", &mut cfg.enabled);
    set(section, "sources_yaml", &mut cfg.sources_yaml);
    set(section, "sinks_yaml", &mut cfg.sinks_yaml);
    // Python's `languages: None` means "no filter"; a null must not
    // deserialize into an empty-but-present list any differently, and
    // `set` on a null simply fails to parse as `Vec<String>` and leaves
    // the constructed empty default.
    set(section, "languages", &mut cfg.languages);
    if let Some(raw) = section.get("callgraph_detection").and_then(Value::as_str) {
        match bc_stage_s0::DetectionMode::parse(raw) {
            Some(mode) => cfg.detection_mode = mode,
            None => eprintln!(
                "  [config] WARN: step0.callgraph_detection: {raw:?} is not \
                 `rules` or `llm`; keeping {:?}",
                cfg.detection_mode.as_str()
            ),
        }
    }
    // `Llm` mode needs a populated `llm` block or `run_callgraph_engine`
    // silently degrades to `rules` ("no model configured", matching
    // Python). Build it from the defaults whenever the mode asks for it,
    // so `callgraph_detection: llm` alone is a complete configuration,
    // and then layer any `step0.callgraph.llm.*` overrides on top.
    let llm_section = section
        .get("callgraph")
        .and_then(|c| c.get("llm"))
        .cloned()
        .unwrap_or(Value::Null);
    if cfg.detection_mode == bc_stage_s0::DetectionMode::Llm || llm_section.is_object() {
        let mut llm = bc_stage_s0::Step0LlmConfig::new(model);
        apply_step0_llm(&mut llm, &llm_section);
        cfg.llm = Some(llm);
    }
}

/// `step0.callgraph.llm.*` — every knob `Step0LlmConfig` names in its own
/// field doc comments. Python's `failure_mode` has no counterpart here
/// (this port only implements the `empty` behavior; see
/// `bc_stage_s0::llm_detect`'s module doc comment).
fn apply_step0_llm(cfg: &mut bc_stage_s0::Step0LlmConfig, section: &Value) {
    set(section, "max_tokens", &mut cfg.max_tokens);
    set(section, "max_candidates", &mut cfg.max_candidates);
    set(
        section,
        "max_batch_candidates",
        &mut cfg.max_batch_candidates,
    );
    set(
        section,
        "min_source_confidence",
        &mut cfg.min_source_confidence,
    );
    set(section, "min_sink_confidence", &mut cfg.min_sink_confidence);
    set(
        section,
        "heuristic_supplement",
        &mut cfg.heuristic_supplement,
    );
    set(section, "min_sources", &mut cfg.min_sources);
    set(section, "min_sinks", &mut cfg.min_sinks);
    set(section, "max_heuristic_specs", &mut cfg.max_heuristic_specs);
}

fn apply_step1(cfg: &mut Step1Config, section: &Value) {
    set(section, "allowed_tools", &mut cfg.allowed_tools);
    set(section, "timeout", &mut cfg.timeout_secs);
    set(section, "max_turns", &mut cfg.max_turns);
    set(section, "max_tokens", &mut cfg.max_tokens);
    set(
        section,
        "max_transient_retries",
        &mut cfg.max_transient_retries,
    );
    set(section, "max_context_shrinks", &mut cfg.max_context_shrinks);
    apply_walk(&mut cfg.walk, section);
    if let Some(dedup_section) = section.get("config_dedup") {
        apply_dedup(&mut cfg.dedup, dedup_section);
    }
    let call_graph = serde_json::json!({
        "validate": section.get("call_graph_validate"),
        "supplement": section.get("call_graph_supplement"),
        "rounds": section.get("call_graph_rounds"),
        "max_targets": section.get("call_graph_max_targets"),
    });
    apply_call_graph(&mut cfg.call_graph, &call_graph);
    // `step1.mode` and `step1.call_graph` are BOTH string keys in
    // Python's `_STEP_DEFAULTS` (`"full"` / `"regex"`), and neither had a
    // reader here despite `Step1Mode`/`CallGraphMode` existing. An
    // unrecognized value warns and keeps the constructed default rather
    // than silently picking one — same reasoning as
    // `step0.callgraph_detection`.
    //
    // NOTE the shipped Python default for `call_graph` is `"regex"`,
    // while `Step1Config::new()` defaults to `TreeSitter`. That
    // divergence is deliberate and predates this key being readable: the
    // tree-sitter backend is strictly better evidenced (real `def_spans`,
    // exact end lines) and is what every downstream consumer in this port
    // was built against. Setting `call_graph: regex` explicitly still
    // gets you Python's backend.
    if let Some(raw) = section.get("mode").and_then(Value::as_str) {
        match raw.trim().to_ascii_lowercase().as_str() {
            "full" => cfg.mode = bc_stage_s1::Step1Mode::Full,
            "gap_fill" | "gap-fill" => cfg.mode = bc_stage_s1::Step1Mode::GapFill,
            other => eprintln!(
                "  [config] WARN: step1.mode: {other:?} is not `full` or \
                 `gap_fill`; keeping the default"
            ),
        }
    }
    if let Some(raw) = section.get("call_graph").and_then(Value::as_str) {
        match raw.trim().to_ascii_lowercase().as_str() {
            "tree_sitter" | "tree-sitter" | "treesitter" | "ast" => {
                cfg.call_graph_mode = bc_stage_s1::CallGraphMode::TreeSitter
            }
            "regex" => cfg.call_graph_mode = bc_stage_s1::CallGraphMode::Regex,
            other => eprintln!(
                "  [config] WARN: step1.call_graph: {other:?} is not \
                 `tree_sitter` or `regex`; keeping the default"
            ),
        }
    }
}

fn apply_step2(cfg: &mut Step2Config, section: &Value) {
    set(section, "max_tokens", &mut cfg.max_tokens);
    set(section, "timeout", &mut cfg.timeout_secs);
    set(section, "max_threats", &mut cfg.max_threats);
    set(section, "baseline", &mut cfg.baseline);
    set(section, "max_doc_chars", &mut cfg.max_doc_chars);
    set(section, "max_manifest_chars", &mut cfg.max_manifest_chars);
    set(section, "max_config_reps", &mut cfg.max_config_reps);
    set(section, "max_api_artefacts", &mut cfg.max_api_artefacts);
    set(section, "max_function_sites", &mut cfg.max_function_sites);
    // The nine narrowing caps, mapped the way `_gather_evidence` actually
    // reads them (`s2_threatmodel.py:229-251`), which is NOT what the
    // key names suggest and not what this file used to do:
    //
    //   step2.max_modules            -> ast_context_view(max_modules=)
    //   step2.max_entry_points       -> ast_context_view(max_entry_points=)
    //   step2.max_prompt_modules     -> the prompt-display module cap
    //   step2.max_prompt_entry_points-> the prompt-display entry-point cap
    //
    // i.e. the two unprefixed keys are FRONTIER caps and the `max_prompt_*`
    // pair is the display cap — the opposite of the previous mapping,
    // which sent both unprefixed keys to the prompt caps and left every
    // frontier cap unreachable from a config file. `default.yaml`'s own
    // comment on `max_modules` ("ctx.modules[] lines in the prompt") is
    // wrong about its own key; the call site is authoritative.
    set(section, "max_modules", &mut cfg.frontier_max_modules);
    set(
        section,
        "max_entry_points",
        &mut cfg.frontier_max_entry_points,
    );
    set(section, "max_graph_files", &mut cfg.frontier_max_files);
    set(section, "max_graph_sinks", &mut cfg.frontier_max_sinks);
    set(section, "max_graph_edges", &mut cfg.frontier_max_edges);
    set(
        section,
        "max_notes_chars",
        &mut cfg.frontier_max_notes_chars,
    );
    set(section, "max_prompt_modules", &mut cfg.max_modules);
    set(
        section,
        "max_prompt_entry_points",
        &mut cfg.max_entry_points,
    );
}

fn apply_step3(cfg: &mut Step3Config, section: &Value) {
    set(section, "max_tokens", &mut cfg.max_tokens);
    set(section, "timeout", &mut cfg.timeout_secs);
    set(section, "taint_chunks", &mut cfg.taint_chunks);
    set(section, "taint_max_hops", &mut cfg.taint_max_hops);
    set(section, "taint_max_chunks", &mut cfg.taint_max_chunks);
    set(section, "taint_files_per_hop", &mut cfg.taint_files_per_hop);
    set(section, "pack_by", &mut cfg.pack_by);
    set(
        section,
        "pack_merge_underfilled",
        &mut cfg.pack_merge_underfilled,
    );
    set(section, "chunk_token_budget", &mut cfg.chunk_token_budget);
    set(
        section,
        "chunk_overhead_tokens",
        &mut cfg.chunk_overhead_tokens,
    );
    set(section, "risk_chunk_loc", &mut cfg.risk_chunk_loc);
    set(section, "catchall_enabled", &mut cfg.catchall_enabled);
    set(section, "catchall_chunk_loc", &mut cfg.catchall_chunk_loc);
    set(section, "catchall_max_files", &mut cfg.catchall_max_files);
    set(section, "catchall_mode", &mut cfg.catchall_mode);
    set(
        section,
        "catchall_reachable_min_ratio",
        &mut cfg.catchall_reachable_min_ratio,
    );
    set(
        section,
        "catchall_reachable_min_files",
        &mut cfg.catchall_reachable_min_files,
    );
    set(section, "max_files_per_chunk", &mut cfg.max_files_per_chunk);
    set(section, "specialists", &mut cfg.specialists);
    set(
        section,
        "specialist_chunk_loc",
        &mut cfg.specialist_chunk_loc,
    );
    set(
        section,
        "threat_surface_fallbacks",
        &mut cfg.threat_surface_fallbacks,
    );
    set(
        section,
        "threat_fallback_max_files",
        &mut cfg.threat_fallback_max_files,
    );
}

fn apply_step4(cfg: &mut Step4Config, section: &Value) {
    set(section, "parallel", &mut cfg.parallel);
    set(section, "max_tokens", &mut cfg.max_tokens);
    set(section, "timeout", &mut cfg.timeout_secs);
    set(
        section,
        "max_findings_per_run",
        &mut cfg.max_findings_per_run,
    );
    set(
        section,
        "neighbor_context_lines",
        &mut cfg.neighbor_context_lines,
    );
    set(
        section,
        "neighbor_context_max",
        &mut cfg.neighbor_context_max,
    );
    set(section, "runs", &mut cfg.runs);
    set(section, "vote_threshold", &mut cfg.vote_threshold);
    set(section, "specialist_runs", &mut cfg.specialist_runs);
    set(section, "line_bucket", &mut cfg.line_bucket);
    set(section, "taint_prompt_mode", &mut cfg.taint_prompt_mode);
    set(section, "taint_runs", &mut cfg.taint_runs);
    set(
        section,
        "frontier_max_funcs_per_file",
        &mut cfg.frontier_max_funcs_per_file,
    );
    // NOT `taint_chunk_slice`: that key spans two sections and is
    // resolved by `step4_taint_chunk_slice` against the whole tree.
}

/// `step4.taint_chunk_slice`, falling back to `step3.taint_chunk_slice`,
/// normalized the way Python's `_slice_mode` normalizes it
/// (`s4_deepdive.py:993-1007`): `str(mode or "file").lower()`, so an
/// empty string means `"file"` and `"Function"` means `"function"`.
///
/// Two sections for one setting because that is how Python ships it: the
/// key is declared under `step3` (where `profiles/taint.yaml` sets it)
/// and only OPTIONALLY overridden under `step4`, which no shipped profile
/// does. Resolving it here rather than in [`apply_step4`] is what lets a
/// single `bc_stage_s4::Step4Config::taint_chunk_slice` field carry both
/// — `apply_step4` only ever sees the `step4` section, and the fallback
/// needs both. `None` when neither section names it (or both spell it
/// `null`), leaving `Step4Config::new()`'s own `"file"` in place.
pub(crate) fn step4_taint_chunk_slice(data: &Value) -> Option<String> {
    let from = |section: &str| -> Option<String> {
        get::<String>(data.get(section)?, "taint_chunk_slice")
    };
    let raw = from("step4").or_else(|| from("step3"))?;
    Some(if raw.is_empty() {
        "file".to_string()
    } else {
        raw.to_lowercase()
    })
}

fn apply_step5(cfg: &mut Step5Config, section: &Value) {
    set(section, "min_pre_confidence", &mut cfg.min_pre_confidence);
    set(section, "require_evidence", &mut cfg.require_evidence);
    set(section, "ast_backfill_evidence", &mut cfg.ast_backfill);
    // `pre_verify_threshold` is NOT read here — Python reads it off the
    // `step7_dedup` section (`s5_prefilter.py:219`, `getattr(s7d,
    // "pre_verify_threshold", 25)`), which is where
    // `apply_pre_verify_threshold` looks. A `step5_prefilter` spelling is
    // still honoured, with a warning, so an existing config keeps working.
}

/// `pre_verify_threshold`, from `step7_dedup` (Python's actual location,
/// `s5_prefilter.py:219`) with a deprecated `step5_prefilter` fallback.
///
/// The key controls an S5 behaviour but lives in S7's section because the
/// pass it gates IS S7's semantic dedup, run early. This port read it
/// under `step5_prefilter` — the intuitive place, and the wrong one: a
/// config written against Python set it under `step7_dedup` and got the
/// hard-coded default, silently running (or not running) the pre-verify
/// dedup pass at a threshold nobody chose.
fn apply_pre_verify_threshold(cfg: &mut Step5Config, data: &Value) {
    if let Some(v) = data
        .get("step7_dedup")
        .and_then(|s| get::<usize>(s, "pre_verify_threshold"))
    {
        cfg.pre_verify_threshold = v;
        return;
    }
    if let Some(v) = data
        .get("step5_prefilter")
        .and_then(|s| get::<usize>(s, "pre_verify_threshold"))
    {
        eprintln!(
            "  [config] WARN: step5_prefilter.pre_verify_threshold is \
             deprecated; Python reads this key under step7_dedup \
             (s5_prefilter.py:219). Move it there."
        );
        cfg.pre_verify_threshold = v;
    }
}

fn apply_step6(cfg: &mut Step6Config, section: &Value) {
    set(section, "parallel", &mut cfg.parallel);
    set(section, "timeout", &mut cfg.timeout_secs);
    set(section, "min_confidence", &mut cfg.min_confidence);
    set(section, "max_turns", &mut cfg.max_turns);
    set(section, "allowed_tools", &mut cfg.allowed_tools);
    set(
        section,
        "max_transient_retries",
        &mut cfg.max_transient_retries,
    );
    set(section, "max_context_shrinks", &mut cfg.max_context_shrinks);
}

fn apply_step7(cfg: &mut Step7Config, section: &Value) {
    set(section, "line_tolerance", &mut cfg.line_tolerance);
    set(section, "semantic", &mut cfg.semantic);
    set(section, "max_tokens", &mut cfg.max_tokens);
    set(
        section,
        "merge_same_range_cwes",
        &mut cfg.merge_same_range_cwes,
    );
    set(section, "merge_same_sink", &mut cfg.merge_same_sink);
    set(section, "timeout", &mut cfg.timeout_secs);
}

fn apply_step8(cfg: &mut Step8Config, section: &Value) {
    set(section, "max_tokens", &mut cfg.max_tokens);
    set(section, "timeout", &mut cfg.timeout_secs);
}

/// The `pricing` namespace: which provider's rates this run's tokens are
/// costed at, and any corrections to those rates.
///
/// ```yaml
/// pricing:
///   provider: acme-gateway
///   rates:
///     acme-gateway:
///       claude-sonnet-4-5:
///         input: 1500000        # picodollars per token, i.e. 1.50 USD
///         output: 7500000       # per million tokens
///         cache_read: 150000
///         cache_write: 1875000
/// ```
///
/// `rates` is the vendored price table's own `providers` shape, so an
/// entry copied straight out of `crates/bc-pricing/data/models-dev-prices.json`
/// is a valid correction as it stands. This is the escape hatch that makes
/// the whole feature honest: a public rate table is exactly wrong for the
/// case it matters most in, a gateway on negotiated terms, and without
/// this the report would state that deployment's cost confidently and be
/// wrong by whatever the discount is. A provider id of `*` matches any
/// provider, for a deployment that fronts everything through one endpoint
/// at one price.
///
/// A malformed `rates` block is WARNED about loudly and then ignored,
/// rather than silently dropped or turned into a hard error. Silence is
/// the one unacceptable option: it would leave an operator believing a
/// negotiated rate had been applied to a report that used list prices.
/// The warning, and not an error, because this module's contract for every
/// other key is that one bad field keeps its default rather than failing
/// the run (see the module doc comment), and a scan is not worth aborting
/// over its cost annotation.
///
/// Not a port. The Python original has no pricing of any kind.
fn apply_pricing(cfg: &mut bc_orchestrator::pricing::PricingConfig, section: &Value) {
    if let Some(provider) = section.get("provider").and_then(Value::as_str) {
        cfg.provider = Some(provider.to_string());
    }
    let Some(rates) = section.get("rates") else {
        return;
    };
    // Wrapped back into the file-level `{"providers": ...}` envelope so
    // the operator writes the inner shape they can copy, and this parses
    // it through exactly the same deny-unknown-fields path the vendored
    // table itself is parsed through.
    let wrapped = serde_json::json!({ "providers": rates });
    match bc_pricing::PriceTable::from_json(&wrapped.to_string()) {
        Ok(table) => cfg.overrides = table,
        Err(e) => eprintln!(
            "  [config] WARN: pricing.rates could not be read ({e}); \
             no rate overrides applied, so costs use published rates"
        ),
    }
}

/// Applies `models.remediate` and the `step_remediate.*` block onto an
/// already-constructed `Step10Config`. Unlike the eight `apply_stepN`
/// functions above, this is called separately from [`apply_overrides`]
/// (Phase 2's S10 remediation config, not part of `ScanConfig`/the S1-S8
/// scan pipeline at all).
///
/// The seven safety-gate keys (`syntax_check` .. `verify_timeout_secs`)
/// have no Python counterpart — S10's rollback gates are a Rust-side
/// addition (see `bc-stage-s10`'s crate doc comment). Their defaults live
/// in `bc_config::step_defaults()`'s `step_remediate` section and are
/// pinned to `Step10Config::new()` by a cross-crate invariant test, so
/// reading them unconditionally here reproduces the constructed default
/// rather than silently changing it.
///
/// `verify_command` is deliberately read as `Option<String>`: the shipped
/// default is JSON `null` (meaning "run nothing"), and `""` would be a
/// command `sh -c` accepts and runs.
pub fn apply_step10_overrides(
    cfg: &mut bc_stage_s10::Step10Config,
    data: &Value,
    global: GlobalSampling,
) {
    let role = model_role(data, "remediate");
    if let Some(m) = role.id {
        cfg.model = m;
    }
    apply_sampling!(cfg, role, global);
    if let Some(section) = data.get("step_remediate") {
        set(section, "max_turns", &mut cfg.max_turns);
        set(section, "allowed_tools", &mut cfg.allowed_tools);
        set(
            section,
            "max_transient_retries",
            &mut cfg.max_transient_retries,
        );
        set(section, "max_context_shrinks", &mut cfg.max_context_shrinks);
        set(section, "timeout", &mut cfg.timeout_secs);
        set(section, "syntax_check", &mut cfg.syntax_check);
        set(section, "keep_unverified", &mut cfg.keep_unverified);
        set(section, "retry_unapplied_fix", &mut cfg.retry_unapplied_fix);
        set(section, "max_diff_lines", &mut cfg.max_diff_lines);
        set(section, "max_files_touched", &mut cfg.max_files_touched);
        set(section, "dry_run", &mut cfg.dry_run);
        set(section, "verify_command", &mut cfg.verify_command);
        set(section, "verify_timeout_secs", &mut cfg.verify_timeout_secs);
    }
}

/// `inject.cve_file` / `inject.controls_file`, resolved against
/// `config_dir` — the same rule as [`step_remediate_policy_paths`], and
/// the same reason: `orchestrator/scan.py:210-211` runs both through
/// `_resolve_against(Path(args.config).resolve().parent, ...)` because a
/// profile ships its own `./inputs/known_cves.json` next to itself.
pub fn inject_paths(
    data: &Value,
    config_dir: &std::path::Path,
) -> (Option<std::path::PathBuf>, Option<std::path::PathBuf>) {
    (
        resolve_against(data.get("inject"), "cve_file", config_dir),
        resolve_against(data.get("inject"), "controls_file", config_dir),
    )
}

/// A single configured path, resolved against `config_dir` when relative
/// and used verbatim when absolute. Shared by the `inject.*` and
/// `step_remediate.*_file` keys, which have identical semantics in
/// Python. An absent section, an absent key, a non-string value, or a
/// blank string all yield `None`.
fn resolve_against(
    section: Option<&Value>,
    key: &str,
    config_dir: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let raw: String = get(section?, key)?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let path = std::path::Path::new(raw);
    Some(if path.is_absolute() {
        path.to_path_buf()
    } else {
        config_dir.join(path)
    })
}

/// `step_remediate.policy_file` / `step_remediate.playbook_file`, each
/// resolved against `config_dir` (the directory holding the `--config`
/// file) exactly the way Python resolves them —
/// `remediation_agent/policy/context.py:94-95` runs every configured
/// remediation input through `_resolve_against(cfg_dir, raw)`, because a
/// profile ships its own `./inputs/...` next to itself and the process's
/// CWD is wherever the operator happened to be standing.
///
/// An absolute configured path is used verbatim; a relative one is joined
/// onto `config_dir`. Unlike Python this does NOT drop a configured path
/// that doesn't exist on disk — `bc_policy_gate::RemediationGate::load`
/// already fails closed on an unreadable file, and Python's "fall back to
/// the bundled default" branch has no counterpart here (this port bundles
/// no default policy), so silently discarding the path would turn a typo
/// into a permissive-looking run.
pub fn step_remediate_policy_paths(
    data: &Value,
    config_dir: &std::path::Path,
) -> (Option<std::path::PathBuf>, Option<std::path::PathBuf>) {
    let section = data.get("step_remediate");
    (
        resolve_against(section, "policy_file", config_dir),
        resolve_against(section, "playbook_file", config_dir),
    )
}

/// Applies `models.validate` and `step_validate.{max_turns,
/// allowed_tools, fact_tools}` onto an already-constructed
/// `Step11Config`. Mirrors
/// [`apply_step10_overrides`] exactly — Phase 3's S11 validation config,
/// not part of `ScanConfig`/the S1-S8 scan pipeline either.
pub fn apply_step11_overrides(
    cfg: &mut bc_stage_s11::Step11Config,
    data: &Value,
    global: GlobalSampling,
) {
    let role = validate_role(data);
    if let Some(m) = role.id {
        cfg.model = m;
    }
    apply_sampling!(cfg, role, global);
    cfg.security_architect_model = nested_model_role(data, "validate", "security_architect")
        .or_else(|| cfg.security_architect_model.clone());
    cfg.penetration_tester_model = nested_model_role(data, "validate", "penetration_tester")
        .or_else(|| cfg.penetration_tester_model.clone());
    cfg.cross_repo_analyzer_model = nested_model_role(data, "validate", "cross_repo_analyzer")
        .or_else(|| cfg.cross_repo_analyzer_model.clone());
    if let Some(section) = data.get("step_validate") {
        set(section, "max_turns", &mut cfg.max_turns);
        set(section, "allowed_tools", &mut cfg.allowed_tools);
        set(
            section,
            "max_transient_retries",
            &mut cfg.max_transient_retries,
        );
        set(section, "max_context_shrinks", &mut cfg.max_context_shrinks);
        set(section, "timeout", &mut cfg.timeout_secs);
        set(section, "max_findings", &mut cfg.max_findings);
        set(section, "cross_repo_analyzer", &mut cfg.cross_repo_analyzer);
        // Net-new versus Python, which hardwires `fact_tools=
        // DEFAULT_FACT_TOOLS` at `validation/session/launcher.py:259`.
        // Turning it off also strips the five names back out of
        // `allowed_tools` at run time (`Step11Config::fact_tools`), so
        // this stays a single key even for an operator who also set an
        // explicit `allowed_tools`.
        set(section, "fact_tools", &mut cfg.fact_tools);
    }
}

/// `step_validate.enabled`'s value, matching Python's own
/// `cfg.step_validate.enabled` toggle — mirrors [`step2_enabled_override`].
/// The baked-in default this overrides (see `build_remediate_settings`) is
/// `true`, matching the shipped `default.yaml` profile ("s11 validator —
/// ON by default, mirrors step_remediate"), not the bare
/// `bc_config::step_defaults()` base value (`false` there, since Python's
/// own un-profiled `_STEP_DEFAULTS` ships validation off until a profile
/// turns it on).
pub fn step_validate_enabled_override(data: &Value) -> Option<bool> {
    get(data.get("step_validate")?, "enabled")
}

/// `step_remediate.top_n_findings`'s value, as a [`bc_stage_s10::TopSpec`]
/// — the profile-configured default `--top` falls back to (a CLI `--top`
/// always wins when given). Accepts either a YAML integer or the
/// `"all"`/`"*"` string wildcard, matching the Python original's own
/// `top_n_findings: 5` vs. `top_n_findings: all` shipped-profile forms.
/// `None` when the key (or the whole `step_remediate` section) is absent,
/// or its value doesn't parse as a valid top-spec.
pub fn step_remediate_top_n_findings(data: &Value) -> Option<bc_stage_s10::TopSpec> {
    let raw = data.get("step_remediate")?.get("top_n_findings")?;
    let token = match raw {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => return None,
    };
    bc_stage_s10::parse_top_spec(&token, "step_remediate.top_n_findings").ok()
}

/// `step_remediate.enforce_policy`'s value, matching Python's own
/// strictly-opt-in gate toggle (every shipped profile except `default`
/// sets this `false`).
pub fn step_remediate_enforce_policy(data: &Value) -> Option<bool> {
    get(data.get("step_remediate")?, "enforce_policy")
}

/// Applies every per-stage YAML override and `models.<role>` model-role
/// override onto an already-constructed `ScanConfig`. A no-op for any
/// section/role absent from `data` — every stage keeps whatever its own
/// `Step*Config::new()` (or the CLI's shared `--model`) already set.
/// The config sections whose `max_budget_usd` a user set.
///
/// In the Python original this key was never a harness feature: it is a
/// passthrough to Anthropic's own tooling. `claude_cli.py:874` appends
/// `--max-budget-usd` to the `claude` subprocess, and only when the
/// installed binary advertises the flag; `agent_sdk.py:275` sets it on a
/// Claude Agent SDK session. Both of those backends do the enforcing.
/// The two routes this port's wire dialects correspond to ignore it
/// outright: `sdk.py:447` carries the literal comment "accepted for
/// parity; unused", and `oai.py` never reads it. Python computes a dollar
/// figure nowhere, and ships no price table.
///
/// Since this port deliberately does not have those two backends, there
/// is nothing here for the key to reach, so it is no longer shipped as a
/// default. A config written against Python still loads; the key just
/// buys nothing, which is worth saying out loud rather than letting an
/// operator believe a spend cap is in force. `--max-tokens` and
/// `--max-scan-seconds` are the caps this port actually enforces.
fn unenforced_budget_sections(data: &Value) -> Vec<&'static str> {
    ["step1", "step6_verify", "step_remediate", "step_validate"]
        .into_iter()
        .filter(|section| {
            data.get(section)
                .and_then(|s| s.get("max_budget_usd"))
                .is_some_and(|v| !v.is_null())
        })
        .collect()
}

fn warn_unenforced_budget_keys(data: &Value) {
    let sections = unenforced_budget_sections(data);
    if sections.is_empty() {
        return;
    }
    eprintln!(
        "  [config] WARN: max_budget_usd is set on {} but is not enforced \
         by this port. In Python it was forwarded to the Claude CLI and \
         Claude Agent SDK backends, which enforce it themselves and which \
         this port does not have. Use --max-tokens and --max-scan-seconds \
         for spend caps.",
        sections.join(", ")
    );
}

pub fn apply_overrides(config: &mut ScanConfig, data: &Value, global: GlobalSampling) {
    warn_unenforced_budget_keys(data);
    let preprocess = model_role(data, "preprocess");
    let threatmodel = model_role(data, "threatmodel");
    let decompose = model_role(data, "decompose");
    let deepdive = model_role(data, "deepdive");
    let verify = model_role(data, "verify");
    let dedup = model_role(data, "dedup");
    let chain = model_role(data, "chain");
    if let Some(m) = preprocess.id.clone() {
        config.step1.model = m;
    }
    if let Some(m) = threatmodel.id.clone() {
        config.step2.model = m;
    }
    if let Some(m) = decompose.id.clone() {
        config.step3.model = m;
    }
    if let Some(m) = deepdive.id.clone() {
        config.step4.model = m;
    }
    if let Some(m) = verify.id.clone() {
        config.step6.model = m;
    }
    if let Some(m) = dedup.id.clone() {
        config.step7.model = m.clone();
        config.step5.dedup.model = m;
    }
    if let Some(m) = chain.id.clone() {
        config.step8.model = m;
    }

    if let Some(section) = data.get("step0") {
        // The annotator's model falls back through `models.graph_annotate`
        // -> `models.preprocess` -> whatever `--model` already put on S1,
        // mirroring `_annotator.py:375-379`'s own resolution chain.
        let annotate = model_role_with_aliases(data, "graph_annotate", &["callgraph_creation"]);
        let model = annotate
            .id
            .clone()
            .or_else(|| preprocess.id.clone())
            .unwrap_or_else(|| config.step1.model.clone());
        apply_step0(&mut config.step0, section, &model);
    }
    if let Some(section) = data.get("step1") {
        apply_step1(&mut config.step1, section);
    }
    if let Some(section) = data.get("step2") {
        apply_step2(&mut config.step2, section);
    }
    if let Some(section) = data.get("step3") {
        apply_step3(&mut config.step3, section);
    }
    if let Some(section) = data.get("step4") {
        apply_step4(&mut config.step4, section);
    }
    // After `apply_step4`, and outside the `step4`-section guard: this one
    // key is declared under `step3` in every shipped Python profile and
    // only optionally overridden under `step4`.
    if let Some(mode) = step4_taint_chunk_slice(data) {
        config.step4.taint_chunk_slice = mode;
    }
    if let Some(section) = data.get("step5_prefilter") {
        apply_step5(&mut config.step5, section);
    }
    apply_pre_verify_threshold(&mut config.step5, data);
    if let Some(section) = data.get("step6_verify") {
        apply_step6(&mut config.step6, section);
    }
    if let Some(section) = data.get("step7_dedup") {
        apply_step7(&mut config.step7, section);
        apply_step7(&mut config.step5.dedup, section);
    }
    if let Some(section) = data.get("step8") {
        apply_step8(&mut config.step8, section);
    }
    if let Some(section) = data.get("output") {
        set(
            section,
            "emit_unreachable_appendix",
            &mut config.emit_unreachable_appendix,
        );
    }
    if let Some(section) = data.get("pricing") {
        apply_pricing(&mut config.pricing, section);
    }

    // Sampling LAST, so `--step-timeout` overrides the `stepN.timeout`
    // each `apply_stepN` above has just read. S5 has no LLM call of its
    // own — its one model call goes through the S7 dedup config, which
    // is why `step5.dedup` gets the `dedup` role's knobs rather than a
    // role of its own.
    apply_sampling!(config.step1, preprocess, global);
    apply_sampling!(config.step2, threatmodel, global);
    apply_sampling!(config.step3, decompose, global);
    apply_sampling!(config.step4, deepdive, global);
    apply_sampling!(config.step6, verify, global);
    apply_sampling!(config.step7, dedup, global);
    apply_sampling!(config.step5.dedup, dedup, global);
    apply_sampling!(config.step8, chain, global);
    if let Some(llm) = &mut config.step0.llm {
        let annotate = model_role_with_aliases(data, "graph_annotate", &["callgraph_creation"]);
        apply_sampling!(llm, annotate, global);
    }
}

/// `step2.enabled`'s value if present, matching Python's own
/// `cfg.step2.enabled` toggle — the CLI's `--no-threat-model` flag is
/// applied on top of this by the caller (a pure "disable" switch with no
/// "explicitly enable" counterpart, so it can only further restrict this
/// baseline, never conflict with it).
pub fn step2_enabled_override(data: &Value) -> Option<bool> {
    get(data.get("step2")?, "enabled")
}

/// Mirrors [`step2_enabled_override`] for the orchestrator-level
/// `ScanConfig.step0_enabled` gate — see [`apply_step0`]'s own doc
/// comment for why this is a second, separate read of the same
/// `step0.enabled` key rather than a single shared flag.
pub fn step0_enabled_override(data: &Value) -> Option<bool> {
    get(data.get("step0")?, "enabled")
}

/// `llm.stream_large_responses` — the config half of
/// `--stream-large-responses` (see `crate::stream_large_responses`, which
/// ORs the two).
///
/// Its own `llm` section rather than a key under some stage's: streaming
/// is a property of the transport every stage shares, decided from a
/// request's own `max_tokens`, so there is nothing per-stage about it and
/// eight copies of the same key would only invite them to disagree.
/// Net-new versus Python, which has no equivalent key — it streams
/// unconditionally (`backends/sdk.py:288-289`) and offers no way to turn
/// that off.
pub fn llm_stream_large_responses_override(data: &Value) -> Option<bool> {
    get(data.get("llm")?, "stream_large_responses")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bc_stage_s0::Step0Config;
    use serde_json::json;

    fn default_scan_config() -> ScanConfig {
        ScanConfig {
            step0_enabled: true,
            step0: Step0Config::new(),
            step1: Step1Config::new("m"),
            step2_enabled: true,
            step2: Step2Config::new("m"),
            step3: Step3Config::new("m"),
            step4: Step4Config::new("m"),
            step5: Step5Config::new("m"),
            step6: Step6Config::new("m"),
            step7: Step7Config::new("m"),
            step8: Step8Config::new("m"),
            tool_version: "test".to_string(),
            spend_cap: None,
            checkpoint: None,
            resume: false,
            emit_unreachable_appendix: false,
            progress: None,
            pricing: bc_orchestrator::pricing::PricingConfig::default(),
        }
    }

    #[test]
    fn apply_overrides_is_a_no_op_on_an_empty_tree() {
        let mut config = default_scan_config();
        apply_overrides(&mut config, &json!({}), GlobalSampling::default());
        assert_eq!(config.step1.model, "m");
        assert_eq!(config.step1.max_turns, Step1Config::new("m").max_turns);
        assert_eq!(config.step4.parallel, Step4Config::new("m").parallel);
        assert_eq!(
            config.step7.line_tolerance,
            Step7Config::new("m").line_tolerance
        );
        assert_eq!(config.pricing.provider, None);
        assert!(config.pricing.overrides.is_empty());
    }

    #[test]
    fn the_pricing_section_names_a_provider_and_layers_negotiated_rates() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({
                "pricing": {
                    "provider": "acme-gateway",
                    "rates": {
                        "acme-gateway": {
                            "claude-sonnet-4-5": {
                                "input": 1_500_000,
                                "output": 7_500_000,
                                "cache_read": 150_000,
                                "cache_write": 1_875_000,
                            },
                        },
                    },
                }
            }),
            GlobalSampling::default(),
        );
        assert_eq!(config.pricing.provider.as_deref(), Some("acme-gateway"));
        let price = config
            .pricing
            .overrides
            .lookup("acme-gateway", "claude-sonnet-4-5")
            .expect("the negotiated rate is in force");
        // Half Anthropic's own published 3.00 per million input tokens.
        assert_eq!(price.input, 1_500_000);
        assert_eq!(price.cache_write, Some(1_875_000));
    }

    #[test]
    fn a_pricing_section_may_name_a_provider_without_correcting_any_rate() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"pricing": {"provider": "acme-gateway"}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.pricing.provider.as_deref(), Some("acme-gateway"));
        assert!(config.pricing.overrides.is_empty());
    }

    #[test]
    fn a_pricing_section_may_correct_rates_without_naming_a_provider() {
        // The wildcard case: one endpoint fronting everything at one
        // price, with the provider itself supplied by the CLI flag.
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"pricing": {"rates": {"*": {"house-model": {"input": 1, "output": 2}}}}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.pricing.provider, None);
        assert!(config
            .pricing
            .overrides
            .lookup(bc_pricing::ANY_PROVIDER, "house-model")
            .is_ok());
    }

    #[test]
    fn a_malformed_rates_block_is_ignored_rather_than_silently_half_applied() {
        // `cache-read` is not a key the price table has. Accepting it
        // quietly would leave the operator believing a negotiated rate
        // had been applied to a report priced at list rates; the parse
        // fails as a whole and a WARN says so.
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({
                "pricing": {
                    "provider": "acme-gateway",
                    "rates": {"acme-gateway": {"m": {"input": 1, "output": 2, "cache-read": 3}}},
                }
            }),
            GlobalSampling::default(),
        );
        // The provider still applies: it parsed fine, and dropping it
        // would turn one bad key into a wholly unpriced run.
        assert_eq!(config.pricing.provider.as_deref(), Some("acme-gateway"));
        assert!(config.pricing.overrides.is_empty());
    }

    #[test]
    fn a_non_string_pricing_provider_leaves_the_inferred_one_alone() {
        let mut config = default_scan_config();
        config.pricing.provider = Some("inferred".to_string());
        apply_overrides(
            &mut config,
            &json!({"pricing": {"provider": 7}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.pricing.provider.as_deref(), Some("inferred"));
    }

    #[test]
    fn model_roles_override_every_stage_including_the_shared_dedup_role() {
        let mut config = default_scan_config();
        let data = json!({
            "models": {
                "preprocess": {"id": "preprocess-model"},
                "threatmodel": {"id": "threatmodel-model"},
                "decompose": {"id": "decompose-model"},
                "deepdive": {"id": "deepdive-model"},
                "verify": {"id": "verify-model"},
                "dedup": {"id": "dedup-model"},
                "chain": {"id": "chain-model"},
            }
        });
        apply_overrides(&mut config, &data, GlobalSampling::default());
        assert_eq!(config.step1.model, "preprocess-model");
        assert_eq!(config.step2.model, "threatmodel-model");
        assert_eq!(config.step3.model, "decompose-model");
        assert_eq!(config.step4.model, "deepdive-model");
        assert_eq!(config.step6.model, "verify-model");
        assert_eq!(config.step7.model, "dedup-model");
        assert_eq!(config.step5.dedup.model, "dedup-model");
        assert_eq!(config.step8.model, "chain-model");
    }

    #[test]
    fn missing_model_role_leaves_that_stages_model_unchanged() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"models": {}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step1.model, "m");
    }

    #[test]
    fn model_role_reads_the_sampling_knobs_beside_the_id() {
        let data = json!({"models": {"deepdive": {
            "id": "opus", "temperature": 0.0, "top_p": 0.9, "seed": 7,
        }}});
        assert_eq!(
            model_role(&data, "deepdive"),
            ModelRole {
                id: Some("opus".to_string()),
                temperature: Some(0.0),
                top_p: Some(0.9),
                seed: Some(7),
            }
        );
    }

    #[test]
    fn a_role_with_only_sampling_and_no_id_is_still_read() {
        let role = model_role(
            &json!({"models": {"verify": {"temperature": 0.2}}}),
            "verify",
        );
        assert_eq!(role.id, None);
        assert_eq!(role.temperature, Some(0.2));
    }

    #[test]
    fn an_absent_role_or_models_block_yields_an_empty_role() {
        assert_eq!(model_role(&json!({}), "verify"), ModelRole::default());
        assert_eq!(
            model_role(&json!({"models": {}}), "verify"),
            ModelRole::default()
        );
    }

    #[test]
    fn callgraph_creation_is_accepted_as_an_alias_of_graph_annotate() {
        let data = json!({"models": {"callgraph_creation": {"id": "legacy"}}});
        let role = model_role_with_aliases(&data, "graph_annotate", &["callgraph_creation"]);
        assert_eq!(role.id.as_deref(), Some("legacy"));
    }

    #[test]
    fn the_canonical_graph_annotate_spelling_wins_over_the_alias() {
        let data = json!({"models": {
            "graph_annotate": {"id": "current"},
            "callgraph_creation": {"id": "legacy", "temperature": 0.5},
        }});
        let role = model_role_with_aliases(&data, "graph_annotate", &["callgraph_creation"]);
        assert_eq!(role.id.as_deref(), Some("current"));
        // Not merged field-by-field — the alias's temperature is ignored
        // rather than silently grafted onto the canonical id.
        assert_eq!(role.temperature, None);
    }

    #[test]
    fn the_validate_role_prefers_pythons_nested_orchestrator_spelling() {
        let data = json!({"models": {"validate": {
            "id": "flat-fallback",
            "orchestrator": {"id": "opus", "temperature": 0.0},
        }}});
        let role = validate_role(&data);
        assert_eq!(role.id.as_deref(), Some("opus"));
        assert_eq!(role.temperature, Some(0.0));
    }

    #[test]
    fn the_validate_role_falls_back_to_the_flat_spelling() {
        let role = validate_role(&json!({"models": {"validate": {"id": "sonnet"}}}));
        assert_eq!(role.id.as_deref(), Some("sonnet"));
        assert_eq!(validate_role(&json!({})), ModelRole::default());
    }

    #[test]
    fn global_sampling_flags_reach_every_stage() {
        let mut config = default_scan_config();
        config.step0.llm = Some(bc_stage_s0::Step0LlmConfig::new("m"));
        let global = GlobalSampling {
            temperature: Some(0.0),
            top_p: Some(0.8),
            seed: Some(42),
            step_timeout_secs: Some(90),
        };
        apply_overrides(&mut config, &json!({}), global);
        for (temp, top_p, seed, timeout) in [
            (
                config.step1.temperature,
                config.step1.top_p,
                config.step1.seed,
                config.step1.timeout_secs,
            ),
            (
                config.step2.temperature,
                config.step2.top_p,
                config.step2.seed,
                config.step2.timeout_secs,
            ),
            (
                config.step3.temperature,
                config.step3.top_p,
                config.step3.seed,
                config.step3.timeout_secs,
            ),
            (
                config.step4.temperature,
                config.step4.top_p,
                config.step4.seed,
                config.step4.timeout_secs,
            ),
            (
                config.step6.temperature,
                config.step6.top_p,
                config.step6.seed,
                config.step6.timeout_secs,
            ),
            (
                config.step7.temperature,
                config.step7.top_p,
                config.step7.seed,
                config.step7.timeout_secs,
            ),
            (
                config.step5.dedup.temperature,
                config.step5.dedup.top_p,
                config.step5.dedup.seed,
                config.step5.dedup.timeout_secs,
            ),
            (
                config.step8.temperature,
                config.step8.top_p,
                config.step8.seed,
                config.step8.timeout_secs,
            ),
        ] {
            assert_eq!(temp, Some(0.0));
            assert_eq!(top_p, Some(0.8));
            assert_eq!(seed, Some(42));
            assert_eq!(timeout, Some(90));
        }
        let llm = config.step0.llm.as_ref().unwrap();
        assert_eq!(llm.temperature, Some(0.0));
        assert_eq!(llm.top_p, Some(0.8));
        assert_eq!(llm.seed, Some(42));
        assert_eq!(llm.timeout_secs, Some(90));
    }

    #[test]
    fn a_per_role_sampling_value_wins_over_the_global_flag() {
        let mut config = default_scan_config();
        let data = json!({"models": {"deepdive": {"temperature": 0.7, "seed": 1}}});
        apply_overrides(
            &mut config,
            &data,
            GlobalSampling {
                temperature: Some(0.0),
                top_p: Some(0.5),
                seed: Some(9),
                step_timeout_secs: None,
            },
        );
        assert_eq!(config.step4.temperature, Some(0.7));
        assert_eq!(config.step4.seed, Some(1));
        // Not set per-role, so the global still applies.
        assert_eq!(config.step4.top_p, Some(0.5));
        // A role that set nothing takes the globals wholesale.
        assert_eq!(config.step2.temperature, Some(0.0));
    }

    #[test]
    fn step_timeout_keys_are_read_and_the_global_flag_overrides_them() {
        let mut config = default_scan_config();
        let data = json!({
            "step1": {"timeout": 11}, "step2": {"timeout": 22}, "step3": {"timeout": 33},
            "step4": {"timeout": 44}, "step6_verify": {"timeout": 66},
            "step7_dedup": {"timeout": 77}, "step8": {"timeout": 88},
        });
        apply_overrides(&mut config, &data, GlobalSampling::default());
        assert_eq!(config.step1.timeout_secs, Some(11));
        assert_eq!(config.step2.timeout_secs, Some(22));
        assert_eq!(config.step3.timeout_secs, Some(33));
        assert_eq!(config.step4.timeout_secs, Some(44));
        assert_eq!(config.step6.timeout_secs, Some(66));
        assert_eq!(config.step7.timeout_secs, Some(77));
        assert_eq!(config.step8.timeout_secs, Some(88));

        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &data,
            GlobalSampling {
                step_timeout_secs: Some(5),
                ..GlobalSampling::default()
            },
        );
        assert_eq!(config.step3.timeout_secs, Some(5));
        assert_eq!(config.step8.timeout_secs, Some(5));
    }

    #[test]
    fn step0_overrides_every_field() {
        let mut config = default_scan_config();
        let data = json!({
            "step0": {
                "enabled": true,
                "sources_yaml": "/rules/sources.yaml",
                "sinks_yaml": "/rules/sinks.yaml",
            }
        });
        apply_overrides(&mut config, &data, GlobalSampling::default());
        assert!(config.step0.enabled);
        assert_eq!(
            config.step0.sources_yaml,
            Some(std::path::PathBuf::from("/rules/sources.yaml"))
        );
        assert_eq!(
            config.step0.sinks_yaml,
            Some(std::path::PathBuf::from("/rules/sinks.yaml"))
        );
    }

    #[test]
    fn step0_reads_the_detection_mode_languages_and_the_whole_llm_block() {
        let mut config = default_scan_config();
        let data = json!({
            "models": {"graph_annotate": {"id": "annotator-model"}},
            "step0": {
                "enabled": true,
                "callgraph_detection": "llm",
                "languages": ["python", "go"],
                "callgraph": {"llm": {
                    "max_tokens": 1, "max_candidates": 2, "max_batch_candidates": 3,
                    "min_source_confidence": 0.1, "min_sink_confidence": 0.2,
                    "heuristic_supplement": false, "min_sources": 4, "min_sinks": 5,
                    "max_heuristic_specs": 6,
                }},
            }
        });
        apply_overrides(&mut config, &data, GlobalSampling::default());
        assert_eq!(config.step0.detection_mode, bc_stage_s0::DetectionMode::Llm);
        assert_eq!(
            config.step0.languages,
            vec!["python".to_string(), "go".to_string()]
        );
        let llm = config.step0.llm.as_ref().expect("llm mode populates it");
        assert_eq!(llm.model, "annotator-model");
        assert_eq!(llm.max_tokens, 1);
        assert_eq!(llm.max_candidates, 2);
        assert_eq!(llm.max_batch_candidates, 3);
        assert_eq!(llm.min_source_confidence, 0.1);
        assert_eq!(llm.min_sink_confidence, 0.2);
        assert!(!llm.heuristic_supplement);
        assert_eq!(llm.min_sources, 4);
        assert_eq!(llm.min_sinks, 5);
        assert_eq!(llm.max_heuristic_specs, 6);
    }

    /// `callgraph_detection: llm` alone must be a COMPLETE configuration —
    /// with no `llm` block the engine silently degrades to `rules`
    /// ("no model configured"), which is exactly the invisible failure
    /// this wiring exists to remove.
    #[test]
    fn llm_detection_mode_alone_populates_the_llm_block_with_defaults() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"step0": {"callgraph_detection": "llm"}}),
            GlobalSampling::default(),
        );
        assert!(config.step0.llm.is_some());
        assert_eq!(
            config.step0.llm.as_ref().unwrap().max_candidates,
            bc_stage_s0::Step0LlmConfig::new("m").max_candidates
        );
    }

    #[test]
    fn the_step0_annotator_model_falls_back_through_preprocess() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({
                "models": {"preprocess": {"id": "s1-model"}},
                "step0": {"callgraph_detection": "llm"},
            }),
            GlobalSampling::default(),
        );
        assert_eq!(config.step0.llm.as_ref().unwrap().model, "s1-model");

        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"step0": {"callgraph_detection": "llm"}}),
            GlobalSampling::default(),
        );
        // Neither role set: whatever `--model` already put on S1.
        assert_eq!(config.step0.llm.as_ref().unwrap().model, "m");
    }

    #[test]
    fn max_budget_usd_is_reported_per_section_that_sets_it() {
        let data = json!({
            "step1": {"max_budget_usd": 25.0},
            "step6_verify": {"max_turns": 30},
            "step_remediate": {"max_budget_usd": 10.0},
            "step_validate": {"max_budget_usd": null},
        });
        assert_eq!(
            unenforced_budget_sections(&data),
            vec!["step1", "step_remediate"]
        );
        // covers the branch that actually prints
        warn_unenforced_budget_keys(&data);
    }

    #[test]
    fn a_config_without_max_budget_usd_reports_nothing() {
        let data = json!({"step1": {"max_turns": 40}});
        assert!(unenforced_budget_sections(&data).is_empty());
        warn_unenforced_budget_keys(&data);
    }

    #[test]
    fn an_unrecognized_detection_mode_keeps_the_default_rather_than_guessing() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"step0": {"callgraph_detection": "rulez"}}),
            GlobalSampling::default(),
        );
        assert_eq!(
            config.step0.detection_mode,
            bc_stage_s0::DetectionMode::Rules
        );
        assert!(config.step0.llm.is_none());
    }

    #[test]
    fn step1_reads_the_mode_and_call_graph_backend_keys() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"step1": {"mode": "gap_fill", "call_graph": "regex"}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step1.mode, bc_stage_s1::Step1Mode::GapFill);
        assert_eq!(
            config.step1.call_graph_mode,
            bc_stage_s1::CallGraphMode::Regex
        );

        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"step1": {"mode": "FULL", "call_graph": "tree_sitter"}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step1.mode, bc_stage_s1::Step1Mode::Full);
        assert_eq!(
            config.step1.call_graph_mode,
            bc_stage_s1::CallGraphMode::TreeSitter
        );
    }

    #[test]
    fn unrecognized_step1_mode_values_keep_the_defaults() {
        let mut config = default_scan_config();
        let before_mode = config.step1.mode;
        let before_backend = config.step1.call_graph_mode;
        apply_overrides(
            &mut config,
            &json!({"step1": {"mode": "half", "call_graph": "antlr"}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step1.mode, before_mode);
        assert_eq!(config.step1.call_graph_mode, before_backend);
    }

    #[test]
    fn pre_verify_threshold_is_read_from_step7_dedup_like_python() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"step7_dedup": {"pre_verify_threshold": 3}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step5.pre_verify_threshold, 3);
    }

    #[test]
    fn a_step5_prefilter_pre_verify_threshold_still_works_as_a_deprecated_spelling() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"step5_prefilter": {"pre_verify_threshold": 4}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step5.pre_verify_threshold, 4);
    }

    #[test]
    fn the_step7_dedup_spelling_wins_when_both_are_present() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({
                "step7_dedup": {"pre_verify_threshold": 3},
                "step5_prefilter": {"pre_verify_threshold": 4},
            }),
            GlobalSampling::default(),
        );
        assert_eq!(config.step5.pre_verify_threshold, 3);
    }

    #[test]
    fn step5_prefilter_reads_ast_backfill_evidence() {
        let mut config = default_scan_config();
        assert!(config.step5.ast_backfill);
        apply_overrides(
            &mut config,
            &json!({"step5_prefilter": {"ast_backfill_evidence": false}}),
            GlobalSampling::default(),
        );
        assert!(!config.step5.ast_backfill);
    }

    #[test]
    fn step0_overrides_are_a_no_op_when_the_section_is_absent() {
        let mut config = default_scan_config();
        apply_overrides(&mut config, &json!({}), GlobalSampling::default());
        assert_eq!(config.step0.enabled, Step0Config::new().enabled);
        assert_eq!(config.step0.sources_yaml, None);
        assert_eq!(config.step0.sinks_yaml, None);
    }

    #[test]
    fn step1_overrides_every_field_including_nested_dedup_and_call_graph() {
        let mut config = default_scan_config();
        let data = json!({
            "step1": {
                "allowed_tools": ["Read"],
                "max_turns": 99,
                "max_tokens": 1,
                "max_transient_retries": 2,
                "max_context_shrinks": 3,
                "exclude_dirs": ["node_modules"],
                "exclude_exts": [".min.js"],
                "exclude_globs": ["**/vendor/**"],
                "max_file_kb": 42,
                "call_graph_validate": false,
                "call_graph_supplement": false,
                "call_graph_rounds": 7,
                "call_graph_max_targets": 8,
                "config_dedup": {
                    "enabled": false,
                    "exts": [".yaml"],
                    "min_cluster_size": 9,
                    "keep_per_top_dir": false,
                    "promote_on_secret_hit": false,
                    "promote_on_insecure_value": false,
                    "max_file_kb": 11,
                },
            }
        });
        apply_overrides(&mut config, &data, GlobalSampling::default());
        let s1 = &config.step1;
        assert_eq!(s1.allowed_tools, vec!["Read".to_string()]);
        assert_eq!(s1.max_turns, 99);
        assert_eq!(s1.max_tokens, 1);
        assert_eq!(s1.max_transient_retries, 2);
        assert_eq!(s1.max_context_shrinks, 3);
        assert_eq!(s1.walk.exclude_dirs, vec!["node_modules".to_string()]);
        assert_eq!(s1.walk.exclude_exts, vec![".min.js".to_string()]);
        assert_eq!(s1.walk.exclude_globs, vec!["**/vendor/**".to_string()]);
        assert_eq!(s1.walk.max_file_kb, 42);
        assert!(!s1.call_graph.validate);
        assert!(!s1.call_graph.supplement);
        assert_eq!(s1.call_graph.rounds, 7);
        assert_eq!(s1.call_graph.max_targets, 8);
        assert!(!s1.dedup.enabled);
        assert_eq!(s1.dedup.exts, vec![".yaml".to_string()]);
        assert_eq!(s1.dedup.min_cluster_size, 9);
        assert!(!s1.dedup.keep_per_top_dir);
        assert!(!s1.dedup.promote_on_secret_hit);
        assert!(!s1.dedup.promote_on_insecure_value);
        assert_eq!(s1.dedup.max_file_kb, 11);
    }

    #[test]
    fn step1_without_config_dedup_section_leaves_dedup_defaults_untouched() {
        let mut config = default_scan_config();
        let default_dedup = config.step1.dedup.clone();
        apply_overrides(
            &mut config,
            &json!({"step1": {"max_turns": 1}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step1.dedup, default_dedup);
    }

    /// All NINE narrowing caps, each asserted against the field
    /// `_gather_evidence` actually passes it to — the unprefixed
    /// `max_modules`/`max_entry_points` are FRONTIER caps and the
    /// `max_prompt_*` pair is the prompt-display cap, not the other way
    /// round (`s2_threatmodel.py:229-251`).
    #[test]
    fn step2_overrides_every_field() {
        let mut config = default_scan_config();
        let data = json!({
            "step2": {
                "max_tokens": 1, "max_threats": 2, "baseline": "owasp",
                "max_doc_chars": 3, "max_manifest_chars": 4, "max_modules": 5,
                "max_entry_points": 6, "max_config_reps": 7, "max_api_artefacts": 8,
                "max_function_sites": 9, "max_graph_files": 10, "max_graph_sinks": 11,
                "max_graph_edges": 12, "max_notes_chars": 13,
                "max_prompt_modules": 14, "max_prompt_entry_points": 15,
            }
        });
        apply_overrides(&mut config, &data, GlobalSampling::default());
        let s2 = &config.step2;
        assert_eq!(s2.max_tokens, 1);
        assert_eq!(s2.max_threats, 2);
        assert_eq!(s2.baseline, "owasp");
        assert_eq!(s2.max_doc_chars, 3);
        assert_eq!(s2.max_manifest_chars, 4);
        assert_eq!(s2.frontier_max_modules, 5);
        assert_eq!(s2.frontier_max_entry_points, 6);
        assert_eq!(s2.max_config_reps, 7);
        assert_eq!(s2.max_api_artefacts, 8);
        assert_eq!(s2.max_function_sites, 9);
        assert_eq!(s2.frontier_max_files, 10);
        assert_eq!(s2.frontier_max_sinks, 11);
        assert_eq!(s2.frontier_max_edges, 12);
        assert_eq!(s2.frontier_max_notes_chars, 13);
        assert_eq!(s2.max_modules, 14);
        assert_eq!(s2.max_entry_points, 15);
    }

    #[test]
    fn step3_overrides_every_field() {
        let mut config = default_scan_config();
        let data = json!({
            "step3": {
                "max_tokens": 1, "taint_chunks": false, "taint_max_hops": 2,
                "taint_max_chunks": 3, "taint_files_per_hop": 4, "pack_by": "tokens",
                "pack_merge_underfilled": false,
                "chunk_token_budget": 5, "chunk_overhead_tokens": 6, "risk_chunk_loc": 7,
                "catchall_enabled": false, "catchall_chunk_loc": 8, "catchall_max_files": 9,
                "catchall_mode": "reachable_only", "catchall_reachable_min_ratio": 0.5,
                "catchall_reachable_min_files": 12,
                "max_files_per_chunk": 10, "specialists": ["crypto"], "specialist_chunk_loc": 11,
                "threat_surface_fallbacks": false, "threat_fallback_max_files": 13,
            }
        });
        apply_overrides(&mut config, &data, GlobalSampling::default());
        let s3 = &config.step3;
        assert_eq!(s3.max_tokens, 1);
        assert!(!s3.taint_chunks);
        assert_eq!(s3.taint_max_hops, 2);
        assert_eq!(s3.taint_max_chunks, 3);
        assert_eq!(s3.taint_files_per_hop, 4);
        assert_eq!(s3.pack_by, "tokens");
        assert!(!s3.pack_merge_underfilled);
        assert_eq!(s3.chunk_token_budget, 5);
        assert_eq!(s3.chunk_overhead_tokens, 6);
        assert_eq!(s3.risk_chunk_loc, 7);
        assert!(!s3.catchall_enabled);
        assert_eq!(s3.catchall_chunk_loc, 8);
        assert_eq!(s3.catchall_max_files, 9);
        assert_eq!(s3.catchall_mode, "reachable_only");
        assert_eq!(s3.catchall_reachable_min_ratio, 0.5);
        assert_eq!(s3.catchall_reachable_min_files, 12);
        assert_eq!(s3.max_files_per_chunk, 10);
        assert_eq!(s3.specialists, vec!["crypto".to_string()]);
        assert_eq!(s3.specialist_chunk_loc, 11);
        assert!(!s3.threat_surface_fallbacks);
        assert_eq!(s3.threat_fallback_max_files, 13);
    }

    #[test]
    fn output_section_overrides_emit_unreachable_appendix() {
        let mut config = default_scan_config();
        assert!(!config.emit_unreachable_appendix);
        let data = json!({"output": {"emit_unreachable_appendix": true}});
        apply_overrides(&mut config, &data, GlobalSampling::default());
        assert!(config.emit_unreachable_appendix);
    }

    #[test]
    fn missing_output_section_leaves_emit_unreachable_appendix_unchanged() {
        let mut config = default_scan_config();
        apply_overrides(&mut config, &json!({}), GlobalSampling::default());
        assert!(!config.emit_unreachable_appendix);
    }

    #[test]
    fn step4_overrides_every_field() {
        let mut config = default_scan_config();
        let data = json!({
            "step4": {
                "parallel": 1, "max_tokens": 2, "max_findings_per_run": 3,
                "neighbor_context_lines": 4, "neighbor_context_max": 5,
                "runs": 6, "vote_threshold": 7, "specialist_runs": 8, "line_bucket": 9,
                "taint_prompt_mode": "confirm_refute", "taint_runs": 2,
                "frontier_max_funcs_per_file": 11,
            }
        });
        apply_overrides(&mut config, &data, GlobalSampling::default());
        let s4 = &config.step4;
        assert_eq!(s4.parallel, 1);
        assert_eq!(s4.max_tokens, 2);
        assert_eq!(s4.max_findings_per_run, Some(3));
        assert_eq!(s4.neighbor_context_lines, 4);
        assert_eq!(s4.neighbor_context_max, 5);
        assert_eq!(s4.runs, 6);
        assert_eq!(s4.vote_threshold, 7);
        assert_eq!(s4.specialist_runs, 8);
        assert_eq!(s4.line_bucket, 9);
        assert_eq!(s4.taint_prompt_mode, "confirm_refute");
        assert_eq!(s4.taint_runs, Some(2));
        assert_eq!(s4.frontier_max_funcs_per_file, 11);
    }

    #[test]
    fn taint_chunk_slice_is_read_from_step3_where_every_shipped_profile_declares_it() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"step3": {"taint_chunk_slice": "function"}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step4.taint_chunk_slice, "function");
    }

    #[test]
    fn an_explicit_step4_taint_chunk_slice_wins_over_step3() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({
                "step3": {"taint_chunk_slice": "function"},
                "step4": {"taint_chunk_slice": "file"},
            }),
            GlobalSampling::default(),
        );
        assert_eq!(config.step4.taint_chunk_slice, "file");
    }

    #[test]
    fn a_null_step4_taint_chunk_slice_falls_back_to_step3() {
        // `_STEP_DEFAULTS` ships exactly this shape, so the fallback has
        // to survive the defaults layer being merged underneath.
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({
                "step3": {"taint_chunk_slice": "function"},
                "step4": {"taint_chunk_slice": null},
            }),
            GlobalSampling::default(),
        );
        assert_eq!(config.step4.taint_chunk_slice, "function");
    }

    #[test]
    fn taint_chunk_slice_is_normalized_the_way_python_normalizes_it() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"step3": {"taint_chunk_slice": "Function"}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step4.taint_chunk_slice, "function");
        // `str(mode or "file")`: an empty string is "file", not "".
        apply_overrides(
            &mut config,
            &json!({"step3": {"taint_chunk_slice": ""}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step4.taint_chunk_slice, "file");
    }

    #[test]
    fn taint_chunk_slice_absent_from_both_sections_keeps_the_built_in_default() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"step4": {"runs": 2}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step4.taint_chunk_slice, "file");
    }

    #[test]
    fn step5_prefilter_overrides_every_field() {
        let mut config = default_scan_config();
        let data = json!({
            "step5_prefilter": {
                "min_pre_confidence": 0.1, "require_evidence": false, "pre_verify_threshold": 2,
                "ast_backfill_evidence": false,
            }
        });
        apply_overrides(&mut config, &data, GlobalSampling::default());
        let s5 = &config.step5;
        assert_eq!(s5.min_pre_confidence, 0.1);
        assert!(!s5.require_evidence);
        assert!(!s5.ast_backfill);
        assert_eq!(s5.pre_verify_threshold, 2);
    }

    #[test]
    fn step6_verify_overrides_every_field() {
        let mut config = default_scan_config();
        let data = json!({
            "step6_verify": {
                "parallel": 1, "min_confidence": 2, "max_turns": 3, "allowed_tools": ["Grep"],
                "max_transient_retries": 4, "max_context_shrinks": 5,
            }
        });
        apply_overrides(&mut config, &data, GlobalSampling::default());
        let s6 = &config.step6;
        assert_eq!(s6.parallel, 1);
        assert_eq!(s6.min_confidence, 2);
        assert_eq!(s6.max_turns, 3);
        assert_eq!(s6.allowed_tools, vec!["Grep".to_string()]);
        assert_eq!(s6.max_transient_retries, 4);
        assert_eq!(s6.max_context_shrinks, 5);
    }

    #[test]
    fn step7_dedup_overrides_every_field_on_both_step7_and_step5s_shared_dedup() {
        let mut config = default_scan_config();
        let data = json!({
            "step7_dedup": {
                "line_tolerance": 1,
                "semantic": false,
                "max_tokens": 2,
                "merge_same_range_cwes": false,
                "merge_same_sink": false,
            }
        });
        apply_overrides(&mut config, &data, GlobalSampling::default());
        assert_eq!(config.step7.line_tolerance, 1);
        assert!(!config.step7.semantic);
        assert_eq!(config.step7.max_tokens, 2);
        assert!(!config.step7.merge_same_range_cwes);
        assert!(!config.step7.merge_same_sink);
        assert_eq!(config.step5.dedup.line_tolerance, 1);
        assert!(!config.step5.dedup.semantic);
        assert_eq!(config.step5.dedup.max_tokens, 2);
        assert!(!config.step5.dedup.merge_same_range_cwes);
        assert!(!config.step5.dedup.merge_same_sink);
    }

    #[test]
    fn merge_same_sink_defaults_on_and_survives_an_unrelated_override() {
        let mut config = default_scan_config();
        assert!(config.step7.merge_same_sink);
        assert!(config.step5.dedup.merge_same_sink);
        apply_overrides(
            &mut config,
            &json!({"step7_dedup": {"line_tolerance": 9}}),
            GlobalSampling::default(),
        );
        assert!(config.step7.merge_same_sink);
        assert!(config.step5.dedup.merge_same_sink);
    }

    #[test]
    fn merge_same_range_cwes_defaults_on_and_survives_an_unrelated_override() {
        let mut config = default_scan_config();
        assert!(config.step7.merge_same_range_cwes);
        assert!(config.step5.dedup.merge_same_range_cwes);
        apply_overrides(
            &mut config,
            &json!({"step7_dedup": {"line_tolerance": 9}}),
            GlobalSampling::default(),
        );
        assert!(config.step7.merge_same_range_cwes);
        assert!(config.step5.dedup.merge_same_range_cwes);
    }

    #[test]
    fn step8_overrides_its_field() {
        let mut config = default_scan_config();
        apply_overrides(
            &mut config,
            &json!({"step8": {"max_tokens": 1}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step8.max_tokens, 1);
    }

    #[test]
    fn a_wrong_typed_field_is_left_at_its_constructed_default() {
        let mut config = default_scan_config();
        let default_max_turns = config.step1.max_turns;
        apply_overrides(
            &mut config,
            &json!({"step1": {"max_turns": "not a number"}}),
            GlobalSampling::default(),
        );
        assert_eq!(config.step1.max_turns, default_max_turns);
    }

    #[test]
    fn step2_enabled_override_reads_the_toggle() {
        assert_eq!(
            step2_enabled_override(&json!({"step2": {"enabled": false}})),
            Some(false)
        );
        assert_eq!(step2_enabled_override(&json!({"step2": {}})), None);
        assert_eq!(step2_enabled_override(&json!({})), None);
    }

    #[test]
    fn step0_enabled_override_reads_the_toggle() {
        assert_eq!(
            step0_enabled_override(&json!({"step0": {"enabled": true}})),
            Some(true)
        );
        assert_eq!(step0_enabled_override(&json!({"step0": {}})), None);
        assert_eq!(step0_enabled_override(&json!({})), None);
    }

    #[test]
    fn llm_stream_large_responses_override_reads_the_toggle() {
        assert_eq!(
            llm_stream_large_responses_override(&json!({"llm": {"stream_large_responses": true}})),
            Some(true)
        );
        assert_eq!(
            llm_stream_large_responses_override(&json!({"llm": {"stream_large_responses": false}})),
            Some(false)
        );
        assert_eq!(
            llm_stream_large_responses_override(&json!({"llm": {}})),
            None
        );
        assert_eq!(llm_stream_large_responses_override(&json!({})), None);
        // A non-boolean value is "no opinion", not an error — the same
        // leniency every other single-field read here applies.
        assert_eq!(
            llm_stream_large_responses_override(&json!({"llm": {"stream_large_responses": "yes"}})),
            None
        );
    }

    #[test]
    fn apply_step10_overrides_is_a_no_op_on_an_empty_tree() {
        let mut cfg = bc_stage_s10::Step10Config::new("m");
        let default_max_turns = cfg.max_turns;
        let default_tools = cfg.allowed_tools.clone();
        apply_step10_overrides(&mut cfg, &json!({}), GlobalSampling::default());
        assert_eq!(cfg.model, "m");
        assert_eq!(cfg.max_turns, default_max_turns);
        assert_eq!(cfg.allowed_tools, default_tools);
    }

    #[test]
    fn apply_step10_overrides_reads_the_remediate_model_role() {
        let mut cfg = bc_stage_s10::Step10Config::new("m");
        apply_step10_overrides(
            &mut cfg,
            &json!({"models": {"remediate": {"id": "opus"}}}),
            GlobalSampling::default(),
        );
        assert_eq!(cfg.model, "opus");
    }

    #[test]
    fn apply_step10_overrides_reads_retry_unapplied_fix() {
        // Default is on; the YAML key must be able to turn it off, which
        // is the one thing the gate's own crate could not wire itself.
        let mut cfg = bc_stage_s10::Step10Config::new("m");
        assert!(cfg.retry_unapplied_fix);
        apply_step10_overrides(
            &mut cfg,
            &json!({"step_remediate": {"retry_unapplied_fix": false}}),
            GlobalSampling::default(),
        );
        assert!(!cfg.retry_unapplied_fix);
    }

    #[test]
    fn apply_step10_overrides_reads_max_turns_and_allowed_tools() {
        let mut cfg = bc_stage_s10::Step10Config::new("m");
        apply_step10_overrides(
            &mut cfg,
            &json!({"step_remediate": {
                "max_turns": 7, "allowed_tools": ["Read", "Grep"],
                "max_transient_retries": 8, "max_context_shrinks": 9,
            }}),
            GlobalSampling::default(),
        );
        assert_eq!(cfg.max_turns, 7);
        assert_eq!(
            cfg.allowed_tools,
            vec!["Read".to_string(), "Grep".to_string()]
        );
        assert_eq!(cfg.max_transient_retries, 8);
        assert_eq!(cfg.max_context_shrinks, 9);
    }

    #[test]
    fn apply_step10_overrides_reads_every_safety_gate_key() {
        let mut cfg = bc_stage_s10::Step10Config::new("m");
        apply_step10_overrides(
            &mut cfg,
            &json!({"step_remediate": {
                "syntax_check": false,
                "keep_unverified": true,
                "max_diff_lines": 12,
                "max_files_touched": 34,
                "dry_run": true,
                "verify_command": "cargo test",
                "verify_timeout_secs": 90,
            }}),
            GlobalSampling::default(),
        );
        assert!(!cfg.syntax_check);
        assert!(cfg.keep_unverified);
        assert_eq!(cfg.max_diff_lines, 12);
        assert_eq!(cfg.max_files_touched, 34);
        assert!(cfg.dry_run);
        assert_eq!(cfg.verify_command.as_deref(), Some("cargo test"));
        assert_eq!(cfg.verify_timeout_secs, 90);
    }

    /// The shipped `step_defaults()` spells "run nothing" as JSON `null`,
    /// which must round-trip to `None` rather than being ignored (leaving
    /// a previously-set command in place) or coerced to `Some("")`.
    #[test]
    fn a_null_verify_command_clears_it() {
        let mut cfg = bc_stage_s10::Step10Config::new("m");
        cfg.verify_command = Some("stale".to_string());
        apply_step10_overrides(
            &mut cfg,
            &json!({"step_remediate": {"verify_command": null}}),
            GlobalSampling::default(),
        );
        assert_eq!(cfg.verify_command, None);
    }

    #[test]
    fn step_remediate_policy_paths_resolve_relative_paths_against_the_config_dir() {
        let data = json!({"step_remediate": {
            "policy_file": "./inputs/policy.yaml",
            "playbook_file": "inputs/playbook.yaml",
        }});
        let (policy, playbook) =
            step_remediate_policy_paths(&data, std::path::Path::new("/etc/bc/profiles"));
        assert_eq!(
            policy,
            Some(std::path::PathBuf::from(
                "/etc/bc/profiles/./inputs/policy.yaml"
            ))
        );
        assert_eq!(
            playbook,
            Some(std::path::PathBuf::from(
                "/etc/bc/profiles/inputs/playbook.yaml"
            ))
        );
    }

    #[test]
    fn an_absolute_policy_path_is_used_verbatim() {
        let data = json!({"step_remediate": {"policy_file": "/abs/policy.yaml"}});
        let (policy, playbook) =
            step_remediate_policy_paths(&data, std::path::Path::new("/etc/bc"));
        assert_eq!(policy, Some(std::path::PathBuf::from("/abs/policy.yaml")));
        assert_eq!(playbook, None);
    }

    #[test]
    fn step_remediate_policy_paths_ignore_absent_empty_and_wrong_typed_values() {
        let dir = std::path::Path::new("/etc/bc");
        assert_eq!(step_remediate_policy_paths(&json!({}), dir), (None, None));
        assert_eq!(
            step_remediate_policy_paths(&json!({"step_remediate": {}}), dir),
            (None, None)
        );
        assert_eq!(
            step_remediate_policy_paths(
                &json!({"step_remediate": {"policy_file": "   ", "playbook_file": 7}}),
                dir
            ),
            (None, None)
        );
    }

    #[test]
    fn step_remediate_top_n_findings_reads_a_numeric_value() {
        assert_eq!(
            step_remediate_top_n_findings(&json!({"step_remediate": {"top_n_findings": 5}})),
            Some(bc_stage_s10::TopSpec::N(5))
        );
    }

    #[test]
    fn step_remediate_top_n_findings_reads_the_all_wildcard() {
        assert_eq!(
            step_remediate_top_n_findings(&json!({"step_remediate": {"top_n_findings": "all"}})),
            Some(bc_stage_s10::TopSpec::All)
        );
    }

    #[test]
    fn step_remediate_top_n_findings_is_none_for_a_wrong_typed_value() {
        assert_eq!(
            step_remediate_top_n_findings(&json!({"step_remediate": {"top_n_findings": true}})),
            None
        );
    }

    #[test]
    fn step_remediate_top_n_findings_is_none_without_the_section_or_key() {
        assert_eq!(step_remediate_top_n_findings(&json!({})), None);
        assert_eq!(
            step_remediate_top_n_findings(&json!({"step_remediate": {}})),
            None
        );
    }

    #[test]
    fn step_remediate_enforce_policy_reads_the_toggle() {
        assert_eq!(
            step_remediate_enforce_policy(&json!({"step_remediate": {"enforce_policy": true}})),
            Some(true)
        );
        assert_eq!(step_remediate_enforce_policy(&json!({})), None);
    }

    #[test]
    fn apply_step11_overrides_is_a_no_op_on_an_empty_tree() {
        let mut cfg = bc_stage_s11::Step11Config::new("m");
        let default_max_turns = cfg.max_turns;
        let default_tools = cfg.allowed_tools.clone();
        apply_step11_overrides(&mut cfg, &json!({}), GlobalSampling::default());
        assert_eq!(cfg.model, "m");
        assert_eq!(cfg.max_turns, default_max_turns);
        assert_eq!(cfg.allowed_tools, default_tools);
        assert_eq!(cfg.security_architect_model, None);
        assert_eq!(cfg.penetration_tester_model, None);
        assert_eq!(cfg.cross_repo_analyzer_model, None);
        assert!(!cfg.cross_repo_analyzer);
    }

    #[test]
    fn apply_step11_overrides_reads_the_validate_model_role() {
        let mut cfg = bc_stage_s11::Step11Config::new("m");
        apply_step11_overrides(
            &mut cfg,
            &json!({"models": {"validate": {"id": "opus"}}}),
            GlobalSampling::default(),
        );
        assert_eq!(cfg.model, "opus");
    }

    #[test]
    fn apply_step11_overrides_reads_per_persona_model_overrides() {
        let mut cfg = bc_stage_s11::Step11Config::new("m");
        apply_step11_overrides(
            &mut cfg,
            &json!({"models": {"validate": {
                "id": "opus",
                "security_architect": {"id": "architect-model"},
                "penetration_tester": {"id": "pentester-model"},
                "cross_repo_analyzer": {"id": "cross-repo-model"},
            }}}),
            GlobalSampling::default(),
        );
        assert_eq!(cfg.model, "opus");
        assert_eq!(
            cfg.security_architect_model,
            Some("architect-model".to_string())
        );
        assert_eq!(
            cfg.penetration_tester_model,
            Some("pentester-model".to_string())
        );
        assert_eq!(
            cfg.cross_repo_analyzer_model,
            Some("cross-repo-model".to_string())
        );
    }

    #[test]
    fn apply_step11_overrides_leaves_unset_persona_models_at_none() {
        let mut cfg = bc_stage_s11::Step11Config::new("m");
        apply_step11_overrides(
            &mut cfg,
            &json!({"models": {"validate": {
                "id": "opus",
                "security_architect": {"id": "architect-model"},
            }}}),
            GlobalSampling::default(),
        );
        assert_eq!(
            cfg.security_architect_model,
            Some("architect-model".to_string())
        );
        assert_eq!(cfg.penetration_tester_model, None);
        assert_eq!(cfg.cross_repo_analyzer_model, None);
    }

    #[test]
    fn apply_step11_overrides_reads_the_cross_repo_analyzer_toggle() {
        let mut cfg = bc_stage_s11::Step11Config::new("m");
        apply_step11_overrides(
            &mut cfg,
            &json!({"step_validate": {"cross_repo_analyzer": true}}),
            GlobalSampling::default(),
        );
        assert!(cfg.cross_repo_analyzer);
    }

    #[test]
    fn apply_step11_overrides_reads_max_turns_and_allowed_tools() {
        let mut cfg = bc_stage_s11::Step11Config::new("m");
        apply_step11_overrides(
            &mut cfg,
            &json!({"step_validate": {
                "max_turns": 7, "allowed_tools": ["Read", "Grep"],
                "max_transient_retries": 8, "max_context_shrinks": 9,
                "max_findings": 3,
            }}),
            GlobalSampling::default(),
        );
        assert_eq!(cfg.max_turns, 7);
        assert_eq!(
            cfg.allowed_tools,
            vec!["Read".to_string(), "Grep".to_string()]
        );
        assert_eq!(cfg.max_transient_retries, 8);
        assert_eq!(cfg.max_context_shrinks, 9);
        assert_eq!(cfg.max_findings, Some(3));
    }

    #[test]
    fn apply_step11_overrides_reads_the_fact_tools_toggle() {
        let mut cfg = bc_stage_s11::Step11Config::new("m");
        assert!(cfg.fact_tools, "the five fact tools are on by default");
        apply_step11_overrides(
            &mut cfg,
            &json!({"step_validate": {"fact_tools": false}}),
            GlobalSampling::default(),
        );
        assert!(!cfg.fact_tools);
    }

    #[test]
    fn step_validate_enabled_override_reads_the_toggle() {
        assert_eq!(
            step_validate_enabled_override(&json!({"step_validate": {"enabled": false}})),
            Some(false)
        );
        assert_eq!(
            step_validate_enabled_override(&json!({"step_validate": {}})),
            None
        );
        assert_eq!(step_validate_enabled_override(&json!({})), None);
    }
}
